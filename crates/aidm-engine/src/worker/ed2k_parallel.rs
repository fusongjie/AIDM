//! eD2k 任务编排：缓存源立即连接，服务器/Kad 并行增量发现，多源协调器分配校验片。
use super::*;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::AtomicUsize;
use std::sync::mpsc;

use crate::ed2k::{
    multi_source as pool, private_index, private_pool, source_discovery as discovery,
};

fn private_identity(user_hash: &[u8; 16], task_id: i64) -> [u8; 16] {
    let mut seed = b"AIDM private task identity\0".to_vec();
    seed.extend_from_slice(user_hash);
    seed.extend_from_slice(&task_id.to_le_bytes());
    let digest = ring::digest::digest(&ring::digest::SHA256, &seed);
    private_index::peer_id(digest.as_ref()[..16].try_into().unwrap())
}

fn metadata_matches(link: &aidm_core::ed2k::FileLink, meta: &private_index::Metadata) -> bool {
    let count = aidm_core::ed2k::peer::part_count(link.size);
    if count == 0 || count > 65535 || meta.part_hashes.len() != count {
        return false;
    }
    let actual = if count == 1 {
        meta.part_hashes[0]
    } else {
        aidm_core::ed2k::hash::md4(&meta.part_hashes.concat())
    };
    actual == link.hash
}

/// The detached index request can outlive this wait. Pause/cancel must not join it.
fn wait_metadata<T>(
    rx: &mpsc::Receiver<T>,
    stop: &dyn Fn() -> bool,
    timeout: Duration,
) -> Option<T> {
    let started = Instant::now();
    while !stop() {
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return rx.try_recv().ok();
        }
        match rx.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(meta) => return (!stop()).then_some(meta),
            Err(mpsc::RecvTimeoutError::Disconnected) => return None,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
    None
}

struct Hooks<'a> {
    args: &'a Args,
    global_cap: u64,
    task_limiter: Arc<TokenBucket>,
}

impl pool::TransferHooks for Hooks<'_> {
    fn try_acquire_connection(&self) -> bool {
        let counter = &self.args.active_conns;
        let mut current = counter.load(Ordering::Acquire);
        while current < self.global_cap {
            match counter.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
        false
    }

    fn release_connection(&self) {
        self.args.active_conns.fetch_sub(1, Ordering::AcqRel);
    }

    fn received(&self, bytes: u64) {
        self.args.speed_window.add(bytes);
        let stop =
            || self.args.cancel.load(Ordering::SeqCst) || self.args.pause.load(Ordering::SeqCst);
        self.args.limiter.take_until(bytes, &stop);
        self.task_limiter.take_until(bytes, stop);
    }
}

/// 单池的进度计数：两个池各一份，聚合之后才是任务进度。
#[derive(Default)]
struct SideCounters {
    done: AtomicU64,
    verified: AtomicUsize,
    active: AtomicUsize,
    transferring: AtomicUsize,
    queued: AtomicUsize,
    verifying: AtomicBool,
    /// 该池最近一次上报的逐切片状态；两池合并后才是任务视图。
    slices: Mutex<Vec<u8>>,
}

/// 合并两个池的切片状态。切片按全局下标对齐，未归属的片在各自池里是 Pending。
/// done 优先于 checking/active/pending，避免一个池已完成、另一个池的旧状态把它盖回去。
fn merge_slices(left: &[u8], right: &[u8]) -> Vec<u8> {
    let len = left.len().max(right.len());
    (0..len)
        .map(|i| {
            let a = left.get(i).copied().unwrap_or(0);
            let b = right.get(i).copied().unwrap_or(0);
            if a == 2 || b == 2 {
                2
            } else if a == 3 || b == 3 {
                3
            } else if a == 1 || b == 1 {
                1
            } else {
                0
            }
        })
        .collect()
}

/// 写库节流时钟（相位变化必写，其余按 `PERSIST_INTERVAL`）。
struct PersistClock {
    last: Instant,
    phase: &'static str,
}

/// 两个池并发时**唯一**的进度出口：聚合 → 上抛 → 节流写库。
///
/// 为什么必须单点：`set_segment_progress` 是无条件 UPDATE，两个池各自上报会把
/// "本池字节"当成任务进度来回覆盖，进度条因此回退；`emit_progress` 同理，
/// 会覆盖 `live.done_bytes`（前端看到的实时字节数）。
struct ProgressAgg<'a> {
    args: &'a Args,
    known: &'a AtomicU64,
    queue_ranks: &'a Mutex<HashMap<SocketAddr, u16>>,
    size: u64,
    total_parts: usize,
    max_connections: u32,
    left: SideCounters,
    right: SideCounters,
    persist: Mutex<PersistClock>,
    floor: AtomicU64,
}

impl ProgressAgg<'_> {
    /// 单池一次进度上报：先落本池计数，再按聚合值发布。
    fn publish(&self, side: &SideCounters, progress: pool::PoolProgress) {
        side.done.store(progress.done, Ordering::Relaxed);
        // 逐片校验是 eD2k 特有的阶段：片数增加时留一条，才能把「传输慢」与
        // 「校验拖后腿」分开看（规格 §3.3 verify.part）。
        let prev_verified = side.verified.load(Ordering::Relaxed);
        side.verified
            .store(progress.verified_parts, Ordering::Relaxed);
        if progress.verified_parts > prev_verified {
            tracing::info!(
                event = "verify.part",
                phase = "verify",
                proto = "ed2k",
                algo = "md4",
                verified_parts = progress.verified_parts,
                total_parts = aidm_core::ed2k::peer::part_count(self.size),
            );
        }
        side.active.store(progress.active_peers, Ordering::Relaxed);
        side.transferring
            .store(progress.transferring_peers, Ordering::Relaxed);
        side.queued.store(progress.queued_peers, Ordering::Relaxed);
        side.verifying.store(progress.verifying, Ordering::Relaxed);
        *side.slices.lock().unwrap() = progress.slices;
        self.publish_now(false);
    }

    /// 整包 MD4 开始：立刻把 `verifying` 推给界面（这一步可能持续很久）。
    fn begin_verify(&self) {
        self.left.verifying.store(true, Ordering::Relaxed);
        self.publish_now(true);
    }

    /// 标准池被动态交接停掉：清掉它的计数，所有权已转给继续运行的私有池。
    fn retire_left(&self) {
        self.left.done.store(0, Ordering::Relaxed);
        self.left.verified.store(0, Ordering::Relaxed);
        self.left.active.store(0, Ordering::Relaxed);
        self.left.transferring.store(0, Ordering::Relaxed);
        self.left.queued.store(0, Ordering::Relaxed);
        self.left.slices.lock().unwrap().clear();
    }

    /// 私有池已退出：清掉它的计数，避免与兜底轮的字节数叠加。
    fn retire_right(&self) {
        self.right.done.store(0, Ordering::Relaxed);
        self.right.verified.store(0, Ordering::Relaxed);
        self.right.active.store(0, Ordering::Relaxed);
        self.right.transferring.store(0, Ordering::Relaxed);
        self.right.queued.store(0, Ordering::Relaxed);
        self.right.slices.lock().unwrap().clear();
    }

    /// 兜底轮开始：把当前聚合字节设为下限，进度条只进不退。
    fn set_floor(&self) {
        let current =
            self.left.done.load(Ordering::Relaxed) + self.right.done.load(Ordering::Relaxed);
        self.floor.fetch_max(current, Ordering::Relaxed);
    }

    /// 收口：两池（或兜底轮）都已 join，写入**最终**进度。
    ///
    /// `verified_parts` 是磁盘上的事实覆盖（两池分片互不相交，可直接相加）；
    /// 覆盖满分片即整包字节，避免把"下完又被判失败重下"的片算进进度。
    fn settle(&self, verified_parts: usize) {
        // 收口也保持单调：清掉 floor 会让 UI 从 9.7MB 掉回 0（实测 ed2k 换源后
        // live 进度 9,728,000 → 0）。真实完成字节由 `verified_parts` 决定，
        // 这里只保证"已经展示给用户的字节"不回退。
        let complete = self.total_parts > 0 && verified_parts >= self.total_parts;
        let raw = if complete {
            self.size
        } else {
            self.left.done.load(Ordering::Relaxed) + self.right.done.load(Ordering::Relaxed)
        };
        let done = self.floor.fetch_max(raw, Ordering::Relaxed).max(raw);
        self.left.done.store(done, Ordering::Relaxed);
        self.right.done.store(0, Ordering::Relaxed);
        self.left.verified.store(verified_parts, Ordering::Relaxed);
        self.right.verified.store(0, Ordering::Relaxed);
        for side in [&self.left, &self.right] {
            side.active.store(0, Ordering::Relaxed);
            side.transferring.store(0, Ordering::Relaxed);
            side.queued.store(0, Ordering::Relaxed);
        }
        if complete {
            self.left.slices.lock().unwrap().fill(2);
            self.right.slices.lock().unwrap().clear();
        }
        self.publish_now(true);
    }

    fn publish_now(&self, force: bool) {
        let left = &self.left;
        let right = &self.right;
        // 池内 `PoolProgress.done` 允许换源时回退（未完成分片会被丢弃），
        // 但界面/DB 的进度必须单调：用 floor 记住已经展示过的最大值。
        let raw = left.done.load(Ordering::Relaxed) + right.done.load(Ordering::Relaxed);
        let done = self.floor.fetch_max(raw, Ordering::Relaxed).max(raw);
        let verified =
            left.verified.load(Ordering::Relaxed) + right.verified.load(Ordering::Relaxed);
        let active = left.active.load(Ordering::Relaxed) + right.active.load(Ordering::Relaxed);
        let transferring =
            left.transferring.load(Ordering::Relaxed) + right.transferring.load(Ordering::Relaxed);
        let queued = left.queued.load(Ordering::Relaxed) + right.queued.load(Ordering::Relaxed);
        let verifying =
            left.verifying.load(Ordering::Relaxed) || right.verifying.load(Ordering::Relaxed);
        let left_slices = self.left.slices.lock().unwrap().clone();
        let right_slices = self.right.slices.lock().unwrap().clone();
        let slices = merge_slices(&left_slices, &right_slices);
        let phase: &'static str = if verifying {
            "verifying"
        } else if transferring > 0 {
            "downloading"
        } else if queued > 0 {
            "queued"
        } else if active > 0 {
            "connecting"
        } else {
            "discovering"
        };
        *self.args.live.p2p.lock().unwrap() = Some(aidm_ipc::P2pView {
            phase: phase.into(),
            known_sources: self.known.load(Ordering::Relaxed) as u32,
            active_peers: active as u32,
            transferring_peers: transferring as u32,
            queued_peers: queued as u32,
            max_connections: self.max_connections,
            queue_rank: self
                .queue_ranks
                .lock()
                .unwrap()
                .values()
                .min()
                .copied()
                .map(u32::from),
            verified_parts: Some(verified as u32),
            total_parts: self.total_parts as u32,
            slices: if slices.is_empty() {
                None
            } else {
                Some(slices)
            },
        });
        emit_progress(self.args, done, Some(self.size));
        let mut clock = self.persist.lock().unwrap();
        if force || clock.phase != phase || clock.last.elapsed() >= PERSIST_INTERVAL {
            let conn = self.args.db.lock().unwrap();
            // 同时更新 status：只写 done_bytes 会让库里长期停在 pending，
            // 与 live 进度（17MB/49MB）看起来像两个任务。ed2k 的分段行是 idx 0。
            let _ = model::set_segment_state(&conn, self.args.id, 0, done as i64, "running");
            if clock.phase != phase {
                let status = match phase {
                    "verifying" => Status::Verifying,
                    "downloading" => Status::Downloading,
                    _ => Status::Connecting,
                };
                let _ = model::set_status(&conn, self.args.id, status, None);
                clock.phase = phase;
            }
            clock.last = Instant::now();
        }
    }
}

pub(super) fn download(
    args: &Args,
    row: &DownloadRow,
    link: &aidm_core::ed2k::FileLink,
    part_path: &Path,
    user_hash: [u8; 16],
    switch_http: &std::sync::atomic::AtomicBool,
    known_out: &AtomicU64,
    first_standard_source: &std::sync::atomic::AtomicBool,
) -> WorkerEnd {
    // 阶段事件：eD2k 的「传输开始」在源已就绪、进入分片调度之前。
    // 之后的进度由共用的 `emit_progress` 节流上报（5 秒一条），与 HTTP/FTP 同口径。
    tracing::info!(
        event = "transfer.start",
        phase = "transfer",
        proto = "ed2k",
        mode = "ed2k",
        total_bytes = link.size,
        parts = aidm_core::ed2k::peer::part_count(link.size),
    );
    let id = args.id;
    let (cached, server_list, kad_enabled, global_cap, max_connections) = {
        let conn = args.db.lock().unwrap();
        let snap =
            settings::Snapshot::load(&conn).unwrap_or_else(|_| settings::Snapshot::defaults());
        (
            model::list_ed2k_sources(&conn, id, 128).unwrap_or_default(),
            settings::get(&conn, "ed2k.servers")
                .ok()
                .flatten()
                .and_then(|v| settings::parse_ed2k_servers(&v).ok())
                .unwrap_or_default(),
            settings::get(&conn, "ed2k.kad_enabled")
                .ok()
                .flatten()
                .as_deref()
                != Some("false"),
            snap.gates.max_conns_total.max(1),
            // 连接预算只有一个解析器：每服务器例外 > 全局闸门（`hosts::task_conns`）；
            // 再由候选源数与分片数收窄。
            aidm_core::hosts::task_conns(&conn, &row.url_orig) as usize,
        )
    };
    let mut discovery_cfg = discovery::SourceDiscoveryCfg {
        file_hash: link.hash,
        file_size: link.size,
        user_hash,
        ..Default::default()
    };
    // 连续超时/0 源的服务器冷却 30 分钟，后续轮次不再优先使用。
    const SERVER_COOLDOWN_MS: i64 = 30 * 60 * 1000;
    let bad_servers = {
        let conn = args.db.lock().unwrap();
        model::ed2k_bad_servers(&conn, model::now_ms(), SERVER_COOLDOWN_MS).unwrap_or_default()
    };
    for (host, port) in server_list {
        if bad_servers.contains(&(host.clone(), port)) {
            let conn = args.db.lock().unwrap();
            model::log_event(
                &conn,
                id,
                "ed2k_server_skipped",
                Some(&format!("{host}:{port}")),
            );
            continue;
        }
        if let Ok(addr) = crate::ed2k::peer_session::resolve_source(&host, port) {
            discovery_cfg.servers.push(addr);
        }
    }
    // 明确配置的回环服务器可用于本地 eD2k/LAN 服务和真实 socket 验收；
    // 链接自带源全是回环时同理（否则 XS/查源回来的 127.0.0.1 会被过滤掉）。
    // 公网任务不受影响：任一非回环源存在即关闭放行。
    let local_sources_only = !cached.is_empty()
        && cached.iter().all(|s| {
            s.host.eq_ignore_ascii_case("localhost")
                || s.host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
    discovery_cfg.allow_private_addresses =
        discovery_cfg.servers.iter().any(|s| s.ip().is_loopback()) || local_sources_only;
    let use_index = !discovery_cfg.allow_private_addresses && !local_sources_only;
    if kad_enabled {
        // 优先用刷新过的 nodes.dat（库里最新一份），退回编译期内嵌样本。
        discovery_cfg.kad_seeds = {
            let conn = args.db.lock().unwrap();
            crate::ed2k::kad_bootstrap::bootstrap_nodes(&conn)
        };
    }
    known_out.store(cached.len() as u64, Ordering::Relaxed);
    if !cached.is_empty() {
        first_standard_source.store(true, Ordering::SeqCst);
    }
    let known = known_out;
    let seen = Mutex::new(HashSet::<SocketAddr>::new());
    let (source_tx, source_rx) = mpsc::channel();
    // 源地址留档：一次性 channel 被第一轮池消费后无法二次投递，
    // 兜底轮（私有池失败、标准池需接管整包）靠这里重放全部已知源。
    let source_log = Arc::new(Mutex::new(Vec::<SocketAddr>::new()));
    // 源交换（XS）是独立通道：不断开查源完成信号，只补增量源。
    let (xs_tx, xs_rx) = mpsc::channel::<SocketAddr>();
    // 查源中继结束即置位：XS 转发线程持有 source_tx 克隆，
    // 通道断开信号不再可靠，池子以此标志做快速退出（见 MultiSourceCfg::feed_done）。
    let relay_finished = Arc::new(AtomicBool::new(false));
    let allow_private_xs = discovery_cfg.allow_private_addresses;
    for source in &cached {
        if let Ok(addr) = crate::ed2k::peer_session::resolve_source(&source.host, source.port) {
            if seen.lock().unwrap().insert(addr) {
                let _ = source_tx.send(addr);
            }
        }
    }
    *args.live.p2p.lock().unwrap() = Some(aidm_ipc::P2pView {
        phase: "discovering".into(),
        known_sources: cached.len() as u32,
        max_connections: max_connections as u32,
        total_parts: aidm_core::ed2k::peer::part_count(link.size) as u32,
        ..Default::default()
    });
    args.live.total_bytes.store(link.size, Ordering::Relaxed);
    {
        let conn = args.db.lock().unwrap();
        let _ = model::set_status(&conn, id, Status::Connecting, None);
        model::log_event(
            &conn,
            id,
            "ed2k_start",
            Some(&format!(
                "mode=multi_source cached={} max_peers={max_connections}",
                cached.len()
            )),
        );
    }
    let discovery_done = Arc::new(AtomicBool::new(false));
    let hooks = Hooks {
        args,
        global_cap,
        task_limiter: TokenBucket::new(row.speed_limit_kbps.max(0) as u64),
    };
    let receiving = Mutex::new(HashSet::new());
    let queue_ranks = Mutex::new(HashMap::<SocketAddr, u16>::new());
    let on_event = |event: pool::PeerEvent| {
        let (kind, detail) = match event {
            pool::PeerEvent::Connecting { addr } => ("ed2k_try_source", addr.to_string()),
            pool::PeerEvent::Queued { addr, rank } => {
                if let Some(rank) = rank {
                    queue_ranks.lock().unwrap().insert(addr, rank);
                }
                ("ed2k_peer_queue", format!("{addr} rank={rank:?}"))
            }
            pool::PeerEvent::Receiving { addr, .. } => {
                queue_ranks.lock().unwrap().remove(&addr);
                if !receiving.lock().unwrap().insert(addr) {
                    return;
                }
                ("ed2k_peer_receiving", addr.to_string())
            }
            pool::PeerEvent::Finished {
                addr,
                network_bytes,
                error,
            } => {
                queue_ranks.lock().unwrap().remove(&addr);
                let useful = network_bytes > 0
                    && error
                        .as_ref()
                        .is_none_or(|e| !e.contains("hash") && !e.contains("corrupt"));
                if useful || error.is_some() {
                    let conn = args.db.lock().unwrap();
                    let _ = model::note_ed2k_source_result(
                        &conn,
                        id,
                        &addr.ip().to_string(),
                        addr.port(),
                        useful,
                    );
                }
                // 一次对端会话**结束**时记一条，用 `outcome` 表达结果。
                //
                // 之前按结果拆成 ok/failed/idle 三种 kind，而 ok 的定义是
                // “错误码不含 hash/corrupt”——于是 `ed2k_peer_low_score`、
                // `ed2k_transfer_idle_timeout` 这类错误会被记成 `ed2k_peer_ok`
                // 且 detail 里带着 error。看事件的人无法区分“真成功”和
                // “失败但传了一点字节”，阶段 D 排查坏源时会直接瞎掉。
                let outcome = if error.is_none() {
                    if useful {
                        "progress"
                    } else {
                        "idle"
                    }
                } else if useful {
                    // 传了有用字节才断的：部分成功，仍要保留 error。
                    "fail_useful"
                } else {
                    "fail"
                };
                (
                    "ed2k_peer_session_end",
                    format!("{addr} bytes={network_bytes} outcome={outcome} error={error:?}"),
                )
            }
        };
        let conn = args.db.lock().unwrap();
        model::log_event(&conn, id, kind, Some(&detail));
    };
    let private_receiving = Mutex::new(HashSet::new());
    let on_private_event = |event: pool::PeerEvent| {
        // These are UDP transport endpoints, never standard eD2k source records.
        let (kind, detail) = match event {
            pool::PeerEvent::Connecting { addr } => ("private_try_source", addr.to_string()),
            pool::PeerEvent::Queued { addr, rank } => {
                ("private_peer_queue", format!("{addr} rank={rank:?}"))
            }
            pool::PeerEvent::Receiving { addr, .. } => {
                if !private_receiving.lock().unwrap().insert(addr) {
                    return;
                }
                ("private_peer_receiving", addr.to_string())
            }
            pool::PeerEvent::Finished {
                addr,
                network_bytes,
                error,
            } => {
                private_receiving.lock().unwrap().remove(&addr);
                (
                    if error.is_some() {
                        "private_peer_failed"
                    } else {
                        "private_peer_finished"
                    },
                    format!("{addr} bytes={network_bytes} error={error:?}"),
                )
            }
        };
        let conn = args.db.lock().unwrap();
        model::log_event(&conn, id, kind, Some(&detail));
    };
    let stop = || {
        args.cancel.load(Ordering::SeqCst)
            || args.pause.load(Ordering::SeqCst)
            || switch_http.load(Ordering::SeqCst)
    };
    let private_identity = private_identity(&user_hash, id);
    // 只读归属观测：把池内的 owner→peer→part 关系回写到
    // `LiveState`，让统一视图能展示**真实**的“哪个源负责哪个区间”。
    // 回调只写一个 Vec，不建连、不改调度、不碰文件，因此 legacy 行为不变。
    let live_owner = args.live.clone();
    let on_ownership = move |parts: &[crate::ed2k::multi_source::PartOwnership]| {
        if let Ok(mut slot) = live_owner.ownership.lock() {
            *slot = parts.to_vec();
        }
    };
    // 领取序号基础：优先用任务级持久号段（C1：跨重启不依赖墙钟）；
    // 数据库不可用时退回进程内单调基数，保证至少不撞号。
    let claim_reserve = (aidm_core::ed2k::peer::part_count(link.size) as u64) * 16 + 1024;
    let claim_base = {
        let mut conn = args.db.lock().unwrap();
        // 运行记录不存在时先建一条（默认 legacy），否则分配号段会报错。
        let _ = aidm_core::download::store::ensure_runtime(&conn, id);
        aidm_core::download::store::allocate_claim_seq(&mut conn, id, claim_reserve)
            .unwrap_or_else(|_| crate::ed2k::multi_source::fallback_claim_seq())
    };
    // 号段续领：池耗尽许可时从这里再拿一段。失败返回 None，池会报
    // `ed2k_claim_seq_exhausted`，不会退回墙钟基数。
    let claim_refill: Arc<dyn Fn(u64) -> Option<(u64, u64)> + Send + Sync> = {
        let db = args.db.clone();
        Arc::new(move |want: u64| {
            let mut conn = db.lock().unwrap();
            aidm_core::download::store::allocate_claim_seq(&mut conn, id, want)
                .ok()
                .map(|start| (start, want))
        })
    };
    let cfg = pool::MultiSourceCfg {
        user_hash,
        file_hash: link.hash,
        file_size: link.size,
        target: part_path,
        max_connections,
        // 慢源保留：180 KiB 块在 8 秒读超时下要求对端 ≥22KB/s，否则误杀慢源；
        // 30 秒收超时 + 60 秒传输空闲上限（会话层）才断，连接 10 秒给跨国握手留余量。
        // 三者都在并行线程里等待，不阻塞其他源。
        connect_timeout: Duration::from_secs(10),
        read_timeout: Duration::from_secs(30),
        discovery_timeout: Duration::from_secs(50),
        stop: &stop,
        hooks: &hooks,
        on_event: &on_event,
        xs_sources: None,
        feed_done: None,
        aich_root: link
            .aich_root
            .as_deref()
            .and_then(aidm_core::ed2k::aich::decode_base32),
        // 第 1 步：过滤器先不启用（None = 单池独占整个文件，行为与历史一致）。
        part_filter: None,
        // 真实归属观测：与上面的 `on_ownership` 回调配合，只读。
        on_ownership: Some(&on_ownership),
        expansion: None,
        claim_base,
        claim_reserve,
        claim_refill: Some(claim_refill.clone()),
    };
    // ---- 进度单点聚合 ---------------------------------------------------
    // 两个池并发时只能有一个写库/上抛点：`set_segment_progress` 是无条件
    // UPDATE，谁后写谁生效；各自上报会让进度在两个池的字节数之间来回跳，
    // 甚至被"较小值"覆盖而回退。聚合器必须在 `thread::scope` 之外定义，
    // 作用域线程只能借用它的数据。
    let agg = ProgressAgg {
        args,
        known: &known,
        queue_ranks: &queue_ranks,
        size: link.size,
        total_parts: aidm_core::ed2k::peer::part_count(link.size),
        max_connections: max_connections as u32,
        left: SideCounters::default(),
        right: SideCounters::default(),
        // 跨轮次续跑：上一轮已经展示过的字节就是本轮的下限。
        // 池内换源会从"当前独占分片"重新计数，若这里从 0 开始，UI 会从
        // 9.7MB 掉回 0.5MB（实测 task 14）。真实完成值仍由分片校验决定。
        floor: AtomicU64::new(args.live.done_bytes.load(Ordering::Relaxed)),
        persist: Mutex::new(PersistClock {
            last: Instant::now(),
            phase: "discovering",
        }),
    };
    let std_stop = Arc::new(AtomicBool::new(false));
    let std_stop_gate = std_stop.clone();
    let std_stop_fn = {
        let cancel = args.cancel.clone();
        let pause = args.pause.clone();
        let switch = switch_http;
        move || {
            cancel.load(Ordering::SeqCst)
                || pause.load(Ordering::SeqCst)
                || switch.load(Ordering::SeqCst)
                || std_stop_gate.load(Ordering::Acquire)
        }
    };
    let result = std::thread::scope(|scope| {
        let (hashset_tx, hashset_rx) = mpsc::channel();
        let (metadata_tx, metadata_rx) = mpsc::channel();
        if use_index {
            let index_done = discovery_done.clone();
            let index_pause = args.pause.clone();
            let index_cancel = args.cancel.clone();
            let index_db = args.db.clone();
            let index_link = link.clone();
            let index_uri = row.url_orig.clone();
            // 查询自身有 5 秒上限；不加入传输线程的 join，结束/暂停不等待索引网络。
            std::thread::spawn(move || {
                let stop = || {
                    index_done.load(Ordering::Acquire)
                        || index_pause.load(Ordering::SeqCst)
                        || index_cancel.load(Ordering::SeqCst)
                };
                if stop() {
                    return;
                }
                let index =
                    crate::ed2k::private_index::query(&index_link, &index_uri, &private_identity);
                if stop() {
                    return;
                }
                let (event, detail) = match index {
                    Ok(Some(meta)) => {
                        let count = meta.part_hashes.len();
                        if hashset_tx.send(meta.part_hashes.clone()).is_err() {
                            return;
                        }
                        // Preserve CID/GCID for the private pool while keeping
                        // the same verified hashes available to standard fallback.
                        let _ = metadata_tx.send(meta);
                        (
                            "ed2k_index_hashset",
                            format!("hashes={count} identity_verified=true"),
                        )
                    }
                    Ok(None) => ("ed2k_index_empty", "no_file_metadata".into()),
                    Err(e) if private_index::is_integrity_rejection(&e) => (
                        "ed2k_index_rejected",
                        format!("reason={e} identity_verified=false"),
                    ),
                    Err(e) => ("ed2k_index_failed", e),
                };
                let conn = index_db.lock().unwrap();
                model::log_event(&conn, id, event, Some(&detail));
            });
        }
        let local_stop = discovery_done.clone();
        let pause = args.pause.clone();
        let cancel = args.cancel.clone();
        let relay_finished_flag = relay_finished.clone();
        let discovery_done = &discovery_done;
        let known = &known;
        let seen = &seen;
        let stop = &stop;
        // 源交换（XS）转发：合法性过滤 + kind='pex' 落库后并入发现流，
        // 由池调度器的去重集统一排重。通道关闭（任务收尾）即退出。
        let xs_fwd_tx = source_tx.clone();
        let xs_log = source_log.clone();
        // 句柄由作用域结束时统一 join；命名下划线前缀避免未使用警告。
        let _xs_fwd = scope.spawn(move || {
            let mut sent = HashSet::new();
            while let Ok(addr) = xs_rx.recv() {
                if stop() {
                    break;
                }
                let usable = match addr.ip() {
                    std::net::IpAddr::V4(ip) => {
                        addr.port() != 0
                            && crate::ed2k::source_discovery::allowed_peer(ip, allow_private_xs)
                    }
                    _ => false,
                };
                if !usable || !sent.insert(addr) {
                    continue;
                }
                {
                    let conn = args.db.lock().unwrap();
                    let _ = model::upsert_ed2k_source(
                        &conn,
                        id,
                        &addr.ip().to_string(),
                        addr.port(),
                        Some("pex"),
                    );
                }
                known.fetch_add(1, Ordering::Relaxed);
                xs_log.lock().unwrap().push(addr);
                if xs_fwd_tx.send(addr).is_err() {
                    break;
                }
            }
        });
        let relay_log = source_log.clone();
        let relay = scope.spawn(move || {
            let handle = discovery::start(discovery_cfg, move || {
                local_stop.load(Ordering::Acquire)
                    || pause.load(Ordering::SeqCst)
                    || cancel.load(Ordering::SeqCst)
            });
            // 发现阶段的"收尾审计"抽成闭包：主循环与**收尾排空**共用。
            // 为什么需要排空：下载可能先于发现阶段完成（stop() 已置位），此时通道里
            // 还压着 ServerFinished/KadFinished；若只按主循环退出，就会丢掉
            // "登录过服务器 / 查过 Kad" 的审计记录 —— 源已入库、已用于下载，记录却没了。
            let log_finish = |ev: &discovery::DiscoveryEvent| {
                let conn = args.db.lock().unwrap();
                match ev {
                    discovery::DiscoveryEvent::ServerFinished { addr, result } => match result {
                        Ok(r) => {
                            let useful = r.usable_sources > 0;
                            let _ = model::note_ed2k_server_result(
                                &conn,
                                &addr.ip().to_string(),
                                addr.port(),
                                useful,
                                model::now_ms(),
                            );
                            if r.logged_in {
                                model::log_event(
                                    &conn,
                                    id,
                                    "ed2k_server_login",
                                    Some(&format!("{addr} id={:?}", r.client_id)),
                                );
                            }
                            model::log_event(
                                &conn,
                                id,
                                "ed2k_server_sources",
                                Some(&format!(
                                    "{addr} direct={} callback_required={} elapsed_ms={}",
                                    r.usable_sources,
                                    r.low_id_sources,
                                    r.elapsed.as_millis()
                                )),
                            );
                        }
                        Err(e) => {
                            let _ = model::note_ed2k_server_result(
                                &conn,
                                &addr.ip().to_string(),
                                addr.port(),
                                false,
                                model::now_ms(),
                            );
                            model::log_event(
                                &conn,
                                id,
                                "ed2k_server_failed",
                                Some(&format!("{addr} {e}")),
                            )
                        }
                    },
                    discovery::DiscoveryEvent::KadFinished { result } => match result {
                        Ok(r) => model::log_event(
                            &conn,
                            id,
                            "ed2k_kad_sources",
                            Some(&format!(
                                "found={} bootstrap={}/{} lookup={}/{} source={}/{}",
                                r.sources.len(),
                                r.bootstrap_replies,
                                r.bootstrap_sent,
                                r.lookup_replies,
                                r.lookup_sent,
                                r.source_replies,
                                r.source_sent
                            )),
                        ),
                        Err(e) => model::log_event(&conn, id, "ed2k_kad_failed", Some(&e)),
                    },
                    _ => {}
                }
            };
            while !discovery_done.load(Ordering::Acquire) && !stop() {
                match handle.events.recv_timeout(Duration::from_millis(25)) {
                    Ok(discovery::DiscoveryEvent::Source { addr, kind, .. }) => {
                        let name = match kind {
                            discovery::SourceKind::Server(_) => "server",
                            discovery::SourceKind::Kad => "kad",
                        };
                        let mut first = seen.lock().unwrap();
                        let fresh = first.insert(addr);
                        drop(first);
                        first_standard_source.store(true, Ordering::SeqCst);
                        let conn = args.db.lock().unwrap();
                        let _ = model::upsert_ed2k_source(
                            &conn,
                            id,
                            &addr.ip().to_string(),
                            addr.port(),
                            Some(name),
                        );
                        drop(conn);
                        if fresh {
                            known.fetch_add(1, Ordering::Relaxed);
                            relay_log.lock().unwrap().push(addr);
                            if source_tx.send(addr).is_err() {
                                break;
                            }
                        }
                    }
                    Ok(ev @ discovery::DiscoveryEvent::ServerFinished { .. })
                    | Ok(ev @ discovery::DiscoveryEvent::KadFinished { .. }) => log_finish(&ev),
                    Ok(discovery::DiscoveryEvent::Finished(_))
                    | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                }
            }
            // 收尾排空：下载可能先于发现阶段完成（上面循环因 stop() 退出），
            // 通道里可能还压着 ServerFinished/KadFinished —— 必须补记审计，
            // 否则"登录过服务器"这类记录会时有时无（实测 1/3 概率丢失）。
            let drain_until = Instant::now() + Duration::from_secs(2);
            loop {
                match handle.events.recv_timeout(Duration::from_millis(20)) {
                    Ok(ev @ discovery::DiscoveryEvent::ServerFinished { .. })
                    | Ok(ev @ discovery::DiscoveryEvent::KadFinished { .. }) => log_finish(&ev),
                    Ok(discovery::DiscoveryEvent::Finished(_))
                    | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    Ok(_) => {}
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        if Instant::now() >= drain_until {
                            break;
                        }
                    }
                }
            } // 查源通道到此结束（XS 转发线程不持有本句柄，见 feed_done 注释）。
            relay_finished_flag.store(true, Ordering::Release);
            drop(source_tx);
            handle.join()
        });
        let total_parts = agg.total_parts;
        // 校验片哈希集：400 ms 上限拿，绝不拖住标准池。
        let mut metadata = if use_index {
            wait_metadata(&metadata_rx, stop, Duration::from_millis(400)).filter(|meta| {
                let verified = metadata_matches(link, meta);
                if !verified {
                    let conn = args.db.lock().unwrap();
                    model::log_event(
                        &conn,
                        id,
                        "private_index_rejected",
                        Some("file_hashset_mismatch"),
                    );
                }
                verified
            })
        } else {
            None
        };
        // 双池并发只在拿到可信校验片时开启：没有哈希集就无法确认两池写的是
        // 同一份数据的同一分片。
        let dual = metadata.is_some() && !stop() && max_connections >= STANDARD_MIN_CONNS;
        // 标准池的份额：按 4 取模，只拿 1/4 分片。私有通道稳态带宽更高，但它要先花
        // 30~60 秒做 SN 查询与打洞 —— 那段时间只有标准池能出速度，所以必须并发；
        // 若等私有池跑完再开标准池，恢复后会长时间零速度。
        // 连接预算太小（<4）时不做双池：拆开会让两边都只剩一两根连接，反而更慢。
        const STANDARD_MIN_CONNS: usize = 4;
        const STANDARD_STRIDE: usize = 4;
        let (std_filter, priv_filter) = if dual {
            (
                Some(Arc::new(pool::PartFilter::modulo(
                    total_parts,
                    STANDARD_STRIDE,
                    0,
                ))),
                Some(Arc::new(pool::PartFilter::from_indices(
                    total_parts,
                    (0..total_parts).filter(|idx| idx % STANDARD_STRIDE != 0),
                ))),
            )
        } else {
            (None, None)
        };
        // 连接预算按池拆开，两池之和不超过任务的 max_connections。
        let (std_max, priv_max) = if dual {
            let private = (max_connections / 4).max(2).min(max_connections);
            (max_connections - private, private)
        } else {
            (max_connections, max_connections)
        };
        let expand = Arc::new(pool::ExpandSignal::default());
        let private_filter_handoff = priv_filter.clone();
        let std_cfg = pool::MultiSourceCfg {
            max_connections: std_max,
            xs_sources: Some(xs_tx.clone()),
            feed_done: Some(relay_finished.clone()),
            stop: &std_stop_fn,
            part_filter: std_filter,
            expansion: None,
            ..cfg.clone()
        };
        // 兜底轮也要哈希集（一次性 channel 已随第一轮关闭），提前留一份。
        let fallback_hashes = metadata.as_ref().map(|meta| meta.part_hashes.clone());
        // 私有池连配置和元数据一起**按值**搬进线程：作用域线程只能借用
        // `thread::scope` 之外的数据，借用函数体内的局部量编译器不接受。
        let private_job = metadata.take().map(|meta| {
            (
                pool::MultiSourceCfg {
                    max_connections: priv_max,
                    on_event: &on_private_event,
                    // 私有传输不跑 eD2k 源交换：它的对端地址不是标准源记录。
                    // 两个非 Copy 字段都显式置空，其余字段由 `..cfg` 复制。
                    xs_sources: None,
                    feed_done: None,
                    part_filter: priv_filter,
                    expansion: Some(expand.clone()),
                    ..cfg.clone()
                },
                meta,
            )
        });
        // 私有池先挂上去（建链慢），标准池立刻开跑自己那份分片。
        let private_handle = match private_job {
            Some((private_cfg, meta)) if !stop() => {
                // 私有通道启动（聚合一条，不逐 peer）：与标准池的 transfer.start 用同一事件名，
                // 由 `mode` 区分；task 字段由 worker 的 enter_task 继承。
                tracing::info!(
                    event = "transfer.start",
                    phase = "transfer",
                    proto = "ed2k",
                    mode = "private",
                );
                let agg_ref = &agg;
                let mut private_known = 0usize;
                Some(scope.spawn(move || {
                    private_pool::download(
                        &private_cfg,
                        link,
                        &row.url_orig,
                        &meta,
                        &private_identity,
                        |count| {
                            // The private callback is a deduplicated total snapshot.
                            if count > private_known {
                                known.fetch_add((count - private_known) as u64, Ordering::Relaxed);
                                private_known = count;
                            }
                        },
                        |p| agg_ref.publish(&agg_ref.right, p),
                    )
                }))
            }
            _ => None,
        };
        let standard_handle = {
            let agg_ref = &agg;
            scope.spawn(move || {
                pool::download_from_sources_with_hashsets(
                    &std_cfg,
                    source_rx,
                    Some(hashset_rx),
                    |p| agg_ref.publish(&agg_ref.left, p),
                )
            })
        };
        let standard_result = {
            // 私有池先完成自己的份额时，会置 `expand.ready`。此时停止标准池，
            // 等它释放连接后，把全部剩余分片交给仍活着的私有快源；避免快源
            // 被静态 filter 提前送走。标准池先完成或私有池失败时走普通收尾。
            let mut stopped_standard = false;
            if let Some(handle) = &private_handle {
                loop {
                    if expand.ready.load(Ordering::Acquire) {
                        std_stop.store(true, Ordering::SeqCst);
                        stopped_standard = true;
                        break;
                    }
                    if handle.is_finished() || standard_handle.is_finished() {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
            let result = standard_handle
                .join()
                .map_err(|_| "ed2k_standard_panic".to_string())
                .and_then(|outcome| outcome);
            if private_handle.is_some() {
                if let Some(filter) = private_filter_handoff.as_ref() {
                    filter.allow_all();
                }
                expand.all.store(true, Ordering::SeqCst);
                if stopped_standard {
                    agg.retire_left();
                    let conn = args.db.lock().unwrap();
                    model::log_event(
                        &conn,
                        id,
                        "ed2k_handoff",
                        Some("private_share_done standard_stopped private_takes_all"),
                    );
                }
            }
            result
        };
        let private_result = private_handle.map(|handle| {
            handle
                .join()
                .map_err(|_| "ed2k_private_panic".to_string())
                .and_then(|outcome| outcome)
        });
        // 关闭 XS 通道（各池的克隆随线程结束已释放），转发线程才会退出。
        drop(xs_tx);
        discovery_done.store(true, Ordering::Release);
        let _ = relay.join();
        let standard_parts = standard_result
            .as_ref()
            .map(|out| out.verified_parts)
            .unwrap_or(0);
        let private_parts = private_result
            .as_ref()
            .and_then(|outcome| outcome.as_ref().ok())
            .map(|out| out.verified_parts)
            .unwrap_or(0);
        let aich_blocks = standard_result
            .as_ref()
            .map(|out| out.aich_recovered_blocks)
            .unwrap_or(0)
            + private_result
                .as_ref()
                .and_then(|outcome| outcome.as_ref().ok())
                .map(|out| out.aich_recovered_blocks)
                .unwrap_or(0);
        let result: Result<pool::MultiDownload, String> = if stop() {
            Err("ed2k_stopped".into())
        } else if !dual {
            // 单池独占整包（无元数据）：池内已做 set_len + 整包校验。
            agg.settle(standard_parts);
            standard_result
        } else if total_parts > 0 && standard_parts + private_parts >= total_parts {
            // 两池分片互不相交，覆盖满即整包到齐。分片 MD4 各自已校验，
            // 但整包 MD4 只能在全部分片落盘后算一次。
            agg.begin_verify();
            let sized = std::fs::OpenOptions::new()
                .write(true)
                .open(part_path)
                .and_then(|file| file.set_len(link.size));
            match sized {
                Err(e) => {
                    agg.settle(total_parts);
                    Err(format!("ed2k_truncate: {e}"))
                }
                Ok(()) => match pool::verify_interruptible(&cfg) {
                    Ok(true) => {
                        agg.settle(total_parts);
                        Ok(pool::MultiDownload {
                            written: link.size,
                            verified_parts: total_parts,
                            total_parts,
                            stopped: false,
                            aich_recovered_blocks: aich_blocks,
                        })
                    }
                    Ok(false) => {
                        agg.settle(total_parts);
                        Err("ed2k_hash_mismatch".into())
                    }
                    Err(e) => {
                        agg.settle(total_parts);
                        Err(e)
                    }
                },
            }
        } else {
            // 兜底：私有池没建起来或中途失败 —— 标准池接管整包。
            // 第一轮的源 channel 已随池关闭，用 source_log 重放全部已知源。
            let (kind, detail) = match &private_result {
                Some(Err(e)) => ("private_pool_fallback", e.clone()),
                Some(Ok(out)) => (
                    "private_pool_incomplete",
                    format!(
                        "verified={}/{} owned_bytes={}",
                        out.verified_parts, out.total_parts, out.written
                    ),
                ),
                None => ("private_pool_absent", "no_metadata".into()),
            };
            {
                let conn = args.db.lock().unwrap();
                model::log_event(&conn, id, kind, Some(&detail));
            }
            // 私有池已退出：先清掉它的计数，否则兜底轮的字节数会与它叠加。
            agg.set_floor();
            agg.retire_right();
            let (replay_tx, replay_rx) = mpsc::channel();
            for addr in source_log.lock().unwrap().iter() {
                let _ = replay_tx.send(*addr);
            }
            drop(replay_tx);
            let (hash_tx, hash_rx) = mpsc::channel();
            if let Some(hashes) = fallback_hashes.clone() {
                let _ = hash_tx.send(hashes);
            }
            drop(hash_tx);
            // 兜底轮开始前先清掉上一轮的归属：否则快照会继续展示已经不存在的
            // 标准池通路（用户复核指出的“旧归属失效”）。清空是只读侧的唯一效果，
            // 不影响下载本身。
            args.live.ownership.lock().unwrap().clear();
            let live_fallback = args.live.clone();
            let on_ownership_fallback =
                move |parts: &[crate::ed2k::multi_source::PartOwnership]| {
                    if let Ok(mut slot) = live_fallback.ownership.lock() {
                        *slot = parts.to_vec();
                    }
                };
            // 兜底轮必须拿**新号段**：`..cfg` 会继承标准池的 `claim_base`，
            // 两池序号一旦重叠，同一 part 的两次归属会撞成同一个 assignment_id。
            let fallback_claim_base = {
                let mut conn = args.db.lock().unwrap();
                aidm_core::download::store::allocate_claim_seq(&mut conn, id, claim_reserve)
                    .unwrap_or_else(|_| crate::ed2k::multi_source::fallback_claim_seq())
            };
            let fallback_cfg = pool::MultiSourceCfg {
                max_connections,
                xs_sources: None,
                feed_done: Some(relay_finished.clone()),
                part_filter: None,
                claim_base: fallback_claim_base,
                claim_reserve,
                claim_refill: Some(claim_refill.clone()),
                // 兜底池也要接归属观测：否则“换源后的归属”在快照里永远看不到。
                on_ownership: Some(&on_ownership_fallback),
                expansion: None,
                ..cfg.clone()
            };
            let agg_ref = &agg;
            let outcome = pool::download_from_sources_with_hashsets(
                &fallback_cfg,
                replay_rx,
                Some(hash_rx),
                |p| agg_ref.publish(&agg_ref.left, p),
            );
            let parts = outcome.as_ref().map(|out| out.verified_parts).unwrap_or(0);
            agg.settle(parts);
            outcome
        };
        result
    });
    persist_single(args, args.live.done_bytes.load(Ordering::Relaxed));
    if args.cancel.load(Ordering::SeqCst) {
        return WorkerEnd::Cancelled;
    }
    if args.pause.load(Ordering::SeqCst) {
        let conn = args.db.lock().unwrap();
        let _ = model::set_status(&conn, id, Status::Paused, None);
        model::log_event(&conn, id, "paused", Some("ed2k multi-source"));
        return WorkerEnd::Paused;
    }
    match result {
        Ok(out) if out.is_complete() => {
            super::finish_ed2k(args, row, part_path, &link.hash_hex, out.written)
        }
        Ok(_) => super::ed2k_wait_sources(
            args,
            id,
            &link.hash_hex,
            link.size,
            known.load(Ordering::Relaxed) as usize,
        ),
        Err(e) => WorkerEnd::Failed(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_identity_is_stable_per_profile_task_and_does_not_reuse_another_task() {
        let first = private_identity(&[1; 16], 40);
        assert_eq!(first, private_identity(&[1; 16], 40));
        assert_ne!(first, private_identity(&[1; 16], 41));
        assert_ne!(first, private_identity(&[2; 16], 40));
        assert_eq!(&first[14..], b"NM");
        assert!(first[..14].iter().all(u8::is_ascii_hexdigit));
    }

    #[test]
    fn cancelled_metadata_wait_never_waits_for_detached_network_request() {
        let (_sender, receiver) = mpsc::channel::<()>();
        let started = Instant::now();
        assert!(wait_metadata(&receiver, &|| true, Duration::from_secs(5)).is_none());
        assert!(started.elapsed() < Duration::from_millis(100));
        // A stop raised after the initial check is observed on the next short poll.
        let polls = AtomicU64::new(0);
        let started = Instant::now();
        assert!(wait_metadata(
            &receiver,
            &|| polls.fetch_add(1, Ordering::SeqCst) > 0,
            Duration::from_secs(5),
        )
        .is_none());
        assert!(started.elapsed() < Duration::from_millis(200));
    }

    #[test]
    fn metadata_wait_accepts_ready_value_and_disconnected_index_falls_back_immediately() {
        let (sender, receiver) = mpsc::channel();
        sender.send(7).unwrap();
        assert_eq!(wait_metadata(&receiver, &|| false, Duration::ZERO), Some(7));
        drop(sender);
        let started = Instant::now();
        assert!(wait_metadata(&receiver, &|| false, Duration::from_secs(5)).is_none());
        assert!(started.elapsed() < Duration::from_millis(100));
    }

    #[test]
    fn mismatched_hashset_never_enters_private_backend() {
        let parts = vec![[1; 16], [2; 16]];
        let link = aidm_core::ed2k::FileLink {
            name: "fixture.bin".into(),
            size: aidm_core::ed2k::PART_SIZE + 1,
            hash: aidm_core::ed2k::hash::md4(&parts.concat()),
            hash_hex: String::new(),
            sources: Vec::new(),
            aich_root: None,
        };
        let mut meta = private_index::Metadata {
            part_hashes: parts,
            cid: [1; 20],
            gcid: [2; 20],
            block_size: 2097152,
            gcid_level: 81,
        };
        assert!(metadata_matches(&link, &meta));
        meta.part_hashes[0][0] ^= 1;
        assert!(!metadata_matches(&link, &meta));
        meta.part_hashes.pop();
        assert!(!metadata_matches(&link, &meta));
        let mut single = link.clone();
        single.size = 1;
        single.hash = [3; 16];
        meta.part_hashes = vec![[3; 16]];
        assert!(metadata_matches(&single, &meta));
        meta.part_hashes[0][0] ^= 1;
        assert!(!metadata_matches(&single, &meta));
    }
}

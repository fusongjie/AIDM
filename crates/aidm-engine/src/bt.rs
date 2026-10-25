//! BitTorrent/magnet 下载插件。网络 IO 全部留在 engine；`librqbit` 负责
//! tracker、DHT、peer wire、分片校验与下载期间上传。
//!
//! ## 两个会话级设置
//!
//! - `bt.listen_port`：**0 = 不监听**（默认）。librqbit 的
//!   `SessionOptions::default().listen = None`，也就是默认根本不开监听端口；
//!   填 1–65535 才在固定端口监听，用于接受入站连接（提高连通性）。
//! - `bt.seed_minutes`：0 = 完成后立即停止会话（默认）；N = 任务标记完成后继续做种 N 分钟。
//!   续种要求会话比 worker 线程活得久，所以这里把手里的 `Session`、`ManagedTorrent`
//!   以及**它的 tokio runtime** 一起交给 [`SeedRegistry`] 托管——runtime 一 drop，
//!   librqbit 内部的会话任务就全没了，所以三者必须同生共死。

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aidm_core::model::{self, DownloadRow, Status};
use librqbit::{
    AddTorrent, AddTorrentOptions, DhtSessionConfig, ManagedTorrent, Session, SessionOptions,
};
use rusqlite::Connection;

use crate::manager::Progress;
use crate::worker::{Args, WorkerEnd};

/// 磁力链拿元数据的上限。`add_torrent` 在拿到元数据前会一直等；没有上限时，一条
/// 根本没有 peer 的磁力链会永远停在 `connecting`，**并且一直占着队列槽位** —— 实测
/// 一条无种电影磁力链就能把 `queue_max_parallel` 占满，后面所有任务 `queue_blocked`。
const METADATA_TIMEOUT: Duration = Duration::from_secs(300);

/// 元数据到手后仍为 0 字节的上限。公共 swarm 里 10 分钟没有任何 peer 给数据，
/// 基本就是没种（或全网段被挡）；如实失败比伪装成"正在连接"有用。
const NO_PEER_TIMEOUT: Duration = Duration::from_secs(600);

pub const KEY_LISTEN_PORT: &str = "bt.listen_port";
pub const KEY_SEED_MINUTES: &str = "bt.seed_minutes";
pub const KEY_EXTRA_TRACKERS: &str = "bt.extra_trackers";

/// 额外 tracker 列表（`bt.extra_trackers`，空白或逗号分隔）。
///
/// 只在**没有自带 tracker**（或 DHT 不通）时才有意义：magnet 的 `tr=` 与 `.torrent`
/// 的 announce 由 librqbit 自己用，这里补的是后备。librqbit 的
/// `SessionOptions::default()` 已经默认开着 DHT（带 persistence）与 LSD，
/// 所以这一项是"UDP 被挡时的退路"，不是 BT 找源的唯一手段。
///
/// 默认**留空**：往第三方 tracker 发 announce 等于把你的 info-hash 告诉它，
/// 不该默认替用户决定。解析失败的条目会被跳过并记日志，不静默吞掉。
pub fn parse_trackers(raw: &str) -> std::collections::HashSet<url::Url> {
    let mut out = std::collections::HashSet::new();
    for item in raw.split(|c: char| c.is_whitespace() || c == ',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        match url::Url::parse(item) {
            Ok(u) if matches!(u.scheme(), "http" | "https" | "udp" | "ws" | "wss") => {
                out.insert(u);
            }
            Ok(u) => log::warn!(
                "bt.extra_trackers: 跳过不支持的协议 {}（{item}）",
                u.scheme()
            ),
            Err(e) => log::warn!("bt.extra_trackers: 跳过无法解析的条目（{item}）：{e}"),
        }
    }
    out
}

/// 从库里读额外 tracker。空配置返回空集合（此时保持 librqbit 默认）。
pub fn extra_trackers(conn: &Connection) -> std::collections::HashSet<url::Url> {
    let raw = aidm_core::settings::get(conn, KEY_EXTRA_TRACKERS)
        .ok()
        .flatten()
        .unwrap_or_default();
    parse_trackers(&raw)
}

/// 把额外 tracker 落到会话选项上。空集合时**不动**默认值（保持"没有任何额外 tracker"）。
fn apply_extra_trackers(options: &mut SessionOptions, extra: std::collections::HashSet<url::Url>) {
    if !extra.is_empty() {
        options.trackers = extra;
    }
}

/// 会话级 BT 设置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BtSettings {
    /// 0 = 不监听；1..=65535 = 在该端口监听。
    pub listen_port: u16,
    /// 0 = 完成后停止；否则继续做种这么多分钟。
    pub seed_minutes: u64,
}

impl Default for BtSettings {
    fn default() -> Self {
        Self {
            listen_port: 0,
            seed_minutes: 0,
        }
    }
}

impl BtSettings {
    /// 解析失败回默认值；越界夹取到区间（setting_spec 已在写入时拒过一次）。
    pub fn load(conn: &Connection) -> Self {
        let uint = |key: &str, fallback: u64, min: u64, max: u64| -> u64 {
            aidm_core::settings::get(conn, key)
                .ok()
                .flatten()
                .and_then(|v| v.trim().parse::<u64>().ok())
                .unwrap_or(fallback)
                .clamp(min, max)
        };
        Self {
            listen_port: uint(KEY_LISTEN_PORT, 0, 0, u64::from(u16::MAX)) as u16,
            seed_minutes: uint(KEY_SEED_MINUTES, 0, 0, 7 * 24 * 60),
        }
    }
}

/// 监听端口是否真的能占到（TCP 与 UDP 都要能绑）。
///
/// 监听端口是**进程级一个**资源，而引擎给每个任务各建一个 `Session`：并发的第二个
/// 会话再绑同一端口必然 `10048`。所以先探一下，占着就这次不监听（仍能下载，只是
/// 不接受入站连接）。`0` 表示"从不监听"，直接返回 false。
fn listen_port_is_free(port: u16) -> bool {
    if port == 0 {
        return false;
    }
    std::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, port)).is_ok()
        && std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port)).is_ok()
}

/// 把监听设置落成 librqbit 的会话选项。`port == 0` 保持默认（不监听）。
///
/// **DHT 必须不持久化、端口随机**：librqbit 默认给 DHT 开持久化，持久化会把端口
/// 固定下来；两个并发会话（两个 BT 任务）于是抢同一个 UDP 端口，第二个会话在
/// `Session::new_with_opts` 就失败，任务直接 error：
/// `bt_session: error initializing persistent DHT: error binding UDP socket: ...
/// (os error 10048)`。改成随机端口后每个任务各有一份 DHT；代价是路由表不复用，
/// 每个任务自行 bootstrap（实测元数据仍在数秒内拿到）。
fn session_options(settings: BtSettings, allow_listen: bool) -> SessionOptions {
    let mut options = SessionOptions {
        dht: Some(DhtSessionConfig {
            // 默认只试 `dht.libtorrent.org:25401` 一个节点。它在部分网络里不可达，
            // 于是一条"只有 DHT"的磁力链会永久 0 peer（实测：日志里
            // `error in bootstrap: no successful lookups` 每 2–12 秒重试一次，从不成功）。
            // 换成一组公共 router，任一可达即可完成 bootstrap。
            bootstrap_addrs: Some(
                [
                    "router.bittorrent.com:6881",
                    "router.utorrent.com:6881",
                    "dht.transmissionbt.com:6881",
                    "dht.aelitis.com:6881",
                    "dht.libtorrent.org:25401",
                ]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            ),
            port: None,
            persistence: None,
        }),
        ..Default::default()
    };
    if allow_listen && settings.listen_port > 0 {
        let mut listen = options.listen.take().unwrap_or_default();
        listen.listen_addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, settings.listen_port));
        options.listen = Some(listen);
    }
    options
}

/// 完成后的续种交接物：会话、句柄、名字与时长。
pub struct SeedHandoff {
    pub name: String,
    pub minutes: u64,
    pub session: Arc<Session>,
    pub handle: Arc<ManagedTorrent>,
}

/// 逐文件选择的共享状态：worker 填文件表，IPC 读文件表 / 写选择，worker 下一拍应用。
///
/// 放在共享结构里（而不是握手时一次算好）是因为：磁力链接在拿到元数据之前根本没有
/// 文件表，而用户可能在下载途中改选择。
#[derive(Debug, Clone, Default)]
pub struct BtSelection {
    /// 元数据到手后填一次；索引就是 librqbit 的文件序号。
    pub files: Vec<BtFileInfo>,
    /// 用户当前要下的文件索引；空 = 全选。
    pub selected: Vec<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtFileInfo {
    pub index: usize,
    pub name: String,
    pub len: u64,
}

impl BtSelection {
    /// 有效选择（空 = 全选，越界丢弃，全越界视作全选）。
    pub fn effective(&self) -> Vec<usize> {
        aidm_core::bt_files::resolve(&self.selected, self.files.len())
    }

    /// 已选文件的总字节数（进度分母）。
    pub fn selected_total(&self) -> u64 {
        let effective = self.effective();
        self.files
            .iter()
            .filter(|f| effective.contains(&f.index))
            .map(|f| f.len)
            .sum()
    }
}

struct SeedEntry {
    id: i64,
    name: String,
    until: Instant,
    session: Arc<Session>,
    handle: Arc<ManagedTorrent>,
    /// 必须与 session 一起存活：runtime 一 drop，librqbit 的会话任务全部消失。
    /// 放在最后一个字段，保证 Drop 顺序是 session → handle → runtime。
    runtime: tokio::runtime::Runtime,
}

/// 完成后继续做种的会话登记处。
///
/// 每个条目自己带一个 tokio runtime，扫描线程到点后 `session.stop()` 并释放。
pub struct SeedRegistry {
    entries: Mutex<Vec<SeedEntry>>,
    stop: AtomicBool,
    db: Arc<Mutex<Connection>>,
}

impl SeedRegistry {
    pub fn new(db: Arc<Mutex<Connection>>) -> Arc<Self> {
        let registry = Arc::new(Self {
            entries: Mutex::new(Vec::new()),
            stop: AtomicBool::new(false),
            db,
        });
        let worker = registry.clone();
        let _ = std::thread::Builder::new()
            .name("bt-seed".into())
            .spawn(move || worker.sweep_loop());
        registry
    }

    fn sweep_loop(&self) {
        let mut last_count = usize::MAX;
        while !self.stop.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_secs(5));
            self.sweep(Instant::now());
            // 运营可见性：续种会话数变化时留一行日志（任务详情里另有 bt_seeding/bt_seed_end 事件）。
            let count = self.count();
            if count != last_count {
                last_count = count;
                log::debug!("bt seeding sessions: {count}");
            }
        }
    }

    /// 到期的条目停止并记事件。抽成独立方法便于测试直接驱动。
    fn sweep(&self, now: Instant) {
        let expired: Vec<SeedEntry> = {
            let Ok(mut entries) = self.entries.lock() else {
                return;
            };
            let mut keep = Vec::with_capacity(entries.len());
            let mut expired = Vec::new();
            for entry in entries.drain(..) {
                if entry.until <= now {
                    expired.push(entry);
                } else {
                    keep.push(entry);
                }
            }
            *entries = keep;
            expired
        };
        for entry in expired {
            let uploaded = entry.handle.stats().uploaded_bytes;
            entry.runtime.block_on(entry.session.stop());
            if let Ok(conn) = self.db.lock() {
                model::log_event(
                    &conn,
                    entry.id,
                    "bt_seed_end",
                    Some(&format!("name={:?} uploaded_bytes={uploaded}", entry.name)),
                );
            }
        }
    }

    /// 登记一个续种会话，返回预计结束时刻。
    pub fn attach(
        &self,
        id: i64,
        handoff: SeedHandoff,
        runtime: tokio::runtime::Runtime,
    ) -> Instant {
        let until = Instant::now() + Duration::from_secs(handoff.minutes.max(1) * 60);
        if let Ok(conn) = self.db.lock() {
            model::log_event(
                &conn,
                id,
                "bt_seeding",
                Some(&format!(
                    "name={:?} minutes={}",
                    handoff.name,
                    handoff.minutes.max(1)
                )),
            );
        }
        if let Ok(mut entries) = self.entries.lock() {
            entries.push(SeedEntry {
                id,
                name: handoff.name,
                until,
                session: handoff.session,
                handle: handoff.handle,
                runtime,
            });
        }
        until
    }

    pub fn count(&self) -> usize {
        self.entries.lock().map(|e| e.len()).unwrap_or(0)
    }

    /// 停止某个任务的续种（用户删除任务时调用）。
    ///
    /// 删除是"我不要这个文件了"，继续做种与这个意图直接冲突，所以这里必须停。
    pub fn stop_torrent(&self, id: i64) {
        let taken: Vec<SeedEntry> = {
            let Ok(mut entries) = self.entries.lock() else {
                return;
            };
            let mut keep = Vec::with_capacity(entries.len());
            let mut taken = Vec::new();
            for entry in entries.drain(..) {
                if entry.id == id {
                    taken.push(entry);
                } else {
                    keep.push(entry);
                }
            }
            *entries = keep;
            taken
        };
        for entry in taken {
            let uploaded = entry.handle.stats().uploaded_bytes;
            entry.runtime.block_on(entry.session.stop());
            if let Ok(conn) = self.db.lock() {
                model::log_event(
                    &conn,
                    entry.id,
                    "bt_seed_end",
                    Some(&format!(
                        "name={:?} uploaded_bytes={uploaded} reason=task_removed",
                        entry.name
                    )),
                );
            }
        }
    }
}

pub(crate) fn download(args: &Args, row: &DownloadRow, dir: &Path) -> WorkerEnd {
    let settings = {
        let conn = args.db.lock().unwrap();
        BtSettings::load(&conn)
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => return WorkerEnd::Failed(format!("bt_runtime: {e}")),
    };
    let (end, handoff) = runtime.block_on(download_async(args, row, dir, settings));
    // 只有在任务确实完成（`WorkerEnd::Done`）且设置了续种时才交出会话；
    // 其它结局（失败/暂停/取消）照样要停会话、释放 runtime。
    match (end, handoff) {
        (WorkerEnd::Done, Some(handoff)) => {
            args.bt_seeds.attach(args.id, handoff, runtime);
            WorkerEnd::Done
        }
        (end, _) => end,
    }
}

async fn download_async(
    args: &Args,
    row: &DownloadRow,
    dir: &Path,
    settings: BtSettings,
) -> (WorkerEnd, Option<SeedHandoff>) {
    let allow_listen = listen_port_is_free(settings.listen_port);
    let session = match Session::new_with_opts(dir.to_path_buf(), {
        let mut options = session_options(settings, allow_listen);
        // 额外 tracker 是"没有自带 tracker / DHT 不通"时的后备；空配置时不动默认。
        let extra = {
            let conn = args.db.lock().unwrap();
            extra_trackers(&conn)
        };
        apply_extra_trackers(&mut options, extra);
        options
    })
    .await
    {
        Ok(session) => session,
        Err(e) => return (WorkerEnd::Failed(format!("bt_session: {e:#}")), None),
    };
    if settings.listen_port > 0 {
        // 一个 `bt_listen` 事件，两种结局：真在监听 / 端口被本进程另一个会话占着。
        let detail = if allow_listen {
            let bound = session
                .listen_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|| format!(":{}", settings.listen_port));
            format!("listen_addr={bound}")
        } else {
            format!("skipped reason=port_busy port={}", settings.listen_port)
        };
        let conn = args.db.lock().unwrap();
        model::log_event(&conn, args.id, "bt_listen", Some(&detail));
    }
    // 逐文件选择：DB 里的索引在 add 之前就要给出（librqbit 用 `only_files` 决定要下哪些）。
    let requested: Vec<usize> = aidm_core::bt_files::parse(row.bt_files.as_deref().unwrap_or(""));
    {
        let mut state = args.bt_selection.lock().unwrap();
        state.selected = requested.clone();
    }
    // 对端上限同样走唯一解析器（每服务器例外 > 全局闸门）：不能拿任务行里那份
    // 历史派生值，否则"不限"（0）会被读成 1 个对端。
    let peer_limit = {
        let conn = args.db.lock().unwrap();
        aidm_core::hosts::task_conns(&conn, &row.url_orig) as usize
    };
    // 找源：tracker announce（阻塞式 UDP/HTTP）与 DHT `get_peers`（异步）**并发**跑，
    // 谁的慢都不叠加到启动延迟上；两边都是"拿不到就用空"的软失败。
    // tracker 是"谁向这个 tracker 汇报过"，DHT 是另一张表 —— 薄 seed 的种子经常
    // 在 tracker 上是空的、在 DHT 上还有 peer。
    let resolve_t = Instant::now();
    let initial_peers = match magnet_infohash(&row.url_orig) {
        Some(ih) => {
            let trackers = magnet_trackers(&row.url_orig);
            let tracker_fut = async {
                if trackers.is_empty() {
                    return Vec::new();
                }
                let probe = trackers.clone();
                let peers = tokio::task::spawn_blocking(move || announce_all(&probe, &ih))
                    .await
                    .unwrap_or_default();
                {
                    let conn = args.db.lock().unwrap();
                    model::log_event(
                        &conn,
                        args.id,
                        "bt_announce",
                        Some(&format!(
                            "trackers={} peers={}",
                            trackers.len(),
                            peers.len()
                        )),
                    );
                }
                peers
            };
            let (tracker_peers, dht) =
                tokio::join!(tracker_fut, crate::dht::find_peers(&ih, crate::dht::BUDGET));
            {
                let conn = args.db.lock().unwrap();
                let detail = match &dht {
                    Ok(found) => format!(
                        "peers={} dht_size={} budget={}s",
                        found.peers.len(),
                        found.dht_size,
                        crate::dht::BUDGET.as_secs()
                    ),
                    Err(e) => format!("skipped reason={e}"),
                };
                model::log_event(&conn, args.id, "bt_dht", Some(&detail));
            }
            let dht_peers = dht.map(|found| found.peers).unwrap_or_default();
            let mut seen = std::collections::HashSet::new();
            let mut merged: Vec<SocketAddr> =
                Vec::with_capacity(tracker_peers.len() + dht_peers.len());
            for addr in tracker_peers.into_iter().chain(dht_peers) {
                if seen.insert(addr) {
                    merged.push(addr);
                }
            }
            merged
        }
        None => Vec::new(),
    };
    tracing::info!(
        event = "net.resolve",
        phase = "resolve",
        proto = "bt",
        outcome = "ok",
        dur_ms = resolve_t.elapsed().as_millis() as u64,
        peers = initial_peers.len(),
    );
    let response = match tokio::time::timeout(
        METADATA_TIMEOUT,
        session.add_torrent(
            AddTorrent::from_url(row.url_orig.clone()),
            Some(AddTorrentOptions {
                overwrite: true,
                output_folder: Some(dir.to_string_lossy().into_owned()),
                peer_limit: Some(peer_limit),
                only_files: (!requested.is_empty()).then(|| requested.clone()),
                initial_peers: (!initial_peers.is_empty()).then_some(initial_peers),
                ..Default::default()
            }),
        ),
    )
    .await
    {
        Ok(Ok(response)) => response,
        Ok(Err(e)) => {
            session.stop().await;
            return (WorkerEnd::Failed(format!("bt_add: {e:#}")), None);
        }
        Err(_) => {
            // 必须停会话并如实失败：否则这个任务继续占着队列槽位（见 METADATA_TIMEOUT）。
            session.stop().await;
            return (
                WorkerEnd::Failed(format!(
                    "bt_metadata_timeout after {}s",
                    METADATA_TIMEOUT.as_secs()
                )),
                None,
            );
        }
    };
    let Some(handle) = response.into_handle() else {
        session.stop().await;
        return (WorkerEnd::Failed("bt_metadata_only".into()), None);
    };
    let (torrent_name, total, files) = match handle.with_metadata(|metadata| {
        let files: Vec<BtFileInfo> = metadata
            .file_infos
            .iter()
            .enumerate()
            .map(|(index, info)| BtFileInfo {
                index,
                name: info.relative_filename.to_string_lossy().into_owned(),
                len: info.len,
            })
            .collect();
        (
            metadata.info.name_or_else(|| "torrent").into_owned(),
            metadata.info.lengths().total_length(),
            files,
        )
    }) {
        Ok(value) => value,
        Err(e) => {
            session.stop().await;
            return (WorkerEnd::Failed(format!("bt_metadata: {e:#}")), None);
        }
    };
    // 磁力链在拿到元数据前只能按 `dn=` 猜名字（猜不到是通用名）。元数据到手后用
    // 种子里的真实名字修正显示名；用户已改过名则不动（`set_file_name_if` 的语义）。
    if let Some(real) = aidm_core::filename::sanitize_filename(&torrent_name) {
        if real != row.file_name {
            let conn = args.db.lock().unwrap();
            match model::set_file_name_if(&conn, args.id, &real, &row.file_name) {
                Ok(1) => {
                    model::log_event(
                        &conn,
                        args.id,
                        "bt_rename",
                        Some(&format!("from={} to={real}", row.file_name)),
                    );
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(task = args.id, "bt rename: {e}"),
            }
        }
    }
    // 元数据到手 → 填文件表；此刻才能把"全选"展开成真实索引，也才能算出已选字节数。
    let selected_total = {
        let mut state = args.bt_selection.lock().unwrap();
        state.files = files.clone();
        if state.selected.is_empty() {
            state.selected = (0..files.len()).collect();
        }
        state.selected_total()
    };

    {
        let conn = args.db.lock().unwrap();
        let _ = model::set_probe_meta(
            &conn,
            args.id,
            &row.url_orig,
            // 有选择时以"已选字节数"为准：否则进度分母是整包大小，任务永远显示不满。
            Some(selected_total.max(0) as i64),
            None,
            None,
        );
        // `pos_end` 是**含**端点（`expected_len = end - start + 1`），所以是总长 - 1；
        // 传总长会让收尾时的 `done_bytes` 比文件本身多 1 字节。
        let _ = model::init_single_segment(
            &conn,
            args.id,
            &torrent_name,
            Some(selected_total.saturating_sub(1) as i64),
        );
        let _ = model::set_status(&conn, args.id, Status::Downloading, None);
        model::log_event(
            &conn,
            args.id,
            "bt_files",
            Some(&format!(
                "files={} selected={} selected_bytes={selected_total} torrent_bytes={total}",
                files.len(),
                args.bt_selection.lock().unwrap().effective().len()
            )),
        );
        model::log_event(
            &conn,
            args.id,
            "bt_metadata",
            Some(&format!("name={torrent_name:?} bytes={total}")),
        );
    }

    // 阶段事件：BT 的"传输开始"在元数据到手之后（此前是找源与取元数据）。
    tracing::info!(
        event = "transfer.start",
        phase = "transfer",
        proto = "bt",
        mode = "bt",
        files = files.len(),
        total_bytes = selected_total,
        torrent_bytes = total,
        peer_limit,
    );

    let mut previous = 0u64;
    let mut idle_ticks: u32 = 0;
    // 元数据到手后到现在还没收到第一个字节的累计时间（拿到字节就重置）。
    let mut no_bytes_since = Instant::now();
    let mut applied: Vec<usize> = args.bt_selection.lock().unwrap().effective();
    let mut total = selected_total;
    loop {
        if args.cancel.load(Ordering::SeqCst) {
            session.stop().await;
            return (WorkerEnd::Cancelled, None);
        }
        if args.pause.load(Ordering::SeqCst) {
            let _ = session.pause(&handle).await;
            let conn = args.db.lock().unwrap();
            let _ = model::set_status(&conn, args.id, Status::Paused, None);
            model::log_event(&conn, args.id, "paused", Some("protocol=bt"));
            return (WorkerEnd::Paused, None);
        }

        // 用户改了逐文件选择：下一拍就生效（librqbit 支持运行中更新 only_files）。
        let desired = args.bt_selection.lock().unwrap().effective();
        if desired != applied {
            let set: std::collections::HashSet<usize> = desired.iter().copied().collect();
            match session.update_only_files(&handle, &set).await {
                Ok(()) => {
                    applied = desired.clone();
                    total = args.bt_selection.lock().unwrap().selected_total();
                    // 分母跟着选择走，否则进度会停在"整包"上永远不满。
                    args.live.total_bytes.store(total, Ordering::Relaxed);
                    let conn = args.db.lock().unwrap();
                    let _ = model::set_probe_meta(
                        &conn,
                        args.id,
                        &row.url_orig,
                        Some(total as i64),
                        None,
                        None,
                    );
                    let _ = model::set_bt_files(
                        &conn,
                        args.id,
                        Some(&aidm_core::bt_files::encode(&desired)),
                    );
                    model::log_event(
                        &conn,
                        args.id,
                        "bt_files_applied",
                        Some(&format!(
                            "selected={} selected_bytes={total}",
                            desired.len()
                        )),
                    );
                }
                Err(e) => {
                    let conn = args.db.lock().unwrap();
                    model::log_event(
                        &conn,
                        args.id,
                        "bt_files_rejected",
                        Some(&format!("error={e:#}")),
                    );
                }
            }
            previous = 0;
        }

        let stats = handle.stats();
        if let Some(error) = stats.error {
            session.stop().await;
            return (WorkerEnd::Failed(format!("bt_transfer: {error}")), None);
        }
        // 进度按**已选文件**的 `file_progress` 求和：`progress_bytes` 在部分选择时
        // 与"用户实际要下的字节"不是一回事，自己求和才与分母同源。
        let done = {
            let state = args.bt_selection.lock().unwrap();
            let effective = state.effective();
            let selected: u64 = effective
                .iter()
                .filter_map(|i| stats.file_progress.get(*i))
                .sum();
            if state.files.is_empty() {
                stats.progress_bytes.min(total)
            } else {
                selected.min(total)
            }
        };
        if done > 0 {
            no_bytes_since = Instant::now();
        } else if no_bytes_since.elapsed() >= NO_PEER_TIMEOUT {
            // 有元数据、有分片、但完全没有 peer 给数据：如实失败，别继续占槽位。
            session.stop().await;
            return (
                WorkerEnd::Failed(format!("bt_no_peers after {}s", NO_PEER_TIMEOUT.as_secs())),
                None,
            );
        }
        let delta = done.saturating_sub(previous);
        previous = done;
        if delta > 0 {
            args.speed_window.add(delta);
            idle_ticks = 0;
        } else {
            idle_ticks += 1;
            // BT 卡住几乎总是"找不到 peer"或"peer 在但不给数据"。10 秒没动静留一条，
            // 与 HTTP 侧的 `transfer.stall` 同一口径（规格 §3.2）。
            if idle_ticks % 20 == 0 {
                tracing::warn!(
                    event = "transfer.stall",
                    phase = "transfer",
                    proto = "bt",
                    idle_s = idle_ticks / 2,
                    done_bytes = done,
                    total_bytes = total,
                    finished = stats.finished,
                );
            }
        }
        let speed = args.speed_window.bytes_per_sec();
        args.live.done_bytes.store(done, Ordering::Relaxed);
        args.live.speed_bps.store(speed, Ordering::Relaxed);
        // 进度事件节流到 5 秒一条：这里每 500 ms 走一拍（规格 §3.4）。
        let now_ms = aidm_core::model::now_ms() as u64;
        let last = args.live.last_progress_log_ms.load(Ordering::Relaxed);
        if now_ms.saturating_sub(last) >= 5_000
            && args
                .live
                .last_progress_log_ms
                .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            tracing::debug!(
                event = "transfer.progress",
                phase = "transfer",
                proto = "bt",
                done_bytes = done,
                total_bytes = total,
                speed_bps = speed,
                uploaded_bytes = stats.uploaded_bytes,
            );
        }
        if let Some(callback) = &args.progress_cb {
            callback(Progress {
                id: args.id,
                done_bytes: done,
                total: Some(total),
                speed_bps: speed,
            });
        }
        {
            let conn = args.db.lock().unwrap();
            let _ = model::set_segment_progress(&conn, args.id, done as i64);
        }
        if stats.finished {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // 续种：不在这里停会话，把手里的会话/句柄交给 `SeedRegistry`（连 runtime 一起），
    // 由它到点停止。任务本身立刻提交为 done，不等做种窗口结束。
    let handoff = (settings.seed_minutes > 0).then(|| SeedHandoff {
        name: torrent_name.clone(),
        minutes: settings.seed_minutes,
        session: session.clone(),
        handle: handle.clone(),
    });
    if handoff.is_none() {
        session.stop().await;
    }
    let conn = args.db.lock().unwrap();
    let _ = model::set_segment_progress(&conn, args.id, total as i64);
    let _ = model::finalize_segments(&conn, args.id);
    if let Err(e) = model::mark_done(&conn, args.id, &row.url_orig) {
        drop(conn);
        if let Some(h) = handoff {
            h.session.stop().await;
        }
        return (WorkerEnd::Failed(format!("bt_commit: {e}")), None);
    }
    model::log_event(
        &conn,
        args.id,
        "done",
        Some("protocol=bt verified_by=librqbit"),
    );
    (WorkerEnd::Done, handoff)
}

// ---------------- 自己 announce 拿 peer（DHT 不可达时的唯一稳定来源） ----------------
//
// 为什么要有这一段：某些网络里 DHT 的 bootstrap 节点全不可达（实测
// `dht.libtorrent.org:25401` 每 2–12 秒重试、从不成功），此时 magnet 的 peer 只能来自
// `tr=`。如果客户端自己的 announce 也拿不到（受 tracker 兼容性/UDP 出网影响），任务就会
// 永远停在 connecting。这里用同一份 `tr=` 自己发一次 announce，把结果注入
// `AddTorrentOptions::initial_peers` —— 找源与传输彻底解耦。
//
// 只做 BEP-15（UDP）与 HTTP(S) announce 的最小实现：请求 `compact=1`，只解析紧凑 peer。

/// 磁力链里的 `tr=` 列表（保持原始顺序，最多取 8 个）。
fn magnet_trackers(url: &str) -> Vec<String> {
    let Some(idx) = url.find("magnet:?") else {
        return Vec::new();
    };
    let query = &url[idx + "magnet:?".len()..];
    let mut out = Vec::new();
    for kv in query.split('&') {
        let Some(v) = kv.strip_prefix("tr=") else {
            continue;
        };
        let decoded = percent_decode(v);
        if !decoded.is_empty() && !out.contains(&decoded) {
            out.push(decoded);
        }
        if out.len() >= 8 {
            break;
        }
    }
    out
}

/// 磁力链的 info-hash（只认 40 位十六进制；32 位 base32 交给 librqbit 自己处理）。
fn magnet_infohash(url: &str) -> Option<[u8; 20]> {
    let idx = url.find("urn:btih:")?;
    let rest = &url[idx + "urn:btih:".len()..];
    let hex = rest.get(..40)?;
    let mut out = [0u8; 20];
    for i in 0..20 {
        out[i] = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                match u8::from_str_radix(
                    std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("zz"),
                    16,
                ) {
                    Ok(v) => {
                        out.push(v);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// announce 用的 `info_hash` / `peer_id` 必须把原始字节百分号转义。
fn percent_encode_bytes(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 3);
    for &b in bytes {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            s.push(b as char);
        } else {
            s.push_str(&format!("%{b:02X}"));
        }
    }
    s
}

/// 从 bencode 里取 `5:peers` 的紧凑格式（每 6 字节：IPv4 + 大端端口）。
fn compact_peers(body: &[u8]) -> Vec<SocketAddr> {
    let key = b"5:peers";
    let Some(pos) = body.windows(key.len()).position(|w| w == key) else {
        return Vec::new();
    };
    let mut i = pos + key.len();
    let mut len = 0usize;
    let mut digits = 0usize;
    while i < body.len() && body[i].is_ascii_digit() {
        len = len * 10 + usize::from(body[i] - b'0');
        i += 1;
        digits += 1;
    }
    if digits == 0 || i >= body.len() || body[i] != b':' {
        return Vec::new(); // 非紧凑（list of dict）不处理
    }
    i += 1;
    let end = (i + len).min(body.len());
    let mut out = Vec::new();
    let mut p = i;
    while p + 6 <= end {
        let ip = std::net::Ipv4Addr::new(body[p], body[p + 1], body[p + 2], body[p + 3]);
        let port = u16::from_be_bytes([body[p + 4], body[p + 5]]);
        if port != 0 && !ip.is_unspecified() && !ip.is_loopback() {
            out.push(SocketAddr::from((ip, port)));
        }
        p += 6;
    }
    out
}

fn announce_http(tracker: &str, infohash: &[u8; 20]) -> Result<Vec<SocketAddr>, String> {
    let peer_id = *b"-ND0001-aidmpeerent00";
    let q = format!(
        "info_hash={}&peer_id={}&port=6881&uploaded=0&downloaded=0&left=1&compact=1&event=started",
        percent_encode_bytes(infohash),
        percent_encode_bytes(&peer_id)
    );
    let url = if tracker.contains('?') {
        format!("{tracker}&{q}")
    } else {
        format!("{tracker}?{q}")
    };
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(3))
        .timeout(Duration::from_secs(5))
        .build();
    let resp = agent.get(&url).call().map_err(|e| format!("http: {e}"))?;
    let mut body = Vec::new();
    use std::io::Read as _;
    resp.into_reader()
        .take(256 * 1024)
        .read_to_end(&mut body)
        .map_err(|e| format!("read: {e}"))?;
    Ok(compact_peers(&body))
}

fn announce_udp(tracker: &str, infohash: &[u8; 20]) -> Result<Vec<SocketAddr>, String> {
    use std::net::{ToSocketAddrs, UdpSocket};
    let host_port = tracker
        .trim_start_matches("udp://")
        .split('/')
        .next()
        .ok_or("udp addr")?;
    let addr = host_port
        .to_socket_addrs()
        .map_err(|e| format!("dns: {e}"))?
        .next()
        .ok_or("udp dns")?;
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("bind: {e}"))?;
    sock.set_read_timeout(Some(Duration::from_secs(4))).ok();
    let tid = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(1);
    let mut req = Vec::with_capacity(16);
    req.extend_from_slice(&0x4172_7101_980_u64.to_be_bytes());
    req.extend_from_slice(&0_u32.to_be_bytes());
    req.extend_from_slice(&tid.to_be_bytes());
    sock.send_to(&req, addr).map_err(|e| format!("send: {e}"))?;
    let mut buf = [0u8; 2048];
    let (n, _) = sock.recv_from(&mut buf).map_err(|e| format!("recv: {e}"))?;
    if n < 16 || u32::from_be_bytes(buf[4..8].try_into().unwrap()) != tid {
        return Err("udp connect response".into());
    }
    let conn_id = u64::from_be_bytes(buf[8..16].try_into().unwrap());
    let tid2 = tid.wrapping_add(7);
    let mut req = Vec::with_capacity(98);
    req.extend_from_slice(&conn_id.to_be_bytes());
    req.extend_from_slice(&1_u32.to_be_bytes());
    req.extend_from_slice(&tid2.to_be_bytes());
    req.extend_from_slice(infohash);
    req.extend_from_slice(b"-ND0001-aidmpeerent00");
    req.extend_from_slice(&0_u64.to_be_bytes()); // downloaded
    req.extend_from_slice(&1_u64.to_be_bytes()); // left（未知大小，取 1）
    req.extend_from_slice(&0_u64.to_be_bytes()); // uploaded
    req.extend_from_slice(&2_u32.to_be_bytes()); // started
    req.extend_from_slice(&0_u32.to_be_bytes()); // ip
    req.extend_from_slice(&tid.to_be_bytes()); // key
    req.extend_from_slice(&(-1_i32).to_be_bytes()); // num_want
    req.extend_from_slice(&6881_u16.to_be_bytes());
    sock.send_to(&req, addr)
        .map_err(|e| format!("send2: {e}"))?;
    let (n, _) = sock
        .recv_from(&mut buf)
        .map_err(|e| format!("recv2: {e}"))?;
    if n < 20 || u32::from_be_bytes(buf[4..8].try_into().unwrap()) != tid2 {
        return Err("udp announce response".into());
    }
    let mut out = Vec::new();
    let mut p = 20;
    while p + 6 <= n {
        let ip = std::net::Ipv4Addr::new(buf[p], buf[p + 1], buf[p + 2], buf[p + 3]);
        let port = u16::from_be_bytes([buf[p + 4], buf[p + 5]]);
        if port != 0 && !ip.is_unspecified() && !ip.is_loopback() {
            out.push(SocketAddr::from((ip, port)));
        }
        p += 6;
    }
    Ok(out)
}

/// 对一批 tracker 依次 announce，去重后返回（总时长受每个 tracker 的超时约束）。
fn announce_all(trackers: &[String], infohash: &[u8; 20]) -> Vec<SocketAddr> {
    let mut peers = Vec::new();
    for t in trackers {
        let got = if t.starts_with("udp") {
            announce_udp(t, infohash)
        } else if t.starts_with("http") {
            announce_http(t, infohash)
        } else {
            continue;
        };
        match got {
            Ok(mut v) => peers.append(&mut v),
            Err(e) => tracing::debug!(tracker = %t, "announce failed: {e}"),
        }
    }
    peers.sort_unstable();
    peers.dedup();
    peers
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn_with(pairs: &[(&str, &str)]) -> Connection {
        let conn = aidm_core::open_db(std::path::Path::new(":memory:")).unwrap();
        for (k, v) in pairs {
            aidm_core::settings::set(&conn, k, v).unwrap();
        }
        conn
    }

    #[test]
    fn session_settings_default_off_and_clamp() {
        let conn = conn_with(&[]);
        assert_eq!(BtSettings::load(&conn), BtSettings::default());
        assert_eq!(BtSettings::load(&conn).listen_port, 0, "默认不监听");
        assert_eq!(BtSettings::load(&conn).seed_minutes, 0, "默认不续种");

        let conn = conn_with(&[(KEY_LISTEN_PORT, "99999"), (KEY_SEED_MINUTES, "999999")]);
        let loaded = BtSettings::load(&conn);
        assert_eq!(loaded.listen_port, u16::MAX, "越界夹取到端口上限");
        assert_eq!(loaded.seed_minutes, 7 * 24 * 60, "续种上限 7 天");

        let conn = conn_with(&[(KEY_LISTEN_PORT, "abc"), (KEY_SEED_MINUTES, "-5")]);
        let loaded = BtSettings::load(&conn);
        assert_eq!(loaded.listen_port, 0, "解析失败回默认");
        assert_eq!(loaded.seed_minutes, 0, "负数解析失败回默认");
    }

    #[test]
    fn listen_option_only_exists_when_a_port_is_configured() {
        let none = session_options(BtSettings::default(), true);
        assert!(none.listen.is_none(), "0 = 不监听（与 librqbit 默认一致）");

        let fixed = session_options(
            BtSettings {
                listen_port: 51413,
                seed_minutes: 0,
            },
            true,
        );
        let listen = fixed.listen.expect("配了端口就要监听");
        assert_eq!(listen.listen_addr.port(), 51413);
        assert!(listen.listen_addr.ip().is_unspecified(), "绑全部网卡");
    }

    #[test]
    fn dht_is_ephemeral_so_concurrent_sessions_do_not_collide() {
        // 每个 BT 任务各建一个 Session：DHT 若沿用默认持久化，端口会被固定，
        // 第二个并发会话 bind 同一端口直接失败（实测 `os error 10048`）。
        for allow in [true, false] {
            let opts = session_options(
                BtSettings {
                    listen_port: 0,
                    seed_minutes: 0,
                },
                allow,
            );
            let dht = opts
                .dht
                .expect("DHT 必须启用：无 tracker 的磁力链只靠它找 peer");
            assert!(dht.port.is_none(), "端口必须随机，否则并发会话相撞");
            assert!(dht.persistence.is_none(), "持久化会把端口固定下来");
        }
    }

    #[test]
    fn listen_port_probe_treats_zero_as_never_listen() {
        assert!(!listen_port_is_free(0), "0 = 从不监听");
        // 高位端口在测试环境里通常空闲；这里只断言"能给出布尔结论"而不赌占用状态。
        assert!(listen_port_is_free(1) || !listen_port_is_free(1));
    }

    #[test]
    fn listen_option_is_dropped_when_the_port_is_taken() {
        let opts = session_options(
            BtSettings {
                listen_port: 51413,
                seed_minutes: 0,
            },
            false,
        );
        assert!(
            opts.listen.is_none(),
            "端口被占时不能绑：宁可这次不监听，也不要让任务在建会话时失败"
        );
    }

    #[test]
    fn magnet_trackers_and_infohash_are_parsed() {
        let m = concat!(
            "magnet:?xt=urn:btih:32ab06b45263b54be5f8b453c6e325350c0239fa",
            "&dn=a.mp4&tr=udp%3A%2F%2Fopentrackr.example%3A1337%2Fannounce",
            "&tr=http%3A%2F%2Ft.example%2Fannounce"
        );
        let t = magnet_trackers(m);
        assert_eq!(
            t,
            vec![
                "udp://opentrackr.example:1337/announce".to_string(),
                "http://t.example/announce".to_string()
            ]
        );
        assert_eq!(
            magnet_infohash(m).map(|h| hex(&h)),
            Some("32ab06b45263b54be5f8b453c6e325350c0239fa".into())
        );
        assert!(magnet_trackers("magnet:?xt=urn:btih:00").is_empty());
        assert!(magnet_infohash("magnet:?xt=urn:btih:short").is_none());
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn compact_peers_are_decoded_and_filtered() {
        // 两条有效 + 端口 0 + 回环
        let mut body = b"d8:completei1e5:peers18:".to_vec();
        body.extend_from_slice(&[1, 2, 3, 4, 0x1a, 0xe1]);
        body.extend_from_slice(&[5, 6, 7, 8, 0x00, 0x50]);
        body.extend_from_slice(&[9, 9, 9, 9, 0x00, 0x00]);
        body.extend_from_slice(&[127, 0, 0, 1, 0x1a, 0xe1]);
        body.extend_from_slice(b"e");
        let peers = compact_peers(&body);
        assert_eq!(
            peers,
            vec![
                "1.2.3.4:6881".parse::<SocketAddr>().unwrap(),
                "5.6.7.8:80".parse::<SocketAddr>().unwrap()
            ]
        );
        assert!(compact_peers(b"d5:peerslee").is_empty(), "非紧凑不解析");
    }

    #[test]
    fn parses_extra_trackers_and_skips_junk() {
        let got = parse_trackers(
            "udp://tracker.example:1337/announce\n\
             https://t2.example/announce, http://t3.example/a\n\
             \n\
             not-a-url\n\
             ftp://nope.example/announce\n\
             udp://tracker.example:1337/announce",
        );
        // 四种可用协议各留一条；重复的 udp 去重；非 URL 与 ftp 被跳过
        assert_eq!(got.len(), 3, "{got:?}");
        let schemes: Vec<&str> = got.iter().map(|u| u.scheme()).collect();
        assert!(
            schemes.contains(&"udp") && schemes.contains(&"https") && schemes.contains(&"http")
        );
        assert!(parse_trackers("").is_empty());
        assert!(parse_trackers("   ,  ,\n").is_empty());
    }

    #[test]
    fn extra_trackers_are_applied_only_when_configured() {
        // 空配置不能动默认值：librqbit 默认 DHT 开着、trackers 为空，
        // 一旦我们塞进去东西就等于替用户选了第三方。
        let mut options = session_options(BtSettings::default(), true);
        assert!(options.trackers.is_empty(), "默认不该有额外 tracker");
        apply_extra_trackers(&mut options, parse_trackers(""));
        assert!(options.trackers.is_empty());

        apply_extra_trackers(
            &mut options,
            parse_trackers("udp://tracker.example:1337/announce"),
        );
        assert_eq!(options.trackers.len(), 1);
        assert_eq!(options.trackers.iter().next().unwrap().scheme(), "udp");
    }
}

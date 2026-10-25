//! Private multi-source piece coordinator: one identity, one UDP receive owner,
//! single piece ownership (bounded duplication only for stalled parts), shared
//! connection budget and original ed2k verification.
use super::{
    multi_source::{self, MultiDownload, MultiSourceCfg, PeerEvent, PoolProgress, TransferHooks},
    private_channel,
    private_connection::{Connection, Connector, ConnectorStats},
    private_index::Metadata,
    private_nat,
    private_peer::{self, NetworkInfo},
    private_session::{RangeOutput, Session, SessionStats},
};
use aidm_core::ed2k::{
    hash,
    peer::{part_count, PARTSIZE},
    FileLink,
};
use std::{
    collections::HashMap,
    fs::OpenOptions,
    io::{Read, Seek, SeekFrom, Write},
    net::{Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    time::{Duration, Instant},
};

struct Permits<'a> {
    hooks: &'a dyn TransferHooks,
    count: usize,
}
impl Drop for Permits<'_> {
    fn drop(&mut self) {
        for _ in 0..self.count {
            self.hooks.release_connection();
        }
    }
}
/// A part in flight this long may also be requested by an idle connection;
/// a healthy peer moves one 9,728,000-byte part in about three seconds.
const ENDGAME_AFTER: Duration = Duration::from_secs(10);
const ENDGAME_HOLDERS: u8 = 3;

/// 末段阈值：已收字节 / 全文件 ≥ 该比例即视为进入末段。
/// 末段统计包含进度占比、通道数、有效源与废弃源。
///
/// 本池按**本池**已收字节 / 全文件字节统计，当 `filter` 只让本池负责部分分片时
/// 会低估进度，从而**偏晚**进入末段。该记账只用于诊断，不参与任何调度决策。
const TAIL_RATIO: f64 = 0.99;

/// 末段阶段记账：进入后累计期间时长、通道数峰值、供过数的源集合与废弃源数。
#[derive(Default)]
struct TailPhase {
    entered: Option<Instant>,
    at_enter_peers: usize,
    peak_peers: usize,
    useful: std::collections::HashSet<u16>,
    retired_at_enter: u32,
}

impl TailPhase {
    fn observe(&mut self, done: u64, size: u64, peers: &HashMap<u16, Peer>, retired_total: u32) {
        if self.entered.is_none() {
            if size == 0 || (done as f64) < size as f64 * TAIL_RATIO {
                return;
            }
            self.entered = Some(Instant::now());
            self.at_enter_peers = peers.len();
            self.peak_peers = peers.len();
            self.retired_at_enter = retired_total;
            return;
        }
        self.peak_peers = self.peak_peers.max(peers.len());
        for (port, p) in peers {
            if p.part.as_ref().is_some_and(|(_, r)| r.covered > 0) {
                self.useful.insert(*port);
            }
        }
    }

    fn elapsed(&self) -> Option<Duration> {
        self.entered.map(|t| t.elapsed())
    }

    fn abandoned(&self, retired_total: u32) -> u32 {
        retired_total.saturating_sub(self.retired_at_enter)
    }
}

/// 低分淘汰：给新连接多少观察时间后才允许因"持续低速且零字节"被淘汰。
const LOW_SCORE_GRACE: Duration = Duration::from_secs(20);
/// 低分淘汰：至少需要这么多个采样窗口（每个约 1 秒）。
const LOW_SCORE_MIN_SAMPLES: u32 = 3;
/// 低分淘汰：速度均值低于该值（字节/秒）即视为"挂着但不供数"。
const LOW_SCORE_BYTES_PER_SEC: f64 = 1024.0;
/// 低分淘汰：低于同任务活跃源速率中位数的 25% 视为明显偏慢。
const LOW_SCORE_RELATIVE: f64 = 0.25;
/// 慢源被移除后，同一地址的冷却时间，避免“移除→立刻重连”死循环。
const SLOW_SOURCE_COOLDOWN: Duration = Duration::from_secs(60);

/// 慢源判定：必须已有切片、已过观察窗口、且至少还有另一个源。
/// 单源任务不淘汰最后一个源，否则会从“慢”变成“完全没速度”。
fn should_retire_slow(
    age: Duration,
    samples: u32,
    mean: f64,
    median: f64,
    covered: u64,
    has_part: bool,
    peers: usize,
) -> bool {
    if !has_part || peers < 2 || age < LOW_SCORE_GRACE {
        return false;
    }
    // 完全没有字节时没有采样窗口；不能因此永远不淘汰。
    if covered == 0 && mean < LOW_SCORE_BYTES_PER_SEC.max(median * LOW_SCORE_RELATIVE) {
        return true;
    }
    if samples < LOW_SCORE_MIN_SAMPLES {
        return false;
    }
    let threshold = LOW_SCORE_BYTES_PER_SEC.max(median * LOW_SCORE_RELATIVE);
    mean < threshold
}

/// 两段式请求窗口的**单请求上限**：每个 REQUEST 覆盖的字节数。
/// 每个区间先裁到该上限以内。
///
/// 私有通道协议没有对端通告的请求上限字段，因此这里取本地值；
/// 若将来能从对端取到，只需改这一处来源。
const REQUEST_CHUNK: u64 = 1024 * 1024;

/// 两段式请求窗口的**上界**：已请求量相对已收字节的允许超前量。
/// 已请求量达到窗口上界就停止发 REQUEST。
///
/// 上界恒取单请求上限的 4 倍，由同一不变量派生，而不是各写一个魔数。
const WINDOW_BYTES: u64 = REQUEST_CHUNK * 4;

/// 单个连接在某个分片上的请求窗口状态。
///
/// `requested_upto` 是已请求量，`base + part_len` 是本轮可请求范围；
/// 窗口上界与单请求裁剪分别由 `WINDOW_BYTES` / `REQUEST_CHUNK` 表达。
#[derive(Clone, Copy, Debug)]
struct Window {
    /// 分片起始的绝对文件位置。
    base: u64,
    /// 分片长度（最后一个分片可能短于 PARTSIZE）。
    part_len: u64,
    /// 分片内已请求到的偏移（只增不减）。
    requested_upto: u64,
}

/// 源质量滑动窗口：派发评分口径
/// （速度与通道数各有一路均值 + 方差统计，方差入分以惩罚抖动源，而不只看平均速度）。
///
/// 用指数加权（EWMA + EW 方差）而非固定样本环：O(1) 空间，且近期样本权重高，
/// 天然是"滑动"的。`ALPHA` 取 0.3 相当于约 3 个样本的有效窗口。
///
/// 阈值属 AIDM 自有取值。
#[derive(Clone, Copy, Debug, Default)]
struct SourceScore {
    mean: f64,
    var: f64,
    seeded: bool,
    samples: u32,
}

impl SourceScore {
    const ALPHA: f64 = 0.3;

    /// 采样一次瞬时速度（字节/秒）。`elapsed` 是本次采样窗口的时长。
    fn observe(&mut self, bytes: u64, elapsed: Duration) {
        let secs = elapsed.as_secs_f64();
        if secs <= 0.0 {
            return;
        }
        let x = bytes as f64 / secs;
        self.samples = self.samples.saturating_add(1);
        if !self.seeded {
            self.mean = x;
            self.var = 0.0;
            self.seeded = true;
            return;
        }
        let delta = x - self.mean;
        self.mean += Self::ALPHA * delta;
        self.var = (1.0 - Self::ALPHA) * (self.var + Self::ALPHA * delta * delta);
    }

    fn mean(&self) -> f64 {
        if self.seeded {
            self.mean
        } else {
            0.0
        }
    }

    fn var(&self) -> f64 {
        if self.seeded {
            self.var
        } else {
            0.0
        }
    }

    /// 已完成的采样窗口数。淘汰判定用它保证"观察够了再动手"。
    fn samples(&self) -> u32 {
        self.samples
    }
}

struct Part {
    verified: bool,
    /// 已完整落盘、正在被后台线程读回校验。**不参与分配**（`pick` 跳过），
    /// 所以校验再慢也不会被重复下载，更不会挡住私有通道建链。
    checking: bool,
    holders: u8,
    /// Set once two connections held it; their interleaved writes are then
    /// replaced by the verified buffer.
    shared: bool,
    assigned: Option<Instant>,
    received: u64,
}

impl Part {
    fn new() -> Self {
        Self {
            verified: false,
            checking: false,
            holders: 0,
            shared: false,
            assigned: None,
            received: 0,
        }
    }
}

/// Unheld parts first; otherwise the least-held stalled part, so a slow or
/// silent holder cannot pin the tail of the download.
/// 分片归属过滤器（与标准池共用 `multi_source::PartFilter`）：
/// `Some` 时只挑本池负责的分片，两个池才能并发写同一文件而不互相覆盖。
fn pick(
    parts: &[Part],
    goal: usize,
    filter: Option<&crate::ed2k::multi_source::PartFilter>,
) -> Option<usize> {
    let open =
        parts.iter().take(goal).enumerate().filter(|(idx, p)| {
            !p.verified && !p.checking && filter.is_none_or(|f| f.contains(*idx))
        });
    if let Some((idx, _)) = open.clone().find(|(_, p)| p.holders == 0) {
        return Some(idx);
    }
    open.filter(|(_, p)| {
        p.holders < ENDGAME_HOLDERS && p.assigned.is_some_and(|at| at.elapsed() >= ENDGAME_AFTER)
    })
    .min_by_key(|(_, p)| (p.holders, p.received))
    .map(|(idx, _)| idx)
}
struct Peer {
    session: Session,
    part: Option<(usize, RangeOutput)>,
    network: u64,
    started: Instant,
    receiving: bool,
    /// 源质量滑动窗口（速度均值 + 方差），按约 1 秒的窗口采样。
    score: SourceScore,
    /// 当前采样窗口内累积的字节数与窗口起点。
    sample_bytes: u64,
    sample_at: Instant,
    /// 两段式请求窗口；`None` 表示当前没有在办分片。
    window: Option<Window>,
}

#[derive(Clone, Debug)]
pub struct PeerDiag {
    pub port: u16,
    pub addr: SocketAddr,
    pub file_bytes: u64,
    pub part: Option<usize>,
    pub part_covered: usize,
    pub ready: bool,
    pub queued: bool,
    pub age: Duration,
    pub stats: SessionStats,
    pub retired: Option<String>,
    /// 源质量滑动窗口：速度均值与方差（字节/秒）。
    pub speed_mean: f64,
    pub speed_var: f64,
}

/// Snapshot for explicit diagnostics; production callers pass no observer.
#[derive(Clone, Debug, Default)]
pub struct PoolDiag {
    pub elapsed: Duration,
    pub directory_peers: usize,
    pub received: u64,
    pub verified_parts: usize,
    pub udp_packets: u64,
    pub udp_bytes: u64,
    pub undecodable: u64,
    pub unrouted: u64,
    /// Time spent inside recv_from (waiting or copying); the rest is loop work.
    pub idle_wait: Duration,
    pub connections_opened: u64,
    pub connector: ConnectorStats,
    pub peers: Vec<PeerDiag>,
    pub retired: Vec<PeerDiag>,
    /// 末段（已收 ≥ `TAIL_RATIO` × 全文件）阶段的诊断口径：
    /// 进度占比、通道数、有效源与废弃源。
    /// `None` 表示整轮都没进入末段。
    pub tail_elapsed: Option<Duration>,
    pub tail_enter_peers: usize,
    pub tail_peak_peers: usize,
    pub tail_useful_peers: usize,
    pub tail_abandoned_peers: u32,
}

pub type DiagObserver<'a> = &'a mut dyn FnMut(&PoolDiag);

fn peer_diag(port: u16, peer: &Peer, retired: Option<String>) -> PeerDiag {
    PeerDiag {
        port,
        addr: peer.session.connection.remote_endpoint,
        file_bytes: peer.network,
        part: peer.part.as_ref().map(|(i, _)| *i),
        part_covered: peer.part.as_ref().map_or(0, |(_, r)| r.covered),
        ready: peer.session.is_ready(),
        queued: peer.session.is_queued(),
        age: peer.started.elapsed(),
        stats: peer.session.stats,
        retired,
        speed_mean: peer.score.mean(),
        speed_var: peer.score.var(),
    }
}

fn length(size: u64, index: usize) -> u64 {
    size.saturating_sub(index as u64 * PARTSIZE).min(PARTSIZE)
}

/// 后台读回校验的单片结果落定：校验中的片转成 `verified`，校验失败则回到可分配
/// （字节数清零，让 peer 重下）。校验中的片从不参与分配，所以这里没有竞态。
fn apply_check(parts: &mut [Part], idx: usize, ok: bool, size: u64) {
    let part = &mut parts[idx];
    part.checking = false;
    if ok {
        part.verified = true;
        part.received = length(size, idx);
    } else {
        part.received = 0;
    }
}
fn progress(parts: &[Part], peers: &HashMap<u16, Peer>, verifying: bool) -> PoolProgress {
    PoolProgress {
        verifying,
        done: parts.iter().map(|p| p.received).sum(),
        verified_parts: parts.iter().filter(|p| p.verified).count(),
        total_parts: parts.len(),
        slices: parts
            .iter()
            .map(|p| {
                if p.verified {
                    2
                } else if p.checking {
                    3
                } else if p.holders > 0 || p.received > 0 {
                    1
                } else {
                    0
                }
            })
            .collect(),
        active_peers: peers.len(),
        transferring_peers: peers
            .values()
            .filter(|p| p.part.as_ref().is_some_and(|(_, r)| r.covered > 0))
            .count(),
        queued_peers: peers.values().filter(|p| p.session.is_queued()).count(),
        // 私有通道不做 AICH：它有自己的分片校验与索引。
        aich_recovered_blocks: 0,
        // 私有通道不提供 owner→peer 归属观测（其索引模型不同），版本恒为 0。
        ownership_rev: 0,
    }
}

fn query_directory(
    cfg: &MultiSourceCfg<'_>,
    link: &FileLink,
    uri: &str,
    meta: &Metadata,
    identity: &[u8; 16],
) -> Result<private_peer::Directory, String> {
    let (tx, rx) = mpsc::channel();
    let link = link.clone();
    let uri = uri.to_owned();
    let meta = meta.clone();
    let identity = *identity;
    std::thread::Builder::new()
        .name("aidm-private-directory".into())
        .spawn(move || {
            let network = NetworkInfo {
                internal_ip: Ipv4Addr::UNSPECIFIED,
                nat_type: 0,
                upnp_ip: Ipv4Addr::UNSPECIFIED,
                upnp_port: 0,
                address_is_translated_or_unknown: true,
            };
            let _ = tx.send(private_peer::query(&link, &uri, &meta, &identity, &network));
        })
        .map_err(|_| "private_directory_thread")?;
    let started = Instant::now();
    loop {
        if (cfg.stop)() {
            return Err("ed2k_stopped".into());
        }
        if started.elapsed() > Duration::from_secs(5) {
            return Err("private_directory_timeout".into());
        }
        match rx.recv_timeout(Duration::from_millis(25)) {
            Ok(out) => return out,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(_) => return Err("private_directory_closed".into()),
        }
    }
}

fn add_connection(
    cfg: &MultiSourceCfg<'_>,
    link: &FileLink,
    meta: &Metadata,
    connection: Connection,
    peers: &mut HashMap<u16, Peer>,
    slow_removed: &HashMap<SocketAddr, Instant>,
) -> Result<(), String> {
    let port = connection.source_port;
    let addr = connection.remote_endpoint;
    if slow_removed
        .get(&addr)
        .is_some_and(|at| at.elapsed() < SLOW_SOURCE_COOLDOWN)
    {
        return Err("private_slow_source_cooldown".into());
    }
    (cfg.on_event)(PeerEvent::Connecting { addr });
    let session = Session::new(connection, link, meta)?;
    peers.insert(
        port,
        Peer {
            session,
            part: None,
            network: 0,
            started: Instant::now(),
            receiving: false,
            score: SourceScore::default(),
            sample_bytes: 0,
            sample_at: Instant::now(),
            window: None,
        },
    );
    Ok(())
}

fn retire(
    cfg: &MultiSourceCfg<'_>,
    port: u16,
    error: String,
    peers: &mut HashMap<u16, Peer>,
    parts: &mut [Part],
    connector: &mut Connector,
    diag: &mut Option<PoolDiag>,
) -> bool {
    if let Some(peer) = peers.remove(&port) {
        if let Some(d) = diag {
            d.retired.push(peer_diag(port, &peer, Some(error.clone())));
        }
        if let Some((idx, _)) = peer.part {
            let part = &mut parts[idx];
            part.holders = part.holders.saturating_sub(1);
            if part.holders == 0 && !part.verified {
                part.received = 0;
            }
        }
        (cfg.on_event)(PeerEvent::Finished {
            addr: peer.session.connection.remote_endpoint,
            network_bytes: peer.network,
            error: Some(error),
        });
        connector.release_connection(port);
        true
    } else {
        false
    }
}

/// 计算窗口内下一个应发出的请求区间（相对分片的偏移与长度）。
/// `None` 表示已达窗口上界、或分片已请求完。
///
/// 这是两段式的判定核心：上界由 `covered + WINDOW_BYTES` 与分片末端共同夹住，
/// 单次长度再由 `REQUEST_CHUNK` 裁剪。
fn next_request(window: &Window, covered: u64) -> Option<(u64, u64)> {
    let limit = covered.saturating_add(WINDOW_BYTES).min(window.part_len);
    if window.requested_upto >= limit {
        return None;
    }
    let want = (limit - window.requested_upto).min(REQUEST_CHUNK);
    Some((window.requested_upto, want))
}

/// 推进两段式请求窗口：把已请求量补到窗口上界，单次请求不超过 `REQUEST_CHUNK`。
///
/// 循环条件为「已请求量 < 窗口上界」，每次取一段、裁到单请求上限后发出，
/// 发完累加已请求量；达到上界即退出，等数据到达推进 `covered` 后再被调用。
///
/// 这里按"已收字节 + 窗口"线性推进，等价于对单个分片做顺序窗口。
fn pump(peer: &mut Peer) -> Result<(), String> {
    let covered = match &peer.part {
        Some((_, output)) => output.covered as u64,
        None => return Ok(()),
    };
    let Some(window) = peer.window.as_mut() else {
        return Ok(());
    };
    while let Some((offset, want)) = next_request(window, covered) {
        let at = window.base + offset;
        match peer.session.request_range(at, want) {
            Ok(()) => window.requested_upto += want,
            // 窗口满不是会话错误：保留 requested_upto（不推进），等下一轮
            // assign → pump 时 ACK 已释放窗口，再从同一位置继续请求。
            Err(e) if e == "private_channel_window_full" => break,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn assign(
    peer: &mut Peer,
    parts: &mut [Part],
    size: u64,
    goal: usize,
    filter: Option<&crate::ed2k::multi_source::PartFilter>,
) -> Result<(), String> {
    if !peer.session.is_ready() {
        return Ok(());
    }
    // 已有分片在传：每轮把请求窗口补到上界。窗口满时 pump 会停下等待 ACK，
    // 下一轮本函数会再次被调用，因此不需要把 peer 判失败。
    if peer.part.is_some() {
        return pump(peer);
    }
    let Some(idx) = pick(parts, goal, filter) else {
        return Ok(());
    };
    let len = length(size, idx);
    let base = idx as u64 * PARTSIZE;
    let part = &mut parts[idx];
    if part.holders == 0 {
        part.received = 0;
    } else {
        part.shared = true;
    }
    part.holders += 1;
    part.assigned = Some(Instant::now());
    // 两段式：这里只建立输出缓冲与请求窗口，实际 REQUEST 由 `pump` 按
    // 「窗口上界 + 单请求裁剪」分批发出——不再一次请求整个分片。
    // 缓冲仍按整片分配，因此乱序/部分到达由 `RangeOutput` 去重填充，
    // 完成判定与 MD4 校验路径都不需要改。
    peer.part = Some((idx, RangeOutput::new(base, len as usize)));
    peer.window = Some(Window {
        base,
        part_len: len,
        requested_upto: 0,
    });
    pump(peer)
}

pub fn download<F, S>(
    cfg: &MultiSourceCfg<'_>,
    link: &FileLink,
    uri: &str,
    meta: &Metadata,
    identity: &[u8; 16],
    on_sources: S,
    on_progress: F,
) -> Result<MultiDownload, String>
where
    F: FnMut(PoolProgress),
    S: FnMut(usize),
{
    run(
        cfg,
        link,
        uri,
        meta,
        identity,
        None,
        on_sources,
        on_progress,
        None,
    )
}

/// Explicit partial live validation. It cannot complete the whole task and
/// never runs the final-file verifier for a prefix-only request.
pub fn download_first_parts<F, S>(
    cfg: &MultiSourceCfg<'_>,
    link: &FileLink,
    uri: &str,
    meta: &Metadata,
    identity: &[u8; 16],
    parts: usize,
    on_sources: S,
    on_progress: F,
) -> Result<MultiDownload, String>
where
    F: FnMut(PoolProgress),
    S: FnMut(usize),
{
    run(
        cfg,
        link,
        uri,
        meta,
        identity,
        Some(parts),
        on_sources,
        on_progress,
        None,
    )
}

/// Explicit live diagnostics: `download_first_parts` plus a once-per-second
/// observer with per-stream counters and receive-loop occupancy.
#[allow(clippy::too_many_arguments)]
pub fn download_first_parts_diag<F, S>(
    cfg: &MultiSourceCfg<'_>,
    link: &FileLink,
    uri: &str,
    meta: &Metadata,
    identity: &[u8; 16],
    parts: usize,
    on_sources: S,
    on_progress: F,
    observer: DiagObserver<'_>,
) -> Result<MultiDownload, String>
where
    F: FnMut(PoolProgress),
    S: FnMut(usize),
{
    run(
        cfg,
        link,
        uri,
        meta,
        identity,
        Some(parts),
        on_sources,
        on_progress,
        Some(observer),
    )
}

#[allow(clippy::too_many_arguments)]
fn run<F, S>(
    cfg: &MultiSourceCfg<'_>,
    link: &FileLink,
    uri: &str,
    meta: &Metadata,
    identity: &[u8; 16],
    limit: Option<usize>,
    mut on_sources: S,
    mut on_progress: F,
    mut observer: Option<DiagObserver<'_>>,
) -> Result<MultiDownload, String>
where
    F: FnMut(PoolProgress),
    S: FnMut(usize),
{
    let total = part_count(link.size);
    let goal = limit.unwrap_or(total).min(total);
    if cfg.file_size != link.size
        || cfg.file_hash != link.hash
        || meta.part_hashes.len() != total
        || goal == 0
    {
        return Err("private_file_metadata_mismatch".into());
    }
    let directory = query_directory(cfg, link, uri, meta, identity)?;
    on_sources(directory.peers.len());
    if directory.peers.is_empty() {
        return Err("private_directory_empty".into());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(cfg.target)
        .map_err(|e| format!("ed2k_open: {e}"))?;
    let existing = file.metadata().map_err(|e| e.to_string())?.len();
    let mut parts: Vec<_> = (0..total).map(|_| Part::new()).collect();
    let mut peers = HashMap::new();
    // 已落盘分片先只"圈起来"（索引运算，微秒级）：私有通道立刻开始建链，
    // 读回 + MD4 交给后台线程。校验若同步放在建链之前，恢复下载时要先
    // 花几秒到十几秒重读已下好的片，用户看到的就是"恢复后长时间连不上资源"。
    let mut pending_check: Vec<(usize, u64)> = Vec::new();
    for (idx, part) in parts.iter_mut().enumerate().take(goal) {
        // 有过滤器时只认可自己负责的分片：读回别池的片会读到半片、误判失败后重复下载。
        if !cfg.part_filter.as_ref().is_none_or(|f| f.contains(idx)) {
            continue;
        }
        let len = length(link.size, idx);
        if existing >= idx as u64 * PARTSIZE + len {
            // `received = len`：字节确实在盘上，进度条不能因为"还没校验"先掉回 0。
            part.checking = true;
            part.received = len;
            pending_check.push((idx, len));
        }
    }
    // 后台校验：独立只读句柄（主句柄要留给传输线程写），结果按片回传。
    let (check_tx, check_rx) = mpsc::channel::<(usize, bool)>();
    let mut checks_pending = pending_check.len();
    let check_file = if pending_check.is_empty() {
        None
    } else {
        Some(
            OpenOptions::new()
                .read(true)
                .open(cfg.target)
                .map_err(|e| format!("ed2k_open: {e}"))?,
        )
    };
    let check_hashes = meta.part_hashes.clone();
    // 线程要 `'static`：用共享标志做取消（收尾时置位并 join，暂停不会被读回拖住）。
    let check_cancel = Arc::new(AtomicBool::new(false));
    let check_handle = check_file.and_then(|mut cf| {
        let cancel = check_cancel.clone();
        std::thread::Builder::new()
            .name("aidm-private-verify".into())
            .spawn(move || {
                for (idx, len) in pending_check {
                    if cancel.load(Ordering::Relaxed) {
                        return;
                    }
                    let mut bytes = vec![0u8; len as usize];
                    let ok = cf
                        .seek(SeekFrom::Start(idx as u64 * PARTSIZE))
                        .and_then(|_| cf.read_exact(&mut bytes))
                        .map(|_| hash::md4(&bytes) == check_hashes[idx])
                        .unwrap_or(false);
                    if check_tx.send((idx, ok)).is_err() {
                        return;
                    }
                }
            })
            .ok()
    });
    on_progress(progress(&parts, &peers, false));
    let mut permits = Permits {
        hooks: cfg.hooks,
        count: 0,
    };
    // 每任务连接数不设限：只受对端数与目标分片数约束。
    let cap = cfg
        .max_connections
        .max(1)
        .min(directory.peers.len())
        .min(goal);
    while permits.count < cap && cfg.hooks.try_acquire_connection() {
        permits.count += 1;
    }
    if permits.count == 0 {
        return Err("private_connection_capacity".into());
    }
    let cancelled = AtomicBool::new(false);
    let mut connector = Connector::begin(
        identity,
        &directory.peers,
        permits.count,
        Duration::from_secs(10),
    )?;
    connector.stream_until_exhausted();
    connector
        .socket()
        .set_read_timeout(Some(Duration::from_millis(2)))
        .map_err(|e| e.to_string())?;
    let _ = socket2::SockRef::from(connector.socket()).set_recv_buffer_size(8 * 1024 * 1024);
    let mut buffer = [0; 65507];
    let mut last_progress = Instant::now();
    let started = Instant::now();
    let mut first_data = None;
    let mut peak = 0;
    // 末段阶段记账（诊断口径，见 TailPhase）。`retired_total` 只统计真正
    // 从 `peers` 里移除的连接，用于算末段期间的废弃源数。
    let mut tail = TailPhase::default();
    let mut retired_total: u32 = 0;
    let mut diag = observer.as_ref().map(|_| PoolDiag {
        directory_peers: directory.peers.len(),
        ..Default::default()
    });
    let mut last_diag = Instant::now();
    // 慢源移除后的地址冷却表；只在本次私有池运行期间有效。
    let mut slow_removed: HashMap<SocketAddr, Instant> = HashMap::new();
    loop {
        if let (Some(d), Some(observe)) = (&mut diag, &mut observer) {
            if last_diag.elapsed() >= Duration::from_secs(1) {
                last_diag = Instant::now();
                d.elapsed = started.elapsed();
                d.received = parts.iter().map(|p| p.received).sum();
                d.verified_parts = parts.iter().filter(|p| p.verified).count();
                d.connector = connector.stats();
                d.peers = peers.iter().map(|(&k, p)| peer_diag(k, p, None)).collect();
                d.tail_elapsed = tail.elapsed();
                d.tail_enter_peers = tail.at_enter_peers;
                d.tail_peak_peers = tail.peak_peers;
                d.tail_useful_peers = tail.useful.len();
                d.tail_abandoned_peers = tail.abandoned(retired_total);
                observe(d);
                d.retired.clear();
            }
        }
        if (cfg.stop)() {
            cancelled.store(true, Ordering::Relaxed);
            break;
        }
        // 后台读回校验结果：逐片落定。校验中的片不参与分配，所以这里只做状态转换，
        // 不存在与传输线程的竞态。
        while let Ok((idx, ok)) = check_rx.try_recv() {
            apply_check(&mut parts, idx, ok, link.size);
            checks_pending = checks_pending.saturating_sub(1);
        }
        if parts
            .iter()
            .enumerate()
            .take(goal)
            .filter(|(i, _)| cfg.part_filter.as_ref().is_none_or(|f| f.contains(*i)))
            .all(|(_, p)| p.verified && !p.checking)
        {
            // 私有池的初始份额已完成：不要立刻退出。
            // 编排层还保留标准池时，先在这里等它停掉标准池并打开 all；
            // 当前私有连接继续接管标准池剩余的 Pending 分片。
            let mut wait_all = false;
            if let Some(exp) = cfg.expansion.as_ref() {
                if !exp.all.load(Ordering::Acquire) {
                    exp.ready.store(true, Ordering::Release);
                    while !exp.all.load(Ordering::Acquire) && !(cfg.stop)() {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                }
                wait_all = exp.all.load(Ordering::Acquire);
            }
            if !wait_all {
                break;
            }
            // all 已打开：如果标准池的剩余分片还没完成，继续认领；
            // 只有全部分片都校验完成才真正退出。
            if parts.iter().take(goal).all(|p| p.verified && !p.checking) {
                break;
            }
            continue;
        }
        for connection in connector.tick(&cancelled)? {
            let port = connection.source_port;
            if let Err(e) = add_connection(cfg, link, meta, connection, &mut peers, &slow_removed) {
                connector.release_connection(port);
                log::debug!("private_session_start: {e}");
            } else if let Some(d) = &mut diag {
                d.connections_opened += 1;
            }
        }
        // 当前活跃源速率中位数：慢源按相对中位数判定，避免被单个快源拉偏。
        let mut rates: Vec<f64> = peers
            .values()
            .filter(|p| p.part.is_some() && p.score.samples() > 0)
            .map(|p| p.score.mean())
            .collect();
        rates.sort_by(f64::total_cmp);
        let median = rates.get(rates.len() / 2).copied().unwrap_or(0.0);
        let peer_count = peers.len();
        let mut failed = Vec::new();
        for (&port, peer) in &mut peers {
            if let Err(e) = peer.session.tick(&cancelled).and_then(|_| {
                assign(
                    peer,
                    &mut parts,
                    link.size,
                    goal,
                    cfg.part_filter.as_deref(),
                )
            }) {
                failed.push((port, e));
                continue;
            }
            if (!peer.session.is_ready() && peer.started.elapsed() > Duration::from_secs(10))
                || peer.session.last_file_data.elapsed() > Duration::from_secs(60)
            {
                failed.push((port, "private_peer_idle_timeout".into()));
            } else {
                let covered = peer.part.as_ref().map_or(0, |(_, r)| r.covered as u64);
                if should_retire_slow(
                    peer.started.elapsed(),
                    peer.score.samples(),
                    peer.score.mean(),
                    median,
                    covered,
                    peer.part.is_some(),
                    peer_count,
                ) {
                    // 慢源让位：切片由 retire 退回 Pending，其他 peer / 新源可立即接手。
                    // 只淘汰“持有切片且明显落后”的源；最后一个源永不移除。
                    failed.push((port, "private_peer_low_score".into()));
                }
            }
        }
        for (port, e) in failed {
            if e == "private_peer_low_score" {
                if let Some(peer) = peers.get(&port) {
                    slow_removed.insert(peer.session.connection.remote_endpoint, Instant::now());
                }
            }
            if retire(
                cfg,
                port,
                e,
                &mut peers,
                &mut parts,
                &mut connector,
                &mut diag,
            ) {
                retired_total += 1;
            }
        }
        for _ in 0..128 {
            let waited = Instant::now();
            let received = connector.socket().recv_from(&mut buffer);
            if let Some(d) = &mut diag {
                d.idle_wait += waited.elapsed();
            }
            let (n, from) = match received {
                Ok(r) => r,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    break
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionRefused
                            | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    continue
                }
                Err(e) => return Err(format!("private_pool_receive: {e}")),
            };
            if let Some(d) = &mut diag {
                d.udp_packets += 1;
                d.udp_bytes += n as u64;
            }
            let Ok(packet) = private_nat::decode_datagram(&buffer[..n]) else {
                if let Some(d) = &mut diag {
                    d.undecodable += 1;
                }
                continue;
            };
            if let Some(connection) = connector.on_packet(from, &packet)? {
                let port = connection.source_port;
                if let Err(e) =
                    add_connection(cfg, link, meta, connection, &mut peers, &slow_removed)
                {
                    connector.release_connection(port);
                    log::debug!("private_session_start: {e}");
                } else if let Some(d) = &mut diag {
                    d.connections_opened += 1;
                }
            }
            let port = if matches!(packet.command, 9 | 18) && packet.body.len() >= 4 {
                u16::from_le_bytes(packet.body[2..4].try_into().unwrap())
            } else if packet.command == 6 && packet.body.len() >= 8 {
                u16::from_le_bytes(packet.body[6..8].try_into().unwrap())
            } else {
                continue;
            };
            let Some(peer) = peers.get_mut(&port) else {
                if let Some(d) = &mut diag {
                    d.unrouted += 1;
                }
                continue;
            };
            let result = (|| -> Result<Option<usize>, String> {
                let mut superseded = None;
                let mut frames = peer.session.take_pending()?;
                frames.extend(peer.session.on_packet(from, &packet)?);
                assign(
                    peer,
                    &mut parts,
                    link.size,
                    goal,
                    cfg.part_filter.as_deref(),
                )?;
                for frame in frames {
                    if frame.command != 107 {
                        continue;
                    }
                    let response = private_channel::parse_response(&frame)?;
                    let Some((idx, output)) = &mut peer.part else {
                        continue;
                    };
                    output.insert(response.position, &response.data, &mut |position, bytes| {
                        file.seek(SeekFrom::Start(position))
                            .and_then(|_| file.write_all(bytes))
                            .map_err(|e| format!("ed2k_write: {e}"))?;
                        cfg.hooks.received(bytes.len() as u64);
                        peer.network += bytes.len() as u64;
                        // 源质量采样：按约 1 秒窗口汇总一次瞬时速度，
                        // 避免用几十毫秒的碎片样本污染均值/方差。
                        peer.sample_bytes += bytes.len() as u64;
                        let window = peer.sample_at.elapsed();
                        if window >= Duration::from_secs(1) {
                            peer.score.observe(peer.sample_bytes, window);
                            peer.sample_bytes = 0;
                            peer.sample_at = Instant::now();
                        }
                        first_data.get_or_insert(started.elapsed());
                        Ok(())
                    })?;
                    parts[*idx].received = parts[*idx].received.max(output.covered as u64);
                    if !peer.receiving {
                        peer.receiving = true;
                        (cfg.on_event)(PeerEvent::Receiving {
                            addr: peer.session.connection.remote_endpoint,
                            network_bytes: peer.network,
                        });
                    }
                    if output.covered == output.data.len() {
                        let done = *idx;
                        if hash::md4(&output.data) != meta.part_hashes[done] {
                            return Err("ed2k_private_part_hash_mismatch".into());
                        }
                        let part = &mut parts[done];
                        if part.shared {
                            file.seek(SeekFrom::Start(done as u64 * PARTSIZE))
                                .and_then(|_| file.write_all(&output.data))
                                .map_err(|e| format!("ed2k_write: {e}"))?;
                            superseded = Some(done);
                        }
                        part.verified = true;
                        part.holders = part.holders.saturating_sub(1);
                        part.received = output.data.len() as u64;
                        peer.part = None;
                        peer.window = None;
                        assign(
                            peer,
                            &mut parts,
                            link.size,
                            goal,
                            cfg.part_filter.as_deref(),
                        )?;
                    } else {
                        // 分片未收满：数据到达推进了 covered，把在途量补回窗口上界。
                        pump(peer)?;
                    }
                }
                Ok(superseded)
            })();
            match result {
                Err(e) => {
                    if retire(
                        cfg,
                        port,
                        e,
                        &mut peers,
                        &mut parts,
                        &mut connector,
                        &mut diag,
                    ) {
                        retired_total += 1;
                    }
                }
                Ok(Some(done)) => {
                    // No range-cancel command is known; Reset7 stops the
                    // remaining holders from uploading the finished part.
                    let losers: Vec<u16> = peers
                        .iter()
                        .filter(|(_, p)| p.part.as_ref().is_some_and(|(i, _)| *i == done))
                        .map(|(&k, _)| k)
                        .collect();
                    for loser in losers {
                        if retire(
                            cfg,
                            loser,
                            "private_part_superseded".into(),
                            &mut peers,
                            &mut parts,
                            &mut connector,
                            &mut diag,
                        ) {
                            retired_total += 1;
                        }
                    }
                }
                Ok(None) => {}
            }
            if (cfg.stop)() {
                break;
            }
        }
        let p = progress(&parts, &peers, false);
        peak = peak.max(p.transferring_peers);
        tail.observe(p.done, link.size, &peers, retired_total);
        if last_progress.elapsed() >= Duration::from_millis(100) {
            on_progress(p);
            last_progress = Instant::now();
        }
        if peers.is_empty() && connector.is_finished() && checks_pending == 0 {
            break;
        }
    }
    // 收尾统计之前必须等后台校验线程结束并把结果落定，否则会把"已校验完的片"
    // 当成未完成（恢复下载时表现为进度与已完成片数少算）。
    check_cancel.store(true, Ordering::Relaxed);
    if let Some(handle) = check_handle {
        let _ = handle.join();
    }
    for (idx, ok) in check_rx.try_iter() {
        apply_check(&mut parts, idx, ok, link.size);
        checks_pending = checks_pending.saturating_sub(1);
    }
    file.flush().map_err(|e| e.to_string())?;
    if let (Some(d), Some(observe)) = (&mut diag, &mut observer) {
        d.elapsed = started.elapsed();
        d.received = parts.iter().map(|p| p.received).sum();
        d.verified_parts = parts.iter().filter(|p| p.verified).count();
        d.connector = connector.stats();
        d.peers = peers.iter().map(|(&k, p)| peer_diag(k, p, None)).collect();
        d.tail_elapsed = tail.elapsed();
        d.tail_enter_peers = tail.at_enter_peers;
        d.tail_peak_peers = tail.peak_peers;
        d.tail_useful_peers = tail.useful.len();
        d.tail_abandoned_peers = tail.abandoned(retired_total);
        observe(d);
    }
    let stopped = (cfg.stop)();
    for peer in peers.values() {
        (cfg.on_event)(PeerEvent::Finished {
            addr: peer.session.connection.remote_endpoint,
            network_bytes: peer.network,
            error: None,
        });
    }
    let p = progress(&parts, &peers, false);
    // Stop remote uploads before the potentially long final disk verification.
    // Session::drop sends the native per-stream Reset without closing the pool.
    drop(peers);
    log::info!("ed2k_private_pool first_file_ms={:?} elapsed_ms={} peak_transferring={} verified_parts={}/{} bytes={} tail_ms={:?} tail_enter_peers={} tail_peak_peers={} tail_useful_peers={} tail_abandoned_peers={}",first_data.map(|d|d.as_millis()),started.elapsed().as_millis(),peak,p.verified_parts,total,p.done,tail.elapsed().map(|d|d.as_millis()),tail.at_enter_peers,tail.peak_peers,tail.useful.len(),tail.abandoned(retired_total));
    if !stopped && p.verified_parts == total {
        file.set_len(link.size).map_err(|e| e.to_string())?;
        let mut verifying = p.clone();
        verifying.verifying = true;
        on_progress(verifying);
        if !multi_source::verify_interruptible(cfg)? {
            return Err("ed2k_hash_mismatch".into());
        }
    }
    on_progress(p.clone());
    Ok(MultiDownload {
        written: p.done,
        verified_parts: p.verified_parts,
        total_parts: total,
        stopped,
        aich_recovered_blocks: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn held(holders: u8, age: Duration, received: u64) -> Part {
        Part {
            holders,
            assigned: Some(Instant::now() - age),
            received,
            ..Part::new()
        }
    }

    #[test]
    fn slow_source_requires_grace_samples_peers_and_a_part() {
        let grace = LOW_SCORE_GRACE;
        let median = 1_000_000.0;
        assert!(!should_retire_slow(
            grace - Duration::from_millis(1),
            3,
            0.0,
            median,
            0,
            true,
            2
        ));
        assert!(!should_retire_slow(grace, 2, 0.0, median, 1024, true, 2));
        assert!(!should_retire_slow(grace, 3, 0.0, median, 0, true, 1));
        assert!(!should_retire_slow(grace, 3, 0.0, median, 0, false, 2));
        // 零字节源没有采样窗口，超过 grace 仍应淘汰。
        assert!(should_retire_slow(grace, 0, 0.0, median, 0, true, 2));
        assert!(should_retire_slow(grace, 3, 500.0, median, 0, true, 2));
        // 有进度但低于中位数 25%（100 KiB/s < 250 KiB/s）也淘汰。
        assert!(should_retire_slow(
            grace, 3, 100_000.0, median, 1024, true, 2
        ));
        // 高于相对阈值：保留。
        assert!(!should_retire_slow(
            grace, 3, 400_000.0, median, 1024, true, 2
        ));
    }

    #[test]
    fn source_score_seeds_on_first_sample_then_tracks_mean() {
        let mut s = SourceScore::default();
        assert_eq!(s.mean(), 0.0);
        assert_eq!(s.var(), 0.0);
        s.observe(1_000_000, Duration::from_secs(1));
        assert!((s.mean() - 1_000_000.0).abs() < 1.0);
        assert_eq!(s.var(), 0.0, "首个样本只定均值，不产生方差");
        for _ in 0..10 {
            s.observe(1_000_000, Duration::from_secs(1));
        }
        assert!((s.mean() - 1_000_000.0).abs() < 1.0);
        assert!(s.var() < 1.0, "稳定速率下方差应趋零：{}", s.var());
    }

    #[test]
    fn source_score_penalises_jitter_with_variance() {
        let mut steady = SourceScore::default();
        let mut jittery = SourceScore::default();
        for _ in 0..20 {
            steady.observe(1_000_000, Duration::from_secs(1));
            jittery.observe(1_000_000, Duration::from_secs(1));
            jittery.observe(0, Duration::from_secs(1));
        }
        assert!(steady.var() < 1.0);
        assert!(
            jittery.var() > 1e9,
            "抖动源必须被方差显著惩罚：steady={} jittery={}",
            steady.var(),
            jittery.var()
        );
    }

    #[test]
    fn source_score_counts_samples_and_stays_low_for_silent_source() {
        let mut s = SourceScore::default();
        assert_eq!(s.samples(), 0);
        for _ in 0..3 {
            s.observe(0, Duration::from_secs(1));
        }
        assert_eq!(s.samples(), 3);
        assert!(
            s.mean() < LOW_SCORE_BYTES_PER_SEC,
            "零字节源的均值必须低于淘汰阈值：{}",
            s.mean()
        );
    }

    #[test]
    fn source_score_does_not_flag_a_slow_but_active_source() {
        let mut s = SourceScore::default();
        // 慢但确实在供数：每窗口 64 KiB = 64 KiB/s，远高于阈值，
        // 所以"低速"这一条不成立，不会被误淘汰。
        for _ in 0..3 {
            s.observe(64 * 1024, Duration::from_secs(1));
        }
        assert!(s.mean() >= LOW_SCORE_BYTES_PER_SEC, "{}", s.mean());
    }

    #[test]
    fn window_issues_contiguous_chunks_up_to_the_limit_then_stops() {
        let mut w = Window {
            base: 0,
            part_len: 10_000_000,
            requested_upto: 0,
        };
        let mut issued = Vec::new();
        while let Some((off, len)) = next_request(&w, 0) {
            issued.push((off, len));
            w.requested_upto += len;
        }
        // 每个请求都不得超过单请求上限
        assert!(issued.iter().all(|&(_, l)| l <= REQUEST_CHUNK));
        // 首个窗口的总量 = min(WINDOW_BYTES, 分片长度)
        let total: u64 = issued.iter().map(|&(_, l)| l).sum();
        assert_eq!(total, WINDOW_BYTES.min(10_000_000));
        // 区间必须连续、无空洞
        let mut expect = 0u64;
        for (off, len) in &issued {
            assert_eq!(*off, expect);
            expect += len;
        }
    }

    #[test]
    fn window_is_clamped_by_part_end_and_stops_when_fully_requested() {
        let mut w = Window {
            base: 0,
            part_len: 3_000_000,
            requested_upto: 0,
        };
        let mut total = 0u64;
        while let Some((_, len)) = next_request(&w, 2_000_000) {
            total += len;
            w.requested_upto += len;
        }
        assert_eq!(total, 3_000_000, "请求总量必须被分片末端夹住");
        assert!(
            next_request(&w, 3_000_000).is_none(),
            "分片已全部请求完就不再发"
        );
    }

    #[test]
    fn window_advances_only_as_bytes_actually_arrive() {
        let w = Window {
            base: 0,
            part_len: 9_728_000,
            requested_upto: 0,
        };
        // 一个字节都没收到时，最多只能请求 WINDOW_BYTES
        let mut first = w;
        let mut issued = 0u64;
        while let Some((_, len)) = next_request(&first, 0) {
            issued += len;
            first.requested_upto += len;
        }
        assert_eq!(issued, WINDOW_BYTES);
        // 收到 1 MiB 后，窗口上界随之推进 1 MiB
        let mut advanced = first;
        let mut more = 0u64;
        while let Some((_, len)) = next_request(&advanced, 1024 * 1024) {
            more += len;
            advanced.requested_upto += len;
        }
        assert_eq!(more, 1024 * 1024);
    }

    #[test]
    fn unheld_parts_are_preferred_over_duplicating_a_stalled_one() {
        let parts = [held(1, ENDGAME_AFTER * 2, 0), Part::new()];
        assert_eq!(pick(&parts, 2, None), Some(1));
    }

    #[test]
    fn only_stalled_parts_below_the_holder_cap_are_duplicated() {
        let fresh = held(1, Duration::ZERO, 0);
        assert_eq!(pick(&[fresh], 1, None), None);
        let full = held(ENDGAME_HOLDERS, ENDGAME_AFTER * 2, 0);
        assert_eq!(pick(&[full], 1, None), None);
        let verified = Part {
            verified: true,
            ..held(1, ENDGAME_AFTER * 2, 0)
        };
        assert_eq!(pick(&[verified], 1, None), None);
        let parts = [
            held(2, ENDGAME_AFTER * 2, 0),
            held(1, ENDGAME_AFTER * 2, 900),
            held(1, ENDGAME_AFTER * 2, 100),
        ];
        assert_eq!(pick(&parts, 3, None), Some(2));
    }

    #[test]
    fn duplication_never_reaches_beyond_the_goal() {
        let parts = [
            Part {
                verified: true,
                ..Part::new()
            },
            Part::new(),
        ];
        assert_eq!(pick(&parts, 1, None), None);
    }

    /// 恢复下载：已落盘分片在后台校验期间不能被分配（否则会被从头重下一遍），
    /// 且它们的字节数必须立刻计入进度（进度条不能因为"还没校验"掉回 0）。
    #[test]
    fn checking_parts_are_never_assigned_and_resolve_to_verified() {
        let size = PARTSIZE * 2;
        let mut parts = vec![
            Part {
                checking: true,
                received: PARTSIZE,
                ..Part::new()
            },
            Part::new(),
        ];
        assert_eq!(pick(&parts, 2, None), Some(1), "校验中的分片不能分配");
        apply_check(&mut parts, 0, true, size);
        assert!(parts[0].verified && !parts[0].checking);
        assert_eq!(parts[0].received, PARTSIZE);
        assert_eq!(pick(&parts, 2, None), Some(1), "已验证的分片不再分配");

        // 校验失败：回到可分配状态且字节数清零，交给 peer 重下
        let mut parts = vec![Part {
            checking: true,
            received: PARTSIZE,
            ..Part::new()
        }];
        apply_check(&mut parts, 0, false, size);
        assert!(!parts[0].verified && !parts[0].checking);
        assert_eq!(parts[0].received, 0);
        assert_eq!(pick(&parts, 1, None), Some(0));
    }
}

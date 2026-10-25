//! `fastdl`：多连接分段下载内核。
//!
//! ## 设计要点
//!
//! 1. **Range 分块 + 连接即分块**：`Range: bytes=%I64d-%I64d`，一个连接一段，
//!    并发上限默认 32。
//! 2. **动态再切分**：新连接把「当前最大剩余块」一分为二、取走上半段。
//! 3. **连接复用**：一条 TCP 上连发多次 Range，省掉每块一次 TCP+TLS 握手。
//! 4. **爬坡**：一次放到并发上限。
//! 5. **慢块救援**：为慢连接追加一条可选连接。
//! 6. **用户态 TCP 调参**：`SO_RCVBUF` + `TCP_NODELAY`，不依赖内核驱动。
//!
//! ## 关键取舍
//!
//! - **不合并**：直接定位写进预分配的最终文件，避免对整份文件多做一遍全量读写。
//! - **收包/落盘解耦**：连接线程只 recv，落盘交给写线程池，磁盘抖动不反压 TCP 窗口。
//! - **更快爬坡**：开始即放到并发上限。
//! - **抢分式再切分**：连接下完自己的块后继续领/切剩余最大块；
//!   尾部长尾由「慢块抢分」定时器主动劈开。

pub mod net;
pub mod plan;
pub mod wpool;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use aidm_core::error;
use aidm_core::hash::sha256_file;
use aidm_core::model::{self, DownloadRow, Status};
use aidm_core::segment::{backoff_for_attempt, validators_changed, ByteSpan, SEGMENT_RETRY_MAX};
use aidm_core::settings;
use aidm_core::speed::SpeedWindow;
use ring::digest::{Context, SHA256};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::limiter::TokenBucket;
use crate::manager::{IoFault, LiveState, Progress, ProgressCallback};
use crate::worker::{io_fail_string, Args, WorkerEnd};

use self::net::{Conn, NetCfg, ProxyCfg, ResponseHead, Target};
use self::plan::{Job as ChunkJob, Plan, MIN_CHUNK_BYTES};
use self::wpool::{create_preallocated, WritePool};

const STATE_VERSION: u32 = 1;
/// 每个连接一次 recv 的缓冲区大小。
const DEFAULT_CHUNK_BUF: usize = 256 * 1024;
const RAMP_STEP: usize = 8;
/// 爬坡间隔；只在 `init_conns < max_conns` 时才会用到。
const RAMP_INTERVAL: Duration = Duration::from_millis(150);

/// 起步连接数上限：`init_conns` 不会超过它，超出的部分交给 ramp 补。
///
/// 原实现是「一次就放到 `max_conns`」，其依据是 32 条时的一次实测（那时上限也低）。
/// 上限调到 256 后这个做法反噬：15 GiB 的真实任务在 `init=256` 下，握手期间成片拿到
/// `connect: unexpected end of file`（对端/代理接受不了这么多并发），失败者按
/// `backoff_for_attempt` 退避 6–8 秒 —— 表现就是"下载几乎停止，然后又一次性爆发"，
/// 并在之后形成周期锯齿。实测（256 条上限的真实镜像）：
/// 26 秒里 `segment_retry` 130 次、`code` 全是 `connect: unexpected end of file`。
///
/// 取 8：实测 1 条 = 5 MiB/s、2 条 = 10 MiB/s、8 条 = 40 MiB/s（320 Mb/s），
/// **8 条已远超家宽**（100 Mb/s 量级），再往上加只是给对端增加并发压力。
/// 其余交给 ramp 逐步补到 `max_conns`。
///
/// **关于 NTFS 的 VDL 填充，这里要说清一个反面结论**：`set_len` 只改 EOF、VDL 仍为 0，
/// 而 NTFS 写入超出 VDL 的位置时**必须先零填充到那里**，代价与偏移成正比
/// （实测 256 KiB 定位写：偏移 0 = 0.2 ms、1 GiB = 612 ms、7.2 GiB = 5888 ms）。
/// 降低起步段数不能减少填充量：VDL 是**单调最高水位**，
/// 总填充量 ≈ 文件大小，与段数无关。
/// 要免除它只有 `SetFileValidData`，而它要求 `SE_MANAGE_VOLUME_NAME` 特权；
/// 替代做法「提前把 VDL 写满」会把稀疏文件写实（磁盘占用立刻变成全额），
/// 已实测并回退。**所以这一段成本是 NTFS 的语义成本，客户端无法消除。**
pub const INIT_CONNS_CAP: usize = 8;
/// 单连接超过该吞吐就认为瓶颈不在并发数，停止爬坡。8 MiB/s ≈ 67 Mbit/s，
/// 到这个量级再加连接对总吞吐的贡献通常已经可以忽略。
const FAST_PER_CONN_BPS: u64 = 8 * 1024 * 1024;
const TICK: Duration = Duration::from_millis(100);
const PROGRESS_INTERVAL: Duration = Duration::from_millis(250);
const PERSIST_INTERVAL: Duration = Duration::from_millis(1000);
/// 剩余不足该值时解除并发爬坡限制，让尾块立刻被领走。
const TAIL_BYTES: u64 = 64 * 1024 * 1024;
/// 小于该总长不走 fastdl：小文件本来就一条连接下完，
/// 再去预分配 + 起写线程池 + 维护侧车文件只是纯开销。
pub const MIN_TOTAL_FOR_FASTDL: u64 = 16 * 1024 * 1024;

/// 一条连接被判「持续慢」之后，该块最多换几条新连接。
///
/// 必须有界：换连接解决的是"这一条连接慢"；若源本身慢，换了还是慢 ——
/// 没有上限时任务会在"放弃 → 重连 → 再放弃"里打转，永远下不完。
const SLOW_CONN_MAX_PER_CHUNK: u32 = 3;

/// 相对判据的分母：窗口内速率低于「已完成部分平均速率」的 1/3 才算慢。
///
/// 为什么不直接按"低于平均"：平均会被最快的几条连接拉高，严格按平均会把**接近一半**
/// 的连接判成慢并反复重连，反而把任务拖垮。3 这个系数与既有的慢块抢分
/// （`maybe_split_slow` 里的 `worst_rate * 3 >= median`）是同一条口径。
const SLOW_REF_DIVISOR: f64 = 3.0;

// ---------------------------------------------------------------- 续传侧车

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct State {
    pub v: u32,
    pub total: u64,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    /// 目标文件名（远端变更时要按它清理工作文件）
    pub file: String,
    pub chunks: Vec<(u64, u64, u64)>,
}

/// `<save_dir>/.aidm/<task_id>/fastdl.json`
pub fn state_path(dir: &Path, id: i64) -> PathBuf {
    aidm_core::segment::part_dir(dir, id).join("fastdl.json")
}

/// 工作文件：`<save_dir>/.aidm/<task_id>/<name>.part`，预分配到总长，完成时 rename。
pub fn work_path(dir: &Path, id: i64, name: &str) -> PathBuf {
    aidm_core::segment::part_dir(dir, id).join(format!("{name}.part"))
}

pub fn load_state(dir: &Path, id: i64) -> Option<State> {
    let raw = std::fs::read_to_string(state_path(dir, id)).ok()?;
    let st: State = serde_json::from_str(&raw).ok()?;
    if st.v != STATE_VERSION || st.total == 0 || st.chunks.is_empty() {
        return None;
    }
    Some(st)
}

/// 换源前丢弃旧的 fastdl 侧车：旧 URL 的 ETag/分段布局不再适用。
pub fn discard_state(dir: &Path, id: i64) {
    let _ = std::fs::remove_file(state_path(dir, id));
}

fn write_state(dir: &Path, id: i64, st: &State) -> std::io::Result<()> {
    let path = state_path(dir, id);
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p)?;
    }
    let tmp = path.with_extension("json.tmp");
    let mut f = std::fs::File::create(&tmp)?;
    use std::io::Write as _;
    f.write_all(serde_json::to_string(st)?.as_bytes())?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, &path)
}

/// 崩溃恢复：有 fastdl 侧车文件时用它的进度回填 segments 表，
/// 并让 `recovery` 跳过非 fastdl 路径的「按 part 文件长度对账」。
pub fn restore_from_sidecar(conn: &Connection, dir: &Path, id: i64) -> bool {
    let Some(st) = load_state(dir, id) else {
        return false;
    };
    sync_segments(conn, id, &st.chunks).is_ok()
}

fn sync_segments(conn: &Connection, id: i64, chunks: &[(u64, u64, u64)]) -> rusqlite::Result<()> {
    let spans: Vec<ByteSpan> = chunks
        .iter()
        .map(|&(s, e, _)| ByteSpan { start: s, end: e })
        .collect();
    // part_path 留空：避免 recovery 对账（按 part 文件长度回填 done_bytes）
    // 因为路径不是文件而主动跳过，进度只认侧车文件。
    let paths: Vec<String> = vec![String::new(); chunks.len()];
    model::replace_segments(conn, id, &spans, &paths)?;
    for (i, &(s, e, next)) in chunks.iter().enumerate() {
        let done = next.saturating_sub(s);
        let status = if next > e { "done" } else { "pending" };
        model::set_segment_state(conn, id, i as i32, done as i64, status)?;
    }
    Ok(())
}

/// `settings.engine.fastdl = 0` 时回退到非 fastdl 路径（灰度 / 排障）。
pub fn enabled(conn: &Connection) -> bool {
    !matches!(
        settings::get(conn, "engine.fastdl")
            .ok()
            .flatten()
            .as_deref(),
        Some("0") | Some("false")
    )
}

#[derive(Clone)]
pub struct Settings {
    pub max_conns: usize,
    pub init_conns: usize,
    pub chunk_buf: usize,
    pub writer_threads: usize,
    pub writer_queue: usize,
    pub verify_sha256: bool,
    /// 请求头配置（UA / Accept 系列 / Referer 兜底）
    pub profile: aidm_core::http_profile::RequestProfile,
    pub read_timeout: Duration,
    pub connect_timeout: Duration,
    /// 0 = 交给操作系统自动调优接收窗口（Windows 上通常是更优选择：
    /// 显式设 SO_RCVBUF 会关掉接收窗口自动调优）
    pub recv_buf: usize,
    /// 段内「持续慢」判定窗口（秒）。0 = 关闭。
    ///
    /// 与 worker 段循环用的是**同一个键与同一个内核**（`aidm_core::pace`）。差别在动作：
    /// fastdl 里没有"来源"这个概念（它对着一个 URL 开 N 条连接），所以能做的正是
    /// 「放弃当前这条连接、把该块的剩余区间交给下一条新连接」—— 单源场景下病根就在这。
    pub measure_window_s: u64,
    /// 窗口内低于该值（字节/秒）即判慢；0 = 不用这条判据（`alt.measure_min_bps`）。
    pub measure_min_bps: u64,
}

impl Settings {
    /// 从解析好的设置快照构造（一次解析、零重复查询）。
    ///
    /// `task_conns` 是**已解析好的**任务连接预算（`aidm_core::hosts::task_conns`）：
    /// 每服务器例外 > 全局闸门，恒 ≥ 1。
    pub fn from_snapshot(snap: &settings::Snapshot, task_conns: u32) -> Self {
        let max_conns = task_conns.max(1) as usize;
        Self {
            max_conns,
            init_conns: max_conns.min(INIT_CONNS_CAP),
            chunk_buf: DEFAULT_CHUNK_BUF,
            writer_threads: (max_conns / 8).clamp(1, 4),
            writer_queue: 3,
            verify_sha256: snap.verify_sha256,
            profile: aidm_core::http_profile::RequestProfile::from_snapshot(snap),
            read_timeout: Duration::from_secs(snap.idle_timeout_s.max(30)),
            connect_timeout: Duration::from_secs(snap.connect_timeout_s.max(5)),
            recv_buf: snap.recv_buf_kb as usize * 1024,
            // `Snapshot` 里没有这两个 alt.* 键（它们不属于网络栈快照），
            // 由 `run()` 从库里单独读进来覆盖；留 0 = 不观察。
            measure_window_s: 0,
            measure_min_bps: 0,
        }
    }

    /// 直接从库里解析（连接预算走唯一解析器 `hosts::task_conns`）。
    pub fn from_db(conn: &Connection, url: &str) -> Self {
        let max_conns = aidm_core::hosts::task_conns(conn, url).max(1) as usize;
        let connect_s = int_setting(conn, "conn.timeout_connect_s", 15);
        let idle_s = int_setting(conn, "conn.timeout_idle_s", 60);
        let verify_sha256 = !matches!(
            settings::get(conn, "verify.sha256_after")
                .ok()
                .flatten()
                .as_deref(),
            Some("0") | Some("false")
        );
        Self {
            max_conns,
            // 起步受 `INIT_CONNS_CAP` 限制，其余交给 ramp —— 见该常量的说明：
            // 一次放满在 256 条上限下会被对端限流，反而变成"停顿 + 爆发"。
            init_conns: max_conns.min(INIT_CONNS_CAP),
            chunk_buf: DEFAULT_CHUNK_BUF,
            writer_threads: (max_conns / 8).clamp(1, 4),
            writer_queue: 3,
            verify_sha256,
            profile: aidm_core::http_profile::RequestProfile::from_conn(conn),
            read_timeout: Duration::from_secs(idle_s.max(30)),
            connect_timeout: Duration::from_secs(connect_s.max(5)),
            recv_buf: int_setting(conn, "net.recv_buf_kb", 0) as usize * 1024,
            measure_window_s: int_setting(conn, "alt.measure_window_s", 0),
            measure_min_bps: int_setting(conn, "alt.measure_min_bps", 0),
        }
    }
}

fn int_setting(conn: &Connection, key: &str, default: u64) -> u64 {
    settings::get(conn, key)
        .ok()
        .flatten()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(default)
}

/// 单任务限速：1 秒窗口 + 休眠（与非 fastdl 路径同算法）。
struct TaskRate {
    bps: u64,
    start: Mutex<Instant>,
    used: Mutex<u64>,
}

impl TaskRate {
    fn new(kbps: i64) -> Arc<Self> {
        Arc::new(Self {
            bps: (kbps.max(0) as u64).saturating_mul(1024),
            start: Mutex::new(Instant::now()),
            used: Mutex::new(0),
        })
    }

    fn take(&self, n: u64) {
        if self.bps == 0 {
            return;
        }
        loop {
            let sleep_for = {
                let mut used = self.used.lock().unwrap();
                let mut start = self.start.lock().unwrap();
                if start.elapsed() >= Duration::from_secs(1) {
                    *start = Instant::now();
                    *used = 0;
                }
                if *used + n <= self.bps {
                    *used += n;
                    return;
                }
                Duration::from_secs(1).saturating_sub(start.elapsed())
            };
            std::thread::sleep(sleep_for.max(Duration::from_millis(5)));
        }
    }
}

/// 协调状态：计划 + 唤醒条件变量 + 停止/致命错误。
struct Shared {
    plan: Mutex<Plan>,
    cv: Condvar,
    stop: AtomicBool,
    fatal: Mutex<Option<String>>,
}

impl Shared {
    fn new(plan: Plan) -> Arc<Self> {
        Arc::new(Self {
            plan: Mutex::new(plan),
            cv: Condvar::new(),
            stop: AtomicBool::new(false),
            fatal: Mutex::new(None),
        })
    }

    fn fail(&self, msg: String) {
        let mut g = self.fatal.lock().unwrap();
        if g.is_none() {
            *g = Some(msg);
        }
        drop(g);
        self.stop.store(true, Ordering::SeqCst);
        self.cv.notify_all();
    }

    fn fatal(&self) -> Option<String> {
        self.fatal.lock().unwrap().clone()
    }

    /// 热调并发上限（来自 `settings_set`，不重启任务）。
    pub fn retune(&self, r: crate::manager::Retune) {
        let mut p = self.plan.lock().unwrap();
        match r {
            crate::manager::Retune::MaxConns(n) => p.set_max_conns(n.max(1) as usize),
            _ => {}
        }
        drop(p);
        self.cv.notify_all();
    }

    /// 取下一块；没有可做的就等（200 ms 超时兜底，不会漏唤醒）。
    fn next_job(&self, worker: u32) -> Option<ChunkJob> {
        let mut p = self.plan.lock().unwrap();
        loop {
            if self.stop.load(Ordering::SeqCst) || p.is_complete() {
                return None;
            }
            if let Some(j) = p.claim(worker) {
                return Some(j);
            }
            // 收尾：剩余不足一个最小块时不再受并发上限约束
            if p.remaining() <= MIN_CHUNK_BYTES {
                if let Some(j) = p.claim_beyond_target(worker) {
                    return Some(j);
                }
            }
            let (guard, _) = self.cv.wait_timeout(p, Duration::from_millis(200)).unwrap();
            p = guard;
        }
    }
}

/// 一次下载任务的入参。只在引擎进程内部使用。
pub(crate) struct Job<'a> {
    pub args: &'a Args,
    pub row: &'a DownloadRow,
    pub dir: &'a Path,
    pub file_name: &'a str,
    pub url: &'a str,
    pub total: u64,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub resume: bool,
    /// **探测阶段实际生效的那套请求头**。
    ///
    /// 必须由调用方传进来、不能在 fastdl 内部从设置重建：探测可能在"不声明客户端身份"
    /// 的模式下才成功（自动派生的镜像候选就是这样，见 `RequestProfile::no_browser_ua`），
    /// 而 fastdl 重建出来的档案永远是带 UA 的版本 —— 于是出现
    /// 「探测 206、真正下载时那 64 个连接全被 WAF 挡成 302」这种自相矛盾的失败。
    pub profile: aidm_core::http_profile::RequestProfile,
}

struct Ctx {
    id: i64,
    dir: PathBuf,
    file_name: String,
    url: String,
    /// HTTP 换源任务的 eD2k 整包哈希；完成前必须验过才允许 `mark_done`。
    ed2k_hash: Option<String>,
    /// 独立跑（基准测试）时为 None：没有 DB、不写 events。
    db: Option<Arc<Mutex<Connection>>>,
    live: Arc<LiveState>,
    cancel: Arc<AtomicBool>,
    pause_flag: Arc<AtomicBool>,
    speed: Arc<SpeedWindow>,
    progress_cb: Option<ProgressCallback>,
    limiter: Arc<TokenBucket>,
    io_fault: IoFault,
    cfg: Settings,
    net: NetCfg,
    target: Target,
    total: u64,
    etag: Option<String>,
    last_modified: Option<String>,
    rate: Arc<TaskRate>,
    shared: Arc<Shared>,
    pool: Arc<WritePool>,
    /// 基准测试用的速度轨迹：`(经过秒数, 累计字节)`
    trace: Option<Arc<Mutex<Vec<(f64, u64)>>>>,
    /// 累计发出的 HTTP 请求数（用于观察连接复用率）
    requests: Arc<AtomicU64>,
    /// 预分配的工作文件路径（哈希流水线要重新打开它来读）
    work: PathBuf,
    /// 与下载并行的 SHA-256 流水线
    hash: Mutex<HashState>,
    t0: Instant,
    /// 预热好的连接：`start` 之前抓的，worker 优先从这里取。
    ///
    /// 用户报告的"点下任务后一段时间没有速率"里，有一部分就是这些（经代理的）
    /// CONNECT + TLS 握手 —— 它们与磁盘预分配、段表落库互不依赖，没理由串在
    /// 用户的等待里。worker 取不到时**不等待**，自己建一条：预热只会让事情更早
    /// 开始，不会变成新的阻塞点。
    warm: Mutex<Vec<Conn>>,
    /// 启动可观测性：第一个响应体字节到达的耗时（毫秒），0 = 还没到。
    ///
    /// `start` 事件到真正有数据之间，数据库里原本是**空白**的 —— 用户报"start 后
    /// 有 10 秒极低速率"时，没有任何数据能说明那 10 秒花在哪。先把它变成可观测的。
    first_byte_ms: AtomicU64,
    /// 写盘停顿：worker 在 `pool.acquire()` 上等空缓冲的累计毫秒与次数。
    ///
    /// "应用层一度不读 socket、之后一次性交付"是回压的形状（内核接收窗口填满 →
    /// 服务器停发 → 恢复后突发），与"被拒绝"的形状不同。用户报的正是前者，
    /// 所以把这条内部成因单列出来：任务收尾时若 `count>0` 就说明瓶颈在写盘侧。
    /// 门槛 500 ms —— 低于它的等待属于正常调度抖动，不值得记。
    stall_ms: AtomicU64,
    stall_n: AtomicU64,
    /// worker 自己建连的累计耗时与次数（不含预热）。
    ///
    /// 用来分开两种形状完全不同的"没有数据"：**卡在建连**（这里涨）与
    /// **建好了但收不到数据**（这里小、却没有字节）。
    connect_ms: AtomicU64,
    connect_n: AtomicU64,
    /// 单条连接"进入读循环 → 读到第一个字节"的最大耗时（毫秒）。
    ///
    /// 这是"连好了却收不到数据"的直接量度：建连已经很快（实测 67 ms），
    /// 若这个值很大，就说明时间花在**等对端发正文**上，而不是握手或调度。
    read_wait_max_ms: AtomicU64,
    /// **单次** `read_up_to` 调用的最大耗时（毫秒）。
    ///
    /// 与 `read_wait_max_ms`（进入读循环 → 首个字节）不同，这个每次读都更新，
    /// 所以一个**正卡在 `io.read()` 里**的连接也会让它变大 —— 用来确认"等正文"
    /// 到底等了多久（`read_wait_max_ms` 只在读完之后才写，卡住时恒为旧值）。
    read_call_max_ms: AtomicU64,
    /// 单条连接"发出请求 → 拿到响应头"的最大耗时（毫秒）。
    ///
    /// 与 `read_wait_max_ms` 是两段相邻但成因完全不同的等待：
    /// 前者为 0 而这里很大 ⇒ 连接卡在**响应头**上（请求已发出、对端还没答），
    /// 而不是卡在正文读取，也不是卡在建连（那有 `connect_ms`）。
    req_wait_max_ms: AtomicU64,
    /// 第一条实际写出去的请求头（诊断用）。
    ///
    /// 卡点已定位在 `Conn::request` 上，而 curl 对同一目标 0.26 s 就响应 ——
    /// 两者差异只能在这些字节里，所以把它原样留下来给人核对。
    first_head: Mutex<Option<String>>,
    /// 三个阶段的**在途**计数（进入 − 完成）。
    ///
    /// 前面那三段"最大耗时"都只在**完成后**才记录，所以一个**正卡在**该阶段的连接
    /// 不会让它的值变大 —— 实测就出现过"三段计时全是小值、却有 28 个块没有数据"。
    /// 光看耗时无法区分"卡在建连 / 卡在等响应头 / 卡在等正文"，用进入与完成的差
    /// 才能把在途数直接读出来。
    enter_connect: AtomicU64,
    enter_request: AtomicU64,
    req_done_n: AtomicU64,
    enter_read: AtomicU64,
    read_first_n: AtomicU64,
    /// 因「持续慢」放弃并重开的连接数（段内换连接的直接证据）。
    slow_conns: AtomicU64,
}

struct HashState {
    hasher: Context,
    hashed_upto: u64,
    digest: Option<String>,
}

impl Ctx {
    /// **单连接口径**的「已完成部分」平均速率（B/s）。
    ///
    /// 段内「持续慢」判定的参照物，与 worker 段循环同口径：拿**已完成的部分**当基准
    /// （已落盘字节 ÷ 已花掉的时间），而不是拿某个理想值。0 字节时回 `None` —— 不是 0：
    /// 0 会让每一条连接一上来就被判慢。
    fn per_conn_avg_bps(&self) -> Option<f64> {
        let ms = self.t0.elapsed().as_millis() as u64;
        if ms == 0 {
            return None;
        }
        // 除以**活跃连接数**：参照物必须是单条连接的量级。拿任务总量比，
        // N 条连接每条只分到总量的 1/N，会全部被判慢（实测：4 条同速连接全被换掉）。
        let (done, active) = {
            let p = self.shared.plan.lock().unwrap();
            (p.bytes_done, p.active().max(1))
        };
        if done == 0 {
            return None;
        }
        Some(done as f64 * 1000.0 / ms as f64 / active as f64)
    }
    fn with_db<R>(&self, f: impl FnOnce(&Connection) -> R) -> Option<R> {
        let g = self.db.as_ref()?;
        let conn = g.lock().unwrap();
        Some(f(&conn))
    }
}

// ---------------------------------------------------------------- 入口

pub(crate) fn run(job: Job<'_>) -> WorkerEnd {
    let args = job.args;
    let id = args.id;

    let (cfg, net) = {
        // 一次装载、一次解析：以前这里要分 6 次 settings::get + 1 次代理解析。
        let (cfg, proxy_url, bypass, only_for) = {
            let conn = args.db.lock().unwrap();
            let snap =
                settings::Snapshot::load(&conn).unwrap_or_else(|_| settings::Snapshot::defaults());
            let cfg = {
                let base = aidm_core::hosts::task_conns(&conn, &job.row.url_orig).max(1) as usize;
                // 签名直链异常后的按任务退避上限：只在找源失败后才会存在。
                // 启动/正常任务没有这一行，因此仍然使用正常并发。
                let cap = model::get_conn_cap(&conn, id)
                    .ok()
                    .flatten()
                    .map(|c| c.conn_cap as usize)
                    .unwrap_or(base)
                    .max(1);
                let mut c = Settings::from_snapshot(&snap, base.min(cap) as u32);
                // 用调用方那套**已生效**的头覆盖掉从设置重建的结果：
                // 探测是怎么成功的，下载就必须怎么发（否则见 `Job::profile` 的注释）。
                c.profile = job.profile.clone();
                // 段内「持续慢」的两个键（与 worker 段循环同一口径，见 `aidm_core::pace`）。
                // 在这里读，是因为 `Snapshot` 不含 alt.* 键，而这条路径拿得到连接。
                c.measure_window_s = int_setting(&conn, "alt.measure_window_s", 0);
                c.measure_min_bps = int_setting(&conn, "alt.measure_min_bps", 0);
                c
            };
            (
                cfg,
                crate::http_util::resolve_proxy_url(&conn),
                snap.proxied_hosts_skip.clone(),
                snap.proxy_only_for.clone(),
            )
        };
        // 例外服务器 / 代理开关语义：
        // 命中排除表、或协议被 only_for 排除时，这条任务直接连。
        let host = aidm_core::sched::url_host(job.url);
        let https = job
            .url
            .trim_start()
            .to_ascii_lowercase()
            .starts_with("https://");
        let skip_proxy = aidm_core::sched::host_matches_any(&bypass, &host)
            || match only_for.as_str() {
                "http" => https,
                "https" => !https,
                _ => false,
            };
        let proxy = if skip_proxy {
            None
        } else {
            proxy_url.as_deref().and_then(ProxyCfg::parse)
        };
        if skip_proxy && proxy_url.is_some() {
            log::info!("fastdl: 目标命中代理排除规则，直连 {host}");
        }
        let net = NetCfg {
            task: args.id,
            // 浏览器发起的任务透传浏览器的 UA
            profile: cfg
                .profile
                .clone()
                .with_browser_user_agent(args.browser_user_agent.as_deref()),
            // 没给 Referer 时按设置补站点根；但兜底值若与目标同源，
            // 会被 CDN 判成盗链（实测同源 Referer → 403，不带 → 206），故省略。
            referer: cfg
                .profile
                .referer_for(args.referer.as_deref(), job.url)
                .filter(|r| {
                    args.referer.is_some() || !crate::http_util::same_origin(r, job.url)
                }),
            cookies: args.cookies.clone().filter(|s| !s.is_empty()),
            custom_headers: args
                .custom_headers
                .as_deref()
                .map(aidm_core::headers::parse_custom_headers)
                .transpose()
                .ok()
                .flatten()
                .unwrap_or_default(),
            connect_timeout: cfg.connect_timeout,
            read_timeout: cfg.read_timeout,
            recv_buf: cfg.recv_buf,
            proxy,
        };
        (cfg, net)
    };

    let target = match Target::parse(job.url) {
        Ok(t) => t,
        Err(e) => return WorkerEnd::Failed(format!("url: {e}")),
    };
    if matches!(args.io_fault, IoFault::DiskFull | IoFault::NoPermission) {
        return WorkerEnd::Failed(io_fail_string(args.io_fault, io_err("write"), "write"));
    }

    let work = work_path(job.dir, id, job.file_name);
    // 侧车文件只有在该任务的工作文件仍存在、且长度正好是总长时才可信；
    // 否则会诞生「计划说已下完 + 文件刚被 set_len 归零」这种假完成。
    let work_ok = std::fs::metadata(&work)
        .map(|m| m.len() == job.total)
        .unwrap_or(false);
    let state = if job.resume && work_ok {
        load_state(job.dir, id)
    } else {
        None
    };
    let plan = match &state {
        Some(st)
            if st.total == job.total
                && !validators_changed(
                    st.etag.as_deref(),
                    st.last_modified.as_deref(),
                    job.etag.as_deref(),
                    job.last_modified.as_deref(),
                ) =>
        {
            let mut p = Plan::from_snapshot(st.total, &st.chunks, cfg.max_conns);
            // 设置改动（或上次是在更小并发下跑的）后把段数补到当前并发上限：
            // 只切「还有剩余」的块，已下完的区间一动不动，进度零损失。
            let mut guard = 0;
            while p.chunks.len() < cfg.max_conns && guard < cfg.max_conns * 4 {
                if p.split_largest().is_none() {
                    break;
                }
                guard += 1;
            }
            p
        }
        Some(_) => {
            crate::merge::remove_part_dir(job.dir, id);
            return WorkerEnd::Failed(error::CODE_REMOTE_CHANGED.into());
        }
        None => Plan::new(job.total, cfg.init_conns, cfg.max_conns),
    };
    let is_resume = state.is_some();

    let file = match create_preallocated(&work, job.total) {
        Ok(f) => Arc::new(f),
        Err(e) => return WorkerEnd::Failed(io_fail_string(args.io_fault, e, "create")),
    };

    let already = plan.bytes_done;
    {
        let conn = args.db.lock().unwrap();
        let _ = sync_segments(&conn, id, &plan.snapshot());
        let _ = model::set_status(&conn, id, Status::Downloading, None);
        model::log_event(
            &conn,
            id,
            if is_resume { "resume" } else { "start" },
            Some(&format!(
                "mode=fastdl conns={} init={} total={} resume={is_resume} proxy={} direct_write=1",
                cfg.max_conns,
                cfg.init_conns,
                job.total,
                net.proxy.is_some()
            )),
        );
    }

    let shared = Shared::new(plan);
    shared.plan.lock().unwrap().set_target(cfg.init_conns);
    args.live.total_bytes.store(job.total, Ordering::Relaxed);
    args.live.done_bytes.store(already, Ordering::Relaxed);

    // 登记热调回调：设置里改连接上限时管理器直接调它，**不重启任务**。
    {
        let shared = shared.clone();
        args.retune.set(Arc::new(move |r| shared.retune(r)));
    }

    // fastdl 的写线程是真实落盘点，必须持写入许可。
    // span 覆盖整个工作文件：fastdl 的分块本来就可以写任意偏移，
    // 许可在这里管的是「谁有权写」和「轮次是否还有效」，不是分块边界。
    let lease = job.args.gate.as_ref().map(|gate| {
        gate.issue(
            aidm_core::download::model::AssignmentId::new(format!("fastdl:{id}")),
            aidm_core::download::model::SliceId::new(format!("fastdl:{id}")),
            aidm_core::download::model::Span::known(0, job.total)
                .unwrap_or_else(|| aidm_core::download::model::Span::open(0)),
        )
    });
    // fastdl 收尾时把许可摘掉（池里的写线程已经 drain 过才会走到析构）。
    let _reaper = match (&job.args.gate, &lease) {
        (Some(gate), Some(lease)) => Some(gate.reaper(lease)),
        _ => None,
    };
    let pool = Arc::new(WritePool::new_guarded(
        file.clone(),
        cfg.writer_threads,
        cfg.writer_queue,
        cfg.chunk_buf,
        cfg.max_conns,
        job.args.gate.clone(),
        lease,
    ));

    let ctx = Arc::new(Ctx {
        id,
        dir: job.dir.to_path_buf(),
        file_name: job.file_name.to_string(),
        url: job.url.to_string(),
        ed2k_hash: job.row.ed2k_hash.clone().filter(|_| {
            !job.row
                .url_orig
                .trim_start()
                .to_ascii_lowercase()
                .starts_with("ed2k:")
        }),
        db: Some(args.db.clone()),
        live: args.live.clone(),
        cancel: args.cancel.clone(),
        pause_flag: args.pause.clone(),
        speed: args.speed_window.clone(),
        progress_cb: args.progress_cb.clone(),
        limiter: args.limiter.clone(),
        io_fault: args.io_fault,
        cfg: cfg.clone(),
        net,
        target,
        total: job.total,
        etag: job.etag.clone(),
        last_modified: job.last_modified.clone(),
        rate: TaskRate::new(job.row.speed_limit_kbps),
        shared: shared.clone(),
        pool: pool.clone(),
        trace: None,
        requests: Arc::new(AtomicU64::new(0)),
        work: work.clone(),
        hash: Mutex::new(HashState {
            hasher: Context::new(&SHA256),
            hashed_upto: 0,
            digest: None,
        }),
        t0: Instant::now(),
        warm: Mutex::new(Vec::new()),
        first_byte_ms: AtomicU64::new(0),
        stall_ms: AtomicU64::new(0),
        stall_n: AtomicU64::new(0),
        connect_ms: AtomicU64::new(0),
        connect_n: AtomicU64::new(0),
        read_wait_max_ms: AtomicU64::new(0),
        read_call_max_ms: AtomicU64::new(0),
        req_wait_max_ms: AtomicU64::new(0),
        first_head: Mutex::new(None),
        enter_connect: AtomicU64::new(0),
        enter_request: AtomicU64::new(0),
        req_done_n: AtomicU64::new(0),
        enter_read: AtomicU64::new(0),
        read_first_n: AtomicU64::new(0),
        slow_conns: AtomicU64::new(0),
    });

    // 预热连接：与下面的 worker 并发跑，worker 优先取预热的
    preconnect(&ctx);

    let end = drive(&ctx);
    // 写盘回压汇总：两个等待点任一发生就留痕 —— `count` 是 worker 等**空缓冲**
    // 超过 0.5 秒的次数，`submit_n` 是在 `submit` 上等**写队列**腾位的次数。
    // 只有 `submit_n` 非零说明写队列先满（一个深偏移的定位写就能卡住全部连接）；
    // 两者都非零说明连缓冲池也耗尽，瓶颈已经是磁盘吞吐本身。
    ctx.with_db(|conn| {
        let n = ctx.stall_n.load(Ordering::Relaxed);
        // `submit` 上的等待（写队列满）与 `acquire` 上的等待（缓冲池空）是**两个独立**
        // 的回压点，必须一起报：只记录其中一个时，另一个方向的冻结无法观测。
        let (submit_n, submit_ms) = ctx.pool.submit_wait();
        if n > 0 || submit_n > 0 {
            let stall_ms = ctx.stall_ms.load(Ordering::Relaxed);
            let _ = model::log_event(
                conn,
                ctx.id,
                "write_stall",
                Some(&format!(
                    "count={n} total_ms={stall_ms} submit_n={submit_n} submit_ms={submit_ms}"
                )),
            );
            tracing::warn!(
                event = "transfer.stall",
                phase = "store",
                outcome = "fail",
                kind = "write_backpressure",
                count = n,
                total_ms = stall_ms,
                submit_n,
                submit_ms,
            );
        }
        // worker 自建连的合计：与 `first_byte` 一起看，就能分开"卡在建连"（这里大）
        // 与"连好了但收不到数据"（这里小、却迟迟没有字节）。
        let cn = ctx.connect_n.load(Ordering::Relaxed);
        if cn > 0 {
            let total = ctx.connect_ms.load(Ordering::Relaxed);
            let _ = model::log_event(
                conn,
                ctx.id,
                "conn_timing",
                Some(&format!(
                    "count={cn} total_ms={total} avg_ms={}",
                    total / cn
                )),
            );
            tracing::info!(
                event = "net.connect",
                phase = "connect",
                outcome = "ok",
                conns = cn,
                total_ms = total,
                avg_ms = total / cn,
            );
        }
    });
    // 写池收尾：把剩余缓冲全部落盘 —— 这一步的耗时是「写盘开销」的直接观测点
    // （规格 §3.3 store.fsync）。
    let sync_t = std::time::Instant::now();
    let write_err = pool.finish();
    tracing::info!(
        event = "store.fsync",
        phase = "store",
        dur_ms = sync_t.elapsed().as_millis() as u64,
        mode = "fastdl_pool_finish",
    );

    match end {
        End::Failed(code) => {
            // 失败也要先把最后一段进度落库，否则段里的 done 会比实际少一截
            persist(&ctx);
            WorkerEnd::Failed(code)
        }
        End::Paused => {
            // 线程已全部收束，先把当前进度落库再宣告 paused；persist 是 1 Hz 采样，
            // 不补这一次的话「暂停后进度变小」。
            persist(&ctx);
            ctx.with_db(|conn| {
                let _ = model::set_status(conn, ctx.id, Status::Paused, None);
                model::log_event(conn, ctx.id, "paused", Some("mode=fastdl"));
            });
            WorkerEnd::Paused
        }
        End::Cancelled => {
            persist(&ctx);
            WorkerEnd::Cancelled
        }
        End::Complete => {
            if let Some(e) = write_err {
                return WorkerEnd::Failed(io_fail_string(args.io_fault, io_err(&e), "write"));
            }
            if let Some(code) = shared.fatal() {
                return WorkerEnd::Failed(code);
            }
            finish_ok(&ctx, &file, &work)
        }
    }
}

/// 起连接线程 → 监督 → 收线程。`run` 与 `fetch_standalone` 共用。
/// `start` 之前把连接先握上手。
///
/// 这些（经代理的）CONNECT + TLS 握手与磁盘预分配、段表落库互不依赖，
/// 没理由串在用户的等待里。预热线程与 worker **并发**跑：worker 取到预热连接就
/// 直接发请求，取不到就自己建 —— 所以这里慢也不会拖住启动，只是没帮上忙。
///
/// 数量取 `init_conns`：与 worker 线程数一致，正好一换一。多建的连接随 `warm`
/// 一起 drop（`Conn` 的 Drop 关闭 socket），不泄漏。
fn preconnect(ctx: &Arc<Ctx>) {
    let n = ctx.cfg.init_conns.max(1);
    for _ in 0..n {
        let c = ctx.clone();
        // 起不来就算了：worker 自己会建，这里纯属帮忙
        let _ = std::thread::Builder::new()
            .name(format!("aidm-fd-warm-{}", ctx.id))
            .stack_size(256 * 1024)
            .spawn(move || {
                if c.shared.stop.load(Ordering::SeqCst) {
                    return;
                }
                if let Ok(conn) = Conn::open(&c.target, &c.net) {
                    let mut g = c.warm.lock().unwrap();
                    // 上限防呆：worker 可能已经自己建完了
                    if g.len() < n {
                        g.push(conn);
                    }
                }
            });
    }
}

fn drive(ctx: &Arc<Ctx>) -> End {
    let mut handles = Vec::with_capacity(ctx.cfg.max_conns);
    for w in 0..ctx.cfg.max_conns {
        let c = ctx.clone();
        match std::thread::Builder::new()
            .name(format!("aidm-fd-{}-{w}", ctx.id))
            .stack_size(512 * 1024)
            .spawn(move || worker_loop(c, w as u32))
        {
            Ok(h) => handles.push(h),
            Err(e) => {
                ctx.shared.fail(format!("spawn worker: {e}"));
                break;
            }
        }
    }
    let end = supervise(ctx);
    ctx.shared.stop.store(true, Ordering::SeqCst);
    ctx.shared.cv.notify_all();
    for h in handles {
        if h.join().is_err() {
            ctx.shared.fail("worker panicked".into());
        }
    }
    end
}

fn io_err(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, msg.to_string())
}

// ---------------------------------------------------------------- 监督循环

enum End {
    Complete,
    Paused,
    Cancelled,
    Failed(String),
}

fn supervise(ctx: &Arc<Ctx>) -> End {
    let mut last_progress = Instant::now();
    let mut last_persist = Instant::now();
    let mut last_ramp = Instant::now();
    let mut last_straggler = Instant::now();
    let mut last_bytes = ctx.shared.plan.lock().unwrap().bytes_done;
    let mut ramping = true;
    // 停顿期的快照每 3 秒记一条：只看第一次的话，`req_wait_max_ms` 这类累计量
    // 还停在早期的小值上，看不出它是否随停顿一起增长。
    let mut stall_last_log: Option<Instant> = None;
    let mut samples: HashMap<usize, (u64, Instant)> = HashMap::new();

    loop {
        if ctx.cancel.load(Ordering::SeqCst) {
            persist(ctx);
            return End::Cancelled;
        }
        if ctx.pause_flag.load(Ordering::SeqCst) {
            persist(ctx);
            // 注意：这里 **不** 写 paused 状态。调用方还要 join 连接线程与写线程，
            // 状态必须等线程真正停下来再置位，否则 IPC 会看到 paused 而任务仍在跑，
            // 紧接着的 resume 会撞上 "task_already_running"。
            return End::Paused;
        }
        if let Some(code) = ctx.shared.fatal() {
            persist(ctx);
            return End::Failed(code);
        }

        let (done, remaining, active, target, complete, started) = {
            let p = ctx.shared.plan.lock().unwrap();
            (
                p.bytes_done,
                p.remaining(),
                p.active(),
                p.target(),
                p.is_complete(),
                p.started(),
            )
        };
        if done > last_bytes {
            ctx.speed.add(done - last_bytes);
        }
        last_bytes = done;
        ctx.live.done_bytes.store(done, Ordering::Relaxed);
        let sp = ctx.speed.bytes_per_sec();
        ctx.live.speed_bps.store(sp, Ordering::Relaxed);
        if last_progress.elapsed() >= PROGRESS_INTERVAL {
            if let Some(cb) = &ctx.progress_cb {
                cb(Progress {
                    id: ctx.id,
                    done_bytes: done,
                    total: Some(ctx.total),
                    speed_bps: sp,
                });
            }
            if let Some(tr) = &ctx.trace {
                tr.lock()
                    .unwrap()
                    .push((ctx.t0.elapsed().as_secs_f64(), done));
            }
            last_progress = Instant::now();
        }
        if last_persist.elapsed() >= PERSIST_INTERVAL {
            persist(ctx);
            last_persist = Instant::now();
        }
        if complete {
            persist(ctx);
            return End::Complete;
        }

        // 停顿诊断：**与 ramp 无关**，只要出现"连上却没数据"就记（每 3 秒一条）。
        // 必须放在 `can_grow` 之外：低并发时 `target` 已经等于上限、`can_grow` 为 false，
        // 而实测恰恰是"加到第 2 条连接就晚数秒才有数据"—— 放在里面就整个漏掉了。
        if active >= 2 && started < active {
            let due = stall_last_log.map_or(true, |t| t.elapsed() >= Duration::from_secs(3));
            if due {
                stall_last_log = Some(Instant::now());
                ctx.with_db(|conn| {
                    let _ = model::log_event(
                        conn,
                        ctx.id,
                        "ramp_stall",
                        Some(&format!(
                            "active={active} started={started} target={target} \
                             wait_connect={} wait_request={} wait_read={} \
                             req_wait_max_ms={} read_wait_max_ms={} read_call_max_ms={} head={:?}",
                            ctx.enter_connect
                                .load(Ordering::Relaxed)
                                .saturating_sub(ctx.connect_n.load(Ordering::Relaxed)),
                            ctx.enter_request
                                .load(Ordering::Relaxed)
                                .saturating_sub(ctx.req_done_n.load(Ordering::Relaxed)),
                            ctx.enter_read
                                .load(Ordering::Relaxed)
                                .saturating_sub(ctx.read_first_n.load(Ordering::Relaxed)),
                            ctx.req_wait_max_ms.load(Ordering::Relaxed),
                            ctx.read_wait_max_ms.load(Ordering::Relaxed),
                            ctx.read_call_max_ms.load(Ordering::Relaxed),
                            ctx.first_head
                                .lock()
                                .unwrap()
                                .as_deref()
                                .map(|h| h.chars().take(400).collect::<String>())
                                .unwrap_or_default()
                        )),
                    );
                });
            }
        }

        // 并发爬坡：默认一路加到配置上限，
        // 只有「单连接本身已经很快」时才提前收手——那说明瓶颈不在并发数。
        //
        // 这里刻意不用「加一批连接后 1 秒内速度没涨就停」的规则：新连接要付
        // TCP+TLS 握手与慢启动，增益是滞后的，用短窗口判会一路上不去。
        if ramping && last_ramp.elapsed() >= RAMP_INTERVAL {
            let can_grow =
                remaining > (target as u64 + 1) * MIN_CHUNK_BYTES && target < ctx.cfg.max_conns;
            if can_grow {
                let per_conn = if active > 0 {
                    sp / active.max(1) as u64
                } else {
                    0
                };
                // 扩充守卫（保守）：只有**多数**连接都收不到数据时才停止扩充并发。
                // 与上面的诊断分开是刻意的 —— 记录要敏感，改行为要保守。
                let stalled_guard = active >= 8 && started * 4 < active;
                if stalled_guard {
                    // 本轮不扩充；等对端开口后 `per_conn` 会自己涨上来
                } else if active >= 8 && per_conn > FAST_PER_CONN_BPS {
                    ramping = false;
                    ctx.with_db(|conn| {
                        model::log_event(
                            conn,
                            ctx.id,
                            "ramp_stop",
                            Some(&format!(
                                "conns={target} per_conn={per_conn} reason=fast_per_connection"
                            )),
                        );
                    });
                } else {
                    let next = (target + RAMP_STEP).min(ctx.cfg.max_conns);
                    ctx.shared.plan.lock().unwrap().set_target(next);
                    ctx.shared.cv.notify_all();
                    ctx.with_db(|conn| {
                        model::log_event(conn, ctx.id, "ramp", Some(&format!("conns={next}")));
                    });
                }
            } else if target >= ctx.cfg.max_conns {
                ramping = false;
            }
            last_ramp = Instant::now();
        }

        // 收尾：剩余不大时解除并发限制，让尾块立刻被领走。
        if remaining <= TAIL_BYTES && target < ctx.cfg.max_conns {
            ctx.shared
                .plan
                .lock()
                .unwrap()
                .set_target(ctx.cfg.max_conns);
            ctx.shared.cv.notify_all();
        }

        // 慢块抢分（alternative connection）。
        //
        // 但**只在"多数连接真的在传数据"时才做**：否则"最慢的段"只是"还没拿到
        // 数据的段"，切它只会造出更多需要建连的段，而新连接同样拿不到数据 ——
        // 形成正反馈。实测（15 GiB 真实任务）：停顿期 `target` 被这条
        // 路径从 32 一路推到 136，而 `started` 始终只有 32，`req_wait_max_ms` 涨到
        // 2771 ms。判据取"有数据的段不少于活跃段的一半"。
        if last_straggler.elapsed() >= Duration::from_secs(1) {
            last_straggler = Instant::now();
            if sp > 0 && started * 2 >= active {
                maybe_split_slow(ctx, &mut samples);
            }
        }

        // 与下载并行的 SHA-256：把「收尾时再整文件读一遍」摊到下载过程里。
        // 只对「从文件头算起连续完成的区间」动刀，读到的一定是最终字节。
        hash_step(ctx, HASH_BUDGET_PER_TICK);

        let guard = ctx.shared.plan.lock().unwrap();
        let _ = ctx.shared.cv.wait_timeout(guard, TICK).unwrap();
    }
}

/// 单次 tick 最多哈希多少字节。这是**上限**而非占空比：哈希一旦追上「从文件头
/// 连续完成的区间」，后续 tick 就无事可做、不再耗 CPU。
/// ring（SHA-NI）实测 GB/s 级；16 MB 的预算会花掉约 200 ms CPU、把驱动循环拖慢，
/// 所以放到 64 MB：即使一直处于追赶状态每拍也只占约 40 ms（≈40% 单核），
/// 追上之后为零。
const HASH_BUDGET_PER_TICK: usize = 64 * 1024 * 1024;

/// SHA-256 流水线：把已完成前缀里还没哈希的部分补上。
fn hash_step(ctx: &Arc<Ctx>, budget: usize) {
    if !ctx.cfg.verify_sha256 {
        return;
    }
    let hashable = {
        let p = ctx.shared.plan.lock().unwrap();
        p.complete_prefix()
    };
    let mut st = match ctx.hash.lock() {
        Ok(g) => g,
        Err(_) => return,
    };
    if st.digest.is_some() || hashable <= st.hashed_upto {
        return;
    }
    // 写线程是异步的：`plan.next` 只代表「已提交」，读之前先等它落盘。
    ctx.pool.drain();
    let end = hashable.min(st.hashed_upto.saturating_add(budget as u64));
    let start = st.hashed_upto;
    if let Ok(n) = hash_file_range(&ctx.work, start, end, &mut st.hasher) {
        st.hashed_upto = start + n;
    } else {
        // 读失败不阻断下载：收尾时再兜底整文件算一遍
        st.digest = Some(String::new());
    }
}

fn hash_file_range(
    path: &Path,
    start: u64,
    end: u64,
    hasher: &mut Context,
) -> std::io::Result<u64> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path)?;
    f.seek(SeekFrom::Start(start))?;
    let mut buf = vec![0u8; 1024 * 1024];
    let mut off = start;
    while off < end {
        let want = ((end - off) as usize).min(buf.len());
        let n = f.read(&mut buf[..want])?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        off += n as u64;
    }
    Ok(off - start)
}

/// 收尾：把剩余部分哈希完，返回十六进制摘要。
fn hash_finish(ctx: &Arc<Ctx>) -> Option<String> {
    if !ctx.cfg.verify_sha256 {
        return None;
    }
    let mut st = ctx.hash.lock().ok()?;
    if let Some(d) = &st.digest {
        if !d.is_empty() {
            return Some(d.clone());
        }
    }
    ctx.pool.drain();
    while st.hashed_upto < ctx.total {
        let start = st.hashed_upto;
        let end = (start + HASH_BUDGET_PER_TICK as u64).min(ctx.total);
        match hash_file_range(&ctx.work, start, end, &mut st.hasher) {
            Ok(0) => break,
            Ok(n) => st.hashed_upto = start + n,
            Err(_) => return None,
        }
    }
    if st.hashed_upto != ctx.total {
        return None;
    }
    let d = hex_lower(st.hasher.clone().finish().as_ref());
    st.digest = Some(d.clone());
    Some(d)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// 每秒采样各块进度，把速度远低于中位数的块劈成两半。
///
/// 这是「长尾」的关键：32 条连接里只要有一条被中间设备限速，末尾就会有一整块
/// 拖后腿。为慢连接追加一条替代连接即可解决。
fn maybe_split_slow(ctx: &Arc<Ctx>, samples: &mut HashMap<usize, (u64, Instant)>) {
    let now = Instant::now();
    let mut rates: Vec<(usize, u64)> = Vec::new();
    let mut refresh: Vec<(usize, u64)> = Vec::new();
    {
        let p = ctx.shared.plan.lock().unwrap();
        for (i, c) in p.chunks.iter().enumerate() {
            refresh.push((i, c.next));
            if c.done || c.owner.is_none() {
                continue;
            }
            if let Some((prev, t)) = samples.get(&i) {
                let dt = now.duration_since(*t).as_secs_f64().max(0.2);
                let delta = c.next.saturating_sub(*prev);
                rates.push((i, (delta as f64 / dt) as u64));
            }
        }
    }
    for (i, next) in refresh {
        samples.insert(i, (next, now));
    }
    if rates.len() < 4 {
        return;
    }
    let mut sorted: Vec<u64> = rates.iter().map(|(_, r)| *r).collect();
    sorted.sort_unstable();
    let median = sorted[sorted.len() / 2];
    if median == 0 {
        return;
    }
    let &(worst, worst_rate) = rates.iter().min_by_key(|(_, r)| *r).unwrap();
    if worst_rate * 3 >= median {
        return;
    }
    let mut p = ctx.shared.plan.lock().unwrap();
    if p.chunks.len() >= ctx.cfg.max_conns * 2 {
        return;
    }
    if p.split_at(worst).is_none() {
        return;
    }
    let next_target = (p.target() + 1).min(ctx.cfg.max_conns);
    p.set_target(next_target);
    drop(p);
    ctx.with_db(|conn| {
        model::log_event(
            conn,
            ctx.id,
            "chunk_split",
            Some(&format!(
                "reason=slow_chunk idx={worst} rate={worst_rate} median={median}"
            )),
        );
    });
    // 只切出了**一个**新块，唤醒一个等待者就够；其余靠 `next_job` 的超时兜底。
    ctx.shared.cv.notify_one();
}

// ---------------------------------------------------------------- 连接线程

fn worker_loop(ctx: Arc<Ctx>, worker: u32) {
    let mut conn: Option<Conn> = None;
    loop {
        if ctx.shared.stop.load(Ordering::SeqCst)
            || ctx.cancel.load(Ordering::SeqCst)
            || ctx.pause_flag.load(Ordering::SeqCst)
        {
            return;
        }
        let Some(job) = ctx.shared.next_job(worker) else {
            return;
        };
        let idx = job.idx;
        match fetch_chunk(&ctx, &mut conn, idx) {
            Fetch::Done => {
                ctx.shared.plan.lock().unwrap().complete(idx);
                // `notify_one` 而不是 `notify_all`：完成一块**并不产生新的可领块**
                // （完成的块不再需要下载），所以这里唤醒全部等待者等于"叫醒 256 个
                // 线程、其中 255 个抢锁失败再睡回去" —— 纯开销。
                // 保留一次唤醒是为了收尾阶段（剩余不足一个最小块时 `next_job` 会走
                // `claim_beyond_target` 那条路），漏掉的唤醒由 `next_job` 里 200 ms 的
                // `wait_timeout` 兜底。
                ctx.shared.cv.notify_one();
            }
            Fetch::Stop => {
                ctx.shared.plan.lock().unwrap().release(idx);
                return;
            }
            Fetch::Fatal(code) => {
                ctx.shared.plan.lock().unwrap().release(idx);
                ctx.shared.fail(code);
                return;
            }
        }
    }
}

enum Fetch {
    Done,
    Stop,
    Fatal(String),
}

/// 把一块下完（内部负责重试与退避）。
fn fetch_chunk(ctx: &Arc<Ctx>, conn: &mut Option<Conn>, idx: usize) -> Fetch {
    let mut attempt = 0u32;
    // 本块因「持续慢」换过几次连接（有上限，见 SLOW_CONN_MAX_PER_CHUNK）。
    let mut slow_conns = 0u32;
    loop {
        if ctx.shared.stop.load(Ordering::SeqCst)
            || ctx.cancel.load(Ordering::SeqCst)
            || ctx.pause_flag.load(Ordering::SeqCst)
        {
            return Fetch::Stop;
        }
        // 位置以计划为准：可能已被收窄，也可能被别的连接推进过
        let (pos, end_now) = {
            let p = ctx.shared.plan.lock().unwrap();
            match p.chunks.get(idx) {
                Some(c) => (c.next, c.end()),
                None => return Fetch::Done,
            }
        };
        if pos > end_now {
            return Fetch::Done;
        }

        match stream_range(
            ctx,
            conn,
            idx,
            pos,
            end_now,
            slow_conns < SLOW_CONN_MAX_PER_CHUNK,
        ) {
            Ok(Streamed {
                written,
                drained,
                slow,
            }) => {
                if !drained {
                    *conn = None;
                }
                // 「持续慢」不是错误：**不消耗失败重试预算**（`attempt` 不动），
                // 直接换一条新连接，从落盘位置续下该块的剩余区间（同一块、同一来源）。
                if let Some(reason) = slow {
                    slow_conns += 1;
                    ctx.slow_conns.fetch_add(1, Ordering::Relaxed);
                    ctx.with_db(|c| {
                        model::log_event(
                            c,
                            ctx.id,
                            "segment_retry",
                            Some(&format!(
                                "mode=fastdl idx={idx} attempt={attempt} code=slow_conn reason={} swapped={slow_conns}",
                                reason.as_str()
                            )),
                        );
                    });
                    continue;
                }
                let done_now = {
                    let p = ctx.shared.plan.lock().unwrap();
                    p.chunks.get(idx).map(|c| written > c.end()).unwrap_or(true)
                };
                if done_now {
                    return Fetch::Done;
                }
                // 短读（服务端提前断开 / 被收窄后又放开）：带新位置重试
                attempt += 1;
                if attempt > SEGMENT_RETRY_MAX {
                    return Fetch::Fatal("short_body".into());
                }
            }
            Err(FetchErr { code, soft }) => {
                *conn = None;
                if !soft || is_fatal(&code) {
                    return Fetch::Fatal(code);
                }
                attempt += 1;
                ctx.with_db(|c| {
                    let _ = model::set_segment_retries(c, ctx.id, idx as i32, attempt as i64);
                    model::log_event(
                        c,
                        ctx.id,
                        "segment_retry",
                        Some(&format!(
                            "mode=fastdl idx={idx} attempt={attempt} code={code}"
                        )),
                    );
                });
                if attempt > SEGMENT_RETRY_MAX {
                    return Fetch::Fatal(code);
                }
                let wait = backoff_for_attempt(attempt);
                let deadline = Instant::now() + wait;
                while Instant::now() < deadline {
                    if ctx.shared.stop.load(Ordering::SeqCst)
                        || ctx.cancel.load(Ordering::SeqCst)
                        || ctx.pause_flag.load(Ordering::SeqCst)
                    {
                        return Fetch::Stop;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
    }
}

struct Streamed {
    written: u64,
    /// 响应体是否正好读到请求末端（决定连接能否复用）
    drained: bool,
    /// 本次是**因为「持续慢」主动放弃连接**（`None` = 正常读完或被收窄/短读）。
    ///
    /// 带上它，`fetch_chunk` 才能把"放弃慢连接"与"服务端提前断开"分开处理：
    /// 前者不是错误、不该消耗失败重试预算，后者才消耗。
    slow: Option<aidm_core::pace::SlowReason>,
}

struct FetchErr {
    code: String,
    /// true = 可重试（网络抖动），false = 直接致命
    soft: bool,
}

fn soft_err(code: impl Into<String>) -> FetchErr {
    FetchErr {
        code: code.into(),
        soft: true,
    }
}

fn hard_err(code: impl Into<String>) -> FetchErr {
    FetchErr {
        code: code.into(),
        soft: false,
    }
}

/// 一次 Range 请求的完整收包过程。
fn stream_range(
    ctx: &Arc<Ctx>,
    conn: &mut Option<Conn>,
    idx: usize,
    pos: u64,
    end_now: u64,
    // 是否观察「持续慢」（达到每块上限后置 false：不再观察，老实下完）。
    observe_slow: bool,
) -> Result<Streamed, FetchErr> {
    // 连接线程不在 worker 的 `enter_task` 作用域内；这里用**阶段 span**补 task 字段，
    // 覆盖本段读循环的日志（`io.fault.injected`、`transfer.first_byte` 等）。
    let _task = aidm_core::obs::enter_task("stream", ctx.id);
    if conn.is_none() {
        // 优先用预热的连接（`start` 之前就握好的手）；取不到就直接建，**不等待** ——
        // 预热只该让第一条请求更早发出去，不该成为新的等待点。
        *conn = ctx.warm.lock().unwrap().pop();
        if conn.is_none() {
            let t = Instant::now();
            ctx.enter_connect.fetch_add(1, Ordering::Relaxed);
            match Conn::open(&ctx.target, &ctx.net) {
                Ok(c) => {
                    ctx.connect_n.fetch_add(1, Ordering::Relaxed);
                    ctx.connect_ms
                        .fetch_add(t.elapsed().as_millis() as u64, Ordering::Relaxed);
                    *conn = Some(c);
                }
                Err(e) => return Err(soft_err(format!("connect: {e}"))),
            }
        }
    }
    let req_t0 = Instant::now();
    ctx.enter_request.fetch_add(1, Ordering::Relaxed);
    let head: ResponseHead =
        match conn
            .as_mut()
            .unwrap()
            .request(&ctx.net, "GET", Some((pos, Some(end_now))))
        {
            Ok(h) => h,
            Err(e) => return Err(soft_err(format!("request: {e}"))),
        };
    ctx.req_done_n.fetch_add(1, Ordering::Relaxed);
    ctx.req_wait_max_ms
        .fetch_max(req_t0.elapsed().as_millis() as u64, Ordering::Relaxed);
    // 留下第一条请求头（诊断用）：卡点在 `request()` 上，与 curl 的差异只能在这些字节里。
    {
        let mut g = ctx.first_head.lock().unwrap();
        if g.is_none() {
            if let Some(h) = conn.as_ref().and_then(|c| c.last_head.clone()) {
                *g = Some(h);
            }
        }
    }
    if let Err(code) = check_head(ctx, &head, pos) {
        return Err(FetchErr {
            soft: !is_fatal(&code),
            code,
        });
    }
    ctx.requests.fetch_add(1, Ordering::Relaxed);
    if head.status == 200 && pos > 0 {
        return Err(hard_err("range_ignored"));
    }
    // 服务端可能把末端截到比请求更短（例如它自己限制单次范围）
    let server_end = head
        .content_range
        .map(|(_, e, _)| e)
        .unwrap_or(end_now)
        .min(end_now);

    let mut written = pos;
    // 服务端「声明」的正文长度：206 就是请求的区间长度；200 则是它自己报的
    // Content-Length（忽略 Range 时会等于整个文件）。只有把声明长度正好读完，
    // 才允许复用这条 TCP —— 否则残留正文会被下一个请求当成响应头读进去。
    let declared: Option<u64> = match head.status {
        206 => Some(server_end.saturating_sub(pos).saturating_add(1)),
        _ => head.content_length,
    };
    let c = conn.as_mut().unwrap();
    let mut body = c.body();
    // 本条连接「进入读循环 → 读到首个字节」的耗时，取全局最大值。
    let read_t0 = Instant::now();
    // 连接级「持续慢」观察窗（与 worker 段循环同一个内核）。`measure_window_s == 0`
    // 时是 `None` = 完全不观察，这条热路径的行为与从前逐字节一致。
    let mut slow_gate = if observe_slow {
        aidm_core::pace::SlowGate::new(ctx.cfg.measure_window_s, ctx.cfg.measure_min_bps)
    } else {
        None
    };
    let mut got_first = false;
    ctx.enter_read.fetch_add(1, Ordering::Relaxed);
    loop {
        if ctx.shared.stop.load(Ordering::SeqCst)
            || ctx.cancel.load(Ordering::SeqCst)
            || ctx.pause_flag.load(Ordering::SeqCst)
        {
            break;
        }
        // 每一轮都重新读计划末端：被抢分收窄就立刻停手
        let live_end = {
            let p = ctx.shared.plan.lock().unwrap();
            p.chunks.get(idx).map(|ch| ch.end()).unwrap_or(server_end)
        }
        .min(server_end);
        if written > live_end {
            break;
        }
        // 等空缓冲的耗时是回压的唯一测量点：worker 在这里停下就不再读 socket，
        // 内核接收窗口填满后服务器停发，恢复时表现为"一次性突发"。
        let wait_t0 = Instant::now();
        let Some(mut buf) = ctx.pool.acquire() else {
            return Err(hard_err("write_pool_closed"));
        };
        let waited = wait_t0.elapsed();
        if waited >= Duration::from_millis(500) {
            ctx.stall_n.fetch_add(1, Ordering::Relaxed);
            ctx.stall_ms
                .fetch_add(waited.as_millis() as u64, Ordering::Relaxed);
        }
        let want = ((live_end - written + 1) as usize).min(ctx.cfg.chunk_buf);
        // 单次读调用计时：卡在 io.read() 里的连接也能让它变大（见字段说明）。
        let read_call_t = Instant::now();
        // 故障注入（规格 §8）：**建连成功之后**才失败 —— 这条链路正是"连得上、
        // 收不到数据"，必须能从事件序列里与"建连失败"区分开。
        let read_res = match ctx.io_fault {
            IoFault::Timeout | IoFault::Disconnect => {
                let kind = if matches!(ctx.io_fault, IoFault::Timeout) {
                    "timeout"
                } else {
                    "disconnect"
                };
                tracing::warn!(
                    event = "io.fault.injected",
                    kind,
                    msg = "读循环注入故障：连接已建立但对端不再给数据",
                );
                Err(std::io::Error::new(
                    if matches!(ctx.io_fault, IoFault::Timeout) {
                        std::io::ErrorKind::TimedOut
                    } else {
                        std::io::ErrorKind::ConnectionReset
                    },
                    "injected read fault",
                ))
            }
            // 慢速滴灌：**不失败**，只是极慢 —— 用来验证"速度/TTFB 指标能不能看出来"，
            // 与上面两条（真失败）是不同类别的故障。
            IoFault::SlowDrip => {
                std::thread::sleep(Duration::from_millis(200));
                body.read_up_to(&mut buf[..want])
            }
            _ => body.read_up_to(&mut buf[..want]),
        };
        ctx.read_call_max_ms
            .fetch_max(read_call_t.elapsed().as_millis() as u64, Ordering::Relaxed);
        match read_res {
            Ok(0) => {
                break;
            }
            Ok(n) => {
                // 本条连接的首字节等待（取最大值）：与 `first_byte`（全局第一个字节）
                // 分开看，才能区分"整体起步慢"与"个别连接一直等不到数据"。
                if !got_first {
                    got_first = true;
                    ctx.read_first_n.fetch_add(1, Ordering::Relaxed);
                    ctx.read_wait_max_ms
                        .fetch_max(read_t0.elapsed().as_millis() as u64, Ordering::Relaxed);
                }
                // 启动可观测性：第一个字节到达时记一次。
                // `start` 事件到真正有数据之间，数据库里原本是空白的 ——
                // 用户报"start 后还有 10 秒极低速率"时，无从判断那段时间花在哪。
                // `warm_left` 顺带说明预热连接还剩几条没用上（0 表示 worker 全靠自己建）。
                if ctx.first_byte_ms.load(Ordering::Relaxed) == 0 {
                    let ms = ctx.t0.elapsed().as_millis().max(1) as u64;
                    if ctx
                        .first_byte_ms
                        .compare_exchange(0, ms, Ordering::Relaxed, Ordering::Relaxed)
                        .is_ok()
                    {
                        let warm_left = ctx.warm.lock().unwrap().len();
                        // 顺带带上首批建连的合计：`first_byte` 是"第一个字节到了"的时刻，
                        // 此时若 `conn_avg_ms` 很大，说明这一等是花在**建连**上；
                        // 若它很小，则连接早就好了、卡的是"等对端发数据"。
                        let cn = ctx.connect_n.load(Ordering::Relaxed);
                        let cms = ctx.connect_ms.load(Ordering::Relaxed);
                        let conn = if cn > 0 {
                            format!(" conns={cn} conn_avg_ms={}", cms / cn)
                        } else {
                            String::new()
                        };
                        ctx.with_db(|c| {
                            let _ = model::log_event(
                                c,
                                ctx.id,
                                "first_byte",
                                Some(&format!("ms={ms} warm_left={warm_left}{conn}")),
                            );
                        });
                        tracing::info!(
                            event = "transfer.first_byte",
                            phase = "transfer",
                            dur_ms = ms,
                            warm_left,
                            conns = cn,
                            conn_avg_ms = if cn > 0 { cms / cn } else { 0 },
                        );
                    }
                }
                let off = written;
                if !ctx.pool.submit(buf, n, off, idx) {
                    return Err(hard_err(write_err_code(ctx)));
                }
                written += n as u64;
                ctx.shared.plan.lock().unwrap().advance(idx, written);
                // 段内「持续慢」的连接级动作（R-DL-14）：本条连接在窗口内的速率低于
                // 「已完成部分平均速率 ÷ SLOW_REF_DIVISOR」（或低于绝对下限）时**放弃它** ——
                // 返回 `slow`，由 `fetch_chunk` 换一条新连接，从当前落盘位置继续下该块的
                // 剩余区间（同一块、同一来源，只换连接；不混源也不丢字节）。
                if let Some(gate) = slow_gate.as_mut() {
                    let reference = ctx.per_conn_avg_bps().map(|v| v / SLOW_REF_DIVISOR);
                    if let aidm_core::pace::Pace::Switch(reason) =
                        gate.observe(read_t0.elapsed(), written - pos, reference)
                    {
                        return Ok(Streamed {
                            written,
                            drained: false,
                            slow: Some(reason),
                        });
                    }
                }
                ctx.limiter.take(n as u64);
                ctx.rate.take(n as u64);
            }
            Err(e) => {
                // 已落盘部分保留在计划里，下次从新位置续
                return Err(soft_err(format!(
                    "{}transfer: read: {e}",
                    aidm_core::error::PHASE_PREFIX
                )));
            }
        }
    }
    drop(body);
    let consumed = written.saturating_sub(pos);
    let drained = declared.map(|d| consumed == d).unwrap_or(false);
    Ok(Streamed {
        written,
        drained,
        slow: None,
    })
}

fn write_err_code(ctx: &Arc<Ctx>) -> String {
    match ctx.io_fault {
        IoFault::DiskFull => error::CODE_DISK_FULL.into(),
        IoFault::NoPermission => error::CODE_NO_PERMISSION.into(),
        // 其余注入不改写盘出口（Timeout/Disconnect/SlowDrip 在读循环，
        // Corrupt 在校验前，DnsFail 在解析阶段）。
        _ => ctx
            .pool
            .error()
            .map(|e| io_fail_string(IoFault::None, io_err(&e), "write"))
            .unwrap_or_else(|| "write_failed".into()),
    }
}

fn check_head(ctx: &Arc<Ctx>, head: &ResponseHead, pos: u64) -> Result<(), String> {
    if head.status != 206 && !(head.status == 200 && pos == 0) {
        return Err(format!("http_{}", head.status));
    }
    if validators_changed(
        ctx.etag.as_deref(),
        ctx.last_modified.as_deref(),
        head.etag.as_deref(),
        head.last_modified.as_deref(),
    ) {
        return Err(error::CODE_REMOTE_CHANGED.into());
    }
    if let Some((_, _, total)) = head.content_range {
        if total != ctx.total {
            return Err(error::CODE_REMOTE_CHANGED.into());
        }
    }
    Ok(())
}

fn is_fatal(code: &str) -> bool {
    let c = error::classify(code);
    match c.code.as_str() {
        error::CODE_REMOTE_CHANGED
        | error::CODE_DISK_FULL
        | error::CODE_NO_PERMISSION
        | error::CODE_HTTP_401
        | error::CODE_HTTP_403
        | error::CODE_HTTP_404 => true,
        error::CODE_HTTP_4XX => !matches!(c.http_status, Some(408 | 429)),
        _ => false,
    }
}

// ---------------------------------------------------------------- 持久化与收尾

/// 落一次侧车文件 + segments 表（1 Hz 调用，暂停/取消/完成时也调用）。
fn persist(ctx: &Arc<Ctx>) {
    let (snap, done) = {
        let p = ctx.shared.plan.lock().unwrap();
        (p.snapshot(), p.bytes_done)
    };
    let st = State {
        v: STATE_VERSION,
        total: ctx.total,
        etag: ctx.etag.clone(),
        last_modified: ctx.last_modified.clone(),
        file: ctx.file_name.clone(),
        chunks: snap.clone(),
    };
    let _ = write_state(&ctx.dir, ctx.id, &st);
    // 进度事件节流到 5 秒一条（persist 自身是 1 Hz；规格 §3.4 不逐块记录）。
    let now_ms = aidm_core::model::now_ms() as u64;
    let last = ctx.live.last_progress_log_ms.load(Ordering::Relaxed);
    if now_ms.saturating_sub(last) >= 5_000
        && ctx
            .live
            .last_progress_log_ms
            .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        tracing::debug!(
            event = "transfer.progress",
            phase = "transfer",
            mode = "fastdl",
            done_bytes = done,
            total_bytes = ctx.total,
            segments = snap.len(),
            speed_bps = ctx.live.speed_bps.load(Ordering::Relaxed),
        );
    }
    ctx.with_db(|conn| {
        // 运行中「慢块抢分」会增加块数：行数一旦和当前布局对不上，索引就不再对应
        // 同一段字节，必须按当前布局重建行，否则进度会算错（暂停后进度不满、
        // 完成后仍不是 100% 都是这么来的）。
        let rows = model::count_segments(conn, ctx.id).unwrap_or(0);
        if rows as usize != snap.len() {
            let spans: Vec<ByteSpan> = snap
                .iter()
                .map(|&(s, e, _)| ByteSpan { start: s, end: e })
                .collect();
            // part_path 留空：fastdl 的进度只认侧车文件，不走「按 part 长度对账」。
            let paths: Vec<String> = vec![String::new(); snap.len()];
            let _ = model::replace_segments(conn, ctx.id, &spans, &paths);
        }
        for (i, &(s, e, next)) in snap.iter().enumerate() {
            let status = if next > e { "done" } else { "pending" };
            let _ = model::set_segment_state(
                conn,
                ctx.id,
                i as i32,
                next.saturating_sub(s) as i64,
                status,
            );
        }
        let _ = model::set_probe_meta(
            conn,
            ctx.id,
            &ctx.url,
            Some(ctx.total as i64),
            ctx.etag.as_deref(),
            ctx.last_modified.as_deref(),
        );
        let _ = done;
    });
}

fn finish_ok(ctx: &Arc<Ctx>, file: &Arc<std::fs::File>, work: &Path) -> WorkerEnd {
    // 字节已经下完，后面还有 flush（脏页回写）/ sha256 / 改名，GB 级文件可能要几十秒。
    // 这段时间必须离开 downloading，否则界面会出现「进度 100% 却还显示下载中」。
    ctx.with_db(|conn| {
        let _ = model::set_status(conn, ctx.id, Status::Verifying, None);
    });
    if let Err(e) = file.sync_all() {
        return WorkerEnd::Failed(io_fail_string(ctx.io_fault, e, "flush"));
    }
    // 目标文件名可能在下载过程中被用户改过（IPC rename），必须现取现用。
    let name = ctx
        .with_db(|conn| {
            model::get_download(conn, ctx.id)
                .ok()
                .flatten()
                .map(|r| r.file_name)
        })
        .flatten()
        .unwrap_or_else(|| ctx.file_name.clone());
    ctx.with_db(|conn| {
        model::log_event(
            conn,
            ctx.id,
            "verifying",
            Some(&format!("mode=fastdl bytes={}", ctx.total)),
        );
    });
    let final_path = ctx.dir.join(&name);
    if let Some(parent) = final_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if final_path.exists() {
        let same = std::fs::metadata(&final_path)
            .map(|m| m.len() == ctx.total)
            .unwrap_or(false);
        if same {
            // 已有等长同名文件：以本次下载结果为准，覆盖它
        }
        let _ = std::fs::remove_file(&final_path);
    }
    if let Err(e) = std::fs::rename(work, &final_path) {
        // 跨卷或占用：退化成复制
        if let Err(e2) = std::fs::copy(work, &final_path) {
            return WorkerEnd::Failed(format!("rename: {e}; copy: {e2}"));
        }
        let _ = std::fs::remove_file(work);
    }

    let hash = if ctx.cfg.verify_sha256 {
        // 流水线通常已经算完，这里只是补尾巴
        hash_finish(ctx).or_else(|| sha256_file(&final_path).ok())
    } else {
        None
    };
    // HTTP 换源任务：SHA-256 之外还要按 eD2k 整包 MD4 验收，验过才允许 mark_done。
    // 放在 rename 之后、写 done 之前；失败时任务保持 error，不会产出“看似完成”的错误文件。
    if let Some(want) = ctx.ed2k_hash.as_deref() {
        ctx.with_db(|conn| {
            let _ = model::set_status(conn, ctx.id, aidm_core::model::Status::Verifying, None);
            model::log_event(conn, ctx.id, "verifying", Some("mode=fastdl ed2k=1"));
        });
        match aidm_core::ed2k::hash::hash_file(aidm_core::ed2k::Flavor::Official, &final_path) {
            Ok(done) if done.file_hex().eq_ignore_ascii_case(want) => {
                ctx.with_db(|conn| {
                    model::log_event(conn, ctx.id, "ed2k_hash_ok", Some(want));
                });
            }
            Ok(done) => {
                let got = done.file_hex();
                ctx.with_db(|conn| {
                    model::log_event(
                        conn,
                        ctx.id,
                        "ed2k_hash_mismatch",
                        Some(&format!("want={want} got={got}")),
                    );
                });
                return WorkerEnd::Failed(aidm_core::error::CODE_ED2K_HASH_MISMATCH.into());
            }
            Err(e) => return WorkerEnd::Failed(format!("ed2k_hash_io: {e}")),
        }
    }
    ctx.with_db(|conn| {
        if let Some(h) = hash.as_deref() {
            model::log_event(conn, ctx.id, "sha256", Some(h));
        }
        let _ = model::mark_done(conn, ctx.id, &ctx.url);
        // 完成以文件为准：把各段收尾成整段下满，避免「已完成但进度 < 100%」
        let _ = model::finalize_segments(conn, ctx.id);
        model::log_event(
            conn,
            ctx.id,
            "done",
            Some(&format!(
                "mode=fastdl bytes={} sha256={}",
                ctx.total,
                hash.as_deref().unwrap_or("-")
            )),
        );
    });
    ctx.live.done_bytes.store(ctx.total, Ordering::Relaxed);
    ctx.live.speed_bps.store(0, Ordering::Relaxed);
    crate::merge::remove_part_dir(&ctx.dir, ctx.id);
    WorkerEnd::Done
}

// ---------------------------------------------------------------- 独立跑（基准测试）

/// 独立运行参数：不落 DB、不写事件，只把文件下下来并回报数据。
pub struct Standalone {
    pub url: String,
    pub dir: PathBuf,
    pub file_name: String,
    pub max_conns: usize,
    pub init_conns: usize,
    pub chunk_buf: usize,
    pub proxy: Option<String>,
    pub verify_sha256: bool,
    /// 请求头配置（UA / Accept 系列 / Referer 兜底）
    pub profile: aidm_core::http_profile::RequestProfile,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    /// 0 = 交给操作系统自动调优接收窗口
    pub recv_buf: usize,
    /// 段内「持续慢」的判定窗口（秒）与绝对下限（B/s）；0 = 关闭。
    /// 引擎路径从设置键读；基准没有 DB，所以由调用方显式给（`--window-s` / `--min-bps`）。
    pub measure_window_s: u64,
    pub measure_min_bps: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Report {
    pub bytes: u64,
    pub secs: f64,
    pub mb_per_s: f64,
    pub sha256: Option<String>,
    pub chunks: usize,
    pub splits: u32,
    pub http_requests: u64,
    /// `(经过秒数, 累计字节)`，250 ms 采样一次
    pub trace: Vec<(f64, u64)>,
    pub final_path: String,
    /// 因「持续慢」放弃并重开的连接数（段内换连接）。
    pub slow_conns: u64,
}

/// 一次自发自收的探测：拿总长、ETag、Last-Modified，并确认服务端支持 Range。
fn standalone_probe(
    url: &str,
    net: &NetCfg,
) -> Result<(Target, u64, Option<String>, Option<String>), String> {
    let target = Target::parse(url)?;
    let mut conn = Conn::open(&target, net).map_err(|e| format!("connect: {e}"))?;
    let head = conn
        .request(net, "GET", Some((0, Some(0))))
        .map_err(|e| format!("request: {e}"))?;
    let total = head
        .content_range
        .map(|(_, _, t)| t)
        .or(head.content_length)
        .ok_or_else(|| format!("unknown size (status {})", head.status))?;
    if head.status != 206 {
        return Err(format!(
            "server does not honour Range (status {}), cannot fan out",
            head.status
        ));
    }
    // 把 1 字节探测体读掉，别让连接带着未读数据进池
    {
        let mut body = conn.body();
        let mut one = [0u8; 8];
        let _ = body.read_up_to(&mut one);
    }
    Ok((target, total, head.etag, head.last_modified))
}

pub fn fetch_standalone(o: Standalone) -> Result<Report, String> {
    let cfg = Settings {
        max_conns: o.max_conns.clamp(1, 256),
        init_conns: o.init_conns.max(1).min(o.max_conns.max(1)),
        chunk_buf: o.chunk_buf.max(16 * 1024),
        writer_threads: (o.max_conns / 8).clamp(1, 4),
        writer_queue: 3,
        verify_sha256: o.verify_sha256,
        profile: aidm_core::http_profile::RequestProfile::default(),
        read_timeout: o.read_timeout,
        connect_timeout: o.connect_timeout,
        recv_buf: o.recv_buf,
        // 独立基准没有 DB，读不到 alt.* 键 ⇒ 段内换连接默认关闭；
        // 要让基准也吃这两个键，由调用方在 Standalone 上显式给出（下一轮接）。
        measure_window_s: o.measure_window_s,
        measure_min_bps: o.measure_min_bps,
    };
    let profile = aidm_core::http_profile::RequestProfile::default();
    let net = NetCfg {
        task: 0,
        // 独立抓取也走同一套 Referer 兜底；同源兜底同样省略。
        referer: profile
            .referer_for(None, &o.url)
            .filter(|r| !crate::http_util::same_origin(r, &o.url)),
        profile,
        cookies: None,
        custom_headers: Vec::new(),
        connect_timeout: cfg.connect_timeout,
        read_timeout: cfg.read_timeout,
        recv_buf: o.recv_buf,
        proxy: o.proxy.as_deref().and_then(ProxyCfg::parse),
    };
    let (target, total, etag, last_modified) = standalone_probe(&o.url, &net)?;

    let work = o.dir.join(format!(".aidm-bench/{}.part", o.file_name));
    let file =
        Arc::new(create_preallocated(&work, total).map_err(|e| format!("preallocate: {e}"))?);
    let plan = Plan::new(total, cfg.init_conns, cfg.max_conns);
    let shared = Shared::new(plan);
    shared.plan.lock().unwrap().set_target(cfg.init_conns);
    let pool = Arc::new(WritePool::new(
        file.clone(),
        cfg.writer_threads,
        cfg.writer_queue,
        cfg.chunk_buf,
        cfg.max_conns,
    ));
    let trace = Arc::new(Mutex::new(Vec::<(f64, u64)>::new()));
    let ctx = Arc::new(Ctx {
        id: 0,
        dir: o.dir.clone(),
        file_name: o.file_name.clone(),
        url: o.url.clone(),
        ed2k_hash: None,
        db: None,
        live: Arc::new(LiveState::default()),
        cancel: Arc::new(AtomicBool::new(false)),
        pause_flag: Arc::new(AtomicBool::new(false)),
        speed: Arc::new(SpeedWindow::new()),
        progress_cb: None,
        limiter: TokenBucket::new(0),
        io_fault: IoFault::None,
        cfg: cfg.clone(),
        net,
        target,
        total,
        etag,
        last_modified,
        rate: TaskRate::new(0),
        shared: shared.clone(),
        pool: pool.clone(),
        trace: Some(trace.clone()),
        requests: Arc::new(AtomicU64::new(0)),
        work: work.clone(),
        hash: Mutex::new(HashState {
            hasher: Context::new(&SHA256),
            hashed_upto: 0,
            digest: None,
        }),
        t0: Instant::now(),
        warm: Mutex::new(Vec::new()),
        first_byte_ms: AtomicU64::new(0),
        stall_ms: AtomicU64::new(0),
        stall_n: AtomicU64::new(0),
        connect_ms: AtomicU64::new(0),
        connect_n: AtomicU64::new(0),
        read_wait_max_ms: AtomicU64::new(0),
        read_call_max_ms: AtomicU64::new(0),
        req_wait_max_ms: AtomicU64::new(0),
        first_head: Mutex::new(None),
        enter_connect: AtomicU64::new(0),
        enter_request: AtomicU64::new(0),
        req_done_n: AtomicU64::new(0),
        enter_read: AtomicU64::new(0),
        read_first_n: AtomicU64::new(0),
        slow_conns: AtomicU64::new(0),
    });

    // 预热连接：与下面的 worker 并发跑，worker 优先取预热的
    preconnect(&ctx);

    let end = drive(&ctx);
    // 写盘回压汇总：两个等待点任一发生就留痕 —— `count` 是 worker 等**空缓冲**
    // 超过 0.5 秒的次数，`submit_n` 是在 `submit` 上等**写队列**腾位的次数。
    // 只有 `submit_n` 非零说明写队列先满（一个深偏移的定位写就能卡住全部连接）；
    // 两者都非零说明连缓冲池也耗尽，瓶颈已经是磁盘吞吐本身。
    ctx.with_db(|conn| {
        let n = ctx.stall_n.load(Ordering::Relaxed);
        // `submit` 上的等待（写队列满）与 `acquire` 上的等待（缓冲池空）是**两个独立**
        // 的回压点，必须一起报：只记录其中一个时，另一个方向的冻结无法观测。
        let (submit_n, submit_ms) = ctx.pool.submit_wait();
        if n > 0 || submit_n > 0 {
            let stall_ms = ctx.stall_ms.load(Ordering::Relaxed);
            let _ = model::log_event(
                conn,
                ctx.id,
                "write_stall",
                Some(&format!(
                    "count={n} total_ms={stall_ms} submit_n={submit_n} submit_ms={submit_ms}"
                )),
            );
            tracing::warn!(
                event = "transfer.stall",
                phase = "store",
                outcome = "fail",
                kind = "write_backpressure",
                count = n,
                total_ms = stall_ms,
                submit_n,
                submit_ms,
            );
        }
        // worker 自建连的合计：与 `first_byte` 一起看，就能分开"卡在建连"（这里大）
        // 与"连好了但收不到数据"（这里小、却迟迟没有字节）。
        let cn = ctx.connect_n.load(Ordering::Relaxed);
        if cn > 0 {
            let total = ctx.connect_ms.load(Ordering::Relaxed);
            let _ = model::log_event(
                conn,
                ctx.id,
                "conn_timing",
                Some(&format!(
                    "count={cn} total_ms={total} avg_ms={}",
                    total / cn
                )),
            );
            tracing::info!(
                event = "net.connect",
                phase = "connect",
                outcome = "ok",
                conns = cn,
                total_ms = total,
                avg_ms = total / cn,
            );
        }
    });
    // 写池收尾：把剩余缓冲全部落盘 —— 这一步的耗时是「写盘开销」的直接观测点
    // （规格 §3.3 store.fsync）。
    let sync_t = std::time::Instant::now();
    let write_err = pool.finish();
    tracing::info!(
        event = "store.fsync",
        phase = "store",
        dur_ms = sync_t.elapsed().as_millis() as u64,
        mode = "fastdl_pool_finish",
    );
    let (bytes, chunks, splits) = {
        let p = ctx.shared.plan.lock().unwrap();
        (p.bytes_done, p.chunks.len(), p.splits)
    };
    match end {
        End::Complete => {}
        End::Failed(code) => return Err(format!("failed: {code}")),
        End::Paused => return Err("paused".into()),
        End::Cancelled => return Err("cancelled".into()),
    }
    if let Some(e) = write_err {
        return Err(format!("write: {e}"));
    }
    if bytes != total {
        return Err(format!("short: {bytes}/{total}"));
    }
    let final_path = o.dir.join(&o.file_name);
    let _ = std::fs::remove_file(&final_path);
    std::fs::rename(&work, &final_path).map_err(|e| format!("rename: {e}"))?;
    // 流水线通常已在下载期间算完，这里只补尾巴；计时口径含哈希与改名，
    // 从启动到目标目录出现完整文件的墙钟时间。
    let sha256 = if o.verify_sha256 {
        hash_finish(&ctx)
    } else {
        None
    };
    let secs = ctx.t0.elapsed().as_secs_f64();
    let trace = trace.lock().unwrap().clone();
    Ok(Report {
        bytes,
        secs,
        mb_per_s: bytes as f64 / 1_048_576.0 / secs.max(1e-6),
        sha256,
        chunks,
        splits,
        http_requests: ctx.requests.load(Ordering::Relaxed),
        trace,
        final_path: final_path.to_string_lossy().into_owned(),
        slow_conns: ctx.slow_conns.load(Ordering::Relaxed),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_roundtrip() {
        let _tmp = crate::testsupport::tempdir("fastdl");
        let dir = _tmp.path().to_path_buf();
        let st = State {
            v: STATE_VERSION,
            total: 1 << 30,
            etag: Some("\"x\"".into()),
            last_modified: None,
            file: "a.iso".into(),
            chunks: vec![(0, 511, 100), (512, 1023, 512)],
        };
        write_state(&dir, 7, &st).unwrap();
        let back = load_state(&dir, 7).unwrap();
        assert_eq!(back.total, st.total);
        assert_eq!(back.chunks, st.chunks);
        assert_eq!(back.file, "a.iso");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn work_path_uses_task_dir() {
        let p = work_path(Path::new("D:/dl"), 9, "x.iso");
        assert!(p.ends_with("x.iso.part"));
        assert!(p.to_string_lossy().contains(".aidm"));
    }

    #[test]
    fn fatal_codes() {
        assert!(is_fatal(error::CODE_DISK_FULL));
        assert!(is_fatal("http_404"));
        assert!(!is_fatal("read: timed out"));
        assert!(!is_fatal("http_429"));
    }
}

//! 引擎下载管理器（分段续传 + 设置 / 全局限速 / 代理 / 批删 / 推送）。
//!
//! 职责：任务生命周期、Range 探测、多连接分段、限速令牌桶、进程内代理、
//! 批量删除、完成/统计推送。HTTP 仅在引擎进程内发生。

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aidm_core::error;
use aidm_core::filename::resolve_filename;
use aidm_core::model::{self, DownloadRow, Status};
use aidm_core::proxy;
use aidm_core::sched;
use aidm_core::settings;
use aidm_core::speed::SpeedWindow;
use aidm_ipc::{
    truncate_offer_items, validate_add_fields, validate_alt_urls, validate_url, EngineEvent,
    OfferItem, OFFER_TTL_SECS,
};
pub use aidm_ipc::{SegmentView, TaskView};
use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::http_util::HttpRuntime;
use crate::limiter::TokenBucket;
use crate::merge::cleanup_task_files;
use crate::queue_gate::{QueueBudget, QueueVerdict};
use crate::recovery::{self, RecoverOutcome};
use crate::worker;

/// eD2k 切片方案缓存：首次规划后固定。
///
/// 文档 6.1：运行时连接预算变化**不重新编号切片**，工作拆分发生在
/// Assignment 子区间层。若每次查询都按最新预算重新分组，同一个 `slice_id`
/// 的范围会悄悄变化，UI 同一条进度条就代表另一段文件。
#[derive(Debug, Clone)]
struct Ed2kPlanEntry {
    /// 规划时的原生 part 总数。part 数变化说明文件大小变了，必须重新规划。
    total: usize,
    groups: Vec<std::ops::Range<usize>>,
    /// 方案版本；每次真正重新规划时递增。
    revision: u64,
}

/// 兼容投影的版本记账：指纹检测变化，版本单调递增。
#[derive(Debug, Clone, Copy, Default)]
struct RevisionEntry {
    version: u64,
    fingerprint: u64,
}

/// 单任务实时状态（IPC 查询时与 DB 行合并）。
#[derive(Debug, Default)]
pub struct LiveState {
    pub done_bytes: AtomicU64,
    /// 0 = 未知
    pub total_bytes: AtomicU64,
    pub speed_bps: AtomicU64,
    /// 该任务各连接共享的速率窗口；统计 tick 主动刷新，
    /// 没有新字节时能自然衰减到 0，而不是留下旧速度。
    pub speed_window: Arc<SpeedWindow>,
    pub p2p: Mutex<Option<aidm_ipc::P2pView>>,
    /// 本轮 worker 的启动时刻。净下载耗时 = `downloads.active_ms`（历史轮次之和）
    /// + 本轮已跑时长；暂停后 worker 线程退出，这里也就停了，所以暂停时间不计入。
    pub run_start: Mutex<Option<std::time::Instant>>,
    /// 上一条 `transfer.progress` 事件的时刻（毫秒）。进度是**节流**的：
    /// 正常路径 5 秒一条，绝不逐块记录（规格 §3.4）。
    pub last_progress_log_ms: AtomicU64,
    /// eD2k 原生 part 归属快照（只读观测）。
    ///
    /// 由池的 `on_ownership` 回调写入，供统一视图展示“哪个源负责哪个区间”。
    /// 未接或非 eD2k 任务时为空；空不代表“没有源”，只代表“本次没有归属观测”，
    /// 两者必须区分（文档第 2 节）。
    pub ownership: Mutex<Vec<crate::ed2k::multi_source::PartOwnership>>,
    /// 暂停时静止等待超时、仍可能在写盘的数量。
    ///
    /// 非 0 表示"暂停返回时没停干净"，状态页/诊断必须能看到，不能吞掉。
    pub pause_stragglers: AtomicU64,
    /// 写过多少次「许可失效，拒绝写盘」。
    ///
    /// 为 0 只表示没有发生过拒绝，**不表示**闸门已生效——闸门是否接线要看
    /// 真实下载用例，不能靠这个计数自证。
    pub last_write_denied: AtomicU64,
}

impl LiveState {
    /// 从共享窗口重算并写回任务速度。
    pub fn refresh_speed(&self) -> u64 {
        let speed = self.speed_window.bytes_per_sec();
        self.speed_bps.store(speed, Ordering::Relaxed);
        speed
    }

    /// 本轮已运行毫秒数；worker 未启动（或已退出）为 0。
    pub fn run_elapsed_ms(&self) -> u64 {
        self.run_start
            .lock()
            .unwrap()
            .map(|t| t.elapsed().as_millis() as u64)
            .unwrap_or(0)
    }
}

/// 运行中任务的**热调**指令：不改分段、不重启，直接改内存里的并发/闸门。
///
/// 把新上限推给任务自己的调度器，避免"停住 → 切分段 → 原地续跑"
/// 带来的可见停顿。
#[derive(Debug, Clone, Copy)]
pub enum Retune {
    /// 每任务最大连接数
    MaxConns(i64),
    /// 全局连接上限
    GlobalCap(i64),
}

pub type RetuneFn = Arc<dyn Fn(Retune) + Send + Sync>;

/// 任务启动后由下载内核回填自己的回调；管理器据此热调。
#[derive(Default)]
pub struct RetuneCell(Mutex<Option<RetuneFn>>);

impl RetuneCell {
    pub fn set(&self, f: RetuneFn) {
        *self.0.lock().unwrap() = Some(f);
    }

    pub fn clear(&self) {
        *self.0.lock().unwrap() = None;
    }

    pub fn get(&self) -> Option<RetuneFn> {
        self.0.lock().unwrap().clone()
    }
}

pub(crate) struct TaskHandle {
    pub cancel: Arc<AtomicBool>,
    pub pause: Arc<AtomicBool>,
    /// 配额“停止”：与 pause 一起置位，worker 退出后由 `worker::run` 写成 error/quota。
    pub stop: Arc<AtomicBool>,
    pub live: Arc<LiveState>,
    pub worker: Option<std::thread::JoinHandle<()>>,
    /// 热调回调（下载内核注册）
    pub retune: Arc<RetuneCell>,
    /// BitTorrent 逐文件选择（IPC 写、worker 应用）：句柄存活期间保持同一份。
    pub bt_selection: Arc<Mutex<crate::bt::BtSelection>>,
}

/// 进度回调负载。
#[derive(Debug, Clone, Copy)]
pub struct Progress {
    pub id: i64,
    pub done_bytes: u64,
    pub total: Option<u64>,
    pub speed_bps: u64,
}

pub type ProgressCallback = Arc<dyn Fn(Progress) + Send + Sync>;

/// `aidm_core::capability::ProtocolProfile` → IPC 视图。
///
/// 两边刻意是**两套类型**：契约层（`aidm-ipc`）不依赖实现层（`aidm-core`），
/// 所以这里手工映射而不是直接复用。字段一一对应；漏一个会被编译器当场拦住，
/// 语义漂移由 `capabilities_view_matches_core` 这条集成测试盯着。
fn capability_view(p: &aidm_core::capability::ProtocolProfile) -> aidm_ipc::CapabilityView {
    aidm_ipc::CapabilityView {
        transport: p.transport.as_str().to_string(),
        resource: p.resource.as_str().to_string(),
        manifest: p.manifest.map(|m| m.as_str().to_string()),
        wrapper: p.wrapper.map(|w| w.as_str().to_string()),
        capabilities: aidm_ipc::CapabilityFlags {
            pause: p.capabilities.pause,
            resume: p.capabilities.resume,
            segment: p.capabilities.segment,
            seek: p.capabilities.seek,
            multi_source: p.capabilities.multi_source,
            manifest: p.capabilities.manifest,
            verify: p.capabilities.verify,
            seed: p.capabilities.seed,
        },
        // `note` 必须带上：`fs2you://` 这类封装能识别、能给传输层结论，但服务已停运、
        // 其实下不了。丢掉它等于把不可用谎报成可用。
        //
        // 这条映射由 `capabilities.rs` 的 `note_survives_the_contract_mapping` 专门
        // 盯着 —— 早先的通用比对没覆盖它，因为它的样本里没有 fs2you（`note` 恒为
        // None），把这一行改成 `None` 测试也不会红。变异验证发现的。
        note: p.note.clone(),
    }
}

/// 引擎推送扇出（IPC `subscribe` 与测试钩子共用）。
pub struct EventHub {
    subs: Mutex<Vec<std::sync::mpsc::Sender<EngineEvent>>>,
}

impl EventHub {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            subs: Mutex::new(Vec::new()),
        })
    }

    pub fn subscribe(&self) -> std::sync::mpsc::Receiver<EngineEvent> {
        let (tx, rx) = std::sync::mpsc::channel();
        self.subs.lock().unwrap().push(tx);
        rx
    }

    pub fn emit(&self, ev: EngineEvent) {
        self.subs
            .lock()
            .unwrap()
            .retain(|tx| tx.send(ev.clone()).is_ok());
    }

    pub fn live_subscribers(&self) -> usize {
        self.subs.lock().unwrap().len()
    }
}

pub struct DownloadManager {
    db: Arc<Mutex<Connection>>,
    default_dir: PathBuf,
    tasks: Arc<Mutex<HashMap<i64, TaskHandle>>>,
    on_progress: Mutex<Option<ProgressCallback>>,
    limiter: Arc<TokenBucket>,
    http: Arc<HttpRuntime>,
    events: Arc<EventHub>,
    active_conns: Arc<AtomicU64>,
    offers: Mutex<HashMap<String, StoredOffer>>,
    offer_seq: AtomicU64,
    pending: Mutex<HashMap<i64, PendingStart>>,
    last_sched: Mutex<Option<(Option<i64>, u64, u64)>>,
    io_fault: std::sync::atomic::AtomicU8,
    update: Arc<crate::update::UpdateRuntime>,
    /// 解析好的设置快照。调度每拍、每次起任务都从内存读，
    /// 不再每拍做 4 次 SQL + 解析 cron（这是 UI 卡顿与调度抖动的来源）。
    snap: std::sync::RwLock<Arc<settings::Snapshot>>,
    /// 流量配额记账
    quota: Mutex<QuotaTracker>,
    /// 本周期配额是否已触发过（与 after_done 的边沿分开，否则相互吞掉）
    quota_fired: AtomicBool,
    /// 因配额暂停的任务；进入新周期后只恢复这些，不碰用户手动暂停的任务
    quota_paused: Mutex<HashSet<i64>>,
    /// 「队列跑完了」这个边沿只触发一次 after_done 动作
    after_done_fired: AtomicBool,
    /// 是否"确实干过活"。只有先有任务跑过，队列跑空才谈得上"全部完成"——
    /// 否则一开启 `sched.after_done` 就会因为队列本来就是空的而立刻触发
    /// （对方语义是"队列跑完"，不是"队列为空"）。
    after_done_armed: AtomicBool,
    /// eD2k 入站上传服务（L6）的句柄；未启用/未启动时为 `None`。
    /// 状态由它自己维护，这里只是拿一个可查询的引用。
    ed2k_inbound: std::sync::OnceLock<Arc<crate::ed2k::inbound::Inbound>>,
    /// BitTorrent 续种会话（完成后继续做种，独立于任务线程存活）。
    bt_seeds: Arc<crate::bt::SeedRegistry>,
    /// 本进程的引擎实例标识（统一视图与快照游标用）。每次启动不同。
    engine_instance_id: String,
    /// 对端地址 → 不透明 source_id 的持久映射（eD2k 归属投影用）。
    ///
    /// 必须跨快照持久：否则同一个对端每次刷新都换一个 source_id，
    /// UI 无法连续渲染。
    peer_sources: Mutex<crate::download::observe::PeerSourceMap>,
    /// 影子解释器上次运行时间与任务集合签名（节流 + 状态变化立即触发）。
    ///
    /// 只按时间节流会让“任务刚出现/刚变成终态”被 5 秒窗口吞掉；
    /// 文档 10 节要求主状态、等待、错误和完成变化**及时**推送。
    shadow_last: Mutex<Option<(u64, u64)>>,
    /// 上次记录的影子状态摘要（任务 → 摘要）。
    shadow_state: Mutex<HashMap<i64, String>>,
    /// 上次记录的影子决策摘要（任务 → 摘要）。
    shadow_decisions: Mutex<HashMap<i64, String>>,
    /// 上次记录的源观测摘要（任务 → 摘要）。
    shadow_sources: Mutex<HashMap<i64, String>>,
    /// 每任务的递增状态版本 + 最近一次可见事实指纹（兼容投影用）。
    state_revisions: Mutex<HashMap<i64, RevisionEntry>>,
    /// 每任务的 eD2k 切片方案（首次规划后固定，预算变化不重新分组）。
    ed2k_plans: Mutex<HashMap<i64, Ed2kPlanEntry>>,
    /// 影子事件序号（任务内递增，允许缺口）。
    shadow_seq: AtomicU64,
    /// 上次记录的状态枚举（用于 state_changed 的前后值）。
    shadow_status: Mutex<HashMap<i64, Status>>,
    /// 每任务的写入许可闸门。
    ///
    /// worker 启动时建、退出时移除；暂停/删除/接管时由这里统一撤销并等静止。
    /// 闸门必须**每任务一个**：撤销要能精确到任务，不能一个任务暂停把别的任务也停了。
    write_gates: Arc<Mutex<HashMap<i64, Arc<aidm_core::download::control::WriteGate>>>>,
    /// 每任务的协调器。
    ///
    /// 影子期它只做两件事：按 `policy` 产出决策、把 `PlanSlices` 落表。
    /// **不接管执行权**：其它动作一律 `Deferred`（C3-c 才接），worker 一行未改。
    coordinators: Arc<Mutex<HashMap<i64, Arc<crate::download::coordinator::Coordinator>>>>,
}

/// 测试钩子：模拟各类真实故障（生产保持 [`IoFault::None`]）。
///
/// 规格 §8 的故障注入矩阵：每一种都对应一条必须能定位的失败链路 ——
/// 光有错误码不够，事件序列要能指出「卡在哪个阶段」。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IoFault {
    None = 0,
    /// 写盘失败：磁盘满（`disk_full`）。
    DiskFull = 1,
    /// 写盘失败：无权限（`no_permission`）。
    NoPermission = 2,
    /// 连接已建立但对端不发数据（首字节/读超时 → `network`）。
    Timeout = 3,
    /// 传输中途断开（RST → `network`）。
    Disconnect = 4,
    /// 写完之后、校验之前篡改尾块（真实走一遍校验 → `sha256_mismatch`）。
    Corrupt = 5,
    /// 解析地址失败（本机 hosts/DNS 屏蔽语义 → `blocked_by_hosts`）。
    DnsFail = 6,
    /// 慢速滴灌（1 B/s）：起步极慢但**不失败**，用于验证速度/TTFB 指标。
    SlowDrip = 7,
}

impl IoFault {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => IoFault::DiskFull,
            2 => IoFault::NoPermission,
            3 => IoFault::Timeout,
            4 => IoFault::Disconnect,
            5 => IoFault::Corrupt,
            6 => IoFault::DnsFail,
            7 => IoFault::SlowDrip,
            _ => IoFault::None,
        }
    }

    /// 该注入是否会写真实磁盘（用于测试与文档对齐）。
    pub fn touches_disk(self) -> bool {
        matches!(
            self,
            IoFault::DiskFull | IoFault::NoPermission | IoFault::Corrupt
        )
    }
}

#[derive(Clone)]
struct PendingStart {
    referrer: Option<String>,
    cookies: Option<String>,
    /// 浏览器透传的 UA（可为空）
    user_agent: Option<String>,
    /// 每任务自定义请求头（已校验的原始文本块）
    custom_headers: Option<String>,
    filename: Option<String>,
}

#[derive(Clone)]
struct StoredOffer {
    page_url: String,
    #[allow(dead_code)]
    title: String,
    items: Vec<OfferItem>,
    cookies: Option<String>,
    #[allow(dead_code)]
    truncated: bool,
    expires_at: Instant,
}

/// `add` 全量参数（扩展 / UI / offer 回填共用）。
#[derive(Debug, Clone, Default)]
pub struct AddSpec<'a> {
    pub url: &'a str,
    pub dir: Option<&'a str>,
    pub filename: Option<&'a str>,
    pub referrer: Option<&'a str>,
    pub cookies: Option<&'a str>,
    /// 浏览器发起时透传的 UA；手工新建留 None
    pub user_agent: Option<&'a str>,
    /// 每任务自定义请求头（`Name: value` 逐行）；手工新建可为 None
    pub custom_headers: Option<&'a str>,
    /// 备用地址（镜像），每行一个 HTTP(S) 地址；无则 None
    pub alt_urls: Option<&'a str>,
    pub offer_id: Option<&'a str>,
    pub speed_limit_kbps: u64,
    pub source: Option<&'a str>,
    pub start: Option<&'a str>,
}

/// 新任务文件名在同目录内不能与已有任务或磁盘文件冲突：
/// `name.ext` -> `name (1).ext` -> `name (2).ext` …
/// 这样重复下载会创建新名字的新任务，而不是复用/覆盖旧文件。
fn unique_task_file_name(conn: &Connection, dir: &Path, name: &str) -> String {
    let used: HashSet<String> = model::list_downloads(conn)
        .unwrap_or_default()
        .into_iter()
        .filter(|r| Path::new(&r.dir) == dir)
        .map(|r| r.file_name.to_ascii_lowercase())
        .collect();
    let first = aidm_core::filename::unique_file_name(dir, name);
    if !used.contains(&first.to_ascii_lowercase()) {
        return first;
    }
    let path = Path::new(name);
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(name);
    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
    for n in 1..=9999u32 {
        let candidate = if ext.is_empty() {
            format!("{stem} ({n})")
        } else {
            format!("{stem} ({n}).{ext}")
        };
        if !used.contains(&candidate.to_ascii_lowercase()) && !dir.join(&candidate).exists() {
            return candidate;
        }
    }
    first
}

/// 流量配额记账。
///
/// 口径：按周期桶统计**所有任务已下载字节的增量**。增量来自 `segments.done_bytes`
/// 的合计——它是"已落盘字节"的唯一权威来源，暂停/续传都不会重复计数。
///
/// 已知限制：进程重启会丢失"本周期已用"（基线归零）。配额是软约束，
/// 且引擎是常驻进程——重启即视为人工干预。
#[derive(Debug, Default)]
struct QuotaTracker {
    bucket_start: i64,
    used: u64,
    last_total: u64,
    seeded: bool,
}

impl QuotaTracker {
    /// 返回"本周期已用字节"。
    fn observe(&mut self, quota: &aidm_core::sched::Quota, now_secs: i64, total_done: u64) -> u64 {
        let bucket = quota.bucket_start_secs(now_secs);
        if !self.seeded || self.bucket_start != bucket {
            self.bucket_start = bucket;
            self.used = 0;
            self.last_total = total_done;
            self.seeded = true;
            return 0;
        }
        self.used = self
            .used
            .saturating_add(total_done.saturating_sub(self.last_total));
        self.last_total = total_done;
        self.used
    }

    fn reset(&mut self) {
        self.seeded = false;
    }
}

impl DownloadManager {
    pub fn new(db: Arc<Mutex<Connection>>, default_dir: PathBuf) -> Self {
        let kbps = {
            let conn = db.lock().unwrap();
            settings::speed_limit_kbps(&conn)
        };
        Self {
            db: db.clone(),
            default_dir,
            tasks: Arc::new(Mutex::new(HashMap::new())),
            on_progress: Mutex::new(None),
            limiter: TokenBucket::new(kbps),
            http: HttpRuntime::from_db(&db),
            events: EventHub::new(),
            active_conns: Arc::new(AtomicU64::new(0)),
            offers: Mutex::new(HashMap::new()),
            offer_seq: AtomicU64::new(1),
            pending: Mutex::new(HashMap::new()),
            last_sched: Mutex::new(None),
            io_fault: std::sync::atomic::AtomicU8::new(IoFault::None as u8),
            update: crate::update::UpdateRuntime::new(),
            snap: std::sync::RwLock::new(Arc::new(settings::Snapshot::unloaded())),
            quota: Mutex::new(QuotaTracker::default()),
            quota_fired: AtomicBool::new(false),
            quota_paused: Mutex::new(HashSet::new()),
            after_done_fired: AtomicBool::new(false),
            after_done_armed: AtomicBool::new(false),
            ed2k_inbound: std::sync::OnceLock::new(),
            bt_seeds: crate::bt::SeedRegistry::new(db.clone()),
            engine_instance_id: aidm_core::download::model::gen_uuid_v4(),
            peer_sources: Mutex::new(crate::download::observe::PeerSourceMap::new()),
            shadow_last: Mutex::new(None),
            shadow_state: Mutex::new(HashMap::new()),
            shadow_decisions: Mutex::new(HashMap::new()),
            shadow_sources: Mutex::new(HashMap::new()),
            state_revisions: Mutex::new(HashMap::new()),
            ed2k_plans: Mutex::new(HashMap::new()),
            shadow_seq: AtomicU64::new(1),
            shadow_status: Mutex::new(HashMap::new()),
            write_gates: Arc::new(Mutex::new(HashMap::new())),
            coordinators: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// 队列名（用于 `TaskView.queue`）；查不到时回 `default`。
    fn queue_name(&self, queue_id: i64) -> String {
        let conn = self.db.lock().unwrap();
        aidm_core::queues::get(&conn, queue_id)
            .ok()
            .flatten()
            .map(|q| q.name)
            .unwrap_or_else(|| aidm_core::queues::DEFAULT_QUEUE_NAME.to_string())
    }

    /// 全部命名队列 + 计数（多队列列表）。
    pub fn queues_list(&self) -> Result<Vec<aidm_ipc::QueueView>, String> {
        let conn = self.db.lock().unwrap();
        let rows = aidm_core::queues::list(&conn).map_err(|e| e.to_string())?;
        Ok(rows
            .iter()
            .map(|row| {
                let counts = aidm_core::queues::counts(&conn, row.id).unwrap_or_default();
                aidm_ipc::QueueView {
                    id: row.id,
                    name: row.name.clone(),
                    enabled: row.enabled,
                    default_dir: row.default_dir.clone(),
                    schedule_cron: row.schedule_cron.clone(),
                    is_default: row.is_default(),
                    queued: counts.queued,
                    running: counts.running,
                    done: counts.done,
                    failed: counts.failed,
                    paused: counts.paused,
                }
            })
            .collect())
    }

    /// 新建队列。
    pub fn queue_create(
        &self,
        name: &str,
        default_dir: Option<&str>,
        schedule_cron: Option<&str>,
    ) -> Result<Vec<aidm_ipc::QueueView>, String> {
        {
            let conn = self.db.lock().unwrap();
            aidm_core::queues::create(&conn, name, default_dir, schedule_cron)?;
        }
        self.queues_list()
    }

    /// 改队列（只写给出的字段）。
    pub fn queue_update(
        &self,
        id: i64,
        name: Option<&str>,
        enabled: Option<bool>,
        default_dir: Option<Option<&str>>,
        schedule_cron: Option<Option<&str>>,
    ) -> Result<Vec<aidm_ipc::QueueView>, String> {
        {
            let conn = self.db.lock().unwrap();
            aidm_core::queues::update(
                &conn,
                id,
                name,
                enabled,
                default_dir,
                schedule_cron,
            )?;
        }
        // 队列刚被启用/放开并发时立刻给一次派发机会，不用等下一拍。
        self.tick();
        self.queues_list()
    }

    /// 删队列：其任务迁入默认队列（不删任务）。
    pub fn queue_delete(&self, id: i64) -> Result<Vec<aidm_ipc::QueueView>, String> {
        {
            let mut conn = self.db.lock().unwrap();
            aidm_core::queues::delete(&mut conn, id)?;
        }
        self.tick();
        self.queues_list()
    }

    /// 把任务移到某队列（追加到队尾）。
    pub fn task_set_queue(&self, ids: &[u64], queue: i64) -> Result<usize, String> {
        if ids.is_empty() {
            return Err("empty_ids".into());
        }
        let mut moved = 0usize;
        {
            let conn = self.db.lock().unwrap();
            if aidm_core::queues::get(&conn, queue)
                .map_err(|e| e.to_string())?
                .is_none()
            {
                return Err("queue_not_found".into());
            }
            for id in ids {
                if aidm_core::model::get_download(&conn, *id as i64)
                    .map_err(|e| e.to_string())?
                    .is_none()
                {
                    continue; // 未知 id 跳过，不整体失败（批量操作常见竞态）
                }
                aidm_core::queues::set_download_queue(&conn, *id as i64, queue)?;
                aidm_core::model::log_event(
                    &conn,
                    *id as i64,
                    "queue_moved",
                    Some(&format!("queue={queue}")),
                );
                moved += 1;
            }
        }
        // 换队列后顺序变了，立刻给一次派发机会
        self.tick();
        Ok(moved)
    }

    /// BitTorrent 逐文件选择：读当前文件表与已选索引。
    ///
    /// 元数据还没到手（磁力刚入队）时返回空表 + 数据库里已保存的选择，
    /// 界面据此显示"等待元数据"。
    pub fn bt_files(&self, id: i64) -> Result<(Vec<aidm_ipc::BtFileView>, Vec<usize>), String> {
        let (saved, has_task) = {
            let conn = self.db.lock().unwrap();
            let row = model::get_download(&conn, id).map_err(|e| e.to_string())?;
            let Some(row) = row else {
                return Err("task_not_found".into());
            };
            (
                aidm_core::bt_files::parse(row.bt_files.as_deref().unwrap_or("")),
                true,
            )
        };
        if !has_task {
            return Err("task_not_found".into());
        }
        let live = self
            .tasks
            .lock()
            .unwrap()
            .get(&id)
            .map(|h| h.bt_selection.clone());
        let Some(state) = live else {
            // 任务没在跑：只能给出已保存的选择，文件表要等下次运行才有。
            return Ok((Vec::new(), saved));
        };
        let state = state.lock().unwrap().clone();
        let selected = if state.selected.is_empty() {
            saved
        } else {
            state.selected.clone()
        };
        let effective = aidm_core::bt_files::resolve(&selected, state.files.len());
        let files = state
            .files
            .iter()
            .map(|f| aidm_ipc::BtFileView {
                index: f.index as i64,
                name: f.name.clone(),
                len: f.len,
                selected: effective.contains(&f.index),
            })
            .collect();
        Ok((files, selected))
    }

    /// 设置逐文件选择：落库 + 写入共享状态（运行中的 worker 下一拍用
    /// `update_only_files` 应用，不必重启任务）。
    pub fn bt_set_files(
        &self,
        id: i64,
        indices: &[usize],
    ) -> Result<Vec<aidm_ipc::BtFileView>, String> {
        let effective = {
            let conn = self.db.lock().unwrap();
            let row = model::get_download(&conn, id)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| "task_not_found".to_string())?;
            // 没有在线文件表时用调用方给的索引（落库即可，下次运行生效）。
            let known = self
                .tasks
                .lock()
                .unwrap()
                .get(&id)
                .map(|h| h.bt_selection.lock().unwrap().files.len())
                .unwrap_or(0);
            let resolved = if known > 0 {
                aidm_core::bt_files::resolve(indices, known)
            } else {
                aidm_core::bt_files::encode(indices)
                    .split(',')
                    .filter_map(|s| s.parse::<usize>().ok())
                    .collect()
            };
            let text = aidm_core::bt_files::encode(&resolved);
            model::set_bt_files(&conn, id, Some(&text)).map_err(|e| e.to_string())?;
            model::log_event(
                &conn,
                id,
                "bt_files_set",
                Some(&format!("selected={} text={text:?}", resolved.len())),
            );
            let _ = row;
            resolved
        };
        if let Some(handle) = self.tasks.lock().unwrap().get(&id) {
            handle.bt_selection.lock().unwrap().selected = effective.clone();
        }
        let (files, selected) = self.bt_files(id)?;
        let _ = selected;
        Ok(files)
    }

    /// 挂上 eD2k 入站上传服务（主进程启动时调用一次）。
    pub fn attach_ed2k_inbound(&self, inbound: Arc<crate::ed2k::inbound::Inbound>) {
        let _ = self.ed2k_inbound.set(inbound);
    }

    /// eD2k 入站上传状态（L6）。服务未启动时返回 `None`，由调用方决定怎么呈现。
    pub fn ed2k_upload_status(&self) -> Option<aidm_ipc::Ed2kUploadStatus> {
        let inbound = self.ed2k_inbound.get()?;
        let stats = inbound.stats();
        Some(aidm_ipc::Ed2kUploadStatus {
            enabled: stats.enabled,
            listening_port: stats.listening_port,
            active_sessions: stats.active_sessions,
            queued_sessions: stats.queued_sessions,
            connections: stats.connections,
            uploaded_bytes: stats.uploaded_bytes,
            served_blocks: stats.served_blocks,
            rejected_blocks: stats.rejected_blocks,
            shared_files: stats.shared_files,
            last_error: stats.last_error,
        })
    }

    /// 当前设置快照；`settings.revision` 变了才回库重读。
    ///
    /// 热路径（调度每拍、每次起任务、限速、超时、UA…）都走这里。
    /// 只剩一条主键查询（`settings.revision`），派生量早已解析成有类型的字段。
    pub fn settings_snapshot(&self) -> Arc<settings::Snapshot> {
        let (cached, stale) = {
            let g = self.snap.read().unwrap();
            (g.clone(), g.is_empty())
        };
        if cached.is_empty() {
            return self.reload_settings();
        }
        if stale {
            return self.reload_settings();
        }
        // 版本戳一致就完全不用碰库
        let db_rev = {
            let conn = self.db.lock().unwrap();
            settings::revision(&conn)
        };
        if cached.revision == db_rev {
            return cached;
        }
        self.reload_settings()
    }

    /// 无条件重读设置快照（`settings_set` 之后调用）。
    pub fn reload_settings(&self) -> Arc<settings::Snapshot> {
        let fresh = {
            let conn = self.db.lock().unwrap();
            settings::Snapshot::load(&conn)
        };
        // 装载失败时退化成"默认值但非空"，避免每个 tick 都反复失败重试
        let fresh = Arc::new(match fresh {
            Ok(s) if !s.is_empty() => s,
            _ => settings::Snapshot::defaults(),
        });
        {
            let mut w = self.snap.write().unwrap();
            *w = fresh.clone();
        }
        fresh
    }

    /// 快照版本与库里不一致时重读（返回值表示是否发生了重载）。
    pub fn sync_settings_snapshot(&self) -> bool {
        let db_rev = {
            let conn = self.db.lock().unwrap();
            settings::revision(&conn)
        };
        let cur = self.snap.read().unwrap().revision;
        if cur == db_rev {
            return false;
        }
        self.reload_settings();
        true
    }

    /// 测试：替换 MSI 应用实现（不跑真实 msiexec）。
    pub fn set_update_apply_hook(&self, hook: Option<crate::update::ApplyHook>) {
        self.update.set_apply_hook(hook);
    }

    /// 测试：隔离更新包暂存目录，避免并行测试抢同一路径。
    pub fn set_update_staging_dir(&self, path: PathBuf) {
        self.update.set_staging_dir(path);
    }

    pub fn update_auto_check_enabled(&self) -> bool {
        let conn = self.db.lock().unwrap();
        settings::update_auto_check(&conn)
    }

    /// 立即返回；进度走 `event:"update"`。
    pub fn update_check(&self) {
        if !self.update.try_begin() {
            return;
        }
        let http = self.http.clone();
        let db = self.db.clone();
        let events = self.events.clone();
        let update = self.update.clone();
        let _ = std::thread::Builder::new()
            .name("aidm-update-check".into())
            .spawn(move || {
                crate::update::run_check(&http, &db, &events, &update);
                update.end();
            });
    }

    /// 下载 + 校验 + 应用已缓存的可用更新。无可用更新则立刻失败。
    pub fn update_download_apply(&self) -> Result<(), String> {
        if self.update.available().is_none() {
            self.events.emit(aidm_ipc::EngineEvent::Update {
                phase: aidm_ipc::UPDATE_PHASE_ERROR.into(),
                current_version: Some(crate::update::current_app_version().into()),
                version: None,
                notes: None,
                url: None,
                bytes_done: None,
                bytes_total: None,
                error: Some(
                    crate::update::update_error_message(aidm_ipc::ERR_UPDATE_FAILED).into(),
                ),
                code: Some(aidm_ipc::ERR_UPDATE_FAILED.into()),
            });
            return Err("no_update_available".into());
        }
        if !self.update.try_begin() {
            return Ok(());
        }
        let http = self.http.clone();
        let events = self.events.clone();
        let update = self.update.clone();
        let dest = self.update.staging();
        let _ = std::thread::Builder::new()
            .name("aidm-update-apply".into())
            .spawn(move || {
                crate::update::run_apply(&http, &events, &update, &dest);
                update.end();
            });
        Ok(())
    }

    /// 仅集成测试：注入写盘失败。
    pub fn set_io_fault(&self, fault: IoFault) {
        self.io_fault.store(fault as u8, Ordering::SeqCst);
    }

    pub fn io_fault(&self) -> IoFault {
        IoFault::from_u8(self.io_fault.load(Ordering::SeqCst))
    }

    /// 500ms 调度 tick（`serve` 启动）。测试可直接 [`Self::tick`]。
    pub fn spawn_scheduler(this: Arc<Self>) {
        let _ = std::thread::Builder::new()
            .name("aidm-sched".into())
            .spawn(move || loop {
                std::thread::sleep(Duration::from_millis(500));
                this.tick();
            });
    }

    /// 一拍调度：同步设置快照 → 时段门 → 配额门 → 派发 → 完成后动作。
    ///
    /// 闸门、cron、时段、配额全部来自内存快照，避免每拍多次 SQL 与 cron 解析。
    pub fn tick(&self) {
        self.sync_settings_snapshot();
        // 影子：切片方案的决策权先在这里跑一遍。
        // 放在最前面是因为它不依赖调度状态（窗口/配额），而且只对空闲任务生效。
        self.coordinator_tick();
        let snap = self.settings_snapshot();
        // 运行时段：窗口外不派发新任务，也不触发完成后动作
        if !self.window_open(&snap) {
            self.emit_sched_if_changed();
            self.shadow_tick();
            return;
        }
        if self.quota_blocked(&snap) {
            self.emit_sched_if_changed();
            self.shadow_tick();
            return;
        }
        self.dispatch_ready();
        self.emit_sched_if_changed();
        self.check_after_done(&snap);
        // 影子解释器：只记录建议，不影响上面的调度任何一步。
        self.shadow_tick();
    }

    /// 影子解释器节拍。
    ///
    /// 文档 12.2：影子路径不能占连接、改状态或写下载文件。这里只做：
    /// 1. 从统一投影构造输入（与快照同源，不另立一份事实）；
    /// 2. 跑硬规则 + 证据层，把会改变执行的动作降级为 `ObserveOnly`；
    /// 3. 用 `EventEnvelope` 把状态、源观测与决策**关联**起来，仅在变化时落一条。
    ///
    /// 节流 5 秒 + 内容去重，避开 R-OBS-14 的日志预算。
    /// **终态任务也记录一次**：完成/失败本身是必须能追溯的事实，不能被
    /// "只评估活跃任务"的过滤吞掉。
    fn shadow_tick(&self) {
        use aidm_core::download::model::{event_name, Availability, EventPayload, SourceId};
        use aidm_core::download::policy::{evaluate, shadow_only, PolicyConfig, PolicyInput};

        let now = model::now_ms().max(0) as u64;

        let rows = {
            let conn = self.db.lock().unwrap();
            model::list_downloads(&conn).unwrap_or_default()
        };

        // 节流：任务集合与主状态未变时每 5 秒才跑一次；
        // 一旦出现新任务或状态变化（含变成终态），立即跑——否则完成/失败
        // 会被 5 秒窗口吞掉，无法追溯。
        let signature = {
            use std::hash::{Hash, Hasher};
            let mut h = std::collections::hash_map::DefaultHasher::new();
            rows.len().hash(&mut h);
            for row in &rows {
                row.id.hash(&mut h);
                row.status.as_str().hash(&mut h);
            }
            h.finish()
        };
        {
            let mut last = self.shadow_last.lock().unwrap();
            if let Some((prev_at, prev_sig)) = *last {
                if prev_sig == signature && now.saturating_sub(prev_at) < 5_000 {
                    return;
                }
            }
            *last = Some((now, signature));
        }

        for row in rows {
            let terminal =
                matches!(row.status, Status::Done | Status::Error | Status::Paused);

            // 终态：只记录一次状态变化，之后不再为它反复构造投影。
            if terminal {
                let key = format!("terminal:{}", row.status.as_str());
                if !remember(&self.shadow_state, row.id, key) {
                    continue;
                }
                let mut reducer = self.build_unified_reducer(&row);
                reducer.set_now_ms(now);
                let from = self.previous_status(row.id).unwrap_or(row.status);
                self.remember_status(row.id, row.status);
                let env = build_envelope(
                    self.next_shadow_seq(),
                    &reducer,
                    event_name::STATE_CHANGED,
                    EventPayload::StateChanged {
                        from,
                        to: row.status,
                        activity: reducer.task().activity,
                        wait: reducer.task().wait.clone(),
                    },
                    Some("terminal_state"),
                );
                let conn = self.db.lock().unwrap();
                log_envelope(&conn, &env);
                continue;
            }

            let mut reducer = self.build_unified_reducer(&row);
            reducer.set_now_ms(now);
            let budget = reducer.task().budget.connection_budget;
            let input = PolicyInput::from_reducer(
                &reducer,
                PolicyConfig {
                    connection_budget: budget,
                    ..PolicyConfig::default()
                },
            );

            // 状态摘要：只用于去重；前后值进 payload。
            let state_summary = format!(
                "status={} activity={} slices={} stored={} verified={}",
                reducer.task().status.as_str(),
                reducer.task().activity.as_str(),
                reducer.task().slice_ids.len(),
                reducer.task().progress.stored_unique_bytes,
                reducer.task().progress.verified_unique_bytes,
            );
            let state_changed = remember(&self.shadow_state, row.id, state_summary);

            // 源观测：比较**完整 source_id 集合**，不是只比数量。
            // 同数量换源（A 下线、B 接上）在只比数量时会漏报。
            let mut ids: Vec<&str> = reducer.sources().map(|s| s.source_id.as_str()).collect();
            ids.sort_unstable();
            let source_summary = format!(
                "sources={} ids={} eligible={} connections={} active={} queued={}",
                ids.len(),
                ids.join(","),
                reducer.task().counts.eligible_sources,
                reducer.task().counts.connections,
                reducer.task().counts.active_transfers,
                reducer.task().counts.queued_peers,
            );
            let sources_changed = remember(&self.shadow_sources, row.id, source_summary);

            let mut decisions = evaluate(&input);
            for d in decisions.iter_mut() {
                // 硬约束：影子路径绝不执行。
                shadow_only(d);
            }
            let decision_summary = summarize_decisions(&decisions);
            let decisions_changed =
                remember(&self.shadow_decisions, row.id, decision_summary);

            if !state_changed && !sources_changed && !decisions_changed {
                continue;
            }

            // 首拍（还没有历史状态）必须记一条，否则新任务出现时没有 state_changed。
            let previous = self.previous_status(row.id);
            let first_tick = previous.is_none();
            let from = previous.unwrap_or(row.status);
            self.remember_status(row.id, row.status);

            let conn = self.db.lock().unwrap();
            // 只在**状态真的变了**时记 `state_changed`。
            //
            // `state_changed` 的判定用的是摘要（含 stored/verified 字节），所以
            // 下载进度每涨一点都会让它为真；但事件载荷只有 `from`/`to`，
            // 于是会刷出大量 `downloading → downloading` 的空转事件
            // （实测 4 条里 2 条）。进度本身有独立的 `transfer.progress`。
            if state_changed && (first_tick || from != row.status) {
                let env = build_envelope(
                    self.next_shadow_seq(),
                    &reducer,
                    event_name::STATE_CHANGED,
                    EventPayload::StateChanged {
                        from,
                        to: row.status,
                        activity: reducer.task().activity,
                        wait: reducer.task().wait.clone(),
                    },
                    Some("shadow_observe"),
                );
                log_envelope(&conn, &env);
            }
            if sources_changed {
                let env = build_envelope(
                    self.next_shadow_seq(),
                    &reducer,
                    event_name::SOURCE_CHANGED,
                    EventPayload::SourceChanged {
                        source_id: reducer
                            .sources()
                            .next()
                            .map(|s| s.source_id.clone())
                            .unwrap_or_else(|| SourceId::new("unknown")),
                        availability: Availability::Unknown,
                        merged_count: ids.len() as u32,
                    },
                    Some("shadow_observe"),
                );
                log_envelope(&conn, &env);
            }
            if decisions_changed {
                let payload = match decisions.first() {
                    Some(d) => EventPayload::Decision {
                        decision_id: d.decision_id.clone(),
                        rule_id: d.rule_id.clone(),
                        policy_revision: d.policy_revision,
                        action: d.action,
                        scope: d.scope,
                        evidence_refs: d.evidence_refs.clone(),
                        confidence: d.confidence,
                    },
                    None => EventPayload::None,
                };
                let env = build_envelope(
                    self.next_shadow_seq(),
                    &reducer,
                    event_name::DECISION,
                    payload,
                    Some("shadow_observe"),
                );
                log_envelope(&conn, &env);
            }
        }
    }

    fn next_shadow_seq(&self) -> u64 {
        self.shadow_seq.fetch_add(1, Ordering::Relaxed)
    }

    fn previous_status(&self, id: i64) -> Option<Status> {
        self.shadow_status.lock().unwrap().get(&id).copied()
    }

    fn remember_status(&self, id: i64, status: Status) {
        self.shadow_status.lock().unwrap().insert(id, status);
    }

    /// 派发闸门：时段开着 **且** 配额没用尽。
    ///
    /// `add` 的"立即开始"和调度器的批量派发都要过这一关——否则手动添加会绕过配额。
    fn dispatch_allowed(&self, snap: &settings::Snapshot) -> bool {
        self.window_open(snap) && !self.quota_blocked(snap)
    }

    /// 当前是否落在允许下载的时段内（本地时间）。
    pub fn window_open(&self, snap: &settings::Snapshot) -> bool {
        if !snap.window.enabled {
            return true;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let (iso, minute) = aidm_core::cron::local_weekday_minute(now);
        snap.window.is_open(iso, minute)
    }

    /// 配额是否已用尽；用尽时按 `sched.quota_action` 处理正在跑的任务。
    fn quota_blocked(&self, snap: &settings::Snapshot) -> bool {
        if !snap.quota.enabled {
            return false;
        }
        let total_done = {
            let conn = self.db.lock().unwrap();
            model::sum_all_done_bytes(&conn).unwrap_or(0)
        };
        let used = self
            .quota
            .lock()
            .unwrap()
            .observe(&snap.quota, model::now_secs(), total_done);
        if !snap.quota.exceeded(used, 0) {
            // 进入新周期或配额被调大：允许下一次到限重新触发，
            // 并恢复本周期因配额暂停的任务（用户手动暂停的不在集合里）。
            self.quota_fired.store(false, Ordering::SeqCst);
            let ids: Vec<i64> = self.quota_paused.lock().unwrap().drain().collect();
            for id in ids {
                let _ = self.resume(id);
            }
            return false;
        }
        // 到限：每个周期只处理一次（避免每拍重复广播/暂停）。
        if self.quota_fired.swap(true, Ordering::SeqCst) {
            return true;
        }
        self.events.emit(EngineEvent::Quota {
            used_bytes: used,
            limit_bytes: snap.quota.limit_bytes(),
            period: snap.quota.period.as_str().to_string(),
            action: match snap.quota.action {
                aidm_core::sched::QuotaAction::Pause => "pause".into(),
                aidm_core::sched::QuotaAction::Stop => "stop".into(),
            },
        });
        let stop = snap.quota.action == aidm_core::sched::QuotaAction::Stop;
        let ids: Vec<i64> = self.tasks.lock().unwrap().keys().copied().collect();
        for id in ids {
            if stop {
                // 先标记“停止”，再复用协作式 pause 让 worker 走到检查点；
                // worker 退出时按 stop 标志写 error/quota，而不是 paused。
                if let Some(handle) = self.tasks.lock().unwrap().get(&id) {
                    handle.stop.store(true, Ordering::SeqCst);
                }
            }
            if self.pause(id).is_ok() && !stop {
                self.quota_paused.lock().unwrap().insert(id);
            }
            let conn = self.db.lock().unwrap();
            model::log_event(
                &conn,
                id,
                "quota",
                Some(&format!(
                    "used={used} action={}",
                    if stop { "stop" } else { "pause" }
                )),
            );
        }
        if stop {
            // 还没启动的排队任务也要停：否则下个周期一到就会自己开始。
            let conn = self.db.lock().unwrap();
            if let Ok(rows) = model::list_downloads(&conn) {
                for row in rows.iter().filter(|r| r.status == Status::Queued) {
                    let _ = model::set_error_fields(
                        &conn,
                        row.id,
                        Status::Error,
                        Some(aidm_core::error::CODE_QUOTA_EXCEEDED),
                        Some("已达到本周期流量配额"),
                        None,
                    );
                    model::log_event(&conn, row.id, "quota", Some("action=stop state=queued"));
                }
            }
        }
        true
    }

    /// 队列跑完了 → 触发一次 after_done（退出/关机/休眠/待机/断开）。
    ///
    /// **引擎只广播，不动电源**：后台下载器持有 `SeShutdownPrivilege` 容易
    /// 招致安全软件关注。真正执行交给 UI 层，且默认要求用户显式打开。
    fn check_after_done(&self, snap: &settings::Snapshot) {
        if !snap.after_done.is_action() {
            return;
        }
        // 没跑过任何任务 → 不叫"全部完成"
        if !self.after_done_armed.load(Ordering::SeqCst) {
            return;
        }
        let (queued, active) = {
            let conn = self.db.lock().unwrap();
            let rows = model::list_downloads(&conn).unwrap_or_default();
            let queued = rows.iter().filter(|r| r.status == Status::Queued).count();
            let active = rows
                .iter()
                .filter(|r| {
                    matches!(
                        r.status,
                        Status::Connecting | Status::Downloading | Status::Verifying
                    )
                })
                .count();
            (queued, active)
        };
        if queued > 0 || active > 0 {
            return;
        }
        if self.after_done_fired.swap(true, Ordering::SeqCst) {
            return;
        }
        // 触发一次就卸闩：等下次真有任务跑完再谈"全部完成"
        self.after_done_armed.store(false, Ordering::SeqCst);
        self.events.emit(EngineEvent::AfterDone {
            action: snap.after_done.as_str().to_string(),
            force: snap.after_done_force,
        });
    }

    /// 站点凭据列表（**不回传密码**，只回是否已设置）。
    pub fn site_logins_list(&self) -> Result<serde_json::Value, String> {
        let conn = self.db.lock().unwrap();
        let rows = aidm_core::logins::list(&conn).map_err(|e| e.to_string())?;
        let items: Vec<serde_json::Value> = rows
            .iter()
            .map(|l| {
                serde_json::json!({
                    "host": l.host,
                    "username": l.username,
                    "has_password": !l.password.is_empty(),
                })
            })
            .collect();
        Ok(serde_json::Value::Array(items))
    }

    /// 写入/覆盖一条站点凭据。
    /// `capabilities`：查询一个地址（或一个已有任务**生效的**地址）的四层协议结论
    /// 与协议允许的能力上限。
    ///
    /// 给 `id` 时用该任务**已经在用的**地址（`url_final` 优先于 `url_orig`）——
    /// 这样界面看到的能力与任务实际走的那条路径一致，不会出现"预检说能分片的地址、
    /// 实际跑的是另一条单线程路径"。只给 `url` 时直接解析，用于新建前预检：
    /// **不落库、不发任何网络请求**，纯字符串判定。
    ///
    /// 无法识别时回 `unsupported_scheme`，**不做兜底猜测** —— 猜一个协议出来只会
    /// 把失败推后到下载时，而且会让界面显示一个并不存在的"支持"。
    pub fn capabilities(
        &self,
        id: Option<u64>,
        url: Option<&str>,
    ) -> Result<aidm_ipc::CapabilityView, String> {
        let (target, observed) = match (id, url) {
            (Some(id), _) => {
                let conn = self.db.lock().unwrap();
                let row = model::get_download(&conn, id as i64)
                    .map_err(|e| format!("db: {e}"))?
                    .ok_or_else(|| "not_found".to_string())?;
                // 这个任务**实测**到的降级事实（最近一条 `degrade_single`）。
                // 按任务查才收窄：只给 URL 的预检没有观测可用，只能是协议上界。
                let degrade = model::list_events(&conn, id as i64)
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|(k, _)| k == "degrade_single")
                    .filter_map(|(_, d)| {
                        d.and_then(|d| aidm_core::capability::Degrade::from_reason(&d))
                    })
                    .next_back();
                (row.url_final.unwrap_or(row.url_orig), degrade)
            }
            (None, Some(u)) => (u.to_string(), None),
            (None, None) => return Err("missing_target".into()),
        };
        let mut profile = aidm_core::capability::detect(&target)
            .ok_or_else(|| "unsupported_scheme".to_string())?;
        if let Some(d) = observed {
            // 收窄是**只减不增**的：上界说"协议上可能"，这里说"这一次实测如何"。
            profile.capabilities = aidm_core::capability::narrow(profile.capabilities, Some(d));
            // 比上界弱就必须说得清为什么，否则界面只有一个更弱的能力值而说不出原因。
            // 已有的 `note`（如 `fs2you://` 服务停运）不被覆盖。
            if profile.note.is_none() {
                profile.note = Some(d.note().to_string());
            }
        }
        Ok(capability_view(&profile))
    }

    /// `add_batch`：逐条创建，返回**与输入等长**的结果表（顺序严格一致）。
    ///
    /// **刻意不做整批回滚**：批量导入的实际来源是剪贴板或清单文件，里面混着
    /// 重复链接、不支持的 scheme 是常态。整批失败会让用户一条都建不上，而逐条
    /// 结果能告诉他"哪几条没进去、为什么"。顺序保持与输入一致（含失败项），
    /// 调用方才能按序对账。
    ///
    /// 目录与来源按**批**共用；其余字段（referrer/cookies/自定义头）批量场景
    /// 下没有合理默认，留空。
    pub fn add_batch(
        &self,
        urls: &[String],
        dir: Option<&str>,
        source: Option<&str>,
    ) -> Vec<aidm_ipc::BatchAddResult> {
        urls.iter()
            .map(|u| {
                match self.add_spec(AddSpec {
                    user_agent: None,
                    custom_headers: None,
                    alt_urls: None,
                    url: u,
                    dir,
                    filename: None,
                    referrer: None,
                    cookies: None,
                    offer_id: None,
                    speed_limit_kbps: 0,
                    source,
                    start: None,
                }) {
                    Ok(id) => aidm_ipc::BatchAddResult {
                        url: u.clone(),
                        id: Some(id as u64),
                        code: None,
                    },
                    Err(code) => aidm_ipc::BatchAddResult {
                        url: u.clone(),
                        id: None,
                        code: Some(code),
                    },
                }
            })
            .collect()
    }

    /// `task_events`：最近事件（按时间正序），供 UI 事件视图与排障。
    ///
    /// 只读；`detail` 在写入口已脱敏，这里再走一次 `redact_text` 兜底。
    /// 删除某任务的全部下载日志。返回删除条数。
    pub fn clear_task_events(&self, id: i64) -> Result<u64, String> {
        let conn = self.db.lock().unwrap();
        let n = model::clear_task_events(&conn, id).map_err(|e| e.to_string())?;
        Ok(n as u64)
    }

    /// 下载日志分页。`filter` = `error` 时只返回异常事件。
    /// 返回 `(当前页（新→旧）, 同条件总数)`。
    pub fn task_events(
        &self,
        id: i64,
        limit: Option<u32>,
        offset: Option<u32>,
        filter: Option<&str>,
    ) -> Result<(Vec<aidm_ipc::TaskEventView>, u64), String> {
        let conn = self.db.lock().unwrap();
        let exists = model::get_download(&conn, id)
            .map_err(|e| e.to_string())?
            .is_some();
        if !exists {
            return Err("not_found".into());
        }
        let errors_only = matches!(filter, Some("error"));
        let rows = model::list_events_page(
            &conn,
            id,
            limit.unwrap_or(50),
            offset.unwrap_or(0),
            errors_only,
        )
        .map_err(|e| e.to_string())?;
        let total = model::count_events(&conn, id, errors_only).map_err(|e| e.to_string())?;
        let views = rows
            .into_iter()
            .map(|row| aidm_ipc::TaskEventView {
                seq: row.seq,
                ts: row.ts,
                kind: row.kind,
                phase: row.phase,
                outcome: row.outcome,
                err_code: row.err_code,
                dur_ms: row.dur_ms,
                attempt: row.attempt,
                seg: row.seg,
                conn: row.conn,
                proto: row.proto,
                detail: row
                    .detail
                    .map(|text| aidm_core::redact::redact_text(&text).into_owned()),
            })
            .collect();
        Ok((views, total))
    }

    /// `diag_export`：导出脱敏诊断包，返回落在磁盘上的路径。
    ///
    /// **复用** `aidm_core::diag::export_task_bundle` —— 与 `aidm-engine diag export`
    /// 是同一条实现。脱敏规则只能有一处：两份实现必然漂移，而漂移的诊断包会把
    /// 本该脱敏的东西发出去。
    pub fn diag_export(&self, id: Option<u64>, dir: Option<&str>) -> Result<String, String> {
        let task = id.ok_or_else(|| "missing_target".to_string())? as i64;
        let out = dir
            .map(std::path::PathBuf::from)
            .unwrap_or_else(aidm_core::diag::default_out_dir);
        let conn = self.db.lock().unwrap();
        let report = aidm_core::diag::export_task_bundle(&conn, task, &out)
            .map_err(|e| format!("diag_export: {e}"))?;
        Ok(report.path.display().to_string())
    }

    pub fn site_logins_set(
        &self,
        host: &str,
        username: &str,
        password: &str,
    ) -> Result<(), String> {
        let conn = self.db.lock().unwrap();
        aidm_core::logins::set(&conn, host, username, password)
    }

    /// 删除一条站点凭据。
    pub fn site_logins_remove(&self, host: &str) -> Result<bool, String> {
        let conn = self.db.lock().unwrap();
        aidm_core::logins::remove(&conn, host).map_err(|e| e.to_string())
    }

    pub fn events(&self) -> Arc<EventHub> {
        self.events.clone()
    }

    pub fn limiter(&self) -> Arc<TokenBucket> {
        self.limiter.clone()
    }

    /// 注册进度回调（测试钩子；生产路径走 IPC 轮询）。
    pub fn set_progress_callback(&self, cb: ProgressCallback) {
        *self.on_progress.lock().unwrap() = Some(cb);
    }

    /// 新建任务：落库（queued）并立即派发工作线程。
    pub fn add(
        &self,
        url: &str,
        dir: Option<&str>,
        filename: Option<&str>,
        referer: Option<&str>,
        speed_limit_kbps: u64,
    ) -> Result<i64, String> {
        self.add_spec(AddSpec {
            user_agent: None,
            custom_headers: None,
            alt_urls: None,
            url,
            dir,
            filename,
            referrer: referer,
            cookies: None,
            offer_id: None,
            speed_limit_kbps,
            source: None,
            start: None,
        })
    }

    pub fn add_spec(&self, spec: AddSpec<'_>) -> Result<i64, String> {
        // 粘贴来的链接常带 HTML 转义（`&amp;`）：不还原就会丢 `dn=` 与 `tr=`，
        // 磁力链丢 tracker 后只剩 DHT，DHT 不通时任务永久停在 `connecting`。
        let unescaped = aidm_core::htmltext::unescape_entities(spec.url);
        let spec_url: &str = unescaped.as_ref();
        // 封装链接先解码成真实地址再校验与落库；
        // 解码后走的仍是既有内核，所以只需要在这一处收口。
        let (url, decode_note) = match aidm_core::link_decode::decode_link(spec_url) {
            Ok(Some(d)) => match d.url {
                // 载荷里的实体还要再还原一次：封装可能把**已经 HTML 转义过**的
                // magnet 直接 base64 进载荷，外层还原够不到内层。例如解出来的
                // magnet 带 `&amp;`，`dn` 于是变成参数名 `amp;dn`，文件名与 `tr` 一起丢。
                Some(real) => (
                    aidm_core::htmltext::unescape_entities(&real).into_owned(),
                    Some(format!("decoded_from={}", scheme_of(spec_url))),
                ),
                None => {
                    return Err(d
                        .note
                        .map(|n| format!("link_not_downloadable: {n}"))
                        .unwrap_or_else(|| "link_not_downloadable".into()))
                }
            },
            Ok(None) => (spec_url.to_string(), None),
            Err(e) => return Err(e),
        };
        // eD2k（电驴）：链接本身就是最终标识（没有 host，也没有真实 URL），
        // 所以只解析出元信息落库，传输走 P2P 路径（见 docs/adr/0002）。
        //
        // **必须在解码之后判断**：专用链同样被用来包 eD2k 链接，
        // 在原始串上判断会把这类任务当成普通 URL —— 文件名与 `ed2k_hash` 都会丢。
        // 而 worker 是按**解码后**的 `url_orig` 分派 eD2k 的（worker.rs 的协议分派），
        // 两边不一致会让同一个任务在管理侧与下载侧被当成两种协议
        // （`is_ed2k = row.ed2k_hash.is_some()` 也会因此为假）。
        let ed2k_file = if aidm_core::ed2k::is_ed2k_link(&url) {
            match aidm_core::ed2k::parse_link(&url) {
                Ok(aidm_core::ed2k::Link::File(f)) => Some(f),
                Ok(_) => return Err("ed2k_not_file_link".into()),
                Err(e) => return Err(e.code().to_string()),
            }
        } else {
            None
        };
        // 从粘贴文本里抽取真实地址：把镜像页整行（含 `✅ (stable "latest" name)` 这类
        // 注释）粘进「下载链接」框时，整串当 URL 发出去必然 404。与 `link_decode`
        // 共用同一个收口点，因此也覆盖解码之后的结果；抽不出地址就保持原样，
        // 让后面的校验给出原有错误。
        let (url, paste_trimmed) = match aidm_core::alt::extract_http_url(&url) {
            Some(clean) if clean != url => (clean, true),
            _ => (url, false),
        };
        // 开发工具坐标（`npm:lodash@4.17.21` / `cargo:serde@1.0.0`）→ registry 直链。
        //
        // 放在封装解码**之后**：专用链包的坐标也该被认出来。
        //
        // 三种结果要分开处理，**不能一律放行**：
        // - 认得出且换算成功 → 用直链；
        // - **认得出但参数不全**（缺版本/包名非法）→ 如实回绝。放行的话会被后面的
        //   URL 校验拒成 `bad_url`，而真正的原因是"缺版本"，错误信息离原因太远；
        // - 认不出（就是普通 URL）→ 原样放行，这一步对它完全无副作用。
        let (url, devtool_name) = match aidm_core::devtools::resolve(&url) {
            Ok(r) => {
                let note = format!("devtool={} file={}", r.tool.as_str(), r.file_name);
                (r.url, Some((r.file_name, note)))
            }
            Err(aidm_core::devtools::DevToolError::UnknownTool) => (url, None),
            Err(e) => return Err(e.code().to_string()),
        };
        let mut filename = spec
            .filename
            .filter(|s| !s.trim().is_empty())
            .map(str::to_string);
        // 坐标换算自带文件名（`lodash-4.17.21.tgz`），比从 URL 尾巴猜更准。
        if filename.is_none() {
            if let Some((name, _)) = &devtool_name {
                filename = Some(name.clone());
            }
        }
        if filename.is_none() {
            if let Some(f) = &ed2k_file {
                filename = Some(f.decoded_name());
            }
        }
        let mut referrer = spec.referrer.map(str::to_string);
        let mut cookies = spec.cookies.map(str::to_string);
        let mut source = spec.source.unwrap_or("manual").to_string();
        // 自定义请求头：新建时就校验并规范化，非法直接拒绝这次新建
        let custom_headers_for_db: Option<String> = match spec.custom_headers {
            Some(raw) if !raw.trim().is_empty() => {
                let parsed = aidm_core::headers::parse_custom_headers(raw)
                    .map_err(|e| format!("{}:{}", e.code(), e.line()))?;
                Some(aidm_core::headers::format_custom_headers(&parsed))
            }
            _ => None,
        };
        // 备用地址（镜像）：形状非法整体拒绝（错误码 `bad_alt_url`），
        // 合法但重复/与主地址相同的条目在 `alt::parse` 里净化掉。
        validate_alt_urls(spec.alt_urls).map_err(|e| e.as_str().to_string())?;
        let alt_urls_for_db: Option<String> = match spec.alt_urls {
            Some(raw) if !raw.trim().is_empty() => {
                let parsed = aidm_core::alt::parse(raw, &url);
                if parsed.is_empty() {
                    None
                } else {
                    Some(aidm_core::alt::encode(&parsed))
                }
            }
            _ => None,
        };

        if let Some(oid) = spec.offer_id {
            let offer = self.lookup_offer(oid)?;
            if let Some(item) = offer.items.iter().find(|i| i.url == url) {
                if filename.is_none() {
                    filename = item.filename.clone();
                }
            }
            if referrer.is_none() {
                referrer = Some(offer.page_url.clone());
            }
            if cookies.is_none() {
                cookies = offer.cookies.clone();
            }
            source = "ext".into();
        }

        if let Err(e) = validate_add_fields(
            &url,
            referrer.as_deref(),
            filename.as_deref(),
            cookies.as_deref(),
        ) {
            return Err(e.as_str().into());
        }
        // FTP 现在由引擎自己实现（见 `crates/aidm-engine/src/ftp.rs`），不再拒绝
        if source != "ext" {
            source = "manual".into();
        }

        let start = spec.start.unwrap_or("now");
        if start != "now" && start != "queue" {
            return Err("bad_start".into());
        }

        let dir = spec
            .dir
            .filter(|d| !d.trim().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| self.default_dir.clone());
        let dir_str = dir.to_string_lossy().into_owned();
        let placeholder = {
            let base = resolve_filename(filename.as_deref(), None, &url);
            let conn = self.db.lock().unwrap();
            unique_task_file_name(&conn, &dir, &base)
        };
        let snap = self.settings_snapshot();
        let host = sched::url_host(&url);

        // 排除表里的主机一律不接管（引擎侧强制，不依赖扩展自觉）。
        // 手动添加（source=manual）仍然允许。
        if source == "ext" && snap.host_excluded(&host) {
            return Err("host_excluded".into());
        }

        // 分类目录：只有调用方没指定目录时才按扩展名挑；挑不到就用默认目录。
        let dir_str = if spec.dir.map(|d| !d.trim().is_empty()).unwrap_or(false) {
            dir_str
        } else {
            snap.category_dir(&placeholder)
                .map(|d| {
                    aidm_core::paths::expand_user_path(d)
                        .to_string_lossy()
                        .into_owned()
                })
                .unwrap_or(dir_str)
        };

        // 同一链接重复添加时的策略。
        if snap.duplicate_action != "allow" {
            let dup = {
                let conn = self.db.lock().unwrap();
                model::find_active_by_url(&conn, &url).unwrap_or(None)
            };
            if let Some(existing) = dup {
                match snap.duplicate_action.as_str() {
                    "skip" => return Err(format!("duplicate_skipped:{existing}")),
                    "resume" => {
                        let _ = self.resume(existing);
                        return Ok(existing);
                    }
                    // ask：交给 UI 决策，这里只回报既有任务 id
                    _ => return Err(format!("duplicate_url:{existing}")),
                }
            }
        }

        // S3：`s3://bucket/key` 预签成可直接下载的 HTTPS 地址。
        //
        // **`url` 保持 `s3://` 形态**：它是稳定标识（落库成 `url_orig`、能力查询、
        // 将来的重签都靠它），只有落到 `url_final` 的那一份换成预签名地址 ——
        // 于是下载路径**完全复用既有内核**（Range 分片、镜像、续传、代理都不用改）。
        //
        // 位置很关键：必须在**重复检查之后**。预签名地址每次都不同（含时间戳），
        // 拿它去判重等于永远判不出重复。
        let s3_presigned = {
            // 先把设置读成 owned，再借给 `S3Config`（它只借用，不持有）。
            let (ak, sk, rg, ep, ttl) = {
                let conn = self.db.lock().unwrap();
                let g = |k: &str| settings::get(&conn, k).ok().flatten().unwrap_or_default();
                (
                    g("s3.access_key"),
                    g("s3.secret_key"),
                    g("s3.region"),
                    g("s3.endpoint"),
                    g("s3.presign_ttl_s").trim().parse::<u64>().unwrap_or(3600),
                )
            };
            let cfg = crate::s3::S3Config {
                access_key: &ak,
                secret_key: &sk,
                region: &rg,
                endpoint: &ep,
                ttl_secs: ttl,
            };
            match crate::s3::normalize(&url, &cfg) {
                Ok(p) => p.map(|p| p.url),
                // 是 S3 地址但缺凭证/region ⇒ **如实回绝**，不能当成普通 URL 发出去
                //（那必然 404 或 403，而且错误信息离真正原因很远）。
                Err(e) => return Err(e.code().to_string()),
            }
        };

        let db = self.db.clone();
        let id = {
            let conn = db.lock().unwrap();
            // 连接预算**不再在任务行里物化**：建任务只记 0，真正的值在每次派发 /
            // 每个 worker 里由 `aidm_core::hosts::task_conns` 现算
            //（每服务器例外 > 全局闸门）。物化过一次，用户改设置就永远不生效。
            // 任务默认限速：显式给了就用显式的，否则按服务器默认
            let speed = if spec.speed_limit_kbps > 0 {
                spec.speed_limit_kbps as i64
            } else {
                aidm_core::hosts::effective_speed_limit_kbps(
                    &conn,
                    &host,
                    snap.default_task_limit_kbps as i64,
                )
            };
            let id = model::insert_download_ex(
                &conn,
                &url,
                &placeholder,
                &dir_str,
                speed,
                0,
                &source,
                start,
                0,
            )
            .map_err(|e| e.to_string())?;
            // 自定义头与来源网页落库，供重启后续传与任务属性展示；cookies 依旧只进内存。
            model::set_download_custom_headers(&conn, id, custom_headers_for_db.as_deref())
                .map_err(|e| e.to_string())?;
            model::set_download_referrer(&conn, id, referrer.as_deref())
                .map_err(|e| e.to_string())?;
            // 备用地址（镜像）落库：主地址坏掉时重试/重启都要靠它接着下同一份文件。
            model::set_alt_urls(&conn, id, alt_urls_for_db.as_deref())
                .map_err(|e| e.to_string())?;
            // S3 预签名地址落到 `url_final`：worker 用
            // `url_final.unwrap_or(url_orig)` 作为生效地址，所以这一步就完成了接线，
            // **不必改 worker.rs**（那正是选"预签名"而不是"签名头注入"的收益）。
            //
            // 日志里**不记预签名 URL 本身**（签名属于凭证），只记稳定的 s3:// 形态。
            if let Some(p) = &s3_presigned {
                model::set_probe_meta(&conn, id, p, None, None, None).map_err(|e| e.to_string())?;
                model::log_event(&conn, id, "s3_presigned", Some(&url));
            }
            // eD2k：大小与哈希在建任务时就已知，落库供校验/续传对账
            if let Some(f) = &ed2k_file {
                // insert_download_ex 已使用 resolve_filename 处理链接名，不能再用
                // 未净化的 decoded_name 覆盖，避免 %2F / %5C 等变成保存路径。
                model::set_probe_meta(&conn, id, &url, Some(f.size as i64), None, None)
                    .map_err(|e| e.to_string())?;
                model::set_ed2k_meta(&conn, id, Some(&f.hash_hex), f.aich_root.as_deref())
                    .map_err(|e| e.to_string())?;
                // 链接自带源（`sources,`）是 P2P 主链的第一批候选，必须落库，
                // 否则 `ed2k_task` 只能看到空表、永远"等待源"。
                if !f.sources.is_empty() {
                    let _ = model::add_ed2k_sources(&conn, id, &f.sources, Some("link"));
                }
                model::log_event(
                    &conn,
                    id,
                    "ed2k_link",
                    Some(&format!(
                        "hash={} size={} sources={}",
                        f.hash_hex,
                        f.size,
                        f.sources.len()
                    )),
                );
            }
            // 只记 URL，绝不写 cookies。备用地址只记条数：URL 本身在任务行里。
            let created_detail = match &decode_note {
                Some(note) => format!("{url} [{note}]"),
                // 粘贴时带了页面注释、已被抽取成纯地址：留痕，便于排查"地址怎么变了"
                None if paste_trimmed => format!("{url} [trimmed_pasted_text]"),
                // 坐标换算成 registry 直链：留痕是必要的 —— 用户输入的是一个包坐标，
                // 落库的却是另一条地址，不说明白就无从解释"这个任务哪来的"。
                None => match &devtool_name {
                    Some((_, note)) => format!("{url} [{note}]"),
                    None => url.clone(),
                },
            };
            let created_detail = match alt_urls_for_db.as_deref() {
                Some(alts) => format!(
                    "{created_detail} alts={}",
                    aidm_core::alt::parse(alts, &url).len()
                ),
                None => created_detail,
            };
            model::log_event(&conn, id, "created", Some(&created_detail));
            // 任务生命周期的起点（规格 §3.3）：备用地址条数决定后续会不会走镜像。
            tracing::info!(
                event = "task.created",
                alts = alt_urls_for_db
                    .as_deref()
                    .map(|a| aidm_core::alt::parse(a, &url).len())
                    .unwrap_or(0),
                url,
            );
            if decode_note.is_some() {
                model::log_event(&conn, id, "link_decoded", Some(&url));
            }
            id
        };
        self.pending.lock().unwrap().insert(
            id,
            PendingStart {
                user_agent: spec
                    .user_agent
                    .and_then(aidm_core::http_profile::sanitize_user_agent),
                custom_headers: custom_headers_for_db.clone(),
                referrer,
                cookies,
                filename,
            },
        );
        self.try_dispatch_id(id);
        self.emit_sched_if_changed();
        Ok(id)
    }

    pub fn offer(
        &self,
        page_url: String,
        title: String,
        items: Vec<OfferItem>,
        already_truncated: bool,
        cookies: Option<String>,
    ) -> Result<(String, bool), String> {
        if let Err(e) = validate_url(&page_url) {
            return Err(e.as_str().into());
        }
        if self.events.live_subscribers() == 0 {
            return Err("ui_not_running".into());
        }
        let (items, more) = truncate_offer_items(items);
        let truncated = already_truncated || more;
        if let Some(c) = cookies.as_deref() {
            if let Err(e) = aidm_ipc::validate_cookies(Some(c)) {
                return Err(e.as_str().into());
            }
        }
        let seq = self.offer_seq.fetch_add(1, Ordering::Relaxed);
        let id = format!("ofr_{}_{seq}", aidm_core::model::now_secs());
        self.offers.lock().unwrap().insert(
            id.clone(),
            StoredOffer {
                page_url: page_url.clone(),
                title: title.clone(),
                items: items.clone(),
                cookies,
                truncated,
                expires_at: Instant::now() + Duration::from_secs(OFFER_TTL_SECS),
            },
        );
        self.events.emit(EngineEvent::Candidates {
            offer_id: id.clone(),
            page_url,
            title,
            items,
            truncated: if truncated { Some(true) } else { None },
        });
        Ok((id, truncated))
    }

    fn lookup_offer(&self, offer_id: &str) -> Result<StoredOffer, String> {
        let mut offers = self.offers.lock().unwrap();
        offers.retain(|_, o| o.expires_at > Instant::now());
        offers
            .get(offer_id)
            .cloned()
            .ok_or_else(|| "offer_expired".into())
    }

    pub fn expire_offer(&self, offer_id: &str) {
        self.offers.lock().unwrap().remove(offer_id);
    }

    pub fn host_registered(&self) -> bool {
        let paths = aidm_core::nmh::NmhPaths::default_for(&aidm_core::nmh::sibling_host_exe());
        aidm_core::nmh::is_registered(&paths)
    }

    pub fn host_register(&self, register: bool) -> Result<(), String> {
        let paths = aidm_core::nmh::NmhPaths::default_for(&aidm_core::nmh::sibling_host_exe());
        if register {
            let ids = {
                let conn = self.db.lock().unwrap();
                let _ = settings::ensure_defaults(&conn);
                settings::allowed_ext_ids(&conn)
            };
            aidm_core::nmh::register(&paths, &ids)
        } else {
            aidm_core::nmh::unregister(&paths)
        }
    }

    /// 协作式取消：停止工作线程，删除任务记录与全部残留 part / 未完成文件。
    /// 已完成任务只删记录、保留最终文件。
    pub fn cancel(&self, id: i64) -> Result<(), String> {
        // 先断写入，再回收线程。撤销之后 worker 手里的任何凭据都不再放行，
        // 所以即使它正卡在慢源上，也不会在取消之后再落盘一块。
        if let Some(gate) = self.write_gates.lock().unwrap().remove(&id) {
            let _ = gate.revoke_all_quiescent(std::time::Duration::from_secs(1));
        }
        // 协调器与写入闸门一样按任务存活：删任务不清就会常驻内存。
        self.coordinators.lock().unwrap().remove(&id);
        let handle = {
            let mut tasks = self.tasks.lock().unwrap();
            tasks.remove(&id)
        };
        if let Some(mut handle) = handle {
            handle.cancel.store(true, Ordering::SeqCst);
            if let Some(worker) = handle.worker.take() {
                // 不要把 join 留在 IPC 线程里：eD2k/BT 工作线程可能正卡在 30 秒读超时、
                // 45 秒 Kad 预算或私有通道打洞里，cancel 置位后仍要自己走到检查点。
                // 同步 join 会让整个 delete 请求阻塞几十秒 —— 界面就是"点删除后卡死一会儿"。
                // 交给一次性线程回收：删除立即返回，线程在后台退出。
                std::thread::spawn(move || {
                    let _ = worker.join();
                });
            }
        }
        let db = self.db.clone();
        let conn = db.lock().unwrap();
        let row = model::get_download(&conn, id).map_err(|e| e.to_string())?;
        let Some(row) = row else {
            return Err("task_not_found".into());
        };
        let keep_final = row.status == Status::Done;
        cleanup_task_files(Path::new(&row.dir), &row.file_name, id, keep_final);
        if !keep_final {
            model::log_event(&conn, id, "cancelled", None);
        }
        let _ = model::delete_download(&conn, id);
        drop(conn);
        self.pending.lock().unwrap().remove(&id);
        self.emit_sched_if_changed();
        Ok(())
    }

    /// 暂停：工作线程在下一个读写检查点退出，状态 paused，保留 part / 部分文件。
    pub fn pause(&self, id: i64) -> Result<(), String> {
        let (pause, live, gate) = {
            let tasks = self.tasks.lock().unwrap();
            match tasks.get(&id) {
                Some(h) => (
                    h.pause.clone(),
                    h.live.clone(),
                    self.write_gates.lock().unwrap().get(&id).cloned(),
                ),
                None => return Err("task_not_running".into()),
            }
        };
        pause.store(true, Ordering::SeqCst);
        // 先断写入，再返回。
        //
        // 撤销是立即生效的（旧许可一律 `Revoked`）；静止等待的上限取 1 秒——
        // 票据只覆盖单块写（微秒级），正常路径上会立刻返回。真超时了也不能
        // 假装停干净：把数量记进 `live.pause_stragglers`，由诊断页面暴露。
        if let Some(gate) = gate {
            match gate.revoke_all_quiescent(std::time::Duration::from_secs(1)) {
                Ok(_) => {}
                Err(timeout) => {
                    live.pause_stragglers
                        .fetch_add(timeout.still_running as u64, Ordering::Relaxed);
                }
            }
        }
        Ok(())
    }

    /// 影子协调器的一拍：对**空闲**任务产出决策并落表。
    ///
    /// 边界（文档 12.2.12 的任务书）：
    /// - 不新增线程/定时器：走 manager 现有 tick；
    /// - 不改 worker：事实来自 `downloads` 行 + `segments` 汇总 + `live`；
    /// - 只让 `PlanSlices` 产生真实副作用（写表），其余动作 `Deferred`；
    /// - 同一 tick 内单任务只 submit 一次。
    fn coordinator_tick(&self) {
        // **一次加锁**取齐本拍所需的全部数据。
        //
        // 之前是每任务 3 次独立加锁 + 2 次逐任务查询：tick 周期 500ms、任务数 N 时
        // 就是 3N 次加锁与 2N 次 SQL。这条路径是唯一随任务数线性恶化的地方，
        // 所以合并成「1 次锁 + 3 条批量查询 + 1 次逐任务预算解析」。
        //
        // `observe`/`execute_pending` 必须放在锁外：它们会再拿 `self.db`，
        // `std::sync::Mutex` 不可重入。
        let mut budgeted: Vec<(aidm_core::model::DownloadRow, u64, u32, bool, u32)> = Vec::new();
        {
            let conn = self.db.lock().unwrap();
            let rows = aidm_core::model::list_downloads(&conn).unwrap_or_default();
            if rows.is_empty() {
                return;
            }
            // 已完成字节 + 每任务的落盘区间：一次扫描拿全部。
            //
            // 区间是**覆盖账本的唯一来源**：`segments` 的 `pos_start` + `done_bytes`
            // 就是「这一段落到哪儿了」。按任务汇总后写进 `download_coverage`
            // （键为 task + content_generation，见裁决 (c)）。
            let mut done_map: std::collections::HashMap<i64, u64> = std::collections::HashMap::new();
            let mut spans_map: std::collections::HashMap<i64, Vec<(u64, u64)>> =
                std::collections::HashMap::new();
            if let Ok(mut stmt) = conn.prepare(
                "SELECT download_id, pos_start, done_bytes FROM segments WHERE done_bytes > 0",
            ) {
                if let Ok(it) = stmt.query_map([], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?.max(0) as u64,
                        r.get::<_, i64>(2)?.max(0) as u64,
                    ))
                }) {
                    for (id, start, done) in it.flatten() {
                        if done == 0 {
                            continue;
                        }
                        *done_map.entry(id).or_insert(0) += done;
                        spans_map.entry(id).or_default().push((start, start + done));
                    }
                }
            }
            // 现有覆盖的 checkpoint：只在真的变了才写，否则 200 个任务每拍
            // 就是 200 次 UPDATE（采样里这条会直接吃掉调度精度）。
            let mut cov_checkpoint: std::collections::HashMap<i64, u64> =
                std::collections::HashMap::new();
            if let Ok(mut stmt) = conn.prepare(
                "SELECT task_id, checkpoint FROM download_coverage WHERE kind = 'stored'",
            ) {
                if let Ok(it) = stmt.query_map([], |r| {
                    Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
                }) {
                    for (id, cp) in it.flatten() {
                        cov_checkpoint.insert(id, cp.max(0) as u64);
                    }
                }
            }
            // 内容代次与重试预算：覆盖按代次分区，重试预算决定 R-UDL-21/22 的分界。
            let mut gen_map: std::collections::HashMap<i64, u64> = std::collections::HashMap::new();
            let mut retry_map: std::collections::HashMap<i64, u32> = std::collections::HashMap::new();
            if let Ok(mut stmt) = conn.prepare(
                "SELECT task_id, content_generation, retry_budget FROM download_runtime",
            ) {
                if let Ok(it) = stmt.query_map([], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                    ))
                }) {
                    for (id, gen, budget) in it.flatten() {
                        gen_map.insert(id, gen.max(0) as u64);
                        retry_map.insert(id, budget.clamp(0, i64::from(u32::MAX)) as u32);
                    }
                }
            }
            // 落覆盖：只写**语义可信**的任务，且只在 checkpoint 变化时写。
            //
            // 不可信的那一类（eD2k / BT）`done_bytes` 不是「段内已落盘前缀」，
            // 拿它拼区间会造出一条假的连续覆盖——恢复逻辑一旦读它就会跳过
            // 根本没下载的区段。eD2k 的真实覆盖要等阶段 D 用 part 归属账本推导。
            let trustworthy: std::collections::HashSet<i64> = rows
                .iter()
                .filter(|r| aidm_core::download::coverage::done_bytes_is_prefix(&r.url_orig))
                .map(|r| r.id)
                .collect();
            for (id, spans) in &spans_map {
                if !trustworthy.contains(id) {
                    continue;
                }
                let stored = done_map.get(id).copied().unwrap_or(0);
                if stored == 0 || cov_checkpoint.get(id).copied() == Some(stored) {
                    continue;
                }
                let raw: Vec<std::ops::Range<u64>> =
                    spans.iter().map(|(s, e)| *s..*e).collect();
                let merged =
                    aidm_core::download::coverage::CoverageSet::from_snapshot(&raw, &[]);
                let _ = aidm_core::download::store::save_coverage(
                    &conn,
                    *id,
                    gen_map.get(id).copied().unwrap_or(0),
                    "stored",
                    &merged.stored_spans(),
                    stored,
                );
            }
            // 当前生效方案：一次 JOIN 拿全部（只取 runtime 指向的那一版）。
            let mut plan_map: std::collections::HashMap<i64, Vec<aidm_core::download::plan::NormalizedSpan>> =
                std::collections::HashMap::new();
            if let Ok(mut stmt) = conn.prepare(
                "SELECT s.task_id, s.span_start, s.span_end_exclusive
                 FROM download_slices s
                 JOIN download_runtime r
                   ON r.task_id = s.task_id AND r.plan_revision = s.plan_revision",
            ) {
                if let Ok(it) = stmt.query_map([], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, Option<i64>>(2)?,
                    ))
                }) {
                    for (id, start, end) in it.flatten() {
                        plan_map
                            .entry(id)
                            .or_default()
                            .push((start.max(0) as u64, end.map(|e| e.max(0) as u64)));
                    }
                }
            }
            for row in rows {
                // 只有"空闲且无进度"的任务需要规划；其它状态跑一遍只会产出
                // `Deferred`/`Wait`。
                let status = row.status;
                if !matches!(
                    status,
                    aidm_core::model::Status::Queued | aidm_core::model::Status::Error
                ) {
                    continue;
                }
                let Some(total) = row.size_total.map(|t| t.max(0) as u64).filter(|t| *t > 0) else {
                    continue;
                };
                // `stored_bytes` 取**覆盖区间的并集长度**，不是 `SUM(done_bytes)`。
                //
                // 两者的区别在重试与换源时出现：同一段可能被写两次，`SUM` 会把它
                // 算两遍，而覆盖账本关心的是“文件里到底有多少字节是有效的”。
                // 之前这里读的是 `download_coverage.checkpoint`——那只是上一次
                // `SUM` 的副本，比本拍更旧，没有任何信息增量。
                let stored = spans_map
                    .get(&row.id)
                    .map(|spans| {
                        let raw: Vec<std::ops::Range<u64>> =
                            spans.iter().map(|(s, e)| *s..*e).collect();
                        aidm_core::download::coverage::CoverageSet::from_snapshot(&raw, &[])
                            .stored_len()
                    })
                    .unwrap_or_else(|| done_map.get(&row.id).copied().unwrap_or(0));
                let conns = aidm_core::model::task_conns_for(&conn, &row);
                let row_id_for_budget = row.id;
                let plan_ready = plan_map
                    .get(&row.id)
                    .map(|spans| aidm_core::download::plan::covers_exactly(spans, total))
                    .unwrap_or(false);
                budgeted.push((
                    row,
                    stored,
                    conns,
                    plan_ready,
                    retry_map.get(&row_id_for_budget).copied().unwrap_or(0),
                ));
            }
        }

        for (row, stored, conns, plan_ready, retry_budget) in budgeted {
            let total = row.size_total.map(|t| t.max(0) as u64).unwrap_or(0);
            let coord = self.coordinator_for(row.id);
            let error = row.error_code.as_deref().map(|code| {
                aidm_core::download::model::UnifiedError::from_legacy(
                    code,
                    row.http_status.map(|s| s as u16),
                    None,
                )
            });
            let _rep = coord.observe(crate::download::coordinator::TaskSnapshot {
                status: row.status,
                total: Some(total),
                stored_bytes: stored,
                connection_budget: conns,
                plan_ready,
                retry_budget,
                error,
            });
            // 只执行本拍新接纳的命令（`PlanSlices` 会真写表，其余 `Deferred`）。
            coord.executor().execute_pending();
        }
    }

    fn coordinator_for(&self, id: i64) -> Arc<crate::download::coordinator::Coordinator> {
        if let Some(c) = self.coordinators.lock().unwrap().get(&id) {
            return c.clone();
        }
        let mut task_identity = aidm_core::download::model::IdentityContext::for_task(id, &self.engine_instance_id);
        task_identity.run_epoch = 0;
        let task = aidm_core::download::model::TaskState::new(
            task_identity,
            aidm_core::capability::Transport::Http,
        );
        let gate = Arc::new(aidm_core::download::control::WriteGate::new());
        let exec = crate::download::executor::Executor::new(self.db.clone(), gate);
        // 跨重启恢复：把该任务当前轮次里未完成的命令读回账本。
        //
        // 以前这里是死代码——协调器每次都新建 `Executor`，ledger 永远是空的，
        // `download_commands` 里的 `pending` 命令再也不会被执行（C3-c 前置缺口）。
        // 回放是安全的：`CommandLedger::accept` 幂等，`PlanSlices` 的落表也幂等。
        {
            let epoch = {
                let conn = self.db.lock().unwrap();
                aidm_core::download::store::load_runtime(&conn, id)
                    .ok()
                    .flatten()
                    .map(|r| r.run_epoch)
                    .unwrap_or(0)
            };
            exec.begin_epoch(epoch);
            let _ = exec.recover(id, epoch);
        }
        let coord = Arc::new(crate::download::coordinator::Coordinator::new(
            aidm_core::download::reducer::Reducer::new(task),
            exec,
            aidm_core::download::policy::PolicyConfig::default(),
        ));
        self.coordinators
            .lock()
            .unwrap()
            .insert(id, coord.clone());
        coord
    }

    /// 本任务因「写入许可失效」被拒写的次数（诊断/验收用）。
    ///
    /// 这是**写盘路径真的执行过检查**的证据：命令入队不会让这个计数变化。
    pub fn write_denied_count(&self, id: i64) -> u64 {
        self.tasks
            .lock()
            .unwrap()
            .get(&id)
            .map(|h| h.live.last_write_denied.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// 本任务暂停时「静止等待超时、仍可能在写盘」的累计数量（诊断用）。
    ///
    /// 非 0 表示暂停返回时没停干净。生产路径不靠它判定任何东西，但状态页/诊断
    /// 必须能读到——否则“停了”这件事就成了不可验证的宣告。
    pub fn pause_stragglers(&self, id: i64) -> u64 {
        self.tasks
            .lock()
            .unwrap()
            .get(&id)
            .map(|h| h.live.pause_stragglers.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// 切换任务的执行归属（C6 受控启用）。
    ///
    /// 三条硬约束：
    /// - **必须静止**：有 worker 在跑就拒绝（`task_running`）——两条路径同时持有
    ///   一个任务正是文档 12.2 禁止的双归属；
    /// - 只改持久化记录，不改内存中的任何句柄；
    /// - 记一条 `execution_mode` 事件，回退时能查明是什么时候切的。
    ///
    /// 注意：切到 `Unified` 之后 worker **不再自己算切片方案**（缺方案即暂停并报
    /// `plan_missing`）。所以切到 unified 有实质前置：表里必须已有覆盖全文件的方案，
    /// 否则直接拒绝——否则"切过去"只是把一个跑不起来的任务换个标签。
    ///
    /// **这是归属预登记，不代表执行模式已生效**：数据面（探测/传输/校验/提交）
    /// 仍由 legacy 执行器承担，`AssignWork`/`Transfer`/`Verify` 一律 `Deferred`。
    /// UI/IPC 不应把它呈现为"已切换到统一执行"。
    pub fn set_execution_mode(
        &self,
        id: i64,
        mode: aidm_core::download::control::ExecutionMode,
    ) -> Result<(), String> {
        if self.tasks.lock().unwrap().contains_key(&id) {
            return Err("task_running".into());
        }
        let conn = self.db.lock().unwrap();
        // 新任务可能还没有运行记录：先建一条（默认 legacy）再改，否则 `UPDATE`
        // 影响 0 行、设置静默丢失。
        aidm_core::download::store::ensure_runtime(&conn, id).map_err(|e| e.to_string())?;

        if matches!(mode, aidm_core::download::control::ExecutionMode::Unified) {
            // 前置：unified 不许自算方案，所以表里必须已有能覆盖全文件的方案。
            // `size_total` 未知时无法校验，放行（worker 会在 probe 之后自己验）。
            let total: Option<u64> = aidm_core::model::get_download(&conn, id)
                .ok()
                .flatten()
                .and_then(|r| r.size_total)
                .map(|t| t.max(0) as u64)
                .filter(|t| *t > 0);
            if let Some(total) = total {
                let plan_ready = {
                    let rev = aidm_core::download::store::load_runtime(&conn, id)
                        .ok()
                        .flatten()
                        .map(|r| r.plan_revision)
                        .unwrap_or(0);
                    let rows = aidm_core::download::store::load_plan(&conn, id, rev)
                        .unwrap_or_default();
                    let normalized: Vec<aidm_core::download::plan::NormalizedSpan> = rows
                        .iter()
                        .map(|r| (r.span_start, r.span_end_exclusive))
                        .collect();
                    aidm_core::download::plan::covers_exactly(&normalized, total)
                };
                if !plan_ready {
                    return Err("plan_missing".into());
                }
            }
        }
        aidm_core::download::store::set_execution_mode(&conn, id, mode)
            .map_err(|e| e.to_string())?;
        aidm_core::model::log_event(&conn, id, "execution_mode", Some(mode.as_str()));
        Ok(())
    }

    /// 当前执行归属（诊断/对照用）。
    pub fn execution_mode(
        &self,
        id: i64,
    ) -> Option<aidm_core::download::control::ExecutionMode> {
        let conn = self.db.lock().unwrap();
        aidm_core::download::store::load_runtime(&conn, id)
            .ok()
            .flatten()
            .map(|r| r.execution_mode)
    }

    /// 本任务的写入许可闸门（诊断/验收用）。
    ///
    /// 生产路径不需要它；测试用它断言“暂停返回时没有在途写入”、
    /// “撤销之后新写入一律被拒”。返回 `None` 表示任务没有在跑。
    pub fn write_gate(&self, id: i64) -> Option<Arc<aidm_core::download::control::WriteGate>> {
        self.write_gates.lock().unwrap().get(&id).cloned()
    }

    /// 同一 id 从头再来：停跑、清分段与 `.aidm/<id>/`、清校验/错误后入队。
    pub fn restart(&self, id: i64) -> Result<(), String> {
        let handle = {
            let mut tasks = self.tasks.lock().unwrap();
            tasks.remove(&id)
        };
        if let Some(mut handle) = handle {
            handle.cancel.store(true, Ordering::SeqCst);
            if let Some(worker) = handle.worker.take() {
                let _ = worker.join();
            }
        }
        let row = {
            let conn = self.db.lock().unwrap();
            model::get_download(&conn, id).map_err(|e| e.to_string())?
        };
        let Some(row) = row else {
            return Err("task_not_found".into());
        };
        crate::merge::remove_part_dir(Path::new(&row.dir), id);
        {
            let conn = self.db.lock().unwrap();
            let n = model::reset_for_restart(&conn, id).map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("task_not_found".into());
            }
            model::log_event(&conn, id, "restart", Some("wipe_segments"));
        }
        self.pending.lock().unwrap().remove(&id);
        // 交给调度器：闸门有空则立刻拉起，否则保持 queued。
        self.tick();
        Ok(())
    }

    /// 为 eD2k 任务查找 HTTP 备用源（当前实现：archive.org）。
    ///
    /// 只返回文件名/大小都能对上的候选；网络失败时返回空列表，不改变原任务。
    pub fn ed2k_http_sources(&self, id: i64) -> Result<serde_json::Value, String> {
        let row = {
            let conn = self.db.lock().unwrap();
            model::get_download(&conn, id)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| "task_not_found".to_string())?
        };
        if !row
            .url_orig
            .trim_start()
            .to_ascii_lowercase()
            .starts_with("ed2k:")
        {
            return Err("not_ed2k_task".into());
        }
        let size = row.size_total.map(|v| v.max(0) as u64).filter(|v| *v > 0);
        let sources = crate::archive_source::discover_checked_until(
            &self.http,
            &row.file_name,
            size,
            Some(std::time::Instant::now() + std::time::Duration::from_secs(60)),
        )
        .unwrap_or_default();
        Ok(serde_json::to_value(sources).unwrap_or_else(|_| serde_json::Value::Array(Vec::new())))
    }

    /// 把 eD2k 任务切换到 HTTP 源。
    ///
    /// 语义：停掉当前 eD2k 线程 → 丢弃 eD2k 的分段与 `.aidm/<id>/` 工作文件 →
    /// 主地址改成 HTTP → 入队。`ed2k_hash` 保留，HTTP 完成后仍按 eD2k 整包 MD4
    /// 验收；哈希不符会报 `ed2k_hash_mismatch`，不会静默产出错误文件。
    ///
    /// 注意：当前实现不保留 eD2k 已下的 30 片，切换后从 0 重新下载。原因是分段
    /// 布局与"哪些片已校验"没有落库，直接复用 eD2k part 会让 HTTP 在未校验字节上
    /// 续传并最终哈希失败；先保证正确性，再考虑按片恢复。
    pub fn switch_ed2k_to_http(&self, id: i64, url: &str) -> Result<aidm_ipc::TaskView, String> {
        let url = url.trim();
        let parsed = url::Url::parse(url).map_err(|_| "invalid_url".to_string())?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err("invalid_url".into());
        }
        let row = {
            let conn = self.db.lock().unwrap();
            model::get_download(&conn, id)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| "task_not_found".to_string())?
        };
        if row.status == aidm_core::model::Status::Done {
            return Err("already_done".into());
        }
        if !row
            .url_orig
            .trim_start()
            .to_ascii_lowercase()
            .starts_with("ed2k:")
        {
            return Err("not_ed2k_task".into());
        }
        let handle = {
            let mut tasks = self.tasks.lock().unwrap();
            tasks.remove(&id)
        };
        if let Some(mut handle) = handle {
            handle.cancel.store(true, Ordering::SeqCst);
            if let Some(worker) = handle.worker.take() {
                let _ = worker.join();
            }
        }
        crate::merge::remove_part_dir(Path::new(&row.dir), id);
        {
            let conn = self.db.lock().unwrap();
            let n = model::reset_for_restart(&conn, id).map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("task_not_found".into());
            }
            model::set_url_orig(&conn, id, url).map_err(|e| e.to_string())?;
            let _ = model::set_alt_urls(&conn, id, None);
            model::log_event(&conn, id, "ed2k_switch_http", Some(url));
        }
        self.pending.lock().unwrap().remove(&id);
        self.tick();
        self.status(id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "task_not_found".to_string())
    }

    /// 「在磁盘上查找」：文件被移动/改名后把它找回来（`docs/file-missing-handling.md`）。
    ///
    /// 查找范围是**任务自己的目录 + 全部分类目录 + 默认下载目录**，不是整个磁盘：
    /// 用户把下载好的文件挪到别的文件夹是常见操作，而全盘遍历在几块大盘上要几十秒，
    /// 代价与收益不成比例。范围与上限见 `aidm_core::find`。
    pub fn find_file(&self, id: i64) -> Result<aidm_core::find::Report, String> {
        // 快照要在**取 db 锁之前**拿：`settings_snapshot` 自己会读库，
        // 持锁再调就是自死锁（std Mutex 不可重入）。
        let snap = self.settings_snapshot();
        let row = {
            let conn = self.db.lock().unwrap();
            model::get_download(&conn, id)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| "task_not_found".to_string())?
        };
        let mut roots: Vec<PathBuf> = Vec::new();
        if !row.dir.trim().is_empty() {
            roots.push(PathBuf::from(&row.dir));
        }
        roots.push(self.default_dir.clone());
        for (_, dir) in &snap.category_dirs {
            if !dir.trim().is_empty() {
                roots.push(PathBuf::from(dir));
            }
        }
        let report = aidm_core::find::find_file(&aidm_core::find::Query {
            name: &row.file_name,
            size: row.size_total.map(|t| t.max(0) as u64).filter(|t| *t > 0),
            roots: &roots,
        });
        if report.truncated {
            let conn = self.db.lock().unwrap();
            model::log_event(
                &conn,
                id,
                "find_truncated",
                Some(&format!(
                    "visited={} hits={}",
                    report.visited,
                    report.hits.len()
                )),
            );
        }
        Ok(report)
    }

    /// 把找到的文件重新关联到任务。
    ///
    /// 只改"任务指向哪里"，**不搬动文件**——那才是 `move`。已知总长度时必须一致：
    /// 同名不同长度的文件不是同一份下载结果，宁可拒绝也不能拿它冒充完成。
    pub fn relocate(&self, id: i64, path: &str) -> Result<TaskView, String> {
        let target = PathBuf::from(path);
        if target.as_os_str().is_empty() {
            return Err("bad_path".into());
        }
        let row = {
            let conn = self.db.lock().unwrap();
            model::get_download(&conn, id)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| "task_not_found".to_string())?
        };
        if !target.is_file() {
            return Err("file_missing".into());
        }
        let size = std::fs::metadata(&target)
            .map_err(|e| format!("stat: {e}"))?
            .len();
        if let Some(total) = row.size_total.filter(|t| *t > 0) {
            if total as u64 != size {
                return Err("size_mismatch".into());
            }
        }
        let dir = target
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .filter(|d| !d.is_empty())
            .ok_or_else(|| "bad_path".to_string())?;
        let name = target
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .ok_or_else(|| "bad_path".to_string())?;

        // 旧目录里的 part/侧车已经没有意义：文件是完整的，重新关联后不该再留着半成品。
        if !same_dir_entry(Path::new(&row.dir), Path::new(&dir)) {
            crate::merge::cleanup_task_files(Path::new(&row.dir), &row.file_name, id, false);
            crate::merge::remove_part_dir(Path::new(&row.dir), id);
        }
        {
            let conn = self.db.lock().unwrap();
            let n = model::set_location(&conn, id, &dir, &name).map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("task_not_found".into());
            }
            // 分段表按"整份文件都在了"收尾，否则列表会显示 0%（进度来自分段合计）。
            // `pos_end` 是**含**端点，所以是 size-1。
            let _ = model::clear_segments(&conn, id);
            model::init_single_segment(
                &conn,
                id,
                &target.to_string_lossy(),
                Some(size.saturating_sub(1) as i64),
            )
            .map_err(|e| e.to_string())?;
            let _ = model::finalize_segments(&conn, id);
            let _ = model::clear_retry(&conn, id);
            if row.finished_at.is_none() {
                let url = row
                    .url_final
                    .clone()
                    .unwrap_or_else(|| row.url_orig.clone());
                let _ = model::mark_done(&conn, id, &url);
            } else {
                let _ = model::set_error_fields(&conn, id, Status::Done, None, None, None);
            }
            model::log_event(&conn, id, "relocated", Some(&target.to_string_lossy()));
        }
        self.emit_sched_if_changed();
        self.status(id)?.ok_or_else(|| "task_not_found".into())
    }

    /// 改目标文件名。未完成只改 DB；`done` 先改磁盘最终文件。
    pub fn rename(&self, id: i64, filename: &str) -> Result<TaskView, String> {
        if !aidm_ipc::is_valid_rename_filename(filename) {
            return Err(aidm_ipc::ERR_INVALID_FILENAME.into());
        }
        let row = {
            let conn = self.db.lock().unwrap();
            model::get_download(&conn, id).map_err(|e| e.to_string())?
        };
        let Some(row) = row else {
            return Err("task_not_found".into());
        };

        if row.status == Status::Done && filename != row.file_name {
            let src = Path::new(&row.dir).join(&row.file_name);
            let dest = Path::new(&row.dir).join(filename);
            if same_dir_entry(&src, &dest) {
                if src.exists() {
                    std::fs::rename(&src, &dest).map_err(|e| format!("rename: {e}"))?;
                }
            } else if dest.exists() && src.exists() {
                return Err(aidm_ipc::ERR_NAME_TAKEN.into());
            } else if dest.exists() && !src.exists() {
                // 磁盘已是新名（重试）：只改 DB。
            } else if src.exists() {
                if let Err(e) = std::fs::rename(&src, &dest) {
                    std::fs::copy(&src, &dest)
                        .and_then(|_| std::fs::remove_file(&src))
                        .map_err(|e2| format!("rename: {e}; copy: {e2}"))?;
                }
            } else {
                return Err("file_not_found".into());
            }
        }

        {
            let conn = self.db.lock().unwrap();
            let n = model::set_file_name(&conn, id, filename).map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("task_not_found".into());
            }
            model::log_event(&conn, id, "rename", Some(filename));
        }
        if let Some(pending) = self.pending.lock().unwrap().get_mut(&id) {
            pending.filename = Some(filename.to_string());
        }
        self.status(id)?.ok_or_else(|| "task_not_found".into())
    }

    /// 恢复：paused / error 入队后按闸门派发；verifying 立即续合并。
    pub fn resume(&self, id: i64) -> Result<(), String> {
        // 手动恢复后不再参与配额周期的自动恢复。
        self.quota_paused.lock().unwrap().remove(&id);
        let running = self.tasks.lock().unwrap().contains_key(&id);
        if running {
            return Err("task_already_running".into());
        }
        let db = self.db.clone();
        let row = {
            let conn = db.lock().unwrap();
            model::get_download(&conn, id).map_err(|e| e.to_string())?
        };
        let Some(row) = row else {
            return Err("task_not_found".into());
        };
        match row.status {
            Status::Paused | Status::Error | Status::Verifying => {}
            other => return Err(format!("resume_from_{}", other.as_str())),
        }
        if row.status == Status::Verifying {
            self.spawn_worker(id, None, None, None, None, None, true);
            self.emit_sched_if_changed();
            return Ok(());
        }
        {
            let conn = db.lock().unwrap();
            model::set_status(&conn, id, Status::Queued, None).map_err(|e| e.to_string())?;
            let _ = model::set_start_mode(&conn, id, "now");
            let _ = conn.execute("UPDATE downloads SET retry_at = NULL WHERE id = ?1", [id]);
        }
        self.try_dispatch_id(id);
        self.emit_sched_if_changed();
        Ok(())
    }

    pub fn retry_failed(&self) -> Result<u64, String> {
        let count = {
            let conn = self.db.lock().unwrap();
            model::retry_failed(&conn).map_err(|e| e.to_string())?
        };
        self.dispatch_ready();
        self.emit_sched_if_changed();
        Ok(count)
    }

    pub fn sched_status(&self) -> (Option<i64>, u64, u64) {
        self.sched_snapshot()
    }

    /// 单任务快照：DB 行 + 实时进度。
    pub fn status(&self, id: i64) -> Result<Option<TaskView>, String> {
        // 详情只取这一行：`list_downloads` 会扫全表。属性面板 500ms 刷新时
        // 全表扫描 + 逐行 `to_view` 会把别的任务也拉进来，白白放大 IO。
        let row = {
            let conn = self.db.lock().unwrap();
            model::get_download(&conn, id).map_err(|e| e.to_string())?
        };
        let Some(row) = row else {
            return Ok(None);
        };
        let mut view = self.to_view(&row, self.live_for(id));
        // 单任务详情带统一视图；列表只带摘要（文档 10 节：
        // “任务列表只携带摘要，详情按资源、切片和源分页”）。
        // 新客户端优先读它；旧客户端忽略这个新增可选字段。
        // 复用已取的行，不再二次查库。
        view.unified_download = self.unified_summary_for(&row);
        Ok(Some(view))
    }

    /// 全部任务列表。
    pub fn list(&self) -> Result<Vec<TaskView>, String> {
        let db = self.db.clone();
        let rows = {
            let conn = db.lock().unwrap();
            model::list_downloads(&conn).map_err(|e| e.to_string())?
        };
        Ok(rows
            .iter()
            .map(|r| self.to_view(r, self.live_for(r.id)))
            .collect())
    }

    /// §9 全部设置。`proxy.pass` 不回传，以 `proxy.has_password`（bool）代替。
    ///
    /// 冷路径：直读库（每条键一次主键查询），保证 `update.last_check_at`
    /// 这类"引擎写入的只读项"立刻可见。热路径走 [`Self::settings_snapshot`]。
    pub fn settings_get(&self) -> Result<Map<String, Value>, String> {
        let raw = {
            let conn = self.db.lock().unwrap();
            settings::public_map(&conn).map_err(|e| e.to_string())?
        };
        let mut out = Map::new();
        for (k, v) in raw {
            if k == settings::HAS_PASSWORD_KEY {
                out.insert(k, Value::Bool(v == "true"));
            } else {
                out.insert(k, Value::String(v));
            }
        }
        Ok(out)
    }

    /// 校验后写入，并按 schema 声明的 `Apply` 策略决定怎么生效。
    ///
    /// 连接数上限（`conn.global_conn_cap`）与每服务器
    /// 连接数例外都走**热调**：直接把新上限推给正在跑的连接池，
    /// 不再"停任务→切分段→重启"。
    pub fn settings_set(&self, key: &str, value: &str) -> Result<(), settings::SettingError> {
        let key = settings::normalize_key(key);
        let apply = settings::spec_of(key).map(|s| s.apply);
        let old = {
            let conn = self.db.lock().unwrap();
            let old = settings::get(&conn, key).ok().flatten();
            settings::set_validated(&conn, key, value)?;
            old
        };
        let snap = self.reload_settings();
        // 设置变更审计：只记键名、修订号与是否变化，**不记值**（可能含凭据）。
        tracing::info!(
            event = "settings.changed",
            key,
            revision = snap.revision,
            apply = apply.map(|a| a.as_str()).unwrap_or("unknown"),
            changed = old.as_deref() != Some(value),
        );
        self.on_settings_applied(key, apply, &snap, value);
        // 通知所有订阅者：设置变了（不含密值），UI 据此决定要不要重读
        self.events.emit(EngineEvent::SettingsChanged {
            key: key.to_string(),
            revision: snap.revision,
        });
        Ok(())
    }

    /// 刷新 Kad bootstrap 节点列表（`nodes.dat`）。返回落库的节点数。
    ///
    /// **先取回、再持锁落库**：HTTP 可能耗时数秒，握着数据库锁等网络会挡住整个引擎。
    /// 校验在落库时做（见 `aidm_core::ed2k::kad::store`），所以畸形响应既不会入库，
    /// 也不会覆盖已有的好缓存。
    pub fn ed2k_nodes_refresh(&self) -> Result<u64, String> {
        let url = self.setting_text("ed2k.nodes_dat_url")?;
        let agent = self.http.agent();
        let doc = crate::ed2k::kad_bootstrap::fetch_nodes_dat(&agent, &url)?;
        let conn = self.db.lock().unwrap();
        let saved =
            aidm_core::ed2k::kad::store::store(&conn, &url, &doc, aidm_core::model::now_ms())?;
        Ok(saved.node_count as u64)
    }

    /// 刷新公共 eD2k 服务器列表（`server.met`）：解析后**写回** `ed2k.servers`。
    ///
    /// 不另建缓存表：这个文件的唯一消费者就是那个设置项，写回去之后用户还能继续
    /// 手工增删，也不会出现两份互相覆盖的权威（为空仍表示"不查服务器"）。
    pub fn ed2k_servers_refresh(&self) -> Result<u64, String> {
        let url = self.setting_text("ed2k.server_list_url")?;
        let agent = self.http.agent();
        let list = crate::ed2k::server_list::fetch_server_met(&agent, &url)?;
        let text = crate::ed2k::server_list::endpoints_setting(&list);
        if text.is_empty() {
            return Err("server_met_empty".into());
        }
        let count = text.split(',').count() as u64;
        self.settings_set("ed2k.servers", &text)
            .map_err(|e| e.code)?;
        Ok(count)
    }

    /// 读一个"来源地址"设置；未配置（空）视为不可刷新。
    fn setting_text(&self, key: &str) -> Result<String, String> {
        let conn = self.db.lock().unwrap();
        settings::get(&conn, key)
            .ok()
            .flatten()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .ok_or_else(|| format!("{key}_empty"))
    }

    /// 启动时**尽力**刷新 Kad 节点列表（过期才刷），不阻塞启动。
    ///
    /// 单独开线程：引擎启动不能等网络；刷新失败也只是少一份新鲜源，已有缓存与
    /// 编译期内嵌样本仍然可用。取回阶段不持库锁。
    ///
    /// 服务器列表（`server.met`）**不**自动刷：它的刷新语义是写回 `ed2k.servers`，
    /// 而那是用户可以手工编辑的设置项，后台悄悄覆盖会让人莫名其妙。只提供手动按钮。
    pub fn spawn_source_refresh_on_start(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        std::thread::spawn(move || {
            let Some(mgr) = weak.upgrade() else { return };
            let Some(url) = mgr.nodes_refresh_due() else {
                return;
            };
            let agent = mgr.http.agent();
            let doc = match crate::ed2k::kad_bootstrap::fetch_nodes_dat(&agent, &url) {
                Ok(doc) => doc,
                Err(e) => {
                    log::info!("kad bootstrap: 启动时刷新失败（{e}），继续用已有缓存/内嵌样本");
                    return;
                }
            };
            let conn = mgr.db.lock().unwrap();
            match aidm_core::ed2k::kad::store::store(&conn, &url, &doc, aidm_core::model::now_ms())
            {
                Ok(saved) => log::info!("kad bootstrap: 启动时刷新成功，{} 节点", saved.node_count),
                Err(e) => log::warn!("kad bootstrap: 启动时刷新被拒（{e}），继续用已有缓存"),
            }
        });
    }

    /// 节点列表是否该刷了；该刷才返回来源地址。
    fn nodes_refresh_due(&self) -> Option<String> {
        let conn = self.db.lock().unwrap();
        let url = settings::get(&conn, "ed2k.nodes_dat_url")
            .ok()
            .flatten()?
            .trim()
            .to_string();
        if url.is_empty() {
            return None;
        }
        let days = settings::get(&conn, "ed2k.nodes_dat_max_age_days")
            .ok()
            .flatten()
            .and_then(|v| v.trim().parse::<i64>().ok())
            .unwrap_or(7)
            .clamp(1, 90);
        let fetched_at = crate::ed2k::kad_bootstrap::cached_at(&conn);
        let stale = aidm_core::ed2k::kad::store::is_stale(
            fetched_at,
            aidm_core::model::now_ms(),
            days * 24 * 60 * 60 * 1000,
        );
        stale.then_some(url)
    }

    fn on_settings_applied(
        &self,
        key: &str,
        apply: Option<settings::Apply>,
        snap: &settings::Snapshot,
        value: &str,
    ) {
        match key {
            "speed.global_limit_kbps" => {
                let kbps = value.trim().parse::<u64>().unwrap_or(0);
                self.limiter.set_limit_kbps(kbps);
            }
            "conn.global_conn_cap" => {
                if let Ok(v) = value.trim().parse::<i64>() {
                    let _ = self.apply_limits_live(key, v);
                }
                self.tick();
            }
            _ => {}
        }
        if key.starts_with("proxy.") || key.starts_with("conn.timeout_") {
            self.http.reload(&self.db);
        }
        if key.starts_with("sched.") {
            // 配额口径随设置变化，重置统计基线；
            // after_done 的边沿**不在这里重置**：那会让"改任一 sched.* 键"
            // 都重新武装一次触发条件，导致同一个队列跑空广播多次。
            self.quota.lock().unwrap().reset();
            self.quota_fired.store(false, Ordering::SeqCst);
            self.tick();
        }
        if matches!(apply, Some(settings::Apply::Restart)) {
            log::info!("setting {key} 需要重启引擎后才完全生效");
        }
        let _ = snap;
    }

    /// 把新的连接上限推给正在跑的任务（不重启）。
    ///
    /// 返回真正"热调成功"的任务 id；没登记热调回调的任务（旧分段路径）
    /// 才需要走后面那次重排分段。
    pub fn apply_limits_live(&self, key: &str, value: i64) -> Vec<i64> {
        let handles: Vec<(i64, Arc<RetuneCell>)> = {
            let t = self.tasks.lock().unwrap();
            t.iter().map(|(id, h)| (*id, h.retune.clone())).collect()
        };
        let mut done = Vec::new();
        for (id, cell) in handles {
            if self.retune_task(id, &cell, key, value) {
                done.push(id);
            }
        }
        done
    }

    fn retune_task(&self, id: i64, cell: &Arc<RetuneCell>, key: &str, value: i64) -> bool {
        let f = cell.get();
        let Some(f) = f else { return false };
        let detail = match key {
            // 每服务器连接数例外（`host_settings.max_conns`）：不是设置键，
            // 但走同一条热调通道把新上限推给正在跑的任务。
            "host.max_conns" => {
                // 只把新上限推给正在跑的连接池；**不**写回任务行——写回就把派生值
                // 固化成了"任务自己的设置"，之后删掉例外也回不去。
                let conns = value.max(0);
                f(Retune::MaxConns(conns));
                format!("max_conns={conns} hot=1")
            }
            "conn.global_conn_cap" => {
                f(Retune::GlobalCap(value));
                format!("global_conn_cap={value} hot=1")
            }
            _ => return false,
        };
        // 三个键都留痕：热调是"没有重启"的证据，缺事件就无法从任务详情回溯。
        let conn = self.db.lock().unwrap();
        model::log_event(&conn, id, "retune", Some(&detail));
        true
    }

    /// 设置项声明表（键/默认值/类型/区间/分组/生效方式），给 UI 通用渲染用。
    pub fn settings_schema(&self) -> Value {
        settings::schema_json()
    }

    fn host_conns_value(&self) -> Value {
        let conn = self.db.lock().unwrap();
        let list = aidm_core::hosts::list(&conn).unwrap_or_default();
        Value::Array(
            list.into_iter()
                .map(|o| {
                    json!({
                        "host": o.host,
                        "max_conns": o.max_conns,
                        "speed_limit_kbps": o.speed_limit_kbps,
                        "updated_at": o.updated_at,
                    })
                })
                .collect(),
        )
    }

    pub fn host_conns_list(&self) -> Value {
        self.host_conns_value()
    }

    /// 写一项按服务器覆盖；两个值都为 `None` 等价于删除。
    pub fn host_conns_set(
        &self,
        host: &str,
        max_conns: Option<i64>,
        speed_limit_kbps: Option<i64>,
    ) -> Result<Value, String> {
        let host = aidm_core::hosts::validate_pattern(host)?;
        if let Some(n) = max_conns {
            if !(1..=1024).contains(&n) {
                return Err("max_conns_invalid".into());
            }
        }
        if let Some(s) = speed_limit_kbps {
            if s < 0 {
                return Err("speed_limit_invalid".into());
            }
        }
        {
            let conn = self.db.lock().unwrap();
            aidm_core::hosts::set(&conn, &host, max_conns, speed_limit_kbps)
                .map_err(|e| e.to_string())?;
        }
        // 已跑任务若是这个主机，立刻按新上限热调
        if let Some(n) = max_conns {
            let ids: Vec<(i64, Arc<RetuneCell>)> = {
                let t = self.tasks.lock().unwrap();
                t.iter().map(|(id, h)| (*id, h.retune.clone())).collect()
            };
            for (id, cell) in ids {
                let host_of = {
                    let conn = self.db.lock().unwrap();
                    model::get_download(&conn, id)
                        .ok()
                        .flatten()
                        .map(|r| sched::url_host(&r.url_orig))
                };
                if host_of
                    .as_deref()
                    .map(|h| sched::host_matches(&host, h))
                    .unwrap_or(false)
                {
                    self.retune_task(id, &cell, "host.max_conns", n);
                }
            }
        }
        Ok(self.host_conns_value())
    }

    pub fn host_conns_remove(&self, host: &str) -> Result<Value, String> {
        {
            let conn = self.db.lock().unwrap();
            aidm_core::hosts::remove(&conn, host).map_err(|e| e.to_string())?;
        }
        Ok(self.host_conns_value())
    }

    /// 只读系统代理。无代理时返回 JSON null。
    pub fn system_proxy_get(&self) -> Value {
        match proxy::read_system_proxy() {
            Some(p) => json!({ "host": p.host, "port": p.port }),
            None => Value::Null,
        }
    }

    /// 批量删除：停掉工作线程，始终清 part 目录与 DB 行；可选删除最终文件。
    pub fn delete(&self, ids: &[u64], delete_files: bool) -> Result<(), String> {
        if ids.is_empty() {
            return Err("empty_ids".into());
        }
        for id in ids {
            self.delete_one(*id as i64, delete_files)?;
        }
        Ok(())
    }

    fn delete_one(&self, id: i64, delete_files: bool) -> Result<(), String> {
        // 删除任务也要停止它的续种会话：用户删掉的东西不该继续对外做种。
        self.bt_seeds.stop_torrent(id);
        let handle = {
            let mut tasks = self.tasks.lock().unwrap();
            tasks.remove(&id)
        };
        if let Some(mut handle) = handle {
            handle.cancel.store(true, Ordering::SeqCst);
            if let Some(worker) = handle.worker.take() {
                let _ = worker.join();
            }
        }
        let conn = self.db.lock().unwrap();
        let row = model::get_download(&conn, id).map_err(|e| e.to_string())?;
        let Some(row) = row else {
            return Ok(());
        };
        cleanup_task_files(Path::new(&row.dir), &row.file_name, id, !delete_files);
        model::log_event(
            &conn,
            id,
            "deleted",
            Some(&format!("delete_files={delete_files}")),
        );
        let _ = model::delete_download(&conn, id);
        drop(conn);
        self.pending.lock().unwrap().remove(&id);
        self.emit_sched_if_changed();
        Ok(())
    }

    /// `total_speed` / `speed_limit` 单位为 B/s；设置键 `speed.global_limit_kbps` 为 KiB/s（×1024）。
    pub fn stats_snapshot(&self) -> StatsSnapshot {
        let tasks = self.tasks.lock().unwrap();
        let active = !tasks.is_empty();
        let total_speed = tasks.values().map(|h| h.live.refresh_speed()).sum();
        StatsSnapshot {
            total_speed,
            active_conns: self.active_conns.load(Ordering::Relaxed),
            speed_limit: self.limiter.limit_bps(),
            active,
        }
    }

    pub fn emit_event(&self, ev: EngineEvent) {
        self.events.emit(ev);
    }

    /// 启动恢复（§4）：connecting/downloading → `queued` + `interrupted`
    /// （不是 failed）；按 segments + 磁盘回写；全部分段完成但未合并 → verifying。
    pub fn recover_on_startup(&self) {
        let db = self.db.clone();
        let conn = db.lock().unwrap();
        let rows = match model::list_downloads(&conn) {
            Ok(rows) => rows,
            Err(e) => {
                log::error!("startup recovery read failed: {e}");
                return;
            }
        };
        for row in rows {
            if matches!(row.status, Status::Connecting | Status::Downloading) {
                log::info!("recovery: task {} -> queued (interrupted)", row.id);
                let msg = error::human_message(error::CODE_INTERRUPTED, None);
                let _ = model::set_error_fields(
                    &conn,
                    row.id,
                    Status::Queued,
                    Some(error::CODE_INTERRUPTED),
                    Some(&msg),
                    None,
                );
                model::log_event(&conn, row.id, "interrupted", Some("auto_requeue"));
            }
            if row.status == Status::Done {
                // 已完成的任务：段行补齐成整段下满。老版本在运行中再切分时行数会和
                // 布局错位，留下「状态已完成、进度 92%」这种残值，这里一次性修正。
                let _ = model::finalize_segments(&conn, row.id);
                continue;
            }
            match recovery::recover_download(&conn, &row) {
                Ok(RecoverOutcome::ReadyToMerge) => {
                    log::info!("recovery: task {} -> verifying (unmerged parts)", row.id);
                    let _ =
                        model::set_error_fields(&conn, row.id, Status::Verifying, None, None, None);
                    model::log_event(&conn, row.id, "recovered_verifying", None);
                }
                Ok(RecoverOutcome::Pending) => {
                    model::log_event(&conn, row.id, "recovered_segments", None);
                }
                Ok(RecoverOutcome::None) => {}
                Err(e) => log::warn!("recovery segments for {} failed: {e}", row.id),
            }
        }
    }

    /// 当前引擎实例标识（统一视图与快照游标用）。
    pub fn engine_instance_id(&self) -> &str {
        &self.engine_instance_id
    }

    /// 从 legacy 状态构造只读统一视图输入。
    ///
    /// **兼容投影**（文档 12.2）：只读、不改变任何下载行为。
    ///
    /// 三条硬规则（2026-10-24 复核修正）：
    /// - **完成判定看校验策略**：`length_only` 的任务字节铺满即完成，但
    ///   `verified_unique_bytes` 保持 0、`verification` 如实标 `length_only`；
    ///   不能因为「没有内容摘要」就永远停在 verifying。
    /// - **版本不能用字节数**：用投影可见事实的指纹。切片从等待变失败时字节数
    ///   可能不变，但状态变了，旧分页游标必须失效。
    /// - **覆盖只来自可信原生块**：eD2k 不按 `done_bytes` 从文件头铺开——实际
    ///   可能只下了后半段。未知位置的完成量只作统计，不编造区间。
    fn build_unified_reducer(
        &self,
        row: &model::DownloadRow,
    ) -> aidm_core::download::reducer::Reducer {
        use aidm_core::download::model::{
            CommitState, IdentityContext, Integrity, PlanStatus, ResourceId, ResourceState,
            TaskState, VerificationPolicy,
        };
        use aidm_core::download::reducer::Reducer;

        let (segs, budget) = {
            let conn = self.db.lock().unwrap();
            let segs = model::list_segments(&conn, row.id).unwrap_or_default();
            let budget = aidm_core::hosts::task_conns(&conn, &row.url_orig);
            (segs, budget)
        };

        let is_ed2k = row.ed2k_hash.is_some() && aidm_core::ed2k::is_ed2k_link(&row.url_orig);
        let transport = aidm_core::capability::transport_of_url(&row.url_orig)
            .unwrap_or(aidm_core::capability::Transport::Http);
        let live = self.live_for(row.id);

        let file_size = row
            .size_total
            .and_then(|t| u64::try_from(t).ok())
            .or_else(|| {
                live.as_ref()
                    .map(|l| l.total_bytes.load(Ordering::Relaxed))
                    .filter(|v| *v > 0)
            });

        let mut identity = IdentityContext::for_task(row.id, self.engine_instance_id.clone());
        identity.plan_revision = u64::from(!segs.is_empty());
        // legacy 没有轮次/内容代次概念：不从 retry_count 或进程 epoch 推导（文档 4.2）。
        identity.run_epoch = 0;
        identity.content_generation = 0;
        // 先置 0，投影完成后再用可见事实指纹回填（不能用字节数当版本）。
        identity.state_revision = 0;

        let mut task = TaskState::new(identity, transport);
        task.status = row.status;
        task.plan_status = if segs.is_empty() {
            PlanStatus::Unplanned
        } else {
            PlanStatus::Ready
        };
        task.budget.connection_budget = budget;
        task.activity = aidm_core::download::policy::activity_for(row.status);
        task.progress.required_bytes = file_size;
        task.progress.transfer_rate_bps = live.as_ref().map(|l| l.refresh_speed()).unwrap_or(0);

        // 通道计数复用现有 P2pView，不另算一套。`to_view` 内部会再加一次 db 锁，
        // 所以必须在上面释放之后调用（不能在持锁时重入）。
        let p2p = self.to_view(row, live.clone()).p2p;
        if let Some(p2p) = &p2p {
            task.counts.connections = p2p.active_peers;
            task.counts.active_transfers = p2p.transferring_peers;
            task.counts.queued_peers = p2p.queued_peers;
        }

        let mut reducer = Reducer::new(task);

        let resource_id = ResourceId::new(format!("task-{}", row.id));
        let integrity = if is_ed2k {
            Integrity::NativeBlock
        } else if row.sha256_expected.is_some() {
            Integrity::WholeFile
        } else {
            Integrity::LengthOnly
        };
        let mut resource = ResourceState::new(resource_id.clone(), row.id, 0);
        resource.size_bytes = file_size;
        resource.selected = true;
        resource.commit_state = if row.status == Status::Done {
            CommitState::Committed
        } else {
            CommitState::Pending
        };
        resource.verification_policy = VerificationPolicy {
            integrity,
            require_native_block_check: is_ed2k,
            require_file_digest: row.sha256_expected.is_some(),
            require_length_check: true,
        };
        reducer.upsert_resource(resource);

        if is_ed2k {
            self.project_ed2k_parts(
                row,
                &resource_id,
                file_size,
                budget,
                live.as_deref(),
                &p2p,
                &mut reducer,
            );
        } else {
            self.project_legacy_segments(row, &resource_id, integrity, &segs, &mut reducer);
        }

        reducer.recompute_progress();
        reducer.recompute_counts();
        // recompute 会从空源/空分配把三项计数算成 0，这里恢复真实观测值。
        if let Some(p2p) = &p2p {
            reducer.apply_observed_counts(
                p2p.active_peers,
                p2p.transferring_peers,
                p2p.queued_peers,
            );
        }
        // 版本递增：指纹只用来判断“变没变”，版本号本身必须单调递增
        // （文档 4.2 的持久化序号语义）。同一指纹反复取快照不会推高版本，
        // 所以无变化时旧游标仍然有效。
        let fingerprint = projection_fingerprint(&reducer);
        let version = {
            let mut revs = self.state_revisions.lock().unwrap();
            let entry = revs.entry(row.id).or_default();
            if entry.version == 0 || entry.fingerprint != fingerprint {
                entry.version += 1;
                entry.fingerprint = fingerprint;
            }
            entry.version
        };
        reducer.assign_state_revision(version);
        reducer
    }

    /// eD2k：按**原生 part 事实**建立切片、覆盖与通路。
    ///
    /// 数据源优先用池回写的真实归属（`LiveState.ownership`）；没有归属时退回
    /// `P2pView.slices` 的逐 part 状态。两者都没有就什么都不登记——宁可显示
    /// "未知"，也不用 `done_bytes` 猜"从文件头下了多少"。
    ///
    /// 切片分组**首次生成后固定**：预算变化不重新分组（文档 6.1），
    /// 否则同一个 `slice_id` 会悄悄换成另一段范围。
    fn ed2k_plan(
        &self,
        task_id: i64,
        total: usize,
        budget: u32,
    ) -> (Vec<std::ops::Range<usize>>, u64) {
        let mut cache = self.ed2k_plans.lock().unwrap();
        if let Some(entry) = cache.get(&task_id) {
            if entry.total == total {
                return (entry.groups.clone(), entry.revision);
            }
        }
        // 首次规划，或 part 数变化（文件大小变了）必须重新规划。
        let revision = cache
            .get(&task_id)
            .map(|e| e.revision + 1)
            .unwrap_or(1);
        let groups = crate::download::observe::part_groups(total, budget);
        cache.insert(
            task_id,
            Ed2kPlanEntry {
                total,
                groups: groups.clone(),
                revision,
            },
        );
        (groups, revision)
    }

    #[allow(clippy::too_many_arguments)]
    fn project_ed2k_parts(
        &self,
        row: &model::DownloadRow,
        resource_id: &aidm_core::download::model::ResourceId,
        file_size: Option<u64>,
        budget: u32,
        live: Option<&LiveState>,
        p2p: &Option<aidm_ipc::P2pView>,
        reducer: &mut aidm_core::download::reducer::Reducer,
    ) {
        use crate::ed2k::multi_source::PartOwnership;
        use aidm_core::ed2k::peer::{part_count, PARTSIZE};

        let Some(size) = file_size else {
            // 总长未知：只能顺序读取，不能按 part 分配。
            return;
        };
        if size == 0 {
            return;
        }
        let total = part_count(size);
        // 切片方案首次生成后固定：预算变化不重新分组（文档 6.1）。
        let (groups, plan_revision) = self.ed2k_plan(row.id, total, budget);
        reducer.assign_plan_revision(plan_revision);

        // 1) 优先：池回写的真实归属（含 owner 与对端地址）。
        let mut parts: Vec<PartOwnership> = live
            .map(|l| l.ownership.lock().unwrap().clone())
            .unwrap_or_default();

        // 2) 退回：逐 part 状态（无 owner，因此不会生成通路）。
        if parts.is_empty() {
            if let Some(states) = p2p.as_ref().and_then(|p| p.slices.as_ref()) {
                parts = states
                    .iter()
                    .enumerate()
                    .take(total)
                    .map(|(idx, &state)| {
                        let start = idx as u64 * PARTSIZE;
                        PartOwnership {
                            part_index: idx,
                            span_start: start,
                            span_end: (start + PARTSIZE).min(size),
                            owner: None,
                            peer_addr: None,
                            // 无归属观测时没有真实的领取生命周期，用 0 表示“未知”。
                            claim_seq: 0,
                            state: match state {
                                1 => "active",
                                2 => "done",
                                3 => "checking",
                                _ => "pending",
                            },
                            verified: state == 2,
                        }
                    })
                    .collect();
            }
        }
        if parts.is_empty() {
            // 没有任何 part 事实。如果任务已确认为 `done`，eD2k 的完成定义就是
            // “所有原生 part 校验通过”，所以整文件覆盖仍然可信（worker 退出、
            // 内存观测丢失不等于“没下过”）。切片仍按 part 分组生成，
            // ID 与下载期间一致，不因重启而变。
            //
            // 未完成的任务保持“未知”：不用 segments 的聚合 done_bytes 猜位置。
            // 没有任何 part 事实（暂停、重启后运行时观测丢失）。
            //
            // 仍然生成切片条目：`groups` 由 `total + budget` 确定性推导，重启后同值，
            // 所以“暂停一下详情整段消失”不是可接受的行为。
            //
            // 但**不写覆盖**：`done_bytes` 是累计接收量、乱序，不能推导位置（P1）。
            // 只有任务确认为 `done` 时，eD2k 的完成定义（所有原生 part 校验通过）
            // 才使整段覆盖可信。
            let finished = row.status == Status::Done;
            let plan_revision = reducer.task().identity.plan_revision;
            for (group_idx, group) in groups.iter().enumerate() {
                use aidm_core::download::model::{SliceId, SliceState, SliceStatus, Span};

                let start = group.start as u64 * PARTSIZE;
                let end = ((group.end as u64) * PARTSIZE).min(size);
                let Some(span) = Span::known(start, end) else {
                    continue;
                };
                let mut slice = SliceState::new(
                    SliceId::new(format!("task-{}-slice-{group_idx}", row.id)),
                    resource_id.clone(),
                    0,
                    plan_revision,
                    span,
                );
                if finished {
                    let _ = slice.coverage.insert_stored(start, end);
                    let _ = slice.coverage.insert_verified(start, end);
                }
                slice.progress.stored_unique_bytes = slice.coverage.stored_len();
                slice.progress.verified_unique_bytes = slice.coverage.verified_len();
                slice.progress.wire_bytes = slice.progress.stored_unique_bytes;
                slice.progress.required_bytes = span.len();
                slice.state = if finished {
                    SliceStatus::Done
                } else {
                    SliceStatus::Pending
                };
                reducer.upsert_slice(slice);
            }
            return;
        }

        let plan_revision = reducer.task().identity.plan_revision;
        let projection = {
            let mut map = self.peer_sources.lock().unwrap();
            crate::download::observe::project_ed2k_with_groups(
                row.id,
                0,
                0,
                plan_revision,
                resource_id,
                size,
                &groups,
                &parts,
                &mut map,
            )
        };

        let now = model::now_ms().max(0) as u64;
        for slice in projection.slices {
            reducer.upsert_slice(slice);
        }
        for assignment in projection.assignments {
            reducer.upsert_assignment(assignment);
        }
        for mut source in projection.sources {
            source.last_observed_at_ms = Some(now);
            reducer.upsert_source(source);
        }
    }

    /// HTTP 等旧分段：闭区间转左闭右开，完成判定按校验策略。
    fn project_legacy_segments(
        &self,
        row: &model::DownloadRow,
        resource_id: &aidm_core::download::model::ResourceId,
        integrity: aidm_core::download::model::Integrity,
        segs: &[model::SegmentRow],
        reducer: &mut aidm_core::download::reducer::Reducer,
    ) {
        use aidm_core::download::model::{Integrity, SliceId, SliceState, SliceStatus, Span};

        let plan_revision = reducer.task().identity.plan_revision;
        for seg in segs {
            let start = seg.pos_start.max(0) as u64;
            let span = match seg.pos_end {
                Some(end) => match end.checked_add(1) {
                    // 闭区间 → 左闭右开；溢出时放弃这一行，不静默截断。
                    Some(exclusive) if exclusive as u64 > start => {
                        Span::known(start, exclusive as u64)
                    }
                    _ => None,
                },
                None => Some(Span::open(start)),
            };
            let Some(span) = span else { continue };

            let mut slice = SliceState::new(
                SliceId::new(format!("task-{}-seg-{}", row.id, seg.idx)),
                resource_id.clone(),
                0,
                plan_revision,
                span,
            );

            let done = seg.done_bytes.max(0) as u64;
            let covered = done.min(span.len().unwrap_or(done));
            if covered > 0 {
                let _ = slice.coverage.insert_stored(start, start + covered);
                // 已验证必须记在**切片**上：任务级进度由 `recompute_progress`
                // 从切片覆盖求并集得出，只写任务级会被下一次重算覆盖。
                // - eD2k 走原生块路径（`project_ed2k_parts`）。
                // - HTTP：只有存在整文件摘要且任务已完成时才能宣称已验证。
                let seg_verified = row.sha256_expected.is_some()
                    && row.status == Status::Done
                    && seg.status == "done";
                if seg_verified {
                    let _ = slice.coverage.insert_verified(start, start + covered);
                }
            }
            slice.progress.stored_unique_bytes = slice.coverage.stored_len();
            slice.progress.verified_unique_bytes = slice.coverage.verified_len();
            slice.progress.wire_bytes = slice.progress.stored_unique_bytes;
            slice.progress.required_bytes = span.len();

            // 完成判定按任务校验策略：
            // - `length_only` / `none`：字节铺满即完成（verified 仍为 0）。
            // - `whole_file` / `native_block` / `mixed`：必须有已验证覆盖。
            let covered_enough = match integrity {
                Integrity::None | Integrity::LengthOnly => slice.coverage.covers_stored(span),
                _ => slice.coverage.covers_verified(span),
            };
            slice.state = match seg.status.as_str() {
                "running" => SliceStatus::Active,
                "error" => SliceStatus::Error,
                "done" if covered_enough => SliceStatus::Done,
                "done" => SliceStatus::Verifying,
                _ if covered_enough => SliceStatus::Done,
                _ => SliceStatus::Pending,
            };
            // legacy segments 的 idx 与 eD2k 原生 part 索引的对应关系未写进契约，
            // 所以不填 native_blocks：宁可显示“原生块未知”，也不伪造校验边界。
            reducer.upsert_slice(slice);
        }
    }
    /// 生成统一视图摘要。任务不存在时返回 `None`。
    pub fn unified_summary(&self, id: i64) -> Option<aidm_ipc::UnifiedDownloadView> {
        let row = {
            let conn = self.db.lock().unwrap();
            model::get_download(&conn, id).ok().flatten()?
        };
        self.unified_summary_for(&row)
    }

    /// 已持有任务行时的摘要投影（避免详情路径重复查库）。
    fn unified_summary_for(
        &self,
        row: &model::DownloadRow,
    ) -> Option<aidm_ipc::UnifiedDownloadView> {
        let reducer = self.build_unified_reducer(row);
        let sampled = model::now_ms().max(0) as u64;
        let src = crate::download::snapshot::SnapshotSource::from_reducer(&reducer, sampled);
        Some(crate::download::snapshot::to_summary_view(
            &src,
            aidm_ipc::SNAPSHOT_DEFAULT_LIMIT,
        ))
    }

    /// 生成 `task_snapshot` 分页响应（`unified_download_v1`）。
    pub fn unified_snapshot(
        &self,
        id: i64,
        section: Option<&str>,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<aidm_ipc::UnifiedSnapshotResponse, crate::download::snapshot::SnapshotError> {
        let row = {
            let conn = self.db.lock().unwrap();
            model::get_download(&conn, id)
                .ok()
                .flatten()
                .ok_or(crate::download::snapshot::SnapshotError::NoSuchTask)?
        };
        let reducer = self.build_unified_reducer(&row);
        let sampled = model::now_ms().max(0) as u64;
        let src = crate::download::snapshot::SnapshotSource::from_reducer(&reducer, sampled);
        crate::download::snapshot::to_snapshot_response(&src, section, cursor, limit)
    }

    fn live_for(&self, id: i64) -> Option<Arc<LiveState>> {
        self.tasks.lock().unwrap().get(&id).map(|h| h.live.clone())
    }

    fn to_view(&self, row: &DownloadRow, live: Option<Arc<LiveState>>) -> TaskView {
        // 分段先取：后面 done 的"持久化下限"与 segments 视图都要用。
        // 不要在持 db 锁时调用其它 self 方法（会重入死锁）。
        let segs = {
            let conn = self.db.lock().unwrap();
            model::list_segments(&conn, row.id).unwrap_or_default()
        };
        // **恢复后进度不能从 0 起算**：进程重启/暂停续跑时内存计数器是新的、从 0 开始，
        // 而磁盘上早已有若干 GB。显示值取「内存计数器」与「分段持久化字节」的较大者，
        // 否则重连/找源期间界面显示 0%（实测 2.14 GB 已落盘却显示 0），
        // 用户看到的就是"连不上源、一点没下"。
        let persisted: u64 = segs.iter().map(|s| s.done_bytes.max(0) as u64).sum();
        // 净下载耗时 = 历史轮次落库值 + 本轮已跑时长。暂停 / 排队 / 退避不计入：
        // 那些时刻没有 worker 线程，`run_start` 也就无从推进。
        let active_ms =
            row.active_ms.max(0) as u64 + live.as_ref().map(|l| l.run_elapsed_ms()).unwrap_or(0);
        let (done, total, speed) = match &live {
            Some(l) => {
                let t = l.total_bytes.load(Ordering::Relaxed);
                let total = if t == 0 {
                    row.size_total.unwrap_or(0).max(0) as u64
                } else {
                    t
                };
                let live_done = l.done_bytes.load(Ordering::Relaxed);
                let shown = live_done.max(persisted);
                (
                    if total > 0 { shown.min(total) } else { shown },
                    total,
                    l.refresh_speed(),
                )
            }
            None => {
                let total = row.size_total.unwrap_or(0).max(0) as u64;
                let persisted = self.persisted_done(row.id);
                // 收尾时分段会被 finalize（done 任务可能已没有分段行）：
                // 已完成任务的进度就是总大小，不能因为分段行没了就显示 0%。
                let done = if row.status == Status::Done && total > 0 {
                    total
                } else {
                    persisted
                };
                (done, total, 0)
            }
        };
        let total = if total == 0 { None } else { Some(total) };
        let pct = total
            .filter(|t| *t > 0)
            .map(|t| (done as f64 / t as f64) * 100.0);
        // `ed2k_hash` 在 eD2k 自动切 HTTP 后仍保留，用于完成时校验；
        // 协议视图必须看当前实际 URL，否则 HTTP 任务会被误显示成 eD2k。
        let is_ed2k = row.ed2k_hash.is_some() && aidm_core::ed2k::is_ed2k_link(&row.url_orig);
        let mode = if is_ed2k {
            Some("ed2k".into())
        } else if segs.len() >= 2 {
            Some("multi".into())
        } else if segs.len() == 1 {
            Some("single".into())
        } else {
            None
        };
        let p2p = if is_ed2k {
            let snapshot = live.as_ref().and_then(|l| l.p2p.lock().unwrap().clone());
            Some(snapshot.unwrap_or_else(|| {
                let known_sources = {
                    let conn = self.db.lock().unwrap();
                    conn.query_row(
                        "SELECT COUNT(*) FROM ed2k_sources WHERE download_id=?1",
                        [row.id],
                        |r| r.get::<_, u32>(0),
                    )
                    .unwrap_or(0)
                };
                let parts = aidm_core::ed2k::peer::part_count(total.unwrap_or(0)) as u32;
                // 显示值与实际派发用的是**同一个解析器**（每服务器例外 > 全局闸门）：
                // 拿任务行的历史派生值会让界面显示 32、而设置里写的是 64。
                let max_connections = {
                    let conn = self.db.lock().unwrap();
                    aidm_core::hosts::task_conns(&conn, &row.url_orig)
                };
                aidm_ipc::P2pView {
                    // 本地调度队列不表示已进入任一 peer 的上传队列。
                    phase: if row.status == Status::Queued {
                        "waiting"
                    } else {
                        row.status.as_str()
                    }
                    .into(),
                    known_sources,
                    max_connections,
                    verified_parts: (row.status == Status::Done).then_some(parts),
                    total_parts: parts,
                    ..Default::default()
                }
            }))
        } else {
            None
        };
        let segments = if segs.is_empty() {
            None
        } else {
            Some(segs.iter().map(segment_view).collect())
        };
        TaskView {
            id: row.id as u64,
            name: row.file_name.clone(),
            state: row.status.as_str().to_string(),
            done,
            total,
            speed,
            pct,
            save_path: Path::new(&row.dir)
                .join(&row.file_name)
                .to_string_lossy()
                .into_owned(),
            url: Some(row.url_orig.clone()),
            error: view_error(row),
            error_code: view_error_code(row),
            http_status: view_http_status(row),
            mode,
            p2p,
            segments,
            source: Some(row.source.clone()),
            retry_at: row.retry_at,
            referrer: row.referrer.clone(),
            alt_urls: row.alt_urls.clone(),
            alt_cursor: row.alt_urls.as_ref().map(|_| row.alt_cursor.max(0) as u32),
            created_at_ms: Some(row.created_at.saturating_mul(1000)),
            finished_at_ms: row.finished_at.map(|t| t.saturating_mul(1000)),
            active_ms: Some(active_ms),
            queue: Some(aidm_ipc::QueueRef {
                id: row.queue_id,
                name: self.queue_name(row.queue_id),
            }),
            // 统一视图由专门的快照入口提供，列表不逐条构造（成本高）。
            unified_download: None,
        }
    }

    fn dispatch_ready(&self) {
        let now = model::now_ms();
        let snap = self.settings_snapshot();
        let (gates, rows, queues) = {
            let conn = self.db.lock().unwrap();
            (
                snap.gates.clone(),
                model::list_downloads(&conn).unwrap_or_default(),
                aidm_core::queues::list(&conn).unwrap_or_default(),
            )
        };
        let cron = snap.cron.clone();
        // 队列层只做启停/时间窗准入，不限制任务数、不参与排序。
        let budget = QueueBudget::new(&rows);
        let mut queued: Vec<DownloadRow> = rows
            .iter()
            .filter(|r| r.status == Status::Queued)
            .cloned()
            .collect();
        queued.retain(|r| {
            r.retry_at.map(|t| t <= now).unwrap_or(true)
                && sched::is_eligible(&r.start_mode, cron.as_ref(), r.created_at, now)
        });
        // 不再有优先级：只按 id（入队先后）派发。
        queued.sort_by_key(|r| r.id);
        for row in queued {
            match budget.admit(&row, &queues, now) {
                QueueVerdict::Run => {}
                // 该队列这一拍不放行（停用/窗口外/并发满/队列数已满）：
                // 它后面同队列的任务会被同样拒绝，但别的队列的任务仍可能过，
                // 所以只跳过这一条，不中断整个序列。
                QueueVerdict::Skip | QueueVerdict::BlockQueue => continue,
            }
            if !self.try_dispatch_row(&row, &gates, cron.as_ref()) {
                // 连接数闸门满：后面的任务仍然可能过（不同 host），继续。
                continue;
            }
        }
    }

    fn try_dispatch_id(&self, id: i64) {
        let now = model::now_ms();
        let snap = self.settings_snapshot();
        // 手动添加同样要守闸门：时段之外、或配额已用尽，都只入队不下载。
        if !self.dispatch_allowed(&snap) {
            return;
        }
        let (gates, row) = {
            let conn = self.db.lock().unwrap();
            (
                snap.gates.clone(),
                model::get_download(&conn, id).ok().flatten(),
            )
        };
        let cron = snap.cron.clone();
        let Some(row) = row else {
            return;
        };
        if row.status != Status::Queued {
            return;
        }
        if !row.retry_at.map(|t| t <= now).unwrap_or(true) {
            return;
        }
        if !sched::is_eligible(&row.start_mode, cron.as_ref(), row.created_at, now) {
            return;
        }
        // 队列闸门与调度器同一套规则：队列停用 / 不在时间窗时，
        // 手动"立即开始"也不放行；此时把原因写进事件。
        let (queues, rows) = {
            let conn = self.db.lock().unwrap();
            (
                aidm_core::queues::list(&conn).unwrap_or_default(),
                model::list_downloads(&conn).unwrap_or_default(),
            )
        };
        let budget = QueueBudget::new(&rows);
        let (verdict, reason) = budget.admit_with_reason(&row, &queues, now);
        if verdict != QueueVerdict::Run {
            let conn = self.db.lock().unwrap();
            model::log_event(
                &conn,
                row.id,
                "queue_blocked",
                Some(&format!("reason={reason} queue={}", row.queue_id)),
            );
            return;
        }
        let _ = self.try_dispatch_row(&row, &gates, cron.as_ref());
    }

    /// 派发一个 queued 任务。
    ///
    /// 闸门与每服务器连接上限都来自设置快照 / `host_settings`，
    /// 因此按服务器例外在这里生效。
    fn try_dispatch_row(
        &self,
        row: &DownloadRow,
        gates: &sched::Gates,
        _cron: Option<&aidm_core::cron::CronExpr>,
    ) -> bool {
        if self.tasks.lock().unwrap().contains_key(&row.id) {
            return false;
        }
        // 闸门（双保险：dispatch_ready 已经拦过一层）
        if !self.dispatch_allowed(&self.settings_snapshot()) {
            return false;
        }
        let host = sched::url_host(&row.url_orig);
        // 每服务器例外优先（精确 > *.通配 > 全局值）；这里只问"这个主机有没有
        // 显式例外"，任务行里的历史派生值不参与——否则设置改了也不生效。
        let per_host = {
            let conn = self.db.lock().unwrap();
            aidm_core::hosts::effective_max_conns(
                &conn,
                &host,
                0,
                gates.max_conns_total.max(1) as i64,
            )
        };
        // 闸门只看"至少要几根连接"：不限的任务**不能**把整个全局预算预占掉，
        // 否则第二个任务永远排不进来。真正的上限由运行时的
        // `Hooks::try_acquire_connection` 按实际连接数执行。
        let cap = gates.max_conns_total.max(1);
        let gate_conns = if per_host > 0 {
            (per_host as u64).min(cap)
        } else {
            1
        };
        let snap = self.gate_snapshot(cap);
        if !sched::can_start(gates, &snap, &host, gate_conns) {
            return false;
        }
        {
            let conn = self.db.lock().unwrap();
            if !model::claim_queued(&conn, row.id, model::now_ms()).unwrap_or(false) {
                return false;
            }
        }
        let pending = self.pending.lock().unwrap().remove(&row.id);
        let (referrer, cookies, browser_user_agent, custom_headers, filename) = match pending {
            Some(p) => (
                p.referrer,
                p.cookies,
                p.user_agent,
                p.custom_headers,
                p.filename,
            ),
            // 引擎重启后 pending 已清空：自定义头必须回落到库里那份，
            // 否则续传会丢掉它，防盗链站点会立刻失败。
            None => (
                row.referrer.clone(),
                None,
                None,
                row.custom_headers.clone(),
                None,
            ),
        };
        let resume = {
            let conn = self.db.lock().unwrap();
            model::list_segments(&conn, row.id)
                .map(|s| !s.is_empty())
                .unwrap_or(false)
        };
        self.spawn_worker(
            row.id,
            referrer,
            cookies,
            browser_user_agent,
            custom_headers,
            filename,
            resume,
        );
        // 有任务真正开始跑 → 允许"队列跑空"判定
        self.after_done_armed.store(true, Ordering::SeqCst);
        true
    }

    /// 在跑任务的连接预占：按**每服务器例外**解析（一次查表，循环里不逐行查库）。
    ///
    /// 任务行里的 `downloads.max_conns` 不再参与——那是历史派生值。
    fn gate_snapshot(&self, cap: u64) -> sched::GateSnapshot {
        let conn = self.db.lock().unwrap();
        let rows = model::list_downloads(&conn).unwrap_or_default();
        let overrides = aidm_core::hosts::list(&conn).unwrap_or_default();
        let mut snap = sched::GateSnapshot::default();
        for r in rows {
            if matches!(
                r.status,
                Status::Connecting | Status::Downloading | Status::Verifying
            ) {
                let host = sched::url_host(&r.url_orig);
                // 不限的任务按 1 预占：它不该把整个全局预算占住。
                let budget =
                    aidm_core::hosts::effective_with(&overrides, &host, 0, cap.max(1) as i64);
                snap.reserved_conns += budget.max(1) as u64;
            }
        }
        snap
    }

    fn sched_snapshot(&self) -> (Option<i64>, u64, u64) {
        let snap = self.settings_snapshot();
        let next = snap
            .cron
            .as_ref()
            .and_then(|e| aidm_core::cron::next_fire_ms(e, model::now_ms()));
        let conn = self.db.lock().unwrap();
        let rows = model::list_downloads(&conn).unwrap_or_default();
        let queued = rows.iter().filter(|r| r.status == Status::Queued).count() as u64;
        let active = rows
            .iter()
            .filter(|r| {
                matches!(
                    r.status,
                    Status::Connecting | Status::Downloading | Status::Verifying
                )
            })
            .count() as u64;
        (next, queued, active)
    }

    fn emit_sched_if_changed(&self) {
        let cur = self.sched_snapshot();
        let mut last = self.last_sched.lock().unwrap();
        if last.as_ref() != Some(&cur) {
            *last = Some(cur);
            self.events.emit(EngineEvent::Sched {
                next_start_at: cur.0,
                queued: cur.1,
                active: cur.2,
            });
        }
    }

    fn persisted_done(&self, id: i64) -> u64 {
        let conn = self.db.lock().unwrap();
        model::sum_done_bytes(&conn, id).unwrap_or(0)
    }

    fn spawn_worker(
        &self,
        id: i64,
        referer: Option<String>,
        cookies: Option<String>,
        browser_user_agent: Option<String>,
        custom_headers: Option<String>,
        filename: Option<String>,
        resume: bool,
    ) {
        let cancel = Arc::new(AtomicBool::new(false));
        let pause = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let speed_window = Arc::new(SpeedWindow::new());
        let live = Arc::new(LiveState {
            speed_window: speed_window.clone(),
            ..Default::default()
        });
        // 净下载耗时从这里起算：worker 线程一退出（暂停/失败/完成）计时即停。
        *live.run_start.lock().unwrap() = Some(std::time::Instant::now());
        let retune = Arc::new(RetuneCell::default());
        let bt_selection = Arc::new(Mutex::new(crate::bt::BtSelection::default()));
        // 每任务一个写入许可闸门。轮次取库里当前的 run_epoch
        // （没有运行记录时按 0，worker 会在自己的启动路径里再对齐一次）。
        // 轮次、内容代次与执行模式都取自运行记录：
        // - 代次写死 1 会让写入许可与覆盖账本（按 generation=0 分区）分家；
        // - 执行模式是**持久化状态**，用它判断归属比「表是否为空」可靠——
        //   后者是瞬态条件，删任务、迁移、清理都能让它成立。
        let execution_mode = {
            let conn = self.db.lock().unwrap();
            let _ = aidm_core::download::store::ensure_runtime(&conn, id);
            aidm_core::download::store::load_runtime(&conn, id)
                .ok()
                .flatten()
                .and_then(|r| aidm_core::download::control::ExecutionMode::parse(r.execution_mode.as_str()))
                .unwrap_or(aidm_core::download::control::ExecutionMode::Legacy)
        };
        let gate = {
            let (epoch, generation) = {
                let conn = self.db.lock().unwrap();
                let rt = aidm_core::download::store::load_runtime(&conn, id)
                    .ok()
                    .flatten();
                (
                    rt.as_ref().map(|r| r.run_epoch).unwrap_or(0),
                    rt.as_ref().map(|r| r.content_generation).unwrap_or(0),
                )
            };
            let g = Arc::new(aidm_core::download::control::WriteGate::new());
            g.begin_epoch(epoch, generation);
            self.write_gates.lock().unwrap().insert(id, g.clone());
            g
        };
        let handle = TaskHandle {
            cancel: cancel.clone(),
            pause: pause.clone(),
            stop: stop.clone(),
            live: live.clone(),
            worker: None,
            retune: retune.clone(),
            bt_selection: bt_selection.clone(),
        };
        self.tasks.lock().unwrap().insert(id, handle);

        let db = self.db.clone();
        let default_dir = self.default_dir.clone();
        let progress_cb = self.on_progress.lock().unwrap().clone();
        let tasks = self.tasks.clone();
        let limiter = self.limiter.clone();
        let http = self.http.clone();
        let events = self.events.clone();
        let active_conns = self.active_conns.clone();
        let io_fault = self.io_fault();
        let bt_seeds = self.bt_seeds.clone();
        let worker = std::thread::Builder::new()
            .name(format!("aidm-dl-{id}"))
            .spawn(move || {
                worker::run(worker::Args {
                    id,
                    db,
                    default_dir,
                    live,
                    cancel,
                    pause,
                    stop,
                    referer,
                    cookies,
                    browser_user_agent,
                    custom_headers,
                    filename,
                    resume,
                    speed_window,
                    progress_cb,
                    tasks,
                    limiter,
                    http,
                    events,
                    active_conns,
                    io_fault,
                    retune,
                    bt_seeds,
                    bt_selection,
                    gate: Some(gate),
                    execution_mode,
                });
            })
            .expect("spawn worker");
        self.tasks
            .lock()
            .unwrap()
            .get_mut(&id)
            .expect("handle just inserted")
            .worker = Some(worker);
    }
}

#[derive(Debug, Clone, Copy)]
pub struct StatsSnapshot {
    pub total_speed: u64,
    pub active_conns: u64,
    pub speed_limit: u64,
    pub active: bool,
}

fn view_error(row: &DownloadRow) -> Option<String> {
    if let Some(msg) = row
        .error_message
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return Some(msg.to_string());
    }
    row.error_code.as_deref().map(|raw| {
        let c = error::classify(raw);
        c.message
    })
}

fn view_error_code(row: &DownloadRow) -> Option<String> {
    let raw = row.error_code.as_deref()?.trim();
    if raw.is_empty() {
        return None;
    }
    let c = error::classify(raw);
    if error::is_known_code(&c.code) {
        Some(c.code)
    } else {
        None
    }
}

fn view_http_status(row: &DownloadRow) -> Option<u16> {
    if let Some(s) = row.http_status {
        return Some(s);
    }
    let raw = row.error_code.as_deref()?;
    error::classify(raw).http_status
}

fn same_dir_entry(a: &Path, b: &Path) -> bool {
    #[cfg(windows)]
    {
        a.as_os_str().eq_ignore_ascii_case(b.as_os_str())
    }
    #[cfg(not(windows))]
    {
        a == b
    }
}

/// 用统一信封承载一条影子观测。
///
/// 不新增 `events` 列，所以信封按受控字段投影：
/// `kind` 走兼容映射、`detail` 只放关联编号与版本。这样即使列不够，
/// 状态、源观测与决策仍然能通过 `event_id` / `state_revision` / `decision_id` 串联。
fn build_envelope(
    event_seq: u64,
    reducer: &aidm_core::download::reducer::Reducer,
    name: &'static str,
    payload: aidm_core::download::model::EventPayload,
    reason: Option<&str>,
) -> aidm_core::download::model::EventEnvelope {
    use aidm_core::download::model::{
        EventEnvelope, EventId, EventLevel, Outcome, EVENT_SCHEMA_VERSION,
    };

    let now = model::now_ms().max(0) as u64;
    EventEnvelope {
        schema_version: EVENT_SCHEMA_VERSION,
        event_id: EventId::generate(),
        event_name: name,
        event_seq,
        observed_at_ms: now,
        recorded_at_ms: now,
        level: EventLevel::Info,
        outcome: Some(Outcome::Ok),
        identity: reducer.task().identity.clone(),
        phase: None,
        operation: Some("shadow_observe".to_owned()),
        scope: None,
        subject_id: None,
        decision_id: None,
        command_id: None,
        cause_event_id: None,
        reason_code: reason.map(str::to_owned),
        error: None,
        duration_ms: None,
        payload,
    }
}

/// 把信封投影成 `events` 表的一行。
///
/// `detail` 只放**关联编号与版本**，不放 payload 正文、原始响应或参数：
/// 新消费者禁止从 `detail` 反推业务状态（文档 11.2）。`k=v` 的键名也避开了
/// `log_event` 会提取的结构化列（phase/outcome/err_code/...），不会造成误归类。
fn log_envelope(conn: &Connection, env: &aidm_core::download::model::EventEnvelope) {
    use aidm_core::download::model::{event_name, EventPayload};

    let kind = event_name::compat_kind(env.event_name).unwrap_or("unified_event");
    // 从受控载荷里取出诊断必需的少量字段：动作名、规则号、状态前后值。
    // 不写 payload 的其他内容（证据、参数、原始正文）。
    let (action, rule, transition) = match &env.payload {
        EventPayload::Decision {
            action, rule_id, ..
        } => (action.as_str(), rule_id.as_str(), String::new()),
        EventPayload::StateChanged { from, to, .. } =>
            ("-", "-", format!("from={} to={}", from.as_str(), to.as_str())),
        EventPayload::SourceChanged { merged_count, .. } =>
            ("-", "-", format!("merged={merged_count}")),
        _ => ("-", "-", String::new()),
    };
    let detail = format!(
        "event={} event_id={} rev={} run={} gen={} plan={} decision={} command={} cause={} reason={} action={} rule={} {}",
        env.event_name,
        env.event_id,
        env.identity.state_revision,
        env.identity.run_epoch,
        env.identity.content_generation,
        env.identity.plan_revision,
        env.decision_id
            .as_ref()
            .map(|d| d.as_str())
            .unwrap_or("-"),
        env.command_id
            .as_ref()
            .map(|d| d.as_str())
            .unwrap_or("-"),
        env.cause_event_id
            .as_ref()
            .map(|d| d.as_str())
            .unwrap_or("-"),
        env.reason_code.as_deref().unwrap_or("-"),
        action,
        rule,
        transition,
    );
    model::log_event(conn, env.identity.task_id, kind, Some(detail.trim_end()));
}

/// 记录摘要；仅在内容变化时返回 `true`。
///
/// 影子埋点靠它做内容去重，避免“每拍都写一条解释器日志”（R-OBS-14）。
fn remember(map: &Mutex<HashMap<i64, String>>, id: i64, summary: String) -> bool {
    let mut seen = map.lock().unwrap();
    if seen.get(&id) == Some(&summary) {
        false
    } else {
        seen.insert(id, summary);
        true
    }
}

/// 影子决策摘要（受控短文本，供 `unified_decision` 事件使用）。
///
/// 只记受控字段（规则号、动作、原因码、自信等级），不把参数或证据正文写进去：
/// 事件是脱敏投影，不是调试转储（文档 11.2 / 11.5）。
fn summarize_decisions(decisions: &[aidm_core::download::model::Decision]) -> String {
    if decisions.is_empty() {
        return "count=0".to_owned();
    }
    let mut parts = Vec::new();
    for d in decisions.iter().take(4) {
        parts.push(format!(
            "{}:{}:{}:{}",
            d.rule_id,
            d.action.as_str(),
            d.reason_code,
            d.confidence.as_str()
        ));
    }
    format!("count={} {}", decisions.len(), parts.join(","))
}

/// 投影可见事实的指纹，用于**检测**变化。
///
/// 注意：指纹只能当“变没变”的判据，不能直接当版本号（文档 4.2 要求
/// `state_revision` 是可持久化的递增序号）。递增由 `RevisionEntry` 负责。
///
/// 覆盖范围必须与 IPC 视图一致：任何会出现在 `UnifiedDownloadView` 里的字段
/// 都要参与，否则“改了一个看得见的东西但游标没失效”。2026-10-24 复核就抓到
/// 了 `resources[].verification` 漏算这一例。
fn projection_fingerprint(reducer: &aidm_core::download::reducer::Reducer) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut h = DefaultHasher::new();
    let task = reducer.task();

    // ---- 任务 ----
    task.status.as_str().hash(&mut h);
    task.activity.as_str().hash(&mut h);
    task.plan_status.as_str().hash(&mut h);
    task.primary_transport.as_str().hash(&mut h);
    task.budget.connection_budget.hash(&mut h);
    task.budget.retry_budget.hash(&mut h);
    task.storage_revision.hash(&mut h);
    if let Some(w) = &task.wait {
        w.reason.as_str().hash(&mut h);
        w.scope.as_str().hash(&mut h);
        w.subject_id.hash(&mut h);
        w.since_ms.hash(&mut h);
        w.retry_at_ms.hash(&mut h);
        w.detail_code.hash(&mut h);
    }
    let p = task.progress;
    (
        p.wire_bytes,
        p.stored_unique_bytes,
        p.verified_unique_bytes,
        p.required_bytes,
        p.transfer_rate_bps,
        p.useful_rate_bps,
    )
        .hash(&mut h);
    let c = task.counts;
    (
        c.known_sources,
        c.eligible_sources,
        c.connections,
        c.active_transfers,
        c.queued_peers,
        c.done_slices,
    )
        .hash(&mut h);
    if let Some(e) = &task.current_error {
        e.category.as_str().hash(&mut h);
        e.code.hash(&mut h);
        e.phase.map(|p| p.as_str()).hash(&mut h);
        e.operation.hash(&mut h);
        e.retryable.hash(&mut h);
        e.retry_after_ms.hash(&mut h);
        e.protocol.map(|p| p.as_str()).hash(&mut h);
        e.protocol_code.hash(&mut h);
        e.message.hash(&mut h);
        for link in &e.cause_chain {
            link.code.hash(&mut h);
        }
    }

    // ---- 资源 ----
    // `verification` / `commit_state` / `size_bytes` / `selected` 都是可见字段。
    for r in reducer.task().resource_ids.iter().filter_map(|id| reducer.resource(id)) {
        r.resource_id.as_str().hash(&mut h);
        r.selected.hash(&mut h);
        r.size_bytes.hash(&mut h);
        r.commit_state.as_str().hash(&mut h);
        r.verification_policy.integrity.as_str().hash(&mut h);
        r.verification_policy.require_native_block_check.hash(&mut h);
        r.verification_policy.require_file_digest.hash(&mut h);
        r.verification_policy.require_length_check.hash(&mut h);
        if let Some(id) = &r.identity {
            id.algorithm.as_str().hash(&mut h);
            id.digest_hex.hash(&mut h);
            // TrustLevel 没有 `as_str`，用 Debug 字面量；它是受控闭集，稳定。
            format!("{:?}", id.trust).hash(&mut h);
        }
    }

    // ---- 切片 ----
    for slice in reducer.slices() {
        slice.slice_id.as_str().hash(&mut h);
        slice.state.as_str().hash(&mut h);
        slice.span.start.hash(&mut h);
        slice.span.end_exclusive.hash(&mut h);
        let p = slice.progress;
        (
            p.wire_bytes,
            p.stored_unique_bytes,
            p.verified_unique_bytes,
            p.required_bytes,
            p.transfer_rate_bps,
        )
            .hash(&mut h);
        if let Some(w) = &slice.wait {
            w.reason.as_str().hash(&mut h);
            w.detail_code.hash(&mut h);
        }
        for b in &slice.native_blocks {
            b.native_index.hash(&mut h);
            b.span.start.hash(&mut h);
            b.span.end_exclusive.hash(&mut h);
            b.verified.hash(&mut h);
        }
        slice.assignment_ids.len().hash(&mut h);
    }

    // ---- 通路 ----
    for a in reducer.assignments() {
        a.assignment_id.as_str().hash(&mut h);
        a.slice_id.as_str().hash(&mut h);
        a.source_id.as_str().hash(&mut h);
        a.connection_id.as_ref().map(|c| c.as_str()).hash(&mut h);
        a.state.as_str().hash(&mut h);
        a.span.start.hash(&mut h);
        a.span.end_exclusive.hash(&mut h);
        a.lease_revision.hash(&mut h);
        a.progress.transfer_rate_bps.hash(&mut h);
    }

    // ---- 源 ----
    for s in reducer.sources() {
        s.source_id.as_str().hash(&mut h);
        s.resource_id.as_str().hash(&mut h);
        s.transport.as_str().hash(&mut h);
        s.availability.as_str().hash(&mut h);
        s.eligible.hash(&mut h);
        s.cooldown_until_ms.hash(&mut h);
        s.last_observed_at_ms.hash(&mut h);
        s.expires_at_ms.hash(&mut h);
        s.health.throughput_bps.hash(&mut h);
        s.health.queued_peers.hash(&mut h);
        s.capabilities.metadata_known.as_str().hash(&mut h);
        s.capabilities.random_read.as_str().hash(&mut h);
        s.capabilities.resume.as_str().hash(&mut h);
        s.capabilities.multi_source.as_str().hash(&mut h);
        s.capabilities.integrity.as_str().hash(&mut h);
    }

    h.finish()
}

fn segment_view(row: &aidm_core::model::SegmentRow) -> SegmentView {
    SegmentView {
        idx: row.idx.max(0) as u32,
        pos_start: row.pos_start.max(0) as u64,
        pos_end: row.pos_end.map(|e| e.max(0) as u64),
        done_bytes: row.done_bytes.max(0) as u64,
        status: row.status.clone(),
        retries: if row.retries > 0 {
            Some(row.retries as u32)
        } else {
            None
        },
    }
}

/// 取 URL 的 scheme（小写，不含 `://`）。
fn scheme_of(url: &str) -> String {
    url.trim()
        .split_once("://")
        .map(|(s, _)| s.to_ascii_lowercase())
        .unwrap_or_default()
}

#[cfg(test)]
mod shadow_tests {
    use super::*;

    fn setup(tag: &str) -> (DownloadManager, Arc<Mutex<Connection>>, tempfile::TempDir) {
        let tmp = crate::testsupport::tempdir(tag);
        let conn = aidm_core::open_db(&tmp.path().join("db.sqlite")).expect("open db");
        aidm_core::settings::ensure_defaults(&conn).expect("defaults");
        let db = Arc::new(Mutex::new(conn));
        let mgr = DownloadManager::new(db.clone(), tmp.path().join("dl"));
        (mgr, db, tmp)
    }

    fn seed_task(db: &Arc<Mutex<Connection>>) -> i64 {
        let conn = db.lock().unwrap();
        let id = model::insert_download(
            &conn,
            "https://example.invalid/a.bin",
            "a.bin",
            "/tmp",
            0,
            4,
        )
        .expect("insert");
        conn.execute(
            "UPDATE downloads SET size_total = 1000, status = 'downloading' WHERE id = ?1",
            rusqlite::params![id],
        )
        .expect("set status");
        for (idx, start, end, done, status) in
            [(0i32, 0i64, 499i64, 100i64, "running"), (1, 500, 999, 0, "pending")]
        {
            conn.execute(
                "INSERT INTO segments(download_id, idx, pos_start, pos_end, done_bytes, part_path, status, retries)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, 0)",
                rusqlite::params![id, idx, start, end, done, format!("p{idx}"), status],
            )
            .expect("insert segment");
        }
        id
    }

    fn event_kinds(db: &Arc<Mutex<Connection>>, id: i64) -> Vec<String> {
        let conn = db.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT kind FROM events WHERE download_id = ?1 ORDER BY id")
            .expect("prepare");
        let rows = stmt
            .query_map([id], |r| r.get::<_, String>(0))
            .expect("query");
        rows.map(|r| r.expect("row")).collect()
    }

    #[test]
    fn shadow_writes_state_source_and_decision_events() {
        let (mgr, db, _tmp) = setup("shadow-events");
        let id = seed_task(&db);

        mgr.shadow_tick();

        let kinds = event_kinds(&db, id);
        assert!(
            kinds.iter().any(|k| k == "unified_state_changed"),
            "状态埋点必须落库，实际 {kinds:?}"
        );
        assert!(
            kinds.iter().any(|k| k == "unified_source_changed"),
            "源观测事实必须落库，实际 {kinds:?}"
        );
        assert!(
            kinds.iter().any(|k| k == "unified_decision"),
            "影子决策必须落库，实际 {kinds:?}"
        );

        // 决策必须是“只记录”形态：只允许 `wait`（本来就不改执行状态）
        // 或 `observe_only`（已降级的执行类动作）。
        let conn = db.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT detail FROM events WHERE download_id = ?1 AND kind = 'unified_decision'")
            .expect("prepare");
        let detail: String = stmt
            .query_row([id], |r| r.get::<_, Option<String>>(0))
            .expect("detail")
            .unwrap_or_default();
        let body = detail.split_once(' ').map(|(_, b)| b).unwrap_or("");
        let action = body
            .split_whitespace()
            .find_map(|kv| kv.strip_prefix("action="))
            .unwrap_or("");
        assert!(
            matches!(action, "wait" | "observe_only"),
            "影子决策只允许 wait / observe_only，实际 {action}（{detail}）"
        );
        assert!(
            detail.contains("event=download.decision"),
            "必须用统一信封标记事件名（不是自由文本）：{detail}"
        );
        assert!(
            detail.contains("event_id=") && detail.contains("rev="),
            "信封必须带 event_id 与 state_revision 以支持追溯：{detail}"
        );
        for forbidden in ["assign_work", "retry", "switch_source", "open"] {
            assert!(
                !body.contains(forbidden),
                "影子决策不得包含执行类动作 {forbidden}，实际 {detail}"
            );
        }
    }

    #[test]
    fn shadow_does_not_change_download_state() {
        let (mgr, db, _tmp) = setup("shadow-readonly");
        let id = seed_task(&db);

        mgr.shadow_tick();

        let conn = db.lock().unwrap();
        let row = model::get_download(&conn, id).expect("get").expect("row");
        assert_eq!(row.status, Status::Downloading, "影子路径不得改任务状态");
        let segs = model::list_segments(&conn, id).expect("segments");
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[0].done_bytes, 100, "影子路径不得改分段进度");
        assert_eq!(segs[1].status, "pending");
        assert_eq!(segs[0].status, "running");
    }

    #[test]
    fn shadow_dedupes_unchanged_summaries() {
        let (mgr, db, _tmp) = setup("shadow-dedupe");
        let id = seed_task(&db);

        mgr.shadow_tick();
        let first = event_kinds(&db, id).len();
        assert!(first >= 3, "首拍应写入三类事件，实际 {first}");

        // 清掉节流时间戳、状态不变，再跑一次：不应新增事件。
        *mgr.shadow_last.lock().unwrap() = None;
        mgr.shadow_tick();
        let second = event_kinds(&db, id).len();
        assert_eq!(second, first, "状态未变时不得重复记录（R-OBS-14）");
    }

    #[test]
    fn shadow_records_terminal_state_once_without_decisions() {
        let (mgr, db, _tmp) = setup("shadow-terminal");
        let id = seed_task(&db);
        {
            let conn = db.lock().unwrap();
            conn.execute(
                "UPDATE downloads SET status = 'done' WHERE id = ?1",
                rusqlite::params![id],
            )
            .expect("set done");
        }

        mgr.shadow_tick();
        let kinds = event_kinds(&db, id);
        // 用户复核：完成/失败不能被影子循环过滤掉，否则无法追溯。
        assert_eq!(
            kinds.iter().filter(|k| *k == "unified_state_changed").count(),
            1,
            "终态必须记录一次状态变化，实际 {kinds:?}"
        );
        assert!(
            !kinds.iter().any(|k| k == "unified_decision"),
            "终态任务不应再产生决策建议：{kinds:?}"
        );

        // 再跑一次：不重复记录。
        *mgr.shadow_last.lock().unwrap() = None;
        mgr.shadow_tick();
        let again = event_kinds(&db, id);
        assert_eq!(again.len(), kinds.len(), "终态事件不得每拍重复写");
    }
}

#[cfg(test)]
mod ed2k_projection_tests {
    use super::*;
    use crate::ed2k::multi_source::PartOwnership;
    use aidm_core::ed2k::peer::PARTSIZE;
    use std::net::SocketAddr;

    fn setup(tag: &str) -> (DownloadManager, Arc<Mutex<Connection>>, tempfile::TempDir) {
        let tmp = crate::testsupport::tempdir(tag);
        let conn = aidm_core::open_db(&tmp.path().join("db.sqlite")).expect("open db");
        aidm_core::settings::ensure_defaults(&conn).expect("defaults");
        let db = Arc::new(Mutex::new(conn));
        let mgr = DownloadManager::new(db.clone(), tmp.path().join("dl"));
        (mgr, db, tmp)
    }

    /// 建一个 eD2k 任务并注入运行中句柄（只有 ownership 有数据）。
    fn seed_ed2k(
        mgr: &DownloadManager,
        db: &Arc<Mutex<Connection>>,
        parts: Vec<PartOwnership>,
        size: u64,
    ) -> i64 {
        let id = {
            let conn = db.lock().unwrap();
            let id = model::insert_download(
                &conn,
                "ed2k://|file|a.iso|19456000|E7C526499308841A4A6D116C857DB669|/",
                "a.iso",
                "/tmp",
                0,
                4,
            )
            .expect("insert");
            conn.execute(
                "UPDATE downloads SET size_total = ?1, status = 'downloading', ed2k_hash = ?2 WHERE id = ?3",
                rusqlite::params![size as i64, "e7c526499308841a4a6d116c857db669", id],
            )
            .expect("set ed2k fields");
            id
        };

        let live = Arc::new(LiveState::default());
        *live.ownership.lock().unwrap() = parts;
        let handle = TaskHandle {
            cancel: Arc::new(AtomicBool::new(false)),
            pause: Arc::new(AtomicBool::new(false)),
            stop: Arc::new(AtomicBool::new(false)),
            live,
            worker: None,
            retune: Arc::new(RetuneCell::default()),
            bt_selection: Arc::new(Mutex::new(crate::bt::BtSelection::default())),
        };
        mgr.tasks.lock().unwrap().insert(id, handle);
        id
    }

    fn part(idx: usize, size: u64, owner: Option<usize>, port: Option<u16>, state: &'static str, verified: bool) -> PartOwnership {
        let start = idx as u64 * PARTSIZE;
        PartOwnership {
            part_index: idx,
            span_start: start,
            span_end: (start + PARTSIZE).min(size),
            owner,
            peer_addr: port.map(|p| SocketAddr::from(([127, 0, 0, 1], p))),
            claim_seq: idx as u64 + 1,
            state,
            verified,
        }
    }

    fn count_events(db: &Arc<Mutex<Connection>>, id: i64, kind: &str) -> usize {
        let conn = db.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT COUNT(*) FROM events WHERE download_id = ?1 AND kind = ?2")
            .expect("prepare");
        stmt.query_row(rusqlite::params![id, kind], |r| r.get::<_, i64>(0))
            .expect("count") as usize
    }

    #[test]
    fn budget_change_does_not_change_slice_ranges() {
        // 用户反例：连接上限 2→4，同一个 slice_id 的范围从 [0,19456000) 变成
        // [0,9728000)。文档 6.1 要求运行时预算变化不重新编号切片。
        let (mgr, db, _tmp) = setup("ed2k-budget");
        mgr.settings_set("conn.global_conn_cap", "2")
            .expect("cap 2");

        let size = PARTSIZE * 4;
        let parts: Vec<PartOwnership> = (0..4)
            .map(|i| part(i, size, Some(i), Some(43000 + i as u16), "receiving", false))
            .collect();
        let id = seed_ed2k(&mgr, &db, parts, size);

        fn ranges(v: &aidm_ipc::UnifiedDownloadView) -> Vec<(String, String, Option<String>)> {
            v.slices
                .iter()
                .map(|s| {
                    (
                        s.slice_id.clone(),
                        s.range.start.clone(),
                        s.range.end_exclusive.clone(),
                    )
                })
                .collect()
        }

        let first = mgr.unified_summary(id).expect("first");
        let before = ranges(&first);
        let plan_before = first.identity.plan_revision.clone();
        assert_eq!(before.len(), 2, "预算 2 → 2 个切片");

        // 预算改到 4：不得重新分组。
        mgr.settings_set("conn.global_conn_cap", "4")
            .expect("cap 4");
        let second = mgr.unified_summary(id).expect("second");
        assert_eq!(
            ranges(&second),
            before,
            "预算变化不得改变切片编号与范围（否则 UI 同一进度条会代表另一段文件）"
        );
        assert_eq!(
            second.identity.plan_revision, plan_before,
            "方案版本不得因预算变化而推进"
        );
    }

    #[test]
    fn same_source_count_after_switch_is_still_reported() {
        // 用户复核：源摘要只比数量时，“A 下线、B 接上”会漏报。
        let (mgr, db, _tmp) = setup("ed2k-switch");
        let size = PARTSIZE;
        let id = seed_ed2k(
            &mgr,
            &db,
            vec![part(0, size, Some(0), Some(42001), "receiving", false)],
            size,
        );

        mgr.shadow_tick();
        let first = count_events(&db, id, "unified_source_changed");
        assert_eq!(first, 1, "首次观测应写一条源变化");

        // 换源：源数量仍是 1，但对端地址变了。
        {
            let tasks = mgr.tasks.lock().unwrap();
            let handle = tasks.get(&id).expect("handle");
            *handle.live.ownership.lock().unwrap() =
                vec![part(0, size, Some(0), Some(42002), "receiving", false)];
        }
        *mgr.shadow_last.lock().unwrap() = None;
        mgr.shadow_tick();

        let second = count_events(&db, id, "unified_source_changed");
        assert_eq!(
            second, 2,
            "同数量换源也必须被检出（比较 source_id 集合，不是只比数量）"
        );
    }

    #[test]
    fn ownership_becomes_real_assignments_in_the_snapshot() {
        // 用户验收缺口：装好了传感器接口却未接线。这里验证池回写的真实归属
        // 真的进入了统一视图的切片与通路。
        let (mgr, db, _tmp) = setup("ed2k-own");
        let size = PARTSIZE * 2;
        let parts = vec![
            part(0, size, Some(0), Some(40001), "done", true),
            part(1, size, Some(1), Some(40002), "receiving", false),
        ];
        let id = seed_ed2k(&mgr, &db, parts, size);

        let view = mgr.unified_summary(id).expect("summary");
        assert_eq!(view.slices.len(), 2, "2 个 part、预算≥2 时应为 2 个切片");

        // part0 已完成并通过原生校验：切片 done + 已验证覆盖。
        assert_eq!(view.slices[0].state, "done");
        assert_eq!(
            view.slices[0].progress.verified_unique_bytes,
            PARTSIZE.to_string()
        );
        // part1 正在接收：切片 active，且有真实通路。
        assert_eq!(view.slices[1].state, "active");
        assert_eq!(
            view.slices[1].assignments.len(),
            1,
            "有 owner + 对端地址就必须生成通路"
        );
        assert_eq!(view.slices[1].assignments[0].state, "transferring");

        // 两个不同对端 → 两个不同 source_id；总进度为真实 part 覆盖。
        assert_eq!(view.counts.known_sources, 2);
        assert_eq!(view.progress.verified_unique_bytes, PARTSIZE.to_string());
        assert_eq!(view.progress.stored_unique_bytes, PARTSIZE.to_string());
    }

    #[test]
    fn same_part_owner_keeps_stable_ids_across_refreshes() {
        // 用户验收缺口：编号每次投影重生成，UI 无法连续渲染。
        let (mgr, db, _tmp) = setup("ed2k-stable");
        let size = PARTSIZE * 2;
        let parts = vec![
            part(0, size, Some(0), Some(41001), "receiving", false),
            part(1, size, Some(1), Some(41002), "receiving", false),
        ];
        let id = seed_ed2k(&mgr, &db, parts, size);

        let a = mgr.unified_summary(id).expect("a");
        let b = mgr.unified_summary(id).expect("b");
        let ids_a: Vec<_> = a.slices.iter().map(|s| s.slice_id.clone()).collect();
        let ids_b: Vec<_> = b.slices.iter().map(|s| s.slice_id.clone()).collect();
        assert_eq!(ids_a, ids_b, "切片编号必须跨刷新稳定");

        let asg_a: Vec<_> = a.slices[0].assignments.iter().map(|x| x.assignment_id.clone()).collect();
        let asg_b: Vec<_> = b.slices[0].assignments.iter().map(|x| x.assignment_id.clone()).collect();
        assert_eq!(asg_a, asg_b, "分配编号必须跨刷新稳定");

        let src_a: Vec<_> = a.slices[0].assignments.iter().map(|x| x.source_id.clone()).collect();
        let src_b: Vec<_> = b.slices[0].assignments.iter().map(|x| x.source_id.clone()).collect();
        assert_eq!(src_a, src_b, "source_id 必须跨刷新稳定");
    }

    #[test]
    fn ownership_absent_falls_back_to_part_states_without_peers() {
        // 没有归属时退回逐 part 状态：覆盖正确，但**不生成通路**。
        let (mgr, db, _tmp) = setup("ed2k-fallback");
        let size = PARTSIZE * 2;
        let id = {
            let conn = db.lock().unwrap();
            let id = model::insert_download(
                &conn,
                "ed2k://|file|a.iso|19456000|E7C526499308841A4A6D116C857DB669|/",
                "a.iso",
                "/tmp",
                0,
                4,
            )
            .expect("insert");
            conn.execute(
                "UPDATE downloads SET size_total = ?1, status = 'downloading', ed2k_hash = ?2 WHERE id = ?3",
                rusqlite::params![size as i64, "e7c526499308841a4a6d116c857db669", id],
            )
            .expect("set");
            id
        };
        let live = Arc::new(LiveState::default());
        // 只提供逐 part 状态（0=pending,1=active,2=done,3=checking）
        *live.p2p.lock().unwrap() = Some(aidm_ipc::P2pView {
            phase: "downloading".into(),
            known_sources: 0,
            active_peers: 0,
            transferring_peers: 0,
            queued_peers: 0,
            max_connections: 4,
            queue_rank: None,
            verified_parts: Some(1),
            total_parts: 2,
            slices: Some(vec![2, 1]),
            ..Default::default()
        });
        mgr.tasks.lock().unwrap().insert(
            id,
            TaskHandle {
                cancel: Arc::new(AtomicBool::new(false)),
                pause: Arc::new(AtomicBool::new(false)),
                stop: Arc::new(AtomicBool::new(false)),
                live,
                worker: None,
                retune: Arc::new(RetuneCell::default()),
                bt_selection: Arc::new(Mutex::new(crate::bt::BtSelection::default())),
            },
        );

        let view = mgr.unified_summary(id).expect("summary");
        assert_eq!(view.slices.len(), 2);
        assert_eq!(view.slices[0].state, "done", "part0 已校验完成");
        assert_eq!(
            view.progress.verified_unique_bytes,
            PARTSIZE.to_string(),
            "覆盖来自可信 part 状态"
        );
        assert!(
            view.slices.iter().all(|s| s.assignments.is_empty()),
            "没有对端地址就不能编造通路"
        );
        assert_eq!(view.counts.known_sources, 0, "不得按 part 数推算源数");
    }
}

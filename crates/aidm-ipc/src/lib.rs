//! AIDM 进程间契约（协议 v1，开发文档 §2 / §6 / §9）。
//!
//! 两个通道：
//! - UI / 扩展宿主 -> 引擎：回环 TCP 上的**单行 JSON**（本 crate 定义请求/响应/推送类型 +
//!   客户端辅助）；引擎侧 `aidm-engine::server` 实现分发。
//! - 扩展 <-> 宿主（Chrome/Edge native messaging）：**4 字节本地字节序 u32 长度 + UTF-8 JSON**
//!   （**不是**单行 JSON；见 [`framing`]）。宿主 → 扩展单条上限 1 MiB。
//!   类型：`ExtRequest` / `ExtResponse`，由 `aidm-ext-host` 解析后转发给引擎。
//!
//! 引擎请求（短连接，一行请求一行响应）：
//! - `ping` / `add` / `offer` / `status` / `list` / `cancel` / `pause` / `resume` / `restart` / `rename`
//! - `add` 可选 `referrer`（兼容旧字段 `referer`）/ `filename` / `cookies`（仅内存，作 Cookie 头）
//!   / `offer_id`（从内存 offer 补 cookies）/ `source`（`ext`|`manual`）
//!   / `start`（`now`|`queue`，缺省 `now`）
//! - （已移除）任务优先级：排队顺序固定按入队顺序（id）。
//!   没有"上移/下移"这类手动顺序，避免两套权威互相覆盖（见 `model::dispatch_order`）。
//! - `retry_failed {}` → `{ok, count}`（全部 error 重新入队）
//! - `sched_status` → `{ok, next_start_at, queued, active}`（`next_start_at` 为 unix 毫秒或 null）
//! - 宿主 URL scheme 白名单为 http/https/ftp（§6）。引擎尚未实现 FTP：`add` 对 `ftp://`
//!   回 `{ok:false, error:"unsupported_scheme"}`，宿主原样透传 `{ok:false, code:"unsupported_scheme"}`
//!   供扩展回退浏览器下载。file/javascript 等仍是 `bad_url`。
//! - `add` 的 `offer_id` 未知或已过期 → **`{ok:false, code:"offer_expired"}`**
//!   （`code` 字段，不是 `error` 文本）。宿主原样透传该 `code`。
//! - `restart {id}` → 若在跑则停掉；删全部 segments 行与 `.aidm/<id>/` part；
//!   清空 ETag / Last-Modified / size / error 字段；同一 id 回到 `queued`
//!   （调度器按闸门立即或排队再拉起）。
//! - `rename {id, filename}` → 改目标文件名。未完成（queued / connecting /
//!   downloading / verifying / paused / error / interrupted 重入队）只改 DB
//!   目标名，`TaskView.name` 与 `save_path` 立即反映新名，**不**移动
//!   `.aidm/<id>/` 下的 part；下载结束 / 合并时按新名写最终文件。
//!   已完成（`done`）先改磁盘最终文件再改 DB；目标已存在 →
//!   `{ok:false, code:"name_taken"}`。空名、长度超过 [`LIMIT_FILENAME`]、
//!   含路径分隔符（`/`、`\\`）或 `..` → `{ok:false, code:"invalid_filename"}`。
//!   扩展名变更由 UI 确认后再调用，引擎不再提示。成功 `{ok:true, task}`。
//!   未知 id 同现有 `task_not_found`。
//! - `offer` → `{ok, offer_id, truncated?}`；无 `subscribe` 订阅方则 `ui_not_running`
//! - `settings_get` → `{ok, settings}`（§9 全部键；`proxy.pass` 不回传，改 `proxy.has_password`）
//! - `settings_set {key, value}` → 校验失败不落库。
//!   `proxy.pass`：`value:""` 清除已存密码；不发送该键则密码不变。
//!   数值越界：`{ok:false, code:"invalid_value", key, min, max}`；
//!   非法 cron：`{ok:false, code:"invalid_cron", key}`；
//!   不在声明表里：`{ok:false, code:"unknown_setting_key"}`（没有"未列出的键就放行"）。
//! - `settings_schema` → `{ok, schema:[…]}`：设置项声明表（键/类型/区间/分组/生效方式），
//!   UI 据此渲染与本地校验，不再维护第二套硬编码范围。
//! - `host_conns_list` / `host_conns_set` / `host_conns_remove`：按服务器覆盖设置。
//!   范围：`conn.global_conn_cap` 1–1024、`conn.retry_max` 0–20、
//!   `conn.retry_backoff_ms` 100–60000；每服务器连接数例外 1–1024。
//!   **每任务连接数不设限**（没有 `conn.max_conns_per_task` 这个键）：任务默认
//!   0 = 不限，由分段数 / 候选源数收窄，唯一的硬约束是全局闸门。
//! - `system_proxy_get` → `{ok, system_proxy: {host,port}|null}`（只读，不改系统代理）
//! - `delete {ids, delete_files}` → 批删；始终清 `.aidm` part 与 DB 行
//! - `host_status` → `{ok, registered}`（当前用户是否已登记 `com.aidm.host`）
//! - `host_register {register:bool}` → 只写 HKCU NativeMessagingHosts（永不写浏览器策略键）
//! - `update_check` → 立即 `{ok}`，后台拉 `{manifest_base}/{channel}/version.json`；
//!   进度走 `event:"update"`。`settings_get` 含只读 `app.version`（当前 crate 版本）。
//! - `update_download_apply` → 立即 `{ok}`（无可用更新则 `{ok:false, code:"update_failed"}`），
//!   下载到临时目录、SHA256 必须匹配后调用 MSI 替换；失败不改动已安装版本。
//!   签名字段可选，本里程碑钩子占位、不强制验签。无私有仓鉴权、无客户端 git pull。
//! - `subscribe` → 先回 `{ok}`，随后同一连接推送 `EngineEvent` 行（无读超时）
//!
//! 更新设置（SQLite `settings`，与其它 §9 键相同）：
//! - `update.channel`：`stable` | `beta`，默认 `stable`
//! - `update.auto_check`：bool 字符串，默认 `true`（启动约 24h 后周期检查）
//! - `update.last_check_at`：unix 毫秒字符串，引擎在检查后写入；`settings_set` 只读
//! - `update.manifest_base_url`：可选；空则用环境变量 `AIDM_UPDATE_MANIFEST_BASE_URL`，
//!   再退回占位默认 `https://releases.aidm.dev/app`（生产请改为真实 Release 根）
//!
//! 引擎推送（`{"event":"stats"|"task_completed"|"heartbeat"|"candidates"|"sched"|"update", ...}`）：
//! - `stats {total_speed, active_conns, speed_limit}`：有活跃任务时每秒一次；
//!   全部空闲时再推一条全 0 后停止。
//!   **单位：`total_speed` 与 `speed_limit` 均为字节/秒（B/s）**；`speed_limit=0` 表示不限。
//!   设置键 `speed.global_limit_kbps` 仍为 KiB/s（1 KiB = 1024 B），引擎换算为 B/s 后写入 `stats.speed_limit`。
//! - `task_completed {id, file_path, dir}`：引擎在完成时必推，UI 决定是否通知
//! - `candidates {offer_id, page_url, title, items, truncated?}`：页面收集结果，**不含 cookies**
//! - `heartbeat`：`subscribe` 连接上即使空闲也每 15 秒推一次，供客户端发现引擎已死
//! - `sched {next_start_at, queued, active}`：队列计数 / 下次 cron 变化时推送
//! - `update {phase, current_version?, version?, notes?, url?, bytes_done?, bytes_total?, error?, code?}`
//!   `phase`：`checking` | `available` | `up_to_date` | `downloading` | `verifying` |
//!   `applying` | `done` | `error`。`current_version` 为当前应用版本。
//!   失败 `code`（与 UI 文案对齐）：`network`（检查/下载连不上更新服务器）、
//!   `check_failed`（清单无效等）、`checksum_mismatch`（SHA256 不符，未安装）、
//!   `update_failed`（其它下载/应用失败）
//!
//! `subscribe` 长连接：握手后服务端与 `engine_subscribe` 客户端均**不设读超时**，
//! 靠 `heartbeat` 探活，而不是 socket deadline。
//!
//! 边界：引擎进程独占全部 HTTP 网络 IO；UI 与 ext-host 只做回环 IPC。
//! cookies 只存在于引擎内存，不进 SQLite / 日志 / `TaskView`。
//!
//! `TaskView` 失败字段：
//! - `error`：人类可读说明（始终给 UI 展示）。
//! - `error_code`：机器码；可为空（对端未提供时省略）。取值：
//!   `network`（断网/DNS/复位/超时且重试用尽）、`disk_full`、`no_permission`、
//!   `remote_changed`（ETag / Last-Modified / 大小不一致）、
//!   `http_401` / `http_403` / `http_404` / `http_4xx` / `http_5xx`、
//!   `unsupported_scheme`、`interrupted`（引擎崩溃重启后，原 running 任务
//!   **重新入队 `queued`，不是 failed**）。
//! - `http_status`：所有 `http_*` 码必带；其它码省略。

mod framing;
mod validate;
mod unified;

pub use unified::*;

pub use framing::{
    encode_nmh_message, read_nmh_message, write_nmh_message, NmhError, NMH_MAX_EXT_TO_HOST,
    NMH_MAX_HOST_TO_EXT,
};
pub use validate::{
    is_bittorrent_url, is_devtool_spec, is_ftp_url, is_magnet_url, is_s3_url, is_torrent_url,
    is_valid_rename_filename, scheme_allowed, truncate_offer_items, validate_add_fields,
    validate_alt_urls, validate_cookies, validate_filename, validate_referrer, validate_url,
    FieldError,
};

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u32 = 1;

/// `subscribe` 连接上 `heartbeat` 的间隔（秒）。
pub const SUBSCRIBE_HEARTBEAT_SECS: u64 = 15;

/// Chrome / Edge native messaging host 名。
pub const HOST_NAME: &str = "com.aidm.host";

/// §9 `browser.allowed_ext_ids` 的默认扩展 ID（已打包的 Chrome/Edge MV3 扩展）。
/// Chrome/Edge 扩展 ID 为 32 位 a-p 字符。
pub const AIDM_EXT_ID: &str = "npapgdblbbcppnbmhgdnmdbggfdnpahg";

/// offer 在引擎内存中的存活时间。
pub const OFFER_TTL_SECS: u64 = 10 * 60;

pub const LIMIT_URL: usize = 8 * 1024;
pub const LIMIT_REFERRER: usize = 8 * 1024;
pub const LIMIT_COOKIES: usize = 16 * 1024;
pub const LIMIT_FILENAME: usize = 255;
pub const LIMIT_OFFER_ITEMS: usize = 500;

/// 引擎 `add` 拒绝尚未实现的 scheme（目前：`ftp://`）。宿主透传为 `code`。
pub const ERR_UNSUPPORTED_SCHEME: &str = "unsupported_scheme";

/// `TaskView.error_code` 机器码。
pub const ERR_NETWORK: &str = "network";
/// 目标域名被本机 hosts / DNS 屏蔽（解析为 `0.0.0.0` / 环回地址）。**不参与重试**。
pub const ERR_BLOCKED_BY_HOSTS: &str = "blocked_by_hosts";
pub const ERR_DISK_FULL: &str = "disk_full";
pub const ERR_NO_PERMISSION: &str = "no_permission";
pub const ERR_REMOTE_CHANGED: &str = "remote_changed";
pub const ERR_HTTP_401: &str = "http_401";
pub const ERR_HTTP_403: &str = "http_403";
pub const ERR_HTTP_404: &str = "http_404";
pub const ERR_HTTP_4XX: &str = "http_4xx";
pub const ERR_HTTP_5XX: &str = "http_5xx";
pub const ERR_INTERRUPTED: &str = "interrupted";
pub const ERR_OFFER_EXPIRED: &str = "offer_expired";
pub const ERR_INVALID_FILENAME: &str = "invalid_filename";
pub const ERR_NAME_TAKEN: &str = "name_taken";

/// 更新事件 `phase`（§10）。
pub const UPDATE_PHASE_CHECKING: &str = "checking";
pub const UPDATE_PHASE_AVAILABLE: &str = "available";
pub const UPDATE_PHASE_UP_TO_DATE: &str = "up_to_date";
pub const UPDATE_PHASE_DOWNLOADING: &str = "downloading";
pub const UPDATE_PHASE_VERIFYING: &str = "verifying";
pub const UPDATE_PHASE_APPLYING: &str = "applying";
pub const UPDATE_PHASE_DONE: &str = "done";
pub const UPDATE_PHASE_ERROR: &str = "error";

/// 更新失败 `code`（与 UI 文案对齐；`network` 复用 [`ERR_NETWORK`]）。
pub const ERR_CHECK_FAILED: &str = "check_failed";
pub const ERR_CHECKSUM_MISMATCH: &str = "checksum_mismatch";
pub const ERR_UPDATE_FAILED: &str = "update_failed";
/// 清单签名缺失/无效/不匹配：拒绝下载与安装。
pub const ERR_SIGNATURE_INVALID: &str = "signature_invalid";

/// 单段进度（§8 任务属性分段条；随 status / list 下发）。
///
/// `idx` 与 `segments.idx`（SQLite INTEGER）对齐，对外用无符号。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SegmentView {
    pub idx: u32,
    pub pos_start: u64,
    /// 未知大小时为 null（单线程尚未探明 Content-Length）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pos_end: Option<u64>,
    pub done_bytes: u64,
    /// 与 DB `segments.status` 一致：pending / running / done / error。
    pub status: String,
    /// 0 次重试省略，避免旧客户端噪声。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retries: Option<u32>,
}

/// 单条任务的对外视图（status / list 响应）。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct P2pView {
    /// discovering / connecting / queued / downloading / verifying / paused / done。
    pub phase: String,
    pub known_sources: u32,
    pub active_peers: u32,
    pub transferring_peers: u32,
    pub queued_peers: u32,
    /// 多个对端队列中最靠前的位置，不是本地任务队列位置。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue_rank: Option<u32>,
    pub max_connections: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_parts: Option<u32>,
    pub total_parts: u32,
    /// 逐切片状态（eD2k part）：0=pending，1=active，2=done，3=checking。
    /// 仅用于界面分组展示；可为空。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slices: Option<Vec<u8>>,
}

/// 任务事件视图（`task_events` 响应）。
///
/// 字段与 `events` 表的结构化列一致；`detail` 已脱敏。UI 只读，不参与判断。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskEventView {
    pub seq: i64,
    pub ts: i64,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub err_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dur_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seg: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proto: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// 单条任务的对外视图（status / list 响应）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskView {
    pub id: u64,
    pub name: String,
    pub state: String,
    /// 已完成字节
    pub done: u64,
    /// 总字节；未知为 None
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
    /// 当前速度（B/s，5s 窗口）
    pub speed: u64,
    /// 进度百分比 0..=100；总大小未知时为 None
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pct: Option<f64>,
    /// 保存位置（目录 + 文件名）
    pub save_path: String,
    /// 用户原始 URL（`url_orig`）。不用 `url_final`：CDN 终态常带过期签名。该字段可为空。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// 人类可读失败说明（`error` 状态或 `interrupted` 重入队时存在）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// 机器失败码；旧 JSON / 旧行可缺省。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// HTTP 状态；所有 `http_*` 码必带。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    /// 传输模式：multi / single（HTTP）或 ed2k（协议分片、多源协调）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// P2P 会话的真实统计；与磁盘临时文件/HTTP 分段记录独立。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p2p: Option<P2pView>,
    /// 分段条数据；无 segments 行时省略（旧客户端仍可解码）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub segments: Option<Vec<SegmentView>>,
    /// 任务来源：`ext`（扩展）或 `manual`（UI 手工）。旧行 / 旧 JSON 缺省为 None。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// 下次重试 unix 毫秒（退避中）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_at: Option<i64>,
    /// 来源网页（HTTP Referer）；未知时省略。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub referrer: Option<String>,
    /// 备用地址（镜像），每行一个；没配置镜像时省略。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alt_urls: Option<String>,
    /// 当前生效的候选序号：0 = 主地址，n = 第 n 条备用地址。没配置镜像时省略。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alt_cursor: Option<u32>,
    /// 创建时间（unix 毫秒）；旧 JSON 缺省省略。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at_ms: Option<i64>,
    /// 完成时间（unix 毫秒，仅 `done`）；旧 JSON 缺省省略。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at_ms: Option<i64>,
    /// 净下载耗时（毫秒）：只统计任务真正在跑的时间，暂停 / 排队 / 退避都不计入。
    /// 速度曲线的横轴与「用时」共用它；该字段可为空。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_ms: Option<u64>,
    /// 所属命名队列（多队列）。默认队列也会回填，界面据此显示"队列：default"。
    ///
    /// 队列只是**资源闸门**（并发/主机限/时间窗/启停）；排队顺序只看 `priority`。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue: Option<QueueRef>,
    /// 统一下载视图（`unified_download_v1`）。未协商该能力的对端不返回此字段。
    ///
    /// 新客户端优先读它，缺失时退回上文旧字段；旧客户端忽略该新增可选字段。
    /// 分页详情（源、逐切片分配）走 `task_snapshot`，不在此重复。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unified_download: Option<UnifiedDownloadView>,
}

/// BitTorrent 种子里一个文件的对外视图。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct BtFileView {
    pub index: i64,
    /// 种子内的相对路径（单文件种子就是文件名）。
    pub name: String,
    pub len: u64,
    pub selected: bool,
}

/// 任务所属队列的最小引用（避免在每条任务里重复整套队列配置）。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct QueueRef {
    pub id: i64,
    pub name: String,
}

/// UI/扩展宿主 -> 引擎 请求（§6 协议 v1 的引擎侧形状）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum EngineRequest {
    Ping,
    /// 新建下载；dir 省略时用引擎默认目录。
    ///
    /// `referrer` 为合同字段名；旧 UI 仍发 `referer`，由 alias 兼容。
    /// `cookies` 只进内存，作 HTTP Cookie 头，永不落库。
    /// 带 `offer_id` 时引擎从内存 offer 补 cookies / 缺省 referrer / filename。
    Add {
        url: String,
        #[serde(default)]
        dir: Option<String>,
        #[serde(default)]
        filename: Option<String>,
        #[serde(default, alias = "referer")]
        referrer: Option<String>,
        #[serde(default)]
        cookies: Option<String>,
        /// 浏览器发起时透传的 UA（扩展会带上 `navigator.userAgent`）。
        #[serde(default, alias = "user-agent")]
        user_agent: Option<String>,
        /// 每任务自定义请求头（`Name: value` 逐行）。
        /// 引擎会拒绝会破坏协议语义的头与含控制字符的值。
        #[serde(default, alias = "headers")]
        custom_headers: Option<String>,
        /// 备用地址（镜像）：每行一个 HTTP(S) 地址，主地址不可用时按序接管。
        /// 形状闸门见 [`validate_alt_urls`]；切换与大小对账的规则在 `aidm_core::alt`。
        #[serde(default, alias = "alt-urls", alias = "mirrors")]
        alt_urls: Option<String>,
        #[serde(default)]
        offer_id: Option<String>,
        /// `ext` | `manual`；缺省按 offer/cookies 推断，否则 manual。
        #[serde(default)]
        source: Option<String>,
        /// 任务级限速 kbps（0=不限）
        #[serde(default)]
        speed_limit_kbps: u64,
        /// `now`（缺省）立即具备调度资格；`queue` 若 cron 开启则等到下次触发。
        #[serde(default)]
        start: Option<String>,
    },
    RetryFailed,
    /// 站点凭据。
    SiteLoginsList,
    SiteLoginsSet {
        host: String,
        username: String,
        password: String,
    },
    SiteLoginsRemove {
        host: String,
    },
    SchedStatus,
    /// 页面收集：生成 `offer_id`，内存保留 [`OFFER_TTL_SECS`] 秒，并向订阅方推 `candidates`。
    Offer {
        page_url: String,
        title: String,
        items: Vec<OfferItem>,
        #[serde(default)]
        truncated: bool,
        /// 可选整页 Cookie；只进内存 offer 仓，不随 `candidates` 下发。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cookies: Option<String>,
    },
    Status {
        id: u64,
    },
    /// 任务事件（诊断用）：按时间正序返回最近 `limit` 条。
    ///
    /// 只读；`detail` 已在写入口脱敏。默认 50 条，上限 200 条。
    TaskEvents {
        id: u64,
        #[serde(default)]
        limit: Option<u32>,
        /// 分页偏移（0 = 最新一页）。
        #[serde(default)]
        offset: Option<u32>,
        /// `all`（缺省）= 全部下载事件；`error` = 只保留异常。
        #[serde(default)]
        filter: Option<String>,
    },
    /// 删除某任务的全部下载日志（不可恢复）。
    TaskEventsClear {
        id: u64,
    },
    /// 统一视图分页快照（`unified_download_v1`）。
    ///
    /// 文档 10 节：`section` 缺省 `summary`；`limit` 缺省 64、合法 1..=256，
    /// 超限返回 `invalid_limit`，**不静默截断**。`cursor` 绑定
    /// `engine_instance_id + task_id + state_revision + section`，页间版本变化
    /// 返回 `snapshot_stale`。
    ///
    /// 不支持该查询的对端回 `ok=false` + `code=unsupported`，客户端据此回退到
    /// `status`，不靠超时或版本号猜测。
    TaskSnapshot {
        id: u64,
        #[serde(default)]
        section: Option<String>,
        #[serde(default)]
        cursor: Option<String>,
        #[serde(default)]
        limit: Option<u32>,
    },
    /// 查询一个地址（或一个已有任务**生效的**地址）的四层协议结论与能力上限。
    ///
    /// 二选一：给 `url` 直接解析（新建前预检，不需要落库）；给 `id` 则用该任务
    /// 已经在用的地址（`url_final` 优先于 `url_orig`）—— 这样界面看到的能力与任务
    /// 实际走的那条路径一致，不会出现"预检说能分片、实际跑的是单线程"。
    /// 两者都给时以 `id` 为准。
    ///
    /// 无法识别的地址回 `ok=false` + `code=unsupported_scheme`，不做兜底猜测。
    Capabilities {
        #[serde(default)]
        id: Option<u64>,
        #[serde(default)]
        url: Option<String>,
    },
    /// 批量创建（为 MCP 预留）：一次提交一组地址，回**逐条结果**。
    ///
    /// 为什么不是"全成功或全失败"：批量导入的实际来源是剪贴板或清单文件，
    /// 里面混着重复链接、不支持的 scheme 是常态。整批回滚会让用户一条都建不上，
    /// 而逐条结果能告诉他"哪几条没进去、为什么"（`duplicate_skipped:12` /
    /// `unsupported_scheme` …）。
    ///
    /// 目录与来源标记按**批**共用，不逐条给：真实批量导入几乎总是"同一批、
    /// 同一去处"，逐条字段只会让契约膨胀。
    AddBatch {
        urls: Vec<String>,
        #[serde(default)]
        dir: Option<String>,
        #[serde(default)]
        source: Option<String>,
    },
    /// 导出脱敏诊断包（为 MCP 预留）：**同步**执行，因为调用方要拿路径。
    ///
    /// 与 CLI 的 `aidm-engine diag export` **共用同一条实现**
    /// （`aidm_core::diag::export_task_bundle`）—— 脱敏规则只能有一处，
    /// 两份实现必然漂移，而漂移的诊断包会把本该脱敏的东西发出去。
    DiagExport {
        /// 任务 id；给 `None` 表示不针对具体任务。
        #[serde(default)]
        id: Option<u64>,
        /// 输出目录；`None` 用引擎默认目录。
        #[serde(default)]
        dir: Option<String>,
    },
    List,
    /// 协作式取消：停止下载、删除未完成文件与任务记录。
    Cancel {
        id: u64,
    },
    /// 暂停：关闭连接保留已写文件（total 已知时可续传）。
    Pause {
        id: u64,
    },
    /// 恢复：已完成段跳过；ETag/Last-Modified 变化则拒绝续传并从头。
    Resume {
        id: u64,
    },
    /// 同一任务 id 从头再来：停下载、清分段与 `.aidm/<id>/`、清校验/错误后入队。
    Restart {
        id: u64,
    },
    /// 为 eD2k 任务查找 HTTP 镜像（当前实现查 archive.org）。
    Ed2kHttpSources {
        id: i64,
    },
    /// 把 eD2k 任务切换到 HTTP 源；保留 eD2k 哈希，完成后按哈希验收。
    Ed2kSwitchHttp {
        id: i64,
        url: String,
    },
    /// 改目标文件名。未完成只改 DB；`done` 先改磁盘最终文件再改 DB。
    Rename {
        id: u64,
        filename: String,
    },
    /// 「在磁盘上查找」：文件被移动/改名后，在任务的目录、分类目录与默认目录里
    /// 按「同名 + 同大小」找回它（有界遍历，不是全盘扫描）。
    /// 命中列表走 `hits`；`truncated` 为真表示到上限就停了，不能说"磁盘上没有"。
    FindFile {
        id: u64,
    },
    /// 把找到的文件重新关联到任务。
    /// 只改"任务指向哪里"，不搬动文件；大小与记录不符时拒绝（`size_mismatch`）。
    Relocate {
        id: u64,
        path: String,
    },
    /// 只读：eD2k 入站上传状态（L6）。服务未启用时 `enabled=false` 且无端口。
    Ed2kUploadStatus,
    /// 只读：全部命名队列（多队列）；默认队列恒为 id 1、不可删改。
    QueuesList,
    /// 新建命名队列。任务并发不再由队列限制；名字重复/为空报错。
    QueueCreate {
        name: String,
        #[serde(default)]
        default_dir: Option<String>,
        #[serde(default)]
        schedule_cron: Option<String>,
    },
    /// 改队列：只写给出的字段（`null`/缺省 = 不改）。默认队列不允许改名。
    QueueUpdate {
        id: i64,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        enabled: Option<bool>,
        #[serde(default)]
        default_dir: Option<String>,
        /// `""` = 清空（回到不限时）。
        #[serde(default)]
        schedule_cron: Option<String>,
    },
    /// 删队列：其任务**迁入默认队列**（不删任务），队列项一并删除。默认队列不可删。
    QueueDelete {
        id: i64,
    },
    /// 只读：BitTorrent 逐文件选择（文件表 + 已选标记）。
    BtFiles {
        id: u64,
    },
    /// 设置逐文件选择：落库并让运行中的任务下一拍生效（不重启任务）。
    BtSetFiles {
        id: u64,
        indices: Vec<usize>,
    },
    /// 把任务移到某个队列（追加到该队列末尾）。`queue` 必须是已存在的队列 id。
    TaskSetQueue {
        ids: Vec<u64>,
        queue: i64,
    },
    /// 返回全部 §9 设置（`proxy.pass` 以 `proxy.has_password` 代替）。
    SettingsGet,
    /// 校验后写入单项设置；限速 / 代理立即对运行中与新建任务生效。
    /// `key=proxy.pass` 且 `value=""` 清除密码；不发送该 op 则密码不变。
    SettingsSet {
        key: String,
        value: String,
    },
    /// 只读：当前系统代理 `{host,port}`，无则为 JSON null。永不写系统代理。
    SystemProxyGet,
    /// 只读：设置项声明表（键/默认值/类型/区间/分组/生效方式），
    /// 让 UI 通用渲染而不是硬编码键名。
    SettingsSchema,
    /// 按服务器覆盖设置。
    HostConnsList,
    HostConnsSet {
        host: String,
        /// `null` = 不覆盖
        #[serde(default)]
        max_conns: Option<i64>,
        #[serde(default)]
        speed_limit_kbps: Option<i64>,
    },
    HostConnsRemove {
        host: String,
    },
    /// 批量删除：始终移除 `.aidm` part 目录与 DB 行；`delete_files` 时再删最终文件。
    Delete {
        ids: Vec<u64>,
        #[serde(default)]
        delete_files: bool,
    },
    /// 长连接订阅推送：先回 `{ok:true}`，随后写 `EngineEvent` 行。
    Subscribe,
    /// 引擎进程正常退出（托盘「完全退出」）：先回 `{ok:true}`，随后退出进程。
    Shutdown,
    /// 当前用户是否已登记原生消息宿主（HKCU / 用户配置目录）。
    HostStatus,
    /// `register=true` 写 manifest + HKCU Chrome/Edge NativeMessagingHosts；
    /// `register=false` 撤销。永不写浏览器策略键。
    HostRegister {
        register: bool,
    },
    /// 开始检查更新；立即 `{ok}`，进度走 [`EngineEvent::Update`]。
    UpdateCheck,
    /// 下载 + SHA256 + 应用已检查到的更新；立即 `{ok}`（无可用更新则失败）。
    UpdateDownloadApply,
    /// 刷新 Kad bootstrap 节点列表（`nodes.dat`）：取回 → 校验 → 落库。
    /// 回包 `nodes` 是落库的节点数；失败时 `code` 是 `nodes_dat_*` 稳定错误码。
    Ed2kNodesRefresh,
    /// 刷新公共 eD2k 服务器列表（`server.met`）：取回 → 解析 → 写回 `ed2k.servers`。
    /// 回包 `servers` 是写入的端点数；失败时 `code` 是 `server_met_*`。
    Ed2kServersRefresh,
}

/// 引擎 -> 请求方 响应。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EngineResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task: Option<TaskView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tasks: Option<Vec<TaskView>>,
    /// `task_events`：当前页事件（按时间倒序，最新在前）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_events: Option<Vec<TaskEventView>>,
    /// `task_events`：同一筛选条件下的总条数（分页标题与“是否还有更多”用）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_events_total: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// `settings_get`：键值表。`proxy.has_password` 为 JSON bool，其余为字符串。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<serde_json::Map<String, serde_json::Value>>,
    /// `system_proxy_get`：对象或 JSON `null`。
    /// 显式 `null` 反序列化为 `Some(Null)`，与字段缺省的 `None` 区分。
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_value"
    )]
    pub system_proxy: Option<serde_json::Value>,
    /// `settings_schema`：设置项声明表（键/类型/区间/分组/生效方式）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<serde_json::Value>,
    /// `host_conns_*`：按服务器覆盖项列表。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosts: Option<serde_json::Value>,
    /// `site_logins_*`：站点凭据列表（**含用户名，不含密码**）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logins: Option<serde_json::Value>,
    /// `offer`：引擎生成的内存 id。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offer_id: Option<String>,
    /// `offer`：条目超过 [`LIMIT_OFFER_ITEMS`] 时为 true。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub truncated: Option<bool>,
    /// `host_status`：当前用户是否已登记 `com.aidm.host`。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered: Option<bool>,
    /// `retry_failed` 重新入队条数。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,
    /// `ed2k_nodes_refresh`：落库的 Kad bootstrap 节点数。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nodes: Option<u64>,
    /// `ed2k_servers_refresh`：写回 `ed2k.servers` 的端点数。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub servers: Option<u64>,
    /// `ed2k_http_sources`：HTTP 候选列表（archive.org 等）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_sources: Option<serde_json::Value>,
    /// `sched_status`：下次 cron 触发 unix 毫秒；无 cron 时为 JSON null。
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_value"
    )]
    pub next_start_at: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queued: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<u64>,
    /// `settings_set` 结构化错误码：`invalid_value` / `invalid_cron` / 其它。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<i64>,
    /// `find_file`：命中列表（同名同大小）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hits: Option<Vec<FindHit>>,
    /// `ed2k_upload_status`：入站上传状态。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ed2k_upload: Option<Ed2kUploadStatus>,
    /// `queues_list` / `queue_create` / `queue_update`：队列列表（含计数）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queues: Option<Vec<QueueView>>,
    /// `task_set_queue`：实际移动的任务数（未知 id 会跳过而不是整体失败）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub moved: Option<u64>,
    /// `bt_files` / `bt_set_files`：该种子的文件表（含已选标记）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bt_files: Option<Vec<BtFileView>>,
    /// `capabilities`：该地址的四层结论 + 协议允许的能力上限。
    ///
    /// 地址无法识别（既不是已知传输协议，也没有已知封装）时引擎回
    /// `ok=false` + `code=unsupported_scheme`，**不给兜底协议** ——
    /// 猜一个协议出来只会把失败推后到下载时。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<CapabilityView>,
    /// `add_batch`：逐条结果，顺序与请求里的 `urls` 一致。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub added: Option<Vec<BatchAddResult>>,
    /// `diag_export`：诊断包落盘路径。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diag_path: Option<String>,
    /// `task_snapshot`：统一视图分页快照。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<UnifiedSnapshotResponse>,
    /// `ping`：引擎支持的 IPC 功能标识列表（如 `unified_download_v1`）。
    ///
    /// 该字段缺失表示对端不支持统一视图，客户端据此回退基础展示，
    /// **不**用超时或版本号猜测。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub features: Option<Vec<String>>,
    /// `subscribe`：引擎实际接受的功能子集。请求未声明时缺省。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_features: Option<Vec<String>>,
}

/// 命名队列的对外视图（多队列）。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct QueueView {
    pub id: i64,
    pub name: String,
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule_cron: Option<String>,
    /// 默认队列不可删除、不可改名（界面据此禁用入口）。
    pub is_default: bool,
    pub queued: i64,
    pub running: i64,
    pub done: i64,
    pub failed: i64,
    pub paused: i64,
}

/// eD2k 入站上传服务的对外状态（L6）。
///
/// `listening_port` 是**实际**端口：`ed2k.listen_port = 0` 时这里看到的是系统分配的端口。
/// `uploaded_bytes` 是本次引擎进程启动以来经上传发出的字节，不是信用表里的历史累计。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ed2kUploadStatus {
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listening_port: Option<u16>,
    pub active_sessions: u32,
    pub queued_sessions: u32,
    pub connections: u32,
    pub uploaded_bytes: u64,
    pub served_blocks: u64,
    pub rejected_blocks: u64,
    pub shared_files: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// 「在磁盘上查找」的一个命中（`find_file`）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindHit {
    /// 完整路径（宿主直接展示，也可能交给 `open_path`）。
    pub path: String,
    pub size: u64,
    /// 修改时间 unix 秒；取不到为 0。
    #[serde(default)]
    pub modified: i64,
}

/// 协议允许的**能力上限**（`capabilities` 查询的结果的一部分）。
///
/// ⚠️ 这是**上限**，不是"这个任务现在真的能这么做"。例如 HTTP 的 `segment`
/// 表示"协议允许分片"，而服务端是否真支持要看运行时探测到没到 `206` /
/// `Accept-Ranges`。**调用方拿它控制界面时，必须先用探测结果收窄一次**，
/// 不能把 `true` 当作"已确认可用"。
///
/// 字段与 `aidm_core::capability::Capabilities` 一一对应，但**这里不引用 core**
/// —— 契约层刻意不依赖实现层（同 `validate.rs` 的说明）。两边漂移由
/// `aidm-engine` 的集成测试盯着。
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityFlags {
    /// 能否暂停并保住已下数据。
    pub pause: bool,
    /// 能否从断点继续。
    pub resume: bool,
    /// 能否拆成并行分片。
    pub segment: bool,
    /// 能否在已下载范围内随机定位。
    pub seek: bool,
    /// 是否存在"同一内容的多个来源"这个概念。
    pub multi_source: bool,
    /// 是否需要先解析一份清单文档。
    pub manifest: bool,
    /// 能否做端到端完整性校验。
    pub verify: bool,
    /// 完成后能否继续为别人提供数据（做种）。
    pub seed: bool,
}

/// `capabilities` 查询的**四层结论**：同一个"支持"往往是四种不同的东西，
/// 分开表达才不会把"能识别"谎报成"能下载"。
///
/// - `transport`：怎么取字节（`http` / `https` / `ftp` / `ftps` / `sftp` /
///   `bittorrent` / `ed2k` / `quic`）
/// - `resource`：取到的是不是一个完整文件（`plain_file` / `webdav` /
///   `s3_object` / `hls` / `dash`）
/// - `manifest`：需要先解析才知道下什么（`metalink` / `m3u8` / `mpd` /
///   `zsync` / `torrent`），不需要时为 `None`
/// - `wrapper`：只是外壳，剥掉后是别的协议；值为外部 scheme 名，
///   非封装地址为 `None`
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityView {
    pub transport: String,
    pub resource: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrapper: Option<String>,
    pub capabilities: CapabilityFlags,
    /// 解释性备注。**必须带上**：像网盘资源标识这类封装能识别、能给出传输层
    /// 结论，但服务已停运、其实下不了 —— 这个事实没有别的字段能承载，
    /// 丢掉它等于把不可用谎报成可用。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// `add_batch` 逐条结果：成功给 `id`，失败给稳定 `code`。
///
/// 两项**恰好有一个**非空。调用方按 `code` 分支，不要去解析人话文本。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct BatchAddResult {
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
    /// 失败原因，例如 `duplicate_skipped:12` / `unsupported_scheme` /
    /// `invalid_url`。与 `EngineResponse.code` 同一套码。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

fn deserialize_present_value<'de, D>(deserializer: D) -> Result<Option<serde_json::Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Some(serde_json::Value::deserialize(deserializer)?))
}

/// 引擎 -> 订阅方 推送事件（每行一个 JSON，与响应区分用 `event` 字段）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum EngineEvent {
    /// 总速度与限速均为 **B/s**（字节/秒）。`speed_limit == 0` 表示不限。
    Stats {
        total_speed: u64,
        active_conns: u64,
        speed_limit: u64,
    },
    TaskCompleted {
        id: u64,
        file_path: String,
        dir: String,
        /// 这次下载从哪来（`"ext"` = 浏览器扩展接管，`"manual"` = 手动/剪贴板…）。
        ///
        /// UI 靠它决定提示落在哪里：网页里点出来的在网页内提示，剪贴板来的走系统
        /// 通知。`default` 让不含该字段的旧消息仍能解析。
        #[serde(default)]
        source: String,
    },
    /// 空闲时也每 [`SUBSCRIBE_HEARTBEAT_SECS`] 秒推一次。
    Heartbeat,
    /// 扩展页面收集；**不含 cookies**。
    Candidates {
        offer_id: String,
        page_url: String,
        title: String,
        items: Vec<OfferItem>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        truncated: Option<bool>,
    },
    /// 队列快照变化时推送。`next_start_at` 无 cron 时为 JSON null。
    Sched {
        next_start_at: Option<i64>,
        queued: u64,
        active: u64,
    },
    /// 应用内更新（§10）。失败时 `phase=error` 且带 `code` / `error`。
    Update {
        phase: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        current_version: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        version: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        notes: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        url: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bytes_done: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bytes_total: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        code: Option<String>,
    },
    /// 设置被改动：`revision` 变化即代表"需要重读设置"。不含任何密值。
    SettingsChanged { key: String, revision: u64 },
    /// 队列跑完后应当执行的动作（退出 / 关机 / 休眠 / 待机 / 断开拨号）。
    ///
    /// **引擎只负责判定与广播，不动电源**：后台下载器不该持有
    /// `SeShutdownPrivilege`。真正执行由 UI 层做。
    AfterDone { action: String, force: bool },
    /// 流量配额到达上限。
    Quota {
        used_bytes: u64,
        limit_bytes: u64,
        period: String,
        action: String,
    },
}

impl EngineResponse {
    pub fn ok() -> Self {
        Self {
            ok: true,
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            id: None,
            task: None,
            tasks: None,
            task_events: None,
            task_events_total: None,
            error: None,
            settings: None,
            system_proxy: None,
            schema: None,
            hosts: None,
            logins: None,
            offer_id: None,
            truncated: None,
            registered: None,
            count: None,
            nodes: None,
            servers: None,
            http_sources: None,
            next_start_at: None,
            queued: None,
            active: None,
            code: None,
            key: None,
            min: None,
            max: None,
            hits: None,
            ed2k_upload: None,
            queues: None,
            moved: None,
            bt_files: None,
            capabilities: None,
            added: None,
            diag_path: None,
            snapshot: None,
            features: None,
            accepted_features: None,
        }
    }

    /// 结构化失败：只填 `code`（如 `offer_expired`），不把码写进 `error`。
    pub fn err_code(code: impl Into<String>) -> Self {
        let mut r = Self::err("");
        let code = code.into();
        r.error = None;
        r.code = Some(code);
        r
    }

    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            id: None,
            task: None,
            tasks: None,
            task_events: None,
            task_events_total: None,
            error: Some(msg.into()),
            settings: None,
            system_proxy: None,
            schema: None,
            hosts: None,
            logins: None,
            offer_id: None,
            truncated: None,
            registered: None,
            count: None,
            nodes: None,
            servers: None,
            http_sources: None,
            next_start_at: None,
            queued: None,
            active: None,
            code: None,
            key: None,
            min: None,
            max: None,
            hits: None,
            ed2k_upload: None,
            queues: None,
            moved: None,
            bt_files: None,
            capabilities: None,
            added: None,
            diag_path: None,
            snapshot: None,
            features: None,
            accepted_features: None,
        }
    }
}

/// 页面收集条目（扩展 `offer` / 引擎 `candidates` 共用）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OfferItem {
    pub url: String,
    pub kind: OfferKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
}

/// `offer.items[].kind`：`link` | `video` | `audio`。
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OfferKind {
    Link,
    Video,
    Audio,
}

/// 扩展 -> 宿主 请求（§6 协议 v1）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ExtRequest {
    Ping,
    Add {
        url: String,
        #[serde(default, alias = "referer")]
        referrer: Option<String>,
        #[serde(default)]
        filename: Option<String>,
        #[serde(default)]
        cookies: Option<String>,
        /// 浏览器自己的 UA：透传浏览器的 User-Agent，缺省则用设置里的 UA。
        #[serde(default, alias = "user-agent")]
        user_agent: Option<String>,
        /// 扩展抓到的请求头块（`Name: value` 逐行），采集后原样重放。
        #[serde(default, alias = "headers")]
        custom_headers: Option<String>,
    },
    Offer {
        page_url: String,
        title: String,
        items: Vec<OfferItem>,
    },
    /// 引擎是否在线 + 活跃任务数（不是单任务 status）。
    Status,
    List,
    /// 只读：与浏览器接管相关的设置子集（永不回传代理密码等敏感项）。
    Settings,
    /// 唤起桌面 UI：找到主窗口就置顶，没在运行就启动。不携带任何参数。
    ShowUi,
}

/// 宿主 -> 扩展 响应。
///
/// 成功 `{ok:true, ...}`；失败 `{ok:false, code}`。
/// `code`：`not_allowed` / `bad_url` / `too_long` / `disabled` /
/// `engine_unreachable` / `ui_not_running` / `unsupported_scheme`
/// （以及引擎透传的 `offer_expired`）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExtResponse {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offer_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub truncated: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine_online: Option<bool>,
    /// 活跃任务数（queued/connecting/downloading/verifying）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tasks: Option<Vec<TaskView>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// settings op：与浏览器接管相关的设置子集。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<serde_json::Map<String, serde_json::Value>>,
}

impl ExtResponse {
    pub fn ok() -> Self {
        Self {
            ok: true,
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            id: None,
            offer_id: None,
            truncated: None,
            engine_online: None,
            active: None,
            tasks: None,
            code: None,
            settings: None,
        }
    }

    pub fn err(code: impl Into<String>) -> Self {
        Self {
            ok: false,
            version: None,
            id: None,
            offer_id: None,
            truncated: None,
            engine_online: None,
            active: None,
            tasks: None,
            code: Some(code.into()),
            settings: None,
        }
    }
}

/// 解析一行来自扩展的请求（失败即协议错误）。
pub fn parse_ext_request(line: &str) -> Result<ExtRequest, serde_json::Error> {
    serde_json::from_str(line)
}

/// 向引擎发送单个请求并读取一行响应（回环 TCP，短连接，足够本用途）。
pub fn engine_roundtrip(
    port: u16,
    req: &EngineRequest,
    timeout: Duration,
) -> Result<EngineResponse, String> {
    let addr = format!("127.0.0.1:{port}");
    let mut stream = TcpStream::connect(addr).map_err(|e| format!("connect engine: {e}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|_| stream.set_write_timeout(Some(timeout)))
        .map_err(|e| format!("set timeout: {e}"))?;
    let mut line = serde_json::to_string(req).map_err(|e| e.to_string())?;
    line.push('\n');
    stream
        .write_all(line.as_bytes())
        .map_err(|e| format!("send: {e}"))?;
    let mut reader = BufReader::new(stream);
    let mut buf = String::new();
    reader
        .read_line(&mut buf)
        .map_err(|e| format!("recv: {e}"))?;
    serde_json::from_str(&buf).map_err(|e| format!("decode: {e}"))
}

/// 订阅引擎推送：`handshake_timeout` 仅用于连接与 `{ok}` 握手。
/// 握手成功后**清除读/写超时**，长连接靠服务端 `heartbeat` 探活。
pub fn engine_subscribe(
    port: u16,
    handshake_timeout: Duration,
) -> Result<EventSubscription, String> {
    let addr = format!("127.0.0.1:{port}");
    let mut stream = TcpStream::connect(addr).map_err(|e| format!("connect engine: {e}"))?;
    stream
        .set_read_timeout(Some(handshake_timeout))
        .and_then(|_| stream.set_write_timeout(Some(handshake_timeout)))
        .map_err(|e| format!("set timeout: {e}"))?;
    let mut line = serde_json::to_string(&EngineRequest::Subscribe).map_err(|e| e.to_string())?;
    line.push('\n');
    stream
        .write_all(line.as_bytes())
        .map_err(|e| format!("send: {e}"))?;
    let mut reader = BufReader::new(stream);
    let mut buf = String::new();
    reader
        .read_line(&mut buf)
        .map_err(|e| format!("recv: {e}"))?;
    let resp: EngineResponse = serde_json::from_str(&buf).map_err(|e| format!("decode: {e}"))?;
    if !resp.ok {
        return Err(resp.error.unwrap_or_else(|| "subscribe_failed".into()));
    }
    let stream = reader.get_ref();
    stream
        .set_read_timeout(None)
        .and_then(|_| stream.set_write_timeout(None))
        .map_err(|e| format!("clear timeout: {e}"))?;
    Ok(EventSubscription { reader })
}

/// `subscribe` 之后的事件流（默认无读超时）。
pub struct EventSubscription {
    reader: BufReader<TcpStream>,
}

impl EventSubscription {
    /// 测试用：给后续 `read_event` 设/清超时。生产路径保持 `None`。
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<(), String> {
        self.reader
            .get_ref()
            .set_read_timeout(timeout)
            .map_err(|e| format!("set read timeout: {e}"))
    }

    pub fn read_event(&mut self) -> Result<EngineEvent, String> {
        let mut buf = String::new();
        self.reader
            .read_line(&mut buf)
            .map_err(|e| format!("recv event: {e}"))?;
        if buf.trim().is_empty() {
            return Err("event_eof".into());
        }
        serde_json::from_str(buf.trim()).map_err(|e| format!("decode event: {e}"))
    }
}

/// 引擎端口文件名（位于应用数据目录）。
pub const PORT_FILE: &str = "engine.port";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_roundtrip() {
        let req: ExtRequest = parse_ext_request(r#"{"v":1,"op":"ping"}"#).unwrap();
        assert_eq!(req, ExtRequest::Ping);
    }

    #[test]
    fn show_ui_roundtrip() {
        // 悬浮圆钮点击：扩展 → 宿主的「唤起主程序」请求，不携带任何参数。
        let req = parse_ext_request(r#"{"v":1,"op":"show_ui"}"#).unwrap();
        assert_eq!(req, ExtRequest::ShowUi);
    }

    #[test]
    fn add_with_optional_fields() {
        let req = parse_ext_request(r#"{"v":1,"op":"add","url":"https://x/y.zip"}"#).unwrap();
        assert_eq!(
            req,
            ExtRequest::Add {
                url: "https://x/y.zip".into(),
                referrer: None,
                filename: None,
                cookies: None,
                user_agent: None,
                custom_headers: None
            }
        );
        let old = parse_ext_request(
            r#"{"v":1,"op":"add","url":"https://x/y.zip","referer":"https://r/"}"#,
        )
        .unwrap();
        assert_eq!(
            old,
            ExtRequest::Add {
                url: "https://x/y.zip".into(),
                referrer: Some("https://r/".into()),
                filename: None,
                cookies: None,
                user_agent: None,
                custom_headers: None
            }
        );
    }

    #[test]
    fn engine_request_shapes() {
        // v1 JSON 形状（§6）；旧字段 referer 仍可解码为 referrer
        let req: EngineRequest =
            serde_json::from_str(r#"{"v":1,"op":"add","url":"https://x/y.zip","dir":"/tmp"}"#)
                .unwrap();
        assert_eq!(
            req,
            EngineRequest::Add {
                url: "https://x/y.zip".into(),
                dir: Some("/tmp".into()),
                filename: None,
                referrer: None,
                cookies: None,
                user_agent: None,
                custom_headers: None,
                alt_urls: None,
                offer_id: None,
                source: None,
                speed_limit_kbps: 0,
                start: None
            }
        );
        let req: EngineRequest = serde_json::from_str(
            r#"{"op":"add","url":"https://x/y.zip","referer":"https://r/","cookies":"a=b"}"#,
        )
        .unwrap();
        match req {
            EngineRequest::Add {
                referrer, cookies, ..
            } => {
                assert_eq!(referrer.as_deref(), Some("https://r/"));
                assert_eq!(cookies.as_deref(), Some("a=b"));
            }
            other => panic!("{other:?}"),
        }
        let req: EngineRequest = serde_json::from_str(r#"{"op":"cancel","id":3}"#).unwrap();
        assert_eq!(req, EngineRequest::Cancel { id: 3 });
        let req: EngineRequest = serde_json::from_str(
            r#"{"op":"settings_set","key":"speed.global_limit_kbps","value":"128"}"#,
        )
        .unwrap();
        assert_eq!(
            req,
            EngineRequest::SettingsSet {
                key: "speed.global_limit_kbps".into(),
                value: "128".into()
            }
        );
        let req: EngineRequest =
            serde_json::from_str(r#"{"op":"delete","ids":[1,2],"delete_files":true}"#).unwrap();
        assert_eq!(
            req,
            EngineRequest::Delete {
                ids: vec![1, 2],
                delete_files: true
            }
        );
        let req: EngineRequest = serde_json::from_str(r#"{"op":"subscribe"}"#).unwrap();
        assert_eq!(req, EngineRequest::Subscribe);
        let req: EngineRequest = serde_json::from_str(r#"{"op":"restart","id":9}"#).unwrap();
        assert_eq!(req, EngineRequest::Restart { id: 9 });
        let req: EngineRequest =
            serde_json::from_str(r#"{"op":"rename","id":3,"filename":"new.bin"}"#).unwrap();
        assert_eq!(
            req,
            EngineRequest::Rename {
                id: 3,
                filename: "new.bin".into()
            }
        );
        let req: EngineRequest =
            serde_json::from_str(r#"{"op":"add","url":"https://x/y.zip","start":"queue"}"#)
                .unwrap();
        match req {
            EngineRequest::Add { start, .. } => assert_eq!(start.as_deref(), Some("queue")),
            other => panic!("{other:?}"),
        }
        let req: EngineRequest = serde_json::from_str(r#"{"op":"retry_failed"}"#).unwrap();
        assert_eq!(req, EngineRequest::RetryFailed);
        let req: EngineRequest = serde_json::from_str(r#"{"op":"sched_status"}"#).unwrap();
        assert_eq!(req, EngineRequest::SchedStatus);
        let req: EngineRequest = serde_json::from_str(r#"{"op":"host_status"}"#).unwrap();
        assert_eq!(req, EngineRequest::HostStatus);
        let req: EngineRequest =
            serde_json::from_str(r#"{"op":"host_register","register":true}"#).unwrap();
        assert_eq!(req, EngineRequest::HostRegister { register: true });
        let req: EngineRequest = serde_json::from_str(r#"{"op":"update_check"}"#).unwrap();
        assert_eq!(req, EngineRequest::UpdateCheck);
        let req: EngineRequest = serde_json::from_str(r#"{"op":"update_download_apply"}"#).unwrap();
        assert_eq!(req, EngineRequest::UpdateDownloadApply);
        let req: EngineRequest = serde_json::from_str(r#"{"op":"ed2k_nodes_refresh"}"#).unwrap();
        assert_eq!(req, EngineRequest::Ed2kNodesRefresh);
        let req: EngineRequest = serde_json::from_str(r#"{"op":"ed2k_servers_refresh"}"#).unwrap();
        assert_eq!(req, EngineRequest::Ed2kServersRefresh);
        let req: EngineRequest = serde_json::from_str(
            r#"{"op":"offer","page_url":"https://p/","title":"T","items":[{"url":"https://x/a","kind":"link"}]}"#,
        )
        .unwrap();
        match req {
            EngineRequest::Offer {
                items, truncated, ..
            } => {
                assert_eq!(items[0].kind, OfferKind::Link);
                assert!(!truncated);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn system_proxy_null_is_distinct_from_omitted() {
        let with_null: EngineResponse =
            serde_json::from_str(r#"{"ok":true,"system_proxy":null}"#).unwrap();
        assert_eq!(with_null.system_proxy, Some(serde_json::Value::Null));
        let omitted: EngineResponse = serde_json::from_str(r#"{"ok":true}"#).unwrap();
        assert!(omitted.system_proxy.is_none());
        let mut resp = EngineResponse::ok();
        resp.system_proxy = Some(serde_json::Value::Null);
        let wire = serde_json::to_string(&resp).unwrap();
        assert!(wire.contains("\"system_proxy\":null"));
    }

    #[test]
    fn find_file_and_relocate_ops_roundtrip() {
        let req: EngineRequest = serde_json::from_str(r#"{"op":"find_file","id":3}"#).unwrap();
        assert_eq!(req, EngineRequest::FindFile { id: 3 });
        let req: EngineRequest =
            serde_json::from_str(r#"{"op":"relocate","id":3,"path":"C:\\dl\\moved.bin"}"#).unwrap();
        assert_eq!(
            req,
            EngineRequest::Relocate {
                id: 3,
                path: "C:\\dl\\moved.bin".into()
            }
        );
        // 命中列表：显式 JSON 形状，宿主直接展示 path
        let resp: EngineResponse = serde_json::from_str(
            r#"{"ok":true,"hits":[{"path":"C:\\dl\\moved.bin","size":4096,"modified":0}],"truncated":true}"#,
        )
        .unwrap();
        assert_eq!(
            resp.hits,
            Some(vec![FindHit {
                path: "C:\\dl\\moved.bin".into(),
                size: 4096,
                modified: 0
            }])
        );
        assert_eq!(resp.truncated, Some(true));
        // 没有查找的响应不带 hits 字段（旧客户端形状不变）
        let mut plain = EngineResponse::ok();
        assert!(plain.hits.is_none());
        assert!(!serde_json::to_string(&plain).unwrap().contains("hits"));
        plain.hits = Some(Vec::new());
        assert!(serde_json::to_string(&plain)
            .unwrap()
            .contains("\"hits\":[]"));
    }

    #[test]
    fn engine_event_shapes() {
        let ev: EngineEvent = serde_json::from_str(
            r#"{"event":"stats","total_speed":100,"active_conns":2,"speed_limit":1024}"#,
        )
        .unwrap();
        assert_eq!(
            ev,
            EngineEvent::Stats {
                total_speed: 100,
                active_conns: 2,
                speed_limit: 1024
            }
        );
        let ev: EngineEvent = serde_json::from_str(
            r#"{"event":"task_completed","id":9,"file_path":"/tmp/a.bin","dir":"/tmp"}"#,
        )
        .unwrap();
        assert_eq!(
            ev,
            EngineEvent::TaskCompleted {
                id: 9,
                file_path: "/tmp/a.bin".into(),
                dir: "/tmp".into(),
                // 老引擎推的消息里没有 source：`#[serde(default)]` 兜住，解析不失败。
                source: String::new()
            }
        );
        let ev: EngineEvent = serde_json::from_str(r#"{"event":"heartbeat"}"#).unwrap();
        assert_eq!(ev, EngineEvent::Heartbeat);
        let ev: EngineEvent =
            serde_json::from_str(r#"{"event":"sched","next_start_at":null,"queued":2,"active":1}"#)
                .unwrap();
        assert_eq!(
            ev,
            EngineEvent::Sched {
                next_start_at: None,
                queued: 2,
                active: 1
            }
        );
        let ev: EngineEvent = serde_json::from_str(
            r#"{"event":"candidates","offer_id":"o1","page_url":"https://p/","title":"T","items":[{"url":"https://x/a","kind":"video"}],"truncated":true}"#,
        )
        .unwrap();
        match ev {
            EngineEvent::Candidates {
                offer_id,
                truncated,
                items,
                ..
            } => {
                assert_eq!(offer_id, "o1");
                assert_eq!(truncated, Some(true));
                assert_eq!(items[0].kind, OfferKind::Video);
            }
            other => panic!("{other:?}"),
        }
        let ev: EngineEvent = serde_json::from_str(
            r#"{"event":"update","phase":"available","current_version":"0.1.0","version":"0.2.0","notes":"n","url":"https://x/a.msi"}"#,
        )
        .unwrap();
        match ev {
            EngineEvent::Update {
                phase,
                current_version,
                version,
                notes,
                url,
                ..
            } => {
                assert_eq!(phase, UPDATE_PHASE_AVAILABLE);
                assert_eq!(current_version.as_deref(), Some("0.1.0"));
                assert_eq!(version.as_deref(), Some("0.2.0"));
                assert_eq!(notes.as_deref(), Some("n"));
                assert_eq!(url.as_deref(), Some("https://x/a.msi"));
            }
            other => panic!("{other:?}"),
        }
        let ev: EngineEvent = serde_json::from_str(
            r#"{"event":"update","phase":"error","code":"checksum_mismatch","error":"更新文件校验失败，未安装任何改动"}"#,
        )
        .unwrap();
        match ev {
            EngineEvent::Update { phase, code, .. } => {
                assert_eq!(phase, UPDATE_PHASE_ERROR);
                assert_eq!(code.as_deref(), Some(ERR_CHECKSUM_MISMATCH));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn task_view_old_json_decodes_without_segments() {
        let old = r#"{"id":1,"name":"a.bin","state":"done","done":10,"speed":0,"save_path":"/tmp/a.bin"}"#;
        let v: TaskView = serde_json::from_str(old).unwrap();
        assert!(v.segments.is_none());
        assert!(v.mode.is_none());
        assert!(v.url.is_none());
        assert!(v.source.is_none());
        assert!(v.retry_at.is_none());
        assert!(v.error_code.is_none());
        assert!(v.http_status.is_none());
        assert_eq!(v.done, 10);
    }

    #[test]
    fn task_view_error_code_and_http_status_roundtrip() {
        let view = TaskView {
            id: 1,
            name: "a.bin".into(),
            state: "error".into(),
            done: 0,
            total: None,
            speed: 0,
            pct: None,
            save_path: "/tmp/a.bin".into(),
            url: None,
            error: Some("远程返回 HTTP 404".into()),
            error_code: Some(ERR_HTTP_404.into()),
            http_status: Some(404),
            mode: None,
            p2p: None,
            segments: None,
            source: None,
            retry_at: None,
            referrer: None,
            alt_urls: None,
            alt_cursor: None,
            created_at_ms: None,
            queue: None,
            finished_at_ms: None,
            active_ms: None,
            unified_download: None,
        };
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(json["error_code"], "http_404");
        assert_eq!(json["http_status"], 404);
        assert_eq!(json["error"], "远程返回 HTTP 404");
        let back: TaskView = serde_json::from_value(json).unwrap();
        assert_eq!(back.error_code.as_deref(), Some(ERR_HTTP_404));
        assert_eq!(back.http_status, Some(404));
    }

    #[test]
    fn offer_expired_is_code_not_error_text() {
        let resp = EngineResponse::err_code(ERR_OFFER_EXPIRED);
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["ok"], false);
        assert_eq!(json["code"], "offer_expired");
        assert!(json.get("error").is_none());
        let back: EngineResponse = serde_json::from_value(json).unwrap();
        assert!(!back.ok);
        assert_eq!(back.code.as_deref(), Some(ERR_OFFER_EXPIRED));
        assert!(back.error.is_none());
    }

    #[test]
    fn task_view_segments_roundtrip_and_omit_zero_retries() {
        let view = TaskView {
            id: 3,
            name: "m.bin".into(),
            state: "downloading".into(),
            done: 100,
            total: Some(200),
            speed: 1,
            pct: Some(50.0),
            save_path: "/tmp/m.bin".into(),
            url: Some("https://x/m.bin".into()),
            error: None,
            error_code: None,
            http_status: None,
            mode: Some("multi".into()),
            p2p: None,
            source: Some("manual".into()),
            retry_at: None,
            referrer: None,
            alt_urls: None,
            alt_cursor: None,
            created_at_ms: None,
            queue: None,
            finished_at_ms: None,
            active_ms: None,
            unified_download: None,
            segments: Some(vec![
                SegmentView {
                    idx: 0,
                    pos_start: 0,
                    pos_end: Some(99),
                    done_bytes: 100,
                    status: "done".into(),
                    retries: None,
                },
                SegmentView {
                    idx: 1,
                    pos_start: 100,
                    pos_end: Some(199),
                    done_bytes: 0,
                    status: "pending".into(),
                    retries: Some(2),
                },
            ]),
        };
        let json = serde_json::to_value(&view).unwrap();
        let segs = json.get("segments").unwrap().as_array().unwrap();
        assert_eq!(segs[0]["idx"], 0);
        assert!(
            segs[0].get("retries").is_none(),
            "retries=0 must be omitted"
        );
        assert_eq!(segs[1]["retries"], 2);
        let back: TaskView = serde_json::from_value(json).unwrap();
        assert_eq!(back.segments.as_ref().unwrap()[1].idx, 1);
    }

    #[test]
    fn engine_roundtrip_over_local_server() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let t = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream);
            let mut buf = String::new();
            reader.read_line(&mut buf).unwrap();
            let resp = EngineResponse {
                ok: true,
                version: Some("t".into()),
                id: Some(7),
                task: None,
                tasks: None,
                task_events: None,
                task_events_total: None,
                error: None,
                settings: None,
                system_proxy: None,
                schema: None,
                hosts: None,
                logins: None,
                offer_id: None,
                truncated: None,
                registered: None,
                count: None,
                nodes: None,
                servers: None,
                http_sources: None,
                next_start_at: None,
                queued: None,
                active: None,
                code: None,
                key: None,
                min: None,
                max: None,
                hits: None,
                ed2k_upload: None,
                queues: None,
                moved: None,
                bt_files: None,
                capabilities: None,
                added: None,
                diag_path: None,
                snapshot: None,
                features: None,
                accepted_features: None,
            };
            let mut s = reader.get_ref().try_clone().unwrap();
            writeln!(s, "{}", serde_json::to_string(&resp).unwrap()).unwrap();
            buf
        });
        let resp = engine_roundtrip(
            port,
            &EngineRequest::Status { id: 7 },
            Duration::from_secs(2),
        )
        .unwrap();
        let received = t.join().unwrap();
        assert!(received.contains("\"op\":\"status\""));
        assert!(resp.ok);
        assert_eq!(resp.id, Some(7));
    }
}

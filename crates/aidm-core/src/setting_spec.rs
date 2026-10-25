//! 设置项声明表：**单一事实源**。
//!
//! 默认值、可写键与校验规则合成一张表，避免三份清单各自漂移：
//!
//! - 默认值、可写性、校验规则、是否密文、是否只读、UI 分组、生效方式
//!   全部来自同一个 [`Spec`]；
//! - 不在表里的键一律 `unknown_setting_key`，不存在"漏写分支"这回事；
//! - 表本身可以导出给 UI（`settings_schema`），UI 不必再硬编码键名。

/// 取值类型与校验规则。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Bool,
    /// 整数，越界返回结构化 `invalid_value{key,min,max}`
    Int {
        min: i64,
        max: i64,
    },
    /// 非负整数，无上界；错误码取 `Spec::err`
    NonNeg,
    Enum(&'static [&'static str]),
    Text {
        empty_ok: bool,
    },
    Path {
        empty_ok: bool,
    },
    Url {
        empty_ok: bool,
    },
    Cron {
        empty_ok: bool,
    },
    /// 逗号分隔扩展名（`mp4,zip,7z`）
    ExtList,
    /// eDonkey 服务器清单（`host:port` 逗号分隔，最多 16 台）。
    Ed2kServers,
    /// 逗号或空白分隔的主机名 / URL 通配模式（`*.example.com a.com`）
    HostList,
    /// JSON 对象，值必须是非空字符串
    JsonMap,
    /// JSON 字符串数组（浏览器扩展 ID 这类）
    JsonList,
    /// 任意文本，加密落库
    Secret,
    /// `HH:MM`
    Clock,
    /// 1-7 的逗号列表（ISO 星期）
    Weekdays,
}

/// 设置页分组。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    General,
    Paths,
    Connection,
    Scheduler,
    Browser,
    Proxy,
    Ui,
    Update,
    Advanced,
}

impl Section {
    pub fn as_str(self) -> &'static str {
        match self {
            Section::General => "general",
            Section::Paths => "paths",
            Section::Connection => "connection",
            Section::Scheduler => "scheduler",
            Section::Browser => "browser",
            Section::Proxy => "proxy",
            Section::Ui => "ui",
            Section::Update => "update",
            Section::Advanced => "advanced",
        }
    }
}

/// 改动之后怎么生效——决定 `settings_set` 之后要不要动正在跑的任务。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Apply {
    /// 立即生效：引擎直接改内存里的开关（限速、代理、排除列表…）
    Live,
    /// 立即把新上限推给正在跑的任务，**不重启**（连接数、闸门…）
    LiveLimits,
    /// 只影响之后新建的任务
    NextTask,
    /// 需要重启引擎进程才生效
    Restart,
}

impl Apply {
    pub fn as_str(self) -> &'static str {
        match self {
            Apply::Live => "live",
            Apply::LiveLimits => "live_limits",
            Apply::NextTask => "next_task",
            Apply::Restart => "restart",
        }
    }
}

/// 是否按主机（服务器）单独覆盖（每服务器最大连接数 / 例外）。
/// 带这一标记的键可以在 `host_conns` 表里按主机覆盖。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Global,
    PerHost,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Global => "global",
            Scope::PerHost => "per_host",
        }
    }
}

pub struct Spec {
    pub key: &'static str,
    pub default: &'static str,
    pub kind: Kind,
    /// 值非法时的错误码（`Kind::Int` 越界例外，用结构化 `invalid_value`）
    pub err: &'static str,
    pub section: Section,
    pub scope: Scope,
    pub apply: Apply,
    /// i18n 标签键；UI 侧 `t(label)`
    pub label: &'static str,
    pub readonly: bool,
    pub secret: bool,
}

const fn g(
    key: &'static str,
    default: &'static str,
    kind: Kind,
    err: &'static str,
    section: Section,
    apply: Apply,
    label: &'static str,
) -> Spec {
    Spec {
        key,
        default,
        kind,
        err,
        section,
        scope: Scope::Global,
        apply,
        label,
        readonly: false,
        secret: false,
    }
}

const fn per_host(mut s: Spec) -> Spec {
    s.scope = Scope::PerHost;
    s
}

const fn secret(mut s: Spec) -> Spec {
    s.secret = true;
    s
}

const fn readonly(mut s: Spec) -> Spec {
    s.readonly = true;
    s
}

const BOOL_TRUE: &str = "true";
const BOOL_FALSE: &str = "false";

/// 代理模式取值（`proxy::parse_mode` 同时接受 `system` 作为 `follow-system` 的别名）。
pub const PROXY_MODES: &[&str] = &["none", "follow-system", "manual"];
pub const PROXY_SCHEMES: &[&str] = &["http", "socks5"];
pub const PROXY_ONLY_FOR: &[&str] = &["all", "http", "https"];
pub const UPDATE_CHANNELS: &[&str] = &["stable", "beta"];
pub const AFTER_DONE: &[&str] = &[
    "none",
    "exit",
    "shutdown",
    "hibernate",
    "sleep",
    "disconnect",
];
pub const QUOTA_ACTIONS: &[&str] = &["pause", "stop"];
/// 时段/配额的统计周期。
pub const QUOTA_PERIODS: &[&str] = &["hour", "day", "week"];
pub const DUPLICATE_ACTIONS: &[&str] = &["allow", "ask", "resume", "skip"];
pub const SOUND_MODES: &[&str] = &["none", "beep", "file"];

/// 内置默认 User-Agent。
///
/// 使用 IE11 兼容 UA：部分站点/CDN 只对"像浏览器"的 UA 返回完整分块支持。
pub const DEFAULT_USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko";
/// 接管快捷键的可选值：常见的修饰键组合，外加 `del` / `ins` 两个单键。
///
/// 默认按住 Delete 不接管、按住 Insert 强制接管；单键与浏览器自身快捷键冲突更小。
pub const HOTKEYS: &[&str] = &[
    "",
    "alt",
    "ctrl",
    "shift",
    "ctrl+alt",
    "ctrl+shift",
    "alt+shift",
    "del",
    "ins",
];

/// 全部设置项。
///
/// `paths.default_dir` / `paths.metadata_dir` 的默认值走 `paths` 模块的 token；
/// `paths.category_dirs` 默认给出一组分类目录。
pub const SPECS: &[Spec] = &[
    // ---------------- General（语言 / 开机启动） ----------------
    // 占位：多语言热切换尚未实现（界面「语言」页写明"后续版本提供"）。
    // 审计脚本会把它列为"仅声明"，这是**有意为之**而不是漏接线。
    g(
        "general.language",
        "zh-CN",
        Kind::Text { empty_ok: false },
        "setting_empty",
        Section::General,
        Apply::Restart,
        "setting.general.language",
    ),
    g(
        "general.start_with_windows",
        BOOL_FALSE,
        Kind::Bool,
        "bool_invalid",
        Section::General,
        Apply::Live,
        "setting.general.start_with_windows",
    ),
    g(
        "general.tray_icon",
        BOOL_TRUE,
        Kind::Bool,
        "bool_invalid",
        Section::General,
        Apply::Live,
        "setting.general.tray_icon",
    ),
    g(
        "general.close_to_tray",
        BOOL_TRUE,
        Kind::Bool,
        "bool_invalid",
        Section::General,
        Apply::Live,
        "setting.general.close_to_tray",
    ),
    // ---------------- Paths（默认目录 / 分类目录 / 临时目录） ----------------
    g(
        "paths.default_dir",
        crate::paths::DEFAULT_DIR_SETTING,
        Kind::Path { empty_ok: false },
        "setting_empty",
        Section::Paths,
        Apply::NextTask,
        "setting.paths.default_dir",
    ),
    g(
        "paths.metadata_dir",
        if cfg!(windows) {
            "%LOCALAPPDATA%\\AIDM"
        } else {
            "$HOME/.local/share/aidm"
        },
        Kind::Path { empty_ok: false },
        "setting_empty",
        Section::Paths,
        Apply::Restart,
        "setting.paths.metadata_dir",
    ),
    // 分类 -> 目录 的 JSON 映射。
    g(
        "paths.category_dirs",
        "{}",
        Kind::JsonMap,
        "category_dirs_invalid",
        Section::Paths,
        Apply::NextTask,
        "setting.paths.category_dirs",
    ),
    g(
        "paths.remember_last_dir",
        BOOL_TRUE,
        Kind::Bool,
        "bool_invalid",
        Section::Paths,
        Apply::NextTask,
        "setting.paths.remember_last_dir",
    ),
    // ---------------- Connection（Connections and Limits） ----------------
    // 每任务连接数**不设限**：没有 `conn.max_conns_per_task` 这个键。
    // 连接预算的唯一解析器是 `hosts::task_conns`：每服务器例外
    //（`host_settings.max_conns`）> 全局闸门（`conn.global_conn_cap`），
    // 再由分段数 / 候选源数收窄。`downloads.max_conns` 不参与解析——
    // 派生值一旦落库，用户改设置就永远不生效。
    g(
        "conn.global_conn_cap",
        "256",
        Kind::Int { min: 1, max: 1024 },
        "",
        Section::Connection,
        Apply::LiveLimits,
        "setting.conn.global_conn_cap",
    ),
    g(
        "conn.timeout_connect_s",
        "15",
        Kind::Int { min: 1, max: 300 },
        "",
        Section::Connection,
        Apply::Live,
        "setting.conn.timeout_connect_s",
    ),
    g(
        "conn.timeout_idle_s",
        "60",
        Kind::Int { min: 1, max: 3600 },
        "",
        Section::Connection,
        Apply::Live,
        "setting.conn.timeout_idle_s",
    ),
    g(
        "conn.retry_max",
        "5",
        Kind::Int { min: 0, max: 20 },
        "",
        Section::Connection,
        Apply::NextTask,
        "setting.conn.retry_max",
    ),
    g(
        "conn.retry_backoff_ms",
        "1000",
        Kind::Int { min: 100, max: 60_000 },
        "",
        Section::Connection,
        Apply::NextTask,
        "setting.conn.retry_backoff_ms",
    ),
    per_host(g(
        "conn.speed_limit_default_kbps",
        "0",
        Kind::NonNeg,
        "speed_limit_invalid",
        Section::Connection,
        Apply::NextTask,
        "setting.conn.speed_limit_default_kbps",
    )),
    // ---------------- Scheduler（调度 / 下载限额） ----------------
    g(
        "sched.start_cron",
        "",
        Kind::Cron { empty_ok: true },
        "invalid_cron",
        Section::Scheduler,
        Apply::Live,
        "setting.sched.start_cron",
    ),
    g(
        "sched.window_enabled",
        BOOL_FALSE,
        Kind::Bool,
        "bool_invalid",
        Section::Scheduler,
        Apply::Live,
        "setting.sched.window_enabled",
    ),
    g(
        "sched.window_start",
        "00:00",
        Kind::Clock,
        "clock_invalid",
        Section::Scheduler,
        Apply::Live,
        "setting.sched.window_start",
    ),
    g(
        "sched.window_end",
        "23:59",
        Kind::Clock,
        "clock_invalid",
        Section::Scheduler,
        Apply::Live,
        "setting.sched.window_end",
    ),
    g(
        "sched.window_days",
        "1,2,3,4,5,6,7",
        Kind::Weekdays,
        "weekdays_invalid",
        Section::Scheduler,
        Apply::Live,
        "setting.sched.window_days",
    ),
    g(
        "sched.quota_enabled",
        BOOL_FALSE,
        Kind::Bool,
        "bool_invalid",
        Section::Scheduler,
        Apply::Live,
        "setting.sched.quota_enabled",
    ),
    g(
        "sched.quota_mb",
        "200",
        Kind::Int {
            min: 1,
            max: 10_000_000,
        },
        "",
        Section::Scheduler,
        Apply::Live,
        "setting.sched.quota_mb",
    ),
    g(
        "sched.quota_period",
        "day",
        Kind::Enum(QUOTA_PERIODS),
        "quota_period_invalid",
        Section::Scheduler,
        Apply::Live,
        "setting.sched.quota_period",
    ),
    g(
        "sched.quota_action",
        "pause",
        Kind::Enum(QUOTA_ACTIONS),
        "quota_action_invalid",
        Section::Scheduler,
        Apply::Live,
        "setting.sched.quota_action",
    ),
    // 队列处理完后 退出 / 关机 / 休眠 / 待机 / 断开拨号，并可强制。
    g(
        "sched.after_done",
        "none",
        Kind::Enum(AFTER_DONE),
        "after_done_invalid",
        Section::Scheduler,
        Apply::NextTask,
        "setting.sched.after_done",
    ),
    g(
        "sched.after_done_force",
        BOOL_FALSE,
        Kind::Bool,
        "bool_invalid",
        Section::Scheduler,
        Apply::NextTask,
        "setting.sched.after_done_force",
    ),
    // ---------------- Speed（限速） ----------------
    g(
        "speed.global_limit_kbps",
        "0",
        Kind::NonNeg,
        "speed_limit_invalid",
        Section::Connection,
        Apply::Live,
        "setting.speed.global_limit_kbps",
    ),
    // ---------------- eD2k（电驴）：服务器查源（L3） ----------------
    g(
        "ed2k.kad_enabled",
        BOOL_TRUE,
        Kind::Bool,
        "invalid_value",
        Section::Connection,
        Apply::NextTask,
        "setting.ed2k.kad_enabled",
    ),
    // 为空 = 不查服务器，只用链接自带源与已入库的源；配了才在"无新鲜源"
    // （表空或已有源全部失败过）时逐个登录查源，结果进 `ed2k_sources`。
    // 默认值经实网探测逐台验证（登录 ok；其中
    // 85.17.116.222:6082 与 91.208.162.87:4232 对真实文件返回过源，
    // 见 `crates/aidm-engine/tests/ed2k_probe.rs probe_iso_sources_on_public_servers`）。
    // 公网服务器会更替：如大面积登录失败，请在设置里更新本项。
    g(
        "ed2k.servers",
        "85.17.116.222:6082,91.208.162.87:4232,91.208.162.182:4232,143.246.192.192:4232,212.95.35.240:4232",
        Kind::Ed2kServers,
        "ed2k_servers_invalid",
        Section::Connection,
        Apply::NextTask,
        "setting.ed2k.servers",
    ),
    // 额外 BT tracker（空白或逗号分隔）。只在 magnet 没带 `tr=` 或 DHT 不通时才有用。
    // 默认**留空**：往第三方 tracker 发 announce 等于把 info-hash 告诉它，
    // 不该默认替用户决定。librqbit 的默认已经开着 DHT 与 LSD，所以这不是唯一手段。
    g(
        "bt.extra_trackers",
        "",
        Kind::Text { empty_ok: true },
        "setting_empty",
        Section::Connection,
        Apply::NextTask,
        "setting.bt.extra_trackers",
    ),
    // 自动镜像（L3 静态表）：主地址失败时把「同一路径换 host」的候选补进候选序列。
    // 只在已知命名空间下派生（见 `aidm_core::mirrors`），所以不会把任意下载
    // 悄悄发往陌生站点；表项都必须实测验证过。
    g(
        "alt.auto_mirrors",
        BOOL_TRUE,
        Kind::Bool,
        "invalid_value",
        Section::Connection,
        Apply::NextTask,
        "setting.alt.auto_mirrors",
    ),
    // ---- 智能加速：什么时候**不值得我们**去找更多来源 ----
    //
    // 背景：跨源聚合本身要发探测请求（每个候选一次 Range 探测），而小文件的总下载
    // 时间可能比"找源"还短。下面四个键决定"什么时候去找源"，默认值**全部保持
    // 既有行为**（等价于"总是按老规矩判断"），要开启省流才需要用户显式改。
    //
    // 低于该大小（MiB）的任务不做镜像发现。0 = 不启用跳过（保持既有行为）。
    g(
        "alt.probe_min_size_mb",
        "0",
        Kind::NonNeg,
        "invalid_value",
        Section::Connection,
        Apply::NextTask,
        "setting.alt.probe_min_size_mb",
    ),
    // 切块源的判定窗口（秒）：段级换源与段内换连接共用同一个内核（`aidm_core::pace`）。
    // **默认 5 秒 = 全自动开启**；显式设 0 才表示关闭。
    g(
        "alt.measure_window_s",
        "5",
        Kind::Int { min: 0, max: 120 },
        "invalid_value",
        Section::Connection,
        Apply::NextTask,
        "setting.alt.measure_window_s",
    ),
    // 观察窗口内的平均速率低于该值（**字节/秒**）才认为"速度不足、值得去找源"。
    // 0 = 不按速率判断（保持既有行为）。与上一个键配合使用，单独设它没有意义。
    g(
        "alt.measure_min_bps",
        "0",
        Kind::NonNeg,
        "invalid_value",
        Section::Connection,
        Apply::NextTask,
        "setting.alt.measure_min_bps",
    ),
    // 跨源聚合的来源数上限（含生效地址本身）。默认值必须与
    // `aidm_core::segment::MAX_SOURCES` 保持一致 —— 有一个测试盯着这条不变量，
    // 改一处忘了另一处会红。
    g(
        "alt.max_sources",
        "4",
        Kind::Int { min: 1, max: 16 },
        "invalid_value",
        Section::Connection,
        Apply::NextTask,
        "setting.alt.max_sources",
    ),
    // ---- 找源预算（`docs/source-discovery.md` §4.2/§7.1）----
    //
    // 只登记**已经被 worker 消费**的 7 个键；`find.slow_*`、`find.web_search_*` 等
    // 仍未接线，等对应阶段实现后再加，避免“声明了但永远不生效”。
    g(
        "find.enabled",
        BOOL_TRUE,
        Kind::Bool,
        "invalid_value",
        Section::Connection,
        Apply::NextTask,
        "setting.find.enabled",
    ),
    g(
        "find.max_elapsed_s",
        "60",
        Kind::Int { min: 0, max: 60 },
        "invalid_value",
        Section::Connection,
        Apply::NextTask,
        "setting.find.max_elapsed_s",
    ),
    g(
        "find.max_candidates",
        "12",
        Kind::Int { min: 1, max: 32 },
        "invalid_value",
        Section::Connection,
        Apply::NextTask,
        "setting.find.max_candidates",
    ),
    // 下载开始后，速率持续低于该值达到窗口秒数，开启新一轮找源。
    // 50 MiB/s = 51200 KiB/s；0 = 关闭慢速重触发。
    g(
        "find.slow_window_s",
        "60",
        Kind::Int { min: 0, max: 600 },
        "invalid_value",
        Section::Connection,
        Apply::NextTask,
        "setting.find.slow_window_s",
    ),
    g(
        "find.slow_min_mbps",
        "50",
        Kind::Int { min: 0, max: 10_000 },
        "invalid_value",
        Section::Connection,
        Apply::NextTask,
        "setting.find.slow_min_mbps",
    ),
    g(
        "find.negative_ttl_s",
        "600",
        Kind::Int { min: 60, max: 86400 },
        "invalid_value",
        Section::Connection,
        Apply::NextTask,
        "setting.find.negative_ttl_s",
    ),
    g(
        "find.platform_qpm",
        "6",
        Kind::Int { min: 1, max: 120 },
        "invalid_value",
        Section::Connection,
        Apply::NextTask,
        "setting.find.platform_qpm",
    ),
    // ---- S3 兼容对象存储（`s3://bucket/key`）----
    //
    // 引擎把 `s3://` 预签成一条普通 HTTPS 地址再交给既有内核下载，所以签名所需的
    // 凭证必须落到设置里。**secret 走 `Kind::Secret` 加密落库**，与站点凭据同一套。
    g(
        "s3.access_key",
        "",
        Kind::Text { empty_ok: true },
        "setting_empty",
        Section::Connection,
        Apply::NextTask,
        "setting.s3.access_key",
    ),
    g(
        "s3.secret_key",
        "",
        Kind::Secret,
        "setting_empty",
        Section::Connection,
        Apply::NextTask,
        "setting.s3.secret_key",
    ),
    // 缺 region 时 `s3://` 会被明确回绝（`s3_missing_region`）而不是猜一个 ——
    // 猜错 region 得到的是 `AuthorizationHeaderMalformed`，比直说缺参数难排查得多。
    g(
        "s3.region",
        "",
        Kind::Text { empty_ok: true },
        "setting_empty",
        Section::Connection,
        Apply::NextTask,
        "setting.s3.region",
    ),
    // 留空 = AWS 默认端点（`s3.<region>.amazonaws.com`，virtual-hosted 风格）。
    // 填了就是自建 S3 兼容实现（MinIO/Ceph/OSS…），此时按**路径式**拼
    // `/{bucket}/{key}` —— 那些端点不支持 virtual-hosted 的默认证书。
    g(
        "s3.endpoint",
        "",
        Kind::Text { empty_ok: true },
        "setting_empty",
        Section::Connection,
        Apply::NextTask,
        "setting.s3.endpoint",
    ),
    // 预签名有效期（秒）。上限 604800（7 天）是 AWS 的硬限制，越界由 `presign` 夹紧。
    g(
        "s3.presign_ttl_s",
        "3600",
        Kind::Int { min: 60, max: 604_800 },
        "invalid_value",
        Section::Connection,
        Apply::NextTask,
        "setting.s3.presign_ttl_s",
    ),
    // ---- 开发工具资源（`pip:name==ver` 等坐标）----
    //
    // PyPI 元数据接口的基地址。留空 = 官方 `https://pypi.org/pypi`。
    // 存在的理由有两个：一是镜像（国内直连官方源很慢），二是**可测试性** ——
    // 硬编码的地址让端到端测试没法指向本地 stub。
    g(
        "devtools.pypi_api_base",
        "",
        Kind::Text { empty_ok: true },
        "setting_empty",
        Section::Connection,
        Apply::NextTask,
        "setting.devtools.pypi_api_base",
    ),
    // 公共源列表的**刷新来源**。两者装的都是别人的公网地址，会随时更替，
    // 所以地址可配置、并且必须能手动刷新（而不是写死在二进制里）。
    // 实测：两个地址都返回 HTTP 200（nodes.dat 6030 B / v2 / 177 节点；
    // server.met 3125 B）。`gruk.org` 只有 server.met，没有 nodes.dat（实测 404）。
    // 留空 = 不刷新，只用已有缓存与内嵌兜底样本。
    g(
        "ed2k.nodes_dat_url",
        crate::ed2k::kad::store::DEFAULT_NODES_URL,
        Kind::Text { empty_ok: true },
        "setting_empty",
        Section::Connection,
        Apply::NextTask,
        "setting.ed2k.nodes_dat_url",
    ),
    // 超过这个天数就认为该重新抓了。节点会下线，放太久等于没有 bootstrap。
    g(
        "ed2k.nodes_dat_max_age_days",
        "7",
        Kind::Int { min: 1, max: 90 },
        "invalid_value",
        Section::Connection,
        Apply::Live,
        "setting.ed2k.nodes_dat_max_age_days",
    ),
    g(
        "ed2k.server_list_url",
        crate::ed2k::server_met::DEFAULT_SERVER_MET_URL,
        Kind::Text { empty_ok: true },
        "setting_empty",
        Section::Connection,
        Apply::NextTask,
        "setting.ed2k.server_list_url",
    ),
    // ---------------- eD2k（电驴）：入站上传（L6） ----------------
    // 默认**关闭**：开启后本机在 `ed2k.listen_port` 上监听并对外提供已完成的 eD2k 任务。
    // 与 eMule 默认开启不同——"对外监听"在这里是需要用户明确选择的能力。
    g(
        "ed2k.upload_enabled",
        BOOL_FALSE,
        Kind::Bool,
        "bool_invalid",
        Section::Connection,
        Apply::Live,
        "setting.ed2k.upload_enabled",
    ),
    // 0 = 让系统分配端口（启动后实际端口在「P2P 状态」里显示）。
    g(
        "ed2k.listen_port",
        "4662",
        Kind::Int { min: 0, max: 65535 },
        "invalid_value",
        Section::Connection,
        Apply::Live,
        "setting.ed2k.listen_port",
    ),
    // 同时上传给几个对端（上传槽）。
    g(
        "ed2k.upload_slots",
        "3",
        Kind::Int { min: 1, max: 16 },
        "invalid_value",
        Section::Connection,
        Apply::Live,
        "setting.ed2k.upload_slots",
    ),
    // 排队等待上传槽的对端数量上限；超过就不再接受新的上传请求。
    g(
        "ed2k.upload_max_waiting",
        "50",
        Kind::Int { min: 1, max: 500 },
        "invalid_value",
        Section::Connection,
        Apply::Live,
        "setting.ed2k.upload_max_waiting",
    ),
    // 独立于下载限速：上传占用的是用户的上行带宽。0 = 不限。
    g(
        "ed2k.upload_rate_kbps",
        "0",
        Kind::NonNeg,
        "speed_limit_invalid",
        Section::Connection,
        Apply::Live,
        "setting.ed2k.upload_rate_kbps",
    ),
    // ---------------- BitTorrent ----------------
    // **0 = 不监听**（默认，只做主动连接）；填 1–65535 才在固定端口监听。
    // 与"随机端口监听"的常见约定不同：这里把"开门"当成需要用户明确选择的事，
    // 而且 librqbit 的会话默认就不监听（`SessionOptions::default().listen = None`）。
    g(
        "bt.listen_port",
        "0",
        Kind::Int { min: 0, max: 65535 },
        "invalid_value",
        Section::Connection,
        Apply::NextTask,
        "setting.bt.listen_port",
    ),
    // 0 = 完成后立即停止（默认）；N = 任务标记完成后继续做种 N 分钟。
    // 做种期间会话与它的 tokio runtime 由引擎托管，任务本身已经是 done。
    g(
        "bt.seed_minutes",
        "0",
        Kind::Int { min: 0, max: 10080 },
        "invalid_value",
        Section::Connection,
        Apply::NextTask,
        "setting.bt.seed_minutes",
    ),
    // ---------------- Browser / System Integration ----------------
    g(
        "browser.enabled",
        BOOL_TRUE,
        Kind::Bool,
        "bool_invalid",
        Section::Browser,
        Apply::Live,
        "setting.browser.enabled",
    ),
    // 浏览器开始下载时由扩展判定并转交引擎（扩展名 / 排除服务器 / 跳过网页规则同下）。
    g(
        "browser.click_takeover",
        BOOL_TRUE,
        Kind::Bool,
        "bool_invalid",
        Section::Browser,
        Apply::Live,
        "setting.browser.click_takeover",
    ),
    g(
        "browser.allowed_ext_ids",
        r#"["npapgdblbbcppnbmhgdnmdbggfdnpahg"]"#,
        Kind::JsonList,
        "allowed_ext_ids_invalid",
        Section::Browser,
        Apply::Live,
        "setting.browser.allowed_ext_ids",
    ),
    // 这些主机上的下载一律不接管。
    g(
        "browser.exclude_hosts",
        "*.update.microsoft.com download.windowsupdate.com *.download.windowsupdate.com siteseal.thawte.com",
        Kind::HostList,
        "hosts_invalid",
        Section::Browser,
        Apply::Live,
        "setting.browser.exclude_hosts",
    ),
    // 命中这些扩展名的链接才算"可下载资源"。
    g(
        "browser.auto_catch_exts",
        "3gp 7z aac ace aif apk arj asf avi bin bz2 exe gz gzip img iso lzh m4a m4v mkv mov mp3 mp4 mpa mpe mpeg mpg msi msu ogg ogv plj pps ppt qt r0* r1* ra rar rm rmvb sea sit sitx tar tif tiff wav wma wmv z zip",
        Kind::ExtList,
        "exts_invalid",
        Section::Browser,
        Apply::Live,
        "setting.browser.auto_catch_exts",
    ),
    // 悬浮"下载此视频/音频"面板按扩展名开关。
    g(
        "browser.panel_enabled",
        BOOL_TRUE,
        Kind::Bool,
        "bool_invalid",
        Section::Browser,
        Apply::Live,
        "setting.browser.panel_enabled",
    ),
    g(
        "browser.panel_exts",
        "3gp aac asf avi dfxp f4v flv m4a m4v mkv mov mp3 mp4 mpeg mpg ogg ogv qt rm srt ts ttml ttml2 wav webm wma wmv",
        Kind::ExtList,
        "exts_invalid",
        Section::Browser,
        Apply::Live,
        "setting.browser.panel_exts",
    ),
    // 这些主机上不显示悬浮面板。
    g(
        "browser.panel_exclude_hosts",
        "*.gstatic.com media.tenor.co *.giphy.com",
        Kind::HostList,
        "hosts_invalid",
        Section::Browser,
        Apply::Live,
        "setting.browser.panel_exclude_hosts",
    ),
    // 剪贴板里的链接自动弹出"批量下载"；识别规则见 `clipboard_policy`。
    g(
        "browser.monitor_clipboard",
        BOOL_TRUE,
        Kind::Bool,
        "bool_invalid",
        Section::Browser,
        Apply::Live,
        "setting.browser.monitor_clipboard",
    ),
    // 按住这些修饰键时不接管。
    g(
        "browser.hotkey_prevent",
        "del",
        Kind::Enum(HOTKEYS),
        "hotkey_invalid",
        Section::Browser,
        Apply::Live,
        "setting.browser.hotkey_prevent",
    ),
    // 按住这些修饰键时强制接管。
    g(
        "browser.hotkey_force",
        "ins",
        Kind::Enum(HOTKEYS),
        "hotkey_invalid",
        Section::Browser,
        Apply::Live,
        "setting.browser.hotkey_force",
    ),
    // 不把网页本身当下载目标。
    g(
        "browser.skip_html",
        BOOL_TRUE,
        Kind::Bool,
        "bool_invalid",
        Section::Browser,
        Apply::Live,
        "setting.browser.skip_html",
    ),
    // ---------------- Proxy ----------------
    g(
        "proxy.mode",
        "follow-system",
        Kind::Enum(PROXY_MODES),
        "proxy_mode_invalid",
        Section::Proxy,
        Apply::Live,
        "setting.proxy.mode",
    ),
    g(
        "proxy.scheme",
        "http",
        Kind::Enum(PROXY_SCHEMES),
        "proxy_scheme_invalid",
        Section::Proxy,
        Apply::Live,
        "setting.proxy.scheme",
    ),
    g(
        "proxy.host",
        "",
        Kind::Text { empty_ok: true },
        "proxy_host_malformed",
        Section::Proxy,
        Apply::Live,
        "setting.proxy.host",
    ),
    g(
        "proxy.port",
        "",
        Kind::Text { empty_ok: true },
        "proxy_port_malformed",
        Section::Proxy,
        Apply::Live,
        "setting.proxy.port",
    ),
    g(
        "proxy.user",
        "",
        Kind::Text { empty_ok: true },
        "setting_empty",
        Section::Proxy,
        Apply::Live,
        "setting.proxy.user",
    ),
    secret(g(
        "proxy.pass",
        "",
        Kind::Secret,
        "setting_empty",
        Section::Proxy,
        Apply::Live,
        "setting.proxy.pass",
    )),
    // 只对其中一种协议走代理。
    g(
        "proxy.only_for",
        "all",
        Kind::Enum(PROXY_ONLY_FOR),
        "proxy_only_for_invalid",
        Section::Proxy,
        Apply::Live,
        "setting.proxy.only_for",
    ),
    // 这些主机直连，不走代理。
    g(
        "proxy.bypass_hosts",
        "",
        Kind::HostList,
        "hosts_invalid",
        Section::Proxy,
        Apply::Live,
        "setting.proxy.bypass_hosts",
    ),
    // ---------------- UI（下载列表页 / 声音） ----------------
    g(
        "ui.confirm_on_delete",
        BOOL_TRUE,
        Kind::Bool,
        "bool_invalid",
        Section::Ui,
        Apply::Live,
        "setting.ui.confirm_on_delete",
    ),
    g(
        "ui.notify_on_complete",
        BOOL_TRUE,
        Kind::Bool,
        "bool_invalid",
        Section::Ui,
        Apply::Live,
        "setting.ui.notify_on_complete",
    ),
    // 完成/失败时播放声音。
    g(
        "ui.sound_complete",
        "beep",
        Kind::Enum(SOUND_MODES),
        "sound_invalid",
        Section::Ui,
        Apply::Live,
        "setting.ui.sound_complete",
    ),
    g(
        "ui.sound_file_complete",
        "",
        Kind::Path { empty_ok: true },
        "setting_empty",
        Section::Ui,
        Apply::Live,
        "setting.ui.sound_file_complete",
    ),
    g(
        "ui.sound_error",
        "beep",
        Kind::Enum(SOUND_MODES),
        "sound_invalid",
        Section::Ui,
        Apply::Live,
        "setting.ui.sound_error",
    ),
    g(
        "ui.sound_file_error",
        "",
        Kind::Path { empty_ok: true },
        "setting_empty",
        Section::Ui,
        Apply::Live,
        "setting.ui.sound_file_error",
    ),
    // 同一链接再次添加时的策略。
    g(
        "ui.duplicate_action",
        "allow",
        Kind::Enum(DUPLICATE_ACTIONS),
        "duplicate_action_invalid",
        Section::Ui,
        Apply::NextTask,
        "setting.ui.duplicate_action",
    ),
    // ---------------- Update ----------------
    g(
        "update.channel",
        "stable",
        Kind::Enum(UPDATE_CHANNELS),
        "update_channel_invalid",
        Section::Update,
        Apply::NextTask,
        "setting.update.channel",
    ),
    g(
        "update.auto_check",
        BOOL_TRUE,
        Kind::Bool,
        "bool_invalid",
        Section::Update,
        Apply::NextTask,
        "setting.update.auto_check",
    ),
    g(
        "update.manifest_base_url",
        "",
        Kind::Url { empty_ok: true },
        "manifest_base_url_invalid",
        Section::Update,
        Apply::NextTask,
        "setting.update.manifest_base_url",
    ),
    // ---------------- Advanced（引擎内部开关） ----------------
    // 引擎内部开关也纳入 schema，避免代码与设置表漂移。
    g(
        "engine.fastdl",
        BOOL_TRUE,
        Kind::Bool,
        "bool_invalid",
        Section::Advanced,
        Apply::NextTask,
        "setting.engine.fastdl",
    ),
    g(
        "verify.sha256_after",
        BOOL_TRUE,
        Kind::Bool,
        "bool_invalid",
        Section::Advanced,
        Apply::NextTask,
        "setting.verify.sha256_after",
    ),
    g(
        "net.recv_buf_kb",
        "0",
        Kind::Int {
            min: 0,
            max: 8192,
        },
        "",
        Section::Advanced,
        Apply::Live,
        "setting.net.recv_buf_kb",
    ),
    // User-Agent 逻辑：不配就用内置默认串，配了就整串替换；
    // 留空表示"回到内置默认"。
    g(
        "net.user_agent",
        DEFAULT_USER_AGENT,
        Kind::Text { empty_ok: true },
        "setting_empty",
        Section::Advanced,
        Apply::Live,
        "setting.net.user_agent",
    ),
    // 内置默认请求头集合：Accept / Accept-Charset /
    // Accept-Language / Accept-Encoding: identity，加上"没给 Referer 时补站点根"。
    g(
        "net.accept",
        "*/*",
        Kind::Text { empty_ok: true },
        "setting_empty",
        Section::Advanced,
        Apply::Live,
        "setting.net.accept",
    ),
    g(
        "net.accept_charset",
        "*",
        Kind::Text { empty_ok: true },
        "setting_empty",
        Section::Advanced,
        Apply::Live,
        "setting.net.accept_charset",
    ),
    // `auto` = 跟随系统区域，也可写死 zh-CN / en-US
    g(
        "net.accept_language",
        "auto",
        Kind::Text { empty_ok: true },
        "setting_empty",
        Section::Advanced,
        Apply::Live,
        "setting.net.accept_language",
    ),
    g(
        "net.accept_encoding",
        "identity",
        Kind::Text { empty_ok: true },
        "setting_empty",
        Section::Advanced,
        Apply::Live,
        "setting.net.accept_encoding",
    ),
    g(
        "net.referer_fallback",
        "true",
        Kind::Bool,
        "bool_invalid",
        Section::Advanced,
        Apply::Live,
        "setting.net.referer_fallback",
    ),
    // ---------------- 只读（引擎写入，UI 只展示） ----------------
    readonly(g(
        "settings.revision",
        "",
        Kind::Text { empty_ok: true },
        "setting_readonly",
        Section::Advanced,
        Apply::Live,
        "setting.settings_revision",
    )),
    readonly(g(
        "update.last_check_at",
        "",
        Kind::Text { empty_ok: true },
        "setting_readonly",
        Section::Update,
        Apply::Live,
        "setting.update.last_check_at",
    )),
    readonly(g(
        "app.version",
        "",
        Kind::Text { empty_ok: true },
        "setting_readonly",
        Section::General,
        Apply::Live,
        "setting.app_version",
    )),
    readonly(g(
        "proxy.has_password",
        BOOL_FALSE,
        Kind::Bool,
        "setting_readonly",
        Section::Proxy,
        Apply::Live,
        "setting.proxy.has_password",
    )),
];

/// 设置修订号：每次用户可见的设置写入都会推高它。
pub const KEY_REVISION: &str = "settings.revision";

pub fn specs() -> &'static [Spec] {
    SPECS
}

pub fn get(key: &str) -> Option<&'static Spec> {
    SPECS.iter().find(|s| s.key == key)
}

/// 已从 schema 移除、但可能残留在库里的键：读取时过滤，避免泄漏给 UI。
pub const LEGACY_KEYS: &[&str] = &["browser.integration_enabled"];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn keys_are_unique() {
        let mut seen = HashSet::new();
        for s in SPECS {
            assert!(seen.insert(s.key), "重复的键: {}", s.key);
        }
    }

    #[test]
    fn every_spec_has_a_label_and_error_code() {
        for s in SPECS {
            assert!(!s.label.is_empty(), "{} 缺 label", s.key);
            if !s.readonly {
                assert!(
                    !s.err.is_empty() || matches!(s.kind, Kind::Int { .. }),
                    "{} 缺错误码",
                    s.key
                );
            }
        }
    }

    /// 默认值基线。
    ///
    /// 这里把基线钉住：默认值漂了必须是有意识的改动，而不是顺手改了没注意。
    #[test]
    fn defaults_follow_the_calibrated_baseline() {
        let d = |k: &str| crate::setting_spec::get(k).unwrap().default;

        // 传输：每任务连接数不设限（无该键）；全局闸门默认 256
        assert_eq!(d("conn.global_conn_cap"), "256");
        assert!(crate::setting_spec::get("conn.max_conns_per_task").is_none());

        // 调度：配额与时段默认关闭；配额 200 MB / 天，超限暂停
        assert_eq!(d("sched.quota_enabled"), "false");
        assert_eq!(d("sched.quota_mb"), "200");
        assert_eq!(d("sched.quota_period"), "day");
        assert_eq!(d("sched.quota_action"), "pause");
        assert_eq!(d("sched.window_enabled"), "false");
        assert_eq!(d("sched.start_cron"), "");
        assert_eq!(d("sched.after_done"), "none");

        // 目录与界面默认值
        assert_eq!(d("paths.remember_last_dir"), "true");
        assert_eq!(d("general.tray_icon"), "true");
        assert_eq!(d("general.language"), "zh-CN");
        assert_eq!(d("ui.duplicate_action"), "allow");
        // 提示音：默认完成/失败都出声，用系统提示音
        assert_eq!(d("ui.sound_complete"), "beep");
        assert_eq!(d("ui.sound_error"), "beep");

        // 浏览器接管默认值
        let exclude = d("browser.exclude_hosts");
        for host in [
            "*.update.microsoft.com",
            "download.windowsupdate.com",
            "*.download.windowsupdate.com",
            "siteseal.thawte.com",
        ] {
            assert!(exclude.contains(host), "排除表缺 {host}: {exclude}");
        }
        let exts: Vec<&str> = d("browser.auto_catch_exts").split(' ').collect();
        assert_eq!(exts.len(), 52, "自动接管扩展名数量应稳定");
        for e in ["iso", "zip", "exe", "r0*", "r1*", "msu", "sitx"] {
            assert!(exts.contains(&e), "自动接管缺 {e}");
        }
        let panel: Vec<&str> = d("browser.panel_exts").split(' ').collect();
        assert_eq!(
            panel.len(),
            27,
            "悬浮面板扩展名数量应稳定（VTT 未启用）"
        );
        assert!(panel.contains(&"ttml2"));
        assert!(!panel.contains(&"vtt"), "VTT 默认不启用");
        let panel_ex = d("browser.panel_exclude_hosts");
        for host in ["*.gstatic.com", "media.tenor.co", "*.giphy.com"] {
            assert!(panel_ex.contains(host), "面板排除表缺 {host}: {panel_ex}");
        }
        assert_eq!(d("browser.hotkey_prevent"), "del");
        assert_eq!(d("browser.hotkey_force"), "ins");
        assert_eq!(d("browser.skip_html"), "true");
        assert_eq!(d("browser.monitor_clipboard"), "true");
        assert_eq!(d("browser.panel_enabled"), "true");
        assert_eq!(d("browser.enabled"), "true");

        // 代理：默认跟随系统，排除表为空
        assert_eq!(d("proxy.mode"), "follow-system");
        assert_eq!(d("proxy.only_for"), "all");
        assert_eq!(d("proxy.bypass_hosts"), "");

        // eD2k 查源服务器：实网探测可用（登录 ok，其中两台返回过源），
        // 出处见 ed2k_probe.rs probe_iso_sources_on_public_servers
        assert_eq!(
            d("ed2k.servers"),
            "85.17.116.222:6082,91.208.162.87:4232,91.208.162.182:4232,143.246.192.192:4232,212.95.35.240:4232"
        );

        // 有意的默认值差异（改动需同步文档）
        assert_eq!(
            d("general.start_with_windows"),
            "false",
            "开机自启默认关（产品决策）"
        );
        assert_eq!(
            d("net.recv_buf_kb"),
            "0",
            "交给系统自动调优（实测比固定缓冲快）"
        );
        // 默认请求头保持稳定（见 docs/http-profile.md）
        assert_eq!(d("net.user_agent"), DEFAULT_USER_AGENT);
        assert_eq!(
            d("net.user_agent"),
            "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko"
        );
        assert_eq!(d("net.accept"), "*/*");
        assert_eq!(d("net.accept_charset"), "*");
        assert_eq!(d("net.accept_language"), "auto");
        assert_eq!(d("net.accept_encoding"), "identity");
        assert_eq!(d("net.referer_fallback"), "true");
        assert_eq!(d("engine.fastdl"), "true");
        assert_eq!(d("verify.sha256_after"), "true");
    }
    #[test]
    fn defaults_are_self_consistent() {
        // 默认值必须能通过自己的校验：否则首次落库就会写出一个非法值
        for s in SPECS {
            if s.readonly {
                continue;
            }
            if let Err(e) = crate::settings::validate_value(s, s.default) {
                panic!("默认值 {}.{} 通不过校验: {}", s.key, s.default, e.code);
            }
        }
    }

    #[test]
    fn smart_acceleration_defaults_preserve_existing_behaviour() {
        let d = |k: &str| crate::setting_spec::get(k).unwrap().default;

        // 四个智能加速键的默认值都是**产品行为**，改它不该悄悄发生：镜像发现的两项
        // 默认关闭（升级后不多发探测请求）；切块源的判定窗口默认 5 秒（
        // 的目标是「全自动」），绝对下限默认 0（不发明阈值）。
        assert_eq!(d("alt.probe_min_size_mb"), "0", "默认不按大小跳过镜像发现");
        assert_eq!(
            d("alt.measure_window_s"),
            "5",
            "默认 5 秒：切块源全自动开启（0 才表示关闭）"
        );
        assert_eq!(d("alt.measure_min_bps"), "0", "默认不按速率判断");
        // 来源上限是唯一"非零"的默认值，因为它必须等于代码里既有的硬上限。
        assert_eq!(
            d("alt.max_sources"),
            crate::segment::MAX_SOURCES.to_string(),
            "来源上限的默认值必须与 segment::MAX_SOURCES 一致（改一处忘了另一处会红）"
        );
        // 四者都只在下一个任务生效：改设置不该扰动正在跑的任务。
        for k in [
            "alt.probe_min_size_mb",
            "alt.measure_window_s",
            "alt.measure_min_bps",
            "alt.max_sources",
        ] {
            assert_eq!(
                get(k).unwrap().apply,
                Apply::NextTask,
                "{k} 只应影响之后新建的任务"
            );
            assert_eq!(
                get(k).unwrap().section,
                Section::Connection,
                "{k} 属于连接页"
            );
        }
    }

    #[test]
    fn lookup_and_sections() {
        assert!(get("conn.global_conn_cap").is_some());
        assert!(get("nope").is_none());
        assert!(
            get("conn.max_conns_per_task").is_none(),
            "每任务连接数不设限：该键必须不存在"
        );
        assert_eq!(get("conn.global_conn_cap").unwrap().scope, Scope::Global);
        assert_eq!(
            get("conn.global_conn_cap").unwrap().apply,
            Apply::LiveLimits
        );
        assert!(get("paths.default_dir").unwrap().section == Section::Paths);
        assert!(get("proxy.pass").unwrap().secret);
        assert!(get(KEY_REVISION).unwrap().readonly);
    }
}

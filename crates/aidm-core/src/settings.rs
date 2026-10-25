//! 设置项：`settings(key, value)` 读写 + 校验 + 只读快照。
//!
//! 三条设计原则：
//!
//! 1. **单一事实源**：默认值 / 可写性 / 校验规则 / 分组 / 生效方式全部来自
//!    [`crate::setting_spec::SPECS`]，不存在"三份平行清单互相漂移"的问题，
//!    也不存在"未列出的键静默放行"的校验漏洞。
//! 2. **一次解析、全局共享**：[`Snapshot`] 把 ~60 个字符串键解析成有类型的字段
//!    （闸门、cron、时段、代理排除表…），调度器每拍只读内存，不再每拍做 4 次
//!    SQL 查询 + cron 解析。
//! 3. **变更可检测**：[`revision`] 写入即推高，读方据此决定要不要重载快照。
//!
//! `settings_get` 返回全部 schema 键 + 只读 `app.version` / `settings.revision`；
//! `proxy.pass` 永不回传明文，改为 `proxy.has_password`。

use std::collections::BTreeMap;
use std::fmt;
use std::sync::OnceLock;

use rusqlite::Connection;

use crate::cron;
use crate::proxy;
use crate::sched;
use crate::secret;
use crate::setting_spec::{self, Spec};

/// 重新导出，方便引擎侧按 schema 的声明做事（`Apply` / `Scope` / `Section` / `Kind`）。
pub use crate::setting_spec::{Apply, Kind, Scope, Section};

/// 可写数值键的闭区间改为从 schema 查询（[`range_of`]），不再维护第二份常量。
///
/// `settings_get` 只读键：当前 crate / 应用版本（不落库）。
pub const KEY_APP_VERSION: &str = "app.version";

/// `settings_set` 结构化错误（IPC 原样下发）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingError {
    pub code: String,
    pub key: Option<String>,
    pub min: Option<i64>,
    pub max: Option<i64>,
}

impl SettingError {
    pub fn msg(code: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            key: None,
            min: None,
            max: None,
        }
    }

    pub fn invalid_value(key: &str, min: i64, max: i64) -> Self {
        Self {
            code: "invalid_value".into(),
            key: Some(key.into()),
            min: Some(min),
            max: Some(max),
        }
    }

    pub fn invalid_cron(key: &str) -> Self {
        Self {
            code: "invalid_cron".into(),
            key: Some(key.into()),
            min: None,
            max: None,
        }
    }
}

impl fmt::Display for SettingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.code)
    }
}

/// §9 设置项默认值（由 [`crate::setting_spec::SPECS`] 派生，不再是第二份清单）。
pub fn defaults() -> impl Iterator<Item = (&'static str, &'static str)> {
    crate::setting_spec::specs()
        .iter()
        .filter(|s| !s.readonly && !s.secret)
        .map(|s| (s.key, s.default))
}

/// `settings_get` 只读键：当前 crate / 应用版本（不落库）。
pub const KEY_UPDATE_CHANNEL: &str = "update.channel";
pub const KEY_UPDATE_AUTO_CHECK: &str = "update.auto_check";
pub const KEY_UPDATE_LAST_CHECK_AT: &str = "update.last_check_at";
pub const KEY_UPDATE_MANIFEST_BASE_URL: &str = "update.manifest_base_url";

/// version.json 根路径占位默认。生产请设 `AIDM_UPDATE_MANIFEST_BASE_URL`
/// 或 `update.manifest_base_url` 为真实 Release 根（无鉴权；本里程碑无私有仓）。
/// 实际请求 `{base}/{channel}/version.json`。
pub const DEFAULT_MANIFEST_BASE_URL: &str =
    "https://github.com/fusongjie/AIDM/releases/latest/download";

pub fn app_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// `proxy.pass` 加密存储；对外以 `proxy.has_password` 呈现。
pub const PASSWORD_KEY: &str = "proxy.pass";
pub const HAS_PASSWORD_KEY: &str = "proxy.has_password";

/// 历史别名：写 `browser.integration_enabled` 等价于写 `browser.enabled`。
pub const KEY_BROWSER_ALIAS: &str = "browser.integration_enabled";

pub fn get(conn: &Connection, key: &str) -> rusqlite::Result<Option<String>> {
    conn.query_row("SELECT value FROM settings WHERE key = ?1", [key], |row| {
        row.get::<_, String>(0)
    })
    .map(Some)
    .or_else(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => Ok(None),
        other => Err(other),
    })
}

pub fn set(conn: &Connection, key: &str, value: &str) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO settings(key, value) VALUES(?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        [key, value],
    )?;
    Ok(())
}

/// 首次运行时把默认值写入库中（已存在的键不覆盖，保留用户改动）。
/// 建立默认配置时，哪些键的**上一个默认值**是已知的。
///
/// 只用于一次性过渡：`setting_seeds` 是随本次改动才有的表，所以老库里
/// "用户没改过"和"用户改成了旧默认值"看起来一样。对下面这几个键，
/// 我们确切知道旧默认值是什么，于是可以安全地把"现值 == 旧默认值"判定为
/// 没改过并升到新默认值；不在表里的键一律不动。
///
/// 新增条目只应出现在"默认值确实变了"的那一次改动里，并在下个版本清掉。
const LEGACY_DEFAULTS: &[(&str, &str)] = &[
    ("sched.quota_mb", "10240"),
    ("browser.exclude_hosts", ""),
    (
        "browser.auto_catch_exts",
        "3GP 7Z AAC ACE AIF APK ARJ ASF AVI BIN BZ2 EXE GZ GZIP IMG ISO LZH M4A M4V MKV MOV \
         MP3 MP4 MPA MPE MPEG MPG MSI MSU OGG OGV PLJ PPS PPT QT R0 R1 RA RAR RM RMVB SEA SIT \
         SITX TAR TIF TIFF WAV WMA WMV Z ZIP",
    ),
    (
        "browser.panel_exts",
        "FLV MP3 MP4 M4V F4V M4A MPG MPEG AVI WMV WMA WAV ASF RM OGG OGV MOV 3GP QT WEBM TS \
         MKV AAC TTML SRT",
    ),
    ("browser.panel_exclude_hosts", ""),
    ("browser.hotkey_prevent", ""),
    ("browser.hotkey_force", ""),
    ("ui.sound_complete", "none"),
    ("ui.sound_error", "none"),
];

fn legacy_default_of(key: &str) -> Option<&'static str> {
    LEGACY_DEFAULTS
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| *v)
}

/// `ensure_defaults` 的结果，用于启动日志：一眼看出这次启动到底动了什么。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SeedReport {
    /// 新建的键（库里原本没有）
    pub created: usize,
    /// 用户没改过、跟随新默认值升级的键
    pub upgraded: usize,
    /// 用户改过或本来就一致的键
    pub kept: usize,
}

/// 在库里建立"默认配置"：写入所有缺失的键，并把每个键**当时的默认值**记下来。
///
/// 为什么要记：默认值会随版本调整。
/// 只写"缺失的键"是不够的——老库里键已经存在，用户从没改过，却永远停在旧默认值上。
/// 记下种子值后，下次启动就能区分两种情况：
/// - 当前值 == 当初写入的默认值 → 用户没动过 → 跟着新默认值升级；
/// - 当前值 != 种子值 → 用户自己改过 → 一律不动。
///
/// 表 `setting_seeds` 只服务这个用途，不参与任何业务读取。
pub fn ensure_defaults(conn: &Connection) -> rusqlite::Result<SeedReport> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS setting_seeds(
            key          TEXT PRIMARY KEY,
            seeded_value TEXT NOT NULL
        )",
        [],
    )?;
    let mut report = SeedReport::default();
    for (key, value) in defaults() {
        let current = get(conn, key)?;
        let seeded: Option<String> = conn
            .query_row(
                "SELECT seeded_value FROM setting_seeds WHERE key = ?1",
                [key],
                |r| r.get(0),
            )
            .ok();
        match (current, seeded) {
            // 全新键：写入默认值并记种子
            (None, _) => {
                set(conn, key, value)?;
                report.created += 1;
                conn.execute(
                    "INSERT INTO setting_seeds(key, seeded_value) VALUES(?1, ?2)
                     ON CONFLICT(key) DO UPDATE SET seeded_value = excluded.seeded_value",
                    rusqlite::params![key, &value],
                )?;
            }
            // 用户没动过（现值仍等于种子）→ 跟随新默认值
            (Some(cur), Some(seed)) if cur == seed && cur != value => {
                set(conn, key, value)?;
                report.upgraded += 1;
                conn.execute(
                    "UPDATE setting_seeds SET seeded_value = ?2 WHERE key = ?1",
                    rusqlite::params![key, &value],
                )?;
            }
            // 有值但没有种子记录：正常情况下无法判断用户改没改，保守当成"用户的值"。
            // 例外：这个键的旧默认值是我们确切知道的，且现值正好等于它 —— 那就可以
            // 安全地升到新默认值（一次性过渡，见 `LEGACY_DEFAULTS`）。
            (Some(cur), None) => {
                let upgraded = legacy_default_of(key) == Some(cur.as_str()) && cur != value;
                if upgraded {
                    set(conn, key, value)?;
                    report.upgraded += 1;
                } else {
                    report.kept += 1;
                }
                let seeded_value: &str = if upgraded { value } else { cur.as_str() };
                conn.execute(
                    "INSERT OR REPLACE INTO setting_seeds(key, seeded_value) VALUES(?1, ?2)",
                    rusqlite::params![key, seeded_value],
                )?;
            }
            // 用户改过：不动
            _ => {
                report.kept += 1;
            }
        }
    }
    Ok(report)
}

/// 可写 = 在 schema 里且不是只读项。不在 schema 里的键一律不可写。
pub fn is_writable_key(key: &str) -> bool {
    crate::setting_spec::get(key)
        .map(|s| !s.readonly)
        .unwrap_or(false)
}

/// 校验写入值。失败时不得落库。
///
/// 规则全部来自 [`crate::setting_spec::Spec`]：**没有**任何"未列出的键就放行"
/// 的兜底分支——不在 schema 里就是 `unknown_setting_key`。
pub fn validate(key: &str, value: &str) -> Result<(), SettingError> {
    let key = normalize_key(key);
    let spec =
        crate::setting_spec::get(key).ok_or_else(|| SettingError::msg("unknown_setting_key"))?;
    if spec.readonly {
        return Err(SettingError::msg("setting_readonly"));
    }
    validate_value(spec, value)
}

/// 历史别名归一：写入端只认主键名。
pub fn normalize_key(key: &str) -> &str {
    if key == KEY_BROWSER_ALIAS {
        "browser.enabled"
    } else {
        key
    }
}

/// 按 spec 校验单个值（`setting_spec` 的默认值自检也用它）。
pub fn validate_value(spec: &crate::setting_spec::Spec, value: &str) -> Result<(), SettingError> {
    use crate::setting_spec::Kind;
    let bad = || SettingError::msg(spec.err);
    match spec.kind {
        Kind::Bool => parse_bool(value),
        Kind::Int { min, max } => parse_range_key(spec.key, value, (min, max)),
        Kind::NonNeg => parse_nonneg_int(value, spec.err).map(|_| ()),
        Kind::Enum(values) => {
            // 代理模式/类型沿用 `proxy` 模块的解析：它额外接受 `system` / `socks`
            // 这类历史值，保持旧配置可继续写入。
            if spec.key == "proxy.mode" {
                return proxy::parse_mode(value)
                    .map(|_| ())
                    .ok_or_else(|| SettingError::msg("proxy_mode_invalid"));
            }
            if spec.key == "proxy.scheme" {
                return proxy::parse_scheme(value)
                    .map(|_| ())
                    .ok_or_else(|| SettingError::msg("proxy_scheme_invalid"));
            }
            if values.iter().any(|v| v.eq_ignore_ascii_case(value.trim())) {
                Ok(())
            } else {
                Err(bad())
            }
        }
        Kind::Text { empty_ok } => non_empty(value, empty_ok, spec.err),
        Kind::Path { empty_ok } => non_empty(value, empty_ok, spec.err),
        Kind::Secret => Ok(()),
        Kind::Url { empty_ok } => {
            // `empty_ok: false` 的 URL 键不允许留空；留空即视为非法
            if value.trim().is_empty() {
                if empty_ok {
                    Ok(())
                } else {
                    Err(bad())
                }
            } else {
                validate_manifest_base_url(value)
            }
        }
        Kind::Cron { empty_ok } => {
            if value.trim().is_empty() && empty_ok {
                return Ok(());
            }
            cron::parse(value)
                .map(|_| ())
                .map_err(|_| SettingError::invalid_cron(spec.key))
        }
        Kind::Clock => parse_clock(value).map(|_| ()).map_err(|_| bad()),
        Kind::Weekdays => parse_weekdays(value).map(|_| ()).map_err(|_| bad()),
        Kind::ExtList => parse_ext_list(value).map(|_| ()).map_err(|_| bad()),
        Kind::Ed2kServers => parse_ed2k_servers(value).map(|_| ()).map_err(|_| bad()),
        Kind::HostList => parse_host_list(value).map(|_| ()).map_err(|_| bad()),
        Kind::JsonMap => parse_json_map(value).map(|_| ()).map_err(|_| bad()),
        Kind::JsonList => parse_allowed_ext_ids(value).map(|_| ()).map_err(|_| bad()),
    }
}

/// `proxy.host` 的格式校验走 `proxy` 模块（IPv4/IPv6/DNS 标签）。
pub fn validate_proxy_host(raw: &str) -> Result<(), SettingError> {
    proxy::validate_host(raw).map_err(SettingError::msg)
}

pub fn validate_proxy_port(raw: &str) -> Result<(), SettingError> {
    proxy::validate_port(raw)
        .map(|_| ())
        .map_err(SettingError::msg)
}

fn non_empty(value: &str, empty_ok: bool, err: &str) -> Result<(), SettingError> {
    if value.trim().is_empty() && !empty_ok {
        Err(SettingError::msg(err))
    } else {
        Ok(())
    }
}

/// `HH:MM`
pub fn parse_clock(value: &str) -> Result<(u8, u8), String> {
    let s = value.trim();
    let (h, m) = s.split_once(':').ok_or("clock_invalid")?;
    if h.len() > 2 || m.len() != 2 {
        return Err("clock_invalid".into());
    }
    let h: u8 = h.parse().map_err(|_| "clock_invalid".to_string())?;
    let m: u8 = m.parse().map_err(|_| "clock_invalid".to_string())?;
    if h > 23 || m > 59 {
        return Err("clock_invalid".into());
    }
    Ok((h, m))
}

/// ISO 星期（1=周一，7=周日），逗号分隔、去重、升序。
pub fn parse_weekdays(value: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    for part in value.split(',') {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        let n: u8 = p.parse().map_err(|_| "weekdays_invalid".to_string())?;
        if !(1..=7).contains(&n) {
            return Err("weekdays_invalid".into());
        }
        if !out.contains(&n) {
            out.push(n);
        }
    }
    if out.is_empty() {
        return Err("weekdays_invalid".into());
    }
    out.sort_unstable();
    Ok(out)
}

/// 扩展名清单：接受 `mp4,zip` 或空白分隔；归一化为小写、去点。
pub fn parse_ext_list(value: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for part in value.split(|c: char| c == ',' || c.is_whitespace()) {
        let p = part.trim().trim_start_matches('.').to_ascii_lowercase();
        if p.is_empty() {
            continue;
        }
        if p.len() > 32
            || !p
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '*' || c == '-')
        {
            return Err("exts_invalid".into());
        }
        if !out.contains(&p) {
            out.push(p);
        }
    }
    Ok(out)
}

/// eDonkey 服务器清单：`host:port` 逗号/分号/空白分隔，最多 16 台。
/// 空串表示不查服务器。主机部分不做 DNS 预检（解析失败在查源时按服务器
/// 记一次失败，不连累整批）；端口必须为 1..=65535。
pub fn parse_ed2k_servers(value: &str) -> Result<Vec<(String, u16)>, String> {
    let mut out = Vec::new();
    for part in value.split(|c: char| c == ',' || c == ';' || c.is_whitespace()) {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        let (host, port) = p.rsplit_once(':').ok_or("ed2k_servers_invalid")?;
        let host = host
            .trim()
            .trim_matches(|c| c == '[' || c == ']')
            .to_string();
        let port: u16 = port.trim().parse().map_err(|_| "ed2k_servers_invalid")?;
        if host.is_empty() || host.len() > 253 || port == 0 {
            return Err("ed2k_servers_invalid".into());
        }
        if host.chars().any(|c| c.is_whitespace() || c == '/') {
            return Err("ed2k_servers_invalid".into());
        }
        if !out.contains(&(host.clone(), port)) {
            out.push((host, port));
        }
        if out.len() > 16 {
            return Err("ed2k_servers_invalid".into());
        }
    }
    Ok(out)
}

/// 主机 / URL 通配模式清单。接受 `*.example.com`、`example.com`、
/// `https://example.com/path`（只取主机部分）。
pub fn parse_host_list(value: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for part in value.split(|c: char| c == ',' || c == ';' || c.is_whitespace()) {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        let host = crate::sched::url_host(p);
        // 保留 `*.` 前缀：它是通配语义（`*.example.com` 匹配子域）
        let host = host.split('/').next().unwrap_or(&host).to_string();
        if host.is_empty()
            || host.len() > 253
            || !host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '*' || c == '_')
        {
            return Err("hosts_invalid".into());
        }
        if !out.contains(&host) {
            out.push(host);
        }
    }
    Ok(out)
}

/// JSON 对象，值必须是非空字符串（分类目录映射等）。
pub fn parse_json_map(value: &str) -> Result<Vec<(String, String)>, String> {
    let s = value.trim();
    if s.is_empty() {
        return Ok(Vec::new());
    }
    let parsed: serde_json::Value =
        serde_json::from_str(s).map_err(|_| "json_invalid".to_string())?;
    let obj = parsed.as_object().ok_or("json_invalid")?;
    let mut out = Vec::with_capacity(obj.len());
    for (k, v) in obj {
        let key = k.trim();
        let val = v.as_str().unwrap_or("").trim();
        if key.is_empty() || val.is_empty() {
            return Err("json_invalid".into());
        }
        out.push((key.to_string(), val.to_string()));
    }
    Ok(out)
}

/// 校验后写入。`proxy.pass` 加密存储；`value` 为空串则清除密码。
/// 不调用本函数（或只写其他键）时，已存密码保持不变。
/// `browser.integration_enabled` 为 §9 旧键别名，写入 `browser.enabled`。
///
/// 写入成功后推高 `settings.revision`，
/// 供 UI / 引擎判断"要不要重新读设置"。
pub fn set_validated(conn: &Connection, key: &str, value: &str) -> Result<(), SettingError> {
    let key = normalize_key(key);
    validate(key, value)?;
    // proxy.host / proxy.port 有各自的格式校验（IPv4/IPv6/DNS、端口范围）
    if key == "proxy.host" {
        validate_proxy_host(value)?;
    } else if key == "proxy.port" {
        validate_proxy_port(value)?;
    }
    let stored = if key == PASSWORD_KEY {
        secret::protect(value).map_err(|e| SettingError::msg(format!("secret_protect: {e}")))?
    } else {
        value.to_string()
    };
    set(conn, key, &stored).map_err(|e| SettingError::msg(e.to_string()))?;
    bump_revision(conn).map_err(|e| SettingError::msg(e.to_string()))?;
    Ok(())
}

/// 单调递增的设置版本戳（毫秒时间戳与 `previous + 1` 取大）。
///
/// 为什么不能只存"当前时间"：同一毫秒内的两次写入必须给出不同的版本，
/// 否则 UI 会漏掉一次变更。
pub fn bump_revision(conn: &Connection) -> rusqlite::Result<u64> {
    let now = crate::model::now_ms().max(0) as u64;
    let prev = get(conn, crate::setting_spec::KEY_REVISION)
        .ok()
        .flatten()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    let next = now.max(prev.saturating_add(1));
    set(conn, crate::setting_spec::KEY_REVISION, &next.to_string())?;
    Ok(next)
}

pub fn revision(conn: &Connection) -> u64 {
    get(conn, crate::setting_spec::KEY_REVISION)
        .ok()
        .flatten()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0)
}

/// 对外设置快照：全部 schema 键 + 只读派生项；不含 `proxy.pass`，带 `proxy.has_password`。
///
/// 这是**冷路径**（打开设置页 / UI 查询 / IPC `settings_get`）用的直读实现：
/// 每键一次主键查询，约 65 次。以前它还会顺带调 `ensure_defaults`（最多 60 次写），
/// 那才是"打开一次设置页写上百条 SQL"的来源——默认值现在只在引擎启动时种一次。
///
/// 热路径（调度每拍、每次起任务、限速/超时/UA）不要用它，用 [`Snapshot`]：
/// 那份是解析好的有类型结构，读它不碰数据库。
pub fn public_map(conn: &Connection) -> rusqlite::Result<BTreeMap<String, String>> {
    let mut map = BTreeMap::new();
    for spec in crate::setting_spec::specs() {
        if spec.key == PASSWORD_KEY || spec.key == crate::setting_spec::KEY_REVISION {
            continue;
        }
        let value = get(conn, spec.key)?.unwrap_or_else(|| spec.default.to_string());
        map.insert(spec.key.to_string(), value);
    }
    let has_password = get(conn, PASSWORD_KEY)?
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false);
    map.insert(
        HAS_PASSWORD_KEY.into(),
        if has_password { "true" } else { "false" }.into(),
    );
    map.insert(KEY_APP_VERSION.into(), app_version().into());
    map.insert(
        crate::setting_spec::KEY_REVISION.into(),
        revision(conn).to_string(),
    );
    Ok(map)
}

/// 设置项声明表的 JSON 视图，供 UI 通用渲染（键名不再硬编码在 UI 里）。
pub fn schema_json() -> serde_json::Value {
    use crate::setting_spec::Kind;
    let items: Vec<serde_json::Value> = crate::setting_spec::specs()
        .iter()
        .map(|s| {
            let (kind, min, max, values) = match s.kind {
                Kind::Bool => ("bool", None, None, Vec::new()),
                Kind::Int { min, max } => ("int", Some(min), Some(max), Vec::new()),
                Kind::NonNeg => ("nonneg", Some(0), None, Vec::new()),
                Kind::Enum(v) => ("enum", None, None, v.to_vec()),
                Kind::Text { empty_ok } => ("text", None, None, bool_vec(empty_ok)),
                Kind::Path { empty_ok } => ("path", None, None, bool_vec(empty_ok)),
                Kind::Url { empty_ok } => ("url", None, None, bool_vec(empty_ok)),
                Kind::Cron { empty_ok } => ("cron", None, None, bool_vec(empty_ok)),
                Kind::ExtList => ("ext_list", None, None, Vec::new()),
                Kind::Ed2kServers => ("ed2k_servers", None, None, Vec::new()),
                Kind::HostList => ("host_list", None, None, Vec::new()),
                Kind::JsonMap => ("json_map", None, None, Vec::new()),
                Kind::JsonList => ("id_list", None, None, Vec::new()),
                Kind::Secret => ("secret", None, None, Vec::new()),
                Kind::Clock => ("clock", None, None, Vec::new()),
                Kind::Weekdays => ("weekdays", None, None, Vec::new()),
            };
            let mut obj = serde_json::Map::new();
            obj.insert("key".into(), s.key.into());
            obj.insert("default".into(), s.default.into());
            obj.insert("kind".into(), kind.into());
            obj.insert("section".into(), s.section.as_str().into());
            obj.insert("scope".into(), s.scope.as_str().into());
            obj.insert("apply".into(), s.apply.as_str().into());
            obj.insert("label".into(), s.label.into());
            obj.insert("readonly".into(), s.readonly.into());
            obj.insert("secret".into(), s.secret.into());
            if let Some(v) = min {
                obj.insert("min".into(), v.into());
            }
            if let Some(v) = max {
                obj.insert("max".into(), v.into());
            }
            if !values.is_empty() {
                obj.insert("values".into(), values.into());
            }
            serde_json::Value::Object(obj)
        })
        .collect();
    serde_json::Value::Array(items)
}

fn bool_vec(empty_ok: bool) -> Vec<&'static str> {
    if empty_ok {
        vec!["empty_ok"]
    } else {
        Vec::new()
    }
}

/// 解析好的只读设置快照。
///
/// 为什么要它：调度器每拍（1 s）要用闸门、cron、时段、配额、代理排除表；
/// 下载线程每次启动要用连接数、限速、超时。如果每次都用 `settings::get`，
/// 就要反复拿全局 DB 锁做几十次查询、反复解析 cron 与主机模式串——这正是
/// UI 卡顿与调度抖动的来源。这里**一次解析**，之后全是内存读取。
#[derive(Debug, Clone)]
pub struct Snapshot {
    /// 生成这份快照时的设置版本；与 `settings.revision` 不等即需重载
    pub revision: u64,
    /// 原始键值（含只读派生项，不含明文密码）
    values: BTreeMap<String, String>,
    pub gates: sched::Gates,
    pub cron: Option<cron::CronExpr>,
    pub window: sched::RunWindow,
    pub quota: sched::Quota,
    pub after_done: sched::AfterDone,
    pub after_done_force: bool,
    pub duplicate_action: String,
    pub default_dir: String,
    pub category_dirs: Vec<(String, String)>,
    pub proxied_hosts_skip: Vec<String>,
    pub proxy_only_for: String,
    pub intercept_exclude_hosts: Vec<String>,
    pub auto_catch_exts: Vec<String>,
    pub panel_exts: Vec<String>,
    pub panel_exclude_hosts: Vec<String>,
    pub panel_enabled: bool,
    pub click_takeover: bool,
    pub skip_html: bool,
    pub monitor_clipboard: bool,
    pub hotkey_prevent: String,
    pub hotkey_force: String,
    pub limit_kbps: u64,
    pub default_task_limit_kbps: u64,
    pub connect_timeout_s: u64,
    pub idle_timeout_s: u64,
    pub retry_max: u64,
    pub retry_backoff_ms: u64,
    pub recv_buf_kb: u64,
    pub fastdl: bool,
    pub verify_sha256: bool,
    pub user_agent: String,
    pub sound_complete: String,
    pub sound_file_complete: String,
    pub sound_error: String,
    pub sound_file_error: String,
    pub notify_on_complete: bool,
    pub confirm_on_delete: bool,
    pub remember_last_dir: bool,
    pub tray_icon: bool,
    pub language: String,
}

impl Snapshot {
    /// 从库中读出并一次性解析全部派生量。
    ///
    /// 只做读取，不做 `ensure_defaults`（默认值种子只在引擎启动时跑一次；
    /// 以前 `public_map` 每次都会尝试写 60 个键，等于每次打开设置页
    /// 就是上百条 SQL）。
    pub fn load(conn: &Connection) -> rusqlite::Result<Self> {
        let mut values = BTreeMap::new();
        for spec in setting_spec::specs() {
            if spec.key == PASSWORD_KEY {
                continue;
            }
            let v = get(conn, spec.key)?.unwrap_or_else(|| spec.default.to_string());
            values.insert(spec.key.to_string(), v);
        }
        let revision = revision(conn);
        Ok(Self::from_values(revision, values))
    }

    /// 无库（测试 / 纯逻辑）时的默认快照。
    pub fn defaults() -> Self {
        let values = setting_spec::specs()
            .iter()
            .filter(|s| s.key != PASSWORD_KEY)
            .map(|s| (s.key.to_string(), s.default.to_string()))
            .collect();
        Self::from_values(0, values)
    }

    /// "尚未装载"的哨兵：派生字段取默认值，但 `is_empty()` 为真，
    /// 所以 `DownloadManager` 第一次访问一定会回库装载。
    pub fn unloaded() -> Self {
        Self::from_values(0, BTreeMap::new())
    }

    fn from_values(revision: u64, values: BTreeMap<String, String>) -> Self {
        let s = |k: &str| values.get(k).cloned().unwrap_or_default();
        let b = |k: &str| s(k).trim() == "true";
        let n = |k: &str| s(k).trim().parse::<u64>().unwrap_or(0);
        let snap = Self {
            revision,
            values: BTreeMap::new(),
            gates: sched::Gates {
                max_conns_total: n("conn.global_conn_cap"),
            },
            cron: cron::parse(&s("sched.start_cron")).ok().flatten(),
            window: sched::RunWindow::parse(
                b("sched.window_enabled"),
                &s("sched.window_start"),
                &s("sched.window_end"),
                &s("sched.window_days"),
            ),
            quota: sched::Quota::parse(
                b("sched.quota_enabled"),
                n("sched.quota_mb"),
                &s("sched.quota_period"),
                &s("sched.quota_action"),
            ),
            after_done: sched::AfterDone::parse(&s("sched.after_done")),
            after_done_force: b("sched.after_done_force"),
            duplicate_action: s("ui.duplicate_action"),
            default_dir: s("paths.default_dir"),
            category_dirs: parse_json_map(&s("paths.category_dirs")).unwrap_or_default(),
            proxied_hosts_skip: parse_host_list(&s("proxy.bypass_hosts")).unwrap_or_default(),
            proxy_only_for: s("proxy.only_for"),
            intercept_exclude_hosts: parse_host_list(&s("browser.exclude_hosts"))
                .unwrap_or_default(),
            auto_catch_exts: parse_ext_list(&s("browser.auto_catch_exts")).unwrap_or_default(),
            panel_exts: parse_ext_list(&s("browser.panel_exts")).unwrap_or_default(),
            panel_exclude_hosts: parse_host_list(&s("browser.panel_exclude_hosts"))
                .unwrap_or_default(),
            panel_enabled: b("browser.panel_enabled"),
            click_takeover: b("browser.click_takeover"),
            skip_html: b("browser.skip_html"),
            monitor_clipboard: b("browser.monitor_clipboard"),
            hotkey_prevent: s("browser.hotkey_prevent"),
            hotkey_force: s("browser.hotkey_force"),
            limit_kbps: n("speed.global_limit_kbps"),
            default_task_limit_kbps: n("conn.speed_limit_default_kbps"),
            connect_timeout_s: n("conn.timeout_connect_s"),
            idle_timeout_s: n("conn.timeout_idle_s"),
            retry_max: n("conn.retry_max"),
            retry_backoff_ms: n("conn.retry_backoff_ms"),
            recv_buf_kb: n("net.recv_buf_kb"),
            fastdl: b("engine.fastdl"),
            verify_sha256: b("verify.sha256_after"),
            user_agent: s("net.user_agent"),
            sound_complete: s("ui.sound_complete"),
            sound_file_complete: s("ui.sound_file_complete"),
            sound_error: s("ui.sound_error"),
            sound_file_error: s("ui.sound_file_error"),
            notify_on_complete: b("ui.notify_on_complete"),
            confirm_on_delete: b("ui.confirm_on_delete"),
            remember_last_dir: b("paths.remember_last_dir"),
            tray_icon: b("general.tray_icon"),
            language: s("general.language"),
        };
        // `values` 是 `BTreeMap`，上面三个闭包都只是借用；NLL 到此已结束，
        // 这里直接把它搬进结构体，不需要（也做不到）显式 drop 闭包。
        Snapshot { values, ..snap }
    }

    pub fn raw(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(String::as_str)
    }

    /// 尚未装载过（`DownloadManager` 用它判断要不要回库读一次）。
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn raw_map(&self) -> &BTreeMap<String, String> {
        &self.values
    }

    pub fn bool_of(&self, key: &str) -> bool {
        self.raw(key).map(|v| v.trim() == "true").unwrap_or(false)
    }

    /// 某个主机是否命中"不接管"排除表（精确或 `*.` 通配）。
    pub fn host_excluded(&self, host: &str) -> bool {
        sched::host_matches_any(&self.intercept_exclude_hosts, host)
    }

    /// 某个主机是否命中"不走代理"表。
    pub fn host_bypasses_proxy(&self, host: &str) -> bool {
        sched::host_matches_any(&self.proxied_hosts_skip, host)
    }

    /// 某个主机是否命中"不显示悬浮面板"表。
    pub fn host_panel_excluded(&self, host: &str) -> bool {
        sched::host_matches_any(&self.panel_exclude_hosts, host)
    }

    /// 按扩展名挑分类目录。
    ///
    /// 先精确匹配扩展名，再退回 `*` 兜底——顺序不能靠 map 的迭代顺序决定
    /// （JSON 对象的键序在 serde_json 里是字典序）。
    pub fn category_dir(&self, file_name: &str) -> Option<&str> {
        let ext = std::path::Path::new(file_name)
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())?;
        if let Some((_, v)) = self
            .category_dirs
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(&ext))
        {
            return Some(v.as_str());
        }
        self.category_dirs
            .iter()
            .find(|(k, _)| k == "*")
            .map(|(_, v)| v.as_str())
    }
}

pub fn update_channel(conn: &Connection) -> String {
    match get(conn, KEY_UPDATE_CHANNEL)
        .ok()
        .flatten()
        .unwrap_or_else(|| "stable".into())
        .trim()
    {
        "beta" => "beta".into(),
        _ => "stable".into(),
    }
}

/// `update.auto_check`，缺省 true。
pub fn update_auto_check(conn: &Connection) -> bool {
    get(conn, KEY_UPDATE_AUTO_CHECK)
        .ok()
        .flatten()
        .map(|s| s.trim() == "true")
        .unwrap_or(true)
}

/// 解析 version.json 根：设置 > 环境变量 `AIDM_UPDATE_MANIFEST_BASE_URL` > 占位默认。
pub fn resolve_manifest_base_url(conn: &Connection) -> String {
    let from_setting = get(conn, KEY_UPDATE_MANIFEST_BASE_URL)
        .ok()
        .flatten()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    if let Some(s) = from_setting {
        return s;
    }
    std::env::var("AIDM_UPDATE_MANIFEST_BASE_URL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_MANIFEST_BASE_URL.to_string())
}

/// 清单 URL。
///
/// GitHub Release 资产不支持目录：`.../latest/download` 下用
/// `version-{channel}.json`；自建服务器仍保留 `{base}/{channel}/version.json`。
pub fn manifest_url(base: &str, channel: &str) -> String {
    let base = base.trim().trim_end_matches('/');
    let channel = channel.trim().trim_matches('/');
    if base.contains("/releases/") || base.ends_with("/download") {
        format!("{base}/version-{channel}.json")
    } else {
        format!("{base}/{channel}/version.json")
    }
}

/// 引擎在检查后写入"上次检查时间"（只读键，由引擎维护）。
///
/// 这里也推高 `settings.revision`：它确实是设置状态的变化，
/// 让读方（UI/引擎快照）能察觉。
pub fn write_last_check_at(conn: &Connection, unix_ms: i64) -> rusqlite::Result<()> {
    set(conn, KEY_UPDATE_LAST_CHECK_AT, &unix_ms.to_string())?;
    bump_revision(conn).map(|_| ())
}

fn validate_manifest_base_url(value: &str) -> Result<(), SettingError> {
    let s = value.trim();
    if s.is_empty() {
        return Ok(());
    }
    let lower = s.to_ascii_lowercase();
    if !(lower.starts_with("https://") || lower.starts_with("http://")) {
        return Err(SettingError::msg("manifest_base_url_invalid"));
    }
    if s.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(SettingError::msg("manifest_base_url_invalid"));
    }
    Ok(())
}

pub fn speed_limit_kbps(conn: &Connection) -> u64 {
    get(conn, "speed.global_limit_kbps")
        .ok()
        .flatten()
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|n| *n >= 0)
        .map(|n| n as u64)
        .unwrap_or(0)
}

pub fn parse_allowed_ext_ids(value: &str) -> Result<Vec<String>, String> {
    let parsed: serde_json::Value =
        serde_json::from_str(value.trim()).map_err(|_| "allowed_ext_ids_invalid".to_string())?;
    let arr = parsed
        .as_array()
        .ok_or_else(|| "allowed_ext_ids_invalid".to_string())?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let id = item
            .as_str()
            .ok_or_else(|| "allowed_ext_ids_invalid".to_string())?
            .trim();
        if id.is_empty() || id.len() > 128 {
            return Err("allowed_ext_ids_invalid".into());
        }
        out.push(id.to_string());
    }
    Ok(out)
}

/// §5 三层闸门 + 按主机限流的当前有效值（区间与默认值都取自 schema）。
pub fn sched_gates(conn: &Connection) -> sched::Gates {
    sched::Gates {
        max_conns_total: int_setting(conn, "conn.global_conn_cap"),
    }
}

pub fn start_cron(conn: &Connection) -> Option<cron::CronExpr> {
    get(conn, "sched.start_cron")
        .ok()
        .flatten()
        .and_then(|s| cron::parse(&s).ok().flatten())
}

pub fn retry_limits(conn: &Connection) -> (u64, u64) {
    (
        int_setting(conn, "conn.retry_max"),
        int_setting(conn, "conn.retry_backoff_ms"),
    )
}

/// O(1) 键 -> spec 索引（避免每次校验都线性扫 ~60 项做字符串比较）。
fn index() -> &'static std::collections::HashMap<&'static str, &'static Spec> {
    static IDX: OnceLock<std::collections::HashMap<&'static str, &'static Spec>> = OnceLock::new();
    IDX.get_or_init(|| setting_spec::specs().iter().map(|s| (s.key, s)).collect())
}

/// 快查（大小写敏感，键名是程序内部常量）。
pub fn spec_of(key: &str) -> Option<&'static Spec> {
    index().get(key).copied()
}

/// 某个键的声明默认值（不在 schema 里返回 None）。
pub fn default_of(key: &str) -> Option<&'static str> {
    crate::setting_spec::get(key).map(|s| s.default)
}

/// 某个整数键的声明区间（不在 schema 里或不是整数键返回 None）。
pub fn range_of(key: &str) -> Option<(i64, i64)> {
    match crate::setting_spec::get(key)?.kind {
        crate::setting_spec::Kind::Int { min, max } => Some((min, max)),
        _ => None,
    }
}

/// `conn.global_conn_cap` 等整数键的当前有效值（缺省与区间都来自 schema）。
fn int_setting(conn: &Connection, key: &str) -> u64 {
    let Some(spec) = crate::setting_spec::get(key) else {
        return 0;
    };
    let (default, min, max) = match spec.kind {
        crate::setting_spec::Kind::Int { min, max } => {
            (spec.default.parse::<i64>().unwrap_or(min), min, max)
        }
        _ => (spec.default.parse::<i64>().unwrap_or(0), i64::MIN, i64::MAX),
    };
    get(conn, key)
        .ok()
        .flatten()
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|n| *n >= min && *n <= max)
        .unwrap_or(default)
        .max(0) as u64
}

/// `browser.enabled`；旧库仅有 `browser.integration_enabled` 时回退。
pub fn browser_enabled(conn: &Connection) -> bool {
    let raw = get(conn, "browser.enabled")
        .ok()
        .flatten()
        .or_else(|| get(conn, "browser.integration_enabled").ok().flatten())
        .unwrap_or_else(|| "true".into());
    raw.trim() == "true"
}

pub fn allowed_ext_ids(conn: &Connection) -> Vec<String> {
    let raw = get(conn, "browser.allowed_ext_ids")
        .ok()
        .flatten()
        .unwrap_or_else(|| r#"["npapgdblbbcppnbmhgdnmdbggfdnpahg"]"#.into());
    parse_allowed_ext_ids(&raw).unwrap_or_default()
}

fn parse_bool(value: &str) -> Result<(), SettingError> {
    match value.trim() {
        "true" | "false" => Ok(()),
        _ => Err(SettingError::msg("bool_invalid")),
    }
}

fn parse_nonneg_int(value: &str, err: &str) -> Result<u64, SettingError> {
    let s = value.trim();
    if s.starts_with('-') {
        return Err(SettingError::msg(err));
    }
    s.parse::<u64>().map_err(|_| SettingError::msg(err))
}

fn parse_range_key(key: &str, value: &str, range: (i64, i64)) -> Result<(), SettingError> {
    let n: i64 = value
        .trim()
        .parse()
        .map_err(|_| SettingError::invalid_value(key, range.0, range.1))?;
    if n < range.0 || n > range.1 {
        return Err(SettingError::invalid_value(key, range.0, range.1));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_db;
    use std::path::Path;

    fn mem() -> Connection {
        open_db(Path::new(":memory:")).unwrap()
    }

    #[test]
    fn set_then_get_roundtrip() {
        let conn = mem();
        set(&conn, "general.language", "en-US").unwrap();
        assert_eq!(get(&conn, "general.language").unwrap().unwrap(), "en-US");
    }

    #[test]
    fn get_missing_returns_none() {
        let conn = mem();
        assert!(get(&conn, "nope").unwrap().is_none());
    }

    #[test]
    fn set_overwrites() {
        let conn = mem();
        set(&conn, "k", "v1").unwrap();
        set(&conn, "k", "v2").unwrap();
        assert_eq!(get(&conn, "k").unwrap().unwrap(), "v2");
    }

    #[test]
    fn ensure_defaults_seeds_and_preserves_user_values() {
        let conn = mem();
        set(&conn, "general.language", "en-US").unwrap();
        ensure_defaults(&conn).unwrap();
        assert_eq!(get(&conn, "general.language").unwrap().unwrap(), "en-US");
        assert_eq!(get(&conn, "conn.global_conn_cap").unwrap().unwrap(), "256");
        assert_eq!(get(&conn, "proxy.mode").unwrap().unwrap(), "follow-system");
        // 种子表要覆盖所有可写键（只读项与密值不种）
        let seeded: i64 = conn
            .query_row("SELECT COUNT(*) FROM setting_seeds", [], |r| r.get(0))
            .unwrap();
        assert_eq!(seeded as usize, defaults().count());
    }

    /// 默认值随版本调整时：用户没改过的键跟着升级，用户改过的一律不动。
    ///
    /// 这就是"默认配置升级"能真正生效的关键——只补缺失键的做法，
    /// 会让老库永远停在旧默认值上。
    #[test]
    fn defaults_upgrade_only_for_untouched_keys() {
        let conn = mem();
        ensure_defaults(&conn).unwrap();
        let sound_default = crate::setting_spec::get("ui.sound_complete")
            .unwrap()
            .default;
        assert_eq!(
            get(&conn, "ui.sound_complete").unwrap().unwrap(),
            sound_default
        );

        // ① 用户改过：值 != 种子 → 不覆盖
        set(&conn, "ui.sound_complete", "none").unwrap();
        ensure_defaults(&conn).unwrap();
        assert_eq!(get(&conn, "ui.sound_complete").unwrap().unwrap(), "none");

        // ② 从旧版本升上来：值和种子都还是旧默认值 → 升级到新默认值
        set(&conn, "ui.sound_error", "legacy-old-default").unwrap();
        conn.execute(
            "UPDATE setting_seeds SET seeded_value = ?2 WHERE key = ?1",
            rusqlite::params!["ui.sound_error", "legacy-old-default"],
        )
        .unwrap();
        ensure_defaults(&conn).unwrap();
        let new_default = crate::setting_spec::get("ui.sound_error").unwrap().default;
        assert_eq!(
            get(&conn, "ui.sound_error").unwrap().unwrap(),
            new_default,
            "没被用户改过的键应跟随新默认值"
        );

        // ③ 升级后种子同步，第二次运行幂等
        let seeded: String = conn
            .query_row(
                "SELECT seeded_value FROM setting_seeds WHERE key = 'ui.sound_error'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(seeded, new_default);
        ensure_defaults(&conn).unwrap();
        assert_eq!(get(&conn, "ui.sound_error").unwrap().unwrap(), new_default);

        // ④ 早期版本没有种子记录：现值等于**已知的旧默认值**时升级，
        //    其余情况只补记录、不动现值。
        set(&conn, "ui.sound_file_error", "user-set-path.wav").unwrap();
        conn.execute(
            "DELETE FROM setting_seeds WHERE key = 'ui.sound_file_error'",
            [],
        )
        .unwrap();
        ensure_defaults(&conn).unwrap();
        assert_eq!(
            get(&conn, "ui.sound_file_error").unwrap().unwrap(),
            "user-set-path.wav"
        );
    }

    /// 一次性过渡：老库里"没改过"的键要跟上新默认值，改过的一律不动。
    #[test]
    fn legacy_defaults_migrate_once() {
        let conn = mem();
        // 造一个"上一版留下的库"：没有 setting_seeds，两个键分别停在
        // 旧默认值与用户自定义值上
        set(&conn, "ui.sound_complete", "none").unwrap(); // 旧默认值
        set(&conn, "ui.sound_error", "file").unwrap(); // 用户改过
        set(&conn, "browser.hotkey_prevent", "").unwrap(); // 旧默认值（空）
        ensure_defaults(&conn).unwrap();

        assert_eq!(
            get(&conn, "ui.sound_complete").unwrap().unwrap(),
            "beep",
            "停在旧默认值的键应升到新默认值"
        );
        assert_eq!(
            get(&conn, "ui.sound_error").unwrap().unwrap(),
            "file",
            "用户改过的键不得被覆盖"
        );
        assert_eq!(
            get(&conn, "browser.hotkey_prevent").unwrap().unwrap(),
            "del",
            "旧默认空串也要升级"
        );
        // 升级完种子记录与现值一致，再跑一次不会二次改动
        ensure_defaults(&conn).unwrap();
        assert_eq!(get(&conn, "ui.sound_complete").unwrap().unwrap(), "beep");
    }

    #[test]
    fn reject_unknown_and_invalid() {
        let conn = mem();
        assert_eq!(
            set_validated(&conn, "not.a.key", "1").unwrap_err().code,
            "unknown_setting_key"
        );
        assert_eq!(
            set_validated(&conn, "speed.global_limit_kbps", "-1")
                .unwrap_err()
                .code,
            "speed_limit_invalid"
        );
        assert!(get(&conn, "speed.global_limit_kbps").unwrap().is_none());
        assert_eq!(
            set_validated(&conn, "proxy.host", "http://bad")
                .unwrap_err()
                .code,
            "proxy_host_malformed"
        );
        assert_eq!(
            set_validated(&conn, "proxy.port", "99999")
                .unwrap_err()
                .code,
            "proxy_port_malformed"
        );
        assert_eq!(
            set_validated(&conn, "proxy.port", "-1").unwrap_err().code,
            "proxy_port_malformed"
        );
        set_validated(&conn, "speed.global_limit_kbps", "512").unwrap();
        assert_eq!(
            get(&conn, "speed.global_limit_kbps").unwrap().unwrap(),
            "512"
        );
    }

    #[test]
    fn ed2k_servers_accept_host_port_lists_and_reject_garbage() {
        // 空 = 不查服务器（默认），必须合法
        assert_eq!(parse_ed2k_servers("").unwrap(), vec![]);
        assert_eq!(parse_ed2k_servers("  ").unwrap(), vec![]);
        // 单台 / 多台 / 分隔符混用 / 去重
        assert_eq!(
            parse_ed2k_servers("1.2.3.4:4662").unwrap(),
            vec![("1.2.3.4".to_string(), 4662)]
        );
        assert_eq!(
            parse_ed2k_servers("1.2.3.4:4662, 5.6.7.8:5000;example.com:4242").unwrap(),
            vec![
                ("1.2.3.4".to_string(), 4662),
                ("5.6.7.8".to_string(), 5000),
                ("example.com".to_string(), 4242),
            ]
        );
        assert_eq!(
            parse_ed2k_servers("1.2.3.4:4662,1.2.3.4:4662,").unwrap(),
            vec![("1.2.3.4".to_string(), 4662)]
        );
        assert_eq!(
            parse_ed2k_servers("[::1]:4662").unwrap(),
            vec![("::1".to_string(), 4662)]
        );
        // 非法：缺端口 / 端口 0 或超范围 / 空主机 / 超过 16 台
        for bad in [
            "noport",
            "1.2.3.4:0",
            "1.2.3.4:70000",
            ":4662",
            "1.2.3.4:abc",
        ] {
            assert!(parse_ed2k_servers(bad).is_err(), "{bad} 应被拒绝");
        }
        let many = (1..=17)
            .map(|i| format!("10.0.0.{i}:4662"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(parse_ed2k_servers(&many).is_err(), "超过 16 台应被拒绝");
        // 落库路径：非法值进不去，合法值可读回
        let conn = mem();
        assert_eq!(
            set_validated(&conn, "ed2k.servers", "noport")
                .unwrap_err()
                .code,
            "ed2k_servers_invalid"
        );
        set_validated(&conn, "ed2k.servers", "1.2.3.4:4662").unwrap();
        assert_eq!(get(&conn, "ed2k.servers").unwrap().unwrap(), "1.2.3.4:4662");
    }

    #[test]
    fn password_not_plaintext_and_redacted() {
        let conn = mem();
        set_validated(&conn, "proxy.pass", "hunter2-secret").unwrap();
        let raw = get(&conn, "proxy.pass").unwrap().unwrap();
        assert!(!raw.contains("hunter2-secret"), "plaintext leaked: {raw}");
        assert!(secret::is_protected(&raw), "expected protected blob: {raw}");
        let pubmap = public_map(&conn).unwrap();
        assert!(!pubmap.contains_key("proxy.pass"));
        assert_eq!(
            pubmap.get("proxy.has_password").map(String::as_str),
            Some("true")
        );
        assert_eq!(secret::unprotect(&raw).unwrap(), "hunter2-secret");
    }

    #[test]
    fn empty_password_clears_omitting_key_leaves_it() {
        let conn = mem();
        set_validated(&conn, "proxy.pass", "hunter2-secret").unwrap();
        set_validated(&conn, "proxy.user", "alice").unwrap();
        let raw = get(&conn, "proxy.pass").unwrap().unwrap();
        assert!(secret::is_protected(&raw), "other key must not clear pass");
        assert_eq!(
            public_map(&conn)
                .unwrap()
                .get("proxy.has_password")
                .map(String::as_str),
            Some("true")
        );
        set_validated(&conn, "proxy.pass", "").unwrap();
        assert_eq!(get(&conn, "proxy.pass").unwrap().unwrap(), "");
        assert_eq!(
            public_map(&conn)
                .unwrap()
                .get("proxy.has_password")
                .map(String::as_str),
            Some("false")
        );
    }

    #[test]
    fn public_map_lists_section9_keys() {
        let conn = mem();
        let map = public_map(&conn).unwrap();
        for (k, _) in defaults() {
            assert!(map.contains_key(k), "missing {k}");
        }
        assert_eq!(
            map.get("proxy.has_password").map(String::as_str),
            Some("false")
        );
        assert!(!map.contains_key("proxy.pass"));
        assert_eq!(map.get("browser.enabled").map(String::as_str), Some("true"));
        assert!(map
            .get("browser.allowed_ext_ids")
            .unwrap()
            .contains("npapgdblbbcppnbmhgdnmdbggfdnpahg"));
        assert_eq!(
            map.get("update.channel").map(String::as_str),
            Some("stable")
        );
        assert_eq!(
            map.get("update.auto_check").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            map.get("update.last_check_at").map(String::as_str),
            Some("")
        );
        assert_eq!(
            map.get("update.manifest_base_url").map(String::as_str),
            Some("")
        );
        assert_eq!(
            map.get(KEY_APP_VERSION).map(String::as_str),
            Some(app_version())
        );
    }

    #[test]
    fn update_keys_validate_and_readonly() {
        let conn = mem();
        set_validated(&conn, "update.channel", "beta").unwrap();
        assert_eq!(update_channel(&conn), "beta");
        assert_eq!(
            set_validated(&conn, "update.channel", "nightly")
                .unwrap_err()
                .code,
            "update_channel_invalid"
        );
        set_validated(&conn, "update.auto_check", "false").unwrap();
        assert!(!update_auto_check(&conn));
        assert_eq!(
            set_validated(&conn, "update.auto_check", "yes")
                .unwrap_err()
                .code,
            "bool_invalid"
        );
        assert_eq!(
            set_validated(&conn, KEY_UPDATE_LAST_CHECK_AT, "1")
                .unwrap_err()
                .code,
            "setting_readonly"
        );
        assert_eq!(
            set_validated(&conn, KEY_APP_VERSION, "9.9.9")
                .unwrap_err()
                .code,
            "setting_readonly"
        );
        write_last_check_at(&conn, 1_700_000_000_000).unwrap();
        assert_eq!(
            get(&conn, KEY_UPDATE_LAST_CHECK_AT).unwrap().as_deref(),
            Some("1700000000000")
        );
        set_validated(&conn, "update.manifest_base_url", "").unwrap();
        set_validated(
            &conn,
            "update.manifest_base_url",
            "https://releases.example/app",
        )
        .unwrap();
        assert_eq!(
            set_validated(&conn, "update.manifest_base_url", "ftp://x/")
                .unwrap_err()
                .code,
            "manifest_base_url_invalid"
        );
        assert_eq!(
            manifest_url("https://releases.aidm.dev/app/", "stable"),
            "https://releases.aidm.dev/app/stable/version.json"
        );
    }

    #[test]
    fn browser_keys_validate() {
        let conn = mem();
        assert_eq!(
            set_validated(&conn, "browser.enabled", "maybe")
                .unwrap_err()
                .code,
            "bool_invalid"
        );
        set_validated(&conn, "browser.integration_enabled", "false").unwrap();
        assert_eq!(get(&conn, "browser.enabled").unwrap().unwrap(), "false");
        assert!(get(&conn, "browser.integration_enabled").unwrap().is_none());
        assert_eq!(
            set_validated(&conn, "browser.allowed_ext_ids", "not-json")
                .unwrap_err()
                .code,
            "allowed_ext_ids_invalid"
        );
        set_validated(&conn, "browser.allowed_ext_ids", r#"["abcd"]"#).unwrap();
        assert_eq!(allowed_ext_ids(&conn), vec!["abcd".to_string()]);
        set_validated(&conn, "browser.click_takeover", "true").unwrap();
    }

    #[test]
    fn range_and_cron_structured_errors() {
        let conn = mem();
        let e = set_validated(&conn, "conn.global_conn_cap", "0").unwrap_err();
        assert_eq!((e.min, e.max), (Some(1), Some(1024)));
        let e = set_validated(&conn, "conn.retry_max", "-1").unwrap_err();
        assert_eq!((e.min, e.max), (Some(0), Some(20)));
        let e = set_validated(&conn, "conn.retry_backoff_ms", "50").unwrap_err();
        assert_eq!((e.min, e.max), (Some(100), Some(60_000)));
        let e = set_validated(&conn, "sched.start_cron", "not cron").unwrap_err();
        assert_eq!(e.code, "invalid_cron");
        assert_eq!(e.key.as_deref(), Some("sched.start_cron"));
        set_validated(&conn, "sched.start_cron", "").unwrap();
        set_validated(&conn, "sched.start_cron", "0 2 * * *").unwrap();
        set_validated(&conn, "sched.after_done", "none").unwrap();
        // 完成后动作支持 退出/关机/休眠/待机/断开
        set_validated(&conn, "sched.after_done", "shutdown").unwrap();
        set_validated(&conn, "sched.after_done", "hibernate").unwrap();
        set_validated(&conn, "sched.after_done", "disconnect").unwrap();
        assert_eq!(
            set_validated(&conn, "sched.after_done", "reboot")
                .unwrap_err()
                .code,
            "after_done_invalid"
        );
        set_validated(&conn, "sched.after_done", "none").unwrap();
        assert_eq!(
            get(&conn, "sched.after_done").unwrap().as_deref(),
            Some("none")
        );
    }

    #[test]
    fn revision_advances_on_every_write() {
        let conn = mem();
        assert_eq!(revision(&conn), 0);
        set_validated(&conn, "speed.global_limit_kbps", "128").unwrap();
        let r1 = revision(&conn);
        assert!(r1 > 0);
        set_validated(&conn, "speed.global_limit_kbps", "256").unwrap();
        let r2 = revision(&conn);
        assert!(r2 > r1, "同一毫秒内的两次写入也必须拿到不同版本");
        // 只读键不可写
        assert_eq!(
            set_validated(&conn, crate::setting_spec::KEY_REVISION, "1")
                .unwrap_err()
                .code,
            "setting_readonly"
        );
        let map = public_map(&conn).unwrap();
        assert_eq!(
            map.get(crate::setting_spec::KEY_REVISION)
                .map(String::as_str),
            Some(r2.to_string().as_str())
        );
    }

    #[test]
    fn undeclared_keys_are_rejected_not_silently_accepted() {
        // 这条就是本次架构修正要钉住的行为：以前 validate() 末尾的
        // `_ => Ok(())` 会让任何"漏写校验分支"的键静默通过任意值。
        let conn = mem();
        for k in [
            "conn.timeout_connect_sX",
            "paths.temp_dir",
            "engine.fastdl.typo",
            "",
        ] {
            let e = set_validated(&conn, k, "whatever").unwrap_err();
            assert_eq!(e.code, "unknown_setting_key", "键 {k:?} 不应被接受");
        }
    }

    #[test]
    fn snapshot_parses_once_and_matches_db() {
        let conn = mem();
        ensure_defaults(&conn).unwrap();
        set_validated(&conn, "conn.global_conn_cap", "512").unwrap();
        set_validated(&conn, "sched.start_cron", "0 3 * * *").unwrap();
        set_validated(
            &conn,
            "proxy.bypass_hosts",
            "127.0.0.1, *.internal.example.com",
        )
        .unwrap();
        set_validated(
            &conn,
            "paths.category_dirs",
            r#"{"iso":"D:\\iso","*":"D:\\dl"}"#,
        )
        .unwrap();

        let snap = Snapshot::load(&conn).unwrap();
        assert_eq!(snap.gates.max_conns_total, 512);
        assert!(snap.cron.is_some());
        assert!(snap.host_bypasses_proxy("127.0.0.1"));
        assert!(snap.host_bypasses_proxy("a.internal.example.com"));
        assert!(!snap.host_bypasses_proxy("example.com"));
        assert_eq!(snap.category_dir("x.iso"), Some("D:\\iso"));
        assert_eq!(snap.category_dir("x.bin"), Some("D:\\dl"));
        assert_eq!(snap.revision, revision(&conn));
        // 快照是纯内存的：改库后旧快照不变，直到重新 load
        set_validated(&conn, "conn.global_conn_cap", "256").unwrap();
        assert_eq!(snap.gates.max_conns_total, 512);
        assert_ne!(Snapshot::load(&conn).unwrap().revision, snap.revision);
    }
}

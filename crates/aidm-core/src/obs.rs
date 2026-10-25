//! 结构化日志底座（`docs/download-observability.md` §3 的实现）。
//!
//! 出口只有一个：[`init`]。它按角色（`engine` / `ui` / `ext-host`）装配一个
//! tracing subscriber，输出 **JSON 行** —— 一行一条事件、字段扁平，便于 grep，
//! 也便于后续原样收进诊断包。三件事在这里一次做掉，调用方不必记得：
//!
//! 1. **脱敏**：自由文本字段按字段名走 [`crate::redact`]（URL / 用户路径 / 请求头）；
//! 2. **限流**：全局令牌桶（默认 200 行/秒），超出丢弃并累计 `suppressed`；
//! 3. **落盘**：`paths::logs_dir()/aidm-<role>.log`，超过 32 MB 轮转为 `.log.1`。
//!
//! 字段约定（不变量 I1，见规格 §2）：进程级事件带 `role`；任务级事件带 `task`；
//! 阶段事件再带 `phase`。`task`/`attempt`/`seg`/`conn` 可以直接写在事件上
//! （`info!(task = id, phase = "connect", ...)`），也可以写在 span 上
//! （[`task_span`] 或 `#[instrument]`）—— span 字段会被展平进同一行，所以
//! 进程日志与 `events` 表一样能按任务过滤。
//!
//! `log` crate 的既有调用点经 `LogTracer` 桥接进同一通路，
//! 因此不必一次改完所有 `log::info!`。

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use serde_json::{Map, Value};
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::fmt::format::{FormatEvent, FormatFields, Writer as FmtWriter};
use tracing_subscriber::fmt::{FmtContext, FormattedFields};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;

use crate::redact;

/// 全局行数上限（行/秒）。正常路径单任务 ≤20 行，这里是防「单任务风暴淹没多任务」的兜底。
const DEFAULT_LINES_PER_SEC: u64 = 200;
/// 单个日志文件上限；超过后轮转为 `*.log.1`（只留一代，避免无界增长）。
const MAX_LOG_BYTES: u64 = 32 * 1024 * 1024;

/// 引擎/前端实例启动时刻（毫秒）。用来区分「同一次运行」与「重启后的同名尝试」。
static EPOCH: AtomicU64 = AtomicU64::new(0);
static LOG_PATH: OnceLock<PathBuf> = OnceLock::new();
static LOG_FILE: OnceLock<Mutex<File>> = OnceLock::new();
static LIMITER: OnceLock<LineLimiter> = OnceLock::new();

/// 当前进程实例的启动时刻（毫秒，0 表示未初始化）。
pub fn epoch() -> u64 {
    EPOCH.load(Ordering::Relaxed)
}

/// 携带任务身份的 span：字段会被展平进该 span 内所有日志行。
///
/// ```ignore
/// let _sp = obs::task_span("download", task_id);
/// tracing::info!(event = "net.connect", phase = "connect", dur_ms = 12);
/// ```
pub fn task_span(op: &'static str, task: i64) -> tracing::Span {
    tracing::info_span!("aidm_task", op, task)
}

/// 进入任务上下文，drop 时自动退出。同步路径（下载 worker）用这个最省事。
///
/// ```ignore
/// let _task = obs::enter_task("download", task_id);
/// tracing::info!(event = "net.connect", phase = "connect", dur_ms = 12);
/// ```
///
/// 注意：`EnteredSpan` **不能跨 `.await`**；异步路径请改用
/// [`task_span`] + `.instrument(fut)`。
pub fn enter_task(op: &'static str, task: i64) -> tracing::span::EnteredSpan {
    task_span(op, task).entered()
}

/// 初始化结构化日志。重复调用安全（第二次起静默返回）。
///
/// `role` 进日志文件名与 `role` 字段；`default_filter` 在 `RUST_LOG` 缺失时生效。
pub fn init(role: &str, default_filter: &str) {
    init_at(&crate::paths::logs_dir(), role, default_filter);
}

/// 与 [`init`] 相同，但日志目录由调用方指定。
///
/// 测试一律走这里 + `tempfile::tempdir()`：日志写进绝对路径的临时目录、
/// `TempDir` 在 Drop 时清理，既不碰真实 `%LOCALAPPDATA%\AIDM\logs`，
/// 也不会因为相对路径把文件落在当前工作目录里。
///
/// **注意**：日志文件句柄与限流器是全局 `OnceLock`，整个进程只生效一次 ——
/// 测试里只应有一个用例调用本函数，后调用者不会改变已确定的目录。
pub fn init_at(dir: &Path, role: &str, default_filter: &str) {
    let started = now_ms();
    let _ = EPOCH.compare_exchange(0, started, Ordering::Relaxed, Ordering::Relaxed);

    // 落盘：失败不致命（只读盘/权限问题下仍保留 stderr 输出）。
    let _ = std::fs::create_dir_all(dir);
    let path = dir.join(format!("aidm-{role}.log"));
    if let Ok(file) = OpenOptions::new().create(true).append(true).open(&path) {
        let _ = LOG_PATH.set(path.clone());
        let _ = LOG_FILE.set(Mutex::new(file));
    }

    let per_sec = std::env::var("AIDM_LOG_LINES_PER_SEC")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_LINES_PER_SEC);
    let _ = LIMITER.set(LineLimiter::new(per_sec));

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_filter));
    // 必须是 `registry + layer`：只有带 registry 的 subscriber 才提供 `LookupSpan`，
    // span 字段（`task`/`seg`/`conn`）才取得到并展平进日志行。
    let subscriber = tracing_subscriber::registry().with(filter).with(
        tracing_subscriber::fmt::layer()
            .with_ansi(false)
            // 真正的输出在 `JsonFormat` 内完成（脱敏 + 限流 + 落盘），这里给个空 sink。
            .with_writer(std::io::sink)
            .event_format(JsonFormat),
    );

    // 桥接 `log`：既有 `log::info!` 调用点无需改动即进同一通路。
    let _ = tracing_log::LogTracer::init();
    if tracing::subscriber::set_global_default(subscriber).is_ok() {
        tracing::info!(
            event = "obs.ready",
            role,
            version = env!("CARGO_PKG_VERSION"),
            epoch = epoch(),
            os = std::env::consts::OS,
            arch = std::env::consts::ARCH,
            cpus = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(0),
            log_path = %path.display(),
            lines_per_sec = per_sec,
        );
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------- 限流

/// 固定窗口的行数限流：窗口内超出即丢弃，丢弃数累计到 `suppressed`。
struct LineLimiter {
    per_sec: u64,
    window_start_ms: AtomicU64,
    used: AtomicU64,
    suppressed: AtomicU64,
}

impl LineLimiter {
    fn new(per_sec: u64) -> Self {
        Self {
            per_sec,
            window_start_ms: AtomicU64::new(0),
            used: AtomicU64::new(0),
            suppressed: AtomicU64::new(0),
        }
    }

    fn allow(&self, now: u64) -> bool {
        let start = self.window_start_ms.load(Ordering::Relaxed);
        if now.saturating_sub(start) >= 1000
            && self
                .window_start_ms
                .compare_exchange(start, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            self.used.store(0, Ordering::Relaxed);
        }
        if self.used.fetch_add(1, Ordering::Relaxed) < self.per_sec {
            true
        } else {
            self.suppressed.fetch_add(1, Ordering::Relaxed);
            false
        }
    }

    fn take_suppressed(&self) -> u64 {
        self.suppressed.swap(0, Ordering::Relaxed)
    }
}

/// 同一 `(event, err_code, seg)` 的去重窗口。
const DEDUP_WINDOW_MS: u64 = 5_000;
/// 去重表容量上限；超过后先清理 5 分钟前的条目，仍超就清空。
const DEDUP_MAX_ENTRIES: usize = 2048;

struct DedupEntry {
    last_emit_ms: u64,
    first_ms: u64,
    merged: u64,
}

static DEDUP: OnceLock<Mutex<HashMap<String, DedupEntry>>> = OnceLock::new();

/// 返回 `None` 表示本行应被丢弃；返回 `Some((merged, first_ms))` 表示
/// 本行应输出，并附带窗口内被合并的条数与首次时刻（0 条时不附）。
fn dedup_check(key: &str, now: u64) -> Option<(u64, u64)> {
    let table = DEDUP.get_or_init(|| Mutex::new(HashMap::new()));
    let mut table = table.lock().ok()?;
    if let Some(entry) = table.get_mut(key) {
        if now.saturating_sub(entry.last_emit_ms) < DEDUP_WINDOW_MS {
            entry.merged += 1;
            return None;
        }
        let merged = entry.merged;
        let first = entry.first_ms;
        entry.merged = 0;
        entry.first_ms = now;
        entry.last_emit_ms = now;
        return Some((merged, first));
    }
    if table.len() >= DEDUP_MAX_ENTRIES {
        table.retain(|_, entry| now.saturating_sub(entry.last_emit_ms) < 300_000);
        if table.len() >= DEDUP_MAX_ENTRIES {
            table.clear();
        }
    }
    table.insert(
        key.to_string(),
        DedupEntry {
            last_emit_ms: now,
            first_ms: now,
            merged: 0,
        },
    );
    Some((0, now))
}

// ---------------------------------------------------------------- 字段脱敏

/// URL 类字段：整值按 URL 规则打码（保留 scheme/host/path）。
const URL_FIELDS: &[&str] = &[
    "url", "urlorig", "urlfinal", "srcurl", "referer", "referrer", "location", "href", "link",
    "proxy", "proxyurl",
];
/// 路径类字段：用户目录 → `~`。
const PATH_FIELDS: &[&str] = &[
    "path",
    "dir",
    "file",
    "filename",
    "target",
    "partpath",
    "working",
    "output",
    "destination",
    "savepath",
    "logpath",
];
/// 请求头类字段：逐行按头名判定。
const HEADER_FIELDS: &[&str] = &["headers", "customheaders", "requestheaders"];

/// 字段名归一化（小写、只留 ASCII 字母数字），与 `redact` 的判定取向一致。
fn normalized(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// 按字段名选择脱敏策略；无法归类的一律走 `redact_text`（宁可多打码）。
fn redact_field<'a>(name: &str, value: &'a str) -> Cow<'a, str> {
    let norm = normalized(name);
    if URL_FIELDS.contains(&norm.as_str()) {
        return redact::redact_url(value);
    }
    if PATH_FIELDS.contains(&norm.as_str()) {
        return redact::redact_path(value);
    }
    if HEADER_FIELDS.contains(&norm.as_str()) {
        return Cow::Owned(redact::redact_headers(value));
    }
    redact::redact_text(value)
}

/// span 字段来自格式化后的字符串（`task=12`），这里还原成 JSON 原生类型，
/// 让同一字段无论写在 span 还是事件上都呈现一致（`"task":12` 而非 `"task":"12"`）。
fn value_from_str(value: &str) -> Value {
    if let Ok(n) = value.parse::<i64>() {
        return Value::from(n);
    }
    match value {
        "true" => Value::from(true),
        "false" => Value::from(false),
        _ => Value::from(value.to_string()),
    }
}

#[derive(Default)]
struct Fields {
    values: Vec<(String, Value)>,
}

impl Fields {
    fn push(&mut self, name: &str, value: Value) {
        self.values.push((name.to_string(), value));
    }

    fn push_text(&mut self, name: &str, value: &str) {
        let redacted = redact_field(name, value);
        self.push(name, Value::from(redacted.into_owned()));
    }
}

impl Visit for Fields {
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.push(field.name(), Value::from(value));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.push(field.name(), Value::from(value));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.push(field.name(), Value::from(value));
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.push(field.name(), Value::from(value));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.push_text(field.name(), value);
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.push_text(field.name(), &value.to_string());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        let raw = format!("{value:?}");
        self.push_text(field.name(), &raw);
    }
}

/// 解析 span 字段的格式化结果（默认形态 `task=12 host="example.com"`）。
///
/// 只按 ASCII 边界切分：`=`、`"`、空白都是 ASCII，多字节 UTF-8 序列的每个字节
/// 都 ≥ 0x80，不会误判为分隔符，因此索引始终落在字符边界上。
fn parse_pairs(text: &str) -> Vec<(String, String)> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let key_start = i;
        while i < bytes.len() && bytes[i] != b'=' && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let key = text[key_start..i].to_string();
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'=' {
            if !key.is_empty() {
                out.push((key, String::new()));
            }
            continue;
        }
        i += 1; // 跳过 '='
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let value = if i < bytes.len() && bytes[i] == b'"' {
            i += 1;
            let start = i;
            while i < bytes.len() && bytes[i] != b'"' {
                if bytes[i] == b'\\' {
                    i += 1;
                }
                i += 1;
            }
            let v = text[start..i.min(text.len())].to_string();
            if i < bytes.len() {
                i += 1;
            }
            v
        } else {
            let start = i;
            while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            text[start..i].to_string()
        };
        if !key.is_empty() {
            out.push((key, value));
        }
    }
    out
}

// ---------------------------------------------------------------- 格式化器

/// JSON 行格式器：一条事件一行，字段扁平。
pub struct JsonFormat;

impl<S, N> FormatEvent<S, N> for JsonFormat
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        _writer: FmtWriter<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let meta = event.metadata();
        let mut obj = Map::new();
        obj.insert(
            "ts".to_string(),
            Value::from(chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, false)),
        );
        obj.insert(
            "level".to_string(),
            Value::from(meta.level().as_str().to_ascii_lowercase()),
        );
        obj.insert("target".to_string(), Value::from(meta.target()));

        // span 字段先铺（外层 → 内层），事件字段后写，同名以事件为准。
        let mut span_name = String::new();
        if let Some(scope) = ctx.event_scope() {
            for span in scope.from_root() {
                span_name = span.name().to_string();
                if let Some(fields) = span.extensions().get::<FormattedFields<N>>() {
                    for (k, v) in parse_pairs(&fields.fields) {
                        let redacted = redact_field(&k, &v);
                        obj.insert(k, value_from_str(&redacted));
                    }
                }
            }
        }
        if !span_name.is_empty() {
            obj.insert("span".to_string(), Value::from(span_name));
        }

        let mut fields = Fields::default();
        event.record(&mut fields);
        let mut message: Option<Value> = None;
        let mut event_name: Option<Value> = None;
        for (k, v) in fields.values {
            match k.as_str() {
                "message" => message = Some(v),
                "event" => event_name = Some(v),
                _ => {
                    obj.insert(k, v);
                }
            }
        }
        if let Some(v) = event_name {
            obj.insert("event".to_string(), v);
        }
        if let Some(v) = message {
            obj.insert("msg".to_string(), v);
        }

        // 去重：同一 `(event, err_code, seg)` 5 秒内只输出首条；窗口结束后的首条
        // 带上 `merged_count` / `merged_first_ms`，避免重复错误刷屏。
        if let Some(event_name) = obj.get("event").and_then(Value::as_str) {
            let err_code = obj
                .get("err_code")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let seg = obj
                .get("seg")
                .map(|value| value.to_string())
                .unwrap_or_default();
            let key = format!("{event_name}|{err_code}|{seg}");
            match dedup_check(&key, now_ms()) {
                Some((merged, first_ms)) if merged > 0 => {
                    obj.insert("merged_count".to_string(), Value::from(merged));
                    obj.insert("merged_first_ms".to_string(), Value::from(first_ms));
                }
                Some(_) => {}
                None => return Ok(()),
            }
        }

        // 限流：丢弃时仍返回 Ok（调用方无需感知），丢弃数在下一条里报出。
        if let Some(limiter) = LIMITER.get() {
            if !limiter.allow(now_ms()) {
                return Ok(());
            }
            let dropped = limiter.take_suppressed();
            if dropped > 0 {
                obj.insert("suppressed".to_string(), Value::from(dropped));
            }
        }

        let line = match serde_json::to_string(&Value::Object(obj)) {
            Ok(line) => line,
            Err(_) => "{\"level\":\"error\",\"event\":\"obs.encode_failed\"}".to_string(),
        };
        emit(&line);
        Ok(())
    }
}

/// 写出：stderr + 日志文件（带大小轮转）。任何失败都静默 —— 日志不能拖垮主流程。
fn emit(line: &str) {
    let mut buf = String::with_capacity(line.len() + 1);
    buf.push_str(line);
    buf.push('\n');
    let _ = std::io::stderr().write_all(buf.as_bytes());

    let Some(file) = LOG_FILE.get() else {
        return;
    };
    let Ok(mut f) = file.lock() else {
        return;
    };
    if f.metadata().map(|m| m.len()).unwrap_or(0) > MAX_LOG_BYTES {
        rotate(&mut f);
    }
    let _ = f.write_all(buf.as_bytes());
}

fn rotate(file: &mut File) {
    let _ = file.flush();
    let Some(path) = LOG_PATH.get() else {
        let _ = file.set_len(0);
        return;
    };
    let rolled = PathBuf::from(format!("{}.1", path.display()));
    let _ = std::fs::rename(path, &rolled);
    if let Ok(fresh) = OpenOptions::new().create(true).append(true).open(path) {
        *file = fresh;
    }
}

/// 供诊断包使用：当前日志文件路径。
pub fn log_path() -> Option<&'static Path> {
    LOG_PATH.get().map(PathBuf::as_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pairs_handles_quoted_and_bare_values() {
        assert_eq!(
            parse_pairs(r#"task=12 host="example.com" seg=3"#),
            vec![
                ("task".to_string(), "12".to_string()),
                ("host".to_string(), "example.com".to_string()),
                ("seg".to_string(), "3".to_string()),
            ]
        );
        // 值里带空格与转义引号。
        assert_eq!(
            parse_pairs(r#"note="a \"b\" c" tail=1"#),
            vec![
                ("note".to_string(), r#"a \"b\" c"#.to_string()),
                ("tail".to_string(), "1".to_string()),
            ]
        );
        // 中文值不破坏切分。
        assert_eq!(
            parse_pairs("name=中文 名=值"),
            vec![
                ("name".to_string(), "中文".to_string()),
                ("名".to_string(), "值".to_string()),
            ]
        );
        assert!(parse_pairs("").is_empty());
    }

    #[test]
    fn field_redaction_follows_field_name() {
        assert_eq!(
            redact_field("url", "https://h/a?token=1"),
            "https://h/a?token=***"
        );
        assert_eq!(
            redact_field("part_path", r"C:\Users\bob\Downloads\a.part"),
            r"~\Downloads\a.part"
        );
        assert_eq!(
            redact_field("custom_headers", "Cookie: SID=abc\nAccept: */*\n"),
            "Cookie: ***\nAccept: */*\n"
        );
        // 未归类字段仍扫内嵌 URL。
        assert_eq!(
            redact_field("msg", "see https://h/x?sign=9"),
            "see https://h/x?sign=***"
        );
    }

    #[test]
    fn init_writes_redacted_json_lines() {
        // 端到端：装配 → 打一条带任务身份与敏感字段的事件 → 从落盘的行里验证
        // 「JSON 结构 + span 字段展平 + 脱敏」三件事同时成立。
        // 日志写进 tempdir：绝对路径 + Drop 自动清理，不污染真实 %LOCALAPPDATA%。
        let tmp = crate::testsupport::tempdir("obs");
        init_at(tmp.path(), "test", "info");
        {
            let _task = enter_task("download", 4242);
            tracing::warn!(
                event = "net.connect",
                phase = "connect",
                url = "https://h/a.iso?token=deadbeef",
                part_path = r"C:\Users\bob\a.part",
                dur_ms = 7_u64,
            );
        }
        let path = log_path().expect("日志文件应已建立");
        let text = std::fs::read_to_string(path).expect("读日志");
        let line = text
            .lines()
            .rev()
            .find(|l| l.contains("\"event\":\"net.connect\""))
            .unwrap_or_else(|| panic!("未找到事件行；文件尾部：{text}"));
        assert!(
            line.contains("\"task\":4242"),
            "span 字段应展平为数值：{line}"
        );
        assert!(line.contains("\"dur_ms\":7"), "事件字段应保持数值：{line}");
        assert!(line.contains("token=***"), "查询串凭据应打码：{line}");
        assert!(!line.contains("deadbeef"), "凭据明文不得落盘：{line}");
        // JSON 文本里反斜杠是转义的（`~\\a.part`）。
        assert!(line.contains(r"~\\a.part"), "用户路径应收敛为 ~：{line}");
        assert!(!line.contains("bob"), "用户名不得落盘：{line}");
    }

    #[test]
    fn limiter_drops_beyond_window_and_counts() {
        let limiter = LineLimiter::new(2);
        assert!(limiter.allow(1_000));
        assert!(limiter.allow(1_000));
        assert!(!limiter.allow(1_000), "窗口内第三条应被丢弃");
        assert_eq!(limiter.take_suppressed(), 1);
        assert_eq!(limiter.take_suppressed(), 0, "取走后归零");
        // 下一个窗口重新放行。
        assert!(limiter.allow(2_500));
    }

    #[test]
    fn dedup_merges_same_key_within_window() {
        let key = "dedup.test.event|dedup_code|7";
        assert_eq!(dedup_check(key, 1_000), Some((0, 1_000)));
        assert_eq!(dedup_check(key, 2_000), None);
        assert_eq!(dedup_check(key, 3_000), None);
        assert_eq!(
            dedup_check(key, 7_000),
            Some((2, 1_000)),
            "窗口结束后的首条应带合并数与首次时刻"
        );
        assert_eq!(dedup_check(key, 8_000), None);
    }
}

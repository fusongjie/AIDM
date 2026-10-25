//! 一键诊断包（`docs/download-observability.md` §7）。
//!
//! 目标：**离线自证一次失败**。给定一个 task，导出一个 zip，里面是「这条任务
//! 当时看到了什么」——事件序列、阶段、错误与原因链、分片状态、设置、日志尾部、
//! 系统信息 —— 全部**脱敏后**打包，并在打包后做一次二次扫描自检。
//!
//! 设计取舍：
//! - **不压缩也能读**：zip 条目是普通文本（JSON / JSONL / LOG），用任何解压工具
//!   打开即可，不依赖本程序；
//! - **先脱敏再打包**：自由文本一律过 [`crate::redact`]，未知字段也走 `redact_text`
//!   （宁可多打码）；
//! - **打包后二次扫描**：命中的条目改写为 `<redacted:auto>` 并计入 `manifest.redaction_findings`，
//!   这样「新增字段忘了脱敏」会在导出时暴露，而不是在用户把包发给别人之后。

use std::io::Write;
use std::path::{Path, PathBuf};

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::redact;

/// 未压缩上限；超过按 events → logs → segments 顺序截断。
const MAX_RAW_BYTES: usize = 32 * 1024 * 1024;
/// 日志尾部保留行数。
const LOG_TAIL_LINES: usize = 2000;
/// 事件保留条数。
const EVENT_LIMIT: usize = 500;

/// 系统信息（manifest.json）。
#[derive(Debug, Clone, Default)]
pub struct SystemInfo {
    pub os: String,
    pub arch: String,
    pub cpus: usize,
    pub mem_total_mb: u64,
    pub mem_avail_mb: u64,
    pub disk_free_mb: u64,
}

impl SystemInfo {
    pub fn collect() -> Self {
        let (mem_total_mb, mem_avail_mb) = memory_mb();
        Self {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            cpus: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(0),
            mem_total_mb,
            mem_avail_mb,
            disk_free_mb: disk_free_mb(&crate::paths::app_data_dir()),
        }
    }
}

#[cfg(windows)]
fn memory_mb() -> (u64, u64) {
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    unsafe {
        let mut status: MEMORYSTATUSEX = std::mem::zeroed();
        status.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        if GlobalMemoryStatusEx(&mut status) != 0 {
            (
                status.ullTotalPhys / 1_048_576,
                status.ullAvailPhys / 1_048_576,
            )
        } else {
            (0, 0)
        }
    }
}

#[cfg(not(windows))]
fn memory_mb() -> (u64, u64) {
    // 非 Windows（开发/CI）：从 /proc/meminfo 取，失败就给 0（不编造数字）。
    let Ok(text) = std::fs::read_to_string("/proc/meminfo") else {
        return (0, 0);
    };
    let pick = |key: &str| -> u64 {
        text.lines()
            .find(|l| l.starts_with(key))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse::<u64>().ok())
            .map(|kb| kb / 1024)
            .unwrap_or(0)
    };
    (pick("MemTotal:"), pick("MemAvailable:"))
}

#[cfg(windows)]
fn disk_free_mb(path: &Path) -> u64 {
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    let wide: Vec<u16> = path
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut free = 0u64;
    unsafe {
        if GetDiskFreeSpaceExW(
            wide.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut free,
        ) != 0
        {
            free / 1_048_576
        } else {
            0
        }
    }
}

#[cfg(not(windows))]
fn disk_free_mb(_path: &Path) -> u64 {
    0
}

/// 导出结果（给 CLI 与 UI 用）。
#[derive(Debug, Clone)]
pub struct ExportReport {
    pub path: PathBuf,
    pub bytes: u64,
    pub entries: Vec<(String, usize)>,
    pub truncated: Vec<String>,
    pub redaction_findings: usize,
}

// ---------------------------------------------------------------- 最小 ZIP 写入
//
// 只为「把一堆文本装进一个可分享的文件」而写：deflate + CRC32，没有 zip64、
// 没有加密、没有目录项。条目名全部是 ASCII 常量，因此不需要做编码转换。

struct ZipEntry {
    name: String,
    method: u16,
    crc: u32,
    compressed: Vec<u8>,
    uncompressed_len: usize,
}

#[derive(Default)]
struct Zip {
    entries: Vec<ZipEntry>,
}

impl Zip {
    fn add(&mut self, name: &str, data: &[u8]) {
        let mut crc = flate2::Crc::new();
        crc.update(data);
        let crc = crc.sum();
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        let compressed = match encoder.write_all(data).and_then(|_| encoder.finish()) {
            Ok(bytes) => bytes,
            // 压缩失败就退回 store（仍然是一个合法 zip），不让导出失败。
            Err(_) => data.to_vec(),
        };
        let method = if compressed.len() < data.len() { 8 } else { 0 };
        let compressed = if method == 8 {
            compressed
        } else {
            data.to_vec()
        };
        self.entries.push(ZipEntry {
            name: name.to_string(),
            method,
            crc,
            compressed,
            uncompressed_len: data.len(),
        });
    }

    fn finish(self, path: &Path) -> std::io::Result<u64> {
        let mut out = std::io::BufWriter::new(std::fs::File::create(path)?);
        let mut central = Vec::new();
        let mut offset = 0u32;
        for entry in &self.entries {
            let name = entry.name.as_bytes();
            let mut local = Vec::new();
            local.extend_from_slice(&0x0403_4b50u32.to_le_bytes()); // local file header
            local.extend_from_slice(&20u16.to_le_bytes()); // version needed
            local.extend_from_slice(&0u16.to_le_bytes()); // flags
            local.extend_from_slice(&entry.method.to_le_bytes());
            local.extend_from_slice(&0u16.to_le_bytes()); // mod time
            local.extend_from_slice(&0x21u16.to_le_bytes()); // mod date (1980-01-01)
            local.extend_from_slice(&entry.crc.to_le_bytes());
            local.extend_from_slice(&(entry.compressed.len() as u32).to_le_bytes());
            local.extend_from_slice(&(entry.uncompressed_len as u32).to_le_bytes());
            local.extend_from_slice(&(name.len() as u16).to_le_bytes());
            local.extend_from_slice(&0u16.to_le_bytes()); // extra len
            local.extend_from_slice(name);
            out.write_all(&local)?;
            out.write_all(&entry.compressed)?;

            central.extend_from_slice(&0x0201_4b50u32.to_le_bytes()); // central header
            central.extend_from_slice(&20u16.to_le_bytes()); // version made by
            central.extend_from_slice(&20u16.to_le_bytes()); // version needed
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&entry.method.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0x21u16.to_le_bytes());
            central.extend_from_slice(&entry.crc.to_le_bytes());
            central.extend_from_slice(&(entry.compressed.len() as u32).to_le_bytes());
            central.extend_from_slice(&(entry.uncompressed_len as u32).to_le_bytes());
            central.extend_from_slice(&(name.len() as u16).to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes()); // extra
            central.extend_from_slice(&0u16.to_le_bytes()); // comment
            central.extend_from_slice(&0u16.to_le_bytes()); // disk
            central.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
            central.extend_from_slice(&0u32.to_le_bytes()); // external attrs
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(name);

            offset += local.len() as u32 + entry.compressed.len() as u32;
        }
        let central_offset = offset;
        out.write_all(&central)?;
        let mut eocd = Vec::new();
        eocd.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        eocd.extend_from_slice(&0u16.to_le_bytes()); // disk
        eocd.extend_from_slice(&0u16.to_le_bytes()); // cd disk
        eocd.extend_from_slice(&(self.entries.len() as u16).to_le_bytes());
        eocd.extend_from_slice(&(self.entries.len() as u16).to_le_bytes());
        eocd.extend_from_slice(&(central.len() as u32).to_le_bytes());
        eocd.extend_from_slice(&central_offset.to_le_bytes());
        eocd.extend_from_slice(&0u16.to_le_bytes()); // comment len
        out.write_all(&eocd)?;
        out.flush()?;
        Ok(std::fs::metadata(path).map(|m| m.len()).unwrap_or(0))
    }
}

// ---------------------------------------------------------------- 采集与导出

fn sensitive_setting(key: &str) -> bool {
    let norm: String = key
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    [
        "password", "passwd", "pwd", "token", "secret", "cookie", "auth",
    ]
    .iter()
    .any(|s| norm.contains(s))
}

/// 二次脱敏扫描：对已经生成好的文本再跑一遍规则。
///
/// 返回（扫描后的文本，命中次数）。命中说明**前置脱敏漏了**——这是缺陷信号，
/// 不是正常路径，所以计数会写进 manifest 供排查。
fn rescan(text: &str) -> (String, usize) {
    let mut findings = 0usize;
    let mut out = String::with_capacity(text.len());
    for (i, line) in text.lines().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        let cleaned = redact::redact_text(line);
        if matches!(cleaned, std::borrow::Cow::Owned(_)) {
            findings += 1;
            out.push_str("<redacted:auto> ");
            out.push_str(&cleaned);
        } else {
            out.push_str(line);
        }
    }
    (out, findings)
}

fn task_json(conn: &Connection, id: i64) -> Result<Value, String> {
    let row = crate::model::get_download(conn, id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("任务 {id} 不存在"))?;
    Ok(json!({
        "id": row.id,
        "url_orig": redact::redact_url(&row.url_orig),
        "url_final": row.url_final.as_deref().map(redact::redact_url),
        "file_name": row.file_name,
        "dir": redact::redact_path(&row.dir),
        "size_total": row.size_total,
        "status": format!("{:?}", row.status),
        "created_at": row.created_at,
        "finished_at": row.finished_at,
        "error_code": row.error_code,
        "error_message": row.error_message.as_deref().map(redact::redact_text),
        "http_status": row.http_status,
        "retry_count": row.retry_count,
        "retry_at": row.retry_at,
        "max_conns": row.max_conns,
        "active_ms": row.active_ms,
        "speed_limit_kbps": row.speed_limit_kbps,
        "source": row.source,
        "referrer": row.referrer.as_deref().map(redact::redact_url),
        "custom_headers": row.custom_headers.as_deref().map(redact::redact_headers),
        "alt_urls": row.alt_urls.as_deref().map(redact::redact_text),
        "sha256_expected": row.sha256_expected,
        "etag": row.etag,
        "last_modified": row.last_modified,
    }))
}

fn segments_json(conn: &Connection, id: i64) -> Value {
    let segs = crate::model::list_segments(conn, id).unwrap_or_default();
    let items: Vec<Value> = segs
        .iter()
        .map(|s| {
            json!({
                "idx": s.idx,
                "pos_start": s.pos_start,
                "pos_end": s.pos_end,
                "done_bytes": s.done_bytes,
                "status": s.status,
                "retries": s.retries,
                "part_path": redact::redact_path(&s.part_path),
                "src_url": s.src_url.as_deref().map(redact::redact_url),
            })
        })
        .collect();
    json!({ "count": items.len(), "items": items })
}

fn events_jsonl(conn: &Connection, id: i64, since_ts: Option<i64>) -> (String, usize) {
    let mut stmt = match conn.prepare(
        "SELECT id, kind, ts, detail, phase, outcome, err_code, dur_ms, attempt, seg, conn, proto          FROM events WHERE download_id = ?1 AND ts >= ?3 ORDER BY id DESC LIMIT ?2",
    ) {
        Ok(s) => s,
        Err(_) => return (String::new(), 0),
    };
    let since = since_ts.unwrap_or(0);
    let rows = stmt.query_map(rusqlite::params![id, EVENT_LIMIT as i64, since], |r| {
        Ok(json!({
            "seq": r.get::<_, i64>(0)?,
            "kind": r.get::<_, String>(1)?,
            "ts": r.get::<_, i64>(2)?,
            "detail": r.get::<_, Option<String>>(3)?
                .map(|text| redact::redact_text(&text).into_owned()),
            "phase": r.get::<_, Option<String>>(4)?,
            "outcome": r.get::<_, Option<String>>(5)?,
            "err_code": r.get::<_, Option<String>>(6)?,
            "dur_ms": r.get::<_, Option<i64>>(7)?,
            "attempt": r.get::<_, Option<i64>>(8)?,
            "seg": r.get::<_, Option<i64>>(9)?,
            "conn": r.get::<_, Option<String>>(10)?,
            "proto": r.get::<_, Option<String>>(11)?,
        }))
    });
    let mut items: Vec<Value> = match rows {
        Ok(iter) => iter.filter_map(Result::ok).collect(),
        Err(_) => Vec::new(),
    };
    items.reverse(); // 取最近 N 条后按时间正序输出
    let total = items.len();
    let mut out = items
        .iter()
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    (out, total)
}

fn metrics_json(conn: &Connection, id: i64) -> Value {
    // 规格 §4 里能离线复算的部分：成功/失败、重试、分片、阶段耗时事件计数。
    let count_kind = |kind: &str| -> i64 {
        conn.query_row(
            "SELECT count(*) FROM events WHERE download_id = ?1 AND kind = ?2",
            rusqlite::params![id, kind],
            |r| r.get(0),
        )
        .unwrap_or(0)
    };
    let segs = crate::model::list_segments(conn, id).unwrap_or_default();
    let seg_retries: i64 = segs.iter().map(|s| s.retries).sum();
    let seg_done = segs.iter().filter(|s| s.status == "done").count();
    let system = SystemInfo::collect();
    json!({
        "task_retries": count_kind("retry"),
        "segment_retries": seg_retries,
        "segments_total": segs.len(),
        "segments_done": seg_done,
        "errors": count_kind("error"),
        "alternates_rejected": count_kind("alt_rejected"),
        "validator_changes": count_kind("validator_changed"),
        "first_byte_events": count_kind("first_byte"),
        "write_stalls": count_kind("write_stall"),
        "conn_timings": count_kind("conn_timing"),
        "process": {
            "mem_total_mb": system.mem_total_mb,
            "mem_avail_mb": system.mem_avail_mb,
            "disk_free_mb": system.disk_free_mb,
            "cpus": system.cpus,
        }
    })
}

/// 错误视图（`error.json` 的内容）：机器码 + 类型化阶段 + 原因链。
///
/// 单独公开，是为了让调用方（UI、测试）**不必解包**就能回答"失败在哪个阶段"。
/// 注意：阶段来自码映射，因此 `network` 只能归到 `connect` —— 读循环中途断流与
/// 建连失败共用同一个机器码，这是 §5 记录的已知边界（修法是让 `WorkerEnd::Failed`
/// 携带阶段，见规格）。
pub fn error_view(conn: &Connection, task_id: i64) -> Value {
    let code = conn
        .query_row(
            "SELECT error_code FROM downloads WHERE id = ?1",
            [task_id],
            |r| r.get::<_, Option<String>>(0),
        )
        .ok()
        .flatten();
    match code.as_deref() {
        Some(code) if !code.is_empty() => {
            let typed = crate::error::DownloadError::from_code(code);
            // 阶段优先取失败事件里的标记：`error_code` 列是归一化后的机器码，
            // 像 `network` 这类码本身分不出"建连失败"与"读中途断流"（规格 §5）。
            let from_event = conn
                .query_row(
                    "SELECT detail FROM events WHERE download_id = ?1 AND kind = 'error' \
                     ORDER BY id DESC LIMIT 1",
                    [task_id],
                    |r| r.get::<_, Option<String>>(0),
                )
                .ok()
                .flatten()
                .and_then(|d| crate::error::phase_from_text(&d));
            let phase = from_event.unwrap_or_else(|| typed.phase());
            json!({
                "code": typed.code(),
                "phase": phase.as_str(),
                "retryable": typed.retryable(),
                "chain": typed.chain(),
                "message": crate::error::classify(code).message,
            })
        }
        _ => Value::Null,
    }
}

/// 全局指标快照（规格 §4 中不需要实时 live 状态的那部分）。
///
/// 运行中的「当前速度 / 活跃连接数」只存在于引擎进程内存里，独立进程读不到 ——
/// 这里诚实标成 `null`，其余（成功率、重试、分片、错误、内存、磁盘）都可从库与
/// 系统复算。用例：`aidm-engine diag metrics`。
pub fn global_metrics(conn: &Connection) -> Value {
    let mut by_status = Map::new();
    if let Ok(mut stmt) = conn.prepare("SELECT status, count(*) FROM downloads GROUP BY status") {
        if let Ok(rows) = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
        {
            for (status, n) in rows.filter_map(|r| r.ok()) {
                by_status.insert(status, Value::from(n));
            }
        }
    }
    let count = |sql: &str| -> i64 { conn.query_row(sql, [], |r| r.get(0)).unwrap_or(0) };
    let done = by_status.get("done").and_then(Value::as_i64).unwrap_or(0);
    // 终态是 `Status::Error`（字符串 `error`），不是 "failed"；用错会永远算出 0%。
    let failed = by_status.get("error").and_then(Value::as_i64).unwrap_or(0);
    let finished = done + failed;
    let system = SystemInfo::collect();
    json!({
        "tasks_by_status": by_status,
        "success_rate": if finished > 0 { done as f64 / finished as f64 } else { 0.0 },
        "retries_total": count("SELECT coalesce(sum(retry_count),0) FROM downloads"),
        "segments_total": count("SELECT count(*) FROM segments"),
        "segments_done": count("SELECT count(*) FROM segments WHERE status='done'"),
        "error_events": count("SELECT count(*) FROM events WHERE kind='error'"),
        "write_stalls": count("SELECT count(*) FROM events WHERE kind='write_stall'"),
        // 需引擎进程内 live 状态，独立进程读不到 → 显式 null（不编造数字）。
        "current_speed_bps": Value::Null,
        "active_connections": Value::Null,
        "process": {
            "mem_total_mb": system.mem_total_mb,
            "mem_avail_mb": system.mem_avail_mb,
            "disk_free_mb": system.disk_free_mb,
            "cpus": system.cpus,
        }
    })
}

/// 诊断包设置白名单：只导出排障需要的并发/超时/限速/代理/镜像相关键。
///
/// 不导出全量设置：设置项会随功能增长，全量导出既增大包体，也扩大泄露面
/// （R-CR-14 要求设置快照经白名单掩码）。
const DIAG_SETTINGS_KEYS: &[&str] = &[
    "conn.global_conn_cap",
    "conn.timeout_connect_s",
    "conn.timeout_idle_s",
    "conn.retry_max",
    "conn.retry_backoff_ms",
    "speed.global_limit_kbps",
    "proxy.mode",
    "proxy.only_for",
    "proxy.bypass_hosts",
    "proxy.host",
    "proxy.port",
    "proxy.user",
    "proxy.pass",
    "alt.max_sources",
    "alt.probe_min_size_mb",
    "net.recv_buf_kb",
    "engine.fastdl",
    "verify.sha256_after",
    "paths.metadata_dir",
    "browser.exclude_hosts",
    "browser.auto_catch_exts",
];

fn settings_json(conn: &Connection) -> Value {
    let mut map = Map::new();
    for key in DIAG_SETTINGS_KEYS {
        let Ok(Some(value)) = crate::settings::get(conn, key) else {
            continue;
        };
        let value = if sensitive_setting(key) {
            "***".to_string()
        } else if key.ends_with("_dir") {
            redact::redact_path(&value).into_owned()
        } else {
            redact::redact_text(&value).into_owned()
        };
        map.insert((*key).to_string(), Value::from(value));
    }
    Value::Object(map)
}

/// 引擎进程的日志全文（诊断包要的是**引擎**看到的现场，而不是导出进程自己的日志）。
///
/// 轮转过的 `.1` 接在前面：一次事故的日志很可能正好跨在轮转点上。
fn engine_log_text() -> String {
    let dir = crate::paths::logs_dir();
    let mut text = String::new();
    if let Ok(rolled) = std::fs::read_to_string(dir.join("aidm-engine.log.1")) {
        text.push_str(&rolled);
        if !text.ends_with('\n') {
            text.push('\n');
        }
    }
    if let Ok(current) = std::fs::read_to_string(dir.join("aidm-engine.log")) {
        text.push_str(&current);
    }
    text
}

fn tail_lines(text: &str, limit: usize) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(limit);
    lines[start..].join("\n")
}

/// 从 JSON 行日志里聚合某任务的**阶段耗时**（规格 §4 那组 `*_seconds` 的离线版）。
///
/// 日志本身就是结构化行，所以阶段分布不必再落一遍库：导出时扫一遍就能复算。
/// 只保留该任务的行，且只保留带数值字段的事件。
fn phases_json(log_text: &str, task_id: i64) -> Value {
    let mut stages: Map<String, Value> = Map::new();
    for line in log_text.lines() {
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if value.get("task").and_then(Value::as_i64) != Some(task_id) {
            continue;
        }
        let Some(event) = value.get("event").and_then(Value::as_str) else {
            continue;
        };
        let phase = value.get("phase").and_then(Value::as_str).unwrap_or("-");
        let mut nums = Map::new();
        for key in ["dur_ms", "total_ms", "avg_ms", "conns", "speed_bps"] {
            if let Some(n) = value.get(key) {
                nums.insert(key.to_string(), n.clone());
            }
        }
        if nums.is_empty() {
            continue;
        }
        let entry = stages
            .entry(event.to_string())
            .or_insert_with(|| json!({ "phase": phase, "count": 0 }));
        if let Some(obj) = entry.as_object_mut() {
            let count = obj.get("count").and_then(Value::as_u64).unwrap_or(0);
            obj.insert("count".to_string(), Value::from(count + 1));
            // 同名事件可能多条（每次重试/每条连接），这里给累计值与最后一次。
            for (key, val) in &nums {
                let prev = obj.get(key).and_then(Value::as_u64).unwrap_or(0);
                let now = val.as_u64().unwrap_or(0);
                obj.insert(key.clone(), Value::from(prev + now));
            }
            obj.insert("last".to_string(), Value::Object(nums));
        }
    }
    Value::Object(stages)
}

/// 导出某个任务的诊断包，返回落盘路径与自检结果。
/// 解析 `--since` 的时长：`30s` / `10m` / `2h` / `1d`，无后缀按秒。
pub fn parse_since(text: &str) -> Option<i64> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    let (number, mult) = match text.chars().last()? {
        's' => (&text[..text.len() - 1], 1),
        'm' => (&text[..text.len() - 1], 60),
        'h' => (&text[..text.len() - 1], 3600),
        'd' => (&text[..text.len() - 1], 86_400),
        _ => (text, 1),
    };
    let n: i64 = number.parse().ok()?;
    (n > 0).then_some(n * mult)
}

/// `REDACTION.md`：本次导出应用的规则与逐条目命中数。
fn redaction_report(task_id: i64, entries: &[(String, usize)], total: usize) -> String {
    let mut out = String::new();
    out.push_str("# 脱敏说明\n\n");
    out.push_str(&format!("- 任务：{task_id}\n"));
    out.push_str(&format!(
        "- 生成时间：{}\n",
        chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, false)
    ));
    out.push_str(&format!("- 二次扫描总命中：{total}\n\n"));
    out.push_str("## 规则\n\n");
    out.push_str("- URL 查询串与 userinfo 中的敏感参数值替换为 `***`；\n");
    out.push_str("- 用户目录收敛为 `~`，保留文件名与扩展名；\n");
    out.push_str("- 请求头中的认证/Cookie/代理认证值替换为 `***`；\n");
    out.push_str("- 设置快照只导出白名单键，敏感键值替换为 `***`；\n");
    out.push_str("- 打包后对所有文本条目再扫描一次，命中行前置 `<redacted:auto> `。\n\n");
    out.push_str("## 逐条目命中\n\n");
    out.push_str("| 条目 | 二次扫描命中 |\n|---|---:|\n");
    for (name, hits) in entries {
        out.push_str(&format!("| `{name}` | {hits} |\n"));
    }
    out
}

pub fn export_task_bundle(
    conn: &Connection,
    task_id: i64,
    out_dir: &Path,
) -> Result<ExportReport, String> {
    export_task_bundle_since(conn, task_id, out_dir, None)
}

/// 与 [`export_task_bundle`] 相同，但只导出 `since_ts`（unix 秒）之后的事件。
pub fn export_task_bundle_since(
    conn: &Connection,
    task_id: i64,
    out_dir: &Path,
    since_ts: Option<i64>,
) -> Result<ExportReport, String> {
    let started = std::time::Instant::now();
    std::fs::create_dir_all(out_dir).map_err(|e| format!("创建导出目录失败：{e}"))?;

    let task = task_json(conn, task_id)?;
    let (events, event_count) = events_jsonl(conn, task_id, since_ts);
    let segments = segments_json(conn, task_id);
    let metrics = metrics_json(conn, task_id);
    let settings = settings_json(conn);
    // 引擎日志：诊断包里的日志尾部与阶段耗时都来自它（不是导出进程自己的日志）。
    let log_text = engine_log_text();
    let logs = tail_lines(&log_text, LOG_TAIL_LINES);
    let phases = phases_json(&log_text, task_id);
    let system = SystemInfo::collect();

    // 错误视图：机器码 + 类型化阶段 + 原因链（规格 §5）。
    let error = error_view(conn, task_id);

    let mut truncated: Vec<String> = Vec::new();
    let mut entries: Vec<(String, String)> = vec![
        ("task.json".into(), task.to_string()),
        ("segments.json".into(), segments.to_string()),
        ("metrics.json".into(), metrics.to_string()),
        ("phases.json".into(), phases.to_string()),
        ("settings.json".into(), settings.to_string()),
        ("error.json".into(), error.to_string()),
        ("events.jsonl".into(), events),
        ("logs/tail.log".into(), logs),
    ];

    // 限额：超出按 events → logs → segments 顺序截断（规格 §7）。
    let mut raw: usize = entries.iter().map(|(n, t)| n.len() + t.len()).sum();
    for name in ["events.jsonl", "logs/tail.log", "segments.json"] {
        if raw <= MAX_RAW_BYTES {
            break;
        }
        if let Some((_, text)) = entries.iter_mut().find(|(n, _)| n == name) {
            truncated.push(name.to_string());
            raw -= text.len();
            *text = format!("[truncated: 超过 {MAX_RAW_BYTES} 字节上限，本条目已省略]\n");
            raw += text.len();
        }
    }

    // 二次扫描自检 + 组装 manifest。
    let mut zip = Zip::default();
    let mut findings = 0usize;
    let mut entry_report = Vec::new();
    let mut entry_hits: Vec<(String, usize)> = Vec::new();
    for (name, text) in &entries {
        let (clean, hits) = rescan(text);
        findings += hits;
        entry_hits.push((name.clone(), hits));
        entry_report.push((name.clone(), clean.len()));
        zip.add(name, clean.as_bytes());
    }
    // 脱敏说明：规则清单 + 逐条目命中数。它本身也过一次 rescan（正常为 0）。
    let redaction = redaction_report(task_id, &entry_hits, findings);
    let (redaction_clean, redaction_hits) = rescan(&redaction);
    findings += redaction_hits;
    entry_report.push(("REDACTION.md".into(), redaction_clean.len()));
    zip.add("REDACTION.md", redaction_clean.as_bytes());

    let manifest = json!({
        "schema_version": 1,
        "generated_at": chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, false),
        "app_version": env!("CARGO_PKG_VERSION"),
        "engine_epoch_ms": crate::obs::epoch(),
        "task_id": task_id,
        "export_ms": started.elapsed().as_millis() as u64,
        "events_included": event_count,
        "since_ts": since_ts,
        "entries": entry_report.iter().map(|(n, len)| json!({"name": n, "bytes": len})).collect::<Vec<_>>(),
        "truncated": truncated,
        "redaction_findings": findings,
        "system": {
            "os": system.os,
            "arch": system.arch,
            "cpus": system.cpus,
            "mem_total_mb": system.mem_total_mb,
            "mem_avail_mb": system.mem_avail_mb,
            "disk_free_mb": system.disk_free_mb,
        },
    });
    let (manifest_text, _) = rescan(&manifest.to_string());
    zip.add("manifest.json", manifest_text.as_bytes());
    entry_report.push(("manifest.json".into(), manifest_text.len()));

    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
    let path = out_dir.join(format!("aidm-diag-task{task_id}-{stamp}.zip"));
    let bytes = zip
        .finish(&path)
        .map_err(|e| format!("写诊断包失败：{e}"))?;

    // 导出本身也是可观测事件（脱敏：路径只留文件名）。
    tracing::info!(
        event = "diag.export",
        result = "ok",
        bytes,
        entries = entry_report.len(),
        redaction_findings = findings,
        file = %path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
    );

    Ok(ExportReport {
        path,
        bytes,
        entries: entry_report,
        truncated,
        redaction_findings: findings,
    })
}

/// 默认导出目录（与日志同级，便于一起打包带走）。
pub fn default_out_dir() -> PathBuf {
    crate::paths::app_data_dir().join("diag")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn since_durations_parse_with_suffix() {
        assert_eq!(parse_since("30s"), Some(30));
        assert_eq!(parse_since("10m"), Some(600));
        assert_eq!(parse_since("2h"), Some(7200));
        assert_eq!(parse_since("1d"), Some(86_400));
        assert_eq!(parse_since("45"), Some(45));
        assert_eq!(parse_since("0"), None);
        assert_eq!(parse_since("bad"), None);
        assert_eq!(parse_since(""), None);
    }

    #[test]
    fn zip_entries_roundtrip() {
        // 绝对路径的临时目录：`TempDir` 在 Drop 时连目录一起删，无需手写清理。
        let tmp = crate::testsupport::tempdir("diag");
        let path = tmp.path().join("t.zip");
        let mut zip = Zip::default();
        zip.add("a.json", b"{\"k\":1}");
        zip.add("b.txt", "中文内容".as_bytes());
        let bytes = zip.finish(&path).unwrap();
        assert!(bytes > 0);
        let raw = std::fs::read(&path).unwrap();
        // 本地文件头 + 中央目录 + EOCD 都在，且条目名可读。
        assert_eq!(&raw[0..4], &0x0403_4b50u32.to_le_bytes());
        let text = String::from_utf8_lossy(&raw);
        assert!(text.contains("a.json") && text.contains("b.txt"));
    }

    #[test]
    fn rescan_flags_and_masks_leftover_credentials() {
        let (clean, hits) = rescan("see https://h/x?token=abc\nplain line");
        assert_eq!(hits, 1, "含凭据的行应被二次扫描捕获");
        assert!(clean.contains("token=***"));
        assert!(!clean.contains("abc"));
        // 已经脱敏过的文本不会被误报。
        let (_, hits) = rescan("see https://h/x?token=***");
        assert_eq!(hits, 0);
    }

    #[test]
    fn sensitive_settings_are_masked() {
        assert!(sensitive_setting("proxy.password"));
        assert!(sensitive_setting("ed2k_token"));
        assert!(!sensitive_setting("general.max_conns"));
    }

    #[test]
    fn export_writes_a_bundle_for_a_failed_task() {
        // 临时目录用 `tempfile::tempdir()`（绝对路径 + Drop 自动清理）。
        let tmp = crate::testsupport::tempdir("diag");
        let dir = tmp.path();
        let conn = crate::db::open_db(&dir.join("db.sqlite")).expect("open db");
        let id = crate::model::insert_download(
            &conn,
            "https://cdn.example/a.iso?token=deadbeef&sign=abc",
            "a.iso",
            r"C:\Users\bob\Downloads",
            0,
            4,
        )
        .expect("insert");
        // 事件里也塞一份凭据：两条通路都必须被打码。
        crate::model::log_event(&conn, id, "start", Some("mode=fastdl token=deadbeef"));
        crate::model::log_event(&conn, id, "error", Some("disk_full"));

        let report = export_task_bundle(&conn, id, dir).expect("export");
        assert!(report.path.exists(), "诊断包应落盘");
        assert!(report.bytes > 0);
        // `redaction_findings` 是**二次扫描**的命中数：正常应恒为 0。
        // 一旦有人加了新字段却忘了脱敏，这里会立刻变红。
        assert_eq!(
            report.redaction_findings, 0,
            "导出内容里出现了漏脱敏的文本：{:?}",
            report.entries
        );
        assert!(report.truncated.is_empty());

        // 条目名在 zip 中央目录里是明文，据此验证包结构（内容已压缩，不在此解压）。
        let raw = std::fs::read(&report.path).unwrap();
        let names = String::from_utf8_lossy(&raw).into_owned();
        for want in [
            "manifest.json",
            "task.json",
            "events.jsonl",
            "metrics.json",
            "error.json",
            "REDACTION.md",
        ] {
            assert!(names.contains(want), "诊断包缺少条目 {want}");
        }
    }

    #[test]
    fn phases_are_aggregated_from_json_log_lines() {
        let log = concat!(
            r#"{"ts":"t","level":"info","event":"net.connect","task":7,"phase":"connect","total_ms":40,"conns":2}"#,
            "\n",
            r#"{"ts":"t","level":"info","event":"net.connect","task":7,"phase":"connect","total_ms":10,"conns":1}"#,
            "\n",
            r#"{"ts":"t","level":"info","event":"task.start","task":7}"#,
            "\n",
            r#"{"ts":"t","level":"info","event":"net.connect","task":99,"total_ms":999}"#,
            "\n",
            "这不是 JSON\n",
        );
        let view = phases_json(log, 7);
        let connect = &view["net.connect"];
        assert_eq!(connect["count"].as_u64(), Some(2));
        assert_eq!(connect["total_ms"].as_u64(), Some(50), "同名事件应累计");
        assert_eq!(
            connect["last"]["total_ms"].as_u64(),
            Some(10),
            "并保留最后一次"
        );
        assert_eq!(connect["phase"].as_str(), Some("connect"));
        // 别的任务、非 JSON 行、以及不带数值字段的事件都不计入。
        assert!(view.get("task.start").is_none());
        assert_eq!(view.as_object().map(|m| m.len()), Some(1));
    }

    #[test]
    fn global_metrics_summarise_success_and_retries() {
        let tmp = crate::testsupport::tempdir("diag");
        let dir = tmp.path();
        let conn = crate::db::open_db(&dir.join("db.sqlite")).expect("open db");
        let dir_text = dir.to_string_lossy().into_owned();
        let ok =
            crate::model::insert_download(&conn, "https://h/ok.bin", "ok.bin", &dir_text, 0, 1)
                .unwrap();
        let bad =
            crate::model::insert_download(&conn, "https://h/bad.bin", "bad.bin", &dir_text, 0, 1)
                .unwrap();
        let _ = crate::model::set_status(&conn, ok, crate::model::Status::Done, None);
        // 顺序有讲究：`set_retry_wait` 会把状态打回 `queued`（重试排期的语义），
        // 所以它必须在置终态**之前**调用，否则终态会被它覆盖掉。
        let _ = crate::model::set_retry_wait(&conn, bad, 3, 0);
        let _ = crate::model::set_status(&conn, bad, crate::model::Status::Error, None);

        let m = global_metrics(&conn);
        assert_eq!(m["tasks_by_status"]["done"].as_i64(), Some(1));
        assert_eq!(
            m["tasks_by_status"]["error"].as_i64(),
            Some(1),
            "失败终态名是 error（不是 failed）"
        );
        assert_eq!(m["success_rate"].as_f64(), Some(0.5));
        assert_eq!(m["retries_total"].as_i64(), Some(3));
        // 只有引擎进程内存里才有的两项必须是显式 null，而不是编造的 0。
        assert!(m["active_connections"].is_null());
        assert!(m["current_speed_bps"].is_null());
    }
}

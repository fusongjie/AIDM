//! §3.1 状态机 + §4 数据模型的持久化层。
//!
//! 状态机：queued -> connecting -> downloading <-> paused
//!                            |            |
//!                            v            v
//!                         verifying -> done     error(可重试)

use rusqlite::Connection;
use rusqlite::OptionalExtension;

/// 下载任务状态（§3.1，含 `verifying`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Queued,
    Connecting,
    Downloading,
    Paused,
    Verifying,
    Done,
    Error,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Queued => "queued",
            Status::Connecting => "connecting",
            Status::Downloading => "downloading",
            Status::Paused => "paused",
            Status::Verifying => "verifying",
            Status::Done => "done",
            Status::Error => "error",
        }
    }
}

impl Status {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "queued" => Status::Queued,
            "connecting" => Status::Connecting,
            "downloading" => Status::Downloading,
            "paused" => Status::Paused,
            "verifying" => Status::Verifying,
            "done" => Status::Done,
            "error" => Status::Error,
            _ => return None,
        })
    }
}

/// 一行下载任务（downloads 表的读取投影）。
#[derive(Debug, Clone)]
pub struct DownloadRow {
    pub id: i64,
    pub url_orig: String,
    pub url_final: Option<String>,
    pub file_name: String,
    pub dir: String,
    pub size_total: Option<i64>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub status: Status,
    pub created_at: i64,
    pub finished_at: Option<i64>,
    pub error_code: Option<String>,
    /// 人类可读失败说明；旧行可能为空（由 `error_code` 回填）。
    pub error_message: Option<String>,
    pub http_status: Option<u16>,
    pub speed_limit_kbps: i64,
    pub max_conns: i64,
    /// `ext` 或 `manual`；旧数据缺省按 manual 处理。
    pub source: String,
    /// 来源网页（HTTP Referer）；未知为 None。
    pub referrer: Option<String>,
    /// 每任务自定义请求头（`Name: value` 逐行）；无则 None。
    pub custom_headers: Option<String>,
    /// 备用地址（镜像），每行一个；无则 None。候选序列见 `crate::alt`。
    pub alt_urls: Option<String>,
    /// 当前生效的候选序号：0 = `url_orig`，n>0 = `alt_urls` 的第 n 行。
    pub alt_cursor: i64,
    /// 所属队列（`queues.id`）；默认队列恒为 1。
    ///
    /// 队列只做启停/时间窗准入，不参与排序；任务按 id（入队先后）派发。
    pub queue_id: i64,
    /// BitTorrent 逐文件选择（逗号分隔索引）；None = 全选。
    pub bt_files: Option<String>,
    /// 累计下载耗时（毫秒）。**只统计 worker 真正在跑的时间**：暂停、排队等待、
    /// 失败退避都不计入，所以它是"净下载时间"，速度曲线横轴与「用时」都用它。
    pub active_ms: i64,
    /// eD2k 文件哈希（32 位十六进制小写）；非 eD2k 任务为 None。
    pub ed2k_hash: Option<String>,
    /// eD2k AICH 根哈希（Base32 原文）；链接没给就 None。
    pub aich_root: Option<String>,
    /// 上游声明的整文件 SHA-256（64 位小写十六进制）；未知为 None。
    ///
    /// 来源是同目录的兄弟文件（`CHECKSUM` / `<文件名>.sha256`）。**不校验上游签名**
    /// （不内置发行方公钥），所以它是"跨镜像比对与下载后校验用的内容凭证"，
    /// 不是信任根；取不到时行为与从前完全一致。
    pub sha256_expected: Option<String>,
    /// 历史列：保留以兼容旧库，调度器不再读取。
    pub priority: i32,
    /// unix 毫秒；未在退避中为 None。
    pub retry_at: Option<i64>,
    pub retry_count: i64,
    /// `now` | `queue`
    pub start_mode: String,
    /// 找源已执行次数（仅统计/兼容老库，不再作为预算）。
    pub find_rounds: i64,
    /// 累计适配器执行耗时（毫秒，不含下载）。
    pub find_spent_ms: i64,
    /// 最近一轮找源时刻（unix 毫秒）；`None` = 从未找过。
    pub find_last_at: Option<i64>,
}

/// 一行分段（segments 表）。
#[derive(Debug, Clone)]
pub struct SegmentRow {
    pub id: i64,
    pub download_id: i64,
    pub idx: i32,
    pub pos_start: i64,
    pub pos_end: Option<i64>,
    pub done_bytes: i64,
    pub part_path: String,
    pub status: String,
    pub retries: i64,
    /// 该段绑定的来源地址（跨源聚合下载）。`None` = 用任务级 `url_final` / `url_orig`。
    ///
    /// 同一段**只从一个源取**：没有分片级哈希时，"各源内容一致"只能靠完成后用上游
    /// 整文件 SHA-256 兜底，所以来源必须可追溯（重启续传也要接着用它）。
    pub src_url: Option<String>,
    /// 该段绑定来源在**分配时**的版本标识（`etag:<v>` / `lm:<v>`）；未知为 None。
    ///
    /// 换源/重启续传时与当前探测到的版本比对；不同就换源或重下，绝不拼字节。
    pub src_version: Option<String>,
}

impl SegmentRow {
    /// 该段期望字节数（`pos_end` 未知时为 None）。
    pub fn expected_len(&self) -> Option<u64> {
        let end = self.pos_end?;
        Some((end - self.pos_start + 1).max(0) as u64)
    }

    pub fn is_done(&self) -> bool {
        self.status == "done"
    }
}

pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// 记录一条事件（events 表）。事件失败仅上报，不影响主流程。
///
/// 这里是 events 表的唯一写入口，脱敏（§11）也放在这里：调用方无需记得处理，
/// 任何路径写进来的 URL 都会被 `redact::redact_text` 处理一次。
pub fn log_event(conn: &Connection, download_id: i64, kind: &str, detail: Option<&str>) {
    let ts = now_secs();
    let detail = detail.map(crate::redact::redact_text);
    let mut fields = detail
        .as_deref()
        .map(extract_event_fields)
        .unwrap_or_default();
    if fields.err_code.is_none() && kind == "error" {
        fields.err_code = detail
            .as_deref()
            .and_then(|text| text.split_whitespace().next())
            .map(str::to_string);
    }
    if let Err(e) = conn.execute(
        "INSERT INTO events(download_id, kind, ts, detail, phase, outcome, err_code,          dur_ms, attempt, seg, conn, proto) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        rusqlite::params![
            download_id,
            kind,
            ts,
            detail.as_deref(),
            fields.phase,
            fields.outcome,
            fields.err_code,
            fields.dur_ms,
            fields.attempt,
            fields.seg,
            fields.conn,
            fields.proto
        ],
    ) {
        eprintln!("aidm: log_event failed: {e}");
    }
}

/// `events` 表的结构化字段（从 `detail` 的 `k=v` 片段提取）。
#[derive(Default)]
struct EventFields {
    phase: Option<String>,
    outcome: Option<String>,
    err_code: Option<String>,
    dur_ms: Option<i64>,
    attempt: Option<i64>,
    seg: Option<i64>,
    conn: Option<String>,
    proto: Option<String>,
}

/// 从 `detail` 的 `k=v` 片段提取结构化字段，写入 `events` 的对应列。
///
/// 只认固定键；其余内容仍留在 `detail` 文本里，保持旧调用点兼容。
fn extract_event_fields(detail: &str) -> EventFields {
    let mut fields = EventFields::default();
    for token in detail.split_whitespace() {
        let Some((key, value)) = token.split_once('=') else {
            continue;
        };
        let value = value.trim_matches(|c: char| c == ',' || c == ';');
        if value.is_empty() {
            continue;
        }
        match key {
            "phase" => fields.phase = Some(value.to_string()),
            "outcome" => fields.outcome = Some(value.to_string()),
            "err_code" | "code" => fields.err_code = Some(value.to_string()),
            "dur_ms" => fields.dur_ms = value.parse().ok(),
            "attempt" => fields.attempt = value.parse().ok(),
            "seg" => fields.seg = value.parse().ok(),
            "conn" => fields.conn = Some(value.to_string()),
            "proto" => fields.proto = Some(value.to_string()),
            _ => {}
        }
    }
    fields
}

/// 列出某任务事件（按 id 升序）。
pub fn list_events(
    conn: &Connection,
    download_id: i64,
) -> rusqlite::Result<Vec<(String, Option<String>)>> {
    let mut stmt =
        conn.prepare("SELECT kind, detail FROM events WHERE download_id = ?1 ORDER BY id")?;
    let rows = stmt.query_map([download_id], |r| Ok((r.get(0)?, r.get(1)?)))?;
    rows.collect()
}

/// 任务事件的结构化视图（`task_events` IPC 与诊断包共用）。
#[derive(Debug, Clone)]
pub struct EventRecord {
    pub seq: i64,
    pub kind: String,
    pub ts: i64,
    pub phase: Option<String>,
    pub outcome: Option<String>,
    pub err_code: Option<String>,
    pub dur_ms: Option<i64>,
    pub attempt: Option<i64>,
    pub seg: Option<i64>,
    pub conn: Option<String>,
    pub proto: Option<String>,
    pub detail: Option<String>,
}

fn event_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<EventRecord> {
    Ok(EventRecord {
        seq: r.get(0)?,
        kind: r.get(1)?,
        ts: r.get(2)?,
        phase: r.get(3)?,
        outcome: r.get(4)?,
        err_code: r.get(5)?,
        dur_ms: r.get(6)?,
        attempt: r.get(7)?,
        seg: r.get(8)?,
        conn: r.get(9)?,
        proto: r.get(10)?,
        detail: r.get(11)?,
    })
}

/// 异常判定：明确失败类事件，或带错误码的重试——**排除 `slow_conn`**。
///
/// 「持续慢」只是换一条新连接（不消耗重试预算），是正常调度而不是错误；
/// 混进来会把慢源交换刷成一片红色，反而盖住真正的失败。
const ERROR_EVENT_COND: &str =
    " AND (kind IN ('error','alt_failed','sha256_mismatch','write_denied','quota') \
       OR (err_code IS NOT NULL AND err_code <> 'slow_conn') \
       OR outcome = 'fail')";

/// 最近 `limit` 条事件，按时间正序返回（先取最新再反转）。
pub fn list_events_full(
    conn: &Connection,
    download_id: i64,
    limit: u32,
) -> rusqlite::Result<Vec<EventRecord>> {
    let limit = i64::from(limit.clamp(1, 500));
    let mut stmt = conn.prepare(
        "SELECT id, kind, ts, phase, outcome, err_code, dur_ms, attempt, seg, conn, proto, detail          FROM events WHERE download_id = ?1 ORDER BY id DESC LIMIT ?2",
    )?;
    let rows = stmt.query_map(rusqlite::params![download_id, limit], event_from_row)?;
    let mut items: Vec<EventRecord> = rows.collect::<rusqlite::Result<_>>()?;
    items.reverse();
    Ok(items)
}

/// 下载日志的一页：**倒序**（最新在前），跳过 `unified_*` 影子埋点。
///
/// `errors_only` 只保留异常；分页与计数用同一条件，保证标题数字与列表一致。
pub fn list_events_page(
    conn: &Connection,
    download_id: i64,
    limit: u32,
    offset: u32,
    errors_only: bool,
) -> rusqlite::Result<Vec<EventRecord>> {
    let limit = i64::from(limit.clamp(1, 500));
    let offset = i64::from(offset);
    let cond = if errors_only { ERROR_EVENT_COND } else { "" };
    let sql = format!(
        "SELECT id, kind, ts, phase, outcome, err_code, dur_ms, attempt, seg, conn, proto, detail \
         FROM events WHERE download_id = ?1 AND kind NOT LIKE 'unified_%'{cond} \
         ORDER BY id DESC LIMIT ?2 OFFSET ?3"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(rusqlite::params![download_id, limit, offset], event_from_row)?;
    rows.collect()
}

/// 删除某任务的全部事件（下载日志）。返回删除行数。
pub fn clear_task_events(conn: &Connection, download_id: i64) -> rusqlite::Result<usize> {
    conn.execute("DELETE FROM events WHERE download_id = ?1", [download_id])
}

/// 同一筛选条件下的总条数（下载日志标题与“还有更多”判定）。
pub fn count_events(
    conn: &Connection,
    download_id: i64,
    errors_only: bool,
) -> rusqlite::Result<u64> {
    let cond = if errors_only { ERROR_EVENT_COND } else { "" };
    let sql = format!(
        "SELECT count(*) FROM events WHERE download_id = ?1 AND kind NOT LIKE 'unified_%'{cond}"
    );
    let n: i64 = conn.query_row(&sql, [download_id], |r| r.get(0))?;
    Ok(n.max(0) as u64)
}

/// 新建任务行（status=queued），返回任务 id。
pub fn insert_download(
    conn: &Connection,
    url_orig: &str,
    file_name: &str,
    dir: &str,
    speed_limit_kbps: i64,
    max_conns: i64,
) -> rusqlite::Result<i64> {
    insert_download_with_source(
        conn,
        url_orig,
        file_name,
        dir,
        speed_limit_kbps,
        max_conns,
        "manual",
    )
}

/// 新建任务行，并记录来源（`ext` / `manual`）。
pub fn insert_download_with_source(
    conn: &Connection,
    url_orig: &str,
    file_name: &str,
    dir: &str,
    speed_limit_kbps: i64,
    max_conns: i64,
    source: &str,
) -> rusqlite::Result<i64> {
    insert_download_ex(
        conn,
        url_orig,
        file_name,
        dir,
        speed_limit_kbps,
        max_conns,
        source,
        "now",
        0,
    )
}

/// 新建任务行，指定来源与 `start_mode`（`now`/`queue`）；`priority` 仅为兼容旧调用。
pub fn insert_download_ex(
    conn: &Connection,
    url_orig: &str,
    file_name: &str,
    dir: &str,
    speed_limit_kbps: i64,
    max_conns: i64,
    source: &str,
    start_mode: &str,
    priority: i32,
) -> rusqlite::Result<i64> {
    // 每任务连接数不设限：0 = 不限（由分段数/候选源数与全局闸门收窄），正数 = 用户指定。
    let max_conns = max_conns.max(0);
    let source = if source == "ext" { "ext" } else { "manual" };
    let start_mode = if start_mode == "queue" {
        "queue"
    } else {
        "now"
    };
    conn.execute(
        "INSERT INTO downloads(url_orig, file_name, dir, status, created_at, speed_limit_kbps, max_conns, source,
            priority, retry_count, start_mode)
         VALUES(?1, ?2, ?3, 'queued', ?4, ?5, ?6, ?7, ?8, 0, ?9)",
        rusqlite::params![
            url_orig,
            file_name,
            dir,
            now_secs(),
            speed_limit_kbps,
            max_conns,
            source,
            priority,
            start_mode
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

/// 初始化单连接分段行（idx=0；未知大小 `pos_end` 为 None）。
pub fn init_single_segment(
    conn: &Connection,
    download_id: i64,
    part_path: &str,
    pos_end: Option<i64>,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO segments(download_id, idx, pos_start, pos_end, part_path, status)
         VALUES(?1, 0, 0, ?3, ?2, 'running')
         ON CONFLICT(download_id, idx) DO UPDATE SET
            part_path = excluded.part_path,
            pos_end = COALESCE(excluded.pos_end, pos_end),
            status = 'running'",
        rusqlite::params![download_id, part_path, pos_end],
    )?;
    Ok(())
}

/// 用规划好的多段覆盖该任务的 segments 行。
pub fn replace_segments(
    conn: &Connection,
    download_id: i64,
    spans: &[crate::segment::ByteSpan],
    part_paths: &[String],
) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM segments WHERE download_id = ?1", [download_id])?;
    for (idx, (span, path)) in spans.iter().zip(part_paths.iter()).enumerate() {
        conn.execute(
            "INSERT INTO segments(download_id, idx, pos_start, pos_end, done_bytes, part_path, status, retries)
             VALUES(?1, ?2, ?3, ?4, 0, ?5, 'pending', 0)",
            rusqlite::params![
                download_id,
                idx as i32,
                span.start as i64,
                span.end as i64,
                path
            ],
        )?;
    }
    Ok(())
}

/// 删除某任务全部分段行。
pub fn clear_segments(conn: &Connection, download_id: i64) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM segments WHERE download_id = ?1", [download_id])?;
    Ok(())
}

/// 多段布局：段数 ≥ 2，或 part 落在 `.aidm/<id>/`（单线程降级时 part 就是最终文件）。
pub fn is_multi_part_layout(segs: &[SegmentRow]) -> bool {
    segs.len() >= 2
        || segs
            .iter()
            .any(|s| s.part_path.contains("/.aidm/") || s.part_path.contains("\\.aidm\\"))
}

/// part 落在任务自己的中间目录里（再切分时新段的文件名才保证不撞车）。
fn is_part_in_dir(part_path: &str) -> bool {
    part_path.contains("/.aidm/") || part_path.contains("\\.aidm\\")
}

/// 再切分预演（不写库）：返回新布局；`None` 表示不适用或无需切分。
///
/// 只有在「多段布局 + 段长已知 + 段数少于设置值 + 新段 part 文件名不会撞车」时才可切。
pub fn resplit_plan(
    segs: &[SegmentRow],
    desired: i64,
) -> Option<Vec<crate::segment::PlannedSegment>> {
    let desired = desired.max(1) as u32;
    if segs.is_empty() || segs.len() >= desired as usize {
        return None;
    }
    if !segs.iter().all(|s| is_part_in_dir(&s.part_path)) {
        // 单线程布局（part 即最终文件）不可切
        return None;
    }
    let mut states = Vec::with_capacity(segs.len());
    for s in segs {
        let end = s.pos_end?;
        if end < s.pos_start {
            return None;
        }
        states.push(crate::segment::SegmentState {
            start: s.pos_start.max(0) as u64,
            end: end.max(0) as u64,
            done: s.done_bytes.max(0) as u64,
        });
    }
    let planned = crate::segment::resplit_segments(&states, desired);
    if planned.len() <= segs.len() {
        return None;
    }
    Some(planned)
}

/// 按 [`resplit_plan`] 落库：按字节序重编号，保留各段已完成字节、状态与 part 文件；
/// 新段 `status='pending'`、`done_bytes=0`，part 文件接在现有最大 idx 之后。
/// 返回新增段数（0 = 未改动）。调用方必须确保该任务没有正在写盘的段线程。
pub fn resplit_task_segments(
    conn: &Connection,
    download_id: i64,
    dir: &std::path::Path,
    desired: i64,
) -> rusqlite::Result<usize> {
    let segs = list_segments(conn, download_id)?;
    let Some(planned) = resplit_plan(&segs, desired) else {
        return Ok(0);
    };
    let created = planned.iter().filter(|p| p.source.is_none()).count();
    let mut next_idx = segs.iter().map(|s| s.idx).max().unwrap_or(-1) + 1;
    let mut rows: Vec<(i32, i64, i64, i64, String, String, i64)> =
        Vec::with_capacity(planned.len());
    for (i, p) in planned.iter().enumerate() {
        let (part_path, status, retries) = match p.source {
            Some(src) => (
                segs[src].part_path.clone(),
                segs[src].status.clone(),
                segs[src].retries,
            ),
            None => {
                let path = crate::segment::part_path(dir, download_id, next_idx)
                    .to_string_lossy()
                    .into_owned();
                next_idx += 1;
                (path, "pending".to_string(), 0)
            }
        };
        rows.push((
            i as i32,
            p.start as i64,
            p.end as i64,
            p.done as i64,
            part_path,
            status,
            retries,
        ));
    }
    // 防御：新段 part 文件名不能撞上任何已有段（正常流程下 idx 恒为 0..n-1）。
    let mut paths = std::collections::HashSet::with_capacity(rows.len());
    if !rows.iter().all(|r| paths.insert(r.4.as_str())) {
        return Ok(0);
    }
    let tx = conn.unchecked_transaction()?;
    tx.execute("DELETE FROM segments WHERE download_id = ?1", [download_id])?;
    for (idx, start, end, done, part_path, status, retries) in &rows {
        tx.execute(
            "INSERT INTO segments(download_id, idx, pos_start, pos_end, done_bytes, part_path, status, retries)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![download_id, idx, start, end, done, part_path, status, retries],
        )?;
    }
    tx.commit()?;
    Ok(created)
}

/// 列出某任务全部分段（按 idx）。
/// 每任务**期望**连接数：主机/任务级例外优先，否则用全局闸门；两者取小。
///
/// 这是全项目唯一的解析器。worker 用它决定切几段，协调器用它产出
/// `PlanSlices`——两边各算一套就会切出不同段数，"方案逐字节相同"的验收
/// 也就失去意义。
pub fn task_conns_for(conn: &Connection, row: &DownloadRow) -> u32 {
    let base = crate::hosts::task_conns(conn, &row.url_orig).max(1);
    let cap = get_conn_cap(conn, row.id)
        .ok()
        .flatten()
        .map(|c| c.conn_cap)
        .unwrap_or(base)
        .max(1);
    base.min(cap)
}

pub fn list_segments(conn: &Connection, download_id: i64) -> rusqlite::Result<Vec<SegmentRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, download_id, idx, pos_start, pos_end, done_bytes, part_path, status, retries,
                src_url, src_version
         FROM segments WHERE download_id = ?1 ORDER BY idx",
    )?;
    let rows = stmt.query_map([download_id], seg_from)?;
    rows.collect()
}

/// 记录某段绑定的来源（跨源聚合下载）。
pub fn set_segment_src(
    conn: &Connection,
    download_id: i64,
    idx: i32,
    src_url: Option<&str>,
) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE segments SET src_url = ?3 WHERE download_id = ?1 AND idx = ?2",
        rusqlite::params![download_id, idx, src_url],
    )?;
    Ok(())
}

/// 记录某段绑定来源的版本标识。
pub fn set_segment_src_version(
    conn: &Connection,
    download_id: i64,
    idx: i32,
    version: Option<&str>,
) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE segments SET src_version = ?3 WHERE download_id = ?1 AND idx = ?2",
        rusqlite::params![download_id, idx, version],
    )?;
    Ok(())
}

/// 某个来源上已绑定的段版本（取第一条非 NULL）。用于换源/续传前比对。
pub fn segment_src_version(
    conn: &Connection,
    download_id: i64,
    src_url: &str,
) -> rusqlite::Result<Option<String>> {
    Ok(conn
        .query_row(
            "SELECT src_version FROM segments
             WHERE download_id = ?1 AND src_url = ?2 AND src_version IS NOT NULL
             LIMIT 1",
            rusqlite::params![download_id, src_url],
            |r| r.get::<_, String>(0),
        )
        .ok())
}

fn seg_from(row: &rusqlite::Row<'_>) -> rusqlite::Result<SegmentRow> {
    Ok(SegmentRow {
        id: row.get(0)?,
        download_id: row.get(1)?,
        idx: row.get(2)?,
        pos_start: row.get(3)?,
        pos_end: row.get(4)?,
        done_bytes: row.get(5)?,
        part_path: row.get(6)?,
        status: row.get(7)?,
        retries: row.get(8)?,
        src_url: row.get(9)?,
        src_version: row.get(10)?,
    })
}

/// 更新指定 idx 段的进度与状态。
pub fn set_segment_state(
    conn: &Connection,
    download_id: i64,
    idx: i32,
    done_bytes: i64,
    status: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE segments SET done_bytes = ?3, status = ?4 WHERE download_id = ?1 AND idx = ?2",
        rusqlite::params![download_id, idx, done_bytes, status],
    )?;
    Ok(())
}

/// 写入段重试次数。
pub fn set_segment_retries(
    conn: &Connection,
    download_id: i64,
    idx: i32,
    retries: i64,
) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE segments SET retries = ?3 WHERE download_id = ?1 AND idx = ?2",
        rusqlite::params![download_id, idx, retries],
    )?;
    Ok(())
}

/// 已完成字节合计。
pub fn sum_done_bytes(conn: &Connection, download_id: i64) -> rusqlite::Result<u64> {
    let n: i64 = conn.query_row(
        "SELECT COALESCE(SUM(done_bytes), 0) FROM segments WHERE download_id = ?1",
        [download_id],
        |r| r.get(0),
    )?;
    Ok(n.max(0) as u64)
}

/// 该任务当前的分段行数。
pub fn count_segments(conn: &Connection, download_id: i64) -> rusqlite::Result<u64> {
    let n: i64 = conn.query_row(
        "SELECT COUNT(*) FROM segments WHERE download_id = ?1",
        [download_id],
        |r| r.get(0),
    )?;
    Ok(n.max(0) as u64)
}

/// 收尾：把各段记成「整段下满」。
///
/// 任务完成是以**文件**为准（改名/校验成功）判定的，比逐段累加更权威。运行期
/// `persist` 是 1 Hz 采样，暂停/失败的最后一段进度以及「运行中再切分」带来的
/// 行数与布局错位，都会让 `sum_done_bytes < size_total`，从而出现「状态已完成、
/// 进度却不是 100%」。完成时调用本函数让两者对齐。
pub fn finalize_segments(conn: &Connection, download_id: i64) -> rusqlite::Result<usize> {
    conn.execute(
        // 未知总长的单连接行 `pos_end` 为 NULL：这种行不能拿 NULL 去算，
        // 保留它原来的 done_bytes（= 实际写入字节），只把状态收尾。
        "UPDATE segments
            SET done_bytes = CASE
                    WHEN pos_end IS NULL THEN done_bytes
                    ELSE MAX(pos_end - pos_start + 1, 0)
                 END,
                status = 'done'
          WHERE download_id = ?1",
        [download_id],
    )
}

/// 找一个"同一 URL 且尚未完成"的任务（重复链接策略用）。
pub fn find_active_by_url(conn: &Connection, url: &str) -> rusqlite::Result<Option<i64>> {
    conn.query_row(
        "SELECT id FROM downloads
         WHERE url_orig = ?1 AND status NOT IN ('done','error')
         ORDER BY id LIMIT 1",
        [url],
        |r| r.get::<_, i64>(0),
    )
    .map(Some)
    .or_else(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => Ok(None),
        other => Err(other),
    })
}

/// 所有任务已落盘字节合计（流量配额用）。
pub fn sum_all_done_bytes(conn: &Connection) -> rusqlite::Result<u64> {
    let n: i64 = conn.query_row(
        "SELECT COALESCE(SUM(done_bytes), 0) FROM segments",
        [],
        |r| r.get(0),
    )?;
    Ok(n.max(0) as u64)
}

/// 是否所有段均为 done（无段时为 false）。
pub fn all_segments_done(conn: &Connection, download_id: i64) -> rusqlite::Result<bool> {
    let (n, done): (i64, i64) = conn.query_row(
        "SELECT COUNT(*), COALESCE(SUM(CASE WHEN status = 'done' THEN 1 ELSE 0 END), 0)
         FROM segments WHERE download_id = ?1",
        [download_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    Ok(n > 0 && n == done)
}

/// 更新任务状态；带错误码时同时落库（不改 `error_message` / `http_status`）。
pub fn set_status(
    conn: &Connection,
    id: i64,
    status: Status,
    error_code: Option<&str>,
) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE downloads SET status = ?2, error_code = ?3 WHERE id = ?1",
        rusqlite::params![id, status.as_str(), error_code],
    )?;
    Ok(())
}

/// 写入机器码 + 可读说明 + 可选 HTTP 状态。
pub fn set_error_fields(
    conn: &Connection,
    id: i64,
    status: Status,
    error_code: Option<&str>,
    error_message: Option<&str>,
    http_status: Option<u16>,
) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE downloads SET status = ?2, error_code = ?3, error_message = ?4, http_status = ?5 WHERE id = ?1",
        rusqlite::params![
            id,
            status.as_str(),
            error_code,
            error_message,
            http_status.map(i64::from)
        ],
    )?;
    Ok(())
}

/// 完成任务：状态 done + finished_at + 最终 URL。
pub fn mark_done(conn: &Connection, id: i64, url_final: &str) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE downloads SET status = 'done', url_final = ?2, finished_at = ?3,
                error_code = NULL, error_message = NULL, http_status = NULL WHERE id = ?1",
        rusqlite::params![id, url_final, now_secs()],
    )?;
    // 任务已完成，下一次重新下载应该从正常并发开始。
    clear_conn_cap(conn, id)?;
    Ok(())
}

/// 一条 eD2k 源。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed2kSource {
    pub host: String,
    pub port: u16,
    /// 来源：`server` / `kad` / `link` / `pex`
    pub kind: Option<String>,
    /// 已尝试次数
    pub tries: i64,
    /// 已失败次数
    pub fails: i64,
}

/// 写入/更新一个 eD2k 源（同一 (任务,主机,端口) 只更新 `seen_at` 与来源）。
pub fn upsert_ed2k_source(
    conn: &Connection,
    download_id: i64,
    host: &str,
    port: u16,
    kind: Option<&str>,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO ed2k_sources(download_id, host, port, kind, tries, fails, seen_at)
         VALUES(?1, ?2, ?3, ?4, 0, 0, ?5)
         ON CONFLICT(download_id, host, port) DO UPDATE SET
            kind = COALESCE(excluded.kind, ed2k_sources.kind),
            seen_at = excluded.seen_at",
        rusqlite::params![download_id, host, port, kind, now_secs()],
    )?;
    Ok(())
}

/// 批量写入源，返回新增（真正插入）的条数。
pub fn add_ed2k_sources(
    conn: &Connection,
    download_id: i64,
    sources: &[(String, u16)],
    kind: Option<&str>,
) -> rusqlite::Result<usize> {
    let mut added = 0usize;
    for (host, port) in sources {
        let before: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM ed2k_sources WHERE download_id=?1 AND host=?2 AND port=?3",
                rusqlite::params![download_id, host, port],
                |r| r.get(0),
            )
            .unwrap_or(0);
        upsert_ed2k_source(conn, download_id, host, *port, kind)?;
        if before == 0 {
            added += 1;
        }
    }
    Ok(added)
}

/// 有成功传输记录的源优先，其余按失败少、尝试少、最近见到排序。
pub fn list_ed2k_sources(
    conn: &Connection,
    download_id: i64,
    limit: usize,
) -> rusqlite::Result<Vec<Ed2kSource>> {
    let mut stmt = conn.prepare(
        "SELECT host, port, kind, tries, fails FROM ed2k_sources
         WHERE download_id = ?1
         ORDER BY (tries > fails) DESC, fails ASC, tries ASC, seen_at DESC
         LIMIT ?2",
    )?;
    let rows = stmt.query_map(rusqlite::params![download_id, limit as i64], |r| {
        Ok(Ed2kSource {
            host: r.get(0)?,
            port: r.get::<_, i64>(1)? as u16,
            kind: r.get(2)?,
            tries: r.get(3)?,
            fails: r.get(4)?,
        })
    })?;
    rows.collect()
}

/// 记录一次源连接结果（尝试 +1，失败时失败数 +1）。
pub fn note_ed2k_source_result(
    conn: &Connection,
    download_id: i64,
    host: &str,
    port: u16,
    ok: bool,
) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE ed2k_sources SET tries = tries + 1, fails = fails + (CASE WHEN ?4 THEN 0 ELSE 1 END)
         WHERE download_id = ?1 AND host = ?2 AND port = ?3",
        rusqlite::params![download_id, host, port, ok],
    )?;
    Ok(())
}

/// 清空某任务的源（换哈希/重下时用）。
pub fn clear_ed2k_sources(conn: &Connection, download_id: i64) -> rusqlite::Result<usize> {
    conn.execute(
        "DELETE FROM ed2k_sources WHERE download_id = ?1",
        rusqlite::params![download_id],
    )
}

/// 记录 eD2k 元信息（文件哈希 / AICH 根哈希）。P2P 任务靠哈希对账与校验，必须落库。
pub fn set_ed2k_meta(
    conn: &Connection,
    id: i64,
    ed2k_hash: Option<&str>,
    aich_root: Option<&str>,
) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE downloads SET ed2k_hash = ?2, aich_root = ?3 WHERE id = ?1",
        rusqlite::params![id, ed2k_hash, aich_root],
    )?;
    Ok(())
}

/// 记录每任务自定义请求头。
///
/// 与 cookies 不同：这是**任务配置**而不是会话凭据，必须落库，
/// 否则引擎重启后续传会丢掉它，防盗链站点会立刻失败。
pub fn set_download_custom_headers(
    conn: &Connection,
    id: i64,
    custom_headers: Option<&str>,
) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE downloads SET custom_headers = ?2 WHERE id = ?1",
        rusqlite::params![id, custom_headers],
    )?;
    Ok(())
}

/// 把任务主地址改成新的地址（eD2k -> HTTP 换源用）。`ed2k_hash` 不动，
/// 供 HTTP 下载完成后的 eD2k 整包校验使用。
pub fn set_url_orig(conn: &Connection, id: i64, url: &str) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE downloads SET url_orig = ?2 WHERE id = ?1",
        rusqlite::params![id, url],
    )?;
    Ok(())
}

/// 记录备用地址（镜像）序列。
///
/// 与自定义请求头同理：这是**任务配置**，必须落库——主地址中途坏掉时，
/// 重试、引擎重启与续传都要靠它把同一份文件接着下完。
/// 候选序列与切换规则见 [`crate::alt`]。
pub fn set_alt_urls(conn: &Connection, id: i64, alt_urls: Option<&str>) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE downloads SET alt_urls = ?2 WHERE id = ?1",
        rusqlite::params![id, alt_urls],
    )?;
    Ok(())
}

/// 记录上游 Metalink 里发现的镜像地址（每行一个）。
///
/// 这些地址**不参与候选序号**（`alt_cursor` 是对下标的承诺，网络发现的列表不稳定），
/// 只作为跨源聚合的来源池输入。
pub fn set_mirrors_urls(conn: &Connection, id: i64, urls: Option<&str>) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE downloads SET mirrors_urls = ?2 WHERE id = ?1",
        rusqlite::params![id, urls],
    )?;
    Ok(())
}

/// 读上游发现的镜像地址（每行一个）。没有则空 Vec。
pub fn get_mirrors_urls(conn: &Connection, id: i64) -> Vec<String> {
    conn.query_row(
        "SELECT mirrors_urls FROM downloads WHERE id = ?1",
        [id],
        |r| r.get::<_, Option<String>>(0),
    )
    .ok()
    .flatten()
    .map(|s| {
        s.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect()
    })
    .unwrap_or_default()
}

/// 记录当前生效的候选序号（0 = 主地址，n>0 = 备用地址第 n 条）。
pub fn set_alt_cursor(conn: &Connection, id: i64, cursor: i64) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE downloads SET alt_cursor = ?2 WHERE id = ?1",
        rusqlite::params![id, cursor.max(0)],
    )?;
    Ok(())
}

/// 记录上游声明的整文件 SHA-256（下载完成后据此校验；换镜像时也用它比对身份）。
pub fn set_sha256_expected(
    conn: &Connection,
    id: i64,
    sha256: Option<&str>,
) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE downloads SET sha256_expected = ?2 WHERE id = ?1",
        rusqlite::params![id, sha256],
    )?;
    Ok(())
}

/// BitTorrent 逐文件选择（`None`/空 = 全选）。文本先由 `crate::bt_files` 规范化。
pub fn set_bt_files(conn: &Connection, id: i64, files: Option<&str>) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE downloads SET bt_files = ?2 WHERE id = ?1",
        rusqlite::params![id, files.filter(|f| !f.is_empty())],
    )?;
    Ok(())
}

/// 清掉退避标记。重新关联到磁盘上已有的文件之后，任务不该再显示"等待重试"。
pub fn clear_retry(conn: &Connection, id: i64) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE downloads SET retry_at = NULL, retry_count = 0 WHERE id = ?1",
        [id],
    )?;
    Ok(())
}

/// 把任务重新指向磁盘上已有的文件（`relocate`：文件被移动/改名后找回）。
///
/// 只改"任务指向哪里"，不动文件本身——这与 `Move`（真的搬文件）是两件事。
pub fn set_location(
    conn: &Connection,
    id: i64,
    dir: &str,
    file_name: &str,
) -> rusqlite::Result<usize> {
    conn.execute(
        "UPDATE downloads SET dir = ?2, file_name = ?3 WHERE id = ?1",
        rusqlite::params![id, dir, file_name],
    )
}

/// 记录来源网页（HTTP Referer）。cookies 只进内存，永不落库。
pub fn set_download_referrer(
    conn: &Connection,
    id: i64,
    referrer: Option<&str>,
) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE downloads SET referrer = ?2 WHERE id = ?1",
        rusqlite::params![id, referrer],
    )?;
    Ok(())
}

/// 记录探明的元信息（最终 URL / 总大小 / ETag / Last-Modified / 解析出的文件名）。
pub fn set_meta(
    conn: &Connection,
    id: i64,
    url_final: &str,
    size_total: Option<i64>,
    etag: Option<&str>,
    last_modified: Option<&str>,
    file_name: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE downloads SET url_final = ?2, size_total = ?3, etag = ?4, last_modified = ?5, file_name = ?6 WHERE id = ?1",
        rusqlite::params![id, url_final, size_total, etag, last_modified, file_name],
    )?;
    Ok(())
}

/// 探明元信息（不含文件名）。用户 `rename` 后探测不得覆盖目标名。
pub fn set_probe_meta(
    conn: &Connection,
    id: i64,
    url_final: &str,
    size_total: Option<i64>,
    etag: Option<&str>,
    last_modified: Option<&str>,
) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE downloads SET url_final = ?2, size_total = ?3, etag = ?4, last_modified = ?5 WHERE id = ?1",
        rusqlite::params![id, url_final, size_total, etag, last_modified],
    )?;
    Ok(())
}

/// 无条件改目标文件名（`rename` IPC）。
pub fn set_file_name(conn: &Connection, id: i64, file_name: &str) -> rusqlite::Result<usize> {
    conn.execute(
        "UPDATE downloads SET file_name = ?2 WHERE id = ?1",
        rusqlite::params![id, file_name],
    )
}

/// 仅当当前名仍是 `expected` 时写入解析名，避免覆盖用户 `rename`。
pub fn set_file_name_if(
    conn: &Connection,
    id: i64,
    file_name: &str,
    expected: &str,
) -> rusqlite::Result<usize> {
    conn.execute(
        "UPDATE downloads SET file_name = ?2 WHERE id = ?1 AND file_name = ?3",
        rusqlite::params![id, file_name, expected],
    )
}

/// 更新单连接分段进度（idx=0 段，单连接兼容路径）。
pub fn set_segment_progress(
    conn: &Connection,
    download_id: i64,
    done_bytes: i64,
) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE segments SET done_bytes = ?2 WHERE download_id = ?1 AND idx = 0",
        rusqlite::params![download_id, done_bytes],
    )?;
    Ok(())
}

/// 读取单行任务；不存在返回 None。
pub fn get_download(conn: &Connection, id: i64) -> rusqlite::Result<Option<DownloadRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, url_orig, url_final, file_name, dir, size_total, etag, last_modified,
                status, created_at, finished_at, error_code, speed_limit_kbps, max_conns,
                COALESCE(source, 'manual'),
                COALESCE(priority, 0), retry_at,
                COALESCE(retry_count, 0), COALESCE(start_mode, 'now'),
                error_message, http_status, referrer, custom_headers, ed2k_hash, aich_root,
                alt_urls, COALESCE(alt_cursor, 0), COALESCE(queue_id, 1), bt_files,
                COALESCE(active_ms, 0), sha256_expected,
                COALESCE(find_rounds, 0), COALESCE(find_spent_ms, 0), find_last_at
         FROM downloads WHERE id = ?1",
    )?;
    let mut rows = stmt.query([id])?;
    match rows.next()? {
        Some(row) => Ok(Some(row_from(row)?)),
        None => Ok(None),
    }
}

/// 列出全部任务（created_at 升序）。
pub fn list_downloads(conn: &Connection) -> rusqlite::Result<Vec<DownloadRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, url_orig, url_final, file_name, dir, size_total, etag, last_modified,
                status, created_at, finished_at, error_code, speed_limit_kbps, max_conns,
                COALESCE(source, 'manual'),
                COALESCE(priority, 0), retry_at,
                COALESCE(retry_count, 0), COALESCE(start_mode, 'now'),
                error_message, http_status, referrer, custom_headers, ed2k_hash, aich_root,
                alt_urls, COALESCE(alt_cursor, 0), COALESCE(queue_id, 1), bt_files,
                COALESCE(active_ms, 0), sha256_expected,
                COALESCE(find_rounds, 0), COALESCE(find_spent_ms, 0), find_last_at
         FROM downloads ORDER BY created_at, id",
    )?;
    let rows = stmt.query_map([], row_from)?;
    rows.collect()
}

/// 删除任务（事件/分段随 ON DELETE CASCADE 级联）。
pub fn delete_download(conn: &Connection, id: i64) -> rusqlite::Result<usize> {
    conn.execute("DELETE FROM downloads WHERE id = ?1", [id])
}

fn row_from(row: &rusqlite::Row<'_>) -> rusqlite::Result<DownloadRow> {
    let status: String = row.get(8)?;
    Ok(DownloadRow {
        id: row.get(0)?,
        url_orig: row.get(1)?,
        url_final: row.get(2)?,
        file_name: row.get(3)?,
        dir: row.get(4)?,
        size_total: row.get(5)?,
        etag: row.get(6)?,
        last_modified: row.get(7)?,
        status: Status::from_str(&status).unwrap_or(Status::Error),
        created_at: row.get(9)?,
        finished_at: row.get(10)?,
        error_code: row.get(11)?,
        speed_limit_kbps: row.get(12)?,
        max_conns: row.get(13)?,
        source: row.get(14)?,
        priority: row.get(15)?,
        retry_at: row.get(16)?,
        retry_count: row.get(17)?,
        start_mode: row.get(18)?,
        error_message: row.get(19)?,
        http_status: row
            .get::<_, Option<i64>>(20)?
            .and_then(|n| u16::try_from(n).ok()),
        referrer: row.get(21)?,
        custom_headers: row.get(22)?,
        ed2k_hash: row.get(23)?,
        aich_root: row.get(24)?,
        alt_urls: row.get(25)?,
        alt_cursor: row.get(26)?,
        queue_id: row.get(27)?,
        bt_files: row.get(28)?,
        active_ms: row.get(29)?,
        sha256_expected: row.get(30)?,
        find_rounds: row.get(31)?,
        find_spent_ms: row.get(32)?,
        find_last_at: row.get(33)?,
    })
}

/// 记录一次 eD2k 服务器查源结果。`ok = true` 清零失败；失败累加。
pub fn note_ed2k_server_result(
    conn: &Connection,
    host: &str,
    port: u16,
    ok: bool,
    now_ms: i64,
) -> rusqlite::Result<()> {
    if ok {
        conn.execute(
            "INSERT INTO ed2k_server_health(host, port, fail_streak, last_ok_at)
             VALUES(?1, ?2, 0, ?3)
             ON CONFLICT(host, port) DO UPDATE SET fail_streak = 0, last_ok_at = excluded.last_ok_at",
            rusqlite::params![host, port, now_ms],
        )?;
    } else {
        conn.execute(
            "INSERT INTO ed2k_server_health(host, port, fail_streak, last_fail_at)
             VALUES(?1, ?2, 1, ?3)
             ON CONFLICT(host, port) DO UPDATE SET
                 fail_streak = ed2k_server_health.fail_streak + 1,
                 last_fail_at = excluded.last_fail_at",
            rusqlite::params![host, port, now_ms],
        )?;
    }
    Ok(())
}

/// 冷却期内连续失败 ≥2 次的服务器。返回 `(host, port)` 集合。
pub fn ed2k_bad_servers(
    conn: &Connection,
    now_ms: i64,
    cooldown_ms: i64,
) -> rusqlite::Result<std::collections::HashSet<(String, u16)>> {
    let since = now_ms.saturating_sub(cooldown_ms.max(0));
    let mut stmt = conn.prepare(
        "SELECT host, port FROM ed2k_server_health
         WHERE fail_streak >= 2 AND COALESCE(last_fail_at, 0) >= ?1",
    )?;
    let rows = stmt.query_map([since], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u16))
    })?;
    let mut out = std::collections::HashSet::new();
    for row in rows {
        out.insert(row?);
    }
    Ok(out)
}

/// 一行找源候选（`source_candidates` 表，`docs/source-discovery.md` §7.2）。
#[derive(Debug, Clone, PartialEq)]
pub struct SourceCandidateRow {
    pub id: i64,
    pub download_id: i64,
    pub url: String,
    pub platform: String,
    pub kind: String,
    pub size: Option<i64>,
    pub version: Option<String>,
    pub container: Option<String>,
    pub evidence: String,
    pub digest_algo: Option<String>,
    pub digest_hex: Option<String>,
    pub auth_ref: Option<String>,
    pub origin: Option<String>,
    pub expires_at: Option<i64>,
    pub probe_at: Option<i64>,
    pub score: Option<f64>,
    pub state: String,
    pub created_at: i64,
}

/// `CandidateSource` → 落库行。`state` 默认 `candidate`，`probe_at`/`score` 留空。
pub fn candidate_to_row(
    download_id: i64,
    c: &crate::source::CandidateSource,
    now_ms: i64,
) -> SourceCandidateRow {
    use crate::source::IdentityEvidence;
    let (digest_algo, digest_hex) = match &c.evidence {
        IdentityEvidence::StrongDigest(h) | IdentityEvidence::WeakDigest(h) => {
            (Some(h.algo.as_str().to_string()), Some(h.normalized_hex()))
        }
        IdentityEvidence::PieceManifest { id, algo } => {
            (Some(algo.as_str().to_string()), Some(id.clone()))
        }
        IdentityEvidence::SizeOnly { .. } | IdentityEvidence::Unverified => (None, None),
    };
    SourceCandidateRow {
        id: 0,
        download_id,
        url: c.url.clone(),
        platform: c.platform.as_str().to_string(),
        kind: c.kind.as_str().to_string(),
        size: c.size.and_then(|v| i64::try_from(v).ok()),
        version: c.version.clone(),
        container: c.container.clone(),
        evidence: c.evidence.level().as_str().to_string(),
        digest_algo,
        digest_hex,
        auth_ref: c.auth_ref.clone(),
        origin: c.origin.clone(),
        expires_at: c.expires_at,
        probe_at: None,
        score: None,
        state: "candidate".into(),
        created_at: now_ms,
    }
}

/// 落库行 → `CandidateSource`。未知 platform/kind/evidence 返回 `None`（不猜）。
pub fn row_to_candidate(row: &SourceCandidateRow) -> Option<crate::source::CandidateSource> {
    use crate::source::{
        DeclaredHash, EvidenceOrigin, HashAlgo, IdentityEvidence, Platform, SourceKind,
    };
    let platform = Platform::from_str(&row.platform)?;
    let kind = SourceKind::from_str(&row.kind)?;
    let size = row.size.and_then(|v| u64::try_from(v).ok());
    let declared = || {
        let algo = HashAlgo::from_str(row.digest_algo.as_deref()?)?;
        let hex = row.digest_hex.clone()?;
        Some(DeclaredHash {
            algo,
            hex,
            origin: EvidenceOrigin::PlatformApi,
        })
    };
    let evidence = match row.evidence.as_str() {
        "l4" => IdentityEvidence::StrongDigest(declared()?),
        "l2" => IdentityEvidence::WeakDigest(declared()?),
        "l3" => IdentityEvidence::PieceManifest {
            id: row.digest_hex.clone().unwrap_or_default(),
            algo: row
                .digest_algo
                .as_deref()
                .and_then(HashAlgo::from_str)
                .unwrap_or(HashAlgo::Sha256),
        },
        "l1" => match size {
            Some(size) => IdentityEvidence::SizeOnly { size },
            None => IdentityEvidence::Unverified,
        },
        "l0" => IdentityEvidence::Unverified,
        _ => return None,
    };
    Some(crate::source::CandidateSource {
        url: row.url.clone(),
        platform,
        kind,
        size,
        version: row.version.clone(),
        container: row.container.clone(),
        evidence,
        auth_ref: row.auth_ref.clone(),
        origin: row.origin.clone(),
        expires_at: row.expires_at,
    })
}

const SOURCE_CANDIDATE_COLUMNS: &str = "id, download_id, url, platform, kind, size, version, container,
     evidence, digest_algo, digest_hex, auth_ref, origin, expires_at, probe_at, score, state, created_at";

fn row_from_source_candidate(row: &rusqlite::Row<'_>) -> rusqlite::Result<SourceCandidateRow> {
    Ok(SourceCandidateRow {
        id: row.get(0)?,
        download_id: row.get(1)?,
        url: row.get(2)?,
        platform: row.get(3)?,
        kind: row.get(4)?,
        size: row.get(5)?,
        version: row.get(6)?,
        container: row.get(7)?,
        evidence: row.get(8)?,
        digest_algo: row.get(9)?,
        digest_hex: row.get(10)?,
        auth_ref: row.get(11)?,
        origin: row.get(12)?,
        expires_at: row.get(13)?,
        probe_at: row.get(14)?,
        score: row.get(15)?,
        state: row.get(16)?,
        created_at: row.get(17)?,
    })
}

/// 批量写入/更新候选。冲突键是 `(download_id, url)`；重复候选不会产生第二行。
pub fn upsert_source_candidates(
    conn: &Connection,
    download_id: i64,
    candidates: &[crate::source::CandidateSource],
    now_ms: i64,
) -> rusqlite::Result<usize> {
    let mut stmt = conn.prepare(
        "INSERT INTO source_candidates(download_id, url, platform, kind, size, version, container,
             evidence, digest_algo, digest_hex, auth_ref, origin, expires_at, probe_at, score, state, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, 'candidate', ?16)
         ON CONFLICT(download_id, url) DO UPDATE SET
             platform = excluded.platform,
             kind = excluded.kind,
             size = excluded.size,
             version = excluded.version,
             container = excluded.container,
             evidence = excluded.evidence,
             digest_algo = excluded.digest_algo,
             digest_hex = excluded.digest_hex,
             auth_ref = excluded.auth_ref,
             origin = excluded.origin,
             expires_at = excluded.expires_at,
             state = 'candidate'",
    )?;
    let mut n = 0usize;
    for c in candidates {
        let r = candidate_to_row(download_id, c, now_ms);
        n += stmt.execute(rusqlite::params![
            r.download_id,
            r.url,
            r.platform,
            r.kind,
            r.size,
            r.version,
            r.container,
            r.evidence,
            r.digest_algo,
            r.digest_hex,
            r.auth_ref,
            r.origin,
            r.expires_at,
            r.probe_at,
            r.score,
            r.created_at
        ])?;
    }
    Ok(n)
}

/// 列出候选；`state = None` 表示全部状态。
pub fn list_source_candidates(
    conn: &Connection,
    download_id: i64,
    state: Option<&str>,
) -> rusqlite::Result<Vec<SourceCandidateRow>> {
    let sql = format!(
        "SELECT {SOURCE_CANDIDATE_COLUMNS} FROM source_candidates
         WHERE download_id = ?1 AND (?2 IS NULL OR state = ?2)
         ORDER BY id"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(
        rusqlite::params![download_id, state],
        row_from_source_candidate,
    )?;
    rows.collect()
}

pub fn set_source_candidate_state(
    conn: &Connection,
    id: i64,
    state: &str,
) -> rusqlite::Result<usize> {
    conn.execute(
        "UPDATE source_candidates SET state = ?2 WHERE id = ?1",
        rusqlite::params![id, state],
    )
}

/// 回写探测时间与评分（`source_candidates` 的诊断列）。
pub fn set_source_candidate_probe(
    conn: &Connection,
    download_id: i64,
    url: &str,
    probe_at: i64,
    score: Option<f64>,
) -> rusqlite::Result<usize> {
    conn.execute(
        "UPDATE source_candidates SET probe_at = ?3, score = ?4
         WHERE download_id = ?1 AND url = ?2",
        rusqlite::params![download_id, url, probe_at, score],
    )
}

/// 删掉该任务已过期的候选；返回删除行数。
pub fn delete_expired_source_candidates(
    conn: &Connection,
    download_id: i64,
    now_ms: i64,
) -> rusqlite::Result<usize> {
    conn.execute(
        "DELETE FROM source_candidates
         WHERE download_id = ?1 AND expires_at IS NOT NULL AND expires_at <= ?2",
        rusqlite::params![download_id, now_ms],
    )
}

/// 回写找源预算（轮数/耗时/最近时刻）。
pub fn set_find_state(
    conn: &Connection,
    id: i64,
    rounds: i64,
    spent_ms: i64,
    last_at: Option<i64>,
) -> rusqlite::Result<usize> {
    conn.execute(
        "UPDATE downloads SET find_rounds = ?2, find_spent_ms = ?3, find_last_at = ?4 WHERE id = ?1",
        rusqlite::params![id, rounds, spent_ms, last_at],
    )
}

/// 原子认领：仅当仍为 `queued` 且已到 `retry_at` 时转入 `connecting`。
pub fn claim_queued(conn: &Connection, id: i64, now_ms: i64) -> rusqlite::Result<bool> {
    let n = conn.execute(
        "UPDATE downloads SET status = 'connecting', error_code = NULL,
                error_message = NULL, http_status = NULL
         WHERE id = ?1 AND status = 'queued'
           AND (retry_at IS NULL OR retry_at <= ?2)",
        rusqlite::params![id, now_ms],
    )?;
    Ok(n == 1)
}

pub fn set_start_mode(conn: &Connection, id: i64, start_mode: &str) -> rusqlite::Result<usize> {
    conn.execute(
        "UPDATE downloads SET start_mode = ?2 WHERE id = ?1",
        rusqlite::params![id, start_mode],
    )
}

/// 任务重新开始（worker 已拿到执行权）时清掉上一轮 P2P 等待留下的 `retry_at`。
///
/// 不清会让库里出现「status=downloading 但 retry_at 已过期」的矛盾组合，
/// 诊断/调度器都要额外判断；`0` 表示没有等待。
pub fn clear_retry_at(conn: &Connection, id: i64) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE downloads SET retry_at = 0 WHERE id = ?1",
        rusqlite::params![id],
    )?;
    Ok(())
}

pub fn set_retry_wait(
    conn: &Connection,
    id: i64,
    retry_count: i64,
    retry_at: i64,
) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE downloads SET status = 'queued', error_code = NULL, error_message = NULL,
                http_status = NULL, retry_count = ?2, retry_at = ?3 WHERE id = ?1",
        rusqlite::params![id, retry_count, retry_at],
    )?;
    Ok(())
}

/// 按任务的连接上限（签名直链异常后的退避状态）。
pub struct ConnCap {
    pub conn_cap: u32,
    /// 本轮异常已经跑过找源；后续重试不再重复找源。
    pub finder_done: bool,
}

/// 读取任务的连接上限；没有退避记录时返回 None（按正常并发）。
pub fn get_conn_cap(conn: &Connection, id: i64) -> rusqlite::Result<Option<ConnCap>> {
    conn.query_row(
        "SELECT conn_cap, finder_done FROM download_conn_caps WHERE download_id = ?1",
        [id],
        |r| {
            Ok(ConnCap {
                conn_cap: r.get::<_, i64>(0)?.max(1) as u32,
                finder_done: r.get::<_, i64>(1)? != 0,
            })
        },
    )
    .optional()
}

/// 写入/更新任务的连接上限。
pub fn set_conn_cap(
    conn: &Connection,
    id: i64,
    conn_cap: u32,
    finder_done: bool,
) -> rusqlite::Result<usize> {
    conn.execute(
        "INSERT INTO download_conn_caps(download_id, conn_cap, finder_done, updated_at)
         VALUES(?1, ?2, ?3, ?4)
         ON CONFLICT(download_id) DO UPDATE SET
            conn_cap = excluded.conn_cap,
            finder_done = excluded.finder_done,
            updated_at = excluded.updated_at",
        rusqlite::params![id, conn_cap.max(1) as i64, i64::from(finder_done), now_ms()],
    )
}

/// 清空任务的连接上限。找源成功、任务完成或重新开始时调用。
pub fn clear_conn_cap(conn: &Connection, id: i64) -> rusqlite::Result<usize> {
    conn.execute(
        "DELETE FROM download_conn_caps WHERE download_id = ?1",
        [id],
    )
}

/// 同一 id 从头再来：清校验/大小/错误，状态回到 queued。
pub fn reset_for_restart(conn: &Connection, id: i64) -> rusqlite::Result<usize> {
    clear_segments(conn, id)?;
    clear_conn_cap(conn, id)?;
    conn.execute(
        "UPDATE downloads SET url_final = NULL, size_total = NULL, etag = NULL,
                last_modified = NULL, status = 'queued', finished_at = NULL,
                error_code = NULL, error_message = NULL, http_status = NULL,
                retry_at = NULL, retry_count = 0, start_mode = 'now', active_ms = 0
         WHERE id = ?1",
        [id],
    )
}

/// 累加净下载耗时（毫秒）。由 worker 在**每次运行结束时**写一次：
/// 线程存在即代表任务在跑，所以暂停 / 排队 / 退避天然不计入。
pub fn add_active_ms(conn: &Connection, id: i64, ms: i64) -> rusqlite::Result<usize> {
    if ms <= 0 {
        return Ok(0);
    }
    conn.execute(
        "UPDATE downloads SET active_ms = COALESCE(active_ms, 0) + ?2 WHERE id = ?1",
        rusqlite::params![id, ms],
    )
}

/// 把全部 `error` 任务重新入队（立即具备资格）。返回条数。
pub fn retry_failed(conn: &Connection) -> rusqlite::Result<u64> {
    // 用户主动“重试失败”时从正常并发重新开始，不继承上一轮的签名退避档位。
    conn.execute(
        "DELETE FROM download_conn_caps
         WHERE download_id IN (SELECT id FROM downloads WHERE status = 'error')",
        [],
    )?;
    let n = conn.execute(
        "UPDATE downloads SET status = 'queued', error_code = NULL, error_message = NULL,
                http_status = NULL, retry_at = NULL, retry_count = 0, start_mode = 'now',
                find_rounds = 0, find_spent_ms = 0, find_last_at = NULL
         WHERE status = 'error'",
        [],
    )?;
    Ok(n as u64)
}

/// 队列内待跑任务的排序：只按 id（入队先后），不再有优先级。
pub fn dispatch_order(rows: &[DownloadRow], _now_ms: i64) -> Vec<i64> {
    let mut queued: Vec<&DownloadRow> =
        rows.iter().filter(|r| r.status == Status::Queued).collect();
    queued.sort_by_key(|r| r.id);
    queued.iter().map(|r| r.id).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_db;
    use crate::segment::{plan_segments, ByteSpan};
    use std::path::Path;

    fn mem() -> Connection {
        open_db(Path::new(":memory:")).unwrap()
    }

    #[test]
    fn ed2k_server_health_skips_after_two_failures_and_recovers_on_ok() {
        let conn = mem();
        note_ed2k_server_result(&conn, "1.2.3.4", 4232, false, 1_000).unwrap();
        assert!(ed2k_bad_servers(&conn, 1_000, 60_000).unwrap().is_empty());
        note_ed2k_server_result(&conn, "1.2.3.4", 4232, false, 2_000).unwrap();
        assert!(ed2k_bad_servers(&conn, 2_000, 60_000)
            .unwrap()
            .contains(&("1.2.3.4".to_string(), 4232)));
        // 冷却过期后恢复；成功一次直接清零。
        assert!(ed2k_bad_servers(&conn, 62_001, 60_000).unwrap().is_empty());
        note_ed2k_server_result(&conn, "1.2.3.4", 4232, true, 3_000).unwrap();
        assert!(ed2k_bad_servers(&conn, 3_000, 60_000).unwrap().is_empty());
    }

    #[test]
    fn reset_for_restart_keeps_task_bound_source_candidates() {
        use crate::source::{CandidateSource, IdentityEvidence, Platform, SourceKind};
        let conn = mem();
        let id = insert_download(&conn, "u", "f", "d", 0, 1).unwrap();
        let c = CandidateSource {
            url: "https://m.test/f".into(),
            platform: Platform::ArchiveOrg,
            kind: SourceKind::File,
            size: Some(10),
            version: None,
            container: None,
            evidence: IdentityEvidence::SizeOnly { size: 10 },
            auth_ref: None,
            origin: None,
            expires_at: None,
        };
        upsert_source_candidates(&conn, id, &[c], 100).unwrap();
        reset_for_restart(&conn, id).unwrap();
        // 暂停/重新下载会 reset 分段与 URL，但**不能丢任务已取得的源**。
        assert_eq!(list_source_candidates(&conn, id, None).unwrap().len(), 1);
    }

    #[test]
    fn segment_src_version_roundtrip() {
        let conn = mem();
        let id = insert_download(&conn, "u", "f", "d", 0, 1).unwrap();
        init_single_segment(&conn, id, "p0", None).unwrap();
        set_segment_src(&conn, id, 0, Some("https://m.test/f")).unwrap();
        set_segment_src_version(&conn, id, 0, Some("etag:v1")).unwrap();
        let seg = list_segments(&conn, id).unwrap().remove(0);
        assert_eq!(seg.src_url.as_deref(), Some("https://m.test/f"));
        assert_eq!(seg.src_version.as_deref(), Some("etag:v1"));
        assert_eq!(
            segment_src_version(&conn, id, "https://m.test/f")
                .unwrap()
                .as_deref(),
            Some("etag:v1")
        );
        set_segment_src_version(&conn, id, 0, None).unwrap();
        assert!(segment_src_version(&conn, id, "https://m.test/f")
            .unwrap()
            .is_none());
    }

    #[test]
    fn source_candidates_roundtrip_and_find_state() {
        use crate::source::{
            CandidateSource, EvidenceLevel, IdentityEvidence, Platform, SourceKind,
        };
        let conn = mem();
        let id = insert_download(&conn, "u", "f", "d", 0, 1).unwrap();
        let c = CandidateSource {
            url: "https://m.test/f.iso".into(),
            platform: Platform::Wayback,
            kind: SourceKind::File,
            size: Some(10),
            version: Some("v1".into()),
            container: Some("iso".into()),
            evidence: IdentityEvidence::SizeOnly { size: 10 },
            auth_ref: None,
            origin: Some("wayback:1".into()),
            expires_at: None,
        };
        assert_eq!(
            upsert_source_candidates(&conn, id, std::slice::from_ref(&c), 100).unwrap(),
            1
        );
        // 同一 (download_id,url) 再写一次只更新，不新增行。
        assert_eq!(
            upsert_source_candidates(&conn, id, std::slice::from_ref(&c), 101).unwrap(),
            1
        );
        let rows = list_source_candidates(&conn, id, Some("candidate")).unwrap();
        assert_eq!(rows.len(), 1);
        let back = row_to_candidate(&rows[0]).unwrap();
        assert_eq!(back.url, c.url);
        assert_eq!(back.platform, c.platform);
        assert_eq!(back.kind, c.kind);
        assert_eq!(back.container.as_deref(), Some("iso"));
        assert_eq!(back.evidence.level(), EvidenceLevel::L1SizeOnly);

        set_source_candidate_state(&conn, rows[0].id, "admitted").unwrap();
        assert_eq!(
            list_source_candidates(&conn, id, Some("admitted"))
                .unwrap()
                .len(),
            1
        );

        let mut expired = c.clone();
        expired.expires_at = Some(50);
        upsert_source_candidates(&conn, id, &[expired], 100).unwrap();
        assert_eq!(delete_expired_source_candidates(&conn, id, 60).unwrap(), 1);
        assert!(list_source_candidates(&conn, id, None).unwrap().is_empty());

        set_find_state(&conn, id, 2, 1_234, Some(999)).unwrap();
        let row = get_download(&conn, id).unwrap().unwrap();
        assert_eq!(row.find_rounds, 2);
        assert_eq!(row.find_spent_ms, 1_234);
        assert_eq!(row.find_last_at, Some(999));
    }

    #[test]
    fn conn_cap_roundtrip_and_reset_clear() {
        let conn = mem();
        let id = insert_download(&conn, "https://x/a.bin", "a.bin", "/tmp", 0, 8).unwrap();
        assert!(get_conn_cap(&conn, id).unwrap().is_none());
        set_conn_cap(&conn, id, 4, true).unwrap();
        let c = get_conn_cap(&conn, id).unwrap().unwrap();
        assert_eq!((c.conn_cap, c.finder_done), (4, true));
        reset_for_restart(&conn, id).unwrap();
        assert!(get_conn_cap(&conn, id).unwrap().is_none());
    }

    #[test]
    fn retry_failed_clears_conn_cap() {
        let conn = mem();
        let id = insert_download(&conn, "https://x/a.bin", "a.bin", "/tmp", 0, 8).unwrap();
        set_conn_cap(&conn, id, 1, true).unwrap();
        crate::model::set_status(&conn, id, Status::Error, Some("http_5xx")).unwrap();
        assert_eq!(retry_failed(&conn).unwrap(), 1);
        assert!(get_conn_cap(&conn, id).unwrap().is_none());
    }

    #[test]
    fn conn_cap_cascades_with_download() {
        let conn = mem();
        let id = insert_download(&conn, "https://x/a.bin", "a.bin", "/tmp", 0, 8).unwrap();
        set_conn_cap(&conn, id, 2, true).unwrap();
        assert_eq!(delete_download(&conn, id).unwrap(), 1);
        let n: i64 = conn
            .query_row("SELECT count(*) FROM download_conn_caps", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn status_roundtrip() {
        for s in [
            Status::Queued,
            Status::Connecting,
            Status::Downloading,
            Status::Paused,
            Status::Verifying,
            Status::Done,
            Status::Error,
        ] {
            assert_eq!(Status::from_str(s.as_str()), Some(s));
        }
        assert_eq!(Status::from_str("nope"), None);
    }

    #[test]
    fn insert_and_get() {
        let conn = mem();
        let id = insert_download(&conn, "https://x/a.bin", "a.bin", "/tmp", 0, 8).unwrap();
        let row = get_download(&conn, id).unwrap().unwrap();
        assert_eq!(row.status, Status::Queued);
        assert_eq!(row.file_name, "a.bin");
        assert_eq!(row.max_conns, 8);
        assert_eq!(row.source, "manual");
        assert!(row.etag.is_none());
    }

    #[test]
    fn cascade_delete() {
        let conn = mem();
        let id = insert_download(&conn, "https://x/a.bin", "a.bin", "/tmp", 0, 1).unwrap();
        init_single_segment(&conn, id, "p0", None).unwrap();
        log_event(&conn, id, "created", None);
        assert_eq!(delete_download(&conn, id).unwrap(), 1);
        let seg: i64 = conn
            .query_row("SELECT count(*) FROM segments", [], |r| r.get(0))
            .unwrap();
        let ev: i64 = conn
            .query_row("SELECT count(*) FROM events", [], |r| r.get(0))
            .unwrap();
        assert_eq!((seg, ev), (0, 0));
    }

    #[test]
    fn progress_and_done() {
        let conn = mem();
        let id = insert_download(&conn, "u", "f", "d", 0, 1).unwrap();
        init_single_segment(&conn, id, "p0", None).unwrap();
        set_status(&conn, id, Status::Downloading, None).unwrap();
        set_segment_progress(&conn, id, 4096).unwrap();
        mark_done(&conn, id, "https://final/a.bin").unwrap();
        let row = get_download(&conn, id).unwrap().unwrap();
        assert_eq!(row.status, Status::Done);
        assert_eq!(row.url_final.as_deref(), Some("https://final/a.bin"));
        assert!(row.finished_at.is_some());
    }

    #[test]
    fn multi_segment_replace_and_sum() {
        let conn = mem();
        let id = insert_download(&conn, "u", "f", "d", 0, 4).unwrap();
        let spans = plan_segments(1024 * 1024, 8);
        assert_eq!(spans.len(), 4);
        let paths: Vec<String> = (0..spans.len()).map(|i| format!("part{i}")).collect();
        replace_segments(&conn, id, &spans, &paths).unwrap();
        let segs = list_segments(&conn, id).unwrap();
        assert_eq!(segs.len(), 4);
        assert_eq!(segs[0].pos_start, 0);
        set_segment_state(&conn, id, 0, spans[0].len() as i64, "done").unwrap();
        set_segment_state(&conn, id, 1, 100, "running").unwrap();
        assert_eq!(sum_done_bytes(&conn, id).unwrap(), spans[0].len() + 100);
        assert!(!all_segments_done(&conn, id).unwrap());
        for (i, s) in spans.iter().enumerate() {
            set_segment_state(&conn, id, i as i32, s.len() as i64, "done").unwrap();
        }
        assert!(all_segments_done(&conn, id).unwrap());
        let _ = ByteSpan { start: 0, end: 0 };
    }

    #[test]
    fn finalize_segments_makes_progress_reach_total() {
        // 运行中再切分会让「行数/布局」和计划错位，留下一堆下不满的残值：
        // 完成时收尾，Σdone 必须等于总长，否则界面上会「已完成却不到 100%」。
        let conn = mem();
        let total = 1024 * 1024;
        let id = insert_download(&conn, "u", "f", "d", 0, 4).unwrap();
        let spans = plan_segments(total, 4);
        let paths: Vec<String> = (0..spans.len()).map(|i| format!("part{i}")).collect();
        replace_segments(&conn, id, &spans, &paths).unwrap();
        // 假装只落了一部分，而且状态还停在 pending
        set_segment_state(&conn, id, 0, 1234, "pending").unwrap();
        set_segment_state(&conn, id, 1, 4321, "pending").unwrap();
        assert!(sum_done_bytes(&conn, id).unwrap() < total);

        finalize_segments(&conn, id).unwrap();
        assert_eq!(sum_done_bytes(&conn, id).unwrap(), total);
        assert!(all_segments_done(&conn, id).unwrap());
    }

    #[test]
    fn finalize_segments_keeps_unknown_size_rows() {
        // 未知总长的单连接行 pos_end 为 NULL：不能把它算成 NULL/0
        let conn = mem();
        let id = insert_download(&conn, "u", "f", "d", 0, 1).unwrap();
        init_single_segment(&conn, id, "p0", None).unwrap();
        set_segment_progress(&conn, id, 4096).unwrap();
        finalize_segments(&conn, id).unwrap();
        assert_eq!(sum_done_bytes(&conn, id).unwrap(), 4096);
        let segs = list_segments(&conn, id).unwrap();
        assert_eq!(segs[0].status, "done");
    }

    #[test]
    fn meta_persists_validators() {
        let conn = mem();
        let id = insert_download(&conn, "u", "f", "d", 0, 8).unwrap();
        set_meta(
            &conn,
            id,
            "https://final/a.bin",
            Some(10),
            Some("\"etag1\""),
            Some("Mon, 01 Jan 2024 00:00:00 GMT"),
            "a.bin",
        )
        .unwrap();
        let row = get_download(&conn, id).unwrap().unwrap();
        assert_eq!(row.etag.as_deref(), Some("\"etag1\""));
        assert_eq!(
            row.last_modified.as_deref(),
            Some("Mon, 01 Jan 2024 00:00:00 GMT")
        );
    }

    #[test]
    fn set_file_name_if_skips_when_user_renamed() {
        let conn = mem();
        let id = insert_download(&conn, "u", "old.bin", "d", 0, 1).unwrap();
        assert_eq!(set_file_name(&conn, id, "user.bin").unwrap(), 1);
        assert_eq!(
            set_file_name_if(&conn, id, "from-cd.bin", "old.bin").unwrap(),
            0
        );
        let row = get_download(&conn, id).unwrap().unwrap();
        assert_eq!(row.file_name, "user.bin");
        set_probe_meta(&conn, id, "https://final/a", Some(9), Some("\"e\""), None).unwrap();
        let row = get_download(&conn, id).unwrap().unwrap();
        assert_eq!(row.file_name, "user.bin");
        assert_eq!(row.url_final.as_deref(), Some("https://final/a"));
        assert_eq!(
            set_file_name_if(&conn, id, "next.bin", "user.bin").unwrap(),
            1
        );
        assert_eq!(
            get_download(&conn, id).unwrap().unwrap().file_name,
            "next.bin"
        );
    }

    #[test]
    fn dispatch_order_is_fifo_by_id() {
        let conn = mem();
        let a = insert_download(&conn, "u1", "a", "d", 0, 1).unwrap();
        let b = insert_download(&conn, "u2", "b", "d", 0, 1).unwrap();
        let c = insert_download(&conn, "u3", "c", "d", 0, 1).unwrap();
        let rows = list_downloads(&conn).unwrap();
        assert_eq!(dispatch_order(&rows, now_ms()), vec![a, b, c]);
    }

    #[test]
    fn dispatch_order_only_covers_queued_rows() {
        let conn = mem();
        let a = insert_download(&conn, "u1", "a", "d", 0, 1).unwrap();
        let b = insert_download(&conn, "u2", "b", "d", 0, 1).unwrap();
        conn.execute(
            "UPDATE downloads SET status = 'downloading' WHERE id = ?1",
            [a],
        )
        .unwrap();
        let rows = list_downloads(&conn).unwrap();
        assert_eq!(dispatch_order(&rows, now_ms()), vec![b]);
    }

    #[test]
    fn resplit_renumbers_and_keeps_progress() {
        let conn = mem();
        let id = insert_download(&conn, "u", "f", "d", 0, 4).unwrap();
        let total = 4 * 1024 * 1024u64;
        let dir = Path::new("/tmp/dl");
        let spans = plan_segments(total, 4);
        let paths: Vec<String> = spans
            .iter()
            .enumerate()
            .map(|(i, _)| {
                crate::segment::part_path(dir, id, i as i32)
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        replace_segments(&conn, id, &spans, &paths).unwrap();
        set_segment_state(&conn, id, 1, 512 * 1024, "running").unwrap();

        let segs = list_segments(&conn, id).unwrap();
        let planned = resplit_plan(&segs, 8).expect("should be splittable");
        assert_eq!(planned.len(), 8);
        assert_eq!(resplit_task_segments(&conn, id, dir, 8).unwrap(), 4);

        let after = list_segments(&conn, id).unwrap();
        assert_eq!(after.len(), 8);
        for (i, s) in after.iter().enumerate() {
            assert_eq!(s.idx, i as i32, "renumbered by byte order");
        }
        assert_eq!(after[0].pos_start, 0);
        assert_eq!(after.last().unwrap().pos_end.unwrap() as u64, total - 1);
        for w in after.windows(2) {
            assert_eq!(w[1].pos_start, w[0].pos_end.unwrap() + 1);
        }
        assert_eq!(
            after.iter().map(|s| s.done_bytes).sum::<i64>(),
            512 * 1024,
            "downloaded bytes must survive the split"
        );
        assert_eq!(
            after.iter().filter(|s| s.status == "running").count(),
            1,
            "in-flight segment keeps its status"
        );
        let paths: std::collections::HashSet<&str> =
            after.iter().map(|s| s.part_path.as_str()).collect();
        assert_eq!(paths.len(), after.len(), "part files must not collide");
        assert!(after.iter().any(|s| s.pos_start > 0 && s.done_bytes == 0));

        // 幂等：段数已达标不再改动
        assert_eq!(resplit_task_segments(&conn, id, dir, 8).unwrap(), 0);
        // 减少连接数不做合并（只切分）
        assert!(resplit_plan(&after, 2).is_none());
    }

    #[test]
    fn resplit_skips_single_part_layout() {
        let conn = mem();
        let id = insert_download(&conn, "u", "f", "d", 0, 8).unwrap();
        init_single_segment(&conn, id, "/tmp/dl/f", Some(1024 * 1024 - 1)).unwrap();
        let segs = list_segments(&conn, id).unwrap();
        assert!(resplit_plan(&segs, 8).is_none(), "part 即最终文件，不可切");
        assert_eq!(
            resplit_task_segments(&conn, id, Path::new("/tmp/dl"), 8).unwrap(),
            0
        );
    }

    #[test]
    fn reset_for_restart_clears_validators_and_segments() {
        let conn = mem();
        let id = insert_download(&conn, "u", "f", "d", 0, 4).unwrap();
        set_meta(
            &conn,
            id,
            "https://final/f",
            Some(10),
            Some("\"e\""),
            Some("Mon"),
            "f",
        )
        .unwrap();
        init_single_segment(&conn, id, "p0", Some(9)).unwrap();
        set_error_fields(
            &conn,
            id,
            Status::Error,
            Some("remote_changed"),
            Some("远程文件已变化，无法续传"),
            None,
        )
        .unwrap();
        assert_eq!(reset_for_restart(&conn, id).unwrap(), 1);
        let row = get_download(&conn, id).unwrap().unwrap();
        assert_eq!(row.status, Status::Queued);
        assert!(row.etag.is_none());
        assert!(row.size_total.is_none());
        assert!(row.error_code.is_none());
        assert!(list_segments(&conn, id).unwrap().is_empty());
    }

    #[test]
    fn retry_failed_requeues_and_counts() {
        let conn = mem();
        let a = insert_download(&conn, "u1", "a", "d", 0, 1).unwrap();
        let b = insert_download(&conn, "u2", "b", "d", 0, 1).unwrap();
        set_status(&conn, a, Status::Error, Some("connect: x")).unwrap();
        set_status(&conn, b, Status::Error, Some("http_500")).unwrap();
        set_find_state(&conn, a, 2, 1_234, Some(9)).unwrap();
        assert_eq!(retry_failed(&conn).unwrap(), 2);
        assert_eq!(retry_failed(&conn).unwrap(), 0);
        let a = get_download(&conn, a).unwrap().unwrap();
        assert_eq!(a.status, Status::Queued);
        assert!(a.error_code.is_none());
        assert!(a.retry_at.is_none());
        assert_eq!(a.start_mode, "now");
        assert_eq!(
            (a.find_rounds, a.find_spent_ms, a.find_last_at),
            (0, 0, None)
        );
    }

    #[test]
    fn two_process_file_lock_and_claim_protection() {
        // 临时目录由 `tempfile::tempdir()` 提供：绝对路径 + Drop 自动清理。
        let tmp = crate::testsupport::tempdir("model");
        let dir = tmp.path().to_path_buf();
        let lock_a = crate::try_acquire_instance_lock(&dir).expect("first process lock");
        assert_eq!(
            crate::try_acquire_instance_lock(&dir).unwrap_err(),
            "engine_already_running"
        );

        let db_path = dir.join("db.sqlite");
        let id = {
            let conn = crate::db::open_db(&db_path).unwrap();
            insert_download(&conn, "https://x/a.bin", "a.bin", "/tmp", 0, 1).unwrap()
        };
        let now = now_ms();
        let path_a = db_path.clone();
        let path_b = db_path.clone();
        let h1 = std::thread::spawn(move || {
            let conn = crate::db::open_db(&path_a).unwrap();
            claim_queued(&conn, id, now).unwrap()
        });
        let h2 = std::thread::spawn(move || {
            let conn = crate::db::open_db(&path_b).unwrap();
            claim_queued(&conn, id, now).unwrap()
        });
        let wins = [h1.join().unwrap(), h2.join().unwrap()];
        assert_eq!(
            wins.iter().filter(|w| **w).count(),
            1,
            "exactly one claim: {wins:?}"
        );
        let conn = crate::db::open_db(&db_path).unwrap();
        let row = get_download(&conn, id).unwrap().unwrap();
        assert_eq!(row.status, Status::Connecting);
        drop(lock_a);
    }

    #[test]
    fn ed2k_sources_upsert_list_and_stats() {
        let conn = mem();
        let id = insert_download(
            &conn,
            "ed2k://|file|a.bin|10|965c013e991ee246d63d45ea71954c4d|/",
            "a.bin",
            "/tmp",
            10,
            1,
        )
        .unwrap();
        assert_eq!(
            add_ed2k_sources(
                &conn,
                id,
                &[("1.2.3.4".into(), 4662), ("5.6.7.8".into(), 4662)],
                Some("server")
            )
            .unwrap(),
            2
        );
        // 重复写同一源不增加条数，只刷新 seen_at
        assert_eq!(
            add_ed2k_sources(&conn, id, &[("1.2.3.4".into(), 4662)], Some("kad")).unwrap(),
            0
        );
        let list = list_ed2k_sources(&conn, id, 10).unwrap();
        assert_eq!(list.len(), 2);
        // kind 不因重复写而被 NULL 覆盖
        let s = list.iter().find(|s| s.host == "1.2.3.4").unwrap();
        assert_eq!(s.kind.as_deref(), Some("kad"));
        assert_eq!((s.tries, s.fails), (0, 0));

        // 统计：失败数影响排序（没失败的排前面）
        note_ed2k_source_result(&conn, id, "1.2.3.4", 4662, false).unwrap();
        note_ed2k_source_result(&conn, id, "1.2.3.4", 4662, true).unwrap();
        let list = list_ed2k_sources(&conn, id, 10).unwrap();
        assert_eq!(
            list[0].host, "1.2.3.4",
            "实传成功过的源优先于从未验证的新源"
        );
        let s = list.iter().find(|s| s.host == "1.2.3.4").unwrap();
        assert_eq!((s.tries, s.fails), (2, 1));

        // 另一个任务的源互不影响；清空只清自己
        let id2 = insert_download(
            &conn,
            "ed2k://|file|b.bin|10|965c013e991ee246d63d45ea71954c4d|/",
            "b.bin",
            "/tmp",
            10,
            1,
        )
        .unwrap();
        add_ed2k_sources(&conn, id2, &[("9.9.9.9".into(), 4662)], None).unwrap();
        assert_eq!(clear_ed2k_sources(&conn, id).unwrap(), 2);
        assert!(list_ed2k_sources(&conn, id, 10).unwrap().is_empty());
        assert_eq!(list_ed2k_sources(&conn, id2, 10).unwrap().len(), 1);
    }

    #[test]
    fn download_log_page_skips_shadow_events_and_filters_errors() {
        let conn = mem();
        conn.execute(
            "INSERT INTO downloads(url_orig, file_name, dir, created_at) \
             VALUES('https://e/a','a.bin','/tmp',0)",
            [],
        )
        .unwrap();
        let id = conn.last_insert_rowid();
        for (kind, err) in [
            ("unified_state_changed", None::<&str>),
            ("start", None),
            ("unified_decision", None),
            ("segment_retry", Some("slow_conn")),
            ("error", Some("http_403")),
            ("done", None),
        ] {
            conn.execute(
                "INSERT INTO events(download_id, kind, ts, err_code) VALUES(?1, ?2, 0, ?3)",
                rusqlite::params![id, kind, err],
            )
            .unwrap();
        }

        let all = list_events_page(&conn, id, 10, 0, false).unwrap();
        assert_eq!(all.len(), 4, "只排除影子事件；慢源换源仍在全部日志里");
        assert!(all.iter().all(|e| !e.kind.starts_with("unified_")));
        assert_eq!(count_events(&conn, id, false).unwrap(), 4);

        let errs = list_events_page(&conn, id, 10, 0, true).unwrap();
        assert_eq!(errs.len(), 1, "slow_conn 是正常换源，不算异常");
        assert_eq!(errs[0].kind, "error");
        assert_eq!(count_events(&conn, id, true).unwrap(), 1);
    }

    #[test]
    fn download_log_pages_do_not_overlap() {
        let conn = mem();
        conn.execute(
            "INSERT INTO downloads(url_orig, file_name, dir, created_at) \
             VALUES('https://e/a','a.bin','/tmp',0)",
            [],
        )
        .unwrap();
        let id = conn.last_insert_rowid();
        for i in 0..5i64 {
            conn.execute(
                "INSERT INTO events(download_id, kind, ts) VALUES(?1, ?2, ?3)",
                rusqlite::params![id, format!("e{i}"), i],
            )
            .unwrap();
        }
        let p1 = list_events_page(&conn, id, 2, 0, false).unwrap();
        let p2 = list_events_page(&conn, id, 2, 2, false).unwrap();
        assert_eq!(p1.len(), 2);
        assert_eq!(p2.len(), 2);
        assert!(p1[0].seq > p1[1].seq, "倒序：最新在前");
        assert!(p1[1].seq > p2[0].seq, "两页不能重叠");
    }

    #[test]
    fn clearing_download_log_only_touches_that_task() {
        let conn = mem();
        for name in ["a", "b"] {
            conn.execute(
                "INSERT INTO downloads(url_orig, file_name, dir, created_at) \
                 VALUES(?1, ?1, '/tmp', 0)",
                [format!("https://e/{name}")],
            )
            .unwrap();
        }
        let ids: Vec<i64> = conn
            .prepare("SELECT id FROM downloads ORDER BY id")
            .unwrap()
            .query_map([], |r| r.get::<_, i64>(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        for id in &ids {
            conn.execute(
                "INSERT INTO events(download_id, kind, ts) VALUES(?1, 'x', 0)",
                [id],
            )
            .unwrap();
        }
        assert_eq!(clear_task_events(&conn, ids[0]).unwrap(), 1);
        assert_eq!(count_events(&conn, ids[0], false).unwrap(), 0);
        assert_eq!(
            count_events(&conn, ids[1], false).unwrap(),
            1,
            "不能误删其他任务的日志"
        );
    }
}

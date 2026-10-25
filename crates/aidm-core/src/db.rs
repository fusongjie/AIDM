//! SQLite 打开与初始化（首次运行自动建库）。

use std::path::{Path, PathBuf};

use rusqlite::Connection;

/// open_db 的错误：区分建目录/路径类 I/O 错误与真正的 SQLite 错误。
#[derive(Debug)]
pub enum OpenError {
    /// 数据目录创建失败（I/O / 路径问题，非 SQLite 问题）
    CreateDir {
        path: PathBuf,
        source: std::io::Error,
    },
    Sqlite(rusqlite::Error),
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenError::CreateDir { path, source } => {
                write!(f, "create data dir {} failed: {source}", path.display())
            }
            OpenError::Sqlite(e) => write!(f, "sqlite: {e}"),
        }
    }
}

impl std::error::Error for OpenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            OpenError::CreateDir { source, .. } => Some(source),
            OpenError::Sqlite(e) => Some(e),
        }
    }
}

impl From<rusqlite::Error> for OpenError {
    fn from(e: rusqlite::Error) -> Self {
        OpenError::Sqlite(e)
    }
}

/// 打开（或创建）数据库并执行首次运行迁移。
///
/// 打开后启用 `foreign_keys`（§4 外键级联：删任务时 events/segments 随之清理）。
pub fn open_db(path: &Path) -> Result<Connection, OpenError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| OpenError::CreateDir {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let mut conn = Connection::open(path)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    migrate(&conn)?;
    migrate_download_tables(&mut conn)?;
    Ok(conn)
}

/// 统一下载表的迁移版本（`PRAGMA user_version`）。
///
/// 为什么单独一条链：`migrate()` 是**结构检查式幂等**（`CREATE TABLE IF NOT EXISTS`
/// + `ensure_column`），它保证“结构齐全”，但不记录“做到哪一步”。新表需要顺序版本，
/// 否则分不清“旧库没建”与“建到一半失败”。
const DOWNLOAD_SCHEMA_VERSION: i32 = 2;

/// 统一下载表。
///
/// 只建**当前真实依赖**的表，不为将来预埋空字段（文档 10 节）。
/// 区间与位图一律存文本，避免 SQLite 无原生区间类型。
const DOWNLOAD_SCHEMA_SQL: &str = "
CREATE TABLE IF NOT EXISTS download_runtime(
    task_id            INTEGER PRIMARY KEY REFERENCES downloads(id) ON DELETE CASCADE,
    execution_mode     TEXT NOT NULL DEFAULT 'legacy',
    run_epoch          INTEGER NOT NULL DEFAULT 0,
    content_generation INTEGER NOT NULL DEFAULT 0,
    plan_revision      INTEGER NOT NULL DEFAULT 0,
    state_revision     INTEGER NOT NULL DEFAULT 0,
    storage_revision   INTEGER NOT NULL DEFAULT 0,
    retry_budget       INTEGER NOT NULL DEFAULT 0,
    -- 分配身份：跨重启唯一的领取序号。不依赖墙钟基数，重启后继续递增。
    next_claim_seq     INTEGER NOT NULL DEFAULT 1,
    updated_at_ms      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS download_resources(
    resource_id        TEXT PRIMARY KEY,
    task_id            INTEGER NOT NULL REFERENCES downloads(id) ON DELETE CASCADE,
    content_generation INTEGER NOT NULL DEFAULT 0,
    selected           INTEGER NOT NULL DEFAULT 1,
    size_bytes         INTEGER,
    identity_algorithm TEXT,
    identity_digest    TEXT,
    identity_trust     TEXT,
    verification       TEXT NOT NULL DEFAULT 'none',
    commit_state       TEXT NOT NULL DEFAULT 'pending',
    updated_at_ms      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS download_resources_task ON download_resources(task_id);

CREATE TABLE IF NOT EXISTS download_slices(
    slice_id            TEXT PRIMARY KEY,
    resource_id         TEXT NOT NULL,
    task_id             INTEGER NOT NULL REFERENCES downloads(id) ON DELETE CASCADE,
    content_generation  INTEGER NOT NULL DEFAULT 0,
    plan_revision       INTEGER NOT NULL DEFAULT 0,
    span_start          INTEGER NOT NULL,
    span_end_exclusive  INTEGER,
    state               TEXT NOT NULL DEFAULT 'pending',
    updated_at_ms       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS download_slices_task ON download_slices(task_id, plan_revision);

CREATE TABLE IF NOT EXISTS download_sources(
    source_id           TEXT PRIMARY KEY,
    resource_id         TEXT NOT NULL,
    task_id             INTEGER NOT NULL REFERENCES downloads(id) ON DELETE CASCADE,
    transport           TEXT NOT NULL,
    locator_ref         TEXT,
    availability        TEXT NOT NULL DEFAULT 'unknown',
    eligible            INTEGER NOT NULL DEFAULT 0,
    cooldown_until_ms   INTEGER,
    last_observed_at_ms INTEGER,
    expires_at_ms       INTEGER,
    updated_at_ms       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS download_sources_task ON download_sources(task_id);

CREATE TABLE IF NOT EXISTS download_assignments(
    assignment_id       TEXT PRIMARY KEY,
    task_id             INTEGER NOT NULL REFERENCES downloads(id) ON DELETE CASCADE,
    run_epoch           INTEGER NOT NULL,
    content_generation  INTEGER NOT NULL DEFAULT 0,
    slice_id            TEXT NOT NULL,
    source_id           TEXT NOT NULL,
    connection_id       TEXT,
    span_start          INTEGER NOT NULL,
    span_end_exclusive  INTEGER,
    lease_revision      INTEGER NOT NULL DEFAULT 0,
    state               TEXT NOT NULL DEFAULT 'pending',
    updated_at_ms       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS download_assignments_task ON download_assignments(task_id, run_epoch);

CREATE TABLE IF NOT EXISTS download_coverage(
    -- v2：覆盖账本按**任务 + 内容代次**存，不再绑切片。
    --
    -- 依据：`coverage.rs` 的 intervals 是绝对字节区间的并集，本身不含任何
    -- 切片边界语义。绑到 slice_id 上等于把事实绑在计划上——计划一变
    -- （重分段/预算调整）事实就没了。重分段必须能保住已完成字节。
    --
    -- 删任务时级联清掉；删切片**不再**影响覆盖。
    task_id            INTEGER NOT NULL REFERENCES downloads(id) ON DELETE CASCADE,
    content_generation INTEGER NOT NULL DEFAULT 0,
    kind               TEXT NOT NULL,
    intervals          TEXT NOT NULL,
    checkpoint         INTEGER NOT NULL DEFAULT 0,
    updated_at_ms      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(task_id, content_generation, kind)
);

CREATE TABLE IF NOT EXISTS download_commands(
    command_id      TEXT PRIMARY KEY,
    task_id         INTEGER NOT NULL REFERENCES downloads(id) ON DELETE CASCADE,
    run_epoch       INTEGER NOT NULL,
    decision_id     TEXT,
    target          TEXT NOT NULL,
    action          TEXT NOT NULL,
    parameters      TEXT,
    idempotency_key TEXT NOT NULL,
    state           TEXT NOT NULL DEFAULT 'pending',
    result_event_id TEXT,
    error_code      TEXT,
    created_at_ms   INTEGER NOT NULL DEFAULT 0,
    updated_at_ms   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS download_commands_key
    ON download_commands(task_id, idempotency_key);
CREATE INDEX IF NOT EXISTS download_commands_pending
    ON download_commands(task_id, state);
";

/// 应用一次迁移：整批 DDL、events 扩列与版本号在**同一个显式事务**里。
///
/// `rusqlite` 0.32 的 `execute_batch` 是逐条 `prepare`+`step`，**不会**自动包事务；
/// 中途失败会留下“表建了、版本没写”的半成品。events 扩列也必须在同一事务，
/// 否则“七张表已提交、扩列失败”仍然是一种部分升级。
fn apply_migration(conn: &mut Connection, sql: &str, version: i32) -> rusqlite::Result<()> {
    let tx = conn.transaction()?;
    tx.execute_batch(sql)?;
    ensure_event_columns(&tx)?;
    tx.pragma_update(None, "user_version", version)?;
    tx.commit()?;
    Ok(())
}

fn migrate_download_tables(conn: &mut Connection) -> rusqlite::Result<()> {
    let current: i32 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if current >= DOWNLOAD_SCHEMA_VERSION {
        // 已迁移：只补齐可能缺失的 events 扩展列（老库可能停在更早的结构）。
        ensure_event_columns(conn)?;
        purge_untrusted_coverage(conn)?;
        return Ok(());
    }
    if current == 0 {
        // 全新库（或从未迁移过）：当前结构一次建齐。
        apply_migration(conn, DOWNLOAD_SCHEMA_SQL, DOWNLOAD_SCHEMA_VERSION)?;
        purge_untrusted_coverage(conn)?;
        return Ok(());
    }
    // v1 → v2：覆盖账本与切片脱钩。
    //
    // 与 `apply_migration` 一样**整体一个事务**：迁移中途失败必须回滚到 v1，
    // 不能留下“表改了、版本号没改”的半升级状态。
    let tx = conn.transaction()?;
    migrate_coverage_to_task_scoped(&tx)?;
    // 其余表用 `IF NOT EXISTS` 补齐（对 v1 库是幂等的）。
    tx.execute_batch(DOWNLOAD_SCHEMA_SQL)?;
    ensure_event_columns(&tx)?;
    tx.pragma_update(None, "user_version", DOWNLOAD_SCHEMA_VERSION)?;
    tx.commit()?;
    purge_untrusted_coverage(conn)?;
    Ok(())
}

/// 清掉「推导不出可信覆盖」的协议的覆盖行。
///
/// 这些行是 `download_coverage` 早期从 `segments.done_bytes` 汇总出来的，
/// 而 eD2k / BT 的 `done_bytes` 不是「段内已落盘前缀」——它们是跨 part 的累计
/// 接收量。留着它们，恢复逻辑会读到一条**假的连续覆盖**并跳过没下的区段。
///
/// 每次打开库都跑一次：幂等、一条 DELETE、代价可忽略。判定复用
/// [`aidm_core::download::coverage::done_bytes_is_prefix`]，新增协议时只改那一处。
fn purge_untrusted_coverage(conn: &Connection) -> rusqlite::Result<usize> {
    let mut stmt = conn.prepare("SELECT id, url_orig FROM downloads")?;
    let rows: Vec<(i64, String)> = stmt
        .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?
        .filter_map(|r| r.ok())
        .collect();
    drop(stmt);
    let mut removed = 0usize;
    for (id, url) in rows {
        if crate::download::coverage::done_bytes_is_prefix(&url) {
            continue;
        }
        removed += conn.execute(
            "DELETE FROM download_coverage WHERE task_id = ?1",
            [id],
        )?;
    }
    Ok(removed)
}

/// v1（`slice_id` 键）→ v2（`task_id + content_generation` 键）的覆盖账本迁移。
///
/// 同一任务同代次的多个切片会被合并成一行：`intervals` 本来就是绝对区间并集，
/// 合并只是排序 + 相邻/重叠归并，不引入任何猜测。
fn migrate_coverage_to_task_scoped(tx: &rusqlite::Transaction<'_>) -> rusqlite::Result<()> {
    let exists: i64 = tx.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'download_coverage'",
        [],
        |r| r.get(0),
    )?;
    if exists == 0 {
        return Ok(());
    }
    // 已经是新结构就什么都不做（重复迁移必须幂等）。
    let has_slice_id: i64 = tx.query_row(
        "SELECT count(*) FROM pragma_table_info('download_coverage') WHERE name = 'slice_id'",
        [],
        |r| r.get(0),
    )?;
    if has_slice_id == 0 {
        return Ok(());
    }

    tx.execute_batch(
        "CREATE TABLE download_coverage_v2(
            task_id            INTEGER NOT NULL REFERENCES downloads(id) ON DELETE CASCADE,
            content_generation INTEGER NOT NULL DEFAULT 0,
            kind               TEXT NOT NULL,
            intervals          TEXT NOT NULL,
            checkpoint         INTEGER NOT NULL DEFAULT 0,
            updated_at_ms      INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(task_id, content_generation, kind)
        );",
    )?;

    // 旧行 → 任务级：同一 (task, gen, kind) 的多个切片合并。
    let mut merged: std::collections::BTreeMap<(i64, i64, String), (Vec<(u64, u64)>, i64, i64)> =
        std::collections::BTreeMap::new();
    {
        let mut stmt = tx.prepare(
            "SELECT s.task_id, s.content_generation, c.kind, c.intervals, c.checkpoint,
                    c.updated_at_ms
             FROM download_coverage c
             JOIN download_slices s ON s.slice_id = c.slice_id",
        )?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let key = (
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
            );
            let spans = crate::download::store::decode_intervals(&row.get::<_, String>(3)?);
            let checkpoint = row.get::<_, i64>(4)?;
            let updated = row.get::<_, i64>(5)?;
            let entry = merged
                .entry(key)
                .or_insert_with(|| (Vec::new(), 0, 0));
            entry.0.extend(spans.into_iter().map(|r| (r.start, r.end)));
            entry.1 = entry.1.max(checkpoint);
            entry.2 = entry.2.max(updated);
        }
    }
    for ((task_id, gen, kind), (spans, checkpoint, updated)) in merged {
        let merged_spans = merge_open_intervals(spans);
        tx.execute(
            "INSERT INTO download_coverage_v2(
                task_id, content_generation, kind, intervals, checkpoint, updated_at_ms)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                task_id,
                gen,
                kind,
                crate::download::store::encode_intervals(&merged_spans),
                checkpoint,
                updated
            ],
        )?;
    }
    tx.execute_batch("DROP TABLE download_coverage;")?;
    tx.execute_batch("ALTER TABLE download_coverage_v2 RENAME TO download_coverage;")?;
    Ok(())
}

/// 排序 + 相邻/重叠归并（左闭右开）。零长度区间丢弃。
fn merge_open_intervals(mut spans: Vec<(u64, u64)>) -> Vec<std::ops::Range<u64>> {
    spans.retain(|(s, e)| s < e);
    spans.sort_by_key(|(s, e)| (*s, *e));
    let mut out: Vec<std::ops::Range<u64>> = Vec::with_capacity(spans.len());
    for (s, e) in spans {
        match out.last_mut() {
            Some(last) if s <= last.end => last.end = last.end.max(e),
            _ => out.push(s..e),
        }
    }
    out
}

/// `events` 表的新增关联列（文档 11.2 的信封字段落地所需）。
fn ensure_event_columns(conn: &Connection) -> rusqlite::Result<()> {
    ensure_column(conn, "events", "event_id", "TEXT")?;
    ensure_column(conn, "events", "event_seq", "INTEGER")?;
    ensure_column(conn, "events", "run_epoch", "INTEGER")?;
    ensure_column(conn, "events", "payload", "TEXT")?;
    Ok(())
}

fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS settings(
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        -- §4 数据模型（downloads + 多行 segments）
        CREATE TABLE IF NOT EXISTS downloads(
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            url_orig         TEXT NOT NULL,
            url_final        TEXT,
            file_name        TEXT NOT NULL,
            dir              TEXT NOT NULL,
            size_total       INTEGER,          -- Content-Length，未知为 NULL
            etag             TEXT,
            last_modified    TEXT,
            status           TEXT NOT NULL DEFAULT 'queued',
            created_at       INTEGER NOT NULL, -- unix 秒
            finished_at      INTEGER,
            error_code       TEXT,
            speed_limit_kbps INTEGER NOT NULL DEFAULT 0, -- 0=不限
            -- 不参与连接预算：唯一解析器是 `hosts::task_conns`（每服务器例外 > 全局闸门）。
            -- 保留列是为了不破坏老库的列顺序。
            max_conns        INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS segments(
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            download_id INTEGER NOT NULL REFERENCES downloads(id) ON DELETE CASCADE,
            idx        INTEGER NOT NULL,
            pos_start  INTEGER NOT NULL,
            pos_end    INTEGER,                 -- 未知大小时为 NULL
            done_bytes INTEGER NOT NULL DEFAULT 0,
            part_path  TEXT NOT NULL,
            status     TEXT NOT NULL DEFAULT 'pending',
            retries    INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS events(
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            download_id INTEGER NOT NULL REFERENCES downloads(id) ON DELETE CASCADE,
            kind        TEXT NOT NULL,
            ts          INTEGER NOT NULL,
            detail      TEXT,
            -- 结构化字段：从 detail 的 `k=v` 提取，便于 SQL 过滤/聚合（规格 §3.1）。
            phase       TEXT,
            outcome     TEXT,
            err_code    TEXT,
            dur_ms      INTEGER,
            attempt     INTEGER,
            seg         INTEGER,
            conn        TEXT,
            proto       TEXT
        );

        CREATE UNIQUE INDEX IF NOT EXISTS segments_download_idx
            ON segments(download_id, idx);

        -- 按任务查事件（诊断包、能力收窄）是热路径；没有索引会全表扫描。
        CREATE INDEX IF NOT EXISTS events_download_idx
            ON events(download_id, id);

        -- 按服务器（主机）覆盖设置。
        -- 目前只覆盖每服务器最大连接数；加列即可扩展到别的 PerHost 设置项。
        -- eD2k 源表：L3（服务器查源）/L4（对等连接）/L5（Kad 搜源）共用。
        -- 主键是 (任务, 主机, 端口)：同一源重复出现只更新 seen_at。
        CREATE TABLE IF NOT EXISTS ed2k_sources(
            download_id INTEGER NOT NULL,
            host        TEXT NOT NULL,
            port        INTEGER NOT NULL,
            kind        TEXT,               -- server / kad / link / pex
            tries       INTEGER NOT NULL DEFAULT 0,
            fails       INTEGER NOT NULL DEFAULT 0,
            seen_at     INTEGER NOT NULL,
            PRIMARY KEY(download_id, host, port)
        );
        CREATE TABLE IF NOT EXISTS ed2k_credits(
            user_hash        BLOB PRIMARY KEY CHECK(length(user_hash) = 16),
            uploaded_bytes   INTEGER NOT NULL DEFAULT 0,
            downloaded_bytes INTEGER NOT NULL DEFAULT 0,
            public_key       BLOB,
            ident_state      INTEGER NOT NULL DEFAULT 0,
            updated_at       INTEGER NOT NULL
        );
        -- Kad bootstrap 节点列表（`nodes.dat`）。存**刷新到的原始文件字节**而不是
        -- 解析结果：nodes.dat 的字段有版本差异，保存原文才能无损重解析，也便于
        -- 用文件 SHA-256 复盘「当时刷的是哪一份」。
        -- 读取顺序为「本表最新一份 → 编译期内嵌的兜底样本」，因此本表为空时
        -- 行为与从前完全一致。节点是别人的公网 IP/UDP key，会过期，所以才要能刷新。
        CREATE TABLE IF NOT EXISTS kad_bootstrap(
            source_url TEXT PRIMARY KEY,
            doc        BLOB NOT NULL,
            sha256     TEXT NOT NULL,
            node_count INTEGER NOT NULL,
            fetched_at INTEGER NOT NULL   -- unix 毫秒
        );
        -- 多队列（产品文档 §4 / 队列规格 §1）：命名队列是**资源闸门**，不是排序权威。
        -- 不变量：归属看 `downloads.queue_id`；任务按 id（入队先后）派发
        -- （见 `model::dispatch_order`）。不再提供手动顺序层，避免两套权威互相覆盖。
        CREATE TABLE IF NOT EXISTS queues(
            id              INTEGER PRIMARY KEY,
            name            TEXT NOT NULL UNIQUE,
            enabled         INTEGER NOT NULL DEFAULT 1,
            max_parallel    INTEGER NOT NULL DEFAULT 2,
            host_limit      INTEGER NOT NULL DEFAULT 2,
            default_dir     TEXT,
            schedule_cron   TEXT,
            created_at      INTEGER NOT NULL,
            updated_at      INTEGER NOT NULL
        );
        -- L6 上传侧：共享文件的分片哈希集缓存。算一次要整读文件（4 GB 文件就是 4 GB 的
        -- MD4），所以按文件哈希落库，供每次 OP_HASHSETREQUEST 直接回答。
        CREATE TABLE IF NOT EXISTS ed2k_hashsets(
            md4         BLOB PRIMARY KEY CHECK(length(md4) = 16),
            size        INTEGER NOT NULL,
            parts       BLOB NOT NULL,
            updated_at  INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS site_logins(
            host          TEXT PRIMARY KEY,   -- 小写主机名（不含端口）
            username      TEXT NOT NULL,
            password_enc  TEXT,               -- 受保护后的密码；空 = 无密码
            updated_at    INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS host_settings(
            host              TEXT PRIMARY KEY,   -- 小写主机名，或 *.example.com
            max_conns         INTEGER,            -- NULL = 不覆盖
            speed_limit_kbps  INTEGER,            -- NULL = 不覆盖
            updated_at        INTEGER NOT NULL
        );

        -- 签名直链被限流/拒绝后的按任务连接上限。
        -- 只影响该任务；找源成功或任务完成/重新开始时清空。
        -- `finder_done` = 已经为该异常轮跑过找源，重试时不再重复跑。
        CREATE TABLE IF NOT EXISTS download_conn_caps(
            download_id INTEGER PRIMARY KEY REFERENCES downloads(id) ON DELETE CASCADE,
            conn_cap    INTEGER NOT NULL,
            finder_done INTEGER NOT NULL DEFAULT 0,
            updated_at  INTEGER NOT NULL
        );

        -- eD2k 服务器健康：连续超时/0 源的服务器冷却后不再优先使用。
        CREATE TABLE IF NOT EXISTS ed2k_server_health(
            host          TEXT NOT NULL,
            port          INTEGER NOT NULL,
            fail_streak   INTEGER NOT NULL DEFAULT 0,
            last_fail_at  INTEGER,
            last_ok_at    INTEGER,
            PRIMARY KEY(host, port)
        );

        -- 找源候选（`docs/source-discovery.md` §7.2）：只存已验证/已采纳的候选。
        -- 任务删除时随外键级联；过期行在该任务下次找源前清理，不做全局后台清理。
        CREATE TABLE IF NOT EXISTS source_candidates(
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            download_id  INTEGER NOT NULL REFERENCES downloads(id) ON DELETE CASCADE,
            url          TEXT NOT NULL,
            platform     TEXT NOT NULL,          -- platform.as_str()
            kind         TEXT NOT NULL,          -- page | record | file
            size         INTEGER,
            version      TEXT,
            container    TEXT,
            evidence     TEXT NOT NULL,          -- l4 | l3 | l2 | l1 | l0
            digest_algo  TEXT,
            digest_hex   TEXT,
            auth_ref     TEXT,
            origin       TEXT,
            expires_at   INTEGER,
            probe_at     INTEGER,
            score        REAL,
            state        TEXT NOT NULL DEFAULT 'candidate',
            created_at   INTEGER NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS source_candidates_task_url
            ON source_candidates(download_id, url);
        CREATE INDEX IF NOT EXISTS source_candidates_task_state
            ON source_candidates(download_id, state);",
    )?;
    ensure_column(
        conn,
        "downloads",
        "source",
        "TEXT NOT NULL DEFAULT 'manual'",
    )?;
    ensure_column(conn, "downloads", "priority", "INTEGER NOT NULL DEFAULT 0")?;
    // priority 列保留兼容旧库，但调度器不再读取；手动顺序层已整层删除。
    // 旧库把这两处一起清掉，避免留下"看起来还能排序"的死数据。
    drop_table_if_exists(conn, "queue_items")?;
    drop_column_if_exists(conn, "downloads", "queue_order")?;
    ensure_column(conn, "downloads", "retry_at", "INTEGER")?;
    ensure_column(
        conn,
        "downloads",
        "retry_count",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_column(
        conn,
        "downloads",
        "start_mode",
        "TEXT NOT NULL DEFAULT 'now'",
    )?;
    // 人类可读错误与 HTTP 状态。旧库只有 error_code（可能是混杂原文）。
    ensure_column(conn, "downloads", "error_message", "TEXT")?;
    // 来源网页（HTTP Referer）；旧库为空。cookies 永不落库。
    ensure_column(conn, "downloads", "referrer", "TEXT")?;
    // 每任务自定义请求头：落库才能让重启后续传仍然带上
    ensure_column(conn, "downloads", "custom_headers", "TEXT")?;
    // eD2k（电驴）：文件哈希与 AICH 根哈希（链接里给的，用于校验与续传对账）
    ensure_column(conn, "downloads", "ed2k_hash", "TEXT")?;
    ensure_column(conn, "downloads", "aich_root", "TEXT")?;
    ensure_column(conn, "downloads", "http_status", "INTEGER")?;
    // 备用地址（镜像）：每行一个 URL，主地址失败时按序接管。
    ensure_column(conn, "downloads", "alt_urls", "TEXT")?;
    // events 结构化字段（旧库补列；新库建表时已包含）。
    ensure_column(conn, "events", "phase", "TEXT")?;
    ensure_column(conn, "events", "outcome", "TEXT")?;
    ensure_column(conn, "events", "err_code", "TEXT")?;
    ensure_column(conn, "events", "dur_ms", "INTEGER")?;
    ensure_column(conn, "events", "attempt", "INTEGER")?;
    ensure_column(conn, "events", "seg", "INTEGER")?;
    ensure_column(conn, "events", "conn", "TEXT")?;
    ensure_column(conn, "events", "proto", "TEXT")?;
    // 当前生效的候选序号：0 = `url_orig`，n>0 = `alt_urls` 的第 n 行。
    ensure_column(
        conn,
        "downloads",
        "alt_cursor",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    // BitTorrent 逐文件选择：逗号分隔的文件索引；NULL/空 = 全选。
    ensure_column(conn, "downloads", "bt_files", "TEXT")?;
    // 多队列：任务归属的队列（默认队列 id = 1，见 nsure_default_queue）。
    ensure_column(conn, "downloads", "queue_id", "INTEGER NOT NULL DEFAULT 1")?;
    // 累计下载耗时（毫秒）：只统计 worker 真正在跑的时间，暂停 / 排队 / 退避都不计。
    // 速度曲线的横轴与「用时」共用它，所以必须落库——否则重启后曲线横轴归零。
    ensure_column(conn, "downloads", "active_ms", "INTEGER NOT NULL DEFAULT 0")?;
    // 上游声明的整文件 SHA-256（64 位小写十六进制）：取自同目录兄弟文件
    // `CHECKSUM` / `<文件名>.sha256`，用于换镜像时比对身份与下载完成后校验。
    // 取不到时保持 NULL，行为与没有这一列时完全一致。
    ensure_column(conn, "downloads", "sha256_expected", "TEXT")?;
    // 分段绑定的来源（跨源聚合下载，§3）。同一段**只从一个源取**，不混源：
    // 没有分片级哈希时，"内容一致"只能靠完成后用上游整文件 SHA-256 兜底，
    // 所以必须能追溯每一段当时是从哪来的（重启续传也要能接着用它）。
    // 老库与单源任务保持 NULL，此时回落到任务级 url_final / url_orig。
    ensure_column(conn, "segments", "src_url", "TEXT")?;
    // 段级来源版本（`etag:<v>` / `lm:<v>`）：换源/重启续传时比对，避免把两个
    // 不同版本的字节拼进同一个 part。老库为 NULL，行为与从前一致。
    ensure_column(conn, "segments", "src_version", "TEXT")?;
    // 上游 Metalink 里发现的镜像地址（每行一个）。**故意不进候选序列**：
    // `alt_cursor` 落库的是下标，而网络发现的列表每次都可能不同 ——
    // 一旦进序列，换过镜像之后 cursor 会指向另一个地址。它只喂"跨源聚合"的来源池，
    // 那里不依赖下标（每段绑的是地址本身）。
    ensure_column(conn, "downloads", "mirrors_urls", "TEXT")?;
    // 找源预算（`docs/source-discovery.md` §4.2/§7.2）：每个任务终生累计。
    ensure_column(
        conn,
        "downloads",
        "find_rounds",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_column(
        conn,
        "downloads",
        "find_spent_ms",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_column(conn, "downloads", "find_last_at", "INTEGER")?;
    ensure_default_queue(conn)?;
    backfill_error_fields(conn)?;
    Ok(())
}

/// 默认队列必须先于任何任务存在：`downloads.queue_id` 默认指向它。
///
/// `default` **不可删除、不可改名**（`delete_queue`/`update_queue` 会拒绝），
/// 这样"任务总有一个队列"这个不变量永远成立。
pub fn ensure_default_queue(conn: &Connection) -> rusqlite::Result<()> {
    let now = crate::model::now_ms();
    conn.execute(
        "INSERT OR IGNORE INTO queues(id, name, enabled, max_parallel, host_limit, created_at, updated_at)
         VALUES(1, 'default', 1, 2, 2, ?1, ?1)",
        [now],
    )?;
    Ok(())
}

/// 旧行：`error_code` 可能是 `http_404` / `connect: …`，没有 `error_message`。
fn backfill_error_fields(conn: &Connection) -> rusqlite::Result<()> {
    let mut stmt = conn.prepare(
        "SELECT id, error_code FROM downloads
         WHERE error_code IS NOT NULL AND TRIM(error_code) != ''
           AND error_message IS NULL",
    )?;
    let rows: Vec<(i64, String)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    drop(stmt);
    for (id, raw) in rows {
        let c = crate::error::classify(&raw);
        conn.execute(
            "UPDATE downloads SET error_code = ?2, error_message = ?3, http_status = ?4 WHERE id = ?1",
            rusqlite::params![id, c.code, c.message, c.http_status.map(i64::from)],
        )?;
    }
    Ok(())
}

fn column_exists(conn: &Connection, table: &str, column: &str) -> rusqlite::Result<bool> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name == column {
            return Ok(true);
        }
    }
    Ok(false)
}

fn ensure_column(conn: &Connection, table: &str, column: &str, decl: &str) -> rusqlite::Result<()> {
    if column_exists(conn, table, column)? {
        return Ok(());
    }
    conn.execute(
        &format!("ALTER TABLE {table} ADD COLUMN {column} {decl}"),
        [],
    )?;
    Ok(())
}

/// 删列（迁移用）。列不存在时是 no-op，老库与新库都能跑。
fn drop_column_if_exists(conn: &Connection, table: &str, column: &str) -> rusqlite::Result<()> {
    if !column_exists(conn, table, column)? {
        return Ok(());
    }
    conn.execute(&format!("ALTER TABLE {table} DROP COLUMN {column}"), [])?;
    Ok(())
}

/// 删表（迁移用）。表不存在时是 no-op。
fn drop_table_if_exists(conn: &Connection, table: &str) -> rusqlite::Result<()> {
    conn.execute(&format!("DROP TABLE IF EXISTS {table}"), [])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_settings_table() {
        let conn = open_db(Path::new(":memory:")).unwrap();
        let n: i64 = conn
            .query_row("SELECT count(*) FROM settings", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn creates_m1_tables() {
        let conn = open_db(Path::new(":memory:")).unwrap();
        for table in ["downloads", "segments", "events"] {
            let n: i64 = conn
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    [table],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(n, 1, "table {table} missing");
        }
    }

    #[test]
    fn foreign_keys_enabled_and_cascade_works() {
        let conn = open_db(Path::new(":memory:")).unwrap();
        let fk: i64 = conn
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .unwrap();
        assert_eq!(fk, 1, "foreign_keys pragma must be ON");
        let id = crate::model::insert_download(&conn, "u", "f", "d", 0, 1).unwrap();
        crate::model::init_single_segment(&conn, id, "p0", None).unwrap();
        crate::model::log_event(&conn, id, "created", None);
        conn.execute("DELETE FROM downloads WHERE id = ?1", [id])
            .unwrap();
        let orphans: i64 = conn
            .query_row(
                "SELECT (SELECT count(*) FROM segments) + (SELECT count(*) FROM events)",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(orphans, 0, "cascade must remove child rows");
    }

    #[test]
    fn create_dir_failure_maps_to_io_error() {
        // 试图在文件路径下建库 -> 建目录失败应报 CreateDir，而非伪造 SQLite 错误
        let tmp = crate::testsupport::tempdir("db");
        let file = tmp.path().join("blocker");
        std::fs::write(&file, b"x").unwrap();
        let err = open_db(&file.join("db.sqlite")).unwrap_err();
        assert!(matches!(err, OpenError::CreateDir { .. }), "got: {err:?}");
    }

    #[test]
    fn migrates_source_column_default_manual() {
        let conn = open_db(Path::new(":memory:")).unwrap();
        let id = crate::model::insert_download(&conn, "u", "f", "d", 0, 1).unwrap();
        let src: String = conn
            .query_row("SELECT source FROM downloads WHERE id = ?1", [id], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(src, "manual");
    }

    #[test]
    fn migrates_queue_columns_with_defaults() {
        let conn = open_db(Path::new(":memory:")).unwrap();
        let id = crate::model::insert_download(&conn, "u", "f", "d", 0, 1).unwrap();
        let (prio, retry_at, retries, start): (i64, Option<i64>, i64, String) = conn
            .query_row(
                "SELECT priority, retry_at, retry_count, start_mode FROM downloads WHERE id = ?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(prio, 0);
        assert!(retry_at.is_none());
        assert_eq!(retries, 0);
        assert_eq!(start, "now");
        // 手动顺序层已删除：列与表都不该再存在。
        assert!(!column_exists(&conn, "downloads", "queue_order").unwrap());
        let tables: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='queue_items'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(tables, 0, "queue_items 表必须已删除");
    }

    #[test]
    fn old_database_drops_the_manual_order_layer() {
        // 模拟升级前的老库：有 queue_order 列与 queue_items 表。
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE downloads(
                id INTEGER PRIMARY KEY, url_orig TEXT NOT NULL, file_name TEXT NOT NULL,
                dir TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'queued',
                created_at INTEGER NOT NULL, speed_limit_kbps INTEGER NOT NULL DEFAULT 0,
                max_conns INTEGER NOT NULL DEFAULT 1, error_code TEXT,
                queue_order INTEGER NOT NULL DEFAULT 0);
             CREATE TABLE queue_items(
                id INTEGER PRIMARY KEY AUTOINCREMENT, queue_id INTEGER NOT NULL,
                download_id INTEGER NOT NULL UNIQUE, position INTEGER NOT NULL,
                priority INTEGER NOT NULL DEFAULT 0, added_at INTEGER NOT NULL);
             INSERT INTO downloads(url_orig, file_name, dir, created_at, queue_order)
                VALUES('u','f','d',1,7);
             INSERT INTO queue_items(queue_id, download_id, position, added_at)
                VALUES(1,1,3,1);",
        )
        .unwrap();
        migrate(&conn).unwrap();
        assert!(!column_exists(&conn, "downloads", "queue_order").unwrap());
        let n: i64 = conn
            .query_row("SELECT count(*) FROM queue_items", [], |r| r.get(0))
            .unwrap_or(0);
        assert_eq!(n, 0, "老库升级后 queue_items 必须清空");
        // 迁移不能弄丢任务行本身。
        let rows: i64 = conn
            .query_row("SELECT count(*) FROM downloads", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 1);
    }

    #[test]
    fn old_database_gains_the_sha256_expected_column() {
        // 升级前的老库没有 sha256_expected 列：补列必须是 no-op 式的增量迁移，
        // 既有任务行不能丢，且新列默认为 NULL（= 没有上游哈希可比对）。
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE downloads(
                id INTEGER PRIMARY KEY, url_orig TEXT NOT NULL, file_name TEXT NOT NULL,
                dir TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'queued',
                created_at INTEGER NOT NULL, speed_limit_kbps INTEGER NOT NULL DEFAULT 0,
                max_conns INTEGER NOT NULL DEFAULT 1, error_code TEXT);
             INSERT INTO downloads(url_orig, file_name, dir, created_at)
                VALUES('u','f','d',1);",
        )
        .unwrap();
        assert!(!column_exists(&conn, "downloads", "sha256_expected").unwrap());
        migrate(&conn).unwrap();
        assert!(column_exists(&conn, "downloads", "sha256_expected").unwrap());
        let rows: i64 = conn
            .query_row("SELECT count(*) FROM downloads", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 1, "迁移不能弄丢任务行");
        let got: Option<String> = conn
            .query_row(
                "SELECT sha256_expected FROM downloads WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(got.is_none(), "老行应保持 NULL");
    }

    #[test]
    fn migrates_error_message_and_http_status_from_old_error_code() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE downloads(
                id INTEGER PRIMARY KEY,
                url_orig TEXT NOT NULL,
                url_final TEXT,
                file_name TEXT NOT NULL,
                dir TEXT NOT NULL,
                size_total INTEGER,
                etag TEXT,
                last_modified TEXT,
                status TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                finished_at INTEGER,
                error_code TEXT,
                speed_limit_kbps INTEGER NOT NULL DEFAULT 0,
                max_conns INTEGER NOT NULL DEFAULT 1
            );",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO downloads(url_orig, file_name, dir, status, created_at, error_code)
             VALUES('u','f','d','error',1,'http_404')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO downloads(url_orig, file_name, dir, status, created_at, error_code)
             VALUES('u2','f2','d','error',1,'connect: reset')",
            [],
        )
        .unwrap();
        migrate(&conn).unwrap();
        let (code, msg, http): (String, String, Option<i64>) = conn
            .query_row(
                "SELECT error_code, error_message, http_status FROM downloads WHERE file_name='f'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(code, crate::error::CODE_HTTP_404);
        assert!(msg.contains("404"));
        assert_eq!(http, Some(404));
        let net: String = conn
            .query_row(
                "SELECT error_code FROM downloads WHERE file_name='f2'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(net, crate::error::CODE_NETWORK);
    }
}

#[cfg(test)]
mod c1_migration_tests {
    use super::*;

    fn table_exists(conn: &Connection, name: &str) -> bool {
        conn.query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
            [name],
            |_| Ok(()),
        )
        .is_ok()
    }

    fn user_version(conn: &Connection) -> i32 {
        conn.pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap()
    }

    #[test]
    fn v1_slice_scoped_coverage_is_migrated_to_task_scope() {
        // (c) 的迁移面：v1 的覆盖挂在 slice_id 上，v2 挂在 (task, generation) 上。
        // 迁移必须保住已完成字节，否则升级一次等于从头下。
        let mut conn = open_db(Path::new(":memory:")).unwrap();
        conn.execute_batch(
            "DROP TABLE download_coverage;
             CREATE TABLE download_coverage(
                slice_id       TEXT NOT NULL,
                kind           TEXT NOT NULL,
                intervals      TEXT NOT NULL,
                checkpoint     INTEGER NOT NULL DEFAULT 0,
                updated_at_ms  INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(slice_id, kind)
             );
             INSERT INTO downloads(url_orig, file_name, dir, created_at)
                VALUES('https://e/a', 'a.bin', '/t', 0);
             INSERT INTO download_slices(slice_id, resource_id, task_id, span_start, span_end_exclusive)
                VALUES('s0', 'r1', 1, 0, 100), ('s1', 'r1', 1, 100, 200);
             -- 覆盖是**任务绝对**偏移：s0 覆盖前 60 字节，s1 覆盖 100..140。
             INSERT INTO download_coverage(slice_id, kind, intervals, checkpoint, updated_at_ms)
                VALUES('s0', 'stored', '0:60', 3, 10),
                      ('s1', 'stored', '100:140', 5, 20),
                      ('s0', 'verified', '0:50', 3, 10);
             PRAGMA user_version = 1;",
        )
        .unwrap();

        // 重开一次库 = 触发迁移。
        migrate_download_tables(&mut conn).unwrap();
        // 内存库无法重开，直接对同一连接跑迁移函数（它读 user_version=1）。
        assert_eq!(user_version(&conn), DOWNLOAD_SCHEMA_VERSION, "版本必须升到 v2");

        let cols: Vec<String> = {
            let mut stmt = conn
                .prepare("SELECT name FROM pragma_table_info('download_coverage') ORDER BY name")
                .unwrap();
            let rows = stmt.query_map([], |r| r.get::<_, String>(0)).unwrap();
            rows.filter_map(|r| r.ok()).collect()
        };
        assert!(!cols.contains(&"slice_id".to_owned()), "v2 不得再有 slice_id 列");
        assert!(cols.contains(&"task_id".to_owned()));
        assert!(cols.contains(&"content_generation".to_owned()));

        let stored = crate::download::store::load_coverage(&conn, 1, 0, "stored").unwrap();
        assert_eq!(
            stored,
            vec![0u64..60, 100u64..140],
            "两个切片的覆盖必须合并成任务级区间"
        );
        let verified = crate::download::store::load_coverage(&conn, 1, 0, "verified").unwrap();
        assert_eq!(verified, vec![0u64..50]);
    }

    #[test]
    fn migration_is_idempotent_when_coverage_is_already_v2() {
        let mut conn = open_db(Path::new(":memory:")).unwrap();
        // 已是 v2 结构 + 版本号已是 2：再跑一次不得改动任何数据。
        conn.execute(
            "INSERT INTO downloads(url_orig, file_name, dir, created_at)
             VALUES('https://e/a', 'a.bin', '/t', 0)",
            [],
        )
        .unwrap();
        crate::download::store::save_coverage(&conn, 1, 0, "stored", &[0..10], 1).unwrap();
        migrate_download_tables(&mut conn).unwrap();
        assert_eq!(
            crate::download::store::load_coverage(&conn, 1, 0, "stored").unwrap(),
            vec![0u64..10],
            "重复迁移必须幂等"
        );
    }

    #[test]
    fn download_tables_and_version_are_created() {
        let conn = open_db(Path::new(":memory:")).unwrap();
        assert_eq!(user_version(&conn), DOWNLOAD_SCHEMA_VERSION);
        for table in [
            "download_runtime",
            "download_resources",
            "download_slices",
            "download_sources",
            "download_assignments",
            "download_coverage",
            "download_commands",
        ] {
            assert!(table_exists(&conn, table), "缺少表 {table}");
        }
    }

    #[test]
    fn events_gain_envelope_columns() {
        let conn = open_db(Path::new(":memory:")).unwrap();
        for col in ["event_id", "event_seq", "run_epoch", "payload"] {
            assert!(
                column_exists(&conn, "events", col).unwrap(),
                "events 缺少信封列 {col}"
            );
        }
    }

    #[test]
    fn migration_is_idempotent_when_reopening_a_file_db() {
        let dir = crate::testsupport::tempdir("c1-reopen");
        let path = dir.path().join("db.sqlite");
        {
            let conn = open_db(&path).unwrap();
            assert_eq!(user_version(&conn), DOWNLOAD_SCHEMA_VERSION);
        }
        // 二次打开：不能重复建表、也不能把版本号写回。
        let conn = open_db(&path).unwrap();
        assert_eq!(user_version(&conn), DOWNLOAD_SCHEMA_VERSION);
        let n: i64 = conn
            .query_row("SELECT count(*) FROM download_runtime", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0, "重复打开不能插数据");
    }

    #[test]
    fn failed_migration_rolls_back_tables_and_version() {
        // 故意在批里塞一条非法语句：`execute_batch` 本身不包事务，
        // 必须由 `apply_migration` 的显式事务保证整批回滚。
        let mut conn = Connection::open_in_memory().unwrap();
        let bad = "CREATE TABLE should_not_persist(a INTEGER); THIS IS NOT SQL;";
        let err = apply_migration(&mut conn, bad, 1);
        assert!(err.is_err(), "非法 DDL 必须报错");
        assert!(
            !table_exists(&conn, "should_not_persist"),
            "失败后不能留下半成品表"
        );
        assert_eq!(user_version(&conn), 0, "失败后版本号不能推进");
    }

    #[test]
    fn old_database_upgrades_without_losing_existing_rows() {
        // 模拟 C1 之前的库：先跑一遍结构检查式迁移建出老表，再把版本留在 0。
        // 不能手写一个只有两列的 downloads——真实的旧库有 `error_code` 等列，
        // 否则测的是“残废库”而不是“旧库”。
        let dir = crate::testsupport::tempdir("c1-old-db");
        let path = dir.path().join("db.sqlite");
        {
            let conn = Connection::open(&path).unwrap();
            migrate(&conn).unwrap();
            conn.execute(
                "INSERT INTO downloads(url_orig, file_name, dir, created_at)
                 VALUES ('https://example/a', 'a.bin', '/tmp', 0)",
                [],
            )
            .unwrap();
            assert_eq!(user_version(&conn), 0, "旧库尚未有 C1 版本记录");
            assert!(
                !table_exists(&conn, "download_runtime"),
                "旧库不应该已有 C1 表"
            );
        }
        let conn = open_db(&path).unwrap();
        assert_eq!(user_version(&conn), DOWNLOAD_SCHEMA_VERSION);
        let url: String = conn
            .query_row("SELECT url_orig FROM downloads WHERE id=1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(url, "https://example/a", "升级不能丢老数据");
        assert!(table_exists(&conn, "download_runtime"));
    }

    #[test]
    fn deleting_a_task_cascades_download_tables() {
        let conn = open_db(Path::new(":memory:")).unwrap();
        conn.execute(
            "INSERT INTO downloads(id, url_orig, file_name, dir, created_at)
             VALUES (1, 'https://example/a', 'a.bin', '/tmp', 0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO download_runtime(task_id, run_epoch) VALUES (1, 5)",
            [],
        )
        .unwrap();
        conn.execute("DELETE FROM downloads WHERE id = 1", []).unwrap();
        let n: i64 = conn
            .query_row("SELECT count(*) FROM download_runtime", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0, "删任务必须级联清理运行时记录");
    }
}

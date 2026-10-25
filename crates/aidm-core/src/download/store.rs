//! 运行身份、分配身份与命令的持久化（不含执行逻辑）。
//!
//! 依据 `docs/unified-download-state-review.md` 12.2.6 的 C1：
//! - 持久化执行模式、`run_epoch`、`content_generation`、方案版本与命令身份；
//! - 同次分配身份稳定、新领取唯一；
//! - **跨重启不依赖墙钟基数**保证身份。
//!
//! 本模块只做读写与事务，不决定何时推进轮次、也不接管执行路径。
//! 表结构在 `db.rs` 的 `DOWNLOAD_SCHEMA_SQL`（`user_version = 1`）。
//!
//! # 为什么分配序号要落库
//!
//! C0 时 `claim_seq` 用进程启动时刻做基数，跨重启会与历史值重叠。
//! 这里改为在每个任务的行上维护 `next_claim_seq`，用**事务内自增**分配号段，
//! 所以重启后仍单调递增，同一个 `assignment_id` 不会指向两次不同的归属。

use super::control::ExecutionMode;
use super::model::{
    Action, ActionParams, Command, CommandId, CommandStatus, DecisionId,
};
use crate::model::now_ms;
use rusqlite::{params, Connection, OptionalExtension};
use std::ops::Range;

/// 任务的运行身份与控制记录。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadRuntime {
    pub task_id: i64,
    pub execution_mode: ExecutionMode,
    pub run_epoch: u64,
    pub content_generation: u64,
    pub plan_revision: u64,
    pub state_revision: u64,
    pub storage_revision: u64,
    pub retry_budget: u32,
    /// 下一次可以分配给原生领取的起始序号（单调递增，跨重启不重置）。
    pub next_claim_seq: u64,
}

impl DownloadRuntime {
    /// 新任务的默认运行记录：**默认 legacy**（C0 的归属约定）。
    pub fn new(task_id: i64) -> Self {
        Self {
            task_id,
            execution_mode: ExecutionMode::default_for_new_task(),
            run_epoch: 0,
            content_generation: 0,
            plan_revision: 0,
            state_revision: 0,
            storage_revision: 0,
            retry_budget: 0,
            next_claim_seq: 1,
        }
    }
}

fn mode_from_str(raw: &str) -> ExecutionMode {
    match raw {
        "unified" => ExecutionMode::Unified,
        // 未知值一律回到 legacy：宁可少做，不可偷偷接管。
        _ => ExecutionMode::Legacy,
    }
}

fn row_to_runtime(row: &rusqlite::Row<'_>) -> rusqlite::Result<DownloadRuntime> {
    Ok(DownloadRuntime {
        task_id: row.get(0)?,
        execution_mode: mode_from_str(&row.get::<_, String>(1)?),
        run_epoch: row.get::<_, i64>(2)?.max(0) as u64,
        content_generation: row.get::<_, i64>(3)?.max(0) as u64,
        plan_revision: row.get::<_, i64>(4)?.max(0) as u64,
        state_revision: row.get::<_, i64>(5)?.max(0) as u64,
        storage_revision: row.get::<_, i64>(6)?.max(0) as u64,
        retry_budget: row.get::<_, i64>(7)?.max(0) as u32,
        next_claim_seq: row.get::<_, i64>(8)?.max(1) as u64,
    })
}

/// 读取运行记录；不存在返回 `None`（不隐式创建）。
pub fn load_runtime(conn: &Connection, task_id: i64) -> rusqlite::Result<Option<DownloadRuntime>> {
    conn.query_row(
        "SELECT task_id, execution_mode, run_epoch, content_generation, plan_revision,
                state_revision, storage_revision, retry_budget, next_claim_seq
         FROM download_runtime WHERE task_id = ?1",
        [task_id],
        row_to_runtime,
    )
    .optional()
}

/// 确保运行记录存在，返回当前值。
///
/// 新任务一律 legacy；已有记录原样返回（**不改模式**，模式只能显式设置）。
pub fn ensure_runtime(conn: &Connection, task_id: i64) -> rusqlite::Result<DownloadRuntime> {
    if let Some(rt) = load_runtime(conn, task_id)? {
        return Ok(rt);
    }
    conn.execute(
        "INSERT OR IGNORE INTO download_runtime(task_id, updated_at_ms) VALUES(?1, ?2)",
        params![task_id, now_ms()],
    )?;
    load_runtime(conn, task_id)?.ok_or(rusqlite::Error::QueryReturnedNoRows)
}

/// 写入运行记录（检查点）。
///
/// **不写 `next_claim_seq` 与 `execution_mode`**：
/// - 领取序号只能由 [`allocate_claim_seq`] 推高。旧检查点回写会让分配器倒退，
///   直接导致 `assignment_id` 在重启后被复用（用户复核的局限之一）。
/// - 执行模式只能由 [`set_execution_mode`] 显式切换，检查点不得隐式改回 legacy。
///
/// 单调字段（`run_epoch` / `content_generation` / `plan_revision` /
/// `state_revision` / `storage_revision`）用 `MAX` 合并：晚到的旧消息
/// 不会把新轮次写回去。`retry_budget` 是“剩余量”，可以下降，所以直接赋值。
pub fn save_runtime(conn: &Connection, rt: &DownloadRuntime) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE download_runtime SET
            run_epoch = MAX(run_epoch, ?2),
            content_generation = MAX(content_generation, ?3),
            plan_revision = MAX(plan_revision, ?4),
            state_revision = MAX(state_revision, ?5),
            storage_revision = MAX(storage_revision, ?6),
            retry_budget = ?7,
            updated_at_ms = ?8
         WHERE task_id = ?1",
        params![
            rt.task_id,
            rt.run_epoch as i64,
            rt.content_generation as i64,
            rt.plan_revision as i64,
            rt.state_revision as i64,
            rt.storage_revision as i64,
            rt.retry_budget as i64,
            now_ms(),
        ],
    )?;
    Ok(())
}

/// 显式设置执行模式。
///
/// 返回 `false` 表示记录不存在。**不提供从 unified 回退的静默路径**：
/// 回退必须由调用方先停写、再显式设置（12.3）。
pub fn set_execution_mode(
    conn: &Connection,
    task_id: i64,
    mode: ExecutionMode,
) -> rusqlite::Result<bool> {
    let n = conn.execute(
        "UPDATE download_runtime SET execution_mode = ?2, updated_at_ms = ?3 WHERE task_id = ?1",
        params![task_id, mode.as_str(), now_ms()],
    )?;
    Ok(n > 0)
}

/// 开始新一轮运行：`run_epoch += 1`，返回新值。
///
/// 只在**取得任务执行权**时调用；普通重试不递增（文档 4.2）。
pub fn begin_run(
    conn: &mut Connection,
    task_id: i64,
    content_generation: Option<u64>,
) -> rusqlite::Result<u64> {
    let tx = conn.transaction()?;
    let current = tx
        .query_row(
            "SELECT run_epoch FROM download_runtime WHERE task_id = ?1",
            [task_id],
            |r| r.get::<_, i64>(0),
        )
        .optional()?;
    let Some(current) = current else {
        return Err(rusqlite::Error::QueryReturnedNoRows);
    };
    let next = current.max(0) + 1;
    match content_generation {
        Some(gen) => tx.execute(
            "UPDATE download_runtime SET run_epoch = ?2, content_generation = ?3, updated_at_ms = ?4
             WHERE task_id = ?1",
            params![task_id, next, gen as i64, now_ms()],
        )?,
        None => tx.execute(
            "UPDATE download_runtime SET run_epoch = ?2, updated_at_ms = ?3 WHERE task_id = ?1",
            params![task_id, next, now_ms()],
        )?,
    };
    tx.commit()?;
    Ok(next as u64)
}

/// 方案版本 +1，返回新值。切片范围发生**结构变化**时调用。
pub fn bump_plan_revision(conn: &mut Connection, task_id: i64) -> rusqlite::Result<u64> {
    let tx = conn.transaction()?;
    let current: Option<i64> = tx
        .query_row(
            "SELECT plan_revision FROM download_runtime WHERE task_id = ?1",
            [task_id],
            |r| r.get(0),
        )
        .optional()?;
    let Some(current) = current else {
        return Err(rusqlite::Error::QueryReturnedNoRows);
    };
    let next = current.max(0) + 1;
    tx.execute(
        "UPDATE download_runtime SET plan_revision = ?2, updated_at_ms = ?3 WHERE task_id = ?1",
        params![task_id, next, now_ms()],
    )?;
    tx.commit()?;
    Ok(next as u64)
}

/// 从任务行里**原子**分配一段领取序号，返回起始值。
///
/// 调用方拿到 `start` 后可以使用 `start..start+count` 这一段。
/// 这就是“跨重启不依赖墙钟基数”的落点：号段本身在数据库里，重启后继续。
pub fn allocate_claim_seq(
    conn: &mut Connection,
    task_id: i64,
    count: u64,
) -> rusqlite::Result<u64> {
    let count = count.max(1);
    let tx = conn.transaction()?;
    let start: Option<i64> = tx
        .query_row(
            "SELECT next_claim_seq FROM download_runtime WHERE task_id = ?1",
            [task_id],
            |r| r.get(0),
        )
        .optional()?;
    let Some(start) = start else {
        return Err(rusqlite::Error::QueryReturnedNoRows);
    };
    tx.execute(
        "UPDATE download_runtime SET next_claim_seq = ?2, updated_at_ms = ?3 WHERE task_id = ?1",
        params![task_id, start + count as i64, now_ms()],
    )?;
    tx.commit()?;
    Ok(start.max(1) as u64)
}

// ---------------------------------------------------------------- 覆盖账本

/// 把归一化区间编码成 `start:end,start:end`。
///
/// 不用 JSON：区间只是一串数字对，纯文本更小，也不需要引入结构体。
/// 非法/空输入一律当空集，不猜。
pub fn encode_intervals(spans: &[Range<u64>]) -> String {
    spans
        .iter()
        .filter(|r| r.start < r.end)
        .map(|r| format!("{}:{}", r.start, r.end))
        .collect::<Vec<_>>()
        .join(",")
}

/// 解析 `start:end` 列表；无法解析的片段直接丢弃（宁可少算，不可多算）。
pub fn decode_intervals(raw: &str) -> Vec<Range<u64>> {
    let mut out: Vec<Range<u64>> = Vec::new();
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let Some((a, b)) = part.split_once(':') else {
            continue;
        };
        let (Ok(start), Ok(end)) = (a.trim().parse::<u64>(), b.trim().parse::<u64>()) else {
            continue;
        };
        if start < end {
            out.push(start..end);
        }
    }
    out.sort_by_key(|r| r.start);
    out
}

/// 保存某任务的覆盖账本（`kind` = `stored` / `verified`）。
///
/// `checkpoint` 的语义是**写入门槛**：调用方上一次落账时的 `SUM(done_bytes)`，
/// 只用来判断“这次要不要写”，**不是覆盖长度**。
///
/// 两者的差在重复写时出现：同一段重试/换源会被写两次，`SUM` 把它算两遍，
/// 而覆盖长度（`intervals` 的区间并集）只算一次。所以：
/// - 需要“已下载字节” → 用 `intervals` 求并集长度；
/// - 需要“该不该再写一次” → 用 `checkpoint`。
///
/// 不要把 `checkpoint` 当进度用。
pub fn save_coverage(
    conn: &Connection,
    task_id: i64,
    content_generation: u64,
    kind: &str,
    spans: &[Range<u64>],
    checkpoint: u64,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO download_coverage(
            task_id, content_generation, kind, intervals, checkpoint, updated_at_ms)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(task_id, content_generation, kind) DO UPDATE SET
            intervals = excluded.intervals,
            checkpoint = excluded.checkpoint,
            updated_at_ms = excluded.updated_at_ms",
        params![
            task_id,
            content_generation as i64,
            kind,
            encode_intervals(spans),
            checkpoint as i64,
            now_ms()
        ],
    )?;
    Ok(())
}

/// 切片方案里的一行（`download_slices` 的写入形状）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SliceRow {
    pub slice_id: String,
    pub resource_id: String,
    pub span_start: u64,
    pub span_end_exclusive: Option<u64>,
    pub state: String,
}

/// 写入一份切片方案。
///
/// 不变式（文档 4.3）：**同一 `slice_id` 与 `plan_revision` 下范围不可变**。
/// 所以这里不是 upsert——`(task_id, plan_revision)` 已有行就直接返回 `false`，
/// 一行都不动。改方案必须递增 `plan_revision` 后重建切片。
///
/// 重建只影响**计划**：覆盖账本按任务存（12.2.8 的裁决 (c)），已完成字节不受
/// 重分段影响。所以允许重分段，代价仅是 `slice_id` 重新编号。
///
/// 返回是否真的写入（`false` = 该版本已存在，幂等跳过）。
pub fn save_plan(
    conn: &mut Connection,
    task_id: i64,
    content_generation: u64,
    plan_revision: u64,
    slices: &[SliceRow],
) -> rusqlite::Result<bool> {
    let existing: i64 = conn.query_row(
        "SELECT count(*) FROM download_slices WHERE task_id = ?1 AND plan_revision = ?2",
        params![task_id, plan_revision as i64],
        |r| r.get(0),
    )?;
    if existing > 0 {
        return Ok(false);
    }
    let tx = conn.transaction()?;
    // 新版本 = 重建切片，但**只作废切片**。
    //
    // 覆盖账本自 v2 起挂在 `(task_id, content_generation, kind)` 上，不随切片删除
    // （见 12.2.8 的裁决 (c)）。所以「改方案必须重建」不等于「已完成字节清零」——
    // 删的只是计划，事实留在 `download_coverage` 里。
    //
    // 不删旧切片的话，`slice_id`（全局主键）会与旧行冲突，而且旧范围会继续
    // 参与投影，让“同一 slice_id + plan_revision 下范围不可变”变成一句空话。
    tx.execute(
        "DELETE FROM download_slices WHERE task_id = ?1 AND plan_revision <> ?2",
        params![task_id, plan_revision as i64],
    )?;
    for s in slices {
        tx.execute(
            "INSERT INTO download_slices(
                slice_id, resource_id, task_id, content_generation, plan_revision,
                span_start, span_end_exclusive, state, updated_at_ms)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                s.slice_id,
                s.resource_id,
                task_id,
                content_generation as i64,
                plan_revision as i64,
                s.span_start as i64,
                s.span_end_exclusive.map(|e| e as i64),
                s.state,
                now_ms(),
            ],
        )?;
    }
    tx.commit()?;
    Ok(true)
}

/// 读取某任务某版本的切片方案，按 `span_start` 升序。
pub fn load_plan(
    conn: &Connection,
    task_id: i64,
    plan_revision: u64,
) -> rusqlite::Result<Vec<SliceRow>> {
    let mut stmt = conn.prepare(
        "SELECT slice_id, resource_id, span_start, span_end_exclusive, state
         FROM download_slices
         WHERE task_id = ?1 AND plan_revision = ?2
         ORDER BY span_start, slice_id",
    )?;
    // **不做 clamp**：负数只可能来自坏数据或 8 EB 以上的溢出。
    // 悄悄折成 0 会让 `plan.rs` 的「坏行照原样编码、让比较失败」变成一句空话——
    // 投影看起来对，实际范围已经被抹平。宁可读失败。
    let rows = stmt.query_map(params![task_id, plan_revision as i64], |r| {
        let start: i64 = r.get(2)?;
        let end: Option<i64> = r.get(3)?;
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            start,
            end,
            r.get::<_, String>(4)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (slice_id, resource_id, start, end, state) = row?;
        let span_start = u64::try_from(start).map_err(|_| {
            rusqlite::Error::IntegralValueOutOfRange(2, start)
        })?;
        let span_end_exclusive = match end {
            Some(e) => Some(u64::try_from(e).map_err(|_| {
                rusqlite::Error::IntegralValueOutOfRange(3, e)
            })?),
            None => None,
        };
        out.push(SliceRow {
            slice_id,
            resource_id,
            span_start,
            span_end_exclusive,
            state,
        });
    }
    Ok(out)
}

/// 读取某切片某一类的覆盖账本；无记录返回空。
pub fn load_coverage(
    conn: &Connection,
    task_id: i64,
    content_generation: u64,
    kind: &str,
) -> rusqlite::Result<Vec<Range<u64>>> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT intervals FROM download_coverage
             WHERE task_id = ?1 AND content_generation = ?2 AND kind = ?3",
            params![task_id, content_generation as i64, kind],
            |r| r.get(0),
        )
        .optional()?;
    Ok(raw.map(|s| decode_intervals(&s)).unwrap_or_default())
}

// ---------------------------------------------------------------- 命令账本

/// 持久化一条命令。
///
/// **只插入新命令**（`DO NOTHING`）：已存在的命令状态只能由 [`finish_command`]
/// 推进。若这里允许 `state = excluded.state`，一次“重复保存原 pending 快照”
/// 就会把 succeeded 改回 pending，命令重新进入回放集合 → 重复副作用。
pub fn save_command(conn: &Connection, command: &Command) -> rusqlite::Result<()> {
    // 参数必须落库：恢复时按原样回放，不能只剩一个动作名。
    let parameters = serde_json::to_string(&command.parameters).ok();
    conn.execute(
        "INSERT INTO download_commands(
            command_id, task_id, run_epoch, decision_id, target, action,
            parameters, idempotency_key, state, created_at_ms, updated_at_ms)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10)
         ON CONFLICT(command_id) DO NOTHING",
        params![
            command.command_id.as_str(),
            command.task_id,
            command.run_epoch as i64,
            command.decision_id.as_ref().map(|d| d.as_str()),
            command.target,
            command.action.as_str(),
            parameters,
            command.idempotency_key,
            command.state.as_str(),
            now_ms(),
        ],
    )?;
    Ok(())
}

/// 读取某任务在当前轮次下尚未完成的命令（完整载荷）。
///
/// 只返回 `pending` / `running`：已结束的命令不回放（文档 9 节）。
/// 无法解析的行直接跳过——宁可少回放，不可猜。
pub fn load_unfinished_commands(
    conn: &Connection,
    task_id: i64,
    run_epoch: u64,
) -> rusqlite::Result<Vec<Command>> {
    let mut stmt = conn.prepare(
        "SELECT command_id, run_epoch, decision_id, target, action, parameters,
                idempotency_key, state
         FROM download_commands
         WHERE task_id = ?1 AND run_epoch = ?2 AND state IN ('pending','running')
         ORDER BY created_at_ms, command_id",
    )?;
    let rows = stmt.query_map(params![task_id, run_epoch as i64], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, i64>(1)?.max(0) as u64,
            r.get::<_, Option<String>>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, Option<String>>(5)?,
            r.get::<_, String>(6)?,
            r.get::<_, String>(7)?,
        ))
    })?;

    let mut out = Vec::new();
    for row in rows {
        let (id, epoch, decision, target, action, params, key, state) = row?;
        let Some(action) = Action::parse(&action) else {
            continue;
        };
        let status = CommandStatus::parse(&state).unwrap_or(CommandStatus::Pending);
        let parameters = params
            .and_then(|s| serde_json::from_str::<ActionParams>(&s).ok())
            .unwrap_or_default();
        out.push(Command {
            command_id: CommandId::new(id),
            decision_id: decision.and_then(|d| DecisionId::parse(&d)),
            task_id,
            run_epoch: epoch,
            target,
            action,
            parameters,
            idempotency_key: key,
            state: status,
            result_event_id: None,
            error: None,
        });
    }
    Ok(out)
}

/// 写回执。返回 `false` 表示命令不存在或已经结束（不覆盖第一条结果）。
pub fn finish_command(
    conn: &Connection,
    command_id: &CommandId,
    state: CommandStatus,
) -> rusqlite::Result<bool> {
    let n = conn.execute(
        "UPDATE download_commands SET state = ?2, updated_at_ms = ?3
         WHERE command_id = ?1 AND state IN ('pending','running')",
        params![command_id.as_str(), state.as_str(), now_ms()],
    )?;
    Ok(n > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::download::model::{Action, ActionParams};
    use crate::open_db;
    use std::path::Path;

    fn db() -> Connection {
        open_db(Path::new(":memory:")).expect("open db")
    }

    fn seed_task(conn: &Connection) -> i64 {
        conn.execute(
            "INSERT INTO downloads(url_orig, file_name, dir, created_at)
             VALUES ('https://example/a', 'a.bin', '/tmp', 0)",
            [],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    #[test]
    fn new_task_defaults_to_legacy() {
        let conn = db();
        let id = seed_task(&conn);
        let rt = ensure_runtime(&conn, id).expect("runtime");
        assert_eq!(rt.execution_mode, ExecutionMode::Legacy);
        assert_eq!(rt.run_epoch, 0);
        assert_eq!(rt.next_claim_seq, 1);
    }

    #[test]
    fn ensure_runtime_is_idempotent_and_keeps_mode() {
        let conn = db();
        let id = seed_task(&conn);
        ensure_runtime(&conn, id).expect("first");
        assert!(set_execution_mode(&conn, id, ExecutionMode::Unified).expect("set"));
        let rt = ensure_runtime(&conn, id).expect("second");
        assert_eq!(
            rt.execution_mode,
            ExecutionMode::Unified,
            "ensure 不能把已登记的模式改回 legacy"
        );
    }

    #[test]
    fn begin_run_increments_epoch_and_sets_generation() {
        let mut conn = db();
        let id = seed_task(&conn);
        ensure_runtime(&conn, id).expect("runtime");
        assert_eq!(begin_run(&mut conn, id, Some(1)).expect("run1"), 1);
        assert_eq!(begin_run(&mut conn, id, Some(2)).expect("run2"), 2);
        let rt = load_runtime(&conn, id).expect("load").expect("row");
        assert_eq!(rt.run_epoch, 2);
        assert_eq!(rt.content_generation, 2);
    }

    #[test]
    fn begin_run_without_generation_keeps_it() {
        let mut conn = db();
        let id = seed_task(&conn);
        ensure_runtime(&conn, id).expect("runtime");
        begin_run(&mut conn, id, Some(7)).expect("run1");
        let epoch = begin_run(&mut conn, id, None).expect("run2");
        assert_eq!(epoch, 2);
        let rt = load_runtime(&conn, id).expect("load").expect("row");
        assert_eq!(rt.content_generation, 7, "不传代次时保持原值");
    }

    #[test]
    fn plan_revision_only_moves_on_structural_change() {
        let mut conn = db();
        let id = seed_task(&conn);
        ensure_runtime(&conn, id).expect("runtime");
        assert_eq!(bump_plan_revision(&mut conn, id).expect("bump"), 1);
        assert_eq!(bump_plan_revision(&mut conn, id).expect("bump"), 2);
        // 预算变化不应该调用它（调用方才决定）；这里只验证它单调递增。
        let rt = load_runtime(&conn, id).expect("load").expect("row");
        assert_eq!(rt.plan_revision, 2);
    }

    #[test]
    fn claim_seq_allocations_never_overlap() {
        let mut conn = db();
        let id = seed_task(&conn);
        ensure_runtime(&conn, id).expect("runtime");
        let a = allocate_claim_seq(&mut conn, id, 10).expect("a");
        let b = allocate_claim_seq(&mut conn, id, 5).expect("b");
        assert_eq!(a, 1);
        assert_eq!(b, 11, "第二段必须紧接第一段之后");
        // 段内可用区间不相交。
        assert!(a + 10 <= b);
    }

    #[test]
    fn claim_seq_survives_reopen() {
        let dir = crate::testsupport::tempdir("c1-claim");
        let path = dir.path().join("db.sqlite");
        let (id, first) = {
            let mut conn = open_db(&path).expect("open");
            let id = seed_task(&conn);
            ensure_runtime(&conn, id).expect("runtime");
            let start = allocate_claim_seq(&mut conn, id, 100).expect("alloc");
            (id, start)
        };
        // 模拟进程重启：重新打开同一个库。
        let mut conn = open_db(&path).expect("reopen");
        let second = allocate_claim_seq(&mut conn, id, 1).expect("alloc2");
        assert_eq!(first, 1);
        assert_eq!(
            second, 101,
            "重启后领取序号必须继续，不能依赖启动时刻的基数"
        );
    }

    #[test]
    fn coverage_roundtrips_intervals() {
        let conn = db();
        let id = seed_task(&conn);
        save_coverage(&conn, id, 0, "stored", &[0..100, 200..300], 3).expect("save");
        save_coverage(&conn, id, 0, "verified", &[0..50], 3).expect("save");
        assert_eq!(
            load_coverage(&conn, id, 0, "stored").expect("load"),
            vec![0..100, 200..300]
        );
        assert_eq!(load_coverage(&conn, id, 0, "verified").expect("load"), vec![0..50]);
        // 覆盖更新而不是追加。
        save_coverage(&conn, id, 0, "stored", &[0..10], 4).expect("overwrite");
        assert_eq!(load_coverage(&conn, id, 0, "stored").expect("load"), vec![0..10]);
    }

    #[test]
    fn decode_ignores_garbage_and_keeps_valid_pairs() {
        assert_eq!(decode_intervals(""), Vec::<Range<u64>>::new());
        assert_eq!(decode_intervals("bad,10:5,3:7"), vec![3..7]);
        assert_eq!(decode_intervals("0:10,"), vec![0..10]);
        assert_eq!(encode_intervals(&[0..0, 5..9]), "5:9");
    }

    fn command(id: &str, key: &str, epoch: u64) -> Command {
        Command {
            command_id: CommandId::new(id),
            decision_id: None,
            task_id: 1,
            run_epoch: epoch,
            target: "http".to_owned(),
            action: Action::Open,
            parameters: ActionParams::default(),
            idempotency_key: key.to_owned(),
            state: CommandStatus::Pending,
            result_event_id: None,
            error: None,
        }
    }

    #[test]
    fn commands_persist_and_unfinished_only_returns_current_epoch() {
        let conn = db();
        let id = seed_task(&conn);
        ensure_runtime(&conn, id).expect("runtime");
        let mut c = command("c1", "k1", 2);
        c.task_id = id;
        save_command(&conn, &c).expect("save");
        let mut done = command("c2", "k2", 2);
        done.task_id = id;
        save_command(&conn, &done).expect("save");
        assert!(finish_command(&conn, &CommandId::new("c2"), CommandStatus::Succeeded).expect("fin"));

        let unfinished = load_unfinished_commands(&conn, id, 2).expect("load");
        assert_eq!(unfinished.len(), 1);
        assert_eq!(unfinished[0].command_id.as_str(), "c1");
        // 旧轮次不可见。
        assert!(load_unfinished_commands(&conn, id, 1).expect("load").is_empty());
    }

    #[test]
    fn finish_command_does_not_overwrite_a_finished_receipt() {
        let conn = db();
        let id = seed_task(&conn);
        let mut c = command("c1", "k1", 1);
        c.task_id = id;
        save_command(&conn, &c).expect("save");
        assert!(finish_command(&conn, &CommandId::new("c1"), CommandStatus::Succeeded).expect("fin"));
        assert!(
            !finish_command(&conn, &CommandId::new("c1"), CommandStatus::Failed).expect("fin"),
            "已结束的命令不能被后到的失败覆盖"
        );
    }

    #[test]
    fn missing_runtime_is_an_error_not_a_silent_default() {
        let mut conn = db();
        let id = seed_task(&conn);
        // 没有 ensure_runtime：分配号段必须报错，而不是凭空造一条记录。
        assert!(allocate_claim_seq(&mut conn, id, 1).is_err());
        assert!(begin_run(&mut conn, id, None).is_err());
    }
}

#[cfg(test)]
mod c1_regression_tests {
    use super::*;
    use crate::download::model::{ActionParams, Span};
    use crate::open_db;
    use rusqlite::params;
    use std::path::Path;

    fn db() -> Connection {
        open_db(Path::new(":memory:")).expect("open db")
    }

    fn seed_task(conn: &Connection) -> i64 {
        conn.execute(
            "INSERT INTO downloads(url_orig, file_name, dir, created_at)
             VALUES ('https://example/a', 'a.bin', '/tmp', 0)",
            [],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    fn command(id: &str, key: &str, epoch: u64) -> Command {
        Command {
            command_id: CommandId::new(id),
            decision_id: None,
            task_id: 1,
            run_epoch: epoch,
            target: "http".to_owned(),
            action: Action::Open,
            parameters: ActionParams::default(),
            idempotency_key: key.to_owned(),
            state: CommandStatus::Pending,
            result_event_id: None,
            error: None,
        }
    }

    #[test]
    fn save_runtime_does_not_rewind_claim_seq() {
        // 用户反例：预留 [1,101) 后保存旧快照，下一次分配又回到 1。
        let mut conn = db();
        let id = seed_task(&conn);
        let stale = ensure_runtime(&conn, id).expect("runtime");
        assert_eq!(allocate_claim_seq(&mut conn, id, 100).expect("alloc"), 1);

        save_runtime(&conn, &stale).expect("save stale");

        assert_eq!(
            allocate_claim_seq(&mut conn, id, 1).expect("alloc2"),
            101,
            "旧检查点不能回退领取序号水位"
        );
    }

    #[test]
    fn save_runtime_does_not_rewind_epoch_or_mode() {
        let mut conn = db();
        let id = seed_task(&conn);
        let stale = ensure_runtime(&conn, id).expect("runtime");
        begin_run(&mut conn, id, Some(5)).expect("run");
        assert!(set_execution_mode(&conn, id, ExecutionMode::Unified).expect("mode"));

        save_runtime(&conn, &stale).expect("save stale");

        let rt = load_runtime(&conn, id).expect("load").expect("row");
        assert_eq!(rt.run_epoch, 1, "旧快照不能把轮次写回");
        assert_eq!(rt.content_generation, 5, "内容代次同样单调");
        assert_eq!(
            rt.execution_mode,
            ExecutionMode::Unified,
            "检查点不能隐式把模式改回 legacy"
        );
    }

    #[test]
    fn resaving_a_pending_snapshot_cannot_revive_a_finished_command() {
        // 用户反例：pending → succeeded → 再次保存原 pending，命令复活。
        let conn = db();
        let id = seed_task(&conn);
        let mut c = command("c1", "k1", 1);
        c.task_id = id;
        save_command(&conn, &c).expect("save");
        assert!(finish_command(&conn, &CommandId::new("c1"), CommandStatus::Succeeded).expect("fin"));

        save_command(&conn, &c).expect("save stale again");

        let state: String = conn
            .query_row(
                "SELECT state FROM download_commands WHERE command_id='c1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(state, "succeeded", "已完成的命令不能被重复保存复活");
        assert!(
            load_unfinished_commands(&conn, id, 1).expect("load").is_empty(),
            "不能重新进入回放集合"
        );
    }

    #[test]
    fn command_parameters_survive_roundtrip() {
        // 用户反例：parameters 固定写 NULL，恢复时拿不到完整载荷。
        let conn = db();
        let id = seed_task(&conn);
        let mut c = command("c1", "k1", 1);
        c.task_id = id;
        c.parameters = ActionParams {
            delay_ms: Some(1500),
            to_concurrency: Some(4),
            detail_code: Some("retry_after".into()),
            span: Some(Span::known(10, 20).expect("span")),
            ..ActionParams::default()
        };
        save_command(&conn, &c).expect("save");

        let loaded = load_unfinished_commands(&conn, id, 1).expect("load");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].parameters, c.parameters, "参数必须完整回放");
        assert_eq!(loaded[0].action, c.action);
        assert_eq!(loaded[0].idempotency_key, "k1");
    }

    #[test]
    fn save_plan_is_idempotent_per_revision_and_never_rewrites_ranges() {
        // 不变式：同一 plan_revision 下范围不可变。
        let mut conn = db();
        let id = seed_task(&conn);
        let rows = vec![
            SliceRow {
                slice_id: "t-0".into(),
                resource_id: "r".into(),
                span_start: 0,
                span_end_exclusive: Some(100),
                state: "pending".into(),
            },
            SliceRow {
                slice_id: "t-1".into(),
                resource_id: "r".into(),
                span_start: 100,
                span_end_exclusive: Some(200),
                state: "pending".into(),
            },
        ];
        assert!(save_plan(&mut conn, id, 0, 1, &rows).expect("save"));

        // 同版本再来一次：一行都不改。
        let tampered = vec![SliceRow {
            slice_id: "t-0".into(),
            resource_id: "r".into(),
            span_start: 0,
            span_end_exclusive: Some(999),
            state: "done".into(),
        }];
        assert!(
            !save_plan(&mut conn, id, 0, 1, &tampered).expect("save again"),
            "同版本必须幂等跳过"
        );
        let loaded = load_plan(&conn, id, 1).expect("load");
        assert_eq!(loaded, rows, "范围与状态都必须保持原样");

        // 新版本才允许重建，且旧版本必须整批作废。
        assert!(save_plan(&mut conn, id, 0, 2, &tampered).expect("v2"));
        assert_eq!(load_plan(&conn, id, 2).expect("load v2").len(), 1);
        assert!(
            load_plan(&conn, id, 1).expect("load v1").is_empty(),
            "重建必须清掉旧版本，否则旧范围会继续参与投影"
        );
    }

    #[test]
    fn load_plan_refuses_negative_spans_instead_of_clamping() {
        // P3-a-01：把负数 clamp 成 0 会让 `plan.rs` 的「坏行照原样编码、
        // 让比较失败」变成空话——投影看起来对，实际范围已经被悄悄抹平。
        let conn = db();
        let id = seed_task(&conn);
        conn.execute(
            "INSERT INTO download_slices(
                slice_id, resource_id, task_id, plan_revision, span_start, span_end_exclusive)
             VALUES('bad', 'r', ?1, 1, -5, 10)",
            params![id],
        )
        .unwrap();
        let err = load_plan(&conn, id, 1).expect_err("负数跨度必须读失败");
        assert!(
            matches!(err, rusqlite::Error::IntegralValueOutOfRange(..)),
            "必须是明确的范围错误，而不是折成 0：{err:?}"
        );
    }

    #[test]
    fn open_ended_slice_roundtrips_as_none() {
        let mut conn = db();
        let id = seed_task(&conn);
        let rows = vec![SliceRow {
            slice_id: "t-0".into(),
            resource_id: "r".into(),
            span_start: 0,
            span_end_exclusive: None,
            state: "pending".into(),
        }];
        save_plan(&mut conn, id, 0, 1, &rows).expect("save");
        let loaded = load_plan(&conn, id, 1).expect("load");
        assert_eq!(
            loaded[0].span_end_exclusive, None,
            "未知总长必须保持开区间，不能变成某个具体字节数"
        );
    }

    #[test]
    fn deleting_a_task_cascades_task_scoped_coverage() {
        // 用户反例：删任务后 download_coverage 仍有残留（v2 直接挂在任务上）。
        let conn = db();
        let id = seed_task(&conn);
        save_coverage(&conn, id, 0, "stored", &[0..10], 1).expect("save");
        conn.execute("DELETE FROM downloads WHERE id = ?1", params![id])
            .unwrap();
        let n: i64 = conn
            .query_row("SELECT count(*) FROM download_coverage", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0, "删任务必须清掉覆盖记录");
    }

    #[test]
    fn replanning_slices_does_not_wipe_coverage() {
        // (c) 的核心：覆盖是**事实**，按任务存；重分段是**计划**，不能把事实清零。
        //
        // 旧结构把 overlap 挂在 slice_id 上并级联删除，于是“改并发数重切段”
        // 会连带把已完成字节一起丢掉——这是选 (c) 的直接原因。
        let mut conn = db();
        let id = seed_task(&conn);
        let row = |sid: &str, s: u64, e: u64| SliceRow {
            slice_id: sid.into(),
            resource_id: "r".into(),
            span_start: s,
            span_end_exclusive: Some(e),
            state: "pending".into(),
        };
        save_plan(&mut conn, id, 0, 1, &[row("t-0", 0, 100), row("t-1", 100, 200)])
            .expect("plan v1");
        save_coverage(&conn, id, 0, "stored", &[0..150], 7).expect("save coverage");

        // 重分段：新版本会删掉旧切片（`slice_id` 是全局主键）。
        save_plan(&mut conn, id, 0, 2, &[row("t-0", 0, 200)]).expect("plan v2");

        assert!(
            load_plan(&conn, id, 1).expect("v1").is_empty(),
            "旧版本的切片应当作废"
        );
        assert_eq!(
            load_coverage(&conn, id, 0, "stored").expect("coverage"),
            vec![0..150],
            "重分段不得让已完成字节消失"
        );
    }

    #[test]
    fn coverage_is_partitioned_by_content_generation() {
        // 内容代次变了就是另一份内容：旧代次的覆盖不能冒充新代次。
        let conn = db();
        let id = seed_task(&conn);
        save_coverage(&conn, id, 0, "stored", &[0..10], 1).expect("gen0");
        assert_eq!(
            load_coverage(&conn, id, 1, "stored").expect("gen1"),
            Vec::<Range<u64>>::new(),
            "新代次必须从零开始"
        );
        assert_eq!(load_coverage(&conn, id, 0, "stored").expect("gen0"), vec![0..10]);
    }
}

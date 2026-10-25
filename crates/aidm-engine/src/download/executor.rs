//! 命令执行器。
//!
//! 只做「幂等接纳 → 执行 → 回执」闭环，**不接管 HTTP 传输**（那是 C3）。
//! 因此动作分派是显式的：认识的控制动作给出确定性回执；不认识的动作必须回
//! `not_implemented_in_c2` 并落库登记，不允许“假装成功”。
//!
//! 与本模块配套的写入许可在 [`WriteGate`]（`aidm-core::download::control`）：
//! 真实写盘前先 `check` 拿票据，撤销必须等到在途写入归零。

use aidm_core::download::control::{AcceptOutcome, CommandLedger, WriteGate};
use aidm_core::download::model::{Action, Command, CommandId, CommandStatus};
use aidm_core::download::plan;
use aidm_core::download::store;
use rusqlite::{Connection, OptionalExtension};
use std::sync::{Arc, Mutex};

/// 一条命令的执行回执。
///
/// `code` 是稳定诊断码：测试和事件都断言它，而不是断言人类可读文案。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub command_id: CommandId,
    pub action: Action,
    pub outcome: CommandStatus,
    pub code: &'static str,
}

/// 命令执行器。
///
/// 内部用 `Mutex<CommandLedger>` 串行化接纳：同一时刻只有一条命令能进入执行，
/// 因此“检查未完成 → 执行 → 写回执”之间不会被另一条同键命令插入。
pub struct Executor {
    db: Arc<Mutex<Connection>>,
    gate: Arc<WriteGate>,
    ledger: Mutex<CommandLedger>,
}

impl Executor {
    pub fn new(db: Arc<Mutex<Connection>>, gate: Arc<WriteGate>) -> Self {
        Self {
            db,
            gate,
            ledger: Mutex::new(CommandLedger::new()),
        }
    }

    pub fn gate(&self) -> &Arc<WriteGate> {
        &self.gate
    }

    /// 切换运行轮次：未完成命令全部作废，**不回放给新轮次**。
    ///
    /// 返回被作废的命令数。数据库侧同步标为 `cancelled`，避免重启后又被读出来。
    pub fn begin_epoch(&self, run_epoch: u64) -> usize {
        let (cancelled, ids) = {
            let mut l = self.ledger.lock().unwrap_or_else(|e| e.into_inner());
            let before: Vec<CommandId> = l.pending().map(|r| r.command.command_id.clone()).collect();
            let n = l.begin_epoch(run_epoch);
            (n, before)
        };
        if !ids.is_empty() {
            let conn = self.db.lock().unwrap_or_else(|e| e.into_inner());
            for id in ids {
                let _ = store::finish_command(&conn, &id, CommandStatus::Cancelled);
            }
        }
        cancelled
    }

    /// 幂等接纳一条命令。
    ///
    /// 只在 `Accepted` 时落库：`Merged`/`Duplicate` 不产生新的副作用，
    /// 也不改已有行（改状态只能走 [`Executor::execute_pending`] 的回执）。
    pub fn accept(&self, command: Command) -> AcceptOutcome {
        let outcome = {
            let mut l = self.ledger.lock().unwrap_or_else(|e| e.into_inner());
            l.accept(command.clone())
        };
        if matches!(outcome, AcceptOutcome::Accepted) {
            let conn = self.db.lock().unwrap_or_else(|e| e.into_inner());
            let _ = store::save_command(&conn, &command);
        }
        outcome
    }

    /// 恢复本轮未完成的命令（重启后调用）。
    ///
    /// 按 `created_at_ms` 顺序回放；已结束的命令不会被读到（`store` 只查
    /// `pending`/`running`）。
    pub fn recover(&self, task_id: i64, run_epoch: u64) -> usize {
        let loaded = {
            let conn = self.db.lock().unwrap_or_else(|e| e.into_inner());
            store::load_unfinished_commands(&conn, task_id, run_epoch).unwrap_or_default()
        };
        let mut n = 0;
        let mut l = self.ledger.lock().unwrap_or_else(|e| e.into_inner());
        for command in loaded {
            if matches!(l.accept(command), AcceptOutcome::Accepted) {
                n += 1;
            }
        }
        n
    }

    /// 执行当前所有未完成命令，返回回执。
    ///
    /// 逐条串行：执行前先 `mark_running`，执行后只写一次回执
    /// （`CommandLedger::complete` 拒绝第二次结束）。
    pub fn execute_pending(&self) -> Vec<Receipt> {
        let pending: Vec<Command> = {
            let l = self.ledger.lock().unwrap_or_else(|e| e.into_inner());
            l.pending().map(|r| r.command.clone()).collect()
        };

        let mut receipts = Vec::with_capacity(pending.len());
        for command in pending {
            // 可能在取快照后已被同一批的前一条合并掉。
            if !self
                .ledger
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .mark_running(&command.command_id)
            {
                continue;
            }
            let (outcome, code) = self.run_action(&command);
            {
                let mut l = self.ledger.lock().unwrap_or_else(|e| e.into_inner());
                // 失败不覆盖已写入的回执：`complete` 只写一次。
                let _ = l.complete(&command.command_id, outcome, None, None);
            }
            {
                let conn = self.db.lock().unwrap_or_else(|e| e.into_inner());
                let _ = store::finish_command(&conn, &command.command_id, outcome);
            }
            receipts.push(Receipt {
                command_id: command.command_id,
                action: command.action,
                outcome,
                code,
            });
        }
        receipts
    }

    /// 动作分派。
    ///
    /// C2 只实现「不产生文件副作用」的控制动作。数据面动作（探测、传输、校验、
    /// 提交）要等 C3 接管，这里必须如实回 `not_implemented_in_c2`。
    fn run_action(&self, command: &Command) -> (CommandStatus, &'static str) {
        match command.action {
            // 影子/等待：本来就是“记录意图”，执行即完成。
            Action::ObserveOnly => (CommandStatus::Succeeded, "observe_only"),
            Action::Wait => (CommandStatus::Succeeded, "wait_recorded"),
            // 退避：真实等待由调度方 sleep，这里只确认“已记账”，
            // 否则回执语义与实际的 429/Retry-After 时序会脱节。
            Action::Backoff => (CommandStatus::Succeeded, "backoff_recorded"),
            // 撤销类动作：能走到执行器说明分配已经结束，账本层面只需记账。
            Action::Cancel | Action::ReleaseAssignment => {
                (CommandStatus::Succeeded, "released")
            }
            // C3-a：切片方案决策权落表。**只写表**，不改任何执行路径。
            Action::PlanSlices => self.apply_plan_slices(command),
            // 数据面动作（探测/建连/传输/校验/提交/换源/结束……）归 C3-c。
            //
            // 记成 `Deferred` 而不是 `Failed`：policy 每个 tick 都会产出这类决策，
            // 记失败就会刷出一串假失败，把真正的失败埋掉。`Deferred` 是终态、
            // 不回放，等 C3-c 接管后它们才会变成真命令。
            _ => (CommandStatus::Deferred, "deferred_to_c3c"),
        }
    }

    /// `Action::PlanSlices` 的唯一实现：把命令里的方案写进 `download_slices`。
    ///
    /// 三条边界：
    /// - **只写表**：不建连、不写文件、不改 worker 的内存分段；
    /// - **方案相同不递增版本**：与 worker 影子写表同一语义，避免「每 tick 都 bump」；
    /// - **坏方案直接失败**：空方案、`end <= start` 一律回 `plan_invalid_*`，
    ///   不猜也不修。
    fn apply_plan_slices(&self, command: &Command) -> (CommandStatus, &'static str) {
        let Some(slices) = command.parameters.plan.as_ref() else {
            return (CommandStatus::Failed, "plan_missing");
        };
        if slices.is_empty() {
            return (CommandStatus::Failed, "plan_empty");
        }
        // 没有这条上限，一条命令就能让 worker spawn 出任意多个线程。
        if slices.len() > plan::MAX_PLAN_SLICES {
            return (CommandStatus::Failed, "plan_too_many");
        }
        if slices
            .iter()
            .any(|s| s.end_exclusive.is_some_and(|e| e <= s.start))
        {
            return (CommandStatus::Failed, "plan_invalid_span");
        }

        let mut conn = self.db.lock().unwrap_or_else(|e| e.into_inner());

        // 前置约束（裁决 1b）：任务必须**空闲且无进度**才能改方案。
        //
        // 为什么不做事后重建：`segments` 是执行事实（带 `done_bytes` 与 `part_path`），
        // 而 `download_slices` 只有范围、`state` 恒为 pending。拿表去重建 segments
        // 等于把已完成字节清零。所以在源头拒绝，比事后修补便宜也安全。
        let status: Option<String> = conn
            .query_row(
                "SELECT status FROM downloads WHERE id = ?1",
                [command.task_id],
                |r| r.get(0),
            )
            .optional()
            .unwrap_or(None);
        let Some(status) = status else {
            return (CommandStatus::Failed, "plan_no_task");
        };
        if !matches!(status.as_str(), "queued" | "error") {
            return (CommandStatus::Failed, "plan_task_busy");
        }
        let done: i64 = conn
            .query_row(
                "SELECT COALESCE(SUM(done_bytes), 0) FROM segments WHERE download_id = ?1",
                [command.task_id],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if done > 0 {
            return (CommandStatus::Failed, "plan_has_progress");
        }

        let _ = store::ensure_runtime(&conn, command.task_id);
        let runtime = store::load_runtime(&conn, command.task_id).ok().flatten();
        let generation = runtime.as_ref().map(|r| r.content_generation).unwrap_or(0);
        let current = runtime.as_ref().map(|r| r.plan_revision).unwrap_or(0);

        let rows: Vec<store::SliceRow> = slices
            .iter()
            .enumerate()
            .map(|(i, s)| store::SliceRow {
                slice_id: format!("task-{}-seg-{i}", command.task_id),
                resource_id: format!("task-{}", command.task_id),
                span_start: s.start,
                span_end_exclusive: s.end_exclusive,
                state: "pending".to_owned(),
            })
            .collect();

        let projected_new = plan::project_rows(
            &rows
                .iter()
                .map(|r| (r.span_start, r.span_end_exclusive))
                .collect::<Vec<_>>(),
        );
        let projected_old = plan::project_rows(
            &store::load_plan(&conn, command.task_id, current)
                .unwrap_or_default()
                .iter()
                .map(|r| (r.span_start, r.span_end_exclusive))
                .collect::<Vec<_>>(),
        );
        if projected_new == projected_old {
            return (CommandStatus::Succeeded, "plan_unchanged");
        }

        let Ok(rev) = store::bump_plan_revision(&mut conn, command.task_id) else {
            return (CommandStatus::Failed, "plan_no_runtime");
        };
        match store::save_plan(&mut conn, command.task_id, generation, rev, &rows) {
            Ok(true) => (CommandStatus::Succeeded, "plan_written"),
            Ok(false) => (CommandStatus::Succeeded, "plan_exists"),
            Err(_) => (CommandStatus::Failed, "plan_write_failed"),
        }
    }

    /// 未完成命令数（诊断/验收用）。
    pub fn pending_len(&self) -> usize {
        self.ledger
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pending()
            .count()
    }

    pub fn finished_len(&self) -> usize {
        self.ledger
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .finished_len()
    }

    pub fn current_epoch(&self) -> u64 {
        self.ledger
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .current_epoch()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aidm_core::download::model::{ActionParams, CommandId, Span};
    use aidm_core::open_db;
    use std::path::Path;

    /// 建库 + 一条任务 + 运行记录。**同一个库**可以喂给多个执行器，
    /// 用来模拟“进程重启后从库恢复”。
    fn db_fixture() -> (Arc<Mutex<Connection>>, i64) {
        let conn = Arc::new(Mutex::new(open_db(Path::new(":memory:")).expect("db")));
        let task_id = {
            let c = conn.lock().unwrap();
            c.execute(
                "INSERT INTO downloads(url_orig, file_name, dir, created_at)
                 VALUES('https://example/a', 'a.bin', '/tmp', 0)",
                [],
            )
            .unwrap();
            c.last_insert_rowid()
        };
        {
            let mut c = conn.lock().unwrap();
            store::ensure_runtime(&c, task_id).expect("runtime");
            store::begin_run(&mut c, task_id, Some(1)).expect("begin");
        }
        (conn, task_id)
    }

    fn fixture_from(conn: Arc<Mutex<Connection>>) -> Executor {
        let gate = Arc::new(WriteGate::new());
        gate.begin_epoch(1, 1);
        let exec = Executor::new(conn, gate);
        exec.begin_epoch(1);
        exec
    }

    fn fixture() -> (Executor, Arc<Mutex<Connection>>, i64) {
        let (conn, task_id) = db_fixture();
        (fixture_from(conn.clone()), conn, task_id)
    }

    fn command(id: &str, key: &str, epoch: u64, task_id: i64, action: Action) -> Command {
        Command {
            command_id: CommandId::new(id),
            decision_id: None,
            task_id,
            run_epoch: epoch,
            target: "http".to_owned(),
            action,
            parameters: ActionParams::default(),
            idempotency_key: key.to_owned(),
            state: CommandStatus::Pending,
            result_event_id: None,
            error: None,
        }
    }

    #[test]
    fn duplicate_delivery_does_not_execute_twice() {
        // C2 退出条件之一：重复命令不重复副作用。
        let (exec, _conn, id) = fixture();
        assert_eq!(
            exec.accept(command("c1", "k1", 1, id, Action::ObserveOnly)),
            AcceptOutcome::Accepted
        );
        assert_eq!(
            exec.accept(command("c1", "k1", 1, id, Action::ObserveOnly)),
            AcceptOutcome::Merged(CommandId::new("c1")),
            "未完成时重复投递不得新建命令"
        );
        let receipts = exec.execute_pending();
        assert_eq!(receipts.len(), 1, "只能执行一次");

        assert_eq!(
            exec.accept(command("c1", "k1", 1, id, Action::ObserveOnly)),
            AcceptOutcome::Duplicate(CommandId::new("c1")),
            "已完成后重复投递只补回执"
        );
        assert!(exec.execute_pending().is_empty(), "回放集合里不能再出现它");
    }

    #[test]
    fn same_idempotency_key_merges_before_execution() {
        let (exec, _conn, id) = fixture();
        exec.accept(command("c1", "same", 1, id, Action::ObserveOnly));
        assert_eq!(
            exec.accept(command("c2", "same", 1, id, Action::ObserveOnly)),
            AcceptOutcome::Merged(CommandId::new("c1"))
        );
        let receipts = exec.execute_pending();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].command_id.as_str(), "c1");
    }

    #[test]
    fn receipts_are_persisted_and_survive_recovery() {
        let (exec, conn, id) = fixture();
        exec.accept(command("c1", "k1", 1, id, Action::ObserveOnly));
        exec.execute_pending();
        let state: String = conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT state FROM download_commands WHERE command_id='c1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(state, "succeeded");
        // 已结束的命令不进回放集合。
        assert_eq!(exec.recover(id, 1), 0);
    }

    #[test]
    fn unimplemented_data_plane_actions_are_deferred_not_failed() {
        // 数据面归 C3-c。记 `Deferred` 而不是 `Failed`：policy 每个 tick 都会产出
        // 这类决策，记失败就会刷出一串假失败，把真正的失败埋掉。
        let (exec, _conn, id) = fixture();
        exec.accept(command("c1", "k1", 1, id, Action::Transfer));
        let receipts = exec.execute_pending();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].outcome, CommandStatus::Deferred);
        assert_eq!(receipts[0].code, "deferred_to_c3c");
        // 终态：不回放。
        assert_eq!(exec.pending_len(), 0);
        assert_eq!(exec.recover(id, 1), 0);
    }

    #[test]
    fn begin_epoch_cancels_and_persists_unfinished_commands() {
        let (exec, conn, id) = fixture();
        exec.accept(command("c1", "k1", 1, id, Action::Transfer));
        exec.accept(command("c2", "k2", 1, id, Action::ObserveOnly));
        exec.execute_pending(); // c1 失败、c2 成功
        exec.accept(command("c3", "k3", 1, id, Action::ObserveOnly));
        assert_eq!(exec.begin_epoch(2), 1, "只作废未完成的那条");

        assert_eq!(exec.pending_len(), 0);
        assert_eq!(exec.current_epoch(), 2);
        let state: String = conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT state FROM download_commands WHERE command_id='c3'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(state, "cancelled", "作废必须落库，重启后不能复活");
    }

    #[test]
    fn recovery_replays_only_unfinished_commands() {
        let (exec, conn, id) = fixture();
        exec.accept(command("c1", "k1", 1, id, Action::ObserveOnly));
        exec.accept(command("c2", "k2", 1, id, Action::ObserveOnly));
        // 只执行一条，模拟“写库了但没执行完就重启”。
        {
            let mut l = exec.ledger.lock().unwrap();
            l.mark_running(&CommandId::new("c2"));
        }
        drop(exec);

        // 新执行器：同一个库，模拟进程重启。
        let exec2 = fixture_from(conn);
        let n = exec2.recover(id, 1);
        assert_eq!(n, 2, "pending 与 running 都属于未完成");
        assert_eq!(exec2.execute_pending().len(), 2);
    }
}

#[cfg(test)]
mod plan_slices_tests {
    use super::*;
    use aidm_core::download::model::{ActionParams, AssignmentId, CommandId, SliceId, Span};
    use aidm_core::download::plan;
    use aidm_core::download::store;
    use aidm_core::open_db;
    use std::path::Path;
    use std::sync::{Arc, Mutex};

    fn fixture() -> (Executor, Arc<Mutex<Connection>>, i64) {
        let conn = Arc::new(Mutex::new(open_db(Path::new(":memory:")).expect("db")));
        let id = {
            let c = conn.lock().unwrap();
            c.execute(
                "INSERT INTO downloads(url_orig, file_name, dir, created_at)
                 VALUES('https://example/a', 'a.bin', '/tmp', 0)",
                [],
            )
            .unwrap();
            c.last_insert_rowid()
        };
        let gate = Arc::new(WriteGate::new());
        gate.begin_epoch(0, 0);
        let exec = Executor::new(conn.clone(), gate);
        exec.begin_epoch(0);
        (exec, conn, id)
    }

    fn plan_command(id: &str, task_id: i64, spans: Vec<Span>) -> Command {
        Command {
            command_id: CommandId::new(id),
            decision_id: None,
            task_id,
            run_epoch: 0,
            target: "task".to_owned(),
            action: Action::PlanSlices,
            parameters: ActionParams {
                plan: Some(spans),
                ..ActionParams::default()
            },
            idempotency_key: format!("plan:{task_id}:{id}"),
            state: CommandStatus::Pending,
            result_event_id: None,
            error: None,
        }
    }

    fn spans_of(pairs: &[(u64, u64)]) -> Vec<Span> {
        pairs
            .iter()
            .map(|(s, e)| Span::known(*s, *e).expect("span"))
            .collect()
    }

    #[test]
    fn plan_slices_writes_the_table_and_mirrors_runtime_version() {
        let (exec, conn, id) = fixture();
        exec.accept(plan_command("p1", id, spans_of(&[(0, 100), (100, 200)])));
        let receipts = exec.execute_pending();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].code, "plan_written");

        let db = conn.lock().unwrap();
        let rt = store::load_runtime(&db, id).unwrap().expect("runtime");
        assert_eq!(rt.plan_revision, 1, "首次写入版本应为 1");
        let rows = store::load_plan(&db, id, rt.plan_revision).unwrap();
        let projected = plan::project_rows(
            &rows
                .iter()
                .map(|r| (r.span_start, r.span_end_exclusive))
                .collect::<Vec<_>>(),
        );
        assert_eq!(projected, "plan-v1|0..100|100..200");
    }

    #[test]
    fn plan_slices_from_the_legacy_planner_projects_identically() {
        // C3-a 的等价性在执行面复现：把 `plan_segments` 的输出交给 `PlanSlices`，
        // 落表后的投影必须与 `project_legacy` 逐字节相同。
        // 这条成立，把决策权从 worker 搬到协调器才是“没改语义”。
        let (exec, conn, id) = fixture();
        let total = 2u64 * 1024 * 1024;
        let conns = 4u32;
        let spans: Vec<Span> = aidm_core::segment::plan_segments(total, conns)
            .into_iter()
            .map(|s| Span::known(s.start, s.end + 1).expect("span"))
            .collect();
        exec.accept(plan_command("p1", id, spans));
        assert_eq!(exec.execute_pending()[0].code, "plan_written");

        let db = conn.lock().unwrap();
        let rt = store::load_runtime(&db, id).unwrap().expect("runtime");
        let rows = store::load_plan(&db, id, rt.plan_revision).unwrap();
        let got = plan::project_rows(
            &rows
                .iter()
                .map(|r| (r.span_start, r.span_end_exclusive))
                .collect::<Vec<_>>(),
        );
        assert_eq!(got, plan::project_legacy(total, conns));
    }

    #[test]
    fn plan_slices_is_idempotent_for_the_same_plan() {
        // 同一方案重复投递：不递增版本、不重写表。
        let (exec, conn, id) = fixture();
        exec.accept(plan_command("p1", id, spans_of(&[(0, 100), (100, 200)])));
        exec.execute_pending();
        exec.accept(plan_command("p2", id, spans_of(&[(0, 100), (100, 200)])));
        let receipts = exec.execute_pending();
        assert_eq!(receipts[0].code, "plan_unchanged");

        let db = conn.lock().unwrap();
        let rt = store::load_runtime(&db, id).unwrap().expect("runtime");
        assert_eq!(rt.plan_revision, 1, "方案没变不得递增版本");
    }

    #[test]
    fn plan_slices_replans_and_keeps_coverage() {
        // 裁决 (c) 的执行面：重规划换版本、旧切片作废，但已完成字节仍在。
        let (exec, conn, id) = fixture();
        exec.accept(plan_command("p1", id, spans_of(&[(0, 100), (100, 200)])));
        exec.execute_pending();
        {
            let db = conn.lock().unwrap();
            store::save_coverage(&db, id, 0, "stored", &[0..150], 5).expect("coverage");
        }

        exec.accept(plan_command("p2", id, spans_of(&[(0, 200)])));
        let receipts = exec.execute_pending();
        assert_eq!(receipts[0].code, "plan_written");

        let db = conn.lock().unwrap();
        let rt = store::load_runtime(&db, id).unwrap().expect("runtime");
        assert_eq!(rt.plan_revision, 2);
        assert!(store::load_plan(&db, id, 1).unwrap().is_empty(), "旧版本切片作废");
        assert_eq!(
            store::load_coverage(&db, id, 0, "stored").unwrap(),
            vec![0u64..150],
            "重规划不得让已完成字节消失"
        );
    }

    #[test]
    fn plan_slices_refuses_more_than_the_configured_maximum() {
        // 没有上限，一条命令就能让 worker spawn 出任意多个线程。
        let (exec, _conn, id) = fixture();
        let many: Vec<Span> = (0..=(aidm_core::download::plan::MAX_PLAN_SLICES as u64))
            .map(|i| Span::known(i, i + 1).expect("span"))
            .collect();
        exec.accept(plan_command("p1", id, many));
        let receipts = exec.execute_pending();
        assert_eq!(receipts[0].code, "plan_too_many");
        assert_eq!(receipts[0].outcome, CommandStatus::Failed);
    }

    #[test]
    fn plan_slices_refuses_when_the_task_is_busy_or_has_progress() {
        // 裁决 1b：任务忙 → 拒绝。事后重建会把 done_bytes 清零，所以在源头拦。
        let (exec, conn, id) = fixture();
        conn.lock()
            .unwrap()
            .execute("UPDATE downloads SET status = 'downloading' WHERE id = ?1", [id])
            .unwrap();
        exec.accept(plan_command("p1", id, spans_of(&[(0, 100)])));
        assert_eq!(exec.execute_pending()[0].code, "plan_task_busy");
    }

    #[test]
    fn plan_slices_refuses_when_the_task_already_has_bytes() {
        // 状态回到 queued 也不算空闲：segments 里有已完成字节就不能改方案。
        let (exec, conn, id) = fixture();
        conn.lock()
            .unwrap()
            .execute(
                "INSERT INTO segments(
                    download_id, idx, pos_start, pos_end, done_bytes, part_path, status)
                 VALUES(?1, 0, 0, 100, 40, '/tmp/p0', 'running')",
                [id],
            )
            .unwrap();
        exec.accept(plan_command("p1", id, spans_of(&[(0, 100)])));
        let receipts = exec.execute_pending();
        assert_eq!(receipts[0].code, "plan_has_progress");
        assert!(
            store::load_runtime(&conn.lock().unwrap(), id)
                .unwrap()
                .is_none()
                || store::load_plan(&conn.lock().unwrap(), id, 0).unwrap().is_empty(),
            "被拒的命令不得写表"
        );
    }

    #[test]
    fn plan_slices_refuses_missing_or_malformed_plans() {
        let (exec, conn, id) = fixture();
        // 缺方案
        let mut missing = plan_command("p1", id, Vec::new());
        missing.parameters.plan = None;
        exec.accept(missing);
        // 空方案
        exec.accept(plan_command("p2", id, Vec::new()));
        // 倒挂区间（end <= start）：`Span::known` 会拒绝，所以直接构造坏值，
        // 模拟“表里/外部输入里真的出现了坏行”。
        exec.accept(plan_command(
            "p3",
            id,
            vec![Span {
                start: 100,
                end_exclusive: Some(100),
            }],
        ));
        let receipts = exec.execute_pending();
        let codes: Vec<&str> = receipts.iter().map(|r| r.code).collect();
        assert_eq!(codes, vec!["plan_missing", "plan_empty", "plan_invalid_span"]);
        assert!(
            receipts.iter().all(|r| r.outcome == CommandStatus::Failed),
            "坏方案必须失败，不能猜也不能修"
        );
        let db = conn.lock().unwrap();
        // 坏命令在 `ensure_runtime` 之前就被拒，所以可能连运行记录都没有；
        // 两种情况下版本都必须是 0。
        let rev = store::load_runtime(&db, id)
            .unwrap()
            .map(|r| r.plan_revision)
            .unwrap_or(0);
        assert_eq!(rev, 0, "失败不得推进版本");
        assert!(
            store::load_plan(&db, id, 0).unwrap().is_empty(),
            "失败不得写入任何切片"
        );
    }
}

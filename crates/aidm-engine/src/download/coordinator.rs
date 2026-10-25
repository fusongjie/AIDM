//! 唯一协调器。
//!
//! 职责边界（文档 12.2.6 C2）：
//! - **串行接纳事实**：所有事实从这里进，`Reducer` / `policy` 保持纯逻辑；
//! - **命令化**：决策在这里翻译成 `Command`，交给 [`Executor`] 幂等接纳；
//! - **暂停即静止**：暂停必须撤销写入许可并等在途写入归零，才允许对外宣布已停止；
//! - **不接管数据面**：探测、传输、校验、提交仍是 legacy 执行器的活（C3）。
//!
//! 之所以要“唯一”：事实与命令如果允许两条线程各自推进，`state_revision` 的单调性
//! 和幂等键的唯一性就都失去意义。这里用一把 `Mutex` 把「应用事实 → 生成决策 →
//! 接纳命令」做成一个原子段。

use super::executor::{Executor, Receipt};
use aidm_core::download::control::{AcceptOutcome, QuiesceTimeout};
use aidm_core::download::model::{Action, Command, CommandId, CommandStatus, Decision, FactEvent, Span};
use aidm_core::download::plan;
use aidm_core::download::policy::{self, PolicyConfig};
use aidm_core::download::reducer::{ApplyOutcome, Reducer};
use std::sync::Mutex;
use std::time::Duration;

/// 一批事实的处理结果。
#[derive(Debug, Default)]
pub struct SubmitReport {
    /// 被接纳（状态确实变化）的事实数。
    pub applied: usize,
    /// 被拒收的事实及其原因码（用于 `download.stale_result`）。
    pub rejected: Vec<&'static str>,
    /// 本轮生成的决策。
    pub decisions: Vec<Decision>,
    /// 真正新建的命令（合并/重复不计入）。
    pub accepted_commands: Vec<CommandId>,
}

/// 影子期的一次任务快照。
///
/// 这是「快照对齐」而不是事实流：`reducer` 的可见字段被直接覆盖成当前值，
/// 然后跑一次决策。允许这么做的前提是它**只读不写库**——`PlanSlices` 落表
/// 走的是 `Executor`，与这里的覆盖是两件事。真正的 `FactEvent` 流属 C3-c。
#[derive(Debug, Clone)]
pub struct TaskSnapshot {
    pub status: aidm_core::model::Status,
    /// 任务总长；未知为 `None`（此时不产 `PlanSlices`）。
    pub total: Option<u64>,
    /// 有效落盘字节（快照期用 `live.done_bytes` 的近似）。
    pub stored_bytes: u64,
    /// 连接预算，与 worker 的 `task_conns_for` 同源。
    pub connection_budget: u32,
    /// 表里是否已有覆盖全文件的方案。
    pub plan_ready: bool,
    /// 剩余重试预算（`download_runtime.retry_budget`）。
    ///
    /// `R-UDL-21/22` 的分界：> 0 才允许再试，= 0 必须终止。
    pub retry_budget: u32,
    /// 当前错误（`downloads.error_code` + `http_status` 的归一化）。
    ///
    /// `R-UDL-20/21/22` 的输入。影子期由 manager 从行里构造，
    /// C3-c 之后会改成由执行器上报的 `OperationFailed` 事实。
    pub error: Option<aidm_core::download::model::UnifiedError>,
}

/// 一次 tick 的结果。
#[derive(Debug)]
pub struct TickReport {
    pub decisions: Vec<Decision>,
    pub accepted_commands: Vec<CommandId>,
    pub receipts: Vec<Receipt>,
}

/// 暂停结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PauseReport {
    /// 被撤销的写入许可数。
    pub revoked_leases: usize,
    /// 被作废的未完成命令数。
    pub cancelled_commands: usize,
    /// 撤销时仍在途、已被等待到退出的写入数（> 0 表示确实等过）。
    pub waited_in_flight: usize,
}

/// 唯一协调器。
pub struct Coordinator {
    /// 串行段：应用事实 + 生成决策 + 接纳命令。
    inner: Mutex<Reducer>,
    executor: Executor,
    config: PolicyConfig,
    policy_revision: u64,
}

impl Coordinator {
    pub fn new(reducer: Reducer, executor: Executor, config: PolicyConfig) -> Self {
        Self {
            inner: Mutex::new(reducer),
            executor,
            config,
            policy_revision: 1,
        }
    }

    pub fn executor(&self) -> &Executor {
        &self.executor
    }

    /// 任务当前状态版本（供投影/诊断）。
    pub fn state_revision(&self) -> u64 {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .task()
            .identity
            .state_revision
    }

    pub fn run_epoch(&self) -> u64 {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).task().identity.run_epoch
    }

    /// 只读访问归约器（投影用）。**不提供可变访问**：状态只能经事实推进。
    pub fn read<R>(&self, f: impl FnOnce(&Reducer) -> R) -> R {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        f(&g)
    }

    /// 串行接纳一批事实，并在最后统一跑一次政策。
    ///
    /// 事实按到达顺序应用；任何被拒收的事实都不改变状态，只登记原因码。
    /// 政策每批只跑一次（而不是每条事实一次），避免同一批内重复生成命令。
    pub fn submit(&self, facts: &[FactEvent]) -> SubmitReport {
        let mut report = SubmitReport::default();
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        for fact in facts {
            match guard.apply(fact) {
                ApplyOutcome::Applied => report.applied += 1,
                ApplyOutcome::Unchanged => {}
                ApplyOutcome::Rejected(reason) => report.rejected.push(reason.code()),
            }
        }

        // 政策只看到“事实应用之后”的状态。
        let input = policy::PolicyInput::from_reducer(&guard, self.config);
        let decisions = policy::evaluate(&input);
        drop(guard);

        for mut decision in decisions {
            decision.policy_revision = self.policy_revision;
            for command in self.materialize(&decision) {
                // 记的是**这条命令自己**的 id：之前用 `decision.command_ids.last()`
                // 而那个字段从没被回填，于是 `accepted_commands` 恒为空。
                let command_id = command.command_id.clone();
                match self.executor.accept(command) {
                    AcceptOutcome::Accepted => {
                        decision.command_ids.push(command_id.clone());
                        report.accepted_commands.push(command_id);
                    }
                    // 合并/重复都不算新命令：副作用不会发生两次。
                    AcceptOutcome::Merged(_) | AcceptOutcome::Duplicate(_) => {}
                    AcceptOutcome::StaleEpoch { .. } => {}
                }
            }
            report.decisions.push(decision);
        }
        report
    }

    /// 影子期入口：用快照对齐可见状态，然后跑一次决策 + 命令接纳。
    ///
    /// 不新增线程、不新增回调、不改 worker 的上报路径——manager 的 tick
    /// 每拍调一次，单任务单次。
    pub fn observe(&self, snapshot: TaskSnapshot) -> SubmitReport {
        {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if guard.task().status != snapshot.status {
                let _ = guard.request_status(snapshot.status);
            }
            let task = guard.task_mut();
            task.progress.required_bytes = snapshot.total;
            task.progress.stored_unique_bytes = snapshot.stored_bytes;
            task.budget.connection_budget = snapshot.connection_budget;
            task.plan_status = if snapshot.plan_ready {
                aidm_core::download::model::PlanStatus::Ready
            } else {
                aidm_core::download::model::PlanStatus::Unplanned
            };
            task.budget.retry_budget = snapshot.retry_budget;
            task.current_error = snapshot.error;
        }
        self.submit(&[])
    }

    /// 跑一轮执行：把未完成命令交给执行器。
    pub fn tick(&self) -> TickReport {
        let decisions = {
            let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            let input = policy::PolicyInput::from_reducer(&guard, self.config);
            policy::evaluate(&input)
        };
        let mut accepted = Vec::new();
        for decision in &decisions {
            for command in self.materialize(decision) {
                let command_id = command.command_id.clone();
                if matches!(self.executor.accept(command), AcceptOutcome::Accepted) {
                    accepted.push(command_id);
                }
            }
        }
        TickReport {
            decisions,
            accepted_commands: accepted,
            receipts: self.executor.execute_pending(),
        }
    }

    /// 暂停：撤销写入许可 → 等在途写入归零 → 作废未完成命令。
    ///
    /// 顺序是契约：先断写入，再断命令。反过来会让“已作废的命令”在退出前
    /// 又写了一段，暂停就不干净。
    pub fn pause(&self, timeout: Duration) -> Result<PauseReport, QuiesceTimeout> {
        let before = self.executor.gate().in_flight();
        let revoked = self.executor.gate().revoke_all_quiescent(timeout)?;
        let cancelled = self.executor.begin_epoch(self.run_epoch());
        Ok(PauseReport {
            revoked_leases: revoked,
            cancelled_commands: cancelled,
            waited_in_flight: before,
        })
    }

    /// 决策 → 命令。同一决策在 `submit`/`tick` 里重复出现时靠幂等键合并。
    fn materialize(&self, decision: &Decision) -> Vec<Command> {
        // `PlanSlices` 的 id 必须带**方案指纹**。
        //
        // 不带的话「同一任务 + 同一轮次 + 同一条规则」派生出的 id 恒等：
        // 方案变了，`CommandLedger::accept` 会先按 `command_id` 命中旧命令
        // 直接返回 `Merged`（去重顺序是 by_id 优先、by_key 其后），
        // 新方案永远发不出去。所以指纹要同时进 `command_id` 和幂等键——
        // 只改其中一个都不行。
        let fingerprint = if decision.action == Action::PlanSlices {
            decision
                .parameters
                .plan
                .as_ref()
                .map(|p| format!(":{}", plan::fingerprint(&to_normalized(p))))
                .unwrap_or_default()
        } else {
            String::new()
        };
        let idempotency_key = format!(
            "{}:{}:{}:{}{}",
            decision.task_id,
            decision.run_epoch,
            decision.rule_id,
            decision.scope.as_str(),
            fingerprint
        );
        let command_id = CommandId::new(format!(
            "cmd-{}-{}-{}{}",
            decision.task_id,
            decision.rule_id.replace('.', "_"),
            decision.scope.as_str(),
            fingerprint
        ));
        vec![Command {
            command_id,
            decision_id: Some(decision.decision_id.clone()),
            task_id: decision.task_id,
            run_epoch: decision.run_epoch,
            target: decision.scope.as_str().to_owned(),
            action: decision.action,
            parameters: decision.parameters.clone(),
            idempotency_key,
            state: CommandStatus::Pending,
            result_event_id: None,
            error: None,
        }]
    }
}


/// `Span` → 投影用的规范化二元组。
fn to_normalized(spans: &[Span]) -> Vec<plan::NormalizedSpan> {
    spans.iter().map(|s| (s.start, s.end_exclusive)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aidm_core::capability::Transport;
    use aidm_core::download::control::WriteGate;
    use aidm_core::download::model::{
        EventId, FactEvent, FactKind, FactPayload, IdentityContext, TaskState, UnifiedError,
    };
    use aidm_core::download::store;
    use aidm_core::model::Status;
    use aidm_core::open_db;
    use std::path::Path;
    use std::sync::Arc;

    fn identity(epoch: u64, generation: u64) -> IdentityContext {
        let mut id = IdentityContext::for_task(7, "engine-test");
        id.run_epoch = epoch;
        id.content_generation = generation;
        id
    }

    fn reducer(status: Status) -> Reducer {
        let mut task = TaskState::new(identity(1, 0), Transport::Http);
        task.status = status;
        Reducer::new(task)
    }

    fn fact(kind: FactKind, payload: FactPayload) -> FactEvent {
        FactEvent {
            event_id: EventId::generate(),
            identity: identity(1, 0),
            producer_id: "test".into(),
            producer_seq: 1,
            observed_at_ms: 1_000,
            kind,
            payload,
            cause_event_id: None,
        }
    }

    /// 一条"什么都没变"的事实：用来验证串行接纳本身不产生副作用。
    fn noop_fact() -> FactEvent {
        fact(
            FactKind::CoverageChanged,
            FactPayload::Coverage {
                slice_id: aidm_core::download::model::SliceId::new("s-missing"),
                stored: aidm_core::download::coverage::CoverageSet::new(),
                verified: aidm_core::download::coverage::CoverageSet::new(),
            },
        )
    }

    fn coordinator(status: Status) -> (Coordinator, i64) {
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
        }
        let gate = Arc::new(WriteGate::new());
        gate.begin_epoch(1, 0);
        let exec = Executor::new(conn, gate);
        exec.begin_epoch(1);
        let cfg = PolicyConfig::default();
        (Coordinator::new(reducer(status), exec, cfg), task_id)
    }

    fn snapshot(total: u64, conns: u32, plan_ready: bool) -> TaskSnapshot {
        TaskSnapshot {
            status: Status::Queued,
            total: Some(total),
            stored_bytes: 0,
            connection_budget: conns,
            plan_ready,
            retry_budget: 3,
            error: None,
        }
    }

    fn plan_commands(report: &SubmitReport) -> Vec<&CommandId> {
        report
            .decisions
            .iter()
            .filter(|d| d.action == Action::PlanSlices)
            .flat_map(|d| d.command_ids.iter())
            .collect()
    }

    #[test]
    fn repeated_observe_does_not_produce_duplicate_plan_commands() {
        // 验收 ①：同一 tick 重复 submit 不产生重复命令。
        let (coord, _id) = coordinator(Status::Queued);
        let first = coord.observe(snapshot(2 * 1024 * 1024, 4, false));
        assert_eq!(plan_commands(&first).len(), 1, "首次观测必须产出一条 PlanSlices");
        let second = coord.observe(snapshot(2 * 1024 * 1024, 4, false));
        assert!(
            plan_commands(&second).is_empty(),
            "方案没变时不得再建 PlanSlices（指纹与幂等键生效）"
        );
    }

    #[test]
    fn a_changed_plan_produces_a_new_command() {
        // 验收 ②：方案变了必须能产生**新**命令。
        //
        // 这条是反例证明：如果 `command_id` 不带方案指纹，`CommandLedger::accept`
        // 会先按 by_id 命中旧命令直接 `Merged`，新方案永远发不出去。
        let (coord, _id) = coordinator(Status::Queued);
        let first = coord.observe(snapshot(2 * 1024 * 1024, 4, false));
        let first_ids: Vec<CommandId> = plan_commands(&first).into_iter().cloned().collect();
        assert_eq!(first_ids.len(), 1);

        // 连接预算变化 → 段数变化 → 方案指纹变化。
        let changed = coord.observe(snapshot(2 * 1024 * 1024, 2, false));
        let changed_ids: Vec<CommandId> = plan_commands(&changed).into_iter().cloned().collect();
        assert_eq!(
            changed_ids.len(),
            1,
            "方案变了却拿不到新命令：指纹没进 command_id"
        );
        assert_ne!(
            first_ids[0], changed_ids[0],
            "新旧命令的 id 必须不同"
        );
    }

    #[test]
    fn a_task_that_already_has_a_plan_emits_nothing() {
        let (coord, _id) = coordinator(Status::Queued);
        let report = coord.observe(snapshot(2 * 1024 * 1024, 4, true));
        assert!(
            plan_commands(&report).is_empty(),
            "已有方案时不该再造 PlanSlices（其它动作如 Wait 可以有）"
        );
    }

    #[test]
    fn unknown_subject_facts_are_rejected_not_guessed() {
        // 文档 2 节：未知就是未知。没有对应切片的覆盖事实必须被拒收，
        // 协调器不能顺手造一个切片出来。
        let (coord, _id) = coordinator(Status::Downloading);
        let report = coord.submit(&[noop_fact()]);
        assert_eq!(report.applied, 0, "没有对应切片时状态不得变化");
        assert_eq!(
            coord.read(|r| r.slices().count()),
            0,
            "未知切片的覆盖事实不能被顺手造成一个新切片"
        );
    }

    #[test]
    fn paused_task_produces_no_execution_decisions() {
        // R-UDL-01：用户暂停不得被自动重试复活。
        let (coord, _id) = coordinator(Status::Paused);
        let report = coord.submit(&[]);
        assert!(
            report.decisions.is_empty(),
            "暂停状态不得产生执行决策：{:?}",
            report.decisions
        );
        assert!(report.accepted_commands.is_empty());
        assert_eq!(coord.executor().pending_len(), 0);
    }

    #[test]
    fn repeated_ticks_do_not_multiply_commands() {
        // 串行协调器的核心保证：同一原因形成的重复决策不能无限生成相同命令。
        let (coord, _id) = coordinator(Status::Queued);
        let first = coord.tick();
        let second = coord.tick();
        assert_eq!(
            second.accepted_commands.len(),
            0,
            "第二轮不得再建同名命令（第一轮已建 {} 条）",
            first.accepted_commands.len()
        );
    }

    #[test]
    fn pause_revokes_writes_and_cancels_commands() {
        use aidm_core::download::model::{Action, ActionParams, CommandId, CommandStatus};

        let (coord, id) = coordinator(Status::Downloading);
        let gate = coord.executor().gate().clone();
        let _lease = gate.with_book(|b| {
            b.issue(
                aidm_core::download::model::AssignmentId::new("a1"),
                aidm_core::download::model::SliceId::new("s1"),
                aidm_core::download::model::Span::known(0, 100).expect("span"),
            )
        });
        coord.executor().accept(Command {
            command_id: CommandId::new("c1"),
            decision_id: None,
            task_id: id,
            run_epoch: 1,
            target: "http".to_owned(),
            action: Action::Transfer,
            parameters: ActionParams::default(),
            idempotency_key: "k1".to_owned(),
            state: CommandStatus::Pending,
            result_event_id: None,
            error: None,
        });
        assert_eq!(gate.active_leases(), 1);

        let report = coord.pause(Duration::from_secs(2)).expect("pause");
        assert_eq!(report.revoked_leases, 1, "暂停必须撤销写入许可");
        assert_eq!(report.cancelled_commands, 1, "暂停必须作废未完成命令");
        assert_eq!(gate.active_leases(), 0);
        assert_eq!(gate.in_flight(), 0, "暂停返回时不得有在途写入");
        assert_eq!(coord.executor().pending_len(), 0);
    }

    #[test]
    fn tick_runs_pending_commands_and_reports_receipts() {
        use aidm_core::download::model::{Action, ActionParams, CommandId, CommandStatus};

        let (coord, id) = coordinator(Status::Downloading);
        coord.executor().accept(Command {
            command_id: CommandId::new("c1"),
            decision_id: None,
            task_id: id,
            run_epoch: 1,
            target: "http".to_owned(),
            action: Action::ObserveOnly,
            parameters: ActionParams::default(),
            idempotency_key: "k1".to_owned(),
            state: CommandStatus::Pending,
            result_event_id: None,
            error: None,
        });
        let report = coord.tick();
        assert!(report
            .receipts
            .iter()
            .any(|r| r.command_id.as_str() == "c1" && r.code == "observe_only"));
        assert_eq!(coord.executor().pending_len(), 0);
    }
}

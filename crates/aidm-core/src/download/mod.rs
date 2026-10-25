//! 统一下载业务模型（契约与纯逻辑）。
//!
//! 依据 `docs/unified-download-state-review.md` 第四节至第七节。本模块只做
//! **纯业务计算**：不打开连接、不读写文件、不碰数据库、不启动线程。所有
//! IO 事实由引擎层通过 [`model::FactEvent`] 提交，归约与决策在这里完成。
//!
//! 四个子模块的职责边界：
//!
//! - [`model`]：实体、编号、状态、能力、等待、错误、进度、事实/决策/命令。
//! - [`coverage`]：左闭右开区间并集、失效、原生块映射与投影。
//! - [`reducer`]：合法状态转换、乱序与重复去重、切片聚合成任务状态。
//! - [`policy`]：硬规则层与证据评估层，只产出 [`model::Decision`]，不执行。
//!
//! # 硬性不变量（本模块所有代码必须维持）
//!
//! 1. 范围一律左闭右开 `start..end_exclusive`；已知非空范围必须
//!    `start < end_exclusive`。`end_exclusive` 为 `None` 只表示"总长未知、
//!    只能顺序读取"。
//! 2. 未知大小与 0 字节严格分开：前者 `size_bytes == None`，后者
//!    `size_bytes == Some(0)`。0 个切片是合法结果，不等于错误。
//! 3. 能力是三态（支持 / 不支持 / 未知），不得用 `bool` 冒充未知。
//! 4. `verified_unique_bytes <= stored_unique_bytes <= wire_bytes` 恒成立。
//! 5. 旧轮次（`run_epoch` 更低）的事实不得改变新轮次状态。
//! 6. 协议块的完成与验证只由协议适配器确认，归约层不自行推断。
//!
//! 暂不启用任何执行路径：本模块产出的 [`model::Decision`] 目前仅供
//! 影子解释器记录，不生成会建连、重试、换源或写下载文件的命令。

pub mod control;
pub mod coverage;
pub mod model;
pub mod plan;
pub mod policy;
pub mod reducer;
pub mod store;

pub use control::{
    resolve_ownership, AcceptOutcome, CommandLedger, CommandRecord, ExecutionMode, LeaseBook,
    Ownership, WriteDecision, WriteLease,
};
pub use coverage::CoverageSet;
pub use store::DownloadRuntime;
pub use model::{
    Action, Activity, AssignmentState, AssignmentStatus, Availability, Budget, CapabilitySet,
    Command, CommandStatus, Confidence, ConnectionRole, ConnectionState, ConnectionStatus, Counts,
    Decision, EventEnvelope, EventId, FactEvent, FactKind, FactPayload, IdentityContext,
    PlanStatus, Progress, ResourceState, SliceState, SliceStatus, SourceState, Span, TaskState,
    TriState, UnifiedError, WaitInfo, WaitReason,
};

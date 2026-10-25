//! 统一下载引擎侧模块（只读观测与快照投影）。
//!
//! 边界（文档 12.2）：
//! - 现有 HTTP / eD2k 执行器输出统一事实与**只读**快照。
//! - UI、MCP 与诊断读同一投影，旧字段继续兼容。
//! - 影子解释器**只记录建议，绝不发命令**。
//!
//! 本模块不接管执行路径：`worker` 仍是唯一执行者。这里只做
//! `aidm-core::download` 内部实体到 `aidm-ipc::UnifiedDownloadView` 的**唯一**转换，
//! 以及从现有执行器读取观测事实的适配。

pub mod coordinator;
pub mod executor;
pub mod observe;
pub mod snapshot;

pub use snapshot::{to_snapshot_response, to_summary_view, SnapshotError, SnapshotSource};

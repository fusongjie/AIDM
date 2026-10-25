//! 找源（source discovery）的**纯逻辑模型**：任务视图、候选源、证据分级、去重分组、判源预算。
//!
//! 规格唯一权威是 `docs/source-discovery.md`（§3 统一模型、§4.1 任务标准化器、
//! §4.2 判断器、§4.6 去重与分组器）。本模块只放**纯函数与数据结构**：
//!
//! - **不做任何 IO**：不联网、不读写磁盘、不碰数据库；
//! - **不新增依赖**：URL 拆分手写（抄 `alt.rs` / `mirrors.rs` 的写法，见
//!   `docs/guides/02-rust-constraints.md` R-RS-10，不为一个判重键引入 `url` crate）；
//! - **不新增任务状态 / 失败码**：级别（`L0`–`L4`）只是内存里的分类，不落
//!   `TaskView.error_code`。
//!
//! 四层身份（§3.1）在本模块里的对应关系：
//!
//! ```text
//! TaskProfile   → task.rs        任务视图（DownloadRow 的只读派生，不落库）
//! ContentGroup  → group.rs       同一份内容的分组（含分组键）
//! CandidateSource → candidate.rs 候选源（带证据与出处）
//! ResolvedTarget  → candidate.rs 解析后的可下载文件地址
//! ```
//!
//! 后续批次的对接面：`crates/aidm-engine/src/source/*`（finder / adapter / resolve）
//! 产出 [`CandidateSource`]，交给 [`group`] 分组后由调度器消费；判断器 [`decide`]
//! 只回答"这一轮要不要找源、预算是多少"，不执行搜索。

pub mod candidate;
pub mod evidence;
pub mod group;
pub mod task;
pub mod verify;

pub use candidate::{
    CandidateSource, Platform, ResolvedTarget, SourceCapabilities, SourceKind, SourceQuery,
};
pub use evidence::{
    DeclaredHash, DigestStrength, EvidenceLevel, EvidenceOrigin, HashAlgo, IdentityEvidence,
};
pub use group::{dedup, group, group_key, normalize_url, ContentGroup, GroupKey};
pub use task::{TaskPolicy, TaskProfile};
pub use verify::{majority, sample_ranges, Majority, SampleRange, SampleSet};

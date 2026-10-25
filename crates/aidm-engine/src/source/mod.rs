//! 引擎侧「找源」实现（`docs/source-discovery.md`）。
//!
//! 本批次只有 P0.2 的 `SourceProvider` 抽象（§4.9、§5.1–§5.4）：
//! DTO 在 `aidm-core::source`，trait 与 HTTP 实现在 [`provider`]。
//!
//! **不接线 worker / manager**：新增本模块不改变任何现有下载行为。

pub mod adapter;
pub mod adapters;
pub mod cache;
pub mod finder;
pub mod provider;
pub mod resolve;
pub mod sample;

pub use adapter::{AdapterError, PlatformAdapter, SearchBudget};
pub use adapters::{ArchiveOrgAdapter, GitHubAdapter, WaybackAdapter};
pub use cache::{cache_key, NegativeCache, Quota, TtlCache};
pub use finder::{FindOutcome, Finder, FinderConfig};
pub use provider::{
    Health, HttpProvider, ProbeResult, ProviderError, ProviderId, RangeChunk, ReadRequest,
    SourceProvider, VersionToken,
};
pub use resolve::Resolver;
pub use sample::{fetch_samples, SampleFetch};

//! 平台适配器实现（`docs/source-discovery.md` §4.4）。
//!
//! 一个平台一个文件；`mod.rs` 只做模块声明与再导出，不放业务逻辑。

pub mod archive_org;
pub mod github;
pub mod wayback;

pub use archive_org::ArchiveOrgAdapter;
pub use github::GitHubAdapter;
pub use wayback::WaybackAdapter;

//! archive.org 适配器（`docs/source-discovery.md` §4.4）。
//!
//! 复用 `crate::archive_source` 的查询/解析（eD2k 的 HTTP 备用源已经在用同一套），
//! 只把它包成统一的 [`PlatformAdapter`]：
//!
//! - 返回的 `HttpSource` 已经是**文件地址**（`/download/<id>/<name>`），所以 `kind = File`；
//! - 平台元数据里的长度是可信的**声明值**，但 archive.org 不提供整文件强摘要，
//!   因此证据级别最多 `L1 SizeOnly`，不能授权跨源分段（§3.2）；
//! - 没有命中返回 `Ok(空)`（finder 写短负缓存）；只有"所有搜索都失败"才返回 `Err`，
//!   避免一次网络抖动把查询锁死 10 分钟。

use std::sync::Arc;
use std::time::{Duration, Instant};

use aidm_core::source::{
    CandidateSource, IdentityEvidence, Platform, ResolvedTarget, SourceKind, SourceQuery,
};

use crate::archive_source::HttpSource;
use crate::http_util::HttpRuntime;
use crate::source::adapter::{AdapterError, PlatformAdapter, SearchBudget};

/// archive.org 适配器。`HttpRuntime` 负责按代理设置选 Agent（与下载路径一致）。
pub struct ArchiveOrgAdapter {
    http: Arc<HttpRuntime>,
}

impl ArchiveOrgAdapter {
    pub fn new(http: Arc<HttpRuntime>) -> Self {
        ArchiveOrgAdapter { http }
    }
}

/// `HttpSource` → 统一候选。单独抽出来便于离线单测（不碰网络）。
pub(crate) fn to_candidate(src: &HttpSource) -> CandidateSource {
    let evidence = match src.size {
        Some(size) => IdentityEvidence::SizeOnly { size },
        None => IdentityEvidence::Unverified,
    };
    CandidateSource {
        url: src.url.clone(),
        platform: Platform::ArchiveOrg,
        kind: SourceKind::File,
        size: src.size,
        version: None,
        // 容器类型由验证器按文件名/内容探测，平台元数据不声明。
        container: None,
        evidence,
        auth_ref: None,
        // 只记平台与条目 label；不记查询串（§8.2）。
        origin: Some(format!("archive_org:{}", src.label)),
        expires_at: None,
    }
}

impl PlatformAdapter for ArchiveOrgAdapter {
    fn platform(&self) -> Platform {
        Platform::ArchiveOrg
    }

    fn search(
        &self,
        query: &SourceQuery,
        budget: SearchBudget,
    ) -> Result<Vec<CandidateSource>, AdapterError> {
        let now = crate::source_registry::now_ms();
        if budget.expired(now) {
            return Err(AdapterError::Timeout);
        }
        let remaining_ms = budget.remaining_ms(now).clamp(1, 60_000) as u64;
        let deadline = Instant::now() + Duration::from_millis(remaining_ms);
        match crate::archive_source::discover_checked_until(
            &self.http,
            &query.file_name,
            query.size,
            Some(deadline),
        ) {
            Ok(items) => Ok(items
                .iter()
                .take(budget.max_results)
                .map(to_candidate)
                .collect()),
            Err(e) => Err(AdapterError::network(e)),
        }
    }

    fn resolve(&self, candidate: &CandidateSource) -> Result<ResolvedTarget, AdapterError> {
        match candidate.kind {
            SourceKind::File => Ok(ResolvedTarget {
                url: candidate.url.clone(),
                final_url: candidate.url.clone(),
                size: candidate.size,
                content_type: None,
                file_name: None,
                expires_at: candidate.expires_at,
            }),
            // search 只会产出 File；Page/Record 交给将来的通用解析器。
            _ => Err(AdapterError::Unsupported),
        }
    }

    fn refresh(&self, target: &ResolvedTarget) -> Result<ResolvedTarget, AdapterError> {
        // archive.org 的 `/download/` 地址是稳定的，没有签名过期问题。
        Ok(target.clone())
    }

    fn quota_per_min(&self) -> u32 {
        6
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aidm_core::source::EvidenceLevel;

    fn src(size: Option<u64>) -> HttpSource {
        HttpSource {
            url: "https://archive.org/download/id/f.iso".into(),
            label: "id".into(),
            size,
            provider: "archive.org",
        }
    }

    #[test]
    fn known_size_is_l1_and_carries_label_origin() {
        let c = to_candidate(&src(Some(1024)));
        assert_eq!(c.platform, Platform::ArchiveOrg);
        assert_eq!(c.kind, SourceKind::File);
        assert_eq!(c.size, Some(1024));
        assert_eq!(c.evidence.level(), EvidenceLevel::L1SizeOnly);
        assert!(!c.evidence.allows_multi_source(), "L1 不得授权跨源");
        assert_eq!(c.origin.as_deref(), Some("archive_org:id"));
        assert!(c.auth_ref.is_none());
    }

    #[test]
    fn unknown_size_is_l0() {
        let c = to_candidate(&src(None));
        assert_eq!(c.evidence.level(), EvidenceLevel::L0Unverified);
        assert_eq!(c.size, None);
    }

    #[test]
    fn resolve_file_passthrough_and_reject_page() {
        let adapter = ArchiveOrgAdapter {
            http: HttpRuntime::from_db(&std::sync::Mutex::new(
                rusqlite::Connection::open_in_memory().unwrap(),
            )),
        };
        let c = to_candidate(&src(Some(10)));
        let t = adapter.resolve(&c).unwrap();
        assert_eq!(t.url, c.url);
        assert_eq!(t.final_url, c.url);
        assert_eq!(t.size, Some(10));

        let mut page = c;
        page.kind = SourceKind::Page;
        assert_eq!(adapter.resolve(&page), Err(AdapterError::Unsupported));
    }

    #[test]
    fn refresh_is_stable_for_archive_urls() {
        let adapter = ArchiveOrgAdapter {
            http: HttpRuntime::from_db(&std::sync::Mutex::new(
                rusqlite::Connection::open_in_memory().unwrap(),
            )),
        };
        let target = ResolvedTarget {
            url: "https://archive.org/download/id/f.iso".into(),
            final_url: "https://archive.org/download/id/f.iso".into(),
            size: Some(1),
            content_type: None,
            file_name: Some("f.iso".into()),
            expires_at: None,
        };
        assert_eq!(adapter.refresh(&target).unwrap(), target);
    }
}

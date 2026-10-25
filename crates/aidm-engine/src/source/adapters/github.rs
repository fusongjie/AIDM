//! GitHub Releases 适配器（`docs/source-discovery.md` §4.4）。
//!
//! # 边界
//!
//! GitHub 没有"按任意文件名全局搜索可下载文件"的匿名 API；本适配器只在任务本身
//! 带**仓库线索**（`orig_url` 是 `github.com/<owner>/<repo>`）时启用，否则返回
//! `Unsupported`，不伪造结果。
//!
//! # 证据
//!
//! 新版 Release asset 带 `digest: "sha256:..."`，来源是发布方 API → 可作 `L4`
//! 强摘要；没有 digest 时只能按长度给 `L1`。`zipball_url`/`tarball_url` 是源码包，
//! 不是用户要的文件，一律忽略。
//!
//! # 配额
//!
//! 未认证 GitHub API 是 **60 次/小时/IP**，所以适配器把每分钟配额压到 1。

use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use aidm_core::source::{
    CandidateSource, DeclaredHash, EvidenceOrigin, HashAlgo, IdentityEvidence, Platform,
    ResolvedTarget, SourceKind, SourceQuery,
};

use crate::http_util::HttpRuntime;
use crate::source::adapter::{AdapterError, PlatformAdapter, SearchBudget};

const DEFAULT_BASE: &str = "https://api.github.com";
const MAX_BODY: u64 = 2 * 1024 * 1024;
const MAX_TIMEOUT_MS: i64 = 6_000;
const MAX_RELEASES: usize = 20;

pub struct GitHubAdapter {
    http: Arc<HttpRuntime>,
    base: String,
}

impl GitHubAdapter {
    pub fn new(http: Arc<HttpRuntime>) -> Self {
        let base = std::env::var("AIDM_SOURCE_GITHUB_BASE")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_BASE.to_string());
        Self::with_base(http, base)
    }

    pub fn with_base(http: Arc<HttpRuntime>, base: impl Into<String>) -> Self {
        GitHubAdapter {
            http,
            base: base.into().trim_end_matches('/').to_string(),
        }
    }

    pub fn base(&self) -> &str {
        &self.base
    }
}

/// 从 `https://github.com/<owner>/<repo>[/...]` 取 `(owner, repo)`。
/// 只接受 github.com 根域；`gist.github.com`、企业域名一律不认。
pub(crate) fn repo_from_url(raw: &str) -> Option<(String, String)> {
    let url = url::Url::parse(raw).ok()?;
    if url.host_str()? != "github.com" && url.host_str()? != "www.github.com" {
        return None;
    }
    let mut segs = url.path_segments()?;
    let owner = segs.next()?.trim();
    let repo = segs.next()?.trim().trim_end_matches(".git");
    if owner.is_empty() || repo.is_empty() {
        return None;
    }
    Some((owner.to_string(), repo.to_string()))
}

fn releases_url(base: &str, owner: &str, repo: &str, limit: usize) -> Result<String, AdapterError> {
    let mut url = url::Url::parse(&format!(
        "{}/repos/{owner}/{repo}/releases",
        base.trim_end_matches('/')
    ))
    .map_err(|_| AdapterError::Config("invalid github api base".into()))?;
    url.query_pairs_mut()
        .append_pair("per_page", &limit.clamp(1, 100).to_string());
    Ok(url.into())
}

fn digest_to_hash(digest: &str) -> Option<DeclaredHash> {
    let (algo, hex) = digest.split_once(':')?;
    let algo = match algo.to_ascii_lowercase().as_str() {
        "sha256" => HashAlgo::Sha256,
        "sha512" => HashAlgo::Sha512,
        "sha1" => HashAlgo::Sha1,
        "md5" => HashAlgo::Md5,
        _ => return None,
    };
    let hex = hex.trim();
    if hex.is_empty() {
        return None;
    }
    Some(DeclaredHash {
        algo,
        hex: hex.to_string(),
        origin: EvidenceOrigin::PublisherApi,
    })
}

/// 解析 releases JSON。只保留**文件名精确相等**的 asset；不做模糊匹配。
pub(crate) fn parse_releases(
    body: &str,
    owner: &str,
    repo: &str,
    file_name: &str,
    limit: usize,
) -> Result<Vec<CandidateSource>, AdapterError> {
    let value: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| AdapterError::Malformed(format!("github json: {e}")))?;
    let releases = value
        .as_array()
        .ok_or_else(|| AdapterError::Malformed("github: top-level is not an array".into()))?;
    let mut out = Vec::new();
    for release in releases.iter().take(MAX_RELEASES) {
        let tag = release
            .get("tag_name")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let Some(assets) = release.get("assets").and_then(|v| v.as_array()) else {
            continue;
        };
        for asset in assets {
            let name = asset.get("name").and_then(|v| v.as_str()).unwrap_or("");
            if name != file_name {
                continue;
            }
            let Some(url) = asset
                .get("browser_download_url")
                .and_then(|v| v.as_str())
                .filter(|v| v.starts_with("https://"))
            else {
                continue;
            };
            let size = asset
                .get("size")
                .and_then(|v| v.as_u64())
                .filter(|v| *v > 0);
            let declared = asset
                .get("digest")
                .and_then(|v| v.as_str())
                .and_then(digest_to_hash);
            let evidence = match (declared, size) {
                (Some(h), _) => match h.strength() {
                    aidm_core::source::DigestStrength::Strong => IdentityEvidence::StrongDigest(h),
                    aidm_core::source::DigestStrength::Weak => IdentityEvidence::WeakDigest(h),
                },
                (None, Some(size)) => IdentityEvidence::SizeOnly { size },
                (None, None) => IdentityEvidence::Unverified,
            };
            out.push(CandidateSource {
                url: url.to_string(),
                platform: Platform::GitHub,
                kind: SourceKind::File,
                size,
                version: if tag.is_empty() {
                    None
                } else {
                    Some(tag.to_string())
                },
                container: None,
                evidence,
                auth_ref: None,
                origin: Some(format!("github:{owner}/{repo}@{tag}")),
                expires_at: None,
            });
            if out.len() >= limit.max(1) {
                return Ok(out);
            }
        }
    }
    Ok(out)
}

impl PlatformAdapter for GitHubAdapter {
    fn platform(&self) -> Platform {
        Platform::GitHub
    }

    fn search(
        &self,
        query: &SourceQuery,
        budget: SearchBudget,
    ) -> Result<Vec<CandidateSource>, AdapterError> {
        let Some(orig) = query.orig_url.as_deref() else {
            return Err(AdapterError::Unsupported);
        };
        let Some((owner, repo)) = repo_from_url(orig) else {
            return Err(AdapterError::Unsupported);
        };
        let now = crate::source_registry::now_ms();
        if budget.expired(now) {
            return Err(AdapterError::Timeout);
        }
        let limit = budget.max_results.min(MAX_RELEASES);
        let url = releases_url(&self.base, &owner, &repo, limit)?;
        let timeout_ms = budget.remaining_ms(now).clamp(1, MAX_TIMEOUT_MS);
        let resp = self
            .http
            .agent_for(&url)
            .get(&url)
            .set("Accept", "application/vnd.github+json")
            .set("X-GitHub-Api-Version", "2022-11-28")
            .timeout(Duration::from_millis(timeout_ms as u64))
            .call()
            .map_err(|e| match e {
                ureq::Error::Status(code, _) => AdapterError::from_status(code),
                ureq::Error::Transport(t) => AdapterError::network(t.to_string()),
            })?;
        let status = resp.status();
        if !(200..300).contains(&status) {
            return Err(AdapterError::from_status(status));
        }
        let mut raw = Vec::new();
        resp.into_reader()
            .take(MAX_BODY + 1)
            .read_to_end(&mut raw)
            .map_err(|e| AdapterError::network(format!("github read: {e}")))?;
        if raw.len() as u64 > MAX_BODY {
            return Err(AdapterError::Malformed("github body too large".into()));
        }
        let body = String::from_utf8(raw)
            .map_err(|_| AdapterError::Malformed("github body is not utf-8".into()))?;
        parse_releases(&body, &owner, &repo, &query.file_name, limit)
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
            _ => Err(AdapterError::Unsupported),
        }
    }

    fn refresh(&self, target: &ResolvedTarget) -> Result<ResolvedTarget, AdapterError> {
        Ok(target.clone())
    }

    fn quota_per_min(&self) -> u32 {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aidm_core::source::EvidenceLevel;

    const RELEASES: &str = r#"[
      {
        "tag_name": "v1.2.3",
        "assets": [
          {"name":"f.iso","size":1024,"browser_download_url":"https://github.com/o/r/releases/download/v1.2.3/f.iso","digest":"sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
          {"name":"source.zip","size":10,"browser_download_url":"https://github.com/o/r/archive/refs/tags/v1.2.3.zip"}
        ]
      },
      {
        "tag_name": "v1.2.2",
        "assets": [
          {"name":"f.iso","size":1024,"browser_download_url":"https://github.com/o/r/releases/download/v1.2.2/f.iso"}
        ]
      }
    ]"#;

    fn dummy_http() -> Arc<HttpRuntime> {
        HttpRuntime::from_db(&std::sync::Mutex::new(
            rusqlite::Connection::open_in_memory().unwrap(),
        ))
    }

    #[test]
    fn parse_matches_exact_asset_and_keeps_digest() {
        let got = parse_releases(RELEASES, "o", "r", "f.iso", 10).unwrap();
        assert_eq!(got.len(), 2, "两个 release 都有同名 asset");
        assert_eq!(got[0].platform, Platform::GitHub);
        assert_eq!(got[0].version.as_deref(), Some("v1.2.3"));
        assert_eq!(got[0].size, Some(1024));
        assert_eq!(got[0].evidence.level(), EvidenceLevel::L4StrongDigest);
        assert!(got[0].evidence.allows_multi_source());
        assert_eq!(got[0].origin.as_deref(), Some("github:o/r@v1.2.3"));
        assert_eq!(got[1].evidence.level(), EvidenceLevel::L1SizeOnly);
        assert!(!got[1].evidence.allows_multi_source());
    }

    #[test]
    fn parse_ignores_non_matching_assets() {
        let got = parse_releases(RELEASES, "o", "r", "other.iso", 10).unwrap();
        assert!(got.is_empty());
    }

    #[test]
    fn parse_respects_limit() {
        let got = parse_releases(RELEASES, "o", "r", "f.iso", 1).unwrap();
        assert_eq!(got.len(), 1);
    }

    #[test]
    fn parse_rejects_malformed() {
        assert!(matches!(
            parse_releases("{}", "o", "r", "f.iso", 10),
            Err(AdapterError::Malformed(_))
        ));
    }

    #[test]
    fn repo_from_url_accepts_github_and_strips_git_suffix() {
        assert_eq!(
            repo_from_url("https://github.com/o/r"),
            Some(("o".into(), "r".into()))
        );
        assert_eq!(
            repo_from_url("https://github.com/o/r.git/tree/main"),
            Some(("o".into(), "r".into()))
        );
        assert_eq!(repo_from_url("https://gitlab.com/o/r"), None);
        assert_eq!(repo_from_url("https://github.com/o"), None);
        assert_eq!(repo_from_url("not a url"), None);
    }

    #[test]
    fn search_requires_repo_clue() {
        let a = GitHubAdapter::with_base(dummy_http(), DEFAULT_BASE);
        let q = SourceQuery {
            file_name: "f.iso".into(),
            size: Some(10),
            hashes: Vec::new(),
            version: None,
            orig_url: Some("https://example.com/f.iso".into()),
            source_hint: None,
        };
        let budget = SearchBudget::new(1_000, 1_000, 5);
        assert_eq!(a.search(&q, budget), Err(AdapterError::Unsupported));
    }

    #[test]
    fn digest_to_hash_maps_algorithms_and_rejects_unknown() {
        assert_eq!(
            digest_to_hash("sha256:AbC").map(|h| h.algo),
            Some(HashAlgo::Sha256)
        );
        assert_eq!(
            digest_to_hash("sha512:AbC").map(|h| h.algo),
            Some(HashAlgo::Sha512)
        );
        assert_eq!(digest_to_hash("md5:"), None);
        assert_eq!(digest_to_hash("blake3:abc"), None);
        assert_eq!(digest_to_hash("nonsense"), None);
    }
}

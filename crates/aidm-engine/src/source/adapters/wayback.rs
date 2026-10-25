//! Wayback CDX 适配器（`docs/source-discovery.md` §4.4）。
//!
//! # 为什么只接受原始 URL
//!
//! CDX 的检索维度是 **URL**，不是文件名。没有原始 URL 时，本适配器返回
//! `Unsupported`，不做"按文件名猜 URL"的伪搜索。
//!
//! # 为什么 size 一定是 `None`
//!
//! CDX 返回的 `length` 是**压缩 WARC 记录长度**，不是原始文件长度。把它当文件大小
//! 会直接把不同文件判成同一份（§3.2），所以这里一律不采信；证据级别封顶 `L0`。
//! captures 还可能被截断或是错误页，最终由验证器的 S0/S1 阶段淘汰。
//!
//! # 地址形态
//!
//! `https://web.archive.org/web/<timestamp>id_/<original>`：`id_` 表示返回**原始字节**
//! （不插 Wayback 工具条）。没有这个后缀会拿到被改写的 HTML。

use std::collections::HashSet;
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use aidm_core::source::{
    CandidateSource, IdentityEvidence, Platform, ResolvedTarget, SourceKind, SourceQuery,
};

use crate::http_util::HttpRuntime;
use crate::source::adapter::{AdapterError, PlatformAdapter, SearchBudget};

const DEFAULT_BASE: &str = "https://web.archive.org";
const MAX_BODY: u64 = 2 * 1024 * 1024;
const MAX_CAPTURES: usize = 20;
const MAX_TIMEOUT_MS: i64 = 6_000;

pub struct WaybackAdapter {
    http: Arc<HttpRuntime>,
    base: String,
}

impl WaybackAdapter {
    /// 生产构造：base 可用 `AIDM_SOURCE_WAYBACK_BASE` 覆盖（测试/镜像用）。
    pub fn new(http: Arc<HttpRuntime>) -> Self {
        let base = std::env::var("AIDM_SOURCE_WAYBACK_BASE")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_BASE.to_string());
        Self::with_base(http, base)
    }

    pub fn with_base(http: Arc<HttpRuntime>, base: impl Into<String>) -> Self {
        WaybackAdapter {
            http,
            base: base.into().trim_end_matches('/').to_string(),
        }
    }

    pub fn base(&self) -> &str {
        &self.base
    }
}

/// 组 CDX 查询 URL。`original` 可能自带查询串，交给 `Url` 统一编码。
pub(crate) fn cdx_url(base: &str, original: &str, limit: usize) -> Result<String, AdapterError> {
    let mut url = url::Url::parse(&format!("{}/cdx/search/cdx", base.trim_end_matches('/')))
        .map_err(|_| AdapterError::Config("invalid wayback base".into()))?;
    url.query_pairs_mut()
        .append_pair("url", original)
        .append_pair("output", "json")
        .append_pair("filter", "statuscode:200")
        .append_pair("collapse", "digest")
        .append_pair("fl", "timestamp,original")
        .append_pair("limit", &limit.clamp(1, MAX_CAPTURES).to_string());
    Ok(url.into())
}

/// 解析 CDX JSON。第一行是表头，按"时间戳必须是纯数字"跳过。
pub(crate) fn parse_cdx(
    body: &str,
    base: &str,
    limit: usize,
) -> Result<Vec<CandidateSource>, AdapterError> {
    let value: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| AdapterError::Malformed(format!("cdx json: {e}")))?;
    let rows = value
        .as_array()
        .ok_or_else(|| AdapterError::Malformed("cdx: top-level is not an array".into()))?;
    let base = base.trim_end_matches('/');
    let mut out = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    // CDX 默认列序是 urlkey,timestamp,original,...；带 `fl` 时可能是 timestamp,original。
    // 先按表头定位；没有表头时按内容判断，避免把 urlkey 当时间戳。
    let mut columns: Option<(usize, usize)> = None;
    for row in rows {
        let Some(cells) = row.as_array() else {
            continue;
        };
        if cells.len() < 2 {
            continue;
        }
        if columns.is_none() {
            if let (Some(t), Some(o)) = (
                cells.iter().position(|c| c.as_str() == Some("timestamp")),
                cells.iter().position(|c| c.as_str() == Some("original")),
            ) {
                columns = Some((t, o));
                continue; // 表头行
            }
        }
        let (ts_idx, orig_idx) = columns.unwrap_or_else(|| default_columns(cells));
        let Some(timestamp) = cells.get(ts_idx).and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(original) = cells.get(orig_idx).and_then(|v| v.as_str()) else {
            continue;
        };
        if !is_timestamp(timestamp) || original.is_empty() {
            continue;
        }
        if !(original.starts_with("http://") || original.starts_with("https://")) {
            continue;
        }
        let url = format!("{base}/web/{timestamp}id_/{original}");
        if !seen.insert(url.clone()) {
            continue;
        }
        out.push(CandidateSource {
            url,
            platform: Platform::Wayback,
            kind: SourceKind::File,
            // CDX 的 length 是压缩 WARC 记录长度，不是文件大小：不采信。
            size: None,
            version: None,
            container: None,
            evidence: IdentityEvidence::Unverified,
            auth_ref: None,
            origin: Some(format!("wayback:{timestamp}")),
            expires_at: None,
        });
        if out.len() >= limit.max(1) {
            break;
        }
    }
    Ok(out)
}

fn is_timestamp(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit())
}

/// 没有表头时猜列序：`[timestamp, original]` 或默认的 `[urlkey, timestamp, original]`。
fn default_columns(cells: &[serde_json::Value]) -> (usize, usize) {
    let ts0 = cells
        .first()
        .and_then(|v| v.as_str())
        .is_some_and(is_timestamp);
    let orig1 = cells
        .get(1)
        .and_then(|v| v.as_str())
        .is_some_and(|s| s.starts_with("http://") || s.starts_with("https://"));
    if ts0 && orig1 {
        (0, 1)
    } else {
        (1, 2)
    }
}

impl PlatformAdapter for WaybackAdapter {
    fn platform(&self) -> Platform {
        Platform::Wayback
    }

    fn search(
        &self,
        query: &SourceQuery,
        budget: SearchBudget,
    ) -> Result<Vec<CandidateSource>, AdapterError> {
        let Some(original) = query.orig_url.as_deref() else {
            return Err(AdapterError::Unsupported);
        };
        if !(original.starts_with("http://") || original.starts_with("https://")) {
            return Err(AdapterError::Unsupported);
        }
        let now = crate::source_registry::now_ms();
        if budget.expired(now) {
            return Err(AdapterError::Timeout);
        }
        let limit = budget.max_results.min(MAX_CAPTURES);
        let url = cdx_url(&self.base, original, limit)?;
        let timeout_ms = budget.remaining_ms(now).clamp(1, MAX_TIMEOUT_MS);
        let resp = self
            .http
            .agent_for(&url)
            .get(&url)
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
            .map_err(|e| AdapterError::network(format!("cdx read: {e}")))?;
        if raw.len() as u64 > MAX_BODY {
            return Err(AdapterError::Malformed("cdx body too large".into()));
        }
        let body = String::from_utf8(raw)
            .map_err(|_| AdapterError::Malformed("cdx body is not utf-8".into()))?;
        parse_cdx(&body, &self.base, limit)
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
        // `web/<ts>id_/...` 是稳定的捕获地址，没有签名过期。
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

    const ROWS: &str = r#"[
      ["urlkey","timestamp","original","mimetype","statuscode","digest","length"],
      ["org,example)/f.iso","20200101000000","http://example.com/f.iso","application/octet-stream","200","ABC","123"],
      ["org,example)/f.iso","20200202000000","http://example.com/f.iso","application/octet-stream","200","DEF","456"],
      ["org,example)/bad","not-a-timestamp","http://example.com/bad","text/html","200","X","1"]
    ]"#;

    fn dummy_http() -> Arc<HttpRuntime> {
        HttpRuntime::from_db(&std::sync::Mutex::new(
            rusqlite::Connection::open_in_memory().unwrap(),
        ))
    }

    #[test]
    fn parse_builds_id_urls_and_never_trusts_cdx_length() {
        let got = parse_cdx(ROWS, DEFAULT_BASE, 10).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(
            got[0].url,
            "https://web.archive.org/web/20200101000000id_/http://example.com/f.iso"
        );
        assert_eq!(got[0].platform, Platform::Wayback);
        assert_eq!(got[0].kind, SourceKind::File);
        assert_eq!(got[0].size, None, "CDX length 不是文件大小");
        assert_eq!(got[0].evidence.level(), EvidenceLevel::L0Unverified);
        assert_eq!(got[0].origin.as_deref(), Some("wayback:20200101000000"));
        assert!(!got[0].evidence.allows_multi_source());
    }

    #[test]
    fn parse_skips_header_and_non_numeric_timestamp() {
        let got = parse_cdx(ROWS, DEFAULT_BASE, 10).unwrap();
        assert!(got.iter().all(|c| c.url.contains("id_/")));
        assert!(got.iter().all(|c| !c.url.contains("not-a-timestamp")));
    }

    #[test]
    fn parse_respects_limit() {
        let got = parse_cdx(ROWS, DEFAULT_BASE, 1).unwrap();
        assert_eq!(got.len(), 1);
    }

    #[test]
    fn parse_dedupes_identical_capture_urls() {
        let body = r#"[
          ["20200101000000","http://example.com/f.iso"],
          ["20200101000000","http://example.com/f.iso"]
        ]"#;
        let got = parse_cdx(body, DEFAULT_BASE, 10).unwrap();
        assert_eq!(got.len(), 1);
    }

    #[test]
    fn parse_rejects_malformed_and_non_array() {
        assert!(matches!(
            parse_cdx("{not json", DEFAULT_BASE, 10),
            Err(AdapterError::Malformed(_))
        ));
        assert!(matches!(
            parse_cdx(r#"{"a":1}"#, DEFAULT_BASE, 10),
            Err(AdapterError::Malformed(_))
        ));
    }

    #[test]
    fn cdx_url_encodes_the_original_and_sets_capture_filters() {
        let u = cdx_url(DEFAULT_BASE, "http://example.com/a b.iso?x=1&y=2", 5).unwrap();
        let parsed = url::Url::parse(&u).unwrap();
        let pairs: std::collections::HashMap<_, _> = parsed.query_pairs().into_owned().collect();
        assert_eq!(
            pairs.get("url").map(String::as_str),
            Some("http://example.com/a b.iso?x=1&y=2")
        );
        assert_eq!(pairs.get("output").map(String::as_str), Some("json"));
        assert_eq!(
            pairs.get("filter").map(String::as_str),
            Some("statuscode:200")
        );
        assert_eq!(pairs.get("collapse").map(String::as_str), Some("digest"));
        assert_eq!(
            pairs.get("fl").map(String::as_str),
            Some("timestamp,original")
        );
        assert_eq!(pairs.get("limit").map(String::as_str), Some("5"));
    }

    #[test]
    fn search_requires_an_original_url() {
        let a = WaybackAdapter::with_base(dummy_http(), DEFAULT_BASE);
        let q = SourceQuery {
            file_name: "f.iso".into(),
            size: Some(10),
            hashes: Vec::new(),
            version: None,
            orig_url: None,
            source_hint: None,
        };
        let budget = SearchBudget::new(1_000, 1_000, 5);
        assert_eq!(a.search(&q, budget), Err(AdapterError::Unsupported));
    }

    #[test]
    fn resolve_file_passthrough() {
        let a = WaybackAdapter::with_base(dummy_http(), DEFAULT_BASE);
        let c = parse_cdx(ROWS, DEFAULT_BASE, 1).unwrap().remove(0);
        let t = a.resolve(&c).unwrap();
        assert_eq!(t.url, c.url);
        assert_eq!(t.size, None);
    }
}

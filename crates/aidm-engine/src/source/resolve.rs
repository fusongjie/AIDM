//! 地址解析器（`docs/source-discovery.md` §4.5）：页面/记录 → 可下载文件地址。
//!
//! # 只做有界解析
//!
//! - 只接受 `<a href>` 里的绝对/相对 `http(s)` 地址；
//! - 只接受"路径最后一段与目标文件名相等"的链接（先百分号解码再比）；
//! - 不上执行 JS、不猜 `onclick`、不跟随 `javascript:`/`mailto:`；
//! - 响应体上限 2 MiB，链接上限 20 条，先到先得。
//!
//! # 不做什么
//!
//! 平台结构化解析（archive.org 的 `/download/...`、GitHub 的 `browser_download_url`）
//! 在各自适配器的 `resolve` 里；本模块只处理**没有结构化字段**的 HTML 页面。

use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use aidm_core::http_profile::RequestProfile;
use aidm_core::source::{CandidateSource, ResolvedTarget, SourceKind};

use crate::http_util::{apply_common, header_owned, HttpRuntime};
use crate::source::adapter::AdapterError;

const MAX_BODY: u64 = 2 * 1024 * 1024;
const MAX_LINKS: usize = 20;
const MAX_TIMEOUT_MS: i64 = 6_000;

pub struct Resolver {
    http: Arc<HttpRuntime>,
    profile: RequestProfile,
}

impl Resolver {
    pub fn new(http: Arc<HttpRuntime>) -> Self {
        Resolver {
            http,
            profile: RequestProfile::default(),
        }
    }

    pub fn with_profile(http: Arc<HttpRuntime>, profile: RequestProfile) -> Self {
        Resolver { http, profile }
    }

    /// 把 Page/Record 候选解析成文件地址。`file_name` 必须是已过闸门的目标文件名。
    pub fn resolve_page(
        &self,
        candidate: &CandidateSource,
        file_name: &str,
        timeout_ms: i64,
    ) -> Result<ResolvedTarget, AdapterError> {
        if candidate.kind == SourceKind::File {
            return Err(AdapterError::Unsupported);
        }
        let url = candidate.url.as_str();
        let timeout = Duration::from_millis(timeout_ms.clamp(1, MAX_TIMEOUT_MS) as u64);
        let request = apply_common(
            self.http.agent_for(url).get(url),
            &self.profile,
            url,
            None,
            None,
            &[],
        )
        .timeout(timeout);
        let resp = request.call().map_err(|e| match e {
            ureq::Error::Status(code, _) => map_status(code),
            ureq::Error::Transport(t) => AdapterError::network(t.to_string()),
        })?;
        let status = resp.status();
        if !(200..300).contains(&status) {
            return Err(map_status(status));
        }
        let final_url = resp.get_url().to_string();
        let content_type = header_owned(&resp, "content-type");
        let size = header_owned(&resp, "content-length").and_then(|v| v.trim().parse::<u64>().ok());
        let is_html = content_type
            .as_deref()
            .map(|ct| {
                let ct = ct.to_ascii_lowercase();
                ct.starts_with("text/html") || ct.starts_with("application/xhtml")
            })
            .unwrap_or(true);
        if !is_html {
            // 页面候选直接回文件：不再解析 body，避免把大文件读进内存。
            drop(resp);
            return Ok(ResolvedTarget {
                url: candidate.url.clone(),
                final_url,
                size,
                content_type,
                file_name: Some(file_name.to_string()),
                expires_at: candidate.expires_at,
            });
        }

        let mut raw = Vec::new();
        resp.into_reader()
            .take(MAX_BODY + 1)
            .read_to_end(&mut raw)
            .map_err(|e| AdapterError::network(format!("resolve read: {e}")))?;
        if raw.len() as u64 > MAX_BODY {
            return Err(AdapterError::Malformed("resolve body too large".into()));
        }
        let html = String::from_utf8_lossy(&raw);
        let links = extract_file_links(&html, &final_url, file_name);
        let Some(found) = links.into_iter().next() else {
            return Err(AdapterError::NotFound);
        };
        Ok(ResolvedTarget {
            url: candidate.url.clone(),
            final_url: found,
            size: None,
            content_type: None,
            file_name: Some(file_name.to_string()),
            expires_at: None,
        })
    }
}

fn map_status(code: u16) -> AdapterError {
    AdapterError::from_status(code)
}

/// 提取与目标文件名匹配的链接；顺序 = 页面出现顺序，去重，最多 [`MAX_LINKS`] 条。
pub fn extract_file_links(html: &str, page_url: &str, file_name: &str) -> Vec<String> {
    let Ok(base) = url::Url::parse(page_url) else {
        return Vec::new();
    };
    let wanted = decode_percent(file_name);
    let lower = html.to_ascii_lowercase();
    let mut out: Vec<String> = Vec::new();
    let mut cursor = 0usize;
    while out.len() < MAX_LINKS {
        let Some(rel) = lower[cursor..].find("href") else {
            break;
        };
        let at = cursor + rel;
        cursor = at + 4;
        let Some(href) = read_href_value(html, at + 4) else {
            continue;
        };
        let href = href.replace("&amp;", "&").replace("&quot;", "\"");
        let Ok(mut joined) = base.join(href.trim()) else {
            continue;
        };
        if !matches!(joined.scheme(), "http" | "https") {
            continue;
        }
        joined.set_fragment(None);
        let last = joined
            .path_segments()
            .and_then(|mut s| s.next_back())
            .map(decode_percent)
            .unwrap_or_default();
        if last != wanted {
            continue;
        }
        let s = joined.to_string();
        if !out.contains(&s) {
            out.push(s);
        }
    }
    out
}

/// 从 `href` 之后读值：跳过空白与 `=`，支持单/双引号或无引号。
fn read_href_value(html: &str, from: usize) -> Option<&str> {
    let bytes = html.as_bytes();
    let mut i = from;
    while i < bytes.len() && (bytes[i] as char).is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() || bytes[i] != b'=' {
        return None;
    }
    i += 1;
    while i < bytes.len() && (bytes[i] as char).is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }
    let quote = bytes[i];
    if quote == b'"' || quote == b'\'' {
        let start = i + 1;
        let end = html[start..].find(quote as char)? + start;
        return Some(&html[start..end]);
    }
    let start = i;
    let mut end = i;
    while end < bytes.len() {
        let c = bytes[end] as char;
        if c.is_ascii_whitespace() || c == '>' {
            break;
        }
        end += 1;
    }
    if end == start {
        None
    } else {
        Some(&html[start..end])
    }
}

/// 只处理 `%XX`；不把 `+` 当空格（路径语义）。
fn decode_percent(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = hex_val(bytes[i + 1]);
            let lo = hex_val(bytes[i + 2]);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push(hi << 4 | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aidm_core::source::Platform;
    use std::io::Write as _;
    use std::net::TcpListener;

    fn dummy_http() -> Arc<HttpRuntime> {
        HttpRuntime::from_db(&std::sync::Mutex::new(
            rusqlite::Connection::open_in_memory().unwrap(),
        ))
    }

    /// 起一次 HTTP 服务，返回 (url, join handle)。
    fn serve_once(
        status: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let status = status.to_string();
        let headers: Vec<(String, String)> = headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let body = body.to_string();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let mut resp = format!("HTTP/1.1 {status}\r\n");
            for (k, v) in headers {
                resp.push_str(&format!("{k}: {v}\r\n"));
            }
            resp.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
            resp.push_str(&body);
            let _ = stream.write_all(resp.as_bytes());
        });
        (format!("http://{addr}/page"), handle)
    }

    #[test]
    fn extracts_absolute_relative_and_ignores_others() {
        let html = r#"
          <a href="https://cdn.example/f.iso?x=1&amp;y=2">ok</a>
          <a href="/files/f.iso">relative</a>
          <a href="javascript:void(0)">js</a>
          <a href="/files/other.iso">wrong</a>
          <a href='https://cdn.example/f.iso?x=1&y=2#frag'>dup</a>
        "#;
        let links = extract_file_links(html, "https://site.example/dir/page.html", "f.iso");
        assert_eq!(
            links,
            vec![
                "https://cdn.example/f.iso?x=1&y=2".to_string(),
                "https://site.example/files/f.iso".to_string(),
            ]
        );
    }

    #[test]
    fn percent_encoded_file_names_match() {
        let html = r#"<a href="/d/a%20b.iso">x</a>"#;
        let links = extract_file_links(html, "https://s.example/p", "a b.iso");
        assert_eq!(links, vec!["https://s.example/d/a%20b.iso".to_string()]);
    }

    #[test]
    fn resolve_html_page_finds_file() {
        let (url, handle) = serve_once(
            "200 OK",
            &[("Content-Type", "text/html; charset=utf-8")],
            r#"<html><a href="/files/f.iso">download</a></html>"#,
        );
        let resolver = Resolver::new(dummy_http());
        let cand = CandidateSource {
            url,
            platform: Platform::WebSearch,
            kind: SourceKind::Page,
            size: None,
            version: None,
            container: None,
            evidence: aidm_core::source::IdentityEvidence::Unverified,
            auth_ref: None,
            origin: None,
            expires_at: None,
        };
        let t = resolver.resolve_page(&cand, "f.iso", 3_000).unwrap();
        assert!(t.final_url.ends_with("/files/f.iso"), "{}", t.final_url);
        assert_eq!(t.file_name.as_deref(), Some("f.iso"));
        handle.join().unwrap();
    }

    #[test]
    fn resolve_non_html_page_is_direct() {
        let (url, handle) = serve_once(
            "200 OK",
            &[("Content-Type", "application/octet-stream")],
            "abc",
        );
        let resolver = Resolver::new(dummy_http());
        let cand = CandidateSource {
            url,
            platform: Platform::WebSearch,
            kind: SourceKind::Page,
            size: None,
            version: None,
            container: None,
            evidence: aidm_core::source::IdentityEvidence::Unverified,
            auth_ref: None,
            origin: None,
            expires_at: None,
        };
        let t = resolver.resolve_page(&cand, "f.iso", 3_000).unwrap();
        assert_eq!(t.size, Some(3));
        assert_eq!(t.content_type.as_deref(), Some("application/octet-stream"));
        handle.join().unwrap();
    }

    #[test]
    fn resolve_html_without_match_is_not_found() {
        let (url, handle) = serve_once(
            "200 OK",
            &[("Content-Type", "text/html")],
            r#"<html><a href="/other.iso">x</a></html>"#,
        );
        let resolver = Resolver::new(dummy_http());
        let cand = CandidateSource {
            url,
            platform: Platform::WebSearch,
            kind: SourceKind::Page,
            size: None,
            version: None,
            container: None,
            evidence: aidm_core::source::IdentityEvidence::Unverified,
            auth_ref: None,
            origin: None,
            expires_at: None,
        };
        assert_eq!(
            resolver.resolve_page(&cand, "f.iso", 3_000),
            Err(AdapterError::NotFound)
        );
        handle.join().unwrap();
    }

    #[test]
    fn resolve_404_is_not_found() {
        let (url, handle) = serve_once("404 Not Found", &[("Content-Type", "text/html")], "no");
        let resolver = Resolver::new(dummy_http());
        let cand = CandidateSource {
            url,
            platform: Platform::WebSearch,
            kind: SourceKind::Page,
            size: None,
            version: None,
            container: None,
            evidence: aidm_core::source::IdentityEvidence::Unverified,
            auth_ref: None,
            origin: None,
            expires_at: None,
        };
        assert_eq!(
            resolver.resolve_page(&cand, "f.iso", 3_000),
            Err(AdapterError::NotFound)
        );
        handle.join().unwrap();
    }
}

//! 上游 Metalink（`<文件地址>.metalink` / `.meta4`）的取回。
//!
//! 比 `CHECKSUM` 多做一件事：它**同时**给出镜像地址列表与整文件 SHA-256，
//! 所以既能补"去哪找镜像"，又能补"怎么证明是同一份文件"。
//!
//! 实测：openSUSE Tumbleweed 的 `.metalink` 由 MirrorCache 生成，
//! 11 个镜像地址 + sha-256 + 4 MiB 粒度分片哈希；**AlmaLinux 的 ISO 没有**
//! `.metalink`（404），所以这只是多一条路，不替代 `CHECKSUM`。

use std::io::Read;

use aidm_core::headers::HeaderLine;
use aidm_core::http_profile::RequestProfile;
use aidm_core::metalink::{self, FileEntry};

/// 正文上限。实测样本约 88 KB（含 1100+ 条分片哈希，会随文件增大而变长；
/// 4 MiB 粒度的分片意味着 50 GB 文件约 625 KB）。
///
/// **必须在读正文之前先看 `Content-Length`**：这条请求挡在下载主路径上，
/// 一旦对面回的是一个大文件（或慢速连接），按上限"读满再放弃"会把任务卡住很久。
const MAX_BODY: u64 = 1024 * 1024;

/// 兄弟文件候选：`.metalink`（Metalink 3.0）优先，其次 `.meta4`（RFC 5854 常用后缀）。
pub fn sibling_urls(url: &str) -> Vec<String> {
    let u = url.trim();
    if u.is_empty() {
        return Vec::new();
    }
    vec![format!("{u}.metalink"), format!("{u}.meta4")]
}

/// 取回并解析；任一候选能给出**文件名匹配**的条目就返回它。
///
/// 只接受 HTTP 200：404/403/30x 一律视为"这个文件没有 metalink"。
/// 解析失败或没有匹配条目也返回 `None` —— 调用方退回 `CHECKSUM`。
pub fn fetch_linked(
    agent: &ureq::Agent,
    url: &str,
    file_name: &str,
    profile: &RequestProfile,
    referer: Option<&str>,
    cookies: Option<&str>,
    custom_headers: &[HeaderLine],
) -> Option<FileEntry> {
    for cand in sibling_urls(url) {
        let resp = match crate::http_util::apply_common(
            agent.get(&cand),
            profile,
            &cand,
            referer,
            cookies,
            custom_headers,
        )
        .call()
        {
            Ok(r) if r.status() == 200 => r,
            _ => continue,
        };
        let mut raw = Vec::new();
        // 先看声明长度：明显过大就不读正文（见 MAX_BODY 的说明）。
        if crate::http_util::header_owned(&resp, "content-length")
            .and_then(|v| v.trim().parse::<u64>().ok())
            .is_some_and(|n| n > MAX_BODY)
        {
            log::debug!("metalink: {cand} 响应过大，跳过");
            continue;
        }
        if resp
            .into_reader()
            .take(MAX_BODY)
            .read_to_end(&mut raw)
            .is_err()
        {
            continue;
        }
        let text = String::from_utf8_lossy(&raw);
        let entries = metalink::parse(&text);
        if let Some(found) = metalink::find(&entries, file_name) {
            if !found.urls.is_empty() || found.sha256.is_some() {
                return Some(found.clone());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::net::TcpListener;
    use std::path::Path;

    fn fixture() -> String {
        let p = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../aidm-core/tests/fixtures/metalink/opensuse-tumbleweed-dvd.metalink");
        std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("读取 {} 失败: {e}", p.display()))
    }

    /// 一次性 HTTP 服务：所有路径回同一份正文（够本模块的用例用）。
    fn serve(body: String) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut s = match stream {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let mut buf = [0u8; 2048];
                let _ = std::io::Read::read(&mut s, &mut buf);
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(head.as_bytes());
                let _ = s.write_all(body.as_bytes());
                let _ = s.flush();
            }
        });
        format!("http://{addr}/openSUSE-Tumbleweed-DVD-x86_64-Snapshot20261016-Media.iso")
    }

    fn profile() -> RequestProfile {
        RequestProfile::default()
    }

    #[test]
    fn sibling_urls_cover_both_metalink_spellings() {
        let u = "https://d.test/a.iso";
        assert_eq!(
            sibling_urls(u),
            vec![format!("{u}.metalink"), format!("{u}.meta4")]
        );
        assert!(sibling_urls("   ").is_empty());
    }

    #[test]
    fn fetches_and_matches_the_real_metalink() {
        let url = serve(fixture());
        let agent = ureq::AgentBuilder::new().build();
        let got = fetch_linked(
            &agent,
            &url,
            "openSUSE-Tumbleweed-DVD-x86_64-Snapshot20261016-Media.iso",
            &profile(),
            None,
            None,
            &[],
        )
        .expect("真实样本要能取回并匹配");
        assert_eq!(got.size, Some(4_666_163_200));
        assert!(got.sha256.is_some());
        assert!(got.is_usable());
    }

    #[test]
    fn returns_none_when_the_file_is_not_listed() {
        let url = serve(fixture());
        let agent = ureq::AgentBuilder::new().build();
        assert!(
            fetch_linked(&agent, &url, "some-other.iso", &profile(), None, None, &[]).is_none()
        );
    }

    #[test]
    fn returns_none_on_garbage_or_unreachable() {
        let agent = ureq::AgentBuilder::new().build();
        let url = serve("<html>not a metalink</html>".to_string());
        assert!(fetch_linked(&agent, &url, "a.iso", &profile(), None, None, &[]).is_none());
        // 连不上的地址：不该 panic，也不该卡住调用方
        assert!(fetch_linked(
            &agent,
            "http://127.0.0.1:9/a.iso",
            "a.iso",
            &profile(),
            None,
            None,
            &[]
        )
        .is_none());
    }
}

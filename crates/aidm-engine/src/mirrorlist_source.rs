//! 上游 `.mirrorlist` 的取回。
//!
//! 与 Metalink 的分工：Metalink 一次给"镜像 + 哈希"，`.mirrorlist` **只给镜像**。
//! 所以它是在"已经拿到哈希、但还不知道别的镜像"时补位（例如哈希来自 `CHECKSUM`）。
//!
//! 实测：TDF 与 KDE 的 `.mirrorlist` 都是 HTML 页面，含各镜像上的
//! **完整文件地址**；解析规则见 `aidm_core::mirrorlist`。

use std::io::Read;

use aidm_core::headers::HeaderLine;
use aidm_core::http_profile::RequestProfile;

/// 正文上限。实测样本约 24–30 KB。
///
/// 与 Metalink 同理：**读正文之前先看 `Content-Length`** —— 这条请求挡在下载主路径上，
/// 对面若回一个大文件（或慢速连接），"读满上限再放弃"会把任务卡住很久。
const MAX_BODY: u64 = 1024 * 1024;

/// 取回 `<文件地址>.mirrorlist` 并抽出目标文件的镜像地址。没有/解析不出就返回空。
pub fn fetch_linked(
    agent: &ureq::Agent,
    url: &str,
    file_name: &str,
    profile: &RequestProfile,
    referer: Option<&str>,
    cookies: Option<&str>,
    custom_headers: &[HeaderLine],
) -> Vec<String> {
    let cand = format!("{}.mirrorlist", url.trim());
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
        _ => return Vec::new(),
    };
    if crate::http_util::header_owned(&resp, "content-length")
        .and_then(|v| v.trim().parse::<u64>().ok())
        .is_some_and(|n| n > MAX_BODY)
    {
        log::debug!("mirrorlist: 响应过大，跳过");
        return Vec::new();
    }
    let mut raw = Vec::new();
    if resp
        .into_reader()
        .take(MAX_BODY)
        .read_to_end(&mut raw)
        .is_err()
    {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&raw);
    aidm_core::mirrorlist::parse(&text, file_name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::net::TcpListener;
    use std::path::Path;

    fn fixture() -> String {
        let p = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../aidm-core/tests/fixtures/mirrorlist/tdf-libreoffice.mirrorlist");
        std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("读取 {} 失败: {e}", p.display()))
    }

    fn serve(status: &'static str, body: String) -> String {
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
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(head.as_bytes());
                let _ = s.write_all(body.as_bytes());
                let _ = s.flush();
            }
        });
        format!("http://{addr}/LibreOffice_26.8.1_Linux_x86-64_deb.tar.gz")
    }

    fn profile() -> RequestProfile {
        RequestProfile::default()
    }

    #[test]
    fn fetches_and_parses_the_real_tdf_mirrorlist() {
        let url = serve("200 OK", fixture());
        let agent = ureq::AgentBuilder::new().build();
        let got = fetch_linked(
            &agent,
            &url,
            "LibreOffice_26.8.1_Linux_x86-64_deb.tar.gz",
            &profile(),
            None,
            None,
            &[],
        );
        assert!(got.len() >= 20, "{}", got.len());
        assert!(got
            .iter()
            .all(|u| u.ends_with("LibreOffice_26.8.1_Linux_x86-64_deb.tar.gz")));
    }

    #[test]
    fn returns_empty_on_404_or_garbage() {
        let agent = ureq::AgentBuilder::new().build();
        let url = serve("404 Not Found", "nope".into());
        assert!(fetch_linked(&agent, &url, "a.iso", &profile(), None, None, &[]).is_empty());
        let url = serve("200 OK", "<html>no urls</html>".into());
        assert!(fetch_linked(&agent, &url, "a.iso", &profile(), None, None, &[]).is_empty());
        assert!(fetch_linked(
            &agent,
            "http://127.0.0.1:9/a.iso",
            "a.iso",
            &profile(),
            None,
            None,
            &[]
        )
        .is_empty());
    }
}

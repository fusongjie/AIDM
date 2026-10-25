//! Range 探测：GET `Range: bytes=0-0`（§3.2）。
//! 206 + 合法 Content-Range（含总长）⇒ 可多连接；否则降级单线程。
//! 探测响应体丢弃（不落盘），避免服务器忽略 Range 时把整文件读进内存。

use aidm_core::segment::{parse_content_range, range_supports_multi, ContentRange};

use crate::http_util::{apply_common, header_owned};

#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub status: u16,
    pub final_url: String,
    #[allow(dead_code)]
    pub content_range: Option<ContentRange>,
    #[allow(dead_code)]
    pub content_length: Option<u64>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub content_disposition: Option<String>,
    pub content_type: Option<String>,
    pub range_ok: bool,
    pub total: Option<u64>,
    /// 401 响应里的全部 `WWW-Authenticate` 头值（其余状态为空）。
    pub www_authenticate: Vec<String>,
}

pub fn probe(
    agent: &ureq::Agent,
    url: &str,
    profile: &aidm_core::http_profile::RequestProfile,
    referer: Option<&str>,
    cookies: Option<&str>,
    custom_headers: &[aidm_core::headers::HeaderLine],
) -> Result<ProbeResult, String> {
    let req = apply_common(
        agent.get(url),
        profile,
        url,
        referer,
        cookies,
        custom_headers,
    )
    .set("Range", "bytes=0-0");
    let resp = match req.call() {
        Ok(resp) => resp,
        Err(ureq::Error::Status(code, resp)) => {
            // 401/407 是"挑战"而不是终点：上层的站点凭据逻辑要拿到状态码才能重试。
            // 其余非 2xx 仍然直接失败（含 Retry-After 透传）。
            if code == 401 || code == 407 {
                let final_url = resp.get_url().to_string();
                let content_type = header_owned(&resp, "content-type");
                let www_authenticate = resp
                    .all("www-authenticate")
                    .into_iter()
                    .map(str::to_string)
                    .collect();
                drop(resp);
                return Ok(ProbeResult {
                    status: code,
                    final_url,
                    content_range: None,
                    content_length: None,
                    etag: None,
                    last_modified: None,
                    content_disposition: None,
                    content_type,
                    range_ok: false,
                    total: None,
                    www_authenticate,
                });
            }
            let retry = header_owned(&resp, "retry-after");
            return Err(match retry {
                Some(h) => format!("http_{code} retry-after={h}"),
                None => format!("http_{code}"),
            });
        }
        Err(e) => return Err(format!("connect: {e}")),
    };

    let status = resp.status();
    let final_url = resp.get_url().to_string();
    let cr_raw = header_owned(&resp, "content-range");
    let content_range = cr_raw.as_deref().and_then(parse_content_range);
    let content_length = header_owned(&resp, "content-length").and_then(|v| v.parse().ok());
    let etag = header_owned(&resp, "etag");
    let last_modified = header_owned(&resp, "last-modified");
    let content_disposition = header_owned(&resp, "content-disposition");
    let content_type = header_owned(&resp, "content-type");
    let range_ok = range_supports_multi(status, cr_raw.as_deref());
    let total = content_range.and_then(|c| c.total).or_else(|| {
        if (200..300).contains(&status) && status != 206 {
            content_length
        } else {
            None
        }
    });

    // 故意不读 body：200 且忽略 Range 时 body 可能是整文件。
    drop(resp);

    // 「错误页冒充文件」：部分镜像站会对特定 UA 返回
    // 200 + text/html 的反爬提示页。不拦的话它会被当合法候选 → 降级单线程 →
    // 5 KB 的 HTML 被存成 .iso 并判定完成，比明确失败更糟。
    // 判定保守（只在内容类型与文件名**确定矛盾**时拒绝），见 `aidm_core::content_check`。
    if aidm_core::content_check::looks_like_error_page(content_type.as_deref(), &final_url) {
        return Err("html_not_file".to_string());
    }

    Ok(ProbeResult {
        status,
        final_url,
        content_range,
        content_length,
        etag,
        last_modified,
        content_disposition,
        content_type,
        range_ok,
        total,
        www_authenticate: Vec::new(),
    })
}

/// 只取「第一跳」的重定向目标，**不跟随**。
///
/// 主地址 302 到另一个主机时（实测：`mirrors.aliyun.com` 把 ISO 302 到
/// `http://iso-osm.mirrors.aliyuncs.com`），跳转目标本身就是另一个地址，值得纳入尝试；
/// 但让 ureq 一路跟到底就会丢掉「原始地址」这个身份。所以这里单独发一次
/// `redirects(0)` 请求，只读 `Location`。
///
/// **只在候选探测失败之后调用**，因此成功路径的请求数不变。
/// 无 3xx / 无 `Location` / 本身失败 → `None`。
pub fn redirect_target(
    agent: &ureq::Agent,
    url: &str,
    profile: &aidm_core::http_profile::RequestProfile,
    referer: Option<&str>,
    cookies: Option<&str>,
    custom_headers: &[aidm_core::headers::HeaderLine],
) -> Option<String> {
    // ureq 把 3xx 当正常响应返回（只有 >=400 才是 `Error::Status`）。
    // 调用方必须传 `HttpRuntime::agent_for_noredirect` 取到的 Agent——
    // `redirects` 只能设在 Agent 上，不能按请求覆盖。
    let resp = apply_common(
        agent.get(url),
        profile,
        url,
        referer,
        cookies,
        custom_headers,
    )
    .call()
    .ok()?;
    let status = resp.status();
    if !(300..400).contains(&status) {
        return None;
    }
    let location = header_owned(&resp, "location")?;
    let resolved = resolve_location(url, location.trim())?;
    aidm_core::alt::is_http_url(&resolved).then_some(resolved)
}

/// 把 `Location` 解析成绝对地址。只处理 HTTP(S) 里实际会出现的四种形态；
/// 其余（含畸形值）返回 `None`，宁可少一个候选也不要猜错主机。
fn resolve_location(base: &str, location: &str) -> Option<String> {
    if location.is_empty() {
        return None;
    }
    let (scheme, rest) = base.split_once("://")?;
    if location.len() >= 7 && location[..7].eq_ignore_ascii_case("http://") {
        return Some(location.to_string());
    }
    if location.len() >= 8 && location[..8].eq_ignore_ascii_case("https://") {
        return Some(location.to_string());
    }
    // 网络相对路径：`//host/path`
    if let Some(host_path) = location.strip_prefix("//") {
        return Some(format!("{scheme}://{host_path}"));
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    if authority.is_empty() {
        return None;
    }
    // 绝对路径：`/path`
    if let Some(path) = location.strip_prefix('/') {
        return Some(format!("{scheme}://{authority}/{path}"));
    }
    // 文档相对路径：拼到 base 的目录上
    let base_path = &rest[authority.len()..];
    let dir = match base_path.rfind('/') {
        Some(i) => &base_path[..=i],
        None => "/",
    };
    Some(format!("{scheme}://{authority}{dir}{location}"))
}

#[cfg(test)]
mod tests {
    use super::resolve_location;

    #[test]
    fn resolves_absolute_and_scheme_relative() {
        let base = "https://mirrors.aliyun.com/almalinux/9/isos/x86_64/a.iso";
        assert_eq!(
            resolve_location(base, "http://iso-osm.mirrors.aliyuncs.com/a.iso").as_deref(),
            Some("http://iso-osm.mirrors.aliyuncs.com/a.iso")
        );
        assert_eq!(
            resolve_location(base, "HTTPS://Other.test/a.iso").as_deref(),
            Some("HTTPS://Other.test/a.iso")
        );
        assert_eq!(
            resolve_location(base, "//other.test/a.iso").as_deref(),
            Some("https://other.test/a.iso")
        );
    }

    #[test]
    fn resolves_absolute_path_on_same_authority() {
        let base = "https://a.test/x/y/a.iso";
        assert_eq!(
            resolve_location(base, "/z/a.iso").as_deref(),
            Some("https://a.test/z/a.iso")
        );
        // 带端口的 authority 必须原样保留
        let base = "http://a.test:8080/x/a.iso";
        assert_eq!(
            resolve_location(base, "/z/a.iso").as_deref(),
            Some("http://a.test:8080/z/a.iso")
        );
    }

    #[test]
    fn resolves_document_relative_against_base_directory() {
        let base = "https://a.test/x/y/a.iso";
        assert_eq!(
            resolve_location(base, "b.iso").as_deref(),
            Some("https://a.test/x/y/b.iso")
        );
        let base = "https://a.test/a.iso";
        assert_eq!(
            resolve_location(base, "b.iso").as_deref(),
            Some("https://a.test/b.iso")
        );
    }

    #[test]
    fn rejects_unusable_locations() {
        let base = "https://a.test/x/a.iso";
        assert_eq!(resolve_location(base, ""), None);
        assert_eq!(resolve_location("not-a-url", "/z"), None);
    }

    #[test]
    fn a_waf_that_challenges_browser_uas_passes_without_one() {
        // 复刻实测形态（`mirrors.nju.edu.cn`）：**带 UA 就 302 跳回自己**并下发挑战
        // cookie；不带 UA 直接给 206。跟随重定向的 agent 会在第一种情况下打到
        // "Too Many Redirects"，正是 AIDM 记录到的那条错误。
        let seen: std::sync::Arc<std::sync::Mutex<Vec<Option<String>>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut s = match stream {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let mut buf = [0u8; 4096];
                let n = std::io::Read::read(&mut s, &mut buf).unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).to_ascii_lowercase();
                let ua = head
                    .lines()
                    .find_map(|l| l.strip_prefix("user-agent:").map(|v| v.trim().to_string()));
                // 复刻实测的 WAF 判据：**只挑战"自称浏览器"的请求**。
                // 空值 / curl / ureq / AIDM 这类非浏览器标识一律放行。
                let claims_browser = ua
                    .as_deref()
                    .is_some_and(|v| v.contains("mozilla") || v.contains("chrome"));
                seen2.lock().unwrap().push(ua);
                let resp = if claims_browser {
                    format!(
                        "HTTP/1.1 302 Moved Temporarily\r\nLocation: http://{addr}/a.iso\r\n\
                         Set-Cookie: bcheck=true; Path=/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                } else {
                    "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-0/1000\r\n\
                     Content-Length: 1\r\nContent-Type: application/octet-stream\r\n\
                     Connection: close\r\n\r\nX"
                        .to_string()
                };
                let _ = std::io::Write::write_all(&mut s, resp.as_bytes());
            }
        });
        let agent = ureq::AgentBuilder::new().build();
        let url = format!("http://{addr}/a.iso");
        let profile = aidm_core::http_profile::RequestProfile::default();

        // 自称浏览器：被挑战 → 跟随重定向绕圈 → 探测失败
        match super::probe(&agent, &url, &profile, None, None, &[]) {
            Err(e) => assert!(
                e.contains("Too Many Redirects") || e.contains("connect:"),
                "自称浏览器时应当被挑战拦住: {e}"
            ),
            Ok(p) => panic!(
                "自称浏览器时应当被挑战拦住，实际拿到 status={} total={:?}",
                p.status, p.total
            ),
        }

        // 换成不声明身份的 UA：同一地址直接 206，且总长可用
        let ok = super::probe(
            &agent,
            &url,
            &profile.clone().without_browser_ua(),
            None,
            None,
            &[],
        )
        .expect("不声明身份时应当正常通过");
        assert_eq!(ok.status, 206);
        assert_eq!(ok.total, Some(1000));
        assert!(ok.range_ok, "应当支持多连接");

        // 线上真正发出去的是什么：既试过那串 IE11（失败那次），也发出了自报标识（成功那次）
        let seen = seen.lock().unwrap();
        let list: Vec<&String> = seen.iter().flatten().collect();
        // 注意 `head` 整体被转成小写了，所以这里要忽略大小写比较
        assert!(
            list.iter()
                .any(|v| v.eq_ignore_ascii_case(aidm_core::http_profile::ANON_USER_AGENT)),
            "应当发出不声明身份的（空）UA: {seen:?}"
        );
        assert!(
            list.iter().any(|v| v.contains("mozilla")),
            "带浏览器 UA 的那一跳也应当试过（否则这条用例没测到挑战）: {seen:?}"
        );
    }

    #[test]
    #[ignore = "需要真实网络；验证 aliyun 这条真实坏链在新策略下能拿到足够多的可用源"]
    fn real_almalinux_link_reaches_a_working_mirror() {
        // 现场：`mirrors.aliyun.com` 的 ISO 路径 302 到一个不可达主机。
        // 自动镜像补上的几家在国内镜像的 WAF 下表现不同，而**触发条件是"是否自称浏览器"**：
        //   nju 系列 → 带着浏览器 UA 时 302 跳回自己（挑战 cookie），换成空值后 206
        //   sjtug    → 带着浏览器 UA 时 200 + 反爬 HTML 页，换成空值后 206
        //   huaweicloud / tencent / zju / repo → 两种 UA 下都 206
        // 这条用例把两种策略各跑一遍，断言"换成自报标识后可用源明显变多"。
        use aidm_core::setting_spec::DEFAULT_USER_AGENT;

        const URL: &str =
            "https://mirrors.aliyun.com/almalinux/9/isos/x86_64/AlmaLinux-9-latest-x86_64-dvd.iso";
        const EXPECTED_TOTAL: u64 = 15_151_923_200;

        let agent = ureq::AgentBuilder::new()
            .user_agent(DEFAULT_USER_AGENT)
            .build();
        let base = aidm_core::http_profile::RequestProfile::default();
        let cands = aidm_core::alt::candidates_with_mirrors(URL, None, true);
        assert!(cands.len() > 1, "应当派生出镜像候选: {cands:?}");

        let probe_all = |profile: &aidm_core::http_profile::RequestProfile| {
            let mut usable: Vec<String> = Vec::new();
            let mut rejected: Vec<(String, String)> = Vec::new();
            for c in &cands {
                match super::probe(&agent, c, profile, None, None, &[]) {
                    Ok(p) if p.total == Some(EXPECTED_TOTAL) => usable.push(c.clone()),
                    Ok(p) => rejected.push((
                        c.clone(),
                        format!("total={:?} status={}", p.total, p.status),
                    )),
                    Err(e) => rejected.push((c.clone(), e)),
                }
            }
            (usable, rejected)
        };

        let (browser_usable, browser_rejected) = probe_all(&base);
        let (client_usable, _) = probe_all(&base.clone().without_browser_ua());
        eprintln!("[声称浏览器] 可用 {} 个:", browser_usable.len());
        for u in &browser_usable {
            eprintln!("  ✓ {u}");
        }
        for (u, why) in &browser_rejected {
            eprintln!("  ✗ {u}  →  {why}");
        }
        eprintln!("[不声明身份] 可用 {} 个:", client_usable.len());
        for u in &client_usable {
            eprintln!("  ✓ {u}");
        }

        assert!(
            client_usable.len() >= 6,
            "换成不声明身份后应当几乎所有已知镜像都可用，实际 {}: {client_usable:?}",
            client_usable.len()
        );
        assert!(
            client_usable.len() > browser_usable.len(),
            "新策略必须**明显**多于旧策略（{} vs {}）",
            client_usable.len(),
            browser_usable.len()
        );
    }
}

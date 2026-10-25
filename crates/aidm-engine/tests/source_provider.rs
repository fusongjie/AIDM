//! `SourceProvider` 抽象（`docs/source-discovery.md` §4.9、§5.1–§5.4）的最小验证。
//!
//! 每个用例在 `127.0.0.1:0` 上起一个裸 `TcpListener`（只用标准库），
//! 走真实的 ureq HTTP 请求，不引入新 dev-dependency。

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use aidm_core::http_profile::RequestProfile;
use aidm_core::source::SourceCapabilities;
use aidm_engine::source::{
    Health, HttpProvider, ProbeResult, ProviderError, ProviderId, ReadRequest, SourceProvider,
    VersionToken,
};

// ---------- 极简测试 HTTP 服务器 ----------

#[derive(Debug, Clone)]
struct Recorded {
    path: String,
    range: Option<String>,
    if_range: Option<String>,
}

/// 起一次性服务器：每个连接读一个请求头 → 交给 `handler` → 写回 → 关连接。
fn spawn<F>(handler: F) -> (String, Arc<Mutex<Vec<Recorded>>>)
where
    F: Fn(&Recorded) -> Vec<u8> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen2 = Arc::clone(&seen);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = match stream {
                Ok(s) => s,
                Err(_) => break,
            };
            let mut raw = Vec::new();
            let mut buf = [0u8; 1024];
            while !raw.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                raw.extend_from_slice(&buf[..n]);
                if raw.len() > 64 * 1024 {
                    break;
                }
            }
            let head = String::from_utf8_lossy(&raw).to_string();
            let path = head
                .split("\r\n")
                .next()
                .unwrap_or("")
                .split(' ')
                .nth(1)
                .unwrap_or("")
                .to_string();
            // 头名统一小写后按名查，不依赖请求头顺序（`Range` 之后才是 `If-Range`）。
            let headers: Vec<(String, String)> = head
                .split("\r\n")
                .filter_map(|l| l.split_once(':'))
                .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
                .collect();
            let header = |name: &str| {
                headers
                    .iter()
                    .find(|(k, _)| k == name)
                    .map(|(_, v)| v.clone())
            };
            let rec = Recorded {
                path,
                range: header("range"),
                if_range: header("if-range"),
            };
            seen2.lock().unwrap().push(rec.clone());
            let resp = handler(&rec);
            let _ = stream.write_all(&resp);
            let _ = stream.flush();
            // 响应头带 `Connection: close`，drop 即关闭。
        }
    });
    (format!("http://{addr}/file.bin"), seen)
}

fn response(status: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut head = format!("HTTP/1.1 {status}\r\nConnection: close\r\n");
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    out
}

// ---------- 构造辅助 ----------

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new().build()
}

fn provider(url: &str) -> HttpProvider {
    HttpProvider::new(
        url.to_string(),
        agent(),
        RequestProfile::default(),
        None,
        None,
        Vec::new(),
    )
}

fn read_req(offset: u64, len: u64) -> ReadRequest {
    ReadRequest {
        source_id: ProviderId("test".into()),
        offset,
        len,
        expected_version: None,
    }
}

fn probe_result(
    range_ok: bool,
    total: Option<u64>,
    etag: Option<&str>,
    last_modified: Option<&str>,
) -> ProbeResult {
    ProbeResult {
        status: if range_ok { 206 } else { 200 },
        final_url: "http://127.0.0.1:1/file.bin".into(),
        content_range: None,
        content_length: total,
        etag: etag.map(str::to_string),
        last_modified: last_modified.map(str::to_string),
        content_disposition: None,
        content_type: Some("application/octet-stream".into()),
        range_ok,
        total,
        www_authenticate: Vec::new(),
    }
}

/// 用探测结果构造 provider，并把 `final_url` 指到测试服务器（`refresh()` 探的是它）。
fn provider_from_probe(url: &str, probe: &ProbeResult) -> HttpProvider {
    let mut probe = probe.clone();
    probe.final_url = url.to_string();
    HttpProvider::from_probe(
        url.to_string(),
        &probe,
        agent(),
        RequestProfile::default(),
        None,
        None,
        Vec::new(),
    )
}

// ---------- 用例 ----------

/// 1. 206 + 合法 Content-Range + 完整 body → 偏移与字节都正确。
#[test]
fn range_206_returns_requested_bytes() {
    let body: Vec<u8> = (0..100u8).collect();
    let served = body.clone();
    let (url, seen) = spawn(move |_| {
        response(
            "206 Partial Content",
            &[("Content-Range", "bytes 100-199/1000")],
            &served,
        )
    });

    let chunk = provider(&url)
        .read_range(&read_req(100, 100))
        .expect("206 + 合法 Content-Range 应当成功");

    assert_eq!(chunk.offset, 100, "偏移必须回填请求值");
    assert_eq!(chunk.bytes, body, "返回字节必须与服务端一致");

    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].path, "/file.bin");
    assert_eq!(
        seen[0].range.as_deref(),
        Some("bytes=100-199"),
        "实际发出的 Range 必须与请求区间一致"
    );
}

/// 2. 服务器忽略 Range（回 200）→ RangeIgnored，绝不把整响应当这段数据。
#[test]
fn status_200_is_range_ignored() {
    let (url, seen) = spawn(|_| {
        response(
            "200 OK",
            &[("Content-Type", "application/octet-stream")],
            b"whole-file",
        )
    });

    let err = provider(&url)
        .read_range(&read_req(0, 4))
        .expect_err("200 必须判为 RangeIgnored");
    assert_eq!(err, ProviderError::RangeIgnored);

    // 证明请求里确实带了 Range（否则这条用例测不到"忽略"）。
    let seen = seen.lock().unwrap();
    assert_eq!(seen[0].range.as_deref(), Some("bytes=0-3"));
    assert!(
        seen[0].if_range.is_none(),
        "没有 expected_version 时不得发 If-Range"
    );
}

/// 3. 416 → RangeNotSatisfiable，total 来自 `Content-Range: bytes */total`。
#[test]
fn status_416_reports_total() {
    let (url, _seen) = spawn(|_| {
        response(
            "416 Range Not Satisfiable",
            &[("Content-Range", "bytes */1000")],
            b"",
        )
    });

    let err = provider(&url)
        .read_range(&read_req(5000, 10))
        .expect_err("416 必须报越界");
    assert_eq!(
        err,
        ProviderError::RangeNotSatisfiable { total: Some(1000) }
    );
}

/// 4. 401 → Auth{401}。
#[test]
fn status_401_is_auth() {
    let (url, _seen) =
        spawn(|_| response("401 Unauthorized", &[("WWW-Authenticate", "Basic")], b""));

    let err = provider(&url)
        .read_range(&read_req(0, 10))
        .expect_err("401 必须报认证失败");
    assert_eq!(err, ProviderError::Auth { status: 401 });
}

/// 5. body 比 Content-Range 声明短 → ShortRead（短读按字节数报）。
#[test]
fn short_body_is_short_read() {
    let (url, _seen) = spawn(|_| {
        // 声明 [0,99]，实际只给 50 字节。
        response(
            "206 Partial Content",
            &[("Content-Range", "bytes 0-99/1000")],
            &[b'x'; 50],
        )
    });

    let err = provider(&url)
        .read_range(&read_req(0, 100))
        .expect_err("短读必须失败");
    assert_eq!(
        err,
        ProviderError::ShortRead {
            expected: 100,
            got: 50
        }
    );
}

/// 6. 探测结果 → 五项能力映射（§3.3）。
#[test]
fn capabilities_from_probe_maps_five_fields() {
    // 全部可用
    let full = probe_result(true, Some(1000), Some("\"v1\""), None);
    let c = HttpProvider::capabilities_from_probe(&full);
    assert!(c.random_read, "range_ok ⇒ random_read");
    assert!(c.resume, "range_ok ⇒ resume");
    assert!(c.length_query, "有总长 ⇒ length_query");
    assert!(c.version_check, "有 ETag ⇒ version_check");
    assert_eq!(c.conns_max, 4, "默认每源并发 4（§5.6）");

    // 什么都没探到：一律 false
    let bare = probe_result(false, None, None, None);
    let c = HttpProvider::capabilities_from_probe(&bare);
    assert!(!c.random_read);
    assert!(!c.resume);
    assert!(!c.length_query);
    assert!(!c.version_check);
    assert_eq!(c.conns_max, 4);

    // 只有 Last-Modified 也算能查版本
    let lm = probe_result(false, None, None, Some("Wed, 21 Oct 2026 07:28:00 GMT"));
    let c = HttpProvider::capabilities_from_probe(&lm);
    assert!(c.version_check, "有 Last-Modified ⇒ version_check");
    assert!(!c.random_read);
    assert!(!c.length_query);
}

/// 7. 版本 token：ETag 优先，其次 Last-Modified，都没有 → None。
#[test]
fn version_token_prefers_etag_then_last_modified_then_none() {
    let with_etag = probe_result(
        true,
        Some(10),
        Some("\"v1\""),
        Some("Wed, 21 Oct 2026 07:28:00 GMT"),
    );
    let p = HttpProvider::from_probe(
        "http://127.0.0.1:1/file.bin".into(),
        &with_etag,
        agent(),
        RequestProfile::default(),
        None,
        None,
        Vec::new(),
    );
    assert_eq!(
        p.version_token(),
        Some(VersionToken("etag:\"v1\"".into())),
        "ETag 优先"
    );

    let with_lm = probe_result(true, Some(10), None, Some("Wed, 21 Oct 2026 07:28:00 GMT"));
    let p = HttpProvider::from_probe(
        "http://127.0.0.1:1/file.bin".into(),
        &with_lm,
        agent(),
        RequestProfile::default(),
        None,
        None,
        Vec::new(),
    );
    assert_eq!(
        p.version_token(),
        Some(VersionToken("lm:Wed, 21 Oct 2026 07:28:00 GMT".into())),
        "没有 ETag 时退回 Last-Modified"
    );

    let bare = probe_result(false, None, None, None);
    let p = HttpProvider::from_probe(
        "http://127.0.0.1:1/file.bin".into(),
        &bare,
        agent(),
        RequestProfile::default(),
        None,
        None,
        Vec::new(),
    );
    assert_eq!(p.version_token(), None, "两者都没有 ⇒ None");
}

/// 8. trait object 可直接读取（调度器只认识 `dyn SourceProvider`）。
#[test]
fn trait_object_can_read_range() {
    let body = b"abcdefgh".to_vec();
    let served = body.clone();
    let (url, _seen) = spawn(move |_| {
        response(
            "206 Partial Content",
            &[("Content-Range", "bytes 8-15/64")],
            &served,
        )
    });

    let boxed: Box<dyn SourceProvider> = Box::new(provider(&url));
    assert_eq!(
        boxed.id(),
        ProviderId::for_url(&url),
        "id 必须是 URL 的稳定摘要"
    );
    assert_ne!(
        boxed.id(),
        ProviderId(url.clone()),
        "id 不得直接回显原始地址"
    );
    assert_eq!(boxed.health(), Health::Healthy, "默认健康");
    let chunk = boxed
        .read_range(&read_req(8, 8))
        .expect("trait object 调用应当成功");
    assert_eq!(chunk.offset, 8);
    assert_eq!(chunk.bytes, body);
}

/// 附加：参数与版本在**发请求之前**就被挡掉（不依赖网络）。
#[test]
fn rejects_zero_len_and_version_change_before_any_io() {
    let p = provider("http://127.0.0.1:9/never");
    assert_eq!(
        p.read_range(&read_req(0, 0)).unwrap_err(),
        ProviderError::Config("len 必须大于 0".into())
    );

    let probed = probe_result(true, Some(100), Some("\"v2\""), None);
    let p = HttpProvider::from_probe(
        "http://127.0.0.1:9/never".into(),
        &probed,
        agent(),
        RequestProfile::default(),
        None,
        None,
        Vec::new(),
    );
    let mut req = read_req(0, 10);
    req.expected_version = Some(VersionToken("etag:\"v1\"".into()));
    assert_eq!(
        p.read_range(&req).unwrap_err(),
        ProviderError::VersionChanged,
        "已知版本与期望不一致必须直接拒绝"
    );

    // 版本一致时才会真正发请求：这里用不可达端口验证它走到了网络层。
    let mut req = read_req(0, 10);
    req.expected_version = Some(VersionToken("etag:\"v2\"".into()));
    assert!(matches!(
        p.read_range(&req).unwrap_err(),
        ProviderError::Network(_)
    ));
}

/// 附加：`set_health` 对 `health()` 生效（默认 Healthy）。
#[test]
fn set_health_is_observable() {
    let p = provider("http://127.0.0.1:9/never");
    assert_eq!(p.health(), Health::Healthy);
    p.set_health(Health::Observing);
    assert_eq!(p.health(), Health::Observing);
    p.set_health(Health::Suspended);
    assert_eq!(p.health(), Health::Suspended);
}

/// 9. 403 → Auth{403}（与 401 同归一类）。
#[test]
fn status_403_is_auth() {
    let (url, _seen) = spawn(|_| response("403 Forbidden", &[], b"nope"));

    let err = provider(&url)
        .read_range(&read_req(0, 10))
        .expect_err("403 必须报认证失败");
    assert_eq!(err, ProviderError::Auth { status: 403 });
}

/// 10. 206 但缺 `Content-Range` → 按"未正确支持 Range"降级（§5.3）。
#[test]
fn status_206_without_content_range_is_range_ignored() {
    let (url, _seen) = spawn(|_| response("206 Partial Content", &[], b"abc"));

    let err = provider(&url)
        .read_range(&read_req(0, 3))
        .expect_err("206 缺 Content-Range 必须降级");
    assert_eq!(err, ProviderError::RangeIgnored);
}

/// 11. 206 且 `Content-Range` 起止与请求不符 → RangeMismatch（四个字段都要对）。
#[test]
fn status_206_content_range_mismatch_is_range_mismatch() {
    let (url, _seen) = spawn(|_| {
        response(
            "206 Partial Content",
            &[("Content-Range", "bytes 0-49/1000")],
            &[b'x'; 50],
        )
    });

    let err = provider(&url)
        .read_range(&read_req(100, 10))
        .expect_err("起止不符必须报 RangeMismatch");
    assert_eq!(
        err,
        ProviderError::RangeMismatch {
            expected_start: 100,
            expected_end: 109,
            got_start: 0,
            got_end: 49,
        }
    );
}

/// 12. `Content-Encoding` 非 identity → 拒绝；identity 大小写不敏感地放行（§5.3）。
#[test]
fn content_encoding_must_be_identity() {
    let (url, _seen) = spawn(|_| {
        response(
            "206 Partial Content",
            &[
                ("Content-Range", "bytes 0-9/1000"),
                ("Content-Encoding", "gzip"),
            ],
            &[b'x'; 10],
        )
    });
    let err = provider(&url)
        .read_range(&read_req(0, 10))
        .expect_err("gzip 编码必须拒绝");
    assert_eq!(err, ProviderError::UnsupportedEncoding("gzip".into()));

    let (url, _seen) = spawn(|_| {
        response(
            "206 Partial Content",
            &[
                ("Content-Range", "bytes 0-9/1000"),
                ("Content-Encoding", "Identity"),
            ],
            &[b'x'; 10],
        )
    });
    let chunk = provider(&url)
        .read_range(&read_req(0, 10))
        .expect("identity 编码应当放行");
    assert_eq!(chunk.bytes, vec![b'x'; 10]);
}

/// 13. `expected_version` → `If-Range`；带条件却回 200 → VersionChanged（§5.2/§5.4）。
#[test]
fn expected_version_sends_if_range_and_200_is_version_changed() {
    let (url, seen) = spawn(|_| {
        response(
            "200 OK",
            &[("Content-Type", "application/octet-stream")],
            b"whole-file",
        )
    });
    let p = provider_from_probe(&url, &probe_result(true, Some(1000), Some("v1"), None));
    let mut req = read_req(0, 10);
    req.expected_version = Some(VersionToken("etag:v1".into()));

    let err = p
        .read_range(&req)
        .expect_err("带 If-Range 的 200 必须判为版本变化");
    assert_eq!(err, ProviderError::VersionChanged);

    let seen = seen.lock().unwrap();
    assert_eq!(
        seen[0].if_range.as_deref(),
        Some("v1"),
        "服务器必须收到 If-Range: v1"
    );
}

/// 14. `lm:` 前缀同样发 `If-Range`（本地无 token 也照发）；未知前缀不发条件头。
#[test]
fn if_range_from_lm_token_and_unknown_prefix() {
    let (url, seen) = spawn(|_| {
        response(
            "206 Partial Content",
            &[("Content-Range", "bytes 0-9/1000")],
            &[b'x'; 10],
        )
    });
    // 探测没拿到版本 ⇒ 本地 token 为 None；仍必须按期望版本发 If-Range。
    let p = provider_from_probe(&url, &probe_result(true, Some(1000), None, None));
    assert_eq!(p.version_token(), None, "本地确实没有版本");
    let mut req = read_req(0, 10);
    req.expected_version = Some(VersionToken("lm:Wed, 21 Oct 2026 07:28:00 GMT".into()));
    p.read_range(&req)
        .expect("lm: 条件请求 + 合法 206 应当成功");
    assert_eq!(
        seen.lock().unwrap()[0].if_range.as_deref(),
        Some("Wed, 21 Oct 2026 07:28:00 GMT"),
        "lm: 前缀必须转成 If-Range"
    );

    let (url, seen) = spawn(|_| {
        response(
            "206 Partial Content",
            &[("Content-Range", "bytes 0-9/1000")],
            &[b'x'; 10],
        )
    });
    let p = provider_from_probe(&url, &probe_result(true, Some(1000), None, None));
    let mut req = read_req(0, 10);
    req.expected_version = Some(VersionToken("platform:123".into()));
    p.read_range(&req)
        .expect("未知前缀不带条件头，206 正常返回");
    assert!(
        seen.lock().unwrap()[0].if_range.is_none(),
        "未知前缀不得发 If-Range"
    );
}

/// 15. ProviderId 是脱敏摘要（§4.9/§8.2）：不含 userinfo、查询串、签名。
#[test]
fn provider_id_is_redacted_digest() {
    let secret_url = "https://user:pw@example.com/file.bin?token=SECRET&X-Amz-Signature=abc";
    let p = provider(secret_url);
    let id = p.id();
    let raw = &id.0;
    let hex = raw.strip_prefix("u:").expect("id 必须以 u: 开头");
    assert_eq!(hex.len(), 64, "sha256 hex 必须 64 位: {raw}");
    assert!(
        hex.chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
        "必须是 64 位小写 hex: {raw}"
    );
    for bad in ["SECRET", "token", "pw", "user", "?", "X-Amz", "example"] {
        assert!(!raw.contains(bad), "id 不得包含 {bad}: {raw}");
    }
    // 原始地址只留在访问器里，供网络层使用。
    assert_eq!(p.url(), secret_url, "url() 仍返回原始地址");
    // 查询串不同 ⇒ 身份不同（不同签名的地址不能合并）。
    let other = provider("https://user:pw@example.com/file.bin?token=OTHER&X-Amz-Signature=abc");
    assert_ne!(id, other.id(), "不同查询串必须派生不同 id");
}

/// 16. 网络错误串必须脱敏（`Transport` 与 `map_probe_error` 的 connect 分支）。
#[test]
fn network_error_text_is_redacted() {
    // 127.0.0.1:9 上没有监听：ureq 的 Transport Display 会带完整 URL。
    let p = provider("http://127.0.0.1:9/f.bin?token=SECRET&X-Amz-Signature=abc");
    let err = p
        .read_range(&read_req(0, 4))
        .expect_err("连接失败必须报 Network");
    let text = err.to_string();
    assert!(
        matches!(err, ProviderError::Network(_)),
        "应归类 Network: {text}"
    );
    assert!(
        text.contains("127.0.0.1:9"),
        "Transport 错误串确实带请求地址（这正是必须脱敏的原因）: {text}"
    );
    assert!(!text.contains("SECRET"), "错误串不得含查询串凭据: {text}");
    assert!(!text.contains("abc"), "错误串不得含签名值: {text}");

    // 同一路径经 refresh() → probe() 的 `connect: …` 分支。
    let p = provider("http://127.0.0.1:9/f.bin?token=SECRET");
    let err = p.refresh().expect_err("不可达地址的 refresh 必须失败");
    let text = err.to_string();
    assert!(
        matches!(err, ProviderError::Network(_)),
        "应归类 Network: {text}"
    );
    assert!(
        text.contains("127.0.0.1:9"),
        "connect 分支确实带请求地址: {text}"
    );
    assert!(
        !text.contains("SECRET"),
        "connect 分支的错误串必须脱敏: {text}"
    );
}

/// 17. refresh 成功：能力与版本都换成新探测值（206 + ETag）。
#[test]
fn refresh_success_updates_capabilities_and_version() {
    let (url, seen) = spawn(|_| {
        response(
            "206 Partial Content",
            &[
                ("Content-Range", "bytes 0-0/1000"),
                ("ETag", "v2"),
                ("Content-Type", "application/octet-stream"),
            ],
            b"v",
        )
    });
    let p = provider_from_probe(&url, &probe_result(true, Some(1000), Some("v1"), None));
    assert_eq!(p.version_token(), Some(VersionToken("etag:v1".into())));

    p.refresh().expect("探测 206 + ETag 应当成功");

    let caps = p.capabilities();
    assert!(caps.random_read, "206 + 合法 Content-Range ⇒ random_read");
    assert!(caps.resume);
    assert!(caps.length_query, "有总长 ⇒ length_query");
    assert!(caps.version_check, "有 ETag ⇒ version_check");
    assert_eq!(caps.conns_max, 4);
    assert_eq!(
        p.version_token(),
        Some(VersionToken("etag:v2".into())),
        "refresh 必须换成新版本"
    );
    assert_eq!(
        seen.lock().unwrap()[0].range.as_deref(),
        Some("bytes=0-0"),
        "refresh 应重新探测"
    );
}

/// 18. refresh 遇 401：报 Auth 且能力/版本退回未验证（§3.3）。
#[test]
fn refresh_401_is_auth_and_clears_capabilities() {
    let (url, _seen) =
        spawn(|_| response("401 Unauthorized", &[("WWW-Authenticate", "Basic")], b""));
    let p = provider_from_probe(&url, &probe_result(true, Some(1000), Some("v1"), None));
    assert!(p.capabilities().random_read, "初始能力来自探测");

    let err = p.refresh().expect_err("401 必须报认证失败");
    assert_eq!(err, ProviderError::Auth { status: 401 });
    assert_eq!(
        p.capabilities(),
        SourceCapabilities::default(),
        "探测失败后能力必须全部为 false"
    );
    assert_eq!(p.version_token(), None, "探测失败后版本必须清空");
}

/// 19. refresh 遇 500：报 Http{500} 且能力/版本退回未验证。
#[test]
fn refresh_500_is_http_and_clears_capabilities() {
    let (url, _seen) = spawn(|_| response("500 Internal Server Error", &[], b""));
    let p = provider_from_probe(&url, &probe_result(true, Some(1000), Some("v1"), None));
    assert!(p.capabilities().random_read, "初始能力来自探测");

    let err = p.refresh().expect_err("500 必须报 HTTP 失败");
    assert_eq!(err, ProviderError::Http { status: 500 });
    assert_eq!(
        p.capabilities(),
        SourceCapabilities::default(),
        "探测失败后能力必须全部为 false"
    );
    assert_eq!(p.version_token(), None, "探测失败后版本必须清空");
}

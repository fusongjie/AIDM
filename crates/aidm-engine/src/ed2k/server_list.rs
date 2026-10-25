//! 公共 eD2k 服务器列表（`server.met`）的取回。
//!
//! 与 Kad 的 `nodes.dat` 不同，这里**不建缓存表**：`server.met` 的结果就是一份
//! `ip:port` 列表，而它唯一的消费者是 `ed2k.servers` 设置。所以刷新的语义是
//! 「取回 → 解析 → **写回设置**」，用户可以在此基础上继续手工编辑。
//!
//! 这样既不改动既有语义（`ed2k.servers` 为空仍表示"不查服务器"），也不引入
//! 第二份互相覆盖的权威。

use std::io::Read;

use aidm_core::ed2k::server_met::{ServerList, MAX_SERVER_MET_BYTES};

/// 取回并解析 `server.met`。只接受 HTTP 200；正文有上限。
pub fn fetch_server_met(agent: &ureq::Agent, url: &str) -> Result<ServerList, String> {
    let resp = match agent.get(url).call() {
        Ok(r) => r,
        Err(ureq::Error::Status(code, _)) => return Err(format!("server_met_http_{code}")),
        Err(e) => return Err(format!("server_met_http: {e}")),
    };
    if resp.status() != 200 {
        return Err(format!("server_met_http_{}", resp.status()));
    }
    let mut doc = Vec::new();
    resp.into_reader()
        .take(MAX_SERVER_MET_BYTES + 1)
        .read_to_end(&mut doc)
        .map_err(|e| format!("server_met_read: {e}"))?;
    aidm_core::ed2k::server_met::parse(&doc)
        .map_err(|e| format!("server_met_invalid: {}", e.code()))
}

/// 把服务器列表渲染成 `ed2k.servers` 的存储形态（逗号分隔的 `ip:port`）。
///
/// 去重并保持原顺序：`server.met` 里同一台服务器可能重复出现。
pub fn endpoints_setting(list: &ServerList) -> String {
    let mut seen = Vec::new();
    for (ip, port) in list.endpoints() {
        let one = format!("{ip}:{port}");
        if !seen.contains(&one) {
            seen.push(one);
        }
    }
    seen.join(",")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::net::TcpListener;
    use std::path::Path;

    fn fixture(name: &str) -> Vec<u8> {
        let p = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../aidm-core/tests/fixtures/ed2k")
            .join(name);
        std::fs::read(&p).unwrap_or_else(|e| panic!("读取 {} 失败: {e}", p.display()))
    }

    fn serve_once(status: &'static str, body: Vec<u8>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            // 只服务一个连接：`accept` 一次就够。写成
            // `for stream in listener.incoming() { …; break }` 会触发 clippy 的
            // `never_loop`（错误级），而且这里本来也没有"循环"这回事。
            let Ok((mut s, _)) = listener.accept() else {
                return;
            };
            let mut buf = [0u8; 2048];
            let _ = std::io::Read::read(&mut s, &mut buf);
            let head = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = s.write_all(head.as_bytes());
            let _ = s.write_all(&body);
            let _ = s.flush();
        });
        format!("http://{addr}/server.met")
    }

    #[test]
    fn fetches_and_parses_a_real_server_met() {
        let body = fixture("emule-security-server.met");
        let url = serve_once("200 OK", body);
        let agent = ureq::AgentBuilder::new().build();
        let list = fetch_server_met(&agent, &url).unwrap();
        // 夹具是采集的 emule-security 列表，实测 14 台
        assert_eq!(list.servers.len(), 14);
        let text = endpoints_setting(&list);
        assert!(text.contains(':'), "{text}");
        assert_eq!(text.split(',').count(), 14);
    }

    #[test]
    fn rejects_garbage_and_http_errors() {
        let agent = ureq::AgentBuilder::new().build();
        let url = serve_once("200 OK", vec![0xAA, 0xBB, 0xCC]);
        let err = fetch_server_met(&agent, &url).unwrap_err();
        assert!(err.starts_with("server_met_invalid:"), "{err}");

        let url = serve_once("404 Not Found", b"nope".to_vec());
        assert_eq!(
            fetch_server_met(&agent, &url).unwrap_err(),
            "server_met_http_404"
        );
    }

    #[test]
    fn setting_text_is_deduped_and_ordered() {
        let body = fixture("gruk-server.met");
        let url = serve_once("200 OK", body);
        let agent = ureq::AgentBuilder::new().build();
        let list = fetch_server_met(&agent, &url).unwrap();
        let text = endpoints_setting(&list);
        let parts: Vec<&str> = text.split(',').collect();
        // 顺序与原文件一致
        let first = list.endpoints()[0];
        assert_eq!(parts[0], format!("{}:{}", first.0, first.1));
        // 无重复
        let mut uniq = parts.clone();
        uniq.sort_unstable();
        uniq.dedup();
        assert_eq!(uniq.len(), parts.len(), "不应有重复端点: {text}");
    }
}

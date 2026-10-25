//! stdio 端到端（R-MCPS-01）：真实子进程、真实管道、一行一条消息。

mod common;

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{json, Value};

#[test]
fn multiple_requests_are_answered_in_order_on_one_pipe() {
    let mut mcp = common::Mcp::spawn(false);

    let discover = mcp.call(1, "server/discover", json!({}));
    let list = mcp.call_modern(2, "tools/list", json!({}));
    let unknown = mcp.call(3, "no/such/method", json!({}));

    assert_eq!(discover["id"], json!(1));
    assert_eq!(list["id"], json!(2));
    assert_eq!(unknown["id"], json!(3));
    assert_eq!(unknown["error"]["code"], json!(-32601));
}

#[test]
fn notification_produces_no_response() {
    let mut mcp = common::Mcp::spawn(false);
    // 先握手再发通知；随后用一个请求当"栅栏"：如果通知产生了响应，
    // 栅栏读到的就会是那条多余的响应而不是 id=9。
    let init = mcp.call(
        1,
        "initialize",
        json!({"protocolVersion": "2025-11-25", "capabilities": {}}),
    );
    assert!(init["result"].is_object());
    mcp.notify("notifications/initialized");
    mcp.notify("notifications/cancelled");

    let response = mcp.call(9, "tools/list", json!({}));
    assert_eq!(response["id"], json!(9));
}

#[test]
fn stdout_contains_only_valid_json_lines() {
    // 直接跑原始管道，验证"每行都是合法 JSON、没有杂讯"。
    let exe = env!("CARGO_BIN_EXE_aidm-mcp");
    let dir = common::TempDir::new("stdio-raw");
    let mut child = Command::new(exe)
        .env("LOCALAPPDATA", dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("拉起 aidm-mcp");

    {
        let stdin = child.stdin.as_mut().unwrap();
        for line in [
            r#"{"jsonrpc":"2.0","id":1,"method":"server/discover"}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#,
        ] {
            stdin.write_all(line.as_bytes()).unwrap();
            stdin.write_all(b"\n").unwrap();
        }
        stdin.flush().unwrap();
    }

    // 关闭 stdin → 服务读到 EOF 必须自行退出。
    child.stdin.take();
    let status = child.wait().expect("等待子进程退出");
    assert!(status.success(), "EOF 后应正常退出");

    let mut lines = String::new();
    use std::io::Read;
    child.stdout.take().unwrap().read_to_string(&mut lines).unwrap();
    let lines: Vec<&str> = lines.lines().filter(|line| !line.trim().is_empty()).collect();
    assert_eq!(lines.len(), 3, "三条请求应产生三条响应，实际：{lines:?}");
    for line in lines {
        let value: Value = serde_json::from_str(line).expect("stdout 出现非 JSON 内容");
        assert_eq!(value["jsonrpc"], json!("2.0"));
    }
}

#[test]
fn blank_lines_are_ignored() {
    let mut mcp = common::Mcp::spawn(false);
    mcp.send_raw("");
    mcp.send_raw("   ");
    let response = mcp.call(5, "server/discover", json!({}));
    assert_eq!(response["id"], json!(5));
}

#[test]
fn eof_shuts_down_the_process() {
    let exe = env!("CARGO_BIN_EXE_aidm-mcp");
    let dir = common::TempDir::new("stdio-eof");
    let mut child = Command::new(exe)
        .env("LOCALAPPDATA", dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("拉起 aidm-mcp");

    child.stdin.take();
    let status = child.wait().expect("等待退出");
    assert!(status.success(), "stdin EOF 是标准关闭信号，应正常退出");
}

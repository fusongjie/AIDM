//! 审计与脱敏（R-MCPS-12）：stderr 有审计行，但不含 URL 查询串。

mod common;

use std::time::Duration;

use serde_json::json;

#[test]
fn audit_line_is_written_without_parameter_values() {
    let stub = common::start_stub(|_| common::ok_response(json!({"id": 11})));
    let mut mcp = common::Mcp::spawn(true);
    mcp.write_port(stub.port);

    let response = mcp.call_modern(
        1,
        "tools/call",
        json!({
            "name": "aidm_add",
            "arguments": {"url": "https://example.com/a.bin?token=supersecret123"},
        }),
    );
    assert_eq!(response["result"]["structuredContent"]["id"], json!(11));

    assert!(
        mcp.wait_stderr("tool=aidm_add", Duration::from_secs(3)),
        "应有一条工具审计行，实际 stderr：{}",
        mcp.stderr()
    );
    let log = mcp.stderr();
    assert!(
        !log.contains("supersecret123"),
        "审计不得记录参数值（URL 查询串）：{log}"
    );
    assert!(
        !log.contains("token="),
        "审计不得记录查询串：{log}"
    );
}

#[test]
fn rpc_errors_are_audited_by_code_not_by_message() {
    let mut mcp = common::Mcp::spawn(true);
    let _ = mcp.call_modern(
        1,
        "tools/call",
        json!({
            "name": "aidm_add",
            "arguments": {"url": "https://example.com/a.bin?token=anothersecret"},
        }),
    );
    assert!(
        mcp.wait_stderr("rpc_error=", Duration::from_secs(3)),
        "未授权/参数错误应有审计行：{}",
        mcp.stderr()
    );
    assert!(!mcp.stderr().contains("anothersecret"));
}

#[test]
fn stdout_stays_clean_when_help_or_version_is_requested() {
    // --version 写到 stderr；stdout 必须一条协议消息都没有。
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_aidm-mcp"))
        .arg("--version")
        .output()
        .expect("运行 aidm-mcp --version");
    assert!(output.status.success());
    assert!(
        output.stdout.is_empty(),
        "帮助/版本不得污染 stdout：{:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("aidm-mcp"));
}

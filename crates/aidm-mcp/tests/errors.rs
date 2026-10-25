//! 错误三层（R-MCPS-07）：协议错误用 JSON-RPC 码，业务失败用 `isError`。

mod common;

use serde_json::json;

#[test]
fn malformed_json_is_parse_error_with_null_id() {
    let mut mcp = common::Mcp::spawn(false);
    mcp.send_raw("{not valid json");
    let response = mcp.recv();
    assert_eq!(response["error"]["code"], json!(-32700));
    assert_eq!(response["id"], json!(null));
}

#[test]
fn bad_envelope_is_invalid_request() {
    let mut mcp = common::Mcp::spawn(false);
    mcp.send(&json!({"jsonrpc": "1.0", "id": 1, "method": "ping"}));
    let response = mcp.recv();
    assert_eq!(response["error"]["code"], json!(-32600));
    // JSON-RPC 2.0：无法确认请求 id 时，错误响应的 id 必须是 null。
    assert_eq!(response["id"], json!(null));
}

#[test]
fn null_id_is_rejected() {
    let mut mcp = common::Mcp::spawn(false);
    mcp.send(&json!({"jsonrpc": "2.0", "id": null, "method": "ping"}));
    let response = mcp.recv();
    assert_eq!(response["error"]["code"], json!(-32600));
}

#[test]
fn unknown_method_is_method_not_found() {
    let mut mcp = common::Mcp::spawn(false);
    let response = mcp.call(1, "tools/explode", json!({}));
    assert_eq!(response["error"]["code"], json!(-32601));
    assert!(response["error"]["message"]
        .as_str()
        .unwrap()
        .contains("tools/explode"));
}

#[test]
fn non_object_params_is_invalid_params() {
    let mut mcp = common::Mcp::spawn(false);
    mcp.send(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": [1, 2, 3],
    }));
    let response = mcp.recv();
    assert_eq!(response["error"]["code"], json!(-32602));
}

#[test]
fn unknown_tool_is_method_not_found() {
    let mut mcp = common::Mcp::spawn(false);
    let response = mcp.call_modern(
        1,
        "tools/call",
        json!({"name": "aidm_delete_everything", "arguments": {}}),
    );
    assert_eq!(response["error"]["code"], json!(-32601));
}

#[test]
fn engine_absence_is_internal_error_with_a_stable_code() {
    let mut mcp = common::Mcp::spawn(false);
    mcp.remove_port();
    let response = mcp.call_modern(
        1,
        "tools/call",
        json!({"name": "aidm_status", "arguments": {"id": 1}}),
    );
    assert_eq!(response["error"]["code"], json!(-32603));
    assert_eq!(
        response["error"]["data"]["code"],
        json!("engine_unreachable"),
        "MCP 自己的稳定码必须放 data.code"
    );
    assert!(
        response["result"].is_null(),
        "协议层错误不应带 result"
    );
}

#[test]
fn business_failure_is_is_error_not_protocol_error() {
    let stub = common::start_stub(|_| {
        json!({
            "ok": false,
            "version": "0.1.0",
            "code": "bad_url",
            "error": "链接格式不合法",
        })
    });
    let mut mcp = common::Mcp::spawn(true);
    mcp.write_port(stub.port);

    let response = mcp.call_modern(
        1,
        "tools/call",
        json!({"name": "aidm_status", "arguments": {"id": 1}}),
    );
    assert!(response["error"].is_null(), "业务失败不能是协议错误");
    assert_eq!(response["result"]["isError"], json!(true));
    assert_eq!(
        response["result"]["structuredContent"]["code"],
        json!("bad_url")
    );
}

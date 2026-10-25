//! 版本策略（R-MCPS-02）：modern 无握手、legacy 握手、版本不支持时的结构化拒绝。

mod common;

use serde_json::json;

#[test]
fn modern_request_with_meta_succeeds() {
    let mut mcp = common::Mcp::spawn(false);
    let response = mcp.call_modern(1, "tools/list", json!({}));
    assert!(response["result"]["tools"].is_array(), "{response}");
}

#[test]
fn modern_request_without_meta_is_rejected() {
    let mut mcp = common::Mcp::spawn(false);
    // 没有 initialize、也没有 _meta：无法判断用哪套语义。
    let response = mcp.call(1, "tools/list", json!({}));
    assert_eq!(response["error"]["code"], json!(-32600));
}

#[test]
fn unsupported_version_lists_supported_versions() {
    let mut mcp = common::Mcp::spawn(false);
    let params = json!({
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2099-01-01",
            "io.modelcontextprotocol/clientCapabilities": {},
        }
    });
    let response = mcp.call(1, "tools/list", params);
    assert_eq!(response["error"]["code"], json!(-32022));
    assert_eq!(
        response["error"]["data"]["supported"],
        json!(["2026-07-28"])
    );
    assert_eq!(
        response["error"]["data"]["requested"],
        json!("2099-01-01")
    );
}

#[test]
fn meta_must_carry_client_capabilities() {
    let mut mcp = common::Mcp::spawn(false);
    let params = json!({
        "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}
    });
    let response = mcp.call(1, "tools/list", params);
    assert_eq!(response["error"]["code"], json!(-32600));
}

#[test]
fn legacy_handshake_then_requests_without_meta() {
    let mut mcp = common::Mcp::spawn(false);
    let init = mcp.call(
        1,
        "initialize",
        json!({
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1.0"},
        }),
    );
    assert_eq!(init["result"]["protocolVersion"], json!("2025-11-25"));
    assert!(init["result"]["capabilities"]["tools"].is_object());
    assert_eq!(init["result"]["serverInfo"]["name"], json!("aidm-mcp"));

    mcp.notify("notifications/initialized");

    // legacy 会话内不要求 _meta；响应不带 resultType（旧客户端不需要）。
    let list = mcp.call(2, "tools/list", json!({}));
    assert_eq!(list["result"]["tools"].as_array().unwrap().len(), 11);
    assert!(
        list["result"].get("resultType").is_none(),
        "legacy 响应不应伪造 resultType"
    );
}

#[test]
fn legacy_initialize_negotiates_a_supported_version() {
    let mut mcp = common::Mcp::spawn(false);
    // 客户端报一个我们不支持的版本：服务器回自己最高的 legacy 版本。
    let init = mcp.call(1, "initialize", json!({"protocolVersion": "2024-01-01"}));
    assert_eq!(init["result"]["protocolVersion"], json!("2025-11-25"));
}

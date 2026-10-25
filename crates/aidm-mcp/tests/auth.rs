//! 授权模型（R-MCPS-11）：默认只读、`--allow-write` 才写、调用侧必须再判一次。

mod common;

use serde_json::json;

fn listed(mcp: &mut common::Mcp) -> Vec<String> {
    let response = mcp.call_modern(1, "tools/list", json!({}));
    response["result"]["tools"]
        .as_array()
        .expect("tools 数组")
        .iter()
        .map(|tool| tool["name"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn default_exposes_only_read_tools() {
    let mut mcp = common::Mcp::spawn(false);
    let names = listed(&mut mcp);
    assert_eq!(names.len(), 11, "默认只读应为 11 个（含 aidm_wait）：{names:?}");
    for write in ["aidm_add", "aidm_cancel", "aidm_settings_set"] {
        assert!(!names.contains(&write.to_string()), "{write} 不应默认暴露");
    }
    assert!(names.contains(&"aidm_status".to_string()));
}

#[test]
fn allow_write_exposes_all_tools() {
    let mut mcp = common::Mcp::spawn(true);
    assert_eq!(listed(&mut mcp).len(), 24);
}

#[test]
fn calling_a_write_tool_without_authorization_is_rejected() {
    let mut mcp = common::Mcp::spawn(false);
    let response = mcp.call_modern(
        1,
        "tools/call",
        json!({"name": "aidm_add", "arguments": {"url": "https://example.com/a.bin"}}),
    );
    assert_eq!(response["error"]["code"], json!(-32602));
    assert_eq!(response["error"]["data"]["code"], json!("not_authorized"));
}

#[test]
fn authorization_is_checked_even_if_the_tool_is_not_listed() {
    // 即使客户端跳过 tools/list 直接调用，也必须被拒——列表过滤只是 UX。
    let mut mcp = common::Mcp::spawn(false);
    let response = mcp.call_modern(
        1,
        "tools/call",
        json!({"name": "aidm_restart", "arguments": {"id": 1}}),
    );
    assert_eq!(response["error"]["data"]["code"], json!("not_authorized"));
}

#[test]
fn read_tool_reaches_the_engine_layer_instead_of_auth_layer() {
    // 只读工具在默认授权下应放行到 IPC 层：没有引擎时得到 engine_unreachable，
    // 而不是 not_authorized。
    let mut mcp = common::Mcp::spawn(false);
    mcp.remove_port();
    let response = mcp.call_modern(
        1,
        "tools/call",
        json!({"name": "aidm_status", "arguments": {"id": 1}}),
    );
    assert_eq!(response["error"]["code"], json!(-32603));
    assert_eq!(response["error"]["data"]["code"], json!("engine_unreachable"));
}

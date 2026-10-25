//! 参数闸门（R-MCPS-11）：全部在触网之前拒绝，因此不需要假引擎。

mod common;

use serde_json::{json, Value};

fn tool_call(mcp: &mut common::Mcp, name: &str, arguments: Value) -> Value {
    mcp.call_modern(
        1,
        "tools/call",
        json!({"name": name, "arguments": arguments}),
    )
}

fn assert_invalid_params(response: &Value, needle: &str) {
    assert_eq!(
        response["error"]["code"],
        json!(-32602),
        "期望参数错误，实际：{response}"
    );
    let message = response["error"]["message"].as_str().unwrap_or("");
    assert!(
        message.contains(needle),
        "错误信息应包含 {needle:?}，实际：{message}"
    );
}

#[test]
fn batch_of_101_urls_is_rejected() {
    let mut mcp = common::Mcp::spawn(true);
    let urls: Vec<String> = (0..=100)
        .map(|index| format!("https://example.com/{index}.bin"))
        .collect();
    let response = tool_call(&mut mcp, "aidm_add_batch", json!({"urls": urls}));
    assert_invalid_params(&response, "最多");
}

#[test]
fn relative_directory_is_rejected() {
    let mut mcp = common::Mcp::spawn(true);
    let response = tool_call(
        &mut mcp,
        "aidm_add",
        json!({"url": "https://example.com/a.bin", "dir": "relative/dir"}),
    );
    assert_invalid_params(&response, "绝对路径");
}

#[test]
fn settings_whitelist_is_closed() {
    let mut mcp = common::Mcp::spawn(true);
    for key in ["proxy.pass", "s3.secret_key", "update.channel", "paths.default_dir"] {
        let response = tool_call(
            &mut mcp,
            "aidm_settings_set",
            json!({"key": key, "value": "x"}),
        );
        assert_invalid_params(&response, "白名单");
    }
    // 白名单内的键应放行到 IPC 层（无引擎 → engine_unreachable）。
    let allowed = tool_call(
        &mut mcp,
        "aidm_settings_set",
        json!({"key": "sched.window_enabled", "value": "true"}),
    );
    assert_eq!(allowed["error"]["data"]["code"], json!("engine_unreachable"));
}

#[test]
fn cookies_are_not_a_parameter() {
    let mut mcp = common::Mcp::spawn(true);
    let response = tool_call(
        &mut mcp,
        "aidm_add",
        json!({"url": "https://example.com/a.bin", "cookies": "session=1"}),
    );
    assert_invalid_params(&response, "未知参数");
}

#[test]
fn misspelled_parameters_are_not_silently_ignored() {
    let mut mcp = common::Mcp::spawn(true);
    let response = tool_call(
        &mut mcp,
        "aidm_add",
        json!({"url": "https://example.com/a.bin", "speed_limit": 100}),
    );
    assert_invalid_params(&response, "未知参数");
    assert!(
        response["error"]["message"]
            .as_str()
            .unwrap()
            .contains("speed_limit_kbps"),
        "错误应提示正确字段名"
    );
}

#[test]
fn wrong_types_are_rejected() {
    let mut mcp = common::Mcp::spawn(true);
    let response = tool_call(
        &mut mcp,
        "aidm_status",
        json!({"id": "not-a-number"}),
    );
    assert_invalid_params(&response, "类型不符");
}

#[test]
fn missing_required_parameter_is_rejected() {
    let mut mcp = common::Mcp::spawn(true);
    let response = tool_call(&mut mcp, "aidm_rename", json!({"id": 3}));
    assert_invalid_params(&response, "缺少必填参数");
}

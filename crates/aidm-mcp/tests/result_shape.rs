//! 结果形状（R-MCPS-06）：`structuredContent` 原样透传，不裁剪、不改名。

mod common;

use serde_json::json;

#[test]
fn structured_content_is_the_engine_response_verbatim() {
    let engine_response = json!({
        "ok": true,
        "version": "0.1.0",
        "id": 42,
        "task": {
            "id": 42,
            "name": "a.bin",
            "state": "downloading",
            "done": 10,
            "speed": 1,
            "save_path": "C:\\dl\\a.bin",
        },
        "added": [],
    });
    let expected = engine_response.clone();
    let stub = common::start_stub(move |_| expected.clone());
    let mut mcp = common::Mcp::spawn(false);
    mcp.write_port(stub.port);

    let response = mcp.call_modern(
        1,
        "tools/call",
        json!({"name": "aidm_status", "arguments": {"id": 42}}),
    );
    let result = &response["result"];
    assert_eq!(
        result["structuredContent"], engine_response,
        "字段必须原样保留（包括 null 与可选字段）"
    );
    assert_eq!(result["resultType"], json!("complete"));
    assert!(result.get("isError").is_none(), "成功时不应带 isError");

    // 文本块必须能还原出同一对象（B-4 的向后兼容建议）。
    let text = result["content"][0]["text"].as_str().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(parsed, engine_response);
    assert_eq!(result["content"][0]["type"], json!("text"));
}

#[test]
fn failure_keeps_the_code_inside_structured_content() {
    let stub = common::start_stub(|_| {
        json!({
            "ok": false,
            "version": "0.1.0",
            "error": "任务不存在",
            "code": "task_not_found",
        })
    });
    let mut mcp = common::Mcp::spawn(false);
    mcp.write_port(stub.port);

    let response = mcp.call_modern(
        1,
        "tools/call",
        json!({"name": "aidm_status", "arguments": {"id": 999}}),
    );
    let result = &response["result"];
    assert_eq!(result["isError"], json!(true));
    assert_eq!(result["structuredContent"]["code"], json!("task_not_found"));
    assert_eq!(result["structuredContent"]["ok"], json!(false));
    // 人类可读说明仍在原字段，不被改写成 MCP 的错误信息。
    assert_eq!(result["structuredContent"]["error"], json!("任务不存在"));
}

#[test]
fn legacy_requests_omit_result_type() {
    let stub = common::start_stub(|_| {
        common::ok_response(json!({
            "task": {
                "id": 1, "name": "a.bin", "state": "paused",
                "done": 1, "speed": 0, "save_path": r"C:\dl\a.bin"
            }
        }))
    });
    let mut mcp = common::Mcp::spawn(false);
    mcp.write_port(stub.port);
    mcp.legacy_handshake();

    let response = mcp.call(
        2,
        "tools/call",
        json!({"name": "aidm_status", "arguments": {"id": 1}}),
    );
    assert_eq!(response["result"]["structuredContent"]["ok"], json!(true));
    assert!(
        response["result"].get("resultType").is_none(),
        "legacy 结果不应带 resultType"
    );
}

#[test]
fn capabilities_note_is_preserved() {
    // R-MCP-14：note 是唯一能表达"识别得出但下不了"的字段，绝不能丢。
    let stub = common::start_stub(|_| {
        common::ok_response(json!({
            "capabilities": {
                "transport": "http",
                "resource": "plain_file",
                "capabilities": {
                    "pause": true, "resume": true, "segment": true, "seek": true,
                    "multi_source": false, "manifest": false, "verify": false, "seed": false
                },
                "note": "服务已停运，实际无法下载",
            }
        }))
    });
    let mut mcp = common::Mcp::spawn(false);
    mcp.write_port(stub.port);

    let response = mcp.call_modern(
        1,
        "tools/call",
        json!({"name": "aidm_capabilities", "arguments": {"url": "fs2you://abc"}}),
    );
    assert_eq!(
        response["result"]["structuredContent"]["capabilities"]["note"],
        json!("服务已停运，实际无法下载")
    );
}

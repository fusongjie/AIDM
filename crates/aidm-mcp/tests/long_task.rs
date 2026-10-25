//! 长任务语义（R-MCPS-08）：建任务立即返回 id，进度靠轮询，绝不在调用内等完成。

mod common;

use std::time::{Duration, Instant};

use serde_json::json;

#[test]
fn add_returns_immediately_with_only_the_id() {
    // 用 id 的取值证明 op 被翻译成 add（未知字段会在 EngineResponse 反序列化时被丢弃，
    // 所以不能用 echo 字段）。
    let stub = common::start_stub(|request| {
        let id = if request["op"] == json!("add") { 7 } else { 0 };
        common::ok_response(json!({"id": id}))
    });
    let mut mcp = common::Mcp::spawn(true);
    mcp.write_port(stub.port);

    let started = Instant::now();
    let response = mcp.call_modern(
        1,
        "tools/call",
        json!({
            "name": "aidm_add",
            "arguments": {"url": "https://example.com/big.iso", "source": "manual"},
        }),
    );
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_millis(500),
        "add 必须在引擎回包后立即返回，实际 {elapsed:?}"
    );

    let content = &response["result"]["structuredContent"];
    assert_eq!(content["id"], json!(7), "op 必须被翻译成 add");
    // 没有等待下载完成的痕迹：响应里不应出现完成态字段。
    assert!(content.get("file_path").is_none());
    assert!(content.get("done").is_none());
}

#[test]
fn progress_is_read_through_status_polling() {
    let stub = common::start_stub(|request| match request["op"].as_str() {
        Some("add") => common::ok_response(json!({"id": 9})),
        Some("status") => common::ok_response(json!({
            "task": {
                "id": 9, "name": "big.iso", "state": "downloading",
                "done": 512, "total": 1024, "pct": 50.0, "speed": 10,
                "save_path": r"C:\dl\big.iso"
            }
        })),
        other => panic!("意外 op: {other:?}"),
    });
    let mut mcp = common::Mcp::spawn(true);
    mcp.write_port(stub.port);

    let add = mcp.call_modern(
        1,
        "tools/call",
        json!({"name": "aidm_add", "arguments": {"url": "https://example.com/big.iso"}}),
    );
    assert_eq!(add["result"]["structuredContent"]["id"], json!(9));

    let status = mcp.call_modern(
        2,
        "tools/call",
        json!({"name": "aidm_status", "arguments": {"id": 9}}),
    );
    let task = &status["result"]["structuredContent"]["task"];
    assert_eq!(task["state"], json!("downloading"));
    assert_eq!(task["pct"], json!(50.0));
}

#[test]
fn batch_reports_per_item_and_keeps_input_order() {
    let stub = common::start_stub(|request| {
        let urls = request["urls"].as_array().unwrap().clone();
        let added: Vec<serde_json::Value> = urls
            .iter()
            .enumerate()
            .map(|(index, url)| {
                json!({"url": url, "id": index + 1})
            })
            .collect();
        let id = if request["op"] == json!("add_batch") { 1 } else { 0 };
        common::ok_response(json!({"added": added, "id": id}))
    });
    let mut mcp = common::Mcp::spawn(true);
    mcp.write_port(stub.port);

    let urls = json!([
        "https://example.com/a.bin",
        "https://example.com/b.bin",
        "https://example.com/c.bin",
    ]);
    let response = mcp.call_modern(
        1,
        "tools/call",
        json!({"name": "aidm_add_batch", "arguments": {"urls": urls}}),
    );
    assert_eq!(
        response["result"]["structuredContent"]["id"],
        json!(1),
        "op 必须被翻译成 add_batch"
    );
    let added = response["result"]["structuredContent"]["added"]
        .as_array()
        .unwrap();
    assert_eq!(added.len(), 3);
    assert_eq!(added[0]["url"], json!("https://example.com/a.bin"));
    assert_eq!(added[2]["id"], json!(3));
}

#[test]
fn diag_export_is_allowed_a_longer_budget_but_still_synchronous() {
    let stub = common::start_stub(|request| {
        assert_eq!(request["op"], json!("diag_export"));
        common::ok_response(json!({"diag_path": "C:\\tmp\\diag.zip"}))
    });
    let mut mcp = common::Mcp::spawn(true);
    mcp.write_port(stub.port);

    let response = mcp.call_modern(
        1,
        "tools/call",
        json!({"name": "aidm_diag_export", "arguments": {"id": 3}}),
    );
    assert_eq!(
        response["result"]["structuredContent"]["diag_path"],
        json!("C:\\tmp\\diag.zip")
    );
}

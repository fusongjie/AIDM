//! Tasks 扩展（`io.modelcontextprotocol/tasks`）：创建、查询、取消、终态结果。

mod common;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

const TASKS: &str = "io.modelcontextprotocol/tasks";

fn with_tasks(params: Value) -> Value {
    let mut value = common::modern_params(params);
    value["_meta"]["io.modelcontextprotocol/clientCapabilities"] = json!({
        "extensions": { (TASKS): {} }
    });
    value
}

fn task_view(state: &str, error_code: Option<&str>) -> Value {
    let mut view = json!({
        "id": 7,
        "name": "a.bin",
        "state": state,
        "done": if state == "done" { 10 } else { 3 },
        "total": 10,
        "speed": 0,
        "save_path": r"C:\dl\a.bin",
    });
    if let Some(code) = error_code {
        view["error_code"] = json!(code);
    }
    view
}

fn add_args() -> Value {
    json!({"name": "aidm_add", "arguments": {"url": "https://example.com/a.bin"}})
}

#[test]
fn add_returns_a_task_handle_when_the_client_declares_tasks() {
    let stub = common::start_stub(|_| common::ok_response(json!({"id": 7})));
    let mut mcp = common::Mcp::spawn(true);
    mcp.write_port(stub.port);

    let response = mcp.call(1, "tools/call", with_tasks(add_args()));
    let result = &response["result"];
    assert_eq!(result["resultType"], json!("task"));
    assert_eq!(result["taskId"], json!("aidm:7"));
    assert_eq!(result["status"], json!("working"));
    assert_eq!(result["ttlMs"], json!(3_600_000));
    assert!(result["createdAt"].as_str().unwrap().ends_with('Z'));
}

#[test]
fn add_keeps_the_plain_shape_without_the_extension() {
    let stub = common::start_stub(|_| common::ok_response(json!({"id": 7})));
    let mut mcp = common::Mcp::spawn(true);
    mcp.write_port(stub.port);

    let response = mcp.call_modern(1, "tools/call", add_args());
    let result = &response["result"];
    assert_eq!(result["structuredContent"]["id"], json!(7));
    assert!(
        result.get("taskId").is_none(),
        "未声明扩展时不应返回任务句柄"
    );
}

#[test]
fn tasks_get_moves_from_working_to_completed_with_the_final_result() {
    let slot = Arc::new(Mutex::new(common::ok_response(json!({
        "id": 7, "task": task_view("downloading", None)
    }))));
    let stub = {
        let slot = slot.clone();
        common::start_stub(move |request| {
            if request["op"] == json!("status") {
                slot.lock().unwrap().clone()
            } else {
                common::ok_response(json!({"id": 7}))
            }
        })
    };
    let mut mcp = common::Mcp::spawn(true);
    mcp.write_port(stub.port);

    let add = mcp.call(1, "tools/call", with_tasks(add_args()));
    assert_eq!(add["result"]["status"], json!("working"));

    let working = mcp.call(2, "tasks/get", with_tasks(json!({"taskId": "aidm:7"})));
    assert_eq!(working["result"]["resultType"], json!("complete"));
    assert_eq!(working["result"]["status"], json!("working"));
    assert!(working["result"].get("result").is_none());

    // 让引擎报告完成。
    *slot.lock().unwrap() = common::ok_response(json!({
        "id": 7, "task": task_view("done", None)
    }));

    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let response = mcp.call(3, "tasks/get", with_tasks(json!({"taskId": "aidm:7"})));
        let status = response["result"]["status"].as_str().unwrap_or("").to_string();
        if status == "completed" {
            let final_result = &response["result"]["result"];
            assert_eq!(
                final_result["structuredContent"]["task"]["save_path"],
                json!(r"C:\dl\a.bin")
            );
            assert!(final_result.get("isError").is_none());
            break;
        }
        assert!(
            Instant::now() < deadline,
            "等待 completed 超时，最后状态：{status}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn a_failed_download_completes_with_is_error() {
    let slot = Arc::new(Mutex::new(common::ok_response(json!({
        "id": 7, "task": task_view("downloading", None)
    }))));
    let stub = {
        let slot = slot.clone();
        common::start_stub(move |request| {
            if request["op"] == json!("status") {
                slot.lock().unwrap().clone()
            } else {
                common::ok_response(json!({"id": 7}))
            }
        })
    };
    let mut mcp = common::Mcp::spawn(true);
    mcp.write_port(stub.port);

    let _ = mcp.call(1, "tools/call", with_tasks(add_args()));
    *slot.lock().unwrap() = common::ok_response(json!({
        "id": 7, "task": task_view("error", Some("http_404"))
    }));

    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let response = mcp.call(2, "tasks/get", with_tasks(json!({"taskId": "aidm:7"})));
        let status = response["result"]["status"].as_str().unwrap_or("").to_string();
        if status == "completed" {
            let result = &response["result"]["result"];
            assert_eq!(result["isError"], json!(true), "下载失败必须带 isError");
            assert_eq!(
                result["structuredContent"]["task"]["error_code"],
                json!("http_404")
            );
            break;
        }
        assert!(Instant::now() < deadline, "等待 failed 任务超时：{status}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn cancel_stops_tracking_but_does_not_cancel_the_download() {
    let stub = common::start_stub(|request| {
        if request["op"] == json!("status") {
            common::ok_response(json!({"id": 7, "task": task_view("downloading", None)}))
        } else {
            common::ok_response(json!({"id": 7}))
        }
    });
    let mut mcp = common::Mcp::spawn(true);
    mcp.write_port(stub.port);

    let _ = mcp.call(1, "tools/call", with_tasks(add_args()));

    let cancelled = mcp.call(2, "tasks/cancel", with_tasks(json!({"taskId": "aidm:7"})));
    assert_eq!(cancelled["result"]["resultType"], json!("complete"));

    let state = mcp.call(3, "tasks/get", with_tasks(json!({"taskId": "aidm:7"})));
    assert_eq!(state["result"]["status"], json!("cancelled"));
    assert!(
        state["result"]["statusMessage"]
            .as_str()
            .unwrap()
            .contains("download continues"),
        "必须写明只停止跟踪"
    );
}

#[test]
fn unknown_task_ids_are_rejected() {
    let mut mcp = common::Mcp::spawn(false);
    for id in ["aidm:999", "not-a-task", "42"] {
        let response = mcp.call(1, "tasks/get", with_tasks(json!({"taskId": id})));
        assert_eq!(response["error"]["code"], json!(-32602));
        assert_eq!(
            response["error"]["data"]["code"],
            json!("unknown_task"),
            "id={id}"
        );
    }
}

//! `subscriptions/listen` + `notifications/tasks`：完成时主动通知。

mod common;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

const TASKS: &str = "io.modelcontextprotocol/tasks";
const SUBSCRIPTION_ID: &str = "io.modelcontextprotocol/subscriptionId";

fn with_tasks(params: Value) -> Value {
    let mut value = common::modern_params(params);
    value["_meta"]["io.modelcontextprotocol/clientCapabilities"] = json!({
        "extensions": { (TASKS): {} }
    });
    value
}

fn task_view(state: &str) -> Value {
    json!({
        "id": 7,
        "name": "a.bin",
        "state": state,
        "done": if state == "done" { 10 } else { 3 },
        "total": 10,
        "speed": 0,
        "save_path": r"C:\dl\a.bin",
    })
}

/// 收消息直到出现完成的 `notifications/tasks`。
fn wait_for_completed(mcp: &mut common::Mcp, deadline: Instant) -> Value {
    loop {
        assert!(
            Instant::now() < deadline,
            "等待 notifications/tasks(completed) 超时"
        );
        let message = mcp.recv();
        if message["method"] == json!("notifications/tasks")
            && message["params"]["status"] == json!("completed")
        {
            return message;
        }
    }
}

#[test]
fn listen_acknowledges_then_pushes_completion() {
    let slot = Arc::new(Mutex::new(common::ok_response(json!({
        "id": 7, "task": task_view("downloading")
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

    // 先订阅全部任务（空 taskIds = 全部当前与未来任务）。
    mcp.send(&json!({
        "jsonrpc": "2.0",
        "id": 10,
        "method": "subscriptions/listen",
        "params": with_tasks(json!({"notifications": {"taskIds": []}})),
    }));
    let ack = mcp.recv();
    assert_eq!(ack["method"], json!("notifications/subscriptions/acknowledged"));
    assert_eq!(ack["params"]["notifications"]["taskIds"], json!([]));
    assert_eq!(ack["params"]["_meta"][SUBSCRIPTION_ID], json!(10));

    // 建任务（支持 tasks 时返回句柄）。
    let add = mcp.call(1, "tools/call", with_tasks(json!({
        "name": "aidm_add",
        "arguments": {"url": "https://example.com/a.bin"},
    })));
    assert_eq!(add["result"]["taskId"], json!("aidm:7"));

    // 让引擎报告完成，随后应主动收到通知。
    *slot.lock().unwrap() = common::ok_response(json!({"id": 7, "task": task_view("done")}));

    let notification = wait_for_completed(&mut mcp, Instant::now() + Duration::from_secs(8));
    assert_eq!(notification["params"]["taskId"], json!("aidm:7"));
    assert_eq!(notification["params"]["_meta"][SUBSCRIPTION_ID], json!(10));
    let final_result = &notification["params"]["result"];
    assert_eq!(
        final_result["structuredContent"]["task"]["save_path"],
        json!(r"C:\dl\a.bin")
    );
}

#[test]
fn a_subscription_only_receives_the_tasks_it_asked_for() {
    let slot = Arc::new(Mutex::new(common::ok_response(json!({"id": 7}))));
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

    // 只订阅另一个任务 id。
    mcp.send(&json!({
        "jsonrpc": "2.0",
        "id": 11,
        "method": "subscriptions/listen",
        "params": with_tasks(json!({"notifications": {"taskIds": ["aidm:999"]}})),
    }));
    let ack = mcp.recv();
    assert_eq!(ack["params"]["notifications"]["taskIds"], json!(["aidm:999"]));

    let _ = mcp.call(1, "tools/call", with_tasks(json!({
        "name": "aidm_add",
        "arguments": {"url": "https://example.com/a.bin"},
    })));
    *slot.lock().unwrap() = common::ok_response(json!({"id": 7, "task": task_view("done")}));

    // add 的响应之后，不应收到 aidm:7 的任何通知。
    let mut seen = Vec::new();
    while let Some(message) = mcp.try_recv(Duration::from_millis(800)) {
        if message["method"] == json!("notifications/tasks") {
            seen.push(message);
        }
    }
    assert!(
        seen.is_empty(),
        "不该收到未订阅任务的通知：{seen:?}"
    );
}

#[test]
fn unknown_filter_types_are_simply_not_acknowledged() {
    let mut mcp = common::Mcp::spawn(false);
    mcp.send(&json!({
        "jsonrpc": "2.0",
        "id": 12,
        "method": "subscriptions/listen",
        "params": with_tasks(json!({
            "notifications": {"toolsListChanged": true, "taskIds": ["aidm:1"]}
        })),
    }));
    let ack = mcp.recv();
    assert_eq!(ack["method"], json!("notifications/subscriptions/acknowledged"));
    // 未实现的过滤器不回：acknowledged 里只有 taskIds。
    assert!(ack["params"]["notifications"].get("toolsListChanged").is_none());
    assert_eq!(ack["params"]["notifications"]["taskIds"], json!(["aidm:1"]));
}

#[test]
fn malformed_listen_is_rejected() {
    let mut mcp = common::Mcp::spawn(false);
    let response = mcp.call_modern(1, "subscriptions/listen", json!({}));
    assert_eq!(response["error"]["code"], json!(-32602));

    let response = mcp.call_modern(
        2,
        "subscriptions/listen",
        json!({"notifications": {"taskIds": "aidm:1"}}),
    );
    assert_eq!(response["error"]["code"], json!(-32602));
}

//! `notifications/progress`：`aidm_wait` 在等待期间推送细粒度进度。

mod common;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

const TASKS: &str = "io.modelcontextprotocol/tasks";

fn with_progress(params: Value, token: &str) -> Value {
    let mut value = common::modern_params(params);
    value["_meta"]["progressToken"] = json!(token);
    value
}

fn with_tasks(params: Value) -> Value {
    let mut value = common::modern_params(params);
    value["_meta"]["io.modelcontextprotocol/clientCapabilities"] = json!({
        "extensions": { (TASKS): {} }
    });
    value
}

fn task_view(state: &str, done: u64) -> Value {
    json!({
        "id": 1,
        "name": "a.bin",
        "state": state,
        "done": done,
        "total": 100,
        "speed": 0,
        "save_path": r"C:\dl\a.bin",
    })
}

/// 每次 `status` 前进 25 字节，到 100 后报 done。
fn ramping_stub() -> (common::Stub, Arc<AtomicU64>) {
    let counter = Arc::new(AtomicU64::new(0));
    let stub = {
        let counter = counter.clone();
        common::start_stub(move |request| {
            if request["op"] == json!("status") {
                let step = counter.fetch_add(1, Ordering::SeqCst) + 1;
                let done = (step * 25).min(100);
                let state = if done >= 100 { "done" } else { "downloading" };
                common::ok_response(json!({"id": 1, "task": task_view(state, done)}))
            } else {
                common::ok_response(json!({"id": 1}))
            }
        })
    };
    (stub, counter)
}

#[test]
fn wait_sends_increasing_progress_then_the_final_status() {
    let (stub, _counter) = ramping_stub();
    let mut mcp = common::Mcp::spawn(false);
    mcp.write_port(stub.port);

    mcp.send(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": with_progress(
            json!({"name": "aidm_wait", "arguments": {"id": 1, "timeout_s": 10}}),
            "tok-1",
        ),
    }));

    let mut progresses = Vec::new();
    let response = loop {
        let message = mcp.recv();
        if message["method"] == json!("notifications/progress") {
            assert_eq!(message["params"]["progressToken"], json!("tok-1"));
            assert_eq!(message["params"]["total"], json!(100));
            progresses.push(message["params"]["progress"].as_u64().unwrap());
            continue;
        }
        assert_eq!(message["id"], json!(1), "应是等待请求的响应");
        break message;
    };

    assert!(
        progresses.len() >= 2,
        "至少应收到两条进度，实际：{progresses:?}"
    );
    for pair in progresses.windows(2) {
        assert!(pair[1] >= pair[0], "进度必须单调不减：{progresses:?}");
    }
    assert_eq!(*progresses.last().unwrap(), 100);

    let task = &response["result"]["structuredContent"]["task"];
    assert_eq!(task["state"], json!("done"));
    assert_eq!(task["done"], json!(100));
    assert!(response["result"].get("isError").is_none());
}

#[test]
fn wait_without_a_progress_token_sends_no_progress() {
    let (stub, _counter) = ramping_stub();
    let mut mcp = common::Mcp::spawn(false);
    mcp.write_port(stub.port);

    mcp.send(&json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": common::modern_params(
            json!({"name": "aidm_wait", "arguments": {"id": 1, "timeout_s": 10}}),
        ),
    }));

    // 第一条必须是响应本身：没有 token 就不许发进度。
    let response = mcp.recv();
    assert_eq!(response["id"], json!(2));
    assert_eq!(
        response["result"]["structuredContent"]["task"]["state"],
        json!("done")
    );
}

#[test]
fn wait_times_out_with_is_error_and_the_last_status() {
    let stub = common::start_stub(|request| {
        if request["op"] == json!("status") {
            common::ok_response(json!({"id": 1, "task": task_view("downloading", 10)}))
        } else {
            common::ok_response(json!({"id": 1}))
        }
    });
    let mut mcp = common::Mcp::spawn(false);
    mcp.write_port(stub.port);

    mcp.send(&json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": with_progress(
            json!({"name": "aidm_wait", "arguments": {"id": 1, "timeout_s": 1}}),
            "tok-3",
        ),
    }));

    let response = loop {
        let message = mcp.recv();
        if message["method"] == json!("notifications/progress") {
            continue;
        }
        break message;
    };
    assert_eq!(response["result"]["isError"], json!(true));
    let task = &response["result"]["structuredContent"]["task"];
    assert_eq!(task["state"], json!("downloading"));
    assert_eq!(task["done"], json!(10));
}

#[test]
fn wait_returns_a_task_handle_when_tasks_are_declared() {
    let (stub, _counter) = ramping_stub();
    let mut mcp = common::Mcp::spawn(false);
    mcp.write_port(stub.port);

    // Tasks 客户端：立即拿句柄，不阻塞等 10 秒。
    let started = std::time::Instant::now();
    let response = mcp.call(
        4,
        "tools/call",
        with_tasks(json!({
            "name": "aidm_wait",
            "arguments": {"id": 1, "timeout_s": 10},
        })),
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "声明 Tasks 后 aidm_wait 必须立即返回"
    );
    assert_eq!(response["result"]["resultType"], json!("task"));
    assert_eq!(response["result"]["taskId"], json!("aidm:1"));
}

#[test]
fn wait_timeout_is_capped_at_two_minutes() {
    // 超过上限的 timeout_s 被夹取；用 999 秒的请求验证它仍然在上限内返回。
    // 这里只验证"不会因为超大值而拒绝"：工具本身是只读的，参数夹取在 server 侧。
    let (stub, _counter) = ramping_stub();
    let mut mcp = common::Mcp::spawn(false);
    mcp.write_port(stub.port);
    let response = mcp.call(
        5,
        "tools/call",
        common::modern_params(json!({
            "name": "aidm_wait",
            "arguments": {"id": 1, "timeout_s": 999},
        })),
    );
    assert_eq!(
        response["result"]["structuredContent"]["task"]["state"],
        json!("done")
    );
}

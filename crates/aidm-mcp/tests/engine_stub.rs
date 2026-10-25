//! 引擎发现与不可达行为（R-MCPS-04）。

mod common;

use serde_json::json;

#[test]
fn missing_port_file_makes_tools_fail_but_discover_succeed() {
    let mut mcp = common::Mcp::spawn(false);
    mcp.remove_port();

    let discover = mcp.call(1, "server/discover", json!({}));
    assert!(discover["result"].is_object(), "discover 不依赖引擎");

    let status = mcp.call_modern(
        2,
        "tools/call",
        json!({"name": "aidm_status", "arguments": {"id": 1}}),
    );
    assert_eq!(status["error"]["code"], json!(-32603));
    assert_eq!(
        status["error"]["data"]["code"],
        json!("engine_unreachable")
    );
}

#[test]
fn garbage_port_file_is_treated_as_unreachable() {
    let mut mcp = common::Mcp::spawn(false);
    let path = mcp.port_path();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "not-a-port").unwrap();

    let status = mcp.call_modern(
        1,
        "tools/call",
        json!({"name": "aidm_list", "arguments": {}}),
    );
    assert_eq!(status["error"]["data"]["code"], json!("engine_unreachable"));
}

#[test]
fn closed_port_is_unreachable() {
    let mut mcp = common::Mcp::spawn(false);
    // 绑定后立刻释放，保证这个端口现在没人监听。
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    mcp.write_port(port);

    let status = mcp.call_modern(
        1,
        "tools/call",
        json!({"name": "aidm_list", "arguments": {}}),
    );
    assert_eq!(status["error"]["data"]["code"], json!("engine_unreachable"));
}

#[test]
fn a_live_engine_receives_the_translated_request() {
    // 子线程里的 assert 不会传回测试线程，因此把收到的 op/id 回显出来，
    // 由测试线程断言（否则断言失败会被静默吞掉）。
    let stub = common::start_stub(|request| {
        // TaskView 的必填字段：id/name/state/done/speed/save_path。
        common::ok_response(json!({
            "task": {
                "id": request["id"].clone(),
                "name": "a.bin",
                "state": request["op"].clone(),
                "done": 0,
                "speed": 0,
                "save_path": r"C:\dl\a.bin",
            }
        }))
    });
    let mut mcp = common::Mcp::spawn(false);
    mcp.write_port(stub.port);

    let response = mcp.call_modern(
        1,
        "tools/call",
        json!({"name": "aidm_status", "arguments": {"id": 42}}),
    );
    let task = &response["result"]["structuredContent"]["task"];
    assert_eq!(task["id"], json!(42));
    assert_eq!(task["state"], json!("status"), "op 必须被翻译成 status");
}

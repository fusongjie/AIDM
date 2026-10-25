//! `inputSchema` 的形状与安全边界（R-MCPS-10 / B-4）。

mod common;

use serde_json::json;

const FORBIDDEN_PROPS: &[&str] = &["cookies", "password", "passwd", "secret", "token"];

#[test]
fn every_tool_has_an_object_schema_with_no_extra_properties() {
    let mut mcp = common::Mcp::spawn(true);
    let response = mcp.call_modern(1, "tools/list", json!({}));
    let tools = response["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 24);

    for tool in tools {
        let name = tool["name"].as_str().unwrap();
        let schema = &tool["inputSchema"];
        assert_eq!(schema["type"], json!("object"), "{name} 的根必须是对象");
        assert_eq!(
            schema["additionalProperties"],
            json!(false),
            "{name} 必须拒绝未知参数"
        );
        assert!(schema["properties"].is_object(), "{name} 缺 properties");

        if schema.get("required").is_some() {
            assert!(schema["required"].is_array(), "{name} 的 required 必须是数组");
        }

        let props = schema["properties"].as_object().unwrap();
        for forbidden in FORBIDDEN_PROPS {
            assert!(
                !props.contains_key(*forbidden),
                "{name} 不得暴露 `{forbidden}` 参数（R-MCPS-10）"
            );
        }
    }
}

#[test]
fn annotations_match_the_read_write_class() {
    let mut mcp = common::Mcp::spawn(true);
    let response = mcp.call_modern(1, "tools/list", json!({}));
    for tool in response["result"]["tools"].as_array().unwrap() {
        let name = tool["name"].as_str().unwrap();
        let annotations = &tool["annotations"];
        assert!(
            annotations["readOnlyHint"].is_boolean(),
            "{name} 缺 readOnlyHint"
        );
    }
}

#[test]
fn destructive_operations_are_labeled() {
    let mut mcp = common::Mcp::spawn(true);
    let response = mcp.call_modern(1, "tools/list", json!({}));
    let tools = response["result"]["tools"].as_array().unwrap();

    let find = |name: &str| {
        tools
            .iter()
            .find(|tool| tool["name"] == json!(name))
            .unwrap_or_else(|| panic!("找不到 {name}"))
    };

    assert_eq!(find("aidm_cancel")["annotations"]["destructiveHint"], json!(true));
    assert_eq!(find("aidm_restart")["annotations"]["destructiveHint"], json!(true));
    assert_eq!(find("aidm_add")["annotations"]["destructiveHint"], json!(false));
    assert_eq!(find("aidm_add")["annotations"]["openWorldHint"], json!(true));
    assert_eq!(find("aidm_status")["annotations"]["readOnlyHint"], json!(true));
}

#[test]
fn directory_parameters_are_documented_as_absolute() {
    let mut mcp = common::Mcp::spawn(true);
    let response = mcp.call_modern(1, "tools/list", json!({}));
    let add = response["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == json!("aidm_add"))
        .unwrap();
    let note = add["inputSchema"]["properties"]["dir"]["description"]
        .as_str()
        .unwrap_or("");
    assert!(note.contains("绝对"), "dir 的描述必须写明绝对路径，实际：{note}");
}

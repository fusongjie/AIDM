//! `server/discover` 的形状（R-MCPS-02 ③）。
//!
//! 关键点：`supportedVersions` 只列 modern 版本——legacy 不是通过 discover
//! 协商的，列进去会让 modern 客户端选一个它用不了的版本。

mod common;

use serde_json::json;

#[test]
fn discover_reports_modern_versions_and_tools_only() {
    let mut mcp = common::Mcp::spawn(false);
    let response = mcp.call(1, "server/discover", json!({}));

    let result = &response["result"];
    assert_eq!(result["supportedVersions"], json!(["2026-07-28"]));
    assert_eq!(result["resultType"], json!("complete"));

    assert!(result["capabilities"]["tools"].is_object());
    for absent in ["resources", "prompts", "logging", "completions"] {
        assert!(
            result["capabilities"].get(absent).is_none(),
            "未实现的能力不得声明：{absent}"
        );
    }

    assert_eq!(
        result["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
        json!("aidm-mcp")
    );
    assert!(
        result["instructions"].as_str().unwrap_or("").len() > 20,
        "instructions 应给出用法提示"
    );
}

#[test]
fn discover_works_without_an_engine() {
    // 不写端口文件：discover 不依赖引擎，必须仍然成功（R-MCPS-04）。
    let mut mcp = common::Mcp::spawn(false);
    let response = mcp.call(7, "server/discover", json!({}));
    assert!(response["result"].is_object(), "discover 不应因引擎缺失而失败");
}

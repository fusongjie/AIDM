#![allow(dead_code)] // 复用 src/tools.rs 时只用到一部分字段（R-TEST-04 的既定代价）

//! 工具表的双面校验：
//! 1. 契约源码里的每个 `EngineRequest` 变体都被归类为"暴露"或"不暴露"；
//! 2. `tools/list` 对外的形状与工具表一致。
//!
//! 这里用 `#[path]` 直接引源文件（07-testing.md R-TEST-04）：只有这样才能在没有
//! 网络与引擎的情况下断言"48 = 24 + 24"，而不是相信文档。

#[path = "../src/tools.rs"]
mod tools;

mod common;

use serde_json::json;

fn to_snake(name: &str) -> String {
    let mut out = String::new();
    for (index, ch) in name.chars().enumerate() {
        if ch.is_ascii_uppercase() {
            if index > 0 {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

/// 从契约源码里穷举变体名：新增 op 会让本测试先红，逼着作者同步工具表。
fn contract_ops() -> Vec<String> {
    let source = include_str!("../../aidm-ipc/src/lib.rs");
    let start = source
        .find("pub enum EngineRequest {")
        .expect("找不到 EngineRequest 定义");
    let rest = &source[start..];
    let end = rest.find("\n}").expect("找不到 enum 结束");
    rest[..end]
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if !line.starts_with(|c: char| c.is_ascii_uppercase()) {
                return None;
            }
            let name: String = line
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric())
                .collect();
            if name.is_empty() {
                None
            } else {
                Some(to_snake(&name))
            }
        })
        .collect()
}

#[test]
fn every_contract_op_is_classified() {
    // `aidm_wait` 是复合工具（底层 op=status），所以按 op 去重后对账；
    // 工具名本身仍必须唯一。
    let mut classified: Vec<String> = tools::TOOLS
        .iter()
        .map(|tool| tool.op.to_string())
        .chain(tools::HIDDEN_OPS.iter().map(|(op, _)| op.to_string()))
        .collect();
    let mut contract = contract_ops();
    assert_eq!(contract.len(), 49, "契约变体数变了：{contract:?}");

    classified.sort();
    classified.dedup();
    contract.sort();
    assert_eq!(
        classified, contract,
        "新增/删除 op 必须同步 TOOLS 或 HIDDEN_OPS（R-MCPS-09）"
    );

    let mut names: Vec<&str> = tools::TOOLS.iter().map(|tool| tool.name).collect();
    names.sort_unstable();
    let before = names.len();
    names.dedup();
    assert_eq!(names.len(), before, "工具名必须唯一");
}

#[test]
fn hidden_class_letters_are_from_the_documented_set() {
    for (op, class) in tools::HIDDEN_OPS {
        assert!(
            matches!(*class, "A" | "B" | "C" | "D"),
            "{op} 的类别 {class} 不在 A/B/C/D 内"
        );
    }
}

#[test]
fn tools_list_matches_the_table() {
    let mut mcp = common::Mcp::spawn(true);
    let response = mcp.call_modern(1, "tools/list", json!({}));
    let listed: Vec<&str> = response["result"]["tools"]
        .as_array()
        .expect("tools 必须是数组")
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();

    let mut expected: Vec<&str> = tools::TOOLS.iter().map(|tool| tool.name).collect();
    expected.sort_unstable();
    assert_eq!(listed, expected, "tools/list 的集合与顺序必须与工具表一致");

    // 确定性顺序：再请求一次，顺序不变。
    let again = mcp.call_modern(2, "tools/list", json!({}));
    assert_eq!(again["result"]["tools"], response["result"]["tools"]);
}

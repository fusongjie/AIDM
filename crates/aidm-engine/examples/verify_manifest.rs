//! 校验更新清单签名：供发布流水线在 `gh release create` 之前自证。
//!
//! 用途：确认 CI 里的 `TAURI_SIGNING_PRIVATE_KEY` 与
//! `crates/aidm-engine/src/update.rs` 的 `UPDATE_PUBKEY` 配对，
//! 避免发布出客户端无法验签的清单。
//!
//! 用法：cargo run -p aidm-engine --example verify_manifest -- version-stable.json

use aidm_engine::update::{verify_manifest_signature, AvailableUpdate};

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "version-stable.json".to_string());
    let raw = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("读取清单失败 {path}: {e}");
            std::process::exit(2);
        }
    };
    let value: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("解析清单失败 {path}: {e}");
            std::process::exit(2);
        }
    };
    let field = |name: &str| {
        value
            .get(name)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    };
    let pkg = AvailableUpdate {
        version: field("version").unwrap_or_default(),
        url: field("url").unwrap_or_default(),
        sha256: field("sha256").unwrap_or_default(),
        signature: field("signature"),
        notes: field("notes"),
    };
    match verify_manifest_signature(&pkg) {
        Ok(()) => println!("签名有效：version={} sha256={}", pkg.version, pkg.sha256),
        Err(code) => {
            eprintln!(
                "签名无效：{code}（私钥与 update.rs 的 UPDATE_PUBKEY 不配对，或 version/url/sha256 被改动）"
            );
            std::process::exit(1);
        }
    }
}

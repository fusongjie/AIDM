//! AIDM 的 MCP 服务（stdio）。
//!
//! `stdout` **只**承载 MCP 消息（一行一条 JSON-RPC）；所有人类可读输出（帮助、
//! 版本、审计、错误）一律走 `stderr`。这条规则用 `clippy::print_stdout` 钉住：
//! 任何人写 `println!` 都会在 `cargo clippy -p aidm-mcp` 里失败。
//!
//! 线程：主线程读 stdin；writer 线程独占 stdout（行不交错）；tracker 线程推进
//! Tasks 扩展的任务状态并推送 `notifications/tasks`。

#![deny(clippy::print_stdout)]

mod engine;
mod jsonrpc;
mod server;
mod tasks;
mod tools;

use std::io::{self, BufRead};
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::thread;

use serde_json::Value;

use crate::jsonrpc::RpcError;

const USAGE: &str = "\
aidm-mcp — AIDM 的 MCP 服务（stdio）

用法:
  aidm-mcp [--allow-write]

选项:
  --allow-write   暴露写工具（默认只读）。也可用环境变量 AIDM_MCP_ALLOW_WRITE=1。
  -h, --help      显示本帮助（写到 stderr）。
  -V, --version   显示版本（写到 stderr）。

说明:
  本进程的 stdout 只输出 MCP 协议消息，因此帮助与日志都在 stderr。
  需要先启动 AIDM 引擎；本服务不会自行拉起它。

Tasks 扩展:
  客户端在 _meta.clientCapabilities.extensions 里声明
  \"io.modelcontextprotocol/tasks\" 后，aidm_add 返回任务句柄（taskId=aidm:<id>），
  可用 tasks/get 查询、tasks/cancel 停止跟踪（**不会取消下载**），
  并通过 subscriptions/listen 接收 notifications/tasks 状态推送。";

enum Action {
    Run { allow_write: bool },
    Help,
    Version,
    Invalid(String),
}

fn parse_args() -> Action {
    let mut allow_write = env_flag("AIDM_MCP_ALLOW_WRITE");
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--allow-write" => allow_write = true,
            "-h" | "--help" => return Action::Help,
            "-V" | "--version" => return Action::Version,
            other => return Action::Invalid(other.to_string()),
        }
    }
    Action::Run { allow_write }
}

fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name).ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes")
    )
}

fn main() {
    match parse_args() {
        Action::Help => eprintln!("{USAGE}"),
        Action::Version => eprintln!("aidm-mcp {}", env!("CARGO_PKG_VERSION")),
        Action::Invalid(arg) => {
            eprintln!("aidm-mcp: 未知参数 `{arg}`\n\n{USAGE}");
            std::process::exit(2);
        }
        Action::Run { allow_write } => run(allow_write),
    }
}

fn run(allow_write: bool) {
    // 单 writer：所有协议行都从这里出，避免主线程与 tracker 的写入交错。
    let (tx, rx) = mpsc::channel::<String>();
    let writer = thread::Builder::new()
        .name("aidm-mcp-out".into())
        .spawn(move || {
            use std::io::Write;
            let stdout = io::stdout();
            let mut out = stdout.lock();
            for line in rx {
                if out
                    .write_all(line.as_bytes())
                    .and_then(|_| out.write_all(b"\n"))
                    .and_then(|_| out.flush())
                    .is_err()
                {
                    break;
                }
            }
        })
        .ok();

    let server = server::Server::new(allow_write, tx.clone());
    let shared = server.shared();
    let tracker = server::spawn_tracker(shared.clone());

    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(line) => line,
            Err(error) => {
                eprintln!("aidm-mcp: stdin error: {error}");
                break;
            }
        };
        if line.trim().is_empty() {
            continue;
        }

        let payload = match jsonrpc::parse(&line) {
            Ok(request) => {
                let id = request.id.clone();
                let method = request.method.clone();
                match server.handle(&request) {
                    Ok(server::HandleOutcome::Reply(result)) => {
                        if method == "tools/call" {
                            audit_tool_call(&request, &result);
                        }
                        id.map(|id| jsonrpc::result(&id, result))
                    }
                    // 通知、`subscriptions/listen`、以及由后台线程写响应的 `aidm_wait`。
                    Ok(server::HandleOutcome::NoReply | server::HandleOutcome::Deferred) => None,
                    Err(error) => {
                        audit_rpc_error(&method, &error);
                        Some(jsonrpc::error(id.as_ref(), error))
                    }
                }
            }
            Err(error) => Some(jsonrpc::error(None, error)),
        };

        if let Some(payload) = payload {
            if tx.send(payload.to_string()).is_err() {
                break;
            }
        }
    }

    // stdin EOF 是 MCP stdio 的标准关闭信号：先让 tracker 停下，再排空 writer。
    shared.shutdown.store(true, Ordering::SeqCst);
    if let Some(tracker) = tracker {
        let _ = tracker.join();
    }
    // 关闭顺序很重要：writer 只有在**所有** Sender 都 drop 之后才会结束。
    // `shared` 与 `server` 各持有一份 `out`，漏掉任何一个都会让 join 永久阻塞。
    drop(server);
    drop(shared);
    drop(tx);
    if let Some(writer) = writer {
        let _ = writer.join();
    }
}

/// 审计：只记工具名与成败，**不记参数值**——URL 查询串、cookie、口令都在参数里
/// （14-mcp-service.md R-MCPS-12）。
fn audit_tool_call(request: &jsonrpc::Request, result: &Value) {
    let tool = request
        .params
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("?");
    let failed = result
        .get("isError")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    // Tasks 形状没有 id 字段，但有 taskId。
    let id = result
        .get("structuredContent")
        .and_then(|value| value.get("id"))
        .and_then(Value::as_u64)
        .or_else(|| result.get("taskId").and_then(Value::as_str).and_then(|task_id| {
            task_id.strip_prefix("aidm:").and_then(|s| s.parse().ok())
        }));
    match id {
        Some(id) => eprintln!("aidm-mcp: tool={tool} ok={} id={id}", !failed),
        None => eprintln!("aidm-mcp: tool={tool} ok={}", !failed),
    }
}

fn audit_rpc_error(method: &str, error: &RpcError) {
    eprintln!("aidm-mcp: method={method} rpc_error={}", error.code);
}

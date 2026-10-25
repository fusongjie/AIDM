// 浏览器以 Native Messaging 拉起本宿主，通信只走 stdio 管道，不需要控制台。
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! `com.aidm.host`：Chrome/Edge native messaging 入口。
//!
//! argv[1] = `chrome-extension://<id>/`（浏览器传入）。stdio 为长度前缀 JSON，
//! 日志只走 stderr，避免破坏帧。

use std::io::{stdin, stdout};

use aidm_ext_host::{caller_origin_from_argv, handle, load_host_settings, parent};
use aidm_ipc::{read_nmh_message, write_nmh_message, ExtResponse, NmhError, PORT_FILE};

fn engine_port() -> Option<u16> {
    let path = aidm_core::app_data_dir().join(PORT_FILE);
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// 诊断日志：每次连接追加若干行到 `%LOCALAPPDATA%\AIDM\logs\ext-host.log`。
///
/// 为什么不用 `log` crate：需要事后追溯"浏览器到底怎么拉起宿主"——父进程
/// 是谁、`argv[1]` 是什么、白名单读到几条——而 Chrome 会吞掉宿主的 stderr，
/// 文件是唯一还能读到的地方。任何失败一律静默：写日志绝不能影响帧。
fn diag(line: &str) {
    use std::io::Write;
    let path = aidm_core::app_data_dir().join("logs").join("ext-host.log");
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    else {
        return;
    };
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let _ = writeln!(f, "t={secs} {line}");
}

fn main() {
    // 只走 stderr 与日志文件，绝不碰 stdout —— 那里是长度前缀的 JSON 帧。
    aidm_core::obs::init("ext-host", "warn");

    let args: Vec<String> = std::env::args().collect();
    let origin = caller_origin_from_argv(&args);
    let parent_ok = parent::parent_allowed();
    let (ppid, chain) = parent::parent_diag();
    let settings = match load_host_settings() {
        Ok(s) => s,
        Err(e) => {
            log::warn!("settings: {e}");
            aidm_ext_host::HostSettings {
                enabled: true,
                allowed_ext_ids: Vec::new(),
            }
        }
    };
    let port = engine_port();
    diag(&format!(
        "start pid={} ppid={ppid:?} parent_chain={chain:?} parent_ok={parent_ok} \
         skip_parent={} origin={origin:?} allowed={:?} enabled={} port={port:?}",
        std::process::id(),
        parent::skip_parent_check(),
        settings.allowed_ext_ids,
        settings.enabled,
    ));

    let mut stdin = stdin().lock();
    let mut stdout = stdout();
    loop {
        let raw = match read_nmh_message(&mut stdin) {
            Ok(b) => b,
            Err(NmhError::Eof) => break,
            Err(NmhError::TooLong) => {
                let _ = write_json(&mut stdout, &ExtResponse::err("too_long"));
                continue;
            }
            Err(e) => {
                log::warn!("nmh read: {e}");
                break;
            }
        };
        let req = match aidm_ext_host::protocol::decode_request(&raw) {
            Ok(r) => r,
            Err(resp) => {
                let _ = write_json(&mut stdout, &resp);
                continue;
            }
        };
        // cookies 只在内存中转发，此处不记录请求体。
        // 端口**每次请求重读**：长连接下宿主会活很久，中间引擎可能重启、端口随之
        // 变化；只在启动时读一次的话，之后所有请求都会打向一个已经没人监听的端口。
        let resp = handle(req, origin.as_deref(), parent_ok, &settings, engine_port());
        diag(&format!(
            "resp pid={} ok={} code={:?}",
            std::process::id(),
            resp.ok,
            resp.code
        ));
        if write_json(&mut stdout, &resp).is_err() {
            break;
        }
    }
}

fn write_json(out: &mut impl std::io::Write, resp: &ExtResponse) -> Result<(), ()> {
    let Ok(bytes) = serde_json::to_vec(resp) else {
        return Err(());
    };
    match write_nmh_message(out, &bytes) {
        Ok(()) => Ok(()),
        Err(NmhError::TooLong) => {
            write_nmh_message(out, br#"{"ok":false,"code":"too_long"}"#).map_err(|_| ())
        }
        Err(_) => Err(()),
    }
}

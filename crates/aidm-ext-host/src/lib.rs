//! AIDM 原生消息宿主。
//!
//! Chrome/Edge native messaging：4 字节本地字节序长度 + UTF-8 JSON。
//! 鉴权后把 `add` / `offer` / `status` / `list` 转到引擎回环单行 JSON IPC。

pub mod parent;
pub mod protocol;
pub mod ui_window;

pub use protocol::{
    caller_origin_from_argv, handle, load_host_settings, HostSettings, ACTIVE_STATES,
};

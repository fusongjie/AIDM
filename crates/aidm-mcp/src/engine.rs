//! 引擎发现与 IPC 调用。
//!
//! 只有一条路：读 `<应用数据目录>/engine.port` → 连 `127.0.0.1:<port>`。
//! 不拉起引擎、不打开数据库、不缓存端口（14-mcp-service.md R-MCPS-04）：
//! 引擎是单实例的，端口文件由引擎自己维护并自愈。

use std::path::{Path, PathBuf};
use std::time::Duration;

use aidm_ipc::{EngineRequest, EngineResponse};

/// 普通 op 的 IPC 超时。引擎的每个 op 都是"立即回包"型，5 秒足够。
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// `diag_export` 要打包 ZIP 并二次脱敏，给它更长的预算。
pub const DIAG_TIMEOUT: Duration = Duration::from_secs(30);

/// 端口文件路径。目录逻辑复用 `aidm_core::paths::app_data_dir()`——
/// 与引擎、UI、ext-host 完全同一套（`%LOCALAPPDATA%\AIDM\engine.port`）。
pub fn port_file() -> PathBuf {
    aidm_core::paths::app_data_dir().join(aidm_ipc::PORT_FILE)
}

/// 读端口。文件缺失、内容不是合法 u16 都当作"引擎不可达"。
pub fn read_port(path: &Path) -> Option<u16> {
    let text = std::fs::read_to_string(path).ok()?;
    text.trim().parse::<u16>().ok()
}

#[derive(Debug, PartialEq, Eq)]
pub enum EngineError {
    /// 端口文件缺失、连接被拒、或其它非超时错误。
    Unreachable(String),
    /// 连接成功但读写在预算内没完成。
    Timeout(String),
}

impl EngineError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unreachable(_) => "engine_unreachable",
            Self::Timeout(_) => "ipc_timeout",
        }
    }
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable(message) => write!(f, "engine unreachable: {message}"),
            Self::Timeout(message) => write!(f, "engine ipc timeout: {message}"),
        }
    }
}

/// 调用引擎。
///
/// 复用 `aidm_ipc::engine_roundtrip`（契约层的短连接客户端）。它把失败压成字符串，
/// 因此这里按错误前缀分类：
/// - `connect engine: ...` → 不可达；
/// - `send` / `recv` / 超时族 → 超时；
/// - 其余（含 `decode`）保守归为不可达 —— 宁可让调用方重试连接，也不谎报"超时"。
///
/// 这段字符串契约与 `aidm_ipc` 同源；改动 `engine_roundtrip` 的错误文本必须同步这里。
pub fn call(
    port: u16,
    request: &EngineRequest,
    timeout: Duration,
) -> Result<EngineResponse, EngineError> {
    aidm_ipc::engine_roundtrip(port, request, timeout).map_err(classify)
}

fn classify(message: String) -> EngineError {
    if message.starts_with("connect engine") {
        return EngineError::Unreachable(message);
    }
    let lower = message.to_ascii_lowercase();
    if lower.contains("timed out")
        || lower.contains("timeout")
        || lower.contains("would block")
        || message.starts_with("recv")
        || message.starts_with("send")
    {
        EngineError::Timeout(message)
    } else {
        EngineError::Unreachable(message)
    }
}

/// 一次"完整"的引擎调用：发现 → 调用。
pub fn call_once(request: &EngineRequest, timeout: Duration) -> Result<EngineResponse, EngineError> {
    match read_port(&port_file()) {
        Some(port) => call(port, request, timeout),
        None => Err(EngineError::Unreachable(format!(
            "端口文件不存在或无效：{}",
            port_file().display()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_separates_connect_from_timeout() {
        assert_eq!(
            classify("connect engine: refused".into()),
            EngineError::Unreachable("connect engine: refused".into())
        );
        assert_eq!(
            classify("recv: timed out".into()),
            EngineError::Timeout("recv: timed out".into())
        );
        // 解码错误不能谎报成超时。
        assert_eq!(
            classify("decode: expected value".into()),
            EngineError::Unreachable("decode: expected value".into())
        );
    }

    #[test]
    fn read_port_rejects_garbage() {
        let dir = std::env::temp_dir().join("aidm-mcp-unit-port");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("engine.port");
        std::fs::write(&path, " 4242\n").unwrap();
        assert_eq!(read_port(&path), Some(4242));
        std::fs::write(&path, "not-a-port").unwrap();
        assert_eq!(read_port(&path), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

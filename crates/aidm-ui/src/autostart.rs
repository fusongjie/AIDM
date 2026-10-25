//! 开机自启（`general.start_with_windows`）。
//!
//! 只写当前用户的 `HKCU\...\CurrentVersion\Run`，**不碰**任何策略键，也不需要
//! 管理员权限；关闭时删掉该值（值本来不存在也算成功，保持幂等）。
//!
//! 注册表里存的是**当前 exe 的绝对路径**并加引号（路径可能含空格）。程序被移动
//! 之后旧值就会失配，所以 `is_enabled()` 是按"当前 exe"比对的，而不是"值存在
//! 即算开启"——启动时同步一次即可自愈。

use std::path::PathBuf;

#[cfg(windows)]
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
#[cfg(windows)]
const VALUE_NAME: &str = "AIDM";

/// 写入注册表的可执行文件。
fn launch_target() -> Result<PathBuf, String> {
    std::env::current_exe().map_err(|e| format!("current_exe: {e}"))
}

/// 注册表里记录的命令行原文。
#[cfg(windows)]
fn registered_command() -> Option<String> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let key = hkcu.open_subkey(RUN_KEY).ok()?;
    key.get_value::<String, _>(VALUE_NAME).ok()
}

/// 把注册表里存的 `"<exe>"` 还原成路径。
///
/// 单独抽出来是为了能在任何平台上单测：引号处理是这里唯一容易写错的地方。
pub fn parse_registered(raw: &str) -> Option<String> {
    let t = raw.trim();
    let inner = t
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(t)
        .trim();
    if inner.is_empty() {
        None
    } else {
        Some(inner.to_string())
    }
}

/// 当前用户是否已开启自启，且指向的正是当前这个可执行文件。
#[cfg(windows)]
pub fn is_enabled() -> bool {
    let Some(raw) = registered_command() else {
        return false;
    };
    let Some(path) = parse_registered(&raw) else {
        return false;
    };
    match launch_target() {
        Ok(exe) => PathBuf::from(path) == exe,
        Err(_) => false,
    }
}

#[cfg(not(windows))]
pub fn is_enabled() -> bool {
    false
}

/// 开 / 关自启。
#[cfg(windows)]
pub fn set_enabled(enabled: bool) -> Result<(), String> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (key, _) = hkcu
        .create_subkey(RUN_KEY)
        .map_err(|e| format!("open Run key: {e}"))?;
    if enabled {
        let exe = launch_target()?;
        let cmd = format!("\"{}\"", exe.display());
        key.set_value(VALUE_NAME, &cmd)
            .map_err(|e| format!("write autostart: {e}"))
    } else {
        match key.delete_value(VALUE_NAME) {
            Ok(()) => Ok(()),
            // 值本来就不在：幂等成功，不打扰用户。
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("delete autostart: {e}")),
        }
    }
}

#[cfg(not(windows))]
pub fn set_enabled(_enabled: bool) -> Result<(), String> {
    Err("开机自启只在 Windows 上实现".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_quoted_command() {
        assert_eq!(
            parse_registered(r#""C:\Program Files\AIDM\aidm-ui.exe""#).as_deref(),
            Some(r"C:\Program Files\AIDM\aidm-ui.exe")
        );
    }

    #[test]
    fn parses_bare_command() {
        assert_eq!(
            parse_registered(r"C:\AIDM\aidm-ui.exe").as_deref(),
            Some(r"C:\AIDM\aidm-ui.exe")
        );
    }

    #[test]
    fn blank_or_quotes_only_is_none() {
        assert_eq!(parse_registered(""), None);
        assert_eq!(parse_registered("   "), None);
        assert_eq!(parse_registered(r#""""#), None);
    }

    #[test]
    fn trims_surrounding_space_inside_quotes() {
        assert_eq!(
            parse_registered("  \"C:\\x\\a.exe\"  ").as_deref(),
            Some(r"C:\x\a.exe")
        );
    }
}

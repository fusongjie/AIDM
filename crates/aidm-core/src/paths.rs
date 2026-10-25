//! 应用数据目录解析与用户路径展开。
//!
//! 约定（开发文档 §4 / §9）：
//! - Windows: `%LOCALAPPDATA%\AIDM\`（db.sqlite 与 logs/ 均在此）
//! - 其余平台（开发/CI）: `$XDG_DATA_HOME/aidm/`，退回 `~/.local/share/aidm/`
//!
//! settings 中的用户路径（如 `paths.default_dir = %USERPROFILE%\Downloads`）
//! 存储为原始 token 形式；**使用处必须先经 `expand_user_path` 展开**。

use std::path::PathBuf;

pub const APP_DIR_NAME: &str = if cfg!(windows) { "AIDM" } else { "aidm" };

pub fn app_data_dir() -> PathBuf {
    if cfg!(windows) {
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            if !local.trim().is_empty() {
                return PathBuf::from(local).join(APP_DIR_NAME);
            }
        }
    }
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(APP_DIR_NAME)
}

pub fn db_path() -> PathBuf {
    app_data_dir().join("db.sqlite")
}

pub fn logs_dir() -> PathBuf {
    app_data_dir().join("logs")
}

/// 展开 Windows `%VAR%` 与 POSIX `$VAR` / `${VAR}` 环境变量 token；
/// 未定义的变量保留原样（不丢信息）。
pub fn expand_env_tokens(input: &str) -> String {
    // 第一遍：Windows %VAR%
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if let Some(end) = input[i + 1..].find('%') {
                let name = &input[i + 1..i + 1 + end];
                if !name.is_empty() && !name.contains('/') && !name.contains('\\') {
                    if let Ok(val) = std::env::var(name) {
                        out.push_str(&val);
                        i += end + 2;
                        continue;
                    }
                }
            }
        }
        let c = input[i..].chars().next().expect("non-empty remainder");
        out.push(c);
        i += c.len_utf8();
    }

    // 第二遍：POSIX $VAR / ${VAR}
    let mut out2 = String::with_capacity(out.len());
    let mut rest = out.as_str();
    loop {
        let Some(pos) = rest.find('$') else {
            out2.push_str(rest);
            break;
        };
        out2.push_str(&rest[..pos]);
        let after = &rest[pos + 1..];
        if let Some(stripped) = after.strip_prefix('{') {
            match stripped.find('}') {
                Some(end) => {
                    let name = &stripped[..end];
                    match std::env::var(name) {
                        Ok(val) => out2.push_str(&val),
                        // 未定义：保留 ${name} 原样
                        Err(_) => out2.push_str(&format!("${{{name}}}")),
                    }
                    rest = &stripped[end + 1..];
                }
                None => {
                    out2.push('$');
                    rest = after;
                }
            }
        } else {
            let mut chars = after.chars();
            let name: String = match chars.next() {
                Some(c) if c.is_ascii_alphabetic() || c == '_' => {
                    let mut name = String::new();
                    name.push(c);
                    for c in chars {
                        if c.is_ascii_alphanumeric() || c == '_' {
                            name.push(c);
                        } else {
                            break;
                        }
                    }
                    name
                }
                _ => String::new(), // 非法变量名首字符（含数字开头）：视为字面 $
            };
            if name.is_empty() {
                out2.push('$');
            } else {
                match std::env::var(&name) {
                    Ok(val) => out2.push_str(&val),
                    // 未定义：丢弃 $，保留变量名原文
                    Err(_) => out2.push_str(&name),
                }
            }
            rest = &after[name.len()..];
        }
    }
    out2
}

/// 展开 token 并把结果转成绝对路径（相对路径锚定 home，避免落到进程 cwd）。
pub fn expand_user_path(input: &str) -> PathBuf {
    let expanded = expand_env_tokens(input);
    let path = PathBuf::from(&expanded);
    if path.is_absolute() {
        path
    } else {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(path)
    }
}

/// §9 `paths.default_dir` 的默认值（token 形式存储）。
pub const DEFAULT_DIR_SETTING: &str = if cfg!(windows) {
    "%USERPROFILE%\\Downloads"
} else {
    "$HOME/Downloads"
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn db_path_is_under_app_dir() {
        assert!(db_path().starts_with(app_data_dir()));
        assert_eq!(db_path().file_name().unwrap(), "db.sqlite");
    }

    #[test]
    fn logs_dir_is_under_app_dir() {
        assert!(logs_dir().starts_with(app_data_dir()));
        assert_eq!(logs_dir().file_name().unwrap(), "logs");
    }

    #[test]
    fn expands_windows_tokens() {
        std::env::set_var("AIDM_TEST_HOME", "/home/tester");
        assert_eq!(
            expand_env_tokens("%AIDM_TEST_HOME%\\Downloads"),
            "/home/tester\\Downloads"
        );
        // 未定义变量保留原样
        assert_eq!(
            expand_env_tokens("%AIDM_UNDEF_XYZ%\\Downloads"),
            "%AIDM_UNDEF_XYZ%\\Downloads"
        );
    }

    #[test]
    fn expands_posix_tokens() {
        std::env::set_var("AIDM_TEST_HOME", "/home/tester");
        assert_eq!(
            expand_env_tokens("$AIDM_TEST_HOME/Downloads"),
            "/home/tester/Downloads"
        );
        assert_eq!(
            expand_env_tokens("${AIDM_TEST_HOME}/Downloads"),
            "/home/tester/Downloads"
        );
        // 字面 $：$5 非法变量名，保留 $
        assert_eq!(expand_env_tokens("cost$5"), "cost$5");
        assert_eq!(expand_env_tokens("${unclosed"), "${unclosed");
    }

    #[test]
    fn expand_user_path_anchors_relative_to_home() {
        let p = expand_user_path("relative/dir");
        assert!(p.is_absolute(), "relative input must anchor to home: {p:?}");
        // `/home/...` is not a Windows absolute path (no drive prefix), so
        // expand_user_path would join it onto the current drive. Use a
        // platform-absolute token value when asserting the expanded PathBuf.
        if cfg!(windows) {
            std::env::set_var("AIDM_TEST_HOME", r"C:\Users\tester");
            assert_eq!(
                expand_user_path(r"%AIDM_TEST_HOME%\Downloads"),
                PathBuf::from(r"C:\Users\tester\Downloads")
            );
        } else {
            std::env::set_var("AIDM_TEST_HOME", "/home/tester");
            assert_eq!(
                expand_user_path("%AIDM_TEST_HOME%\\Downloads"),
                PathBuf::from("/home/tester\\Downloads")
            );
        }
    }
}

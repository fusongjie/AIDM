//! 原生消息宿主登记（仅当前用户）。
//!
//! 写 `com.aidm.host` 的 manifest JSON，以及：
//! - Windows：`HKCU\Software\Google\Chrome\NativeMessagingHosts\com.aidm.host`
//!   与 `HKCU\Software\Microsoft\Edge\NativeMessagingHosts\com.aidm.host`
//! - 非 Windows：用户配置目录下 Chrome / Edge 的 `NativeMessagingHosts/`
//!
//! **永不**写浏览器策略键（`Software\Policies\...` / ExtensionInstallForcelist 等）。

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::paths::app_data_dir;

pub const HOST_NAME: &str = "com.aidm.host";
pub const CHROME_NMH_REG: &str = r"Software\Google\Chrome\NativeMessagingHosts\com.aidm.host";
pub const EDGE_NMH_REG: &str = r"Software\Microsoft\Edge\NativeMessagingHosts\com.aidm.host";

/// 策略键前缀（禁止写入，测试会断言）。
pub const POLICY_KEY_PREFIXES: &[&str] = &[
    r"Software\Policies\Google\Chrome",
    r"Software\Policies\Microsoft\Edge",
    r"SOFTWARE\Policies\Google\Chrome",
    r"SOFTWARE\Policies\Microsoft\Edge",
];

#[derive(Debug, Clone)]
pub struct NmhPaths {
    pub manifest_path: PathBuf,
    pub host_exe: PathBuf,
    pub chrome_user_manifest: Option<PathBuf>,
    pub edge_user_manifest: Option<PathBuf>,
    /// 生产为 true；单测为 false，避免覆盖本机已有 HKCU 登记。
    pub write_registry: bool,
}

impl NmhPaths {
    pub fn default_for(host_exe: &Path) -> Self {
        let manifest_path = app_data_dir().join(format!("{HOST_NAME}.json"));
        let (chrome_user_manifest, edge_user_manifest) = user_browser_manifests();
        Self {
            manifest_path,
            host_exe: host_exe.to_path_buf(),
            chrome_user_manifest,
            edge_user_manifest,
            write_registry: true,
        }
    }
}

fn user_browser_manifests() -> (Option<PathBuf>, Option<PathBuf>) {
    if cfg!(windows) {
        return (None, None);
    }
    let cfg = dirs::config_dir();
    (
        cfg.as_ref().map(|p| {
            p.join("google-chrome/NativeMessagingHosts")
                .join(format!("{HOST_NAME}.json"))
        }),
        cfg.as_ref().map(|p| {
            p.join("microsoft-edge/NativeMessagingHosts")
                .join(format!("{HOST_NAME}.json"))
        }),
    )
}

pub fn allowed_origins_from_ids(ids: &[String]) -> Vec<String> {
    ids.iter()
        .map(|id| {
            let id = id.trim();
            if id.starts_with("chrome-extension://") {
                if id.ends_with('/') {
                    id.to_string()
                } else {
                    format!("{id}/")
                }
            } else {
                format!("chrome-extension://{id}/")
            }
        })
        .collect()
}

pub fn manifest_json(host_exe: &Path, allowed_origins: &[String]) -> Value {
    json!({
        "name": HOST_NAME,
        "description": "AIDM native messaging host",
        "path": host_exe.to_string_lossy(),
        "type": "stdio",
        "allowed_origins": allowed_origins,
    })
}

fn write_json_file(path: &Path, value: &Value) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create nmh dir: {e}"))?;
    }
    let body = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
    std::fs::write(path, body).map_err(|e| format!("write nmh manifest: {e}"))
}

fn remove_file_if_exists(path: &Path) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("remove nmh manifest: {e}")),
    }
}

/// 登记宿主：写 manifest，并只写当前用户的 Chrome/Edge NativeMessagingHosts。
pub fn register(paths: &NmhPaths, allowed_ext_ids: &[String]) -> Result<(), String> {
    assert_no_policy_targets();
    let origins = allowed_origins_from_ids(allowed_ext_ids);
    let manifest = manifest_json(&paths.host_exe, &origins);
    write_json_file(&paths.manifest_path, &manifest)?;
    if let Some(p) = &paths.chrome_user_manifest {
        write_json_file(p, &manifest)?;
    }
    if let Some(p) = &paths.edge_user_manifest {
        write_json_file(p, &manifest)?;
    }
    #[cfg(windows)]
    if paths.write_registry {
        write_hkcu_default(CHROME_NMH_REG, &paths.manifest_path)?;
        write_hkcu_default(EDGE_NMH_REG, &paths.manifest_path)?;
    }
    Ok(())
}

/// 撤销登记：删用户级 manifest / HKCU 值，不动策略键。
pub fn unregister(paths: &NmhPaths) -> Result<(), String> {
    assert_no_policy_targets();
    remove_file_if_exists(&paths.manifest_path)?;
    if let Some(p) = &paths.chrome_user_manifest {
        remove_file_if_exists(p)?;
    }
    if let Some(p) = &paths.edge_user_manifest {
        remove_file_if_exists(p)?;
    }
    #[cfg(windows)]
    if paths.write_registry {
        delete_hkcu_key(CHROME_NMH_REG)?;
        delete_hkcu_key(EDGE_NMH_REG)?;
    }
    Ok(())
}

pub fn is_registered(paths: &NmhPaths) -> bool {
    #[cfg(windows)]
    if paths.write_registry
        && (hkcu_default_exists(CHROME_NMH_REG) || hkcu_default_exists(EDGE_NMH_REG))
    {
        return true;
    }
    if paths.manifest_path.is_file() {
        return true;
    }
    paths
        .chrome_user_manifest
        .as_ref()
        .map(|p| p.is_file())
        .unwrap_or(false)
        || paths
            .edge_user_manifest
            .as_ref()
            .map(|p| p.is_file())
            .unwrap_or(false)
}

/// 与引擎同目录的 `aidm-ext-host` 可执行文件（不存在时仍返回预期路径，供安装后登记）。
pub fn sibling_host_exe() -> PathBuf {
    let name = if cfg!(windows) {
        "aidm-ext-host.exe"
    } else {
        "aidm-ext-host"
    };
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join(name)))
        .unwrap_or_else(|| PathBuf::from(name))
}

fn assert_no_policy_targets() {
    // 编译期文档：本模块只引用 HKCU NativeMessagingHosts，不含 Policies。
    debug_assert!(POLICY_KEY_PREFIXES
        .iter()
        .all(|p| { !CHROME_NMH_REG.starts_with(p) && !EDGE_NMH_REG.starts_with(p) }));
}

#[cfg(windows)]
fn write_hkcu_default(subkey: &str, manifest_path: &Path) -> Result<(), String> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (key, _) = hkcu
        .create_subkey(subkey)
        .map_err(|e| format!("create {subkey}: {e}"))?;
    key.set_value("", &manifest_path.to_string_lossy().into_owned())
        .map_err(|e| format!("set {subkey}: {e}"))
}

#[cfg(windows)]
fn delete_hkcu_key(subkey: &str) -> Result<(), String> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    match hkcu.delete_subkey(subkey) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("delete {subkey}: {e}")),
    }
}

#[cfg(windows)]
fn hkcu_default_exists(subkey: &str) -> bool {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let Ok(key) = hkcu.open_subkey(subkey) else {
        return false;
    };
    let val: Result<String, _> = key.get_value("");
    val.map(|s| !s.trim().is_empty()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins_normalize_ids() {
        let v = allowed_origins_from_ids(&[
            "npapgdblbbcppnbmhgdnmdbggfdnpahg".into(),
            "chrome-extension://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
        ]);
        assert_eq!(
            v,
            vec![
                "chrome-extension://npapgdblbbcppnbmhgdnmdbggfdnpahg/".to_string(),
                "chrome-extension://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/".to_string(),
            ]
        );
    }

    #[test]
    fn register_unregister_roundtrip_user_only() {
        // 临时目录由 `tempfile::tempdir()` 提供：绝对路径 + Drop 自动清理。
        let tmp = crate::testsupport::tempdir("nmh");
        let dir = tmp.path().to_path_buf();
        let host = dir.join(if cfg!(windows) {
            "aidm-ext-host.exe"
        } else {
            "aidm-ext-host"
        });
        std::fs::write(&host, b"").unwrap();
        let paths = NmhPaths {
            manifest_path: dir.join("com.aidm.host.json"),
            host_exe: host,
            chrome_user_manifest: Some(dir.join("chrome").join("com.aidm.host.json")),
            edge_user_manifest: Some(dir.join("edge").join("com.aidm.host.json")),
            write_registry: false,
        };
        assert!(!is_registered(&paths));
        register(&paths, &["npapgdblbbcppnbmhgdnmdbggfdnpahg".into()]).unwrap();
        assert!(is_registered(&paths));
        let body = std::fs::read_to_string(&paths.manifest_path).unwrap();
        assert!(body.contains(HOST_NAME));
        assert!(body.contains("chrome-extension://npapgdblbbcppnbmhgdnmdbggfdnpahg/"));
        assert!(!body.to_ascii_lowercase().contains("policies"));
        unregister(&paths).unwrap();
        #[cfg(not(windows))]
        {
            assert!(!is_registered(&paths));
        }
    }

    #[test]
    fn never_targets_policy_keys() {
        for p in POLICY_KEY_PREFIXES {
            assert!(
                !CHROME_NMH_REG.starts_with(p),
                "chrome key must not be under {p}"
            );
            assert!(
                !EDGE_NMH_REG.starts_with(p),
                "edge key must not be under {p}"
            );
        }
    }
}

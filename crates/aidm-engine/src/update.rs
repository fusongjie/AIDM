//! 应用内更新（开发文档 §10）。
//!
//! 流程：GET `{base}/{channel}/version.json` → 与当前 crate 版本比较 →
//! 下载到用户临时目录 → SHA256 必须匹配 → 调用 MSI 替换。
//! 失败不改动已安装版本；永不写系统代理或浏览器策略键。
//! 签名字段可选，本里程碑钩子占位。无私有仓鉴权、无客户端 git pull。

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aidm_core::error as core_error;
use aidm_core::hash::sha256_file;
use aidm_core::model;
use aidm_core::settings;
use aidm_ipc::{
    EngineEvent, ERR_CHECKSUM_MISMATCH, ERR_CHECK_FAILED, ERR_NETWORK, ERR_SIGNATURE_INVALID,
    ERR_UPDATE_FAILED, UPDATE_PHASE_APPLYING, UPDATE_PHASE_AVAILABLE, UPDATE_PHASE_CHECKING,
    UPDATE_PHASE_DONE, UPDATE_PHASE_DOWNLOADING, UPDATE_PHASE_ERROR, UPDATE_PHASE_UP_TO_DATE,
    UPDATE_PHASE_VERIFYING,
};
use rusqlite::Connection;
use serde_json::Value;

use crate::http_util::HttpRuntime;
use crate::manager::EventHub;

/// 成功检查后缓存的可用更新（供 `update_download_apply`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvailableUpdate {
    pub version: String,
    pub url: String,
    pub sha256: String,
    pub signature: Option<String>,
    pub notes: Option<String>,
}

pub type ApplyHook = Arc<dyn Fn(&Path) -> Result<(), String> + Send + Sync>;

pub struct UpdateRuntime {
    busy: AtomicBool,
    available: Mutex<Option<AvailableUpdate>>,
    apply: Mutex<Option<ApplyHook>>,
    staging: Mutex<PathBuf>,
}

impl UpdateRuntime {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            busy: AtomicBool::new(false),
            available: Mutex::new(None),
            apply: Mutex::new(None),
            staging: Mutex::new(staging_dir()),
        })
    }

    pub fn set_staging_dir(&self, path: PathBuf) {
        *self.staging.lock().unwrap() = path;
    }

    pub fn staging(&self) -> PathBuf {
        self.staging.lock().unwrap().clone()
    }

    pub(crate) fn try_begin(&self) -> bool {
        self.busy
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    pub(crate) fn end(&self) {
        self.busy.store(false, Ordering::SeqCst);
    }

    pub fn available(&self) -> Option<AvailableUpdate> {
        self.available.lock().unwrap().clone()
    }

    pub fn set_apply_hook(&self, hook: Option<ApplyHook>) {
        *self.apply.lock().unwrap() = hook;
    }
}

/// 解析 `version.json`。缺字段 / 非法 version / 非 http(s) url / 非法 sha256 → 失败。
pub fn parse_manifest(text: &str) -> Result<AvailableUpdate, String> {
    let v: Value = serde_json::from_str(text).map_err(|_| "invalid_json".to_string())?;
    if !v.is_object() {
        return Err("invalid_json".into());
    }
    let version = v
        .get("version")
        .and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "missing_version".to_string())?
        .to_string();
    if parse_semver(&version).is_none() {
        return Err("invalid_version".into());
    }
    let url = v
        .get("url")
        .and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "missing_url".to_string())?
        .to_string();
    let lower = url.to_ascii_lowercase();
    if !(lower.starts_with("https://") || lower.starts_with("http://")) {
        return Err("invalid_url".into());
    }
    let sha256 = v
        .get("sha256")
        .and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "missing_sha256".to_string())?
        .to_ascii_lowercase();
    if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("invalid_sha256".into());
    }
    let signature = v
        .get("signature")
        .and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let notes = v
        .get("notes")
        .and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    Ok(AvailableUpdate {
        version,
        url,
        sha256,
        signature,
        notes,
    })
}

pub fn parse_semver(s: &str) -> Option<(u64, u64, u64)> {
    let s = s.trim().trim_start_matches('v');
    let mut parts = s.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts
        .next()
        .unwrap_or("0")
        .split('-')
        .next()?
        .parse()
        .ok()?;
    let patch = parts
        .next()
        .unwrap_or("0")
        .split('-')
        .next()?
        .parse()
        .ok()?;
    Some((major, minor, patch))
}

pub fn is_newer(remote: &str, current: &str) -> bool {
    match (parse_semver(remote), parse_semver(current)) {
        (Some(r), Some(c)) => r > c,
        _ => false,
    }
}

pub fn current_app_version() -> &'static str {
    settings::app_version()
}

pub fn update_error_message(code: &str) -> &'static str {
    match code {
        ERR_NETWORK => "无法连接更新服务器",
        ERR_CHECK_FAILED => "检查更新失败",
        ERR_CHECKSUM_MISMATCH => "更新文件校验失败，未安装任何改动",
        ERR_SIGNATURE_INVALID => "更新签名无效，已拒绝安装",
        _ => "更新失败",
    }
}

/// 签名钩子：本里程碑占位，有字段也不验、不失败。
/// 清单签名公钥（minisign 公钥的 base64 部分，Tauri signer 生成）。
/// 对应私钥只存放在发布机 / GitHub Environment，不进仓库。
const UPDATE_PUBKEY: &str = "RWRWibd8Ary9uPMO9bGt8yCWZzbAH0N3D3s9PpjOf/6EA3qW3pBhGwXp";

/// 签名覆盖的规范化字节：`version\nurl\nsha256`（sha256 小写）。
/// 发布脚本必须用完全相同的字节签名，否则签名不匹配。
pub fn signature_payload(version: &str, url: &str, sha256: &str) -> String {
    format!(
        "{}\n{}\n{}",
        version.trim(),
        url.trim(),
        sha256.trim().to_ascii_lowercase()
    )
}

/// 签名内容可能是 Tauri 的 base64 `.sig`，也可能是解码后的 minisign 文本。
fn minisign_signature_text(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    if raw.starts_with("untrusted comment:") {
        return Ok(raw.to_string());
    }
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(raw)
        .map_err(|_| "invalid_signature".to_string())?;
    String::from_utf8(bytes).map_err(|_| "invalid_signature".to_string())
}

/// 验证清单签名；缺失、格式错误或不匹配都拒绝。
pub fn verify_manifest_signature(pkg: &AvailableUpdate) -> Result<(), String> {
    let raw = pkg
        .signature
        .as_deref()
        .ok_or_else(|| "missing_signature".to_string())?;
    let text = minisign_signature_text(raw)?;
    let key = minisign_verify::PublicKey::from_base64(UPDATE_PUBKEY)
        .map_err(|_| "invalid_pubkey".to_string())?;
    let sig = minisign_verify::Signature::decode(&text)
        .map_err(|_| "invalid_signature".to_string())?;
    let payload = signature_payload(&pkg.version, &pkg.url, &pkg.sha256);
    key.verify(payload.as_bytes(), &sig, false)
        .map_err(|_| "signature_mismatch".to_string())
}

pub fn staging_dir() -> PathBuf {
    if let Ok(p) = std::env::var("AIDM_UPDATE_STAGING_DIR") {
        let p = p.trim();
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    aidm_core::app_data_dir().join("update")
}

pub fn auto_check_interval() -> Duration {
    if let Ok(ms) = std::env::var("AIDM_UPDATE_AUTO_CHECK_MS") {
        if let Ok(n) = ms.parse::<u64>() {
            if n > 0 {
                return Duration::from_millis(n);
            }
        }
    }
    Duration::from_secs(3600)
}

/// 启动后先检查一次（默认 5s 后），之后每 1 小时一次。
pub fn spawn_auto_check(manager: Arc<crate::manager::DownloadManager>) {
    let interval = auto_check_interval();
    let initial = std::env::var("AIDM_UPDATE_INITIAL_DELAY_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_millis)
        .unwrap_or(Duration::from_secs(5));
    let _ = std::thread::Builder::new()
        .name("aidm-update".into())
        .spawn(move || {
            std::thread::sleep(initial);
            if manager.update_auto_check_enabled() {
                manager.update_check();
            }
            loop {
                std::thread::sleep(interval);
                if manager.update_auto_check_enabled() {
                    manager.update_check();
                }
            }
        });
}

pub(crate) fn run_check(
    http: &HttpRuntime,
    db: &Mutex<Connection>,
    events: &EventHub,
    update: &UpdateRuntime,
) {
    let current = current_app_version().to_string();
    emit(
        events,
        EngineEvent::Update {
            phase: UPDATE_PHASE_CHECKING.into(),
            current_version: Some(current.clone()),
            version: None,
            notes: None,
            url: None,
            bytes_done: None,
            bytes_total: None,
            error: None,
            code: None,
        },
    );

    let (url, channel) = {
        let conn = db.lock().unwrap();
        let channel = settings::update_channel(&conn);
        let base = settings::resolve_manifest_base_url(&conn);
        (settings::manifest_url(&base, &channel), channel)
    };
    log::info!(
        "update check {channel} {}",
        aidm_core::redact::redact_url(&url)
    );

    let agent = http.agent();
    let result = fetch_manifest(&agent, &url);
    touch_last_check(db);

    match result {
        Ok(manifest) => {
            if is_newer(&manifest.version, &current) {
                emit(
                    events,
                    EngineEvent::Update {
                        phase: UPDATE_PHASE_AVAILABLE.into(),
                        current_version: Some(current),
                        version: Some(manifest.version.clone()),
                        notes: manifest.notes.clone(),
                        url: Some(manifest.url.clone()),
                        bytes_done: None,
                        bytes_total: None,
                        error: None,
                        code: None,
                    },
                );
                *update.available.lock().unwrap() = Some(manifest);
            } else {
                *update.available.lock().unwrap() = None;
                emit(
                    events,
                    EngineEvent::Update {
                        phase: UPDATE_PHASE_UP_TO_DATE.into(),
                        current_version: Some(current),
                        version: Some(manifest.version),
                        notes: manifest.notes,
                        url: None,
                        bytes_done: None,
                        bytes_total: None,
                        error: None,
                        code: None,
                    },
                );
            }
        }
        Err((code, detail)) => {
            log::warn!("update check failed ({code}): {detail}");
            emit_error(events, &current, None, code, None);
        }
    }
}

pub(crate) fn run_apply(
    http: &HttpRuntime,
    events: &EventHub,
    update: &UpdateRuntime,
    dest_dir: &Path,
) {
    let current = current_app_version().to_string();
    let Some(pkg) = update.available() else {
        emit_error(
            events,
            &current,
            None,
            ERR_UPDATE_FAILED,
            Some("no_update_available"),
        );
        return;
    };

    let file_name = dest_file_name(&pkg.url);
    if let Err(e) = std::fs::create_dir_all(dest_dir) {
        emit_error(
            events,
            &current,
            Some(&pkg.version),
            ERR_UPDATE_FAILED,
            Some(&e.to_string()),
        );
        return;
    }
    let dest = dest_dir.join(&file_name);

    match download_package(http, events, &current, &pkg, &dest) {
        Ok(()) => {}
        Err((code, detail)) => {
            let _ = std::fs::remove_file(&dest);
            emit_error(events, &current, Some(&pkg.version), code, Some(&detail));
            return;
        }
    }

    emit(
        events,
        EngineEvent::Update {
            phase: UPDATE_PHASE_VERIFYING.into(),
            current_version: Some(current.clone()),
            version: Some(pkg.version.clone()),
            notes: pkg.notes.clone(),
            url: Some(pkg.url.clone()),
            bytes_done: None,
            bytes_total: None,
            error: None,
            code: None,
        },
    );

    match sha256_file(&dest) {
        Ok(got) if hashes_equal(&got, &pkg.sha256) => {}
        Ok(_) => {
            let _ = std::fs::remove_file(&dest);
            emit_error(
                events,
                &current,
                Some(&pkg.version),
                ERR_CHECKSUM_MISMATCH,
                None,
            );
            return;
        }
        Err(e) => {
            let _ = std::fs::remove_file(&dest);
            emit_error(
                events,
                &current,
                Some(&pkg.version),
                ERR_UPDATE_FAILED,
                Some(&e.to_string()),
            );
            return;
        }
    }
    if let Err(e) = verify_manifest_signature(&pkg) {
        let _ = std::fs::remove_file(&dest);
        emit_error(
            events,
            &current,
            Some(&pkg.version),
            ERR_SIGNATURE_INVALID,
            Some(&e),
        );
        return;
    }

    emit(
        events,
        EngineEvent::Update {
            phase: UPDATE_PHASE_APPLYING.into(),
            current_version: Some(current.clone()),
            version: Some(pkg.version.clone()),
            notes: pkg.notes.clone(),
            url: Some(pkg.url.clone()),
            bytes_done: None,
            bytes_total: None,
            error: None,
            code: None,
        },
    );

    let apply_result = {
        let hook = update.apply.lock().unwrap().clone();
        match hook {
            Some(hook) => hook(&dest),
            None => apply_package(&dest),
        }
    };
    match apply_result {
        Ok(()) => {
            *update.available.lock().unwrap() = None;
            emit(
                events,
                EngineEvent::Update {
                    phase: UPDATE_PHASE_DONE.into(),
                    current_version: Some(current),
                    version: Some(pkg.version),
                    notes: pkg.notes,
                    url: Some(pkg.url),
                    bytes_done: None,
                    bytes_total: None,
                    error: None,
                    code: None,
                },
            );
        }
        Err(e) => {
            // MSI 失败由安装器回滚；此处不覆盖已安装文件。
            log::warn!("update apply failed (previous install intact): {e}");
            emit_error(
                events,
                &current,
                Some(&pkg.version),
                ERR_UPDATE_FAILED,
                Some(&e),
            );
        }
    }
}

/// Windows：`.msi` 走 `msiexec /qn`；Tauri NSIS 的 `*-setup.exe` 走 `/S` 静默安装。
/// 安装器的 PREINSTALL 钩子会结束 AIDM 引擎/界面，因此 exe 分支只负责拉起安装器，
/// 然后让当前进程退出；旧安装由安装器自行替换，失败时保留旧版本。
/// 非 Windows：不替换，返回错误（测试请注入 apply hook）。
pub fn apply_package(path: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        let is_exe = path
            .extension()
            .and_then(|s| s.to_str())
            .map(|s| s.eq_ignore_ascii_case("exe"))
            .unwrap_or(false);
        if is_exe {
            std::process::Command::new(path)
                .arg("/S")
                .spawn()
                .map_err(|e| format!("nsis: {e}"))?;
            // 给安装器时间启动并接管（它会结束当前引擎与界面）。
            std::thread::sleep(Duration::from_millis(1500));
            std::process::exit(0);
        }
        let status = std::process::Command::new("msiexec")
            .arg("/i")
            .arg(path.as_os_str())
            .arg("/qn")
            .arg("/norestart")
            .status()
            .map_err(|e| format!("msiexec: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("msiexec_failed: {}", status.code().unwrap_or(-1)))
        }
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err("update_apply_unsupported".into())
    }
}

fn fetch_manifest(
    agent: &ureq::Agent,
    url: &str,
) -> Result<AvailableUpdate, (&'static str, String)> {
    let resp = match agent.get(url).call() {
        Ok(r) => r,
        Err(ureq::Error::Status(code, _)) => {
            return Err((classify_http_for_check(code), format!("http_{code}")));
        }
        Err(e) => {
            return Err((
                classify_transport(&e.to_string(), ERR_CHECK_FAILED),
                e.to_string(),
            ))
        }
    };
    let status = resp.status();
    if !(200..300).contains(&status) {
        return Err((classify_http_for_check(status), format!("http_{status}")));
    }
    let text = resp.into_string().map_err(|e| {
        (
            classify_transport(&e.to_string(), ERR_CHECK_FAILED),
            e.to_string(),
        )
    })?;
    parse_manifest(&text)
        .map_err(|e| (ERR_CHECK_FAILED, e))
        .and_then(|pkg| {
            verify_manifest_signature(&pkg).map_err(|e| (ERR_SIGNATURE_INVALID, e))?;
            Ok(pkg)
        })
}

fn download_package(
    http: &HttpRuntime,
    events: &EventHub,
    current: &str,
    pkg: &AvailableUpdate,
    dest: &Path,
) -> Result<(), (&'static str, String)> {
    let agent = http.agent();
    let resp = match agent.get(&pkg.url).call() {
        Ok(r) => r,
        Err(ureq::Error::Status(code, _)) => {
            return Err((classify_http_for_download(code), format!("http_{code}")));
        }
        Err(e) => {
            return Err((
                classify_transport(&e.to_string(), ERR_UPDATE_FAILED),
                e.to_string(),
            ))
        }
    };
    let status = resp.status();
    if !(200..300).contains(&status) {
        return Err((classify_http_for_download(status), format!("http_{status}")));
    }
    let total = resp
        .header("Content-Length")
        .and_then(|s| s.parse::<u64>().ok());
    emit(
        events,
        EngineEvent::Update {
            phase: UPDATE_PHASE_DOWNLOADING.into(),
            current_version: Some(current.into()),
            version: Some(pkg.version.clone()),
            notes: pkg.notes.clone(),
            url: Some(pkg.url.clone()),
            bytes_done: Some(0),
            bytes_total: total,
            error: None,
            code: None,
        },
    );

    let mut reader = resp.into_reader();
    let mut file = std::fs::File::create(dest).map_err(|e| (ERR_UPDATE_FAILED, e.to_string()))?;
    let mut buf = vec![0u8; 64 * 1024];
    let mut done = 0u64;
    loop {
        let n = reader.read(&mut buf).map_err(|e| {
            (
                classify_transport(&e.to_string(), ERR_NETWORK),
                e.to_string(),
            )
        })?;
        if n == 0 {
            break;
        }
        file.write_all(&buf[..n])
            .map_err(|e| (ERR_UPDATE_FAILED, e.to_string()))?;
        done += n as u64;
        emit(
            events,
            EngineEvent::Update {
                phase: UPDATE_PHASE_DOWNLOADING.into(),
                current_version: Some(current.into()),
                version: Some(pkg.version.clone()),
                notes: pkg.notes.clone(),
                url: Some(pkg.url.clone()),
                bytes_done: Some(done),
                bytes_total: total,
                error: None,
                code: None,
            },
        );
    }
    file.flush()
        .map_err(|e| (ERR_UPDATE_FAILED, e.to_string()))?;
    Ok(())
}

fn classify_http_for_check(status: u16) -> &'static str {
    match status {
        408 | 429 | 500..=599 => ERR_NETWORK,
        _ => ERR_CHECK_FAILED,
    }
}

fn classify_http_for_download(status: u16) -> &'static str {
    match status {
        408 | 429 | 500..=599 => ERR_NETWORK,
        _ => ERR_UPDATE_FAILED,
    }
}

fn classify_transport(raw: &str, fallback: &'static str) -> &'static str {
    let c = core_error::classify(raw);
    if c.code == core_error::CODE_NETWORK {
        return ERR_NETWORK;
    }
    let lower = raw.to_ascii_lowercase();
    if lower.contains("connection")
        || lower.contains("dns")
        || lower.contains("timeout")
        || lower.contains("timed out")
        || lower.contains("reset")
        || lower.contains("refused")
        || lower.contains("unreachable")
        || lower.contains("name or service")
        || lower.contains("failed to lookup")
        || lower.contains("io error")
        || lower.contains("broken pipe")
        || lower.contains("eof")
    {
        ERR_NETWORK
    } else {
        fallback
    }
}

fn hashes_equal(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b.trim())
}

fn dest_file_name(url: &str) -> String {
    let path = url.split('?').next().unwrap_or(url);
    path.rsplit('/')
        .next()
        .filter(|s| {
            !s.is_empty()
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        })
        .unwrap_or("pending.msi")
        .to_string()
}

fn touch_last_check(db: &Mutex<Connection>) {
    let conn = db.lock().unwrap();
    if let Err(e) = settings::write_last_check_at(&conn, model::now_ms()) {
        log::warn!("write update.last_check_at failed: {e}");
    }
}

fn emit(events: &EventHub, ev: EngineEvent) {
    events.emit(ev);
}

fn emit_error(
    events: &EventHub,
    current: &str,
    version: Option<&str>,
    code: &str,
    detail: Option<&str>,
) {
    let msg = update_error_message(code);
    let error = match detail {
        Some(d) if !d.is_empty() && code == ERR_UPDATE_FAILED => format!("{msg}: {d}"),
        _ => msg.to_string(),
    };
    emit(
        events,
        EngineEvent::Update {
            phase: UPDATE_PHASE_ERROR.into(),
            current_version: Some(current.into()),
            version: version.map(str::to_string),
            notes: None,
            url: None,
            bytes_done: None,
            bytes_total: None,
            error: Some(error),
            code: Some(code.into()),
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_manifest() {
        let m = parse_manifest(
            r#"{
              "version": "0.2.0",
              "url": "https://releases.example/app.msi",
              "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
              "notes": "fix",
              "signature": "optional"
            }"#,
        )
        .unwrap();
        assert_eq!(m.version, "0.2.0");
        assert_eq!(m.notes.as_deref(), Some("fix"));
        assert_eq!(m.signature.as_deref(), Some("optional"));
    }

    #[test]
    fn rejects_invalid_manifests() {
        assert!(parse_manifest("not-json").is_err());
        assert!(parse_manifest(r#"{"version":"0.2.0"}"#).is_err());
        assert!(parse_manifest(
            r#"{"version":"nope","url":"https://x/a","sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}"#
        )
        .is_err());
        assert!(parse_manifest(
            r#"{"version":"0.2.0","url":"ftp://x/a","sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}"#
        )
        .is_err());
        assert!(
            parse_manifest(r#"{"version":"0.2.0","url":"https://x/a","sha256":"zzzz"}"#).is_err()
        );
    }

    #[test]
    fn semver_newer() {
        assert!(is_newer("0.2.0", "0.1.0"));
        assert!(is_newer("1.0.0", "0.9.9"));
        assert!(!is_newer("0.1.0", "0.1.0"));
        assert!(!is_newer("0.0.9", "0.1.0"));
        assert!(!is_newer("not-semver", "0.1.0"));
    }

    #[test]
    fn error_copy_matches_ui() {
        assert_eq!(update_error_message(ERR_NETWORK), "无法连接更新服务器");
        assert_eq!(update_error_message(ERR_CHECK_FAILED), "检查更新失败");
        assert_eq!(
            update_error_message(ERR_CHECKSUM_MISMATCH),
            "更新文件校验失败，未安装任何改动"
        );
        assert_eq!(
            update_error_message(ERR_SIGNATURE_INVALID),
            "更新签名无效，已拒绝安装"
        );
        assert_eq!(update_error_message(ERR_UPDATE_FAILED), "更新失败");
    }

    #[test]
    fn signature_payload_is_stable() {
        assert_eq!(
            signature_payload(" 0.2.0 ", " https://x/a ", "ABCDEF"),
            "0.2.0\nhttps://x/a\nabcdef"
        );
    }

    #[test]
    fn pubkey_is_valid() {
        assert!(minisign_verify::PublicKey::from_base64(UPDATE_PUBKEY).is_ok());
    }

    #[test]
    fn rejects_missing_signature() {
        let pkg = AvailableUpdate {
            version: "0.2.0".into(),
            url: "https://x/a".into(),
            sha256: "0".repeat(64),
            signature: None,
            notes: None,
        };
        assert_eq!(
            verify_manifest_signature(&pkg).unwrap_err(),
            "missing_signature"
        );
    }

    #[test]
    fn verifies_real_tauri_signature() {
        // 用生产公钥对应的私钥签的固定向量（签名本身可公开）。
        // payload = "0.2.0\nhttps://example.com/a.exe\n" + 64 个 '0'。
        let signature = "dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZSBmcm9tIHRhdXJpIHNlY3JldCBrZXkKUlVSV2liZDhBcnk5dUQ1aWRFMnFrWWNmWUdwbk9OUHlGRDlNK1Z5eTEzQXF1M1Boa3pSeU9YUjJmL3NxNHhZL1BjcXZabUFaNU02b3FRS2tDUWdvT2x6VTRhUWdtVnJRT1FZPQp0cnVzdGVkIGNvbW1lbnQ6IHRpbWVzdGFtcDoxNzkyNzQwNDQxCWZpbGU6cGF5bG9hZC50eHQKN2lNbHdlYlRJYXBjWnE5Q3YrTzFEU2lNaElmaHdZeE9ZeEh1TFhkYXZDWVYwVHRWeFovYWdCQUxCcThLYzlyT3VlemlobUNYTkJpaVIrSkh0dXJsQmc9PQo=";
        let pkg = AvailableUpdate {
            version: "0.2.0".into(),
            url: "https://example.com/a.exe".into(),
            sha256: "0".repeat(64),
            signature: Some(signature.into()),
            notes: None,
        };
        assert!(verify_manifest_signature(&pkg).is_ok());

        let mut tampered = pkg.clone();
        tampered.version = "0.2.1".into();
        assert!(verify_manifest_signature(&tampered).is_err());
    }

    #[test]
    fn transport_is_network() {
        assert_eq!(
            classify_transport("Connection Failed: Connection refused", ERR_CHECK_FAILED),
            ERR_NETWORK
        );
        assert_eq!(
            classify_transport("dns lookup failed", ERR_CHECK_FAILED),
            ERR_NETWORK
        );
        assert_eq!(classify_http_for_check(503), ERR_NETWORK);
        assert_eq!(classify_http_for_check(404), ERR_CHECK_FAILED);
        assert_eq!(classify_http_for_download(404), ERR_UPDATE_FAILED);
    }
}

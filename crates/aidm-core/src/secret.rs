//! 敏感设置保护：密码不得以明文写入 SQLite。
//!
//! - Windows：DPAPI（`CryptProtectData` / `CryptUnprotectData`，当前用户作用域）
//! - 非 Windows（开发 / CI）：本地 `enc:v1:` 混淆回退，仅保证库内不是明文

use sha2::{Digest, Sha256};

pub const ENC_PREFIX: &str = "enc:v1:";
pub const DPAPI_PREFIX: &str = "dpapi:";

const FALLBACK_SALT: &[u8] = b"aidm-proxy-pass-v1";

/// 保护明文。空串原样返回（表示未设置）。
pub fn protect(plain: &str) -> Result<String, String> {
    if plain.is_empty() {
        return Ok(String::new());
    }
    #[cfg(windows)]
    {
        let blob = win_dpapi::protect(plain.as_bytes())?;
        return Ok(format!("{DPAPI_PREFIX}{}", hex_encode(&blob)));
    }
    #[cfg(not(windows))]
    {
        Ok(fallback_protect(plain.as_bytes()))
    }
}

/// 还原受保护值。空串、未加前缀的历史值按原样返回。
pub fn unprotect(stored: &str) -> Result<String, String> {
    if stored.is_empty() {
        return Ok(String::new());
    }
    if let Some(_hex) = stored.strip_prefix(DPAPI_PREFIX) {
        #[cfg(windows)]
        {
            let blob = hex_decode(_hex).ok_or_else(|| "dpapi_blob_corrupt".to_string())?;
            let plain = win_dpapi::unprotect(&blob)?;
            return String::from_utf8(plain).map_err(|_| "dpapi_utf8".into());
        }
        #[cfg(not(windows))]
        {
            return Err("dpapi_unavailable".into());
        }
    }
    if let Some(hex) = stored.strip_prefix(ENC_PREFIX) {
        let blob = hex_decode(hex).ok_or_else(|| "enc_blob_corrupt".to_string())?;
        let plain = fallback_unprotect(&blob)?;
        return String::from_utf8(plain).map_err(|_| "enc_utf8".into());
    }
    // 兼容：历史明文（不应再写入）
    Ok(stored.to_string())
}

pub fn is_protected(stored: &str) -> bool {
    stored.starts_with(ENC_PREFIX) || stored.starts_with(DPAPI_PREFIX)
}

/// 非 Windows 的本地回退：`enc:v1:` + 盐化 SHA-256 密钥流异或。
///
/// **只在非 Windows 编译**：Windows 上 `protect()` 走 DPAPI，这两个函数会变成
/// 死代码。它们不是"留着以后用"，而是 Linux/CI 上唯一的写入路径，
/// 所以用 cfg 精确表达，而不是 `allow(dead_code)`。
#[cfg(not(windows))]
fn fallback_protect(plain: &[u8]) -> String {
    let mut nonce = [0u8; 16];
    fill_nonce(&mut nonce);
    let key = derive_key(&nonce);
    let mut out = Vec::with_capacity(16 + plain.len());
    out.extend_from_slice(&nonce);
    for (i, b) in plain.iter().enumerate() {
        out.push(b ^ key[i % key.len()]);
    }
    format!("{ENC_PREFIX}{}", hex_encode(&out))
}

fn fallback_unprotect(blob: &[u8]) -> Result<Vec<u8>, String> {
    if blob.len() < 16 {
        return Err("enc_blob_short".into());
    }
    let (nonce, ct) = blob.split_at(16);
    let key = derive_key(nonce);
    Ok(ct
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect())
}

fn derive_key(nonce: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(FALLBACK_SALT);
    h.update(nonce);
    h.finalize().into()
}

/// 随机数：优先 `/dev/urandom`，否则用纳秒 + pid 混合（非 Windows 回退专用）。
#[cfg(not(windows))]
fn fill_nonce(buf: &mut [u8]) {
    #[cfg(unix)]
    {
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            use std::io::Read;
            if f.read_exact(buf).is_ok() {
                return;
            }
        }
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    for (i, slot) in buf.iter_mut().enumerate() {
        *slot = ((nanos >> ((i % 8) * 8)) as u8) ^ (pid as u8).wrapping_add(i as u8);
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = from_hex(bytes[i])?;
        let lo = from_hex(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(windows)]
mod win_dpapi {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB,
    };

    pub fn protect(plain: &[u8]) -> Result<Vec<u8>, String> {
        crypt(plain, true)
    }

    pub fn unprotect(blob: &[u8]) -> Result<Vec<u8>, String> {
        crypt(blob, false)
    }

    fn crypt(input: &[u8], seal: bool) -> Result<Vec<u8>, String> {
        let data_in = CRYPT_INTEGER_BLOB {
            cbData: input.len() as u32,
            pbData: input.as_ptr() as *mut u8,
        };
        let mut data_out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        // CI / 无桌面会话：禁止弹出 DPAPI UI。
        const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;
        let ok = unsafe {
            if seal {
                CryptProtectData(
                    &data_in,
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    CRYPTPROTECT_UI_FORBIDDEN,
                    &mut data_out,
                )
            } else {
                CryptUnprotectData(
                    &data_in,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    CRYPTPROTECT_UI_FORBIDDEN,
                    &mut data_out,
                )
            }
        };
        if ok == 0 {
            return Err(if seal {
                "dpapi_protect_failed".into()
            } else {
                "dpapi_unprotect_failed".into()
            });
        }
        let out = unsafe {
            if data_out.pbData.is_null() {
                Vec::new()
            } else {
                std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize).to_vec()
            }
        };
        unsafe {
            if !data_out.pbData.is_null() {
                LocalFree(data_out.pbData as _);
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_roundtrip() {
        assert_eq!(protect("").unwrap(), "");
        assert_eq!(unprotect("").unwrap(), "");
    }

    #[test]
    fn fallback_roundtrip_not_plaintext() {
        let stored = protect("hunter2-secret").unwrap();
        assert!(!stored.contains("hunter2-secret"), "stored={stored}");
        assert!(is_protected(&stored), "stored={stored}");
        assert_eq!(unprotect(&stored).unwrap(), "hunter2-secret");
    }

    #[test]
    fn unprotect_legacy_plaintext() {
        assert_eq!(unprotect("legacy").unwrap(), "legacy");
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_roundtrip_not_plaintext() {
        let stored = protect("win-secret").unwrap();
        assert!(stored.starts_with(DPAPI_PREFIX), "stored={stored}");
        assert!(!stored.contains("win-secret"));
        assert_eq!(unprotect(&stored).unwrap(), "win-secret");
    }
}

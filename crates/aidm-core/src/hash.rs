//! 最终文件 SHA256（§3.2 校验；流式，避免把整文件读进内存）。

use std::io::{Read, Write};
use std::path::Path;

use ring::digest::{digest, Context, SHA256};

/// 计算内存字节的 SHA256，返回小写 hex。
///
/// 用于对短串（如规范化后的 URL）做不可逆的判重键，避免把原文写进键/事件。
pub fn sha256_hex(input: &[u8]) -> String {
    hex_lower(digest(&SHA256, input).as_ref())
}

/// 计算文件 SHA256，返回小写 hex。
pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    let file = std::fs::File::open(path)?;
    sha256_reader(file)
}

/// 从任意 Read 计算 SHA256。
pub fn sha256_reader<R: Read>(mut reader: R) -> std::io::Result<String> {
    let mut hasher = Context::new(&SHA256);
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex_lower(hasher.finish().as_ref()))
}

/// 边复制边哈希：`src → dst`，返回写入字节数与 SHA256 hex。
pub fn copy_hashed<R: Read, W: Write>(mut src: R, mut dst: W) -> std::io::Result<(u64, String)> {
    let mut hasher = Context::new(&SHA256);
    let mut buf = vec![0u8; 1024 * 1024];
    let mut written = 0u64;
    loop {
        let n = src.read(&mut buf)?;
        if n == 0 {
            break;
        }
        dst.write_all(&buf[..n])?;
        hasher.update(&buf[..n]);
        written += n as u64;
    }
    dst.flush()?;
    Ok((written, hex_lower(hasher.finish().as_ref())))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn hashes_known_vector() {
        // SHA256("")
        let h = sha256_reader(Cursor::new(b"")).unwrap();
        assert_eq!(
            h,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let h = sha256_reader(Cursor::new(b"abc")).unwrap();
        assert_eq!(
            h,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_hex_known_vector() {
        // SHA256("abc")：与流式实现必须逐字节一致
        let abc = sha256_hex(b"abc");
        assert_eq!(
            abc,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(abc, sha256_reader(Cursor::new(b"abc")).unwrap());
        // 空输入同样对齐
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // 小写 hex，长度固定 64
        assert_eq!(abc.len(), 64);
        assert!(abc
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    }

    #[test]
    fn copy_hashed_matches() {
        let src = b"hello-aidm";
        let mut dst = Vec::new();
        let (n, hex) = copy_hashed(Cursor::new(src), &mut dst).unwrap();
        assert_eq!(n, src.len() as u64);
        assert_eq!(dst, src);
        assert_eq!(hex, sha256_reader(Cursor::new(src)).unwrap());
    }
}

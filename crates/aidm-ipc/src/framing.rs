//! Chrome / Edge native messaging 分帧（开发文档 §6）。
//!
//! 浏览器与宿主之间的 stdio **不是**单行 JSON。正确帧格式为：
//! `4 字节本地字节序 u32 长度` + 等长 UTF-8 JSON。
//! 宿主 → 扩展单条上限 1 MiB（Chrome/Edge 硬限制）。

use std::io::{Read, Write};

/// 宿主发给扩展的单条消息上限（字节）。
pub const NMH_MAX_HOST_TO_EXT: usize = 1024 * 1024;

/// 扩展发给宿主的单条消息上限（Chrome 现为 64 MiB）。
pub const NMH_MAX_EXT_TO_HOST: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NmhError {
    Io(String),
    /// 长度字段超过通道上限。
    TooLong,
    /// 对端关闭。
    Eof,
}

impl std::fmt::Display for NmhError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NmhError::Io(e) => write!(f, "nmh_io:{e}"),
            NmhError::TooLong => write!(f, "too_long"),
            NmhError::Eof => write!(f, "eof"),
        }
    }
}

impl From<std::io::Error> for NmhError {
    fn from(e: std::io::Error) -> Self {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            NmhError::Eof
        } else {
            NmhError::Io(e.to_string())
        }
    }
}

/// 从 `r` 读取一帧（长度前缀 + payload）。
pub fn read_nmh_message<R: Read>(r: &mut R) -> Result<Vec<u8>, NmhError> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(NmhError::Eof),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_ne_bytes(len_buf) as usize;
    if len > NMH_MAX_EXT_TO_HOST {
        return Err(NmhError::TooLong);
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// 向 `w` 写入一帧。超过 1 MiB 拒绝（宿主→扩展硬限制）。
pub fn write_nmh_message<W: Write>(w: &mut W, bytes: &[u8]) -> Result<(), NmhError> {
    if bytes.len() > NMH_MAX_HOST_TO_EXT {
        return Err(NmhError::TooLong);
    }
    let len = u32::try_from(bytes.len()).map_err(|_| NmhError::TooLong)?;
    w.write_all(&len.to_ne_bytes())?;
    w.write_all(bytes)?;
    w.flush()?;
    Ok(())
}

/// 编码一帧到 `Vec`（测试 / 回放）。
pub fn encode_nmh_message(bytes: &[u8]) -> Result<Vec<u8>, NmhError> {
    if bytes.len() > NMH_MAX_HOST_TO_EXT {
        return Err(NmhError::TooLong);
    }
    let mut out = Vec::with_capacity(4 + bytes.len());
    write_nmh_message(&mut out, bytes)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn framing_roundtrip_native_endian() {
        let payload = br#"{"v":1,"op":"ping"}"#;
        let framed = encode_nmh_message(payload).unwrap();
        assert_eq!(&framed[..4], &(payload.len() as u32).to_ne_bytes());
        assert_eq!(&framed[4..], payload);
        let mut cur = Cursor::new(framed);
        let back = read_nmh_message(&mut cur).unwrap();
        assert_eq!(back, payload);
    }

    #[test]
    fn framing_rejects_host_to_ext_over_1mb() {
        let too_big = vec![b'x'; NMH_MAX_HOST_TO_EXT + 1];
        assert_eq!(
            write_nmh_message(&mut Vec::new(), &too_big),
            Err(NmhError::TooLong)
        );
        assert_eq!(encode_nmh_message(&too_big), Err(NmhError::TooLong));
    }

    #[test]
    fn framing_rejects_declared_length_over_ext_cap() {
        let mut framed = Vec::new();
        let len = (NMH_MAX_EXT_TO_HOST as u32).saturating_add(1);
        framed.extend_from_slice(&len.to_ne_bytes());
        framed.extend_from_slice(&[0u8; 8]);
        let err = read_nmh_message(&mut Cursor::new(framed)).unwrap_err();
        assert_eq!(err, NmhError::TooLong);
    }

    #[test]
    fn framing_eof_on_empty() {
        let err = read_nmh_message(&mut Cursor::new(Vec::<u8>::new())).unwrap_err();
        assert_eq!(err, NmhError::Eof);
    }
}

//! `server.met`（eDonkey/eMule 服务器列表文件）解析。
//!
//! 布局依据 `docs/ed2k-server-protocol-spec.md`（eMule `server.h` 的
//! `#pragma pack(1) ServerMet_Struct`、aMule、Wireshark 三方交叉），并用两份
//! **真实文件**逐字节验证到 EOF：
//!
//! | 文件 | 头标记 | 服务器数 | 长度 |
//! |---|---|---|---|
//! | `emule-security-server.met` | `0xE0` | 14 | 2,465 B |
//! | `gruk-server.met` | `0x0E` | 11 | 1,964 B |
//!
//! ## 字节序（这里踩过坑，务必记住）
//!
//! - **IP 与 ClientID：按点分序原样读**（`55 11 74 DE` = `85.17.116.222`），
//!   Wireshark 对这两类字段统一 `ENC_BIG_ENDIAN`，与 gruk HTML 列表双向核对 6/6 命中。
//! - **端口、计数、标签值：小端**。
//! - 反面教材：aMule wiki 里"IP 要反序"的例子是错的。

use std::net::Ipv4Addr;

/// 文件头标记。eMule 写 `0xE0`，aMule 写 `0x0E`（`MET_HEADER`）；`0x0F` 是 64 位标签变体。
pub const MET_HEADER_EMULE: u8 = 0xE0;
pub const MET_HEADER_AMULE: u8 = 0x0E;
pub const MET_HEADER_I64TAGS: u8 = 0x0F;

/// 服务器标签名（`CTag` 的数字 ID）。
pub mod tag_name {
    pub const SERVERNAME: u8 = 0x01;
    pub const DESCRIPTION: u8 = 0x0B;
    pub const PING: u8 = 0x0C;
    pub const FAIL: u8 = 0x0D;
    pub const PREFERENCE: u8 = 0x0E;
    pub const PORT: u8 = 0x0F;
    pub const IP: u8 = 0x10;
    pub const DYNIP: u8 = 0x85;
    pub const MAXUSERS: u8 = 0x87;
    pub const SOFTFILES: u8 = 0x88;
    pub const HARDFILES: u8 = 0x89;
    pub const LASTPING: u8 = 0x90;
    pub const VERSION: u8 = 0x91;
    pub const UDPFLAGS: u8 = 0x92;
    pub const AUXPORTSLIST: u8 = 0x93;
    pub const LOWIDUSERS: u8 = 0x94;
    pub const UDPKEY: u8 = 0x95;
    pub const UDPKEYIP: u8 = 0x96;
    pub const TCPPORTOBFUSCATION: u8 = 0x97;
    pub const UDPPORTOBFUSCATION: u8 = 0x98;
}

/// 一条服务器条目。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerEntry {
    /// 点分序原样读出的 IPv4。
    pub ip: Ipv4Addr,
    /// 小端端口。
    pub port: u16,
    /// `ST_SERVERNAME`
    pub name: Option<String>,
    /// `ST_DESCRIPTION`
    pub description: Option<String>,
    /// `ST_MAXUSERS`
    pub max_users: Option<u32>,
    /// `ST_SOFTFILES`
    pub soft_files: Option<u32>,
    /// `ST_HARDFILES`
    pub hard_files: Option<u32>,
    /// `ST_TCPPORTOBFUSCATION`（真实文件里是 u32）
    pub tcp_obfuscation_port: Option<u32>,
    /// `ST_UDPPORTOBFUSCATION`
    pub udp_obfuscation_port: Option<u32>,
    /// 其余标签按 (名字, 值) 原样保留，便于将来取用而不必改解析器。
    pub extra: Vec<(String, TagValue)>,
}

/// 标签值（只区分实际会遇到的几种）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TagValue {
    Str(String),
    Uint(u64),
    Bool(bool),
    Hash([u8; 16]),
    Bytes(Vec<u8>),
}

impl TagValue {
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            TagValue::Uint(v) => Some(*v),
            TagValue::Bool(b) => Some(u64::from(*b)),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            TagValue::Str(s) => Some(s),
            _ => None,
        }
    }
}

/// 解析错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetError {
    /// 文件为空或短于头部。
    TooShort,
    /// 头标记不认识。
    BadHeader(u8),
    /// 字节不够（附偏移）。
    Truncated(usize),
    /// 标签类型不认识。
    BadTagType(u8),
    /// 解析结束后仍有剩余字节 —— 说明布局理解有误，宁可报错。
    TrailingBytes(usize),
    /// 服务器数超过合理上限。
    TooManyServers(u32),
}

impl MetError {
    pub fn code(&self) -> &'static str {
        match self {
            MetError::TooShort => "met_too_short",
            MetError::BadHeader(_) => "met_bad_header",
            MetError::Truncated(_) => "met_truncated",
            MetError::BadTagType(_) => "met_bad_tag_type",
            MetError::TrailingBytes(_) => "met_trailing_bytes",
            MetError::TooManyServers(_) => "met_too_many_servers",
        }
    }

    pub fn message(&self) -> String {
        match self {
            MetError::TooShort => "server.met 太短".into(),
            MetError::BadHeader(h) => format!("server.met 头标记不认识：0x{h:02X}"),
            MetError::Truncated(off) => format!("server.met 在偏移 {off} 处截断"),
            MetError::BadTagType(t) => format!("server.met 标签类型不认识：0x{t:02X}"),
            MetError::TrailingBytes(n) => format!("server.met 解析后还剩 {n} 字节（布局不符）"),
            MetError::TooManyServers(n) => format!("server.met 服务器数过多：{n}"),
        }
    }
}

/// 合理上限（真实列表几百到几千条）。
const MAX_SERVERS: u32 = 100_000;

struct Cursor<'a> {
    b: &'a [u8],
    o: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], MetError> {
        if self.o + n > self.b.len() {
            return Err(MetError::Truncated(self.o));
        }
        let s = &self.b[self.o..self.o + n];
        self.o += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, MetError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, MetError> {
        let s = self.take(2)?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }
    fn u32(&mut self) -> Result<u32, MetError> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn u64(&mut self) -> Result<u64, MetError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    /// IP 与 ClientID：**点分序原样**（不要反序）。
    fn ipv4(&mut self) -> Result<Ipv4Addr, MetError> {
        let s = self.take(4)?;
        Ok(Ipv4Addr::new(s[0], s[1], s[2], s[3]))
    }
}

/// 默认刷新来源。实测：HTTP 200 / 3125 B；同日 `gruk.org` 亦 200 / 1964 B。
///
/// 注意它和 `nodes.dat` **不是**同一种来源形态：这个文件给的是服务器列表，
/// 刷新后应当**写回** `ed2k.servers` 设置（用户可以再手工编辑），而不是另建缓存表。
pub const DEFAULT_SERVER_MET_URL: &str = "http://upd.emule-security.org/server.met";

/// 单份 `server.met` 的读取上限。真实列表实测 2–3 KB；给足余量但不接受超大响应。
pub const MAX_SERVER_MET_BYTES: u64 = 256 * 1024;

/// 解析后的服务器列表。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerList {
    /// 头标记（`0xE0` / `0x0E` / `0x0F`）。
    pub header: u8,
    pub servers: Vec<ServerEntry>,
}

impl ServerList {
    /// 直接可连的 `ip:port` 列表（按原顺序）。
    pub fn endpoints(&self) -> Vec<(Ipv4Addr, u16)> {
        self.servers.iter().map(|s| (s.ip, s.port)).collect()
    }
}

/// 解析 `server.met`。**要求精确到 EOF**：有剩余字节就报错，避免"半对"的解析结果。
pub fn parse(bytes: &[u8]) -> Result<ServerList, MetError> {
    if bytes.len() < 5 {
        return Err(MetError::TooShort);
    }
    let header = bytes[0];
    if !matches!(
        header,
        MET_HEADER_EMULE | MET_HEADER_AMULE | MET_HEADER_I64TAGS
    ) {
        return Err(MetError::BadHeader(header));
    }
    let mut c = Cursor { b: bytes, o: 1 };
    let count = c.u32()?;
    if count > MAX_SERVERS {
        return Err(MetError::TooManyServers(count));
    }
    let mut servers = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let ip = c.ipv4()?;
        let port = c.u16()?;
        let tag_count = c.u32()?;
        let mut entry = ServerEntry {
            ip,
            port,
            name: None,
            description: None,
            max_users: None,
            soft_files: None,
            hard_files: None,
            tcp_obfuscation_port: None,
            udp_obfuscation_port: None,
            extra: Vec::new(),
        };
        for _ in 0..tag_count {
            let (name, value) = read_tag(&mut c)?;
            let id = name.parse::<u8>().ok();
            match (id, &value) {
                (Some(tag_name::SERVERNAME), TagValue::Str(s)) => entry.name = Some(s.clone()),
                (Some(tag_name::DESCRIPTION), TagValue::Str(s)) => {
                    entry.description = Some(s.clone())
                }
                (Some(tag_name::MAXUSERS), v) => entry.max_users = v.as_u64().map(|x| x as u32),
                (Some(tag_name::SOFTFILES), v) => entry.soft_files = v.as_u64().map(|x| x as u32),
                (Some(tag_name::HARDFILES), v) => entry.hard_files = v.as_u64().map(|x| x as u32),
                (Some(tag_name::TCPPORTOBFUSCATION), v) => {
                    entry.tcp_obfuscation_port = v.as_u64().map(|x| x as u32)
                }
                (Some(tag_name::UDPPORTOBFUSCATION), v) => {
                    entry.udp_obfuscation_port = v.as_u64().map(|x| x as u32)
                }
                _ => entry.extra.push((name, value)),
            }
        }
        servers.push(entry);
    }
    if c.o != bytes.len() {
        return Err(MetError::TrailingBytes(bytes.len() - c.o));
    }
    Ok(ServerList { header, servers })
}

/// 读一个标签：`type(1)`（bit7 = 短名）→ 名字 → 值。
fn read_tag(c: &mut Cursor<'_>) -> Result<(String, TagValue), MetError> {
    let type_byte = c.u8()?;
    let short_name = type_byte & 0x80 != 0;
    let ty = type_byte & 0x7F;
    let name = if short_name {
        // 短名：1 字节名称 ID，统一按十进制字符串保存（与长名比较方便）
        format!("{}", c.u8()?)
    } else {
        let len = c.u16()? as usize;
        let raw = c.take(len)?;
        match len {
            1 => format!("{}", raw[0]),
            _ => String::from_utf8_lossy(raw).into_owned(),
        }
    };
    let value = match ty {
        0x01 => TagValue::Hash(c.take(16)?.try_into().unwrap()),
        0x02 => {
            let len = c.u16()? as usize;
            let raw = c.take(len)?;
            // 容忍 BOM
            let s = String::from_utf8_lossy(raw)
                .trim_start_matches('\u{feff}')
                .to_string();
            TagValue::Str(s)
        }
        0x03 => TagValue::Uint(c.u32()? as u64),
        0x04 => TagValue::Bytes(c.take(4)?.to_vec()),
        0x05 => TagValue::Bool(c.u8()? != 0),
        0x06 => {
            let bits = c.u16()? as usize;
            let bytes = bits / 8 + 1;
            TagValue::Bytes(c.take(bytes)?.to_vec())
        }
        0x07 => {
            let len = c.u32()? as usize;
            TagValue::Bytes(c.take(len)?.to_vec())
        }
        0x08 => TagValue::Uint(c.u16()? as u64),
        0x09 => TagValue::Uint(c.u8()? as u64),
        0x0A => {
            // BSOB：一个 u8 长度前缀
            let len = c.u8()? as usize;
            TagValue::Bytes(c.take(len)?.to_vec())
        }
        0x0B => TagValue::Uint(c.u64()?),
        0x11..=0x26 => {
            let len = (ty - 0x10) as usize;
            let raw = c.take(len)?;
            TagValue::Str(String::from_utf8_lossy(raw).into_owned())
        }
        other => return Err(MetError::BadTagType(other)),
    };
    Ok((name, value))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Vec<u8> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/ed2k")
            .join(name);
        std::fs::read(&p).unwrap_or_else(|e| panic!("读取夹具失败 {}: {e}", p.display()))
    }

    /// 真实文件必须解析到**精确 EOF**，且条目数/首条目与规范一致。
    #[test]
    fn parses_real_fixtures_to_exact_eof() {
        let emule = fixture("emule-security-server.met");
        let gruk = fixture("gruk-server.met");
        assert_eq!(emule.len(), 2465);
        assert_eq!(gruk.len(), 1964);

        let a = parse(&emule).expect("emule-security 应能解析");
        assert_eq!(a.header, MET_HEADER_EMULE);
        assert_eq!(a.servers.len(), 14, "规范实测 14 台");

        let b = parse(&gruk).expect("gruk 应能解析");
        assert_eq!(b.header, MET_HEADER_AMULE, "gruk 用 0x0E 头");
        assert_eq!(b.servers.len(), 11, "规范实测 11 台");

        // 首条目：55 11 74 DE C2 17 = 85.17.116.222:6082，名字 ed2k-rust
        let first = &b.servers[0];
        assert_eq!(
            first.ip,
            Ipv4Addr::new(0x55, 0x11, 0x74, 0xDE),
            "IP 必须按点分序原样读（反序会得到 222.116.17.85）"
        );
        assert_eq!(first.ip.to_string(), "85.17.116.222");
        assert_eq!(first.port, 0xC217u16.swap_bytes(), "端口小端：C2 17 → 6082");
        assert_eq!(first.port, 6082);
        assert_eq!(first.name.as_deref(), Some("ed2k-rust"));

        // 该条目的混淆端口字段与端口字段自洽（规范用它做了独立验证）
        assert_eq!(
            first.tcp_obfuscation_port,
            Some(6082),
            "ST_TCPPORTOBFUSCATION 应与端口一致（也证明它是 u32 LE）"
        );

        // 每个条目都应有名字、端口、IP 合理
        for (i, s) in a.servers.iter().enumerate() {
            assert!(s.port > 0, "第 {i} 条端口应为正");
            assert!(!s.ip.is_unspecified(), "第 {i} 条 IP 不应为 0.0.0.0");
        }
        assert!(a.servers.iter().filter(|s| s.name.is_some()).count() >= 13);
        assert!(
            a.servers.iter().any(|s| s.description.is_some()),
            "应有描述字段"
        );
        // endpoints 顺序与条目一致
        let eps = b.endpoints();
        assert_eq!(eps.len(), 11);
        assert_eq!(eps[0], (Ipv4Addr::new(0x55, 0x11, 0x74, 0xDE), 6082));
    }

    /// 坏输入必须明确失败，而不是给出"半对"的结果。
    #[test]
    fn rejects_bad_input() {
        assert_eq!(parse(&[]).unwrap_err(), MetError::TooShort);
        assert_eq!(parse(&[0xE0, 0, 0, 0]).unwrap_err(), MetError::TooShort);
        assert_eq!(
            parse(&[0x42, 0, 0, 0, 0]).unwrap_err(),
            MetError::BadHeader(0x42)
        );
        assert_eq!(
            parse(&[0xE0, 1, 0, 0, 0]).unwrap_err(),
            MetError::Truncated(5),
            "声明 1 台却没有内容"
        );

        // 多一个字节 → 精确 EOF 检查必须报错
        let mut good = fixture("gruk-server.met");
        good.push(0);
        assert_eq!(parse(&good).unwrap_err(), MetError::TrailingBytes(1));

        // 服务器数超上限
        let mut huge = vec![0xE0];
        huge.extend_from_slice(&(MAX_SERVERS + 1).to_le_bytes());
        assert_eq!(
            parse(&huge).unwrap_err(),
            MetError::TooManyServers(MAX_SERVERS + 1)
        );

        // 未知标签类型
        let mut bad_tag = vec![0xE0];
        bad_tag.extend_from_slice(&1u32.to_le_bytes()); // 1 台
        bad_tag.extend_from_slice(&[1, 2, 3, 4]); // ip
        bad_tag.extend_from_slice(&4661u16.to_le_bytes()); // port
        bad_tag.extend_from_slice(&1u32.to_le_bytes()); // 1 个标签
        bad_tag.push(0x80 | 0x7F); // 短名位 + 未知类型，紧跟 1 字节名称
        bad_tag.push(0x01);
        assert_eq!(parse(&bad_tag).unwrap_err(), MetError::BadTagType(0x7F));

        // 没有短名位则先按 u16 名字长度读，字节不够时应报截断而不是猜类型
        let mut short_tag = bad_tag[..bad_tag.len() - 2].to_vec();
        short_tag.push(0x7F);
        assert!(matches!(
            parse(&short_tag).unwrap_err(),
            MetError::Truncated(_)
        ));

        // 每种错误都有机器码与中文说明
        for e in [
            MetError::TooShort,
            MetError::BadHeader(1),
            MetError::Truncated(0),
            MetError::BadTagType(1),
            MetError::TrailingBytes(1),
            MetError::TooManyServers(1),
        ] {
            assert!(e.code().starts_with("met_"));
            assert!(!e.message().is_empty());
        }
    }

    /// 自己造一份最小文件并解析（覆盖短名标签与各类型）。
    #[test]
    fn parses_synthetic_minimal_file() {
        let mut b = vec![MET_HEADER_EMULE];
        b.extend_from_slice(&1u32.to_le_bytes()); // 1 台
        b.extend_from_slice(&[85, 17, 116, 222]); // ip 点分序
        b.extend_from_slice(&6082u16.to_le_bytes()); // port 小端
        b.extend_from_slice(&3u32.to_le_bytes()); // 3 个标签
                                                  // 短名 SERVERNAME + 字符串
        b.push(0x80 | 0x02);
        b.push(tag_name::SERVERNAME);
        b.extend_from_slice(&4u16.to_le_bytes());
        b.extend_from_slice(b"test");
        // 短名 MAXUSERS + u32
        b.push(0x80 | 0x03);
        b.push(tag_name::MAXUSERS);
        b.extend_from_slice(&1234u32.to_le_bytes());
        // 长名标签（字符串名）
        b.push(0x03); // u32
        b.extend_from_slice(&5u16.to_le_bytes());
        b.extend_from_slice(b"users");
        b.extend_from_slice(&7u32.to_le_bytes());

        let list = parse(&b).unwrap();
        assert_eq!(list.servers.len(), 1);
        let s = &list.servers[0];
        assert_eq!(s.ip, Ipv4Addr::new(85, 17, 116, 222));
        assert_eq!(s.port, 6082);
        assert_eq!(s.name.as_deref(), Some("test"));
        assert_eq!(s.max_users, Some(1234));
        assert_eq!(s.extra, vec![("users".to_string(), TagValue::Uint(7))]);
    }
}

//! eMule 对等（peer）协议的**线路编解码层**（L4 地基）。
//!
//! 只做"字节 ↔ 结构体"，不做网络与状态机；上层（连接、队列、下载会话）在其上实现。
//! 字节布局全部来自 `docs/emule-peer-protocol-spec.md`（逐条带 eMule 源码行号／Wireshark 出处）。
//!
//! ## 已覆盖
//!
//! | 项 | 说明 |
//! |---|---|
//! | 报文框架 | 6 字节头：`protocol(1) + packetlength(4, = 载荷+1) + opcode(1)` |
//! | opcode 常量 | eD2k（`0xE3`）与 eMule 扩展（`0xC5`）两套 |
//! | 标签（新式） | 类型字节高位置 `0x80` = 1 字节短名；发送侧自动降位宽 |
//! | `OP_HELLO` / `OP_HELLOANSWER` | **HELLO 多一个 `0x10` 长度字节，HELLOANSWER 没有** |
//! | 能力位域 | `MISCOPTIONS1` / `MISCOPTIONS2`，含 `Requests &= Supports` 强制约束 |
//! | `OP_FILESTATUS` | 分片位图（`n==0` = 完整源） |
//! | `OP_REQUESTPARTS` / `_I64` | 固定 40 / 64 字节，**End 是排他上界** |
//! | `OP_SENDINGPART` / `_I64` | 同上 |
//! | `OP_QUEUERANKING` / `OP_QUEUERANK` | **固定 12 字节** / 4 字节 |
//! | `OP_REQUESTSOURCES2` / `OP_ANSWERSOURCES2` | 源交换 v2（v1..v4 条目布局， fail closed） |
//!
//! ## 刻意未覆盖
//!
//! 分片级压缩 `OP_COMPRESSEDPART`（要 raw-inflate 会话状态）、AICH 树、加密/混淆、
//! MultiPacket——它们各自需要独立实现，不在本层职责内。

use std::fmt;

/// eD2k 分片大小：9500 KiB。
pub const PARTSIZE: u64 = 9_728_000;
/// AICH 块大小：180 KiB。
pub const EMBLOCKSIZE: u64 = 184_320;

/// 协议标识字节。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Protocol {
    /// 经典 eDonkey 报文（对等协议主体）
    Edonkey = 0xE3,
    /// eMule 扩展报文
    Emule = 0xC5,
    /// 整包 zlib 压缩（解压后恢复原协议）
    Packed = 0xD4,
}

impl Protocol {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0xE3 => Some(Protocol::Edonkey),
            0xC5 => Some(Protocol::Emule),
            0xD4 => Some(Protocol::Packed),
            _ => None,
        }
    }
}

/// eD2k（`0xE3`）opcode。
pub mod ed2k {
    pub const HELLO: u8 = 0x01;
    pub const SENDINGPART: u8 = 0x46;
    pub const REQUESTPARTS: u8 = 0x47;
    pub const FILEREQANSNOFIL: u8 = 0x48;
    pub const END_OF_DOWNLOAD: u8 = 0x49;
    pub const HELLOANSWER: u8 = 0x4C;
    pub const SETREQFILEID: u8 = 0x4F;
    pub const FILESTATUS: u8 = 0x50;
    pub const HASHSETREQUEST: u8 = 0x51;
    pub const HASHSETANSWER: u8 = 0x52;
    pub const STARTUPLOADREQ: u8 = 0x54;
    pub const ACCEPTUPLOADREQ: u8 = 0x55;
    pub const CANCELTRANSFER: u8 = 0x56;
    pub const OUTOFPARTREQS: u8 = 0x57;
    pub const REQUESTFILENAME: u8 = 0x58;
    pub const REQFILENAMEANSWER: u8 = 0x59;
    pub const QUEUERANK: u8 = 0x5C;
}

/// eMule 扩展（`0xC5`）opcode。
pub mod emule {
    pub const EMULEINFO: u8 = 0x01;
    pub const EMULEINFOANSWER: u8 = 0x02;
    pub const COMPRESSEDPART: u8 = 0x40;
    pub const QUEUERANKING: u8 = 0x60;
    pub const FILEDESC: u8 = 0x61;
    pub const REQUESTSOURCES2: u8 = 0x83;
    pub const ANSWERSOURCES2: u8 = 0x84;
    pub const PUBLICKEY: u8 = 0x85;
    pub const SIGNATURE: u8 = 0x86;
    pub const SECIDENTSTATE: u8 = 0x87;
    pub const AICHREQUEST: u8 = 0x9B;
    pub const AICHANSWER: u8 = 0x9C;
    pub const COMPRESSEDPART_I64: u8 = 0xA1;
    pub const SENDINGPART_I64: u8 = 0xA2;
    pub const REQUESTPARTS_I64: u8 = 0xA3;
    pub const MULTIPACKET_EXT2: u8 = 0xA9;
    pub const MULTIPACKETANSWER_EXT2: u8 = 0xB0;
    pub const HASHSETREQUEST2: u8 = 0xB1;
    pub const HASHSETANSWER2: u8 = 0xB2;
}

/// eMule 协议版本（`OP_EMULEINFO` 第 2 字节）。
pub const EMULE_PROTOCOL: u8 = 0x01;
/// `CT_VERSION` 标签取值（eD2k 客户端版本 60）。
pub const EDONKEYVERSION: u32 = 0x3C;
/// 我们声明的 Kad 版本。
pub const KADEMLIA_VERSION: u32 = 9;
/// 我们声明的兼容客户端 ID（0 = eMule）。
pub const COMPAT_CLIENT_EMULE: u32 = 0;
/// 解析/发送时单包载荷上限（超出视为异常，防内存放大）。
pub const MAX_PAYLOAD: usize = 2 * 1024 * 1024;

/// 编解码错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerError {
    /// 字节数不够。
    Truncated {
        /// 需要的字节数
        need: usize,
        /// 实际剩余
        have: usize,
    },
    /// 协议标识不认识。
    BadProtocol(u8),
    /// 报文长度字段与实际不符。
    BadLength {
        /// 头里声明的载荷长度
        declared: usize,
        /// 实际载荷长度
        actual: usize,
    },
    /// 载荷超过上限。
    TooLarge(usize),
    /// 某个字段取值非法（附字段名）。
    BadField(&'static str),
    /// 标签类型不支持。
    BadTagType(u8),
    /// 标签名不是合法 UTF-8。
    BadTagName,
}

impl fmt::Display for PeerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeerError::Truncated { need, have } => {
                write!(f, "报文截断：需要 {need} 字节，只剩 {have}")
            }
            PeerError::BadProtocol(b) => write!(f, "未知协议标识 0x{b:02X}"),
            PeerError::BadLength { declared, actual } => {
                write!(f, "长度字段 {declared} 与实际 {actual} 不符")
            }
            PeerError::TooLarge(n) => write!(f, "载荷过大：{n}"),
            PeerError::BadField(name) => write!(f, "字段非法：{name}"),
            PeerError::BadTagType(t) => write!(f, "不支持的标签类型 0x{t:02X}"),
            PeerError::BadTagName => write!(f, "标签名不是合法 UTF-8"),
        }
    }
}

impl std::error::Error for PeerError {}

type R<T> = Result<T, PeerError>;

// ---------- 读写助手 ----------

struct Reader<'a> {
    b: &'a [u8],
    o: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, o: 0 }
    }

    fn remaining(&self) -> usize {
        self.b.len().saturating_sub(self.o)
    }

    fn take(&mut self, n: usize) -> R<&'a [u8]> {
        if self.remaining() < n {
            return Err(PeerError::Truncated {
                need: n,
                have: self.remaining(),
            });
        }
        let s = &self.b[self.o..self.o + n];
        self.o += n;
        Ok(s)
    }

    fn u8(&mut self) -> R<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> R<u16> {
        let s = self.take(2)?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }

    fn u32(&mut self) -> R<u32> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn u64(&mut self) -> R<u64> {
        let s = self.take(8)?;
        Ok(u64::from_le_bytes(s.try_into().unwrap()))
    }

    fn hash16(&mut self) -> R<[u8; 16]> {
        Ok(self.take(16)?.try_into().unwrap())
    }

    /// u16 长度前缀 + 字节。
    fn short_bytes(&mut self) -> R<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
}

#[derive(Default)]
struct Writer {
    b: Vec<u8>,
}

impl Writer {
    fn new() -> Self {
        Self { b: Vec::new() }
    }

    fn u8(&mut self, v: u8) {
        self.b.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.b.extend_from_slice(&v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.b.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.b.extend_from_slice(&v.to_le_bytes());
    }
    fn bytes(&mut self, v: &[u8]) {
        self.b.extend_from_slice(v);
    }
    fn short_bytes(&mut self, v: &[u8]) {
        self.u16(v.len() as u16);
        self.bytes(v);
    }
}

// ---------- 报文框架 ----------

/// 一条对等协议报文。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub protocol: Protocol,
    pub opcode: u8,
    pub payload: Vec<u8>,
}

impl Packet {
    pub fn new(protocol: Protocol, opcode: u8, payload: Vec<u8>) -> Self {
        Self {
            protocol,
            opcode,
            payload,
        }
    }

    /// 编码为线上字节。`packetlength = 载荷长度 + 1`（含 opcode 字节）。
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.payload.len() + 6);
        out.push(self.protocol as u8);
        out.extend_from_slice(&((self.payload.len() as u32 + 1).to_le_bytes()));
        out.push(self.opcode);
        out.extend_from_slice(&self.payload);
        out
    }

    /// 解析一条完整报文（必须刚好一条，长度不符即报错）。
    pub fn decode(b: &[u8]) -> R<Packet> {
        if b.len() < 6 {
            return Err(PeerError::Truncated {
                need: 6,
                have: b.len(),
            });
        }
        let protocol = Protocol::from_byte(b[0]).ok_or(PeerError::BadProtocol(b[0]))?;
        let declared = u32::from_le_bytes([b[1], b[2], b[3], b[4]]) as usize;
        let opcode = b[5];
        // packetlength 含 opcode 本身，最小为 1
        if declared == 0 {
            return Err(PeerError::BadLength {
                declared,
                actual: 0,
            });
        }
        let payload_len = declared - 1;
        if payload_len > MAX_PAYLOAD {
            return Err(PeerError::TooLarge(payload_len));
        }
        let actual = b.len() - 6;
        if actual != payload_len {
            return Err(PeerError::BadLength {
                declared: payload_len,
                actual,
            });
        }
        Ok(Packet {
            protocol,
            opcode,
            payload: b[6..].to_vec(),
        })
    }

    /// 读头部（流式接收时先读 6 字节判断要再收多少）。
    pub fn header(b: &[u8; 6]) -> R<(Protocol, usize, u8)> {
        let protocol = Protocol::from_byte(b[0]).ok_or(PeerError::BadProtocol(b[0]))?;
        let declared = u32::from_le_bytes([b[1], b[2], b[3], b[4]]) as usize;
        if declared == 0 {
            return Err(PeerError::BadLength {
                declared,
                actual: 0,
            });
        }
        let payload_len = declared - 1;
        if payload_len > MAX_PAYLOAD {
            return Err(PeerError::TooLarge(payload_len));
        }
        Ok((protocol, payload_len, b[5]))
    }
}

// ---------- 标签 ----------

/// 标签类型（只实现对等协议实际用到的）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagType {
    Hash,
    String,
    Uint32,
    Float32,
    Bool,
    Blob,
    Uint16,
    Uint8,
    Uint64,
}

impl TagType {
    fn code(self) -> u8 {
        match self {
            TagType::Hash => 0x01,
            TagType::String => 0x02,
            TagType::Uint32 => 0x03,
            TagType::Float32 => 0x04,
            TagType::Bool => 0x05,
            TagType::Blob => 0x07,
            TagType::Uint16 => 0x08,
            TagType::Uint8 => 0x09,
            TagType::Uint64 => 0x0B,
        }
    }
}

/// 标签名：短名（1 字节 ID）或字符串名。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TagName {
    /// 1 字节名称 ID（类型字节高位置 1）
    Short(u8),
    /// u16 长度 + 名称
    Long(String),
}

/// 标签值。
#[derive(Debug, Clone, PartialEq)]
pub enum TagValue {
    Hash([u8; 16]),
    Str(String),
    Uint(u64),
    Float(f32),
    Bool(bool),
    Blob(Vec<u8>),
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

/// 一个标签。
#[derive(Debug, Clone, PartialEq)]
pub struct Tag {
    pub name: TagName,
    pub value: TagValue,
}

impl Tag {
    /// 用 1 字节短名构造。
    pub fn short(id: u8, value: TagValue) -> Self {
        Self {
            name: TagName::Short(id),
            value,
        }
    }

    /// 用字符串名构造。
    pub fn named(name: impl Into<String>, value: TagValue) -> Self {
        Self {
            name: TagName::Long(name.into()),
            value,
        }
    }

    pub fn name_id(&self) -> Option<u8> {
        match &self.name {
            TagName::Short(id) => Some(*id),
            TagName::Long(_) => None,
        }
    }

    /// 按规范自动降位宽：≤0xFF 用 UINT8、≤0xFFFF 用 UINT16、否则 UINT32；
    /// 字符串长度 1..=16 用定长 `STRn`，否则 `STRING`。
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        // 决定实际类型
        let (type_byte, fixed_str_len) = match &self.value {
            TagValue::Uint(v) => {
                if *v <= 0xFF {
                    (TagType::Uint8.code(), None)
                } else if *v <= 0xFFFF {
                    (TagType::Uint16.code(), None)
                } else {
                    (TagType::Uint32.code(), None)
                }
            }
            TagValue::Str(s) => {
                let n = s.as_bytes().len();
                if (1..=16).contains(&n) {
                    // STR1 = 0x11 … STR16 = 0x20
                    (0x10 + n as u8, Some(n))
                } else {
                    (TagType::String.code(), None)
                }
            }
            TagValue::Hash(_) => (TagType::Hash.code(), None),
            TagValue::Float(_) => (TagType::Float32.code(), None),
            TagValue::Bool(_) => (TagType::Bool.code(), None),
            TagValue::Blob(_) => (TagType::Blob.code(), None),
        };
        let with_short_name = matches!(self.name, TagName::Short(_));
        w.u8(if with_short_name {
            type_byte | 0x80
        } else {
            type_byte
        });
        match &self.name {
            TagName::Short(id) => w.u8(*id),
            TagName::Long(n) => w.short_bytes(n.as_bytes()),
        }
        match &self.value {
            TagValue::Uint(v) => match type_byte {
                t if t == TagType::Uint8.code() => w.u8(*v as u8),
                t if t == TagType::Uint16.code() => w.u16(*v as u16),
                _ => w.u32(*v as u32),
            },
            TagValue::Str(s) => {
                if let Some(n) = fixed_str_len {
                    // 定长串：按字节写入（不足不补，长度由类型表达）
                    let b = s.as_bytes();
                    w.bytes(&b[..n.min(b.len())]);
                } else {
                    w.short_bytes(s.as_bytes());
                }
            }
            TagValue::Hash(h) => w.bytes(h),
            TagValue::Float(f) => w.bytes(&f.to_le_bytes()),
            TagValue::Bool(b) => w.u8(u8::from(*b)),
            TagValue::Blob(b) => {
                w.u32(b.len() as u32);
                w.bytes(b);
            }
        }
        w.b
    }

    /// 解析一个标签（新式格式；旧式格式恰好被其覆盖，因为旧式只是"无 0x80 短名"）。
    // 只被本文件的 HELLO 标签解析（`decode_hello`）与同文件单测调用，所以保持私有：
    // `Reader` 是本模块的内部缓冲区类型，不该为它放宽可见性。
    fn decode(r: &mut Reader<'_>) -> R<Tag> {
        let type_byte = r.u8()?;
        let short_name = type_byte & 0x80 != 0;
        let ty = type_byte & 0x7F;
        let name = if short_name {
            TagName::Short(r.u8()?)
        } else {
            let raw = r.short_bytes()?;
            // 经典 eMule HELLO 仍使用旧式头：u16(1) 后面是原始数字 ID，
            // 包括 FA/FB/FE，绝不是一个 UTF-8 字符串。
            if raw.len() == 1 {
                TagName::Short(raw[0])
            } else {
                TagName::Long(String::from_utf8(raw.to_vec()).map_err(|_| PeerError::BadTagName)?)
            }
        };
        let value = match ty {
            0x01 => TagValue::Hash(r.hash16()?),
            0x02 => {
                let raw = r.short_bytes()?;
                TagValue::Str(String::from_utf8_lossy(raw).into_owned())
            }
            0x03 => TagValue::Uint(r.u32()? as u64),
            0x04 => {
                let s = r.take(4)?;
                TagValue::Float(f32::from_le_bytes(s.try_into().unwrap()))
            }
            0x05 => TagValue::Bool(r.u8()? != 0),
            0x07 => {
                let n = r.u32()? as usize;
                TagValue::Blob(r.take(n)?.to_vec())
            }
            0x08 => TagValue::Uint(r.u16()? as u64),
            0x09 => TagValue::Uint(r.u8()? as u64),
            0x0B => TagValue::Uint(r.u64()?),
            0x11..=0x26 => {
                // 定长串：长度内嵌在类型里（STR1..STR22）
                let n = (ty - 0x10) as usize;
                TagValue::Str(String::from_utf8_lossy(r.take(n)?).into_owned())
            }
            other => return Err(PeerError::BadTagType(other)),
        };
        Ok(Tag { name, value })
    }
}

// ---------- 能力位域 ----------

/// `CT_EMULE_MISCOPTIONS1`(0xFA)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MiscOptions1 {
    pub aich_version: u8,
    pub unicode: bool,
    pub udp_version: u8,
    pub data_compression: u8,
    pub sec_ident: u8,
    pub source_exchange: u8,
    pub ext_requests: u8,
    pub comments: u8,
    pub peer_cache: bool,
    pub no_view_shared: bool,
    pub multi_packet: bool,
    pub preview: bool,
}

impl MiscOptions1 {
    pub fn to_u32(self) -> u32 {
        ((self.aich_version as u32 & 0x7) << 29)
            | ((self.unicode as u32) << 28)
            | ((self.udp_version as u32 & 0xF) << 24)
            | ((self.data_compression as u32 & 0xF) << 20)
            | ((self.sec_ident as u32 & 0xF) << 16)
            | ((self.source_exchange as u32 & 0xF) << 12)
            | ((self.ext_requests as u32 & 0xF) << 8)
            | ((self.comments as u32 & 0xF) << 4)
            | ((self.peer_cache as u32) << 3)
            | ((self.no_view_shared as u32) << 2)
            | ((self.multi_packet as u32) << 1)
            | (self.preview as u32)
    }

    pub fn from_u32(v: u32) -> Self {
        Self {
            aich_version: ((v >> 29) & 0x7) as u8,
            unicode: (v >> 28) & 1 != 0,
            udp_version: ((v >> 24) & 0xF) as u8,
            data_compression: ((v >> 20) & 0xF) as u8,
            sec_ident: ((v >> 16) & 0xF) as u8,
            source_exchange: ((v >> 12) & 0xF) as u8,
            ext_requests: ((v >> 8) & 0xF) as u8,
            comments: ((v >> 4) & 0xF) as u8,
            peer_cache: (v >> 3) & 1 != 0,
            no_view_shared: (v >> 2) & 1 != 0,
            multi_packet: (v >> 1) & 1 != 0,
            preview: v & 1 != 0,
        }
    }
}

/// `CT_EMULE_MISCOPTIONS2`(0xFE)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MiscOptions2 {
    pub file_ident: bool,
    pub direct_udp_callback: bool,
    pub captcha: bool,
    pub source_exchange2: bool,
    pub requires_crypt: bool,
    pub requests_crypt: bool,
    pub supports_crypt: bool,
    pub ext_multipacket: bool,
    pub large_files: bool,
    pub kad_version: u8,
}

impl MiscOptions2 {
    pub fn to_u32(self) -> u32 {
        ((self.file_ident as u32) << 13)
            | ((self.direct_udp_callback as u32) << 12)
            | ((self.captcha as u32) << 11)
            | ((self.source_exchange2 as u32) << 10)
            | ((self.requires_crypt as u32) << 9)
            | ((self.requests_crypt as u32) << 8)
            | ((self.supports_crypt as u32) << 7)
            | ((self.ext_multipacket as u32) << 5)
            | ((self.large_files as u32) << 4)
            | (self.kad_version as u32 & 0xF)
    }

    /// 解析并施加规范里的强制约束：
    /// `Requests &= Supports`、`Requires &= Requests`。
    pub fn from_u32(v: u32) -> Self {
        let supports = (v >> 7) & 1 != 0;
        let requests = ((v >> 8) & 1 != 0) && supports;
        let requires = ((v >> 9) & 1 != 0) && requests;
        Self {
            file_ident: (v >> 13) & 1 != 0,
            direct_udp_callback: (v >> 12) & 1 != 0,
            captcha: (v >> 11) & 1 != 0,
            source_exchange2: (v >> 10) & 1 != 0,
            requires_crypt: requires,
            requests_crypt: requests,
            supports_crypt: supports,
            ext_multipacket: (v >> 5) & 1 != 0,
            large_files: (v >> 4) & 1 != 0,
            kad_version: (v & 0xF) as u8,
        }
    }
}

// ---------- 握手 ----------

/// HELLO / HELLOANSWER 的公共内容。
#[derive(Debug, Clone, PartialEq)]
pub struct HelloInfo {
    /// 客户端哈希（UserHash）。
    pub user_hash: [u8; 16],
    /// 客户端 ID（HighID 时为 IP 的网络序数值）。
    pub client_id: u32,
    pub tcp_port: u16,
    pub tags: Vec<Tag>,
    pub server_ip: u32,
    pub server_port: u16,
}

/// eMule 客户端哈希特征：`byte[5]==14 && byte[14]==111`。
pub fn is_emule_hash(h: &[u8; 16]) -> bool {
    h[5] == 14 && h[14] == 111
}

/// 生成符合 eMule 特征的客户端哈希（其余字节随机）。
///
/// `seed` 用于可复现测试；生产路径传 16 字节随机数。
pub fn make_emule_hash(mut seed: [u8; 16]) -> [u8; 16] {
    seed[5] = 14;
    seed[14] = 111;
    seed
}

/// `CT_EMULE_VERSION` 打包：`compat<<24 | major<<17 | minor<<10 | upd<<7 | build`。
pub fn pack_emule_version(compat: u32, major: u32, minor: u32, update: u32, build: u32) -> u32 {
    ((compat & 0xFF) << 24)
        | ((major & 0x7F) << 17)
        | ((minor & 0x7F) << 10)
        | ((update & 0x7) << 7)
        | (build & 0x7F)
}

/// 解出 `(compat, major, minor, update, build)`。
pub fn unpack_emule_version(v: u32) -> (u32, u32, u32, u32, u32) {
    (
        (v >> 24) & 0xFF,
        (v >> 17) & 0x7F,
        (v >> 10) & 0x7F,
        (v >> 7) & 0x7,
        v & 0x7F,
    )
}

impl HelloInfo {
    /// 编码。`is_answer = false`（HELLO）时**多一个 `0x10` 长度字节**。
    pub fn encode(&self, is_answer: bool) -> Vec<u8> {
        let mut w = Writer::new();
        if !is_answer {
            w.u8(16); // UserHash 长度，仅 HELLO 有
        }
        w.bytes(&self.user_hash);
        w.u32(self.client_id);
        w.u16(self.tcp_port);
        w.u32(self.tags.len() as u32);
        for t in &self.tags {
            w.bytes(&t.encode());
        }
        w.u32(self.server_ip);
        w.u16(self.server_port);
        w.b
    }

    /// 解码。必须按 opcode 区分：`OP_HELLO`(0x01) 有长度字节，`OP_HELLOANSWER`(0x4C) 没有。
    pub fn decode(opcode: u8, b: &[u8]) -> R<HelloInfo> {
        let mut r = Reader::new(b);
        match opcode {
            ed2k::HELLO => {
                let n = r.u8()?;
                if n != 16 {
                    return Err(PeerError::BadField("hello.user_hash_len"));
                }
            }
            ed2k::HELLOANSWER => {}
            _ => return Err(PeerError::BadField("hello.opcode")),
        }
        let user_hash = r.hash16()?;
        let client_id = r.u32()?;
        let tcp_port = r.u16()?;
        let count = r.u32()?;
        if count > 512 {
            return Err(PeerError::BadField("hello.tag_count"));
        }
        let mut tags = Vec::with_capacity(count as usize);
        for _ in 0..count {
            tags.push(Tag::decode(&mut r)?);
        }
        let server_ip = r.u32()?;
        let server_port = r.u16()?;
        Ok(HelloInfo {
            user_hash,
            client_id,
            tcp_port,
            tags,
            server_ip,
            server_port,
        })
    }

    /// 按标签 ID 取值（只认短名标签）。
    pub fn tag(&self, id: u8) -> Option<&TagValue> {
        self.tags
            .iter()
            .find(|t| t.name_id() == Some(id))
            .map(|t| &t.value)
    }
}

// ---------- 分片位图 ----------

/// `OP_FILESTATUS` 的分片位图。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileStatus {
    pub file_hash: [u8; 16],
    /// `true` 表示对端是完整源（`PartCount == 0`，无位图）。
    pub complete_source: bool,
    /// 每个分片是否可用（长度 = 分片数）。
    pub parts: Vec<bool>,
}

/// 分片数：`ceil(size / PARTSIZE)`。
pub fn part_count(file_size: u64) -> usize {
    if file_size == 0 {
        0
    } else {
        file_size.div_ceil(PARTSIZE) as usize
    }
}

impl FileStatus {
    /// 全部可用（完整源）。
    pub fn complete(file_hash: [u8; 16], file_size: u64) -> Self {
        Self {
            file_hash,
            complete_source: true,
            parts: vec![true; part_count(file_size)],
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&self.file_hash);
        if self.complete_source {
            w.u16(0);
            return w.b;
        }
        let n = self.parts.len();
        w.u16(n as u16);
        let bytes = n.div_ceil(8);
        let mut bm = vec![0u8; bytes];
        for (i, ok) in self.parts.iter().enumerate() {
            if *ok {
                bm[i / 8] |= 1 << (i % 8);
            }
        }
        w.bytes(&bm);
        w.b
    }

    pub fn decode(b: &[u8]) -> R<FileStatus> {
        let mut r = Reader::new(b);
        let file_hash = r.hash16()?;
        let n = r.u16()? as usize;
        if n == 0 {
            return Ok(FileStatus {
                file_hash,
                complete_source: true,
                parts: Vec::new(),
            });
        }
        let bytes = n.div_ceil(8);
        let bm = r.take(bytes)?;
        let mut parts = Vec::with_capacity(n);
        for i in 0..n {
            parts.push(bm[i / 8] >> (i % 8) & 1 == 1);
        }
        Ok(FileStatus {
            file_hash,
            complete_source: false,
            parts,
        })
    }
}

// ---------- 分片请求 / 发送 ----------

/// 一个 (start, end) 请求区间，**end 排他**。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartRange {
    pub start: u64,
    /// 排他上界（= 最后一个字节 + 1）
    pub end: u64,
}

impl PartRange {
    pub fn len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }
    pub fn is_empty(&self) -> bool {
        self.end <= self.start
    }
}

/// `OP_REQUESTPARTS`（40 字节）/ `OP_REQUESTPARTS_I64`（64 字节）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestParts {
    pub file_hash: [u8; 16],
    /// 最多 3 个区间；空槽以 `start == end == 0` 表示。
    pub ranges: Vec<PartRange>,
}

impl RequestParts {
    pub fn uses_i64(&self) -> bool {
        self.ranges
            .iter()
            .any(|r| r.start > u32::MAX as u64 || r.end > u32::MAX as u64)
    }

    pub fn encode(&self) -> R<(u8, Vec<u8>)> {
        if self.ranges.len() > 3 {
            return Err(PeerError::BadField("requestparts.too_many_ranges"));
        }
        let i64v = self.uses_i64();
        let mut w = Writer::new();
        w.bytes(&self.file_hash);
        // 起点 3 个，再终点 3 个
        for i in 0..3 {
            let v = self.ranges.get(i).map(|r| r.start).unwrap_or(0);
            if i64v {
                w.u64(v);
            } else {
                w.u32(v as u32);
            }
        }
        for i in 0..3 {
            let v = self.ranges.get(i).map(|r| r.end).unwrap_or(0);
            if i64v {
                w.u64(v);
            } else {
                w.u32(v as u32);
            }
        }
        let op = if i64v {
            emule::REQUESTPARTS_I64
        } else {
            ed2k::REQUESTPARTS
        };
        Ok((op, w.b))
    }

    pub fn decode(opcode: u8, b: &[u8]) -> R<RequestParts> {
        let i64v = match opcode {
            ed2k::REQUESTPARTS => false,
            emule::REQUESTPARTS_I64 => true,
            _ => return Err(PeerError::BadField("requestparts.opcode")),
        };
        let expect = if i64v { 64 } else { 40 };
        if b.len() != expect {
            return Err(PeerError::BadLength {
                declared: expect,
                actual: b.len(),
            });
        }
        let mut r = Reader::new(b);
        let file_hash = r.hash16()?;
        let mut starts = [0u64; 3];
        let mut ends = [0u64; 3];
        for s in starts.iter_mut() {
            *s = if i64v { r.u64()? } else { r.u32()? as u64 };
        }
        for e in ends.iter_mut() {
            *e = if i64v { r.u64()? } else { r.u32()? as u64 };
        }
        let mut ranges = Vec::new();
        for i in 0..3 {
            // 上传侧语义：End <= Start 视为空槽
            if ends[i] > starts[i] {
                ranges.push(PartRange {
                    start: starts[i],
                    end: ends[i],
                });
            }
        }
        Ok(RequestParts { file_hash, ranges })
    }
}

/// `OP_SENDINGPART` / `OP_SENDINGPART_I64`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendingPart {
    pub file_hash: [u8; 16],
    pub start: u64,
    /// 排他上界
    pub end: u64,
    pub data: Vec<u8>,
}

impl SendingPart {
    pub fn encode(&self) -> (u8, Vec<u8>) {
        let i64v = self.start > u32::MAX as u64 || self.end > u32::MAX as u64;
        let mut w = Writer::new();
        w.bytes(&self.file_hash);
        if i64v {
            w.u64(self.start);
            w.u64(self.end);
        } else {
            w.u32(self.start as u32);
            w.u32(self.end as u32);
        }
        w.bytes(&self.data);
        let op = if i64v {
            emule::SENDINGPART_I64
        } else {
            ed2k::SENDINGPART
        };
        (op, w.b)
    }

    pub fn decode(opcode: u8, b: &[u8]) -> R<SendingPart> {
        let i64v = match opcode {
            ed2k::SENDINGPART => false,
            emule::SENDINGPART_I64 => true,
            _ => return Err(PeerError::BadField("sendingpart.opcode")),
        };
        let mut r = Reader::new(b);
        let file_hash = r.hash16()?;
        let (start, end) = if i64v {
            (r.u64()?, r.u64()?)
        } else {
            (r.u32()? as u64, r.u32()? as u64)
        };
        if end <= start {
            return Err(PeerError::BadField("sendingpart.range"));
        }
        let data = r.take(r.remaining())?.to_vec();
        if data.len() as u64 != end - start {
            return Err(PeerError::BadField("sendingpart.data_len"));
        }
        Ok(SendingPart {
            file_hash,
            start,
            end,
            data,
        })
    }
}

// ---------- 队列 ----------

/// `OP_QUEUERANKING`(0xC5/0x60)：**固定 12 字节**（Rank u16 + 10 个保留 0）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueRanking {
    pub rank: u16,
}

impl QueueRanking {
    pub const WIRE_LEN: usize = 12;

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u16(self.rank);
        w.bytes(&[0u8; 10]);
        debug_assert_eq!(w.b.len(), Self::WIRE_LEN);
        w.b
    }

    pub fn decode(b: &[u8]) -> R<QueueRanking> {
        if b.len() != Self::WIRE_LEN {
            return Err(PeerError::BadLength {
                declared: Self::WIRE_LEN,
                actual: b.len(),
            });
        }
        Ok(QueueRanking {
            rank: u16::from_le_bytes([b[0], b[1]]),
        })
    }
}

/// 老式 `OP_QUEUERANK`(0xE3/0x5C)：4 字节 u32。
pub fn encode_queue_rank(rank: u32) -> Vec<u8> {
    rank.to_le_bytes().to_vec()
}

pub fn decode_queue_rank(b: &[u8]) -> R<u32> {
    if b.len() != 4 {
        return Err(PeerError::BadLength {
            declared: 4,
            actual: b.len(),
        });
    }
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

// ---------- SecureIdent（信用身份；不传积分） ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SecureIdentNeed {
    Unavailable = 0,
    SignatureNeeded = 1,
    KeyAndSignatureNeeded = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecureIdentState {
    pub need: SecureIdentNeed,
    pub challenge: u32,
}

impl SecureIdentState {
    pub const WIRE_LEN: usize = 5;

    pub fn encode(self) -> Vec<u8> {
        let mut out = vec![self.need as u8];
        out.extend_from_slice(&self.challenge.to_le_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> R<Self> {
        if b.len() != Self::WIRE_LEN {
            return Err(PeerError::BadLength {
                declared: Self::WIRE_LEN,
                actual: b.len(),
            });
        }
        let need = match b[0] {
            0 => SecureIdentNeed::Unavailable,
            1 => SecureIdentNeed::SignatureNeeded,
            2 => SecureIdentNeed::KeyAndSignatureNeeded,
            _ => return Err(PeerError::BadField("secidentstate.state")),
        };
        Ok(Self {
            need,
            challenge: u32::from_le_bytes(b[1..5].try_into().unwrap()),
        })
    }
}

pub fn encode_public_key(key: &[u8]) -> R<Vec<u8>> {
    if key.is_empty() || key.len() > u8::MAX as usize {
        return Err(PeerError::BadField("publickey.length"));
    }
    let mut out = Vec::with_capacity(key.len() + 1);
    out.push(key.len() as u8);
    out.extend_from_slice(key);
    Ok(out)
}

pub fn decode_public_key(b: &[u8]) -> R<Vec<u8>> {
    let Some(&len) = b.first() else {
        return Err(PeerError::Truncated { need: 1, have: 0 });
    };
    if len == 0 || b.len() != len as usize + 1 {
        return Err(PeerError::BadLength {
            declared: len as usize + 1,
            actual: b.len(),
        });
    }
    Ok(b[1..].to_vec())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureIdentSignature {
    pub signature: Vec<u8>,
    /// SecureIdent v2 才有；0=远端 IP，1=本地 IP。
    pub ip_kind: Option<u8>,
}

impl SecureIdentSignature {
    pub fn encode(&self) -> R<Vec<u8>> {
        if self.signature.is_empty() || self.signature.len() > u8::MAX as usize {
            return Err(PeerError::BadField("signature.length"));
        }
        if self.ip_kind.is_some_and(|v| v > 1) {
            return Err(PeerError::BadField("signature.ip_kind"));
        }
        let mut out = Vec::with_capacity(self.signature.len() + 2);
        out.push(self.signature.len() as u8);
        out.extend_from_slice(&self.signature);
        if let Some(kind) = self.ip_kind {
            out.push(kind);
        }
        Ok(out)
    }

    pub fn decode(b: &[u8]) -> R<Self> {
        let Some(&len) = b.first() else {
            return Err(PeerError::Truncated { need: 1, have: 0 });
        };
        let len = len as usize;
        if len == 0 || (b.len() != len + 1 && b.len() != len + 2) {
            return Err(PeerError::BadLength {
                declared: len + 1,
                actual: b.len(),
            });
        }
        let ip_kind = b.get(len + 1).copied();
        if ip_kind.is_some_and(|v| v > 1) {
            return Err(PeerError::BadField("signature.ip_kind"));
        }
        Ok(Self {
            signature: b[1..1 + len].to_vec(),
            ip_kind,
        })
    }
}

// ---------- AICH 恢复消息 ----------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AichRequest {
    pub file_hash: [u8; 16],
    pub part: u16,
    pub master_hash: [u8; 20],
}

impl AichRequest {
    pub const WIRE_LEN: usize = 38;

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::WIRE_LEN);
        out.extend_from_slice(&self.file_hash);
        out.extend_from_slice(&self.part.to_le_bytes());
        out.extend_from_slice(&self.master_hash);
        out
    }

    pub fn decode(b: &[u8]) -> R<Self> {
        if b.len() != Self::WIRE_LEN {
            return Err(PeerError::BadLength {
                declared: Self::WIRE_LEN,
                actual: b.len(),
            });
        }
        Ok(Self {
            file_hash: b[..16].try_into().unwrap(),
            part: u16::from_le_bytes(b[16..18].try_into().unwrap()),
            master_hash: b[18..38].try_into().unwrap(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AichRecoveryHash {
    pub identifier: u32,
    pub hash: [u8; 20],
    pub wide_identifier: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AichAnswer {
    Failed {
        file_hash: [u8; 16],
    },
    Recovery {
        request: AichRequest,
        hashes: Vec<AichRecoveryHash>,
    },
}

impl AichAnswer {
    pub fn decode(b: &[u8]) -> R<Self> {
        if b.len() == 16 {
            return Ok(Self::Failed {
                file_hash: b.try_into().unwrap(),
            });
        }
        if b.len() < AichRequest::WIRE_LEN + 4 {
            return Err(PeerError::BadLength {
                declared: AichRequest::WIRE_LEN + 4,
                actual: b.len(),
            });
        }
        let request = AichRequest::decode(&b[..AichRequest::WIRE_LEN])?;
        let mut r = Reader::new(&b[AichRequest::WIRE_LEN..]);
        let count16 = r.u16()? as usize;
        let mut hashes = Vec::with_capacity(count16);
        for _ in 0..count16 {
            let identifier = r.u16()? as u32;
            if identifier == 1 {
                return Err(PeerError::BadField("aich.identifier_root"));
            }
            hashes.push(AichRecoveryHash {
                identifier,
                hash: r.take(20)?.try_into().unwrap(),
                wide_identifier: false,
            });
        }
        let count32 = r.u16()? as usize;
        hashes.reserve(count32);
        for _ in 0..count32 {
            let identifier = r.u32()?;
            if identifier == 1 || identifier > 0x40_0000 {
                return Err(PeerError::BadField("aich.identifier32"));
            }
            hashes.push(AichRecoveryHash {
                identifier,
                hash: r.take(20)?.try_into().unwrap(),
                wide_identifier: true,
            });
        }
        if r.remaining() != 0 {
            return Err(PeerError::BadLength {
                declared: b.len() - r.remaining(),
                actual: b.len(),
            });
        }
        Ok(Self::Recovery { request, hashes })
    }
}

/// 便捷构造：只带 FileHash 的消息（`SETREQFILEID` / `STARTUPLOADREQ` / `END_OF_DOWNLOAD` 等）。
pub fn hash_only_packet(protocol: Protocol, opcode: u8, file_hash: &[u8; 16]) -> Packet {
    Packet::new(protocol, opcode, file_hash.to_vec())
}

/// 便捷构造：零载荷消息（`ACCEPTUPLOADREQ` / `CANCELTRANSFER` / `OUTOFPARTREQS`）。
pub fn empty_packet(protocol: Protocol, opcode: u8) -> Packet {
    Packet::new(protocol, opcode, Vec::new())
}

// ---------- 源交换 v2 ----------

/// `OP_REQUESTSOURCES2` / `OP_ANSWERSOURCES2` 的协议版本（`SOURCEEXCHANGE2_VERSION`）。
pub const SOURCEEXCHANGE2_VERSION: u8 = 4;
/// 单条应答里的源条数上限（防内存放大；正常对端一次只给 handful）。
pub const MAX_XS_SOURCES: usize = 1024;

/// 源交换应答里的一条源。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeSource {
    /// 对端报的客户端 ID（点分序；HighID 才可直连）。
    pub client_id: u32,
    /// HighID 时为点分序 IP；LowID（需服务器回调）为 None。
    pub ip: Option<std::net::Ipv4Addr>,
    pub port: u16,
    /// v2+ 才有：该源所在服务器。
    pub server_ip: Option<std::net::Ipv4Addr>,
    pub server_port: Option<u16>,
    /// v3+ 才有：该源的用户哈希。
    pub user_hash: Option<[u8; 16]>,
    /// v4 才有：加密选项。
    pub crypt_options: Option<u8>,
}

impl ExchangeSource {
    /// 是否可直接 TCP 连接（HighID 且端口非零；是否过滤私网由调用方按场景决定）。
    pub fn is_direct(&self) -> bool {
        self.ip.is_some() && self.port != 0
    }

    pub fn socket_addr(&self) -> Option<std::net::SocketAddr> {
        Some(std::net::SocketAddr::from((self.ip?, self.port)))
    }
}

/// LowID 判定与服务器协议一致：`id < 0x01000000`。
fn is_low_id(id: u32) -> bool {
    id < 0x0100_0000
}

/// IP 与 ClientID 一律点分序原样（`55 11 74 DE` = 85.17.116.222），与服务器协议同规则。
fn ipv4_dotted(b: &[u8]) -> std::net::Ipv4Addr {
    std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3])
}

/// 编码 `OP_REQUESTSOURCES2`：Version(1) + Options(2) + FileHash(16)。
/// Options 置 0：不提加密等特殊要求，拿到常规源即可。
pub fn encode_request_sources2(file_hash: &[u8; 16]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(SOURCEEXCHANGE2_VERSION);
    w.u16(0);
    w.bytes(file_hash);
    w.b
}

/// 解析 `OP_ANSWERSOURCES2`：Version(1) + FileHash(16) + Count(2) + 条目。
///
/// eMule `PartFile.cpp::CreateSrcInfoPacket` 的字段顺序：
/// `v1: ID4+PORT2+SRVIP4+SRVPORT2；v2/v3: +USERHASH16；v4: +CRYPT1`。
/// v3 不增加字段，只把 ID 改为 Hybrid 格式（HighID 的四个线上字节相对 v1/v2 反序）。
/// 文件哈希、未知版本（>4）与长度任一不符都拒绝，不猜边界。
pub fn decode_answer_sources2(b: &[u8], expected_file_hash: &[u8; 16]) -> R<Vec<ExchangeSource>> {
    let mut r = Reader::new(b);
    let version = r.u8()?;
    if !(1..=SOURCEEXCHANGE2_VERSION).contains(&version) {
        return Err(PeerError::BadField("answersources2.version"));
    }
    if &r.hash16()? != expected_file_hash {
        return Err(PeerError::BadField("answersources2.file_hash"));
    }
    let count = r.u16()? as usize;
    if count > MAX_XS_SOURCES {
        return Err(PeerError::BadField("answersources2.too_many"));
    }
    let entry_len = match version {
        1 => 12,
        2 | 3 => 28,
        _ => 29,
    };
    // 长度必须精确吻合：多一字节都说明布局理解有误，宁可整包丢弃。
    if r.remaining() != count * entry_len {
        return Err(PeerError::BadLength {
            declared: count * entry_len,
            actual: r.remaining(),
        });
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let id_bytes = r.take(4)?;
        let client_id = u32::from_le_bytes(id_bytes.try_into().unwrap());
        let port = r.u16()?;
        let server_ip = Some(ipv4_dotted(r.take(4)?));
        let server_port = Some(r.u16()?);
        let user_hash = if version >= 2 {
            Some(r.hash16()?)
        } else {
            None
        };
        let crypt_options = if version >= 4 { Some(r.u8()?) } else { None };
        let ip = if is_low_id(client_id) {
            None
        } else if version >= 3 {
            Some(ipv4_dotted(&[
                id_bytes[3],
                id_bytes[2],
                id_bytes[1],
                id_bytes[0],
            ]))
        } else {
            Some(ipv4_dotted(id_bytes))
        };
        out.push(ExchangeSource {
            client_id,
            ip,
            port,
            server_ip,
            server_port,
            user_hash,
            crypt_options,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(seed: u8) -> [u8; 16] {
        [seed; 16]
    }

    /// 报文头：`packetlength = 载荷 + 1`；最小报文 6 字节。
    #[test]
    fn packet_framing_matches_spec() {
        let p = Packet::new(Protocol::Edonkey, ed2k::HELLO, vec![0xAA, 0xBB]);
        let b = p.encode();
        assert_eq!(b.len(), 8);
        assert_eq!(b[0], 0xE3, "协议字节");
        assert_eq!(
            u32::from_le_bytes([b[1], b[2], b[3], b[4]]),
            3,
            "packetlength 应为 载荷(2)+1"
        );
        assert_eq!(b[5], ed2k::HELLO);
        assert_eq!(Packet::decode(&b).unwrap(), p);

        // 零载荷：整包 6 字节，packetlength = 1
        let e = empty_packet(Protocol::Edonkey, ed2k::ACCEPTUPLOADREQ).encode();
        assert_eq!(e.len(), 6);
        assert_eq!(u32::from_le_bytes([e[1], e[2], e[3], e[4]]), 1);
        assert_eq!(Packet::decode(&e).unwrap().payload.len(), 0);

        // 头部解析
        let (proto, len, op) = Packet::header(&e[..6].try_into().unwrap()).unwrap();
        assert_eq!(
            (proto, len, op),
            (Protocol::Edonkey, 0, ed2k::ACCEPTUPLOADREQ)
        );
    }

    /// 长度不符 / 截断 / 未知协议 / 超限都要明确失败。
    #[test]
    fn packet_framing_rejects_bad_input() {
        let mut b = Packet::new(Protocol::Edonkey, 0x50, vec![1, 2, 3]).encode();
        b.push(0xFF); // 多一字节
        assert!(matches!(
            Packet::decode(&b),
            Err(PeerError::BadLength { .. })
        ));

        assert!(matches!(
            Packet::decode(&[0xE3, 0x01]),
            Err(PeerError::Truncated { .. })
        ));

        let mut bad = Packet::new(Protocol::Edonkey, 0x01, vec![]).encode();
        bad[0] = 0x99;
        assert!(matches!(
            Packet::decode(&bad),
            Err(PeerError::BadProtocol(0x99))
        ));

        // packetlength = 0 非法
        let zero = [0xE3, 0, 0, 0, 0, 0x01];
        assert!(matches!(
            Packet::decode(&zero),
            Err(PeerError::BadLength { .. })
        ));

        // 声明超大载荷
        let big = [0xE3, 0xFF, 0xFF, 0xFF, 0xFF, 0x01];
        assert!(matches!(Packet::decode(&big), Err(PeerError::TooLarge(_))));
    }

    /// 标签：短名（0x80 位）、长名、自动降位宽、定长串。
    #[test]
    fn tags_roundtrip_with_auto_width() {
        // 短名 + 小整数 → UINT8
        let t = Tag::short(0x11, TagValue::Uint(0x3C));
        let enc = t.encode();
        assert_eq!(enc[0] & 0x80, 0x80, "短名应置 0x80");
        assert_eq!(enc[0] & 0x7F, TagType::Uint8.code(), "≤0xFF 应用 UINT8");
        assert_eq!(enc[1], 0x11, "1 字节名称 ID");
        assert_eq!(enc.len(), 3);
        let mut r = Reader::new(&enc);
        assert_eq!(Tag::decode(&mut r).unwrap(), t);

        // 中整数 → UINT16
        let t2 = Tag::short(0xF9, TagValue::Uint(0x1234));
        let e2 = t2.encode();
        assert_eq!(e2[0] & 0x7F, TagType::Uint16.code());
        assert_eq!(Tag::decode(&mut Reader::new(&e2)).unwrap(), t2);

        // 大整数 → UINT32
        let t3 = Tag::short(0xFB, TagValue::Uint(0x0064_0000));
        let e3 = t3.encode();
        assert_eq!(e3[0] & 0x7F, TagType::Uint32.code());
        assert_eq!(Tag::decode(&mut Reader::new(&e3)).unwrap(), t3);

        // 长名 + 长字符串 → STRING
        let t4 = Tag::named("filename", TagValue::Str("a".repeat(20)));
        let e4 = t4.encode();
        assert_eq!(e4[0], TagType::String.code(), "长名不置 0x80");
        assert_eq!(Tag::decode(&mut Reader::new(&e4)).unwrap(), t4);

        // 短字符串（≤16）→ 定长 STRn
        let t5 = Tag::short(0x01, TagValue::Str("nick".into()));
        let e5 = t5.encode();
        assert_eq!(e5[0] & 0x7F, 0x10 + 4, "4 字节串应用 STR4(0x14)");
        assert_eq!(Tag::decode(&mut Reader::new(&e5)).unwrap(), t5);

        // 16 字节串正好是 STR16
        let t6 = Tag::short(0x01, TagValue::Str("0123456789abcdef".into()));
        let e6 = t6.encode();
        assert_eq!(e6[0] & 0x7F, 0x20);

        // HASH 与 BOOL
        let t7 = Tag::short(0x02, TagValue::Hash(hash(0x5A)));
        assert_eq!(Tag::decode(&mut Reader::new(&t7.encode())).unwrap(), t7);
        let t8 = Tag::short(0x03, TagValue::Bool(true));
        assert_eq!(Tag::decode(&mut Reader::new(&t8.encode())).unwrap(), t8);

        // 未知类型要报错（0xFF = 短名位 + 类型 0x7F；类型在读完名字后才分派）
        assert!(matches!(
            Tag::decode(&mut Reader::new(&[0xFF, 0x01])),
            Err(PeerError::BadTagType(0x7F))
        ));
        // 名字都没读完就该报截断，而不是猜类型
        assert!(matches!(
            Tag::decode(&mut Reader::new(&[0x7F, 0x01])),
            Err(PeerError::Truncated { .. })
        ));
    }

    #[test]
    fn classic_hello_numeric_tag_names_are_not_utf8_strings() {
        let mut payload = vec![0x11; 16];
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(&4662u16.to_le_bytes());
        payload.extend_from_slice(&2u32.to_le_bytes());
        for (id, value) in [(0xFA, 0x1000_0000u32), (0xFB, 0x0064_0000)] {
            payload.push(0x03); // old-style uint32, no 0x80 short-name flag
            payload.extend_from_slice(&1u16.to_le_bytes());
            payload.push(id);
            payload.extend_from_slice(&value.to_le_bytes());
        }
        payload.extend_from_slice(&[0; 6]);
        let hello = HelloInfo::decode(ed2k::HELLOANSWER, &payload).unwrap();
        assert_eq!(
            hello.tag(0xFA).and_then(TagValue::as_u64),
            Some(0x1000_0000)
        );
        assert_eq!(
            hello.tag(0xFB).and_then(TagValue::as_u64),
            Some(0x0064_0000)
        );
    }

    /// 能力位域：往返一致 + `Requests &= Supports` 约束。
    #[test]
    fn misc_options_bitfields() {
        let o1 = MiscOptions1 {
            aich_version: 1,
            unicode: true,
            udp_version: 4,
            data_compression: 1,
            sec_ident: 3,
            source_exchange: 4,
            ext_requests: 2,
            comments: 1,
            peer_cache: true,
            no_view_shared: false,
            multi_packet: true,
            preview: false,
        };
        assert_eq!(MiscOptions1::from_u32(o1.to_u32()), o1);

        let o2 = MiscOptions2 {
            file_ident: true,
            direct_udp_callback: true,
            captcha: false,
            source_exchange2: true,
            requires_crypt: false,
            requests_crypt: false,
            supports_crypt: true,
            ext_multipacket: false,
            large_files: true,
            kad_version: KADEMLIA_VERSION as u8,
        };
        let raw = o2.to_u32();
        assert_eq!(MiscOptions2::from_u32(raw), o2);

        // 未声明 Supports 时 Requests/Requires 必须被清掉
        let lying = (1 << 8) | (1 << 9); // 只置 Requests/Requires，不置 Supports
        let parsed = MiscOptions2::from_u32(lying);
        assert!(!parsed.supports_crypt);
        assert!(!parsed.requests_crypt, "未声明 Supports → Requests 归零");
        assert!(!parsed.requires_crypt, "未声明 Requests → Requires 归零");

        // 声明 Supports + Requests + Requires → 三者都保留
        let full = (1 << 7) | (1 << 8) | (1 << 9);
        let p2 = MiscOptions2::from_u32(full);
        assert!(p2.supports_crypt && p2.requests_crypt && p2.requires_crypt);
    }

    /// 版本打包：eMule 0.50a → 0x00640000。
    #[test]
    fn emule_version_packing() {
        let v = pack_emule_version(COMPAT_CLIENT_EMULE, 50, 0, 0, 0);
        assert_eq!(v, 0x0064_0000, "eMule 0.50a 应为 0x00640000");
        assert_eq!(unpack_emule_version(v), (0, 50, 0, 0, 0));
        let v2 = pack_emule_version(3, 1, 2, 4, 5);
        assert_eq!(unpack_emule_version(v2), (3, 1, 2, 4, 5));
    }

    /// HELLO 有 `0x10` 长度字节、HELLOANSWER 没有 —— 最容易写错的一处。
    #[test]
    fn hello_and_helloanswer_differ_by_length_byte() {
        let info = HelloInfo {
            user_hash: make_emule_hash(hash(0x11)),
            client_id: 0x0102_0304,
            tcp_port: 4662,
            tags: vec![
                Tag::short(0x01, TagValue::Str("aidm".into())),
                Tag::short(0x11, TagValue::Uint(EDONKEYVERSION as u64)),
                Tag::short(
                    0xFB,
                    TagValue::Uint(pack_emule_version(0, 50, 0, 0, 0) as u64),
                ),
            ],
            server_ip: 0,
            server_port: 0,
        };
        let hello = info.encode(false);
        let answer = info.encode(true);
        assert_eq!(hello[0], 0x10, "HELLO 首字节是 UserHash 长度 16");
        assert_eq!(
            &hello[1..17],
            &info.user_hash[..],
            "HELLO 的哈希从偏移 1 开始"
        );
        assert_eq!(
            &answer[0..16],
            &info.user_hash[..],
            "HELLOANSWER 的哈希直接从偏移 0 开始"
        );
        assert_eq!(answer.len(), hello.len() - 1, "只差那个长度字节");

        assert_eq!(HelloInfo::decode(ed2k::HELLO, &hello).unwrap(), info);
        assert_eq!(HelloInfo::decode(ed2k::HELLOANSWER, &answer).unwrap(), info);

        // 用错 opcode 解必须失败（HELLO 会读到 0x10 之外的字节）
        assert!(HelloInfo::decode(ed2k::HELLO, &answer).is_err());

        // eMule 哈希特征：byte[5]=14, byte[14]=111
        let h = make_emule_hash([0u8; 16]);
        assert!(is_emule_hash(&h));
        assert_eq!(h[5], 14);
        assert_eq!(h[14], 111);

        // 标签取值便捷方法
        let d = HelloInfo::decode(ed2k::HELLO, &hello).unwrap();
        assert_eq!(d.tag(0x11).and_then(|v| v.as_u64()), Some(0x3C));
        assert_eq!(d.tag(0x01).and_then(|v| v.as_str()), Some("aidm"));
        assert!(d.tag(0x99).is_none());
    }

    /// 分片位图：精确位序、n==0 完整源、分片数计算。
    #[test]
    fn file_status_bitmap() {
        assert_eq!(part_count(0), 0);
        assert_eq!(part_count(1), 1);
        assert_eq!(part_count(PARTSIZE), 1);
        assert_eq!(part_count(PARTSIZE + 1), 2);
        assert_eq!(part_count(PARTSIZE * 3), 3);

        // 10 个分片，只有第 0、8、9 个可用 → bm[0]=0x01, bm[1]=0x03
        let mut parts = vec![false; 10];
        parts[0] = true;
        parts[8] = true;
        parts[9] = true;
        let fs = FileStatus {
            file_hash: hash(1),
            complete_source: false,
            parts,
        };
        let enc = fs.encode();
        assert_eq!(enc.len(), 16 + 2 + 2, "10 位 → 2 字节位图");
        assert_eq!(enc[16], 10, "分片数小端");
        assert_eq!(enc[18], 0x01, "第 0 位");
        assert_eq!(enc[19], 0x03, "第 8、9 位");
        assert_eq!(FileStatus::decode(&enc).unwrap(), fs);

        // n == 0：完整源，且不带位图
        let complete = FileStatus {
            file_hash: hash(2),
            complete_source: true,
            parts: vec![],
        };
        let ce = complete.encode();
        assert_eq!(ce.len(), 18, "完整源只有 哈希+计数(0)");
        let cd = FileStatus::decode(&ce).unwrap();
        assert!(cd.complete_source);
        assert!(cd.parts.is_empty());

        // 完整源便捷构造：按文件大小填满
        let full = FileStatus::complete(hash(3), PARTSIZE * 2 + 5);
        assert!(full.complete_source && full.parts.len() == 3);

        // 23 个分片 → 3 字节，末字节越界位必须为 0
        let fs23 = FileStatus {
            file_hash: hash(4),
            complete_source: false,
            parts: vec![true; 23],
        };
        let e23 = fs23.encode();
        assert_eq!(e23.len(), 16 + 2 + 3);
        assert_eq!(e23[20], 0x7F, "23 位只用到低 7 位，高位必须为 0");
        assert_eq!(FileStatus::decode(&e23).unwrap(), fs23);

        // 18 个零字节本身是合法报文：count=0 → 完整源（不能当错误）
        let zeros = FileStatus::decode(&[0u8; 18]).unwrap();
        assert!(zeros.complete_source && zeros.parts.is_empty());

        // 真正截断：计数说 10 个分片，却没跟位图；以及连计数都不够
        let mut truncated = vec![0u8; 18];
        truncated[16..18].copy_from_slice(&10u16.to_le_bytes());
        assert!(matches!(
            FileStatus::decode(&truncated),
            Err(PeerError::Truncated { .. })
        ));
        assert!(matches!(
            FileStatus::decode(&[0u8; 17]),
            Err(PeerError::Truncated { .. })
        ));
    }

    /// REQUESTPARTS 固定 40 字节、End 排他、空槽为 0；I64 版 64 字节。
    #[test]
    fn request_parts_layout() {
        let rp = RequestParts {
            file_hash: hash(7),
            ranges: vec![
                PartRange {
                    start: 0,
                    end: 1024,
                },
                PartRange {
                    start: 9728000,
                    end: 9728000 + 512,
                },
            ],
        };
        let (op, enc) = rp.encode().unwrap();
        assert_eq!(op, ed2k::REQUESTPARTS);
        assert_eq!(enc.len(), 40, "固定 40 字节");
        assert_eq!(&enc[0..16], &hash(7)[..]);
        assert_eq!(u32::from_le_bytes([enc[16], enc[17], enc[18], enc[19]]), 0);
        assert_eq!(
            u32::from_le_bytes([enc[20], enc[21], enc[22], enc[23]]),
            9_728_000,
            "起点 2"
        );
        assert_eq!(
            u32::from_le_bytes([enc[24], enc[25], enc[26], enc[27]]),
            0,
            "起点 3 空槽"
        );
        assert_eq!(
            u32::from_le_bytes([enc[28], enc[29], enc[30], enc[31]]),
            1024
        );
        assert_eq!(
            u32::from_le_bytes([enc[32], enc[33], enc[34], enc[35]]),
            9_728_512,
            "终点 2（排他）"
        );
        assert_eq!(RequestParts::decode(op, &enc).unwrap(), rp);

        // 空槽（end <= start）在解析侧被丢弃
        let mut zeroed = enc.clone();
        zeroed[16..28].copy_from_slice(&[0u8; 12]);
        zeroed[28..40].copy_from_slice(&[0u8; 12]);
        let only_hash = RequestParts::decode(op, &zeroed).unwrap();
        assert!(only_hash.ranges.is_empty());

        // 长度不符
        assert!(matches!(
            RequestParts::decode(op, &enc[..39]),
            Err(PeerError::BadLength { .. })
        ));

        // 超过 3 个区间拒绝
        let too_many = RequestParts {
            file_hash: hash(1),
            ranges: vec![PartRange { start: 0, end: 1 }; 4],
        };
        assert!(matches!(
            too_many.encode(),
            Err(PeerError::BadField("requestparts.too_many_ranges"))
        ));

        // I64：偏移超过 u32 时自动切换，载荷 64 字节
        let big = RequestParts {
            file_hash: hash(9),
            ranges: vec![PartRange {
                start: u32::MAX as u64 + 10,
                end: u32::MAX as u64 + 20,
            }],
        };
        let (op64, e64) = big.encode().unwrap();
        assert_eq!(op64, emule::REQUESTPARTS_I64);
        assert_eq!(e64.len(), 64);
        assert_eq!(RequestParts::decode(op64, &e64).unwrap(), big);
    }

    /// SENDINGPART：数据长度必须与区间一致；End 排他；I64 变体。
    #[test]
    fn sending_part_layout() {
        let sp = SendingPart {
            file_hash: hash(3),
            start: 100,
            end: 104,
            data: vec![1, 2, 3, 4],
        };
        let (op, enc) = sp.encode();
        assert_eq!(op, ed2k::SENDINGPART);
        assert_eq!(enc.len(), 16 + 4 + 4 + 4);
        assert_eq!(
            u32::from_le_bytes([enc[16], enc[17], enc[18], enc[19]]),
            100
        );
        assert_eq!(
            u32::from_le_bytes([enc[20], enc[21], enc[22], enc[23]]),
            104
        );
        assert_eq!(&enc[24..], &[1, 2, 3, 4]);
        assert_eq!(SendingPart::decode(op, &enc).unwrap(), sp);

        // 数据长度不符 → 报错
        let mut bad = enc.clone();
        bad.push(5);
        assert!(matches!(
            SendingPart::decode(op, &bad),
            Err(PeerError::BadField("sendingpart.data_len"))
        ));

        // end <= start 非法
        let mut zero = enc.clone();
        zero[20..24].copy_from_slice(&100u32.to_le_bytes());
        assert!(matches!(
            SendingPart::decode(op, &zero),
            Err(PeerError::BadField("sendingpart.range"))
        ));

        // I64
        let big = SendingPart {
            file_hash: hash(4),
            start: u32::MAX as u64 + 1,
            end: u32::MAX as u64 + 3,
            data: vec![9, 9],
        };
        let (op64, e64) = big.encode();
        assert_eq!(op64, emule::SENDINGPART_I64);
        assert_eq!(e64.len(), 16 + 8 + 8 + 2);
        assert_eq!(SendingPart::decode(op64, &e64).unwrap(), big);
    }

    /// QUEUERANKING 必须正好 12 字节（写 2 字节会被对端按坏包断连）。
    #[test]
    fn queue_ranking_is_twelve_bytes() {
        let q = QueueRanking { rank: 42 };
        let enc = q.encode();
        assert_eq!(enc.len(), 12);
        assert_eq!(u16::from_le_bytes([enc[0], enc[1]]), 42);
        assert_eq!(&enc[2..], &[0u8; 10], "后 10 字节为保留 0");
        assert_eq!(QueueRanking::decode(&enc).unwrap(), q);

        // 长度不对必须失败
        assert!(matches!(
            QueueRanking::decode(&enc[..2]),
            Err(PeerError::BadLength { .. })
        ));
        assert!(matches!(
            QueueRanking::decode(&[0u8; 4]),
            Err(PeerError::BadLength { .. })
        ));

        // 老式 OP_QUEUERANK 是 4 字节 u32
        let old = encode_queue_rank(7);
        assert_eq!(old.len(), 4);
        assert_eq!(decode_queue_rank(&old).unwrap(), 7);
        assert!(decode_queue_rank(&old[..2]).is_err());
    }

    #[test]
    fn secure_ident_messages_are_length_strict() {
        let state = SecureIdentState {
            need: SecureIdentNeed::KeyAndSignatureNeeded,
            challenge: 0x1234_5678,
        };
        assert_eq!(SecureIdentState::decode(&state.encode()).unwrap(), state);
        assert!(SecureIdentState::decode(&state.encode()[..4]).is_err());
        assert!(SecureIdentState::decode(&[3, 0, 0, 0, 0]).is_err());

        let key = vec![0x5A; 80];
        assert_eq!(
            decode_public_key(&encode_public_key(&key).unwrap()).unwrap(),
            key
        );
        assert!(decode_public_key(&[2, 1]).is_err());

        let signature = SecureIdentSignature {
            signature: vec![7; 64],
            ip_kind: Some(1),
        };
        assert_eq!(
            SecureIdentSignature::decode(&signature.encode().unwrap()).unwrap(),
            signature
        );
        let mut invalid = signature.encode().unwrap();
        *invalid.last_mut().unwrap() = 2;
        assert!(SecureIdentSignature::decode(&invalid).is_err());
    }

    #[test]
    fn aich_recovery_messages_are_length_strict() {
        let request = AichRequest {
            file_hash: hash(3),
            part: 4,
            master_hash: [5; 20],
        };
        assert_eq!(AichRequest::decode(&request.encode()).unwrap(), request);
        assert!(AichRequest::decode(&request.encode()[..37]).is_err());

        let mut answer = request.encode();
        answer.extend_from_slice(&1u16.to_le_bytes());
        answer.extend_from_slice(&3u16.to_le_bytes());
        answer.extend_from_slice(&[7; 20]);
        answer.extend_from_slice(&1u16.to_le_bytes());
        answer.extend_from_slice(&6u32.to_le_bytes());
        answer.extend_from_slice(&[8; 20]);
        let decoded = AichAnswer::decode(&answer).unwrap();
        let AichAnswer::Recovery { hashes, .. } = decoded else {
            panic!("recovery")
        };
        assert_eq!(hashes.len(), 2);
        assert!(!hashes[0].wide_identifier);
        assert!(hashes[1].wide_identifier);
        assert!(matches!(
            AichAnswer::decode(&hash(9)),
            Ok(AichAnswer::Failed { .. })
        ));
        answer.push(0);
        assert!(AichAnswer::decode(&answer).is_err());
    }

    /// 便捷构造与 PartRange 语义。
    #[test]
    fn convenience_builders_and_range_semantics() {
        let p = hash_only_packet(Protocol::Edonkey, ed2k::STARTUPLOADREQ, &hash(8));
        assert_eq!(p.payload.len(), 16);
        let dec = Packet::decode(&p.encode()).unwrap();
        assert_eq!(dec.opcode, ed2k::STARTUPLOADREQ);
        assert_eq!(dec.payload, hash(8).to_vec());

        let e = empty_packet(Protocol::Emule, emule::QUEUERANKING);
        assert_eq!(e.encode().len(), 6);

        let r = PartRange { start: 10, end: 20 };
        assert_eq!(r.len(), 10);
        assert!(!r.is_empty());
        assert!(PartRange { start: 5, end: 5 }.is_empty());
        assert!(PartRange { start: 9, end: 3 }.is_empty());
    }

    /// 源交换 v2：请求固定 19 字节；应答带文件哈希并按版本解条目。
    #[test]
    fn source_exchange_roundtrip() {
        let h = hash(7);
        let req = encode_request_sources2(&h);
        assert_eq!(req.len(), 19, "Version(1)+Options(2)+Hash(16)");
        assert_eq!(req[0], SOURCEEXCHANGE2_VERSION);
        assert_eq!(&req[3..], &h[..]);

        // v1：每条已经包含服务器地址；一条 HighID + 一条 LowID。
        let mut v1 = vec![1u8];
        v1.extend_from_slice(&h);
        v1.extend_from_slice(&2u16.to_le_bytes());
        v1.extend_from_slice(&[85, 17, 116, 222]);
        v1.extend_from_slice(&6082u16.to_le_bytes());
        v1.extend_from_slice(&[1, 2, 3, 4]);
        v1.extend_from_slice(&4661u16.to_le_bytes());
        v1.extend_from_slice(&0x00FF_FFFFu32.to_le_bytes());
        v1.extend_from_slice(&4662u16.to_le_bytes());
        v1.extend_from_slice(&[5, 6, 7, 8]);
        v1.extend_from_slice(&4661u16.to_le_bytes());
        let srcs = decode_answer_sources2(&v1, &h).unwrap();
        assert_eq!(srcs.len(), 2);
        assert_eq!(
            srcs[0].ip,
            Some(std::net::Ipv4Addr::new(85, 17, 116, 222)),
            "HighID 必须点分序原样，不能反序"
        );
        assert_eq!(srcs[0].port, 6082);
        assert_eq!(srcs[0].server_ip, Some(std::net::Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(srcs[0].server_port, Some(4661));
        assert_eq!(srcs[0].user_hash, None);
        assert!(srcs[0].is_direct());
        assert_eq!(srcs[0].socket_addr().unwrap().port(), 6082);
        assert_eq!(srcs[1].ip, None, "LowID 不可直连");
        assert!(!srcs[1].is_direct());
        assert!(srcs[1].socket_addr().is_none());

        // v4：Hybrid HighID 的线上四字节相对 v1/v2 反序，另附 UserHash/加密位。
        let mut v4 = vec![4u8];
        v4.extend_from_slice(&h);
        v4.extend_from_slice(&1u16.to_le_bytes());
        v4.extend_from_slice(&[70, 120, 64, 186]);
        v4.extend_from_slice(&4232u16.to_le_bytes());
        v4.extend_from_slice(&[1, 2, 3, 4]);
        v4.extend_from_slice(&5000u16.to_le_bytes());
        v4.extend_from_slice(&[0x5A; 16]);
        v4.push(0x07);
        let s4 = decode_answer_sources2(&v4, &h).unwrap();
        assert_eq!(s4.len(), 1);
        assert_eq!(s4[0].ip, Some(std::net::Ipv4Addr::new(186, 64, 120, 70)));
        assert_eq!(s4[0].server_ip, Some(std::net::Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(s4[0].server_port, Some(5000));
        assert_eq!(s4[0].user_hash, Some([0x5A; 16]));
        assert_eq!(s4[0].crypt_options, Some(0x07));
        assert!(s4[0].is_direct());

        // fail closed：未知版本 / 长度不符 / 条数超限
        let mut bad_ver = v1.clone();
        bad_ver[0] = 5;
        assert!(decode_answer_sources2(&bad_ver, &h).is_err());
        assert!(matches!(
            decode_answer_sources2(&v1, &hash(8)),
            Err(PeerError::BadField("answersources2.file_hash"))
        ));
        let mut trailing = v1.clone();
        trailing.push(0);
        assert!(matches!(
            decode_answer_sources2(&trailing, &h),
            Err(PeerError::BadLength { .. })
        ));
        // 少一字节：总长与 count×条目不符即拒绝（先于逐条解析）
        assert!(decode_answer_sources2(&v1[..v1.len() - 1], &h).is_err());
        let mut many = vec![1u8];
        many.extend_from_slice(&h);
        many.extend_from_slice(&2000u16.to_le_bytes());
        assert!(decode_answer_sources2(&many, &h).is_err());
        // 空应答合法
        let mut empty = vec![1u8];
        empty.extend_from_slice(&h);
        empty.extend_from_slice(&0u16.to_le_bytes());
        assert!(decode_answer_sources2(&empty, &h).unwrap().is_empty());
    }
}

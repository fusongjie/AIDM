//! eDonkey/eMule **服务器协议**的消息编解码（L3）。
//!
//! 帧格式与对等协议相同（`0xE3 | u32 LE(1+载荷) | opcode | 载荷`），区别在 opcode 集合
//! 与载荷布局。依据 `docs/ed2k-server-protocol-spec.md`（eMule + aMule + Wireshark 三方交叉，
//! 并用两份真实 `server.met` 验证到精确 EOF）。
//!
//! ## 字节序（务必按此，反了会得到看似合理但全错的地址）
//!
//! - **IP 与 ClientID：点分序原样**（`55 11 74 DE` = 85.17.116.222）。
//! - **端口、计数、标签值：小端**。
//!
//! ## 这个模块存在的理由：流式分帧
//!
//! 服务器会把多条消息塞进同一个 TCP 帧（eMule `iMaxFilesPerTcpFrame = 15` 的 0x19 包），
//! 也会**不请自来**地推 `0x38 MOTD` / `0x34 SERVERSTATUS`。没有正确的分帧与"可跳过未知消息"
//! 的能力，后面的状态机一律错位——所以这里把"读一条完整消息"做成独立可测的单元。

use std::net::Ipv4Addr;

use super::peer::{Packet, PeerError, Protocol};

/// 服务器协议 opcode。
pub mod op {
    pub const LOGINREQUEST: u8 = 0x01;
    pub const REJECT: u8 = 0x05;
    pub const GETSERVERLIST: u8 = 0x14;
    pub const OFFERFILES: u8 = 0x15;
    pub const SEARCHREQUEST: u8 = 0x16;
    pub const DISCONNECT: u8 = 0x18;
    pub const GETSOURCES: u8 = 0x19;
    pub const CALLBACKREQUEST: u8 = 0x1C;
    pub const QUERY_MORE_RESULT: u8 = 0x21;
    pub const GETSOURCES_OBFU: u8 = 0x23;
    pub const SERVERLIST: u8 = 0x32;
    pub const SEARCHRESULT: u8 = 0x33;
    pub const SERVERSTATUS: u8 = 0x34;
    pub const CALLBACKREQUESTED: u8 = 0x35;
    pub const CALLBACK_FAIL: u8 = 0x36;
    pub const SERVERMESSAGE: u8 = 0x38;
    pub const IDCHANGE: u8 = 0x40;
    pub const SERVERIDENT: u8 = 0x41;
    pub const FOUNDSOURCES: u8 = 0x42;
    pub const USERS_LIST: u8 = 0x43;
    pub const FOUNDSOURCES_OBFU: u8 = 0x44;
}

/// 服务器下发的 TCP 能力标志（`0x40` 的第二个 u32）。
pub mod tcp_flags {
    pub const COMPRESSION: u32 = 0x01;
    pub const NEWTAGS: u32 = 0x08;
    pub const UNICODE: u32 = 0x10;
    pub const RELATEDSEARCH: u32 = 0x40;
    pub const INTTAGS: u32 = 0x80;
    pub const LARGEFILES: u32 = 0x100;
    /// ⚠️ `0x400` 在**两个不同字段**里含义不同：服务器 TCP 能力里是"支持 TCP 混淆"，
    /// 客户端 SRVCAP 里是"请求加密"。这里保留两个同名常量，用的时候先看是哪个字段。
    pub const TCPOBFUSCATION: u32 = 0x400;
    // 客户端声明自己是否支持/请求/要求加密层（我们未实现，故一律不声明）
    pub const SUPPORTCRYPT: u32 = 0x200;
    pub const REQUESTCRYPT: u32 = 0x400;
    pub const REQUIRECRYPT: u32 = 0x800;
    /// 全部加密相关位（用于自检"我们没谎报加密能力"）。
    pub const CRYPT_MASK: u32 = SUPPORTCRYPT | REQUESTCRYPT | REQUIRECRYPT;
}

/// LowID 判定：`id < 0x01000000`（最高字节为 0 即 LowID）。
pub fn is_low_id(id: u32) -> bool {
    id < 0x0100_0000
}

/// 把点分序的 4 字节读成 `Ipv4Addr`。
pub fn ip_from_dotted(b: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(b[0], b[1], b[2], b[3])
}

/// 解析 `0x40 IDCHANGE`。
///
/// 载荷按长度递增存在：4(仅 CID) / 8(+flags) / 12(+保留) / 20(+公网 IP + 混淆端口)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdChange {
    /// 服务器分配给我的客户端 ID（点分序）。
    pub client_id: u32,
    /// 服务器 TCP 能力标志。
    pub tcp_flags: Option<u32>,
    /// 第三个 u32（eMule 注释为 unused，本实现不解读）。
    pub reserved: Option<u32>,
    /// 服务器看到的我的公网 IP（仅 LowID 时有意义）。
    pub public_ip: Option<Ipv4Addr>,
    /// TCP 混淆端口（0 = 不支持）。
    pub obfuscation_port: Option<u32>,
}

impl IdChange {
    pub fn decode(b: &[u8]) -> Result<IdChange, PeerError> {
        if b.len() < 4 {
            return Err(PeerError::Truncated {
                need: 4,
                have: b.len(),
            });
        }
        let u32at = |o: usize| -> Option<u32> {
            b.get(o..o + 4)
                .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        };
        Ok(IdChange {
            client_id: u32at(0).unwrap(),
            tcp_flags: if b.len() >= 8 { u32at(4) } else { None },
            reserved: if b.len() >= 12 { u32at(8) } else { None },
            public_ip: if b.len() >= 16 {
                Some(ip_from_dotted(&b[12..16]))
            } else {
                None
            },
            obfuscation_port: if b.len() >= 20 { u32at(16) } else { None },
        })
    }

    pub fn is_low_id(&self) -> bool {
        is_low_id(self.client_id)
    }
}

/// 服务器状态（`0x34`）：只读前 8 字节。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerStatus {
    pub users: u32,
    pub files: u32,
}

impl ServerStatus {
    pub fn decode(b: &[u8]) -> Result<ServerStatus, PeerError> {
        if b.len() < 8 {
            return Err(PeerError::Truncated {
                need: 8,
                have: b.len(),
            });
        }
        Ok(ServerStatus {
            users: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            files: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
        })
    }
}

/// `0x38 SERVERMESSAGE`：`u16 LE 长度 + 文本`（可多行，容忍尾部多余字节）。
pub fn decode_server_message(b: &[u8]) -> Result<String, PeerError> {
    if b.len() < 2 {
        return Err(PeerError::Truncated {
            need: 2,
            have: b.len(),
        });
    }
    let len = u16::from_le_bytes([b[0], b[1]]) as usize;
    let end = (2 + len).min(b.len());
    Ok(String::from_utf8_lossy(&b[2..end]).into_owned())
}

/// 一个源条目。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceEntry {
    pub ip: Ipv4Addr,
    pub port: u16,
}

/// `0x42 FOUNDSOURCES` 的解析结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundSources {
    pub file_hash: [u8; 16],
    pub sources: Vec<SourceEntry>,
}

impl FoundSources {
    /// 载荷：`hash16 | count(1 字节) | count × (ID4 点分序 + PORT2 小端)`。
    ///
    /// **注意 count 是 1 字节**（不是 u32）——这点与 0x33 的结果集不同。
    pub fn decode(b: &[u8]) -> Result<FoundSources, PeerError> {
        let truncated = |need: usize, have: usize| PeerError::Truncated { need, have };
        if b.len() < 17 {
            return Err(truncated(17, b.len()));
        }
        let file_hash: [u8; 16] = b[0..16].try_into().unwrap();
        let count = b[16] as usize;
        let need = 17 + count * 6;
        if b.len() < need {
            return Err(truncated(need, b.len()));
        }
        let mut sources = Vec::with_capacity(count);
        for i in 0..count {
            let o = 17 + i * 6;
            sources.push(SourceEntry {
                ip: ip_from_dotted(&b[o..o + 4]),
                port: u16::from_le_bytes([b[o + 4], b[o + 5]]),
            });
        }
        Ok(FoundSources { file_hash, sources })
    }
}

/// `0x19 GETSOURCES` 请求载荷：`hash16 | filesize u32 LE`；
/// 大文件（> 4 GiB）用 `hash16 | 0u32 | filesize u64 LE`。
pub fn encode_get_sources(file_hash: &[u8; 16], file_size: u64) -> Vec<u8> {
    let mut v = file_hash.to_vec();
    if file_size > u32::MAX as u64 {
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&file_size.to_le_bytes());
    } else {
        v.extend_from_slice(&(file_size as u32).to_le_bytes());
    }
    v
}

/// `0x01 LOGINREQUEST` 的一个标签。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginTag {
    /// 字符串标签（短名 + 字符串）
    Str(u8, String),
    /// 整数标签（短名 + u32）
    Uint(u8, u32),
}

impl LoginTag {
    /// 编码：`type(1)`（短名位 `0x80` 置位） + 名称(1) + 值。
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::new();
        match self {
            LoginTag::Str(id, s) => {
                v.push(0x80 | 0x02);
                v.push(*id);
                v.extend_from_slice(&(s.len() as u16).to_le_bytes());
                v.extend_from_slice(s.as_bytes());
            }
            LoginTag::Uint(id, n) => {
                // 值 ≤0xFF 用 u8、≤0xFFFF 用 u16，否则 u32（与 eMule 自动降位宽一致）
                let ty = if *n <= 0xFF {
                    0x09
                } else if *n <= 0xFFFF {
                    0x08
                } else {
                    0x03
                };
                v.push(0x80 | ty);
                v.push(*id);
                match ty {
                    0x09 => v.push(*n as u8),
                    0x08 => v.extend_from_slice(&(*n as u16).to_le_bytes()),
                    _ => v.extend_from_slice(&n.to_le_bytes()),
                }
            }
        }
        v
    }
}

/// `0x01 LOGINREQUEST` 载荷：`hash16 | id u32(点分序) | port u16 | tagcount u32 | tags`。
pub fn encode_login(user_hash: &[u8; 16], client_id: u32, port: u16, tags: &[LoginTag]) -> Vec<u8> {
    let mut v = user_hash.to_vec();
    // client_id 在线上是点分序的 4 字节；内部按"点分序读出的 u32"保存，
    // 因此这里用 to_be_bytes 把它写回原始字节顺序。
    v.extend_from_slice(&client_id.to_be_bytes());
    v.extend_from_slice(&port.to_le_bytes());
    v.extend_from_slice(&(tags.len() as u32).to_le_bytes());
    for t in tags {
        v.extend_from_slice(&t.encode());
    }
    v
}

/// 构造一条服务器协议报文（协议字节恒为 `0xE3`）。
pub fn packet(opcode: u8, payload: Vec<u8>) -> Packet {
    Packet::new(Protocol::Edonkey, opcode, payload)
}

/// 客户端 UserHash：随机 16 字节 + 强制 `[5]=0x0E`、`[14]=0x6F`。
pub fn make_user_hash(mut seed: [u8; 16]) -> [u8; 16] {
    seed[5] = 0x0E;
    seed[14] = 0x6F;
    seed
}

/// 校验一个 UserHash 是否符合客户端特征。
pub fn is_client_user_hash(h: &[u8; 16]) -> bool {
    h[5] == 0x0E && h[14] == 0x6F
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idchange_is_length_driven() {
        // 最短：只有 CID
        let mut b = 0x0A000001u32.to_le_bytes().to_vec();
        let c = IdChange::decode(&b).unwrap();
        assert_eq!(c.client_id, 0x0A000001);
        assert!(c.tcp_flags.is_none() && c.public_ip.is_none());
        assert!(!c.is_low_id());

        // 8 字节：带 flags
        b.extend_from_slice(&(tcp_flags::LARGEFILES | tcp_flags::UNICODE).to_le_bytes());
        let c = IdChange::decode(&b).unwrap();
        assert_eq!(
            c.tcp_flags,
            Some(tcp_flags::LARGEFILES | tcp_flags::UNICODE)
        );
        assert!(c.public_ip.is_none());

        // 12 字节：+保留
        b.extend_from_slice(&7u32.to_le_bytes());
        let c = IdChange::decode(&b).unwrap();
        assert_eq!(c.reserved, Some(7));

        // 20 字节：+公网 IP +混淆端口
        b.extend_from_slice(&[85, 17, 116, 222]);
        b.extend_from_slice(&6082u32.to_le_bytes());
        let c = IdChange::decode(&b).unwrap();
        assert_eq!(c.public_ip, Some(Ipv4Addr::new(85, 17, 116, 222)));
        assert_eq!(c.obfuscation_port, Some(6082));

        // LowID 判定：最高字节为 0
        let low = IdChange::decode(&0x00FF_FFFFu32.to_le_bytes()).unwrap();
        assert!(low.is_low_id());
        let high = IdChange::decode(&0x0100_0000u32.to_le_bytes()).unwrap();
        assert!(!high.is_low_id());

        assert!(IdChange::decode(&[0, 0]).is_err());
    }

    #[test]
    fn found_sources_has_one_byte_count() {
        let mut b = [0xABu8; 16].to_vec();
        b.push(2); // count 是 1 字节
                   // 条目 1：85.17.116.222:6082
        b.extend_from_slice(&[85, 17, 116, 222]);
        b.extend_from_slice(&6082u16.to_le_bytes());
        // 条目 2：186.64.120.70:4232
        b.extend_from_slice(&[186, 64, 120, 70]);
        b.extend_from_slice(&4232u16.to_le_bytes());

        let fs = FoundSources::decode(&b).unwrap();
        assert_eq!(fs.file_hash, [0xABu8; 16]);
        assert_eq!(fs.sources.len(), 2);
        assert_eq!(fs.sources[0].ip, Ipv4Addr::new(85, 17, 116, 222));
        assert_eq!(fs.sources[0].port, 6082);
        assert_eq!(fs.sources[1].ip, Ipv4Addr::new(186, 64, 120, 70));
        assert_eq!(fs.sources[1].port, 4232);

        // 条目数说 2 却只给 1 条 → 截断
        let short = &b[..b.len() - 6];
        assert!(FoundSources::decode(short).is_err());
        // 连 count 都不够
        assert!(FoundSources::decode(&b[..10]).is_err());
    }

    #[test]
    fn get_sources_switches_to_u64_for_large_files() {
        let h = [0x11u8; 16];
        let small = encode_get_sources(&h, 1_000_000);
        assert_eq!(small.len(), 20, "hash16 + u32");
        assert_eq!(
            u32::from_le_bytes(small[16..20].try_into().unwrap()),
            1_000_000
        );

        let big = encode_get_sources(&h, 5_000_000_000);
        assert_eq!(big.len(), 28, "hash16 + 0u32 + u64");
        assert_eq!(u32::from_le_bytes(big[16..20].try_into().unwrap()), 0);
        assert_eq!(
            u64::from_le_bytes(big[20..28].try_into().unwrap()),
            5_000_000_000
        );
    }

    #[test]
    fn login_request_layout() {
        let hash = make_user_hash([0x5A; 16]);
        assert!(is_client_user_hash(&hash));
        assert_eq!(hash[5], 0x0E);
        assert_eq!(hash[14], 0x6F);

        let tags = vec![
            LoginTag::Str(0x01, "AIDM".into()),
            LoginTag::Uint(0x11, 0x3C),        // CT_VERSION
            LoginTag::Uint(0x20, 0x0000_0000), // SERVER_FLAGS
            LoginTag::Uint(0xFB, 0x0064_0000), // CT_EMULE_VERSION
        ];
        let p = encode_login(&hash, 0, 4662, &tags);
        assert_eq!(&p[0..16], &hash[..]);
        assert_eq!(&p[16..20], &[0, 0, 0, 0], "首登 ID 为 0");
        assert_eq!(u16::from_le_bytes(p[20..22].try_into().unwrap()), 4662);
        assert_eq!(u32::from_le_bytes(p[22..26].try_into().unwrap()), 4);

        // 标签编码：短名位、自动降位宽
        let s = LoginTag::Str(0x01, "AIDM".into()).encode();
        assert_eq!(s[0], 0x80 | 0x02);
        assert_eq!(s[1], 0x01);
        assert_eq!(u16::from_le_bytes(s[2..4].try_into().unwrap()), 4);
        assert_eq!(&s[4..], b"AIDM");

        let small = LoginTag::Uint(0x11, 0x3C).encode();
        assert_eq!(small[0], 0x80 | 0x09, "≤0xFF 用 u8");
        assert_eq!(small.len(), 3);

        let mid = LoginTag::Uint(0x11, 0x1234).encode();
        assert_eq!(mid[0], 0x80 | 0x08, "≤0xFFFF 用 u16");
        assert_eq!(mid.len(), 4);

        let big = LoginTag::Uint(0xFB, 0x0064_0000).encode();
        assert_eq!(big[0], 0x80 | 0x03, "否则 u32");
        assert_eq!(big.len(), 6);

        // 整条消息用统一分帧器能编解码
        let pkt = packet(op::LOGINREQUEST, p.clone());
        let enc = pkt.encode();
        assert_eq!(enc[0], 0xE3);
        assert_eq!(enc[5], op::LOGINREQUEST);
        let back = Packet::decode(&enc).unwrap();
        assert_eq!(back.payload, p);
    }

    #[test]
    fn server_status_and_message() {
        let mut b = 1234u32.to_le_bytes().to_vec();
        b.extend_from_slice(&5678u32.to_le_bytes());
        b.extend_from_slice(&[0xFF, 0xFF]); // 多余字节应被忽略
        let st = ServerStatus::decode(&b).unwrap();
        assert_eq!(st.users, 1234);
        assert_eq!(st.files, 5678);
        assert!(ServerStatus::decode(&b[..4]).is_err());

        let mut m = 5u16.to_le_bytes().to_vec();
        m.extend_from_slice(b"hello");
        m.extend_from_slice(b"trailing"); // 容忍尾部
        assert_eq!(decode_server_message(&m).unwrap(), "hello");
        assert!(decode_server_message(&[1]).is_err());
    }
}

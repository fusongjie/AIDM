//! eD2k（电驴）支持：链接解析 + 哈希校验。
//!
//! 这是 eD2k 支持的**基础层**（第一层）。网络层（eDonkey 服务器协议、eMule 对等
//! 协议、Kad）在其上分阶段实现，见 `docs/adr/0002-p2p-protocol-alignment.md`。
//!
//! 链接文法依据 eD2k URI scheme 的公开定义：
//!
//! | 形式 | 含义 |
//! |---|---|
//! | `ed2k://\|file\|<名>\|<字节>\|<MD4>\|/` | 文件链接 |
//! | `ed2k://\|file\|…\|/` 后接 `\|sources,<ip>:<port>[,…]\|/` | 附带已知源 |
//! | `ed2k://\|file\|…\|h=<BASE32>\|/` | 附带 AICH 根哈希 |
//! | `ed2k://\|server\|<ip>\|<port>\|/` | 服务器链接 |
//! | `ed2k://\|serverlist\|<url>\|/`、`\|nodeslist\|<url>\|/`、`\|friend\|<ip>\|<port>\|/` | 其它类型 |

pub mod aich;
pub mod credits;
pub mod hash;
/// Kad（eMule 的 Kademlia 变体）：节点身份、`nodes.dat` 解析、协议常量。
pub mod kad;
/// eMule 对等协议（L4）的线路编解码：报文框架 / 标签 / 握手 / 分片位图 / 分片收发 / 队列。
pub mod peer;
/// eDonkey/eMule **服务器协议**（L3）的消息编解码。
pub mod server;
/// `server.met`（eDonkey/eMule 服务器列表文件）解析。
pub mod server_met;
/// 共享文件注册表（L6 上传侧）：已完成的 eD2k 任务 + 分片哈希集缓存。
pub mod share;

pub use hash::{Ed2kDigest, Ed2kHasher, Flavor, Md4Hash, HASH_LEN, PART_SIZE};

/// 解析出的链接。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Link {
    /// 文件链接。
    File(FileLink),
    /// `ed2k://|server|ip|port|/`
    Server { host: String, port: u16 },
    /// `ed2k://|serverlist|url|/`
    ServerList { url: String },
    /// `ed2k://|nodeslist|url|/`（Kad 节点表）
    NodeList { url: String },
    /// `ed2k://|friend|ip|port|/`
    Friend { host: String, port: u16 },
}

/// 文件链接。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileLink {
    /// 文件名（保持链接里的原样；`%XX` 需用 [`FileLink::decoded_name`] 解）。
    pub name: String,
    /// 文件字节数。
    pub size: u64,
    /// 文件 eD2k 哈希（MD4）。
    pub hash: Md4Hash,
    /// 该哈希的小写十六进制形式（等价于链接里的那 32 个字符）。
    pub hash_hex: String,
    /// `sources,` 里附加的已知源。
    pub sources: Vec<(String, u16)>,
    /// `h=` 给出的 AICH 根哈希（Base32 原文）。
    pub aich_root: Option<String>,
}

impl FileLink {
    /// 链接里出现 `%XX` 时尝试百分号解码（best-effort，仅供显示/落盘命名）。
    pub fn decoded_name(&self) -> String {
        if !self.name.contains('%') {
            return self.name.clone();
        }
        let bytes = self.name.as_bytes();
        let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                if let (Some(hi), Some(lo)) = (hex_digit(bytes[i + 1]), hex_digit(bytes[i + 2])) {
                    let v = hi * 16 + lo;
                    out.push(v);
                    i += 3;
                    continue;
                }
            }
            out.push(bytes[i]);
            i += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    /// 重新生成规范化的文件链接（用于展示/复制）。
    pub fn to_link(&self) -> String {
        let mut s = format!(
            "ed2k://|file|{}|{}|{}|",
            self.name, self.size, self.hash_hex
        );
        if let Some(aich) = &self.aich_root {
            s.push_str(&format!("h={aich}|"));
        }
        if !self.sources.is_empty() {
            let list: Vec<String> = self
                .sources
                .iter()
                .map(|(h, p)| format!("{h}:{p}"))
                .collect();
            s.push_str(&format!("sources,{}|", list.join(",")));
        }
        s.push('/');
        s
    }
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// 解析失败的原因（机器码，可直接回给界面）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkError {
    /// 不是 `ed2k://` 链接。
    NotEd2k,
    /// 结构不对（缺少 token 等）。
    BadShape,
    /// 未知的链接类型。
    BadKind(String),
    /// 大小不是十进制数字。
    BadSize(String),
    /// 哈希不是 32 位十六进制。
    BadHash(String),
    /// AICH 根不是 32 位 RFC 4648 Base32。
    BadAich(String),
    /// 端口非法。
    BadPort(String),
    /// 文件名解析后为空。
    EmptyName,
}

impl LinkError {
    pub fn code(&self) -> &'static str {
        match self {
            LinkError::NotEd2k => "ed2k_not_link",
            LinkError::BadShape => "ed2k_bad_shape",
            LinkError::BadKind(_) => "ed2k_bad_kind",
            LinkError::BadSize(_) => "ed2k_bad_size",
            LinkError::BadHash(_) => "ed2k_bad_hash",
            LinkError::BadAich(_) => "ed2k_bad_aich",
            LinkError::BadPort(_) => "ed2k_bad_port",
            LinkError::EmptyName => "ed2k_empty_name",
        }
    }

    /// 面向用户的中文说明。
    pub fn message(&self) -> String {
        match self {
            LinkError::NotEd2k => "不是 ed2k 链接".into(),
            LinkError::BadShape => "ed2k 链接结构不完整".into(),
            LinkError::BadKind(k) => format!("不认识的 ed2k 链接类型：{k}"),
            LinkError::BadSize(s) => format!("ed2k 文件大小不是数字：{s}"),
            LinkError::BadHash(h) => format!("ed2k 哈希必须是 32 位十六进制，实际：{h}"),
            LinkError::BadAich(h) => format!("ed2k AICH 根必须是 32 位 Base32，实际：{h}"),
            LinkError::BadPort(p) => format!("ed2k 端口非法：{p}"),
            LinkError::EmptyName => "ed2k 链接里没有文件名".into(),
        }
    }
}

/// 是否 `ed2k://` 链接（大小写不敏感）。
pub fn is_ed2k_link(raw: &str) -> bool {
    raw.trim().to_ascii_lowercase().starts_with("ed2k://")
}

/// 解析 `ed2k://` 链接。
pub fn parse_link(raw: &str) -> Result<Link, LinkError> {
    let s = raw.trim();
    let lower = s.to_ascii_lowercase();
    if !lower.starts_with("ed2k://") {
        return Err(LinkError::NotEd2k);
    }
    let rest = &s["ed2k://".len()..];
    let tokens: Vec<&str> = rest.split('|').collect();
    // 典型结构：["", "file", 名, 大小, 哈希, "/", …]
    if tokens.len() < 3 {
        return Err(LinkError::BadShape);
    }
    let kind = tokens[1].trim().to_ascii_lowercase();
    match kind.as_str() {
        "file" => {
            if tokens.len() < 5 {
                return Err(LinkError::BadShape);
            }
            let name = tokens[2].to_string();
            if name.trim().is_empty() {
                return Err(LinkError::EmptyName);
            }
            let size_raw = tokens[3].trim();
            let size: u64 = size_raw
                .parse()
                .map_err(|_| LinkError::BadSize(size_raw.to_string()))?;
            let hash_raw = tokens[4].trim();
            let hash = hash::parse_hex(hash_raw)
                .ok_or_else(|| LinkError::BadHash(hash_raw.to_string()))?;
            let mut sources = Vec::new();
            let mut aich_root = None;
            for t in &tokens[5..] {
                let t = t.trim();
                if t.is_empty() || t == "/" {
                    continue;
                }
                let tl = t.to_ascii_lowercase();
                if let Some(list) = tl.strip_prefix("sources,") {
                    // 用原文切片，避免大小写转换破坏内容
                    let list = &t[t.len() - list.len()..];
                    for item in list.split(',') {
                        if let Some((h, p)) = parse_host_port(item) {
                            sources.push((h, p));
                        }
                    }
                } else if let Some(v) = t.strip_prefix("h=").or_else(|| t.strip_prefix("H=")) {
                    let v = v.trim();
                    if !v.is_empty() {
                        aich::decode_base32(v).ok_or_else(|| LinkError::BadAich(v.to_string()))?;
                        aich_root = Some(v.to_ascii_uppercase());
                    }
                }
                // 其它参数（如 p=…）当前忽略，不报错：保持宽容
            }
            Ok(Link::File(FileLink {
                name,
                size,
                hash,
                hash_hex: hash::hex(&hash),
                sources,
                aich_root,
            }))
        }
        "server" | "friend" => {
            if tokens.len() < 4 {
                return Err(LinkError::BadShape);
            }
            let host = tokens[2].trim().to_string();
            let port_raw = tokens[3].trim();
            let port: u16 = port_raw
                .parse()
                .map_err(|_| LinkError::BadPort(port_raw.to_string()))?;
            if host.is_empty() || port == 0 {
                return Err(LinkError::BadPort(port_raw.to_string()));
            }
            Ok(if kind == "server" {
                Link::Server { host, port }
            } else {
                Link::Friend { host, port }
            })
        }
        "serverlist" | "nodeslist" => {
            if tokens.len() < 3 {
                return Err(LinkError::BadShape);
            }
            let url = tokens[2].trim().to_string();
            if url.is_empty() {
                return Err(LinkError::BadShape);
            }
            Ok(if kind == "serverlist" {
                Link::ServerList { url }
            } else {
                Link::NodeList { url }
            })
        }
        other => Err(LinkError::BadKind(other.to_string())),
    }
}

/// `ip:port` / `[v6]:port` / `host:port`。
fn parse_host_port(s: &str) -> Option<(String, u16)> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    if let Some(rest) = t.strip_prefix('[') {
        let (h, p) = rest.split_once(']')?;
        let p = p.strip_prefix(':')?;
        return Some((h.to_string(), p.trim().parse().ok()?));
    }
    let (h, p) = t.rsplit_once(':')?;
    if h.is_empty() {
        return None;
    }
    Some((h.to_string(), p.trim().parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    const WIKI_FILE: &str = "ed2k://|file|The_Two_Towers-The_Purist_Edit-Trailer.avi|14997504|965c013e991ee246d63d45ea71954c4d|/";
    const WIKI_SOURCES: &str = "ed2k://|file|The_Two_Towers-The_Purist_Edit-Trailer.avi|14997504|965c013e991ee246d63d45ea71954c4d|/|sources,202.89.123.6:4662|/";
    const WIKI_AICH: &str = "ed2k://|file|The_Two_Towers-The_Purist_Edit-Trailer.avi|14997504|965c013e991ee246d63d45ea71954c4d|h=H52BRVWPBBTAED5NXQDH2RJDDAKRUWST|/";
    const WIKI_SERVER: &str = "ed2k://|server|207.44.222.51|4242|/";

    #[test]
    fn parses_wikipedia_file_link() {
        let l = parse_link(WIKI_FILE).unwrap();
        let Link::File(f) = l else {
            panic!("应为文件链接")
        };
        assert_eq!(f.name, "The_Two_Towers-The_Purist_Edit-Trailer.avi");
        assert_eq!(f.size, 14_997_504);
        assert_eq!(f.hash_hex, "965c013e991ee246d63d45ea71954c4d");
        assert_eq!(f.hash.len(), 16);
        assert!(f.sources.is_empty());
        assert!(f.aich_root.is_none());
        // 回写应是同一串（规范化后）
        assert_eq!(f.to_link(), WIKI_FILE);
    }

    #[test]
    fn parses_sources_and_aich() {
        let Link::File(f) = parse_link(WIKI_SOURCES).unwrap() else {
            panic!("应为文件链接")
        };
        assert_eq!(f.sources, vec![("202.89.123.6".to_string(), 4662)]);

        let Link::File(f2) = parse_link(WIKI_AICH).unwrap() else {
            panic!("应为文件链接")
        };
        assert_eq!(
            f2.aich_root.as_deref(),
            Some("H52BRVWPBBTAED5NXQDH2RJDDAKRUWST")
        );
        assert!(f2.to_link().contains("h=H52BRVWPBBTAED5NXQDH2RJDDAKRUWST|"));
        assert!(matches!(
            parse_link("ed2k://|file|a.bin|1|965c013e991ee246d63d45ea71954c4d|h=INVALID|/"),
            Err(LinkError::BadAich(_))
        ));
    }

    #[test]
    fn parses_server_and_other_kinds() {
        assert_eq!(
            parse_link(WIKI_SERVER).unwrap(),
            Link::Server {
                host: "207.44.222.51".into(),
                port: 4242
            }
        );
        assert_eq!(
            parse_link("ed2k://|serverlist|http://x/servers.met|/").unwrap(),
            Link::ServerList {
                url: "http://x/servers.met".into()
            }
        );
        assert_eq!(
            parse_link("ed2k://|nodeslist|http://x/nodes.dat|/").unwrap(),
            Link::NodeList {
                url: "http://x/nodes.dat".into()
            }
        );
        assert_eq!(
            parse_link("ed2k://|friend|1.2.3.4|4662|/").unwrap(),
            Link::Friend {
                host: "1.2.3.4".into(),
                port: 4662
            }
        );
    }

    #[test]
    fn multiple_sources_and_ipv6_source() {
        let raw = "ed2k://|file|a.bin|100|965c013e991ee246d63d45ea71954c4d|/|sources,1.2.3.4:4662,[::1]:4662,5.6.7.8:5000|/";
        let Link::File(f) = parse_link(raw).unwrap() else {
            panic!()
        };
        assert_eq!(
            f.sources,
            vec![
                ("1.2.3.4".to_string(), 4662),
                ("::1".to_string(), 4662),
                ("5.6.7.8".to_string(), 5000),
            ]
        );
    }

    #[test]
    fn rejects_bad_links_with_typed_errors() {
        assert_eq!(parse_link("http://x/a").unwrap_err(), LinkError::NotEd2k);
        assert_eq!(
            parse_link("ed2k://|file|").unwrap_err(),
            LinkError::BadShape
        );
        assert_eq!(
            parse_link("ed2k://|file||1|965c013e991ee246d63d45ea71954c4d|/").unwrap_err(),
            LinkError::EmptyName
        );
        assert_eq!(
            parse_link("ed2k://|file|a.bin|abc|965c013e991ee246d63d45ea71954c4d|/").unwrap_err(),
            LinkError::BadSize("abc".into())
        );
        assert_eq!(
            parse_link("ed2k://|file|a.bin|100|zzz|/").unwrap_err(),
            LinkError::BadHash("zzz".into())
        );
        assert_eq!(
            parse_link("ed2k://|server|1.2.3.4|0|/").unwrap_err(),
            LinkError::BadPort("0".into())
        );
        assert_eq!(
            parse_link("ed2k://|nonsense|a|b|/").unwrap_err(),
            LinkError::BadKind("nonsense".into())
        );
        // 每种错误都有机器码与中文说明
        for e in [
            LinkError::NotEd2k,
            LinkError::BadShape,
            LinkError::BadKind("x".into()),
            LinkError::BadSize("x".into()),
            LinkError::BadHash("x".into()),
            LinkError::BadPort("x".into()),
            LinkError::EmptyName,
        ] {
            assert!(e.code().starts_with("ed2k_"));
            assert!(!e.message().is_empty());
        }
    }

    #[test]
    fn case_insensitive_scheme_and_hash() {
        let raw = "ED2K://|file|A.BIN|100|965C013E991EE246D63D45EA71954C4D|/";
        assert!(is_ed2k_link(raw));
        let Link::File(f) = parse_link(raw).unwrap() else {
            panic!()
        };
        assert_eq!(
            f.hash_hex, "965c013e991ee246d63d45ea71954c4d",
            "哈希应归一为小写"
        );
        assert_eq!(f.name, "A.BIN");
    }

    #[test]
    fn percent_encoded_names_are_decoded_best_effort() {
        let raw = "ed2k://|file|My%20File%20%E4%B8%AD.bin|100|965c013e991ee246d63d45ea71954c4d|/";
        let Link::File(f) = parse_link(raw).unwrap() else {
            panic!()
        };
        assert_eq!(f.name, "My%20File%20%E4%B8%AD.bin", "原始名保持不动");
        assert_eq!(f.decoded_name(), "My File 中.bin");
        // 没有百分号时原样返回
        let plain = FileLink {
            name: "a.bin".into(),
            size: 1,
            hash: [0u8; 16],
            hash_hex: "0".repeat(32),
            sources: vec![],
            aich_root: None,
        };
        assert_eq!(plain.decoded_name(), "a.bin");
        let mut malformed = plain;
        malformed.name = "%中%20文件.bin".into();
        assert_eq!(malformed.decoded_name(), "%中 文件.bin");
    }
}

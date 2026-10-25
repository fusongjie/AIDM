//! Kad（eMule 的 Kademlia 变体）基础层。
//!
//! 本模块目前覆盖 **L5 的可离线验证部分**：节点身份（128-bit ID 与 XOR 距离）、
//! `nodes.dat` 解析、以及协议常量。UDP 收发与查找状态机在其上继续实现。
//!
//! ## 规范来源
//!
//! `nodes.dat` 与常量取自 eMule 源码 / aMule 文档，并经**真实文件逐字节验证**：
//!
//! | 项 | 出处 |
//! |---|---|
//! | `nodes.dat` v2 布局 | eMule `RoutingZone.cpp`；aMule `file-formats/nodes-dat` |
//! | UDP key 语义（`GetKeyValue(myIP)` 仅在 IP 匹配时有效） | eMule `KadUDPKey.h` |
//! | 版本常量 `KADEMLIA_VERSION` | eMule `opcodes.h` |
//!
//! 实测样本 `crates/aidm-core/tests/fixtures/ed2k/nodes.dat`（采集自公开节点列表）：
//! 6,234 B = 12 + 183×34，`version=2`、`count=183`、kadVer 分布 `7×1 / 8×121 / 9×30 / 10×31`。
//!
//! ## 已知陷阱（都是实测踩过的）
//!
//! - **IP 字段是小端**：`E5 5E 04 DE` → `222.4.94.229`（需反序读）。
//! - **ID 字段是原始字节序**：等于线上字节序，不要做端序转换。
//! - **UDP key 绑定"写文件者自己的公网 IP"**：换台机器/换公网 IP 后这些 key 全部失效，
//!   必须重新验证。实测样本里绝大多数记录的 keyIP 是同一个值（个别不同，见测试）。

pub mod store;

use std::net::Ipv4Addr;

/// 我们对外广播的 Kad 版本（eMule 0.50a）。
///
/// 实测网络里已有 v10 节点，但 eMule 源码只定义到 9 且 v10 语义未确认，
/// 所以**广播 9、接受 ≥6**，不主动使用 v10 专属特性。
pub const KADEMLIA_VERSION: u8 = 9;
/// 低于此版本的对端不参与现代 Kad 交互。
pub const MIN_ACCEPTED_VERSION: u8 = 6;

/// 路由表 k 桶大小。
pub const K: usize = 10;
/// 桶分裂基准。
pub const KBASE: usize = 4;
/// 并发查询数（alpha）。
pub const ALPHA_QUERY: usize = 3;
/// 收敛容差。
pub const SEARCH_TOLERANCE: u64 = 16_777_216;
/// 握手超时。
pub const HELLO_TIMEOUT_SECS: u64 = 20;
/// 单次搜源生命周期（秒）。
pub const SEARCH_FIND_SOURCE_LIFETIME_SECS: u64 = 45;
/// 单次搜源最多询问的节点数。
pub const SEARCH_FIND_SOURCE_TOTAL: usize = 20;
/// 源在索引里的存活/刷新周期（秒）：5 小时。
pub const REPUBLISH_SOURCE_SECS: u64 = 5 * 3600;
/// 关键字在索引里的存活/刷新周期（秒）：24 小时。
pub const REPUBLISH_KEYWORD_SECS: u64 = 24 * 3600;

/// 128-bit Kad 节点/资源 ID。
///
/// 线上字节序就是存储顺序（不要端序转换），因此 `Ord` 与 `Xor` 距离都按字节做。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KadId(pub [u8; 16]);

impl KadId {
    pub const ZERO: KadId = KadId([0u8; 16]);

    pub fn from_slice(b: &[u8]) -> Option<Self> {
        let arr: [u8; 16] = b.get(..16)?.try_into().ok()?;
        Some(KadId(arr))
    }

    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|b| *b == 0)
    }

    /// XOR 距离（Kademlia 度量）。
    pub fn distance(&self, other: &KadId) -> [u8; 16] {
        let mut out = [0u8; 16];
        for i in 0..16 {
            out[i] = self.0[i] ^ other.0[i];
        }
        out
    }

    /// 距离的高位前导零个数（用于桶索引），16 字节全同则返回 128。
    pub fn common_prefix_bits(&self, other: &KadId) -> u32 {
        let mut bits = 0u32;
        for i in 0..16 {
            let x = self.0[i] ^ other.0[i];
            if x == 0 {
                bits += 8;
                continue;
            }
            bits += x.leading_zeros();
            return bits;
        }
        bits
    }

    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// XOR 距离比较：`a` 到 `target` 是否比 `b` 更近。
pub fn closer(target: &KadId, a: &KadId, b: &KadId) -> bool {
    target.distance(a) < target.distance(b)
}

/// `nodes.dat` 里的一个节点。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KadNode {
    pub id: KadId,
    pub ip: Ipv4Addr,
    pub udp_port: u16,
    pub tcp_port: u16,
    /// Kad 协议版本；v1 及更早（≤1）读取时按规范忽略。
    pub version: u8,
    /// v2 才有：KadUDPKey。
    pub udp_key: Option<u32>,
    /// v2 才有：该 key 绑定的 IP（= 写文件者的公网 IP）。
    pub key_ip: Option<Ipv4Addr>,
    /// v2 才有：已验证。
    pub verified: bool,
}

impl KadNode {
    /// 该节点的 UDP key 在我方公网 IP 下是否可用。
    ///
    /// 规范：`GetKeyValue(myIP) = (myIP == key_ip) ? key : 0`。所以别人
    /// `nodes.dat` 里的 key 对我们**基本都不可用**，必须重新验证。
    pub fn udp_key_for(&self, my_ip: Ipv4Addr) -> u32 {
        match (self.udp_key, self.key_ip) {
            (Some(k), Some(ip)) if ip == my_ip => k,
            _ => 0,
        }
    }
}

/// 解析失败原因。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KadError {
    /// 文件短于最小长度。
    TooShort,
    /// 版本不认识（高于 3）。
    UnsupportedVersion(u32),
    /// 长度与计数不吻合（**fail closed**：宁可拒绝也不猜边界）。
    LengthMismatch { expected: usize, actual: usize },
    /// 节点数超过上限。
    TooManyNodes(u32),
    /// 记录字段非法（IP/端口全零等）。
    BadRecord(usize),
}

impl KadError {
    pub fn code(&self) -> &'static str {
        match self {
            KadError::TooShort => "kad_nodes_too_short",
            KadError::UnsupportedVersion(_) => "kad_nodes_version",
            KadError::LengthMismatch { .. } => "kad_nodes_length",
            KadError::TooManyNodes(_) => "kad_nodes_too_many",
            KadError::BadRecord(_) => "kad_nodes_bad_record",
        }
    }

    pub fn message(&self) -> String {
        match self {
            KadError::TooShort => "nodes.dat 太短".into(),
            KadError::UnsupportedVersion(v) => format!("不支持的 nodes.dat 版本：{v}"),
            KadError::LengthMismatch { expected, actual } => {
                format!("nodes.dat 长度与计数不符：期望 {expected}，实际 {actual}")
            }
            KadError::TooManyNodes(n) => format!("nodes.dat 节点数过多：{n}"),
            KadError::BadRecord(i) => format!("nodes.dat 第 {i} 条记录非法"),
        }
    }
}

/// 规范里的实际上限。
pub const MAX_NODES: u32 = 5000;

/// IP 字段是小端存储：
fn ip_from_le(b: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(b[3], b[2], b[1], b[0])
}

fn u16_le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

fn u32_le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// 解析一条 25 字节记录（v0/v1/v3）。
fn parse_record_short(b: &[u8], off: usize, idx: usize) -> Result<KadNode, KadError> {
    let id = KadId::from_slice(&b[off..off + 16]).ok_or(KadError::BadRecord(idx))?;
    let ip = ip_from_le(&b[off + 16..off + 20]);
    let udp_port = u16_le(b, off + 20);
    let tcp_port = u16_le(b, off + 22);
    let version = b[off + 24];
    if ip.is_unspecified() {
        return Err(KadError::BadRecord(idx));
    }
    Ok(KadNode {
        id,
        ip,
        udp_port,
        tcp_port,
        version,
        udp_key: None,
        key_ip: None,
        verified: false,
    })
}

/// 解析一条 34 字节记录（v2）。
fn parse_record_long(b: &[u8], off: usize, idx: usize) -> Result<KadNode, KadError> {
    let mut n = parse_record_short(b, off, idx)?;
    n.udp_key = Some(u32_le(b, off + 25));
    n.key_ip = Some(ip_from_le(&b[off + 29..off + 33]));
    n.verified = b[off + 33] != 0;
    Ok(n)
}

/// 解析 `nodes.dat`。
///
/// 支持 v0（无头、25B 记录）、v1（12B 头、25B 记录）、v2（12B 头、34B 记录）、
/// v3（16B 头、25B 记录）。**长度必须与计数严格吻合**，否则拒绝 —— 边界一错，
/// 后面 180 条记录全是垃圾，不如直接失败。
pub fn parse_nodes_dat(b: &[u8]) -> Result<Vec<KadNode>, KadError> {
    if b.len() < 8 {
        return Err(KadError::TooShort);
    }
    // v3：头部是 `00000000 03000000 01000000 <count>`
    if b.len() >= 16 && u32_le(b, 0) == 0 && u32_le(b, 4) == 3 {
        let edition = u32_le(b, 8);
        let count = u32_le(b, 12);
        if edition != 1 {
            return Err(KadError::UnsupportedVersion(3));
        }
        return parse_records(b, 16, count, 25, false);
    }
    // v1/v2：`00000000 <version> <count>`
    let version = u32_le(b, 4);
    let count = u32_le(b, 8);
    match version {
        1 => parse_records(b, 12, count, 25, false),
        2 => parse_records(b, 12, count, 34, true),
        0 => {
            // v0：文件直接以 count 开头，无版本头
            let count = u32_le(b, 0);
            parse_records(b, 4, count, 25, false)
        }
        other => Err(KadError::UnsupportedVersion(other)),
    }
}

fn parse_records(
    b: &[u8],
    header: usize,
    count: u32,
    rec: usize,
    long: bool,
) -> Result<Vec<KadNode>, KadError> {
    if count > MAX_NODES {
        return Err(KadError::TooManyNodes(count));
    }
    let expected = header + count as usize * rec;
    if expected != b.len() {
        return Err(KadError::LengthMismatch {
            expected,
            actual: b.len(),
        });
    }
    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let off = header + i * rec;
        let node = if long {
            parse_record_long(b, off, i)?
        } else {
            parse_record_short(b, off, i)?
        };
        out.push(node);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 真实样本（采集自 upd.emule-security.org，见 fixtures/ed2k/README.md）。
    fn real_nodes_dat() -> Vec<u8> {
        let p =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ed2k/nodes.dat");
        std::fs::read(&p).unwrap_or_else(|e| panic!("读取夹具失败 {}: {e}", p.display()))
    }

    /// 黄金样本：结构、计数、版本分布、IP 唯一性逐项对齐实测值。
    #[test]
    fn parses_real_nodes_dat_fixture() {
        let b = real_nodes_dat();
        assert_eq!(b.len(), 6234, "夹具长度应为 6234");
        assert_eq!(&b[0..4], &[0, 0, 0, 0], "头 4 字节应为空标记");
        assert_eq!(u32_le(&b, 4), 2, "版本应为 2");
        assert_eq!(u32_le(&b, 8), 183, "计数应为 183");

        let nodes = parse_nodes_dat(&b).expect("应能解析真实文件");
        assert_eq!(nodes.len(), 183);

        // kadVer 分布（实测：7×1 / 8×121 / 9×30 / 10×31）——这条断言等价于
        // 校验了全部 183 条记录的**边界对齐**：错 1 字节就会全乱。
        let mut dist = std::collections::BTreeMap::new();
        for n in &nodes {
            *dist.entry(n.version).or_insert(0usize) += 1;
        }
        assert_eq!(dist.get(&7).copied(), Some(1));
        assert_eq!(dist.get(&8).copied(), Some(121));
        assert_eq!(dist.get(&9).copied(), Some(30));
        assert_eq!(dist.get(&10).copied(), Some(31));

        // IP 各不相同、非 0；端口合理；ID 非全零
        let ips: std::collections::HashSet<_> = nodes.iter().map(|n| n.ip).collect();
        assert_eq!(ips.len(), 183, "183 条记录应有 183 个不同 IP");
        for (i, n) in nodes.iter().enumerate() {
            assert!(!n.ip.is_unspecified(), "第 {i} 条 IP 不应为 0.0.0.0");
            assert!(n.tcp_port > 0, "第 {i} 条 TCP 端口应为正");
            assert!(!n.id.is_zero(), "第 {i} 条 ID 不应全零");
        }

        // v2 才有 key/verified，应全部存在
        assert!(nodes.iter().all(|n| n.udp_key.is_some()));
        assert!(nodes.iter().all(|n| n.key_ip.is_some()));

        // keyIP 语义：规范说"绑定写文件者的公网 IP"。研究员称 183 条全同，
        // 但独立统计发现样本里有 **2 个**不同值 —— 这里按实测断言，
        // 并钉住"绝大多数为同一个值"这一可复现事实。
        let key_ips: std::collections::HashMap<Ipv4Addr, usize> = nodes
            .iter()
            .filter_map(|n| n.key_ip)
            .fold(std::collections::HashMap::new(), |mut m, ip| {
                *m.entry(ip).or_insert(0usize) += 1;
                m
            });
        assert!(
            key_ips.len() <= 2,
            "keyIP 的种类应很少（实测 ≤2），实际 {key_ips:?}"
        );
        let dominant = key_ips.values().copied().max().unwrap_or(0);
        assert!(
            dominant >= 180,
            "应绝大多数记录共享同一个 keyIP，实际分布 {key_ips:?}"
        );
    }

    /// keyIP 不同则 key 不可用（规范的 `GetKeyValue(myIP)` 语义）。
    #[test]
    fn udp_key_is_only_valid_for_matching_public_ip() {
        let node = KadNode {
            id: KadId([1u8; 16]),
            ip: Ipv4Addr::new(1, 2, 3, 4),
            udp_port: 4672,
            tcp_port: 4662,
            version: 9,
            udp_key: Some(0xDEADBEEF),
            key_ip: Some(Ipv4Addr::new(206, 221, 226, 91)),
            verified: true,
        };
        assert_eq!(
            node.udp_key_for(Ipv4Addr::new(206, 221, 226, 91)),
            0xDEADBEEF
        );
        assert_eq!(
            node.udp_key_for(Ipv4Addr::new(8, 8, 8, 8)),
            0,
            "IP 不匹配时 key 必须为 0"
        );
    }

    /// v1（12B 头 + 25B 记录）与 v3（16B 头 + 25B 记录）都要能解析。
    #[test]
    fn parses_v1_and_v3_layouts() {
        // v1：一条记录
        let mut v1 = vec![0u8, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0];
        v1.extend_from_slice(&[0xAA; 16]); // id
        v1.extend_from_slice(&[4, 3, 2, 1]); // ip 小端 → 1.2.3.4
        v1.extend_from_slice(&4672u16.to_le_bytes());
        v1.extend_from_slice(&4662u16.to_le_bytes());
        v1.push(8);
        let n = parse_nodes_dat(&v1).unwrap();
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].ip, Ipv4Addr::new(1, 2, 3, 4), "IP 需反序读出");
        assert_eq!(n[0].udp_port, 4672);
        assert_eq!(n[0].tcp_port, 4662);
        assert_eq!(n[0].version, 8);
        assert_eq!(n[0].udp_key, None, "v1 无 key");

        // v3：16B 头（0 / 3 / edition=1 / count）
        let mut v3 = vec![0u8, 0, 0, 0, 3, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0];
        v3.extend_from_slice(&[0xBB; 16]);
        v3.extend_from_slice(&[9, 8, 7, 6]);
        v3.extend_from_slice(&1000u16.to_le_bytes());
        v3.extend_from_slice(&2000u16.to_le_bytes());
        v3.push(9);
        let n = parse_nodes_dat(&v3).unwrap();
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].ip, Ipv4Addr::new(6, 7, 8, 9));
        assert_eq!(n[0].tcp_port, 2000);
    }

    /// 长度/版本不符必须 fail closed，而不是猜着往后读。
    #[test]
    fn rejects_inconsistent_or_unsupported_files() {
        let mut b = real_nodes_dat();
        // 少 1 字节 → 长度与计数不符
        b.pop();
        assert!(matches!(
            parse_nodes_dat(&b),
            Err(KadError::LengthMismatch { .. })
        ));

        let mut b2 = real_nodes_dat();
        b2[4] = 9; // 版本 9：不存在
        assert!(matches!(
            parse_nodes_dat(&b2),
            Err(KadError::UnsupportedVersion(9))
        ));

        assert!(matches!(
            parse_nodes_dat(&[0, 1, 2]),
            Err(KadError::TooShort)
        ));

        // 计数超上限
        let mut b3 = real_nodes_dat();
        b3[8..12].copy_from_slice(&6000u32.to_le_bytes());
        assert!(matches!(
            parse_nodes_dat(&b3),
            Err(KadError::TooManyNodes(6000))
        ));

        // 全零 IP 的记录视为非法
        let mut v1 = vec![0u8, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0];
        v1.extend_from_slice(&[0xCC; 16]);
        v1.extend_from_slice(&[0, 0, 0, 0]);
        v1.extend_from_slice(&0u16.to_le_bytes());
        v1.extend_from_slice(&0u16.to_le_bytes());
        v1.push(8);
        assert!(matches!(parse_nodes_dat(&v1), Err(KadError::BadRecord(0))));

        // 每个错误码都有机器码与中文说明
        for e in [
            KadError::TooShort,
            KadError::UnsupportedVersion(9),
            KadError::LengthMismatch {
                expected: 1,
                actual: 2,
            },
            KadError::TooManyNodes(1),
            KadError::BadRecord(0),
        ] {
            assert!(e.code().starts_with("kad_"));
            assert!(!e.message().is_empty());
        }
    }

    /// XOR 距离的性质：自距为 0、对称、前缀位数用于分桶。
    #[test]
    fn xor_distance_metric() {
        let a = KadId([0u8; 16]);
        let mut b = [0u8; 16];
        b[0] = 0b1000_0000;
        let b = KadId(b);
        let mut c = [0u8; 16];
        c[0] = 0b0000_0001;
        let c = KadId(c);

        assert_eq!(a.distance(&a), [0u8; 16]);
        assert_eq!(a.distance(&b), b.distance(&a), "距离应对称");
        assert_eq!(a.common_prefix_bits(&a), 128);
        assert_eq!(a.common_prefix_bits(&b), 0, "首位就不同");

        // b 比 c 更近吗？按字节大端比较，0x80 < ... 这里 c 的字节值更小
        assert!(closer(&a, &c, &b), "0x01 距离小于 0x80");
        assert!(!closer(&a, &b, &c));

        // 前缀位数：前 2 字节相同 → 16 位
        let mut d = [0u8; 16];
        d[2] = 0xFF;
        assert_eq!(a.common_prefix_bits(&KadId(d)), 16);

        assert_eq!(KadId([0; 16]).to_hex().len(), 32);
        assert!(KadId([0; 16]).is_zero());
    }
}

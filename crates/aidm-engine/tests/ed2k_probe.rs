//! 真实网络探测（默认忽略；用 `cargo test --test ed2k_probe -- --ignored --nocapture` 手动跑）。
//!
//! 目的有三个：
//! 1. **复核 nodes.dat 的 IP 字节序**：结论已由 eMule 源码与公网 Kad 应答钉死为
//!    little-endian u32；这里比较解析结果与错误的“点分序原样”解释，防止回归。
//! 2. 顺带验证我们的对等协议编解码能被**真实 eMule 客户端**接受（能收到 HELLOANSWER）。
//! 3. 用夹具里的真实 `server.met` 逐台登录查源，验证公网查源链路与具体文件有无源。

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

fn nodes_dat() -> Vec<u8> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../aidm-core/tests/fixtures/ed2k/nodes.dat");
    std::fs::read(&p).unwrap_or_else(|e| panic!("读取 nodes.dat 失败 {}: {e}", p.display()))
}

fn reverse(ip: Ipv4Addr) -> Ipv4Addr {
    let o = ip.octets();
    Ipv4Addr::new(o[3], o[2], o[1], o[0])
}

#[test]
#[ignore = "需要真实网络；手动运行以复核 nodes.dat 字节序"]
fn probe_real_nodes_byte_order() {
    let bytes = nodes_dat();
    let nodes = aidm_core::ed2k::kad::parse_nodes_dat(&bytes).expect("解析 nodes.dat");
    println!("nodes.dat 解析到 {} 个节点", nodes.len());

    let connect = Duration::from_secs(3);
    let read = Duration::from_secs(3);
    let mut parsed_ok = 0;
    let mut wrong_order_ok = 0;
    let mut parsed_tcp = 0;
    let mut wrong_order_tcp = 0;
    let mut tried = 0;

    // 只探前 40 个有 TCP 端口的节点，控制耗时
    for n in nodes.iter().filter(|n| n.tcp_port > 0).take(40) {
        tried += 1;
        for (label, ip) in [("parsed_le", n.ip), ("wrong_dotted", reverse(n.ip))] {
            let addr = SocketAddr::new(IpAddr::V4(ip), n.tcp_port);
            // 先看 TCP 能不能连上（弱证据）
            let tcp_ok = std::net::TcpStream::connect_timeout(&addr, connect).is_ok();
            if tcp_ok {
                if label == "parsed_le" {
                    parsed_tcp += 1;
                } else {
                    wrong_order_tcp += 1;
                }
            }
            // 再试着完成 HELLO 交换（强证据）
            if let Ok(info) = aidm_engine::ed2k::peer_session::probe_peer(addr, connect, read) {
                println!(
                    "  [{label}] {ip}:{} HELLOANSWER 成功，对端哈希 {}…{} 端口 {} 标签 {} 个",
                    n.tcp_port,
                    info.user_hash[0],
                    info.user_hash[15],
                    info.tcp_port,
                    info.tags.len()
                );
                if label == "parsed_le" {
                    parsed_ok += 1;
                } else {
                    wrong_order_ok += 1;
                }
            }
        }
    }
    println!(
        "探测 {tried} 个节点：parsed_le → TCP {parsed_tcp} / HELLO {parsed_ok}；wrong_dotted → TCP {wrong_order_tcp} / HELLO {wrong_order_ok}"
    );
    assert!(
        parsed_ok > 0 || wrong_order_ok > 0,
        "两种解释都没探到可用对等点：可能是出网受限（本环境历史上到 6082/4725 无字节返回）"
    );
    assert!(
        parsed_ok >= wrong_order_ok,
        "错误的点分序解释反而命中更多（parsed_le {parsed_ok} < wrong_dotted {wrong_order_ok}）"
    );
}

/// Kad 通道实测：对 ISO 哈希做一次完整搜源，看能回多少可用源。
/// 用于判断"连接数上不去"是不是缺源，以及缺的是哪条通道。
#[test]
#[ignore = "需要真实网络；手动运行"]
fn probe_iso_sources_via_kad() {
    let hash: [u8; 16] = aidm_core::ed2k::hash::parse_hex("E7C526499308841A4A6D116C857DB669")
        .expect("用例哈希应合法");
    let seeds = aidm_engine::ed2k::kad_session::default_bootstrap_nodes().expect("种子节点");
    println!("种子 {} 个，开始 60 秒搜源", seeds.len());
    let r = aidm_engine::ed2k::kad_session::lookup_sources(&hash, 4_478_906_368, &seeds, || false)
        .expect("搜源不应抛错");
    println!(
        "bootstrap {}/{} lookup {}/{} source {}/{} → 源 {} 个（略过回调 {} 加密 {}，畸形 {} 不支持 {}）耗时 {:?}",
        r.bootstrap_replies,
        r.bootstrap_sent,
        r.lookup_replies,
        r.lookup_sent,
        r.source_replies,
        r.source_sent,
        r.sources.len(),
        r.skipped_callback_sources,
        r.skipped_crypto_sources,
        r.malformed_packets,
        r.unsupported_packets,
        r.elapsed,
    );
    for s in r.sources.iter().take(20) {
        println!(
            "  {}:{} type={} crypt={}",
            s.ip, s.port, s.source_type, s.crypt_options
        );
    }
}

/// 真实案例探测：`cn_windows_10_enterprise_ltsc_2019_x64_dvd`（4_478_906_368 B）
/// 能否在公网 eD2k 服务器上查到源。只做"登录→查源"，不下载。
/// 每份 server.met 只探前 8 台（先 3s TCP 预检，死的直接跳过，控制总耗时）。
#[test]
#[ignore = "需要真实网络；手动运行"]
fn probe_iso_sources_on_public_servers() {
    use aidm_engine::ed2k::server_session::{ServerSession, ServerSessionCfg};

    let hash: [u8; 16] = aidm_core::ed2k::hash::parse_hex("E7C526499308841A4A6D116C857DB669")
        .expect("用例哈希应合法");
    let size = 4_478_906_368u64;
    let user_hash = aidm_engine::ed2k::peer_session::client_hash();

    for file in ["emule-security-server.met", "gruk-server.met"] {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../aidm-core/tests/fixtures/ed2k")
            .join(file);
        let bytes = std::fs::read(&p).unwrap_or_else(|e| panic!("读取 {file} 失败: {e}"));
        let list = aidm_core::ed2k::server_met::parse(&bytes).expect("解析 server.met");
        println!("{file}: {} 台，取前 8 台探测", list.servers.len());
        for s in list.servers.iter().take(8) {
            let addr = SocketAddr::new(IpAddr::V4(s.ip), s.port);
            // TCP 预检：死的服务器 3 秒跳过，不进 20 秒的登录等待
            if std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(3)).is_err() {
                println!(
                    "  {}:{} {} TCP 不通，跳过",
                    s.ip,
                    s.port,
                    s.name.as_deref().unwrap_or("?")
                );
                continue;
            }
            let cfg = ServerSessionCfg {
                addr,
                user_hash,
                listen_port: 0,
                nickname: "AIDM",
                connect_timeout: Duration::from_secs(4),
                read_timeout: Duration::from_secs(4),
            };
            let mut sess = match ServerSession::connect(&cfg) {
                Ok(x) => x,
                Err(e) => {
                    println!("  {}:{} 连接失败: {e}", s.ip, s.port);
                    continue;
                }
            };
            match sess.login(&cfg) {
                Ok(l) => println!(
                    "  {}:{} 登录 ok（{}，用户/文件 {:?}）",
                    s.ip,
                    s.port,
                    if l.is_low_id() { "LowID" } else { "HighID" },
                    l.status.map(|st| (st.users, st.files)),
                ),
                Err(e) => {
                    println!("  {}:{} 登录失败: {e}", s.ip, s.port);
                    continue;
                }
            }
            match sess.get_sources(&hash, size, Duration::from_secs(6)) {
                Ok(srcs) => println!("  {}:{} 查源到 {} 个", s.ip, s.port, srcs.len()),
                Err(e) => println!("  {}:{} 查源失败: {e}", s.ip, s.port),
            }
        }
    }
}

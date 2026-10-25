//! Mainline DHT（BEP-5）主动找源：**只查 `get_peers`，不 announce**。
//!
//! 动机：tracker 只回答"谁向这个 tracker 汇报过这个 infohash"。大量客户端
//! （qBittorrent / Transmission 等）同时也会向 DHT `announce_peer`，但不一定
//! 出现在我们手头这几个 tracker 的响应里；若只在 magnet 自带 tracker 有回包时
//! 才有 peer，薄 seed 的种子会直接卡在"没有任何 peer"。
//!
//! 这里起一个**短命**的 DHT 客户端，对着目标 infohash 做一次迭代查询，把拿到的
//! peer 地址交给 `AddTorrentOptions::initial_peers` —— 找源与传输彻底解耦：
//! 即使 DHT 一个 peer 都没找到，也照样进 librqbit 走它自己的 DHT/PeX。
//!
//! 隐私取舍：不 `announce_peer`、不开 `server_mode`，本进程在 DHT 里既不表态
//! 也不对外服务；节点用完即丢（actor 线程随最后一个句柄 Drop 退出）。

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use futures_lite::StreamExt as _;
use mainline::Id;

/// 单次探测的时间预算。
///
/// 与 tracker announce **并发**执行（`tokio::join!`），所以它不叠加在 BT 启动
/// 延迟上，只决定"最晚等多久开始下载"。
pub const BUDGET: Duration = Duration::from_secs(15);

/// 交回 `initial_peers` 的上限：每个地址都要真握一次手，堆太多只会拖慢起播。
pub const MAX_PEERS: usize = 150;

/// 一次探测的结果。
#[derive(Debug, Default, Clone)]
pub struct Found {
    /// 去重后的 peer 地址（保序：越早从响应里拿到的越靠前）。
    pub peers: Vec<SocketAddr>,
    /// 探测结束时路由表规模的估计值，仅用于日志（0 说明连 bootstrap 都没通）。
    pub dht_size: usize,
}

/// 对着 `infohash` 做一次 `get_peers`，最多等 `budget`。
///
/// 失败只覆盖"起不来"（UDP 绑定失败 / infohash 长度不对）；网络不通、没有 peer
/// 都是**正常的空结果**，由调用方自己决定要不要记账。
pub async fn find_peers(infohash: &[u8], budget: Duration) -> Result<Found, String> {
    // 长度在这里兜住（必须是 20 字节 SHA-1），调用方不必再重复校验。
    let id = Id::from_bytes(infohash).map_err(|e| format!("dht_id: {e}"))?;
    // `port` / `persistence` 都留默认：随机端口 + 不落盘，多个 BT 任务并发时
    // 不会抢同一个固定 UDP 端口（那是 librqbit 自带 DHT 的老问题）。
    let node = mainline::Dht::builder()
        .build()
        .map_err(|e| format!("dht_bind: {e}"))?;
    let dht = node.as_async();

    let mut peers: Vec<SocketAddr> = Vec::new();
    let mut seen: HashSet<SocketAddr> = HashSet::new();
    let mut stream = dht.get_peers(id);
    let deadline = tokio::time::Instant::now() + budget;

    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            break;
        }
        match tokio::time::timeout(left, stream.next()).await {
            // 一个响应里的 peer 批量到货。
            Ok(Some(chunk)) => {
                if absorb(&mut peers, &mut seen, &chunk) {
                    break;
                }
            }
            // 查询自然结束（迭代收敛 / 发送端 drop）。
            Ok(None) => break,
            // 预算用完：拿到的部分照用，不阻塞下载。
            Err(_) => break,
        }
    }

    let dht_size = dht.info().await.dht_size_estimate().0;
    // 显式丢弃最后一个句柄：actor 线程看到通道断开就退出，端口随之释放。
    drop(dht);

    Ok(Found { peers, dht_size })
}

/// 把一批响应合并进 `dst`，返回是否已经到 `MAX_PEERS` 上限。
fn absorb(
    dst: &mut Vec<SocketAddr>,
    seen: &mut HashSet<SocketAddr>,
    chunk: &[SocketAddrV4],
) -> bool {
    for v4 in chunk {
        let addr = SocketAddr::V4(*v4);
        if !usable(&addr) {
            continue;
        }
        if seen.insert(addr) {
            dst.push(addr);
        }
        if dst.len() >= MAX_PEERS {
            return true;
        }
    }
    false
}

/// 明显不可用的地址直接丢：端口 0、`0.0.0.0`、广播地址、组播地址。
///
/// 私有网段**不丢**——同局域网里的 peer（192.168/10.x）常常是唯一真实的源。
fn usable(addr: &SocketAddr) -> bool {
    if addr.port() == 0 {
        return false;
    }
    match addr.ip() {
        IpAddr::V4(v4) => !(v4.is_unspecified() || v4.is_broadcast() || v4.is_multicast()),
        IpAddr::V6(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(text: &str) -> SocketAddrV4 {
        text.parse().unwrap()
    }

    #[test]
    fn placeholder_addresses_are_unusable() {
        assert!(!usable(&SocketAddr::V4(v4("0.0.0.0:6881"))));
        assert!(!usable(&SocketAddr::V4(v4("1.2.3.4:0"))));
        assert!(!usable(&SocketAddr::V4(v4("255.255.255.255:6881"))));
    }

    #[test]
    fn private_and_public_peers_are_both_usable() {
        // 私有网段不丢：同局域网的 peer 常常就是唯一的源。
        assert!(usable(&SocketAddr::V4(v4("192.168.1.9:51413"))));
        assert!(usable(&SocketAddr::V4(v4("203.0.113.7:6881"))));
    }

    #[test]
    fn chunk_is_absorbed_deduped_and_ordered() {
        let mut dst = Vec::new();
        let mut seen = HashSet::new();
        let reached = absorb(
            &mut dst,
            &mut seen,
            &[v4("198.51.100.1:6881"), v4("198.51.100.2:6881")],
        );
        assert!(!reached);
        let reached = absorb(
            &mut dst,
            &mut seen,
            &[
                // 与第一轮重复 + 一个不可用地址 + 一个新地址。
                v4("198.51.100.1:6881"),
                v4("0.0.0.0:6881"),
                v4("198.51.100.3:6881"),
            ],
        );
        assert!(!reached);
        let text: Vec<String> = dst.iter().map(|a| a.to_string()).collect();
        assert_eq!(
            text,
            [
                "198.51.100.1:6881",
                "198.51.100.2:6881",
                "198.51.100.3:6881"
            ]
        );
    }

    #[test]
    fn absorb_stops_at_the_cap() {
        let mut dst = Vec::new();
        let mut seen = HashSet::new();
        let mut chunk = Vec::new();
        for i in 0..(MAX_PEERS + 10) {
            chunk.push(v4(&format!("198.51.100.{}:6881", (i % 250) + 1)));
        }
        // 地址会重复，所以第一轮一定拿不满；反复灌直到够数。
        let mut rounds = 0;
        while !absorb(&mut dst, &mut seen, &chunk) {
            rounds += 1;
            assert!(rounds < 1000, "should reach the cap");
        }
        assert_eq!(dst.len(), MAX_PEERS);
    }

    #[test]
    fn bad_infohash_length_is_reported() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = runtime
            .block_on(find_peers(&[0u8; 19], Duration::from_millis(1)))
            .unwrap_err();
        assert!(err.starts_with("dht_id:"), "{err}");
    }

    /// 真实的 DHT 探测（联网）；手动验收用：
    ///
    /// ```text
    /// $env:AIDM_DHT_INFOHASH='<40 位十六进制>[,<另一个>,…]'
    /// cargo test -p aidm-engine dht_live_probe -- --ignored --nocapture
    /// ```
    ///
    /// 支持逗号分隔的批量：一次 cargo 调用就能把搜到的候选全验一遍
    /// （每个 12 s 预算，实测通常 3–4 s 收敛）。
    #[test]
    #[ignore = "需要联网 + AIDM_DHT_INFOHASH"]
    fn dht_live_probe() {
        let Ok(list) = std::env::var("AIDM_DHT_INFOHASH") else {
            eprintln!("skip: AIDM_DHT_INFOHASH 未设置");
            return;
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        for hex in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let bytes = hex20(hex).expect("需要 40 位十六进制 infohash");
            let started = std::time::Instant::now();
            match runtime.block_on(find_peers(&bytes, Duration::from_secs(12))) {
                Ok(found) => {
                    println!(
                        "infohash={hex} peers={} dht_size={} elapsed={:?}",
                        found.peers.len(),
                        found.dht_size,
                        started.elapsed()
                    );
                    for peer in found.peers.iter().take(10) {
                        println!("  {peer}");
                    }
                }
                Err(e) => println!("infohash={hex} error={e}"),
            }
        }
    }

    fn hex20(text: &str) -> Option<[u8; 20]> {
        if text.len() != 40 {
            return None;
        }
        let mut out = [0u8; 20];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).ok()?;
        }
        Some(out)
    }
}

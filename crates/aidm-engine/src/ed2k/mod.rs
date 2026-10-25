//! eD2k 引擎侧实现（L3/L4/L5 的网络部分）。
//!
//! 服务器/Kad 增量查源、多源 TCP 校验片协调及原生 SHub 文件信息查询。
//! 私有 peer 的寻址/穿透及传输尚未实现；当前验收边界见
//! `docs/private-protocol-alignment.md`。标准线路编解码在
//! `aidm_core::ed2k::peer`。

pub mod identity;
/// 入站上传服务（L6）：共享已完成的 eD2k 任务，默认关闭。
pub mod inbound;
/// Kad bootstrap 节点列表（`nodes.dat`）的取用与刷新：优先库里的最新一份，
/// 退回编译期内嵌样本。
pub mod kad_bootstrap;
pub mod kad_session;
pub mod multi_source;
pub mod peer_session;
/// 实网文件握手、范围请求及响应的有界 Channel 帧。
pub mod private_channel;
/// 同一 UDP socket 上的私有注册、穿透及双向连接确认。
pub mod private_connection;
/// 经文件 MD4 校验的云端校验片查询，与 peer 查源并行。
pub mod private_index;
/// 私有 SN 目录与 UDP wrapper，实际文件 peer 仍需 Broker/穿透。
pub mod private_nat;
/// 私有 PeerID 资源目录；不将 InternalIP 当作公网 eD2k 端点。
pub mod private_peer;
/// 私有多源校验片协调；单 UDP 收包者、任务和全局许可硬上限。
pub mod private_pool;
/// 可由单个 UDP 接收循环分派的私有可靠流与文件会话。
pub mod private_session;
/// 帧格式经报文样本交叉校验的可靠 UDP 帧；尚非完整文件会话。
pub mod private_transport;
/// 公共 eD2k 服务器列表（`server.met`）的取回：刷新语义是「写回 `ed2k.servers`」。
pub mod server_list;
/// eDonkey 服务器会话（L3）：登录 → 查源。
pub mod server_session;
pub mod source_discovery;
pub mod upload_queue;
/// 消息分帧（对等与服务器共用）。
pub mod wire;

pub use peer_session::{download_from_peer, PeerDownload, PeerSessionCfg};

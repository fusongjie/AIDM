//! AIDM 引擎库：下载管理器与 IPC 服务（进程入口见 bin `aidm-engine`）。

mod bt;
/// eD2k 引擎侧实现：L4 对等会话（连接、握手、入队、分片收发、逐片校验）。
pub mod ed2k;
pub mod fastdl;
/// 最小 FTP 客户端。
pub mod ftp;
pub mod limiter;
pub mod manager;
pub mod quic;
pub mod server;
/// 找源抽象（P0）：`SourceProvider` trait 与 HTTP 实现，本批次不接线 worker。
pub mod source;
/// 进程内的来源记分板：把真实传输尝试喂进 `aidm_core::source_score`，并按总分给出取源顺序。
pub mod source_registry;
pub mod update;

/// eD2k 任务的 HTTP 备用源发现（archive.org）。
mod archive_source;
mod checksum;
/// Mainline DHT（BEP-5）`get_peers` 主动找源：只查不 announce，结果喂 `initial_peers`。
mod dht;
/// 统一下载引擎侧：只读观测与 IPC 唯一快照投影。
pub mod download;
mod http_util;
mod merge;
/// 上游 Metalink 的取回：同时补镜像地址与整文件哈希。
mod metalink_source;
/// 上游 `.mirrorlist` 的取回：只补镜像地址（哈希来自别处时用）。
mod mirrorlist_source;
mod probe;
/// 队列层闸门（多队列的第二层配额）；纯逻辑，可脱离 manager 直接测。
pub mod queue_gate;
mod recovery;
/// S3 兼容对象存储：把 `s3://bucket/key` 预签成可直接下载的 HTTPS 地址。
///
/// 走预签名而不是"给请求注入签名头"，是为了让下载路径完整复用现有内核
/// （签名只在 query 里，fastdl/ureq 两条栈都不用改）。见模块注释。
pub mod s3;
mod url_resolve;
mod worker;

pub use http_util::HttpRuntime;
pub use limiter::TokenBucket;
pub use manager::{
    AddSpec, DownloadManager, EventHub, IoFault, LiveState, Progress, SegmentView, TaskView,
};

/// 测试临时目录工厂（`target/<profile>/tmp`，不写系统 `%TEMP%`）。
#[cfg(test)]
mod testsupport;

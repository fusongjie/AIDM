//! AIDM 核心库：路径解析、SQLite 持久化、设置项读写、下载模型与纯逻辑。
//!
//! 补齐任务失败码（`error` / `error_code` / `http_status`）与崩溃重入队；
//! HTTP 传输本身在 `aidm-engine`（引擎进程独占网络 IO）。

/// 备用地址（镜像）候选序列：解析、尝试顺序与大小对账。
pub mod alt;
/// BitTorrent 逐文件选择：索引集合的解析/编码/收敛（纯函数）。
pub mod bt_files;
/// 协议能力模型：传输/资源/清单/封装四层正交属性 + 协议允许的能力上限。
pub mod capability;
/// 剪贴板「下载提示」三层策略：链接识别 / 下载目标判定 / 提示策略（纯逻辑，可单测）。
pub mod clipboard_policy;
/// 内容类型与文件名矛盾的识别（错误页冒充文件），见模块注释。
pub mod content_check;
pub mod cron;
/// MPEG-DASH（ISO/IEC 23009-1）清单解析：分片寻址、模板展开与加密识别。
pub mod dash;
pub mod db;
/// 开发工具的资源地址：npm/pnpm/cargo 的包坐标 → registry 直链（纯换算，不联网）。
pub mod devtools;
/// 一键诊断包：脱敏后打包任务现场（事件/分片/错误链/设置/日志/系统信息）。
pub mod diag;
/// 统一下载业务模型：契约、覆盖账本、状态归约与解释器。
///
/// 纯逻辑、无 IO；执行路径仍由 legacy worker 承担，本模块只提供事实与决策。
pub mod download;
/// eD2k（电驴）：链接解析 + MD4 分片哈希树。网络层分阶段实现。
pub mod ed2k;
pub mod error;
pub mod filename;
/// 「在磁盘上查找」：把被移动/改名的下载文件找回来（有界遍历，不是全盘扫描）。
pub mod find;
pub mod hash;
/// 每任务自定义请求头：解析、防注入校验与回显。
pub mod headers;
/// HLS（RFC 8216）清单解析：分片列表、字节区间、加密识别与主清单变体选择。
pub mod hls;
pub mod hosts;
pub mod htmltext;
/// HTTP 认证挑战解析与 Digest 应答（RFC 7616）。
pub mod http_auth;
/// 请求头配置（UA / Accept 系列 / Referer 兜底）。见 docs/http-profile.md。
pub mod http_profile;
/// 链接封装（专用链/裸地址/带标记地址/网盘资源标识）的链接解码。
pub mod link_decode;
pub mod lock;
/// 站点凭据（按主机存用户名/密码，401 挑战时自动重试）。见 `docs/capability-gap-analysis.md` P1.2。
pub mod logins;
/// Metalink（RFC 5854 / 3.0）的**有界**解析：整文件 SHA-256 + 镜像地址列表。
pub mod metalink;
/// MirrorBrain 风格 `.mirrorlist` 页面：抽同一文件在各镜像上的完整地址。
pub mod mirrorlist;
/// 已知镜像族（L3 静态表）：同一路径换 host 派生镜像候选，表项须实测验证。
pub mod mirrors;
pub mod model;
pub mod nmh;
/// 结构化日志底座：JSON 行输出 + 字段脱敏 + 限流 + 落盘（见 `docs/download-observability.md`）。
pub mod obs;
pub mod pace;
pub mod paths;
pub mod proxy;
/// 多队列：命名队列、队列项顺序与队列维度计数（产品文档 §4 / 队列规格 §1）。
pub mod queues;
/// 日志脱敏：写入 events 表与进程日志前打码 URL 里的凭据类查询参数（§11）。
pub mod redact;
pub mod sched;
pub mod secret;
pub mod segment;
pub mod setting_spec;
pub mod settings;
pub mod source;
/// 来源打分与排名（内存滚动统计：Wilson 保守成功率 × 速度/稳定性/响应三项加权）。
/// 口径见 `docs/protocol-capabilities.md`「P6 来源打分」。
pub mod source_score;
pub mod speed;
/// zsync 控制文件（`.zsync`）解析与缺失块规划（格式对照 `zsync-rs 0.2.1` 实现）。
pub mod zsync;

pub use db::open_db;
pub use error::{classify as classify_error, ClassifiedError};
pub use lock::{try_acquire as try_acquire_instance_lock, InstanceLock};
pub use model::Status;
pub use paths::{app_data_dir, db_path, logs_dir};

/// 测试临时目录工厂（`target/<profile>/tmp`，不写系统 `%TEMP%`）。
#[cfg(test)]
pub(crate) mod testsupport;

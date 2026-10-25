//! 统一下载对外视图（`unified_download_v1`，开发文档第 10 节）。
//!
//! 本文件是引擎到 UI / MCP / 诊断的**唯一**统一视图契约。内部实体在
//! `aidm-core::download`，此处只放投影后的形状；转换由 `aidm-engine` 的唯一
//! 快照层负责，`aidm-ipc` 不依赖 `aidm-core`。
//!
//! # 兼容约束
//!
//! - 全部新增字段都是**可选**的：未知字段忽略，缺失字段按默认值处理。
//! - 既有 `TaskView` 字段与事件不变义、不删除。
//! - 新推送只发给在 `ping` / `subscribe` 中声明了
//!   [`FEATURE_UNIFIED_DOWNLOAD_V1`] 的客户端。
//!
//! # 数值精度
//!
//! 文档 4.1：可能超过 JavaScript 安全整数范围的 ID、序号与字节计数一律用十进制
//! 字符串，客户端用 `BigInt` 或精确整数工具处理。本文件里所有 `String` 表示的
//! 数值字段都遵守这条，不做例外。

use serde::{Deserialize, Serialize};

/// 统一视图结构版本，首版为 1。
pub const UNIFIED_SCHEMA_VERSION: u16 = 1;

/// IPC 功能标识。它表示"客户端能理解统一视图"，与"协议是否支持分片"无关。
pub const FEATURE_UNIFIED_DOWNLOAD_V1: &str = "unified_download_v1";

/// `task_snapshot` 默认每页条目数。
pub const SNAPSHOT_DEFAULT_LIMIT: u32 = 64;

/// `task_snapshot` 允许的最大每页条目数。超过按参数错误返回，不静默截断。
pub const SNAPSHOT_MAX_LIMIT: u32 = 256;

/// 统一视图的任务身份与版本。
///
/// 序号用字符串：`state_revision` 允许缺口且由持久化号段预留，客户端不应假设连续。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct UnifiedIdentity {
    /// 复用 `downloads.id`，任务终生不变。
    pub task_id: String,
    /// 每次引擎启动生成的新 UUID；用于识别"快照来自另一个进程"。
    pub engine_instance_id: String,
    pub run_epoch: String,
    pub content_generation: String,
    pub plan_revision: String,
    pub state_revision: String,
}

/// 统一进度。
///
/// `stored_unique_bytes` 是有效落盘范围并集长度；`verified_unique_bytes` 不得超过它。
/// 重复传输只增加 `wire_bytes`。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct UnifiedProgress {
    pub wire_bytes: String,
    pub stored_unique_bytes: String,
    pub verified_unique_bytes: String,
    /// 用户所选范围总长；未知为 None（不是 0）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_bytes: Option<String>,
    pub transfer_rate_bps: String,
    pub useful_rate_bps: String,
}

/// 计数快照。各项独立计数，不能互相推导。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct UnifiedCounts {
    pub known_sources: u32,
    pub eligible_sources: u32,
    pub connections: u32,
    pub active_transfers: u32,
    pub queued_peers: u32,
    pub done_slices: u32,
}

/// 等待事实。`scope` 与 `reason` 为受控小写标识。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct UnifiedWait {
    pub reason: String,
    pub scope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<String>,
    pub since_ms: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_at_ms: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail_code: Option<String>,
}

/// 三态能力。字符串取值 `yes` / `no` / `unknown`。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct UnifiedCapabilitySet {
    pub metadata_known: String,
    pub random_read: String,
    pub resume: String,
    pub multi_source: String,
    /// `none` / `length_only` / `whole_file` / `native_block` / `mixed`。
    pub integrity: String,
}

/// 左闭右开范围。`end_exclusive` 为空表示总长未知、只能顺序读取。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct UnifiedRange {
    pub start: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_exclusive: Option<String>,
}

/// 原因链的一层；根因在链尾。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct UnifiedCause {
    pub code: String,
    pub message: String,
}

/// 统一错误。
///
/// `message` 只供人阅读，**禁止**从它反推业务状态；`category` / `code` 才是判据。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct UnifiedErrorView {
    pub category: String,
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<String>,
    pub retryable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// HTTP 状态、FTP 回复码或 P2P 原始类别。旧 `http_status` 仍单独保留。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_code: Option<String>,
    pub message: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cause_chain: Vec<UnifiedCause>,
}

/// 内容身份摘要。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct UnifiedContentIdentity {
    pub algorithm: String,
    pub digest_hex: String,
    pub evidence_source: String,
    /// `unknown` / `weak` / `strong`。
    pub trust: String,
}

/// 资源摘要。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct UnifiedResource {
    pub resource_id: String,
    pub selected: bool,
    /// 可空；`"0"` 是合法空文件，缺失表示未知。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<UnifiedContentIdentity>,
    /// `none` / `length_only` / `whole_file` / `native_block` / `mixed`。
    pub verification: String,
    /// `pending` / `committing` / `committed` / `failed`。
    pub commit_state: String,
}

/// 原生块映射条目。只在协议详情里出现，不作为切片语义。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct UnifiedNativeBlock {
    pub native_index: String,
    pub range: UnifiedRange,
    /// `true` / `false`；缺失表示尚未验证。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,
    /// 运行时状态：`pending` / `active` / `done` / `checking`；缺失 = 未知。
    ///
    /// 与 `verified` 分开：前者回答“现在在下/没开始”，后者回答“能不能算完成”。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

/// 通路分配摘要。
///
/// 子行展示用：源、连接、负责的互不重叠子区间、排队与失败原因。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct UnifiedAssignment {
    pub assignment_id: String,
    pub slice_id: String,
    pub source_id: String,
    /// 连接未建成时为空。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<String>,
    pub range: UnifiedRange,
    /// `pending` / `connecting` / `queued` / `transferring` / `draining` /
    /// `completed` / `failed` / `cancelled`。
    pub state: String,
    pub transfer_rate_bps: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<UnifiedErrorView>,
}

/// 切片摘要。切片是 AIDM 唯一的业务切片与展示维度。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct UnifiedSlice {
    pub slice_id: String,
    pub resource_id: String,
    pub range: UnifiedRange,
    /// `pending` / `active` / `waiting` / `verifying` / `done` / `error`。
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait: Option<UnifiedWait>,
    pub progress: UnifiedProgress,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assignments: Vec<UnifiedAssignment>,
    /// 协议原生块详情，可展开；不参与切片语义。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub native_blocks: Vec<UnifiedNativeBlock>,
}

/// 源摘要（按需加载，不随任务列表推送）。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct UnifiedSource {
    pub source_id: String,
    pub resource_id: String,
    pub transport: String,
    /// `available` / `unavailable` / `unknown`。
    pub availability: String,
    pub eligible: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cooldown_until_ms: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_observed_at_ms: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<String>,
    pub throughput_bps: String,
    pub queued_peers: u32,
    pub capabilities: UnifiedCapabilitySet,
}

/// 完整性标记：说明本视图是否被分页或抽样截断。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct UnifiedCompleteness {
    /// `false` 表示还有未包含的对象；`total_count` 仍是真实总数。
    pub complete: bool,
    pub total_count: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    /// 采样时间（UTC Unix 毫秒）。
    pub sampled_at_ms: String,
}

/// 首版结构版本的 serde 默认值。字段缺失时按当前版本处理，而不是 0。
fn default_schema_version() -> u16 {
    UNIFIED_SCHEMA_VERSION
}

/// 统一视图主体。
///
/// `sources` 为 `None` 表示"本次没有附带源详情"，与"源数量为 0"不同。
///
/// 整个结构宽松解析（`serde(default)`）：缺失字段按默认值补齐，多出的字段忽略，
/// 任一侧升级都不会导致解析失败。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct UnifiedDownloadView {
    /// 本结构版本，首版为 [`UNIFIED_SCHEMA_VERSION`]。
    #[serde(default = "default_schema_version")]
    pub schema_version: u16,
    pub identity: UnifiedIdentity,
    /// `queued` / `connecting` / `downloading` / `paused` / `verifying` /
    /// `done` / `error`（与旧七状态闭集一致）。
    pub status: String,
    /// `discovering` / `probing` / `connecting` / `transferring` / `waiting` /
    /// `verifying` / `committing` / `idle`。
    pub activity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait: Option<UnifiedWait>,
    pub progress: UnifiedProgress,
    pub counts: UnifiedCounts,
    pub capabilities: UnifiedCapabilitySet,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<UnifiedResource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub slices: Vec<UnifiedSlice>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sources: Option<Vec<UnifiedSource>>,
    pub completeness: UnifiedCompleteness,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<UnifiedErrorView>,
}

/// `task_snapshot` 的 section 取值。缺省为 `summary`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SnapshotSection {
    #[default]
    Summary,
    Resources,
    Slices,
    Assignments,
    Sources,
}

impl SnapshotSection {
    pub fn as_str(self) -> &'static str {
        match self {
            SnapshotSection::Summary => "summary",
            SnapshotSection::Resources => "resources",
            SnapshotSection::Slices => "slices",
            SnapshotSection::Assignments => "assignments",
            SnapshotSection::Sources => "sources",
        }
    }

    /// 解析请求里的 section；未知值返回 `None`，由引擎回参数错误。
    ///
    /// 空串与缺省都按 `summary` 处理（文档 10 节："默认 summary"）。
    pub fn parse(raw: Option<&str>) -> Option<Self> {
        Some(match raw {
            None | Some("") | Some("summary") => SnapshotSection::Summary,
            Some("resources") => SnapshotSection::Resources,
            Some("slices") => SnapshotSection::Slices,
            Some("assignments") => SnapshotSection::Assignments,
            Some("sources") => SnapshotSection::Sources,
            Some(_) => return None,
        })
    }
}

/// 分页结果的一条条目。类型由同响应里的 `section` 决定。
///
/// 为什么不用 `#[serde(untagged)]`：所有子结构都是宽松解析（结构级
/// `#[serde(default)]`），untagged 会**按变体顺序逐个尝试**，于是任何 JSON
/// 对象都能被第一个变体 `UnifiedResource` 吃掉——条目数量对、类型全错。
/// 用户复核的端到端用例就踩到了：通路永远反序列化成 Resource，真实的
/// `assignment_id` / `range` 根本读不到。改用内部 tag + content，类型无歧义。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum UnifiedSnapshotItem {
    Resource(UnifiedResource),
    Slice(UnifiedSlice),
    Assignment(UnifiedAssignment),
    Source(UnifiedSource),
}

/// `task_snapshot` 响应体。
///
/// 文档 10 节：`summary` 与 `items` 二选一，`total_count` 永远是真实总数，
/// 不因分页而变小。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct UnifiedSnapshotResponse {
    #[serde(default = "default_schema_version")]
    pub schema_version: u16,
    pub identity: UnifiedIdentity,
    pub section: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<Box<UnifiedDownloadView>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub items: Option<Vec<UnifiedSnapshotItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub total_count: u32,
    pub complete: bool,
}

/// `task_snapshot` 的结构化错误码。
pub mod snapshot_error {
    /// 请求的 `limit` 超出 [`super::SNAPSHOT_MAX_LIMIT`] 或为 0。
    pub const INVALID_LIMIT: &str = "invalid_limit";
    /// `section` 不是受控取值。
    pub const INVALID_SECTION: &str = "invalid_section";
    /// 游标已失效（引擎实例、任务、版本或 section 不匹配）。
    pub const SNAPSHOT_STALE: &str = "snapshot_stale";
    /// 对端尚未实现该查询。
    pub const UNSUPPORTED: &str = "unsupported";
    /// 任务不存在。
    pub const NO_SUCH_TASK: &str = "no_such_task";
}

/// 把 `limit` 收敛到合法区间；非法输入返回 `None`，由引擎回参数错误。
pub fn normalize_snapshot_limit(raw: Option<u32>) -> Option<u32> {
    match raw {
        None => Some(SNAPSHOT_DEFAULT_LIMIT),
        Some(0) => None,
        Some(n) if n <= SNAPSHOT_MAX_LIMIT => Some(n),
        Some(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_version_is_one() {
        assert_eq!(UNIFIED_SCHEMA_VERSION, 1);
    }

    #[test]
    fn limit_normalization_rejects_out_of_range() {
        assert_eq!(normalize_snapshot_limit(None), Some(64));
        assert_eq!(normalize_snapshot_limit(Some(0)), None, "0 不是合法分页大小");
        assert_eq!(normalize_snapshot_limit(Some(1)), Some(1));
        assert_eq!(normalize_snapshot_limit(Some(256)), Some(256));
        assert_eq!(
            normalize_snapshot_limit(Some(257)),
            None,
            "超上限必须报参数错误，不静默截断"
        );
    }

    #[test]
    fn section_parse_defaults_to_summary() {
        assert_eq!(SnapshotSection::parse(None), Some(SnapshotSection::Summary));
        assert_eq!(
            SnapshotSection::parse(Some("")),
            Some(SnapshotSection::Summary)
        );
        assert_eq!(
            SnapshotSection::parse(Some("summary")),
            Some(SnapshotSection::Summary)
        );
        assert_eq!(
            SnapshotSection::parse(Some("slices")),
            Some(SnapshotSection::Slices)
        );
        assert_eq!(SnapshotSection::parse(Some("bogus")), None);
        assert_eq!(SnapshotSection::parse(Some("Summary")), None, "大小写敏感");
    }

    #[test]
    fn section_roundtrips_through_as_str() {
        for s in [
            SnapshotSection::Summary,
            SnapshotSection::Resources,
            SnapshotSection::Slices,
            SnapshotSection::Assignments,
            SnapshotSection::Sources,
        ] {
            assert_eq!(SnapshotSection::parse(Some(s.as_str())), Some(s));
        }
    }

    #[test]
    fn empty_view_serializes_without_null_noise() {
        let view = UnifiedDownloadView {
            schema_version: UNIFIED_SCHEMA_VERSION,
            ..Default::default()
        };
        let json = serde_json::to_value(&view).expect("serialize");
        let obj = json.as_object().expect("object");
        assert!(!obj.contains_key("wait"), "空可选字段不应出现");
        assert!(!obj.contains_key("error"));
        assert!(!obj.contains_key("sources"));
        assert!(!obj.contains_key("slices"), "空数组也应省略");
        assert_eq!(obj["schema_version"], 1);
    }

    #[test]
    fn old_payload_without_new_fields_still_parses() {
        // 兼容：对端只提供 schema_version、缺少其它字段。
        let raw = r#"{"schema_version":1}"#;
        let view: UnifiedDownloadView = serde_json::from_str(raw).expect("parse old");
        assert_eq!(view.schema_version, 1);
        assert!(view.slices.is_empty());
        assert!(view.error.is_none());
    }

    #[test]
    fn big_numbers_stay_exact_as_strings() {
        // 超过 2^53 的字节计数必须无损。
        let big = 9_007_199_254_740_993u64; // 2^53 + 1
        let view = UnifiedDownloadView {
            progress: UnifiedProgress {
                wire_bytes: big.to_string(),
                ..Default::default()
            },
            ..Default::default()
        };
        let json = serde_json::to_string(&view).expect("serialize");
        assert!(json.contains(&big.to_string()));
        let back: UnifiedDownloadView = serde_json::from_str(&json).expect("parse");
        assert_eq!(back.progress.wire_bytes, big.to_string());
    }

    #[test]
    fn unknown_fields_are_ignored_for_forward_compat() {
        // 新引擎加了字段，旧客户端反序列化不应失败（serde 默认忽略未知字段）。
        let raw = r#"{"schema_version":1,"future_field":"x","status":"queued"}"#;
        let view: UnifiedDownloadView = serde_json::from_str(raw).expect("ignore unknown");
        assert_eq!(view.status, "queued");
    }

    #[test]
    fn snapshot_items_keep_their_type_through_roundtrip() {
        // 曾经的缺陷：`#[serde(untagged)]` 让所有条目反序列化成第一个变体
        // （Resource 全字段可选），数量对、类型全错。端到端用例就踩到了，
        // 真实 assignment 的 ID 与 range 根本读不到。
        let item = UnifiedSnapshotItem::Assignment(UnifiedAssignment {
            assignment_id: "a1".into(),
            slice_id: "s1".into(),
            source_id: "src1".into(),
            connection_id: None,
            range: UnifiedRange {
                start: "0".into(),
                end_exclusive: Some("100".into()),
            },
            state: "transferring".into(),
            transfer_rate_bps: "1024".into(),
            error: None,
        });
        let json = serde_json::to_string(&item).expect("serialize");
        assert!(json.contains("\"kind\":\"assignment\""), "必须有显式 tag：{json}");
        let back: UnifiedSnapshotItem = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, item, "条目类型必须经序列化后保持不变");
        match back {
            UnifiedSnapshotItem::Assignment(a) => assert_eq!(a.source_id, "src1"),
            other => panic!("必须还原成 Assignment，实际 {other:?}"),
        }
    }

    #[test]
    fn snapshot_response_omits_absent_parts() {
        let resp = UnifiedSnapshotResponse {
            schema_version: UNIFIED_SCHEMA_VERSION,
            section: "slices".into(),
            total_count: 0,
            complete: true,
            ..Default::default()
        };
        let json = serde_json::to_value(&resp).expect("serialize");
        let obj = json.as_object().expect("object");
        assert!(!obj.contains_key("summary"));
        assert!(!obj.contains_key("items"));
        assert!(!obj.contains_key("next_cursor"));
        assert_eq!(obj["complete"], true);
    }
}

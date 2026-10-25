//! MCP Tasks 扩展（`io.modelcontextprotocol/tasks`）的数据形状与时间格式化。
//!
//! 只放纯数据和纯函数：状态机与线程在 `server`。任务 id 用 `aidm:<下载 id>`，
//! 与引擎的稳定任务 id 一一对应（R-MCP-12：不另造标识体系）。

use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};

/// 任务被跟踪多久（从最后一次更新算起）。过期后 `tasks/get` 回 `unknown_task`。
pub const TTL_MS: u64 = 60 * 60 * 1000;
/// 建议客户端轮询间隔。
pub const POLL_INTERVAL_MS: u64 = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskStatus {
    Working,
    Completed,
    Failed,
    Cancelled,
}

impl TaskStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Working => "working",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn is_terminal(self) -> bool {
        !matches!(self, Self::Working)
    }
}

/// 一个被 MCP 跟踪的任务。`result`/`error` 只在终态出现。
#[derive(Debug, Clone)]
pub struct TrackedTask {
    pub id: String,
    pub aidm_id: u64,
    pub status: TaskStatus,
    pub status_message: String,
    pub created_at: SystemTime,
    pub updated_at: SystemTime,
    /// 终态的 `CallToolResult`（不含 `resultType`）。
    pub result: Option<Value>,
    /// 终态的 JSON-RPC error 对象（只有 IPC 失败才有）。
    pub error: Option<Value>,
}

impl TrackedTask {
    pub fn new(aidm_id: u64, status_message: impl Into<String>) -> Self {
        let now = SystemTime::now();
        Self {
            id: task_id(aidm_id),
            aidm_id,
            status: TaskStatus::Working,
            status_message: status_message.into(),
            created_at: now,
            updated_at: now,
            result: None,
            error: None,
        }
    }

    /// `CreateTaskResult`（`tools/call` 用 `resultType:"task"`）。
    pub fn create_result(&self) -> Value {
        let mut value = self.detail();
        value["resultType"] = json!("task");
        value
    }

    /// `tasks/get` / `notifications/tasks` 用的 DetailedTask（`resultType` 由调用方决定）。
    pub fn detail(&self) -> Value {
        let mut value = json!({
            "taskId": self.id,
            "status": self.status.as_str(),
            "createdAt": iso8601(self.created_at),
            "lastUpdatedAt": iso8601(self.updated_at),
            "ttlMs": TTL_MS,
            "pollIntervalMs": POLL_INTERVAL_MS,
        });
        if !self.status_message.is_empty() {
            value["statusMessage"] = json!(self.status_message);
        }
        if let Some(result) = &self.result {
            value["result"] = result.clone();
        }
        if let Some(error) = &self.error {
            value["error"] = error.clone();
        }
        value
    }
}

pub fn task_id(aidm_id: u64) -> String {
    format!("aidm:{aidm_id}")
}

/// 只接受本服务自己的 id 形状；外部 id 一律当作未知任务。
pub fn parse_task_id(id: &str) -> Option<u64> {
    id.strip_prefix("aidm:")?.parse().ok()
}

/// ISO 8601 UTC（秒精度，`Z` 结尾）。不引第三方时间库：只要求一个格式。
pub fn iso8601(time: SystemTime) -> String {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = seconds.div_euclid(86_400);
    let rest = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        (rest % 3600) / 60,
        rest % 60
    )
}

/// Howard Hinnant 的 `civil_from_days`（1970-01-01 起的天数 → 年月日）。
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn task_ids_roundtrip() {
        assert_eq!(task_id(42), "aidm:42");
        assert_eq!(parse_task_id("aidm:42"), Some(42));
        assert_eq!(parse_task_id("42"), None);
        assert_eq!(parse_task_id("aidm:"), None);
        assert_eq!(parse_task_id("other:42"), None);
    }

    #[test]
    fn iso8601_matches_known_instants() {
        let epoch = UNIX_EPOCH;
        assert_eq!(iso8601(epoch), "1970-01-01T00:00:00Z");
        // 2026-10-23T00:00:00Z = 1792713600
        assert_eq!(
            iso8601(epoch + Duration::from_secs(1_792_713_600)),
            "2026-10-23T00:00:00Z"
        );
        // 闰日：2024-02-29T12:34:56Z = 1709210096
        assert_eq!(
            iso8601(epoch + Duration::from_secs(1_709_210_096)),
            "2024-02-29T12:34:56Z"
        );
    }

    #[test]
    fn detail_carries_status_and_ttl() {
        let mut task = TrackedTask::new(7, "downloading");
        let value = task.detail();
        assert_eq!(value["taskId"], "aidm:7");
        assert_eq!(value["status"], "working");
        assert_eq!(value["ttlMs"], TTL_MS);
        assert!(value.get("result").is_none());

        task.status = TaskStatus::Completed;
        task.result = Some(json!({"content": [], "structuredContent": {"ok": true}}));
        let done = task.detail();
        assert_eq!(done["status"], "completed");
        assert!(done["result"]["structuredContent"]["ok"].as_bool().unwrap());
    }
}

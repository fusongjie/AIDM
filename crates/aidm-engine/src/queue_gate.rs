//! 队列层闸门（产品文档 §4 的"第二层配额"）。
//!
//! 队列只做**启停 / 时间窗**准入，不限制同时下载任务数，也不参与排序。
//! 任务按 id（入队先后）派发。
//!
//! 判定只有两档：
//! - [`QueueVerdict::Run`]：这个任务可以进连接数闸门；
//! - [`QueueVerdict::BlockQueue`]：所属队列停用或不在时间窗内。

use std::collections::HashSet;

use aidm_core::model::DownloadRow;
use aidm_core::queues::QueueRow;
use aidm_core::Status;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueVerdict {
    Run,
    Skip,
    BlockQueue,
}

#[derive(Debug, Default)]
pub struct QueueBudget {
    active_queues: HashSet<i64>,
}

impl QueueBudget {
    /// 从当前任务表建立在跑集合（只用于展示活动队列数）。
    pub fn new(rows: &[DownloadRow]) -> Self {
        let mut budget = Self::default();
        for row in rows.iter().filter(|r| is_running(&r.status)) {
            budget.active_queues.insert(row.queue_id);
        }
        budget
    }

    /// 判定一个候选任务。`queues` 是队列行（可能为空 = 老库还没建队列）。
    pub fn admit(&self, row: &DownloadRow, queues: &[QueueRow], now_ms: i64) -> QueueVerdict {
        self.admit_with_reason(row, queues, now_ms).0
    }

    /// 与 [`Self::admit`] 相同，但把"为什么不放行"一起返回（事件留痕用）。
    pub fn admit_with_reason(
        &self,
        _row: &DownloadRow,
        queues: &[QueueRow],
        now_ms: i64,
    ) -> (QueueVerdict, &'static str) {
        let Some(queue) = queues.iter().find(|q| q.id == _row.queue_id) else {
            // 队列行不存在（手改库或极端竞态）：不做队列层限制，交给全局闸门。
            return (QueueVerdict::Run, "");
        };
        if !queue.enabled {
            return (QueueVerdict::BlockQueue, "queue_disabled");
        }
        if let Some(cron) = queue.schedule_cron.as_deref() {
            match aidm_core::cron::parse(cron) {
                Ok(Some(expr)) if !aidm_core::cron::matches_now(&expr, now_ms) => {
                    return (QueueVerdict::BlockQueue, "queue_window");
                }
                // 解析失败：不因为一个坏 cron 就把队列永久冻结，按"不限时"处理。
                _ => {}
            }
        }
        (QueueVerdict::Run, "")
    }

    /// 当前有任务在跑的队列数（供状态展示）。
    pub fn active_queue_count(&self) -> usize {
        self.active_queues.len()
    }
}

fn is_running(status: &Status) -> bool {
    matches!(
        status,
        Status::Connecting | Status::Downloading | Status::Verifying
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use aidm_core::queues;

    fn row(id: i64, queue_id: i64, url: &str, status: Status, created_at: i64) -> DownloadRow {
        DownloadRow {
            id,
            url_orig: url.into(),
            url_final: None,
            file_name: format!("f{id}"),
            dir: "d".into(),
            size_total: None,
            etag: None,
            last_modified: None,
            status,
            created_at,
            finished_at: None,
            error_code: None,
            error_message: None,
            http_status: None,
            speed_limit_kbps: 0,
            max_conns: 8,
            source: "manual".into(),
            referrer: None,
            custom_headers: None,
            alt_urls: None,
            alt_cursor: 0,
            ed2k_hash: None,
            aich_root: None,
            sha256_expected: None,
            priority: 0,
            retry_at: None,
            retry_count: 0,
            start_mode: "now".into(),
            queue_id,
            bt_files: None,
            active_ms: 0,
            find_rounds: 0,
            find_spent_ms: 0,
            find_last_at: None,
        }
    }

    fn queue(id: i64, name: &str) -> QueueRow {
        QueueRow {
            id,
            name: name.into(),
            enabled: true,
            max_parallel: 2,
            host_limit: 2,
            default_dir: None,
            schedule_cron: None,
            created_at: 0,
            updated_at: 0,
        }
    }

    #[test]
    fn disabled_queue_and_window_block_the_whole_queue() {
        let mut disabled = queue(1, "default");
        disabled.enabled = false;
        let queues = vec![disabled.clone()];
        let now = chrono_now();
        let rows = vec![row(1, 1, "https://a/1", Status::Queued, 0)];
        let budget = QueueBudget::new(&rows);
        assert_eq!(
            budget.admit(&rows[0], &queues, now),
            QueueVerdict::BlockQueue
        );

        // 时间窗：用"一定不命中"的 cron（本地时间不可能同时是 0 分与 1 分）
        let mut windowed = queue(1, "default");
        windowed.schedule_cron = Some("0 0 1 1 *".into()); // 1 月 1 日 00:00
        let queues = vec![windowed];
        let budget = QueueBudget::new(&rows);
        assert_eq!(
            budget.admit(&rows[0], &queues, now),
            QueueVerdict::BlockQueue,
            "不在时间窗内"
        );
        // 坏 cron 不冻结队列
        let mut broken = queue(1, "default");
        broken.schedule_cron = Some("not a cron".into());
        let queues = vec![broken];
        assert_eq!(budget.admit(&rows[0], &queues, now), QueueVerdict::Run);
    }

    fn chrono_now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }

    /// `QueueRow` 来自 core；这里确认默认队列的字段与期望一致（跨 crate 契约）。
    #[test]
    fn default_queue_row_matches_gate_expectations() {
        let conn = aidm_core::open_db(std::path::Path::new(":memory:")).unwrap();
        let queues = queues::list(&conn).unwrap();
        assert_eq!(queues.len(), 1);
        assert!(queues[0].enabled);
        assert!(queues[0].max_parallel >= 1);
        assert!(queues[0].host_limit >= 1);
        assert!(queues[0].schedule_cron.is_none());
    }
}

//! 多队列（产品文档 §4 / 队列规格 §1）的持久层。
//!
//! ## 不变量
//!
//! - **归属看 `downloads.queue_id`**。队列只负责**分组、启停、时间窗、默认目录**；
//!   不限制同时下载任务数，也不参与排序。任务按 id（入队先后）派发。
//! - **默认队列 id = 1、名字 `default`**：不可删除、不可改名，任务永远有队列可归。
//! - 队列名唯一（大小写敏感，但创建/改名时会拒绝纯空白与超长）。
//! - 删除队列时其任务**迁入默认队列**（不删任务）。

use rusqlite::{params, Connection, OptionalExtension};

/// 默认队列的 id（`db::ensure_default_queue` 保证存在）。
pub const DEFAULT_QUEUE_ID: i64 = 1;
pub const DEFAULT_QUEUE_NAME: &str = "default";
/// 队列名长度上限（与文件名同量级，够用且能防止把 UI 撑坏）。
pub const MAX_QUEUE_NAME: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueRow {
    pub id: i64,
    pub name: String,
    pub enabled: bool,
    /// 已废弃：保留列以兼容旧库，调度器不再读取。
    pub max_parallel: i64,
    /// 已废弃：保留列以兼容旧库，调度器不再读取。
    pub host_limit: i64,
    /// 该队列新建任务的默认目录；None = 跟随全局默认目录。
    pub default_dir: Option<String>,
    /// 该队列的时间窗（cron）；None/空 = 不限时。
    pub schedule_cron: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl QueueRow {
    /// 默认队列不能被删除/改名（界面据此禁用入口）。
    pub fn is_default(&self) -> bool {
        self.id == DEFAULT_QUEUE_ID
    }
}

/// 队列名净化：去首尾空白、拒绝空名/超长/控制字符。
pub fn normalize_name(raw: &str) -> Result<String, String> {
    let name = raw.trim();
    if name.is_empty() {
        return Err("queue_name_empty".into());
    }
    if name.chars().count() > MAX_QUEUE_NAME {
        return Err("queue_name_too_long".into());
    }
    if name.chars().any(|c| c.is_control()) {
        return Err("queue_name_invalid".into());
    }
    Ok(name.to_string())
}

fn row_from(row: &rusqlite::Row<'_>) -> rusqlite::Result<QueueRow> {
    Ok(QueueRow {
        id: row.get(0)?,
        name: row.get(1)?,
        enabled: row.get::<_, i64>(2)? != 0,
        max_parallel: row.get(3)?,
        host_limit: row.get(4)?,
        default_dir: row.get(5)?,
        schedule_cron: row.get(6)?,
        created_at: row.get(7)?,
        updated_at: row.get(8)?,
    })
}

const QUEUE_COLS: &str = "id, name, enabled, max_parallel, host_limit, default_dir,
     schedule_cron, created_at, updated_at";

pub fn list(conn: &Connection) -> rusqlite::Result<Vec<QueueRow>> {
    let mut stmt = conn.prepare(&format!("SELECT {QUEUE_COLS} FROM queues ORDER BY id"))?;
    let rows = stmt.query_map([], row_from)?;
    rows.collect()
}

pub fn get(conn: &Connection, id: i64) -> rusqlite::Result<Option<QueueRow>> {
    conn.query_row(
        &format!("SELECT {QUEUE_COLS} FROM queues WHERE id = ?1"),
        [id],
        row_from,
    )
    .optional()
}

pub fn find_by_name(conn: &Connection, name: &str) -> rusqlite::Result<Option<QueueRow>> {
    conn.query_row(
        &format!("SELECT {QUEUE_COLS} FROM queues WHERE name = ?1"),
        [name],
        row_from,
    )
    .optional()
}

/// 新建队列（默认启用；任务并发不再由队列限制）。
pub fn create(
    conn: &Connection,
    name: &str,
    default_dir: Option<&str>,
    schedule_cron: Option<&str>,
) -> Result<QueueRow, String> {
    let name = normalize_name(name)?;
    if name == DEFAULT_QUEUE_NAME {
        return Err("queue_name_taken".into());
    }
    if find_by_name(conn, &name)
        .map_err(|e| e.to_string())?
        .is_some()
    {
        return Err("queue_name_taken".into());
    }
    let now = crate::model::now_ms();
    conn.execute(
        "INSERT INTO queues(name, enabled, max_parallel, host_limit, default_dir, schedule_cron,
                            created_at, updated_at)
         VALUES(?1, 1, 64, 64, ?2, ?3, ?4, ?4)",
        params![
            name,
            default_dir.filter(|d| !d.trim().is_empty()),
            schedule_cron.filter(|c| !c.trim().is_empty()),
            now
        ],
    )
    .map_err(|e| e.to_string())?;
    let id = conn.last_insert_rowid();
    get(conn, id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "queue_missing".to_string())
}

/// 更新队列。`None` 表示不改该字段（只写改动项）。
pub fn update(
    conn: &Connection,
    id: i64,
    name: Option<&str>,
    enabled: Option<bool>,
    default_dir: Option<Option<&str>>,
    schedule_cron: Option<Option<&str>>,
) -> Result<QueueRow, String> {
    let current = get(conn, id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "queue_not_found".to_string())?;
    let name = match name {
        Some(raw) => {
            let name = normalize_name(raw)?;
            if current.is_default() && name != DEFAULT_QUEUE_NAME {
                return Err("queue_default_immutable".into());
            }
            if name != current.name
                && find_by_name(conn, &name)
                    .map_err(|e| e.to_string())?
                    .is_some()
            {
                return Err("queue_name_taken".into());
            }
            name
        }
        None => current.name.clone(),
    };
    let enabled = enabled.unwrap_or(current.enabled);
    let default_dir = match default_dir {
        Some(v) => v.map(|d| d.to_string()).filter(|d| !d.trim().is_empty()),
        None => current.default_dir.clone(),
    };
    let schedule_cron = match schedule_cron {
        Some(v) => v.map(|c| c.to_string()).filter(|c| !c.trim().is_empty()),
        None => current.schedule_cron.clone(),
    };
    conn.execute(
        "UPDATE queues SET name=?2, enabled=?3, default_dir=?4, schedule_cron=?5,
           updated_at=?6 WHERE id=?1",
        params![
            id,
            name,
            i64::from(enabled),
            default_dir,
            schedule_cron,
            crate::model::now_ms()
        ],
    )
    .map_err(|e| e.to_string())?;
    get(conn, id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "queue_missing".to_string())
}

/// 删除队列：其任务迁入默认队列。默认队列不可删。
pub fn delete(conn: &mut Connection, id: i64) -> Result<usize, String> {
    let queue = get(conn, id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "queue_not_found".to_string())?;
    if queue.is_default() {
        return Err("queue_default_immutable".into());
    }
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let moved = tx
        .execute(
            "UPDATE downloads SET queue_id = ?2 WHERE queue_id = ?1",
            params![id, DEFAULT_QUEUE_ID],
        )
        .map_err(|e| e.to_string())?;
    tx.execute("DELETE FROM queues WHERE id = ?1", [id])
        .map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(moved)
}

/// 把某任务改归到指定队列（只改归属，派发按 id 入队先后）。
pub fn set_download_queue(
    conn: &Connection,
    download_id: i64,
    queue_id: i64,
) -> Result<(), String> {
    if get(conn, queue_id).map_err(|e| e.to_string())?.is_none() {
        return Err("queue_not_found".into());
    }
    conn.execute(
        "UPDATE downloads SET queue_id = ?2 WHERE id = ?1",
        params![download_id, queue_id],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

/// 所有队列的任务计数（排队 / 运行 / 完成 / 失败）。列表页与调度都用它。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QueueCounts {
    pub queued: i64,
    pub running: i64,
    pub done: i64,
    pub failed: i64,
    pub paused: i64,
}

pub fn counts(conn: &Connection, queue_id: i64) -> rusqlite::Result<QueueCounts> {
    let mut counts = QueueCounts::default();
    let mut stmt =
        conn.prepare("SELECT status, COUNT(*) FROM downloads WHERE queue_id = ?1 GROUP BY status")?;
    let rows = stmt.query_map([queue_id], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;
    for row in rows {
        let (status, n) = row?;
        match status.as_str() {
            "queued" => counts.queued += n,
            "connecting" | "downloading" | "verifying" => counts.running += n,
            "done" => counts.done += n,
            "paused" => counts.paused += n,
            _ => counts.failed += n,
        }
    }
    Ok(counts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> Connection {
        crate::open_db(std::path::Path::new(":memory:")).unwrap()
    }

    fn task(conn: &Connection, name: &str) -> i64 {
        crate::model::insert_download(conn, &format!("https://h/{name}"), name, "d", 0, 1).unwrap()
    }

    #[test]
    fn default_queue_exists_and_cannot_be_removed_or_renamed() {
        let mut conn = db();
        let queues = list(&conn).unwrap();
        assert_eq!(queues.len(), 1);
        assert_eq!(queues[0].name, DEFAULT_QUEUE_NAME);
        assert!(queues[0].is_default());
        assert!(queues[0].enabled);
        assert_eq!(
            update(
                &conn,
                DEFAULT_QUEUE_ID,
                Some("renamed"),
                None,
                None,
                None
            ),
            Err("queue_default_immutable".into())
        );
        assert_eq!(
            delete(&mut conn, DEFAULT_QUEUE_ID),
            Err("queue_default_immutable".into())
        );
        // 启用状态可以改（默认队列仍不可改名/删）
        let updated = update(&conn, DEFAULT_QUEUE_ID, None, Some(false), None, None).unwrap();
        assert!(!updated.enabled);
    }

    #[test]
    fn create_rejects_duplicates_and_bad_names() {
        let conn = db();
        assert_eq!(normalize_name("  "), Err("queue_name_empty".into()));
        assert_eq!(
            normalize_name(&"x".repeat(65)),
            Err("queue_name_too_long".into())
        );
        assert_eq!(normalize_name("a\u{7}b"), Err("queue_name_invalid".into()));
        assert_eq!(normalize_name(" 夜晚 ").unwrap(), "夜晚");

        assert_eq!(
            create(&conn, "default", None, None),
            Err("queue_name_taken".into())
        );
        let night = create(&conn, "夜晚", None, None).unwrap();
        assert_eq!(night.name, "夜晚");
        assert_eq!(
            create(&conn, "夜晚", None, None),
            Err("queue_name_taken".into())
        );
    }

    #[test]
    fn membership_follows_moves_and_rejects_unknown_queue() {
        let conn = db();
        let night = create(&conn, "night", None, None).unwrap();
        let a = task(&conn, "a");
        let b = task(&conn, "b");
        let c = task(&conn, "c");
        // 新建任务默认归默认队列。
        assert_eq!(
            crate::model::get_download(&conn, a)
                .unwrap()
                .unwrap()
                .queue_id,
            DEFAULT_QUEUE_ID
        );

        set_download_queue(&conn, b, night.id).unwrap();
        set_download_queue(&conn, c, night.id).unwrap();
        let row = crate::model::get_download(&conn, b).unwrap().unwrap();
        assert_eq!(row.queue_id, night.id, "归属只看 downloads.queue_id");
        let night_counts = counts(&conn, night.id).unwrap();
        assert_eq!(night_counts.queued, 2, "改归属后计数跟着走");
        assert_eq!(counts(&conn, DEFAULT_QUEUE_ID).unwrap().queued, 1);

        assert_eq!(
            set_download_queue(&conn, a, 9999),
            Err("queue_not_found".into())
        );
    }

    #[test]
    fn delete_moves_tasks_to_default_and_keeps_them() {
        let mut conn = db();
        let q = create(&conn, "temp", None, None).unwrap();
        let a = task(&conn, "a");
        set_download_queue(&conn, a, q.id).unwrap();
        let moved = delete(&mut conn, q.id).unwrap();
        assert_eq!(moved, 1);
        assert!(get(&conn, q.id).unwrap().is_none());
        let row = crate::model::get_download(&conn, a).unwrap().unwrap();
        assert_eq!(
            row.queue_id, DEFAULT_QUEUE_ID,
            "任务迁入默认队列而不是被删掉"
        );
    }

    #[test]
    fn counts_group_by_status_within_a_queue() {
        let conn = db();
        let q = create(&conn, "q", None, None).unwrap();
        let running = task(&conn, "r");
        let queued = task(&conn, "q1");
        let failed = task(&conn, "f");
        let done = task(&conn, "d");
        for id in [running, queued, failed, done] {
            set_download_queue(&conn, id, q.id).unwrap();
        }
        crate::model::set_status(&conn, running, crate::model::Status::Downloading, None).unwrap();
        crate::model::set_status(&conn, failed, crate::model::Status::Error, Some("x")).unwrap();
        crate::model::set_status(&conn, done, crate::model::Status::Done, None).unwrap();
        let group = counts(&conn, q.id).unwrap();
        assert_eq!(
            (group.queued, group.running, group.done, group.failed),
            (1, 1, 1, 1)
        );
        assert_eq!(
            counts(&conn, DEFAULT_QUEUE_ID).unwrap(),
            QueueCounts::default()
        );
    }
}

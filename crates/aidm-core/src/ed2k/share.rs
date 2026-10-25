//! 共享文件注册表（L6 上传侧）。
//!
//! 共享范围**只来自本机已完成的 eD2k 任务**：不额外维护"共享目录"这一层状态，
//! 用户删掉任务就不再对外提供该文件，语义与"我下过什么"完全一致。
//!
//! 两条与性能/安全相关的约定：
//! - **不在这里 stat 磁盘**：注册表只回答"记录上有这个哈希吗"，磁盘存在性由真正
//!   要读文件的那一刻判断（否则每次连接都要为所有共享文件做磁盘 IO）。
//! - **分片哈希集落库缓存**：算一次要整读文件（4 GB 文件就是 4 GB 的 MD4），
//!   绝不能每个 `OP_HASHSETREQUEST` 都重算。

use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};

use rusqlite::{params, Connection, OptionalExtension};

use super::hash::{hash_reader, Flavor};
use super::peer::{part_count, EMBLOCKSIZE};

/// 一个对外提供的文件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedFile {
    /// 文件 MD4（eD2k 身份）。
    pub md4: [u8; 16],
    pub size: u64,
    /// 对外宣告的文件名（本机文件名，非法字符在落盘时已被净化）。
    pub name: String,
    /// 本机完整路径。
    pub path: PathBuf,
}

/// 把 32 位十六进制（大小写均可）解成 16 字节 MD4。
pub fn parse_md4_hex(value: &str) -> Option<[u8; 16]> {
    let value = value.trim();
    if value.len() != 32 || !value.is_ascii() {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let s = std::str::from_utf8(chunk).ok()?;
        out[i] = u8::from_str_radix(s, 16).ok()?;
    }
    Some(out)
}

/// 本机已完成的 eD2k 任务 → 共享文件清单（按哈希去重，先出现的胜出）。
pub fn shared_files(conn: &Connection) -> rusqlite::Result<Vec<SharedFile>> {
    let mut stmt = conn.prepare(
        "SELECT ed2k_hash, dir, file_name, size_total FROM downloads
         WHERE status = 'done' AND ed2k_hash IS NOT NULL AND TRIM(ed2k_hash) != ''
         ORDER BY id",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Option<i64>>(3)?,
        ))
    })?;
    let mut out: Vec<SharedFile> = Vec::new();
    for row in rows {
        let (hash_hex, dir, name, size) = row?;
        let Some(md4) = parse_md4_hex(&hash_hex) else {
            continue;
        };
        if out.iter().any(|f| f.md4 == md4) {
            continue;
        }
        let path = Path::new(&dir).join(&name);
        out.push(SharedFile {
            md4,
            size: size.unwrap_or(0).max(0) as u64,
            name,
            path,
        });
    }
    Ok(out)
}

/// 按哈希找共享文件。
pub fn find(conn: &Connection, md4: &[u8; 16]) -> rusqlite::Result<Option<SharedFile>> {
    Ok(shared_files(conn)?.into_iter().find(|f| &f.md4 == md4))
}

/// 一次上传请求可服务的字节区间。
///
/// fail-closed：`end <= start`、越过文件尾、或单块超过 180 KiB 一律拒绝。
/// 不夹取（clamp）到合法区间——夹取会让"对端要 4 GB 我们就读 4 GB"这类请求
/// 看起来成功，不如直接不服务这一块。
pub fn request_range(start: u64, end: u64, file_size: u64) -> Option<(u64, u64)> {
    if end <= start || end > file_size || start >= file_size {
        return None;
    }
    if end - start > EMBLOCKSIZE {
        return None;
    }
    Some((start, end))
}

/// 读回分片哈希集缓存；`size` 不一致视为缓存失效（文件被替换过）。
pub fn cached_part_hashes(
    conn: &Connection,
    md4: &[u8; 16],
    size: u64,
) -> rusqlite::Result<Option<Vec<[u8; 16]>>> {
    let row = conn
        .query_row(
            "SELECT size, parts FROM ed2k_hashsets WHERE md4 = ?1",
            [md4.as_slice()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?;
    let Some((stored_size, blob)) = row else {
        return Ok(None);
    };
    if stored_size.max(0) as u64 != size || blob.len() % 16 != 0 || blob.is_empty() {
        return Ok(None);
    }
    let parts = blob
        .chunks_exact(16)
        .map(|c| {
            let mut h = [0u8; 16];
            h.copy_from_slice(c);
            h
        })
        .collect();
    Ok(Some(parts))
}

pub fn store_part_hashes(
    conn: &Connection,
    md4: &[u8; 16],
    size: u64,
    parts: &[[u8; 16]],
) -> rusqlite::Result<()> {
    let mut blob = Vec::with_capacity(parts.len() * 16);
    for p in parts {
        blob.extend_from_slice(p);
    }
    conn.execute(
        "INSERT INTO ed2k_hashsets(md4, size, parts, updated_at) VALUES(?1, ?2, ?3, ?4)
         ON CONFLICT(md4) DO UPDATE SET size=excluded.size, parts=excluded.parts,
           updated_at=excluded.updated_at",
        params![
            md4.as_slice(),
            size.min(i64::MAX as u64) as i64,
            blob,
            crate::model::now_ms()
        ],
    )?;
    Ok(())
}

/// 整读一遍文件算分片哈希集（顺带得到文件哈希，供调用方与任务记录核对）。
///
/// 返回值里 `parts.len() == part_count(size)`，与 eMule 的 `OP_HASHSETANSWER` 条数一致。
pub fn compute_part_hashes(path: &Path) -> Result<([u8; 16], Vec<[u8; 16]>), String> {
    let file = File::open(path).map_err(|e| format!("open: {e}"))?;
    let digest =
        hash_reader(Flavor::Official, BufReader::new(file)).map_err(|e| format!("hash: {e}"))?;
    Ok((digest.file, digest.parts))
}

/// 共享文件当前是否可读，且长度与记录一致。
///
/// 长度不一致时**不提供**：以另一个文件的内容冒充共享文件，比"我没有这个文件"更糟。
pub fn readable(f: &SharedFile) -> Option<u64> {
    let meta = std::fs::metadata(&f.path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let len = meta.len();
    if f.size > 0 && len != f.size {
        return None;
    }
    Some(len)
}

/// 该文件在 `OP_FILESTATUS` 里应报的分片数（0 = 完整源）。
pub fn part_total(size: u64) -> usize {
    part_count(size)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 临时库 + 临时目录。字段顺序是关键：`Connection` 在前，先于 `TempDir` 析构，
    /// sqlite 关闭后 Windows 才删得掉目录。
    struct TempDb(Connection, tempfile::TempDir);

    impl TempDb {
        fn new(tag: &str) -> Self {
            let tmp = crate::testsupport::tempdir(&format!("share-{tag}"));
            let conn = crate::db::open_db(&tmp.path().join("db.sqlite")).unwrap();
            Self(conn, tmp)
        }

        /// 该用例的工作目录（绝对路径）。
        fn dir(&self) -> &Path {
            self.1.path()
        }
    }

    fn add_done_task(db: &TempDb, hash_hex: &str, name: &str, dir: &Path, size: u64) -> i64 {
        let id = crate::model::insert_download(
            &db.0,
            &format!("ed2k://|file|{name}|{size}|{}|/", hash_hex.to_uppercase()),
            name,
            &dir.to_string_lossy(),
            0,
            1,
        )
        .unwrap();
        crate::model::set_probe_meta(&db.0, id, "ed2k://|file|", Some(size as i64), None, None)
            .unwrap();
        crate::model::set_ed2k_meta(&db.0, id, Some(hash_hex), None).unwrap();
        crate::model::set_status(&db.0, id, crate::model::Status::Done, None).unwrap();
        id
    }

    #[test]
    fn only_completed_ed2k_tasks_are_shared() {
        let db = TempDb::new("shared");
        let data = vec![9u8; 300_000];
        let path = db.dir().join("a.bin");
        std::fs::write(&path, &data).unwrap();
        let (file_hash, parts) = compute_part_hashes(&path).unwrap();
        let hex: String = file_hash.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(parts.len(), part_count(data.len() as u64));

        let id = add_done_task(&db, &hex, "a.bin", db.dir(), data.len() as u64);
        let shared = shared_files(&db.0).unwrap();
        assert_eq!(shared.len(), 1);
        assert_eq!(shared[0].size, data.len() as u64);
        assert!(find(&db.0, &file_hash).unwrap().is_some());
        assert!(readable(&shared[0]).is_some());

        // 未完成的任务不共享
        crate::model::set_status(&db.0, id, crate::model::Status::Error, Some("http_404")).unwrap();
        assert!(shared_files(&db.0).unwrap().is_empty());
        // 非 eD2k 任务不共享
        crate::model::set_status(&db.0, id, crate::model::Status::Done, None).unwrap();
        crate::model::set_ed2k_meta(&db.0, id, None, None).unwrap();
        assert!(shared_files(&db.0).unwrap().is_empty());
    }

    #[test]
    fn hashset_cache_roundtrip_and_size_invalidation() {
        let db = TempDb::new("hashset");
        let md4 = [5u8; 16];
        let parts = vec![[1u8; 16], [2u8; 16]];
        store_part_hashes(&db.0, &md4, 1000, &parts).unwrap();
        assert_eq!(
            cached_part_hashes(&db.0, &md4, 1000).unwrap(),
            Some(parts.clone())
        );
        // 大小变了 → 缓存作废
        assert!(cached_part_hashes(&db.0, &md4, 1001).unwrap().is_none());
        assert!(cached_part_hashes(&db.0, &[9u8; 16], 1000)
            .unwrap()
            .is_none());
        // 覆盖写
        store_part_hashes(&db.0, &md4, 1000, &parts[..1]).unwrap();
        assert_eq!(
            cached_part_hashes(&db.0, &md4, 1000).unwrap(),
            Some(parts[..1].to_vec())
        );
    }

    #[test]
    fn request_range_is_fail_closed() {
        let size = 300_000;
        assert_eq!(request_range(0, 100, size), Some((0, 100)));
        assert_eq!(
            request_range(0, EMBLOCKSIZE, size),
            Some((0, EMBLOCKSIZE)),
            "恰好一块可以"
        );
        assert_eq!(
            request_range(0, EMBLOCKSIZE + 1, size),
            None,
            "超过一块拒绝"
        );
        assert_eq!(request_range(100, 100, size), None, "空区间拒绝");
        assert_eq!(request_range(200, 100, size), None, "倒序拒绝");
        assert_eq!(request_range(0, size + 1, size), None, "越过文件尾拒绝");
        assert_eq!(request_range(size, size + 10, size), None, "起点越界拒绝");
    }

    #[test]
    fn md4_hex_parsing_is_strict() {
        assert_eq!(
            parse_md4_hex("E7C526499308841A4A6D116C857DB669"),
            parse_md4_hex("e7c526499308841a4a6d116c857db669")
        );
        assert!(parse_md4_hex("e7c526499308841a4a6d116c857db66").is_none());
        assert!(parse_md4_hex("zzc526499308841a4a6d116c857db669").is_none());
    }

    #[test]
    fn unreadable_or_size_mismatched_files_are_not_served() {
        let db = TempDb::new("readable");
        let path = db.dir().join("gone.bin");
        std::fs::write(&path, vec![1u8; 10]).unwrap();
        let shared = SharedFile {
            md4: [1u8; 16],
            size: 10,
            name: "gone.bin".into(),
            path: path.clone(),
        };
        assert_eq!(readable(&shared), Some(10));
        // 长度不符（被替换过）→ 不提供
        let wrong = SharedFile {
            size: 11,
            ..shared.clone()
        };
        assert!(readable(&wrong).is_none());
        std::fs::remove_file(&path).unwrap();
        assert!(readable(&shared).is_none());
    }
}

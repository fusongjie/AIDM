//! eMule 信用记录。线上不传积分；UserHash 是主键，字节累计与评分只保存在本机。

use rusqlite::{params, Connection, OptionalExtension};

const MIB: f64 = 1024.0 * 1024.0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditRecord {
    pub user_hash: [u8; 16],
    pub uploaded_bytes: u64,
    pub downloaded_bytes: u64,
    pub public_key: Option<Vec<u8>>,
    /// 0=未验证/不可用，1=已验证。需要挑战/签名的瞬态不落成“已验证”。
    pub identified: bool,
}

/// eMule 0.50a `ClientCredits.cpp::GetScoreRatio`。
///
/// 参数名采用“本机视角”：`downloaded_from_peer` 越多，对方在我方上传队列倍率越高。
pub fn score_ratio(
    uploaded_to_peer: u64,
    downloaded_from_peer: u64,
    identified: bool,
    crypto_available: bool,
) -> f64 {
    if crypto_available && !identified {
        return 1.0;
    }
    let downloaded = downloaded_from_peer as f64;
    if downloaded < MIB {
        return 1.0;
    }
    let ratio = if uploaded_to_peer == 0 {
        10.0
    } else {
        downloaded * 2.0 / uploaded_to_peer as f64
    };
    let max_by_exp = (downloaded / MIB + 2.0).sqrt();
    let max_by_lin = if downloaded < 9_646_899.0 {
        ((downloaded - MIB) / 8_598_323.0) * 2.34 + 1.0
    } else {
        10.0
    };
    ratio.min(max_by_exp).min(max_by_lin).clamp(1.0, 10.0)
}

pub fn queue_score(wait_seconds: u64, ratio: f64, file_priority: u8) -> u64 {
    ((wait_seconds as f64) * ratio.clamp(1.0, 10.0) * (file_priority as f64 / 10.0)).max(0.0) as u64
}

pub fn load(conn: &Connection, hash: &[u8; 16]) -> rusqlite::Result<Option<CreditRecord>> {
    conn.query_row(
        "SELECT uploaded_bytes, downloaded_bytes, public_key, ident_state
         FROM ed2k_credits WHERE user_hash=?1",
        [hash.as_slice()],
        |row| {
            Ok(CreditRecord {
                user_hash: *hash,
                uploaded_bytes: row.get::<_, i64>(0)?.max(0) as u64,
                downloaded_bytes: row.get::<_, i64>(1)?.max(0) as u64,
                public_key: row.get(2)?,
                identified: row.get::<_, i64>(3)? == 1,
            })
        },
    )
    .optional()
}

pub fn add_transfer(
    conn: &Connection,
    hash: &[u8; 16],
    uploaded: u64,
    downloaded: u64,
) -> rusqlite::Result<()> {
    let now = crate::model::now_ms();
    conn.execute(
        "INSERT INTO ed2k_credits(user_hash,uploaded_bytes,downloaded_bytes,updated_at)
         VALUES(?1,?2,?3,?4)
         ON CONFLICT(user_hash) DO UPDATE SET
           uploaded_bytes=MIN(9223372036854775807,uploaded_bytes+excluded.uploaded_bytes),
           downloaded_bytes=MIN(9223372036854775807,downloaded_bytes+excluded.downloaded_bytes),
           updated_at=excluded.updated_at",
        params![
            hash.as_slice(),
            uploaded.min(i64::MAX as u64) as i64,
            downloaded.min(i64::MAX as u64) as i64,
            now
        ],
    )?;
    Ok(())
}

pub fn set_identity(
    conn: &Connection,
    hash: &[u8; 16],
    public_key: &[u8],
    identified: bool,
) -> rusqlite::Result<()> {
    if public_key.is_empty() || public_key.len() > u8::MAX as usize {
        return Err(rusqlite::Error::InvalidParameterName(
            "public_key_length".into(),
        ));
    }
    conn.execute(
        "INSERT INTO ed2k_credits(user_hash,public_key,ident_state,updated_at)
         VALUES(?1,?2,?3,?4)
         ON CONFLICT(user_hash) DO UPDATE SET
           public_key=excluded.public_key, ident_state=excluded.ident_state,
           updated_at=excluded.updated_at",
        params![
            hash.as_slice(),
            public_key,
            i64::from(identified),
            crate::model::now_ms()
        ],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ratios_follow_emule_caps() {
        assert_eq!(score_ratio(0, MIB as u64 - 1, true, true), 1.0);
        assert_eq!(score_ratio(1, 100 * MIB as u64, false, true), 1.0);
        let ratio = score_ratio(0, 100 * MIB as u64, true, true);
        assert!((1.0..=10.0).contains(&ratio));
        assert_eq!(ratio, 10.0);
        assert_eq!(queue_score(100, 2.0, 7), 140);
    }

    #[test]
    fn records_accumulate_locally_by_user_hash() {
        let conn = crate::db::open_db(std::path::Path::new(":memory:")).unwrap();
        let hash = [7; 16];
        add_transfer(&conn, &hash, 10, 20).unwrap();
        add_transfer(&conn, &hash, 30, 40).unwrap();
        set_identity(&conn, &hash, &[3; 32], true).unwrap();
        let record = load(&conn, &hash).unwrap().unwrap();
        assert_eq!((record.uploaded_bytes, record.downloaded_bytes), (40, 60));
        assert_eq!(record.public_key, Some(vec![3; 32]));
        assert!(record.identified);
    }
}

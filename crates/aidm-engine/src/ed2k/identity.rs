//! eMule 信用身份属于配置目录，不能每次重启重新生成。
use aidm_core::ed2k::{hash, peer};
use ring::rand::{SecureRandom, SystemRandom};
use rusqlite::Connection;

const KEY: &str = "internal.ed2k_user_hash";

pub fn load_or_create(conn: &Connection) -> Result<[u8; 16], String> {
    if let Some(value) = aidm_core::settings::get(conn, KEY).map_err(|e| e.to_string())? {
        return hash::parse_hex(&value)
            .filter(peer::is_emule_hash)
            .ok_or_else(|| "ed2k_identity_invalid".into());
    }
    let mut seed = [0; 16];
    SystemRandom::new()
        .fill(&mut seed)
        .map_err(|_| "ed2k_identity_random")?;
    let value = hash::hex(&peer::make_emule_hash(seed));
    conn.execute(
        "INSERT OR IGNORE INTO settings(key,value) VALUES(?1,?2)",
        [KEY, &value],
    )
    .map_err(|e| e.to_string())?;
    let saved = aidm_core::settings::get(conn, KEY)
        .map_err(|e| e.to_string())?
        .ok_or("ed2k_identity_missing")?;
    hash::parse_hex(&saved).ok_or_else(|| "ed2k_identity_invalid".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn persisted_identity_survives_reopen_and_differs_across_profiles() {
        let _tmp = crate::testsupport::tempdir("identity");
        let root = _tmp.path().to_path_buf();
        let conn = aidm_core::open_db(&root.join("first.sqlite")).unwrap();
        let first = load_or_create(&conn).unwrap();
        drop(conn);
        let reopened = aidm_core::open_db(&root.join("first.sqlite")).unwrap();
        assert_eq!(load_or_create(&reopened).unwrap(), first);
        assert!(peer::is_emule_hash(&first));
        let other = aidm_core::open_db(&root.join("other.sqlite")).unwrap();
        assert_ne!(load_or_create(&other).unwrap(), first);
        drop((reopened, other));
        let _ = std::fs::remove_dir_all(root);
    }
}

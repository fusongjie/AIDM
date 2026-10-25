//! eDonkey/eMule **服务器会话**（L3）：登录 → 查源。
//!
//! 按 `docs/ed2k-server-protocol-spec.md` 的实现顺序建议，只做三对消息：
//!
//! | 序 | 发 | 收 | 作用 |
//! |---|---|---|---|
//! | 1 | `0x01 LOGINREQUEST` | `0x40 IDCHANGE` | 登录；拿到分配的 ID、TCP flags、公网 IP、混淆端口 |
//! | 2 | `0x19 GETSOURCES` | `0x42 FOUNDSOURCES` | 按文件哈希查源（count 是 **1 字节**） |
//! | 3 | — | `0x38 SERVERMESSAGE` / `0x34 SERVERSTATUS` | 服务器**不请自来**，必须能收下并跳过 |
//!
//! 不确定的消息一律按帧长跳过——这正是分帧层存在的意义：**绝不能因为不认识某条消息
//! 就让后续字节错位**。
//!
//! 其它可延后的消息（服务器列表 `0x14/0x32/0x41`、搜索 `0x16/0x33`、LowID 回调
//! `0x1C/0x35`、保活 `0x15`、混淆 `0x23/0x44`）本模块只做"能安全跳过"。

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use aidm_core::ed2k::peer::Protocol;
use aidm_core::ed2k::server::{
    self as srv, encode_get_sources, encode_login, op, FoundSources, IdChange, LoginTag,
    ServerStatus, SourceEntry,
};

use super::wire::Conn;

/// 会话参数。
pub struct ServerSessionCfg<'a> {
    pub addr: SocketAddr,
    /// 客户端 UserHash（`[5]=0x0E`、`[14]=0x6F`）。
    pub user_hash: [u8; 16],
    /// 我方 eD2k 监听端口；纯下载端不监听时给 0。
    pub listen_port: u16,
    /// 客户端昵称（登录标签）。
    pub nickname: &'a str,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
}

/// 登录结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginResult {
    pub client_id: u32,
    pub tcp_flags: Option<u32>,
    pub public_ip: Option<Ipv4Addr>,
    pub obfuscation_port: Option<u32>,
    /// 服务器下发的公告（MOTD），已按到达顺序收集。
    pub motd: Vec<String>,
    /// 服务器状态（用户数/文件数）。
    pub status: Option<ServerStatus>,
}

impl LoginResult {
    /// 是否 LowID（`id < 0x01000000`）。
    pub fn is_low_id(&self) -> bool {
        srv::is_low_id(self.client_id)
    }

    pub fn public_ip(&self) -> Option<Ipv4Addr> {
        self.public_ip
    }
}

/// 一个已登录的服务器会话。
pub struct ServerSession {
    conn: Conn,
    logged_in: bool,
    /// 登录时服务器给的公网 IP（LowID 回调要用）。
    public_ip: Option<Ipv4Addr>,
}

impl ServerSession {
    /// 连接（不登录；登录动作显式调用，便于上层决定何时发标签）。
    pub fn connect(cfg: &ServerSessionCfg<'_>) -> Result<Self, String> {
        let conn = Conn::connect(cfg.addr, cfg.connect_timeout, cfg.read_timeout)?;
        Ok(Self {
            conn,
            logged_in: false,
            public_ip: None,
        })
    }

    /// 发送登录请求并等到 `0x40 IDCHANGE`。
    ///
    /// 期间到达的 `0x38`/`0x34` 会被收下；其它未知消息按帧长安全跳过。
    pub fn login(&mut self, cfg: &ServerSessionCfg<'_>) -> Result<LoginResult, String> {
        let tags = vec![
            LoginTag::Str(0x01, cfg.nickname.to_string()), // CT_NAME
            LoginTag::Uint(0x11, 0x3C),                    // CT_VERSION = 60
            LoginTag::Uint(0x20, srv_server_flags()),      // CT_SERVER_FLAGS
            LoginTag::Uint(0xFB, 0x0064_0000),             // CT_EMULE_VERSION = 0.50a
        ];
        let payload = encode_login(&cfg.user_hash, 0, cfg.listen_port, &tags);
        self.conn
            .send(Protocol::Edonkey, op::LOGINREQUEST, &payload)?;

        let mut motd = Vec::new();
        let mut status = None;
        let deadline = Instant::now() + cfg.read_timeout.max(Duration::from_secs(20));
        loop {
            if Instant::now() > deadline {
                return Err("ed2k_login_timeout".into());
            }
            let p = self.conn.recv()?;
            if p.protocol != Protocol::Edonkey {
                continue;
            }
            match p.opcode {
                op::IDCHANGE => {
                    let c =
                        IdChange::decode(&p.payload).map_err(|e| format!("ed2k_idchange: {e}"))?;
                    self.logged_in = true;
                    self.public_ip = c.public_ip;
                    return Ok(LoginResult {
                        client_id: c.client_id,
                        tcp_flags: c.tcp_flags,
                        public_ip: c.public_ip,
                        obfuscation_port: c.obfuscation_port,
                        motd,
                        status,
                    });
                }
                op::REJECT => return Err("ed2k_login_rejected".into()),
                op::SERVERMESSAGE => {
                    if let Ok(m) = srv::decode_server_message(&p.payload) {
                        motd.push(m);
                    }
                }
                op::SERVERSTATUS => {
                    if let Ok(s) = ServerStatus::decode(&p.payload) {
                        status = Some(s);
                    }
                }
                // 服务器可能先推自己的标识/服务器列表：收下即可
                op::SERVERIDENT | op::SERVERLIST | op::DISCONNECT => {}
                _ => {} // 其余按帧长跳过（分帧层已保证不错位）
            }
        }
    }

    /// 按文件哈希查源，取得第一个有效应答批次即返回，避免空闲超时拖延首次连接源。
    pub fn get_sources(
        &mut self,
        file_hash: &[u8; 16],
        file_size: u64,
        wait: Duration,
    ) -> Result<Vec<SourceEntry>, String> {
        if !self.logged_in {
            return Err("ed2k_not_logged_in".into());
        }
        let payload = encode_get_sources(file_hash, file_size);
        self.conn
            .send(Protocol::Edonkey, op::GETSOURCES, &payload)?;

        let mut out: Vec<SourceEntry> = Vec::new();
        let deadline = Instant::now() + wait;
        loop {
            if Instant::now() > deadline {
                break;
            }
            match self.conn.recv_opt() {
                // 对端关闭 / 读超时：视为"没有更多源"，把已拿到的返回
                Ok(None) => break,
                Ok(Some(p)) => {
                    if p.protocol != Protocol::Edonkey {
                        continue;
                    }
                    match p.opcode {
                        op::FOUNDSOURCES => {
                            let fs = FoundSources::decode(&p.payload)
                                .map_err(|e| format!("ed2k_foundsources: {e}"))?;
                            if &fs.file_hash == file_hash {
                                out.extend(fs.sources);
                                break;
                            }
                        }
                        op::FOUNDSOURCES_OBFU => {
                            // 混淆源：格式为 count 个 (ID4+PORT2+cryptopt1[+userhash16])。
                            // 未实现混淆，按帧长跳过（不误读）。
                        }
                        op::SERVERMESSAGE | op::SERVERSTATUS | op::SERVERLIST => {}
                        _ => {}
                    }
                }
                // 只有"读到一半断掉 / 解析失败"才是真错误
                Err(e) => return Err(e),
            }
        }
        // 去重（同一源可能被多条 0x42 重复给出）
        out.sort_by_key(|s| (format!("{}", s.ip), s.port));
        out.dedup();
        Ok(out)
    }

    /// 登录时服务器看到的我方公网 IP（LowID 回调需要）。
    pub fn public_ip(&self) -> Option<Ipv4Addr> {
        self.public_ip
    }
}

/// 登录时声明的服务器能力标志。
///
/// 只声明我们**确实支持**的：整型标签、Unicode、大文件；加密层未实现，故不声明。
fn srv_server_flags() -> u32 {
    use aidm_core::ed2k::server::tcp_flags;
    tcp_flags::NEWTAGS | tcp_flags::UNICODE | tcp_flags::INTTAGS | tcp_flags::LARGEFILES
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 我们声明的是"自己支持的能力"，其中**不得包含未实现的加密层**
    /// —— 谎报加密会让对端用加密连接打过来，我们直接连不上。
    #[test]
    fn declared_flags_do_not_overclaim_crypto() {
        use aidm_core::ed2k::server::tcp_flags;
        let f = srv_server_flags();
        assert_eq!(
            f & tcp_flags::CRYPT_MASK,
            0,
            "未实现加密层，就不得声明 SUPPORT/REQUEST/REQUIRE crypt"
        );
        // 确实支持的几项要在
        assert_ne!(f & tcp_flags::NEWTAGS, 0);
        assert_ne!(f & tcp_flags::UNICODE, 0);
        assert_ne!(f & tcp_flags::INTTAGS, 0);
        assert_ne!(f & tcp_flags::LARGEFILES, 0);
    }
}

//! eD2k 入站上传服务（L6）端到端：真实 socket 走完整应答路径。
//!
//! 覆盖：握手、文件名、分片位图、分片哈希集、排队/上传槽、逐块发送、信用记账，
//! 以及三类 fail-closed（未知哈希 / 越界块 / 未占槽就请求数据）。

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aidm_core::ed2k::peer::{
    ed2k, FileStatus, HelloInfo, Packet, Protocol, RequestParts, SendingPart, EMBLOCKSIZE, PARTSIZE,
};
use aidm_core::ed2k::{credits, hash};
use aidm_engine::ed2k::inbound::{Inbound, KEY_ENABLED, KEY_PORT, KEY_SLOTS, KEY_UPLOAD_KBPS};
use rusqlite::Connection;

const UPLOADER: [u8; 16] = [7; 16];

struct Fixture {
    root: PathBuf,
    db: Arc<Mutex<Connection>>,
    data: Vec<u8>,
    file_hash: [u8; 16],
    name: String,
    service: Arc<Inbound>,
    /// 持有 tempdir：Drop 时自动删除。
    _tmp: tempfile::TempDir,
}

impl Fixture {
    /// 多分片文件（2 片）：分片位图与分片哈希集都会走多条目的路径。
    fn new() -> Self {
        let tmp = common::tempdir("inbound");
        let root = tmp.path().to_path_buf();
        let name = "shared.bin".to_string();
        let data: Vec<u8> = (0..PARTSIZE as usize + EMBLOCKSIZE as usize)
            .map(|i| ((i * 31 + i / 97) % 256) as u8)
            .collect();
        let path = root.join(&name);
        std::fs::write(&path, &data).unwrap();
        let file_hash = hash::hash_reader(hash::Flavor::Official, data.as_slice())
            .unwrap()
            .file;
        let conn = aidm_core::open_db(&root.join("db.sqlite")).unwrap();
        let hex: String = file_hash.iter().map(|b| format!("{b:02x}")).collect();
        let id = aidm_core::model::insert_download(
            &conn,
            &format!("ed2k://|file|{name}|{}|{hex}|/", data.len()),
            &name,
            &root.to_string_lossy(),
            0,
            1,
        )
        .unwrap();
        aidm_core::model::set_probe_meta(
            &conn,
            id,
            "ed2k://|file|",
            Some(data.len() as i64),
            None,
            None,
        )
        .unwrap();
        aidm_core::model::set_ed2k_meta(&conn, id, Some(&hex), None).unwrap();
        aidm_core::model::set_status(&conn, id, aidm_core::model::Status::Done, None).unwrap();
        aidm_core::settings::set(&conn, KEY_ENABLED, "true").unwrap();
        aidm_core::settings::set(&conn, KEY_PORT, "0").unwrap();
        aidm_core::settings::set(&conn, KEY_SLOTS, "2").unwrap();
        aidm_core::settings::set(&conn, KEY_UPLOAD_KBPS, "0").unwrap();
        let db = Arc::new(Mutex::new(conn));
        let service = Inbound::spawn(db.clone(), [9; 16]);
        Self {
            root,
            db,
            data,
            file_hash,
            name,
            service,
            _tmp: tmp,
        }
    }

    fn port(&self) -> u16 {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(port) = self.service.stats().listening_port {
                return port;
            }
            assert!(Instant::now() < deadline, "入站服务未在 10 秒内绑定端口");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn connect(&self) -> Client {
        let stream = TcpStream::connect(("127.0.0.1", self.port())).unwrap();
        stream.set_nodelay(true).ok();
        let mut client = Client { stream };
        client.send(Protocol::Edonkey, ed2k::HELLO, &hello(false));
        let answer = client.expect(ed2k::HELLOANSWER);
        let info = HelloInfo::decode(ed2k::HELLOANSWER, &answer.payload).unwrap();
        assert_eq!(info.tcp_port, self.port(), "HELLOANSWER 要宣告真实监听端口");
        client
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.service.stop();
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn hello(is_answer: bool) -> Vec<u8> {
    let info = HelloInfo {
        user_hash: UPLOADER,
        client_id: 0,
        tcp_port: 0,
        tags: vec![],
        server_ip: 0,
        server_port: 0,
    };
    info.encode(is_answer)
}

struct Client {
    stream: TcpStream,
}

impl Client {
    fn send(&mut self, protocol: Protocol, opcode: u8, payload: &[u8]) {
        self.stream
            .write_all(&Packet::new(protocol, opcode, payload.to_vec()).encode())
            .unwrap();
    }

    fn recv(&mut self) -> Option<Packet> {
        let mut header = [0u8; 6];
        self.stream.read_exact(&mut header).ok()?;
        let (protocol, len, opcode) = Packet::header(&header).unwrap();
        let mut body = vec![0; len];
        self.stream.read_exact(&mut body).unwrap();
        Some(Packet::new(protocol, opcode, body))
    }

    fn expect(&mut self, opcode: u8) -> Packet {
        self.stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let packet = self
            .recv()
            .unwrap_or_else(|| panic!("等待 0x{opcode:02X} 时对端关闭"));
        assert_eq!(
            packet.opcode, opcode,
            "期望 0x{opcode:02X}，收到 0x{:02X}",
            packet.opcode
        );
        packet
    }

    /// 在 `window` 内不该有任何报文（用于 fail-closed 断言）。
    fn expect_silence(&mut self, window: Duration) {
        self.stream.set_read_timeout(Some(window)).unwrap();
        match self.recv() {
            None => {}
            Some(p) => panic!("不该收到报文，却收到 0x{:02X}", p.opcode),
        }
    }
}

#[test]
fn serves_a_shared_completed_task_and_records_credits() {
    let fixture = Fixture::new();
    let mut client = fixture.connect();

    // 1) 文件名
    client.send(Protocol::Edonkey, ed2k::REQUESTFILENAME, &fixture.file_hash);
    let answer = client.expect(ed2k::REQFILENAMEANSWER);
    assert_eq!(&answer.payload[..16], &fixture.file_hash[..]);
    let name_len = u16::from_le_bytes(answer.payload[16..18].try_into().unwrap()) as usize;
    assert_eq!(
        String::from_utf8_lossy(&answer.payload[18..18 + name_len]),
        fixture.name
    );

    // 2) 分片位图：我们是完整源
    client.send(Protocol::Edonkey, ed2k::SETREQFILEID, &fixture.file_hash);
    let status = FileStatus::decode(&client.expect(ed2k::FILESTATUS).payload).unwrap();
    assert_eq!(status.file_hash, fixture.file_hash);
    assert!(status.complete_source);
    // 完整源位不带位图（`complete_source` 一个标志就表示全部可用），
    // 所以解码出来是空表——这正是 eMule 的 `OP_FILESTATUS` 语义。
    assert!(status.parts.is_empty(), "完整源不传位图");

    // 3) 分片哈希集：必须与本地重算一致
    client.send(Protocol::Edonkey, ed2k::HASHSETREQUEST, &fixture.file_hash);
    let answer = client.expect(ed2k::HASHSETANSWER);
    let digest = hash::hash_reader(hash::Flavor::Official, fixture.data.as_slice()).unwrap();
    let count = u16::from_le_bytes(answer.payload[16..18].try_into().unwrap()) as usize;
    assert_eq!(count, digest.parts.len());
    for (i, want) in digest.parts.iter().enumerate() {
        let got = &answer.payload[18 + i * 16..34 + i * 16];
        assert_eq!(got, want, "第 {i} 片哈希");
    }

    // 4) 入队 → 有槽就立刻接受
    client.send(Protocol::Edonkey, ed2k::STARTUPLOADREQ, &fixture.file_hash);
    client.expect(ed2k::ACCEPTUPLOADREQ);

    // 5) 请求第二片的第一块（PARTSIZE 起的偏移，不是 0）
    let start = PARTSIZE;
    let end = PARTSIZE + EMBLOCKSIZE;
    client.send(
        Protocol::Edonkey,
        ed2k::REQUESTPARTS,
        &RequestParts {
            file_hash: fixture.file_hash,
            ranges: vec![aidm_core::ed2k::peer::PartRange { start, end }],
        }
        .encode()
        .unwrap()
        .1,
    );
    let sent =
        SendingPart::decode(ed2k::SENDINGPART, &client.expect(ed2k::SENDINGPART).payload).unwrap();
    assert_eq!(sent.file_hash, fixture.file_hash);
    assert_eq!((sent.start, sent.end), (start, end));
    assert_eq!(
        sent.data,
        fixture.data[start as usize..end as usize],
        "发出的字节必须与共享文件一致"
    );

    // 6) 结束：释放上传槽 + 冲掉信用
    client.send(Protocol::Edonkey, ed2k::END_OF_DOWNLOAD, &fixture.file_hash);
    // 给服务端一点时间做完收尾（释放槽 + 写信用）
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let recorded = {
            let conn = fixture.db.lock().unwrap();
            credits::load(&conn, &UPLOADER)
                .unwrap()
                .map(|r| r.uploaded_bytes)
                .unwrap_or(0)
        };
        if recorded == EMBLOCKSIZE {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "信用未记账：uploaded_bytes={recorded}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let stats = fixture.service.stats();
    assert!(stats.enabled);
    assert_eq!(stats.uploaded_bytes, EMBLOCKSIZE);
    assert_eq!(stats.served_blocks, 1);
    assert_eq!(stats.shared_files, 1);
    assert_eq!(stats.active_sessions, 0, "结束后必须释放上传槽");
}

#[test]
fn unknown_hash_and_oversized_block_fail_closed() {
    let fixture = Fixture::new();
    let mut client = fixture.connect();

    // 未知哈希：明确回答"没有这个文件"，不得假装成功
    let unknown = [0xAB; 16];
    client.send(Protocol::Edonkey, ed2k::REQUESTFILENAME, &unknown);
    let answer = client.expect(ed2k::FILEREQANSNOFIL);
    assert_eq!(&answer.payload[..16], &unknown[..]);

    // 未占上传槽就请求数据：不发数据
    client.send(Protocol::Edonkey, ed2k::STARTUPLOADREQ, &unknown);
    client.expect(ed2k::FILEREQANSNOFIL);
    client.send(
        Protocol::Edonkey,
        ed2k::REQUESTPARTS,
        &RequestParts {
            file_hash: fixture.file_hash,
            ranges: vec![aidm_core::ed2k::peer::PartRange {
                start: 0,
                end: EMBLOCKSIZE,
            }],
        }
        .encode()
        .unwrap()
        .1,
    );
    client.expect_silence(Duration::from_millis(600));
    assert_eq!(
        fixture.service.stats().uploaded_bytes,
        0,
        "没占槽就不能发出任何字节"
    );

    // 占槽后请求超过一块的范围：拒绝，不读出 180 KiB 以上
    client.send(Protocol::Edonkey, ed2k::STARTUPLOADREQ, &fixture.file_hash);
    client.expect(ed2k::ACCEPTUPLOADREQ);
    client.send(
        Protocol::Edonkey,
        ed2k::REQUESTPARTS,
        &RequestParts {
            file_hash: fixture.file_hash,
            ranges: vec![aidm_core::ed2k::peer::PartRange {
                start: 0,
                end: EMBLOCKSIZE + 1,
            }],
        }
        .encode()
        .unwrap()
        .1,
    );
    client.expect_silence(Duration::from_millis(600));
    assert_eq!(fixture.service.stats().uploaded_bytes, 0);
    assert!(fixture.service.stats().rejected_blocks >= 2);
}

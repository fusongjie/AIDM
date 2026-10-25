//! eD2k 消息分帧（对等协议与服务器协议共用）。
//!
//! 帧格式：`protocol(1) | packetlength u32 LE (= 1 + 载荷长度) | opcode(1) | 载荷`。
//!
//! 这一层必须**流式**：一次 `read` 可能读到多条消息，一条消息也可能跨多次 `read`；
//! 服务器还会不请自来地推 `0x38 MOTD`/`0x34 SERVERSTATUS`。所以"读一条完整消息"
//! 是独立单元，上层只按 opcode 分派、对不认识的消息直接跳过。

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use aidm_core::ed2k::peer::{Packet, Protocol};

/// 一条已建立的对等/服务器连接。
pub struct Conn {
    stream: TcpStream,
    buf: Vec<u8>,
}

impl Conn {
    /// 协调器只用于暂停/取消时 shutdown，数据读取仍由唯一会话线程负责。
    pub fn interrupt_handle(&self) -> Result<TcpStream, String> {
        self.stream.try_clone().map_err(|e| e.to_string())
    }

    pub fn connect(
        addr: SocketAddr,
        connect_timeout: Duration,
        read_timeout: Duration,
    ) -> Result<Self, String> {
        let stream = TcpStream::connect_timeout(&addr, connect_timeout)
            .map_err(|e| format!("ed2k_connect: {e}"))?;
        stream
            .set_read_timeout(Some(read_timeout))
            .map_err(|e| e.to_string())?;
        stream
            .set_write_timeout(Some(read_timeout))
            .map_err(|e| e.to_string())?;
        stream.set_nodelay(true).ok();
        Ok(Self {
            stream,
            buf: Vec::new(),
        })
    }

    /// 包住一条**已接受**的连接（入站上传服务用同一个分帧实现）。
    pub fn from_stream(stream: TcpStream, read_timeout: Duration) -> Result<Self, String> {
        stream
            .set_read_timeout(Some(read_timeout))
            .map_err(|e| e.to_string())?;
        stream
            .set_write_timeout(Some(read_timeout))
            .map_err(|e| e.to_string())?;
        stream.set_nodelay(true).ok();
        Ok(Self {
            stream,
            buf: Vec::new(),
        })
    }

    pub fn send(&mut self, protocol: Protocol, opcode: u8, payload: &[u8]) -> Result<(), String> {
        let pkt = Packet::new(protocol, opcode, payload.to_vec());
        self.stream
            .write_all(&pkt.encode())
            .map_err(|e| format!("ed2k_write: {e}"))
    }

    pub fn send_packet(&mut self, pkt: &Packet) -> Result<(), String> {
        self.stream
            .write_all(&pkt.encode())
            .map_err(|e| format!("ed2k_write: {e}"))
    }

    pub fn recv(&mut self) -> Result<Packet, String> {
        let mut header = [0u8; 6];
        self.stream
            .read_exact(&mut header)
            .map_err(|e| format!("ed2k_read_header: {e}"))?;
        let (protocol, payload_len, opcode) =
            Packet::header(&header).map_err(|e| format!("ed2k_header: {e}"))?;
        self.buf.resize(payload_len, 0);
        if payload_len > 0 {
            self.stream
                .read_exact(&mut self.buf)
                .map_err(|e| format!("ed2k_read_payload: {e}"))?;
        }
        Ok(Packet::new(protocol, opcode, self.buf.clone()))
    }

    /// 尽力读一条消息：**对端正常关闭或读超时都返回 `Ok(None)`**。
    ///
    /// 服务器答完就断开是常态，不能当成错误；只有"读到一半断掉"才算错。
    pub fn recv_opt(&mut self) -> Result<Option<Packet>, String> {
        self.recv_maybe(true)
    }

    /// 排队可在帧边界暂时无数据；连接关闭和半包仍然是错误。
    pub fn recv_idle(&mut self) -> Result<Option<Packet>, String> {
        self.recv_maybe(false)
    }

    pub fn set_read_timeout(&self, timeout: Duration) -> Result<(), String> {
        self.stream
            .set_read_timeout(Some(timeout))
            .map_err(|e| e.to_string())
    }

    fn recv_maybe(&mut self, eof_is_none: bool) -> Result<Option<Packet>, String> {
        use std::io::ErrorKind;
        let mut header = [0u8; 6];
        let mut got = 0usize;
        while got < 6 {
            match self.stream.read(&mut header[got..]) {
                Ok(0) if got == 0 && eof_is_none => return Ok(None),
                Ok(0) if got == 0 => return Err("ed2k_read_header: eof".into()),
                Ok(0) => return Err("ed2k_read_header: truncated eof".into()),
                Ok(n) => got += n,
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    if got == 0 {
                        return Ok(None); // 帧边界超时：暂时没有更多数据
                    }
                    return Err("ed2k_read_header: truncated timeout".into());
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(format!("ed2k_read_header: {e}")),
            }
        }
        let (protocol, payload_len, opcode) =
            Packet::header(&header).map_err(|e| format!("ed2k_header: {e}"))?;
        self.buf.resize(payload_len, 0);
        if payload_len > 0 {
            let mut got = 0usize;
            while got < payload_len {
                match self.stream.read(&mut self.buf[got..]) {
                    Ok(0) => return Err("ed2k_read_payload: eof".into()),
                    Ok(n) => got += n,
                    Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                    Err(e) => return Err(format!("ed2k_read_payload: {e}")),
                }
            }
        }
        Ok(Some(Packet::new(protocol, opcode, self.buf.clone())))
    }

    /// 收到指定 opcode 为止（其它消息丢弃）。
    pub fn wait_for(&mut self, opcode: u8, timeout: Duration) -> Result<Packet, String> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if std::time::Instant::now() > deadline {
                return Err(format!("ed2k_wait_timeout: opcode 0x{opcode:02X}"));
            }
            let p = self.recv()?;
            if p.opcode == opcode {
                return Ok(p);
            }
        }
    }
}

//! 目标文件的并发定位写：**不合并**。
//!
//! 下载前把最终文件一次性预分配到目标长度（`set_len`），每个分块用
//! 定位写（Windows `seek_write` / POSIX `pwrite`）直接写进自己的偏移区间。
//! 好处：
//! - 少一遍全量读 + 一遍全量写（6 GB 文件约省 12 GB 磁盘 IO）；
//! - 全部连接共用一个文件句柄，无寻址竞争（定位写不改变文件指针）；
//! - 完成时只需 `rename`，没有 merge 窗口，也不会出现「合并中」这一额外状态。
//!
//! 写线程池把「收包」和「落盘」解耦：连接线程只负责 recv 并把缓冲区投递给
//! 写线程，因此磁盘抖动（NTFS 回写压力、机械盘寻道）不会阻塞 socket 读取、
//! 不会让 TCP 接收窗口关闭。

use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;

use aidm_core::download::control::{WriteGate, WriteLease};
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::fs::FileExt;
#[cfg(windows)]
use std::os::windows::fs::FileExt;

/// 定位写：返回写入字节数（短写由调用方循环）。
#[inline]
fn write_at(file: &File, buf: &[u8], off: u64) -> io::Result<usize> {
    #[cfg(windows)]
    {
        file.seek_write(buf, off)
    }
    #[cfg(unix)]
    {
        file.write_at(buf, off)
    }
}

/// 把文件标记为稀疏。**这是 `create_preallocated` 的全部收益前提。**
///
/// `set_len` 只改 EOF，但 NTFS 的 VDL（有效数据长度）另有一套语义：**文件未标记
/// 稀疏时**，任何超出当前 VDL 的定位写都必须先把 VDL 物理填零到该偏移，代价与
/// 偏移成正比。fastdl 是 N 个段**各自从自己的起点**开始写，所以每个段的首写都要
/// 付这笔钱，而 VDL 是单调高水位 —— **总填充量约等于整个文件**（与段数几乎无关：
/// 8 段 87.5%、64 段 98.4%）。
///
/// 实测同一块 M.2、同一个 15 GiB 目标、4 GiB 处首次定位写 256 KiB：
///
/// | 文件 | 首次写 | 同位置第二次 |
/// |---|---|---|
/// | 未标记稀疏 | **1997.5 ms** | 0.0 ms |
/// | 标记稀疏 | **0.2 ms** | 0.1 ms |
///
/// 标记稀疏后，洞是文件系统层的虚拟零，不需要 VDL 先去"坐实"，因此定位写不再付
/// 填充代价；顺带让磁盘占用从"写入深处即实体化前面全部"变回**按需增长**。
///
/// 失败**不致命**：FAT/exFAT 与部分网络盘不支持稀疏，此时退回原来的行为（慢，
/// 但仍然正确），所以调用方忽略错误。
#[cfg(windows)]
fn set_sparse(file: &File) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::IO::DeviceIoControl;

    /// 允许在任意偏移分配而不先填零，`IOCTL` 码取自 `winioctl.h`。
    const FSCTL_SET_SPARSE: u32 = 0x0009_00C4;

    let mut bytes: u32 = 0;
    // SAFETY: 句柄由 `file` 持有且在本调用期间有效；无输入/输出缓冲（两者均为空），
    // 因此长度参数为 0 且指针为空是 `FSCTL_SET_SPARSE` 的合法用法。
    let ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle() as _,
            FSCTL_SET_SPARSE,
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            0,
            &mut bytes,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// POSIX 的 `ftruncate` 本来就产生稀疏文件，没有对应动作。
#[cfg(not(windows))]
fn set_sparse(_file: &File) -> io::Result<()> {
    Ok(())
}

/// 预分配目标文件。`set_len` 只改元数据（NTFS 上为惰性置零），
/// 因此比「写完再扩」少一次文件系统元数据风暴，也不会碎片化。
///
/// **先设稀疏、再设长度**，顺序不能反（见 [`set_sparse`]）。
pub fn create_preallocated(path: &Path, len: u64) -> io::Result<File> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)?;
    if file.metadata()?.len() != len {
        let _ = set_sparse(&file);
        file.set_len(len)?;
    }
    Ok(file)
}

struct Job {
    buf: Vec<u8>,
    len: usize,
    off: u64,
}

/// 缓冲区自由表：`Mutex<Vec<_>> + Condvar`。
///
/// 不用 `mpsc::Receiver` 是因为它不实现 `Sync`，而缓冲池要被所有连接线程共享；
/// `Condvar::wait_timeout` 在等待时会释放锁，因此不会把并发取缓冲区串行化。
struct FreeList {
    bufs: Mutex<Vec<Vec<u8>>>,
    cv: Condvar,
    closed: AtomicBool,
}

impl FreeList {
    fn new(cap: usize, buf_size: usize) -> Arc<Self> {
        let mut bufs = Vec::with_capacity(cap);
        for _ in 0..cap {
            bufs.push(vec![0u8; buf_size]);
        }
        Arc::new(Self {
            bufs: Mutex::new(bufs),
            cv: Condvar::new(),
            closed: AtomicBool::new(false),
        })
    }

    fn acquire(&self) -> Option<Vec<u8>> {
        let mut g = self.bufs.lock().unwrap();
        loop {
            if let Some(b) = g.pop() {
                return Some(b);
            }
            if self.closed.load(Ordering::SeqCst) {
                return None;
            }
            let (ng, _) = self.cv.wait_timeout(g, Duration::from_millis(200)).unwrap();
            g = ng;
        }
    }

    fn release(&self, buf: Vec<u8>) {
        self.bufs.lock().unwrap().push(buf);
        self.cv.notify_one();
    }

    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.cv.notify_all();
    }
}

/// 写线程池：`threads` 个写线程；提交时按分块下标分片，同一分块固定落到同一线程，
/// 保持每个文件区域的写顺序，同时让不同分块并行落盘。
pub struct WritePool {
    senders: Vec<SyncSender<Job>>,
    free: Arc<FreeList>,
    buf_size: usize,
    written: Arc<AtomicU64>,
    err: Arc<Mutex<Option<String>>>,
    shutdown: Arc<AtomicBool>,
    handles: Mutex<Vec<JoinHandle<()>>>,
    /// 在途任务数（提交 +1、落盘完成 -1），用于 `drain` 静默
    pending: Arc<AtomicUsize>,
    idle: Arc<(Mutex<()>, Condvar)>,
    /// 累计"在 `submit` 上等队列腾位"的毫秒数与次数（见 [`WritePool::submit_wait`]）。
    submit_wait_ms: Arc<AtomicU64>,
    submit_wait_n: Arc<AtomicU64>,
    /// 写入许可。`None` 表示不启用闸门（只用于不涉及真实下载的夹具）。
    ///
    /// 检查点在**写线程**里、真正 `write_at` 之前：这是唯一能保证
    /// “撤销之后不再落盘”的位置。放在 `submit` 处不够——任务可能已经排在队列里。
    gate: Option<Arc<WriteGate>>,
    lease: Option<WriteLease>,
    /// 因许可失效被拒写的任务数（诊断用）。
    denied: Arc<AtomicU64>,
}

impl WritePool {
    /// `threads` 个写线程、每线程 `queue` 个在途任务、缓冲区 `buf_size` 字节。
    /// `min_buffers` 保证缓冲池容量不小于同时在跑的连接数，避免 acquire 成为串行点。
    pub fn new(
        file: Arc<File>,
        threads: usize,
        queue: usize,
        buf_size: usize,
        min_buffers: usize,
    ) -> Self {
        Self::new_guarded(file, threads, queue, buf_size, min_buffers, None, None)
    }

    /// 带写入许可的构造。`gate`/`lease` 同时为 `Some` 时才做写盘检查。
    pub fn new_guarded(
        file: Arc<File>,
        threads: usize,
        queue: usize,
        buf_size: usize,
        min_buffers: usize,
        gate: Option<Arc<WriteGate>>,
        lease: Option<WriteLease>,
    ) -> Self {
        let threads = threads.max(1);
        let queue = queue.max(1);
        let cap = (threads * queue + threads).max(min_buffers + threads);
        let free = FreeList::new(cap, buf_size);
        let written = Arc::new(AtomicU64::new(0));
        let err = Arc::new(Mutex::new(None));
        let shutdown = Arc::new(AtomicBool::new(false));
        let pending = Arc::new(AtomicUsize::new(0));
        let idle = Arc::new((Mutex::new(()), Condvar::new()));
        let submit_wait_ms = Arc::new(AtomicU64::new(0));
        let submit_wait_n = Arc::new(AtomicU64::new(0));
        let denied = Arc::new(AtomicU64::new(0));
        let mut senders = Vec::with_capacity(threads);
        let mut handles = Vec::with_capacity(threads);
        for t in 0..threads {
            let (tx, rx) = sync_channel::<Job>(queue);
            senders.push(tx);
            let file = file.clone();
            let free = free.clone();
            let written = written.clone();
            let err = err.clone();
            let shutdown = shutdown.clone();
            let pending = pending.clone();
            let idle = idle.clone();
            let gate = gate.clone();
            let lease = lease.clone();
            let denied = denied.clone();
            let h = std::thread::Builder::new()
                .name(format!("aidm-write-{t}"))
                .stack_size(256 * 1024)
                .spawn(move || {
                    writer_loop(
                        file, rx, free, written, err, shutdown, pending, idle, gate, lease, denied,
                    )
                })
                .expect("spawn writer");
            handles.push(h);
        }
        Self {
            senders,
            free,
            buf_size,
            written,
            err,
            shutdown,
            handles: Mutex::new(handles),
            pending,
            idle,
            submit_wait_ms,
            submit_wait_n,
            gate,
            lease,
            denied,
        }
    }

    /// 因写入许可失效被拒写的任务数（诊断/验收用）。
    pub fn denied_writes(&self) -> u64 {
        self.denied.load(Ordering::Relaxed)
    }

    /// 等待已提交的定位写全部落盘。
    ///
    /// 哈希流水线要读「已完成前缀」，必须确认那段字节真的写到磁盘上了；
    /// 写线程是异步的，`plan.next` 只代表「已提交」而不是「已落盘」。
    pub fn drain(&self) {
        if self.pending.load(Ordering::Acquire) == 0 {
            return;
        }
        let (lock, cv) = &*self.idle;
        let mut g = lock.lock().unwrap();
        while self.pending.load(Ordering::Acquire) != 0 {
            let (ng, _) = cv.wait_timeout(g, Duration::from_millis(20)).unwrap();
            g = ng;
        }
    }

    /// 借一个空缓冲区（池空则等待写线程归还）。
    pub fn acquire(&self) -> Option<Vec<u8>> {
        self.free.acquire()
    }

    pub fn buf_size(&self) -> usize {
        self.buf_size
    }

    /// 投递一次落盘。缓冲区所有权转移给写线程，写完后自动回收。
    ///
    /// **这里是 worker 一个容易被忽略的停顿点**：`senders` 是有界
    /// `sync_channel`，队列满时 `send` 会直接阻塞；写线程卡在深偏移定位写上时，
    /// `write_stall`（挂在 `acquire()` 上）不会增长。
    /// 等待会计进 [`WritePool::submit_wait`]，便于观测。
    pub fn submit(&self, buf: Vec<u8>, len: usize, off: u64, shard: usize) -> bool {
        if self.shutdown.load(Ordering::Relaxed) {
            return false;
        }
        if self.failed() {
            return false;
        }
        let s = &self.senders[shard % self.senders.len()];
        self.pending.fetch_add(1, Ordering::AcqRel);
        let t = Instant::now();
        let sent = s.send(Job { buf, len, off });
        let waited = t.elapsed().as_millis() as u64;
        if waited > 0 {
            self.submit_wait_n.fetch_add(1, Ordering::Relaxed);
            self.submit_wait_ms.fetch_add(waited, Ordering::Relaxed);
        }
        if sent.is_err() {
            self.pending.fetch_sub(1, Ordering::AcqRel);
            return false;
        }
        true
    }

    /// `(次数, 累计毫秒)`：worker 在 `submit` 上等队列腾位的合计。
    ///
    /// 与 `write_stall`（等空缓冲）合起来才覆盖完整的写盘回压：两者都非零说明缓冲池
    /// 和写队列同时饱和，**瓶颈在磁盘**；只有这里非零则说明缓冲还够、是**写队列**
    /// 先满 —— 后一种正是"一个深偏移写卡住全部连接"的形状。
    pub fn submit_wait(&self) -> (u64, u64) {
        (
            self.submit_wait_n.load(Ordering::Relaxed),
            self.submit_wait_ms.load(Ordering::Relaxed),
        )
    }

    pub fn written(&self) -> u64 {
        self.written.load(Ordering::Relaxed)
    }

    pub fn failed(&self) -> bool {
        self.err.lock().map(|g| g.is_some()).unwrap_or(true)
    }

    pub fn error(&self) -> Option<String> {
        self.err.lock().ok().and_then(|g| g.clone())
    }

    /// 让写线程把队列排空后退出并汇合；返回写失败原因（若有）。
    pub fn finish(&self) -> Option<String> {
        self.shutdown.store(true, Ordering::SeqCst);
        let mut hs = self.handles.lock().unwrap();
        for h in hs.drain(..) {
            let _ = h.join();
        }
        self.free.close();
        self.error()
    }
}

impl Drop for WritePool {
    fn drop(&mut self) {
        // 兜底：即便调用方忘了 finish，也不要留下悬挂线程。
        self.shutdown.store(true, Ordering::SeqCst);
        self.free.close();
        if let Ok(mut hs) = self.handles.lock() {
            for h in hs.drain(..) {
                let _ = h.join();
            }
        }
    }
}

fn writer_loop(
    file: Arc<File>,
    rx: Receiver<Job>,
    free: Arc<FreeList>,
    written: Arc<AtomicU64>,
    err: Arc<Mutex<Option<String>>>,
    shutdown: Arc<AtomicBool>,
    pending: Arc<AtomicUsize>,
    idle: Arc<(Mutex<()>, Condvar)>,
    gate: Option<Arc<WriteGate>>,
    lease: Option<WriteLease>,
    denied: Arc<AtomicU64>,
) {
    loop {
        // 关闭时把已入队任务处理完再退出（先排空，再看关闭标志）。
        let job = match rx.recv_timeout(Duration::from_millis(50)) {
            Ok(j) => j,
            Err(RecvTimeoutError::Timeout) => {
                if shutdown.load(Ordering::SeqCst) {
                    break;
                }
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => break,
        };
        if err.lock().map(|g| g.is_some()).unwrap_or(true) {
            free.release(job.buf);
            finish_job(&pending, &idle);
            continue;
        }
        // 唯一真实写盘检查点。
        //
        // 放在写线程的 `write_at` 之前，而不是 `submit` 处：任务可能已经在队列里，
        // 只在提交时检查的话，撤销之后它们仍然会落盘。
        // 票据只覆盖这一次写，撤销的静止等待因此是毫秒级。
        let _ticket = match (&gate, &lease) {
            (Some(gate), Some(lease)) => {
                let at = job.off;
                match gate.check(lease, at, at + job.len as u64) {
                    Ok(t) => Some(t),
                    Err(_) => {
                        denied.fetch_add(1, Ordering::Relaxed);
                        set_err(&err, "write_denied: lease_revoked");
                        free.release(job.buf);
                        finish_job(&pending, &idle);
                        continue;
                    }
                }
            }
            _ => None,
        };
        let mut done = 0usize;
        while done < job.len {
            match write_at(&file, &job.buf[done..job.len], job.off + done as u64) {
                Ok(0) => {
                    set_err(&err, "write: 0 bytes");
                    break;
                }
                Ok(n) => {
                    done += n;
                    written.fetch_add(n as u64, Ordering::Relaxed);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    set_err(&err, &format!("write: {e}"));
                    break;
                }
            }
        }
        free.release(job.buf);
        finish_job(&pending, &idle);
    }
}

fn finish_job(pending: &AtomicUsize, idle: &(Mutex<()>, Condvar)) {
    if pending.fetch_sub(1, Ordering::AcqRel) == 1 {
        let (lock, cv) = idle;
        let _g = lock.lock().unwrap();
        cv.notify_all();
    }
}

fn set_err(err: &Mutex<Option<String>>, msg: &str) {
    let mut g = err.lock().unwrap();
    if g.is_none() {
        *g = Some(msg.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 返回 `(目录, TempDir)`：`TempDir` 必须由调用者持有到用例结束。
    fn tmpdir(_tag: &str) -> (std::path::PathBuf, tempfile::TempDir) {
        let tmp = crate::testsupport::tempdir("wpool");
        let dir = tmp.path().to_path_buf();
        (dir, tmp)
    }

    #[test]
    fn concurrent_positional_writes_land_at_offsets() {
        let (dir, _tmp) = tmpdir("a");
        let path = dir.join("t.bin");
        let buf_size = 4096;
        let blocks = 64usize;
        let file = Arc::new(create_preallocated(&path, (blocks * buf_size) as u64).unwrap());
        let pool = WritePool::new(file.clone(), 3, 2, buf_size, 4);
        for b in 0..blocks {
            let mut buf = pool.acquire().unwrap();
            buf.iter_mut().for_each(|x| *x = b as u8);
            assert!(pool.submit(buf, buf_size, (b * buf_size) as u64, b % 3));
        }
        assert!(pool.finish().is_none());
        assert_eq!(pool.written(), (blocks * buf_size) as u64);
        let data = std::fs::read(&path).unwrap();
        assert_eq!(data.len(), blocks * buf_size);
        for b in 0..blocks {
            assert!(
                data[b * buf_size..(b + 1) * buf_size]
                    .iter()
                    .all(|&x| x == b as u8),
                "block {b} misplaced"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn finish_drains_queued_jobs() {
        let (dir, _tmp) = tmpdir("b");
        let path = dir.join("t2.bin");
        let buf_size = 8192;
        let n = 128usize;
        let file = Arc::new(create_preallocated(&path, (n * buf_size) as u64).unwrap());
        let pool = WritePool::new(file.clone(), 2, 8, buf_size, 2);
        for b in 0..n {
            let mut buf = pool.acquire().unwrap();
            buf.iter_mut().for_each(|x| *x = (b % 251) as u8);
            pool.submit(buf, buf_size, (b * buf_size) as u64, b);
        }
        assert!(pool.finish().is_none(), "排队任务必须全部落盘后才退出");
        assert_eq!(pool.written(), (n * buf_size) as u64);
        let data = std::fs::read(&path).unwrap();
        for b in 0..n {
            assert!(data[b * buf_size..(b + 1) * buf_size]
                .iter()
                .all(|&x| x == (b % 251) as u8));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn preallocated_file_has_full_length_before_writes() {
        let (dir, _tmp) = tmpdir("c");
        let path = dir.join("t3.bin");
        let f = create_preallocated(&path, 1 << 20).unwrap();
        assert_eq!(f.metadata().unwrap().len(), 1 << 20);
        drop(f);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 预分配的目标文件必须是**稀疏**的：没写过的洞不能实体化。
    ///
    /// 判据来自文件系统本身（`FSCTL_QUERY_ALLOCATED_RANGES` 问"哪些区间真的占了
    /// 盘"），**不依赖计时**，所以在任何机器上都稳定。未标记稀疏时，在 1 GiB 处写
    /// 一块会把前面 1 GiB 一并实体化 —— NTFS 必须先把 VDL 填到那个偏移，这正是
    /// 用户看到的"启动后十几秒极低速率"。
    #[cfg(windows)]
    #[test]
    fn preallocated_target_keeps_the_unwritten_gap_unallocated() {
        use std::os::windows::fs::FileExt;
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::IO::DeviceIoControl;

        const FSCTL_QUERY_ALLOCATED_RANGES: u32 = 0x0009_40CF;

        #[repr(C)]
        #[derive(Clone, Copy, Default, Debug)]
        struct Range {
            offset: i64,
            length: i64,
        }

        let (dir, _tmp) = tmpdir("sparse");
        let path = dir.join("deep.bin");
        // 只写 1 GiB 处的一个块：文件逻辑长度 1 GiB+，实际占用应远小于 1 MiB。
        let deep = 1u64 << 30;
        let block = 256 * 1024usize;
        let file = create_preallocated(&path, deep + block as u64).unwrap();
        file.seek_write(&vec![0x5Au8; block], deep).unwrap();
        file.sync_all().unwrap();

        let query = Range {
            offset: 0,
            length: (deep + block as u64) as i64,
        };
        let mut out = [Range::default(); 16];
        let mut bytes: u32 = 0;
        let ok = unsafe {
            DeviceIoControl(
                file.as_raw_handle() as _,
                FSCTL_QUERY_ALLOCATED_RANGES,
                &query as *const Range as *const _,
                std::mem::size_of::<Range>() as u32,
                out.as_mut_ptr() as *mut _,
                std::mem::size_of_val(&out) as u32,
                &mut bytes,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(
            ok,
            0,
            "FSCTL_QUERY_ALLOCATED_RANGES 失败: {}",
            std::io::Error::last_os_error()
        );

        let ranges = &out[..bytes as usize / std::mem::size_of::<Range>()];
        assert!(!ranges.is_empty(), "至少应有一个已分配区间");
        assert_eq!(
            ranges[0].offset, deep as i64,
            "1 GiB 之前必须仍是洞，但第一个已分配区间是 {:?} —— 说明稀疏标志没生效，\
             NTFS 已经为了写入深处把前面的洞实体化了",
            ranges[0]
        );
        drop(file);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 队列满时在 `submit` 上等待，必须被记进 `submit_wait()`。
    ///
    /// 这条埋点补一个缺失的观测点：队列满时 `write_stall`（挂在 `acquire()` 上）
    /// 不增长，只看它就看不到写队列阻塞。
    ///
    /// 复现的关键是**并发**而不是总量：事故里是 68 个 worker 同时投递、而写队列只装
    /// 得下 `4 × 3 = 12` 个。单线程串行投递是复现不出来的 —— `acquire()` 会先把主线程
    /// 挡在缓冲池上，等于自带限流（这一点本身就说明"缓冲池够大时队列不会满"）。
    /// 所以这里让 8 个线程各持一个缓冲，同时往深度 1 的单线程队列里投。
    #[test]
    fn submit_wait_is_recorded_once_the_write_queue_fills() {
        let (dir, _tmp) = tmpdir("submit-wait");
        let path = dir.join("q.bin");
        let buf_size = 1 << 20;
        let threads = 8usize;
        let per_thread = 4usize;
        let total = threads * per_thread;
        let file = Arc::new(create_preallocated(&path, (total * buf_size) as u64).unwrap());
        // 缓冲 9 个（`max(1*1+1, 8+1)`）> 队列槽位 1 个 ⇒ 并发投递必然有人等在 `send` 上。
        let pool = Arc::new(WritePool::new(file.clone(), 1, 1, buf_size, threads));

        let mut hs = Vec::new();
        for t in 0..threads {
            let pool = pool.clone();
            hs.push(std::thread::spawn(move || {
                for b in 0..per_thread {
                    let mut buf = pool.acquire().unwrap();
                    buf[0] = b as u8;
                    // 等队列不等于失败：落盘仍然必须成功。
                    assert!(pool.submit(
                        buf,
                        buf_size,
                        ((t * per_thread + b) * buf_size) as u64,
                        0
                    ));
                }
            }));
        }
        for h in hs {
            h.join().unwrap();
        }
        assert!(pool.finish().is_none(), "全部块都必须落盘");
        assert_eq!(pool.written(), (total * buf_size) as u64);

        let (cnt, ms) = pool.submit_wait();
        assert!(
            cnt > 0,
            "写队列满时的 submit 等待必须被记录，否则这条路径又是盲区（实测 {cnt} 次 / {ms} ms）"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

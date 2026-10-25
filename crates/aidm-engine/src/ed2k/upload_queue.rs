//! eD2k 上传槽调度纯逻辑。TCP 监听器可把 `OP_STARTUPLOADREQ` 映射为 `enqueue`，
//! 用 `ranking_packet` 推送固定 12 字节排名，并在 `grant_next` 后发送上传槽。

use std::collections::{HashMap, HashSet};

use aidm_core::ed2k::credits;
use aidm_core::ed2k::peer::{emule, Packet, Protocol, QueueRanking};

#[derive(Debug, Clone)]
struct Waiting {
    user_hash: [u8; 16],
    wait_seconds: u64,
    credit_ratio: f64,
    file_priority: u8,
    sequence: u64,
}

#[derive(Debug)]
pub struct UploadQueue {
    max_waiting: usize,
    max_slots: usize,
    next_sequence: u64,
    waiting: HashMap<[u8; 16], Waiting>,
    active: HashSet<[u8; 16]>,
}

impl UploadQueue {
    pub fn new(max_waiting: usize, max_slots: usize) -> Self {
        Self {
            max_waiting: max_waiting.max(1),
            max_slots: max_slots.max(1),
            next_sequence: 0,
            waiting: HashMap::new(),
            active: HashSet::new(),
        }
    }

    /// 设置变更后调整上限。**不驱逐已在排队/已占槽的连接**：
    /// 用户改设置不该把已经等了几分钟的对端踢下线；新上限只对后续准入生效。
    pub fn set_limits(&mut self, max_waiting: usize, max_slots: usize) {
        self.max_waiting = max_waiting.max(1);
        self.max_slots = max_slots.max(1);
    }

    pub fn waiting(&self) -> usize {
        self.waiting.len()
    }

    pub fn active(&self) -> usize {
        self.active.len()
    }

    /// 该用户哈希是否已占上传槽（别的会话的轮询可能已经放行了它）。
    pub fn is_active(&self, user_hash: &[u8; 16]) -> bool {
        self.active.contains(user_hash)
    }

    /// 队列里是否已有该用户（用于区分"首次入队"与"刷新等待时长"）。
    pub fn is_waiting(&self, user_hash: &[u8; 16]) -> bool {
        self.waiting.contains_key(user_hash)
    }

    pub fn enqueue(
        &mut self,
        user_hash: [u8; 16],
        wait_seconds: u64,
        credit_ratio: f64,
        file_priority: u8,
    ) -> Option<u16> {
        if self.active.contains(&user_hash) {
            return Some(0);
        }
        if !self.waiting.contains_key(&user_hash) && self.waiting.len() >= self.max_waiting {
            return None;
        }
        let sequence = self
            .waiting
            .get(&user_hash)
            .map(|entry| entry.sequence)
            .unwrap_or_else(|| {
                let current = self.next_sequence;
                self.next_sequence = self.next_sequence.wrapping_add(1);
                current
            });
        self.waiting.insert(
            user_hash,
            Waiting {
                user_hash,
                wait_seconds,
                credit_ratio,
                file_priority,
                sequence,
            },
        );
        self.rank(&user_hash)
    }

    fn ordered(&self) -> Vec<&Waiting> {
        let mut entries: Vec<_> = self.waiting.values().collect();
        entries.sort_by(|a, b| {
            let a_score = credits::queue_score(a.wait_seconds, a.credit_ratio, a.file_priority);
            let b_score = credits::queue_score(b.wait_seconds, b.credit_ratio, b.file_priority);
            b_score.cmp(&a_score).then(a.sequence.cmp(&b.sequence))
        });
        entries
    }

    pub fn rank(&self, user_hash: &[u8; 16]) -> Option<u16> {
        self.ordered()
            .iter()
            .position(|entry| &entry.user_hash == user_hash)
            .and_then(|position| u16::try_from(position + 1).ok())
    }

    pub fn ranking_packet(&self, user_hash: &[u8; 16]) -> Option<Packet> {
        let rank = self.rank(user_hash)?;
        Some(Packet::new(
            Protocol::Emule,
            emule::QUEUERANKING,
            QueueRanking { rank }.encode(),
        ))
    }

    pub fn grant_next(&mut self) -> Option<[u8; 16]> {
        if self.active.len() >= self.max_slots {
            return None;
        }
        let user_hash = self.ordered().first()?.user_hash;
        self.waiting.remove(&user_hash);
        self.active.insert(user_hash);
        Some(user_hash)
    }

    pub fn release(&mut self, user_hash: &[u8; 16]) -> bool {
        self.active.remove(user_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aidm_core::ed2k::peer::Packet;

    #[test]
    fn credit_score_orders_queue_and_slots_are_bounded() {
        let mut queue = UploadQueue::new(3, 1);
        let ordinary = [1; 16];
        let credited = [2; 16];
        assert_eq!(queue.enqueue(ordinary, 100, 1.0, 7), Some(1));
        assert_eq!(queue.enqueue(credited, 100, 3.0, 7), Some(1));
        assert_eq!(queue.rank(&ordinary), Some(2));
        let packet = queue.ranking_packet(&ordinary).unwrap().encode();
        let decoded = Packet::decode(&packet).unwrap();
        assert_eq!(decoded.payload.len(), 12);
        assert_eq!(queue.grant_next(), Some(credited));
        assert_eq!(queue.grant_next(), None, "只有一个上传槽");
        assert!(queue.release(&credited));
        assert_eq!(queue.grant_next(), Some(ordinary));
    }

    #[test]
    fn queue_limit_fails_closed() {
        let mut queue = UploadQueue::new(1, 1);
        assert_eq!(queue.enqueue([1; 16], 1, 1.0, 7), Some(1));
        assert_eq!(queue.enqueue([2; 16], 1, 1.0, 7), None);
    }
}

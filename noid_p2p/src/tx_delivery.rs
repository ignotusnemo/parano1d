// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Coalesce byte-identical direct/gossip deliveries before admission quotas.
//! This is bounded transport bookkeeping, never a transaction-validity cache.
//! Only node-side admission can mark an exact payload accepted for forwarding.

use libp2p::{
    gossipsub::{MessageAcceptance, MessageId},
    PeerId,
};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

const MAX_TRACKED: usize = 1024;
const ACCEPTED_TTL: Duration = Duration::from_secs(30);
pub(crate) type PayloadKey = [u8; 32];
type Gossip = (MessageId, PeerId);
pub(crate) type Resolution = (MessageId, PeerId, MessageAcceptance);

/// Nonblocking completion capability for one exact inbound payload. Clones
/// share one decision. Dropping an unconsumed event cannot strand the cache.
#[derive(Clone, Debug)]
pub struct TxDelivery {
    state: Arc<AtomicU8>,
    txid: Arc<std::sync::OnceLock<[u8; 32]>>,
    notify: Arc<tokio::sync::Notify>,
}

impl TxDelivery {
    pub fn admitted(&self, txid: [u8; 32]) {
        let _ = self.txid.set(txid);
        self.complete(MessageAcceptance::Accept);
    }

    pub fn complete(&self, acceptance: MessageAcceptance) {
        let value = match acceptance {
            MessageAcceptance::Accept if self.txid.get().is_some() => 1,
            MessageAcceptance::Accept => 3,
            MessageAcceptance::Reject => 2,
            MessageAcceptance::Ignore => 3,
        };
        let _ = self
            .state
            .compare_exchange(0, value, Ordering::Release, Ordering::Relaxed);
        self.notify.notify_one();
    }
}

struct Entry {
    state: Arc<AtomicU8>,
    txid: Arc<std::sync::OnceLock<[u8; 32]>>,
    gossip: Option<Gossip>,
    accepted_until: Option<Instant>,
}

#[derive(Default)]
pub(crate) struct TxDeliveries {
    entries: HashMap<PayloadKey, Entry>,
    notify: Arc<tokio::sync::Notify>,
}

impl TxDeliveries {
    fn make_room(&mut self) -> bool {
        if self.entries.len() < MAX_TRACKED {
            return true;
        }
        // A full cache of completed transactions must not obstruct fresh
        // payments after a block frees mempool slots. Only completed entries
        // without an unresolved gossip notification are disposable.
        let oldest = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.gossip.is_none() && entry.state.load(Ordering::Acquire) == 1)
            .min_by_key(|(_, entry)| entry.accepted_until)
            .map(|(key, _)| *key);
        if let Some(key) = oldest {
            self.entries.remove(&key);
        }
        self.entries.len() < MAX_TRACKED
    }
    pub(crate) fn notifier(&self) -> Arc<tokio::sync::Notify> {
        self.notify.clone()
    }
    pub(crate) fn key(bytes: &[u8]) -> PayloadKey {
        // Cheap transient exact-payload deduplication, not a consensus hash,
        // txid, authorization shortcut or peer-supplied identifier.
        *blake3::hash(bytes).as_bytes()
    }

    pub(crate) fn admitted_id(&self, key: &PayloadKey) -> Option<[u8; 32]> {
        let entry = self.entries.get(key)?;
        (entry.state.load(Ordering::Acquire) == 1)
            .then(|| entry.txid.get().copied())
            .flatten()
    }

    pub(crate) fn forget_admitted(&mut self, key: &PayloadKey) -> Option<Resolution> {
        self.admitted_id(key)?;
        self.entries
            .remove(key)?
            .gossip
            .map(|(id, peer)| (id, peer, MessageAcceptance::Ignore))
    }

    pub(crate) fn duplicate(&mut self, key: &PayloadKey, gossip: Option<Gossip>) -> bool {
        let Some(entry) = self.entries.get_mut(key) else {
            return false;
        };
        // Content-addressed gossipsub emits one message ID for these bytes.
        // Keep the first forwarding source until its validation is resolved.
        if entry.gossip.is_none() {
            entry.gossip = gossip;
        }
        true
    }

    pub(crate) fn start(&mut self, key: PayloadKey, gossip: Option<Gossip>) -> Option<TxDelivery> {
        if self.entries.contains_key(&key) || !self.make_room() {
            return None;
        }
        let state = Arc::new(AtomicU8::new(0));
        let txid = Arc::new(std::sync::OnceLock::new());
        self.entries.insert(
            key,
            Entry {
                state: state.clone(),
                txid: txid.clone(),
                gossip,
                accepted_until: None,
            },
        );
        Some(TxDelivery {
            state,
            txid,
            notify: self.notify.clone(),
        })
    }

    /// BroadcastTx is emitted only for the byte-exact intent the mempool has
    /// admitted. It may race the return of that same node-side submission.
    pub(crate) fn admitted(&mut self, key: PayloadKey, txid: [u8; 32], now: Instant) {
        if let Some(entry) = self.entries.get_mut(&key) {
            let _ = entry.txid.set(txid);
            entry.state.store(1, Ordering::Release);
            entry.accepted_until = Some(now + ACCEPTED_TTL);
        } else if self.make_room() {
            self.entries.insert(
                key,
                Entry {
                    state: Arc::new(AtomicU8::new(1)),
                    txid: Arc::new(std::sync::OnceLock::from(txid)),
                    gossip: None,
                    accepted_until: Some(now + ACCEPTED_TTL),
                },
            );
        }
    }

    pub(crate) fn drain(&mut self, now: Instant) -> Vec<Resolution> {
        let mut resolutions = Vec::new();
        self.entries.retain(|_, entry| {
            let status = entry.state.load(Ordering::Acquire);
            let acceptance = match status {
                1 => MessageAcceptance::Accept,
                2 => MessageAcceptance::Reject,
                3 => MessageAcceptance::Ignore,
                _ if Arc::strong_count(&entry.state) == 1 => MessageAcceptance::Ignore,
                _ => return true, // real node worker still owns the capability
            };
            if let Some((id, peer)) = entry.gossip.take() {
                resolutions.push((id, peer, acceptance));
            }
            if status != 1 {
                return false;
            }
            now < *entry.accepted_until.get_or_insert(now + ACCEPTED_TTL)
        });
        resolutions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_then_gossip_uses_one_admission_and_waits_for_real_verification() {
        let mut cache = TxDeliveries::default();
        let now = Instant::now();
        let key = TxDeliveries::key(b"one exact payload");
        let worker = cache.start(key, None).unwrap();
        let source = PeerId::random();
        let id = MessageId::from(vec![1]);
        assert!(cache.duplicate(&key, Some((id.clone(), source))));
        for _ in 0..1000 {
            assert!(cache.duplicate(&key, None));
        }
        assert_eq!(cache.entries.len(), 1);
        assert!(cache.drain(now).is_empty());
        worker.admitted([42; 32]);
        let resolved = cache.drain(now);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].0, id);
        assert_eq!(resolved[0].1, source);
        assert!(matches!(resolved[0].2, MessageAcceptance::Accept));
        assert!(cache.drain(now).is_empty());
    }

    #[test]
    fn altered_authorization_rejection_and_dropped_events_do_not_poison_retry() {
        let mut cache = TxDeliveries::default();
        let now = Instant::now();
        let key = TxDeliveries::key(b"valid payload");
        cache.admitted(key, [42; 32], now);
        assert!(!cache.duplicate(&TxDeliveries::key(b"valid payloae"), None));
        let bad = TxDeliveries::key(b"bad proof");
        let worker = cache.start(bad, None).unwrap();
        worker.complete(MessageAcceptance::Ignore);
        cache.drain(now);
        assert!(!cache.duplicate(&bad, None));
        drop(cache.start(bad, None).unwrap()); // dropped under queue backpressure
        cache.drain(now);
        assert!(!cache.duplicate(&bad, None));
        cache.drain(now + ACCEPTED_TTL);
        assert!(!cache.duplicate(&key, None));
    }

    #[test]
    #[ignore = "explicit release-mode transport microbenchmark"]
    fn exact_payload_dedup_microbenchmark() {
        let mut cache = TxDeliveries::default();
        let payload = vec![0xA5; noid_chain::consensus::wire_limits::MAX_TX_INTENT_BYTES_GLOBAL];
        let key = TxDeliveries::key(&payload);
        let worker = cache.start(key, None).unwrap();
        let started = Instant::now();
        for _ in 0..10_000 {
            let key = TxDeliveries::key(std::hint::black_box(&payload));
            assert!(cache.duplicate(&key, None));
        }
        eprintln!(
            "dedup payload_bytes={} iterations=10000 mean_us={:.3}",
            payload.len(),
            started.elapsed().as_secs_f64() * 100.0
        );
        assert_eq!(cache.entries.len(), 1);
        drop(worker);
    }

    #[tokio::test]
    async fn completion_wakes_reactor_without_a_timer_or_command_queue() {
        let mut cache = TxDeliveries::default();
        let notify = cache.notifier();
        let worker = cache.start([1; 32], None).unwrap();
        worker.admitted([42; 32]);
        tokio::time::timeout(Duration::from_secs(1), notify.notified())
            .await
            .unwrap();
        cache.drain(Instant::now());
        assert_eq!(cache.entries[&[1; 32]].state.load(Ordering::Acquire), 1);
    }

    #[test]
    fn departed_transaction_can_be_reconsidered_before_cache_ttl() {
        let mut cache = TxDeliveries::default();
        let key = TxDeliveries::key(b"reorg transaction");
        let worker = cache.start(key, None).unwrap();
        worker.admitted([42; 32]);
        assert_eq!(cache.admitted_id(&key), Some([42; 32]));
        cache.forget_admitted(&key);
        assert!(!cache.duplicate(&key, None));
        let next = cache.start(key, None).unwrap();
        // A completion retained from the previous admission cannot resolve
        // the fresh worker after eviction/reorg invalidated the cache entry.
        worker.complete(MessageAcceptance::Reject);
        assert!(cache.admitted_id(&key).is_none());
        next.admitted([42; 32]);
        assert_eq!(cache.admitted_id(&key), Some([42; 32]));
    }

    #[test]
    fn completed_cache_does_not_create_a_new_transaction_admission_boundary() {
        let mut cache = TxDeliveries::default();
        let now = Instant::now();
        for i in 0..MAX_TRACKED {
            cache.admitted(TxDeliveries::key(&i.to_le_bytes()), [42; 32], now);
        }
        assert_eq!(cache.entries.len(), MAX_TRACKED);
        let worker = cache
            .start(TxDeliveries::key(b"new payment after a block"), None)
            .unwrap();
        assert_eq!(cache.entries.len(), MAX_TRACKED);
        worker.admitted([42; 32]);
    }

    #[test]
    fn pending_capacity_is_fixed_and_cannot_evict_inflight_verification() {
        let mut cache = TxDeliveries::default();
        let workers: Vec<_> = (0..MAX_TRACKED)
            .map(|i| {
                cache
                    .start(TxDeliveries::key(&i.to_le_bytes()), None)
                    .unwrap()
            })
            .collect();
        assert!(cache.start(TxDeliveries::key(b"overflow"), None).is_none());
        assert!(cache
            .drain(Instant::now() + Duration::from_secs(3600))
            .is_empty());
        assert_eq!(cache.entries.len(), MAX_TRACKED);
        drop(workers);
        cache.drain(Instant::now());
        assert!(cache.entries.is_empty());
    }
}

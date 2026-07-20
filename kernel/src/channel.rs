//! Payment channels without adaptor signatures (spec/07-CHANNELS.md).
//!
//! Updates are kernel-native eltoo: co-signed [`ChannelState`]s carry a
//! sequence number and the highest sequence wins within the dispute window —
//! no penalty algebra, no revocation-key derivation, no toxic state. The
//! [`SignGuard`] enforces the never-re-sign discipline the dispute rules
//! depend on. Routing atomicity is hash-locks with XOR-chained per-hop
//! preimages for decorrelation. Assumption base: hash functions, nothing else.
//!
//! Channels are the protocol's weakest tier — they assume liveness and state
//! retrievability that the base rail does not (spec/07-CHANNELS.md).

use std::collections::HashSet;

use crate::hash::{boundary_hash, sha256, Hash256};

const CHANNEL_STATE_DOMAIN: &str = "uv/channel-state/v1";
const LOCK_PREIMAGE_LEN: usize = 32;

/// Per-channel record of which sequence numbers this wallet has already
/// co-signed. Enforces the never-re-sign discipline (spec/07-CHANNELS.md):
/// signing two different states at one seq lets a cheating counterparty win
/// the "first claim wins" tie at settlement, so a wallet must refuse the
/// second signature. This set is persisted across restarts by the wallet.
#[derive(Clone, Debug, Default)]
pub struct SignGuard {
    signed_seqs: HashSet<u64>,
}

impl SignGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Rehydrate from persisted state.
    pub fn from_signed_seqs(seqs: impl IntoIterator<Item = u64>) -> Self {
        SignGuard { signed_seqs: seqs.into_iter().collect() }
    }

    /// Record intent to co-sign `state`. Returns `true` if this seq is fresh
    /// (the wallet may sign, and the seq is now recorded); `false` if the seq
    /// was already co-signed and signing MUST be refused.
    #[must_use]
    pub fn allow(&mut self, state: &ChannelState) -> bool {
        self.signed_seqs.insert(state.seq)
    }

    /// Whether this seq has already been co-signed (read-only).
    pub fn has_signed(&self, seq: u64) -> bool {
        self.signed_seqs.contains(&seq)
    }
}

/// An in-flight conditional payment inside a channel state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HashLock {
    /// `sha256(preimage)`.
    pub lock: Hash256,
    /// Amount conditionally moving from `from_party`.
    pub amount: u64,
    /// Party (0 or 1) whose balance funds the lock.
    pub from_party: u8,
    /// Nullifier-record epoch after which the lock refunds.
    pub deadline_epoch: u64,
}

impl HashLock {
    /// Check a claimed preimage against this lock.
    pub fn claims(&self, preimage: &[u8; LOCK_PREIMAGE_LEN]) -> bool {
        sha256(preimage) == self.lock
    }
}

/// One co-signed state of a two-party channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelState {
    /// Commitment identifying the channel (the 2-of-2 note's commitment).
    pub channel_id: Hash256,
    /// eltoo sequence: within the dispute window, higher supersedes lower.
    pub seq: u64,
    /// Settled balances for party 0 and party 1.
    pub balances: [u64; 2],
    /// In-flight hash-locks (bounded by policy; unordered set semantics).
    pub locks: Vec<HashLock>,
}

impl ChannelState {
    /// The 32-byte payload both parties' SLH-DSA signatures must cover.
    pub fn signing_payload(&self) -> Hash256 {
        let mut lock_bytes = Vec::with_capacity(self.locks.len() * 49);
        for l in &self.locks {
            lock_bytes.extend_from_slice(&l.lock);
            lock_bytes.extend_from_slice(&l.amount.to_le_bytes());
            lock_bytes.push(l.from_party);
            lock_bytes.extend_from_slice(&l.deadline_epoch.to_le_bytes());
        }
        boundary_hash(
            CHANNEL_STATE_DOMAIN,
            &[
                &self.channel_id,
                &self.seq.to_le_bytes(),
                &self.balances[0].to_le_bytes(),
                &self.balances[1].to_le_bytes(),
                &lock_bytes,
            ],
        )
    }

    /// The eltoo rule: does `candidate` supersede `self` in a dispute?
    /// Same channel, strictly higher sequence.
    ///
    /// Note this is only sound alongside the never-re-sign discipline
    /// ([`SignGuard`]): a strictly-higher seq wins, but two *different* states
    /// at the *same* seq must never both exist, or the tie-break at
    /// settlement is exploitable.
    pub fn superseded_by(&self, candidate: &ChannelState) -> bool {
        candidate.channel_id == self.channel_id && candidate.seq > self.seq
    }

    /// Total value the state accounts for (balances + in-flight locks).
    /// A valid update chain conserves this against the funding note.
    pub fn total(&self) -> Option<u64> {
        let mut sum = self.balances[0].checked_add(self.balances[1])?;
        for l in &self.locks {
            sum = sum.checked_add(l.amount)?;
        }
        Some(sum)
    }
}

/// XOR-chained per-hop preimages (spec/07-CHANNELS.md).
///
/// The sender picks the recipient's preimage `x_n` and per-hop blinders
/// `z_i`; hop *i*'s preimage is `x_i = x_{i+1} ⊕ z_i`. Locks along the route
/// are unlinkable, and a downstream reveal lets each hop claim upstream.
pub mod chain {
    use super::{sha256, Hash256, LOCK_PREIMAGE_LEN};

    /// Derive hop *i*'s preimage from hop *i+1*'s reveal and the blinder the
    /// sender delivered to hop *i*.
    pub fn upstream_preimage(
        downstream: &[u8; LOCK_PREIMAGE_LEN],
        blinder: &[u8; LOCK_PREIMAGE_LEN],
    ) -> [u8; LOCK_PREIMAGE_LEN] {
        let mut out = [0u8; LOCK_PREIMAGE_LEN];
        for i in 0..LOCK_PREIMAGE_LEN {
            out[i] = downstream[i] ^ blinder[i];
        }
        out
    }

    /// Sender-side: from the final preimage and per-hop blinders (ordered
    /// from the hop nearest the sender), derive each hop's lock.
    /// Returns locks `[lock_1 … lock_n]` where `lock_n` is the recipient's.
    pub fn derive_locks(
        final_preimage: &[u8; LOCK_PREIMAGE_LEN],
        blinders: &[[u8; LOCK_PREIMAGE_LEN]],
    ) -> Vec<Hash256> {
        // Walk backward from the recipient: x_n, x_{n-1} = x_n ⊕ z_{n-1}, …
        let mut preimages = vec![*final_preimage];
        for z in blinders.iter().rev() {
            let next = *preimages.last().unwrap();
            preimages.push(upstream_preimage(&next, z));
        }
        preimages.reverse(); // now [x_1 … x_n]
        preimages.iter().map(sha256_of).collect()
    }

    fn sha256_of(p: &[u8; LOCK_PREIMAGE_LEN]) -> Hash256 {
        sha256(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(seq: u64, balances: [u64; 2], locks: Vec<HashLock>) -> ChannelState {
        ChannelState { channel_id: [7; 32], seq, balances, locks }
    }

    #[test]
    fn higher_sequence_supersedes_same_channel_only() {
        let old = state(4, [60, 40], vec![]);
        let new = state(5, [50, 50], vec![]);
        assert!(old.superseded_by(&new));
        assert!(!new.superseded_by(&old), "lower seq never supersedes");
        assert!(!old.superseded_by(&old), "equal seq never supersedes");

        let mut other = state(9, [50, 50], vec![]);
        other.channel_id = [8; 32];
        assert!(!old.superseded_by(&other), "different channel never supersedes");
    }

    #[test]
    fn sign_guard_refuses_second_signature_at_a_seq() {
        let mut g = SignGuard::new();
        let s7 = state(7, [50, 50], vec![]);
        assert!(g.allow(&s7), "first co-sign at seq 7 is allowed");

        // A different state at the same seq (equivocation attempt) is refused.
        let s7_conflict = state(7, [80, 20], vec![]);
        assert!(!g.allow(&s7_conflict), "second co-sign at seq 7 must be refused");
        assert!(g.has_signed(7));

        // A fresh higher seq is fine.
        assert!(g.allow(&state(8, [40, 60], vec![])));
    }

    #[test]
    fn sign_guard_survives_restart_via_persisted_seqs() {
        let mut g = SignGuard::from_signed_seqs([5, 6, 7]);
        assert!(!g.allow(&state(7, [1, 99], vec![])), "persisted seq refused after restart");
        assert!(g.allow(&state(9, [1, 99], vec![])));
    }

    #[test]
    fn signing_payload_binds_every_field() {
        let base = state(4, [60, 40], vec![]);
        let mut reseq = base.clone();
        reseq.seq = 5;
        assert_ne!(base.signing_payload(), reseq.signing_payload());

        let mut rebal = base.clone();
        rebal.balances = [59, 41];
        assert_ne!(base.signing_payload(), rebal.signing_payload());

        let locked = state(
            4,
            [50, 40],
            vec![HashLock { lock: [1; 32], amount: 10, from_party: 0, deadline_epoch: 99 }],
        );
        assert_ne!(base.signing_payload(), locked.signing_payload());
    }

    #[test]
    fn totals_conserve_and_overflow_is_none() {
        let s = state(
            1,
            [50, 40],
            vec![HashLock { lock: [1; 32], amount: 10, from_party: 0, deadline_epoch: 9 }],
        );
        assert_eq!(s.total(), Some(100));
        let bad = state(1, [u64::MAX, 1], vec![]);
        assert_eq!(bad.total(), None);
    }

    #[test]
    fn three_hop_chain_decorrelates_and_propagates() {
        let x_final = [0xAB; 32];
        let blinders = [[0x11; 32], [0x22; 32]]; // hops 1 and 2 (recipient is hop 3)
        let locks = chain::derive_locks(&x_final, &blinders);
        assert_eq!(locks.len(), 3);

        // Decorrelation: every hop's lock is distinct.
        assert_ne!(locks[0], locks[1]);
        assert_ne!(locks[1], locks[2]);
        assert_ne!(locks[0], locks[2]);

        // Propagation: recipient reveals x_final; hop 2 derives its upstream
        // preimage with its blinder, hop 1 with its own — each claim verifies
        // against that hop's lock.
        let hl = |lock| HashLock { lock, amount: 5, from_party: 0, deadline_epoch: 9 };
        assert!(hl(locks[2]).claims(&x_final));
        let x2 = chain::upstream_preimage(&x_final, &blinders[1]);
        assert!(hl(locks[1]).claims(&x2));
        let x1 = chain::upstream_preimage(&x2, &blinders[0]);
        assert!(hl(locks[0]).claims(&x1));

        // A wrong blinder yields a preimage that claims nothing.
        let x_bad = chain::upstream_preimage(&x_final, &[0x33; 32]);
        assert!(!hl(locks[1]).claims(&x_bad));
    }
}

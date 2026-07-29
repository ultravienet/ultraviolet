//! Bitcoin backend: the `Chain` trait `uv-wallet2` mocks, backed by a real
//! node. Publishing a record is a funded transaction with one OP_RETURN output
//! carrying the record bytes; first-occurrence is answered from a persistent
//! forward-scan index.
//!
//! Node-agnostic: the same code serves regtest and signet — only the RPC
//! endpoint and how the wallet is funded differ (see the demo scripts).

use bitcoin::opcodes::all::OP_RETURN;
use bitcoin::script::Instruction;
use bitcoin::Amount;
use bitcoincore_rpc::json::FundRawTransactionOptions;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use serde_json::json;

use uv_air::wots::Digest;
use uv_kernel2::digest;
use uv_kernel2::digest::DIGEST_BYTES;
use uv_kernel2::issuance::{Issuance, ISSUANCE_BYTES};
use uv_kernel2::record::{Record, RECORD_BYTES};
use uv_wallet2::chain::{Chain, ChainViewError, Lookup, Occurrence, PublishError};

/// Fallback fee rate, in sats per vByte, for when the node cannot estimate.
///
/// Only a fallback. This constant used to be the *policy*, described as fine
/// because records are "tiny and not time-critical" — which contradicted the
/// paragraph next to it. A record's exposure window in spec/99 [FRONTRUN] *is*
/// its mempool dwell time: while it sits unconfirmed, a stranger can publish a
/// record for the same nullifier and, if theirs confirms first, first-occurrence
/// binds theirs and the payment is destroyed. Fee is what buys that window
/// shut. Two sat/vB on a busy mainnet is a record that sits for hours.
///
/// So the rate is asked of the node ([`BitcoinChain::feerate_sat_vb`]) and this
/// is what is used when the answer does not come — on regtest, which has no fee
/// history at all, and on a node too freshly synced to have one.
const FALLBACK_FEERATE_SAT_VB: u64 = 2;

/// How many blocks the estimate targets. One, not six: this is the window an
/// attacker races in, and the cost of overpaying on a transaction with one
/// OP_RETURN output is measured in cents.
const FEE_TARGET_BLOCKS: u16 = 1;

/// Refuse an absurd estimate rather than emptying the wallet on one record.
/// A node with a corrupt or adversarial estimator is a real thing, and a record
/// is ~150 vB, so this caps a single publish at roughly 150,000 sats.
const MAX_FEERATE_SAT_VB: u64 = 1_000;

pub mod index;
pub mod mirror;
pub mod mirror_fetch;
use index::RecordIndex;

/// Turn `estimatesmartfee`'s answer into a fee rate this crate can use.
///
/// Split out from the RPC so the arithmetic is testable without a node, which
/// matters more than it sounds: the unit conversion is the part that is easy to
/// get wrong by a factor of a thousand, and getting it wrong upward empties a
/// wallet on one 64-byte record.
///
/// `None` covers every way the node declines to answer, including the quiet
/// one — on regtest and on a thinly-synced node `estimatesmartfee` *succeeds*
/// and returns an object with no `feerate` and an `errors` array.
fn feerate_from_estimate(btc_per_kvb: Option<f64>) -> u64 {
    // 1 BTC/kvB = 100_000_000 sats / 1000 vB = 100_000 sats/vB.
    let estimated = btc_per_kvb
        .filter(|r| r.is_finite() && *r > 0.0)
        .map(|r| (r * 100_000.0).ceil() as u64)
        .filter(|&r| r > 0);
    match estimated {
        Some(r) if r > MAX_FEERATE_SAT_VB => {
            eprintln!(
                "node estimated {r} sat/vB for a record, which is beyond anything \
                 reasonable; capping at {MAX_FEERATE_SAT_VB}"
            );
            MAX_FEERATE_SAT_VB
        }
        // The floor as well as the fallback: a node reporting a rate below this
        // is describing an empty mempool, and paying less buys nothing.
        Some(r) => r.max(FALLBACK_FEERATE_SAT_VB),
        None => FALLBACK_FEERATE_SAT_VB,
    }
}

pub struct BitcoinChain {
    rpc: Client,
    /// Confirm published records by mining a block (regtest only).
    mine_own_blocks: bool,
    /// Address to mine to / receive change (regtest funding).
    mine_to: Option<bitcoin::Address>,
    /// Fee rate override from `UV_BTC_FEERATE`, sats per vByte. `None` asks
    /// the node instead — see [`BitcoinChain::feerate_sat_vb`].
    feerate_override: Option<u64>,
    /// nullifier → first occurrence, so a lookup is a map read rather than a
    /// full rescan: the receive path checks every hop of a lineage.
    index: std::sync::Mutex<RecordIndex>,
}

impl BitcoinChain {
    /// Connect to a node's wallet RPC endpoint
    /// (`http://host:port/wallet/<name>`), user/pass auth.
    pub fn connect(
        url: &str,
        user: &str,
        pass: &str,
        scan_from: u64,
        mine_own_blocks: bool,
    ) -> Result<Self, bitcoincore_rpc::Error> {
        let rpc = Client::new(url, Auth::UserPass(user.to_string(), pass.to_string()))?;
        let mine_to = if mine_own_blocks {
            rpc.get_new_address(None, None).ok().and_then(|a| {
                a.require_network(rpc.get_blockchain_info().ok()?.chain)
                    .ok()
            })
        } else {
            None
        };
        let feerate_override = std::env::var("UV_BTC_FEERATE")
            .ok()
            .and_then(|s| s.parse().ok());
        let index_path =
            std::env::var("UV_BTC_INDEX").unwrap_or_else(|_| "./uv-record-index.json".to_string());
        Ok(BitcoinChain {
            rpc,
            mine_own_blocks,
            mine_to,
            feerate_override,
            index: std::sync::Mutex::new(RecordIndex::load(index_path, scan_from)),
        })
    }

    /// What to pay for a record, in sats per vByte.
    ///
    /// `UV_BTC_FEERATE` wins outright — the demos set it, and an operator who
    /// names a number means it. Otherwise ask the node for a
    /// [`FEE_TARGET_BLOCKS`]-block estimate, because the mempool dwell time is
    /// the front-running window and the node is the only thing here that knows
    /// how busy the mempool is.
    ///
    /// Every failure lands on [`FALLBACK_FEERATE_SAT_VB`], and there are more
    /// of them than there look: `estimatesmartfee` answers with an empty
    /// `feerate` and an `errors` array on regtest and on a node without enough
    /// fee history, rather than failing the call. A silent zero there would
    /// hand Core a fee rate of nothing.
    ///
    /// Public so `uv fees` can price the schedule against the same rate a real
    /// publication would pay, rather than a number typed into a docs page.
    pub fn feerate_sat_vb(&self) -> u64 {
        if let Some(r) = self.feerate_override {
            return r;
        }
        let answer = self
            .rpc
            .call::<serde_json::Value>("estimatesmartfee", &[json!(FEE_TARGET_BLOCKS)])
            .ok()
            .and_then(|v| v.get("feerate").and_then(|f| f.as_f64()));
        feerate_from_estimate(answer)
    }

    /// Build, fund, sign, and broadcast the OP_RETURN transaction.
    ///
    /// The raw tx is built by Core's `createrawtransaction` with a `data`
    /// output — hand-serializing a 0-input tx in Rust collides with SegWit's
    /// marker byte and the node rejects it ("TX decode failed"). Always pass
    /// hex strings between fund/sign/send.
    fn publish_inner(&self, record: &Record) -> Result<(), bitcoincore_rpc::Error> {
        self.publish_bytes(&record.encode())
    }

    /// Put arbitrary bytes in a single `OP_RETURN` and broadcast.
    ///
    /// Shared by both record types, because the transaction machinery is
    /// identical and the *length* is the only thing that distinguishes them on
    /// the wire. Splitting the payload out also means the awkward part — Core
    /// building the script, for the SegWit-marker reason below — is written and
    /// debugged once.
    fn publish_bytes(&self, payload: &[u8]) -> Result<(), bitcoincore_rpc::Error> {
        let data_hex = hex::encode(payload);
        let inputs = json!([]);
        let outputs = json!([{ "data": data_hex }]);
        let raw_hex: String = self.rpc.call("createrawtransaction", &[inputs, outputs])?;

        // `fee_rate` is BTC per kvB: sats/vB × 1000 sats per kvB.
        let opts = FundRawTransactionOptions {
            fee_rate: Some(Amount::from_sat(self.feerate_sat_vb() * 1000)),
            ..Default::default()
        };
        let funded = self
            .rpc
            .fund_raw_transaction(raw_hex.as_str(), Some(&opts), None)?;
        let funded_hex = hex::encode(&funded.hex);
        let signed = self
            .rpc
            .sign_raw_transaction_with_wallet(funded_hex.as_str(), None, None)?;
        let signed_hex = hex::encode(&signed.hex);
        self.rpc.send_raw_transaction(signed_hex.as_str())?;
        if self.mine_own_blocks {
            if let Some(addr) = &self.mine_to {
                self.rpc.generate_to_address(1, addr)?;
            }
        }
        Ok(())
    }

    /// Scan the mempool for a record. Unconfirmed occurrences report depth 0,
    /// so a receiver sees a payment as *visible* within seconds while the
    /// confirmation policy still gates trust.
    fn scan_mempool(
        &self,
        nf: &[u8; DIGEST_BYTES],
    ) -> Result<Option<[u8; RECORD_BYTES]>, bitcoincore_rpc::Error> {
        let txids: Vec<bitcoin::Txid> = self.rpc.get_raw_mempool()?;
        for txid in txids {
            let Ok(tx) = self.rpc.get_raw_transaction(&txid, None) else {
                continue;
            };
            for outp in &tx.output {
                if !outp.script_pubkey.is_op_return() {
                    continue;
                }
                if let Some(data) = extract_op_return(&outp.script_pubkey) {
                    if data.len() == RECORD_BYTES && data[..DIGEST_BYTES] == nf[..] {
                        return Ok(Some(data.as_slice().try_into().unwrap()));
                    }
                }
            }
        }
        Ok(None)
    }

    /// Bring the index up to the tip, then answer from it.
    ///
    /// Returns the tip alongside the hit, because the caller needs both to
    /// compute a depth and fetching the tip twice is a race as well as a wasted
    /// round trip.
    #[allow(clippy::type_complexity)]
    fn scan(
        &self,
        nf: &[u8; DIGEST_BYTES],
    ) -> Result<Option<([u8; RECORD_BYTES], u64, u64)>, bitcoincore_rpc::Error> {
        let tip = self.rpc.get_block_count()?;
        let mut ix = self.index.lock().unwrap();
        self.detect_reorg(&mut ix, tip)?;
        let from = ix.next_height();
        if from <= tip {
            self.index_blocks(&mut ix, from, tip)?;
            ix.save();
        }
        Ok(ix.get(nf).map(|(rec, at)| (rec, at.height, tip)))
    }

    /// Does this index cover the whole chain, or does it start part-way?
    ///
    /// An index built from a floor above genesis cannot tell "no record
    /// exists" from "no record exists *that I can see*", and the difference is
    /// a double-spend. Until an asset's issuance height is recorded and
    /// compared against this floor (spec/99 `[SCAN-FLOOR]`), the only honest
    /// answer for a partial view is that it does not know.
    fn index_covers_everything(&self) -> bool {
        self.index.lock().unwrap().scan_floor() == 0
    }

    /// Has the chain moved out from under the index, and if so, how far back?
    ///
    /// **One RPC in the common case.** A block header commits to its parent, so
    /// a block hash commits to its entire ancestry: if the hash at
    /// `scanned_through` still matches, every block at or below it is unchanged
    /// and there is nothing to do. The walk backwards exists only to *locate* a
    /// fork once one is known to exist, never to detect one.
    ///
    /// This is what was missing. The old code only ever scanned forward, so a
    /// reorg left every stale entry in place — and because depth was computed
    /// from a stale height with `saturating_sub`, a withdrawn record reported
    /// depth 1 and then got *deeper* with every new block.
    fn detect_reorg(&self, ix: &mut RecordIndex, tip: u64) -> Result<(), bitcoincore_rpc::Error> {
        let Some((at, stored)) = ix.tip_scanned() else {
            return Ok(()); // nothing scanned yet, nothing to invalidate
        };

        // A chain shorter than what we scanned is a reorg, proven for free.
        if at > tip {
            ix.rollback_to(tip + 1);
            ix.save();
            return Ok(());
        }

        if self.rpc.get_block_hash(at)?.to_string() == stored {
            return Ok(());
        }

        // Diverged. Walk back through the window to find where the chains agree.
        // Collected first: the walk queries the node, and the rollback mutates
        // the index, so they cannot share a borrow.
        let window: Vec<(u64, String)> = ix.recent().collect();
        for (h, hash) in window {
            if h > tip {
                continue;
            }
            if self.rpc.get_block_hash(h)?.to_string() == hash {
                ix.rollback_to(h + 1);
                ix.save();
                return Ok(());
            }
        }

        // Deeper than the window. Rebuild from the floor: rolling back to the
        // oldest hash held would look correct and be wrong, because the fork may
        // be below it.
        ix.rebuild();
        ix.save();
        Ok(())
    }

    /// Scan `[from, to]` into the index. Every record found is offered; the
    /// index keeps the earliest per nullifier.
    fn index_blocks(
        &self,
        ix: &mut RecordIndex,
        from: u64,
        to: u64,
    ) -> Result<(), bitcoincore_rpc::Error> {
        for h in from..=to {
            let hash = self.rpc.get_block_hash(h)?;
            let block = self.rpc.get_block(&hash)?;
            for (txi, tx) in block.txdata.iter().enumerate() {
                for (vout, outp) in tx.output.iter().enumerate() {
                    if !outp.script_pubkey.is_op_return() {
                        continue;
                    }
                    if let Some(data) = extract_op_return(&outp.script_pubkey) {
                        // Exactly RECORD_BYTES: a longer payload is some other
                        // protocol's data, not one of our records.
                        // An issuance record: 76 bytes, tagged, and kept in
                        // its own list. Length is the discriminant — there is
                        // no room for a type byte in a spend record, whose 64
                        // bytes are two digests.
                        if data.len() == ISSUANCE_BYTES {
                            let arr: [u8; ISSUANCE_BYTES] = data.as_slice().try_into().unwrap();
                            if Issuance::decode(&arr).is_some() {
                                ix.insert_issuance(hex::encode(arr), h);
                            }
                            continue;
                        }
                        if data.len() != RECORD_BYTES {
                            continue;
                        }
                        let arr: [u8; RECORD_BYTES] = data.as_slice().try_into().unwrap();
                        // **Decide "is this a record?" here, not at read time.**
                        //
                        // This used to index any 64 bytes and let `occurrence`
                        // reject non-canonical ones later — but `insert` is
                        // first-wins, so a stranger's 64 bytes whose first half
                        // is a real nullifier and whose second half is *not* a
                        // canonical digest took the slot permanently. Every
                        // later lookup answered `Unanswerable`, which `accept`
                        // refuses. One cheap transaction bricked any nullifier
                        // an attacker could name, with no race to win.
                        //
                        // `Record::decode` answers the question exactly — it
                        // rejects out-of-range limbs rather than reducing them.
                        // Asking here means garbage never occupies a slot.
                        if Record::decode(&arr).is_none() {
                            continue;
                        }
                        // The vout completes the ordering `SPEC.md`
                        // specifies — (height, transaction index, position
                        // within the transaction). Two records in one
                        // transaction used to store identical positions,
                        // leaving the tiebreak to iteration order: real,
                        // deterministic, and written down nowhere.
                        ix.insert(&arr, h, txi as u32, vout as u32);
                    }
                }
            }
            ix.advance_to(h, hash.to_string());
        }
        Ok(())
    }

    /// A raw occurrence as the wallet's `Occurrence`, canonicality
    /// enforced: bytes that don't decode are not a record at all.
    fn occurrence(bytes: &[u8; RECORD_BYTES], depth: u64) -> Option<Occurrence> {
        let rec = Record::decode(bytes)?;
        Some(Occurrence {
            bundle_hash: rec.bundle_hash,
            depth,
        })
    }
}

fn extract_op_return(script: &bitcoin::Script) -> Option<Vec<u8>> {
    // `instructions_minimal`, not `instructions`: the non-minimal iterator
    // accepts `OP_PUSHDATA1/2/4` for a 64-byte payload as readily as the direct
    // `OP_PUSHBYTES_64`, so one record had **four** valid script encodings — all
    // under the datacarrier limit, all relayable, all yielding identical bytes.
    // The trailing-opcode check below already refuses one kind of encoding
    // slack; this refuses the other, which that comment did not consider.
    let mut it = script.instructions_minimal();
    match it.next() {
        Some(Ok(Instruction::Op(op))) if op == OP_RETURN => {}
        _ => return None,
    }
    let payload = match it.next() {
        Some(Ok(Instruction::PushBytes(pb))) => pb.as_bytes().to_vec(),
        _ => return None,
    };
    // The script must be exactly OP_RETURN and one push, nothing after. Without
    // this, `OP_RETURN <record> <anything>` also reads as a record — a script
    // that encodes the same record two ways. Harmless today, since a record's
    // identity is its record bytes and the index keys on the nullifier, but a
    // record encoding with slack in it is not something to leave lying around
    // when the accumulator (spec/99 `[ACC]`) would make encodings consensus.
    if it.next().is_some() {
        return None;
    }
    Some(payload)
}

impl Chain for BitcoinChain {
    fn first_occurrence(&self, nf: &Digest) -> Lookup {
        let key = digest::encode(nf);
        // Confirmed occurrences always win over mempool ones.
        match self.scan(&key) {
            Ok(Some((bytes, height, tip))) => {
                // `height > tip` means the record is above the tip, i.e. a
                // reorg took the block that held it. This used to be
                // `tip.saturating_sub(height) + 1`, which reported that
                // situation as depth 1 — and then the phantom got *deeper*
                // with every new block. Refuse instead.
                if height > tip {
                    return Lookup::Unanswerable;
                }
                match Self::occurrence(&bytes, tip - height + 1) {
                    Some(occ) => Lookup::Found(occ),
                    None => Lookup::Unanswerable,
                }
            }
            // **Confirmed-only, deliberately.** This used to fall through to a
            // mempool scan, which is `getrawmempool` plus a
            // `getrawtransaction` per txid — thousands of round trips against
            // a 1.6 ms proof verification. A junk nullifier is attacker-chosen
            // and therefore always misses the index, so every piece of junk
            // triggered the full walk: the receiver's node paid, at the
            // sender's choosing.
            //
            // Dropping it changes no verdict. A mempool occurrence reports
            // depth 0; `accept` requires at least 3 and `reconcile` at least 1,
            // so a depth-0 hit could never produce a positive answer on either
            // path. It was pure cost. `publish` still checks the mempool,
            // because *there* the answer is actionable — it stops a needless
            // duplicate broadcast.
            Ok(None) => {
                // "Not in my index" is only `None` if the index covers this
                // asset's whole life. The floor check establishes that;
                // otherwise the honest answer is that this view cannot say.
                if self.index_covers_everything() {
                    Lookup::None
                } else {
                    Lookup::Unanswerable
                }
            }
            Err(_) => Lookup::Unanswerable,
        }
    }

    fn tip(&self) -> Result<u64, ChainViewError> {
        // The last `.expect()` on a chain response lived here. `uv status`
        // aborted on a node hiccup, and `uv issue` — which stamps an issuance
        // floor from this number — would have panicked rather than stamp a
        // floor from a failed call, which was accidentally the right behaviour
        // for the wrong reason. Now the caller chooses.
        self.rpc
            .get_block_count()
            .map_err(|e| ChainViewError(e.to_string()))
    }

    fn publish_issuance(&mut self, issuance: &Issuance) -> Result<(), PublishError> {
        // Same OP_RETURN machinery as a spend record, 44 bytes instead of 64.
        // No mempool dedup check: issuance is additive, so a second record is
        // a second issuance rather than an inert duplicate, and silently
        // skipping one would under-report supply.
        self.publish_bytes(&issuance.encode())
            .map_err(|e| PublishError(format!("{e}")))
    }

    fn issuances(&self) -> Vec<Issuance> {
        let mut ix = self.index.lock().unwrap();
        if let Ok(tip) = self.rpc.get_block_count() {
            let _ = self.detect_reorg(&mut ix, tip);
            let from = ix.next_height();
            if from <= tip {
                let _ = self.index_blocks(&mut ix, from, tip);
                ix.save();
            }
        }
        ix.issuances()
    }

    fn rollback_epoch(&self) -> u64 {
        self.index.lock().unwrap().rollback_epoch()
    }

    fn scan_floor(&self) -> u64 {
        self.index.lock().unwrap().scan_floor()
    }

    fn refresh(&self) {
        if let Ok(tip) = self.rpc.get_block_count() {
            let mut ix = self.index.lock().unwrap();
            let _ = self.detect_reorg(&mut ix, tip);
            let from = ix.next_height();
            if from <= tip {
                let _ = self.index_blocks(&mut ix, from, tip);
                ix.save();
            }
        }
    }

    fn publish(&mut self, record: &Record) -> Result<(), PublishError> {
        let key = digest::encode(&record.nullifier);
        // First-occurrence wins: if this nullifier is already known — confirmed
        // *or* sitting in the mempool — don't re-publish. Retrying is free for
        // the network and useless to an attacker.
        //
        // Dedup is an optimisation, so a view that cannot answer publishes
        // anyway: a duplicate costs a fee and first occurrence makes it inert,
        // where skipping a publish you could not check is a lost payment.
        // A dedup check that cannot answer must not block the publish: a
        // duplicate costs a fee and first occurrence makes it inert, where a
        // skipped publish is a lost payment.
        let already = matches!(self.scan(&key), Ok(Some(_)))
            || matches!(self.scan_mempool(&key), Ok(Some(_)));
        if already {
            return Ok(());
        }
        // Not `.expect(...)`. This runs after the spend is signed, so aborting
        // here used to turn "the node hiccuped, retry" into "sign a second
        // message with a one-time key". Handing the failure back leaves the
        // durable, un-broadcast spend the replay path is built for.
        self.publish_inner(record)
            .map_err(|e| PublishError(format!("publishing the record failed: {e}")))
    }
}

#[cfg(test)]
mod fee_tests {
    use super::*;

    /// The conversion, in both directions of getting it wrong.
    #[test]
    fn btc_per_kvb_becomes_sats_per_vbyte() {
        // A busy mainnet: 0.0002 BTC/kvB is 20 sat/vB.
        assert_eq!(feerate_from_estimate(Some(0.0002)), 20);
        // A quiet one: 0.00001 BTC/kvB is 1 sat/vB, floored to the fallback.
        assert_eq!(
            feerate_from_estimate(Some(0.00001)),
            FALLBACK_FEERATE_SAT_VB
        );
        // Fractional rates round up, never down to zero.
        assert_eq!(
            feerate_from_estimate(Some(0.000_000_1)),
            FALLBACK_FEERATE_SAT_VB
        );
    }

    /// Every way the node declines to answer lands on the fallback rather than
    /// on a fee rate of nothing. The quiet one is the dangerous one:
    /// `estimatesmartfee` *succeeds* on regtest and returns no `feerate` field.
    #[test]
    fn a_node_that_cannot_estimate_falls_back_instead_of_paying_zero() {
        assert_eq!(feerate_from_estimate(None), FALLBACK_FEERATE_SAT_VB);
        assert_eq!(feerate_from_estimate(Some(0.0)), FALLBACK_FEERATE_SAT_VB);
        assert_eq!(feerate_from_estimate(Some(-1.0)), FALLBACK_FEERATE_SAT_VB);
        assert_eq!(
            feerate_from_estimate(Some(f64::NAN)),
            FALLBACK_FEERATE_SAT_VB
        );
        assert_eq!(
            feerate_from_estimate(Some(f64::INFINITY)),
            FALLBACK_FEERATE_SAT_VB
        );
    }

    /// A corrupt or adversarial estimator must not empty the wallet on one
    /// 64-byte record. Uncapped, the infinity case above would be a fee rate of
    /// 2^64 sats/vB and Core would be asked to spend everything.
    #[test]
    fn an_absurd_estimate_is_capped() {
        assert_eq!(feerate_from_estimate(Some(1.0)), MAX_FEERATE_SAT_VB);
        assert_eq!(feerate_from_estimate(Some(1_000_000.0)), MAX_FEERATE_SAT_VB);
    }
}

#[cfg(test)]
mod reading_path {
    use super::*;
    use bitcoin::script::PushBytesBuf;
    use bitcoin::ScriptBuf;

    fn op_return(payload: &[u8]) -> ScriptBuf {
        let mut buf = PushBytesBuf::new();
        buf.extend_from_slice(payload).unwrap();
        ScriptBuf::new_op_return(buf)
    }

    /// A canonical record. Small byte values keep every 4-byte little-endian
    /// limb far below BabyBear's order, which is what `Record::decode` checks —
    /// the same construction `index.rs`'s tests use.
    fn canonical() -> [u8; RECORD_BYTES] {
        let mut r = [0u8; RECORD_BYTES];
        r[..DIGEST_BYTES].fill(7);
        r[DIGEST_BYTES..].fill(9);
        assert!(Record::decode(&r).is_some(), "fixture must be canonical");
        r
    }

    #[test]
    fn a_well_formed_record_is_read() {
        let r = canonical();
        assert_eq!(
            extract_op_return(&op_return(&r)).as_deref(),
            Some(&r[..]),
            "the control: an ordinary record must still parse, or every \
             assertion below is vacuous"
        );
    }

    /// One record, one script encoding.
    ///
    /// `instructions()` accepted `OP_PUSHDATA1/2/4` for a 64-byte payload as
    /// readily as the minimal `OP_PUSHBYTES_64`, so a single record had four
    /// relayable script encodings. Harmless while a record's identity is its
    /// bytes — and `[NO-BYTE-IDENTITY]` says `[ACC]` ends that.
    #[test]
    fn a_non_minimally_pushed_record_is_refused() {
        let r = canonical();
        // OP_RETURN OP_PUSHDATA1 0x40 <64 bytes> — same payload, longer script.
        let mut script = vec![0x6a, 0x4c, 0x40];
        script.extend_from_slice(&r);
        let non_minimal = ScriptBuf::from_bytes(script);
        assert_eq!(
            extract_op_return(&non_minimal),
            None,
            "a non-minimal push is a second encoding of the same record"
        );
    }

    /// A trailing opcode was already refused; keep it that way.
    #[test]
    fn a_record_with_anything_after_it_is_refused() {
        let r = canonical();
        let mut script = op_return(&r).to_bytes();
        script.push(0x51); // OP_1
        assert_eq!(extract_op_return(&ScriptBuf::from_bytes(script)), None);
    }

    /// **The wedge.** 64 bytes whose first half is a real nullifier and whose
    /// second half is not a canonical digest.
    ///
    /// The parser still hands these bytes up — they are a well-formed
    /// `OP_RETURN` with one minimal push, and refusing them here would be
    /// refusing to *look*. What must not happen is that they reach the index,
    /// and that is now decided by `Record::decode` in the scanner rather than
    /// at read time, after `or_insert` has already given them the slot.
    #[test]
    fn a_non_canonical_payload_is_not_a_record() {
        let mut wedge = canonical();
        // BabyBear's order is 0x78000001; 0xFFFFFFFF is not a field element.
        wedge[DIGEST_BYTES..DIGEST_BYTES + 4].copy_from_slice(&[0xFF; 4]);

        assert!(
            extract_op_return(&op_return(&wedge)).is_some(),
            "the script is well formed — the parser should still read it"
        );
        assert!(
            Record::decode(&wedge).is_none(),
            "...but it is not a record, which is what the scanner now checks \
             BEFORE inserting. Indexing it let a stranger take the slot for a \
             nullifier they merely named, permanently, with no race."
        );
    }

    /// **The 76-byte record's script, measured rather than assumed.**
    ///
    /// A direct push tops out at 75 bytes, so a 76-byte payload must use
    /// `OP_PUSHDATA1` — three bytes of overhead instead of two, which is where
    /// `ISSUANCE_SCRIPT_BYTES` gets its 79 and why the datacarrier margin is 4
    /// rather than 7.
    ///
    /// The part worth pinning is that `instructions_minimal()` **accepts** it.
    /// That parser exists to refuse `OP_PUSHDATA1` where a direct push would
    /// do, and the whole issuance path would silently stop being readable if
    /// it treated the only legal encoding at this length as non-minimal. This
    /// was a real risk of the size change, not a hypothetical one.
    #[test]
    fn an_issuance_script_is_the_minimal_encoding_of_its_length() {
        use uv_kernel2::issuance::{Issuance, ISSUANCE_BYTES, ISSUANCE_SCRIPT_BYTES};

        let issuance = Issuance {
            amount: 1000,
            asset: uv_kernel2::digest::decode(&[7u8; DIGEST_BYTES]).expect("canonical"),
            commitment: uv_kernel2::digest::decode(&[9u8; DIGEST_BYTES]).expect("canonical"),
        };
        let script = op_return(&issuance.encode());

        assert_eq!(
            script.len(),
            ISSUANCE_SCRIPT_BYTES,
            "the constant must describe the script rust-bitcoin actually builds"
        );
        assert_eq!(script.len(), 79);
        assert!(script.len() <= 83, "over the historical datacarrier limit");

        let read = extract_op_return(&script).expect(
            "instructions_minimal must accept OP_PUSHDATA1 at 76 bytes — it is \
             the only legal encoding at this length, and refusing it would make \
             every issuance record unreadable",
        );
        assert_eq!(read.len(), ISSUANCE_BYTES);
        let arr: [u8; ISSUANCE_BYTES] = read.as_slice().try_into().expect("length checked");
        assert_eq!(Issuance::decode(&arr), Some(issuance));
    }

    /// The other direction: a *spend* record is 64 bytes, where a direct push
    /// is legal, so `OP_PUSHDATA1` there is non-minimal and still refused. The
    /// size change must not have relaxed that.
    #[test]
    fn a_non_minimal_push_is_still_refused_at_spend_record_length() {
        let mut script = vec![0x6a, 0x4c, RECORD_BYTES as u8];
        script.extend_from_slice(&canonical());
        let script = bitcoin::ScriptBuf::from_bytes(script);
        assert!(
            extract_op_return(&script).is_none(),
            "OP_PUSHDATA1 for 64 bytes is not minimal and must not read as a record"
        );
    }
}

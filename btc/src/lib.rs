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
    fn feerate_sat_vb(&self) -> u64 {
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
        let data_hex = hex::encode(record.encode());
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
                for outp in &tx.output {
                    if !outp.script_pubkey.is_op_return() {
                        continue;
                    }
                    if let Some(data) = extract_op_return(&outp.script_pubkey) {
                        // Exactly RECORD_BYTES: a longer payload is some other
                        // protocol's data, not one of our records.
                        if data.len() == RECORD_BYTES {
                            let arr: [u8; RECORD_BYTES] = data.as_slice().try_into().unwrap();
                            ix.insert(&arr, h, txi as u32);
                        }
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
    let mut it = script.instructions();
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

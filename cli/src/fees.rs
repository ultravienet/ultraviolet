//! What Ultraviolet costs in bitcoin, and — the part people get wrong — what it
//! does not cost anything at all.
//!
//! **There is no gas token.** Fees are paid in bitcoin and only in bitcoin, and
//! only two operations pay them: publishing a spend record and publishing an
//! issuance record. Both are one ordinary Bitcoin transaction. Everything else
//! — receiving, scanning, proving, validating a whole lineage, generating
//! addresses, reading the supply — happens on your own machine and touches the
//! chain not at all.
//!
//! That asymmetry is worth stating plainly because it is the opposite of the
//! usual expectation. On most systems the *receiver* pays something, or a
//! contract call costs per step. Here proving a payment is ~0.2 s of your own
//! CPU and costs nothing, and receiving one is a few lookups against your own
//! node.
//!
//! ## The transaction model, and why it is a model
//!
//! A record transaction is funded by the Bitcoin wallet, so its exact size
//! depends on which coins that wallet picks. What is fixed is the shape we
//! build: one input, the `OP_RETURN` output, one change output. These constants
//! describe that shape for a key-path taproot input, which is what the demos
//! and the signet run used.
//!
//! `demo/regtest.sh` measures the real thing and compares it against
//! [`record_vsize`], so this model cannot quietly drift away from what the node
//! actually builds. When it disagrees, the measurement is right and this file
//! is wrong.
//!
//! **Two numbers, and only one of them is ours.** That run measures 197 vB and
//! 210 vB against the 186 and 199 here, because its wallet funds from a
//! different address type than the taproot shape modelled below — coin
//! selection, not drift. What the run checks *exactly* is the **13-vByte gap**
//! between the two, which is pure payload and cannot vary with anything a
//! wallet decides. Quote the gap with confidence; quote the absolute size as
//! the shape it names.

use uv_kernel2::issuance::ISSUANCE_SCRIPT_BYTES;
use uv_kernel2::record::RECORD_BYTES;

/// `scriptPubKey` for a spend record: `OP_RETURN` + a direct push + 64 bytes.
///
/// Two bytes of overhead, unlike issuance: 64 is under the 75-byte limit for a
/// direct push, so no `OP_PUSHDATA1` is needed.
pub const RECORD_SCRIPT_BYTES: usize = 1 + 1 + RECORD_BYTES;

/// Non-witness bytes of a transaction output: 8-byte value, one length varint,
/// then the script. Sound for any script under 253 bytes, which both of ours
/// are by a wide margin.
const fn output_bytes(script: usize) -> usize {
    8 + 1 + script
}

/// Version, input count, output count, locktime.
const TX_OVERHEAD: usize = 4 + 1 + 1 + 4;
/// Outpoint, an empty `scriptSig`'s length byte, sequence.
const TAPROOT_INPUT_NONWITNESS: usize = 36 + 1 + 4;
/// Segwit marker and flag, plus one 64-byte Schnorr signature with its two
/// length prefixes.
const TAPROOT_INPUT_WITNESS: usize = 2 + 1 + 1 + 64;
/// A P2TR change output: value, length, `OP_1` + 32-byte push.
const TAPROOT_OUTPUT: usize = output_bytes(2 + 32);

/// Virtual size of a record transaction carrying `script` bytes of
/// `scriptPubKey`, in the one-input one-change taproot shape.
///
/// Weight is `non_witness × 4 + witness`, and vsize is weight ÷ 4 — so witness
/// bytes cost a quarter. **The data is not witness data**, which is the whole
/// reason a 64-byte record is not cheap: it weighs four times what an equal
/// number of signature bytes would.
pub const fn record_vsize(script: usize) -> usize {
    let non_witness =
        TX_OVERHEAD + TAPROOT_INPUT_NONWITNESS + output_bytes(script) + TAPROOT_OUTPUT;
    // Integer division, matching Bitcoin Core's ceil on weight/4 closely enough
    // for an estimate; the measurement in regtest is the authority.
    non_witness + TAPROOT_INPUT_WITNESS.div_ceil(4)
}

/// One line of the estimate.
pub struct Cost {
    pub operation: &'static str,
    /// `None` for anything that never touches the chain.
    pub vsize: Option<usize>,
    pub note: &'static str,
}

/// Every operation, priced. Ordered so the two that cost money come first.
pub fn schedule() -> Vec<Cost> {
    vec![
        Cost {
            operation: "uv send",
            vsize: Some(record_vsize(RECORD_SCRIPT_BYTES)),
            note: "one 64-byte OP_RETURN: the spend marker and the bundle hash",
        },
        Cost {
            operation: "uv issue",
            vsize: Some(record_vsize(ISSUANCE_SCRIPT_BYTES)),
            note: "one 76-byte OP_RETURN: asset, amount and genesis, in the clear",
        },
        Cost {
            operation: "uv scan / receive",
            vsize: None,
            note: "verifies every hop's proof locally, then reads your own node",
        },
        Cost {
            operation: "proving a payment",
            vsize: None,
            note: "~0.2 s of your own CPU; the witness never leaves the device",
        },
        Cost {
            operation: "uv address",
            vsize: None,
            note: "one-time slots, handed over out of band — nothing published",
        },
        Cost {
            operation: "uv balance / status",
            vsize: None,
            note: "local wallet state",
        },
        Cost {
            operation: "uv supply",
            vsize: None,
            note: "reads confirmed records your node already has",
        },
        Cost {
            operation: "uv reconcile",
            vsize: None,
            note: "re-checks what you hold after a reorg; reads only",
        },
        Cost {
            operation: "uv anchor export / import",
            vsize: None,
            note: "a file handed over out of band",
        },
    ]
}

/// Render the schedule at a fee rate, in sats per vByte.
pub fn report(rate_sat_vb: u64, source: &str) -> String {
    let mut out = String::new();
    out.push_str(&format!("fee rate: {rate_sat_vb} sat/vB ({source})\n\n"));
    out.push_str("COSTS BITCOIN\n");
    for c in schedule().iter().filter(|c| c.vsize.is_some()) {
        let v = c.vsize.unwrap();
        out.push_str(&format!(
            "  {:<26} {:>4} vB  {:>8} sats   {}\n",
            c.operation,
            v,
            v as u64 * rate_sat_vb,
            c.note
        ));
    }
    out.push_str("\nCOSTS NOTHING\n");
    for c in schedule().iter().filter(|c| c.vsize.is_none()) {
        out.push_str(&format!("  {:<26} {:>17}   {}\n", c.operation, "—", c.note));
    }
    out.push_str(
        "\nFees are paid in bitcoin and only in bitcoin. There is no gas token, and no\n\
         second asset you must hold to use the protocol. Receiving is free: the payer\n\
         publishes the record, and the receiver verifies it against their own node.\n\
         \n\
         Sizes assume one taproot input and one change output — the shape the demos\n\
         build. Your wallet's coin selection moves them; demo/regtest.sh measures a\n\
         real transaction and checks these numbers against it.\n",
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Pinned against a real measurement.** The signet run in `README.md`
    /// reported 143–186 vB for a record transaction, and 186 is the
    /// one-input-one-change taproot case this model describes. If this
    /// arithmetic ever stops landing there, the model is wrong and the numbers
    /// on the website are wrong with it.
    #[test]
    fn a_payment_matches_what_signet_measured() {
        assert_eq!(record_vsize(RECORD_SCRIPT_BYTES), 186);
    }

    /// Issuance carries 12 more data bytes and one more push-length byte than a
    /// spend record, and nothing else differs — so the gap is 13 vB and can be
    /// derived rather than trusted.
    #[test]
    fn issuance_costs_exactly_its_extra_bytes() {
        let send = record_vsize(RECORD_SCRIPT_BYTES);
        let issue = record_vsize(ISSUANCE_SCRIPT_BYTES);
        assert_eq!(issue - send, ISSUANCE_SCRIPT_BYTES - RECORD_SCRIPT_BYTES);
        assert_eq!(issue - send, 13);
        assert_eq!(issue, 199);
    }

    /// The record is **non-witness** data, so it weighs four times what witness
    /// bytes do. This is the correction that killed an earlier "~10× denser
    /// than an ordinary payment" claim: a record transaction is about the size
    /// of an ordinary payment, and density comes from batching instead.
    #[test]
    fn record_bytes_weigh_four_times_witness_bytes() {
        let one_more_data_byte =
            record_vsize(RECORD_SCRIPT_BYTES + 1) - record_vsize(RECORD_SCRIPT_BYTES);
        assert_eq!(one_more_data_byte, 1, "a data byte costs a full vByte");
        // Four more witness bytes would cost one vByte; the ratio is the point.
        assert_eq!(TAPROOT_INPUT_WITNESS.div_ceil(4), 17);
    }

    /// Every operation is classified, and the free ones are the majority. If a
    /// new command starts publishing, it belongs in the paying list and this
    /// count changes deliberately.
    #[test]
    fn only_publishing_costs_anything() {
        let paid: Vec<_> = schedule()
            .into_iter()
            .filter(|c| c.vsize.is_some())
            .collect();
        assert_eq!(paid.len(), 2, "only send and issue touch the chain");
        assert!(paid.iter().any(|c| c.operation == "uv send"));
        assert!(paid.iter().any(|c| c.operation == "uv issue"));
    }

    /// The report says the thing people most often get wrong.
    #[test]
    fn the_report_states_that_receiving_is_free() {
        let r = report(5, "test");
        assert!(r.contains("COSTS NOTHING"));
        assert!(r.contains("Receiving is free"));
        assert!(r.contains("no gas token"));
        // And it prices the two that are not free.
        assert!(r.contains("930 sats"), "186 vB at 5 sat/vB");
    }
}

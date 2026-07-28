# 10 · Comparisons

**One sentence:** Every incumbent is excellent engineering inside the classical UTXO-bound model; Ultraviolet is what becomes possible by leaving it.

**Requires:** [00-OVERVIEW](00-OVERVIEW.md) (standalone reading is fine)

## Scorecard

| | RGB v0.12 | Taproot Assets | Shielded CSV | SuperScalar | **Ultraviolet** |
|---|---|---|---|---|---|
| Ownership | UTXO → Schnorr | UTXO → Schnorr | Schnorr keys | one MuSig2 point for 128 parties | **hash-based keys** |
| Receive cost | O(history) | O(lineage) | O(1) | n/a (channels) | **O(1), measured** |
| Needs a UTXO to receive | yes | yes | no | yes (factory slot) | **no** |
| Amounts/history private | no (v0.12 removed) | no (visible in proofs) | yes | n/a | **yes, even from receiver** |
| Instant payments | via classical LN | shipped (classical) | — | shipped (classical) | receipts + PQ channels |
| Post-quantum anything | ✗ | ✗ | ✗ | ✗ | **✓ all layers** |
| Status | mainnet; USDT via UTEXO (Jul 2026) | v0.8.0; USDT on LN (Mar 2026) | paper (eprint 2025/068) | signet implementation | design + working kernel/prover |

## One paragraph each

**How RGB avoids our hardest problem, and what it pays for that.** RGB binds assets to Bitcoin
UTXOs as single-use seals, so uniqueness is **consensus-enforced**: only one transaction can spend a
UTXO, therefore only one transition can close a seal, and no second occurrence can exist to get the
rule wrong about. Ours is a *client-side* rule — the price of dropping the UTXO binding, which is
what buys keyless records, zero UTXO-set growth, and post-quantum safety. RGB then replays the whole
history at every receiver, paying O(n) on **both** validity and settlement, and is sound for it. We
compressed validity to O(1) and assumed settlement came along; that assumption was a supply-inflation
bug ([99](99-OPEN-PROBLEMS.md), review gate 2 — since closed). With the ancestry rule ([03](03-RECORDS.md)) we sit at
O(n) settlement + O(1) validity — better than RGB, same architectural family. Note the per-ancestor
lookup leak is inherited from that family too: an RGB receiver fetches anchors for every ancestor.

**The cost profiles are mirror images, and "we moved the cost" is the honest framing.** RGB does no
proving at all, so *sending* is milliseconds and works on a phone today, while the receiver replays
everything, every time. We prove once and push the cost onto the sender. The defence is totals, not
per-payment feel: our proving is paid once per hop and amortized over every future holder, so across
a chain of n holders RGB's system-wide cost is quadratic and ours linear — decisive for an asset
that circulates, and right for merchants who receive constantly and spend rarely. The cost we accept:
it is the wrong direction for the latency a human feels standing at a till, which is why retail is
our hardest case and RGB's easiest.

**RGB v0.12** modernized its VM (zk-AluVM) but removed confidential amounts, never shipped history compression, and stays UTXO-bound — a CRQC steals RGB assets by stealing anchor UTXOs. **UTEXO** (Tether-led, USDT on RGB v0.11.1 + Lightning) is the commercial layer proving demand — and the case study in what a high-velocity stablecoin does to O(history) validation; its mint key is the ecosystem's single richest quantum target. **Taproot Assets** is the best-executed incumbent (uniform on-chain footprint, static addresses, shipped multi-asset Lightning, USDT live) — same three ceilings: Schnorr ownership, growing proofs that reveal history and amounts, no PQ story; and RWAs sharpen it, since a 10-year instrument issued classically in 2026 must stay unforgeable into the mid-2030s. **Shielded CSV** (Blockstream/Alpen/ZeroSync) contributed the architecture we build on — 64-byte nullifiers, PCD, O(1) receive — with Schnorr at the core. **SuperScalar** (implemented, signet) is the strongest classical answer to receiving-without-a-UTXO: 127 clients behind one MuSig2 output — which *concentrates* quantum exposure into one point, and whose safety-critical core (each signer's persisted refusal to double-sign) is the equivocation problem our nullifier rule solves structurally; its cheater-funds-the-penalty poison is prior art for bonds-are-notes ([05](05-NETWORK.md)). **Tether is now on both rails** (TA-Lightning Mar 2026, RGB-UTEXO Jul 2026) — issuers already hedge across rails, which is exactly the mechanism [09-INTEROP](09-INTEROP.md)'s M-Day depends on.

Deep dives live on the site: [taproot.html](../docs/taproot.html) · [compare.html](../docs/compare.html).

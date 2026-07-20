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

**RGB v0.12** modernized its VM (zk-AluVM) but removed confidential amounts, never shipped history compression, and stays UTXO-bound — a CRQC steals RGB assets by stealing anchor UTXOs. **UTEXO** (Tether-led, USDT on RGB v0.11.1 + Lightning) is the commercial layer proving demand — and the case study in what a high-velocity stablecoin does to O(history) validation; its mint key is the ecosystem's single richest quantum target. **Taproot Assets** is the best-executed incumbent (uniform on-chain footprint, static addresses, shipped multi-asset Lightning, USDT live) — same three ceilings: Schnorr ownership, growing proofs that reveal history and amounts, no PQ story; and RWAs sharpen it, since a 10-year instrument issued classically in 2026 must stay unforgeable into the mid-2030s. **Shielded CSV** (Blockstream/Alpen/ZeroSync) contributed the architecture we build on — 64-byte nullifiers, PCD, O(1) receive — with Schnorr at the core. **SuperScalar** (implemented, signet) is the strongest classical answer to receiving-without-a-UTXO: 127 clients behind one MuSig2 output — which *concentrates* quantum exposure into one point, and whose safety-critical core (each signer's persisted refusal to double-sign) is the equivocation problem our nullifier rule solves structurally; its cheater-funds-the-penalty poison is prior art for bonds-are-notes ([05](05-NETWORK.md)). **Tether is now on both rails** (TA-Lightning Mar 2026, RGB-UTEXO Jul 2026) — issuers already hedge across rails, which is exactly the mechanism [09-INTEROP](09-INTEROP.md)'s M-Day depends on.

Deep dives live on the site: [taproot.html](../docs/taproot.html) · [compare.html](../docs/compare.html).

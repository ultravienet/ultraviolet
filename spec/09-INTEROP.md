# 09 · Interop & Migration

**One sentence:** Never upgrade the old rails — do two cheap things on them now, build Ultraviolet clean, and move the money by issuer decree when it's ready.

**Requires:** [06-PAYMENTS](06-PAYMENTS.md)

## The separation decision (locked)

RGB is never made post-quantum. Its retrofit ceiling is "hybrid-hardened" (a quantum attacker could still freeze via the UTXO-bound seal even when co-signatures prevent theft), hybrid validation doubles the audit surface, and a consensus-level migration would put another community's roadmap on our critical path. So: coexistence, not upgrade.

## The whole plan

1. **Two unilateral actions on the old rail, now.** (a) Hybrid ML-KEM transport encryption in the UTEXO SDK — harvest-now-decrypt-later exposure accrues daily and nothing fixes it retroactively. (b) Tether publishes a hash commitment to an SLH-DSA mint key — needs nobody's cooperation, and a commitment provably predating any CRQC is the one artifact that can't be created later under pressure.
2. **Build Ultraviolet greenfield.** Native USDT issuance from genesis under that pre-committed key. The only gate: audit-grade implementation.
3. **M-Day, a policy flag day.** Issuer announces; bridge (the existing mint-bridge machinery) opens free 1:1 swaps; the RGB contract stops minting; exchanges auto-swap deposits; after a year, swaps go manual. Postponement is a press release, not a fork negotiation; a laggard's funds degrade to a support queue, never a loss.
4. **Out of scope, deliberately:** RGB assets without centralized issuers get no lifeboat — a protocol upgrade was the only thing that could save them, and we chose not to build it.

Main risk: the classical interim window (~18–36 months) while value waits on the old rail — mitigated only by step 1 and by shipping faster.

## Lightning interop

Hash-locked gateway swaps ([06-PAYMENTS](06-PAYMENTS.md)) — atomic via LN's own SHA-256 preimages, no channels of ours, custody-free. For signature-level atomicity with chains whose only language is signatures, a lattice adaptor tier exists as a clearly-labeled option off the money path ([01-CRYPTO](01-CRYPTO.md)).

## Bitcoin itself

No trustless two-way BTC bridge exists here (same as every CSV design — see [10-COMPARISONS](10-COMPARISONS.md)). v1 scope is issued assets, where issuance is native and no bridge is needed.

# 99 · Open Problems

**One sentence:** The single authoritative list of everything unfinished — if it isn't here, it isn't open.

**Requires:** nothing; every file may point here.

## Review gates (block shipping v1)

1. **External security audit** of kernel + guest before anything holds value.
2. **Channel dispute rules** ([07](07-CHANNELS.md)) — mechanism specified (two nullifiers; retrievably-backed highest-seq settlement; never-re-sign discipline; freeze corner, with liveness + retrievability residues named). Adversarial review of those exact rules before channels hold value — the residues are believed minimal but unproven.

The optional speed layer ([11](11-SPEED-LAYER.md)) carries its own review gate — reconciling notary reservations with direct publication — which blocks only that layer, never v1.

## Engineering (ordered, roughly)

3. In-circuit SLH-DSA verification (spend auth is host-side in v0) — then channel disputes enter the guest.
4. Blacklight fork work: wallet crate wiring, payment event kinds, bundle transfer over Blossom, mempool-watching for the "visible" state.
5. Signet end-to-end: self-publish a real 64-byte record, a cooperative batch, the chain-view check.
6. Proving performance: GPU/delegated proving; FRI parameter tightening toward the 50–300 KB proof-size target (current: 1,242 KB).
7. ML-KEM note encryption in the kernel (design locked in [01](01-CRYPTO.md); not yet code).

## Design (not blocking v1)

8. **Speed layer** ([11](11-SPEED-LAYER.md)) — build only if the stranger-retail market demands it: the notary/batcher programs, bond sizing, receipt event kinds as draft NIPs, its epoch/exit review, the one-time-key leakage strengthener, and the further-shelved federated tier.
9. Channel residue reduction ([07](07-CHANNELS.md)): shrinking the liveness window and the retrievability assumption — e.g. longer watchtower-friendly windows, redundant state replication policy, or a bonded arbiter (which is the speed layer, #8). The freeze corner is chosen for v1; whether the residues can be reduced further without a bonded party is open.
10. Seq-chain scaling ([07](07-CHANNELS.md)): the length-`N` hash chain is O(N) to set up at open and must be fixed in advance — awkward for machine-speed streaming channels wanting huge N. Pebbling helps traversal; the open-cost and fixed-N ceiling remain. A per-channel WOTS+ chain or a different seq authenticator is the likely fix.
11. WOTS+ profiles: one-time note spends (wallet never-re-sign discipline) and per-channel chains for machine-speed updates.
12. zk-locks ([07](07-CHANNELS.md)): circuit and per-hop proving cost; recipient-extended final link for proof-of-payment.
13. Lattice adaptor swap tier ([01](01-CRYPTO.md)): parameters and an LN-PTLC interop profile.
14. Cooperative-batch availability ([03](03-RECORDS.md)): retention duty for batch contents; inline mode is the floor meanwhile.

## Watch items (external clocks)

15. Lightning PTLC migration — would break gateway preimage coupling ([06](06-PAYMENTS.md)); ours unchanged, plumbing would need rework.
16. Bitcoin's own PQ migration (BIP-360/361) — systemic dependency on ordering availability ([01](01-CRYPTO.md)); nothing here changes when it lands.
17. Marmot/White Noise upstream appetite — how much lands as extensions vs fork-local ([08](08-CLIENT.md)).

# 07 · Channels

**One sentence:** Kernel-native eltoo — highest co-signed state wins, written as a kernel rule instead of waiting for a Bitcoin soft fork — gives instant bilateral payments between repeat counterparties with no adaptor signatures anywhere, at the cost of being the one tier that assumes liveness.

**Tier warning:** channels are the **weakest tier in the protocol** and the only one that does not inherit the base rail's guarantees. The base rail ([06](06-PAYMENTS.md)) needs zero liveness — receive with a dead phone and an empty wallet. A channel does not: defending against a cheating counterparty's stale close requires you (or a watchtower holding no secrets) to act within the dispute window. Channels are an *opt-in optimization for ongoing relationships*, never the network's fabric; the base rail handles anyone-to-anyone with none of this. Don't sell channels as inheriting base-rail safety — they don't.

**Requires:** [06-PAYMENTS](06-PAYMENTS.md)

## The unlock

Eltoo (latest-state-wins channels: no penalties, no toxic state, safe backups) never shipped on Bitcoin because script can't express "the latest co-signed state supersedes earlier ones" — that needed `SIGHASH_ANYPREVOUT`. Ultraviolet's kernel defines its own spend rules, so eltoo is just `if new.seq > old.seq` in Rust. Adaptor signatures — the entire PQ-channels research problem — turn out to be a workaround for script poverty we don't have.

## The construction (`kernel/src/channel.rs`)

- **Open**: fund a 2-of-2 note (both parties' SLH-DSA keys). Its commitment is the `channel_id`.
- **Update**: co-sign `ChannelState { channel_id, seq, balances, locks }`. Final between the parties the instant both signatures exist — **trustless instant finality, bilaterally**.
- **Close, cooperative**: co-sign a settlement; immediate.
- **Close, unilateral**: open the window (publish `nf_dispute`), survive *W* epochs ([03](03-RECORDS.md)), settle `nf_funding` at the highest retrievably-backed sequence — full rules below.
- **No toxic state**: old states are superseded, never punished — restoring from backup is safe, the failure Poon-Dryja punishes with total loss.
- **Conservation**: balances + in-flight locks must equal the funding note at every update (checked arithmetic; a circuit rule at settlement — see dispute rules).
- **Never-re-sign**: a wallet refuses to co-sign a seq it already co-signed, persisted across restarts (dispute rules — load-bearing against equivocation).

## Dispute rules (v1, freeze corner)

Eltoo's "latest wins" is an *absence* predicate — "no higher co-signed state exists" — and nothing off the two parties' own devices can prove absence. Bitcoin verifies nothing for us, and putting funds under L1 script would re-expose them to quantum theft and can't even see UV assets ([10](10-COMPARISONS.md)). So the dispute rule surfaces the latest seq on-chain via authenticated claims and accepts a bounded residue. We choose the **freeze corner**: an attacker can wedge a channel but can never take its funds.

### Two separate nullifiers (soundness)

The funding note has one nullifier, and the core rule ([03](03-RECORDS.md)) binds a nullifier's *first* occurrence to *one* immutable bundle — which is incompatible with an outcome decided later in a window. So a channel uses **two** nullifiers:

- **`nf_dispute`** — a channel-specific marker (derived from `channel_id`, not the funding note). Its first occurrence opens the window and carries no settlement outcome.
- **`nf_funding`** — the funding note's own nullifier, spent *only* by the final settlement, whose bundle is the window's resolved outcome.

This is the one place the core "one immutable bundle per nullifier, chain verifies nothing extra" invariant bends: settling `nf_funding` requires the validator to apply the windowed dispute function below, not the plain first-occurrence rule. It is the protocol's single validation special-case, and it is confined to channel funding notes.

### The mechanism

- **Seq chains.** At open, each party commits a hash-chain root into the co-signed opening state (length `N` = the channel's max updates, fixed at open — see the streaming caveat in [99](99-OPEN-PROBLEMS.md)). Claiming seq *s* reveals the chain element at depth *s*; anyone verifies it by hashing to the root. Outsiders hold no preimages, so **third parties cannot forge claims** — the chain authenticates *a party is claiming s*, nothing more.
- **Open.** First occurrence of `nf_dispute` opens the window `[E, E+W]` (W agreed at open; default 24 epochs ≈ 1 day, chosen with a reorg margin so relative in-window ordering is stable).
- **Claims.** In-window, either party publishes `channel_id ‖ seq ‖ chain_element ‖ state_pointer` — the pointer resolves (Nostr/Blossom) to the full co-signed state at that seq.
- **Settlement.** After `E+W`, either party spends `nf_funding` presenting the co-signed state of the **highest seq whose claim is *backed by a retrievable, co-signed state*** (ties: first claim wins). A claim whose state is not retrievable is dropped to the next — so a bare "phantom" claim at an unbacked seq is **inert, not a freeze**: nobody can ever present a state for it, so it never wins and never blocks a real lower claim from settling.
- **Never-re-sign discipline (load-bearing).** A wallet MUST refuse to co-sign a seq it has already co-signed, persisted across restarts — else an equivocation-induced pair of same-seq states lets "first claim wins" ratify the cheater's choice. This is the channel analog of the WOTS+ discipline and SuperScalar's `client_ps_signed_inputs` refusal ([10](10-COMPARISONS.md)); the kernel must enforce it, not just `superseded_by`'s `seq >` check.
- **Conservation.** Settlement verifies in-circuit that the presented state's `total()` equals the funding note's value; a state that over-allocates is rejected even if co-signed.
- **Watch duty** (post your higher claim, keep your latest state retrievable) is delegable to a relay holding no secrets.

### Threat accounting — the freeze corner, honestly

| Attack | Outcome |
|---|---|
| Outsider forges claims | Impossible — no chain preimages |
| Stale close, target **online-or-watched** | Higher real claim posted in-window → settles at the true state. No loss. |
| Phantom claim at an unbacked seq | Inert — no retrievable state backs it, so it is dropped; the real max settles. **Not a freeze.** |
| Equivocation (same-seq double co-sign) | Prevented by the never-re-sign discipline; absent it, cheater wins the tie — hence the discipline is mandatory. |
| Stale close, target **offline past W and unwatched** | **Theft.** The liveness assumption is real and is why this is the weakest tier. Mitigated by watchtowers (which cannot themselves steal). |
| Counterparty eclipses your relays so your latest state is unretrievable at settlement | **Theft via DA.** Mitigated by replicating your latest 16 KB state widely — a standing DA duty channels carry and the base rail does not. |

Two residues remain by construction — a **liveness** assumption (act within W) and a **retrievability** assumption (your latest state stays fetchable). Both are the price of resolving an absence predicate without L1 script or a bonded arbiter; both are strictly milder than Lightning's, where the same failures yield theft *plus* toxic-state and quantum-exposed custody. A bonded arbiter would dissolve both — that is exactly the optional speed layer ([11](11-SPEED-LAYER.md)), kept out of core on purpose. These rules are one of the two v1 review gates ([99](99-OPEN-PROBLEMS.md)).

## Routing without PTLCs

Multi-hop uses in-channel hash-locks with **XOR-chained per-hop preimages**: sender picks the recipient's preimage `x_n` and blinders `z_i`, hop *i*'s preimage is `x_i = x_{i+1} ⊕ z_i`. Every hop's lock is distinct — the payment-decorrelation property PTLCs were invented for — yet a downstream reveal unlocks each upstream claim with one XOR. Pure SHA-256; tested three-hop in the kernel. Where stronger binding is wanted, a **zk-lock** (a STARK proving the lock chain well-formed) restores PTLC-grade guarantees as proofs about hashes. Honest deltas vs true PTLCs: the sender knows all preimages (recipient-extended final link partially recovers proof-of-payment); stuckless tricks don't port. Neither affects safety.

## Where channels sit

An optimization for relationships (user↔exchange, market makers, machine-speed streaming) — not the network's fabric. No routing mesh is required for the default rail, so Lightning's liquidity topology problem never appears; most users never notice channels exist. Update signing cost (2 × SLH-DSA per update) is fine at human speed; a WOTS+ per-channel chain is the likely machine-speed optimization ([99](99-OPEN-PROBLEMS.md)).

# Ultraviolet

### Post-Quantum Assets on Bitcoin, Validated by Their Holders

**Version:** identified by the content hash of this file and the code it describes, not by an
edition number — a running project keeps one always-amended commit, so a version string could
never resolve. **Status: research, not money.** Nothing here has been professionally audited, the
proof circuit is hand-written, and volunteer review has twice found ways to create value from
nothing (both fixed; the second class is now scheduled for deletion). **Do not put value on this.**

---

## Abstract

Ultraviolet is a protocol for issuing and transferring assets whose ownership, validity, and
supply survive a quantum computer, while using Bitcoin for nothing but transaction ordering. A
coin is a private hash commitment held on its owner's own devices; spending it publishes a
64-byte keyless record in an `OP_RETURN`, and Bitcoin's only role is to decide which of two
conflicting spends occurred first. Validity travels with the coin as a succinct hash-based proof
that a receiver checks itself — there is no global chain of asset state, no server that must be
trusted, and nothing on-chain for a quantum adversary to forge. Every primitive that could steal
or forge money reduces to the security of a hash function; lattice and elliptic-curve
cryptography appear only where a break would cost privacy rather than funds. Supply is counted
from Bitcoin rather than taken on an issuer's word. A working core exists end to end, proves a
complete transfer in tenths of a second on a phone, and has settled real payments on Bitcoin's
signet — carried, in one measured instance, across Signal's own production servers with no
server-side change.

The honest counterweight, stated once and meant: this is unfinished and unaudited. The consensus
circuits that decide whether money can be forged have had no professional review, which is the
one thing they most need before anyone relies on them. This document is written to be attacked.

---

## 1. Introduction

### 1.1 The problem

A cryptographically relevant quantum computer breaks the elliptic-curve signatures that secure
essentially every digital asset today. The timeline is uncertain and the debate is loud, but the
shape of the risk is not: a **long-duration** asset — a tokenized bond, a note meant to be
redeemable in a decade — must remain unforgeable across exactly the window those forecasts argue
about. Payments can migrate when the threat becomes concrete; a ten-year instrument issued on
classical rails cannot.

Bitcoin itself will migrate, but slowly, because its signatures live **on-chain**: post-quantum
signatures are forty to a hundred-plus times larger than Schnorr, and the block-space economics
that make that painful are precisely what a base-layer migration must overcome. The insight
Ultraviolet is built on is that an asset layer does not have to inherit that cost. If validity is
checked by the coin's holder rather than by the chain, the large post-quantum artifacts — keys,
signatures, proofs — live in client-side data that is free to be large, and the chain is asked
only for the one thing a quantum computer cannot forge anyway: an ordering backed by
proof-of-work.

### 1.2 Contributions

- **A money path that reduces entirely to hash security** (§5). No signature, commitment,
  nullifier, or proof on the path from "can this be stolen or forged" depends on anything but a
  hash function. Lattice and curve cryptography are confined to confidentiality, where a break
  leaks privacy and never funds.
- **Client-side validation with a keyless 64-byte settlement record** (§7). Bitcoin orders
  records by first occurrence and runs no script, owns no UTXO on the asset's behalf, and grows
  its unspent-output set by zero.
- **A hand-written STARK proving a complete transfer in one small table** (§8), with no
  zero-knowledge virtual machine and no SNARK wrapper, verified in milliseconds and proved in
  tenths of a second on a phone.
- **Supply that is counted from Bitcoin** (§9): issuance publishes a record carrying the asset
  and amount in the clear, so how much of an asset exists is a question the chain answers
  exactly, per asset, rather than the issuer asserting.
- **A carrier that never learns it is carrying money** (§10): payments ride an ordinary
  end-to-end-encrypted messaging session as opaque content, demonstrated across Signal's
  production service with no server change.
- **A discipline of deletion and measurement** (§3, §11). Three designed-but-unbuilt subsystems
  were removed rather than carried; a signature scheme was removed because a measured benchmark
  said a proof-native alternative was faster and safer. What remains is backed by machine-checked
  models run on every change.

### 1.3 What exists, and what does not

A working core runs end to end with no zero-knowledge VM anywhere: the money path on Poseidon2, a
STARK per hop proving a complete transfer, and a wallet enforcing every discipline the formal
models proved necessary. Payments have settled on public signet. The client — a chat application
where sending money is sending a message — is design-stage; today's usable surface is a
command-line tool, an iOS wallet app over the same command layer (reading a local chain view,
not yet Bitcoin), and a transport that rides Signal as a linked device. The consensus circuits
have not been professionally reviewed. §14 states precisely what is built and what is not, and
`spec/99-OPEN-PROBLEMS.md` is the single authoritative list of everything unfinished.

---

## 2. System overview

Ultraviolet is three nouns and a carrier.

1. **Notes** are the money: a note is a hash commitment to `(asset, amount, spend anchor,
   randomness)`, existing only on its owner's devices. No chain, relay, or third party ever sees
   a note. Ownership is knowledge of the spend anchor's preimage — there is no separate owner key
   (§6, §8.4). (§6)
2. **Records** are the double-spend lock: spending a note publishes a keyless 64-byte record in a
   Bitcoin `OP_RETURN`, and first occurrence wins. Bitcoin orders records and does nothing
   else — no UTXO is owned, no script is run. (§7)
3. **Proofs** are validity: every hop carries one small STARK attesting that the transfer opened
   its commitments, derived its spend marker correctly, conserved value, and was authorized. A
   receiver verifies one proof per hop of the coin's history, plus one chain lookup per hop to
   confirm each hop settled. (§8)

A payment, in time: the message arrives **instantly**; the record is **visible in seconds** in
Bitcoin's mempool; it is **final in about a block**; and the proof follows in the **background**,
proved in tenths of a second on the sender's own device.

```
Alice's wallet ──encrypted note bundle──▶ Signal ──▶ Bob's wallet
      │                                                  │
      └────────64-byte record──▶ Bitcoin (OP_RETURN)◀────┘ watches mempool
                     proof ◀── one STARK per hop, follows in background
```

The carrier — Signal — moves a ciphertext it cannot read and a blob it cannot interpret, and
needs no server-side change to do it (§10). Everything a quantum computer could attack is either
a hash or Bitcoin's proof-of-work ordering.

---

## 3. Design principles

These are the rules the whole system is held to, stated so that a reviewer can check the code
against them.

**Hashes only on the money path; a break must never move money.** Any primitive on the path to
theft or forgery reduces to hash security. Primitives that affect only privacy may use NIST
lattice standards, always hybridized with a classical scheme. Nothing anywhere uses pairings,
trusted setups, or elliptic-curve assumptions for *safety*. This is the load-bearing principle;
§5 is its accounting.

**Bitcoin orders, and does nothing else.** No soft fork, no new opcode, no covenant, no owned
UTXO, no script execution on the asset's behalf. The chain contributes a deterministic
first-occurrence order and proof-of-work finality; all validity is client-side.

**No token, and fees are bitcoin.** There is no Ultraviolet coin to buy, no premine, no gas
asset. The only operations that cost anything publish one ordinary Bitcoin transaction and pay
its ordinary fee; receiving, proving, scanning, and issuing addresses cost nothing but the payer's
own CPU and their own node.

**Delete rather than carry unbuilt scope.** A design that is specified but not built makes a
project look larger than it is and invites claims the code cannot support. Three subsystems —
payment channels, Lightning interop, and an optional bonded-receipt speed layer — were removed in
July 2026 rather than carried as "designed, not built." A signature scheme (§8.4) is scheduled
for the same treatment because a measurement said so. The reasoning for each deletion is in the
project journal.

**Every number carries its provenance.** A figure in this document is traceable to a demo, a
benchmark harness, a formal-model run, or a measured on-chain transaction, and says which. Claims
without provenance have repeatedly turned out wrong; §11 records several.

---

## 4. Threat model and security posture

The adversary is assumed to hold a cryptographically relevant quantum computer and full view of
Bitcoin and of the messaging network. Against this adversary:

| Property | Rests on | Quantum status |
|---|---|---|
| Theft / forgery of a coin | hash preimage/collision resistance | quantum-safe (Grover-quadratic only) |
| Double-spend / equivocation | hash + Bitcoin first-occurrence ordering | quantum-safe cryptographically; ordering is systemic (below) |
| History validity | hash (FRI/STARK, QROM analyses) | quantum-safe, standard caveat |
| Confidentiality of amounts and recipients | ML-KEM-768 ∧ X25519 | quantum-safe under lattice assumptions, with a classical hybrid floor |
| Availability of ordering | Bitcoin surviving its own PQ migration | systemic, not cryptographic |

Two rows are deliberately not cryptographic. **Ordering availability** depends on Bitcoin
continuing to exist and to order transactions through its own quantum migration — a systemic
assumption Ultraviolet shares with everything built on Bitcoin, and one a quantum thief who steals
the specific UTXO that *carried* a record does not defeat, because that record commits to nothing
spendable. **Confidentiality** is where lattice cryptography lives: a lattice break lets an
adversary read who paid whom and how much, and never lets them forge or steal a coin.

Terminology is disciplined: marketing may say "quantum-safe" (the ETSI term, which this stack has
an unusually strong claim to); technical writing says "post-quantum"; nothing ever says
"quantum-proof," because these are well-studied assumptions, not guarantees.

---

## 5. Cryptographic foundations

### 5.1 The rule, and why hashes

The best known quantum attack on a hash function is Grover's algorithm, a quadratic speedup, so a
256-bit hash retains roughly 128-bit security against a quantum adversary. Hash-based cryptography
is the conservative extreme of the post-quantum spectrum — NIST's own fallback if lattice
assumptions fall — and it is the only family the money path is allowed to use.

### 5.2 The primitives

| Job | Primitive | Rests on | Notes |
|---|---|---|---|
| Commitments, nullifiers, records, history | **Poseidon2 over BabyBear**, one domain-separated sponge | hash | The proof system's own hash, so a money-path hash costs one circuit row. Every use is the same sponge with a different domain tag (`air/src/sponge.rs`). |
| Spend authorization | **in-circuit anchor-preimage** (§8.4) | hash | A spender proves in-circuit that they know the preimage of the anchor the note committed to; no signature is made anywhere on the money path. The WOTS+ one-time signature that once sat beside it was removed on a measured decision (§8.4). |
| Issuer / mint authority | **hash-chain of one-time keys** (§9), not yet built | hash | A reusable mint key is a chain of one-time keys, each naming its successor. No new primitive. |
| Proof system | **FRI STARKs, hand-written AIR on Plonky3** | hash | Transparent, no trusted setup, never a SNARK wrapper — pairings would break the post-quantum claim. |
| The proof's *own* hashing — trace Merkle commitments, FRI folding, Fiat–Shamir | **Keccak** (`air/src/prove.rs`) | hash | **In the trusted base and easy to miss**, because it is not a money-path hash: the circuit constrains Poseidon2, and the STARK proving that circuit ran commits with Keccak. Keccak is SHA-3 — the most reviewed hash here — so this strengthens rather than weakens §5.1. It has a cost, in §5.3. |
| Note / bundle encryption | **ML-KEM-768 + X25519** hybrid (`envelope/`, built) | lattice ∧ ECDH | Privacy only. Both legs load-bearing by test; the hybrid defends against harvest-now-decrypt-later while a lattice break is only a privacy loss. |

**Why one hash and not a standard one.** Poseidon2 is used everywhere on the money path because it
*is* the proof system's hash: one call is one row of the trace. SHA-256 costs 1,353 in-circuit
cycles against Poseidon2's 402, and a signature scheme's in-circuit cost is dominated by machinery
whose only purpose is making a key **reusable** — which a note spent exactly once does not need.
The assumption base is the same either way: hashes only, Grover-quadratic. What changes is which
hash, and how often it runs. See `[SPONGE-MARGIN]` for the cost of choosing a less-reviewed hash.

### 5.3 There are two hashes, and the second one is not on the money path

Poseidon2 hashes the **statement** — commitments, nullifiers, spend anchors, records, history
digests, asset ids. Keccak hashes the **proof about that statement** — the Merkle tree committing
to the execution trace, the FRI folding, and the Fiat–Shamir challenger
(`air/src/prove.rs`: `ByteHash = Keccak256Hash`, `U64Hash = PaddingFreeSponge<KeccakF, …>`).

Both are live in every payment. Neither is legacy. This is written down because until 2026-07-30
it was not: Keccak appeared in no chapter of this document, in no row of
`formal/COMPOSITION.md`'s assumption table, and in no line of `AUDIT-BRIEF.md` — while assumption
**A2** ("Fiat–Shamir binds a proof to its whole statement") rested on it without naming it. A
primitive in the trusted base that nothing names is the exact shape of the defect that produced
this project's only total forgery, and it was found by someone asking whether Keccak was legacy.

**It does not weaken the §5.1 rule.** Keccak is SHA-3: a hash, Grover-quadratic, and by a wide
margin the most reviewed primitive in this system. If anything the money path is the adventurous
half.

**Its cost is recursion.** Verifying a proof *inside* a circuit means recomputing that Merkle and
challenger hashing in-circuit, where Poseidon2 is one row per hash and Keccak is roughly a
thousand times more. That is what blocks `[ACC]` Part 2 — lineage compression — and it is a
configuration problem rather than a research one. The configuration is consensus-visible, so
changing it is a fork: it happens before any freeze (§11) or it waits a long time.

### 5.4 The sponge's capacity, stated as a decision

Every commitment, nullifier, spend anchor, and history digest is an output of the same
domain-separated sponge, which carries **8 BabyBear lanes of capacity**. BabyBear elements are
just under 31 bits, so the capacity is ≈248 bits and generic collision-finding costs ≈2^124
rather than the 2^128 a round number implies.

**This is accepted, deliberately, below the 128-bit line.** 2^124 is beyond the reach of an
adversary who can already perform on the order of 10^37 operations, and the alternative is real:
more capacity means more absorb rows per hash, a taller trace, slower proving. This is recorded as
a decision because it was previously nobody's — it fell out of the sponge's shape and an audit
found it rather than a design note declaring it. A reviewer who disagrees should argue with this
paragraph.

### 5.5 The sponge construction is ours, and that is a separate assumption

`formal/COMPOSITION.md` names seven cryptographic assumptions and every one of them is about a
**primitive**: Poseidon2's preimage resistance, Keccak's, FRI's soundness, the seal's. None is
about the **construction** built on top, and the construction is ours.

Domain separation, the rate/capacity split, and length binding are code in `air/src/sponge.rs`. A
bug there is a collision in *our* hash that no assumption about the permutation covers, because
"Poseidon2 is a secure permutation" and "our sponge is collision-resistant" are different
statements with a proof between them that nobody here has written.

The argument, as far as it goes:

- the domain tag sits in lane 15 and the input length in lane 14, **both in the capacity**, so two
  inputs of different lengths or different domains begin from different states;
- length binding makes the sponge prefix-free without padding rules, so `H(x)` and `H(x ‖ 0)`
  diverge even though add-absorb cannot otherwise see a trailing zero inside a chunk;
- the tags are distinct constants, frozen, and one is never reused across call sites;
- as of 2026-07-30 there is exactly **one** construction — a second add-absorb sponge with no tag
  and no length binding was live on a consensus value until then, kept separate from this one only
  by an accident of initial states, and `air/tests/known_answer_vectors.rs` now fails if a second
  is added.

**What is missing is the step from those four facts to "therefore no cross-domain collision", and
that step is the finding.** It is written here as an argument rather than a proof because an
argument is what exists. This is the one item in this document where an outside cryptographer is
worth more than any test we could write, and it is named in `AUDIT-BRIEF.md` as such.

### 5.6 Why this ships before Bitcoin's migration

Post-quantum signatures are painful on-chain and free off-chain. Ultraviolet keeps signatures and
proofs in client-side data and asks the chain only for hash commitments and proof-of-work
ordering, neither of which a quantum computer forges. The block-space economics that make a
base-layer migration slow simply do not apply.

---

## 6. Notes and ownership

### 6.1 Notes

A **note** commits, under the domain-separated Poseidon2 sponge, to
`(asset, amount, spend_anchor, randomness)` (`kernel2/src/note.rs`) — 28 field elements. Notes exist
only in their owner's client-side data; no chain, relay, or third party ever sees one. `randomness`
makes commitments unlinkable. There is **no owner public key**: a public key here would authorize
nothing (the spend anchor's preimage does — §6.3, §8.4), so it was dropped, and with it five rows of
every transfer's trace. The **spend anchor** is the subtle part and is the subject of §6.3.

The v1 contract scope is locked to **fungible assets** — issue, transfer, burn. The kernel
interface is written for generality; arbitrary contracts are a later version and change no
consensus rule.

### 6.2 Spending, and the shape of a transfer

A spend is authorized in-circuit (§8) and takes **one input and exactly two outputs** — payment
and change. A single-recipient payment still carries a genuine zero-amount change note, so every
hop looks alike and the dummy is indistinguishable from real change; this is a privacy property,
not a cost, since output count was already public in the bundle. Value is conserved exactly:
limb-wise with carries over range-checked 16-bit limbs in the circuit, and checked `u64`
arithmetic on the host, where an overflowing sum is invalid and never wrapped
(`kernel2/src/transfer.rs`, `amount.rs`). What makes a spend *final* is the record layer (§7);
what makes it *valid* is the proof layer (§8).

### 6.3 The spend anchor, and a design error worth keeping

An earlier version of this protocol derived a note's one-time owner key from a shared secret
between payer and payee, in the manner of an elliptic-curve stealth address. **That construction
is self-refuting over hash-based keys, and the reason is instructive.** If the owner key is a
function of the shared secret, everyone who can compute the shared secret can derive the key —
including the payer, who chose it. The payer could spend the note it had just paid out.

The deeper cause is not a slip. Elliptic curves permit tweaking a public key publicly while its
secret is tweaked privately, which is exactly what stealth addressing needs. A hash-based one-time
public key is a hash tree over its own secret; there is no public operation that yields a key
whose preimage only someone else knows. Getting that from hashes alone would be key agreement from
a one-way function, which does not exist. **The property has to come from somewhere other than key
derivation.**

The fix: a note commits to a **spend anchor** `t = H(nullifier_key)` rather than to the key
itself. Spending requires exhibiting, in-circuit, a preimage of the committed anchor
(`air/src/authproto_air.rs`, constraint 12). Everything a payer needs to build a note is then
public — the asset, the amount, the anchor, the blinding — and nothing a payer holds lets it spend.
A one-time owner key is not among them: it authorized nothing beside the anchor, so §8.4 removed it
from the note entirely. This also closed a live privacy leak: before the anchor, the payer
learned the nullifier key and could therefore compute the coin's nullifier and watch the chain for
the exact moment its payment was spent onward. With the anchor, the payer holds `t` and can
compute nothing. Its cost was one sponge row and nine columns, which the trace's power-of-two
height had to spare.

**This anchor-preimage check is the seed of §8.4:** it is already, on its own, a proof that the
spender knows a secret only the payee holds. The signature verified beside it turns out to be
redundant.

### 6.4 Addresses

An address carries a scan key (ML-KEM-768 + X25519), an identity reference, and **slots**:
pre-issued `(index, anchor, randomness)` tuples the payee generated from its own seed. A
payer takes the next unused slot, builds the note, and seals the envelope to the scan key; the
payee reconstructs everything from `(seed, index)`, and the nullifier key — the one secret that
authorizes a spend — never leaves the payee. Slots are handed over once and replenished — a genuine round trip, and the honest claim is
*no invoice per payment*, not *no interaction ever*. Which slots a payer has consumed is
payer-local state by design, so two independent payers of one address both begin at slot 0
without either misbehaving; §7.4 and the wallet's reservation discipline handle the collision.

---

## 7. Records and settlement

### 7.1 The record

```
nf     = H(nullifier_key ‖ note_commitment)     — one deterministic value per note
record = nf ‖ H(transfer_bundle)                — 64 bytes, in an OP_RETURN
```

The consensus rule, enforced client-side (`kernel2/src/nullifier.rs`): **a spend of note N is
valid iff the first on-chain occurrence of `nf(N)` carries this transfer's bundle hash.** Two
conflicting spends of one note produce the same `nf`; at most one is first; the bundle hash pins
which transfer won. Double-spend prevention and equivocation resistance, with zero on-chain
verification and nothing on-chain to attack.

Records are **keyless**: anyone may publish anyone's record, and copying one merely pays its fee.
This is why no service is required — a sender self-publishes, or an asset-only sender hands the
record to the receiver who wants it on-chain anyway.

#### What keyless records forbid, stated once

**Normative, and it closes a whole family of designs.**

> **On-chain presence proves *publication*, never *legitimacy*.** A record on the chain says
> someone paid a fee to put it there. It says nothing about whether the coin it names was ever
> validly created, because anyone may publish anything.

Legitimacy of a coin's ancestry is a property of a **chain of hops**, not of any single hop. A
chain property can be established two ways: walk it, which is what a receiver does today (§7.3),
or compress it recursively into one proof (`[ACC]` Part 2). **There is no third option, and in
particular no on-chain data structure supplies one.**

Two designs were proposed and killed on this in July 2026 — accumulate nullifiers, then accumulate
bundle hashes — and both died the same way: a griefer publishes a record for a bundle she invented,
it legitimately enters the accumulator, she proves inclusion honestly, and spends a coin created
from nothing. The journal has both. A third variant will fail identically.

**This is not an accident to be engineered away; it is the project's distinguishing claim.**
Zcash is easier to reason about here precisely because it publishes commitments, so existence
becomes set membership and one inclusion proof suffices — but that is a system where *consensus
validates*. Ultraviolet's claim is that Bitcoin orders 64-byte keyless records, the UTXO set grows
by zero, and nothing about a note is public. The difference is **who validates**, not what is
published, and the walk is the price.

**And the record cannot simply grow to fit.** BIP-110 reinstates an 83-byte `OP_RETURN` cap; a
64-byte record is a 66-byte script, so there are **17 spare bytes**. No post-quantum signature or
commitment pair fits in 17 bytes, and publishing created commitments instead of hashing them is
`nf ‖ out0 ‖ out1` = **96 bytes against an 83-byte limit**. That thirteen-byte gap is the whole
reason this is hard, and it is the number that closes the "just put a bit more on chain" family.

*What would have to change for this to stop being true:* records gaining a key (an authorized
publisher), or the datacarrier limit growing enough to carry commitments, or consensus itself
validating. A wall with no stated door is indistinguishable from a failure of imagination.

### 7.2 What this costs Bitcoin

`OP_RETURN` outputs never enter the UTXO set, so millions of transfers add **zero** entries to the
state every node must hold forever — the important claim, and it stands. On block space, an honest
accounting: a 64-byte payload is non-witness data and weighs ×4, so a whole record transaction —
one taproot input, the `OP_RETURN`, one change output — measured **143–186 vB** on signet,
comparable to an ordinary payment rather than denser. Density, where it is wanted, comes from
**batching**: one 32-byte Merkle root covering many payments amortizes to ≈1.7 weight units per
payment at 100 payments. An earlier version of this document claimed ~10× settlement density; it
was wrong, having counted the payload bytes alone. The real wins are zero UTXO growth,
prunability, and privacy.

The datacarrier footprint is a deliberate invariant: a 64-byte record is a 66-byte script, under
the historical 83-byte `OP_RETURN` limit, with no data-bearing spendable output and nothing in the
witness. It stays relayable under the strictest datacarrier policy anyone has plausibly proposed.

### 7.3 The ancestry rule (normative)

First occurrence decides which spend of a note is real. The rule whose absence was once the bug is
that a receiver must apply it to **every hop of a note's history, not only their own.** A receiver
MUST, before accepting a note:

1. **Bind the ancestry to the proof.** The sender supplies the ancestry, so it is adversarial
   input. Fold each hop's canonical transition bytes from a genesis constant and require the
   result to equal the history digest the verified proof committed to — *before any chain lookup*,
   so a receiver never leaks which nullifiers it was willing to ask about.
2. **Check every hop settled, including hop 0.** Every nullifier a hop spends MUST have a first
   occurrence whose bundle hash is that hop's. Hop 0 is not exempt: it is the first *spend of* the
   genesis note, and settles like any other. What issuance rests on is §9's on-chain genesis
   record, not a circuit exemption.
3. **Derive, never accept, a hop's nullifiers.** Records are keyless, so a hop carrying its own
   nullifier field could be forged by pairing a fresh nullifier with losing bytes. Nullifiers come
   out of the canonical encoding or the hop is refused.

**Per-hop checking does not compose**, which is why the whole lineage is checked. The tempting
induction — my sender checked their hop, so their note is good — fails exactly when the sender is
the adversary, and you cannot verify that someone else ran a check. A machine-checked model
(`formal/multihop.qnt`) produced the counterexample: an attacker routing a losing branch through a
second wallet of their own makes two conforming receivers each accept, and one note becomes two.
The fix is implemented in `wallet2/src/accept.rs` and the model's inductive `supplyInv` proves
conservation across hops at all depths, over a five-note universe (§11.1).

The cost, stated plainly: one chain lookup per ancestor hop, and about 136 bytes per hop on the
wire. Receiving is O(history), bounded by a cap of 256 hops (`MAX_LINEAGE`) beyond which a lineage
is refused before any proof work. Collapsing this to O(1) is the deferred accumulator (§13).

### 7.4 Confirmations, reorgs, and quarantine

Acceptance waits for a value-tiered confirmation depth; a proposed 1-confirmation tier was
**withdrawn because a model proved it unsafe** (`formal/reorg.qnt`: a depth-1 acceptance is
violated by a 2-block reorg, and only prompt reconciliation rescues it). When Bitcoin reorganizes,
the wallet re-checks what it holds: a note whose ancestry no longer settles, or whose genesis
record is gone, is **quarantined** — not deleted, because the honest record may reconfirm — and
released only by the full positive check it was condemned by, never by "the failing check stopped
failing," which would let a note un-quarantine itself and be spent twice.

A refusal is classified **transient** or **permanent**, and the classification is fund-critical:
permanent means the caller may destroy the bundle. This got one variant wrong once — a
chain-view-too-narrow verdict was defaulted to permanent, so a node merely mid-resync destroyed
real payments — and the classification is now an exhaustive match with no wildcard, so adding a
verdict is a compile error until it is classified.

---

## 8. Transfer proofs

### 8.1 One proof per hop, in one table

Each hop is proved by one STARK over a single **16 × 361** table (`air/src/authproto_air.rs`).
The table proves a complete money-path hop: it opens the input commitment, derives the nullifier,
opens the two output commitments, checks conservation over range-checked 16-bit limbs, and proves
the spender knows the preimage of the coin's spend anchor — the authorization, standing alone.
The proof is FRI-based and transparent, with no trusted setup. §8.4 records the measurement that
set this shape and the row count it collapsed to 16.

The headline is **validity, not safety.** The proof attests every transition was well-formed and
authorized; it cannot attest that each hop's record won its first-occurrence race, because the
circuit has no view of the chain. Safe receiving is therefore one proof verification **plus one
chain lookup per ancestor hop** (§7.3). The standing caution, learned twice: price the
cryptography *and* the data access. O(1) proof verification once hid O(n) lookups, and "verification
is milliseconds" hid "milliseconds *given an indexed chain view*"; a light client that must ask a
server for that view reinstates both a metadata leak and a completeness assumption (§10.3).

### 8.2 The constraint groups

The 16 numbered constraints fall into groups an auditor can attack independently: the Poseidon2
permutation and its sponge discipline (capacity, length, domain tag, absorb injection); the
nullifier derivation tied to the input commitment through a shared "bus"; conservation over
boolean carries and 16-bit range checks (the `2^16`-limb alias is the specific defense); and the
spend anchor's preimage (constraint 12), which authorizes the spend on its own. Appendix A maps
every constraint; `air/COVERAGE.md` records which are isolated by a test and which are not.

### 8.3 Measured cost

Measured on one laptop (Apple Silicon), one configuration per process so peak memory belongs to
one circuit. At 16 rows the prover is dominated by fixed FRI overhead, so the prove column is a
range across runs, not one sample; trace, proof size, and peak are deterministic. Reproduce with
`UV_MEASURE=standard|hiding cargo run --release --bin measure` in `air/`.

| Configuration | Trace | Prove | Proof | Verify | Peak RSS |
|---|---|---|---|---|---|
| Standard | 16 × 361 | ~0.011 s | 81.5 KB | ~1.1 ms | 4 MB |
| **Hiding (the payment format)** | 16 × 361 | ~0.01–0.02 s | 117.2 KB | ~1.6 ms | 5 MB |

That is roughly an **order of magnitude faster and ~23× less memory** than the signature circuit
this replaced (§8.4), which proved hiding in 0.20–0.24 s at 117 MB peak. On a phone, from a signed
build on the device: hiding is **0.006–0.012 s on an iPhone 16e (A18)** — the cheapest current
model — using **1 MB** beyond the app's own footprint, with proof bytes identical to the desktop's.
The signature circuit took 0.331–0.354 s and ~260 MB of prover memory on that same phone, so this
is roughly 30× faster on a fraction of the memory. The witness never leaves the device.

The **payment format is the hiding configuration**, which keeps amounts confidential along a whole
lineage. Hiding adds a blinding mask; at this trace size it costs about 1.4× the proof size of the
standard configuration and a proving time indistinguishable from it within run-to-run noise — a
cost §8.4 makes non-optional.

### 8.4 Proof-native authorization: why there is no signature

**Normative.** Spend authorization is the anchor-preimage constraint and nothing else. A spender
exhibits, in-circuit, a preimage of the anchor its note committed to (§6.3, constraint 12). That is
a proof of a secret only the payee holds, bound to this exact transfer because every public value —
the bundle hash included — enters the Fiat–Shamir transcript. **No signature is made or verified
anywhere on the money path.**

An in-circuit one-time signature was verified alongside this until 2026-07-29. It was removed under
a rule recorded before the measurement — *retained only if more than 2× faster than the
proof-native alternative* — which it missed by 6.7×, on 1.6× the proof and 3.2× the memory. The
measurement and the design it replaced are in `docs/journal.html` and `spec/99-OPEN-PROBLEMS.md`
under `[PROOF-AUTH]`.

Two consequences are normative, not commentary.

**Zero-knowledge is load-bearing for funds.** The witness — the nullifier key — *is* the
authorization, so a witness leak is a fund loss, not merely a privacy loss. The **hiding
configuration is therefore mandatory on the money path**; the standard configuration is for
measurement and tests only. The blast radius of a leak is bounded to one note by keeping anchors
one-time per note (§6.3), which is why that rule is fund-critical rather than hygienic.

**Re-proving is safe; re-preparing is not.** There is no key that a second use discloses, so
proving the same statement twice reveals nothing and state loss is an inconvenience rather than a
compromise. What a wallet must still not do is *rebuild* a spend it has already broadcast: a
rebuilt transfer draws a fresh change index, carries a different bundle hash, and races its own
first record. `wallet2::signlog` enforces this as an idempotency cache.

The assumption base is unchanged by any of the above — FRI and Poseidon2 are hashes, and the
Fiat–Shamir binding was already load-bearing.

---

### 8.5 The FRI parameters, stated as a decision

**Normative.** The proof system runs at **blowup 16 (`log_blowup = 4`), 25 queries, and 16 bits of
query grinding**. Conjectured soundness is `queries × log_blowup + grinding` = **116 bits**, against
a stated target of **100**. Changing any of the three is a consensus change.

**Conjectured, not proven, and the gap is deliberate.** The proven soundness bounds for FRI are
meaningfully worse than this heuristic. The heuristic is what deployed STARK systems use and what
these numbers were chosen against; a reviewer is entitled to reject it. If they do, the answer is
more queries — 50 queries clears 216 conjectured bits — and the cost is prover time, of which there
is roughly 50× headroom against the gate. **The stricter bound is affordable and unexercised, not
unavailable.** That sentence is the one to argue with.

**These constants had no defences at all until 2026-07-30**, and the gap is recorded because its
shape recurs. `NUM_QUERIES` could be edited to `1` — twenty bits of soundness, a forgery for about
a million attempts — and the entire test suite stayed green: nothing referenced the constant, and
the prover and verifier read the same one, so the weakened proof verified. Meanwhile the trace
height, which was the vector for this project's only total forgery, carried a runtime check, a
typed rejection, and a dedicated test file. Two constants of the same class, one hardened by an
incident and one protected by a comment.

They now have the same three defences: a soundness function
(`prove::conjectured_soundness_bits`), a **compile-time** assertion that refuses to build a
below-target configuration, and `air/tests/fri_parameters_are_pinned.rs`, whose tests are written
to hand the check *weakened* configurations and require refusal — including the exact one-query
case that used to pass.

---

## 9. Issuance and supply

### 9.1 The record, in the clear

Issuance publishes a **second, differently-shaped record**:

```
tag(4) ‖ amount(8) ‖ asset(32) ‖ genesis_commitment(32)     = 76 bytes
```

Everything a receiver checks is in the open — there is nothing to recompute and so nothing that
can drift. It is deliberately **not 64 bytes**: the record index keys spend records on their first
32 bytes, so a second 64-byte type would be stored under a nullifier-shaped key and could
permanently shadow a real spend record. Length is the discriminant, and 76 is neither 64 nor the
44 an earlier version used. At 76 bytes the minimal script is a 79-byte `OP_PUSHDATA1`, four bytes
under the 83-byte datacarrier limit — a margin `kernel2::issuance` asserts exactly, spent
deliberately to make supply countable.

### 9.2 Supply is counted, exactly, per asset

Because the asset id is on chain in the clear, an asset's issuances **enumerate**:
`app::commands::supply` filters the confirmed records and sums them per asset, and the answer is the total —
read from Bitcoin with nothing fetched from anywhere. This was not always so, and the history is
the point of §11: a first version stored a one-way *hash* of the record's fields, which confirms a
record you already know but enumerates nothing, so the only computable figure was a chain-wide sum
over every asset — a bound, not an answer.

The genesis commitment is on chain too, and must be: without it, an issuer could mint two genesis
notes of equal amount under one asset id, hand out two anchors, and have one record satisfy both
receivers. Truncating it to save bytes was refused — the issuer chooses both notes, so a short
binding is a 2^64 collision problem rather than a 2^128 second-preimage one, and that is not a
trade to make on the money path.

### 9.3 What a receiver checks

A receiver requires a confirmed record whose asset, genesis commitment, and amount all match the
anchor's opening — three byte comparisons against the chain, with nothing derived — and refuses
any coin whose genesis is not so confirmed, at acceptance and again after every reorg. An
unpublished issuance is therefore worthless, which is what makes the sum *binding* rather than
advisory. The check is not optional: an anchor that cannot state its own amount is refused at
import, where a person reads why.

### 9.4 The residual, and reissuance

One residual remains, and is reported rather than hidden: nothing authenticates a record's asset
id, so a stranger may publish a **decoy** bearing someone else's asset. It creates no spendable
coin — that needs a secret only the owner holds — but it bears the id, so supply reporting keeps
**attested** records (accounted for by an anchor) apart from **unattested** ones and never sums
them together. Closing the decoy case needs a signature over the record, and a rule was decided
for it: **a minter may attest, never validate.** A Bitcoin-authenticated minter is cheap and needs
no durable-storage dependency, but it is a curve signature, not a hash — so if it decided
*validity*, a quantum adversary who took the minter key could construct a spendable coin, violating
§3. Confined to attestation, the same break corrupts a reported number and nothing else.

**Reissuance** — adding to an existing asset under a mint key — is designed and not built. The
plan is a hash-chain of one-time keys, each issuance naming the key permitted to sign the next: no
new primitive, hashes only, and an honest failure mode (lose the next key and supply freezes,
which is the safe direction). Until it is built, every issuance mints a fresh fixed-supply
asset, which is the safe default rather than the intended policy.

---

## 10. Delivery

### 10.1 The carrier is untrusted for funds

A payment is a sealed bundle handed to a carrier, and the carrier may drop, delay, reorder,
duplicate, or read it. None of that can lose money: the record is on Bitcoin independently of the
bundle, so a lost bundle is re-sendable, a duplicate is inert (the record's first occurrence
already decided the outcome), and a tampered bundle is refused because the lineage and proofs are
self-validating. The carrier can cost **time**, and — only if the seal fails — **privacy**, never
funds. This property is modelled in `formal/delivery.qnt`, which checks it both ways: a carrier
that drops, delays and duplicates loses no settled payment, and a client that treats a transient
refusal as permanent does — the `ViewIncomplete` loss, reproduced as a counterexample rather than
described. What the model still lacks is a **conformance tie**: nothing yet replays its
counterexample against the real `is_permanent`, so the model and the code are known to agree by
reading rather than by running. That debt is tracked as claim S13.

### 10.2 Signal as carrier, measured

The carrier is Signal, and carrying money costs it **no server-side change** — it moves a
ciphertext it cannot read and a blob it cannot interpret. On 2026-07-28 this stopped being a
design claim: a real payment of 300 units crossed **Signal's production service** between two
accounts, carried by `signal-cli` acting as a linked device, with nothing self-hosted anywhere;
the sealed 214 KB bundle arrived in under a second, appeared as an ordinary file attachment on the
recipient's phone, and the receiving wallet accepted the payment against a genesis and spend
record confirmed on signet. The run is recorded in the journal.

The honest counterweight: Signal does not officially support third-party clients, so the
linked-device path rides tolerance rather than a promise, and the full chat-app experience needs
either Signal adopting the message type or a fork. Anchors and addresses still travel by hand and
are authenticated by the conversation you already trust — neither carries a signature, so an anchor
from the wrong hands makes a forged lineage look valid; sending them through the same Signal
session closes that with no new cryptography.

### 10.3 The light-client data problem, named

A receiver that cannot maintain its own record index must ask a server for chain lookups, which
reinstates a metadata leak (which nullifiers it asked about) and a completeness assumption (that
the server's answer is not a lie of omission). The mitigation is **index-mirror sync**, and it is
built: bulk replication of the record set in content-addressed pages so lookups happen locally
and no nullifier crosses the wire, with completeness treated as multi-source trust — N mirrors
cross-checked, disagreement surfaced rather than silently resolved (`btc/src/mirror.rs`,
`btc/src/bin/uv-mirror.rs`). The mirror serves pages by height and **offers no endpoint that
takes a nullifier**, which is the design rather than an omission; its 404 body says so. The
wallet app reads public signet through it. `btc`'s mirror tests demonstrate the whole thing in
checks, including that the leaking endpoint does not exist.

**This is a mitigation and not a removal**, and it shipped with a fail-open that is worth
recording because it is the exact shape the mitigation invites. A mirror pointed at an index built
from a later scan floor served an *empty* index, reported tip 0, and satisfied its own
completeness test — `0 >= 0` — so a client concluded "no record exists" for a nullifier that was
on chain. Nothing was wrong with the proofs; the view was silently empty and said it was
complete. The fix was to serve the index's own floor, have the client adopt it, and require
`tip > 0` before a view calls itself caught up. The accumulator (§13) is the eventual removal of
the problem rather than its mitigation, and this is part of the argument for it: a completeness
assumption that fails silently is a bad assumption to keep mitigating.

---

## 11. Verification, and being wrong on purpose

### 11.1 Machine-checked models

Seven Quint models cover the protocol's contested properties: supply conservation across hops
(`multihop`), on-chain issuance and the two ways it was gotten wrong (`issuance`), the
confirmation policy under reorgs (`reorg`), off-circuit ancestry linkage (`linkage`),
proof-native spend authorization and the public-anchor
strawman that must fail (`authorization`), the untrusted carrier (`delivery`), and base-rail
publication liveness and its griefing residue (`baserail`). Together they run **73 checks, on
every push in CI**.

**Twelve properties are proved inductively, at all depths rather than to a bound**, and **every one
of the eight models now has at least one** — supply conservation across hops (`multihop`), both of
`issuance`'s supply claims under the strict rule, `authorization`'s only-the-owner-spends, both of
`reorg`'s reconciliation claims, `linkage`'s no-spliced-history, `delivery`'s no-settled-payment-lost,
and four in `baserail`. The rest are bounded symbolic checks, and where a bound is used the model
file says so rather than implying a proof.

**What "all depths" means here, because the phrase is the most misreadable claim in this
document.** Inductive means an **unbounded number of steps**: no run of any length breaks the
invariant, and no counterexample hides past the bound a bounded check would have used. It does
**not** mean an unbounded number of *things*. Every model reasons over a small fixed universe —
`multihop` over five notes and four wallets, `linkage` over four hops, `baserail` over two notes,
`reorg` over five blocks — while `wallet2/src/accept.rs` accepts lineages of 256. So "supply is
conserved at all depths" states that **over a five-note system, no run of any length inflates
supply**, which is a strong result about a small world. `delivery` is the sole exception: its state
is four booleans, so its universe is the entire reachable space. The per-model table, and what it
would take to measure the real ceiling, are in `formal/README.md`.

**The last two models to get an all-depths proof were the two LIVENESS models**, and that ordering
was backwards. `baserail` asks whether a payment can ever be *made*; `delivery` asks whether a
settled one can still be *taken*. Those are the claims that say what the protocol can actually do —
and until 2026-07-30 all five safety models were proved at all depths while neither liveness model
had a single inductive row. `baserail`'s own header had been arguing for an unbounded check since
the day it was written, and the runbook had been running it at depth 8 the whole time.

What they cost: `delivery`'s is one line (*the payment is always either already taken or still
re-sendable*) over a four-boolean state; `baserail`'s needs the **one-live-bundle discipline stated
as an invariant**, because without it an arbitrary well-typed state can hold two transfers over the
same notes with their records crossed — which is not a hypothetical, it is exactly the deadlock the
`splitRecords` module exhibits. **One module stays bounded on purpose**: `splitRecords` has a
genuinely unbounded counter, and capping it was rejected because bounding the state space of a
module whose job is to produce a violating run risks bounding away the run.

**Each of the twelve is paired with a check that the induction FAILS on a variant that drops the
rule it depends on** — twelve `ok` rows, twelve `violation` rows, and the equality is the check.
This matters more than the count: an inductive invariant that holds whether or not the protocol
enforces its rule is proving something about the model's own bookkeeping, and nothing else in a
green suite would say so. Six of those pairs were added on 2026-07-30 after a comment claiming they
already existed turned out to be false.

**The liveness rows carry a further guard, because both liveness properties are disjunctions and a
disjunction is free if its easy term always holds.** Four *anti-vacuity* rows must VIOLATE: they
exhibit reachable states where the easy term does not carry the property, so the expensive conjuncts
are demonstrably doing work. The sharpest asks whether a part-payment ever arrives while the payment
is still incomplete — if that row stopped failing, the split model would have quietly become a model
of one atomic payment, and the claim that a wallet holding 1 + 1 can pay 2 would have nothing
behind it.

`linkage` is the newest and was the hardest. Stated directly, its induction defeated a 4 GB heap,
thrashed a 16 GB laptop, and hit an internal Z3 `table overflow` after 22 minutes on a 243 GB
64-core machine — the ancestry walk is four nested existentials over the whole hop set, and under
induction the starting state is arbitrary, so the solver must consider every combination the
domain admits. Re-encoded with descent carried in a **ghost variable**, the same property proves
in **15.8 seconds on the laptop that could not do it at all.** Three escalations of hardware
bought nothing; changing the encoding bought everything. What the ghost costs is one
well-foundedness step discharged by hand and stated in `formal/README.md`, plus two invariants
whose job is to stop the ghost from being self-fulfilling — including one requiring every ghost
member to have a *real* creating hop, without which the all-depths result would be a statement
about bookkeeping.
An eighth model, the one-time-key discipline (`onetime`), was retired 2026-07-29 with the
signature itself: proof-native authorization has no key a second use discloses, so both the
hazard it modelled and the replay discipline it validated are gone (§8.4).

Two lessons are baked into the runbook. Every attack that must *reproduce* is a check in both
directions: a counterexample that vanishes is a model that stopped modelling its risk, and is
treated as a regression exactly like an invariant that stops holding. And a model that crashes
must never read as a pass — a rule that earned its keep the first time the full suite ran and
found a runbook line naming a scenario that had been renamed away.

**Seven models are not one system, and the gap between them is where the worst bug lived.** The
free mint was not inside a model — each looked complete, each assumed another had a rule covered,
and nothing checked that any model's assumptions had an owner. A single composed model was
considered and **rejected on measurement**: `linkage`'s induction alone defeated a 64-core machine
when stated directly, so a model whose state space is the product of seven is a different problem
rather than a bigger one; and composition would trade seven all-depths proofs for bounded checks
while making counterexamples span seven subsystems. What ships instead is
`formal/COMPOSITION.md`, an explicit assume/guarantee layering — `authorization` beneath the four
things a proof does *not* attest (`linkage`, `multihop`, `issuance`, `reorg`) beneath `delivery`,
over six named cryptographic assumptions nothing in `formal/` discharges. `compose-check.sh` runs
in CI and fails if a model has no stated position in the layering or an assumption has no owner,
which turns the free mint's *shape* into a build error.

### 11.2 Mutation testing, honestly ledgered

The constraint system is mutation-tested: each numbered constraint is deleted in turn and the
suite re-run, to check that some test notices. The latest sweep is **16 mutants, 16 killed, 0
survived** — every constraint in the money-path circuit is defended by a test that fails if it
vanishes.

**Getting there needed a change of instrument, not more tests.** Nine of the sixteen had survived
every sweep, and not because they were redundant: each pins a permutation input lane, so tampering
with a lane also breaks the permutation constraint, and deleting the target left the tamper still
caught. A proof-level test cannot separate those — it sees one boolean, "the proof failed". The
standing justification was **inheritance**: those nine are byte-identical to the deleted signature
circuit's, which swept clean. An inheritance argument is not a test.

The replacement evaluates the constraint system **concretely, without proving**, recording every
assertion separately by index. Because evaluation is deterministic, a perturbation's failure *set*
names which rules objected. The permutation's assertions are a measured prefix, so "our own rule
fired, not the permutation covering for it" became a checkable claim rather than a hope, and all
nine closed.

**The same instrument settles a larger question the sweep structurally cannot ask.** A sweep
deletes constraints, so it can never find a column that **no constraint mentions** — deleting
nothing changes nothing — and an unconstrained column is a free variable a prover may choose,
which in the wrong place mints money. Perturbing every column on every row: **all 361 of 361
provoke an objection.** There are no free variables in the circuit that authorizes payments.

Two limits, stated because 0 survivors invites the wrong conclusion. The probe changes **one cell
at a time**, so a hole needing two coordinated changes is out of reach. And none of this says the
sixteen constraints are *sufficient* — only that each is load-bearing against our tests. That is
the external review's question, and exhausting the cheap mechanical checks makes it more pressing
rather than less.

The number is recorded against a content hash of the constraint sources rather than a commit, so
an old result is known to still describe the current constraints or known not to. The tool itself
once nearly shipped a hole — a run killed by a timeout left a constraint commented out, and the
next run overwrote its own backup — which is written up in the ledger and guarded against three
ways, including a CI check that fails on the marker itself.

### 11.3 The gap between a model and the code

The sharpest lesson this project has: a verified model plus an unfaithful translation is an
unverified system, and the gap is invisible from either side. The supply rule's first
implementation compared amounts where the model required identity, and no amount of model-checking
could have caught it, because the model does not know what the code says. The response is a
**shared source of truth** — verifying the actual decision-logic functions directly where a
bounded model checker can, driving the real code from the models' own counterexample traces
elsewhere, and a claims-to-model-to-code matrix (`formal/CLAIMS.md`) that makes any uncovered claim
a build-noticed gap rather than a silent one. The trace-driven half has begun: the models export
their own executions as frozen ITF traces, and Rust tests replay them against the production code —
`conformance_authorization` drives the real spend circuit from `authorization.qnt`, and
`conformance_issuance` drives the real `accept` gate from `issuance.qnt`, where the free mint's own
counterexample is now a test the code must pass (and demonstrably fails if the gate reverts to the
amount-only check that shipped).

**`[MODEL-CONFORMANCE]` is now closed to zero.** The matrix stands at **15 of 21 claims tied to
code**, with **no model-only rows and no test-only rows** — six ITF-replay rungs
(`authorization`, `issuance`, `multihop`, `reorg`, `baserail`, `delivery`), each shown to fail when
the rule it defends is removed. The remaining six are accounted for rather than pending: **three
are cryptographic hardness assumptions** with a verified structural half and a half nothing here
can falsify (S2 and P2 are Poseidon2 preimage resistance; P1 is the commitment scheme's
zero-knowledge, which since proof-native authorization is a *fund* claim and is the single
strongest argument for the external audit), and **three were retired** when the signature left the
money path. `formal/claims-coverage.sh` prints the tally in CI and counts the assumption rows
separately, because folding them into the total would inflate it by rows whose hard part is an
auditor's job.

### 11.4 Adversarial review found real forgeries

On 2026-07-27, volunteer adversarial review forged a payment outright — no key, no secret, money
from nothing — by exploiting a trace height nothing pinned. It is fixed, with two regression tests;
then the *fix* turned out to reject every honest private payment, and that was caught the same way.
Neither was found by the authors. Both are written up without varnish in the journal, because a
project asking you to trust its arithmetic owes you its failures more than its successes. This is
the standing argument for professional review before value.

---

## 12. Related work

| | RGB v0.12 | Taproot Assets | Shielded CSV | Ultraviolet |
|---|---|---|---|---|
| Ownership | UTXO → Schnorr | UTXO → Schnorr | Schnorr keys | **hash-based (post-quantum)** |
| Receive cost | O(history) | O(lineage) | O(1) | O(history): one hiding proof + one lookup per hop, measured |
| UTXO to receive? | required | required | no | **no** |
| Amounts hidden from receiver | no | no | yes | **yes** (lineage visible — the receiver validates it) |
| Supply readable from Bitcoin alone | needs the contract | needs the proofs | — | **yes — asset id and amount in the clear on chain** |
| Instant settlement | via classical Lightning | shipped (classical channels) | — | none; the designed channel was deleted, not carried |
| Post-quantum | ✗ | ✗ | ✗ | **✓ ownership, validation, encryption** |
| Status | mainnet | v0.8.0, USDT on Lightning | paper | working core, live on signet, unaudited |

Taproot Assets is what excellent engineering achieves *within* the classical, UTXO-bound model,
and its shipped multi-asset Lightning is a real present-tense advantage Ultraviolet does not match.
Ultraviolet is what becomes possible by leaving that model: hash-based ownership, no UTXO per
holder, and supply an outside party can count from the chain. The comparison is drawn from these
projects' own documentation; for their designs, read theirs.

---

## 13. Limitations and open problems

The single authoritative list is `spec/99-OPEN-PROBLEMS.md`. The load-bearing ones:

- **Unaudited.** The consensus circuits have had no professional review. This is the gap that
  matters most, and §11.4 is why it is not rhetorical.
- **Front-running the record (`[FRONTRUN]`).** While a record sits unconfirmed, a stranger who
  can name a nullifier may publish a competing record; if theirs confirms first, the payment is
  destroyed. The attacker gains nothing and pays one record transaction — but that is **~$0.19–$28
  regardless of the note's value**, so the cost-to-damage ratio is a cheap weapon, not a nuisance
  (`spec/99 [FRONTRUN]` has the table). No coin is stolen and supply is unchanged, which is why the
  safety proofs do not see it. The real bound is the exposure window, and the real defence is
  **out-of-band record submission** (direct to a miner or a private relay), which collapses the
  window to zero. That path is owed, not built; broadcasting a record normally in a congested
  mempool is the exposed case.
- **Zero-knowledge becomes fund-critical** once the signature is removed (§8.4). Whether the
  hiding property can be load-bearing for funds rather than only privacy is re-examined as part of
  that migration, not deferred to an auditor.
- **Receive is O(history), and lineage is visible to the receiver.** The accumulator `[ACC]` — a
  canonical commitment over all records that would let a prover show first-occurrence in-circuit —
  is the most substantial open design. **It does not restore O(1) receive**, and this sentence used
  to say it did: an accumulator makes the per-hop *chain lookup* O(1), while the per-hop *proof
  verification* and the per-hop transmission remain. Only **recursion** — each hop's proof verifying
  its parent's — makes receive constant, and that is unmeasured (`spec/99 [ACC]`, Part 2).
  It is **deferred deliberately**: it would grow the system and double the audit surface in the
  same window the audit is being prepared, and its O(1) claim rests on an unresolved composition
  question. The mitigation until then is index-mirror sync (§10.3) and the 256-hop cap, with issuer
  redemption cycles keeping real lineages short.
- **Durable storage (`[STORAGE]`)** is an unbuilt pluggable role that batching and reissuance
  payloads need and the messaging carrier does not perform.
- **True multi-input transfers (`[MERGE]`)** are not built; a wallet that must pay more than any
  single note holds sends several independent transfers that add up, which the models prove safe.

---

## 14. Status

**Built and running.** Nothing but hashes on the money path: every money-path hash
on Poseidon2; one 16-row STARK per hop proving a complete transfer with authorization by the
anchor preimage, in ~0.01–0.02 s / 117 KB hiding (~0.011 s / 82 KB standard); a wallet enforcing
every modeled discipline; supply counted exactly per asset from Bitcoin. The whole cycle —
issuance, a validated two-hop payment, a double-spend refused by first-occurrence with the
original record rebroadcast, supply counted off-chain with a free-mint attempt refused, and reorg
reconciliation — is a Rust test over `app/`, the shared command layer
(`app/tests/the_whole_system_still_pays.rs`), exercising the exact path a phone runs through the
FFI. A bitcoind-gated test drives the same records and reorgs against a real node. **237 tests**,
real proofs included; fmt, clippy, and eight formal models green on every push.

**Live on public signet:** payments settled 2026-07-26; a real payment crossed Signal's production
service 2026-07-28 with supply read back off the chain.

**Costs, measured against a real node:** a payment is ~186 vB, an issuance ~199 vB
(exactly 13 more, all data), at whatever fee rate the node reports. Receiving, scanning, proving,
addresses, balance, and supply cost nothing. Fees are bitcoin; there is no gas token.

**Design-stage:** the chat-app client (the linked-device transport is the shipped reality); the
accumulator; reissuance; durable storage. **Not reviewed:** the circuits, by professionals. Do not
put value on this.

---

## Appendix A — Constraint map (for auditors)

**The signature was removed (§8.4, 2026-07-29), so there is now one circuit.** The transfer AIR is
`air/src/authproto_air.rs`, 16 numbered constraints over a 16-row table: the Poseidon2 permutation
(1) and the vendored export flag (2); the sponge-section register seeding and padding (3, 4); the
five-sponge tie table pinning each note/nullifier/anchor sponge to its public digest or bus
(5–11, 13); the **anchor-preimage authorization** (12); and conservation and range-checking of the
amount limbs (14–16). Every constraint carries a `// N.` comment naming what it stops, with the
production-circuit number it inherited in parentheses, an artifact of renumbering that
`air/COVERAGE.md`'s ledger explains. `air/COVERAGE.md` records, per
constraint, whether an isolating test exists: the latest sweep kills **16 of 16**, and every
column of the 361 is shown to provoke an objection when perturbed, so no column is a free
variable. The nine sponge-lane and permutation constraints that used to rest on an inheritance
argument now have direct evidence.

## Appendix B — Artifacts, and what each evidences

| Artifact | Evidences |
|---|---|
| `app/tests/the_whole_system_still_pays.rs` | the whole flow end to end over the shared command layer, in CI |
| `iosffi` `paying_through_the_door` | the same payment through the FFI's JSON door, the seam the iOS client uses |
| `btc/tests/reorgs_on_a_real_node.rs` | records, reorgs, and first-occurrence against a real `bitcoind` |
| `btc` mirror tests | a light client reading Bitcoin without naming a coin: pages in, lookups local, no leaking endpoint |
| the journal | the ledger of the real Signal production round trip (2026-07-28) |
| `formal/*.qnt`, `formal/VERIFIED.md` | the eight models and the dated record of full-suite runs |
| `air/mutants.py`, `air/COVERAGE.md` | which constraints a test would notice the loss of |
| `air/src/authproto_air.rs` | the proof-native transfer circuit — the only money-path AIR, and its measured numbers |
| `AUDIT-BRIEF.md` | the attacks the authors most want a reviewer to try, and why the tests structurally cannot find them |
| `spec/99-OPEN-PROBLEMS.md` | the single authoritative list of everything unfinished |

---

*This document is written to be attacked. If you are a reviewer, start at `AUDIT-BRIEF.md`.*

# 99 · Open Problems

**One sentence:** The single authoritative list of everything unfinished — if it isn't here, it isn't open.

**Requires:** nothing; every file may point here.

**How to read this.** Every entry is open. Finished work is not kept here — it lives in the
[journal](https://ultravienet.github.io/ultraviolet/journal.html), with a one-line index in
[Closed](#closed) at the bottom so old references still resolve. Each item has a **stable
slug** (`[ACC]`, `[FRONTRUN]`, …). Cite the slug, never the position: this file used to be
numbered, the numbers drifted, and two other spec files spent weeks pointing at the wrong
items without anyone noticing.

Each entry says what is wrong, what it blocks, and what would close it. Detail sits under
the entry rather than inside it.

---

## Review gates (block shipping v1)

These three are numbered as well as slugged, because other files cite "review gate N".

### Gate 1 — External security audit `[AUDIT]`

**Nothing should hold value until someone outside this project has attacked the circuits.**
The constraints are ours (`air/src/authproto_air.rs` — the one money-path circuit since the
signature left it on 2026-07-29 — plus `air/src/poseidon2_eval.rs` vendored from upstream), so
a rule that quietly does nothing is a mint. A differential test against the host reference is necessary and *not* sufficient by
construction: it only ever exercises honest witnesses.

**This gate stopped being theoretical on 2026-07-27.** Volunteer adversarial review found a
total forgery — see `[ASSUMPTIONS]` — and then found a bug in the fix for it. Neither was
found by us. Scope for a reviewer: [`AUDIT-BRIEF.md`](../AUDIT-BRIEF.md).

### Gate 2 — Multi-hop validity `[closed]`

Fixed. See [Closed](#closed).

### Gate 3 — *(removed)*

Channel dispute rules were a review gate here. **The channels concept was deleted on**
**2026-07-28** — `SPEC.md` and `formal/channels.qnt` are gone. It was 27 of
the suite's 59 checks and the only reason the verification runbook took hours rather
than minutes, all of it about code nobody had written. Reviewing it would have been
reviewing a design, not a system. If instant settlement is built later it gets a new
model and a new gate; see the journal for the reasoning.
### Load-bearing assumptions nobody enforces `[ASSUMPTIONS]`

**The instance is closed; the class is open, and it is the most valuable thing on this page.**

On 2026-07-27 adversarial review produced a total forgery: an eight-row trace of zeros
proved an arbitrary transfer, and a second proof-of-concept ran it up the whole rail to a
`wallet2::accept` that returned `Ok` on money forged from nothing. No key, no secret, ~20 ms.

The cause was not a wrong constraint. **The constraints were fine; something they rested on
was never checked.** `p3_uni_stark` takes the trace height from the proof and validates it
against nothing — its contract is that an AIR is sound at *every* height, and ours is not.
Below the designed height `is_last` never fires, the sponge register is never seeded, and
constraints 20–32 are all gated off, while the verifier builds public values that nothing
reads. `AUDIT-BRIEF.md` had written "1,024 rows" down as a fact about the system. It was an
assumption wearing a fact's clothing.

Fixed by `prove::check_height`. That makes the declared height a **third wrapper consensus
obligation**, beside verifier-built public values and the definitional owner key — and the
easiest of the three to lose, because nothing in the AIR hints it exists. **A recursive
verifier must reproduce all three.** Regression tests: `air/tests/trace_height_is_pinned.rs`,
`wallet2/tests/forged_lineage_is_rejected.rs`.

**The enumeration was done 2026-07-27, and it found four more.** Three are now closed:

- **The FRI parameters were the same bug, one layer out.** `Config` and every p3 type it is
  built from are public, so any caller could construct blowup 1 / one query / zero
  proof-of-work bits — on the order of two bits of soundness — and hand it to `verify_transfer`,
  which would accept it. Nothing in this repository did, which is exactly the problem: it was
  protected by convention, and so was the height. Closed by `prove::Vouched`, a wrapper with no
  public constructor, so a weakened configuration is now a compile error.
- **The public-value count** was a `debug_assert`, which compiles out of release; a mismatch
  panicked inside the constraint folder rather than rejecting. Now a real assertion. This is a
  **fourth** wrapper obligation: the public-value length and layout are part of the statement.
- **Nothing bound a proof to this protocol.** Both challengers were seeded with an empty
  vector. Now seeded with `ultraviolet/air/v1`. Note this does *not* separate the two AIRs from
  each other — one configuration serves both — and that separation rests on trace width
  (enforced by the library) and public-value count (enforced as of today). A third AIR sharing
  both would need its own tag.
- **Padding-row inertness turned out to be far stronger than believed**, which is the pleasant
  direction. Of the cells an audit listed as free on row 1023, only the amount bus actually is;
  `SEL`, `DIGIT`, `BITS`, `ACC`, `CHAIN_IN` and `CHAIN_OUT` all refuse garbage there.
  `air/tests/padding_is_inert.rs` now pins that, with a control that fails if the probe goes
  blind, and a diagnostic for re-establishing the free set if the layout changes.

**Why this stays open anyway:** confirmed properly enforced are trace width, tip count, quotient
shape, and the FRI parameters encoded in a proof (there are none — the proof carries no
parameters, only counts checked against the verifier's). The class is the thing, not the list.

#### Sweep of 2026-07-30 — partial, and the partiality is the point

The sweep outside `air/` had been run once, on 2026-07-28. Since then: mirror sync, `MirrorView`,
`uv-mirror`, the iOS app reading signet, the FFI door, and the accumulator harness — **none of it
swept**. This is a partial catch-up, and what it did *not* cover is listed at the end so the next
person knows where to start rather than re-deriving it.

**Found and fixed the same day** (each has its own detail elsewhere in this file or in the code):

- **`Keccak` was in the trusted base and named in no document.** The proof system commits with it —
  trace Merkle tree, FRI folding, Fiat–Shamir challenger — while `SPEC.md`'s primitives table,
  `AUDIT-BRIEF.md`, and `formal/COMPOSITION.md`'s assumption list named Poseidon2, FRI, ML-KEM and
  Bitcoin's ordering. Assumption **A2** rested on Keccak without saying so. Now `SPEC.md` §5.3 and
  **A7**. *The question that found it: which primitives are we trusting? Nothing in the apparatus
  asks it, and the answer had to be recovered by reading a type alias.*
- **The FRI parameters were protected by a comment.** `NUM_QUERIES` could be set to 1 — twenty bits
  of soundness — with every test green. Now a compile-time assertion and a test that hands the check
  weakened configurations. See `SPEC.md` §8.5.
- **28 free field elements on the circuit's padding row**, read by nothing. Constraint 4b.
- **A corrupt `chain.json` read as an empty chain**, in which every nullifier is unspent. Now
  fail-closed; absent still means fresh. See `wallet2::chain::FileChain::open`.
- **Two `detect_reorg` failures were discarded**, then the code indexed anyway — onto a view that
  may have been reorganised away. Now reported *and* the scan is skipped.
- **Slot reservation had two races**, one predicted and one worse and not predicted. See
  `[SLOT-COLLISION]`.

**Checked and found sound**, recorded because a sweep that only reports problems teaches nothing
about what "checked" means:

- **`mirror::replay` mutates the index before validating the whole feed.** A feed with a gap in
  page three leaves pages one and two inserted. Verified fail-*safe*: `advance_to` and `save` are
  both after the loop, so the covered range is never advanced over records that were not stored.
  The index ends up claiming *less* coverage than it holds, which is the conservative direction.
- **`Synced::complete()` requires `tip > 0`**, so an empty index cannot report completeness by
  `0 >= 0`. That clause is load-bearing and its comment says so; this sweep confirms it is still
  there.

**Not swept, and owed:** `uv-mirror` the binary, `app/src/commands.rs`, the iOS app's own Swift
layer, and `air/src/bin/acc-shape.rs`. The question to ask of each is the one that worked above:
*what does this treat as a fact that nothing checks?*

**The sweep outside `air/` has now been done once (2026-07-28), and found one live instance.**

- **The durable write between signing and broadcasting was a convention.** `PreparedSpend` made
  "prepare before broadcast" impossible to express wrongly, and did nothing about the step
  *between* them — which is the one that matters, because a crash after publishing and before
  the sign-log reaches disk leaves a signature the wallet cannot remember making, and the retry
  signs a second message with a one-time key. The CLI did it in the right order. Nothing
  required it to. **Closed structurally:** `send::broadcast` now takes the persist step as an
  argument and runs it first, so there is no path to `chain.publish` that skips it, and a failed
  write aborts before anything is published. Tests: `persisted_before_publishing` (asserts the
  order, not just the outcome) and `a_failed_write_publishes_nothing`.
- **Chain-view completeness is inferred from configuration, not from work done.**
  `index_covers_everything()` is `scan_floor() == 0` — which says the index was *asked* to start
  at genesis, not that every block below the tip was parsed. What makes the inference sound
  today is that a scan which cannot reach the tip propagates its error and the lookup answers
  `Unanswerable` rather than `None`. That is a real argument, and it is an argument rather than
  a check. Written down at `btc/src/index.rs::scan_floor`. **`[ACC]` makes this load-bearing in
  a much sharper way** — an incomplete scan there yields a silently wrong accumulator root, with
  no fail-closed path at all.
- **`MockChain` and `FileChain` assert completeness by returning zero**, which for `FileChain` is
  a claim about a JSON file that nothing validates. Test doubles, so not consensus — noted
  because the same shape in a real backend would be.
- **Mutation testing found the enforcement gap's mirror image in the tests**, not the code: on
  its first run, most constraints in the money-path circuit could be deleted with every test
  still green, because no test isolated them. That is now 16 of 16 killed and 361 of 361 columns
  constrained (`air/COVERAGE.md`). An unenforced assumption and an unfalsifiable test are the
  same defect seen from two sides.

A second lesson, recorded because it cost real time: **the first fix was wrong in the
opposite direction.** It rejected every honest *hiding* proof, because a ZK proof runs over
an extended domain and legitimately declares one more bit
(`degree_bits = log_degree + config.is_zk()`). It passed 43 of 44 tests. Derive that number
from the configuration; never hardcode it.

### "Hiding" is a promise the prover makes to itself `[HIDING-UNVERIFIABLE]`

**The payment format's privacy cannot be checked by the person it protects.**

`p3` verifies that randomization is *present* — `opened_values.random.is_some()` must match
`Pcs::ZK` — but never that there is *enough* of it. The number of random codewords and the
length of each Merkle leaf salt are prover-side parameters; the verifier appends whatever it is
given and checks no length. A wallet could emit a proof with zero-length salts and no
randomization columns. It would verify identically.

Why it matters here specifically: a receiver in `wallet2::accept` verifies hops proved by
*other people's wallets*, and the hiding configuration is what keeps those hops' amounts, keys
and randomness from every later holder of the lineage. So this is not a foot-gun a wallet
points at itself — it is a property a third party is relying on and cannot confirm.

`air/tests/hiding_is_randomized.rs` tests *our* prover, which is the wrong direction: it
establishes that we blind, not that a proof we received was blinded.

**Stated where a user can see it, 2026-07-30.** This is a **standing limitation of the design**,
not a to-do, and it was previously visible only here. A coin's amount privacy is only as good as
the least careful wallet that ever held it, and a receiver cannot check. That sentence is now on
the front page beside the privacy claim it qualifies, and it is named in `AUDIT-BRIEF.md` as a
question for the reviewer.

**The first model of a privacy adversary landed 2026-07-31** — `formal/privacy.qnt`, the observer
rather than the thief, which this file had said was owed and not started. It composes the two leaks
that actually matter together: an on-chain record *event* and an addressed off-chain *delivery*.
Neither breaks privacy alone; the composition does. The `lone` module **violates** `unlinkable`: a
payment whose record and delivery fall in one correlation window is uniquely pairable, and the
observer reads the payer→payee edge with the amount still sealed. Two mitigations hold — `offband`
(submit the record out of band, so there is no on-chain event to pair — the same mitigation
`[FRONTRUN]` leans on) and `decorrelated` (deliver in a later window than the record). **The result
is that payment-graph privacy is a function of traffic and timing, not of the cryptography**, which
sharpens this entry: amount privacy is only as good as the least careful holder, and *relationship*
privacy is only as good as the busiest channel and the loosest timing.

It is a first cut, scoped to the pairing leak. What it does NOT model, and is owed: bundle size as a
hop-count leak (known, `P3`'s own test), a mirror's IP + block-range correlation, and a global
traffic-analysis adversary that watches every channel at once. Those are the rest of the observer
calculus, and they are the next increments rather than the whole thing at once.

Probably not fixable without upstream changes, since the parameters are not in the proof to be
checked. Options if it ever needs closing: a length check contributed upstream, or a
convention that blinding parameters are part of the statement and therefore in the public
values. Recorded because hiding is *the* payment format and this is the one thing about it a
receiver must take on trust.

**Re-examined 2026-07-29, the day zero-knowledge became load-bearing for funds.** Under
proof-native authorization the witness in every spend proof is the nullifier key — the spend
secret itself. What changes and what does not:

- **The self-inflicted direction is now a fund hazard, not a privacy one.** A wallet whose
  blinding is absent, fixed, or predictable exposes its own in-flight note's `nk` in the FRI
  openings. Whoever extracts it can build a *different* verifying spend of the same note and race
  the honest record to first-occurrence — theft of the in-flight payment during the mempool
  window. Contained to one note (anchors are one-time), and it requires the wallet's own prover
  to be broken; `air/tests/hiding_is_randomized.rs` guards our prover against exactly the
  fixed-seed failure we shipped once.
- **The receiver-side unverifiability is unchanged in mechanism and unchanged in stake.** A
  receiver still cannot confirm that hops proved by *others* were blinded; what a third party's
  missing blinding leaks is still that third party's own secrets, never the receiver's funds.
  The verifier's soundness does not depend on the proof being zero-knowledge.
- **Net: the property this project cannot independently verify now protects money.** That is why
  the composition of `HidingFriPcs`/`MerkleTreeHidingMmcs` moved from "review if you want to"
  into the audit's explicit scope (AUDIT-BRIEF §3, attack 7).

### An address file makes its own payments' amounts guessable `[AMOUNT-GUESS]`

**Found 2026-07-28 while scoping `[SUPPLY]`.** A note commitment is
`H(Domain::Note, asset ‖ amount ‖ nullifier_anchor ‖ randomness)` — 28 field elements since the
`owner_pk` drop (2026-07-29), of which **24 are published in the payee's own address file**:
`nullifier_anchor_hex` and `randomness_hex` per slot, plus the asset id from the anchor. The only
unknown is the amount, and output commitments travel in the clear inside every `Transfer`.

So anyone holding an address file can take any output commitment they can see and try amounts
against it. Nominally that is a 64-bit search; in practice payment amounts are small, round, or
drawn from a short list, so it is a dictionary of a few thousand. A hit also identifies *which
slot* was paid, linking the payment to the payee.

**Narrow, but real.** An address goes to one counterparty and travels sealed, so the reach is
"a payer can confirm amounts of other payments made to slots in a batch they were given" — not
the general public. And a payer already knows what *they* paid. It is not a break of the hiding
STARK, which is doing exactly its job: the leak is in the address layer, not the proof.

`SPEC.md` says "`randomness` makes commitments unlinkable", which is true and is not the
same as saying randomness is secret. Nothing anywhere said it was published; nothing said it was
not.

**The fix direction, not yet taken:** derive the note's randomness from a shared secret — the
payer's ephemeral key against the payee's scan key, both of which the envelope already
establishes — instead of publishing it per slot. Then only the two parties can recompute the
commitment, and the address file stops carrying the last input a guesser needs. That is an
address-layer change with no consensus effect, and it interacts with `[ANCHOR-REUSE]`, which is
the other open question about what a slot must contain.

### The invariant that makes the encoder safe: bytes are never an identity `[NO-BYTE-IDENTITY]`

**Not a bug — an invariant that must be preserved, written down because breaking it would be
silent.** `[DEPS]` owed a canonical-encoding review, since `bincode` is unmaintained and sits
on the money path. The review was done 2026-07-27; the verdict is that canonicality is **not**
load-bearing today, and the reason is structural rather than lucky:

- every consensus value is hashed over **field elements**, never serialized bytes — the bundle
  hash, the nullifier, note commitments, the history digest;
- the on-chain record is a fixed-width 64-byte encoding whose decoder **rejects** out-of-range
  limbs rather than reducing them, so encode∘decode is a bijection;
- proof blobs are never hashed, compared, or used as a map key. The never-re-sign rule compares
  decoded `Transfer` values, not bytes.

So `bincode`'s trailing-byte tolerance was a free malleability channel with nothing downstream
of it. It is closed anyway (`accept.rs` now decodes strictly), `btc`'s OP_RETURN parser now
rejects trailing pushes, and a test pins the upstream behaviour that field elements out of
range are rejected — which we depend on and nothing asserted.

**A second instance, found 2026-07-28.** Proof blobs are malleable too: an honest transfer proof
carries `preprocessed_local: None`, and a proof carrying `Some(vec![])` verifies identically on
different bytes (`[DESERIALIZE]`). Same verdict, same reason, same expiry — it is safe only
while nothing treats a proof's bytes as its identity.

**What would break it:** the accumulator (`[ACC]`) makes record encodings consensus-visible.
An implementer who hashes `bincode::serialize(&record)` as a Merkle leaf, instead of absorbing
field elements through the existing sponge, makes canonicality load-bearing instantly — and
trailing-byte tolerance becomes a non-membership-proof problem. Batching to a 32-byte root has
the same exposure. Swapping encoders does not help: `postcard` uses varints and is not
canonical either. The property to preserve is this one, not a choice of library.

### Deserialization runs before validation `[DESERIALIZE]`

`wallet2/src/accept.rs` calls `bincode::deserialize` on attacker-supplied bytes before any
structural check, then hands the result to `p3_verify`.

**Partly closed 2026-07-27.** The unbounded reads are gone: mailbox files are size-checked
against their metadata *before* being read, so a stranger cannot make a wallet pull an
arbitrarily large file into memory; `MAX_LINEAGE` caps how many hops can be presented; and the
decode is now strict about trailing bytes. Rejected mail is also discarded rather than
re-verified on every future scan, which was the largest amplification here by a wide margin.

**Closed 2026-07-28 — and measuring it corrected two beliefs.**

The boundary exists: `prove::catching_panics` wraps every verifier entry point and converts an
unwind into `Rejected::Panicked`. It sits in `air`, not in `wallet2::accept`, because `accept`
is not the only caller — the iOS FFI and the Signal path verify too, and a net that lives in one
caller is a net the next caller does not have.

**Correction 1: the panic surface is narrower than this entry assumed.** `air/tests/
a_hostile_proof_cannot_crash_the_wallet.rs` fuzzes an honest proof two ways. Random byte
mutation: 338 mutants decoded, **every one rejected cleanly, none reaching the boundary** — a
flipped bit breaks a Merkle path and FRI refuses long before a length field is used as an index.
Structural mutation of the vectors whose lengths the verifier trusts (truncated, emptied,
doubled openings and quotient chunks): 13 of 14 refused with `InvalidProofShape`. Upstream
checks its own shapes more carefully than we credited. The net is kept because "we could not
find a panic" is not "there is none", but it is defence, not a patch over a known hole.

**Correction 2: the fourteenth structural mutant found a proof malleability channel.** The
transfer AIR has no preprocessed trace, so an honest proof carries `preprocessed_local: None`.
A proof carrying `Some(vec![])` is **different bytes and verifies identically** — the field is
not part of the statement and the verifier ignores it. Harmless today for exactly the reason in
`[NO-BYTE-IDENTITY]`: proof blobs are never hashed, compared, or used as a map key, and the
never-re-sign rule compares decoded `Transfer` values rather than bytes. It is the same argument
that made bincode's trailing-byte tolerance harmless, and it has the same expiry date —
**`[ACC]` makes encodings consensus-visible**. Pinned as `Expect::Malleable` in that test so the
next person to make proof bytes an identity has to walk past it.

---

## Engineering

### Front-running the first occurrence `[FRONTRUN]`

**A liveness failure, not "griefing".** Records are keyless, so a mempool watcher can copy a
revealed nullifier, pair it with a garbage bundle hash, and out-fee the honest record —
permanently invalidating that payment. `formal/baserail.qnt` (module `griefable`) reproduces
it in three steps and, more usefully, shows the safety property **holds** in exactly those
runs: the attacker gains nothing, ever. That is why the old name was wrong. But a safety
failure needs a check and a liveness failure needs a recovery path, and this has none — the
note is unspendable forever with no route back.

**DECIDED for v1 (2026-07-26): accepted and documented, not fixed.** The window is narrow and
precisely bounded. With Signal as transport the transfer travels encrypted, so the only
public exposure of a nullifier before confirmation is **the record transaction sitting in the
Bitcoin mempool**. Exploiting it means out-feeing that transaction, paying real fees per
attempt, gaining nothing, and burning exactly one payment's note. Spite-only and
attacker-pays; pricing every honest payment against it was judged the wrong trade.

**The race was staged as a demo (2026-07-29, `demo/frontrun.sh`), deleted with the demos on 2026-07-31.** It staged the loss against a real
`bitcoind` and asserts all three halves of the accepted trade: the honest payment is destroyed
(`LostRace`, and *discarded* rather than re-verified forever), the attacker creates no coin (supply
unchanged, every record still attested — a garbage record opens no note, so nobody can spend it),
and — the part that was only ever argued before — **the payer's own change is quarantined too.**
Alice's change descends from the same hop whose record lost, so `reconcile` moves her spendable
from 380 to 0. A wallet that still called that note spendable would be lying to its owner in
exactly the way the payee was nearly lied to.

Two honest limits on the harness, stated rather than buried. First, on regtest the backend mines
its own block on publish, so there is no unconfirmed window on that chain to read a nullifier out
of; the harness therefore *hands* the attacker the nullifier (via `uv nullifier`), which is
strictly more generous to them than reality, and tests what happens when they win. The
mempool-read step is what a signet run would exercise. Second, an attacker cannot bind a nullifier
to arbitrary *bytes*: each 4-byte limb must be below the field modulus or the record decoder
refuses it — the first version of the harness used `0xba` repeated and was rejected for that
reason.

**Still owed for v1:** fee guidance for record transactions (a well-fed record confirms before
it can be raced), and **the economics**, below.

#### The mitigation nobody had written down: submit the record out of band

**The attack requires mempool visibility.** This entry says so in as many words — "a mempool
watcher can copy a revealed nullifier" — and then never proposes removing the visibility.
Submitting the record straight to a miner, or through a private relay, collapses the exposure
window to zero. **No protocol change at all.** This is how MEV protection works elsewhere and it
applies here unchanged.

Stated with its costs, because it is a mitigation and not a fix:

- it trusts the submission path for **liveness only** — a record that never lands is a retry, not
  a loss, so the trust is bounded in the way that matters;
- it does nothing if the payer broadcasts normally, so it is transport plus guidance rather than
  a guarantee;
- a miner who sees the transaction can still grief it, so the trust **moves** rather than
  vanishing;
- depending on a private relay is real centralisation pressure, and naming it is better than
  discovering it.

Owed: the transport option, and the guidance saying when to use it.

#### Two fixes that do not work, recorded so they are not re-proposed

Both look obviously right. The repo's own precedent for writing these down is
`formal/README.md`'s linkage attempt table, which is why the ghost encoding was found instead of
re-attempted.

**"First occurrence *with a verifiable bundle* wins."** The receiver *can* tell the honest record
from the grief — the honest one's bundle hash has a verifying proof and the griefer's has no
bundle at all. It fails because **verifiability is observer-relative**. Alice double-spends to Bob
and Carol. Bob holds bundle 1, Carol holds bundle 2. Bob sees record 1 first, can verify it,
accepts. Carol sees record 1 first and **cannot verify it — she does not have that bundle** — so
she treats it as unverifiable and accepts record 2. **Both accept.** A rule that two honest
parties evaluate differently is not a rule; it is the same defect as the free mint.

**Epoch'd nullifiers.** Give a note a family `nf_e = H(nk ‖ C ‖ e)` so a griefed note can be
re-spent at the next epoch, turning a permanent loss into a griefing *tax*. Attractive because
`baserail` says liveness failures need recovery paths and neither of its two has one. It fails
because a receiver must then check that no *other* epoch's nullifier was bound to a real payment,
and cannot — bundles are private. Refusing whenever any epoch is bound restores the original
problem; not refusing permits a double-spend.

#### The economics, worked 2026-07-31 — and it is a cheap weapon on the naive ratio

"The attacker pays and gains nothing" is true and it was hiding the important number. The attacker
gains nothing, yes — but *pays how much, to destroy how much?* A grief is **one record
transaction**, 186 vB measured. At real fee rates:

| regime | sat/vB | attacker cost | ≈ USD at $100k/BTC |
|---|---|---|---|
| quiet / signet | 1 | 186 sats | $0.19 |
| normal | 10 | 1,860 sats | $1.86 |
| busy | 50 | 9,300 sats | $9.30 |
| congested | 150 | 27,900 sats | $27.90 |

**Victim damage is the full value of the griefed note, and the attack does not scale with it.** The
same $0.19–$28 transaction strands a note of *any* size. So the cost-to-damage ratio → 0 as the note
grows: **on the naive ratio this is a cheap weapon, not a nuisance**, and that is the honest reading.
The safety proofs are all intact — no coin is stolen, supply is unchanged — and none of them would
notice that a $2 transaction can freeze an arbitrarily large payment.

**What actually bounds it is the exposure window, not the fee — which makes the out-of-band
mitigation load-bearing rather than optional.** The attack requires the revealed nullifier *from the
mempool, before the honest record confirms* (`spec/99:274`). Submitting the record out of band —
direct to a miner, or through a private relay — collapses that window toward zero, and the attacker
never sees the nullifier in time. The mitigation was recorded above as a nice-to-have; the economics
say it is the defence. **Owed for v1: build the out-of-band submission path, and state in the client
that broadcasting a record normally, in a congested mempool, is the exposed case.** Until then the
honest posture is not "accepted trade" but "cheap to grief, mitigated only by transport we have not
yet built."

*What would change this:* an on-chain cost the griefer must pay proportional to the note's value
(no design fits the 17-byte record headroom — see `[ACC]`'s negative result), or a record that only
the owner can publish (same headroom wall). Neither exists, which is why the window is the whole
defence.

`btc/tests/reorgs_on_a_real_node.rs` covers the *safety* half against a real node: a duplicate record for an
already-bound nullifier is inert, so a stranger cannot redirect a payment. What it does not yet
stage is the race itself — a garbage record landing *first* and burning the payment — which
needs a record published for a nullifier before the honest wallet's own transaction confirms.
That is the residue this item accepts, and it remains untested rather than unaccepted.

<details>
<summary>The escape hatch, specced so it is a switch rather than a redesign: commit-reveal records</summary>

Publish `C = H(nf ‖ H(bundle) ‖ salt)` — 32 bytes, revealing nothing. Once `C` confirms,
publish the 96-byte reveal `(nf, H(bundle), salt)`. First occurrence of a nullifier is
redefined as *the earliest confirmed commit whose reveal opens correctly*, so a mempool
watcher sees either an opaque commitment or a reveal whose commit already out-ranks anything
they could now publish. This kills the race structurally.

Cost: two transactions, doubled fees, one extra confirmation of latency, and a rework of the
first-occurrence rule. All four `formal/` models would need re-verification against the
two-phase rule — budgeted as part of flipping the switch, not before.
</details>

### Minimum scan start, and the index's sharp edges `[SCAN-FLOOR]`

**Largely fixed 2026-07-27. What remains is a decision and a harness, not a bug.**

This entry previously said reorg rollback had "landed". It had landed in `wallet2` only, and
against the real Bitcoin backend it did nothing: the index stored no block hashes, never removed
an entry, and had no reorg detection, so a withdrawn record was still returned and — because
depth came from a stale height via `saturating_sub` — its depth *grew*. Reconciliation then
confirmed the note was fine. The formally-proven repair was exercised solely by
`MockChain::reorg_drop` in tests.

**What now exists:**

- **Detection in one RPC.** A block header commits to its parent, so a hash commits to an entire
  ancestry: if the hash at the highest scanned height still matches, everything below is
  unchanged. The backwards walk exists only to *locate* a fork, never to detect one. A chain
  shorter than what was scanned proves a reorg for free.
- **Rollback.** Entries at or above the fork are dropped — `>=`, because the fork block's own
  records are exactly the ones in doubt. First occurrence re-establishes itself on rescan
  without extra machinery. A reorg deeper than the 144-block window rebuilds from the floor
  rather than guessing.
- **A version field, not `#[serde(default)]`.** An old index is rebuilt. The alternative would
  have loaded one claiming to have scanned a range it holds no hashes for — detection could not
  run over it and nothing would say so. That is the `[ASSUMPTIONS]` shape exactly, and it is the
  trap this fix most wanted to avoid.
- **A persisted rollback counter**, because every `uv` invocation is its own process and an
  in-memory flag would be consumed by whichever command happened to trigger the scan. `uv scan`
  and `uv send` both reconcile when it moves — `send` as much as `scan`, since spending a note
  whose ancestry was just orphaned is the loss case.
- **A three-way `Lookup`.** `first_occurrence` no longer returns `Option`, which conflated "no
  record exists" (fail-closed, correct) with "my view cannot see that far back" (fail-**open**).
  There is deliberately no `as_option()`: the value of the change was that all five call sites
  became compile errors until somebody decided what the third answer meant. `Unanswerable` is
  transient, so an unanswerable bundle is kept rather than discarded.
- **An issuance floor.** An anchor records the height below which its asset cannot have records,
  stamped at *tip minus a reorg margin* rather than the bare tip — that tip can itself be
  reorged away, and a floor above a record is a silent fail-open. The check lives in `accept`,
  not the CLI, so the iOS and Signal paths inherit it.
- **Reconciliation does not quarantine on an unanswerable view.** Quarantine is a one-way door;
  nothing un-quarantines a note. Treating "I cannot tell" as "this is bad" would let a node
  mid-resync permanently freeze the user's money. Those notes are reported separately and left
  alone — safe, because `accept` refuses an unanswerable view outright, so an unjudged note
  cannot be *taken*.

**Seen to work, not merely written.** `btc/tests/reorgs_on_a_real_node.rs` runs a real `bitcoind`, publishes a
record, confirms it, and then forces two different reorgs with `invalidateblock`:

- one where the orphaned record is **re-mined** into the new chain — the note must survive, and
  a wallet that panicked and quarantined a still-good note would fail here;
- one where the record is **lost for good** — the note must quarantine.

Both pass. The harness earned its place immediately by failing: detection is lazy, living
inside a lookup, so reading the rollback counter before doing any lookup read a *stale* one and
the wallet was permanently one invocation behind the chain. `Chain::refresh` fixes it, and
removing that call makes the harness fail again — checked, because a harness nobody has watched
fail is not evidence.

Three things about Bitcoin Core that the harness had to learn the hard way, recorded so the
next person does not: regtest mining is deterministic, so re-generating on a fork rebuilds the
byte-identical block that was just invalidated and Core rejects it as `duplicate-invalid` (mine
to a fresh address); `mempool.dat` is written on the shutdown *before* you set
`-persistmempool=0`; and the node's own wallet rebroadcasts the transaction it created unless
started with `-walletbroadcast=0`.

**Still open:**

1. ~~**Restoring the 1-confirmation tier.**~~ **Decided 2026-07-28: no.** `formal/reorg.qnt`'s
   `shallow` module proves depth-1 acceptance violated by a 2-block reorg, and only `reconciled`
   rescues it — which makes safety conditional on the receiver reconciling promptly, something
   the protocol cannot enforce. The tier would buy accepting a small payment about twenty
   minutes sooner; it would risk money evaporating for a receiver who did nothing wrong. Three
   is the floor. The reasoning lives with the code, at `wallet2::chain::required_confirmations`.
2. **`[FRONTRUN]`'s adversarial race test.** The harness exists now and is the right place for
   it; the race itself is not yet scripted.
3. **Un-quarantine.** A note can enter quarantine and never leave. The restore condition would
   have to be the full positive check — found, bundle matches, deep enough — never "the failing
   check stopped failing", because a note that un-quarantines itself is a note that can be spent
   again.

(A fourth item, "the reorg suite is manual", is closed: `btc/tests/reorgs_on_a_real_node.rs` runs in CI against a pinned
`bitcoind`, with a step that fails the build rather than letting the script's own `SKIP` path
pass silently.)

### Verify-before-you-trust ordering `[DOS-ORDER]`

A stranger can fill a mailbox with junk bundles, and each costs the recipient one proof
verification *per hop*.

**Two of the three fixes landed 2026-07-27, and they were the big ones.** Rejected mail is now
discarded rather than left in place — previously a single junk bundle was re-verified on
*every* subsequent scan, forever, which dominated every other cost in this item. The policy is
verdict-aware: `NoRecord` and `InsufficientDepth` are payments in flight and are kept;
everything else can never become valid and is thrown away. And `MAX_LINEAGE` now caps how many
hops a stranger can make you verify, refused before any proof is deserialized.

**The remaining piece is not what this entry originally proposed, and the original would have
made things worse.** Checking the chain first is *not* "nearly free": on an index miss
`BitcoinChain::first_occurrence` falls through to a full mempool walk — `get_raw_mempool` plus
a `get_raw_transaction` per txid — against a proof verification of 1.6 ms. A junk nullifier is
attacker-chosen and therefore always a miss, so the literal fix trades 1.6 ms of local CPU for
a multi-second RPC storm and hands the attacker a lever on the receiver's node.

**Closed 2026-07-27.** `first_occurrence` is confirmed-only now. The mempool fallback could
never change a verdict — a mempool occurrence reports depth 0, `accept` requires at least 3 and
`reconcile` at least 1 — so on those paths it was pure cost, and a junk nullifier always missed
the index and therefore always triggered the full walk. `publish` still checks the mempool,
because there the answer is actionable: it stops a needless duplicate broadcast.

**The reorder itself is not done and no longer looks worth doing.** With junk mail discarded,
the lineage capped, and the mempool walk off the hot path, what remains is one proof
verification per hop of a bundle that reached the wallet at all — and the sender pays a Bitcoin
transaction per hop for the privilege. Reordering would save a verification on the first bad
hop of a bundle whose earlier hops verified, which is a narrow case. Reconsider if a real
workload disagrees.

### Proof merging `[MERGE]`

**The product gap is closed; the protocol limit remains.** A transfer still takes exactly one
input, so two notes with two histories still cannot be spent in one transfer. What changed
2026-07-27 is that the *wallet* no longer needs them to be: a payment larger than any single
note is sent as several independent single-input transfers that add up. A wallet holding 1 + 1
that owes 2 can now pay, which it previously could not do at all.

**Why this is safe, and why the safety is not obvious.** `formal/baserail.qnt`'s `splitRecords`
deadlock — two transfers over the same two notes whose records interleave, leaving both notes
consumed and nothing paid — needs a conjunction across records: settlement requires *every*
input bound to the same transfer. With one input that `forall` degenerates to "my one record
won", so there is nothing to interleave. And k transfers over k distinct notes carry k distinct
nullifiers, so their records cannot race one another at all.

**That argument is now checked rather than asserted.** `formal/baserail.qnt` gained a `split`
module and two instances. `splitPayment` proves `paymentRemainsPossible` holds where `noMerge`
violates it at the initial state, and `nobodyElseGetsPaid` still holds. Leaving the directory
containing a module that says the payment is impossible, while the wallet quietly did it
anyway, was not an option.

**The residual is partial delivery.** Under the accepted `[FRONTRUN]` risk a burnt record leaves
the payee short by one note rather than the whole payment — `splitGriefed` violates liveness for
exactly that reason, and should. This is strictly better than the merge alternative, where one
burnt record makes the whole multi-input transfer unsettleable and consumes *every* input. But
it is a genuinely new outcome, "the payee got 3 of 4", and there is no invoice to reconcile it
against. A payer sees which parts published; a payee sees what arrived.

**Costs, so nobody is surprised:** k notes means k Bitcoin records (k fees), k address slots,
and k proofs. Selection is largest-first to keep k small, and the wallet refuses up front if the
balance is short or the address has too few slots left — before publishing anything, because a
payment that publishes two of three records has spent real money and paid nobody in full.

**Still open at the protocol level:** a genuinely multi-input transfer. It needs a second
commitment opening, a second nullifier and a second anchor in-circuit, which pushes the trace
past 1,024 rows and roughly doubles proving cost — and it must ship with either atomic
multi-input settlement or the never-two-live-transfers discipline (module `atomic` holds both).
Not worth doing to circuits whose first forgery was found this week; it wants the audit first.

### Bound the ancestry — settlement proven in-circuit `[ACC]`

**The most substantial open design here.** Previously buried inside a completed item, which
is why three other files cite it by a number that points at closed work.

The ancestry rule ([§7](../SPEC.md#7-records-and-settlement)) is correct but linear: O(n) chain lookups per receive,
and **every nullifier in a coin's history is revealed to whoever serves the chain view**. Both
follow from settlement being checked *outside* the proof.

The fix: define `A_h`, a canonical accumulator over every record in blocks ≤ h in the existing
first-occurrence order — a deterministic function of the Bitcoin chain, so no consensus, no
committee, no trust. A prover then shows in-circuit that each ancestor's first occurrence
within `A_h` is the claimed bundle: inclusion of the winner **plus non-inclusion of any
earlier record with that nullifier**. The receiver checks one thing — that `A_h` matches its
own view at height h.

This buys O(1) lookups and deletes the chain-view leak. *(The rest of this sentence used to claim
it "restores honest O(1) receive" and "recovers the ancestry privacy … since nothing would need
transmitting at all." **Both are Part 2 consequences**, as the table below assigns them, and reading
this paragraph instead of that table is what produced two failed designs on 2026-07-30.)*

**Open sub-problems:** the accumulator structure (non-membership is the hard half — a
nullifier-keyed sparse or indexed Merkle tree, not a position-ordered MMR); reorgs mutate
`A_h`, tying into the confirmation policy; scan completeness becomes load-bearing, since an
incomplete scan yields a silently wrong root; batch leaves must be included; a prover needs
the full record set while a receiver needs only `A_h`. Light clients that cannot compute
`A_h` get the ordinary SPV progression — multi-source agreement, then fraud proofs (which fit
unusually well here, since clients already sit on a messaging network), then recursively
proving the accumulator itself.

Notably **not** a MobileCoin-Fog-shaped problem: Fog makes a query oblivious inside an SGX
enclave; this deletes the query, so no enclave and no attestation appears anywhere.

#### It is two decisions, not one

Written down 2026-07-30, before measuring anything, because the previous paragraphs have been
treating this as a single go/no-go and it is not. Two independent mechanisms hide inside `[ACC]`,
with different costs, different risks, and different things they buy:

| | **Part 1 — in-circuit settlement** | **Part 2 — lineage compression** |
|---|---|---|
| Mechanism | each hop proves, in its own circuit, that its record is the first occurrence of its nullifier in `A_h` | hop *n*'s proof verifies hop *n−1*'s proof, so a lineage is one proof |
| Buys | **the chain-view leak dies** (no nullifier is ever asked about) and receive drops to O(1) chain lookups | receive drops to O(1) *proof verifications*, and **ancestry privacy comes back** because nothing per-hop is transmitted |
| Needs | Merkle inclusion + non-inclusion in-circuit | a FRI verifier expressed as an AIR |
| Risk | low — arithmetic in a primitive already in the circuit | **high — this is the research** |

Part 1 alone is worth having. It kills the privacy problem that motivated `[ACC]` in the first
place, and it does not need recursion. Deciding both at once would let the hard half veto the easy
half, which is how a design ends up with neither.

#### The cost model is countable, which is why a rule can be sharp

**One trace row is one Poseidon2 permutation** (`air/src/authproto_air.rs`: 15 sponge rows padded
to 16). So Part 1's cost is not a mystery to be discovered, it is a count:

- One Merkle path of depth *d* is *d* compressions, so *d* rows.
- **Non-inclusion is the hard half of the design but not of the cost**: in an *indexed* Merkle
  tree it is one inclusion proof of the predecessor leaf plus a range check on the key — so
  another *d* rows and a handful of columns, not a new primitive. A position-ordered MMR cannot
  do this at all, which is why the structure has to be nullifier-keyed.
- At 2^24 records, *d* = 24, so a hop costs ~48 rows on top of today's 15: **16 → 64 rows**,
  a 4× trace.

That arithmetic predicts Part 1 lands near 4–5× today's prove time. **Prediction is not
measurement**, and the whole reason this project measures before deciding is that this kind of
arithmetic was wrong by two orders of magnitude the last time this project trusted it over a
measurement. The number below is what decides.

#### The rule, recorded before the measurement

**Part 1 is built if a hop proving its own settlement in-circuit lands inside the envelope of the
signature circuit this project already shipped** — ≤ 0.215 s prove, ≤ 208.0 KB proof, ≤ 114 MB
peak RSS, hiding configuration, same machine, one configuration per process.

That bar is chosen because it is not arbitrary: those are the measured costs of the
WOTS+-verifying production circuit that ran on the money path until 2026-07-29 and was considered
acceptable enough to ship and to run on a phone. **A cost we already shipped cannot be used to
reject a feature that buys more than that one did.** If Part 1 exceeds it, that is a real refusal
with a real reason.

**Part 2 is built if one recursive step — verify one parent proof and prove this hop's own
transition — costs ≤ 1.0 s prove and ≤ 1.0 GB peak prover share**, same machine and
configuration. The reason for those two numbers specifically: the sender does this work, the
sender is on a phone, an A18 measures at parity with this laptop on the current circuit
(0.007–0.008 s against ~0.011 s), and iOS terminates an app well before 1.5 GB — so 1.0 GB leaves
room for the host app's ~80 MB and a margin, and 1.0 s is a payment that sends in about a second.

**Both parts refuse loudly rather than quietly.** If Part 2 misses, Part 1 ships alone and the
consequences are stated where the claims are made, not buried here: per-hop proofs keep being
transmitted, ancestry privacy stays a **known limit** rather than a solved problem, and the
256-hop cap plus issuer redemption cycles remain the answer to unbounded growth. If Part 1 also
misses, `[ACC]` is refused entirely and said so as plainly as WOTS+'s removal was said, and the
chain-view leak becomes a permanent documented property of light-client operation instead of a
problem with a plan attached.

**What gets measured, and the one place a proxy is used.** Part 1's dominant cost is trace height
at a fixed column count, and every row of this AIR — sponge or Merkle — is the same Poseidon2
permutation, so **a 64-row trace of the current circuit measures the shape Part 1 will have**
before the Merkle constraints exist. That proxy is honest about exactly one thing and not
another: it captures the prover's cost, which is what the rule is about, and it captures nothing
about whether the Merkle constraints are *sound*. A proxy measurement is not a build, and it
cannot be reported as one. Part 2 gets no proxy — a FRI verifier's cost cannot be inferred from a
padded trace, so its number waits for a prototype and until then the honest statement is that
Part 2 is unmeasured.

Ledgered by subject hash (`./scripts/subject-hash.sh`), like every other measurement here.

#### Part 1 measured, 2026-07-30: the rule passes with an order of magnitude to spare

Subject `6a7813d3b1a9dd45`, harness `air/src/bin/acc-shape`, hiding configuration (the payment
format), **one process per height** so each peak-RSS figure belongs to one circuit, three cold
runs each. **Every proof was verified, not merely produced** — including the padded ones, which
is the check that says a taller trace of this AIR is still this AIR.

| trace height | what it represents | prove (3 cold runs) | proof | peak RSS |
|---|---|---|---|---|
| 16 | today's circuit — **the control** | 0.0107–0.0349 s | **117.2 KB** | **5 MB** |
| 32 | | 0.0122–0.0406 s | 127.9 KB | 6 MB |
| **64** | **Part 1 at 2^24 records (d = 24)** | **0.0205–0.0310 s** | **139.5 KB** | **9 MB** |
| 128 | d ≈ 56 | 0.0290–0.0503 s | 151.8 KB | 13 MB |
| 256 | d ≈ 120 — a tree of 2^120 leaves | 0.0589–0.0903 s | 165.0 KB | 22 MB |

The control agrees with the published figure exactly on the two deterministic columns — 117.2 KB
and 5 MB — which is what says this harness measures the same circuit as `air/src/bin/measure`.

**Against the rule** (≤ 0.215 s, ≤ 208.0 KB, ≤ 114 MB), using the **worst** of the three runs at
height 64 rather than the best, because that is how a threshold should be cleared:

| | budget | measured (worst) | inside by |
|---|---|---|---|
| prove | 0.215 s | 0.0310 s | **6.9×** |
| proof | 208.0 KB | 139.5 KB | 1.5× |
| peak RSS | 114 MB | 9 MB | **12.7×** |

**Part 1 clears its cost rule.** *(Wording corrected 2026-07-30 — this said "Part 1 is built", and
an adversarial review of that conclusion found it was carrying much more weight than a cost
measurement can bear. See "What the cost rule does not decide" below, which is the more important
half of this entry.)* And the more useful finding is the shape of the last table row: at 256 rows
the circuit is still inside every budget, and 256 rows is a Merkle depth of about 120 — a tree of
2^120 leaves, which is more records than Bitcoin will ever carry. **Trace height is not the
constraint on this design.** Whatever makes `[ACC]` hard, it is not the cost of hashing a path.

**Three honest qualifications**, none of which move the decision:

- **The timings are noisy — about 3× spread on a cold process** at these sub-100 ms scales, which
  is why the table gives ranges and the decision uses the worst case. Proof size and peak RSS are
  deterministic and repeated exactly across runs.
- **The proxy holds the column count fixed at 361.** Real Merkle constraints want a few more:
  a sibling digest and a direction bit per row, plus range-check columns. That is bounded and
  small — **299 of the 361 columns (83%) are the Poseidon2 permutation witness**, so a sibling and
  a bit is on the order of 2–3% growth, not a doubling. Bounded, but *unmeasured*, and said so.
- **This is a cost measurement and not a design.** It says nothing about whether Merkle inclusion
  and predecessor non-inclusion over this layout are *sound*, which is the whole of the work and
  all of the risk. Part 1 being affordable is not Part 1 being right.

**Part 2 (recursion) remains unmeasured, and the rule for it stands unexecuted.** It gets no
proxy, for the reason stated above: a FRI verifier's cost cannot be read off a padded trace.

#### A safety finding that gates Part 2, ahead of any cost measurement

**Written 2026-07-31, and it is the cheapest artifact on this whole entry — a formal model, not a
circuit.** Before any FRI-verifier prototype, one question decides whether recursion is even safe:
**what does a reorg do to a recursive proof?**

A recursive proof is bound to the chain state it was made against — an accumulator root at some
height. The walk design that ships survives a reorg by *re-walking* the new chain
(`reorg.qnt`'s `reconciled` module proves it stays safe at all depths). **Recursion cannot
re-walk, because its entire purpose is that the wallet discarded the ancestry.** A reorg below the
height a coin's proof committed to orphans that proof, and there is nothing left to rebuild it
from. The coin is valid — its records were re-mined, no double-spend — and **permanently
unspendable.** That is a liveness failure, and `reorg.qnt` had no liveness property until now.

`reorg.qnt` gained a `recursion` module with a root-freshness abstraction — one fork-height
variable, no accumulator tree — and the liveness property `paymentRemainsPossible`, in `baserail`'s
shape. Two runs, in `formal/verify.sh`:

- `recursionReprovable` (the wallet kept the ancestry, or the walk) — **holds**, the control.
- `recursionStrict` (pure recursion) — **violates in 3 steps**: mine to height 1, receive a coin
  whose proof commits to height 1, reorg to height 1. The proof's root is rewritten, the coin is
  stranded.

**So Part 2 cannot ship as stated.** The counterexample names the exact tension: recursion buys
O(1) receive by throwing away the ancestry, and a reorg is precisely when the ancestry is needed
to recover. The available doors, none free: (a) retain enough ancestry to re-prove after a reorg —
which gives back the per-hop transmission recursion was meant to remove, so it is recursion in name
only; (b) a confirmation depth deeper than any reorg *before* a proof is trusted, pushing the
staleness window below `MAX_REORG` — a real option, at a latency cost, and it needs its own model;
(c) an on-chain root the proof commits to, so a reorg that changes the root is visible and the coin
is quarantinable rather than silently stuck — which turns the liveness loss into the safety-shaped
`quarantine` the walk already has. **Whichever, the decision rule for Part 2 now has a safety gate
in front of its cost gate, and the safety gate is failed by the naive design.**

#### What the cost rule does not decide — an adversarial review of "build Part 1 next"

**Written 2026-07-30.** A proposal that Part 1 be adopted as *"the largest available
proof-simplification"* was red-teamed and did not survive. It claimed Part 1 would delete
`linkage.qnt`, make `multihop.qnt`'s composition failure unrepresentable, remove `MAX_LINEAGE`, close
the bundle-size leak, and take lineages out of the wallet file. **Every one of those is a Part 2
consequence.** The table above already assigns them to Part 2, and the paragraph above already says
that if Part 2 misses, the hop cap and per-hop transmission both stay. The proposal contradicted this
entry from sixteen lines away — which is a demonstration that splitting the problem in two was right,
and that the split has to be **re-read** each time rather than written once and remembered.

Three of the following were nobody's finding before that review.

**1. Part 1 does not fix linkage, and cannot.** `linkage.qnt`'s attack is a hop consuming a note
**nobody ever created**. The accumulator is *nullifier-keyed* — it accumulates **records**, not note
commitments — and **records are keyless**, so anyone may publish one. An attacker invents an input
commitment, derives its nullifier honestly, publishes a record for it, and produces a perfectly valid
in-circuit first-occurrence proof for a note that never existed. Part 1 proves *"my nullifier settled
first"*, never *"the note it names existed"*. Fixing linkage in-circuit needs an accumulator over
**note commitments** — a second, different structure, not in this entry.

**2. Part 1 does not change the composition failure.** `multihop.qnt`'s switch is
`if (CHECK_ANCESTORS) ancestryWins(b) else hopWins(b)`. Part 1 changes what `hopWins` *consults* — a
proof instead of a chain lookup — not its shape. A receiver verifying only the final hop still gets
the free mint, because hop *n*'s proof attests nothing about hop *n−1*. Only recursion makes the
`false` branch unrepresentable.

**3. The incentive on scan completeness INVERTS, and this is the sharpest finding.** Today a prover
must exhibit their record's **presence**, and a truncated view cannot do that — a short scan gains an
attacker nothing. Under Part 1 a prover must exhibit **non-inclusion of any earlier record**, and
**non-inclusion is easier the less your tree contains.** A prover whose view omits the competing
record builds a tree in which that record genuinely is absent, and the non-inclusion proof is honest
*against that tree*. The prover computes `A_h`, and **the prover profits from computing it wrong.**

So this entry's standing claim that `[ACC]` is the eventual *removal* of the completeness problem is
**wrong in the Part-1-only configuration.** It does not remove the assumption; it promotes it from
per-nullifier and locally guarded to global and unguarded, and flips the failure direction to favour
the attacker. Part 1 also deletes the one completeness guard that works: `accept`'s refusal when
`scan_floor() > issued_below` is *per-asset* and carried in the anchor, and a record is
`nf ‖ H(bundle)` with no asset tag — so there is no per-asset accumulator and no per-asset floor.

**4. Reorgs are worse than "ties into the confirmation policy".** `A_h` orders leaves by chain
position (`btc/src/index.rs` sorts by height, then tx index, then vout). A reorg that **re-mines the
same records** — the ordinary outcome, and the case `btc/tests/reorgs_on_a_real_node.rs` stages as *"the note must
SURVIVE"* — leaves first-occurrence unchanged and **changes the root.** Every proof anchored at or
above the fork is then against a dead root. `reconcile`'s restore path cannot help: it works by
re-evaluating a predicate over current chain state, and a proof against a fixed root is not a
predicate. And the witness in every spend proof is that hop's spender's nullifier key, so **only the
original spender of each hop can re-prove** — a party several owners upstream with no obligation to
still exist. Recoverable quarantine becomes unrecoverable proof death, reintroducing the "frozen
forever" bug `reconcile.rs` records having fixed.

`reorg.qnt`'s two inductive claims do not *break* — they become **non-covering**, which is harder to
notice. `acceptedStaysValid` still holds; what a receiver needs becomes "the root my proof committed
to is still the root at that height", which the model does not state.

**5. It adds models rather than removing them.** Net: `linkage` kept, `multihop` kept, `reorg` kept
and needing a new property, **plus** an accumulator model whose semantics is a leaf *ordering* — the
construct Apalache handles worst, and one the ghost-variable rescue does not transfer to, because a
ghost can eliminate a derived query and not a primary state variable.

#### What Part 1 does buy, so the refusal is fair

The chain-view leak dies, and that is the largest privacy defect in the shipped system — mirror sync
exists solely to mitigate it and says so. `[DOS-ORDER]`'s worst lever dies with it: no per-nullifier
lookup means no attacker-chosen index miss falling through to mempool RPC. And the cost is settled
with an order of magnitude to spare. **That is a privacy and denial-of-service result — which is
exactly what the table above says Part 1 is, and no more.**

#### The decision, revised

**Do not build Part 1 next.** Build the artifact that decides whether it is safe at all: an extension
of `reorg.qnt` with a root-freshness abstraction — one fork-height variable, no tree — and a
**liveness** property, which that model does not have today. It is the cheapest thing on this list and
it is expected to produce a spendability counterexample within a few steps. If it does, Part 1 as
specified is unsafe and this entry needs redesigning before any circuit work.

Owed before any Part 1 code, beyond that model:

- a normative `SPEC.md` clause defining the **record total order** and the **record-validity
  predicate**, which today live only in `btc/src/index.rs` and become consensus the moment a root
  depends on them — note `[NO-BYTE-IDENTITY]` already says canonicality becomes load-bearing here;
- a decision on whether Merkle depth `d` is **pinned** (a new consensus parameter, since
  `prove::check_height` demands exact equality, and a floating height is what the 2026-07-27 total
  forgery exploited) or **floating** (which weakens `check_height`);
- a sound transient/permanent classification for a root mismatch, which a two-valued root comparison
  may not admit — the three-valued `Lookup` exists precisely so "I cannot tell" is distinguishable
  from "no", and a root comparison collapses that;
- isolating tests for every new constraint, written *before* the sweep runs: the ~14 new constraints
  have **no swept-clean predecessor to inherit from**, unlike the nine sponge-lane survivors.

One extension worth not spending a week on: making the nullifier a private witness so a receiver never
learns ancestors' nullifiers buys nothing, because the record is `nf ‖ H(bundle)` and the receiver
needs `H(bundle)` for history binding — anyone can read `nf` off the chain by its bundle hash. **The
ancestry leak is structural in the record format, not in where the settlement check runs.**

#### A second design, also rejected — and the general theorem it produced

**Proposed and killed the same day.** Accumulate **bundle hashes** rather than nullifiers. It looked
strictly better than Part 1: `H(bundle)` is *already* in every record, so **zero on-chain cost** and
the 64-byte/66-byte-script datacarrier invariant survives untouched; a bundle-hash-keyed **sparse**
tree is reorg-stable where Part 1's position-ordered tree is not; it needs only **inclusion**, so none
of Part 1's predecessor/ordering/non-inclusion machinery; and the completeness incentive points the
**right** way — a prover needs the tree to *contain* their leaf, so a short view hurts them. Three of
those four are true, and they are real repairs of Part 1's defects.

It dies four times over, and the first one is the general result.

**1. Records are keyless, so the accumulator proves publication and not legitimacy.** Mallory
publishes a record carrying the hash of a bundle *she invented*, whose outputs she owns. Her leaf
enters the tree honestly. She proves inclusion honestly, and spends a note descending from nothing.
**This attack is already staged in the test suite**: `wallet2/src/lib.rs`'s `fabricateHop` test
publishes `Record { nullifier: fab_transfer.nullifier, bundle_hash: fab_transfer.bundle_hash() }`
with the comment *"Settle the fabricated hop so only linkage can refuse it."* The only thing refusing
it is the receiver's byte comparison in `accept.rs` — precisely the check the proposal wanted to make
redundant. Cost of the free mint: one extra `OP_RETURN`.

> **The theorem, stated so a third variant does not get designed.** *No accumulator over any function
> of Ultraviolet's chain data can establish that a note was validly created — for any leaf shape —
> because publication is permissionless and Bitcoin validates nothing.* Changing **what** you
> accumulate cannot fix it. Only making the parent's *proof* a precondition of the child's proof —
> recursion, Part 2 — can.
>
> The one-line diagnosis: **`A_issuance` would be meaningful because the chain publishes the genesis
> commitment in the clear; `A_bundles` is meaningless because the chain publishes a *hash*, and a
> hash is unverifiable by the third party computing the tree.**

**2. Keying by bundle hash deletes first-occurrence.** `A_bundles` carries no nullifier association
at all, and the entire settlement rule is a nullifier→bundle binding. Free double-spend: Alice builds
`B1` (pays Bob) and `B2` (pays Carol) over one note, publishes `nf(C) ‖ H(B1)` — which wins the race —
then publishes `<any garbage> ‖ H(B2)`. Both hashes are now in the tree, and Carol, checking only the
accumulator, accepts. Part 1's nullifier keying was not decoration: it is the only thing that makes
first-occurrence *expressible* in a tree, and the proposal deleted it while calling it a simplification.

**3. It converts `[FRONTRUN]` from a liveness bug into a safety bug.** Today a griefer pairs a stolen
nullifier with garbage and — this is the accepted v1 trade — **gains nothing**. `demo/frontrun.sh`
asserts exactly that: *"no coin exists for the garbage record: it opens no note, so nobody can spend
it."* Under `A_bundles` the griefer pairs the stolen nullifier with `H(B*)` for a bundle whose outputs
they own, so one transaction both destroys Alice's payment **and mints the attacker a note**. The
accepted trade is void and a passing demo assertion becomes false. `baserail`'s
`recordsMatchTheirBundle` does not *break* — it goes **non-covering**, because `grief` only ever
writes the distinguished `GARBAGE` value and nothing models griefing with a real bundle id.

**4. The depth claim was wrong, and there is a trilemma.** Content-keyed plus inclusion-only means
depth is the **key width — 248 bits, not 32** — so a ~512-row trace, past the measured table. Depth
~32 needs either position keying (which kills the reorg-stability that was the design's best
property) or a compacted tree with **variable path length**, which the AIR cannot express: `SP` is a
rigid one-hot shift register seeded at row 0. Binding a prefix length is the "hard half" all over
again. The column growth was also mis-budgeted — ~361 → ~450, a **25% increase, not the 2–3%** the
Part 1 measurement assumed, and `NUM_PUBLIC_VALUES` (pinned at 56) would have to grow too.

**And the claim that motivated it was stale by one day.** "Deletes the hardest induction in the
suite" was true until 2026-07-30, when `linkage` became inductive **in 15.8 s** via the ghost
encoding. The proposal amounted to a circuit rewrite to save fifteen seconds of CI — and what it
would delete is not a liability but the four falsification rows that prove the receiver's linkage
check is load-bearing.

#### The filter that would have caught both proposals

Both failed designs share one signature: **they claim a benefit from the Part 2 column while
proposing a mechanism from the Part 1 column.** The table above already assigns each benefit to a
part, and both proposals were written a few lines away from it.

So, before designing a third: **write down which column each claimed benefit sits in, and refuse any
proposal that claims a Part 2 benefit without a FRI verifier in it.** If the mechanism is a single
in-circuit membership check and the claimed benefit is "ancestry is now sound", the proposal is
wrong before the details are read.

**What would have to change for these rejections to stop holding** — stated because a wall with no
door is indistinguishable from a failure of imagination: records would have to stop being keyless
(publication authorized by something only the owner can produce), or created commitments would have
to be published rather than hashed.

#### The theorem, strengthened — and why the byte cap was never the real constraint

The second door above was written as *"the honest minimum for in-circuit linkage without recursion —
`nf ‖ out0 ‖ out1` = 96 bytes against BIP-110's 83-byte cap"*, as though thirteen bytes of relay
policy were what stood in the way. **That framing is wrong twice**, and both corrections matter.

**First, BIP-110 is relay policy, not consensus.** An oversized `OP_RETURN` is a *valid* transaction;
it may not propagate through default nodes, and it can be submitted directly to a miner. Letting a
policy proposal veto a consensus design is backwards for a system whose premise is that Bitcoin
validates nothing about it. The datacarrier footprint is worth keeping as an *operational* property —
relayability is real — but it is not a wall.

**Second, and decisively: more bytes would not help.** Publishing created commitments does not fix
linkage either, for the same reason as everything else in this section — **nothing gates what gets
published.** Anyone can publish a commitment for a note they invented, exactly as they can publish a
record for a bundle they invented. So:

> **Strengthened theorem.** With permissionless publication and no consensus validation, **no
> on-chain data structure can establish that a coin was validly created.** Not an accumulator over
> nullifiers, not over bundle hashes, not over commitments, not over anything. Whatever is published,
> anyone can publish anything. **Validity must therefore travel with the coin**, and the only way to
> keep that constant-size is **recursion.**

**The contrast that explains it, because Zcash looks like a counterexample and is not.** Zcash
publishes note commitments and a set-membership proof suffices — but only because **Zcash's consensus
verifies every shielded transaction before its commitment enters the tree.** The tree contains only
validly-created notes. Bitcoin verifies nothing here. So the difference between Zcash and this design
is **not what is published; it is who validates.** Absent a validator, publication is not evidence.

#### What this says about Shielded CSV, and what to take from it

`SPEC.md` §12's comparison table already records the gap in the project's own words: **Shielded CSV's
receive cost is O(1); Ultraviolet's is O(history).** And the architecture behind that number is
exactly the split this entry has been conflating:

| question | Shielded CSV's mechanism | Ultraviolet today |
|---|---|---|
| *Is this coin already spent?* | the on-chain nullifier set | records + first-occurrence + `RecordIndex` — **the same** |
| *Did this coin come from a valid history?* | a **recursive proof carried with the coin** | the receiver **walks** every hop |

**Ultraviolet already has the first half and answers the second by walking.** That is the whole of the
O(history) difference, and the strengthened theorem says the walk cannot be replaced by any on-chain
structure — which is presumably why Shielded CSV uses recursion rather than an accumulator for it.

So "take more from Shielded CSV" means one specific thing: **adopt the split explicitly, and stop
asking the accumulator to do the ancestry job.** `[ACC]` Part 1 and Part 2 are not two sizes of the
same idea — they answer different questions, and only Part 2 answers the one that costs O(history).
Two designs died on 2026-07-30 for missing this.

What must **not** be taken: Shielded CSV's nullifier check is a Schnorr verification, so it is not
post-quantum. That is the axis on which this project differs, and it is the one thing not to import.

**The reframing that follows.** Recursion has been filed as an optional scaling feature. It is better
understood as **the missing half of a client-side-validation architecture** — the half that every
comparable design has and this one does not. It stays unmeasured and genuinely hard: a FRI verifier
expressed as an AIR, and four wrapper obligations (trace height, public-value count, verifier-built
publics, domain tag) move *inside* the circuit, which is the class that produced the 2026-07-27 total
forgery. But one fact cuts the other way and is worth stating: **recursion cost scales with the
circuit being verified, and that circuit went from 1,024 rows to 16.** The deferral reasoning predates
that change, and the measurement — Part 2's rule, still unexecuted — is now the thing worth doing.

### One address, two payers `[SLOT-COLLISION]`

**A fund-loss bug the single shared directory was hiding, found 2026-07-28 while scoping the
transport work.** Slot reservations live in `used-slots-<id>.json`, which is **payer-local**,
but the invariant they enforce — each slot paid to at most once — belongs to the **payee**. In
the demo every payer shares one `--home`, so they share the file. Two payers on two machines do
not, and both start at slot 0 without either doing anything wrong. `Store::insert`'s own doc
comment predicted this in as many words.

The payee's backstop was `.expect("fresh index")`. Two payments to one slot for *different*
amounts have different commitments, so the already-ingested check misses, both pass `accept`,
and the second insert panicked the scan — **after** earlier accepted bundles had been deleted
and **before** the wallet was saved. Measured on a wallet owed 700: it ended holding 300, and
the missing 400 was unrecoverable, its only copy of the lineage deleted.

**Fixed, in three parts.**

- **Durable before irreversible.** Accepted bundles are now deleted only after `save_wallet`.
  This is the receive-side of the rule the send path already enforces structurally
  (`send::broadcast` takes its persist step as an argument); the two paths disagreed and only
  one of them had been thought about.
- **A collision is never a panic.** It is a real settled payment with nowhere to sit, so the
  bundle is moved to `mailbox/unplaceable/` — kept, because discarding it destroys the only copy
  of the lineage, and moved, because leaving it in the inbox re-verifies it on every future scan
  (`[DOS-ORDER]`'s amplification). `uv status` reports the count.
- **The reservation filename no longer depends on the toolchain.** It was keyed by
  `DefaultHasher`, whose output is explicitly unstable across Rust releases, while
  `rust-toolchain.toml` floats on `stable` — so `rustup update` would have renamed every
  reservation file, every slot would have read as unused, and two notes would have landed on one
  spend anchor — one of them unspendable, both linkable, with no visible cause. (When this was
  written the consequence was worse: the slot held a signing key and the collision disclosed it.)
  Now SHA-256, pinned by a known-vector test.

**Per-peer batches, added 2026-07-28.** `uv address --for <peer>` records which slot range went
to whom in a sidecar ledger, and `uv status` lists what is outstanding. The mechanism was
already there — `allocate_index` is monotonic, so two `uv address` calls produce disjoint
batches automatically — what was missing was any record of who received which, so replenishment
was guesswork and a collision could not name the counterparty. It now does.

**Still open: the payee cannot prevent it.** Recording the batch makes a collision diagnosable
and survivable; nothing stops a payee handing one batch to two people, and the payee still
cannot see which slots a payer has consumed, because that state is payer-local by design. A
per-peer channel is what makes replenishment automatic rather than manual, so the last of this
closes alongside `[SIGNAL]`.

### WOTS+ is measured out `[PROOF-AUTH]`

**The decision rule fired on 2026-07-28, and it fired against WOTS+.**

The rule, recorded before the measurement: *WOTS+ is retained only if it measures more than 2×
faster than proof-native authorization; otherwise proof-native authorization becomes the design
and WOTS+ is removed.* Measured, same machine, same day, one configuration per process
(subject `5a67df5d591726b5`):

| circuit | trace | prove | proof | verify | peak RSS |
|---|---|---|---|---|---|
| production hop, hiding (WOTS+ in-circuit) | 1,024 × 457 | 0.215 s | 208.0 KB | 1.7 ms | 114 MB |
| **prototype hop, hiding (proof-native auth)** | **32 × 364** | **0.032 s** | **128.3 KB** | 1.0 ms | 36 MB |
| production hop, standard | 1,024 × 457 | 0.070–0.084 s | 158.3 KB | 1.4 ms | 67 MB |
| prototype hop, standard | 32 × 364 | 0.037 s | 90.4 KB | 1.4 ms | 36 MB |

WOTS+ is not 2× faster; it is **6.7× slower** on the payment format, with 1.6× the proof and
3.2× the memory. **So WOTS+ goes**, and spend authorization becomes what constraint 32 already
half-was: in-circuit knowledge of the committed anchor's preimage, with the whole statement —
bundle hash included — bound to the proof by Fiat–Shamir.

**Why the argument was never only speed.** Signing twice under one WOTS+ key discloses the key,
so *state loss is key compromise*: the sign-log, its version gate, replay-instead-of-resign and
fund-critical slot reservations all exist downstream of that one property, and that family has
produced several of this project's worst near-misses. Proving twice reveals nothing. Under
proof-native authorization, wallet-state loss degrades to inconvenience.

**The honest cost, stated before anyone asks.** The witness — the nullifier key — enters every
spend proof, so witness secrecy becomes load-bearing for **funds**: the hiding configuration
stops being optional on the money path, and the zero-knowledge property this project has so far
kept privacy-only becomes safety-critical. Contained: anchors stay one-time per note, so a leak's
blast radius is one note. The assumption base is unchanged — FRI and Poseidon2 are hashes, and
Fiat–Shamir binding is already load-bearing today. The prototype is also a conservative measure:
its note preimage keeps the production shape, `owner_pk` included, which a real proof-auth note
would drop.

**Migration complete, 2026-07-29 — every stage verified before the next began.**

The bill as it was written, and how each line was paid:

- **Authorization is the anchor-preimage constraint alone** (constraint 12, Fiat–Shamir over all
  56 public values, bundle hash included). No signature is made anywhere on the money path.
  Landed additively first (`kernel2::transfer_prove::prove_hiding`/`verify_hiding` beside the
  WOTS+ path, both green), then cut over, then the signature machinery deleted.
- **`owner_pk` is dropped from the note.** The from-scratch consensus circuit landed same day:
  note preimage 28 field elements (was 36), note sponges four absorb rows (was five), trace **16
  rows** (was 32 in the prototype, 1,024 in production). The tie table was re-derived from
  scratch and validated by the differential tests (host `sponge_states` and circuit `eval` must
  agree on a real hop) — they passed unmodified.
- **Fresh isolating tests and a fresh `air/mutants.py` sweep**: at the cutover, 16 mutants, 7
  killed, 9 survivors — the identical kill pattern before and after the `owner_pk` drop, which is
  what "the rewrite is the same circuit" looks like from the sweep's side. The nine were the
  sponge-lane cluster, and the only evidence they had was **inherited** from a circuit that had
  since been deleted. **Closed 2026-07-30**: the per-column probe
  (`air/tests/every_column_is_constrained.rs`) killed all nine directly, and the sweep now reads
  **16 of 16, 0 survived**, with 361 of 361 columns shown to provoke an objection. Ledgered in
  `air/COVERAGE.md` at subject `9bcccd1036e813d7`. The inheritance argument is retired.
- **Hiding-only enforced at every verify entry point**: `wallet2::accept` and every consensus
  caller go through `verify_hiding`; the height check (`prove::check_height`) is re-pinned for
  the 16-row circuit by `air/tests/trace_height_is_pinned.rs`, both directions, both configs.
- **The deletions, which were the point**: `wots_air.rs`, `transfer_air.rs` and the chain trace
  (~4,700 lines of circuit), `wots::sign` from the money path, replay-instead-of-resign and slot
  reservations as *fund-critical* state. The sign-log survives only as an idempotency cache;
  slot reuse is a privacy bug now, not key disclosure. `onetime.qnt` retired to the journal like
  `channels` (2026-07-29); `baserail.qnt`'s premises re-derived, its 9 rows unchanged.
- **Every anchor and asset minted before the change is invalid** — the one asset-invalidating
  break this campaign budgeted, spent while every coin is play money, stated loudly on the site.

**The landed numbers** (laptop, one configuration per process, `UV_MEASURE=standard|hiding
cargo run --release -p uv-air --bin measure`): hiding **~0.01–0.02 s / 117.2 KB / 5 MB peak**,
standard ~0.011 s / 81.5 KB / 4 MB, verify under 2 ms, trace 16 × 361 — an order of magnitude
faster and ~23× less memory than the design it replaced. **The iPhone numbers were re-measured**
on 2026-07-29 in a signed build on an iPhone 16e — the cheapest one Apple sells —
**0.006–0.012 s using 1 MB** beyond the app's own footprint, proof bytes identical to the Mac's.
They had been withdrawn when the circuit they described was deleted; they are back because they
were taken again, not because the withdrawal expired.

**What remains open here:** `[HIDING-UNVERIFIABLE]`. Zero-knowledge is now load-bearing for
funds, and the property is still not independently verifiable, which is exactly why it is named
for the professional review. The circuit-coverage half of this entry **closed 2026-07-30** and is
recorded above; it is named here as closed rather than deleted, because "what remains open" is a
list a reader trusts to shrink honestly.

### Tying a model to the code `[MODEL-CONFORMANCE]`

**First two rungs landed 2026-07-28.** `kernel2/tests/conformance_authorization.rs` replays
`authorization.qnt`'s own executions (frozen as `formal/traces/*.itf.json`) against the real
proof-native circuit: every spend the model attributes to the owner must verify, and the
forger-spend the strawman permits must be refused. `wallet2/tests/conformance_issuance.rs` then
replays `issuance.qnt` against the real `accept` genesis gate — the `strict` trace's accepted coins
clear it, and the `byAmount` free-mint coin (accepted in the model against a same-amount sibling) is
refused by it. That second one closes the loop on *this very bug*: the test is shown to fail if the
gate reverts to the amount-only check that shipped. This is the ITF-replay pattern, and **as of
2026-07-30 every model-only row has followed it: the count is zero.** Six rungs
(`authorization`, `issuance`, `multihop`, `reorg`, `baserail`, `delivery`), each shown to fail when
the rule it defends is removed — the model's frozen testimony is the test vector, so a code change
that diverges from the model fails a test derived from the model. `formal/regen-traces.sh`
regenerates the traces when a model changes (a review event, not a refresh).

**What closing it to zero did *not* do**, since a zero invites the wrong conclusion. Two rows drifted
in opposite directions and both were found only by checking them one at a time: S6 cited a test that
**did not exist**, and L4 was labelled untied while a conformance test for its exact claim had
existed for days. The matrix is a document, and documents rot in both directions — so the audit of
the matrix is now part of the phase gate, not an assumption about it.

**The gap that produced the free-mint bug, and the only one no amount of modelling closes.**
`formal/issuance.qnt` was right; the Rust compared amounts instead of identity. A verified model
plus an unfaithful translation is an unverified system, and nothing in either artifact can see the
other.

**The mechanism exists and is not exotic.** Quint 0.32.0 emits traces as Informal Trace Format
JSON — `quint verify --out-itf` for a counterexample, `quint run --out-itf` for simulation. A
trace is a list of states, each a map of model variable to value. Verified by export on
2026-07-28: the `byAmount` free-mint counterexample comes out as five states over seven variables.

The shape of the work:

1. A test-only adapter mapping model actions (`issueOpenly`, `issueSecretly`, `receive`) to real
   calls, and model variables (`minted`, `published`, `accepted`) to observable wallet and chain
   state. All of them are already observable; no production change is required.
2. A replay harness that walks a trace and asserts agreement at each step.
3. For a **counterexample** trace the assertion is sharper and is the whole point: the model says
   the invariant broke here, so the implementation must **refuse** here. Replaying `byAmount`
   against today's `accept` must yield `GenesisNotOnChain`.

**Start with `issuance.qnt`**, because it is the one model whose counterexample the code is known
to have once failed — so the harness can be shown to catch a real bug rather than argued to.

**The honest limit.** A wrong adapter is a wrong translation; this moves the trust rather than
removing it. What it buys is surface area: from an entire rule reimplemented by hand, down to one
mechanical mapping file where a mismatch is a failing test instead of a silent divergence.

### Supply is counted from Bitcoin `[SUPPLY]` — closed

**Closed 2026-07-28.** Was: nobody could check how much of an asset exists, and the file that
said so was unauthenticated. Now an asset's supply is the sum of its confirmed issuance records,
computed from Bitcoin with nothing fetched from anywhere.

The design is [`SPEC.md`](../SPEC.md#9-issuance-and-supply). The story — two wrong attempts and what
they taught — is in the
[journal](https://ultravienet.github.io/ultraviolet/journal.html); this entry keeps the decisions.

**What is in the code.** `kernel2::issuance` (a 76-byte record: tag, amount, asset id, genesis
commitment, all in the clear), `Chain::publish_issuance`/`issuances`, `uv issue` publishing one,
`wallet2::accept` refusing any lineage whose genesis record is not confirmed — three byte
comparisons, no derivation — `wallet2::reconcile` asking again after every reorg, and
`uv supply --asset X`.

**Two bugs fixed while scoping this, both 2026-07-28.**

- **The asset id was a published secret.** `cmd_issue` set `asset = keys.nullifier_key`, which
  `NoteKeys` documents as *"**Secret**: only the owner holds it"*, and `anchor.json` publishes the
  asset id. Since the anchor also carries the genesis commitment and
  `nullifier = H(Domain::Nullifier, key ‖ commitment)`, both inputs were public: anyone holding an
  anchor could compute the genesis nullifier **before the issuer ever spent**, publish one keyless
  garbage record, and kill the asset for one transaction fee. Now the owner key.
- **`anchor import` never compared the genesis commitment.** Two anchors sharing an asset id but
  naming different genesis notes both installed, so two payees each validated a different issuance
  and each believed they held the asset. Now refused.

**Two rule versions were wrong before this one, and both are reproducing counterexamples.**

- `byAmount` — the rule compared *amounts* rather than identity, so an attacker minted against an
  honest issuer's confirmed record.
- `globalSum` — the record hashed its details, so only a chain-wide total was computable, and an
  unpublished coin of one asset hides under records another asset paid for.

The general lesson, worth more than either bug: **`formal/issuance.qnt` was right both times.**
The model does not know what the code says, so a verified model plus an unfaithful translation is
an unverified system, and the gap is invisible from either side alone.

**The allowances are gone.**

- The genesis opening was `Option`, and absent meant *skip the supply check*. It is now required,
  and an anchor without one is refused at import where a person reads why. Removing the `Option`
  removed the allowance as a category — there is no longer a way to spell it.
- "Upper bound, not a total" is no longer true. The asset id is on chain in the clear, so an
  asset's records enumerate and sum exactly. `[STORAGE]` still stands, but it holds up
  *reissuance*, not counting.

**One residual, and it is narrow.** Nothing authenticates a record's asset id, so a stranger can
publish a **decoy** bearing someone else's asset. It creates no spendable coin — that needs a
secret only the owner holds — but it bears the id, so `uv supply` reports **attested** and
**unattested** separately and never sums them.

Closing it needs a signature over the record, and the scope of one is decided:
**a minter may attest, never validate.** A Bitcoin-authenticated minter is cheap and needs no
`[STORAGE]`, but it is Schnorr rather than hashes — deciding *validity* with it would let a
quantum adversary who took the minter key publish a record and construct a note opening to its
commitment, which is spendable money out of a broken signature. Confined to attestation, the same
break corrupts a number and nothing else. The money path stays hashes-only.

**Front-running, for completeness.** An asset id is public once its record reaches the mempool —
the same `[FRONTRUN]` window spend records have. The consequence is a bricked asset before it has
value, not stolen money, and the issuer re-issues under a fresh id.

**Reissuance is designed and not built.** Every `uv issue` mints a fresh asset; nothing can add to
an existing one. So what the code produces is fixed-supply, which is the safe direction and is not
the same as having built the policy that would allow anything else.

### Signal transport `[SIGNAL]`

**The direction is decided: a Signal-iOS fork on a linked device, and NO Signal infrastructure
of our own — ever** (decision 2026-07-30). The fork provisions as a linked device to a real
Signal account, the way Signal Desktop and signal-cli do, and talks to Signal's production
servers. Self-hosting is not a fallback and not a later phase; it is out of scope. The reasons
are below, and they are not going to change.

**What is proven.** A real payment crossed **Signal's own production service** on 2026-07-28,
carried by `signal-cli` as a linked device: a sealed Ultraviolet bundle went out as an
attachment over a genuine PQXDH session and came back in through the same `accept` path, and the
receiving wallet took the money. That is the strongest possible demonstration of the SPEC §10
claim — *the server change required for payments is none* — because production Signal **is** the
unmodified server, and nobody configured it to cooperate. The journal has the ledger row.

The Rust-level Signal-Protocol proof-of-concept (a `signal/` crate over `libsignal`, a hop end
to end through an in-process relay) and the signal-cli transport (`uv --transport signal`) were
both **deleted on 2026-07-31** with the client pivot. They had done their job — showing the
payload rides an opaque attachment and the protocol layer is untouched — and they were a library,
a test, and a CLI subcommand for a CLI that no longer exists. The evidence they produced survives
as the production ledger row; the code did not need to.

**Why no self-hosted server, recorded so nobody re-attempts it blind.** `Signal-Server` was
stood up on 2026-07-27. It *builds* (Java 25, the FoundationDB client its README requires) and has
exactly one documented way to run — a test profile, `mvn integration-test -Ptest-server`, which
warns that "many features are non-functional, especially those that depend on external services."
That path brings up a three-node Redis cluster through testcontainers and then fails on cluster
topology discovery through nested Docker. **That last failure is ordinary plumbing and is not why
it was abandoned.** It was abandoned because the profile that runs disables precisely the
external-service features the claim would be about, and a real deployment needs FoundationDB,
DynamoDB, several Redis clusters, and credentials for APNs, Firebase, Apple DeviceCheck, the App
Store, Braintree and Google Play Billing — plus, fatally for a self-hoster, a separate
`registrationService` for SMS verification **that has no open implementation**. Signal states it
cannot support running the software elsewhere, and the software is visibly not built to be. The
linked-device model sidesteps all of it: the device never registers, because a real phone already
did.

**What the fork still owes.** A payment *message type* inside the encrypted message (rather than a
file attachment); attachment transfer for large lineages; a chain view via an Esplora-style
endpoint; mempool-watching for the *visible* state; and in-band address exchange. The fork sends
through the FFI door's `send`/`scan` arms (`iosffi/src/call.rs`), which exist and are tested
(`paying_through_the_door`) — so "wire the client to the money path" is done at the seam; what
remains is the fork's own UI and the message-type work above. `[WATCH-SIGNAL]` tracks the one
external unknown: whether Signal ever ships the message type themselves, which would remove the
need for a fork at all.

### Durable storage is an unbuilt role `[STORAGE]`

Signal delivers then deletes, so two duties have no home: **cooperative-batch contents**
(§7) and **portable receipts**. Needs a content-addressed blob-host interface, a replication
policy, and a retention duty per role. The base payment rail is deliberately built not to
need it, which is why this is unbuilt rather than late.

**Repaired 2026-07-30.** This entry said *three* duties and listed **channel state
retrievability** first — a duty belonging to a subsystem deleted on 2026-07-28. The text had
also lost a conjunction and a sentence boundary, so it read as one broken sentence. Recorded
because the entry describing an unbuilt role was itself the least-read thing in the file, and
that is exactly where rot survives longest.

### Proving performance `[PROVE-PERF]`

GPU and delegated proving are no longer needed for phones — the signature-era circuit already
proved a hop in ~0.3 s on an iPhone, and the proof-native circuit is an order of magnitude
cheaper on the laptop (~0.01–0.02 s hiding; the phone re-measures in the signed app). What
remains is optional: proof size is 81.5 KB standard / 117.2 KB hiding against a 50–300 KB
target, i.e. comfortably inside it. Open only as tightening.

### Anchor reuse across notes `[ANCHOR-REUSE]`

**A risk-appetite call, not an engineering one, and deliberately left open.**

Per-slot anchors keep the current property that **no witness secret outlives the spend it
authorizes**, at the cost of needing slots handed over on first contact and replenished. A
reusable anchor removes that interaction entirely and lets anyone pay a published address —
but it puts one long-lived secret in every spend's witness, which makes the proof's
zero-knowledge property load-bearing for something other than privacy.

Zcash Sapling and Orchard both do the latter; their proof systems have reviewed ZK theorems
and ours does not yet (`[AUDIT]`). **The circuit is deliberately agnostic**: anchor lifetime
is an address-layer choice, decidable later without touching consensus.

**Re-examined 2026-07-29, the day proof-native authorization landed.** ZK is now load-bearing
for funds *even with one-time anchors* — but the exposure is bounded to one in-flight note
during its mempool window (`[HIDING-UNVERIFIABLE]`'s re-examination has the mechanics). That
bound is exactly what anchor reuse would remove: a reusable anchor's leaked witness drains
everything the anchor still guards, retroactively and forever. So the migration *sharpens*
this call rather than reopening it — one-time anchors are no longer only an interaction-cost
tradeoff, they are the containment for a hazard the system now permanently carries. The
decision stays open, but the default hardened: reuse should not be adopted before the
professional review returns a statement on the hiding composition.

---

## Design (not blocking v1)

- **Four entries lost their heads, and their slugs `[LOST-ENTRIES]`** — a register-integrity
  failure, filed here so the loss is tracked even though its contents are not.

  Four bullets in this file — three in this section, one under *Watch items* — were left as
  orphaned continuation lines with no `**Name [SLUG]**` head. Their opening text, and therefore
  their slugs and their scope, are **gone**. Verbatim, this is everything that survives:

  > epoch/exit review, the one-time-key leakage strengthener, and the shelved federated tier.

  > never-re-sign discipline.

  > interop profile.

  > (§2); ours unchanged, plumbing would need rework.

  **They are not recoverable.** This repository keeps exactly one commit, amended forever, so
  there is no history to read; the phrases appear nowhere else in the tree, the website, the
  journal, or the archive repository, and no other document cites the missing slugs. Searched
  2026-07-30.

  So four tracked problems became untracked silently, and every count of open problems in this
  file was wrong for as long as it lasted. **They have not been reconstructed**, deliberately:
  inventing four plausible entries would put fabricated scope into the one document whose
  purpose is being trusted about what is unfinished, and a fabricated entry is worse than a
  missing one because it stops anyone from looking. If you recognise one of these fragments,
  re-file it as a real entry and delete it from this list.

  **Why nothing caught it, which is the reusable part.** `check-refs.sh` validated *cited slug →
  entry exists*. Nothing validated *entry → well-formed*. That is a one-directional check, the
  same shape that let a claims-matrix row cite a test that did not exist and let a conformance
  tie go unrecorded. A well-formedness check landed with this entry
  (`check-refs.sh`, "register integrity"), so a headless bullet is now a build failure.

- **Cooperative-batch availability `[BATCH-AVAIL]`** ([§7](../SPEC.md#7-records-and-settlement)) — retention duty
  for batch contents; inline mode is the floor meanwhile.

---

## Watch items (external clocks)

- **Bitcoin's own PQ migration `[WATCH-BTC-PQ]`** (BIP-360/361) — a systemic dependency on
  ordering availability ([§5](../SPEC.md#5-cryptographic-foundations)); nothing here changes when it lands.
- **Datacarrier-policy tightening `[WATCH-DATACARRIER]`** (e.g. BIP-110, July 2026 —
  reinstates the 83-byte OP_RETURN limit, caps other data outputs at 34 bytes). Our 64-byte
  records already comply; a sub-64-byte regime is met by batching to a 32-byte root. Watch for
  any *semantic* rather than size filter, which would be a different threat.
- **Signal's appetite `[WATCH-SIGNAL]`** — whether the payment message type is something
  Signal would ever ship, which is the difference between *nothing to deploy* and *operate
  your own server forever* ([§10](../SPEC.md#10-delivery)). A business question with a hard technical
  floor in our favour: carrying payments needs no server changes. Worth checking the state of
  Signal's own payments surface before any pitch, since replacing a feature that embarrassed
  them reads differently from adding one.
- **Dependency advisories `[DEPS]`** — `cargo audit` runs in CI; vulnerabilities fail the
  build, informational advisories are reported without failing. Zero vulnerabilities as of
  2026-07-27. The standing informational set is unmaintained transitive crates, plus one that
  matters: **`bincode` 1.3 is unmaintained and we depend on it directly, on the money path's
  serialization.** A permanently-unmaintained encoder is a v1 replacement candidate
  **Format stability — done 2026-07-31.** The wallet file is the *only* remaining copy of a
  note's lineage once accepted bundles are deleted (`SPEC.md` §10), so a silent codec change is
  fund loss, not an inconvenience. Two guards now stand where none did:

  - A `format: u32` field at the front of the wallet body, checked on load and refused on
    mismatch — the `SignLog::version_ok()` pattern, applied to the whole wallet
    (`app/src/wallet::WALLET_FORMAT`). The magic bumped `UVW1` → `UVW2` so pre-version files
    reject precisely rather than misparse.
  - A **golden fixture** (`app/tests/the_wallet_format_is_pinned.rs`): a committed serialization
    of a known single-note wallet that today's encoder must reproduce byte for byte and today's
    decoder must read back to the right amount, index, state, lineage and commitment. Verified to
    bite: reordering two `Held` fields fails both halves. `bincode` is untagged, so a same-version
    field reorder produces *wrong values, not an error* — the decoder half is what catches that,
    on the amount specifically.

  A single note on purpose: `Store` holds notes in a `HashMap` whose order is randomised per
  process, so a multi-note fixture would not have stable bytes. One note exercises every persisted
  type.

  (`postcard` is the likely target). **The canonical-encoding review this entry used to say was
  "owed regardless" was done on 2026-07-27** — the verdict, and the three structural reasons
  canonicality is not load-bearing today, are in `[NO-BYTE-IDENTITY]`. This line contradicted
  that entry for three days, in the same file, and nothing reconciled them; corrected 2026-07-30.
  What remains owed here is the *replacement*, not the review.

---

## Closed

Finished work, kept only as an index so older references resolve. The detail is in the
[journal](https://ultravienet.github.io/ultraviolet/journal.html).

| Was | What | Outcome |
|---|---|---|
| gate 2, item 2 | Multi-hop validity / supply inflation | Fixed. Receivers bind ancestry to the proof's history digest before any lookup, then require every post-genesis hop's nullifiers to have a winning record. `formal/multihop.qnt` proves supply conservation at **all** depths by inductive invariant. |
| item 4 | In-circuit SLH-DSA verification | Done, then superseded, then deleted. Nothing on the money path verifies a signature (`[PROOF-AUTH]`); the crate no longer exists. |
| item 9 | One-time note secrets | Done. Per-note diversified `owner_key_i` and `nullifier_key_i`, so no witness secret outlives the spend it authorizes. Residue, bounded and documented: the change note's randomness is a next-note secret the circuit must see. |
| item 10 | Encrypted seed at rest | Done (`app/src/vault.rs`). ChaCha20-Poly1305 under an Argon2id passphrase key; plaintext storage must be asked for explicitly. |
| item 11 | Cheaper spend authorization | Done, then done again. A one-time signature over Poseidon2 replaced the original scheme; a measurement then removed signatures from the money path entirely (`[PROOF-AUTH]`). Authorization is the anchor preimage. |
| item 13 | Delegated proving leaks the witness | **Dissolved by measurement.** A phone proves a payment in about 0.3 s using 279 MB, so nothing needs delegating and the witness never leaves the device. |
| item 15 | Replace the general-purpose prover with a hand-written AIR | Done, and then the AIR shrank again when the signature came out. One 16 × 361 table per hop, ~0.01–0.02 s / 117 KB zero-knowledge. The measured comparison is in the journal. The accumulator design that was buried inside this item is now `[ACC]`. |
| item 16 | A record index | Done (`btc/src/index.rs`). Remaining sharp edges tracked under `[SCAN-FLOOR]`. |
| item 17 | Signet end-to-end | Done. Real payments settled on public signet. |
| item 19 | The address layer | Done — spend anchor, one-time slot batches, hybrid ML-KEM-768 + X25519 envelope. The one open decision it carried is now `[ANCHOR-REUSE]`. |
| `[EXPORT-COL]` | The unconstrained `export` column | Closed. Column 0 of the Poseidon2 layout was prover-chosen and read by nothing — 1,024 free field elements per proof. Now pinned to the value an honest trace carries, with a rejection test. |
| `[SPONGE-MARGIN]` | Sponge capacity margin | Decided rather than fixed: ~2^124 generic collision cost, accepted deliberately and written into [§5](../SPEC.md#5-cryptographic-foundations) as a target instead of an accident. |
| — | Audit #13 (2026-07-25) | All findings closed, corrected, or documented. Tracker: [issue #13](https://github.com/ultravienet/ultraviolet/issues/13). |

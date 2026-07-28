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
The constraints are ours (`air/src/transfer_air.rs`, `air/src/wots_air.rs`, plus
`air/src/poseidon2_eval.rs` vendored from upstream), so a rule that quietly does nothing is
a mint. A differential test against the host reference is necessary and *not* sufficient by
construction: it only ever exercises honest witnesses.

**This gate stopped being theoretical on 2026-07-27.** Volunteer adversarial review found a
total forgery — see `[ASSUMPTIONS]` — and then found a bug in the fix for it. Neither was
found by us. Scope for a reviewer: [`AUDIT-BRIEF.md`](../AUDIT-BRIEF.md).

### Gate 2 — Multi-hop validity `[closed]`

Fixed. See [Closed](#closed).

### Gate 3 — Channel dispute rules `[CHANNELS-REVIEW]`

**Blocks:** channels ([07](07-CHANNELS.md)). Not v1's base rail.

The mechanism is specified and `formal/channels.qnt` supports the spec on all four of its
claims: settlement never deadlocks, the never-re-sign discipline is load-bearing rather than
decorative (dropping it alone produces theft by equivocation), and both admitted residues —
offline past `W`, storage eclipsed — reproduce as theft.

**What is still owed is human adversarial review**, now narrower: attack the model's
assumptions rather than the rules. The assumption the model explicitly cannot see is that
**in-window claim ordering is stable**, which is what the reorg margin buys. If ordering can
be reordered, first-claim-wins is not well defined and tie-breaking needs rethinking.

The optional speed layer ([11](11-SPEED-LAYER.md)) carries its own gate — reconciling notary
reservations with direct publication — which blocks only that layer, never v1.

---

## Soundness

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
- **Mutation testing found the enforcement gap's mirror image in the tests**, not the code: 11 of
  17 constraints in `wots_air.rs` survive deletion because no test isolates them. See
  `air/COVERAGE.md`. An unenforced assumption and an unfalsifiable test are the same defect seen
  from two sides.

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

Probably not fixable without upstream changes, since the parameters are not in the proof to be
checked. Options if it ever needs closing: a length check contributed upstream, or a
convention that blinding parameters are part of the statement and therefore in the public
values. Recorded because hiding is *the* payment format and this is the one thing about it a
receiver must take on trust.

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

**Still owed for v1:** fee guidance for record transactions (a well-fed record confirms before
it can be raced), and the adversarial race test.

`demo/regtest.sh` now covers the *safety* half against a real node: a duplicate record for an
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

**Seen to work, not merely written.** `demo/regtest.sh` runs a real `bitcoind`, publishes a
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

1. **Restoring the 1-confirmation tier.** `required_confirmations` still returns 3 for every
   tier below 100,000. The repair now works and is exercised against a real node, so this is a
   policy decision rather than a blocked one — but it is a decision, and it should be taken
   deliberately rather than fall out of this work.
2. **`[FRONTRUN]`'s adversarial race test.** The harness exists now and is the right place for
   it; the race itself is not yet scripted.
3. **CI.** `demo/regtest.sh` is manual — it needs a `bitcoind` the runner does not have.
3. **Un-quarantine.** A note can enter quarantine and never leave. The restore condition would
   have to be the full positive check — found, bundle matches, deep enough — never "the failing
   check stopped failing", because a note that un-quarantines itself is a note that can be spent
   again.

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

The ancestry rule ([03](03-RECORDS.md)) is correct but linear: O(n) chain lookups per receive,
and **every nullifier in a coin's history is revealed to whoever serves the chain view**. Both
follow from settlement being checked *outside* the proof.

The fix: define `A_h`, a canonical accumulator over every record in blocks ≤ h in the existing
first-occurrence order — a deterministic function of the Bitcoin chain, so no consensus, no
committee, no trust. A prover then shows in-circuit that each ancestor's first occurrence
within `A_h` is the claimed bundle: inclusion of the winner **plus non-inclusion of any
earlier record with that nullifier**. The receiver checks one thing — that `A_h` matches its
own view at height h.

This buys O(1) lookups, deletes the chain-view leak, restores honest **O(1) receive**, and
recovers the ancestry privacy that shipping per-hop proofs gave away, since nothing would
need transmitting at all.

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
  reservation file, every slot would have read as unused, and two notes would have landed under
  one WOTS+ key. That is key disclosure with no visible cause. Now SHA-256, pinned by a
  known-vector test.

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

### Signal transport `[SIGNAL]`

**The protocol half is done; the deployment half is not.** A real payment now rides a real
Signal Protocol session: `signal/` uses Signal's own `libsignal` (from `signalapp/libsignal`
at a release tag, not a same-named reimplementation on crates.io), establishes a genuine
PQXDH session from a published pre-key bundle, and carries a sealed Ultraviolet bundle
through it. `signal/tests/a_payment_rides_signal.rs` proves a hop end to end — hiding STARK,
settled record, ML-KEM envelope, Signal session — and the receiving wallet accepts the money.
The relay in that test is instrumented and confirms it saw only opaque incompressible bytes.

`iosffi/` and `ios/UVProbe` land the Rust core on iOS.

**`uv --transport signal` exists, and is tested against the contract rather than the
service.** A sealed bundle goes out as a signal-cli attachment over JSON-RPC and comes back
in through the same `accept` path; `cli/tests/signal_transport_speaks_the_contract.rs` drives
it against a stub daemon, because CI has no Signal account and never will. The stub checks
the parts most likely to be wrong and that a stub *can* check: the JSON-RPC envelope, that
the attachment path really reaches `send`, that a JSON-RPC `error` member is not mistaken
for success (it arrives with HTTP 200), and that the same attachment is never collected
twice. Both of the load-bearing checks were verified by deleting the code they defend.

**What is still owed is a run.** The stub cannot show that Signal accepts any of it.
`demo/signal.md` is the runbook — link signal-cli as a secondary device the way Signal
Desktop does, no new number, no SMS — and it ends in a ledger table. **Until a row exists
there, the spec/05 claim remains argued rather than demonstrated**, which is the whole point
of this item and is not closed by writing the code.

**A payment now crosses a network, over a carrier that is not Signal.**
`uv --transport relay` moves the sealed bundle through `uv-relay`, a ~200-line
append-only bag of opaque blobs, and `demo/relay.sh` runs two homes against it in CI —
two wallets sharing no filesystem, the carrier holding only incompressible ciphertext with
no addressee on it. `demo/two-machines.md` is the same thing between two hosts on signet.
That closes the *shared directory*, which was the largest fake in the demo. It does **not**
close this item: the carrier is ours, and the claim here is about Signal's.

**Still open: the relay is a stand-in, not a Signal server.** Attempted 2026-07-27, and how
far it got is worth recording so nobody repeats it blind.

`Signal-Server` **builds** — all modules, on Java 25 with the FoundationDB client library its
README requires. It also has exactly one documented way to *run*, hidden in a test class:
`mvn integration-test -DskipTests=true -Ptest-server`, which carries its own warning that
"many features are non-functional, especially those that depend on external services". That
path gets as far as bringing up a three-node Redis cluster through testcontainers and then
fails on cluster topology discovery through nested Docker.

That last failure is ordinary plumbing and could be pushed through. **It is not worth
pushing**, because the profile that runs disables precisely the external-service features the
claim is about. A real deployment needs FoundationDB, DynamoDB, several Redis clusters, and
credentials for APNs, Firebase, Apple DeviceCheck, the App Store, Braintree and Google Play
Billing — plus, fatally for a self-hoster, a separate `registrationService` for SMS
verification that has no open implementation. Signal states plainly that it cannot support
running the software elsewhere, and the software is visibly not built to be.

So **the spec/05 claim that "the server change required for payments is none" remains argued
rather than demonstrated.** The argument is still good — the payload is an opaque attachment
and the protocol layer is untouched, which `signal/tests/` does demonstrate — but the
deployment claim is not the same claim, and `[WATCH-SIGNAL]` is what would actually settle it.

Also unbuilt: a payment message type inside the encrypted message, attachment transfer for
large lineages, chain view via an Esplora-style endpoint, mempool-watching for the *visible*
state, and in-band address exchange. Today the CLI still moves payments through a shared
local directory; `signal/` is a library and a test, not yet wired into `uv send`.

### Durable storage is an unbuilt role `[STORAGE]`

Signal delivers then deletes, so three duties have no home: **channel state retrievability**
([07](07-CHANNELS.md), where unavailability is a *theft* vector rather than an inconvenience),
cooperative-batch contents ([03](03-RECORDS.md)), and portable receipts
([11](11-SPEED-LAYER.md)). Needs a content-addressed blob-host interface, a replication
policy, and a retention duty per role. The base payment rail is deliberately built not to
need it.

### Proving performance `[PROVE-PERF]`

GPU and delegated proving are no longer needed for phones — a hop proves in 0.28 s on an
iPhone 17 Pro Max — so what remains is optional: proof size is 158 KB standard / 208 KB
hiding against a 50–300 KB target, i.e. already inside it. Open only as tightening.

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

---

## Design (not blocking v1)

- **Speed layer `[SPEED]`** ([11](11-SPEED-LAYER.md)) — build only if the stranger-retail
  market demands it: notary/batcher programs, bond sizing, a receipt publication path, its
  epoch/exit review, the one-time-key leakage strengthener, and the shelved federated tier.
- **Channel residue reduction `[CHANNEL-RESIDUE]`** ([07](07-CHANNELS.md)) — shrinking the
  liveness window and the retrievability assumption. The freeze corner is chosen for v1;
  whether the residues shrink further without a bonded party is open.
- **Seq-chain scaling `[SEQ-CHAIN]`** ([07](07-CHANNELS.md)) — the length-`N` hash chain is
  O(N) to set up and must be fixed in advance, awkward for machine-speed streaming. Pebbling
  helps traversal; the open cost and fixed-N ceiling remain.
- **Per-channel WOTS+ chains `[CHANNEL-WOTS]`** for machine-speed updates; needs the wallet's
  never-re-sign discipline.
- **zk-locks `[ZK-LOCKS]`** ([07](07-CHANNELS.md)) — circuit and per-hop proving cost;
  recipient-extended final link for proof-of-payment.
- **Lattice adaptor swap tier `[ADAPTOR]`** ([01](01-CRYPTO.md)) — parameters and an LN-PTLC
  interop profile.
- **Cooperative-batch availability `[BATCH-AVAIL]`** ([03](03-RECORDS.md)) — retention duty
  for batch contents; inline mode is the floor meanwhile.

---

## Watch items (external clocks)

- **Lightning PTLC migration `[WATCH-PTLC]`** — would break gateway preimage coupling
  ([06](06-PAYMENTS.md)); ours unchanged, plumbing would need rework.
- **Bitcoin's own PQ migration `[WATCH-BTC-PQ]`** (BIP-360/361) — a systemic dependency on
  ordering availability ([01](01-CRYPTO.md)); nothing here changes when it lands.
- **Datacarrier-policy tightening `[WATCH-DATACARRIER]`** (e.g. BIP-110, July 2026 —
  reinstates the 83-byte OP_RETURN limit, caps other data outputs at 34 bytes). Our 64-byte
  records already comply; a sub-64-byte regime is met by batching to a 32-byte root. Watch for
  any *semantic* rather than size filter, which would be a different threat.
- **Signal's appetite `[WATCH-SIGNAL]`** — whether the payment message type is something
  Signal would ever ship, which is the difference between *nothing to deploy* and *operate
  your own server forever* ([05](05-NETWORK.md)). A business question with a hard technical
  floor in our favour: carrying payments needs no server changes. Worth checking the state of
  Signal's own payments surface before any pitch, since replacing a feature that embarrassed
  them reads differently from adding one.
- **Dependency advisories `[DEPS]`** — `cargo audit` runs in CI; vulnerabilities fail the
  build, informational advisories are reported without failing. Zero vulnerabilities as of
  2026-07-27. The standing informational set is unmaintained transitive crates, plus one that
  matters: **`bincode` 1.3 is unmaintained and we depend on it directly, on the money path's
  serialization.** A permanently-unmaintained encoder is a v1 replacement candidate
  (`postcard` is the likely target), and a canonical-encoding review is owed regardless, since
  consensus reads bytes.

---

## Closed

Finished work, kept only as an index so older references resolve. The detail is in the
[journal](https://ultravienet.github.io/ultraviolet/journal.html).

| Was | What | Outcome |
|---|---|---|
| gate 2, item 2 | Multi-hop validity / supply inflation | Fixed. Receivers bind ancestry to the proof's history digest before any lookup, then require every post-genesis hop's nullifiers to have a winning record. `formal/multihop.qnt` proves supply conservation at **all** depths by inductive invariant. |
| item 4 | In-circuit SLH-DSA verification | Done, then superseded and deleted — WOTS+ replaced it on the money path. The crate no longer exists. |
| item 9 | One-time note secrets | Done. Per-note diversified `owner_key_i` and `nullifier_key_i`, so no witness secret outlives the spend it authorizes. Residue, bounded and documented: the change note's randomness is a next-note secret the circuit must see. |
| item 10 | Encrypted seed at rest | Done (`cli/src/vault.rs`). ChaCha20-Poly1305 under an Argon2id passphrase key; plaintext storage must be asked for explicitly. |
| item 11 | Cheaper spend authorization | Done. WOTS+ one-time signatures over Poseidon2. |
| item 13 | Delegated proving leaks the witness | **Dissolved by measurement.** A phone proves a payment in about 0.3 s using 279 MB, so nothing needs delegating and the witness never leaves the device. |
| item 15 | Replace the zkVM with a hand-written AIR | Done. One 1,024 × 457 table per hop at ~0.075 s / 158 KB, or ~0.22 s / 208 KB zero-knowledge, against the zkVM's 124 s / 1,242 KB / 9.67 GB. The accumulator design that was buried inside this item is now `[ACC]`. |
| item 16 | A record index | Done (`btc/src/index.rs`). Remaining sharp edges tracked under `[SCAN-FLOOR]`. |
| item 17 | Signet end-to-end | Done. Real payments settled on public signet. |
| item 19 | The address layer | Done — spend anchor, one-time slot batches, hybrid ML-KEM-768 + X25519 envelope. The one open decision it carried is now `[ANCHOR-REUSE]`. |
| `[EXPORT-COL]` | The unconstrained `export` column | Closed. Column 0 of the Poseidon2 layout was prover-chosen and read by nothing — 1,024 free field elements per proof. Now pinned to the value an honest trace carries, with a rejection test. |
| `[SPONGE-MARGIN]` | Sponge capacity margin | Decided rather than fixed: ~2^124 generic collision cost, accepted deliberately and written into [01](01-CRYPTO.md) as a target instead of an accident. |
| — | Audit #13 (2026-07-25) | All findings closed, corrected, or documented. Tracker: [issue #13](https://github.com/ultravienet/ultraviolet/issues/13). |

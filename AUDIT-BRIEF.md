# Audit brief: what to attack, and why our own tests cannot find it

**Status of this document.** A scope for an external reviewer. It is written to be
adversarial about our own work, because the thing we most need from a review is the class
of defect our tests are structurally incapable of finding.

**The one-sentence ask.** We hand-wrote the constraint system that decides whether a
payment is valid, and spend authorization is nothing but that system. Please try to
satisfy it with a witness that should be impossible.

---

## 1. Why this review matters more than it would have a month ago

Two things moved the stakes, in the same month.

First, the proof system stopped being someone else's. Until recently it was a
general-purpose zero-knowledge virtual machine (SP1); its soundness was one artifact,
reviewed by many people, and our job was only to use it correctly. We deleted it —
measured at 124 s and 9.67 GB per payment against ~0.01–0.02 s and 5 MB for today's
hand-written circuit (`docs/benchmarks.html` has the full case). That trade moved the
soundness burden onto us. **A hand-written AIR is sound only if every column is
constrained.** A column nobody constrained is a free variable for a prover, and a free
variable in the wrong place mints money.

Second, the signature left the money path (2026-07-29, SPEC.md §8.4). Spend
authorization is now **in-circuit knowledge of a hash preimage**: a note commits to
`t = H(nk)`, and the spend proof exhibits `nk`, bound to the exact transfer by
Fiat–Shamir over every public value. There is no signature beside it. Two consequences
a reviewer should hold at once:

- The constraint system is not merely *validating* payments; it **is** the
  authorization. There is no second lock behind it.
- The witness — the nullifier key — enters every spend proof, so **zero-knowledge is
  load-bearing for funds**, not privacy. A proof that leaks its witness leaks the thing
  that moves the money. The blast radius of one leak is one note (anchors are one-time),
  but "the hiding configuration works" is now a fund-safety claim.

**Our test suite cannot find the under-constraint class of bug, by construction.** Every
test generates a witness with our own honest witness generator and checks the prover
accepts it, or tampers with one cell and checks it rejects. Both directions only ever
explore witnesses we thought of. An under-constrained column is invisible to
honest-witness testing — it is precisely the thing that *is* accepted, and should not
be. We have written the negative tests we could imagine (see §5); the value of a
reviewer is the ones we could not.

---

## 2. What is in scope, in priority order

### Priority 1 — the transfer circuit (`air/src/authproto_air.rs`)

One table, **16 rows × 361 columns**, proving a complete payment: the input coin's
commitment opens, its nullifier derives correctly, two output commitments open, value is
conserved over range-checked 16-bit limbs, and the spender knows the preimage of the
input note's committed spend anchor. Constraints are numbered 1–16 in the source with a
comment each explaining what it stops (and, for the sponge constraints, the number it
carried in the deleted signature circuit, whose sponge section it inherits verbatim).

**The height lesson, retold for 16 rows.** The sharpest bug this project has had was
found by an outside reviewer against the previous circuit: `p3_uni_stark` takes the
trace height from the *proof* and never pins it — its contract is that an AIR must be
sound at every height. An eight-row trace of zeros kept every money constraint gated off
and verified perfectly. The fix is host-side (`prove::check_height`): a proof must
declare exactly the height the AIR is sound at, derived from the configuration because a
hiding proof legitimately declares one bit more. The circuit changed; the hazard did
not. This circuit is sound at 16 rows and nothing else, and the check is pinned by
`air/tests/trace_height_is_pinned.rs` in both directions — the first version of the fix
rejected every honest private payment, which is why "both directions" is written down.
**The bug was not in a constraint; it was in an assumption a constraint rested on. Look
for more of those.**

The register families, and the story each tells about why the prover has no freedom in
it. Please disbelieve those stories:

- **The sponge-row register `SP`** (15 one-hot columns): claimed fully determined by
  induction — row 0 is exactly `(1, 0, …, 0)` and every transition shifts by one with a
  zero fed in (constraint 3). Everything else is gated on it: which rows are sponge
  rows, which are starts, which chunk a row absorbs, which row is the anchor row. If a
  prover can put anything else in `SP` on any row, it can relabel a sponge row as a
  different sponge.
- **The buses**: `NK` (8 columns, the nullifier key) and `T` (8 columns, the anchor),
  plus twelve amount-limb columns, all claimed constant across the sponge section
  (constraint 13). The entire authorization argument is a tie *through these buses*: the
  input commitment absorbs `T` (constraint 10), the anchor sponge hashes `NK` and must
  land on `T` (constraint 12), and the nullifier sponge absorbs `NK` (constraint 8). A
  bus that can change mid-section snaps the tie between "the anchor the note committed
  to" and "the key the spender exhibited."
- **The absorb tie table** (constraint 10): each continuing row's rate is the previous
  permutation's output plus the chunk it absorbs, and the table says which trace cells
  each chunk comes from. Some lanes are **deliberately free** — the input note's
  randomness, and the output notes' anchors and randomness (the payer's choice, pinned
  only through the public output commitment). The zero ties on each note sponge's final
  chunk are load-bearing: without them the tail of the 28-element preimage is
  prover-chosen padding. Check that the free lanes are exactly the ones the design
  claims and no more.
- **The pins** (constraints 5, 11): each sponge's start has a zeroed capacity, its
  first chunk is pinned (the public asset for note sponges, `NK` for nullifier and
  anchor — constraint 8), its length and domain tag are pinned (constraints 6, 7), and
  its final output equals the public digest it claims (constraint 11 for the four
  digests, constraint 12 for the anchor landing on `T`).
- **Conservation** (constraints 14–16): exact over u64, limb-wise with boolean carries
  and sixteen shared range-check bits. The `2^16`-limb alias — a limb of exactly
  `2^16` acting as a free carry — is the specific defense; the range bits route each
  limb through a shared 16-bit decomposition.
- **The padding row** (constraint 4): row 15 is inert and feeds the permutation
  nothing. It still has to satisfy every constraint. Padding is where a reviewer should
  look first, because it is the part nobody designs and everybody assumes — and here it
  is one row carrying sixteen would-be-free lanes.

### Priority 2 — the vendored permutation (`air/src/poseidon2_eval.rs`)

Copied from upstream `p3-poseidon2-air` because upstream's `eval` is `pub(crate)` and
its `Borrow` implementation asserts an exact-width row, so the published AIR cannot be
composed with our own columns. **We now own this code.** Two questions: does it still
match upstream (`air/tests/poseidon2_differential.rs` checks the permutation against the
host implementation), and does composing it beside our columns break any assumption it
made about owning the whole row? The round constants are the published BabyBear ones;
note that the real permutation has **13** partial rounds, not the 20 in upstream's
benchmark examples, and we got that wrong once.

### Priority 3 — the verifier wrapper (`air/src/prove.rs`, `kernel2/src/transfer_prove.rs`)

**The STARK alone proves nothing about any payment.** Host-side consensus rules complete
it:

1. the public values must be built by the verifier from the transfer it is validating —
   never accepted from the prover. `kernel2::transfer_prove::verify_hiding` derives all
   56 from the `Transfer` in hand, including the bundle hash;
2. the proof's declared trace height must equal the height the AIR is sound at,
   derived from the configuration (one bit more under hiding — see Priority 1);
3. the wallet accepts **hiding proofs only**: `wallet2::accept` and every consensus
   entry point call `verify_hiding`. A standard-configuration proof of a real spend
   would expose witness-bearing cells at FRI query positions, so "which configuration
   verified this" is itself fund-critical.

Questions: can a caller reach the raw verifier with public values of its choosing? Is
there any path where a proof verifies against a statement other than the transfer in
hand? If someone builds a recursive verifier later, is the obligation on them stated
clearly enough that they cannot miss it?

---

## 3. The specific attacks we most want tried

Each of these should be impossible. We believe it is. That belief is the thing under
test.

1. **Mint.** Produce a verifying transfer whose outputs total more than its input. The
   amount limbs are 16-bit and range-checked by shared bit columns, and conservation is
   limb-wise with boolean carries — a `2^16` limb acting as a free carry is the alias we
   specifically defend against.
2. **Spend a stranger's coin.** Produce a verifying spend of a commitment whose anchor
   preimage you do not know. The chain is short now: the commitment absorbs `T`
   (constraint 10), and constraint 12 forces the anchor sponge to hash `NK` onto that
   same `T`. Break either tie, or find a second preimage family the sponge padding
   admits.
3. **Spend a coin you paid to someone else.** Sharper than #2: the payer knows
   *everything* about the coin it created — amount, randomness, anchor, the whole
   preimage — except the payee's nullifier key. The barrier is exactly one hash
   preimage. This is the attack the whole design now stands on.
4. **Forge a nullifier.** Derive a different valid nullifier for a coin, defeating
   first-occurrence double-spend prevention. The nullifier sponge absorbs `NK` then the
   input commitment (constraints 8, 10), so the marker is claimed to be a function of
   the coin alone.
5. **Transplant a proof.** Make a proof for transfer A verify against transfer B — a
   different payee, amount, or position in history. The claimed defense is Fiat–Shamir
   over all 56 public values; the bundle hash is bound that way and read by no
   constraint.
6. **Mix assets.** Produce a transfer whose output is a different asset from its input.
   All three note sponges absorb the same public asset id as their first chunk
   (constraint 8).
7. **Extract the witness.** Zero-knowledge is fund-critical now (§1). The hiding
   configuration uses Plonky3's `HidingFriPcs` + `MerkleTreeHidingMmcs`; our composition
   of it is not independently reviewed. `air/tests/hiding_is_randomized.rs` catches the
   failure we already shipped once — blinding seeded from a compile-time constant, so
   two proofs of one witness were byte-identical and the mask was recomputable. Find
   the leak that test cannot see: bias in the blinding, witness-dependent proof
   structure, anything that distinguishes two witnesses across proofs.
8. **Find another load-bearing assumption nobody enforces.** The height bug was one; we
   do not assume it was the only one. What else does the constraint system quietly rely
   on that no line of code checks — trace width, public-value count, the shape of the
   padding row, the FRI parameters a proof was produced under?
9. **Break the ancestry rules off-circuit.** The receive path (`wallet2/src/accept.rs`)
   checks per-hop proofs, linkage, the history digest, and that every hop's record won
   its first-occurrence race. A formal model already found that per-hop checks do not
   compose (`formal/multihop.qnt`); we fixed it. Is the fix complete?
10. **Inflate the supply without publishing.** A coin whose genesis is not in a
    confirmed 76-byte issuance record — carrying the asset id, genesis commitment and
    amount in the clear, all three compared byte-for-byte — is refused
    ([spec/12](SPEC.md#9-issuance-and-supply)). **This rule has already been wrong
    twice**: the first version compared only the amount, so an attacker minted against
    an honest issuer's record; the first record format hashed its details, so supply
    could only ever be a chain-wide bound. Both are fixed and both are reproducing
    counterexamples in `formal/issuance.qnt`.

    The episode is the point, and it is the thing to attack: the design was right and
    `formal/issuance.qnt` was right, and the *translation* was wrong. No amount of
    model-checking catches that. **Attack the translation**, not the model.

    One residual is named and deliberate: nothing authenticates a record's asset id, so
    a decoy can bear someone else's asset. It creates no spendable coin, and `uv supply`
    keeps attested and unattested apart. Is there a second we did not name?

---

## 4. What is deliberately *not* in scope

- **The cryptography of the primitives.** Poseidon2 and FRI soundness are assumed. If
  you think our *parameters* are wrong — FRI at blowup 16 with 25 queries for ~100-bit
  soundness — say so, but we are not asking for a hash review. (Note the boundary
  moved: the zero-knowledge *property of our composition* used to sit in this section
  as optional. It is attack #7 now, because it stopped being optional.)
- **The Signal transport's delivery guarantees.** The carrier is untrusted by
  construction — `formal/delivery.qnt` checks that a hostile carrier costs time and
  privacy, never funds — so transport bugs are liveness bugs, and the planned
  Signal-fork client is explicitly post-campaign scope.
- **Bitcoin.** Reorg handling and confirmation policy are modelled (`formal/reorg.qnt`)
  and demoed against a real node (`demo/regtest.sh`), but Bitcoin's own consensus is
  assumed.

---

## 5. What we have already done, so you can skip it

- **Negative tests per constraint family**, each tampering one thing and confirming
  rejection: a key that does not open the anchor, a forged anchor, bus tampering, the
  `2^16` limb alias, non-boolean carries, broken capacity carry, a relabelled `SP`
  register, wrong domain tags and lengths, and a wrong-asset output. See the tests in
  `air/src/prove.rs` and `air/tests/authproto_constraints_are_isolated.rs`.

  **Read `air/COVERAGE.md` before trusting that list.** We mutation-tested it — delete
  each constraint region, see whether any test fails. **Latest sweep: 16 mutants, 7
  killed, 9 survive** (constraints 1, 4, 5–10, 13: the permutation, the padding gate,
  and the sponge-lane cluster). They are not redundant; nothing *isolates* them — a
  tamper that violates one is caught by a neighbouring constraint or by the Fiat–Shamir
  transcript before the deleted constraint is ever consulted. Their soundness argument
  today is **inheritance**: they are byte-identical to constraints of the deleted
  signature circuit that a structural per-column sweep did isolate and kill. That
  argument is honest and it is weaker than an isolating test per constraint — porting
  the structural probes is open work, named in `air/COVERAGE.md`. **This is the
  sharpest thing we can tell you about where our evidence is thin.**
- **The height forgery, kept as a running regression test**
  (`air/tests/trace_height_is_pinned.rs`): forged `degree_bits` in both directions, on
  both configurations, checked to fail as `WrongTraceHeight` specifically.
- **Zero-knowledge regressions** (`air/tests/hiding_is_randomized.rs`): two proofs of
  one witness must differ and must both verify — the alarm for fixed, predictable, or
  disabled blinding.
- **Differential testing**: the circuit's sponge section against the host reference
  (`transfer_trace::sponge_states` is the *same function* the wallet's hashes are
  defined on, so circuit and hash cannot drift silently), and the vendored permutation
  against the host Poseidon2 (`air/tests/poseidon2_differential.rs`).
- **Seven formal models** (`formal/`, Quint + Apalache), 32 checks in CI on every push:
  supply conservation, both strict-rule supply claims, the authorization rule, and both
  reorg reconciliation claims all proven inductively at all depths, issuance with both historical
  free-mint counterexamples reproducing, reorgs, off-circuit linkage,
  **proof-native authorization itself** (`authorization.qnt`: the anchor-preimage rule
  holds; the public-anchor strawman is theft in six steps), the untrusted carrier, and
  base-rail liveness. `formal/README.md` records what each assumes and the modelling
  traps that produced confident-looking wrong answers.
- **Conformance replay**: frozen model traces replayed against the real code
  (`kernel2/tests/conformance_authorization.rs`, `wallet2/tests/conformance_issuance.rs`)
  — the model's counterexamples must make the production code refuse.
- **An end-to-end demo in CI** that self-checks its own claims, plus real payments
  settled on Bitcoin signet and a payment bundle carried across Signal's production
  service.

---

## 6. Practicalities

- **Repository:** https://github.com/ultravienet/ultraviolet — one commit, always
  amended.
- **Build and test:** `cargo test --workspace` (207 tests, real proofs included);
  `./demo/local2.sh` for the end-to-end flow; `cargo run --release -p uv-air --bin
  measure` to reproduce every performance number.
- **Reading order:** `SPEC.md` §8 for the proof design and its measurements, then
  `air/src/authproto_air.rs` top to bottom (the constraint list is commented in order,
  ~620 lines), then `air/COVERAGE.md` for what the mutation sweep defends, then
  `formal/README.md` for what is already proven and what the models deliberately do not
  cover.
- **Scale:** one circuit, ~620 lines of constraint code plus ~240 vendored. The wrapper
  and money path are another ~1,500. It is small enough to read completely, which is
  the main argument for having written it by hand.
- **What a finding is worth to us:** a mint or a theft is the whole point of the
  exercise. An under-constrained column with no known exploit is nearly as valuable,
  because we cannot find those ourselves. So is "your test suite would not catch X."

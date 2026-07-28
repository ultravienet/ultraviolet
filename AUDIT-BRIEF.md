# Audit brief: what to attack, and why our own tests cannot find it

**Status of this document.** A scope for an external reviewer. It is written to be
adversarial about our own work, because the thing we most need from a review is the class
of defect our tests are structurally incapable of finding.

**The one-sentence ask.** We hand-wrote the constraint system that decides whether a
payment is valid. Please try to satisfy it with a witness that should be impossible.

---

## 1. Why this review matters more than it would have a month ago

Until recently the proof system was a general-purpose zero-knowledge virtual machine
(SP1). Its soundness was one artifact, reviewed by many people, and our job was only to
use it correctly. We deleted it — measured at 124 s and 9.67 GB per payment against
~0.07 s and 67 MB for the replacement — 0.19 s and 117 MB in the hiding
configuration payments actually use (`docs/benchmarks.html` has the full case).

That trade moved the soundness burden onto us. **A hand-written AIR is sound only if
every column is constrained.** A column nobody constrained is a free variable for a
prover, and a free variable in the wrong place mints money.

**Our test suite cannot find that class of bug, by construction.** Every test generates a
witness with our own honest witness generator and checks the prover accepts it, or
tampers with one cell and checks it rejects. Both directions only ever explore witnesses
we thought of. An under-constrained column is invisible to honest-witness testing — it is
precisely the thing that *is* accepted, and should not be. We have written the negative
tests we could imagine (see §5); the value of a reviewer is the ones we could not.

---

## 2. What is in scope, in priority order

### Priority 1 — the transfer circuit (`air/src/transfer_air.rs`)

One table, 1,024 rows × 457 columns, proving a complete payment: the input coin's
commitment opens, its spend marker derives correctly, two output commitments open, value
is conserved, and the owner's one-time signature verifies. Constraints are numbered 1–32
in the source with a comment each explaining what it stops.

**An earlier draft of this document stated that height as a fact about the system. It was
an assumption, and nothing enforced it.** `p3_uni_stark` takes the trace height from the
proof and never pins it — its contract is that an AIR must be sound at *every* height, and
this one is not. Below 1,024 rows the position counter never reaches the end of a chain, so
`is_last` never fires, the sponge section never begins, and constraints 20–32 are all gated
off. An eight-row trace of zeros proved an arbitrary transfer. The verifier now pins the
height (`prove::check_height`) and two regression tests hold it there. We are telling you
because it is the sharpest illustration we have of what this review is for: **the bug was
not in a constraint, it was in an assumption a constraint rested on.** Look for more of
those.

The specific questions we want answered:

- **Is every column constrained on every row where it matters?** The layout has several
  register families: a 67-wide one-hot chain index (`OH`), an 18-wide sponge-section
  register (`SP`), "bus" columns held constant across the section (`NK`, `T`, and twelve
  amount limbs), conservation carries, and sixteen shared range-check bits. Each family
  has a story about why the prover has no freedom in it. Please disbelieve those stories.
- **The one-hot registers are claimed to be fully determined by induction** from a pinned
  first row plus a deterministic rotation. If a prover can put something else in `OH` or
  `SP` on any row, it can pair one chain's walk with another chain's public digit, or
  relabel a sponge row as a different sponge. Constraints 15, 18, 19.
- **The bus columns are claimed constant across the sponge section.** Constraint 27 gates
  that with a sum of `SP` cells. Check the gate's boundaries: does it cover the transition
  into the section, out of it, and every row between? A bus that can change mid-section
  breaks the tie between "the key the commitment binds" and "the key the spend marker
  derives from."
- **The padding rows.** Rows 1,023 and beyond are inert. They still have to satisfy every
  constraint. We believe they do; we also believe padding is where a reviewer should look
  first, because it is the part nobody designs and everybody assumes.
- **Constraint 3 is gated** so sponge rows may feed the permutation something other than
  the chain value. That gate is the one place the shared chain section behaves differently
  between the two circuits. Is the gate exactly right?

### Priority 2 — the signature circuit (`air/src/wots_air.rs`)

Constraints 1–17, shared verbatim with the transfer circuit. Verifies a WOTS+ one-time
signature: 67 hash chains, each walked a number of steps determined by a digit of the
message.

- **The digits are public values, not witness columns.** The verifier computes them from
  the message; the prover cannot choose one. Confirm there is no path by which a
  prover-supplied value reaches the digit comparison.
- **Chain boundaries.** `is_last` marks the end of each chain. We found and fixed a bug
  here: it was boolean but positionally free, so a prover could shift boundaries and remap
  chains onto the wrong digits and tips. It is now pinned by a step counter plus an inverse
  witness (constraints 13, 14). That fix is young. Please attack it.
- **Selectors are non-increasing within a chain** (constraint 10), so a prover cannot
  scatter the same number of steps to reach a different endpoint.

### Priority 3 — the vendored permutation (`air/src/poseidon2_eval.rs`)

Copied from upstream `p3-poseidon2-air` because upstream's `eval` is `pub(crate)` and its
`Borrow` implementation asserts an exact-width row, so the published AIR cannot be
composed with our own columns. **We now own this code.** Two questions: does it still
match upstream, and does composing it beside our columns break any assumption it made
about owning the whole row? The round constants are the published BabyBear ones; note that
the real permutation has **13** partial rounds, not the 20 in upstream's benchmark
examples, and we got that wrong once.

### Priority 4 — the verifier wrapper (`air/src/prove.rs`, `kernel2/src/transfer_prove.rs`)

**The STARK alone proves nothing about any payment.** Three host-side steps complete it,
and all three are consensus rules:

1. the public values must be built by the verifier from the transfer it is validating —
   above all the message digits, derived from that transfer's bundle hash;
2. the owner key is *defined* as `compress(proof.tips)` rather than compared to it;
3. the proof's declared trace height must equal the height the AIR is sound at. This one is
   the newest and the easiest to lose, because unlike the other two nothing in the AIR hints
   that it exists. Note the expected value is not a constant: a zero-knowledge proof runs
   over an extended domain and legitimately declares one bit more, so the check derives it
   from the configuration. Getting that wrong in the other direction rejects every honest
   payment — which we also did, briefly.

`kernel2::transfer_prove::verify` is the only intended entry point. Questions: can a caller
reach the raw verifier with public values of its choosing? Is there any path where a proof
verifies against a statement other than the transfer in hand? If someone builds a recursive
verifier later, is the obligation on them stated clearly enough that they cannot miss it?

---

## 3. The specific attacks we most want tried

Each of these should be impossible. We believe it is. That belief is the thing under test.

1. **Mint.** Produce a verifying transfer whose outputs total more than its input. Note
   the amount limbs are 16-bit and range-checked by shared bit columns, and conservation
   is limb-wise with boolean carries — a `2^16` limb acting as a free carry is the alias
   we specifically defend against, and the defence is young.
2. **Spend someone else's coin.** Produce a verifying spend of a commitment whose owner
   key you do not hold the secret for. The chain of custody is: the proof's chain tips →
   (host) `compress` → the owner key → (constraint 25) the input commitment's preimage.
   Break any link.
3. **Spend a coin you paid to someone else.** A payer knows everything public about the
   coin it created. It must not be able to spend it. The barrier is the spend anchor: the
   commitment binds `t = H(nullifier_key)` and constraint 32 makes the spender exhibit a
   preimage of `t`. This is the newest constraint in the system.
4. **Forge a spend marker.** Derive a different valid nullifier for a coin, which would
   defeat first-occurrence double-spend prevention entirely. The marker must be a function
   of the coin alone.
5. **Transplant a proof.** Make a proof for transfer A verify against transfer B — a
   different payee, a different amount, or a different position in a coin's history.
6. **Mix assets.** Produce a transfer whose output is a different asset from its input.
   All three commitments absorb the same public asset id (constraint 23).
7. **Find another load-bearing assumption nobody enforces.** The height bug was one; we do
   not assume it was the only one. What else does the constraint system quietly rely on that
   no line of code checks — trace width, public-value count, the number of tips, the shape
   of a padding row, the FRI parameters a proof was produced under?
8. **Break the ancestry rules off-circuit.** The receive path (`wallet2/src/accept.rs`)
   checks per-hop proofs, linkage, the history digest, and that every hop's record won its
   first-occurrence race. A formal model already found that per-hop checks do not compose
   (`formal/multihop.qnt`); we fixed it. Is the fix complete?

---

## 4. What is deliberately *not* in scope

- **The cryptography of the primitives.** Poseidon2, FRI soundness, and ChaCha20-Poly1305
  are assumed sound. If you think our *parameters* are wrong — FRI at blowup 16 with 25
  queries for ~100-bit soundness — say so, but we are not asking for a hash review.
- **Channels, the speed layer, and the Signal client.** Designed, not built. The channel
  dispute rules are formally modelled (`formal/channels.qnt`) and want their own adversarial
  review later; they are not code yet.
- **The zero-knowledge property, unless you want to.** We use Plonky3's `HidingFriPcs` and
  `MerkleTreeHidingMmcs` and claim the hiding configuration is genuinely zero-knowledge.
  This is upstream code, but our composition of it is not reviewed, and one open design
  question is gated on whether that property can ever be load-bearing for fund safety
  rather than only privacy (spec/99 [ANCHOR-REUSE]). A statement on it would be valuable.

---

## 5. What we have already done, so you can skip it

- **Negative tests per constraint family.** Each new column family has a test that tampers
  with it and confirms rejection: scattered selectors, digit/walk mismatch, non-boolean
  bits, shifted chain boundary, relabelled one-hot register, broken sponge capacity carry,
  bus tampering, the `2^16` limb alias, a key that does not open the anchor, and a forged
  anchor. See the `transfer` module in `air/src/prove.rs`.

  **Read `air/COVERAGE.md` before trusting that list.** We mutation-tested it — delete each
  constraint, see whether any test fails — and **eleven of the seventeen constraints in
  `wots_air.rs` survived deletion**. They are not redundant; nothing *isolates* them. Two
  causes, both worth your attention: a tamper that leaves dependent columns stale is caught
  by whichever neighbouring constraint objects first (deleting constraints 4 *and* 10
  together still passes), and a tamper to a public value fails on the Fiat-Shamir transcript
  without consulting a constraint at all — which is why our sharpest test, the complicit-key
  tip tamper, passes with constraint 17 deleted. Constraint 17 now has an isolating test;
  the other ten do not yet. **Where the table says SURVIVED, our evidence is weaker than
  this document previously implied, and that is where we would look.**
- **The height forgery, kept as a running regression test** (`air/tests/trace_height_is_pinned.rs`,
  `wallet2/tests/forged_lineage_is_rejected.rs`). The second one runs the complete rail: a
  note forged from nothing, a record published and confirmed, and `wallet2::accept` asked to
  take it.
- **The sharpest one we could think of:** tamper a chain tip *and* verify against the key
  that compresses from the tampered tips, so the host-side key check passes and only the
  in-circuit constraint stands between the forger and acceptance. It rejects.
- **Differential testing** of every circuit against the host reference implementation, and
  of witness generation against the same `absorb_states` function the host hash is defined
  on — so circuit and hash cannot drift apart silently.
- **Six formal models** (`formal/`, Quint + Apalache) covering supply conservation (proven
  at *all* depths by an inductive invariant, not merely to a search bound), reorgs,
  off-circuit linkage, one-time key discipline, the channel dispute machine, and base-rail
  liveness. `formal/README.md` records what each assumes, what the adversary controls, and
  eight modelling and tooling traps that produced confident-looking wrong answers.
- **An end-to-end demo in CI** that self-checks its own claims, plus real payments settled
  on Bitcoin signet.

---

## 6. Practicalities

- **Repository:** https://github.com/ultravienet/ultraviolet — one commit, always amended.
- **Build and test:** `cargo test --workspace` (161 tests, real proofs included);
  `./demo/local2.sh` for the end-to-end flow; `cargo run --release -p uv-air --bin measure`
  to reproduce every performance number.
- **Reading order:** `spec/04-PROOFS.md` for the proof design and its measurements, then
  `air/src/transfer_air.rs` (the constraint list is commented in order), then
  `formal/README.md` for what is already proven and what the models deliberately do not
  cover.
- **Scale:** the two circuits are roughly 700 lines of constraint code plus ~400 vendored.
  The wrapper and money path are another ~1,500. It is small enough to read completely,
  which is the main argument for having written it by hand.
- **What a finding is worth to us:** a mint or a theft is the whole point of the exercise.
  An under-constrained column with no known exploit is nearly as valuable, because we
  cannot find those ourselves. So is "your test suite would not catch X."

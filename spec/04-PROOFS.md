# 04 · Proofs

**One sentence:** Every hop carries one small STARK proving that hop and only that hop; receiving a note costs one proof verification and one chain lookup **per hop of its history**, and the accumulator (99 [ACC]) — not recursion — is what would collapse that to O(1).

> This headline used to say "one constant-size recursive STARK … O(1) forever". That was the
> zkVM design, retracted twice (journal), and the body of this very file contradicted it while
> the title kept the claim. The title now says what the system does.

> **Scope correction (`formal/multihop.qnt`).** O(1) applies to **validity**, not to safety. The proof attests that every transition was well-formed and authorized; it cannot attest that each hop's *record* won its first-occurrence race, because the circuit has no view of the chain. A Quint model shows per-hop record checks do not compose — two conforming wallets can each accept and supply doubles ([99](99-OPEN-PROBLEMS.md), review gate 2 — since closed). Safe receiving therefore costs one constant-size proof verification **plus one chain lookup per ancestor hop**. The proof still removes the need to re-verify history; it does not remove the need to confirm that history settled. The rule is normative in [03](03-RECORDS.md).
>
> **And "verification is milliseconds" needs the same qualification.** It is milliseconds *given
> indexed chain access*. A light client that cannot build a record index has to ask a server, which
> reinstates both the metadata leak and the completeness trust of audit B2. **The standing caution:
> twice now the cryptography was priced and the data access was not** — O(1) proof verification hid
> O(n) lookups, and "verification is milliseconds" hid "from where?". Price both, every time.

**Requires:** [03-RECORDS](03-RECORDS.md)

## One proof per hop, and why not one per history

Each hop carries **one small STARK** attesting that transfer and only that transfer: its
input commitment opens, its nullifier derives from the key that commitment binds, its two
output commitments open under the same asset, value is exactly conserved, and the input
note's one-time key authorized this exact bundle hash. Public values expose the
commitments, the nullifier, the asset, and the history position; amounts, owner keys, and
randomness stay in the witness, and in the hiding configuration — **the payment format** —
they stay hidden from the receiver and from every later holder too.

A receiver verifies one proof **per hop**, plus one chain lookup per hop to confirm each
settled. That is a change from the recursive design, and an honest downgrade of the
headline: **receiving is O(k) in the note's history depth, not O(1)**. Two reasons it is
the right trade today. In-circuit recursion over a hand-written AIR is a large piece of
new consensus-critical work, where the zkVM gave it for free. And the O(1) claim was
already only ever about *validity*: safely accepting a note requires knowing every
ancestor's record won its race, which is a chain lookup per hop no proof removes
([03](03-RECORDS.md), and `formal/multihop.qnt` for why per-hop checks cannot be trusted
to compose). The accumulator (spec/99 [ACC]) is what collapses both back to O(1) —
recursion is not.

Per-hop cost, measured: 207 KB and 1.6 ms of verification. A 100-hop note is ~20 MB of
ancestry over Signal attachments, which is why the accumulator is the next structural
item rather than a nicety.

## The stack (locked)

**A hand-written AIR on upstream Plonky3 — no zkVM, and never a SNARK wrapper** (pairings
would reintroduce a trusted setup and break the PQ claim). BabyBear field, Poseidon2
permutation, FRI at blowup 16 / 25 queries for ~100-bit soundness. The money path's
transition rules live in `kernel2/` and run identically on the host and in the circuit;
the circuits are `air/src/transfer_air.rs` (a full hop) and `air/src/wots_air.rs` (the
signature alone), sharing one constraint set for the signature section.

**We own these constraints now.** That is the cost of leaving the zkVM: a zkVM's
soundness is one artifact many people review, while an AIR's soundness is every column
being constrained. `air/src/poseidon2_eval.rs` is vendored from `p3-poseidon2-air`
because upstream's `eval` is `pub(crate)` and its `Borrow` asserts an exact-width row, so
the published AIR cannot be composed. External review is required before this holds value
(spec/99 gate 1).

## In-circuit spend authorization

Each note names its owner as a **WOTS+ public key**, one key per note, and the circuit
verifies a signature over the transfer's bundle hash — which commits to the nullifier, both
output commitments, and the history position, so an authorization cannot be replayed onto
a different payment or a different lineage. The chain of custody the circuit and its
verifier wrapper establish together: the proof's chain tips are pinned in-circuit
(constraint 17), the wrapper defines the owner key as `compress(tips)`, and constraint 25
absorbs that key into the input commitment's preimage — so the key that signed is provably
the key the spent note commits to.

Verified refusals, each a test: a foreign key (the tips do not compress to the committed
owner), a signature lifted from another payment (different bundle hash → different digits),
a signature for a different lineage position, an inflating or burning output pair, a
mixed-asset output, and a nullifier derived from someone else's key.

## Measured, historical: the zkVM this replaced (laptop CPU, SP1 v6.3, July 2026)

> **Everything in this section is history, kept because it is the argument.** These numbers
> are what justified abandoning the zkVM, and they were measured, not projected — so they
> stay on the record. The crates and `uv-prove --bin …` commands they name were deleted with
> the zkVM and no longer exist; nothing here describes what runs today. Current numbers are
> above.

Measured at the **real** circuit size — in-circuit SLH-DSA included — by `uv-prove --bin bench`:

| Hop | Cycles | Prove | Size |
|---|---|---|---|
| Genesis, core | 4,009,212 | 65.1 s | 2,795 KB |
| Genesis, compressed | 4,009,212 | 106.7 s | 1,242 KB |
| **Chained, compressed** (what a payment costs) | 5,183,690 | **124.0 s** | **1,242 KB — constant across depth** |

Two corrections this table replaces, both of which were repeated widely before anyone ran the
benchmark:

- **"~45 min/hop" was never measured.** It was an extrapolation from the transition-only circuit
  (88,724 cycles, ~14 s core / ~55–71 s compressed) on the assumption that proving time scales
  linearly with cycles. It does not: 45× the cycles cost ~5× the time. The real figure is **about
  two minutes**, and the demo scripts had been quietly running at that speed the whole time.
- **In-circuit recursion is not the wall.** Verifying the previous STARK inside the circuit costs
  **+17.3 s** — 14% of a payment — against an intuition that it dominates. What dominates is the
  **signature**: 4.0M of the 5.2M cycles.

That makes the optimization ordering unambiguous. WOTS+ one-time signatures attack 77% of the cost
(notes are spent once, so a reusable key's hypertree is waste — [99](99-OPEN-PROBLEMS.md)), while
skipping recursion could recover at most the 17 s and would cost 2.2× the proof size plus O(k)
verification. Measure before optimizing; the intuition was backwards.

### How proving time responds to circuit size (`uv-prove --bin scaling`)

Sweeping the number of inputs scales the in-circuit signature work on one machine, one circuit,
one afternoon — so unlike cross-version comparisons, this measures the shape directly:

| Inputs | Cycles | Prove (core) |
|---|---|---|
| 1 | 4,078,888 | 64.2 s |
| 2 | 8,012,002 | 143.7 s |
| 3 | ~12M | **killed, no output** |

Doubling the circuit cost **2.24×** the time. Proving here is **superlinear** in cycles
(exponent ≈ 1.19), not sublinear as an earlier cross-version comparison suggested. That reverses
the conclusion about optimization: shrinking the circuit pays *more* than proportionally.

Projecting WOTS+ onto that curve — a payment's 5,183,690 cycles drop to ~1.6M once the SLH-DSA
hypertree goes — gives roughly **124 s → 31 s, about 4× faster**. Treat that as a fit, not a
measurement: it is two points, extrapolated below the measured range, from genesis hops rather
than chained ones. It is enough to rank the work, not to quote.

**Memory is the harder wall, and tuning does not move it.** Measured peak RSS for one payment
(chained, compressed) is **9.67 GB**. SP1 v6 exposes `SHARD_SIZE`, `ELEMENT_THRESHOLD`,
`HEIGHT_THRESHOLD`, `TRACE_CHUNK_SLOTS`, and `MINIMAL_TRACE_CHUNK_THRESHOLD`
(`sp1-core-executor/src/opts.rs`), and a sweep of them changed almost nothing worth having:

| Profile | Payment | Peak RSS | Core proof |
|---|---|---|---|
| Default | 124.0 s | ~9.0 GB | 2,795 KB |
| `SHARD_SIZE=2^22`, `TRACE_CHUNK_SLOTS=2`, `MINIMAL_TRACE_CHUNK_THRESHOLD=2^21` | 116.0 s | **9.67 GB** | 4,219 KB |

So **there is no low-memory profile to find.** Smaller shards make the *core* proof bigger (more
shards to commit) without reducing peak RAM, because the memory is the trace itself, not the
chunking policy. A ~12M-cycle proof (3 inputs) dies on this 16 GB machine either way — SP1 logs
`Memory usage is high: 80.06%` and the process is killed.

A trap worth recording: an early sweep looked like a 2.2× RSS win (9.0 GB → 4.28 GB) until it turned
out the low number was measured from a run that **died before reaching peak**. A crashed run's high
water mark is not its requirement.

The consequence is a clean redirect: memory scales with trace length, so the only lever on RAM is
**fewer cycles** — the same lever as wall-clock, and the reason the signature (4.0M of 5.18M cycles)
is the whole optimization target. Tuning is a dead end; the circuit is not.

Cycle counts also vary ~9% run to run (3.80M–4.16M for the same transfer shape) because SLH-DSA
signing is hedged, so signature content differs. Quote ranges, not single digits.

## Which hash to build the signature on (measured `uv-prove --bin hashbench`)

The signature is 4.0M of a payment's 5.18M cycles because SLH-DSA is built on SHA-256 — a hash
foreign to the proof system. Poseidon2 is the hash the STARK already uses for its own Merkle trees,
and SP1 exposes it as a syscall (`sp1-lib::poseidon2`). Measured in-circuit, per hash call over the
same 64-byte input:

| Hash | Cycles / call |
|---|---|
| SHA-256 (SP1-patched precompile) | 1,353 |
| **Poseidon2 (native syscall)** | **402** |

**3.4× cheaper — not the order of magnitude one might assume.** SHA-256 is already accelerated by
its own precompile, so it was never running unassisted; Poseidon2's advantage is being the field's
native hash, not the absence of acceleration on the other side.

WOTS+ verification is a fixed count of hash calls (w=16, n=32: ~570 — 67 chains averaging ~7.5
steps, plus public-key compression), so cost-per-call decides the design:

| Spend authorization | Payment cycles | Projected | Recursion share |
|---|---|---|---|
| SLH-DSA / SHA-256 (today) | 5,183,690 | 124 s measured | 22% |
| WOTS+ / SHA-256 | ~1,955,000 | ~39 s | 59% |
| **WOTS+ / Poseidon2** | ~1,413,000 | **~26 s** | **81%** |
| *(hypothetical: no signature at all)* | ~1,184,000 | ~21 s | 97% |

Projections use the superlinear fit; treat them as ranking, not quotes.

**The conclusion that matters is where it leaves the bottleneck.** After Poseidon2-WOTS+ the
signature is ~4% of the circuit and **in-circuit recursion is ~81%** — within a few seconds of the
floor that exists even with no signature whatsoever. So this change is worth making once, and then
hash-level optimization is finished forever: everything remaining is the cost of running a STARK
verifier as RISC-V instructions. Going below ~21 s is a structural question (a purpose-built
Plonky3 AIR instead of a general-purpose zkVM, or GPU proving), not a cryptographic one.

## Phase A spike: the zkVM is the bottleneck (measured 2026-07-26, `uv-spike`)

The recursion floor above (~21 s even with a free signature) is the cost of executing a STARK
verifier as RISC-V instructions. So: build the **real** Poseidon2 AIR on upstream Plonky3
(`p3-poseidon2-air`) and measure one WOTS+ verification's worth of hashing — 600 permutations, padded
to 1024 as the AIR requires.

Two methodology errors happened first, both of which produced a confident wrong answer:

1. **Keccak was a useless stand-in.** The first attempt proved 600 keccak-f permutations, reasoning
   keccak is dearer per permutation. True but irrelevant: keccak-air is **2,633 columns and 24 rows
   per permutation** where Poseidon2 is 313 columns and 1 row — ~120× the trace cells. It failed
   three gates and the failure meant nothing.
2. **Proof size and verify scale with AIR *width*, not trace height.** Sweeping height over a 64×
   range moved proof size only 711→855 KB. Projecting them against cell counts was meaningless.

### Measured: 1024-row, 313-column Poseidon2 AIR, ~100-bit FRI soundness

Soundness is roughly `num_queries × log_blowup`, so blowup can be raised and queries cut
proportionally — trading prove time, which has enormous headroom, for proof size:

| log_blowup | queries | Prove | Proof | Verify |
|---|---|---|---|---|
| 1 | 100 | 0.010 s | 406.9 KB | 3.20 ms |
| 2 | 50 | 0.032 s | 227.4 KB | 1.79 ms |
| 3 | 34 | 0.048 s | 170.7 KB | 1.33 ms |
| **4** | **25** | **0.040 s** | **137.7 KB** | **1.04 ms** |

### Gates, at blowup 4 / 25 queries

| Metric | Gate | Measured | vs zkVM |
|---|---|---|---|
| Prove | ≤ 2 s | **0.040 s** ✅ | 124 s → **~3,100× faster** |
| Peak RSS | ≤ 1 GB | **111 MB** ✅ | 9.67 GB → **~87× less** |
| Proof size | ≤ 300 KB | **137.7 KB** ✅ | 1,242 KB → **9× smaller** |
| Verify | *(no gate)* | 1.04 ms | ~ms |

**All gates pass.** The proof is also now inside the 50–300 KB figure this document long carried as
an aspiration and had to relabel as a target rather than a measurement — it is a measurement again.

### Zero-knowledge, priced for the first time

SP1's raw STARK is not hiding (see below), and the SNARK wrapper that would fix it is refused on
post-quantum grounds. **Upstream Plonky3 supports hiding directly** — `HidingFriPcs` +
`MerkleTreeHidingMmcs` — so the same circuit was measured both ways:

| Config | Prove | Proof | Verify |
|---|---|---|---|
| Standard | 0.040 s | 137.7 KB | 1.04 ms |
| **Hiding (actually ZK)** | **0.169 s** | **187.4 KB** | 1.26 ms |

Hiding costs **4.2× prove time and 1.36× proof size** — and even so it is ~730× faster and ~6.6×
smaller than the non-hiding zkVM proof we ship today. So the rewrite does not merely go faster; it
**adds a privacy property currently unobtainable at any price**.

### The lookup blocker was wrong — no lookups are needed

Phase A's write-up said WOTS+ chain structure "needs lookups or permutation arguments, and
`p3-uni-stark` is a single-AIR prover with no cross-table lookups." That was too pessimistic and the
constraint system does not need them.

The apparent problem is that chains have *variable* length: chain `i` runs `w-1-d_i` steps, so rows
are not uniform. The fix is a **selector**, standard in AIR design. Every row applies the Poseidon2
permutation unconditionally — keeping those constraints at their natural degree — and a boolean
column decides whether the *chain value* advances:

```
perm_out  = Poseidon2(inputs)                     // unconditional, degree 7
chain_out = sel * perm_out + (1 - sel) * chain_in  // degree 2 on top
next.chain_in = chain_out                          // transition constraint
```

Digits are constrained to their base-`w` range by boolean bit columns (4 bits at `w=16`) rather than
a lookup table, and the digit-to-message binding works through **public values** rather than in-circuit
decomposition (see "How the proof binds message and key" below). So the whole verification is
expressible in one AIR with `p3-uni-stark`, which is what the Phase A measurement was already made
against.

What *does* still need care: `p3-poseidon2-air`'s `eval` is `pub(crate)` and its `Borrow` impl asserts
the row is exactly one `Poseidon2Cols`, so the AIR is **not composable as published**. Its round
evaluation has to be vendored into `air/` (Plonky3 is dual MIT/Apache-2.0; vendored with attribution) to sit alongside our own
columns. The plan already accepts owning consensus-critical circuit code; this is where that begins.

### Host-side WOTS+ landed (`air/src/wots.rs`)

The reference implementation the AIR will be differentially tested against, since that is how the
host/circuit parity the zkVM gave for free gets preserved. Poseidon2 over BabyBear with
**published fixed constants** (`default_babybear_poseidon2_16`, deliberately not `from_rng` — host and
circuit must agree and a protocol cannot have per-instance constants). Classic parameters: `w=16`,
64 message digits, 3 checksum digits, 67 chains, ~1,005 chain permutations — which is why the AIR was
sized at ~1,024 rows.

Seven tests, including the property that makes WOTS+ safe at all: **advancing a chain to claim a
larger digit lowers the checksum**, whose own chains would then need walking backwards, which requires
inverting the hash. Also tested: cross-message and cross-key rejection, and tampering with the first,
middle, and last chain.

A parameter note worth measuring later rather than arguing: total hashing is ~`chains × (w-1)`, so
*smaller* `w` is cheaper in circuit — `w=4` is ~512 permutations against `w=16`'s ~1,005 — at the cost
of a larger signature.

### The real circuit, measured (`uv-air --bin measure`)

Phase A measured a bare Poseidon2 AIR and projected from it. This is the finished WOTS+ verification
circuit — chain constraints included — proving and verifying for real:

| Config | Trace | Prove | Proof | Verify | Peak RSS |
|---|---|---|---|---|---|
| Standard | 1,024 × 392 | **0.076 s** | **150.0 KB** | 1.21 ms | **111 MB** |
| **Hiding (zero-knowledge)** | 1,024 × 392 | 0.158 s | 199.6 KB | 1.36 ms | 111 MB |

These are the numbers **with the message and public-key binding constrained** — the proof means
something. ZK costs 2.1× prove time and 1.33× proof size. Proof size includes the 2.1 KB of tips the
proof carries (see below).

**How these were measured, because it bit us.** Every figure above and below is from
`uv-air --bin measure`, which now proves one throwaway proof before timing anything and
can isolate either circuit (`UV_MEASURE=signature|transfer`). Both were necessary. The
first proof in a process pays for allocator growth and cold caches, so timing it flattered
whichever circuit ran second — and did: the transfer circuit read as 0.055 s against the
signature circuit's 0.111 s, which cannot be right for a *wider* trace with *more*
constraints. Once isolated and warmed, the transfer circuit appeared to be genuinely the faster of the
two (0.067 s vs 0.083 s), reproducibly, which we recorded as measured, surprising and
unexplained.

**Re-measured 2026-07-27: it no longer reproduces, and the ordering has inverted.** The
signature circuit is now the faster one — 0.050–0.057 s against the transfer circuit's
0.070–0.084 s across four runs — which is the physically expected direction for a narrower
trace with fewer constraints.

We are not claiming the anomaly is *resolved*, because there is a confound we should have
seen the first time: **the harness's warm-up proves a signature.** So the signature circuit
is measured warm and the transfer circuit is measured cold, and the isolation flags added
since (`UV_MEASURE=transfer-standard|transfer-hiding`) changed which proofs run in a process
and therefore how much of that warm-up carries. That biases *toward* the signature circuit
today and away from it before, which is the wrong shape to explain a clean inversion — so it
is a candidate, not an answer. What is fair to say: the surprising result was not stable
across a change in harness, and a comparison between the two circuits should not be leaned on
until the warm-up warms whichever circuit is about to be timed.

History of this table, kept because each step was measured rather than projected: Phase A's
313-column stand-in said 0.040 s / 137.7 KB; the unbound circuit (323 columns — the published
BabyBear permutation has **13** partial rounds, not the 20 in upstream's examples, so Poseidon2 is
299 columns, plus 24 chaining/digit columns) measured 0.097 s / 139 KB; the binding added 69 columns
(a 67-wide one-hot register plus two boundary-pinning columns) and zero rows, for +14% prove time
and +8% proof size. Each widening moved the numbers the way the column count predicted.

### How the proof binds message and key (constraints 13–17)

The circuit never decomposes the message. The **verifier** computes `digits(msg)` host-side —
canonical by construction, since `as_canonical_u32` is a bijection onto `0..p`, which kills the
`e` vs `e+p` ambiguity an in-circuit decomposition would have to range-check away — and supplies
all 67 digits as public values, alongside the 67 chain tips the proof carries. The prover never
supplies a digit; there is nothing for it to choose.

In-circuit, a constraint-pinned **one-hot chain-index register** (67 columns whose first row is
pinned and whose rotation on chain boundaries is deterministic — the prover has zero freedom in it)
selects each chain's public digit and tip as a degree-1 sum, sidestepping the degree-66
interpolation that per-chain indexing would otherwise need. Pinning the rotation to real boundaries
required making `is_last ⇔ pos = w-2` a constraint (a step counter plus an inverse witness) —
closing a latent gap where `is_last` was boolean but positionally free, harmless while the proof
bound nothing and fatal the moment boundaries index public values.

The binding is therefore a property of **STARK + wrapper**, and the wrapper's **three**
host-side checks are consensus rules: public values MUST be `digits(msg) ++ tips` built by the
verifier, `compress(tips)` MUST equal the public key, and the proof's **declared trace height MUST
equal the height the AIR is sound at**. `uv_air::prove::verify` is the only exported entry point
and performs all three; a future recursive verifier must reproduce all three.

**The third one is new, and it was added because its absence was a total break.** `p3_uni_stark`
takes the trace height out of the proof and never validates it — its contract is that an AIR is
sound at *every* height. Ours is not, and nothing said so. These AIRs are positional: `is_last`
fires only when the position counter reaches the end of a chain, the sponge register is seeded only
by `is_last`, and every sponge constraint is gated on that register. Give the prover a shorter
trace and none of it happens — no commitment opening, no nullifier derivation, no conservation, no
range check, no spend anchor — while the verifier dutifully builds public values that nothing then
reads. An eight-row trace of zeros proved an arbitrary transfer, and a second proof-of-concept ran
it up the whole rail to a `wallet2::accept` that returned `Ok` on money forged from nothing.

Two details worth carrying. **The height check is invisible from inside the AIR**, unlike the other
two obligations, which is what makes it easy to lose in a rewrite. And **the expected height is not
a constant**: a hiding proof runs over an extended domain and legitimately declares one more bit
(`degree_bits = log_degree + config.is_zk()`), so the check derives it from the configuration.
Hardcoding the standard value rejects every honest payment — a mistake this code also made, for
about twenty minutes, before an adversarial reader caught it. The checksum needs no
in-circuit constraint at all under this design: the verifier derives checksum digits from the
message exactly as host-side WOTS+ verification does, so there is no prover-influenced path to any
digit.

The negative suite now includes the tests that were unwritable while the proof bound nothing:
cross-message rejection, cross-key rejection, a digit vector for a different message, a shifted
chain boundary, a re-labelled one-hot register — and the sharpest one, **tampered tips verified
against the key that compresses from them**, so the host-side check passes and only constraint 17
stands between the forger and acceptance. It rejects in the AIR, which is the proof that the pk
binding does not live in the wrapper alone.

### The transfer circuit: one complete hop, same trace height (constraints 18–31)

The full money-path hop — input-commitment opening, nullifier derivation, two output-commitment
openings, conservation over range-checked 16-bit limbs, and the WOTS+ verification — is **one
table at 1,024 × 457**: the eighteen sponge permutations ride in rows the power-of-two padding
was already paying for. Measured (`uv-air --bin measure`):

| Config | Trace | Prove | Proof | Verify | Peak RSS |
|---|---|---|---|---|---|
| Standard | 1,024 × 457 | **0.070–0.084 s** | **158.3 KB** | 1.4 ms | 67 MB |
| **Hiding (zero-knowledge)** | 1,024 × 457 | 0.202–0.241 s | 208.0 KB | 1.6 ms | 117 MB |

**On an iPhone 17 Pro Max (A19 Pro, iOS 26.5.2), from a signed app on the device:** hiding
**0.284–0.314 s / 208.0 KB / 1.6–1.7 ms verify / 279 MB peak**, standard **0.099–0.102 s /
158.3 KB / 1.3 ms / 56 MB**. On an **iPhone 16e (A18)**, the cheapest current model, hiding is
**0.331–0.354 s / 304 MB peak** — ~1.15× slower, with the prover's share of memory within 2 MB
of the flagship's. Proof sizes are byte-identical across both phones and the macOS build. This is what
dissolves the delegated-proving problem (99-OPEN-PROBLEMS, now closed): a phone that can
prove in a third of a second never has to hand its witness to a server. Reproduce with
`ios/UVProbe`; measure one configuration per process, because peak RSS is a process
high-water mark and running both reports their union.

Against the zkVM hop it replaces (124 s / 1,242 KB): **~1,850× faster, ~8× smaller — and
this hop is *sound* (message-bound) and, in the hiding configuration, actually zero-knowledge,
neither of which the SP1 hop ever was.** The witness contains amounts, keys, and randomness, so
the hiding configuration is the one that matters for payments.

**DECIDED for v1 (2026-07-26, user): the hiding configuration is the payment format, and the only
one.** A note travels with one hiding transfer proof per hop (~208 KB each); ancestors' amounts,
keys, and randomness are never revealed to any later holder — amount confidentiality along the
whole lineage is the property being bought, and ~70× the bandwidth of shipping plain witnesses
(~3 KB/hop) is its measured price. A plain-witness validation mode was considered and rejected:
two consensus validation paths is two consensus surfaces, and a mixed lineage inherits its weakest
hop's privacy. The standard (non-hiding) configuration remains for benchmarking and for public-data
proofs; the accumulator (spec/99 [ACC]) is what eventually collapses per-hop ancestry entirely.

**Constraint 32, the spend anchor.** The note commits to `t = H(nullifier_key)`
rather than to the key, and one sponge row proves the spender knows a preimage of
the committed anchor. This is what lets a payer build a note from public material
alone — the design error in [02](02-NOTES.md)'s previous address section — and it
closes a privacy leak that was live until now: a payer who learned the nullifier
key could compute exactly when its payment was spent onward, forever. The section
had spare rows under the power-of-two height, so the anchor cost one row, nine
columns, and no change in trace height.

The re-measurement is worth reading carefully, because it moved in two directions
at once. Standard proving went 0.053 s → 0.067 s (+26%, the expected direction for
nine more columns). Hiding proving went 0.232 s → **0.189 s (−19%)**, which is the
wrong direction and reproducible across runs. That is the same unexplained
width/speed interaction recorded above, now observed inverting between the two
configurations. We do not have an explanation, and are not inventing one.

Design points, each carrying a soundness argument (`air/src/transfer_air.rs`): a 17-wide one-hot
shift register (seeded by `is_last · oh[66]`, true exactly once) marks the sponge rows with zero
prover freedom; "bus" columns hold the nullifier key and the twelve amount limbs constant across
the section, so the key the commitment binds is provably the key the nullifier derives from;
per-lane absorb ties pin every non-private absorbed value (the zero ties on final chunks are
load-bearing — without them the sponge is not the host's hash); the shape is **fixed two-output**
(a single-recipient payment carries a genuine zero-amount change note — uniform trace, uniform
observables); and the shared 16 range-bit columns kill the `2^16`-limb alias that would otherwise
satisfy conservation *with its carry*. The sponge itself lives in one place
(`air/src/sponge.rs`, re-exported by kernel2), and witness generation is defined on the same
`absorb_states` the host hash is — circuit and hash cannot drift. The consensus verify entry
point is `uv_kernel2::transfer_prove::verify`, which derives the whole public statement — bundle
hash above all — from the transfer being validated.

**And a differential test is necessary, not sufficient.** The suite shows the circuit agrees with the
host reference on the cases exercised — including that a tampered witness fails to verify. It cannot
show that *no other* witness satisfies the constraints, which is the property that actually stops
forgery. Under-constrained columns are invisible to honest-witness testing, and we now own this code:
`air/src/poseidon2_eval.rs` is vendored from `p3-poseidon2-air` because upstream's `eval` is
`pub(crate)` and its `Borrow` impl asserts an exact-width row, so the published AIR cannot be
composed. External review is required before this holds value.

## Not zero-knowledge (verified against the prover source, 2026-07-26)

The proofs are **succinct, not hiding**. SP1 v6.3.1's entire commitment stack —
`slop-merkle-tree`, `slop-basefold-prover`, `slop-whir`, `slop-sumcheck`, `slop-jagged`,
`sp1-prover` — contains no blinding, masking, or randomization for hiding: commitments are
deterministic Merkle trees over the unblinded execution trace, and every opening the proof carries
is a genuine trace value. (Historically SP1's zero-knowledge came from the SNARK wrapper — the one
this design refuses on post-quantum grounds. Refusing the wrapper refused its hiding too, and
nobody re-checked. Same failure shape as the O(1) and 45-minute claims: an inherited property
asserted, not verified.)

What this does and does not break:

- **Public privacy stands.** The chain sees 64-byte keyless records; relays and carriers see
  ciphertext. No party or amount is ever public. The note commitment itself is genuinely hiding
  (randomness inside the hash).
- **Recipient-facing privacy is weaker than claimed.** The proof's witness contains the sender's
  `nullifier_key`, the input note's randomness, and every output note — including the **change**
  note's amount and randomness. The openings sample the trace at verifier-chosen points, so a
  single proof leaks an unpredictable fragment; extraction of a specific secret from one proof is
  not established to be practical. But the guarantee claimed ("reveals nothing") is simply absent.
- **Leakage accumulates.** With today's per-identity `nullifier_key`, every payment a wallet sends
  embeds the *same* secret into a fresh unblinded trace with fresh random openings. Enough
  payments, enough samples. This converts per-note key diversification ([99](99-OPEN-PROBLEMS.md))
  from a privacy nicety into **witness hygiene**, and it is why spend authorization must stay
  *leak-tolerant* (a payload-bound signature in the witness authorizes nothing else if it leaks;
  a bare preimage would be fatal). The design principle that follows: **the witness of a spend
  should contain no secret that outlives the spend.** The one residue that cannot be fully removed
  is the change note's randomness — the circuit must see the outputs it commits.
- **The fix is upstream or structural**: a hiding STARK (ZK variants of BaseFold/WHIR exist in the
  literature; RISC0-style trace blinding is prior art) is a watch item, not something to fork in.

## Status

Two-hop recursion demonstrated end-to-end 2026-07-22, including in-circuit rejection of linkage violations. In-circuit SLH-DSA spend authorization landed 2026-07-25 with the cost above. Channel disputes are the next guest milestone ([99](99-OPEN-PROBLEMS.md)).

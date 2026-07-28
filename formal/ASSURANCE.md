# Formal assurance matrix

This matrix is the boundary around every formal claim in Ultraviolet. It says
what is modeled, what the checker established, which implementation path is
meant to refine it, and what remains assumed.

## Evidence classes

- **Counterexample:** Apalache found a concrete bounded trace. This is proof
  that the modeled design variant is unsafe.
- **Bounded check:** no counterexample exists up to the documented transition
  depth in the fixed finite universe. This is evidence, not a proof beyond that
  bound.
- **Inductive check:** initialization, preservation, and implication all hold.
  This removes the transition-depth bound but not the model's finite data
  universe or its abstractions.
- **Rust replay:** an executable test exercises the corresponding implementation
  transition or counterexample. It is a conformance witness, not a refinement
  proof.

## Claims and implementation bridges

| Claim | Model/property | Evidence | Rust bridge | Assumptions and exclusions |
|---|---|---|---|---|
| Checking only the final hop can inflate honest holdings | `multihop/buggy::noInflation` | Counterexample, depth 8 | `wallet2/tests/multihop_inflation.rs` | Whole-note identity model; cryptography sound |
| Bound, fully settled ancestry prevents that modeled branch inflation | `multihop/bound::supplyInv ⇒ noInflation` | Inductive in a five-note universe | `wallet2/src/accept.rs` | Not parameterized over arbitrary notes, amounts, assets, or ordered output vectors |
| Non-recursive proofs require explicit hop linkage | `linkage/unchecked::noSplicedHistory` | Counterexample, depth 8 | `wallet2/src/accept.rs` | At most four hops; proof verification abstracted |
| One confirmation is unsafe against admitted two-block reorgs | `reorg/shallow::acceptedStaysValid` | Counterexample, depth 8 | `wallet2/src/chain.rs` | Ideal canonical-chain oracle; maximum reorg is a model parameter |
| A persistent scan must be one coherent chain snapshot | `indexer/midscanUnsafe::noMixedSnapshot` | Counterexample, depth 6 | `btc/src/lib.rs::index_stable_range`, `btc/src/index.rs::discard_from` | Two forks, one first occurrence, three heights |
| Shortening must verify the retained tip hash before answering | `indexer/shortUnsafe::answersCanonical` | Counterexample, depth 6 | `btc/src/lib.rs::reconcile_index_tip` | Same finite fork abstraction |
| A WOTS key must not expose two different payloads | `onetime/*::noKeyReuse` | Counterexamples and bounded checks, depth 8 | `wallet2/src/signlog.rs`, `wallet2/src/send.rs` | WOTS security consequence abstracted as a forbidden event |
| Replay needs the exact signed payload | `onetime/replay::eventuallySpendable` | Bounded check, depth 8 | `wallet2/src/send.rs`, `wallet2/tests/replay_pays_the_original_payee.rs` | Deterministic signing; no scheduler eventuality claim |
| Persist-before-publish requires inter-process serialization | `wallet_io/current::noExposedKeyReuse` | Counterexample, depth 8 | `cli/src/durable.rs::ExclusiveLock` | Two processes and one WOTS key |
| A published sign log must survive power loss | `wallet_io/current::publishedIsRemembered` | Counterexample, depth 5 | `cli/src/durable.rs::atomic_write` | Filesystem honors file and directory sync contracts |
| Failed replacement must preserve the prior wallet | `wallet_io/current::walletFileSurvives` | Counterexample, depth 4 | `cli/src/durable.rs::atomic_write` | Same-directory rename is atomic |
| Highest backed channel state avoids phantom-claim deadlock | `channels/*::settlementNeverDeadlocks` | Bounded checks, depth 5–6 | Design only (`spec/07-CHANNELS.md`) | Channels unimplemented; stable in-window ordering and sound signatures assumed |
| Base-rail payment can become terminally impossible | `baserail/*::paymentRemainsPossible` | Counterexamples and bounded checks, depth 8 | `wallet2/src/store.rs`, `wallet2/src/send.rs` | One two-unit payment; viability, not eventual completion |
| A chain view that cannot answer is retryable, not permanent rejection | `reorg`/`indexer` operational consequence | Rust replay | `wallet2/src/accept.rs::Rejected::is_permanent` | Mailbox remains the delivery source until acceptance |

## What is not formally verified

- Poseidon2, WOTS, FRI, or STARK cryptographic security.
- Correctness or completeness of every AIR constraint. `air/COVERAGE.md`
  provides mutation evidence, not a proof.
- A refinement mapping from Rust states to Quint states.
- Filesystem, operating-system lock, Bitcoin Core RPC, or network
  implementations.
- Arbitrary assets, issuance policy, arbitrary lineage length, or arbitrary
  channel parameters.
- Temporal liveness under fairness. The channel and base-rail properties are
  bounded viability checks.

## Verification tiers

```bash
# Every push/PR: typecheck, references, and the seconds-fast bounded suite.
./formal/verify.sh fast

# Manual or scheduled: every bounded row plus multihop's inductive check and
# the expensive channel matrix.
./formal/verify.sh
```

Every complete run belongs in `formal/VERIFIED.md` with the exact commit and
tool version. Expected violations are part of the suite: losing a known
counterexample is a model regression until explained.

// Ultraviolet — base-rail liveness, and two failures that were filed wrong.
//
// Every property in this directory before this file was a safety property. That
// is not because the base rail has no liveness failures; it is because the two
// it has were named in ways that sound like safety and then reasoned about as
// safety:
//
//   **Griefing.** A third party pairs a revealed nullifier with a garbage bundle
//   hash. First-occurrence-wins binds that nullifier forever, so the real
//   transfer can never settle and the note is destroyed. Filed in spec/99 as
//   "griefing" — a word for annoyance.
//
//   **No proof merging.** A transfer spends one note. A wallet holding two notes
//   whose *combined* value it needs cannot pay at all. Filed as a performance or
//   scope limitation.
//
// The point of this model is the shape of the result, not novelty: both failures
// are already known. What is new is showing that the safety properties **hold**
// in exactly the runs where the payment becomes impossible. That is what makes
// them liveness failures, and liveness failures need *recovery paths* — neither
// of these has one, and calling them griefing and scope hid that.
//
// ---- What is modelled ----
// One honest payment of TARGET, the notes available to fund it, nullifier
// revelation, keyless record publication, first-occurrence-wins, and settlement.
//
// ---- What is assumed ----
// Proofs are sound, and a note's nullifier becomes visible to third parties when
// the transfer is broadcast — which is what makes the griefing race exist at all.
// If nullifiers could stay hidden until the record confirmed, there would be no
// race; that is a design direction, not something this model evaluates.
//
// ---- What the adversary controls ----
// Record publication timing, and the ability to publish a record pairing a
// revealed nullifier with a hash of their choosing. They are given no notes, no
// keys, and no way to receive value — deliberately, because the finding is that
// they *gain nothing* and the damage is real anyway.
//
// ---- Liveness technique ----
// Deadlock-freedom, as an invariant with no step bound: the payment must never
// become impossible. This is the safety-shaped *necessary condition* for
// liveness — if it fails, no amount of scheduling saves the payment — and it is
// used here for the reason recorded under "Modelling mistakes" in formal/README.md: a
// bounded "paid by step K" invariant would report the simulator's choices
// rather than the protocol's.
//
// **"No step bound" became true on 2026-07-30, and was not before.** This
// paragraph made the argument from the day the file was written, and every row
// in `verify.sh` ran at `--max-steps=8` anyway — the file described an unbounded
// claim and the suite made a bounded one. The gap was found by auditing which
// models had all-depths proofs: five safety models did, and **both liveness
// models had none**, which is the wrong way round for a file whose whole point is
// that liveness failures were being filed as safety. The strengthenings at the
// bottom of each module close it. What is still bounded, and why, is
// `splitRecords` — see its module comment.
//
// ---- Re-derived after proof-native authorization (2026-07-29) ----
// This model was first written when spends were signed with one-time keys, and
// one premise leaned on that: the one-live-bundle rule was justified as the
// analog of the never-re-sign discipline. The signature is gone — building a
// second proof for a note is now cryptographically free — so every premise was
// re-examined. The findings stand, because the model never mentioned
// signatures: griefing and no-merge are facts about *keyless records and
// first-occurrence-wins*, which the migration did not touch. What changed is
// only the reason one-live-bundle holds (see the constant below): it is now an
// operational rule against racing yourself, not a key-safety rule, and a
// wallet that breaks it loses a race, not a key.
//
// Run (safety, all depths — expected to hold even with the griefer on):
//   quint verify formal/baserail.qnt --main=griefable --invariant=nobodyElseGetsPaid --inductive-invariant=railSafetyInv
// Run (liveness, all depths):
//   quint verify formal/baserail.qnt --main=atomic       --invariant=paymentRemainsPossible --inductive-invariant=railInv
//   quint verify formal/baserail.qnt --main=splitPayment --invariant=paymentRemainsPossible --inductive-invariant=splitInv
// Run (the two failures, which must still reproduce):
//   quint verify formal/baserail.qnt --main=griefable --invariant=paymentRemainsPossible --max-steps=8
//   quint verify formal/baserail.qnt --main=noMerge   --invariant=paymentRemainsPossible --max-steps=8
//
// The `atomic` line above said `--main=ideal` until 2026-07-30. **There has never
// been a `module ideal`** — it was renamed `atomic`, and `verify.sh` carried the
// same dead reference until a full run caught it. `check-refs.sh` was then
// extended to validate module names, but only those cited in `verify.sh`, so this
// copy in a header comment survived the fix that was written for it. It now
// checks header run-lines too.

module rail {
  // Can a third party publish a record for a nullifier it has merely observed?
  // True is the protocol as specified: records are keyless.
  const GRIEF_POSSIBLE: bool
  // How many notes one transfer may spend. 1 is the protocol today — no proof
  // merging. 2 models a merge capability.
  const MAX_INPUTS: int
  // A wallet discipline: never build a second transfer spending a note some
  // unsettled transfer of yours already spends. Under proof-native
  // authorization a second proof costs nothing cryptographically — what this
  // rule prevents is the wallet racing *itself* at first-occurrence, where one
  // record settling destroys the other transfer's note — and, see
  // `splitRecords`, it becomes load-bearing the moment a transfer may spend
  // more than one note.
  const ONE_LIVE_BUNDLE_PER_NOTE: bool

  // Whether a settled transfer is dropped from `bundles`.
  //
  // **False is the rule, and this constant exists so the rule can be absent.**
  // `settle`'s own comment records pruning as a mistake that was actually made:
  // removing a settled bundle leaves its first-occurrence records naming a
  // transfer that no longer exists, which reads as a safety violation. It did, on
  // the first attempt.
  //
  // That history is the reason it is a constant now. The all-depths safety proofs
  // (`railSafetyInv`, `splitSafetyInv`) both rest on `bundles` never shrinking,
  // and nothing else in this file can make safety fail — third parties are given
  // no notes, no keys and no bundles, so no adversary constant can redirect a
  // record. Without a way to switch retention off, an all-depths safety result
  // would have nothing able to break it, which is the definition of a claim about
  // bookkeeping. `railPruned`/`splitPruned` are that switch.
  const PRUNE_SETTLED: bool

  // Alice must pay 2, and holds two notes worth 1 each. The smallest holding
  // that needs merging.
  pure val NOTES = Set(1, 2)
  pure val VALUES: int -> int = Map(1 -> 1, 2 -> 1)
  pure val TARGET = 2
  // A hash that resolves to no bundle anyone will ever produce.
  pure val GARBAGE = -1

  type Bundle = { id: int, inputs: Set[int] }

  // nullifier -> the bundle hash its first occurrence bound it to.
  var recorded: int -> int
  var bundles: Set[Bundle]
  // Nullifiers third parties can see, i.e. those of broadcast transfers.
  var revealed: Set[int]
  var paid: bool
  var nextId: int

  def valueOf(s: Set[int]): int = s.fold(0, (a, n) => a + VALUES.get(n))
  def hasRecord(n: int): bool = recorded.keys().contains(n)

  // Note sets that could fund the payment: within the input limit, worth enough,
  // and none of their nullifiers already bound.
  def fundable: Set[Set[int]] =
    NOTES.powerset().filter(s =>
      s != Set() and s.size() <= MAX_INPUTS and valueOf(s) >= TARGET
        and s.forall(n => not(hasRecord(n))))

  // A built bundle can still settle if every input is either unbound or already
  // bound to this very bundle — partial publication is progress, not death.
  def settleable(b: Bundle): bool =
    valueOf(b.inputs) >= TARGET
      and b.inputs.forall(n => not(hasRecord(n)) or recorded.get(n) == b.id)

  // ---- SAFETY ----
  // A first occurrence either settles one of Alice's own transfers or destroys
  // the note. Nothing a third party does can redirect the money to anyone else.
  // This is precisely why the failure got called "griefing": it holds, in every
  // run, including the ones where Alice loses her money outright.
  val nobodyElseGetsPaid: bool =
    recorded.keys().forall(n =>
      recorded.get(n) == GARBAGE or bundles.exists(b => b.id == recorded.get(n)))

  // ---- LIVENESS (deadlock-freedom) ----
  // The payment is never rendered impossible: either it settled, or some funding
  // set or already-built bundle can still get there.
  val paymentRemainsPossible: bool =
    paid or fundable != Set() or bundles.exists(b => settleable(b))

  // ---- The inductive strengthening: liveness at ALL DEPTHS ----
  //
  //   quint verify formal/baserail.qnt --main=atomic \
  //     --inductive-invariant=railInv --invariant=paymentRemainsPossible
  //
  // This model's header argues that deadlock-freedom is checked "as an invariant
  // with no step bound", because a bounded "paid by step K" property would report
  // the simulator's choices rather than the protocol's. That argument was right
  // and the runbook did not honour it: every row ran at `--max-steps=8`. These
  // definitions are what make the file's own claim true.
  //
  // Domain constraints first — required, not decorative. Induction begins at an
  // *arbitrary* state satisfying the invariant, so every variable needs a
  // constructible domain (the lesson `multihop.qnt` records, and which
  // `delivery.qnt` learned again the hard way: even four booleans need pinning,
  // because Apalache demands an assignment per variable, not a small domain).
  val BUNDLE_IDS: Set[int] = 1.to(2)
  val BUNDLE_UNIVERSE: Set[Bundle] =
    tuples(BUNDLE_IDS, NOTES.powerset()).map(((i, s)) => { id: i, inputs: s })

  val typeOK: bool =
    NOTES.powerset().exists(kd =>
      recorded.in(kd.setOfMaps(Set(GARBAGE).union(BUNDLE_IDS))))
      and bundles.in(BUNDLE_UNIVERSE.powerset())
      and revealed.in(NOTES.powerset())
      and paid.in(Set(false, true))
      and nextId.in(1.to(2))

  // Ids come from one counter, so each names at most one bundle and none has been
  // handed out yet. Not runtime properties — they exist to stop the induction
  // considering states the counter cannot produce.
  val uniqueIds: bool =
    bundles.forall(a => bundles.forall(b => (a.id == b.id) implies (a == b)))
  val freshIds: bool = bundles.forall(b => b.id < nextId)

  // **The counter counts the bundles.** `build` is the only action that touches
  // either, and it adds exactly one bundle and increments once.
  //
  // This conjunct is here because of a counterexample worth keeping. Without it,
  // the first attempt bounded `nextId` to `1.to(3)` and Apalache immediately
  // found the hole: start from `bundles = Set()` with `nextId = 3` — the top of
  // the domain, well-typed, invariant satisfied — then fire `build`. It produces
  // a bundle with `id: 3` and `nextId' = 4`, both **outside the domain**, so
  // `typeOK'` fails and the step case dies.
  //
  // The lesson generalises past this file: **a domain constraint has to be closed
  // under the transition relation, not merely large enough for reachable states.**
  // Padding the bound would not have helped — any `K` has a `K+1`. What closes it
  // is relating the counter to what it counts, because then the same rule that
  // stops `build` firing again also stops the counter moving.
  val counterCountsBundles: bool = nextId == bundles.size() + 1

  // **`ONE_LIVE_BUNDLE_PER_NOTE`, stated as an invariant.** This is the conjunct
  // that carries a real protocol rule rather than bookkeeping, and without it the
  // induction fails on a state that is unreachable but perfectly well-typed: two
  // bundles over the same notes with *crossed* records — note 1 bound to bundle 2
  // and note 2 bound to bundle 1. Neither can settle, and neither note is free.
  // That is not a hypothetical; it is exactly the deadlock `splitRecords`
  // exhibits, which is why the discipline has to appear here to prove anything
  // about `atomic`.
  val disjointInputs: bool =
    bundles.forall(a =>
      bundles.forall(b =>
        (a.id != b.id) implies (a.inputs.intersect(b.inputs) == Set())))

  // **Every bundle was built from a funding set.** `build` draws its inputs from
  // `fundable`, so a bundle always covers the target and respects the input
  // limit. Stating it is load-bearing: without it the induction dies on a state
  // holding two single-note bundles worth 1 each, where binding either note
  // leaves nothing fundable and nothing settleable. In `atomic` no such bundle
  // can exist — with unit values, reaching TARGET = 2 needs both notes — but the
  // induction has no way to know that unless it is written down.
  //
  // In `noMerge` this conjunct is unsatisfiable for any non-empty `bundles`
  // (value >= 2 and size <= 1 cannot both hold), which is correct and is the
  // finding: no transfer can be built at all.
  val bundlesAreFundingSets: bool =
    bundles.forall(b =>
      valueOf(b.inputs) >= TARGET and b.inputs.size() <= MAX_INPUTS)

  // A record either destroys its note or points at a bundle that really spends
  // it. `publishReal` only ever binds `n` to a bundle whose inputs contain `n`;
  // `grief` only ever writes GARBAGE. This *strengthens* `nobodyElseGetsPaid`,
  // which asks only that the bundle exists — the extra clause is what
  // `settleable` needs to survive a step.
  val recordsMatchTheirBundle: bool =
    recorded.keys().forall(n =>
      recorded.get(n) == GARBAGE
        or bundles.exists(b => b.id == recorded.get(n) and b.inputs.contains(n)))

  // Liveness, all depths. Expected to hold under `atomic` and to FAIL under
  // `griefable` (a griefed note is burnt) and `noMerge` (nothing can be built) —
  // and those two failures are the anti-vacuity evidence: an invariant that held
  // in all three would be describing the model rather than the protocol.
  val railInv: bool =
    typeOK and uniqueIds and freshIds and counterCountsBundles and disjointInputs
      and bundlesAreFundingSets and recordsMatchTheirBundle
      and paymentRemainsPossible

  // Safety, all depths, and deliberately a *separate* invariant. It must hold
  // under `griefable`, where `railInv` cannot — griefing destroys the payment
  // (liveness) without ever redirecting it (safety), and that gap is the whole
  // point of this model. One combined invariant would collapse the distinction
  // the file exists to draw.
  // `bundlesAreFundingSets` is in here too, and not because safety needs it:
  // **domain closure** does. Apalache found the hole with a bundle whose `inputs`
  // is the EMPTY SET — well-typed, and it intersects nothing, so it fails to
  // block `build` the way a real bundle does. `build` then fires and `nextId`
  // leaves its domain, exactly the escape `counterCountsBundles` was added for.
  // A bundle can never have empty inputs (`build` draws from `fundable`, whose
  // members all reach TARGET), so the conjunct is true — it just has to be said.
  val railSafetyInv: bool =
    typeOK and uniqueIds and freshIds and counterCountsBundles
      and bundlesAreFundingSets and recordsMatchTheirBundle

  // ---- Anti-vacuity, run as rows expecting a VIOLATION ----
  //
  // `paymentRemainsPossible` is a three-way disjunction, and it would be **free**
  // if `fundable` were never empty: the property would discharge on its first
  // term forever, `settleable` would never be consulted, and `disjointInputs` and
  // `recordsMatchTheirBundle` — the two conjuncts that cost the work — would be
  // proving nothing. This row failing exhibits a reachable state where the
  // payment survives ONLY because a built bundle can still win, which is the
  // clause the crossed-records trap attacks.
  //
  // If it ever stops failing, the all-depths result above has quietly become a
  // statement about `fundable` alone.
  val fundableOrPaid: bool = paid or fundable != Set()

  // ...and the payment must be completable, not merely never-dead. "Always
  // possible, never done" satisfies deadlock-freedom and is not a payment.
  val neverPaid: bool = not(paid)

  action init = all {
    recorded' = Map(),
    bundles' = Set(),
    revealed' = Set(),
    paid' = false,
    nextId' = 1,
  }

  // Build a transfer funded by an eligible note set.
  action build = all {
    nondet s = oneOf(NOTES.powerset())
    all {
      fundable.contains(s),
      ONE_LIVE_BUNDLE_PER_NOTE implies
        bundles.forall(b => b.inputs.intersect(s) == Set()),
      bundles' = bundles.union(Set({ id: nextId, inputs: s })),
      nextId' = nextId + 1,
      recorded' = recorded,
      revealed' = revealed,
      paid' = paid,
    }
  }

  // Broadcasting the transfer to its recipient exposes its nullifiers. This is
  // the step that opens the race: before it, no third party knows what to grief.
  //
  // The `bundles != Set()` guard here and below is not decoration. `oneOf` over
  // an **empty** set is unconstrained rather than disabled: Apalache supplies an
  // arbitrary value of the element type. Without the guard, `publishReal` fired
  // before any bundle existed, bound a nullifier to a bundle id nobody had
  // produced, and manufactured violations of *both* properties — including in
  // `ideal`, where nothing adversarial happens at all. Any action drawing from a
  // set a previous action populates needs this guard, or the model invents its
  // own counterexamples.
  action broadcast = all {
    bundles != Set(),
    nondet b = oneOf(bundles)
    all {
      revealed' = revealed.union(b.inputs),
      recorded' = recorded,
      bundles' = bundles,
      paid' = paid,
      nextId' = nextId,
    }
  }

  // Alice publishes the real record for one of her inputs.
  action publishReal = all {
    bundles != Set(),
    nondet b = oneOf(bundles)
    nondet n = oneOf(NOTES)
    all {
      b.inputs.contains(n),
      not(hasRecord(n)),
      recorded' = recorded.put(n, b.id),
      bundles' = bundles,
      revealed' = revealed,
      paid' = paid,
      nextId' = nextId,
    }
  }

  // The grief: pair an observed nullifier with a hash backing no bundle. Records
  // are keyless, so this needs no authorization and no stake. The griefer
  // receives nothing — that is the entire problem with how it was filed.
  action grief = all {
    GRIEF_POSSIBLE,
    nondet n = oneOf(NOTES)
    all {
      revealed.contains(n),
      not(hasRecord(n)),
      recorded' = recorded.put(n, GARBAGE),
      bundles' = bundles,
      revealed' = revealed,
      paid' = paid,
      nextId' = nextId,
    }
  }

  action settle = all {
    bundles != Set(),
    nondet b = oneOf(bundles)
    all {
      valueOf(b.inputs) >= TARGET,
      b.inputs.forall(n => hasRecord(n) and recorded.get(n) == b.id),
      paid' = true,
      recorded' = recorded,
      bundles' = if (PRUNE_SETTLED) bundles.filter(x => x.id != b.id) else bundles,
      revealed' = revealed,
      nextId' = nextId,
    }
  }

  // A no-op, so the machine never runs out of enabled actions. Without it,
  // `noMerge` deadlocks at the initial state — no funding set exists, so nothing
  // is enabled — and Apalache reports that deadlock in place of the invariant
  // result, making a *safety* check look violated when it was never evaluated.
  // The deadlock is a real finding, but `paymentRemainsPossible` is where it
  // belongs; it must not masquerade as a safety failure.
  action stutter = all {
    recorded' = recorded,
    bundles' = bundles,
    revealed' = revealed,
    paid' = paid,
    nextId' = nextId,
  }

  action step = any { build, broadcast, publishReal, grief, settle, stutter }
}

// **A finding this model was not built to look for.** Merging available, no
// griefer, no adversary of any kind — and the payment can still become
// impossible. Alice builds two transfers over the same two notes (a rebuild
// after a failed broadcast is enough), and their records interleave: note 1's
// first occurrence names transfer 2, note 2's names transfer 1. Neither transfer
// can settle, because settling needs *every* input bound to itself. Both notes
// are consumed and nothing was paid.
//
// This matters because merging is the obvious fix for `noMerge` below, and it is
// not free: one record per nullifier means a multi-input transfer settles
// **non-atomically**, a failure single-input transfers cannot have — with one
// input, the record either lands or it does not. Adding merging therefore has to
// come with either atomic multi-input settlement or the wallet discipline in
// `atomic`.
//
// ---- The one module that stays a BOUNDED claim, and why ----
//
// Every other module here gained an all-depths proof on 2026-07-30. This one
// cannot have one: **no constructible domain exists for `nextId`.** With
// `ONE_LIVE_BUNDLE_PER_NOTE = false` the disjointness guard on `build` is
// vacuous, so while `recorded == Map()` the action never disables, and every
// firing mints a fresh id. No `K` bounds the counter, so no `typeOK` can pin it,
// so `--inductive-invariant` has nothing to start from.
//
// **Capping it in the model was considered and rejected.** Adding `nextId <= K`
// as a guard would make the domain finite and the induction possible. But this
// module's job is to *exhibit* a counterexample — `paymentRemainsPossible` must
// violate here — and bounding the state space of a module whose purpose is to
// produce a violating run risks bounding away the run that produces it. The
// unboundedness is not an artifact of the encoding either: **it IS the absence of
// the discipline.** A wallet with no one-live-bundle rule really can rebuild
// forever, and that is the point.
//
// So it keeps its depth-8 row. Stated here rather than left as a silence, the
// same way `formal/README.md` recorded linkage's three failed attempts before the
// ghost encoding was found — a recorded limit is a result; a quiet downgrade is
// not. `railInv` is additionally run against this module expecting a **violation**,
// which is a genuine falsification row: it says the all-depths liveness proof for
// `atomic` rests on the discipline this module drops.
module splitRecords {
  import rail(GRIEF_POSSIBLE = false, MAX_INPUTS = 2,
              ONE_LIVE_BUNDLE_PER_NOTE = false, PRUNE_SETTLED = false).*
}

// Merging plus the discipline: never two live transfers over one note. The
// baseline where the payment always remains possible.
module atomic {
  import rail(GRIEF_POSSIBLE = false, MAX_INPUTS = 2,
              ONE_LIVE_BUNDLE_PER_NOTE = true, PRUNE_SETTLED = false).*
}

// Liveness failure 1 — griefing, with the discipline in force so the violation
// is attributable to the griefer alone and not to the split above. Safety holds
// throughout; the money is destroyed anyway, by someone who gains nothing, with
// no recovery path.
module griefable {
  import rail(GRIEF_POSSIBLE = true, MAX_INPUTS = 2,
              ONE_LIVE_BUNDLE_PER_NOTE = true, PRUNE_SETTLED = false).*
}

// Liveness failure 2 — no proof merging. Alice holds 1 + 1 and owes 2, and one
// transfer spends one note. Expect the violation **at the initial state**: this
// is not a race that can be lost, it is a payment that can never be attempted.
module noMerge {
  import rail(GRIEF_POSSIBLE = false, MAX_INPUTS = 1,
              ONE_LIVE_BUNDLE_PER_NOTE = true, PRUNE_SETTLED = false).*
}

// **The retention rule removed — the only thing in this file that can make safety
// fail.** A settled transfer is garbage-collected while its first-occurrence
// records still name it, so `nobodyElseGetsPaid` reads as violated by a wallet
// that merely tidied up.
//
// This is not a hypothetical adversary; it is **the first attempt at this model**,
// recorded in `settle`'s comment as a mistake that produced a false safety
// violation. It is kept as a reproducing violation because the all-depths safety
// proof rests on `bundles` never shrinking, and no *protocol* constant here can
// break safety — the griefer is given no notes, no keys and no bundles, so it can
// destroy a payment but never redirect one. An all-depths result with nothing able
// to falsify it is a result about bookkeeping.
//
// Labelled honestly in `verify.sh` as a **model-soundness** pair rather than a
// protocol one: it says "the induction rests on retention", which is true and
// checkable, instead of pretending a protocol rule is missing.
module railPruned {
  import rail(GRIEF_POSSIBLE = false, MAX_INPUTS = 2,
              ONE_LIVE_BUNDLE_PER_NOTE = true, PRUNE_SETTLED = true).*
}

// ---------------------------------------------------------------------------
// The wallet's answer to `noMerge`: pay in several single-input transfers.
//
// `noMerge` violates `paymentRemainsPossible` at the *initial state* — Alice
// holds 1 + 1, owes 2, a transfer takes one input, so no funding set exists and
// nothing is even enabled. That is a real limitation of the circuit, and it is
// not going away soon.
//
// What the wallet does instead is send two payments that add up. This module
// exists because closing `[MERGE]` on the strength of an argument, while the
// `formal/` directory still contained a module saying the payment is
// impossible, is exactly the move this project does not make.
//
// The shape differs from `rail` in one way, and only one: a payment completes
// when the *sum* of settled transfers reaches the target, rather than when a
// single transfer worth the target settles. Everything else — first occurrence,
// the never-two-live-transfers discipline, griefing — is unchanged, because
// nothing else about the protocol changes.
//
// Run:
//   quint verify formal/baserail.qnt --main=splitPayment \
//     --invariant=paymentRemainsPossible --max-steps=8
//   quint verify formal/baserail.qnt --main=splitPayment \
//     --invariant=nobodyElseGetsPaid --max-steps=8
//   quint verify formal/baserail.qnt --main=splitGriefed \
//     --invariant=paymentRemainsPossible --max-steps=8
module split {
  // Same holding and same debt as `rail`: 1 + 1, owing 2.
  pure val NOTES = Set(1, 2)
  pure val VALUES: int -> int = Map(1 -> 1, 2 -> 1)
  pure val TARGET = 2
  pure val GARBAGE = -1

  const GRIEF_POSSIBLE: bool

  // Whether a settled transfer is dropped from `bundles`.
  //
  // **False is the rule, and this constant exists so the rule can be absent.**
  // `settle`'s own comment records pruning as a mistake that was actually made:
  // removing a settled bundle leaves its first-occurrence records naming a
  // transfer that no longer exists, which reads as a safety violation. It did, on
  // the first attempt.
  //
  // That history is the reason it is a constant now. The all-depths safety proofs
  // (`railSafetyInv`, `splitSafetyInv`) both rest on `bundles` never shrinking,
  // and nothing else in this file can make safety fail — third parties are given
  // no notes, no keys and no bundles, so no adversary constant can redirect a
  // record. Without a way to switch retention off, an all-depths safety result
  // would have nothing able to break it, which is the definition of a claim about
  // bookkeeping. `railPruned`/`splitPruned` are that switch.
  const PRUNE_SETTLED: bool

  type Bundle = { id: int, inputs: Set[int] }

  var recorded: int -> int
  var bundles: Set[Bundle]
  var revealed: Set[int]
  // How much has actually arrived, rather than whether one transfer landed.
  var delivered: int
  // Which parts have already been counted. A settled bundle stays in `bundles`
  // — removing it would leave its record pointing at a transfer that no longer
  // exists, which reads as a safety violation. (It did, on the first attempt.)
  var settledIds: Set[int]
  var nextId: int

  def valueOf(s: Set[int]): int = s.fold(0, (a, n) => a + VALUES.get(n))
  def hasRecord(n: int): bool = recorded.keys().contains(n)

  val paid: bool = delivered >= TARGET

  // A note can fund a further part-payment if nothing has bound it yet and no
  // live transfer already spends it — the same discipline `atomic` needs, and
  // the one the wallet's note-state store already enforces.
  def live: Set[Bundle] = bundles.filter(b => not(settledIds.contains(b.id)))

  def stillSpendable: Set[int] =
    NOTES.filter(n =>
      not(hasRecord(n)) and not(live.exists(b => b.inputs.contains(n))))

  // The liveness property, restated for a payment made of parts: what has
  // already arrived, plus what could still be sent, must reach the target.
  val paymentRemainsPossible: bool =
    paid or (delivered + valueOf(stillSpendable)
             + live.filter(b => b.inputs.forall(n =>
                 not(hasRecord(n)) or recorded.get(n) == b.id))
                   .fold(0, (a, b) => a + valueOf(b.inputs))) >= TARGET

  // Safety is unchanged and must stay that way: every first occurrence either
  // settles one of Alice's own transfers or destroys the note.
  val nobodyElseGetsPaid: bool =
    recorded.keys().forall(n =>
      recorded.get(n) == GARBAGE or bundles.exists(b => b.id == recorded.get(n)))

  action init = all {
    recorded' = Map(),
    bundles' = Set(),
    revealed' = Set(),
    delivered' = 0,
    settledIds' = Set(),
    nextId' = 1,
  }

  // One note, one transfer. The discipline is always on here: the wallet that
  // splits a payment is the same wallet that refuses two live transfers over
  // one note.
  action build = all {
    stillSpendable != Set(),
    nondet n = oneOf(stillSpendable)
    all {
      bundles' = bundles.union(Set({ id: nextId, inputs: Set(n) })),
      nextId' = nextId + 1,
      recorded' = recorded,
      revealed' = revealed,
      delivered' = delivered,
      settledIds' = settledIds,
    }
  }

  action broadcast = all {
    bundles != Set(),
    nondet b = oneOf(bundles)
    all {
      revealed' = revealed.union(b.inputs),
      recorded' = recorded,
      bundles' = bundles,
      delivered' = delivered,
      settledIds' = settledIds,
      nextId' = nextId,
    }
  }

  // First occurrence, honest.
  action record = all {
    bundles != Set(),
    nondet b = oneOf(bundles)
    all {
      b.inputs.exists(n => not(hasRecord(n))),
      recorded' = b.inputs.fold(recorded, (m, n) =>
        if (m.keys().contains(n)) m else m.put(n, b.id)),
      bundles' = bundles,
      revealed' = revealed,
      delivered' = delivered,
      settledIds' = settledIds,
      nextId' = nextId,
    }
  }

  // A mempool watcher burns a revealed nullifier. Only enabled when the
  // griefing residue is in scope.
  action grief = all {
    GRIEF_POSSIBLE,
    revealed.exists(n => not(hasRecord(n))),
    nondet n = oneOf(revealed.filter(n => not(hasRecord(n))))
    all {
      recorded' = recorded.put(n, GARBAGE),
      bundles' = bundles,
      revealed' = revealed,
      delivered' = delivered,
      settledIds' = settledIds,
      nextId' = nextId,
    }
  }

  // A part arrives. Single-input, so this is just "my one record won" — there
  // is no conjunction across records to interleave, which is precisely why the
  // `splitRecords` deadlock cannot occur here.
  action settle = all {
    live != Set(),
    nondet b = oneOf(live)
    all {
      b.inputs.forall(n => hasRecord(n) and recorded.get(n) == b.id),
      delivered' = delivered + valueOf(b.inputs),
      settledIds' = settledIds.union(Set(b.id)),
      bundles' = if (PRUNE_SETTLED) bundles.filter(x => x.id != b.id) else bundles,
      recorded' = recorded,
      revealed' = revealed,
      nextId' = nextId,
    }
  }

  action stutter = all {
    recorded' = recorded, bundles' = bundles, revealed' = revealed,
    delivered' = delivered, settledIds' = settledIds, nextId' = nextId,
  }

  action step = any { build, broadcast, record, grief, settle, stutter }

  // ---- The inductive strengthening: the split's claims at ALL DEPTHS ----
  //
  //   quint verify formal/baserail.qnt --main=splitPayment \
  //     --inductive-invariant=splitInv --invariant=paymentRemainsPossible
  //
  // One transfer per note and one note per transfer, so the whole space is two
  // ids, two notes and a running total in 0..TARGET. That is why this induction
  // is cheap where an induction over merged transfers would not be.
  pure val IDS: Set[int] = 1.to(2)
  pure val HASHES: Set[int] = IDS.union(Set(GARBAGE))
  pure val BUNDLE_UNIVERSE: Set[Bundle] =
    tuples(IDS, NOTES.powerset()).map(((i, s)) => { id: i, inputs: s })

  val typeOK: bool =
    NOTES.powerset().exists(d => recorded.in(d.setOfMaps(HASHES)))
      and bundles.in(BUNDLE_UNIVERSE.powerset())
      and revealed.in(NOTES.powerset())
      and settledIds.in(IDS.powerset())
      // Alice holds 1 + 1, so nothing can ever arrive beyond TARGET. The bound
      // is tight on purpose and it leans on `deliveredCountsSettled` below to
      // keep `settle` inside it.
      and delivered.in(0.to(TARGET))
      and nextId.in(1.to(3))

  val uniqueIds: bool =
    bundles.forall(a => bundles.forall(b => (a.id == b.id) implies (a == b)))
  val freshIds: bool = bundles.forall(b => b.id < nextId)
  // Same domain-closure role as `rail`'s: without it the induction may start at
  // the top of `nextId`'s range holding no bundles, fire `build`, and step out
  // of the domain. See that conjunct's comment for the counterexample.
  val counterCountsBundles: bool = nextId == bundles.size() + 1

  // One note, one transfer — the shape that makes a split work, and the reason
  // `splitRecords`' interleaving cannot arise here: a single-input transfer has
  // no conjunction across records to lose.
  val singletonInputs: bool =
    bundles.forall(b => b.inputs.subseteq(NOTES) and b.inputs.size() == 1)

  // The never-two-live-transfers discipline, as a fact about the state rather
  // than a precondition. `build` draws from `stillSpendable`, which excludes any
  // note a live transfer spends; a settled transfer's notes are bound, so they
  // are excluded too. No note is ever spent twice.
  val disjointInputs: bool =
    bundles.forall(a =>
      bundles.forall(b =>
        (a.id != b.id) implies (a.inputs.intersect(b.inputs) == Set())))

  // A settled id names a transfer that still exists. `settle` deliberately does
  // NOT prune `bundles` — see its comment, where pruning once produced a false
  // safety violation — and the induction needs that retention stated, because an
  // arbitrary state is otherwise free to have settled something absent.
  val settledAreReal: bool =
    settledIds.forall(i => bundles.exists(b => b.id == i))

  // A settled transfer won every one of its nullifiers at first occurrence:
  // `settle`'s own guard, carried into the induction. Without it an arbitrary
  // state counts a part as delivered whose note is bound elsewhere, and
  // `delivered` stops meaning what arrived.
  val settledAreRecorded: bool =
    bundles.forall(b =>
      settledIds.contains(b.id) implies
        b.inputs.forall(n => hasRecord(n) and recorded.get(n) == b.id))

  // **The accounting clause, and the load-bearing one.** `delivered` is EXACTLY
  // the value of the notes that settled — not at most. Without it the induction
  // begins either with `delivered = 0` beside two settled transfers, concluding
  // the payment is dead, or with `delivered = TARGET` beside a live settleable
  // transfer, stepping past the domain bound.
  //
  // Folded over `NOTES` rather than over `bundles`, deliberately: the fold
  // domain is then a constant and the solver never enumerates subsets of a state
  // variable. Addition is order-independent, so the order-dependent-fold trap
  // `reorg.qnt` records does not apply.
  val deliveredCountsSettled: bool =
    delivered == NOTES.fold(0, (a, n) =>
      if (bundles.exists(b => settledIds.contains(b.id) and b.inputs.contains(n)))
        a + VALUES.get(n)
      else a)

  val recordsMatchTheirBundle: bool =
    recorded.keys().forall(n =>
      recorded.get(n) == GARBAGE
        or bundles.exists(b => b.id == recorded.get(n) and b.inputs.contains(n)))

  // Safety at all depths, expected to hold under BOTH `splitPayment` and
  // `splitGriefed`: a burnt note is bound to GARBAGE and to nobody, so safety
  // survives the residue that liveness does not. That asymmetry is the file's
  // thesis, now stated with no step bound.
  val splitSafetyInv: bool =
    typeOK and uniqueIds and freshIds and counterCountsBundles
      and singletonInputs and disjointInputs
      and settledAreReal and settledAreRecorded and deliveredCountsSettled
      and recordsMatchTheirBundle

  // Liveness at all depths, expected under `splitPayment` ONLY. Every note is in
  // exactly one of three states — still spendable, spent by a transfer that can
  // still win, or already delivered — and each contributes its value, so the
  // parts always still reach the target. `splitGriefed` breaks it, because
  // `grief` moves a note into a fourth state contributing nothing and no wallet
  // action moves it back. That is the griefing residue, depth-free.
  val splitInv: bool = splitSafetyInv and paymentRemainsPossible

  // ---- Anti-vacuity, run as rows expecting a VIOLATION ----
  //
  // `paymentRemainsPossible` here is a three-term sum, and the middle term —
  // live transfers that can still win — is the only one the hard conjuncts
  // serve. If what has arrived plus what is loose in the wallet always reached
  // the target on its own, `settledAreRecorded`, `disjointInputs` and
  // `deliveredCountsSettled` would all be idle.
  val fullyFundedFromNotes: bool =
    paid or (delivered + valueOf(stillSpendable)) >= TARGET

  // **The sharpest one in this module.** A state must exist where a part has
  // arrived and the payment is not yet complete. If this row ever stops failing,
  // `split` has stopped modelling a SPLIT — it is modelling one atomic payment
  // under another name, and everything above about parts adding up is a claim
  // about a sum with one term. `CLAIMS.md` L4 rests on this.
  val deliveryIsAllOrNothing: bool = delivered == 0 or delivered >= TARGET
}

// The wallet's split, with no adversary: the payment always remains possible,
// which is exactly what `noMerge` violates at its initial state.
module splitPayment {
  import split(GRIEF_POSSIBLE = false, PRUNE_SETTLED = false).*
}

// The split under the accepted griefing residue. Safety must still hold; the
// payment can still be made impossible, because a burnt note is a burnt note —
// but only one part is lost, where a merged transfer would lose every input.
module splitGriefed {
  import split(GRIEF_POSSIBLE = true, PRUNE_SETTLED = false).*
}

// The same retention rule removed on the split side. A part-payment settles, its
// transfer is dropped, and the record naming it now points at nothing.
module splitPruned {
  import split(GRIEF_POSSIBLE = false, PRUNE_SETTLED = true).*
}

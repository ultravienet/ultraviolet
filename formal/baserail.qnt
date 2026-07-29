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
// used here for the same reason the since-removed channels model used it: a
// bounded "paid by step K" invariant would report the simulator's choices
// rather than the protocol's.
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
// Run (safety — expected to hold everywhere):
//   quint verify formal/baserail.qnt --main=griefable --invariant=nobodyElseGetsPaid --max-steps=8
// Run (liveness):
//   quint verify formal/baserail.qnt --main=ideal     --invariant=paymentRemainsPossible --max-steps=8
//   quint verify formal/baserail.qnt --main=griefable --invariant=paymentRemainsPossible --max-steps=8
//   quint verify formal/baserail.qnt --main=noMerge   --invariant=paymentRemainsPossible --max-steps=8

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
      bundles' = bundles,
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
module splitRecords {
  import rail(GRIEF_POSSIBLE = false, MAX_INPUTS = 2,
              ONE_LIVE_BUNDLE_PER_NOTE = false).*
}

// Merging plus the discipline: never two live transfers over one note. The
// baseline where the payment always remains possible.
module atomic {
  import rail(GRIEF_POSSIBLE = false, MAX_INPUTS = 2,
              ONE_LIVE_BUNDLE_PER_NOTE = true).*
}

// Liveness failure 1 — griefing, with the discipline in force so the violation
// is attributable to the griefer alone and not to the split above. Safety holds
// throughout; the money is destroyed anyway, by someone who gains nothing, with
// no recovery path.
module griefable {
  import rail(GRIEF_POSSIBLE = true, MAX_INPUTS = 2,
              ONE_LIVE_BUNDLE_PER_NOTE = true).*
}

// Liveness failure 2 — no proof merging. Alice holds 1 + 1 and owes 2, and one
// transfer spends one note. Expect the violation **at the initial state**: this
// is not a race that can be lost, it is a payment that can never be attempted.
module noMerge {
  import rail(GRIEF_POSSIBLE = false, MAX_INPUTS = 1,
              ONE_LIVE_BUNDLE_PER_NOTE = true).*
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
      bundles' = bundles,
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
}

// The wallet's split, with no adversary: the payment always remains possible,
// which is exactly what `noMerge` violates at its initial state.
module splitPayment {
  import split(GRIEF_POSSIBLE = false).*
}

// The split under the accepted griefing residue. Safety must still hold; the
// payment can still be made impossible, because a burnt note is a burnt note —
// but only one part is lost, where a merged transfer would lose every input.
module splitGriefed {
  import split(GRIEF_POSSIBLE = true).*
}

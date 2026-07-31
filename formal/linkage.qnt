// Ultraviolet — does linkage still hold once it leaves the circuit?
//
// Linkage is the rule that a transfer may only spend notes its own ancestry
// created. It is not in the circuit, and that is the whole reason this model
// exists.
//
// The STARK has no in-circuit recursion. Each hop gets its own small
// proof attesting only its own transition, and the receiver verifies k of them
// and checks linkage themselves — `wallet2/src/accept.rs`, which walks every
// hop. That moves linkage from *enforced by the proof* to *the receiver does
// it* — exactly the shape that produced the supply-inflation bug in
// `multihop.qnt`, where per-hop settlement checks failed to compose.
//
// This model asked that question of linkage *before* the code existed; the
// code now exists and follows the `checked` module's shape.
//
// What is modelled: hops, the notes they consume and produce, per-hop proofs, and
// a receiver's accept decision.
// What is assumed sound: the proofs themselves. A verifying proof means "this
// transition was well-formed and authorized" — nothing about its ancestors.
// What the adversary controls: which hops exist, **the hop sequence presented to
// a receiver**, and — the crucial one — the ability to build a hop consuming a
// note **that was never created**. A non-recursive proof attests "this transition
// consumed a note with commitment X"; it says nothing about whether X ever
// existed. In-circuit recursion made that impossible, because the previous
// proof had to exist and list X among its outputs. Off-circuit, it is only
// impossible if the receiver checks.
//
// (The first draft of this model let hops consume only notes their builder
// actually held, which made every ancestry well-formed by construction and both
// modules pass. That was the same error `multihop.qnt` made with ancestry —
// handing the system for free the very thing under test.)
//
// Run:
//   quint verify formal/linkage.qnt --main=unchecked --invariant=noSplicedHistory --max-steps=8
//   quint verify formal/linkage.qnt --main=checked   --invariant=noSplicedHistory --max-steps=8

module protocol {
  // When false, the receiver verifies every proof but never checks that the hops
  // actually link — the failure mode the rewrite makes possible.
  const CHECK_LINKAGE: bool

  pure val HONEST = Set("carol", "dave")
  pure val ATTACKER = Set("mallory", "mallory2")
  pure val WALLETS = HONEST.union(ATTACKER)
  pure val MAX_HOP = 4

  // A hop spends note `input` and creates note `id`, paying `to`. Its proof
  // attests this and only this.
  type Hop = { id: int, input: int, to: str }

  var hops: Set[Hop]
  // Notes each wallet holds as spendable.
  var held: str -> Set[int]
  // Note 0 is issued; every other note exists only if some hop created it.
  var nextNote: int
  // What honest receivers accepted, with the chain they were shown.
  var accepted: Set[int]

  // GHOST STATE — carries no runtime meaning. The set of notes that descend
  // from the genesis note, maintained one hop at a time as hops are created.
  // Nothing in the protocol computes this; it exists so the safety property can
  // be stated as a set membership instead of a search back through the ancestry.
  // See `linkInv` for why that matters and what it costs.
  var descends: Set[int]

  def hopOf(n: int): Set[Hop] = hops.filter(h => h.id == n)

  // A presented chain, as up to three hops oldest-first plus a length. Written
  // as explicit cases rather than a list because Apalache rejects dynamic ranges
  // over `Len(list)` (a documented limitation) — and chains here are short enough
  // that the case analysis is clearer anyway.
  //
  // `linksUp` is the check the circuit used to perform: the oldest hop must
  // consume the genesis note, and every later hop must consume the note the hop
  // before it produced.
  def linksUp(a: Hop, b: Hop, h: Hop, len: int): bool =
    if (len == 1) h.input == 0
    else if (len == 2) a.input == 0 and h.input == a.id
    else a.input == 0 and b.input == a.id and h.input == b.id

  // Every presented hop is real, i.e. carries a verifying proof.
  def allProven(a: Hop, b: Hop, h: Hop, len: int): bool =
    if (len == 1) hops.contains(h)
    else if (len == 2) hops.contains(a) and hops.contains(h)
    else hops.contains(a) and hops.contains(b) and hops.contains(h)

  def accepts(a: Hop, b: Hop, h: Hop, len: int): bool =
    if (CHECK_LINKAGE) allProven(a, b, h, len) and linksUp(a, b, h, len)
    else allProven(a, b, h, len)

  // ---- The property (safety) ----
  // Every accepted note has a genuinely linked ancestry back to issuance.
  def trulyDescends(n: int): bool =
    // Walk the real hop graph: n's creating hop, its input's creating hop, ...
    // Bounded unrolling to MAX_HOP, which is enough for the model's depth.
    hopOf(n).exists(h1 =>
      h1.input == 0 or
      hopOf(h1.input).exists(h2 =>
        h2.input == 0 or
        hopOf(h2.input).exists(h3 =>
          h3.input == 0 or
          hopOf(h3.input).exists(h4 => h4.input == 0))))

  val noSplicedHistory: bool = accepted.forall(n => trulyDescends(n))

  // The same property said through the ghost. Deliberately kept as a SECOND
  // property rather than a redefinition of the first, so that `unchecked` is
  // run against both: a ghost formulation that stopped catching the attack
  // would be worthless, and the only way to know is to point it at the attack.
  val noSplicedHistoryG: bool = accepted.subseteq(descends)

  action init = all {
    hops' = Set(),
    held' = WALLETS.mapBy(w => if (w == "mallory") Set(0) else Set()),
    nextNote' = 1,
    accepted' = Set(),
    descends' = Set(0),
  }

  // Build a hop spending a note you hold. Unilateral: nothing stops an owner
  // building several from one note.
  action buildHop = all {
    nextNote <= MAX_HOP,
    nondet from = oneOf(WALLETS)
    nondet dest = oneOf(WALLETS)
    nondet n = oneOf(held.get(from).union(Set(0)))
    all {
      held.get(from).contains(n),
      hops' = hops.union(Set({ id: nextNote, input: n, to: dest })),
      nextNote' = nextNote + 1,
      held' = held,
      accepted' = accepted,
      // The ghost's whole definition: a new note descends exactly when the note
      // it spends does. One step, no lookback.
      descends' =
        if (descends.contains(n)) descends.union(Set(nextNote)) else descends,
    }
  }

  // An attacker's own wallet takes any proven note without checking anything.
  action takeAttacker = all {
    nondet h = oneOf(hops)
    all {
      ATTACKER.contains(h.to),
      held' = held.set(h.to, held.get(h.to).union(Set(h.id))),
      hops' = hops,
      nextNote' = nextNote,
      accepted' = accepted,
      descends' = descends,
    }
  }

  // An honest receiver is shown SOME chain by the sender and runs its checks.
  // The chain is adversarial input: any sequence of up to 3 real hops.
  action receiveHonest = all {
    nondet h = oneOf(hops)
    nondet a = oneOf(hops)
    nondet b = oneOf(hops)
    nondet len = oneOf(Set(1, 2, 3))
    all {
      HONEST.contains(h.to),
      accepts(a, b, h, len),
      held' = held.set(h.to, held.get(h.to).union(Set(h.id))),
      accepted' = accepted.union(Set(h.id)),
      hops' = hops,
      nextNote' = nextNote,
      // Receiving does not create a hop, so it cannot make a note descend. If
      // the accepted note is not already in the ghost, the property breaks here
      // — which is the point.
      descends' = descends,
    }
  }

  // The linkage attack: build a hop consuming a note NOBODY created. The
  // transition is internally valid and its proof verifies; the note it spends is
  // fiction. This is what in-circuit recursion used to make unrepresentable.
  //
  // (The fictional note used to be called `ghost` here. Renamed to `fiction`
  // when a ghost *variable* arrived, because two unrelated meanings of "ghost"
  // in one model is how a reader mistakes the attack for bookkeeping.)
  //
  // `fiction` starts at MAX_HOP + 1, i.e. strictly above every id the build
  // counter can hand out. It used to start AT MAX_HOP, which overlapped the
  // last creatable note, so some "fabricated" hops were quietly spending a real
  // note and were not attacks at all. Moving it up sharpens the attack and buys
  // `inputsAreOlder` below, which needs fiction to be distinguishable from a
  // real note by its number alone.
  action fabricateHop = all {
    nextNote <= MAX_HOP,
    nondet dest = oneOf(WALLETS)
    nondet fiction = oneOf((MAX_HOP + 1).to(MAX_HOP + 3))
    all {
      hops' = hops.union(Set({ id: nextNote, input: fiction, to: dest })),
      nextNote' = nextNote + 1,
      held' = held,
      accepted' = accepted,
      // Fiction never descends, so neither does anything spending it.
      descends' = descends,
    }
  }

  action step = any { buildHop, fabricateHop, takeAttacker, receiveHonest }

  // ---- The inductive strengthening: the property at ALL depths ----
  //
  // Domain constraints, required by inductive checking (see multihop.qnt):
  // the induction step starts from an arbitrary state satisfying the
  // invariant, so every variable needs a constructible domain. Hops draw ids
  // from the build counter's range and inputs from notes ∪ ghosts.
  val HOP_UNIVERSE: Set[Hop] =
    tuples(1.to(MAX_HOP), 0.to(MAX_HOP + 3), WALLETS)
      .map(((i, n, w)) => { id: i, input: n, to: w })

  val typeOK: bool =
    hops.in(HOP_UNIVERSE.powerset())
      and held.in(WALLETS.setOfMaps(0.to(MAX_HOP).powerset()))
      and accepted.in(1.to(MAX_HOP).powerset())
      and nextNote.in(1.to(MAX_HOP + 1))
      // The ghost never contains fiction. This is a domain constraint, not a
      // claim: fiction is numbered above MAX_HOP precisely so that this bound
      // rules it out arithmetically.
      and descends.in(0.to(MAX_HOP).powerset())
      // The genesis note descends from itself. Obvious from `init` and NOT
      // obtainable from it — induction starts from an arbitrary state, and a
      // ghost that had lost its base case would make `ghostClosed` conclude
      // nothing and the step would fail with no hint as to why.
      and descends.contains(0)

  // Ids are handed out in order by one counter, so each id names at most one
  // hop. Not a property anyone relies on at runtime — it exists to make the
  // induction *checkable*: with it, `trulyDescends`' nested existentials stop
  // being a search over every combination of hops and collapse to walking the
  // one chain each id admits. Without it the SMT instance exhausted a 4 GB
  // heap and then thrashed a 16 GB machine.
  val uniqueIds: bool =
    hops.forall(h1 => hops.forall(h2 => (h1.id == h2.id) implies (h1 == h2)))
  val freshIds: bool = hops.forall(h => h.id < nextNote)

  // A wallet only ever holds the genesis note or a note some hop created. With
  // `freshIds` this is what bounds a spent note below the id being handed out,
  // which is what `inputsAreOlder` needs from `buildHop`.
  val heldAreCreated: bool =
    WALLETS.forall(w =>
      held.get(w).forall(n => n == 0 or hops.exists(h => h.id == n)))

  // ---- The three invariants that carry the ghost ----
  //
  // 1. CLOSURE. Anything a hop can reach from a descending note is itself in the
  //    ghost. This is the one that does the work: it is what lets an honest
  //    receiver's presented chain — up to three hops, each checked to link —
  //    conclude membership by three one-step implications instead of a search.
  val ghostClosed: bool =
    hops.forall(h => h.input.in(descends) implies h.id.in(descends))

  // 2. LOCAL WITNESS. Every member of the ghost other than the genesis has a
  //    REAL hop that created it from another member. This is the invariant that
  //    stops the exercise from being circular. Without it the ghost could name
  //    any set at all and closure would still hold, and the all-depths result
  //    would be a result about bookkeeping. With it, membership is backed by
  //    hops that actually exist in `hops`.
  val ghostWitnessed: bool =
    descends.forall(n =>
      n == 0 or hopOf(n).exists(h => h.input.in(descends)))

  // 3. DESCENT MEASURE. A hop either spends the genesis, or spends a
  //    strictly-lower-numbered note, or spends fiction (numbered above every
  //    creatable note). Ids come from one increasing counter, so this holds by
  //    construction — and it is what makes the witness chain in (2) finite.
  val inputsAreOlder: bool =
    hops.forall(h => h.input == 0 or h.input < h.id or h.input > MAX_HOP)

  // Inductive under `checked`:
  //
  //   quint verify formal/linkage.qnt --main=checked \
  //     --inductive-invariant=linkInv --invariant=noSplicedHistoryG
  //
  // WHAT THIS PROVES, EXACTLY — because the distinction is the whole point.
  //
  // Machine-checked at all depths: no note is ever accepted unless it is in the
  // ghost, and the ghost is closed (1), witnessed by real hops (2), and
  // numbered downward (3).
  //
  // Discharged by hand, once, here: (2) gives every member a real creating hop
  // whose input is also a member; (3) makes that input strictly smaller
  // whenever it is a real note, and `typeOK` keeps every member inside
  // 0..MAX_HOP so it can never be fiction. A strictly decreasing sequence of
  // naturals bounded below terminates, and (2) permits termination only at 0.
  // So every member of the ghost genuinely descends from the genesis note, and
  // `noSplicedHistoryG` implies `noSplicedHistory`.
  //
  // That last step is arithmetic well-foundedness, which is exactly the shape of
  // reasoning an inductive invariant cannot express about its own state — it is
  // a statement about the *chain* of states a member's history implies, not
  // about any one state. It is stated rather than hidden, and it is also checked
  // by machine at bounded depth by `ghostFaithful` below, so a mistake in the
  // encoding shows up as a counterexample rather than as a comfortable comment.
  val linkInv: bool =
    typeOK and uniqueIds and freshIds and heldAreCreated
      and ghostClosed and ghostWitnessed and inputsAreOlder
      and noSplicedHistoryG

  // The tie between the ghost and the real hop graph, checked directly rather
  // than argued: the ghost holds exactly the notes that walk back to the
  // genesis. Bounded — but bounded on a property with no nested search on the
  // ghost side, so it is cheap where `noSplicedHistory` alone was not. If the
  // ghost ever drifts from the ancestry it is meant to shadow, this row fails.
  val ghostFaithful: bool =
    0.to(MAX_HOP).forall(n =>
      descends.contains(n) iff (n == 0 or trulyDescends(n)))

  // Anti-vacuity, run as a row expecting a VIOLATION. `accepted.subseteq(...)`
  // is free if `accepted` is always empty, and "always empty" is what a model
  // with an over-tight receive guard silently becomes. Stating it this way — an
  // honest receiver accepts a note whose creating hop spends something OTHER
  // than the genesis — demands more than that receipt happens: it demands the
  // linkage rule be exercised on a chain at least two hops long, which is the
  // only place `linksUp` can differ from `allProven`. A model where this row
  // stopped failing would be one where the all-depths result had quietly become
  // a statement about the empty set.
  val onlyGenesisChildrenAccepted: bool =
    accepted.forall(n => hopOf(n).forall(h => h.input == 0))
}

// The rewrite's hazard: k proofs verified, linkage never checked.
module unchecked {
  import protocol(CHECK_LINKAGE = false).*
}

// Linkage checked off-circuit by the receiver, as the rewrite must do.
module checked {
  import protocol(CHECK_LINKAGE = true).*
}

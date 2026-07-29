// Ultraviolet — does linkage still hold once it leaves the circuit?
//
// In the zkVM design, `check_linkage` ran INSIDE the SP1 guest: each hop's
// proof verified the previous hop's proof and checked that this transfer only
// spent notes that hop created. A receiver could not skip it, because without
// it the proof would not exist. That guest was deleted with the zkVM
// (2026-07-26).
//
// The sovereign STARK has no in-circuit recursion. Each hop gets its own small
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

  action init = all {
    hops' = Set(),
    held' = WALLETS.mapBy(w => if (w == "mallory") Set(0) else Set()),
    nextNote' = 1,
    accepted' = Set(),
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
    }
  }

  // The linkage attack: build a hop consuming a note NOBODY created. The
  // transition is internally valid and its proof verifies; the note it spends is
  // fiction. This is what in-circuit recursion used to make unrepresentable.
  action fabricateHop = all {
    nextNote <= MAX_HOP,
    nondet dest = oneOf(WALLETS)
    nondet ghost = oneOf(MAX_HOP.to(MAX_HOP + 2))
    all {
      hops' = hops.union(Set({ id: nextNote, input: ghost, to: dest })),
      nextNote' = nextNote + 1,
      held' = held,
      accepted' = accepted,
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
    tuples(1.to(MAX_HOP), 0.to(MAX_HOP + 2), WALLETS)
      .map(((i, n, w)) => { id: i, input: n, to: w })

  val typeOK: bool =
    hops.in(HOP_UNIVERSE.powerset())
      and held.in(WALLETS.setOfMaps(0.to(MAX_HOP).powerset()))
      and accepted.in(1.to(MAX_HOP).powerset())
      and nextNote.in(1.to(MAX_HOP + 1))

  // Ids are handed out in order by one counter, so each id names at most one
  // hop. Not a property anyone relies on at runtime — it exists to make the
  // induction *checkable*: with it, `trulyDescends`' nested existentials stop
  // being a search over every combination of hops and collapse to walking the
  // one chain each id admits. Without it the SMT instance exhausted a 4 GB
  // heap and then thrashed a 16 GB machine.
  val uniqueIds: bool =
    hops.forall(h1 => hops.forall(h2 => (h1.id == h2.id) implies (h1 == h2)))
  val freshIds: bool = hops.forall(h => h.id < nextNote)

  // Inductive under `checked`, and the reason is the argument itself: an
  // honest receiver only accepts behind a presented chain whose hops are all
  // REAL and which links back to the genesis — so the presented chain is a
  // witness that the note truly descends, and adding hops can never un-descend
  // a note (`trulyDescends` is an exists over a growing set). Proving it
  // upgrades the linkage claim from bounded to all depths:
  //
  //   quint verify formal/linkage.qnt --main=checked \
  //     --inductive-invariant=linkInv --invariant=noSplicedHistory
  val linkInv: bool = typeOK and uniqueIds and freshIds and noSplicedHistory
}

// The rewrite's hazard: k proofs verified, linkage never checked.
module unchecked {
  import protocol(CHECK_LINKAGE = false).*
}

// Linkage checked off-circuit by the receiver, as the rewrite must do.
module checked {
  import protocol(CHECK_LINKAGE = true).*
}

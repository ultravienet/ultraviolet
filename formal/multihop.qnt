// Ultraviolet — multi-hop validity under first-occurrence records.
//
// The question this model answers: is checking first-occurrence *at your own
// hop* enough to keep supply conserved, or does safety require checking the
// whole ancestry?
//
// The protocol layer only. Hashes, signatures, and the recursive STARK are
// assumed sound and are not modelled: a bundle here is always well-formed and
// authorized, exactly as a verifying proof attests. What the proof does *not*
// attest — and what this model is about — is whether the ancestors' records
// won their races.
//
// Abstractions, stated so they can be argued with:
//   - One note per transfer (no splitting). Supply is "how many live notes".
//   - `recorded` is the confirmed chain, and first-occurrence-wins is baked in
//     as put-if-absent, matching the `Chain::publish` contract. The mempool
//     race is a separate concern and is deliberately not modelled here.
//   - A note's nullifier is its own id: deterministic in (note, owner), so one
//     note has exactly one nullifier however many bundles are built from it.
//     That is audit #13 A2, and it is what makes the race well-defined.
//
// Run:
//   quint run formal/multihop.qnt --main=buggy --invariant=noInflation
//   quint run formal/multihop.qnt --main=fixed --invariant=noInflation

module protocol {
  // When false, a receiver checks first-occurrence for its own hop only —
  // what the wallet did when this model was written, and what this model
  // proved insufficient. When true, it checks every ancestor — what
  // `wallet2/src/accept.rs` does now, with this model as the reason.
  const CHECK_ANCESTORS: bool

  pure val HONEST = Set("carol", "dave")
  pure val ATTACKER = Set("mallory", "mallory2")
  pure val WALLETS = HONEST.union(ATTACKER)
  pure val NOTE_IDS = 0.to(4)

  // A bundle spends note `input` and creates note `id`, paying `to`.
  // The nullifier of this hop is `input` (see abstractions above).
  type Bundle = { id: int, input: int, to: str }

  // A step in a note's ancestry: "nullifier `nf` was spent by bundle `bundle`".
  type Hop = { nf: int, bundle: int }

  // --- State ---

  // Bitcoin. nullifier -> the bundle that owns it. First occurrence wins:
  // once a key is set it never changes.
  var recorded: int -> int
  // Every bundle ever constructed. Building one is free and unilateral —
  // nothing stops an owner building two spends of the same note.
  var bundles: Set[Bundle]
  // wallet -> note ids it has accepted as spendable.
  var held: str -> Set[int]
  // note id -> its full ancestry. This is the data a receiver would need to
  // check ancestors — and precisely the data no bundle carries today.
  var lineage: int -> Set[Hop]
  var nextNote: int

  // --- Helpers ---

  def hasRecord(nf: int): bool = recorded.keys().contains(nf)

  // A note is spent once its nullifier has a first occurrence on chain.
  def isSpent(n: int): bool = hasRecord(n)

  // What a receiver checks about this hop: the chain's first occurrence for
  // my input's nullifier must be *this* bundle. A double-spend loses here.
  def hopWins(b: Bundle): bool = hasRecord(b.input) and recorded.get(b.input) == b.id

  // The stronger property: every hop in the ancestry won its race.
  def ancestryWins(b: Bundle): bool =
    lineage.get(b.id).forall(h => hasRecord(h.nf) and recorded.get(h.nf) == h.bundle)

  def accepts(b: Bundle): bool =
    if (CHECK_ANCESTORS) ancestryWins(b) else hopWins(b)

  // Honest wallets' live holdings. Genesis issued exactly one note, and every
  // transfer moves a whole note, so honest parties should never collectively
  // hold more than one live note.
  val honestLive: Set[int] =
    HONEST.fold(Set(), (acc, w) => acc.union(held.get(w).filter(n => not(isSpent(n)))))

  // --- The invariant ---
  val noInflation: bool = honestLive.size() <= 1

  // --- Init ---
  action init = all {
    // Genesis: note 0 is issued to mallory. Its lineage is empty.
    recorded' = Map(),
    bundles' = Set(),
    held' = WALLETS.mapBy(w => if (w == "mallory") Set(0) else Set()),
    lineage' = NOTE_IDS.mapBy(_ => Set()),
    nextNote' = 1,
  }

  // --- Actions ---

  // Build a spend of a note you hold. Unilateral and unlimited: an owner may
  // build two bundles from one note, which is the whole point.
  action buildBundle = all {
    nextNote < 5,
    nondet from = oneOf(WALLETS)
    nondet dest = oneOf(WALLETS)
    nondet n = oneOf(held.get(from).union(Set(0)))
    all {
      held.get(from).contains(n),
      bundles' = bundles.union(Set({ id: nextNote, input: n, to: dest })),
      lineage' = lineage.set(nextNote, lineage.get(n).union(Set({ nf: n, bundle: nextNote }))),
      nextNote' = nextNote + 1,
      recorded' = recorded,
      held' = held,
    }
  }

  // Publish a bundle's 64-byte record. Keyless: anyone may publish any record,
  // and the first one for a nullifier is the one that counts.
  action publishRecord = all {
    nondet b = oneOf(bundles)
    all {
      not(hasRecord(b.input)),
      recorded' = recorded.put(b.input, b.id),
      bundles' = bundles,
      held' = held,
      lineage' = lineage,
      nextNote' = nextNote,
    }
  }

  // An honest wallet receives: verify the proof (assumed sound), confirm the
  // note is mine, then run the first-occurrence check.
  action receiveHonest = all {
    nondet b = oneOf(bundles)
    all {
      HONEST.contains(b.to),
      accepts(b),
      held' = held.set(b.to, held.get(b.to).union(Set(b.id))),
      recorded' = recorded,
      bundles' = bundles,
      lineage' = lineage,
      nextNote' = nextNote,
    }
  }

  // An attacker's own wallet takes a note without checking anything. This
  // costs the attacker nothing and breaks no rule anyone can observe.
  action receiveAttacker = all {
    nondet b = oneOf(bundles)
    all {
      ATTACKER.contains(b.to),
      held' = held.set(b.to, held.get(b.to).union(Set(b.id))),
      recorded' = recorded,
      bundles' = bundles,
      lineage' = lineage,
      nextNote' = nextNote,
    }
  }

  action step = any {
    buildBundle,
    publishRecord,
    receiveHonest,
    receiveAttacker,
  }
}

// What the code does today: each receiver checks its own hop.
module buggy {
  import protocol(CHECK_ANCESTORS = false).*
}

// Checking the ancestry, but trusting the sender's copy of it. This is the
// version that looks correct and is not: see `bound` below.
module fixed {
  import protocol(CHECK_ANCESTORS = true).*
}

// ---------------------------------------------------------------------------
// The blind spot, and the fix for it.
//
// `protocol` above models `lineage` as trusted system state — the model hands
// each note its true ancestry. Reality does not: the ancestry arrives FROM THE
// SENDER, so it is adversarial input. That modelling choice assumed away a
// whole attack, and the model would have certified the buggy code as correct.
//
// Here the adversary chooses which ancestry to present. The only thing standing
// between that and inflation is the digest binding: an ancestry must reproduce
// the history digest the verified proof committed to.
// ---------------------------------------------------------------------------
module adversarial {
  const BIND: bool

  pure val HONEST = Set("carol", "dave")
  pure val ATTACKER = Set("mallory", "mallory2")
  pure val WALLETS = HONEST.union(ATTACKER)
  pure val NOTE_IDS = 0.to(4)

  type Bundle = { id: int, input: int, to: str }
  type Hop = { nf: int, bundle: int }

  var recorded: int -> int
  var bundles: Set[Bundle]
  var held: str -> Set[int]
  // The TRUE ancestry of each note, known to the system but not trusted by it.
  var lineage: int -> Set[Hop]
  // What the digest binding pins: a note's real ancestry, as an opaque value.
  // Two ancestries agree on the digest exactly when they are the same set.
  var nextNote: int

  def hasRecord(nf: int): bool = recorded.keys().contains(nf)
  def isSpent(n: int): bool = hasRecord(n)
  def hopWins(h: Hop): bool = hasRecord(h.nf) and recorded.get(h.nf) == h.bundle

  // Every hop of the PRESENTED ancestry settled.
  def allHopsWin(presented: Set[Hop]): bool = presented.forall(h => hopWins(h))

  // The binding: the presented ancestry must be the note's real one. This is
  // what recomputing the history digest buys — nothing more, nothing less.
  def isBound(noteId: int, presented: Set[Hop]): bool = presented == lineage.get(noteId)

  def accepts(noteId: int, presented: Set[Hop]): bool =
    if (BIND) isBound(noteId, presented) and allHopsWin(presented)
    else allHopsWin(presented)

  val honestLive: Set[int] =
    HONEST.fold(Set(), (acc, w) => acc.union(held.get(w).filter(n => not(isSpent(n)))))
  val noInflation: bool = honestLive.size() <= 1

  // ---- Inductive strengthening ----
  //
  // Bounded model checking proves `noInflation` only to the depth searched. An
  // inductive invariant proves it at **every** depth: Apalache checks
  // `Init ⇒ Inv`, `Inv ∧ Step ⇒ Inv'`, and `Inv ⇒ noInflation`, none of which
  // mention a step count.
  //
  // `noInflation` alone is not inductive — it says nothing about *why* honest
  // holdings are safe, so the induction step can start from a fabricated state
  // where an honest wallet holds a note with an unsettled ancestry. The
  // strengthening below supplies the missing structure, and the interesting part
  // is that it is not inductive for `unbound` either: the clause that fails is
  // exactly `honestHoldingsAreSettled`, because without the digest binding a
  // receiver can accept a note whose *presented* ancestry settled while its real
  // one did not. The binding is what makes the induction close.

  def createdBy(m: int): Set[Bundle] = bundles.filter(b => b.id == m)

  // Bundle ids are unique, in range, and always exceed the note they spend —
  // the last conjunct is what makes ancestry acyclic, and without it the chain
  // argument below has nothing to stand on.
  val idsWellFormed: bool =
    bundles.forall(b => b.id >= 1 and b.id < nextNote and b.input < b.id)
      and bundles.forall(b1 => bundles.forall(b2 => b1.id == b2.id implies b1 == b2))
      and WALLETS.forall(w => held.get(w).forall(n => n < nextNote))

  // A note's lineage is exactly its creating bundle's hop appended to its
  // input's lineage, and a note nobody created has no lineage at all.
  val lineageWellFormed: bool =
    lineage.get(0) == Set()
      and NOTE_IDS.forall(m =>
            createdBy(m).forall(b =>
              lineage.get(m) == lineage.get(b.input).union(Set({ nf: b.input, bundle: m }))))
      and NOTE_IDS.forall(m => createdBy(m) == Set() implies lineage.get(m) == Set())

  // Every first occurrence names a bundle that really spends that nullifier.
  val recordsAreReal: bool =
    recorded.keys().forall(nf =>
      bundles.exists(b => b.id == recorded.get(nf) and b.input == nf))

  // The load-bearing clause: an honest wallet only ever holds a note whose
  // **true** ancestry settled, hop for hop.
  val honestHoldingsAreSettled: bool =
    HONEST.forall(w => held.get(w).forall(n => n >= 1 and allHopsWin(lineage.get(n))))

  // Notes that exist. Without this the invariant is inductive but useless: the
  // implication step produced a state with no bundles at all, all lineages
  // empty, and carol holding notes 3 and 4 out of thin air — `allHopsWin` over
  // an empty ancestry is vacuously true, so two notes that never existed both
  // counted as fully settled. Saying "every hop settled" means nothing until
  // something forces the hops to be there.
  val notesExist: bool =
    WALLETS.forall(w => held.get(w).forall(n => n == 0 or createdBy(n) != Set()))
      and bundles.forall(b => b.input == 0 or createdBy(b.input) != Set())

  // Why this implies `noInflation`: take two live honest notes. Each has a fully
  // settled true ancestry, so each is the end of a chain
  // `recorded(0) = c1, recorded(c1) = c2, …`. `recorded` is a function, so the
  // two chains agree step for step from note 0 and one is a prefix of the other.
  // The shorter one's endpoint therefore appears as a nullifier in the longer
  // chain — which means it has a record, which means it is spent. So no two
  // honest notes are live at once.
  pure val ALL_HOPS: Set[Hop] =
    tuples(NOTE_IDS, 1.to(4)).map(t => { nf: t._1, bundle: t._2 })
  pure val ALL_BUNDLES: Set[Bundle] =
    tuples(1.to(4), NOTE_IDS, WALLETS).map(t => { id: t._1, input: t._2, to: t._3 })

  // Domain constraints on every variable. Not a property — a requirement of
  // inductive checking: the induction step starts from an *arbitrary* state
  // satisfying the invariant, so Apalache must be told how to construct one.
  // Without this it refuses with "bundles is used before it is assigned".
  // `recorded` is a partial map, so its domain is existentially quantified over
  // subsets of the note ids rather than fixed.
  val typeOK: bool =
    nextNote.in(1.to(5))
      and bundles.in(ALL_BUNDLES.powerset())
      and held.in(WALLETS.setOfMaps(NOTE_IDS.powerset()))
      and lineage.in(NOTE_IDS.setOfMaps(ALL_HOPS.powerset()))
      and NOTE_IDS.powerset().exists(d => recorded.in(d.setOfMaps(NOTE_IDS)))

  val supplyInv: bool =
    typeOK and idsWellFormed and lineageWellFormed and recordsAreReal
      and notesExist and honestHoldingsAreSettled

  action init = all {
    recorded' = Map(),
    bundles' = Set(),
    held' = WALLETS.mapBy(w => if (w == "mallory") Set(0) else Set()),
    lineage' = NOTE_IDS.mapBy(_ => Set()),
    nextNote' = 1,
  }

  action buildBundle = all {
    nextNote < 5,
    nondet from = oneOf(WALLETS)
    nondet dest = oneOf(WALLETS)
    nondet n = oneOf(held.get(from).union(Set(0)))
    all {
      held.get(from).contains(n),
      bundles' = bundles.union(Set({ id: nextNote, input: n, to: dest })),
      lineage' = lineage.set(nextNote, lineage.get(n).union(Set({ nf: n, bundle: nextNote }))),
      nextNote' = nextNote + 1,
      recorded' = recorded,
      held' = held,
    }
  }

  action publishRecord = all {
    nondet b = oneOf(bundles)
    all {
      not(hasRecord(b.input)),
      recorded' = recorded.put(b.input, b.id),
      bundles' = bundles,
      held' = held,
      lineage' = lineage,
      nextNote' = nextNote,
    }
  }

  // The adversary presents ANY ancestry it likes, drawn from every hop it could
  // possibly have observed. Substitution and truncation are both in this set.
  action receiveHonest = all {
    nondet b = oneOf(bundles)
    nondet presented = oneOf(powerset(NOTE_IDS.fold(Set(), (acc, n) => acc.union(lineage.get(n)))))
    all {
      HONEST.contains(b.to),
      accepts(b.id, presented),
      held' = held.set(b.to, held.get(b.to).union(Set(b.id))),
      recorded' = recorded,
      bundles' = bundles,
      lineage' = lineage,
      nextNote' = nextNote,
    }
  }

  action receiveAttacker = all {
    nondet b = oneOf(bundles)
    all {
      ATTACKER.contains(b.to),
      held' = held.set(b.to, held.get(b.to).union(Set(b.id))),
      recorded' = recorded,
      bundles' = bundles,
      lineage' = lineage,
      nextNote' = nextNote,
    }
  }

  action step = any { buildBundle, publishRecord, receiveHonest, receiveAttacker }
}

// Ancestry checked but NOT bound: the attacker substitutes a clean list.
module unbound {
  import adversarial(BIND = false).*
}

// Ancestry checked AND bound to the proof. This is what ships.
module bound {
  import adversarial(BIND = true).*
}

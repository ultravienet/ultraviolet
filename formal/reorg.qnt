// Ultraviolet — does the confirmation policy survive a reorg?
//
// `required_confirmations` (wallet2/src/chain.rs) scales depth with value.
// It was 1 confirmation under 1,000 units, 3 under 100,000, 6 above — until
// this model's `shallow` module proved the 1-tier unsafe against a 2-block
// reorg, and it was withdrawn: the floor is 3 now, everywhere. A receiver
// accepts once its record is that deep. But Bitcoin reorganizes, and a reorg can change
// *which* record for a nullifier came first — so a note accepted in good faith
// can stop being valid afterwards, and the wallet has no rollback (spec/99).
//
// Questions:
//   1. Is depth alone enough when it is shallower than the reorg?  `shallow`
//   2. Is depth alone enough when it is deeper than any reorg?      `deep`
//   3. Does reconciling after a reorg rescue the shallow case?      `reconciled`
//
// Scope: the protocol layer. Proofs, signatures, and hashes are assumed sound.
//
// Modelling note worth stating, because getting it wrong made the first draft
// useless: reorg depth is bounded **relative to the chain's high-water mark**,
// not to the current tip. Without that, repeated small reorgs walk the chain
// backwards without limit and no confirmation depth is ever safe — which is a
// fact about the model, not about Bitcoin.
//
// Run:
//   quint verify formal/reorg.qnt --main=shallow    --invariant=acceptedStaysValid --max-steps=8
//   quint verify formal/reorg.qnt --main=deep       --invariant=acceptedStaysValid --max-steps=8
//   quint verify formal/reorg.qnt --main=reconciled --invariant=acceptedStaysValid --max-steps=8

module chainmodel {
  // Confirmations the receiver waits for before accepting.
  const REQUIRED: int
  // How deep a reorg can go, measured from the highest tip ever reached.
  const MAX_REORG: int
  // Whether the wallet re-examines what it holds when the chain changes.
  const RECONCILE: bool
  // Whether that re-examination also asks whether the *issuance* survived.
  //
  // Added 2026-07-28, and it was a genuine hole in this file rather than a
  // refinement: the model had no notion of a genesis at all, so the property
  // "a reorg that orphans the issuance must condemn the coins" was checked by
  // two Rust tests and nothing else. `wallet2::reconcile` does ask, and
  // `wallet2::accept` refuses a coin whose genesis is not confirmed — with no
  // way left to opt out — so the rule deserves a module that can fail.
  const CHECK_GENESIS: bool

  // A record: nullifier `nf` claimed by bundle `bundle`. Two bundles competing
  // for one nullifier is the point — only the first occurrence counts.
  type Marker = { nf: int, bundle: int }

  pure val NULLIFIERS = Set(1)
  pure val BUNDLES = Set(1, 2)
  pure val MAX_HEIGHT = 5
  pure val ALL_MARKERS = NULLIFIERS.map(n => BUNDLES.map(b => { nf: n, bundle: b })).flatten()

  var blocks: int -> Set[Marker]
  var tip: int
  // The highest tip ever reached; reorg depth is bounded against this.
  var highWater: int
  var accepted: Set[Marker]
  // The height holding this asset's issuance record; 0 means not on chain.
  // A reorg to at-or-below it takes the issuance away, and — this is the case
  // that matters — the spend records can be re-mined into the new chain while
  // the issuance is not.
  var genesisAt: int

  // --- Chain-parameterized helpers, so a step can reason about its own
  // --- post-state rather than only the state it started in.

  // NOTE: iterate a *list*, not a set. `1.to(n)` is a set and `fold` over a
  // set has no defined order in Quint — using it here silently picked an
  // arbitrary block as "first", which made every module fail identically and
  // looked like a protocol bug. Order matters to first-occurrence by
  // definition, so the traversal has to be ordered.
  def firstClaimIn(bs: int -> Set[Marker], t: int, nf: int): Set[int] =
    range(1, MAX_HEIGHT + 1).foldl(Set(), (acc, h) =>
      if (acc != Set() or h > t) acc
      else bs.get(h).filter(r => r.nf == nf).map(r => r.bundle))

  def isFirstIn(bs: int -> Set[Marker], t: int, r: Marker): bool =
    firstClaimIn(bs, t, r.nf).contains(r.bundle)

  def depthIn(bs: int -> Set[Marker], t: int, r: Marker): int =
    range(1, MAX_HEIGHT + 1).foldl(0, (acc, h) =>
      if (acc != 0 or h > t) acc
      else if (bs.get(h).contains(r)) t - h + 1
      else 0)

  // --- The property: everything held is still the first occurrence.
  val acceptedStaysValid: bool = accepted.forall(r => isFirstIn(blocks, tip, r))

  // **Nothing is held whose issuance is not on the chain.** Every coin
  // descends from the genesis, so an orphaned issuance condemns all of them
  // however well their own hops settled.
  val acceptedHasLiveGenesis: bool = accepted != Set() implies genesisAt > 0

  action init = all {
    blocks' = 1.to(MAX_HEIGHT).mapBy(_ => Set()),
    tip' = 0,
    highWater' = 0,
    accepted' = Set(),
    genesisAt' = 0,
  }

  action mine = all {
    tip < MAX_HEIGHT,
    nondet content = oneOf(powerset(ALL_MARKERS))
    all {
      blocks' = blocks.set(tip + 1, content),
      tip' = tip + 1,
      highWater' = if (tip + 1 > highWater) tip + 1 else highWater,
      accepted' = accepted,
      genesisAt' = genesisAt,
    }
  }

  // The issuer publishes the asset's issuance record.
  action issue = all {
    genesisAt == 0,
    tip < MAX_HEIGHT,
    blocks' = blocks,
    tip' = tip + 1,
    highWater' = if (tip + 1 > highWater) tip + 1 else highWater,
    accepted' = accepted,
    genesisAt' = tip + 1,
  }

  // Rewrite from `newTip` upward. Bounded against the high-water mark, which is
  // the assumption any confirmation policy actually rests on.
  action reorg = all {
    nondet newTip = oneOf(1.to(MAX_HEIGHT))
    nondet content = oneOf(powerset(ALL_MARKERS))
    all {
      newTip <= tip,
      newTip > highWater - MAX_REORG,
      val bs = 1.to(MAX_HEIGHT).mapBy(h =>
        if (h < newTip) blocks.get(h)
        else if (h == newTip) content
        else Set())
      // The issuance is orphaned by any rewrite that reaches its height.
      val g = if (genesisAt >= newTip) 0 else genesisAt
      all {
        blocks' = bs,
        tip' = newTip,
        highWater' = highWater,
        genesisAt' = g,
        // A reconciling wallet drops what no longer holds first occurrence, in
        // the same step — modelling a wallet that reacts to the reorg it saw.
        // With CHECK_GENESIS it also drops everything when the issuance itself
        // went away, which is the half this model did not have.
        accepted' =
          if (RECONCILE and CHECK_GENESIS and g == 0) Set()
          else if (RECONCILE) accepted.filter(r => isFirstIn(bs, newTip, r))
          else accepted,
      }
    }
  }

  action accept = all {
    nondet r = oneOf(ALL_MARKERS)
    all {
      isFirstIn(blocks, tip, r),
      depthIn(blocks, tip, r) >= REQUIRED,
      // A receiver refuses a coin whose issuance is not confirmed. Not
      // optional in the code, and not optional here.
      genesisAt > 0,
      accepted' = accepted.union(Set(r)),
      blocks' = blocks,
      tip' = tip,
      highWater' = highWater,
      genesisAt' = genesisAt,
    }
  }

  action step = any { mine, reorg, accept, issue }

  // ---- Inductive strengthenings: both reorg claims at ALL depths ----
  //
  // Domain constraints for the induction's arbitrary start state (the
  // multihop.qnt lesson). The whole space is tiny — two markers, five
  // heights — which is why these proofs are cheap where linkage's was not.
  val typeOK: bool =
    blocks.in(1.to(MAX_HEIGHT).setOfMaps(ALL_MARKERS.powerset()))
      and tip.in(0.to(MAX_HEIGHT))
      and highWater.in(0.to(MAX_HEIGHT))
      and accepted.in(ALL_MARKERS.powerset())
      and genesisAt.in(0.to(MAX_HEIGHT))

  // Under `reconciled` (RECONCILE with CHECK_GENESIS): every held marker is
  // still the first occurrence — inductive because `accept` only admits a
  // current first, `reorg` re-filters in the same step, and `mine` appends
  // above the tip, which can never change who was first below it.
  //
  //   quint verify formal/reorg.qnt --main=reconciled \
  //     --inductive-invariant=reorgInv --invariant=acceptedStaysValid
  val reorgInv: bool = typeOK and acceptedStaysValid

  // Under `genesisChecked` (same constants): nothing is held whose issuance
  // is off the chain — inductive because `accept` requires a live genesis and
  // the reorg step condemns everything the moment the issuance is orphaned.
  //
  //   quint verify formal/reorg.qnt --main=reconciled \
  //     --inductive-invariant=genesisInv --invariant=acceptedHasLiveGenesis
  val genesisInv: bool = typeOK and acceptedStaysValid and acceptedHasLiveGenesis
}

// What ships today for small payments: 1 confirmation, no rollback, against
// reorgs up to 2 blocks.
module shallow {
  import chainmodel(REQUIRED = 1, MAX_REORG = 2, RECONCILE = false, CHECK_GENESIS = true).*
}

// Depth alone, but waiting deeper than any reorg the model permits.
module deep {
  import chainmodel(REQUIRED = 3, MAX_REORG = 2, RECONCILE = false, CHECK_GENESIS = true).*
}

// Shallow depth, but the wallet reconciles when the chain changes.
module reconciled {
  import chainmodel(REQUIRED = 1, MAX_REORG = 2, RECONCILE = true, CHECK_GENESIS = true).*
}

// **A reorg that takes the issuance and leaves the spends.** The wallet
// re-checks settlement and nothing else, so every coin stays held — backed by
// an issuance no reader of Bitcoin can find. That is precisely the state the
// supply argument says cannot exist, and until this module the only thing
// standing against it was a pair of Rust tests.
module genesisUnchecked {
  import chainmodel(REQUIRED = 3, MAX_REORG = 2, RECONCILE = true, CHECK_GENESIS = false).*
}

// What `wallet2::reconcile` does: ask the genesis question again on every
// reorg, and quarantine the asset's notes when the answer changed.
module genesisChecked {
  import chainmodel(REQUIRED = 3, MAX_REORG = 2, RECONCILE = true, CHECK_GENESIS = true).*
}

// ===========================================================================
// Recursion changes the reorg question — a root-freshness abstraction.
//
// **Why this is here, and what it decides.** The design that ships makes a
// receiver walk a coin's whole ancestry (the modules above). `[ACC]` Part 2
// would replace the walk with recursion: each hop's proof verifies the
// previous hop's proof, so a coin carries ONE proof and the receiver checks
// one thing. That proof is not free-floating — it is bound to the chain state
// it was made against, an accumulator root at some height. Call it `provedAt`.
//
// A reorg below `provedAt` rewrites the chain the proof committed to. The proof
// is now about a history that is no longer canonical. In the walk design the
// wallet simply re-walks the new chain (`reconciled` above proves it stays
// safe). **Recursion cannot do that**, because the whole point of recursion is
// that the wallet DISCARDED the ancestry — there is nothing left to re-prove
// from. The coin is perfectly valid (its records were re-mined, no double
// spend), and it is stuck.
//
// That is a LIVENESS failure, and `reorg.qnt` had no liveness property. This
// module adds one, in the shape `baserail` uses: an invariant that says the
// money is still spendable, checked to hold at all depths where it can and to
// FAIL where the design cannot support it. The failure is the result.
//
// One fork-height variable, no accumulator tree: the tree's soundness is a
// separate (harder) question, and it is not what decides whether the design is
// safe against reorgs. This is.
module recursion {
  // How deep a reorg can go from the high-water mark.
  const MAX_REORG: int
  // **The load-bearing constant.** Whether a wallet whose recursive proof went
  // stale can rebuild it — which it can only do if it kept the ancestry that
  // recursion exists to throw away. `true` models recursion-with-retained-
  // ancestry (or the walk); `false` models pure recursion.
  const CAN_REPROVE: bool

  // A held coin and the height its recursive proof committed to. `stranded`
  // means a reorg invalidated that proof and it could not be rebuilt.
  type Coin = { id: int, provedAt: int, stranded: bool }

  pure val IDS = Set(1, 2)
  pure val MAX_HEIGHT = 5

  var tip: int
  var highWater: int
  var held: Set[Coin]
  var spent: Set[int]

  // **The liveness property: every coin a wallet holds and has not spent can
  // still be spent.** A coin whose proof was orphaned and cannot be rebuilt
  // violates it — the money is real and unreachable.
  val paymentRemainsPossible: bool =
    held.forall(c => c.stranded implies spent.contains(c.id))

  action init = all {
    tip' = 0,
    highWater' = 0,
    held' = Set(),
    spent' = Set(),
  }

  action mine = all {
    tip < MAX_HEIGHT,
    tip' = tip + 1,
    highWater' = if (tip + 1 > highWater) tip + 1 else highWater,
    held' = held,
    spent' = spent,
  }

  // Receive a coin: its recursive proof commits to the current tip.
  action receive =
    nondet id = oneOf(IDS)
    all {
      tip > 0,
      not(held.exists(c => c.id == id)),
      held' = held.union(Set({ id: id, provedAt: tip, stranded: false })),
      tip' = tip,
      highWater' = highWater,
      spent' = spent,
    }

  // Spend a held coin — only possible if its proof is still good.
  action spend =
    nondet c = oneOf(held)
    all {
      held != Set(),
      not(c.stranded),
      not(spent.contains(c.id)),
      spent' = spent.union(Set(c.id)),
      held' = held,
      tip' = tip,
      highWater' = highWater,
    }

  // Rewrite from `newTip` up. Every proof frozen at or above `newTip` is now
  // about an orphaned history.
  action reorg =
    nondet newTip = oneOf(1.to(MAX_HEIGHT))
    all {
      newTip <= tip,
      newTip > highWater - MAX_REORG,
      tip' = newTip,
      highWater' = highWater,
      spent' = spent,
      // A coin whose proof committed at or above the fork is stale. If the
      // wallet can re-prove (it kept the ancestry), it re-binds to the new
      // tip. If it cannot — pure recursion — it is stranded.
      held' = held.map(c =>
        if (c.provedAt < newTip) c
        else if (CAN_REPROVE) { id: c.id, provedAt: newTip, stranded: false }
        else { id: c.id, provedAt: c.provedAt, stranded: true }),
    }

  action step = any { mine, receive, spend, reorg }
}

// **Recursion that kept the ancestry, or the walk: liveness holds.** A reorg
// re-binds every stale proof, so nothing is ever stranded. This is the control
// — it must PASS, or the model proves nothing about the failing case.
//
//   quint verify formal/reorg.qnt --main=recursionReprovable \
//     --invariant=paymentRemainsPossible --max-steps=8
module recursionReprovable {
  import recursion(MAX_REORG = 2, CAN_REPROVE = true).*
}

// **Pure recursion: liveness FAILS.** A reorg below a coin's proof height
// strands it with no way to rebuild, and the money is real and unspendable.
// This module is EXPECTED to produce a counterexample — that is the finding,
// and it is why `[ACC]` Part 2 cannot ship without either retaining ancestry
// (defeating its purpose) or a recovery path this model says it does not have.
//
//   quint verify formal/reorg.qnt --main=recursionStrict \
//     --invariant=paymentRemainsPossible --max-steps=8   # MUST fail
module recursionStrict {
  import recursion(MAX_REORG = 2, CAN_REPROVE = false).*
}

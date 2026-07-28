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

  action init = all {
    blocks' = 1.to(MAX_HEIGHT).mapBy(_ => Set()),
    tip' = 0,
    highWater' = 0,
    accepted' = Set(),
  }

  action mine = all {
    tip < MAX_HEIGHT,
    nondet content = oneOf(powerset(ALL_MARKERS))
    all {
      blocks' = blocks.set(tip + 1, content),
      tip' = tip + 1,
      highWater' = if (tip + 1 > highWater) tip + 1 else highWater,
      accepted' = accepted,
    }
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
      all {
        blocks' = bs,
        tip' = newTip,
        highWater' = highWater,
        // A reconciling wallet drops what no longer holds first occurrence, in
        // the same step — modelling a wallet that reacts to the reorg it saw.
        accepted' =
          if (RECONCILE) accepted.filter(r => isFirstIn(bs, newTip, r))
          else accepted,
      }
    }
  }

  action accept = all {
    nondet r = oneOf(ALL_MARKERS)
    all {
      isFirstIn(blocks, tip, r),
      depthIn(blocks, tip, r) >= REQUIRED,
      accepted' = accepted.union(Set(r)),
      blocks' = blocks,
      tip' = tip,
      highWater' = highWater,
    }
  }

  action step = any { mine, reorg, accept }
}

// What ships today for small payments: 1 confirmation, no rollback, against
// reorgs up to 2 blocks.
module shallow {
  import chainmodel(REQUIRED = 1, MAX_REORG = 2, RECONCILE = false).*
}

// Depth alone, but waiting deeper than any reorg the model permits.
module deep {
  import chainmodel(REQUIRED = 3, MAX_REORG = 2, RECONCILE = false).*
}

// Shallow depth, but the wallet reconciles when the chain changes.
module reconciled {
  import chainmodel(REQUIRED = 1, MAX_REORG = 2, RECONCILE = true).*
}

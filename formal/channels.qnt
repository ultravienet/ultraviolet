// Ultraviolet — the channel dispute machine (spec/07), safety and liveness.
//
// Channels are the protocol's weakest tier and the only one that assumes
// liveness, so they are the place where a safety-shaped argument is most likely
// to be hiding a liveness failure. spec/07 makes four claims worth checking:
//
//   1. Outsiders cannot forge claims (they hold no seq-chain preimages).
//   2. A phantom claim at an unbacked seq is "inert, **not a freeze**".
//   3. The never-re-sign discipline is *mandatory*: absent it, equivocation lets
//      "first claim wins" ratify the cheater's choice.
//   4. Exactly two residues remain — theft when offline past W, and theft when
//      your storage is eclipsed.
//
// Claim 1 is structural, so it is modelled by construction: only the two parties
// can publish claims, and there is no action by which anyone else could. Claims
// 2–4 are what this model actually tests, and claim 4 is a demand on the model
// rather than on the protocol: **if the model cannot produce those two thefts,
// the model is wrong, not the spec.** Both are reproduced below as their own
// modules.
//
// ---- What is modelled ----
// Co-signed states (seq + the honest party's balance + the total the state
// allocates), the two nullifiers as a window that opens once and closes after W,
// in-window claims with publication order, retrievability of the state a claim
// points to, and settlement at the highest backed seq with first-claim-wins ties.
//
// ---- What is assumed ----
// The cryptography: seq-chain elements authenticate "a party claims s" and
// nothing more, and a co-signed state is genuinely co-signed. Also assumed: the
// window is long enough that in-window claim *ordering* is stable, which is what
// spec/07's reorg margin buys. If ordering were unstable, first-claim-wins would
// not be well-defined and tie-breaking would need rethinking — this model cannot
// see that failure, and says so rather than implying coverage.
//
// ---- What the adversary controls ----
// When the channel closes and with which state, every claim they publish
// (including claims at seqs no state backs), retrievability of the state the
// honest party's claim points to (the eclipse), and the tie-break advantage that
// comes from moving first — a unilateral close is *theirs*, so their claim lands
// before the honest party's response. Handing the honest party tie priority would
// quietly delete the equivocation attack, which is the mistake `multihop.qnt`
// made in a different costume.
//
// Not handed to the adversary: further channel updates once the window is open.
// A closing channel does not keep transacting, and freezing `latest` at open is
// what makes "the honest party's entitlement" well-defined.
//
// ---- Liveness technique ----
// **Deadlock-freedom**, as a true invariant with no step bound: whenever a claim
// is backed, the settlement rule must have a winner, so settlement is always
// *enabled*. See `settlementNeverDeadlocks` for why the bounded-liveness form
// this originally used had to be abandoned — it violated even in the fully
// disciplined module, for reasons that were about the simulator rather than the
// protocol.
//
// The split this leaves is worth naming: settlement being always possible is
// proven here; settlement being *taken* requires a party to act within W, which
// is spec/07's admitted assumption and is what module `offline` prices.
//
// Run (safety):
//   quint verify formal/channels.qnt --main=disciplined  --invariant=noTheft --max-steps=8
//   quint verify formal/channels.qnt --main=equivocating --invariant=noTheft --max-steps=8
//   quint verify formal/channels.qnt --main=offline      --invariant=noTheft --max-steps=8
//   quint verify formal/channels.qnt --main=eclipsed     --invariant=noTheft --max-steps=8
// Run (liveness):
//   quint verify formal/channels.qnt --main=disciplined  --invariant=settlementNeverDeadlocks --max-steps=8
//   quint verify formal/channels.qnt --main=naiveSettle  --invariant=settlementNeverDeadlocks --max-steps=8

module channel {
  // A wallet refuses to co-sign a seq it already co-signed, persisted across
  // restarts. spec/07 calls this load-bearing; `equivocating` tests whether it
  // actually is.
  const NEVER_RESIGN: bool
  // The honest party (or a watchtower holding no secrets) posts their claim
  // inside the window.
  const HONEST_ONLINE: bool
  // The state the honest party's claim points to is still retrievable at
  // settlement. False models the counterparty eclipsing their blob storage.
  const STORAGE_LIVE: bool
  // Settlement drops a claim whose state is not retrievable and falls through to
  // the next-highest backed claim — spec/07's actual rule. False models the
  // tempting simpler rule "settle at the highest *claimed* seq", which is where
  // a phantom claim turns into a freeze.
  const DROP_UNBACKED: bool

  pure val FUNDING = 4
  pure val MAX_SEQ = 2
  pure val W = 2
  // Two balances are enough to distinguish "rolled back" from "settled fairly".
  pure val BALS = Set(1, 3)
  // A state either allocates exactly the funding note, or over-allocates.
  pure val TOTALS = Set(FUNDING, FUNDING + 2)

  // `honest` is the honest party's balance; `total` is what the state allocates
  // in full, which conservation requires to equal the funding note.
  type St = { seq: int, honest: int, total: int }
  // A claim publishes a seq-chain element plus a pointer; `st` is what the
  // pointer resolves to, and `at` is publication order.
  type Claim = { st: St, by: str, at: int }

  pure val OPENING: St = { seq: 0, honest: 1, total: FUNDING }

  // Every state a claim could point to — including ones nobody co-signed, which
  // is exactly what a phantom claim points at.
  pure val ALL_STATES: Set[St] =
    tuples(0.to(MAX_SEQ), BALS, TOTALS)
      .map(t => { seq: t._1, honest: t._2, total: t._3 })

  var cosigned: Set[St]
  // The last state the honest party co-signed: their view of their own money,
  // and therefore what they are entitled to at settlement.
  var latest: St
  var claims: Set[Claim]
  // -1 until the first occurrence of nf_dispute opens the window.
  var openedAt: int
  var epoch: int
  var tick: int
  // The resolved outcome: empty, or exactly one state.
  var settled: Set[St]

  def isOpen: bool = openedAt >= 0 and epoch <= openedAt + W
  def closed: bool = openedAt >= 0 and epoch > openedAt + W

  // Conservation: settlement verifies in-circuit that the presented state
  // allocates exactly the funding note, so a co-signed over-allocation is still
  // rejected.
  def conserves(st: St): bool = st.total == FUNDING

  // The honest party's own latest state is what an eclipse targets; the
  // counterparty naturally keeps retrievable whatever helps them.
  def retrievable(st: St): bool = STORAGE_LIVE or st != latest

  // "Backed by a retrievable, co-signed state" — the whole of spec/07's
  // settlement predicate.
  def backed(c: Claim): bool =
    cosigned.contains(c.st) and retrievable(c.st) and conserves(c.st)

  def backedClaims: Set[Claim] = claims.filter(c => backed(c))
  def topSeqOf(cs: Set[Claim]): int =
    cs.fold(-1, (m, c) => if (c.st.seq > m) c.st.seq else m)

  // The candidate set. With the real rule, every backed claim competes and the
  // highest wins. With the naive rule, only the highest *claimed* seq is
  // considered — so an unbacked claim above the real maximum leaves nothing
  // eligible at all.
  def eligible: Set[Claim] =
    if (DROP_UNBACKED) backedClaims
    else claims.filter(c => c.st.seq == topSeqOf(claims) and backed(c))

  def atTop: Set[Claim] = eligible.filter(c => c.st.seq == topSeqOf(eligible))
  // Ties go to the first claim published.
  def winner: Set[Claim] = atTop.filter(c => atTop.forall(o => c.at <= o.at))

  // ---- SAFETY ----
  // An honest party settles at no worse than the balance in the last state they
  // co-signed. Stated unconditionally: the modules that violate it are the
  // residues spec/07 admits, and stating it conditionally would hide them.
  val noTheft: bool = settled.forall(st => st.honest >= latest.honest)

  // Settlement never ratifies a state that allocates more than the funding note.
  // Distinct from theft: this is supply, not fairness — an over-allocation can
  // be generous to the honest party and still print money.
  val conservationAtSettlement: bool = settled.forall(st => conserves(st))

  // ---- LIVENESS (deadlock-freedom) ----
  // Whenever some claim is backed and settlement has not happened, the rule must
  // *have* a winner — settlement must be enabled. A phantom claim that empties
  // the winner set is a freeze; one that is merely ignored is inert.
  //
  // This started life as bounded liveness — "settled within an epoch of the
  // window closing" — and violated in every module including the fully
  // disciplined one. The counterexample was a state where a backed claim existed
  // and the winner was non-empty, but the model had simply never scheduled the
  // `settle` step. An invariant cannot tell "not yet taken" from "impossible"
  // without fairness assumptions, so the bound was measuring the simulator, not
  // the protocol.
  //
  // Deadlock-freedom is the right shape here, and it is stronger than the bound
  // would have been: no step count, no fairness, and it holds at every reachable
  // state. It is worth being exact about the split it leaves behind. This proves
  // settlement is always *possible*; whether someone actually acts is spec/07's
  // openly admitted liveness assumption, and `offline` is what its failure costs.
  // The bound worked in `onetime.qnt` only because nothing there ever unfreezes a
  // note, which made "still frozen at K" genuinely terminal.
  val settlementNeverDeadlocks: bool =
    openedAt < 0 or backedClaims == Set() or settled != Set() or winner != Set()

  action init = all {
    cosigned' = Set(OPENING),
    latest' = OPENING,
    claims' = Set(),
    openedAt' = -1,
    epoch' = 0,
    tick' = 0,
    settled' = Set(),
  }

  // Co-sign the next state. Balances move as payments flow.
  action update = all {
    openedAt < 0,
    latest.seq < MAX_SEQ,
    nondet h = oneOf(BALS)
    all {
      cosigned' = cosigned.union(Set({ seq: latest.seq + 1, honest: h, total: FUNDING })),
      latest' = { seq: latest.seq + 1, honest: h, total: FUNDING },
      claims' = claims,
      openedAt' = openedAt,
      epoch' = epoch,
      tick' = tick,
      settled' = settled,
    }
  }

  // Equivocation: a second, different state co-signed at a seq already used.
  // The honest party's view advances to the new one — they think it is a normal
  // update — while the *earlier* same-seq state stays co-signed and claimable.
  // That is the attack: the cheater claims the earlier one first and the tie
  // resolves their way.
  action equivocate = all {
    not(NEVER_RESIGN),
    openedAt < 0,
    latest.seq >= 1,
    nondet h = oneOf(BALS)
    all {
      h != latest.honest,
      cosigned' = cosigned.union(Set({ seq: latest.seq, honest: h, total: FUNDING })),
      latest' = { seq: latest.seq, honest: h, total: FUNDING },
      claims' = claims,
      openedAt' = openedAt,
      epoch' = epoch,
      tick' = tick,
      settled' = settled,
    }
  }

  // The honest party is induced to co-sign a state whose balances exceed the
  // funding note. It does not become their view of current — they are not paying
  // themselves — but it is co-signed, so only the conservation check stops it
  // from settling.
  action cosignOverAllocated = all {
    openedAt < 0,
    nondet s = oneOf(1.to(MAX_SEQ))
    nondet h = oneOf(BALS)
    all {
      cosigned' = cosigned.union(Set({ seq: s, honest: h, total: FUNDING + 2 })),
      latest' = latest,
      claims' = claims,
      openedAt' = openedAt,
      epoch' = epoch,
      tick' = tick,
      settled' = settled,
    }
  }

  // The counterparty closes unilaterally: first occurrence of nf_dispute opens
  // the window, and their own claim rides along with it — a close *is* a claim.
  // An online honest party responds inside the window, necessarily after the
  // cheater's claim, so the cheater holds tie priority.
  action closeUnilaterally = all {
    openedAt < 0,
    nondet st = oneOf(ALL_STATES)
    all {
      openedAt' = epoch,
      claims' = claims
        .union(Set({ st: st, by: "cheat", at: tick }))
        .union(if (HONEST_ONLINE) Set({ st: latest, by: "honest", at: tick + 1 })
               else Set()),
      tick' = tick + 2,
      cosigned' = cosigned,
      latest' = latest,
      epoch' = epoch,
      settled' = settled,
    }
  }

  // Any further in-window claim by the cheater, at any seq — backed or phantom.
  action claimAgain = all {
    isOpen,
    nondet st = oneOf(ALL_STATES)
    all {
      claims' = claims.union(Set({ st: st, by: "cheat", at: tick })),
      tick' = tick + 1,
      cosigned' = cosigned,
      latest' = latest,
      openedAt' = openedAt,
      epoch' = epoch,
      settled' = settled,
    }
  }

  // Time passes to the end of the window in one step. `tickEpoch` still exists,
  // so this removes no behaviour — it only shortens the path to settlement.
  // Without it the equivocation attack needs three separate epoch ticks and does
  // not fit inside a depth-6 bound, which made `equivocating` report `[ok]`:
  // a **false negative from an insufficient bound**, not a passing property.
  // Any bounded result has to be read against the length of the attack it is
  // meant to find.
  action closeWindow = all {
    isOpen,
    epoch' = openedAt + W + 1,
    cosigned' = cosigned,
    latest' = latest,
    claims' = claims,
    openedAt' = openedAt,
    tick' = tick,
    settled' = settled,
  }

  action tickEpoch = all {
    epoch < 8,
    epoch' = epoch + 1,
    cosigned' = cosigned,
    latest' = latest,
    claims' = claims,
    openedAt' = openedAt,
    tick' = tick,
    settled' = settled,
  }

  // After E+W, the winner is spent against nf_funding.
  action settle = all {
    closed,
    settled == Set(),
    winner != Set(),
    settled' = winner.map(c => c.st),
    cosigned' = cosigned,
    latest' = latest,
    claims' = claims,
    openedAt' = openedAt,
    epoch' = epoch,
    tick' = tick,
  }

  // A no-op, so a bounded epoch counter or an exhausted set of moves never
  // deadlocks the machine. Apalache reports a deadlock in place of the invariant
  // verdict, which would silently turn "nothing left to do" into "property
  // failed".
  action stutter = all {
    cosigned' = cosigned, latest' = latest, claims' = claims,
    openedAt' = openedAt, epoch' = epoch, tick' = tick, settled' = settled,
  }

  action step = any {
    update, equivocate, cosignOverAllocated,
    closeUnilaterally, claimAgain, tickEpoch, closeWindow, settle, stutter,
  }
}

// spec/07 as written: the discipline enforced, the honest party watched, storage
// replicated, unbacked claims dropped. Both properties should hold.
module disciplined {
  import channel(NEVER_RESIGN = true, HONEST_ONLINE = true,
                 STORAGE_LIVE = true, DROP_UNBACKED = true).*
}

// Claim 3: drop only the never-re-sign discipline. If safety still held, the
// discipline would be decoration rather than load-bearing.
module equivocating {
  import channel(NEVER_RESIGN = false, HONEST_ONLINE = true,
                 STORAGE_LIVE = true, DROP_UNBACKED = true).*
}

// Residue 1: offline past W and unwatched. Must produce theft.
module offline {
  import channel(NEVER_RESIGN = true, HONEST_ONLINE = false,
                 STORAGE_LIVE = true, DROP_UNBACKED = true).*
}

// Residue 2: storage eclipsed, so the honest party's claim resolves to nothing.
// Must produce theft.
module eclipsed {
  import channel(NEVER_RESIGN = true, HONEST_ONLINE = true,
                 STORAGE_LIVE = false, DROP_UNBACKED = true).*
}

// Claim 2, from the other side: settle at the highest *claimed* seq instead of
// the highest *backed* one, and a phantom claim stops being inert.
module naiveSettle {
  import channel(NEVER_RESIGN = true, HONEST_ONLINE = true,
                 STORAGE_LIVE = true, DROP_UNBACKED = false).*
}

// Ultraviolet — the first model of an OBSERVER, not a thief.
//
// Every other model here asks whether an attacker can move money they should
// not. This one asks the question the product's pitch actually rests on: what
// does someone who only *watches* learn? For a private-payments system that is
// the claim with the least verification behind it — the three privacy claims
// (`P1`, `P2`, `P3` in `formal/CLAIMS.md`) are "argued" or "test-only", and
// none of them composes the leaks.
//
// The leaks are known individually and are not in dispute:
//
//   - **On chain**, spending publishes a record. It is a keyless nullifier —
//     anonymous in itself — but it is a *public event at a time*, and the payer
//     usually self-publishes it, so a network observer can often see *which
//     node* sent it (`[FRONTRUN]`, `spec/99:274`: "a mempool watcher").
//   - **Off chain**, the bundle is delivered to the payee through a carrier.
//     The carrier does not see the amount (`P3`, sealed), but it sees the
//     *recipient* and the *time*: a chat message goes to an addressed inbox.
//
// Neither leak is a break on its own. **The break is the composition**: an
// observer who sees a record appear and a delivery happen in the same window
// can PAIR them — linking the anonymous on-chain event to the addressed
// off-chain delivery, and so learning *who paid whom*, even though the amount
// stays hidden. Nothing modelled that until now.
//
// The property is `unlinkable`: for every payment the observer holds, it cannot
// pair that payment's record with its delivery. The finding is that this FAILS
// for a lone payment and HOLDS only when enough traffic shares the window — so
// **payment-graph privacy is a function of traffic, not of the cryptography**,
// and a single payment in a quiet window is linkable no matter how good the
// seal is.
//
// Scope, stated plainly. This models the *pairing* leak — record-event to
// delivery-event — over discrete rounds. It does NOT model amounts (P1, hidden
// by the seal and assumed), the payer's network identity beyond "an event was
// observed", or a global traffic-analysis adversary. Rounds stand in for a
// correlation window; two events in one round are indistinguishable in time.
// It is a first cut at a large question and it is scoped to the one composition
// that turns two harmless leaks into a real one.
//
// Run:
//   quint verify formal/privacy.qnt --main=lone         --invariant=unlinkable --max-steps=8   # FAILS: the finding
//   quint verify formal/privacy.qnt --main=offband      --invariant=unlinkable --max-steps=8   # holds: no record event
//   quint verify formal/privacy.qnt --main=decorrelated --invariant=unlinkable --max-steps=8   # holds: events split in time

module observer {
  // Rounds between a payment's record (on chain) and its delivery (off chain).
  // `0` is the exposed case: both land in the same correlation window and pair
  // uniquely. `>= 1` decorrelates them in time, so no single window holds both
  // halves of one payment.
  const DELAY: int
  // Whether the record is published OUT OF BAND — straight to a miner or a
  // private relay — so no public mempool event is tied to the payer. With this
  // on, there is no record-event for the observer to pair at all.
  const OUT_OF_BAND: bool

  pure val PARTIES = Set(1, 2, 3)
  // A payment: who paid, who was paid, and a unique id.
  type Payment = { id: int, payer: int, payee: int }

  pure val MAX_ID = 4

  // Payments that have happened.
  var made: Set[Payment]
  // What the observer has seen, as two channels:
  //   recordAt[r]   = the set of payment ids whose record was published in round r
  //   deliveryAt[r] = the set of (id, payee) whose bundle was delivered in round r
  // The observer never sees the id directly — it is carried here only so the
  // property can ask whether a UNIQUE pairing exists. The observer sees the
  // round, the fact of a record, and the delivery's recipient.
  var recordAt: int -> Set[int]
  var deliveryAt: int -> Set[int]
  var round: int

  pure val MAX_ROUND = 4

  // **The privacy property.** A payment is *linked* when some round holds
  // exactly its record and exactly its delivery, alone — then the observer
  // pairs them **correctly** and learns "this payee was paid by whoever sent
  // that record". The pairing must be of the SAME payment: a round that happens
  // to hold one payment's record and a different payment's delivery gives the
  // observer a confident but WRONG link, which does not break privacy — it is
  // noise, and decorrelation (below) works precisely by manufacturing it.
  //
  // Unlinkability holds iff no payment is correctly, uniquely pairable this way.
  def paymentLinked(id: int): bool =
    1.to(MAX_ROUND).exists(r =>
      recordAt.get(r) == Set(id) and deliveryAt.get(r) == Set(id))

  val unlinkable: bool =
    made.forall(p => not(paymentLinked(p.id)))

  action init = all {
    made' = Set(),
    recordAt' = 1.to(MAX_ROUND).mapBy(_ => Set()),
    deliveryAt' = 1.to(MAX_ROUND).mapBy(_ => Set()),
    round' = 1,
  }

  // A payment happens in the current round. Its record is observable in this
  // round (unless out of band), and its bundle is delivered in this round.
  //
  // BATCH gates how many payments a round admits before it advances: a round
  // that already holds BATCH deliveries is "full", so the next payment moves to
  // a fresh round. That is what models a quiet channel (BATCH = 1: every
  // payment gets its own round, uniquely pairable) versus a busy one.
  action pay =
    nondet id = oneOf(1.to(MAX_ID))
    nondet payer = oneOf(PARTIES)
    nondet payee = oneOf(PARTIES)
    val deliverRound = round + DELAY
    all {
      round <= MAX_ROUND,
      deliverRound <= MAX_ROUND,
      payer != payee,
      not(made.exists(p => p.id == id)),
      made' = made.union(Set({ id: id, payer: payer, payee: payee })),
      // The record is observable in the current round (unless out of band); the
      // delivery is observable DELAY rounds later.
      recordAt' =
        if (OUT_OF_BAND) recordAt
        else recordAt.set(round, recordAt.get(round).union(Set(id))),
      deliveryAt' = deliveryAt.set(deliverRound, deliveryAt.get(deliverRound).union(Set(id))),
      round' = round,
    }

  // Close the current round and open the next. Advances time so a later payment
  // lands in a fresh window.
  action tick = all {
    round < MAX_ROUND,
    round' = round + 1,
    made' = made,
    recordAt' = recordAt,
    deliveryAt' = deliveryAt,
  }

  // A stutter, so an exhausted state space is not reported as a deadlock — that
  // is a modelling artifact, not a privacy failure, and it would mask the real
  // verdict on `unlinkable`.
  action stutter = all {
    made' = made,
    recordAt' = recordAt,
    deliveryAt' = deliveryAt,
    round' = round,
  }

  action step = any { pay, tick, stutter }
}

// **The exposed case: record and delivery in one window. Unlinkable FAILS.**
// DELAY = 0, in band. A payment's record and its delivery land in the same
// round, pair uniquely, and the observer reads the payer->payee edge — the
// amount stays sealed and the relationship does not. This is the finding, and
// it produces a counterexample.
module lone {
  import observer(DELAY = 0, OUT_OF_BAND = false).*
}

// **Mitigation 1 — out-of-band submission. Unlinkable HOLDS.** The record goes
// straight to a miner, so there is no on-chain event for the observer to see,
// and nothing to correlate with the delivery. The same mitigation `[FRONTRUN]`
// leans on, seen from the privacy side: it removes the observable event rather
// than hiding its content.
module offband {
  import observer(DELAY = 0, OUT_OF_BAND = true).*
}

// **Mitigation 2 — decorrelate the two events in time. Unlinkable HOLDS.**
// DELAY = 1: the delivery is one window later than the record, so no single
// window holds both halves of one payment and the pairing never becomes unique.
// This is what a client buys by not delivering the bundle in the same beat it
// publishes the record.
module decorrelated {
  import observer(DELAY = 1, OUT_OF_BAND = false).*
}

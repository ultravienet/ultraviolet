// Ultraviolet — the carrier is untrusted for funds.
//
// A payment is a sealed bundle handed to a messenger (Signal, the relay, a
// directory). The messenger may drop, delay, reorder, duplicate, and read it,
// and the claim (SPEC.md §10) is that none of that loses money: the record is
// on Bitcoin independently of the bundle, so a lost bundle is re-sendable, a
// duplicate is inert, and the payment's outcome is decided by the chain's
// first-occurrence, not by whether a message arrived.
//
// The one way a payment IS lost is not the carrier's doing — it is the
// receiver's: discarding a bundle on a *transient* verdict. That is the
// `ViewIncomplete` bug this project actually shipped (a node mid-resync
// destroyed real payments), and it is modelled here as the module that must
// violate, so it can never come back silently.
//
// What is assumed sound and NOT modelled: the seal (a tampered bundle is
// refused by the proof/lineage checks in `air`/`wallet2`, not here) and
// Bitcoin's ordering (that is `reorg.qnt`'s and `multihop.qnt`'s job). This
// model is only about delivery.
//
// Run:
//   quint verify formal/delivery.qnt --main=keeps    --invariant=noSettledPaymentLost --max-steps=10
//   quint verify formal/delivery.qnt --main=discards --invariant=noSettledPaymentLost --max-steps=8

module delivery {
  // When true, a receiver that cannot yet accept a bundle (record not
  // confirmed, or its own chain view too narrow) DISCARDS it — the bug. When
  // false, it keeps the bundle, which is the fix.
  const DISCARD_ON_TRANSIENT: bool

  // The record's life on Bitcoin, independent of the bundle.
  var recordConfirmed: bool
  // Does the receiver currently hold the sealed bundle?
  var bundleHeld: bool
  // Has the receiver accepted the payment (money in hand)?
  var accepted: bool
  // Can the payer still re-send the bundle? True until accepted — the payer
  // holds the sealed bytes and a dropped message never destroys them.
  var resendable: bool

  action init = all {
    recordConfirmed' = false,
    bundleHeld' = false,
    accepted' = false,
    resendable' = true,
  }

  // The carrier delivers the bundle (possibly a re-send).
  action deliver = all {
    resendable,
    bundleHeld' = true,
    recordConfirmed' = recordConfirmed,
    accepted' = accepted,
    resendable' = resendable,
  }

  // The carrier drops the in-flight bundle. Costs time, not money: the payer
  // can re-send (resendable stays true), and the record is untouched.
  action drop = all {
    bundleHeld' = false,
    recordConfirmed' = recordConfirmed,
    accepted' = accepted,
    resendable' = resendable,
  }

  // The carrier delivers a duplicate. Inert: holding a bundle you already hold
  // changes nothing.
  action duplicate = all {
    bundleHeld,
    bundleHeld' = true,
    recordConfirmed' = recordConfirmed,
    accepted' = accepted,
    resendable' = resendable,
  }

  // The record confirms on Bitcoin. This is what actually decides the payment.
  action confirm = all {
    not(recordConfirmed),
    recordConfirmed' = true,
    bundleHeld' = bundleHeld,
    accepted' = accepted,
    resendable' = resendable,
  }

  // The receiver scans. If the bundle is held and the record is confirmed, the
  // payment is accepted. Otherwise the verdict is transient — and the rule
  // under test decides what happens to the bundle.
  action scan = all {
    bundleHeld,
    not(accepted),
    if (recordConfirmed) all {
      // Positive: money in hand, and the payer no longer needs the bytes.
      accepted' = true,
      bundleHeld' = true,
      resendable' = false,
      recordConfirmed' = recordConfirmed,
    } else all {
      // Transient: the record has not confirmed yet.
      //
      // Keep (fix): the bundle stays held and the payment stays recoverable.
      // Discard (the ViewIncomplete bug): the receiver treats the transient
      // verdict as permanent, deletes the bundle, AND stops expecting the
      // payment — so nothing re-sends (the payer already published the record
      // and considers the payment made). Both halves matter: deleting the
      // bundle is only a loss because the giving-up means no re-send follows.
      accepted' = accepted,
      bundleHeld' = not(DISCARD_ON_TRANSIENT),
      resendable' = not(DISCARD_ON_TRANSIENT),
      recordConfirmed' = recordConfirmed,
    },
  }

  action step = any { deliver, drop, duplicate, confirm, scan }

  // **The property.** A payment whose record has confirmed on Bitcoin is never
  // lost: the receiver either already has it, or can still get it (the bundle
  // is held, or the payer can re-send it). "Lost" means confirmed on chain yet
  // impossible to accept — which is money the carrier or a bad receiver policy
  // destroyed.
  val noSettledPaymentLost: bool =
    recordConfirmed implies (accepted or bundleHeld or resendable)
}

// The fix: a receiver keeps a bundle it cannot yet accept. No carrier action
// loses a settled payment.
module keeps {
  import delivery(DISCARD_ON_TRANSIENT = false).*
}

// **The bug, kept as a reproducing violation.** A receiver that discards a
// bundle on a transient verdict — the `ViewIncomplete` misclassification —
// loses a payment that then settles on chain. If this ever stops violating,
// the model has stopped modelling the failure it was written to guard.
//
// Note it still needs `resendable` to become false for the loss to bite, which
// happens the way it did in production: nothing re-sends because the receiver
// believed it was done. Here the carrier simply never re-delivers after the
// discard, and the confirmed record has no bundle to meet.
module discards {
  import delivery(DISCARD_ON_TRANSIENT = true).*
}

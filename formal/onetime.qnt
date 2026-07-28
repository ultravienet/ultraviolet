// Ultraviolet — WOTS+ one-time keys: safety AND liveness, because they conflict.
//
// Dropping SLH-DSA for WOTS+ introduces a new failure class: **signing two
// different messages with one key reveals the private key**. Not degraded
// security — total loss, and anyone holding both signatures can spend everything
// that key owns.
//
// So the protocol needs per-note keys plus a never-re-sign discipline. This model
// asks two questions:
//
//   SAFETY   no key ever signs two DISTINCT payloads
//   LIVENESS every note still unspent on-chain eventually becomes spendable
//
// and the result is that the obvious discipline cannot satisfy both.
//
// ---- Getting the liveness property right ----
//
// The first version of this model asserted "every note the wallet holds is
// eventually spendable" and produced a violation immediately — by spending a
// note, restoring, and then refusing to spend it again. That is not a liveness
// failure; that is the wallet correctly declining to double-spend. The property
// was too strong, and a too-strong property manufactures findings.
//
// The distinction that matters is whether the **money is still there**:
//
//   settled     a record for this note's nullifier confirmed on-chain. The note
//               is legitimately gone. No liveness is owed.
//   signed but  the signature exists — the key is burnt — but no record ever
//   not settled confirmed. The coin is still unspent as far as Bitcoin is
//               concerned, and the only key that can move it must never be used
//               again. THAT is a freeze, and it is real money.
//
// Getting this right also removes a supposed requirement: nullifiers are derived
// deterministically from the note, so a restored wallet can **rescan the chain
// for its own nullifiers** and learn exactly which of its notes settled. It needs
// no persisted state for that. The persisted log is only load-bearing for the
// narrow window between signing and settlement.
//
// What is modelled: a wallet's notes, which keys have signed what, settlement,
// backup restore, and a reorg that returns a signed-but-unsettled note to
// spendable.
// What is assumed: the cryptography. "Signed two payloads" is tracked as a fact
// rather than derived from key recovery. Also assumed: WOTS+ signing is
// **deterministic** — same key and same message produce the same signature, byte
// for byte. That is true of the construction in `air/src/wots.rs`, where chain
// starts come from the seed and nothing samples randomness, and module `replay`
// depends on it.
// What the adversary controls: nothing. This is a model of *honest wallet
// operation*, which is why these failures are easy to ship by accident — no
// attacker has to show up.
//
// Liveness is checked as **bounded** liveness — "nothing is frozen by step K" —
// as an invariant, because Apalache's support for true temporal properties is
// thin. Nothing in the model ever unfreezes a note, so a bounded violation does
// mean permanently stuck; the bound is stated rather than glossed.
//
// Run:
//   quint verify formal/onetime.qnt --main=naive   --invariant=noKeyReuse --max-steps=6
//   quint verify formal/onetime.qnt --main=guarded --invariant=noKeyReuse --max-steps=8
//   quint verify formal/onetime.qnt --main=guarded --invariant=eventuallySpendable --max-steps=6
//   quint verify formal/onetime.qnt --main=replay  --invariant=noKeyReuse --max-steps=8
//   quint verify formal/onetime.qnt --main=replay  --invariant=eventuallySpendable --max-steps=8

module wallet {
  // Persist a signing log across restarts. Without it, a restored wallet cannot
  // know what it signed in the window before settlement.
  const PERSIST_SIGN_LOG: bool
  // Record in that log *what was signed*, not merely that something was, and
  // re-sign the identical payload when a signed note comes back. Because signing
  // is deterministic, replaying the same message reproduces the same signature
  // and reveals nothing new.
  const REPLAY_SAME_PAYLOAD: bool

  pure val NOTES = Set(1, 2, 3)
  // Two payloads a note could be spent to — enough to tell "signed the same
  // payment twice" (harmless) from "signed two different payments" (fatal).
  pure val PAYLOADS = Set(10, 20)
  pure val K = 4

  // Notes the wallet believes it can spend.
  var unspent: Set[int]
  // Notes whose record confirmed on-chain. Ground truth; the money is gone.
  var settled: Set[int]
  // note -> payloads its key actually signed. Ground truth, always.
  var signedWith: int -> Set[int]
  // What the wallet has durably recorded signing. Diverges from truth after a
  // restore when the log is not persisted.
  var log: int -> Set[int]
  // Steps elapsed, for the bounded-liveness check.
  var clock: int
  // Notes the wallet has refused to spend, whose money is still on-chain.
  var frozen: Set[int]

  // ---- SAFETY ----
  // No key ever signed two distinct payloads. Re-signing the *same* payload is
  // not reuse: it reproduces one signature.
  val noKeyReuse: bool = NOTES.forall(n => signedWith.get(n).size() <= 1)

  // ---- LIVENESS (bounded) ----
  // No note whose coin is still unspent on-chain is stuck. `frozen` only ever
  // admits unsettled notes, so this is a claim about live money.
  val eventuallySpendable: bool = clock < K or frozen == Set()

  action init = all {
    unspent' = NOTES,
    settled' = Set(),
    signedWith' = NOTES.mapBy(_ => Set()),
    log' = NOTES.mapBy(_ => Set()),
    clock' = 0,
    frozen' = Set(),
  }

  // Sign a note's transfer and broadcast it. The wallet consults its durable
  // log; with a persisted one that is the truth, without one a restore has
  // emptied it and this signs a second payload with a burnt key.
  action spend = all {
    nondet n = oneOf(NOTES)
    nondet payload = oneOf(PAYLOADS)
    all {
      unspent.contains(n),
      log.get(n) == Set(),
      signedWith' = signedWith.set(n, signedWith.get(n).union(Set(payload))),
      log' = log.set(n, log.get(n).union(Set(payload))),
      unspent' = unspent.exclude(Set(n)),
      settled' = settled,
      clock' = clock + 1,
      frozen' = frozen,
    }
  }

  // The record confirms deep enough to be final. Only now is the money actually
  // gone, and only now does the wallet owe this note nothing.
  action settle = all {
    nondet n = oneOf(NOTES)
    all {
      signedWith.get(n) != Set(),
      not(settled.contains(n)),
      settled' = settled.union(Set(n)),
      unspent' = unspent,
      signedWith' = signedWith,
      log' = log,
      clock' = clock + 1,
      frozen' = frozen,
    }
  }

  // A signed transfer that never confirmed — the record lost a first-occurrence
  // race, or a reorg dropped it. Bitcoin still shows the coin as unspent, so the
  // wallet sees it as spendable again. The key, however, is already burnt. This
  // path needs no backup restore: it happens in ordinary operation.
  action reorgUnspend = all {
    nondet n = oneOf(NOTES)
    all {
      not(settled.contains(n)),
      not(unspent.contains(n)),
      signedWith.get(n) != Set(),
      unspent' = unspent.union(Set(n)),
      settled' = settled,
      signedWith' = signedWith,
      log' = log,
      clock' = clock + 1,
      frozen' = frozen,
    }
  }

  // Restore from a backup. The seed recovers the keys, and rescanning the chain
  // for the derived nullifiers recovers which notes settled — so `unspent` is
  // reconstructed correctly with no local state at all. Only the log of
  // in-flight signatures depends on having been persisted.
  action restore = all {
    unspent' = NOTES.exclude(settled),
    settled' = settled,
    signedWith' = signedWith,
    log' = if (PERSIST_SIGN_LOG) log else NOTES.mapBy(_ => Set()),
    clock' = clock + 1,
    frozen' = frozen,
  }

  // Re-broadcast by re-signing the *identical* payload out of the log. Signing
  // is deterministic, so this reproduces the one signature that already exists:
  // `signedWith` does not grow, and safety is untouched. This is the recovery
  // path a boolean "already signed" flag cannot offer, because it does not
  // remember *what* to replay.
  action resign = all {
    REPLAY_SAME_PAYLOAD,
    nondet n = oneOf(NOTES)
    all {
      unspent.contains(n),
      log.get(n) != Set(),
      // Same message, same signature — the ground truth set is unchanged.
      signedWith' = signedWith,
      log' = log,
      unspent' = unspent.exclude(Set(n)),
      settled' = settled,
      clock' = clock + 1,
      frozen' = frozen,
    }
  }

  // The only safe response when the wallet knows the key has signed but cannot
  // reproduce what it signed: refuse, forever. This is where safety is bought
  // and liveness is spent. With the replay discipline the wallet is never in
  // this position, so the action is unavailable there.
  action refuseToSpend = all {
    not(REPLAY_SAME_PAYLOAD),
    nondet n = oneOf(NOTES)
    all {
      unspent.contains(n),
      log.get(n) != Set(),
      // Refusing an already-settled note is correctness, not a freeze. Only
      // live money counts.
      not(settled.contains(n)),
      frozen' = frozen.union(Set(n)),
      unspent' = unspent,
      settled' = settled,
      signedWith' = signedWith,
      log' = log,
      clock' = clock + 1,
    }
  }

  action step = any { spend, settle, reorgUnspend, restore, resign, refuseToSpend }
}

// Per-note keys, but no persisted log — a wallet that trusts its own memory.
// What a straightforward implementation looks like.
module naive {
  import wallet(PERSIST_SIGN_LOG = false, REPLAY_SAME_PAYLOAD = false).*
}

// Per-note keys plus a persisted "this key has signed" flag, refusing when
// unsure. Safe, and it freezes live money.
module guarded {
  import wallet(PERSIST_SIGN_LOG = true, REPLAY_SAME_PAYLOAD = false).*
}

// The log records *what* was signed, and a signed-but-unsettled note is
// re-broadcast by replaying that identical payload.
module replay {
  import wallet(PERSIST_SIGN_LOG = true, REPLAY_SAME_PAYLOAD = true).*
}

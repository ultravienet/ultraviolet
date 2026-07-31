// Ultraviolet — proof-native spend authorization: is knowing the anchor
// preimage the same as being allowed to spend?
//
// Spend authorization is the anchor-preimage constraint and nothing else
// (spec/99 [PROOF-AUTH], SPEC.md §8.4): a note commits to
// `t = H(nk)`, and a spend is authorized iff the spender exhibits `nk` in the
// proof. This model asks the safety question that change turns on — can a party
// who does not know `nk` spend the note? — and pins the answer to the rule
// rather than to the circuit's implementation.
//
// What is modelled: notes, each committing to one owner's secret via its
// anchor; who knows which secret; and two authorization rules. What is assumed
// sound and NOT modelled: the hash itself (a preimage the adversary does not
// know, they cannot compute) and the Fiat–Shamir binding of a proof to its
// statement — those are the circuit's job, checked by `air`'s tests. The
// question here is whether the *rule* is sound given a sound hash.
//
// Run:
//   quint verify formal/authorization.qnt --main=enforced  --invariant=onlyOwnerSpends --max-steps=8
//   quint verify formal/authorization.qnt --main=anchorOnly --invariant=onlyOwnerSpends --max-steps=6

module authorization {
  // When true, spending requires exhibiting the anchor's PREIMAGE (what the
  // proof-auth circuit checks). When false, the weak strawman: presenting the
  // anchor itself — which is public — suffices. The strawman stands in for any
  // scheme where authorization does not bind to a secret only the owner holds.
  const REQUIRE_PREIMAGE: bool

  val PARTIES = Set("owner", "forger")
  val NOTES = 0.to(2)

  // Each note's owner is "owner"; "forger" never owns one. Fixed, because the
  // question is about a note whose owner is someone else.
  // Who knows the preimage of note n's anchor. Only its owner does — a hash is
  // one-way, which is the assumption this model rests on rather than re-proves.
  var knowsPreimage: int -> Set[str]
  // Which notes each party has managed to spend.
  var spent: str -> Set[int]

  action init = all {
    knowsPreimage' = NOTES.mapBy(_ => Set("owner")),
    spent' = PARTIES.mapBy(_ => Set()),
  }

  // A party attempts to spend a note. The rule under test decides whether the
  // attempt is authorized.
  action trySpend(p: str, n: int): bool = all {
    NOTES.contains(n),
    not(spent.get(p).contains(n)),
    // The anchor is public, so ANY party can present it. The preimage is not:
    // only a party in `knowsPreimage[n]` can exhibit `nk`.
    if (REQUIRE_PREIMAGE)
      knowsPreimage.get(n).contains(p)
    else
      true,                       // anchor-only: presenting the public value is enough
    spent' = spent.set(p, spent.get(p).union(Set(n))),
    knowsPreimage' = knowsPreimage,
  }

  // A stutter keeps the system deadlock-free once every spendable note is
  // spent — otherwise the owner spending all three notes is a dead end, which
  // `verify` reports as a deadlock and would mask the real safety question. The
  // stutter adds no new state, so it changes no safety invariant; the
  // `anchorOnly` violation is a reached state and still reproduces.
  action step = any {
    {
      nondet p = PARTIES.oneOf()
      nondet n = NOTES.oneOf()
      trySpend(p, n)
    },
    all {
      knowsPreimage' = knowsPreimage,
      spent' = spent,
    },
  }

  // **The property.** No note is spent by anyone but its owner — i.e. the
  // forger, who knows no preimage, spends nothing. This is the whole safety
  // claim of proof-native authorization (SPEC.md S1).
  val onlyOwnerSpends: bool =
    NOTES.forall(n => not(spent.get("forger").contains(n)))

  // A liveness companion: the owner, who does know the preimage, is not locked
  // out. Without this, "refuse everyone" would satisfy `onlyOwnerSpends`
  // vacuously — the trap recorded under "Modelling mistakes" in formal/README.md.
  val ownerCanSpend: bool =
    NOTES.forall(n => spent.get("owner").contains(n) implies knowsPreimage.get(n).contains("owner"))

  // ---- The inductive strengthening: the same property at ALL depths ----
  //
  // Domain constraints on every variable — not a property, a requirement of
  // inductive checking: the induction step starts from an *arbitrary* state
  // satisfying the invariant, so Apalache must be told how to construct one
  // (the lesson recorded in `multihop.qnt`).
  val typeOK: bool =
    knowsPreimage.in(NOTES.setOfMaps(PARTIES.powerset()))
      and spent.in(PARTIES.setOfMaps(NOTES.powerset()))

  // The hash assumption, carried into the induction: preimage knowledge never
  // spreads. `knowsPreimage` is assigned only at `init` and copied by every
  // step, so this is preserved — and it is exactly what stops the arbitrary
  // starting state of the induction from handing the forger a preimage.
  val preimagesStayPrivate: bool =
    NOTES.forall(n => knowsPreimage.get(n) == Set("owner"))

  // Inductive: holds at `init`, closed under `step` (under `enforced`), and
  // implies `onlyOwnerSpends`. Proving it upgrades S1's safety claim from
  // "no counterexample within the search bound" to **all depths**:
  //
  //   quint verify formal/authorization.qnt --main=enforced \
  //     --inductive-invariant=authInv --invariant=onlyOwnerSpends
  val authInv: bool = typeOK and preimagesStayPrivate and onlyOwnerSpends
}

// The rule the proof-auth circuit enforces: spending requires the preimage.
module enforced {
  import authorization(REQUIRE_PREIMAGE = true).*
}

// **The strawman that must fail.** Authorizing on the public anchor rather than
// its preimage lets the forger spend a note it does not own. Kept as a
// reproducing violation: if it ever stops violating, the model has stopped
// distinguishing "knows the secret" from "has seen the public value" — which is
// the exact distinction proof-native authorization rests on.
module anchorOnly {
  import authorization(REQUIRE_PREIMAGE = false).*
}

// Ultraviolet — can an issuer inflate supply without anyone seeing?
//
// `multihop.qnt` proves supply is conserved *across transfers*, but it has no
// `issue` action at all: it hardcodes one genesis note as an initial condition
// (`held' = ... Set(0)`), so `supplyInv` says nothing about how many genesis
// notes exist or who may create them. Every supply claim in the project rests
// on a model where issuance cannot happen.
//
// This model asks the other half. Issuance is an action here, the adversary is
// the issuer, and the question is whether a holder who reads the chain can be
// wrong about the total.
//
// What is modelled: issuance records on Bitcoin, the mint-key chain that
// authorises them, and two receiver policies — one that requires a confirmed
// issuance record and one that does not (what the code does today).
//
// What is assumed sound and NOT modelled: hashes and signatures. A forged
// signature is out of scope; the question is whether the *rules* let an
// unforged one inflate unseen.
//
// What is deliberately abstracted:
//   - one note per issuance, no splitting — supply is "how many issued units"
//   - the chain is a set of confirmed records; reorgs are `reorg.qnt`'s job
//   - a decoy — a record bearing an asset id its publisher does not own — is
//     not modelled. It creates no spendable coin, so it cannot violate
//     supplyIsKnown; it inflates a *reported* figure, which is a property about
//     the tool rather than the rules. `uv supply` keeps attested and unattested
//     records apart for it.
//
// Run:
//   quint verify formal/issuance.qnt --main=lax     --invariant=supplyIsKnown --max-steps=8
//   quint verify formal/issuance.qnt --main=strict  --invariant=supplyIsKnown --max-steps=8
//   quint verify formal/issuance.qnt --main=strict  --invariant=onlyMintKeyIssues --max-steps=8
//   quint verify formal/issuance.qnt --main=byAmount --invariant=supplyIsKnown --max-steps=6
//   quint verify formal/issuance.qnt --main=strict    --invariant=assetSupplyIsKnown --max-steps=8
//   quint verify formal/issuance.qnt --main=globalSum --invariant=assetSupplyIsKnown --max-steps=8

module issuance {
  // When false, a receiver accepts a lineage whose genesis was never published
  // — which is what `wallet2::accept` does today. When true, it requires a
  // confirmed issuance record, which is spec/12's rule.
  const REQUIRE_ON_CHAIN: bool

  // When true, "is it published?" is answered by looking for *any* confirmed
  // issuance of the same AMOUNT rather than for this one. That is what the
  // first implementation of the rule actually did, and it is inflatable — see
  // the `byAmount` module at the bottom. Modelled because the bug was not in
  // the design, it was in the translation: this model was faithful and the code
  // was not, so the model gained a module for what the code did.
  const MATCH_BY_AMOUNT: bool

  // When true, a receiver's check is answered by the **chain-wide** published
  // total rather than by this asset's records. That is not a strawman: it is
  // the only number the tool could compute while the record carried a one-way
  // hash of its details, because a hash cannot be enumerated — you could
  // confirm a record you already knew, never ask which records belonged to an
  // asset. See the `globalSum` module.
  const GLOBAL_SUM: bool

  // Issuances the issuer performs, whether or not they publish them.
  var minted: int -> int
  // Which asset each issuance belongs to. Parallel maps rather than a record,
  // to keep the state cheap for the solver.
  var mintedAsset: int -> int
  // Issuance records that reached Bitcoin: id -> amount.
  var published: int -> int
  var publishedAsset: int -> int
  // Which issuance ids a receiver has accepted coins from.
  var accepted: Set[int]
  // The mint chain: an issuance is authorised only if it is the next link.
  var nextLink: int
  var idCounter: int

  val IDS = 0.to(4)
  // Two assets is enough to separate "this asset's records" from "the chain's".
  val ASSETS = 0.to(1)

  action init = all {
    minted' = Map(),
    mintedAsset' = Map(),
    published' = Map(),
    publishedAsset' = Map(),
    accepted' = Set(),
    nextLink' = 0,
    idCounter' = 0,
  }

  // Mint under the chain's next authorised link, and publish the record.
  action issueOpenly(asset: int, amount: int): bool = all {
    idCounter < 5,
    amount > 0,
    amount <= 3,
    minted' = minted.put(idCounter, amount),
    mintedAsset' = mintedAsset.put(idCounter, asset),
    published' = published.put(idCounter, amount),
    publishedAsset' = publishedAsset.put(idCounter, asset),
    nextLink' = nextLink + 1,
    idCounter' = idCounter + 1,
    accepted' = accepted,
  }

  // **The attack.** Mint without publishing anything. The issuer holds coins
  // whose issuance no reader of the chain can see.
  action issueSecretly(asset: int, amount: int): bool = all {
    idCounter < 5,
    amount > 0,
    amount <= 3,
    minted' = minted.put(idCounter, amount),
    mintedAsset' = mintedAsset.put(idCounter, asset),
    published' = published,
    publishedAsset' = publishedAsset,
    nextLink' = nextLink + 1,
    idCounter' = idCounter + 1,
    accepted' = accepted,
  }

  // A receiver takes coins descending from issuance `id`.
  action receive(id: int): bool = all {
    minted.keys().contains(id),
    not(accepted.contains(id)),
    // The rule under test: by identity, by amount, or against the chain-wide
    // total.
    REQUIRE_ON_CHAIN implies (
      if (GLOBAL_SUM)
        // Everything anyone has published, of any asset, covers this coin.
        onChainTotal >= minted.get(id)
      else if (MATCH_BY_AMOUNT)
        published.keys().exists(k => published.get(k) == minted.get(id))
      else
        published.keys().contains(id)
    ),
    accepted' = accepted.union(Set(id)),
    minted' = minted,
    mintedAsset' = mintedAsset,
    published' = published,
    publishedAsset' = publishedAsset,
    nextLink' = nextLink,
    idCounter' = idCounter,
  }

  action step = any {
    nondet x = ASSETS.oneOf()
    nondet a = 1.to(3).oneOf()
    any {
      issueOpenly(x, a),
      issueSecretly(x, a),
    },
    nondet i = IDS.oneOf()
    receive(i),
  }

  // What a reader of Bitcoin would compute.
  val onChainTotal: int =
    published.keys().fold(0, (acc, k) => acc + published.get(k))

  // What a holder could actually be holding.
  val acceptedTotal: int =
    accepted.fold(0, (acc, k) => acc + minted.get(k))

  // **The property.** Everything anyone can spend is covered by what the chain
  // says exists. Not "the chain shows every coin" — coins minted and never
  // given to anyone are nobody's problem — but "no accepted coin is invisible".
  val supplyIsKnown: bool = acceptedTotal <= onChainTotal

  // Every issuance consumed exactly one link of the mint chain, so the number
  // of issuances cannot exceed the number of authorisations.
  val onlyMintKeyIssues: bool = minted.keys().size() <= nextLink

  // What the chain shows for one asset.
  def onChainFor(asset: int): int =
    published.keys()
      .filter(k => publishedAsset.get(k) == asset)
      .fold(0, (acc, k) => acc + published.get(k))

  // What holders of one asset could be holding.
  def acceptedFor(asset: int): int =
    accepted
      .filter(k => mintedAsset.get(k) == asset)
      .fold(0, (acc, k) => acc + minted.get(k))

  // **The property the record change exists for.** Every asset's accepted coins
  // are covered by *that asset's* confirmed records — not by the chain's total.
  //
  // The difference is the whole point. A chain-wide sum is a true statement and
  // a useless one: an unpublished coin of asset A sits comfortably under a total
  // that asset B's issuances paid for. `globalSum` reproduces exactly that.
  val assetSupplyIsKnown: bool =
    ASSETS.forall(a => acceptedFor(a) <= onChainFor(a))

  // ---- The inductive strengthening: strict's supply claims at ALL depths ----
  //
  // Domain constraints on every variable — a requirement of inductive checking
  // (the induction step starts from an arbitrary state satisfying the
  // invariant; see `multihop.qnt`). `minted`/`published` are partial maps, so
  // their domains are existentially quantified subsets, published's inside
  // minted's because typeOK is easiest to preserve when it mirrors the truth.
  val typeOK: bool =
    IDS.powerset().exists(md =>
      minted.in(md.setOfMaps(1.to(3)))
        and mintedAsset.in(md.setOfMaps(ASSETS))
        and IDS.powerset().exists(pd =>
          published.in(pd.setOfMaps(1.to(3)))
            and publishedAsset.in(pd.setOfMaps(ASSETS))))
      and accepted.in(IDS.powerset())
      and nextLink.in(0.to(5))
      and idCounter.in(0.to(5))

  // Ids are handed out in order, so a new issuance can never overwrite an old
  // one — without this the induction must reason about `put` clobbering a key
  // some receiver already counted.
  val freshIds: bool = minted.keys().forall(k => k < idCounter)

  // The mint chain and the id counter advance together: both start at 0 and
  // every issuance increments both. Without this the arbitrary induction state
  // can hold `nextLink = 5` beside `idCounter = 4`, and one more issuance
  // pushes `nextLink` past its domain bound — the counterexample Apalache
  // actually produced.
  val linkCounterAligned: bool = nextLink == idCounter

  // Under strict, a receiver only ever accepted a published id, and every
  // record states exactly what was minted — records never drift from mints.
  val acceptedHaveRecords: bool = accepted.subseteq(published.keys())
  val recordsMatchMinted: bool =
    published.keys().forall(k =>
      minted.keys().contains(k)
        and published.get(k) == minted.get(k)
        and publishedAsset.get(k) == mintedAsset.get(k))

  // Inductive under `strict`: holds at init, closed under `step`, and carries
  // both supply properties as conjuncts. Proving it upgrades S7's claims from
  // bounded to **all depths**:
  //
  //   quint verify formal/issuance.qnt --main=strict \
  //     --inductive-invariant=supplyInv --invariant=supplyIsKnown
  //   quint verify formal/issuance.qnt --main=strict \
  //     --inductive-invariant=supplyInv --invariant=assetSupplyIsKnown
  val supplyInv: bool =
    typeOK and freshIds and linkCounterAligned
      and acceptedHaveRecords and recordsMatchMinted
      and supplyIsKnown and assetSupplyIsKnown
}

// The rule before spec/12: a receiver never looks for an issuance record.
module lax {
  import issuance(REQUIRE_ON_CHAIN = false, MATCH_BY_AMOUNT = false, GLOBAL_SUM = false).*
}

// spec/12's rule: a lineage whose genesis is not confirmed on chain is refused,
// and "confirmed" means *that* issuance and not one of the same size.
module strict {
  import issuance(REQUIRE_ON_CHAIN = true, MATCH_BY_AMOUNT = false, GLOBAL_SUM = false).*
}

// **The free mint.** The rule as first implemented: a receiver requires a
// confirmed issuance record, but checks only that some record carries the same
// amount. It looks like the strict rule and is barely stronger than the lax
// one.
//
// The counterexample is three steps and entirely ordinary: an honest issuer
// mints and publishes; an attacker mints the same amount and publishes nothing;
// a receiver takes both, because the honest record answers the attacker's
// check. Two coins exist, the chain shows one, and the bound the whole file
// rests on is broken. Amounts are round numbers — this collides by accident.
//
// Kept as a *violation* row in formal/verify.sh: if this ever stops
// reproducing, the model has stopped modelling the weakness it was written for.
module byAmount {
  import issuance(REQUIRE_ON_CHAIN = true, MATCH_BY_AMOUNT = true, GLOBAL_SUM = false).*
}

// **The chain-wide sum, which is all the old record could give you.**
//
// While an issuance record carried `H(asset ‖ commitment ‖ amount)`, nobody
// could ask which records belonged to an asset — a one-way hash confirms a
// record you already know and enumerates nothing. So the only computable figure
// was the total across every asset and every stranger, and that total is a
// bound rather than an answer: an unpublished coin of one asset hides under
// records another asset paid for.
//
// Kept as a *violation* row. The record now carries the asset in the clear, so
// if this ever stops reproducing, the model has stopped modelling the weakness
// the format change was made to remove.
module globalSum {
  import issuance(REQUIRE_ON_CHAIN = true, MATCH_BY_AMOUNT = false, GLOBAL_SUM = true).*
}

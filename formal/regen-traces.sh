#!/usr/bin/env bash
# Regenerate the ITF traces that the Rust conformance tests replay against the
# real code. Run this ONLY when a model changes — the committed traces are the
# model's frozen testimony, and the conformance tests (e.g.
# kernel2/tests/conformance_authorization.rs) require the real code to agree
# with them. A regenerated trace that changes what the code must do is a real
# review event, not a refresh.
#
# Needs quint (see formal/verify.sh for the pinned version). CI does not run
# this — the traces are committed so the Rust tests need no quint.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p formal/traces

# authorization: a positive owner-spends execution, and the forger-steals
# counterexample the strawman produces.
quint run    formal/authorization.qnt --main=enforced   --max-steps=6 --seed=0x1 \
  --out-itf formal/traces/authorization_enforced.itf.json
quint verify formal/authorization.qnt --main=anchorOnly --invariant=onlyOwnerSpends --max-steps=6 \
  --out-itf formal/traces/authorization_anchorOnly.itf.json

# issuance: a positive strict execution where every accepted coin has its own
# record on chain, and the byAmount free-mint counterexample. The seed is pinned
# because `quint run` is random and the conformance test needs a run that
# actually accepts something AND covers S9: seed 0x2 lands four issuances, TWO
# per asset, all accepted — so the per-identity gate is exercised with same-asset
# siblings on chain, which is what "one asset id cannot show two supplies" needs.
quint run    formal/issuance.qnt --main=strict   --max-steps=10 --seed=0x2 \
  --out-itf formal/traces/issuance_strict.itf.json
quint verify formal/issuance.qnt --main=byAmount --invariant=supplyIsKnown --max-steps=6 \
  --out-itf formal/traces/issuance_byAmount.itf.json

# multihop: the 8-step inflation counterexample (per-hop checks do not
# compose — the attack that started the formal program), and a positive fixed
# execution. Seed 0x2 pinned because the conformance test needs a run where an
# honest wallet actually accepts something; 0x2 lands dave holding note 2 with
# its record on chain.
quint verify formal/multihop.qnt --main=buggy --invariant=noInflation --max-steps=8 \
  --out-itf formal/traces/multihop_buggy.itf.json
quint run    formal/multihop.qnt --main=fixed --max-steps=10 --seed=0x2 \
  --out-itf formal/traces/multihop_fixed.itf.json

# baserail: a COMPLETED split payment (the liveness rung) — two part-payments
# of 1 against TARGET 2, both settled, delivered = 2. Seed 0x2 at 20 steps
# pinned because random runs usually settle one part and wander; the
# conformance test requires a schedule that actually finishes.
quint run formal/baserail.qnt --main=splitPayment --max-steps=20 --seed=0x2 \
  --out-itf formal/traces/baserail_splitPayment.itf.json

# reorg: the shallow flip (accept at depth, reorg flips first occurrence, the
# non-reconciling wallet never notices) and the orphaned-issuance case (spends
# survive, genesis does not — settlement-only reconciliation is blind to it).
quint verify formal/reorg.qnt --main=shallow --invariant=acceptedStaysValid --max-steps=8 \
  --out-itf formal/traces/reorg_shallow.itf.json
quint verify formal/reorg.qnt --main=genesisUnchecked --invariant=acceptedHasLiveGenesis --max-steps=8 \
  --out-itf formal/traces/reorg_genesisUnchecked.itf.json

echo "traces regenerated — re-run the conformance tests and review any change:"
echo "  cargo test -p uv-kernel2  --test conformance_authorization"
echo "  cargo test -p uv-wallet2  --test conformance_issuance"
echo "  cargo test -p uv-wallet2  --test conformance_multihop"
echo "  cargo test -p uv-wallet2  --test conformance_reorg"
echo "  cargo test -p uv-wallet2  --test conformance_baserail"

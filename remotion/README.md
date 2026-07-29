# Ultraviolet film series

Six 1920 × 1080 Remotion films:

- `UltravioletComparison` — the original 60-second field comparison.
- `ShieldedCsvExplainer` — a 45-second Shielded CSV architecture explainer.
- `TaprootAssetsExplainer` — a 45-second Taproot Assets explainer.
- `RgbExplainer` — a 45-second RGB explainer.
- `UltravioletBenchmarks` — a 50-second film about the measured prover.
- `FormalVerificationExplainer` — a 75-second film about Ultraviolet's formal
  methods, their trust boundary, and the 2026 Collatz/Lean soundness incident.

## Preview and render

```bash
npm install
npm run studio
npm run render
npm run render:series
```

Each render and poster is written to `out/`. Individual `render:*` and
`still:*` scripts are available for every composition.

## Story

1. Four related architectures on the same Bitcoin base layer.
2. UTXO-bound ownership versus client-side notes and ordered records.
3. The nearly identical public spend surface of Shielded CSV and Ultraviolet,
   separated from Ultraviolet's deliberately public issuance records.
4. Classical Schnorr authorization versus Ultraviolet's signature-free
   anchor-preimage proof.
5. The different lesson Ultraviolet takes from RGB, Taproot Assets, and
   Shielded CSV.
6. An explicit maturity check: RGB and Taproot Assets ship on mainnet,
   Shielded CSV is a paper, and Ultraviolet is unaudited research with a working
   core and public signet demo.

The comparison copy is intentionally narrower than the full protocol analysis.
Its source of truth is [the related-work section of `../SPEC.md`](../SPEC.md#12-related-work),
with status language aligned to [`../README.md`](../README.md).

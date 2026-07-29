# Ultraviolet film series

Five 1920 × 1080 Remotion films:

- `UltravioletComparison` — the original 60-second field comparison.
- `ShieldedCsvExplainer` — a 45-second Shielded CSV architecture explainer.
- `TaprootAssetsExplainer` — a 45-second Taproot Assets explainer.
- `RgbExplainer` — a 45-second RGB explainer.
- `UltravioletBenchmarks` — a 50-second film about the measured prover.

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

1. Four architectures on the same Bitcoin base layer.
2. UTXO-bound ownership versus client-side notes and nullifier records.
3. What each receiver learns about amounts and history.
4. Classical Schnorr ownership versus Ultraviolet's hash-based WOTS+ path.
5. An explicit maturity check: RGB and Taproot Assets ship on mainnet,
   Shielded CSV is a paper, and Ultraviolet is unaudited research with a working
   core and public signet demo.

The comparison copy is intentionally narrower than the full protocol analysis.
Its source of truth is [`../spec/10-COMPARISONS.md`](../spec/10-COMPARISONS.md),
with status language aligned to [`../README.md`](../README.md).

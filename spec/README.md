# Where the spec went

The specification is a **whitepaper at the repository root**:
[`SPEC.md`](../SPEC.md) — abstract, threat model, cryptographic foundations,
notes, records, proofs, issuance, delivery, verification, related work,
limitations, and a constraint map for auditors.

It was thirteen chapter files in this directory, then one merged file, now a
whitepaper rewritten from scratch. The chapters drifted out of step with each
other repeatedly; several subsystems were **deleted** rather than carried, because they described
mechanisms nobody had built. The
[journal](https://ultravienet.github.io/ultraviolet/journal.html) has the
reasoning.

What stays here:

- [`99-OPEN-PROBLEMS.md`](99-OPEN-PROBLEMS.md) — the only list of what is
  unfinished. A living register cited by slug (`[SUPPLY]`, `[FRONTRUN]`, …),
  not a specification, which is why it did not merge.

The claim-by-claim coverage of the formal models against the code is
[`formal/CLAIMS.md`](../formal/CLAIMS.md).

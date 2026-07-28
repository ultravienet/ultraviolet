#!/usr/bin/env python3
"""Constraint mutation testing: delete each constraint, require a test to fail.

Why this exists. The AIR's soundness is every column being constrained, and the
test suite's blind spot — stated in AUDIT-BRIEF.md §1 — is that it only explores
witnesses somebody thought of. This tool asks the complementary question: is
every *constraint* actually load-bearing against the tests we have? A constraint
whose deletion changes no test's verdict is either redundant (worth knowing) or
guarding against a witness no test builds (worth much more than knowing).

What it does. Both AIR files mark every constraint with a `// N.` comment. For
each such region this script comments out the region's `assert` statements (and
the `eval_permutation` call, for constraint 1), rebuilds, runs the fast half of
the suite, and records KILLED (some test failed) or SURVIVED (all green).
Originals are restored after every run, and on interrupt.

Deliberately NOT in CI: a full sweep is ~33 rebuild+test cycles. Run it by hand
after touching the constraints, and record the result in air/COVERAGE.md —
the same manual-verification-plus-ledger discipline as formal/.

    python3 air/mutants.py            # full sweep, ~45-60 min
    python3 air/mutants.py 27 32      # just constraints 27 and 32
"""

import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FILES = [
    ROOT / "air" / "src" / "wots_air.rs",
    ROOT / "air" / "src" / "transfer_air.rs",
]
MARKER = re.compile(r"^\s*// (\d+[a-z]?)\.")

# The fast, high-signal half of the suite. The negative-test suite in
# air/src/prove.rs (--lib) is the main killer; the two integration tests are
# the forgery regressions. The timing/ratio tests are skipped — they kill no
# constraints and cost a minute each.
TEST_CMD = [
    ["cargo", "test", "-q", "-p", "uv-air", "--lib"],
    ["cargo", "test", "-q", "-p", "uv-air", "--test", "trace_height_is_pinned",
     "--test", "sponge_lanes_are_tied", "--test", "poseidon2_differential"],
    ["cargo", "test", "-q", "-p", "uv-wallet2", "--test", "forged_lineage_is_rejected"],
]


def regions(path: Path):
    """Yield (label, start_line, end_line) for each `// N.` region."""
    lines = path.read_text().splitlines()
    marks = [(m.group(1), i) for i, l in enumerate(lines) if (m := MARKER.match(l))]
    for k, (label, start) in enumerate(marks):
        end = marks[k + 1][1] if k + 1 < len(marks) else len(lines)
        yield label, start, end


def mutate(path: Path, start: int, end: int) -> int:
    """Comment out assert statements (and eval_permutation) in [start, end).

    Returns how many statements were removed. Multi-line statements are tracked
    to their terminating `;` by parenthesis depth.
    """
    lines = path.read_text().splitlines(keepends=True)
    removed = 0
    i = start
    while i < end:
        stripped = lines[i].lstrip()
        starts_stmt = (
            not stripped.startswith("//")
            and (".assert_" in stripped or stripped.startswith("eval_permutation"))
        )
        if not starts_stmt:
            i += 1
            continue
        depth = 0
        j = i
        while j < len(lines):
            depth += lines[j].count("(") - lines[j].count(")")
            done = depth <= 0 and lines[j].rstrip().endswith(";")
            lines[j] = "// MUTANT " + lines[j]
            j += 1
            if done:
                break
        removed += 1
        i = j
    path.write_text("".join(lines))
    return removed


def run_tests() -> bool:
    """True if every test command passes (mutant SURVIVED)."""
    for cmd in TEST_CMD:
        if subprocess.run(cmd, cwd=ROOT, capture_output=True).returncode != 0:
            return False
    return True


def main():
    only = set(sys.argv[1:])
    backups = {p: p.with_suffix(".rs.orig") for p in FILES}
    for p, b in backups.items():
        shutil.copy(p, b)

    print("baseline (no mutation) ...", flush=True)
    if not run_tests():
        sys.exit("baseline is red — fix the suite before measuring it")
    print("baseline green\n")

    results = []
    try:
        for path in FILES:
            for label, start, end in regions(path):
                if only and label not in only:
                    continue
                n = mutate(path, start, end)
                if n == 0:
                    # A marker with no asserts of its own (e.g. prose headers).
                    shutil.copy(backups[path], path)
                    continue
                survived = run_tests()
                shutil.copy(backups[path], path)
                verdict = "SURVIVED" if survived else "killed"
                results.append((path.name, label, n, verdict))
                print(f"{path.name:18} constraint {label:>3}  "
                      f"({n} stmt{'s' if n > 1 else ''} removed)  {verdict}",
                      flush=True)
    finally:
        for p, b in backups.items():
            shutil.copy(b, p)
            b.unlink()

    survivors = [r for r in results if r[3] == "SURVIVED"]
    print(f"\n{len(results)} mutants, {len(survivors)} survived")
    if survivors:
        print("survivors — each is a constraint no test defends:")
        for f, label, n, _ in survivors:
            print(f"  {f} constraint {label}")
        sys.exit(1)


if __name__ == "__main__":
    main()

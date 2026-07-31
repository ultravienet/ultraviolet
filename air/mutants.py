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
Originals are restored after every run, and on interrupt — see `main` for what
"interrupt" does and does not cover, and for the guard that catches the rest.

Deliberately NOT in CI: a full sweep is ~33 rebuild+test cycles. Run it by hand
after touching the constraints, and record the result in air/COVERAGE.md —
the same manual-verification-plus-ledger discipline as formal/.

    python3 air/mutants.py            # full sweep, ~45-60 min
    python3 air/mutants.py 27 32      # just constraints 27 and 32
"""

import re
import shutil
import signal
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FILES = [
    # The one money-path circuit, and the only source this sweep touches.
    # If a second consensus circuit is ever added it must be listed here, or the
    # sweep will report a full kill over half the money path.
    ROOT / "air" / "src" / "authproto_air.rs",
]
MARKER = re.compile(r"^\s*// (\d+[a-z]?)\.")

# Test targets that cost minutes and kill no constraints: timing ratios and the
# randomness check. Everything else in `air/tests/` runs.
SKIP_TESTS = {"hiding_is_randomized"}


def air_test_targets():
    """Every integration test in `air/tests/`, discovered rather than listed.

    This was a hand-written allowlist, and it went stale the first time it
    mattered: `constraints_are_isolated.rs` — the file whose entire purpose is
    isolating constraints — was not in it. So the sweep never ran the tests
    written to kill mutants, reported them as survivors, and `COVERAGE.md`
    recorded a constraint as defended when nothing in the sweep had checked it.
    A list of tests that must be kept in step with a directory is a list that
    will eventually disagree with it; read the directory.
    """
    names = sorted(
        f.stem for f in (ROOT / "air" / "tests").glob("*.rs") if f.stem not in SKIP_TESTS
    )
    cmd = ["cargo", "test", "-q", "-p", "uv-air"]
    for n in names:
        cmd += ["--test", n]
    return cmd


TEST_CMD = [
    # The negative-test suite in air/src/prove.rs is the main killer. `--lib`
    # also carries `authproto_air.rs`'s own constraint tests.
    ["cargo", "test", "-q", "-p", "uv-air", "--lib"],
    air_test_targets(),
    # The proof-native circuit's killers live in kernel2: the native prove/verify
    # negative tests (inflation, transplant, wrong owner_pk, foreign nullifier)
    # and the authorization conformance replay (the forger must be refused). A
    # deleted authproto constraint that these do not catch is a survivor to be
    # given its own isolating test, exactly as `constraints_are_isolated.rs` does
    # for the production circuit.
    ["cargo", "test", "-q", "-p", "uv-kernel2", "--lib"],
    ["cargo", "test", "-q", "-p", "uv-kernel2", "--test", "conformance_authorization"],
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
    # Args split by shape: bare integers (with an optional trailing letter) are
    # constraint labels; anything else is a file stem selecting which source(s)
    # to sweep. `mutants.py authproto_air` sweeps one circuit; `mutants.py
    # authproto_air 12` sweeps one constraint of it.
    raw = sys.argv[1:]
    only = {a for a in raw if re.fullmatch(r"\d+[a-z]?", a)}
    file_sel = {a for a in raw if a not in only}
    files = [p for p in FILES if not file_sel or p.stem in file_sel]
    if file_sel and not files:
        sys.exit(f"no swept file matches {file_sel}; known: {[p.stem for p in FILES]}")
    backups = {p: p.with_suffix(".rs.orig") for p in files}

    # --- Three guards, all added after this tool silently left a hole ---
    #
    # On 2026-07-28 a run was killed by a 10-minute command timeout while
    # constraint 9 was mutated. The `finally` below did not run: SIGTERM
    # terminates CPython without unwinding, so "restored on interrupt" was only
    # ever true for Ctrl-C. A circuit source was left with constraint 9
    # commented out — a real soundness hole in the working tree of a repository
    # whose whole convention is one amended commit and a force push.
    #
    # The next run then made it worse. Its first act was to copy the source over
    # the backup, so the mutated file became the "original" and the only good
    # copy was gone. The sweep that followed reported 31 mutants and 6 survivors
    # against a circuit already missing a constraint, and every verdict in it
    # was void — it looked like an ordinary result, only smaller.

    # 1. Never measure a file that is already mutated, and never overwrite a
    #    backup with one. This is the guard that works even against SIGKILL,
    #    which no handler can catch.
    dirty = [p for p in FILES if "// MUTANT" in p.read_text()]
    if dirty:
        print("REFUSING TO RUN — these sources are already mutated:", file=sys.stderr)
        for p in dirty:
            print(f"  {p}", file=sys.stderr)
        print("\nA previous run died before restoring. Recover FIRST, or this run",
              file=sys.stderr)
        print("will copy the damage over the backup and measure a circuit that is",
              file=sys.stderr)
        print("missing a constraint:\n", file=sys.stderr)
        for p in FILES:
            b = p.with_suffix(".rs.orig")
            if b.exists():
                print(f"  cp {b} {p}      # the surviving backup", file=sys.stderr)
        print(f"  git checkout {' '.join(str(p) for p in dirty)}", file=sys.stderr)
        sys.exit(1)

    # 2. A leftover backup is itself evidence of a death mid-run. Harmless once
    #    the check above passes, but worth saying rather than silently clobbering.
    stale = [b for b in backups.values() if b.exists()]
    if stale:
        print(f"note: {len(stale)} stale .orig from an earlier run; sources are clean, "
              f"replacing them")

    for p, b in backups.items():
        shutil.copy(p, b)

    # 3. Turn the signals that CAN be caught into an exception, so `finally`
    #    unwinds. SIGKILL is still unstoppable, which is why guard 1 exists.
    def _restore_and_die(signum, _frame):
        for p, b in backups.items():
            if b.exists():
                shutil.copy(b, p)
                b.unlink()
        sys.exit(f"killed by signal {signum}; sources restored")

    for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(sig, _restore_and_die)

    print("baseline (no mutation) ...", flush=True)
    if not run_tests():
        sys.exit("baseline is red — fix the suite before measuring it")
    print("baseline green\n")

    results = []
    try:
        for path in files:
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
        # Say it out loud. A restore that happens silently is a restore nobody
        # checks, and the failure this guards against was invisible precisely
        # because nothing ever mentioned the file again.
        left = [p for p in files if "// MUTANT" in p.read_text()]
        if left:
            sys.exit(f"RESTORE FAILED — still mutated: {left}")
        print("sources restored and verified clean")

    survivors = [r for r in results if r[3] == "SURVIVED"]
    print(f"\n{len(results)} mutants, {len(survivors)} survived")
    if survivors:
        print("survivors — each is a constraint no test defends:")
        for f, label, n, _ in survivors:
            print(f"  {f} constraint {label}")
        sys.exit(1)


if __name__ == "__main__":
    main()

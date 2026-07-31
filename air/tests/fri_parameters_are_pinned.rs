//! The FRI parameters are a consensus constant, and until 2026-07-30 nothing said so.
//!
//! **What this file exists to stop.** `LOG_BLOWUP` and `NUM_QUERIES` decide how
//! many bits of soundness a proof carries. They were defined with a comment
//! claiming "~100 bits" and nothing else: no runtime check, no test, and no
//! justification in the specification. Nothing in the workspace referenced
//! either name, so **editing `NUM_QUERIES` to 1 left the whole suite green** —
//! the prover and the verifier read the same constant, so a two-bit proof
//! verified without complaint.
//!
//! That is the same shape as the trace height, which was the vector for this
//! project's only total forgery: a value everything depended on and nothing
//! enforced. The height now has a runtime check, a typed rejection and its own
//! test file. This is the equivalent for FRI.
//!
//! **The tests that matter here are the ones that weaken things.** A test which
//! only asserts the current numbers pass would go green against a check that
//! always returns `Ok`. So most of this file hands `check_fri_strength`
//! configurations that must be refused, including the exact one the old code
//! would have accepted.

use uv_air::prove::{check_fri_strength, conjectured_soundness_bits, FriTooWeak};

/// The target, restated so a change to it is a change to this test.
const TARGET: usize = 100;

// ---------------------------------------------------------------------------
// The check refuses weak configurations. This is the half that can fail.
// ---------------------------------------------------------------------------

/// The exact edit that used to be invisible.
///
/// One query at blowup 16 plus 16 grinding bits is 20 bits of soundness — a
/// forgery costs about a million attempts. Before this check, that configuration
/// produced proofs the verifier accepted and no test noticed.
#[test]
fn one_query_is_refused() {
    let verdict = check_fri_strength(4, 1, 16);
    assert_eq!(
        verdict,
        Err(FriTooWeak {
            bits: 20,
            required: TARGET
        }),
        "a 1-query configuration must be refused; this is the edit that was \
         silently accepted until 2026-07-30"
    );
}

/// Blowup 1 — no redundancy at all — is refused even with the shipped query count.
#[test]
fn no_blowup_is_refused() {
    assert!(
        check_fri_strength(1, 25, 16).is_err(),
        "blowup 1 gives 25 + 16 = 41 bits and must be refused"
    );
}

/// Removing the grinding is refused when it takes the total under the target.
#[test]
fn dropping_the_proof_of_work_is_refused_when_it_matters() {
    // 21 queries x 4 = 84, plus 16 grinding = 100: exactly at the target.
    assert!(
        check_fri_strength(4, 21, 16).is_ok(),
        "84 + 16 = 100 is the line"
    );
    // The same queries with the grinding removed is 84, and must fail.
    assert_eq!(
        check_fri_strength(4, 21, 0),
        Err(FriTooWeak {
            bits: 84,
            required: TARGET
        }),
        "grinding is part of the budget; removing it must be caught"
    );
}

/// Everything below the target is refused, and everything at or above it is not.
///
/// Walks the boundary rather than sampling it, because an off-by-one in a
/// comparison is exactly the bug a hand-picked pair of cases misses.
#[test]
fn the_boundary_is_exactly_the_target() {
    for queries in 0..40usize {
        let bits = conjectured_soundness_bits(4, queries, 16);
        let verdict = check_fri_strength(4, queries, 16);
        if bits >= TARGET {
            assert!(
                verdict.is_ok(),
                "{queries} queries gives {bits} bits, which clears {TARGET}, but was refused"
            );
        } else {
            assert_eq!(
                verdict,
                Err(FriTooWeak {
                    bits,
                    required: TARGET
                }),
                "{queries} queries gives {bits} bits, under {TARGET}, and must be refused"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// The arithmetic itself, and what the shipped numbers come to.
// ---------------------------------------------------------------------------

/// The formula is `queries x log_blowup + grinding`, and this pins it.
///
/// Without this, `conjectured_soundness_bits` could return a large constant and
/// every refusal test above would still pass.
#[test]
fn the_formula_is_queries_times_blowup_plus_grinding() {
    assert_eq!(conjectured_soundness_bits(4, 25, 16), 116);
    assert_eq!(conjectured_soundness_bits(4, 25, 0), 100);
    assert_eq!(conjectured_soundness_bits(1, 1, 0), 1);
    assert_eq!(conjectured_soundness_bits(8, 10, 20), 100);
    // Monotone in each argument, which is what makes it a budget.
    assert!(conjectured_soundness_bits(4, 26, 16) > conjectured_soundness_bits(4, 25, 16));
    assert!(conjectured_soundness_bits(5, 25, 16) > conjectured_soundness_bits(4, 25, 16));
    assert!(conjectured_soundness_bits(4, 25, 17) > conjectured_soundness_bits(4, 25, 16));
}

/// The shipped configuration, stated as a literal.
///
/// `blowup 16 (log 4), 25 queries, 16 grinding bits` = **116 conjectured bits**,
/// against a 100-bit target. Changing any of the three changes this number, and
/// a consensus change should have to edit a test that says so out loud.
///
/// A compile-time assertion in `prove.rs` already refuses to build a
/// below-target configuration; this records what the passing one actually is,
/// since "it builds" tells a reader nothing about the margin.
#[test]
fn the_shipped_parameters_are_116_bits_against_a_100_bit_target() {
    let bits = check_fri_strength(4, 25, 16).expect("the shipped parameters must clear the target");
    assert_eq!(
        bits, 116,
        "the shipped FRI configuration is 116 conjectured bits"
    );
    assert!(
        bits >= TARGET,
        "116 against a {TARGET}-bit target leaves 16 bits of margin"
    );
}

/// The conjectured bound is not the proven one, and the gap is affordable.
///
/// Recorded as a test rather than a comment so the trade stays visible: doubling
/// the queries to 50 clears 200 conjectured bits, which is roughly what holding
/// this system to *proven* FRI soundness would demand. Prove time has about 50x
/// headroom against its gate, so that change is available — it is a decision
/// nobody has needed to make, not a limit.
#[test]
fn holding_us_to_a_stricter_bound_is_affordable() {
    assert!(
        check_fri_strength(4, 50, 16).is_ok(),
        "50 queries clears the target with room; the cost is prover time, which we have"
    );
    assert_eq!(conjectured_soundness_bits(4, 50, 16), 216);
}

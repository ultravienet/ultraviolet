//! Two writers, one `--home`. This has never been run before.
//!
//! `[SLOT-COLLISION]` is the hazard `app/src/slots.rs` exists to prevent: which
//! slots of a payee's address a payer has consumed is **payer-local** state, and
//! the invariant it protects is **payee-global**. The module header calls itself
//! "the most dangerous small file in the system", the write is atomic, the
//! ordering is reserve-then-publish, and a corrupt file is refused rather than
//! read as empty. Every one of those defences is about a *single* writer.
//!
//! Nothing has ever run two.
//!
//! **The suspected race.** `reserve(home, addr, used, newly)` takes `used` as
//! `&mut Vec<u64>` — the caller's in-memory copy, read at some earlier point —
//! and never re-reads the file inside the critical section. So:
//!
//! ```text
//!   A: read -> []            B: read -> []
//!   A: reserve [0] -> writes [0]
//!                            B: reserve [0] -- its `used` is still [], so the
//!                               duplicate check passes -- writes [0]
//! ```
//!
//! The atomic rename does not help: neither write is torn, the second simply
//! overwrites the first with a value derived from a stale read. Last writer
//! wins, and both payers believe they own slot 0.
//!
//! **What it costs, stated at today's severity.** Before proof-native
//! authorization this was key disclosure. It is not any more: two notes on one
//! anchor means the payee can spend exactly one of them, the other is an
//! unplaceable bundle, and the two are publicly linkable as paying the same
//! person. A fund loss for one of the two payments, and a privacy loss for both.
//!
//! This test is written to **fail** against the unfixed code. If it passes, read
//! `reserve` and check the read-modify-write is actually serialized before
//! believing it.

use std::sync::{Arc, Barrier};

use uv_app::slots;

fn tmp_home(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("uv-slots-{}-{}", std::process::id(), tag));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("temp home");
    d
}

/// The direct collision: two writers, both reaching for slot 0.
#[test]
fn two_writers_cannot_both_take_slot_zero() {
    let home = tmp_home("slot-zero");
    let addr = "addr-under-contention";

    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let home = home.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            // Both read before either writes — the interleaving that matters,
            // and the one two independent processes hit routinely.
            let mut used = slots::read(&home, addr).expect("read reservations");
            barrier.wait();
            slots::reserve(&home, addr, &mut used, &[0])
        }));
    }
    let outcomes: Vec<_> = handles
        .into_iter()
        .map(|h| h.join().expect("thread"))
        .collect();

    let succeeded = outcomes.iter().filter(|r| r.is_ok()).count();
    assert_eq!(
        succeeded, 1,
        "exactly one writer may take slot 0; {succeeded} did. Two notes on one \
         spend anchor means the payee can spend only one of them and both are \
         publicly linkable. Outcomes: {outcomes:?}"
    );

    // And the file must agree with whoever won.
    let final_state = slots::read(&home, addr).expect("read back");
    assert_eq!(
        final_state,
        vec![0],
        "the reservation file must record exactly the one slot that was taken"
    );
    let _ = std::fs::remove_dir_all(&home);
}

/// The subtler loss: two writers taking *different* slots must not erase each
/// other.
///
/// This one produces no duplicate, so a check that only looks for duplicates
/// would pass — and slot 1 would read as free forever after, ready to be handed
/// out a second time.
#[test]
fn concurrent_reservations_of_different_slots_are_not_lost() {
    let home = tmp_home("distinct-slots");
    let addr = "addr-two-payers";

    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for slot in 0..2u64 {
        let home = home.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            let mut used = slots::read(&home, addr).expect("read reservations");
            barrier.wait();
            slots::reserve(&home, addr, &mut used, &[slot])
        }));
    }
    for h in handles {
        h.join()
            .expect("thread")
            .expect("distinct slots must both succeed");
    }

    let mut final_state = slots::read(&home, addr).expect("read back");
    final_state.sort_unstable();
    assert_eq!(
        final_state,
        vec![0, 1],
        "both reservations must survive; a lost one reads as a free slot and \
         gets handed out again"
    );
    let _ = std::fs::remove_dir_all(&home);
}

/// Many writers, one address. Nothing may be reserved twice, nothing may vanish.
#[test]
fn eight_writers_leave_a_consistent_file() {
    let home = tmp_home("eight-writers");
    let addr = "addr-busy";
    const N: u64 = 8;

    let barrier = Arc::new(Barrier::new(N as usize));
    let mut handles = Vec::new();
    for slot in 0..N {
        let home = home.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            let mut used = slots::read(&home, addr).expect("read reservations");
            barrier.wait();
            slots::reserve(&home, addr, &mut used, &[slot])
        }));
    }
    for h in handles {
        h.join()
            .expect("thread")
            .expect("distinct slots must all succeed");
    }

    let mut final_state = slots::read(&home, addr).expect("read back");
    final_state.sort_unstable();
    assert_eq!(
        final_state,
        (0..N).collect::<Vec<_>>(),
        "every reservation must survive concurrent writers"
    );
    let _ = std::fs::remove_dir_all(&home);
}

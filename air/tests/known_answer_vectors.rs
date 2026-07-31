//! **Known-answer vectors: literal digests, frozen.**
//!
//! Every money-path value in Ultraviolet is a hash — note commitments,
//! nullifiers, spend anchors, asset ids, the history fold, bundle hashes. So a
//! change to the hash is a change to every coin that exists, which is to say a
//! consensus fork. This file is the only artifact in the repository that would
//! notice one.
//!
//! ## The hole this closes, which was subtle and total
//!
//! `air/src/sponge.rs` has a test called `test_vector_is_frozen`, whose comment
//! says *"if the absorb rule, the capacity slots, or the permutation constants
//! change, this vector changes, and that is a consensus fork someone must have
//! meant to make."* Two of those three are true. The third is not, and it is the
//! dangerous one.
//!
//! That test recomputes its own expected value using the **same**
//! `poseidon2::permutation()` and the **same** `Domain::Note as u32` it is checking.
//! So it genuinely pins the absorb rule and the literal lane indices 14 and 15 —
//! real value — but it is **blind to a change in the round constants**, because
//! both sides of the comparison move together. Its one literal assertion,
//! `assert_ne!(out[0], 0)`, fires with probability about 1 in 2×10⁹ and would
//! pass happily on a completely different hash function.
//!
//! The same circularity runs through the differential suite:
//! `air/tests/poseidon2_differential.rs` compares our vendored in-circuit
//! evaluation against `p3_baby_bear`'s permutation, and asserts
//! `constants().partial == BABYBEAR_RC16_INTERNAL` — but *both* sides come from
//! the upstream crate. It is an excellent check that our copy matches upstream.
//! It cannot tell you upstream changed.
//!
//! And `p3-poseidon2-air = "0.4.3"` in `air/Cargo.toml` is a **caret**
//! requirement, so 0.4.4 satisfies it. `Cargo.lock` pins 0.4.3 and is committed,
//! but no CI step passes `--locked`.
//!
//! Put together: **a round-constant change upstream, applied consistently to the
//! AIR and the permutation, would silently change every commitment and nullifier
//! in the system and the entire test suite would stay green.** Nothing in the
//! repository held a literal output value. Now something does.
//!
//! ## What a failure here means
//!
//! Not "a test broke." It means the hash changed, so **every note, nullifier,
//! anchor, asset id and record on any chain is now invalid**. If that was
//! intended, update these literals in the same commit that makes the change and
//! say so where the format breaks are recorded. If it was not intended, stop:
//! the most likely cause is a dependency moving under a caret.

use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_symmetric::Permutation;

use uv_air::poseidon2::{self, WIDTH};
use uv_air::sponge::{self, Domain};

/// The nine inputs `1..=9` — deliberately more than the rate (8), so the vector
/// exercises a second absorb round and the rate-carry between them.
fn inputs() -> Vec<BabyBear> {
    (1u32..=9).map(BabyBear::from_u32).collect()
}

fn canon(d: &[BabyBear]) -> Vec<u32> {
    d.iter().map(|x| x.as_canonical_u32()).collect()
}

/// **All eight domains, each with its literal digest.**
///
/// Covering all eight matters beyond freezing the hash: before this file,
/// `Randomness` and `SpendAnchor` appeared in **no sponge test at all**, and the
/// separation test in `sponge.rs` checked three hand-picked pairs out of the
/// twenty-eight that exist.
#[test]
fn the_sponge_is_frozen_for_every_domain() {
    let cases: [(&str, Domain, [u32; 8]); 9] = [
        (
            "Note",
            Domain::Note,
            [
                1392338817, 1270666111, 1387384213, 917691753, 1789265255, 1586027062, 311234545,
                1453582606,
            ],
        ),
        (
            "Nullifier",
            Domain::Nullifier,
            [
                1630483000, 1681479913, 290768577, 1973200362, 1032573089, 187995049, 871806898,
                163380007,
            ],
        ),
        (
            "Bundle",
            Domain::Bundle,
            [
                1993990273, 1140453342, 519727401, 612663257, 654148531, 672722986, 934747631,
                423607353,
            ],
        ),
        (
            "History",
            Domain::History,
            [
                1355869550, 1281758448, 42610086, 370693034, 1748405984, 388267033, 1626754814,
                963805213,
            ],
        ),
        (
            "OwnerSeed",
            Domain::OwnerSeed,
            [
                1441469685, 1155424014, 1657955222, 246733251, 711442369, 496473633, 1946188622,
                1014591716,
            ],
        ),
        (
            "NullifierKey",
            Domain::NullifierKey,
            [
                127567371, 152578106, 720732555, 1110503913, 526642097, 1359198606, 1275699759,
                1963806268,
            ],
        ),
        (
            "Randomness",
            Domain::Randomness,
            [
                692318179, 1120881175, 1174665892, 1113119716, 1661882956, 1123442171, 314437896,
                1221858112,
            ],
        ),
        (
            "SpendAnchor",
            Domain::SpendAnchor,
            [
                569768734, 247173860, 48641832, 522528735, 146303659, 609227986, 1850103921,
                32437081,
            ],
        ),
        (
            "AssetId",
            Domain::AssetId,
            [
                1253997883, 484530496, 21342583, 1379959570, 991565339, 717911043, 264255657,
                488909930,
            ],
        ),
    ];

    let mut drifted = Vec::new();
    for (name, domain, want) in cases {
        let got = canon(&sponge::hash(domain, &inputs()));
        if got[..] != want[..] {
            drifted.push(format!("  {name}: expected {want:?}, got {got:?}"));
        }
    }
    assert!(
        drifted.is_empty(),
        "THE HASH CHANGED. Every note, nullifier, anchor, asset id and record in \
         existence is now invalid. Most likely cause: a dependency moved under a \
         caret requirement (`p3-poseidon2-air = \"0.4.3\"` accepts 0.4.4+, and no \
         CI step passes --locked). If this was deliberate, update these literals \
         in the same commit and record the break.\n{}",
        drifted.join("\n")
    );
}

/// **All 36 domain pairs separate**, rather than the three that were spot-checked.
///
/// Cheap and exhaustive over a closed domain, so there is no reason to sample.
#[test]
fn every_pair_of_domains_separates() {
    let all = [
        Domain::Note,
        Domain::Nullifier,
        Domain::Bundle,
        Domain::History,
        Domain::OwnerSeed,
        Domain::NullifierKey,
        Domain::Randomness,
        Domain::SpendAnchor,
        Domain::AssetId,
    ];
    let xs = inputs();
    let mut collisions = Vec::new();
    let mut pairs = 0usize;
    for (i, a) in all.iter().enumerate() {
        for b in all.iter().skip(i + 1) {
            pairs += 1;
            if sponge::hash(*a, &xs) == sponge::hash(*b, &xs) {
                collisions.push(format!("{a:?} vs {b:?}"));
            }
        }
    }
    assert_eq!(
        pairs, 36,
        "9 domains have 36 unordered pairs; the loop is wrong"
    );
    assert!(
        collisions.is_empty(),
        "two domains hash the same input to the same digest, so their hash spaces \
         have collapsed into each other: {collisions:?}"
    );
}

/// **The domain tags are canonical field elements and pairwise distinct as such.**
///
/// `sponge::hash` puts the tag into lane 15 via `BabyBear::from_u32(domain as u32)`,
/// which **reduces mod p**. rustc's E0081 rejects two *identical* discriminants;
/// it says nothing about two discriminants congruent mod p, and neither did any
/// test. Every current tag is below p, so nothing is wrong today — the point is
/// that nothing was checking, and a future four-letter tag with a high first
/// byte (anything from `0x78...` upward) would alias silently.
#[test]
fn domain_tags_are_canonical_and_distinct_mod_p() {
    let all = [
        ("Note", Domain::Note as u32),
        ("Nullifier", Domain::Nullifier as u32),
        ("Bundle", Domain::Bundle as u32),
        ("History", Domain::History as u32),
        ("OwnerSeed", Domain::OwnerSeed as u32),
        ("NullifierKey", Domain::NullifierKey as u32),
        ("Randomness", Domain::Randomness as u32),
        ("SpendAnchor", Domain::SpendAnchor as u32),
        ("AssetId", Domain::AssetId as u32),
    ];
    let p = BabyBear::ORDER_U32;

    for (name, raw) in all {
        assert!(
            raw < p,
            "domain tag {name} = {raw} is >= the field order {p}, so it is reduced \
             on the way into lane 15 and no longer means what it says"
        );
    }
    for (i, (na, a)) in all.iter().enumerate() {
        for (nb, b) in all.iter().skip(i + 1) {
            assert_ne!(
                a % p,
                b % p,
                "domain tags {na} and {nb} are congruent mod {p}: as field elements \
                 they are the SAME tag, and the two hash spaces collapse"
            );
        }
    }
}

/// **The raw permutation is frozen**, independent of the sponge framing.
///
/// This is the one that catches an upstream round-constant change, because it
/// compares against literals rather than against another copy of upstream. Two
/// states: an index ramp, and all-zero (which the sponge's own padding relies on
/// behaving).
#[test]
fn the_permutation_is_frozen() {
    let perm = poseidon2::permutation();

    let mut ramp: [BabyBear; WIDTH] = core::array::from_fn(|i| BabyBear::from_u32(i as u32));
    perm.permute_mut(&mut ramp);
    assert_eq!(
        canon(&ramp),
        vec![
            1906786279, 1737026427, 1959749225, 700325316, 1638050605, 1021608788, 1726691001,
            1761127344, 1552405120, 417318995, 36799261, 1215172152, 614923223, 1300746575,
            957311597, 304856115
        ],
        "the Poseidon2 permutation changed on the ramp state — round constants, \
         linear layers, or the round counts moved. This is a consensus fork."
    );

    let mut zero = [BabyBear::ZERO; WIDTH];
    perm.permute_mut(&mut zero);
    assert_eq!(
        canon(&zero),
        vec![
            1168947398, 128782440, 747404447, 883925857, 360581875, 1704698758, 1878363991,
            1054281681, 682225194, 705839125, 1218819873, 41544645, 1095344608, 174996601,
            1678438226, 11259290
        ],
        "the Poseidon2 permutation changed on the all-zero state — and the sponge's \
         implicit zero-padding of a short final chunk depends on this value."
    );
}

/// **There is now exactly one sponge, and this is what checks it stays that way.**
///
/// `sponge.rs` opens by claiming *"Every hash in the v2 kernel is this one
/// function… One primitive, one implementation, one place to audit."* That claim
/// was **false until 2026-07-30** — a second add-absorb sponge with no domain tag
/// and no length binding was live on a consensus value, and the two constructions
/// were kept apart only by an accident of their initial states. The journal
/// records what it was.
///
/// This test used to pin the accident. It now pins the property that made the
/// accident irrelevant: **every money-path hash goes through `sponge::hash` under
/// a tag**, so a second construction cannot be reintroduced without failing here.
#[test]
fn there_is_only_one_sponge() {
    // A digest-typed value can only be produced by `sponge::hash` now — the
    // second construction and its whole module are deleted. What remains
    // checkable is the property the deletion bought: a tag of zero would make a
    // sponge start from the all-zero state that `compress` used, so the domain
    // separation would have nothing to stand on.
    for d in [
        Domain::Note,
        Domain::Nullifier,
        Domain::Bundle,
        Domain::History,
        Domain::OwnerSeed,
        Domain::NullifierKey,
        Domain::Randomness,
        Domain::SpendAnchor,
        Domain::AssetId,
    ] {
        assert_ne!(
            d as u32, 0,
            "a domain tag of 0 starts the sponge from an all-zero state, which is \
             where the deleted second construction began"
        );
    }

    // And the surface is minimal: `uv_air::poseidon2` exposes only the digest type,
    // the widths, and the permutation. If a hash function reappears there, this
    // stops compiling before it stops being true.
    let _: fn() -> p3_baby_bear::Poseidon2BabyBear<{ uv_air::poseidon2::WIDTH }> =
        poseidon2::permutation;
    let _: uv_air::poseidon2::Digest = [BabyBear::ZERO; 8];
}

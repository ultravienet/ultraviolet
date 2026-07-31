//! The anchor is public. It must not contain a secret.
//!
//! **The bug this pins.** `cmd_issue` set the asset id to the genesis note's
//! own `nullifier_key` — a field `kernel2::keys::NoteKeys` documents as
//! *"**Secret**: only the owner holds it"* — and then published it as
//! `asset_hex` in `anchor.json`. The anchor also carries `commitment_hex`, and
//!
//!     nullifier = H(Domain::Nullifier, nullifier_key ‖ commitment)
//!
//! so **both inputs were public**. Anyone handed an anchor — which is everyone,
//! since a payee cannot validate anything without one — could compute the
//! genesis note's nullifier before the issuer ever spent it, publish one
//! keyless garbage record against it, and make the entire asset permanently
//! unspendable for the price of one Bitcoin transaction.
//!
//! At the time it was not theft, only destruction — a signature still guarded
//! spending. **That is no longer true**, and it makes this file's second
//! assertion sharper than it was written to be. See it below.
//!
//! Two invariants this file exists to keep true, both stated as properties of
//! the *published bytes* rather than of any particular derivation, so a future
//! change of asset-id scheme is still checked:
//!
//! 1. the values in an anchor do not compose into the genesis nullifier;
//! 2. they do not compose into the genesis note's spend anchor either — the
//!    note commits to `H(nullifier_key)`, and constraint 32 makes a spender
//!    exhibit its preimage, so publishing the preimage made that check vacuous
//!    for the one note whose loss kills the asset.
//!
//! It also contradicted `kernel2::nullifier`'s own doc — "a third party cannot
//! compute the nullifier of an unspent note" — and spec/99 `[FRONTRUN]`, which
//! accepts a *mempool-width* window on the argument that a nullifier is not
//! public until broadcast. For the genesis note that window was unbounded and
//! opened at issuance.

use uv_air::poseidon2::Digest;
use uv_kernel2::amount::Amount;
use uv_kernel2::keys::{anchor_of, derive, WalletSeed};
use uv_kernel2::note::Note;
use uv_kernel2::nullifier;

/// Rebuild what `cmd_issue` publishes: the asset id and the genesis
/// commitment. Kept deliberately close to the CLI rather than calling it, so
/// this test states the *rule* and fails if the CLI drifts back toward it.
fn issue(seed_byte: u8, amount: u64) -> (Digest, Digest, Digest) {
    let seed = WalletSeed([seed_byte; 32]);
    let keys = derive(&seed, 0);
    // The asset id as the CLI derives it. If this line and `cmd_issue`
    // disagree, the end-to-end demo catches it; what this file checks is that
    // whatever is published cannot reconstruct a secret.
    let asset = keys.asset_id;
    let note = Note::build(asset, Amount(amount), &keys);
    (asset, note.commitment(), keys.nullifier_key)
}

/// The attack, run against the published values.
#[test]
fn the_published_asset_and_commitment_do_not_yield_the_genesis_nullifier() {
    let (asset, commitment, secret_nullifier_key) = issue(11, 1_000);

    // What an attacker holding `anchor.json` would compute.
    let guess = nullifier::derive(&asset, &commitment);
    // What the issuer will actually publish when they spend.
    let real = nullifier::derive(&secret_nullifier_key, &commitment);

    assert_ne!(
        guess, real,
        "ANCHOR LEAKS THE GENESIS NULLIFIER: anyone holding the anchor can \
         publish a record against this value and the asset is dead before it \
         is ever spent"
    );
}

/// The same values must not open the spend anchor either.
///
/// The note commits to `H(nullifier_key)` and constraint 32 requires a spender
/// to exhibit a preimage of it.
///
/// **This assertion got stricter on 2026-07-29 and the comment above it did
/// not, until 2026-07-30.** It used to read "publishing that preimage does not
/// let anyone spend — the signature still stands in the way." Since
/// authorization became the anchor preimage itself (spec/99 `[PROOF-AUTH]`),
/// exhibiting it *is* the whole of spend authorization. There is no second
/// barrier. Publishing the preimage of a note's spend anchor hands that note to
/// whoever reads it — and this test guards the one note whose loss destroys an
/// entire asset.
#[test]
fn the_published_asset_is_not_the_spend_anchors_preimage() {
    let (asset, _commitment, secret_nullifier_key) = issue(12, 500);
    assert_ne!(
        anchor_of(&asset),
        anchor_of(&secret_nullifier_key),
        "the asset id opens the genesis note's spend anchor — constraint 32 is \
         vacuous for that note"
    );
}

/// The control. If `nullifier::derive` were a constant function, or the test
/// fixture built the two sides from the same input, both assertions above
/// would pass while proving nothing.
#[test]
fn the_probe_can_tell_a_leak_when_there_is_one() {
    let seed = WalletSeed([13u8; 32]);
    let keys = derive(&seed, 0);
    // Issue the OLD way — asset id *is* the secret nullifier key.
    let leaky_asset = keys.nullifier_key;
    let note = Note::build(leaky_asset, Amount(7), &keys);
    let commitment = note.commitment();

    assert_eq!(
        nullifier::derive(&leaky_asset, &commitment),
        nullifier::derive(&keys.nullifier_key, &commitment),
        "the probe must detect the original bug; if this fails the two tests \
         above are vacuous"
    );
    assert_eq!(
        anchor_of(&leaky_asset),
        anchor_of(&keys.nullifier_key),
        "and must detect the spend-anchor half of it"
    );
}

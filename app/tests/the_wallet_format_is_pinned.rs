//! The wallet on-disk format is pinned, because the file is the only copy.
//!
//! Once a payment settles, its bundle is deleted and the note's whole lineage
//! lives **only** in the wallet file (`SPEC.md` §10). So a change to how that
//! file is encoded — a `bincode` bump, a reordered field in `Store`, `Held`,
//! `Note`, `Hop`, or `SignLog`, a new enum variant — is not a compatibility
//! nuisance. `bincode` is untagged: it would read the new layout as *wrong
//! values*, not as an error. A note's amount read from where its index used to
//! be. A lineage misattributed. Silent, and it is somebody's coin.
//!
//! `WALLET_FORMAT` (checked on load) catches a version bump. This catches the
//! rest: a committed serialization of a known wallet that today's encoder must
//! reproduce **byte for byte**, and that today's decoder must read back to the
//! same values. If either fails, the format changed — and the fix is to make
//! that change deliberate: update this fixture AND bump `WALLET_FORMAT` in the
//! same commit, never one without the other.
//!
//! The fixture is a single-note wallet on purpose: `Store` holds its notes in a
//! `HashMap`, whose iteration order is randomised per process, so a multi-note
//! store would not serialize to stable bytes. One note is enough — every
//! persisted type is exercised by it.

use uv_app::wallet::{open_or_create, save, Wallet, WALLET_FORMAT};
use uv_kernel2::amount::Amount;
use uv_kernel2::keys::{derive, WalletSeed};
use uv_kernel2::note::Note;
use uv_kernel2::transfer::Transfer;
use uv_wallet2::accept::{Hop, Lineage};
use uv_wallet2::signlog::SignLog;
use uv_wallet2::store::{Held, NoteState, Store};

/// The exact bytes a fresh `save` of the fixture wallet must produce. Generated
/// once; a change here is a deliberate format change.
const GOLDEN_HEX: &str = "5556573200010000004000000000000000313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131310100000000000000400000000000000036333233313435393332653264303335333963623630356239386666613236313332383436613036313330376535366138346131303231333331373465363732a1feff77a1feff77a1feff77a1feff77a1feff77a1feff77a1feff77a1feff77f401000000000000c3c9035fcbc43b20d10d1a35821e9063b3cd6d3838bbe61e5bb75843bf84ef5305496064b88fcf57708adf07df9b7207e5c39a37aa767f6dd397f80b3ee0380400000000000000000100000000000000feffff0ffeffff0ffeffff0ffeffff0ffeffff0ffeffff0ffeffff0ffeffff0ffcffff1ffcffff1ffcffff1ffcffff1ffcffff1ffcffff1ffcffff1ffcffff1f000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000deadbeef000000000000000000000000020000000000000000000000";

/// The fixture note's commitment, so the decode test asserts real content.
const GOLDEN_COMMITMENT: &str = "6323145932e2d03539cb605b98ffa26132846a061307e56a84a102133174e672";

fn fixture_wallet() -> Wallet {
    let seed = WalletSeed([0x11u8; 32]);
    let keys = derive(&seed, 0);
    let asset = [p3_baby_bear::BabyBear::new(0xA5); 8];
    let note = Note::build(asset, Amount(500), &keys);

    let hop = Hop {
        transfer: Transfer {
            input_commitment: [p3_baby_bear::BabyBear::new(1); 8],
            nullifier: [p3_baby_bear::BabyBear::new(2); 8],
            outputs: vec![],
            prev_history: uv_kernel2::history::GENESIS,
        },
        proof: vec![0xDE, 0xAD, 0xBE, 0xEF],
    };
    let mut store = Store::new();
    store
        .insert(Held {
            note,
            key_index: 0,
            lineage: Lineage::from(vec![hop]),
            state: NoteState::Unspent,
        })
        .expect("insert");

    Wallet {
        seed,
        store,
        log: SignLog::new(),
    }
}

fn tmp_home(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("uv-wallet-fixture-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("home");
    d
}

/// **Encoding is pinned.** A fresh save of the fixture reproduces the committed
/// bytes exactly. Any change to the wire format breaks this.
#[test]
fn the_encoder_reproduces_the_golden_bytes() {
    let home = tmp_home("encode");
    let w = fixture_wallet();
    save(&home, "fix", &w.seed, &w.store, &w.log, None).expect("save");
    let bytes = std::fs::read(home.join("wallets").join("fix.uvw")).expect("read");

    let golden = hex::decode(GOLDEN_HEX).expect("golden hex");
    assert_eq!(
        hex::encode(&bytes),
        GOLDEN_HEX,
        "the wallet encoder no longer produces the committed bytes ({} vs {} bytes). \
         If this change is intentional, regenerate GOLDEN_HEX and bump WALLET_FORMAT \
         in the SAME commit — the file is the only copy of a lineage.",
        bytes.len(),
        golden.len()
    );
    let _ = std::fs::remove_dir_all(&home);
}

/// **Decoding is pinned.** The committed bytes read back to the fixture wallet:
/// the seed, the note, its amount, its lineage. A field reorder that still
/// decodes would surface here as a wrong value.
#[test]
fn the_decoder_reads_the_golden_bytes_to_the_right_values() {
    let home = tmp_home("decode");
    std::fs::create_dir_all(home.join("wallets")).expect("wallets dir");
    let bytes = hex::decode(GOLDEN_HEX).expect("golden hex");
    std::fs::write(home.join("wallets").join("fix.uvw"), &bytes).expect("write golden");

    let w = open_or_create(&home, "fix", None).expect("open the golden wallet");

    assert_eq!(w.seed.0, [0x11u8; 32], "seed misread");
    let notes: Vec<_> = w.store.iter().collect();
    assert_eq!(notes.len(), 1, "note count misread");
    let h = notes[0];
    assert_eq!(
        h.note.amount.0, 500,
        "AMOUNT misread — this is the fund-loss case"
    );
    assert_eq!(h.key_index, 0, "key index misread");
    assert_eq!(h.state, NoteState::Unspent, "state misread");
    assert_eq!(h.lineage.len(), 1, "lineage length misread");
    assert_eq!(
        h.lineage[0].proof,
        vec![0xDE, 0xAD, 0xBE, 0xEF],
        "proof bytes misread"
    );
    assert_eq!(
        hex::encode(uv_kernel2::digest::encode(&h.note.commitment())),
        GOLDEN_COMMITMENT,
        "the note commitment does not match — a field was misread"
    );
    let _ = std::fs::remove_dir_all(&home);
}

/// A wallet whose body declares a format this build does not know is REFUSED,
/// not read under the wrong layout. The magic stays `UVW2`; only the body
/// version byte is bumped, which is the future-version case.
#[test]
fn a_future_format_version_is_refused() {
    let home = tmp_home("future");
    std::fs::create_dir_all(home.join("wallets")).expect("wallets dir");
    let mut bytes = hex::decode(GOLDEN_HEX).expect("golden hex");
    // The format u32 is the first field of the body, right after the 5-byte
    // magic+sealing header. Bump it past what this build accepts.
    assert_eq!(bytes[5], WALLET_FORMAT as u8, "fixture format byte moved");
    bytes[5] = (WALLET_FORMAT + 99) as u8;
    std::fs::write(home.join("wallets").join("fix.uvw"), &bytes).expect("write");

    let r = open_or_create(&home, "fix", None);
    assert!(
        r.is_err(),
        "a wallet of an unknown body format must be refused, not read under a \
         guessed layout"
    );
    let _ = std::fs::remove_dir_all(&home);
}

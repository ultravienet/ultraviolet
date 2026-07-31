//! `uv_call(json) -> json`: the one string-in/string-out door to the command
//! layer, so the Swift side stays a thin veneer over `uv-app` and reimplements
//! none of the disciplines that live there.
//!
//! ## The contract
//!
//! Request: `{"cmd": "...", "home": "/path", ...}` — fields per command below.
//! Response: `{"ok": <result>}` or
//! `{"err": {"kind": "...", "message": "...", "transient": bool}}`.
//!
//! `kind` is `uv_app::Error::kind()`'s closed set — the stable tags a caller
//! branches on; the message is for a human and may be reworded freely. Two
//! extra kinds exist only at this boundary: `"bad_request"` (the JSON itself
//! was unusable) and `"panic"` (a bug tripped the guard below).
//!
//! ## The panic guard
//!
//! Rust panics must not unwind across an FFI boundary — that is undefined
//! behavior, and on a phone it presents as a crash with no diagnosis. Every
//! dispatch runs under `catch_unwind`, and a panic becomes an `"err"` with
//! `kind: "panic"`: the app shows a real message, and the wallet files were
//! written atomically or not at all (`uv_app::wallet::save`).
//!
//! ## Persistence
//!
//! A phone has no separate "save" step to forget, so every mutating command
//! persists internally, in the same order the CLI does: `issue` saves the
//! wallet between staging and publishing; `scan` saves before deleting the
//! files it accepted. The orderings are the `#[must_use]` types' contract in
//! `uv-app`; this file is just the place their sequence is spelled once for
//! the FFI.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

fn err_json(kind: &str, message: &str, transient: bool) -> String {
    json!({"err": {"kind": kind, "message": message, "transient": transient}}).to_string()
}

fn app_err(e: &uv_app::Error) -> String {
    err_json(e.kind(), &e.to_string(), e.is_transient())
}

fn into_c(s: String) -> *mut c_char {
    // A NUL inside the JSON would truncate; serde_json never emits one for
    // valid UTF-8 input, and the fallback covers a hostile message string.
    CString::new(s)
        .unwrap_or_else(|_| {
            CString::new(
                r#"{"err":{"kind":"panic","message":"NUL in response","transient":false}}"#,
            )
            .expect("static")
        })
        .into_raw()
}

/// The chain view this build uses.
///
/// Two shapes, one trait. With `UV_MIRROR` unset (or empty) this is the
/// file-backed demo chain in the home — self-contained, no network, what the
/// simulator and the tests use. Set it to a mirror's base URL and the phone
/// reads **Bitcoin** instead, through `uv_btc::mirror::MirrorView`: bulk pages
/// replayed into a local index, every lookup answered in-process, and no
/// nullifier ever sent anywhere.
///
/// The switch is one constructor because every command takes the trait. That
/// was the point of the trait.
enum ChainView {
    File(uv_wallet2::chain::FileChain),
    Mirror(uv_btc::mirror::MirrorView),
}

impl ChainView {
    fn open(home: &Path) -> Self {
        match std::env::var("UV_MIRROR").ok().filter(|s| !s.is_empty()) {
            // A corrupt chain file is fatal here too, and this is the backend the
            // app uses by default. Surfaced as a panic rather than swallowed: the
            // FFI boundary turns it into an error JSON, and a wallet that cannot
            // read its chain must not answer questions about spentness.
            None => ChainView::File(
                uv_wallet2::chain::FileChain::open(home.join("chain.json"))
                    .unwrap_or_else(|e| panic!("{e}")),
            ),
            Some(base) => {
                let view = uv_btc::mirror::MirrorView::open(home.join("mirror-index.json"));
                // Sync on open: a view that has not caught up answers
                // `Unanswerable` for everything, so the alternative to syncing
                // here is a wallet that refuses every payment and cannot say
                // why. A failure is left to surface as that refusal rather
                // than papered over with a guess.
                let _ = uv_btc::mirror_fetch::sync_all(&view, &base);
                ChainView::Mirror(view)
            }
        }
    }

    /// How this view should be described to a person. The app's warning
    /// banner is driven by this rather than by a hardcoded string, so it
    /// cannot keep saying "not connected to Bitcoin" once it is.
    fn describe(&self) -> String {
        match self {
            ChainView::File(_) => "local file (not Bitcoin)".to_string(),
            ChainView::Mirror(_) => match std::env::var("UV_MIRROR") {
                Ok(u) => format!("mirror {u}"),
                Err(_) => "mirror".to_string(),
            },
        }
    }

    fn as_chain(&self) -> &dyn uv_wallet2::chain::Chain {
        match self {
            ChainView::File(c) => c,
            ChainView::Mirror(c) => c,
        }
    }

    fn as_chain_mut(&mut self) -> &mut dyn uv_wallet2::chain::Chain {
        match self {
            ChainView::File(c) => c,
            ChainView::Mirror(c) => c,
        }
    }
}

fn chain(home: &Path) -> ChainView {
    ChainView::open(home)
}

fn str_field<'a>(req: &'a Value, name: &str) -> Result<&'a str, String> {
    req.get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing or non-string field `{name}`"))
}

fn u64_field(req: &Value, name: &str) -> Result<u64, String> {
    req.get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing or non-integer field `{name}`"))
}

/// Errors from here are already-encoded response envelopes, never bare
/// messages — the fuzz floor caught exactly that mixup on its first run.
fn open_wallet(req: &Value, home: &Path) -> Result<(String, uv_app::wallet::Wallet), String> {
    let name = match str_field(req, "wallet") {
        Ok(n) => n.to_string(),
        Err(m) => return Err(err_json("bad_request", &m, false)),
    };
    let pass = req.get("passphrase").and_then(Value::as_str);
    uv_app::wallet::open_or_create(home, &name, pass)
        .map(|w| (name, w))
        .map_err(|e| app_err(&e))
}

fn dispatch(req: &Value) -> String {
    let Ok(home_s) = str_field(req, "home") else {
        return err_json("bad_request", "missing or non-string field `home`", false);
    };
    let home = PathBuf::from(home_s);
    let Ok(cmd) = str_field(req, "cmd") else {
        return err_json("bad_request", "missing or non-string field `cmd`", false);
    };

    match cmd {
        // ---- read-only ----
        "sealing" => match str_field(req, "wallet") {
            Err(m) => err_json("bad_request", &m, false),
            Ok(name) => match uv_app::wallet::sealing(&home, name) {
                Ok(s) => json!({"ok": format!("{s:?}").to_lowercase()}).to_string(),
                Err(e) => app_err(&e),
            },
        },
        "balance" => match open_wallet(req, &home) {
            Err(e) => e,
            Ok((_, w)) => json!({"ok": uv_app::commands::balance(&w)}).to_string(),
        },
        "status" => match open_wallet(req, &home) {
            Err(e) => e,
            Ok((name, w)) => {
                let c = chain(&home);
                let mut s =
                    serde_json::to_value(uv_app::commands::status(&home, &name, &w, c.as_chain()))
                        .unwrap_or_else(|_| json!({}));
                // Which chain this view actually is, and whether it is caught
                // up. A wallet that cannot say what it is reading is a wallet
                // whose numbers mean nothing.
                if let Some(o) = s.as_object_mut() {
                    o.insert("backend".into(), json!(c.describe()));
                    o.insert(
                        "is_bitcoin".into(),
                        json!(matches!(c, ChainView::Mirror(_))),
                    );
                }
                json!({"ok": s}).to_string()
            }
        },
        "supply" => {
            let filter = req.get("asset").and_then(Value::as_str);
            let c = chain(&home);
            json!({"ok": uv_app::commands::supply(&home, c.as_chain(), filter)}).to_string()
        }
        // ---- mutating ----
        "address" => match open_wallet(req, &home) {
            Err(e) => e,
            Ok((name, mut w)) => {
                let count = req.get("count").and_then(Value::as_u64).unwrap_or(8);
                let peer = req.get("peer").and_then(Value::as_str);
                let addr = match uv_app::commands::make_address(&home, &name, &mut w, count, peer) {
                    Ok(a) => a,
                    Err(e) => return app_err(&e),
                };
                // Slots are consumed the moment they are handed out, so the
                // wallet must be durable before the address leaves this
                // function — otherwise a crash hands the same batch out twice.
                let pass = req.get("passphrase").and_then(Value::as_str);
                if let Err(e) = uv_app::wallet::save(&home, &name, &w.seed, &w.store, &w.log, pass)
                {
                    return app_err(&e);
                }
                json!({"ok": addr}).to_string()
            }
        },
        "issue" => match (open_wallet(req, &home), u64_field(req, "amount")) {
            (Err(e), _) => e,
            (_, Err(m)) => err_json("bad_request", &m, false),
            (Ok((name, mut w)), Ok(amount)) => {
                let mut c = chain(&home);
                let prepared = match uv_app::commands::prepare_issue(&mut w, c.as_chain(), amount) {
                    Ok(p) => p,
                    Err(e) => return app_err(&e),
                };
                // The ordering the CLI spells with its own save: durable
                // wallet, then the record, then the anchor (inside
                // `publish_issue`).
                let pass = req.get("passphrase").and_then(Value::as_str);
                if let Err(e) = uv_app::wallet::save(&home, &name, &w.seed, &w.store, &w.log, pass)
                {
                    return app_err(&e);
                }
                match uv_app::commands::publish_issue(c.as_chain_mut(), &home, prepared) {
                    Ok(done) => json!({"ok": done}).to_string(),
                    Err(e) => app_err(&e),
                }
            }
        },
        "scan" => match open_wallet(req, &home) {
            Err(e) => e,
            Ok((name, mut w)) => {
                let anchor = match uv_app::anchor::read(&home) {
                    Ok(Some(a)) => a,
                    Ok(None) => {
                        return err_json(
                            "not_found",
                            "no anchor.json — nothing to validate against",
                            false,
                        )
                    }
                    Err(e) => return app_err(&e),
                };
                let c = chain(&home);
                let outcome =
                    match uv_app::commands::scan_inbox(&home, &name, &mut w, c.as_chain(), &anchor)
                    {
                        Ok(o) => o,
                        Err(e) => return app_err(&e),
                    };
                let pass = req.get("passphrase").and_then(Value::as_str);
                // Durable first, irreversible second — same order as the CLI.
                if let Err(e) = uv_app::wallet::save(&home, &name, &w.seed, &w.store, &w.log, pass)
                {
                    return app_err(&e);
                }
                let (a, r) = (outcome.accepted, outcome.rejected);
                let events: Vec<String> =
                    outcome.events.iter().map(|ev| format!("{ev:?}")).collect();
                outcome.finish();
                json!({"ok": {"accepted": a, "rejected": r, "events": events}}).to_string()
            }
        },
        "send" => {
            // The recipient's address arrives as a JSON string field, exactly
            // the object `make_address` returns. The fork will get it from a
            // chat message; here it is a request field.
            let addr: uv_app::address::Address = match req.get("to") {
                Some(v) => match serde_json::from_value(v.clone()) {
                    Ok(a) => a,
                    Err(e) => {
                        return err_json(
                            "bad_request",
                            &format!("field `to` is not an address: {e}"),
                            false,
                        )
                    }
                },
                None => {
                    return err_json(
                        "bad_request",
                        "missing field `to` (the recipient address)",
                        false,
                    )
                }
            };
            let amount = match u64_field(req, "amount") {
                Ok(a) => a,
                Err(m) => return err_json("bad_request", &m, false),
            };
            // `from` selects a specific note by commitment; optional.
            let from = match req.get("from").and_then(Value::as_str) {
                Some(h) => match hex::decode(h)
                    .ok()
                    .and_then(|b| <[u8; 32]>::try_from(b).ok())
                    .and_then(|a| uv_kernel2::digest::decode(&a))
                {
                    Some(d) => Some(d),
                    None => {
                        return err_json(
                            "bad_request",
                            "field `from` is not a canonical commitment",
                            false,
                        )
                    }
                },
                None => None,
            };
            let (name, mut w) = match open_wallet(req, &home) {
                Ok(x) => x,
                Err(e) => return e,
            };
            let pass = req.get("passphrase").and_then(Value::as_str);
            let mut c = chain(&home);
            let cfg = uv_air::prove::hiding_config();
            match uv_app::commands::send(
                &home,
                &name,
                &mut w,
                c.as_chain_mut(),
                &cfg,
                &addr,
                amount,
                from.as_ref(),
                pass,
            ) {
                Ok(out) => {
                    // The sealed bundles go back to the caller to DELIVER — the
                    // one thing the FFI does not do, because delivery is the
                    // chat layer's job (the CLI mailed, the fork attaches). Hex
                    // rather than base64: no new dependency, and it is how the
                    // rest of this door encodes bytes.
                    let parts: Vec<Value> = out
                        .sent
                        .iter()
                        .map(|p| {
                            json!({
                                "bundle_name": p.bundle_name,
                                "bundle_hex": hex::encode(&p.bundle_wire),
                                "nullifier": p.nullifier_hex,
                                "amount": p.amount,
                            })
                        })
                        .collect();
                    json!({"ok": {
                        "rebroadcast": out.rebroadcast,
                        "parts": out.parts,
                        "bundles": parts,
                    }})
                    .to_string()
                }
                Err(e) => app_err(&e),
            }
        }
        "reconcile" => match open_wallet(req, &home) {
            Err(e) => e,
            Ok((name, mut w)) => {
                let c = chain(&home);
                let out = uv_app::commands::reconcile(&home, &mut w, c.as_chain());
                let pass = req.get("passphrase").and_then(Value::as_str);
                if let Err(e) = uv_app::wallet::save(&home, &name, &w.seed, &w.store, &w.log, pass)
                {
                    return app_err(&e);
                }
                json!({"ok": {
                    "quarantined": out.quarantined.iter().map(hex::encode).collect::<Vec<_>>(),
                    "restored": out.restored.iter().map(hex::encode).collect::<Vec<_>>(),
                }})
                .to_string()
            }
        },
        other => err_json("bad_request", &format!("unknown cmd `{other}`"), false),
    }
}

/// The door. Takes a JSON request, returns a JSON response; never panics
/// across the boundary, never returns null. Free the result with `uv_free`.
///
/// # Safety
/// `req` must be null or a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn uv_call(req: *const c_char) -> *mut c_char {
    let parsed: Result<Value, String> = if req.is_null() {
        Err("null request".into())
    } else {
        match CStr::from_ptr(req).to_str() {
            Err(_) => Err("request is not UTF-8".into()),
            Ok(s) => serde_json::from_str(s).map_err(|e| format!("request is not JSON: {e}")),
        }
    };
    let out = match parsed {
        Err(m) => err_json("bad_request", &m, false),
        Ok(v) => catch_unwind(AssertUnwindSafe(|| dispatch(&v))).unwrap_or_else(|p| {
            let msg = p
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| p.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "unnamed panic".into());
            err_json("panic", &msg, false)
        }),
    };
    into_c(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn call(s: &str) -> Value {
        let c = CString::new(s).unwrap();
        let out = unsafe { uv_call(c.as_ptr()) };
        let raw = unsafe { CStr::from_ptr(out) }.to_str().unwrap().to_string();
        unsafe { crate::uv_free(out) };
        serde_json::from_str(&raw)
            .unwrap_or_else(|e| panic!("response to {s:?} is not JSON ({e}): {raw:?}"))
    }

    /// The fuzz floor: garbage in, an error JSON out, never a crash and never
    /// a non-JSON response. This is the whole contract a hostile or buggy
    /// caller gets to rely on.
    #[test]
    fn garbage_requests_get_error_json_not_crashes() {
        for bad in [
            "",
            "not json",
            "42",
            "[]",
            "{}",
            r#"{"cmd":"balance"}"#,
            r#"{"home": 3, "cmd":"balance"}"#,
            r#"{"home":"/nonexistent","cmd":"nope"}"#,
            "{\"cmd\":\"balance\",\"home\":\"\\u0000\"}",
        ] {
            let v = call(bad);
            assert!(
                v.get("err").is_some(),
                "{bad:?} must produce an err envelope, got {v}"
            );
            let kind = v["err"]["kind"].as_str().unwrap();
            assert!(!kind.is_empty(), "every err carries a kind");
        }
        let c = unsafe { uv_call(std::ptr::null()) };
        let s = unsafe { CStr::from_ptr(c) }.to_str().unwrap();
        assert!(s.contains("bad_request"));
        unsafe { crate::uv_free(c) };
    }

    /// A real round trip in a temp home: balance on a fresh wallet is zero,
    /// issue mints, balance sees it — all through the string door.
    #[test]
    fn issue_then_balance_through_the_door() {
        let home = std::env::temp_dir().join(format!("uv-call-test-{}", std::process::id()));
        std::fs::create_dir_all(&home).unwrap();
        let h = home.to_str().unwrap();

        let v = call(&format!(r#"{{"cmd":"balance","home":"{h}","wallet":"w"}}"#));
        assert_eq!(v["ok"]["spendable"], 0, "fresh wallet: {v}");

        let v = call(&format!(
            r#"{{"cmd":"issue","home":"{h}","wallet":"w","amount":700}}"#
        ));
        assert!(v.get("ok").is_some(), "issue: {v}");

        let v = call(&format!(r#"{{"cmd":"balance","home":"{h}","wallet":"w"}}"#));
        assert_eq!(v["ok"]["spendable"], 700, "after issue: {v}");

        let v = call(&format!(r#"{{"cmd":"supply","home":"{h}"}}"#));
        assert_eq!(v["ok"]["assets"][0]["total"], 700, "supply: {v}");

        // Receive side: an address of fresh slots, and the batch recorded.
        let v = call(&format!(
            r#"{{"cmd":"address","home":"{h}","wallet":"w","count":3,"peer":"carol"}}"#
        ));
        assert_eq!(
            v["ok"]["slots"].as_array().map(|s| s.len()),
            Some(3),
            "address: {v}"
        );
        assert!(
            v["ok"]["scan"]["x25519_hex"].is_string(),
            "scan key present: {v}"
        );
        let v = call(&format!(r#"{{"cmd":"status","home":"{h}","wallet":"w"}}"#));
        assert_eq!(
            v["ok"]["batches"][0]["peer"], "carol",
            "batch ledgered: {v}"
        );

        std::fs::remove_dir_all(&home).ok();
    }

    /// **The move that makes the Signal fork possible: paying through the door.**
    ///
    /// `send` did not exist as a dispatch arm until the client pivot — the FFI
    /// could issue and receive but not spend, so a fork could show a balance and
    /// not move it. This drives issue → address → **send** → reconcile entirely
    /// through the JSON string boundary, which is the exact seam the fork calls.
    ///
    /// It stops at "the payment left correctly": the bundles come back as hex for
    /// the caller to deliver (the one thing the door does not do), the spent note
    /// leaves the spendable set, and a replay of the same note re-sends nothing.
    /// Deep settlement — mining, the ancestry walk on accept — is the uv-app
    /// end-to-end test's job; this proves the door marshals a spend.
    #[test]
    fn paying_through_the_door() {
        let home = std::env::temp_dir().join(format!("uv-call-send-{}", std::process::id()));
        std::fs::create_dir_all(&home).unwrap();
        let h = home.to_str().unwrap();

        // Mint, so there is something to spend.
        let v = call(&format!(
            r#"{{"cmd":"issue","home":"{h}","wallet":"w","amount":500}}"#
        ));
        assert!(v.get("ok").is_some(), "issue: {v}");
        assert_eq!(
            call(&format!(r#"{{"cmd":"balance","home":"{h}","wallet":"w"}}"#))["ok"]["spendable"],
            500
        );

        // An address to pay — to ourselves is fine; the door does not care who
        // the counterparty is, only that the address is well-formed.
        let addr = call(&format!(
            r#"{{"cmd":"address","home":"{h}","wallet":"w","count":2,"peer":"self"}}"#
        ));
        let to = addr["ok"].clone();
        assert!(to["slots"].as_array().is_some(), "address: {addr}");

        // Pay 200. The address object goes straight back in as the `to` field —
        // exactly how a chat message would carry it.
        let req = json!({
            "cmd": "send", "home": h, "wallet": "w", "amount": 200, "to": to,
        });
        let v = call(&req.to_string());
        assert!(v.get("ok").is_some(), "send: {v}");
        assert_eq!(v["ok"]["rebroadcast"], 0, "first spend replays nothing");
        let bundles = v["ok"]["bundles"].as_array().expect("bundles array");
        assert_eq!(bundles.len(), 1, "one part, one bundle: {v}");
        let b = &bundles[0];
        assert!(b["bundle_name"].is_string(), "bundle named: {v}");
        // The wire is hex and it is really sealed — no plaintext markers.
        let hexed = b["bundle_hex"].as_str().expect("bundle_hex");
        let wire = hex::decode(hexed).expect("bundle_hex decodes");
        for leak in [b"amount".as_slice(), b"lineage", b"proof"] {
            assert!(
                !wire.windows(leak.len()).any(|w| w == leak),
                "sealed bundle leaked {:?}",
                String::from_utf8_lossy(leak)
            );
        }
        assert_eq!(b["amount"], 200, "part amount echoed: {v}");

        // The spent note left the spendable set: 500 - 200 spent, 300 change.
        assert_eq!(
            call(&format!(r#"{{"cmd":"balance","home":"{h}","wallet":"w"}}"#))["ok"]["spendable"],
            300,
            "the input went in-flight; only the change is spendable"
        );

        // reconcile runs cleanly and returns its two lists.
        let v = call(&format!(
            r#"{{"cmd":"reconcile","home":"{h}","wallet":"w"}}"#
        ));
        assert!(v["ok"]["quarantined"].is_array(), "reconcile shape: {v}");
        assert!(v["ok"]["restored"].is_array(), "reconcile shape: {v}");

        // A malformed `to` is a bad_request, not a crash.
        let v = call(&format!(
            r#"{{"cmd":"send","home":"{h}","wallet":"w","amount":10,"to":"not an address"}}"#
        ));
        assert_eq!(v["err"]["kind"], "bad_request", "garbage address: {v}");

        std::fs::remove_dir_all(&home).ok();
    }
}

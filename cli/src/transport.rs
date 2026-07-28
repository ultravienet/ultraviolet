//! How a sealed bundle gets from the payer to the payee.
//!
//! **The transport moves opaque blobs and nothing else.** It never learns who a
//! payment is for, because there is nothing in a blob that says: bundles are
//! sealed to the payee's scan key and a wallet finds its own mail by trial
//! decapsulation (`cmd_scan`). There is deliberately no addressee — an
//! identifier is exactly the metadata the design refuses to leak.
//!
//! **Its whole job is to get new blobs into the local inbox.** Everything
//! downstream — trial decapsulation, `accept`, keep-a-payment-that-is-merely-
//! early, discard-what-can-never-be-valid, set-aside-what-has-nowhere-to-sit —
//! is already written and tested against that directory, and stays untouched.
//! That is what keeps a network transport a small change rather than a rewrite.
//!
//! ## What the untargeted bag costs
//!
//! Every wallet fetches every blob and tries to open each one. That leaks
//! nothing, and it does **not scale**: it is O(all traffic) per user. Fine for
//! a proof of concept with a handful of participants, and precisely the problem
//! Signal already solved — because Signal knows who its users are and we, on
//! purpose, do not. Stated here rather than discovered later.

use std::path::{Path, PathBuf};

/// Where sealed bundles go and come from.
pub trait Transport {
    /// Hand a sealed bundle to the carrier. `name` is a stable filename for it
    /// (the nullifier, which is public and already on Bitcoin).
    fn put(&self, name: &str, sealed: &[u8]) -> Result<(), String>;

    /// Pull anything new into the local inbox. Returns how many arrived.
    ///
    /// Idempotent: fetching twice must not produce two copies. Implementations
    /// track their own position; the wallet's inbox is the only shared state.
    fn take(&self, inbox: &Path) -> Result<usize, String>;

    /// For the messages the CLI prints.
    fn describe(&self) -> String;
}

/// The local drop box: the payer writes into a directory the payee reads.
///
/// This is what the demos have always done, kept as an implementation rather
/// than deleted, because it is the only transport CI can run — there is no
/// second machine in a GitHub runner — and because it is the fallback when the
/// network is the thing being debugged.
pub struct Directory {
    pub inbox: PathBuf,
}

impl Transport for Directory {
    fn put(&self, name: &str, sealed: &[u8]) -> Result<(), String> {
        std::fs::create_dir_all(&self.inbox).map_err(|e| format!("mkdir: {e}"))?;
        std::fs::write(self.inbox.join(name), sealed).map_err(|e| format!("write: {e}"))
    }

    /// Nothing to do: the payer wrote straight into this directory.
    fn take(&self, _inbox: &Path) -> Result<usize, String> {
        Ok(0)
    }

    fn describe(&self) -> String {
        format!("directory {}", self.inbox.display())
    }
}

/// A relay: an append-only bag of opaque blobs, reachable over HTTP.
///
/// `POST /drop` adds one. `GET /bag?since=N` returns everything after a
/// cursor. The operator sees byte counts and timing and nothing else — no
/// sender, no recipient, no amount, and no way to tell two payments apart from
/// two pieces of noise.
///
/// The cursor is **client-side**, which is what makes a relay restart survivable
/// from the wallet's side and what stops one wallet's fetch from consuming
/// another's mail.
pub struct Relay {
    pub url: String,
    /// Where this wallet remembers how much of the bag it has seen.
    pub cursor_path: PathBuf,
}

impl Relay {
    fn cursor(&self) -> u64 {
        std::fs::read_to_string(&self.cursor_path)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
    }

    /// Advanced only after the blobs are on disk. A crash between the two
    /// re-fetches, which is free — the inbox is keyed by filename, so a repeat
    /// overwrites rather than duplicating.
    fn set_cursor(&self, n: u64) {
        if let Some(parent) = self.cursor_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&self.cursor_path, n.to_string());
    }
}

impl Transport for Relay {
    fn put(&self, name: &str, sealed: &[u8]) -> Result<(), String> {
        let resp = minreq::post(format!(
            "{}/drop?name={name}",
            self.url.trim_end_matches('/')
        ))
        .with_body(sealed.to_vec())
        .with_timeout(30)
        .send()
        .map_err(|e| format!("relay unreachable at {}: {e}", self.url))?;
        if resp.status_code != 200 {
            return Err(format!(
                "relay refused the bundle: {} {}",
                resp.status_code,
                resp.as_str().unwrap_or("")
            ));
        }
        Ok(())
    }

    fn take(&self, inbox: &Path) -> Result<usize, String> {
        let from = self.cursor();
        let resp = minreq::get(format!(
            "{}/bag?since={from}",
            self.url.trim_end_matches('/')
        ))
        .with_timeout(60)
        .send()
        .map_err(|e| format!("relay unreachable at {}: {e}", self.url))?;
        if resp.status_code != 200 {
            return Err(format!("relay returned {}", resp.status_code));
        }
        let body = resp.as_bytes();
        let bag: Bag =
            serde_json::from_slice(body).map_err(|e| format!("relay spoke junk: {e}"))?;

        std::fs::create_dir_all(inbox).map_err(|e| format!("mkdir: {e}"))?;
        let mut written = 0usize;
        for item in &bag.items {
            let bytes = match hex::decode(&item.hex) {
                Ok(b) => b,
                // One malformed item must not cost the rest of the fetch, and
                // must not stall the cursor forever behind it.
                Err(_) => continue,
            };
            if !safe_name(&item.name) {
                continue;
            }
            if std::fs::write(inbox.join(&item.name), &bytes).is_ok() {
                written += 1;
            }
        }
        // Advance past everything the relay offered, including items skipped
        // above: they were malformed and will be malformed next time too.
        self.set_cursor(bag.next);
        Ok(written)
    }

    fn describe(&self) -> String {
        format!("relay {}", self.url)
    }
}

/// Is this a filename, or an attempt to write somewhere else?
///
/// Names in a relay's reply come from whoever dropped the blob — a stranger.
/// Without this, `inbox.join(name)` with `../../.ssh/authorized_keys` writes
/// wherever it likes. Allow-list rather than deny-list: the honest names are
/// hex nullifiers with a `.uvb` suffix, so nothing else needs to be expressible.
pub fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !name.contains("..")
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
}

/// The relay's reply to `GET /bag`. Hex rather than raw bytes so the whole
/// response is one JSON document — a bundle is ~208 KB per hop and this is a
/// proof of concept, not a CDN.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Bag {
    pub items: Vec<Item>,
    /// The cursor to send next time.
    pub next: u64,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Item {
    pub name: String,
    pub hex: String,
}
/// Real Signal, via a linked `signal-cli` daemon.
///
/// **Why this and not the `signal/` crate.** That crate speaks the Signal
/// Protocol correctly and proves a payment can ride a PQXDH session — but its
/// relay is a `HashMap`, and wiring it for real needs six libsignal store
/// traits persisted so a ratchet survives between `uv` invocations, each of
/// which is its own process. signal-cli already holds that state, and it links
/// as a *secondary device* — the same mechanism Signal Desktop uses, no new
/// number, no SMS. So payments ride Signal's own servers, unmodified, which is
/// the claim spec/05 could previously only argue.
///
/// It is a third-party client Signal does not support, and each side needs a
/// real account. Said plainly here and in `demo/signal.md`.
///
/// **The bundle stays sealed inside the attachment.** Signal encrypts it again
/// in transit, so a compromise of the Signal account still does not open a
/// payment — the money layer never depends on the carrier.
pub struct SignalCli {
    /// `signal-cli daemon --http` endpoint, e.g. `http://127.0.0.1:8080`.
    pub url: String,
    /// Who to send to: a phone number, or your own for Note-to-Self.
    pub recipient: String,
    /// Where signal-cli writes attachments it has downloaded.
    pub attachments: PathBuf,
    /// Attachment filenames already copied into the inbox.
    pub seen_path: PathBuf,
    /// Scratch directory for outbound attachment files.
    pub outbox: PathBuf,
}

impl SignalCli {
    fn rpc(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, String> {
        let body = serde_json::json!({
            "jsonrpc": "2.0", "method": method, "params": params, "id": 1
        });
        let resp = minreq::post(format!("{}/api/v1/rpc", self.url.trim_end_matches('/')))
            .with_header("Content-Type", "application/json")
            .with_body(body.to_string())
            .with_timeout(120)
            .send()
            .map_err(|e| {
                format!(
                    "signal-cli daemon unreachable at {}: {e}\n  start it with: \
                     signal-cli -a <your-number> daemon --http 127.0.0.1:8080",
                    self.url
                )
            })?;
        let v: serde_json::Value = serde_json::from_slice(resp.as_bytes())
            .map_err(|e| format!("signal-cli spoke junk: {e}"))?;
        if let Some(err) = v.get("error") {
            return Err(format!("signal-cli refused `{method}`: {err}"));
        }
        Ok(v)
    }

    fn seen(&self) -> std::collections::BTreeSet<String> {
        std::fs::read_to_string(&self.seen_path)
            .map(|s| s.lines().map(str::to_string).collect())
            .unwrap_or_default()
    }

    fn remember(&self, seen: &std::collections::BTreeSet<String>) {
        if let Some(p) = self.seen_path.parent() {
            let _ = std::fs::create_dir_all(p);
        }
        let _ = std::fs::write(
            &self.seen_path,
            seen.iter().cloned().collect::<Vec<_>>().join("\n"),
        );
    }

    /// A stable, safe inbox name for an attachment.
    ///
    /// signal-cli names attachments by its own id, which is not guaranteed to
    /// be a shape `safe_name` accepts — and it arrives from the network. Hash
    /// it instead of sanitising: stable across runs (so a re-copy overwrites
    /// rather than duplicating) and incapable of naming anything but a file.
    fn inbox_name(source: &str) -> String {
        use sha2::{Digest as _, Sha256};
        let mut h = Sha256::new();
        h.update(source.as_bytes());
        format!("{}.uvb", hex::encode(&h.finalize()[..16]))
    }
}

impl Transport for SignalCli {
    fn put(&self, name: &str, sealed: &[u8]) -> Result<(), String> {
        std::fs::create_dir_all(&self.outbox).map_err(|e| format!("mkdir outbox: {e}"))?;
        let path = self.outbox.join(name);
        std::fs::write(&path, sealed).map_err(|e| format!("stage attachment: {e}"))?;
        let abs = std::fs::canonicalize(&path).unwrap_or(path);

        // An empty message body: the attachment is the payment, and a text
        // label would put "this is a payment" in the recipient's chat history
        // for no benefit. Signal encrypts both either way.
        self.rpc(
            "send",
            serde_json::json!({
                "recipient": [self.recipient],
                "message": "",
                "attachments": [abs.to_string_lossy()],
            }),
        )?;
        Ok(())
    }

    fn take(&self, inbox: &Path) -> Result<usize, String> {
        // Best effort: this is what makes the daemon fetch and write down
        // anything waiting. Some versions deliver via notifications instead and
        // answer this with an error, in which case the directory scan below
        // still finds whatever the daemon already downloaded. Failing here
        // would turn a version difference into "you have no mail".
        let _ = self.rpc("receive", serde_json::json!({}));

        std::fs::create_dir_all(inbox).map_err(|e| format!("mkdir inbox: {e}"))?;
        let mut seen = self.seen();
        let mut written = 0usize;
        let entries = std::fs::read_dir(&self.attachments)
            .map_err(|e| format!("cannot read {}: {e}", self.attachments.display()))?;
        for e in entries.flatten() {
            let source = e.file_name().to_string_lossy().to_string();
            if seen.contains(&source) {
                continue;
            }
            let Ok(bytes) = std::fs::read(e.path()) else {
                continue;
            };
            // Everyone's attachments land here, not just payments. A file that
            // is not a sealed bundle is somebody's photo; skip it rather than
            // filling the inbox with things every scan will re-verify.
            //
            // Decoded with the real `uv_envelope::Sealed`, not a local
            // look-alike, so a change to the envelope format cannot leave this
            // filter quietly asking last year's question.
            if bincode::deserialize::<uv_envelope::Sealed>(&bytes).is_err() {
                seen.insert(source);
                continue;
            }
            if std::fs::write(inbox.join(Self::inbox_name(&source)), &bytes).is_ok() {
                seen.insert(source);
                written += 1;
            }
        }
        self.remember(&seen);
        Ok(written)
    }

    fn describe(&self) -> String {
        format!("signal-cli -> {}", self.recipient)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_directory_put_lands_where_a_scan_will_look() {
        let dir = std::env::temp_dir().join(format!("uv-t-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let t = Directory {
            inbox: dir.join("inbox"),
        };
        t.put("abc.uvb", b"sealed").unwrap();
        assert_eq!(
            std::fs::read(dir.join("inbox").join("abc.uvb")).unwrap(),
            b"sealed"
        );
        // And `take` is a no-op, because the payer already wrote here.
        assert_eq!(t.take(&dir.join("inbox")).unwrap(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The relay's reply is parsed from a stranger's bytes, so the names in it
    /// are a path-traversal surface. Nothing may land outside the inbox.
    #[test]
    fn a_relay_cannot_write_outside_the_inbox() {
        let root = std::env::temp_dir().join(format!("uv-esc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let inbox = root.join("inbox");
        std::fs::create_dir_all(&inbox).unwrap();

        for bad in [
            "../escaped.uvb",
            "a/b.uvb",
            "..",
            "",
            "/etc/passwd",
            "x/../../y",
            "..\\windows",
            "a\u{0}b",
        ] {
            assert!(!safe_name(bad), "{bad:?} must be refused as a filename");
        }
        // ...and a real one is accepted, or the filter rejects everything and
        // this test would pass while delivering no mail at all.
        assert!(safe_name(
            "8cfd33132e4cc657ee68a645ef95b14e1873ce5f826d072683d9d0038b9d4653.uvb"
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_cursor_survives_and_defaults_to_zero() {
        let root = std::env::temp_dir().join(format!("uv-cur-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let r = Relay {
            url: "http://127.0.0.1:1".into(),
            cursor_path: root.join("cursor"),
        };
        assert_eq!(r.cursor(), 0, "no file means start from the beginning");
        r.set_cursor(42);
        assert_eq!(r.cursor(), 42);
        let _ = std::fs::remove_dir_all(&root);
    }
}

//! Fetching mirror pages over HTTP/1.1, by hand.
//!
//! A wallet needs exactly two requests — `GET /head` and `GET /pages` — and
//! the money path already argues for a small dependency closure. An HTTP
//! client crate would pull a TLS stack and often an async runtime into the
//! binary that also holds the prover; a hundred lines of `TcpStream` is less
//! to audit and less to ship.
//!
//! **Plain HTTP is deliberate and stated, not overlooked.** A mirror serves
//! public chain data to anyone who asks, so confidentiality of the *response*
//! buys nothing — everyone may have it. What TLS would buy is integrity
//! against a network attacker who edits pages in flight, and that attack is
//! the same one a dishonest mirror can mount anyway. The defence is therefore
//! not the transport: it is that a phone **cross-checks page digests across
//! mirrors** (`uv_btc::mirror::disagreements`) and refuses a feed with a hole
//! in it. Adding TLS would narrow the set of attackers without changing what
//! the client must already assume, which is why it is not the first thing
//! bought here. A public deployment should still have it, and the
//! `[STORAGE]`/mirror notes in spec/99 say so.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::mirror::{MirrorView, Page, Synced};

/// A page never legitimately exceeds this. A mirror that sends more is either
/// broken or hostile, and a phone that read it anyway would be a phone whose
/// memory a stranger controls.
const MAX_BODY: usize = 32 * 1024 * 1024;

fn get(base: &str, path: &str) -> Result<Vec<u8>, String> {
    let host = base
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_string();
    let mut stream = TcpStream::connect(&host).map_err(|e| format!("connect {host}: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| format!("timeout: {e}"))?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("write: {e}"))?;

    let mut reader = BufReader::new(stream);
    let mut status = String::new();
    reader
        .read_line(&mut status)
        .map_err(|e| format!("read status: {e}"))?;
    if !status.contains(" 200") {
        return Err(format!("mirror said: {}", status.trim()));
    }
    // Drain headers. Content-Length is ignored on purpose: the connection is
    // closed by the server, so read-to-end is the framing, and a truncated
    // body fails to parse rather than being trusted at its claimed length.
    loop {
        let mut h = String::new();
        match reader.read_line(&mut h) {
            Ok(0) => break,
            Ok(_) if h.trim().is_empty() => break,
            Ok(_) => {}
            Err(e) => return Err(format!("read headers: {e}")),
        }
    }
    let mut body = Vec::new();
    reader
        .take(MAX_BODY as u64)
        .read_to_end(&mut body)
        .map_err(|e| format!("read body: {e}"))?;
    Ok(body)
}

/// Catch a view up to a mirror's tip, one page request at a time.
///
/// Returns what the final sync learned. **A caller must not treat an error as
/// "nothing new"**: the view keeps whatever it had, remains not-caught-up, and
/// every lookup answers `Unanswerable` — which is the refusal that keeps an
/// out-of-date phone from accepting a double-spend.
pub fn sync_all(view: &MirrorView, base: &str) -> Result<Synced, String> {
    let head = get(base, "/head")?;
    let head: serde_json::Value =
        serde_json::from_slice(&head).map_err(|e| format!("head is not JSON: {e}"))?;
    let tip = head["tip"].as_u64().ok_or("head has no tip")?;

    let mut last = None;
    // Bounded: a mirror that never advances `through` would otherwise spin
    // forever. Each iteration must make progress or the loop ends.
    for _ in 0..10_000 {
        let from = view.next_height();
        if from > tip {
            break;
        }
        let body = get(base, &format!("/pages?from={from}"))?;
        let pages: Vec<Page> =
            serde_json::from_slice(&body).map_err(|e| format!("pages are not JSON: {e}"))?;
        if pages.is_empty() {
            break;
        }
        let advanced = pages.iter().any(|p| p.through >= from);
        let synced = view.sync(from, &pages)?;
        let complete = synced.complete();
        last = Some(synced);
        if complete || !advanced {
            break;
        }
    }
    last.ok_or_else(|| "mirror returned no pages".to_string())
}

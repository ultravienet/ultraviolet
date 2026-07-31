//! `uv-mirror` — serves ranges of the chain so a phone never has to ask about
//! a coin.
//!
//! ```text
//! uv-mirror --bind 0.0.0.0:8788 --index ./uv-record-index.json
//! ```
//!
//! **Why this exists at all.** A phone cannot run a full node, and safe
//! receiving needs one chain lookup per hop: *did this nullifier's record win
//! its race?* Asking a server that question hands it the two facts the design
//! exists to hide — which coins are yours, and when you are about to spend
//! them. So no such endpoint is offered here. This serves **pages of
//! everything** by height, and the phone answers its own lookups from its own
//! replayed index (`uv_btc::mirror`).
//!
//! **What the operator can see:** that somebody asked for a range of blocks.
//! That is what any block explorer, any SPV wallet, and any node already
//! reveals. There is no per-caller filtering to do, which is the point rather
//! than an omission.
//!
//! **What the operator is trusted for:** completeness, and nothing else. Proofs
//! are verified on the phone and a lying mirror cannot make an invalid payment
//! valid — but a mirror that *omits* a record can make a double-spend look
//! unopposed. That is why pages are content-addressed, why a client refuses a
//! feed with a hole in it, and why running two mirrors from different operators
//! turns the assumption into a comparison (`uv_btc::mirror::disagreements`).
//!
//! **What it deliberately does not do:** authenticate, rate-limit, or expire.
//! Same posture as `uv-relay`, and the same honesty about it: a public one
//! would want a size cap and a connection limit, and this is a proof of
//! concept that says so rather than one that hopes nobody notices.
//!
//! The index it serves is the ordinary one a full-node-backed wallet builds
//! (`uv --backend signet scan` writes it). A mirror is not a special kind of
//! node; it is a wallet that shares its reading.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use uv_btc::index::RecordIndex;
use uv_btc::mirror;

/// Heights per page. Small enough that a phone on a slow link makes progress
/// and can abandon a page cheaply; large enough that catching up on a long
/// chain is not a million requests.
const PAGE_SPAN: u64 = 1_000;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let flag = |name: &str, default: &str| -> String {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .cloned()
            .unwrap_or_else(|| default.to_string())
    };
    let bind = flag("--bind", "127.0.0.1:8788");
    let index_path = PathBuf::from(flag("--index", "./uv-record-index.json"));

    // **Adopt the index's own floor.** Demanding zero here was a real bug:
    // `RecordIndex::load` discards an index built from a *later* floor — the
    // right call in general, since it cannot answer for earlier blocks — so a
    // mirror pointed at a floored index silently served an empty one, reported
    // tip 0, and a client concluded "no record exists" for a nullifier that was
    // on chain. The floor is served in `/head` and in every page instead, so a
    // client bounds its own answers by it rather than being misled.
    let stored = RecordIndex::stored_floor(&index_path).unwrap_or(0);
    let index = Arc::new(Mutex::new(RecordIndex::load(&index_path, stored)));
    let floor = index.lock().unwrap().scan_floor();
    let through = index.lock().unwrap().tip_scanned().map(|(h, _)| h);

    let listener = TcpListener::bind(&bind).unwrap_or_else(|e| {
        eprintln!("cannot bind {bind}: {e}");
        std::process::exit(1);
    });
    println!("uv-mirror on {bind}, index {}", index_path.display());
    match through {
        Some(h) => println!("  serving heights {floor}..={h}"),
        None => println!(
            "  WARNING: this index has scanned nothing. Clients will read it as \
             incomplete and refuse to accept payments against it, which is correct."
        ),
    }
    println!("  GET /pages?from=N[&span=M]   GET /head");
    println!("it can see that someone asked for blocks. It cannot see which coins are theirs.");

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let index = Arc::clone(&index);
        let path = index_path.clone();
        std::thread::spawn(move || {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                serve(stream, &index, &path)
            }));
        });
    }
}

fn reply(s: &mut TcpStream, code: u16, kind: &str, body: &[u8]) {
    let head = format!(
        "HTTP/1.1 {code} {}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        if code == 200 { "OK" } else { "Error" },
        body.len()
    );
    let _ = s.write_all(head.as_bytes());
    let _ = s.write_all(body);
    let _ = s.flush();
}

fn query(target: &str, key: &str) -> Option<u64> {
    target
        .split_once('?')?
        .1
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == key)
        .and_then(|(_, v)| v.parse().ok())
}

fn serve(mut stream: TcpStream, index: &Mutex<RecordIndex>, path: &std::path::Path) {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(30)));
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    });

    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return;
    }
    let mut parts = line.split_whitespace();
    let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));

    // Drain headers; a body is never read because nothing here accepts one.
    loop {
        let mut h = String::new();
        match reader.read_line(&mut h) {
            Ok(0) => break,
            Ok(_) if h.trim().is_empty() => break,
            Ok(_) => {}
            Err(_) => return,
        }
    }
    let mut sink = Vec::new();
    let _ = reader.get_mut().take(0).read_to_end(&mut sink);

    // Re-read from disk per request: the index is written by whichever `uv`
    // process is scanning, so a long-lived mirror that cached it would serve a
    // frozen chain forever — and "frozen" reads to a client as "complete but
    // behind", which is the shape of a stale-view bug.
    let fresh = RecordIndex::load(path, RecordIndex::stored_floor(path).unwrap_or(0));
    *index.lock().unwrap() = fresh;
    let idx = index.lock().unwrap();
    let tip = idx.tip_scanned().map(|(h, _)| h).unwrap_or(0);

    match (method, target.split('?').next().unwrap_or("")) {
        ("GET", "/head") => {
            let body = serde_json::json!({
                "tip": tip,
                "floor": idx.scan_floor(),
                "page_span": PAGE_SPAN,
            });
            reply(
                &mut stream,
                200,
                "application/json",
                body.to_string().as_bytes(),
            );
        }
        ("GET", "/pages") => {
            let from = query(target, "from").unwrap_or(0);
            let span = query(target, "span")
                .unwrap_or(PAGE_SPAN)
                .clamp(1, PAGE_SPAN);
            if from > tip {
                // Not an error: a client that is caught up asks for the next
                // height and gets an empty page saying so.
                let page = mirror::Page {
                    from,
                    through: from.saturating_sub(1),
                    tip,
                    floor: idx.scan_floor(),
                    records: Vec::new(),
                    issuances: Vec::new(),
                };
                let body = serde_json::to_vec(&[page]).unwrap_or_default();
                reply(&mut stream, 200, "application/json", &body);
                return;
            }
            let through = (from + span - 1).min(tip);
            let page = mirror::build_page(&idx, from, through, tip);
            let body = serde_json::to_vec(&[page]).unwrap_or_default();
            reply(&mut stream, 200, "application/json", &body);
        }
        _ => reply(
            &mut stream,
            404,
            "text/plain",
            b"GET /pages?from=N[&span=M] or GET /head\n\
              (there is deliberately no endpoint that takes a nullifier)\n",
        ),
    }
}

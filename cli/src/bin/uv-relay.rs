//! `uv-relay` — an append-only bag of opaque blobs.
//!
//! ```text
//! uv-relay --bind 0.0.0.0:8787 --dir ./relay-data
//! ```
//!
//! **What it is for.** Two people on two machines need somewhere to leave a
//! sealed bundle for each other. This is the smallest thing that works. Real
//! Signal is the destination (spec/99 `[SIGNAL]`); this exists so the rail can
//! be used by anyone who does not want to link a Signal account to try it, and
//! so there is a fallback when Signal is the thing being debugged.
//!
//! **What the operator can see.** Byte counts, timing, and source IPs. Nothing
//! else — not who is paying whom, not amounts, not even which blobs belong
//! together. Bundles arrive already sealed to a scan key nobody here knows, and
//! there is no addressee field to read, because recipients find their own mail
//! by trying to open everything (`cli/src/transport.rs`).
//!
//! **What it deliberately does not do:** authenticate, rate-limit, expire,
//! or delete. Anyone can drop anything and everyone can fetch everything. That
//! is honest for a proof of concept and is stated in the README rather than
//! discovered — a public one would want at least a size cap and an expiry, and
//! is not what this is.
//!
//! Hand-rolled HTTP/1.1: two endpoints do not justify a web framework, and this
//! sits off the money path entirely, so the argument for a small dependency
//! closure is weaker here than anywhere else in the tree — but a hundred lines
//! of `TcpListener` is still less to reason about than a runtime.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

// The same allow-list the client applies, from the same source. Checked here
// too rather than trusted: a relay that stores `../` names corrupts its own
// directory regardless of what the client later does about it.
use uv_cli::transport::safe_name;

/// Refuse anything absurd before reading it. A bundle is ~208 KB per hop and
/// `MAX_LINEAGE` is 256, so this is the ceiling a real payment could reach with
/// room to spare — and it stops one POST eating the machine's memory.
const MAX_DROP_BYTES: usize = 80 * 1024 * 1024;

struct Bag {
    dir: PathBuf,
    /// Names in arrival order. The index into this is the cursor.
    order: Vec<String>,
}

impl Bag {
    /// Rebuild from disk so a restart does not lose the bag or renumber it.
    ///
    /// Blobs are stored as `<seq>-<name>`, and the sequence is what fixes the
    /// order — directory listing order is not defined, and a cursor against an
    /// unstable order would silently skip mail.
    fn open(dir: PathBuf) -> std::io::Result<Self> {
        std::fs::create_dir_all(&dir)?;
        let mut seen: Vec<(u64, String)> = std::fs::read_dir(&dir)?
            .flatten()
            .filter_map(|e| {
                let f = e.file_name().to_string_lossy().to_string();
                let (seq, name) = f.split_once('-')?;
                Some((seq.parse().ok()?, name.to_string()))
            })
            .collect();
        seen.sort_by_key(|(seq, _)| *seq);
        Ok(Bag {
            dir,
            order: seen.into_iter().map(|(_, n)| n).collect(),
        })
    }

    fn add(&mut self, name: &str, bytes: &[u8]) -> std::io::Result<()> {
        let seq = self.order.len() as u64;
        std::fs::write(self.dir.join(format!("{seq:012}-{name}")), bytes)?;
        self.order.push(name.to_string());
        Ok(())
    }

    /// Everything at or after `since`, plus the cursor to use next.
    fn since(&self, since: usize) -> (Vec<(String, Vec<u8>)>, usize) {
        let mut out = Vec::new();
        for (i, name) in self.order.iter().enumerate().skip(since) {
            if let Ok(b) = std::fs::read(self.dir.join(format!("{i:012}-{name}"))) {
                out.push((name.clone(), b));
            }
        }
        (out, self.order.len())
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let flag = |name: &str, default: &str| -> String {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .cloned()
            .unwrap_or_else(|| default.to_string())
    };
    let bind = flag("--bind", "127.0.0.1:8787");
    let dir = PathBuf::from(flag("--dir", "./uv-relay-data"));

    let bag = Arc::new(Mutex::new(Bag::open(dir.clone()).unwrap_or_else(|e| {
        eprintln!("cannot use {}: {e}", dir.display());
        std::process::exit(1);
    })));
    let held = bag.lock().unwrap().order.len();

    let listener = TcpListener::bind(&bind).unwrap_or_else(|e| {
        eprintln!("cannot bind {bind}: {e}");
        std::process::exit(1);
    });
    println!("uv-relay on {bind}, {} blob(s) in {}", held, dir.display());
    println!("  POST /drop?name=X   GET /bag?since=N");
    println!("it can see byte counts and timing. It cannot see who, whom, or how much.");

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let bag = Arc::clone(&bag);
        // A thread per connection: one slow client must not stall everyone
        // else, and a panic in a handler must not take the relay down.
        std::thread::spawn(move || {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| serve(stream, &bag)));
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

fn serve(mut stream: TcpStream, bag: &Mutex<Bag>) {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(60)));
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

    let mut length = 0usize;
    loop {
        let mut h = String::new();
        match reader.read_line(&mut h) {
            Ok(0) => break,
            Ok(_) => {}
            Err(_) => return,
        }
        if h.trim().is_empty() {
            break;
        }
        if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
            length = v.trim().parse().unwrap_or(0);
        }
    }

    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let param = |key: &str| -> Option<String> {
        query
            .split('&')
            .filter_map(|kv| kv.split_once('='))
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.to_string())
    };

    match (method, path) {
        ("POST", "/drop") => {
            if length > MAX_DROP_BYTES {
                reply(&mut stream, 413, "text/plain", b"too large for any payment");
                return;
            }
            let name = param("name").unwrap_or_default();
            if !safe_name(&name) {
                reply(&mut stream, 400, "text/plain", b"bad name");
                return;
            }
            let mut body = vec![0u8; length];
            if reader.read_exact(&mut body).is_err() {
                reply(&mut stream, 400, "text/plain", b"short body");
                return;
            }
            let stored = bag.lock().ok().and_then(|mut b| b.add(&name, &body).ok());
            match stored {
                Some(()) => reply(&mut stream, 200, "text/plain", b"ok"),
                None => reply(&mut stream, 500, "text/plain", b"could not store"),
            }
        }
        ("GET", "/bag") => {
            let since: usize = param("since").and_then(|s| s.parse().ok()).unwrap_or(0);
            let (items, next) = match bag.lock() {
                Ok(b) => b.since(since),
                Err(_) => {
                    reply(&mut stream, 500, "text/plain", b"bag unavailable");
                    return;
                }
            };
            let body = serde_json::json!({
                "items": items.into_iter()
                    .map(|(name, bytes)| serde_json::json!({"name": name, "hex": hex::encode(bytes)}))
                    .collect::<Vec<_>>(),
                "next": next,
            });
            reply(
                &mut stream,
                200,
                "application/json",
                body.to_string().as_bytes(),
            );
        }
        ("GET", "/") => reply(
            &mut stream,
            200,
            "text/plain",
            b"uv-relay: POST /drop?name=X, GET /bag?since=N\n",
        ),
        _ => reply(&mut stream, 404, "text/plain", b"no such thing here"),
    }
}

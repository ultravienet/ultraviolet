//! The signal-cli transport, against a stub that speaks its JSON-RPC.
//!
//! **Why a stub and not the real thing.** signal-cli needs a linked Signal
//! account, and neither CI nor a fresh clone has one. Without a test, the only
//! evidence this code works would be one person running it once — and the parts
//! most likely to be wrong are exactly the mechanical ones a stub *can* check:
//! the JSON-RPC envelope, whether an attachment path actually reaches `send`,
//! whether an error is noticed rather than swallowed, and whether the same
//! attachment gets copied into the inbox twice.
//!
//! What the stub cannot check is that Signal accepts any of it. That is
//! `demo/signal.md`, run by hand against two real accounts and recorded in a
//! ledger, the same discipline as `formal/verify.sh`.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::mpsc;

use uv_cli::transport::{SignalCli, Transport};

/// A one-connection-at-a-time stand-in for `signal-cli daemon --http`.
///
/// Returns its URL and a channel carrying every request body it saw, so a test
/// can assert on what was actually sent rather than on what we meant to send.
fn stub_daemon(
    reply: &'static str,
) -> (String, mpsc::Receiver<String>, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!("http://{}", listener.local_addr().unwrap());
    let (tx, rx) = mpsc::channel();
    let handle = std::thread::spawn(move || {
        // Exactly one request per stub: each test makes one call, and accepting
        // a second would leave the thread parked on a port nobody will use.
        if let Ok(mut stream) = listener.accept().map(|(s, _)| s) {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() {
                return;
            }
            let mut len = 0usize;
            loop {
                let mut h = String::new();
                if reader.read_line(&mut h).is_err() || h.trim().is_empty() {
                    break;
                }
                if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0u8; len];
            let _ = reader.read_exact(&mut body);
            let _ = tx.send(String::from_utf8_lossy(&body).to_string());

            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                reply.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(reply.as_bytes());
            let _ = stream.flush();
        }
    });
    (url, rx, handle)
}

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("uv-sig-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A real sealed bundle, so the "is this a payment?" filter is exercised with
/// the shape it will actually meet rather than a hand-rolled look-alike.
fn a_real_sealed_bundle() -> Vec<u8> {
    let (_, scan) = uv_envelope::derive_scan(&[7u8; 32]);
    let sealed = uv_envelope::seal(&scan, b"a bundle would be here").expect("seal");
    bincode::serialize(&sealed).expect("serialize")
}

#[test]
fn send_puts_the_attachment_path_and_recipient_on_the_wire() {
    let d = scratch("send");
    let (url, rx, h) = stub_daemon(r#"{"jsonrpc":"2.0","result":{"timestamp":1},"id":1}"#);
    let t = SignalCli {
        url,
        recipient: "+15550001111".into(),
        attachments: d.join("att"),
        seen_path: d.join("seen"),
        outbox: d.join("out"),
    };

    t.put("deadbeef.uvb", b"sealed payload").expect("send");

    let body = rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
    let v: serde_json::Value = serde_json::from_str(&body).expect("stub saw JSON");
    assert_eq!(v["method"], "send");
    assert_eq!(v["params"]["recipient"][0], "+15550001111");
    let attached = v["params"]["attachments"][0].as_str().unwrap();
    assert!(
        attached.ends_with("deadbeef.uvb"),
        "the attachment path must reach signal-cli, got {attached:?}"
    );
    // The bytes must really be on disk where that path says, or signal-cli
    // would be handed a name pointing at nothing.
    assert_eq!(std::fs::read(attached).unwrap(), b"sealed payload");
    let _ = h.join();
    let _ = std::fs::remove_dir_all(&d);
}

/// A refusal from signal-cli must surface. JSON-RPC signals failure with a
/// 200 and an `error` member, so a transport that only checked the HTTP status
/// would report a payment as delivered when it was rejected.
#[test]
fn a_json_rpc_error_is_not_mistaken_for_success() {
    let d = scratch("err");
    let (url, _rx, h) = stub_daemon(
        r#"{"jsonrpc":"2.0","error":{"code":-32602,"message":"Unregistered user"},"id":1}"#,
    );
    let t = SignalCli {
        url,
        recipient: "+15550009999".into(),
        attachments: d.join("att"),
        seen_path: d.join("seen"),
        outbox: d.join("out"),
    };

    let outcome = t.put("x.uvb", b"sealed");
    let msg = outcome.expect_err("an error member means the send failed");
    assert!(
        msg.contains("Unregistered user"),
        "the reason must reach the user, got {msg:?}"
    );
    let _ = h.join();
    let _ = std::fs::remove_dir_all(&d);
}

/// Receiving: payments are copied in, everything else is left alone, and
/// nothing is copied twice.
#[test]
fn take_collects_payments_once_and_ignores_other_attachments() {
    let d = scratch("take");
    let att = d.join("att");
    let inbox = d.join("inbox");
    std::fs::create_dir_all(&att).unwrap();

    // What a real attachments directory looks like: our payment, and somebody's
    // photo, under signal-cli's own opaque ids.
    std::fs::write(att.join("Zm9vYmFy1234"), a_real_sealed_bundle()).unwrap();
    std::fs::write(att.join("cGhvdG85999"), b"\x89PNG\r\n\x1a\n not a payment").unwrap();

    let make = |url: String| SignalCli {
        url,
        recipient: "+15550001111".into(),
        attachments: att.clone(),
        seen_path: d.join("seen"),
        outbox: d.join("out"),
    };

    let (url, _rx, h) = stub_daemon(r#"{"jsonrpc":"2.0","result":[],"id":1}"#);
    let got = make(url).take(&inbox).expect("take");
    let _ = h.join();
    assert_eq!(got, 1, "exactly the payment should be collected");

    let names: Vec<String> = std::fs::read_dir(&inbox)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    assert_eq!(names.len(), 1, "the photo must not be in the inbox");
    assert!(
        names[0].ends_with(".uvb") && names[0].len() == 36,
        "inbox names must be derived, not taken from the network: {names:?}"
    );

    // Second pass: nothing new, and no duplicate. Re-copying would make every
    // scan re-verify a payment it already holds.
    let (url2, _rx2, h2) = stub_daemon(r#"{"jsonrpc":"2.0","result":[],"id":1}"#);
    let again = make(url2).take(&inbox).expect("take again");
    let _ = h2.join();
    assert_eq!(
        again, 0,
        "an already-collected attachment must not come again"
    );
    assert_eq!(std::fs::read_dir(&inbox).unwrap().count(), 1);

    let _ = std::fs::remove_dir_all(&d);
}

/// A daemon that is not running must say so usefully, and must not be reported
/// as "no mail" — the two are very different for someone waiting on money.
#[test]
fn an_absent_daemon_is_an_error_not_an_empty_inbox() {
    let d = scratch("down");
    std::fs::create_dir_all(d.join("att")).unwrap();
    let t = SignalCli {
        // Port 1 is reserved and nothing listens there.
        url: "http://127.0.0.1:1".into(),
        recipient: "+15550001111".into(),
        attachments: d.join("att"),
        seen_path: d.join("seen"),
        outbox: d.join("out"),
    };
    let msg = t.put("x.uvb", b"sealed").expect_err("no daemon, no send");
    assert!(
        msg.contains("daemon") && msg.contains("signal-cli"),
        "the message should tell someone how to start it, got {msg:?}"
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// A freshly linked device has no attachments directory until something with
/// an attachment arrives. That must read as "no mail yet".
///
/// Found by running this against a real account: the very first scan after
/// linking reported `cannot read .../attachments: No such file or directory`,
/// which makes a correct setup look broken at exactly the moment someone is
/// least able to tell the difference.
#[test]
fn a_freshly_linked_device_has_no_mail_rather_than_an_error() {
    let d = scratch("fresh");
    let (url, _rx, h) = stub_daemon(r#"{"jsonrpc":"2.0","result":[],"id":1}"#);
    let t = SignalCli {
        url,
        recipient: "+15550001111".into(),
        // Deliberately absent: signal-cli has not created it yet.
        attachments: d.join("never-created"),
        seen_path: d.join("seen"),
        outbox: d.join("out"),
    };
    assert_eq!(t.take(&d.join("inbox")).expect("absent is not an error"), 0);
    let _ = h.join();
    let _ = std::fs::remove_dir_all(&d);
}

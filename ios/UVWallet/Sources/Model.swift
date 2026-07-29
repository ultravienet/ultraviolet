import Foundation
import SwiftUI

/// The app's whole state. One object, because the wallet is one thing and a
/// phone showing two disagreeing views of a balance is worse than a phone
/// showing one late.
@MainActor
final class Model: ObservableObject {
    /// The wallet name inside the home. One wallet per app today; the CLI's
    /// multi-wallet homes are a desktop convenience.
    let wallet = "phone"

    @Published var spendable: UInt64 = 0
    @Published var notes: [NoteLine] = []
    @Published var status: Status?
    @Published var address: String?
    @Published var busy = false
    /// The last refusal, shown as an alert. `transient` decides whether the
    /// alert offers "try again" — a node that is down says nothing about the
    /// money, and telling someone their payment failed when their network
    /// blinked is how a wallet loses trust it cannot re-earn.
    @Published var failure: UVError?

    struct NoteLine: Identifiable {
        let id = UUID()
        let state: String
        let amount: UInt64
        let commitment: String
    }

    struct Status {
        let addressID: String
        let tip: String
        let scanFloor: UInt64
        let anchor: String
        let unspent: UInt64
        let inFlight: UInt64
        let spent: UInt64
        let quarantined: UInt64
        let stuck: Int
    }

    /// Run a command off the main thread, publish the result on it.
    private func run<T>(_ work: @escaping () throws -> T, then apply: @escaping (T) -> Void) {
        busy = true
        Task.detached(priority: .userInitiated) {
            do {
                let value = try work()
                await MainActor.run {
                    apply(value)
                    self.busy = false
                }
            } catch let e as UVError {
                await MainActor.run {
                    self.failure = e
                    self.busy = false
                }
            } catch {
                await MainActor.run {
                    self.failure = UVError(kind: "panic", message: "\(error)", transient: false)
                    self.busy = false
                }
            }
        }
    }

    func refresh() {
        let w = wallet
        run({ try UV.callObject(["cmd": "balance", "wallet": w]) }) { ok in
            self.spendable = (ok["spendable"] as? NSNumber)?.uint64Value ?? 0
            self.notes = (ok["notes"] as? [[String: Any]] ?? []).map {
                NoteLine(
                    state: "\($0["state"] ?? "?")",
                    amount: ($0["amount"] as? NSNumber)?.uint64Value ?? 0,
                    commitment: $0["commitment_hex"] as? String ?? ""
                )
            }
        }
        refreshStatus()
    }

    func refreshStatus() {
        let w = wallet
        run({ try UV.callObject(["cmd": "status", "wallet": w]) }) { ok in
            let tally = ok["notes"] as? [String: Any] ?? [:]
            // `tip` is a Result on the Rust side: a string on the error arm, so
            // an unreachable node reports as a report rather than as nothing.
            let tip: String
            if let t = ok["tip"] as? [String: Any] {
                if let v = t["Ok"] as? NSNumber { tip = "\(v)" } else { tip = "unavailable" }
            } else if let v = ok["tip"] as? NSNumber {
                tip = "\(v)"
            } else {
                tip = "unavailable"
            }
            var anchor = "no anchor — cannot validate anything"
            if let a = ok["anchor"] as? [String: Any],
               let present = a["Present"] as? [String: Any],
               let asset = present["asset_hex"] as? String {
                anchor = String(asset.prefix(16)) + "…"
            } else if let a = ok["anchor"] as? [String: Any], a["Unreadable"] != nil {
                anchor = "anchor unreadable"
            }
            self.status = Status(
                addressID: ok["address_id"] as? String ?? "?",
                tip: tip,
                scanFloor: (ok["scan_floor"] as? NSNumber)?.uint64Value ?? 0,
                anchor: anchor,
                unspent: (tally["unspent"] as? NSNumber)?.uint64Value ?? 0,
                inFlight: (tally["in_flight"] as? NSNumber)?.uint64Value ?? 0,
                spent: (tally["spent"] as? NSNumber)?.uint64Value ?? 0,
                quarantined: (tally["quarantined"] as? NSNumber)?.uint64Value ?? 0,
                stuck: (ok["stuck"] as? NSNumber)?.intValue ?? 0
            )
        }
    }

    /// Fresh slots to hand ONE counterparty. Each slot pays once; handing one
    /// batch to two payers means both start at slot 0 and the second payment
    /// has nowhere to sit.
    func makeAddress(count: UInt64, peer: String?) {
        let w = wallet
        var req: [String: Any] = ["cmd": "address", "wallet": w, "count": count]
        if let p = peer, !p.isEmpty { req["peer"] = p }
        run({ try UV.call(req) }) { r in
            if let ok = r["ok"],
               let data = try? JSONSerialization.data(withJSONObject: ok, options: [.prettyPrinted]) {
                self.address = String(data: data, encoding: .utf8)
            }
            self.refreshStatus()
        }
    }

    /// Take mail from the inbox: verify whole lineages, store what settles.
    func scan() {
        let w = wallet
        run({ try UV.callObject(["cmd": "scan", "wallet": w]) }) { _ in self.refresh() }
    }
}

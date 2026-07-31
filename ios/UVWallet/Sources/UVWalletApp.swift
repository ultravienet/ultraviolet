import SwiftUI
import UIKit

@main
struct UVWalletApp: App {
    @StateObject private var model = Model()

    init() {
        // A smoke test for the whole stack, run only when asked
        // (`UV_SELFTEST=1` in the launch environment). It proves on the actual
        // device that Swift reached Rust, that the command layer answered, and
        // that a wallet round-tripped through the app's own container —
        // questions a screenshot cannot answer and a simulator run should not
        // be trusted to answer for a phone.
        if ProcessInfo.processInfo.environment["UV_SELFTEST"] == "1" {
            UVSelfTest.run()
        }
    }

    var body: some Scene {
        WindowGroup {
            RootView().environmentObject(model)
        }
    }
}

@_silgen_name("uv_measure")
private func uv_measure(_ runs: UInt32, _ mode: UInt32) -> UnsafeMutablePointer<CChar>?
@_silgen_name("uv_free")
private func uv_free_m(_ p: UnsafeMutablePointer<CChar>?)

enum UVSelfTest {
    /// Everything the self-test says, kept in the app container as well as the
    /// system log. A console stream needs the phone unlocked at exactly the
    /// right moment; a file can be pulled whenever, which is what makes a
    /// device run repeatable instead of a race.
    private static var transcript: [String] = []

    private static func say(_ line: String) {
        NSLog("UVSELFTEST %@", line)
        transcript.append(line)
    }

    /// Where the transcript lands. Pullable with
    /// `xcrun devicectl device copy from --domain-type appDataContainer`, which
    /// is how a device run gets reported without racing the lock screen.
    static var transcriptPath: URL { UV.home.appendingPathComponent("selftest.log") }

    private static func writeTranscript() {
        let path = transcriptPath
        try? transcript.joined(separator: "\n").appending("\n")
            .write(to: path, atomically: true, encoding: .utf8)
    }

    /// The number the benchmarks page has been missing: what a payment costs
    /// to prove on this actual phone. Runs one configuration per call so the
    /// peak-memory figure belongs to one circuit.
    private static func measure(_ label: String, mode: UInt32) {
        guard let p = uv_measure(3, mode) else {
            say("measure-\(label)=FAILED")
            return
        }
        let out = String(cString: p)
        uv_free_m(p)
        for line in out.split(separator: "\n") where !line.isEmpty {
            say("measure-\(label) \(line)")
        }
    }

    static func run() {
        transcript.removeAll()
        say("home=\(UV.home.path)")
        say("device=\(UIDevice.current.model) ios=\(UIDevice.current.systemVersion)")
        do {
            let before = try UV.callObject(["cmd": "balance", "wallet": "selftest"])
            say("balance-before=\(before["spendable"] ?? "?")")

            let issued = try UV.callObject(["cmd": "issue", "wallet": "selftest", "amount": 700])
say("issued=\(issued["amount"] ?? "?") asset=\(String("\(issued["asset_hex"] ?? "?")".prefix(16)))")

            let after = try UV.callObject(["cmd": "balance", "wallet": "selftest"])
            say("balance-after=\(after["spendable"] ?? "?")")

            let addr = try UV.callObject(["cmd": "address", "wallet": "selftest", "count": 3])
            let slots = (addr["slots"] as? [[String: Any]])?.count ?? 0
            say("address-slots=\(slots)")

            // The failure path matters as much: a refusal must arrive as a
            // typed error, not a crash.
            do {
                _ = try UV.callObject(["cmd": "nope"])
                say("FAIL: unknown command did not refuse")
            } catch let e as UVError {
                say("refusal-kind=\(e.kind)")
            }

            // **Relative, not absolute.** This asserted `== 700`, which passed
            // once and then failed on every later run of a wallet that already
            // held coins — a test that only works on a fresh device is a test
            // that reports FAIL for a working build. What must hold is that
            // issuing 700 raised the balance by exactly 700.
            let b0 = UInt64("\(before["spendable"] ?? "0")") ?? 0
            let b1 = UInt64("\(after["spendable"] ?? "0")") ?? 0
            let ok = b1 == b0 + 700 && slots == 3
            say("balance-delta=\(b1 &- b0) (expected 700)")
            say(ok ? "PASS" : "FAIL")

            // Real hardware timings, after the correctness check — a number
            // from a build that does not work is worth nothing.
            measure("standard", mode: 1)
            measure("hiding", mode: 2)
        } catch {
            say("FAIL: \(error)")
        }
        writeTranscript()
    }
}

struct RootView: View {
    @EnvironmentObject var model: Model
    // Which tab to open on. Normally Balance; `UV_TAB` overrides it so the
    // screenshots on the website can be retaken by a command instead of by
    // someone tapping and cropping.
    @State private var tab = Int(ProcessInfo.processInfo.environment["UV_TAB"] ?? "0") ?? 0

    var body: some View {
        TabView(selection: $tab) {
            BalanceView().tabItem { Label("Balance", systemImage: "creditcard") }.tag(0)
            ReceiveView().tabItem { Label("Receive", systemImage: "qrcode") }.tag(1)
            StatusView().tabItem { Label("Status", systemImage: "stethoscope") }.tag(2)
        }
        .onAppear { model.refresh() }
        .alert(item: Binding(
            get: { model.failure.map { AlertBox(error: $0) } },
            set: { _ in model.failure = nil }
        )) { box in
            // Transient and permanent read differently on purpose: a node that
            // is down says nothing about the money.
            Alert(
                title: Text(box.error.transient ? "Try again in a moment" : "Refused"),
                message: Text(box.error.message),
                dismissButton: .default(Text("OK"))
            )
        }
    }

    struct AlertBox: Identifiable {
        let id = UUID()
        let error: UVError
    }
}

struct BalanceView: View {
    @EnvironmentObject var model: Model

    var body: some View {
        NavigationStack {
            List {
                Section {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("\(model.spendable)")
                            .font(.system(size: 44, weight: .semibold, design: .rounded))
                        // Said plainly, because it is the number people act on:
                        // in-flight, quarantined and spent notes are not it.
                        Text("spendable — unspent notes only")
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 6)
                }
                Section("Notes") {
                    if model.notes.isEmpty {
                        Text("no notes yet").foregroundStyle(.secondary)
                    }
                    ForEach(model.notes) { n in
                        HStack {
                            Text(n.state).font(.caption.monospaced())
                                .foregroundStyle(n.state == "Unspent" ? .primary : .secondary)
                            Spacer()
                            Text("\(n.amount)").font(.body.monospacedDigit())
                        }
                    }
                }
            }
            .navigationTitle("Ultraviolet")
            .toolbar {
                Button {
                    model.scan()
                } label: {
                    Label("Scan", systemImage: "tray.and.arrow.down")
                }
                .disabled(model.busy)
            }
            .refreshable { model.refresh() }
            .overlay { if model.busy { ProgressView() } }
        }
    }
}

struct ReceiveView: View {
    @EnvironmentObject var model: Model
    @State private var peer = ""
    @State private var count = 8.0

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Stepper("\(Int(count)) slots", value: $count, in: 1...64, step: 1)
                    TextField("who is this for (a label)", text: $peer)
                        .textInputAutocapitalization(.never)
                    Button("Create address") {
                        model.makeAddress(count: UInt64(count), peer: peer)
                    }
                    .disabled(model.busy)
                } footer: {
                    Text("Hand this to ONE person. Each slot pays once; giving the same "
                         + "batch to two payers means both start at slot 0 and the second "
                         + "payment has nowhere to sit. The label is only a reminder of who "
                         + "got it — nothing authenticates it.")
                }
                if let a = model.address {
                    Section("Address") {
                        ShareLink(item: a) { Label("Share", systemImage: "square.and.arrow.up") }
                        Text(a).font(.caption2.monospaced()).textSelection(.enabled)
                    }
                }
            }
            .navigationTitle("Receive")
        }
    }
}

struct StatusView: View {
    @EnvironmentObject var model: Model

    var body: some View {
        NavigationStack {
            List {
                if let s = model.status, !s.isBitcoin {
                    Section {
                        Label {
                            Text("Not connected to Bitcoin — reading \(s.backend). Nothing "
                                 + "here is a claim about signet or mainnet until this says "
                                 + "otherwise.")
                                .font(.footnote)
                        } icon: {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundStyle(.orange)
                        }
                    }
                }
                if let s = model.status {
                    Section("This wallet") {
                        row("id", s.addressID)
                        row("asset", s.anchor)
                    }
                    Section("Chain view") {
                        row("reading", s.backend)
                        row("tip", s.tip)
                        // A floor above zero means the view cannot answer for
                        // anything below it — which is why acceptance refuses
                        // rather than assuming.
                        row("sees from", s.scanFloor == 0 ? "the whole chain" : "height \(s.scanFloor)")
                    }
                    Section("Notes") {
                        row("unspent", "\(s.unspent)")
                        row("in flight", "\(s.inFlight)")
                        row("spent", "\(s.spent)")
                        row("quarantined", "\(s.quarantined)")
                    }
                    if s.stuck > 0 {
                        Section("Set aside") {
                            Text("\(s.stuck) payment(s) arrived with no free slot to sit in. "
                                 + "They are real and settled — send that payer a fresh "
                                 + "address and ask them to re-mail.")
                                .font(.footnote)
                        }
                    }
                } else {
                    Text("loading…").foregroundStyle(.secondary)
                }
            }
                Section {
                    Button {
                        model.runDiagnostics()
                    } label: {
                        Label(
                            model.busy ? "running…" : "Run diagnostics",
                            systemImage: "checkmark.seal"
                        )
                    }
                    .disabled(model.busy)
                    if let d = model.diagnostics {
                        Text(d).font(.caption2.monospaced()).textSelection(.enabled)
                    }
                } header: {
                    Text("Diagnostics")
                } footer: {
                    Text("Proves this build works on this device: a real issuance, a real "
                         + "address, a refusal arriving as an error rather than a crash, and "
                         + "what a payment costs to prove on this phone. Writes a transcript "
                         + "next to the wallet.")
                }
            .navigationTitle("Status")
            .refreshable { model.refreshStatus() }
        }
    }

    private func row(_ k: String, _ v: String) -> some View {
        HStack {
            Text(k).foregroundStyle(.secondary)
            Spacer()
            Text(v).font(.callout.monospaced()).multilineTextAlignment(.trailing)
        }
    }
}

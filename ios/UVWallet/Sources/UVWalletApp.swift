import SwiftUI

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

enum UVSelfTest {
    static func run() {
        NSLog("UVSELFTEST home=%@", UV.home.path)
        do {
            let before = try UV.callObject(["cmd": "balance", "wallet": "selftest"])
            NSLog("UVSELFTEST balance-before=%@", "\(before["spendable"] ?? "?")")

            let issued = try UV.callObject(["cmd": "issue", "wallet": "selftest", "amount": 700])
            NSLog("UVSELFTEST issued=%@ asset=%@",
                  "\(issued["amount"] ?? "?")",
                  String("\(issued["asset_hex"] ?? "?")".prefix(16)))

            let after = try UV.callObject(["cmd": "balance", "wallet": "selftest"])
            NSLog("UVSELFTEST balance-after=%@", "\(after["spendable"] ?? "?")")

            let addr = try UV.callObject(["cmd": "address", "wallet": "selftest", "count": 3])
            let slots = (addr["slots"] as? [[String: Any]])?.count ?? 0
            NSLog("UVSELFTEST address-slots=%d", slots)

            // The failure path matters as much: a refusal must arrive as a
            // typed error, not a crash.
            do {
                _ = try UV.callObject(["cmd": "nope"])
                NSLog("UVSELFTEST FAIL: unknown command did not refuse")
            } catch let e as UVError {
                NSLog("UVSELFTEST refusal-kind=%@", e.kind)
            }

            let ok = "\(after["spendable"] ?? "0")" == "700" && slots == 3
            NSLog("UVSELFTEST %@", ok ? "PASS" : "FAIL")
        } catch {
            NSLog("UVSELFTEST FAIL: %@", "\(error)")
        }
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
                Section {
                    Label {
                        Text("Not connected to Bitcoin. This build reads a local chain "
                             + "file; the network view lands with mirror sync, so nothing "
                             + "here is a claim about signet or mainnet.")
                            .font(.footnote)
                    } icon: {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                    }
                }
                if let s = model.status {
                    Section("This wallet") {
                        row("id", s.addressID)
                        row("asset", s.anchor)
                    }
                    Section("Chain view") {
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

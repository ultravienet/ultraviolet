import Foundation

/// The one door into the wallet: `uv_call(json) -> json`, over the Rust
/// command layer (`uv-app`).
///
/// **Nothing about the protocol is reimplemented on this side.** Every rule
/// that decides whether money moves — refuse before reserving a slot, persist
/// before publishing, keep a bundle on a transient verdict, re-check the
/// genesis after a reorg — lives in Rust and is shared with the `uv` CLI. A
/// Swift function that made one of those decisions would be a second
/// implementation of a rule this project has already paid to learn once.
///
/// So this file is deliberately thin: encode a request, call, decode a
/// response, surface the error. If a view ever needs logic that is not
/// presentation, the logic belongs in `uv-app`.
@_silgen_name("uv_call")
private func uv_call(_ req: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?

@_silgen_name("uv_free")
private func uv_free(_ p: UnsafeMutablePointer<CChar>?)

/// A refusal from the command layer, carrying the stable tag callers branch on.
struct UVError: Error, LocalizedError {
    /// The closed set from `uv_app::Error::kind()`, plus `bad_request` and
    /// `panic` which exist only at the FFI boundary.
    let kind: String
    let message: String
    /// Whether trying again later could plausibly succeed with nothing else
    /// changing. A phone has to choose between a retry button and an error
    /// state without a human in the loop, which is why this crosses the wire.
    let transient: Bool

    var errorDescription: String? { message }
}

enum UV {
    /// The wallet's home directory: the app's own container, with the strongest
    /// file protection iOS offers and excluded from iCloud backup.
    ///
    /// Both matter for the same reason. The seed derives every note key, so a
    /// wallet file that syncs to a backup is a wallet in someone else's
    /// custody, and one readable while the device is locked is a wallet
    /// readable by anything that can reach the filesystem. `completeUntilFirstUserAuthentication`
    /// rather than `complete`: the app must be able to finish a scan it started
    /// before the screen locked, and a payment that fails because a pocket
    /// locked the phone is a payment a person retries — which is the one thing
    /// a one-time-slot wallet should never make routine.
    static let home: URL = {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        var dir = base.appendingPathComponent("uv", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [
            .protectionKey: FileProtectionType.completeUntilFirstUserAuthentication
        ])
        var resource = URLResourceValues()
        resource.isExcludedFromBackup = true
        try? dir.setResourceValues(resource)
        return dir
    }()

    /// Call the command layer. Runs the request on the calling thread; views
    /// dispatch it off the main one (see `Model.run`).
    static func call(_ request: [String: Any]) throws -> [String: Any] {
        var req = request
        req["home"] = home.path

        let body = try JSONSerialization.data(withJSONObject: req)
        guard let json = String(data: body, encoding: .utf8) else {
            throw UVError(kind: "bad_request", message: "request is not UTF-8", transient: false)
        }

        guard let raw = json.withCString({ uv_call($0) }) else {
            // The Rust side never returns null; this is belt-and-braces so a
            // future change cannot turn into a crash on the phone.
            throw UVError(kind: "panic", message: "no response from the wallet core", transient: false)
        }
        let text = String(cString: raw)
        uv_free(raw)

        guard let data = text.data(using: .utf8),
              let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw UVError(kind: "panic", message: "unreadable response: \(text)", transient: false)
        }
        if let err = obj["err"] as? [String: Any] {
            throw UVError(
                kind: err["kind"] as? String ?? "panic",
                message: err["message"] as? String ?? "unknown failure",
                transient: err["transient"] as? Bool ?? false
            )
        }
        guard let ok = obj["ok"] else {
            throw UVError(kind: "panic", message: "response had neither ok nor err", transient: false)
        }
        return ["ok": ok]
    }

    /// Convenience for commands whose result is a dictionary.
    static func callObject(_ request: [String: Any]) throws -> [String: Any] {
        let r = try call(request)
        return r["ok"] as? [String: Any] ?? [:]
    }
}

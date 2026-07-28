import Foundation
import UIKit

@_silgen_name("uv_measure")
func uv_measure(_ runs: UInt32, _ mode: UInt32) -> UnsafeMutablePointer<CChar>?
@_silgen_name("uv_free")
func uv_free(_ p: UnsafeMutablePointer<CChar>?)

final class AppDelegate: NSObject, UIApplicationDelegate {
    func application(_ app: UIApplication,
                     didFinishLaunchingWithOptions o: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        // Which circuit to run comes from the environment, so each launch is one
        // process and the peak-memory figure belongs to one circuit only.
        let mode = UInt32(ProcessInfo.processInfo.environment["UV_MODE"] ?? "0") ?? 0
        DispatchQueue.global(qos: .userInitiated).async {
            NSLog("UVPROBE-START mode=\(mode) ios=\(UIDevice.current.systemVersion)")
            if let p = uv_measure(3, mode) {
                let s = String(cString: p)
                uv_free(p)
                for line in s.split(separator: "\n") { NSLog("UVPROBE %@", String(line)) }
            } else {
                NSLog("UVPROBE-ERROR null result")
            }
            NSLog("UVPROBE-DONE")
        }
        return true
    }
}
UIApplicationMain(CommandLine.argc, CommandLine.unsafeArgv, nil,
                  NSStringFromClass(AppDelegate.self))

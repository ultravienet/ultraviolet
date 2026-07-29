# UVProbe — the prover, on an actual iPhone

A deliberately minimal app: it links the Rust static library, proves one payment hop
three times, and writes the timings to the system log. There is no user interface,
because the thing being measured is not a user interface.

It exists because a simulator cannot answer the question. The simulator runs arm64
natively on the development Mac, so a "simulator" timing is a Mac timing. Only a phone
can tell you what a phone does.

## Build and run

```sh
export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
cargo build --release -p uv-iosffi --target aarch64-apple-ios
cp target/aarch64-apple-ios/release/libuv_iosffi.a ios/

cd ios
xcodebuild -project UVProbe.xcodeproj -scheme UVProbe -configuration Release \
  -destination "id=$DEVICE_UDID" \
  -allowProvisioningUpdates -allowProvisioningDeviceRegistration \
  DEVELOPMENT_TEAM=$YOUR_TEAM build

xcrun devicectl device install app --device "$DEVICE_UDID" \
  ~/Library/Developer/Xcode/DerivedData/UVProbe-*/Build/Products/Release-iphoneos/UVProbe.app

xcrun devicectl device process launch --device "$DEVICE_UDID" --console \
  --terminate-existing --environment-variables '{"UV_MODE":"2"}' net.ultravie.uvprobe
```

`UV_MODE` picks the configuration: `1` standard, `2` hiding, anything else both.
**Run one configuration per launch when you care about memory.** Peak RSS is a process
high-water mark, so running both reports their union, which is neither one's cost.

**Measure on more than one phone if you are going to publish a number.** The figures in
`demo/ios.md` come from an iPhone 17 Pro Max and an iPhone 16e, deliberately far apart in
price, because "the fastest phone can do it" is a much weaker claim than "a phone can do it".
The app reports its own baseline separately from the prover's share for the same reason: on
the 16e those two differ by 24 MB, and quoting only the peak invents a hardware gap that does
not exist.

## Two traps that cost us numbers

- **`-allowProvisioningUpdates` is not enough for a new phone.** It lets Xcode mint a
  profile but not enrol hardware, and the install fails later with
  `0xe8008012 This provisioning profile cannot be installed on this device`. You also
  need `-allowProvisioningDeviceRegistration`.
- **`xcode-select -p` reports the *active* toolchain, not what is installed.** Seeing
  `CommandLineTools` does not mean Xcode is absent. Set `DEVELOPER_DIR` rather than
  running `sudo xcode-select -s`.

---

# UVWallet — the wallet app

`UVProbe` above measures; **`UVWallet` is the wallet**. It is a SwiftUI shell
over `uv_call(json) -> json` (`iosffi/src/call.rs`), which is a door onto the
same Rust command layer the `uv` CLI uses. Nothing about the protocol is
implemented in Swift: every rule that decides whether money moves lives in
`uv-app` and is shared, because a second implementation of one of those rules
is a second chance to get it wrong.

```sh
./ios/build-wallet.sh sim          # simulator — no Apple account needed
./ios/build-wallet.sh device       # a real iPhone; set DEVELOPMENT_TEAM
```

The script builds the Rust static library for the destination, generates the
Xcode project from `UVWallet/project.yml` with `xcodegen`, and builds. Both the
library and the generated `.xcodeproj` are build outputs and are git-ignored —
the reviewable artifacts are the Swift sources and the generator spec.

## The self-test, which is the point of a device run

A screenshot cannot tell you the FFI works. Launching with `UV_SELFTEST=1`
runs a real sequence through the door and logs the result:

```sh
xcrun simctl install <sim-udid> ~/Library/Developer/Xcode/DerivedData/UVWallet-*/Build/Products/Release-iphonesimulator/UVWallet.app
SIMCTL_CHILD_UV_SELFTEST=1 xcrun simctl launch <sim-udid> net.ultravie.uvwallet
xcrun simctl spawn <sim-udid> log stream --predicate 'eventMessage CONTAINS "UVSELFTEST"'
```

Recorded 2026-07-29, iPhone 17 Pro simulator (arm64), Release:

```
UVSELFTEST balance-before=0
UVSELFTEST issued=700 asset=d7771404ef2fef4f
UVSELFTEST balance-after=700
UVSELFTEST address-slots=3
UVSELFTEST refusal-kind=bad_request
UVSELFTEST PASS
```

That is a real issuance with a real proof, a real wallet file in the app's own
container, a real address of one-time slots, and a refusal arriving as a typed
error rather than a crash. **On a device the same command reports the same
lines** — and the simulator's arm64 timings are a Mac's, which is why speed
claims wait for hardware (`demo/ios.md`).

## What this build is not

The chain is a **local file** (`FileChain` in `call.rs`), not Bitcoin. Balance,
status, supply, issue, receive and scan are real against it; sending over a
network and reading a real chain need the mirror-sync view, which is the next
piece. The Status tab says so in the app rather than only here, because a
wallet that lets someone believe they are on signet is worse than one that
admits it is not.

## Storage

The wallet lives in the app's Application Support container with
`completeUntilFirstUserAuthentication` protection and excluded from iCloud
backup. Both for the same reason: the seed derives every note key, so a wallet
that syncs to a backup is a wallet in someone else's custody.

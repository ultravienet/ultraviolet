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

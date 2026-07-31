#!/usr/bin/env bash
# Build the SwiftUI wallet: Rust static library first, then the app.
#
# The Rust half is the whole protocol (`uv-app` behind `uv_call`); the Swift
# half is presentation. This script builds the library for the destination
# being targeted and drops it where the generated project looks for it.
#
#   ./ios/build-wallet.sh sim      # simulator (no Apple account needed)
#   ./ios/build-wallet.sh device   # a real iPhone (needs DEVELOPMENT_TEAM)
set -euo pipefail
cd "$(dirname "$0")/.."
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"

WHAT="${1:-sim}"
case "$WHAT" in
  sim)    TARGET=aarch64-apple-ios-sim; PLATFORM=iphonesimulator
          DEST="platform=iOS Simulator,name=iPhone 17 Pro" ;;
  device) TARGET=aarch64-apple-ios;     PLATFORM=iphoneos
          DEST="generic/platform=iOS" ;;
  *) echo "usage: $0 [sim|device]" >&2; exit 1 ;;
esac

echo "== rust: $TARGET"
cargo build --release -p uv-iosffi --target "$TARGET"
mkdir -p "ios/UVWallet/lib/$PLATFORM"
cp "target/$TARGET/release/libuv_iosffi.a" "ios/UVWallet/lib/$PLATFORM/"

echo "== project: xcodegen"
( cd ios/UVWallet && xcodegen generate --quiet )

echo "== app: $PLATFORM"
xcodebuild -project ios/UVWallet/UVWallet.xcodeproj -scheme UVWallet \
  -configuration Release -destination "$DEST" \
  ${DEVELOPMENT_TEAM:+DEVELOPMENT_TEAM="$DEVELOPMENT_TEAM"} \
  ${DEVELOPMENT_TEAM:+-allowProvisioningUpdates} \
  CODE_SIGNING_ALLOWED="${CODE_SIGNING_ALLOWED:-NO}" \
  build "${@:2}"

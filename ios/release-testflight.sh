#!/usr/bin/env bash
# Archive UVWallet and hand it to TestFlight.
#
#   ./ios/release-testflight.sh archive   # build a signed .xcarchive
#   ./ios/release-testflight.sh export    # archive -> .ipa for App Store Connect
#   ./ios/release-testflight.sh upload    # export -> upload (needs the API key)
#   ./ios/release-testflight.sh all       # all three
#
# **What this script will not do, on purpose.** It does not create certificates,
# accept agreements, answer the export-compliance question, or add testers. Those
# are Apple *account* actions and they belong to a human who can see what they are
# agreeing to. This script does the packaging, which is the part that should be
# repeatable.
#
# ## What you need before `upload` works
#
# - **An Apple Distribution certificate.** Development certificates cannot sign a
#   TestFlight build, and as of 2026-07-30 this machine has only Development ones
#   (`security find-identity -v -p codesigning`). `-allowProvisioningUpdates`
#   below will create one via the API key if the key has the rights; otherwise
#   make it in Xcode → Settings → Accounts → Manage Certificates → +.
# - **The App Store Connect API key**, already present here as
#   `~/.appstoreconnect/private_keys/AuthKey_<KEYID>.p8`.
# - **`UV_ASC_KEY_ID` and `UV_ASC_ISSUER_ID`.** The key id is the `<KEYID>` in
#   that filename. The issuer id is a UUID shown once per team at
#   App Store Connect → Users and Access → Integrations → App Store Connect API,
#   above the key list. It is not derivable from the key file.
#
# ## Build numbers are consumed forever
#
# App Store Connect permanently reserves a build number: a build cannot be deleted
# and its number reused. `CURRENT_PROJECT_VERSION` in `project.yml` is therefore
# bumped by hand, deliberately. This script refuses to upload a build number that
# it has already recorded as uploaded, because the failure mode — a rejected
# upload after a ten-minute archive — is tedious and entirely avoidable.
set -euo pipefail
cd "$(dirname "$0")/.."
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"

TEAM_ID="${DEVELOPMENT_TEAM:-2858MX5336}"
BUNDLE_ID="net.ultravie.uvwallet"
OUT="target/ios-release"
ARCHIVE="$OUT/UVWallet.xcarchive"
EXPORT_DIR="$OUT/export"
UPLOADED="$OUT/uploaded-build-numbers.txt"

step="${1:-all}"

version_of() {
  # Read from the generator spec, which is the reviewable source, not from the
  # generated pbxproj.
  awk -F'"' "/$1:/ {print \$2; exit}" ios/UVWallet/project.yml
}

do_archive() {
  echo "== rust: aarch64-apple-ios"
  cargo build --release -p uv-iosffi --target aarch64-apple-ios
  mkdir -p ios/UVWallet/lib/iphoneos
  cp target/aarch64-apple-ios/release/libuv_iosffi.a ios/UVWallet/lib/iphoneos/

  echo "== project: xcodegen"
  ( cd ios/UVWallet && xcodegen generate --quiet )

  echo "== archive (team $TEAM_ID)"
  mkdir -p "$OUT"
  rm -rf "$ARCHIVE"
  xcodebuild -project ios/UVWallet/UVWallet.xcodeproj -scheme UVWallet \
    -configuration Release -destination "generic/platform=iOS" \
    -archivePath "$ARCHIVE" \
    DEVELOPMENT_TEAM="$TEAM_ID" \
    -allowProvisioningUpdates \
    archive
  echo "archive: $ARCHIVE"
}

do_export() {
  [ -d "$ARCHIVE" ] || { echo "no archive at $ARCHIVE — run 'archive' first" >&2; exit 1; }
  # Written here rather than committed: it carries the team id and the method,
  # both of which are already in this script, and a stray plist is one more thing
  # to drift.
  local plist="$OUT/ExportOptions.plist"
  cat > "$plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>method</key><string>app-store-connect</string>
  <key>teamID</key><string>$TEAM_ID</string>
  <key>destination</key><string>export</string>
  <key>uploadSymbols</key><true/>
  <!-- No bitcode: Apple removed it, and asking for it is an error on modern Xcode. -->
  <key>manageAppVersionAndBuildNumber</key><false/>
</dict>
</plist>
PLIST
  echo "== export"
  rm -rf "$EXPORT_DIR"
  xcodebuild -exportArchive -archivePath "$ARCHIVE" \
    -exportOptionsPlist "$plist" -exportPath "$EXPORT_DIR" \
    -allowProvisioningUpdates
  echo "ipa: $(find "$EXPORT_DIR" -name '*.ipa' | head -1)"
}

do_upload() {
  local ipa
  ipa="$(find "$EXPORT_DIR" -name '*.ipa' 2>/dev/null | head -1)"
  [ -n "$ipa" ] || { echo "no .ipa in $EXPORT_DIR — run 'export' first" >&2; exit 1; }

  : "${UV_ASC_KEY_ID:?set UV_ASC_KEY_ID (the <KEYID> in AuthKey_<KEYID>.p8)}"
  : "${UV_ASC_ISSUER_ID:?set UV_ASC_ISSUER_ID (App Store Connect > Users and Access > Integrations)}"

  local build; build="$(version_of CURRENT_PROJECT_VERSION)"
  local marketing; marketing="$(version_of MARKETING_VERSION)"
  local tag="$marketing ($build)"

  if [ -f "$UPLOADED" ] && grep -qxF "$tag" "$UPLOADED"; then
    echo "REFUSING: build $tag is already recorded as uploaded." >&2
    echo "  App Store Connect consumes a build number permanently — it cannot be" >&2
    echo "  deleted and reused. Bump CURRENT_PROJECT_VERSION in" >&2
    echo "  ios/UVWallet/project.yml and archive again." >&2
    exit 1
  fi

  # Preflight the one failure Apple reports cryptically. If the app declares
  # non-exempt encryption and App Store Connect holds documentation for it, the
  # Info.plist must carry the matching code — and `altool` reports the mismatch as
  # "key value []" rather than "you are missing a key".
  local plist_in_ipa="$EXPORT_DIR/.check/Payload/UVWallet.app/Info.plist"
  rm -rf "$EXPORT_DIR/.check"; mkdir -p "$EXPORT_DIR/.check"
  ( cd "$EXPORT_DIR/.check" && unzip -q "../$(basename "$ipa")" ) || true
  if [ -f "$plist_in_ipa" ]; then
    local uses code
    uses="$(/usr/libexec/PlistBuddy -c 'Print :ITSAppUsesNonExemptEncryption' "$plist_in_ipa" 2>/dev/null || echo false)"
    code="$(/usr/libexec/PlistBuddy -c 'Print :ITSEncryptionExportComplianceCode' "$plist_in_ipa" 2>/dev/null || echo '')"
    if [ "$uses" = "true" ] && [ -z "$code" ]; then
      echo "WILL FAIL: the app declares non-exempt encryption and carries no" >&2
      echo "  ITSEncryptionExportComplianceCode, so validation returns error 90592:" >&2
      echo "    \"the export compliance key value [] ... doesn't match the key value" >&2
      echo "     of the app's export compliance documentation\"" >&2
      echo "  That wording implies documentation exists. It need not — the message is" >&2
      echo "  the same when there is none, and [] means the key is ABSENT." >&2
      echo "  Either create the declaration in App Store Connect and set the code it" >&2
      echo "  issues, or drop the YES key and answer the questions in App Store" >&2
      echo "  Connect's UI. See ios/README.md \"Export compliance\"." >&2
    fi
  fi
  rm -rf "$EXPORT_DIR/.check"

  echo "== validate $tag"
  xcrun altool --validate-app -f "$ipa" -t ios \
    --apiKey "$UV_ASC_KEY_ID" --apiIssuer "$UV_ASC_ISSUER_ID"

  echo "== upload $tag"
  xcrun altool --upload-app -f "$ipa" -t ios \
    --apiKey "$UV_ASC_KEY_ID" --apiIssuer "$UV_ASC_ISSUER_ID"

  echo "$tag" >> "$UPLOADED"
  cat <<'NEXT'

Uploaded. What happens now, and none of it is this script's job:

  1. App Store Connect processes the build. Minutes, sometimes an hour.
  2. **Export compliance.** The Info.plist deliberately OMITS
     ITSAppUsesNonExemptEncryption, so the build lands as "Missing Compliance"
     and App Store Connect asks the encryption questions in its own UI. Answer
     them there. Absent is not `false`; see project.yml.
  3. Assign the build to the internal TestFlight group.

Internal testers need no Apple review and no listing metadata — no description,
keywords or screenshots. External testers need Beta App Review.
NEXT
}

case "$step" in
  archive) do_archive ;;
  export)  do_export ;;
  upload)  do_upload ;;
  all)     do_archive; do_export; do_upload ;;
  *) echo "usage: $0 [archive|export|upload|all]" >&2; exit 1 ;;
esac

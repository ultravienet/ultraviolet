# UVWallet — Ultraviolet on an iPhone

A SwiftUI shell over `uv_call(json) -> json` (`iosffi/src/call.rs`), which is a door onto the
same Rust command layer the `uv` CLI uses. **Nothing about the protocol is implemented in
Swift**: every rule that decides whether money moves lives in `uv-app` and is shared, because a
second implementation of one of those rules is a second chance to get it wrong.

```sh
export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
./ios/build-wallet.sh sim          # simulator — no Apple account needed
./ios/build-wallet.sh device       # a real iPhone; set DEVELOPMENT_TEAM
```

The script builds the Rust static library for the destination, generates the Xcode project from
`UVWallet/project.yml` with `xcodegen`, and builds. Both the library and the generated
`.xcodeproj` are build outputs and are git-ignored — the reviewable artifacts are the Swift
sources and the generator spec.

> "How fast does a phone prove?" is answered by the self-test below and by
> `air/src/bin/measure`, which measure on the phone as part of proving the phone works — not by a
> separate benchmark app, which is how you end up publishing numbers for a build nobody ships.

## The self-test, which is the point of a device run

A screenshot cannot tell you the FFI works. Launching with `UV_SELFTEST=1` runs a real sequence
through the door — a real issuance with a real proof, a real wallet file in the app's own
container, a real address of one-time slots, a refusal arriving as a typed error rather than a
crash — then measures the prover, and writes everything to `selftest.log` in the app container
as well as to the system log.

```sh
xcrun simctl install <sim-udid> ~/Library/Developer/Xcode/DerivedData/UVWallet-*/Build/Products/Release-iphonesimulator/UVWallet.app
SIMCTL_CHILD_UV_SELFTEST=1 xcrun simctl launch <sim-udid> net.ultravie.uvwallet
# then read the transcript out of the container, which does not race the log stream:
cat "$(xcrun simctl get_app_container <sim-udid> net.ultravie.uvwallet data)/Library/Application Support/uv/selftest.log"
```

On a device, `UV_SELFTEST=1` goes through `--environment-variables` on
`devicectl device process launch`, and the transcript comes back with
`devicectl device copy from --domain-type appDataContainer`. **Prefer the file to the console
either way**: a console stream needs the phone unlocked at exactly the right moment, and a file
can be pulled whenever, which is the difference between a repeatable device run and a race.

### The correctness path — simulator, 2026-07-30, iPhone 17 Pro sim, Release

```
balance-before=0
issued=700 asset=309c8a769b8a9350
balance-after=700
address-slots=3
refusal-kind=bad_request
balance-delta=700 (expected 700)
PASS
```

### The prover on real hardware — iPhone 16e (A18), iOS 26.2.1

```
measure-standard threads 6
measure-standard run 1: standard 0.008s verify 0.89ms ok=true size 81.5 KB
measure-standard run 2: standard 0.007s verify 1.08ms ok=true size 81.5 KB
measure-standard run 3: standard 0.008s verify 1.05ms ok=true size 81.5 KB
measure-standard RSS before proving 87 MB, peak 89 MB, prover share 2 MB
measure-hiding  threads 6
measure-hiding  run 1: hiding 0.007s verify 1.25ms ok=true size 117.2 KB
measure-hiding  run 2: hiding 0.006s verify 1.33ms ok=true size 117.2 KB
measure-hiding  run 3: hiding 0.012s verify 1.35ms ok=true size 117.2 KB
measure-hiding  RSS before proving 89 MB, peak 90 MB, prover share 1 MB
```

**Two honesty notes about the pairing above, because it is two runs and not one.**

The device run happened before the self-test's correctness assertion was fixed, and **it printed
`FAIL`**. Not because anything was broken: the assertion was `balance == 700`, which passes once
on a fresh wallet and then fails forever on a phone somebody has actually used (that run started
from `balance-before=2800`). It is now `b1 == b0 + 700`. The device's *timings* are unaffected —
they are measured after the correctness lines and do not depend on the assertion — so they stand
as the published A18 figures. A post-fix device run showing `PASS` has **not** been recorded; it
needs the phone in hand, and until then the honest statement is that the correctness path is
green on the simulator and the timing path is green on hardware.

**Do not quote the simulator's timings for a phone.** The simulator runs arm64 natively on the
development Mac, so a simulator timing is a Mac timing — and the run above was taken while the
formal suite was saturating every core, which made its hiding figures (0.026–0.055 s) *four to
eight times slower* than the A18's. That inversion is a useful accident: it shows the number a
simulator gives you is a fact about your desk, not about the phone.

## TestFlight

`./ios/release-testflight.sh [archive|export|upload|all]` does the packaging.
**It deliberately does no Apple account actions** — no certificates, no
agreements, no compliance answers, no testers. Those need a human who can see
what they are agreeing to.

### Already done (2026-07-28)

| | |
|---|---|
| Team ID | `2858MX5336` |
| Bundle ID | `net.ultravie.uvwallet` (explicit App ID registered) |
| App Store Connect record | created; app id `92396522` |
| TestFlight internal group | exists — "no builds available" until an archive lands, which is correct |
| Paid Apps agreement | **not needed.** Free app, no in-app purchases, so no banking or tax setup |
| App Store Connect API key | `~/.appstoreconnect/private_keys/AuthKey_<KEYID>.p8` |

### The certificate, and the trap it hid

**Resolved 2026-07-30.** `Apple Distribution: ttt246 llc (2858MX5336)` now signs
this app.

Worth recording because the first diagnosis was wrong in an instructive way. A
distribution certificate *and* a Store provisioning profile for
`net.ultravie.uvwallet` already existed in the account — so "the certificate is
missing" was false. What was missing was the **private key**: the certificate had
been created on another machine, and a certificate without its key signs nothing.
`security find-identity` shows only identities whose key is in the keychain,
which is why it looked like an absence rather than a mismatch.

The check that tells them apart, worth keeping:

```sh
# extract the cert the profile names, then ask the keychain for its key
security cms -D -i ~/Library/Developer/Xcode/UserData/Provisioning\ Profiles/<uuid>.mobileprovision \
  | plutil -extract DeveloperCertificates.0 raw -o - - | base64 -d > /tmp/c.cer
openssl x509 -inform DER -in /tmp/c.cer -noout -subject -fingerprint -sha1
security find-identity -v -p codesigning | grep <that fingerprint>
```

**One caution for next time.** This team is `ttt246 llc` and it also carries
`com.ttt246llc.wtm` profiles — WebTimeMachine. Apple caps Apple Distribution
certificates per team, so creating one can require revoking one, and revoking the
certificate WTM ships with breaks WTM's releases. Check the cap before creating,
not after.

### Two values the script needs and cannot derive

- `UV_ASC_KEY_ID` — the `<KEYID>` in the `AuthKey_<KEYID>.p8` filename.
- `UV_ASC_ISSUER_ID` — a per-team UUID at App Store Connect → **Users and
  Access → Integrations → App Store Connect API**, shown above the key list. It
  is not in the key file and not derivable from it.

### Export compliance

`ITSAppUsesNonExemptEncryption` is **YES**, and `UVWallet/project.yml` carries the
reasoning at length: the app bundles its own ChaCha20-Poly1305 and a hybrid
ML-KEM-768 + X25519 exchange to seal payment bundles, which is data
confidentiality in code we ship, so none of the exempt categories apply.
Declaring NO would be a false statement about a shipped app.

**Correction, 2026-07-30.** An earlier version of this section said documentation
was already on file, inferred from the wording of the error below. **That was
wrong.** Queried directly —
`GET /v1/appEncryptionDeclarations?filter[app]=6795737764` — the app has **no
encryption declaration at all**. Apple emits this error whenever
`ITSAppUsesNonExemptEncryption` is `true` and no matching code is present,
regardless of whether any documentation exists, and its phrase "the app's export
compliance documentation" reads as though some exists. It does not. Recorded
because the misreading cost a wrong instruction ("go find the code" — there is no
code) and the error text will mislead the same way next time.

`altool --validate-app` refuses the build:

```
Invalid Export Compliance Code. The export compliance key value [] in the app's
Info.plist doesn't match the key value of the app's export compliance
documentation. (90592)
```

`[]` is the empty value it found, which reads as "your code is wrong" and means
"you have no code".

**Two ways forward, and they differ in more than convenience.**

1. **Omit `ITSAppUsesNonExemptEncryption` from the Info.plist.** The upload then
   succeeds, App Store Connect marks the build **Missing Compliance**, and it asks
   the encryption questions in its own UI — with Apple's own wording and
   explanations, which is a better place to answer a regulatory question than a
   plist key. The answers there can be truthful. This is the path that unblocks a
   build today.
2. **Create the encryption declaration first**, in App Store Connect, and put the
   code it issues into `INFOPLIST_KEY_ITSEncryptionExportComplianceCode` — the
   line is present and commented in `UVWallet/project.yml`. Later builds then skip
   the questions entirely.

**What is not an option: declaring `false`.** The crypto is demonstrably in the
shipped binary — the linked library carries 136 ML-KEM symbols, 58 ChaCha20, 45
Poly1305, 20 X25519 and 76 Argon2, and `uv_envelope::seal` is on the send path
(`app/src/commands.rs`). `false` would be a false statement about a shipped app.

Whichever path, the underlying declaration for a product like this is normally a
**self-classification report to BIS** (EAR 740.17(b)(1) mass-market provisions)
rather than a CCATS — but *that is a legal question this repository cannot
settle*, and it is the step worth asking someone qualified about rather than
guessing.

### Build numbers are consumed permanently

App Store Connect reserves a build number forever — a build cannot be deleted and
its number reused. `CURRENT_PROJECT_VERSION` is bumped by hand in `project.yml`,
never automatically, and the script refuses to upload a number it has already
recorded rather than letting you find out after a ten-minute archive.

### Verified 2026-07-30

`archive` and `export` both run clean, and the `.ipa` was checked rather than
assumed:

| | |
|---|---|
| signing authority | `Apple Distribution: ttt246 llc (2858MX5336)` |
| embedded profile | `iOS Team Store Provisioning Profile: net.ultravie.uvwallet` |
| `get-task-allow` | **false** — a development-signed build has `true` here and is rejected |
| `codesign --verify --deep --strict` | passes |
| bundle / version | `net.ultravie.uvwallet`, `0.1 (1)` |
| encryption declaration | `ITSAppUsesNonExemptEncryption = true` |
| size / arch | 1.5 MB, arm64, iOS 17.0 minimum, iPhone-only |

Note the archive is signed with a *Development* identity and the export re-signs
it for distribution. That is the normal automatic-signing flow and not a
misconfiguration — what matters is the authority on the exported `.ipa`, which is
why it is checked above rather than the archive's.

**Uploaded 2026-07-30**: build `0.1 (1)`, delivery UUID
`45b441b8-74da-4e47-bc14-f9224eb8cf72`, 1.5 MB, `VERIFY SUCCEEDED` then
`UPLOAD SUCCEEDED`. Build number `1` is now permanently consumed; the next build
needs `CURRENT_PROJECT_VERSION: "2"`.

The first attempt was refused at validation (error 90592) and consumed nothing,
because `--validate-app` runs first and does not reserve a number. That ordering
is the reason the script has it.

**State after upload**, read back from the API rather than assumed:

| | |
|---|---|
| processing | `VALID` |
| build | `1`, expires 2026-10-28 |
| minimum OS | 17.0 |
| `usesNonExemptEncryption` | **`null`** — the "Missing Compliance" state |
| internal group | `test` (`e6fc95a2-2b97-4417-9730-4a4dab401ec3`) |

`null` is the point. Because the Info.plist omits the declaration, App Store
Connect asks in its own UI: **TestFlight → the build → Manage** beside *Missing
Compliance*. Answering it is a regulatory statement about a shipped binary and is
deliberately not automated here — the API can `PATCH` that field, and this
repository does not.

The honest answer is **yes, it uses non-exempt encryption** (the evidence is above:
136 ML-KEM symbols, 58 ChaCha20, 45 Poly1305, 20 X25519, 76 Argon2 in the linked
library, and `uv_envelope::seal` on the send path). Expect Apple to then ask
whether it qualifies for an exemption — it does not — and to want a
self-classification report on file.

## What this build is and is not

**It reads Bitcoin.** With `UV_MIRROR` set to a mirror's address the app reads **public signet**
through bulk content-addressed pages and answers its own nullifier lookups from a locally
replayed index, so no nullifier ever crosses the wire (`btc/src/mirror.rs`,
`btc/src/bin/uv-mirror.rs`). Without it, the chain is a local file
(`FileChain` in `call.rs`) and the Status tab says so, in an orange banner driven by the
backend's own `is_bitcoin` rather than by a hardcoded string — because a wallet that lets
somebody believe they are on signet is worse than one that admits it is not.

Balance, status, supply, issue, receive and scan are real either way. Sending to a counterparty
still goes through the bundle/transport layer rather than a chat app; that is what the Signal
fork is for.

## Storage

The wallet lives in the app's Application Support container with
`completeUntilFirstUserAuthentication` protection and excluded from iCloud backup. Both for the
same reason: the seed derives every note key, so a wallet that syncs to a backup is a wallet in
someone else's custody.

## Two traps that cost a full build cycle each

- **`-allowProvisioningUpdates` is not enough for a phone the account has never seen.** It lets
  Xcode mint a profile but not enrol hardware, so the build succeeds and the *install* fails
  with `0xe8008012 This provisioning profile cannot be installed on this device`. Add
  `-allowProvisioningDeviceRegistration`.
- **`xcode-select -p` reports the *active* toolchain, not what is installed.** Seeing
  `CommandLineTools` does not mean Xcode is absent — exactly the trap that once made a run of
  this conclude "no Xcode installed", and that reappeared on 2026-07-30 in a fresh shell where
  `simctl` came back as "not a developer tool". Export `DEVELOPER_DIR`; you do not need
  `sudo xcode-select -s`.

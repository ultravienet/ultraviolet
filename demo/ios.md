# Running the prover under iOS

**A payment proves in about a third of a second on an iPhone — and not only on an expensive
one.** Measured 2026-07-27 from an app built against `aarch64-apple-ios`, on two devices
chosen to be far apart in price:

**iPhone 17 Pro Max (A19 Pro), iOS 26.5.2** — the flagship:

| Config | Prove | Proof | Verify | Peak RSS | Prover's share |
|---|---|---|---|---|---|
| Hiding (the payment format) | 0.284–0.314 s | 208.0 KB | 1.6–1.7 ms | 279 MB | 259 MB |
| Standard | 0.099–0.102 s | 158.3 KB | 1.3 ms | 56 MB | 37 MB |

**iPhone 16e (A18), iOS 26.2.1** — the cheapest iPhone Apple currently sells:

| Config | Prove | Proof | Verify | Peak RSS | Prover's share |
|---|---|---|---|---|---|
| Hiding (the payment format) | 0.331–0.354 s | 208.0 KB | 1.8–2.0 ms | 304 MB | 261 MB |
| Standard | 0.121–0.128 s | 158.3 KB | 1.5–1.8 ms | 81 MB | 39 MB |

**The budget phone is only ~1.15× slower on the payment format** (~1.25× on the standard
configuration). That is the number that matters: the claim is that *a* phone can prove, not
that a flagship can, and a two-tier price gap moves it by a sixth.

**Read the memory column carefully.** The 16e's peak looks 25 MB higher, but the *prover's*
share is within 2 MB of the flagship's — 261 MB against 259 MB. The difference is entirely the
host app's baseline (43 MB on the 16e against 19 MB on the Pro Max), which is iOS and UIKit,
not us. Quoting the peak without the baseline would have invented a difference that is not
there. Proof sizes are byte-identical on both phones and on the Mac.

That byte-identical agreement with the macOS build is the useful signal: the port is faithful,
not approximately faithful. This is what closed spec/99's delegated-proving problem — there is
no reason to delegate proving to a server, so the witness never leaves the phone.

The app that produces these numbers is [`ios/UVProbe`](../ios/README.md), committed so the
measurement can be repeated rather than believed.

**Re-measured 2026-07-27 after the blinding generator changed** from a fast insecure RNG to an
OS-seeded cryptographic one — a change that touches the hot path, since a hiding proof draws on
the order of half a million random field elements. It cost nothing detectable. The control that
makes that a conclusion rather than a hope: the *standard* configuration, which never touches
that generator, drifted by the same few percent, so the difference is a warm phone rather than
the change. `air/tests/published_numbers_hold.rs` now guards these figures on every build.

## Measuring memory honestly

Peak RSS is a **process** high-water mark, and two things will quietly corrupt it.

**Run one configuration per process.** Proving standard and hiding in the same process
reports the union of the two, which is neither one's cost. This is not a rounding error:
the desktop figure was 146 MB for the pair and 117 MB for hiding alone. Both harnesses now
isolate — `UV_MEASURE=transfer-hiding` on the desktop, `UV_MODE=2` on the phone.

**Subtract the host app's baseline.** UIKit costs ~20–25 MB before any proving begins, so
the app reports its own baseline and the prover's share separately.

### A gap we measured and could not explain

Hiding needs ~279 MB on the phone against ~117 MB on the Mac, while standard matches
closely (56 MB vs 67 MB). It is specific to the hiding configuration, not a platform-wide
offset.

Thread count is ruled out. The phone reports 6 threads to the Mac's 10 — *fewer* threads and
*more* memory — and pinning both to `RAYON_NUM_THREADS=1` moved neither the memory nor the
time. The leading hypothesis is allocator page retention: the hiding path churns many large
short-lived buffers, and an allocator that holds freed spans instead of returning them
raises the resident high-water mark without the program holding more live data. That is a
hypothesis, not a finding. It does not threaten the conclusion, since 279 MB is well inside
an app's budget either way, but quote the phone's number for a phone.

## The simulator, and why it cannot answer the question

The simulator executes arm64 natively on the development machine's own CPU, so a simulator
timing is a Mac timing. It is still useful for checking that the port builds, links, and
runs — just never for speed. On an M4 with the iPhone 17 Pro simulator it gave 0.10 s
standard and 0.26 s hiding, which happened to land near the phone's numbers by coincidence
of the M4 and A19 Pro being close, not because the simulator models the phone.

Xcode must be the active developer directory:

```bash
export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
xcodebuild -version          # confirm you have Xcode, not just the CLI tools
```

`xcode-select -p` reports the *active* toolchain, not what is installed. Xcode can be
present while that path still points at `CommandLineTools` — exactly the trap that made an
earlier run of this conclude "no Xcode installed". Override `DEVELOPER_DIR`; you do not
need `sudo xcode-select -s`.

```bash
rustup target add aarch64-apple-ios-sim          # once
cargo build --release -p uv-air --bin measure --target aarch64-apple-ios-sim

UDID=$(xcrun simctl list devices available -j | python3 -c "
import json,sys
for rt, devs in json.load(sys.stdin)['devices'].items():
    for d in devs:
        if 'iPhone' in d['name']: print(d['udid']); raise SystemExit")
xcrun simctl boot "$UDID"

# simctl does NOT inherit your environment. Pass variables through with the
# SIMCTL_CHILD_ prefix, or both circuits run and the numbers mix.
SIMCTL_CHILD_UV_MEASURE=transfer-hiding xcrun simctl spawn "$UDID" \
  "$PWD/target/aarch64-apple-ios-sim/release/measure"
```

Peak memory is self-reported by the binary via `getrusage`, because there is no shell inside
the simulated process to wrap the command in. It agrees with `/usr/bin/time -l` on macOS,
which is what makes it trustworthy elsewhere.

## The device build

iOS runs app bundles, not bare binaries, so measuring on hardware means embedding the prover
in a signed app. `ios/UVProbe` is that app and `ios/README.md` has the commands.

One trap is worth repeating here because it costs a full build cycle to discover:
**`-allowProvisioningUpdates` is not enough for a phone the account has never seen.** It
lets Xcode mint a profile but not enrol hardware, so the build succeeds and the *install*
fails with `0xe8008012 This provisioning profile cannot be installed on this device`. Add
`-allowProvisioningDeviceRegistration`.

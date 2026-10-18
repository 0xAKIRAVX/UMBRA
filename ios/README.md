# UMBRA iOS — build & run

## Requirements

- macOS 13+ with **Xcode 15+** (Xcode 14 works too) and an Apple ID (a free
  team is enough to run on your own device)
- iOS 16.0+ device or simulator

## Open & run

1. `open UMBRA.xcodeproj`
2. Select the **UMBRA** scheme + your device/simulator
3. In *Signing & Capabilities* pick your team (Xcode manages the rest — no
   special entitlements, no capabilities, no App-Store setup)
4. `Cmd+R`

No CocoaPods. No SPM dependencies. The app is 100% first-party frameworks:
CryptoKit, Network, SwiftUI, CoreImage.

## Verify the crypto before trusting a scan (recommended once)

`Cmd+U` runs the test suite. The critical one is **WgVectorsTests** — it
compares the full WireGuard handshake stack **byte-for-byte** against the
shared reference vectors that the Android app also passes (generated from a
Python reference that was verified live against production Cloudflare WARP
endpoints). If it is green, this app speaks exactly the same wire protocol
as the validated Android build.

## If the project file ever drifts

- Preferred: regenerate with XcodeGen — `brew install xcodegen && xcodegen generate`
  (uses `project.yml`), or
- Re-run the deterministic generator: `python3 ../tools/gen_pbxproj.py`
  (the shipped `UMBRA.xcodeproj` was produced by exactly this script — see
  `ios/tools/gen_pbxproj.py`)

## What is included (parity with Android v3.11.0)

- **ENDPOINT mode** — the BPB-Warp-Scanner workflow: random ip:port pairs
  from the WARP ranges (IPv4 + IPv6 embedded twins), each validated by a
  REAL Noise_IKpsk2 WireGuard handshake over UDP with the registered
  identity, plus the in-tunnel ICMP echo as the bonus data-plane proof
- **EDGE mode** — Cloudflare edge CIDR sampling + TCP storm + real TLS
  verification (the DPI-fake filter) + exact-IP speed test
- **Pre-flight witness gate + recovery ladder** — family-balanced witness,
  stale-identity self-heal, full-port sweep (v4 then v6 twins), re-aim onto
  proven paths, honest abort verdicts with NTP/VPN evidence
- **Smart ranking** — adaptive weights from the measured line profile
  (NETSENSE), smart picks (best / lowest ping / most stable / fastest)
- **VLESS builder + QR**, CSV/TXT/JSON exports, live log console
- **EN + FA UI with full RTL**

## iOS-specific notes

- Scans run while the app is foregrounded (the screen is kept awake during a
  scan). iOS suspends the app in the background, so let a deep scan finish
  in the foreground — same discipline as any network test app.
- The event-driven UDP stack (Network.framework) means the storm never
  blocks threads: the Android "elastic lanes" fix is structural here.
- Update checks are Android-only (GitHub releases serve the APK); the iOS
  side shows the version + source link in Settings.

## Versioning

The initial iOS release carries marketing version 3.11.0 — the engine
semantics it ports. The Android app has since moved to a v4.x Rust/Go
architecture (Android-internal changes; the wire protocol and scan
methodology are unchanged), and the next iOS release will track the repo
version again.

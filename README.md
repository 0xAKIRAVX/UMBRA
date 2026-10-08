<p align="center">
  <img src="docs/banner.svg" alt="UMBRA" width="860"/>
</p>

<h1 align="center">U M B R A</h1>

<p align="center">
  <strong>A native Android scanner that hunts for the fastest Cloudflare and WARP endpoints hiding in your network — and turns them into ready-to-use VLESS configs.</strong>
</p>

<p align="center">
  <a href="https://github.com/0xAKIRAVX/UMBRA/releases"><img src="https://img.shields.io/badge/release-v3.1.0-ff3b4a?style=flat-square&labelColor=0d1420" alt="release"></a>
  <img src="https://img.shields.io/badge/platform-Android%208.0%2B-34d399?style=flat-square&labelColor=0d1420" alt="platform">
  <img src="https://img.shields.io/badge/Kotlin-2.0-7f52ff?style=flat-square&labelColor=0d1420" alt="kotlin">
  <img src="https://img.shields.io/badge/Jetpack%20Compose-Material%203-4285f4?style=flat-square&labelColor=0d1420" alt="compose">
  <img src="https://img.shields.io/badge/APK-%E2%89%882.5%20MB-f15bb5?style=flat-square&labelColor=0d1420" alt="size">
  <img src="https://img.shields.io/badge/tests-94%2F94%20green-00f5d4?style=flat-square&labelColor=0d1420" alt="tests">
  <img src="https://img.shields.io/badge/license-MIT-9b5de5?style=flat-square&labelColor=0d1420" alt="license">
</p>

---

## Why UMBRA

Your connection to Cloudflare's edge is only as good as the *specific IP* your network happens to reach. Some Cloudflare IPs answer in 15 ms with zero loss; others sit behind congested routes and quietly throttle your throughput. Cloudflare's own client never tells you which IP you got — and never lets you choose.

**UMBRA flips the table.** It samples the live Cloudflare and WARP address space directly from *your* device, measures what your network *actually* delivers to each candidate — latency, packet loss, TLS handshake, real download speed — ranks everything for you, and generates a VLESS config bound to the winner.

No root. No Termux. No server. ~2 MB.

---

## What's new in v3.1.0 — the NETSENSE release

- **نت‌سنج / NET CHECK** — a new card on the scan tab measures **your own line**: ping (12 interleaved TCP handshakes to Cloudflare seeds), jitter, packet loss, a **DPI-proof real TLS round-trip** (immune to fake-accepting middleboxes), exact-IP download **and upload**, and the IPv6 route. The result grades your network (عالی / خوب / متوسط / ضعیف) and is stored on-device.
- **SMART PICKS · انتخاب‌های هوشمند** — the results board now opens with a recommendation board computed **for your measured line**: the adaptive **BEST**, the **lowest PING**, the **most STABLE**, and the **FASTEST** endpoint — **both WARP and CF EDGE on one screen** (each family keeps its last verified results). Tap any pick to open its full profile.
- **Adaptive ranking (SMART sort)** — the default sort now weighs every endpoint *relative to your own baseline*: a 350 ms endpoint ranks high on a 300 ms line and low on a 40 ms one. Excellent lines → throughput dominates; poor, lossy lines → stability + ping dominate (speed measurements on a rough line are noise).
- **Bug fixes** — the live top-endpoints board no longer shows unverified TCP-alive endpoints during edge scans (DPI fakes used to flash there before TLS verification pruned them); a failed speed test no longer stamps an error onto a fully-verified WARP endpoint; auto-tune + scan now **share one WARP identity** (15-min cache) instead of registering two accounts per session; the boot splash version label is read from the package instead of being hardcoded.

---

## What's new in v3.0.0 — the Crimson Orbit release

<p align="center">
  <img src="docs/icon.png" alt="UMBRA v3 icon" width="96"/>
</p>

- **New app icon** — the crimson cyber-globe (adaptive on Android 8+, themed/monochrome on 13+, legacy squircle below).
- **فارسی** — the whole interface now speaks Persian: every screen, RTL layout, and the **Vazirmatn** typeface. Persian phones start in Persian automatically; a language switch lives in SYSTEM.
- **New CRIMSON ORBIT palette** (default) matching the icon, plus the original four.
- **Boot splash** — the orbit globe breathes over the void with a gradient wordmark before dissolving into the app.
- **OrbitGlobe live visual** — a wireframe globe with counter-rotating orbital rings and traveling nodes, drawn in a single canvas (it also fills the empty results state).
- **Podium medals** — gold / silver / bronze tint the top-3 result rows.
- **Bug fixes** — VLESS prefill from the results sheet now works every time (not just once per app launch), the scan log no longer drops lines under concurrency, notifications tint with the chosen palette, and family-filter switches reset the reveal window.

---

## Screenshots

Real renders of the app's actual Compose UI — dark substrate, rare typefaces (Bruno Ace SC · Chakra Petch · Major Mono Display · Vazirmatn), spring physics and neon glow:

| Scan configuration | NET CHECK · نت‌سنج card |
| :---: | :---: |
| ![Scan configuration](docs/screenshots/scan-config.png) | ![Net check](docs/screenshots/netcheck.png) |

| Live scan · radar console | Results · smart picks + board |
| :---: | :---: |
| ![Live scan](docs/screenshots/scan-live.png) | ![Results](docs/screenshots/results.png) |

| System settings | Update announcement |
| :---: | :---: |
| ![Settings](docs/screenshots/settings.png) | ![Update dialog](docs/screenshots/update-dialog.png) |

| VLESS generator · QR |
| :---: |
| ![VLESS](docs/screenshots/vless.png) |

---

## Feature Matrix

| Capability | Detail |
| --- | --- |
| **Cloudflare edge scan** | Random sampling of 14 IPv4 + 7 IPv6 edge CIDRs (never enumerates whole ranges) |
| **WARP / WARP+ scan** | Endpoint hunt across 14 BPB-verified ranges — the classic `162.159.192.0/24`-family blocks **plus the newer `8.x` WARP space** many ISPs have not throttled yet |
| **Real WireGuard validation** | Every WARP endpoint is proven by a **full Noise\_IKpsk2 handshake over UDP** followed by an **ICMP echo ping inside the encrypted tunnel** — the same guarantee BPB-Warp-Scanner gives, without shipping a 30 MB xray core |
| **Fresh WARP identity per scan** | Registers a free account on `api.cloudflareclient.com` (the BPB `warp.go` flow) so handshakes authenticate against Cloudflare's production WARP service |
| **UDP noise (anti-DPI)** | Optional burst of 5 random packets before every handshake — the BPB trick that keeps WARP alive on ISPs that pattern-match the first packet |
| **Port sweep** | Single port, or full 55-port WARP sweep (BPB's verified list) for networks that block `2408` |
| **TCP quality** | Multi-attempt connect (1–10 tries) with per-IP latency and packet-loss statistics (edge mode) |
| **TLS verification** | Real handshake against each candidate — valid cert required, per-port SNI (edge mode) |
| **True speed test** | HTTPS download **directly from the candidate IP** with SNI/Host pinned to `speed.cloudflare.com` — DNS cannot redirect the measurement |
| **Ranking engine** | WARP results ranked by in-tunnel ping RTT + loss; edge results by the composite score |
| **NET CHECK / نت‌سنج** | Measures the user's own line — ping, jitter, loss, DPI-proof TLS RTT, exact-IP download **and upload** (POST `speed.cloudflare.com/__up`), IPv6 — and grades it عالی/خوب/متوسط/ضعیف |
| **SMART PICKS / انتخاب‌های هوشمند** | Adaptive BEST · LOW PING · MOST STABLE · FASTEST per family (WARP + CF EDGE side by side), baseline-relative scoring, weights that shift with the measured grade of your line |
| **VLESS generator** | One-tap `vless://` URLs, QR codes, IPv6 correctly bracketed (`vless://uuid@[2606:4700:...]:443`) |
| **AUTO-TUNE** | Single-tap network calibration — the WARP port sweep now validates each port with a **live WireGuard handshake**, so the tuned port list is guaranteed to carry WARP traffic on your network |
| **Export** | Results as CSV, JSON, or TXT |
| **Self-update** | Silent GitHub release check on launch (24 h throttle) + animated in-app announcement with one-tap download |
| **English + فارسی** | Full bilingual interface with RTL mirroring, Vazirmatn typography, and a system-integrated per-app language config |
| **Background scans** | Foreground service with live notification + STOP action |
| **Privacy** | Zero analytics, zero trackers, zero data collection — everything stays on device |

---

## Download

Grab the latest signed APK from the **[Releases](https://github.com/0xAKIRAVX/UMBRA/releases)** page.

| | |
| --- | --- |
| Latest version | **v3.1.0** (build 9) |
| Requirement | Android 8.0+ (API 26) |
| Architecture | Universal (all ABIs) |
| Permissions | `INTERNET`, `FOREGROUND_SERVICE`, `POST_NOTIFICATIONS` — nothing else |

> Install like any sideloaded app: download, open, allow "unknown sources" if asked, done.
>
> ⚠ **Upgrading from v2.5.0 or older?** The v3.0.0+ APKs are signed with a **new release key** (the signing workstation was rebuilt and the old private key could not be recovered), so Android will refuse an in-place update. **Uninstall the old UMBRA first, then install v3.1.0** — nothing of value is lost (scans are per-session, settings take 5 seconds to re-pick). **v3.0.0 users upgrade in place.**

---

## Two Scanners, One Engine

| | Cloudflare Edge mode | WARP / WARP+ mode |
| --- | --- | --- |
| IPv4 pools | 14 Cloudflare edge CIDRs (`104.16.0.0/13`, `172.64.0.0/13`, …) | 14 BPB-verified WARP `/24`s: `162.159.192/193/195.x`, `188.114.96–99.x`, **`8.34.146.x`**, **`8.39.214.x`**, **`8.6.112.x`**, … |
| IPv6 pools | 7 Cloudflare v6 /32s (`2606:4700::/32`, …) | `2606:4700:d0::/48`, `2606:4700:d1::/48` (v4-embedded hosts) |
| Ports | 443, 8443, 2053, 2083, 2087, 2096 | 57 canonical WARP ports (BPB list + 443), `2408` first |
| Validation | TCP pre-filter + **mandatory TLS-certificate verification** | **Real WireGuard handshake + ICMP ping inside the tunnel** |
| Output use | VLESS / proxy config, best-IP routing | WireGuard endpoint, WARP client config |

The WARP v6 generator is not random guessing: real WARP endpoints embed their IPv4 address in the low 32 bits (`162.159.192.1` ⇔ `2606:4700:d0::a29f:c001`), so UMBRA maps the live v4 pool into both `/48`s and hits real hosts instead of spraying into 2^80 dead space.

### What "speed test" means here

UMBRA never resolves `speed.cloudflare.com` with DNS. It opens TLS **directly to the candidate IP** while presenting the hostname only inside the TLS SNI and HTTP `Host` header. The certificate is fully validated. That means:

- the bytes you measure are served by the IP you scanned, not an "optimized" anycast re-route;
- a green result proves that exact IP is usable as a host override / endpoint;
- failures are honest — reported as `TLS handshake timeout`, `HTTP status: 403`, etc. Nothing is silently dropped.

### Why a TCP connect alone is never "alive" (v2.5.0)

On heavily-filtered networks (Iran being the textbook case) DPI middleboxes
**complete the TCP handshake for any destination** — connect() succeeds to IPs
that are nowhere near alive. A scanner that trusts TCP will happily hand you a
board full of fake endpoints. UMBRA v2.5.0 therefore treats TCP as a mere
pre-filter: every edge-mode result is only reported after a full **TLS
handshake whose certificate validates for `speed.cloudflare.com`** through that
exact IP. DPI-fake endpoints fail that check and are discarded — what remains
is guaranteed to work in v2rayNG / Hiddify / sing-box as a host override.

---

## Real WireGuard Validation — why UMBRA's WARP results actually work

Most "WARP scanners" check whether a TCP port answers. That proves nothing: WARP
speaks **UDP WireGuard**, so a TCP-reachable endpoint can be completely dead for
real traffic — which is exactly why so many scanner results look fake.

UMBRA v2.5.0 ports the **BPB-Warp-Scanner** approach into pure Kotlin (no 30 MB
xray-core, the APK stays under 2 MB):

1. **Registers a free WARP identity** on `api.cloudflareclient.com` — the same
   flow as BPB's `warp.go`. The account's WireGuard key, reserved bytes and
   assigned addresses are used for every probe in the scan.
2. **Speaks the actual protocol**: a complete Noise\_IKpsk2 handshake initiation
   (X25519 + ChaCha20-Poly1305 + BLAKE2s, hand-rolled in ~700 lines of dependency-
   free Kotlin, ported line-by-line from wireguard-go and verified byte-for-byte
   against it) is sent over UDP to each candidate `ip:port`.
3. **Carries the WARP client_id in every packet** (v2.5.0 fix): Cloudflare's data
   plane reads the 3-byte WireGuard *reserved* field of **every** packet —
   handshake included — as the account's client_id, exactly like Xray's WARP
   outbound does. Packets without it cannot be associated with the registered
   identity and are silently dropped; this was the root cause of empty/dead
   WARP scans in earlier builds.
4. **Proves the data plane**: after the handshake response is authenticated,
   UMBRA derives the session keys, sends an **ICMP echo request to 1.1.1.1 inside
   the encrypted tunnel**, and parses the echo reply. An endpoint only counts as
   *alive* when data actually flows — the same guarantee BPB gets by pushing HTTP
   through an xray WireGuard tunnel.
5. **Optionally fires anti-DPI noise**: a burst of 5 random UDP packets before
   every handshake (on by default) — the trick that keeps WARP usable on ISPs
   that fingerprint the first packet.

The crypto stack is covered by **76 unit tests**, including byte-for-byte
differential vectors against the Python reference implementation that was itself
validated live against production Cloudflare WARP endpoints.

---

## How Updating Works

From v2.3.0 on, UMBRA keeps itself honest about updates — no store, no middleman:

1. On every launch (silent, ~1.5 s after the UI settles) the app queries the GitHub **releases API** for the latest tag — throttled to one attempt per 24 hours, toggleable in settings.
2. If the tag is strictly newer than the installed build, an animated **announcement dialog** appears over the current screen: current version → new version, the release notes, and a **DOWNLOAD FROM GITHUB** button that jumps straight to the release.
3. Dismissed announcements never nag again for the same tag. A **CHECK NOW** row in settings forces a check any time, with live status (checking / up-to-date / unreachable).

New versions are distributed as signed APK assets on the [releases page](https://github.com/0xAKIRAVX/UMBRA/releases) — nothing else is contacted, and no update is ever installed without you tapping the button.

---

## AUTO-TUNE — one tap, optimal settings

Advanced panels in scanner apps are usually guesswork. AUTO-TUNE removes the guessing:

1. Fires RTT probes at known-good seed endpoints.
2. Checks whether IPv6 routing actually works on your network.
3. Registers a WARP identity and sweeps the full port matrix with **live WireGuard handshakes** — every port in the tuned list is proven to carry WARP traffic on your network.
4. Measures a 512 KB direct-IP download to gauge link quality.
5. Reads device class (RAM, core count).

The result is a concrete, explained configuration — network family, port set, sweep on/off, timeout, concurrency, sample count, verify/speed shortlist, download size — with a visible report of *why* each value was chosen. Weak device? Animations drop to a lightweight mode automatically.

---

## The Interface

A dark, instrument-panel aesthetic built for legibility at a glance:

- **Boot splash & OrbitGlobe** — the v3 signature: a live wireframe globe with counter-rotating orbital rings and traveling nodes (single canvas, draw-phase only), echoing the launcher icon at startup, in the idle hero, and in the empty results state.
- **CRIMSON ORBIT palette** — the new default accent matches the crimson globe icon; four more rare palettes ship alongside.
- **English + فارسی** — full RTL mirroring with Vazirmatn typography; the language flips instantly from SYSTEM, and Persian devices start in Persian.
- **Aurora background** — two slow-orbiting accent orbs, computed in the draw phase (no recomposition cost).
- **Radar console** — expanding echo rings and a pulsing dot while a scan is live.
- **Springy everything** — sliding selection pills, staggered card entrances, shimmer sweeps on buttons and progress, count-up numbers, QR reveal animation, animated list re-ordering while results sort.
- **Rare typefaces** — *Bruno Ace SC* display, *Chakra Petch* body, *Major Mono Display* telemetry numerals, *Vazirmatn* for Persian (all SIL OFL).
- **60 FPS discipline** — every animation reads state in the draw phase, zero allocations per frame, all effects freeze under LIGHTWEIGHT FX on low-end hardware.

Every result row shows rank medal, protocol, port, TLS state, latency, loss and speed — in fixed columns that never overflow, on any screen width.

---

## Performance Engineering

| Technique | Payoff |
| --- | --- |
| Draw-phase animations (`graphicsLayer` state reads) | Buttons, glows and pills animate without triggering recomposition |
| Batched, throttled `StateFlow` emission | 150 concurrent probes never stall the UI thread |
| `@Stable` / `@Immutable` models + `derivedStateOf` | Recomposition skips untouched subtrees |
| Keyed `LazyColumn` + `animateItem` | Sorting 10k+ rows re-animates placement smoothly |
| `preferredDisplayModeId` frame-rate unlock | High-refresh displays run at their native rate |
| R8 full mode + resource shrinking | Whole app, fonts and launcher icons included, in ~2.5 MB |

32 unit tests cover CIDR math, IPv6 generation, WARP embedding, ranking (incl. the v2.5.0 anti-fake-DPI aliveness rules), VLESS formatting and AUTO-TUNE decisions; 15 more verify the WireGuard crypto stack (incl. the WARP client_id/reserved-bytes vectors) byte-for-byte against the wireguard-go-derived reference vectors (X25519 incl. RFC 7748, BLAKE2s, HMAC, ChaCha20-Poly1305, full handshake + transport + ICMP), 6 cover the WARP registration flow, and 19 cover the update checker, the rendered screenshots, and the bilingual string system — **80 total, all green**.

---

## Build From Source

```bash
git clone https://github.com/0xAKIRAVX/UMBRA.git
cd UMBRA
./gradlew assembleRelease        # or: assembleDebug
```

Requirements: JDK 17 and an Android SDK with platform 34.

**Signing:** the release keystore is deliberately *not* in this repository. Builds without it are automatically signed with the debug key and install normally. To reproduce official release signing, create `app/keystore.properties`:

```properties
storeFile=umbra-release.jks
storePassword=...
keyAlias=...
keyPassword=...
```

Run the test suite:

```bash
./gradlew test
```

---

## Project Structure

```
app/src/main/java/com/umbra/scanner/
├── core/            Cidr · IpText · Model · Presets · Ranking
├── engine/          ScanEngine · ScanController · AutoTune · ScanForegroundService
├── i18n/            Strings (English + فارسی)
├── net/             TcpProbe · HttpsOverIp · WarpProbe · WgProtocol · WgCrypto · WarpAccount
├── export/          Exporters (CSV / JSON / TXT)
├── vless/           VlessGenerator · QrGen
├── settings/        UmbraSettings (persistence)
└── ui/
    ├── theme/       Color · Type · Theme
    ├── components/  Atoms · Motion · Radar · OrbitGlobe · UpdateDialog
    ├── screens/     Scan · Config · Results · VLESS · Settings
    └── UmbraRoot.kt navigation + screen transitions
```

32 Kotlin files, ~6,600 lines, zero third-party UI dependencies — the entire visual system is hand-built on Compose primitives.

---

## Tech Stack

| Layer | Choice |
| --- | --- |
| Language | Kotlin (JVM target 17) |
| UI | Jetpack Compose + Material 3 (BOM 2024.09.03) |
| Concurrency | Kotlin coroutines + structured concurrency (semaphore-gated lanes) |
| Networking | Raw `Socket` / `SSLSocket` — no OkHttp, no DNS |
| QR | ZXing core |
| Persistence | SharedPreferences via UmbraSettings |
| Min / target SDK | 26 / 34 |

---

## FAQ

<details>
<summary><b>Why do other scanners' WARP endpoints not work, and UMBRA's do?</b></summary>
&nbsp;TCP-reachable ≠ WARP-alive. WARP speaks UDP WireGuard, so a port that answers TCP can be completely dead for real tunnel traffic. Since v2.4.0, UMBRA only lists endpoints that completed a <b>real WireGuard handshake</b> and passed an <b>ICMP ping inside the encrypted tunnel</b>; since <b>v2.5.0</b> every packet also carries the account's <b>client_id</b> in the reserved bytes (Xray parity), which is what makes Cloudflare's data plane actually route the tunnel traffic. Copy the results into WireGuard / v2rayNG / Hiddify and they work.
</details>

<details>
<summary><b>WARP scan finds nothing on my network</b></summary>
&nbsp;Your ISP is probably blocking port 2408 (common in some regions). Enable <b>SWEEP</b> in the WARP port row — UMBRA will validate all 57 canonical WARP ports per candidate with real handshakes, and always falls back to 443 for the speed measurement. If literally every port is dead, run AUTO-TUNE: its report will tell you which ports survived a live handshake. Keep <b>UDP NOISE</b> enabled — it defeats DPI throttling of the first WARP packet.
</details>

<details>
<summary><b>Why is the speed test measured on port 443 in WARP mode?</b></summary>
&nbsp;Most WARP ports carry WARP's own protocol, not TLS for <code>speed.cloudflare.com</code>. Measuring throughput on :443 with the correct SNI is the only honest apples-to-apples measurement of the endpoint's raw forwarding capacity.
</details>

<details>
<summary><b>Is scanning Cloudflare ranges legal / safe?</b></summary>
&nbsp;UMBRA performs ordinary TCP connects, TLS handshakes, and WireGuard handshakes with free self-registered WARP accounts — the same traffic any WARP client makes — only aimed at addresses Cloudflare publishes as its own ranges. No exploit probing, no port enumeration beyond documented service ports, nothing sent to third parties. Be a good citizen: reasonable sample counts, reasonable concurrency.
</details>

<details>
<summary><b>Where are my results stored?</b></summary>
&nbsp;In memory and in the files you explicitly export. UMBRA has no analytics, no crash reporter, no accounts and no servers of its own.
</details>

---

## Author

**UMBRA** is designed, built and maintained by [**0xAKIRAVX**](https://github.com/0xAKIRAVX).

The in-app PROJECT card (SYSTEM tab) exposes the same credits — creator, repository link, license — with one-tap open and copy actions.

| | |
| --- | --- |
| GitHub | [github.com/0xAKIRAVX](https://github.com/0xAKIRAVX) |
| Repository | [github.com/0xAKIRAVX/UMBRA](https://github.com/0xAKIRAVX/UMBRA) |
| Issues & feature requests | [issue tracker](https://github.com/0xAKIRAVX/UMBRA/issues) |

---

## Acknowledgements

- **[BPB-Warp-Scanner](https://github.com/bia-pain-bache/BPB-Warp-Scanner)** (bia-pain-bache) — the endpoint validation model (fresh WARP registration + real-traffic proof + UDP noise) and the verified IP/port pool that UMBRA's WireGuard probe is built on.
- **[wireguard-go](https://github.com/WireGuard/wireguard-go)** / **[Xray-core](https://github.com/XTLS/Xray-core)** — protocol references: the noise KDF chain is ported line-by-line from wireguard-go, and the WARP client_id-in-reserved-bytes extension is verified against Xray's `proxy/wireguard/bind.go`.
- **Cloudflare** — for publishing its IP ranges and running a fast, open edge.
- **[Bruno Ace SC](https://fonts.google.com/specimen/Bruno+Ace+SC)**, **[Chakra Petch](https://fonts.google.com/specimen/Chakra+Petch)**, **[Major Mono Display](https://fonts.google.com/specimen/Major+Mono+Display)**, **[Vazirmatn](https://github.com/rastikerdar/vazirmatn)** by their respective designers, under the SIL Open Font License.
- **[ZXing](https://github.com/zxing/zxing)** for QR generation.
- The community-maintained WARP endpoint port list.

---

## License

Released under the **MIT License** — see [LICENSE](LICENSE). Fonts ship under their own SIL OFL terms.

> **Disclaimer:** UMBRA is a network measurement tool. Users are responsible for complying with their local laws and their provider's terms of service. This project is not affiliated with Cloudflare.

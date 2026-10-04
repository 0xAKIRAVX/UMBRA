<p align="center">
  <img src="docs/banner.svg" alt="UMBRA" width="860"/>
</p>

<h1 align="center">U M B R A</h1>

<p align="center">
  <strong>A native Android scanner that hunts for the fastest Cloudflare and WARP endpoints hiding in your network — and turns them into ready-to-use VLESS configs.</strong>
</p>

<p align="center">
  <a href="https://github.com/0xAKIRAVX/UMBRA/releases"><img src="https://img.shields.io/badge/release-v2.2.0-00f5d4?style=flat-square&labelColor=0d1420" alt="release"></a>
  <img src="https://img.shields.io/badge/platform-Android%208.0%2B-34d399?style=flat-square&labelColor=0d1420" alt="platform">
  <img src="https://img.shields.io/badge/Kotlin-2.0-7f52ff?style=flat-square&labelColor=0d1420" alt="kotlin">
  <img src="https://img.shields.io/badge/Jetpack%20Compose-Material%203-4285f4?style=flat-square&labelColor=0d1420" alt="compose">
  <img src="https://img.shields.io/badge/APK-%E2%89%881.8%20MB-f15bb5?style=flat-square&labelColor=0d1420" alt="size">
  <img src="https://img.shields.io/badge/tests-32%2F32%20green-00f5d4?style=flat-square&labelColor=0d1420" alt="tests">
  <img src="https://img.shields.io/badge/license-MIT-9b5de5?style=flat-square&labelColor=0d1420" alt="license">
</p>

---

## Why UMBRA

Your connection to Cloudflare's edge is only as good as the *specific IP* your network happens to reach. Some Cloudflare IPs answer in 15 ms with zero loss; others sit behind congested routes and quietly throttle your throughput. Cloudflare's own client never tells you which IP you got — and never lets you choose.

**UMBRA flips the table.** It samples the live Cloudflare and WARP address space directly from *your* device, measures what your network *actually* delivers to each candidate — latency, packet loss, TLS handshake, real download speed — ranks everything for you, and generates a VLESS config bound to the winner.

No root. No Termux. No server. ~1.8 MB.

---

## Feature Matrix

| Capability | Detail |
| --- | --- |
| **Cloudflare edge scan** | Random sampling of 14 IPv4 + 7 IPv6 edge CIDRs (never enumerates whole ranges) |
| **WARP / WARP+ scan** | Dedicated endpoint hunt across `162.159.192.0/24`-family v4 ranges + embedded-IPv6 `2606:4700:d0::/48` & `d1::/48` space |
| **Port sweep** | Single port, or full 68-port WARP sweep (500–9425) for networks that block `2408` |
| **TCP quality** | Multi-attempt connect (1–10 tries) with per-IP latency and packet-loss statistics |
| **TLS verification** | Real handshake against each candidate — valid cert required, per-port SNI |
| **True speed test** | HTTPS download **directly from the candidate IP** with SNI/Host pinned to `speed.cloudflare.com` — DNS cannot redirect the measurement |
| **Ranking engine** | Sort by loss, latency, or speed; composite scoring picks the overall winner |
| **VLESS generator** | One-tap `vless://` URLs, QR codes, IPv6 correctly bracketed (`vless://uuid@[2606:4700:...]:443`) |
| **AUTO-TUNE** | Single-tap network calibration that configures every advanced setting for you |
| **Export** | Results as CSV, JSON, or TXT |
| **Background scans** | Foreground service with live notification + STOP action |
| **Privacy** | Zero analytics, zero trackers, zero data collection — everything stays on device |

---

## Download

Grab the latest signed APK from the **[Releases](https://github.com/0xAKIRAVX/UMBRA/releases)** page.

| | |
| --- | --- |
| Latest version | **v2.2.0** (build 4) |
| Requirement | Android 8.0+ (API 26) |
| Architecture | Universal (all ABIs) |
| Permissions | `INTERNET`, `FOREGROUND_SERVICE`, `POST_NOTIFICATIONS` — nothing else |

> Install like any sideloaded app: download, open, allow "unknown sources" if asked, done. The APK is signed with the UMBRA release key; updates install over previous versions.

---

## Two Scanners, One Engine

| | Cloudflare Edge mode | WARP / WARP+ mode |
| --- | --- | --- |
| IPv4 pools | 14 Cloudflare edge CIDRs (`104.16.0.0/13`, `172.64.0.0/13`, …) | `162.159.192.0/24`, `162.159.193.0/24`, `162.159.195.0/24`, `188.114.96.0/23`, `188.114.98.0/23` |
| IPv6 pools | 7 Cloudflare v6 /32s (`2606:4700::/32`, …) | `2606:4700:d0::/48`, `2606:4700:d1::/48` (v4-embedded hosts) |
| Ports | 443, 8443, 2053, 2083, 2087, 2096 | 68 canonical WARP ports, `2408` first |
| TLS SNI / Host | `speed.cloudflare.com` | `engage.cloudflareclient.com` |
| Output use | VLESS / proxy config, best-IP routing | WireGuard endpoint, WARP client config |

The WARP v6 generator is not random guessing: real WARP endpoints embed their IPv4 address in the low 32 bits (`162.159.192.1` ⇔ `2606:4700:d0::a29f:c001`), so UMBRA maps the live v4 pool into both `/48`s and hits real hosts instead of spraying into 2^80 dead space.

### What "speed test" means here

UMBRA never resolves `speed.cloudflare.com` with DNS. It opens TLS **directly to the candidate IP** while presenting the hostname only inside the TLS SNI and HTTP `Host` header. The certificate is fully validated. That means:

- the bytes you measure are served by the IP you scanned, not an "optimized" anycast re-route;
- a green result proves that exact IP is usable as a host override / endpoint;
- failures are honest — reported as `TLS handshake timeout`, `HTTP status: 403`, etc. Nothing is silently dropped.

---

## AUTO-TUNE — one tap, optimal settings

Advanced panels in scanner apps are usually guesswork. AUTO-TUNE removes the guessing:

1. Fires RTT probes at known-good seed endpoints.
2. Checks whether IPv6 routing actually works on your network.
3. Sweeps the full 68-port matrix on live seeds to discover what your ISP lets through.
4. Measures a 512 KB direct-IP download to gauge link quality.
5. Reads device class (RAM, core count).

The result is a concrete, explained configuration — network family, port set, sweep on/off, timeout, concurrency, sample count, verify/speed shortlist, download size — with a visible report of *why* each value was chosen. Weak device? Animations drop to a lightweight mode automatically.

---

## The Interface

A dark, instrument-panel aesthetic built for legibility at a glance:

- **Aurora background** — two slow-orbiting accent orbs, computed in the draw phase (no recomposition cost).
- **Radar console** — expanding echo rings and a pulsing dot while a scan is live.
- **Springy everything** — sliding selection pills, staggered card entrances, shimmer sweeps on buttons and progress, count-up numbers, QR reveal animation, animated list re-ordering while results sort.
- **Rare typefaces** — *Bruno Ace SC* display, *Chakra Petch* body, *Major Mono Display* telemetry numerals (all SIL OFL).
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
| R8 full mode + resource shrinking | Whole app, fonts included, in ~1.8 MB |

32 unit tests cover CIDR math, IPv6 generation, WARP embedding, ranking, VLESS formatting and AUTO-TUNE decisions.

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
├── net/             TcpProbe · HttpsOverIp (direct-IP TLS + speed)
├── export/          Exporters (CSV / JSON / TXT)
├── vless/           VlessGenerator · QrGen
├── settings/        UmbraSettings (persistence)
└── ui/
    ├── theme/       Color · Type · Theme
    ├── components/  Atoms · Motion · Radar
    ├── screens/     Scan · Config · Results · VLESS · Settings
    └── UmbraRoot.kt navigation + screen transitions
```

32 Kotlin files, ~6,100 lines, zero third-party UI dependencies — the entire visual system is hand-built on Compose primitives.

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
<summary><b>WARP scan finds nothing on my network</b></summary>
&nbsp;Your ISP is probably blocking port 2408 (common in some regions). Enable <b>SWEEP</b> in the WARP port row — UMBRA will probe all 68 canonical WARP ports per candidate, and always falls back to 443 for the speed measurement. If literally every port is dead, run AUTO-TUNE: its report will tell you which ports survived.
</details>

<details>
<summary><b>Why is the speed test measured on port 443 in WARP mode?</b></summary>
&nbsp;Most WARP ports carry WARP's own protocol, not TLS for <code>speed.cloudflare.com</code>. Measuring throughput on :443 with the correct SNI is the only honest apples-to-apples measurement of the endpoint's raw forwarding capacity.
</details>

<details>
<summary><b>Is scanning Cloudflare ranges legal / safe?</b></summary>
&nbsp;UMBRA performs ordinary TCP connects and TLS handshakes — the same traffic your browser makes — only aimed at addresses Cloudflare publishes as its own ranges. No exploit probing, no port enumeration beyond documented service ports, nothing sent to third parties. Be a good citizen: reasonable sample counts, reasonable concurrency.
</details>

<details>
<summary><b>Where are my results stored?</b></summary>
&nbsp;In memory and in the files you explicitly export. UMBRA has no analytics, no crash reporter, no accounts and no servers of its own.
</details>

---

## Acknowledgements

- **Cloudflare** — for publishing its IP ranges and running a fast, open edge.
- **[Bruno Ace SC](https://fonts.google.com/specimen/Bruno+Ace+SC)**, **[Chakra Petch](https://fonts.google.com/specimen/Chakra+Petch)**, **[Major Mono Display](https://fonts.google.com/specimen/Major+Mono+Display)** by their respective designers, under the SIL Open Font License.
- **[ZXing](https://github.com/zxing/zxing)** for QR generation.
- The community-maintained WARP endpoint port list.

---

## License

Released under the **MIT License** — see [LICENSE](LICENSE). Fonts ship under their own SIL OFL terms.

> **Disclaimer:** UMBRA is a network measurement tool. Users are responsible for complying with their local laws and their provider's terms of service. This project is not affiliated with Cloudflare.

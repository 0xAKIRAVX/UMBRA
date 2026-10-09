<p align="center">
  <img src="docs/banner.svg" alt="UMBRA" width="860"/>
</p>

<h1 align="center">U M B R A</h1>

<p align="center">
  <strong>A native Android scanner that hunts for the fastest Cloudflare and WARP endpoints hiding in your network — and turns them into ready-to-use VLESS configs.</strong>
</p>

<p align="center">
  <a href="https://github.com/0xAKIRAVX/UMBRA/releases"><img src="https://img.shields.io/badge/release-v3.4.0-ff3b4a?style=flat-square&labelColor=0d1420" alt="release"></a>
  <img src="https://img.shields.io/badge/platform-Android%208.0%2B-34d399?style=flat-square&labelColor=0d1420" alt="platform">
  <img src="https://img.shields.io/badge/Kotlin-2.0-7f52ff?style=flat-square&labelColor=0d1420" alt="kotlin">
  <img src="https://img.shields.io/badge/Jetpack%20Compose-Material%203-4285f4?style=flat-square&labelColor=0d1420" alt="compose">
  <img src="https://img.shields.io/badge/APK-%E2%89%882.5%20MB-f15bb5?style=flat-square&labelColor=0d1420" alt="size">
  <img src="https://img.shields.io/badge/tests-128%2F128%20green-00f5d4?style=flat-square&labelColor=0d1420" alt="tests">
  <img src="https://img.shields.io/badge/license-MIT-9b5de5?style=flat-square&labelColor=0d1420" alt="license">
</p>

---

## Why UMBRA

Your connection to Cloudflare's edge is only as good as the *specific IP* your network happens to reach. Some Cloudflare IPs answer in 15 ms with zero loss; others sit behind congested routes and quietly throttle your throughput. Cloudflare's own client never tells you which IP you got — and never lets you choose.

**UMBRA flips the table.** It samples the live Cloudflare and WARP address space directly from *your* device, measures what your network *actually* delivers to each candidate — latency, packet loss, TLS handshake, real download speed — ranks everything for you, and generates a VLESS config bound to the winner.

No root. No Termux. No server. ~2 MB.

---

## What's new in v3.4.0 — the honest-features release

A fourth full-codebase audit found and fixed what was left: a placebo feature, a hidden memory bomb, and a handful of silent misconfigurations:

1. **WARP+ is now REAL** — the WARP+ toggle used to be cosmetic: nothing ever applied a license key. Picking WARP+ now reveals a license-key field; the key is applied to the registered account through the Cloudflare account API right after registration (the wgcf flow), and the scan log states the outcome plainly — "warp+ license applied" or "key rejected — free warp tier continues". A blank key means free WARP, honestly labelled. The key persists across restarts; plain WARP mode never quietly re-applies an old key.
2. **Mega-sweeps can no longer OOM the app** — a capped 120 000-probe sweep used to materialize every pair coroutine up front *and* keep a result entry for every dead endpoint: on low-RAM devices that was a memory kill before the first probe even answered. The storm now launches through a bounded window (≈2 048 live jobs at any moment) and confirmed-dead probes are counted for progress but never stored — the map only ever holds endpoints worth reading.
3. **Capped sweeps no longer bias the address space** — trimming the candidate list to the 120k budget used to cut from the front, which silently starved the newer 8.x WARP ranges and IPv6 entirely. The trim is now random, so every block keeps its shot.
4. **WARP retries: slider, engine and restore now agree** — the slider offered 8–10 retries while the engine silently clamped at 7; and a restored WARP session showed the TCP attempts value instead of the WG retries Auto-Tune had chosen. Both fixed at the source.
5. **VLESS port garbage is rejected, not rewritten** — a port of "00000" used to parse to 0 and quietly become 1 in the generated link; now it's simply invalid.

> **Running an older build (≤ v3.0.0)?** Install the v3.4.0 APK from Releases — it installs in place (same signature) and fixes the WARP deep-scan crash plus adds the missing NETSENSE (نت‌سنج) card.

---

## What's new in v3.3.1 — the can't-crash-anymore release

A defensive hardening pass over the entire scan pipeline. If any version ever still shows "UMBRA has stopped", this one records the exact reason and keeps running:

1. **Crash journal + last-resort net** — a process-wide uncaught-exception hook records every crash (version, device, full stack trace) to an on-disk journal, visible under **SETTINGS → CRASH LOG** with a one-tap COPY REPORT button. Even a hard crash becomes a pastable, fixable report instead of a mystery.
2. **Coroutine crash nets on every engine scope** — scan engine, foreground service, NETSENSE and the update center now carry `CoroutineExceptionHandler`s: an exception escaping any of them is journaled and logged, and the **process survives**. Uncaught coroutine exceptions are silent process-killers — this closes that class entirely.
3. **The INITIATE DEEP SCAN button press itself is guarded** — the one main-thread call that starts the foreground service (the exact moment "has stopped" dialogs used to appear) now reverts to Idle with an honest message instead of dying on odd OEM restrictions.
4. **Deferred scans are now visible** — starting a scan while NETSENSE is measuring used to be silently swallowed (the button looked dead); the reason now shows in an amber notice on the scan screen.

> **Running an older build (≤ v3.0.0)?** Install the v3.4.0 APK from Releases — it installs in place (same signature) and fixes the WARP deep-scan crash plus adds the missing NETSENSE (نت‌سنج) card.

---

## What's new in v3.3.0 — the WARP-crash release

The scan engine no longer dies mid-scan. A full audit of the WARP data path found the crash users were reporting on filtered networks:

1. **WARP scans no longer collapse on UDP errors (the crash)** — a *connected* datagram socket throws `PortUnreachableException` the moment the OS reports an ICMP error for the destination — which happens constantly when probing thousands of random endpoints, especially on filtered networks. One such exception used to race up the coroutine tree and abort the **entire scan** ("engine failure"). Every UDP send, the socket creation, and every single probe are now exception-proof: a dead endpoint counts as a dead endpoint, and the storm rolls on.
2. **WARP identity survives a blocked registration API** — `api.cloudflareclient.com` is exactly the kind of endpoint that gets filtered. Registration now persists the last working identity to disk (like BPB's `warp.json`) and reuses it whenever a fresh registration cannot be made, instead of aborting the scan outright.
3. **Zero-result scans explain themselves** — when a scan ends with nothing verified, the Done panel now shows the engine's actual last word (blocked registration, capped budget, network state) instead of a silent empty board.
4. **Probe-budget cap** — extreme sweep × samples settings could queue hundreds of thousands of multi-second UDP probes (an overnight "scan" that looks like a hang). The workload is now capped at 120 000 pairs with an honest log line.
5. **New launcher icon** — the cyber-globe artwork, fully re-cut into adaptive (safe-zone), monochrome (Material You themed) and legacy layers for every density.

---

## What's new in v3.2.0 — the second bug-hunt (11 fixes)

A second full-codebase audit (static + regression-tested + live-verified against production Cloudflare) shipped **eleven real fixes**:

1. **"TLS VERIFY off" no longer zero-fills the board** — turning the toggle off skipped the TLS phase, but *alive* still required TLS/HTTP proof, so an EDGE scan ended with an empty board after minutes of probing. TCP-alive endpoints now stay alive and are honestly marked `TCP-ONLY` when you opt out of verification (DPI-fake protection stays fully intact when it's on).
2. **AUTO-TUNE no longer freezes the UI** — the link-capacity step ran a blocking socket download on the **main thread** (up to ~6.7 s, ANR territory). It now dispatches to IO and is actually preemptable by its timeout.
3. **NETSENSE race fixed** — two rapid taps on *Measure* could launch two concurrent measurements that poisoned each other; the guard flag is now set atomically *before* the coroutine launches.
4. **Scan ↔ measurement mutual exclusion, both directions** — starting a scan while NETSENSE was measuring used to corrupt both latency statistics. A scan now defers (with a log line) until the measurement finishes.
5. **No more stuck "scanning…" notification** — with POST_NOTIFICATIONS denied (Android 13+), the *ongoing* progress notification survived the scan forever, undismissable. It's now removed cleanly at completion when the final notification can't be posted.
6. **Honest jitter/loss for NETSENSE** — jitter and loss were pooled across 4 different anycast seeds, so a perfectly stable line graded FAIR (inter-seed RTT spread ≠ jitter) and one blocked seed counted as 25% packet loss. Metrics are now computed per-seed on the most responsive witness.
7. **QR codes no longer jank** — the VLESS QR was encoded synchronously *during composition* and re-encoded on every keystroke; it's now generated off-thread, cached, and only produced for valid links.
8. **Honest WARP probe estimate** — the pre-scan "≈ N PROBES" line ignored the small-block enumeration cap and overstated the workload up to 12× with a high samples setting.
9. **Refresh-rate toggle actually toggles** — switching *Max refresh rate* OFF now resets the window mode (it previously only ever pinned the max mode).
10. **The update dialog is truly modal** — taps on the dimmed scrim used to fall through to the screen behind it.
11. **Smart picks memoized** — the board re-sorted the full result set on every keystroke of the search field; it's now remembered on its exact inputs.

**One-time signature change:** v3.2.0 is signed with a new key (kept in-repo from now on — see *Signing* below). **Uninstall v3.1.1 or older, then install v3.2.0.** Every future update upgrades in place.

---

## What's new in v3.1.1 — the bug-hunt patch

A full-codebase audit shipped **nine real fixes** (each locked in with a regression test):

1. **Results survive a restart** — the persisted smart-pick board was written on every scan but never read back: the results tab greeted you with *NO SCAN DATA YET* after every app restart. The last scan's verified results now hydrate the board on launch, and *Clear board* actually clears them (it used to leave the persisted buckets behind, resurrecting "deleted" results on next launch).
2. **The samples knob is now honest** — small blocks (every WARP `/24`) ignored the *samples/prefix* setting and fully enumerated 254 hosts per block, silently generating ~2.6× more candidates than the on-screen estimate promised and stretching scans just as long. Sampling now respects the knob exactly; the estimate and the engine agree (full enumeration only when you ask for it).
3. **No stale error on verified endpoints** — an endpoint that had already passed full verification could still show an old "timeout" from an earlier phase in its detail sheet.
4. **Latin digits everywhere technical** — on Persian-locale devices, every `%.1f`-style readout rendered Persian numerals inside the Latin mono typeface (fallback glyphs, broken metrics alignment) — and worse, **exported JSON/CSV contained Persian digits, producing invalid JSON**. All technical formatting is now pinned to `Locale.US` (14 call sites swept).
5. **"TLS OK" filter works in WARP scans** — it used to yield an empty list (WARP rows carry their proof in the WireGuard handshake, not in a TLS flag); it now filters on *verified* for both families.
6. **DPI lines can't grade عالی** — a fake-accepting line (perfect TCP, dead TLS) no longer grades EXCELLENT, which used to tilt the smart weights toward raw speed on a line that can't complete a real handshake.
7. **Notification permission asked once** — the system dialog popped on *every* scan start; now exactly once per install.
8. **WARP registration backoff** — the three registration retries fired back-to-back and all hit the same rate-limit window; a 700 ms backoff lets the retry actually land.
9. **Upload metric on IPv6 lines** — the upload probe used the 1.1.1.1 v6 resolver anycast, which doesn't serve the speed SNI, silently nulling the upload number on every v6-capable line.

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
| Latest version | **v3.4.0** (build 14) |
| Requirement | Android 8.0+ (API 26) |
| Architecture | Universal (all ABIs) |
| Permissions | `INTERNET`, `FOREGROUND_SERVICE`, `POST_NOTIFICATIONS` — nothing else |

> Install like any sideloaded app: download, open, allow "unknown sources" if asked, done.
>
> ⚠ **Upgrading from v3.1.1 or older?** The v3.2.0 APK is signed with a new release key that now lives **inside the repo** (`keystore/umbra-release.jks`) so every future build keeps the same signature — Android refuses an in-place update across different keys, so **uninstall the old UMBRA once, then install v3.2.0**. From this version on, updates install over each other seamlessly. Nothing of value is lost (scans are per-session, settings take seconds to re-pick).

### Signing

The release keystore is **committed to this repository** (`keystore/umbra-release.jks`, credentials in `app/keystore.properties`). This is a deliberate trade-off: UMBRA is a personal, sideloaded utility, and the build machine gets rebuilt regularly — an out-of-repo key would silently rotate the signing identity on every rebuild and force every user to uninstall/reinstall on each update. Keeping the key in-repo pins the signature forever. If this project ever becomes widely distributed, rotate to a private key and treat the in-repo one as burned.

> ⚠ The in-repo key means anyone can build an APK that Android accepts as an update to UMBRA. Only ever install builds you produced yourself or downloaded from this repository's Releases page.
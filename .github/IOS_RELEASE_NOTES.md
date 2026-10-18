# UMBRA iOS — sideload build (unsigned)

**English**

This `.ipa` is **unsigned** — install it entirely on your iPhone, no computer needed:

1. Install **Esign** (or Scarlet / GBox) from its official page via **Safari**.
2. Download `UMBRA-unsigned.ipa` from this release (Safari → Downloads).
3. In the signing app: **Import** the `.ipa` from Files → **Sign** with a certificate (your own Apple ID certificate created inside the app, or a shared/free certificate) → **Install**.
4. Settings → General → VPN & Device Management → **Trust** the profile → open **UMBRA**.

> Free certificates expire (7 days for a personal Apple ID; shared certs rotate) — if the app stops opening, re-sign and re-install the SAME `.ipa`. Your scan results and WARP identity survive on the device.

<details><summary>Computer available? Sideloadly / AltStore also work (7-day free certificates, $99/yr for 1-year/TestFlight)</summary>

1. Install Sideloadly on Windows/macOS (Windows also needs iTunes for USB drivers).
2. Connect the iPhone via cable, drag the `.ipa` into Sideloadly, sign with your Apple ID, press Start.
3. On the iPhone: Settings → General → VPN & Device Management → Trust the developer profile.
4. If Apple ID login fails, create an App-Specific Password at appleid.apple.com and use that.

Full Persian walkthrough for the computer path: `ios/INSTALL-FA.md`.

</details>

**فارسی — نصب کاملاً بدون کامپیوتر**

این فایل `.ipa` **بدون امضاست** — همه‌چیز را روی خودِ آیفون انجام می‌دهید، بدون کامپیوتر، بدون دامنه، بدون سرور:

1. برنامه **Esign** (یا Scarlet / GBox) را از صفحه رسمی‌اش با **Safari** نصب کنید.
2. فایل `UMBRA-unsigned.ipa` را از همین ریلیز دانلود کنید (Safari → Downloads).
3. داخل برنامه امضا: **Import** فایل از Files → **Sign** با گواهی (اپل‌آی‌دی خودتان را داخل برنامه وارد کنید تا گواهی ساخته شود، یا گواهی رایگان/اشتراکی برنامه) → **Install**.
4. Settings → General → VPN & Device Management → گواهی را **Trust** کنید → **UMBRA** را باز کنید.

> گواهی‌های رایگان منقضی می‌شوند (اپل‌آی‌دی شخصی: ۷ روز؛ گواهی‌های اشتراکی چرخشی) — اگر برنامه باز نشد، همین `.ipa` را دوباره امضا و نصب کنید. نتایج اسکن و هویت WARP روی گوشی حفظ می‌شوند.

---

Built by GitHub Actions (cloud Mac) from `main`. The WG crypto/protocol stack is verified **byte-for-byte** on the simulator against the same `warp_vectors.json` reference vectors the Android build passes (BLAKE2s, HMAC, X25519, ChaCha20-Poly1305, a complete handshake + transport round-trip) before this `.ipa` is packaged.

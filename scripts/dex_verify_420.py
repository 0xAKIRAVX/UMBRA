#!/usr/bin/env python3
"""DEX verification for UMBRA v4.2.0 — proves the release artifact actually
contains the v4.2 code paths: the census-proven Akamai SNI (www.bing.com),
the DEEP MEASURE phase, the repeated real-page throughput measure, the new
regional Akamai blocks, and the FA/EN deep-measure strings (in the DEX string
pool — AppStrings is a Kotlin object, not res/values)."""
import sys, zipfile

APK = "app/build/outputs/apk/release/app-release.apk"

with zipfile.ZipFile(APK) as z:
    dexes = sorted(n for n in z.namelist() if n.endswith(".dex"))
    print(f"dex files: {dexes}")
    blob = b""
    for n in dexes:
        blob += z.read(n)

text = blob.decode("utf-8", errors="ignore")

checks = {
    # v4.2: the census-proven Akamai probe host
    "akamai sni host": "www.bing.com",
    # v4.2: new census-verified regional blocks (a few representatives)
    "akamai block 60.254.128.0/18": "60.254.128.0/18",
    "akamai block 118.215.128.0/18": "118.215.128.0/18",
    "akamai block 125.252.192.0/18": "125.252.192.0/18",
    # v4.2: the deep-measure phase
    "deep measure log": "deep measure done",
    "deep measure phase label": "DEEP MEASURE",
    "deep re-measure marker": "re-measured",
    "flaky marker": "flaky (loss",
    # v4.2: the repeated real-page throughput measure
    "repeated fetch error": "budget window closed",
    "speed via line": "repeated real-page fetches",
    "deep rounds log": "wireguard rounds",
    # v4.2: persisted deep-param keys
    "deep pref key": "p_deepN",
    # session trust line
    "akamai session line": "real-page throughput",
    # i18n (dex string pool — AppStrings is Kotlin, not resources)
    "deep label EN": "DEEP MEASURE",
    "fa deep label": "\u0633\u0646\u062c\u0634 \u0639\u0645\u06cc\u0642",
    "fa akamai throughput hint": "\u062a\u0648\u0627\u0646 \u0639\u0628\u0648\u0631\u06cc",
    # the retired v4.1 strings must be GONE (checked via absence below)
}
fails = []
for name, needle in checks.items():
    ok = needle in text
    print(f"  {'OK ' if ok else 'MISS'}  {name}: {needle!r}")
    if not ok:
        fails.append(name)

# retired v4.1 skip-line must be ABSENT (the mode runs the speed phase now)
gone = {
    "retired skip line": "speed phase skipped",
    "retired akamai.com probe sni in params": "www.akamai.com",
}
print("\nABSENCE checks:")
for name, needle in gone.items():
    n = text.count(needle)
    print(f"  {'OK ' if n == 0 else 'PRESENT'}  {name}: {n} occurrences")
    if n > 0:
        fails.append(name)

print("\nDEX verification:", "FAILED" if fails else "PASSED")
sys.exit(1 if fails else 0)

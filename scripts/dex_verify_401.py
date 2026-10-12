#!/usr/bin/env python3
"""v4.0.1 DEX verification.

Extends the v4.0.0 contract (JNI bridge + gomobile classes must survive R8)
and scans ALL dex files in the multidex APK (the Go runtime pushes the app
past a single classes.dex), plus the v4.0.1 locale-hardening strings.
"""
import re
import sys
import zipfile

APK = "app/build/outputs/apk/release/app-release.apk"
BAD = []

with zipfile.ZipFile(APK) as z:
    names = z.namelist()
    dex_names = [n for n in names if n.endswith(".dex")]
    dex = b"".join(z.read(n) for n in dex_names)
    manifest = b"".join(z.read(n) for n in names if n.startswith("AndroidManifest"))

print(f"dex files: {len(dex_names)} ({', '.join(dex_names[:6])})")


def has(s: str) -> bool:
    return s.encode() in dex


# Descriptor checks are ONLY for classes bound BY NAME (JNI native-method
# lookup, gomobile's Class.forName, JNI_OnLoad). Every other class is
# legitimately R8-renamed — verified against the OFFICIAL v4.0.0 release APK
# (identical MISS pattern there); their presence is instead pinned by the
# feature-STRING checks below.
checks = {
    "JNI bridge class": "Lcom/umbra/scanner/bridge/UmbraCore;",
    "gomobile runtime (go.Seq)": "Lgo/Seq;",
    "gomobile bindings pkg": "Lcom/umbra/scanner/goclean/goclean/Goclean;",
}
for name, desc in checks.items():
    ok = has(desc)
    print(f"{'OK ' if ok else 'MISS'} {name}")
    if not ok:
        BAD.append(name)

# native method names must NOT be renamed (JNI resolution is by exact name)
for sym in (b"nativeStart", b"nativeProbeOnce", b"nativePoll", b"nativeGetMark"):
    ok = re.search(sym, dex) is not None
    print(f"{'OK ' if ok else 'MISS'} symbol {sym.decode()}")
    if not ok:
        BAD.append(sym.decode())

# ── v4.0.1: the locale-hardening round's feature strings + version ──
required_strings = [
    "scan session started",          # sessionStartLine (extracted pure)
    "recovery sweep",                # formatRttCompact caller
    "scan re-aimed",                 # v3.10 feature, still live
    "witness verdict",
    "pre-flight witness",
    "engines · ",                    # v4 engine lineup line
    "wg deep probe",                 # DebugScreen deep probe
    "clean deep probe",
    "probe crashed",                 # v4.0.1 runDeepProbe crash-net line
    "vless://",
]
for s in required_strings:
    ok = s.encode() in dex
    print(f"{'OK ' if ok else 'MISS'} string: {s}")
    if not ok:
        BAD.append(s)

# versionName lives in the binary manifest string pool as UTF-16LE; the
# engine cores keep their OWN version constants (prebuilt .so/AAR — they
# legitimately still report 4.0.0, engine versions ≠ app version).
version_ok = (
    b"4.0.1" in dex
    or "4.0.1".encode("utf-16-le") in manifest
    or b"4.0.1" in manifest
)
print("OK " if version_ok else "MISS", "versionName 4.0.1")
if not version_ok:
    BAD.append("version 4.0.1")

two_refs = dex.count(b"Ljava/math/BigInteger;->TWO:Ljava/math/BigInteger;")
print("OK " if two_refs == 0 else "FAIL", "BigInteger.TWO refs == 0")
if two_refs != 0:
    BAD.append("BigInteger.TWO")

print("DEX VERIFICATION:", "PASSED" if not BAD else f"FAILED ({BAD})")
sys.exit(1 if BAD else 0)

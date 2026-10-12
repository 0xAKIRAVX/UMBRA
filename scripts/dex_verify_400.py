#!/usr/bin/env python3
"""v4.0.0 DEX verification: the tri-lingual rebuild's critical classes must
survive R8 — the JNI bridge (native symbol binding) and the gomobile Go
runtime bindings (JNI_OnLoad class lookup by exact name)."""
import re, subprocess, sys, zipfile

APK = "app/build/outputs/apk/release/app-release.apk"
BAD = []

with zipfile.ZipFile(APK) as z:
    dex = z.read("classes.dex")

# strings scan over the dex blob (class descriptors are plain strings)
def has(s: str) -> bool:
    return s.encode() in dex

checks = {
    "JNI bridge class": "Lcom/umbra/scanner/bridge/UmbraCore;",
    "Go bridge class": "Lcom/umbra/scanner/bridge/GoClean;",
    "gomobile runtime (go.Seq)": "Lgo/Seq;",
    "gomobile bindings pkg": "Lcom/umbra/scanner/goclean/goclean/Goclean;",
    "debug screen": "Lcom/umbra/scanner/ui/screens/DebugScreen;",
    "warp account (identity store)": "Lcom/umbra/scanner/net/WarpAccount;",
}
for name, desc in checks.items():
    ok = has(desc)
    print(f"{'OK ' if ok else 'MISS'} {name}")
    if not ok:
        BAD.append(name)

# native method names must NOT be renamed (JNI resolution is by exact name)
m = re.search(rb"nativeStart", dex)
print("OK " if m else "MISS", "nativeStart symbol")
if not m: BAD.append("nativeStart")
m = re.search(rb"nativeProbeOnce", dex)
print("OK " if m else "MISS", "nativeProbeOnce symbol")
if not m: BAD.append("nativeProbeOnce")

sys.exit(1 if BAD else 0)

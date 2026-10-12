# Keep zxing QR core
-keep class com.google.zxing.** { *; }
-dontwarn java.beans.**
-dontwarn javax.servlet.**

# Coroutines internal
-dontwarn kotlinx.coroutines.**
-keepclassmembers class kotlinx.coroutines.** { volatile <fields>; }

# UMBRA models (kept for reflection-free usage)
-keep class com.umbra.scanner.core.** { *; }

# v4 (tri-lingual rebuild): the Rust JNI bridge — native symbols bind to these
# exact class/method names; renaming breaks System.loadLibrary resolution.
-keep class com.umbra.scanner.bridge.UmbraCore { *; }

# v4: gomobile-generated Go runtime bindings — the .so resolves the generated
# classes by exact name via JNI_OnLoad.
-keep class go.** { *; }
-keep class com.umbra.scanner.goclean.** { *; }
-dontwarn go.**

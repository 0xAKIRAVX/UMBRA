# Keep zxing QR core
-keep class com.google.zxing.** { *; }
-dontwarn java.beans.**
-dontwarn javax.servlet.**

# Coroutines internal
-dontwarn kotlinx.coroutines.**
-keepclassmembers class kotlinx.coroutines.** { volatile <fields>; }

# UMBRA models (kept for reflection-free usage)
-keep class com.umbra.scanner.core.** { *; }

/* UMBRA JNI shim — the ONLY file that talks to the JVM.
 * Rust owns all logic (libumbra_core.a); this shim translates JNI types.
 * The Kotlin class is com.umbra.scanner.bridge.UmbraCore (object).
 */
#include <jni.h>
#include <string.h>

/* Rust FFI surface (see native/umbra-core/src/lib.rs) */
extern const char *umbra_version(void);
extern int umbra_start_scan(const unsigned char *cfg, size_t len);
extern int umbra_poll_events(const unsigned char **out_ptr, size_t *out_len);
extern void umbra_cancel_scan(void);
extern int umbra_scan_running(void);
extern int umbra_probe_once(const char *ip, unsigned short port,
                            const unsigned char *cfg, size_t len,
                            unsigned char *out, size_t cap);
extern int umbra_get_mark(unsigned char *out);
extern void umbra_reset_mark(void);
extern void umbra_load_mark(const unsigned char *mark, size_t len);

#define UMBRA_PKG(func) Java_com_umbra_scanner_bridge_UmbraCore_##func

static jstring safe_version(JNIEnv *env);
static jbyteArray wrap_bytes(JNIEnv *env, const unsigned char *data, size_t len);

JNIEXPORT jstring JNICALL
UMBRA_PKG(nativeVersion)(JNIEnv *env, jclass clazz) {
    (void)clazz;
    const char *v = umbra_version();
    if (v == NULL) return (*env)->NewStringUTF(env, "unknown");
    jstring s = (*env)->NewStringUTF(env, v);
    if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); return safe_version(env); }
    return s;
}

static jstring safe_version(JNIEnv *env) {
    return (*env)->NewStringUTF(env, "UMBRA-RUST-CORE (version unavailable)");
}

JNIEXPORT jint JNICALL
UMBRA_PKG(nativeStart)(JNIEnv *env, jclass clazz, jbyteArray cfg) {
    (void)clazz;
    if (cfg == NULL) return -1;
    jsize len = (*env)->GetArrayLength(env, cfg);
    if (len <= 0) return -1;
    jbyte buf[131072];
    if (len > (jsize)sizeof(buf)) {
        jbyte *heap = (jbyte *)(*env)->GetByteArrayElements(env, cfg, NULL);
        if (heap == NULL) return -1;
        int rc = umbra_start_scan((const unsigned char *)heap, (size_t)len);
        (*env)->ReleaseByteArrayElements(env, cfg, heap, JNI_ABORT);
        return rc;
    }
    (*env)->GetByteArrayRegion(env, cfg, 0, len, buf);
    if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); return -1; }
    return umbra_start_scan((const unsigned char *)buf, (size_t)len);
}

JNIEXPORT jbyteArray JNICALL
UMBRA_PKG(nativePoll)(JNIEnv *env, jclass clazz) {
    (void)clazz;
    const unsigned char *data = NULL;
    size_t len = 0;
    int rc = umbra_poll_events(&data, &len);
    if (rc != 0 || data == NULL) {
        return (*env)->NewByteArray(env, 0);
    }
    return wrap_bytes(env, data, len);
}

JNIEXPORT void JNICALL
UMBRA_PKG(nativeCancel)(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    umbra_cancel_scan();
}

JNIEXPORT jboolean JNICALL
UMBRA_PKG(nativeRunning)(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    return umbra_scan_running() != 0 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jbyteArray JNICALL
UMBRA_PKG(nativeProbeOnce)(JNIEnv *env, jclass clazz, jstring ip, jint port,
                           jbyteArray cfg) {
    (void)clazz;
    if (ip == NULL || cfg == NULL) return NULL;
    const char *ip_c = (*env)->GetStringUTFChars(env, ip, NULL);
    if (ip_c == NULL) return NULL;
    jsize len = (*env)->GetArrayLength(env, cfg);
    jbyte *cfg_buf = (jbyte *)(*env)->GetByteArrayElements(env, cfg, NULL);
    if (cfg_buf == NULL) {
        (*env)->ReleaseStringUTFChars(env, ip, ip_c);
        return NULL;
    }
    /* stack buffer — per-call, thread-safe by construction */
    static const size_t OUT_CAP = 65536;
    unsigned char out[65536];
    int n = umbra_probe_once(ip_c, (unsigned short)port,
                             (const unsigned char *)cfg_buf, (size_t)len,
                             out, OUT_CAP);
    (*env)->ReleaseStringUTFChars(env, ip, ip_c);
    (*env)->ReleaseByteArrayElements(env, cfg, cfg_buf, JNI_ABORT);
    if (n <= 0) {
        jbyteArray empty = (*env)->NewByteArray(env, 0);
        return empty;
    }
    return wrap_bytes(env, out, (size_t)n);
}

JNIEXPORT jbyteArray JNICALL
UMBRA_PKG(nativeGetMark)(JNIEnv *env, jclass clazz) {
    (void)clazz;
    unsigned char mark[12];
    int n = umbra_get_mark(mark);
    if (n <= 0) {
        return (*env)->NewByteArray(env, 0);
    }
    return wrap_bytes(env, mark, (size_t)n);
}

JNIEXPORT void JNICALL
UMBRA_PKG(nativeResetMark)(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    umbra_reset_mark();
}

JNIEXPORT void JNICALL
UMBRA_PKG(nativeLoadMark)(JNIEnv *env, jclass clazz, jbyteArray mark) {
    (void)clazz;
    if (mark == NULL) return;
    jsize len = (*env)->GetArrayLength(env, mark);
    if (len != 12) return;
    jbyte buf[12];
    (*env)->GetByteArrayRegion(env, mark, 0, 12, buf);
    if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); return; }
    umbra_load_mark((const unsigned char *)buf, 12);
}

static jbyteArray wrap_bytes(JNIEnv *env, const unsigned char *data, size_t len) {
    jbyteArray arr = (*env)->NewByteArray(env, (jsize)len);
    if (arr == NULL) return NULL;
    if (len > 0) {
        (*env)->SetByteArrayRegion(env, arr, 0, (jsize)len, (const jbyte *)data);
        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionClear(env);
            return NULL;
        }
    }
    return arr;
}

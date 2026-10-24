package com.umbra.scanner.net

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import kotlin.random.Random

/**
 * Registers a fresh, free WARP account with the Cloudflare API — the same
 * flow BPB-Warp-Scanner uses (warp.go). The resulting WireGuard identity is
 * what makes endpoint validation REAL: endpoints are proven live by a full
 * Noise_IKpsk2 handshake plus data-plane traffic for this identity, not by
 * a meaningless TCP connect.
 */
// v3.4: data class — register() returns upgraded copies via copy(licenseApplied)
// when a WARP+ key is applied; equality/hashCode are never relied upon.
data class WarpAccount(
    /** Clamped X25519 static private key (32 raw bytes). */
    val privateKey: ByteArray,
    /** Static public key (32 raw bytes). */
    val publicKey: ByteArray,
    /** Registration client_id bytes — informational only. v3.5 live testing
     *  proved production WARP servers REJECT packets carrying these bytes in
     *  the WireGuard reserved field, so they are never written into packets
     *  (kept for identity bookkeeping / future API use). */
    val reserved: ByteArray,
    /** Assigned tunnel IPv6 (no prefix length). */
    val v6: String,
    /** Assigned tunnel IPv4 (typically 172.16.0.2). */
    val v4: String,
    /** The WARP peer (responder) static public key — server-side identity. */
    val responderPublicKey: ByteArray,
    /** v3.4: Cloudflare account id — needed to apply a WARP+ license key. */
    val accountId: String? = null,
    /** v3.4: registration bearer token — needed to apply a WARP+ license key. */
    val authToken: String? = null,
    /** v3.4: set (transiently) once a WARP+ license was applied to this identity. */
    val licenseApplied: Boolean = false,
) {
    /** v3.3: JSON round-trip for the disk-backed identity fallback. */
    fun toJson(): String {
        val o = JSONObject()
        o.put("priv", Base64.encodeToString(privateKey, Base64.NO_WRAP))
        o.put("pub", Base64.encodeToString(publicKey, Base64.NO_WRAP))
        o.put("reserved", Base64.encodeToString(reserved, Base64.NO_WRAP))
        o.put("v6", v6)
        o.put("v4", v4)
        o.put("peer", Base64.encodeToString(responderPublicKey, Base64.NO_WRAP))
        // v3.4: account id + token persist so a later WARP+ key can be applied
        // to the reused identity without a fresh registration.
        accountId?.let { o.put("aid", it) }
        authToken?.let { o.put("tok", it) }
        return o.toString()
    }

    companion object {
        fun fromJson(text: String): WarpAccount? = runCatching {
            val o = JSONObject(text)
            fun b(key: String): ByteArray = Base64.decode(o.getString(key), Base64.NO_WRAP)
            WarpAccount(
                privateKey = b("priv"),
                publicKey = b("pub"),
                reserved = b("reserved"),
                v6 = o.optString("v6"),
                v4 = o.optString("v4").ifBlank { "172.16.0.2" },
                responderPublicKey = b("peer"),
                accountId = o.optString("aid").ifBlank { null },
                authToken = o.optString("tok").ifBlank { null },
                // licenseApplied is transient — a fresh process re-applies keys
            )
        }.getOrNull()?.let { acc ->
            // only accept structurally valid identities
            if (acc.privateKey.size == 32 && acc.publicKey.size == 32 &&
                acc.responderPublicKey.size == 32 && acc.v6.isNotBlank()
            ) acc else null
        }
    }
}

object WarpRegistration {

    private const val API_HOST = "api.cloudflareclient.com"
    private const val API_PATH = "/v0a4005/reg"
    private const val USER_AGENT = "insomnia/8.6.1"

    /**
     * v3.6.1 — pinned Cloudflare IPs for the registration fallback. When the
     * api.cloudflareclient.com DOMAIN is unreachable (DNS poisoning, SNI-less
     * filtering) the POST is retried against these literals: the CF edge
     * routes by SNI, so any serving edge IP with SNI/Host = the API hostname
     * reaches the SAME origin, and the certificate still validates for the
     * real hostname. All four verified live (2026-10-10):
     * 104.16.192.82 / 104.16.24.84 are the domain's real addresses;
     * 162.159.192.1 / 188.114.96.1 are WARP-range IPs that serve the API on
     * :443 alongside their WireGuard service.
     */
    private val PINNED_API_IPS = listOf("104.16.192.82", "104.16.24.84", "162.159.192.1", "188.114.96.1")

    /**
     * Registration transport seam — production posts to the domain first and
     * falls back to the pinned SNI-routed IPs; tests inject offline behavior.
     * Throws (never returns null) — the reason rides the exception message.
     * v4.1.1: [defaultApiPoster] is kept beside it so tests can RESTORE the
     * production transport after replacing the seam (object-level seams
     * otherwise leak into later test classes sharing the sandbox).
     */
    internal val defaultApiPoster: suspend (payload: String) -> String =
        { payload -> postRegistration(payload) }

    internal var apiPoster: suspend (payload: String) -> String = defaultApiPoster

    private suspend fun postRegistration(payload: String): String = withContext(Dispatchers.IO) {
        // 1. the domain, as always
        val domainError = runCatching {
            val conn = URL("https://$API_HOST$API_PATH").openConnection() as HttpURLConnection
            try {
                conn.requestMethod = "POST"
                conn.doOutput = true
                conn.setRequestProperty("User-Agent", USER_AGENT)
                conn.setRequestProperty("Content-Type", "application/json")
                conn.connectTimeout = 10_000
                conn.readTimeout = 15_000
                conn.outputStream.use { it.write(payload.toByteArray(Charsets.UTF_8)) }
                val code = conn.responseCode
                if (code !in 200..299) {
                    // a real HTTP answer from the origin — pinned IPs would hit
                    // the SAME origin and get the SAME code; do not fallback.
                    throw java.io.IOException("registration HTTP $code")
                }
                conn.inputStream.bufferedReader().use { it.readText() }
            } finally {
                conn.disconnect()
            }
        }
        domainError.getOrNull()?.let { return@withContext it }

        // 2. domain unreachable at the transport level → pinned SNI-routed IPs.
        //    (An HTTP-level rejection above never reaches this branch.)
        val cause = domainError.exceptionOrNull()
        for (ip in PINNED_API_IPS) {
            val body = runCatching {
                val bytes = com.umbra.scanner.core.IpText.literalToBytes(ip)
                    ?: throw java.io.IOException("bad pinned ip literal $ip")
                ExactIpHttps.postJson(
                    bytes, 443, API_HOST, API_PATH, payload, USER_AGENT,
                    connectTimeoutMs = 4_000, readTimeoutMs = 12_000,
                )
            }.getOrNull()
            if (body != null) return@withContext body
        }
        throw java.io.IOException(
            "$UNREACHABLE_MARKER — domain failed " +
                "(${cause?.javaClass?.simpleName ?: "unknown"}) and every pinned ip failed " +
                "(dns poisoned or cloudflare tcp blocked on this network)",
        )
    }

    /**
     * Identity cache (15 min TTL) — v3.1 fix: auto-tune + the scan itself used
     * to register TWO separate accounts per session; BPB reuses one identity
     * for the whole run, and the API is rate-limited per source IP, so the
     * registered account is now shared until it goes stale.
     */
    private const val CACHE_TTL_MS = 15 * 60 * 1000L

    @Volatile private var cachedAccount: WarpAccount? = null
    @Volatile private var cachedAtMs: Long = 0L

    // v3.3: disk-backed identity store. api.cloudflareclient.com is exactly
    // the kind of endpoint that gets blocked on filtered networks — a fresh
    // registration then fails and WARP scans aborted outright. A WARP
    // identity stays valid server-side for weeks, so the last working one is
    // persisted and reused whenever the API cannot be reached (BPB keeps its
    // identity in warp.json for the same reason).
    @Volatile private var prefs: SharedPreferences? = null

    fun attach(context: Context) {
        // v4.1.1: unconditional — re-attaching with the SAME context is a
        // no-op in production (getSharedPreferences returns the same
        // instance), and Robolectric tests re-attach each method's fresh
        // application so the persisted-identity store always follows the
        // live context.
        prefs = context.getSharedPreferences("warp_identity", Context.MODE_PRIVATE)
    }

    private fun persist(account: WarpAccount) {
        runCatching {
            prefs?.edit()?.putString("identity_v1", account.toJson())?.apply()
        }
    }

    /** v3.6: persists the TAI64N high-water mark next to the identity so a
     * restarted process reusing the identity never presents a timestamp the
     * WARP responder already saw (silent anti-replay drops = "no endpoints
     * found" on API-blocked networks where the disk identity is the only one).
     * v4: the RUST core owns the handshake timestamps now — its mark wins when
     * the native engine is live (the Kotlin mark belongs to the fallback path). */
    fun persistTimestampMark() {
        runCatching {
            val mark = com.umbra.scanner.bridge.UmbraCore.mark()
                ?: WgProtocol.saveMark() ?: return
            prefs?.edit()?.putString("ts_mark_v1",
                Base64.encodeToString(mark, Base64.NO_WRAP))?.apply()
        }
    }

    /** v4: raw persisted mark for restoring into the Rust core at scan start. */
    fun persistedMark(): ByteArray? = runCatching {
        prefs?.getString("ts_mark_v1", null)?.let { b64 ->
            Base64.decode(b64, Base64.NO_WRAP).takeIf { it.size == 12 }
        }
    }.getOrNull()

    private fun loadPersisted(): WarpAccount? {
        val acc = runCatching { prefs?.getString("identity_v1", null) }
            .getOrNull()
            ?.let { WarpAccount.fromJson(it) } ?: return null
        // v3.6: restore the anti-replay mark WITH the identity — they are one
        // logical unit (the mark is what the server remembers for this key).
        runCatching {
            prefs?.getString("ts_mark_v1", null)?.let { b64 ->
                WgProtocol.loadMark(Base64.decode(b64, Base64.NO_WRAP))
            }
        }
        return acc
    }

    // v3.4: the license key applied in THIS process — re-applying the same key
    // to the same identity is pointless, but a DIFFERENT key must be applied.
    @Volatile private var appliedLicenseKey: String? = null

    /** Wipes both caches — used when the server rejects the stored identity. */
    fun clearCache() {
        cachedAccount = null
        cachedAtMs = 0L
        appliedLicenseKey = null
        // v3.6: the mark belongs to the (now dead) identity — drop it too so a
        // fresh key starts from the wall clock instead of a stale future mark.
        WgProtocol.resetMark()
        runCatching {
            prefs?.edit()
                ?.remove("identity_v1")
                ?.remove("ts_mark_v1")
                ?.apply()
        }
    }

    private fun cached(): WarpAccount? {
        val acc = cachedAccount ?: return null
        if (System.currentTimeMillis() - cachedAtMs >= CACHE_TTL_MS) return null
        return acc
    }

    /** Deterministic identity generation, isolated for unit tests. */
    fun newIdentity(random: Random = Random(System.nanoTime())): Pair<ByteArray, ByteArray> {
        val priv = WgCrypto.clampScalar(ByteArray(32).also { random.nextBytes(it) })
        return priv to WgCrypto.x25519Base(priv)
    }

    /** Builds the exact JSON body the Android registration endpoint expects. */
    fun buildPayload(publicKeyB64: String, tosIso: String): String {
        val o = JSONObject()
        o.put("install_id", "")
        o.put("fcm_token", "")
        o.put("tos", tosIso)
        o.put("type", "Android")
        o.put("model", "PC")
        o.put("locale", "en_US")
        o.put("warp_enabled", true)
        o.put("key", publicKeyB64)
        return o.toString()
    }

    fun tosTimestamp(now: Long = System.currentTimeMillis()): String {
        val fmt = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'.000Z'", Locale.US)
        fmt.timeZone = TimeZone.getTimeZone("UTC")
        return fmt.format(Date(now))
    }

    /** Parses the registration response; null when the payload is unusable. */
    fun parseResponse(body: String, privateKey: ByteArray, publicKey: ByteArray): WarpAccount? =
        runCatching {
            val root = JSONObject(body)
            val cfg = root.getJSONObject("config")
            val clientIdB64 = cfg.optString("client_id")
            val v6 = cfg.getJSONObject("interface").getJSONObject("addresses").optString("v6")
            val v4 = cfg.getJSONObject("interface").getJSONObject("addresses").optString("v4")
            val peers = cfg.getJSONArray("peers")
            require(peers.length() > 0 && v6.isNotBlank() && clientIdB64.isNotBlank())
            val reserved = Base64.decode(clientIdB64, Base64.NO_WRAP)
            val peerPub = Base64.decode(peers.getJSONObject(0).optString("public_key"), Base64.NO_WRAP)
            require(reserved.size in 1..8 && peerPub.size == 32)
            WarpAccount(
                privateKey = privateKey,
                publicKey = publicKey,
                reserved = reserved,
                v6 = v6,
                v4 = v4.ifBlank { "172.16.0.2" },
                responderPublicKey = peerPub,
                // v3.4: account id + bearer token — required for WARP+ upgrade
                accountId = root.optString("id").ifBlank { null },
                authToken = root.optString("token").ifBlank { null },
            )
        }.getOrNull()

    /**
     * v3.4: applies a WARP+ license key to a registered account — the wgcf
     * flow (PUT /reg/{id}/account, bearer token, {"license": key}). A free
     * WARP identity upgrades to WARP+ entitlements server-side; the tunnel
     * keys stay the same, so scanning continues with the same account.
     */
    private suspend fun applyLicense(account: WarpAccount, licenseKey: String): Boolean =
        withContext(Dispatchers.IO) {
            val id = account.accountId ?: return@withContext false
            val token = account.authToken ?: return@withContext false
            runCatching {
                val conn = URL("https://$API_HOST$API_PATH/$id/account").openConnection() as HttpURLConnection
                try {
                    conn.requestMethod = "PUT"
                    conn.doOutput = true
                    conn.setRequestProperty("User-Agent", USER_AGENT)
                    conn.setRequestProperty("Content-Type", "application/json")
                    conn.setRequestProperty("Authorization", "Bearer $token")
                    conn.connectTimeout = 10_000
                    conn.readTimeout = 15_000
                    val payload = JSONObject().put("license", licenseKey).toString()
                    conn.outputStream.use { it.write(payload.toByteArray(Charsets.UTF_8)) }
                    conn.responseCode in 200..299
                } finally {
                    conn.disconnect()
                }
            }.getOrDefault(false)
        }

    /** v4.1.1: message prefix postRegistration uses for TRANSPORT-level
     *  unreachable verdicts — register() fast-fails the retry loop on it
     *  (retrying cannot change the network; HTTP-level rejections keep their
     *  backoff retries because rate-limit windows slide). */
    private const val UNREACHABLE_MARKER = "registration api unreachable"

    /**
     * Registers a new account (or reuses the cached identity within its TTL).
     * Falls back to the last persisted identity when the API is unreachable —
     * a dead registration endpoint no longer kills WARP scanning. Throws only
     * when neither a fresh nor a stored identity is available.
     *
     * v3.4: [licenseKey] — a WARP+ key is applied to the account right after
     * registration (fresh OR reused); a rejected key never aborts the scan,
     * the identity simply stays on the free WARP tier.
     *
     * v3.6: [fresh] — bypasses BOTH the in-process cache and the disk fallback
     * and forces a brand-new API registration (used by the pre-flight gate
     * when the current identity fails the seed check). A failure never
     * disturbs the existing caches, so an API-blocked network keeps its
     * persisted identity intact.
     *
     * v4.1.1 (THE frozen-IDENTITY-phase fix): the PERSISTED identity is now
     * the PRIMARY source, consulted BEFORE any network call — BPB's warp.json
     * semantics. The old order (API first, disk only as the last fallback)
     * burned up to 3 × (10 s domain connect + 4 × 4 s pinned connects) ≈
     * 50–80 s of SILENT identity phase on exactly the API-blocked networks
     * this app is built for — even when a perfectly valid identity was
     * already on disk. That is the same "frozen scan" symptom class as
     * v3.5.2/v3.9/v3.10: phase bar stuck on IDENTITY, 0/0 tested, 0.0/s,
     * elapsed ticking. A stale disk identity is self-healed by the engine's
     * witness gate (fresh re-registration + recovery sweep) — exactly the
     * machinery that exists for it — so nothing is lost on healthy networks
     * either, and the API is hit only when there is no stored identity at
     * all, or when the witness explicitly asked for a fresh one. Bonus: the
     * rate limiter is no longer poked with a fresh registration every 15 min
     * on networks where the API does work.
     *
     * v4.1.1 (fast-fail): a TRANSPORT-level unreachable verdict is a property
     * of the network, not of the attempt — the three 700 ms-apart retries
     * exist for HTTP-level rate limiting (fast failures); re-running them
     * against a black-holed API only multiplied the silent wait. Unreachable
     * now aborts the retry loop after ONE attempt.
     */
    suspend fun register(
        licenseKey: String? = null,
        attempts: Int = 3,
        fresh: Boolean = false,
    ): WarpAccount = withContext(Dispatchers.IO) {
        var account: WarpAccount? = if (fresh) null else cached()
        if (account == null && !fresh) {
            // v4.1.1: disk identity FIRST (see the doc above) — an instant
            // start for every scan after the first, on every network. It also
            // enters the in-process TTL cache so auto-tune and a scan in the
            // same session share it without any re-read.
            account = loadPersisted()?.also {
                cachedAccount = it
                cachedAtMs = System.currentTimeMillis()
            }
        }
        var lastError: Exception? = null
        if (account == null) {
            var transportUnreachable = false
            repeat(attempts) { i ->
                if (account != null || transportUnreachable) return@repeat
                try {
                    val (priv, pub) = newIdentity()
                    val pubB64 = Base64.encodeToString(pub, Base64.NO_WRAP)
                    val payload = buildPayload(pubB64, tosTimestamp())
                    // v3.6.1: domain first, pinned SNI-routed IPs when the
                    // domain is DNS-poisoned/filtered — see postRegistration.
                    val body = apiPoster(payload)
                    val fresh2 = parseResponse(body, priv, pub)
                        ?: throw java.io.IOException("unparsable registration payload")
                    account = fresh2
                    cachedAccount = fresh2
                    cachedAtMs = System.currentTimeMillis()
                    persist(fresh2)
                } catch (e: kotlinx.coroutines.CancellationException) {
                    throw e
                } catch (e: Exception) {
                    lastError = e
                    // v4.1.1 fast-fail: retrying cannot heal a black-holed API.
                    // (HTTP-level rejections — rate limits — keep the retries.)
                    if (e.message?.startsWith(UNREACHABLE_MARKER) == true) {
                        transportUnreachable = true
                    }
                }
                // v3.1.1 fix: the API is rate-limited per source IP — three instant
                // back-to-back retries all hit the same limiter window and all fail.
                // A short backoff lets the window slide and the retry actually land.
                if (account == null && !transportUnreachable && i < attempts - 1) delay(700)
            }
            // v3.3 note: the disk fallback USED to happen here — after the full
            // 3-attempt API gauntlet. It now runs before any of it (see above);
            // reaching this point with no account means there was no stored
            // identity either, and register() throws below. [fresh]: never
            // falls back — the caller asked for a brand-new identity or nothing.
        }
        val acc = account ?: throw IllegalStateException(
            "WARP registration failed: ${lastError?.message ?: "unknown"}", lastError)

        // v3.4: WARP+ license application (fresh, cached or persisted identity).
        // The same key is never applied twice in one process; a DIFFERENT key
        // always gets its own PUT. Failure is honest and non-fatal.
        val key = licenseKey?.trim().orEmpty()
        if (key.isNotEmpty() && appliedLicenseKey != key) {
            val ok = try {
                applyLicense(acc, key)
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e // cancellation must never be swallowed by a license retry
            } catch (_: Exception) {
                false
            }
            appliedLicenseKey = if (ok) key else null
            return@withContext acc.copy(licenseApplied = ok)
        }
        acc
    }
}

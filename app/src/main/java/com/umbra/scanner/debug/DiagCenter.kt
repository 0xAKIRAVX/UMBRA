package com.umbra.scanner.debug

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import com.umbra.scanner.core.Candidate
import com.umbra.scanner.core.EndpointPair
import com.umbra.scanner.core.IpGenerator
import com.umbra.scanner.core.IpText
import com.umbra.scanner.core.Presets
import com.umbra.scanner.net.UdpEvidence
import com.umbra.scanner.net.UdpNoiseConfig
import com.umbra.scanner.net.WarpAccount
import com.umbra.scanner.net.WarpProbe
import com.umbra.scanner.net.WarpRegistration
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.withTimeout
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

/**
 * v3.12 — FULL NETWORK ENVIRONMENT DIAGNOSTICS: the "why does every scan
 * say 0 ALIVE" interrogation, run on demand from the Diagnostics tab.
 *
 * The scanner's in-scan honesty features (witness gate, recovery sweep,
 * NTP evidence, VPN hint) each answer ONE question at the moment a scan
 * needs it. Diagnostics runs the complete interrogation deliberately, in
 * order, and turns it into a persistent report:
 *
 *   1. CONNECTIVITY  — is there a network at all? validated? is a system
 *                      VPN tunneling everything? (the #1 silent killer on
 *                      the app's audience networks: a tcp-only proxy VPN
 *                      drops ALL udp — scans die, web works fine)
 *   2. DNS           — does api.cloudflareclient.com resolve (v4+v6)?
 *   3. TCP EGRESS    — can we reach a Cloudflare edge over TCP :443?
 *                      (proves general CF reachability; EDGE scans depend
 *                      on this, WARP does not)
 *   4. UDP EGRESS    — NTP round-trips: Cloudflare-network witness +
 *                      non-Cloudflare control (UdpEvidence — the exact
 *                      probes the zero-result verdict already uses)
 *   5. WARP IDENTITY — silent registration / disk identity (the WG
 *                      handshake is meaningless with a ghost key)
 *   6. WARP WITNESS  — live WG handshakes against the census seeds (v4
 *                      AND v6 twins): the definitive "warp works here"
 *                      proof, with RTT
 *   7. RUNTIME       — device/app context lines for bug reports
 *
 * Every stage streams into [DebugLog] as it runs (the console on the same
 * tab shows the interrogation live), and the final verdict is a decision
 * tree over ALL inputs — pure [verdictOf], unit-tested against every
 * failure class this app has shipped a fix for since v3.5.
 */
object DiagCenter {

    // ------------------------------------------------------------ model --

    enum class DiagState { OK, WARN, FAIL, UNKNOWN }

    data class DiagCheck(
        val id: String,
        val label: String,
        val state: DiagState,
        val detail: String,
    )

    data class DiagReport(
        val checks: List<DiagCheck>,
        val verdict: String,
        val level: DbgLevel,
        val witnessAnswered: Int,
        val witnessTotal: Int,
        val epochMs: Long,
    )

    sealed interface DiagUi {
        data object Idle : DiagUi
        data class Running(val step: String) : DiagUi
        data class Done(val report: DiagReport) : DiagUi
    }

    /** Raw connectivity facts from ConnectivityManager. */
    data class ConnectivityFacts(
        val network: Boolean,
        val validated: Boolean,
        val vpn: Boolean?,
    )

    /** One answering witness endpoint. */
    data class Hit(val ip: String, val port: Int, val rttMs: Double?)

    private val _state = MutableStateFlow<DiagUi>(DiagUi.Idle)
    val state: StateFlow<DiagUi> = _state.asStateFlow()

    // ------------------------------------------------------------- seams --

    @Volatile
    internal var isScanRunning: () -> Boolean = { false }

    @Volatile
    internal var connectivityProbe: () -> ConnectivityFacts? = { null }

    @Volatile
    internal var dnsResolver: suspend (String) -> List<String> =
        { host -> withTimeout(4_000) { resolveHost(host) } }

    @Volatile
    internal var tcpProber: suspend (String, Int) -> Boolean =
        { ip, port -> tcpConnect(ip, port, 2_500) }

    @Volatile
    internal var udpEvidence: suspend (Int) -> UdpEvidence.Evidence? =
        { t -> runCatching { UdpEvidence.gather(t) }.getOrNull() }

    @Volatile
    internal var registrationProvider: suspend () -> WarpAccount? =
        { runCatching { WarpRegistration.register(null, fresh = false) }.getOrNull() }

    @Volatile
    internal var witnessProber: suspend (WarpAccount, List<EndpointPair>, Int) -> List<Hit> =
        { acc, pairs, t -> realWitnessRound(acc, pairs, t) }

    @Volatile
    internal var runtimeInfo: () -> String? = { null }

    /** Wired once from UmbraApp with the app context. */
    fun attach(context: Context) {
        connectivityProbe = {
            runCatching {
                val cm = context.getSystemService(ConnectivityManager::class.java)
                val caps = cm?.activeNetwork?.let { cm.getNetworkCapabilities(it) }
                when {
                    caps == null -> ConnectivityFacts(false, false, null)
                    else -> ConnectivityFacts(
                        network = true,
                        validated = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED),
                        vpn = caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN),
                    )
                }
            }.getOrNull()
        }
        runtimeInfo = {
            runCatching {
                val version = context.packageManager
                    .getPackageInfo(context.packageName, 0).versionName ?: "?"
                "umbra v$version · ${android.os.Build.MANUFACTURER} ${android.os.Build.MODEL} · " +
                    "android ${android.os.Build.VERSION.RELEASE} (api ${android.os.Build.VERSION.SDK_INT})"
            }.getOrDefault(null)
        }
    }

    // -------------------------------------------------------------- run --

    /**
     * Runs the full interrogation. Refuses (returns null) while a scan is
     * running — witness probes and the scan storm would poison each other's
     * RTT statistics exactly like a NETSENSE measurement would.
     */
    suspend fun run(timeoutMs: Int = 2_500): DiagReport? {
        if (isScanRunning()) {
            DebugLog.warn(DebugLog.TAG_DIAG, "diagnostics refused — a scan is running")
            return null
        }
        if (_state.value is DiagUi.Running) return null
        _state.value = DiagUi.Running("starting")
        DebugLog.info(DebugLog.TAG_DIAG, "diagnostics started · full environment interrogation")
        try {
            val report = runChecks(timeoutMs)
            _state.value = DiagUi.Done(report)
            DebugLog.log(report.level, DebugLog.TAG_DIAG, "verdict — ${report.verdict}")
            return report
        } finally {
            if (_state.value is DiagUi.Running) _state.value = DiagUi.Idle
        }
    }

    private suspend fun runChecks(timeoutMs: Int): DiagReport {
        val checks = ArrayList<DiagCheck>()

        // 1. connectivity
        step("connectivity")
        val conn = runCatching { connectivityProbe() }.getOrNull()
        checks += when {
            conn == null -> DiagCheck("connectivity", "CONNECTIVITY", DiagState.UNKNOWN,
                "connectivity manager unavailable on this device")
            !conn.network -> DiagCheck("connectivity", "CONNECTIVITY", DiagState.FAIL,
                "no active network — wi-fi/data off, captive portal or airplane mode")
            !conn.validated -> DiagCheck("connectivity", "CONNECTIVITY", DiagState.WARN,
                "network present but NOT validated — no confirmed internet access")
            conn.vpn == true -> DiagCheck("connectivity", "CONNECTIVITY", DiagState.WARN,
                "network validated · SYSTEM VPN ACTIVE — every socket rides the tunnel")
            else -> DiagCheck("connectivity", "CONNECTIVITY", DiagState.OK,
                "network validated · no vpn detected")
        }
        if (conn?.network == false) {
            // nothing else can run — publish the obvious verdict immediately
            return finish(checks, verdictOf(conn, null, null, null, null, 0, 0), 0, 0)
        }

        // 2. dns
        step("dns")
        val dns = runCatching { dnsResolver("api.cloudflareclient.com") }.getOrDefault(emptyList())
        val dnsV4 = dns.count { !it.contains(':') }
        val dnsV6 = dns.count { it.contains(':') }
        checks += when {
            dns.isEmpty() -> DiagCheck("dns", "DNS RESOLUTION", DiagState.FAIL,
                "api.cloudflareclient.com does not resolve — offline, dns broken or poisoned")
            else -> DiagCheck("dns", "DNS RESOLUTION", DiagState.OK,
                "api.cloudflareclient.com → ${dns.joinToString(" · ")} · v4 $dnsV4 · v6 $dnsV6")
        }

        // 3. tcp egress (to a census seed edge, :443)
        step("tcp")
        val tcp = runCatching { tcpProber(Presets.WARP_SEED_V4.first(), 443) }.getOrDefault(false)
        checks += DiagCheck(
            "tcp", "TCP EGRESS · :443",
            if (tcp) DiagState.OK else DiagState.FAIL,
            if (tcp) {
                "cloudflare edge reachable over tcp (${Presets.WARP_SEED_V4.first()}:443) — " +
                    "edge-mode scanning works"
            } else {
                "cloudflare tcp unreachable — the network cannot reach cloudflare at all " +
                    "(tcp is the baseline; if this fails everything else is moot)"
            },
        )

        // 4. udp egress (NTP witnesses — the exact evidence the scan verdicts use)
        step("udp")
        val udp = runCatching { udpEvidence(timeoutMs) }.getOrNull()
        checks += when {
            udp == null -> DiagCheck("udp", "UDP EGRESS · NTP", DiagState.UNKNOWN,
                "ntp witnesses could not run")
            udp.cloudflareNtp && udp.otherNtp -> DiagCheck("udp", "UDP EGRESS · NTP", DiagState.OK,
                "udp round-trips work — cloudflare ntp + external ntp both answered")
            udp.cloudflareNtp || udp.otherNtp -> DiagCheck("udp", "UDP EGRESS · NTP", DiagState.WARN,
                "partial udp — " + (if (udp.cloudflareNtp) "cloudflare answered, " else "cloudflare silent, ") +
                    (if (udp.otherNtp) "external answered" else "external silent"))
            else -> DiagCheck("udp", "UDP EGRESS · NTP", DiagState.FAIL,
                "NO udp round-trip anywhere — udp egress is blocked on this network " +
                    "(isp, firewall, or a tcp-only vpn tunnel)")
        }

        // 5. warp identity
        step("identity")
        val account = runCatching { registrationProvider() }.getOrNull()
        checks += when {
            account != null -> DiagCheck("identity", "WARP IDENTITY", DiagState.OK,
                "registered key available (reused/cached) · tunnel ${account.v4}")
            else -> DiagCheck("identity", "WARP IDENTITY", DiagState.FAIL,
                "registration unreachable AND no stored identity — wg handshakes are " +
                    "meaningless without one (ghost keys are dropped silently)")
        }

        // 6. warp witness — census seeds v4 + v6 twins, live handshakes
        step("warp")
        val witnessPairs = buildWitnessPairs()
        val witness = if (account == null) emptyList() else {
            runCatching { witnessProber(account, witnessPairs, 2_000) }.getOrDefault(emptyList())
        }
        checks += when {
            account == null -> DiagCheck("warp", "WARP WITNESS", DiagState.UNKNOWN,
                "skipped — no identity to handshake with")
            witness.isEmpty() -> DiagCheck("warp", "WARP WITNESS", DiagState.FAIL,
                "0/${witnessPairs.size} census endpoints answered a live wg handshake — " +
                    "warp udp is filtered on this network")
            else -> {
                val best = witness.mapNotNull { it.rttMs }.minOrNull()
                DiagCheck("warp", "WARP WITNESS", DiagState.OK,
                    "${witness.size}/${witnessPairs.size} answered · best " +
                        // v4.0.1: Locale.US — the default format locale renders
                        // Persian digits (۵ms) on فارسی devices inside this
                        // otherwise-ASCII verdict line.
                        (best?.let { "%.0f ms".format(java.util.Locale.US, it) } ?: "rtt n/a") + " · " +
                        witness.take(3).joinToString(" · ") { "${it.ip}:${it.port}" })
            }
        }

        // 7. runtime context
        step("runtime")
        runtimeInfo()?.let {
            checks += DiagCheck("runtime", "RUNTIME", DiagState.UNKNOWN, it)
        }

        return finish(
            checks,
            verdictOf(conn, dns, tcp, udp, account, witness.size, witnessPairs.size),
            witness.size, witnessPairs.size,
        )
    }

    private fun step(name: String) {
        _state.value = DiagUi.Running(name)
        DebugLog.info(DebugLog.TAG_DIAG, "check · $name")
    }

    private fun finish(
        checks: List<DiagCheck>,
        verdict: Pair<String, DbgLevel>,
        witnessAnswered: Int,
        witnessTotal: Int,
    ): DiagReport = DiagReport(
        checks, verdict.first, verdict.second, witnessAnswered, witnessTotal,
        System.currentTimeMillis(),
    )

    // ---------------------------------------------------- pure verdicts --

    /**
     * The decision tree over all inputs — pure function, unit-tested against
     * every failure class the app has met since v3.5:
     * no-network, VPN-swallowed-UDP, DNS broken, total CF block, UDP block,
     * registration blocked, WARP-filtered-but-UDP-fine, healthy.
     */
    internal fun verdictOf(
        conn: ConnectivityFacts?,
        dns: List<String>?,
        tcp: Boolean?,
        udp: UdpEvidence.Evidence?,
        identity: WarpAccount?,
        witnessAnswered: Int,
        witnessTotal: Int,
    ): Pair<String, DbgLevel> = when {
        conn != null && !conn.network ->
            "NO USABLE NETWORK — wi-fi/data off, captive portal or airplane mode. " +
                "fix connectivity, then re-run diagnostics." to DbgLevel.ERROR
        conn?.vpn == true && udp != null && !udp.cloudflareNtp && !udp.otherNtp ->
            "SYSTEM VPN IS ACTIVE AND UDP IS DEAD INSIDE ITS TUNNEL — a tcp-only proxy " +
                "tunnel (common v2rayng/hiddify setup) silently drops every udp probe. " +
                "disconnect the vpn and re-run diagnostics for a verdict about the real " +
                "network." to DbgLevel.ERROR
        dns != null && dns.isEmpty() ->
            "DNS BROKEN — domains do not resolve (fully offline, or dns poisoned). " +
                "pinned-ip fallbacks in the app may still work, but this is the first " +
                "thing to fix." to DbgLevel.ERROR
        tcp == false ->
            "CLOUDFLARE UNREACHABLE OVER TCP — the baseline transport to cloudflare " +
                "fails on this network. no scanner mode can work here." to DbgLevel.ERROR
        udp != null && !udp.cloudflareNtp && !udp.otherNtp ->
            "UDP EGRESS BLOCKED — tcp works but no udp round-trip anywhere (isp or " +
                "firewall). warp needs udp: endpoint scans cannot work on this network; " +
                "edge (tcp/tls) scans still can." to DbgLevel.ERROR
        udp != null && (!udp.cloudflareNtp || !udp.otherNtp) && witnessAnswered == 0 ->
            "PARTIAL UDP + WARP SILENT — some udp paths answer but no census endpoint " +
                "completed a wg handshake. cloudflare's warp ranges/ports look filtered " +
                "here. try: ipv6, another isp/network, or different ports." to DbgLevel.WARN
        identity == null && witnessAnswered == 0 && udp != null &&
            (udp.cloudflareNtp || udp.otherNtp) ->
            "REGISTRATION BLOCKED — udp witnesses answered, but the warp registration " +
                "api is unreachable and no stored identity exists, so no handshake could " +
                "be tested. endpoint validation needs a registered key; retry on another " +
                "network or later (an identity, once registered, is kept on disk)." to DbgLevel.WARN
        witnessTotal > 0 && witnessAnswered == 0 ->
            "WARP FILTERED ON THIS NETWORK — udp works (ntp answered) and the identity " +
                "is fine, but 0/$witnessTotal census endpoints answered a wg handshake: " +
                "cloudflare's warp ranges/ports are selectively dropped. try: ipv6 " +
                "twins, random ports, another network/isp." to DbgLevel.ERROR
        witnessAnswered > 0 ->
            "WARP PATH PROVEN — $witnessAnswered/$witnessTotal census endpoints answered " +
                "a real wg handshake on this network. scans should work; if a scan still " +
                "returns 0, run the deep endpoint test on a seed (162.159.192.1:2408)." to DbgLevel.INFO
        else ->
            "INCOMPLETE — some checks could not run; re-run diagnostics. " +
                "hardware toggles (airplane/wifi) mid-run can cause this." to DbgLevel.WARN
    }

    // ------------------------------------------------------ witness pool --

    /**
     * Census seeds (v4) + v6 twins of two seeds — the definitive cross-family
     * witness set. Pure.
     */
    internal fun buildWitnessPairs(): List<EndpointPair> {
        val out = ArrayList<EndpointPair>()
        for ((ip, port) in Presets.WARP_SEED_ENDPOINTS) {
            IpText.literalToBytes(ip)?.let { out.add(EndpointPair(Candidate(it), port)) }
        }
        for (ip in Presets.WARP_SEED_V4.take(2)) {
            val v4 = IpText.literalToBytes(ip) ?: continue
            IpGenerator.v6Embedded(Presets.WARP_V6_PREFIX_D0, v4)?.let {
                out.add(EndpointPair(Candidate(it), 2408))
            }
        }
        return out
    }

    // -------------------------------------------------- production probes --

    private suspend fun realWitnessRound(
        account: WarpAccount,
        pairs: List<EndpointPair>,
        budgetMs: Int,
    ): List<Hit> = coroutineScope {
        val dispatcher = Dispatchers.IO.limitedParallelism(pairs.size.coerceIn(4, 16))
        val probe = WarpProbe(
            account,
            noise = UdpNoiseConfig(enabled = true, count = 3),
            dispatcher = dispatcher,
        )
        val hits = ArrayList<Hit>()
        val jobs = pairs.map { pair ->
            launch(dispatcher) {
                val st = runCatching {
                    probe.probe(
                        pair.candidate.bytes, pair.port,
                        attempts = 1, timeoutMs = budgetMs, interAttemptDelayMs = 0,
                    )
                }.getOrNull()
                if (st != null && (st.handshakes > 0 || st.cookieReplies > 0)) {
                    val rtt = st.handshakeLatenciesMs.firstOrNull()
                        ?: st.pingLatenciesMs.firstOrNull()
                    synchronized(hits) {
                        hits.add(Hit(pair.candidate.text, pair.port, rtt))
                    }
                }
            }
        }
        jobs.joinAll()
        hits.sortedBy { it.rttMs ?: Double.MAX_VALUE }
    }

    private suspend fun resolveHost(host: String): List<String> =
        runInterruptible(Dispatchers.IO) {
            runCatching {
                InetAddress.getAllByName(host).mapNotNull { it.hostAddress }
            }.getOrDefault(emptyList())
        }

    private suspend fun tcpConnect(ip: String, port: Int, timeoutMs: Int): Boolean =
        runInterruptible(Dispatchers.IO) {
            runCatching {
                Socket().use { s ->
                    s.connect(InetSocketAddress(ip, port), timeoutMs)
                    true
                }
            }.getOrDefault(false)
        }

    internal fun reset() {
        _state.value = DiagUi.Idle
    }

    /**
     * Test/screenshot hook — injects a finished report (or clears back to
     * Idle) without running any network checks. Never called from
     * production code.
     */
    fun debugInjectReport(report: DiagReport?) {
        _state.value = report?.let { DiagUi.Done(it) } ?: DiagUi.Idle
    }
}

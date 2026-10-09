package com.umbra.scanner.core

object Presets {

    val CF_EDGE_V4: List<String> = listOf(
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "172.64.0.0/13",
        "131.0.72.0/22",
    )

    val CF_EDGE_V6: List<String> = listOf(
        "2400:cb00::/32",
        "2606:4700::/32",
        "2803:f800::/32",
        "2405:b500::/32",
        "2405:8100::/32",
        "2a06:98c0::/29",
        "2c0f:f248::/32",
    )

    /** WARP v4 pool — BPB-Warp-Scanner range set (includes the newer 8.x blocks
     *  that many ISPs have not rate-limited yet). Endpoints on these ranges are
     *  only reported when a real WireGuard handshake answers, so stale or
     *  non-WARP ranges are harmless (they simply never validate). */
    val WARP_V4: List<String> = listOf(
        "162.159.192.0/24",
        "162.159.193.0/24",
        "162.159.195.0/24",
        "162.159.198.0/24",
        "162.159.199.0/24",
        "188.114.96.0/24",
        "188.114.97.0/24",
        "188.114.98.0/24",
        "188.114.99.0/24",
        "8.34.146.0/24",
        "8.39.214.0/24",
        "8.39.204.0/24",
        "8.6.112.0/24",
        "8.35.211.0/24",
        "8.39.125.0/24",
        "8.47.69.0/24",
    )

    val WARP_V6: List<String> = listOf(
        "2606:4700:d0::/48",
        "2606:4700:d1::/48",
    )

    val CF_EDGE_PORTS: List<Int> = listOf(443, 8443, 2053, 2083, 2087, 2096)

    /** Quick-pick ports shown as chips for WARP mode. */
    val WARP_PORTS: List<Int> = listOf(2408, 894, 443, 928, 1843, 500, 1701, 4500)

    /**
     * Full canonical WARP endpoint port list — BPB-Warp-Scanner's verified set
     * plus :443. Endpoints on these ports are validated with a real WireGuard
     * handshake, so a port being open for TCP is no longer a requirement.
     */
    val WARP_PORTS_FULL: List<Int> = listOf(
        500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939,
        942, 943, 945, 946, 955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070,
        1074, 1180, 1387, 1701, 1843, 2371, 2408, 2506, 3138, 3476, 3581, 3854,
        4177, 4198, 4233, 4500, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319,
        8742, 8854, 8886, 443,
    ).sorted()

    /** Seed WARP endpoint IPs used for calibration (DNS-verified live pool).
     *  v3.6.1 refresh (live census 2026-10-10): the old first seed
     *  162.159.192.1 stopped answering WG on :2408 from several PoPs (it
     *  still answers on :894/:928 — kept as the port-diversity third seed),
     *  while 188.114.96.1 and 162.159.192.42 verified live on :2408. Anycast
     *  lands different countries on different Cloudflare PoPs, so no seed is
     *  authoritative — the v3.6.1 gate additionally probes a MINI-STORM of
     *  random pool endpoints and never concludes "blocked" from seeds alone. */
    val WARP_SEED_V4: List<String> = listOf(
        "188.114.96.1",
        "162.159.192.42",
        "162.159.192.1",
    )

    /** v3.6.2: IPv6 WARP seeds — the d0-embedded twins of the v4 seeds.
     *  Iranian mobile carriers frequently filter the v4 WARP ranges while
     *  leaving v6 untouched (v6 filtering is far rarer), so "every v4 probe
     *  silent" is NOT proof the network can't carry WARP — the gate now
     *  probes these before concluding anything. Generated from the v4 list
     *  so the two never drift apart. */
    val WARP_SEED_V6: List<ByteArray> = WARP_SEED_V4.mapNotNull { v4 ->
        IpText.literalToBytes(v4)?.let { IpGenerator.v6Embedded(WARP_V6_PREFIX_D0, it) }
    }

    /** WARP IPv6 endpoints embed the IPv4 pool: 2606:4700:d0::a29f:c001 == 162.159.192.1 */
    const val WARP_V6_PREFIX_D0 = "2606:4700:d0::"
    const val WARP_V6_PREFIX_D1 = "2606:4700:d1::"

    fun warpPortsCount(): Int = WARP_PORTS_FULL.size

    fun cidrsFor(mode: ScanMode, family: NetFamily): List<String> = when (mode) {
        ScanMode.CF_EDGE -> when (family) {
            NetFamily.BOTH -> CF_EDGE_V4 + CF_EDGE_V6
            NetFamily.V4 -> CF_EDGE_V4
            NetFamily.V6 -> CF_EDGE_V6
        }
        ScanMode.WARP, ScanMode.ENDPOINT -> when (family) {
            NetFamily.BOTH -> WARP_V4 + WARP_V6
            NetFamily.V4 -> WARP_V4
            NetFamily.V6 -> WARP_V6
        }
        ScanMode.CUSTOM -> emptyList()
    }

    /** v3.7: 0 is the ENDPOINT-mode sentinel for "draw a random port per
     *  endpoint from the canonical WARP list" (BPB behavior). Every other
     *  mode pins a real port. */
    fun defaultPort(mode: ScanMode): Int = when (mode) {
        ScanMode.WARP -> 2408
        ScanMode.ENDPOINT -> 0
        else -> 443
    }

    fun portsFor(mode: ScanMode): List<Int> = when (mode) {
        ScanMode.WARP, ScanMode.ENDPOINT -> WARP_PORTS
        else -> CF_EDGE_PORTS
    }
}

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

    val WARP_V4: List<String> = listOf(
        "162.159.192.0/24",
        "162.159.193.0/24",
        "162.159.195.0/24",
        "188.114.96.0/23",
        "188.114.98.0/23",
    )

    val WARP_V6: List<String> = listOf(
        "2606:4700:d0::/48",
        "2606:4700:d1::/48",
    )

    val CF_EDGE_PORTS: List<Int> = listOf(443, 8443, 2053, 2083, 2087, 2096)

    /** Quick-pick ports shown as chips for WARP mode. */
    val WARP_PORTS: List<Int> = listOf(2408, 894, 443, 928, 1843, 500, 1701, 4500)

    /**
     * Full canonical WARP endpoint port list (community-verified). TCP on these
     * ports terminates on WARP endpoints; ISPs that block 2408 usually still
     * allow several of these, so the sweep mode probes them all.
     */
    val WARP_PORTS_FULL: List<Int> = listOf(
        500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939,
        943, 945, 946, 955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074,
        1180, 1387, 1701, 1843, 2371, 2408, 2506, 3138, 3476, 3581, 3854, 4177,
        4198, 4233, 443, 4500, 5222, 5228, 5229, 5233, 5277, 5278, 5279, 5280,
        5281, 5282, 5283, 5744, 6178, 6179, 6180, 6181, 6182, 6881, 8086, 8914,
        8938, 9275, 9397, 9424, 9425,
    ).sorted()

    /** Seed WARP endpoint IPs used for calibration (DNS-verified live pool). */
    val WARP_SEED_V4: List<String> = listOf(
        "162.159.192.1",
        "162.159.193.10",
        "188.114.96.1",
    )

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
        ScanMode.WARP -> when (family) {
            NetFamily.BOTH -> WARP_V4 + WARP_V6
            NetFamily.V4 -> WARP_V4
            NetFamily.V6 -> WARP_V6
        }
        ScanMode.CUSTOM -> emptyList()
    }

    fun defaultPort(mode: ScanMode): Int = when (mode) {
        ScanMode.WARP -> 2408
        else -> 443
    }

    fun portsFor(mode: ScanMode): List<Int> = when (mode) {
        ScanMode.WARP -> WARP_PORTS
        else -> CF_EDGE_PORTS
    }
}

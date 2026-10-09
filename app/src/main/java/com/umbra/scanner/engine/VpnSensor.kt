package com.umbra.scanner.engine

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities

/**
 * v3.6.2 — system VPN detector for the WARP pre-flight gate.
 *
 * WHY THIS EXISTS (the live-finding behind this release): on networks where
 * WARP handshakes get zero replies while the registration API (TCP) works
 * perfectly, the classic silent killer is an ACTIVE Android VPN. Every app
 * socket — including our UDP probes — is routed INTO the tunnel; TCP-only
 * proxy tunnels (VLESS/vmess over ws/grpc-tcp, many v2rayNG/Hiddify setups)
 * DROP UDP silently inside the tunnel. The gate then sees "total UDP silence
 * with a fresh identity on every endpoint/port" and honestly reports
 * "warp unreachable on this network" — a verdict that is technically about
 * the TUNNEL, not the real network. The user is left believing the scanner
 * is broken.
 *
 * The sensor makes the situation VISIBLE: the gate logs a warning before
 * probing and appends the VPN hint to any negative verdict, so the fix
 * ("disconnect the VPN and rescan") is stated instead of guessed.
 *
 * Seam design: production wires [attach] from UmbraApp with the app context;
 * JVM unit tests inject [probe] directly. A null return means "unknown"
 * (JVM/Robolectric default) — never treated as active.
 */
object VpnSensor {

    /** Production probe override — tests replace this. Null = unknown. */
    @Volatile
    internal var probe: () -> Boolean? = { null }

    /** Wired once from UmbraApp; safe to call repeatedly. */
    fun attach(context: Context) {
        probe = {
            val cm = context.getSystemService(ConnectivityManager::class.java)
            if (cm == null) {
                null
            } else {
                val caps = cm.activeNetwork?.let { cm.getNetworkCapabilities(it) }
                when {
                    caps == null -> null // no active network reported — unknown
                    else -> caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                }
            }
        }
    }

    /** True/False when known, null when the platform cannot tell. */
    fun active(): Boolean? = runCatching { probe() }.getOrNull()

    /** Log/verdict suffix used by the gate when a VPN is confirmed active. */
    internal fun hint(): String? =
        if (active() == true) {
            " · a system VPN is ACTIVE — all udp probes ride its tunnel and " +
                "tcp-only proxy tunnels drop udp silently. disconnect the vpn and rescan " +
                "for a verdict about the real network"
        } else null
}

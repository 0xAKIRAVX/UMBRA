package com.umbra.scanner

import android.app.Application
import com.umbra.scanner.engine.CrashGuard
import com.umbra.scanner.engine.NetStatusCenter
import com.umbra.scanner.engine.ScanController
import com.umbra.scanner.engine.UpdateCenter
import com.umbra.scanner.engine.VpnSensor
import com.umbra.scanner.engine.WarpGate
import com.umbra.scanner.net.WarpRegistration
import com.umbra.scanner.settings.UmbraSettings

class UmbraApp : Application() {
    lateinit var settings: UmbraSettings
    lateinit var controller: ScanController
    lateinit var updateCenter: UpdateCenter
    lateinit var netStatus: NetStatusCenter

    override fun onCreate() {
        super.onCreate()
        // v3.3.1: FIRST — the crash journal must exist before anything can throw.
        CrashGuard.install(this)
        settings = UmbraSettings(this)
        controller = ScanController(settings)
        updateCenter = UpdateCenter(this, settings)
        netStatus = NetStatusCenter(settings) { controller.isRunning }
        // v3.2: both directions guarded — a scan also refuses to start while
        // NETSENSE is measuring (the reverse check exists above).
        controller.startGate = { netStatus.measuring.value }
        // v3.3: disk-backed WARP identity — survives blocked registration APIs
        WarpRegistration.attach(this)
        // v3.6.2: the pre-flight gate reads the persisted "scan anyway"
        // switch, and the VPN sensor gets a real ConnectivityManager to
        // consult (null on JVM tests — unknown, never "active").
        WarpGate.gateEnabled = { settings.preflightGate.value }
        VpnSensor.attach(this)
    }
}

package com.umbra.scanner

import android.app.Application
import com.umbra.scanner.engine.CrashGuard
import com.umbra.scanner.engine.NetStatusCenter
import com.umbra.scanner.engine.ScanController
import com.umbra.scanner.engine.UpdateCenter
import com.umbra.scanner.engine.VpnSensor
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
        // v3.3: disk-backed WARP identity — survives blocked registration APIs.
        // v3.8: the identity now powers the ENDPOINT scanner (silent internal
        // plumbing — the WARP mode itself is gone).
        WarpRegistration.attach(this)
        // v3.6.2 → v3.8: the VPN sensor still feeds the ENDPOINT zero-result
        // diagnosis (an active VPN silently swallows every UDP probe).
        VpnSensor.attach(this)
    }
}

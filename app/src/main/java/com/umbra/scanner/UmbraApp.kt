package com.umbra.scanner

import android.app.Application
import com.umbra.scanner.engine.NetStatusCenter
import com.umbra.scanner.engine.ScanController
import com.umbra.scanner.engine.UpdateCenter
import com.umbra.scanner.settings.UmbraSettings

class UmbraApp : Application() {
    lateinit var settings: UmbraSettings
    lateinit var controller: ScanController
    lateinit var updateCenter: UpdateCenter
    lateinit var netStatus: NetStatusCenter

    override fun onCreate() {
        super.onCreate()
        settings = UmbraSettings(this)
        controller = ScanController(settings)
        updateCenter = UpdateCenter(this, settings)
        netStatus = NetStatusCenter(settings) { controller.isRunning }
        // v3.2: both directions guarded — a scan also refuses to start while
        // NETSENSE is measuring (the reverse check exists above).
        controller.startGate = { netStatus.measuring.value }
    }
}

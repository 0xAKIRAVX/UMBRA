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
    }
}

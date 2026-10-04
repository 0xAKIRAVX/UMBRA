package com.umbra.scanner

import android.app.Application
import com.umbra.scanner.engine.ScanController
import com.umbra.scanner.engine.UpdateCenter
import com.umbra.scanner.settings.UmbraSettings

class UmbraApp : Application() {
    lateinit var settings: UmbraSettings
    lateinit var controller: ScanController
    lateinit var updateCenter: UpdateCenter

    override fun onCreate() {
        super.onCreate()
        settings = UmbraSettings(this)
        controller = ScanController()
        updateCenter = UpdateCenter(this, settings)
    }
}

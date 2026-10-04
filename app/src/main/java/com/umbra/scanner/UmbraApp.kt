package com.umbra.scanner

import android.app.Application
import com.umbra.scanner.engine.ScanController
import com.umbra.scanner.settings.UmbraSettings

class UmbraApp : Application() {
    lateinit var settings: UmbraSettings
    lateinit var controller: ScanController

    override fun onCreate() {
        super.onCreate()
        settings = UmbraSettings(this)
        controller = ScanController()
    }
}

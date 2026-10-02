package com.clipcast.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.clipcast.service.ClipcastService
import com.clipcast.util.Preferences

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (Intent.ACTION_BOOT_COMPLETED == intent.action) {
            val prefs = Preferences.getInstance(context)
            if (prefs.autostart && prefs.isConfigured()) {
                val serviceIntent = Intent(context, ClipcastService::class.java).apply {
                    action = ClipcastService.ACTION_START
                }
                // minSdk 26: startForegroundService always available.
                context.startForegroundService(serviceIntent)
            }
        }
    }
}
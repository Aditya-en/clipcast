package com.clipcast.ui

import android.app.Activity
import android.os.Bundle
import android.widget.ImageButton
import com.clipcast.R

/**
 * M2 stub: grouped sections with validation land in M3.
 */
class SettingsActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        EdgeToEdge.apply(this, findViewById(android.R.id.content))
        setContentView(R.layout.activity_settings)

        findViewById<ImageButton>(R.id.backButton).setOnClickListener {
            finish()
        }
    }
}

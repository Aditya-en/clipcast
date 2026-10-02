package com.clipcast.ui

import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.content.Intent
import com.clipcast.R

class ClipcastTileService : TileService() {
    override fun onClick() {
        super.onClick()
        val intent = Intent(this, SendActivity::class.java)
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        startActivityAndCollapse(intent)
    }

    override fun onStartListening() {
        super.onStartListening()
        // Reflect the sync state with the same wording as the main screen.
        val running = ServiceStateHolder.last.running
        val tile = qsTile ?: return
        tile.label = if (running) {
            getString(R.string.status_on)
        } else {
            getString(R.string.status_off)
        }
        tile.contentDescription = tile.label
        tile.state = if (running) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.updateTile()
    }

    override fun onTileAdded() {
        super.onTileAdded()
        val tile = qsTile
        tile.state = Tile.STATE_INACTIVE
        tile.updateTile()
    }

    override fun onTileRemoved() {
        super.onTileRemoved()
    }
}

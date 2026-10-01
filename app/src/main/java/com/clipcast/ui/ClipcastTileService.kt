package com.clipcast.ui

import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.content.Intent

class ClipcastTileService : TileService() {
    override fun onClick() {
        super.onClick()
        val intent = Intent(this, SendActivity::class.java)
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        startActivityAndCollapse(intent)
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
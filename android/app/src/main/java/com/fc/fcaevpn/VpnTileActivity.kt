package com.fc.fcaevpn

import android.app.Activity
import android.os.Bundle

/** Android 14 only: the tile cannot start the tunnel service itself. */
class VpnTileActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!VpnCommands.connect(this)) VpnCommands.openApp(this)
        else VpnCommands.recheck(this)
        finish()
    }
}

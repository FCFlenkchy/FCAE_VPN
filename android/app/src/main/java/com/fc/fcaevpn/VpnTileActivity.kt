package com.fc.fcaevpn

import android.app.Activity
import android.os.Bundle

/** Visible trampoline that releases SystemUI's tile binding before commands run. */
class VpnTileActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (intent.getBooleanExtra(EXTRA_DISCONNECT, false)) {
            VpnCommands.disconnect(this)
        } else if (!VpnCommands.connect(this)) {
            VpnCommands.openApp(this)
        } else {
            VpnCommands.recheck(this)
        }
        finish()
    }

    companion object {
        const val EXTRA_DISCONNECT = "disconnect"
    }
}

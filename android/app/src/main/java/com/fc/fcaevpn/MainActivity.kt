package com.fc.fcaevpn

import android.Manifest
import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate

class MainActivity : AppCompatActivity() {
    private var surface: ImGuiSurface? = null
    private var resumed = false
    private var pendingSession: Intent? = null
    private var pendingGeneration = 0L
    @Volatile internal var commandGeneration = 0L
        private set
    private var requestConnect = false
    private var requestGrant = false

    override fun onCreate(state: Bundle?) {
        AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_YES)
        super.onCreate(state)
        window.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE or
            WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN)
        ImGuiBridge.attach(this)
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                if (surface?.handleBack() == true) return
                // Back closes this UI session; Home/Recents merely minimize it.
                // Do not stop the independently owned VPN service.
                finish()
            }
        })
        ImGuiBridge.worker.execute {
            try {
                check(NativeEngine.ensureLoaded()) { NativeEngine.nativeLoadFailure() }
                ImGuiSettingsMigration.migrate(applicationContext)
                NativeEngine.nativeSetNativeLibDir(applicationInfo.nativeLibraryDir)
                NativeEngine.nativeSponsorInitAndroidContext(applicationContext)
                runOnUiThread {
                    if (!isDestroyed && !isFinishing) {
                        surface = ImGuiSurface(this).also { setContentView(it) }
                        if (resumed) surface?.resumeRendering()
                        handleIntent(intent)
                    }
                }
            } catch (error: Exception) {
                runOnUiThread {
                    if (!isDestroyed) AlertDialog.Builder(this).setTitle("Unable to initialize FCAE VPN")
                        .setMessage(error.message).setPositiveButton("Close") { _, _ -> finish() }.show()
                }
            }
        }
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
            != android.content.pm.PackageManager.PERMISSION_GRANTED)
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 2)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIntent(intent)
    }

    private fun handleIntent(intent: Intent) {
        if (intent.getBooleanExtra(EXTRA_DISCONNECT_NOW, false)) {
            intent.removeExtra(EXTRA_DISCONNECT_NOW)
            disconnect()
        }
        requestConnect = requestConnect || intent.getBooleanExtra(EXTRA_TRIGGER_CONNECT, false)
        requestGrant = requestGrant || intent.getBooleanExtra(EXTRA_GRANT_VPN, false)
        intent.removeExtra(EXTRA_TRIGGER_CONNECT)
        intent.removeExtra(EXTRA_GRANT_VPN)
        if (surface == null) return
        if (requestConnect) {
            requestConnect = false
            FCAEVpnService.recalledSession(this)?.let(::connect)
                ?: showError("Choose and save a session before connecting.")
        } else if (requestGrant) {
            requestGrant = false
            VpnService.prepare(this)?.let { startActivityForResult(it, 1) }
        }
    }

    internal fun connect(session: Intent) {
        if (SessionState.snapshot(this).active) return
        pendingGeneration = ++commandGeneration
        pendingSession = Intent(session)
        surface?.enqueue { ImGuiBridge.nativeError("") }
        ProcessExit.cancel()
        val consent = if (session.getIntExtra("mode", 1) == 1) VpnService.prepare(this) else null
        if (consent != null) {
            startActivityForResult(consent, 1)
        } else startPending()
    }

    private fun startPending() {
        val session = pendingSession ?: return
        pendingSession = null
        if (pendingGeneration != commandGeneration) return
        FCAEVpnService.rememberSession(this, session)
        if (!VpnCommands.connect(this)) showError("Android could not start the VPN service.")
    }

    @Deprecated("Uses the existing VPN consent request contract")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 1) {
            if (resultCode == Activity.RESULT_OK) startPending()
            else {
                pendingSession = null
                showError("VPN permission was not granted.")
            }
        }
    }

    private fun disconnect() {
        ++commandGeneration
        pendingSession = null
        SessionState.command(SessionState.Command.DISCONNECT)
        SessionState.markIdle(this)
        val tun = FCAEVpnService.disconnectNow()
        val proxy = ProxyNotification.disconnectNow()
        if (!tun && !proxy) NativeEngine.lifecycleExecutor.execute {
            NativeEngine.nativeStopBegin()
            NativeEngine.nativeStop()
            PsiphonTunnelService.stopForExit(applicationContext)
        }
    }

    internal fun platformCommand(action: String, payload: String) {
        when (action) {
            "disconnect" -> disconnect()
            "pause", "resume" -> {
                val resume = action == "resume"
                SessionState.command(if (resume) SessionState.Command.RESUME else SessionState.Command.PAUSE)
                if (!VpnCommands.dispatch(this, Intent(this, FCAEVpnService::class.java)
                    .setAction(if (resume) FCAEVpnService.ACTION_START else FCAEVpnService.ACTION_STOP)))
                {
                    SessionState.command(SessionState.Command.NONE)
                    SessionState.markPause(this, resume)
                    showError("Android could not ${if (resume) "resume" else "pause"} the VPN.")
                }
            }
            "url" -> try {
                val uri = Uri.parse(payload)
                require(uri.scheme == "https" && (uri.host in setOf("github.com", "t.me") ||
                    payload == "https://accounts.firefox.com/signup" || payload == "https://ur.io/c?bonus=HZ0G13"))
                startActivity(Intent(Intent.ACTION_VIEW, uri))
            } catch (_: Exception) { showError("Could not open the link.") }
            "clipboardRead" -> {
                val manager = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                val value = manager.primaryClip?.getItemAt(0)?.coerceToText(this)?.toString().orEmpty()
                surface?.enqueue { ImGuiBridge.nativeClipboard(value) }
            }
            "clipboard" -> (getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager)
                .setPrimaryClip(ClipData.newPlainText("FCAE VPN", payload))
        }
    }

    internal fun enqueueUiAction(action: () -> Unit) { surface?.enqueue(action) }

    internal fun requestUiFrame() { surface?.requestFrame() }

    internal fun showError(message: String) {
        surface?.enqueue { ImGuiBridge.nativeError(message) }
    }

    override fun onResume() {
        super.onResume()
        resumed = true
        surface?.resumeRendering()
        if (!FCAEVpnService.publishCurrentState()) ProxyNotification.publishCurrentState()
    }
    override fun onPause() {
        resumed = false
        surface?.pauseRendering(closeUi = isFinishing)
        super.onPause()
    }
    override fun onDestroy() {
        ++commandGeneration
        surface?.stopRendering()
        ImGuiBridge.detach(this)
        super.onDestroy()
    }

    companion object {
        const val EXTRA_DISCONNECT_NOW = "com.fc.fcaevpn.DISCONNECT_NOW"
        const val EXTRA_TRIGGER_CONNECT = "com.fc.fcaevpn.TRIGGER_CONNECT"
        const val EXTRA_GRANT_VPN = "com.fc.fcaevpn.GRANT_VPN"
    }
}

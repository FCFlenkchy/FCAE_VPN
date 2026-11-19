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
import android.widget.LinearLayout
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import com.google.android.material.switchmaterial.SwitchMaterial

class MainActivity : AppCompatActivity() {
    private var surface: ImGuiSurface? = null
    private var resumed = false
    private var pendingSession: Intent? = null
    private var pendingGeneration = 0L
    @Volatile internal var commandGeneration = 0L
        private set
    private var importKind = "routes"
    private var requestConnect = false
    private var requestGrant = false

    override fun onCreate(state: Bundle?) {
        AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_YES)
        super.onCreate(state)
        window.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE)
        ImGuiBridge.attach(this)
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
        if (requestCode == 3 && resultCode == Activity.RESULT_OK) {
            val uri = data?.data ?: return
            val kind = importKind
            val app = applicationContext
            ImGuiBridge.worker.execute {
                try {
                    val bytes = app.contentResolver.openInputStream(uri)?.use { input ->
                        val output = java.io.ByteArrayOutputStream()
                        val buffer = ByteArray(8192)
                        while (true) {
                            val count = input.read(buffer)
                            if (count < 0) break
                            require(output.size() + count <= 4 * 1024 * 1024) { "File exceeds 4 MiB" }
                            output.write(buffer, 0, count)
                        }
                        output.toByteArray()
                    } ?: error("Cannot read file")
                    runOnUiThread { surface?.enqueue {
                        ImGuiBridge.nativeImport(kind, bytes.toString(Charsets.UTF_8))
                    } }
                } catch (error: Exception) { ImGuiBridge.reportError("Import failed: ${error.message}") }
            }
        }
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
                require(uri.scheme == "https" && (uri.host in setOf("github.com", "t.me") || payload == "https://accounts.firefox.com/signup"))
                startActivity(Intent(Intent.ACTION_VIEW, uri))
            } catch (_: Exception) { showError("Could not open the link.") }
            "clipboard" -> (getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager)
                .setPrimaryClip(ClipData.newPlainText("FCAE VPN", payload))
            "import" -> {
                importKind = payload
                try {
                    startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT)
                        .addCategory(Intent.CATEGORY_OPENABLE).setType("*/*"), 3)
                } catch (_: Exception) { showError("No document picker is available.") }
            }
            "settings" -> showPlatformSettings()
        }
    }

    private fun showPlatformSettings() {
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            val padding = (20 * resources.displayMetrics.density).toInt()
            setPadding(padding, 0, padding, 0)
        }
        val tile = SwitchMaterial(this).apply { text = "Quick Settings tile" }
        val widgets = SwitchMaterial(this).apply { text = "Home-screen widgets" }
        ExternalControls.bind(this, tile, widgets)
        content.addView(tile)
        content.addView(widgets)
        val prefs = getSharedPreferences("fcae_vpn", MODE_PRIVATE)
        val routing = android.widget.Spinner(this).apply {
            adapter = android.widget.ArrayAdapter(this@MainActivity,
                android.R.layout.simple_spinner_dropdown_item,
                arrayOf("Route all apps", "Only selected apps", "Exclude selected apps"))
            setSelection(prefs.getInt("splitTunnelMode", 0).coerceIn(0, 2))
        }
        content.addView(routing)
        content.addView(android.widget.Button(this).apply {
            text = "Import core configuration"
            setOnClickListener {
                AlertDialog.Builder(this@MainActivity).setTitle("Configuration backend")
                    .setItems(arrayOf("Xray", "sing-box")) { _, backend ->
                        platformCommand("import", "core$backend")
                    }.show()
            }
        })
        content.addView(android.widget.Button(this).apply {
            text = "Select apps"
            setOnClickListener { selectApps() }
        })
        AlertDialog.Builder(this).setTitle("Android controls & app routing").setView(content)
            .setPositiveButton("Save") { _, _ ->
                prefs.edit().putInt("splitTunnelMode", routing.selectedItemPosition).apply()
                Toast.makeText(this, "App routing applies on the next connection.", Toast.LENGTH_SHORT).show()
            }.setNegativeButton("Close", null).show()
    }

    private fun selectApps() {
        ImGuiBridge.worker.execute {
            try {
                val apps = packageManager.getInstalledApplications(0)
                    .filter { it.packageName != packageName }
                    .map { it.packageName to packageManager.getApplicationLabel(it).toString() }
                    .sortedWith(compareBy(String.CASE_INSENSITIVE_ORDER) { it.second })
                runOnUiThread {
                    if (isFinishing || isDestroyed) return@runOnUiThread
                    val prefs = getSharedPreferences("fcae_vpn", MODE_PRIVATE)
                    val selected = prefs.getStringSet("splitTunnelApps", emptySet()).orEmpty().toMutableSet()
                    AlertDialog.Builder(this).setTitle("Apps")
                        .setMultiChoiceItems(apps.map { "${it.second}\n${it.first}" }.toTypedArray(),
                            BooleanArray(apps.size) { apps[it].first in selected }) { _, index, checked ->
                            if (checked) selected.add(apps[index].first) else selected.remove(apps[index].first)
                        }.setPositiveButton("Save") { _, _ ->
                            prefs.edit().putStringSet("splitTunnelApps", selected).apply()
                        }.setNegativeButton("Cancel", null).show()
                }
            } catch (error: Exception) { ImGuiBridge.reportError("Could not list apps: ${error.message}") }
        }
    }

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
        surface?.pauseRendering()
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

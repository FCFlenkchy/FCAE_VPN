package com.fc.fcaevpn

import android.content.Context
import android.content.Intent
import android.os.Handler
import android.os.Looper
import org.json.JSONObject
import java.lang.ref.WeakReference
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

object ImGuiBridge {
    private val main = Handler(Looper.getMainLooper())
    internal val worker = Executors.newSingleThreadExecutor { task ->
        Thread(task, "FCAE-UI-storage").apply { isDaemon = true }
    }
    @Volatile private var activity = WeakReference<MainActivity>(null)
    @Volatile private var application: Context? = null
    private var lastSession = ""
    private val framePosted = AtomicBoolean(false)

    @JvmStatic fun requestFrame() {
        if (framePosted.compareAndSet(false, true)) main.post {
            framePosted.set(false)
            activity.get()?.requestUiFrame()
        }
    }

    fun attach(owner: MainActivity) {
        application = owner.applicationContext
        activity = WeakReference(owner)
    }

    fun detach(owner: MainActivity) {
        if (activity.get() === owner) activity.clear()
    }

    fun postNative(action: () -> Unit) {
        main.post { activity.get()?.enqueueUiAction(action) }
    }

    @JvmStatic fun foldAppQuery(value: String): String = appSearchKey(value)

    @JvmStatic fun dispatch(action: String, payload: String) {
        val app = application ?: return
        if (action in setOf("androidLoad", "androidSave", "appsLoad", "appIcon")) {
            AndroidPlatformSettings.dispatch(app, action, payload)
            return
        }
        if (action == "save" || action == "connect") {
            val generation = activity.get()?.commandGeneration ?: return
            worker.execute {
                try {
                    val value = JSONObject(payload)
                    val session = Intent(app, FCAEVpnService::class.java).setAction(FCAEVpnService.ACTION_START)
                    for (key in value.keys()) {
                        when (val item = value.get(key)) {
                            is Boolean -> session.putExtra(key, item)
                            is Number -> {
                                val number = item.toLong()
                                require(number in Int.MIN_VALUE.toLong()..Int.MAX_VALUE.toLong()) { "Invalid $key" }
                                session.putExtra(key, number.toInt())
                            }
                            is String -> session.putExtra(key, item)
                        }
                    }
                    val chain = value.getJSONArray("chainTransports")
                    session.putExtra("chainTransports", IntArray(chain.length()) { chain.getInt(it) })
                    for (key in arrayOf("configPath", "routesFile")) {
                        val path = session.getStringExtra(key).orEmpty()
                        if (path.isNotEmpty() && !java.io.File(path).isAbsolute)
                            session.putExtra(key, java.io.File(app.filesDir, path).absolutePath)
                    }
                    val validation = validate(session)
                    if (validation.isNotEmpty()) {
                        FCAEVpnService.invalidateRecalledSession(app)
                        if (action == "connect") reportError(validation)
                        return@execute
                    }
                    if (payload != lastSession) {
                        app.getSharedPreferences("fcae_vpn", Context.MODE_PRIVATE).edit()
                            .putString("tunDnsV4", value.getString("tunDnsV4"))
                            .putString("tunDnsV6", value.getString("tunDnsV6"))
                            .putBoolean("tunExcludePrivate", value.getBoolean("tunExcludePrivate"))
                            .apply()
                        FCAEVpnService.rememberSession(app, session)
                        lastSession = payload
                    }
                    if (action == "connect") main.post {
                        activity.get()?.takeIf { it.commandGeneration == generation }?.connect(session)
                    }
                } catch (error: Exception) {
                    reportError("Cannot ${if (action == "connect") "connect" else "save session"}: ${error.message}")
                }
            }
        } else main.post { activity.get()?.platformCommand(action, payload) }
    }

    private fun validate(session: Intent): String {
        if (session.getIntExtra("mode", 1) == 1) {
            if (session.getIntExtra("tunMtu", 1500) !in 1280..9000) return "TUN MTU must be 1280..9000."
            for (key in arrayOf("tunTcpSndbuf", "tunTcpRcvbuf"))
                if (session.getIntExtra(key, 256000) !in 4096..4194304) return "Invalid TCP buffer size."
        }
        return NativeEngine.nativeCheckUpstreamProxy(session.getStringExtra("upstreamProxy").orEmpty())
    }

    fun reportError(message: String) { main.post { activity.get()?.showError(message) } }

    @JvmStatic fun snapshot(): LongArray {
        val app = application ?: return longArrayOf(-1, 1, 0, 0, 0, 0, 0, 0)
        val state = SessionState.snapshot(app)
        val phase = when (state.phase) {
            SessionState.Phase.DISCONNECTED -> if (SessionState.isLive()) -1 else 0
            SessionState.Phase.CONNECTING -> 3
            SessionState.Phase.RECONNECTING -> 6
            SessionState.Phase.CONNECTED, SessionState.Phase.PAUSED -> 4
        }
        return longArrayOf(phase.toLong(), state.mode.toLong(), state.rx, state.tx,
            state.totalRx, state.totalTx, state.rtt.toLong(), if (state.paused) 1 else 0)
    }

    @JvmStatic external fun nativePlatformState(revision: Long, mode: Int, selected: Array<String>, tile: Boolean, widgets: Boolean)
    @JvmStatic external fun nativeApps(packages: Array<String>, labels: Array<String>, search: Array<String>)
    @JvmStatic external fun nativeAppIcon(name: String, pixels: IntArray?)
    @JvmStatic external fun nativeImportRoutes(text: String)
    @JvmStatic external fun nativeSurface(directory: String, density: Float, touchSlop: Float)
    @JvmStatic external fun nativeResize(width: Int, height: Int)
    @JvmStatic external fun nativeFrame(): Int
    @JvmStatic external fun nativePointer(x: Float, y: Float, action: Int, timeMillis: Long, touch: Boolean)
    @JvmStatic external fun nativeWheel(x: Float, y: Float)
    @JvmStatic external fun nativeKey(code: Int, down: Boolean, modifiers: Int)
    @JvmStatic external fun nativeText(value: String)
    @JvmStatic external fun nativeClipboard(value: String)
    @JvmStatic external fun nativeVisibility(visible: Boolean)
    @JvmStatic external fun nativeBack()
    @JvmStatic external fun nativeError(message: String)
}

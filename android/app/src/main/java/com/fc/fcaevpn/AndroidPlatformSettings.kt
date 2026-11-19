package com.fc.fcaevpn

import android.content.Context
import android.graphics.Bitmap
import android.graphics.Canvas
import android.os.Handler
import android.os.Looper
import org.json.JSONObject
import java.util.Locale
import java.util.concurrent.Executors

internal fun appSearchKey(value: String): String = value.trim().lowercase(Locale.ROOT)

/** Android data/permission boundary only; all controls are drawn by ImGui. */
internal object AndroidPlatformSettings {
    private val main = Handler(Looper.getMainLooper())
    private val packages = Executors.newSingleThreadExecutor { task ->
        Thread(task, "FCAE-app-inventory").apply { isDaemon = true }
    }

    fun dispatch(context: Context, action: String, payload: String) {
        when (action) {
            "androidLoad" -> ImGuiBridge.worker.execute {
                publish(context, payload.toLongOrNull() ?: 0)
            }
            "androidSave" -> ImGuiBridge.worker.execute {
                try {
                    val value = JSONObject(payload)
                    val mode = value.getInt("mode")
                    require(mode in 0..2)
                    val apps = value.getJSONArray("apps")
                    val selected = (0 until apps.length()).map { apps.getString(it) }.toSet()
                    context.getSharedPreferences("fcae_vpn", Context.MODE_PRIVATE).edit()
                        .putInt("splitTunnelMode", mode).putStringSet("splitTunnelApps", selected).apply()
                    main.post {
                        try {
                            ExternalControls.setEnabled(context, false, value.getBoolean("tile"))
                            ExternalControls.setEnabled(context, true, value.getBoolean("widgets"))
                        } catch (error: RuntimeException) {
                            ImGuiBridge.reportError("Could not change Android controls: ${error.message}")
                        }
                        publish(context, value.getLong("revision"))
                    }
                } catch (error: Exception) {
                    ImGuiBridge.reportError("Could not save app routing: ${error.message}")
                }
            }
            "appsLoad" -> packages.execute {
                try {
                    val manager = context.packageManager
                    val apps = manager.getInstalledApplications(0).asSequence()
                        .filter { it.packageName != context.packageName }
                        .map { info ->
                            val label = try { manager.getApplicationLabel(info).toString() }
                                catch (_: RuntimeException) { info.packageName }
                            Triple(info.packageName, label, appSearchKey(label))
                        }.sortedWith(compareBy<Triple<String, String, String>> { it.third }.thenBy { it.first })
                        .toList()
                    val names = apps.map { it.first }.toTypedArray()
                    val labels = apps.map { it.second }.toTypedArray()
                    val search = apps.map { "${it.third}\n${appSearchKey(it.first)}" }.toTypedArray()
                    ImGuiBridge.postNative { ImGuiBridge.nativeApps(names, labels, search) }
                } catch (error: Exception) {
                    ImGuiBridge.postNative { ImGuiBridge.nativeApps(emptyArray(), emptyArray(), emptyArray()) }
                    ImGuiBridge.reportError("Could not list apps: ${error.message}")
                }
            }
            "appIcon" -> packages.execute {
                val pixels = try {
                    val manager = context.packageManager
                    val drawable = try { manager.getApplicationIcon(payload) }
                        catch (_: Exception) { manager.defaultActivityIcon }
                    val bitmap = Bitmap.createBitmap(48, 48, Bitmap.Config.ARGB_8888)
                    try {
                        drawable.setBounds(0, 0, 48, 48)
                        drawable.draw(Canvas(bitmap))
                        IntArray(48 * 48).also { bitmap.getPixels(it, 0, 48, 0, 0, 48, 48) }
                    } finally { bitmap.recycle() }
                } catch (_: Exception) { null }
                ImGuiBridge.postNative { ImGuiBridge.nativeAppIcon(payload, pixels) }
            }
        }
    }

    private fun publish(context: Context, revision: Long) {
        val prefs = context.getSharedPreferences("fcae_vpn", Context.MODE_PRIVATE)
        val mode = prefs.getInt("splitTunnelMode", 0).coerceIn(0, 2)
        val selected = prefs.getStringSet("splitTunnelApps", emptySet()).orEmpty().toTypedArray()
        main.post {
            val tile = ExternalControls.enabled(context, false)
            val widgets = ExternalControls.enabled(context, true)
            // Keep the compact and original widget components in sync for old installations.
            try { ExternalControls.setEnabled(context, true, widgets) }
            catch (_: RuntimeException) { }
            ImGuiBridge.postNative { ImGuiBridge.nativePlatformState(revision, mode, selected, tile, widgets) }
        }
    }
}

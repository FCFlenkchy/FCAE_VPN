package com.fc.fcaevpn

import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager

object ExternalControls {
    private fun components(widgets: Boolean): List<Class<*>> = if (widgets)
        listOf(VpnWidgetProvider::class.java, VpnCompactWidgetProvider::class.java)
    else listOf(VpnTileService::class.java)

    fun enabled(context: Context, widgets: Boolean): Boolean =
        context.packageManager.getComponentEnabledSetting(ComponentName(context, components(widgets).first())) ==
            PackageManager.COMPONENT_ENABLED_STATE_ENABLED

    fun setEnabled(context: Context, widgets: Boolean, enabled: Boolean) {
        val manager = context.packageManager
        val names = components(widgets).map { ComponentName(context, it) }
        val previous = names.map { manager.getComponentEnabledSetting(it) }
        val desired = if (enabled) PackageManager.COMPONENT_ENABLED_STATE_ENABLED
            else PackageManager.COMPONENT_ENABLED_STATE_DISABLED
        if (previous.all { it == desired }) return
        try {
            names.forEach { manager.setComponentEnabledSetting(it, desired, PackageManager.DONT_KILL_APP) }
            if (enabled) {
                if (!FCAEVpnService.publishCurrentState()) ProxyNotification.publishCurrentState()
                if (widgets) {
                    VpnWidgetProvider.refreshAfterEnable(context)
                    VpnCompactWidgetProvider.refresh(context)
                } else VpnTileService.refreshAfterEnable(context)
            } else if (widgets) VpnWidgetProvider.cancelEnableRefresh()
            else VpnTileService.cancelEnableRefresh()
        } catch (error: RuntimeException) {
            names.forEachIndexed { index, name ->
                try { manager.setComponentEnabledSetting(name, previous[index], PackageManager.DONT_KILL_APP) }
                catch (_: RuntimeException) { }
            }
            throw error
        }
    }
}

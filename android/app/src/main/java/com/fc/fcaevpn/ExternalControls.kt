package com.fc.fcaevpn

import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import android.widget.Toast
import com.google.android.material.switchmaterial.SwitchMaterial

object ExternalControls {
    fun bind(
        context: Context,
        tileSwitch: SwitchMaterial,
        widgetSwitch: SwitchMaterial
    ) {
        bindComponent(
            context,
            tileSwitch,
            VpnTileService::class.java,
            {
                republishOwnerState()
                VpnTileService.refreshAfterEnable(context)
            },
            VpnTileService::cancelEnableRefresh
        )
        bindComponent(
            context,
            widgetSwitch,
            VpnWidgetProvider::class.java,
            {
                republishOwnerState()
                VpnWidgetProvider.refreshAfterEnable(context)
                VpnCompactWidgetProvider.refresh(context)
            },
            VpnWidgetProvider::cancelEnableRefresh,
            listOf(VpnCompactWidgetProvider::class.java)
        )
    }

    private fun republishOwnerState() {
        if (!FCAEVpnService.publishCurrentState()) {
            ProxyNotification.publishCurrentState()
        }
    }

    private fun bindComponent(
        context: Context,
        control: SwitchMaterial,
        componentClass: Class<*>,
        onEnabled: () -> Unit,
        onDisabled: () -> Unit,
        additionalComponents: List<Class<*>> = emptyList()
    ) {
        val manager = context.packageManager
        val components = (listOf(componentClass) + additionalComponents).map { ComponentName(context, it) }
        val enabled = isEnabled(manager, components.first())
        // Existing installations may already have the original widget enabled.
        for (component in components.drop(1)) {
            if (isEnabled(manager, component) != enabled) {
                try {
                    manager.setComponentEnabledSetting(component,
                        if (enabled) PackageManager.COMPONENT_ENABLED_STATE_ENABLED
                        else PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                        PackageManager.DONT_KILL_APP)
                } catch (_: RuntimeException) { }
            }
        }
        control.isChecked = enabled
        control.setOnCheckedChangeListener { button, checked ->
            val previous = components.map { manager.getComponentEnabledSetting(it) }
            try {
                for (component in components) {
                    manager.setComponentEnabledSetting(component,
                        if (checked) PackageManager.COMPONENT_ENABLED_STATE_ENABLED
                        else PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                        PackageManager.DONT_KILL_APP)
                }
                if (checked) onEnabled() else onDisabled()
            } catch (_: RuntimeException) {
                components.forEachIndexed { index, component ->
                    try { manager.setComponentEnabledSetting(component, previous[index], PackageManager.DONT_KILL_APP) }
                    catch (_: RuntimeException) { }
                }
                button.setOnCheckedChangeListener(null)
                button.isChecked = !checked
                bindComponent(context, button as SwitchMaterial, componentClass,
                    onEnabled, onDisabled, additionalComponents)
                Toast.makeText(context, "Could not change this control", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun isEnabled(manager: PackageManager, component: ComponentName): Boolean =
        manager.getComponentEnabledSetting(component) ==
                PackageManager.COMPONENT_ENABLED_STATE_ENABLED
}

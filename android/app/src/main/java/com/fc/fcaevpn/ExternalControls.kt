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
        bindComponent(context, tileSwitch, VpnTileService::class.java) {
            VpnTileService.publish(context)
        }
        bindComponent(context, widgetSwitch, VpnWidgetProvider::class.java) {
            VpnWidgetProvider.refresh(context)
        }
    }

    private fun bindComponent(
        context: Context,
        control: SwitchMaterial,
        componentClass: Class<*>,
        onEnabled: () -> Unit
    ) {
        val component = ComponentName(context, componentClass)
        control.isChecked = isEnabled(context.packageManager, component)
        control.setOnCheckedChangeListener { button, enabled ->
            try {
                context.packageManager.setComponentEnabledSetting(
                    component,
                    if (enabled) PackageManager.COMPONENT_ENABLED_STATE_ENABLED
                    else PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                    PackageManager.DONT_KILL_APP
                )
                if (enabled) onEnabled()
            } catch (_: RuntimeException) {
                button.setOnCheckedChangeListener(null)
                button.isChecked = !enabled
                bindComponent(context, button as SwitchMaterial, componentClass, onEnabled)
                Toast.makeText(context, "Could not change this control", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun isEnabled(manager: PackageManager, component: ComponentName): Boolean =
        manager.getComponentEnabledSetting(component) ==
                PackageManager.COMPONENT_ENABLED_STATE_ENABLED
}

package com.fc.fcaevpn

import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.RemoteViews

class VpnCompactWidgetProvider : AppWidgetProvider() {
    override fun onUpdate(context: Context, manager: AppWidgetManager, ids: IntArray) {
        render(context, manager, ids, force = true)
    }

    companion object {
        private val main = Handler(Looper.getMainLooper())
        private var lastKey: String? = null
        private var paintContext: Context? = null
        private val paint = Runnable {
            val context = paintContext ?: return@Runnable
            val manager = AppWidgetManager.getInstance(context) ?: return@Runnable
            val ids = manager.getAppWidgetIds(ComponentName(context, VpnCompactWidgetProvider::class.java))
            render(context, manager, ids)
        }

        internal fun invalidatePaint() { lastKey = null }

        @JvmStatic
        fun refresh(context: Context) {
            val app = context.applicationContext
            val manager = AppWidgetManager.getInstance(app) ?: return
            val ids = manager.getAppWidgetIds(ComponentName(app, VpnCompactWidgetProvider::class.java))
            if (ids.isEmpty()) return
            if (Looper.myLooper() == Looper.getMainLooper() && !VpnWidgetProvider.isReceivingTap()) {
                main.removeCallbacks(paint)
                render(app, manager, ids)
            } else {
                paintContext = app
                main.removeCallbacks(paint)
                main.post(paint)
            }
        }

        private fun render(context: Context, manager: AppWidgetManager, ids: IntArray, force: Boolean = false) {
            if (ids.isEmpty()) return
            val active = SessionState.reconciled(context).active
            val revision = WidgetActions.current(context)
            val key = "$active|$revision"
            if (!force && key == lastKey) return
            val views = RemoteViews(context.packageName, R.layout.widget_vpn_compact)
            views.setViewVisibility(R.id.widget_compact_connect, if (active) View.GONE else View.VISIBLE)
            views.setViewVisibility(R.id.widget_compact_disconnect, if (active) View.VISIBLE else View.GONE)
            views.setOnClickPendingIntent(R.id.widget_compact_connect,
                VpnWidgetProvider.connectPending(context, revision))
            views.setOnClickPendingIntent(R.id.widget_compact_disconnect,
                VpnWidgetProvider.disconnectPending(context, revision))
            for (id in ids) manager.updateAppWidget(id, views)
            lastKey = key
        }
    }
}

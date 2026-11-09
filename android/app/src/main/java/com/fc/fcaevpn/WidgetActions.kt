package com.fc.fcaevpn

import android.content.Context
import android.content.Intent
import android.net.Uri
import java.security.SecureRandom

/** A revision identifies the controls a launcher actually displayed. */
object WidgetActions {
    const val EXTRA_REVISION = "com.fc.fcaevpn.WIDGET_REVISION"
    private const val PREFS = "fcae_widget_controls"
    private const val REVISION = "revision"
    private val random = SecureRandom()

    private fun nextRevision(previous: Long): Long {
        var next: Long
        do { next = random.nextLong() and Long.MAX_VALUE } while (next == 0L || next == previous)
        return next
    }

    @JvmStatic
    @Synchronized
    fun current(context: Context): Long {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val existing = prefs.getLong(REVISION, 0L)
        if (existing > 0L) return existing
        val created = nextRevision(existing)
        prefs.edit().putLong(REVISION, created).commit()
        return created
    }

    @JvmStatic
    @Synchronized
    fun invalidate(context: Context) {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        prefs.edit().putLong(REVISION, nextRevision(prefs.getLong(REVISION, 0L))).commit()
    }

    @JvmStatic
    @Synchronized
    fun consume(context: Context, intent: Intent): Boolean {
        val expected = intent.getLongExtra(EXTRA_REVISION, -1L)
        if (expected < 1L || expected != current(context)) return false
        invalidate(context)
        return true
    }

    fun stamp(intent: Intent, revision: Long, command: String): Intent = intent
        .setData(Uri.parse("fcae-widget://control/$revision/$command"))
        .putExtra(EXTRA_REVISION, revision)
}

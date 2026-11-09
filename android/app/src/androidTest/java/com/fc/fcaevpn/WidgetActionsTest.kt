package com.fc.fcaevpn

import android.app.PendingIntent
import android.content.Intent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class WidgetActionsTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    private fun action(revision: Long, command: String = "disconnect") =
        WidgetActions.stamp(Intent("com.fc.fcaevpn.TEST_WIDGET_ACTION"), revision, command)

    @Test
    fun revisionCanOnlyBeConsumedOnce() {
        val old = WidgetActions.current(context)
        assertTrue(WidgetActions.consume(context, action(old)))
        assertFalse(WidgetActions.consume(context, action(old)))
        assertNotEquals(old, WidgetActions.current(context))
    }

    @Test
    fun previousControlCannotActAfterStateChanges() {
        val old = WidgetActions.current(context)
        WidgetActions.invalidate(context)
        val now = WidgetActions.current(context)
        assertFalse(WidgetActions.consume(context, action(old)))
        assertTrue(WidgetActions.consume(context, action(now, "connect")))
    }

    @Test
    fun disconnectInvalidatesAQueuedConnect() {
        SessionState.command(SessionState.Command.NONE)
        SessionState.markIdle(context)
        SessionState.command(SessionState.Command.CONNECT)
        SessionState.markConnecting(context, 1)
        val queued = action(WidgetActions.current(context), "control-connect")
        SessionState.command(SessionState.Command.DISCONNECT)
        SessionState.markIdle(context)
        assertFalse(WidgetActions.consume(context, queued))
        SessionState.command(SessionState.Command.NONE)
    }

    @Test
    fun cancellingExitInvalidatesDelayedExitTicket() {
        val old = ProcessExit.currentTicket()
        ProcessExit.cancel()
        assertFalse(ProcessExit.isCurrentTicket(old))
        assertTrue(ProcessExit.isCurrentTicket(ProcessExit.currentTicket()))
    }

    @Test
    fun revisionsHaveDistinctPendingIntentIdentities() {
        val revision = WidgetActions.current(context) xor 0x4000000000000000L
        val first = VpnWidgetProvider.connectPending(context, revision)
        val same = VpnWidgetProvider.connectPending(context, revision)
        val next = VpnWidgetProvider.connectPending(context, revision xor 0x2000000000000000L)
        try {
            assertEquals(first, same)
            assertNotEquals(first, next)
        } finally {
            first.cancel()
            next.cancel()
        }
    }

    @Test
    fun oneShotPendingIntentRejectsDuplicateSend() {
        val intent = Intent("com.fc.fcaevpn.TEST_WIDGET_ACTION").setPackage(context.packageName)
        val pending = PendingIntent.getBroadcast(context, 19201, intent,
            PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_ONE_SHOT or PendingIntent.FLAG_IMMUTABLE)
        pending.send()
        var cancelled = false
        try {
            pending.send()
        } catch (_: PendingIntent.CanceledException) {
            cancelled = true
        }
        assertTrue(cancelled)
    }
}

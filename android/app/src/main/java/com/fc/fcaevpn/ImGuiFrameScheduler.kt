package com.fc.fcaevpn

/** Fixed 60 FPS target, aligned to display VSYNC; at most one GL frame in flight. */
internal class ImGuiFrameScheduler(private val driver: Driver) {
    interface Driver {
        fun postFrame()
        fun cancelFrame()
        fun postWake(delayMillis: Long)
        fun cancelWake()
        fun render()
    }

    @Volatile var generation = 0L
        private set
    private var running = false
    private var posted = false
    private var inFlight = false
    private var nextFrameNanos = 0L
    private val frameIntervalNanos = 1_000_000_000L / 60

    fun start() {
        if (running) return
        running = true
        ++generation
        inFlight = false
        nextFrameNanos = 0L
        request()
    }

    fun stop() {
        running = false
        ++generation
        posted = false
        inFlight = false
        driver.cancelFrame()
        driver.cancelWake()
    }

    fun request() {
        driver.cancelWake()
        if (running && !posted && !inFlight) {
            posted = true
            driver.postFrame()
        }
    }

    fun onVsync(frameTimeNanos: Long) {
        posted = false
        if (!running) return
        // Arm the following VSYNC now, not after a GL -> main-thread round trip.
        // Slow frames still have only one render in flight.
        posted = true
        driver.postFrame()
        if (inFlight || frameTimeNanos + 500_000L < nextFrameNanos) return
        // Preserve phase on 90/120Hz screens instead of running at panel rate.
        if (nextFrameNanos == 0L || frameTimeNanos - nextFrameNanos > frameIntervalNanos)
            nextFrameNanos = frameTimeNanos
        nextFrameNanos += frameIntervalNanos
        inFlight = true
        driver.render()
    }

    fun isCurrent(epoch: Long): Boolean = running && generation == epoch

    fun rendered(epoch: Long) {
        if (!isCurrent(epoch)) return
        inFlight = false
        // Continuous visible 60 FPS; lifecycle stop() cancels callbacks.
        request()
    }
}

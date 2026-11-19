package com.fc.fcaevpn

/** Main-thread frame pacing; input wakes the next VSYNC, never an idle timer. */
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
    private var dirty = false

    fun start() {
        if (running) return
        running = true
        ++generation
        inFlight = false
        request()
    }

    fun stop() {
        running = false
        ++generation
        posted = false
        inFlight = false
        dirty = false
        driver.cancelFrame()
        driver.cancelWake()
    }

    fun request() {
        dirty = true
        driver.cancelWake()
        if (running && !posted && !inFlight) {
            posted = true
            driver.postFrame()
        }
    }

    fun onVsync() {
        posted = false
        if (!running || inFlight) return
        inFlight = true
        dirty = false
        driver.render()
    }

    fun isCurrent(epoch: Long): Boolean = running && generation == epoch

    fun rendered(epoch: Long, delayMillis: Int) {
        if (!isCurrent(epoch)) return
        inFlight = false
        if (dirty || delayMillis <= 0) request()
        else if (!posted) driver.postWake(delayMillis.toLong().coerceAtMost(250))
    }
}

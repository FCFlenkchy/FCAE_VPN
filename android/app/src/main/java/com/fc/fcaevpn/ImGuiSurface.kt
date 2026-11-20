package com.fc.fcaevpn

import android.content.ClipboardManager
import android.content.Context
import android.opengl.GLSurfaceView
import android.os.Handler
import android.os.Looper
import android.text.Editable
import android.text.InputType
import android.text.SpannableStringBuilder
import android.view.Choreographer
import android.view.InputDevice
import android.view.ViewConfiguration
import android.view.KeyEvent
import android.view.MotionEvent
import android.view.inputmethod.BaseInputConnection
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputConnection
import android.view.inputmethod.InputMethodManager
import javax.microedition.khronos.egl.EGLConfig
import javax.microedition.khronos.opengles.GL10

class ImGuiSurface(context: Context) : GLSurfaceView(context), GLSurfaceView.Renderer {
    private val main = Handler(Looper.getMainLooper())
    private val choreographer = Choreographer.getInstance()
    private val pending = ArrayDeque<() -> Unit>()
    @Volatile private var acceptingEvents = false
    private var nativeReady = false // GL-thread owned
    private var freshUiSession = true // New View, not an EGL resume.
    private var renderingResumed = false
    private var keyboard = false
    private var popupOpen = false
    private var backHandled = false
    private var activePointer = MotionEvent.INVALID_POINTER_ID
    private val frameCallback: Choreographer.FrameCallback = Choreographer.FrameCallback { frames.onVsync(it) }
    private val repaint = Runnable { frames.request() }
    private val frames: ImGuiFrameScheduler = ImGuiFrameScheduler(object : ImGuiFrameScheduler.Driver {
        override fun postFrame() { choreographer.postFrameCallback(frameCallback) }
        override fun cancelFrame() { choreographer.removeFrameCallback(frameCallback) }
        override fun postWake(delayMillis: Long) {
            main.removeCallbacks(repaint)
            main.postDelayed(repaint, delayMillis)
        }
        override fun cancelWake() { main.removeCallbacks(repaint) }
        override fun render() { requestRender() }
    })

    init {
        setEGLContextClientVersion(3)
        preserveEGLContextOnPause = false
        setRenderer(this)
        renderMode = RENDERMODE_WHEN_DIRTY
        isFocusable = true
        isFocusableInTouchMode = true
        requestFocus()
    }

    fun requestFrame() { frames.request() }

    fun enqueue(action: () -> Unit) {
        synchronized(pending) {
            if (!acceptingEvents) return
            pending.addLast(action)
        }
        frames.request()
    }

    fun resumeRendering() {
        if (renderingResumed) return
        renderingResumed = true
        ImGuiBridge.invalidateView()
        acceptingEvents = true
        onResume()
        frames.start()
        val manager = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val value = manager.primaryClip?.getItemAt(0)?.coerceToText(context)?.toString().orEmpty()
        enqueue {
            ImGuiBridge.nativeClipboard(value)
            ImGuiBridge.nativeVisibility(true)
        }
    }

    fun pauseRendering(closeUi: Boolean = false) {
        if (!renderingResumed) return
        renderingResumed = false
        ImGuiBridge.invalidateView()
        acceptingEvents = false
        frames.stop()
        activePointer = MotionEvent.INVALID_POINTER_ID
        val events = synchronized(pending) { pending.toList().also { pending.clear() } }
        queueEvent {
            events.forEach { it() }
            ImGuiBridge.nativeVisibility(false)
            if (closeUi) ImGuiBridge.nativeRelease() else ImGuiBridge.nativeSuspend()
            nativeReady = false
        }
        // GLSurfaceView drains queued events before acknowledging pause.
        // Release GPU resources before EGL is discarded, retaining UI state.
        onPause()
        keyboard = false
        (context.getSystemService(Context.INPUT_METHOD_SERVICE) as InputMethodManager)
            .hideSoftInputFromWindow(windowToken, 0)
    }

    fun stopRendering() {
        pauseRendering(closeUi = true)
        queueEvent {
            ImGuiBridge.nativeRelease()
            nativeReady = false
        }
        acceptingEvents = false
        frames.stop()
        synchronized(pending) { pending.clear() }
        main.removeCallbacksAndMessages(null)
    }

    private fun ensureNative() {
        if (nativeReady) return
        if (freshUiSession) {
            // A service can keep the process alive after the previous Activity
            // was removed. Never reuse that Activity's native navigation state.
            // Do this on the new GL thread, before creating the new UI context.
            ImGuiBridge.nativeRelease()
            freshUiSession = false
        }
        ImGuiBridge.nativeSurface(context.filesDir.absolutePath, resources.displayMetrics.density,
            ViewConfiguration.get(context).scaledTouchSlop.toFloat())
        ImGuiBridge.nativeResize(width.coerceAtLeast(1), height.coerceAtLeast(1))
        nativeReady = true
    }

    override fun onSurfaceCreated(gl: GL10?, config: EGLConfig?) {
        nativeReady = false
        ensureNative()
    }
    override fun onSurfaceChanged(gl: GL10?, width: Int, height: Int) {
        ImGuiBridge.nativeResize(width, height)
        main.post { frames.request() }
    }
    override fun onDrawFrame(gl: GL10?) {
        if (!acceptingEvents) return
        ensureNative()
        val epoch = frames.generation
        val events = synchronized(pending) { pending.toList().also { pending.clear() } }
        events.forEach { it() }
        val result = ImGuiBridge.nativeFrame()
        main.post {
            if (!frames.isCurrent(epoch)) return@post
            popupOpen = result and 0x20000 != 0
            val wantsKeyboard = result and 0x10000 != 0
            if (wantsKeyboard != keyboard) {
                keyboard = wantsKeyboard
                val input = context.getSystemService(Context.INPUT_METHOD_SERVICE) as InputMethodManager
                if (keyboard) {
                    requestFocus()
                    input.restartInput(this)
                    input.showSoftInput(this, InputMethodManager.SHOW_IMPLICIT)
                } else input.hideSoftInputFromWindow(windowToken, 0)
            }
            frames.rendered(epoch)
        }
    }

    override fun onTouchEvent(event: MotionEvent): Boolean {
        val touch = !event.isFromSource(InputDevice.SOURCE_MOUSE)
        val action = event.actionMasked
        if (action == MotionEvent.ACTION_DOWN) {
            requestFocus()
            parent?.requestDisallowInterceptTouchEvent(true)
            activePointer = event.getPointerId(0)
        }
        // A second finger cancels, rather than releasing the first finger over
        // an unrelated control or jumping to another pointer's coordinates.
        if (action == MotionEvent.ACTION_POINTER_DOWN || action == MotionEvent.ACTION_CANCEL) {
            cancelPointer(event.eventTime, touch)
            return true
        }
        val index = event.findPointerIndex(activePointer)
        if (index < 0) return true
        if (action == MotionEvent.ACTION_DOWN || action == MotionEvent.ACTION_MOVE || action == MotionEvent.ACTION_UP) {
            val x = event.getX(index)
            val y = event.getY(index)
            val time = event.eventTime
            enqueue { ImGuiBridge.nativePointer(x, y, action, time, touch) }
            if (action == MotionEvent.ACTION_UP) {
                activePointer = MotionEvent.INVALID_POINTER_ID
                parent?.requestDisallowInterceptTouchEvent(false)
                performClick()
            }
        } else if (action == MotionEvent.ACTION_POINTER_UP && event.getPointerId(event.actionIndex) == activePointer) {
            cancelPointer(event.eventTime, touch)
        }
        return true
    }

    private fun cancelPointer(time: Long, touch: Boolean) {
        if (activePointer != MotionEvent.INVALID_POINTER_ID)
            enqueue { ImGuiBridge.nativePointer(0f, 0f, MotionEvent.ACTION_CANCEL, time, touch) }
        activePointer = MotionEvent.INVALID_POINTER_ID
        parent?.requestDisallowInterceptTouchEvent(false)
    }

    override fun performClick(): Boolean {
        super.performClick()
        return true
    }

    override fun onGenericMotionEvent(event: MotionEvent): Boolean {
        if (event.actionMasked == MotionEvent.ACTION_SCROLL || event.actionMasked == MotionEvent.ACTION_HOVER_MOVE) {
            val px = event.x
            val py = event.y
            val time = event.eventTime
            enqueue { ImGuiBridge.nativePointer(px, py, MotionEvent.ACTION_MOVE, time, false) }
            if (event.actionMasked == MotionEvent.ACTION_HOVER_MOVE) return true
            val x = event.getAxisValue(MotionEvent.AXIS_HSCROLL)
            val y = event.getAxisValue(MotionEvent.AXIS_VSCROLL)
            enqueue { ImGuiBridge.nativeWheel(x, y) }
            return true
        }
        return super.onGenericMotionEvent(event)
    }

    fun handleBack(): Boolean {
        if (keyboard) {
            enqueue {
                ImGuiBridge.nativeKey(KeyEvent.KEYCODE_ESCAPE, true, 0)
                ImGuiBridge.nativeKey(KeyEvent.KEYCODE_ESCAPE, false, 0)
            }
            return true
        }
        if (!popupOpen) return false
        enqueue { ImGuiBridge.nativeBack() }
        return true
    }

    override fun dispatchKeyEvent(event: KeyEvent): Boolean {
        if (event.keyCode == KeyEvent.KEYCODE_BACK) {
            if (event.action == KeyEvent.ACTION_DOWN) backHandled = handleBack()
            if (!backHandled) return super.dispatchKeyEvent(event)
            if (event.action == KeyEvent.ACTION_UP) backHandled = false
            return true
        }
        if (event.action != KeyEvent.ACTION_DOWN && event.action != KeyEvent.ACTION_UP)
            return super.dispatchKeyEvent(event)
        // Do not consume every hardware key: Android must retain volume,
        // media, power, camera and other system/default actions on both edges.
        // Only text and keys actually understood by our ImGui bridge belong here.
        val code = event.keyCode
        val navigationOrModifier = when (code) {
            KeyEvent.KEYCODE_DPAD_UP, KeyEvent.KEYCODE_DPAD_DOWN,
            KeyEvent.KEYCODE_DPAD_LEFT, KeyEvent.KEYCODE_DPAD_RIGHT,
            KeyEvent.KEYCODE_TAB, KeyEvent.KEYCODE_SPACE, KeyEvent.KEYCODE_ENTER,
            KeyEvent.KEYCODE_DEL, KeyEvent.KEYCODE_FORWARD_DEL,
            KeyEvent.KEYCODE_PAGE_UP, KeyEvent.KEYCODE_PAGE_DOWN,
            KeyEvent.KEYCODE_ESCAPE, KeyEvent.KEYCODE_MOVE_HOME, KeyEvent.KEYCODE_MOVE_END,
            KeyEvent.KEYCODE_CTRL_LEFT, KeyEvent.KEYCODE_CTRL_RIGHT,
            KeyEvent.KEYCODE_SHIFT_LEFT, KeyEvent.KEYCODE_SHIFT_RIGHT,
            KeyEvent.KEYCODE_ALT_LEFT, KeyEvent.KEYCODE_ALT_RIGHT,
            KeyEvent.KEYCODE_META_LEFT, KeyEvent.KEYCODE_META_RIGHT -> true
            else -> false
        }
        if (event.isSystem || (!event.isPrintingKey && !navigationOrModifier))
            return super.dispatchKeyEvent(event)
        if (!acceptingEvents) return super.dispatchKeyEvent(event)
        val down = event.action == KeyEvent.ACTION_DOWN
        val meta = event.metaState
        val unicode = if (down && !event.isCtrlPressed && !event.isMetaPressed) event.unicodeChar else 0
        enqueue {
            ImGuiBridge.nativeKey(code, down, meta)
            if (unicode >= 32 && unicode != 127 && unicode and android.view.KeyCharacterMap.COMBINING_ACCENT == 0)
                ImGuiBridge.nativeText(String(Character.toChars(unicode)))
        }
        return true
    }

    override fun onCheckIsTextEditor(): Boolean = keyboard

    override fun onCreateInputConnection(info: EditorInfo): InputConnection? {
        if (!keyboard) return null
        info.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or
            InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        info.imeOptions = EditorInfo.IME_FLAG_NO_EXTRACT_UI or EditorInfo.IME_FLAG_NO_FULLSCREEN
        return object : BaseInputConnection(this, true) {
            private val buffer = SpannableStringBuilder()
            override fun getEditable(): Editable = buffer
            override fun commitText(text: CharSequence?, newCursorPosition: Int): Boolean {
                val value = text?.toString().orEmpty()
                buffer.clear()
                enqueue { ImGuiBridge.nativeText(value) }
                return true
            }
            override fun finishComposingText(): Boolean {
                val value = buffer.toString()
                buffer.clear()
                if (value.isNotEmpty()) enqueue { ImGuiBridge.nativeText(value) }
                return super.finishComposingText()
            }
            override fun deleteSurroundingText(beforeLength: Int, afterLength: Int): Boolean {
                if (buffer.isNotEmpty()) return super.deleteSurroundingText(beforeLength, afterLength)
                repeat(beforeLength.coerceIn(0, 128)) { sendKey(KeyEvent.KEYCODE_DEL) }
                repeat(afterLength.coerceIn(0, 128)) { sendKey(KeyEvent.KEYCODE_FORWARD_DEL) }
                return true
            }
            override fun sendKeyEvent(event: KeyEvent): Boolean = this@ImGuiSurface.dispatchKeyEvent(event)
            override fun performEditorAction(editorAction: Int): Boolean {
                sendKey(KeyEvent.KEYCODE_ENTER)
                return true
            }
            override fun performContextMenuAction(id: Int): Boolean {
                if (id == android.R.id.paste) {
                    val manager = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                    return commitText(manager.primaryClip?.getItemAt(0)?.coerceToText(context), 1)
                }
                val code = when (id) {
                    android.R.id.selectAll -> KeyEvent.KEYCODE_A
                    android.R.id.copy -> KeyEvent.KEYCODE_C
                    android.R.id.cut -> KeyEvent.KEYCODE_X
                    else -> return false
                }
                enqueue {
                    ImGuiBridge.nativeKey(code, true, KeyEvent.META_CTRL_ON)
                    ImGuiBridge.nativeKey(code, false, 0)
                }
                return true
            }
            private fun sendKey(code: Int) {
                enqueue {
                    ImGuiBridge.nativeKey(code, true, 0)
                    ImGuiBridge.nativeKey(code, false, 0)
                }
            }
        }
    }
}

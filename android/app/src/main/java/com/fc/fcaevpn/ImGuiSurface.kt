package com.fc.fcaevpn

import android.content.ClipboardManager
import android.content.Context
import android.opengl.GLSurfaceView
import android.os.Handler
import android.os.Looper
import android.text.Editable
import android.text.InputType
import android.text.SpannableStringBuilder
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
    @Volatile private var running = false
    private var keyboard = false
    private var lastScrollY = 0f
    private val repaint = Runnable { if (running) requestRender() }

    init {
        setEGLContextClientVersion(3)
        preserveEGLContextOnPause = true
        setRenderer(this)
        renderMode = RENDERMODE_WHEN_DIRTY
        isFocusable = true
        isFocusableInTouchMode = true
        requestFocus()
    }

    fun enqueue(action: () -> Unit) {
        queueEvent { action() }
        requestRender()
    }

    fun resumeRendering() {
        running = true
        onResume()
        val manager = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val value = manager.primaryClip?.getItemAt(0)?.coerceToText(context)?.toString().orEmpty()
        enqueue {
            ImGuiBridge.nativeClipboard(value)
            ImGuiBridge.nativeVisibility(true)
        }
    }

    fun pauseRendering() {
        running = false
        main.removeCallbacks(repaint)
        queueEvent { ImGuiBridge.nativeVisibility(false) }
        onPause()
    }

    fun stopRendering() {
        running = false
        main.removeCallbacksAndMessages(null)
    }

    override fun onSurfaceCreated(gl: GL10?, config: EGLConfig?) {
        ImGuiBridge.nativeSurface(context.filesDir.absolutePath, resources.displayMetrics.density)
    }
    override fun onSurfaceChanged(gl: GL10?, width: Int, height: Int) {
        ImGuiBridge.nativeResize(width, height)
    }
    override fun onDrawFrame(gl: GL10?) {
        val result = ImGuiBridge.nativeFrame()
        main.post {
            if (!running) return@post
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
            main.removeCallbacks(repaint)
            main.postDelayed(repaint, (result and 0xffff).coerceIn(16, 1000).toLong())
        }
    }

    override fun onTouchEvent(event: MotionEvent): Boolean {
        requestFocus()
        val x = event.x
        val y = event.y
        val action = event.actionMasked
        if (event.pointerCount >= 2) {
            if (action == MotionEvent.ACTION_MOVE) {
                val delta = (y - lastScrollY) / (resources.displayMetrics.density * 48f)
                enqueue { ImGuiBridge.nativeWheel(0f, delta) }
            } else enqueue { ImGuiBridge.nativePointer(x, y, MotionEvent.ACTION_CANCEL) }
        } else if (action == MotionEvent.ACTION_DOWN || action == MotionEvent.ACTION_MOVE ||
            action == MotionEvent.ACTION_UP || action == MotionEvent.ACTION_CANCEL) {
            enqueue { ImGuiBridge.nativePointer(x, y, action) }
        }
        lastScrollY = y
        return true
    }

    override fun onGenericMotionEvent(event: MotionEvent): Boolean {
        if (event.actionMasked == MotionEvent.ACTION_SCROLL) {
            val x = event.getAxisValue(MotionEvent.AXIS_HSCROLL)
            val y = event.getAxisValue(MotionEvent.AXIS_VSCROLL)
            enqueue { ImGuiBridge.nativeWheel(x, y) }
            return true
        }
        return super.onGenericMotionEvent(event)
    }

    override fun dispatchKeyEvent(event: KeyEvent): Boolean {
        if (event.keyCode == KeyEvent.KEYCODE_BACK) {
            if (!keyboard) return super.dispatchKeyEvent(event)
            if (event.action == KeyEvent.ACTION_DOWN)
                enqueue { ImGuiBridge.nativeKey(KeyEvent.KEYCODE_ESCAPE, true, 0) }
            else enqueue { ImGuiBridge.nativeKey(KeyEvent.KEYCODE_ESCAPE, false, 0) }
            return true
        }
        if (event.action != KeyEvent.ACTION_DOWN && event.action != KeyEvent.ACTION_UP)
            return super.dispatchKeyEvent(event)
        val down = event.action == KeyEvent.ACTION_DOWN
        val code = event.keyCode
        val meta = event.metaState
        val unicode = if (down && !event.isCtrlPressed && !event.isMetaPressed) event.unicodeChar else 0
        enqueue {
            ImGuiBridge.nativeKey(code, down, meta)
            if (unicode > 0 && unicode and android.view.KeyCharacterMap.COMBINING_ACCENT == 0)
                ImGuiBridge.nativeText(String(Character.toChars(unicode)))
        }
        return true
    }

    override fun onCheckIsTextEditor(): Boolean = true

    override fun onCreateInputConnection(info: EditorInfo): InputConnection {
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
            override fun sendKeyEvent(event: KeyEvent): Boolean = dispatchKeyEvent(event)
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

// FCAE VPN — Android EGL/GLES3 ImGui frontend + touch routing
#include <jni.h>
#include <EGL/egl.h>
#include <GLES3/gl3.h>
#include <android/log.h>
#include <android_native_app_glue.h>
#include <android/native_window.h>

#include "imgui.h"
#include "imgui_impl_android.h"
#include "imgui_impl_opengl3.h"

#include "ui_render.h"

#define LOG_TAG "FCAE_VPN"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

struct AndroidAppData {
    struct android_app* app;
    EGLDisplay display;
    EGLSurface surface;
    EGLContext context;
    int32_t width;
    int32_t height;
    bool initialized;
    bool focused;
};

static int engine_init_display(AndroidAppData* data) {
    EGLDisplay display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
    eglInitialize(display, nullptr, nullptr);

    const EGLint attribs[] = {
        EGL_SURFACE_TYPE, EGL_WINDOW_BIT,
        EGL_BLUE_SIZE, 8,
        EGL_GREEN_SIZE, 8,
        EGL_RED_SIZE, 8,
        EGL_DEPTH_SIZE, 24,
        EGL_RENDERABLE_TYPE, EGL_OPENGL_ES3_BIT,
        EGL_NONE
    };

    EGLint numConfigs;
    EGLConfig config;
    eglChooseConfig(display, attribs, &config, 1, &numConfigs);

    EGLint format;
    eglGetConfigAttrib(display, config, EGL_NATIVE_VISUAL_ID, &format);
    ANativeWindow_setBuffersGeometry(data->app->window, 0, 0, format);

    EGLSurface surface = eglCreateWindowSurface(display, config, data->app->window, nullptr);

    const EGLint context_attribs[] = { EGL_CONTEXT_CLIENT_VERSION, 3, EGL_NONE };
    EGLContext context = eglCreateContext(display, config, EGL_NO_CONTEXT, context_attribs);

    eglMakeCurrent(display, surface, surface, context);

    data->display = display;
    data->surface = surface;
    data->context = context;

    eglQuerySurface(display, surface, EGL_WIDTH, &data->width);
    eglQuerySurface(display, surface, EGL_HEIGHT, &data->height);

    LOGI("EGL display initialized: %dx%d", data->width, data->height);
    return 0;
}

static void engine_draw_frame(AndroidAppData* data) {
    if (data->display == EGL_NO_DISPLAY) return;

    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplAndroid_NewFrame();
    ImGui::NewFrame();

    ui_frame();

    ImGui::Render();

    glViewport(0, 0, data->width, data->height);
    glClearColor(0.05f, 0.05f, 0.08f, 1.0f);
    glClear(GL_COLOR_BUFFER_BIT);

    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

    eglSwapBuffers(data->display, data->surface);
}

static void engine_term_display(AndroidAppData* data) {
    if (data->display != EGL_NO_DISPLAY) {
        eglMakeCurrent(data->display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
        if (data->context != EGL_NO_CONTEXT) eglDestroyContext(data->display, data->context);
        if (data->surface != EGL_NO_SURFACE) eglDestroySurface(data->display, data->surface);
        eglTerminate(data->display);
    }
    data->display = EGL_NO_DISPLAY;
    data->context = EGL_NO_CONTEXT;
    data->surface = EGL_NO_SURFACE;
}

static int32_t engine_handle_input(struct android_app* app, AInputEvent* event) {
    AndroidAppData* data = (AndroidAppData*)app->userData;
    (void)data;

    if (AInputEvent_getType(event) == AINPUT_EVENT_TYPE_MOTION) {
        ImGui_ImplAndroid_HandleInputEvent(event);
        return 1;
    }
    return 0;
}

static void engine_handle_cmd(struct android_app* app, int32_t cmd) {
    AndroidAppData* data = (AndroidAppData*)app->userData;

    switch (cmd) {
        case APP_CMD_INIT_WINDOW:
            if (app->window != nullptr) {
                engine_init_display(data);
                data->initialized = true;

                IMGUI_CHECKVERSION();
                ImGui::CreateContext();
                ImGuiIO& io = ImGui::GetIO();
                io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
                io.IniFilename = nullptr;

                ImGui::StyleColorsDark();
                ImGuiStyle& style = ImGui::GetStyle();
                style.WindowRounding = 8.0f;
                style.FrameRounding  = 4.0f;
                style.FramePadding   = ImVec2(8, 4);
                style.WindowPadding  = ImVec2(12, 8);

                ImGui_ImplAndroid_Init(app->window);
                ImGui_ImplOpenGL3_Init("#version 300 es");

                ui_init();
                LOGI("Window initialized, ImGui ready");
            }
            break;

        case APP_CMD_TERM_WINDOW:
            ui_shutdown();
            ImGui_ImplOpenGL3_Shutdown();
            ImGui_ImplAndroid_Shutdown();
            ImGui::DestroyContext();
            engine_term_display(data);
            data->initialized = false;
            break;

        case APP_CMD_GAINED_FOCUS:
            data->focused = true;
            break;

        case APP_CMD_LOST_FOCUS:
            data->focused = false;
            break;

        default:
            break;
    }
}

void android_main(struct android_app* app) {
    AndroidAppData data = {};
    data.app = app;
    data.display = EGL_NO_DISPLAY;
    data.context = EGL_NO_CONTEXT;
    data.surface = EGL_NO_SURFACE;
    data.initialized = false;
    data.focused = true;

    app->userData = &data;
    app->onAppCmd = engine_handle_cmd;
    app->onInputEvent = engine_handle_input;

    LOGI("FCAE VPN starting on Android");

    while (true) {
        int events;
        struct android_poll_source* source;

        while (ALooper_pollAll(data.focused ? 0 : -1, nullptr, &events, (void**)&source) >= 0) {
            if (source != nullptr) {
                source->process(app, source);
            }
            if (app->destroyRequested) {
                engine_term_display(&data);
                return;
            }
        }

        if (data.initialized) {
            engine_draw_frame(&data);
        }
    }
}

// JNI bridge: pass Android VpnService fd to Rust FFI
extern "C" JNIEXPORT void JNICALL
Java_com_fc_fcaevpn_FCAEVpnService_nativeSetTunFd(JNIEnv* env, jobject thiz, jint fd) {
    (void)env; (void)thiz;
    aether_set_android_tun_fd(fd);
    LOGI("TUN fd %d passed to Rust FFI", fd);
}

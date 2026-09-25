// FCAE VPN — Linux OpenGL3 + GLFW + Dear ImGui frontend
#include <cstdio>
#include <cstdlib>
#include <cstddef>
#include <thread>
#include <chrono>

#define GL_GLEXT_PROTOTYPES 1
#include <GLFW/glfw3.h>

// X11 dark title bar support
#ifdef __linux__
#define GLFW_EXPOSE_NATIVE_X11
#include <GLFW/glfw3native.h>
#include <X11/Xlib.h>
#include <X11/Xatom.h>
#endif

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"

#include "ui_render.h"

// Window / taskbar icon, embedded so it is right even when the app runs
// straight from the extracted archive.
#include "icon_data.h"

static void glfw_error_callback(int error, const char* description) {
    fprintf(stderr, "GLFW Error %d: %s\n", error, description);
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;

    glfwSetErrorCallback(glfw_error_callback);
    if (!glfwInit()) return 1;

    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GLFW_TRUE);
    glfwWindowHint(GLFW_RESIZABLE, GLFW_FALSE);

    // Request dark window decorations (GNOME/KDE Wayland & X11 dark title bar)
#ifdef GLFW_WAYLAND_APP_ID
    glfwWindowHintString(GLFW_WAYLAND_APP_ID, "fcaevpn");
#endif

    // Stable WM class so desktop environments group the window correctly.
#ifdef GLFW_X11_CLASS_NAME
    glfwWindowHintString(GLFW_X11_CLASS_NAME, "fcaevpn");
#endif
#ifdef GLFW_X11_INSTANCE_NAME
    glfwWindowHintString(GLFW_X11_INSTANCE_NAME, "fcaevpn");
#endif

    GLFWwindow* window = glfwCreateWindow(1024, 700, "FCAE VPN", nullptr, nullptr);
    if (!window) {
        glfwTerminate();
        return 1;
    }
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    {
        GLFWimage icons[sizeof(FCAE_ICONS) / sizeof(FCAE_ICONS[0])];
        for (size_t i = 0; i < sizeof(icons) / sizeof(icons[0]); ++i) {
            icons[i].width  = FCAE_ICONS[i].width;
            icons[i].height = FCAE_ICONS[i].height;
            icons[i].pixels = const_cast<unsigned char*>(FCAE_ICONS[i].rgba);
        }
        glfwSetWindowIcon(window, (int)(sizeof(icons) / sizeof(icons[0])), icons);
    }

    // Set dark title bar on X11 via _GTK_THEME_VARIANT hint
    // This tells GNOME/XFCE/Cinnamon etc. to render the window frame in dark mode
    {
        Display* x11_dpy = glfwGetX11Display();
        if (x11_dpy) {
            GLFWwindow* win = glfwGetCurrentContext() ? window : nullptr;
            if (win) {
                Atom atom = XInternAtom(x11_dpy, "_GTK_THEME_VARIANT", False);
                if (atom != None) {
                    const char dark[] = "dark";
                    XChangeProperty(x11_dpy, glfwGetX11Window(window),
                                    atom, XA_STRING, 8, PropModeReplace,
                                    (unsigned char*)dark, (int)sizeof(dark) - 1);
                }
            }
        }
    }

    // Disable maximize (define constant if GLFW < 3.3 doesn't provide it)
#ifndef GLFW_MAXIMIZABLE
#define GLFW_MAXIMIZABLE 0x00020006
#endif
    glfwSetWindowAttrib(window, GLFW_MAXIMIZABLE, GLFW_FALSE);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    ImGui::StyleColorsDark();
    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding   = 10.0f;
    style.FrameRounding    = 6.0f;
    style.GrabRounding     = 4.0f;
    style.ScrollbarRounding = 6.0f;
    style.FramePadding     = ImVec2(10, 6);
    style.WindowPadding    = ImVec2(16, 12);

    // Custom dark palette
    ImVec4* colors = style.Colors;
    colors[ImGuiCol_WindowBg]        = ImVec4(0.08f, 0.08f, 0.12f, 1.0f);
    colors[ImGuiCol_ChildBg]         = ImVec4(0.10f, 0.10f, 0.14f, 1.0f);
    colors[ImGuiCol_PopupBg]         = ImVec4(0.10f, 0.10f, 0.14f, 0.95f);
    colors[ImGuiCol_FrameBg]         = ImVec4(0.14f, 0.14f, 0.20f, 1.0f);
    colors[ImGuiCol_FrameBgHovered]  = ImVec4(0.18f, 0.18f, 0.26f, 1.0f);
    colors[ImGuiCol_FrameBgActive]   = ImVec4(0.22f, 0.22f, 0.30f, 1.0f);
    colors[ImGuiCol_TitleBg]         = ImVec4(0.06f, 0.06f, 0.10f, 1.0f);
    colors[ImGuiCol_TitleBgActive]   = ImVec4(0.10f, 0.10f, 0.16f, 1.0f);
    colors[ImGuiCol_Button]          = ImVec4(0.16f, 0.40f, 0.60f, 1.0f);
    colors[ImGuiCol_ButtonHovered]   = ImVec4(0.20f, 0.50f, 0.70f, 1.0f);
    colors[ImGuiCol_ButtonActive]    = ImVec4(0.14f, 0.36f, 0.56f, 1.0f);
    colors[ImGuiCol_Tab]             = ImVec4(0.12f, 0.12f, 0.18f, 1.0f);
    colors[ImGuiCol_TabHovered]      = ImVec4(0.20f, 0.30f, 0.45f, 1.0f);
    colors[ImGuiCol_TabSelected]     = ImVec4(0.16f, 0.36f, 0.52f, 1.0f);
    colors[ImGuiCol_SliderGrab]      = ImVec4(0.30f, 0.60f, 0.80f, 1.0f);
    colors[ImGuiCol_SliderGrabActive]= ImVec4(0.35f, 0.70f, 0.90f, 1.0f);

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 330");

    ui_init();

    // Event-driven, change-gated render loop: glfwWaitEventsTimeout sleeps the
    // thread while idle, and a frame is painted only when something actually
    // changed (stats/logs/transient text) or the user is interacting. An idle
    // window therefore costs ~0% CPU instead of a full-frame repaint every
    // second, and events that change nothing no longer force frames either.
    auto last_frame_time = std::chrono::steady_clock::now();
    constexpr auto min_frame_interval = std::chrono::milliseconds(16);   // ~60 FPS cap
    constexpr double interaction_tail  = 0.7;                            // smooth for this long after the last event
    double last_event_time = -1e9;                                       // monotonic seconds (glfwGetTime)
    bool minimized = false;

    while (!glfwWindowShouldClose(window) && g_app.running.load()) {
        minimized = glfwGetWindowAttrib(window, GLFW_ICONIFIED) == GLFW_TRUE;
        const double t_before = glfwGetTime();
        bool interacting = (t_before - last_event_time) < interaction_tail;

        // Wait for events: ~60 FPS while interacting, slower when idle (the
        // engine poll still runs, see ui_sleep_ms()).
        double timeout = minimized ? 1.0
                       : interacting ? min_frame_interval.count() / 1000.0
                       : (double)ui_sleep_ms() / 1000.0;
        glfwWaitEventsTimeout(timeout);

        // Only render if the window is still alive after processing events.
        if (glfwWindowShouldClose(window)) break;

        const double t = glfwGetTime();
        // The wait returned before its timeout ⇒ events (i.e. user input or
        // window changes) arrived; keep frames smooth for a short tail.
        if (t - t_before < timeout - 0.005) last_event_time = t;
        interacting = (t - last_event_time) < interaction_tail;

        if (minimized) continue;

        // Throttle to 60 FPS max — skip frame if less than 16ms since last render
        auto now = std::chrono::steady_clock::now();
        if (now - last_frame_time < min_frame_interval) {
            continue;
        }

        // Skip frames whose pixels would be identical to the last painted one.
        if (!ui_should_render(interacting)) continue;

        last_frame_time = now;

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        ui_frame();

        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(0.05f, 0.05f, 0.08f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        glfwSwapBuffers(window);
    }

    ui_shutdown();

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();
    return 0;
}

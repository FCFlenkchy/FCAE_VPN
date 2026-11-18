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
#if defined(FCAE_HAVE_FREETYPE)
#include "imgui_freetype.h"
#endif
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"

#include "ui_render.h"

// Window / taskbar icon, embedded so it is right even when the app runs
// straight from the extracted archive.
#include "icon_data.h"

ImTextureID sponsor_texture_update(const uint8_t* rgba, int width, int height, uint64_t generation, int slot) {
    static GLuint textures[3] = {};
    static uint64_t loaded[3] = {};
    static int texture_width[3] = {};
    static int texture_height[3] = {};
    const int index = slot >= 0 && slot < 3 ? slot : 0;
    GLuint& texture = textures[index];
    if (!rgba || width <= 0 || height <= 0) return (ImTextureID)0;
    if (!texture) {
        glGenTextures(1, &texture);
        glBindTexture(GL_TEXTURE_2D, texture);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    } else {
        glBindTexture(GL_TEXTURE_2D, texture);
    }
    if (loaded[index] != generation) {
        glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
        if (texture_width[index] != width || texture_height[index] != height) {
            glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, width, height, 0, GL_RGBA,
                         GL_UNSIGNED_BYTE, rgba);
            texture_width[index] = width;
            texture_height[index] = height;
        } else {
            // Keep the GPU allocation and upload only the changed frame.
            glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, width, height, GL_RGBA,
                            GL_UNSIGNED_BYTE, rgba);
        }
        loaded[index] = generation;
    }
    return (ImTextureID)(intptr_t)texture;
}

// Minimized, or unmapped by the window manager on another workspace.
static bool window_hidden(GLFWwindow* window) {
    return glfwGetWindowAttrib(window, GLFW_ICONIFIED) == GLFW_TRUE
        || glfwGetWindowAttrib(window, GLFW_VISIBLE) == GLFW_FALSE;
}

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

    // The designed size in 96-DPI units, scaled by the desktop's text scale.
    // Creating at a fixed 1024x700 and letting the compositor scale it is what
    // made the window read as small under a fractional or 200% desktop scale.
    // GLFW can only answer this once a monitor is known, and on Wayland only
    // after the window exists, so the size is corrected below as well.
    constexpr int kWindowWidthDip  = 1180;
    constexpr int kWindowHeightDip = 780;
    float content_scale = 1.0f;
    {
        GLFWmonitor* primary = glfwGetPrimaryMonitor();
        if (primary != nullptr) glfwGetMonitorContentScale(primary, &content_scale, nullptr);
    }
    if (!(content_scale > 0.0f)) content_scale = 1.0f;

    GLFWwindow* window = glfwCreateWindow((int)(kWindowWidthDip * content_scale + 0.5f),
                                          (int)(kWindowHeightDip * content_scale + 0.5f),
                                          "FCAE VPN", nullptr, nullptr);
    if (!window) {
        glfwTerminate();
        return 1;
    }
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    // Authoritative scale for this window (a different monitor may have a
    // different one than the primary used above).
    {
        float sx = 1.0f, sy = 1.0f;
        glfwGetWindowContentScale(window, &sx, &sy);
        if (sx > 0.0f) content_scale = sx;
    }

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
    // FreeType replaces the default glyph rasteriser when the build found it.
    // Set before the font atlas is first built (the first frame does that), so
    // the loader is in place for the initial bake. Through public API only:
    // nothing defines IMGUI_ENABLE_FREETYPE, which would make the symbol a hard
    // link requirement on machines that do not have the library.
#if defined(FCAE_HAVE_FREETYPE)
    ImGui::GetIO().Fonts->SetFontLoader(ImGuiFreeType::GetFontLoader());
#endif
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    ImGui::StyleColorsDark();
    ImGuiStyle& style = ImGui::GetStyle();
    // Per-monitor factor, on top of which ui_frame() applies the user's own
    // text scale through FontScaleMain.
    style.FontScaleDpi     = content_scale;
    style.WindowRounding   = 10.0f;
    style.FrameRounding    = 6.0f;
    style.GrabRounding     = 4.0f;
    style.ScrollbarRounding = 6.0f;
    style.FramePadding     = ImVec2(10, 6);
    style.WindowPadding    = ImVec2(16, 12);
    // Button labels sit in the middle of their box on every platform: the
    // default left alignment read as off-centre wherever a label was narrower
    // than the fixed width these rows use.
    style.ButtonTextAlign  = ImVec2(0.5f, 0.5f);

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

    // Registered before the loop parks, so a redraw requested from a worker
    // thread can end the wait in glfwWaitEventsTimeout() immediately instead of
    // arriving as a late repaint after the idle timeout.
    ui_set_window_handle(window);

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 330");

    ui_init();

    // Paint only for input or changed UI content; block on events while idle.
    auto last_frame_time = std::chrono::steady_clock::now();
    constexpr auto min_frame_interval = std::chrono::milliseconds(33);
    constexpr double interaction_tail  = 0.7;
    double last_event_time = -1e9;
    bool hidden = false;
    bool sponsor_window_visible = false;

    while (!glfwWindowShouldClose(window) && g_app.running.load()) {
        hidden = window_hidden(window);
        const double t_before = glfwGetTime();
        bool interacting = (t_before - last_event_time) < interaction_tail;

        double timeout = hidden ? 1.0
                       : interacting ? min_frame_interval.count() / 1000.0
                       : (double)ui_sleep_ms() / 1000.0;
        glfwWaitEventsTimeout(timeout);

        if (glfwWindowShouldClose(window)) break;

        const double t = glfwGetTime();
        // An early wake indicates input or a window event.
        if (t - t_before < timeout - 0.005) last_event_time = t;
        interacting = (t - last_event_time) < interaction_tail;

        hidden = window_hidden(window);
        if (hidden) {
            ui_autosave_tick();
            if (sponsor_window_visible) {
                ui_set_window_visible(false);
                sponsor_window_visible = false;
            }
            continue;
        }
        if (!sponsor_window_visible) {
            ui_set_window_visible(true);
            sponsor_window_visible = true;
        }
        ui_set_window_focused(glfwGetWindowAttrib(window, GLFW_FOCUSED) != 0);

        auto now = std::chrono::steady_clock::now();
        if (now - last_frame_time < min_frame_interval) {
            continue;
        }

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

    ui_set_window_handle(nullptr);
    ui_shutdown();

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();
    return 0;
}

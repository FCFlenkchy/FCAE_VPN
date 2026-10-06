// FCAE VPN — macOS OpenGL3 + GLFW + Dear ImGui frontend
#include <cstdio>
#include <cstdlib>
#include <thread>
#include <chrono>

#define GL_SILENCE_DEPRECATION
#define GL_GLEXT_PROTOTYPES 1
#include <GLFW/glfw3.h>
#define GLFW_EXPOSE_NATIVE_COCOA
#include <GLFW/glfw3native.h>
#include <objc/message.h>

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"

#include "ui_render.h"

// Minimized, hidden with the app (Cmd+H), on another Space or fully covered:
// NSWindow reports all of them through its occlusion state.
static bool window_hidden(GLFWwindow* window) {
    if (glfwGetWindowAttrib(window, GLFW_ICONIFIED) == GLFW_TRUE) return true;
    constexpr unsigned long kOcclusionStateVisible = 1UL << 1;
    static const SEL occlusion_state = sel_registerName("occlusionState");
    const auto send = reinterpret_cast<unsigned long (*)(id, SEL)>(objc_msgSend);
    return (send(glfwGetCocoaWindow(window), occlusion_state) & kOcclusionStateVisible) == 0;
}

ImTextureID sponsor_texture_update(const uint8_t* rgba, int width, int height, uint64_t generation, int slot) {
    static GLuint textures[2] = {};
    static uint64_t loaded[2] = {};
    static int texture_width[2] = {};
    static int texture_height[2] = {};
    const int index = slot == 1 ? 1 : 0;
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
            glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, width, height, GL_RGBA,
                            GL_UNSIGNED_BYTE, rgba);
        }
        loaded[index] = generation;
    }
    return (ImTextureID)(intptr_t)texture;
}

static void glfw_error_callback(int error, const char* description) {
    fprintf(stderr, "GLFW Error %d: %s\n", error, description);
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;

    glfwSetErrorCallback(glfw_error_callback);
    if (!glfwInit()) return 1;

    // macOS requires forward-compat core profile for OpenGL 3.3+
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GLFW_TRUE);
    glfwWindowHint(GLFW_RESIZABLE, GLFW_FALSE);

    // macOS Cocoa: use dark appearance if available (GLFW 3.4+)
#ifdef GLFW_COCOA_CHDIR_RESOURCES
    glfwWindowHint(GLFW_COCOA_CHDIR_RESOURCES, GLFW_FALSE);
#endif

    GLFWwindow* window = glfwCreateWindow(1024, 700, "FCAE VPN", nullptr, nullptr);
    if (!window) {
        glfwTerminate();
        return 1;
    }
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    // Disable maximize
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
    style.WindowRounding    = 10.0f;
    style.FrameRounding     = 6.0f;
    style.GrabRounding      = 4.0f;
    style.ScrollbarRounding = 6.0f;
    style.FramePadding      = ImVec2(10, 6);
    style.WindowPadding     = ImVec2(16, 12);

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
    ImGui_ImplOpenGL3_Init("#version 150");

    ui_init();

    // Event-driven, change-gated render loop: glfwWaitEventsTimeout sleeps the
    // thread while idle, and a frame is painted only when something actually
    // changed (stats/logs/transient text) or the user is interacting.
    auto last_frame_time = std::chrono::steady_clock::now();
    constexpr auto min_frame_interval = std::chrono::milliseconds(33);   // ~30 FPS cap
    constexpr double interaction_tail  = 0.7;
    double last_event_time = -1e9;                                       // monotonic seconds (glfwGetTime)
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
        if (t - t_before < timeout - 0.005) last_event_time = t;
        interacting = (t - last_event_time) < interaction_tail;

        hidden = window_hidden(window);
        if (hidden) {
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
        if (now - last_frame_time < min_frame_interval) continue;
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

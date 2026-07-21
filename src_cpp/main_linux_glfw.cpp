// FCAE VPN — Linux OpenGL3 + GLFW + Dear ImGui frontend
#include <cstdio>
#include <cstdlib>

#define GL_GLEXT_PROTOTYPES 1
#include <GLFW/glfw3.h>

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"

#include "ui_render.h"

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

    GLFWwindow* window = glfwCreateWindow(1024, 700, "FCAE VPN", nullptr, nullptr);
    if (!window) {
        glfwTerminate();
        return 1;
    }
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
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

    while (!glfwWindowShouldClose(window) && g_app.running.load()) {
        glfwPollEvents();

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

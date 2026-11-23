#include "ui_style.h"
#include "ui_frame_pacing.h"
#include "imgui_internal.h"
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

#include <dlfcn.h>
#include <unordered_map>
#include <filesystem>
#include "app_icon_hints.h"
static std::unordered_map<std::string,GLuint> app_icon_textures;
static void release_app_icons(){for(const auto& entry:app_icon_textures)if(entry.second)glDeleteTextures(1,&entry.second);app_icon_textures.clear();}
ImTextureID app_routing_icon(const std::string& executable) {
    auto found=app_icon_textures.find(executable);if(found!=app_icon_textures.end())return (ImTextureID)(intptr_t)found->second;
    if(app_icon_textures.size()>=512)return ImTextureID{};
    static void* gtk=dlopen("libgtk-3.so.0",RTLD_LAZY|RTLD_LOCAL);
    if(!gtk)return ImTextureID{};
    using Init=int(*)(int*,char***);using Theme=void*(*)();using Load=void*(*)(void*,const char*,int,int,void**);
    using File=void*(*)(const char*,int,int,int,void**);using Int=int(*)(void*);using Pixels=unsigned char*(*)(void*);using Unref=void(*)(void*);
    static auto init=(Init)dlsym(gtk,"gtk_init_check");static auto theme=(Theme)dlsym(gtk,"gtk_icon_theme_get_default");static auto load=(Load)dlsym(gtk,"gtk_icon_theme_load_icon");
    static auto file=(File)dlsym(gtk,"gdk_pixbuf_new_from_file_at_scale");static auto width=(Int)dlsym(gtk,"gdk_pixbuf_get_width");static auto height=(Int)dlsym(gtk,"gdk_pixbuf_get_height");
    static auto stride=(Int)dlsym(gtk,"gdk_pixbuf_get_rowstride");static auto channels=(Int)dlsym(gtk,"gdk_pixbuf_get_n_channels");static auto pixels=(Pixels)dlsym(gtk,"gdk_pixbuf_get_pixels");static auto unref=(Unref)dlsym(gtk,"g_object_unref");
    static bool ready=[&]{
        auto disable_locale=(void(*)())dlsym(gtk,"gtk_disable_setlocale");if(disable_locale)disable_locale();
        return init&&theme&&load&&file&&width&&height&&stride&&channels&&pixels&&unref&&init(nullptr,nullptr);
    }();
    if(!ready)return ImTextureID{};
    std::string name=AppIconHints::get(executable);if(name.empty())name=std::filesystem::path(executable).filename().string();
    void* bitmap=!name.empty()&&name[0]=='/'?file(name.c_str(),48,48,1,nullptr):load(theme(),name.c_str(),48,0,nullptr);
    GLuint texture=0;
    if(bitmap){
        int w=width(bitmap),h=height(bitmap),row=stride(bitmap),n=channels(bitmap);auto data=pixels(bitmap);
        if(w>0&&h>0&&w<=256&&h<=256&&(n==3||n==4)&&row>=w*n&&data){
            std::vector<unsigned char> rgba(w*h*4);
            for(int y=0;y<h;++y)for(int x=0;x<w;++x){auto src=data+y*row+x*n;auto dst=rgba.data()+(y*w+x)*4;dst[0]=src[0];dst[1]=src[1];dst[2]=src[2];dst[3]=n==4?src[3]:255;}
            glGenTextures(1,&texture);glBindTexture(GL_TEXTURE_2D,texture);glTexParameteri(GL_TEXTURE_2D,GL_TEXTURE_MIN_FILTER,GL_LINEAR);glTexParameteri(GL_TEXTURE_2D,GL_TEXTURE_MAG_FILTER,GL_LINEAR);
            glPixelStorei(GL_UNPACK_ALIGNMENT,1);glTexImage2D(GL_TEXTURE_2D,0,GL_RGBA8,w,h,0,GL_RGBA,GL_UNSIGNED_BYTE,rgba.data());
        }
        unref(bitmap);
    }
    app_icon_textures.emplace(executable,texture);return (ImTextureID)(intptr_t)texture;
}

static GLuint sponsor_textures[3] = {};
static uint64_t sponsor_loaded[3] = {};
static int sponsor_width[3] = {};
static int sponsor_height[3] = {};

static void release_cached_visuals() {
    release_app_icons();
    for (int i = 0; i < 3; ++i) {
        if (sponsor_textures[i]) glDeleteTextures(1, &sponsor_textures[i]);
        sponsor_textures[i] = 0;
        sponsor_loaded[i] = 0;
        sponsor_width[i] = sponsor_height[i] = 0;
    }
}

ImTextureID sponsor_texture_update(const uint8_t* rgba, int width, int height, uint64_t generation, int slot) {
    const int index = slot >= 0 && slot < 3 ? slot : 0;
    GLuint& texture = sponsor_textures[index];
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
    if (sponsor_loaded[index] != generation) {
        glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
        if (sponsor_width[index] != width || sponsor_height[index] != height) {
            glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, width, height, 0, GL_RGBA,
                         GL_UNSIGNED_BYTE, rgba);
            sponsor_width[index] = width;
            sponsor_height[index] = height;
        } else {
            // Keep the GPU allocation and upload only the changed frame.
            glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, width, height, GL_RGBA,
                            GL_UNSIGNED_BYTE, rgba);
        }
        sponsor_loaded[index] = generation;
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
    glfwWindowHint(GLFW_RESIZABLE, GLFW_TRUE);

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

    // The designed size, in pixels: larger than the original 1024x700, which
    // was cramped once the settings pages and the log tail were both on screen.
    //
    // Not scaled by the desktop's content scale: scaling both the window and the
    // ImGui font applied the factor twice, so the window grew and the text
    // inside it grew again and the layout overflowed. Text size is the user's
    // ui_scale_percent instead, which leaves the frame alone.
    constexpr int kWindowWidth  = 1280;
    constexpr int kWindowHeight = 860;
    // The base font size, in pixels, and the size the ui_render.cpp layout is
    // designed against: about 1.7x the 13 px ImGui's embedded default face used
    // to give this UI. See the same constant in the Win32 host for why it is not
    // the full 2x.
    constexpr float kUiBaseFontSize = 22.0f;

    // Never open larger than the monitor can show; a window that starts
    // off-screen cannot be grabbed by the title bar.
    int window_w = kWindowWidth;
    int window_h = kWindowHeight;
    if (GLFWmonitor* primary = glfwGetPrimaryMonitor()) {
        int area_x = 0, area_y = 0, area_w = 0, area_h = 0;
        glfwGetMonitorWorkarea(primary, &area_x, &area_y, &area_w, &area_h);
        if (area_w > 480 && window_w > area_w - 40) window_w = area_w - 40;
        if (area_h > 360 && window_h > area_h - 80) window_h = area_h - 80;
    }

    GLFWwindow* window = glfwCreateWindow(window_w, window_h, "FCAE VPN", nullptr, nullptr);
    if (!window) {
        glfwTerminate();
        return 1;
    }
    glfwSetWindowSizeLimits(window, 480, 360, GLFW_DONT_CARE, GLFW_DONT_CARE);
    glfwSetFramebufferSizeCallback(window, [](GLFWwindow*, int, int) { ui_request_redraw(); });
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
    // FreeType replaces the default glyph rasteriser when the build found it.
    // Set before the font atlas is first built (the first frame does that), so
    // the loader is in place for the initial bake. Through public API only:
    // nothing defines IMGUI_ENABLE_FREETYPE, which would make the symbol a hard
    // link requirement on machines that do not have the library.
#if defined(FCAE_HAVE_FREETYPE)
    ImGui::GetIO().Fonts->SetFontLoader(ImGuiFreeType::GetFontLoader());
#endif
    // A base font at a readable size. Without this the atlas holds only ImGui's
    // embedded 13 px ProggyClean bitmap face, which is what made the UI read as
    // tiny, and a bitmap face cannot be enlarged without turning into mush.
    // AddFontDefaultVector() is named explicitly: AddFontDefault() chooses
    // between the bitmap and vector faces from the expected context size, which
    // is still unset here.
    {
        ImFontConfig font_cfg;
        font_cfg.SizePixels = kUiBaseFontSize;
        ImGui::GetIO().Fonts->AddFontDefaultVector(&font_cfg);
    }
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    ui_apply_style(kUiBaseFontSize);

    // Registered before the loop parks, so a redraw requested from a worker
    // thread can end the wait in glfwWaitEventsTimeout() immediately instead of
    // arriving as a late repaint after the idle timeout.
    ui_set_window_handle(window);

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 330");

    ui_init();

    // Paint only for input or changed UI content; block on events while idle.
    constexpr double min_frame_interval = UiFrame::interaction_interval;
    double last_frame_time = glfwGetTime() - min_frame_interval;
    constexpr double interaction_tail  = 0.7;
    double last_event_time = -1e9;
    bool hidden = false;
    bool sponsor_window_visible = false;

    while (!glfwWindowShouldClose(window) && g_app.running.load()) {
        hidden = window_hidden(window);
        const double t_before = glfwGetTime();
        bool interacting = (t_before - last_event_time) < interaction_tail;

        const double idle = (double)ui_sleep_ms() / 1000.0;
        const double timeout = hidden ? 1.0 : UiFrame::wait_seconds(t_before, last_frame_time,
            min_frame_interval, idle, true);
        if (timeout > 0.0) glfwWaitEventsTimeout(timeout);
        else glfwPollEvents();

        if (glfwWindowShouldClose(window)) break;

        const double t = glfwGetTime();
        // An early wake indicates input or a window event.
        if ((timeout > 0.0 && t - t_before < timeout - 0.001) || GImGui->InputEventsQueue.Size != 0)
            last_event_time = t;
        interacting = (t - last_event_time) < interaction_tail;

        hidden = window_hidden(window);
        if (hidden) {
            ui_autosave_tick();
            if (sponsor_window_visible) {
                ui_set_window_visible(false);
                release_cached_visuals();
                sponsor_window_visible = false;
            }
            continue;
        }
        if (!sponsor_window_visible) {
            ui_set_window_visible(true);
            sponsor_window_visible = true;
        }
        ui_set_window_focused(glfwGetWindowAttrib(window, GLFW_FOCUSED) != 0);

        const double now = glfwGetTime();
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
    release_cached_visuals();

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();
    return 0;
}

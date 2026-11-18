#ifndef UNICODE
#define UNICODE
#endif
#include <windows.h>
#include <d3d11.h>
#include <dwmapi.h>
#include <tchar.h>
#include <chrono>

#include "imgui.h"
#if defined(FCAE_HAVE_FREETYPE)
#include "imgui_freetype.h"
#endif
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"

#include "ui_render.h"

static ID3D11Device*           g_pd3dDevice       = nullptr;
static ID3D11DeviceContext*    g_pd3dDeviceContext = nullptr;
static IDXGISwapChain*         g_pSwapChain       = nullptr;
static ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;
static ID3D11Texture2D*        g_sponsor_textures[3] = {};
static ID3D11ShaderResourceView* g_sponsor_views[3] = {};
static uint64_t g_sponsor_loaded[3] = {};
static int g_sponsor_texture_width[3] = {};
static int g_sponsor_texture_height[3] = {};
static bool g_imgui_win32_ready = false;
// The size the window was created at, in physical pixels. Kept so the first
// WM_DPICHANGED after creation cannot be mistaken for a user resize.
static int g_created_width  = 0;
static int g_created_height = 0;

ImTextureID sponsor_texture_update(const uint8_t* rgba, int width, int height, uint64_t generation, int slot) {
    const int index = slot >= 0 && slot < 3 ? slot : 0;
    ID3D11Texture2D*& texture = g_sponsor_textures[index];
    ID3D11ShaderResourceView*& view = g_sponsor_views[index];
    if (!rgba || width <= 0 || height <= 0 || !g_pd3dDevice || !g_pd3dDeviceContext)
        return (ImTextureID)0;
    if (!texture || g_sponsor_texture_width[index] != width
            || g_sponsor_texture_height[index] != height) {
        if (view) { view->Release(); view = nullptr; }
        if (texture) { texture->Release(); texture = nullptr; }
        D3D11_TEXTURE2D_DESC desc = {};
        desc.Width = (UINT)width;
        desc.Height = (UINT)height;
        desc.MipLevels = 1;
        desc.ArraySize = 1;
        desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        desc.SampleDesc.Count = 1;
        desc.Usage = D3D11_USAGE_DEFAULT;
        desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
        if (FAILED(g_pd3dDevice->CreateTexture2D(&desc, nullptr, &texture)) || !texture
                || FAILED(g_pd3dDevice->CreateShaderResourceView(texture, nullptr, &view))) {
            if (view) { view->Release(); view = nullptr; }
            if (texture) { texture->Release(); texture = nullptr; }
            return (ImTextureID)0;
        }
        g_sponsor_texture_width[index] = width;
        g_sponsor_texture_height[index] = height;
        g_sponsor_loaded[index] = 0;
    }
    if (g_sponsor_loaded[index] != generation) {
        g_pd3dDeviceContext->UpdateSubresource(
            texture, 0, nullptr, rgba, (UINT)width * 4, (UINT)width * (UINT)height * 4);
        g_sponsor_loaded[index] = generation;
    }
    return (ImTextureID)view;
}

static void release_sponsor_textures() {
    for (int i = 0; i < 3; ++i) {
        if (g_sponsor_views[i]) { g_sponsor_views[i]->Release(); g_sponsor_views[i] = nullptr; }
        if (g_sponsor_textures[i]) { g_sponsor_textures[i]->Release(); g_sponsor_textures[i] = nullptr; }
        g_sponsor_loaded[i] = 0;
        g_sponsor_texture_width[i] = 0;
        g_sponsor_texture_height[i] = 0;
    }
}

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// ---------------------------------------------------------------------------
// DPI
//
// app.manifest declares PerMonitorV2, which means every size in this file is a
// physical pixel: at 150% scale a 1024x700 window covers 683x467 of the space
// the user thinks in. The window was created at a fixed 1024x700, so on any
// scaled display it opened at roughly two-thirds the intended size and read as
// "came up tiny". The same factor has to reach ImGui, or the UI would be laid
// out for 96 DPI inside a window sized for 144.
// ---------------------------------------------------------------------------

// GetDpiForWindow only exists from Windows 10 1607; resolving it at run time
// keeps the binary loading on anything older instead of failing to start.
static UINT window_dpi(HWND hwnd) {
    using GetDpiForWindowFn = UINT(WINAPI*)(HWND);
    static GetDpiForWindowFn get_dpi = []() -> GetDpiForWindowFn {
        const HMODULE user32 = GetModuleHandleW(L"user32.dll");
        return user32 ? reinterpret_cast<GetDpiForWindowFn>(
                            reinterpret_cast<void*>(GetProcAddress(user32, "GetDpiForWindow")))
                      : nullptr;
    }();
    if (get_dpi != nullptr && hwnd != nullptr) {
        const UINT dpi = get_dpi(hwnd);
        if (dpi != 0) return dpi;
    }
    // Pre-1607: the system DPI is the best available answer, and the manifest
    // is not per-monitor on those builds anyway.
    HDC screen = GetDC(nullptr);
    const UINT fallback = screen ? (UINT)GetDeviceCaps(screen, LOGPIXELSX) : 96u;
    if (screen) ReleaseDC(nullptr, screen);
    return fallback != 0 ? fallback : 96u;
}

static float window_dpi_scale(HWND hwnd) { return (float)window_dpi(hwnd) / 96.0f; }

// The designed window size, in pixels.
//
// Larger than the original 1024x700, which was cramped once the settings pages
// and the log tail were both on screen. The constants below are what the layout
// is designed against; if the monitor cannot hold that, the window is shrunk to
// fit instead of opening larger than the screen.
//
// Deliberately not scaled by DPI: an earlier revision scaled both the window and
// the ImGui font metrics by the monitor factor, which applied it twice -- the
// window grew 1.5x and the text inside it 1.5x again, so the layout overflowed.
// One factor owns the scaling, and it is the user's ui_scale_percent, which
// grows the text without moving the frame.
static constexpr int kWindowWidth  = 1280;
static constexpr int kWindowHeight = 860;

// The base UI font size, in pixels: exactly twice the 13 px that ImGui's
// embedded default face used to give this UI, which is what the whole window is
// sized against now. The user's ui_scale_percent still multiplies on top of it
// through style.FontScaleMain, so this is the floor, not the ceiling.
//
// On top of this, the layout's own constants -- action row heights, button
// widths, the log pane -- are computed from measured text rather than from
// fixed pixel values, so doubling the type does not push labels past their
// backgrounds. Anything still fixed (the modals' 680x620 and so on) is clamped
// to the viewport and scrolls its contents.
static constexpr float kUiBaseFontSize = 26.0f;

// Clamp a designed size to what the monitor actually offers, leaving room for
// the taskbar and window decorations.
static void clamp_to_screen(int& width, int& height) {
    const int max_w = GetSystemMetrics(SM_CXSCREEN) - 80;
    const int max_h = GetSystemMetrics(SM_CYSCREEN) - 120;
    if (max_w > 480 && width  > max_w) width  = max_w;
    if (max_h > 360 && height > max_h) height = max_h;
}

static void CleanupDeviceD3D();

static LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (g_imgui_win32_ready && ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return 1;

    switch (msg) {
        // Window events that change what should be on screen: ask for exactly
        // one repaint instead of leaving the loop free-running. (Resize/DPI also
        // rebuild the swapchain, in the WM_SIZE case below.)
        case WM_NULL:
            // A posted wake-up from ui_request_redraw(): the redraw flag it set
            // is the whole message, so this only has to consume it.
            //
            // It must NOT call ui_request_redraw() here. That stores the flag
            // and posts WM_NULL again, from inside this very handler, so every
            // wake-up posted the next one: the queue never emptied, the pump
            // below never reached a frame, and the client area stayed at the
            // class background -- a white, frozen window that still accepted
            // clicks. The flag is already set by whoever posted this.
            return 0;
        case WM_PAINT:
            ui_request_redraw();
            break;
        case WM_DPICHANGED:
            // Windows hands over the rectangle this window should occupy at
            // the new scale. Taking it is what keeps the layout the same
            // physical size after a monitor change or a scale change.
            if (lParam != 0) {
                const RECT* suggested = reinterpret_cast<const RECT*>(lParam);
                SetWindowPos(hWnd, nullptr, suggested->left, suggested->top,
                             suggested->right - suggested->left,
                             suggested->bottom - suggested->top,
                             SWP_NOZORDER | SWP_NOACTIVATE);
            }
            // The font factor is deliberately not touched here; see the style
            // block below. Taking the suggested rectangle is enough to keep the
            // window a sane physical size on a monitor change.
            ui_request_redraw();
            break;
        case WM_DISPLAYCHANGE:
        case WM_THEMECHANGED:
        case WM_SYSCOLORCHANGE:
        case WM_ACTIVATE:
        case WM_SETFOCUS:
        case WM_KILLFOCUS:
        case WM_SHOWWINDOW:
            ui_request_redraw();
            break;
        case WM_SIZE:
            // A restored/maximized window must be painted even if the render
            // gate had nothing new to show.
            ui_request_redraw();
            if (g_pd3dDevice != nullptr && g_pd3dDeviceContext != nullptr
                    && g_pSwapChain != nullptr && wParam != SIZE_MINIMIZED) {
                // The immediate context keeps its own reference to the bound
                // target. Release that reference as well before ResizeBuffers.
                g_pd3dDeviceContext->OMSetRenderTargets(0, nullptr, nullptr);
                if (g_mainRenderTargetView) {
                    g_mainRenderTargetView->Release();
                    g_mainRenderTargetView = nullptr;
                }
                const HRESULT resized = g_pSwapChain->ResizeBuffers(
                    0, (UINT)LOWORD(lParam), (UINT)HIWORD(lParam), DXGI_FORMAT_UNKNOWN, 0);
                // If resizing failed, keep rendering to the existing back
                // buffer instead of leaving the window permanently blank.
                ID3D11Texture2D* pBackBuffer = nullptr;
                if (SUCCEEDED(g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer))) && pBackBuffer) {
                    g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
                    pBackBuffer->Release();
                }
                if (FAILED(resized)) ui_request_redraw();
            }
            return 0;
        case WM_SYSCOMMAND:
            if ((wParam & 0xfff0) == SC_KEYMENU) return 0;
            break;
        case WM_CLOSE:
            // User clicked X button — set running=false so the message
            // loop exits, then ui_shutdown() will call fcae_shutdown() which
            // does synchronous DNS restore and cleanup.
            g_app.running.store(false);
            DestroyWindow(hWnd);
            return 0;
        case WM_DESTROY:
            // Trigger full cleanup before the window closes.
            // This ensures tun2socks is killed and TUN adapters are removed
            // even if the user closes the window with X button instead of
            // clicking DISCONNECT first.
            g_app.running.store(false);
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

static bool CreateDeviceD3D(HWND hWnd) {
    DXGI_SWAP_CHAIN_DESC sd = {};
    sd.BufferCount       = 2;
    sd.BufferDesc.Width  = 0;
    sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags              = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage        = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow       = hWnd;
    sd.SampleDesc.Count   = 1;
    sd.SampleDesc.Quality = 0;
    sd.Windowed           = TRUE;
    sd.SwapEffect         = DXGI_SWAP_EFFECT_FLIP_DISCARD;

    UINT createDeviceFlags = 0;
    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL levels[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };

    const D3D_DRIVER_TYPE drivers[] = {
        D3D_DRIVER_TYPE_HARDWARE,
        D3D_DRIVER_TYPE_WARP
        // No D3D_DRIVER_TYPE_REFERENCE: the reference rasterizer is a
        // conformance-validation library that emulates the pipeline in
        // software without any optimization. A shipping UI that lands on it
        // is effectively frozen — the window appears after seconds or
        // minutes of a task that never settles. HARDWARE (any real GPU) or
        // WARP (software D3D11, ample for a 2D UI) is the correct floor;
        // failing to get either should fail startup, not crawl.
    };
    HRESULT device_result = E_FAIL;
    // The flip model presents without a DWM copy; Windows before 10 lacks it.
    for (DXGI_SWAP_EFFECT effect : { DXGI_SWAP_EFFECT_FLIP_DISCARD, DXGI_SWAP_EFFECT_DISCARD }) {
        sd.SwapEffect = effect;
        for (D3D_DRIVER_TYPE driver : drivers) {
            device_result = D3D11CreateDeviceAndSwapChain(
                nullptr, driver, nullptr, createDeviceFlags, levels, 2,
                D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice,
                &featureLevel, &g_pd3dDeviceContext);
            if (SUCCEEDED(device_result) && g_pSwapChain && g_pd3dDevice && g_pd3dDeviceContext)
                break;
            CleanupDeviceD3D();
        }
        if (SUCCEEDED(device_result) && g_pSwapChain) break;
    }
    if (FAILED(device_result) || !g_pSwapChain || !g_pd3dDevice || !g_pd3dDeviceContext)
        return false;

    ID3D11Texture2D* pBackBuffer = nullptr;
    if (SUCCEEDED(g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer))) && pBackBuffer) {
        g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
        pBackBuffer->Release();
    }
    return g_mainRenderTargetView != nullptr;
}

static void CleanupDeviceD3D() {
    release_sponsor_textures();
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
    if (g_pSwapChain)  { g_pSwapChain->Release();  g_pSwapChain = nullptr; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice)  { g_pd3dDevice->Release();  g_pd3dDevice = nullptr; }
}

// Must match IDI_ICON1 in icon.rc (resource id 101 is conventional for first ICON).
#ifndef IDI_ICON1
#define IDI_ICON1 101
#endif

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int) {
    // Kick the runtime/config initializer off first: it does not touch ImGui
    // or the window, so engine setup overlaps window and D3D creation
    // instead of serializing behind it.
    ui_init();

    HINSTANCE inst = hInst ? hInst : GetModuleHandleW(nullptr);

    WNDCLASSEXW wc = {};
    wc.cbSize        = sizeof(wc);
    // Redraw requests arrive from worker threads as a posted message, which
    // must not be filtered for this class, and the window must repaint when it
    // is resized or uncovered.
    // CS_OWNDC: the device context the swap chain presents through belongs to
    // the window class for the life of the window.
    wc.style         = CS_OWNDC | CS_DBLCLKS | CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = inst;
    wc.hIcon         = LoadIconW(inst, MAKEINTRESOURCEW(IDI_ICON1));
    wc.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
    wc.lpszClassName = L"FCAE_VPN_CLASS";
    wc.hIconSm       = (HICON)LoadImageW(inst, MAKEINTRESOURCEW(IDI_ICON1), IMAGE_ICON,
                                         GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON),
                                         LR_DEFAULTCOLOR);
    // An explicit background brush rather than the default white: uncovered
    // edges, and the moments before the first frame reaches the flip chain,
    // must show the UI's own background, not a white sheet.
    wc.hbrBackground = CreateSolidBrush(RGB(13, 13, 20));   // 0.05, 0.05, 0.08
    if (!wc.hIcon) {
        wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    }
    if (!wc.hIconSm) {
        wc.hIconSm = wc.hIcon;
    }
    if (!RegisterClassExW(&wc))
        return 1;

    // Size in DIPs scaled to the primary monitor's DPI. Before the window
    // exists there is no per-window DPI to ask for, so this reads the system's;
    // WM_DPICHANGED below fixes the window up if it opens on another monitor.
    int window_w = kWindowWidth;
    int window_h = kWindowHeight;
    clamp_to_screen(window_w, window_h);
    HWND hWnd = CreateWindowW(wc.lpszClassName, L"FCAE VPN",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, window_w, window_h,
        nullptr, nullptr, inst, nullptr);
    if (!hWnd) {
        UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    // A worker thread's redraw request must be able to wake this window's
    // message loop, so the window is registered before the loop can park.
    ui_set_window_handle(hWnd);

    // Enable dark title bar on Windows 10/11 (requires 1809+)
    {
        BOOL use_dark = TRUE;
        // DWMWA_USE_IMMERSIVE_DARK_MODE = 20 (before 20H1) or 19 (20H1+)
        // Try both values for compatibility
        DwmSetWindowAttribute(hWnd, 20, &use_dark, sizeof(use_dark));
        DwmSetWindowAttribute(hWnd, 19, &use_dark, sizeof(use_dark));
    }

    if (!CreateDeviceD3D(hWnd)) { CleanupDeviceD3D(); UnregisterClassW(wc.lpszClassName, wc.hInstance); return 1; }

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
    // A base font at a readable size, replacing ImGui's embedded 13 px
    // ProggyClean bitmap font -- which is what made the whole UI read as tiny.
    // The old 13 px bitmap face cannot be enlarged without turning into mush,
    // which is why simply raising the scale factor never fixed it. This is the size the
    // layout in ui_render.cpp is designed against, and the user's
    // ui_scale_percent multiplies on top of it through style.FontScaleMain.
    {
        ImFontConfig font_cfg;
        font_cfg.SizePixels = kUiBaseFontSize;
        // Named explicitly rather than through AddFontDefault(): that one picks
        // between the bitmap and vector faces from the expected context size,
        // which is still unset at this point, so it could hand back the 13 px
        // bitmap face and ignore SizePixels.
        ImGui::GetIO().Fonts->AddFontDefaultVector(&font_cfg);
    }
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    ImGui::StyleColorsDark();
    ImGuiStyle& style = ImGui::GetStyle();
    // Left at 1.0 on purpose: the window is created at its designed pixel size
    // and the UI lays itself out in those same pixels. Scaling the font by the
    // monitor DPI here as well is what made text overflow its rows at 150%.
    // The user's own text scale arrives from ui_frame() as FontScaleMain.
    style.FontScaleDpi     = 1.0f;
    // The size the layout is designed against, so a card's heights and the
    // action row's 32 px floor are computed from the same number the glyphs are
    // drawn at. Without this it defaults to the font's legacy size on the first
    // frame and the two can disagree.
    style.FontSizeBase     = kUiBaseFontSize;
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
    colors[ImGuiCol_FrameBg]         = ImVec4(0.14f, 0.14f, 0.20f, 1.0f);
    colors[ImGuiCol_FrameBgHovered]  = ImVec4(0.18f, 0.18f, 0.26f, 1.0f);
    colors[ImGuiCol_Button]          = ImVec4(0.16f, 0.40f, 0.60f, 1.0f);
    colors[ImGuiCol_ButtonHovered]   = ImVec4(0.20f, 0.50f, 0.70f, 1.0f);
    colors[ImGuiCol_Tab]             = ImVec4(0.12f, 0.12f, 0.18f, 1.0f);
    colors[ImGuiCol_TabHovered]      = ImVec4(0.20f, 0.30f, 0.45f, 1.0f);
    colors[ImGuiCol_SliderGrab]      = ImVec4(0.30f, 0.60f, 0.80f, 1.0f);

    const bool imgui_win32_initialized = ImGui_ImplWin32_Init(hWnd);
    const bool imgui_dx11_initialized = imgui_win32_initialized
        && ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);
    if (!imgui_win32_initialized || !imgui_dx11_initialized) {
        if (imgui_dx11_initialized) ImGui_ImplDX11_Shutdown();
        if (imgui_win32_initialized) ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext();
        CleanupDeviceD3D();
        DestroyWindow(hWnd);
        UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 1;
    }
    g_imgui_win32_ready = true;
    ShowWindow(hWnd, SW_SHOWDEFAULT);
    UpdateWindow(hWnd);

    // Paint only for input, changed UI content, or an explicit redraw request.
    // Block on the message queue while idle instead of repainting unconditionally.
    bool done = false;
    bool sponsor_window_visible = false;
    constexpr auto min_frame_interval = std::chrono::milliseconds(16);
    auto last_frame_time = std::chrono::steady_clock::now() - min_frame_interval;
    auto last_input_time = std::chrono::steady_clock::now();
    POINT last_mouse_pos = {};
    bool have_mouse_pos = false;
    constexpr auto interaction_tail   = std::chrono::milliseconds(700);

    while (!done && g_app.running.load()) {
        const auto loop_now = std::chrono::steady_clock::now();
        const bool interacting = (loop_now - last_input_time) < interaction_tail;

        // Keep polling while hidden so the next visible frame is fresh.
        bool paintable = !IsIconic(hWnd) && IsWindowVisible(hWnd);

        DWORD timeout;
        if (!paintable)         timeout = 1000;
        else if (interacting) {
            const auto next_frame = last_frame_time + min_frame_interval;
            const auto remaining = next_frame - loop_now;
            timeout = remaining > std::chrono::steady_clock::duration::zero()
                ? (DWORD)std::chrono::duration_cast<std::chrono::milliseconds>(remaining + std::chrono::milliseconds(1)).count()
                : 0;
        }
        else                    timeout = (DWORD)ui_sleep_ms();

        MsgWaitForMultipleObjects(0, nullptr, FALSE, timeout, QS_ALLINPUT);

        // Drain pending window messages; real input counts as interaction.
        bool got_input = false;
        MSG msg;
        while (PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            if (msg.message == WM_QUIT) { done = true; break; }
            switch (msg.message) {
                case WM_MOUSEMOVE:
                    // Ignore repeated positions so WM_MOUSEMOVE cannot pin rendering at the interaction rate.
                    if (!have_mouse_pos || msg.pt.x != last_mouse_pos.x || msg.pt.y != last_mouse_pos.y) {
                        last_mouse_pos = msg.pt;
                        have_mouse_pos = true;
                        got_input = true;
                    }
                    break;
                case WM_LBUTTONDOWN: case WM_LBUTTONUP:
                case WM_RBUTTONDOWN: case WM_RBUTTONUP:
                case WM_MBUTTONDOWN: case WM_MBUTTONUP:
                case WM_MOUSEWHEEL:  case WM_MOUSEHWHEEL:
                case WM_KEYDOWN:     case WM_KEYUP:
                case WM_SYSKEYDOWN:  case WM_SYSKEYUP:
                case WM_CHAR:        case WM_UNICHAR:
                    got_input = true;
                    break;
                default:
                    break;
            }
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        if (done) break;
        if (got_input) last_input_time = std::chrono::steady_clock::now();
        paintable = !IsIconic(hWnd) && IsWindowVisible(hWnd);

        // Hidden windows release sponsor audio; visible windows claim it again.
        if (!paintable) {
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
        ui_set_window_focused(GetForegroundWindow() == hWnd);

        const auto frame_now = std::chrono::steady_clock::now();
        if (frame_now - last_frame_time < min_frame_interval) continue;

        const bool active = got_input || (frame_now - last_input_time) < interaction_tail;
        if (!ui_should_render(active)) continue;

        // A lost D3D device cannot render; normal shutdown still owns teardown.
        if (!g_pd3dDevice || !g_pd3dDeviceContext || !g_pSwapChain || !g_mainRenderTargetView)
            continue;

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        ui_frame();

        ImGui::Render();

        // ImGui has a frame open from NewFrame() until Render(), and its
        // assertion against a second NewFrame() is compiled out in Release.
        // Any `continue` between the two therefore corrupted the next frame --
        // which is exactly what a WM_SIZE arriving mid-frame can cause, because
        // it can take the render target away here. Abandoning the frame costs
        // one unlock, and the next NewFrame() opens a clean one.
        ImGui::EndFrame();
        if (!g_mainRenderTargetView) continue;

        const float clear_color[4] = { 0.05f, 0.05f, 0.08f, 1.0f };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        // Ignore Present failure; the next frame sees the device guard.
        g_pSwapChain->Present(1, 0);
        last_frame_time = std::chrono::steady_clock::now();
    }

    ui_set_window_handle(nullptr);
    ui_shutdown();

    g_imgui_win32_ready = false;
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    CleanupDeviceD3D();
    // A hand-off (TUN start needing elevation) already destroyed the window on
    // this thread to get it off screen before the route/DNS restore ran, so
    // this must not destroy it twice.
    if (IsWindow(hWnd)) DestroyWindow(hWnd);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
    if (wc.hbrBackground) DeleteObject(wc.hbrBackground);
    return 0;
}

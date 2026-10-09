#ifndef UNICODE
#define UNICODE
#endif
#include <windows.h>
#include <d3d11.h>
#include <dwmapi.h>
#include <tchar.h>
#include <chrono>

#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"

#include "ui_render.h"

static ID3D11Device*           g_pd3dDevice       = nullptr;
static ID3D11DeviceContext*    g_pd3dDeviceContext = nullptr;
static IDXGISwapChain*         g_pSwapChain       = nullptr;
static ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;
static ID3D11Texture2D*        g_sponsor_textures[2] = {};
static ID3D11ShaderResourceView* g_sponsor_views[2] = {};
static uint64_t g_sponsor_loaded[2] = {};
static int g_sponsor_texture_width[2] = {};
static int g_sponsor_texture_height[2] = {};
static bool g_imgui_win32_ready = false;

ImTextureID sponsor_texture_update(const uint8_t* rgba, int width, int height, uint64_t generation, int slot) {
    const int index = slot == 1 ? 1 : 0;
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
    for (int i = 0; i < 2; ++i) {
        if (g_sponsor_views[i]) { g_sponsor_views[i]->Release(); g_sponsor_views[i] = nullptr; }
        if (g_sponsor_textures[i]) { g_sponsor_textures[i]->Release(); g_sponsor_textures[i] = nullptr; }
        g_sponsor_loaded[i] = 0;
        g_sponsor_texture_width[i] = 0;
        g_sponsor_texture_height[i] = 0;
    }
}

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

static void CleanupDeviceD3D();

static LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (g_imgui_win32_ready && ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return 1;

    switch (msg) {
        // Window events that change what should be on screen: ask for exactly
        // one repaint instead of leaving the loop free-running. (Resize/DPI also
        // rebuild the swapchain, in the WM_SIZE case below.)
        case WM_PAINT:
        case WM_DPICHANGED:
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
            if (g_pd3dDevice != nullptr && g_pSwapChain != nullptr && wParam != SIZE_MINIMIZED) {
                // Release old RTV before ResizeBuffers invalidates its backing buffer
                if (g_mainRenderTargetView) {
                    g_mainRenderTargetView->Release();
                    g_mainRenderTargetView = nullptr;
                }
                if (FAILED(g_pSwapChain->ResizeBuffers(0, (UINT)LOWORD(lParam), (UINT)HIWORD(lParam), DXGI_FORMAT_UNKNOWN, 0)))
                    return 0;
                ID3D11Texture2D* pBackBuffer = nullptr;
                if (SUCCEEDED(g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer))) && pBackBuffer) {
                    g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
                    pBackBuffer->Release();
                }
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
        D3D_DRIVER_TYPE_WARP,
        D3D_DRIVER_TYPE_REFERENCE
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
    HINSTANCE inst = hInst ? hInst : GetModuleHandleW(nullptr);

    WNDCLASSEXW wc = {};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_CLASSDC;
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = inst;
    wc.hIcon         = LoadIconW(inst, MAKEINTRESOURCEW(IDI_ICON1));
    wc.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
    wc.lpszClassName = L"FCAE_VPN_CLASS";
    wc.hIconSm       = (HICON)LoadImageW(inst, MAKEINTRESOURCEW(IDI_ICON1), IMAGE_ICON,
                                         GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON),
                                         LR_DEFAULTCOLOR);
    if (!wc.hIcon) {
        wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    }
    if (!wc.hIconSm) {
        wc.hIconSm = wc.hIcon;
    }
    if (!RegisterClassExW(&wc))
        return 1;

    HWND hWnd = CreateWindowW(wc.lpszClassName, L"FCAE VPN",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        100, 100, 1024, 700, nullptr, nullptr, inst, nullptr);
    if (!hWnd) {
        UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 1;
    }

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

    ui_init();

    // Paint only for input, changed UI content, or an explicit redraw request.
    // Block on the message queue while idle instead of repainting unconditionally.
    bool done = false;
    bool sponsor_window_visible = false;
    auto last_frame_time = std::chrono::steady_clock::now();
    auto last_input_time = last_frame_time;
    POINT last_mouse_pos = {};
    bool have_mouse_pos = false;
    constexpr auto min_frame_interval = std::chrono::milliseconds(33);
    constexpr auto interaction_tail   = std::chrono::milliseconds(700);

    while (!done && g_app.running.load()) {
        const auto loop_now = std::chrono::steady_clock::now();
        const bool interacting = (loop_now - last_input_time) < interaction_tail;

        // Keep polling while hidden so the next visible frame is fresh.
        bool paintable = !IsIconic(hWnd) && IsWindowVisible(hWnd);

        DWORD timeout;
        if (!paintable)         timeout = 1000;
        else if (interacting)   timeout = (DWORD)min_frame_interval.count();
        else                    timeout = (DWORD)ui_sleep_ms();

        MsgWaitForMultipleObjects(0, nullptr, FALSE, timeout, QS_ALLINPUT);

        // Drain pending window messages; real input counts as interaction.
        bool got_input = false;
        MSG msg;
        while (PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            if (msg.message == WM_QUIT) { done = true; break; }
            switch (msg.message) {
                case WM_MOUSEMOVE:
                    // Ignore repeated positions so WM_MOUSEMOVE cannot pin rendering at 30 FPS.
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

        // WM_SIZE can invalidate the render target between NewFrame and Render.
        if (!g_mainRenderTargetView) continue;

        const float clear_color[4] = { 0.05f, 0.05f, 0.08f, 1.0f };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        // Ignore Present failure; the next frame sees the device guard.
        g_pSwapChain->Present(1, 0);
        last_frame_time = std::chrono::steady_clock::now();
    }

    ui_shutdown();

    g_imgui_win32_ready = false;
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    CleanupDeviceD3D();
    DestroyWindow(hWnd);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
    return 0;
}

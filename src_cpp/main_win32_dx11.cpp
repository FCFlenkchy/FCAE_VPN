// FCAE VPN — Windows DirectX 11 + Win32 + Dear ImGui frontend
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

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

static void CleanupDeviceD3D();

static LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
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
    sd.SwapEffect         = DXGI_SWAP_EFFECT_DISCARD;

    UINT createDeviceFlags = 0;
    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL levels[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };

    if (D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, createDeviceFlags,
        levels, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext) != S_OK)
        return false;

    if (!g_pSwapChain || !g_pd3dDevice) {
        CleanupDeviceD3D();
        return false;
    }

    ID3D11Texture2D* pBackBuffer = nullptr;
    if (SUCCEEDED(g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer))) && pBackBuffer) {
        g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
        pBackBuffer->Release();
    }
    return g_mainRenderTargetView != nullptr;
}

static void CleanupDeviceD3D() {
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
    RegisterClassExW(&wc);
    HWND hWnd = CreateWindowW(wc.lpszClassName, L"FCAE VPN",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        100, 100, 1024, 700, nullptr, nullptr, inst, nullptr);

    // Enable dark title bar on Windows 10/11 (requires 1809+)
    {
        BOOL use_dark = TRUE;
        // DWMWA_USE_IMMERSIVE_DARK_MODE = 20 (before 20H1) or 19 (20H1+)
        // Try both values for compatibility
        DwmSetWindowAttribute(hWnd, 20, &use_dark, sizeof(use_dark));
        DwmSetWindowAttribute(hWnd, 19, &use_dark, sizeof(use_dark));
    }

    if (!CreateDeviceD3D(hWnd)) { CleanupDeviceD3D(); UnregisterClassW(wc.lpszClassName, wc.hInstance); return 1; }

    ShowWindow(hWnd, SW_SHOWDEFAULT);
    UpdateWindow(hWnd);

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

    ImGui_ImplWin32_Init(hWnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    ui_init();

    // ── Event-driven, change-gated render loop ───────────────────────────────
    // A frame is painted only when
    //   * the user interacts with the window (hover/drag/type — capped at 60 FPS
    //     and kept alive for a short tail after the last input),
    //   * the fingerprint of everything the UI paints changed (telemetry stats,
    //     logs, transient status text, settings), or
    //   * a window event asked for a repaint (resize, DPI, focus, theme, …).
    //
    // Previously the loop woke every 1 s and repainted unconditionally, and any
    // stray window message (WS_EX_COMPOSITED/DWM redraws, hidden tooltip windows,
    // the IME, a hovering cursor…) woke it early and cost a full frame — which is
    // where the idle CPU went. Now the thread blocks on the message queue and an
    // idle window is genuinely 0% CPU: no periodic repaint, and messages that
    // don't change anything (a repeated WM_MOUSEMOVE at the same position, for
    // example) no longer force a frame.
    bool done = false;
    auto last_frame_time = std::chrono::steady_clock::now();
    auto last_input_time = last_frame_time;
    POINT last_mouse_pos = {};
    bool have_mouse_pos = false;
    constexpr auto min_frame_interval = std::chrono::milliseconds(16);   // ~60 FPS cap
    constexpr auto interaction_tail   = std::chrono::milliseconds(700);  // smooth for this long after the last input

    while (!done && g_app.running.load()) {
        const auto loop_now = std::chrono::steady_clock::now();
        const bool interacting = (loop_now - last_input_time) < interaction_tail;

        // A minimized or hidden window has nothing to paint. Sleep in 1 s steps
        // (keeps the engine-state poll alive) and leave a pending redraw request
        // alone so the first frame after restoring is guaranteed to be fresh.
        const bool paintable = !IsIconic(hWnd) && IsWindowVisible(hWnd);

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
                    // Only movement counts. Windows repeats WM_MOUSEMOVE at the
                    // same position, and treating those as input would pin the
                    // loop at 60 FPS forever.
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

        // Hidden window: keep the engine poll alive, paint nothing.
        if (!paintable) continue;

        // Throttle to 60 FPS max — skip the frame if it is too early.
        const auto frame_now = std::chrono::steady_clock::now();
        if (frame_now - last_frame_time < min_frame_interval) continue;

        // Skip frames whose pixels would be identical to the last painted frame.
        const bool active = got_input || (frame_now - last_input_time) < interaction_tail;
        if (!ui_should_render(active)) continue;

        // ── Crash-safe D3D11 guard ──────────────────────────────
        // If the device was lost or context became invalid (driver crash,
        // GPU hang, or rapid suspend/resume), skip the frame instead of
        // crashing the process.  The window will remain visible but frozen;
        // the engine threads continue running in the background.
        if (!g_pd3dDevice || !g_pd3dDeviceContext || !g_pSwapChain || !g_mainRenderTargetView)
            continue;

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        ui_frame();

        ImGui::Render();

        // Double-check RTV again after ImGui::Render — resizing or
        // WM_SIZE between NewFrame and Render can invalidate the RTV.
        if (!g_mainRenderTargetView) continue;

        const float clear_color[4] = { 0.05f, 0.05f, 0.08f, 1.0f };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        // Present can fail if device lost (DXGI_ERROR_DEVICE_REMOVED).
        // Ignore the HRESULT — next frame will skip via the null guard above.
        g_pSwapChain->Present(1, 0);
        last_frame_time = std::chrono::steady_clock::now();
    }

    ui_shutdown();

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    CleanupDeviceD3D();
    DestroyWindow(hWnd);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
    return 0;
}

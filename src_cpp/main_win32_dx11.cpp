#include "ui_frame_pacing.h"
#include <cmath>
#include "ui_style.h"
#ifndef UNICODE
#define UNICODE
#endif
#include <windows.h>
#include "windows_privilege.h"
#include <d3d11.h>
#include <dwmapi.h>
#include <tchar.h>
#include <chrono>
#include <shellapi.h>
#include <cwchar>
#include <cerrno>
#include <algorithm>
#include <functional>

#include "imgui.h"
#if defined(FCAE_HAVE_FREETYPE)
#include "imgui_freetype.h"
#endif
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"

#include "ui_render.h"

extern "C" void fcae_ui_diagnostic(uint32_t event, uint32_t value);

static ID3D11Device*           g_pd3dDevice       = nullptr;
static ID3D11DeviceContext*    g_pd3dDeviceContext = nullptr;
static IDXGISwapChain*         g_pSwapChain       = nullptr;
static ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;
static bool g_has_presented_frame = false;
static UINT g_resize_width = 0;
static UINT g_resize_height = 0;
static bool g_device_lost = false;
static bool g_swapchain_occluded = false;
static ID3D11Texture2D*        g_sponsor_textures[3] = {};
static ID3D11ShaderResourceView* g_sponsor_views[3] = {};
static uint64_t g_sponsor_loaded[3] = {};
static int g_sponsor_texture_width[3] = {};
static int g_sponsor_texture_height[3] = {};
static bool g_imgui_win32_ready = false;
static bool g_imgui_dx11_ready = false;
static bool g_live_resize = false;
static bool g_drawing_frame = false;
static constexpr UINT_PTR kResizeTimer = 0xFCAE;
static std::function<void()> g_draw_frame;
// The size the window was created at, in physical pixels. Kept so the first
// WM_DPICHANGED after creation cannot be mistaken for a user resize.
static int g_created_width  = 0;
static int g_created_height = 0;

#include <unordered_map>
#include <shellapi.h>
static std::unordered_map<std::string,ID3D11ShaderResourceView*> app_icon_views;
static void release_app_icons() {
    for(auto& entry:app_icon_views)if(entry.second)entry.second->Release();
    app_icon_views.clear();
}
ImTextureID app_routing_icon(const std::string& executable) {
    if(!g_pd3dDevice)return ImTextureID{};
    auto found=app_icon_views.find(executable);if(found!=app_icon_views.end())return (ImTextureID)(intptr_t)found->second;
    if(app_icon_views.size()>=512)return ImTextureID{};
    ID3D11ShaderResourceView* view=nullptr;
    const int count=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,executable.c_str(),-1,nullptr,0);
    if(count>0) {
        std::wstring path(count,L'\0');MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,executable.c_str(),-1,path.data(),count);
        SHFILEINFOW info{};
        if(SHGetFileInfoW(path.c_str(),0,&info,sizeof(info),SHGFI_ICON|SHGFI_LARGEICON)&&info.hIcon) {
            BITMAPINFO bitmap{};bitmap.bmiHeader.biSize=sizeof(BITMAPINFOHEADER);bitmap.bmiHeader.biWidth=48;bitmap.bmiHeader.biHeight=-48;bitmap.bmiHeader.biPlanes=1;bitmap.bmiHeader.biBitCount=32;bitmap.bmiHeader.biCompression=BI_RGB;
            void* pixels=nullptr;HDC dc=CreateCompatibleDC(nullptr);HBITMAP dib=dc?CreateDIBSection(dc,&bitmap,DIB_RGB_COLORS,&pixels,nullptr,0):nullptr;
            if(dib&&pixels){
                auto old=SelectObject(dc,dib);memset(pixels,0,48*48*4);DrawIconEx(dc,0,0,info.hIcon,48,48,0,nullptr,DI_NORMAL);
                auto bytes=static_cast<unsigned char*>(pixels);bool alpha=false;for(int i=0;i<48*48;++i)alpha|=bytes[i*4+3]!=0;
                if(!alpha)for(int i=0;i<48*48;++i)bytes[i*4+3]=255;
                D3D11_TEXTURE2D_DESC desc{};desc.Width=desc.Height=48;desc.MipLevels=desc.ArraySize=1;desc.Format=DXGI_FORMAT_B8G8R8A8_UNORM;desc.SampleDesc.Count=1;desc.Usage=D3D11_USAGE_IMMUTABLE;desc.BindFlags=D3D11_BIND_SHADER_RESOURCE;
                D3D11_SUBRESOURCE_DATA data{};data.pSysMem=pixels;data.SysMemPitch=48*4;ID3D11Texture2D* texture=nullptr;
                if(SUCCEEDED(g_pd3dDevice->CreateTexture2D(&desc,&data,&texture))){g_pd3dDevice->CreateShaderResourceView(texture,nullptr,&view);texture->Release();}
                SelectObject(dc,old);
            }
            if(dib)DeleteObject(dib);if(dc)DeleteDC(dc);DestroyIcon(info.hIcon);
        }
    }
    app_icon_views.emplace(executable,view);return (ImTextureID)(intptr_t)view;
}

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
    release_app_icons();
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
// The window's client area, in pixels. Wider than it is tall on purpose: the
// settings pages and the log tail sit side by side, so width buys layout room
// while height mostly buys empty space. 800 rather than the previous 860 leaves
// the title bar and taskbar some breathing room on a 1080p display instead of
// the frame hugging the bottom of the screen.
//
// Deliberately not scaled by DPI: an earlier revision scaled both the window and
// the ImGui font metrics by the monitor factor, which applied it twice -- the
// window grew 1.5x and the text inside it 1.5x again, so the layout overflowed.
// One factor owns the scaling, and it is the user's ui_scale_percent, which
// grows the text without moving the frame.
static constexpr DWORD kWindowStyle = WS_OVERLAPPEDWINDOW;
static constexpr int kWindowWidth  = 1280;
static constexpr int kWindowHeight = 800;

// The base UI font size, in pixels, and what the whole window is sized against.
//
// 22 px is about 1.7x the 13 px that ImGui's embedded default face used to give
// this UI -- which is what the UI was stuck with when it read as far too small.
// It was 26 px (exactly 2x) for a while and read as zoomed in: every row grew,
// so fewer of them fitted on screen for no gain in legibility. 22 keeps the
// readable size and gives the rows back.
//
// The user's ui_scale_percent still multiplies on top of it through
// style.FontScaleMain, so this is the floor, not the ceiling, and the layout's
// own constants are computed from measured text rather than from fixed pixels.
// Anything still fixed (the modals' 680x620 and so on) is clamped to the
// viewport and scrolls its contents.
static constexpr float kUiBaseFontSize = 22.0f;

// Work out where the window goes.
//
static void place_window(int& x, int& y, int& width, int& height) {
    MONITORINFO info = {};
    info.cbSize = sizeof(info);
    const HMONITOR monitor = MonitorFromPoint(POINT{0, 0}, MONITOR_DEFAULTTOPRIMARY);
    if (!GetMonitorInfoW(monitor, &info)) {
        x = CW_USEDEFAULT;
        y = CW_USEDEFAULT;
        return;
    }
    const RECT& work = info.rcWork;
    const int work_w = work.right - work.left;
    const int work_h = work.bottom - work.top;

    // Room for the frame: measured rather than guessed, because the caption and
    // border thicknesses change with the Windows version and the user's theme.
    RECT frame = {0, 0, width, height};
    AdjustWindowRectEx(&frame, kWindowStyle, FALSE, 0);
    const int frame_w = frame.right - frame.left;
    const int frame_h = frame.bottom - frame.top;

    if (width  + (frame_w - width)  > work_w - 40) width  = work_w - (frame_w - width) - 40;
    if (height + (frame_h - height) > work_h - 40) height = work_h - (frame_h - height) - 40;
    if (width  < 480) width  = 480;
    if (height < 360) height = 360;

    frame = RECT{0, 0, width, height};
    AdjustWindowRectEx(&frame, kWindowStyle, FALSE, 0);
    const int size_w = frame.right - frame.left;
    const int size_h = frame.bottom - frame.top;

    x = work.left + (work_w - size_w) / 2;
    y = work.top  + (work_h - size_h) / 2;
    // Keep a slight upward bias without placing the window too high.
    y -= size_h / 20;
    if (y < work.top) y = work.top;
}

static void CleanupDeviceD3D();

static constexpr UINT kTrayMessage = WM_APP + 41;
static constexpr UINT kTrayIconId = 1;
static UINT g_taskbar_created = 0;
static bool g_tray_installed = false;

static bool install_tray(HWND window) {
    NOTIFYICONDATAW data = {};
    data.cbSize = sizeof(data);
    data.hWnd = window;
    data.uID = kTrayIconId;
    data.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    data.uCallbackMessage = kTrayMessage;
    data.hIcon = reinterpret_cast<HICON>(GetClassLongPtrW(window, GCLP_HICONSM));
    if (!data.hIcon) data.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    wcscpy_s(data.szTip, L"FCAE VPN");
    g_tray_installed = Shell_NotifyIconW(NIM_ADD, &data) != FALSE;
    return g_tray_installed;
}

static void remove_tray(HWND window) {
    if (!g_tray_installed) return;
    NOTIFYICONDATAW data = {};
    data.cbSize = sizeof(data);
    data.hWnd = window;
    data.uID = kTrayIconId;
    Shell_NotifyIconW(NIM_DELETE, &data);
    g_tray_installed = false;
}

static void show_main_window(HWND window) {
    ShowWindow(window, IsIconic(window) ? SW_RESTORE : SW_SHOW);
    SetForegroundWindow(window);
    ui_request_redraw();
}

static void show_tray_menu(HWND window) {
    HMENU menu = CreatePopupMenu();
    if (!menu) return;
    constexpr UINT open_id = 1, toggle_id = 2, exit_id = 3, tun_id = 4;
    AppendMenuW(menu, MF_STRING, open_id, L"Open FCAE VPN");
    FcaeTelemetry telemetry = {};
    telemetry.struct_size = sizeof(telemetry);
    telemetry.abi_version = FCAE_ABI_VERSION;
    const bool ready = ui_runtime_ready();
    const bool have_state = ready && fcae_get_telemetry(&telemetry) == FCAE_OK;
    const bool error = have_state && telemetry.state == FCAE_STATE_ERROR;
    const bool active = g_app.start_busy.load() || (have_state &&
        telemetry.state != FCAE_STATE_DISCONNECTED && !error) || (ready && fcae_tun_paused());
    const wchar_t* action = error ? L"Clear error" : active ? L"Disconnect" : L"Connect";
    AppendMenuW(menu, MF_STRING | (ready && have_state ? MF_ENABLED : MF_GRAYED), toggle_id, action);
    const bool tun_paused = ready && fcae_tun_paused();
    if (g_app.mode == 1) {
        const bool tun_control_ready = have_state &&
            (telemetry.state == FCAE_STATE_CONNECTED || tun_paused);
        AppendMenuW(menu, MF_STRING | (tun_control_ready ? MF_ENABLED : MF_GRAYED),
                    tun_id, tun_paused ? L"Start" : L"Stop");
    }
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, exit_id, L"Exit FCAE VPN");
    POINT point = {};
    GetCursorPos(&point);
    SetForegroundWindow(window);
    const UINT choice = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON,
                                      point.x, point.y, 0, window, nullptr);
    DestroyMenu(menu);
    // Required by the shell menu convention so it dismisses correctly.
    PostMessageW(window, WM_NULL, 0, 0);
    if (choice == open_id) show_main_window(window);
    else if (choice == toggle_id) {
        // The existing UI action owns validation, UAC handoff and cancellation.
        // Showing it also makes any validation error or consent prompt visible.
        show_main_window(window);
        ui_request_tray_toggle(error ? 3 : active ? 2 : 1);
    } else if (choice == tun_id) {
        // Reuse the UI control and re-check the displayed state in its next frame.
        show_main_window(window);
        ui_request_tray_tun_control(tun_paused);
    } else if (choice == exit_id) {
        DestroyWindow(window); // WM_DESTROY exits the loop and runs ui_shutdown.
    }
}

static LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (g_taskbar_created && msg == g_taskbar_created) {
        g_tray_installed = false;
        if (!install_tray(hWnd) && !IsWindowVisible(hWnd)) show_main_window(hWnd);
        return 0;
    }
    if (msg == kTrayMessage && wParam == kTrayIconId) {
        if (lParam == WM_LBUTTONUP || lParam == WM_LBUTTONDBLCLK) show_main_window(hWnd);
        else if (lParam == WM_RBUTTONUP || lParam == WM_CONTEXTMENU) show_tray_menu(hWnd);
        return 0;
    }
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
        case WM_ERASEBKGND:
            // D3D paints the whole client area. A separate GDI erase between
            // focus/desktop restoration and Present can flash the background.
            if (g_imgui_win32_ready && g_mainRenderTargetView && g_has_presented_frame) return 1;
            break;
        case WM_PAINT:
            ui_request_redraw();
            break;
        case WM_ENTERSIZEMOVE:
            g_live_resize = true;
            SetTimer(hWnd, kResizeTimer, 16, nullptr);
            return 0;
        case WM_EXITSIZEMOVE:
            KillTimer(hWnd, kResizeTimer);
            g_live_resize = false;
            ui_request_redraw();
            return 0;
        case WM_TIMER:
            if (wParam == kResizeTimer) {
                // DefWindowProc runs a modal message loop while an edge is
                // dragged. Paint here too, instead of stretching the old frame.
                if (g_live_resize && g_draw_frame) g_draw_frame();
                return 0;
            }
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
        case WM_ACTIVATEAPP:
        case WM_SETFOCUS:
        case WM_KILLFOCUS:
        case WM_SHOWWINDOW:
            ui_request_redraw();
            break;
        case WM_GETMINMAXINFO: {
            RECT minimum = {0, 0, 480, 360};
            AdjustWindowRectEx(&minimum, kWindowStyle, FALSE, 0);
            auto* limits = reinterpret_cast<MINMAXINFO*>(lParam);
            limits->ptMinTrackSize.x = minimum.right - minimum.left;
            limits->ptMinTrackSize.y = minimum.bottom - minimum.top;
            return 0;
        }
        case WM_SIZE:
            // A restored/maximized window must be painted even if the render
            // gate had nothing new to show.
            ui_request_redraw();
            if (wParam != SIZE_MINIMIZED && LOWORD(lParam) && HIWORD(lParam)) {
                g_resize_width = LOWORD(lParam);
                g_resize_height = HIWORD(lParam);
            }
            return 0;
        case WM_SYSCOMMAND:
            if ((wParam & 0xfff0) == SC_KEYMENU) return 0;
            break;
        case WM_CLOSE:
            // Keep the session alive, even when disconnected. Never hide the
            // only window if the notification icon could not be installed.
            if (g_tray_installed || install_tray(hWnd)) {
                ShowWindow(hWnd, SW_HIDE);
            } else {
                MessageBoxW(hWnd, L"The notification-area icon could not be created. FCAE will remain open.",
                            L"FCAE VPN", MB_OK | MB_ICONWARNING);
            }
            return 0;
        case WM_DESTROY:
            remove_tray(hWnd);
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
    sd.Flags              = 0;
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
    g_has_presented_frame = false;
    release_sponsor_textures();
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
    if (g_pSwapChain)  { g_pSwapChain->Release();  g_pSwapChain = nullptr; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice)  { g_pd3dDevice->Release();  g_pd3dDevice = nullptr; }
}

// All D3D resource changes stay outside WndProc and outside an ImGui frame.
static bool resize_target() {
    if (!g_resize_width || !g_resize_height) return true;
    const UINT width = g_resize_width, height = g_resize_height;
    g_pd3dDeviceContext->OMSetRenderTargets(0, nullptr, nullptr);
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
    const HRESULT resized = g_pSwapChain->ResizeBuffers(0, width, height, DXGI_FORMAT_UNKNOWN, 0);
    if (FAILED(resized)) return false;
    ID3D11Texture2D* buffer = nullptr;
    const HRESULT fetched = g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&buffer));
    if (FAILED(fetched) || !buffer) return false;
    const HRESULT created = g_pd3dDevice->CreateRenderTargetView(buffer, nullptr, &g_mainRenderTargetView);
    buffer->Release();
    if (FAILED(created)) return false;
    g_resize_width = g_resize_height = 0;
    g_has_presented_frame = false;
    ui_request_redraw();
    return true;
}

struct ElevatedWindow {
    HANDLE ready = nullptr;
    RECT bounds = {};
    int show = SW_SHOWNORMAL;
    bool placed = false;
    ~ElevatedWindow() { if (ready) CloseHandle(ready); }
};

static bool read_elevated_window(ElevatedWindow& handoff) {
    int count = 0;
    LPWSTR* args = CommandLineToArgvW(GetCommandLineW(), &count);
    if (!args) return true;
    if (count >= 3 && std::wcscmp(args[1], L"--fcae-wait-parent") == 0) {
        if (!fcae_windows_process_admin(GetCurrentProcess())) {
            LocalFree(args);
            MessageBoxW(nullptr,L"Windows launched the requested administrator instance without administrator rights. FCAE will keep the original window open instead of requesting elevation repeatedly. Check UAC and application compatibility settings (RunAsInvoker), or start FCAE as administrator.",L"FCAE: administrator access was not granted",MB_OK|MB_ICONERROR);
            return false;
        }
        wchar_t* end = nullptr;
        errno = 0;
        const unsigned long pid = std::wcstoul(args[2], &end, 10);
        if (!errno && end != args[2] && *end == L'\0' && pid && pid != GetCurrentProcessId()) {
            wchar_t name[96];
            std::swprintf(name, 96, L"Local\\FCAE.UI.Ready.%lu", pid);
            handoff.ready = OpenEventW(EVENT_MODIFY_STATE, FALSE, name);
        }
        if (!handoff.ready) {
            const DWORD error = GetLastError();
            fcae_ui_diagnostic(12, error);
            LocalFree(args);
            MessageBoxW(nullptr, L"The administrator handoff event could not be opened. The original FCAE window has been kept open. Close extra copies and retry CONNECT.", L"FCAE: administrator handoff failed", MB_OK | MB_ICONERROR);
            return false;
        }
        if (handoff.ready && count == 9 && std::wcscmp(args[3], L"--fcae-window") == 0) {
            long values[5] = {};
            bool valid = true;
            for (int i = 0; i < 5; ++i) {
                errno = 0;
                values[i] = std::wcstol(args[4 + i], &end, 10);
                valid &= !errno && end != args[4 + i] && *end == L'\0';
            }
            if (valid && values[0] >= -1000000 && values[0] <= 1000000
                    && values[1] >= -1000000 && values[1] <= 1000000
                    && values[2] >= 1 && values[2] <= 65535 && values[3] >= 1 && values[3] <= 65535
                    && (values[4] == SW_SHOWNORMAL || values[4] == SW_SHOWMAXIMIZED)) {
                handoff.bounds = RECT{values[0], values[1], values[0] + values[2], values[1] + values[3]};
                handoff.show = (int)values[4];
                handoff.placed = true;
            }
        }
    }
    LocalFree(args);
    return true;
}

// Must match IDI_ICON1 in icon.rc (resource id 101 is conventional for first ICON).
#ifndef IDI_ICON1
#define IDI_ICON1 101
#endif

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int) {
    // Kick the runtime/config initializer off first: it does not touch ImGui
    // or the window, so engine setup overlaps window and D3D creation
    // instead of serializing behind it.
    fcae_ui_diagnostic(8, GetCurrentProcessId());
    ElevatedWindow handoff;
    if (!read_elevated_window(handoff)) return ERROR_ELEVATION_REQUIRED;
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
    wc.hbrBackground = CreateSolidBrush(RGB(20, 20, 31));   // shared WindowBg, including startup
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
    int window_x = CW_USEDEFAULT;
    int window_y = CW_USEDEFAULT;
    place_window(window_x, window_y, window_w, window_h);
    if (handoff.placed) {
        MONITORINFO monitor = {};
        monitor.cbSize = sizeof(monitor);
        if (GetMonitorInfoW(MonitorFromRect(&handoff.bounds, MONITOR_DEFAULTTONEAREST), &monitor)) {
            window_w = (std::min)((int)(handoff.bounds.right - handoff.bounds.left), (int)(monitor.rcWork.right - monitor.rcWork.left));
            window_h = (std::min)((int)(handoff.bounds.bottom - handoff.bounds.top), (int)(monitor.rcWork.bottom - monitor.rcWork.top));
            window_x = std::clamp((int)handoff.bounds.left, (int)monitor.rcWork.left, (int)monitor.rcWork.right - window_w);
            window_y = std::clamp((int)handoff.bounds.top, (int)monitor.rcWork.top, (int)monitor.rcWork.bottom - window_h);
        }
    }
    HWND hWnd = CreateWindowW(wc.lpszClassName, L"FCAE VPN",
        kWindowStyle,
        window_x, window_y, window_w, window_h,
        nullptr, nullptr, inst, nullptr);
    if (!hWnd) {
        UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    g_taskbar_created = RegisterWindowMessageW(L"TaskbarCreated");
    install_tray(hWnd);

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

    ui_apply_style(kUiBaseFontSize);

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
    g_imgui_dx11_ready = true;
    g_imgui_win32_ready = true;
    ShowWindow(hWnd, handoff.placed ? handoff.show : SW_SHOWDEFAULT);
    UpdateWindow(hWnd);

    // Paint only for input, changed UI content, or an explicit redraw request.
    // Block on the message queue while idle instead of repainting unconditionally.
    auto next_device_retry = std::chrono::steady_clock::now();
    bool done = false;
    bool sponsor_window_visible = false;
    const auto min_frame_interval = std::chrono::duration_cast<std::chrono::steady_clock::duration>(
        std::chrono::duration<double>(UiFrame::interaction_interval));
    auto last_frame_time = std::chrono::steady_clock::now() - min_frame_interval;
    auto last_input_time = std::chrono::steady_clock::now();
    POINT last_mouse_pos = {};
    bool have_mouse_pos = false;
    constexpr auto interaction_tail   = std::chrono::milliseconds(700);

    g_draw_frame = [&] {
        if (g_drawing_frame || !g_app.running.load() || !IsWindow(hWnd)
                || IsIconic(hWnd) || !IsWindowVisible(hWnd)) return;
        struct FrameGuard {
            FrameGuard() { g_drawing_frame = true; }
            ~FrameGuard() { g_drawing_frame = false; }
        } guard;
        const auto frame_now = std::chrono::steady_clock::now();
        if (g_device_lost) {
            if (frame_now < next_device_retry) return;
            next_device_retry = frame_now + std::chrono::seconds(1);
            if (g_imgui_dx11_ready) {
                ImGui_ImplDX11_Shutdown();
                g_imgui_dx11_ready = false;
            }
            CleanupDeviceD3D();
            if (!CreateDeviceD3D(hWnd)) { CleanupDeviceD3D(); return; }
            if (!ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext)) return;
            g_imgui_dx11_ready = true;
            g_device_lost = false;
            g_swapchain_occluded = false;
            g_resize_width = g_resize_height = 0;
            ui_request_redraw();
        }
        if (g_swapchain_occluded) {
            const HRESULT test = g_pSwapChain->Present(0, DXGI_PRESENT_TEST);
            if (test == DXGI_STATUS_OCCLUDED) return;
            if (FAILED(test)) { g_device_lost = true; return; }
            g_swapchain_occluded = false;
            ui_request_redraw();
        }
        if (!resize_target()) { g_device_lost = true; return; }
        if (frame_now - last_frame_time < min_frame_interval) return;
        const bool active = g_live_resize || (frame_now - last_input_time) < interaction_tail;
        if (!ui_should_render(active)) return;

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        ui_frame();
        if (!g_app.running.load() || !IsWindow(hWnd) || !IsWindowVisible(hWnd)) {
            ImGui::EndFrame();
            return;
        }

        ImGui::Render();

        if (!g_mainRenderTargetView) return;

        const ImVec4 background = ImGui::GetStyle().Colors[ImGuiCol_WindowBg];
        const float clear_color[4] = { background.x, background.y, background.z, background.w };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        const HRESULT presented = g_pSwapChain->Present(1, 0);
        if (presented == S_OK) {
            g_has_presented_frame = true;
            if (handoff.ready && ui_runtime_ready()) {
                if (!SetEvent(handoff.ready)) {
                    fcae_ui_diagnostic(12, GetLastError());
                } else {
                    fcae_ui_diagnostic(13, GetCurrentProcessId());
                }
                CloseHandle(handoff.ready);
                handoff.ready = nullptr;
                SetForegroundWindow(hWnd);
            }
        } else if (presented == DXGI_STATUS_OCCLUDED) {
            g_swapchain_occluded = true;
        } else if (FAILED(presented)) {
            g_device_lost = true;
            g_has_presented_frame = false;
            g_app.add_log(FCAE_LOG_ERROR, "[ui] Direct3D presentation failed; rebuilding the renderer");
            ui_request_redraw();
        }
        // Present(1) may already have waited for VSYNC. Count its time inside
        // this frame, not as work preceding a second full throttle interval.
        last_frame_time = frame_now;
    };

    while (!done && g_app.running.load()) {
        const auto loop_now = std::chrono::steady_clock::now();

        // Keep polling while hidden so the next visible frame is fresh.
        bool paintable = !IsIconic(hWnd) && IsWindowVisible(hWnd);

        DWORD timeout;
        if (!paintable)         timeout = 1000;
        else if (g_swapchain_occluded || g_device_lost) timeout = 100;
        else {
            const double idle = (double)ui_sleep_ms() / 1000.0;
            const double since_start = std::chrono::duration<double>(loop_now - last_frame_time).count();
            const double cadence = UiFrame::interaction_interval;
            const double wait = UiFrame::wait_seconds(since_start, 0.0, cadence, idle,
                true);
            timeout = (DWORD)std::ceil(wait * 1000.0);
        }

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
        // Complete an approved elevation even while minimized or while the
        // content gate has no reason to open another ImGui frame.
        ui_handoff_tick();
        if (!g_app.running.load() || !IsWindow(hWnd)) break;
        if (got_input) last_input_time = std::chrono::steady_clock::now();
        paintable = !IsIconic(hWnd) && IsWindowVisible(hWnd);

        // Hidden windows release sponsor audio; visible windows claim it again.
        if (!paintable) {
            ui_autosave_tick();
            if (sponsor_window_visible) {
                ui_set_window_visible(false);
                release_sponsor_textures();
                sponsor_window_visible = false;
            }
            continue;
        }
        if (!sponsor_window_visible) {
            ui_set_window_visible(true);
            sponsor_window_visible = true;
        }
        ui_set_window_focused(GetForegroundWindow() == hWnd);

        g_draw_frame();
    }

    KillTimer(hWnd, kResizeTimer);
    g_live_resize = false;
    g_draw_frame = {};
    ui_set_window_handle(nullptr);
    ui_shutdown();

    g_imgui_win32_ready = false;
    if (g_imgui_dx11_ready) ImGui_ImplDX11_Shutdown();
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

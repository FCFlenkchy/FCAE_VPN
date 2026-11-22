#include "ui_style.h"
// FCAE VPN — macOS front end: AppKit window + Metal (MTKView) + Dear ImGui.
//
// This replaces the GLFW + OpenGL host. The shared UI (ui_render.cpp) does not
// know which renderer it runs on: everything it needs from a host is the ui_*
// hooks below plus `sponsor_texture_update`, which is the only piece of the
// renderer this file owns.
//
// Behaviour the old host had, and where each piece lives now:
//
//   * Paint only when the content changed, on input, or while something
//     animates; otherwise block. GLFW blocked in glfwWaitEventsTimeout();
//     AppKit's equivalent is nextEventMatchingMask:untilDate:inMode:dequeue:,
//     which also keeps the run loop alive for the menu bar and the Dock.
//   * A worker thread can ask for a frame (ui_request_redraw()). GLFW was
//     woken by posting an event; AppKit may only be touched from the main
//     thread, so the wait is bounded instead (kMaxWakeSeconds) and the request
//     flag is picked up on the next trip round the loop. The bound is tighter
//     than the idle interval ui_sleep_ms() would allow, so a redraw from a
//     worker lands sooner than it did under GLFW, never later.
//   * A hidden window (minimised, Cmd+H, another Space, fully covered) stops
//     painting and releases the sponsor media plane. The old host polled once
//     a second; so does this one, from the same occlusion signal.
//   * The window is fixed size, is not zoomable, and closing it ends the
//     process, because the engine runs in it.
//
// Built as Objective-C++ without ARC, like the ImGui backends it links against.

#import <Cocoa/Cocoa.h>
#import <Metal/Metal.h>
#import <MetalKit/MetalKit.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <thread>

#include "imgui.h"
#include "ui_frame_pacing.h"
#if defined(FCAE_HAVE_FREETYPE)
#include "imgui_freetype.h"
#endif
#include "imgui_impl_metal.h"
#include "imgui_impl_osx.h"

#include "ui_render.h"

// The designed window size, in AppKit points: larger than the original
// 1024x700, which was cramped once the settings pages and the log tail were both
// on screen. Points, not pixels, so Retina and 1x displays give the same
// physical size without any scaling here -- and nothing else may scale it
// again. The frame is reduced to the visible screen area below if it would not
// fit.
static constexpr int kWindowWidth = 1280;
static constexpr int kWindowHeight = 860;

// The base UI font size, in points, and the size the ui_render.cpp layout is
// designed against: about 1.7x the 13 px ImGui's embedded default face used to
// give this UI. Without a font at this size the atlas holds only that 13 px
// bitmap face, which cannot be enlarged without turning into mush. See the Win32
// host for why it is not the full 2x. The user's ui_scale_percent multiplies on
// top through style.FontScaleMain.
static constexpr float kUiBaseFontSize = 22.0f;
// Match the GLFW host's 60Hz interaction cadence.
static constexpr double kMinFrameInterval = UiFrame::interaction_interval;
// Upper bound on a single run-loop wait: how late a redraw requested by a
// worker thread can land, and how quickly a window that became visible starts
// painting again.
static constexpr double kMaxWakeSeconds = 0.05;
static constexpr double kInteractionTail = 0.7;
// With the window hidden the old host slept a second between polls.
static constexpr double kHiddenWakeSeconds = 1.0;

// ---------------------------------------------------------------------------
// Sponsor / CAPTCHA textures
//
// ui_render.cpp only ever sees an opaque ImTextureID. The Metal renderer
// resolves that ID to a texture with `(__bridge id<MTLTexture>)(void*)tex_id`,
// so the ID is the MTLTexture pointer itself. Three slots, exactly as the
// OpenGL and D3D11 hosts had: sponsor foreground, sponsor background, Firefox
// CAPTCHA. Called from the UI thread only.
// ---------------------------------------------------------------------------

struct MetalTextureSlot {
    id<MTLTexture> texture;
    uint64_t loaded;
    int width;
    int height;
};

static MetalTextureSlot g_slots[3];
static id<MTLDevice> g_device = nil;

ImTextureID sponsor_texture_update(const uint8_t* rgba, int width, int height, uint64_t generation, int slot) {
    const int index = (slot >= 0 && slot < 3) ? slot : 0;
    MetalTextureSlot& entry = g_slots[index];
    if (!rgba || width <= 0 || height <= 0 || g_device == nil) return (ImTextureID)0;
    if (entry.texture != nil && entry.loaded == generation) {
        return (ImTextureID)(intptr_t)(__bridge void*)entry.texture;
    }
    // A size change means a new texture; a generation change at the same size
    // is a straight upload, the way the other two hosts do it.
    if (entry.texture == nil || entry.width != width || entry.height != height) {
        MTLTextureDescriptor* descriptor = [MTLTextureDescriptor
            texture2DDescriptorWithPixelFormat:MTLPixelFormatRGBA8Unorm
                                         width:(NSUInteger)width
                                        height:(NSUInteger)height
                                     mipmapped:NO];
        descriptor.usage = MTLTextureUsageShaderRead;
        // Managed works on both Intel and Apple silicon and is what a texture
        // written by the CPU and sampled by the GPU wants on macOS.
        descriptor.storageMode = MTLStorageModeManaged;
        [entry.texture release];
        entry.texture = [g_device newTextureWithDescriptor:descriptor];
        if (entry.texture == nil) return (ImTextureID)0;
        entry.width = width;
        entry.height = height;
        entry.loaded = 0;
    }
    [entry.texture replaceRegion:MTLRegionMake2D(0, 0, (NSUInteger)width, (NSUInteger)height)
                     mipmapLevel:0
                       withBytes:rgba
                     bytesPerRow:(NSUInteger)width * 4];
    entry.loaded = generation;
    return (ImTextureID)(intptr_t)(__bridge void*)entry.texture;
}

static void release_sponsor_textures(void) {
    for (int i = 0; i < 3; ++i) {
        [g_slots[i].texture release];
        g_slots[i].texture = nil;
        g_slots[i].loaded = 0;
        g_slots[i].width = 0;
        g_slots[i].height = 0;
    }
}

// ---------------------------------------------------------------------------
// Application
// ---------------------------------------------------------------------------

@interface FcaeApplicationDelegate : NSObject <NSApplicationDelegate, NSWindowDelegate, MTKViewDelegate>
@property(nonatomic, assign) NSWindow* window;
@property(nonatomic, assign) MTKView* view;
@property(nonatomic, assign) id<MTLDevice> device;
@property(nonatomic, assign) id<MTLCommandQueue> commandQueue;
// When the last real input arrived and when the last frame was painted, both
// on the same monotonic clock the interaction tail is measured against.
@property(nonatomic, assign) double lastEventTime;
@property(nonatomic, assign) double lastFrameTime;
@property(nonatomic, assign) BOOL sponsorWindowVisible;
@property(nonatomic, assign) BOOL running;
@end

static id g_eventMonitor = nil;

@implementation FcaeApplicationDelegate

- (instancetype)init {
    if ((self = [super init])) {
        _device = MTLCreateSystemDefaultDevice();
        if (_device == nil) {
            fprintf(stderr, "Metal is not supported on this machine\n");
            return nil;
        }
        _commandQueue = [_device newCommandQueue];
        _running = YES;
        _lastEventTime = -1e9;
        _lastFrameTime = -1e9;
    }
    return self;
}

- (double)now {
    using clock = std::chrono::steady_clock;
    static const clock::time_point start = clock::now();
    return std::chrono::duration<double>(clock::now() - start).count();
}

// A local monitor sees every event the application dispatches, including the
// mouse moves and scrolls that only reach a view through the event stream. It
// is the AppKit counterpart of the GLFW host's last_event_time bookkeeping: any
// input restarts the interaction tail that keeps the UI animating.
- (void)installEventMonitor {
    if (g_eventMonitor != nil) return;
    __block FcaeApplicationDelegate* delegate = self;
    NSEventMask mask = NSEventMaskMouseMoved | NSEventMaskScrollWheel
                     | NSEventMaskLeftMouseDown | NSEventMaskLeftMouseUp | NSEventMaskLeftMouseDragged
                     | NSEventMaskRightMouseDown | NSEventMaskRightMouseUp | NSEventMaskRightMouseDragged
                     | NSEventMaskOtherMouseDown | NSEventMaskOtherMouseUp | NSEventMaskOtherMouseDragged
                     | NSEventMaskKeyDown | NSEventMaskKeyUp | NSEventMaskFlagsChanged;
    g_eventMonitor = [[NSEvent addLocalMonitorForEventsMatchingMask:mask
                                                           handler:^NSEvent*(NSEvent* event) {
        delegate.lastEventTime = [delegate now];
        return event;
    }] retain];
}

- (void)dealloc {
    if (g_eventMonitor != nil) {
        [NSEvent removeMonitor:g_eventMonitor];
        [g_eventMonitor release];
        g_eventMonitor = nil;
    }
    [super dealloc];
}

// Minimised, hidden with the app (Cmd+H), on another Space or fully covered:
// NSWindow reports all of them through its occlusion state, the same signal the
// GLFW host read from the Cocoa window.
- (BOOL)windowHidden {
    if (self.window == nil) return YES;
    if (self.window.miniaturized) return YES;
    if (!self.window.isVisible) return YES;
    return (self.window.occlusionState & NSWindowOcclusionStateVisible) == 0;
}

- (void)applicationDidFinishLaunching:(NSNotification*)notification {
    (void)notification;

    NSRect frame = NSMakeRect(0, 0, kWindowWidth, kWindowHeight);
    // Keep the window inside the usable screen area: on a 1440x900 MacBook the
    // designed height would otherwise not fit once the menu bar and Dock are
    // accounted for.
    {
        NSRect usable = NSScreen.mainScreen.visibleFrame;
        if (usable.size.width  > 480.0 && frame.size.width  > usable.size.width  - 40.0)
            frame.size.width  = usable.size.width  - 40.0;
        if (usable.size.height > 360.0 && frame.size.height > usable.size.height - 60.0)
            frame.size.height = usable.size.height - 60.0;
    }
    // `styleMask`, not `style`: the ImGui style block further down this same
    // function declares `style` too, and a window mask and an ImGuiStyle&
    // cannot share a scope.
    NSWindowStyleMask styleMask = NSWindowStyleMaskTitled | NSWindowStyleMaskClosable
                                | NSWindowStyleMaskMiniaturizable | NSWindowStyleMaskResizable;
    self.window = [[NSWindow alloc] initWithContentRect:frame
                                             styleMask:styleMask
                                               backing:NSBackingStoreBuffered
                                                 defer:NO];
    self.window.title = @"FCAE VPN";
    self.window.contentMinSize = NSMakeSize(480.0, 360.0);
    self.window.delegate = self;
    [self.window center];

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
    // is still unset here. Points, so a Retina display draws it at 2x pixels.
    {
        ImFontConfig font_cfg;
        font_cfg.SizePixels = kUiBaseFontSize;
        ImGui::GetIO().Fonts->AddFontDefaultVector(&font_cfg);
    }
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    // One style block, shared by every desktop front end.
    ui_apply_style(kUiBaseFontSize);

    g_device = self.device;
    self.view = [[MTKView alloc] initWithFrame:frame device:self.device];
    self.view.delegate = self;
    self.view.colorPixelFormat = MTLPixelFormatBGRA8Unorm;
    // The frame loop below drives every draw; MTKView must not draw on its own
    // schedule, and must not draw behind the content gate's back.
    self.view.paused = YES;
    self.view.enableSetNeedsDisplay = NO;
    self.view.autoResizeDrawable = YES;

    self.window.contentView = self.view;
    [self.window makeKeyAndOrderFront:nil];
    if ([NSApp respondsToSelector:@selector(activate)]) {
        [NSApp activate];                       // macOS 14+
    } else {
        [NSApp activateIgnoringOtherApps:YES];
    }

    // Renderer then platform: the OSX backend installs its text-input client
    // and event translation on this view, and both want the context to exist.
    // The KeyEventResponder it adds makes itself first responder on its own.
    ImGui_ImplMetal_Init(self.device);
    ImGui_ImplOSX_Init(self.view);

    ui_init();
    [self installEventMonitor];

    [self runFrameLoop];
}

// The window cannot be closed without the process: the engine lives in it, and
// ui_shutdown() has to release the sponsor media plane on the way out.
- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication*)sender {
    (void)sender;
    return YES;
}

- (void)windowWillClose:(NSNotification*)notification {
    (void)notification;
    self.running = NO;
    g_app.running.store(false);
}

- (void)applicationWillTerminate:(NSNotification*)notification {
    (void)notification;
    self.running = NO;
    g_app.running.store(false);
}

// ---------------------------------------------------------------------------
// Frame loop
// ---------------------------------------------------------------------------

// Paints one frame and reports whether one was painted.
//
// Everything that touches the drawable is checked before ImGui is asked for a
// frame: the Metal renderer dereferences the render pass descriptor's colour
// attachment in NewFrame, so a nil descriptor (no drawable yet, window
// occluded, display asleep) has to end the attempt before that call, not after
// it.
- (BOOL)paintFrame {
    id<CAMetalDrawable> drawable = self.view.currentDrawable;
    MTLRenderPassDescriptor* pass = self.view.currentRenderPassDescriptor;
    id<MTLCommandBuffer> commandBuffer = [self.commandQueue commandBuffer];
    if (drawable == nil || pass == nil || commandBuffer == nil) return NO;

    ImGui_ImplMetal_NewFrame(pass);
    ImGui_ImplOSX_NewFrame(self.view);
    ImGui::NewFrame();

    ui_frame();

    ImGui::Render();

    // The clear colour every desktop front end uses.
    pass.colorAttachments[0].clearColor = MTLClearColorMake(0.05, 0.05, 0.08, 1.0);
    id<MTLRenderCommandEncoder> encoder = [commandBuffer renderCommandEncoderWithDescriptor:pass];
    ImGui_ImplMetal_RenderDrawData(ImGui::GetDrawData(), commandBuffer, encoder);
    [encoder endEncoding];
    [commandBuffer presentDrawable:drawable];
    [commandBuffer commit];
    return YES;
}

- (void)runFrameLoop {
    while (self.running && g_app.running.load()) {
        @autoreleasepool {
            const BOOL hidden = [self windowHidden];

            // Block until something happens, never longer than the host needs
            // to notice a worker-side redraw request.
            const double before = [self now];
            const double cadence = (double)ui_sleep_ms() / 1000.0;
            const double wait = hidden ? kHiddenWakeSeconds : UiFrame::wait_seconds(before,
                self.lastFrameTime, kMinFrameInterval,
                std::min(kMaxWakeSeconds, cadence), true);
            NSDate* until = [NSDate dateWithTimeIntervalSinceNow:wait];
            NSEvent* event = [NSApp nextEventMatchingMask:NSEventMaskAny
                                                untilDate:until
                                                   inMode:NSDefaultRunLoopMode
                                                  dequeue:YES];
            if (event != nil) [NSApp sendEvent:event];
            // Then drain whatever is already queued, so a burst of input is one
            // trip round the loop rather than one trip per event.
            while ((event = [NSApp nextEventMatchingMask:NSEventMaskAny
                                                untilDate:[NSDate distantPast]
                                                   inMode:NSDefaultRunLoopMode
                                                  dequeue:YES]) != nil) {
                [NSApp sendEvent:event];
            }

            if (hidden) {
                // Keep the settings file warm and release the sponsor plane
                // while nothing can be seen.
                ui_autosave_tick();
                if (self.sponsorWindowVisible) {
                    ui_set_window_visible(false);
                    self.sponsorWindowVisible = NO;
                }
                // A closed window ends the app even though it is still "hidden".
                if (!self.running || !g_app.running.load()) break;
                continue;
            }
            if (!self.sponsorWindowVisible) {
                ui_set_window_visible(true);
                self.sponsorWindowVisible = YES;
            }
            ui_set_window_focused(self.window.isKeyWindow);

            const double now = [self now];
            if (now - self.lastFrameTime < kMinFrameInterval) continue;
            const BOOL interacting = (now - self.lastEventTime) < kInteractionTail;
            if (!ui_should_render(interacting)) continue;
            // Only a painted frame counts as one; a frame the drawable was not
            // ready for must be retried on the next trip round the loop.
            if ([self paintFrame]) self.lastFrameTime = now;
        }
    }

    ui_shutdown();
    ImGui_ImplOSX_Shutdown();
    ImGui_ImplMetal_Shutdown();
    ImGui::DestroyContext();
    release_sponsor_textures();

    // No ARC here, so the objects this delegate owns are released by hand.
    // Releasing the window takes the view, its layer and the drawable with it;
    // the loop above has already stopped touching any of them.
    self.window.contentView = nil;
    [self.view release];
    self.view = nil;
    [self.window release];
    self.window = nil;
    [self.commandQueue release];
    self.commandQueue = nil;
    [self.device release];
    self.device = nil;
    g_device = nil;
}

// MTKViewDelegate: the loop above drives every frame, so nothing is drawn here.
- (void)mtkView:(MTKView*)view drawableSizeWillChange:(CGSize)size {
    (void)view;
    (void)size;
    ui_request_redraw();
}

- (void)drawInMTKView:(MTKView*)view {
    (void)view;
}

@end

// A menu bar with the one item that matters: without it a command-line-launched
// GUI app has no way to quit from the keyboard.
static void install_main_menu(void) {
    NSMenu* bar = [[NSMenu alloc] init];
    NSMenuItem* app_item = [[NSMenuItem alloc] init];
    [bar addItem:app_item];
    NSMenu* app_menu = [[NSMenu alloc] init];
    NSString* name = [[NSProcessInfo processInfo] processName];
    [app_menu addItemWithTitle:[@"About " stringByAppendingString:name]
                        action:@selector(orderFrontStandardAboutPanel:)
                 keyEquivalent:@""];
    [app_menu addItem:[NSMenuItem separatorItem]];
    [app_menu addItemWithTitle:[@"Hide " stringByAppendingString:name]
                        action:@selector(hide:)
                 keyEquivalent:@"h"];
    [app_menu addItem:[NSMenuItem separatorItem]];
    [app_menu addItemWithTitle:[@"Quit " stringByAppendingString:name]
                        action:@selector(terminate:)
                 keyEquivalent:@"q"];
    app_item.submenu = app_menu;
    NSApp.mainMenu = bar;
}

extern "C" void fcae_macos_ne_host_initialize(void);
int main(int argc, char** argv) {
    (void)argc;
    (void)argv;

    @autoreleasepool {
        fcae_macos_ne_host_initialize();
        [NSApplication sharedApplication];
        [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
        install_main_menu();

        FcaeApplicationDelegate* delegate = [[FcaeApplicationDelegate alloc] init];
        if (delegate == nil) return 1;
        NSApp.delegate = delegate;
        [NSApp run];
    }
    return 0;
}

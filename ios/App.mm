#import <UIKit/UIKit.h>
#import <MetalKit/MetalKit.h>
#import "Platform.h"
#include "ui_render.h"
#include "ui_style.h"
#include "ui_text_input.h"
#include "android_imgui_input.h"
#include "imgui_impl_metal.h"

void ios_vpn_poll();
static id<MTLDevice> metal;
static AndroidImGuiInput* text_input = nullptr;
struct Texture { id<MTLTexture> image; uint64_t generation=0; int width=0,height=0; };
static Texture textures[3];
ImTextureID sponsor_texture_update(const uint8_t* rgba,int width,int height,uint64_t generation,int slot) {
    if (!rgba || width<=0 || height<=0 || slot<0 || slot>=3) return 0;
    auto& texture=textures[slot];
    if (!texture.image || width!=texture.width || height!=texture.height) {
        auto* descriptor=[MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatRGBA8Unorm width:width height:height mipmapped:NO];
        descriptor.storageMode=MTLStorageModeShared;descriptor.usage=MTLTextureUsageShaderRead;
        texture.image=[metal newTextureWithDescriptor:descriptor];
        texture.width=width;texture.height=height;texture.generation=0;
    }
    if (texture.image && generation!=texture.generation) {
        [texture.image replaceRegion:MTLRegionMake2D(0,0,width,height) mipmapLevel:0 withBytes:rgba bytesPerRow:width*4];
        texture.generation=generation;
    }
    return (ImTextureID)(intptr_t)(__bridge void*)texture.image;
}
@interface FCAEMetalView : MTKView <UIKeyInput,MTKViewDelegate>
@end
@implementation FCAEMetalView {
    id<MTLCommandQueue> _commands;
    AndroidImGuiInput _input;
    UITouch* _pointer;
    CFTimeInterval _lastFrame;
}
- (instancetype)initWithFrame:(CGRect)frame device:(id<MTLDevice>)device {
    if ((self=[super initWithFrame:frame device:device])) {
        _commands=[device newCommandQueue];self.delegate=self;
        self.preferredFramesPerSecond=30;self.multipleTouchEnabled=YES;
        IMGUI_CHECKVERSION();ImGui::CreateContext();
        auto& io=ImGui::GetIO();io.IniFilename=nullptr;io.BackendPlatformName="fcae_uikit";
        ImFontConfig font;font.SizePixels=16;font.RasterizerDensity=UIScreen.mainScreen.scale;
        io.Fonts->AddFontDefaultVector(&font);ui_apply_style(16);
        ImGui::GetStyle().TouchExtraPadding={3,3};
        auto& platform=ImGui::GetPlatformIO();
        platform.Platform_GetClipboardTextFn=[](ImGuiContext*)->const char* {
            static std::string clipboard;clipboard=UIPasteboard.generalPasteboard.string.UTF8String ?: "";return clipboard.c_str();
        };
        platform.Platform_SetClipboardTextFn=[](ImGuiContext*,const char* text) {
            UIPasteboard.generalPasteboard.string=[NSString stringWithUTF8String:text ?: ""];
        };
        ImGui_ImplMetal_Init(device);
        _input.set_touch_slop(8);
        text_input = &_input;
        UiText::reset();
        UiText::touch_hold = [](ImGuiID id, const ImRect& rect) { return text_input && text_input->text_hold(id, rect); };
        UiText::touch_menu = [](ImGuiID id) { return text_input && text_input->text_menu(id); };
        UiText::refresh_clipboard = nullptr;
        ui_init();
    }
    return self;
}
- (void)dealloc {
    if (text_input == &_input) {
        text_input = nullptr;
        UiText::reset();
        UiText::touch_hold = nullptr;UiText::touch_menu = nullptr;
    }
}
- (BOOL)canBecomeFirstResponder {return YES;}
- (BOOL)hasText {return YES;}
- (UIKeyboardType)keyboardType {return UIKeyboardTypeDefault;}
- (UITextAutocorrectionType)autocorrectionType {return UITextAutocorrectionTypeNo;}
- (UITextAutocapitalizationType)autocapitalizationType {return UITextAutocapitalizationTypeNone;}
- (void)insertText:(NSString*)text {
    auto& io=ImGui::GetIO();
    if ([text isEqualToString:@"\n"]) {io.AddKeyEvent(ImGuiKey_Enter,true);io.AddKeyEvent(ImGuiKey_Enter,false);}
    else io.AddInputCharactersUTF8(text.UTF8String);
    ui_request_redraw();
}
- (void)deleteBackward {
    auto& io=ImGui::GetIO();io.AddKeyEvent(ImGuiKey_Backspace,true);io.AddKeyEvent(ImGuiKey_Backspace,false);ui_request_redraw();
}
- (void)touchesBegan:(NSSet<UITouch*>*)touches withEvent:(UIEvent*)event {
    if (_pointer || event.allTouches.count!=1) {_input.reset();_pointer=nil;return;}
    _pointer=touches.anyObject;CGPoint p=[_pointer locationInView:self];
    _input.pointer(p.x,p.y,AndroidImGuiInput::Down,_pointer.timestamp,true);ui_request_redraw();
}
- (void)touchesMoved:(NSSet<UITouch*>*)touches withEvent:(UIEvent*)event {
    if (!_pointer || ![touches containsObject:_pointer]) return;
    CGPoint p=[_pointer locationInView:self];_input.pointer(p.x,p.y,AndroidImGuiInput::Move,_pointer.timestamp,true);ui_request_redraw();
}
- (void)touchesEnded:(NSSet<UITouch*>*)touches withEvent:(UIEvent*)event {
    if (!_pointer || ![touches containsObject:_pointer]) return;
    CGPoint p=[_pointer locationInView:self];_input.pointer(p.x,p.y,AndroidImGuiInput::Up,_pointer.timestamp,true);_pointer=nil;ui_request_redraw();
}
- (void)touchesCancelled:(NSSet<UITouch*>*)touches withEvent:(UIEvent*)event {_input.reset();_pointer=nil;}
- (void)mtkView:(MTKView*)view drawableSizeWillChange:(CGSize)size {ui_request_redraw();}
- (void)drawInMTKView:(MTKView*)view {
    auto& io=ImGui::GetIO();
    const double now=CACurrentMediaTime();
    io.DeltaTime=_lastFrame?std::clamp((float)(now-_lastFrame),.001f,.25f):1.f/30;_lastFrame=now;
    io.DisplaySize={(float)view.bounds.size.width,(float)view.bounds.size.height};
    io.DisplayFramebufferScale={(float)(view.drawableSize.width/std::max(1.f,io.DisplaySize.x)),(float)(view.drawableSize.height/std::max(1.f,io.DisplaySize.y))};
    _input.new_frame(io.DeltaTime);
    if (!ui_should_render(_input.active() || io.WantTextInput || UiText::wants_keyboard() || GImGui->InputEventsQueue.Size)) return;
    MTLRenderPassDescriptor* pass=view.currentRenderPassDescriptor;
    id<CAMetalDrawable> drawable=view.currentDrawable;if (!pass || !drawable) return;
    ImGui_ImplMetal_NewFrame(pass);ImGui::NewFrame();ui_frame();ImGui::Render();
    id<MTLCommandBuffer> command=[_commands commandBuffer];
    id<MTLRenderCommandEncoder> encoder=[command renderCommandEncoderWithDescriptor:pass];
    ImGui_ImplMetal_RenderDrawData(ImGui::GetDrawData(),command,encoder);
    [encoder endEncoding];[command presentDrawable:drawable];[command commit];
    const bool keyboard = io.WantTextInput || UiText::wants_keyboard();
    if (keyboard && !self.isFirstResponder) [self becomeFirstResponder];
    if (!keyboard && self.isFirstResponder) [self resignFirstResponder];
}
- (void)setPaused:(BOOL)paused {
    [super setPaused:paused];
    if (!ImGui::GetCurrentContext()) return;
    ui_set_window_visible(!paused);ui_set_window_focused(!paused);ImGui::GetIO().AddFocusEvent(!paused);
    _input.reset();_pointer=nil;_lastFrame=0;
    if (paused) {UiText::reset();ios_flush_settings();for (auto& texture:textures)texture={};[self resignFirstResponder];}
}
@end
@interface FCAEController : UIViewController
@end
@implementation FCAEController {
    FCAEMetalView* _surface;
    CGRect _keyboard;
}
- (void)viewDidLoad {
    [super viewDidLoad];self.view.backgroundColor=UIColor.blackColor;
    metal=MTLCreateSystemDefaultDevice();
    if (!metal) return;
    _surface=[[FCAEMetalView alloc] initWithFrame:self.view.bounds device:metal];[self.view addSubview:_surface];
    [NSNotificationCenter.defaultCenter addObserver:self selector:@selector(keyboard:) name:UIKeyboardWillChangeFrameNotification object:nil];
    [NSNotificationCenter.defaultCenter addObserver:self selector:@selector(keyboard:) name:UIKeyboardWillHideNotification object:nil];
}
- (void)keyboard:(NSNotification*)notification {
    _keyboard=[notification.name isEqualToString:UIKeyboardWillHideNotification]?CGRectZero:[notification.userInfo[UIKeyboardFrameEndUserInfoKey] CGRectValue];
    [self.view setNeedsLayout];
}
- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    CGRect frame=UIEdgeInsetsInsetRect(self.view.bounds,self.view.safeAreaInsets);
    if (!CGRectIsEmpty(_keyboard)) {
        CGRect keyboard=[self.view convertRect:_keyboard fromView:nil];
        if (CGRectIntersectsRect(frame,keyboard)) frame.size.height=MAX(1,MIN(CGRectGetMaxY(frame),CGRectGetMinY(keyboard))-frame.origin.y);
    }
    _surface.frame=frame;ui_request_redraw();
}
- (void)dealloc {[NSNotificationCenter.defaultCenter removeObserver:self];}
@end
@interface FCAEApp : UIResponder <UIApplicationDelegate>
@property(nonatomic,strong) UIWindow* window;
@end
@implementation FCAEApp
- (BOOL)application:(UIApplication*)application didFinishLaunchingWithOptions:(NSDictionary*)options {
    // App Group access is intentionally mandatory: app and VPN must share credentials/configs.
    if (ios_data_dir().empty()) {
        self.window=[[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
        UIViewController* controller=[UIViewController new];self.window.rootViewController=controller;[self.window makeKeyAndVisible];
        UIAlertController* error=[UIAlertController alertControllerWithTitle:@"Signing required" message:@"Sign the app and PacketTunnel extension with Network Extension and the configured App Group entitlements." preferredStyle:UIAlertControllerStyleAlert];
        [error addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [controller presentViewController:error animated:YES completion:nil];return YES;
    }
    self.window=[[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    self.window.rootViewController=[FCAEController new];[self.window makeKeyAndVisible];
    [NSTimer scheduledTimerWithTimeInterval:1 repeats:YES block:^(NSTimer*){ios_vpn_poll();}];
    return YES;
}
- (void)applicationWillResignActive:(UIApplication*)application {
    UIView* surface=self.window.rootViewController.view.subviews.firstObject;
    if ([surface isKindOfClass:MTKView.class]) ((MTKView*)surface).paused=YES;
}
- (void)applicationDidBecomeActive:(UIApplication*)application {
    UIView* surface=self.window.rootViewController.view.subviews.firstObject;
    if ([surface isKindOfClass:MTKView.class]) ((MTKView*)surface).paused=NO;
}
@end
int main(int argc,char** argv) {@autoreleasepool{return UIApplicationMain(argc,argv,nil,NSStringFromClass(FCAEApp.class));}}

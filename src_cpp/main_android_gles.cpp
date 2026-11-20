#include "ui_render.h"
#include "ui_text_input.h"
#include "android_ui.h"
#include "imgui_impl_opengl3.h"
#include "android_imgui_input.h"
#include "android_settings_ui.h"
#include <unordered_map>
#include "ui_style.h"
#if defined(FCAE_HAVE_FREETYPE)
#include "imgui_freetype.h"
#endif
#include <GLES3/gl3.h>
#include <jni.h>
#include <codecvt>
#include <locale>
#include <memory>


namespace {
JavaVM* vm = nullptr;
jclass bridge = nullptr;
jmethodID dispatch_method = nullptr;
jmethodID snapshot_method = nullptr;
jmethodID wake_method = nullptr;
jmethodID fold_method = nullptr;
std::unique_ptr<AndroidSettingsUi> settings;
std::atomic<bool> wake_ready{false};
std::unique_ptr<AndroidImGuiInput> input;
double interaction_until = 0.0;
std::string files_dir;
std::string last_error;
std::string clipboard;
bool initialized = false;
bool runtime_started = false;
bool renderer_initialized = false;
bool paused = false;
float density = 1.0f;
int surface_width = 1;
int surface_height = 1;
double last_frame = 0.0;
int settle_frames = 0;
struct Texture {
    GLuint id = 0;
    int width = 0;
    int height = 0;
    uint64_t generation = 0;
};
Texture textures[3];
struct AppIcon {
    std::vector<uint8_t> rgba;
    GLuint texture = 0;
    int used_frame = 0;
};
std::unordered_map<std::string, AppIcon> app_icons;

class Env {
public:
    Env() {
        if (!vm) return;
        if (vm->GetEnv(reinterpret_cast<void**>(&value), JNI_VERSION_1_6) == JNI_EDETACHED) {
            attached = vm->AttachCurrentThread(&value, nullptr) == JNI_OK;
        }
    }
    ~Env() { if (attached) vm->DetachCurrentThread(); }
    JNIEnv* value = nullptr;
private:
    bool attached = false;
};

jstring java_string(JNIEnv* env, const std::string& text) {
    std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> converter;
    try {
        const auto utf16 = converter.from_bytes(text);
        return env->NewString(reinterpret_cast<const jchar*>(utf16.data()), static_cast<jsize>(utf16.size()));
    } catch (const std::range_error&) {
        return env->NewStringUTF("Invalid UTF-8 text");
    }
}
std::string native_string(JNIEnv* env, jstring value) {
    if (!value) return {};
    const jchar* data = env->GetStringChars(value, nullptr);
    if (!data) return {};
    std::u16string utf16(reinterpret_cast<const char16_t*>(data), env->GetStringLength(value));
    env->ReleaseStringChars(value, data);
    std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> converter;
    try { return converter.to_bytes(utf16); }
    catch (const std::range_error&) { return {}; }
}

std::vector<std::string> strings(JNIEnv* env, jobjectArray values) {
    std::vector<std::string> result;
    if (!values) return result;
    const jsize count = env->GetArrayLength(values);
    result.reserve(count);
    for (jsize i = 0; i < count; ++i) {
        auto value = static_cast<jstring>(env->GetObjectArrayElement(values, i));
        result.push_back(native_string(env, value));
        env->DeleteLocalRef(value);
    }
    return result;
}

std::string fold_query(const std::string& value) {
    Env scope;
    if (!scope.value || !fold_method) return value;
    jstring text = java_string(scope.value, value);
    auto result = static_cast<jstring>(scope.value->CallStaticObjectMethod(bridge, fold_method, text));
    if (scope.value->ExceptionCheck()) {
        scope.value->ExceptionClear();
        scope.value->DeleteLocalRef(text);
        scope.value->DeleteLocalRef(result);
        return value;
    }
    const std::string folded = native_string(scope.value, result);
    scope.value->DeleteLocalRef(text);
    scope.value->DeleteLocalRef(result);
    return folded;
}

bool reserve_icon() {
    if (app_icons.size() < 128) return true;
    auto victim = app_icons.end();
    for (auto it = app_icons.begin(); it != app_icons.end(); ++it)
        if (it->second.used_frame < ImGui::GetFrameCount() &&
            (victim == app_icons.end() || it->second.used_frame < victim->second.used_frame)) victim = it;
    if (victim == app_icons.end()) return false;
    if (victim->second.texture) glDeleteTextures(1, &victim->second.texture);
    app_icons.erase(victim);
    return true;
}

ImTextureID app_icon(const std::string& package) {
    auto found = app_icons.find(package);
    if (found == app_icons.end()) {
        if (!reserve_icon()) return {};
        found = app_icons.emplace(package, AppIcon{}).first;
        android_ui_command("appIcon", package);
    }
    AppIcon& icon = found->second;
    icon.used_frame = ImGui::GetFrameCount();
    if (!icon.texture && !icon.rgba.empty()) {
        GLint previous = 0;
        glGetIntegerv(GL_TEXTURE_BINDING_2D, &previous);
        glGenTextures(1, &icon.texture);
        glBindTexture(GL_TEXTURE_2D, icon.texture);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, 48, 48, 0, GL_RGBA, GL_UNSIGNED_BYTE, icon.rgba.data());
        glBindTexture(GL_TEXTURE_2D, static_cast<GLuint>(previous));
    }
    return static_cast<ImTextureID>(icon.texture);
}

struct Json {
    std::string value = "{";
    void key(const char* name) {
        if (value.size() > 1) value += ',';
        value += '"'; value += name; value += "\":";
    }
    void text(const char* name, const char* text) {
        key(name); value += '"'; core_json_escape_into(value, text ? text : ""); value += '"';
    }
    void number(const char* name, uint64_t number) { key(name); value += std::to_string(number); }
    void boolean(const char* name, bool flag) { key(name); value += flag ? "true" : "false"; }
};

ImGuiKey key_from_android(int code) {
    if (code >= 29 && code <= 54) return static_cast<ImGuiKey>(ImGuiKey_A + code - 29);
    if (code >= 7 && code <= 16) return static_cast<ImGuiKey>(ImGuiKey_0 + code - 7);
    switch (code) {
        case 19: return ImGuiKey_UpArrow;
        case 20: return ImGuiKey_DownArrow;
        case 21: return ImGuiKey_LeftArrow;
        case 22: return ImGuiKey_RightArrow;
        case 61: return ImGuiKey_Tab;
        case 62: return ImGuiKey_Space;
        case 66: return ImGuiKey_Enter;
        case 67: return ImGuiKey_Backspace;
        case 92: return ImGuiKey_PageUp;
        case 93: return ImGuiKey_PageDown;
        case 111: return ImGuiKey_Escape;
        case 112: return ImGuiKey_Delete;
        case 122: return ImGuiKey_Home;
        case 123: return ImGuiKey_End;
        default: return ImGuiKey_None;
    }
}
}

const std::string& android_ui_data_dir() { return files_dir; }
void android_ui_command(const char* action, const std::string& payload) {
    Env scope;
    JNIEnv* env = scope.value;
    if (!env || !bridge || !dispatch_method) return;
    jstring command = java_string(env, action);
    jstring argument = java_string(env, payload);
    if (command && argument) env->CallStaticVoidMethod(bridge, dispatch_method, command, argument);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        g_app.add_log(FCAE_LOG_ERROR, "[android] platform command failed");
    }
    env->DeleteLocalRef(command);
    env->DeleteLocalRef(argument);
}

void android_ui_wake() {
    if (!wake_ready.load(std::memory_order_acquire)) return;
    Env scope;
    if (!scope.value) return;
    scope.value->CallStaticVoidMethod(bridge, wake_method);
    if (scope.value->ExceptionCheck()) scope.value->ExceptionClear();
}

void android_ui_save_session(bool connect) {
    FcaeConfig c = g_app.to_config();
    Json json;
    json.number("protocol", c.protocol);
    json.number("mode", c.mode);
    json.number("backend", c.backend);
    json.number("scanMode", c.scan_mode);
    json.number("ipVersion", c.ip_version);
    json.number("sysProfile", c.sys_profile);
    json.number("socksPort", c.socks_port);
    json.number("httpPort", c.http_port);
    json.number("tunEngine", c.tun_engine);
    json.number("tunMtu", c.tun_mtu);
    json.number("tunTcpSndbuf", c.tun_tcp_sndbuf);
    json.number("tunTcpRcvbuf", c.tun_tcp_rcvbuf);
    json.number("t2sLog", c.tun2socks_log_level);
    json.number("torMode", c.tor.mode);
    json.number("torBridges", c.tor.bridges);
    json.number("torSocksPort", c.tor.socks_port);
    json.number("torHttpPort", c.tor_http_port);
    json.number("engineLog", c.engine_log);
    json.number("coreLog", c.core.log_level);
    json.number("psiphonSocksPort", c.psiphon.socks_port);
    json.number("psiphonHttpPort", c.psiphon.http_port);
    json.number("psiphonTransport", g_app.psiphon_transport);
    json.number("fragMinSize", c.obfuscation.frag_min_size);
    json.number("fragMaxSize", c.obfuscation.frag_max_size);
    json.number("fragMinDelay", c.obfuscation.frag_min_delay_ms);
    json.number("fragMaxDelay", c.obfuscation.frag_max_delay_ms);
    json.boolean("lanSharing", c.lan_sharing);
    json.boolean("quickReconnect", c.quick_reconnect);
    json.boolean("h2Enabled", c.obfuscation.h2_enabled);
    json.boolean("echEnabled", c.obfuscation.ech_enabled);
    json.boolean("fragmentEnabled", c.obfuscation.fragment_enabled);
    json.boolean("tunTcpAutoTuning", c.tun_tcp_auto_tuning == 1);
    json.boolean("tunHttpEnabled", (c._reserved[0] & FCAE_CONFIG_TUN_HTTP) != 0);
    json.boolean("psiphonThroughTunnel", false);
    json.boolean("tunExcludePrivate", g_app.tun_exclude_private);
    json.boolean("tlsVerify", c.aether.tls_verify);
    json.boolean("disableGrease", c.aether.disable_grease);
    json.boolean("enableGreaseSigalgs", c.aether.enable_grease_sigalgs);
    json.boolean("enableEchGrease", c.aether.enable_ech_grease);
    json.boolean("disableOcspStapling", c.aether.disable_ocsp_stapling);
    json.boolean("disableSct", c.aether.disable_sct);
    json.boolean("disableSessionTicket", c.aether.disable_session_ticket);
    json.boolean("disableExtensionPermutation", c.aether.disable_extension_permutation);
    json.boolean("fragmentSni", c.aether.fragment_sni);
    json.text("configPath", c.config_path);
    json.text("noizeProfile", c.obfuscation.noize_profile);
    json.text("forcePeer", c.force_peer);
    json.text("upstreamProxy", c.upstream_proxy);
    json.text("sni", c.dns.sni);
    json.text("echDns", c.aether.ech_dns);
    json.text("echDomain", c.aether.ech_domain);
    json.text("goolInner", c.aether.gool_inner);
    json.text("tlsCiphers", c.aether.tls_ciphers);
    json.text("apiAddress", c.aether.api_address);
    json.text("apiHost", c.aether.api_host);
    json.text("apiSni", c.aether.api_sni);
    json.text("exitLoc", c.aether.exit_loc);
    json.text("tls13Ciphers", c.aether.tls13_ciphers);
    json.text("tlsGroups", c.dns.tls_groups);
    json.text("tlsKeyShares", c.aether.tls_key_shares);
    json.text("tlsSigalgs", c.aether.tls_sigalgs);
    json.text("tlsCertCompression", c.aether.tls_cert_compression);
    json.text("tlsAlps", c.aether.tls_alps);
    json.text("tlsTrustAnchors", c.aether.tls_trust_anchors);
    json.text("tlsServerPadding", c.aether.tls_server_padding);
    json.text("teamName", c.zero_trust.team_name);
    json.text("accessToken", c.zero_trust.access_token);
    json.text("accessEmail", c.zero_trust.access_email);
    json.text("routesInline", c.routing.rules_inline);
    json.text("torBridgeLines", c.tor.bridge_lines);
    json.text("coreConfigs", c.core.library);
    json.text("coreConfigId", c.core.config_ref);
    json.text("firefoxAccountId", c.firefox.account_id);
    json.text("firefoxLocation", c.firefox.location);
    json.text("firefoxServer", c.firefox.server);
    json.text("firefoxTransport", c.firefox.transport);
    json.text("psiphonConfig", c.psiphon.config_json);
    json.text("psiphonRegion", c.psiphon.egress_region);
    json.text("tunDnsV4", g_app.tun_dns4);
    json.text("tunDnsV6", g_app.tun_dns6);
    json.key("chainTransports");
    json.value += '[';
    bool first_hop = true;
    for (int transport : g_app.chain_transports) {
        const int doc = g_app.core_doc_index(transport);
        if (transport >= kCoreTransportBase && doc < 0) continue;
        if (!first_hop) json.value += ',';
        first_hop = false;
        json.value += std::to_string(transport >= kCoreTransportBase
            ? kCoreTransportBase + doc : transport);
    }
    json.value += "]}";
    android_ui_command(connect ? "connect" : "save", json.value);
}

void android_ui_telemetry(FcaeTelemetry& telemetry) {
    Env scope;
    JNIEnv* env = scope.value;
    if (!env || !bridge || !snapshot_method) return;
    auto values = static_cast<jlongArray>(env->CallStaticObjectMethod(bridge, snapshot_method));
    if (env->ExceptionCheck()) { env->ExceptionClear(); return; }
    if (!values) return;
    if (env->GetArrayLength(values) == 8) {
        jlong data[8];
        env->GetLongArrayRegion(values, 0, 8, data);
        paused = data[7] != 0;
        if (data[0] >= 0) {
            telemetry.state = static_cast<FcaeState>(data[0]);
            telemetry.active_mode = static_cast<FcaeMode>(data[1]);
            telemetry.rx_bytes_sec = data[2]; telemetry.tx_bytes_sec = data[3];
            telemetry.total_rx = data[4]; telemetry.total_tx = data[5];
            telemetry.rtt_ms = static_cast<uint32_t>(data[6]);
        }
    }
    env->DeleteLocalRef(values);
    if (!last_error.empty() && telemetry.state == FCAE_STATE_DISCONNECTED) {
        telemetry.state = FCAE_STATE_ERROR;
        snprintf(telemetry.last_error, sizeof(telemetry.last_error), "%s", last_error.c_str());
    }
}
bool android_ui_paused() { return paused; }

ImTextureID sponsor_texture_update(const uint8_t* rgba, int width, int height, uint64_t generation, int slot) {
    if (!rgba || width <= 0 || height <= 0 || slot < 0 || slot >= 3) return ImTextureID{};
    Texture& texture = textures[slot];
    if (!texture.id) glGenTextures(1, &texture.id);
    GLint previous = 0;
    glGetIntegerv(GL_TEXTURE_BINDING_2D, &previous);
    glBindTexture(GL_TEXTURE_2D, texture.id);
    if (texture.width != width || texture.height != height) {
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, width, height, 0, GL_RGBA, GL_UNSIGNED_BYTE, rgba);
        texture.width = width; texture.height = height; texture.generation = generation;
    } else if (texture.generation != generation) {
        glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, width, height, GL_RGBA, GL_UNSIGNED_BYTE, rgba);
        texture.generation = generation;
    }
    glBindTexture(GL_TEXTURE_2D, static_cast<GLuint>(previous));
    return static_cast<ImTextureID>(texture.id);
}

extern "C" JNIEXPORT void JNICALL
Java_com_fc_fcaevpn_ImGuiBridge_nativeSurface(JNIEnv* env, jclass type, jstring directory, jfloat scale, jfloat touch_slop) {
    if (!initialized) {
        env->GetJavaVM(&vm);
        if (!bridge) {
            bridge = static_cast<jclass>(env->NewGlobalRef(type));
            dispatch_method = env->GetStaticMethodID(bridge, "dispatch", "(Ljava/lang/String;Ljava/lang/String;)V");
            snapshot_method = env->GetStaticMethodID(bridge, "snapshot", "()[J");
            wake_method = env->GetStaticMethodID(bridge, "requestFrame", "()V");
            fold_method = env->GetStaticMethodID(bridge, "foldAppQuery", "(Ljava/lang/String;)Ljava/lang/String;");
        }
        input = std::make_unique<AndroidImGuiInput>();
        UiText::reset();
        UiText::touch_hold = [](ImGuiID id, const ImRect& rect) { return input && input->text_hold(id, rect); };
        UiText::touch_menu = [](ImGuiID id) { return input && input->text_menu(id); };
        UiText::refresh_clipboard = [] { android_ui_command("clipboardRead"); };
        settings = std::make_unique<AndroidSettingsUi>(
            [](const char* action, const std::string& payload) { android_ui_command(action, payload); },
            fold_query, app_icon);
        files_dir = native_string(env, directory);
        IMGUI_CHECKVERSION();
        ImGui::CreateContext();
        ImGuiIO& io = ImGui::GetIO();
        io.IniFilename = nullptr;
        io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
#if defined(FCAE_HAVE_FREETYPE)
        io.Fonts->SetFontLoader(ImGuiFreeType::GetFontLoader());
#endif
        io.BackendPlatformName = "fcae_android";
        io.ConfigWindowsMoveFromTitleBarOnly = true;
        ImFontConfig font;
        font.SizePixels = 16.0f;
        font.RasterizerDensity = std::max(0.5f, scale);
        io.Fonts->AddFontDefaultVector(&font);
        ui_apply_style(font.SizePixels);
        ImGui::GetStyle().TouchExtraPadding = ImVec2(3.0f, 3.0f);
        ImGuiPlatformIO& platform = ImGui::GetPlatformIO();
        platform.Platform_SetClipboardTextFn = [](ImGuiContext*, const char* text) {
            clipboard = text ? text : "";
            android_ui_command("clipboard", clipboard);
        };
        platform.Platform_GetClipboardTextFn = [](ImGuiContext*) { return clipboard.c_str(); };
        initialized = true;
        wake_ready.store(true, std::memory_order_release);
        if (!runtime_started) {
            runtime_started = true;
            ui_init();
        }
        if (settings) settings->refresh();
    }
    density = std::max(0.5f, scale);
    input->reset();
    input->set_touch_slop(touch_slop / density);
    if (renderer_initialized) ImGui_ImplOpenGL3_Shutdown();
    for (Texture& texture : textures) texture = {};
    for (auto it = app_icons.begin(); it != app_icons.end();) {
        if (it->second.rgba.empty()) it = app_icons.erase(it);
        else { it->second.texture = 0; ++it; }
    }
    ImGui_ImplOpenGL3_Init("#version 300 es");
    renderer_initialized = true;
    wake_ready.store(true, std::memory_order_release);
    last_frame = 0.0;
    ui_set_window_visible(true);
    ui_set_window_focused(true);
}
static void release_view_gpu() {
    for (auto& entry : app_icons) {
        if (entry.second.texture) glDeleteTextures(1, &entry.second.texture);
        entry.second.texture = 0;
    }
    for (Texture& texture : textures) {
        if (texture.id) glDeleteTextures(1, &texture.id);
        texture = {};
    }
    if (renderer_initialized) ImGui_ImplOpenGL3_Shutdown();
    renderer_initialized = false;
}

extern "C" JNIEXPORT void JNICALL
Java_com_fc_fcaevpn_ImGuiBridge_nativeSuspend(JNIEnv*, jclass) {
    if (!initialized) return;
    // Called on the GL thread before GLSurfaceView discards its EGL context.
    // Keep ImGui and editor state alive until the Activity is destroyed.
    wake_ready.store(false, std::memory_order_release);
    input->reset();
    release_view_gpu();
    interaction_until = last_frame = 0.0;
}

extern "C" JNIEXPORT void JNICALL
Java_com_fc_fcaevpn_ImGuiBridge_nativeRelease(JNIEnv*, jclass) {
    if (!initialized) {
        std::string{}.swap(clipboard);
        std::string{}.swap(last_error);
        return;
    }
    wake_ready.store(false, std::memory_order_release);
    ui_set_window_visible(false);
    ui_set_window_focused(false);
    input->reset();
    input.reset();
    UiText::reset_android_view();
    settings.reset();
    release_view_gpu();
    decltype(app_icons){}.swap(app_icons);
    ImGui::DestroyContext();
    initialized = false;
    std::string{}.swap(clipboard);
    std::string{}.swap(last_error);
    interaction_until = last_frame = 0.0;
    ui_release_view();
}
extern "C" JNIEXPORT void JNICALL
Java_com_fc_fcaevpn_ImGuiBridge_nativeResize(JNIEnv*, jclass, jint width, jint height) {
    surface_width = std::max(1, width); surface_height = std::max(1, height);
    ui_request_redraw();
}
void android_ui_horizontal_drag_item() { if (input) input->horizontal_drag_item(); }
bool android_ui_is_scrolling() { return input && input->scrolling_window(ImGui::GetCurrentWindow()->ID); }

extern "C" JNIEXPORT jint JNICALL
Java_com_fc_fcaevpn_ImGuiBridge_nativeFrame(JNIEnv*, jclass) {
    if (!initialized || !renderer_initialized) return 250;
    ImGuiIO& io = ImGui::GetIO();
    const double now = ui_now_seconds();
    io.DisplaySize = ImVec2(surface_width / density, surface_height / density);
    io.DisplayFramebufferScale = ImVec2(density, density);
    io.DeltaTime = last_frame > 0 ? static_cast<float>(std::clamp(now - last_frame, 0.001, 0.25)) : 1.0f / 60.0f;
    last_frame = now;
    input->new_frame(io.DeltaTime);
    const bool interacting = input->active() || now < interaction_until || io.MouseDown[0]
        || GImGui->InputEventsQueue.Size != 0;
    // The scheduler already chose to draw this frame. The app fingerprint does
    // not include ImGui's deferred tab selection, focus or child-window layout;
    // using it as a second gate can replay stale draw data after an input/wake.
    // Keep its asynchronous polling, but always process an offered ImGui frame.
    ui_should_render(interacting);
    ImGui_ImplOpenGL3_NewFrame();
    ImGui::NewFrame();
    ui_frame();
    ImGui::Render();
    glViewport(0, 0, surface_width, surface_height);
    const ImVec4 background = ImGui::GetStyle().Colors[ImGuiCol_WindowBg];
    glClearColor(background.x, background.y, background.z, background.w);
    glClear(GL_COLOR_BUFFER_BIT);
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
    // A text-action popup temporarily owns ImGui focus, not the Android IME.
    const bool keyboard = io.WantTextInput || UiText::wants_keyboard();
    const unsigned delay = 0; // Java schedules the single 60 FPS cadence.
    return static_cast<jint>(delay) | (keyboard ? 0x10000 : 0)
        | (GImGui->OpenPopupStack.Size ? 0x20000 : 0);
}
extern "C" JNIEXPORT void JNICALL
Java_com_fc_fcaevpn_ImGuiBridge_nativePointer(JNIEnv*, jclass, jfloat x, jfloat y, jint action, jlong time_ms, jboolean touch) {
    if (!initialized) return;
    input->pointer(x / density, y / density, action, time_ms / 1000.0, touch);
    interaction_until = ui_now_seconds() + 0.25;
}
extern "C" JNIEXPORT void JNICALL
Java_com_fc_fcaevpn_ImGuiBridge_nativeWheel(JNIEnv*, jclass, jfloat x, jfloat y) {
    if (!initialized) return;
    ImGui::GetIO().AddMouseWheelEvent(x, y);
    interaction_until = ui_now_seconds() + 0.25;
}
extern "C" JNIEXPORT void JNICALL
Java_com_fc_fcaevpn_ImGuiBridge_nativeKey(JNIEnv*, jclass, jint code, jboolean down, jint modifiers) {
    if (!initialized) return;
    ImGuiIO& io = ImGui::GetIO();
    io.AddKeyEvent(ImGuiMod_Ctrl, (modifiers & 0x1000) != 0);
    io.AddKeyEvent(ImGuiMod_Shift, (modifiers & 1) != 0);
    io.AddKeyEvent(ImGuiMod_Alt, (modifiers & 2) != 0);
    io.AddKeyEvent(ImGuiMod_Super, (modifiers & 0x10000) != 0);
    const ImGuiKey key = key_from_android(code);
    if (key != ImGuiKey_None) io.AddKeyEvent(key, down);
    interaction_until = ui_now_seconds() + 0.25;
}
extern "C" JNIEXPORT void JNICALL
Java_com_fc_fcaevpn_ImGuiBridge_nativeText(JNIEnv* env, jclass, jstring value) {
    if (!initialized) return;
    const std::string text = native_string(env, value);
    ImGui::GetIO().AddInputCharactersUTF8(text.c_str());
    interaction_until = ui_now_seconds() + 0.25;
}
extern "C" JNIEXPORT void JNICALL
Java_com_fc_fcaevpn_ImGuiBridge_nativeClipboard(JNIEnv* env, jclass, jstring value) {
    clipboard = native_string(env, value);
}
extern "C" JNIEXPORT void JNICALL
Java_com_fc_fcaevpn_ImGuiBridge_nativeVisibility(JNIEnv*, jclass, jboolean visible) {
    if (!initialized) return;
    ui_set_window_visible(visible); ui_set_window_focused(visible);
    ImGui::GetIO().AddFocusEvent(visible);
    if (visible && settings) settings->refresh();
    last_frame = 0.0;
    settle_frames = visible ? 2 : 0;
    if (!visible) {
        input->reset();
        interaction_until = 0.0;
        android_ui_flush_settings();
    }
}
extern "C" JNIEXPORT void JNICALL
Java_com_fc_fcaevpn_ImGuiBridge_nativeError(JNIEnv* env, jclass, jstring value) {
    last_error = native_string(env, value);
    if (!last_error.empty()) g_app.add_log(FCAE_LOG_ERROR, last_error.c_str());
    g_app.last_telem_t = 0.0;
    ui_request_redraw();
}


void android_ui_render_controls() { if (settings) settings->controls(); }
void android_ui_render_routing() { if (settings) settings->routing(); }
void android_ui_render_app_picker() { if (settings) settings->picker(); }

extern "C" JNIEXPORT void JNICALL
Java_com_fc_fcaevpn_ImGuiBridge_nativePlatformState(JNIEnv* env, jclass, jlong revision, jint mode, jobjectArray selected, jboolean tile, jboolean widgets) {
    if (settings) settings->state(static_cast<uint64_t>(revision), mode, strings(env, selected), tile, widgets);
    ui_request_redraw();
}

extern "C" JNIEXPORT void JNICALL
Java_com_fc_fcaevpn_ImGuiBridge_nativeApps(JNIEnv* env, jclass, jobjectArray packages, jobjectArray labels, jobjectArray search) {
    if (!settings) return;
    const auto names = strings(env, packages);
    const auto titles = strings(env, labels);
    const auto folded = strings(env, search);
    if (names.size() != titles.size() || names.size() != folded.size()) return;
    std::vector<AndroidSettingsUi::App> apps;
    apps.reserve(names.size());
    for (size_t i = 0; i < names.size(); ++i) apps.push_back({names[i], titles[i], folded[i]});
    settings->apps(std::move(apps));
    ui_request_redraw();
}

extern "C" JNIEXPORT void JNICALL
Java_com_fc_fcaevpn_ImGuiBridge_nativeAppIcon(JNIEnv* env, jclass, jstring name, jintArray pixels) {
    const std::string package = native_string(env, name);
    auto found = app_icons.find(package);
    if (found == app_icons.end() || !pixels || env->GetArrayLength(pixels) != 48 * 48) return;
    std::vector<jint> colors(48 * 48);
    env->GetIntArrayRegion(pixels, 0, static_cast<jsize>(colors.size()), colors.data());
    auto& rgba = found->second.rgba;
    rgba.resize(colors.size() * 4);
    for (size_t i = 0; i < colors.size(); ++i) {
        const uint32_t argb = static_cast<uint32_t>(colors[i]);
        rgba[i * 4] = static_cast<uint8_t>(argb >> 16);
        rgba[i * 4 + 1] = static_cast<uint8_t>(argb >> 8);
        rgba[i * 4 + 2] = static_cast<uint8_t>(argb);
        rgba[i * 4 + 3] = static_cast<uint8_t>(argb >> 24);
    }
    ui_request_redraw();
}

extern "C" JNIEXPORT void JNICALL
Java_com_fc_fcaevpn_ImGuiBridge_nativeBack(JNIEnv*, jclass) {
    if (!initialized) return;
    input->reset();
    if (GImGui->OpenPopupStack.Size)
        ImGui::ClosePopupToLevel(GImGui->OpenPopupStack.Size - 1, true);
    interaction_until = ui_now_seconds() + 0.25;
    ui_request_redraw();
}

#include "ui_render.h"
#include "android_ui.h"
#include "imgui_impl_opengl3.h"
#include "imgui_internal.h"
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
std::string files_dir;
std::string last_error;
std::string clipboard;
bool initialized = false;
bool renderer_initialized = false;
bool paused = false;
float density = 1.0f;
int surface_width = 1;
int surface_height = 1;
double last_frame = 0.0;
struct Texture {
    GLuint id = 0;
    int width = 0;
    int height = 0;
    uint64_t generation = 0;
};
Texture textures[3];

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
    json.text("routesFile", c.routing.rules_file);
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
Java_com_fc_fcaevpn_ImGuiBridge_nativeSurface(JNIEnv* env, jclass type, jstring directory, jfloat scale) {
    if (!initialized) {
        env->GetJavaVM(&vm);
        bridge = static_cast<jclass>(env->NewGlobalRef(type));
        dispatch_method = env->GetStaticMethodID(bridge, "dispatch", "(Ljava/lang/String;Ljava/lang/String;)V");
        snapshot_method = env->GetStaticMethodID(bridge, "snapshot", "()[J");
        files_dir = native_string(env, directory);
        IMGUI_CHECKVERSION();
        ImGui::CreateContext();
        ImGuiIO& io = ImGui::GetIO();
        io.IniFilename = nullptr;
        io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
        ImFontConfig font;
        font.SizePixels = 16.0f;
        font.RasterizerDensity = std::max(0.5f, scale);
        io.Fonts->AddFontDefaultVector(&font);
        ImGui::StyleColorsDark();
        ImGui::GetStyle().FrameRounding = 8.0f;
        ImGuiPlatformIO& platform = ImGui::GetPlatformIO();
        platform.Platform_SetClipboardTextFn = [](ImGuiContext*, const char* text) {
            clipboard = text ? text : "";
            android_ui_command("clipboard", clipboard);
        };
        platform.Platform_GetClipboardTextFn = [](ImGuiContext*) { return clipboard.c_str(); };
        initialized = true;
        ui_init();
    }
    density = std::max(0.5f, scale);
    if (renderer_initialized) ImGui_ImplOpenGL3_Shutdown();
    for (Texture& texture : textures) texture = {};
    ImGui_ImplOpenGL3_Init("#version 300 es");
    renderer_initialized = true;
    last_frame = 0.0;
    ui_set_window_visible(true);
    ui_set_window_focused(true);
}
extern "C" JNIEXPORT void JNICALL
Java_com_fc_fcaevpn_ImGuiBridge_nativeResize(JNIEnv*, jclass, jint width, jint height) {
    surface_width = std::max(1, width); surface_height = std::max(1, height);
    ui_request_redraw();
}
extern "C" JNIEXPORT jint JNICALL
Java_com_fc_fcaevpn_ImGuiBridge_nativeFrame(JNIEnv*, jclass) {
    if (!initialized || !renderer_initialized) return 250;
    ImGuiIO& io = ImGui::GetIO();
    const double now = ui_now_seconds();
    io.DisplaySize = ImVec2(surface_width / density, surface_height / density);
    io.DisplayFramebufferScale = ImVec2(density, density);
    io.DeltaTime = last_frame > 0 ? static_cast<float>(std::clamp(now - last_frame, 0.001, 0.25)) : 1.0f / 60.0f;
    last_frame = now;
    ui_should_render(io.MouseDown[0] || io.WantTextInput);
    ImGui_ImplOpenGL3_NewFrame();
    ImGui::NewFrame();
    ui_frame();
    ImGui::Render();
    glViewport(0, 0, surface_width, surface_height);
    glClearColor(0.078f, 0.078f, 0.125f, 1.0f);
    glClear(GL_COLOR_BUFFER_BIT);
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
    return static_cast<jint>(std::min(ui_sleep_ms(), io.WantTextInput ? 33u : 1000u))
        | (io.WantTextInput ? 0x10000 : 0);
}
extern "C" JNIEXPORT void JNICALL
Java_com_fc_fcaevpn_ImGuiBridge_nativePointer(JNIEnv*, jclass, jfloat x, jfloat y, jint action) {
    if (!initialized) return;
    ImGuiIO& io = ImGui::GetIO();
    static float previous_y = 0.0f;
    static float down_y = 0.0f;
    const float logical_y = y / density;
    if (action == 0) down_y = logical_y;
    if (action == 2 && ImGui::GetActiveID() == 0 && std::abs(logical_y - down_y) > 8.0f)
        io.AddMouseWheelEvent(0.0f, (logical_y - previous_y) / 48.0f);
    previous_y = logical_y;
    io.AddMouseSourceEvent(ImGuiMouseSource_TouchScreen);
    io.AddMousePosEvent(x / density, logical_y);
    if (action == 0) io.AddMouseButtonEvent(0, true);
    if (action == 1 || action == 3) io.AddMouseButtonEvent(0, false);
    ui_request_redraw();
}
extern "C" JNIEXPORT void JNICALL
Java_com_fc_fcaevpn_ImGuiBridge_nativeWheel(JNIEnv*, jclass, jfloat x, jfloat y) {
    if (initialized) ImGui::GetIO().AddMouseWheelEvent(x, y);
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
}
extern "C" JNIEXPORT void JNICALL
Java_com_fc_fcaevpn_ImGuiBridge_nativeText(JNIEnv* env, jclass, jstring value) {
    if (!initialized) return;
    const std::string text = native_string(env, value);
    ImGui::GetIO().AddInputCharactersUTF8(text.c_str());
}
extern "C" JNIEXPORT void JNICALL
Java_com_fc_fcaevpn_ImGuiBridge_nativeClipboard(JNIEnv* env, jclass, jstring value) {
    clipboard = native_string(env, value);
}
extern "C" JNIEXPORT void JNICALL
Java_com_fc_fcaevpn_ImGuiBridge_nativeVisibility(JNIEnv*, jclass, jboolean visible) {
    if (!initialized) return;
    ui_set_window_visible(visible); ui_set_window_focused(visible);
    if (!visible) {
        ImGui::GetIO().AddMouseButtonEvent(0, false);
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

extern "C" JNIEXPORT void JNICALL
Java_com_fc_fcaevpn_ImGuiBridge_nativeImport(JNIEnv* env, jclass, jstring kind, jstring text) {
    const std::string value = native_string(env, text);
    if (native_string(env, kind) == "routes") {
        const std::string path = files_dir + "/routes-import.txt";
        FILE* file = fopen(path.c_str(), "wb");
        if (!file) { last_error = "Cannot write routing rules"; return; }
        const bool written = fwrite(value.data(), 1, value.size(), file) == value.size();
        const bool closed = fclose(file) == 0;
        if (!written || !closed) { last_error = "Cannot save routing rules"; return; }
        snprintf(g_app.routes_file, sizeof(g_app.routes_file), "%s", path.c_str());
    } else {
        AppState::CoreConfigEntry entry;
        entry.name = "Imported config " + std::to_string(g_app.core_configs.size() + 1);
        entry.text = value;
        entry.backend = native_string(env, kind) == "core1" ? 1 : 0;
        g_app.core_configs.push_back(std::move(entry));
        g_app.refresh_core_listeners();
    }
    android_ui_flush_settings();
    ui_request_redraw();
}

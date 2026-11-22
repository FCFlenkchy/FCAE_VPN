#pragma once
#include "app_routing_ui.h"
#include <memory>
#include <cstdlib>

#if !defined(FCAE_IOS) && !defined(__IPHONE_OS_VERSION_MIN_REQUIRED)
#include "app_routing_inventory.h"
#endif

// Desktop draft persistence is separate from runtime enforcement acknowledgements.
// Android still owns its package inventory and VpnService policy contract.
namespace PlatformAppRouting {
struct Capabilities {
    bool enforcement;
    bool inventory;
    const char* explanation;
};
inline Capabilities capabilities() {
#if defined(FCAE_IOS) || defined(__IPHONE_OS_VERSION_MIN_REQUIRED)
    // Editable draft capability, explicitly not an enforcement acknowledgement.
    return {true, true,
        "Add apps by bundle identifier."};
#elif defined(_WIN32) || defined(__linux__) || defined(__APPLE__)
    return {fcae_app_routing_flow_available(), true,
        "Desktop routing uses the embedded sing-box captured-flow provider, not OS-level exclusion. Executable attribution is best effort. Unknown owners and ordinary DNS (ports 53/853) use the existing VPN exit chain. The normal LAN exclusions still apply. New connections only; no independent crash-persistent kill switch. Helper executables must be selected separately; application bundles, shared hosts and sandboxed packages are not grouped automatically. Native exit configurations may contain DIRECT rules; VPN here means handed to the configured exit chain, not a promise to override its rules. Requires the app's normal VPN administrator/root permission."};
#else
    return {false, false, "Per-app routing is not supported on this platform."};
#endif
}

inline const char* platform_name() {
#if defined(_WIN32)
    return "windows";
#elif defined(__APPLE__) && !defined(FCAE_IOS)
    return "macos";
#elif defined(__linux__) && !defined(ANDROID)
    return "linux";
#else
    return "unsupported";
#endif
}
inline bool uses_macos_ne() {
#if defined(__APPLE__) && !defined(FCAE_IOS)
    return g_app.desktop_app_mode!=0 && !g_app.desktop_app_paths.empty() && g_app.desktop_app_provider=="macos_ne" && fcae_app_routing_macos_ne_available();
#else
    return false;
#endif
}
inline Capabilities local_support() {
    auto result=capabilities();
#if defined(__APPLE__) && !defined(FCAE_IOS)
    if(g_app.desktop_app_provider=="macos_ne") {
        result.enforcement=fcae_app_routing_macos_ne_available();
        result.explanation="Experimental signed macOS transparent proxy, not packet-TUN capture. App identity is checked using audit tokens and designated signing requirements. Declined flows remain OS-routed; VPN-required flows use the existing exit chain with no direct fallback. Select helper executables explicitly. Shared OS DNS is not isolated per app. Native exit DIRECT rules still apply. Other VPNs can affect OS-routed flows. No independent crash-persistent kill switch; extension/host failure can release capture. Requires valid Apple entitlements, provisioning and user approval. An unsigned build cannot activate this provider.";
    }
#endif
#if !defined(FCAE_IOS) && !defined(__IPHONE_OS_VERSION_MIN_REQUIRED)
    if(!g_app.desktop_app_platform.empty()&&g_app.desktop_app_platform!=platform_name()) {
        result.enforcement=false;
        result.explanation="Foreign-platform selectors are retained inactive. Remove the imported app policy explicitly before creating a local one.";
    }
#endif
    return result;
}
class Panel {
public:
    Panel() : ui_(
        [this](const char* action, const std::string& payload) {
            if (std::strcmp(action, "load") == 0) {
                const auto revision = static_cast<uint64_t>(std::strtoull(payload.c_str(), nullptr, 10));
#if defined(FCAE_IOS) || defined(__IPHONE_OS_VERSION_MIN_REQUIRED)
                ui_.state(revision, g_app.ios_app_draft_mode, g_app.ios_app_draft_ids);
#else
                ui_.state(revision, g_app.desktop_app_mode, g_app.desktop_app_paths);
#endif
            }
#if defined(FCAE_IOS) || defined(__IPHONE_OS_VERSION_MIN_REQUIRED)
            else if (std::strcmp(action, "appsLoad") == 0) {
                ui_.apps({});
                ui_.inventory_status("Manually added apps.");
            }
#else
            else if (std::strcmp(action, "appsLoad") == 0) {
                if (!job_.start()) ui_.inventory_status("Application inventory is already loading.");
            }
#endif
            else if (std::strcmp(action, "save") == 0) {
#if defined(FCAE_IOS) || defined(__IPHONE_OS_VERSION_MIN_REQUIRED)
                auto ids=ui_.selected();
                if(ids.size()>8192){flow_message_="Draft not saved: too many identifiers.";return;}
                for(const auto& id:ids) {
                    const bool valid=!id.empty() && id.size()<=255 && id.front()!='.' && id.back()!='.' && id.find("..") == std::string::npos &&
                        std::all_of(id.begin(),id.end(),[](unsigned char c){return (c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='.'||c=='-';});
                    if(!valid){flow_message_="Draft not saved: bundle identifiers must use letters, digits, dots or hyphens, without empty components.";return;}
                }
                std::sort(ids.begin(),ids.end());
                g_app.ios_app_draft_ids=std::move(ids);g_app.ios_app_draft_mode=ui_.mode();
                ui_.accepted();flow_message_="Draft saved.";
                return;
#endif
#if defined(_WIN32)
                if (windows_use_driver_) {
                    if (!windows_risk_accepted_) return;
                    if (!g_app.desktop_app_platform.empty() && g_app.desktop_app_platform != platform_name()) {windows_message_="Remove foreign-platform selectors before creating a local driver policy.";return;}
                    const std::string request = "{\"action\":\"configure\",\"acknowledge_kernel_crash_risk\":true," + payload.substr(1);
                    char result[4096]{};
                    const auto status = fcae_app_routing_request(request.c_str(), result, sizeof(result), &windows_active_);
                    windows_message_ = result;
                    if (status != FCAE_OK) windows_message_ = "Draft was not accepted: " + windows_message_;
                    else ui_.accepted();
                    return;
                }
#endif
                if (!g_app.desktop_app_platform.empty() && g_app.desktop_app_platform != platform_name()) {
                    flow_message_ = "Foreign-platform selectors are retained inactive. Remove the imported policy before creating a local draft.";
                    return;
                }
                std::string request = "{\"action\":\"flow_configure\",\"platform\":\"" + std::string(platform_name()) + "\",\"provider\":\"";
                core_json_escape_into(request,g_app.desktop_app_provider);
                request += "\"," + payload.substr(1);
                char result[4096]{};
                const auto status = fcae_app_routing_request(request.c_str(), result, sizeof(result), &flow_active_);
                flow_message_ = result;
                if (status == FCAE_OK) {
                    g_app.desktop_app_mode = ui_.mode();
                    g_app.desktop_app_paths = ui_.selected();
                    std::sort(g_app.desktop_app_paths.begin(), g_app.desktop_app_paths.end());
                    g_app.desktop_app_platform = platform_name();
                    ui_.accepted();
                } else flow_message_ = "Draft rejected; saved policy was not replaced: " + flow_message_;
            }
        },
        [](const std::string& text) {
            std::string folded = text;
            for (char& c : folded) if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
            return folded;
        }, [](const std::string&) { return ImTextureID{}; })
#if !defined(FCAE_IOS) && !defined(__IPHONE_OS_VERSION_MIN_REQUIRED)
        , job_([] { ui_request_redraw(); })
#endif
    {
        const auto support = local_support();
        ui_.capabilities(support.enforcement, support.inventory, support.explanation);
        ui_.deferred_apply(true);
        ui_.manual_executable_selection(support.enforcement);
#if defined(FCAE_IOS) || defined(__IPHONE_OS_VERSION_MIN_REQUIRED)
        ui_.draft_only(true);
        ui_.platform_controls([this] {
            if(!flow_message_.empty())ImGui::TextWrapped("%s",flow_message_.c_str());
        });
#endif
#if defined(_WIN32)
        ui_.platform_controls([this] { windows_controls(); });
#endif
#if defined(__linux__) && !defined(ANDROID) && !defined(FCAE_IOS)
        const char* uid = std::getenv("SUDO_UID");
        if (!uid) uid = std::getenv("PKEXEC_UID");
        if (uid) { char* end = nullptr; const long value = std::strtol(uid, &end, 10);
            if (end && !*end && value > 0 && value <= 2147483647L) launch_uid_ = static_cast<int>(value); }
        ui_.application_action("Choose a row to fill the controlled-launch executable. This does not modify VPN policy.",
            [this](const AppRoutingUi::App& app) {
                if (!launch_active_ && app.id.size() < sizeof(launch_executable_)) {
                    std::memcpy(launch_executable_, app.id.c_str(), app.id.size() + 1);
                }
            });
        ui_.platform_controls([this] { flow_controls(); launch_controls(); });
#endif
#if defined(__APPLE__) && !defined(FCAE_IOS) && !defined(__IPHONE_OS_VERSION_MIN_REQUIRED)
        ui_.platform_controls([this] { flow_controls(); });
#endif
    }
    bool uses_driver() const {
#if defined(_WIN32)
        return windows_use_driver_;
#else
        return false;
#endif
    }
    void routing() {
        poll();
#if defined(_WIN32)
        if(!windows_use_driver_)
#endif
        {const auto support=local_support();ui_.capabilities(support.enforcement,support.inventory,support.explanation);}
        ui_.routing();
    }
    void picker() { poll(); ui_.picker(); }
private:
    AppRoutingUi ui_;
    bool flow_active_ = false;
#if defined(__APPLE__) && !defined(FCAE_IOS)
    bool ne_maintenance_active_=false;
    std::string ne_maintenance_message_;
#endif
    double flow_next_poll_ = 0;
    std::string flow_message_;
    void flow_controls() {
#if defined(__APPLE__) && !defined(FCAE_IOS)
        bool native=g_app.desktop_app_provider=="macos_ne";
        if(ImGui::Checkbox("Use signed transparent-proxy extension (experimental)",&native)) {
            g_app.desktop_app_provider=native?"macos_ne":"captured_flow";
            flow_message_="Provider choice saved for the next connection. No running flows were moved.";
        }
        if(native&&!fcae_app_routing_macos_ne_available())ImGui::TextWrapped("This app has no validated, matching signed extension host. Build/package it with NetworkExtension provisioning before activation. No captured-flow fallback will be substituted.");
        if(native&&fcae_app_routing_macos_ne_available()) {
            ImGui::BeginDisabled(fcae_is_running()||ne_maintenance_active_);
            if(ImGui::Button("Remove inactive proxy configuration")) {
                char result[4096]{};fcae_app_routing_request("{\"action\":\"macos_ne_remove\"}",result,sizeof(result),&ne_maintenance_active_);ne_maintenance_message_=result;
            }
            ImGui::EndDisabled();
            if(ne_maintenance_active_) {
                char result[4096]{};fcae_app_routing_request("{\"action\":\"macos_ne_maintenance_status\"}",result,sizeof(result),&ne_maintenance_active_);ne_maintenance_message_=result;ui_request_redraw();
            }
            if(!ne_maintenance_message_.empty())ImGui::TextWrapped("%s",ne_maintenance_message_.c_str());
        }
#endif
        const bool foreign=!g_app.desktop_app_platform.empty() && g_app.desktop_app_platform!=platform_name();
        if(foreign) {
            ImGui::TextWrapped("Imported %s selectors are inactive; they have not been reinterpreted for this platform.",g_app.desktop_app_platform.c_str());
            if(ImGui::Button("Remove foreign app policy")) {
                g_app.desktop_app_mode=0;g_app.desktop_app_paths.clear();g_app.desktop_app_platform=platform_name();g_app.desktop_app_provider="captured_flow";
                ui_.refresh();
            }
        }
        if (g_app.desktop_app_provider=="captured_flow" && !fcae_app_routing_flow_available()) ImGui::TextWrapped("This build has no live embedded sing-box flow provider. Saved drafts are not silently enforced by a proxy rule or a disabled picker.");
        const double now = ImGui::GetTime();
        if (now >= flow_next_poll_) {
            char result[4096]{};
            fcae_app_routing_request("{\"action\":\"flow_status\"}", result, sizeof(result), &flow_active_);
            if (result[0]) flow_message_ = result;
            flow_next_poll_ = now + 0.5;
        }
        if (!flow_message_.empty()) ImGui::TextWrapped("%s", flow_message_.c_str());
        if (flow_active_) ui_request_redraw();
    }
#if defined(_WIN32)
    bool windows_use_driver_ = false;
    bool windows_risk_accepted_ = false, windows_active_ = false, windows_recovery_pending_ = false;
    double windows_next_poll_ = 0;
    std::string windows_message_;
    void windows_controls() {
        if (!windows_use_driver_) flow_controls();
        const bool bundled = fcae_app_routing_experimental_windows_available();
        ImGui::BeginDisabled(!bundled);
        if (ImGui::Checkbox("Use experimental OS driver instead of captured-flow routing", &windows_use_driver_)) {
            if (!windows_use_driver_) {
                char result[4096]{};
                fcae_app_routing_request("{\"action\":\"stop\"}", result, sizeof(result), &windows_active_);
                ui_.refresh();
            }
        }
        ImGui::EndDisabled();
        ImGui::BeginDisabled(!bundled);
        if (ImGui::Checkbox("I accept the experimental kernel-driver crash risk (#11487)", &windows_risk_accepted_) && !windows_risk_accepted_) {
            char result[4096]{};
            fcae_app_routing_request("{\"action\":\"stop\"}", result, sizeof(result), &windows_active_);
            windows_message_ = result;
        }
        ImGui::EndDisabled();
        if (!bundled) ImGui::TextWrapped("The experimental split-driver package was not bundled into this build. No driver will be downloaded or installed at runtime.");
        if (ImGui::TreeNode("Driver provenance and known risk")) {
            ImGui::TextWrapped("Unmodified Mullvad split-tunnel driver 1.3.0.0, distributed under MPL-2.0. Its license is embedded and copied with the protected driver package. This is not a production-safety endorsement.");
            ImGui::TextWrapped("Source: https://github.com/mullvad/win-split-tunnel/tree/0a0eb97f67d1dbcb3d08bda66d3b24f465d95475");
            ImGui::TextWrapped("Unresolved crash report: https://github.com/mullvad/mullvadvpn-app/issues/11487");
            ImGui::TextWrapped("Recovery only accepts protected ownership records whose original process has exited. Live owners, other services and mismatched resources are refused. Recovery cannot fix a kernel crash or guarantee this experimental driver is safe.");
            ImGui::TreePop();
        }
        if (bundled && !fcae_is_privileged()) ImGui::TextWrapped("Driver installation needs administrator permission. Use the app's normal VPN elevation flow.");
        const auto support = local_support();
        if (windows_use_driver_) {
            ui_.allowed_modes(5u);
            ui_.capabilities(bundled && windows_risk_accepted_, support.inventory,
                "Experimental OS bypass: descendants inherit exclusions. DNS stays in the VPN tunnel. Include mode and an independent kill switch are unavailable. This draft is not persisted. Known upstream kernel-crash report remains unresolved.");
        } else {
            ui_.allowed_modes(7u);
            ui_.capabilities(support.enforcement, support.inventory, support.explanation);
        }
        ImGui::BeginDisabled(windows_active_ || windows_recovery_pending_ || !fcae_is_privileged());
        if (ImGui::Button("Recover stale FCAE Windows routing")) {
            char result[4096]{};
            windows_recovery_pending_ = fcae_app_routing_request("{\"action\":\"recover\"}", result, sizeof(result), &windows_active_) == FCAE_OK;
            windows_message_ = result;
        }
        ImGui::EndDisabled();
        const double now = ImGui::GetTime();
        if (now >= windows_next_poll_) {
            char result[4096]{};
            fcae_app_routing_request("{\"action\":\"status\"}", result, sizeof(result), &windows_active_);
            if (result[0]) windows_message_ = result;
            if (windows_message_.find("Recovering confirmed stale") != 0) windows_recovery_pending_ = false;
            windows_next_poll_ = now + 0.5;
        }
        if (windows_recovery_pending_) ui_request_redraw();
        if (!windows_message_.empty()) ImGui::TextWrapped("%s", windows_message_.c_str());
        if (windows_active_) ImGui::TextWrapped("Installed policy remains active until the VPN disconnects. Changing the draft or risk checkbox does not silently move existing flows.");
    }
#endif
#if defined(__linux__) && !defined(ANDROID) && !defined(FCAE_IOS)
    char launch_executable_[4096]{};
    int launch_uid_ = -1;
    bool launch_accepted_ = false, launch_active_ = false;
    double launch_next_poll_ = 0;
    std::string launch_message_;
    void launch_request(const char* command) {
        char result[4096]{};
        const FcaeStatus status = fcae_app_routing_request(command, result, sizeof(result), &launch_active_);
        launch_message_ = result;
        if (status != FCAE_OK && launch_message_.empty()) launch_message_ = "Routing request failed.";
    }
    void launch_controls() {
        if (!ImGui::CollapsingHeader("Experimental Linux controlled launch")) return;
        const double now = ImGui::GetTime();
        if (now >= launch_next_poll_) { launch_request("{\"action\":\"status\"}"); launch_next_poll_ = now + 0.25; }
        UiText::TextColoredWrapped(ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled),
            "Choose a target with the shared application picker above, or enter a path. Only a newly launched scope is covered; existing instances, service handoff and shared DNS are not. No VPN kill switch is provided. Closing FCAE or pressing Stop terminates every process in this launch scope. Recovery cleans stopped scopes only.");
        if (!fcae_is_privileged()) ImGui::TextWrapped("Requires FCAE to be running as root; no elevation helper is installed.");
        ImGui::BeginDisabled(launch_active_);
        ImGui::SetNextItemWidth(-FLT_MIN);
        UiText::InputTextWithHint("##launch_executable", "Absolute executable path", launch_executable_, sizeof(launch_executable_));
        ImGui::InputInt("Target non-root UID", &launch_uid_);
        ImGui::Checkbox("I accept the experimental launch limitations", &launch_accepted_);
        ImGui::EndDisabled();
        ImGui::BeginDisabled(launch_active_ || !launch_accepted_ || launch_uid_ <= 0 || launch_executable_[0] != '/' || !fcae_is_privileged());
        if (ImGui::Button("Launch outside VPN")) {
            std::string command = "{\"action\":\"launch\",\"uid\":" + std::to_string(launch_uid_) + ",\"executable\":\"";
            core_json_escape_into(command, launch_executable_); command += "\"}";
            launch_request(command.c_str());
        }
        ImGui::EndDisabled();
        ImGui::BeginDisabled(!launch_active_);
        if (ImGui::Button("Stop launched app and restore routes")) launch_request("{\"action\":\"stop\"}");
        ImGui::EndDisabled();
        ImGui::BeginDisabled(launch_active_ || !fcae_is_privileged());
        if (ImGui::Button("Recover stale routing (stopped apps only)")) launch_request("{\"action\":\"recover\"}");
        ImGui::EndDisabled();
        if (!launch_message_.empty()) ImGui::TextWrapped("%s", launch_message_.c_str());
        if (launch_active_) ui_request_redraw();
    }
#endif
#if !defined(FCAE_IOS) && !defined(__IPHONE_OS_VERSION_MIN_REQUIRED)
    AppRouting::InventoryJob job_;
#endif
    void poll() {
#if !defined(FCAE_IOS) && !defined(__IPHONE_OS_VERSION_MIN_REQUIRED)
        AppRouting::InventoryResult result;
        if (job_.poll(result)) {
            std::vector<AppRoutingUi::App> apps;
            apps.reserve(result.entries.size());
            for (auto& entry : result.entries)
                apps.push_back({std::move(entry.id), std::move(entry.label), std::move(entry.search)});
            ui_.apps(std::move(apps));
            ui_.inventory_status(std::move(result.status));
        }
#endif
    }
};
inline std::unique_ptr<Panel>& instance() { static std::unique_ptr<Panel> panel; return panel; }
inline Panel& panel() {
    auto& value = instance();
    if (!value) value = std::make_unique<Panel>();
    return *value;
}
inline std::string connection_policy() {
    if (instance() && instance()->uses_driver()) return "{\"mode\":0,\"apps\":[]}";
    std::string request = "{\"schema_version\":1,\"mode\":" + std::to_string(g_app.desktop_app_mode) + ",\"platform\":\"";
    core_json_escape_into(request, g_app.desktop_app_platform.empty() ? platform_name() : g_app.desktop_app_platform);
    request += "\",\"provider\":\"";
    core_json_escape_into(request,g_app.desktop_app_provider);
    request += "\",\"apps\":[";
    bool first = true;
    for (const auto& path : g_app.desktop_app_paths) {
        if (!first) request += ',';
        first = false; request += '\"'; core_json_escape_into(request, path); request += '\"';
    }
    request += "]}";
    return request;
}
inline void routing() { panel().routing(); }
inline void picker() { if (instance()) instance()->picker(); }
inline void shutdown() { instance().reset(); }
} // namespace PlatformAppRouting

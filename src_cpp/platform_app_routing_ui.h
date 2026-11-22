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
    return {true,true,""};
#else
    return {fcae_app_routing_flow_available(),true,""};
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
inline bool uses_macos_ne() {return false;}
inline Capabilities local_support() {return capabilities();}
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

                if (ui_.mode()!=0 && !g_app.desktop_app_platform.empty() && g_app.desktop_app_platform != platform_name()) {
                    flow_message_ = "Turn app routing off before replacing a policy from another platform.";
                    return;
                }
                std::string request = "{\"action\":\"flow_configure\",\"platform\":\"" + std::string(platform_name()) + "\",\"provider\":\"";
                g_app.desktop_app_provider="captured_flow";
                core_json_escape_into(request,"captured_flow");
                request += "\"," + payload.substr(1);
                char result[4096]{};
                const auto status = fcae_app_routing_request(request.c_str(), result, sizeof(result), &flow_active_);
                flow_message_ = status == FCAE_OK ? "" : result;
                if (status == FCAE_OK) {
                    g_app.desktop_app_mode = ui_.mode();
                    if(ui_.mode()==0 && !g_app.desktop_app_platform.empty() && g_app.desktop_app_platform!=platform_name()) {
                        g_app.desktop_app_paths.clear();
                    } else g_app.desktop_app_paths = ui_.selected();
                    std::sort(g_app.desktop_app_paths.begin(), g_app.desktop_app_paths.end());
                    g_app.desktop_app_platform = platform_name();
                    ui_.accepted();
                    if(ui_.mode()==0 && g_app.desktop_app_paths.empty())ui_.refresh();
                } else flow_message_ = "Draft rejected; saved policy was not replaced: " + flow_message_;
            }
        },
        [](const std::string& text) {
            std::string folded = text;
            for (char& c : folded) if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
            return folded;
        }, [](const std::string& id) { return app_routing_icon(id); })
#if !defined(FCAE_IOS) && !defined(__IPHONE_OS_VERSION_MIN_REQUIRED)
        , job_([] { ui_request_redraw(); })
#endif
    {
        const auto support = local_support();
        ui_.capabilities(support.enforcement, support.inventory, support.explanation);
        ui_.deferred_apply(false);
#if defined(FCAE_IOS) || defined(__IPHONE_OS_VERSION_MIN_REQUIRED)
        ui_.manual_executable_selection(true);
        ui_.draft_only(true);
#endif
        ui_.platform_controls([this] {if(!flow_message_.empty())ImGui::TextWrapped("%s",flow_message_.c_str());});
    }
    void routing() {
        poll();
        const auto support=local_support();ui_.capabilities(support.enforcement,support.inventory,support.explanation);
        ui_.routing();
    }
    void picker() { poll(); ui_.picker(); }
private:
    AppRoutingUi ui_;
    bool flow_active_ = false;
    std::string flow_message_;
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
    std::string request = "{\"schema_version\":1,\"mode\":" + std::to_string(g_app.desktop_app_mode) + ",\"platform\":\"";
    core_json_escape_into(request, g_app.desktop_app_platform.empty() ? platform_name() : g_app.desktop_app_platform);
    request += "\",\"provider\":\"";
    core_json_escape_into(request,"captured_flow");
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

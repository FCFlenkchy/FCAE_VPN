#pragma once
#include "app_routing_ui.h"

// Android owns package discovery, persistence and VpnService enforcement.
// Only the renderer/model is shared; the Java command contract stays intact.
class AndroidSettingsUi {
public:
    using App = AppRoutingUi::App;
    using Command = AppRoutingUi::Command;
    using Fold = AppRoutingUi::Fold;
    using Icon = AppRoutingUi::Icon;

    AndroidSettingsUi(Command command, Fold fold, Icon icon)
        : command_(std::move(command)), routing_(
            [this](const char* action, const std::string& payload) {
                if (std::strcmp(action, "load") == 0) command_("androidLoad", payload);
                else if (std::strcmp(action, "appsLoad") == 0) command_("appsLoad", payload);
                else if (std::strcmp(action, "save") == 0) {
                    std::string value = payload;
                    value.pop_back(); // AppRoutingUi emits one complete JSON object.
                    value += ",\"tile\":" + std::string(tile_ ? "true" : "false")
                           + ",\"widgets\":" + (widgets_ ? "true" : "false") + "}";
                    command_("androidSave", value);
                }
            }, std::move(fold), std::move(icon)) { routing_.capabilities(true, true, ""); }

    AndroidSettingsUi(const AndroidSettingsUi&) = delete;
    AndroidSettingsUi& operator=(const AndroidSettingsUi&) = delete;

    void refresh() { routing_.refresh(); }
    void state(uint64_t revision, int mode, std::vector<std::string> selected, bool tile, bool widgets) {
        if (routing_.state(revision, mode, std::move(selected))) { tile_ = tile; widgets_ = widgets; }
    }
    void apps(std::vector<App> values) { routing_.apps(std::move(values)); }
    void discard_inventory() { routing_.discard_inventory(); }
    void routing() { routing_.routing(); }
    void picker() { routing_.picker(); }
    void controls() {
        routing_.ensure_loaded();
        ImGui::BeginDisabled(!routing_.loaded());
        if (ImGui::Checkbox("Quick Settings tile", &tile_)) routing_.commit();
        if (ImGui::Checkbox("Home-screen widgets", &widgets_)) routing_.commit();
        ImGui::EndDisabled();
    }
private:
    Command command_;
    bool tile_ = false, widgets_ = false;
    AppRoutingUi routing_;
};

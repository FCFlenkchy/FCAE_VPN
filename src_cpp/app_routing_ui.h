#pragma once
#include "ui_text_input.h"
#include "destination_routing_ui.h"

#include "ui_render.h"
#include "imgui_internal.h"
#include <functional>
#include <unordered_set>

class AppRoutingUi {
public:
    struct App { std::string id, label, search; };
    using Command = std::function<void(const char*, const std::string&)>;
    using Fold = std::function<std::string(const std::string&)>;
    using Icon = std::function<ImTextureID(const std::string&)>;
    using ApplicationAction = std::function<void(const App&)>;

    AppRoutingUi(Command command, Fold fold, Icon icon)
        : command_(std::move(command)), fold_(std::move(fold)), icon_(std::move(icon)) {}

    void refresh() {
        requested_ = true;
        command_("load", std::to_string(revision_));
    }

    bool state(uint64_t revision, int mode, std::vector<std::string> selected) {
        if (revision != revision_) return false;
        mode_ = std::clamp(mode, 0, 2);
        selected_.clear();
        selected_.insert(selected.begin(), selected.end());
        loaded_ = requested_ = true;
        saved_mode_ = mode_;
        saved_selected_ = selected_;
        dirty_ = false;
        retain_selected_rows();
        filter_dirty_ = true;
        return true;
    }

    void apps(std::vector<App> values) {
        apps_ = std::move(values);
        retain_selected_rows();
        loading_apps_ = false;
        filter_dirty_ = true;
    }

    // A visible picker is not proof of an installed enforcement mechanism.
    void capabilities(bool editable, bool inventory, const char* reason) {
        if (editable_ != editable) filter_dirty_ = true;
        editable_ = editable;
        inventory_ = inventory;
        capability_reason_ = reason ? reason : "";
    }
    void allowed_modes(unsigned mask) { allowed_modes_ = mask & 7u; }
    void draft_only(bool enabled) { draft_only_ = enabled; }
    void deferred_apply(bool enabled) { deferred_apply_ = enabled; }
    void accepted() { saved_mode_ = mode_; saved_selected_ = selected_; dirty_ = false; }
    void manual_executable_selection(bool enabled) { manual_executable_ = enabled; }
    int mode() const { return mode_; }
    std::vector<std::string> selected() const { return {selected_.begin(), selected_.end()}; }
    bool loaded() const { return loaded_; }
    void ensure_loaded() { if (!requested_) refresh(); }
    void commit() { save(); }
    void inventory_status(std::string message) { inventory_status_ = std::move(message); }
    // Optional platform action reuses this picker without granting policy-write
    // capability. Choosing a launch target is not an enforced include/exclude rule.
    void application_action(const char* label, ApplicationAction action) {
        action_label_ = label ? label : ""; application_action_ = std::move(action);
    }
    void platform_controls(std::function<void()> render) { platform_controls_ = std::move(render); }

    void routing() {
        ensure_loaded();
        ImGui::Spacing();
        ImGui::TextUnformatted(draft_only_ ? "App-selection draft" : "Split tunneling");
        ImGui::BeginDisabled(!loaded_ || !editable_);
        static const char* live_modes[] = {"Off", "Only Selected Apps (Whitelist)", "Bypass Selected Apps (Blacklist)"};
        static const char* draft_modes[] = {"Off (draft)", "Only selected apps (draft)", "Bypass selected apps (draft)"};
        const char* const* modes = draft_only_ ? draft_modes : live_modes;
        ImGui::SetNextItemWidth(-FLT_MIN);
        if (allowed_modes_ == 7u) {
            if (ImGui::Combo("##split_tunnel_mode", &mode_, modes, 3)) save();
        } else if (ImGui::BeginCombo("##split_tunnel_mode", modes[mode_])) {
            for (int mode = 0; mode < 3; ++mode) {
                ImGui::BeginDisabled((allowed_modes_ & (1u << mode)) == 0);
                if (ImGui::Selectable(modes[mode], mode_ == mode)) { mode_ = mode; save(); }
                ImGui::EndDisabled();
            }
            ImGui::EndCombo();
        }
        ImGui::EndDisabled();
        if (inventory_ && (mode_ != 0 || !editable_)) {
            const std::string label = editable_ ? std::string(draft_only_ ? "Edit app draft (" : "Select Apps (") + std::to_string(selected_.size()) + ")"
                                               : (application_action_ ? "Choose application for controlled launch" : "View running applications");
            if (ImGui::Button(label.c_str())) open_picker_ = true;
        }
        if (!capability_reason_.empty())
            UiText::TextColoredWrapped(ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled), "%s", capability_reason_.c_str());
        if (editable_ && !draft_only_) ImGui::TextWrapped("App routing applies on the next connection. Restart the app or reconnect its network sessions to apply fully.");
        if (deferred_apply_ && editable_) {
            if (!draft_only_ && mode_ == 2 && selected_.empty()) ImGui::TextWrapped("No exclusions: all captured apps use the VPN.");
            ImGui::BeginDisabled(!dirty_ || (mode_ == 1 && selected_.empty()));
            if (ImGui::Button(draft_only_ ? "Save app draft" : "Apply app policy")) dispatch_save();
            ImGui::EndDisabled();
            ImGui::SameLine();
            ImGui::BeginDisabled(!dirty_);
            if (ImGui::Button("Cancel app changes")) {
                mode_ = saved_mode_; selected_ = saved_selected_; dirty_ = false;
                retain_selected_rows(); filter_dirty_ = true;
            }
            ImGui::EndDisabled();
            if (dirty_) ImGui::TextDisabled(draft_only_ ? "Unsaved draft changes." : "Unapplied changes — the saved connection policy is unchanged.");
        }
        if (platform_controls_) platform_controls_();
        destination_routing_ui();
    }

    void picker() {
        constexpr const char* title = "Applications##app_routing_picker";
        if (open_picker_) {
            open_picker_ = false;
            query_[0] = 0;
            folded_query_.clear();
            filter_dirty_ = true;
            loading_apps_ = true;
            command_("appsLoad", "");
            ImGui::OpenPopup(title);
        }
        const ImGuiViewport* viewport = ImGui::GetMainViewport();
        const ImVec2 room(std::max(1.0f, viewport->WorkSize.x - 24), std::max(1.0f, viewport->WorkSize.y - 24));
        ImGui::SetNextWindowPos(viewport->GetWorkCenter(), ImGuiCond_Always, ImVec2(0.5f, 0.5f));
        ImGui::SetNextWindowSize(ImVec2(std::min(560.0f, room.x), std::min(640.0f, room.y)), ImGuiCond_Always);
        ImGui::SetNextWindowSizeConstraints(ImVec2(1, 1), room);
        bool opened = true;
        if (!ImGui::BeginPopupModal(title, &opened, ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize)) return;
        ImGui::SetNextItemWidth(-FLT_MIN);
        if (UiText::InputTextWithHint("##app_search", "Search by application name or identifier", query_, sizeof(query_))) {
            folded_query_ = fold_(query_);
            filter_dirty_ = true;
            reset_scroll_ = true;
        }
        if (editable_) {
            if (ImGui::Checkbox("Selected apps only", &selected_only_)) filter_dirty_ = true;
            if (manual_executable_) {
                ImGui::SetNextItemWidth(-FLT_MIN);
                UiText::InputTextWithHint("##manual_app", draft_only_ ? "Bundle identifier, e.g. com.example.app" : "Absolute executable path (validated on connect)", manual_path_, sizeof(manual_path_));
                ImGui::BeginDisabled(!manual_path_[0]);
                if (ImGui::Button(draft_only_ ? "Add bundle identifier" : "Add executable")) {
                    selected_.insert(manual_path_);
                    retain_selected_rows(); manual_path_[0] = 0; filter_dirty_ = true; save();
                }
                ImGui::EndDisabled();
            }
        }
        if (filter_dirty_) refilter();
        if (editable_) ImGui::Text("%zu selected | %zu shown", selected_.size(), filtered_.size());
        else ImGui::Text("%zu executable identities shown (policy read-only)", filtered_.size());
        if (!editable_ && application_action_) ImGui::TextWrapped("%s", action_label_.c_str());
        if (!inventory_status_.empty())
            UiText::TextColoredWrapped(ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled), "%s", inventory_status_.c_str());
        if (loading_apps_) ImGui::TextDisabled("Loading apps...");
        const float footer = ImGui::GetFrameHeightWithSpacing();
        ImGui::BeginChild("##app_list", ImVec2(0, -footer), ImGuiChildFlags_Borders);
        if (reset_scroll_) { ImGui::SetScrollY(0); reset_scroll_ = false; }
        const float row_height = std::max(36.0f, ImGui::GetTextLineHeight() * 2 + 4) + 8;
        int toggled = -1, action_index = -1;
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(filtered_.size()), row_height + ImGui::GetStyle().ItemSpacing.y);
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const size_t index = filtered_[row];
                const App& app = apps_[index];
                ImGui::PushID(app.id.c_str());
                const bool selected = editable_ ? selected_.count(app.id) != 0 : action_identity_ == app.id;
                const ImVec2 start = ImGui::GetCursorScreenPos();
                const float width = ImGui::GetContentRegionAvail().x;
                if (ImGui::Selectable("##app", selected, (editable_ || application_action_) ? ImGuiSelectableFlags_None : ImGuiSelectableFlags_Disabled,
                                      ImVec2(width, row_height))) {
                    if (editable_) toggled = static_cast<int>(index);
                    else if (application_action_) action_index = static_cast<int>(index);
                }
                ImDrawList* draw = ImGui::GetWindowDrawList();
                const ImTextureID texture = icon_(app.id);
                if (texture) draw->AddImage(texture, ImVec2(start.x + 4, start.y + 4), ImVec2(start.x + 40, start.y + 40));
                const float check_size = ImGui::GetFontSize();
                const ImVec2 check(start.x + width - check_size - 6, start.y + (row_height - check_size) * 0.5f);
                if (editable_) {
                    draw->AddRect(check, ImVec2(check.x + check_size, check.y + check_size), ImGui::GetColorU32(ImGuiCol_Border), 3);
                    if (selected) ImGui::RenderCheckMark(draw, check, ImGui::GetColorU32(ImGuiCol_CheckMark), check_size);
                }
                draw->PushClipRect(ImVec2(start.x + 48, start.y), ImVec2(check.x - 6, start.y + row_height), true);
                draw->AddText(ImVec2(start.x + 48, start.y + 4), ImGui::GetColorU32(ImGuiCol_Text), app.label.c_str());
                draw->AddText(ImVec2(start.x + 48, start.y + 6 + ImGui::GetTextLineHeight()), ImGui::GetColorU32(ImGuiCol_TextDisabled), app.id.c_str());
                draw->PopClipRect();
                if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNormal | ImGuiHoveredFlags_AllowWhenDisabled)) UiText::Tooltip("%s\n%s", app.label.c_str(), app.id.c_str());
                ImGui::PopID();
            }
        }
        if (!loading_apps_ && filtered_.empty()) ImGui::TextDisabled("No matching apps");
        ImGui::EndChild();
        if (toggled >= 0) {
            const std::string& id = apps_[toggled].id;
            if (selected_.count(id)) selected_.erase(id); else selected_.insert(id);
            filter_dirty_ = true;
            save();
        }
        if (action_index >= 0 && application_action_) {
            // Copy before invoking a platform callback, which may replace inventory.
            const App app = apps_[action_index];
            action_identity_ = app.id;
            application_action_(app);
            ImGui::CloseCurrentPopup();
        }
        if (ImGui::Button("Close")) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }

private:
    Command command_;
    Fold fold_;
    Icon icon_;
    ApplicationAction application_action_;
    std::function<void()> platform_controls_;
    std::string action_label_, action_identity_;
    std::vector<App> apps_;
    std::vector<size_t> filtered_;
    std::unordered_set<std::string> selected_;
    std::string folded_query_;
    char query_[256]{};
    char manual_path_[4096]{};
    bool selected_only_ = false, manual_executable_ = false;
    uint64_t revision_ = 0;
    unsigned allowed_modes_ = 7u;
    int mode_ = 0;
    bool draft_only_ = false;
    bool deferred_apply_ = false, dirty_ = false;
    int saved_mode_ = 0;
    std::unordered_set<std::string> saved_selected_;
    bool editable_ = false, inventory_ = false;
    std::string capability_reason_, inventory_status_;
    bool loaded_ = false, requested_ = false, loading_apps_ = false;
    bool open_picker_ = false, filter_dirty_ = false, reset_scroll_ = false;

    void retain_selected_rows() {
        for (const auto& id : selected_) {
            if (std::none_of(apps_.begin(), apps_.end(), [&](const App& app) { return app.id == id; }))
                apps_.push_back({id, id, fold_(id)});
        }
    }
    void refilter() {
        filtered_.clear();
        // Inventory is already alphabetic, so stable selected-first partitioning
        // needs no sort or PackageManager calls on a render/search frame.
        for (bool selected : {true, false})
            for (size_t index = 0; index < apps_.size(); ++index)
                if ((!editable_ || !selected_only_ || selected) && (selected_.count(apps_[index].id) != 0) == selected &&
                    (folded_query_.empty() || apps_[index].search.find(folded_query_) != std::string::npos))
                    filtered_.push_back(index);
        filter_dirty_ = false;
    }

    void save() {
        if (!loaded_ || !editable_) return;
        if (deferred_apply_) { dirty_ = mode_ != saved_mode_ || selected_ != saved_selected_; return; }
        dispatch_save();
    }
    void dispatch_save() {
        if (!loaded_ || !editable_) return;
        ++revision_;
        std::string payload = "{\"revision\":" + std::to_string(revision_) + ",\"mode\":" + std::to_string(mode_)
            + ",\"apps\":[";
        bool first = true;
        for (const std::string& id : selected_) {
            if (!first) payload += ',';
            first = false;
            payload += '"'; core_json_escape_into(payload, id); payload += '"';
        }
        payload += "]}";
        command_("save", payload);
    }
};

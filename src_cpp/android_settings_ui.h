#pragma once

#include "ui_render.h"
#include "imgui_internal.h"
#include <functional>
#include <unordered_set>

class AndroidSettingsUi {
public:
    struct App { std::string package, label, search; };
    using Command = std::function<void(const char*, const std::string&)>;
    using Fold = std::function<std::string(const std::string&)>;
    using Icon = std::function<ImTextureID(const std::string&)>;

    AndroidSettingsUi(Command command, Fold fold, Icon icon)
        : command_(std::move(command)), fold_(std::move(fold)), icon_(std::move(icon)) {}

    void refresh() {
        requested_ = true;
        command_("androidLoad", std::to_string(revision_));
    }

    void state(uint64_t revision, int mode, std::vector<std::string> selected, bool tile, bool widgets) {
        if (revision != revision_) return;
        mode_ = std::clamp(mode, 0, 2);
        selected_.clear();
        selected_.insert(selected.begin(), selected.end());
        tile_ = tile;
        widgets_ = widgets;
        loaded_ = requested_ = true;
        filter_dirty_ = true;
    }

    void apps(std::vector<App> values) {
        apps_ = std::move(values);
        loading_apps_ = false;
        filter_dirty_ = true;
    }

    void controls() {
        ensure_loaded();
        ImGui::BeginDisabled(!loaded_);
        if (ImGui::Checkbox("Quick Settings tile", &tile_)) save();
        if (ImGui::Checkbox("Home-screen widgets", &widgets_)) save();
        ImGui::EndDisabled();
    }

    void routing() {
        ensure_loaded();
        ImGui::Spacing();
        ImGui::TextUnformatted("Split tunneling");
        ImGui::BeginDisabled(!loaded_);
        static const char* modes[] = {"Off", "Only Selected Apps (Whitelist)", "Bypass Selected Apps (Blacklist)"};
        ImGui::SetNextItemWidth(-FLT_MIN);
        if (ImGui::Combo("##split_tunnel_mode", &mode_, modes, 3)) save();
        if (mode_ != 0) {
            const std::string label = "Select Apps (" + std::to_string(selected_.size()) + ")";
            if (ImGui::Button(label.c_str())) open_picker_ = true;
        }
        ImGui::EndDisabled();
        ImGui::TextWrapped("App routing applies on the next connection.");
    }

    void picker() {
        constexpr const char* title = "Select Apps##android_apps";
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
        if (ImGui::InputTextWithHint("##app_search", "Search by app or package name", query_, sizeof(query_))) {
            folded_query_ = fold_(query_);
            filter_dirty_ = true;
            reset_scroll_ = true;
        }
        if (filter_dirty_) refilter();
        ImGui::Text("%zu selected | %zu shown", selected_.size(), filtered_.size());
        if (loading_apps_) ImGui::TextDisabled("Loading apps...");
        const float footer = ImGui::GetFrameHeightWithSpacing();
        ImGui::BeginChild("##app_list", ImVec2(0, -footer), ImGuiChildFlags_Borders);
        if (reset_scroll_) { ImGui::SetScrollY(0); reset_scroll_ = false; }
        const float row_height = std::max(36.0f, ImGui::GetTextLineHeight() * 2 + 4) + 8;
        int toggled = -1;
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(filtered_.size()), row_height + ImGui::GetStyle().ItemSpacing.y);
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const size_t index = filtered_[row];
                const App& app = apps_[index];
                ImGui::PushID(app.package.c_str());
                const bool selected = selected_.count(app.package) != 0;
                const ImVec2 start = ImGui::GetCursorScreenPos();
                const float width = ImGui::GetContentRegionAvail().x;
                if (ImGui::Selectable("##app", selected, ImGuiSelectableFlags_None, ImVec2(width, row_height))) toggled = static_cast<int>(index);
                ImDrawList* draw = ImGui::GetWindowDrawList();
                const ImTextureID texture = icon_(app.package);
                if (texture) draw->AddImage(texture, ImVec2(start.x + 4, start.y + 4), ImVec2(start.x + 40, start.y + 40));
                const float check_size = ImGui::GetFontSize();
                const ImVec2 check(start.x + width - check_size - 6, start.y + (row_height - check_size) * 0.5f);
                draw->AddRect(check, ImVec2(check.x + check_size, check.y + check_size), ImGui::GetColorU32(ImGuiCol_Border), 3);
                if (selected) ImGui::RenderCheckMark(draw, check, ImGui::GetColorU32(ImGuiCol_CheckMark), check_size);
                draw->PushClipRect(ImVec2(start.x + 48, start.y), ImVec2(check.x - 6, start.y + row_height), true);
                draw->AddText(ImVec2(start.x + 48, start.y + 4), ImGui::GetColorU32(ImGuiCol_Text), app.label.c_str());
                draw->AddText(ImVec2(start.x + 48, start.y + 6 + ImGui::GetTextLineHeight()), ImGui::GetColorU32(ImGuiCol_TextDisabled), app.package.c_str());
                draw->PopClipRect();
                if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNormal)) ImGui::SetTooltip("%s\n%s", app.label.c_str(), app.package.c_str());
                ImGui::PopID();
            }
        }
        if (!loading_apps_ && filtered_.empty()) ImGui::TextDisabled("No matching apps");
        ImGui::EndChild();
        if (toggled >= 0) {
            const std::string& package = apps_[toggled].package;
            if (selected_.count(package)) selected_.erase(package); else selected_.insert(package);
            filter_dirty_ = true;
            save();
        }
        if (ImGui::Button("Close")) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }

private:
    Command command_;
    Fold fold_;
    Icon icon_;
    std::vector<App> apps_;
    std::vector<size_t> filtered_;
    std::unordered_set<std::string> selected_;
    std::string folded_query_;
    char query_[256]{};
    uint64_t revision_ = 0;
    int mode_ = 0;
    bool tile_ = false, widgets_ = false;
    bool loaded_ = false, requested_ = false, loading_apps_ = false;
    bool open_picker_ = false, filter_dirty_ = false, reset_scroll_ = false;

    void ensure_loaded() { if (!requested_) refresh(); }

    void refilter() {
        filtered_.clear();
        // Inventory is already alphabetic, so stable selected-first partitioning
        // needs no sort or PackageManager calls on a render/search frame.
        for (bool selected : {true, false})
            for (size_t index = 0; index < apps_.size(); ++index)
                if ((selected_.count(apps_[index].package) != 0) == selected &&
                    (folded_query_.empty() || apps_[index].search.find(folded_query_) != std::string::npos))
                    filtered_.push_back(index);
        filter_dirty_ = false;
    }

    void save() {
        ++revision_;
        std::string payload = "{\"revision\":" + std::to_string(revision_) + ",\"mode\":" + std::to_string(mode_)
            + ",\"tile\":" + (tile_ ? "true" : "false") + ",\"widgets\":" + (widgets_ ? "true" : "false") + ",\"apps\":[";
        bool first = true;
        for (const std::string& package : selected_) {
            if (!first) payload += ',';
            first = false;
            payload += '"'; core_json_escape_into(payload, package); payload += '"';
        }
        payload += "]}";
        command_("androidSave", payload);
    }
};

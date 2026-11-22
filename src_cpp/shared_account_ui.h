#pragma once

// Shared by the Firefox and URnetwork account/settings dialogs on every host.
static bool begin_account_dialog(const char* title, float width) {
    ImGui::SetNextWindowPos(viewport_center(), ImGuiCond_Always, ImVec2(0.5f, 0.5f));
    const ImVec2 room = ImGui::GetMainViewport()->WorkSize;
    ImGui::SetNextWindowSize(ImVec2(std::min(width, std::max(1.0f, room.x - 24)), 0), ImGuiCond_Appearing);
    ImGui::SetNextWindowSizeConstraints(ImVec2(1, 1), ImVec2(std::max(1.0f, room.x - 24), std::max(1.0f, room.y - 24)));
    return ImGui::BeginPopupModal(title, nullptr, ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoMove);
}
static void account_identity_fields(char* email, size_t email_size, char* password, size_t password_size) {
    ImGui::SetNextItemWidth(-1);
    UiText::InputTextWithHint("##account_email", "Email", email, email_size);
    ImGui::SetNextItemWidth(-1);
    UiText::InputTextWithHint("##account_password", "Password", password, password_size, ImGuiInputTextFlags_Password);
}
static bool account_region_combo(const char* id, std::string& selected,
        const std::vector<std::pair<std::string, std::string>>& options) {
    std::string preview = selected.empty() ? "Best available" : selected;
    for (const auto& row : options) if (row.first == selected) preview = row.second;
    ImGui::PushID(id);
    ImGui::TextUnformatted("Region");
    ImGui::SetNextItemWidth(-1);
    bool changed = false;
    const bool open = ImGui::BeginCombo("##region", preview.c_str());
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", preview.c_str());
    if (open) {
        auto choice = [&](const std::string& value, const std::string& label) {
            ImGui::PushID(value.c_str());
            const float width = std::max(40.0f, ImGui::GetContentRegionAvail().x);
            const ImVec2 text = ImGui::CalcTextSize(label.c_str(), nullptr, false, width - 8);
            if (ImGui::Selectable("##choice", selected == value, 0, ImVec2(0, text.y + 6))) {
                selected = value; changed = true;
            }
            const ImVec2 min = ImGui::GetItemRectMin();
            ImGui::GetWindowDrawList()->AddText(nullptr, 0, ImVec2(min.x + 4, min.y + 3),
                ImGui::GetColorU32(ImGuiCol_Text), label.c_str(), nullptr, width - 8);
            ImGui::PopID();
        };
        choice("", "Best available");
        for (const auto& row : options) if (!row.first.empty()) choice(row.first, row.second);
        ImGui::EndCombo();
    }
    ImGui::PopID();
    return changed;
}

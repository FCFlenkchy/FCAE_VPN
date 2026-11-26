#pragma once

// Shared by the Firefox and URnetwork account/settings dialogs on every host.
//
// The width is fixed and only the height follows the content. Fitting both
// axes to the content made the dialog fit itself to its own fields: a field
// sized "to the right edge" is a pixel narrower than the room it was given, so
// every drawn frame took a pixel off the window and, centred as it is, slid its
// left edge to the right until only the buttons held it open.
//
// It opens centred and then keeps its top edge where that put it. A status line
// below the buttons comes and goes, and a dialog centred afresh on each of
// those changes moved the field being typed in up and down with it.
static bool begin_account_dialog(const char* title, float width) {
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    const ImVec2 room = viewport->WorkSize;
    // A resized window, a rotated screen or a keyboard sliding in changes the
    // room the dialog is centred in; on that frame it is centred again.
    static ImVec2 s_room_pos, s_room_size;
    static int s_room_frame = -1;
    if (s_room_pos.x != viewport->WorkPos.x || s_room_pos.y != viewport->WorkPos.y
            || s_room_size.x != room.x || s_room_size.y != room.y) {
        s_room_pos = viewport->WorkPos;
        s_room_size = room;
        s_room_frame = ImGui::GetFrameCount();
    }
    // "Drawn last frame": a popup is hidden on the frame it opens, which only
    // measures it, so the frame after that is the first with its real size.
    const ImGuiWindow* shown = ImGui::FindWindowByName(title);
    if (shown && shown->WasActive && !shown->Hidden && s_room_frame != ImGui::GetFrameCount()) {
        // Kept on screen when it grows: the size is last frame's, so a dialog
        // that outgrows the room is pulled back up one frame later.
        const float lowest = viewport->WorkPos.y + room.y - 12.0f - shown->Size.y;
        const float top = std::max(viewport->WorkPos.y + 12.0f, std::min(shown->Pos.y, lowest));
        ImGui::SetNextWindowPos(ImVec2(viewport_center().x, top), ImGuiCond_Always, ImVec2(0.5f, 0.0f));
    } else {
        ImGui::SetNextWindowPos(viewport_center(), ImGuiCond_Always, ImVec2(0.5f, 0.5f));
    }
    ImGui::SetNextWindowSize(ImVec2(std::min(width, std::max(1.0f, room.x - 24)), 0), ImGuiCond_Always);
    ImGui::SetNextWindowSizeConstraints(ImVec2(1, 1), ImVec2(std::max(1.0f, room.x - 24), std::max(1.0f, room.y - 24)));
    return ImGui::BeginPopupModal(title, nullptr, ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoMove);
}
/// A dialog's quieter action (Cancel, Close, Later): the shape of the primary
/// button without competing with it for the eye.
static bool secondary_button(const char* label, const ImVec2& size = ImVec2(0, 0)) {
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.20f, 0.25f, 0.34f, 0.90f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.27f, 0.34f, 0.46f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.17f, 0.22f, 0.30f, 1.0f));
    const bool pressed = ImGui::Button(label, size);
    ImGui::PopStyleColor(3);
    return pressed;
}
/// Continue a row of buttons with `next_label` while it fits, and start a new
/// row when it does not: a dialog is as narrow as a phone lets it be.
static void button_row_next(const char* next_label) {
    const float needed = ImGui::CalcTextSize(next_label, nullptr, true).x + ImGui::GetStyle().FramePadding.x * 2.0f;
    ImGui::SameLine();
    if (ImGui::GetContentRegionAvail().x < needed) ImGui::NewLine();
}
/// Email over password, each as wide as the dialog. Returns true when Enter was
/// pressed in either field, so the caller can submit the form from the keyboard.
static bool account_identity_fields(char* email, size_t email_size, char* password, size_t password_size,
        const char* password_hint = "Password") {
    bool submitted = false;
    ImGui::SetNextItemWidth(-FLT_MIN);
    submitted |= UiText::InputTextWithHint("##account_email", "Email", email, email_size,
        ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SetNextItemWidth(-FLT_MIN);
    submitted |= UiText::InputTextWithHint("##account_password", password_hint, password, password_size,
        ImGuiInputTextFlags_Password | ImGuiInputTextFlags_EnterReturnsTrue);
    return submitted;
}
static bool account_region_combo(const char* id, std::string& selected,
        const std::vector<std::pair<std::string, std::string>>& options) {
    std::string preview = selected.empty() ? "Auto" : selected;
    for (const auto& row : options) if (row.first == selected) preview = row.second;
    ImGui::PushID(id);
    ImGui::TextUnformatted("Region");
    ImGui::SetNextItemWidth(-FLT_MIN);
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
        choice("", "Auto");
        for (const auto& row : options) if (!row.first.empty()) choice(row.first, row.second);
        ImGui::EndCombo();
    }
    ImGui::PopID();
    return changed;
}

static void backend_log_combo(const char* label, uint32_t backend, int& level) {
    static const char* const levels[] = {"Silent", "Error", "Warning", "Info", "Debug"};
    ImGui::TextUnformatted(label);
    ImGui::PushID(label);
    ImGui::SetNextItemWidth(-FLT_MIN);
    if (ImGui::Combo("##log_level", &level, levels, 5))
        fcae_backend_set_log_level(backend, (uint32_t)level);
    ImGui::PopID();
}

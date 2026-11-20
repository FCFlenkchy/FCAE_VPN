#pragma once
#include "imgui.h"
#include "imgui_internal.h"
#include <cstdarg>
#include <algorithm>
#include <cstring>

namespace UiText {
inline void TextColoredWrapped(const ImVec4& color, const char* format, ...) {
    ImGui::PushStyleColor(ImGuiCol_Text, color);
    ImGui::PushTextWrapPos(0.0f);
    va_list args;
    va_start(args, format);
    ImGui::TextV(format, args);
    va_end(args);
    ImGui::PopTextWrapPos();
    ImGui::PopStyleColor();
}

// Host touch/clipboard hooks. Editing and menus remain entirely in ImGui.
inline bool (*touch_hold)(ImGuiID, const ImRect&) = nullptr;
inline bool (*touch_menu)(ImGuiID) = nullptr;
inline void (*refresh_clipboard)() = nullptr;
namespace Detail {
inline ImGuiContext* context = nullptr;
inline ImGuiID select_id = 0, menu_id = 0, popup_id = 0, restore_id = 0, collapse_id = 0;
inline int select_frame = 0, menu_frame = 0, restore_frame = 0, collapse_frame = 0;
inline int start = 0, end = 0;
inline ImGuiKey action = ImGuiKey_None;
}
inline void close_menu() {
    if (GImGui && Detail::context == GImGui && Detail::popup_id)
        for (int n = 0; n < GImGui->OpenPopupStack.Size; ++n)
            if (GImGui->OpenPopupStack[n].PopupId == Detail::popup_id) {
                ImGui::ClosePopupToLevel(n, true); break;
            }
    Detail::popup_id = 0;
}
inline void reset() {
    close_menu();
    Detail::context = ImGui::GetCurrentContext();
    Detail::select_id = Detail::menu_id = Detail::restore_id = Detail::collapse_id = 0;
    Detail::action = ImGuiKey_None;
    Detail::start = Detail::end = 0;
}
inline void reset_android_view() { reset(); }
inline bool wants_keyboard() {
    using namespace Detail;
    if (!GImGui) return false;
    if (context != GImGui) reset();
    if (menu_id && GImGui->FrameCount > menu_frame + 1) { close_menu(); menu_id = 0; }
    if (restore_id && GImGui->FrameCount > restore_frame + 6) { restore_id = 0; action = ImGuiKey_None; }
    if (collapse_id && GImGui->FrameCount > collapse_frame + 6) collapse_id = 0;
    return menu_id || restore_id || collapse_id;
}
inline void prepare(const char* label) {
    wants_keyboard(); // Also expires a pending restore if the field disappeared.
    const ImGuiID id = ImGui::GetID(label);
    // A text-actions popup must not turn the editor's selection into a visual
    // imitation. Keep the real InputText state active so ImGui renders and
    // operates on its own selected range (including wrapped/multiline text).
    if (id != 0 && Detail::menu_id == id && Detail::popup_id != 0 &&
        ImGui::IsPopupOpen(Detail::popup_id, ImGuiPopupFlags_None)) {
        if (auto* state = ImGui::GetInputTextState(id)) {
            if (GImGui->ActiveId != id) {
                ImGui::SetActiveID(id, ImGui::GetCurrentWindow());
                state->SetSelection(std::clamp(Detail::start, 0, state->TextLen),
                                    std::clamp(Detail::end, 0, state->TextLen));
            }
        }
    }
    if (Detail::restore_id == id) ImGui::SetKeyboardFocusHere();
}
inline void finish(ImGuiInputTextFlags flags, const char* text) {
    using namespace Detail;
    if ((flags & ImGuiInputTextFlags_ReadOnly) || (GImGui->LastItemData.ItemFlags & ImGuiItemFlags_Disabled)) return;
    const ImGuiID id = ImGui::GetItemID();
    // Clipped/omitted widgets can leave a zero LastItem ID. Zero is also our
    // "no pending action" sentinel: never dispatch hooks or open a popup for it.
    if (id == 0) return;
    auto* state = ImGui::GetInputTextState(id);
    const bool restoring_action = restore_id == id;
    if (touch_hold && touch_hold(id, ImRect(ImGui::GetItemRectMin(), ImGui::GetItemRectMax()))) {
        if (refresh_clipboard) refresh_clipboard();
        select_id = id; select_frame = GImGui->FrameCount;
    }
    if (select_id == id && state && GImGui->ActiveId == id && GImGui->FrameCount > select_frame) {
        state->SelectAll(); select_id = 0;
    }
    if (collapse_id == id && state && GImGui->ActiveId == id && GImGui->FrameCount > collapse_frame) {
        state->ClearSelection(); collapse_id = 0;
    }
    if (restore_id == id && state && GImGui->ActiveId == id &&
        GImGui->ActiveIdPreviousFrame == id && GImGui->FrameCount > restore_frame) {
        state->SetSelection(std::clamp(start, 0, state->TextLen), std::clamp(end, 0, state->TextLen));
        if (action != ImGuiKey_None) {
            ImGuiIO& io = ImGui::GetIO();
            const ImGuiKey modifier = io.ConfigMacOSXBehaviors ? ImGuiMod_Super : ImGuiMod_Ctrl;
            io.AddKeyEvent(modifier, true); io.AddKeyEvent(action, true);
            io.AddKeyEvent(action, false); io.AddKeyEvent(modifier, false);
            collapse_id = id; collapse_frame = GImGui->FrameCount;
        }
        restore_id = 0; action = ImGuiKey_None;
    }
    const bool open = (touch_menu && touch_menu(id)) ||
        (ImGui::IsItemHovered() && ImGui::IsMouseReleased(ImGuiMouseButton_Right));
    ImGui::PushID((int)id);
    if (open) {
        if (refresh_clipboard) refresh_clipboard();
        start = state ? state->GetSelectionStart() : 0;
        end = state ? state->GetSelectionEnd() : 0;
        menu_id = id; menu_frame = GImGui->FrameCount;
        popup_id = ImGui::GetID("Text actions");
        ImGui::OpenPopup("Text actions");
    }
    if (menu_id == id) {
        menu_frame = GImGui->FrameCount;
    }
    if (menu_id == id && popup_id != 0 && ImGui::BeginPopup("Text actions", ImGuiWindowFlags_NoFocusOnAppearing)) {
        const bool password = (flags & ImGuiInputTextFlags_Password) != 0;
        const bool selected = start != end;
        ImGuiKey key = ImGuiKey_None;
        const bool all = ImGui::MenuItem("Select all");
        if (ImGui::MenuItem("Cut", nullptr, false, selected && !password)) key = ImGuiKey_X;
        if (ImGui::MenuItem("Copy", nullptr, false, selected && !password)) key = ImGuiKey_C;
        const char* clipboard = ImGui::GetClipboardText();
        if (ImGui::MenuItem("Paste", nullptr, false, clipboard && *clipboard)) key = ImGuiKey_V;
        if (all || key != ImGuiKey_None) {
            if (all) { start = 0; end = (int)strlen(text); }
            restore_id = id; restore_frame = GImGui->FrameCount; action = key;
        }
        ImGui::EndPopup();
    }
    if (menu_id == id && !ImGui::IsPopupOpen("Text actions")) {
        menu_id = popup_id = 0;
        // Dismissing the menu without an action preserves the selection. A tap
        // on another active control must not pull focus back to this editor.
        if (!restoring_action && !restore_id && !collapse_id && (!GImGui->ActiveId || GImGui->ActiveId == id)) {
            restore_id = id; restore_frame = GImGui->FrameCount;
        }
    }
    ImGui::PopID();
}

inline bool InputText(const char* label, char* buf, size_t size, ImGuiInputTextFlags flags = 0) {
    prepare(label);
    bool changed = ImGui::InputText(label, buf, size, flags);
    finish(flags, buf);
    return changed;
}
inline bool InputTextWithHint(const char* label, const char* hint, char* buf, size_t size, ImGuiInputTextFlags flags = 0) {
    prepare(label);
    bool changed = ImGui::InputTextWithHint(label, hint, buf, size, flags);
    finish(flags, buf);
    return changed;
}
inline bool InputTextMultiline(const char* label, char* buf, size_t size, const ImVec2& dimensions = ImVec2(), ImGuiInputTextFlags flags = 0) {
    prepare(label);
    bool changed = ImGui::InputTextMultiline(label, buf, size, dimensions, flags);
    finish(flags, buf);
    return changed;
}
inline bool InputTextMultilineWithHint(const char* label, const char* hint, char* buf, size_t size,
                                       const ImVec2& dimensions, ImGuiInputTextFlags flags = 0) {
    prepare(label);
    const bool changed = ImGui::InputTextMultiline(label, buf, size, dimensions, flags);
    if (!buf[0] && !ImGui::IsItemActive() && ImGui::IsItemVisible()) {
        const auto& children = ImGui::GetCurrentWindow()->DC.ChildWindows;
        ImGuiWindow* child = children.empty() ? nullptr : children.back();
        if (child && child->ChildId == ImGui::GetItemID()) {
            const ImVec2 padding = ImGui::GetStyle().FramePadding;
            const ImVec2 start(child->InnerRect.Min.x + padding.x, child->InnerRect.Min.y + padding.y);
            const ImVec2 end(child->InnerRect.Max.x - padding.x, child->InnerRect.Max.y - padding.y);
            if (end.x > start.x && end.y > start.y) {
                ImDrawList* draw = child->DrawList;
                draw->PushClipRect(start, end, true);
                draw->AddText(ImGui::GetFont(), ImGui::GetFontSize() * 0.85f, start,
                              ImGui::GetColorU32(ImGuiCol_TextDisabled), hint, nullptr, end.x - start.x);
                draw->PopClipRect();
            }
        }
    }
    finish(flags, buf);
    return changed;
}

}

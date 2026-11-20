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
    if (Detail::restore_id == ImGui::GetID(label)) ImGui::SetKeyboardFocusHere();
}
// InputText doesn't draw its selection while a popup owns focus. Draw the saved
// range using the widget's own visual-line index (UTF-8 byte offsets), including
// wrapping and child scrolling. No text bytes or wrap points are modified.
inline void draw_menu_selection(ImGuiID id, const char* text, int start, int end) {
    if (start == end) return;
    const int length = (int)strlen(text);
    start = std::clamp(start, 0, length); end = std::clamp(end, 0, length);
    if (start > end) std::swap(start, end);
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    const auto& children = window->DC.ChildWindows;
    ImGuiWindow* child = !children.empty() && children.back()->ChildId == id ? children.back() : nullptr;
    const auto& lines = GImGui->InputTextLineIndex.Offsets;
    const int count = child ? std::max(1, lines.Size) : 1;
    auto line_start = [&](int n) { return child && !lines.empty() ? std::clamp(lines[n], 0, length) : 0; };
    ImVec2 origin = ImGui::GetItemRectMin();
    if (child) origin = child->DC.CursorStartPos;
    else { origin.x += ImGui::GetStyle().FramePadding.x; origin.y += ImGui::GetStyle().FramePadding.y; }
    if (auto* state = ImGui::GetInputTextState(id)) origin.x -= state->Scroll.x;
    ImDrawList* draw = child ? child->DrawList : window->DrawList;
    const ImRect clip = child ? child->InnerClipRect : ImRect(ImGui::GetItemRectMin(), ImGui::GetItemRectMax());
    draw->PushClipRect(clip.Min, clip.Max, true);
    const float height = ImGui::GetFontSize();
    auto width = [&](int a, int b) {
        return ImFontCalcTextSizeEx(ImGui::GetFont(), height, FLT_MAX, 0,
            text + a, text + b, text + b, nullptr, nullptr, ImDrawTextFlags_WrapKeepBlanks).x;
    };
    ImVec4 color = ImGui::GetStyleColorVec4(ImGuiCol_TextSelectedBg);
    color.w = std::min(color.w, 0.35f); // Overlay, not an opaque cover over glyphs.
    const int first = std::clamp((int)((clip.Min.y - origin.y) / height), 0, count - 1);
    for (int n = first; n < count; ++n) {
        const float y = origin.y + n * height;
        if (y + height < clip.Min.y) continue;
        if (y > clip.Max.y) break;
        const int begin = line_start(n), finish = n + 1 < count ? line_start(n + 1) : length;
        const int a = std::max(start, begin), b = std::min(end, finish);
        if (a >= b) continue;
        int visible_end = b;
        if (visible_end > a && text[visible_end - 1] == '\n') --visible_end;
        const float x = origin.x + width(begin, a);
        const float right = origin.x + width(begin, visible_end);
        draw->AddRectFilled(ImVec2(x, y), ImVec2(std::max(x + 2.0f, right), y + height), ImGui::GetColorU32(color));
    }
    draw->PopClipRect();
}
inline void finish(ImGuiInputTextFlags flags, const char* text) {
    using namespace Detail;
    if ((flags & ImGuiInputTextFlags_ReadOnly) || (GImGui->LastItemData.ItemFlags & ImGuiItemFlags_Disabled)) return;
    const ImGuiID id = ImGui::GetItemID();
    auto* state = ImGui::GetInputTextState(id);
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
        if (GImGui->ActiveId != id && !(flags & ImGuiInputTextFlags_Password)) draw_menu_selection(id, text, start, end);
    }
    if (ImGui::BeginPopup("Text actions")) {
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
        if (!restore_id && (!GImGui->ActiveId || GImGui->ActiveId == id)) {
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

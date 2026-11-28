#pragma once
#include "imgui.h"
#include "imgui_internal.h"
#include <cstdarg>
#include <algorithm>
#include <cstring>
#include <string>

namespace UiText {
// Tooltips must be bounded by the actual viewport, not an unwrapped URL or
// desktop-sized text estimate. Long words/URLs are broken by ImGui itself.
inline void TooltipV(const char* format, va_list args) {
    const float viewport_width = ImGui::GetWindowViewport()->WorkSize.x;
    const auto& style = ImGui::GetStyle();
    const float outer_width = std::max(1.0f, viewport_width - 16.0f);
    const float wrap_width = std::max(1.0f, std::min(ImGui::GetFontSize() * 35.0f,
        outer_width - style.WindowPadding.x * 2.0f - style.WindowBorderSize * 2.0f));
    ImGui::SetNextWindowSizeConstraints(ImVec2(0, 0), ImVec2(outer_width, FLT_MAX));
    if (ImGui::BeginTooltip()) {
        ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + wrap_width);
        ImGui::TextV(format, args);
        ImGui::PopTextWrapPos();
        ImGui::EndTooltip();
    }
}
inline void Tooltip(const char* format, ...) {
    va_list args; va_start(args, format); TooltipV(format, args); va_end(args);
}
inline void ItemTooltip(const char* format, ...) {
    if (!ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip)) return;
    va_list args; va_start(args, format); TooltipV(format, args); va_end(args);
}
// Keep native, keyboard-accessible TextLink items on each visual line rather
// than shrinking long URLs to unreadable text. The original URL is untouched.
inline bool TextLinkWrapped(const char* text, bool* hovered = nullptr) {
    const float width = std::max(1.0f, ImGui::GetContentRegionAvail().x);
    const char* end = text + std::strlen(text);
    bool pressed = false, any_hovered = false;
    ImGui::PushID(text);
    ImGui::BeginGroup();
    int line = 0;
    for (const char* begin = text; begin < end;) {
        const char* next = ImGui::GetFont()->CalcWordWrapPosition(ImGui::GetFontSize(), begin, end, width);
        if (next <= begin) {
            unsigned int character;
            next = begin + std::max(1, ImTextCharFromUtf8(&character, begin, end));
        }
        ImGui::PushID(line++);
        const std::string label(begin, next);
        pressed |= ImGui::TextLink(label.c_str());
        any_hovered |= ImGui::IsItemHovered();
        ImGui::PopID();
        begin = next;
        while (begin < end && (*begin == ' ' || *begin == '\n' || *begin == '\r')) ++begin;
    }
    ImGui::EndGroup();
    ImGui::PopID();
    if (hovered) *hovered = any_hovered;
    return pressed;
}
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
// Set by a host that cannot read its clipboard inside GetClipboardText() and
// keeps a copy instead (Android): asks it to read the clipboard again. The
// answer arrives on a later frame, and the host counts it in
// clipboard_revision. A host that leaves this unset reads the clipboard
// whenever it is asked for.
inline void (*refresh_clipboard)() = nullptr;
inline unsigned clipboard_revision = 0;
namespace Detail {
inline ImGuiContext* context = nullptr;
inline ImGuiID select_id = 0, menu_id = 0, popup_id = 0, restore_id = 0, collapse_id = 0;
inline int select_frame = 0, menu_frame = 0, restore_frame = 0, collapse_frame = 0;
inline int start = 0, end = 0;
inline ImGuiKey action = ImGuiKey_None;
inline ImGuiID editor_id = 0;
inline ImRect editor_rect;
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
    Detail::editor_id = 0;
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
// A tap on a text field this frame, whether it starts the editing or the field
// was being edited already. Read once the frame is submitted. A host with an
// on-screen keyboard asks for it again on this: the user can put the keyboard
// away (Back, its own hide key) while the field keeps the focus, and then a
// tap on that field changes nothing else the host could go by. A tap anywhere
// else is not one: the field that had the focus is no longer the active item.
inline bool editor_tapped() {
    const ImGuiContext* g = GImGui;
    return g && g->IO.MouseClicked[ImGuiMouseButton_Left] && g->ActiveId != 0 &&
        g->HoveredId == g->ActiveId && g->InputTextState.ID == g->ActiveId;
}
// Touch adapters call this on the physical Down, before deciding whether a
// completed gesture becomes a click. Otherwise the popup blocks hover capture
// and the adapter may suppress the very tap that should dismiss the menu.
inline void pointer_down(ImVec2 position) {
    using namespace Detail;
    if (!GImGui || context != GImGui) return;
    if (menu_id && popup_id) {
        for (const auto& popup : GImGui->OpenPopupStack)
            if (popup.PopupId == popup_id && popup.Window && popup.Window->Rect().Contains(position))
                return; // Actual menu actions keep their real selection.
    }
    const ImGuiID owner = editor_id ? editor_id : menu_id;
    const bool outside_editor = owner && (editor_id != owner || !editor_rect.Contains(position));
    if (!menu_id && !outside_editor) return;
    close_menu();
    menu_id = select_id = restore_id = collapse_id = 0;
    action = ImGuiKey_None;
    if (outside_editor) {
        // Clear the real InputText range, not merely its painted highlight.
        // Leave another control's active ID alone so its tap can complete.
        if (auto* state = ImGui::GetInputTextState(owner)) state->ClearSelection();
        if (GImGui->ActiveId == owner) ImGui::ClearActiveID();
        editor_id = 0;
        start = end = 0;
    }
}
inline void prepare(const char* label) {
    wants_keyboard(); // Also expires a pending restore if the field disappeared.
    if (ImGui::IsMouseClicked(ImGuiMouseButton_Left)) pointer_down(ImGui::GetIO().MousePos);
    const ImGuiID id = ImGui::GetID(label);
    // A text-actions popup must not turn the editor's selection into a visual
    // imitation. Keep the real InputText state active so ImGui renders and
    // operates on its own selected range (including wrapped/multiline text).
    if (id != 0 && Detail::menu_id == id && Detail::popup_id != 0 &&
        ImGui::IsPopupOpen(Detail::popup_id, ImGuiPopupFlags_None)) {
        if (auto* state = ImGui::GetInputTextState(id)) {
            if (GImGui->ActiveId == 0) {
                ImGui::SetActiveID(id, ImGui::GetCurrentWindow());
                state->SetSelection(std::clamp(Detail::start, 0, state->TextLen),
                                    std::clamp(Detail::end, 0, state->TextLen));
            }
        }
    }
    if (Detail::restore_id == id) {
        if (GImGui->ActiveId && GImGui->ActiveId != id) {
            // A button/another field owns an in-progress gesture. Never steal
            // it between press and release just to restore a text selection.
            Detail::restore_id = Detail::collapse_id = 0;
            Detail::action = ImGuiKey_None;
        } else ImGui::SetKeyboardFocusHere();
    }
}
inline void finish(ImGuiInputTextFlags flags, const char* text) {
    using namespace Detail;
    if ((flags & ImGuiInputTextFlags_ReadOnly) || (GImGui->LastItemData.ItemFlags & ImGuiItemFlags_Disabled)) return;
    const ImGuiID id = ImGui::GetItemID();
    // Clipped/omitted widgets can leave a zero LastItem ID. Zero is also our
    // "no pending action" sentinel: never dispatch hooks or open a popup for it.
    if (id == 0) return;
    auto* state = ImGui::GetInputTextState(id);
    if (state && (GImGui->ActiveId == id || menu_id == id)) {
        editor_id = id;
        editor_rect = ImRect(ImGui::GetItemRectMin(), ImGui::GetItemRectMax());
        editor_rect.ClipWith(ImGui::GetCurrentWindow()->ClipRect);
    }
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
        // The editor stays active for its native selection, but must not
        // block hover/press ownership of the popup's real MenuItem widgets.
        if (GImGui->ActiveId == id) GImGui->ActiveIdAllowOverlap = true;
    }
    if (menu_id == id && popup_id != 0 && ImGui::BeginPopup("Text actions", ImGuiWindowFlags_NoFocusOnAppearing)) {
        // NoFocusOnAppearing preserves native editor selection, but must not
        // leave this popup behind a multiline editor's child window.
        ImGui::BringWindowToDisplayFront(ImGui::GetCurrentWindow());
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

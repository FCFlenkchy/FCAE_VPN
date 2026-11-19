#pragma once
#include "imgui.h"
#include "imgui_internal.h"

namespace UiText {
#if defined(ANDROID)
void prepare(const char* label);
void finish(ImGuiInputTextFlags flags);
inline bool InputText(const char* label, char* buf, size_t size, ImGuiInputTextFlags flags = 0) {
    prepare(label);
    bool changed = ImGui::InputText(label, buf, size, flags);
    finish(flags);
    return changed;
}
inline bool InputTextWithHint(const char* label, const char* hint, char* buf, size_t size, ImGuiInputTextFlags flags = 0) {
    prepare(label);
    bool changed = ImGui::InputTextWithHint(label, hint, buf, size, flags);
    finish(flags);
    return changed;
}
inline bool InputTextMultiline(const char* label, char* buf, size_t size, const ImVec2& dimensions = ImVec2(), ImGuiInputTextFlags flags = 0) {
    prepare(label);
    bool changed = ImGui::InputTextMultiline(label, buf, size, dimensions, flags);
    finish(flags);
    return changed;
}
#else
using ImGui::InputText;
using ImGui::InputTextWithHint;
using ImGui::InputTextMultiline;
#endif
inline bool InputTextMultilineWithHint(const char* label, const char* hint, char* buf, size_t size,
                                       const ImVec2& dimensions, ImGuiInputTextFlags flags = 0) {
#if defined(ANDROID)
    prepare(label);
#endif
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
#if defined(ANDROID)
    finish(flags);
#endif
    return changed;
}

}

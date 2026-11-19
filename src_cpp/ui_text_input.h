#pragma once
#include "imgui.h"

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
}

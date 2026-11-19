#pragma once

#include "imgui_internal.h"
#include <algorithm>
#include <cmath>

class ImGuiHorizontalDrag {
public:
    // Run after widgets so controls, scrollbars and selectable text get first refusal.
    bool update() {
        ImGuiContext& g = *GImGui;
        const ImGuiIO& io = g.IO;
        if (io.AppFocusLost || io.MouseSource != ImGuiMouseSource_Mouse ||
                !ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
            window_id_ = 0;
            dragging_ = false;
            return false;
        }
        if (ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
            window_id_ = 0;
            dragging_ = false;
            ImGuiWindow* window = g.HoveredWindow;
            if (!window || g.HoveredId || g.HoveredIdIsDisabled || g.ActiveIdDisabledId ||
                    (g.ActiveId && g.ActiveId != window->MoveId) ||
                    !(window->RootWindow->Flags & ImGuiWindowFlags_NoMove) ||
                    !window->InnerRect.Contains(io.MousePos)) return false;
            ImGuiWindow* modal = ImGui::GetTopMostPopupModal();
            if (modal && !ImGui::IsWindowWithinBeginStackOf(window, modal)) return false;
            for (; window; window = window->ParentWindow) {
                if (!(window->Flags & (ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoMouseInputs)) &&
                        window->ScrollMax.x > 0.0f) {
                    window_id_ = window->ID;
                    origin_ = previous_ = io.MousePos;
                    break;
                }
                if (!(window->Flags & ImGuiWindowFlags_ChildWindow)) break;
            }
        }
        if (!window_id_) return false;
        ImGuiWindow* window = ImGui::FindWindowByID(window_id_);
        ImGuiWindow* modal = ImGui::GetTopMostPopupModal();
        if (!window || !window->Active || (modal && !ImGui::IsWindowWithinBeginStackOf(window, modal)) ||
                (g.ActiveId && (!g.ActiveIdWindow || g.ActiveId != g.ActiveIdWindow->MoveId))) {
            window_id_ = 0;
            return false;
        }
        const float dx = io.MousePos.x - origin_.x;
        const float dy = io.MousePos.y - origin_.y;
        if (!dragging_) {
            if (std::max(std::abs(dx), std::abs(dy)) < io.MouseDragThreshold) return false;
            if (std::abs(dx) <= std::abs(dy)) {
                window_id_ = 0;
                return false;
            }
            dragging_ = true;
            ImGui::ClearActiveID();
        }
        const float current = window->ScrollTarget.x != FLT_MAX ? window->ScrollTarget.x : window->Scroll.x;
        const float next = std::clamp(current - (io.MousePos.x - previous_.x), 0.0f, window->ScrollMax.x);
        ImGui::SetScrollX(window, next);
        previous_ = io.MousePos;
        return current != next;
    }

private:
    ImGuiID window_id_ = 0;
    ImVec2 origin_{};
    ImVec2 previous_{};
    bool dragging_ = false;
};

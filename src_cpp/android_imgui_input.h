#pragma once

#include "imgui.h"
#include "imgui_internal.h"
#include <algorithm>
#include <cmath>
#include <deque>

// Owned exclusively by the GL thread. Keep taps as separate press/release
// frames, but collapse motion samples so input never builds a render backlog.
class AndroidImGuiInput {
public:
    enum Action { Down = 0, Up = 1, Move = 2, Cancel = 3 };

    void set_touch_slop(float value) { slop_ = std::max(1.0f, value); }

    void pointer(float x, float y, int action, double time, bool touch) {
        if (!touch || action == Down || action == Cancel) velocity_ = 0.0f;
        Event event{ImVec2(x, y), action, time, touch};
        if (action == Move && !events_.empty() && events_.back().action == Move && events_.back().touch == touch)
            events_.back() = event;
        else
            events_.push_back(event);
        if (events_.size() > 256) {
            reset();
        }
    }

    void reset() {
        events_.clear();
        if (down_ || scrolling_) {
            cancel_press();
        }
        down_ = scrolling_ = false;
        window_ = nullptr;
        tab_bar_ = 0;
        velocity_ = 0.0f;
    }

    void new_frame(float dt) {
        if (!down_ && std::abs(velocity_) > 1.0f && (window_ || tab_bar_)) {
            if (!scroll(velocity_ * dt)) velocity_ = 0.0f;
            velocity_ *= std::exp(-7.5f * dt);
            if (std::abs(velocity_) < 12.0f) velocity_ = 0.0f;
        }
        bool transitioned = false;
        while (!events_.empty()) {
            const Event event = events_.front();
            if (event.action != Move && transitioned) break;
            events_.pop_front();
            if (event.action != Move) transitioned = true;
            handle(event);
        }
    }

    bool active() const {
        return down_ || !events_.empty() || std::abs(velocity_) > 1.0f;
    }

private:
    struct Event { ImVec2 pos; int action; double time; bool touch; };
    std::deque<Event> events_;
    ImGuiWindow* window_ = nullptr;
    ImGuiID tab_bar_ = 0;
    ImGuiAxis axis_ = ImGuiAxis_Y;
    ImVec2 origin_{};
    ImVec2 previous_{};
    float slop_ = 8.0f;
    float velocity_ = 0.0f;
    double previous_time_ = 0.0;
    bool down_ = false;
    bool scrolling_ = false;

    static ImGuiWindow* scroll_window(const ImVec2& position, ImGuiAxis axis) {
        ImGuiWindow* hovered = nullptr;
        ImGuiWindow* ignored = nullptr;
        ImGui::FindHoveredWindowEx(position, false, &hovered, &ignored);
        ImGuiWindow* modal = ImGui::GetTopMostPopupModal();
        if (modal && hovered && !ImGui::IsWindowWithinBeginStackOf(hovered, modal)) return nullptr;
        for (ImGuiWindow* window = hovered; window; window = window->ParentWindow) {
            if (!(window->Flags & (ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoMouseInputs)) && window->ScrollMax[axis] > 0)
                return window;
            if (!(window->Flags & ImGuiWindowFlags_ChildWindow)) break;
        }
        return nullptr;
    }

    static void cancel_press() {
        ImGui::ClearActiveID();
        // A complete flick may arrive between two frames. Remove its queued
        // press as well as the already-active ID, or trickling can resurrect
        // that press after scrolling has started and click on release.
        auto& queue = GImGui->InputEventsQueue;
        for (int i = queue.Size - 1; i >= 0; --i)
            if (queue[i].Type == ImGuiInputEventType_MouseButton && queue[i].MouseButton.Button == 0)
                queue.erase(queue.Data + i);
        ImGui::GetIO().ClearInputMouse();
    }

    bool scroll(float delta) {
        if (tab_bar_ && axis_ == ImGuiAxis_X) {
            ImGuiTabBar* bar = GImGui->TabBars.GetByKey(tab_bar_);
            if (!bar || bar->CurrFrameVisible < GImGui->FrameCount - 1) return false;
            ImGuiWindow* modal = ImGui::GetTopMostPopupModal();
            if (modal && !ImGui::IsWindowWithinBeginStackOf(bar->Window, modal)) return false;
            const float current = bar->ScrollingTarget;
            const float next = std::clamp(current - delta, 0.0f,
                std::max(0.0f, bar->WidthAllTabs - bar->BarRect.GetWidth()));
            bar->ScrollingTarget = bar->ScrollingAnim = next;
            bar->ScrollingTargetDistToVisibility = 0.0f;
            return next != current;
        }
        if (!window_ || !window_->WasActive) return false;
        ImGuiWindow* modal = ImGui::GetTopMostPopupModal();
        if (modal && !ImGui::IsWindowWithinBeginStackOf(window_, modal)) return false;
        const float current = window_->ScrollTarget[axis_] != FLT_MAX ? window_->ScrollTarget[axis_] : window_->Scroll[axis_];
        const float next = std::clamp(current - delta, 0.0f, window_->ScrollMax[axis_]);
        if (axis_ == ImGuiAxis_X) ImGui::SetScrollX(window_, next);
        else ImGui::SetScrollY(window_, next);
        return next != current;
    }

    void handle(const Event& event) {
        ImGuiIO& io = ImGui::GetIO();
        io.AddMouseSourceEvent(event.touch ? ImGuiMouseSource_TouchScreen : ImGuiMouseSource_Mouse);
        io.AddMousePosEvent(event.pos.x, event.pos.y);
        if (!event.touch) {
            velocity_ = 0.0f;
            if (event.action == Down) io.AddMouseButtonEvent(0, true);
            if (event.action == Up || event.action == Cancel) io.AddMouseButtonEvent(0, false);
            return;
        }
        if (event.action == Down) {
            velocity_ = 0.0f;
            origin_ = previous_ = event.pos;
            previous_time_ = event.time;
            window_ = nullptr;
            tab_bar_ = 0;
            ImGuiWindow* hovered = nullptr;
            ImGuiWindow* ignored = nullptr;
            ImGui::FindHoveredWindowEx(event.pos, false, &hovered, &ignored);
            for (int i = 0; i < GImGui->TabBars.GetMapSize(); ++i) {
                ImGuiTabBar* bar = GImGui->TabBars.TryGetMapData(i);
                if (bar && bar->Window == hovered && bar->CurrFrameVisible >= GImGui->FrameCount - 1
                        && (bar->Flags & ImGuiTabBarFlags_FittingPolicyScroll)
                        && bar->WidthAllTabs > bar->BarRect.GetWidth() && bar->BarRect.Contains(event.pos)) {
                    tab_bar_ = bar->ID;
                    break;
                }
            }
            down_ = true;
            scrolling_ = false;
            io.AddMouseButtonEvent(0, true);
            return;
        }
        if (event.action == Cancel) {
            cancel_press();
            down_ = scrolling_ = false;
            window_ = nullptr;
            tab_bar_ = 0;
            velocity_ = 0.0f;
            return;
        }
        if (!down_) return;
        if (event.action == Move || event.action == Up) {
            const float dx = event.pos.x - origin_.x;
            const float dy = event.pos.y - origin_.y;
            const ImGuiAxis direction = std::abs(dx) > std::abs(dy) ? ImGuiAxis_X : ImGuiAxis_Y;
            const bool scrollbar = GImGui->ActiveIdWindow &&
                (GImGui->ActiveId == ImGui::GetWindowScrollbarID(GImGui->ActiveIdWindow, ImGuiAxis_X) ||
                 GImGui->ActiveId == ImGui::GetWindowScrollbarID(GImGui->ActiveIdWindow, ImGuiAxis_Y));
            const bool horizontal_control = direction == ImGuiAxis_X && GImGui->ActiveId &&
                (!GImGui->ActiveIdWindow || GImGui->ActiveId != GImGui->ActiveIdWindow->MoveId) &&
                (GImGui->ActiveIdUsingNavDirMask & ((1 << ImGuiDir_Left) | (1 << ImGuiDir_Right)));
            if (!scrolling_ && !scrollbar && !horizontal_control && std::max(std::abs(dx), std::abs(dy)) > slop_) {
                axis_ = direction;
                window_ = scroll_window(origin_, axis_);
                if (window_ || (axis_ == ImGuiAxis_X && tab_bar_)) {
                    scrolling_ = true;
                    velocity_ = 0.0f;
                    cancel_press();
                    scroll(axis_ == ImGuiAxis_X ? dx : dy);
                }
            } else if (scrolling_) {
                scroll(event.pos[axis_] - previous_[axis_]);
            }
            const double elapsed = event.time - previous_time_;
            if (scrolling_ && event.action == Move && elapsed > 0.0 && elapsed < 0.15) {
                const float speed = std::clamp(static_cast<float>((event.pos[axis_] - previous_[axis_]) / elapsed), -6000.0f, 6000.0f);
                velocity_ = velocity_ * 0.35f + speed * 0.65f;
            }
            if (event.action == Up) {
                if (!scrolling_ || elapsed > 0.1) velocity_ = 0.0f;
                down_ = scrolling_ = false;
                io.AddMouseButtonEvent(0, false);
            }
            previous_ = event.pos;
            previous_time_ = event.time;
        }
    }
};

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
        velocity_ = 0.0f;
    }

    void new_frame(float dt) {
        if (!down_ && std::abs(velocity_) > 1.0f && window_) {
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
    ImVec2 origin_{};
    ImVec2 previous_{};
    float slop_ = 8.0f;
    float velocity_ = 0.0f;
    double previous_time_ = 0.0;
    bool down_ = false;
    bool scrolling_ = false;

    static ImGuiWindow* scroll_window(const ImVec2& position) {
        ImGuiWindow* hovered = nullptr;
        ImGuiWindow* ignored = nullptr;
        ImGui::FindHoveredWindowEx(position, false, &hovered, &ignored);
        ImGuiWindow* modal = ImGui::GetTopMostPopupModal();
        if (modal && hovered && !ImGui::IsWindowWithinBeginStackOf(hovered, modal)) return nullptr;
        for (ImGuiWindow* window = hovered; window; window = window->ParentWindow) {
            if (!(window->Flags & (ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoMouseInputs)) && window->ScrollMax.y > 0)
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
        if (!window_ || !window_->WasActive) return false;
        ImGuiWindow* modal = ImGui::GetTopMostPopupModal();
        if (modal && !ImGui::IsWindowWithinBeginStackOf(window_, modal)) return false;
        const float current = window_->ScrollTarget.y != FLT_MAX ? window_->ScrollTarget.y : window_->Scroll.y;
        const float next = std::clamp(current - delta, 0.0f, window_->ScrollMax.y);
        ImGui::SetScrollY(window_, next);
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
            window_ = scroll_window(event.pos);
            down_ = true;
            scrolling_ = false;
            io.AddMouseButtonEvent(0, true);
            return;
        }
        if (event.action == Cancel) {
            cancel_press();
            down_ = scrolling_ = false;
            window_ = nullptr;
            velocity_ = 0.0f;
            return;
        }
        if (!down_) return;
        if (event.action == Move || event.action == Up) {
            const float dx = event.pos.x - origin_.x;
            const float dy = event.pos.y - origin_.y;
            const bool scrollbar = GImGui->ActiveIdWindow &&
                GImGui->ActiveId == ImGui::GetWindowScrollbarID(GImGui->ActiveIdWindow, ImGuiAxis_Y);
            // Horizontal sliders and sponsor swipes retain horizontal drags;
            // vertical motion scrolls even if a button initially took ActiveId.
            if (!scrolling_ && !scrollbar && window_ && std::abs(dy) > slop_ && std::abs(dy) > std::abs(dx)) {
                scrolling_ = true;
                cancel_press();
                scroll(dy);
            } else if (scrolling_) {
                scroll(event.pos.y - previous_.y);
            }
            const double elapsed = event.time - previous_time_;
            if (event.action == Move && elapsed > 0.0 && elapsed < 0.15) {
                const float speed = std::clamp(static_cast<float>((event.pos.y - previous_.y) / elapsed), -6000.0f, 6000.0f);
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

#pragma once

#include "imgui.h"
#include "imgui_internal.h"
#include "ui_text_input.h"
#include <algorithm>
#include <cmath>
#include <deque>
#include <vector>

// GL-thread owned. Ordinary touches become clicks only after a completed tap.
class AndroidImGuiInput {
public:
    enum Action { Down = 0, Up = 1, Move = 2, Cancel = 3 };

    void set_touch_slop(float value) { slop_ = std::max(1.0f, value); }

    void horizontal_drag_item() {
        ImGuiWindow* window = ImGui::GetCurrentWindow();
        if (window->SkipItems || (GImGui->LastItemData.ItemFlags & ImGuiItemFlags_Disabled)) return;
        ImRect rect = GImGui->LastItemData.NavRect;
        rect.ClipWith(window->ClipRect);
        if (!rect.IsInverted()) drag_items_.push_back({window->ID, rect, GImGui->FrameCount});
    }

    bool text_hold(ImGuiID id, const ImRect& rect) {
        if (id != 0 && down_ && !forwarding_ && !scrolling_ && !suppress_tap_ &&
            held_ >= 0.5f && rect.Contains(origin_) && tap_id_ == id) {
            press();
            text_selection_ = id;
            return true;
        }
        return false;
    }

    bool text_menu(ImGuiID id) {
        // Zero means no pending long-press, never a field to open a menu for.
        if (id == 0 || text_selection_ == 0 || text_selection_ != id || down_) return false;
        text_selection_ = 0;
        return true;
    }

    bool scrolling_window(ImGuiID id) const {
        return (down_ && touch_window_ == id) ||
            (window_id_ == id && (scrolling_ || std::abs(velocity_) > 1.0f));
    }

    void pointer(float x, float y, int action, double time, bool touch) {
        const bool stopped_fling = touch && action == Down && std::abs(velocity_) > 1.0f;
        const ImVec2 pos(x, y);
        if (!touch || action == Down || action == Cancel) {
            velocity_ = 0.0f;
            raw_origin_ = raw_previous_ = pos;
            raw_intent_ = raw_velocity_ = ImVec2();
            raw_time_ = time;
        } else {
            const ImVec2 delta(pos.x - raw_origin_.x, pos.y - raw_origin_.y);
            if (raw_intent_.x == 0.0f && raw_intent_.y == 0.0f &&
                    std::max(std::abs(delta.x), std::abs(delta.y)) > slop_)
                raw_intent_ = delta;
            const double elapsed = time - raw_time_;
            if (elapsed > 0.0) {
                if (elapsed >= 0.15) raw_velocity_ = ImVec2();
                else if (action == Move || pos.x != raw_previous_.x || pos.y != raw_previous_.y) {
                    const float blend = 1.0f - std::exp(-static_cast<float>(elapsed) / 0.04f);
                    for (int axis = 0; axis < 2; ++axis) {
                        const float speed = std::clamp(static_cast<float>((pos[axis] - raw_previous_[axis]) / elapsed), -6000.0f, 6000.0f);
                        raw_velocity_[axis] += (speed - raw_velocity_[axis]) * blend;
                    }
                } else if (elapsed > 0.04) raw_velocity_ = ImVec2();
            }
            raw_previous_ = pos;
            raw_time_ = time;
        }
        Event event{pos, action, touch, raw_intent_, raw_velocity_, stopped_fling};
        if (action == Move && !events_.empty() && events_.back().action == Move && events_.back().touch == touch)
            events_.back() = event;
        else events_.push_back(event);
        if (events_.size() > 256) reset();
    }

    void reset() {
        events_.clear();
        text_selection_ = 0;
        if (GImGui) cancel_press();
        down_ = scrolling_ = forwarding_ = horizontal_owner_ = false;
        window_id_ = tab_bar_ = touch_window_ = 0;
        velocity_ = 0.0f;
        suppress_tap_ = false;
        keyboard_gesture_ = false;
        drag_items_.clear();
    }

    void new_frame(float dt) {
        if (down_) held_ += dt;
        if (down_ && !forwarding_ && !scrolling_) {
            if (GImGui->FrameCount == capture_frame_) tap_id_ = GImGui->HoveredId;
            else if (GImGui->FrameCount > capture_frame_ && GImGui->HoveredId != tap_id_)
                suppress_tap_ = true;
        }
        drag_items_.erase(std::remove_if(drag_items_.begin(), drag_items_.end(), [](const DragItem& item) {
            return item.frame < GImGui->FrameCount;
        }), drag_items_.end());
        const bool was_down = down_;
        bool transitioned = false;
        while (!events_.empty()) {
            if (forwarding_ && press_frame_ == GImGui->FrameCount) break;
            const Event event = events_.front();
            if (event.action != Move && transitioned) break;
            events_.pop_front();
            if (event.action != Move) transitioned = true;
            handle(event);
        }
        if (!was_down && !down_ && std::abs(velocity_) > 1.0f) {
            const float elapsed = std::clamp(dt, 0.0f, 0.05f);
            const float decay = std::exp(-7.5f * elapsed);
            if (!scroll(velocity_ * (1.0f - decay) / 7.5f)) velocity_ = 0.0f;
            velocity_ *= decay;
            if (std::abs(velocity_) < 12.0f) velocity_ = 0.0f;
        }
    }

    // Blurring InputText on physical Down must not resize the viewport before
    // this adapter delivers its deferred press/release to the tapped button.
    // Shared by Android and iOS; do not reopen an IME for ordinary touches.
    bool keep_keyboard_open() const { return keyboard_gesture_ && (down_ || forwarding_ || !events_.empty()); }

    bool active() const {
        return down_ || !events_.empty() || std::abs(velocity_) > 1.0f;
    }

private:
    struct Event { ImVec2 pos; int action; bool touch; ImVec2 intent; ImVec2 velocity; bool stopped_fling; };
    struct DragItem { ImGuiID window; ImRect rect; int frame; };
    std::deque<Event> events_;
    std::vector<DragItem> drag_items_;
    ImGuiID window_id_ = 0, tab_bar_ = 0, touch_window_ = 0, tap_id_ = 0;
    ImGuiAxis axis_ = ImGuiAxis_Y;
    ImVec2 origin_{}, previous_{};
    ImVec2 raw_origin_{}, raw_previous_{}, raw_intent_{}, raw_velocity_{};
    double raw_time_ = 0.0;
    ImGuiID text_selection_ = 0;
    float held_ = 0.0f;
    float slop_ = 8.0f, velocity_ = 0.0f, scroll_position_ = 0.0f;
    int press_frame_ = -1, capture_frame_ = -1;
    bool down_ = false, scrolling_ = false, forwarding_ = false;
    bool horizontal_owner_ = false, suppress_tap_ = false;
    bool keyboard_gesture_ = false;

    static ImGuiWindow* hovered_window(const ImVec2& position) {
        ImGuiWindow* hovered = nullptr;
        ImGuiWindow* ignored = nullptr;
        ImGui::FindHoveredWindowEx(position, false, &hovered, &ignored);
        ImGuiWindow* modal = ImGui::GetTopMostPopupModal();
        if (modal && hovered && !ImGui::IsWindowWithinBeginStackOf(hovered, modal)) return nullptr;
        return hovered;
    }

    static ImGuiWindow* scroll_window(ImGuiWindow* window, ImGuiAxis axis) {
        for (; window; window = window->ParentWindow) {
            if (!(window->Flags & (ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoMouseInputs)) && window->ScrollMax[axis] > 0)
                return window;
            if (!(window->Flags & ImGuiWindowFlags_ChildWindow)) break;
        }
        return nullptr;
    }

    static void cancel_press() {
        ImGui::ClearActiveID();
        auto& queue = GImGui->InputEventsQueue;
        for (int i = queue.Size - 1; i >= 0; --i)
            if (queue[i].Type == ImGuiInputEventType_MouseButton && queue[i].MouseButton.Button == 0)
                queue.erase(queue.Data + i);
        ImGui::GetIO().ClearInputMouse();
    }

    void press() {
        ImGuiIO& io = ImGui::GetIO();
        io.AddMousePosEvent(origin_.x, origin_.y);
        io.AddMouseButtonEvent(0, true);
        forwarding_ = true;
        press_frame_ = GImGui->FrameCount;
    }

    bool valid_touch_window() const {
        ImGuiWindow* window = ImGui::FindWindowByID(touch_window_);
        ImGuiWindow* modal = ImGui::GetTopMostPopupModal();
        return window && window->WasActive && (!modal || ImGui::IsWindowWithinBeginStackOf(window, modal));
    }

    bool scroll(float delta) {
        if (tab_bar_ && axis_ == ImGuiAxis_X) {
            ImGuiTabBar* bar = GImGui->TabBars.GetByKey(tab_bar_);
            if (!bar || bar->CurrFrameVisible < GImGui->FrameCount - 1) return false;
            ImGuiWindow* modal = ImGui::GetTopMostPopupModal();
            if (modal && !ImGui::IsWindowWithinBeginStackOf(bar->Window, modal)) return false;
            const float next = std::clamp(scroll_position_ - delta, 0.0f,
                std::max(0.0f, bar->WidthAllTabs - bar->BarRect.GetWidth()));
            const bool changed = next != scroll_position_;
            scroll_position_ = bar->ScrollingTarget = bar->ScrollingAnim = next;
            bar->ScrollingTargetDistToVisibility = 0.0f;
            return changed;
        }
        ImGuiWindow* window = ImGui::FindWindowByID(window_id_);
        if (!window || !window->WasActive) return false;
        ImGuiWindow* modal = ImGui::GetTopMostPopupModal();
        if (modal && !ImGui::IsWindowWithinBeginStackOf(window, modal)) return false;
        const float next = std::clamp(scroll_position_ - delta, 0.0f, window->ScrollMax[axis_]);
        const bool changed = next != scroll_position_;
        scroll_position_ = next;
        if (axis_ == ImGuiAxis_X) ImGui::SetScrollX(window, next);
        else ImGui::SetScrollY(window, next);
        return changed;
    }

    void handle(const Event& event) {
        ImGuiIO& io = ImGui::GetIO();
        io.AddMouseSourceEvent(event.touch ? ImGuiMouseSource_TouchScreen : ImGuiMouseSource_Mouse);
        if (!event.touch) {
            if (down_) {
                cancel_press();
                down_ = scrolling_ = forwarding_ = false;
            }
            io.AddMousePosEvent(event.pos.x, event.pos.y);
            if (event.action == Down) io.AddMouseButtonEvent(0, true);
            if (event.action == Up || event.action == Cancel) io.AddMouseButtonEvent(0, false);
            return;
        }
        if (event.action == Down) {
            keyboard_gesture_ = io.WantTextInput || UiText::wants_keyboard();
            UiText::pointer_down(event.pos);
            held_ = 0.0f;
            text_selection_ = 0;
            origin_ = previous_ = event.pos;
            io.AddMousePosEvent(origin_.x, origin_.y);
            capture_frame_ = GImGui->FrameCount + 1;
            window_id_ = tab_bar_ = touch_window_ = 0;
            down_ = true;
            suppress_tap_ = event.stopped_fling;
            scrolling_ = forwarding_ = horizontal_owner_ = false;
            ImGuiWindow* hovered = hovered_window(origin_);
            if (!hovered) return;
            touch_window_ = hovered->ID;
            for (const DragItem& item : drag_items_)
                if (item.window == touch_window_ && item.rect.Contains(origin_)) horizontal_owner_ = true;
            for (int axis = 0; axis < 2; ++axis)
                if ((axis == ImGuiAxis_X ? hovered->ScrollbarX : hovered->ScrollbarY) &&
                        ImGui::GetWindowScrollbarRect(hovered, static_cast<ImGuiAxis>(axis)).Contains(origin_)) {
                    press();
                    return;
                }
            for (int i = 0; i < GImGui->TabBars.GetMapSize(); ++i) {
                ImGuiTabBar* bar = GImGui->TabBars.TryGetMapData(i);
                if (bar && bar->Window == hovered && bar->CurrFrameVisible >= GImGui->FrameCount - 1 &&
                        (bar->Flags & ImGuiTabBarFlags_FittingPolicyScroll) &&
                        bar->WidthAllTabs > bar->BarRect.GetWidth() && bar->BarRect.Contains(origin_)) {
                    tab_bar_ = bar->ID;
                    break;
                }
            }
            return;
        }
        if (event.action == Cancel || (down_ && !valid_touch_window())) {
            text_selection_ = 0;
            cancel_press();
            down_ = scrolling_ = forwarding_ = false;
            window_id_ = tab_bar_ = 0;
            velocity_ = 0.0f;
            return;
        }
        if (!down_) return;
        if (forwarding_) {
            io.AddMousePosEvent(event.pos.x, event.pos.y);
            if (event.action == Up) {
                io.AddMouseButtonEvent(0, false);
                down_ = forwarding_ = false;
            }
            return;
        }
        // A finger has no proximity hover, but while it is on screen its
        // position must still reach ImGui: menus/buttons need hover feedback
        // before release. Scroll ownership below hides the pointer again so a
        // swipe cannot leave unrelated controls highlighted or clicked.
        if (event.action == Move && !scrolling_)
            io.AddMousePosEvent(event.pos.x, event.pos.y);
        const bool moved = event.intent.x != 0.0f || event.intent.y != 0.0f;
        if (!scrolling_ && moved) {
            axis_ = std::abs(event.intent.x) > std::abs(event.intent.y) ? ImGuiAxis_X : ImGuiAxis_Y;
            if (axis_ == ImGuiAxis_X && horizontal_owner_) {
                press();
                events_.push_front(event);
                return;
            }
            ImGuiWindow* window = scroll_window(ImGui::FindWindowByID(touch_window_), axis_);
            if (tab_bar_ && axis_ == ImGuiAxis_X) {
                ImGuiTabBar* bar = GImGui->TabBars.GetByKey(tab_bar_);
                if (bar) { scroll_position_ = bar->ScrollingTarget; scrolling_ = true; }
            } else if (window) {
                window_id_ = window->ID;
                scroll_position_ = window->ScrollTarget[axis_] != FLT_MAX ? window->ScrollTarget[axis_] : window->Scroll[axis_];
                scrolling_ = true;
            }
            if (scrolling_) {
                io.AddMousePosEvent(-FLT_MAX, -FLT_MAX);
                const float distance = event.pos[axis_] - origin_[axis_];
                scroll(distance - std::copysign(std::min(std::abs(distance), slop_), distance));
            }
        } else if (scrolling_) scroll(event.pos[axis_] - previous_[axis_]);
        previous_ = event.pos;
        if (event.action == Up) {
            if (scrolling_) velocity_ = event.velocity[axis_];
            else if (!moved && !suppress_tap_) {
                press();
                events_.push_front(event);
                return;
            }
            down_ = scrolling_ = false;
        }
    }
};

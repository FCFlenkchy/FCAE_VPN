#pragma once
#include <algorithm>

namespace UiFrame {
constexpr double interaction_interval = 1.0 / 60.0;
// Wait only for the *remaining* frame budget. Waiting a full interval after
// drawing/presenting adds CPU/GPU work and a second VSYNC to the input latency.
inline double wait_seconds(double now, double last_start, double interval,
                           double idle_wait, bool scheduled) {
    return scheduled ? std::clamp(last_start + interval - now, 0.0, idle_wait) : idle_wait;
}
}

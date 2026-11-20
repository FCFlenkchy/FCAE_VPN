#pragma once
#include "imgui.h"
#include <algorithm>

namespace UiMedia {
struct Placement {
    ImVec2 min, max;
    ImVec2 uv0{0, 0}, uv1{1, 1};
};
// Fit once in source space, then clip once. Resizing must never combine a
// pre-cropped UV with another destination-space zoom (double cropping).
inline Placement fit(ImVec2 origin, ImVec2 area, ImVec2 source, bool cover,
                     float scale = 1.0f, ImVec2 anchor = ImVec2(0.5f, 0.5f)) {
    const float x = area.x / std::max(source.x, 1.0f);
    const float y = area.y / std::max(source.y, 1.0f);
    const float ratio = (cover ? std::max(x, y) : std::min(x, y)) * std::max(scale, 0.01f);
    const ImVec2 size(std::max(source.x, 1.0f) * ratio, std::max(source.y, 1.0f) * ratio);
    auto offset = [](float extent, float drawn, float percent) {
        if (drawn >= extent) return (extent - drawn) * 0.5f;
        return std::clamp(extent * std::clamp(percent, 0.0f, 1.0f) - drawn * 0.5f, 0.0f, extent - drawn);
    };
    const ImVec2 start(offset(area.x, size.x, anchor.x), offset(area.y, size.y, anchor.y));
    Placement out;
    const ImVec2 lo(std::max(0.0f, start.x), std::max(0.0f, start.y));
    const ImVec2 hi(std::min(area.x, start.x + size.x), std::min(area.y, start.y + size.y));
    out.min = ImVec2(origin.x + lo.x, origin.y + lo.y);
    out.max = ImVec2(origin.x + hi.x, origin.y + hi.y);
    out.uv0 = ImVec2(std::clamp((lo.x - start.x) / size.x, 0.0f, 1.0f),
                     std::clamp((lo.y - start.y) / size.y, 0.0f, 1.0f));
    out.uv1 = ImVec2(std::clamp((hi.x - start.x) / size.x, 0.0f, 1.0f),
                     std::clamp((hi.y - start.y) / size.y, 0.0f, 1.0f));
    return out;
}
}

#pragma once
#include "imgui.h"
#include <algorithm>

namespace UiMedia {
struct Placement {
    ImVec2 min, max;
    ImVec2 uv0{0, 0}, uv1{1, 1};
};
// Map the complete texture to the destination, independently on each axis.
// Never crop UVs or resize/re-encode the source. Legacy zoom above 100% is
// capped so every source edge remains visible; smaller authored media still
// uses its requested centre, clamped within the card.
inline Placement stretch(ImVec2 origin, ImVec2 area, float scale = 1.0f,
                         ImVec2 anchor = ImVec2(0.5f, 0.5f)) {
    const float factor = std::clamp(scale, 0.5f, 1.0f);
    const ImVec2 size(area.x * factor, area.y * factor);
    auto offset = [](float extent, float drawn, float percent) {
        return std::clamp(extent * std::clamp(percent, 0.0f, 1.0f) - drawn * 0.5f,
                          0.0f, std::max(0.0f, extent - drawn));
    };
    Placement out;
    out.min = ImVec2(origin.x + offset(area.x, size.x, anchor.x),
                     origin.y + offset(area.y, size.y, anchor.y));
    out.max = ImVec2(out.min.x + size.x, out.min.y + size.y);
    return out;
}
}

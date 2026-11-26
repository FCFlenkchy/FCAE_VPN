#pragma once
#include "imgui.h"

inline void ui_apply_style(float base_font_size) {
    ImGui::StyleColorsDark();
    ImGuiStyle& style = ImGui::GetStyle();
    style.FontScaleDpi = 1.0f;
    style.FontSizeBase = base_font_size;
    style.WindowRounding   = 10.0f;
    style.FrameRounding    = 6.0f;
    style.GrabRounding     = 4.0f;
    style.ScrollbarRounding = 6.0f;
    // Corners only. None of these changes what an item measures, so nothing
    // that was laid out around the old style moves.
    style.ChildRounding    = 8.0f;
    style.PopupRounding    = 8.0f;
    style.TabRounding      = 6.0f;
    style.FramePadding     = ImVec2(10, 6);
    style.WindowPadding    = ImVec2(16, 12);
    style.ButtonTextAlign  = ImVec2(0.5f, 0.5f);

    ImVec4* colors = style.Colors;
    colors[ImGuiCol_WindowBg]        = ImVec4(0.08f, 0.08f, 0.12f, 1.0f);
    colors[ImGuiCol_ChildBg]         = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);
    colors[ImGuiCol_PopupBg]         = ImVec4(0.08f, 0.11f, 0.17f, 0.98f);
    colors[ImGuiCol_FrameBg]         = ImVec4(0.12f, 0.16f, 0.24f, 1.0f);
    colors[ImGuiCol_FrameBgHovered]  = ImVec4(0.17f, 0.24f, 0.36f, 1.0f);
    colors[ImGuiCol_FrameBgActive]   = ImVec4(0.21f, 0.31f, 0.45f, 1.0f);
    colors[ImGuiCol_TitleBg]         = ImVec4(0.06f, 0.06f, 0.10f, 1.0f);
    colors[ImGuiCol_TitleBgActive]   = ImVec4(0.10f, 0.10f, 0.16f, 1.0f);
    colors[ImGuiCol_Button]          = ImVec4(0.16f, 0.40f, 0.60f, 1.0f);
    colors[ImGuiCol_ButtonHovered]   = ImVec4(0.20f, 0.50f, 0.70f, 1.0f);
    colors[ImGuiCol_ButtonActive]    = ImVec4(0.14f, 0.36f, 0.56f, 1.0f);
    colors[ImGuiCol_Tab]             = ImVec4(0.12f, 0.12f, 0.18f, 1.0f);
    colors[ImGuiCol_TabHovered]      = ImVec4(0.20f, 0.30f, 0.45f, 1.0f);
    colors[ImGuiCol_TabSelected]     = ImVec4(0.16f, 0.36f, 0.52f, 1.0f);
    colors[ImGuiCol_SliderGrab]      = ImVec4(0.30f, 0.60f, 0.80f, 1.0f);
    colors[ImGuiCol_SliderGrabActive]= ImVec4(0.35f, 0.70f, 0.90f, 1.0f);

    // The rest of the palette, brought in line with the blues above instead of
    // left at the stock greys they were sitting beside.
    colors[ImGuiCol_TabDimmed]            = ImVec4(0.10f, 0.10f, 0.15f, 1.0f);
    colors[ImGuiCol_TabDimmedSelected]    = ImVec4(0.13f, 0.27f, 0.39f, 1.0f);
    colors[ImGuiCol_Header]               = ImVec4(0.16f, 0.36f, 0.52f, 0.55f);
    colors[ImGuiCol_HeaderHovered]        = ImVec4(0.20f, 0.46f, 0.66f, 0.80f);
    colors[ImGuiCol_HeaderActive]         = ImVec4(0.20f, 0.50f, 0.70f, 1.0f);
    colors[ImGuiCol_Border]               = ImVec4(0.33f, 0.40f, 0.54f, 0.55f);
    colors[ImGuiCol_Separator]            = ImVec4(0.33f, 0.40f, 0.54f, 0.55f);
    colors[ImGuiCol_ScrollbarBg]          = ImVec4(0.05f, 0.06f, 0.10f, 0.40f);
    colors[ImGuiCol_ScrollbarGrab]        = ImVec4(0.24f, 0.31f, 0.44f, 1.0f);
    colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.30f, 0.40f, 0.56f, 1.0f);
    colors[ImGuiCol_ScrollbarGrabActive]  = ImVec4(0.34f, 0.47f, 0.66f, 1.0f);
    colors[ImGuiCol_TextSelectedBg]       = ImVec4(0.20f, 0.50f, 0.70f, 0.45f);
    // Captions are read over the background picture as well as over panels.
    colors[ImGuiCol_TextDisabled]         = ImVec4(0.58f, 0.62f, 0.70f, 1.0f);
    // What is behind a dialog goes dark, not pale: the stock veil is a light
    // grey that washed the page out and left the dialog no easier to find.
    colors[ImGuiCol_ModalWindowDimBg]     = ImVec4(0.03f, 0.04f, 0.08f, 0.50f);
}

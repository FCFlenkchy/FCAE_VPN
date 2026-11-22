#pragma once

// Shared ImGui controls: desktop, Android and the iOS containing app use
// the same asynchronous native account operations and never persist passwords.
static bool s_ur_open = false;
static uint64_t s_ur_job = 0;
static std::string s_ur_op, s_ur_status, s_ur_region;
static char s_ur_email[320] = {}, s_ur_password[1024] = {}, s_ur_code[512] = {};
static bool s_ur_signed_in = false, s_ur_verify = false;
static int s_ur_transport = 0;
static const char* const s_ur_modes[] = {"auto", "h1", "h3", "dns", "dnspump"};
static std::vector<std::pair<std::string, std::string>> s_ur_regions;

static void ur_submit(const char* op, const std::string& fields = {}) {
    if (s_ur_job) return;
    std::string request = "{\"op\":\"" + std::string(op) + "\",\"data_dir\":\""
        + firefox_json_escape(data_dir().c_str()) + "\"" + fields + "}";
    s_ur_job = fcae_urnetwork_account_submit(request.c_str());
    std::fill(request.begin(), request.end(), '\0');
    s_ur_op = op;
    s_ur_status = s_ur_job ? "Working…" : "Cannot queue URnetwork operation (busy or not included in this build).";
}
static void ur_poll() {
    if (!s_ur_job) return;
    static double next = 0;
    double now = ui_now_seconds();
    if (now < next) return;
    next = now + 0.15;
    uint32_t size = fcae_urnetwork_job_poll(s_ur_job, nullptr, 0);
    if (!size || size > 4 * 1024 * 1024) {
        fcae_urnetwork_job_release(s_ur_job); s_ur_job = 0;
        s_ur_status = "URnetwork account job is unavailable."; return;
    }
    std::vector<char> bytes(size + 1);
    fcae_urnetwork_job_poll(s_ur_job, bytes.data(), (uint32_t)bytes.size());
    std::string json(bytes.data());
    std::string status = firefox_json_string(json, "status");
    if (status == "pending") return;
    fcae_urnetwork_job_release(s_ur_job); s_ur_job = 0;
    if (status != "done") { s_ur_status = firefox_json_string(json, "error"); return; }
    if (s_ur_op == "load") {
        s_ur_signed_in = firefox_json_bool(json, "signed_in");
        snprintf(s_ur_email, sizeof(s_ur_email), "%s", firefox_json_string(json, "email").c_str());
        s_ur_region = firefox_json_string(json, "region");
        std::string mode = firefox_json_string(json, "transport");
        s_ur_transport = 0;
        for (int i = 0; i < 5; ++i) if (mode == s_ur_modes[i]) s_ur_transport = i;
        s_ur_status = s_ur_signed_in ? "Signed in" : "Sign in to your URnetwork account.";
    } else if (s_ur_op == "regions") {
        s_ur_regions.clear();
        for (const auto& object : firefox_json_objects(json, "locations"))
            s_ur_regions.emplace_back(firefox_json_string(object, "id"), firefox_json_string(object, "name"));
        s_ur_status = "Provider locations loaded.";
    } else if (s_ur_op == "logout") {
        s_ur_signed_in = false; s_ur_verify = false; s_ur_email[0] = 0;
        s_ur_status = "Signed out.";
    } else if (s_ur_op == "login" || s_ur_op == "verify" || s_ur_op == "code-login") {
        s_ur_verify = firefox_json_bool(json, "verification_required");
        s_ur_signed_in = firefox_json_bool(json, "signed_in");
        s_ur_status = s_ur_verify
            ? (firefox_json_bool(json, "send_failed") ? "Verification code could not be sent. Try signing in again later." : "Enter the verification code sent to your email.")
            : "Signed in. Your device will be registered on the next connection.";
    } else s_ur_status = "Saved for the next connection.";
}
static void open_urnetwork_settings() { s_ur_open = true; ur_submit("load"); }
static void render_urnetwork_settings() {
    ur_poll();
    if (s_ur_open) { ImGui::OpenPopup("URnetwork settings"); s_ur_open = false; }
    ImGui::SetNextWindowPos(viewport_center(), ImGuiCond_Always, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(modal_size(640, 560), ImGuiCond_Always);
    if (!ImGui::BeginPopupModal("URnetwork settings", nullptr, ImGuiWindowFlags_NoResize)) return;
    ImGui::BeginChild("##ur_scroll", ImVec2(0, -ImGui::GetFrameHeightWithSpacing() - 8), ImGuiChildFlags_None, ImGuiWindowFlags_AlwaysVerticalScrollbar);
    ImGui::BeginDisabled(s_ur_job != 0 || (g_app.ffi_state.load() != FCAE_STATE_DISCONNECTED && g_app.ffi_state.load() != FCAE_STATE_ERROR));
    if (!s_ur_signed_in) {
        UiText::InputTextWithHint("Email", "URnetwork account email", s_ur_email, sizeof(s_ur_email));
        UiText::InputTextWithHint("Password", "Account password", s_ur_password, sizeof(s_ur_password), ImGuiInputTextFlags_Password);
        if (ImGui::Button("Sign in")) {
            ur_submit("login", ",\"email\":\"" + firefox_json_escape(s_ur_email) + "\",\"password\":\"" + firefox_json_escape(s_ur_password) + "\"");
            std::fill(std::begin(s_ur_password), std::end(s_ur_password), '\0');
        }
        if (s_ur_verify) {
            UiText::InputTextWithHint("Verification code", "Email verification code", s_ur_code, sizeof(s_ur_code));
            if (ImGui::Button("Verify email")) {
                ur_submit("verify", ",\"email\":\"" + firefox_json_escape(s_ur_email) + "\",\"code\":\"" + firefox_json_escape(s_ur_code) + "\"");
                std::fill(std::begin(s_ur_code), std::end(s_ur_code), '\0');
            }
        }
        ImGui::Separator();
        UiText::InputTextWithHint("Authorization code", "Code from your URnetwork account", s_ur_code, sizeof(s_ur_code), ImGuiInputTextFlags_Password);
        if (ImGui::Button("Sign in with authorization code")) {
            ur_submit("code-login", ",\"code\":\"" + firefox_json_escape(s_ur_code) + "\"");
            std::fill(std::begin(s_ur_code), std::end(s_ur_code), '\0');
        }
    } else {
        ImGui::TextWrapped("Signed in: %s", s_ur_email[0] ? s_ur_email : "URnetwork account");
        if (ImGui::Button("Sign out")) ur_submit("logout");
        if (ImGui::Button("Refresh provider locations")) ur_submit("regions");
    }
    ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();
    std::string selected = s_ur_region.empty() ? "Best available" : "Saved location (refresh to load its name)";
    for (const auto& entry : s_ur_regions) if (entry.first == s_ur_region) selected = entry.second;
    if (ImGui::BeginCombo("Region", selected.c_str())) {
        if (ImGui::Selectable("Best available", s_ur_region.empty())) s_ur_region.clear();
        for (const auto& entry : s_ur_regions) {
            ImGui::PushID(entry.first.c_str());
            if (ImGui::Selectable(entry.second.c_str(), entry.first == s_ur_region)) s_ur_region = entry.first;
            ImGui::PopID();
        }
        ImGui::EndCombo();
    }
    const char* labels[] = {"Auto", "HTTP/1.1 (H1)", "HTTP/3 (H3)", "DNS", "DNS pump"};
    ImGui::Combo("Transport", &s_ur_transport, labels, 5);
    if (ImGui::Button("Save region and transport"))
        ur_submit("save", ",\"region\":\"" + firefox_json_escape(s_ur_region.c_str()) + "\",\"transport\":\"" + s_ur_modes[s_ur_transport] + "\"");
    ImGui::EndDisabled();
    ImGui::TextWrapped("%s", s_ur_status.c_str());
    ImGui::EndChild();
    if (ImGui::Button("Close")) {
        std::fill(std::begin(s_ur_password), std::end(s_ur_password), '\0');
        std::fill(std::begin(s_ur_code), std::end(s_ur_code), '\0');
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
}

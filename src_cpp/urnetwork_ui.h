#pragma once

static bool s_ur_open = false, s_ur_visible = false, s_ur_add = false, s_ur_code_prompt = false;
static bool s_ur_add_close = false, s_ur_code_close = false, s_ur_signed_in = false, s_ur_verify = false;
static bool s_ur_dirty = false, s_ur_save_failed = false;
static uint64_t s_ur_job = 0;
static bool ur_account_busy() { return s_ur_job != 0 || s_ur_dirty; }
static std::string s_ur_op, s_ur_status, s_ur_region, s_ur_selected;
static char s_ur_email[320] = {}, s_ur_password[1024] = {}, s_ur_code[512] = {};
static int s_ur_transport = 0;
static double s_ur_regions_after = 0, s_ur_poll_after = 0;
static const char* const s_ur_modes[] = {"auto", "h1", "h3", "dns", "dnspump"};
static std::vector<std::pair<std::string, std::string>> s_ur_regions, s_ur_accounts;

static void ur_clear_secrets() {
    std::fill(std::begin(s_ur_password), std::end(s_ur_password), '\0');
    std::fill(std::begin(s_ur_code), std::end(s_ur_code), '\0');
}
static void ur_submit(const char* op, const std::string& fields = {}) {
    if (s_ur_job) return;
    std::string request = "{\"op\":\"" + std::string(op) + "\",\"data_dir\":\""
        + firefox_json_escape(data_dir().c_str()) + "\"" + fields + "}";
    s_ur_job = fcae_urnetwork_account_submit(request.c_str());
    std::fill(request.begin(), request.end(), '\0');
    s_ur_op = op;
    s_ur_status = s_ur_job ? "Working…" : "Cannot queue URnetwork operation.";
    ui_request_redraw();
}
static void ur_snapshot(const std::string& json) {
    s_ur_signed_in = firefox_json_bool(json, "signed_in");
    s_ur_selected = firefox_json_string(json, "selected");
    s_ur_accounts.clear();
    for (const auto& object : firefox_json_objects(json, "accounts"))
        s_ur_accounts.emplace_back(firefox_json_string(object, "id"), firefox_json_string(object, "email"));
    s_ur_regions.clear();
    for (const auto& object : firefox_json_objects(json, "locations"))
        s_ur_regions.emplace_back(firefox_json_string(object, "id"), firefox_json_string(object, "name"));
    if (!s_ur_dirty) {
        s_ur_region = firefox_json_string(json, "region");
        const std::string mode = firefox_json_string(json, "transport");
        s_ur_transport = 0;
        for (int i = 0; i < 5; ++i) if (mode == s_ur_modes[i]) s_ur_transport = i;
    }
    s_ur_regions_after = firefox_json_bool(json, "locations_stale") ? 0 : ui_now_seconds() + 900;
}
static void ur_poll() {
    if (!s_ur_job || ui_now_seconds() < s_ur_poll_after) return;
    s_ur_poll_after = ui_now_seconds() + .15;
    const uint32_t size = fcae_urnetwork_job_poll(s_ur_job, nullptr, 0);
    if (!size || size > 4 * 1024 * 1024) {
        fcae_urnetwork_job_release(s_ur_job); s_ur_job = 0;
        s_ur_status = "URnetwork account job is unavailable."; return;
    }
    std::vector<char> bytes(size + 1);
    fcae_urnetwork_job_poll(s_ur_job, bytes.data(), (uint32_t)bytes.size());
    std::string json(bytes.data());
    const std::string status = firefox_json_string(json, "status");
    if (status == "pending") return;
    fcae_urnetwork_job_release(s_ur_job); s_ur_job = 0;
    if (status != "done") {
        s_ur_status = firefox_json_string(json, "error");
        if (s_ur_op == "save") { s_ur_dirty = true; s_ur_save_failed = true; }
        if (s_ur_op == "regions") s_ur_regions_after = ui_now_seconds() + 300;
        return;
    }
    if (s_ur_op == "save") { s_ur_status.clear(); return; }
    if (s_ur_op == "login" || s_ur_op == "verify" || s_ur_op == "code-login") {
        s_ur_verify = firefox_json_bool(json, "verification_required");
        if (s_ur_verify) {
            s_ur_add_close = true; s_ur_code_close = false; s_ur_code_prompt = true;
            s_ur_status = firefox_json_bool(json, "send_failed")
                ? "The verification email could not be sent. Close and retry sign-in."
                : "Enter the verification code sent to your email.";
            return;
        }
        s_ur_add_close = s_ur_code_close = true;
        s_ur_verify = false; ur_clear_secrets();
    }
    ur_snapshot(json);
    s_ur_status.clear();
}
static void open_urnetwork_settings() { s_ur_open = true; if (!s_ur_dirty) ur_submit("load"); }
static void render_urnetwork_settings() {
    ur_poll();
    if (s_ur_open) { ImGui::OpenPopup("URnetwork settings"); s_ur_open = false; s_ur_visible = true; }
    const bool disconnected = g_app.ffi_state.load() == FCAE_STATE_DISCONNECTED || g_app.ffi_state.load() == FCAE_STATE_ERROR;
    const bool editable = disconnected && !g_app.start_busy.load();
    if (s_ur_visible && !s_ur_job && editable) {
        if (s_ur_dirty && !s_ur_save_failed) {
            ur_submit("save", ",\"region\":\"" + firefox_json_escape(s_ur_region.c_str())
                + "\",\"transport\":\"" + s_ur_modes[s_ur_transport] + "\"");
            if (s_ur_job) s_ur_dirty = false;
        } else if (s_ur_signed_in && !s_ur_verify && ui_now_seconds() >= s_ur_regions_after) {
            s_ur_regions_after = ui_now_seconds() + 300;
            ur_submit("regions");
        }
    }
    ImGui::SetNextWindowPos(viewport_center(), ImGuiCond_Always, ImVec2(.5f, .5f));
    ImGui::SetNextWindowSize(modal_size(640, 560), ImGuiCond_Always);
    if (!ImGui::BeginPopupModal("URnetwork settings", nullptr, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove)) return;
    ImGui::BeginChild("##ur_scroll", ImVec2(0, -ImGui::GetFrameHeightWithSpacing() - 8));
    ImGui::BeginDisabled(s_ur_job != 0 || !editable);
    if (account_region_combo("urnetwork", s_ur_region, s_ur_regions)) { s_ur_dirty = true; s_ur_save_failed = false; }
    ImGui::TextUnformatted("Transport"); ImGui::SetNextItemWidth(-1);
    const char* labels[] = {"Auto", "HTTP/1.1 (H1)", "HTTP/3 (H3)", "DNS", "DNS pump"};
    if (ImGui::Combo("##ur_transport", &s_ur_transport, labels, 5)) { s_ur_dirty = true; s_ur_save_failed = false; }
    ImGui::SeparatorText("Accounts");
    for (const auto& account : s_ur_accounts) {
        ImGui::PushID(account.first.c_str());
        if (ImGui::RadioButton("##selected", account.first == s_ur_selected))
            ur_submit("select", ",\"account_id\":\"" + firefox_json_escape(account.first.c_str()) + "\"");
        ImGui::SameLine();
        if (ImGui::SmallButton("Remove"))
            ur_submit("remove", ",\"account_id\":\"" + firefox_json_escape(account.first.c_str()) + "\"");
        ImGui::SameLine();
        ImGui::TextWrapped("%s", account.second.empty() ? "URnetwork account" : account.second.c_str());
        ImGui::PopID();
    }
    if (ImGui::Button("Add new account")) {
        ur_clear_secrets(); s_ur_email[0] = 0;
        s_ur_verify = false; s_ur_add_close = s_ur_code_close = false; s_ur_add = true;
        s_ur_status.clear();
    }
    if (s_ur_verify) { ImGui::SameLine(); if (ImGui::Button("Continue verification")) s_ur_code_prompt = true; }
    ImGui::SeparatorText("Local listeners");
    listener_row("URnetwork SOCKS5", &g_app.ur_socks_enabled, &g_app.ur_socks_port, 1, 65535);
    listener_row("URnetwork HTTP", &g_app.ur_http_enabled, &g_app.ur_http_port, 1, 65535);
    ImGui::EndDisabled();
    if (!s_ur_status.empty()) ImGui::TextWrapped("%s", s_ur_status.c_str());
    if (s_ur_save_failed && ImGui::Button("Retry saving settings")) s_ur_save_failed = false;
    ImGui::EndChild();
    // Finish queued autosaves before allowing the settings dialog to close.
    ImGui::BeginDisabled(s_ur_dirty || s_ur_job != 0);
    if (ImGui::Button("Close")) { ur_clear_secrets(); s_ur_visible = false; ImGui::CloseCurrentPopup(); }
    ImGui::EndDisabled();
    if (s_ur_add) { ImGui::OpenPopup("Add URnetwork account"); s_ur_add = false; }
    if (begin_account_dialog("Add URnetwork account", 520)) {
        if (s_ur_add_close) { s_ur_add_close = false; ImGui::CloseCurrentPopup(); }
        else {
            account_identity_fields(s_ur_email, sizeof(s_ur_email), s_ur_password, sizeof(s_ur_password));
            ImGui::BeginDisabled(s_ur_job != 0 || !editable || !s_ur_email[0] || !s_ur_password[0]);
            if (ImGui::Button("Sign in")) {
                ur_submit("login", ",\"email\":\"" + firefox_json_escape(s_ur_email) + "\",\"password\":\"" + firefox_json_escape(s_ur_password) + "\"");
                std::fill(std::begin(s_ur_password), std::end(s_ur_password), '\0');
            }
            ImGui::EndDisabled();
            ImGui::Separator();
            ImGui::SetNextItemWidth(-1);
            UiText::InputTextWithHint("##auth_code", "Authorization code (optional alternative)", s_ur_code, sizeof(s_ur_code), ImGuiInputTextFlags_Password);
            ImGui::BeginDisabled(s_ur_job != 0 || !editable || !s_ur_code[0]);
            if (ImGui::Button("Sign in with authorization code")) {
                ur_submit("code-login", ",\"code\":\"" + firefox_json_escape(s_ur_code) + "\"");
                ur_clear_secrets();
            }
            ImGui::EndDisabled();
            if (!s_ur_status.empty()) ImGui::TextWrapped("%s", s_ur_status.c_str());
            ImGui::BeginDisabled(s_ur_job != 0);
            if (ImGui::Button("Cancel")) { ur_clear_secrets(); ImGui::CloseCurrentPopup(); }
            ImGui::EndDisabled();
        }
        ImGui::EndPopup();
    }
    if (s_ur_code_prompt) { ImGui::OpenPopup("URnetwork account security code"); s_ur_code_prompt = false; }
    if (begin_account_dialog("URnetwork account security code", 500)) {
        if (s_ur_code_close) { s_ur_code_close = false; ImGui::CloseCurrentPopup(); }
        else {
            ImGui::TextWrapped("Enter the email verification code for %s.", s_ur_email);
            ImGui::SetNextItemWidth(-1);
            UiText::InputTextWithHint("##verification", "Verification code", s_ur_code, sizeof(s_ur_code));
            ImGui::BeginDisabled(s_ur_job != 0 || !editable || !s_ur_code[0]);
            if (ImGui::Button("Verify")) {
                ur_submit("verify", ",\"email\":\"" + firefox_json_escape(s_ur_email) + "\",\"code\":\"" + firefox_json_escape(s_ur_code) + "\"");
                ur_clear_secrets();
            }
            ImGui::EndDisabled();
            if (!s_ur_status.empty()) ImGui::TextWrapped("%s", s_ur_status.c_str());
            ImGui::BeginDisabled(s_ur_job != 0);
            if (ImGui::Button("Close")) { ur_clear_secrets(); ImGui::CloseCurrentPopup(); }
            ImGui::EndDisabled();
        }
        ImGui::EndPopup();
    }
    ImGui::EndPopup();
}

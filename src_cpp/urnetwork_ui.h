#pragma once
#include "account_request_status.h"

static bool s_ur_open = false, s_ur_visible = false, s_ur_add = false, s_ur_code_prompt = false;
static bool s_ur_add_close = false, s_ur_code_close = false, s_ur_signed_in = false, s_ur_verify = false;
static bool s_ur_dirty = false, s_ur_save_failed = false;
// Keep credentials only in the existing dialog buffers while a background read finishes.
static bool s_ur_editing_account = false;
static int s_ur_pending_signin = 0; // 1: password, 2: authorization code, 3: code by email
// The add dialog asks for an email first; the authorization-code form is shown
// on demand, when the user picks that way in.
static bool s_ur_use_code = false;
// The verification prompt is on screen, so a resend answers there.
static bool s_ur_code_visible = false;
static uint64_t s_ur_job = 0;
static std::string s_ur_op, s_ur_status, s_ur_region, s_ur_selected;
struct UrUsage { std::string text, updated; bool refresh_failed = false; };
static std::unordered_map<std::string, UrUsage> s_ur_usage;
static uint64_t s_ur_status_revision = 0;
static AccountRequestStatusTimer s_ur_status_timer;
static void ur_set_status(const std::string& text) {
    s_ur_status = text;
    ++s_ur_status_revision;
    ui_request_redraw();
}
// Reads/region refreshes do not lock the main Connect button. Account writes
// and unsaved settings still serialize with session startup.
static bool ur_account_busy() {
    return s_ur_pending_signin || s_ur_dirty || (s_ur_job && s_ur_op != "load" && s_ur_op != "regions" && s_ur_op != "usage");
}
static bool ur_requests_working() {
    return s_ur_pending_signin || s_ur_job || (s_ur_dirty && !s_ur_save_failed);
}
static void ur_request_status() {
    const bool background = s_ur_op == "usage" || s_ur_op == "regions" || s_ur_op == "load";
    if (s_ur_pending_signin) ImGui::TextUnformatted("Waiting for the current account request…");
    else if (ur_requests_working() && !background) ImGui::TextUnformatted("Working…");
    else if (!s_ur_status.empty() && !background) ImGui::TextWrapped("%s", s_ur_status.c_str());
}

static char s_ur_email[320] = {}, s_ur_password[1024] = {}, s_ur_code[512] = {};
static int s_ur_transport = 0;
static double s_ur_regions_after = 0, s_ur_usage_after = 0, s_ur_poll_after = 0;
static const char* const s_ur_modes[] = {"auto", "h1", "h3", "dns", "dnspump"};
static std::vector<std::pair<std::string, std::string>> s_ur_regions, s_ur_accounts;

static void ur_clear_secrets() {
    std::fill(std::begin(s_ur_password), std::end(s_ur_password), '\0');
    std::fill(std::begin(s_ur_code), std::end(s_ur_code), '\0');
}
static std::string ur_trimmed(const char* text) {
    std::string value = text;
    size_t begin = 0;
    while (begin < value.size() && std::isspace((unsigned char)value[begin])) ++begin;
    size_t end = value.size();
    while (end > begin && std::isspace((unsigned char)value[end - 1])) --end;
    return value.substr(begin, end - begin);
}
/// The code itself, from whatever was pasted: surrounding space is dropped, and
/// a link that carries the code as `auth_code=` gives up just the code. A code
/// works once and for minutes, so a paste that needs fixing is a wasted code.
static std::string ur_auth_code(const char* pasted) {
    std::string code = ur_trimmed(pasted);
    const size_t key = code.find("auth_code=");
    if (key != std::string::npos && code.find("://") != std::string::npos) {
        code.erase(0, key + strlen("auth_code="));
        const size_t end = code.find_first_of("&#");
        if (end != std::string::npos) code.resize(end);
    }
    return code;
}
static void ur_submit(const char* op, const std::string& fields = {}) {
    if (s_ur_job) return;
    std::string request = "{\"op\":\"" + std::string(op) + "\",\"data_dir\":\""
        + firefox_json_escape(data_dir().c_str()) + "\"" + fields + "}";
    s_ur_job = fcae_urnetwork_account_submit(request.c_str());
    std::fill(request.begin(), request.end(), '\0');
    s_ur_op = op;
    if (!s_ur_job && s_ur_op == "save") s_ur_save_failed = true;
    ur_set_status(s_ur_job ? "" : "Cannot queue URnetwork operation.");
    ui_request_redraw();
}
static void ur_snapshot(const std::string& json) {
    s_ur_signed_in = firefox_json_bool(json, "signed_in");
    const std::string selected = firefox_json_string(json, "selected");
    if (selected != s_ur_selected) {
        s_ur_usage_after = 0;
    }
    s_ur_selected = selected;
    s_ur_accounts.clear();
    for (const auto& object : firefox_json_objects(json, "accounts")) {
        const std::string id = firefox_json_string(object, "id");
        s_ur_accounts.emplace_back(id, firefox_json_string(object, "email"));
        const std::string usage = firefox_json_string(object, "usage");
        if (!id.empty() && !usage.empty() && s_ur_usage.find(id) == s_ur_usage.end())
            s_ur_usage[id] = {usage, firefox_json_string(object, "usage_updated"), false};
    }
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
        if (s_ur_op == "save") { s_ur_dirty = true; s_ur_save_failed = true; }
        ur_set_status("URnetwork account job is unavailable."); return;
    }
    std::vector<char> bytes(size + 1);
    fcae_urnetwork_job_poll(s_ur_job, bytes.data(), (uint32_t)bytes.size());
    std::string json(bytes.data());
    const std::string status = firefox_json_string(json, "status");
    if (status == "pending") return;
    fcae_urnetwork_job_release(s_ur_job); s_ur_job = 0;
    if (status != "done") {
        ur_set_status(firefox_json_string(json, "error"));
        if (s_ur_op == "save") { s_ur_dirty = true; s_ur_save_failed = true; }
        if (s_ur_op == "regions") s_ur_regions_after = ui_now_seconds() + 300;
        if (s_ur_op == "usage") {
            s_ur_usage[s_ur_selected].refresh_failed = true;
            s_ur_usage_after = ui_now_seconds() + 60;
        }
        return;
    }
    if (s_ur_op == "save") { ur_set_status("Saved for the next connection."); return; }
    if (s_ur_op == "verify-send") {
        // The code is on its way; the verification prompt takes it from here.
        s_ur_verify = true;
        if (!s_ur_code_visible) { s_ur_add_close = true; s_ur_code_close = false; s_ur_code_prompt = true; }
        ur_set_status("A code is on its way to your email.");
        return;
    }
    if (s_ur_op == "usage") {
        const std::string account = firefox_json_string(json, "usage_account");
        const std::string usage = firefox_json_string(json, "usage");
        if (!account.empty() && !usage.empty()) s_ur_usage[account] = {usage, firefox_json_string(json, "usage_updated"), false};
        s_ur_usage_after = ui_now_seconds() + 60;
        ur_set_status("");
        return;
    }
    if (s_ur_op == "remove" || s_ur_op == "logout") s_ur_usage.clear();
    if (s_ur_op == "login" || s_ur_op == "verify" || s_ur_op == "code-login") {
        s_ur_usage.clear(); s_ur_usage_after = 0;
        s_ur_verify = firefox_json_bool(json, "verification_required");
        if (s_ur_verify) {
            s_ur_add_close = true; s_ur_code_close = false; s_ur_code_prompt = true;
            ur_set_status(firefox_json_bool(json, "send_failed")
                ? "The verification email could not be sent. Close and retry sign-in."
                : "Enter the verification code sent to your email.");
            return;
        }
        s_ur_add_close = s_ur_code_close = true;
        s_ur_verify = false; ur_clear_secrets();
    }
    ur_snapshot(json);
    ur_set_status("Done.");
}
static void open_urnetwork_settings() { s_ur_open = true; s_ur_usage_after = 0; if (!s_ur_dirty) ur_submit("load"); }
static void render_urnetwork_settings() {
    ur_poll();
    if (s_ur_open) { ImGui::OpenPopup("URnetwork settings"); s_ur_open = false; s_ur_visible = true; }
    if (!s_ur_job) {
        if (s_ur_pending_signin) {
            const int pending = s_ur_pending_signin;
            s_ur_pending_signin = 0;
            const std::string email = ur_trimmed(s_ur_email);
            snprintf(s_ur_email, sizeof(s_ur_email), "%s", email.c_str());
            if (pending == 1)
                ur_submit("login", ",\"email\":\"" + firefox_json_escape(s_ur_email) + "\",\"password\":\"" + firefox_json_escape(s_ur_password) + "\"");
            else if (pending == 3)
                ur_submit("verify-send", ",\"email\":\"" + firefox_json_escape(s_ur_email) + "\"");
            else
                ur_submit("code-login", ",\"code\":\"" + firefox_json_escape(ur_auth_code(s_ur_code).c_str()) + "\"");
            ur_clear_secrets();
        } else if (s_ur_dirty && !s_ur_save_failed) {
            ur_submit("save", ",\"region\":\"" + firefox_json_escape(s_ur_region.c_str())
                + "\",\"transport\":\"" + s_ur_modes[s_ur_transport] + "\"");
            if (s_ur_job) s_ur_dirty = false;
        } else if (s_ur_visible && !s_ur_editing_account && s_ur_signed_in && !s_ur_verify && ui_now_seconds() >= s_ur_regions_after) {
            s_ur_regions_after = ui_now_seconds() + 300;
            ur_submit("regions");
        } else if (s_ur_visible && !s_ur_editing_account && s_ui_window_visible.load() && s_ur_signed_in && !s_ur_verify && ui_now_seconds() >= s_ur_usage_after) {
            s_ur_usage_after = ui_now_seconds() + 60;
            ur_submit("usage", ",\"account_id\":\"" + firefox_json_escape(s_ur_selected.c_str()) + "\"");
        }
    }
    if (s_ur_status_timer.expired(ur_requests_working(), s_ur_status_revision,
            !s_ur_status.empty(), ui_now_seconds())) {
        s_ur_status.clear();
        ui_request_redraw();
    }
    ImGui::SetNextWindowPos(viewport_center(), ImGuiCond_Always, ImVec2(.5f, .5f));
    ImGui::SetNextWindowSize(modal_size(640, 560), ImGuiCond_Always);
    if (!ImGui::BeginPopupModal("URnetwork settings", nullptr, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove)) {
        s_ur_visible = false;
        s_ur_code_visible = false;
        return;
    }
    ur_request_status();
    ImGui::BeginChild("##ur_scroll", ImVec2(0, -ImGui::GetFrameHeightWithSpacing() - 8));
    if (account_region_combo("urnetwork", s_ur_region, s_ur_regions)) { s_ur_dirty = true; s_ur_save_failed = false; }
    ImGui::TextUnformatted("Transport"); ImGui::SetNextItemWidth(-FLT_MIN);
    const char* labels[] = {"Auto", "HTTP/1.1 (H1)", "HTTP/3 (H3)", "DNS", "DNS pump"};
    if (ImGui::Combo("##ur_transport", &s_ur_transport, labels, 5)) { s_ur_dirty = true; s_ur_save_failed = false; }
    ImGui::SeparatorText("Accounts");
    if (s_ur_accounts.empty()) {
        ImGui::TextUnformatted("Don't have an account?");
        ImGui::SameLine();
        if (ImGui::TextLink("Create one")) open_link(kLinkUrSignup);
    }
    ImGui::BeginDisabled(s_ur_job != 0);
    for (const auto& account : s_ur_accounts) {
        ImGui::PushID(account.first.c_str());
        const bool selected = account.first == s_ur_selected;
        ImGui::TextWrapped("%s", account.second.empty() ? "URnetwork account" : account.second.c_str());
        const auto usage = s_ur_usage.find(account.first);
        if (usage != s_ur_usage.end() && !usage->second.text.empty()) {
            ImGui::TextDisabled("Usage: %s", usage->second.text.c_str());
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Total is the start-of-day balance; available data excludes open transfers.");
        } else if (selected) {
            ImGui::TextDisabled("%s", usage != s_ur_usage.end() && usage->second.refresh_failed
                ? "Usage: Unavailable" : "Usage: Loading…");
        }
        ImGui::BeginDisabled(selected);
        if (ImGui::SmallButton(selected ? "Selected" : "Use"))
            ur_submit("select", ",\"account_id\":\"" + firefox_json_escape(account.first.c_str()) + "\"");
        ImGui::EndDisabled();
        ImGui::SameLine();
        if (ImGui::SmallButton("Remove"))
            ur_submit("remove", ",\"account_id\":\"" + firefox_json_escape(account.first.c_str()) + "\"");
        ImGui::Separator();
        ImGui::PopID();
    }
    ImGui::EndDisabled();
    ImGui::BeginDisabled(s_ur_job && s_ur_op != "usage" && s_ur_op != "regions" && s_ur_op != "load");
    if (ImGui::Button("Add new account")) {
        ur_clear_secrets(); s_ur_email[0] = 0;
        s_ur_verify = false; s_ur_add_close = s_ur_code_close = false; s_ur_add = true; s_ur_editing_account = true;
        s_ur_use_code = false;
        ur_set_status("");
    }
    if (s_ur_verify) { ImGui::SameLine(); if (ImGui::Button("Continue verification")) s_ur_code_prompt = true; }
    ImGui::EndDisabled();
    ImGui::SeparatorText("Local listeners");
    listener_row("URnetwork SOCKS5", &g_app.ur_socks_enabled, &g_app.ur_socks_port, 1, 65535);
    listener_row("URnetwork HTTP", &g_app.ur_http_enabled, &g_app.ur_http_port, 1, 65535);
    backend_log_combo("URnetwork log level", 6, g_app.urnetwork_log);
    if (s_ur_save_failed && ImGui::Button("Retry saving settings")) s_ur_save_failed = false;
    ImGui::EndChild();
    // Closing the dialog does not cancel requests or discard queued autosaves.
    if (ImGui::Button("Close")) { s_ur_pending_signin = 0; s_ur_editing_account = false; ur_clear_secrets(); s_ur_visible = false; ImGui::CloseCurrentPopup(); }
    if (s_ur_add) { ImGui::OpenPopup("Add URnetwork account"); s_ur_add = false; }
    if (begin_account_dialog("Add URnetwork account", 520)) {
        if (s_ur_add_close) { s_ur_add_close = false; s_ur_editing_account = false; ImGui::CloseCurrentPopup(); }
        else {
            const bool busy = s_ur_job && s_ur_op != "usage" && s_ur_op != "regions" && s_ur_op != "load";
            ImGui::BeginDisabled(s_ur_pending_signin != 0);
            if (!s_ur_use_code) {
                // URnetwork accounts sign in with a one-time code sent by email;
                // a password is only for the accounts that still have one.
                const bool enter = account_identity_fields(s_ur_email, sizeof(s_ur_email),
                    s_ur_password, sizeof(s_ur_password), "Password (optional)");
                ImGui::PushTextWrapPos(0.0f);
                ImGui::TextDisabled("Leave the password empty to get a one-time code by email.");
                ImGui::PopTextWrapPos();
                const bool ready = !busy && s_ur_email[0];
                ImGui::BeginDisabled(!ready);
                const bool pressed = ImGui::Button(s_ur_password[0] ? "Sign in###ur_submit" : "Email me a code###ur_submit");
                ImGui::EndDisabled();
                if ((pressed || enter) && ready) { s_ur_pending_signin = s_ur_password[0] ? 1 : 3; ui_request_redraw(); }
            } else {
                ImGui::TextWrapped("Create a code in your URnetwork account settings and paste it here. A code works once and expires within minutes.");
                ImGui::SetNextItemWidth(-FLT_MIN);
                const bool enter = UiText::InputTextWithHint("##auth_code", "Authorization code", s_ur_code, sizeof(s_ur_code),
                    ImGuiInputTextFlags_Password | ImGuiInputTextFlags_EnterReturnsTrue);
                const bool ready = !busy && !ur_auth_code(s_ur_code).empty();
                ImGui::BeginDisabled(!ready);
                const bool pressed = ImGui::Button("Sign in with code");
                ImGui::EndDisabled();
                if ((pressed || enter) && ready) { s_ur_pending_signin = 2; ui_request_redraw(); }
                button_row_next("Get a code");
                if (secondary_button("Get a code")) open_link(kLinkUrAuthCode);
            }
            ImGui::EndDisabled();
            button_row_next("Cancel");
            if (secondary_button("Cancel")) { s_ur_pending_signin = 0; s_ur_editing_account = false; ur_clear_secrets(); ImGui::CloseCurrentPopup(); }
            ur_request_status();
            ImGui::Separator();
            if (ImGui::TextLink(s_ur_use_code ? "Use email instead" : "Use an authorization code instead")) {
                s_ur_use_code = !s_ur_use_code;
                ur_clear_secrets();
            }
        }
        ImGui::EndPopup();
    }
    if (s_ur_code_prompt) { ImGui::OpenPopup("URnetwork account security code"); s_ur_code_prompt = false; }
    s_ur_code_visible = false;
    if (begin_account_dialog("URnetwork account security code", 500)) {
        if (s_ur_code_close) { s_ur_code_close = false; ImGui::CloseCurrentPopup(); }
        else {
            s_ur_code_visible = true;
            ImGui::TextWrapped("Enter the code URnetwork emailed to %s.", s_ur_email);
            ImGui::SetNextItemWidth(-FLT_MIN);
            const bool enter = UiText::InputTextWithHint("##verification", "Verification code", s_ur_code, sizeof(s_ur_code),
                ImGuiInputTextFlags_EnterReturnsTrue);
            const bool ready = s_ur_job == 0 && !ur_trimmed(s_ur_code).empty();
            ImGui::BeginDisabled(!ready);
            const bool pressed = ImGui::Button("Verify");
            ImGui::EndDisabled();
            if ((pressed || enter) && ready) {
                ur_submit("verify", ",\"email\":\"" + firefox_json_escape(s_ur_email) + "\",\"code\":\"" + firefox_json_escape(ur_trimmed(s_ur_code).c_str()) + "\"");
                ur_clear_secrets();
            }
            // A code that never arrived should not send the user back to the start.
            button_row_next("Resend code");
            ImGui::BeginDisabled(s_ur_job != 0 || !s_ur_email[0]);
            if (secondary_button("Resend code"))
                ur_submit("verify-send", ",\"email\":\"" + firefox_json_escape(s_ur_email) + "\"");
            ImGui::EndDisabled();
            button_row_next("Later");
            if (secondary_button("Later")) { ur_clear_secrets(); ImGui::CloseCurrentPopup(); }
            ur_request_status();
        }
        ImGui::EndPopup();
    }
    ImGui::EndPopup();
}

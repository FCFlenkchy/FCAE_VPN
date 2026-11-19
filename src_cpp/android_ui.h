#pragma once
#include <string>
#include "fcae.h"

const std::string& android_ui_data_dir();
FcaeStatus android_ui_initialize_runtime();
void android_ui_command(const char* action, const std::string& payload = {});
void android_ui_save_session(bool connect);
void android_ui_telemetry(FcaeTelemetry& telemetry);
bool android_ui_paused();

void android_ui_flush_settings();

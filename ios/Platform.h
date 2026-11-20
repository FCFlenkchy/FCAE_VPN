#pragma once
#include "fcae.h"
#include <string>
const std::string& ios_data_dir();
bool ios_open_url(const char*);
FcaeStatus ios_start(const FcaeConfig*);
FcaeStatus ios_stop();
FcaeStatus ios_telemetry(FcaeTelemetry*);
bool ios_tun_paused();
FcaeStatus ios_tun_control();
extern "C" uint32_t ios_live_listeners(char*, uint32_t);
uint32_t ios_regions(char*, uint32_t);
void ios_flush_settings();

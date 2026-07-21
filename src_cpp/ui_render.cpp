#include "ui_render.h"

void ui_init() {
    aether_init(log_callback, nullptr);
}

void ui_shutdown() {
    aether_stop();
    aether_free();
}

void ui_frame() {
    render_ui();
}

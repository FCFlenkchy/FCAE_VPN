//go:build ios && with_naive_outbound && !with_purego

// The pinned Cronet iOS archive calls this Chromium feature initializer but
// omits its definition. Upstream only caches TimerSlackMac (default false):
// https://github.com/chromium/chromium/blob/main/base/message_loop/message_pump_kqueue.cc
// Retain that default, not a replacement networking/message-pump implementation.
// Weak linkage lets a corrected archive supply the real implementation.
void fcae_cronet_kqueue_features(void)
    __asm__("__ZN4base17MessagePumpKqueue18InitializeFeaturesEv")
    __attribute__((weak));
void fcae_cronet_kqueue_features(void) {}

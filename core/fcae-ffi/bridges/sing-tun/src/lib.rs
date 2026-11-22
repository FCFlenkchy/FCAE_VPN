//! MetaCubeX/sing-tun packet engine in the app's shared Go runtime.
use fcae_runtime::proxy_cores::CoreFfi;
use std::ffi::{c_char, c_int};
unsafe extern "C" {
    fn mtun_start(config: *const c_char, handle: *mut u64) -> *mut c_char;
    fn mtun_stop(handle: u64);
    fn mtun_stop_all();
    fn mtun_running(handle: u64) -> c_int;
    fn mtun_string_free(message: *mut c_char);
}
unsafe extern "C" fn stats(_: u64, _: *mut i64, _: *mut i64) -> c_int {
    0
}
unsafe extern "C" fn set_log(_: Option<unsafe extern "C" fn(c_int, *const c_char)>, _: c_int) {}
unsafe extern "C" fn listeners(_: *mut c_char, _: c_int) -> c_int {
    0
}
pub fn tun_ffi() -> CoreFfi {
    CoreFfi {
        start: mtun_start,
        stop: mtun_stop,
        stop_all: mtun_stop_all,
        running: mtun_running,
        string_free: mtun_string_free,
        stats,
        set_log,
        listeners,
    }
}

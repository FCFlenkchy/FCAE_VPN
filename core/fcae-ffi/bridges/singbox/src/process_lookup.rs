use std::ffi::c_char;

// The packet engine calls this Rust-owned lookup through a synchronous C ABI.
pub(super) type Callback = Option<
    unsafe extern "C" fn(u32, *const c_char, u16, *const c_char, u16, *mut c_char, u32) -> i64,
>;
pub(super) unsafe extern "C" fn lookup(
    protocol: u32,
    source: *const c_char,
    source_port: u16,
    destination: *const c_char,
    destination_port: u16,
    out: *mut c_char,
    capacity: u32,
) -> i64 {
    std::panic::catch_unwind(|| {
        if source.is_null() || destination.is_null() || out.is_null() || capacity == 0 {
            return -1;
        }
        *out = 0;
        let parse = |text: *const c_char| {
            std::ffi::CStr::from_ptr(text)
                .to_str()
                .ok()?
                .parse::<std::net::IpAddr>()
                .ok()
        };
        let (Some(source), Some(destination)) = (parse(source), parse(destination)) else {
            return -1;
        };
        let Some(owner) = fcae_runtime::process_lookup::lookup(
            protocol,
            std::net::SocketAddr::new(source, source_port),
            std::net::SocketAddr::new(destination, destination_port),
        ) else {
            return -1;
        };
        if owner.path.len() >= capacity as usize {
            return -1;
        }
        std::ptr::copy_nonoverlapping(owner.path.as_ptr(), out.cast(), owner.path.len());
        *out.add(owner.path.len()) = 0;
        owner.pid as i64
    })
    .unwrap_or(-1)
}

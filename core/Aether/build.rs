// Build script for aether-engine.
//
// Deliberately empty.
//
// This used to be ~550 lines that cross-compiled the tun2socks Go binary,
// embedded it into the library and downloaded wintun.dll, so the engine could
// spawn tun2socks as a CHILD PROCESS at runtime.
//
// None of that belongs here any more. TUN is owned entirely by
// core/fcae-ffi/bridges/tun2socks, which links tun2socks IN-PROCESS (a Go
// c-archive on desktop, c-shared on Android) and receives the Android
// VpnService fd through fcae_set_tun_fd(). The engine is driven in proxy mode
// and never touches a TUN device, so it needs no Go toolchain, no embedded
// binary and no wintun.dll.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
}

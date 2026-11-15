//! Stages the native libraries the runtime embeds for Windows: the one copy of
//! `wintun.dll` the TUN bridges share, and `libcronet.dll`, which sing-box's
//! naive outbound loads at run time.

fn main() {
    println!("cargo::rustc-check-cfg=cfg(wintun_staged)");
    println!("cargo::rustc-check-cfg=cfg(cronet_staged)");
    let target = fcae_build::target::Target::from_cargo_env();
    fcae_build::wintun::stage_and_emit(target, "FCAE_WINTUN_DLL");
    fcae_build::cronet::stage_and_emit(target, "FCAE_CRONET_DLL");
}

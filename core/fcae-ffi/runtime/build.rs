//! Stages the one copy of `wintun.dll` the runtime embeds for the Windows
//! TUN bridges (which therefore embed nothing themselves).

fn main() {
    println!("cargo::rustc-check-cfg=cfg(wintun_staged)");
    let target = fcae_build::target::Target::from_cargo_env();
    fcae_build::wintun::stage_and_emit(target, "FCAE_WINTUN_DLL");
}

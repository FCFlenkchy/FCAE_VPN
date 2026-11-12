//! Select the linked desktop Psiphon bridge. Android uses the host service and combined Go library.
fn main() {
    println!("cargo::rustc-check-cfg=cfg(psiphon_linked)");
    if cfg!(feature = "enabled") && std::env::var("CARGO_CFG_TARGET_OS").ok().as_deref() != Some("android") {
        println!("cargo:rustc-cfg=psiphon_linked");
    }
}

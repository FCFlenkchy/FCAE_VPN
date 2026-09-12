//! Builds Psiphon's ClientLibrary as a c-archive and links it statically.
//!
//! Unlike tun2socks, Psiphon **already ships a cgo C ABI**
//! (`ClientLibrary/PsiphonTunnel.go` exports `PsiphonTunnelStart` and
//! `PsiphonTunnelStop`), so there is no hand-written Go shim here — we build
//! the upstream package directly. That is less code to maintain and nothing
//! to rebase when the submodule is bumped.

fn main() {
    println!("cargo::rustc-check-cfg=cfg(psiphon_linked)");
    fcae_build::rerun_if_env_changed("ANDROID_NDK_HOME");
    fcae_build::rerun_if_env_changed("CGO_CC");
    fcae_build::rerun_if_env_changed("GO_BIN");

    if !cfg!(feature = "enabled") {
        return;
    }

    let submodule = fcae_build::repo_root().join("core/psiphon");
    if !submodule.join("go.mod").is_file() {
        panic!(
            "the `enabled` feature is on but the Psiphon submodule is missing at {}.\n\
             Run: git submodule update --init --recursive",
            submodule.display()
        );
    }

    let client_library = submodule.join("ClientLibrary");
    if !client_library.join("PsiphonTunnel.go").is_file() {
        panic!(
            "{} does not contain PsiphonTunnel.go — the upstream layout changed",
            client_library.display()
        );
    }

    let target = fcae_build::target::Target::from_cargo_env();
    let repo_root = fcae_build::repo_root();

    fcae_build::rerun_if_changed(submodule.join("go.mod"));
    fcae_build::go::track_sources(&client_library);

    // The module root is the submodule itself; the package we want is the
    // ClientLibrary subdirectory (it is `package main` with //export
    // directives, which is exactly what c-archive mode needs).
    let mut archive =
        fcae_build::go::CArchive::new(&submodule, "./ClientLibrary", "libpsiphon_bridge");
    archive.target = target;

    match archive.build() {
        Ok(built) => {
            if let Err(e) = built.stage_android_so(&repo_root, target) {
                panic!("failed to stage the Psiphon bridge for Android: {e}");
            }
            built.emit_link_directives("libpsiphon_bridge", target);
            println!("cargo:rustc-cfg=psiphon_linked");
            println!(
                "cargo:rustc-env=FCAE_PSIPHON_HEADER={}",
                built.header.display()
            );
            fcae_build::note("psiphon ClientLibrary linked in-process");
        }
        Err(e) => panic!(
            "failed to build the Psiphon ClientLibrary c-archive: {e}\n\
             Psiphon requires a recent Go toolchain (see core/psiphon/go.mod) \
             and a C toolchain for the target.\n\
             Build without `--features fcae-bridge-psiphon/enabled` to skip it."
        ),
    }
}

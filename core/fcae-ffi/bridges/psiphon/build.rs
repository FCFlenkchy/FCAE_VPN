//! Builds the Psiphon Go bridge as a c-archive and links it statically.
//!
//! ## Why a hand-written shim now
//!
//! The first version compiled upstream's `ClientLibrary` package directly,
//! because it already exports a cgo C ABI. That cannot work on Android: its
//! `PsiphonProvider` has no `BindToDevice`, so Psiphon's own sockets get
//! captured by our TUN and the tunnel tries to reach the internet through
//! itself.
//!
//! `MobileLibrary/psi` does expose `BindToDevice`, but it is a gobind package
//! with no C surface, so `go/bridge.go` wraps it. One shim serves both
//! platforms — desktop simply passes `useDeviceBinder=false`.

use std::path::PathBuf;

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

    // The shim imports MobileLibrary/psi, so fail early and clearly if the
    // submodule layout ever changes under us.
    let mobile_library = submodule.join("MobileLibrary/psi");
    if !mobile_library.join("psi.go").is_file() {
        panic!(
            "{} does not contain psi.go — the upstream layout changed",
            mobile_library.display()
        );
    }

    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let go_dir = manifest.join("go");
    let target = fcae_build::target::Target::from_cargo_env();
    let repo_root = fcae_build::repo_root();

    fcae_build::go::track_sources(&go_dir);
    fcae_build::rerun_if_changed(submodule.join("go.mod"));

    let mut archive = fcae_build::go::CArchive::new(&go_dir, ".", "libpsiphon_bridge");
    archive.target = target;

    // Required by an in-proxy dependency: github.com/wlynxg/anet does
    //
    //     //go:linkname zoneCache net.zoneCache
    //
    // a pull-style linkname into a private stdlib variable. Go 1.23 started
    // rejecting those at link time with "invalid reference to net.zoneCache",
    // so the build fails once it reaches the linker. Upstream hits exactly
    // this and disables the check the same way -- see the -checklinkname=0 in
    // core/psiphon/MobileLibrary/Android/make.bash.
    archive.ldflags.push("-checklinkname=0".into());

    // Build dynamic everywhere, not just on Android.
    //
    // Only ONE Go c-archive can be statically linked into a binary: each
    // embeds a complete Go runtime, so a second one redefines
    // _cgo_topofstack, crosscall2, _cgo_panic and the rest, and the link dies
    // in duplicate symbols. tun2socks keeps the static slot because it is
    // always present; Psiphon is optional, so it takes the dynamic one.
    // Android already did this for both bridges, which is why only the
    // desktop targets ever hit the clash.
    archive.force_shared = true;

    match archive.build() {
        Ok(built) => {
            // Android builds a c-shared .so (Go rejects c-archive there), so
            // it has to land in jniLibs/<abi>/ for the loader. No-op elsewhere.
            if let Err(e) = built.stage_android_so(&repo_root, target) {
                panic!("failed to stage the Psiphon bridge for Android: {e}");
            }
            // Desktop: put the shared library beside the Rust artifacts so
            // CMake can find it and copy it next to the executable.
            if let Err(e) = built.stage_desktop_shared(target) {
                panic!("failed to stage the Psiphon bridge: {e}");
            }
            built.emit_link_directives("libpsiphon_bridge", target);
            println!("cargo:rustc-cfg=psiphon_linked");
            println!(
                "cargo:rustc-env=FCAE_PSIPHON_HEADER={}",
                built.header.display()
            );
            // "MobileLibrary" is just upstream's package name -- psi.go
            // carries no build tags and imports nothing platform-specific,
            // so it compiles for desktop too. We use it everywhere because
            // it is the only variant exposing BindToDevice, which Android
            // needs; desktop passes useDeviceBinder=false and ignores it.
            fcae_build::note(
                "psiphon linked in-process (upstream MobileLibrary/psi, portable Go)",
            );
        }
        Err(e) => panic!(
            "failed to build the Psiphon bridge c-archive: {e}\n\
             Psiphon requires a recent Go toolchain (see core/psiphon/go.mod) \
             and a C toolchain for the target.\n\
             Build without `--features psiphon-live` to skip it."
        ),
    }
}

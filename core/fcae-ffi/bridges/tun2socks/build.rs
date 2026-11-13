//! Builds the tun2socks Go bridge as a c-archive and links it statically.
//!
//! All the heavy lifting lives in `fcae-build`; this stays readable.

use std::path::PathBuf;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(tun2socks_linked)");
    fcae_build::rerun_if_env_changed("ANDROID_NDK_HOME");
    fcae_build::rerun_if_env_changed("CGO_CC");
    fcae_build::rerun_if_env_changed("GO_BIN");

    let target = fcae_build::target::Target::from_cargo_env();

    if cfg!(feature = "stub") {
        if cfg!(feature = "psiphon") {
            panic!("desktop Psiphon requires the live tun2socks Go archive");
        }
        fcae_build::note("fcae-go-bridge: `stub` feature enabled — Go bridge NOT built");
        return;
    }

    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let go_dir = manifest.join("go");
    let submodule = fcae_build::repo_root().join("core/tun2socks");

    if !submodule.join("go.mod").is_file() {
        panic!(
            "tun2socks submodule missing at {}.\n\
             Run: git submodule update --init --recursive",
            submodule.display()
        );
    }

    fcae_build::go::track_sources(&go_dir);
    fcae_build::rerun_if_changed(submodule.join("go.mod"));

    // Build both shims as one Go package when Psiphon is enabled.
    let combined_dir;
    let build_dir = if cfg!(feature = "psiphon") {
        let root = fcae_build::repo_root();
        let psi_go = root.join("core/fcae-ffi/bridges/psiphon/go");
        let psiphon = root.join("core/psiphon");
        if !psiphon.join("go.mod").is_file() {
            panic!("psiphon submodule missing at {}", psiphon.display());
        }
        fcae_build::go::track_sources(&psi_go);
        fcae_build::rerun_if_changed(psiphon.join("go.mod"));
        combined_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"))
            .join("combined-go");
        std::fs::create_dir_all(&combined_dir).expect("create combined Go module");
        std::fs::copy(go_dir.join("bridge.go"), combined_dir.join("bridge.go"))
            .expect("copy tun2socks bridge");
        let psi = std::fs::read_to_string(psi_go.join("bridge.go"))
            .expect("read Psiphon bridge");
        let main = "// c-archive / c-shared require a main package.\nfunc main() {}";
        assert_eq!(psi.matches(main).count(), 1, "unexpected Psiphon bridge main");
        std::fs::write(combined_dir.join("psiphon.go"), psi.replace(main, ""))
            .expect("copy Psiphon bridge");
        let original = std::fs::read_to_string(go_dir.join("go.mod"))
            .expect("read tun2socks module");
        let local = |path: &std::path::Path| {
            assert!(path.is_absolute() && path.is_dir(), "missing Go module: {}", path.display());
            let path = path.to_str().expect("Go module path must be UTF-8").replace('\\', "/");
            format!("{:?}", path)
        };
        let manifest = original.replace("../../../../tun2socks", &local(&submodule));
        let manifest = format!(
            "{manifest}\nrequire github.com/Psiphon-Labs/psiphon-tunnel-core v0.0.0\n\
             replace github.com/Psiphon-Labs/psiphon-tunnel-core => {}\n\
             replace github.com/pion/dtls/v2 => {}\n\
             replace gitlab.com/yawning/obfs4.git => github.com/jmwample/obfs4 v0.0.0-20230725223418-2d2e5b4a16ba\n",
            local(&psiphon), local(&psiphon.join("replace/dtls"))
        );
        std::fs::write(combined_dir.join("go.mod"), manifest).expect("write combined Go module");
        // Regenerate after changing inputs; generated sums must not outlive the
        // manifest they describe in Cargo's reused OUT_DIR.
        let _ = std::fs::remove_file(combined_dir.join("go.sum"));
        combined_dir.as_path()
    } else {
        go_dir.as_path()
    };
    let mut archive = fcae_build::go::CArchive::new(build_dir, ".", "libfcae_go_bridge");
    archive.target = target;
    if target.is_android() && cfg!(feature = "psiphon") {
        // Psiphon's anet dependency links to Go's internal net.zoneCache on
        // Android. This upstream-required flag applies to the whole Go .so.
        archive.ldflags.push("-checklinkname=0".into());
    }

    match archive.build() {
        Ok(built) => {
            // Android builds a c-shared .so (Go rejects c-archive there), so
            // it has to land in jniLibs/<abi>/ for the loader. No-op elsewhere.
            if let Err(e) = built.stage_android_so(&fcae_build::repo_root(), target) {
                panic!("failed to stage the tun2socks bridge for Android: {e}");
            }
            built.emit_link_directives("libfcae_go_bridge", target);
            println!("cargo:rustc-cfg=tun2socks_linked");
            println!(
                "cargo:rustc-env=FCAE_TUN2SOCKS_HEADER={}",
                built.header.display()
            );
            fcae_build::note("tun2socks linked in-process (no subprocess, no embedded binary)");
        }
        Err(e) => panic!(
            "failed to build the in-process tun2socks bridge: {e}\n\
             Install Go (toolchain auto via GOTOOLCHAIN=auto from go.mod) and a C \
             toolchain for the target, or build with \
             `--features fcae-go-bridge/stub` to skip TUN support."
        ),
    }
}

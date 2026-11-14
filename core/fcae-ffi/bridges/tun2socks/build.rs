//! Builds the app's single in-process Go archive.
//!
//! Every Go engine FCAE links — tun2socks, Psiphon, Xray-core, sing-box — is
//! compiled here as one package into one `libfcae_go_bridge.a` (`c-shared` on
//! Android). A Go program carries exactly one runtime, so it also carries
//! exactly one dependency graph: separate archives would collide on runtime
//! symbols and force independent copies of every shared dependency.
//!
//! The module graph is unified by ordinary MVS, and it does unify: the gVisor
//! this repo pins (via `core/tun2socks`) is the newest of the three, Xray-core's
//! symbols are a subset of it, and `github.com/sagernet/sing` resolves to
//! sing-box's version, whose API Xray-core still uses unchanged. sing-box's own
//! gVisor/QUIC forks are distinct module paths, so they sit beside the others
//! rather than competing with them.
//!
//! One shared dependency cannot be resolved that way: every quic-go fork imports
//! `github.com/quic-go/qpack`, but Psiphon's fork predates qpack 0.6's API and
//! sing-box's and Xray-core's forks require it. `core/fcae-ffi/gomods/qpack` is
//! that one version with both API generations, and it is `replace`d in whenever
//! Psiphon is built next to either of them.
//!
//! Each core's shim lives with its own bridge crate and is copied in here, so
//! ownership stays per-core while the output is one package. Cargo features
//! decide what is copied and which Go build tags are set; a build without the
//! `xray` feature links no Xray-core code at all.
//!
//! All the heavy lifting lives in `fcae-build`; this stays readable.

use std::path::{Path, PathBuf};

fn main() {
    println!("cargo::rustc-check-cfg=cfg(tun2socks_linked)");
    fcae_build::rerun_if_env_changed("ANDROID_NDK_HOME");
    fcae_build::rerun_if_env_changed("CGO_CC");
    fcae_build::rerun_if_env_changed("GO_BIN");
    // `go.rs` reads this to decide whether to refresh the module graph.
    fcae_build::rerun_if_env_changed("FCAE_GO_TIDY");

    let target = fcae_build::target::Target::from_cargo_env();

    let psiphon = cfg!(feature = "psiphon");
    let xray = cfg!(feature = "xray");
    let singbox = cfg!(feature = "singbox");

    if cfg!(feature = "stub") {
        // The archive is what exports these symbols; a stub build that also
        // asks for a core would fail at link time with an unhelpful message.
        if psiphon || xray || singbox {
            panic!(
                "a proxy core needs the live Go archive, but `fcae-go-bridge/stub` is enabled; \
                 drop `stub`, or drop the core that needs it"
            );
        }
        fcae_build::note("fcae-go-bridge: `stub` feature enabled — Go bridge NOT built");
        return;
    }

    // sing-box's naive outbound links cronet-go's prebuilt Chromium objects,
    // which carry AArch64 GOTPCREL32 relocations (0x13b). lld learned them in
    // LLVM 18.1, which no release of NDK r27 ships: there the link dies with
    // "unknown relocation (315)", naming neither the object nor the reason.
    // r28 is the floor; CI provisions r30.
    if singbox && target.is_android() {
        if let Some(major) = fcae_build::go::ndk_revision() {
            assert!(
                major >= 28,
                "the Android NDK in use is r{major}, but sing-box's naive outbound needs r28 or \
                 newer: its prebuilt cronet objects use relocations that lld r{major} rejects. \
                 Point ANDROID_NDK_HOME at NDK r30 (what CI provisions) or r28+."
            );
        }
    }

    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let go_dir = manifest.join("go");
    let root = fcae_build::repo_root();
    let submodule = root.join("core/tun2socks");

    if !submodule.join("go.mod").is_file() {
        panic!(
            "tun2socks submodule missing at {}.\n\
             Run: git submodule update --init --recursive",
            submodule.display()
        );
    }

    fcae_build::go::track_sources(&go_dir);
    fcae_build::rerun_if_changed(submodule.join("go.mod"));

    let module = assemble(&root, &go_dir, &submodule, psiphon, xray, singbox);

    let mut archive = fcae_build::go::CArchive::new(&module, ".", "libfcae_go_bridge");
    archive.target = target;
    if xray {
        archive.tags.push("fcae_xray".into());
    }
    if singbox {
        archive.tags.push("fcae_singbox".into());
        // The full upstream feature set: every protocol, transport, endpoint and
        // service an official sing-box binary carries, so a native config is
        // accepted here exactly as the `sing-box` CLI accepts it. These are the
        // tags from sing-box's own library build (`cmd/internal/build_libbox`),
        // plus the ones only its CLI build sets.
        archive.tags.extend(
            [
                "with_gvisor",
                "with_quic",
                "with_dhcp",
                "with_wireguard",
                "with_utls",
                "with_naive_outbound",
                "with_acme",
                "with_clash_api",
                "with_cloudflared",
                "with_ccm",
                "with_ocm",
                "with_usbip",
                "with_openvpn",
                "with_openconnect",
                // Tailscale, trimmed to what an embedded core can use: no SSH,
                // drive, web UI, log uploader or cloud integrations.
                "with_tailscale",
                "ts_omit_logtail",
                "ts_omit_ssh",
                "ts_omit_drive",
                "ts_omit_taildrop",
                "ts_omit_webclient",
                "ts_omit_doctor",
                "ts_omit_capture",
                "ts_omit_kube",
                "ts_omit_aws",
                "ts_omit_synology",
                "ts_omit_bird",
                // An embedded core needs no gRPC tracing; this also drops
                // `golang.org/x/net/trace` from the archive.
                "grpcnotrace",
                // kTLS, the oom-killer's cache cleanup and HTTP/2 force-close
                // reach into stdlib internals with `go:linkname`; upstream ships
                // both tags, and both need the linker check disabled below.
                "badlinkname",
                "tfogo_checklinkname0",
            ]
            .map(str::to_string),
        );
        // `with_naive_outbound` is a cgo dependency on most platforms, but its
        // Windows half is published gated on `with_purego` only: without the
        // tag the package has no buildable files at all. Upstream's Windows tag
        // set carries it for the same reason.
        if target.is_windows() {
            archive.tags.push("with_purego".into());
        }
    }
    // `go:linkname` into packages Go does not own is refused at link time unless
    // this check is off. Two things here need it, and it applies to the whole
    // archive: sing-box's `badlinkname`/`tfogo_checklinkname0` (which upstream
    // ships, and sets the same flag for), and Psiphon's anet dependency linking
    // to Go's internal net.zoneCache on Android.
    if singbox || (target.is_android() && psiphon) {
        archive.ldflags.push("-checklinkname=0".into());
    }
    if singbox {
        // The rest of sing-box's own release linker state: its version string
        // (what the Clash API and outbound user-agents report) and the two Go
        // runtime toggles upstream pins — SHA-1 certificate signatures stay
        // accepted, which Go rejects by default and older servers still need,
        // and MPTCP stays off.
        archive
            .ldflags
            .push(format!("-X github.com/sagernet/sing-box/constant.Version={SING_BOX}"));
        archive
            .ldflags
            .push("-X runtime.godebugDefault=multipathtcp=0,tlssha1=1".into());
    }

    match archive.build() {
        Ok(built) => {
            // Android builds a c-shared .so (Go rejects c-archive there), so
            // it has to land in jniLibs/<abi>/ for the loader. No-op elsewhere.
            if let Err(e) = built.stage_android_so(&root, target) {
                panic!("failed to stage the Go bridge for Android: {e}");
            }
            built.emit_link_directives("libfcae_go_bridge", target);
            println!("cargo:rustc-cfg=tun2socks_linked");
            println!(
                "cargo:rustc-env=FCAE_TUN2SOCKS_HEADER={}",
                built.header.display()
            );
            fcae_build::note(format!(
                "one Go archive built in-process (tun2socks{}, no subprocess, no embedded binary)",
                cores(psiphon, xray, singbox)
            ));
        }
        Err(e) => panic!(
            "failed to build the in-process Go bridge: {e}\n\
             Install Go (toolchain auto via GOTOOLCHAIN=auto from go.mod) and a C \
             toolchain for the target, or build with \
             `--features fcae-go-bridge/stub` to skip the Go engines."
        ),
    }
}

fn cores(psiphon: bool, xray: bool, singbox: bool) -> String {
    let mut names = Vec::new();
    if psiphon {
        names.push("psiphon");
    }
    if xray {
        names.push("xray-core");
    }
    if singbox {
        names.push("sing-box");
    }
    if names.is_empty() {
        String::new()
    } else {
        format!(" + {}", names.join(" + "))
    }
}

/// Lay out the generated module: this crate's own Go sources, the shim of every
/// enabled core, and a `go.mod` whose module graph covers all of them.
///
/// Generated even when nothing is added, because the `replace` for the tun2socks
/// submodule is relative to this crate's directory and has to be rewritten to an
/// absolute path before the build runs from a different directory.
fn assemble(
    root: &Path,
    go_dir: &Path,
    submodule: &Path,
    psiphon: bool,
    xray: bool,
    singbox: bool,
) -> PathBuf {
    let module = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR")).join("go-bridge");
    std::fs::create_dir_all(&module).expect("create the Go bridge module");
    copy(&go_dir.join("bridge.go"), &module.join("bridge.go"));

    // Psiphon's shim still owns the package's single `main`, so it is stripped
    // here: two mains in one package do not compile, and tun2socks's stays.
    if psiphon {
        let psi_go = root.join("core/fcae-ffi/bridges/psiphon/go");
        let psiphon_src = root.join("core/psiphon");
        if !psiphon_src.join("go.mod").is_file() {
            panic!("psiphon submodule missing at {}", psiphon_src.display());
        }
        fcae_build::go::track_sources(&psi_go);
        fcae_build::rerun_if_changed(psiphon_src.join("go.mod"));
        let source = std::fs::read_to_string(psi_go.join("bridge.go")).expect("read Psiphon shim");
        let main = "// c-archive / c-shared require a main package.\nfunc main() {}";
        assert_eq!(source.matches(main).count(), 1, "unexpected Psiphon bridge main");
        std::fs::write(module.join("psiphon.go"), source.replace(main, ""))
            .expect("copy the Psiphon shim");
    }
    for (enabled, dir, name) in [
        (xray, "xray", "xray.go"),
        (singbox, "singbox", "singbox.go"),
    ] {
        if !enabled {
            continue;
        }
        let shim = root.join("core/fcae-ffi/bridges").join(dir).join("go/bridge.go");
        fcae_build::go::track_sources(shim.parent().expect("shim directory"));
        copy(&shim, &module.join(name));
    }

    let local = |path: &Path| {
        assert!(
            path.is_absolute() && path.is_dir(),
            "missing Go module: {}",
            path.display()
        );
        let path = path
            .to_str()
            .expect("Go module path must be UTF-8")
            .replace('\\', "/");
        format!("{path:?}")
    };

    let base = std::fs::read_to_string(go_dir.join("go.mod")).expect("read the bridge module");
    let mut manifest = base.replace("../../../../tun2socks", &local(submodule));
    if psiphon {
        let psiphon_src = root.join("core/psiphon");
        manifest.push_str(&format!(
            "\nrequire github.com/Psiphon-Labs/psiphon-tunnel-core v0.0.0\n\
             replace github.com/Psiphon-Labs/psiphon-tunnel-core => {}\n\
             replace github.com/pion/dtls/v2 => {}\n\
             replace gitlab.com/yawning/obfs4.git => github.com/jmwample/obfs4 v0.0.0-20230725223418-2d2e5b4a16ba\n",
            local(&psiphon_src),
            local(&psiphon_src.join("replace/dtls"))
        ));
    }
    if xray {
        manifest.push_str(&format!(
            "\nrequire github.com/xtls/xray-core {XRAY}\n"
        ));
    }
    if singbox {
        manifest.push_str(&format!(
            "\nrequire github.com/sagernet/sing-box {SING_BOX}\n"
        ));
    }
    // Psiphon's quic-go fork decodes with qpack's pre-0.6 API; sing-box's and
    // Xray-core's forks require 0.6. MVS would hand all three 0.6.0, which
    // Psiphon's fork does not compile against, so the override in `gomods/qpack`
    // (0.6.0 plus the two pre-0.6 entry points) stands in for it.
    if psiphon && (xray || singbox) {
        let qpack = root.join("core/fcae-ffi/gomods/qpack");
        fcae_build::go::track_sources(&qpack);
        manifest.push_str(&format!(
            "\nreplace github.com/quic-go/qpack => {}\n",
            local(&qpack)
        ));
    }
    std::fs::write(module.join("go.mod"), manifest).expect("write the Go bridge module");
    // Regenerate after changing inputs; sums must not outlive the manifest they
    // describe in Cargo's reused OUT_DIR.
    let _ = std::fs::remove_file(module.join("go.sum"));
    module
}

/// Versions the generators target. Bump here, in the README and in the shims'
/// comments together.
const XRAY: &str = "v1.260327.0";
const SING_BOX: &str = "v1.14.4";

fn copy(from: &Path, to: &Path) {
    std::fs::copy(from, to)
        .unwrap_or_else(|e| panic!("copy {} -> {}: {e}", from.display(), to.display()));
}

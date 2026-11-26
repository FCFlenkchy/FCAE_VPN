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
    for key in [
        "SDKROOT",
        "DEVELOPER_DIR",
        "IPHONEOS_DEPLOYMENT_TARGET",
        "CGO_CFLAGS",
        "CGO_CPPFLAGS",
        "CGO_CXXFLAGS",
        "CGO_LDFLAGS",
    ] {
        fcae_build::rerun_if_env_changed(key);
    }
    // `go.rs` reads this to decide whether to refresh the module graph.
    fcae_build::rerun_if_env_changed("FCAE_GO_TIDY");

    let target = fcae_build::target::Target::from_cargo_env();

    let psiphon = cfg!(feature = "psiphon");
    let xray = cfg!(feature = "xray");
    let singbox = cfg!(feature = "singbox");
    let mihomo = cfg!(feature = "mihomo");

    if cfg!(feature = "stub") {
        // The archive is what exports these symbols; a stub build that also
        // asks for a core would fail at link time with an unhelpful message.
        if psiphon
            || xray
            || singbox
            || mihomo
            || cfg!(feature = "sing-tun")
            || cfg!(feature = "urnetwork")
        {
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

    let module = assemble(&root, &go_dir, &submodule, psiphon, xray, singbox, mihomo);

    let mut archive = fcae_build::go::CArchive::new(&module, ".", "libfcae_go_bridge");
    archive.target = target;
    if cfg!(feature = "urnetwork") {
        archive.tags.push("fcae_urnetwork".into());
    }
    if mihomo {
        archive.tags.push("fcae_mihomo".into());
        // Native mobile-host mode: VpnService already owns package selection;
        // do not read Android's root-only package database from the TUN core.
        if archive.target.is_android() {
            archive.tags.push("cmfa".into());
        }
        archive.tags.push("with_gvisor".into());
        archive
            .ldflags
            .push("-X github.com/metacubex/mihomo/constant.Version=embedded".into());
    }
    if cfg!(feature = "sing-tun") {
        archive.tags.push("fcae_sing_tun".into());
        archive.tags.push("with_gvisor".into());
    }
    if xray {
        archive.tags.push("fcae_xray".into());
    }
    if singbox {
        archive.tags.push("fcae_singbox".into());
        // Upstream's Apple libbox profile supports the same embedded protocols.
        // Keep one feature list so mobile does not silently lose endpoints.
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
                "with_v2ray_api",
                "with_cloudflared",
                "with_ccm",
                "with_ocm",
                "with_usbip",
                "with_openvpn",
                "with_openconnect",
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
                "grpcnotrace",
                "badlinkname",
                "tfogo_checklinkname0",
            ]
            .map(str::to_string),
        );
        if target.os == fcae_build::target::Os::Ios {
            archive.tags.push("with_low_memory".into());
        }
        // `with_purego` is what makes cronet-go call cronet through its C ABI at
        // run time instead of linking it: its cgo files then contribute no
        // LDFLAGS, so Chromium's objects stay out of libfcae_ffi.a and out of
        // the frontend link, and the app loads libcronet.dylib from beside
        // itself (see the cronet notes in CMakeLists.txt). Windows has always
        // built that way -- its half of the package is gated on this tag alone
        // -- and macOS needs it because cronet's fourth exception personality
        // routine does not fit a Mach-O image. Linux wants cronet in the one
        // file it ships, so there it stays linked, as does Android, whose Go
        // archive is a c-shared library that already carries cgo.
        if target.is_windows() || target.os == fcae_build::target::Os::MacOS {
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
            .push("-X github.com/sagernet/sing-box/constant.Version=embedded".into());
        archive
            .ldflags
            .push("-X runtime.godebugDefault=multipathtcp=0,tlssha1=1".into());
    }

    if archive.target.is_windows() && (mihomo || cfg!(feature = "sing-tun")) {
        // The pinned SagerNet/sing selected by sing-box already carries the
        // upstream dual-stack fix. MetaCubeX's fork (used by Mihomo and
        // sing-tun) still has the older family selection, so overlay the same
        // socket-family logic without editing its module cache or submodule.
        let replacement = manifest.join("overlays/metacubex_bind_windows.go");
        fcae_build::rerun_if_changed(&replacement);
        archive.source_overlays.push(fcae_build::go::GoSourceOverlay {
            module: "github.com/metacubex/sing",
            target: "common/control/bind_windows.go",
            replacement,
        });
    }

    match archive.build() {
        Ok(built) => {
            // Android builds a c-shared .so (Go rejects c-archive there), so
            // it has to land in jniLibs/<abi>/ for the loader. No-op elsewhere.
            if let Err(e) = built.stage_android_so(&root, target) {
                panic!("failed to stage the Go bridge for Android: {e}");
            }
            built.emit_link_directives("libfcae_go_bridge", target);
            if singbox && target.os == fcae_build::target::Os::Ios {
                // c-archive records cgo LDFLAGS but does not bundle external
                // static libraries. Make rustc include Cronet in libfcae_ffi.a.
                let go = std::env::var_os("GO_BIN")
                    .map(PathBuf::from)
                    .or_else(|| std::env::var_os("GOROOT").map(|p| PathBuf::from(p).join("bin/go")))
                    .unwrap_or_else(|| PathBuf::from("go"));
                let output = std::process::Command::new(go)
                    .current_dir(&module)
                    .args([
                        "list",
                        "-m",
                        "-f",
                        "{{.Dir}}",
                        "github.com/sagernet/cronet-go/lib/ios_arm64",
                    ])
                    .env("GOTOOLCHAIN", "auto")
                    .output()
                    .expect("locate the pinned iOS Cronet archive");
                assert!(
                    output.status.success(),
                    "Cronet lookup failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                let directory = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
                assert!(
                    directory.join("libcronet.a").is_file(),
                    "missing iOS Cronet static library"
                );
                println!("cargo:rustc-link-search=native={}", directory.display());
                println!("cargo:rustc-link-lib=static=cronet");
                println!("cargo:rustc-link-lib=dylib=c++");
            }
            println!("cargo:rustc-cfg=tun2socks_linked");
            println!(
                "cargo:rustc-env=FCAE_TUN2SOCKS_HEADER={}",
                built.header.display()
            );
            fcae_build::note(format!(
                "one Go archive built in-process (tun2socks{}, no subprocess, no embedded binary)",
                cores(psiphon, xray, singbox, mihomo)
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

fn cores(psiphon: bool, xray: bool, singbox: bool, mihomo: bool) -> String {
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
    if mihomo {
        names.push("mihomo");
    }
    if cfg!(feature = "urnetwork") {
        names.push("URnetwork");
    }
    if cfg!(feature = "sing-tun") {
        names.push("MetaCubeX/sing-tun");
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
    mihomo: bool,
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
        assert_eq!(
            source.matches(main).count(),
            1,
            "unexpected Psiphon bridge main"
        );
        std::fs::write(module.join("psiphon.go"), source.replace(main, ""))
            .expect("copy the Psiphon shim");
    }
    for (enabled, dir, name) in [
        (xray, "xray", "xray.go"),
        (singbox, "singbox", "singbox.go"),
        (mihomo, "mihomo", "mihomo.go"),
        (cfg!(feature = "sing-tun"), "sing-tun", "sing_tun.go"),
    ] {
        if !enabled {
            continue;
        }
        let shim = root
            .join("core/fcae-ffi/bridges")
            .join(dir)
            .join("go/bridge.go");
        fcae_build::go::track_sources(shim.parent().expect("shim directory"));
        copy(&shim, &module.join(name));
        if dir == "sing-tun" {
            for file in ["app_routing.go", "app_routing_stub.go"] {
                copy(
                    &shim.with_file_name(file),
                    &module.join(format!("sing_tun_{file}")),
                );
            }
        }
        if dir == "singbox" {
            copy(
                &shim.with_file_name("cronet_ios.c"),
                &module.join("cronet_ios.c"),
            );
        }
    }

    if cfg!(feature = "urnetwork") {
        let source = root.join("core/fcae-ffi/bridges/urnetwork/go");
        fcae_build::go::track_sources(&source);
        for entry in std::fs::read_dir(source).expect("URnetwork shim") {
            let path = entry.expect("URnetwork source").path();
            if path.extension().is_some_and(|x| x == "go") {
                copy(
                    &path,
                    &module.join(format!(
                        "ur_{}",
                        path.file_name().unwrap().to_string_lossy()
                    )),
                );
            }
        }
    }
    if mihomo && singbox {
        let source = root.join("core/fcae-ffi/bridges/mihomo/go/expvar/expvar.go");
        fcae_build::rerun_if_changed(&source);
        let destination = module.join("mihomoexpvar");
        std::fs::create_dir_all(&destination).expect("create namespaced metrics package");
        copy(&source, &destination.join("expvar.go"));
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
    for (enabled, directory, module_name) in [
        (xray, "xray", "github.com/xtls/xray-core"),
        (singbox, "sing-box", "github.com/sagernet/sing-box"),
    ] {
        if enabled {
            let source = root.join("core").join(directory);
            assert!(
                source.join("go.mod").is_file(),
                "missing {directory} submodule"
            );
            fcae_build::go::track_sources(&source);
            manifest.push_str(&format!(
                "\nrequire {module_name} v0.0.0\nreplace {module_name} => {}\n",
                local(&source)
            ));
        }
    }
    if cfg!(feature = "sing-tun") {
        let source = root.join("core/sing-tun");
        assert!(
            source.join("go.mod").is_file(),
            "MetaCubeX/sing-tun submodule is missing; initialize submodules before building"
        );
        fcae_build::go::track_sources(&source);
        let source = if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
            // Keep the git submodule pristine; override only its Windows DLL
            // loader in an OUT_DIR copy. All consumers in this archive share it.
            let staged = module.join("metacubex-sing-tun");
            if staged.exists() {
                std::fs::remove_dir_all(&staged).expect("clear staged sing-tun");
            }
            copy_source_tree(&source, &staged);
            fcae_build::go::defer_tcp_accept(&staged).unwrap_or_else(|error| panic!("{error}"));
            let loader = root.join("core/fcae-ffi/bridges/sing-tun/windows/dll_windows.go");
            fcae_build::rerun_if_changed(&loader);
            copy(&loader, &staged.join("internal/wintun/dll_windows.go"));
            let native_path = staged.join("tun_windows.go");
            let native =
                std::fs::read_to_string(&native_path).expect("read pinned sing-tun Windows source");
            let create="adapter, err := wintun.CreateAdapter(options.Name, TunnelType, generateGUIDByDeviceName(options.Name))";
            assert_eq!(
                native.matches(create).count(),
                1,
                "sing-tun adapter API changed; review Windows override"
            );
            let config_path = root.join("core/fcae-ffi/runtime/src/config.rs");
            fcae_build::rerun_if_changed(&config_path);
            let config = std::fs::read_to_string(config_path).expect("read host adapter identity");
            let guid = config
                .split("pub const WINTUN_ADAPTER_GUID: &str = \"")
                .nth(1)
                .and_then(|tail| tail.split('"').next())
                .expect("host Wintun GUID");
            let native=native.replace(create,"adapter, err := wintun.OpenAdapter(options.Name)\n if err != nil { adapter, err = wintun.CreateAdapter(options.Name, TunnelType, fcaeAdapterGUID()) }");
            let native=format!("{native}\nfunc fcaeAdapterGUID() *windows.GUID {{ value, err := windows.GUIDFromString(\"{{{guid}}}\"); if err != nil {{ panic(err) }}; return &value }}\n");
            // A dead Wintun read loop must not remain reported as Connected.
            // Keep this compatibility hook in the staged copy, not the gitlink.
            let field = "close       atomic.Int32";
            assert_eq!(native.matches(field).count(), 1, "review sing-tun read health hook");
            let native = native.replace(field, "close       atomic.Int32\n fcaeReadError atomic.Pointer[error]");
            let native = format!("{native}\nfunc (t *NativeTun) PacketReadError() error {{ p := t.fcaeReadError.Load(); if p != nil {{ return *p }}; return nil }}\n");
            std::fs::write(native_path, native).expect("stage shared adapter identity");
            let endpoint_path = staged.join("tun_windows_gvisor.go");
            let endpoint = std::fs::read_to_string(&endpoint_path).expect("read Windows packet endpoint");
            let read_failure = "if err != nil {\n\t\t\tbreak\n\t\t}";
            assert_eq!(endpoint.matches(read_failure).count(), 1, "review sing-tun packet reader");
            std::fs::write(endpoint_path, endpoint.replace(read_failure,
                "if err != nil {\n e.tun.fcaeReadError.Store(&err)\n break\n }"))
                .expect("stage packet reader health");
            staged
        } else if matches!(
            std::env::var("CARGO_CFG_TARGET_OS").as_deref(),
            Ok("linux" | "macos")
        ) {
            // The other desktops need no Windows override, but Mihomo's TUN and
            // the sing-tun engine split traffic per app there as well, and a
            // flow sent DIRECT has to be refused, not accepted and closed, when
            // it cannot leave.
            let staged = module.join("metacubex-sing-tun");
            if staged.exists() {
                std::fs::remove_dir_all(&staged).expect("clear staged sing-tun");
            }
            copy_source_tree(&source, &staged);
            fcae_build::go::defer_tcp_accept(&staged).unwrap_or_else(|error| panic!("{error}"));
            staged
        } else {
            source
        };
        manifest.push_str(&format!("\nrequire github.com/metacubex/sing-tun v0.0.0\nreplace github.com/metacubex/sing-tun => {}\n",local(&source)));
    }
    if mihomo {
        let source = root.join("core/mihomo");
        fcae_build::go::track_sources(&source);
        // The deferred TCP accept (bridges/sing-tun/stack/tcp_accept.go) lets
        // Mihomo's early-data peek pass without answering the application, and
        // knows it by this deadline.
        let tunnel = std::fs::read_to_string(source.join("tunnel/tunnel.go"))
            .expect("read the pinned Mihomo tunnel");
        assert_eq!(
            tunnel
                .matches("conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))")
                .count(),
            1,
            "Mihomo's early-data peek changed; review the deferred TCP accept"
        );
        manifest.push_str(&format!("\nrequire github.com/metacubex/mihomo v0.0.0\nreplace github.com/metacubex/mihomo => {}\n",local(&source)));
    }
    if cfg!(feature = "urnetwork") {
        // Dependency replacements are deliberately resolved by the archive's
        // main module, never by editing pinned submodule worktrees.
        for (directory, name) in [
            ("sdk", "github.com/urnetwork/sdk"),
            ("glog", "github.com/urnetwork/glog"),
            ("quic-go", "github.com/urnetwork/quic-go"),
            ("goidenticons", "github.com/urnetwork/goidenticons"),
            ("gvisor", "gvisor.dev/gvisor"),
        ] {
            let source = root.join("core/urnetwork").join(directory);
            assert!(
                source.join("go.mod").is_file(),
                "initialize URnetwork submodules"
            );
            fcae_build::go::track_sources(&source);
            manifest.push_str(&format!("\nreplace {name} => {}\n", local(&source)));
        }
        let source = root.join("core/urnetwork/connect");
        fcae_build::go::track_sources(&source);
        let staged = module.join("urnetwork-connect");
        if staged.exists() {
            std::fs::remove_dir_all(&staged).expect("clear URnetwork connect staging");
        }
        copy_source_tree(&source, &staged);
        let path = staged.join("egress.go");
        let original = std::fs::read_to_string(&path).expect("URnetwork egress source");
        let signature = "func egressControl(_ string, address string, c syscall.RawConn) error {";
        assert_eq!(
            original.matches(signature).count(),
            1,
            "review URnetwork egress API"
        );
        let patched = original.replace(signature, &format!("{signature}\n if hook := fcaeEgressHook.Load(); hook != nil {{ var inner error; if err := c.Control(func(fd uintptr) {{ inner = (*hook)(fd) }}); err != nil {{ return err }}; if inner != nil {{ return inner }} }}"));
        let patched = patched.replace(
            "if index4 == 0 && index6 == 0 {",
            "if index4 == 0 && index6 == 0 && fcaeEgressHook.Load() == nil {",
        );
        std::fs::write(path, format!("{patched}\nvar fcaeEgressHook atomic.Pointer[func(uintptr) error]\nfunc SetFCAEEgressControl(fn func(uintptr) error) {{ fcaeEgressHook.Store(&fn) }}\nfunc FCAEEgressControl(network, address string, raw syscall.RawConn) error {{ return egressControl(network, address, raw) }}\n")).expect("stage URnetwork host egress seam");
        manifest.push_str(&format!("\nrequire github.com/urnetwork/sdk v0.0.0\nreplace github.com/urnetwork/connect => {}\nreplace github.com/pion/sctp => {}\n", local(&staged), local(&source.join("sctp"))));
    }
    // Psiphon's quic-go fork decodes with qpack's pre-0.6 API; sing-box's and
    // Xray-core's forks require 0.6. MVS would hand all three 0.6.0, which
    // Psiphon's fork does not compile against, so the override in `gomods/qpack`
    // (0.6.0 plus the two pre-0.6 entry points) stands in for it.
    if psiphon && (xray || singbox || cfg!(feature = "urnetwork")) {
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

fn copy(from: &Path, to: &Path) {
    std::fs::copy(from, to)
        .unwrap_or_else(|e| panic!("copy {} -> {}: {e}", from.display(), to.display()));
}

fn copy_source_tree(source: &Path, destination: &Path) {
    std::fs::create_dir_all(destination).expect("create staged sing-tun directory");
    for entry in std::fs::read_dir(source).expect("read sing-tun source") {
        let entry = entry.expect("sing-tun source entry");
        let name = entry.file_name();
        if name == ".git" {
            continue;
        }
        let kind = entry.file_type().expect("sing-tun entry type");
        if kind.is_dir() {
            copy_source_tree(&entry.path(), &destination.join(name));
        } else if kind.is_file() {
            copy(&entry.path(), &destination.join(name));
        } else {
            panic!("unexpected non-regular entry in pinned sing-tun source");
        }
    }
}

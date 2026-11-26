//! Cross-compiling Go packages for **in-process** linking.
//!
//! This is what makes tun2socks run in-process. Instead of
//! `go build -o tun2socks.exe` and shipping an executable, we build a
//! linkable library and hand it to rustc, so the Go runtime lives inside
//! our own binary.
//!
//! Psiphon shares tun2socks' Go archive on desktop and Go shared library on Android.
//!
//! ## Why Android differs
//!
//! Every platform uses `-buildmode=c-archive` (a static `.a`) **except
//! Android**, where the Go toolchain rejects it:
//!
//! ```text
//! -buildmode=c-archive not supported on android/arm64
//! ```
//!
//! Android only supports `-buildmode=c-shared`, producing a `.so`. That is
//! still in-process — the shared object is loaded into our address space and
//! its symbols are called directly; there is no subprocess either way. The
//! only consequence is packaging: the `.so` must be shipped in `jniLibs/<abi>/`
//! so the dynamic loader can find it at runtime, which [`Built::stage_android_so`]
//! handles.
//!
//! cgo is required in both modes, which means a C cross-compiler for the
//! target. [`CArchive::cc_for`] resolves the right one (NDK clang for Android,
//! MinGW for Windows, `cc`/`clang` otherwise) and fails with an actionable
//! message rather than emitting a mystery linker error later.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::target::{Arch, Os, Target};

/// Replace a source file from a selected Go module while compiling the archive.
///
/// The module is copied next to the generated `go.mod`, `replacement` is
/// written over `target` in that copy, and a `replace` directive points the
/// build at it. `go build -overlay` cannot do this job: the go command aborts
/// on any overlay entry beneath GOMODCACHE ("Files beneath GOMODCACHE must not
/// be replaced"), which is exactly where a pinned dependency's sources live.
/// Module-cache sources remain untouched.
pub struct GoSourceOverlay {
    pub module: &'static str,
    pub target: &'static str,
    pub replacement: PathBuf,
}

/// A Go c-archive build request.
pub struct CArchive<'a> {
    /// Directory containing the `go.mod` to build from.
    pub module_dir: &'a Path,
    /// Package path within the module, e.g. `.`.
    pub package: &'a str,
    /// Output archive name without extension, e.g. `libfcae_go_bridge`.
    pub lib_name: &'a str,
    pub target: Target,
    /// Android API level for the NDK toolchain.
    pub android_api: u32,
    /// Extra `-ldflags` entries.
    pub ldflags: Vec<String>,
    /// Go build tags.
    pub tags: Vec<String>,
    /// Target-specific source overlays for the pinned dependency graph,
    /// applied to generated copies of the modules they patch.
    pub source_overlays: Vec<GoSourceOverlay>,
}

/// Where the built library and its generated header ended up.
pub struct Built {
    /// The built library: a `.a` (c-archive) or, on Android, a `.so`
    /// (c-shared). Either way it is linked into our own binary.
    pub archive: PathBuf,
    pub header: PathBuf,
    pub search_dir: PathBuf,
    /// True when `archive` is a `c-shared` `.so` that must also be packaged
    /// into `jniLibs/<abi>/` for the runtime loader.
    pub shared: bool,
}

#[derive(Debug)]
pub enum GoError {
    ToolchainMissing(String),
    CcMissing(String),
    Build(String),
}

impl std::fmt::Display for GoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GoError::ToolchainMissing(m) => write!(f, "Go toolchain unusable: {m}"),
            GoError::CcMissing(m) => write!(f, "C cross-compiler unavailable: {m}"),
            GoError::Build(m) => write!(f, "go build failed: {m}"),
        }
    }
}

impl std::error::Error for GoError {}

/// Major version of the Android NDK the build is pointed at, read from the
/// `Pkg.Revision` line of its `source.properties`.
///
/// `None` when no NDK is configured, or when the file is not where every NDK
/// since r19 puts it; the link then reports whatever the real problem is.
pub fn ndk_revision() -> Option<u32> {
    for key in ["ANDROID_NDK_HOME", "ANDROID_NDK_ROOT", "NDK_HOME"] {
        let Ok(dir) = std::env::var(key) else {
            continue;
        };
        let Ok(text) = std::fs::read_to_string(PathBuf::from(dir).join("source.properties")) else {
            continue;
        };
        let revision = text.lines().find_map(|line| {
            let (_, value) = line.strip_prefix("Pkg.Revision")?.split_once('=')?;
            value.trim().split('.').next()?.parse::<u32>().ok()
        });
        if revision.is_some() {
            return revision;
        }
    }
    None
}

impl<'a> CArchive<'a> {
    pub fn new(module_dir: &'a Path, package: &'a str, lib_name: &'a str) -> Self {
        Self {
            module_dir,
            package,
            lib_name,
            target: Target::from_cargo_env(),
            // Must match android/app/build.gradle.kts `minSdk` and the
            // `...29-clang` selected by CI. This keeps the Go bridge on the
            // same Android API surface as Aether v2.4.
            android_api: 29,
            ldflags: vec!["-s".into(), "-w".into()],
            tags: Vec::new(),
            source_overlays: Vec::new(),
        }
    }

    /// Path to the `go` binary, honouring `GO_BIN`/`GOROOT`.
    fn go_bin() -> Result<String, GoError> {
        for candidate in [
            std::env::var("GO_BIN").ok(),
            std::env::var("GOROOT").ok().map(|r| {
                PathBuf::from(r)
                    .join("bin")
                    .join("go")
                    .display()
                    .to_string()
            }),
            Some("go".to_string()),
        ]
        .into_iter()
        .flatten()
        {
            if Command::new(&candidate).arg("version").output().is_ok() {
                return Ok(candidate);
            }
        }
        Err(GoError::ToolchainMissing(
            "`go` not found on PATH. Install Go (https://go.dev/dl/) or set GO_BIN. The module toolchain directive auto-selects via GOTOOLCHAIN=auto.".into(),
        ))
    }

    /// Resolve the C compiler cgo should use for this target.
    pub fn cc_for(target: Target, android_api: u32) -> Result<String, GoError> {
        validate_ios_target(target)?;
        // An explicit override always wins.
        if let Ok(cc) = std::env::var("CGO_CC") {
            return Ok(cc);
        }

        match target.os {
            Os::Android => {
                let ndk = std::env::var("ANDROID_NDK_HOME")
                    .or_else(|_| std::env::var("ANDROID_NDK_ROOT"))
                    .or_else(|_| std::env::var("NDK_HOME"))
                    .map_err(|_| {
                        GoError::CcMissing(
                            "ANDROID_NDK_HOME is not set; the NDK is required to build the \
                             in-process tun2socks bridge for Android."
                                .into(),
                        )
                    })?;
                let host_tag = if cfg!(target_os = "macos") {
                    "darwin-x86_64"
                } else if cfg!(target_os = "windows") {
                    "windows-x86_64"
                } else {
                    "linux-x86_64"
                };
                let cc = PathBuf::from(&ndk)
                    .join("toolchains/llvm/prebuilt")
                    .join(host_tag)
                    .join("bin")
                    .join(format!("{}-clang", target.ndk_clang_triple(android_api)));
                if !cc.exists() {
                    return Err(GoError::CcMissing(format!(
                        "NDK clang not found at {}. Check ANDROID_NDK_HOME and the API level.",
                        cc.display()
                    )));
                }
                Ok(cc.display().to_string())
            }
            Os::Ios => ios_compiler(),
            Os::Windows if !cfg!(target_os = "windows") => {
                // Cross-compiling to Windows: MinGW, the x86_64-pc-windows-gnu toolchain.
                Ok("x86_64-w64-mingw32-gcc".into())
            }
            _ => Ok(std::env::var("CC").unwrap_or_else(|_| "cc".into())),
        }
    }

    /// Run an auxiliary `go` subcommand (module resolution, etc.) in
    /// `module_dir`, surfacing its stderr verbatim when it fails.
    fn run_go_step(go: &str, module_dir: &Path, args: &[&str], what: &str) -> Result<(), GoError> {
        crate::note(format!("{what}..."));
        let output = Command::new(go)
            .current_dir(module_dir)
            .args(args)
            .env("GOFLAGS", "-mod=mod")
            .env("CGO_ENABLED", "0")
            .env("GOTOOLCHAIN", "auto")
            .output()
            .map_err(|e| GoError::Build(format!("could not run `go {}`: {e}", args.join(" "))))?;

        if !output.status.success() {
            return Err(GoError::Build(format!(
                "failed to {what}: {}\n--- stderr ---\n{}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        Ok(())
    }

    /// Apply `source_overlays` to generated copies of the modules they patch.
    ///
    /// Each module is resolved through the build list (never a guessed cache
    /// path), copied into the generated module directory and `replace`d there.
    /// The copy carries the module's own `go.mod`, so the requirement graph and
    /// `go.sum` stay exactly as resolved and the `-mod=readonly` build accepts
    /// the copy as is, the same way it accepts the Mihomo metrics copy.
    fn stage_source_overlays(&self, go: &str) -> Result<(), GoError> {
        // Modules copied by this call: several files of one module must land
        // in the same copy.
        let mut staged: Vec<(&str, PathBuf)> = Vec::new();
        for overlay in &self.source_overlays {
            let replacement = std::fs::read(&overlay.replacement).map_err(|error| {
                GoError::Build(format!(
                    "could not read Go overlay replacement {}: {error}",
                    overlay.replacement.display()
                ))
            })?;
            let known = staged
                .iter()
                .find(|(module, _)| *module == overlay.module)
                .map(|(_, directory)| directory.clone());
            let directory = match known {
                Some(directory) => directory,
                None => {
                    let directory = self.stage_overlay_module(go, overlay.module)?;
                    staged.push((overlay.module, directory.clone()));
                    directory
                }
            };
            let target = directory.join(overlay.target);
            if !target.is_file() {
                return Err(GoError::Build(format!(
                    "Go overlay target does not exist: {} has no {}",
                    overlay.module, overlay.target
                )));
            }
            std::fs::write(&target, replacement).map_err(|error| {
                GoError::Build(format!("could not write {}: {error}", target.display()))
            })?;
        }
        Ok(())
    }

    /// Copy the resolved source of `module` into the generated module directory
    /// and point the build at that copy.
    fn stage_overlay_module(&self, go: &str, module: &str) -> Result<PathBuf, GoError> {
        let downloaded = Command::new(go)
            .current_dir(self.module_dir)
            .args(["mod", "download", module])
            .env_remove("GOFLAGS")
            .env("CGO_ENABLED", "0")
            .env("GOTOOLCHAIN", "auto")
            .output()
            .map_err(|error| {
                GoError::Build(format!(
                    "could not download Go overlay module {module}: {error}"
                ))
            })?;
        if !downloaded.status.success() {
            return Err(GoError::Build(format!(
                "could not download Go overlay module {module}: {}\n{}",
                downloaded.status,
                String::from_utf8_lossy(&downloaded.stderr)
            )));
        }
        let output = Command::new(go)
            .current_dir(self.module_dir)
            .args(["list", "-m", "-f", "{{.Dir}}", module])
            .env("GOFLAGS", "-mod=readonly")
            .env("CGO_ENABLED", "0")
            .env("GOTOOLCHAIN", "auto")
            .output()
            .map_err(|error| {
                GoError::Build(format!(
                    "could not resolve Go overlay module {module}: {error}"
                ))
            })?;
        if !output.status.success() {
            return Err(GoError::Build(format!(
                "could not resolve Go overlay module {module}: {}\n{}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        let source = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
        if !source.is_absolute() {
            return Err(GoError::Build(format!(
                "Go overlay module {module} has no local source directory"
            )));
        }
        let label: String = module
            .chars()
            .map(|character| match character {
                'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '_' | '-' => character,
                _ => '-',
            })
            .collect();
        let destination = self.module_dir.join(format!("source-overlay-{label}"));
        // The generated go.mod is rewritten on every build, so the module
        // normally resolves to its pinned source here. Should it already point
        // at this copy, refresh the files in place: clearing the copy would
        // delete the only source there is.
        let staged = source == destination
            || matches!(
                (source.canonicalize(), destination.canonicalize()),
                (Ok(resolved), Ok(copy)) if resolved == copy
            );
        if staged {
            return Ok(destination);
        }
        let fail = |error: std::io::Error| {
            GoError::Build(format!(
                "could not stage Go overlay module {module}: {error}"
            ))
        };
        if destination.exists() {
            std::fs::remove_dir_all(&destination).map_err(fail)?;
        }
        copy_windows_module(&source, &destination)?;
        let replacement = format!(
            "{module}={}",
            destination.to_string_lossy().replace('\\', "/")
        );
        Self::run_go_step(
            go,
            self.module_dir,
            &["mod", "edit", "-replace", &replacement],
            "stage Go source overlay",
        )?;
        Ok(destination)
    }

    pub fn build(&self) -> Result<Built, GoError> {
        let go = Self::go_bin()?;
        let cc = Self::cc_for(self.target, self.android_api)?;

        let out_dir = PathBuf::from(
            std::env::var("OUT_DIR").map_err(|_| GoError::Build("OUT_DIR unset".into()))?,
        );
        // Android requires c-shared; desktop uses one static Go archive.
        let shared = self.target.is_android();
        let buildmode = if shared { "c-shared" } else { "c-archive" };
        let ext = if shared {
            self.target.shared_lib_ext()
        } else {
            self.target.static_lib_ext()
        };

        let archive = out_dir.join(format!("{}.{}", self.lib_name, ext));
        let header = out_dir.join(format!("{}.h", self.lib_name));

        crate::note(format!(
            "building {} as a Go {} for {}/{} (in-process; no subprocess)",
            self.package,
            buildmode,
            self.target.goos(),
            self.target.goarch()
        ));

        // Resolve the module graph before building.
        //
        // The bridge module `replace`s tun2socks with the submodule checkout,
        // so the submodule is compiled as *source* and its own go.sum does not
        // apply: Go demands that the MAIN module (this bridge) carry go.sum
        // entries for every transitive dependency (gvisor, zap, chi, x/crypto,
        // ...). We deliberately do not vendor or hand-maintain that list, so
        // `go mod tidy` synthesises go.mod/go.sum here instead of failing with
        // a wall of "missing go.sum entry" errors.
        //
        // GOFLAGS=-mod=mod lets tidy write the files; the build below then runs
        // against a complete, consistent graph.
        //
        // `go mod tidy` resolves from the network, so running it on every
        // build makes the artifact depend on what the module proxy served
        // that day -- two builds of the same commit could link different
        // versions of the transitive graph. Once a go.sum exists it is the
        // pinned record, so skip tidy and build in `-mod=readonly`, which
        // fails loudly if anything is missing instead of silently changing
        // the graph. Set FCAE_GO_TIDY=1 to refresh it deliberately.
        let go_sum = self.module_dir.join("go.sum");
        let force_tidy = std::env::var("FCAE_GO_TIDY").is_ok_and(|v| v != "0");
        if force_tidy || !go_sum.is_file() {
            Self::run_go_step(
                &go,
                self.module_dir,
                &["mod", "tidy"],
                "resolve Go dependencies (go mod tidy)",
            )?;
            crate::note("go.sum refreshed -- commit it so the build is reproducible");
        } else {
            crate::note("using the committed go.sum (set FCAE_GO_TIDY=1 to refresh)");
        }

        if self.tags.iter().any(|tag| tag == "fcae_mihomo")
            && self.tags.iter().any(|tag| tag == "fcae_singbox")
        {
            isolate_mihomo_metrics(&go, self.module_dir)?;
        }
        if self.target.os == Os::Windows {
            stage_windows_adapter_guids(&go, self.module_dir)?;
        }
        self.stage_source_overlays(&go)?;
        let mut ldflags = self.ldflags.clone();
        if shared && self.target.is_android() {
            // Android 15 ships 16 KB memory pages. A shared object linked with
            // the historical 4 KB alignment is rejected by the loader there,
            // so every Go .so we stage into jniLibs needs this. It goes
            // through -extldflags because the NDK linker does the final
            // layout, not the Go linker. Psiphon's own make.bash passes the
            // same flag.
            //
            // Android ONLY: `-z max-page-size` is an ELF concept. Passing it
            // on Windows reaches mingw's ld, which rejects `-z` outright
            // ("unrecognized option '-z'") and fails the link.
            ldflags.push("-extldflags=-Wl,-z,max-page-size=16384,-z,common-page-size=16384".into());
        }

        let mut cmd = Command::new(&go);
        cmd.current_dir(self.module_dir)
            .arg("build")
            .arg(format!("-buildmode={buildmode}"))
            .arg("-trimpath");

        if !self.tags.is_empty() {
            cmd.arg("-tags").arg(self.tags.join(","));
        }

        if !ldflags.is_empty() {
            cmd.arg("-ldflags").arg(ldflags.join(" "));
        }
        cmd.arg("-o").arg(&archive).arg(self.package);

        // cgo is mandatory for c-archive.
        cmd.env("GOTOOLCHAIN", "auto")
            .env("CGO_ENABLED", "1")
            .env("GOOS", self.target.goos())
            .env("GOARCH", self.target.goarch())
            .env("CC", &cc);

        if self.target.os == Os::Ios && Path::new(&cc).is_file() {
            cmd.env("CC", format!("'{}'", cc.replace('\'', "'\\''")));
        }

        // Build against the committed graph. Without this an incomplete
        // go.sum would be silently amended mid-build, which is the
        // reproducibility hole the tidy skip above exists to close.
        if !force_tidy {
            cmd.env("GOFLAGS", "-mod=readonly");
        }

        if let Some(goarm) = self.target.goarm() {
            cmd.env("GOARM", goarm);
        }
        if self.target.is_android() {
            // -soname is essential for the c-shared build. Without it the ELF
            // has no SONAME, so whatever links against it records the full
            // build-time path in DT_NEEDED (e.g. /home/runner/work/.../
            // libfcae_go_bridge.so). That path does not exist on the device,
            // so System.loadLibrary() fails at runtime with a dlopen error and
            // NOTHING starts -- no engine, no TUN. With the SONAME set, the
            // loader looks for a bare "libfcae_go_bridge.so" and finds the
            // copy Gradle packaged in the APK's native library dir.
            let soname = format!("{}.so", self.lib_name);
            cmd.env("CGO_CFLAGS", "-O2 -fPIC").env(
                "CGO_LDFLAGS",
                // 16 KiB pages are required by recent Android releases.
                format!("-Wl,-z,max-page-size=16384 -Wl,-soname,{soname}"),
            );
        }
        if self.target.os == Os::Ios {
            configure_ios_cgo(&mut cmd)?;
        }
        if self.target.os == Os::MacOS {
            if let Ok(v) = std::env::var("MACOSX_DEPLOYMENT_TARGET") {
                cmd.env("MACOSX_DEPLOYMENT_TARGET", v);
            }
        }

        let output = cmd
            .output()
            .map_err(|e| GoError::Build(format!("could not run `{go} build`: {e}")))?;

        if !output.status.success() {
            return Err(GoError::Build(format!(
                "{}\n--- stderr ---\n{}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        if !archive.exists() {
            return Err(GoError::Build(format!(
                "go reported success but {} is missing",
                archive.display()
            )));
        }

        Ok(Built {
            archive,
            header,
            search_dir: out_dir,
            shared,
        })
    }
}

impl Built {
    /// Copy a `c-shared` `.so` into `android/app/src/main/jniLibs/<abi>/` so
    /// the dynamic loader finds it at runtime.
    ///
    /// No-op for `c-archive` builds, where the code is already inside
    /// `libfcae_ffi.a` and there is nothing to ship separately.
    ///
    /// Note this is a *library* the app loads, not an executable it runs —
    /// the previous design shipped a tun2socks **binary** here and spawned it
    /// as a child process. Same directory, entirely different mechanism.
    pub fn stage_android_so(&self, repo_root: &Path, target: Target) -> Result<(), GoError> {
        // A desktop shared library must not be staged into Android jniLibs.
        if !self.shared || !target.is_android() {
            return Ok(());
        }
        // android_abi() no longer guesses: an architecture with no ABI
        // mapping is a build error, not a library quietly staged into the
        // wrong directory and discovered as a device-side load failure.
        let abi = target.android_abi().ok_or_else(|| {
            GoError::Build(format!(
                "no Android ABI directory is defined for {}/{}; refusing to guess \
                 which jniLibs directory to stage into",
                target.goos(),
                target.goarch()
            ))
        })?;
        let dest_dir = repo_root.join("android/app/src/main/jniLibs").join(abi);
        std::fs::create_dir_all(&dest_dir)
            .map_err(|e| GoError::Build(format!("could not create {}: {e}", dest_dir.display())))?;

        let file_name = self
            .archive
            .file_name()
            .ok_or_else(|| GoError::Build("built library has no file name".into()))?;
        let dest = dest_dir.join(file_name);

        std::fs::copy(&self.archive, &dest).map_err(|e| {
            GoError::Build(format!(
                "could not stage {} -> {}: {e}",
                self.archive.display(),
                dest.display()
            ))
        })?;
        crate::note(format!("staged {} for {}", dest.display(), abi));
        Ok(())
    }

    pub fn emit_link_directives(&self, lib_name: &str, target: Target) {
        println!(
            "cargo:rustc-link-search=native={}",
            self.search_dir.display()
        );
        // `lib_name` arrives as `libfoo`; rustc wants `foo`.
        let link_name = lib_name.strip_prefix("lib").unwrap_or(lib_name);
        if self.shared {
            println!("cargo:rustc-link-lib=dylib={link_name}");
        } else {
            println!("cargo:rustc-link-lib=static={link_name}");
        }

        match target.os {
            Os::Windows => {
                // The Go runtime's netpoller and process APIs, plus every
                // system DLL the linked Go code imports.
                //
                // The first six cover the runtime itself. The rest are pulled
                // in by Psiphon's dependency tree -- x/sys/windows, go-ole and
                // gopsutil between them reference COM, service-control,
                // performance-counter and device-enumeration APIs. Missing
                // ones surface as a wall of undefined __imp_* symbols from
                // x86_64-w64-mingw32-gcc at the final link.
                //
                // Naming an import library that nothing ends up referencing is
                // free -- the linker simply pulls nothing out of it -- so this
                // list is deliberately generous rather than minimal.
                for l in [
                    // Go runtime.
                    "ws2_32", "winmm", "ntdll", "userenv", "iphlpapi", "bcrypt",
                    // Core Win32 used across the dependency tree.
                    "advapi32", "kernel32", "psapi", "crypt32", "secur32", "mswsock", "shell32",
                    "user32", "dnsapi", "wintrust", "version", "netapi32", "wtsapi32", "setupapi",
                    "cfgmgr32",
                    // COM / OLE (go-ole).
                    //
                    // combase is deliberately absent: mingw-w64 ships no
                    // libcombase.a, so naming it fails the link outright with
                    // "cannot find -lcombase". Everything go-ole actually
                    // resolves at link time lives in ole32/oleaut32; the rest
                    // it loads lazily through LoadLibrary at runtime.
                    "ole32", "oleaut32", // Performance counters (gopsutil).
                    "pdh",
                ] {
                    println!("cargo:rustc-link-lib=dylib={l}");
                }
            }
            Os::MacOS | Os::Ios => {
                println!("cargo:rustc-link-lib=framework=CoreFoundation");
                println!("cargo:rustc-link-lib=framework=Security");
                println!("cargo:rustc-link-lib=dylib=resolv");
            }
            Os::Android => {
                println!("cargo:rustc-link-lib=dylib=log");
            }
            _ => {
                println!("cargo:rustc-link-lib=dylib=pthread");
                println!("cargo:rustc-link-lib=dylib=dl");
            }
        }
    }
}

/// Register every `.go` / `go.mod` / `go.sum` under `dir` as a cargo rerun
/// trigger, so editing the bridge actually rebuilds it.
pub fn track_sources(dir: &Path) {
    fn walk(dir: &Path, depth: usize) {
        if depth > 6 {
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
                if !matches!(name, ".git" | "testdata" | "vendor") {
                    walk(&p, depth + 1);
                }
            } else if p
                .extension()
                .and_then(|s| s.to_str())
                .is_some_and(|e| e == "go")
                || p.file_name()
                    .and_then(|s| s.to_str())
                    .is_some_and(|n| n == "go.mod" || n == "go.sum")
            {
                crate::rerun_if_changed(&p);
            }
        }
    }
    walk(dir, 0);
}

fn validate_ios_target(target: Target) -> Result<(), GoError> {
    if target.os == Os::Ios
        && (target.arch != Arch::Aarch64
            || std::env::var("TARGET").is_ok_and(|value| value != "aarch64-apple-ios"))
    {
        return Err(GoError::Build(
            "the iOS core build supports arm64 physical devices only (aarch64-apple-ios)".into(),
        ));
    }
    Ok(())
}

fn iphoneos_xcrun(arguments: &[&str]) -> Result<String, GoError> {
    let output = Command::new("xcrun")
        .arg("--sdk")
        .arg("iphoneos")
        .args(arguments)
        .output()
        .map_err(|error| {
            GoError::CcMissing(format!(
                "iOS builds require Xcode and its iPhoneOS SDK: {error}"
            ))
        })?;
    let value = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if !output.status.success() || value.is_empty() {
        return Err(GoError::CcMissing(format!(
            "xcrun iphoneos failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(value)
}

fn ios_compiler() -> Result<String, GoError> {
    iphoneos_xcrun(&["--find", "clang"])
}

fn configure_ios_cgo(command: &mut Command) -> Result<(), GoError> {
    let sdk = iphoneos_xcrun(&["--show-sdk-path"])?;
    if !PathBuf::from(&sdk).is_dir() {
        return Err(GoError::CcMissing(format!(
            "iPhoneOS SDK does not exist: {sdk}"
        )));
    }
    let minimum = std::env::var("IPHONEOS_DEPLOYMENT_TARGET").unwrap_or_else(|_| "15.0".into());
    let parts: Vec<_> = minimum.split('.').collect();
    if !(2..=3).contains(&parts.len())
        || parts
            .iter()
            .any(|part| part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()))
        || parts[0].parse::<u32>().map_or(true, |major| major < 15)
    {
        return Err(GoError::Build(
            "IPHONEOS_DEPLOYMENT_TARGET must be a numeric version >= 15.0".into(),
        ));
    }
    let quoted_sdk = format!("'{}'", sdk.replace('\'', "'\\''"));
    let flags = format!("-target arm64-apple-ios{minimum} -isysroot {quoted_sdk}");
    for key in ["CGO_CFLAGS", "CGO_CPPFLAGS", "CGO_CXXFLAGS", "CGO_LDFLAGS"] {
        let existing = std::env::var(key).unwrap_or_default();
        command.env(key, format!("{existing} {flags}"));
    }
    command
        .env("SDKROOT", sdk)
        .env("IPHONEOS_DEPLOYMENT_TARGET", minimum)
        .env(
            "CXX",
            format!("\"{}\"", iphoneos_xcrun(&["--find", "clang++"])?),
        );
    command.env_remove("MACOSX_DEPLOYMENT_TARGET");
    Ok(())
}

// Tailscale forks publish identical expvar keys during package initialization.
// Adapt a generated copy, keeping upstream sources and the module cache intact.
fn isolate_mihomo_metrics(go: &str, module: &Path) -> Result<(), GoError> {
    let listed = Command::new(go)
        .current_dir(module)
        .args([
            "list",
            "-m",
            "-f",
            "{{.Dir}}",
            "github.com/metacubex/tailscale",
        ])
        .env("GOTOOLCHAIN", "auto")
        .env("GOFLAGS", "-mod=readonly")
        .output()
        .map_err(|e| GoError::Build(e.to_string()))?;
    if !listed.status.success() {
        return Err(GoError::Build(
            String::from_utf8_lossy(&listed.stderr).into_owned(),
        ));
    }
    let root = PathBuf::from(String::from_utf8_lossy(&listed.stdout).trim());
    let destination = module.join("mihomo-tailscale");
    if root == destination {
        return Ok(());
    }
    let mut pending = vec![root.clone()];
    let mut replaced = 0;
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(directory).map_err(|e| GoError::Build(e.to_string()))? {
            let path = entry.map_err(|e| GoError::Build(e.to_string()))?.path();
            let output = destination.join(
                path.strip_prefix(&root)
                    .map_err(|e| GoError::Build(e.to_string()))?,
            );
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            std::fs::create_dir_all(output.parent().expect("generated source parent"))
                .map_err(|e| GoError::Build(e.to_string()))?;
            let mut content = std::fs::read(&path).map_err(|e| GoError::Build(e.to_string()))?;
            if path.extension().is_some_and(|extension| extension == "go") {
                let text = String::from_utf8(content).map_err(|e| GoError::Build(e.to_string()))?;
                if text.contains("\"expvar\"") {
                    replaced += 1;
                }
                content=text.replace("\"expvar\"","\"github.com/FCFlenkchy/FCAE_VPN/core/fcae-ffi/bridges/tun2socks/mihomoexpvar\"").into_bytes();
            }
            std::fs::write(output, content).map_err(|e| GoError::Build(e.to_string()))?;
        }
    }
    if replaced == 0 {
        return Err(GoError::Build(
            "Mihomo Tailscale metrics imports changed; review the namespace adapter".into(),
        ));
    }
    let replacement = format!("github.com/metacubex/tailscale={}", destination.display());
    CArchive::run_go_step(
        go,
        module,
        &["mod", "edit", "-replace", &replacement],
        "isolate Mihomo metrics",
    )
}

// Use the actually resolved Go module versions, not guessed cache paths or
// versions. Adapt only generated source copies; keep submodules/cache pristine.
fn stage_windows_adapter_guids(go: &str, module: &Path) -> Result<(), GoError> {
    let fail = |error: std::io::Error| GoError::Build(error.to_string());
    let config_path = crate::repo_root().join("core/fcae-ffi/runtime/src/config.rs");
    crate::rerun_if_changed(&config_path);
    let config = std::fs::read_to_string(config_path).map_err(fail)?;
    let guid = config
        .split("pub const WINTUN_ADAPTER_GUID: &str = \"")
        .nth(1)
        .and_then(|tail| tail.split('"').next())
        .ok_or_else(|| GoError::Build("host Wintun GUID declaration changed".into()))?;
    let listed = Command::new(go)
        .current_dir(module)
        .args(["list", "-m", "-f", "{{.Path}}|{{.Dir}}", "all"])
        .env("GOTOOLCHAIN", "auto")
        .env("GOFLAGS", "-mod=readonly")
        .output()
        .map_err(fail)?;
    if !listed.status.success() {
        return Err(GoError::Build(
            String::from_utf8_lossy(&listed.stderr).into_owned(),
        ));
    }
    let mut changed = false;
    for line in String::from_utf8_lossy(&listed.stdout).lines() {
        let Some((name, directory)) = line.split_once('|') else {
            continue;
        };
        let (label, relative) = match name {
            "github.com/sagernet/sing-tun" => ("sagernet-sing-tun", "tun_windows.go"),
            "github.com/metacubex/sing-tun" => ("metacubex-sing-tun", "tun_windows.go"),
            "github.com/xtls/xray-core" => ("xray", "proxy/tun/tun_windows.go"),
            _ => continue,
        };
        let root = PathBuf::from(directory);
        let text = std::fs::read_to_string(root.join(relative)).map_err(fail)?;
        if text.contains("func fcaeAdapterGUID()") {
            continue;
        }
        let patched = if label == "xray" {
            let original =
                "id := md5.Sum([]byte(name))\n\tguid := (*windows.GUID)(unsafe.Pointer(&id[0]))";
            if text.matches(original).count() != 1 {
                return Err(GoError::Build(
                    "Xray Windows adapter API changed; review shared GUID integration".into(),
                ));
            }
            text.replace(original, "guid := fcaeAdapterGUID()")
                .replace("\t\"crypto/md5\"\n", "")
        } else {
            let original="adapter, err := wintun.CreateAdapter(options.Name, TunnelType, generateGUIDByDeviceName(options.Name))";
            if text.matches(original).count() != 1 {
                return Err(GoError::Build(format!(
                    "{name} Windows adapter API changed; review shared GUID integration"
                )));
            }
            text.replace(original,"adapter, err := wintun.OpenAdapter(options.Name)\n if err != nil { adapter, err = wintun.CreateAdapter(options.Name, TunnelType, fcaeAdapterGUID()) }")
        };
        let patched=format!("{patched}\nfunc fcaeAdapterGUID() *windows.GUID {{ value, err := windows.GUIDFromString(\"{{{guid}}}\"); if err != nil {{ panic(err) }}; return &value }}\n");
        let destination = module.join(format!("shared-guid-{label}"));
        if destination.exists() {
            std::fs::remove_dir_all(&destination).map_err(fail)?;
        }
        copy_windows_module(&root, &destination)?;
        let output = destination.join(relative);
        let mut permissions = std::fs::metadata(&output).map_err(fail)?.permissions();
        permissions.set_readonly(false);
        std::fs::set_permissions(&output, permissions).map_err(fail)?;
        std::fs::write(output, patched).map_err(fail)?;
        if label != "xray" {
            let loader = crate::repo_root()
                .join("core/fcae-ffi/bridges/sing-tun/windows/dll_windows.go");
            crate::rerun_if_changed(&loader);
            share_wintun_image(&destination, &loader, name)?;
        }
        let replacement = format!(
            "{name}={}",
            destination.to_string_lossy().replace('\\', "/")
        );
        CArchive::run_go_step(
            go,
            module,
            &["mod", "edit", "-replace", &replacement],
            "stage shared Windows adapter GUID",
        )?;
        changed = true;
    }
    if changed {
        CArchive::run_go_step(
            go,
            module,
            &["mod", "tidy"],
            "resolve shared-GUID source copies",
        )?;
    }
    Ok(())
}
/// sing-tun carries a wintun.dll of its own and maps it from memory, which puts
/// a second Wintun image into a process whose other engines use the host's.
/// Each image opens Wintun's private namespace for itself, and Windows refuses
/// the second open in one process with ERROR_DUP_NAME. So once one kind of
/// engine had made an adapter, the other kind failed until the app restarted:
/// "configure tun interface: You were not connected because a duplicate name
/// exists on the network". Give the copy the loader that returns the host's
/// image, as the staged MetaCubeX copy already has.
fn share_wintun_image(module: &Path, loader: &Path, name: &str) -> Result<(), GoError> {
    let fail = |error: std::io::Error| GoError::Build(error.to_string());
    let target = module.join("internal/wintun/dll_windows.go");
    let upstream = std::fs::read_to_string(&target).map_err(fail)?;
    // The replacement stands in for this memory loader and no other.
    if upstream.matches("memmod.LoadLibrary(dllContent)").count() != 1
        || upstream.matches("func newLazyDLL(name string) *lazyDLL").count() != 1
    {
        return Err(GoError::Build(format!(
            "{name} Wintun loader changed; review the shared image integration"
        )));
    }
    let replacement = std::fs::read(loader).map_err(fail)?;
    std::fs::write(target, replacement).map_err(fail)
}
fn copy_windows_module(source: &Path, destination: &Path) -> Result<(), GoError> {
    let fail = |error: std::io::Error| GoError::Build(error.to_string());
    std::fs::create_dir_all(destination).map_err(fail)?;
    for entry in std::fs::read_dir(source).map_err(fail)? {
        let entry = entry.map_err(fail)?;
        let name = entry.file_name();
        if name == ".git" {
            continue;
        }
        let kind = entry.file_type().map_err(fail)?;
        if kind.is_dir() {
            copy_windows_module(&entry.path(), &destination.join(name))?;
        } else if kind.is_file() {
            let output = destination.join(name);
            std::fs::copy(entry.path(), &output).map_err(fail)?;
            // Go's module cache is read-only; generated copies must be
            // writable so Windows can replace them on the next build.
            let mut permissions = std::fs::metadata(&output).map_err(fail)?.permissions();
            permissions.set_readonly(false);
            std::fs::set_permissions(output, permissions).map_err(fail)?;
        } else {
            return Err(GoError::Build(
                "unexpected non-regular entry in Go module source".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn staged_module(name: &str, loader: &str) -> PathBuf {
        let module = std::env::temp_dir().join(format!(
            "fcae-wintun-image-test-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&module);
        std::fs::create_dir_all(module.join("internal/wintun")).unwrap();
        std::fs::write(module.join("internal/wintun/dll_windows.go"), loader).unwrap();
        module
    }

    fn host_loader() -> PathBuf {
        crate::repo_root().join("core/fcae-ffi/bridges/sing-tun/windows/dll_windows.go")
    }

    #[test]
    fn a_sing_tun_copy_loads_the_hosts_wintun_image() {
        let module = staged_module(
            "memory",
            "package wintun\nfunc newLazyDLL(name string) *lazyDLL { return &lazyDLL{Name: name} }\n\
             func (d *lazyDLL) Load() error { module, err := memmod.LoadLibrary(dllContent); _ = module; return err }\n",
        );
        share_wintun_image(&module, &host_loader(), "github.com/sagernet/sing-tun").unwrap();
        let staged = std::fs::read_to_string(module.join("internal/wintun/dll_windows.go")).unwrap();
        assert_eq!(staged, std::fs::read_to_string(host_loader()).unwrap());
        // One image for the process: no second copy mapped from memory.
        assert!(staged.contains("fcae_wintun_load_library") && !staged.contains("memmod"));
        std::fs::remove_dir_all(module).unwrap();
    }

    #[test]
    fn an_unknown_wintun_loader_stops_the_build() {
        let other = "package wintun\nfunc newLazyDLL(name string, onLoad func(d *lazyDLL)) *lazyDLL { return nil }\n";
        let module = staged_module("other", other);
        let error = share_wintun_image(&module, &host_loader(), "github.com/sagernet/sing-tun")
            .err()
            .expect("an unreviewed loader must not be replaced");
        assert!(error.to_string().contains("Wintun loader changed"));
        let kept = std::fs::read_to_string(module.join("internal/wintun/dll_windows.go")).unwrap();
        assert_eq!(kept, other);
        std::fs::remove_dir_all(module).unwrap();
    }
}

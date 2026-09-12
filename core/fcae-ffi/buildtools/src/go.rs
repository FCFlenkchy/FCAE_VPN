//! Cross-compiling Go packages for **in-process** linking.
//!
//! This is what makes tun2socks (and later Psiphon, which is also Go) run
//! in-process. Instead of `go build -o tun2socks.exe` and shipping an
//! executable, we build a linkable library and hand it to rustc, so the Go
//! runtime lives inside our own binary.
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
//! so the dynamic loader can find it at runtime, which [`Built::staged_so`]
//! handles.
//!
//! cgo is required in both modes, which means a C cross-compiler for the
//! target. [`CArchive::cc_for`] resolves the right one (NDK clang for Android,
//! MinGW for Windows, `cc`/`clang` otherwise) and fails with an actionable
//! message rather than emitting a mystery linker error later.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::target::{Os, Target};

/// A Go c-archive build request.
pub struct CArchive<'a> {
    /// Directory containing the `go.mod` to build from.
    pub module_dir: &'a Path,
    /// Package path within the module, e.g. `.`.
    pub package: &'a str,
    /// Output archive name without extension, e.g. `libtun2socks_bridge`.
    pub lib_name: &'a str,
    pub target: Target,
    /// Android API level for the NDK toolchain.
    pub android_api: u32,
    /// Extra `-ldflags` entries.
    pub ldflags: Vec<String>,
    /// Go build tags.
    pub tags: Vec<String>,
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

impl<'a> CArchive<'a> {
    pub fn new(module_dir: &'a Path, package: &'a str, lib_name: &'a str) -> Self {
        Self {
            module_dir,
            package,
            lib_name,
            target: Target::from_cargo_env(),
            android_api: 21,
            ldflags: vec!["-s".into(), "-w".into()],
            tags: Vec::new(),
        }
    }

    /// Path to the `go` binary, honouring `GO_BIN`/`GOROOT`.
    fn go_bin() -> Result<String, GoError> {
        for candidate in [
            std::env::var("GO_BIN").ok(),
            std::env::var("GOROOT")
                .ok()
                .map(|r| PathBuf::from(r).join("bin").join("go").display().to_string()),
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
            "`go` not found on PATH. Install Go 1.26.3+ (https://go.dev/dl/) or set GO_BIN.".into(),
        ))
    }

    /// Resolve the C compiler cgo should use for this target.
    pub fn cc_for(target: Target, android_api: u32) -> Result<String, GoError> {
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
            Os::Windows if !cfg!(target_os = "windows") => {
                // Cross-compiling to Windows: MinGW, matching .cargo/config.toml.
                Ok("x86_64-w64-mingw32-gcc".into())
            }
            _ => Ok(std::env::var("CC").unwrap_or_else(|_| "cc".into())),
        }
    }

    /// Build the archive into `OUT_DIR`.
    /// Run an auxiliary `go` subcommand (module resolution, etc.) in
    /// `module_dir`, surfacing its stderr verbatim when it fails.
    fn run_go_step(
        go: &str,
        module_dir: &Path,
        args: &[&str],
        what: &str,
    ) -> Result<(), GoError> {
        crate::note(format!("{what}..."));
        let output = Command::new(go)
            .current_dir(module_dir)
            .args(args)
            .env("GOFLAGS", "-mod=mod")
            .env("CGO_ENABLED", "0")
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

    pub fn build(&self) -> Result<Built, GoError> {
        let go = Self::go_bin()?;
        let cc = Self::cc_for(self.target, self.android_api)?;

        let out_dir = PathBuf::from(
            std::env::var("OUT_DIR").map_err(|_| GoError::Build("OUT_DIR unset".into()))?,
        );
        // Android's Go toolchain supports only c-shared; everywhere else we
        // prefer c-archive so the Go code is statically linked and there is
        // no extra file to ship.
        let shared = self.target.is_android();
        let buildmode = if shared { "c-shared" } else { "c-archive" };
        let ext = if shared { "so" } else { self.target.static_lib_ext() };

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
        Self::run_go_step(
            &go,
            self.module_dir,
            &["mod", "tidy"],
            "resolve Go dependencies (go mod tidy)",
        )?;

        let mut cmd = Command::new(&go);
        cmd.current_dir(self.module_dir)
            .arg("build")
            .arg(format!("-buildmode={buildmode}"))
            .arg("-trimpath");

        if !self.tags.is_empty() {
            cmd.arg("-tags").arg(self.tags.join(","));
        }
        if !self.ldflags.is_empty() {
            cmd.arg("-ldflags").arg(self.ldflags.join(" "));
        }
        cmd.arg("-o").arg(&archive).arg(self.package);

        // cgo is mandatory for c-archive.
        cmd.env("CGO_ENABLED", "1")
            .env("GOOS", self.target.goos())
            .env("GOARCH", self.target.goarch())
            .env("CC", &cc);

        if let Some(goarm) = self.target.goarm() {
            cmd.env("GOARM", goarm);
        }
        if self.target.is_android() {
            cmd.env("CGO_CFLAGS", "-O2 -fPIC")
                // 16 KiB pages are required by recent Android releases.
                .env("CGO_LDFLAGS", "-Wl,-z,max-page-size=16384");
        }
        if self.target.is_apple() {
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
        if !self.shared {
            return Ok(());
        }
        let abi = target.android_abi();
        let dest_dir = repo_root
            .join("android/app/src/main/jniLibs")
            .join(abi);
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

    /// Emit the `cargo:rustc-link-*` directives needed to link this archive,
    /// including the platform libraries the Go runtime itself requires.
    pub fn emit_link_directives(&self, lib_name: &str, target: Target) {
        println!(
            "cargo:rustc-link-search=native={}",
            self.search_dir.display()
        );
        // `lib_name` arrives as `libfoo`; rustc wants `foo`.
        let link_name = lib_name.strip_prefix("lib").unwrap_or(lib_name);
        if self.shared {
            // Android: c-shared produces a .so, so link it dynamically. The
            // runtime loader finds it via jniLibs/<abi>/ (see staged_so).
            println!("cargo:rustc-link-lib=dylib={link_name}");
        } else {
            println!("cargo:rustc-link-lib=static={link_name}");
        }

        match target.os {
            Os::Windows => {
                // The Go runtime's netpoller and process APIs.
                for l in ["ws2_32", "winmm", "ntdll", "userenv", "iphlpapi", "bcrypt"] {
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
            } else if p.extension().and_then(|s| s.to_str()).is_some_and(|e| e == "go")
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

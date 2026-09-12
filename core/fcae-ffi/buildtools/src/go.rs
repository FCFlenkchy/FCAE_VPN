//! Cross-compiling Go packages to **c-archives** for static linking.
//!
//! This is what makes tun2socks (and later Psiphon, which is also Go) run
//! in-process. Instead of `go build -o tun2socks.exe` and shipping an
//! executable, we do `go build -buildmode=c-archive -o libX.a` and hand the
//! archive to rustc, so the Go runtime lives inside our own library.
//!
//! c-archive requires cgo, which requires a C cross-compiler for the target.
//! [`CArchive::cc_for`] resolves the right one (NDK clang for Android, MinGW
//! for Windows, `cc`/`clang` otherwise) and fails with an actionable message
//! rather than emitting a mystery linker error later.

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

/// Where the built archive and its generated header ended up.
pub struct Built {
    pub archive: PathBuf,
    pub header: PathBuf,
    pub search_dir: PathBuf,
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
            "`go` not found on PATH. Install Go 1.22+ (https://go.dev/dl/) or set GO_BIN.".into(),
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
    pub fn build(&self) -> Result<Built, GoError> {
        let go = Self::go_bin()?;
        let cc = Self::cc_for(self.target, self.android_api)?;

        let out_dir = PathBuf::from(
            std::env::var("OUT_DIR").map_err(|_| GoError::Build("OUT_DIR unset".into()))?,
        );
        let archive = out_dir.join(format!("{}.{}", self.lib_name, self.target.static_lib_ext()));
        let header = out_dir.join(format!("{}.h", self.lib_name));

        crate::note(format!(
            "building {} as a Go c-archive for {}/{} (in-process; no subprocess)",
            self.package,
            self.target.goos(),
            self.target.goarch()
        ));

        let mut cmd = Command::new(&go);
        cmd.current_dir(self.module_dir)
            .arg("build")
            .arg("-buildmode=c-archive")
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
        })
    }
}

impl Built {
    /// Emit the `cargo:rustc-link-*` directives needed to link this archive,
    /// including the platform libraries the Go runtime itself requires.
    pub fn emit_link_directives(&self, lib_name: &str, target: Target) {
        println!(
            "cargo:rustc-link-search=native={}",
            self.search_dir.display()
        );
        // `lib_name` arrives as `libfoo`; rustc wants `foo`.
        let link_name = lib_name.strip_prefix("lib").unwrap_or(lib_name);
        println!("cargo:rustc-link-lib=static={link_name}");

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

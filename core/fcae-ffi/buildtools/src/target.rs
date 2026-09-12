//! The single canonical Rust-target → platform table.
//!
//! Previously the Rust→Go mapping, the Android ABI mapping and the wintun
//! architecture mapping were three separate `match` blocks that could (and
//! did) disagree. They all derive from this one type now.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    Windows,
    Linux,
    MacOS,
    Android,
    Ios,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X86_64,
    Aarch64,
    Arm,
    X86,
    Riscv64,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Target {
    pub os: Os,
    pub arch: Arch,
}

impl Target {
    /// Read the target being *built for* from cargo's env (never the host —
    /// getting this wrong is what broke cross-compiling to Windows from CI).
    pub fn from_cargo_env() -> Self {
        let os = match std::env::var("CARGO_CFG_TARGET_OS")
            .unwrap_or_default()
            .as_str()
        {
            "windows" => Os::Windows,
            "linux" => Os::Linux,
            "macos" => Os::MacOS,
            "android" => Os::Android,
            "ios" => Os::Ios,
            _ => Os::Other,
        };
        let arch = match std::env::var("CARGO_CFG_TARGET_ARCH")
            .unwrap_or_default()
            .as_str()
        {
            "x86_64" => Arch::X86_64,
            "aarch64" => Arch::Aarch64,
            "arm" | "armv7" | "thumbv7neon" => Arch::Arm,
            "x86" | "i686" | "i586" => Arch::X86,
            "riscv64" => Arch::Riscv64,
            _ => Arch::Other,
        };
        Self { os, arch }
    }

    /// `GOOS`. Android maps to `android` (not `linux`): now that we build a
    /// c-archive linked into our own `.so`, cgo is available and the real
    /// Android target is correct — the old `GOOS=linux, CGO_ENABLED=0` hack
    /// existed only to dodge external linking for a standalone executable.
    pub fn goos(&self) -> &'static str {
        match self.os {
            Os::Windows => "windows",
            Os::Linux => "linux",
            Os::MacOS => "darwin",
            Os::Android => "android",
            Os::Ios => "ios",
            Os::Other => "linux",
        }
    }

    pub fn goarch(&self) -> &'static str {
        match self.arch {
            Arch::X86_64 => "amd64",
            Arch::Aarch64 => "arm64",
            Arch::Arm => "arm",
            Arch::X86 => "386",
            Arch::Riscv64 => "riscv64",
            Arch::Other => "amd64",
        }
    }

    /// `GOARM` for 32-bit ARM; `None` elsewhere.
    pub fn goarm(&self) -> Option<&'static str> {
        (self.arch == Arch::Arm).then_some("7")
    }

    /// Android NDK ABI directory name.
    pub fn android_abi(&self) -> &'static str {
        match self.arch {
            Arch::Aarch64 => "arm64-v8a",
            Arch::Arm => "armeabi-v7a",
            Arch::X86 => "x86",
            _ => "x86_64",
        }
    }

    /// NDK clang prefix, e.g. `aarch64-linux-android21`.
    pub fn ndk_clang_triple(&self, api_level: u32) -> String {
        let base = match self.arch {
            Arch::Aarch64 => "aarch64-linux-android",
            Arch::Arm => "armv7a-linux-androideabi",
            Arch::X86 => "i686-linux-android",
            _ => "x86_64-linux-android",
        };
        format!("{base}{api_level}")
    }

    /// Architecture folder inside the official wintun zip.
    pub fn wintun_arch(&self) -> &'static str {
        match self.arch {
            Arch::Aarch64 => "arm64",
            Arch::Arm => "arm",
            Arch::X86 => "x86",
            _ => "amd64",
        }
    }

    /// Static library extension for the target. MinGW and MSVC both accept
    /// `.a` from Go's c-archive output.
    pub fn static_lib_ext(&self) -> &'static str {
        "a"
    }

    pub fn is_windows(&self) -> bool {
        self.os == Os::Windows
    }

    pub fn is_android(&self) -> bool {
        self.os == Os::Android
    }

    pub fn is_apple(&self) -> bool {
        matches!(self.os, Os::MacOS | Os::Ios)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn android_uses_the_real_goos() {
        let t = Target {
            os: Os::Android,
            arch: Arch::Aarch64,
        };
        assert_eq!(t.goos(), "android");
        assert_eq!(t.goarch(), "arm64");
        assert_eq!(t.android_abi(), "arm64-v8a");
        assert_eq!(t.ndk_clang_triple(21), "aarch64-linux-android21");
    }

    #[test]
    fn arm32_sets_goarm() {
        let t = Target {
            os: Os::Android,
            arch: Arch::Arm,
        };
        assert_eq!(t.goarm(), Some("7"));
        assert_eq!(t.ndk_clang_triple(21), "armv7a-linux-androideabi21");
    }

    #[test]
    fn non_arm_has_no_goarm() {
        let t = Target {
            os: Os::Linux,
            arch: Arch::X86_64,
        };
        assert_eq!(t.goarm(), None);
        assert_eq!(t.goos(), "linux");
    }
}

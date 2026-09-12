//! # fcae-build — shared build-script helpers
//!
//! The old `aether-engine/build.rs` was 540 lines that did Go compilation,
//! wintun downloading, Android jniLibs packaging and target mapping all in
//! one file, in one crate. Anything else that needed the same logic had to
//! copy it.
//!
//! Here each concern is a module, and a crate's `build.rs` becomes a few
//! calls. Nothing in this crate has dependencies, so it never bloats build
//! time.

pub mod go;
pub mod header;
pub mod target;
pub mod wintun;

/// Emit a `cargo:warning=` line (the only way a build script can talk to the
/// user).
pub fn note(msg: impl AsRef<str>) {
    println!("cargo:warning={}", msg.as_ref());
}

/// Re-run this build script if `path` changes.
pub fn rerun_if_changed(path: impl AsRef<std::path::Path>) {
    println!("cargo:rerun-if-changed={}", path.as_ref().display());
}

/// Re-run if an environment variable changes.
pub fn rerun_if_env_changed(key: &str) {
    println!("cargo:rerun-if-env-changed={key}");
}

/// Locate the repository root by walking up from `CARGO_MANIFEST_DIR` until a
/// directory containing `.gitmodules` (or `.git`) is found.
///
/// The old build script hardcoded `parent().parent().parent()`, which broke
/// the moment a crate moved one level deeper — exactly what this refactor
/// does.
pub fn repo_root() -> std::path::PathBuf {
    let manifest = std::path::PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is always set by cargo"),
    );
    let mut dir = manifest.as_path();
    loop {
        if dir.join(".gitmodules").is_file() || dir.join(".git").exists() {
            return dir.to_path_buf();
        }
        match dir.parent() {
            Some(p) => dir = p,
            None => return manifest,
        }
    }
}

//! C header generation / verification.
//!
//! `include/fcae.h` is committed so that C++ and Gradle builds do not need a
//! Rust toolchain to see the ABI. The risk with a committed generated file is
//! drift, so [`verify`] re-derives a fingerprint of the ABI source and fails
//! the build when the header is stale.
//!
//! cbindgen is intentionally *not* a hard dependency: when it is installed the
//! header is regenerated, otherwise we only check the fingerprint.

use std::path::Path;
use std::process::Command;

/// Marker line appended to the generated header carrying the fingerprint.
const FINGERPRINT_PREFIX: &str = "/* fcae-abi-fingerprint: ";

/// Cheap digest of the ABI source text.
///
/// FNV-1a over comment-stripped, whitespace-stripped bytes: reformatting or
/// re-wording a doc comment must not force a regeneration, but any real
/// declaration change must.
fn fingerprint(src: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut in_line_comment = false;
    let mut prev = '\0';
    for c in src.chars() {
        if in_line_comment {
            if c == '\n' {
                in_line_comment = false;
            }
            continue;
        }
        if prev == '/' && c == '/' {
            in_line_comment = true;
            continue;
        }
        prev = c;
        if c.is_whitespace() || c == '/' {
            continue;
        }
        hash ^= c as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Regenerate `header_path` from the `fcae-abi` crate if cbindgen is present.
///
/// Returns `true` if the header was (re)written.
pub fn generate(abi_crate_dir: &Path, header_path: &Path) -> bool {
    crate::rerun_if_changed(abi_crate_dir.join("src/lib.rs"));

    let result = Command::new("cbindgen")
        .arg("--lang")
        .arg("c")
        .arg("--crate")
        .arg("fcae-abi")
        .arg("--output")
        .arg(header_path)
        .current_dir(abi_crate_dir)
        .status();

    match result {
        Ok(status) if status.success() => {
            // cbindgen emits no marker of its own, so the freshly written file
            // would fail [`verify`] on the next build -- every machine with
            // cbindgen installed would hand CI an unstamped header.
            if let Err(e) = stamp(&abi_crate_dir.join("src/lib.rs"), header_path) {
                crate::note(format!("cannot stamp the regenerated header: {e}"));
            }
            true
        }
        other => {
            match other {
                Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => {},
                Err(e) => crate::note(format!("cannot run cbindgen: {e}; checking the committed header")),
                Ok(status) => crate::note(format!("cbindgen exited with {status}; checking the committed header")),
            }
            verify(&abi_crate_dir.join("src/lib.rs"), header_path)
                .unwrap_or_else(|e| panic!("{e}"));
            false
        }
    }
}

/// Fail the build if the committed header's fingerprint does not match the
/// current ABI source. Call this from CI.
pub fn verify(abi_src: &Path, header_path: &Path) -> Result<(), String> {
    let src = std::fs::read_to_string(abi_src)
        .map_err(|e| format!("cannot read {}: {e}", abi_src.display()))?;
    let header = std::fs::read_to_string(header_path)
        .map_err(|e| format!("cannot read {}: {e}", header_path.display()))?;

    let expected = fingerprint(&src);
    let found = header
        .lines()
        .find_map(|l| l.trim().strip_prefix(FINGERPRINT_PREFIX))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|h| u64::from_str_radix(h.trim_start_matches("0x"), 16).ok());

    match found {
        Some(f) if f == expected => Ok(()),
        Some(f) => Err(format!(
            "include/fcae.h is stale (header fingerprint 0x{f:016x}, ABI 0x{expected:016x}). \
             Regenerate with `cargo run -p fcae-build --bin stamp-header`."
        )),
        None => Err(format!(
            "{} has no fingerprint marker; regenerate it.",
            header_path.display()
        )),
    }
}

/// The line to append to a freshly generated header.
pub fn fingerprint_line(abi_src: &Path) -> std::io::Result<String> {
    let src = std::fs::read_to_string(abi_src)?;
    Ok(format!(
        "{FINGERPRINT_PREFIX}0x{:016x} */\n",
        fingerprint(&src)
    ))
}

/// Rewrite `header_path` with the current fingerprint as its last line,
/// dropping any marker it carried before.
///
/// Idempotent, so it is safe to run over a header cbindgen has just written and
/// over one that is already stamped.
pub fn stamp(abi_src: &Path, header_path: &Path) -> std::io::Result<()> {
    let line = fingerprint_line(abi_src)?;
    let text = std::fs::read_to_string(header_path)?;

    let mut kept: Vec<&str> = text
        .lines()
        .filter(|l| !l.trim_start().starts_with(FINGERPRINT_PREFIX))
        .collect();
    while kept.last().is_some_and(|l| l.trim().is_empty()) {
        kept.pop();
    }

    let mut out = kept.join("\n");
    out.push_str("\n\n");
    out.push_str(&line);
    std::fs::write(header_path, out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comments_and_formatting_do_not_change_the_fingerprint() {
        let a = "pub struct X { pub a: u32 }";
        let b = "// a comment\npub struct X {\n    pub a: u32\n}\n";
        assert_eq!(fingerprint(a), fingerprint(b));
    }

    #[test]
    fn declaration_changes_do_change_it() {
        let a = "pub struct X { pub a: u32 }";
        let b = "pub struct X { pub a: u64 }";
        assert_ne!(fingerprint(a), fingerprint(b));
    }
}

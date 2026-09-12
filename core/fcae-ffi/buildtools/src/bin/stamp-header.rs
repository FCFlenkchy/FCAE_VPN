//! Stamp `include/fcae.h` with the current ABI fingerprint.
//!
//! Run after editing `abi/src/lib.rs`:
//!
//! ```sh
//! cargo run -p fcae-build --bin stamp-header
//! ```
//!
//! CI calls `fcae_build::header::verify` to fail on drift.

fn main() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let abi = root.join("../abi/src/lib.rs");
    let header = root.join("../include/fcae.h");

    let line = fcae_build::header::fingerprint_line(&abi).expect("read abi source");
    let text = std::fs::read_to_string(&header).expect("read header");

    let mut kept: Vec<&str> = text
        .lines()
        .filter(|l| !l.trim_start().starts_with("/* fcae-abi-fingerprint:"))
        .collect();
    while kept.last().map(|l| l.trim().is_empty()).unwrap_or(false) {
        kept.pop();
    }

    let mut out = kept.join("\n");
    out.push_str("\n\n");
    out.push_str(&line);
    std::fs::write(&header, out).expect("write header");

    println!("stamped {}", header.display());
}

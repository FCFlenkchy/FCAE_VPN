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

    fcae_build::header::stamp(&abi, &header).expect("stamp the header");

    println!("stamped {}", header.display());
}

//! Generates/validates the C header for the ABI.

use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let abi_dir = manifest.join("../abi");
    let header = manifest.join("../include/fcae.h");

    fcae_build::rerun_if_changed(abi_dir.join("src/lib.rs"));
    fcae_build::rerun_if_changed(&header);

    // Regenerate when cbindgen is installed; otherwise the committed header
    // is used as-is. CI runs `verify` to catch drift.
    fcae_build::header::generate(&abi_dir, &header);
}

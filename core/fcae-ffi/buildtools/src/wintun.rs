//! Windows: obtain `wintun.dll` at build time.
//!
//! Same sources as before (download from wintun.net, extract the right
//! architecture) but pulled out of the engine's build script and given a size
//! check, so a captive-portal page or a truncated download can no longer be
//! embedded as if it were a DLL.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::target::Target;

const WINTUN_URL: &str = "https://www.wintun.net/builds/wintun-0.14.1.zip";
/// Any real wintun.dll is comfortably larger than this.
const MIN_PLAUSIBLE_DLL: u64 = 64 * 1024;

/// Fetch and stage `wintun.dll` for `target` into `OUT_DIR`.
///
/// Returns the staged path, or `None` when the target is not Windows or the
/// download failed (the caller decides whether that is fatal).
pub fn stage(target: Target) -> Option<PathBuf> {
    if !target.is_windows() {
        return None;
    }

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").ok()?);
    let dest = out_dir.join("wintun.dll");

    if dest.metadata().map(|m| m.len()).unwrap_or(0) >= MIN_PLAUSIBLE_DLL {
        return Some(dest);
    }

    // A vendored copy short-circuits the network entirely — useful for
    // hermetic/offline CI.
    if let Ok(local) = std::env::var("WINTUN_DLL") {
        let p = PathBuf::from(local);
        if p.is_file() && std::fs::copy(&p, &dest).is_ok() {
            crate::note(format!("wintun.dll taken from WINTUN_DLL={}", p.display()));
            return Some(dest);
        }
    }

    let tmp = std::env::temp_dir().join("fcae_wintun.zip");
    let extract = std::env::temp_dir().join("fcae_wintun_extract");
    let _ = std::fs::remove_file(&tmp);
    let _ = std::fs::remove_dir_all(&extract);

    if !download(WINTUN_URL, &tmp) {
        crate::note("could not download wintun.dll — TUN will not work on Windows");
        return None;
    }
    if !extract_dll(&tmp, &extract, &dest, target.wintun_arch()) {
        crate::note("could not extract wintun.dll from the downloaded archive");
        return None;
    }

    let _ = std::fs::remove_file(&tmp);
    let _ = std::fs::remove_dir_all(&extract);

    match dest.metadata() {
        Ok(m) if m.len() >= MIN_PLAUSIBLE_DLL => {
            crate::note(format!("wintun.dll ({}) staged", target.wintun_arch()));
            Some(dest)
        }
        _ => {
            crate::note("staged wintun.dll looks corrupt (too small); discarding");
            let _ = std::fs::remove_file(&dest);
            None
        }
    }
}

fn download(url: &str, dest: &Path) -> bool {
    if run(
        "curl",
        &[
            "-fsSL",
            "--connect-timeout",
            "30",
            "--max-time",
            "180",
            "-o",
            &dest.display().to_string(),
            url,
        ],
    ) {
        return true;
    }
    if run(
        "wget",
        &["-q", "--timeout=30", "-O", &dest.display().to_string(), url],
    ) {
        return true;
    }
    if cfg!(target_os = "windows") {
        let script = format!(
            "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; \
             Invoke-WebRequest -Uri '{url}' -OutFile '{}' -UseBasicParsing",
            dest.display()
        );
        return run("powershell", &["-NoProfile", "-Command", &script]);
    }
    false
}

fn extract_dll(zip: &Path, workdir: &Path, dest: &Path, arch: &str) -> bool {
    let _ = std::fs::create_dir_all(workdir);

    let extracted = if cfg!(target_os = "windows") {
        run(
            "powershell",
            &[
                "-NoProfile",
                "-Command",
                &format!(
                    "Expand-Archive -Path '{}' -DestinationPath '{}' -Force",
                    zip.display(),
                    workdir.display()
                ),
            ],
        )
    } else {
        run(
            "unzip",
            &[
                "-oq",
                &zip.display().to_string(),
                "-d",
                &workdir.display().to_string(),
            ],
        )
    };
    if !extracted {
        return false;
    }

    // wintun/bin/<arch>/wintun.dll
    let direct = workdir
        .join("wintun")
        .join("bin")
        .join(arch)
        .join("wintun.dll");
    if direct.is_file() {
        return std::fs::copy(&direct, dest).is_ok();
    }
    // Fall back to a shallow search in case the layout changes.
    find_dll(workdir, arch, 0)
        .map(|p| std::fs::copy(p, dest).is_ok())
        .unwrap_or(false)
}

fn find_dll(dir: &Path, arch: &str, depth: usize) -> Option<PathBuf> {
    if depth > 5 {
        return None;
    }
    for e in std::fs::read_dir(dir).ok()?.flatten() {
        let p = e.path();
        if p.is_dir() {
            if let Some(found) = find_dll(&p, arch, depth + 1) {
                return Some(found);
            }
        } else if p.file_name().and_then(|s| s.to_str()) == Some("wintun.dll")
            && p.parent()
                .and_then(|d| d.file_name())
                .and_then(|s| s.to_str())
                == Some(arch)
        {
            return Some(p);
        }
    }
    None
}

fn run(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

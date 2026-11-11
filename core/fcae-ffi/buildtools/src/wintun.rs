//! Windows: obtain `wintun.dll` at build time.
//!
//! Same sources as before (download from wintun.net, extract the right
//! architecture) but pulled out of the engine's build script and given a size
//! check, so a captive-portal page or a truncated download can no longer be
//! embedded as if it were a DLL.

use std::io::{Read, Seek, SeekFrom};
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

    crate::rerun_if_env_changed("WINTUN_DLL");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").ok()?);
    let dest = out_dir.join("wintun.dll");
    let arch = target.wintun_arch();

    // An explicit override must not be shadowed by a cached DLL, and must
    // match the target rather than the build host.
    if let Some(local) = std::env::var_os("WINTUN_DLL") {
        let p = PathBuf::from(local);
        crate::rerun_if_changed(&p);
        if !plausible_dll(&p, arch) {
            crate::note(format!("WINTUN_DLL={} is not a plausible {arch} DLL", p.display()));
            return None;
        }
        if p != dest && std::fs::copy(&p, &dest).is_err() {
            crate::note("could not stage WINTUN_DLL");
            return None;
        }
        return Some(dest);
    }
    if plausible_dll(&dest, arch) {
        return Some(dest);
    }
    let _ = std::fs::remove_file(&dest);

    let tmp = out_dir.join("wintun-download.zip");
    let extract = out_dir.join("wintun-extract");
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

    if plausible_dll(&dest, arch) {
        crate::note(format!("wintun.dll ({arch}) staged"));
        Some(dest)
    } else {
        crate::note(format!("staged wintun.dll is not a plausible {arch} DLL; discarding"));
        let _ = std::fs::remove_file(&dest);
        None
    }
}

fn plausible_dll(path: &Path, arch: &str) -> bool {
    let machine = match arch {
        "x86" => 0x014c_u16,
        "amd64" => 0x8664,
        "arm" => 0x01c4,
        "arm64" => 0xaa64,
        _ => return false,
    };
    let check = || -> std::io::Result<bool> {
        let mut file = std::fs::File::open(path)?;
        let len = file.metadata()?.len();
        if len < MIN_PLAUSIBLE_DLL { return Ok(false); }
        let mut dos = [0u8; 64];
        file.read_exact(&mut dos)?;
        if &dos[..2] != b"MZ" { return Ok(false); }
        let offset = u32::from_le_bytes(dos[60..64].try_into().unwrap()) as u64;
        if offset < 64 || offset.checked_add(24).is_none_or(|end| end > len) { return Ok(false); }
        file.seek(SeekFrom::Start(offset))?;
        let mut pe = [0u8; 24];
        file.read_exact(&mut pe)?;
        Ok(&pe[..4] == b"PE\0\0"
            && u16::from_le_bytes([pe[4], pe[5]]) == machine
            && u16::from_le_bytes([pe[22], pe[23]]) & 0x2000 != 0)
    };
    check().unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_architecture_and_dll_header() {
        let path = std::env::temp_dir().join(format!("fcae-wintun-test-{}-{:?}", std::process::id(), std::thread::current().id()));
        let mut data = vec![0u8; MIN_PLAUSIBLE_DLL as usize];
        data[..2].copy_from_slice(b"MZ");
        data[60..64].copy_from_slice(&128u32.to_le_bytes());
        data[128..132].copy_from_slice(b"PE\0\0");
        data[132..134].copy_from_slice(&0x8664u16.to_le_bytes());
        data[150..152].copy_from_slice(&0x2000u16.to_le_bytes());
        std::fs::write(&path, &data).unwrap();
        assert!(plausible_dll(&path, "amd64"));
        assert!(!plausible_dll(&path, "x86"));
        data[150] = 0;
        data[151] = 0;
        std::fs::write(&path, &data).unwrap();
        assert!(!plausible_dll(&path, "amd64"));
        data[60..64].copy_from_slice(&u32::MAX.to_le_bytes());
        std::fs::write(&path, &data).unwrap();
        assert!(!plausible_dll(&path, "amd64"));
        std::fs::remove_file(path).unwrap();
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

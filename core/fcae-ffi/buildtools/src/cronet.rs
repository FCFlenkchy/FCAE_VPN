//! Windows: obtain `libcronet.dll` at build time, so the Windows app can embed
//! it instead of shipping a second file.
//!
//! cronet-go publishes no static cronet for Windows (Chromium is built with
//! MSVC there, and a cgo link can only use MinGW), so Windows is the one
//! platform whose executable cannot carry cronet inside itself. What it can do
//! is carry the DLL inside the executable and unpack it at run time, the way
//! `wintun.dll` already works — plus one extra step: cronet-go's purego loader
//! searches the executable's directory and `PATH`, so the unpacked DLL has to be
//! made visible to it (see `fcae_runtime::cronet`).

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::target::Target;

/// The cronet-go module that carries the Windows artifact.
const CRONET_MODULE: &str = "github.com/sagernet/cronet-go/lib/windows_amd64";
/// Same artifact the frontend stages for Linux and macOS. A real DLL is far
/// larger than this, so a captive-portal page cannot pass as one.
const MIN_PLAUSIBLE_DLL: u64 = 1024 * 1024;

/// Fetch and stage `libcronet.dll` for `target` into `OUT_DIR`.
///
/// Returns the staged path, or `None` when the target is not Windows or nothing
/// could be staged (the caller decides whether that is fatal).
pub fn stage(target: Target) -> Option<PathBuf> {
    if !target.is_windows() {
        return None;
    }

    crate::rerun_if_env_changed("CRONET_DLL");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").ok()?);
    let dest = out_dir.join("libcronet.dll");

    // An explicit override must not be shadowed by a cached copy.
    if let Some(local) = std::env::var_os("CRONET_DLL") {
        let path = PathBuf::from(local);
        crate::rerun_if_changed(&path);
        if !plausible_dll(&path) {
            crate::note(format!("CRONET_DLL={} is not a plausible AMD64 DLL", path.display()));
            return None;
        }
        if path != dest && std::fs::copy(&path, &dest).is_err() {
            crate::note("could not stage CRONET_DLL");
            return None;
        }
        crate::note("libcronet.dll staged from CRONET_DLL");
        return Some(dest);
    }
    if plausible_dll(&dest) {
        return Some(dest);
    }
    let _ = std::fs::remove_file(&dest);

    // The version the Go side pins: it names both what to embed and what to
    // fetch, so the DLL and the binding that loads it cannot drift apart.
    let pinned = pinned_version();

    // The Go build fetches this module anyway, so a warm cache makes the embed
    // free; only a cold one pays for the download.
    if let Some(cached) = cached_dll(pinned.as_deref()) {
        if std::fs::copy(&cached, &dest).is_ok() && plausible_dll(&dest) {
            crate::note(format!("libcronet.dll staged from {}", cached.display()));
            return Some(dest);
        }
        let _ = std::fs::remove_file(&dest);
    }

    let version = match pinned {
        Some(version) => version,
        None => {
            crate::note("no cronet-go version is pinned for the Windows artifact; \
                         set CRONET_DLL to a libcronet.dll to embed one");
            return None;
        }
    };
    let url = format!("https://proxy.golang.org/{CRONET_MODULE}/@v/{version}.zip");
    let archive = out_dir.join("libcronet-download.zip");
    let extract = out_dir.join("libcronet-extract");
    let _ = std::fs::remove_file(&archive);
    let _ = std::fs::remove_dir_all(&extract);

    if !download(&url, &archive) {
        crate::note(format!("could not download libcronet.dll {version}"));
        return None;
    }
    let staged = extract_dll(&archive, &extract, &dest);
    let _ = std::fs::remove_file(&archive);
    let _ = std::fs::remove_dir_all(&extract);
    if !staged || !plausible_dll(&dest) {
        crate::note("staged libcronet.dll is not a plausible AMD64 DLL; discarding");
        let _ = std::fs::remove_file(&dest);
        return None;
    }
    crate::note(format!("libcronet.dll ({version}) staged"));
    Some(dest)
}

/// Stage `libcronet.dll` for `target` into `OUT_DIR` (see [`stage`]) and, when
/// one was produced, emit both the `cronet_staged` rustc-cfg and the rustc-env
/// variable carrying the staged path.
///
/// The accessor side is `fcae_runtime::cronet::cronet_bytes()`. A build that
/// stages none is not fatal: Windows then behaves exactly as it did before the
/// DLL was embedded, and only a naive outbound reports the library as missing.
pub fn stage_and_emit(target: Target, env: &str) {
    if let Some(dll) = stage(target) {
        println!("cargo:rustc-cfg=cronet_staged");
        println!("cargo:rustc-env={env}={}", dll.display());
    }
}

/// A plausible `libcronet.dll` already in the Go module cache. The Go build
/// needs this module for sing-box's naive outbound, so it is there on anything
/// but a cold machine — `pinned` decides which copy, and the newest stands in
/// when the cache holds a different one.
fn cached_dll(pinned: Option<&str>) -> Option<PathBuf> {
    let cache = go_mod_cache()?;
    let mut newest: Option<(String, PathBuf)> = None;
    for entry in std::fs::read_dir(cache.join("github.com/sagernet/cronet-go/lib"))
        .ok()?
        .flatten()
    {
        // `windows_amd64@v0.0.0-<timestamp>-<hash>`
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(version) = name.strip_prefix("windows_amd64@") else {
            continue;
        };
        let dll = entry.path().join("libcronet.dll");
        if !plausible_dll(&dll) {
            continue;
        }
        if pinned == Some(version) {
            return Some(dll);
        }
        // Pseudo-versions of one module sort by timestamp as text.
        if newest.as_ref().is_none_or(|(current, _)| version > current.as_str()) {
            newest = Some((version.to_string(), dll));
        }
    }
    newest.map(|(_, dll)| dll)
}

/// Where the Go build keeps its module cache.
fn go_mod_cache() -> Option<PathBuf> {
    if let Some(cache) = std::env::var_os("GOMODCACHE") {
        return Some(PathBuf::from(cache));
    }
    if let Ok(output) = Command::new("go").args(["env", "GOMODCACHE"]).output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Some(PathBuf::from(path));
            }
        }
    }
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(|home| PathBuf::from(home).join("go/pkg/mod"))
}

/// The version the Go bridge resolves for the Windows artifact, as recorded by
/// sing-box, whose `go.mod` is the checked-in pin the whole archive shares.
fn pinned_version() -> Option<String> {
    let go_mod = crate::repo_root().join("core/sing-box/go.mod");
    crate::rerun_if_changed(&go_mod);
    let text = std::fs::read_to_string(&go_mod).ok()?;
    requirement(&text)
}

/// The version `go.mod` requires for [`CRONET_MODULE`], if it names one.
fn requirement(go_mod: &str) -> Option<String> {
    go_mod.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        if fields.next()? != CRONET_MODULE {
            return None;
        }
        let version = fields.next()?;
        version.starts_with('v').then(|| version.to_string())
    })
}

fn plausible_dll(path: &Path) -> bool {
    const MACHINE_AMD64: u16 = 0x8664;
    let check = || -> std::io::Result<bool> {
        let mut file = std::fs::File::open(path)?;
        let len = file.metadata()?.len();
        if len < MIN_PLAUSIBLE_DLL {
            return Ok(false);
        }
        let mut dos = [0u8; 64];
        file.read_exact(&mut dos)?;
        if &dos[..2] != b"MZ" {
            return Ok(false);
        }
        let offset = u32::from_le_bytes(dos[60..64].try_into().unwrap()) as u64;
        if offset < 64 || offset.checked_add(24).is_none_or(|end| end > len) {
            return Ok(false);
        }
        file.seek(SeekFrom::Start(offset))?;
        let mut pe = [0u8; 24];
        file.read_exact(&mut pe)?;
        Ok(&pe[..4] == b"PE\0\0"
            && u16::from_le_bytes([pe[4], pe[5]]) == MACHINE_AMD64
            // PE32+: a 64-bit image, not a 32-bit or IL-only one.
            && u16::from_le_bytes([pe[22], pe[23]]) & 0x2000 != 0)
    };
    check().unwrap_or(false)
}

fn download(url: &str, dest: &Path) -> bool {
    if run(
        "curl",
        &[
            "-fsSL",
            "--connect-timeout",
            "30",
            "--max-time",
            "600",
            "-o",
            &dest.display().to_string(),
            url,
        ],
    ) {
        return true;
    }
    if run("wget", &["-q", "--timeout=30", "-O", &dest.display().to_string(), url]) {
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

/// Pull `libcronet.dll` out of a module zip. The layout is fixed
/// (`<module>@<version>/libcronet.dll`), but the name is searched for so a
/// change in how the module is packed is a skip rather than a wrong file.
fn extract_dll(archive: &Path, workdir: &Path, dest: &Path) -> bool {
    let _ = std::fs::create_dir_all(workdir);
    let extracted = if cfg!(target_os = "windows") {
        run(
            "powershell",
            &[
                "-NoProfile",
                "-Command",
                &format!(
                    "Expand-Archive -Path '{}' -DestinationPath '{}' -Force",
                    archive.display(),
                    workdir.display()
                ),
            ],
        )
    } else {
        run(
            "unzip",
            &["-oq", &archive.display().to_string(), "-d", &workdir.display().to_string()],
        )
    };
    if !extracted {
        return false;
    }
    find_dll(workdir, 0)
        .map(|found| std::fs::copy(found, dest).is_ok())
        .unwrap_or(false)
}

fn find_dll(dir: &Path, depth: usize) -> Option<PathBuf> {
    if depth > 5 {
        return None;
    }
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Some(found) = find_dll(&path, depth + 1) {
                return Some(found);
            }
        } else if path.file_name().and_then(|name| name.to_str()) == Some("libcronet.dll") {
            return Some(path);
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
        .map(|status| status.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_pinned_version() {
        let go_mod = "module github.com/sagernet/sing-box\n\nrequire (\n\
            \tgithub.com/sagernet/cronet-go v0.0.0-20261023060337-b3c2ed82ac97\n\
            \tgithub.com/sagernet/cronet-go/lib/windows_amd64 v0.0.0-20261023055542-d5437a0df01a // indirect\n\
            \tgithub.com/sagernet/sing v0.8.9\n\
            )\n";
        assert_eq!(
            requirement(go_mod).as_deref(),
            Some("v0.0.0-20261023055542-d5437a0df01a")
        );
        assert_eq!(requirement("module x\n"), None);
    }

    #[test]
    fn validates_architecture_and_dll_header() {
        let path = std::env::temp_dir().join(format!(
            "fcae-cronet-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let mut data = vec![0u8; MIN_PLAUSIBLE_DLL as usize];
        data[..2].copy_from_slice(b"MZ");
        data[60..64].copy_from_slice(&128u32.to_le_bytes());
        data[128..132].copy_from_slice(b"PE\0\0");
        data[132..134].copy_from_slice(&0x8664u16.to_le_bytes());
        data[150..152].copy_from_slice(&0x2000u16.to_le_bytes());
        std::fs::write(&path, &data).unwrap();
        assert!(plausible_dll(&path));
        data[132..134].copy_from_slice(&0xaa64u16.to_le_bytes());
        std::fs::write(&path, &data).unwrap();
        assert!(!plausible_dll(&path));
        std::fs::remove_file(path).unwrap();
    }
}

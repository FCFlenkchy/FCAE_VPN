//! Fetch the exact unmodified driver package; never use floating release URLs.
//! SHA-256 authenticates pinned bytes, not Windows kernel signing policy. The
//! installer must still verify the catalog/driver using Windows trust APIs.
use crate::target::{Arch, Target};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const BINARY_REVISION: &str = "5b6f46cde692acb77ee74b37b9fd3f1678c45a52";
pub const SOURCE_REVISION: &str = "0a0eb97f67d1dbcb3d08bda66d3b24f465d95475";
const LICENSE_SHA: &str = "66a3107d5ad6a058aab753eaac2047ccb2ed0e39465dd0fe5844da3e300d5172";

#[derive(Clone, Copy)]
pub struct Artifact {
    pub name: &'static str,
    pub hash: &'static str,
}
pub fn artifacts(arch: Arch) -> Option<(&'static str, u16, [Artifact; 3])> {
    let (architecture, machine, hashes) = match arch {
        Arch::X86_64 => (
            "x86_64",
            0x8664,
            [
                "10cf25bbcfe51fd663a1fec88a98e9b858f3a579589bb2ec496b66e4fdd1b201",
                "3dd5905e5fb98d61a942a33e8c9a5ba07c3a2de1e4f319e1fec3e54df6591608",
                "c599926a0327d7ae06b534f4cd039db30392e1897bb9d03e4fec3631744a4e6d",
            ],
        ),
        Arch::Aarch64 => (
            "aarch64",
            0xaa64,
            [
                "6af8b3bfe5aa095d5276187558c7c7d3a3e0c174b34406cd6c4b3f8e6ffa6534",
                "0bfdb044e40535dabbeb3620b655c1563714b3a6f3231d3492c972c6e8dea6f1",
                "c3d27636739ebaa7dde369d113347de83e3e2173b8a512bb8863d11b148de7ce",
            ],
        ),
        _ => return None,
    };
    Some((
        architecture,
        machine,
        [
            Artifact {
                name: "mullvad-split-tunnel.sys",
                hash: hashes[0],
            },
            Artifact {
                name: "mullvad-split-tunnel.inf",
                hash: hashes[1],
            },
            Artifact {
                name: "mullvad-split-tunnel.cat",
                hash: hashes[2],
            },
        ],
    ))
}
pub fn verify(path: &Path, expected: &str, machine: Option<u16>) -> Result<(), String> {
    let file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 4 * 1024 * 1024 {
        return Err("driver artifact outside size limit".into());
    }
    let mut bytes = Vec::new();
    file.take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.is_empty() || bytes.len() > 4 * 1024 * 1024 {
        return Err("driver artifact outside size limit".into());
    }
    let actual = format!("{:x}", Sha256::digest(&bytes));
    if actual != expected {
        return Err(format!(
            "{} SHA-256 mismatch: expected {expected}, got {actual}",
            path.display()
        ));
    }
    if let Some(machine) = machine {
        let read16 = |at: usize| {
            bytes
                .get(at..at + 2)
                .map(|v| u16::from_le_bytes([v[0], v[1]]))
        };
        let read32 = |at: usize| {
            bytes
                .get(at..at + 4)
                .map(|v| u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
        };
        let pe = read32(0x3c).ok_or("truncated PE header")? as usize;
        if !bytes.starts_with(b"MZ")
            || bytes.get(pe..pe + 4) != Some(b"PE\0\0")
            || read16(pe + 4) != Some(machine)
            || read16(pe + 24) != Some(0x20b)
        {
            return Err("wrong driver architecture or PE format".into());
        }
        let cert =
            read32(pe + 24 + 112 + 4 * 8).ok_or("missing PE certificate directory")? as usize;
        let length =
            read32(pe + 24 + 112 + 4 * 8 + 4).ok_or("missing PE certificate length")? as usize;
        if cert == 0 || length < 8 || cert.checked_add(length).is_none_or(|end| end > bytes.len()) {
            return Err("missing embedded driver certificate".into());
        }
    }
    Ok(())
}
fn download(url: &str, path: &Path) -> Result<(), String> {
    let status = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--connect-timeout",
            "15",
            "--max-time",
            "60",
            "--retry",
            "2",
            "--max-filesize",
            "4194304",
            "--output",
        ])
        .arg(path)
        .arg(url)
        .status();
    if status.is_ok_and(|s| s.success()) {
        return Ok(());
    }
    if cfg!(windows) {
        let quote = |s: &str| s.replace('\'', "''");
        let command=format!("$ErrorActionPreference='Stop'; [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -UseBasicParsing -TimeoutSec 60 -Uri '{}' -OutFile '{}'",quote(url),quote(&path.display().to_string()));
        if Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &command])
            .status()
            .is_ok_and(|s| s.success())
        {
            return Ok(());
        }
    }
    Err(format!("could not download pinned driver artifact: {url}"))
}
fn obtain(
    out: &Path,
    local: Option<&Path>,
    name: &str,
    url: &str,
    hash: &str,
    machine: Option<u16>,
) -> Result<PathBuf, String> {
    let destination = out.join(name);
    if let Some(local) = local {
        let source = local.join(name);
        crate::rerun_if_changed(&source);
        verify(&source, hash, machine)?;
        if source != destination {
            std::fs::copy(source, &destination).map_err(|e| e.to_string())?;
        }
        verify(&destination, hash, machine)?;
        return Ok(destination);
    }
    if verify(&destination, hash, machine).is_ok() {
        return Ok(destination);
    }
    let next = out.join(format!("{name}.part"));
    let _ = std::fs::remove_file(&next);
    download(url, &next)?;
    if let Err(error) = verify(&next, hash, machine) {
        let _ = std::fs::remove_file(&next);
        return Err(error);
    }
    // OUT_DIR is private build output, never a privileged runtime location.
    if destination.exists() {
        std::fs::remove_file(&destination).map_err(|e| e.to_string())?;
    }
    std::fs::rename(&next, &destination).map_err(|e| e.to_string())?;
    Ok(destination)
}
/// Only explicit experimental builds embed this candidate. It has an upstream
/// reconnect crash report (#11487); bundling must not automatically install it.
/// 0 disables, 1 requires a complete verified package; no silent fallback.
pub fn stage_and_emit(target: Target) -> Result<(), String> {
    println!("cargo::rustc-check-cfg=cfg(split_driver_staged)");
    crate::rerun_if_env_changed("FCAE_BUNDLE_SPLIT_DRIVER");
    crate::rerun_if_env_changed("FCAE_SPLIT_DRIVER_DIR");
    if !target.is_windows() {
        return Ok(());
    }
    match std::env::var("FCAE_BUNDLE_SPLIT_DRIVER").as_deref() {
        Err(_) | Ok("0") => return Ok(()),
        Ok("1") => {}
        _ => return Err("FCAE_BUNDLE_SPLIT_DRIVER must be 0 or 1".into()),
    }
    let (arch, machine, files) =
        artifacts(target.arch).ok_or("split-tunnel driver requires Windows x86_64 or aarch64")?;
    let out = PathBuf::from(std::env::var_os("OUT_DIR").ok_or("OUT_DIR missing")?)
        .join("split-driver-1.3.0.0");
    std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;
    let local = std::env::var_os("FCAE_SPLIT_DRIVER_DIR").map(PathBuf::from);
    let mut envs = Vec::new();
    for (file, key) in files.iter().zip(["SYS", "INF", "CAT"]) {
        let url=format!("https://raw.githubusercontent.com/mullvad/mullvadvpn-app-binaries/{BINARY_REVISION}/{arch}-pc-windows-msvc/split-tunnel/{}",file.name);
        let path = obtain(
            &out,
            local.as_deref(),
            file.name,
            &url,
            file.hash,
            if key == "SYS" { Some(machine) } else { None },
        )?;
        envs.push((
            format!("FCAE_SPLIT_DRIVER_{key}"),
            path.display().to_string(),
        ));
        println!(
            "cargo:rustc-env=FCAE_SPLIT_DRIVER_{key}_SHA256={}",
            file.hash
        );
    }
    let url=format!("https://raw.githubusercontent.com/mullvad/win-split-tunnel/{SOURCE_REVISION}/LICENSE-MPL.txt");
    let license = obtain(
        &out,
        local.as_deref(),
        "LICENSE-MPL.txt",
        &url,
        LICENSE_SHA,
        None,
    )?;
    envs.push((
        "FCAE_SPLIT_DRIVER_LICENSE".into(),
        license.display().to_string(),
    ));
    // Publish cfg only after every artifact and its license have verified.
    for (key, value) in envs {
        println!("cargo:rustc-env={key}={value}");
    }
    println!("cargo:rustc-env=FCAE_SPLIT_DRIVER_BINARY_REV={BINARY_REVISION}");
    println!("cargo:rustc-env=FCAE_SPLIT_DRIVER_SOURCE_REV={SOURCE_REVISION}");
    println!("cargo:rustc-cfg=split_driver_staged");
    crate::note("experimental split driver package embedded; installation/loading still requires explicit in-app opt-in (upstream crash report #11487)");
    Ok(())
}

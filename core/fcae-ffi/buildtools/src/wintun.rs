//! Windows: obtain `wintun.dll` at build time.
//!
//! Same sources as before (download from wintun.net, extract the right
//! architecture) but pulled out of the engine's build script and verified as a
//! PE image before it can be embedded: a captive-portal page, a truncated
//! download or a cached copy left half-written by an interrupted build is
//! rejected here instead of failing later inside `WintunCreateAdapter`.

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
        if let Err(problem) = verify(&p, arch) {
            crate::note(format!("WINTUN_DLL={} rejected: {problem}", p.display()));
            return None;
        }
        if p != dest && std::fs::copy(&p, &dest).is_err() {
            crate::note("could not stage WINTUN_DLL");
            return None;
        }
        return Some(dest);
    }
    if let Err(problem) = verify(&dest, arch) {
        if dest.exists() {
            crate::note(format!("discarding cached {}: {problem}", dest.display()));
        }
    } else {
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

    match verify(&dest, arch) {
        Ok(()) => {
            crate::note(format!("wintun.dll ({arch}) staged"));
            Some(dest)
        }
        Err(problem) => {
            crate::note(format!("staged wintun.dll rejected: {problem}"));
            let _ = std::fs::remove_file(&dest);
            None
        }
    }
}

fn verify(path: &Path, arch: &str) -> Result<(), String> {
    let data = std::fs::read(path).map_err(|error| error.to_string())?;
    inspect(&data, arch).map_err(str::to_owned)
}

struct Section {
    virtual_address: u32,
    virtual_size: u32,
    raw_size: u32,
    raw_pointer: u32,
}

enum Entry {
    Id(u32),
    Text(String),
}

fn slice(data: &[u8], at: usize, len: usize) -> Option<&[u8]> {
    data.get(at..at.checked_add(len)?)
}

fn u16_at(data: &[u8], at: usize) -> Option<u16> {
    slice(data, at, 2).map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    slice(data, at, 4).map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn rva_to_offset(sections: &[Section], rva: u32) -> Option<usize> {
    for section in sections {
        let span = section.virtual_size.max(section.raw_size);
        if rva < section.virtual_address || rva - section.virtual_address >= span {
            continue;
        }
        return section.raw_pointer.checked_add(rva - section.virtual_address).map(|offset| offset as usize);
    }
    None
}

/// One resource directory's entries as `(name, offset)`: the name is a numeric
/// type/id or a lowercased label, and the offset keeps the subdirectory bit.
fn resource_entries(data: &[u8], base: usize, offset: u32) -> Option<Vec<(Entry, u32)>> {
    let at = base.checked_add(offset as usize)?;
    let named = u16_at(data, at.checked_add(12)?)? as usize;
    let ids = u16_at(data, at.checked_add(14)?)? as usize;
    let mut entries = Vec::with_capacity(named + ids);
    for index in 0..named + ids {
        let entry = at.checked_add(16 + index * 8)?;
        let name = u32_at(data, entry)?;
        let target = u32_at(data, entry.checked_add(4)?)?;
        let name = if name & 0x8000_0000 != 0 {
            let string = base.checked_add((name & 0x7fff_ffff) as usize)?;
            let len = u16_at(data, string)? as usize;
            let units = slice(data, string.checked_add(2)?, len.checked_mul(2)?)?;
            let text: String = units
                .chunks_exact(2)
                .map(|unit| char::from_u32(u16::from_le_bytes([unit[0], unit[1]]) as u32).unwrap_or('\u{fffd}'))
                .collect();
            Entry::Text(text.to_lowercase())
        } else {
            Entry::Id(name)
        };
        entries.push((name, target));
    }
    Some(entries)
}

/// Judge the staged bytes as an image, not by their size: headers, every
/// section inside the file, an export table naming `WintunCreateAdapter`, and
/// the `RT_RCDATA` blobs (`wintun.sys`, `wintun.inf`, `wintun.cat`) the adapter
/// installs the driver from.
///
/// A truncated download, a cached copy left half-written by an interrupted
/// build, and an image whose driver blobs were stripped all pass a header check
/// and load fine; the failure then surfaces in the adapter step, where Wintun
/// reports nothing but Win32 error 2 to the engine.
fn inspect(data: &[u8], arch: &str) -> Result<(), &'static str> {
    let (machine, wide) = match arch {
        "x86" => (0x014c_u16, false),
        "amd64" => (0x8664, true),
        "arm" => (0x01c4, false),
        "arm64" => (0xaa64, true),
        _ => return Err("unknown architecture"),
    };
    if data.len() < MIN_PLAUSIBLE_DLL as usize || !data.starts_with(b"MZ") {
        return Err("not a PE image");
    }
    let pe = u32_at(data, 0x3c).ok_or("truncated DOS header")? as usize;
    if pe < 64 || slice(data, pe, 24).is_none() || slice(data, pe, 4) != Some(&b"PE\0\0"[..]) {
        return Err("not a PE image");
    }
    if u16_at(data, pe + 4) != Some(machine) {
        return Err("built for another architecture");
    }
    let sections_count = u16_at(data, pe + 6).ok_or("truncated PE header")? as usize;
    if !(1..=96).contains(&sections_count) {
        return Err("implausible section table");
    }
    let optional = pe + 24;
    let optional_size = u16_at(data, pe + 20).ok_or("truncated PE header")? as usize;
    let minimum = if wide { 112 } else { 96 };
    if optional_size < minimum || slice(data, optional, optional_size).is_none() {
        return Err("truncated optional header");
    }
    if u16_at(data, optional) != Some(if wide { 0x20b } else { 0x10b }) {
        return Err("wrong PE kind for the architecture");
    }
    let size_of_image = u32_at(data, optional + 56).ok_or("truncated optional header")?;
    let size_of_headers = u32_at(data, optional + 60).ok_or("truncated optional header")?;
    if size_of_image == 0 || size_of_headers as usize > data.len() {
        return Err("implausible image sizes");
    }
    let directories = optional + (if wide { 112 } else { 96 });
    let directory_count = u32_at(data, optional + (if wide { 108 } else { 92 }))
        .ok_or("truncated optional header")? as usize;
    if directory_count < 3 || directories + directory_count * 8 > optional + optional_size {
        return Err("no data directories");
    }
    let mut sections = Vec::with_capacity(sections_count);
    for index in 0..sections_count {
        let header = slice(data, optional + optional_size + index * 40, 40).ok_or("truncated section table")?;
        let section = Section {
            virtual_size: u32::from_le_bytes([header[8], header[9], header[10], header[11]]),
            virtual_address: u32::from_le_bytes([header[12], header[13], header[14], header[15]]),
            raw_size: u32::from_le_bytes([header[16], header[17], header[18], header[19]]),
            raw_pointer: u32::from_le_bytes([header[20], header[21], header[22], header[23]]),
        };
        if section.raw_size != 0
            && section.raw_pointer.checked_add(section.raw_size).is_none_or(|end| end as usize > data.len())
        {
            return Err("a section extends past the end of the file");
        }
        sections.push(section);
    }
    let export_rva = u32_at(data, directories).ok_or("truncated data directories")?;
    let export_size = u32_at(data, directories + 4).ok_or("truncated data directories")?;
    if export_rva == 0 || export_size == 0 {
        return Err("no export directory");
    }
    let exports = rva_to_offset(&sections, export_rva).ok_or("export directory outside the sections")?;
    let export_names = u32_at(data, exports + 24).ok_or("truncated export directory")? as usize;
    let name_table_rva = u32_at(data, exports + 32).ok_or("truncated export directory")?;
    if export_names == 0 || name_table_rva == 0 {
        return Err("no export names");
    }
    let name_table = rva_to_offset(&sections, name_table_rva).ok_or("export names outside the sections")?;
    let mut adapter_export = false;
    for index in 0..export_names.min(1024) {
        let Some(at) = u32_at(data, name_table + index * 4).and_then(|rva| rva_to_offset(&sections, rva)) else {
            continue;
        };
        let Some(len) = data.get(at..).and_then(|rest| rest.iter().position(|byte| *byte == 0)) else {
            continue;
        };
        if slice(data, at, len) == Some(&b"WintunCreateAdapter"[..]) {
            adapter_export = true;
            break;
        }
    }
    if !adapter_export {
        return Err("WintunCreateAdapter is not exported");
    }
    let resources_rva = u32_at(data, directories + 16).ok_or("truncated data directories")?;
    let resources_size = u32_at(data, directories + 20).ok_or("truncated data directories")?;
    if resources_rva == 0 || resources_size == 0 {
        return Err("no resource directory");
    }
    let resources = rva_to_offset(&sections, resources_rva).ok_or("resource directory outside the sections")?;
    let rcdata = resource_entries(data, resources, 0)
        .ok_or("truncated resource directory")?
        .into_iter()
        .find_map(|(name, offset)| matches!(name, Entry::Id(10)).then_some(offset))
        .ok_or("no RT_RCDATA resources")?;
    if rcdata & 0x8000_0000 == 0 {
        return Err("RT_RCDATA is not a directory");
    }
    let blobs = resource_entries(data, resources, rcdata & 0x7fff_ffff).ok_or("truncated RT_RCDATA")?;
    for required in ["wintun.sys", "wintun.inf", "wintun.cat"] {
        let blob = blobs
            .iter()
            .find_map(|(name, offset)| matches!(name, Entry::Text(text) if text.as_str() == required).then_some(*offset))
            .ok_or("the driver blobs are missing")?;
        if blob & 0x8000_0000 == 0 {
            return Err("a driver blob entry is not a directory");
        }
        let language = resource_entries(data, resources, blob & 0x7fff_ffff)
            .ok_or("truncated driver blob entry")?
            .first()
            .map(|(_, offset)| *offset)
            .ok_or("a driver blob has no payload")?;
        if language & 0x8000_0000 != 0 {
            return Err("a driver blob payload is not a leaf");
        }
        let at = resources.checked_add(language as usize).ok_or("truncated driver blob")?;
        let rva = u32_at(data, at).ok_or("truncated driver blob")?;
        let size = u32_at(data, at + 4).ok_or("truncated driver blob")?;
        let start = rva_to_offset(&sections, rva).ok_or("a driver blob is outside the sections")?;
        if size == 0 || start.checked_add(size as usize).is_none_or(|end| end > data.len()) {
            return Err("a driver blob is empty or truncated");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_incomplete_images() {
        assert!(inspect(b"", "amd64").is_err());
        assert!(inspect(&vec![0u8; MIN_PLAUSIBLE_DLL as usize], "amd64").is_err());
        let mut image = vec![0u8; MIN_PLAUSIBLE_DLL as usize];
        image[..2].copy_from_slice(b"MZ");
        image[60..64].copy_from_slice(&128u32.to_le_bytes());
        image[128..132].copy_from_slice(b"PE\0\0");
        image[132..134].copy_from_slice(&0x8664u16.to_le_bytes());
        assert!(inspect(&image, "amd64").is_err(), "a bare header is not an image");
        assert!(inspect(&image, "x86").is_err());
    }

    /// Runs against a genuine image when one is at hand, which is how the
    /// section walk is checked against real layouts:
    /// `WINTUN_DLL=/path/to/bin/amd64/wintun.dll cargo test -p fcae-build`.
    #[test]
    fn accepts_a_genuine_image() {
        let Some(path) = std::env::var_os("WINTUN_DLL") else { return };
        let path = PathBuf::from(path);
        let arch = path
            .parent()
            .and_then(|dir| dir.file_name())
            .and_then(|name| name.to_str())
            .filter(|name| matches!(*name, "x86" | "amd64" | "arm" | "arm64"))
            .unwrap_or("amd64");
        assert_eq!(verify(&path, arch), Ok(()));
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

/// Stage `wintun.dll` for `target` into `OUT_DIR` (see [`stage`]) and, when one
/// was produced, emit both the `wintun_staged` rustc-cfg and the rustc-env
/// variable carrying the staged path.
///
/// The engines LoadLibraryExW the stock `"wintun.dll"` (pool "Wintun") from
/// the application directory or System32, so the DLL also travels next to
/// the produced library; a plausible DLL that cannot be staged is skipped,
/// not fatal. `env` is the consuming crate's rustc-env name (e.g.
/// `FCAE_WINTUN_DLL` for `fcae-runtime`, which owns the single embedded
/// copy; the bridges embed nothing). The accessor side is
/// `fcae_runtime::wintun::wintun_bytes()`.
pub fn stage_and_emit(target: Target, env: &str) {
    if let Some(dll) = stage(target) {
        println!("cargo:rustc-cfg=wintun_staged");
        println!("cargo:rustc-env={env}={}", dll.display());
    }
}

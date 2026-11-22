//! Root-private write-ahead ownership records for controlled-launch recovery.
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const DIRECTORY: &str = "/run/fcae-app-routing";
const MAX_BYTES: u64 = 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Journal {
    pub version: u32,
    pub scope: String,
    pub table: u32,
    pub priority: u32,
    pub mark: u32,
    pub undo: Vec<Vec<String>>,
    pub nft_intent: bool,
}
fn private_file(file: &File) -> io::Result<()> {
    let m = file.metadata()?;
    if !m.is_file()
        || m.uid() != 0
        || m.nlink() != 1
        || m.mode() & 0o077 != 0
        || m.len() > MAX_BYTES
    {
        return Err(io::Error::other(
            "insecure or oversized app-routing ownership record",
        ));
    }
    Ok(())
}
fn directory() -> io::Result<PathBuf> {
    let path = PathBuf::from(DIRECTORY);
    match fs::create_dir(&path) {
        Ok(()) => fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let m = fs::symlink_metadata(&path)?;
    if !m.is_dir() || m.uid() != 0 || m.mode() & 0o077 != 0 {
        return Err(io::Error::other("insecure app-routing state directory"));
    }
    Ok(path)
}
impl Journal {
    pub fn validate(&self) -> io::Result<()> {
        let hex = self
            .scope
            .strip_prefix("fcae_app_")
            .ok_or_else(|| io::Error::other("invalid owned scope"))?;
        if hex.is_empty()
            || hex.len() > 16
            || !hex
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err(io::Error::other("invalid scope identity"));
        }
        let nonce = u64::from_str_radix(hex, 16).map_err(io::Error::other)?;
        if self.version != 1
            || self.scope != format!("fcae_app_{nonce:x}")
            || self.table != 40000 + (nonce % 10000) as u32
            || self.priority != 10000 + (nonce % 10000) as u32
            || self.mark != 0xfc000000 | self.table
            || self.undo.len() > 4096
        {
            return Err(io::Error::other("invalid routing ownership metadata"));
        }
        let table = self.table.to_string();
        let priority = self.priority.to_string();
        let mark = format!("{:#x}/0xffffffff", self.mark);
        for args in &self.undo {
            if args.len() < 7
                || args.len() > 20
                || !matches!(args[0].as_str(), "-4" | "-6")
                || args[2] != "del"
                || args
                    .iter()
                    .any(|s| s.len() > 128 || s.chars().any(char::is_control))
            {
                return Err(io::Error::other("invalid cleanup operation"));
            }
            if args[1] == "rule" {
                let expected: Vec<String> = [
                    args[0].as_str(),
                    "rule",
                    "del",
                    "priority",
                    &priority,
                    "fwmark",
                    &mark,
                    "lookup",
                    &table,
                ]
                .iter()
                .map(|s| (*s).to_owned())
                .collect();
                if *args != expected {
                    return Err(io::Error::other("invalid owned policy rule"));
                }
            } else if args[1] == "route" {
                let family6 = args[0] == "-6";
                let interface = |s: &str| {
                    !s.is_empty()
                        && s.len() <= 15
                        && !s.starts_with('-')
                        && s.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
                };
                let ip = |s: &str| {
                    s.parse::<std::net::IpAddr>()
                        .is_ok_and(|a| a.is_ipv6() == family6)
                };
                let prefix = |s: &str| {
                    s.split_once('/').is_some_and(|(a, b)| {
                        ip(a)
                            && b.parse::<u8>()
                                .is_ok_and(|n| n > 0 && n <= if family6 { 128 } else { 32 })
                    })
                };
                let valid = match args.len() {
                    9 => {
                        args[3] == "unreachable"
                            && args[4] == "default"
                            && args[5] == "table"
                            && args[6] == table
                            && args[7] == "metric"
                            && args[8] == "32760"
                    }
                    8 => {
                        prefix(&args[3])
                            && args[4] == "dev"
                            && interface(&args[5])
                            && args[6] == "table"
                            && args[7] == table
                    }
                    10 => {
                        args[3] == "default"
                            && args[4] == "dev"
                            && interface(&args[5])
                            && args[6] == "table"
                            && args[7] == table
                            && args[8] == "metric"
                            && args[9] == "100"
                    }
                    13 => {
                        args[3] == "default"
                            && args[4] == "via"
                            && ip(&args[5])
                            && args[6] == "dev"
                            && interface(&args[7])
                            && args[8] == "onlink"
                            && args[9] == "table"
                            && args[10] == table
                            && args[11] == "metric"
                            && args[12] == "100"
                    }
                    _ => false,
                };
                if !valid {
                    return Err(io::Error::other("invalid owned route"));
                }
            } else {
                return Err(io::Error::other("unsupported recovery operation"));
            }
        }
        Ok(())
    }
    pub fn store(&self) -> io::Result<()> {
        self.validate()?;
        let directory = directory()?;
        let destination = directory.join(format!("{}.json", self.scope));
        let next = directory.join(format!("{}.next", self.scope));
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&next)?;
        private_file(&file)?;
        let bytes = serde_json::to_vec(self).map_err(io::Error::other)?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err(io::Error::other("routing journal too large"));
        }
        file.set_len(0)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(next, destination)?;
        File::open(directory)?.sync_all()
    }
    pub fn remove(&self) -> io::Result<()> {
        self.validate()?;
        let directory = directory()?;
        for suffix in ["json", "next"] {
            let path = directory.join(format!("{}.{suffix}", self.scope));
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        File::open(directory)?.sync_all()
    }
    pub fn load_all() -> io::Result<Vec<Self>> {
        let mut result = Vec::new();
        for entry in fs::read_dir(directory()?)? {
            let path = entry?.path();
            if path.extension().is_none_or(|s| s != "json") {
                continue;
            }
            if result.len() >= 128 {
                return Err(io::Error::other("too many stale app-routing scopes"));
            }
            let mut file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&path)?;
            private_file(&file)?;
            let mut contents = String::new();
            Read::by_ref(&mut file)
                .take(MAX_BYTES + 1)
                .read_to_string(&mut contents)?;
            if contents.len() as u64 > MAX_BYTES {
                return Err(io::Error::other("routing journal exceeded size limit"));
            }
            let journal: Self = serde_json::from_str(&contents).map_err(io::Error::other)?;
            journal.validate()?;
            if path.file_stem().and_then(|s| s.to_str()) != Some(&journal.scope) {
                return Err(io::Error::other("journal filename mismatch"));
            }
            result.push(journal);
        }
        Ok(result)
    }
    pub fn scope_path(&self) -> PathBuf {
        Path::new("/sys/fs/cgroup").join(&self.scope)
    }
}

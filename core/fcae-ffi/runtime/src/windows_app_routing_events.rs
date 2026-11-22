//! Checked decoder for the pinned split driver's 64-bit event ABI.
//! Offsets are FIELD_OFFSET values, not sizeof (the C structs have tail padding).
use std::io;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DriverEvent {
    Started {
        pid: u64,
        reason: u32,
        image: String,
    },
    Stopped {
        pid: u64,
        reason: u32,
        image: String,
    },
    StartFailed {
        pid: u64,
        image: String,
    },
    StopFailed {
        pid: u64,
        image: String,
    },
    Error {
        status: i32,
        message: String,
    },
}
impl DriverEvent {
    pub fn is_error(&self) -> bool {
        matches!(
            self,
            Self::StartFailed { .. } | Self::StopFailed { .. } | Self::Error { .. }
        )
    }
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "incompatible split driver event",
    )
}
fn u16_at(b: &[u8], at: usize) -> io::Result<u16> {
    Ok(u16::from_le_bytes(
        b.get(at..at + 2)
            .ok_or_else(invalid)?
            .try_into()
            .map_err(|_| invalid())?,
    ))
}
fn u32_at(b: &[u8], at: usize) -> io::Result<u32> {
    Ok(u32::from_le_bytes(
        b.get(at..at + 4)
            .ok_or_else(invalid)?
            .try_into()
            .map_err(|_| invalid())?,
    ))
}
fn u64_at(b: &[u8], at: usize) -> io::Result<u64> {
    Ok(u64::from_le_bytes(
        b.get(at..at + 8)
            .ok_or_else(invalid)?
            .try_into()
            .map_err(|_| invalid())?,
    ))
}
fn text(b: &[u8], length_offset: usize, text_offset: usize) -> io::Result<String> {
    let length = u16_at(b, length_offset)? as usize;
    if length & 1 != 0 || b.len() != text_offset + length {
        return Err(invalid());
    }
    let words: Vec<u16> = b[text_offset..]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u16::from_le_bytes([p[0], p[1]]))
        .collect();
    if words.contains(&0) {
        return Err(invalid());
    }
    String::from_utf16(&words).map_err(|_| invalid())
}
pub fn decode(b: &[u8]) -> io::Result<DriverEvent> {
    if b.len() < 16 || b.len() > 128 * 1024 || u64_at(b, 8)? != (b.len() - 16) as u64 {
        return Err(invalid());
    }
    let id = u32_at(b, 0)?;
    let p = &b[16..];
    match id {
        0 | 1 => {
            let pid = u64_at(p, 0)?;
            let reason = u32_at(p, 8)?;
            let image = text(p, 12, 14)?;
            if pid == 0 || reason == 0 || reason & !15 != 0 {
                return Err(invalid());
            }
            Ok(if id == 0 {
                DriverEvent::Started { pid, reason, image }
            } else {
                DriverEvent::Stopped { pid, reason, image }
            })
        }
        0x80000001 | 0x80000002 => {
            let pid = u64_at(p, 0)?;
            let image = text(p, 8, 10)?;
            if pid == 0 {
                return Err(invalid());
            }
            Ok(if id == 0x80000001 {
                DriverEvent::StartFailed { pid, image }
            } else {
                DriverEvent::StopFailed { pid, image }
            })
        }
        0x80000003 => Ok(DriverEvent::Error {
            status: u32_at(p, 0)? as i32,
            message: text(p, 4, 6)?,
        }),
        _ => Err(invalid()),
    }
}

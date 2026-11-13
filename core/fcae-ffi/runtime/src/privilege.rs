//! The one privilege probe behind `fcae_is_privileged()` and the session
//! supervisor's elevation gate.
//!
//! Only coarse answers are needed: this decides whether the frontend shows
//! its elevation prompt. Creation of the TUN device itself reports a precise
//! error when the answer is wrong, so `geteuid` / the net session probe are
//! enough.
pub fn is_privileged() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: geteuid takes no arguments and cannot fail.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        crate::windows_tun::is_privileged()
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

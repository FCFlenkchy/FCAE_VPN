#[cfg(not(windows))]
mod inprocess;
#[cfg(not(windows))]
pub use inprocess::*;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;

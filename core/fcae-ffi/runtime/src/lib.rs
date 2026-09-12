//! # fcae-runtime — backend-agnostic runtime
//!
//! Everything the FFI needs that is *not* C-specific and *not* tied to a
//! particular tunnel engine:
//!
//! * [`config`]  — typed [`SessionConfig`](config::SessionConfig) parsed once
//!   from the ABI struct, with validation.
//! * [`backend`] — the [`Backend`](backend::Backend) plugin trait that Aether
//!   implements today and Psiphon will implement unchanged.
//! * [`telemetry`] — the single shared telemetry cell + log bus.
//! * [`update`] — app-level update checking, with a pluggable fetcher.
//! * [`session`] — the supervisor that owns the runtime thread, starts the
//!   backend, raises the TUN bridge, and guarantees teardown ordering.
//!
//! No `#[no_mangle]` lives in this crate. That is the `fcae-ffi` crate's job,
//! which keeps this one unit-testable as ordinary Rust.

pub mod backend;
pub mod config;
pub mod error;
pub mod registry;
pub mod session;
pub mod telemetry;
pub mod update;

pub use error::{CoreError, Result};

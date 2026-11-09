#![recursion_limit = "512"]

pub mod accounts;
pub mod challenge;
pub mod control;
pub mod crypto;
pub mod dialer;
mod doh;
pub mod engine;
pub mod error;
pub mod fxa;
pub mod guardian;
pub mod proxy;
pub mod server_list;
pub mod store;
pub mod tls;
pub mod transport;
pub mod types;

pub use accounts::{Accounts, LoginOutcome, PendingLogin, TokenManager, UnblockCodePrompt};
pub use challenge::{CaptchaSolver, ChallengeService};
pub use control::ControlPlane;
pub use dialer::Dialer;
pub use engine::FirefoxEngine;
pub use fxa::Fxa;
pub use store::AccountStore;
pub use error::{FirefoxError, Result};
pub use types::{Account, Candidate, EngineConfig, TransportPreference};

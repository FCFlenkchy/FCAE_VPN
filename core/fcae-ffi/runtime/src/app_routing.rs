//! Backend-independent per-application policy validation. Compilation does not
//! install OS policy: only a platform provider can acknowledge enforcement.
use std::collections::BTreeSet;

pub const SCHEMA_VERSION: u32 = 1;
const MAX_SELECTORS: usize = 8192;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    Windows,
    Linux,
    MacOs,
    Ios,
    Android,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    AllApps,
    Include,
    Exclude,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Tunnel,
    Bypass,
    Block,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mechanism {
    OsRouting,
    ControlledLaunch,
    FlowProxy,
    ManagedVpn,
}

/// These are discovery hints until a provider resolves and validates them.
/// Numeric PIDs/cgroup IDs are deliberately not persistent selector types.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Selector {
    WindowsExecutable(String),
    LinuxLaunchTarget(String),
    MacSigningIdentity { team: String, signing_id: String },
    IosManagedApplication(String),
    AndroidPackage(String),
}
impl Selector {
    pub fn platform(&self) -> Platform {
        match self {
            Self::WindowsExecutable(_) => Platform::Windows,
            Self::LinuxLaunchTarget(_) => Platform::Linux,
            Self::MacSigningIdentity { .. } => Platform::MacOs,
            Self::IosManagedApplication(_) => Platform::Ios,
            Self::AndroidPackage(_) => Platform::Android,
        }
    }
    fn valid(&self) -> bool {
        fn text(s: &str) -> bool {
            !s.is_empty() && s.len() <= 32768 && !s.chars().any(char::is_control)
        }
        fn unix_path(s: &str) -> bool {
            text(s) && s.starts_with('/') && !s.split('/').any(|p| p == ".." || p == ".")
        }
        match self {
            Self::WindowsExecutable(p) => {
                let b = p.as_bytes();
                text(p)
                    && b.len() > 3
                    && b[0].is_ascii_alphabetic()
                    && b[1] == b':'
                    && b[2] == b'\\'
                    && !p.contains('/')
                    && !p[2..].contains(':')
                    && !p.split('\\').any(|c| c == ".." || c == ".")
            }
            Self::LinuxLaunchTarget(p) => unix_path(p),
            Self::MacSigningIdentity { team, signing_id } => text(team) && text(signing_id),
            Self::IosManagedApplication(p) | Self::AndroidPackage(p) => {
                text(p)
                    && p.contains('.')
                    && p.split('.').all(|part| {
                        !part.is_empty()
                            && part
                                .bytes()
                                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
                    })
            }
        }
    }
}
#[derive(Clone, Debug)]
pub struct Policy {
    pub schema_version: u32,
    pub revision: u64,
    pub mode: Mode,
    pub selectors: Vec<Selector>,
    /// Unknown ownership cannot be converted into an accidental direct path.
    pub unknown_action: Action,
    pub fail_closed: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PolicyError {
    Schema,
    TooManySelectors,
    InvalidSelector,
    EmptyInclude,
    UnsafeUnknownAction,
    ProviderUnavailable,
    ForeignSelector,
    StaleAcknowledgement,
    InvalidAcknowledgement,
    ProviderOperation(String),
}

/// Immutable requested policy. Foreign selectors survive import, but cannot be
/// installed on this platform or silently reinterpreted as local identities.
#[derive(Clone, Debug)]
pub struct CompiledPolicy {
    revision: u64,
    mode: Mode,
    local: BTreeSet<Selector>,
    foreign: BTreeSet<Selector>,
    unknown: Action,
    fail_closed: bool,
}
impl Policy {
    pub fn compile(&self, platform: Platform) -> Result<CompiledPolicy, PolicyError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(PolicyError::Schema);
        }
        if self.selectors.len() > MAX_SELECTORS {
            return Err(PolicyError::TooManySelectors);
        }
        if self.unknown_action == Action::Bypass {
            return Err(PolicyError::UnsafeUnknownAction);
        }
        let mut local = BTreeSet::new();
        let mut foreign = BTreeSet::new();
        for selector in &self.selectors {
            if !selector.valid() {
                return Err(PolicyError::InvalidSelector);
            }
            if selector.platform() == platform {
                local.insert(selector.clone());
            } else {
                foreign.insert(selector.clone());
            }
        }
        if self.mode == Mode::Include && local.is_empty() {
            return Err(PolicyError::EmptyInclude);
        }
        Ok(CompiledPolicy {
            revision: self.revision,
            mode: self.mode,
            local,
            foreign,
            unknown: self.unknown_action,
            fail_closed: self.fail_closed,
        })
    }
}
impl CompiledPolicy {
    pub fn mode(&self) -> Mode {
        self.mode
    }
    pub fn unknown_action(&self) -> Action {
        self.unknown
    }
    pub fn fail_closed(&self) -> bool {
        self.fail_closed
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn local_selectors(&self) -> &BTreeSet<Selector> {
        &self.local
    }
    pub fn foreign_selectors(&self) -> &BTreeSet<Selector> {
        &self.foreign
    }
    /// Call only with a provider-resolved identity, never a guessed PID owner.
    pub fn action(&self, identity: Option<&Selector>, tunnel_available: bool) -> Action {
        let action = match (self.mode, identity) {
            (Mode::AllApps, _) => Action::Tunnel,
            (_, None) => self.unknown,
            (Mode::Include, Some(s)) => {
                if self.local.contains(s) {
                    Action::Tunnel
                } else {
                    Action::Bypass
                }
            }
            (Mode::Exclude, Some(s)) => {
                if self.local.contains(s) {
                    Action::Bypass
                } else {
                    Action::Tunnel
                }
            }
        };
        if action == Action::Tunnel && !tunnel_available && self.fail_closed {
            Action::Block
        } else {
            action
        }
    }
}

/// A provider must validate identities and install transactionally before
/// returning an acknowledgement. A compiler result is never an installed policy.
pub trait Provider {
    fn mechanism(&self) -> Mechanism;
    fn install(&mut self, policy: &CompiledPolicy) -> Result<u64, PolicyError>;
    fn rollback(&mut self) -> Result<(), PolicyError>;
}
#[derive(Default)]
pub struct EffectivePolicy {
    installed: Option<(CompiledPolicy, Mechanism)>,
}
impl EffectivePolicy {
    pub fn installed(&self) -> Option<(&CompiledPolicy, Mechanism)> {
        self.installed.as_ref().map(|(p, m)| (p, *m))
    }
    pub fn apply(
        &mut self,
        policy: CompiledPolicy,
        provider: &mut dyn Provider,
    ) -> Result<(), PolicyError> {
        if !policy.foreign.is_empty() {
            return Err(PolicyError::ForeignSelector);
        }
        if self
            .installed
            .as_ref()
            .is_some_and(|(p, _)| p.revision >= policy.revision)
        {
            return Err(PolicyError::StaleAcknowledgement);
        }
        let revision = provider.install(&policy)?;
        if revision != policy.revision {
            // State is now uncertain; never keep advertising the previous policy.
            self.installed = None;
            provider.rollback()?;
            return Err(PolicyError::InvalidAcknowledgement);
        }
        self.installed = Some((policy, provider.mechanism()));
        Ok(())
    }
    pub fn stop(&mut self, provider: &mut dyn Provider) -> Result<(), PolicyError> {
        provider.rollback()?;
        self.installed = None;
        Ok(())
    }
}

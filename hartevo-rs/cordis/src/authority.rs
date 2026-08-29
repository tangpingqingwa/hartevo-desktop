//! Typed composition boundary between generic Cordis and Hartevo authorities.
//!
//! Cordis owns orchestration and lifecycle, but it does not own Mission facts,
//! Runtime execution, or external effects. Concrete adapters stay in the
//! Desktop/Application layer and are invoked only for one exact durable scope.

use std::error::Error;
use std::fmt::{self, Display};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::CordisError;
use crate::event::PreparedEmit;
use crate::surface::AgentsSurface;

const SHA256_HEX_LENGTH: usize = 64;

/// Opaque id/revision fence for one durable Runtime record.
///
/// Cordis deliberately does not know whether a record came from Hartevo's
/// recovery or turn ledger. Desktop supplies the real typed ids and revisions.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RuntimeRecordBinding {
    id: String,
    revision: u64,
}

impl RuntimeRecordBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, CordisError> {
        let id = normalized_id(id.into(), "runtime_record_id")?;
        positive_revision(revision, "runtime_record_revision")?;
        Ok(Self { id, revision })
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

/// Exact durable Runtime prestate bound to an authorized operation.
///
/// `fence_digest` is a content-free SHA-256 over the Application-owned Mission,
/// recovery, turn, workspace, attachment, assembly, and handle fences. Cordis
/// treats it as opaque and therefore remains independent of those crates.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RuntimeBinding {
    generation: u64,
    recovery: Option<RuntimeRecordBinding>,
    turn: Option<RuntimeRecordBinding>,
    fence_digest: String,
}

impl RuntimeBinding {
    pub fn new(
        generation: u64,
        recovery: Option<RuntimeRecordBinding>,
        turn: Option<RuntimeRecordBinding>,
        fence_digest: impl Into<String>,
    ) -> Result<Self, CordisError> {
        positive_revision(generation, "runtime_generation")?;
        let fence_digest = canonical_digest(fence_digest.into(), "runtime_fence_digest")?;
        Ok(Self {
            generation,
            recovery,
            turn,
            fence_digest,
        })
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn recovery(&self) -> Option<&RuntimeRecordBinding> {
        self.recovery.as_ref()
    }

    #[must_use]
    pub const fn turn(&self) -> Option<&RuntimeRecordBinding> {
        self.turn.as_ref()
    }

    #[must_use]
    pub fn fence_digest(&self) -> &str {
        &self.fence_digest
    }
}

/// Exact business and durable Runtime scope for one Cordis-authorized call.
///
/// Identifiers remain opaque strings so `hartevo-cordis` does not depend on
/// Domain Kernel types. Desktop constructs this value from the real typed ids.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct AuthorityScope {
    tenant_id: String,
    project_id: String,
    mission_id: String,
    mission_revision: u64,
    runtime: Option<RuntimeBinding>,
}

impl AuthorityScope {
    /// Construct one exact Mission authority scope without Runtime authority.
    pub fn new(
        tenant_id: impl Into<String>,
        project_id: impl Into<String>,
        mission_id: impl Into<String>,
        mission_revision: u64,
    ) -> Result<Self, CordisError> {
        let tenant_id = normalized_id(tenant_id.into(), "tenant_id")?;
        let project_id = normalized_id(project_id.into(), "project_id")?;
        let mission_id = normalized_id(mission_id.into(), "mission_id")?;
        positive_revision(mission_revision, "mission_revision")?;
        Ok(Self {
            tenant_id,
            project_id,
            mission_id,
            mission_revision,
            runtime: None,
        })
    }

    /// Add exact Runtime authority. Planning and Effect paths never call this.
    #[must_use]
    pub fn with_runtime(mut self, runtime: RuntimeBinding) -> Self {
        self.runtime = Some(runtime);
        self
    }

    #[must_use]
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    #[must_use]
    pub fn project_id(&self) -> &str {
        &self.project_id
    }

    #[must_use]
    pub fn mission_id(&self) -> &str {
        &self.mission_id
    }

    #[must_use]
    pub const fn mission_revision(&self) -> u64 {
        self.mission_revision
    }

    #[must_use]
    pub const fn runtime(&self) -> Option<&RuntimeBinding> {
        self.runtime.as_ref()
    }
}

fn normalized_id(value: String, field: &'static str) -> Result<String, CordisError> {
    let normalized = value.trim();
    if normalized.is_empty() || normalized != value {
        return Err(CordisError::InvalidAuthorityScope { field });
    }
    Ok(value)
}

fn positive_revision(value: u64, field: &'static str) -> Result<(), CordisError> {
    if value == 0 {
        return Err(CordisError::InvalidAuthorityRevision { field });
    }
    Ok(())
}

fn canonical_digest(value: String, field: &'static str) -> Result<String, CordisError> {
    if value.len() != SHA256_HEX_LENGTH
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(CordisError::InvalidAuthorityDigest { field });
    }
    Ok(value)
}

/// Unforgeable, one-shot proof that Cordis authorized a Runtime dispatch.
///
/// Only [`crate::CordisHost`] can issue it. Desktop must release the host lock
/// before invoking its Application adapter, then return this permit to Cordis
/// for lifecycle settlement.
pub struct RuntimeDispatchPermit {
    serial: u64,
    scope: AuthorityScope,
    agent_id: String,
    lease: Arc<RuntimeDispatchLease>,
    started: Option<PreparedEmit>,
    disposed: Option<PreparedEmit>,
    started_announced: bool,
    settled: bool,
}

impl RuntimeDispatchPermit {
    pub(crate) fn issue(
        serial: u64,
        scope: AuthorityScope,
        agent_id: String,
        agents: Arc<AgentsSurface>,
        started: PreparedEmit,
        disposed: PreparedEmit,
    ) -> (Self, Arc<RuntimeDispatchLease>) {
        let lease = Arc::new(RuntimeDispatchLease::new(agents, agent_id.clone()));
        (
            Self {
                serial,
                scope,
                agent_id,
                lease: Arc::clone(&lease),
                started: Some(started),
                disposed: Some(disposed),
                started_announced: false,
                settled: false,
            },
            lease,
        )
    }

    /// Publish the started lifecycle after the caller has released its host
    /// lock. Repeated calls are harmless and dispatch at most once.
    pub fn announce_started(&mut self) {
        if let Some(notification) = self.started.take() {
            self.started_announced = true;
            notification.dispatch();
        }
    }

    #[must_use]
    pub const fn scope(&self) -> &AuthorityScope {
        &self.scope
    }

    pub(crate) const fn serial(&self) -> u64 {
        self.serial
    }

    pub(crate) fn agent_id(&self) -> &str {
        &self.agent_id
    }

    pub(crate) fn owns_lease(&self, lease: &Arc<RuntimeDispatchLease>) -> bool {
        Arc::ptr_eq(&self.lease, lease)
    }

    pub(crate) fn complete(mut self) -> RuntimeDispatchCompletion {
        self.lease.release();
        self.settled = true;
        RuntimeDispatchCompletion {
            notification: self
                .started_announced
                .then(|| self.disposed.take())
                .flatten(),
        }
    }
}

impl fmt::Debug for RuntimeDispatchPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeDispatchPermit")
            .field("serial", &self.serial)
            .field("scope", &self.scope)
            .field("agent_id", &self.agent_id)
            .field("started_announced", &self.started_announced)
            .field("settled", &self.settled)
            .finish_non_exhaustive()
    }
}

impl Drop for RuntimeDispatchPermit {
    fn drop(&mut self) {
        if !self.settled {
            self.lease.release();
        }
    }
}

/// Lifecycle notification returned only after Cordis clears the active slot.
/// Dispatching it cannot run a listener while the host mutex is held.
#[derive(Debug)]
pub struct RuntimeDispatchCompletion {
    notification: Option<PreparedEmit>,
}

impl RuntimeDispatchCompletion {
    pub fn announce(mut self) {
        if let Some(notification) = self.notification.take() {
            notification.dispatch();
        }
    }
}

pub(crate) struct RuntimeDispatchLease {
    active: AtomicBool,
    agents: Arc<AgentsSurface>,
    agent_id: String,
}

impl RuntimeDispatchLease {
    fn new(agents: Arc<AgentsSurface>, agent_id: String) -> Self {
        Self {
            active: AtomicBool::new(true),
            agents,
            agent_id,
        }
    }

    pub(crate) fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    pub(crate) fn release(&self) {
        if self.active.swap(false, Ordering::AcqRel) {
            self.agents.unregister(&self.agent_id);
        }
    }
}

impl fmt::Debug for RuntimeDispatchLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeDispatchLease")
            .field("active", &self.is_active())
            .field("agent_id", &self.agent_id)
            .finish_non_exhaustive()
    }
}

/// One-shot typed adapter for the existing Hartevo runtime coordinator.
///
/// The blanket closure implementation keeps the generic crate dependency-light
/// while still forcing Desktop to enter Runtime execution through this trait.
pub trait RuntimeAuthority {
    type Output;
    type Error;

    fn execute(self, permit: &RuntimeDispatchPermit) -> Result<Self::Output, Self::Error>;
}

impl<F, Output, AdapterError> RuntimeAuthority for F
where
    F: FnOnce(&RuntimeDispatchPermit) -> Result<Output, AdapterError>,
{
    type Output = Output;
    type Error = AdapterError;

    fn execute(self, permit: &RuntimeDispatchPermit) -> Result<Self::Output, Self::Error> {
        self(permit)
    }
}

/// Distinguishes a Cordis gate/lifecycle failure from an authority failure.
#[derive(Debug, Eq, PartialEq)]
pub enum AuthorityDispatchError<AdapterError> {
    Cordis(CordisError),
    Authority(AdapterError),
}

impl<AdapterError> From<CordisError> for AuthorityDispatchError<AdapterError> {
    fn from(error: CordisError) -> Self {
        Self::Cordis(error)
    }
}

impl<AdapterError: Display> Display for AuthorityDispatchError<AdapterError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cordis(error) => Display::fmt(error, formatter),
            Self::Authority(error) => Display::fmt(error, formatter),
        }
    }
}

impl<AdapterError> Error for AuthorityDispatchError<AdapterError>
where
    AdapterError: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Cordis(error) => Some(error),
            Self::Authority(error) => Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthorityScope, RuntimeBinding, RuntimeRecordBinding};
    use crate::CordisError;

    #[test]
    fn scope_requires_exact_ids_and_positive_revision() {
        assert_eq!(
            AuthorityScope::new("", "project", "mission", 1).unwrap_err(),
            CordisError::InvalidAuthorityScope { field: "tenant_id" }
        );
        assert_eq!(
            AuthorityScope::new("tenant", "project", " mission ", 1).unwrap_err(),
            CordisError::InvalidAuthorityScope {
                field: "mission_id"
            }
        );
        assert_eq!(
            AuthorityScope::new("tenant", "project", "mission", 0).unwrap_err(),
            CordisError::InvalidAuthorityRevision {
                field: "mission_revision"
            }
        );
        let scope = AuthorityScope::new("tenant", "project", "mission", 3).unwrap();
        assert_eq!(scope.tenant_id(), "tenant");
        assert_eq!(scope.project_id(), "project");
        assert_eq!(scope.mission_id(), "mission");
        assert_eq!(scope.mission_revision(), 3);
        assert!(scope.runtime().is_none());
    }

    #[test]
    fn runtime_binding_requires_generation_revisions_and_canonical_digest() {
        assert_eq!(
            RuntimeBinding::new(0, None, None, "a".repeat(64)).unwrap_err(),
            CordisError::InvalidAuthorityRevision {
                field: "runtime_generation"
            }
        );
        assert_eq!(
            RuntimeRecordBinding::new("turn", 0).unwrap_err(),
            CordisError::InvalidAuthorityRevision {
                field: "runtime_record_revision"
            }
        );
        assert_eq!(
            RuntimeBinding::new(1, None, None, "A".repeat(64)).unwrap_err(),
            CordisError::InvalidAuthorityDigest {
                field: "runtime_fence_digest"
            }
        );
        let binding = RuntimeBinding::new(
            2,
            Some(RuntimeRecordBinding::new("recovery", 4).unwrap()),
            Some(RuntimeRecordBinding::new("turn", 7).unwrap()),
            "b".repeat(64),
        )
        .unwrap();
        assert_eq!(binding.generation(), 2);
        assert_eq!(binding.recovery().unwrap().revision(), 4);
        assert_eq!(binding.turn().unwrap().id(), "turn");
    }
}

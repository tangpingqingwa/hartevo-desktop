//! Typed composition boundary between generic Cordis and Hartevo authorities.
//!
//! Cordis owns orchestration and lifecycle, but it does not own Mission facts,
//! Runtime execution, or external effects. Concrete adapters stay in the
//! Desktop/Application layer and are invoked only for one exact durable scope.

use std::error::Error;
use std::fmt::{self, Display};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::CordisError;
use crate::event::PreparedEmit;
use crate::surface::{AgentPublicationCommit, UnpublishedAgent};

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

/// Exact Domain command kind currently admitted through the Desktop host.
///
/// Approval records remain Application/Domain Kernel state. This enum only
/// names the command crossing Cordis; it grants no Effect execution authority.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DomainCommandKind {
    ProposeEffect,
    ApproveProposedEffect,
}

impl DomainCommandKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProposeEffect => "propose_effect",
            Self::ApproveProposedEffect => "approve_proposed_effect",
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum DomainCommandDigest {
    Proposal(String),
    ApprovalScope(String),
}

/// Content-minimized binding for one exact Domain command.
///
/// Mission identity and revision stay in [`AuthorityScope`]. Proposal and
/// approval-scope digests are distinct variants so neither command can be
/// mistaken for the other. Neither digest is a Receipt, Verification,
/// provider lease, or execution capability.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DomainCommandBinding {
    kind: DomainCommandKind,
    effect_id: String,
    digest: DomainCommandDigest,
}

/// Content-minimized fence for one exact, already-approved Effect execution.
///
/// Mission identity and revision stay in [`AuthorityScope`]. The approval
/// scope digest binds the immutable Effect request, while the Broker
/// authorization digest binds the approval-time permission evidence and exact
/// policy configuration. Cordis deliberately receives neither the Effect
/// payload nor any provider, secret, ledger, Receipt, or Verification handle.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct EffectExecutionBinding {
    effect_id: String,
    approval_scope_digest: String,
    broker_authorization_digest: String,
}

/// Content-minimized fence for one exact uncertain-Effect reconciliation.
///
/// This is deliberately distinct from [`EffectExecutionBinding`]. It admits
/// only a read/recovery observation against the original approval and Broker
/// authorization. It carries no execution lease, provider capability,
/// reconciliation policy, Receipt, or Verification handle.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct EffectReconciliationBinding {
    effect_id: String,
    approval_scope_digest: String,
    broker_authorization_digest: String,
    observation_authority_digest: Option<String>,
}

/// Content-minimized fence for one exact independent verification of a
/// durable Receipt recorded by the Effect Broker.
///
/// Verification is deliberately a third authority family, separate from
/// execution and uncertain-effect reconciliation.  Cordis carries only
/// opaque, immutable digests: it never receives the Receipt, Verification,
/// provider capability, secret, executor, or reconciler.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct EffectVerificationBinding {
    effect_id: String,
    approval_scope_digest: String,
    broker_authorization_digest: String,
    receipt_binding_digest: String,
    observation_authority_digest: String,
    source_binding_digest: String,
}

impl EffectVerificationBinding {
    /// Construct one exact independent-verification fence.
    pub fn new(
        effect_id: impl Into<String>,
        approval_scope_digest: impl Into<String>,
        broker_authorization_digest: impl Into<String>,
        receipt_binding_digest: impl Into<String>,
        observation_authority_digest: impl Into<String>,
        source_binding_digest: impl Into<String>,
    ) -> Result<Self, CordisError> {
        Ok(Self {
            effect_id: normalized_id(effect_id.into(), "effect_verification_effect_id")?,
            approval_scope_digest: canonical_digest(
                approval_scope_digest.into(),
                "effect_verification_approval_scope_digest",
            )?,
            broker_authorization_digest: canonical_digest(
                broker_authorization_digest.into(),
                "effect_verification_broker_authorization_digest",
            )?,
            receipt_binding_digest: canonical_digest(
                receipt_binding_digest.into(),
                "effect_verification_receipt_binding_digest",
            )?,
            observation_authority_digest: canonical_digest(
                observation_authority_digest.into(),
                "effect_verification_observation_authority_digest",
            )?,
            source_binding_digest: canonical_digest(
                source_binding_digest.into(),
                "effect_verification_source_binding_digest",
            )?,
        })
    }

    #[must_use]
    pub fn effect_id(&self) -> &str {
        &self.effect_id
    }

    #[must_use]
    pub fn approval_scope_digest(&self) -> &str {
        &self.approval_scope_digest
    }

    #[must_use]
    pub fn broker_authorization_digest(&self) -> &str {
        &self.broker_authorization_digest
    }

    #[must_use]
    pub fn receipt_binding_digest(&self) -> &str {
        &self.receipt_binding_digest
    }

    #[must_use]
    pub fn observation_authority_digest(&self) -> &str {
        &self.observation_authority_digest
    }

    #[must_use]
    pub fn source_binding_digest(&self) -> &str {
        &self.source_binding_digest
    }
}

impl fmt::Debug for EffectVerificationBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EffectVerificationBinding")
            .field("effect_id", &self.effect_id)
            .field("approval_scope_digest", &"[DIGEST]")
            .field("broker_authorization_digest", &"[DIGEST]")
            .field("receipt_binding_digest", &"[DIGEST]")
            .field("observation_authority_digest", &"[DIGEST]")
            .field("source_binding_digest", &"[DIGEST]")
            .finish()
    }
}

impl EffectReconciliationBinding {
    pub fn new(
        effect_id: impl Into<String>,
        approval_scope_digest: impl Into<String>,
        broker_authorization_digest: impl Into<String>,
    ) -> Result<Self, CordisError> {
        Ok(Self {
            effect_id: normalized_id(effect_id.into(), "effect_reconciliation_effect_id")?,
            approval_scope_digest: canonical_digest(
                approval_scope_digest.into(),
                "effect_reconciliation_approval_scope_digest",
            )?,
            broker_authorization_digest: canonical_digest(
                broker_authorization_digest.into(),
                "effect_reconciliation_broker_authorization_digest",
            )?,
            observation_authority_digest: None,
        })
    }

    /// Binds one content-free, provider-specific observation selector to the
    /// original approved Effect. It grants no provider, secret, write,
    /// Receipt, or Verification capability.
    pub fn new_observation_bound(
        effect_id: impl Into<String>,
        approval_scope_digest: impl Into<String>,
        broker_authorization_digest: impl Into<String>,
        observation_authority_digest: impl Into<String>,
    ) -> Result<Self, CordisError> {
        let mut binding = Self::new(
            effect_id,
            approval_scope_digest,
            broker_authorization_digest,
        )?;
        binding.observation_authority_digest = Some(canonical_digest(
            observation_authority_digest.into(),
            "effect_reconciliation_observation_authority_digest",
        )?);
        Ok(binding)
    }

    #[must_use]
    pub fn effect_id(&self) -> &str {
        &self.effect_id
    }

    #[must_use]
    pub fn approval_scope_digest(&self) -> &str {
        &self.approval_scope_digest
    }

    #[must_use]
    pub fn broker_authorization_digest(&self) -> &str {
        &self.broker_authorization_digest
    }

    #[must_use]
    pub fn observation_authority_digest(&self) -> Option<&str> {
        self.observation_authority_digest.as_deref()
    }
}

impl fmt::Debug for EffectReconciliationBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EffectReconciliationBinding")
            .field("effect_id", &self.effect_id)
            .field("approval_scope_digest", &"[DIGEST]")
            .field("broker_authorization_digest", &"[DIGEST]")
            .field(
                "observation_authority_digest",
                &self
                    .observation_authority_digest
                    .as_ref()
                    .map(|_| "[DIGEST]"),
            )
            .finish()
    }
}

impl EffectExecutionBinding {
    pub fn new(
        effect_id: impl Into<String>,
        approval_scope_digest: impl Into<String>,
        broker_authorization_digest: impl Into<String>,
    ) -> Result<Self, CordisError> {
        Ok(Self {
            effect_id: normalized_id(effect_id.into(), "effect_execution_effect_id")?,
            approval_scope_digest: canonical_digest(
                approval_scope_digest.into(),
                "effect_execution_approval_scope_digest",
            )?,
            broker_authorization_digest: canonical_digest(
                broker_authorization_digest.into(),
                "effect_execution_broker_authorization_digest",
            )?,
        })
    }

    #[must_use]
    pub fn effect_id(&self) -> &str {
        &self.effect_id
    }

    #[must_use]
    pub fn approval_scope_digest(&self) -> &str {
        &self.approval_scope_digest
    }

    #[must_use]
    pub fn broker_authorization_digest(&self) -> &str {
        &self.broker_authorization_digest
    }
}

impl DomainCommandBinding {
    pub fn propose_effect(
        effect_id: impl Into<String>,
        proposal_digest: impl Into<String>,
    ) -> Result<Self, CordisError> {
        Ok(Self {
            kind: DomainCommandKind::ProposeEffect,
            effect_id: normalized_id(effect_id.into(), "domain_command_effect_id")?,
            digest: DomainCommandDigest::Proposal(canonical_digest(
                proposal_digest.into(),
                "domain_command_proposal_digest",
            )?),
        })
    }

    pub fn approve_proposed_effect(
        effect_id: impl Into<String>,
        approval_scope_digest: impl Into<String>,
    ) -> Result<Self, CordisError> {
        Ok(Self {
            kind: DomainCommandKind::ApproveProposedEffect,
            effect_id: normalized_id(effect_id.into(), "domain_command_effect_id")?,
            digest: DomainCommandDigest::ApprovalScope(canonical_digest(
                approval_scope_digest.into(),
                "domain_command_approval_scope_digest",
            )?),
        })
    }

    #[must_use]
    pub const fn kind(&self) -> DomainCommandKind {
        self.kind
    }

    #[must_use]
    pub fn effect_id(&self) -> &str {
        &self.effect_id
    }

    #[must_use]
    pub fn proposal_digest(&self) -> Option<&str> {
        match &self.digest {
            DomainCommandDigest::Proposal(digest) => Some(digest),
            DomainCommandDigest::ApprovalScope(_) => None,
        }
    }

    #[must_use]
    pub fn approval_scope_digest(&self) -> Option<&str> {
        match &self.digest {
            DomainCommandDigest::Proposal(_) => None,
            DomainCommandDigest::ApprovalScope(digest) => Some(digest),
        }
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

/// Unforgeable, one-shot proof that Cordis admitted one exact Domain command.
///
/// Only [`crate::CordisHost`] can issue it. Desktop releases the coordinator
/// lock before invoking Application, then returns the permit for settlement.
pub struct DomainCommandPermit {
    serial: u64,
    scope: AuthorityScope,
    command: DomainCommandBinding,
    lease: Arc<DomainCommandLease>,
    settled: bool,
}

impl DomainCommandPermit {
    pub(crate) fn issue(
        serial: u64,
        scope: AuthorityScope,
        command: DomainCommandBinding,
    ) -> (Self, Arc<DomainCommandLease>) {
        let lease = Arc::new(DomainCommandLease::new());
        (
            Self {
                serial,
                scope,
                command,
                lease: Arc::clone(&lease),
                settled: false,
            },
            lease,
        )
    }

    #[must_use]
    pub const fn scope(&self) -> &AuthorityScope {
        &self.scope
    }

    #[must_use]
    pub const fn command(&self) -> &DomainCommandBinding {
        &self.command
    }

    pub(crate) const fn serial(&self) -> u64 {
        self.serial
    }

    pub(crate) fn owns_lease(&self, lease: &Arc<DomainCommandLease>) -> bool {
        Arc::ptr_eq(&self.lease, lease)
    }

    pub(crate) fn complete(mut self) {
        self.lease.release();
        self.settled = true;
    }
}

impl fmt::Debug for DomainCommandPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DomainCommandPermit")
            .field("serial", &self.serial)
            .field("scope", &self.scope)
            .field("command", &self.command)
            .field("settled", &self.settled)
            .finish_non_exhaustive()
    }
}

impl Drop for DomainCommandPermit {
    fn drop(&mut self) {
        if !self.settled {
            self.lease.release();
        }
    }
}

pub(crate) struct DomainCommandLease {
    active: AtomicBool,
}

impl DomainCommandLease {
    fn new() -> Self {
        Self {
            active: AtomicBool::new(true),
        }
    }

    pub(crate) fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    pub(crate) fn release(&self) {
        self.active.store(false, Ordering::Release);
    }
}

impl fmt::Debug for DomainCommandLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DomainCommandLease")
            .field("active", &self.is_active())
            .finish_non_exhaustive()
    }
}

/// Unforgeable, one-shot proof that Cordis admitted one exact Effect execution.
///
/// Only [`crate::CordisHost`] can issue it. Desktop releases the coordinator
/// lock before invoking Application and the real Effect Broker, then returns
/// the permit for settlement.
pub struct EffectExecutionPermit {
    serial: u64,
    scope: AuthorityScope,
    binding: EffectExecutionBinding,
    lease: Arc<EffectExecutionLease>,
    settled: bool,
}

impl EffectExecutionPermit {
    pub(crate) fn issue(
        serial: u64,
        scope: AuthorityScope,
        binding: EffectExecutionBinding,
    ) -> (Self, Arc<EffectExecutionLease>) {
        let lease = Arc::new(EffectExecutionLease::new());
        (
            Self {
                serial,
                scope,
                binding,
                lease: Arc::clone(&lease),
                settled: false,
            },
            lease,
        )
    }

    #[must_use]
    pub const fn scope(&self) -> &AuthorityScope {
        &self.scope
    }

    #[must_use]
    pub const fn binding(&self) -> &EffectExecutionBinding {
        &self.binding
    }

    pub(crate) const fn serial(&self) -> u64 {
        self.serial
    }

    pub(crate) fn owns_lease(&self, lease: &Arc<EffectExecutionLease>) -> bool {
        Arc::ptr_eq(&self.lease, lease)
    }

    pub(crate) fn complete(mut self) {
        self.lease.release();
        self.settled = true;
    }
}

impl fmt::Debug for EffectExecutionPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EffectExecutionPermit")
            .field("serial", &self.serial)
            .field("scope", &self.scope)
            .field("binding", &self.binding)
            .field("settled", &self.settled)
            .finish_non_exhaustive()
    }
}

impl Drop for EffectExecutionPermit {
    fn drop(&mut self) {
        if !self.settled {
            self.lease.release();
        }
    }
}

pub(crate) struct EffectExecutionLease {
    active: AtomicBool,
}

/// Unforgeable, one-shot proof that Cordis admitted one exact reconciliation.
///
/// The concrete observer and verifier remain in Desktop/Application and run
/// after the Cordis coordinator lock is released.
pub struct EffectReconciliationPermit {
    serial: u64,
    scope: AuthorityScope,
    binding: EffectReconciliationBinding,
    lease: Arc<EffectReconciliationLease>,
    settled: bool,
}

impl EffectReconciliationPermit {
    pub(crate) fn issue(
        serial: u64,
        scope: AuthorityScope,
        binding: EffectReconciliationBinding,
    ) -> (Self, Arc<EffectReconciliationLease>) {
        let lease = Arc::new(EffectReconciliationLease::new());
        (
            Self {
                serial,
                scope,
                binding,
                lease: Arc::clone(&lease),
                settled: false,
            },
            lease,
        )
    }

    #[must_use]
    pub const fn scope(&self) -> &AuthorityScope {
        &self.scope
    }

    #[must_use]
    pub const fn binding(&self) -> &EffectReconciliationBinding {
        &self.binding
    }

    pub(crate) const fn serial(&self) -> u64 {
        self.serial
    }

    pub(crate) fn owns_lease(&self, lease: &Arc<EffectReconciliationLease>) -> bool {
        Arc::ptr_eq(&self.lease, lease)
    }

    pub(crate) fn complete(mut self) {
        self.lease.release();
        self.settled = true;
    }
}

impl fmt::Debug for EffectReconciliationPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EffectReconciliationPermit")
            .field("serial", &self.serial)
            .field("scope", &self.scope)
            .field("binding", &self.binding)
            .field("settled", &self.settled)
            .finish_non_exhaustive()
    }
}

impl Drop for EffectReconciliationPermit {
    fn drop(&mut self) {
        if !self.settled {
            self.lease.release();
        }
    }
}

pub(crate) struct EffectReconciliationLease {
    active: AtomicBool,
}

impl EffectReconciliationLease {
    fn new() -> Self {
        Self {
            active: AtomicBool::new(true),
        }
    }

    pub(crate) fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    pub(crate) fn release(&self) {
        self.active.store(false, Ordering::Release);
    }
}

impl fmt::Debug for EffectReconciliationLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EffectReconciliationLease")
            .field("active", &self.is_active())
            .finish_non_exhaustive()
    }
}

/// Unforgeable, one-shot proof that Cordis admitted one exact independent
/// Receipt verification.
///
/// The concrete read-only source, encrypted evidence, and durable Broker
/// commit remain in Desktop/Application.  This permit only proves that the
/// host admitted the exact opaque scope and fences.
pub struct EffectVerificationPermit {
    serial: u64,
    scope: AuthorityScope,
    binding: EffectVerificationBinding,
    lease: Arc<EffectVerificationLease>,
    settled: bool,
}

impl EffectVerificationPermit {
    pub(crate) fn issue(
        serial: u64,
        scope: AuthorityScope,
        binding: EffectVerificationBinding,
    ) -> (Self, Arc<EffectVerificationLease>) {
        let lease = Arc::new(EffectVerificationLease::new());
        (
            Self {
                serial,
                scope,
                binding,
                lease: Arc::clone(&lease),
                settled: false,
            },
            lease,
        )
    }

    #[must_use]
    pub const fn scope(&self) -> &AuthorityScope {
        &self.scope
    }

    #[must_use]
    pub const fn binding(&self) -> &EffectVerificationBinding {
        &self.binding
    }

    pub(crate) const fn serial(&self) -> u64 {
        self.serial
    }

    pub(crate) fn owns_lease(&self, lease: &Arc<EffectVerificationLease>) -> bool {
        Arc::ptr_eq(&self.lease, lease)
    }

    pub(crate) fn complete(mut self) {
        self.lease.release();
        self.settled = true;
    }
}

impl fmt::Debug for EffectVerificationPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EffectVerificationPermit")
            .field("serial", &self.serial)
            .field("scope", &self.scope)
            .field("binding", &self.binding)
            .field("settled", &self.settled)
            .finish_non_exhaustive()
    }
}

impl Drop for EffectVerificationPermit {
    fn drop(&mut self) {
        if !self.settled {
            self.lease.release();
        }
    }
}

pub(crate) struct EffectVerificationLease {
    active: AtomicBool,
}

impl EffectVerificationLease {
    fn new() -> Self {
        Self {
            active: AtomicBool::new(true),
        }
    }

    pub(crate) fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    pub(crate) fn release(&self) {
        self.active.store(false, Ordering::Release);
    }
}

impl fmt::Debug for EffectVerificationLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EffectVerificationLease")
            .field("active", &self.is_active())
            .finish_non_exhaustive()
    }
}

impl EffectExecutionLease {
    fn new() -> Self {
        Self {
            active: AtomicBool::new(true),
        }
    }

    pub(crate) fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    pub(crate) fn release(&self) {
        self.active.store(false, Ordering::Release);
    }
}

impl fmt::Debug for EffectExecutionLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EffectExecutionLease")
            .field("active", &self.is_active())
            .finish_non_exhaustive()
    }
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
    unpublished: Option<UnpublishedAgent>,
    started: Option<PreparedEmit>,
    disposed: Option<PreparedEmit>,
    started_attempted: bool,
    publication_committed: bool,
    started_result: Option<Result<(), CordisError>>,
    settled: bool,
}

impl RuntimeDispatchPermit {
    pub(crate) fn issue(
        serial: u64,
        scope: AuthorityScope,
        agent_id: String,
        unpublished: UnpublishedAgent,
        started: PreparedEmit,
        disposed: PreparedEmit,
    ) -> (Self, Arc<RuntimeDispatchLease>) {
        let lease = Arc::new(RuntimeDispatchLease::new());
        (
            Self {
                serial,
                scope,
                agent_id,
                lease: Arc::clone(&lease),
                unpublished: Some(unpublished),
                started: Some(started),
                disposed: Some(disposed),
                started_attempted: false,
                publication_committed: false,
                started_result: None,
                settled: false,
            },
            lease,
        )
    }

    /// Publish the started lifecycle after the caller has released its host
    /// lock. Repeated calls are harmless and dispatch at most once.
    pub fn announce_started(&mut self) -> Result<(), CordisError> {
        if let Some(result) = &self.started_result {
            return result.clone();
        }
        self.started_attempted = true;
        let result = self
            .unpublished
            .take()
            .ok_or(CordisError::RuntimePermitMismatch)
            .and_then(UnpublishedAgent::commit)
            .and_then(|publication| {
                self.publication_committed = true;
                self.started.take().map_or(Ok(()), PreparedEmit::dispatch)?;
                self.lease.retain_publication(publication)
            });
        self.started_result = Some(result.clone());
        result
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
        self.unpublished.take();
        self.lease.release();
        self.settled = true;
        RuntimeDispatchCompletion {
            notification: self
                .publication_committed
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
            .field("started_attempted", &self.started_attempted)
            .field("publication_committed", &self.publication_committed)
            .field("started_result", &self.started_result)
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
    pub fn announce(mut self) -> Result<(), CordisError> {
        if let Some(notification) = self.notification.take() {
            notification.dispatch()
        } else {
            Ok(())
        }
    }
}

pub(crate) struct RuntimeDispatchLease {
    active: AtomicBool,
    publication: Mutex<Option<AgentPublicationCommit>>,
}

impl RuntimeDispatchLease {
    fn new() -> Self {
        Self {
            active: AtomicBool::new(true),
            publication: Mutex::new(None),
        }
    }

    pub(crate) fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    fn retain_publication(&self, publication: AgentPublicationCommit) -> Result<(), CordisError> {
        let mut retained = self
            .publication
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !self.is_active() || retained.is_some() {
            return Err(CordisError::RuntimePermitMismatch);
        }
        *retained = Some(publication);
        Ok(())
    }

    pub(crate) fn release(&self) {
        self.active.store(false, Ordering::Release);
        self.publication
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
    }
}

impl fmt::Debug for RuntimeDispatchLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeDispatchLease")
            .field("active", &self.is_active())
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

/// One-shot typed adapter for an Application-owned Domain command.
///
/// The permit proves Cordis scope admission only. The concrete Application
/// adapter still owns command validation, CAS, persistence, and replay rules.
pub trait DomainCommandAuthority {
    type Output;
    type Error;

    fn execute(self, permit: &DomainCommandPermit) -> Result<Self::Output, Self::Error>;
}

/// One-shot typed adapter for the Application-owned Effect Broker path.
///
/// Cordis admits the exact scope and immutable digests only. The concrete
/// Desktop/Application adapter remains the sole holder of the Broker,
/// executor, verifier, durable ledger, and resulting Receipt/Verification.
pub trait EffectExecutionAuthority {
    type Output;
    type Error;

    fn execute(self, permit: &EffectExecutionPermit) -> Result<Self::Output, Self::Error>;
}

/// One-shot typed adapter for Application-owned uncertain-Effect recovery.
///
/// Unlike [`EffectExecutionAuthority`], this adapter can receive only a
/// reconciliation permit and therefore cannot be used as an execution lease.
pub trait EffectReconciliationAuthority {
    type Output;
    type Error;

    fn reconcile(self, permit: &EffectReconciliationPermit) -> Result<Self::Output, Self::Error>;
}

impl<F, Output, AdapterError> EffectReconciliationAuthority for F
where
    F: FnOnce(&EffectReconciliationPermit) -> Result<Output, AdapterError>,
{
    type Output = Output;
    type Error = AdapterError;

    fn reconcile(self, permit: &EffectReconciliationPermit) -> Result<Self::Output, Self::Error> {
        self(permit)
    }
}

/// One-shot typed adapter for the Application-owned independent Receipt
/// verification path.
///
/// This trait is intentionally separate from both execution and uncertain
/// reconciliation. A verification adapter receives no executor, mutable
/// provider adapter, reconciler, or legacy generic `EffectVerifier`.
pub trait EffectVerificationAuthority {
    type Output;
    type Error;

    fn verify(self, permit: &EffectVerificationPermit) -> Result<Self::Output, Self::Error>;
}

impl<F, Output, AdapterError> EffectVerificationAuthority for F
where
    F: FnOnce(&EffectVerificationPermit) -> Result<Output, AdapterError>,
{
    type Output = Output;
    type Error = AdapterError;

    fn verify(self, permit: &EffectVerificationPermit) -> Result<Self::Output, Self::Error> {
        self(permit)
    }
}

impl<F, Output, AdapterError> EffectExecutionAuthority for F
where
    F: FnOnce(&EffectExecutionPermit) -> Result<Output, AdapterError>,
{
    type Output = Output;
    type Error = AdapterError;

    fn execute(self, permit: &EffectExecutionPermit) -> Result<Self::Output, Self::Error> {
        self(permit)
    }
}

impl<F, Output, AdapterError> DomainCommandAuthority for F
where
    F: FnOnce(&DomainCommandPermit) -> Result<Output, AdapterError>,
{
    type Output = Output;
    type Error = AdapterError;

    fn execute(self, permit: &DomainCommandPermit) -> Result<Self::Output, Self::Error> {
        self(permit)
    }
}

/// Multiple phase-preserving authority-dispatch failures.
#[derive(Debug, Eq, PartialEq)]
pub struct AuthorityDispatchFailures<AdapterError> {
    started: Option<CordisError>,
    authority: Option<AdapterError>,
    finish: Option<CordisError>,
    disposed: Option<CordisError>,
}

impl<AdapterError> AuthorityDispatchFailures<AdapterError> {
    #[must_use]
    pub const fn started(&self) -> Option<&CordisError> {
        self.started.as_ref()
    }

    #[must_use]
    pub const fn authority(&self) -> Option<&AdapterError> {
        self.authority.as_ref()
    }

    #[must_use]
    pub const fn finish(&self) -> Option<&CordisError> {
        self.finish.as_ref()
    }

    #[must_use]
    pub const fn disposed(&self) -> Option<&CordisError> {
        self.disposed.as_ref()
    }
}

impl<AdapterError: Display> Display for AuthorityDispatchFailures<AdapterError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut wrote = false;
        macro_rules! phase {
            ($label:literal, $value:expr) => {
                if let Some(value) = $value {
                    if wrote {
                        formatter.write_str("; ")?;
                    }
                    write!(formatter, concat!($label, ": {}"), value)?;
                    wrote = true;
                }
            };
        }
        phase!("started", self.started.as_ref());
        phase!("authority", self.authority.as_ref());
        phase!("finish", self.finish.as_ref());
        phase!("disposed", self.disposed.as_ref());
        debug_assert!(wrote, "combined failures are never empty");
        Ok(())
    }
}

impl<AdapterError> Error for AuthorityDispatchFailures<AdapterError>
where
    AdapterError: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.started
            .as_ref()
            .map(|error| error as &(dyn Error + 'static))
            .or_else(|| {
                self.authority
                    .as_ref()
                    .map(|error| error as &(dyn Error + 'static))
            })
            .or_else(|| {
                self.finish
                    .as_ref()
                    .map(|error| error as &(dyn Error + 'static))
            })
            .or_else(|| {
                self.disposed
                    .as_ref()
                    .map(|error| error as &(dyn Error + 'static))
            })
    }
}

/// Distinguishes a Cordis gate/lifecycle failure from an authority failure.
#[derive(Debug, Eq, PartialEq)]
pub enum AuthorityDispatchError<AdapterError> {
    Cordis(Box<CordisError>),
    Authority(AdapterError),
    Combined(Box<AuthorityDispatchFailures<AdapterError>>),
}

impl<AdapterError> AuthorityDispatchError<AdapterError> {
    /// Classify zero, one, or multiple failures without discarding any phase.
    #[must_use]
    pub fn from_phases(
        started: Option<CordisError>,
        authority: Option<AdapterError>,
        finish: Option<CordisError>,
        disposed: Option<CordisError>,
    ) -> Option<Self> {
        let count = usize::from(started.is_some())
            + usize::from(authority.is_some())
            + usize::from(finish.is_some())
            + usize::from(disposed.is_some());
        match count {
            0 => None,
            1 => authority.map(Self::Authority).or_else(|| {
                started
                    .or(finish)
                    .or(disposed)
                    .map(|error| Self::Cordis(Box::new(error)))
            }),
            _ => Some(Self::Combined(Box::new(AuthorityDispatchFailures {
                started,
                authority,
                finish,
                disposed,
            }))),
        }
    }
}

impl<AdapterError> From<CordisError> for AuthorityDispatchError<AdapterError> {
    fn from(error: CordisError) -> Self {
        Self::Cordis(Box::new(error))
    }
}

impl<AdapterError: Display> Display for AuthorityDispatchError<AdapterError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cordis(error) => Display::fmt(error, formatter),
            Self::Authority(error) => Display::fmt(error, formatter),
            Self::Combined(errors) => Display::fmt(errors, formatter),
        }
    }
}

impl<AdapterError> Error for AuthorityDispatchError<AdapterError>
where
    AdapterError: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Cordis(error) => Some(error.as_ref()),
            Self::Authority(error) => Some(error),
            Self::Combined(errors) => errors.source(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fmt::{self, Display};

    use super::{
        AuthorityDispatchError, AuthorityScope, DomainCommandBinding, DomainCommandKind,
        RuntimeBinding, RuntimeRecordBinding,
    };
    use crate::CordisError;

    #[derive(Debug, Eq, PartialEq)]
    struct AdapterError(&'static str);

    impl Display for AdapterError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(self.0)
        }
    }

    impl Error for AdapterError {}

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

    #[test]
    fn domain_command_binding_is_exact_and_canonical() {
        assert_eq!(
            DomainCommandBinding::approve_proposed_effect("", "a".repeat(64)).unwrap_err(),
            CordisError::InvalidAuthorityScope {
                field: "domain_command_effect_id"
            }
        );
        assert_eq!(
            DomainCommandBinding::approve_proposed_effect(" effect-a ", "a".repeat(64))
                .unwrap_err(),
            CordisError::InvalidAuthorityScope {
                field: "domain_command_effect_id"
            }
        );
        assert_eq!(
            DomainCommandBinding::approve_proposed_effect("effect-a", "A".repeat(64)).unwrap_err(),
            CordisError::InvalidAuthorityDigest {
                field: "domain_command_approval_scope_digest"
            }
        );

        let approval_digest = "b".repeat(64);
        let command =
            DomainCommandBinding::approve_proposed_effect("effect-a", approval_digest.clone())
                .unwrap();
        assert_eq!(command.kind(), DomainCommandKind::ApproveProposedEffect);
        assert_eq!(command.kind().as_str(), "approve_proposed_effect");
        assert_eq!(command.effect_id(), "effect-a");
        assert_eq!(command.proposal_digest(), None);
        assert_eq!(
            command.approval_scope_digest(),
            Some(approval_digest.as_str())
        );

        assert_eq!(
            DomainCommandBinding::propose_effect("effect-a", "A".repeat(64)).unwrap_err(),
            CordisError::InvalidAuthorityDigest {
                field: "domain_command_proposal_digest"
            }
        );
        let proposal_digest = "c".repeat(64);
        let proposal =
            DomainCommandBinding::propose_effect("effect-a", proposal_digest.clone()).unwrap();
        assert_eq!(proposal.kind(), DomainCommandKind::ProposeEffect);
        assert_eq!(proposal.kind().as_str(), "propose_effect");
        assert_eq!(proposal.effect_id(), "effect-a");
        assert_eq!(proposal.proposal_digest(), Some(proposal_digest.as_str()));
        assert_eq!(proposal.approval_scope_digest(), None);
    }

    #[test]
    fn dispatch_failure_table_preserves_every_phase_and_first_source() {
        assert_eq!(
            AuthorityDispatchError::<AdapterError>::from_phases(None, None, None, None),
            None
        );
        assert_eq!(
            AuthorityDispatchError::from_phases(
                None,
                Some(AdapterError("authority-only")),
                None,
                None,
            ),
            Some(AuthorityDispatchError::Authority(AdapterError(
                "authority-only"
            )))
        );

        let started = CordisError::InvalidAuthorityScope { field: "started" };
        let finish = CordisError::InvalidAuthorityRevision { field: "finish" };
        let disposed = CordisError::InvalidAuthorityDigest { field: "disposed" };
        let combined = AuthorityDispatchError::from_phases(
            Some(started.clone()),
            Some(AdapterError("authority")),
            Some(finish.clone()),
            Some(disposed.clone()),
        )
        .unwrap();
        let AuthorityDispatchError::Combined(failures) = &combined else {
            panic!("expected phase-preserving combined failure");
        };
        assert_eq!(failures.started(), Some(&started));
        assert_eq!(failures.authority(), Some(&AdapterError("authority")));
        assert_eq!(failures.finish(), Some(&finish));
        assert_eq!(failures.disposed(), Some(&disposed));
        assert_eq!(
            combined.source().unwrap().downcast_ref::<CordisError>(),
            Some(&started)
        );

        let authority_first = AuthorityDispatchError::from_phases(
            None,
            Some(AdapterError("first")),
            Some(finish),
            None,
        )
        .unwrap();
        assert_eq!(
            authority_first
                .source()
                .unwrap()
                .downcast_ref::<AdapterError>(),
            Some(&AdapterError("first"))
        );
    }
}

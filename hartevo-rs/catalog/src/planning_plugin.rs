//! Scoped, read-only Mission planning composition contracts.
//!
//! This module deliberately models planning as a proposal-producing service. It
//! does not consult the production capability catalog, mint effect authority,
//! or execute a route. The durable log contains digests and typed proposals,
//! never the private objective text supplied to [`PlanningObjective::new`].

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::sha256;

/// Wire schema for the first planning plugin route slice.
pub const PLANNING_PLUGIN_ROUTE_SCHEMA_VERSION: &str = "hartevo-planning-plugin-route/v1";
/// Maximum number of provider route steps in one bounded plan.
pub const MAX_PLANNING_ROUTE_STEPS: usize = 16;
/// Maximum UTF-8 byte length accepted for identifiers and route text.
pub const MAX_PLANNING_TEXT_BYTES: usize = 256;
/// Maximum UTF-8 byte length accepted for a private objective before hashing.
pub const MAX_PLANNING_OBJECTIVE_BYTES: usize = 4_096;
/// Maximum budget units accepted by the planning service.
pub const MAX_PLANNING_BUDGET_UNITS: u32 = 1_000_000;

const INITIAL_LOG_REVISION: u64 = 1;

/// Errors returned by the catalog-scoped planning route contracts.
#[derive(Debug, Error)]
pub enum PlanningError {
    #[error("invalid planning field {field}: {reason}")]
    InvalidField { field: String, reason: String },
    #[error("planning scope mismatch: expected {expected}, got {actual}")]
    ScopeMismatch { expected: String, actual: String },
    #[error("planning request was cancelled at revision {revision}")]
    Cancelled { revision: u64 },
    #[error("planning objective deadline has expired")]
    DeadlineExceeded,
    #[error("planning objective budget is exhausted")]
    BudgetExceeded,
    #[error("unknown planning capability {0}")]
    UnknownCapability(String),
    #[error("provider {provider_id} is unavailable: {state:?}")]
    ProviderUnavailable {
        provider_id: String,
        state: ProviderLifecycleState,
    },
    #[error("provider registration {0} was not found")]
    RegistrationNotFound(String),
    #[error("provider registration {registration_id} has a stale lifecycle revision")]
    StaleRegistration { registration_id: String },
    #[error("provider registration {0} is a duplicate in its scope")]
    DuplicateProvider(String),
    #[error("capability {capability_id} already has an active provider in this scope")]
    DuplicateCapabilityProvider { capability_id: String },
    #[error("planning provider descriptor does not match its scoped registration")]
    ProviderDescriptorMismatch,
    #[error("planning provider rejected the bounded route")]
    ProviderRejected,
    #[error("provider route is invalid: {0}")]
    InvalidProviderRoute(String),
    #[error("proposal is not present in the durable plan log")]
    ProposalNotInPlanLog,
    #[error("proposal digest does not match its content")]
    ProposalDigestMismatch,
    #[error("proposal route digest does not match its route")]
    RouteDrift,
    #[error("proposal provider registration digest does not match current registration")]
    RegistrationDigestMismatch,
    #[error("proposal provider lifecycle revision is stale")]
    ProposalRevisionMismatch,
    #[error("proposal replay conflicts with an existing durable record")]
    ReplayConflict,
    #[error("durable plan log is invalid: {0}")]
    InvalidPlanLog(String),
    #[error("failed to serialize planning contract: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// A capability name owned by a mounted provider, not a central catalog enum.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct PlanningCapabilityId(String);

impl PlanningCapabilityId {
    /// Creates a bounded, non-empty capability identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, PlanningError> {
        let value = value.into();
        validate_text("capability_id", &value)?;
        Ok(Self(value))
    }

    /// Returns the capability identifier without granting execution authority.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Exact Project/Mission revision to which a planning route belongs.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PlanningScope {
    /// Project or tenant-owned composition scope.
    pub project_id: String,
    /// Mission identity within the project.
    pub mission_id: String,
    /// Mission revision fenced into every proposal.
    pub mission_revision: u64,
    /// Digest of the Mission contract revision.
    pub mission_contract_digest: String,
}

impl PlanningScope {
    /// Creates a revision-bound planning scope.
    pub fn new(
        project_id: impl Into<String>,
        mission_id: impl Into<String>,
        mission_revision: u64,
        mission_contract_digest: impl Into<String>,
    ) -> Result<Self, PlanningError> {
        let scope = Self {
            project_id: project_id.into(),
            mission_id: mission_id.into(),
            mission_revision,
            mission_contract_digest: mission_contract_digest.into(),
        };
        scope.validate()?;
        Ok(scope)
    }

    /// Returns the deterministic digest of this exact scope.
    pub fn digest(&self) -> Result<String, PlanningError> {
        self.validate()?;
        digest_json(&(
            PLANNING_PLUGIN_ROUTE_SCHEMA_VERSION,
            &self.project_id,
            &self.mission_id,
            self.mission_revision,
            &self.mission_contract_digest,
        ))
    }

    fn validate(&self) -> Result<(), PlanningError> {
        validate_text("project_id", &self.project_id)?;
        validate_text("mission_id", &self.mission_id)?;
        if self.mission_revision == 0 {
            return Err(invalid_field(
                "mission_revision",
                "must be greater than zero",
            ));
        }
        validate_digest("mission_contract_digest", &self.mission_contract_digest)
    }
}

/// Cancellation fence observed by the synchronous planning service.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PlanningCancellation {
    /// Monotonic caller-owned cancellation revision.
    pub revision: u64,
    /// Whether the request is cancelled.
    pub cancelled: bool,
}

impl PlanningCancellation {
    /// Returns an active cancellation fence.
    #[must_use]
    pub const fn active() -> Self {
        Self {
            revision: 0,
            cancelled: false,
        }
    }

    /// Returns a cancelled fence at `revision`.
    #[must_use]
    pub const fn cancelled(revision: u64) -> Self {
        Self {
            revision,
            cancelled: true,
        }
    }
}

/// Private objective input represented in the planning model by digests only.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PlanningObjective {
    /// Objective identity within the Mission.
    pub objective_id: String,
    /// Exact Mission scope for this objective.
    pub scope: PlanningScope,
    /// Capability requested from the mounted planning provider.
    pub requested_capability: PlanningCapabilityId,
    /// Digest of the private objective text; the text is never retained here.
    pub goal_digest: String,
    /// Caller deadline for the bounded planning request.
    pub deadline: DateTime<Utc>,
    /// Caller budget fence for the bounded route.
    pub budget_units: u32,
    /// Digest covering every public objective field and the private text digest.
    pub objective_digest: String,
}

impl PlanningObjective {
    /// Hashes private text immediately and returns a content-free objective.
    pub fn new(
        objective_id: impl Into<String>,
        scope: PlanningScope,
        goal: &str,
        requested_capability: PlanningCapabilityId,
        deadline: DateTime<Utc>,
        budget_units: u32,
    ) -> Result<Self, PlanningError> {
        if goal.is_empty() || goal.len() > MAX_PLANNING_OBJECTIVE_BYTES {
            return Err(invalid_field(
                "goal",
                "must be non-empty and within the bounded objective size",
            ));
        }
        if budget_units == 0 || budget_units > MAX_PLANNING_BUDGET_UNITS {
            return Err(invalid_field(
                "budget_units",
                "must be within the bounded planning budget",
            ));
        }
        let objective = Self {
            objective_id: objective_id.into(),
            scope,
            requested_capability,
            goal_digest: sha256(goal.as_bytes()),
            deadline,
            budget_units,
            objective_digest: String::new(),
        };
        objective.scope.validate()?;
        validate_text("objective_id", &objective.objective_id)?;
        let objective_digest = objective.expected_digest()?;
        Ok(Self {
            objective_digest,
            ..objective
        })
    }

    /// Recomputes and verifies the objective digest.
    pub fn validate_integrity(&self) -> Result<(), PlanningError> {
        self.scope.validate()?;
        validate_text("objective_id", &self.objective_id)?;
        validate_digest("goal_digest", &self.goal_digest)?;
        validate_digest("objective_digest", &self.objective_digest)?;
        if self.budget_units == 0 || self.budget_units > MAX_PLANNING_BUDGET_UNITS {
            return Err(invalid_field(
                "budget_units",
                "must be within the bounded planning budget",
            ));
        }
        if self.expected_digest()? != self.objective_digest {
            return Err(PlanningError::ProposalDigestMismatch);
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<String, PlanningError> {
        digest_json(&(
            PLANNING_PLUGIN_ROUTE_SCHEMA_VERSION,
            &self.objective_id,
            &self.scope,
            &self.requested_capability,
            &self.goal_digest,
            self.deadline,
            self.budget_units,
        ))
    }
}

/// Versioned and digest-bound provider identity supplied at registration time.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PlanningProviderDescriptor {
    /// Provider identity supplied by the plugin.
    pub provider_id: String,
    /// Semver-shaped provider version bound into the registration.
    pub provider_version: String,
    /// Digest of the provider implementation or signed artifact.
    pub implementation_digest: String,
    /// Capabilities explicitly exposed by this provider in its scope.
    pub capabilities: BTreeSet<PlanningCapabilityId>,
}

impl PlanningProviderDescriptor {
    /// Creates and validates a provider descriptor.
    pub fn new(
        provider_id: impl Into<String>,
        provider_version: impl Into<String>,
        implementation_digest: impl Into<String>,
        capabilities: BTreeSet<PlanningCapabilityId>,
    ) -> Result<Self, PlanningError> {
        let descriptor = Self {
            provider_id: provider_id.into(),
            provider_version: provider_version.into(),
            implementation_digest: implementation_digest.into(),
            capabilities,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    /// Returns the digest used to bind this descriptor to a registration.
    pub fn digest(&self) -> Result<String, PlanningError> {
        self.validate()?;
        digest_json(&(
            PLANNING_PLUGIN_ROUTE_SCHEMA_VERSION,
            &self.provider_id,
            &self.provider_version,
            &self.implementation_digest,
            &self.capabilities,
        ))
    }

    fn validate(&self) -> Result<(), PlanningError> {
        validate_text("provider_id", &self.provider_id)?;
        validate_version(&self.provider_version)?;
        validate_digest("implementation_digest", &self.implementation_digest)?;
        if self.capabilities.is_empty() {
            return Err(invalid_field(
                "capabilities",
                "must expose at least one scoped capability",
            ));
        }
        for capability in &self.capabilities {
            validate_text("capability_id", capability.as_str())?;
        }
        Ok(())
    }
}

/// Provider lifecycle state used to fence proposals after teardown or failure.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProviderLifecycleState {
    /// Provider is mounted and may produce or dispatch proposals.
    Active,
    /// Provider was cleanly unmounted.
    Unmounted,
    /// Provider was explicitly revoked.
    Revoked,
    /// Provider crashed and is fail-closed until remounted.
    Crashed,
}

impl ProviderLifecycleState {
    fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }
}

/// A scoped provider registration and its lifecycle fence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PlanningProviderRegistration {
    /// Registration schema version.
    pub schema_version: String,
    /// Stable identity for this mount instance.
    pub registration_id: String,
    /// Scope in which this provider is mounted.
    pub scope: PlanningScope,
    /// Versioned implementation descriptor.
    pub descriptor: PlanningProviderDescriptor,
    /// Monotonic mount generation for this registry.
    pub generation: u64,
    /// Monotonic lifecycle revision for this registration.
    pub lifecycle_revision: u64,
    /// Current lifecycle state.
    pub state: ProviderLifecycleState,
    /// Digest covering the exact registration and lifecycle state.
    pub registration_digest: String,
    /// Mount timestamp.
    pub registered_at: DateTime<Utc>,
    /// Last lifecycle transition timestamp.
    pub updated_at: DateTime<Utc>,
}

impl PlanningProviderRegistration {
    /// Returns whether this registration can currently back a proposal.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.state.is_active()
    }

    /// Verifies the registration digest and all nested bounds.
    pub fn validate_integrity(&self) -> Result<(), PlanningError> {
        if self.schema_version != PLANNING_PLUGIN_ROUTE_SCHEMA_VERSION {
            return Err(invalid_field(
                "schema_version",
                "unsupported planning provider registration schema",
            ));
        }
        validate_text("registration_id", &self.registration_id)?;
        self.scope.validate()?;
        self.descriptor.validate()?;
        if self.generation == 0 {
            return Err(invalid_field("generation", "must be greater than zero"));
        }
        validate_digest("registration_digest", &self.registration_digest)?;
        let expected = registration_digest(self)?;
        if expected != self.registration_digest {
            return Err(PlanningError::RegistrationDigestMismatch);
        }
        Ok(())
    }
}

/// Provider output consumed by the typed planning service.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PlanningProviderRoute {
    /// Provider-owned route identity.
    pub route_id: String,
    /// Capability at the head of this route.
    pub capability_id: PlanningCapabilityId,
    /// Bounded, read-only route steps.
    pub steps: Vec<PlanningRouteStep>,
    /// Provider's bounded estimate for this route.
    pub estimated_budget_units: u32,
}

impl PlanningProviderRoute {
    /// Creates a typed provider route. The service performs the scoped checks.
    pub fn new(
        route_id: impl Into<String>,
        capability_id: PlanningCapabilityId,
        steps: Vec<PlanningRouteStep>,
        estimated_budget_units: u32,
    ) -> Result<Self, PlanningError> {
        let route = Self {
            route_id: route_id.into(),
            capability_id,
            steps,
            estimated_budget_units,
        };
        route.validate_shape()?;
        Ok(route)
    }

    fn validate_shape(&self) -> Result<(), PlanningError> {
        validate_text("route_id", &self.route_id)?;
        if self.steps.is_empty() || self.steps.len() > MAX_PLANNING_ROUTE_STEPS {
            return Err(invalid_route(
                "must contain one to the bounded maximum number of steps",
            ));
        }
        if self.estimated_budget_units == 0
            || self.estimated_budget_units > MAX_PLANNING_BUDGET_UNITS
        {
            return Err(invalid_route("has an out-of-bounds budget estimate"));
        }
        for (index, step) in self.steps.iter().enumerate() {
            step.validate_shape(bounded_ordinal(index)?)?;
        }
        Ok(())
    }
}

/// One read-only step in a provider route.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PlanningRouteStep {
    /// Provider-owned stable step identity.
    pub step_id: String,
    /// Position in the bounded route.
    pub ordinal: u16,
    /// Capability used by this step.
    pub capability_id: PlanningCapabilityId,
    /// Provider-owned read-only operation name.
    pub operation: String,
    /// Must remain true; false routes are rejected before proposal creation.
    pub read_only: bool,
}

impl PlanningRouteStep {
    /// Creates a read-only step. There is no constructor for an Effect step.
    pub fn new(
        step_id: impl Into<String>,
        ordinal: u16,
        capability_id: PlanningCapabilityId,
        operation: impl Into<String>,
    ) -> Result<Self, PlanningError> {
        let step = Self {
            step_id: step_id.into(),
            ordinal,
            capability_id,
            operation: operation.into(),
            read_only: true,
        };
        step.validate_shape(ordinal)?;
        Ok(step)
    }

    fn validate_shape(&self, expected_ordinal: u16) -> Result<(), PlanningError> {
        validate_text("step_id", &self.step_id)?;
        validate_text("operation", &self.operation)?;
        if self.ordinal != expected_ordinal {
            return Err(invalid_route("step ordinals must be contiguous"));
        }
        if !self.read_only {
            return Err(invalid_route("Effect-capable steps are not permitted"));
        }
        Ok(())
    }
}

/// Trait boundary implemented by a planning plugin provider.
pub trait PlanningProvider {
    /// Returns the versioned descriptor that must match the scoped registration.
    fn descriptor(&self) -> PlanningProviderDescriptor;

    /// Produces a bounded, read-only route for the content-free objective.
    fn propose_route(
        &self,
        objective: &PlanningObjective,
        registration: &PlanningProviderRegistration,
    ) -> Result<PlanningProviderRoute, PlanningProviderError>;
}

/// Provider-local rejection without exposing private objective text.
#[derive(Debug, Error)]
pub enum PlanningProviderError {
    #[error("provider route is invalid")]
    InvalidRoute,
    #[error("provider is unavailable")]
    Unavailable,
    #[error("provider rejected the objective")]
    Rejected,
}

/// Registry containing only providers mounted in one exact Mission scope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ScopedProviderRegistry {
    /// Registry schema version.
    pub schema_version: String,
    /// Scope shared by every registration in this registry.
    pub scope: PlanningScope,
    /// Registry-wide monotonic mutation revision.
    pub registry_revision: u64,
    /// Registration records keyed by mount identity.
    pub registrations: BTreeMap<String, PlanningProviderRegistration>,
    #[serde(skip, default = "initial_generation")]
    next_generation: u64,
}

impl ScopedProviderRegistry {
    /// Creates an empty registry for one Mission revision.
    pub fn new(scope: PlanningScope) -> Result<Self, PlanningError> {
        scope.validate()?;
        Ok(Self {
            schema_version: PLANNING_PLUGIN_ROUTE_SCHEMA_VERSION.into(),
            scope,
            registry_revision: 0,
            registrations: BTreeMap::new(),
            next_generation: initial_generation(),
        })
    }

    /// Registers a provider only inside this registry's scope.
    pub fn register_provider(
        &mut self,
        provider: &dyn PlanningProvider,
        now: DateTime<Utc>,
    ) -> Result<PlanningProviderRegistration, PlanningError> {
        let descriptor = provider.descriptor();
        descriptor.validate()?;
        if self.registrations.values().any(|registration| {
            registration.is_active()
                && registration.descriptor.provider_id == descriptor.provider_id
        }) {
            return Err(PlanningError::DuplicateProvider(
                descriptor.provider_id.clone(),
            ));
        }
        for capability in &descriptor.capabilities {
            if self.registrations.values().any(|registration| {
                registration.is_active()
                    && registration.descriptor.capabilities.contains(capability)
            }) {
                return Err(PlanningError::DuplicateCapabilityProvider {
                    capability_id: capability.as_str().into(),
                });
            }
        }

        let generation = self.allocate_generation();
        let descriptor_digest = descriptor.digest()?;
        let registration_seed = digest_json(&(
            PLANNING_PLUGIN_ROUTE_SCHEMA_VERSION,
            self.scope.digest()?,
            &descriptor.provider_id,
            &descriptor.provider_version,
            descriptor_digest,
            generation,
        ))?;
        let registration_id = format!("planning-registration-{}", &registration_seed[..24]);
        let mut registration = PlanningProviderRegistration {
            schema_version: PLANNING_PLUGIN_ROUTE_SCHEMA_VERSION.into(),
            registration_id,
            scope: self.scope.clone(),
            descriptor,
            generation,
            lifecycle_revision: 0,
            state: ProviderLifecycleState::Active,
            registration_digest: String::new(),
            registered_at: now,
            updated_at: now,
        };
        registration.registration_digest = registration_digest(&registration)?;
        self.registry_revision = self.registry_revision.saturating_add(1);
        self.registrations
            .insert(registration.registration_id.clone(), registration.clone());
        Ok(registration)
    }

    /// Unmounts a provider after checking the caller's lifecycle fence.
    pub fn unmount_provider(
        &mut self,
        registration_id: &str,
        expected_lifecycle_revision: u64,
        now: DateTime<Utc>,
    ) -> Result<PlanningProviderRegistration, PlanningError> {
        self.transition(
            registration_id,
            expected_lifecycle_revision,
            ProviderLifecycleState::Unmounted,
            now,
        )
    }

    /// Revokes a provider and invalidates every proposal bound to this mount.
    pub fn revoke_provider(
        &mut self,
        registration_id: &str,
        expected_lifecycle_revision: u64,
        now: DateTime<Utc>,
    ) -> Result<PlanningProviderRegistration, PlanningError> {
        self.transition(
            registration_id,
            expected_lifecycle_revision,
            ProviderLifecycleState::Revoked,
            now,
        )
    }

    /// Records a provider crash and fences its outstanding proposals.
    pub fn crash_provider(
        &mut self,
        registration_id: &str,
        expected_lifecycle_revision: u64,
        now: DateTime<Utc>,
    ) -> Result<PlanningProviderRegistration, PlanningError> {
        self.transition(
            registration_id,
            expected_lifecycle_revision,
            ProviderLifecycleState::Crashed,
            now,
        )
    }

    /// Looks up a registration by its scoped mount identity.
    pub fn registration(
        &self,
        registration_id: &str,
    ) -> Result<&PlanningProviderRegistration, PlanningError> {
        self.registrations
            .get(registration_id)
            .ok_or_else(|| PlanningError::RegistrationNotFound(registration_id.into()))
    }

    fn active_registration_for(
        &self,
        scope: &PlanningScope,
        capability_id: &PlanningCapabilityId,
    ) -> Result<&PlanningProviderRegistration, PlanningError> {
        ensure_scope(&self.scope, scope)?;
        let matching = self
            .registrations
            .values()
            .filter(|registration| registration.descriptor.capabilities.contains(capability_id))
            .collect::<Vec<_>>();
        if let Some(active) = matching
            .iter()
            .copied()
            .find(|registration| registration.is_active())
        {
            if matching
                .iter()
                .filter(|registration| registration.is_active())
                .count()
                > 1
            {
                return Err(PlanningError::DuplicateCapabilityProvider {
                    capability_id: capability_id.as_str().into(),
                });
            }
            return Ok(active);
        }
        if let Some(unavailable) = matching.first() {
            return Err(PlanningError::ProviderUnavailable {
                provider_id: unavailable.descriptor.provider_id.clone(),
                state: unavailable.state,
            });
        }
        Err(PlanningError::UnknownCapability(
            capability_id.as_str().into(),
        ))
    }

    fn validate_proposal(
        &self,
        proposal: &CapabilityRouteProposal,
        scope: &PlanningScope,
    ) -> Result<(), PlanningError> {
        ensure_scope(&self.scope, scope)?;
        ensure_scope(&self.scope, &proposal.scope)?;
        let registration = self.registration(&proposal.provider_registration_id)?;
        registration.validate_integrity()?;
        if !registration.is_active() {
            return Err(PlanningError::ProviderUnavailable {
                provider_id: registration.descriptor.provider_id.clone(),
                state: registration.state,
            });
        }
        if registration.scope != proposal.scope {
            return Err(PlanningError::ScopeMismatch {
                expected: self.scope.digest()?,
                actual: proposal.scope.digest()?,
            });
        }
        if registration.registration_digest != proposal.provider_registration_digest {
            return Err(PlanningError::RegistrationDigestMismatch);
        }
        if registration.generation != proposal.provider_generation
            || registration.lifecycle_revision != proposal.provider_lifecycle_revision
        {
            return Err(PlanningError::ProposalRevisionMismatch);
        }
        if registration.descriptor.provider_id != proposal.provider_id
            || registration.descriptor.provider_version != proposal.provider_version
            || registration.descriptor.implementation_digest
                != proposal.provider_implementation_digest
            || !registration
                .descriptor
                .capabilities
                .contains(&proposal.capability_id)
        {
            return Err(PlanningError::RegistrationDigestMismatch);
        }
        if proposal.steps.iter().any(|step| {
            !registration
                .descriptor
                .capabilities
                .contains(&step.capability_id)
        }) {
            return Err(PlanningError::UnknownCapability(
                proposal
                    .steps
                    .iter()
                    .find(|step| {
                        !registration
                            .descriptor
                            .capabilities
                            .contains(&step.capability_id)
                    })
                    .map_or_else(String::new, |step| step.capability_id.as_str().into()),
            ));
        }
        Ok(())
    }

    fn allocate_generation(&mut self) -> u64 {
        let highest_existing = self
            .registrations
            .values()
            .map(|registration| registration.generation)
            .max()
            .unwrap_or(0);
        let generation = self.next_generation.max(highest_existing.saturating_add(1));
        self.next_generation = generation.saturating_add(1);
        generation
    }

    fn transition(
        &mut self,
        registration_id: &str,
        expected_lifecycle_revision: u64,
        state: ProviderLifecycleState,
        now: DateTime<Utc>,
    ) -> Result<PlanningProviderRegistration, PlanningError> {
        let current = self.registration(registration_id)?.clone();
        if current.lifecycle_revision != expected_lifecycle_revision {
            return Err(PlanningError::StaleRegistration {
                registration_id: registration_id.into(),
            });
        }
        if !current.is_active() {
            return Err(PlanningError::ProviderUnavailable {
                provider_id: current.descriptor.provider_id,
                state: current.state,
            });
        }
        let registration = self
            .registrations
            .get_mut(registration_id)
            .ok_or_else(|| PlanningError::RegistrationNotFound(registration_id.into()))?;
        registration.lifecycle_revision = registration.lifecycle_revision.saturating_add(1);
        registration.state = state;
        registration.updated_at = now;
        registration.registration_digest = registration_digest(registration)?;
        self.registry_revision = self.registry_revision.saturating_add(1);
        Ok(registration.clone())
    }
}

/// Revision-bound read-only route proposal emitted by [`PlanningService`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CapabilityRouteProposal {
    /// Proposal schema version.
    pub schema_version: String,
    /// Stable proposal identity.
    pub proposal_id: String,
    /// Exact Mission scope.
    pub scope: PlanningScope,
    /// Objective identity and digest.
    pub objective_id: String,
    pub objective_digest: String,
    /// Capability requested by the objective.
    pub capability_id: PlanningCapabilityId,
    /// Provider registration binding.
    pub provider_registration_id: String,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_implementation_digest: String,
    pub provider_registration_digest: String,
    pub provider_generation: u64,
    pub provider_lifecycle_revision: u64,
    /// Provider route and its content digest.
    pub route_id: String,
    pub steps: Vec<PlanningRouteStep>,
    pub estimated_budget_units: u32,
    pub route_digest: String,
    /// Planning revision allocated by the durable log.
    pub planning_revision: u64,
    /// Proposal validity fence copied from the objective.
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// Digest of all proposal fields except this digest itself.
    pub proposal_digest: String,
}

impl CapabilityRouteProposal {
    /// Returns the full proposal digest.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.proposal_digest
    }

    /// Verifies proposal, route, scope, and provider binding bounds.
    pub fn validate_integrity(&self) -> Result<(), PlanningError> {
        if self.schema_version != PLANNING_PLUGIN_ROUTE_SCHEMA_VERSION {
            return Err(invalid_field(
                "schema_version",
                "unsupported planning route proposal schema",
            ));
        }
        validate_text("proposal_id", &self.proposal_id)?;
        self.scope.validate()?;
        validate_text("objective_id", &self.objective_id)?;
        validate_digest("objective_digest", &self.objective_digest)?;
        validate_text("provider_registration_id", &self.provider_registration_id)?;
        validate_text("provider_id", &self.provider_id)?;
        validate_version(&self.provider_version)?;
        validate_digest(
            "provider_implementation_digest",
            &self.provider_implementation_digest,
        )?;
        validate_digest(
            "provider_registration_digest",
            &self.provider_registration_digest,
        )?;
        if self.provider_generation == 0 {
            return Err(invalid_field(
                "provider_generation",
                "must be greater than zero",
            ));
        }
        self.validate_route_shape()?;
        validate_digest("route_digest", &self.route_digest)?;
        validate_digest("proposal_digest", &self.proposal_digest)?;
        if self.planning_revision == 0 {
            return Err(invalid_field(
                "planning_revision",
                "must be greater than zero",
            ));
        }
        let expected_route_digest = self.expected_route_digest()?;
        if expected_route_digest != self.route_digest {
            return Err(PlanningError::RouteDrift);
        }
        if self.expected_proposal_digest()? != self.proposal_digest {
            return Err(PlanningError::ProposalDigestMismatch);
        }
        Ok(())
    }

    fn validate_route_shape(&self) -> Result<(), PlanningError> {
        validate_text("route_id", &self.route_id)?;
        if self.steps.is_empty() || self.steps.len() > MAX_PLANNING_ROUTE_STEPS {
            return Err(invalid_route("has an out-of-bounds step count"));
        }
        if self.estimated_budget_units == 0
            || self.estimated_budget_units > MAX_PLANNING_BUDGET_UNITS
        {
            return Err(invalid_route("has an out-of-bounds budget estimate"));
        }
        for (index, step) in self.steps.iter().enumerate() {
            step.validate_shape(bounded_ordinal(index)?)?;
        }
        Ok(())
    }

    fn expected_route_digest(&self) -> Result<String, PlanningError> {
        digest_json(&(
            PLANNING_PLUGIN_ROUTE_SCHEMA_VERSION,
            &self.scope,
            &self.objective_digest,
            &self.capability_id,
            &self.provider_registration_digest,
            &self.route_id,
            &self.steps,
            self.estimated_budget_units,
        ))
    }

    fn expected_proposal_digest(&self) -> Result<String, PlanningError> {
        digest_json(&(
            PLANNING_PLUGIN_ROUTE_SCHEMA_VERSION,
            &self.proposal_id,
            &self.scope,
            (
                &self.objective_id,
                &self.objective_digest,
                &self.capability_id,
                &self.provider_registration_id,
                &self.provider_id,
                &self.provider_version,
                &self.provider_implementation_digest,
                &self.provider_registration_digest,
                self.provider_generation,
                self.provider_lifecycle_revision,
            ),
            (
                &self.route_id,
                &self.steps,
                self.estimated_budget_units,
                &self.route_digest,
                self.planning_revision,
                self.issued_at,
                self.expires_at,
            ),
        ))
    }
}

/// A durable append-only plan record. It contains no private objective text.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DurablePlanLog {
    /// Log schema version.
    pub schema_version: String,
    /// Scope shared by every log entry.
    pub scope: PlanningScope,
    /// Hash-chain entries in append order.
    pub entries: Vec<PlanLogEntry>,
    /// Digest of the last entry, or the deterministic empty-log digest.
    pub head_digest: String,
}

/// One hash-chained durable planning event.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PlanLogEntry {
    /// One-based append sequence.
    pub sequence: u64,
    /// Typed event payload.
    pub event: PlanLogEvent,
    /// Digest of the previous head and this event.
    pub entry_digest: String,
}

/// Model-visible planning events persisted for replay.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub enum PlanLogEvent {
    /// Objective accepted without retaining its private text.
    ObjectiveAccepted {
        objective_id: String,
        objective_digest: String,
        capability_id: PlanningCapabilityId,
        scope_digest: String,
        recorded_at: DateTime<Utc>,
    },
    /// Full revision-bound proposal emitted by the typed planning service.
    RouteProposed {
        proposal: Box<CapabilityRouteProposal>,
        recorded_at: DateTime<Utc>,
    },
    /// Read-only proposal accepted by the Mission consumer.
    DispatchAccepted {
        record: DurableDispatchRecord,
        recorded_at: DateTime<Utc>,
    },
}

/// Durable, effect-free record of a Mission consumer acceptance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DurableDispatchRecord {
    /// Deterministic acceptance identity.
    pub dispatch_id: String,
    /// Proposal identity and content digests.
    pub proposal_id: String,
    pub proposal_digest: String,
    pub route_digest: String,
    pub provider_registration_digest: String,
}

/// Result returned when the Mission consumer accepts a read-only proposal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionRouteDispatch {
    /// Deterministic acceptance identity.
    pub dispatch_id: String,
    /// Proposal identity and content digests.
    pub proposal_id: String,
    pub proposal_digest: String,
    pub route_digest: String,
    pub provider_registration_digest: String,
    /// Exact Mission scope accepted by the consumer.
    pub scope: PlanningScope,
    /// True when this was an idempotent replay of a durable acceptance.
    pub replayed: bool,
}

impl DurablePlanLog {
    /// Creates an empty durable log for one exact scope.
    pub fn new(scope: PlanningScope) -> Result<Self, PlanningError> {
        scope.validate()?;
        let head_digest = empty_log_digest(&scope)?;
        Ok(Self {
            schema_version: PLANNING_PLUGIN_ROUTE_SCHEMA_VERSION.into(),
            scope,
            entries: Vec::new(),
            head_digest,
        })
    }

    /// Validates the complete hash chain and typed event closure.
    pub fn validate(&self) -> Result<(), PlanningError> {
        if self.schema_version != PLANNING_PLUGIN_ROUTE_SCHEMA_VERSION {
            return Err(PlanningError::InvalidPlanLog(
                "unsupported schema version".into(),
            ));
        }
        self.scope.validate()?;
        validate_digest("head_digest", &self.head_digest)?;
        let mut previous = empty_log_digest(&self.scope)?;
        let mut objective_ids = BTreeMap::<String, String>::new();
        let mut proposals = BTreeMap::<String, String>::new();
        let mut dispatches = BTreeMap::<String, String>::new();
        for (index, entry) in self.entries.iter().enumerate() {
            let expected_sequence = (index as u64).saturating_add(1);
            if entry.sequence != expected_sequence {
                return Err(PlanningError::InvalidPlanLog(
                    "entry sequence is not contiguous".into(),
                ));
            }
            validate_digest("entry_digest", &entry.entry_digest)?;
            let expected_digest =
                entry_digest(&self.scope, entry.sequence, &previous, &entry.event)?;
            if expected_digest != entry.entry_digest {
                return Err(PlanningError::InvalidPlanLog(
                    "entry hash chain does not match".into(),
                ));
            }
            match &entry.event {
                PlanLogEvent::ObjectiveAccepted {
                    objective_id,
                    objective_digest,
                    capability_id,
                    scope_digest,
                    ..
                } => {
                    validate_text("objective_id", objective_id)?;
                    validate_digest("objective_digest", objective_digest)?;
                    validate_digest("scope_digest", scope_digest)?;
                    if scope_digest != &self.scope.digest()? {
                        return Err(PlanningError::InvalidPlanLog(
                            "objective scope digest drifted".into(),
                        ));
                    }
                    if let Some(existing) =
                        objective_ids.insert(objective_id.clone(), objective_digest.clone())
                        && existing != *objective_digest
                    {
                        return Err(PlanningError::ReplayConflict);
                    }
                    validate_text("capability_id", capability_id.as_str())?;
                }
                PlanLogEvent::RouteProposed { proposal, .. } => {
                    proposal.validate_integrity()?;
                    ensure_scope(&self.scope, &proposal.scope)?;
                    let objective_digest =
                        objective_ids.get(&proposal.objective_id).ok_or_else(|| {
                            PlanningError::InvalidPlanLog(
                                "route proposal has no accepted objective".into(),
                            )
                        })?;
                    if objective_digest != &proposal.objective_digest {
                        return Err(PlanningError::ReplayConflict);
                    }
                    if let Some(existing) = proposals.insert(
                        proposal.proposal_id.clone(),
                        proposal.proposal_digest.clone(),
                    ) && existing != proposal.proposal_digest
                    {
                        return Err(PlanningError::ReplayConflict);
                    }
                }
                PlanLogEvent::DispatchAccepted { record, .. } => {
                    validate_dispatch_record(record)?;
                    let proposal_digest = proposals
                        .get(&record.proposal_id)
                        .ok_or(PlanningError::ProposalNotInPlanLog)?;
                    if proposal_digest != &record.proposal_digest {
                        return Err(PlanningError::ReplayConflict);
                    }
                    if let Some(existing) = dispatches
                        .insert(record.proposal_id.clone(), record.proposal_digest.clone())
                    {
                        if existing != record.proposal_digest {
                            return Err(PlanningError::ReplayConflict);
                        }
                        return Err(PlanningError::InvalidPlanLog(
                            "duplicate dispatch acceptance".into(),
                        ));
                    }
                }
            }
            previous.clone_from(&entry.entry_digest);
        }
        if self.head_digest != previous {
            return Err(PlanningError::InvalidPlanLog(
                "head digest does not match the last entry".into(),
            ));
        }
        Ok(())
    }

    /// Returns the next deterministic planning revision.
    #[must_use]
    pub fn next_revision(&self) -> u64 {
        (self.entries.len() as u64).saturating_add(INITIAL_LOG_REVISION)
    }

    /// Finds a previously proposed route for objective replay.
    #[must_use]
    pub fn proposal_for_objective(
        &self,
        objective_id: &str,
        objective_digest: &str,
    ) -> Option<CapabilityRouteProposal> {
        self.entries.iter().find_map(|entry| {
            let PlanLogEvent::RouteProposed { proposal, .. } = &entry.event else {
                return None;
            };
            (proposal.objective_id == objective_id && proposal.objective_digest == objective_digest)
                .then(|| proposal.as_ref().clone())
        })
    }

    /// Finds a durable dispatch record by proposal identity.
    #[must_use]
    pub fn dispatch_for(&self, proposal_id: &str) -> Option<DurableDispatchRecord> {
        self.entries.iter().find_map(|entry| {
            let PlanLogEvent::DispatchAccepted { record, .. } = &entry.event else {
                return None;
            };
            (record.proposal_id == proposal_id).then(|| record.clone())
        })
    }

    fn record_objective(
        &mut self,
        objective: &PlanningObjective,
        recorded_at: DateTime<Utc>,
    ) -> Result<(), PlanningError> {
        objective.validate_integrity()?;
        ensure_scope(&self.scope, &objective.scope)?;
        if let Some(existing) = self.objective_digest_for_id(&objective.objective_id) {
            if existing == objective.objective_digest {
                return Ok(());
            }
            return Err(PlanningError::ReplayConflict);
        }
        self.append(PlanLogEvent::ObjectiveAccepted {
            objective_id: objective.objective_id.clone(),
            objective_digest: objective.objective_digest.clone(),
            capability_id: objective.requested_capability.clone(),
            scope_digest: self.scope.digest()?,
            recorded_at,
        })
    }

    fn record_proposal(
        &mut self,
        proposal: &CapabilityRouteProposal,
        recorded_at: DateTime<Utc>,
    ) -> Result<(), PlanningError> {
        proposal.validate_integrity()?;
        ensure_scope(&self.scope, &proposal.scope)?;
        if let Some(existing) = self.proposal_for_id(&proposal.proposal_id) {
            if existing == proposal.proposal_digest {
                return Ok(());
            }
            return Err(PlanningError::ReplayConflict);
        }
        self.append(PlanLogEvent::RouteProposed {
            proposal: Box::new(proposal.clone()),
            recorded_at,
        })
    }

    fn record_dispatch(
        &mut self,
        record: DurableDispatchRecord,
        recorded_at: DateTime<Utc>,
    ) -> Result<(), PlanningError> {
        validate_dispatch_record(&record)?;
        if let Some(existing) = self.dispatch_for(&record.proposal_id) {
            if existing == record {
                return Ok(());
            }
            return Err(PlanningError::ReplayConflict);
        }
        self.append(PlanLogEvent::DispatchAccepted {
            record,
            recorded_at,
        })
    }

    fn append(&mut self, event: PlanLogEvent) -> Result<(), PlanningError> {
        let sequence = self.next_revision();
        let entry_digest = entry_digest(&self.scope, sequence, &self.head_digest, &event)?;
        self.entries.push(PlanLogEntry {
            sequence,
            event,
            entry_digest: entry_digest.clone(),
        });
        self.head_digest = entry_digest;
        Ok(())
    }

    fn objective_digest_for_id(&self, objective_id: &str) -> Option<String> {
        self.entries.iter().find_map(|entry| {
            let PlanLogEvent::ObjectiveAccepted {
                objective_id: stored_id,
                objective_digest,
                ..
            } = &entry.event
            else {
                return None;
            };
            (stored_id == objective_id).then(|| objective_digest.clone())
        })
    }

    fn proposal_for_id(&self, proposal_id: &str) -> Option<String> {
        self.entries.iter().find_map(|entry| {
            let PlanLogEvent::RouteProposed { proposal, .. } = &entry.event else {
                return None;
            };
            (proposal.proposal_id == proposal_id).then(|| proposal.proposal_digest.clone())
        })
    }
}

/// Typed service that turns an objective into a durable, read-only proposal.
#[derive(Clone, Debug)]
pub struct PlanningService {
    log: DurablePlanLog,
}

impl PlanningService {
    /// Creates a service bound to one Mission scope.
    pub fn new(scope: PlanningScope) -> Result<Self, PlanningError> {
        Ok(Self {
            log: DurablePlanLog::new(scope)?,
        })
    }

    /// Plans through the provider selected by the scoped registration.
    pub fn plan(
        &mut self,
        objective: &PlanningObjective,
        registry: &ScopedProviderRegistry,
        provider: &dyn PlanningProvider,
        cancellation: &PlanningCancellation,
        now: DateTime<Utc>,
    ) -> Result<CapabilityRouteProposal, PlanningError> {
        validate_plan_request(
            objective,
            &self.log.scope,
            &registry.scope,
            cancellation,
            now,
        )?;
        if let Some(replayed) = self
            .log
            .proposal_for_objective(&objective.objective_id, &objective.objective_digest)
        {
            return Ok(replayed);
        }

        let registration =
            registry.active_registration_for(&objective.scope, &objective.requested_capability)?;
        let descriptor = provider.descriptor();
        if descriptor != registration.descriptor {
            return Err(PlanningError::ProviderDescriptorMismatch);
        }
        let route = provider
            .propose_route(objective, registration)
            .map_err(|_| PlanningError::ProviderRejected)?;
        route.validate_shape()?;
        if route.capability_id != objective.requested_capability {
            return Err(invalid_route(
                "head capability does not match the objective",
            ));
        }
        if route.estimated_budget_units > objective.budget_units {
            return Err(PlanningError::BudgetExceeded);
        }
        validate_route_capabilities(&route, registration)?;
        if now > objective.deadline {
            return Err(PlanningError::DeadlineExceeded);
        }

        let planning_revision = self.log.next_revision();
        let proposal = build_proposal(objective, registration, route, planning_revision, now)?;
        proposal.validate_integrity()?;

        let mut next_log = self.log.clone();
        next_log.record_objective(objective, now)?;
        next_log.record_proposal(&proposal, now)?;
        next_log.validate()?;
        self.log = next_log;
        Ok(proposal)
    }

    /// Borrows the current durable plan log.
    #[must_use]
    pub const fn plan_log(&self) -> &DurablePlanLog {
        &self.log
    }

    /// Consumes the service and returns its durable plan log.
    #[must_use]
    pub fn into_plan_log(self) -> DurablePlanLog {
        self.log
    }
}

/// Mission-side consumer that accepts proposals and records no Effect authority.
#[derive(Clone, Debug, Default)]
pub struct MissionPlanningConsumer;

impl MissionPlanningConsumer {
    /// Accepts or idempotently replays a proposal while the provider is active.
    pub fn dispatch(
        &self,
        proposal: &CapabilityRouteProposal,
        current_scope: &PlanningScope,
        registry: &ScopedProviderRegistry,
        log: &mut DurablePlanLog,
        now: DateTime<Utc>,
    ) -> Result<MissionRouteDispatch, PlanningError> {
        proposal.validate_integrity()?;
        current_scope.validate()?;
        ensure_scope(current_scope, &proposal.scope)?;
        ensure_scope(&log.scope, current_scope)?;
        if now > proposal.expires_at {
            return Err(PlanningError::DeadlineExceeded);
        }
        log.validate()?;
        let Some(recorded_proposal) =
            log.proposal_for_objective(&proposal.objective_id, &proposal.objective_digest)
        else {
            return Err(PlanningError::ProposalNotInPlanLog);
        };
        if recorded_proposal.proposal_id != proposal.proposal_id
            || recorded_proposal.proposal_digest != proposal.proposal_digest
        {
            return Err(PlanningError::ReplayConflict);
        }

        // Lifecycle validation intentionally precedes the replay fast path:
        // a revoked, unmounted, crashed, or stale provider cannot dispatch an
        // old proposal even when that proposal was accepted earlier.
        registry.validate_proposal(proposal, current_scope)?;
        if let Some(existing) = log.dispatch_for(&proposal.proposal_id) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(PlanningError::ReplayConflict);
            }
            return Ok(dispatch_from_record(existing, current_scope.clone(), true));
        }

        let record = DurableDispatchRecord {
            dispatch_id: format!("planning-dispatch-{}", &proposal.proposal_digest[..24]),
            proposal_id: proposal.proposal_id.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            route_digest: proposal.route_digest.clone(),
            provider_registration_digest: proposal.provider_registration_digest.clone(),
        };
        let mut next_log = log.clone();
        next_log.record_dispatch(record.clone(), now)?;
        next_log.validate()?;
        *log = next_log;
        Ok(dispatch_from_record(record, current_scope.clone(), false))
    }
}

fn dispatch_from_record(
    record: DurableDispatchRecord,
    scope: PlanningScope,
    replayed: bool,
) -> MissionRouteDispatch {
    MissionRouteDispatch {
        dispatch_id: record.dispatch_id,
        proposal_id: record.proposal_id,
        proposal_digest: record.proposal_digest,
        route_digest: record.route_digest,
        provider_registration_digest: record.provider_registration_digest,
        scope,
        replayed,
    }
}

fn validate_plan_request(
    objective: &PlanningObjective,
    service_scope: &PlanningScope,
    registry_scope: &PlanningScope,
    cancellation: &PlanningCancellation,
    now: DateTime<Utc>,
) -> Result<(), PlanningError> {
    objective.validate_integrity()?;
    ensure_scope(service_scope, &objective.scope)?;
    ensure_scope(registry_scope, &objective.scope)?;
    if cancellation.cancelled {
        return Err(PlanningError::Cancelled {
            revision: cancellation.revision,
        });
    }
    if now > objective.deadline {
        return Err(PlanningError::DeadlineExceeded);
    }
    Ok(())
}

fn validate_route_capabilities(
    route: &PlanningProviderRoute,
    registration: &PlanningProviderRegistration,
) -> Result<(), PlanningError> {
    if let Some(step) = route.steps.iter().find(|step| {
        !registration
            .descriptor
            .capabilities
            .contains(&step.capability_id)
    }) {
        return Err(PlanningError::UnknownCapability(
            step.capability_id.as_str().into(),
        ));
    }
    Ok(())
}

fn build_proposal(
    objective: &PlanningObjective,
    registration: &PlanningProviderRegistration,
    route: PlanningProviderRoute,
    planning_revision: u64,
    now: DateTime<Utc>,
) -> Result<CapabilityRouteProposal, PlanningError> {
    let route_digest = digest_json(&(
        PLANNING_PLUGIN_ROUTE_SCHEMA_VERSION,
        &objective.scope,
        &objective.objective_digest,
        &route.capability_id,
        &registration.registration_digest,
        &route.route_id,
        &route.steps,
        route.estimated_budget_units,
    ))?;
    let proposal_id = format!(
        "planning-proposal-{}-{}",
        &objective.objective_digest[..16],
        planning_revision
    );
    let mut proposal = CapabilityRouteProposal {
        schema_version: PLANNING_PLUGIN_ROUTE_SCHEMA_VERSION.into(),
        proposal_id,
        scope: objective.scope.clone(),
        objective_id: objective.objective_id.clone(),
        objective_digest: objective.objective_digest.clone(),
        capability_id: objective.requested_capability.clone(),
        provider_registration_id: registration.registration_id.clone(),
        provider_id: registration.descriptor.provider_id.clone(),
        provider_version: registration.descriptor.provider_version.clone(),
        provider_implementation_digest: registration.descriptor.implementation_digest.clone(),
        provider_registration_digest: registration.registration_digest.clone(),
        provider_generation: registration.generation,
        provider_lifecycle_revision: registration.lifecycle_revision,
        route_id: route.route_id,
        steps: route.steps,
        estimated_budget_units: route.estimated_budget_units,
        route_digest,
        planning_revision,
        issued_at: now,
        expires_at: objective.deadline,
        proposal_digest: String::new(),
    };
    proposal.proposal_digest = proposal.expected_proposal_digest()?;
    Ok(proposal)
}

fn registration_digest(
    registration: &PlanningProviderRegistration,
) -> Result<String, PlanningError> {
    digest_json(&(
        PLANNING_PLUGIN_ROUTE_SCHEMA_VERSION,
        &registration.registration_id,
        &registration.scope,
        &registration.descriptor,
        registration.generation,
        registration.lifecycle_revision,
        registration.state,
        registration.registered_at,
        registration.updated_at,
    ))
}

fn empty_log_digest(scope: &PlanningScope) -> Result<String, PlanningError> {
    digest_json(&(PLANNING_PLUGIN_ROUTE_SCHEMA_VERSION, scope))
}

fn entry_digest(
    scope: &PlanningScope,
    sequence: u64,
    previous: &str,
    event: &PlanLogEvent,
) -> Result<String, PlanningError> {
    digest_json(&(
        PLANNING_PLUGIN_ROUTE_SCHEMA_VERSION,
        scope,
        sequence,
        previous,
        event,
    ))
}

fn validate_dispatch_record(record: &DurableDispatchRecord) -> Result<(), PlanningError> {
    validate_text("dispatch_id", &record.dispatch_id)?;
    validate_text("proposal_id", &record.proposal_id)?;
    validate_digest("proposal_digest", &record.proposal_digest)?;
    validate_digest("route_digest", &record.route_digest)?;
    validate_digest(
        "provider_registration_digest",
        &record.provider_registration_digest,
    )
}

fn ensure_scope(expected: &PlanningScope, actual: &PlanningScope) -> Result<(), PlanningError> {
    if expected == actual {
        Ok(())
    } else {
        Err(PlanningError::ScopeMismatch {
            expected: expected.digest()?,
            actual: actual.digest()?,
        })
    }
}

fn digest_json<T: Serialize>(value: &T) -> Result<String, PlanningError> {
    Ok(sha256(&serde_json::to_vec(value)?))
}

fn validate_text(field: &str, value: &str) -> Result<(), PlanningError> {
    if value.trim().is_empty() || value.len() > MAX_PLANNING_TEXT_BYTES {
        return Err(invalid_field(
            field,
            "must be non-empty and within the bounded text size",
        ));
    }
    Ok(())
}

fn validate_digest(field: &str, value: &str) -> Result<(), PlanningError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid_field(
            field,
            "must be a lowercase-or-uppercase SHA-256 digest",
        ));
    }
    Ok(())
}

fn validate_version(value: &str) -> Result<(), PlanningError> {
    validate_text("provider_version", value)?;
    let mut components = value.split('.');
    let valid = components.clone().count() == 3
        && components.all(|component| {
            !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit())
        });
    if valid {
        Ok(())
    } else {
        Err(invalid_field(
            "provider_version",
            "must use numeric major.minor.patch form",
        ))
    }
}

fn invalid_field(field: &str, reason: &str) -> PlanningError {
    PlanningError::InvalidField {
        field: field.into(),
        reason: reason.into(),
    }
}

fn invalid_route(reason: &str) -> PlanningError {
    PlanningError::InvalidProviderRoute(reason.into())
}

fn bounded_ordinal(index: usize) -> Result<u16, PlanningError> {
    u16::try_from(index).map_err(|_| invalid_route("step ordinal exceeds the bounded range"))
}

const fn initial_generation() -> u64 {
    1
}

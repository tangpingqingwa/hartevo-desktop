use std::fmt;

use chrono::{DateTime, Utc};

use crate::canonical::digest_parts;
use crate::model::{
    AuthIdentityObservation, CapabilityDescription, CapabilityRegistration, DatabaseGrant,
    DatabasePrivilege, EvidenceProvenance, IdentityProjection, MissionScope, PolicyDecision,
    PolicyDecisionProposal, PolicyProjection, ProjectionReason, RegistrationProbe,
    RegistrationState, RlsPolicyEvidence, SecretReference, SupabaseEvidencePack,
    SupabaseIdentityEvidence, SupabaseIdentityRecord, SupabasePermissionSet,
    SupabasePolicyEvidence, SupabaseScope, TableScope,
};
use crate::provider::{SupabaseIdentityProvider, SupabaseProviderManifest};
use crate::{
    MAX_GRANTS, MAX_POLICIES, MAX_RESPONSE_BYTES, SupabaseIdentityError, SupabaseProviderError,
};

/// Typed Service boundary for read-only Supabase identity and RLS evidence.
/// It owns scope/digest/provenance validation and local proposal compilation,
/// but it exposes no external write, SQL, receipt, or adoption operation.
pub struct SupabaseIdentityService {
    provider: SupabaseIdentityProvider,
    registration: CapabilityRegistration,
    permissions: SupabasePermissionSet,
    secret_reference: SecretReference,
}

impl fmt::Debug for SupabaseIdentityService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SupabaseIdentityService")
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .field("permissions", &self.permissions)
            .field("secret_reference", &self.secret_reference)
            .finish()
    }
}

impl SupabaseIdentityService {
    pub fn new(
        provider: SupabaseIdentityProvider,
        registration: CapabilityRegistration,
        permissions: SupabasePermissionSet,
        secret_reference: SecretReference,
    ) -> Result<Self, SupabaseIdentityError> {
        if secret_reference.is_service_role() {
            return Err(SupabaseIdentityError::ServiceRoleAuthorityRejected);
        }
        secret_reference.validate()?;
        provider
            .manifest()
            .validate_for(&registration.scope, &permissions)?;
        registration.validate(&permissions)?;
        registration.assert_fences(
            &registration.scope,
            provider.provider_digest(),
            &permissions,
        )?;
        if secret_reference.project_ref() != registration.scope.project_ref
            || secret_reference.scope_digest() != registration.scope_digest
        {
            return Err(SupabaseIdentityError::RegistrationDrift);
        }
        Ok(Self {
            provider,
            registration,
            permissions,
            secret_reference,
        })
    }

    pub fn register(
        provider: SupabaseIdentityProvider,
        registration_id: impl Into<String>,
        scope: SupabaseScope,
        permissions: SupabasePermissionSet,
        secret_reference: SecretReference,
    ) -> Result<Self, SupabaseIdentityError> {
        if provider.manifest().scope != scope {
            return Err(SupabaseIdentityError::RegistrationDrift);
        }
        let registration = CapabilityRegistration::new(
            registration_id,
            scope,
            provider.provider_digest().to_owned(),
            &permissions,
        )?;
        Self::new(provider, registration, permissions, secret_reference)
    }

    pub fn provider(&self) -> &SupabaseIdentityProvider {
        &self.provider
    }

    pub fn provider_manifest(&self) -> &SupabaseProviderManifest {
        self.provider.manifest()
    }

    pub fn registration(&self) -> &CapabilityRegistration {
        &self.registration
    }

    pub fn permissions(&self) -> &SupabasePermissionSet {
        &self.permissions
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn scope(&self) -> &SupabaseScope {
        &self.registration.scope
    }

    pub fn describe_capabilities(&self) -> Result<CapabilityDescription, SupabaseIdentityError> {
        self.ensure_fences()?;
        self.provider.capability_description(self.scope())
    }

    pub fn probe_registration(
        &self,
        observed_at: DateTime<Utc>,
    ) -> Result<RegistrationProbe, SupabaseIdentityError> {
        self.ensure_active()?;
        self.ensure_fences()?;
        let evidence_digest = digest_parts(&[
            &self.registration.registration_digest,
            self.provider.provenance_name(),
            &observed_at.to_rfc3339(),
        ]);
        Ok(RegistrationProbe {
            registration_digest: self.registration.registration_digest.clone(),
            provider_digest: self.provider.provider_digest().into(),
            permission_digest: self.registration.permission_digest.clone(),
            scope_digest: self.registration.scope_digest.clone(),
            state: self.registration.state,
            observed_at,
            provenance: self.provider.provenance(),
            native_status: self.provider.native_status(),
            connected: false,
            native: false,
            evidence_digest,
        })
    }

    pub fn reverse_registration(&mut self) -> Result<(), SupabaseIdentityError> {
        self.registration.reverse()
    }

    pub fn restore_registration(&mut self) -> Result<(), SupabaseIdentityError> {
        self.registration.restore()
    }

    pub fn revoke_registration(&mut self) -> Result<(), SupabaseIdentityError> {
        self.registration.revoke()
    }

    pub fn read_project_metadata(
        &self,
        observed_at: DateTime<Utc>,
    ) -> Result<crate::ManagementMetadataObservation, SupabaseIdentityError> {
        self.ensure_active()?;
        self.ensure_fences()?;
        let observation = self.provider.read_management_metadata(
            self.scope(),
            &self.secret_reference,
            observed_at,
        )?;
        self.validate_management_observation(&observation)?;
        Ok(observation)
    }

    pub fn read_identity(
        &self,
        observed_at: DateTime<Utc>,
    ) -> Result<IdentityProjection, SupabaseIdentityError> {
        self.ensure_active()?;
        self.ensure_fences()?;
        if self.secret_reference.authority() == crate::CredentialAuthority::AnonKey {
            return Ok(IdentityProjection::Denied {
                reason: ProjectionReason::AnonymousCredential,
                scope_digest: self.scope().digest(),
                observed_at,
            });
        }
        let observation = match self.provider.read_auth_identity(
            self.scope(),
            &self.secret_reference,
            observed_at,
        ) {
            Ok(observation) => observation,
            Err(error) => return Ok(self.identity_provider_error(error, observed_at)),
        };
        if observation.response_bytes > MAX_RESPONSE_BYTES {
            return Ok(self.identity_unknown(
                ProjectionReason::ProviderUnknown {
                    code: "response_bound_exceeded".into(),
                },
                observed_at,
            ));
        }
        if let Err(error) = observation.verify_integrity() {
            return Ok(self.identity_error_projection(&error, observed_at));
        }
        if observation.scope_digest != self.scope().digest()
            || observation.project_ref != self.scope().project_ref
            || observation.region != self.scope().region
            || observation.tenant_id != self.scope().tenant_id
            || observation.provider_revision != crate::PROVIDER_API_REVISION
        {
            return Ok(self.identity_scope_mismatch(observed_at));
        }
        let Some(identity) = observation.identity.clone() else {
            return Ok(IdentityProjection::Absent {
                reason: ProjectionReason::NoIdentity,
                scope_digest: self.scope().digest(),
                observed_at,
            });
        };
        if let Err(error) = identity.validate() {
            return Ok(self.identity_error_projection(&error, observed_at));
        }
        match identity.state {
            crate::IdentityState::Deleted => {
                return Ok(IdentityProjection::Absent {
                    reason: ProjectionReason::UserDeleted,
                    scope_digest: self.scope().digest(),
                    observed_at,
                });
            }
            crate::IdentityState::AccessLost => {
                return Ok(IdentityProjection::Denied {
                    reason: ProjectionReason::AccessLost,
                    scope_digest: self.scope().digest(),
                    observed_at,
                });
            }
            crate::IdentityState::Active => {}
        }
        if identity.user_id
            != self
                .scope()
                .subject_user_id
                .clone()
                .unwrap_or_else(|| identity.user_id.clone())
        {
            return Ok(self.identity_scope_mismatch(observed_at));
        }
        if identity.tenant_id != self.scope().tenant_id {
            return Ok(IdentityProjection::ScopeMismatch {
                reason: ProjectionReason::TenantCrossing,
                scope_digest: self.scope().digest(),
                observed_at,
            });
        }
        if !self.scope().allowed_roles.contains(&identity.role) {
            return Ok(IdentityProjection::Denied {
                reason: ProjectionReason::RoleNotAllowed,
                scope_digest: self.scope().digest(),
                observed_at,
            });
        }
        let Some(claims) = observation.jwt_claims.clone() else {
            return Ok(IdentityProjection::Absent {
                reason: ProjectionReason::NoIdentity,
                scope_digest: self.scope().digest(),
                observed_at,
            });
        };
        if let Err(error) = claims.validate_for(self.scope(), observed_at) {
            return Ok(self.identity_error_projection(&error, observed_at));
        }
        let evidence = self.identity_evidence(&observation, identity, claims);
        Ok(IdentityProjection::Present(evidence))
    }

    pub fn read_auth_identity(
        &self,
        observed_at: DateTime<Utc>,
    ) -> Result<IdentityProjection, SupabaseIdentityError> {
        self.read_identity(observed_at)
    }

    pub fn read_policy(
        &self,
        observed_at: DateTime<Utc>,
    ) -> Result<PolicyProjection, SupabaseIdentityError> {
        self.ensure_active()?;
        self.ensure_fences()?;
        if self.secret_reference.authority() == crate::CredentialAuthority::AnonKey {
            return Ok(PolicyProjection::Denied {
                reason: ProjectionReason::AnonymousCredential,
                scope_digest: self.scope().digest(),
                observed_at,
            });
        }
        let observation = match self.provider.read_postgrest_metadata(
            self.scope(),
            &self.secret_reference,
            observed_at,
        ) {
            Ok(observation) => observation,
            Err(error) => return Ok(self.policy_provider_error(error, observed_at)),
        };
        if observation.response_bytes > MAX_RESPONSE_BYTES
            || observation.grants.len() > MAX_GRANTS
            || observation.policies.len() > MAX_POLICIES
        {
            return Ok(self.policy_unknown(
                ProjectionReason::ProviderUnknown {
                    code: "response_bound_exceeded".into(),
                },
                observed_at,
            ));
        }
        if let Err(error) = observation.verify_integrity() {
            return Ok(self.policy_error_projection(&error, observed_at));
        }
        if observation.scope_digest != self.scope().digest()
            || observation.project_ref != self.scope().project_ref
            || observation.region != self.scope().region
            || observation.tenant_id != self.scope().tenant_id
            || observation.provider_revision != crate::PROVIDER_API_REVISION
        {
            return Ok(self.policy_scope_mismatch(observed_at));
        }
        for grant in &observation.grants {
            if let Err(error) = self.validate_grant(grant) {
                return Ok(self.policy_scope_or_error(&error, &observation, observed_at));
            }
        }
        for policy in &observation.policies {
            if let Err(error) = self.validate_policy(policy) {
                return Ok(self.policy_scope_or_error(&error, &observation, observed_at));
            }
        }
        let evidence = self.policy_evidence(&observation);
        if observation.grants.is_empty() && observation.policies.is_empty() {
            return Ok(PolicyProjection::Absent {
                reason: ProjectionReason::NotFound,
                scope_digest: self.scope().digest(),
                observed_at,
            });
        }
        if observation.grants.is_empty() || observation.policies.is_empty() {
            return Ok(PolicyProjection::Mismatch {
                reason: ProjectionReason::GrantPolicyMismatch,
                evidence: Some(evidence),
                scope_digest: self.scope().digest(),
                observed_at,
            });
        }
        if observation.grant_revision != self.scope().grant_revision {
            return Ok(PolicyProjection::Mismatch {
                reason: ProjectionReason::GrantRevisionDrift,
                evidence: Some(evidence),
                scope_digest: self.scope().digest(),
                observed_at,
            });
        }
        if observation.policy_revision != self.scope().policy_revision {
            return Ok(PolicyProjection::Mismatch {
                reason: ProjectionReason::PolicyRevisionDrift,
                evidence: Some(evidence),
                scope_digest: self.scope().digest(),
                observed_at,
            });
        }
        if !self.grants_and_policies_match(&observation.grants, &observation.policies) {
            return Ok(PolicyProjection::Mismatch {
                reason: ProjectionReason::GrantPolicyMismatch,
                evidence: Some(evidence),
                scope_digest: self.scope().digest(),
                observed_at,
            });
        }
        Ok(PolicyProjection::Present(evidence))
    }

    pub fn read_rls_policy_evidence(
        &self,
        observed_at: DateTime<Utc>,
    ) -> Result<PolicyProjection, SupabaseIdentityError> {
        self.read_policy(observed_at)
    }

    pub fn read_evidence(
        &self,
        observed_at: DateTime<Utc>,
    ) -> Result<SupabaseEvidencePack, SupabaseIdentityError> {
        let identity = self.read_identity(observed_at)?;
        let policy = self.read_policy(observed_at)?;
        SupabaseEvidencePack::new(
            identity,
            policy,
            self.scope().digest(),
            self.registration.registration_digest.clone(),
            self.provider.provider_digest().to_owned(),
            observed_at,
            self.provider.provenance(),
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the typed proposal boundary keeps every scope input explicit"
    )]
    pub fn compile_policy_decision_proposal(
        &self,
        mission: &MissionScope,
        evidence: &SupabaseEvidencePack,
        requested_decision: PolicyDecision,
        table: TableScope,
        role: impl Into<String>,
        privilege: DatabasePrivilege,
        reason_code: impl Into<String>,
    ) -> Result<PolicyDecisionProposal, SupabaseIdentityError> {
        self.ensure_active()?;
        self.ensure_fences()?;
        if !self.scope().matches_mission(mission) {
            return Err(SupabaseIdentityError::MissionScopeMismatch);
        }
        evidence.verify_integrity()?;
        if evidence.scope_digest != self.scope().digest()
            || evidence.registration_digest != self.registration.registration_digest
            || evidence.provider_digest != self.provider.provider_digest()
        {
            return Err(SupabaseIdentityError::ProposalEvidenceMismatch);
        }
        table.validate()?;
        if !self.scope().tables.contains(&table) {
            return Err(SupabaseIdentityError::MissionScopeMismatch);
        }
        let role = role.into();
        if !self.scope().allowed_roles.contains(&role) {
            return Err(SupabaseIdentityError::RoleMismatch);
        }
        if !privilege.is_read() {
            return Err(SupabaseIdentityError::PermissionDrift);
        }
        let reason_code = reason_code.into();
        if reason_code.is_empty() {
            return Err(SupabaseIdentityError::InvalidModel(
                "reason_code must not be empty".into(),
            ));
        }
        let effective_decision =
            if requested_decision == PolicyDecision::AllowRead && !evidence.is_positive() {
                PolicyDecision::ReviewRequired
            } else {
                requested_decision
            };
        let proposal_id = digest_parts(&[
            &mission.mission_id,
            &mission.mission_revision.to_string(),
            &table.key(),
            &role,
            &evidence.evidence_digest,
        ]);
        let mut proposal = PolicyDecisionProposal {
            proposal_id,
            requested_decision,
            effective_decision,
            reason_code,
            table,
            role,
            privilege,
            mission: mission.clone(),
            scope_digest: self.scope().digest(),
            registration_digest: self.registration.registration_digest.clone(),
            provider_digest: self.provider.provider_digest().to_owned(),
            permission_digest: self.permissions.digest(),
            evidence_digest: evidence.evidence_digest.clone(),
            proposal_digest: String::new(),
            provider_authority: "external_provider_policy_evidence_only".into(),
            native_status: self.provider.native_status(),
            connected: false,
            native: false,
            durable_receipt: false,
            adopted: false,
        };
        proposal.proposal_digest = proposal.expected_digest()?;
        Ok(proposal)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "compatibility alias preserves the explicit proposal seam"
    )]
    pub fn propose_policy_decision(
        &self,
        mission: &MissionScope,
        evidence: &SupabaseEvidencePack,
        requested_decision: PolicyDecision,
        table: TableScope,
        role: impl Into<String>,
        privilege: DatabasePrivilege,
        reason_code: impl Into<String>,
    ) -> Result<PolicyDecisionProposal, SupabaseIdentityError> {
        self.compile_policy_decision_proposal(
            mission,
            evidence,
            requested_decision,
            table,
            role,
            privilege,
            reason_code,
        )
    }

    fn ensure_active(&self) -> Result<(), SupabaseIdentityError> {
        match self.registration.state {
            RegistrationState::Active => Ok(()),
            RegistrationState::Reversed => Err(SupabaseIdentityError::RegistrationInactive),
            RegistrationState::Revoked => Err(SupabaseIdentityError::RegistrationRevoked),
        }
    }

    fn ensure_fences(&self) -> Result<(), SupabaseIdentityError> {
        self.registration.validate(&self.permissions)?;
        self.provider
            .manifest()
            .validate_for(self.scope(), &self.permissions)?;
        if self.secret_reference.is_service_role() {
            return Err(SupabaseIdentityError::ServiceRoleAuthorityRejected);
        }
        self.secret_reference.validate()?;
        if self.secret_reference.project_ref() != self.scope().project_ref
            || self.secret_reference.scope_digest() != self.scope().digest()
        {
            return Err(SupabaseIdentityError::RegistrationDrift);
        }
        Ok(())
    }

    fn validate_management_observation(
        &self,
        observation: &crate::ManagementMetadataObservation,
    ) -> Result<(), SupabaseIdentityError> {
        if observation.response_bytes > MAX_RESPONSE_BYTES {
            return Err(SupabaseIdentityError::BoundsExceeded);
        }
        observation.verify_integrity()?;
        if observation.scope_digest != self.scope().digest()
            || observation.project_ref != self.scope().project_ref
            || observation.region != self.scope().region
            || observation.provider_revision != crate::PROVIDER_API_REVISION
        {
            return Err(SupabaseIdentityError::Provider(
                SupabaseProviderError::ScopeMismatch,
            ));
        }
        Ok(())
    }

    fn identity_evidence(
        &self,
        observation: &AuthIdentityObservation,
        identity: SupabaseIdentityRecord,
        claims: crate::JwtClaimsEvidence,
    ) -> SupabaseIdentityEvidence {
        let evidence_digest = digest_parts(&[
            &observation.response_digest,
            &self.registration.registration_digest,
            self.provider.provider_digest(),
        ]);
        SupabaseIdentityEvidence {
            scope_digest: self.scope().digest(),
            registration_digest: self.registration.registration_digest.clone(),
            provider_digest: self.provider.provider_digest().to_owned(),
            identity,
            jwt_claims: claims,
            provider_revision: observation.provider_revision.clone(),
            observed_at: observation.observed_at,
            evidence_digest,
            provenance: self.provider.provenance(),
            native_status: self.provider.native_status(),
            connected: false,
            native: false,
        }
    }

    fn policy_evidence(
        &self,
        observation: &crate::PostgrestMetadataObservation,
    ) -> SupabasePolicyEvidence {
        let evidence_digest = digest_parts(&[
            &observation.response_digest,
            &self.registration.registration_digest,
            self.provider.provider_digest(),
        ]);
        SupabasePolicyEvidence {
            scope_digest: self.scope().digest(),
            registration_digest: self.registration.registration_digest.clone(),
            provider_digest: self.provider.provider_digest().to_owned(),
            grants: observation.grants.clone(),
            policies: observation.policies.clone(),
            grant_revision: observation.grant_revision.clone(),
            policy_revision: observation.policy_revision.clone(),
            provider_revision: observation.provider_revision.clone(),
            observed_at: observation.observed_at,
            evidence_digest,
            provenance: self.provider.provenance(),
            native_status: self.provider.native_status(),
            connected: false,
            native: false,
        }
    }

    fn validate_grant(&self, grant: &DatabaseGrant) -> Result<(), SupabaseIdentityError> {
        grant.validate()?;
        if !self.scope().allowed_roles.contains(&grant.role)
            || !self.scope().tables.contains(&grant.table)
        {
            return Err(SupabaseIdentityError::TenantMismatch);
        }
        if let Some(column) = &grant.column {
            let columns = self
                .scope()
                .allowlisted_columns
                .get(&grant.table)
                .ok_or(SupabaseIdentityError::TenantMismatch)?;
            if !columns.contains(column) {
                return Err(SupabaseIdentityError::TenantMismatch);
            }
        }
        if grant
            .tenant_id
            .as_ref()
            .is_some_and(|tenant| tenant != &self.scope().tenant_id)
        {
            return Err(SupabaseIdentityError::TenantMismatch);
        }
        Ok(())
    }

    fn validate_policy(&self, policy: &RlsPolicyEvidence) -> Result<(), SupabaseIdentityError> {
        policy.validate()?;
        if !self.scope().tables.contains(&policy.table)
            || !self.scope().allowed_roles.contains(&policy.role)
        {
            return Err(SupabaseIdentityError::TenantMismatch);
        }
        if policy
            .tenant_id
            .as_ref()
            .is_some_and(|tenant| tenant != &self.scope().tenant_id)
        {
            return Err(SupabaseIdentityError::TenantMismatch);
        }
        Ok(())
    }

    fn grants_and_policies_match(
        &self,
        grants: &[DatabaseGrant],
        policies: &[RlsPolicyEvidence],
    ) -> bool {
        self.scope().tables.iter().all(|table| {
            self.scope().allowed_roles.iter().all(|role| {
                let grant_exists = grants.iter().any(|grant| {
                    grant.table == *table
                        && grant.role == *role
                        && grant.privilege == DatabasePrivilege::Select
                });
                let policy_exists = policies.iter().any(|policy| {
                    policy.table == *table
                        && policy.role == *role
                        && policy.enabled
                        && matches!(
                            policy.command,
                            crate::PolicyCommand::Select | crate::PolicyCommand::All
                        )
                });
                grant_exists && policy_exists
            })
        })
    }

    fn identity_provider_error(
        &self,
        error: SupabaseProviderError,
        observed_at: DateTime<Utc>,
    ) -> IdentityProjection {
        match error {
            SupabaseProviderError::Unauthorized => {
                self.identity_denied(ProjectionReason::Unauthorized, observed_at)
            }
            SupabaseProviderError::Forbidden | SupabaseProviderError::ServiceRoleRejected => self
                .identity_denied(
                    if matches!(error, SupabaseProviderError::ServiceRoleRejected) {
                        ProjectionReason::ServiceRoleAuthority
                    } else {
                        ProjectionReason::Forbidden
                    },
                    observed_at,
                ),
            SupabaseProviderError::NotFound => IdentityProjection::Absent {
                reason: ProjectionReason::NotFound,
                scope_digest: self.scope().digest(),
                observed_at,
            },
            SupabaseProviderError::Conflict | SupabaseProviderError::ScopeMismatch => {
                self.identity_scope_mismatch(observed_at)
            }
            SupabaseProviderError::RateLimited { .. } => {
                self.identity_unknown(ProjectionReason::RateLimited, observed_at)
            }
            SupabaseProviderError::ServerFailure { status } => {
                self.identity_unknown(ProjectionReason::ServerFailure { status }, observed_at)
            }
            SupabaseProviderError::Timeout => {
                self.identity_unknown(ProjectionReason::Timeout, observed_at)
            }
            SupabaseProviderError::BlockedEnv => {
                self.identity_unknown(ProjectionReason::BlockedEnv, observed_at)
            }
            SupabaseProviderError::ProviderUnknown { code } => {
                self.identity_unknown(ProjectionReason::ProviderUnknown { code }, observed_at)
            }
            SupabaseProviderError::InvalidResponse { .. }
            | SupabaseProviderError::TamperedResponse => self.identity_tampered(observed_at),
        }
    }

    fn policy_provider_error(
        &self,
        error: SupabaseProviderError,
        observed_at: DateTime<Utc>,
    ) -> PolicyProjection {
        match error {
            SupabaseProviderError::Unauthorized => {
                self.policy_denied(ProjectionReason::Unauthorized, observed_at)
            }
            SupabaseProviderError::Forbidden | SupabaseProviderError::ServiceRoleRejected => self
                .policy_denied(
                    if matches!(error, SupabaseProviderError::ServiceRoleRejected) {
                        ProjectionReason::ServiceRoleAuthority
                    } else {
                        ProjectionReason::Forbidden
                    },
                    observed_at,
                ),
            SupabaseProviderError::NotFound => PolicyProjection::Absent {
                reason: ProjectionReason::NotFound,
                scope_digest: self.scope().digest(),
                observed_at,
            },
            SupabaseProviderError::Conflict | SupabaseProviderError::ScopeMismatch => {
                self.policy_scope_mismatch(observed_at)
            }
            SupabaseProviderError::RateLimited { .. } => {
                self.policy_unknown(ProjectionReason::RateLimited, observed_at)
            }
            SupabaseProviderError::ServerFailure { status } => {
                self.policy_unknown(ProjectionReason::ServerFailure { status }, observed_at)
            }
            SupabaseProviderError::Timeout => {
                self.policy_unknown(ProjectionReason::Timeout, observed_at)
            }
            SupabaseProviderError::BlockedEnv => {
                self.policy_unknown(ProjectionReason::BlockedEnv, observed_at)
            }
            SupabaseProviderError::ProviderUnknown { code } => {
                self.policy_unknown(ProjectionReason::ProviderUnknown { code }, observed_at)
            }
            SupabaseProviderError::InvalidResponse { .. }
            | SupabaseProviderError::TamperedResponse => self.policy_tampered(observed_at),
        }
    }

    fn identity_error_projection(
        &self,
        error: &SupabaseIdentityError,
        observed_at: DateTime<Utc>,
    ) -> IdentityProjection {
        match error {
            SupabaseIdentityError::JwtExpired => IdentityProjection::Expired {
                reason: ProjectionReason::JwtExpired,
                scope_digest: self.scope().digest(),
                observed_at,
            },
            SupabaseIdentityError::JwtAudienceMismatch => IdentityProjection::ScopeMismatch {
                reason: ProjectionReason::WrongAudience,
                scope_digest: self.scope().digest(),
                observed_at,
            },
            SupabaseIdentityError::JwtIssuerMismatch => IdentityProjection::ScopeMismatch {
                reason: ProjectionReason::WrongIssuer,
                scope_digest: self.scope().digest(),
                observed_at,
            },
            SupabaseIdentityError::JwtNotVerified | SupabaseIdentityError::TamperedEvidence => {
                self.identity_tampered(observed_at)
            }
            SupabaseIdentityError::RoleMismatch => IdentityProjection::Denied {
                reason: ProjectionReason::RoleNotAllowed,
                scope_digest: self.scope().digest(),
                observed_at,
            },
            SupabaseIdentityError::TenantMismatch => IdentityProjection::ScopeMismatch {
                reason: ProjectionReason::TenantCrossing,
                scope_digest: self.scope().digest(),
                observed_at,
            },
            SupabaseIdentityError::ProjectMismatch => self.identity_scope_mismatch(observed_at),
            _ => self.identity_unknown(
                ProjectionReason::ProviderUnknown {
                    code: "invalid_identity_evidence".into(),
                },
                observed_at,
            ),
        }
    }

    fn policy_error_projection(
        &self,
        error: &SupabaseIdentityError,
        observed_at: DateTime<Utc>,
    ) -> PolicyProjection {
        match error {
            SupabaseIdentityError::TamperedEvidence => self.policy_tampered(observed_at),
            _ => self.policy_unknown(
                ProjectionReason::ProviderUnknown {
                    code: "invalid_policy_evidence".into(),
                },
                observed_at,
            ),
        }
    }

    fn policy_scope_or_error(
        &self,
        error: &SupabaseIdentityError,
        observation: &crate::PostgrestMetadataObservation,
        observed_at: DateTime<Utc>,
    ) -> PolicyProjection {
        if matches!(
            error,
            SupabaseIdentityError::TenantMismatch
                | SupabaseIdentityError::ProjectMismatch
                | SupabaseIdentityError::MissionScopeMismatch
        ) {
            self.policy_scope_mismatch(observed_at)
        } else {
            let evidence = Some(self.policy_evidence(observation));
            PolicyProjection::Mismatch {
                reason: ProjectionReason::GrantPolicyMismatch,
                evidence,
                scope_digest: self.scope().digest(),
                observed_at,
            }
        }
    }

    fn identity_denied(
        &self,
        reason: ProjectionReason,
        observed_at: DateTime<Utc>,
    ) -> IdentityProjection {
        IdentityProjection::Denied {
            reason,
            scope_digest: self.scope().digest(),
            observed_at,
        }
    }

    fn identity_unknown(
        &self,
        reason: ProjectionReason,
        observed_at: DateTime<Utc>,
    ) -> IdentityProjection {
        IdentityProjection::ProviderUnknown {
            reason,
            scope_digest: self.scope().digest(),
            observed_at,
        }
    }

    fn identity_scope_mismatch(&self, observed_at: DateTime<Utc>) -> IdentityProjection {
        IdentityProjection::ScopeMismatch {
            reason: ProjectionReason::ProjectDrift,
            scope_digest: self.scope().digest(),
            observed_at,
        }
    }

    fn identity_tampered(&self, observed_at: DateTime<Utc>) -> IdentityProjection {
        IdentityProjection::Tampered {
            reason: ProjectionReason::IntegrityFailure,
            scope_digest: self.scope().digest(),
            observed_at,
        }
    }

    fn policy_denied(
        &self,
        reason: ProjectionReason,
        observed_at: DateTime<Utc>,
    ) -> PolicyProjection {
        PolicyProjection::Denied {
            reason,
            scope_digest: self.scope().digest(),
            observed_at,
        }
    }

    fn policy_unknown(
        &self,
        reason: ProjectionReason,
        observed_at: DateTime<Utc>,
    ) -> PolicyProjection {
        PolicyProjection::ProviderUnknown {
            reason,
            scope_digest: self.scope().digest(),
            observed_at,
        }
    }

    fn policy_scope_mismatch(&self, observed_at: DateTime<Utc>) -> PolicyProjection {
        PolicyProjection::ScopeMismatch {
            reason: ProjectionReason::ProjectDrift,
            scope_digest: self.scope().digest(),
            observed_at,
        }
    }

    fn policy_tampered(&self, observed_at: DateTime<Utc>) -> PolicyProjection {
        PolicyProjection::Tampered {
            reason: ProjectionReason::IntegrityFailure,
            scope_digest: self.scope().digest(),
            observed_at,
        }
    }
}

impl SupabaseIdentityProvider {
    fn provenance_name(&self) -> &'static str {
        match self.provenance() {
            EvidenceProvenance::Fixture => "fixture",
            EvidenceProvenance::Recording => "recording",
            EvidenceProvenance::Loopback => "loopback",
            EvidenceProvenance::BlockedEnv => "blocked_env",
            EvidenceProvenance::ProviderUnknown => "provider_unknown",
        }
    }
}

/// Name required by the external plugin seam in the issue description.
pub type SupabaseIdentityPolicyService = SupabaseIdentityService;

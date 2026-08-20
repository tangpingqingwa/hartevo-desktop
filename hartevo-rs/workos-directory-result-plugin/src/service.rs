use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::Serialize;

use crate::canonical::{canonical_digest, digest_parts};
use crate::model::{
    ConnectionProjection, ConnectionState, Consent, Digest, DirectoryGroupRecord,
    DirectoryProjection, DirectoryState, DirectoryUserRecord, EvidenceStatus, GroupProjection,
    GroupState, MembershipFilter, MembershipProjection, MembershipSource, MembershipState, Mission,
    ModelError, PageCursor, PageDirection, PageOperation, Project, ProviderProvenance,
    ProviderRevision, ReadBounds, SecretReference, UserProjection, UserState, WorkOsDirectoryScope,
};
use crate::provider::{WorkOsDirectoryPage, WorkOsDirectoryPageRequest, WorkOsDirectoryProvider};
use crate::{
    Result, WORKOS_DIRECTORY_API_BASE, WORKOS_DIRECTORY_API_REVISION, WORKOS_DIRECTORY_CONSUMER_ID,
    WORKOS_DIRECTORY_PROVIDER_ID, WORKOS_DIRECTORY_RESULT_CONTRACT_VERSION,
    WORKOS_DIRECTORY_RESULT_PLUGIN_ID, WORKOS_DIRECTORY_RESULT_PLUGIN_VERSION_TEXT,
    WORKOS_DIRECTORY_RESULT_SCHEMA_VERSION, WORKOS_DIRECTORY_SERVICE_ID,
    WorkOsDirectoryResultError, contract_digest,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Reversed,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationTransitionEvidence {
    pub previous_status: RegistrationStatus,
    pub new_status: RegistrationStatus,
    pub registration_digest: Digest,
    pub transition_digest: Digest,
}

impl RegistrationTransitionEvidence {
    fn new(
        previous_status: RegistrationStatus,
        new_status: RegistrationStatus,
        registration_digest: Digest,
    ) -> Self {
        let transition_digest = digest_parts(
            "workos-directory-registration-transition/v1",
            &[
                format!("{previous_status:?}"),
                format!("{new_status:?}"),
                registration_digest.as_str().to_owned(),
            ],
        );
        Self {
            previous_status,
            new_status,
            registration_digest,
            transition_digest,
        }
    }
}

/// All registration inputs are digest-bound. The API-key handle is opaque
/// and is never serialised as part of this registration.
#[derive(Clone, Eq, PartialEq)]
pub struct WorkOsDirectoryRegistration {
    id: String,
    plugin_id: String,
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_api_revision: String,
    provider_revision: ProviderRevision,
    provider_digest: Digest,
    api_digest: Digest,
    permission_digest: Digest,
    scope_digest: Digest,
    secret_reference: SecretReference,
    registration_revision: crate::model::Revision,
    scope: WorkOsDirectoryScope,
    status: RegistrationStatus,
    registration_digest: Digest,
}

impl fmt::Debug for WorkOsDirectoryRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkOsDirectoryRegistration")
            .field("id", &self.id)
            .field("plugin_id", &self.plugin_id)
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_id", &self.provider_id)
            .field("provider_api_revision", &self.provider_api_revision)
            .field("provider_revision", &self.provider_revision)
            .field("provider_digest", &self.provider_digest)
            .field("api_digest", &self.api_digest)
            .field("permission_digest", &self.permission_digest)
            .field("scope_digest", &self.scope_digest)
            .field("secret_reference", &self.secret_reference)
            .field("registration_revision", &self.registration_revision)
            .field("scope", &self.scope)
            .field("status", &self.status)
            .field("registration_digest", &self.registration_digest)
            .finish()
    }
}

impl WorkOsDirectoryRegistration {
    pub fn new(
        id: impl Into<String>,
        scope: WorkOsDirectoryScope,
        secret_reference: SecretReference,
        provider: &WorkOsDirectoryProvider,
    ) -> Result<Self> {
        Self::new_with_revision(
            id,
            scope,
            secret_reference,
            provider,
            crate::model::Revision::new(1)?,
        )
    }

    pub fn new_with_revision(
        id: impl Into<String>,
        scope: WorkOsDirectoryScope,
        secret_reference: SecretReference,
        provider: &WorkOsDirectoryProvider,
        registration_revision: crate::model::Revision,
    ) -> Result<Self> {
        let mut registration = Self {
            id: id.into(),
            plugin_id: WORKOS_DIRECTORY_RESULT_PLUGIN_ID.to_owned(),
            plugin_version: WORKOS_DIRECTORY_RESULT_PLUGIN_VERSION_TEXT.to_owned(),
            contract_version: WORKOS_DIRECTORY_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: WORKOS_DIRECTORY_PROVIDER_ID.to_owned(),
            provider_api_revision: WORKOS_DIRECTORY_API_REVISION.to_owned(),
            provider_revision: provider.provider_revision().clone(),
            provider_digest: provider.provider_digest().clone(),
            api_digest: Digest::from_text(WORKOS_DIRECTORY_API_BASE),
            permission_digest: scope.permission_digest.clone(),
            scope_digest: scope.scope_digest().clone(),
            secret_reference,
            registration_revision,
            scope,
            status: RegistrationStatus::Active,
            registration_digest: Digest::from_text("unsealed-workos-registration"),
        };
        registration.registration_digest = registration.recompute_digest();
        registration.validate(provider)?;
        Ok(registration)
    }

    pub fn validate(&self, provider: &WorkOsDirectoryProvider) -> Result<()> {
        if self.id.is_empty()
            || self.plugin_id != WORKOS_DIRECTORY_RESULT_PLUGIN_ID
            || self.plugin_version != WORKOS_DIRECTORY_RESULT_PLUGIN_VERSION_TEXT
            || self.contract_version != WORKOS_DIRECTORY_RESULT_CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.provider_id != WORKOS_DIRECTORY_PROVIDER_ID
            || self.provider_api_revision != WORKOS_DIRECTORY_API_REVISION
            || self.provider_revision != *provider.provider_revision()
            || self.provider_digest != *provider.provider_digest()
            || self.api_digest != Digest::from_text(WORKOS_DIRECTORY_API_BASE)
            || self.permission_digest != self.scope.permission_digest
            || self.scope_digest != *self.scope.scope_digest()
            || self.secret_reference.scope_digest() != self.scope.scope_digest()
            || !self.secret_reference.reference_digest().is_valid()
            || self.registration_digest != self.recompute_digest()
        {
            return Err(WorkOsDirectoryResultError::RegistrationDrift);
        }
        self.scope.validate()?;
        if self.secret_reference.is_revoked() {
            return Err(WorkOsDirectoryResultError::SecretReferenceRevoked);
        }
        Ok(())
    }

    fn recompute_digest(&self) -> Digest {
        digest_parts(
            "workos-directory-registration/v1",
            &[
                self.id.clone(),
                self.plugin_id.clone(),
                self.plugin_version.clone(),
                self.contract_version.clone(),
                self.contract_digest.as_str().to_owned(),
                self.provider_id.clone(),
                self.provider_api_revision.clone(),
                self.provider_revision.as_str().to_owned(),
                self.provider_digest.as_str().to_owned(),
                self.api_digest.as_str().to_owned(),
                self.permission_digest.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.secret_reference.reference_digest().as_str().to_owned(),
                self.registration_revision.value().to_string(),
                self.scope.project.digest().as_str().to_owned(),
                self.scope.mission.digest().as_str().to_owned(),
                self.scope.consent.digest().as_str().to_owned(),
                format!("{:?}", self.status),
            ],
        )
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn scope(&self) -> &WorkOsDirectoryScope {
        &self.scope
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn provider_revision(&self) -> &ProviderRevision {
        &self.provider_revision
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn registration_revision(&self) -> crate::model::Revision {
        self.registration_revision
    }

    pub const fn status(&self) -> RegistrationStatus {
        self.status
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn reverse(
        &mut self,
        provider: &WorkOsDirectoryProvider,
    ) -> Result<RegistrationTransitionEvidence> {
        self.ensure_transitionable(provider)?;
        if self.status != RegistrationStatus::Active {
            return Err(WorkOsDirectoryResultError::InvalidRegistrationTransition);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Reversed;
        self.registration_digest = self.recompute_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    pub fn restore(
        &mut self,
        provider: &WorkOsDirectoryProvider,
    ) -> Result<RegistrationTransitionEvidence> {
        if self.status != RegistrationStatus::Reversed {
            return Err(WorkOsDirectoryResultError::InvalidRegistrationTransition);
        }
        self.validate_without_secret(provider)?;
        let previous_status = self.status;
        self.status = RegistrationStatus::Active;
        self.registration_digest = self.recompute_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    pub fn revoke(
        &mut self,
        provider: &WorkOsDirectoryProvider,
    ) -> Result<RegistrationTransitionEvidence> {
        if self.status == RegistrationStatus::Revoked {
            return Err(WorkOsDirectoryResultError::InvalidRegistrationTransition);
        }
        self.validate_without_secret(provider)?;
        let previous_status = self.status;
        self.status = RegistrationStatus::Revoked;
        self.registration_digest = self.recompute_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    fn validate_without_secret(&self, provider: &WorkOsDirectoryProvider) -> Result<()> {
        if self.id.is_empty()
            || self.provider_digest != *provider.provider_digest()
            || self.provider_revision != *provider.provider_revision()
            || self.scope_digest != *self.scope.scope_digest()
            || self.registration_digest != self.recompute_digest()
        {
            Err(WorkOsDirectoryResultError::RegistrationDrift)
        } else {
            Ok(())
        }
    }

    fn ensure_transitionable(&self, provider: &WorkOsDirectoryProvider) -> Result<()> {
        if self.status == RegistrationStatus::Revoked {
            return Err(WorkOsDirectoryResultError::RegistrationRevoked);
        }
        self.validate(provider)
    }

    pub(crate) fn revoke_secret_reference(&mut self) {
        self.secret_reference.revoke();
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkOsDirectoryCapabilities {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub api_base: String,
    pub allowed_operations: Vec<String>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub external_writes: bool,
    pub identity_authority: bool,
    pub consent_authority: bool,
    pub effect_authority: bool,
}

impl Default for WorkOsDirectoryCapabilities {
    fn default() -> Self {
        Self {
            service_id: WORKOS_DIRECTORY_SERVICE_ID.to_owned(),
            provider_id: WORKOS_DIRECTORY_PROVIDER_ID.to_owned(),
            consumer_id: WORKOS_DIRECTORY_CONSUMER_ID.to_owned(),
            api_base: WORKOS_DIRECTORY_API_BASE.to_owned(),
            allowed_operations: vec![
                "read_connection".to_owned(),
                "read_directory".to_owned(),
                "read_filtered_memberships".to_owned(),
                "compile_evidence_proposal".to_owned(),
                "verify_proposal".to_owned(),
                "record_proposal".to_owned(),
                "read_back_record".to_owned(),
            ],
            read_only: true,
            proposal_only: true,
            connected: false,
            native: false,
            external_writes: false,
            identity_authority: false,
            consent_authority: false,
            effect_authority: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FilteredMembershipEvidence {
    pub filter: MembershipFilter,
    pub users: Vec<UserProjection>,
    pub groups: Vec<GroupProjection>,
    pub memberships: Vec<MembershipProjection>,
    pub pages_observed: u16,
    pub response_bytes: usize,
    pub complete: bool,
    pub request_digest: Digest,
    pub page_digests: Vec<Digest>,
    pub before_cursor_digests: Vec<Digest>,
    pub after_cursor_digests: Vec<Digest>,
    pub pagination_digest: Digest,
}

impl FilteredMembershipEvidence {
    fn recompute_pagination_digest(&self) -> Digest {
        digest_parts(
            "workos-directory-pagination-evidence/v1",
            &[
                self.request_digest.as_str().to_owned(),
                self.page_digests
                    .iter()
                    .map(Digest::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
                self.before_cursor_digests
                    .iter()
                    .map(Digest::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
                self.after_cursor_digests
                    .iter()
                    .map(Digest::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
                self.pages_observed.to_string(),
                self.response_bytes.to_string(),
                self.complete.to_string(),
            ],
        )
    }

    fn verify_integrity(&self) -> Result<()> {
        if self.pagination_digest != self.recompute_pagination_digest()
            || !self.page_digests.iter().all(Digest::is_valid)
            || !self
                .before_cursor_digests
                .iter()
                .chain(&self.after_cursor_digests)
                .all(Digest::is_valid)
        {
            Err(WorkOsDirectoryResultError::TamperedEvidence)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkOsDirectoryEvidence {
    pub schema_version: String,
    pub contract_version: String,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub organization_id: crate::model::OrganizationId,
    pub directory_id: crate::model::DirectoryId,
    pub connection_id: crate::model::ConnectionId,
    pub project: Project,
    pub mission: Mission,
    pub consent: Consent,
    pub directory: DirectoryProjection,
    pub connection: ConnectionProjection,
    pub membership: FilteredMembershipEvidence,
    pub provider_revision: ProviderRevision,
    pub status: EvidenceStatus,
    pub provenance: ProviderProvenance,
    pub request_digest: Digest,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub raw_idp_attributes_retained: bool,
    pub raw_email_retained: bool,
    pub raw_name_retained: bool,
    pub raw_custom_attributes_retained: bool,
    pub identity_authority: bool,
    pub consent_authority: bool,
    pub effect_authority: bool,
}

impl WorkOsDirectoryEvidence {
    fn recompute_digest(&self) -> Digest {
        #[derive(Serialize)]
        struct EvidenceDigest<'a> {
            schema_version: &'a str,
            contract_version: &'a str,
            scope_digest: &'a Digest,
            registration_digest: &'a Digest,
            provider_digest: &'a Digest,
            permission_digest: &'a Digest,
            organization_id: &'a crate::model::OrganizationId,
            directory_id: &'a crate::model::DirectoryId,
            connection_id: &'a crate::model::ConnectionId,
            project: &'a Project,
            mission: &'a Mission,
            consent: &'a Consent,
            directory: &'a DirectoryProjection,
            connection: &'a ConnectionProjection,
            membership: &'a FilteredMembershipEvidence,
            provider_revision: &'a ProviderRevision,
            status: &'a EvidenceStatus,
            provenance: &'a ProviderProvenance,
            request_digest: &'a Digest,
            connected: bool,
            native: bool,
            raw_idp_attributes_retained: bool,
            raw_email_retained: bool,
            raw_name_retained: bool,
            raw_custom_attributes_retained: bool,
            identity_authority: bool,
            consent_authority: bool,
            effect_authority: bool,
        }
        canonical_digest(
            "workos-directory-evidence/v1",
            &EvidenceDigest {
                schema_version: &self.schema_version,
                contract_version: &self.contract_version,
                scope_digest: &self.scope_digest,
                registration_digest: &self.registration_digest,
                provider_digest: &self.provider_digest,
                permission_digest: &self.permission_digest,
                organization_id: &self.organization_id,
                directory_id: &self.directory_id,
                connection_id: &self.connection_id,
                project: &self.project,
                mission: &self.mission,
                consent: &self.consent,
                directory: &self.directory,
                connection: &self.connection,
                membership: &self.membership,
                provider_revision: &self.provider_revision,
                status: &self.status,
                provenance: &self.provenance,
                request_digest: &self.request_digest,
                connected: self.connected,
                native: self.native,
                raw_idp_attributes_retained: self.raw_idp_attributes_retained,
                raw_email_retained: self.raw_email_retained,
                raw_name_retained: self.raw_name_retained,
                raw_custom_attributes_retained: self.raw_custom_attributes_retained,
                identity_authority: self.identity_authority,
                consent_authority: self.consent_authority,
                effect_authority: self.effect_authority,
            },
        )
    }

    pub fn verify_integrity(&self) -> Result<()> {
        self.membership.verify_integrity()?;
        if self.evidence_digest != self.recompute_digest()
            || self.connected
            || self.native
            || self.raw_idp_attributes_retained
            || self.raw_email_retained
            || self.raw_name_retained
            || self.raw_custom_attributes_retained
            || self.identity_authority
            || self.consent_authority
            || self.effect_authority
        {
            return Err(WorkOsDirectoryResultError::TamperedEvidence);
        }
        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        matches!(self.status, EvidenceStatus::Complete)
            && self.membership.complete
            && !self.connected
            && !self.native
    }

    pub fn is_adoptable(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkOsDirectoryResultProposal {
    pub schema_version: String,
    pub contract_version: String,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub project: Project,
    pub mission: Mission,
    pub consent: Consent,
    pub provider_revision: ProviderRevision,
    pub evidence_digest: Digest,
    pub status: EvidenceStatus,
    pub evidence: WorkOsDirectoryEvidence,
    pub proposal_digest: Digest,
    pub adopted_by_kernel: bool,
    pub mutates_identity: bool,
    pub mutates_directory: bool,
    pub creates_access_grant: bool,
    pub connected: bool,
    pub native: bool,
}

impl WorkOsDirectoryResultProposal {
    fn recompute_digest(&self) -> Digest {
        digest_parts(
            "workos-directory-proposal/v1",
            &[
                self.schema_version.clone(),
                self.contract_version.clone(),
                self.scope_digest.as_str().to_owned(),
                self.registration_digest.as_str().to_owned(),
                self.provider_digest.as_str().to_owned(),
                self.permission_digest.as_str().to_owned(),
                self.project.digest().as_str().to_owned(),
                self.mission.digest().as_str().to_owned(),
                self.consent.digest().as_str().to_owned(),
                self.provider_revision.as_str().to_owned(),
                self.evidence_digest.as_str().to_owned(),
                format!("{:?}", self.status),
                self.adopted_by_kernel.to_string(),
                self.mutates_identity.to_string(),
                self.mutates_directory.to_string(),
                self.creates_access_grant.to_string(),
                self.connected.to_string(),
                self.native.to_string(),
            ],
        )
    }

    pub fn verify_integrity(&self) -> Result<()> {
        self.evidence.verify_integrity()?;
        if self.proposal_digest != self.recompute_digest()
            || self.evidence.evidence_digest != self.evidence_digest
            || self.adopted_by_kernel
            || self.mutates_identity
            || self.mutates_directory
            || self.creates_access_grant
            || self.connected
            || self.native
        {
            Err(WorkOsDirectoryResultError::TamperedEvidence)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkOsDirectoryRecordedProposal {
    pub record_id: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub project: Project,
    pub mission: Mission,
    pub consent: Consent,
    pub provider_revision: ProviderRevision,
    pub recorded_registration_revision: crate::model::Revision,
    pub record_digest: Digest,
}

impl WorkOsDirectoryRecordedProposal {
    fn recompute_digest(&self) -> Digest {
        digest_parts(
            "workos-directory-record/v1",
            &[
                self.record_id.as_str().to_owned(),
                self.proposal_digest.as_str().to_owned(),
                self.evidence_digest.as_str().to_owned(),
                self.registration_digest.as_str().to_owned(),
                self.provider_digest.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.permission_digest.as_str().to_owned(),
                self.project.digest().as_str().to_owned(),
                self.mission.digest().as_str().to_owned(),
                self.consent.digest().as_str().to_owned(),
                self.provider_revision.as_str().to_owned(),
                self.recorded_registration_revision.value().to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadBackVerification {
    pub verified: bool,
    pub record_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub independent_provider_reread: bool,
    pub connected: bool,
    pub native: bool,
}

pub struct WorkOsDirectoryResultService {
    provider: WorkOsDirectoryProvider,
    registration: WorkOsDirectoryRegistration,
    recorded: BTreeMap<Digest, WorkOsDirectoryRecordedProposal>,
}

impl fmt::Debug for WorkOsDirectoryResultService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkOsDirectoryResultService")
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .field("recorded_count", &self.recorded.len())
            .finish()
    }
}

impl WorkOsDirectoryResultService {
    pub fn new(
        provider: WorkOsDirectoryProvider,
        registration: WorkOsDirectoryRegistration,
    ) -> Result<Self> {
        registration.validate(&provider)?;
        Ok(Self {
            provider,
            registration,
            recorded: BTreeMap::new(),
        })
    }

    pub fn register(
        provider: WorkOsDirectoryProvider,
        registration_id: impl Into<String>,
        scope: WorkOsDirectoryScope,
        secret_reference: SecretReference,
    ) -> Result<Self> {
        let registration =
            WorkOsDirectoryRegistration::new(registration_id, scope, secret_reference, &provider)?;
        Self::new(provider, registration)
    }

    pub fn register_with_revision(
        provider: WorkOsDirectoryProvider,
        registration_id: impl Into<String>,
        scope: WorkOsDirectoryScope,
        secret_reference: SecretReference,
        registration_revision: crate::model::Revision,
    ) -> Result<Self> {
        let registration = WorkOsDirectoryRegistration::new_with_revision(
            registration_id,
            scope,
            secret_reference,
            &provider,
            registration_revision,
        )?;
        Self::new(provider, registration)
    }

    pub fn provider(&self) -> &WorkOsDirectoryProvider {
        &self.provider
    }

    pub fn registration(&self) -> &WorkOsDirectoryRegistration {
        &self.registration
    }

    pub fn scope(&self) -> &WorkOsDirectoryScope {
        self.registration.scope()
    }

    pub fn secret_reference(&self) -> &SecretReference {
        self.registration.secret_reference()
    }

    pub fn describe_capabilities(&self) -> WorkOsDirectoryCapabilities {
        WorkOsDirectoryCapabilities::default()
    }

    pub const fn is_connected(&self) -> bool {
        false
    }

    pub const fn is_native(&self) -> bool {
        false
    }

    pub fn reverse_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.reverse(&self.provider)
    }

    pub fn restore_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.restore(&self.provider)
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.revoke(&self.provider)
    }

    pub fn revoke_secret_reference(&mut self) {
        self.registration.revoke_secret_reference();
    }

    pub fn read_connection(&self) -> Result<ConnectionProjection> {
        self.ensure_active()?;
        let record = self.provider.read_connection(self.scope())?;
        self.validate_connection_record(&record)?;
        Ok(ConnectionProjection::from(&record))
    }

    pub fn read_directory(&self) -> Result<DirectoryProjection> {
        self.ensure_active()?;
        let record = self.provider.read_directory(self.scope())?;
        self.validate_directory_record(&record)?;
        Ok(DirectoryProjection::from(&record))
    }

    pub fn read_filtered_memberships(
        &self,
        bounds: ReadBounds,
    ) -> Result<FilteredMembershipEvidence> {
        self.ensure_active()?;
        bounds.validate()?;
        let mut request =
            WorkOsDirectoryPageRequest::new(self.scope(), &bounds).map_err(map_model_error)?;
        let mut seen_cursor_digests = BTreeSet::new();
        if let Some(cursor) = &request.cursor {
            seen_cursor_digests.insert(cursor.digest().clone());
        }
        let mut users = BTreeMap::new();
        let mut groups = BTreeMap::new();
        let mut memberships = BTreeMap::new();
        let mut pages_observed = 0_u16;
        let mut response_bytes = 0_usize;
        let mut page_digests = Vec::new();
        let mut before_cursor_digests = Vec::new();
        let mut after_cursor_digests = Vec::new();
        let initial_direction = request
            .cursor
            .as_ref()
            .map_or(PageDirection::After, |cursor| cursor.direction().clone());
        let complete = loop {
            pages_observed = pages_observed.saturating_add(1);
            if pages_observed > bounds.max_pages {
                return Err(WorkOsDirectoryResultError::BoundsExceeded);
            }
            let page = self.provider.read_membership_page(&request)?;
            self.validate_page(&page, &request.operation)?;
            response_bytes = response_bytes
                .checked_add(page.response_bytes)
                .ok_or(WorkOsDirectoryResultError::BoundsExceeded)?;
            if response_bytes > bounds.max_response_bytes {
                return Err(WorkOsDirectoryResultError::BoundsExceeded);
            }
            page_digests.push(page.page_digest.clone());
            if let Some(cursor) = &page.before {
                before_cursor_digests.push(cursor.digest().clone());
            }
            if let Some(cursor) = &page.after {
                after_cursor_digests.push(cursor.digest().clone());
            }
            match &request.operation {
                PageOperation::UsersByGroup(group_id) => {
                    if !page.groups.is_empty() {
                        return Err(WorkOsDirectoryResultError::MembershipMismatch);
                    }
                    for user in &page.users {
                        self.validate_user_record(user)?;
                        if users
                            .insert(user.user_id.clone(), UserProjection::from(user))
                            .is_some()
                        {
                            return Err(WorkOsDirectoryResultError::MembershipMismatch);
                        }
                        let membership = MembershipProjection::new(
                            user.organization_id.clone(),
                            user.directory_id.clone(),
                            user.user_id.clone(),
                            group_id.clone(),
                            membership_state_for_user(&user.state),
                            MembershipSource::GroupFilter,
                            user.provider_revision.clone(),
                        );
                        if memberships
                            .insert(membership.membership_digest.clone(), membership)
                            .is_some()
                        {
                            return Err(WorkOsDirectoryResultError::MembershipMismatch);
                        }
                    }
                }
                PageOperation::GroupsByUser(user_id) => {
                    if !page.users.is_empty() {
                        return Err(WorkOsDirectoryResultError::MembershipMismatch);
                    }
                    for group in &page.groups {
                        self.validate_group_record(group)?;
                        if groups
                            .insert(group.group_id.clone(), GroupProjection::from(group))
                            .is_some()
                        {
                            return Err(WorkOsDirectoryResultError::MembershipMismatch);
                        }
                        let membership = MembershipProjection::new(
                            group.organization_id.clone(),
                            group.directory_id.clone(),
                            user_id.clone(),
                            group.group_id.clone(),
                            membership_state_for_group(&group.state),
                            MembershipSource::UserFilter,
                            group.provider_revision.clone(),
                        );
                        if memberships
                            .insert(membership.membership_digest.clone(), membership)
                            .is_some()
                        {
                            return Err(WorkOsDirectoryResultError::MembershipMismatch);
                        }
                    }
                }
            }
            if users.len().saturating_add(groups.len()) > bounds.max_records
                || memberships.len() > bounds.max_records
            {
                return Err(WorkOsDirectoryResultError::BoundsExceeded);
            }
            let next = match initial_direction {
                PageDirection::Before => page.before.clone(),
                PageDirection::After => page.after.clone(),
            };
            match (page.complete, next) {
                (true, None) => break true,
                (true, Some(_)) => return Err(WorkOsDirectoryResultError::IncompletePagination),
                (false, None) => return Err(WorkOsDirectoryResultError::IncompletePagination),
                (false, Some(cursor)) => {
                    self.validate_cursor(&cursor, &request.operation, &bounds)?;
                    if !seen_cursor_digests.insert(cursor.digest().clone()) {
                        return Err(WorkOsDirectoryResultError::CursorReplay);
                    }
                    request =
                        WorkOsDirectoryPageRequest::with_cursor(self.scope(), &bounds, cursor)
                            .map_err(map_model_error)?;
                }
            }
        };
        let mut users = users.into_values().collect::<Vec<_>>();
        let mut groups = groups.into_values().collect::<Vec<_>>();
        let mut memberships = memberships.into_values().collect::<Vec<_>>();
        users.sort_by(|left, right| left.user_id.as_str().cmp(right.user_id.as_str()));
        groups.sort_by(|left, right| left.group_id.as_str().cmp(right.group_id.as_str()));
        memberships.sort_by(|left, right| {
            left.membership_digest
                .as_str()
                .cmp(right.membership_digest.as_str())
        });
        let mut evidence = FilteredMembershipEvidence {
            filter: self.scope().membership.clone(),
            users,
            groups,
            memberships,
            pages_observed,
            response_bytes,
            complete,
            request_digest: WorkOsDirectoryPageRequest::new(self.scope(), &bounds)
                .map_err(map_model_error)?
                .request_digest,
            page_digests,
            before_cursor_digests,
            after_cursor_digests,
            pagination_digest: Digest::from_text("unsealed-workos-pagination"),
        };
        evidence.pagination_digest = evidence.recompute_pagination_digest();
        Ok(evidence)
    }

    pub fn read_filtered_membership_evidence(
        &self,
        bounds: ReadBounds,
    ) -> Result<FilteredMembershipEvidence> {
        self.read_filtered_memberships(bounds)
    }

    pub fn read_directory_evidence(&self, bounds: ReadBounds) -> Result<WorkOsDirectoryEvidence> {
        self.ensure_active()?;
        let directory_record = self.provider.read_directory(self.scope())?;
        let connection_record = self.provider.read_connection(self.scope())?;
        self.validate_directory_record(&directory_record)?;
        self.validate_connection_record(&connection_record)?;
        let membership = self.read_filtered_memberships(bounds)?;
        let status = evidence_status(
            &directory_record.state,
            &connection_record.state,
            &membership,
        );
        let directory = DirectoryProjection::from(&directory_record);
        let connection = ConnectionProjection::from(&connection_record);
        let request_digest = membership.request_digest.clone();
        let mut evidence = WorkOsDirectoryEvidence {
            schema_version: WORKOS_DIRECTORY_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: WORKOS_DIRECTORY_RESULT_CONTRACT_VERSION.to_owned(),
            scope_digest: self.scope().scope_digest().clone(),
            registration_digest: self.registration.registration_digest().clone(),
            provider_digest: self.provider.provider_digest().clone(),
            permission_digest: self.scope().permission_digest.clone(),
            organization_id: self.scope().organization_id.clone(),
            directory_id: self.scope().directory_id.clone(),
            connection_id: self.scope().connection_id.clone(),
            project: self.scope().project.clone(),
            mission: self.scope().mission.clone(),
            consent: self.scope().consent.clone(),
            directory,
            connection,
            membership,
            provider_revision: self.provider.provider_revision().clone(),
            status,
            provenance: self.provider.provenance(),
            request_digest,
            evidence_digest: Digest::from_text("unsealed-workos-evidence"),
            connected: false,
            native: false,
            raw_idp_attributes_retained: false,
            raw_email_retained: false,
            raw_name_retained: false,
            raw_custom_attributes_retained: false,
            identity_authority: false,
            consent_authority: false,
            effect_authority: false,
        };
        evidence.evidence_digest = evidence.recompute_digest();
        Ok(evidence)
    }

    pub fn read_directory_snapshot(&self, bounds: ReadBounds) -> Result<WorkOsDirectoryEvidence> {
        self.read_directory_evidence(bounds)
    }

    pub fn compile_evidence_proposal(
        &self,
        evidence: WorkOsDirectoryEvidence,
    ) -> Result<WorkOsDirectoryResultProposal> {
        self.ensure_active()?;
        evidence.verify_integrity()?;
        if evidence.scope_digest != *self.scope().scope_digest()
            || evidence.registration_digest != *self.registration.registration_digest()
            || evidence.provider_digest != *self.provider.provider_digest()
            || evidence.permission_digest != self.scope().permission_digest
            || evidence.provider_revision != *self.provider.provider_revision()
            || evidence.project != self.scope().project
            || evidence.mission != self.scope().mission
            || evidence.consent != self.scope().consent
            || evidence.organization_id != self.scope().organization_id
            || evidence.directory_id != self.scope().directory_id
            || evidence.connection_id != self.scope().connection_id
        {
            return Err(WorkOsDirectoryResultError::ScopeMismatch);
        }
        let mut proposal = WorkOsDirectoryResultProposal {
            schema_version: WORKOS_DIRECTORY_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: WORKOS_DIRECTORY_RESULT_CONTRACT_VERSION.to_owned(),
            scope_digest: self.scope().scope_digest().clone(),
            registration_digest: self.registration.registration_digest().clone(),
            provider_digest: self.provider.provider_digest().clone(),
            permission_digest: self.scope().permission_digest.clone(),
            project: self.scope().project.clone(),
            mission: self.scope().mission.clone(),
            consent: self.scope().consent.clone(),
            provider_revision: self.provider.provider_revision().clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            status: evidence.status.clone(),
            evidence,
            proposal_digest: Digest::from_text("unsealed-workos-proposal"),
            adopted_by_kernel: false,
            mutates_identity: false,
            mutates_directory: false,
            creates_access_grant: false,
            connected: false,
            native: false,
        };
        proposal.proposal_digest = proposal.recompute_digest();
        Ok(proposal)
    }

    pub fn compile_proposal(
        &self,
        evidence: WorkOsDirectoryEvidence,
    ) -> Result<WorkOsDirectoryResultProposal> {
        self.compile_evidence_proposal(evidence)
    }

    pub fn verify_proposal(&self, proposal: &WorkOsDirectoryResultProposal) -> Result<()> {
        self.ensure_active()?;
        proposal.verify_integrity()?;
        if proposal.scope_digest != *self.scope().scope_digest()
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.provider_digest != *self.provider.provider_digest()
            || proposal.permission_digest != self.scope().permission_digest
            || proposal.provider_revision != *self.provider.provider_revision()
            || proposal.project != self.scope().project
            || proposal.mission != self.scope().mission
            || proposal.consent != self.scope().consent
            || proposal.evidence.scope_digest != proposal.scope_digest
            || proposal.evidence.registration_digest != proposal.registration_digest
            || proposal.evidence_digest != proposal.evidence.evidence_digest
        {
            return Err(WorkOsDirectoryResultError::StaleProposal);
        }
        Ok(())
    }

    pub fn record_proposal(
        &mut self,
        proposal: &WorkOsDirectoryResultProposal,
    ) -> Result<WorkOsDirectoryRecordedProposal> {
        self.verify_proposal(proposal)?;
        if self.recorded.contains_key(&proposal.proposal_digest) {
            return Err(WorkOsDirectoryResultError::StaleRecord);
        }
        let record_id = digest_parts(
            "workos-directory-record-id/v1",
            &[
                proposal.proposal_digest.as_str().to_owned(),
                self.registration.registration_revision.value().to_string(),
            ],
        );
        let mut record = WorkOsDirectoryRecordedProposal {
            record_id: record_id.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            provider_digest: proposal.provider_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            permission_digest: proposal.permission_digest.clone(),
            project: proposal.project.clone(),
            mission: proposal.mission.clone(),
            consent: proposal.consent.clone(),
            provider_revision: proposal.provider_revision.clone(),
            recorded_registration_revision: self.registration.registration_revision,
            record_digest: Digest::from_text("unsealed-workos-record"),
        };
        record.record_digest = record.recompute_digest();
        self.recorded
            .insert(proposal.proposal_digest.clone(), record.clone());
        Ok(record)
    }

    pub fn read_back_record(
        &self,
        record: &WorkOsDirectoryRecordedProposal,
    ) -> Result<ReadBackVerification> {
        self.ensure_active()?;
        if record.record_digest != record.recompute_digest()
            || self.recorded.get(&record.proposal_digest) != Some(record)
            || record.scope_digest != *self.scope().scope_digest()
            || record.registration_digest != *self.registration.registration_digest()
            || record.provider_digest != *self.provider.provider_digest()
            || record.permission_digest != self.scope().permission_digest
            || record.provider_revision != *self.provider.provider_revision()
            || record.project != self.scope().project
            || record.mission != self.scope().mission
            || record.consent != self.scope().consent
            || record.recorded_registration_revision != self.registration.registration_revision
        {
            return Err(WorkOsDirectoryResultError::ReadBackFence);
        }
        Ok(ReadBackVerification {
            verified: true,
            record_digest: record.record_digest.clone(),
            proposal_digest: record.proposal_digest.clone(),
            evidence_digest: record.evidence_digest.clone(),
            scope_digest: record.scope_digest.clone(),
            registration_digest: record.registration_digest.clone(),
            independent_provider_reread: false,
            connected: false,
            native: false,
        })
    }

    pub fn read_back(
        &self,
        record: &WorkOsDirectoryRecordedProposal,
    ) -> Result<ReadBackVerification> {
        self.read_back_record(record)
    }

    pub fn verify_record(
        &self,
        record: &WorkOsDirectoryRecordedProposal,
    ) -> Result<ReadBackVerification> {
        self.read_back_record(record)
    }

    fn ensure_active(&self) -> Result<()> {
        match self.registration.status() {
            RegistrationStatus::Revoked => {
                return Err(WorkOsDirectoryResultError::RegistrationRevoked);
            }
            RegistrationStatus::Reversed => {
                return Err(WorkOsDirectoryResultError::RegistrationInactive);
            }
            RegistrationStatus::Active => {}
        }
        if self.registration.secret_reference().is_revoked() {
            return Err(WorkOsDirectoryResultError::SecretReferenceRevoked);
        }
        self.registration.validate(&self.provider)
    }

    fn validate_directory_record(&self, record: &crate::model::DirectoryRecord) -> Result<()> {
        if record.organization_id != self.scope().organization_id
            || record.directory_id != self.scope().directory_id
            || record.provider_revision != *self.provider.provider_revision()
        {
            Err(WorkOsDirectoryResultError::RevisionDrift)
        } else {
            Ok(())
        }
    }

    fn validate_connection_record(&self, record: &crate::model::ConnectionRecord) -> Result<()> {
        if record.organization_id != self.scope().organization_id
            || record.connection_id != self.scope().connection_id
            || record.provider_revision != *self.provider.provider_revision()
        {
            Err(WorkOsDirectoryResultError::ScopeMismatch)
        } else {
            Ok(())
        }
    }

    fn validate_user_record(&self, record: &DirectoryUserRecord) -> Result<()> {
        if record.organization_id != self.scope().organization_id
            || record.directory_id != self.scope().directory_id
            || record.provider_revision != *self.provider.provider_revision()
        {
            Err(WorkOsDirectoryResultError::MembershipMismatch)
        } else {
            Ok(())
        }
    }

    fn validate_group_record(&self, record: &DirectoryGroupRecord) -> Result<()> {
        if record.organization_id != self.scope().organization_id
            || record.directory_id != self.scope().directory_id
            || record.provider_revision != *self.provider.provider_revision()
        {
            Err(WorkOsDirectoryResultError::MembershipMismatch)
        } else {
            Ok(())
        }
    }

    fn validate_page(&self, page: &WorkOsDirectoryPage, operation: &PageOperation) -> Result<()> {
        if page.operation != *operation
            || page.provider_revision != *self.provider.provider_revision()
        {
            Err(WorkOsDirectoryResultError::RevisionDrift)
        } else {
            Ok(())
        }
    }

    fn validate_cursor(
        &self,
        cursor: &PageCursor,
        operation: &PageOperation,
        bounds: &ReadBounds,
    ) -> Result<()> {
        cursor
            .validate_against(self.scope(), operation, bounds.now_epoch_seconds)
            .map_err(|error| match error {
                ModelError::CursorExpired => WorkOsDirectoryResultError::CursorExpired,
                other => WorkOsDirectoryResultError::Model(other),
            })
    }
}

fn membership_state_for_user(state: &UserState) -> MembershipState {
    match state {
        UserState::Active => MembershipState::Active,
        UserState::Inactive | UserState::Deactivated => MembershipState::Inactive,
        UserState::Unknown => MembershipState::Unknown,
    }
}

fn membership_state_for_group(state: &GroupState) -> MembershipState {
    match state {
        GroupState::Active => MembershipState::Active,
        GroupState::Inactive => MembershipState::Inactive,
        GroupState::Unknown => MembershipState::Unknown,
    }
}

fn evidence_status(
    directory_state: &DirectoryState,
    connection_state: &ConnectionState,
    membership: &FilteredMembershipEvidence,
) -> EvidenceStatus {
    if !matches!(directory_state, DirectoryState::Linked) {
        return EvidenceStatus::DirectoryDeactivated;
    }
    if !matches!(connection_state, ConnectionState::Active) {
        return EvidenceStatus::AccessLost;
    }
    if membership
        .users
        .iter()
        .any(|user| !matches!(user.state, UserState::Active))
    {
        return EvidenceStatus::UserDeactivated;
    }
    if membership
        .groups
        .iter()
        .any(|group| !matches!(group.state, GroupState::Active))
    {
        return EvidenceStatus::GroupDeactivated;
    }
    if membership.complete {
        EvidenceStatus::Complete
    } else {
        EvidenceStatus::Partial
    }
}

fn map_model_error(error: ModelError) -> WorkOsDirectoryResultError {
    match error {
        ModelError::CursorExpired => WorkOsDirectoryResultError::CursorExpired,
        other => WorkOsDirectoryResultError::Model(other),
    }
}

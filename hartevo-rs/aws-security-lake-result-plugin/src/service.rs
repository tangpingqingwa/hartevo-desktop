//! Typed service, proposal, verification, and reversible registration.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::error::{AwsSecurityLakeError, AwsSecurityLakeTransportError, Result};
use crate::model::{
    AwsSecurityLakeOperation, AwsSecurityLakeScope, ConsentScope, DataLakeExceptionProjection,
    DataLakeProjection, DataLakeSourceProjection, Digest, EvidenceState, GetDataLakeSourcesRequest,
    ListDataLakeExceptionsRequest, ListDataLakesRequest, ListLogSourcesRequest,
    LogSourceProjection, PermissionSnapshot, RetentionFence, SecretReference, TransportProvenance,
};
use crate::provider::{
    AwsSecurityLakeProvider, AwsSecurityLakeProviderDefinition, AwsSecurityLakeTransport,
};
use crate::{
    CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_VERSION, MAX_PAGES, PLUGIN_VERSION, PROVIDER_ID,
    SERVICE_ID, contract_digest,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
    Reversed,
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
        let transition_digest = Digest::from_parts(
            "aws-security-lake-registration-transition/v1",
            &[
                ("previous", format!("{previous_status:?}")),
                ("new", format!("{new_status:?}")),
                ("registration", registration_digest.as_str().to_owned()),
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

/// Registration binds every authority boundary needed to replay a Layer-1
/// result. The secret handle is not stored; only its opaque digest is bound.
#[derive(Clone, Eq, PartialEq)]
pub struct AwsSecurityLakeRegistration {
    id: String,
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_revision: u64,
    provider_release: String,
    provider_digest: Digest,
    lake_digest: Digest,
    scope: AwsSecurityLakeScope,
    scope_digest: Digest,
    permission_snapshot: PermissionSnapshot,
    consent: ConsentScope,
    evidence_digest: Digest,
    secret_reference: SecretReference,
    registration_revision: u64,
    status: RegistrationStatus,
    registration_digest: Digest,
}

impl AwsSecurityLakeRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        scope: AwsSecurityLakeScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        provider: &AwsSecurityLakeProviderDefinition,
        registration_revision: u64,
    ) -> Result<Self> {
        provider.validate()?;
        let mut registration = Self {
            id: id.into(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: Digest::parse(CONTRACT_DIGEST.to_owned())?,
            provider_id: provider.provider_id.clone(),
            provider_revision: provider.provider_revision,
            provider_release: provider.release.clone(),
            provider_digest: provider.provider_digest.clone(),
            lake_digest: scope.lake_digest(),
            scope_digest: scope.digest(),
            scope,
            permission_snapshot,
            consent,
            evidence_digest: Digest::from_text("unsealed-aws-security-lake-evidence-policy"),
            secret_reference,
            registration_revision,
            status: RegistrationStatus::Active,
            registration_digest: Digest::from_text("unsealed-aws-security-lake-registration"),
        };
        registration.evidence_digest = registration.scope.evidence_digest();
        registration.registration_digest = registration.calculate_registration_digest();
        registration.validate()?;
        Ok(registration)
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }

    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub const fn provider_revision(&self) -> u64 {
        self.provider_revision
    }

    pub fn provider_release(&self) -> &str {
        &self.provider_release
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn lake_digest(&self) -> &Digest {
        &self.lake_digest
    }

    pub fn scope(&self) -> &AwsSecurityLakeScope {
        &self.scope
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn permission_snapshot(&self) -> &PermissionSnapshot {
        &self.permission_snapshot
    }

    pub fn permission_digest(&self) -> Digest {
        self.permission_snapshot.digest()
    }

    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    pub fn consent_digest(&self) -> Digest {
        self.consent.digest()
    }

    pub fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn secret_reference_digest(&self) -> &Digest {
        self.secret_reference.reference_digest()
    }

    pub const fn registration_revision(&self) -> u64 {
        self.registration_revision
    }

    pub const fn status(&self) -> RegistrationStatus {
        self.status
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }

    pub fn validate(&self) -> Result<()> {
        if !valid_registration_id(&self.id)
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.contract_digest.as_str() != contract_digest()
            || self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.provider_release.is_empty()
            || self.registration_revision == 0
            || self.lake_digest != self.scope.lake_digest()
            || self.scope_digest != self.scope.digest()
            || self.evidence_digest != self.scope.evidence_digest()
            || self.registration_digest != self.calculate_registration_digest()
        {
            return Err(AwsSecurityLakeError::InvalidRegistration);
        }
        self.permission_snapshot.validate()?;
        self.consent.validate()?;
        self.scope.validate()?;
        self.secret_reference.validate(&self.scope)?;
        if self
            .permission_snapshot
            .permissions
            .iter()
            .any(|permission| permission == "outcome.adopt")
        {
            return Err(AwsSecurityLakeError::InvalidPermissionSnapshot);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsSecurityLakeError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Revoked;
        self.registration_digest = self.calculate_registration_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsSecurityLakeError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Reversed;
        self.registration_digest = self.calculate_registration_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsSecurityLakeError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Active;
        self.registration_digest = self.calculate_registration_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    fn calculate_registration_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-security-lake-registration/v1",
            &[
                ("id", self.id.clone()),
                ("plugin_version", self.plugin_version.clone()),
                ("contract_version", self.contract_version.clone()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider_id", self.provider_id.clone()),
                ("provider_revision", self.provider_revision.to_string()),
                ("provider_release", self.provider_release.clone()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("lake", self.lake_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("permission", self.permission_digest().as_str().to_owned()),
                ("consent", self.consent_digest().as_str().to_owned()),
                ("evidence", self.evidence_digest.as_str().to_owned()),
                ("secret", self.secret_reference_digest().as_str().to_owned()),
                ("revision", self.registration_revision.to_string()),
                ("status", format!("{:?}", self.status)),
            ],
        )
    }
}

fn valid_registration_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= crate::MAX_IDENTIFIER_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

impl fmt::Debug for AwsSecurityLakeRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsSecurityLakeRegistration")
            .field("id_digest", &Digest::from_text(&self.id))
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_id", &self.provider_id)
            .field("provider_revision", &self.provider_revision)
            .field("provider_digest", &self.provider_digest)
            .field("lake_digest", &self.lake_digest)
            .field("scope_digest", &self.scope_digest)
            .field("permission_digest", &self.permission_digest())
            .field("consent_digest", &self.consent_digest())
            .field("evidence_digest", &self.evidence_digest)
            .field("secret_reference_digest", &self.secret_reference_digest())
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("registration_digest", &self.registration_digest)
            .finish()
    }
}

impl Serialize for AwsSecurityLakeRegistration {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsSecurityLakeRegistration", 17)?;
        state.serialize_field("idDigest", &Digest::from_text(&self.id))?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("providerRelease", &self.provider_release)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("lakeDigest", &self.lake_digest)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest())?;
        state.serialize_field("consentDigest", &self.consent_digest())?;
        state.serialize_field("evidenceDigest", &self.evidence_digest)?;
        state.serialize_field("secretReferenceDigest", &self.secret_reference_digest())?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsSecurityLakeCapabilities {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub operations: Vec<String>,
    pub permissions: Vec<String>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub kernel_authority: bool,
    pub outcome_adoption: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaginationEvidence {
    pub pages_observed: u16,
    pub complete: bool,
    pub filter_digest: Digest,
    pub cursor_digests: Vec<Digest>,
    pub page_digests: Vec<Digest>,
    pub pagination_digest: Digest,
}

impl PaginationEvidence {
    fn new(
        operation: AwsSecurityLakeOperation,
        filter_digest: Digest,
        pages_observed: u16,
        complete: bool,
        cursor_digests: Vec<Digest>,
        page_digests: Vec<Digest>,
    ) -> Self {
        let pagination_digest = Digest::from_parts(
            "aws-security-lake-pagination-evidence/v1",
            &[
                ("operation", operation.as_str().to_owned()),
                ("filter", filter_digest.as_str().to_owned()),
                ("pages", pages_observed.to_string()),
                ("complete", complete.to_string()),
                (
                    "cursors",
                    cursor_digests
                        .iter()
                        .map(|digest| digest.as_str())
                        .collect::<Vec<_>>()
                        .join("\u{1f}"),
                ),
                (
                    "page_digests",
                    page_digests
                        .iter()
                        .map(|digest| digest.as_str())
                        .collect::<Vec<_>>()
                        .join("\u{1f}"),
                ),
            ],
        );
        Self {
            pages_observed,
            complete,
            filter_digest,
            cursor_digests,
            page_digests,
            pagination_digest,
        }
    }

    fn validate_integrity(&self, operation: AwsSecurityLakeOperation) -> Result<()> {
        let expected = Digest::from_parts(
            "aws-security-lake-pagination-evidence/v1",
            &[
                ("operation", operation.as_str().to_owned()),
                ("filter", self.filter_digest.as_str().to_owned()),
                ("pages", self.pages_observed.to_string()),
                ("complete", self.complete.to_string()),
                (
                    "cursors",
                    self.cursor_digests
                        .iter()
                        .map(|digest| digest.as_str())
                        .collect::<Vec<_>>()
                        .join("\u{1f}"),
                ),
                (
                    "page_digests",
                    self.page_digests
                        .iter()
                        .map(|digest| digest.as_str())
                        .collect::<Vec<_>>()
                        .join("\u{1f}"),
                ),
            ],
        );
        if self.pages_observed > MAX_PAGES || expected != self.pagination_digest {
            return Err(AwsSecurityLakeError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub lake_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub filter_digest: Digest,
    pub pagination_digest: Digest,
    pub retention_fence_digest: Digest,
    pub evidence_policy_digest: Digest,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsSecurityLakeEvidence {
    pub operation: AwsSecurityLakeOperation,
    pub state: EvidenceState,
    pub scope_digest: Digest,
    pub lake_digest: Digest,
    pub provenance: TransportProvenance,
    pub pages_observed: u16,
    pub complete: bool,
    pub pagination: PaginationEvidence,
    pub retention_fence: RetentionFence,
    pub lakes: Vec<DataLakeProjection>,
    pub log_sources: Vec<LogSourceProjection>,
    pub data_lake_sources: Vec<DataLakeSourceProjection>,
    pub exceptions: Vec<DataLakeExceptionProjection>,
    pub provider_error_digest: Option<Digest>,
    pub digests: EvidenceDigests,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl AwsSecurityLakeEvidence {
    #[allow(clippy::too_many_arguments)]
    fn new(
        operation: AwsSecurityLakeOperation,
        state: EvidenceState,
        scope: &AwsSecurityLakeScope,
        provider: &AwsSecurityLakeProviderDefinition,
        permission: &PermissionSnapshot,
        consent: &ConsentScope,
        provenance: TransportProvenance,
        retention_fence: RetentionFence,
        pagination: PaginationEvidence,
        lakes: Vec<DataLakeProjection>,
        log_sources: Vec<LogSourceProjection>,
        data_lake_sources: Vec<DataLakeSourceProjection>,
        exceptions: Vec<DataLakeExceptionProjection>,
        provider_error_digest: Option<Digest>,
    ) -> Self {
        let mut evidence = Self {
            operation,
            state,
            scope_digest: scope.digest(),
            lake_digest: scope.lake_digest(),
            provenance,
            pages_observed: pagination.pages_observed,
            complete: pagination.complete,
            pagination,
            retention_fence,
            lakes,
            log_sources,
            data_lake_sources,
            exceptions,
            provider_error_digest,
            digests: EvidenceDigests {
                plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
                contract_digest: Digest::from_text(CONTRACT_DIGEST),
                provider_digest: provider.provider_digest.clone(),
                lake_digest: scope.lake_digest(),
                scope_digest: scope.digest(),
                permission_digest: permission.digest(),
                consent_digest: consent.digest(),
                filter_digest: Digest::from_text("unsealed-filter"),
                pagination_digest: Digest::from_text("unsealed-pagination"),
                retention_fence_digest: Digest::from_text("unsealed-retention"),
                evidence_policy_digest: scope.evidence_digest(),
                evidence_digest: Digest::from_text("unsealed-evidence"),
            },
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        evidence.digests.filter_digest = evidence.pagination.filter_digest.clone();
        evidence.digests.pagination_digest = evidence.pagination.pagination_digest.clone();
        evidence.digests.retention_fence_digest = evidence.retention_fence.digest.clone();
        evidence.digests.evidence_digest = evidence.calculate_evidence_digest();
        evidence
    }

    pub fn digest(&self) -> &Digest {
        &self.digests.evidence_digest
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.connected || self.native || self.first_party || self.provider_receipt {
            return Err(AwsSecurityLakeError::TamperedEvidence);
        }
        self.pagination.validate_integrity(self.operation)?;
        self.retention_fence.validate_integrity()?;
        if self.pages_observed != self.pagination.pages_observed
            || self.complete != self.pagination.complete
        {
            return Err(AwsSecurityLakeError::TamperedEvidence);
        }
        if self.scope_digest != self.digests.scope_digest
            || self.lake_digest != self.digests.lake_digest
            || self.pagination.filter_digest != self.digests.filter_digest
            || self.pagination.pagination_digest != self.digests.pagination_digest
            || self.retention_fence.digest != self.digests.retention_fence_digest
            || self.digests.evidence_digest != self.calculate_evidence_digest()
        {
            return Err(AwsSecurityLakeError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_evidence_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-security-lake-evidence/v1",
            &[
                ("operation", self.operation.as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("lake", self.lake_digest.as_str().to_owned()),
                ("provenance", self.provenance.as_str().to_owned()),
                (
                    "pagination",
                    self.pagination.pagination_digest.as_str().to_owned(),
                ),
                ("retention", self.retention_fence.digest.as_str().to_owned()),
                (
                    "lakes",
                    self.lakes
                        .iter()
                        .map(DataLakeProjection::digest)
                        .map(|digest| digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join("\u{1f}"),
                ),
                (
                    "log_sources",
                    self.log_sources
                        .iter()
                        .map(LogSourceProjection::digest)
                        .map(|digest| digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join("\u{1f}"),
                ),
                (
                    "data_lake_sources",
                    self.data_lake_sources
                        .iter()
                        .map(DataLakeSourceProjection::digest)
                        .map(|digest| digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join("\u{1f}"),
                ),
                (
                    "exceptions",
                    self.exceptions
                        .iter()
                        .map(DataLakeExceptionProjection::digest)
                        .map(|digest| digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join("\u{1f}"),
                ),
                (
                    "provider_error",
                    self.provider_error_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "permission",
                    self.digests.permission_digest.as_str().to_owned(),
                ),
                ("consent", self.digests.consent_digest.as_str().to_owned()),
                (
                    "policy",
                    self.digests.evidence_policy_digest.as_str().to_owned(),
                ),
                ("connected", self.connected.to_string()),
                ("native", self.native.to_string()),
                ("first_party", self.first_party.to_string()),
                ("provider_receipt", self.provider_receipt.to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsSecurityLakeProposal {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub operation: AwsSecurityLakeOperation,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub lake_digest: Digest,
    pub state: EvidenceState,
    pub evidence: AwsSecurityLakeEvidence,
    pub proposal_digest: Digest,
    pub provenance: TransportProvenance,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl AwsSecurityLakeProposal {
    fn new(registration: &AwsSecurityLakeRegistration, evidence: AwsSecurityLakeEvidence) -> Self {
        let mut proposal = Self {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            operation: evidence.operation,
            registration_digest: registration.registration_digest().clone(),
            scope_digest: registration.scope_digest().clone(),
            lake_digest: registration.lake_digest().clone(),
            state: evidence.state,
            provenance: evidence.provenance,
            evidence,
            proposal_digest: Digest::from_text("unsealed-aws-security-lake-proposal"),
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        proposal.proposal_digest = proposal.calculate_proposal_digest();
        proposal
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.evidence.validate_integrity()?;
        if self.service_id != SERVICE_ID
            || self.provider_id != PROVIDER_ID
            || self.consumer_id != CONSUMER_ID
            || self.operation != self.evidence.operation
            || self.state != self.evidence.state
            || self.scope_digest != self.evidence.scope_digest
            || self.lake_digest != self.evidence.lake_digest
            || self.provenance != self.evidence.provenance
            || !self.review_only
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.proposal_digest != self.calculate_proposal_digest()
        {
            return Err(AwsSecurityLakeError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_proposal_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-security-lake-proposal/v1",
            &[
                ("service", self.service_id.clone()),
                ("provider", self.provider_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("operation", self.operation.as_str().to_owned()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("lake", self.lake_digest.as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
                ("evidence", self.evidence.digest().as_str().to_owned()),
                ("review_only", self.review_only.to_string()),
                ("connected", self.connected.to_string()),
                ("native", self.native.to_string()),
                ("first_party", self.first_party.to_string()),
                ("provider_receipt", self.provider_receipt.to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailure {
    Tampered,
    RegistrationInactive,
    RegistrationMismatch,
    ScopeMismatch,
    LakeMismatch,
    PermissionMismatch,
    EvidenceMismatch,
    IncompletePagination,
    NonCompleteState,
    NativeClaim,
    ConnectedClaim,
    ProviderReceiptClaim,
    RetentionGap,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub valid: bool,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub failures: Vec<VerificationFailure>,
}

impl VerificationReport {
    pub const fn is_valid(&self) -> bool {
        self.valid
    }
}

pub struct AwsSecurityLakeService<T: AwsSecurityLakeTransport> {
    scope: AwsSecurityLakeScope,
    secret_reference: SecretReference,
    consent: ConsentScope,
    provider: AwsSecurityLakeProvider<T>,
    registration: AwsSecurityLakeRegistration,
    observed_at: DateTime<Utc>,
}

impl<T: AwsSecurityLakeTransport> fmt::Debug for AwsSecurityLakeService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsSecurityLakeService")
            .field("scope_digest", &self.scope.digest())
            .field("provider", &self.provider)
            .field(
                "registration_digest",
                &self.registration.registration_digest(),
            )
            .field("observed_at", &self.observed_at)
            .finish()
    }
}

impl<T: AwsSecurityLakeTransport> AwsSecurityLakeService<T> {
    pub fn new(
        scope: AwsSecurityLakeScope,
        secret_reference: SecretReference,
        consent: ConsentScope,
        provider: AwsSecurityLakeProvider<T>,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        scope.validate()?;
        secret_reference.validate(&scope)?;
        consent.validate()?;
        provider.definition().validate()?;
        let permission_snapshot = PermissionSnapshot::for_layer_one(1);
        let registration = AwsSecurityLakeRegistration::new(
            "aws-security-lake-registration",
            scope.clone(),
            secret_reference.clone(),
            permission_snapshot,
            consent.clone(),
            provider.definition(),
            1,
        )?;
        Ok(Self {
            scope,
            secret_reference,
            consent,
            provider,
            registration,
            observed_at,
        })
    }

    pub fn scope(&self) -> &AwsSecurityLakeScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    pub fn provider(&self) -> &AwsSecurityLakeProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsSecurityLakeProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &AwsSecurityLakeRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut AwsSecurityLakeRegistration {
        &mut self.registration
    }

    pub fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub fn describe_scope(&self) -> &AwsSecurityLakeScope {
        &self.scope
    }

    pub fn describe_capabilities(&self) -> AwsSecurityLakeCapabilities {
        AwsSecurityLakeCapabilities {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            operations: vec![
                AwsSecurityLakeOperation::ListDataLakes.as_str().to_owned(),
                AwsSecurityLakeOperation::ListLogSources.as_str().to_owned(),
                AwsSecurityLakeOperation::GetDataLakeSources
                    .as_str()
                    .to_owned(),
                AwsSecurityLakeOperation::ListDataLakeExceptions
                    .as_str()
                    .to_owned(),
            ],
            permissions: crate::LAYER1_PERMISSIONS
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            read_only: true,
            proposal_only: true,
            recording_only: true,
            connected: false,
            native: false,
            first_party: false,
            kernel_authority: false,
            outcome_adoption: false,
        }
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.revoke()
    }

    pub fn reverse_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.reverse()
    }

    pub fn restore_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.restore()
    }

    pub fn register(&self) -> Result<&AwsSecurityLakeRegistration> {
        self.registration.validate()?;
        if !self.registration.is_active() {
            return Err(AwsSecurityLakeError::RegistrationInactive);
        }
        Ok(&self.registration)
    }

    pub fn read(&mut self, operation: AwsSecurityLakeOperation) -> Result<AwsSecurityLakeProposal> {
        match operation {
            AwsSecurityLakeOperation::ListDataLakes => self.read_list_data_lakes(),
            AwsSecurityLakeOperation::ListLogSources => self.read_list_log_sources(),
            AwsSecurityLakeOperation::GetDataLakeSources => self.read_get_data_lake_sources(),
            AwsSecurityLakeOperation::ListDataLakeExceptions => {
                self.read_list_data_lake_exceptions()
            }
        }
    }

    pub fn propose(
        &mut self,
        operation: AwsSecurityLakeOperation,
    ) -> Result<AwsSecurityLakeProposal> {
        self.read(operation)
    }

    pub fn read_list_data_lakes(&mut self) -> Result<AwsSecurityLakeProposal> {
        let mut request = ListDataLakesRequest::for_scope(&self.scope)?;
        let filter_digest = request.filter_digest();
        if !self.registration.is_active() {
            return self.build_failure(
                AwsSecurityLakeOperation::ListDataLakes,
                filter_digest,
                0,
                Vec::new(),
                Vec::new(),
                EvidenceState::RegistrationRevoked,
            );
        }
        let mut pages = 0;
        let mut cursors = Vec::new();
        let mut page_digests = Vec::new();
        let mut seen = BTreeSet::new();
        let mut lakes = Vec::new();
        loop {
            if let Some(cursor) = request.cursor() {
                if !seen.insert(cursor.token_digest().clone()) {
                    return self.build_proposal(
                        AwsSecurityLakeOperation::ListDataLakes,
                        EvidenceState::PaginationLoop,
                        false,
                        filter_digest,
                        pages,
                        cursors,
                        page_digests,
                        lakes,
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                        None,
                    );
                }
                cursors.push(cursor.token_digest().clone());
            }
            match self.provider.list_data_lakes(&request) {
                Ok(page) => {
                    if page.data_lakes.iter().any(|lake| {
                        !self
                            .scope
                            .allows_lake(&lake.lake_digest, &lake.region_digest)
                            || lake.status == crate::model::LakeStatus::Unknown
                            || self
                                .scope
                                .expected_lake_status()
                                .is_some_and(|expected| expected != lake.status)
                    }) {
                        return self.build_failure(
                            AwsSecurityLakeOperation::ListDataLakes,
                            filter_digest,
                            pages,
                            cursors,
                            page_digests,
                            EvidenceState::Tampered,
                        );
                    }
                    pages = pages.saturating_add(1);
                    page_digests.push(page.page_digest.clone());
                    lakes.extend(page.data_lakes);
                    if let Some(next) = page.next_token.clone() {
                        if seen.contains(next.token_digest()) {
                            return self.build_proposal(
                                AwsSecurityLakeOperation::ListDataLakes,
                                EvidenceState::PaginationLoop,
                                false,
                                filter_digest,
                                pages,
                                cursors,
                                page_digests,
                                lakes,
                                Vec::new(),
                                Vec::new(),
                                Vec::new(),
                                None,
                            );
                        }
                        if pages >= MAX_PAGES {
                            return self.build_proposal(
                                AwsSecurityLakeOperation::ListDataLakes,
                                EvidenceState::Partial,
                                false,
                                filter_digest,
                                pages,
                                cursors,
                                page_digests,
                                lakes,
                                Vec::new(),
                                Vec::new(),
                                Vec::new(),
                                None,
                            );
                        }
                        request = ListDataLakesRequest::new(
                            &self.scope,
                            request.filter().clone(),
                            Some(next),
                        )?;
                    } else {
                        return self.build_proposal(
                            AwsSecurityLakeOperation::ListDataLakes,
                            EvidenceState::Complete,
                            true,
                            filter_digest,
                            pages,
                            cursors,
                            page_digests,
                            lakes,
                            Vec::new(),
                            Vec::new(),
                            Vec::new(),
                            None,
                        );
                    }
                }
                Err(error) => {
                    return self.build_failure(
                        AwsSecurityLakeOperation::ListDataLakes,
                        filter_digest,
                        pages,
                        cursors,
                        page_digests,
                        state_for_transport(&error),
                    );
                }
            }
        }
    }

    pub fn propose_list_data_lakes(&mut self) -> Result<AwsSecurityLakeProposal> {
        self.read_list_data_lakes()
    }

    pub fn read_list_log_sources(&mut self) -> Result<AwsSecurityLakeProposal> {
        let mut request = ListLogSourcesRequest::for_scope(&self.scope)?;
        let filter_digest = request.filter_digest();
        if !self.registration.is_active() {
            return self.build_failure(
                AwsSecurityLakeOperation::ListLogSources,
                filter_digest,
                0,
                Vec::new(),
                Vec::new(),
                EvidenceState::RegistrationRevoked,
            );
        }
        let mut pages = 0;
        let mut cursors = Vec::new();
        let mut page_digests = Vec::new();
        let mut seen = BTreeSet::new();
        let mut sources = Vec::new();
        loop {
            if let Some(cursor) = request.cursor() {
                if !seen.insert(cursor.token_digest().clone()) {
                    return self.build_proposal(
                        AwsSecurityLakeOperation::ListLogSources,
                        EvidenceState::PaginationLoop,
                        false,
                        filter_digest,
                        pages,
                        cursors,
                        page_digests,
                        Vec::new(),
                        sources,
                        Vec::new(),
                        Vec::new(),
                        None,
                    );
                }
                cursors.push(cursor.token_digest().clone());
            }
            match self.provider.list_log_sources(&request) {
                Ok(page) => {
                    if page.sources.iter().any(|source| {
                        !self.scope.allows_log_source(
                            &source.account_digest,
                            &source.region_digest,
                            &source.source_digest,
                        ) || source.state == crate::model::SourceState::Unknown
                    }) {
                        return self.build_failure(
                            AwsSecurityLakeOperation::ListLogSources,
                            filter_digest,
                            pages,
                            cursors,
                            page_digests,
                            EvidenceState::Tampered,
                        );
                    }
                    pages = pages.saturating_add(1);
                    page_digests.push(page.page_digest.clone());
                    sources.extend(page.sources);
                    if let Some(next) = page.next_token.clone() {
                        if seen.contains(next.token_digest()) {
                            return self.build_proposal(
                                AwsSecurityLakeOperation::ListLogSources,
                                EvidenceState::PaginationLoop,
                                false,
                                filter_digest,
                                pages,
                                cursors,
                                page_digests,
                                Vec::new(),
                                sources,
                                Vec::new(),
                                Vec::new(),
                                None,
                            );
                        }
                        if pages >= MAX_PAGES {
                            return self.build_proposal(
                                AwsSecurityLakeOperation::ListLogSources,
                                EvidenceState::Partial,
                                false,
                                filter_digest,
                                pages,
                                cursors,
                                page_digests,
                                Vec::new(),
                                sources,
                                Vec::new(),
                                Vec::new(),
                                None,
                            );
                        }
                        request = ListLogSourcesRequest::new(
                            &self.scope,
                            request.filter().clone(),
                            Some(next),
                        )?;
                    } else {
                        return self.build_proposal(
                            AwsSecurityLakeOperation::ListLogSources,
                            EvidenceState::Complete,
                            true,
                            filter_digest,
                            pages,
                            cursors,
                            page_digests,
                            Vec::new(),
                            sources,
                            Vec::new(),
                            Vec::new(),
                            None,
                        );
                    }
                }
                Err(error) => {
                    return self.build_failure(
                        AwsSecurityLakeOperation::ListLogSources,
                        filter_digest,
                        pages,
                        cursors,
                        page_digests,
                        state_for_transport(&error),
                    );
                }
            }
        }
    }

    pub fn propose_list_log_sources(&mut self) -> Result<AwsSecurityLakeProposal> {
        self.read_list_log_sources()
    }

    pub fn read_get_data_lake_sources(&mut self) -> Result<AwsSecurityLakeProposal> {
        let mut request = GetDataLakeSourcesRequest::for_scope(&self.scope)?;
        let filter_digest = request.filter_digest();
        if !self.registration.is_active() {
            return self.build_failure(
                AwsSecurityLakeOperation::GetDataLakeSources,
                filter_digest,
                0,
                Vec::new(),
                Vec::new(),
                EvidenceState::RegistrationRevoked,
            );
        }
        let mut pages = 0;
        let mut cursors = Vec::new();
        let mut page_digests = Vec::new();
        let mut seen = BTreeSet::new();
        let mut sources = Vec::new();
        loop {
            if let Some(cursor) = request.cursor() {
                if !seen.insert(cursor.token_digest().clone()) {
                    return self.build_proposal(
                        AwsSecurityLakeOperation::GetDataLakeSources,
                        EvidenceState::PaginationLoop,
                        false,
                        filter_digest,
                        pages,
                        cursors,
                        page_digests,
                        Vec::new(),
                        Vec::new(),
                        sources,
                        Vec::new(),
                        None,
                    );
                }
                cursors.push(cursor.token_digest().clone());
            }
            match self.provider.get_data_lake_sources(&request) {
                Ok(page) => {
                    if page.data_lake_sources.iter().any(|source| {
                        !self.scope.allows_data_lake_source(
                            &source.lake_digest,
                            &source.account_digest,
                            &source.source_digest,
                            &source.region_digest,
                        ) || source.state == crate::model::SourceState::Unknown
                    }) {
                        return self.build_failure(
                            AwsSecurityLakeOperation::GetDataLakeSources,
                            filter_digest,
                            pages,
                            cursors,
                            page_digests,
                            EvidenceState::Tampered,
                        );
                    }
                    pages = pages.saturating_add(1);
                    page_digests.push(page.page_digest.clone());
                    sources.extend(page.data_lake_sources);
                    if let Some(next) = page.next_token.clone() {
                        if seen.contains(next.token_digest()) {
                            return self.build_proposal(
                                AwsSecurityLakeOperation::GetDataLakeSources,
                                EvidenceState::PaginationLoop,
                                false,
                                filter_digest,
                                pages,
                                cursors,
                                page_digests,
                                Vec::new(),
                                Vec::new(),
                                sources,
                                Vec::new(),
                                None,
                            );
                        }
                        if pages >= MAX_PAGES {
                            return self.build_proposal(
                                AwsSecurityLakeOperation::GetDataLakeSources,
                                EvidenceState::Partial,
                                false,
                                filter_digest,
                                pages,
                                cursors,
                                page_digests,
                                Vec::new(),
                                Vec::new(),
                                sources,
                                Vec::new(),
                                None,
                            );
                        }
                        request = GetDataLakeSourcesRequest::new(
                            &self.scope,
                            request.filter().clone(),
                            Some(next),
                        )?;
                    } else {
                        return self.build_proposal(
                            AwsSecurityLakeOperation::GetDataLakeSources,
                            EvidenceState::Complete,
                            true,
                            filter_digest,
                            pages,
                            cursors,
                            page_digests,
                            Vec::new(),
                            Vec::new(),
                            sources,
                            Vec::new(),
                            None,
                        );
                    }
                }
                Err(error) => {
                    return self.build_failure(
                        AwsSecurityLakeOperation::GetDataLakeSources,
                        filter_digest,
                        pages,
                        cursors,
                        page_digests,
                        state_for_transport(&error),
                    );
                }
            }
        }
    }

    pub fn propose_get_data_lake_sources(&mut self) -> Result<AwsSecurityLakeProposal> {
        self.read_get_data_lake_sources()
    }

    pub fn read_list_data_lake_exceptions(&mut self) -> Result<AwsSecurityLakeProposal> {
        let retention = self.scope.retention_fence(self.observed_at)?;
        let mut request = ListDataLakeExceptionsRequest::for_scope(&self.scope)?;
        let filter_digest = request.filter_digest();
        if !self.registration.is_active() {
            return self.build_failure(
                AwsSecurityLakeOperation::ListDataLakeExceptions,
                filter_digest,
                0,
                Vec::new(),
                Vec::new(),
                EvidenceState::RegistrationRevoked,
            );
        }
        let mut pages = 0;
        let mut cursors = Vec::new();
        let mut page_digests = Vec::new();
        let mut seen = BTreeSet::new();
        let mut exceptions = Vec::new();
        loop {
            if let Some(cursor) = request.cursor() {
                if !seen.insert(cursor.token_digest().clone()) {
                    return self.build_proposal(
                        AwsSecurityLakeOperation::ListDataLakeExceptions,
                        EvidenceState::PaginationLoop,
                        false,
                        filter_digest,
                        pages,
                        cursors,
                        page_digests,
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                        exceptions,
                        None,
                    );
                }
                cursors.push(cursor.token_digest().clone());
            }
            match self.provider.list_data_lake_exceptions(&request) {
                Ok(page) => {
                    if page
                        .exceptions
                        .iter()
                        .any(|exception| !self.scope.allows_region(&exception.region_digest))
                    {
                        return self.build_failure(
                            AwsSecurityLakeOperation::ListDataLakeExceptions,
                            filter_digest,
                            pages,
                            cursors,
                            page_digests,
                            EvidenceState::Tampered,
                        );
                    }
                    pages = pages.saturating_add(1);
                    page_digests.push(page.page_digest.clone());
                    exceptions.extend(page.exceptions);
                    if exceptions
                        .iter()
                        .any(|exception| exception.validate_retention(&retention).is_err())
                    {
                        return self.build_proposal(
                            AwsSecurityLakeOperation::ListDataLakeExceptions,
                            EvidenceState::RetentionGap,
                            false,
                            filter_digest,
                            pages,
                            cursors,
                            page_digests,
                            Vec::new(),
                            Vec::new(),
                            Vec::new(),
                            exceptions,
                            None,
                        );
                    }
                    if let Some(next) = page.next_token.clone() {
                        if seen.contains(next.token_digest()) {
                            return self.build_proposal(
                                AwsSecurityLakeOperation::ListDataLakeExceptions,
                                EvidenceState::PaginationLoop,
                                false,
                                filter_digest,
                                pages,
                                cursors,
                                page_digests,
                                Vec::new(),
                                Vec::new(),
                                Vec::new(),
                                exceptions,
                                None,
                            );
                        }
                        if pages >= MAX_PAGES {
                            return self.build_proposal(
                                AwsSecurityLakeOperation::ListDataLakeExceptions,
                                EvidenceState::Partial,
                                false,
                                filter_digest,
                                pages,
                                cursors,
                                page_digests,
                                Vec::new(),
                                Vec::new(),
                                Vec::new(),
                                exceptions,
                                None,
                            );
                        }
                        request = ListDataLakeExceptionsRequest::new(
                            &self.scope,
                            request.filter().clone(),
                            Some(next),
                        )?;
                    } else {
                        return self.build_proposal(
                            AwsSecurityLakeOperation::ListDataLakeExceptions,
                            EvidenceState::Complete,
                            true,
                            filter_digest,
                            pages,
                            cursors,
                            page_digests,
                            Vec::new(),
                            Vec::new(),
                            Vec::new(),
                            exceptions,
                            None,
                        );
                    }
                }
                Err(error) => {
                    return self.build_failure(
                        AwsSecurityLakeOperation::ListDataLakeExceptions,
                        filter_digest,
                        pages,
                        cursors,
                        page_digests,
                        state_for_transport(&error),
                    );
                }
            }
        }
    }

    pub fn propose_list_data_lake_exceptions(&mut self) -> Result<AwsSecurityLakeProposal> {
        self.read_list_data_lake_exceptions()
    }

    pub fn record(
        &self,
        proposal: &AwsSecurityLakeProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<crate::consumer::RecordedAwsSecurityLakeResult> {
        let idempotency_key = idempotency_key.as_ref();
        if idempotency_key.is_empty()
            || idempotency_key.len() > crate::MAX_IDENTIFIER_BYTES
            || idempotency_key.chars().any(char::is_control)
        {
            return Err(AwsSecurityLakeError::InvalidIdempotencyKey);
        }
        let report = self.verify(proposal);
        if !report.valid {
            return Err(AwsSecurityLakeError::TamperedEvidence);
        }
        crate::consumer::RecordedAwsSecurityLakeResult::new(
            Digest::from_text(idempotency_key),
            proposal,
            false,
        )
    }

    pub fn verify(&self, proposal: &AwsSecurityLakeProposal) -> VerificationReport {
        let mut failures = Vec::new();
        if proposal.validate_integrity().is_err() {
            failures.push(VerificationFailure::Tampered);
        }
        if !self.registration.is_active() {
            failures.push(VerificationFailure::RegistrationInactive);
        }
        if proposal.registration_digest != *self.registration.registration_digest() {
            failures.push(VerificationFailure::RegistrationMismatch);
        }
        if proposal.scope_digest != self.scope.digest()
            || proposal.evidence.scope_digest != self.scope.digest()
        {
            failures.push(VerificationFailure::ScopeMismatch);
        }
        if proposal.lake_digest != self.scope.lake_digest()
            || proposal.evidence.lake_digest != self.scope.lake_digest()
        {
            failures.push(VerificationFailure::LakeMismatch);
        }
        if proposal.evidence.digests.permission_digest != self.registration.permission_digest() {
            failures.push(VerificationFailure::PermissionMismatch);
        }
        if proposal.evidence.digests.provider_digest != *self.registration.provider_digest()
            || proposal.evidence.digests.contract_digest != Digest::from_text(CONTRACT_DIGEST)
            || proposal.evidence.digests.plugin_version_digest != Digest::from_text(PLUGIN_VERSION)
        {
            failures.push(VerificationFailure::EvidenceMismatch);
        }
        if proposal.evidence.digests.evidence_policy_digest != *self.registration.evidence_digest()
        {
            failures.push(VerificationFailure::EvidenceMismatch);
        }
        if !proposal.evidence.complete || !proposal.evidence.pagination.complete {
            failures.push(VerificationFailure::IncompletePagination);
        }
        if !proposal.state.is_complete() || !proposal.evidence.state.is_complete() {
            failures.push(VerificationFailure::NonCompleteState);
        }
        if proposal.native || proposal.evidence.native {
            failures.push(VerificationFailure::NativeClaim);
        }
        if proposal.connected || proposal.evidence.connected {
            failures.push(VerificationFailure::ConnectedClaim);
        }
        if proposal.provider_receipt || proposal.evidence.provider_receipt {
            failures.push(VerificationFailure::ProviderReceiptClaim);
        }
        if matches!(proposal.state, EvidenceState::RetentionGap) {
            failures.push(VerificationFailure::RetentionGap);
        }
        VerificationReport {
            valid: failures.is_empty(),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.digest().clone(),
            failures,
        }
    }

    fn build_failure(
        &self,
        operation: AwsSecurityLakeOperation,
        filter_digest: Digest,
        pages: u16,
        cursors: Vec<Digest>,
        page_digests: Vec<Digest>,
        state: EvidenceState,
    ) -> Result<AwsSecurityLakeProposal> {
        self.build_proposal(
            operation,
            state,
            false,
            filter_digest,
            pages,
            cursors,
            page_digests,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Some(Digest::from_text(format!("{state:?}"))),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build_proposal(
        &self,
        operation: AwsSecurityLakeOperation,
        state: EvidenceState,
        complete: bool,
        filter_digest: Digest,
        pages: u16,
        cursors: Vec<Digest>,
        page_digests: Vec<Digest>,
        lakes: Vec<DataLakeProjection>,
        log_sources: Vec<LogSourceProjection>,
        data_lake_sources: Vec<DataLakeSourceProjection>,
        exceptions: Vec<DataLakeExceptionProjection>,
        provider_error_digest: Option<Digest>,
    ) -> Result<AwsSecurityLakeProposal> {
        let retention = self.scope.retention_fence(self.observed_at)?;
        let pagination = PaginationEvidence::new(
            operation,
            filter_digest,
            pages,
            complete,
            cursors,
            page_digests,
        );
        let evidence = AwsSecurityLakeEvidence::new(
            operation,
            state,
            &self.scope,
            self.provider.definition(),
            self.registration.permission_snapshot(),
            &self.consent,
            self.provider.provenance(),
            retention,
            pagination,
            lakes,
            log_sources,
            data_lake_sources,
            exceptions,
            provider_error_digest,
        );
        Ok(AwsSecurityLakeProposal::new(&self.registration, evidence))
    }
}

fn state_for_transport(error: &AwsSecurityLakeTransportError) -> EvidenceState {
    match error {
        AwsSecurityLakeTransportError::AccessDenied
        | AwsSecurityLakeTransportError::Unauthorized
        | AwsSecurityLakeTransportError::NotFound => EvidenceState::AccessLoss,
        AwsSecurityLakeTransportError::InvalidToken => EvidenceState::Expired,
        AwsSecurityLakeTransportError::Throttled => EvidenceState::Throttled,
        AwsSecurityLakeTransportError::RetentionExpired => EvidenceState::RetentionGap,
        AwsSecurityLakeTransportError::InvalidResponse => EvidenceState::Tampered,
        AwsSecurityLakeTransportError::ServiceUnavailable
        | AwsSecurityLakeTransportError::Timeout
        | AwsSecurityLakeTransportError::BadRequest
        | AwsSecurityLakeTransportError::ResponseTooLarge
        | AwsSecurityLakeTransportError::EnvironmentBlocked
        | AwsSecurityLakeTransportError::QueueExhausted => EvidenceState::ProviderUnknown,
    }
}

pub type AwsSecurityLakeRegistrationReceipt = AwsSecurityLakeRegistration;

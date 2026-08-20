//! Typed service, proposal, local recording, integrity verification, and
//! reversible registration for the Spanner Layer-1 result seam.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::error::{GcpSpannerError, GcpSpannerTransportError, Result};
use crate::model::{
    DatabaseMetadata, Digest, EvidenceDigests, GcpSpannerDatabaseScope, PermissionSnapshot,
    SecretReference, SpannerDatabaseState, TransportProvenance, validate_page_size,
};
use crate::provider::{
    GcpSpannerAdminProvider, GcpSpannerOperation, GcpSpannerProviderDefinition,
    GcpSpannerTransport, GetDatabaseRequest, GetInstanceRequest, GetOperationRequest,
    ListDatabasesRequest,
};
use crate::{
    API_REVISION, CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_VERSION, EVIDENCE_LEVEL,
    LAYER1_PERMISSIONS, MAX_PAGE_SIZE, MAX_PAGES, MAX_REQUESTS_PER_READ, PLUGIN_VERSION,
    PROVIDER_ID, SERVICE_ID, contract_digest,
};

pub type GcpSpannerDatabaseResultServiceError = GcpSpannerError;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GcpSpannerRegistrationStatus {
    Active,
    Revoked,
    Reversed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationTransitionEvidence {
    pub previous_status: GcpSpannerRegistrationStatus,
    pub new_status: GcpSpannerRegistrationStatus,
    pub registration_digest: Digest,
    pub transition_digest: Digest,
}

impl RegistrationTransitionEvidence {
    fn new(
        previous_status: GcpSpannerRegistrationStatus,
        new_status: GcpSpannerRegistrationStatus,
        registration_digest: Digest,
    ) -> Self {
        let transition_digest = Digest::from_parts(
            "gcp-spanner-registration-transition/v1",
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

/// Version/contract/provider/permission/scope/secret-bound registration.
/// The secret handle itself is retained only as an opaque non-serializing
/// reference and is represented outside serialization by its digest.
#[derive(Clone, Eq, PartialEq)]
pub struct GcpSpannerDatabaseResultRegistration {
    id: String,
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_revision: u64,
    provider_release: String,
    provider_api_revision: String,
    provider_digest: Digest,
    permission_snapshot: PermissionSnapshot,
    scope: GcpSpannerDatabaseScope,
    scope_digest: Digest,
    secret_reference: SecretReference,
    registration_revision: u64,
    status: GcpSpannerRegistrationStatus,
    registration_digest: Digest,
}

impl GcpSpannerDatabaseResultRegistration {
    pub fn new(
        id: impl Into<String>,
        scope: GcpSpannerDatabaseScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        provider: &GcpSpannerProviderDefinition,
        registration_revision: u64,
    ) -> Result<Self> {
        let mut registration = Self {
            id: id.into(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: provider.provider_id.clone(),
            provider_revision: provider.provider_revision,
            provider_release: provider.release.clone(),
            provider_api_revision: provider.api_revision.clone(),
            provider_digest: provider.provider_digest.clone(),
            permission_snapshot,
            scope_digest: scope.digest(),
            scope,
            secret_reference,
            registration_revision,
            status: GcpSpannerRegistrationStatus::Active,
            registration_digest: Digest::from_text("unsealed-gcp-spanner-registration"),
        };
        registration.registration_digest = registration.calculate_digest();
        registration.validate()?;
        Ok(registration)
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }

    #[must_use]
    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    #[must_use]
    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    #[must_use]
    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    #[must_use]
    pub const fn provider_revision(&self) -> u64 {
        self.provider_revision
    }

    #[must_use]
    pub fn provider_release(&self) -> &str {
        &self.provider_release
    }

    #[must_use]
    pub fn provider_api_revision(&self) -> &str {
        &self.provider_api_revision
    }

    #[must_use]
    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    #[must_use]
    pub fn permission_snapshot(&self) -> &PermissionSnapshot {
        &self.permission_snapshot
    }

    #[must_use]
    pub fn permission_digest(&self) -> Digest {
        self.permission_snapshot.digest()
    }

    #[must_use]
    pub fn scope(&self) -> &GcpSpannerDatabaseScope {
        &self.scope
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn secret_reference_digest(&self) -> &Digest {
        self.secret_reference.reference_digest()
    }

    #[must_use]
    pub const fn registration_revision(&self) -> u64 {
        self.registration_revision
    }

    #[must_use]
    pub const fn status(&self) -> GcpSpannerRegistrationStatus {
        self.status
    }

    #[must_use]
    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.status, GcpSpannerRegistrationStatus::Active)
    }

    pub fn validate(&self) -> Result<()> {
        let expected_permissions = LAYER1_PERMISSIONS
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<BTreeSet<_>>();
        let actual_permissions = self
            .permission_snapshot
            .permissions()
            .iter()
            .map(|value| value.as_str().to_owned())
            .collect::<BTreeSet<_>>();
        if self.id.is_empty()
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.contract_digest != contract_digest()
            || self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.provider_release != PLUGIN_VERSION
            || self.provider_api_revision != API_REVISION
            || self.registration_revision == 0
            || self.scope_digest != self.scope.digest()
            || self.registration_digest != self.calculate_digest()
            || actual_permissions != expected_permissions
        {
            return Err(GcpSpannerError::InvalidRegistration);
        }
        self.scope.validate()?;
        self.permission_snapshot.validate()?;
        self.secret_reference.validate(&self.scope)?;
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, GcpSpannerRegistrationStatus::Reversed) {
            return Err(GcpSpannerError::RegistrationRevoked);
        }
        let previous_status = self.status;
        self.status = GcpSpannerRegistrationStatus::Revoked;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, GcpSpannerRegistrationStatus::Reversed) {
            return Err(GcpSpannerError::RegistrationRevoked);
        }
        let previous_status = self.status;
        self.status = GcpSpannerRegistrationStatus::Reversed;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, GcpSpannerRegistrationStatus::Reversed) {
            return Err(GcpSpannerError::RegistrationRevoked);
        }
        let previous_status = self.status;
        self.status = GcpSpannerRegistrationStatus::Active;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-spanner-registration/v1",
            &[
                ("id", Digest::from_text(&self.id).as_str().to_owned()),
                ("plugin", self.plugin_version.clone()),
                ("contract_version", self.contract_version.clone()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider_id", self.provider_id.clone()),
                ("provider_revision", self.provider_revision.to_string()),
                ("provider_release", self.provider_release.clone()),
                ("provider_api", self.provider_api_revision.clone()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("permission", self.permission_digest().as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("secret", self.secret_reference_digest().as_str().to_owned()),
                ("revision", self.registration_revision.to_string()),
                ("status", format!("{:?}", self.status)),
            ],
        )
    }
}

pub type GcpSpannerRegistration = GcpSpannerDatabaseResultRegistration;

impl fmt::Debug for GcpSpannerDatabaseResultRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpSpannerDatabaseResultRegistration")
            .field("id_digest", &Digest::from_text(&self.id))
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_id", &self.provider_id)
            .field("provider_revision", &self.provider_revision)
            .field("provider_api_revision", &self.provider_api_revision)
            .field("provider_digest", &self.provider_digest)
            .field("permission_digest", &self.permission_digest())
            .field("scope_digest", &self.scope_digest)
            .field("secret_reference_digest", &self.secret_reference_digest())
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("registration_digest", &self.registration_digest)
            .finish()
    }
}

impl Serialize for GcpSpannerDatabaseResultRegistration {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("GcpSpannerDatabaseResultRegistration", 15)?;
        state.serialize_field("idDigest", &Digest::from_text(&self.id))?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("providerRelease", &self.provider_release)?;
        state.serialize_field("providerApiRevision", &self.provider_api_revision)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest())?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("secretReferenceDigest", &self.secret_reference_digest())?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityDescription {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub evidence_level: String,
    pub operations: Vec<String>,
    pub permissions: Vec<String>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adoption: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpSpannerDatabaseEvidenceRequest {
    pub scope_digest: Digest,
    pub expected_provider_digest: Digest,
    pub expected_registration_digest: Digest,
    pub page_size: u16,
    pub max_pages: u16,
    pub resolve_via_list: bool,
    pub observed_at: DateTime<Utc>,
    pub request_digest: Digest,
}

impl GcpSpannerDatabaseEvidenceRequest {
    pub fn new(
        scope: &GcpSpannerDatabaseScope,
        provider: &GcpSpannerProviderDefinition,
        registration: &GcpSpannerDatabaseResultRegistration,
        page_size: u16,
        max_pages: u16,
        resolve_via_list: bool,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        validate_page_size(page_size)?;
        if max_pages == 0 || max_pages > MAX_PAGES {
            return Err(GcpSpannerError::PaginationExceeded);
        }
        let request_digest = Digest::from_parts(
            "gcp-spanner-evidence-request/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("provider", provider.provider_digest.as_str().to_owned()),
                (
                    "registration",
                    registration.registration_digest().as_str().to_owned(),
                ),
                ("page_size", page_size.to_string()),
                ("max_pages", max_pages.to_string()),
                ("resolve_via_list", resolve_via_list.to_string()),
                ("observed_at", observed_at.to_rfc3339()),
            ],
        );
        Ok(Self {
            scope_digest: scope.digest(),
            expected_provider_digest: provider.provider_digest.clone(),
            expected_registration_digest: registration.registration_digest().clone(),
            page_size,
            max_pages,
            resolve_via_list,
            observed_at,
            request_digest,
        })
    }

    pub fn validate_against<T: GcpSpannerTransport>(
        &self,
        service: &GcpSpannerDatabaseResultService<T>,
    ) -> Result<()> {
        if self.scope_digest != service.scope.digest()
            || self.expected_provider_digest != service.provider.definition().provider_digest
            || self.expected_registration_digest != *service.registration.registration_digest()
            || self.max_pages == 0
            || self.max_pages > MAX_PAGES
            || self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
        {
            return Err(GcpSpannerError::ScopeDrift);
        }
        let rebuilt = Self::new(
            &service.scope,
            service.provider.definition(),
            &service.registration,
            self.page_size,
            self.max_pages,
            self.resolve_via_list,
            self.observed_at,
        )?;
        if rebuilt.request_digest != self.request_digest {
            return Err(GcpSpannerError::EvidenceTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GcpSpannerDatabaseEvidenceState {
    Creating,
    Ready,
    Updating,
    Restoring,
    BackingUp,
    Failed,
    Partial,
    AccessLost,
    ProviderUnknown,
    Tampered,
    Revoked,
}

pub type GcpSpannerResultState = GcpSpannerDatabaseEvidenceState;
pub type DatabasePostureState = GcpSpannerDatabaseEvidenceState;
pub type GcpSpannerEvidenceState = GcpSpannerDatabaseEvidenceState;
pub type GcpSpannerDatabaseResultRequest = GcpSpannerDatabaseEvidenceRequest;
pub type GcpSpannerResultProposal = GcpSpannerDatabaseResultProposal;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    RateLimited,
    Server,
    Timeout,
    Malformed,
    ProviderUnknown,
    Transport,
    Tampered,
    Partial,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureEvidence {
    pub operation: String,
    pub kind: FailureKind,
    pub status_code: Option<u16>,
    pub request_digest: Digest,
    pub response_digest: Option<Digest>,
    pub failure_digest: Digest,
}

impl FailureEvidence {
    fn from_transport(
        operation: GcpSpannerOperation,
        request_digest: Digest,
        error: &GcpSpannerTransportError,
    ) -> Self {
        let kind = match error {
            GcpSpannerTransportError::HttpStatus { status_code, .. } => match status_code {
                401 => FailureKind::Unauthorized,
                403 => FailureKind::Forbidden,
                404 => FailureKind::NotFound,
                409 => FailureKind::Conflict,
                429 => FailureKind::RateLimited,
                500..=599 => FailureKind::Server,
                _ => FailureKind::ProviderUnknown,
            },
            GcpSpannerTransportError::Timeout { .. } => FailureKind::Timeout,
            GcpSpannerTransportError::MalformedResponse { .. } => FailureKind::Malformed,
            GcpSpannerTransportError::ProviderUnknown { .. }
            | GcpSpannerTransportError::Unsupported { .. } => FailureKind::ProviderUnknown,
            GcpSpannerTransportError::Transport { .. } => FailureKind::Transport,
        };
        let response_digest = error.response_digest().cloned();
        let failure_digest = Digest::from_parts(
            "gcp-spanner-failure/v1",
            &[
                ("operation", operation.as_str().to_owned()),
                ("kind", format!("{kind:?}")),
                ("request", request_digest.as_str().to_owned()),
                (
                    "response",
                    response_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "status",
                    error
                        .status_code()
                        .map_or_else(String::new, |value| value.to_string()),
                ),
            ],
        );
        Self {
            operation: operation.as_str().to_owned(),
            kind,
            status_code: error.status_code(),
            request_digest,
            response_digest,
            failure_digest,
        }
    }

    fn tampered(operation: GcpSpannerOperation, request_digest: Digest) -> Self {
        Self {
            operation: operation.as_str().to_owned(),
            kind: FailureKind::Tampered,
            status_code: None,
            request_digest: request_digest.clone(),
            response_digest: None,
            failure_digest: Digest::from_parts(
                "gcp-spanner-tampered-failure/v1",
                &[
                    ("operation", operation.as_str().to_owned()),
                    ("request", request_digest.as_str().to_owned()),
                ],
            ),
        }
    }

    fn partial(request_digest: Digest) -> Self {
        Self {
            operation: GcpSpannerOperation::ListDatabases.as_str().to_owned(),
            kind: FailureKind::Partial,
            status_code: None,
            request_digest: request_digest.clone(),
            response_digest: None,
            failure_digest: Digest::from_parts(
                "gcp-spanner-partial-failure/v1",
                &[("request", request_digest.as_str().to_owned())],
            ),
        }
    }

    fn validate_integrity(&self) -> Result<()> {
        let expected = match self.kind {
            FailureKind::Tampered => Digest::from_parts(
                "gcp-spanner-tampered-failure/v1",
                &[
                    ("operation", self.operation.clone()),
                    ("request", self.request_digest.as_str().to_owned()),
                ],
            ),
            FailureKind::Partial => Digest::from_parts(
                "gcp-spanner-partial-failure/v1",
                &[("request", self.request_digest.as_str().to_owned())],
            ),
            _ => Digest::from_parts(
                "gcp-spanner-failure/v1",
                &[
                    ("operation", self.operation.clone()),
                    ("kind", format!("{:?}", self.kind)),
                    ("request", self.request_digest.as_str().to_owned()),
                    (
                        "response",
                        self.response_digest
                            .as_ref()
                            .map_or_else(String::new, |value| value.as_str().to_owned()),
                    ),
                    (
                        "status",
                        self.status_code
                            .map_or_else(String::new, |value| value.to_string()),
                    ),
                ],
            ),
        };
        if expected == self.failure_digest {
            Ok(())
        } else {
            Err(GcpSpannerError::EvidenceTampered)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpSpannerDatabaseResultEvidence {
    pub scope_digest: Digest,
    pub instance: Option<crate::model::InstanceMetadata>,
    pub database: Option<DatabaseMetadata>,
    pub operation: Option<crate::model::OperationMetadata>,
    pub state: GcpSpannerDatabaseEvidenceState,
    pub pages: u16,
    pub complete: bool,
    pub truncated: bool,
    pub list_digest: Option<Digest>,
    pub request_digests: Vec<Digest>,
    pub response_digests: Vec<Digest>,
    pub failure: Option<FailureEvidence>,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub evidence_digests: EvidenceDigests,
    pub evidence_digest: Digest,
}

impl GcpSpannerDatabaseResultEvidence {
    #[must_use]
    pub fn is_review_only(&self) -> bool {
        !self.connected && !self.native && !self.first_party && !self.provider_receipt
    }

    #[must_use]
    pub fn can_be_adopted(&self) -> bool {
        false
    }

    #[must_use]
    pub fn is_non_adoptable_state(&self) -> bool {
        matches!(
            self.state,
            GcpSpannerDatabaseEvidenceState::Partial
                | GcpSpannerDatabaseEvidenceState::AccessLost
                | GcpSpannerDatabaseEvidenceState::ProviderUnknown
                | GcpSpannerDatabaseEvidenceState::Tampered
                | GcpSpannerDatabaseEvidenceState::Revoked
                | GcpSpannerDatabaseEvidenceState::Failed
        )
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
            || self.provenance.provider_receipt()
            || self.evidence_digests.evidence_digest != self.evidence_digests.calculate()
            || self.evidence_digest != self.evidence_digests.evidence_digest
        {
            return Err(GcpSpannerError::EvidenceTampered);
        }
        if self.request_digests.is_empty()
            || self.request_digests.len() > MAX_REQUESTS_PER_READ as usize
            || self.pages == 0
            || self.pages > MAX_PAGES
        {
            return Err(GcpSpannerError::EvidenceTampered);
        }
        if self.scope_digest.as_str().len() != 64
            || self.evidence_digests.plugin_version_digest != Digest::from_text(PLUGIN_VERSION)
            || self.evidence_digests.contract_version_digest != Digest::from_text(CONTRACT_VERSION)
            || self.evidence_digests.contract_digest != contract_digest()
            || self.evidence_digests.api_digest != Digest::from_text(API_REVISION)
            || self.evidence_digests.scope_digest != self.scope_digest
            || self.evidence_digests.instance_digest
                != self.instance.as_ref().map(|value| value.digest().clone())
            || self.evidence_digests.database_digest
                != self.database.as_ref().map(|value| value.digest().clone())
            || self.evidence_digests.operation_digest
                != self.operation.as_ref().map(|value| value.digest().clone())
        {
            return Err(GcpSpannerError::EvidenceTampered);
        }
        if let Some(instance) = &self.instance {
            instance
                .validate_integrity()
                .map_err(|_| GcpSpannerError::EvidenceTampered)?;
        }
        if let Some(database) = &self.database {
            database
                .validate_integrity()
                .map_err(|_| GcpSpannerError::EvidenceTampered)?;
        }
        if let Some(operation) = &self.operation {
            operation
                .validate_integrity()
                .map_err(|_| GcpSpannerError::EvidenceTampered)?;
        }
        if let Some(failure) = &self.failure {
            failure.validate_integrity()?;
        }
        let expected_request_digest = request_digest_for(&self.request_digests);
        let expected_response_digest = response_digest_for(
            self.state,
            self.complete,
            self.truncated,
            self.list_digest.as_ref(),
            &self.response_digests,
            self.failure.as_ref(),
        );
        if self.evidence_digests.request_digest != expected_request_digest
            || self.evidence_digests.response_digest != expected_response_digest
            || self.evidence_digests.evidence_digest != self.evidence_digests.calculate()
        {
            return Err(GcpSpannerError::EvidenceTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpSpannerDatabaseResultProposal {
    pub evidence: GcpSpannerDatabaseResultEvidence,
    pub state: GcpSpannerDatabaseEvidenceState,
    pub proposal_digest: Digest,
    pub idempotency_key_digest: Digest,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub adopts_outcome: bool,
    pub adopts_work_product: bool,
}

impl GcpSpannerDatabaseResultProposal {
    #[must_use]
    pub fn is_review_only(&self) -> bool {
        self.proposal_only
            && !self.connected
            && !self.native
            && !self.first_party
            && !self.provider_receipt
            && !self.adopts_outcome
            && !self.adopts_work_product
    }

    #[must_use]
    pub fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpSpannerRecordedResult {
    pub proposal_digest: Digest,
    pub idempotency_key_digest: Digest,
    pub evidence: GcpSpannerDatabaseResultEvidence,
    pub recording_digest: Digest,
    pub replayed: bool,
    pub local_recording: bool,
    pub provider_receipt: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

pub type GcpSpannerRecordReceipt = GcpSpannerRecordedResult;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpSpannerIntegrityReport {
    pub valid: bool,
    pub review_eligible: bool,
    pub proposal_digest: Digest,
    pub failures: Vec<String>,
}

pub struct GcpSpannerDatabaseResultService<T: GcpSpannerTransport> {
    pub(crate) scope: GcpSpannerDatabaseScope,
    pub(crate) provider: GcpSpannerAdminProvider<T>,
    pub(crate) registration: GcpSpannerDatabaseResultRegistration,
    records: BTreeMap<Digest, GcpSpannerRecordedResult>,
}

pub type GcpSpannerService<T> = GcpSpannerDatabaseResultService<T>;

impl<T: GcpSpannerTransport> fmt::Debug for GcpSpannerDatabaseResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpSpannerDatabaseResultService")
            .field("scope_digest", &self.scope.digest())
            .field(
                "provider_digest",
                &self.provider.definition().provider_digest,
            )
            .field("registration", &self.registration)
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl<T: GcpSpannerTransport> GcpSpannerDatabaseResultService<T> {
    pub fn new(
        scope: GcpSpannerDatabaseScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        provider: GcpSpannerAdminProvider<T>,
        _created_at: DateTime<Utc>,
    ) -> Result<Self> {
        Self::new_with_revision(scope, secret_reference, permission_snapshot, provider, 1)
    }

    pub fn new_with_revision(
        scope: GcpSpannerDatabaseScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        provider: GcpSpannerAdminProvider<T>,
        registration_revision: u64,
    ) -> Result<Self> {
        crate::GcpSpannerDatabaseResultContract::baseline()?;
        scope.validate()?;
        permission_snapshot.validate()?;
        provider.definition().validate()?;
        secret_reference.validate(&scope)?;
        let registration = GcpSpannerDatabaseResultRegistration::new(
            "gcp-spanner-database-result-registration",
            scope.clone(),
            secret_reference,
            permission_snapshot,
            provider.definition(),
            registration_revision,
        )?;
        Ok(Self {
            scope,
            provider,
            registration,
            records: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn scope(&self) -> &GcpSpannerDatabaseScope {
        &self.scope
    }

    #[must_use]
    pub fn provider(&self) -> &GcpSpannerAdminProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut GcpSpannerAdminProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn registration(&self) -> &GcpSpannerDatabaseResultRegistration {
        &self.registration
    }

    #[must_use]
    pub fn registration_mut(&mut self) -> &mut GcpSpannerDatabaseResultRegistration {
        &mut self.registration
    }

    #[must_use]
    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            evidence_level: EVIDENCE_LEVEL.to_owned(),
            operations: vec![
                GcpSpannerOperation::GetInstance.as_str().to_owned(),
                GcpSpannerOperation::GetDatabase.as_str().to_owned(),
                GcpSpannerOperation::GetOperation.as_str().to_owned(),
                GcpSpannerOperation::ListInstances.as_str().to_owned(),
                GcpSpannerOperation::ListDatabases.as_str().to_owned(),
            ],
            permissions: LAYER1_PERMISSIONS
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            read_only: true,
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adoption: false,
        }
    }

    pub fn default_request(
        &self,
        observed_at: DateTime<Utc>,
    ) -> Result<GcpSpannerDatabaseEvidenceRequest> {
        GcpSpannerDatabaseEvidenceRequest::new(
            &self.scope,
            self.provider.definition(),
            &self.registration,
            MAX_PAGE_SIZE,
            MAX_PAGES,
            false,
            observed_at,
        )
    }

    pub fn request_with_list_resolution(
        &self,
        observed_at: DateTime<Utc>,
        page_size: u16,
        max_pages: u16,
    ) -> Result<GcpSpannerDatabaseEvidenceRequest> {
        GcpSpannerDatabaseEvidenceRequest::new(
            &self.scope,
            self.provider.definition(),
            &self.registration,
            page_size,
            max_pages,
            true,
            observed_at,
        )
    }

    pub fn read(
        &mut self,
        request: GcpSpannerDatabaseEvidenceRequest,
    ) -> Result<GcpSpannerDatabaseResultEvidence> {
        self.ensure_registration()?;
        request.validate_against(self)?;
        let instance_request = GetInstanceRequest::for_scope(&self.scope)?;
        let database_request = GetDatabaseRequest::for_scope(&self.scope)?;
        let mut request_digests = vec![
            request.request_digest.clone(),
            instance_request.request_digest().clone(),
            database_request.request_digest().clone(),
        ];
        let mut response_digests = Vec::new();
        let mut pages = 1;
        let mut list_digest = None;
        let mut truncated = false;
        let mut failure = None;
        let mut list_match = !request.resolve_via_list;

        if request.resolve_via_list {
            let mut token = None;
            let mut seen_tokens = BTreeSet::new();
            let mut list_complete = false;
            for page in 1..=request.max_pages {
                let list_request =
                    ListDatabasesRequest::new(&self.scope, request.page_size, token)?;
                request_digests.push(list_request.request_digest().clone());
                match self.provider.list_databases(&list_request) {
                    Ok(response) => {
                        if let Err(error) = response.validate_integrity(&list_request) {
                            failure = Some(FailureEvidence::tampered(
                                GcpSpannerOperation::ListDatabases,
                                list_request.request_digest().clone(),
                            ));
                            let _ = error;
                            break;
                        }
                        response_digests.push(response.evidence_digest.clone());
                        list_match |= response.databases.iter().any(|item| {
                            item.database == *self.scope.database()
                                && item.instance == *self.scope.instance()
                                && item.dialect == self.scope.dialect()
                        });
                        list_digest = Some(Digest::from_parts(
                            "gcp-spanner-database-list-pages/v1",
                            &[
                                (
                                    "previous",
                                    list_digest
                                        .as_ref()
                                        .map_or_else(String::new, |value: &Digest| {
                                            value.as_str().to_owned()
                                        }),
                                ),
                                ("page", page.to_string()),
                                ("response", response.evidence_digest.as_str().to_owned()),
                            ],
                        ));
                        if let Some(next) = response.next_page_token {
                            if !seen_tokens.insert(next.token_digest().clone()) {
                                failure = Some(FailureEvidence::tampered(
                                    GcpSpannerOperation::ListDatabases,
                                    list_request.request_digest().clone(),
                                ));
                                break;
                            }
                            token = Some(next);
                            pages = page.saturating_add(1);
                        } else {
                            list_complete = true;
                            pages = page;
                            break;
                        }
                    }
                    Err(error) => {
                        failure = Some(FailureEvidence::from_transport(
                            GcpSpannerOperation::ListDatabases,
                            list_request.request_digest().clone(),
                            &error,
                        ));
                        break;
                    }
                }
            }
            if failure.is_none() && !list_complete {
                truncated = true;
                failure = Some(FailureEvidence::partial(request.request_digest.clone()));
            }
            if !list_match && failure.is_none() {
                truncated = true;
                failure = Some(FailureEvidence::partial(request.request_digest.clone()));
            }
        }

        let instance = if failure.is_some() && !list_match {
            None
        } else {
            match self.provider.get_instance(&instance_request) {
                Ok(response) => {
                    if response.validate_integrity(&instance_request).is_err() {
                        failure = Some(FailureEvidence::tampered(
                            GcpSpannerOperation::GetInstance,
                            instance_request.request_digest().clone(),
                        ));
                        None
                    } else {
                        response_digests.push(response.evidence_digest.clone());
                        Some(response.metadata)
                    }
                }
                Err(error) => {
                    failure = Some(FailureEvidence::from_transport(
                        GcpSpannerOperation::GetInstance,
                        instance_request.request_digest().clone(),
                        &error,
                    ));
                    None
                }
            }
        };

        let database = if instance.is_some()
            && failure
                .as_ref()
                .is_none_or(|value| !matches!(value.kind, FailureKind::Tampered))
        {
            match self.provider.get_database(&database_request) {
                Ok(response) => {
                    if response.validate_integrity(&database_request).is_err() {
                        failure = Some(FailureEvidence::tampered(
                            GcpSpannerOperation::GetDatabase,
                            database_request.request_digest().clone(),
                        ));
                        None
                    } else {
                        response_digests.push(response.evidence_digest.clone());
                        Some(response.metadata)
                    }
                }
                Err(error) => {
                    failure = Some(FailureEvidence::from_transport(
                        GcpSpannerOperation::GetDatabase,
                        database_request.request_digest().clone(),
                        &error,
                    ));
                    None
                }
            }
        } else {
            None
        };

        let operation = if database.is_some() {
            if self.scope.operation().is_some() {
                let operation_request = GetOperationRequest::for_scope(&self.scope)?;
                request_digests.push(operation_request.request_digest().clone());
                match self.provider.get_operation(&operation_request) {
                    Ok(response) => {
                        if response.validate_integrity(&operation_request).is_err() {
                            failure = Some(FailureEvidence::tampered(
                                GcpSpannerOperation::GetOperation,
                                operation_request.request_digest().clone(),
                            ));
                            None
                        } else {
                            response_digests.push(response.evidence_digest.clone());
                            Some(response.metadata)
                        }
                    }
                    Err(error) => {
                        failure = Some(FailureEvidence::from_transport(
                            GcpSpannerOperation::GetOperation,
                            operation_request.request_digest().clone(),
                            &error,
                        ));
                        None
                    }
                }
            } else {
                None
            }
        } else {
            None
        };

        let state = state_for(
            database.as_ref().map(|value| value.state),
            failure.as_ref(),
            self.registration.status(),
        );
        let complete = failure.is_none()
            && list_match
            && instance.is_some()
            && database.is_some()
            && (self.scope.operation().is_none() || operation.is_some());
        Ok(self.finish_evidence(
            request,
            instance,
            database,
            operation,
            state,
            pages,
            complete,
            truncated,
            list_digest,
            request_digests,
            response_digests,
            failure,
        ))
    }

    pub fn propose(
        &mut self,
        request: GcpSpannerDatabaseEvidenceRequest,
    ) -> Result<GcpSpannerDatabaseResultProposal> {
        let evidence = self.read(request)?;
        let idempotency_key_digest = Digest::from_parts(
            "gcp-spanner-proposal-idempotency/v1",
            &[
                ("scope", evidence.scope_digest.as_str().to_owned()),
                (
                    "request",
                    evidence.evidence_digests.request_digest.as_str().to_owned(),
                ),
            ],
        );
        let proposal_digest = Digest::from_parts(
            "gcp-spanner-proposal/v1",
            &[
                ("evidence", evidence.evidence_digest.as_str().to_owned()),
                ("idempotency", idempotency_key_digest.as_str().to_owned()),
            ],
        );
        Ok(GcpSpannerDatabaseResultProposal {
            state: evidence.state,
            evidence,
            proposal_digest,
            idempotency_key_digest,
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            adopts_outcome: false,
            adopts_work_product: false,
        })
    }

    pub fn verify(&self, proposal: &GcpSpannerDatabaseResultProposal) -> GcpSpannerIntegrityReport {
        let mut failures = Vec::new();
        if self.ensure_registration().is_err() {
            failures.push("registration drift or inactivity".to_owned());
        }
        if proposal.evidence.validate_integrity().is_err() {
            failures.push("evidence digest or provenance mismatch".to_owned());
        }
        if proposal.evidence.scope_digest != self.scope.digest()
            || proposal.evidence.evidence_digests.provider_digest
                != self.provider.definition().provider_digest
            || proposal.evidence.evidence_digests.registration_digest
                != *self.registration.registration_digest()
        {
            failures.push("scope/provider/registration binding mismatch".to_owned());
        }
        let expected_idempotency = Digest::from_parts(
            "gcp-spanner-proposal-idempotency/v1",
            &[
                ("scope", proposal.evidence.scope_digest.as_str().to_owned()),
                (
                    "request",
                    proposal
                        .evidence
                        .evidence_digests
                        .request_digest
                        .as_str()
                        .to_owned(),
                ),
            ],
        );
        let expected_proposal = Digest::from_parts(
            "gcp-spanner-proposal/v1",
            &[
                (
                    "evidence",
                    proposal.evidence.evidence_digest.as_str().to_owned(),
                ),
                ("idempotency", expected_idempotency.as_str().to_owned()),
            ],
        );
        if expected_idempotency != proposal.idempotency_key_digest
            || expected_proposal != proposal.proposal_digest
            || proposal.state != proposal.evidence.state
            || !proposal.is_review_only()
        {
            failures.push("proposal digest or authority boundary mismatch".to_owned());
        }
        GcpSpannerIntegrityReport {
            valid: failures.is_empty(),
            review_eligible: failures.is_empty() && !proposal.evidence.is_non_adoptable_state(),
            proposal_digest: proposal.proposal_digest.clone(),
            failures,
        }
    }

    pub fn verify_proposal(
        &self,
        proposal: &GcpSpannerDatabaseResultProposal,
    ) -> Result<GcpSpannerIntegrityReport> {
        let report = self.verify(proposal);
        if report.valid {
            Ok(report)
        } else {
            Err(GcpSpannerError::InvalidProposal)
        }
    }

    pub fn record(
        &mut self,
        proposal: &GcpSpannerDatabaseResultProposal,
    ) -> Result<GcpSpannerRecordedResult> {
        self.verify_proposal(proposal)?;
        self.ensure_registration()?;
        if let Some(existing) = self.records.get(&proposal.idempotency_key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(GcpSpannerError::ReplayConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.recording_digest = recording_digest(&replay);
            return Ok(replay);
        }
        let mut recorded = GcpSpannerRecordedResult {
            proposal_digest: proposal.proposal_digest.clone(),
            idempotency_key_digest: proposal.idempotency_key_digest.clone(),
            evidence: proposal.evidence.clone(),
            recording_digest: Digest::from_text("unsealed-gcp-spanner-recording"),
            replayed: false,
            local_recording: true,
            provider_receipt: false,
            connected: false,
            native: false,
            first_party: false,
        };
        recorded.recording_digest = recording_digest(&recorded);
        self.records
            .insert(recorded.idempotency_key_digest.clone(), recorded.clone());
        Ok(recorded)
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.revoke()
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.reverse()
    }

    pub fn restore_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.restore()
    }

    fn ensure_registration(&self) -> Result<()> {
        self.registration.validate()?;
        self.provider.definition().validate()?;
        if self.registration.provider_digest() != &self.provider.definition().provider_digest
            || self.registration.provider_api_revision() != API_REVISION
            || self.registration.scope_digest() != &self.scope.digest()
            || !self.registration.is_active()
        {
            if !self.registration.is_active() {
                Err(GcpSpannerError::RegistrationInactive)
            } else {
                Err(GcpSpannerError::ProviderDrift)
            }
        } else {
            Ok(())
        }
    }

    fn finish_evidence(
        &self,
        _request: GcpSpannerDatabaseEvidenceRequest,
        instance: Option<crate::model::InstanceMetadata>,
        database: Option<DatabaseMetadata>,
        operation: Option<crate::model::OperationMetadata>,
        state: GcpSpannerDatabaseEvidenceState,
        pages: u16,
        complete: bool,
        truncated: bool,
        list_digest: Option<Digest>,
        request_digests: Vec<Digest>,
        response_digests: Vec<Digest>,
        failure: Option<FailureEvidence>,
    ) -> GcpSpannerDatabaseResultEvidence {
        let request_digest = request_digest_for(&request_digests);
        let response_digest = response_digest_for(
            state,
            complete,
            truncated,
            list_digest.as_ref(),
            &response_digests,
            failure.as_ref(),
        );
        let mut evidence_digests = EvidenceDigests {
            plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_version_digest: Digest::from_text(CONTRACT_VERSION),
            contract_digest: contract_digest(),
            provider_digest: self.provider.definition().provider_digest.clone(),
            api_digest: Digest::from_text(API_REVISION),
            permission_digest: self.registration.permission_digest(),
            scope_digest: self.scope.digest(),
            registration_digest: self.registration.registration_digest().clone(),
            instance_digest: instance.as_ref().map(|value| value.digest().clone()),
            database_digest: database.as_ref().map(|value| value.digest().clone()),
            operation_digest: operation.as_ref().map(|value| value.digest().clone()),
            request_digest,
            response_digest,
            evidence_digest: Digest::from_text("unsealed-gcp-spanner-evidence"),
        };
        evidence_digests.evidence_digest = evidence_digests.calculate();
        GcpSpannerDatabaseResultEvidence {
            scope_digest: self.scope.digest(),
            instance,
            database,
            operation,
            state,
            pages: pages.max(1),
            complete,
            truncated,
            list_digest,
            request_digests,
            response_digests,
            failure,
            provenance: self.provider.provenance(),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            evidence_digest: evidence_digests.evidence_digest.clone(),
            evidence_digests,
        }
    }
}

fn state_for(
    database_state: Option<SpannerDatabaseState>,
    failure: Option<&FailureEvidence>,
    registration_status: GcpSpannerRegistrationStatus,
) -> GcpSpannerDatabaseEvidenceState {
    if !matches!(registration_status, GcpSpannerRegistrationStatus::Active) {
        return GcpSpannerDatabaseEvidenceState::Revoked;
    }
    if let Some(failure) = failure {
        return match failure.kind {
            FailureKind::Unauthorized | FailureKind::Forbidden | FailureKind::NotFound => {
                GcpSpannerDatabaseEvidenceState::AccessLost
            }
            FailureKind::Tampered => GcpSpannerDatabaseEvidenceState::Tampered,
            FailureKind::Partial => GcpSpannerDatabaseEvidenceState::Partial,
            FailureKind::Conflict => GcpSpannerDatabaseEvidenceState::Partial,
            FailureKind::RateLimited
            | FailureKind::Server
            | FailureKind::Timeout
            | FailureKind::Malformed
            | FailureKind::ProviderUnknown
            | FailureKind::Transport
            | FailureKind::Revoked => GcpSpannerDatabaseEvidenceState::ProviderUnknown,
        };
    }
    match database_state {
        Some(SpannerDatabaseState::Creating) => GcpSpannerDatabaseEvidenceState::Creating,
        Some(SpannerDatabaseState::Ready) => GcpSpannerDatabaseEvidenceState::Ready,
        Some(SpannerDatabaseState::Updating) => GcpSpannerDatabaseEvidenceState::Updating,
        Some(SpannerDatabaseState::Restoring) => GcpSpannerDatabaseEvidenceState::Restoring,
        Some(SpannerDatabaseState::BackingUp) => GcpSpannerDatabaseEvidenceState::BackingUp,
        Some(SpannerDatabaseState::Failed) => GcpSpannerDatabaseEvidenceState::Failed,
        None => GcpSpannerDatabaseEvidenceState::ProviderUnknown,
    }
}

fn recording_digest(recorded: &GcpSpannerRecordedResult) -> Digest {
    Digest::from_parts(
        "gcp-spanner-local-recording/v1",
        &[
            ("proposal", recorded.proposal_digest.as_str().to_owned()),
            (
                "idempotency",
                recorded.idempotency_key_digest.as_str().to_owned(),
            ),
            (
                "evidence",
                recorded.evidence.evidence_digest.as_str().to_owned(),
            ),
            ("replayed", recorded.replayed.to_string()),
            ("local", recorded.local_recording.to_string()),
        ],
    )
}

fn request_digest_for(request_digests: &[Digest]) -> Digest {
    Digest::from_parts(
        "gcp-spanner-read-requests/v1",
        &[
            (
                "request",
                request_digests
                    .first()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
            ),
            (
                "calls",
                request_digests
                    .iter()
                    .map(Digest::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
            ),
        ],
    )
}

fn response_digest_for(
    state: GcpSpannerDatabaseEvidenceState,
    complete: bool,
    truncated: bool,
    list_digest: Option<&Digest>,
    response_digests: &[Digest],
    failure: Option<&FailureEvidence>,
) -> Digest {
    Digest::from_parts(
        "gcp-spanner-read-responses/v1",
        &[
            (
                "responses",
                response_digests
                    .iter()
                    .map(Digest::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            ("state", format!("{state:?}")),
            ("complete", complete.to_string()),
            ("truncated", truncated.to_string()),
            (
                "list",
                list_digest.map_or_else(String::new, |value| value.as_str().to_owned()),
            ),
            (
                "failure",
                failure.map_or_else(String::new, |value| {
                    value.failure_digest.as_str().to_owned()
                }),
            ),
        ],
    )
}

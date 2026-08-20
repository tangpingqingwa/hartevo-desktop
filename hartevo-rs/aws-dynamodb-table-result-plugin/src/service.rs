//! Typed service, proposal, recording, verification, and reversible
//! registration seams for bounded DynamoDB table posture.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::consumer::MissionAwsDynamoDbConsumer;
use crate::error::{AwsDynamoDbTableError, AwsDynamoDbTransportError, Result};
use crate::model::{
    AwsDynamoDbEvidenceState, AwsDynamoDbTableScope, BackupPosture, ConsentBinding, Digest,
    EventualConsistencyFence, EvidenceState, OpaquePageToken, PermissionSnapshot, ReadBounds,
    SecretReference, TablePosture, TableSummary, TagKeyPosture, TransportProvenance, TtlPosture,
};
use crate::provider::{
    AwsDynamoDbOperation, AwsDynamoDbProvider, AwsDynamoDbProviderDefinition,
    DescribeContinuousBackupsRequest, DescribeTableRequest, DescribeTimeToLiveRequest,
    ListTablesRequest, ListTagsOfResourceRequest,
};
use crate::{
    CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_VERSION, PLUGIN_VERSION, PROVIDER_API_REVISION,
    PROVIDER_ID, SERVICE_ID, contract_digest,
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
            "aws-dynamodb-registration-transition/v1",
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

/// Version/contract/provider/table/scope/permission/evidence-bound
/// registration. The secret handle itself is never retained or serialized.
#[derive(Clone, Eq, PartialEq)]
pub struct AwsDynamoDbTableRegistration {
    id: String,
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_revision: u64,
    provider_release: String,
    provider_digest: Digest,
    table_digest: Digest,
    permission_snapshot: PermissionSnapshot,
    consent: ConsentBinding,
    scope: AwsDynamoDbTableScope,
    scope_digest: Digest,
    secret_reference: SecretReference,
    evidence_fence_digest: Digest,
    registration_revision: u64,
    status: RegistrationStatus,
    registration_digest: Digest,
}

impl AwsDynamoDbTableRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        scope: AwsDynamoDbTableScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentBinding,
        provider: &AwsDynamoDbProviderDefinition,
        registration_revision: u64,
    ) -> Result<Self> {
        let id = id.into();
        if id.is_empty() || id.len() > crate::MAX_IDENTIFIER_BYTES || registration_revision == 0 {
            return Err(AwsDynamoDbTableError::InvalidRegistration);
        }
        provider.validate()?;
        let scope_digest = scope.digest();
        let evidence_fence_digest =
            calculate_evidence_fence_digest(&scope, &permission_snapshot, &consent, provider);
        let mut registration = Self {
            id,
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: Digest::parse(CONTRACT_DIGEST.to_owned())?,
            provider_id: provider.provider_id.clone(),
            provider_revision: provider.provider_revision,
            provider_release: provider.release.clone(),
            provider_digest: provider.provider_digest.clone(),
            table_digest: scope.table_digest(),
            permission_snapshot,
            consent,
            scope,
            scope_digest,
            secret_reference,
            evidence_fence_digest,
            registration_revision,
            status: RegistrationStatus::Active,
            registration_digest: Digest::zero(),
        };
        registration.registration_digest = registration.calculate_digest();
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

    pub fn table_digest(&self) -> &Digest {
        &self.table_digest
    }

    pub fn permission_snapshot(&self) -> &PermissionSnapshot {
        &self.permission_snapshot
    }

    pub fn permission_digest(&self) -> Digest {
        self.permission_snapshot.digest()
    }

    pub fn consent(&self) -> &ConsentBinding {
        &self.consent
    }

    pub fn consent_digest(&self) -> Digest {
        self.consent.digest()
    }

    pub fn scope(&self) -> &AwsDynamoDbTableScope {
        &self.scope
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn secret_reference_digest(&self) -> &Digest {
        self.secret_reference.reference_digest()
    }

    pub fn evidence_fence_digest(&self) -> &Digest {
        &self.evidence_fence_digest
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
        if self.id.is_empty()
            || self.id.len() > crate::MAX_IDENTIFIER_BYTES
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.contract_digest != contract_digest()
            || self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.provider_release.is_empty()
            || self.registration_revision == 0
            || self.table_digest != self.scope.table_digest()
            || self.scope_digest != self.scope.digest()
            || self.registration_digest != self.calculate_digest()
        {
            return Err(AwsDynamoDbTableError::InvalidRegistration);
        }
        let expected_provider = AwsDynamoDbProviderDefinition::new(
            self.provider_revision,
            self.provider_release.clone(),
        )?;
        if self.provider_id != expected_provider.provider_id
            || self.provider_digest != expected_provider.provider_digest
            || self.provider_revision != expected_provider.provider_revision
        {
            return Err(AwsDynamoDbTableError::ProviderDrift);
        }
        self.scope.validate()?;
        self.permission_snapshot.validate()?;
        self.consent
            .validate_against(&self.permission_snapshot)
            .map_err(|_| AwsDynamoDbTableError::ConsentMismatch)?;
        self.secret_reference
            .validate(&self.scope)
            .map_err(|_| AwsDynamoDbTableError::InvalidSecretReference)?;
        self.provider_digest.validate()?;
        let expected_fence = calculate_evidence_fence_digest(
            &self.scope,
            &self.permission_snapshot,
            &self.consent,
            &AwsDynamoDbProviderDefinition {
                provider_id: self.provider_id.clone(),
                provider_revision: self.provider_revision,
                api_revision: PROVIDER_API_REVISION.to_owned(),
                contract_version: CONTRACT_VERSION.to_owned(),
                release: self.provider_release.clone(),
                capability_digest: Digest::zero(),
                provider_digest: self.provider_digest.clone(),
                connected: false,
                native: false,
                first_party: false,
            },
        );
        if expected_fence != self.evidence_fence_digest {
            return Err(AwsDynamoDbTableError::InvalidRegistration);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsDynamoDbTableError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Revoked;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsDynamoDbTableError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Reversed;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsDynamoDbTableError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Active;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-dynamodb-table-registration/v1",
            &[
                ("id", Digest::from_text(&self.id).as_str().to_owned()),
                ("plugin", self.plugin_version.clone()),
                ("contract_version", self.contract_version.clone()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider_id", self.provider_id.clone()),
                ("provider_revision", self.provider_revision.to_string()),
                ("provider_release", self.provider_release.clone()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("table", self.table_digest.as_str().to_owned()),
                ("permission", self.permission_digest().as_str().to_owned()),
                ("consent", self.consent_digest().as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("secret", self.secret_reference_digest().as_str().to_owned()),
                (
                    "evidence_fence",
                    self.evidence_fence_digest.as_str().to_owned(),
                ),
                ("revision", self.registration_revision.to_string()),
                ("status", format!("{:?}", self.status)),
            ],
        )
    }
}

impl fmt::Debug for AwsDynamoDbTableRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsDynamoDbTableRegistration")
            .field("id_digest", &Digest::from_text(&self.id))
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_id", &self.provider_id)
            .field("provider_revision", &self.provider_revision)
            .field("provider_digest", &self.provider_digest)
            .field("table_digest", &self.table_digest)
            .field("permission_digest", &self.permission_digest())
            .field("consent_digest", &self.consent_digest())
            .field("scope_digest", &self.scope_digest)
            .field("secret_reference_digest", &self.secret_reference_digest())
            .field("evidence_fence_digest", &self.evidence_fence_digest)
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("registration_digest", &self.registration_digest)
            .finish_non_exhaustive()
    }
}

impl Serialize for AwsDynamoDbTableRegistration {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsDynamoDbTableRegistration", 17)?;
        state.serialize_field("idDigest", &Digest::from_text(&self.id))?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("providerRelease", &self.provider_release)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("tableDigest", &self.table_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest())?;
        state.serialize_field("consentDigest", &self.consent_digest())?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("secretReferenceDigest", &self.secret_reference_digest())?;
        state.serialize_field("evidenceFenceDigest", &self.evidence_fence_digest)?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
        state.end()
    }
}

pub type AwsDynamoDbRegistration = AwsDynamoDbTableRegistration;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsDynamoDbTableCapabilities {
    pub service_id: &'static str,
    pub provider_id: &'static str,
    pub consumer_id: &'static str,
    pub operations: Vec<AwsDynamoDbOperation>,
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

impl AwsDynamoDbTableCapabilities {
    fn layer1() -> Self {
        Self {
            service_id: SERVICE_ID,
            provider_id: PROVIDER_ID,
            consumer_id: CONSUMER_ID,
            operations: AwsDynamoDbOperation::ALL.to_vec(),
            permissions: crate::LAYER1_PERMISSIONS
                .iter()
                .map(ToString::to_string)
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
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureEvidence {
    pub operation: AwsDynamoDbOperation,
    pub status_code: Option<u16>,
    pub category: String,
    pub failure_digest: Digest,
}

impl FailureEvidence {
    fn from_transport(operation: AwsDynamoDbOperation, error: &AwsDynamoDbTransportError) -> Self {
        let category = match error {
            AwsDynamoDbTransportError::BadRequest => "bad_request",
            AwsDynamoDbTransportError::Unauthorized => "unauthorized",
            AwsDynamoDbTransportError::Forbidden => "forbidden",
            AwsDynamoDbTransportError::NotFound => "not_found",
            AwsDynamoDbTransportError::RateLimited { .. } => "throttled",
            AwsDynamoDbTransportError::ServerError { .. } => "server_error",
            AwsDynamoDbTransportError::Timeout => "timeout",
            AwsDynamoDbTransportError::Partial => "partial",
            AwsDynamoDbTransportError::AccessLost => "access_loss",
            AwsDynamoDbTransportError::BlockedEnv => "blocked_env",
            AwsDynamoDbTransportError::Conflict => "conflict",
            AwsDynamoDbTransportError::InvalidResponse => "invalid_response",
        };
        Self {
            operation,
            status_code: error.status_code(),
            category: category.to_owned(),
            failure_digest: Digest::from_parts(
                "aws-dynamodb-failure/v1",
                &[
                    ("operation", format!("{operation:?}")),
                    ("category", category.to_owned()),
                    (
                        "status",
                        error
                            .status_code()
                            .map_or_else(String::new, |status| status.to_string()),
                    ),
                ],
            ),
        }
    }

    fn from_category(operation: AwsDynamoDbOperation, category: &'static str) -> Self {
        Self {
            operation,
            status_code: None,
            category: category.to_owned(),
            failure_digest: Digest::from_parts(
                "aws-dynamodb-failure/v1",
                &[
                    ("operation", format!("{operation:?}")),
                    ("category", category.to_owned()),
                ],
            ),
        }
    }

    fn validate(&self) -> Result<()> {
        self.failure_digest.validate()?;
        let expected = Digest::from_parts(
            "aws-dynamodb-failure/v1",
            &[
                ("operation", format!("{:?}", self.operation)),
                ("category", self.category.clone()),
                (
                    "status",
                    self.status_code
                        .map_or_else(String::new, |status| status.to_string()),
                ),
            ],
        );
        if expected != self.failure_digest {
            return Err(AwsDynamoDbTableError::TamperedEvidence);
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
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub scope_digest: Digest,
    pub table_digest: Digest,
    pub allowlist_digest: Digest,
    pub fence_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub list_digest: Option<Digest>,
    pub describe_table_digest: Option<Digest>,
    pub backup_digest: Option<Digest>,
    pub ttl_digest: Option<Digest>,
    pub tags_digest: Option<Digest>,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaginationEvidence {
    pub pages_observed: u16,
    pub complete: bool,
    pub cursor_digest: Option<Digest>,
    pub page_digests: Vec<Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactionSummary {
    pub identifiers_digest_only: bool,
    pub raw_items_dropped: bool,
    pub raw_key_values_dropped: bool,
    pub raw_tags_dropped: bool,
    pub raw_policies_dropped: bool,
    pub account_pii_dropped: bool,
    pub secret_material_dropped: bool,
}

impl Default for RedactionSummary {
    fn default() -> Self {
        Self {
            identifiers_digest_only: true,
            raw_items_dropped: true,
            raw_key_values_dropped: true,
            raw_tags_dropped: true,
            raw_policies_dropped: true,
            account_pii_dropped: true,
            secret_material_dropped: true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsDynamoDbTableReadRequest {
    scope: AwsDynamoDbTableScope,
    bounds: ReadBounds,
    fence: EventualConsistencyFence,
    observed_at: DateTime<Utc>,
    request_digest: Digest,
}

impl AwsDynamoDbTableReadRequest {
    pub fn new(
        scope: AwsDynamoDbTableScope,
        bounds: ReadBounds,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        scope.validate()?;
        bounds.validate()?;
        let fence = EventualConsistencyFence::new(&scope, observed_at);
        let request_digest = Digest::from_parts(
            "aws-dynamodb-table-read-request/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                (
                    "bounds",
                    serde_json::to_string(&bounds).expect("read bounds serialize"),
                ),
                ("fence", fence.digest().as_str().to_owned()),
                ("observed_at", observed_at.to_rfc3339()),
            ],
        );
        Ok(Self {
            scope,
            bounds,
            fence,
            observed_at,
            request_digest,
        })
    }

    pub fn for_scope(scope: &AwsDynamoDbTableScope, observed_at: DateTime<Utc>) -> Result<Self> {
        Self::new(scope.clone(), ReadBounds::layer1(), observed_at)
    }

    pub fn scope(&self) -> &AwsDynamoDbTableScope {
        &self.scope
    }

    pub const fn bounds(&self) -> ReadBounds {
        self.bounds
    }

    pub fn fence(&self) -> &EventualConsistencyFence {
        &self.fence
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        self.bounds.validate()?;
        self.fence.validate(&self.scope)?;
        let expected = Digest::from_parts(
            "aws-dynamodb-table-read-request/v1",
            &[
                ("scope", self.scope.digest().as_str().to_owned()),
                (
                    "bounds",
                    serde_json::to_string(&self.bounds).expect("read bounds serialize"),
                ),
                ("fence", self.fence.digest().as_str().to_owned()),
                ("observed_at", self.observed_at.to_rfc3339()),
            ],
        );
        if expected != self.request_digest {
            return Err(AwsDynamoDbTableError::TamperedEvidence);
        }
        Ok(())
    }
}

pub type AwsDynamoDbReadRequest = AwsDynamoDbTableReadRequest;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsDynamoDbTableEvidence {
    pub service_id: &'static str,
    pub provider_id: String,
    pub scope_digest: Digest,
    pub table_digest: Digest,
    pub allowlist_digest: Digest,
    pub registration_digest: Digest,
    pub state: AwsDynamoDbEvidenceState,
    pub pagination: PaginationEvidence,
    pub table: Option<TablePosture>,
    pub backup: Option<BackupPosture>,
    pub ttl: Option<TtlPosture>,
    pub tags: Option<TagKeyPosture>,
    pub failure: Option<FailureEvidence>,
    pub redaction: RedactionSummary,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub digests: EvidenceDigests,
    pub evidence_digest: Digest,
}

impl AwsDynamoDbTableEvidence {
    #[allow(clippy::too_many_arguments)]
    fn new(
        registration: &AwsDynamoDbTableRegistration,
        state: AwsDynamoDbEvidenceState,
        pagination: PaginationEvidence,
        table: Option<TablePosture>,
        backup: Option<BackupPosture>,
        ttl: Option<TtlPosture>,
        tags: Option<TagKeyPosture>,
        failure: Option<FailureEvidence>,
        provenance: TransportProvenance,
        provider_digest: Digest,
        fence_digest: Digest,
    ) -> Self {
        let cursor_digest = pagination.cursor_digest.clone();
        let list_digest = (!pagination.page_digests.is_empty()).then(|| {
            Digest::from_parts(
                "aws-dynamodb-list-pages/v1",
                &[(
                    "pages",
                    pagination
                        .page_digests
                        .iter()
                        .map(|digest| digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join("\n"),
                )],
            )
        });
        let describe_table_digest = table.as_ref().map(|value| value.digest().clone());
        let backup_digest = backup.as_ref().map(|value| value.digest().clone());
        let ttl_digest = ttl.as_ref().map(|value| value.digest().clone());
        let tags_digest = tags.as_ref().map(|value| value.digest().clone());
        let mut evidence = Self {
            service_id: SERVICE_ID,
            provider_id: registration.provider_id.clone(),
            scope_digest: registration.scope_digest.clone(),
            table_digest: registration.table_digest.clone(),
            allowlist_digest: registration.scope.allowlist_digest().clone(),
            registration_digest: registration.registration_digest.clone(),
            state,
            pagination,
            table,
            backup,
            ttl,
            tags,
            failure,
            redaction: RedactionSummary::default(),
            provenance,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            digests: EvidenceDigests {
                plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
                contract_digest: contract_digest(),
                provider_digest,
                permission_digest: registration.permission_digest(),
                consent_digest: registration.consent_digest(),
                scope_digest: registration.scope_digest.clone(),
                table_digest: registration.table_digest.clone(),
                allowlist_digest: registration.scope.allowlist_digest().clone(),
                fence_digest,
                cursor_digest,
                list_digest,
                describe_table_digest,
                backup_digest,
                ttl_digest,
                tags_digest,
                evidence_digest: Digest::zero(),
            },
            evidence_digest: Digest::zero(),
        };
        let digest = evidence.calculate_evidence_digest();
        evidence.digests.evidence_digest = digest.clone();
        evidence.evidence_digest = digest;
        evidence
    }

    pub fn digest(&self) -> &Digest {
        &self.evidence_digest
    }

    pub fn is_review_only(&self) -> bool {
        true
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.service_id != SERVICE_ID
            || self.provider_id != PROVIDER_ID
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.evidence_digest != self.digests.evidence_digest
            || self.evidence_digest != self.calculate_evidence_digest()
            || self.digests.plugin_version_digest != Digest::from_text(PLUGIN_VERSION)
            || self.digests.contract_digest != contract_digest()
            || self.digests.scope_digest != self.scope_digest
            || self.digests.table_digest != self.table_digest
            || self.digests.allowlist_digest != self.allowlist_digest
        {
            return Err(AwsDynamoDbTableError::TamperedEvidence);
        }
        self.digests.provider_digest.validate()?;
        self.digests.contract_digest.validate()?;
        self.digests.permission_digest.validate()?;
        self.digests.consent_digest.validate()?;
        self.digests.scope_digest.validate()?;
        self.digests.table_digest.validate()?;
        self.digests.allowlist_digest.validate()?;
        self.digests.fence_digest.validate()?;
        self.digests
            .cursor_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.digests
            .list_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        for digest in [
            &self.digests.describe_table_digest,
            &self.digests.backup_digest,
            &self.digests.ttl_digest,
            &self.digests.tags_digest,
        ] {
            digest.as_ref().map(Digest::validate).transpose()?;
        }
        if self.pagination.page_digests.len() != usize::from(self.pagination.pages_observed)
            || self.pagination.pages_observed > crate::MAX_PAGES
            || self
                .pagination
                .page_digests
                .windows(2)
                .any(|pair| pair[0] == pair[1])
        {
            return Err(AwsDynamoDbTableError::TamperedEvidence);
        }
        if let Some(failure) = &self.failure {
            failure.validate()?;
        }
        if let Some(table) = &self.table {
            table.table_digest.validate()?;
        }
        if let Some(backup) = &self.backup {
            backup.table_digest.validate()?;
        }
        if let Some(ttl) = &self.ttl {
            ttl.table_digest.validate()?;
        }
        if let Some(tags) = &self.tags {
            tags.table_digest.validate()?;
        }
        if self.state == EvidenceState::Completed
            && (!self.pagination.complete
                || self.table.is_none()
                || self.backup.is_none()
                || self.ttl.is_none()
                || self.tags.is_none()
                || self.failure.is_some())
        {
            return Err(AwsDynamoDbTableError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_evidence_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-dynamodb-table-evidence/v1",
            &[
                ("service", self.service_id.to_owned()),
                ("provider", self.provider_id.clone()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("table", self.table_digest.as_str().to_owned()),
                ("allowlist", self.allowlist_digest.as_str().to_owned()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
                (
                    "pagination",
                    serde_json::to_string(&self.pagination).expect("pagination serializes"),
                ),
                (
                    "table_posture",
                    serde_json::to_string(&self.table).expect("table posture serializes"),
                ),
                (
                    "backup_posture",
                    serde_json::to_string(&self.backup).expect("backup posture serializes"),
                ),
                (
                    "ttl_posture",
                    serde_json::to_string(&self.ttl).expect("TTL posture serializes"),
                ),
                (
                    "tags_posture",
                    serde_json::to_string(&self.tags).expect("tag posture serializes"),
                ),
                (
                    "failure",
                    serde_json::to_string(&self.failure).expect("failure serializes"),
                ),
                (
                    "redaction",
                    serde_json::to_string(&self.redaction).expect("redaction serializes"),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
                ("provider_receipt", self.provider_receipt.to_string()),
                (
                    "provider_digest",
                    self.digests.provider_digest.as_str().to_owned(),
                ),
                (
                    "permission",
                    self.digests.permission_digest.as_str().to_owned(),
                ),
                ("consent", self.digests.consent_digest.as_str().to_owned()),
                ("fence", self.digests.fence_digest.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsDynamoDbTableReadResult {
    pub evidence: AwsDynamoDbTableEvidence,
    pub page_digests: Vec<Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsDynamoDbTableProposal {
    pub service_id: &'static str,
    pub consumer_id: &'static str,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub state: AwsDynamoDbEvidenceState,
    pub evidence: AwsDynamoDbTableEvidence,
    pub proposed_at: DateTime<Utc>,
    pub proposal_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub review_only: bool,
}

impl AwsDynamoDbTableProposal {
    fn new(
        registration: &AwsDynamoDbTableRegistration,
        evidence: AwsDynamoDbTableEvidence,
        proposed_at: DateTime<Utc>,
    ) -> Self {
        let state = evidence.state;
        let mut proposal = Self {
            service_id: SERVICE_ID,
            consumer_id: CONSUMER_ID,
            registration_digest: registration.registration_digest.clone(),
            scope_digest: registration.scope_digest.clone(),
            state,
            evidence,
            proposed_at,
            proposal_digest: Digest::zero(),
            connected: false,
            native: false,
            first_party: false,
            review_only: true,
        };
        proposal.proposal_digest = proposal.calculate_digest();
        proposal
    }

    pub fn digest(&self) -> &Digest {
        &self.proposal_digest
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || self.connected
            || self.native
            || self.first_party
            || !self.review_only
            || self.state != self.evidence.state
            || self.registration_digest != self.evidence.registration_digest
            || self.scope_digest != self.evidence.scope_digest
            || self.proposal_digest != self.calculate_digest()
        {
            return Err(AwsDynamoDbTableError::TamperedProposal);
        }
        self.evidence.validate_integrity()
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-dynamodb-table-proposal/v1",
            &[
                ("service", self.service_id.to_owned()),
                ("consumer", self.consumer_id.to_owned()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
                (
                    "evidence",
                    self.evidence.evidence_digest.as_str().to_owned(),
                ),
                ("proposed_at", self.proposed_at.to_rfc3339()),
                ("connected", self.connected.to_string()),
                ("native", self.native.to_string()),
                ("review_only", self.review_only.to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsDynamoDbTableRecord {
    pub recorded: bool,
    pub recorded_at: DateTime<Utc>,
    pub state: AwsDynamoDbEvidenceState,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub provenance: TransportProvenance,
    pub recording_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl AwsDynamoDbTableRecord {
    fn new(proposal: &AwsDynamoDbTableProposal, recorded_at: DateTime<Utc>) -> Self {
        let mut record = Self {
            recorded: true,
            recorded_at,
            state: proposal.state,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            provenance: proposal.evidence.provenance.clone(),
            recording_digest: Digest::zero(),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        record.recording_digest = record.calculate_digest();
        record
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if !self.recorded
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.recording_digest != self.calculate_digest()
        {
            return Err(AwsDynamoDbTableError::TamperedRecord);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-dynamodb-table-record/v1",
            &[
                ("recorded", self.recorded.to_string()),
                ("recorded_at", self.recorded_at.to_rfc3339()),
                ("state", format!("{:?}", self.state)),
                ("proposal", self.proposal_digest.as_str().to_owned()),
                ("evidence", self.evidence_digest.as_str().to_owned()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsDynamoDbTableVerifiedRecord {
    pub verified: bool,
    pub state: AwsDynamoDbEvidenceState,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub record_digest: Digest,
    pub verification_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub adopted_outcome: bool,
    pub adopted_work_product: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub verified: bool,
    pub state: AwsDynamoDbEvidenceState,
    pub evidence_digest: Digest,
    pub verification_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub adopted_outcome: bool,
}

pub struct AwsDynamoDbTableService<T = crate::provider::BlockedEnvTransport> {
    scope: AwsDynamoDbTableScope,
    secret_reference: SecretReference,
    provider: AwsDynamoDbProvider<T>,
    capabilities: AwsDynamoDbTableCapabilities,
    registration: AwsDynamoDbTableRegistration,
}

impl<T: crate::provider::AwsDynamoDbTransport> fmt::Debug for AwsDynamoDbTableService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsDynamoDbTableService")
            .field("scope_digest", &self.scope.digest())
            .field("secret_reference", &self.secret_reference)
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .finish_non_exhaustive()
    }
}

impl<T: crate::provider::AwsDynamoDbTransport> AwsDynamoDbTableService<T> {
    pub fn new(
        scope: AwsDynamoDbTableScope,
        secret_reference: SecretReference,
        provider: AwsDynamoDbProvider<T>,
    ) -> Result<Self> {
        let permissions = PermissionSnapshot::layer1();
        let consent = ConsentBinding::layer1();
        let registration = AwsDynamoDbTableRegistration::new(
            "aws-dynamodb-table-registration",
            scope.clone(),
            secret_reference.clone(),
            permissions,
            consent,
            provider.definition(),
            1,
        )?;
        Ok(Self {
            scope,
            secret_reference,
            provider,
            capabilities: AwsDynamoDbTableCapabilities::layer1(),
            registration,
        })
    }

    pub fn with_registration(
        scope: AwsDynamoDbTableScope,
        secret_reference: SecretReference,
        provider: AwsDynamoDbProvider<T>,
        registration: AwsDynamoDbTableRegistration,
    ) -> Result<Self> {
        scope.validate()?;
        provider.definition().validate()?;
        registration.validate()?;
        if registration.scope_digest() != &scope.digest()
            || registration.secret_reference_digest() != secret_reference.reference_digest()
            || registration.provider_digest() != &provider.definition().provider_digest
        {
            return Err(AwsDynamoDbTableError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            secret_reference,
            provider,
            capabilities: AwsDynamoDbTableCapabilities::layer1(),
            registration,
        })
    }

    pub fn scope(&self) -> &AwsDynamoDbTableScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn provider(&self) -> &AwsDynamoDbProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsDynamoDbProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &AwsDynamoDbTableRegistration {
        &self.registration
    }

    pub fn capabilities(&self) -> &AwsDynamoDbTableCapabilities {
        &self.capabilities
    }

    pub fn describe_capabilities(&self) -> &AwsDynamoDbTableCapabilities {
        self.capabilities()
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

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.revoke_registration()
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.reverse_registration()
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.restore_registration()
    }

    pub fn read(
        &mut self,
        request: AwsDynamoDbTableReadRequest,
    ) -> Result<AwsDynamoDbTableReadResult> {
        self.ensure_active_and_bound()?;
        request.validate()?;
        if request.scope().digest() != self.scope.digest() {
            return Err(AwsDynamoDbTableError::ScopeMismatch);
        }

        let mut cursor = None;
        let mut seen_cursors = BTreeSet::new();
        let mut page_digests = Vec::new();
        let mut page_count = 0_u16;
        let mut list_complete = false;
        let mut target_summary: Option<TableSummary> = None;
        let mut list_failure = None;
        let mut list_state = None;

        loop {
            if page_count >= request.bounds().max_pages {
                list_failure = Some(FailureEvidence::from_category(
                    AwsDynamoDbOperation::ListTables,
                    "page_budget",
                ));
                list_state = Some(EvidenceState::Partial);
                break;
            }
            let list_request =
                ListTablesRequest::new(&self.scope, request.bounds(), cursor.clone())?;
            match self.provider.list_tables(&list_request) {
                Ok(response) => {
                    page_count = page_count.saturating_add(1);
                    page_digests.push(response.response_digest.clone());
                    for summary in &response.tables {
                        summary.validate_against(&self.scope)?;
                        if let Some(existing) = &target_summary {
                            if existing.summary_digest != summary.summary_digest {
                                list_failure = Some(FailureEvidence::from_category(
                                    AwsDynamoDbOperation::ListTables,
                                    "table_replaced",
                                ));
                                list_state = Some(EvidenceState::TableReplaced);
                            }
                        } else {
                            target_summary = Some(summary.clone());
                        }
                    }
                    let Some(next_cursor) = response.next_cursor else {
                        list_complete = true;
                        break;
                    };
                    if !seen_cursors.insert(next_cursor.token_digest().clone()) {
                        return Err(AwsDynamoDbTableError::PaginationLoop);
                    }
                    cursor = Some(next_cursor);
                }
                Err(error) => {
                    list_failure = Some(FailureEvidence::from_transport(
                        AwsDynamoDbOperation::ListTables,
                        &error,
                    ));
                    list_state = Some(state_from_transport(&error));
                    break;
                }
            }
        }

        if let Some(state) = list_state {
            return Ok(self.finish_result(
                state,
                page_count,
                list_complete,
                page_digests,
                cursor,
                None,
                None,
                None,
                None,
                list_failure,
                request.fence().digest().clone(),
            ));
        }

        if !list_complete {
            return Ok(self.finish_result(
                EvidenceState::Partial,
                page_count,
                false,
                page_digests,
                cursor,
                None,
                None,
                None,
                None,
                list_failure.or_else(|| {
                    Some(FailureEvidence::from_category(
                        AwsDynamoDbOperation::ListTables,
                        "partial",
                    ))
                }),
                request.fence().digest().clone(),
            ));
        }

        let Some(summary) = target_summary else {
            return Ok(self.finish_result(
                EvidenceState::NotFound,
                page_count,
                true,
                page_digests,
                None,
                None,
                None,
                None,
                None,
                Some(FailureEvidence::from_category(
                    AwsDynamoDbOperation::ListTables,
                    "not_found",
                )),
                request.fence().digest().clone(),
            ));
        };

        let table_request = DescribeTableRequest::for_scope(&self.scope, request.fence().clone())?;
        let table_response = match self.provider.describe_table(&table_request) {
            Ok(response) => response,
            Err(error) => {
                return Ok(self.finish_result(
                    state_from_transport(&error),
                    page_count,
                    true,
                    page_digests,
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some(FailureEvidence::from_transport(
                        AwsDynamoDbOperation::DescribeTable,
                        &error,
                    )),
                    request.fence().digest().clone(),
                ));
            }
        };
        let table = table_response.table.clone();
        if let Some(state) = table_drift_state(&self.scope, &summary, &table, request.fence()) {
            return Ok(self.finish_result(
                state,
                page_count,
                true,
                page_digests,
                None,
                None,
                None,
                None,
                None,
                Some(FailureEvidence::from_category(
                    AwsDynamoDbOperation::DescribeTable,
                    state_category(state),
                )),
                request.fence().digest().clone(),
            ));
        }

        let backup_request =
            DescribeContinuousBackupsRequest::for_scope(&self.scope, request.fence().clone())?;
        let backup_response = match self.provider.describe_continuous_backups(&backup_request) {
            Ok(response) => response,
            Err(error) => {
                return Ok(self.finish_result(
                    state_from_transport(&error),
                    page_count,
                    true,
                    page_digests,
                    None,
                    Some(table),
                    None,
                    None,
                    None,
                    Some(FailureEvidence::from_transport(
                        AwsDynamoDbOperation::DescribeContinuousBackups,
                        &error,
                    )),
                    request.fence().digest().clone(),
                ));
            }
        };
        if backup_response
            .backup
            .validate_against(&self.scope, request.fence())
            .is_err()
        {
            return Ok(self.finish_result(
                EvidenceState::StaleMetadata,
                page_count,
                true,
                page_digests,
                None,
                Some(table),
                None,
                None,
                None,
                Some(FailureEvidence::from_category(
                    AwsDynamoDbOperation::DescribeContinuousBackups,
                    "stale_metadata",
                )),
                request.fence().digest().clone(),
            ));
        }

        let ttl_request =
            DescribeTimeToLiveRequest::for_scope(&self.scope, request.fence().clone())?;
        let ttl_response = match self.provider.describe_time_to_live(&ttl_request) {
            Ok(response) => response,
            Err(error) => {
                return Ok(self.finish_result(
                    state_from_transport(&error),
                    page_count,
                    true,
                    page_digests,
                    None,
                    Some(table),
                    Some(backup_response.backup),
                    None,
                    None,
                    Some(FailureEvidence::from_transport(
                        AwsDynamoDbOperation::DescribeTimeToLive,
                        &error,
                    )),
                    request.fence().digest().clone(),
                ));
            }
        };
        if ttl_response
            .ttl
            .validate_against(&self.scope, request.fence())
            .is_err()
        {
            return Ok(self.finish_result(
                EvidenceState::StaleMetadata,
                page_count,
                true,
                page_digests,
                None,
                Some(table),
                Some(backup_response.backup),
                None,
                None,
                Some(FailureEvidence::from_category(
                    AwsDynamoDbOperation::DescribeTimeToLive,
                    "stale_metadata",
                )),
                request.fence().digest().clone(),
            ));
        }

        let tags_request =
            ListTagsOfResourceRequest::for_scope(&self.scope, request.fence().clone())?;
        let tags_response = match self.provider.list_tags_of_resource(&tags_request) {
            Ok(response) => response,
            Err(error) => {
                return Ok(self.finish_result(
                    state_from_transport(&error),
                    page_count,
                    true,
                    page_digests,
                    None,
                    Some(table),
                    Some(backup_response.backup),
                    Some(ttl_response.ttl),
                    None,
                    Some(FailureEvidence::from_transport(
                        AwsDynamoDbOperation::ListTagsOfResource,
                        &error,
                    )),
                    request.fence().digest().clone(),
                ));
            }
        };
        if tags_response
            .tags
            .validate_against(&self.scope, request.fence())
            .is_err()
        {
            return Ok(self.finish_result(
                EvidenceState::StaleMetadata,
                page_count,
                true,
                page_digests,
                None,
                Some(table),
                Some(backup_response.backup),
                Some(ttl_response.ttl),
                None,
                Some(FailureEvidence::from_category(
                    AwsDynamoDbOperation::ListTagsOfResource,
                    "stale_metadata",
                )),
                request.fence().digest().clone(),
            ));
        }

        Ok(self.finish_result(
            EvidenceState::Completed,
            page_count,
            true,
            page_digests,
            None,
            Some(table),
            Some(backup_response.backup),
            Some(ttl_response.ttl),
            Some(tags_response.tags),
            None,
            request.fence().digest().clone(),
        ))
    }

    pub fn propose(
        &mut self,
        request: AwsDynamoDbTableReadRequest,
        proposed_at: DateTime<Utc>,
    ) -> Result<AwsDynamoDbTableProposal> {
        let result = self.read(request)?;
        Ok(AwsDynamoDbTableProposal::new(
            &self.registration,
            result.evidence,
            proposed_at,
        ))
    }

    pub fn record(&self, proposal: &AwsDynamoDbTableProposal) -> Result<AwsDynamoDbTableRecord> {
        self.record_at(proposal, Utc::now())
    }

    pub fn record_at(
        &self,
        proposal: &AwsDynamoDbTableProposal,
        recorded_at: DateTime<Utc>,
    ) -> Result<AwsDynamoDbTableRecord> {
        self.ensure_active_and_bound()?;
        self.verify_proposal(proposal)?;
        Ok(AwsDynamoDbTableRecord::new(proposal, recorded_at))
    }

    pub fn verify(
        &self,
        record: &AwsDynamoDbTableRecord,
    ) -> Result<AwsDynamoDbTableVerifiedRecord> {
        self.ensure_active_and_bound()?;
        record.validate_integrity()?;
        if record.registration_digest != *self.registration.registration_digest()
            || record.scope_digest != self.scope.digest()
        {
            return Err(AwsDynamoDbTableError::ScopeMismatch);
        }
        let verification_digest = Digest::from_parts(
            "aws-dynamodb-table-verification/v1",
            &[
                ("record", record.recording_digest.as_str().to_owned()),
                (
                    "registration",
                    self.registration.registration_digest().as_str().to_owned(),
                ),
                ("scope", self.scope.digest().as_str().to_owned()),
            ],
        );
        Ok(AwsDynamoDbTableVerifiedRecord {
            verified: true,
            state: record.state,
            proposal_digest: record.proposal_digest.clone(),
            evidence_digest: record.evidence_digest.clone(),
            record_digest: record.recording_digest.clone(),
            verification_digest,
            connected: false,
            native: false,
            first_party: false,
            adopted_outcome: false,
            adopted_work_product: false,
        })
    }

    pub fn verify_record(
        &self,
        record: &AwsDynamoDbTableRecord,
    ) -> Result<AwsDynamoDbTableVerifiedRecord> {
        self.verify(record)
    }

    pub fn verify_report(&self, record: &AwsDynamoDbTableRecord) -> Result<VerificationReport> {
        let verified = self.verify(record)?;
        Ok(VerificationReport {
            verified: verified.verified,
            state: verified.state,
            evidence_digest: verified.evidence_digest,
            verification_digest: verified.verification_digest,
            connected: false,
            native: false,
            adopted_outcome: false,
        })
    }

    pub fn verify_proposal(&self, proposal: &AwsDynamoDbTableProposal) -> Result<()> {
        self.ensure_active_and_bound()?;
        proposal.validate_integrity()?;
        if proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.evidence.registration_digest != *self.registration.registration_digest()
            || proposal.evidence.scope_digest != self.scope.digest()
            || proposal.evidence.digests.provider_digest
                != self.provider.definition().provider_digest
            || proposal.evidence.digests.contract_digest != contract_digest()
            || proposal.evidence.digests.permission_digest != self.registration.permission_digest()
            || proposal.evidence.digests.consent_digest != self.registration.consent_digest()
        {
            return Err(AwsDynamoDbTableError::TamperedProposal);
        }
        Ok(())
    }

    pub fn consumer(&self) -> Result<MissionAwsDynamoDbConsumer> {
        MissionAwsDynamoDbConsumer::new(self.scope.clone(), self.registration.clone())
    }

    fn finish_result(
        &self,
        state: AwsDynamoDbEvidenceState,
        pages_observed: u16,
        complete: bool,
        page_digests: Vec<Digest>,
        cursor: Option<OpaquePageToken>,
        table: Option<TablePosture>,
        backup: Option<BackupPosture>,
        ttl: Option<TtlPosture>,
        tags: Option<TagKeyPosture>,
        failure: Option<FailureEvidence>,
        fence_digest: Digest,
    ) -> AwsDynamoDbTableReadResult {
        let cursor_digest = cursor.as_ref().map(|value| value.token_digest().clone());
        let pagination = PaginationEvidence {
            pages_observed,
            complete,
            cursor_digest,
            page_digests: page_digests.clone(),
        };
        let evidence = AwsDynamoDbTableEvidence::new(
            &self.registration,
            state,
            pagination,
            table,
            backup,
            ttl,
            tags,
            failure,
            self.provider.provenance(),
            self.provider.definition().provider_digest.clone(),
            fence_digest,
        );
        AwsDynamoDbTableReadResult {
            evidence,
            page_digests,
        }
    }

    fn ensure_active_and_bound(&self) -> Result<()> {
        if !self.registration.is_active() {
            return Err(
                if self.registration.status() == RegistrationStatus::Reversed {
                    AwsDynamoDbTableError::RegistrationReversed
                } else {
                    AwsDynamoDbTableError::RegistrationRevoked
                },
            );
        }
        self.registration.validate()?;
        self.provider.definition().validate()?;
        self.secret_reference
            .validate(&self.scope)
            .map_err(|_| AwsDynamoDbTableError::InvalidSecretReference)
    }
}

fn calculate_evidence_fence_digest(
    scope: &AwsDynamoDbTableScope,
    permissions: &PermissionSnapshot,
    consent: &ConsentBinding,
    provider: &AwsDynamoDbProviderDefinition,
) -> Digest {
    Digest::from_parts(
        "aws-dynamodb-evidence-fence/v1",
        &[
            ("plugin", PLUGIN_VERSION.to_owned()),
            ("contract", contract_digest().as_str().to_owned()),
            ("provider_id", provider.provider_id.clone()),
            ("provider_revision", provider.provider_revision.to_string()),
            ("provider", provider.provider_digest.as_str().to_owned()),
            ("table", scope.table_digest().as_str().to_owned()),
            ("scope", scope.digest().as_str().to_owned()),
            ("permission", permissions.digest().as_str().to_owned()),
            ("consent", consent.digest().as_str().to_owned()),
        ],
    )
}

fn state_from_transport(error: &AwsDynamoDbTransportError) -> EvidenceState {
    match error {
        AwsDynamoDbTransportError::Unauthorized
        | AwsDynamoDbTransportError::Forbidden
        | AwsDynamoDbTransportError::AccessLost => EvidenceState::AccessLoss,
        AwsDynamoDbTransportError::NotFound => EvidenceState::NotFound,
        AwsDynamoDbTransportError::RateLimited { .. } => EvidenceState::Throttled,
        AwsDynamoDbTransportError::Partial => EvidenceState::Partial,
        AwsDynamoDbTransportError::BadRequest
        | AwsDynamoDbTransportError::ServerError { .. }
        | AwsDynamoDbTransportError::Timeout
        | AwsDynamoDbTransportError::BlockedEnv
        | AwsDynamoDbTransportError::Conflict
        | AwsDynamoDbTransportError::InvalidResponse => EvidenceState::ProviderUnknown,
    }
}

fn state_category(state: EvidenceState) -> &'static str {
    match state {
        EvidenceState::Completed => "completed",
        EvidenceState::Partial => "partial",
        EvidenceState::NotFound => "not_found",
        EvidenceState::AccessLoss => "access_loss",
        EvidenceState::Throttled => "throttled",
        EvidenceState::ProviderUnknown => "provider_unknown",
        EvidenceState::TableReplaced => "table_replaced",
        EvidenceState::SchemaDrift => "schema_drift",
        EvidenceState::IndexDrift => "index_drift",
        EvidenceState::StaleMetadata => "stale_metadata",
        EvidenceState::RegistrationRevoked => "registration_revoked",
    }
}

fn table_drift_state(
    scope: &AwsDynamoDbTableScope,
    summary: &TableSummary,
    table: &TablePosture,
    fence: &EventualConsistencyFence,
) -> Option<EvidenceState> {
    if table.table_digest != scope.table_digest()
        || table.revision != scope.table_revision()
        || table.table_id_digest != summary.table_id_digest
    {
        return Some(EvidenceState::TableReplaced);
    }
    if table.observed_at < fence.observed_at_floor {
        return Some(EvidenceState::StaleMetadata);
    }
    if table.schema_digest() != &summary.schema_digest {
        return Some(EvidenceState::SchemaDrift);
    }
    if table.index_digest().ok().as_ref() != Some(&summary.index_digest)
        || table.replica_digest().ok().as_ref() != Some(&summary.replica_digest)
    {
        return Some(EvidenceState::IndexDrift);
    }
    if table.validate_against(scope).is_err() {
        return Some(EvidenceState::StaleMetadata);
    }
    None
}

pub type AwsDynamoDbService<T> = AwsDynamoDbTableService<T>;
pub type AwsDynamoDbProposal = AwsDynamoDbTableProposal;
pub type AwsDynamoDbRecordReceipt = AwsDynamoDbTableRecord;
pub type AwsDynamoDbVerifiedRecord = AwsDynamoDbTableVerifiedRecord;

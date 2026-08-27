//! Typed Kinesis service, bounded result proposal, verification, and
//! reversible registration.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::consumer::MissionAwsKinesisConsumer;
use crate::error::{AwsKinesisStreamResultError, AwsKinesisTransportError, Result};
use crate::model::{
    AwsKinesisStreamScope, ConsentScope, Cursor, Digest, EvidenceDigests, KinesisEvidenceState,
    PermissionSnapshot, ProjectProjection, StreamProjection, StreamSummary, TransportProvenance,
    WorkProductProjection, mission_projection, project_projection, shards_digest,
    work_product_projection,
};
use crate::provider::{
    AwsKinesisOperation, AwsKinesisProvider, AwsKinesisProviderDefinition,
    DescribeStreamConsumerRequest, DescribeStreamSummaryRequest, ListShardsRequest,
};
use crate::{
    CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_VERSION, PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID,
    contract_digest,
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
            "aws-kinesis-registration-transition/v1",
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

/// Version/contract/provider/permission/consent/scope/secret-bound
/// registration. The opaque secret handle itself is never retained.
#[derive(Clone, Eq, PartialEq)]
pub struct AwsKinesisStreamResultRegistration {
    id: String,
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_revision: u64,
    provider_release: String,
    provider_digest: Digest,
    api_digest: Digest,
    permission_snapshot: PermissionSnapshot,
    consent: ConsentScope,
    scope: AwsKinesisStreamScope,
    scope_digest: Digest,
    secret_reference: crate::model::SecretReference,
    registration_revision: u64,
    status: RegistrationStatus,
    binding_digest: Digest,
}

impl AwsKinesisStreamResultRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        scope: AwsKinesisStreamScope,
        secret_reference: crate::model::SecretReference,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        provider: &AwsKinesisProviderDefinition,
        registration_revision: u64,
    ) -> Result<Self> {
        let mut registration = Self {
            id: id.into(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: Digest::parse(CONTRACT_DIGEST.to_owned())?,
            provider_id: provider.provider_id.clone(),
            provider_revision: provider.provider_revision,
            provider_release: provider.release.clone(),
            provider_digest: provider.provider_digest.clone(),
            api_digest: provider.api_digest.clone(),
            permission_snapshot,
            consent,
            scope_digest: scope.digest(),
            scope,
            secret_reference,
            registration_revision,
            status: RegistrationStatus::Active,
            binding_digest: Digest::from_text("unsealed-kinesis-registration"),
        };
        registration.binding_digest = registration.calculate_binding_digest();
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
    pub fn api_digest(&self) -> &Digest {
        &self.api_digest
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
    pub fn scope(&self) -> &AwsKinesisStreamScope {
        &self.scope
    }
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }
    pub fn secret_reference(&self) -> &crate::model::SecretReference {
        &self.secret_reference
    }
    pub fn secret_reference_mut(&mut self) -> &mut crate::model::SecretReference {
        &mut self.secret_reference
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
        &self.binding_digest
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
            || self.api_digest != Digest::from_text(crate::PROVIDER_API_REVISION)
            || self.registration_revision == 0
            || self.scope_digest != self.scope.digest()
            || self.binding_digest != self.calculate_binding_digest()
        {
            return Err(AwsKinesisStreamResultError::InvalidRegistration);
        }
        self.permission_snapshot.validate()?;
        self.scope.validate()?;
        self.secret_reference.validate(&self.scope)?;
        if self
            .permission_snapshot
            .permissions
            .iter()
            .any(|permission| !self.consent.permissions().contains(permission))
        {
            return Err(AwsKinesisStreamResultError::InvalidConsent);
        }
        self.consent.validate()
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsKinesisStreamResultError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Revoked;
        self.binding_digest = self.calculate_binding_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.binding_digest.clone(),
        ))
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsKinesisStreamResultError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Reversed;
        self.binding_digest = self.calculate_binding_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.binding_digest.clone(),
        ))
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsKinesisStreamResultError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Active;
        self.binding_digest = self.calculate_binding_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.binding_digest.clone(),
        ))
    }

    fn calculate_binding_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-kinesis-registration/v1",
            &[
                ("id", self.id.clone()),
                ("plugin_version", self.plugin_version.clone()),
                ("contract_version", self.contract_version.clone()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider_id", self.provider_id.clone()),
                ("provider_revision", self.provider_revision.to_string()),
                ("provider_release", self.provider_release.clone()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("api", self.api_digest.as_str().to_owned()),
                ("permission", self.permission_digest().as_str().to_owned()),
                ("consent", self.consent_digest().as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("secret", self.secret_reference_digest().as_str().to_owned()),
                ("revision", self.registration_revision.to_string()),
                ("status", format!("{:?}", self.status)),
            ],
        )
    }
}

pub type AwsKinesisRegistration = AwsKinesisStreamResultRegistration;

impl fmt::Debug for AwsKinesisStreamResultRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsKinesisStreamResultRegistration")
            .field("id_digest", &Digest::from_text(&self.id))
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_id", &self.provider_id)
            .field("provider_revision", &self.provider_revision)
            .field("provider_digest", &self.provider_digest)
            .field("api_digest", &self.api_digest)
            .field("permission_digest", &self.permission_digest())
            .field("consent_digest", &self.consent_digest())
            .field("scope_digest", &self.scope_digest)
            .field("secret_reference_digest", &self.secret_reference_digest())
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("registration_digest", &self.binding_digest)
            .finish()
    }
}

impl Serialize for AwsKinesisStreamResultRegistration {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsKinesisStreamResultRegistration", 17)?;
        state.serialize_field("idDigest", &Digest::from_text(&self.id))?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("providerRelease", &self.provider_release)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("apiDigest", &self.api_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest())?;
        state.serialize_field("consentDigest", &self.consent_digest())?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("secretReferenceDigest", &self.secret_reference_digest())?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("reversible", &true)?;
        state.serialize_field("registrationDigest", &self.binding_digest)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityDescription {
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
    pub truth_authority: bool,
    pub consent_authority: bool,
    pub effect_authority: bool,
    pub receipt_authority: bool,
    pub verification_authority: bool,
    pub outcome_adoption: bool,
    pub work_product_adoption: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KinesisEvidenceRequest {
    pub scope_digest: Digest,
    pub filter: crate::model::ShardFilter,
    pub expected_provider_digest: Digest,
    pub expected_registration_digest: Digest,
    pub max_pages: u16,
    pub max_shards: u16,
    pub observed_at: DateTime<Utc>,
}

impl KinesisEvidenceRequest {
    pub fn new(
        scope: &AwsKinesisStreamScope,
        filter: crate::model::ShardFilter,
        expected_provider_digest: Digest,
        expected_registration_digest: Digest,
        max_pages: u16,
        max_shards: u16,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        if filter != *scope.shard_filter()
            || max_pages == 0
            || max_pages > crate::MAX_PAGES
            || max_shards == 0
            || max_shards as usize > crate::MAX_SHARDS
        {
            return Err(AwsKinesisStreamResultError::InvalidRequest);
        }
        expected_provider_digest.validate()?;
        expected_registration_digest.validate()?;
        Ok(Self {
            scope_digest: scope.digest(),
            filter,
            expected_provider_digest,
            expected_registration_digest,
            max_pages,
            max_shards,
            observed_at,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-kinesis-evidence-request/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("filter", self.filter.digest().as_str().to_owned()),
                (
                    "provider",
                    self.expected_provider_digest.as_str().to_owned(),
                ),
                (
                    "registration",
                    self.expected_registration_digest.as_str().to_owned(),
                ),
                ("max_pages", self.max_pages.to_string()),
                ("max_shards", self.max_shards.to_string()),
                ("observed_at", self.observed_at.to_rfc3339()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureEvidence {
    pub operation: AwsKinesisOperation,
    pub status_code: Option<u16>,
    pub category: String,
    pub failure_digest: Digest,
}

impl FailureEvidence {
    fn from_transport(operation: AwsKinesisOperation, error: &AwsKinesisTransportError) -> Self {
        let category = match error {
            AwsKinesisTransportError::BlockedEnv => "blocked_env",
            AwsKinesisTransportError::BadRequest => "bad_request",
            AwsKinesisTransportError::Unauthorized => "unauthorized",
            AwsKinesisTransportError::Forbidden => "forbidden",
            AwsKinesisTransportError::NotFound => "not_found",
            AwsKinesisTransportError::Conflict => "conflict",
            AwsKinesisTransportError::RateLimited { .. } => "throttled",
            AwsKinesisTransportError::ServerError { .. } => "server_error",
            AwsKinesisTransportError::Timeout => "timeout",
            AwsKinesisTransportError::AccessLost => "access_loss",
            AwsKinesisTransportError::Partial => "partial",
            AwsKinesisTransportError::TokenExpired => "token_expired",
            AwsKinesisTransportError::PaginationLoop => "pagination_loop",
            AwsKinesisTransportError::InvalidResponse => "invalid_response",
            AwsKinesisTransportError::Tampered => "tampered",
        }
        .to_owned();
        let failure_digest = Digest::from_parts(
            "aws-kinesis-failure/v1",
            &[
                ("operation", operation.as_str().to_owned()),
                ("category", category.clone()),
                (
                    "status",
                    error
                        .status_code()
                        .map_or_else(String::new, |status| status.to_string()),
                ),
            ],
        );
        Self {
            operation,
            status_code: error.status_code(),
            category,
            failure_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsKinesisStreamResultProposal {
    pub service_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub account_digest: Digest,
    pub region_digest: Digest,
    pub stream_digest: Digest,
    pub stream_version_digest: Digest,
    pub shard_filter_digest: Digest,
    pub consumer_scope_digest: Option<Digest>,
    pub mission: crate::model::MissionProjection,
    pub project: ProjectProjection,
    pub work_product: WorkProductProjection,
    pub state: KinesisEvidenceState,
    pub list_pages: u16,
    pub list_complete: bool,
    pub stream: Option<StreamProjection>,
    pub failure: Option<FailureEvidence>,
    pub evidence: EvidenceDigests,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub truth_authority: bool,
    pub consent_authority: bool,
    pub effect_authority: bool,
    pub receipt_authority: bool,
    pub verification_authority: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub proposal_digest: Digest,
}

impl AwsKinesisStreamResultProposal {
    #[allow(clippy::too_many_arguments)]
    fn new(
        registration: &AwsKinesisStreamResultRegistration,
        provider: &AwsKinesisProviderDefinition,
        request: &KinesisEvidenceRequest,
        state: KinesisEvidenceState,
        list_pages: u16,
        list_complete: bool,
        summary: Option<&StreamSummary>,
        shards: Vec<crate::model::ShardLineageProjection>,
        consumer: Option<crate::model::ConsumerProjection>,
        cursor_digest: Option<Digest>,
        failure: Option<FailureEvidence>,
        provenance: TransportProvenance,
    ) -> Self {
        let stream = summary.and_then(|value| {
            StreamProjection::from_parts(registration.scope(), value, shards, consumer).ok()
        });
        let summary_digest = stream.as_ref().map(|value| value.summary_digest.clone());
        let shards_digest = stream
            .as_ref()
            .map(|value| shards_digest(&value.shard_lineage));
        let consumer_digest = stream.as_ref().and_then(|value| {
            value
                .consumer
                .as_ref()
                .map(|consumer| consumer.metadata_digest.clone())
        });
        let topology_digest = stream.as_ref().map(|value| value.topology_digest.clone());
        let encryption_digest = stream.as_ref().map(|value| value.encryption.digest());
        let mut evidence = EvidenceDigests {
            plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_digest: registration.contract_digest.clone(),
            provider_digest: provider.provider_digest.clone(),
            api_digest: provider.api_digest.clone(),
            permission_digest: registration.permission_digest(),
            consent_digest: registration.consent_digest(),
            scope_digest: registration.scope_digest.clone(),
            filter_digest: request.filter.digest(),
            cursor_digest,
            summary_digest,
            shards_digest,
            consumer_digest,
            topology_digest,
            encryption_digest,
            evidence_digest: Digest::from_text("unsealed-kinesis-evidence"),
        };
        evidence.evidence_digest = calculate_evidence_digest(
            &evidence,
            state,
            list_pages,
            list_complete,
            stream.as_ref(),
            failure.as_ref(),
        );
        let mut proposal = Self {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_digest: registration.registration_digest().clone(),
            scope_digest: registration.scope_digest.clone(),
            account_digest: registration.scope.account().digest(),
            region_digest: registration.scope.region().digest(),
            stream_digest: registration.scope.stream().digest(),
            stream_version_digest: registration.scope.stream_version().digest(),
            shard_filter_digest: registration.scope.shard_filter().digest(),
            consumer_scope_digest: registration
                .scope
                .consumer()
                .map(crate::model::ConsumerIdentity::digest),
            mission: mission_projection(registration.scope.mission()),
            project: project_projection(registration.scope.project()),
            work_product: work_product_projection(registration.scope.work_product()),
            state,
            list_pages,
            list_complete,
            stream,
            failure,
            evidence,
            provenance,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            truth_authority: false,
            consent_authority: false,
            effect_authority: false,
            receipt_authority: false,
            verification_authority: false,
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: Digest::from_text("unsealed-kinesis-proposal"),
        };
        proposal.proposal_digest = proposal.calculate_digest();
        proposal
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.evidence.plugin_version_digest.validate()?;
        self.evidence.contract_digest.validate()?;
        self.evidence.provider_digest.validate()?;
        self.evidence.api_digest.validate()?;
        self.evidence.permission_digest.validate()?;
        self.evidence.consent_digest.validate()?;
        self.evidence.scope_digest.validate()?;
        self.evidence.filter_digest.validate()?;
        self.evidence
            .cursor_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.evidence
            .summary_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.evidence
            .shards_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.evidence
            .consumer_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.evidence
            .topology_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.evidence
            .encryption_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.evidence.evidence_digest.validate()?;
        if self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.truth_authority
            || self.consent_authority
            || self.effect_authority
            || self.receipt_authority
            || self.verification_authority
            || self.outcome_adopted
            || self.work_product_adopted
            || self.evidence.evidence_digest
                != calculate_evidence_digest(
                    &self.evidence,
                    self.state,
                    self.list_pages,
                    self.list_complete,
                    self.stream.as_ref(),
                    self.failure.as_ref(),
                )
            || self.proposal_digest != self.calculate_digest()
        {
            return Err(AwsKinesisStreamResultError::TamperedEvidence);
        }
        if let Some(stream) = &self.stream {
            if stream.summary_digest
                != self
                    .evidence
                    .summary_digest
                    .clone()
                    .ok_or(AwsKinesisStreamResultError::TamperedEvidence)?
                || Some(stream.topology_digest.clone()) != self.evidence.topology_digest
            {
                return Err(AwsKinesisStreamResultError::TamperedEvidence);
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> &Digest {
        &self.proposal_digest
    }
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
    pub const fn is_review_only(&self) -> bool {
        true
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-kinesis-stream-result-proposal/v1",
            &[
                ("service", self.service_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("account", self.account_digest.as_str().to_owned()),
                ("region", self.region_digest.as_str().to_owned()),
                ("stream", self.stream_digest.as_str().to_owned()),
                (
                    "stream_version",
                    self.stream_version_digest.as_str().to_owned(),
                ),
                ("filter", self.shard_filter_digest.as_str().to_owned()),
                (
                    "consumer_scope",
                    self.consumer_scope_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "mission",
                    serde_json::to_string(&self.mission).expect("mission projection serializes"),
                ),
                (
                    "project",
                    serde_json::to_string(&self.project).expect("project projection serializes"),
                ),
                (
                    "work_product",
                    serde_json::to_string(&self.work_product)
                        .expect("work product projection serializes"),
                ),
                ("state", format!("{:?}", self.state)),
                ("list_pages", self.list_pages.to_string()),
                ("list_complete", self.list_complete.to_string()),
                (
                    "stream",
                    self.stream.as_ref().map_or_else(String::new, |value| {
                        serde_json::to_string(value).expect("stream projection serializes")
                    }),
                ),
                (
                    "failure",
                    self.failure.as_ref().map_or_else(String::new, |value| {
                        serde_json::to_string(value).expect("failure serializes")
                    }),
                ),
                (
                    "evidence",
                    serde_json::to_string(&self.evidence).expect("evidence serializes"),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

fn calculate_evidence_digest(
    evidence: &EvidenceDigests,
    state: KinesisEvidenceState,
    list_pages: u16,
    list_complete: bool,
    stream: Option<&StreamProjection>,
    failure: Option<&FailureEvidence>,
) -> Digest {
    Digest::from_parts(
        "aws-kinesis-evidence/v1",
        &[
            ("plugin", evidence.plugin_version_digest.as_str().to_owned()),
            ("contract", evidence.contract_digest.as_str().to_owned()),
            ("provider", evidence.provider_digest.as_str().to_owned()),
            ("api", evidence.api_digest.as_str().to_owned()),
            ("permission", evidence.permission_digest.as_str().to_owned()),
            ("consent", evidence.consent_digest.as_str().to_owned()),
            ("scope", evidence.scope_digest.as_str().to_owned()),
            ("filter", evidence.filter_digest.as_str().to_owned()),
            (
                "cursor",
                evidence
                    .cursor_digest
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
            ),
            (
                "summary",
                evidence
                    .summary_digest
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
            ),
            (
                "shards",
                evidence
                    .shards_digest
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
            ),
            (
                "consumer",
                evidence
                    .consumer_digest
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
            ),
            (
                "topology",
                evidence
                    .topology_digest
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
            ),
            (
                "encryption",
                evidence
                    .encryption_digest
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
            ),
            ("state", format!("{state:?}")),
            ("list_pages", list_pages.to_string()),
            ("list_complete", list_complete.to_string()),
            (
                "stream_projection",
                stream.map_or_else(String::new, |value| {
                    serde_json::to_string(value).expect("stream projection serializes")
                }),
            ),
            (
                "failure",
                failure.map_or_else(String::new, |value| {
                    serde_json::to_string(value).expect("failure serializes")
                }),
            ),
        ],
    )
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailure {
    RegistrationInactive,
    RegistrationDigestMismatch,
    ProviderDigestMismatch,
    ApiDigestMismatch,
    PermissionDigestMismatch,
    ConsentDigestMismatch,
    ScopeDigestMismatch,
    FilterDigestMismatch,
    EvidenceDigestMismatch,
    ProposalDigestMismatch,
    TamperedEvidence,
    PartialEvidence,
    TokenExpired,
    AccessLoss,
    ProviderUnknown,
    RegistrationRevoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub valid: bool,
    pub review_eligible: bool,
    pub failures: Vec<VerificationFailure>,
    pub verification_digest: Digest,
}

impl VerificationReport {
    fn new(valid: bool, review_eligible: bool, failures: Vec<VerificationFailure>) -> Self {
        let verification_digest = Digest::from_parts(
            "aws-kinesis-verification-report/v1",
            &[
                ("valid", valid.to_string()),
                ("review_eligible", review_eligible.to_string()),
                (
                    "failures",
                    failures
                        .iter()
                        .map(|failure| format!("{failure:?}"))
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
            ],
        );
        Self {
            valid,
            review_eligible,
            failures,
            verification_digest,
        }
    }
}

pub struct AwsKinesisStreamResultService<T: crate::provider::AwsKinesisTransport> {
    registration: AwsKinesisStreamResultRegistration,
    provider: AwsKinesisProvider<T>,
}

impl<T: crate::provider::AwsKinesisTransport> fmt::Debug for AwsKinesisStreamResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsKinesisStreamResultService")
            .field("registration", &self.registration)
            .field("provider", &self.provider)
            .finish()
    }
}

impl<T: crate::provider::AwsKinesisTransport> AwsKinesisStreamResultService<T> {
    pub fn new(
        scope: AwsKinesisStreamScope,
        secret_reference: crate::model::SecretReference,
        consent: ConsentScope,
        provider: AwsKinesisProvider<T>,
        registration_time: DateTime<Utc>,
    ) -> Result<Self> {
        Self::with_registration(
            "aws-kinesis-registration",
            scope,
            secret_reference,
            PermissionSnapshot::for_layer_one(1),
            consent,
            provider,
            1,
            registration_time,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_registration(
        registration_id: impl Into<String>,
        scope: AwsKinesisStreamScope,
        secret_reference: crate::model::SecretReference,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        provider: AwsKinesisProvider<T>,
        registration_revision: u64,
        _registration_time: DateTime<Utc>,
    ) -> Result<Self> {
        let registration = AwsKinesisStreamResultRegistration::new(
            registration_id,
            scope,
            secret_reference,
            permission_snapshot,
            consent,
            provider.definition(),
            registration_revision,
        )?;
        Ok(Self {
            registration,
            provider,
        })
    }

    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            operations: vec![
                AwsKinesisOperation::DescribeStreamSummary
                    .as_str()
                    .to_owned(),
                AwsKinesisOperation::ListShards.as_str().to_owned(),
                AwsKinesisOperation::DescribeStreamConsumer
                    .as_str()
                    .to_owned(),
            ],
            permissions: crate::LAYER1_PERMISSIONS
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect(),
            read_only: true,
            proposal_only: true,
            recording_only: true,
            connected: false,
            native: false,
            first_party: false,
            truth_authority: false,
            consent_authority: false,
            effect_authority: false,
            receipt_authority: false,
            verification_authority: false,
            outcome_adoption: false,
            work_product_adoption: false,
        }
    }

    pub fn scope(&self) -> &AwsKinesisStreamScope {
        self.registration.scope()
    }
    pub fn registration(&self) -> &AwsKinesisStreamResultRegistration {
        &self.registration
    }
    pub fn registration_mut(&mut self) -> &mut AwsKinesisStreamResultRegistration {
        &mut self.registration
    }
    pub fn provider(&self) -> &AwsKinesisProvider<T> {
        &self.provider
    }
    pub fn provider_mut(&mut self) -> &mut AwsKinesisProvider<T> {
        &mut self.provider
    }

    pub fn request(
        &self,
        filter: crate::model::ShardFilter,
        max_pages: u16,
        max_shards: u16,
        observed_at: DateTime<Utc>,
    ) -> Result<KinesisEvidenceRequest> {
        KinesisEvidenceRequest::new(
            self.scope(),
            filter,
            self.provider.definition().provider_digest.clone(),
            self.registration.registration_digest().clone(),
            max_pages,
            max_shards,
            observed_at,
        )
    }

    pub fn default_request(&self, observed_at: DateTime<Utc>) -> Result<KinesisEvidenceRequest> {
        self.request(self.scope().shard_filter().clone(), 1, 256, observed_at)
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

    pub fn consumer(&self) -> Result<MissionAwsKinesisConsumer> {
        MissionAwsKinesisConsumer::new(self.scope().clone(), self.registration.clone())
    }

    pub fn verify(&self, proposal: &AwsKinesisStreamResultProposal) -> VerificationReport {
        let mut failures = Vec::new();
        if !self.registration.is_active() {
            failures.push(VerificationFailure::RegistrationInactive);
        }
        if proposal.registration_digest != *self.registration.registration_digest() {
            failures.push(VerificationFailure::RegistrationDigestMismatch);
        }
        if proposal.evidence.provider_digest != self.provider.definition().provider_digest {
            failures.push(VerificationFailure::ProviderDigestMismatch);
        }
        if proposal.evidence.api_digest != self.provider.definition().api_digest {
            failures.push(VerificationFailure::ApiDigestMismatch);
        }
        if proposal.evidence.permission_digest != self.registration.permission_digest() {
            failures.push(VerificationFailure::PermissionDigestMismatch);
        }
        if proposal.evidence.consent_digest != self.registration.consent_digest() {
            failures.push(VerificationFailure::ConsentDigestMismatch);
        }
        if proposal.scope_digest != *self.registration.scope_digest() {
            failures.push(VerificationFailure::ScopeDigestMismatch);
        }
        if proposal.shard_filter_digest != self.scope().shard_filter().digest() {
            failures.push(VerificationFailure::FilterDigestMismatch);
        }
        if proposal.validate_integrity().is_err() {
            failures.push(VerificationFailure::TamperedEvidence);
        }
        match proposal.state {
            KinesisEvidenceState::Partial => failures.push(VerificationFailure::PartialEvidence),
            KinesisEvidenceState::TokenExpired => failures.push(VerificationFailure::TokenExpired),
            KinesisEvidenceState::AccessLost => failures.push(VerificationFailure::AccessLoss),
            KinesisEvidenceState::ProviderUnknown => {
                failures.push(VerificationFailure::ProviderUnknown);
            }
            KinesisEvidenceState::Tampered => failures.push(VerificationFailure::TamperedEvidence),
            KinesisEvidenceState::Revoked => {
                failures.push(VerificationFailure::RegistrationRevoked);
            }
            KinesisEvidenceState::Creating
            | KinesisEvidenceState::Active
            | KinesisEvidenceState::Updating
            | KinesisEvidenceState::Deleting => {}
        }
        failures.sort_unstable();
        failures.dedup();
        let valid = failures.is_empty();
        VerificationReport::new(
            valid,
            valid && proposal.state.is_review_complete(),
            failures,
        )
    }

    pub fn propose(
        &mut self,
        request: KinesisEvidenceRequest,
    ) -> Result<AwsKinesisStreamResultProposal> {
        if self.registration.secret_reference().is_revoked() {
            return Err(AwsKinesisStreamResultError::SecretRevoked);
        }
        self.registration.validate()?;
        if !self.registration.is_active() {
            return Err(AwsKinesisStreamResultError::RegistrationInactive);
        }
        if request.scope_digest != *self.registration.scope_digest()
            || request.expected_provider_digest != self.provider.definition().provider_digest
            || request.expected_registration_digest != *self.registration.registration_digest()
        {
            return Err(AwsKinesisStreamResultError::ScopeMismatch);
        }
        if request.filter != *self.scope().shard_filter() {
            return Err(AwsKinesisStreamResultError::ShardFilterMismatch);
        }
        if self.registration.consent().is_revoked() {
            return Err(AwsKinesisStreamResultError::ConsentRevoked);
        }
        if !self
            .registration
            .consent()
            .is_active_at(request.observed_at)
        {
            return Err(AwsKinesisStreamResultError::ConsentExpired);
        }

        let summary_request = DescribeStreamSummaryRequest::for_scope(self.scope())?;
        let summary_response = match self.provider.describe_stream_summary(&summary_request) {
            Ok(response) => response,
            Err(error) => {
                return Ok(self.failure_proposal(
                    &request,
                    KinesisEvidenceState::from_transport(&error),
                    0,
                    false,
                    None,
                    Vec::new(),
                    None,
                    None,
                    FailureEvidence::from_transport(
                        AwsKinesisOperation::DescribeStreamSummary,
                        &error,
                    ),
                ));
            }
        };
        let summary = summary_response.summary.clone();
        let mut shards = Vec::new();
        let mut list_pages = 0_u16;
        let mut list_complete = false;
        let mut cursor: Option<Cursor> = None;
        let mut cursor_digest = None;
        let mut seen_tokens = BTreeSet::new();

        loop {
            if list_pages >= request.max_pages {
                break;
            }
            let list_request = match ListShardsRequest::new_at(
                self.scope(),
                request.filter.clone(),
                cursor.clone(),
                crate::MAX_PAGE_SIZE,
                request.observed_at,
            ) {
                Ok(request) => request,
                Err(error) => {
                    let (state, transport_error) = match error {
                        AwsKinesisStreamResultError::CursorExpired => (
                            KinesisEvidenceState::TokenExpired,
                            AwsKinesisTransportError::TokenExpired,
                        ),
                        AwsKinesisStreamResultError::CursorMismatch => (
                            KinesisEvidenceState::Tampered,
                            AwsKinesisTransportError::Tampered,
                        ),
                        _ => (
                            KinesisEvidenceState::Tampered,
                            AwsKinesisTransportError::InvalidResponse,
                        ),
                    };
                    return Ok(self.failure_proposal(
                        &request,
                        state,
                        list_pages,
                        false,
                        Some(&summary),
                        shards,
                        cursor_digest,
                        None,
                        FailureEvidence::from_transport(
                            AwsKinesisOperation::ListShards,
                            &transport_error,
                        ),
                    ));
                }
            };
            let response = match self.provider.list_shards(&list_request) {
                Ok(response) => response,
                Err(error) => {
                    return Ok(self.failure_proposal(
                        &request,
                        KinesisEvidenceState::from_transport(&error),
                        list_pages,
                        false,
                        Some(&summary),
                        shards,
                        cursor_digest,
                        None,
                        FailureEvidence::from_transport(AwsKinesisOperation::ListShards, &error),
                    ));
                }
            };
            list_pages = list_pages.saturating_add(1);
            if shards.len().saturating_add(response.shards.len()) > request.max_shards as usize {
                return Ok(self.failure_proposal(
                    &request,
                    KinesisEvidenceState::Partial,
                    list_pages,
                    false,
                    Some(&summary),
                    shards,
                    cursor_digest,
                    None,
                    FailureEvidence::from_transport(
                        AwsKinesisOperation::ListShards,
                        &AwsKinesisTransportError::Partial,
                    ),
                ));
            }
            shards.extend(response.shards);
            if let Some(next_cursor) = response.next_cursor {
                let token_digest = next_cursor.token_digest().clone();
                if !seen_tokens.insert(token_digest.clone()) {
                    return Ok(self.failure_proposal(
                        &request,
                        KinesisEvidenceState::Tampered,
                        list_pages,
                        false,
                        Some(&summary),
                        shards,
                        Some(token_digest),
                        None,
                        FailureEvidence::from_transport(
                            AwsKinesisOperation::ListShards,
                            &AwsKinesisTransportError::PaginationLoop,
                        ),
                    ));
                }
                cursor_digest = Some(token_digest);
                if request.observed_at >= next_cursor.expires_at() {
                    return Ok(self.failure_proposal(
                        &request,
                        KinesisEvidenceState::TokenExpired,
                        list_pages,
                        false,
                        Some(&summary),
                        shards,
                        cursor_digest,
                        None,
                        FailureEvidence::from_transport(
                            AwsKinesisOperation::ListShards,
                            &AwsKinesisTransportError::TokenExpired,
                        ),
                    ));
                }
                if list_pages >= request.max_pages {
                    break;
                }
                cursor = Some(next_cursor);
            } else {
                list_complete = true;
                break;
            }
        }

        if !list_complete {
            return Ok(self.failure_proposal(
                &request,
                KinesisEvidenceState::Partial,
                list_pages,
                false,
                Some(&summary),
                shards,
                cursor_digest,
                None,
                FailureEvidence::from_transport(
                    AwsKinesisOperation::ListShards,
                    &AwsKinesisTransportError::Partial,
                ),
            ));
        }

        let mut lineage_seen = BTreeSet::new();
        if shards
            .iter()
            .any(|shard| !lineage_seen.insert(shard.shard_id_digest.clone()))
        {
            return Ok(self.failure_proposal(
                &request,
                KinesisEvidenceState::Tampered,
                list_pages,
                list_complete,
                Some(&summary),
                shards,
                cursor_digest,
                None,
                FailureEvidence::from_transport(
                    AwsKinesisOperation::ListShards,
                    &AwsKinesisTransportError::Tampered,
                ),
            ));
        }

        let consumer = if self.scope().consumer().is_some() {
            let consumer_request = DescribeStreamConsumerRequest::for_scope(self.scope())?;
            match self.provider.describe_stream_consumer(&consumer_request) {
                Ok(response) => Some(response.metadata),
                Err(error) => {
                    return Ok(self.failure_proposal(
                        &request,
                        KinesisEvidenceState::from_transport(&error),
                        list_pages,
                        list_complete,
                        Some(&summary),
                        shards,
                        cursor_digest,
                        None,
                        FailureEvidence::from_transport(
                            AwsKinesisOperation::DescribeStreamConsumer,
                            &error,
                        ),
                    ));
                }
            }
        } else {
            None
        };

        let stream = StreamProjection::from_parts(self.scope(), &summary, shards, consumer)
            .map_err(|_| AwsKinesisStreamResultError::TamperedEvidence)?;
        let mut proposal = AwsKinesisStreamResultProposal::new(
            &self.registration,
            self.provider.definition(),
            &request,
            KinesisEvidenceState::from(summary.status()),
            list_pages,
            list_complete,
            Some(&summary),
            stream.shard_lineage.clone(),
            stream.consumer.clone(),
            cursor_digest,
            None,
            self.provider.provenance(),
        );
        proposal.stream = Some(stream);
        proposal.evidence.shards_digest = Some(shards_digest(
            &proposal
                .stream
                .as_ref()
                .expect("stream projection set")
                .shard_lineage,
        ));
        proposal.evidence.evidence_digest = calculate_evidence_digest(
            &proposal.evidence,
            proposal.state,
            proposal.list_pages,
            proposal.list_complete,
            proposal.stream.as_ref(),
            proposal.failure.as_ref(),
        );
        proposal.proposal_digest = proposal.calculate_digest();
        proposal.validate_integrity()?;
        Ok(proposal)
    }

    #[allow(clippy::too_many_arguments)]
    fn failure_proposal(
        &self,
        request: &KinesisEvidenceRequest,
        state: KinesisEvidenceState,
        list_pages: u16,
        list_complete: bool,
        summary: Option<&StreamSummary>,
        shards: Vec<crate::model::ShardLineageProjection>,
        cursor_digest: Option<Digest>,
        consumer: Option<crate::model::ConsumerProjection>,
        failure: FailureEvidence,
    ) -> AwsKinesisStreamResultProposal {
        AwsKinesisStreamResultProposal::new(
            &self.registration,
            self.provider.definition(),
            request,
            state,
            list_pages,
            list_complete,
            summary,
            shards,
            consumer,
            cursor_digest,
            Some(failure),
            self.provider.provenance(),
        )
    }
}

impl KinesisEvidenceState {
    fn from_transport(error: &AwsKinesisTransportError) -> Self {
        match error {
            AwsKinesisTransportError::TokenExpired => Self::TokenExpired,
            AwsKinesisTransportError::AccessLost
            | AwsKinesisTransportError::Unauthorized
            | AwsKinesisTransportError::Forbidden => Self::AccessLost,
            AwsKinesisTransportError::Partial => Self::Partial,
            AwsKinesisTransportError::InvalidResponse
            | AwsKinesisTransportError::Tampered
            | AwsKinesisTransportError::PaginationLoop => Self::Tampered,
            AwsKinesisTransportError::BlockedEnv
            | AwsKinesisTransportError::BadRequest
            | AwsKinesisTransportError::NotFound
            | AwsKinesisTransportError::Conflict
            | AwsKinesisTransportError::RateLimited { .. }
            | AwsKinesisTransportError::ServerError { .. }
            | AwsKinesisTransportError::Timeout => Self::ProviderUnknown,
        }
    }
}

fn valid_registration_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= crate::MAX_IDENTIFIER_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}

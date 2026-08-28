use std::{collections::BTreeSet, fmt};

use serde::Serialize;

use crate::consumer::MissionAwsFirehoseConsumer;
use crate::error::{AwsFirehoseError, AwsFirehoseTransportError, Result};
use crate::model::{
    AwsFirehoseDeliveryScope, ConsentScope, DeliveryStreamObservation, DestinationHealth,
    DestinationObservation, Digest, MissionProjection, PermissionSnapshot, ProjectProjection,
    Revision, SecretReference, StreamStatus, TransportProvenance, WorkProductProjection,
};
use crate::provider::{
    AwsFirehoseOperation, AwsFirehoseProvider, AwsFirehoseProviderDefinition, AwsFirehoseTransport,
    DescribeDeliveryStreamRequest, ListDeliveryStreamsRequest,
};
use crate::{
    API_VERSION, CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_SCHEMA, CONTRACT_VERSION, EVIDENCE_LEVEL,
    MAX_PAGE_SIZE, MAX_PAGES, MAX_REQUESTS_PER_READ, MAX_RESPONSE_BYTES, PLUGIN_ID, PLUGIN_VERSION,
    PROVIDER_API_REVISION, PROVIDER_ID, PROVIDER_VERSION, SERVICE_ID,
};

pub type ServiceError = AwsFirehoseError;
pub type AwsFirehoseServiceError = AwsFirehoseError;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
    Reversed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationTransition {
    pub from: RegistrationState,
    pub to: RegistrationState,
    pub revision: Revision,
    pub prior_registration_digest: Digest,
    pub reason_digest: Digest,
    pub transition_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsFirehoseRegistration {
    pub plugin_id: String,
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_api_revision: String,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub scope_digest: Digest,
    pub provider_scope_digest: Digest,
    pub stream_version_digest: Digest,
    pub source_revision: Revision,
    pub permission_digest: Digest,
    pub permission_revision: Revision,
    pub secret_reference_digest: Digest,
    pub consent_digest: Digest,
    pub evidence_policy_digest: Digest,
    pub registration_revision: Revision,
    pub state: RegistrationState,
    pub transitions: Vec<RegistrationTransition>,
    pub registration_digest: Digest,
}

impl AwsFirehoseRegistration {
    pub fn new(
        scope: &AwsFirehoseDeliveryScope,
        secret_reference: &SecretReference,
        consent: &ConsentScope,
        provider_definition: &AwsFirehoseProviderDefinition,
        registration_revision: Revision,
    ) -> Result<Self> {
        scope.validate()?;
        provider_definition.validate()?;
        if secret_reference.scope_digest() != scope.digest() || secret_reference.is_revoked() {
            return Err(AwsFirehoseError::InvalidSecretReference);
        }
        if consent.is_revoked() {
            return Err(AwsFirehoseError::ConsentRevoked);
        }
        let permission = scope.permission_snapshot();
        let evidence_policy_digest = evidence_policy_digest(scope, provider_definition);
        let mut registration = Self {
            plugin_id: PLUGIN_ID.to_owned(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: provider_definition.provider_id.clone(),
            provider_version: provider_definition.provider_version.clone(),
            provider_api_revision: provider_definition.api_revision.clone(),
            provider_digest: provider_definition.provider_digest.clone(),
            api_digest: api_digest(),
            scope_digest: scope.digest().clone(),
            provider_scope_digest: scope.provider_scope().digest().clone(),
            stream_version_digest: scope.provider_scope().stream_version_id().digest(),
            source_revision: scope.provider_scope().source_revision(),
            permission_digest: permission.digest().clone(),
            permission_revision: permission.revision(),
            secret_reference_digest: secret_reference.reference_digest().clone(),
            consent_digest: consent.digest(),
            evidence_policy_digest,
            registration_revision,
            state: RegistrationState::Active,
            transitions: Vec::new(),
            registration_digest: Digest::from_text("pending-firehose-registration"),
        };
        registration.registration_digest = registration.recomputed_digest();
        Ok(registration)
    }

    pub fn validate(&self) -> Result<()> {
        self.contract_digest.validate()?;
        self.provider_digest.validate()?;
        self.api_digest.validate()?;
        self.scope_digest.validate()?;
        self.provider_scope_digest.validate()?;
        self.stream_version_digest.validate()?;
        self.permission_digest.validate()?;
        self.secret_reference_digest.validate()?;
        self.consent_digest.validate()?;
        self.evidence_policy_digest.validate()?;
        if self.plugin_id != PLUGIN_ID
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.provider_id != PROVIDER_ID
            || self.provider_version != PROVIDER_VERSION
            || self.provider_api_revision != PROVIDER_API_REVISION
            || self.api_digest != api_digest()
            || self.scope_digest.as_str().is_empty()
            || self.provider_scope_digest.as_str().is_empty()
            || self.stream_version_digest.as_str().is_empty()
            || self.permission_digest.as_str().is_empty()
            || self.secret_reference_digest.as_str().is_empty()
            || self.consent_digest.as_str().is_empty()
            || self.evidence_policy_digest.as_str().is_empty()
            || self.registration_digest != self.recomputed_digest()
        {
            return Err(AwsFirehoseError::InvalidRegistration);
        }
        for transition in &self.transitions {
            transition.reason_digest.validate()?;
            transition.transition_digest.validate()?;
            if transition.transition_digest != compute_transition_digest(transition) {
                return Err(AwsFirehoseError::InvalidRegistration);
            }
        }
        Ok(())
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub const fn state(&self) -> RegistrationState {
        self.state
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }

    pub fn revoke(&mut self, reason: impl AsRef<str>) -> Result<RegistrationTransition> {
        self.transition(RegistrationState::Revoked, reason)
    }

    pub fn reverse(&mut self, reason: impl AsRef<str>) -> Result<RegistrationTransition> {
        self.transition(RegistrationState::Reversed, reason)
    }

    pub fn restore(&mut self, reason: impl AsRef<str>) -> Result<RegistrationTransition> {
        if self.is_active() {
            return Err(AwsFirehoseError::RegistrationInactive);
        }
        self.transition(RegistrationState::Active, reason)
    }

    fn transition(
        &mut self,
        to: RegistrationState,
        reason: impl AsRef<str>,
    ) -> Result<RegistrationTransition> {
        if self.state == to {
            return match to {
                RegistrationState::Active => Err(AwsFirehoseError::RegistrationInactive),
                RegistrationState::Revoked => Err(AwsFirehoseError::RegistrationRevoked),
                RegistrationState::Reversed => Err(AwsFirehoseError::RegistrationReversed),
            };
        }
        let prior_registration_digest = self.registration_digest.clone();
        let transition = RegistrationTransition {
            from: self.state,
            to,
            revision: self.registration_revision.next(),
            prior_registration_digest,
            reason_digest: Digest::from_text(reason.as_ref()),
            transition_digest: Digest::from_text("pending-firehose-transition"),
        };
        let mut transition = transition;
        transition.transition_digest = compute_transition_digest(&transition);
        self.state = to;
        self.registration_revision = transition.revision;
        self.transitions.push(transition.clone());
        self.registration_digest = self.recomputed_digest();
        self.validate()?;
        Ok(transition)
    }

    fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-firehose-registration/v1",
            &[
                ("plugin_id", self.plugin_id.clone()),
                ("plugin_version", self.plugin_version.clone()),
                ("contract_version", self.contract_version.clone()),
                ("contract", self.contract_digest.to_string()),
                ("provider_id", self.provider_id.clone()),
                ("provider_version", self.provider_version.clone()),
                ("provider_api_revision", self.provider_api_revision.clone()),
                ("provider", self.provider_digest.to_string()),
                ("api", self.api_digest.to_string()),
                ("scope", self.scope_digest.to_string()),
                ("provider_scope", self.provider_scope_digest.to_string()),
                ("stream_version", self.stream_version_digest.to_string()),
                ("source_revision", self.source_revision.get().to_string()),
                ("permission", self.permission_digest.to_string()),
                (
                    "permission_revision",
                    self.permission_revision.get().to_string(),
                ),
                ("secret", self.secret_reference_digest.to_string()),
                ("consent", self.consent_digest.to_string()),
                ("evidence_policy", self.evidence_policy_digest.to_string()),
                (
                    "registration_revision",
                    self.registration_revision.get().to_string(),
                ),
                ("state", format!("{:?}", self.state)),
                (
                    "transitions",
                    self.transitions
                        .iter()
                        .map(|transition| transition.transition_digest.to_string())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
            ],
        )
    }
}

fn compute_transition_digest(transition: &RegistrationTransition) -> Digest {
    Digest::from_parts(
        "aws-firehose-registration-transition/v1",
        &[
            ("from", format!("{:?}", transition.from)),
            ("to", format!("{:?}", transition.to)),
            ("revision", transition.revision.get().to_string()),
            ("prior", transition.prior_registration_digest.to_string()),
            ("reason", transition.reason_digest.to_string()),
        ],
    )
}

fn evidence_policy_digest(
    scope: &AwsFirehoseDeliveryScope,
    provider_definition: &AwsFirehoseProviderDefinition,
) -> Digest {
    Digest::from_parts(
        "aws-firehose-evidence-policy/v1",
        &[
            ("scope", scope.digest().to_string()),
            ("provider", provider_definition.provider_digest.to_string()),
            ("max_pages", MAX_PAGES.to_string()),
            ("max_page_size", MAX_PAGE_SIZE.to_string()),
            ("max_requests", MAX_REQUESTS_PER_READ.to_string()),
            ("max_response_bytes", MAX_RESPONSE_BYTES.to_string()),
            (
                "redaction",
                "payloads|s3_objects|transformation_code|secrets|raw_next_token".to_owned(),
            ),
        ],
    )
}

pub(crate) fn api_digest() -> Digest {
    Digest::from_parts(
        "aws-firehose-api/v1",
        &[
            ("version", API_VERSION.to_owned()),
            ("revision", PROVIDER_API_REVISION.to_owned()),
            (
                "operations",
                "ListDeliveryStreams,DescribeDeliveryStream".to_owned(),
            ),
        ],
    )
}

pub fn contract_digest() -> Digest {
    Digest::parse(CONTRACT_DIGEST).expect("checked Firehose contract digest")
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsFirehoseDeliveryServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub plugin_id: String,
    pub plugin_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub evidence_level: String,
    pub operations: Vec<String>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub live_execution: bool,
    pub external_writes: bool,
    pub kernel_authority: bool,
    pub outcome_adoption: bool,
}

impl AwsFirehoseDeliveryServiceDefinition {
    pub fn new() -> Self {
        Self {
            schema_version: CONTRACT_SCHEMA.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            plugin_id: PLUGIN_ID.to_owned(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            evidence_level: EVIDENCE_LEVEL.to_owned(),
            operations: vec![
                "describe_capabilities".to_owned(),
                "describe_scope".to_owned(),
                "register_scope".to_owned(),
                "revoke_registration".to_owned(),
                "reverse_registration".to_owned(),
                "restore_registration".to_owned(),
                "read_bounded".to_owned(),
                "propose".to_owned(),
                "record".to_owned(),
                "verify".to_owned(),
            ],
            read_only: true,
            proposal_only: true,
            recording_only: true,
            live_execution: false,
            external_writes: false,
            kernel_authority: false,
            outcome_adoption: false,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != CONTRACT_SCHEMA
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.plugin_id != PLUGIN_ID
            || self.plugin_version != PLUGIN_VERSION
            || self.service_id != SERVICE_ID
            || self.provider_id != PROVIDER_ID
            || self.consumer_id != CONSUMER_ID
            || self.evidence_level != EVIDENCE_LEVEL
            || !self.read_only
            || !self.proposal_only
            || !self.recording_only
            || self.live_execution
            || self.external_writes
            || self.kernel_authority
            || self.outcome_adoption
        {
            return Err(AwsFirehoseError::ContractDrift);
        }
        Ok(())
    }
}

impl Default for AwsFirehoseDeliveryServiceDefinition {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsFirehoseEvidenceState {
    Complete,
    Creating,
    Deleting,
    DeletingFailed,
    CreatingFailed,
    NotFound,
    Partial,
    AccessLoss,
    Throttled,
    Timeout,
    ProviderUnknown,
    RegistrationRevoked,
}

impl AwsFirehoseEvidenceState {
    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }

    pub const fn is_non_adoptable(self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureEvidence {
    pub category: String,
    pub status_code: Option<u16>,
    pub retry_after_seconds: Option<u64>,
    pub error_digest: Digest,
}

impl FailureEvidence {
    fn from_transport(error: &AwsFirehoseTransportError) -> Self {
        Self {
            category: error.category().to_owned(),
            status_code: error.status_code(),
            retry_after_seconds: match error {
                AwsFirehoseTransportError::Throttled {
                    retry_after_seconds,
                } => *retry_after_seconds,
                _ => None,
            },
            error_digest: Digest::from_parts(
                "aws-firehose-transport-error/v1",
                &[
                    ("category", error.category().to_owned()),
                    (
                        "status",
                        error
                            .status_code()
                            .map_or_else(String::new, |status| status.to_string()),
                    ),
                    (
                        "retry_after",
                        match error {
                            AwsFirehoseTransportError::Throttled {
                                retry_after_seconds,
                            } => retry_after_seconds
                                .map_or_else(String::new, |seconds| seconds.to_string()),
                            _ => String::new(),
                        },
                    ),
                ],
            ),
        }
    }

    fn from_category(category: &str) -> Self {
        Self {
            category: category.to_owned(),
            status_code: None,
            retry_after_seconds: None,
            error_digest: Digest::from_parts(
                "aws-firehose-evidence-failure/v1",
                &[("category", category.to_owned())],
            ),
        }
    }

    fn validate_integrity(&self) -> Result<()> {
        let category_digest = Digest::from_parts(
            "aws-firehose-evidence-failure/v1",
            &[("category", self.category.clone())],
        );
        let transport_digest = Digest::from_parts(
            "aws-firehose-transport-error/v1",
            &[
                ("category", self.category.clone()),
                (
                    "status",
                    self.status_code
                        .map_or_else(String::new, |status| status.to_string()),
                ),
                (
                    "retry_after",
                    self.retry_after_seconds
                        .map_or_else(String::new, |seconds| seconds.to_string()),
                ),
            ],
        );
        if self.error_digest != category_digest && self.error_digest != transport_digest {
            return Err(AwsFirehoseError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DestinationEvidence {
    pub destination_id_digest: Digest,
    pub destination_type: crate::model::DestinationType,
    pub health: DestinationHealth,
    pub configuration_fingerprint: Digest,
    pub encryption_fingerprint: Option<Digest>,
}

impl From<&DestinationObservation> for DestinationEvidence {
    fn from(value: &DestinationObservation) -> Self {
        Self {
            destination_id_digest: value.destination_id.digest(),
            destination_type: value.destination_type,
            health: value.health,
            configuration_fingerprint: value.configuration_fingerprint.clone(),
            encryption_fingerprint: value.encryption_fingerprint.clone(),
        }
    }
}

impl DestinationEvidence {
    fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-firehose-destination-evidence/v1",
            &[
                ("id", self.destination_id_digest.to_string()),
                ("type", self.destination_type.as_str().to_owned()),
                ("health", format!("{:?}", self.health)),
                ("configuration", self.configuration_fingerprint.to_string()),
                (
                    "encryption",
                    self.encryption_fingerprint
                        .as_ref()
                        .map_or_else(String::new, ToString::to_string),
                ),
            ],
        )
    }

    fn validate_integrity(&self) -> Result<()> {
        self.destination_id_digest.validate()?;
        self.configuration_fingerprint.validate()?;
        if let Some(fingerprint) = &self.encryption_fingerprint {
            fingerprint.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamEvidence {
    pub stream_name_digest: Digest,
    pub status: StreamStatus,
    pub version_id_digest: Digest,
    pub source_revision: Revision,
    pub destination: DestinationEvidence,
    pub encryption_fingerprint: Option<Digest>,
    pub configuration_fingerprint: Digest,
}

impl StreamEvidence {
    fn from_observation(
        observation: &DeliveryStreamObservation,
    ) -> std::result::Result<Self, AwsFirehoseError> {
        if observation.destinations.len() != 1 {
            return Err(AwsFirehoseError::DestinationAmbiguous);
        }
        let destination = DestinationEvidence::from(&observation.destinations[0]);
        Ok(Self {
            stream_name_digest: observation.stream_name.digest(),
            status: observation.status,
            version_id_digest: observation.version_id.digest(),
            source_revision: observation.source_revision,
            destination,
            encryption_fingerprint: observation.encryption_fingerprint.clone(),
            configuration_fingerprint: observation.configuration_fingerprint.clone(),
        })
    }

    fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-firehose-stream-evidence/v1",
            &[
                ("stream", self.stream_name_digest.to_string()),
                ("status", self.status.as_str().to_owned()),
                ("version", self.version_id_digest.to_string()),
                ("source_revision", self.source_revision.get().to_string()),
                ("destination", self.destination.digest().to_string()),
                (
                    "encryption",
                    self.encryption_fingerprint
                        .as_ref()
                        .map_or_else(String::new, ToString::to_string),
                ),
                ("configuration", self.configuration_fingerprint.to_string()),
            ],
        )
    }

    fn validate_integrity(&self) -> Result<()> {
        self.stream_name_digest.validate()?;
        self.version_id_digest.validate()?;
        self.destination.validate_integrity()?;
        self.configuration_fingerprint.validate()?;
        if let Some(fingerprint) = &self.encryption_fingerprint {
            fingerprint.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactedResponseReceipt {
    pub list_response_digest: Digest,
    pub describe_response_digest: Option<Digest>,
    pub cursor_digests: Vec<Digest>,
    pub response_bytes: u64,
    pub raw_payload_retained: bool,
    pub raw_next_token_retained: bool,
    pub receipt_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CostReceipt {
    pub requests: u16,
    pub response_bytes: u64,
    pub monetary_cost_claimed: bool,
    pub cost_receipt_digest: Digest,
}

fn redacted_response_digest(
    list_digest: &Digest,
    describe_digest: Option<&Digest>,
    response_bytes: u64,
    cursor_digests: &[Digest],
) -> Digest {
    Digest::from_parts(
        "aws-firehose-redacted-response/v1",
        &[
            ("list", list_digest.to_string()),
            (
                "describe",
                describe_digest.map_or_else(String::new, ToString::to_string),
            ),
            ("bytes", response_bytes.to_string()),
            (
                "cursors",
                cursor_digests
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            ),
        ],
    )
}

fn response_receipt_digest(response_digest: &Digest) -> Digest {
    Digest::from_parts(
        "aws-firehose-redacted-response-receipt/v1",
        &[
            ("response", response_digest.to_string()),
            ("payload", "false".to_owned()),
            ("next_token", "false".to_owned()),
        ],
    )
}

fn cost_receipt_digest(requests: u16, response_bytes: u64) -> Digest {
    Digest::from_parts(
        "aws-firehose-cost-receipt/v1",
        &[
            ("requests", requests.to_string()),
            ("bytes", response_bytes.to_string()),
            ("monetary_claim", "false".to_owned()),
        ],
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDigests {
    pub plugin_version_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub contract_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub provider_scope_digest: Digest,
    pub stream_version_digest: Digest,
    pub source_revision_digest: Digest,
    pub list_digest: Digest,
    pub describe_digest: Option<Digest>,
    pub response_digest: Digest,
    pub cost_digest: Digest,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsFirehoseReadRequest {
    pub scope_digest: Digest,
    pub limit: u16,
    pub max_pages: u16,
    pub request_digest: Digest,
}

impl AwsFirehoseReadRequest {
    pub fn new(scope: &AwsFirehoseDeliveryScope, limit: u16, max_pages: u16) -> Result<Self> {
        scope.validate()?;
        if !(1..=MAX_PAGE_SIZE).contains(&limit) || !(1..=MAX_PAGES).contains(&max_pages) {
            return Err(AwsFirehoseError::InvalidRequest);
        }
        let scope_digest = scope.digest().clone();
        let request_digest = Digest::from_parts(
            "aws-firehose-bounded-read-request/v1",
            &[
                ("scope", scope_digest.to_string()),
                (
                    "target",
                    scope.provider_scope().target_stream().digest().to_string(),
                ),
                ("limit", limit.to_string()),
                ("max_pages", max_pages.to_string()),
            ],
        );
        Ok(Self {
            scope_digest,
            limit,
            max_pages,
            request_digest,
        })
    }

    fn validate_against(&self, scope: &AwsFirehoseDeliveryScope) -> Result<()> {
        if self.scope_digest != *scope.digest()
            || !(1..=MAX_PAGE_SIZE).contains(&self.limit)
            || !(1..=MAX_PAGES).contains(&self.max_pages)
            || self.request_digest
                != Digest::from_parts(
                    "aws-firehose-bounded-read-request/v1",
                    &[
                        ("scope", self.scope_digest.to_string()),
                        (
                            "target",
                            scope.provider_scope().target_stream().digest().to_string(),
                        ),
                        ("limit", self.limit.to_string()),
                        ("max_pages", self.max_pages.to_string()),
                    ],
                )
        {
            return Err(AwsFirehoseError::ScopeMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsFirehoseReadEvidence {
    pub state: AwsFirehoseEvidenceState,
    pub list_complete: bool,
    pub pages_observed: u16,
    pub streams_observed: u16,
    pub cursor_digests: Vec<Digest>,
    pub stream: Option<StreamEvidence>,
    pub failure: Option<FailureEvidence>,
    pub redacted_response: RedactedResponseReceipt,
    pub cost: CostReceipt,
    pub provenance: TransportProvenance,
    pub digests: EvidenceDigests,
}

impl AwsFirehoseReadEvidence {
    fn new(
        scope: &AwsFirehoseDeliveryScope,
        provider_definition: &AwsFirehoseProviderDefinition,
        request: &AwsFirehoseReadRequest,
        state: AwsFirehoseEvidenceState,
        list_complete: bool,
        pages_observed: u16,
        streams_observed: u16,
        cursor_digests: Vec<Digest>,
        list_digest: Digest,
        describe_digest: Option<Digest>,
        stream: Option<StreamEvidence>,
        failure: Option<FailureEvidence>,
        response_bytes: u64,
        requests: u16,
        provenance: TransportProvenance,
    ) -> Self {
        let response_digest = redacted_response_digest(
            &list_digest,
            describe_digest.as_ref(),
            response_bytes,
            &cursor_digests,
        );
        let receipt_digest = response_receipt_digest(&response_digest);
        let cost_digest = cost_receipt_digest(requests, response_bytes);
        let redacted_response = RedactedResponseReceipt {
            list_response_digest: list_digest.clone(),
            describe_response_digest: describe_digest.clone(),
            cursor_digests: cursor_digests.clone(),
            response_bytes,
            raw_payload_retained: false,
            raw_next_token_retained: false,
            receipt_digest,
        };
        let cost = CostReceipt {
            requests,
            response_bytes,
            monetary_cost_claimed: false,
            cost_receipt_digest: cost_digest.clone(),
        };
        let evidence_digests = EvidenceDigests {
            plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
            provider_digest: provider_definition.provider_digest.clone(),
            api_digest: api_digest(),
            contract_digest: contract_digest(),
            permission_digest: scope.permission_snapshot().digest().clone(),
            scope_digest: scope.digest().clone(),
            provider_scope_digest: scope.provider_scope().digest().clone(),
            stream_version_digest: scope.provider_scope().stream_version_id().digest(),
            source_revision_digest: Digest::from_text(
                scope.provider_scope().source_revision().get().to_string(),
            ),
            list_digest,
            describe_digest,
            response_digest,
            cost_digest,
            evidence_digest: Digest::from_text("pending-firehose-evidence"),
        };
        let mut evidence = Self {
            state,
            list_complete,
            pages_observed,
            streams_observed,
            cursor_digests,
            stream,
            failure,
            redacted_response,
            cost,
            provenance,
            digests: evidence_digests,
        };
        evidence.digests.evidence_digest = evidence.compute_digest(request);
        evidence
    }

    pub fn validate_integrity(&self, request: &AwsFirehoseReadRequest) -> Result<()> {
        request.request_digest.validate()?;
        if self.digests.scope_digest != request.scope_digest {
            return Err(AwsFirehoseError::ScopeMismatch);
        }
        self.digests.plugin_version_digest.validate()?;
        self.digests.provider_digest.validate()?;
        self.digests.api_digest.validate()?;
        self.digests.contract_digest.validate()?;
        self.digests.permission_digest.validate()?;
        self.digests.scope_digest.validate()?;
        self.digests.provider_scope_digest.validate()?;
        self.digests.stream_version_digest.validate()?;
        self.digests.source_revision_digest.validate()?;
        self.digests.list_digest.validate()?;
        if let Some(digest) = &self.digests.describe_digest {
            digest.validate()?;
        }
        self.digests.response_digest.validate()?;
        self.digests.cost_digest.validate()?;
        self.digests.evidence_digest.validate()?;
        for cursor_digest in &self.cursor_digests {
            cursor_digest.validate()?;
        }
        if let Some(failure) = &self.failure {
            failure.validate_integrity()?;
        }
        if let Some(stream) = &self.stream {
            stream.validate_integrity()?;
        }
        if self.redacted_response.list_response_digest != self.digests.list_digest
            || self.redacted_response.describe_response_digest != self.digests.describe_digest
            || self.redacted_response.response_bytes != self.cost.response_bytes
            || self.redacted_response.cursor_digests != self.cursor_digests
            || self.redacted_response.receipt_digest
                != response_receipt_digest(&self.digests.response_digest)
            || self.digests.response_digest
                != redacted_response_digest(
                    &self.redacted_response.list_response_digest,
                    self.redacted_response.describe_response_digest.as_ref(),
                    self.redacted_response.response_bytes,
                    &self.redacted_response.cursor_digests,
                )
            || self.cost.cost_receipt_digest
                != cost_receipt_digest(self.cost.requests, self.cost.response_bytes)
            || self.cost.requests > MAX_REQUESTS_PER_READ
            || self.cost.response_bytes > MAX_RESPONSE_BYTES
            || self.redacted_response.response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(AwsFirehoseError::TamperedEvidence);
        }
        if !self.provenance.is_non_native()
            || self.redacted_response.raw_payload_retained
            || self.redacted_response.raw_next_token_retained
            || self.cost.monetary_cost_claimed
            || self.digests.evidence_digest != self.compute_digest(request)
        {
            return Err(AwsFirehoseError::TamperedEvidence);
        }
        Ok(())
    }

    fn compute_digest(&self, request: &AwsFirehoseReadRequest) -> Digest {
        Digest::from_parts(
            "aws-firehose-evidence/v1",
            &[
                ("request", request.request_digest.to_string()),
                ("state", format!("{:?}", self.state)),
                ("list_complete", self.list_complete.to_string()),
                ("pages", self.pages_observed.to_string()),
                ("streams", self.streams_observed.to_string()),
                (
                    "cursors",
                    self.cursor_digests
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "stream",
                    self.stream
                        .as_ref()
                        .map_or_else(String::new, |stream| stream.digest().to_string()),
                ),
                (
                    "failure",
                    self.failure
                        .as_ref()
                        .map_or_else(String::new, |failure| failure.error_digest.to_string()),
                ),
                (
                    "response",
                    self.redacted_response.receipt_digest.to_string(),
                ),
                ("cost", self.cost.cost_receipt_digest.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
                (
                    "plugin_version",
                    self.digests.plugin_version_digest.to_string(),
                ),
                ("provider", self.digests.provider_digest.to_string()),
                ("api", self.digests.api_digest.to_string()),
                ("contract", self.digests.contract_digest.to_string()),
                ("permission", self.digests.permission_digest.to_string()),
                (
                    "stream_version",
                    self.digests.stream_version_digest.to_string(),
                ),
                (
                    "source_revision",
                    self.digests.source_revision_digest.to_string(),
                ),
                ("list_digest", self.digests.list_digest.to_string()),
                (
                    "describe_digest",
                    self.digests
                        .describe_digest
                        .as_ref()
                        .map_or_else(String::new, ToString::to_string),
                ),
                ("scope", self.digests.scope_digest.to_string()),
                (
                    "provider_scope",
                    self.digests.provider_scope_digest.to_string(),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsFirehoseDeliveryProposal {
    pub service_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub provider_definition_digest: Digest,
    pub scope_digest: Digest,
    pub mission: MissionProjection,
    pub project: ProjectProjection,
    pub work_product: WorkProductProjection,
    pub request: AwsFirehoseReadRequest,
    pub state: AwsFirehoseEvidenceState,
    pub evidence: AwsFirehoseReadEvidence,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub delivery_completion_claim: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub proposal_digest: Digest,
}

impl AwsFirehoseDeliveryProposal {
    fn from_evidence(
        scope: &AwsFirehoseDeliveryScope,
        registration: &AwsFirehoseRegistration,
        provider_definition: &AwsFirehoseProviderDefinition,
        request: &AwsFirehoseReadRequest,
        evidence: AwsFirehoseReadEvidence,
    ) -> Self {
        let mut proposal = Self {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_digest: registration.registration_digest.clone(),
            registration_revision: registration.registration_revision,
            provider_definition_digest: provider_definition.provider_digest.clone(),
            scope_digest: scope.scope_digest().clone(),
            mission: MissionProjection::from(scope.mission()),
            project: ProjectProjection::from(scope.project()),
            work_product: WorkProductProjection::from(scope.work_product()),
            request: request.clone(),
            state: evidence.state,
            provenance: evidence.provenance,
            evidence,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            delivery_completion_claim: false,
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: Digest::from_text("pending-firehose-proposal"),
        };
        proposal.proposal_digest = proposal.compute_digest();
        proposal
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.registration_digest.validate()?;
        self.provider_definition_digest.validate()?;
        self.scope_digest.validate()?;
        self.mission.id_digest.validate()?;
        self.project.id_digest.validate()?;
        self.work_product.id_digest.validate()?;
        self.request.request_digest.validate()?;
        if self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || self.state != self.evidence.state
            || self.scope_digest != self.evidence.digests.scope_digest
            || self.provenance != self.evidence.provenance
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.delivery_completion_claim
            || self.outcome_adopted
            || self.work_product_adopted
            || self.proposal_digest != self.compute_digest()
        {
            return Err(AwsFirehoseError::TamperedEvidence);
        }
        if self.request.scope_digest != self.scope_digest {
            return Err(AwsFirehoseError::ScopeMismatch);
        }
        self.evidence.validate_integrity(&self.request)
    }

    pub fn is_review_only(&self) -> bool {
        true
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-firehose-proposal/v1",
            &[
                ("service", self.service_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("registration", self.registration_digest.to_string()),
                (
                    "registration_revision",
                    self.registration_revision.get().to_string(),
                ),
                (
                    "provider_definition",
                    self.provider_definition_digest.to_string(),
                ),
                ("scope", self.scope_digest.to_string()),
                ("mission", self.mission.id_digest.to_string()),
                ("project", self.project.id_digest.to_string()),
                ("work_product", self.work_product.id_digest.to_string()),
                ("request", self.request.request_digest.to_string()),
                ("state", format!("{:?}", self.state)),
                (
                    "evidence",
                    self.evidence.digests.evidence_digest.to_string(),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub valid: bool,
    pub review_eligible: bool,
    pub failures: Vec<String>,
    pub evidence_digest: Digest,
    pub proposal_digest: Digest,
}

pub struct AwsFirehoseDeliveryService<T> {
    scope: AwsFirehoseDeliveryScope,
    secret_reference: SecretReference,
    consent: ConsentScope,
    provider: AwsFirehoseProvider<T>,
    service_definition: AwsFirehoseDeliveryServiceDefinition,
    registration: AwsFirehoseRegistration,
    now_epoch_seconds: u64,
}

impl<T: AwsFirehoseTransport> fmt::Debug for AwsFirehoseDeliveryService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsFirehoseDeliveryService")
            .field("scope_digest", self.scope.digest())
            .field("secret_reference", &self.secret_reference)
            .field("consent", &self.consent)
            .field("provider", self.provider.definition())
            .field("service_definition", &self.service_definition)
            .field("registration", &self.registration)
            .field("now_epoch_seconds", &self.now_epoch_seconds)
            .finish()
    }
}

impl<T: AwsFirehoseTransport> AwsFirehoseDeliveryService<T> {
    pub fn new(
        scope: AwsFirehoseDeliveryScope,
        secret_reference: SecretReference,
        consent: ConsentScope,
        provider: AwsFirehoseProvider<T>,
        now_epoch_seconds: u64,
    ) -> Result<Self> {
        scope.validate()?;
        if secret_reference.scope_digest() != scope.digest() {
            return Err(AwsFirehoseError::ScopeMismatch);
        }
        if secret_reference.is_revoked() {
            return Err(AwsFirehoseError::InvalidSecretReference);
        }
        if !consent.is_active_at(now_epoch_seconds) {
            return Err(if consent.is_revoked() {
                AwsFirehoseError::ConsentRevoked
            } else {
                AwsFirehoseError::ConsentExpired
            });
        }
        let service_definition = AwsFirehoseDeliveryServiceDefinition::new();
        service_definition.validate()?;
        let provider_definition = provider.definition().clone();
        let registration = AwsFirehoseRegistration::new(
            &scope,
            &secret_reference,
            &consent,
            &provider_definition,
            Revision::new(1)?,
        )?;
        Ok(Self {
            scope,
            secret_reference,
            consent,
            provider,
            service_definition,
            registration,
            now_epoch_seconds,
        })
    }

    pub fn service_definition(&self) -> &AwsFirehoseDeliveryServiceDefinition {
        &self.service_definition
    }

    pub fn provider_definition(&self) -> &AwsFirehoseProviderDefinition {
        self.provider.definition()
    }

    pub fn into_provider(self) -> AwsFirehoseProvider<T> {
        self.provider
    }

    pub fn scope(&self) -> &AwsFirehoseDeliveryScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn registration(&self) -> &AwsFirehoseRegistration {
        &self.registration
    }

    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            api_version: API_VERSION.to_owned(),
            api_revision: PROVIDER_API_REVISION.to_owned(),
            operations: vec![
                AwsFirehoseOperation::ListDeliveryStreams,
                AwsFirehoseOperation::DescribeDeliveryStream,
            ],
            max_pages: MAX_PAGES,
            max_page_size: MAX_PAGE_SIZE,
            max_response_bytes: MAX_RESPONSE_BYTES,
            read_only: true,
            live_execution: false,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        }
    }

    pub fn describe_scope(&self) -> &AwsFirehoseDeliveryScope {
        &self.scope
    }

    pub fn default_request(
        &self,
        _observed_at_epoch_seconds: u64,
    ) -> Result<AwsFirehoseReadRequest> {
        AwsFirehoseReadRequest::new(&self.scope, MAX_PAGE_SIZE, MAX_PAGES)
    }

    pub fn default_read_request(&self) -> Result<AwsFirehoseReadRequest> {
        self.default_request(self.now_epoch_seconds)
    }

    pub fn read_bounded(
        &mut self,
        request: AwsFirehoseReadRequest,
    ) -> Result<AwsFirehoseReadEvidence> {
        self.ensure_active()?;
        request.validate_against(&self.scope)?;
        let mut cursor = None;
        let mut cursor_digests = Vec::new();
        let mut seen_cursors = BTreeSet::new();
        let mut pages_observed = 0_u16;
        let mut streams_observed = 0_u16;
        let mut list_digests = Vec::new();
        let mut response_bytes = 0_u64;
        let (list_digest, stream_names, next_cursor, list_provenance) = loop {
            if pages_observed >= request.max_pages {
                let list_digest = Digest::from_parts(
                    "aws-firehose-list-page-chain/v1",
                    &[(
                        "pages",
                        list_digests
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(","),
                    )],
                );
                let evidence = AwsFirehoseReadEvidence::new(
                    &self.scope,
                    self.provider.definition(),
                    &request,
                    AwsFirehoseEvidenceState::Partial,
                    false,
                    pages_observed,
                    streams_observed,
                    cursor_digests,
                    list_digest,
                    None,
                    None,
                    Some(FailureEvidence::from_category("page_cap")),
                    response_bytes,
                    pages_observed,
                    self.provider.provenance(),
                );
                return Ok(evidence);
            }
            let list_request = ListDeliveryStreamsRequest::new(
                self.scope.provider_scope(),
                request.limit,
                cursor.clone(),
            )
            .map_err(|_| AwsFirehoseError::InvalidRequest)?;
            let response = match self.provider.list_delivery_streams(&list_request) {
                Ok(response) => response,
                Err(error) => {
                    if matches!(error, AwsFirehoseTransportError::InvalidResponse) {
                        return Err(AwsFirehoseError::TamperedEvidence);
                    }
                    let state = state_for_transport(&error);
                    let evidence = AwsFirehoseReadEvidence::new(
                        &self.scope,
                        self.provider.definition(),
                        &request,
                        state,
                        false,
                        pages_observed,
                        streams_observed,
                        cursor_digests,
                        Digest::from_parts(
                            "aws-firehose-list-page-chain/v1",
                            &[(
                                "pages",
                                list_digests
                                    .iter()
                                    .map(ToString::to_string)
                                    .collect::<Vec<_>>()
                                    .join(","),
                            )],
                        ),
                        None,
                        None,
                        Some(FailureEvidence::from_transport(&error)),
                        response_bytes,
                        pages_observed,
                        self.provider.provenance(),
                    );
                    return Ok(evidence);
                }
            };
            pages_observed = pages_observed.saturating_add(1);
            streams_observed = streams_observed
                .saturating_add(u16::try_from(response.stream_names.len()).unwrap_or(u16::MAX));
            response_bytes = response_bytes.saturating_add(response.response_bytes);
            list_digests.push(response.response_digest.clone());
            if let Some(next) = &response.next_cursor {
                if !seen_cursors.insert(next.token_digest().clone()) {
                    return Err(AwsFirehoseError::ReplayDetected);
                }
                cursor_digests.push(next.token_digest().clone());
            }
            if response_bytes > MAX_RESPONSE_BYTES {
                let list_digest = Digest::from_parts(
                    "aws-firehose-list-page-chain/v1",
                    &[(
                        "pages",
                        list_digests
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(","),
                    )],
                );
                return Ok(AwsFirehoseReadEvidence::new(
                    &self.scope,
                    self.provider.definition(),
                    &request,
                    AwsFirehoseEvidenceState::Partial,
                    false,
                    pages_observed,
                    streams_observed,
                    cursor_digests,
                    list_digest,
                    None,
                    None,
                    Some(FailureEvidence::from_category("response_byte_cap")),
                    MAX_RESPONSE_BYTES,
                    pages_observed,
                    response.provenance,
                ));
            }
            let target_found = response
                .stream_names
                .iter()
                .any(|name| name == self.scope.provider_scope().target_stream());
            if target_found {
                break (
                    Digest::from_parts(
                        "aws-firehose-list-page-chain/v1",
                        &[(
                            "pages",
                            list_digests
                                .iter()
                                .map(ToString::to_string)
                                .collect::<Vec<_>>()
                                .join(","),
                        )],
                    ),
                    response.stream_names,
                    response.next_cursor,
                    response.provenance,
                );
            }
            match response.next_cursor {
                Some(next) => {
                    cursor = Some(next);
                }
                None => {
                    break (
                        Digest::from_parts(
                            "aws-firehose-list-page-chain/v1",
                            &[(
                                "pages",
                                list_digests
                                    .iter()
                                    .map(ToString::to_string)
                                    .collect::<Vec<_>>()
                                    .join(","),
                            )],
                        ),
                        Vec::new(),
                        None,
                        response.provenance,
                    );
                }
            }
        };

        let list_complete = next_cursor.is_none();
        if next_cursor.is_some() {
            return Ok(AwsFirehoseReadEvidence::new(
                &self.scope,
                self.provider.definition(),
                &request,
                AwsFirehoseEvidenceState::Partial,
                false,
                pages_observed,
                streams_observed,
                cursor_digests,
                list_digest,
                None,
                None,
                Some(FailureEvidence::from_category("pagination_incomplete")),
                response_bytes,
                pages_observed,
                list_provenance,
            ));
        }
        if !stream_names
            .iter()
            .any(|name| name == self.scope.provider_scope().target_stream())
        {
            return Ok(AwsFirehoseReadEvidence::new(
                &self.scope,
                self.provider.definition(),
                &request,
                AwsFirehoseEvidenceState::NotFound,
                true,
                pages_observed,
                streams_observed,
                cursor_digests,
                list_digest,
                None,
                None,
                Some(FailureEvidence::from_category("not_found")),
                response_bytes,
                pages_observed,
                list_provenance,
            ));
        }

        let describe_request = DescribeDeliveryStreamRequest::new(self.scope.provider_scope());
        let describe_response = match self.provider.describe_delivery_stream(&describe_request) {
            Ok(response) => response,
            Err(error) => {
                if matches!(error, AwsFirehoseTransportError::InvalidResponse) {
                    return Err(AwsFirehoseError::TamperedEvidence);
                }
                return Ok(AwsFirehoseReadEvidence::new(
                    &self.scope,
                    self.provider.definition(),
                    &request,
                    state_for_transport(&error),
                    list_complete,
                    pages_observed,
                    streams_observed,
                    cursor_digests,
                    list_digest,
                    None,
                    None,
                    Some(FailureEvidence::from_transport(&error)),
                    response_bytes,
                    pages_observed.saturating_add(1),
                    list_provenance,
                ));
            }
        };
        response_bytes = response_bytes.saturating_add(describe_response.response_bytes);
        if response_bytes > MAX_RESPONSE_BYTES {
            return Ok(AwsFirehoseReadEvidence::new(
                &self.scope,
                self.provider.definition(),
                &request,
                AwsFirehoseEvidenceState::Partial,
                false,
                pages_observed,
                streams_observed,
                cursor_digests,
                list_digest,
                Some(describe_response.response_digest),
                None,
                Some(FailureEvidence::from_category("response_byte_cap")),
                MAX_RESPONSE_BYTES,
                pages_observed.saturating_add(1),
                list_provenance,
            ));
        }
        if describe_response.observation.version_id
            != *self.scope.provider_scope().stream_version_id()
        {
            return Err(AwsFirehoseError::StreamVersionDrift);
        }
        if describe_response.observation.source_revision
            != self.scope.provider_scope().source_revision()
        {
            return Err(AwsFirehoseError::SourceRevisionDrift);
        }
        if describe_response.observation.destinations.len() != 1 {
            return Err(AwsFirehoseError::DestinationAmbiguous);
        }
        let stream = StreamEvidence::from_observation(&describe_response.observation)?;
        let (state, failure) = match (
            describe_response.observation.status,
            stream.destination.health,
        ) {
            (_, DestinationHealth::Unknown) => (
                AwsFirehoseEvidenceState::ProviderUnknown,
                Some(FailureEvidence::from_category("destination_health_unknown")),
            ),
            (StreamStatus::Active, DestinationHealth::Healthy) => {
                (AwsFirehoseEvidenceState::Complete, None)
            }
            (StreamStatus::Creating, _) => (AwsFirehoseEvidenceState::Creating, None),
            (StreamStatus::Deleting, _) => (AwsFirehoseEvidenceState::Deleting, None),
            (StreamStatus::DeletingFailed, _) => (AwsFirehoseEvidenceState::DeletingFailed, None),
            (StreamStatus::CreatingFailed, _) => (AwsFirehoseEvidenceState::CreatingFailed, None),
            (_, _) => (
                AwsFirehoseEvidenceState::ProviderUnknown,
                Some(FailureEvidence::from_category("destination_unhealthy")),
            ),
        };
        Ok(AwsFirehoseReadEvidence::new(
            &self.scope,
            self.provider.definition(),
            &request,
            state,
            list_complete,
            pages_observed,
            streams_observed,
            cursor_digests,
            list_digest,
            Some(describe_response.response_digest),
            Some(stream),
            failure,
            response_bytes,
            pages_observed.saturating_add(1),
            list_provenance,
        ))
    }

    pub fn read(&mut self, request: AwsFirehoseReadRequest) -> Result<AwsFirehoseReadEvidence> {
        self.read_bounded(request)
    }

    pub fn propose(
        &mut self,
        request: AwsFirehoseReadRequest,
    ) -> Result<AwsFirehoseDeliveryProposal> {
        let evidence = self.read_bounded(request.clone())?;
        Ok(AwsFirehoseDeliveryProposal::from_evidence(
            &self.scope,
            &self.registration,
            self.provider.definition(),
            &request,
            evidence,
        ))
    }

    pub fn verify(&self, proposal: &AwsFirehoseDeliveryProposal) -> VerificationReport {
        let mut failures = Vec::new();
        if let Err(error) = proposal.validate_integrity() {
            failures.push(error.to_string());
        }
        if proposal.registration_digest != *self.registration.registration_digest() {
            failures.push("registration_digest_mismatch".to_owned());
        }
        if proposal.provider_definition_digest != self.provider.definition().provider_digest {
            failures.push("provider_digest_mismatch".to_owned());
        }
        VerificationReport {
            valid: failures.is_empty(),
            review_eligible: failures.is_empty() && proposal.state.is_complete(),
            failures,
            evidence_digest: proposal.evidence.digests.evidence_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
        }
    }

    pub fn consumer(&self) -> Result<MissionAwsFirehoseConsumer> {
        MissionAwsFirehoseConsumer::new(self.scope.clone(), self.registration.clone()).map_err(
            |error| match error {
                crate::consumer::ConsumerError::Service(error) => error,
                _ => AwsFirehoseError::InvalidRegistration,
            },
        )
    }

    pub fn revoke_registration(
        &mut self,
        reason: impl AsRef<str>,
    ) -> Result<RegistrationTransition> {
        self.registration.revoke(reason)
    }

    pub fn reverse_registration(
        &mut self,
        reason: impl AsRef<str>,
    ) -> Result<RegistrationTransition> {
        self.registration.reverse(reason)
    }

    pub fn restore_registration(
        &mut self,
        reason: impl AsRef<str>,
    ) -> Result<RegistrationTransition> {
        self.registration.restore(reason)
    }

    pub fn revoke_secret_reference(&mut self) -> Result<()> {
        self.secret_reference.revoke()
    }

    pub fn revoke_consent(&mut self) -> Result<()> {
        self.consent.revoke()
    }

    fn ensure_active(&self) -> Result<()> {
        self.registration.validate()?;
        if !self.registration.is_active() {
            return Err(match self.registration.state() {
                RegistrationState::Revoked => AwsFirehoseError::RegistrationRevoked,
                RegistrationState::Reversed => AwsFirehoseError::RegistrationReversed,
                RegistrationState::Active => AwsFirehoseError::RegistrationInactive,
            });
        }
        if self.secret_reference.is_revoked() {
            return Err(AwsFirehoseError::RegistrationRevoked);
        }
        if !self.consent.is_active_at(self.now_epoch_seconds) {
            return Err(if self.consent.is_revoked() {
                AwsFirehoseError::ConsentRevoked
            } else {
                AwsFirehoseError::ConsentExpired
            });
        }
        Ok(())
    }
}

fn state_for_transport(error: &AwsFirehoseTransportError) -> AwsFirehoseEvidenceState {
    match error {
        AwsFirehoseTransportError::NotFound => AwsFirehoseEvidenceState::NotFound,
        AwsFirehoseTransportError::Unauthorized
        | AwsFirehoseTransportError::Forbidden
        | AwsFirehoseTransportError::AccessLost => AwsFirehoseEvidenceState::AccessLoss,
        AwsFirehoseTransportError::Throttled { .. } => AwsFirehoseEvidenceState::Throttled,
        AwsFirehoseTransportError::Timeout => AwsFirehoseEvidenceState::Timeout,
        AwsFirehoseTransportError::Partial => AwsFirehoseEvidenceState::Partial,
        AwsFirehoseTransportError::BlockedEnv
        | AwsFirehoseTransportError::BadRequest
        | AwsFirehoseTransportError::Unknown
        | AwsFirehoseTransportError::InvalidResponse => AwsFirehoseEvidenceState::ProviderUnknown,
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityDescription {
    pub service_id: String,
    pub provider_id: String,
    pub api_version: String,
    pub api_revision: String,
    pub operations: Vec<AwsFirehoseOperation>,
    pub max_pages: u16,
    pub max_page_size: u16,
    pub max_response_bytes: u64,
    pub read_only: bool,
    pub live_execution: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

pub type AwsFirehoseCapabilityDescription = CapabilityDescription;
pub type AwsFirehoseReadResult = AwsFirehoseReadEvidence;
pub type AwsFirehoseProposal = AwsFirehoseDeliveryProposal;
pub type AwsFirehoseService = AwsFirehoseDeliveryService<crate::provider::BlockedEnvTransport>;

trait ScopeDigestExt {
    fn scope_digest(&self) -> &Digest;
}

impl ScopeDigestExt for AwsFirehoseDeliveryScope {
    fn scope_digest(&self) -> &Digest {
        self.digest()
    }
}

#[allow(dead_code)]
fn _permission_snapshot_type_is_kept_typed(snapshot: &PermissionSnapshot) -> &Digest {
    snapshot.digest()
}

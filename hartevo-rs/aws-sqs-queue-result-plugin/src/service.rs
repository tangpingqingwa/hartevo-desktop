//! Bounded SQS queue/DLQ read, proposal, recording, and verification service.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::consumer::MissionAwsSqsConsumer;
use crate::error::{AwsSqsQueueError, AwsSqsQueueTransportError, Result};
use crate::model::{
    ApproximateQueueCounts, AwsSqsQueueScope, Cursor, Digest, EncryptionPosture,
    PermissionSnapshot, QueueAttributesProjection, QueueKind, QueueListFilter, RedriveAllowPosture,
    RedrivePosture, Revision, SecretReference, TransportProvenance,
};
use crate::provider::{
    AwsSqsProvider, AwsSqsProviderDefinition, GetQueueAttributesRequest,
    GetQueueAttributesResponse, GetQueueUrlRequest, GetQueueUrlResponse,
    ListDeadLetterSourceQueuesRequest, ListDeadLetterSourceQueuesResponse, ListQueuesRequest,
    ListQueuesResponse,
};
use crate::{
    CONTRACT_VERSION, MAX_COUNT_AGE_SECONDS, MAX_IDENTIFIER_BYTES, MAX_PAGE_SIZE, MAX_PAGES,
    PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID, contract_digest,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
    Reversed,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationTransitionEvidence {
    pub previous_status: RegistrationStatus,
    pub new_status: RegistrationStatus,
    pub registration_revision: Revision,
    pub transition_digest: Digest,
}

impl RegistrationTransitionEvidence {
    fn new(
        previous_status: RegistrationStatus,
        new_status: RegistrationStatus,
        registration_revision: Revision,
    ) -> Self {
        Self {
            previous_status,
            new_status,
            registration_revision,
            transition_digest: Digest::from_parts(
                "aws-sqs-registration-transition/v1",
                &[
                    ("previous", format!("{previous_status:?}")),
                    ("new", format!("{new_status:?}")),
                    ("revision", registration_revision.get().to_string()),
                ],
            ),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AwsSqsQueueRegistration {
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_revision: u64,
    provider_release: String,
    provider_digest: Digest,
    api_digest: Digest,
    queue_digest: Digest,
    scope_digest: Digest,
    permission_digest: Digest,
    evidence_digest: Digest,
    secret_reference_digest: Digest,
    registration_revision: Revision,
    status: RegistrationStatus,
    registration_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationBody<'a> {
    plugin_version: &'a str,
    contract_version: &'a str,
    contract_digest: &'a Digest,
    provider_id: &'a str,
    provider_revision: u64,
    provider_release: &'a str,
    provider_digest: &'a Digest,
    api_digest: &'a Digest,
    queue_digest: &'a Digest,
    scope_digest: &'a Digest,
    permission_digest: &'a Digest,
    evidence_digest: &'a Digest,
    secret_reference_digest: &'a Digest,
    registration_revision: Revision,
    status: RegistrationStatus,
}

impl AwsSqsQueueRegistration {
    fn new(
        scope: &AwsSqsQueueScope,
        secret_reference: &SecretReference,
        permission_snapshot: &PermissionSnapshot,
        provider: &AwsSqsProviderDefinition,
    ) -> Result<Self> {
        let evidence_digest = Digest::from_parts(
            "aws-sqs-evidence-policy/v1",
            &[
                ("contract", CONTRACT_VERSION.to_owned()),
                ("max_pages", MAX_PAGES.to_string()),
                ("max_page_size", MAX_PAGE_SIZE.to_string()),
                ("max_response_bytes", crate::MAX_RESPONSE_BYTES.to_string()),
                (
                    "max_approximate_count",
                    crate::MAX_APPROXIMATE_COUNT.to_string(),
                ),
                ("count_freshness_seconds", MAX_COUNT_AGE_SECONDS.to_string()),
                ("messages", "excluded".to_owned()),
                ("effects", "excluded".to_owned()),
            ],
        );
        let mut registration = Self {
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: provider.provider_id.clone(),
            provider_revision: provider.provider_revision,
            provider_release: provider.release.clone(),
            provider_digest: provider.provider_digest.clone(),
            api_digest: provider.capability_digest.clone(),
            queue_digest: scope.queue_digest(),
            scope_digest: scope.digest(),
            permission_digest: permission_snapshot.digest().clone(),
            evidence_digest,
            secret_reference_digest: secret_reference.digest().clone(),
            registration_revision: Revision::new(1)?,
            status: RegistrationStatus::Active,
            registration_digest: Digest::zero(),
        };
        registration.registration_digest = registration.recomputed_digest();
        Ok(registration)
    }

    pub fn is_active(&self) -> bool {
        self.status == RegistrationStatus::Active
    }

    pub const fn status(&self) -> RegistrationStatus {
        self.status
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

    pub fn queue_digest(&self) -> &Digest {
        &self.queue_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }

    pub fn secret_reference_digest(&self) -> &Digest {
        &self.secret_reference_digest
    }

    pub const fn registration_revision(&self) -> Revision {
        self.registration_revision
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn recomputed_digest(&self) -> Digest {
        crate::model::digest_serialized(&RegistrationBody {
            plugin_version: &self.plugin_version,
            contract_version: &self.contract_version,
            contract_digest: &self.contract_digest,
            provider_id: &self.provider_id,
            provider_revision: self.provider_revision,
            provider_release: &self.provider_release,
            provider_digest: &self.provider_digest,
            api_digest: &self.api_digest,
            queue_digest: &self.queue_digest,
            scope_digest: &self.scope_digest,
            permission_digest: &self.permission_digest,
            evidence_digest: &self.evidence_digest,
            secret_reference_digest: &self.secret_reference_digest,
            registration_revision: self.registration_revision,
            status: self.status,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.provider_release.is_empty()
            || self.provider_digest.validate().is_err()
            || self.api_digest.validate().is_err()
            || self.queue_digest.validate().is_err()
            || self.scope_digest.validate().is_err()
            || self.permission_digest.validate().is_err()
            || self.evidence_digest.validate().is_err()
            || self.secret_reference_digest.validate().is_err()
            || self.registration_digest != self.recomputed_digest()
        {
            Err(AwsSqsQueueError::InvalidRegistration)
        } else {
            Ok(())
        }
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        let previous = self.status;
        if previous == RegistrationStatus::Reversed {
            return Err(AwsSqsQueueError::RegistrationReversed);
        }
        self.advance_revision()?;
        self.status = RegistrationStatus::Revoked;
        self.registration_digest = self.recomputed_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous,
            self.status,
            self.registration_revision,
        ))
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        let previous = self.status;
        if previous == RegistrationStatus::Reversed {
            return Err(AwsSqsQueueError::RegistrationReversed);
        }
        self.advance_revision()?;
        self.status = RegistrationStatus::Reversed;
        self.registration_digest = self.recomputed_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous,
            self.status,
            self.registration_revision,
        ))
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        let previous = self.status;
        if previous == RegistrationStatus::Reversed {
            return Err(AwsSqsQueueError::RegistrationReversed);
        }
        if previous == RegistrationStatus::Active {
            return Err(AwsSqsQueueError::InvalidRegistration);
        }
        self.advance_revision()?;
        self.status = RegistrationStatus::Active;
        self.registration_digest = self.recomputed_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous,
            self.status,
            self.registration_revision,
        ))
    }

    fn advance_revision(&mut self) -> Result<()> {
        let next = self
            .registration_revision
            .get()
            .checked_add(1)
            .ok_or(AwsSqsQueueError::InvalidRegistration)?;
        self.registration_revision = Revision::new(next)?;
        Ok(())
    }
}

impl fmt::Debug for AwsSqsQueueRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsSqsQueueRegistration")
            .field("provider_id", &self.provider_id)
            .field("provider_revision", &self.provider_revision)
            .field("queue_digest", &self.queue_digest)
            .field("scope_digest", &self.scope_digest)
            .field("permission_digest", &self.permission_digest)
            .field("secret_reference_digest", &self.secret_reference_digest)
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("registration_digest", &self.registration_digest)
            .finish()
    }
}

impl Serialize for AwsSqsQueueRegistration {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("AwsSqsQueueRegistration", 16)?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("providerRelease", &self.provider_release)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("apiDigest", &self.api_digest)?;
        state.serialize_field("queueDigest", &self.queue_digest)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest)?;
        state.serialize_field("evidenceDigest", &self.evidence_digest)?;
        state.serialize_field("secretReferenceDigest", &self.secret_reference_digest)?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsSqsQueueCapabilities {
    pub service_id: &'static str,
    pub provider_id: &'static str,
    pub operations: [&'static str; 13],
    pub allowlisted_api_operations: [&'static str; 4],
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub live_execution: bool,
    pub connected: bool,
    pub native: bool,
    pub external_writes: bool,
    pub raw_queue_attributes: bool,
    pub message_bodies: bool,
    pub message_attributes: bool,
    pub approximate_count_delivery_proof: bool,
    pub kernel_authority: bool,
    pub outcome_authority: bool,
}

impl AwsSqsQueueCapabilities {
    pub const fn layer_one() -> Self {
        Self {
            service_id: SERVICE_ID,
            provider_id: PROVIDER_ID,
            operations: [
                "describe_capabilities",
                "describe_scope",
                "register",
                "read_list_queues",
                "read_get_queue_url",
                "read_get_queue_attributes",
                "read_list_dead_letter_source_queues",
                "propose",
                "record",
                "verify",
                "revoke_registration",
                "reverse_registration",
                "restore_registration",
            ],
            allowlisted_api_operations: [
                "ListQueues",
                "GetQueueUrl",
                "GetQueueAttributes",
                "ListDeadLetterSourceQueues",
            ],
            read_only: true,
            proposal_only: true,
            recording_only: true,
            live_execution: false,
            connected: false,
            native: false,
            external_writes: false,
            raw_queue_attributes: false,
            message_bodies: false,
            message_attributes: false,
            approximate_count_delivery_proof: false,
            kernel_authority: false,
            outcome_authority: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueFailureClass {
    None,
    BlockedEnv,
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    RateLimited,
    Timeout,
    AccessLoss,
    Partial,
    InvalidResponse,
    ServerError,
    QueueReplaced,
    AttributeDrift,
    StaleObservation,
    PaginationLoop,
    ProviderUnknown,
    RegistrationRevoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureEvidence {
    pub classification: QueueFailureClass,
    pub status_code: Option<u16>,
    pub retry_after_seconds: Option<u64>,
}

impl FailureEvidence {
    pub const fn classified(classification: QueueFailureClass) -> Self {
        Self {
            classification,
            status_code: None,
            retry_after_seconds: None,
        }
    }

    pub const fn from_transport(error: &AwsSqsQueueTransportError) -> Self {
        let classification = match error {
            AwsSqsQueueTransportError::BlockedEnv => QueueFailureClass::BlockedEnv,
            AwsSqsQueueTransportError::BadRequest => QueueFailureClass::BadRequest,
            AwsSqsQueueTransportError::Unauthorized => QueueFailureClass::Unauthorized,
            AwsSqsQueueTransportError::Forbidden => QueueFailureClass::Forbidden,
            AwsSqsQueueTransportError::NotFound => QueueFailureClass::NotFound,
            AwsSqsQueueTransportError::RateLimited { .. } => QueueFailureClass::RateLimited,
            AwsSqsQueueTransportError::ServerError { .. } => QueueFailureClass::ServerError,
            AwsSqsQueueTransportError::Timeout => QueueFailureClass::Timeout,
            AwsSqsQueueTransportError::AccessLost => QueueFailureClass::AccessLoss,
            AwsSqsQueueTransportError::Partial => QueueFailureClass::Partial,
            AwsSqsQueueTransportError::InvalidResponse => QueueFailureClass::InvalidResponse,
        };
        Self {
            classification,
            status_code: error.status_code(),
            retry_after_seconds: error.retry_after_seconds(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueEvidenceState {
    Healthy,
    Partial,
    NotFound,
    AccessLoss,
    Throttled,
    Timeout,
    QueueReplaced,
    AttributeDrift,
    Stale,
    PaginationLoop,
    ProviderUnknown,
    RegistrationRevoked,
}

pub type QueueHealthState = QueueEvidenceState;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDigests {
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub queue_digest: Digest,
    pub secret_reference_digest: Digest,
    pub list_queues_digest: Digest,
    pub get_queue_url_digest: Option<Digest>,
    pub get_queue_attributes_digest: Option<Digest>,
    pub list_dead_letter_source_queues_digest: Option<Digest>,
    pub cursor_digest: Option<Digest>,
    pub evidence_digest: Digest,
}

impl EvidenceDigests {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider_digest: Digest,
        permission_digest: Digest,
        scope_digest: Digest,
        queue_digest: Digest,
        secret_reference_digest: Digest,
        list_queues_digest: Digest,
        get_queue_url_digest: Option<Digest>,
        get_queue_attributes_digest: Option<Digest>,
        list_dead_letter_source_queues_digest: Option<Digest>,
        cursor_digest: Option<Digest>,
    ) -> Self {
        let mut result = Self {
            provider_digest,
            permission_digest,
            scope_digest,
            queue_digest,
            secret_reference_digest,
            list_queues_digest,
            get_queue_url_digest,
            get_queue_attributes_digest,
            list_dead_letter_source_queues_digest,
            cursor_digest,
            evidence_digest: Digest::zero(),
        };
        result.evidence_digest = result.recomputed_digest();
        result
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-sqs-evidence-digests/v1",
            &[
                ("provider", self.provider_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("queue", self.queue_digest.as_str().to_owned()),
                (
                    "secret_reference",
                    self.secret_reference_digest.as_str().to_owned(),
                ),
                ("list_queues", self.list_queues_digest.as_str().to_owned()),
                (
                    "get_queue_url",
                    self.get_queue_url_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "get_queue_attributes",
                    self.get_queue_attributes_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "list_dead_letter_source_queues",
                    self.list_dead_letter_source_queues_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "cursor",
                    self.cursor_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
            ],
        )
    }

    pub fn validate(&self) -> Result<()> {
        for digest in [
            &self.provider_digest,
            &self.permission_digest,
            &self.scope_digest,
            &self.queue_digest,
            &self.secret_reference_digest,
            &self.list_queues_digest,
            &self.evidence_digest,
        ] {
            digest.validate()?;
        }
        for digest in [
            self.get_queue_url_digest.as_ref(),
            self.get_queue_attributes_digest.as_ref(),
            self.list_dead_letter_source_queues_digest.as_ref(),
            self.cursor_digest.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            digest.validate()?;
        }
        // `evidence_digest` is sealed by the containing queue evidence after
        // all posture fields are assembled. The outer evidence digest binds
        // this core digest set together, so it is intentionally validated for
        // shape here and compared by `AwsSqsQueueEvidence::validate_integrity`.
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsSqsQueueEvidence {
    pub scope_digest: Digest,
    pub queue_digest: Digest,
    pub queue_name_digest: Option<Digest>,
    pub queue_url_digest: Option<Digest>,
    pub queue_arn_digest: Option<Digest>,
    pub dead_letter_queue_digest: Option<Digest>,
    pub dead_letter_source_queues: Vec<crate::model::DeadLetterSourceProjection>,
    pub queue_attributes: Option<QueueAttributesProjection>,
    pub approximate_counts: Option<ApproximateQueueCounts>,
    pub counts_age_seconds: Option<u64>,
    pub counts_fresh: bool,
    pub queue_kind: Option<QueueKind>,
    pub encryption: Option<EncryptionPosture>,
    pub redrive: Option<RedrivePosture>,
    pub redrive_allow: Option<RedriveAllowPosture>,
    pub list_pages: u16,
    pub list_complete: bool,
    pub truncated: bool,
    pub failure: Option<FailureEvidence>,
    pub state: QueueEvidenceState,
    pub provenance: TransportProvenance,
    pub evidence: EvidenceDigests,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub approximate_counts_are_delivery_proof: bool,
    pub message_bodies_retained: bool,
    pub message_attributes_retained: bool,
}

impl AwsSqsQueueEvidence {
    #[allow(clippy::too_many_arguments)]
    fn new(
        scope: &AwsSqsQueueScope,
        queue_attributes: Option<QueueAttributesProjection>,
        dead_letter_source_queues: Vec<crate::model::DeadLetterSourceProjection>,
        counts_age_seconds: Option<u64>,
        counts_fresh: bool,
        list_pages: u16,
        list_complete: bool,
        truncated: bool,
        failure: Option<FailureEvidence>,
        state: QueueEvidenceState,
        provenance: TransportProvenance,
        evidence: EvidenceDigests,
    ) -> Self {
        let queue_name_digest = Some(scope.queue().name().digest());
        let queue_url_digest = scope.queue().url().map(|value| value.digest());
        let queue_arn_digest = scope.queue().arn().map(|value| value.digest());
        let approximate_counts = queue_attributes
            .as_ref()
            .map(|attributes| attributes.counts.clone());
        let queue_kind = queue_attributes.as_ref().map(|attributes| attributes.kind);
        let encryption = queue_attributes
            .as_ref()
            .map(|attributes| attributes.encryption.clone());
        let redrive = queue_attributes
            .as_ref()
            .map(|attributes| attributes.redrive.clone());
        let redrive_allow = queue_attributes
            .as_ref()
            .map(|attributes| attributes.redrive_allow.clone());
        let mut result = Self {
            scope_digest: scope.digest(),
            queue_digest: scope.queue_digest(),
            queue_name_digest,
            queue_url_digest,
            queue_arn_digest,
            dead_letter_queue_digest: scope.dead_letter_relationship_digest(),
            dead_letter_source_queues,
            queue_attributes,
            approximate_counts,
            counts_age_seconds,
            counts_fresh,
            queue_kind,
            encryption,
            redrive,
            redrive_allow,
            list_pages,
            list_complete,
            truncated,
            failure,
            state,
            provenance,
            evidence,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            approximate_counts_are_delivery_proof: false,
            message_bodies_retained: false,
            message_attributes_retained: false,
        };
        result.seal();
        result
    }

    fn seal(&mut self) {
        self.evidence.evidence_digest = self.recomputed_digest();
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-sqs-queue-evidence/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("queue", self.queue_digest.as_str().to_owned()),
                (
                    "queue_name",
                    self.queue_name_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "queue_url",
                    self.queue_url_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "queue_arn",
                    self.queue_arn_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "dead_letter_queue",
                    self.dead_letter_queue_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "sources",
                    self.dead_letter_source_queues
                        .iter()
                        .map(|value| value.queue_digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                (
                    "attributes",
                    self.queue_attributes
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                (
                    "redrive_allow",
                    self.redrive_allow
                        .as_ref()
                        .map_or_else(String::new, |value| {
                            crate::model::digest_serialized(value).as_str().to_owned()
                        }),
                ),
                (
                    "counts",
                    self.approximate_counts
                        .as_ref()
                        .map_or_else(String::new, |value| {
                            crate::model::digest_serialized(value).as_str().to_owned()
                        }),
                ),
                (
                    "count_age",
                    self.counts_age_seconds
                        .map_or_else(String::new, |value| value.to_string()),
                ),
                ("counts_fresh", self.counts_fresh.to_string()),
                ("state", format!("{:?}", self.state)),
                (
                    "failure",
                    self.failure.as_ref().map_or_else(String::new, |value| {
                        crate::model::digest_serialized(value).as_str().to_owned()
                    }),
                ),
                ("list_pages", self.list_pages.to_string()),
                ("list_complete", self.list_complete.to_string()),
                ("truncated", self.truncated.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
                (
                    "evidence_digests",
                    self.evidence.recomputed_digest().as_str().to_owned(),
                ),
                ("connected", self.connected.to_string()),
                ("native", self.native.to_string()),
                ("first_party", self.first_party.to_string()),
                ("provider_receipt", self.provider_receipt.to_string()),
                (
                    "counts_delivery_proof",
                    self.approximate_counts_are_delivery_proof.to_string(),
                ),
                ("message_bodies", self.message_bodies_retained.to_string()),
                (
                    "message_attributes",
                    self.message_attributes_retained.to_string(),
                ),
            ],
        )
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.evidence.validate()?;
        for digest in [
            self.queue_digest.clone(),
            self.queue_name_digest.clone().unwrap_or_else(Digest::zero),
        ] {
            digest.validate()?;
        }
        if self.scope_digest != self.evidence.scope_digest
            || self.queue_digest != self.evidence.queue_digest
            || self.evidence.evidence_digest != self.recomputed_digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.provenance.is_connected()
            || self
                .approximate_counts
                .as_ref()
                .is_some_and(|counts| !counts.eventually_consistent || counts.delivery_proof)
            || self.approximate_counts_are_delivery_proof
            || self.message_bodies_retained
            || self.message_attributes_retained
            || (self.truncated && self.list_complete)
            || (self.counts_fresh && self.counts_age_seconds.is_none())
        {
            return Err(AwsSqsQueueError::TamperedEvidence);
        }
        if let Some(failure) = &self.failure
            && failure.classification == QueueFailureClass::None
        {
            return Err(AwsSqsQueueError::TamperedEvidence);
        }
        Ok(())
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub const fn is_review_only(&self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsSqsQueueProposal {
    pub service_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub state: QueueEvidenceState,
    pub queue_digest: Digest,
    pub dead_letter_queue_digest: Option<Digest>,
    pub queue_attributes: Option<QueueAttributesProjection>,
    pub redrive_allow: Option<RedriveAllowPosture>,
    pub approximate_counts: Option<ApproximateQueueCounts>,
    pub counts_fresh: bool,
    pub list_pages: u16,
    pub list_complete: bool,
    pub truncated: bool,
    pub failure: Option<FailureEvidence>,
    pub provenance: TransportProvenance,
    pub evidence: AwsSqsQueueEvidence,
    pub proposal_digest: Digest,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub approximate_counts_are_delivery_proof: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProposalBody {
    service_id: String,
    consumer_id: String,
    registration_digest: Digest,
    scope_digest: Digest,
    evidence_digest: Digest,
    queue_digest: Digest,
    state: QueueEvidenceState,
    review_only: bool,
    connected: bool,
    native: bool,
    first_party: bool,
    provider_receipt: bool,
    outcome_adopted: bool,
    work_product_adopted: bool,
    approximate_counts_are_delivery_proof: bool,
}

impl AwsSqsQueueProposal {
    fn new(
        registration: &AwsSqsQueueRegistration,
        scope: &AwsSqsQueueScope,
        evidence: AwsSqsQueueEvidence,
    ) -> Self {
        let mut result = Self {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: crate::CONSUMER_ID.to_owned(),
            registration_digest: registration.registration_digest().clone(),
            scope_digest: scope.digest(),
            state: evidence.state,
            queue_digest: evidence.queue_digest.clone(),
            dead_letter_queue_digest: evidence.dead_letter_queue_digest.clone(),
            queue_attributes: evidence.queue_attributes.clone(),
            redrive_allow: evidence.redrive_allow.clone(),
            approximate_counts: evidence.approximate_counts.clone(),
            counts_fresh: evidence.counts_fresh,
            list_pages: evidence.list_pages,
            list_complete: evidence.list_complete,
            truncated: evidence.truncated,
            failure: evidence.failure.clone(),
            provenance: evidence.provenance,
            evidence,
            proposal_digest: Digest::zero(),
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            approximate_counts_are_delivery_proof: false,
        };
        result.proposal_digest = result.recomputed_digest();
        result
    }

    pub fn recomputed_digest(&self) -> Digest {
        crate::model::digest_serialized(&ProposalBody {
            service_id: self.service_id.clone(),
            consumer_id: self.consumer_id.clone(),
            registration_digest: self.registration_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            evidence_digest: self.evidence.evidence.evidence_digest.clone(),
            queue_digest: self.queue_digest.clone(),
            state: self.state,
            review_only: self.review_only,
            connected: self.connected,
            native: self.native,
            first_party: self.first_party,
            provider_receipt: self.provider_receipt,
            outcome_adopted: self.outcome_adopted,
            work_product_adopted: self.work_product_adopted,
            approximate_counts_are_delivery_proof: self.approximate_counts_are_delivery_proof,
        })
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.evidence.validate_integrity()?;
        if self.service_id != SERVICE_ID
            || self.consumer_id != crate::CONSUMER_ID
            || self.scope_digest != self.evidence.scope_digest
            || self.queue_digest != self.evidence.queue_digest
            || self.state != self.evidence.state
            || self.queue_attributes != self.evidence.queue_attributes
            || self.redrive_allow != self.evidence.redrive_allow
            || self.approximate_counts != self.evidence.approximate_counts
            || self.counts_fresh != self.evidence.counts_fresh
            || self.list_pages != self.evidence.list_pages
            || self.list_complete != self.evidence.list_complete
            || self.truncated != self.evidence.truncated
            || self.failure != self.evidence.failure
            || self.provenance != self.evidence.provenance
            || !self.review_only
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.approximate_counts_are_delivery_proof
            || self.proposal_digest != self.recomputed_digest()
        {
            return Err(AwsSqsQueueError::TamperedEvidence);
        }
        Ok(())
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub const fn is_review_only(&self) -> bool {
        self.review_only
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailure {
    RegistrationInactive,
    RegistrationDigestMismatch,
    PermissionDigestMismatch,
    QueueDigestMismatch,
    ScopeDigestMismatch,
    EvidenceTampered,
    PartialEvidence,
    AccessLoss,
    QueueReplaced,
    AttributeDrift,
    StaleObservation,
    PaginationLoop,
    ProviderUnknown,
    Truncated,
    ApproximateCountsNotFresh,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub valid: bool,
    pub review_eligible: bool,
    pub failures: Vec<VerificationFailure>,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsSqsQueueRecord {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub state: QueueEvidenceState,
    pub failure: Option<FailureEvidence>,
    pub provenance: TransportProvenance,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub approximate_counts_are_delivery_proof: bool,
    pub recording_digest: Digest,
}

impl AwsSqsQueueRecord {
    fn new(idempotency_key_digest: Digest, proposal: &AwsSqsQueueProposal, replayed: bool) -> Self {
        let mut result = Self {
            idempotency_key_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            state: proposal.state,
            failure: proposal.failure.clone(),
            provenance: proposal.provenance,
            replayed,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            approximate_counts_are_delivery_proof: false,
            recording_digest: Digest::zero(),
        };
        result.recording_digest = result.recomputed_digest();
        result
    }

    pub(crate) fn new_for_consumer(
        idempotency_key_digest: Digest,
        proposal: &AwsSqsQueueProposal,
        replayed: bool,
    ) -> Self {
        Self::new(idempotency_key_digest, proposal, replayed)
    }

    fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-sqs-recording/v1",
            &[
                (
                    "idempotency",
                    self.idempotency_key_digest.as_str().to_owned(),
                ),
                ("proposal", self.proposal_digest.as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
                (
                    "failure",
                    self.failure.as_ref().map_or_else(String::new, |value| {
                        crate::model::digest_serialized(value).as_str().to_owned()
                    }),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.idempotency_key_digest.validate().is_err()
            || self.proposal_digest.validate().is_err()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.approximate_counts_are_delivery_proof
            || self.recording_digest != self.recomputed_digest()
        {
            Err(AwsSqsQueueError::TamperedEvidence)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AwsSqsQueueReadRequest {
    scope_digest: Digest,
    filter: QueueListFilter,
    max_pages: u16,
    cursor: Option<Cursor>,
    observed_at: DateTime<Utc>,
    request_digest: Digest,
}

impl AwsSqsQueueReadRequest {
    pub fn new(
        scope: &AwsSqsQueueScope,
        filter: QueueListFilter,
        max_pages: u16,
        observed_at: DateTime<Utc>,
        cursor: Option<Cursor>,
    ) -> Result<Self> {
        if max_pages == 0 || max_pages > MAX_PAGES {
            return Err(AwsSqsQueueError::InvalidRequest);
        }
        filter.validate_against(scope)?;
        if let Some(cursor) = &cursor {
            cursor.validate_against(scope, &filter)?;
        }
        Ok(Self {
            scope_digest: scope.digest(),
            request_digest: Digest::from_parts(
                "aws-sqs-queue-read-request/v1",
                &[
                    ("scope", scope.digest().as_str().to_owned()),
                    ("filter", filter.digest().as_str().to_owned()),
                    ("max_pages", max_pages.to_string()),
                    (
                        "cursor",
                        cursor
                            .as_ref()
                            .map_or_else(String::new, |value| value.token_digest().to_string()),
                    ),
                    ("observed_at", observed_at.to_rfc3339()),
                ],
            ),
            filter,
            max_pages,
            cursor,
            observed_at,
        })
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn filter(&self) -> &QueueListFilter {
        &self.filter
    }

    pub const fn max_pages(&self) -> u16 {
        self.max_pages
    }

    pub fn cursor(&self) -> Option<&Cursor> {
        self.cursor.as_ref()
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    fn validate_against(&self, scope: &AwsSqsQueueScope) -> Result<()> {
        if self.scope_digest != scope.digest() {
            return Err(AwsSqsQueueError::ScopeMismatch);
        }
        self.filter.validate_against(scope)?;
        if let Some(cursor) = &self.cursor {
            cursor.validate_against(scope, &self.filter)?;
        }
        Ok(())
    }
}

impl fmt::Debug for AwsSqsQueueReadRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsSqsQueueReadRequest")
            .field("scope_digest", &self.scope_digest)
            .field("filter", &self.filter)
            .field("max_pages", &self.max_pages)
            .field("cursor", &self.cursor)
            .field("observed_at", &self.observed_at)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

pub struct AwsSqsQueueService<T> {
    scope: AwsSqsQueueScope,
    secret_reference: SecretReference,
    permission_snapshot: PermissionSnapshot,
    provider: AwsSqsProvider<T>,
    registration: AwsSqsQueueRegistration,
    records: BTreeMap<Digest, AwsSqsQueueRecord>,
}

impl<T: crate::provider::AwsSqsTransport> fmt::Debug for AwsSqsQueueService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsSqsQueueService")
            .field("scope_digest", &self.scope.digest())
            .field("registration", &self.registration)
            .field("provider", &self.provider)
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl<T: crate::provider::AwsSqsTransport> AwsSqsQueueService<T> {
    pub fn new(
        scope: AwsSqsQueueScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        provider: AwsSqsProvider<T>,
        _registered_at: DateTime<Utc>,
    ) -> Result<Self> {
        crate::AwsSqsQueueContract::baseline().map_err(|_| AwsSqsQueueError::ContractDrift)?;
        scope.validate()?;
        secret_reference.validate(&scope)?;
        permission_snapshot.validate()?;
        provider.definition().validate()?;
        let registration = AwsSqsQueueRegistration::new(
            &scope,
            &secret_reference,
            &permission_snapshot,
            provider.definition(),
        )?;
        Ok(Self {
            scope,
            secret_reference,
            permission_snapshot,
            provider,
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn scope(&self) -> &AwsSqsQueueScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn permission_snapshot(&self) -> &PermissionSnapshot {
        &self.permission_snapshot
    }

    pub fn registration(&self) -> &AwsSqsQueueRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut AwsSqsQueueRegistration {
        &mut self.registration
    }

    pub fn provider(&self) -> &AwsSqsProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsSqsProvider<T> {
        &mut self.provider
    }

    pub fn is_active(&self) -> bool {
        self.registration.is_active()
    }

    pub fn describe_capabilities(&self) -> AwsSqsQueueCapabilities {
        AwsSqsQueueCapabilities::layer_one()
    }

    pub fn default_request(&self, observed_at: DateTime<Utc>) -> Result<AwsSqsQueueReadRequest> {
        let filter = QueueListFilter::for_scope(&self.scope, MAX_PAGE_SIZE)?;
        self.request(filter, MAX_PAGES, observed_at, None)
    }

    pub fn request(
        &self,
        filter: QueueListFilter,
        max_pages: u16,
        observed_at: DateTime<Utc>,
        cursor: Option<Cursor>,
    ) -> Result<AwsSqsQueueReadRequest> {
        AwsSqsQueueReadRequest::new(&self.scope, filter, max_pages, observed_at, cursor)
    }

    pub fn read_list_queues(&mut self, request: &ListQueuesRequest) -> Result<ListQueuesResponse> {
        self.ensure_active()?;
        self.provider
            .list_queues(request)
            .map_err(AwsSqsQueueError::Transport)
    }

    pub fn read_get_queue_url(
        &mut self,
        request: &GetQueueUrlRequest,
    ) -> Result<GetQueueUrlResponse> {
        self.ensure_active()?;
        self.provider
            .get_queue_url(request)
            .map_err(AwsSqsQueueError::Transport)
    }

    pub fn read_get_queue_attributes(
        &mut self,
        request: &GetQueueAttributesRequest,
    ) -> Result<GetQueueAttributesResponse> {
        self.ensure_active()?;
        self.provider
            .get_queue_attributes(request)
            .map_err(AwsSqsQueueError::Transport)
    }

    pub fn read_list_dead_letter_source_queues(
        &mut self,
        request: &ListDeadLetterSourceQueuesRequest,
    ) -> Result<ListDeadLetterSourceQueuesResponse> {
        self.ensure_active()?;
        self.provider
            .list_dead_letter_source_queues(request)
            .map_err(AwsSqsQueueError::Transport)
    }

    pub fn read(&mut self, request: AwsSqsQueueReadRequest) -> Result<AwsSqsQueueEvidence> {
        self.ensure_active()?;
        request.validate_against(&self.scope)?;

        let mut cursor = request.cursor().cloned();
        let mut page_number = cursor.as_ref().map_or(1, Cursor::page_number);
        let mut seen_cursors = BTreeSet::new();
        let mut list_page_digests = Vec::new();
        let mut list_pages = 0_u16;
        let mut list_complete = false;
        let mut truncated = false;
        let mut failure: Option<FailureEvidence> = None;
        let mut target_found = false;
        let mut name_match_with_different_url = false;
        let mut last_cursor_digest = None;

        for _ in 0..request.max_pages() {
            let list_request = ListQueuesRequest::new(
                &self.scope,
                request.filter().clone(),
                page_number,
                cursor.clone(),
            )?;
            match self.provider.list_queues(&list_request) {
                Ok(response) => {
                    list_pages = list_pages.saturating_add(1);
                    list_page_digests.push(response.digest());
                    for queue in &response.queues {
                        if queue.matches_scope(&self.scope) {
                            target_found = true;
                        } else if queue.matches_name(&self.scope) {
                            name_match_with_different_url = true;
                        }
                    }
                    if let Some(next_cursor) = response.next_cursor.clone() {
                        last_cursor_digest = Some(next_cursor.token_digest().clone());
                        if !seen_cursors.insert(next_cursor.token_digest().clone()) {
                            failure = Some(FailureEvidence::classified(
                                QueueFailureClass::PaginationLoop,
                            ));
                            break;
                        }
                        if list_pages >= request.max_pages() {
                            truncated = true;
                            failure = Some(FailureEvidence::classified(QueueFailureClass::Partial));
                            break;
                        }
                        page_number = page_number.saturating_add(1);
                        cursor = Some(next_cursor);
                    } else {
                        list_complete = true;
                        break;
                    }
                }
                Err(error) => {
                    failure = Some(FailureEvidence::from_transport(&error));
                    break;
                }
            }
        }

        if failure.is_none() && !list_complete {
            truncated = true;
            failure = Some(FailureEvidence::classified(QueueFailureClass::Partial));
        }
        if failure.is_none() && !target_found {
            failure = Some(FailureEvidence::classified(
                if name_match_with_different_url {
                    QueueFailureClass::QueueReplaced
                } else {
                    QueueFailureClass::NotFound
                },
            ));
        }

        let list_digest = Digest::from_parts(
            "aws-sqs-list-queues-evidence/v1",
            &[
                (
                    "pages",
                    list_page_digests
                        .iter()
                        .map(|value| value.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                ("page_count", list_pages.to_string()),
                ("complete", list_complete.to_string()),
            ],
        );

        let mut queue_attributes = None;
        let mut dead_letter_source_queues = Vec::new();
        let mut counts_age_seconds = None;
        let mut counts_fresh = false;
        let mut get_queue_url_digest = None;
        let mut get_queue_attributes_digest = None;
        let mut list_dead_letter_source_queues_digest = None;

        if failure.is_none() {
            match GetQueueUrlRequest::for_scope(&self.scope).and_then(|request| {
                self.provider
                    .get_queue_url(&request)
                    .map_err(AwsSqsQueueError::Transport)
            }) {
                Ok(response) => {
                    get_queue_url_digest = Some(response.digest());
                    let resolved_queue_url = response.queue_url.clone();
                    let queue_url_request =
                        GetQueueAttributesRequest::new(&self.scope, resolved_queue_url.clone());
                    match queue_url_request.and_then(|request| {
                        self.provider
                            .get_queue_attributes(&request)
                            .map_err(AwsSqsQueueError::Transport)
                    }) {
                        Ok(response) => {
                            get_queue_attributes_digest = Some(response.digest());
                            let attributes = response.attributes.clone();
                            let age = attributes.counts.age_at(request.observed_at());
                            counts_age_seconds = age;
                            counts_fresh = attributes.counts.is_fresh_at(request.observed_at());
                            queue_attributes = Some(attributes.clone());
                            if !attributes.matches_scope(&self.scope)
                                || attributes.identity().url() != Some(&resolved_queue_url)
                            {
                                failure = Some(FailureEvidence::classified(
                                    QueueFailureClass::QueueReplaced,
                                ));
                            } else if !counts_fresh {
                                failure = Some(FailureEvidence::classified(
                                    QueueFailureClass::StaleObservation,
                                ));
                            } else if let Err(classification) =
                                validate_dlq_posture(&self.scope, &attributes)
                            {
                                failure = Some(FailureEvidence::classified(classification));
                            } else if self.scope.dead_letter_queue().is_some() {
                                match self.read_dlq_sources(&response, &mut get_queue_url_digest) {
                                    Ok((digest, sources)) => {
                                        list_dead_letter_source_queues_digest = Some(digest);
                                        dead_letter_source_queues = sources;
                                        if !dead_letter_source_queues
                                            .iter()
                                            .any(|source| source.matches_scope(&self.scope))
                                        {
                                            failure = Some(FailureEvidence::classified(
                                                QueueFailureClass::AttributeDrift,
                                            ));
                                        }
                                    }
                                    Err(error) => failure = Some(error),
                                }
                            }
                        }
                        Err(error) => failure = Some(failure_from_error(&error)),
                    }
                }
                Err(error) => failure = Some(failure_from_error(&error)),
            }
        }

        let state = failure
            .as_ref()
            .map_or(QueueEvidenceState::Healthy, |value| {
                state_from_failure(value.classification)
            });
        let evidence_digests = crate::service::EvidenceDigests::new(
            self.provider.definition().provider_digest.clone(),
            self.permission_snapshot.digest().clone(),
            self.scope.digest(),
            self.scope.queue_digest(),
            self.secret_reference.digest().clone(),
            list_digest,
            get_queue_url_digest,
            get_queue_attributes_digest,
            list_dead_letter_source_queues_digest,
            last_cursor_digest,
        );
        Ok(AwsSqsQueueEvidence::new(
            &self.scope,
            queue_attributes,
            dead_letter_source_queues,
            counts_age_seconds,
            counts_fresh,
            list_pages,
            list_complete,
            truncated,
            failure,
            state,
            self.provider.provenance(),
            evidence_digests,
        ))
    }

    pub fn read_bounded(&mut self, request: AwsSqsQueueReadRequest) -> Result<AwsSqsQueueEvidence> {
        self.read(request)
    }

    pub fn propose(&mut self, request: AwsSqsQueueReadRequest) -> Result<AwsSqsQueueProposal> {
        self.ensure_active()?;
        let evidence = self.read(request)?;
        Ok(AwsSqsQueueProposal::new(
            &self.registration,
            &self.scope,
            evidence,
        ))
    }

    pub fn record(
        &mut self,
        proposal: &AwsSqsQueueProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<AwsSqsQueueRecord> {
        self.ensure_active()?;
        self.ensure_proposal_bound(proposal)?;
        let key = idempotency_key.as_ref();
        if key.is_empty() || key.len() > MAX_IDENTIFIER_BYTES || key.chars().any(char::is_control) {
            return Err(AwsSqsQueueError::InvalidRequest);
        }
        let key_digest = Digest::from_text(key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(AwsSqsQueueError::RecordingConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.recording_digest = replay.recomputed_digest();
            return Ok(replay);
        }
        let result = AwsSqsQueueRecord::new(key_digest.clone(), proposal, false);
        self.records.insert(key_digest, result.clone());
        Ok(result)
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn verify(&self, proposal: &AwsSqsQueueProposal) -> VerificationReport {
        let mut failures = Vec::new();
        if !self.registration.is_active() {
            failures.push(VerificationFailure::RegistrationInactive);
        }
        if self.registration.validate().is_err()
            || proposal.registration_digest != *self.registration.registration_digest()
        {
            failures.push(VerificationFailure::RegistrationDigestMismatch);
        }
        if proposal.evidence.evidence.permission_digest != *self.permission_snapshot.digest() {
            failures.push(VerificationFailure::PermissionDigestMismatch);
        }
        if proposal.queue_digest != self.scope.queue_digest() {
            failures.push(VerificationFailure::QueueDigestMismatch);
        }
        if proposal.scope_digest != self.scope.digest()
            || proposal.evidence.scope_digest != self.scope.digest()
        {
            failures.push(VerificationFailure::ScopeDigestMismatch);
        }
        if proposal.validate_integrity().is_err() {
            failures.push(VerificationFailure::EvidenceTampered);
        }
        if proposal.truncated || !proposal.list_complete {
            failures.push(VerificationFailure::Truncated);
        }
        match proposal
            .evidence
            .failure
            .as_ref()
            .map(|value| value.classification)
        {
            Some(
                QueueFailureClass::AccessLoss
                | QueueFailureClass::Unauthorized
                | QueueFailureClass::Forbidden,
            ) => failures.push(VerificationFailure::AccessLoss),
            Some(QueueFailureClass::QueueReplaced) => {
                failures.push(VerificationFailure::QueueReplaced);
            }
            Some(QueueFailureClass::AttributeDrift) => {
                failures.push(VerificationFailure::AttributeDrift);
            }
            Some(QueueFailureClass::StaleObservation) => {
                failures.push(VerificationFailure::StaleObservation);
            }
            Some(QueueFailureClass::PaginationLoop) => {
                failures.push(VerificationFailure::PaginationLoop);
            }
            Some(QueueFailureClass::Partial) => failures.push(VerificationFailure::PartialEvidence),
            Some(
                QueueFailureClass::BlockedEnv
                | QueueFailureClass::BadRequest
                | QueueFailureClass::NotFound
                | QueueFailureClass::RateLimited
                | QueueFailureClass::Timeout
                | QueueFailureClass::InvalidResponse
                | QueueFailureClass::ServerError
                | QueueFailureClass::ProviderUnknown
                | QueueFailureClass::RegistrationRevoked,
            ) => failures.push(VerificationFailure::ProviderUnknown),
            Some(QueueFailureClass::None) | None => {}
        }
        if !proposal.counts_fresh && proposal.approximate_counts.is_some() {
            failures.push(VerificationFailure::ApproximateCountsNotFresh);
        }
        failures.sort();
        failures.dedup();
        let valid = failures.is_empty();
        VerificationReport {
            valid,
            review_eligible: valid
                && proposal.list_complete
                && !proposal.truncated
                && proposal.counts_fresh
                && !proposal.approximate_counts_are_delivery_proof,
            failures,
            evidence_digest: proposal.evidence.evidence.evidence_digest.clone(),
        }
    }

    pub fn consumer(&self) -> Result<MissionAwsSqsConsumer> {
        self.ensure_registration_binding()?;
        MissionAwsSqsConsumer::new(self.scope.clone(), self.registration.clone())
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.revoke()
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.reverse()
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.revoke()
    }

    pub fn reverse_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.reverse()
    }

    pub fn restore_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.restore()
    }

    fn read_dlq_sources(
        &mut self,
        _attributes_response: &GetQueueAttributesResponse,
        get_queue_url_digest: &mut Option<Digest>,
    ) -> std::result::Result<(Digest, Vec<crate::model::DeadLetterSourceProjection>), FailureEvidence>
    {
        let dead_letter_queue = self
            .scope
            .dead_letter_queue()
            .ok_or_else(|| FailureEvidence::classified(QueueFailureClass::AttributeDrift))?;
        let dead_letter_queue_url = if let Some(url) = dead_letter_queue.url() {
            url.clone()
        } else {
            let request = GetQueueUrlRequest::for_queue(&self.scope, dead_letter_queue)
                .map_err(|_| FailureEvidence::classified(QueueFailureClass::QueueReplaced))?;
            let response = self
                .provider
                .get_queue_url(&request)
                .map_err(|error| failure_from_transport(&error))?;
            let prior = get_queue_url_digest.take();
            *get_queue_url_digest = Some(prior.map_or_else(
                || response.digest(),
                |previous| {
                    Digest::from_parts(
                        "aws-sqs-get-queue-url-evidence/v1",
                        &[
                            ("target", previous.as_str().to_owned()),
                            ("dead_letter", response.digest().as_str().to_owned()),
                        ],
                    )
                },
            ));
            response.queue_url
        };
        let request = ListDeadLetterSourceQueuesRequest::new(&self.scope, dead_letter_queue_url)
            .map_err(|_| FailureEvidence::classified(QueueFailureClass::QueueReplaced))?;
        let response = self
            .provider
            .list_dead_letter_source_queues(&request)
            .map_err(|error| failure_from_transport(&error))?;
        Ok((response.digest(), response.source_queues))
    }

    fn ensure_active(&self) -> Result<()> {
        self.ensure_registration_binding()?;
        if self.registration.is_active() {
            Ok(())
        } else {
            Err(AwsSqsQueueError::RegistrationInactive)
        }
    }

    fn ensure_registration_binding(&self) -> Result<()> {
        self.scope.validate()?;
        self.secret_reference.validate(&self.scope)?;
        self.permission_snapshot.validate()?;
        self.provider.definition().validate()?;
        self.registration.validate()?;
        if self.registration.scope_digest() != &self.scope.digest()
            || self.registration.queue_digest() != &self.scope.queue_digest()
            || self.registration.permission_digest() != self.permission_snapshot.digest()
            || self.registration.secret_reference_digest() != self.secret_reference.digest()
            || self.registration.provider_digest() != &self.provider.definition().provider_digest
        {
            return Err(AwsSqsQueueError::ScopeMismatch);
        }
        Ok(())
    }

    fn ensure_proposal_bound(&self, proposal: &AwsSqsQueueProposal) -> Result<()> {
        proposal.validate_integrity()?;
        if proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.queue_digest != self.scope.queue_digest()
        {
            return Err(AwsSqsQueueError::ScopeMismatch);
        }
        Ok(())
    }
}

fn validate_dlq_posture(
    scope: &AwsSqsQueueScope,
    attributes: &QueueAttributesProjection,
) -> std::result::Result<(), QueueFailureClass> {
    let expected = scope.dead_letter_queue();
    match (expected, &attributes.redrive) {
        (None, RedrivePosture::NotConfigured) => Ok(()),
        (None, RedrivePosture::Configured { .. } | RedrivePosture::Unknown)
        | (Some(_), RedrivePosture::NotConfigured | RedrivePosture::Unknown) => {
            Err(QueueFailureClass::AttributeDrift)
        }
        (
            Some(dead_letter_queue),
            RedrivePosture::Configured {
                dead_letter_target_arn_digest,
                ..
            },
        ) => {
            let expected_digest =
                dead_letter_queue
                    .arn()
                    .map(|value| value.digest())
                    .or_else(|| {
                        crate::model::QueueArn::new(format!(
                            "arn:aws:sqs:{}:{}:{}",
                            scope.region(),
                            scope.account(),
                            dead_letter_queue.name()
                        ))
                        .ok()
                        .map(|value| value.digest())
                    });
            if expected_digest.as_ref() == Some(dead_letter_target_arn_digest) {
                Ok(())
            } else {
                Err(QueueFailureClass::AttributeDrift)
            }
        }
    }
}

fn failure_from_transport(error: &AwsSqsQueueTransportError) -> FailureEvidence {
    FailureEvidence::from_transport(error)
}

fn failure_from_error(error: &AwsSqsQueueError) -> FailureEvidence {
    match error {
        AwsSqsQueueError::Transport(error) => failure_from_transport(error),
        AwsSqsQueueError::QueueReplaced => {
            FailureEvidence::classified(QueueFailureClass::QueueReplaced)
        }
        AwsSqsQueueError::AttributeDrift => {
            FailureEvidence::classified(QueueFailureClass::AttributeDrift)
        }
        AwsSqsQueueError::StaleObservation => {
            FailureEvidence::classified(QueueFailureClass::StaleObservation)
        }
        AwsSqsQueueError::PaginationLoop => {
            FailureEvidence::classified(QueueFailureClass::PaginationLoop)
        }
        AwsSqsQueueError::PartialEvidence => {
            FailureEvidence::classified(QueueFailureClass::Partial)
        }
        AwsSqsQueueError::RegistrationInactive | AwsSqsQueueError::RegistrationRevoked => {
            FailureEvidence::classified(QueueFailureClass::RegistrationRevoked)
        }
        AwsSqsQueueError::InvalidRequest
        | AwsSqsQueueError::InvalidScope
        | AwsSqsQueueError::ScopeMismatch
        | AwsSqsQueueError::CursorMismatch
        | AwsSqsQueueError::InvalidIdentifier { .. }
        | AwsSqsQueueError::InvalidDigest
        | AwsSqsQueueError::InvalidPermissionSnapshot
        | AwsSqsQueueError::InvalidSecretReference
        | AwsSqsQueueError::InvalidRegistration
        | AwsSqsQueueError::QueueMismatch
        | AwsSqsQueueError::ProviderDrift
        | AwsSqsQueueError::ContractDrift
        | AwsSqsQueueError::RegistrationReversed
        | AwsSqsQueueError::TamperedEvidence
        | AwsSqsQueueError::RecordingConflict
        | AwsSqsQueueError::InvalidText { .. } => {
            FailureEvidence::classified(QueueFailureClass::ProviderUnknown)
        }
    }
}

fn state_from_failure(classification: QueueFailureClass) -> QueueEvidenceState {
    match classification {
        QueueFailureClass::NotFound => QueueEvidenceState::NotFound,
        QueueFailureClass::AccessLoss
        | QueueFailureClass::Unauthorized
        | QueueFailureClass::Forbidden => QueueEvidenceState::AccessLoss,
        QueueFailureClass::RateLimited => QueueEvidenceState::Throttled,
        QueueFailureClass::Timeout => QueueEvidenceState::Timeout,
        QueueFailureClass::QueueReplaced => QueueEvidenceState::QueueReplaced,
        QueueFailureClass::AttributeDrift => QueueEvidenceState::AttributeDrift,
        QueueFailureClass::StaleObservation => QueueEvidenceState::Stale,
        QueueFailureClass::PaginationLoop => QueueEvidenceState::PaginationLoop,
        QueueFailureClass::Partial => QueueEvidenceState::Partial,
        QueueFailureClass::RegistrationRevoked => QueueEvidenceState::RegistrationRevoked,
        QueueFailureClass::None => QueueEvidenceState::Healthy,
        QueueFailureClass::BlockedEnv
        | QueueFailureClass::BadRequest
        | QueueFailureClass::InvalidResponse
        | QueueFailureClass::ServerError
        | QueueFailureClass::ProviderUnknown => QueueEvidenceState::ProviderUnknown,
    }
}

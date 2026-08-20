//! Typed SNS topic result service, proposal, verification, and registration.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::consumer::MissionAwsSnsConsumer;
use crate::error::{AwsSnsTopicError, AwsSnsTransportError, Result};
use crate::model::{
    AwsSnsTopicScope, ConsentScope, Digest, PermissionSnapshot, SecretReference,
    SubscriptionPosture, TopicPosture, TransportProvenance,
};
use crate::provider::{
    AwsSnsOperation, AwsSnsProvider, AwsSnsProviderDefinition, AwsSnsTransport,
    GetSubscriptionAttributesRequest, GetTopicAttributesRequest, ListSubscriptionsByTopicRequest,
    ListTopicsRequest, OpaqueCursor,
};
use crate::{
    CONTRACT_DIGEST, CONTRACT_VERSION, EVIDENCE_LEVEL, MAX_PAGE_SIZE, MAX_PAGES, PLUGIN_VERSION,
    PROVIDER_ID, SERVICE_ID,
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
            "aws-sns-registration-transition/v1",
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

/// Version/contract/provider/permission/consent/scope/secret/evidence-bound
/// registration. The secret handle itself is never retained or serialized.
#[derive(Clone, Eq, PartialEq)]
pub struct AwsSnsTopicRegistration {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_revision: String,
    pub provider_digest: Digest,
    pub permission_snapshot_digest: Digest,
    pub consent_digest: Digest,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_revision: u64,
    pub status: RegistrationStatus,
}

impl AwsSnsTopicRegistration {
    fn new(
        scope: &AwsSnsTopicScope,
        secret: &SecretReference,
        permission: &PermissionSnapshot,
        consent: &ConsentScope,
        provider: &AwsSnsProviderDefinition,
        provider_digest: Digest,
    ) -> Result<Self> {
        let evidence_digest = Digest::from_parts(
            "aws-sns-registration-evidence/v1",
            &[
                ("plugin", PLUGIN_VERSION.to_owned()),
                ("contract", CONTRACT_DIGEST.to_owned()),
                ("provider", provider_digest.as_str().to_owned()),
                ("permission", permission.digest().as_str().to_owned()),
                ("consent", consent.digest().as_str().to_owned()),
                ("scope", scope.digest().as_str().to_owned()),
                ("secret", secret.reference_digest().as_str().to_owned()),
            ],
        );
        let registration = Self {
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: Digest::parse(CONTRACT_DIGEST.to_owned())?,
            provider_id: provider.id.clone(),
            provider_revision: provider.api_revision.clone(),
            provider_digest,
            permission_snapshot_digest: permission.digest(),
            consent_digest: consent.digest(),
            scope_digest: scope.digest(),
            secret_reference_digest: secret.reference_digest().clone(),
            evidence_digest,
            registration_revision: 1,
            status: RegistrationStatus::Active,
        };
        registration.validate()?;
        Ok(registration)
    }

    pub fn provider_binding_digest(
        provider: &AwsSnsProviderDefinition,
        provider_digest: &Digest,
    ) -> Digest {
        Digest::from_parts(
            "aws-sns-provider-binding/v1",
            &[
                ("id", provider.id.clone()),
                ("revision", provider.api_revision.clone()),
                ("digest", provider_digest.as_str().to_owned()),
                ("contract", provider.contract_version.clone()),
            ],
        )
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-sns-registration/v1",
            &[
                ("plugin", self.plugin_version.clone()),
                ("contract_version", self.contract_version.clone()),
                ("contract_digest", self.contract_digest.as_str().to_owned()),
                ("provider_id", self.provider_id.clone()),
                ("provider_revision", self.provider_revision.clone()),
                ("provider_digest", self.provider_digest.as_str().to_owned()),
                (
                    "permission",
                    self.permission_snapshot_digest.as_str().to_owned(),
                ),
                ("consent", self.consent_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("secret", self.secret_reference_digest.as_str().to_owned()),
                ("evidence", self.evidence_digest.as_str().to_owned()),
                (
                    "registration_revision",
                    self.registration_revision.to_string(),
                ),
                ("status", format!("{:?}", self.status)),
            ],
        )
    }

    pub fn is_active(&self) -> bool {
        self.status == RegistrationStatus::Active
    }

    pub fn validate(&self) -> Result<()> {
        if self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.provider_id != PROVIDER_ID
            || self.provider_revision != crate::PROVIDER_API_REVISION
            || self.registration_revision == 0
            || self.permission_snapshot_digest == Digest::zero()
            || self.consent_digest == Digest::zero()
            || self.scope_digest == Digest::zero()
            || self.secret_reference_digest == Digest::zero()
            || self.evidence_digest == Digest::zero()
        {
            Err(AwsSnsTopicError::InvalidRegistration)
        } else {
            Ok(())
        }
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        let previous = self.status;
        if previous == RegistrationStatus::Revoked {
            return Err(AwsSnsTopicError::RegistrationRevoked);
        }
        self.status = RegistrationStatus::Revoked;
        self.registration_revision = self.registration_revision.saturating_add(1);
        Ok(RegistrationTransitionEvidence::new(
            previous,
            self.status,
            self.digest(),
        ))
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        let previous = self.status;
        if previous != RegistrationStatus::Active {
            return Err(match previous {
                RegistrationStatus::Revoked => AwsSnsTopicError::RegistrationRevoked,
                RegistrationStatus::Reversed => AwsSnsTopicError::RegistrationReversed,
                RegistrationStatus::Active => AwsSnsTopicError::RegistrationInactive,
            });
        }
        self.status = RegistrationStatus::Reversed;
        self.registration_revision = self.registration_revision.saturating_add(1);
        Ok(RegistrationTransitionEvidence::new(
            previous,
            self.status,
            self.digest(),
        ))
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        let previous = self.status;
        if previous != RegistrationStatus::Reversed {
            return Err(match previous {
                RegistrationStatus::Revoked => AwsSnsTopicError::RegistrationRevoked,
                RegistrationStatus::Reversed => AwsSnsTopicError::RegistrationReversed,
                RegistrationStatus::Active => AwsSnsTopicError::RegistrationInactive,
            });
        }
        self.status = RegistrationStatus::Active;
        self.registration_revision = self.registration_revision.saturating_add(1);
        Ok(RegistrationTransitionEvidence::new(
            previous,
            self.status,
            self.digest(),
        ))
    }
}

impl Serialize for AwsSnsTopicRegistration {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("AwsSnsTopicRegistration", 14)?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("permissionSnapshotDigest", &self.permission_snapshot_digest)?;
        state.serialize_field("consentDigest", &self.consent_digest)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("secretReferenceDigest", &self.secret_reference_digest)?;
        state.serialize_field("evidenceDigest", &self.evidence_digest)?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("registrationDigest", &self.digest())?;
        state.end()
    }
}

impl fmt::Debug for AwsSnsTopicRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsSnsTopicRegistration")
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_id", &self.provider_id)
            .field("provider_revision", &self.provider_revision)
            .field("provider_digest", &self.provider_digest)
            .field(
                "permission_snapshot_digest",
                &self.permission_snapshot_digest,
            )
            .field("consent_digest", &self.consent_digest)
            .field("scope_digest", &self.scope_digest)
            .field("secret_reference_digest", &self.secret_reference_digest)
            .field("evidence_digest", &self.evidence_digest)
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityDescription {
    pub service_id: String,
    pub provider_id: String,
    pub contract_version: String,
    pub evidence_level: String,
    pub operations: Vec<AwsSnsOperation>,
    pub permissions: Vec<String>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub external_writes: bool,
    pub kernel_authority: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub adopts_outcome: bool,
    pub adopts_work_product: bool,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentDisposition {
    Active,
    Expired,
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Complete,
    Partial,
    TopicReplaced,
    SubscriptionReplaced,
    NotFound,
    AccessLoss,
    Throttled,
    ProviderUnknown,
    Tampered,
    RegistrationRevoked,
    ConsentExpired,
    ConsentRevoked,
}

impl EvidenceState {
    fn reviewable(self) -> bool {
        !matches!(
            self,
            Self::Tampered | Self::RegistrationRevoked | Self::ConsentRevoked
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureEvidence {
    pub category: String,
    pub status_code: Option<u16>,
    pub error_digest: Digest,
}

impl FailureEvidence {
    fn from_error(error: &AwsSnsTopicError) -> Self {
        let (category, status_code) = match error {
            AwsSnsTopicError::Transport(transport) => {
                (transport.category().to_owned(), transport.status_code())
            }
            AwsSnsTopicError::TopicReplaced => ("topic_replaced".to_owned(), Some(404)),
            AwsSnsTopicError::SubscriptionReplaced => {
                ("subscription_replaced".to_owned(), Some(404))
            }
            AwsSnsTopicError::PaginationLoop => ("pagination_loop".to_owned(), None),
            AwsSnsTopicError::PartialEvidence => ("partial".to_owned(), None),
            AwsSnsTopicError::TamperedEvidence => ("tampered".to_owned(), None),
            AwsSnsTopicError::RegistrationRevoked => ("registration_revoked".to_owned(), None),
            AwsSnsTopicError::ConsentExpired => ("consent_expired".to_owned(), None),
            AwsSnsTopicError::ConsentRevoked => ("consent_revoked".to_owned(), None),
            _ => ("provider_unknown".to_owned(), None),
        };
        Self {
            category,
            status_code,
            error_digest: Digest::from_parts(
                "aws-sns-error/v1",
                &[("category", error.to_string())],
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsSnsTopicReadRequest {
    pub scope_digest: Digest,
    pub max_pages: u16,
    pub page_size: u16,
    pub requested_at: DateTime<Utc>,
    pub request_digest: Digest,
}

impl AwsSnsTopicReadRequest {
    pub fn new(
        scope: &AwsSnsTopicScope,
        max_pages: u16,
        page_size: u16,
        requested_at: DateTime<Utc>,
    ) -> Result<Self> {
        scope.validate()?;
        if !(1..=MAX_PAGES).contains(&max_pages) || !(1..=MAX_PAGE_SIZE).contains(&page_size) {
            return Err(AwsSnsTopicError::InvalidRequest);
        }
        let request_digest = Digest::from_parts(
            "aws-sns-topic-read-request/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("max_pages", max_pages.to_string()),
                ("page_size", page_size.to_string()),
                ("requested_at", requested_at.to_rfc3339()),
            ],
        );
        Ok(Self {
            scope_digest: scope.digest(),
            max_pages,
            page_size,
            requested_at,
            request_digest,
        })
    }

    pub fn validate_against(&self, scope: &AwsSnsTopicScope) -> Result<()> {
        if self.scope_digest != scope.digest()
            || !(1..=MAX_PAGES).contains(&self.max_pages)
            || !(1..=MAX_PAGE_SIZE).contains(&self.page_size)
            || self.request_digest
                != Digest::from_parts(
                    "aws-sns-topic-read-request/v1",
                    &[
                        ("scope", scope.digest().as_str().to_owned()),
                        ("max_pages", self.max_pages.to_string()),
                        ("page_size", self.page_size.to_string()),
                        ("requested_at", self.requested_at.to_rfc3339()),
                    ],
                )
        {
            Err(AwsSnsTopicError::ScopeMismatch)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsSnsTopicEvidence {
    pub state: EvidenceState,
    pub scope_digest: Digest,
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_digest: Digest,
    pub topic_digest: Digest,
    pub subscription_digests: Vec<Digest>,
    pub topic_posture: Option<TopicPosture>,
    pub subscription_postures: Vec<SubscriptionPosture>,
    pub list_topics_pages: u16,
    pub list_subscriptions_pages: u16,
    pub list_topics_complete: bool,
    pub list_subscriptions_complete: bool,
    pub list_topics_digest: Digest,
    pub topic_attributes_digest: Option<Digest>,
    pub list_subscriptions_digest: Digest,
    pub subscription_attributes_digests: Vec<Digest>,
    pub requested_at: DateTime<Utc>,
    pub provenance: TransportProvenance,
    pub failure: Option<FailureEvidence>,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl AwsSnsTopicEvidence {
    fn new(
        scope: &AwsSnsTopicScope,
        request: &AwsSnsTopicReadRequest,
        state: EvidenceState,
        topic_posture: Option<TopicPosture>,
        subscription_postures: Vec<SubscriptionPosture>,
        list_topics_pages: u16,
        list_subscriptions_pages: u16,
        list_topics_complete: bool,
        list_subscriptions_complete: bool,
        list_topics_digest: Digest,
        topic_attributes_digest: Option<Digest>,
        list_subscriptions_digest: Digest,
        subscription_attributes_digests: Vec<Digest>,
        provenance: TransportProvenance,
        failure: Option<FailureEvidence>,
    ) -> Self {
        let mut evidence = Self {
            state,
            scope_digest: scope.digest(),
            plugin_version_digest: Digest::zero(),
            contract_digest: Digest::zero(),
            provider_digest: Digest::zero(),
            permission_digest: Digest::zero(),
            consent_digest: Digest::zero(),
            secret_reference_digest: Digest::zero(),
            registration_digest: Digest::zero(),
            topic_digest: scope.topic().digest(),
            subscription_digests: scope.subscription_digests(),
            topic_posture,
            subscription_postures,
            list_topics_pages,
            list_subscriptions_pages,
            list_topics_complete,
            list_subscriptions_complete,
            list_topics_digest,
            topic_attributes_digest,
            list_subscriptions_digest,
            subscription_attributes_digests,
            requested_at: request.requested_at,
            provenance,
            failure,
            evidence_digest: Digest::zero(),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        evidence.evidence_digest = evidence.calculate_digest();
        evidence
    }

    fn bind_registration(
        &mut self,
        registration: &AwsSnsTopicRegistration,
        permission: &PermissionSnapshot,
        consent: &ConsentScope,
        secret: &SecretReference,
        provider: &AwsSnsProviderDefinition,
    ) {
        self.plugin_version_digest = Digest::from_text(PLUGIN_VERSION);
        self.contract_digest =
            Digest::parse(CONTRACT_DIGEST.to_owned()).expect("checked AWS SNS contract digest");
        self.provider_digest = provider.digest();
        self.permission_digest = permission.digest();
        self.consent_digest = consent.digest();
        self.secret_reference_digest = secret.reference_digest().clone();
        self.registration_digest = registration.digest();
        self.evidence_digest = self.calculate_digest();
    }

    pub fn validate_registration_binding(
        &self,
        registration: &AwsSnsTopicRegistration,
        permission: &PermissionSnapshot,
        consent: &ConsentScope,
        secret: &SecretReference,
        provider: &AwsSnsProviderDefinition,
    ) -> Result<()> {
        if self.plugin_version_digest != Digest::from_text(PLUGIN_VERSION)
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.provider_digest != provider.digest()
            || self.permission_digest != permission.digest()
            || self.consent_digest != consent.digest()
            || self.secret_reference_digest != secret.reference_digest().clone()
            || self.registration_digest != registration.digest()
        {
            Err(AwsSnsTopicError::TamperedEvidence)
        } else {
            Ok(())
        }
    }

    pub fn can_be_adopted(&self) -> bool {
        false
    }

    pub fn is_review_only(&self) -> bool {
        true
    }

    pub(crate) fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-sns-topic-evidence/v1",
            &[
                ("state", format!("{:?}", self.state)),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("plugin", self.plugin_version_digest.as_str().to_owned()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                ("consent", self.consent_digest.as_str().to_owned()),
                ("secret", self.secret_reference_digest.as_str().to_owned()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("topic", self.topic_digest.as_str().to_owned()),
                (
                    "subscriptions",
                    self.subscription_digests
                        .iter()
                        .map(Digest::as_str)
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                (
                    "topic_posture",
                    self.topic_posture
                        .as_ref()
                        .map_or_else(String::new, |posture| posture.digest().as_str().to_owned()),
                ),
                (
                    "subscription_postures",
                    self.subscription_postures
                        .iter()
                        .map(SubscriptionPosture::digest)
                        .map(|digest| digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                ("topic_pages", self.list_topics_pages.to_string()),
                (
                    "subscription_pages",
                    self.list_subscriptions_pages.to_string(),
                ),
                ("topic_complete", self.list_topics_complete.to_string()),
                (
                    "subscription_complete",
                    self.list_subscriptions_complete.to_string(),
                ),
                ("list_topics", self.list_topics_digest.as_str().to_owned()),
                (
                    "topic_attributes",
                    self.topic_attributes_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "list_subscriptions",
                    self.list_subscriptions_digest.as_str().to_owned(),
                ),
                (
                    "subscription_attributes",
                    self.subscription_attributes_digests
                        .iter()
                        .map(Digest::as_str)
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                ("requested_at", self.requested_at.to_rfc3339()),
                ("provenance", self.provenance.as_str().to_owned()),
                (
                    "failure",
                    self.failure.as_ref().map_or_else(String::new, |failure| {
                        failure.error_digest.as_str().to_owned()
                    }),
                ),
            ],
        )
    }

    pub fn validate_integrity(&self, scope: &AwsSnsTopicScope) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self.topic_digest != scope.topic().digest()
            || self.subscription_digests != scope.subscription_digests()
            || self.plugin_version_digest == Digest::zero()
            || self.contract_digest == Digest::zero()
            || self.provider_digest == Digest::zero()
            || self.permission_digest == Digest::zero()
            || self.consent_digest == Digest::zero()
            || self.secret_reference_digest == Digest::zero()
            || self.registration_digest == Digest::zero()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.evidence_digest != self.calculate_digest()
        {
            Err(AwsSnsTopicError::TamperedEvidence)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsSnsTopicProposal {
    pub state: EvidenceState,
    pub evidence: AwsSnsTopicEvidence,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
    pub proposal_digest: Digest,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub adopts_outcome: bool,
    pub adopts_work_product: bool,
}

impl AwsSnsTopicProposal {
    fn new(evidence: AwsSnsTopicEvidence) -> Self {
        let proposal_digest = Digest::from_parts(
            "aws-sns-topic-proposal/v1",
            &[
                ("scope", evidence.scope_digest.as_str().to_owned()),
                ("evidence", evidence.evidence_digest.as_str().to_owned()),
                ("state", format!("{:?}", evidence.state)),
            ],
        );
        Self {
            state: evidence.state,
            scope_digest: evidence.scope_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            evidence,
            proposal_digest,
            read_only: true,
            proposal_only: true,
            recording_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            adopts_outcome: false,
            adopts_work_product: false,
        }
    }

    pub fn can_be_adopted(&self) -> bool {
        false
    }

    pub fn is_review_only(&self) -> bool {
        true
    }

    pub fn validate_integrity(&self, scope: &AwsSnsTopicScope) -> Result<()> {
        self.evidence.validate_integrity(scope)?;
        if self.state != self.evidence.state
            || self.scope_digest != self.evidence.scope_digest
            || self.evidence_digest != self.evidence.evidence_digest
            || self.proposal_digest
                != Digest::from_parts(
                    "aws-sns-topic-proposal/v1",
                    &[
                        ("scope", self.scope_digest.as_str().to_owned()),
                        ("evidence", self.evidence_digest.as_str().to_owned()),
                        ("state", format!("{:?}", self.state)),
                    ],
                )
            || !self.read_only
            || !self.proposal_only
            || !self.recording_only
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.adopts_outcome
            || self.adopts_work_product
        {
            Err(AwsSnsTopicError::TamperedEvidence)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationFailure {
    pub code: String,
    pub detail_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub valid: bool,
    pub review_eligible: bool,
    pub evidence_digest: Digest,
    pub failures: Vec<VerificationFailure>,
}

#[derive(Debug)]
pub struct AwsSnsTopicService<T: AwsSnsTransport> {
    scope: AwsSnsTopicScope,
    secret: SecretReference,
    permission: PermissionSnapshot,
    consent: ConsentScope,
    provider: AwsSnsProvider<T>,
    registration: AwsSnsTopicRegistration,
}

impl<T: AwsSnsTransport> AwsSnsTopicService<T> {
    pub fn new(
        scope: AwsSnsTopicScope,
        secret: SecretReference,
        permission: PermissionSnapshot,
        consent: ConsentScope,
        provider: AwsSnsProvider<T>,
        _now: DateTime<Utc>,
    ) -> Result<Self> {
        scope.validate()?;
        permission.validate()?;
        consent.validate()?;
        secret.validate(&scope)?;
        provider.definition().validate()?;
        let registration = AwsSnsTopicRegistration::new(
            &scope,
            &secret,
            &permission,
            &consent,
            provider.definition(),
            provider.provider_digest(),
        )?;
        Ok(Self {
            scope,
            secret,
            permission,
            consent,
            provider,
            registration,
        })
    }

    pub fn scope(&self) -> &AwsSnsTopicScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret
    }

    pub fn revoke_secret_reference(&mut self) {
        self.secret.revoke();
    }

    pub fn permission(&self) -> &PermissionSnapshot {
        &self.permission
    }

    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    pub fn consent_mut(&mut self) -> &mut ConsentScope {
        &mut self.consent
    }

    pub fn provider(&self) -> &AwsSnsProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsSnsProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &AwsSnsTopicRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut AwsSnsTopicRegistration {
        &mut self.registration
    }

    pub fn is_active(&self) -> bool {
        self.registration.is_active()
    }

    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            evidence_level: EVIDENCE_LEVEL.to_owned(),
            operations: self.provider.definition().operations.clone(),
            permissions: crate::LAYER1_PERMISSIONS
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect(),
            read_only: true,
            proposal_only: true,
            recording_only: true,
            external_writes: false,
            kernel_authority: false,
            connected: false,
            native: false,
            first_party: false,
            adopts_outcome: false,
            adopts_work_product: false,
        }
    }

    pub fn default_request(&self, requested_at: DateTime<Utc>) -> Result<AwsSnsTopicReadRequest> {
        self.request(MAX_PAGES, MAX_PAGE_SIZE, requested_at)
    }

    pub fn request(
        &self,
        max_pages: u16,
        page_size: u16,
        requested_at: DateTime<Utc>,
    ) -> Result<AwsSnsTopicReadRequest> {
        AwsSnsTopicReadRequest::new(&self.scope, max_pages, page_size, requested_at)
    }

    pub fn read(&mut self, request: AwsSnsTopicReadRequest) -> Result<AwsSnsTopicEvidence> {
        request.validate_against(&self.scope)?;
        if let Err(error) = self.ensure_readable(request.requested_at) {
            return Ok(self.failure_evidence(&request, state_for_error(&error), error));
        }

        let provenance = self.provider.definition().provenance.clone();
        let mut list_topics_pages: u16 = 0;
        let list_topics_complete = true;
        let mut list_topics_digest_parts = Vec::new();
        let mut topic_posture = None;
        let mut cursor: Option<OpaqueCursor> = None;
        let mut seen_cursors = BTreeSet::new();

        loop {
            let page_request =
                ListTopicsRequest::new(&self.scope, request.page_size, cursor.clone())?;
            if let Some(cursor) = page_request.cursor() {
                if !seen_cursors.insert(cursor.token_digest().clone()) {
                    return Ok(self.failure_evidence(
                        &request,
                        EvidenceState::Partial,
                        AwsSnsTopicError::PaginationLoop,
                    ));
                }
            }
            let response = match self.provider.list_topics(&page_request) {
                Ok(response) => response,
                Err(error) => {
                    let error = AwsSnsTopicError::Transport(error);
                    return Ok(self.failure_evidence(&request, state_for_error(&error), error));
                }
            };
            if let Err(error) = response.validate_integrity(&page_request) {
                return Ok(self.failure_evidence(&request, state_for_error(&error), error));
            }
            list_topics_pages = list_topics_pages.saturating_add(1);
            list_topics_digest_parts.push(response.evidence_digest.clone());
            for topic in response.topics {
                if topic.topic_digest == self.scope.topic().digest() {
                    topic_posture = Some(topic.posture);
                }
            }
            match response.next_cursor {
                Some(next) if list_topics_pages < request.max_pages => cursor = Some(next),
                Some(_) => {
                    return Ok(self.failure_evidence(
                        &request,
                        EvidenceState::Partial,
                        AwsSnsTopicError::PartialEvidence,
                    ));
                }
                None => {
                    break;
                }
            }
        }

        let list_topics_digest =
            combine_digests("aws-sns-list-topics-pages/v1", &list_topics_digest_parts);
        let Some(_) = topic_posture else {
            return Ok(self.failure_evidence_with_buffers(
                &request,
                EvidenceState::TopicReplaced,
                AwsSnsTopicError::TopicReplaced,
                topic_posture,
                Vec::new(),
                list_topics_pages,
                0,
                list_topics_complete,
                false,
                list_topics_digest,
                None,
                Digest::zero(),
                Vec::new(),
                provenance,
            ));
        };

        let topic_request = GetTopicAttributesRequest::new(&self.scope)?;
        let topic_response = match self.provider.get_topic_attributes(&topic_request) {
            Ok(response) => response,
            Err(error) => {
                let error = AwsSnsTopicError::Transport(error);
                return Ok(self.failure_evidence_with_buffers(
                    &request,
                    state_for_error(&error),
                    error,
                    topic_posture,
                    Vec::new(),
                    list_topics_pages,
                    0,
                    list_topics_complete,
                    false,
                    list_topics_digest,
                    None,
                    Digest::zero(),
                    Vec::new(),
                    provenance,
                ));
            }
        };
        if let Err(error) = topic_response.validate_integrity(&topic_request) {
            return Ok(self.failure_evidence_with_buffers(
                &request,
                state_for_error(&error),
                error,
                topic_posture,
                Vec::new(),
                list_topics_pages,
                0,
                list_topics_complete,
                false,
                list_topics_digest,
                None,
                Digest::zero(),
                Vec::new(),
                provenance,
            ));
        }
        topic_posture = Some(topic_response.posture.clone());
        let topic_attributes_digest = Some(topic_response.evidence_digest.clone());

        let mut list_subscriptions_pages: u16 = 0;
        let mut list_subscriptions_complete = false;
        let mut list_subscriptions_digest_parts = Vec::new();
        let mut subscription_postures = Vec::new();
        let mut found_subscriptions = BTreeSet::new();
        let mut cursor: Option<OpaqueCursor> = None;
        let mut seen_cursors = BTreeSet::new();
        loop {
            let page_request = ListSubscriptionsByTopicRequest::new(
                &self.scope,
                request.page_size,
                cursor.clone(),
            )?;
            if let Some(cursor) = page_request.cursor() {
                if !seen_cursors.insert(cursor.token_digest().clone()) {
                    return Ok(self.failure_evidence_with_buffers(
                        &request,
                        EvidenceState::Partial,
                        AwsSnsTopicError::PaginationLoop,
                        topic_posture,
                        subscription_postures,
                        list_topics_pages,
                        list_subscriptions_pages,
                        list_topics_complete,
                        list_subscriptions_complete,
                        list_topics_digest,
                        topic_attributes_digest,
                        combine_digests(
                            "aws-sns-list-subscriptions-pages/v1",
                            &list_subscriptions_digest_parts,
                        ),
                        Vec::new(),
                        provenance,
                    ));
                }
            }
            let response = match self.provider.list_subscriptions_by_topic(&page_request) {
                Ok(response) => response,
                Err(error) => {
                    let error = AwsSnsTopicError::Transport(error);
                    return Ok(self.failure_evidence_with_buffers(
                        &request,
                        state_for_error(&error),
                        error,
                        topic_posture,
                        subscription_postures,
                        list_topics_pages,
                        list_subscriptions_pages,
                        list_topics_complete,
                        list_subscriptions_complete,
                        list_topics_digest,
                        topic_attributes_digest,
                        combine_digests(
                            "aws-sns-list-subscriptions-pages/v1",
                            &list_subscriptions_digest_parts,
                        ),
                        Vec::new(),
                        provenance,
                    ));
                }
            };
            if let Err(error) = response.validate_integrity(&page_request) {
                return Ok(self.failure_evidence_with_buffers(
                    &request,
                    state_for_error(&error),
                    error,
                    topic_posture,
                    subscription_postures,
                    list_topics_pages,
                    list_subscriptions_pages,
                    list_topics_complete,
                    list_subscriptions_complete,
                    list_topics_digest,
                    topic_attributes_digest,
                    combine_digests(
                        "aws-sns-list-subscriptions-pages/v1",
                        &list_subscriptions_digest_parts,
                    ),
                    Vec::new(),
                    provenance,
                ));
            }
            list_subscriptions_pages = list_subscriptions_pages.saturating_add(1);
            list_subscriptions_digest_parts.push(response.evidence_digest.clone());
            for subscription in response.subscriptions {
                if self
                    .scope
                    .subscriptions()
                    .iter()
                    .any(|allowed| allowed.digest() == subscription.subscription_digest)
                {
                    found_subscriptions.insert(subscription.subscription_digest.clone());
                    subscription_postures.push(subscription.posture);
                }
            }
            match response.next_cursor {
                Some(next) if list_subscriptions_pages < request.max_pages => cursor = Some(next),
                Some(_) => {
                    return Ok(self.failure_evidence_with_buffers(
                        &request,
                        EvidenceState::Partial,
                        AwsSnsTopicError::PartialEvidence,
                        topic_posture,
                        subscription_postures,
                        list_topics_pages,
                        list_subscriptions_pages,
                        list_topics_complete,
                        false,
                        list_topics_digest,
                        topic_attributes_digest,
                        combine_digests(
                            "aws-sns-list-subscriptions-pages/v1",
                            &list_subscriptions_digest_parts,
                        ),
                        Vec::new(),
                        provenance,
                    ));
                }
                None => {
                    list_subscriptions_complete = true;
                    break;
                }
            }
        }

        let list_subscriptions_digest = combine_digests(
            "aws-sns-list-subscriptions-pages/v1",
            &list_subscriptions_digest_parts,
        );
        let expected_subscriptions = self.scope.subscription_digests();
        if found_subscriptions.len() != expected_subscriptions.len() {
            return Ok(self.failure_evidence_with_buffers(
                &request,
                EvidenceState::SubscriptionReplaced,
                AwsSnsTopicError::SubscriptionReplaced,
                topic_posture,
                subscription_postures,
                list_topics_pages,
                list_subscriptions_pages,
                list_topics_complete,
                list_subscriptions_complete,
                list_topics_digest,
                topic_attributes_digest,
                list_subscriptions_digest,
                Vec::new(),
                provenance,
            ));
        }

        let mut subscription_attributes_digests = Vec::new();
        for subscription in self.scope.subscriptions() {
            let subscription_request =
                GetSubscriptionAttributesRequest::new(&self.scope, subscription)?;
            let response = match self
                .provider
                .get_subscription_attributes(&subscription_request)
            {
                Ok(response) => response,
                Err(error) => {
                    let error = AwsSnsTopicError::Transport(error);
                    return Ok(self.failure_evidence_with_buffers(
                        &request,
                        state_for_error(&error),
                        error,
                        topic_posture,
                        subscription_postures,
                        list_topics_pages,
                        list_subscriptions_pages,
                        list_topics_complete,
                        list_subscriptions_complete,
                        list_topics_digest,
                        topic_attributes_digest,
                        list_subscriptions_digest,
                        subscription_attributes_digests,
                        provenance,
                    ));
                }
            };
            if let Err(error) = response.validate_integrity(&subscription_request) {
                return Ok(self.failure_evidence_with_buffers(
                    &request,
                    state_for_error(&error),
                    error,
                    topic_posture,
                    subscription_postures,
                    list_topics_pages,
                    list_subscriptions_pages,
                    list_topics_complete,
                    list_subscriptions_complete,
                    list_topics_digest,
                    topic_attributes_digest,
                    list_subscriptions_digest,
                    subscription_attributes_digests,
                    provenance,
                ));
            }
            subscription_attributes_digests.push(response.evidence_digest);
        }

        Ok(self.bind_evidence(AwsSnsTopicEvidence::new(
            &self.scope,
            &request,
            EvidenceState::Complete,
            topic_posture,
            subscription_postures,
            list_topics_pages,
            list_subscriptions_pages,
            list_topics_complete,
            list_subscriptions_complete,
            list_topics_digest,
            topic_attributes_digest,
            list_subscriptions_digest,
            subscription_attributes_digests,
            provenance,
            None,
        )))
    }

    pub fn read_bounded(&mut self, request: AwsSnsTopicReadRequest) -> Result<AwsSnsTopicEvidence> {
        self.read(request)
    }

    pub fn propose(&mut self, request: AwsSnsTopicReadRequest) -> Result<AwsSnsTopicProposal> {
        Ok(AwsSnsTopicProposal::new(self.read(request)?))
    }

    pub fn verify(&self, proposal: &AwsSnsTopicProposal) -> VerificationReport {
        let mut failures = Vec::new();
        if let Err(error) = proposal.validate_integrity(&self.scope) {
            failures.push(verification_failure("proposal_tamper", &error));
        }
        if let Err(error) = proposal.evidence.validate_registration_binding(
            &self.registration,
            &self.permission,
            &self.consent,
            &self.secret,
            self.provider.definition(),
        ) {
            failures.push(verification_failure("registration_binding", &error));
        }
        if let Err(error) = self.validate_registration_binding() {
            failures.push(verification_failure("registration_definition", &error));
        }
        if !self.registration.is_active() {
            failures.push(verification_failure(
                "registration_inactive",
                &AwsSnsTopicError::RegistrationInactive,
            ));
        }
        if self.secret.is_revoked() {
            failures.push(verification_failure(
                "secret_revoked",
                &AwsSnsTopicError::InvalidSecretReference,
            ));
        }
        if !self.consent.is_active_at(proposal.evidence.requested_at) {
            let error = if self.consent.is_revoked() {
                AwsSnsTopicError::ConsentRevoked
            } else {
                AwsSnsTopicError::ConsentExpired
            };
            failures.push(verification_failure("consent_inactive", &error));
        }
        if proposal.evidence.state != EvidenceState::Complete {
            failures.push(VerificationFailure {
                code: "non_complete_evidence".to_owned(),
                detail_digest: Digest::from_text(format!("{:?}", proposal.evidence.state)),
            });
        }
        let valid = failures.is_empty();
        VerificationReport {
            valid,
            review_eligible: valid && proposal.evidence.state.reviewable(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            failures,
        }
    }

    pub fn consumer(&self) -> Result<MissionAwsSnsConsumer> {
        MissionAwsSnsConsumer::new(self.scope.clone(), self.registration.clone())
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

    fn ensure_readable(&self, at: DateTime<Utc>) -> Result<()> {
        match self.registration.status {
            RegistrationStatus::Active => {}
            RegistrationStatus::Revoked => return Err(AwsSnsTopicError::RegistrationRevoked),
            RegistrationStatus::Reversed => return Err(AwsSnsTopicError::RegistrationReversed),
        }
        if self.secret.is_revoked() {
            return Err(AwsSnsTopicError::InvalidSecretReference);
        }
        if self.consent.is_revoked() {
            return Err(AwsSnsTopicError::ConsentRevoked);
        }
        if !self.consent.is_active_at(at) {
            return Err(AwsSnsTopicError::ConsentExpired);
        }
        self.validate_registration_binding()
    }

    fn failure_evidence(
        &self,
        request: &AwsSnsTopicReadRequest,
        state: EvidenceState,
        error: AwsSnsTopicError,
    ) -> AwsSnsTopicEvidence {
        self.failure_evidence_with_buffers(
            request,
            state,
            error,
            None,
            Vec::new(),
            0,
            0,
            false,
            false,
            Digest::zero(),
            None,
            Digest::zero(),
            Vec::new(),
            self.provider.definition().provenance.clone(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn failure_evidence_with_buffers(
        &self,
        request: &AwsSnsTopicReadRequest,
        state: EvidenceState,
        error: AwsSnsTopicError,
        topic_posture: Option<TopicPosture>,
        subscription_postures: Vec<SubscriptionPosture>,
        list_topics_pages: u16,
        list_subscriptions_pages: u16,
        list_topics_complete: bool,
        list_subscriptions_complete: bool,
        list_topics_digest: Digest,
        topic_attributes_digest: Option<Digest>,
        list_subscriptions_digest: Digest,
        subscription_attributes_digests: Vec<Digest>,
        provenance: TransportProvenance,
    ) -> AwsSnsTopicEvidence {
        self.bind_evidence(AwsSnsTopicEvidence::new(
            &self.scope,
            request,
            state,
            topic_posture,
            subscription_postures,
            list_topics_pages,
            list_subscriptions_pages,
            list_topics_complete,
            list_subscriptions_complete,
            list_topics_digest,
            topic_attributes_digest,
            list_subscriptions_digest,
            subscription_attributes_digests,
            provenance,
            Some(FailureEvidence::from_error(&error)),
        ))
    }

    fn bind_evidence(&self, mut evidence: AwsSnsTopicEvidence) -> AwsSnsTopicEvidence {
        evidence.bind_registration(
            &self.registration,
            &self.permission,
            &self.consent,
            &self.secret,
            self.provider.definition(),
        );
        evidence
    }

    fn validate_registration_binding(&self) -> Result<()> {
        self.provider.definition().validate()?;
        self.permission.validate()?;
        self.consent.validate()?;
        self.secret.validate(&self.scope)?;
        let expected = AwsSnsTopicRegistration::new(
            &self.scope,
            &self.secret,
            &self.permission,
            &self.consent,
            self.provider.definition(),
            self.provider.provider_digest(),
        )?;
        if self.registration.plugin_version != expected.plugin_version
            || self.registration.contract_version != expected.contract_version
            || self.registration.contract_digest != expected.contract_digest
            || self.registration.provider_id != expected.provider_id
            || self.registration.provider_revision != expected.provider_revision
            || self.registration.provider_digest != expected.provider_digest
            || self.registration.permission_snapshot_digest != expected.permission_snapshot_digest
            || self.registration.consent_digest != expected.consent_digest
            || self.registration.scope_digest != expected.scope_digest
            || self.registration.secret_reference_digest != expected.secret_reference_digest
            || self.registration.evidence_digest != expected.evidence_digest
        {
            Err(AwsSnsTopicError::InvalidRegistration)
        } else {
            Ok(())
        }
    }
}

impl Default for AwsSnsTopicService<crate::provider::BlockedEnvTransport> {
    fn default() -> Self {
        let scope = test_scope();
        let secret =
            SecretReference::for_scope("blocked-env-reference", &scope, 1).expect("default secret");
        let permission = PermissionSnapshot::for_layer_one(1);
        let consent = ConsentScope::for_layer_one(
            "blocked-env-consent",
            1,
            Utc::now() + chrono::Duration::days(1),
        )
        .expect("default consent");
        Self::new(
            scope,
            secret,
            permission,
            consent,
            AwsSnsProvider::default(),
            Utc::now(),
        )
        .expect("default AWS SNS service")
    }
}

fn combine_digests(domain: &str, digests: &[Digest]) -> Digest {
    Digest::from_parts(
        domain,
        &[(
            "digests",
            digests
                .iter()
                .map(Digest::as_str)
                .collect::<Vec<_>>()
                .join("\n"),
        )],
    )
}

fn state_for_error(error: &AwsSnsTopicError) -> EvidenceState {
    match error {
        AwsSnsTopicError::TopicReplaced => EvidenceState::TopicReplaced,
        AwsSnsTopicError::SubscriptionReplaced => EvidenceState::SubscriptionReplaced,
        AwsSnsTopicError::PaginationLoop | AwsSnsTopicError::PartialEvidence => {
            EvidenceState::Partial
        }
        AwsSnsTopicError::TamperedEvidence => EvidenceState::Tampered,
        AwsSnsTopicError::RegistrationRevoked | AwsSnsTopicError::RegistrationReversed => {
            EvidenceState::RegistrationRevoked
        }
        AwsSnsTopicError::ConsentExpired => EvidenceState::ConsentExpired,
        AwsSnsTopicError::ConsentRevoked => EvidenceState::ConsentRevoked,
        AwsSnsTopicError::Transport(transport) => match transport {
            AwsSnsTransportError::Unauthorized
            | AwsSnsTransportError::Forbidden
            | AwsSnsTransportError::AccessLost => EvidenceState::AccessLoss,
            AwsSnsTransportError::NotFound => EvidenceState::NotFound,
            AwsSnsTransportError::RateLimited { .. } => EvidenceState::Throttled,
            AwsSnsTransportError::Partial => EvidenceState::Partial,
            AwsSnsTransportError::BadRequest
            | AwsSnsTransportError::ServerError { .. }
            | AwsSnsTransportError::Timeout
            | AwsSnsTransportError::BlockedEnv
            | AwsSnsTransportError::InvalidResponse => EvidenceState::ProviderUnknown,
        },
        _ => EvidenceState::ProviderUnknown,
    }
}

fn verification_failure(code: &str, error: &AwsSnsTopicError) -> VerificationFailure {
    VerificationFailure {
        code: code.to_owned(),
        detail_digest: Digest::from_parts(
            "aws-sns-verification-failure/v1",
            &[("error", error.to_string())],
        ),
    }
}

fn test_scope() -> AwsSnsTopicScope {
    use crate::model::{
        AwsAccountId, AwsRegion, ConsumerDeploymentIdentity, DeploymentId, MissionId,
        MissionIdentity, ProjectId, ProjectIdentity, SubscriptionArn, SubscriptionIdentity,
        TopicArn, TopicIdentity, WorkProductId, WorkProductIdentity,
    };
    AwsSnsTopicScope::new(
        AwsAccountId::new("000000000000").expect("account"),
        AwsRegion::new("blocked-env").expect("region"),
        TopicIdentity::new(
            TopicArn::new("arn:aws:sns:blocked-env:000000000000:blocked-topic")
                .expect("topic"),
        ),
        vec![SubscriptionIdentity::new(
            SubscriptionArn::new(
                "arn:aws:sns:blocked-env:000000000000:blocked-topic:00000000-0000-0000-0000-000000000000",
            )
            .expect("subscription"),
        )],
        ConsumerDeploymentIdentity::new(DeploymentId::new("blocked-deployment").expect("deployment"), 1)
            .expect("deployment binding"),
        MissionIdentity::new(MissionId::new("blocked-mission").expect("mission"), 1)
            .expect("mission binding"),
        ProjectIdentity::new(ProjectId::new("blocked-project").expect("project"), 1)
            .expect("project binding"),
        WorkProductIdentity::new(
            WorkProductId::new("blocked-work-product").expect("work product"),
            1,
        )
        .expect("work product binding"),
    )
    .expect("scope")
}

//! Registration, bounded reads, proposal, recording and verification seams.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;

use crate::consumer::MissionAwsS3BucketConsumer;
use crate::error::{AwsS3BucketError, AwsS3TransportError, Result};
use crate::model::{
    AwsS3BucketScope, AwsS3Observation, AwsS3Operation, AwsS3ReadRequest, BucketDurabilityPosture,
    BucketEncryptionObservation, BucketLifecycleObservation, BucketLocationObservation,
    BucketReplicationObservation, BucketVersioningObservation, Digest, MissionProjection,
    ProjectProjection, ProviderErrorEvidence, RedactedResponseReceipt, Revision, SecretReference,
    TransportProvenance, WorkProductProjection,
};
use crate::provider::{
    AwsS3OperationRequest, AwsS3Provider, AwsS3ProviderDefinition, AwsS3Transport, OpaqueMarker,
};
use crate::{
    API_VERSION, CONSUMER_ID, CONTRACT_SCHEMA, CONTRACT_VERSION, EVIDENCE_LEVEL, MAX_PAGES,
    MAX_REQUESTS_PER_READ, MAX_RESPONSE_BYTES, PLUGIN_ID, PLUGIN_VERSION, PROVIDER_API_REVISION,
    PROVIDER_ID, PROVIDER_VERSION, SERVICE_ID, api_digest, contract_digest, plugin_version_digest,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
    Reversed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsS3RegistrationTransition {
    pub from: RegistrationState,
    pub to: RegistrationState,
    pub revision: Revision,
    pub prior_registration_digest: Digest,
    pub reason_digest: Digest,
    pub transition_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsS3Registration {
    pub plugin_id: String,
    pub plugin_version: String,
    pub plugin_version_digest: Digest,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_api_revision: String,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub scope_digest: Digest,
    pub provider_scope_digest: Digest,
    pub bucket_digest: Digest,
    pub resource_revision: Revision,
    pub permission_digest: Digest,
    pub permission_revision: Revision,
    pub secret_reference_digest: Digest,
    pub evidence_policy_digest: Digest,
    pub registration_revision: Revision,
    pub state: RegistrationState,
    pub transitions: Vec<AwsS3RegistrationTransition>,
    pub registration_digest: Digest,
}

impl AwsS3Registration {
    pub fn new(
        scope: &AwsS3BucketScope,
        secret_reference: &SecretReference,
        provider_definition: &AwsS3ProviderDefinition,
        registration_revision: Revision,
    ) -> Result<Self> {
        scope.validate()?;
        provider_definition.validate()?;
        if secret_reference.scope_digest() != scope.digest() || secret_reference.is_revoked() {
            return Err(AwsS3BucketError::InvalidSecretReference);
        }
        let mut registration = Self {
            plugin_id: PLUGIN_ID.to_owned(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            plugin_version_digest: plugin_version_digest(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: provider_definition.provider_id.clone(),
            provider_version: provider_definition.provider_version.clone(),
            provider_api_revision: provider_definition.api_revision.clone(),
            provider_digest: provider_definition.provider_digest.clone(),
            api_digest: api_digest(),
            scope_digest: scope.digest().clone(),
            provider_scope_digest: scope.provider_scope().digest().clone(),
            bucket_digest: scope.bucket_digest(),
            resource_revision: scope.resource_revision(),
            permission_digest: scope.permission_snapshot().digest().clone(),
            permission_revision: scope.permission_snapshot().revision(),
            secret_reference_digest: secret_reference.reference_digest().clone(),
            evidence_policy_digest: evidence_policy_digest(scope, provider_definition),
            registration_revision,
            state: RegistrationState::Active,
            transitions: Vec::new(),
            registration_digest: Digest::zero(),
        };
        registration.registration_digest = registration.recomputed_digest();
        Ok(registration)
    }

    pub fn validate(&self) -> Result<()> {
        for digest in [
            &self.contract_digest,
            &self.plugin_version_digest,
            &self.provider_digest,
            &self.api_digest,
            &self.scope_digest,
            &self.provider_scope_digest,
            &self.bucket_digest,
            &self.permission_digest,
            &self.secret_reference_digest,
            &self.evidence_policy_digest,
            &self.registration_digest,
        ] {
            digest.validate()?;
        }
        if self.plugin_id != PLUGIN_ID
            || self.plugin_version != PLUGIN_VERSION
            || self.plugin_version_digest != plugin_version_digest()
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.provider_id != PROVIDER_ID
            || self.provider_version != PROVIDER_VERSION
            || self.provider_api_revision != PROVIDER_API_REVISION
            || self.api_digest != api_digest()
            || self.registration_revision.get() == 0
            || self.registration_digest != self.recomputed_digest()
        {
            return Err(AwsS3BucketError::InvalidRegistration);
        }
        for transition in &self.transitions {
            transition.prior_registration_digest.validate()?;
            transition.reason_digest.validate()?;
            transition.transition_digest.validate()?;
            if transition.transition_digest != transition_digest(transition) {
                return Err(AwsS3BucketError::InvalidRegistration);
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

    pub fn revoke(&mut self, reason: impl AsRef<str>) -> Result<AwsS3RegistrationTransition> {
        self.transition(RegistrationState::Revoked, reason)
    }

    pub fn reverse(&mut self, reason: impl AsRef<str>) -> Result<AwsS3RegistrationTransition> {
        self.transition(RegistrationState::Reversed, reason)
    }

    pub fn restore(&mut self, reason: impl AsRef<str>) -> Result<AwsS3RegistrationTransition> {
        if self.is_active() {
            return Err(AwsS3BucketError::RegistrationInactive);
        }
        self.transition(RegistrationState::Active, reason)
    }

    fn transition(
        &mut self,
        to: RegistrationState,
        reason: impl AsRef<str>,
    ) -> Result<AwsS3RegistrationTransition> {
        if self.state == to {
            return Err(match to {
                RegistrationState::Active => AwsS3BucketError::RegistrationInactive,
                RegistrationState::Revoked => AwsS3BucketError::RegistrationRevoked,
                RegistrationState::Reversed => AwsS3BucketError::RegistrationReversed,
            });
        }
        let transition = AwsS3RegistrationTransition {
            from: self.state,
            to,
            revision: self.registration_revision.next(),
            prior_registration_digest: self.registration_digest.clone(),
            reason_digest: Digest::from_text(reason.as_ref()),
            transition_digest: Digest::zero(),
        };
        let mut transition = transition;
        transition.transition_digest = transition_digest(&transition);
        self.state = to;
        self.registration_revision = transition.revision;
        self.transitions.push(transition.clone());
        self.registration_digest = self.recomputed_digest();
        self.validate()?;
        Ok(transition)
    }

    fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-s3-registration/v1",
            &[
                ("plugin_id", self.plugin_id.clone()),
                ("plugin_version", self.plugin_version.clone()),
                (
                    "plugin_version_digest",
                    self.plugin_version_digest.to_string(),
                ),
                ("contract_version", self.contract_version.clone()),
                ("contract", self.contract_digest.to_string()),
                ("provider_id", self.provider_id.clone()),
                ("provider_version", self.provider_version.clone()),
                ("provider_api_revision", self.provider_api_revision.clone()),
                ("provider", self.provider_digest.to_string()),
                ("api", self.api_digest.to_string()),
                ("scope", self.scope_digest.to_string()),
                ("provider_scope", self.provider_scope_digest.to_string()),
                ("bucket", self.bucket_digest.to_string()),
                (
                    "resource_revision",
                    self.resource_revision.get().to_string(),
                ),
                ("permission", self.permission_digest.to_string()),
                (
                    "permission_revision",
                    self.permission_revision.get().to_string(),
                ),
                ("secret", self.secret_reference_digest.to_string()),
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

fn transition_digest(transition: &AwsS3RegistrationTransition) -> Digest {
    Digest::from_parts(
        "aws-s3-registration-transition/v1",
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
    scope: &AwsS3BucketScope,
    provider_definition: &AwsS3ProviderDefinition,
) -> Digest {
    Digest::from_parts(
        "aws-s3-evidence-policy/v1",
        &[
            ("scope", scope.digest().to_string()),
            ("provider", provider_definition.provider_digest.to_string()),
            ("max_pages", MAX_PAGES.to_string()),
            ("max_requests", MAX_REQUESTS_PER_READ.to_string()),
            ("max_response_bytes", MAX_RESPONSE_BYTES.to_string()),
            (
                "redaction",
                "markers|provider_payload|object_keys|object_bytes|bucket_policy|kms_material|replication_role_arns".to_owned(),
            ),
        ],
    )
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsS3EvidenceState {
    Complete,
    ConfigurationUnknown,
    RegionDrift,
    Partial,
    Expired,
    AccessLoss,
    Unauthorized,
    Forbidden,
    NotFound,
    BadRequest,
    Throttled,
    Timeout,
    ProviderUnknown,
    RegistrationRevoked,
}

impl AwsS3EvidenceState {
    pub const fn is_review_complete(self) -> bool {
        matches!(self, Self::Complete)
    }

    pub const fn is_non_adoptable(self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsS3OperationEvidence {
    pub operation: AwsS3Operation,
    pub state: AwsS3EvidenceState,
    pub pages_observed: u16,
    pub response_bytes: u64,
    pub page_digests: Vec<Digest>,
    pub marker_digests: Vec<Digest>,
    pub observation_digest: Option<Digest>,
    pub failure: Option<ProviderErrorEvidence>,
    pub operation_digest: Digest,
}

impl AwsS3OperationEvidence {
    fn new(
        operation: AwsS3Operation,
        state: AwsS3EvidenceState,
        pages_observed: u16,
        response_bytes: u64,
        page_digests: Vec<Digest>,
        marker_digests: Vec<Digest>,
        observation_digest: Option<Digest>,
        failure: Option<ProviderErrorEvidence>,
    ) -> Self {
        let mut value = Self {
            operation,
            state,
            pages_observed,
            response_bytes,
            page_digests,
            marker_digests,
            observation_digest,
            failure,
            operation_digest: Digest::zero(),
        };
        value.operation_digest = value.recomputed_digest();
        value
    }

    pub fn validate(&self) -> Result<()> {
        if self.response_bytes > MAX_RESPONSE_BYTES
            || self.pages_observed > MAX_PAGES
            || self.operation_digest != self.recomputed_digest()
        {
            Err(AwsS3BucketError::TamperedEvidence)
        } else {
            Ok(())
        }
    }

    fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-s3-operation-evidence/v1",
            &[
                ("operation", self.operation.as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
                ("pages", self.pages_observed.to_string()),
                ("bytes", self.response_bytes.to_string()),
                (
                    "page_digests",
                    self.page_digests
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "marker_digests",
                    self.marker_digests
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "observation",
                    self.observation_digest
                        .as_ref()
                        .map_or_else(String::new, ToString::to_string),
                ),
                (
                    "failure",
                    self.failure
                        .as_ref()
                        .map_or_else(String::new, |value| value.error_digest.to_string()),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsS3EvidenceDigests {
    pub plugin_version_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub contract_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub provider_scope_digest: Digest,
    pub bucket_digest: Digest,
    pub resource_revision_digest: Digest,
    pub versioning_digest: Digest,
    pub encryption_digest: Digest,
    pub lifecycle_digest: Digest,
    pub replication_digest: Digest,
    pub location_digest: Digest,
    pub posture_digest: Digest,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsS3ReadEvidence {
    pub state: AwsS3EvidenceState,
    pub request: AwsS3ReadRequest,
    pub posture: BucketDurabilityPosture,
    pub operations: BTreeMap<AwsS3Operation, AwsS3OperationEvidence>,
    pub failure: Option<ProviderErrorEvidence>,
    pub response: RedactedResponseReceipt,
    pub digests: AwsS3EvidenceDigests,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub evidence_digest: Digest,
}

pub type AwsS3ReadResult = AwsS3ReadEvidence;

impl AwsS3ReadEvidence {
    #[allow(clippy::too_many_arguments)]
    fn new(
        state: AwsS3EvidenceState,
        request: AwsS3ReadRequest,
        posture: BucketDurabilityPosture,
        operations: BTreeMap<AwsS3Operation, AwsS3OperationEvidence>,
        failure: Option<ProviderErrorEvidence>,
        response: RedactedResponseReceipt,
        provider_definition: &AwsS3ProviderDefinition,
        provenance: TransportProvenance,
    ) -> Self {
        let mut value = Self {
            state,
            request,
            posture,
            operations,
            failure,
            response,
            digests: AwsS3EvidenceDigests {
                plugin_version_digest: plugin_version_digest(),
                provider_digest: provider_definition.provider_digest.clone(),
                api_digest: api_digest(),
                contract_digest: contract_digest(),
                permission_digest: Digest::zero(),
                scope_digest: Digest::zero(),
                provider_scope_digest: Digest::zero(),
                bucket_digest: Digest::zero(),
                resource_revision_digest: Digest::zero(),
                versioning_digest: Digest::zero(),
                encryption_digest: Digest::zero(),
                lifecycle_digest: Digest::zero(),
                replication_digest: Digest::zero(),
                location_digest: Digest::zero(),
                posture_digest: Digest::zero(),
                evidence_digest: Digest::zero(),
            },
            provenance,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            evidence_digest: Digest::zero(),
        };
        value.digests.permission_digest =
            value.request.scope().permission_snapshot().digest().clone();
        value.digests.scope_digest = value.request.scope().digest().clone();
        value.digests.provider_scope_digest =
            value.request.scope().provider_scope().digest().clone();
        value.digests.bucket_digest = value.request.scope().bucket_digest();
        value.digests.resource_revision_digest =
            Digest::from_text(value.request.scope().resource_revision().get().to_string());
        value.digests.versioning_digest = value
            .posture
            .versioning
            .as_ref()
            .map_or_else(Digest::zero, BucketVersioningObservation::digest);
        value.digests.encryption_digest = value
            .posture
            .encryption
            .as_ref()
            .map_or_else(Digest::zero, BucketEncryptionObservation::digest);
        value.digests.lifecycle_digest = value
            .posture
            .lifecycle
            .as_ref()
            .map_or_else(Digest::zero, BucketLifecycleObservation::digest);
        value.digests.replication_digest = value
            .posture
            .replication
            .as_ref()
            .map_or_else(Digest::zero, BucketReplicationObservation::digest);
        value.digests.location_digest = value
            .posture
            .location
            .as_ref()
            .map_or_else(Digest::zero, BucketLocationObservation::digest);
        value.digests.posture_digest = value.posture.digest().clone();
        value.evidence_digest = value.recomputed_digest();
        value.digests.evidence_digest = value.evidence_digest.clone();
        value
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.request.validate_against(self.request.scope())?;
        self.posture
            .validate_against(self.request.scope().provider_scope())?;
        self.response.validate()?;
        for (operation, evidence) in &self.operations {
            if *operation != evidence.operation {
                return Err(AwsS3BucketError::TamperedEvidence);
            }
            evidence.validate()?;
        }
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || !self.provenance.is_non_native()
            || self.evidence_digest != self.recomputed_digest()
            || self.digests.evidence_digest != self.evidence_digest
        {
            Err(AwsS3BucketError::TamperedEvidence)
        } else {
            Ok(())
        }
    }

    pub const fn is_review_complete(&self) -> bool {
        self.state.is_review_complete()
    }

    fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-s3-evidence/v1",
            &[
                ("state", format!("{:?}", self.state)),
                ("request", self.request.request_digest.to_string()),
                ("posture", self.posture.digest().to_string()),
                (
                    "operations",
                    self.operations
                        .iter()
                        .map(|(operation, evidence)| {
                            format!("{}={}", operation.as_str(), evidence.operation_digest)
                        })
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "failure",
                    self.failure
                        .as_ref()
                        .map_or_else(String::new, |value| value.error_digest.to_string()),
                ),
                ("response", self.response.receipt_digest.to_string()),
                ("plugin", self.digests.plugin_version_digest.to_string()),
                ("provider", self.digests.provider_digest.to_string()),
                ("api", self.digests.api_digest.to_string()),
                ("contract", self.digests.contract_digest.to_string()),
                ("permission", self.digests.permission_digest.to_string()),
                ("scope", self.digests.scope_digest.to_string()),
                (
                    "provider_scope",
                    self.digests.provider_scope_digest.to_string(),
                ),
                ("bucket", self.digests.bucket_digest.to_string()),
                (
                    "resource_revision",
                    self.digests.resource_revision_digest.to_string(),
                ),
                ("versioning", self.digests.versioning_digest.to_string()),
                ("encryption", self.digests.encryption_digest.to_string()),
                ("lifecycle", self.digests.lifecycle_digest.to_string()),
                ("replication", self.digests.replication_digest.to_string()),
                ("location", self.digests.location_digest.to_string()),
                ("posture_digest", self.digests.posture_digest.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsS3Proposal {
    pub service_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub provider_definition_digest: Digest,
    pub scope_digest: Digest,
    pub mission: MissionProjection,
    pub project: ProjectProjection,
    pub work_product: WorkProductProjection,
    pub request: AwsS3ReadRequest,
    pub state: AwsS3EvidenceState,
    pub posture: BucketDurabilityPosture,
    pub evidence: AwsS3ReadEvidence,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub proposal_digest: Digest,
}

pub type AwsS3BucketProposal = AwsS3Proposal;

impl AwsS3Proposal {
    fn new(
        scope: &AwsS3BucketScope,
        registration: &AwsS3Registration,
        provider_definition: &AwsS3ProviderDefinition,
        evidence: AwsS3ReadEvidence,
    ) -> Self {
        let mut value = Self {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_digest: registration.registration_digest.clone(),
            registration_revision: registration.registration_revision,
            provider_definition_digest: provider_definition.provider_digest.clone(),
            scope_digest: scope.digest().clone(),
            mission: MissionProjection::from(scope.mission()),
            project: ProjectProjection::from(scope.project()),
            work_product: WorkProductProjection::from(scope.work_product()),
            request: evidence.request.clone(),
            state: evidence.state,
            posture: evidence.posture.clone(),
            provenance: evidence.provenance,
            evidence,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: Digest::zero(),
        };
        value.proposal_digest = value.recomputed_digest();
        value
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || self.state != self.evidence.state
            || self.scope_digest != *self.evidence.request.scope_digest()
            || self.scope_digest != *self.request.scope_digest()
            || self.provenance != self.evidence.provenance
            || self.posture != self.evidence.posture
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.proposal_digest != self.recomputed_digest()
        {
            return Err(AwsS3BucketError::TamperedEvidence);
        }
        self.evidence.validate_integrity()
    }

    pub const fn is_review_only(&self) -> bool {
        true
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-s3-proposal/v1",
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
                ("posture", self.posture.digest().to_string()),
                ("evidence", self.evidence.evidence_digest.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsS3RecordReceipt {
    pub recorded: bool,
    pub recorded_at: DateTime<Utc>,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub state: AwsS3EvidenceState,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub durable_native_receipt: bool,
    pub independent_native_reread: bool,
    pub work_product_adopted: bool,
    pub receipt_digest: Digest,
}

impl AwsS3RecordReceipt {
    fn new(proposal: &AwsS3Proposal, recorded_at: DateTime<Utc>) -> Self {
        let mut value = Self {
            recorded: true,
            recorded_at,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            state: proposal.state,
            provenance: proposal.provenance,
            connected: false,
            native: false,
            first_party: false,
            durable_native_receipt: false,
            independent_native_reread: false,
            work_product_adopted: false,
            receipt_digest: Digest::zero(),
        };
        value.receipt_digest = value.recomputed_digest();
        value
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if !self.recorded
            || self.connected
            || self.native
            || self.first_party
            || self.durable_native_receipt
            || self.independent_native_reread
            || self.work_product_adopted
            || self.receipt_digest != self.recomputed_digest()
        {
            Err(AwsS3BucketError::TamperedEvidence)
        } else {
            Ok(())
        }
    }

    fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-s3-record-receipt/v1",
            &[
                ("recorded", self.recorded.to_string()),
                ("recorded_at", self.recorded_at.to_rfc3339()),
                ("proposal", self.proposal_digest.to_string()),
                ("evidence", self.evidence_digest.to_string()),
                ("registration", self.registration_digest.to_string()),
                ("scope", self.scope_digest.to_string()),
                ("state", format!("{:?}", self.state)),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsS3VerificationReport {
    pub valid: bool,
    pub review_eligible: bool,
    pub failures: Vec<String>,
    pub evidence_digest: Digest,
    pub proposal_digest: Digest,
    pub verification_digest: Digest,
}

pub type AwsS3Verification = AwsS3VerificationReport;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsS3CapabilityDescription {
    pub service_id: String,
    pub provider_id: String,
    pub api_version: String,
    pub api_revision: String,
    pub operations: Vec<AwsS3Operation>,
    pub max_pages: u16,
    pub max_requests_per_read: u16,
    pub max_response_bytes: u64,
    pub read_only: bool,
    pub proposal_only: bool,
    pub live_execution: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

pub type AwsS3Capability = AwsS3CapabilityDescription;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsS3BucketServiceDefinition {
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

impl AwsS3BucketServiceDefinition {
    fn new() -> Self {
        Self {
            schema_version: crate::CONTRACT_SCHEMA.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            plugin_id: PLUGIN_ID.to_owned(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            evidence_level: EVIDENCE_LEVEL.to_owned(),
            operations: AwsS3Operation::all()
                .iter()
                .map(|operation| operation.as_str().to_owned())
                .collect(),
            read_only: true,
            proposal_only: true,
            recording_only: true,
            live_execution: false,
            external_writes: false,
            kernel_authority: false,
            outcome_adoption: false,
        }
    }

    fn validate(&self) -> Result<()> {
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
            Err(AwsS3BucketError::ApiDrift)
        } else {
            Ok(())
        }
    }
}

pub struct AwsS3BucketService<T: AwsS3Transport> {
    scope: AwsS3BucketScope,
    secret_reference: SecretReference,
    provider: AwsS3Provider<T>,
    service_definition: AwsS3BucketServiceDefinition,
    registration: AwsS3Registration,
    now: DateTime<Utc>,
}

pub type AwsS3Service<T> = AwsS3BucketService<T>;

impl<T: AwsS3Transport> fmt::Debug for AwsS3BucketService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsS3BucketService")
            .field("scope_digest", self.scope.digest())
            .field("secret_reference", &self.secret_reference)
            .field("provider", self.provider.definition())
            .field("service_definition", &self.service_definition)
            .field("registration", &self.registration)
            .field("now", &self.now)
            .finish()
    }
}

impl<T: AwsS3Transport> AwsS3BucketService<T> {
    pub fn new(
        scope: AwsS3BucketScope,
        secret_reference: SecretReference,
        provider: AwsS3Provider<T>,
    ) -> Result<Self> {
        scope.validate()?;
        if secret_reference.scope_digest() != scope.digest() || secret_reference.is_revoked() {
            return Err(AwsS3BucketError::InvalidSecretReference);
        }
        provider.definition().validate()?;
        let service_definition = AwsS3BucketServiceDefinition::new();
        service_definition.validate()?;
        let registration = AwsS3Registration::new(
            &scope,
            &secret_reference,
            provider.definition(),
            Revision::new(1)?,
        )?;
        Ok(Self {
            scope,
            secret_reference,
            provider,
            service_definition,
            registration,
            now: Utc::now(),
        })
    }

    pub fn register(
        scope: AwsS3BucketScope,
        secret_reference: SecretReference,
        provider: AwsS3Provider<T>,
    ) -> Result<Self> {
        Self::new(scope, secret_reference, provider)
    }

    pub fn service_definition(&self) -> &AwsS3BucketServiceDefinition {
        &self.service_definition
    }

    pub fn provider_definition(&self) -> &AwsS3ProviderDefinition {
        self.provider.definition()
    }

    pub fn provider(&self) -> &AwsS3Provider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsS3Provider<T> {
        &mut self.provider
    }

    pub fn scope(&self) -> &AwsS3BucketScope {
        &self.scope
    }

    pub fn describe_scope(&self) -> &AwsS3BucketScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn registration(&self) -> &AwsS3Registration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut AwsS3Registration {
        &mut self.registration
    }

    pub fn set_now(&mut self, now: DateTime<Utc>) {
        self.now = now;
    }

    pub const fn is_active(&self) -> bool {
        self.registration.is_active()
    }

    pub fn describe_capabilities(&self) -> AwsS3CapabilityDescription {
        AwsS3CapabilityDescription {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            api_version: API_VERSION.to_owned(),
            api_revision: PROVIDER_API_REVISION.to_owned(),
            operations: AwsS3Operation::all().to_vec(),
            max_pages: MAX_PAGES,
            max_requests_per_read: MAX_REQUESTS_PER_READ,
            max_response_bytes: MAX_RESPONSE_BYTES,
            read_only: true,
            proposal_only: true,
            live_execution: false,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        }
    }

    pub fn default_request(&self) -> Result<AwsS3ReadRequest> {
        AwsS3ReadRequest::all_posture(&self.scope, self.now, self.now + Duration::minutes(5))
    }

    pub fn default_read_request(&self) -> Result<AwsS3ReadRequest> {
        self.default_request()
    }

    pub fn revoke_registration(
        &mut self,
        reason: impl AsRef<str>,
    ) -> Result<AwsS3RegistrationTransition> {
        self.registration.revoke(reason)
    }

    pub fn reverse_registration(
        &mut self,
        reason: impl AsRef<str>,
    ) -> Result<AwsS3RegistrationTransition> {
        self.registration.reverse(reason)
    }

    pub fn restore_registration(
        &mut self,
        reason: impl AsRef<str>,
    ) -> Result<AwsS3RegistrationTransition> {
        self.registration.restore(reason)
    }

    pub fn revoke_secret_reference(&mut self) -> Result<()> {
        self.secret_reference.revoke()
    }

    pub fn consumer(&self) -> Result<MissionAwsS3BucketConsumer> {
        self.ensure_active_and_bound()?;
        MissionAwsS3BucketConsumer::new(self.scope.clone(), self.registration.clone()).map_err(
            |error| match error {
                crate::consumer::ConsumerError::Service(error) => error,
                _ => AwsS3BucketError::RegistrationRevoked,
            },
        )
    }

    pub fn read_bounded(&mut self, request: AwsS3ReadRequest) -> Result<AwsS3ReadEvidence> {
        self.ensure_active_and_bound()?;
        request.validate_against(&self.scope)?;
        if request.is_expired_at(self.now) {
            return Ok(self.expired_evidence(request));
        }

        let mut operations = BTreeMap::new();
        let mut observations = Vec::new();
        let mut all_page_digests = Vec::new();
        let mut all_marker_digests = Vec::new();
        let mut response_bytes = 0_u64;
        let mut request_count = 0_u16;
        let mut first_failure = None;

        for operation in request.operations().iter().copied() {
            let mut retry_count = 0_u8;
            let mut marker: Option<OpaqueMarker> = None;
            let mut seen_markers = BTreeSet::new();
            let mut page_digests = Vec::new();
            let mut marker_digests = Vec::new();
            let mut pages_observed = 0_u16;
            let mut operation_bytes = 0_u64;
            let mut observation = None;
            let mut operation_failure = None;
            let mut operation_state = AwsS3EvidenceState::Complete;

            loop {
                if request_count >= request.max_requests {
                    operation_state = AwsS3EvidenceState::Partial;
                    let error = AwsS3TransportError::Partial;
                    operation_failure =
                        Some(ProviderErrorEvidence::from_transport(operation, &error));
                    break;
                }
                if pages_observed >= request.max_pages {
                    operation_state = AwsS3EvidenceState::Partial;
                    let error = AwsS3TransportError::Partial;
                    operation_failure =
                        Some(ProviderErrorEvidence::from_transport(operation, &error));
                    break;
                }
                if request.is_expired_at(self.now) {
                    operation_state = AwsS3EvidenceState::Expired;
                    let error = AwsS3TransportError::Expired;
                    operation_failure =
                        Some(ProviderErrorEvidence::from_transport(operation, &error));
                    break;
                }

                let operation_request = AwsS3OperationRequest::new(
                    &request,
                    operation,
                    pages_observed.saturating_add(1),
                    marker.clone(),
                )?;
                request_count = request_count.saturating_add(1);
                match self.provider.read(&operation_request) {
                    Ok(page) => {
                        pages_observed = pages_observed.saturating_add(1);
                        operation_bytes = operation_bytes.saturating_add(page.response_bytes);
                        response_bytes = response_bytes.saturating_add(page.response_bytes);
                        if response_bytes > request.max_response_bytes {
                            operation_state = AwsS3EvidenceState::Partial;
                            let error = AwsS3TransportError::Partial;
                            operation_failure =
                                Some(ProviderErrorEvidence::from_transport(operation, &error));
                            break;
                        }
                        page_digests.push(page.response_digest.clone());
                        all_page_digests.push(page.response_digest.clone());
                        if let Some(next_marker) = page.next_marker.clone() {
                            let marker_digest = next_marker.token_digest().clone();
                            if !seen_markers.insert(marker_digest.clone()) {
                                operation_state = AwsS3EvidenceState::Partial;
                                let error = AwsS3TransportError::MarkerReplay;
                                operation_failure =
                                    Some(ProviderErrorEvidence::from_transport(operation, &error));
                                break;
                            }
                            marker_digests.push(marker_digest.clone());
                            all_marker_digests.push(marker_digest);
                            marker = Some(next_marker);
                        } else {
                            marker = None;
                        }
                        match observation {
                            None => observation = Some(page.observation.clone()),
                            Some(ref existing)
                                if existing.digest() == page.observation.digest() => {}
                            Some(_) => {
                                operation_state = AwsS3EvidenceState::Partial;
                                let error = AwsS3TransportError::ScopeDrift;
                                operation_failure =
                                    Some(ProviderErrorEvidence::from_transport(operation, &error));
                                break;
                            }
                        }
                        if marker.is_none() {
                            break;
                        }
                    }
                    Err(error) => {
                        let transport = match error {
                            AwsS3BucketError::Transport(error) => error,
                            AwsS3BucketError::ScopeMismatch(_) => AwsS3TransportError::ScopeDrift,
                            _ => AwsS3TransportError::Unknown,
                        };
                        if transport.retryable() && retry_count < 2 {
                            retry_count = retry_count.saturating_add(1);
                            continue;
                        }
                        operation_state = state_from_transport(&transport);
                        operation_failure =
                            Some(ProviderErrorEvidence::from_transport(operation, &transport));
                        break;
                    }
                }
            }

            if let Some(observation) = &observation {
                observations.push(observation.clone());
            }
            if first_failure.is_none() {
                first_failure.clone_from(&operation_failure);
            }
            operations.insert(
                operation,
                AwsS3OperationEvidence::new(
                    operation,
                    operation_state,
                    pages_observed,
                    operation_bytes,
                    page_digests,
                    marker_digests,
                    observation.as_ref().map(AwsS3Observation::digest),
                    operation_failure,
                ),
            );
        }

        let posture = BucketDurabilityPosture::from_observations(observations)?;
        let state = aggregate_state(&request, &operations, &posture);
        let response =
            RedactedResponseReceipt::new(response_bytes, all_page_digests, all_marker_digests)?;
        Ok(AwsS3ReadEvidence::new(
            state,
            request,
            posture,
            operations,
            first_failure,
            response,
            self.provider.definition(),
            self.provider.provenance(),
        ))
    }

    pub fn read(&mut self, request: AwsS3ReadRequest) -> Result<AwsS3ReadEvidence> {
        self.read_bounded(request)
    }

    pub fn propose(&mut self, request: AwsS3ReadRequest) -> Result<AwsS3Proposal> {
        self.ensure_active_and_bound()?;
        let evidence = self.read_bounded(request)?;
        Ok(AwsS3Proposal::new(
            &self.scope,
            &self.registration,
            self.provider.definition(),
            evidence,
        ))
    }

    pub fn record(&self, proposal: &AwsS3Proposal) -> Result<AwsS3RecordReceipt> {
        self.ensure_active_and_bound()?;
        self.validate_proposal(proposal)?;
        Ok(AwsS3RecordReceipt::new(proposal, self.now))
    }

    pub fn record_at(
        &self,
        proposal: &AwsS3Proposal,
        recorded_at: DateTime<Utc>,
    ) -> Result<AwsS3RecordReceipt> {
        self.ensure_active_and_bound()?;
        self.validate_proposal(proposal)?;
        Ok(AwsS3RecordReceipt::new(proposal, recorded_at))
    }

    pub fn verify(&self, proposal: &AwsS3Proposal) -> AwsS3VerificationReport {
        let mut failures = Vec::new();
        if !self.registration.is_active() {
            failures.push("registration_inactive".to_owned());
        }
        if proposal.registration_digest != *self.registration.registration_digest() {
            failures.push("registration_digest_mismatch".to_owned());
        }
        if proposal.provider_definition_digest != self.provider.definition().provider_digest {
            failures.push("provider_digest_mismatch".to_owned());
        }
        if proposal.scope_digest != *self.scope.digest() {
            failures.push("scope_digest_mismatch".to_owned());
        }
        if proposal.validate_integrity().is_err() {
            failures.push("tampered_evidence".to_owned());
        }
        if proposal.state != AwsS3EvidenceState::Complete {
            failures.push(format!("state_{:?}", proposal.state).to_lowercase());
        }
        failures.sort_unstable();
        failures.dedup();
        let valid = failures.is_empty();
        let verification_digest = Digest::from_parts(
            "aws-s3-verification/v1",
            &[
                ("valid", valid.to_string()),
                ("proposal", proposal.proposal_digest.to_string()),
                ("evidence", proposal.evidence.evidence_digest.to_string()),
                ("failures", failures.join(",")),
            ],
        );
        AwsS3VerificationReport {
            valid,
            review_eligible: valid && proposal.state == AwsS3EvidenceState::Complete,
            failures,
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            verification_digest,
        }
    }

    pub fn verify_record(&self, receipt: &AwsS3RecordReceipt) -> Result<AwsS3RecordReceipt> {
        self.ensure_active_and_bound()?;
        receipt.validate_integrity()?;
        if receipt.registration_digest != self.registration.registration_digest
            || receipt.scope_digest != *self.scope.digest()
        {
            return Err(AwsS3BucketError::ScopeMismatch(
                "record receipt registration or scope".to_owned(),
            ));
        }
        Ok(receipt.clone())
    }

    fn expired_evidence(&self, request: AwsS3ReadRequest) -> AwsS3ReadEvidence {
        let operations = request
            .operations()
            .iter()
            .copied()
            .map(|operation| {
                (
                    operation,
                    AwsS3OperationEvidence::new(
                        operation,
                        AwsS3EvidenceState::Expired,
                        0,
                        0,
                        Vec::new(),
                        Vec::new(),
                        None,
                        Some(ProviderErrorEvidence::from_transport(
                            operation,
                            &AwsS3TransportError::Expired,
                        )),
                    ),
                )
            })
            .collect();
        let response = RedactedResponseReceipt::new(0, Vec::new(), Vec::new())
            .expect("zero-byte redacted S3 receipt is bounded");
        AwsS3ReadEvidence::new(
            AwsS3EvidenceState::Expired,
            request,
            BucketDurabilityPosture::empty(),
            operations,
            None,
            response,
            self.provider.definition(),
            self.provider.provenance(),
        )
    }

    fn ensure_active_and_bound(&self) -> Result<()> {
        if !self.registration.is_active() {
            return Err(match self.registration.state {
                RegistrationState::Revoked => AwsS3BucketError::RegistrationRevoked,
                RegistrationState::Reversed => AwsS3BucketError::RegistrationReversed,
                RegistrationState::Active => AwsS3BucketError::RegistrationInactive,
            });
        }
        self.scope.validate()?;
        self.provider.definition().validate()?;
        self.registration.validate()?;
        if self.secret_reference.is_revoked()
            || self.secret_reference.scope_digest() != self.scope.digest()
            || self.secret_reference.reference_digest()
                != &self.registration.secret_reference_digest
            || self.registration.scope_digest != *self.scope.digest()
            || self.registration.provider_scope_digest != *self.scope.provider_scope().digest()
            || self.registration.bucket_digest != self.scope.bucket_digest()
            || self.registration.resource_revision != self.scope.resource_revision()
            || self.registration.permission_digest != *self.scope.permission_snapshot().digest()
            || self.registration.provider_digest != self.provider.definition().provider_digest
            || self.registration.api_digest != api_digest()
        {
            return Err(AwsS3BucketError::ScopeMismatch(
                "active S3 registration binding".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_proposal(&self, proposal: &AwsS3Proposal) -> Result<()> {
        proposal.validate_integrity()?;
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.registration_revision != self.registration.registration_revision
            || proposal.provider_definition_digest != self.provider.definition().provider_digest
            || proposal.scope_digest != *self.scope.digest()
            || proposal.evidence.digests.permission_digest
                != *self.scope.permission_snapshot().digest()
            || proposal.evidence.digests.provider_digest
                != self.provider.definition().provider_digest
            || proposal.evidence.digests.api_digest != api_digest()
            || proposal.evidence.digests.contract_digest != contract_digest()
            || proposal.evidence.digests.plugin_version_digest != plugin_version_digest()
        {
            return Err(AwsS3BucketError::TamperedEvidence);
        }
        Ok(())
    }
}

fn state_from_transport(error: &AwsS3TransportError) -> AwsS3EvidenceState {
    match error {
        AwsS3TransportError::Unauthorized => AwsS3EvidenceState::Unauthorized,
        AwsS3TransportError::Forbidden => AwsS3EvidenceState::Forbidden,
        AwsS3TransportError::NotFound => AwsS3EvidenceState::NotFound,
        AwsS3TransportError::BadRequest => AwsS3EvidenceState::BadRequest,
        AwsS3TransportError::Throttled { .. } => AwsS3EvidenceState::Throttled,
        AwsS3TransportError::Timeout => AwsS3EvidenceState::Timeout,
        AwsS3TransportError::Expired => AwsS3EvidenceState::Expired,
        AwsS3TransportError::Partial | AwsS3TransportError::MarkerReplay => {
            AwsS3EvidenceState::Partial
        }
        AwsS3TransportError::ServerFailure { .. }
        | AwsS3TransportError::BlockedEnv
        | AwsS3TransportError::MalformedResponse
        | AwsS3TransportError::ScopeDrift
        | AwsS3TransportError::Unknown => AwsS3EvidenceState::ProviderUnknown,
    }
}

fn aggregate_state(
    request: &AwsS3ReadRequest,
    operations: &BTreeMap<AwsS3Operation, AwsS3OperationEvidence>,
    posture: &BucketDurabilityPosture,
) -> AwsS3EvidenceState {
    if operations
        .values()
        .any(|evidence| evidence.state == AwsS3EvidenceState::Expired)
    {
        return AwsS3EvidenceState::Expired;
    }
    if operations.values().any(|evidence| {
        matches!(
            evidence.state,
            AwsS3EvidenceState::Unauthorized
                | AwsS3EvidenceState::Forbidden
                | AwsS3EvidenceState::NotFound
        )
    }) {
        return AwsS3EvidenceState::AccessLoss;
    }
    if operations.values().any(|evidence| {
        matches!(
            evidence.state,
            AwsS3EvidenceState::Partial
                | AwsS3EvidenceState::BadRequest
                | AwsS3EvidenceState::Throttled
                | AwsS3EvidenceState::Timeout
                | AwsS3EvidenceState::ProviderUnknown
        )
    }) {
        return AwsS3EvidenceState::Partial;
    }
    if posture.has_region_drift() {
        return AwsS3EvidenceState::RegionDrift;
    }
    if !posture.is_complete()
        || posture.has_unknown_configuration()
        || request.operations().iter().any(|operation| {
            operations
                .get(operation)
                .and_then(|evidence| evidence.observation_digest.as_ref())
                .is_none()
        })
    {
        return AwsS3EvidenceState::ConfigurationUnknown;
    }
    AwsS3EvidenceState::Complete
}

pub type AwsS3BucketResultService<T> = AwsS3BucketService<T>;
pub type AwsS3RegistrationReceipt = AwsS3Registration;
pub type AwsS3ServiceError = AwsS3BucketError;

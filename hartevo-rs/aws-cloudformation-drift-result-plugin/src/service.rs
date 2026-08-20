//! Layer-1 CloudFormation drift service, registration, proposal, and
//! verification seams.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::consumer::MissionAwsCloudFormationDriftConsumer;
use crate::error::{AwsCloudFormationDriftError, AwsCloudFormationTransportError, Result};
use crate::model::{
    AwsCloudFormationDriftScope, CloudFormationDriftEvidence, CloudFormationEvidenceRequest,
    CloudFormationEvidenceState, CloudFormationOperation, ConsentScope,
    DescribeStackDriftDetectionStatusRequest, DescribeStackEventsRequest,
    DescribeStackResourceDriftsRequest, DescribeStacksRequest, DetectStackDriftRequest,
    DriftDetectionProgress, DriftDetectionStatus, EvidenceDigests, MissionProjection, OpaqueCursor,
    PermissionSnapshot, ProjectProjection, ProviderErrorEvidence, ResourceDrift,
    ResourceDriftFilter, StackDriftStatus, StackEvent, StackSummary, TransportProvenance,
    WorkProductProjection, digest_serialized, mission_projection, project_projection,
    work_product_projection,
};
use crate::provider::{
    AwsCloudFormationProvider, AwsCloudFormationProviderDefinition, AwsCloudFormationTransport,
};
use crate::{
    CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_VERSION, PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID,
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
    pub registration_digest: crate::model::Digest,
    pub transition_digest: crate::model::Digest,
}

impl RegistrationTransitionEvidence {
    fn new(
        previous_status: RegistrationStatus,
        new_status: RegistrationStatus,
        registration_digest: crate::model::Digest,
    ) -> Self {
        let transition_digest = crate::model::Digest::from_parts(
            "aws-cloudformation-registration-transition/v1",
            &[
                ("previous", format!("{previous_status:?}")),
                ("new", format!("{new_status:?}")),
                ("registration", registration_digest.to_string()),
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

/// Version, provider, permission, consent, scope, and opaque-secret bound
/// registration. The secret reference itself is never serialized.
#[derive(Clone, Eq, PartialEq)]
pub struct AwsCloudFormationDriftRegistration {
    id: String,
    plugin_version: String,
    contract_version: String,
    contract_digest: crate::model::Digest,
    provider_id: String,
    provider_revision: u64,
    provider_release: String,
    provider_digest: crate::model::Digest,
    permission_snapshot: PermissionSnapshot,
    consent: ConsentScope,
    scope: AwsCloudFormationDriftScope,
    scope_digest: crate::model::Digest,
    secret_reference: crate::model::SecretReference,
    registration_revision: u64,
    status: RegistrationStatus,
    registration_digest: crate::model::Digest,
}

impl AwsCloudFormationDriftRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        scope: AwsCloudFormationDriftScope,
        secret_reference: crate::model::SecretReference,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        provider: &AwsCloudFormationProviderDefinition,
        registration_revision: u64,
    ) -> Result<Self> {
        let mut registration = Self {
            id: id.into(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: crate::model::Digest::parse(CONTRACT_DIGEST.to_owned())?,
            provider_id: provider.provider_id.clone(),
            provider_revision: provider.provider_revision,
            provider_release: provider.release.clone(),
            provider_digest: provider.provider_digest.clone(),
            permission_snapshot,
            consent,
            scope_digest: scope.digest(),
            scope,
            secret_reference,
            registration_revision,
            status: RegistrationStatus::Active,
            registration_digest: crate::model::Digest::from_text(
                "unsealed-cloudformation-registration",
            ),
        };
        registration.registration_digest = registration.recomputed_digest();
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

    pub fn contract_digest(&self) -> &crate::model::Digest {
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

    pub fn provider_digest(&self) -> &crate::model::Digest {
        &self.provider_digest
    }

    pub fn permission_snapshot(&self) -> &PermissionSnapshot {
        &self.permission_snapshot
    }

    pub fn permission_digest(&self) -> crate::model::Digest {
        self.permission_snapshot.digest()
    }

    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    pub fn consent_digest(&self) -> crate::model::Digest {
        self.consent.digest()
    }

    pub fn scope(&self) -> &AwsCloudFormationDriftScope {
        &self.scope
    }

    pub fn scope_digest(&self) -> &crate::model::Digest {
        &self.scope_digest
    }

    pub fn secret_reference(&self) -> &crate::model::SecretReference {
        &self.secret_reference
    }

    pub fn secret_reference_digest(&self) -> &crate::model::Digest {
        self.secret_reference.reference_digest()
    }

    pub const fn registration_revision(&self) -> u64 {
        self.registration_revision
    }

    pub const fn status(&self) -> RegistrationStatus {
        self.status
    }

    pub fn registration_digest(&self) -> &crate::model::Digest {
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
            || self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.provider_release.is_empty()
            || self.registration_revision == 0
            || self.scope_digest != self.scope.digest()
            || self.registration_digest != self.recomputed_digest()
        {
            return Err(AwsCloudFormationDriftError::InvalidRegistration);
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
            return Err(AwsCloudFormationDriftError::InvalidConsent);
        }
        self.consent.validate()
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsCloudFormationDriftError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Revoked;
        self.registration_digest = self.recomputed_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsCloudFormationDriftError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Reversed;
        self.registration_digest = self.recomputed_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsCloudFormationDriftError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Active;
        self.registration_digest = self.recomputed_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    fn recomputed_digest(&self) -> crate::model::Digest {
        crate::model::Digest::from_parts(
            "aws-cloudformation-registration/v1",
            &[
                ("id", self.id.clone()),
                ("plugin_version", self.plugin_version.clone()),
                ("contract_version", self.contract_version.clone()),
                ("contract", self.contract_digest.to_string()),
                ("provider_id", self.provider_id.clone()),
                ("provider_revision", self.provider_revision.to_string()),
                ("provider_release", self.provider_release.clone()),
                ("provider", self.provider_digest.to_string()),
                ("permission", self.permission_digest().to_string()),
                ("consent", self.consent_digest().to_string()),
                ("scope", self.scope_digest.to_string()),
                (
                    "secret",
                    self.secret_reference.reference_digest().to_string(),
                ),
                ("revision", self.registration_revision.to_string()),
                ("status", format!("{:?}", self.status)),
            ],
        )
    }
}

impl fmt::Debug for AwsCloudFormationDriftRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsCloudFormationDriftRegistration")
            .field("id_digest", &crate::model::Digest::from_text(&self.id))
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_id", &self.provider_id)
            .field("provider_revision", &self.provider_revision)
            .field("provider_digest", &self.provider_digest)
            .field("permission_digest", &self.permission_digest())
            .field("consent_digest", &self.consent_digest())
            .field("scope_digest", &self.scope_digest)
            .field("secret_reference_digest", &self.secret_reference_digest())
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("registration_digest", &self.registration_digest)
            .finish()
    }
}

impl Serialize for AwsCloudFormationDriftRegistration {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsCloudFormationDriftRegistration", 15)?;
        state.serialize_field("idDigest", &crate::model::Digest::from_text(&self.id))?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("providerRelease", &self.provider_release)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest())?;
        state.serialize_field("consentDigest", &self.consent_digest())?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("secretReferenceDigest", &self.secret_reference_digest())?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
        state.end()
    }
}

pub type AwsCloudFormationRegistration = AwsCloudFormationDriftRegistration;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityDescription {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub operations: Vec<String>,
    pub permissions: Vec<String>,
    pub read_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub outcome_adoption: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsCloudFormationDriftProposal {
    pub service_id: String,
    pub consumer_id: String,
    pub registration_digest: crate::model::Digest,
    pub scope_digest: crate::model::Digest,
    pub account_digest: crate::model::Digest,
    pub region_digest: crate::model::Digest,
    pub stack_digest: crate::model::Digest,
    pub stack_revision: u64,
    pub mission: MissionProjection,
    pub project: ProjectProjection,
    pub work_product: WorkProductProjection,
    pub state: CloudFormationEvidenceState,
    pub observed_drift_status: Option<StackDriftStatus>,
    pub evidence: CloudFormationDriftEvidence,
    pub failure: Option<ProviderErrorEvidence>,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub drift_claim: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub proposal_digest: crate::model::Digest,
}

impl AwsCloudFormationDriftProposal {
    fn new(
        registration: &AwsCloudFormationDriftRegistration,
        evidence: CloudFormationDriftEvidence,
    ) -> Self {
        let observed_drift_status = evidence
            .detection
            .as_ref()
            .and_then(|value| value.stack_drift_status);
        let failure = evidence.provider_errors.first().cloned();
        let mut proposal = Self {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_digest: registration.registration_digest.clone(),
            scope_digest: registration.scope_digest.clone(),
            account_digest: registration.scope.account().digest(),
            region_digest: registration.scope.region().digest(),
            stack_digest: registration.scope.stack().digest(),
            stack_revision: registration.scope.stack_revision(),
            mission: mission_projection(registration.scope.mission()),
            project: project_projection(registration.scope.project()),
            work_product: work_product_projection(registration.scope.work_product()),
            state: evidence.state,
            observed_drift_status,
            evidence,
            failure,
            provenance: TransportProvenance::Recording,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            drift_claim: matches!(observed_drift_status, Some(StackDriftStatus::Drifted)),
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: crate::model::Digest::from_text("unsealed-cloudformation-proposal"),
        };
        proposal.provenance = proposal.evidence.provenance;
        proposal.proposal_digest = proposal.recomputed_digest();
        proposal
    }

    pub fn recomputed_digest(&self) -> crate::model::Digest {
        crate::model::Digest::from_parts(
            "aws-cloudformation-proposal/v1",
            &[
                ("service", self.service_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("registration", self.registration_digest.to_string()),
                ("scope", self.scope_digest.to_string()),
                ("account", self.account_digest.to_string()),
                ("region", self.region_digest.to_string()),
                ("stack", self.stack_digest.to_string()),
                ("stack_revision", self.stack_revision.to_string()),
                ("mission", self.mission.id_digest.to_string()),
                ("project", self.project.id_digest.to_string()),
                ("work_product", self.work_product.id_digest.to_string()),
                ("state", format!("{:?}", self.state)),
                (
                    "drift_status",
                    self.observed_drift_status
                        .map_or_else(String::new, |value| format!("{value:?}")),
                ),
                (
                    "evidence",
                    self.evidence.evidence.evidence_digest.to_string(),
                ),
                (
                    "failure",
                    self.failure
                        .as_ref()
                        .map_or_else(String::new, |value| value.failure_digest.to_string()),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
                ("connected", self.connected.to_string()),
                ("native", self.native.to_string()),
                ("first_party", self.first_party.to_string()),
                ("provider_receipt", self.provider_receipt.to_string()),
                ("drift_claim", self.drift_claim.to_string()),
                ("outcome_adopted", self.outcome_adopted.to_string()),
                (
                    "work_product_adopted",
                    self.work_product_adopted.to_string(),
                ),
            ],
        )
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.evidence.provenance != self.provenance
            || self.evidence.stack_revision != self.stack_revision
            || self.evidence.evidence.scope_digest != self.scope_digest
            || self
                .evidence
                .stack
                .as_ref()
                .is_some_and(|stack| stack.stack_digest != self.stack_digest)
            || self.proposal_digest != self.recomputed_digest()
        {
            return Err(AwsCloudFormationDriftError::TamperedEvidence);
        }
        self.evidence.validate_integrity()
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub const fn is_review_only(&self) -> bool {
        true
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailure {
    RegistrationInactive,
    RegistrationDigestMismatch,
    ProviderDigestMismatch,
    PermissionDigestMismatch,
    ConsentDigestMismatch,
    ScopeDigestMismatch,
    TamperedEvidence,
    PartialEvidence,
    InProgressEvidence,
    AccessLoss,
    Throttled,
    ProviderUnknown,
    NotFound,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub valid: bool,
    pub review_eligible: bool,
    pub failures: Vec<VerificationFailure>,
    pub verification_digest: crate::model::Digest,
}

impl VerificationReport {
    fn new(valid: bool, review_eligible: bool, mut failures: Vec<VerificationFailure>) -> Self {
        failures.sort_unstable();
        failures.dedup();
        let verification_digest = digest_serialized(&(valid, review_eligible, &failures));
        Self {
            valid,
            review_eligible,
            failures,
            verification_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedAwsCloudFormationDriftResult {
    pub idempotency_key_digest: crate::model::Digest,
    pub proposal_digest: crate::model::Digest,
    pub state: CloudFormationEvidenceState,
    pub provenance: TransportProvenance,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub recording_digest: crate::model::Digest,
}

impl RecordedAwsCloudFormationDriftResult {
    pub(crate) fn new(
        idempotency_key_digest: crate::model::Digest,
        proposal: &AwsCloudFormationDriftProposal,
        replayed: bool,
    ) -> Self {
        let mut value = Self {
            idempotency_key_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            state: proposal.state,
            provenance: proposal.provenance,
            replayed,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            recording_digest: crate::model::Digest::from_text("unsealed-cloudformation-recording"),
        };
        value.recording_digest = value.recomputed_digest();
        value
    }

    fn recomputed_digest(&self) -> crate::model::Digest {
        digest_serialized(&(
            &self.idempotency_key_digest,
            &self.proposal_digest,
            self.state,
            self.provenance,
            self.replayed,
        ))
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.recording_digest != self.recomputed_digest()
        {
            return Err(AwsCloudFormationDriftError::TamperedEvidence);
        }
        Ok(())
    }
}

pub struct AwsCloudFormationDriftService<T: AwsCloudFormationTransport> {
    registration: AwsCloudFormationDriftRegistration,
    provider: AwsCloudFormationProvider<T>,
    recordings: BTreeMap<crate::model::Digest, RecordedAwsCloudFormationDriftResult>,
}

impl<T: AwsCloudFormationTransport> fmt::Debug for AwsCloudFormationDriftService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsCloudFormationDriftService")
            .field("registration", &self.registration)
            .field("provider", &self.provider)
            .field("recording_count", &self.recordings.len())
            .finish()
    }
}

impl<T: AwsCloudFormationTransport> AwsCloudFormationDriftService<T> {
    pub fn new(
        scope: AwsCloudFormationDriftScope,
        secret_reference: crate::model::SecretReference,
        consent: ConsentScope,
        provider: AwsCloudFormationProvider<T>,
        _registration_time: DateTime<Utc>,
    ) -> Result<Self> {
        Self::with_registration(
            "aws-cloudformation-drift-registration",
            scope,
            secret_reference,
            PermissionSnapshot::for_layer_one(1),
            consent,
            provider,
            1,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_registration(
        registration_id: impl Into<String>,
        scope: AwsCloudFormationDriftScope,
        secret_reference: crate::model::SecretReference,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        provider: AwsCloudFormationProvider<T>,
        registration_revision: u64,
    ) -> Result<Self> {
        let registration = AwsCloudFormationDriftRegistration::new(
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
            recordings: BTreeMap::new(),
        })
    }

    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            operations: vec![
                CloudFormationOperation::DescribeStacks.as_str().to_owned(),
                CloudFormationOperation::DescribeStackEvents
                    .as_str()
                    .to_owned(),
                CloudFormationOperation::DetectStackDrift
                    .as_str()
                    .to_owned(),
                CloudFormationOperation::DescribeStackDriftDetectionStatus
                    .as_str()
                    .to_owned(),
                CloudFormationOperation::DescribeStackResourceDrifts
                    .as_str()
                    .to_owned(),
            ],
            permissions: crate::LAYER1_PERMISSIONS
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect(),
            read_only: true,
            connected: false,
            native: false,
            first_party: false,
            outcome_adoption: false,
        }
    }

    pub fn scope(&self) -> &AwsCloudFormationDriftScope {
        self.registration.scope()
    }

    pub fn registration(&self) -> &AwsCloudFormationDriftRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut AwsCloudFormationDriftRegistration {
        &mut self.registration
    }

    pub fn provider(&self) -> &AwsCloudFormationProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsCloudFormationProvider<T> {
        &mut self.provider
    }

    pub fn request(
        &self,
        logical_resource_ids: impl IntoIterator<Item = crate::model::LogicalResourceId>,
        resource_filter: ResourceDriftFilter,
        page_size: u16,
        max_pages: u16,
        max_polls: u16,
        max_retries: u8,
        observed_at: DateTime<Utc>,
    ) -> Result<CloudFormationEvidenceRequest> {
        CloudFormationEvidenceRequest::new(
            self.scope(),
            self.provider.definition().provider_digest.clone(),
            self.registration.registration_digest.clone(),
            logical_resource_ids,
            resource_filter,
            page_size,
            max_pages,
            max_polls,
            max_retries,
            observed_at,
        )
    }

    pub fn default_request(
        &self,
        observed_at: DateTime<Utc>,
    ) -> Result<CloudFormationEvidenceRequest> {
        self.request(
            Vec::new(),
            ResourceDriftFilter::all(),
            crate::MAX_PAGE_SIZE,
            crate::MAX_PAGES,
            crate::MAX_POLLS,
            crate::MAX_RETRIES,
            observed_at,
        )
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

    pub fn consumer(&self) -> Result<MissionAwsCloudFormationDriftConsumer> {
        MissionAwsCloudFormationDriftConsumer::new(self.scope().clone(), self.registration.clone())
    }

    pub fn record(
        &mut self,
        proposal: &AwsCloudFormationDriftProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedAwsCloudFormationDriftResult> {
        self.verify_proposal(proposal)?;
        let key = idempotency_key.as_ref();
        if key.is_empty()
            || key.len() > crate::MAX_IDENTIFIER_BYTES
            || key.chars().any(char::is_control)
        {
            return Err(AwsCloudFormationDriftError::InvalidRequest);
        }
        let key_digest = crate::model::Digest::from_text(key);
        if let Some(existing) = self.recordings.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(AwsCloudFormationDriftError::RecordingConflict);
            }
            let replay =
                RecordedAwsCloudFormationDriftResult::new(key_digest.clone(), proposal, true);
            self.recordings.insert(key_digest, replay.clone());
            return Ok(replay);
        }
        let value = RecordedAwsCloudFormationDriftResult::new(key_digest.clone(), proposal, false);
        self.recordings.insert(key_digest, value.clone());
        Ok(value)
    }

    pub fn recording_count(&self) -> usize {
        self.recordings.len()
    }

    pub fn read(
        &mut self,
        request: CloudFormationEvidenceRequest,
    ) -> Result<CloudFormationDriftEvidence> {
        self.registration.validate()?;
        self.ensure_active_and_consented(&request)?;
        request.validate_against(
            self.scope(),
            &self.provider.definition().provider_digest,
            &self.registration.registration_digest,
        )?;

        let mut provider_errors = Vec::new();
        let mut stacks_pages = 0_u16;
        let mut events_pages = 0_u16;
        let mut resource_pages = 0_u16;
        let mut polls_observed = 0_u16;
        let mut truncated = false;
        let mut stack_complete = false;
        let mut events_complete = false;
        let mut resources_complete = false;
        let mut terminal_state = None;
        let mut stack: Option<StackSummary> = None;
        let mut events = Vec::new();
        let mut detection = None;
        let mut resource_drifts = Vec::new();
        let mut cursor_digest = None;

        let mut stack_cursor: Option<OpaqueCursor> = None;
        let mut seen_stack_cursors = BTreeSet::new();
        loop {
            if stacks_pages >= request.max_pages {
                truncated = true;
                break;
            }
            let stack_request = DescribeStacksRequest::new(
                self.scope(),
                request.page_size,
                request.max_pages,
                stack_cursor.clone(),
            )?;
            match retry_transport(request.max_retries, || {
                self.provider.describe_stacks(&stack_request)
            }) {
                Ok(response) => {
                    stacks_pages = stacks_pages.saturating_add(1);
                    for observed in response.stacks {
                        if observed.stack_digest != self.scope().stack().digest() {
                            provider_errors.push(ProviderErrorEvidence::new(
                                CloudFormationOperation::DescribeStacks,
                                None,
                                "scope_mismatch",
                            ));
                            terminal_state = Some(CloudFormationEvidenceState::Partial);
                            truncated = true;
                            break;
                        }
                        if let Some(previous) = &stack
                            && previous.digest() != observed.digest()
                        {
                            provider_errors.push(ProviderErrorEvidence::new(
                                CloudFormationOperation::DescribeStacks,
                                None,
                                "stack_revision_replay",
                            ));
                            terminal_state = Some(CloudFormationEvidenceState::Partial);
                            truncated = true;
                            break;
                        }
                        stack = Some(observed);
                    }
                    if terminal_state.is_some() {
                        break;
                    }
                    let Some(next) = response.next_cursor else {
                        stack_complete = true;
                        break;
                    };
                    cursor_digest = Some(next.token_digest().clone());
                    if !seen_stack_cursors.insert(next.token_digest().clone()) {
                        provider_errors.push(ProviderErrorEvidence::new(
                            CloudFormationOperation::DescribeStacks,
                            None,
                            "cursor_replay",
                        ));
                        terminal_state = Some(CloudFormationEvidenceState::Partial);
                        truncated = true;
                        break;
                    }
                    if stacks_pages >= request.max_pages {
                        truncated = true;
                        break;
                    }
                    stack_cursor = Some(next);
                }
                Err(error) => {
                    provider_errors.push(failure_from_transport(
                        CloudFormationOperation::DescribeStacks,
                        &error,
                    ));
                    terminal_state = Some(state_from_transport(&error));
                    break;
                }
            }
        }

        if stack.is_none() && terminal_state.is_none() {
            terminal_state = Some(CloudFormationEvidenceState::NotFound);
        }

        if stack.is_some() && terminal_state.is_none() && !truncated {
            let mut events_cursor = None;
            let mut seen_event_cursors = BTreeSet::new();
            loop {
                if events_pages >= request.max_pages {
                    truncated = true;
                    break;
                }
                let event_request = DescribeStackEventsRequest::new(
                    self.scope(),
                    request.page_size,
                    request.max_pages,
                    events_cursor.clone(),
                )?;
                match retry_transport(request.max_retries, || {
                    self.provider.describe_stack_events(&event_request)
                }) {
                    Ok(response) => {
                        events_pages = events_pages.saturating_add(1);
                        events.extend(response.events);
                        if events.len() > crate::MAX_EVENTS {
                            events.truncate(crate::MAX_EVENTS);
                            provider_errors.push(ProviderErrorEvidence::new(
                                CloudFormationOperation::DescribeStackEvents,
                                None,
                                "event_budget",
                            ));
                            terminal_state = Some(CloudFormationEvidenceState::Partial);
                            truncated = true;
                            break;
                        }
                        let Some(next) = response.next_cursor else {
                            events_complete = true;
                            break;
                        };
                        cursor_digest = Some(next.token_digest().clone());
                        if !seen_event_cursors.insert(next.token_digest().clone()) {
                            provider_errors.push(ProviderErrorEvidence::new(
                                CloudFormationOperation::DescribeStackEvents,
                                None,
                                "cursor_replay",
                            ));
                            terminal_state = Some(CloudFormationEvidenceState::Partial);
                            truncated = true;
                            break;
                        }
                        if events_pages >= request.max_pages {
                            truncated = true;
                            break;
                        }
                        events_cursor = Some(next);
                    }
                    Err(error) => {
                        provider_errors.push(failure_from_transport(
                            CloudFormationOperation::DescribeStackEvents,
                            &error,
                        ));
                        terminal_state = Some(state_from_transport(&error));
                        break;
                    }
                }
            }
            if !events
                .windows(2)
                .all(|pair| pair[0].timestamp >= pair[1].timestamp)
            {
                provider_errors.push(ProviderErrorEvidence::new(
                    CloudFormationOperation::DescribeStackEvents,
                    None,
                    "event_ordering",
                ));
                terminal_state = Some(CloudFormationEvidenceState::Partial);
                truncated = true;
            }
        }

        if stack.is_some() && terminal_state.is_none() && !truncated {
            let detect_request =
                DetectStackDriftRequest::new(self.scope(), request.logical_resource_ids.clone())?;
            let detect_response = match retry_transport(request.max_retries, || {
                self.provider.detect_stack_drift(&detect_request)
            }) {
                Ok(response) => response,
                Err(error) => {
                    provider_errors.push(failure_from_transport(
                        CloudFormationOperation::DetectStackDrift,
                        &error,
                    ));
                    terminal_state = Some(state_from_transport(&error));
                    return Ok(self.finish_evidence(
                        &request,
                        terminal_state.unwrap_or(CloudFormationEvidenceState::ProviderUnknown),
                        stack,
                        events,
                        detection,
                        resource_drifts,
                        stacks_pages,
                        events_pages,
                        resource_pages,
                        polls_observed,
                        false,
                        truncated,
                        provider_errors,
                        cursor_digest,
                    ));
                }
            };
            let detection_id = detect_response.detection_id;
            let status_request =
                DescribeStackDriftDetectionStatusRequest::new(self.scope(), detection_id.clone())?;
            let mut detection_complete = false;
            for poll in 1..=request.max_polls {
                let status_response = match retry_transport(request.max_retries, || {
                    self.provider
                        .describe_stack_drift_detection_status(&status_request)
                }) {
                    Ok(response) => response,
                    Err(error) => {
                        provider_errors.push(failure_from_transport(
                            CloudFormationOperation::DescribeStackDriftDetectionStatus,
                            &error,
                        ));
                        terminal_state = Some(state_from_transport(&error));
                        break;
                    }
                };
                polls_observed = poll;
                if status_response.detection_id != detection_id {
                    provider_errors.push(ProviderErrorEvidence::new(
                        CloudFormationOperation::DescribeStackDriftDetectionStatus,
                        None,
                        "detection_replay",
                    ));
                    terminal_state = Some(CloudFormationEvidenceState::Partial);
                    truncated = true;
                    break;
                }
                let started_at = detection.as_ref().map_or(
                    status_response.timestamp,
                    |value: &DriftDetectionProgress| value.started_at,
                );
                detection = Some(DriftDetectionProgress::new(
                    &detection_id,
                    status_response.status,
                    status_response.stack_drift_status,
                    status_response.drifted_resource_count,
                    status_response.status_reason_digest,
                    started_at,
                    status_response.timestamp,
                    poll,
                )?);
                match status_response.status {
                    DriftDetectionStatus::DetectionComplete => {
                        detection_complete = true;
                        break;
                    }
                    DriftDetectionStatus::DetectionFailed => {
                        terminal_state = Some(CloudFormationEvidenceState::Partial);
                        break;
                    }
                    DriftDetectionStatus::DetectionInProgress if poll == request.max_polls => {
                        terminal_state = Some(CloudFormationEvidenceState::InProgress);
                        truncated = true;
                    }
                    DriftDetectionStatus::DetectionInProgress => {}
                }
            }

            if detection_complete && terminal_state.is_none() {
                let mut resource_cursor = None;
                let mut seen_resource_cursors = BTreeSet::new();
                loop {
                    if resource_pages >= request.max_pages {
                        truncated = true;
                        break;
                    }
                    let resource_request = DescribeStackResourceDriftsRequest::new(
                        self.scope(),
                        request.resource_filter.clone(),
                        request.page_size,
                        request.max_pages,
                        resource_cursor.clone(),
                    )?;
                    match retry_transport(request.max_retries, || {
                        self.provider
                            .describe_stack_resource_drifts(&resource_request)
                    }) {
                        Ok(response) => {
                            resource_pages = resource_pages.saturating_add(1);
                            resource_drifts.extend(response.resources);
                            if resource_drifts.len() > crate::MAX_RESOURCES {
                                resource_drifts.truncate(crate::MAX_RESOURCES);
                                provider_errors.push(ProviderErrorEvidence::new(
                                    CloudFormationOperation::DescribeStackResourceDrifts,
                                    None,
                                    "resource_budget",
                                ));
                                terminal_state = Some(CloudFormationEvidenceState::Partial);
                                truncated = true;
                                break;
                            }
                            let Some(next) = response.next_cursor else {
                                resources_complete = true;
                                break;
                            };
                            cursor_digest = Some(next.token_digest().clone());
                            if !seen_resource_cursors.insert(next.token_digest().clone()) {
                                provider_errors.push(ProviderErrorEvidence::new(
                                    CloudFormationOperation::DescribeStackResourceDrifts,
                                    None,
                                    "cursor_replay",
                                ));
                                terminal_state = Some(CloudFormationEvidenceState::Partial);
                                truncated = true;
                                break;
                            }
                            if resource_pages >= request.max_pages {
                                truncated = true;
                                break;
                            }
                            resource_cursor = Some(next);
                        }
                        Err(error) => {
                            provider_errors.push(failure_from_transport(
                                CloudFormationOperation::DescribeStackResourceDrifts,
                                &error,
                            ));
                            terminal_state = Some(state_from_transport(&error));
                            break;
                        }
                    }
                }
            }
        }

        let complete = stack_complete
            && events_complete
            && resources_complete
            && detection
                .as_ref()
                .is_some_and(|value| value.status == DriftDetectionStatus::DetectionComplete)
            && terminal_state.is_none()
            && !truncated;
        let state = terminal_state.unwrap_or_else(|| {
            if complete {
                CloudFormationEvidenceState::Completed
            } else if detection
                .as_ref()
                .is_some_and(|value| value.status == DriftDetectionStatus::DetectionInProgress)
            {
                CloudFormationEvidenceState::InProgress
            } else {
                CloudFormationEvidenceState::Partial
            }
        });
        Ok(self.finish_evidence(
            &request,
            state,
            stack,
            events,
            detection,
            resource_drifts,
            stacks_pages,
            events_pages,
            resource_pages,
            polls_observed,
            complete,
            truncated,
            provider_errors,
            cursor_digest,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_evidence(
        &self,
        request: &CloudFormationEvidenceRequest,
        state: CloudFormationEvidenceState,
        stack: Option<StackSummary>,
        events: Vec<StackEvent>,
        detection: Option<DriftDetectionProgress>,
        resource_drifts: Vec<ResourceDrift>,
        stacks_pages: u16,
        events_pages: u16,
        resource_pages: u16,
        polls_observed: u16,
        complete: bool,
        truncated: bool,
        provider_errors: Vec<ProviderErrorEvidence>,
        cursor_digest: Option<crate::model::Digest>,
    ) -> CloudFormationDriftEvidence {
        CloudFormationDriftEvidence::new(
            state,
            self.scope().stack_revision(),
            stack,
            events,
            detection,
            resource_drifts,
            stacks_pages,
            events_pages,
            resource_pages,
            polls_observed,
            complete,
            truncated,
            provider_errors,
            self.provider.definition().provider_digest.clone(),
            crate::api_digest(),
            self.registration.permission_digest(),
            self.registration.consent_digest(),
            self.registration.scope_digest.clone(),
            request.digest(),
            cursor_digest,
            self.provider.provenance(),
        )
    }

    pub fn propose(
        &mut self,
        request: CloudFormationEvidenceRequest,
    ) -> Result<AwsCloudFormationDriftProposal> {
        let evidence = self.read(request)?;
        Ok(AwsCloudFormationDriftProposal::new(
            &self.registration,
            evidence,
        ))
    }

    pub fn verify(&self, proposal: &AwsCloudFormationDriftProposal) -> VerificationReport {
        let mut failures = Vec::new();
        if !self.registration.is_active() {
            failures.push(VerificationFailure::RegistrationInactive);
        }
        if proposal.registration_digest != self.registration.registration_digest {
            failures.push(VerificationFailure::RegistrationDigestMismatch);
        }
        if proposal.evidence.evidence.provider_digest != self.provider.definition().provider_digest
        {
            failures.push(VerificationFailure::ProviderDigestMismatch);
        }
        if proposal.evidence.evidence.permission_digest != self.registration.permission_digest() {
            failures.push(VerificationFailure::PermissionDigestMismatch);
        }
        if proposal.evidence.evidence.consent_digest != self.registration.consent_digest() {
            failures.push(VerificationFailure::ConsentDigestMismatch);
        }
        if proposal.scope_digest != self.registration.scope_digest {
            failures.push(VerificationFailure::ScopeDigestMismatch);
        }
        if proposal.validate_integrity().is_err() {
            failures.push(VerificationFailure::TamperedEvidence);
        }
        match proposal.state {
            CloudFormationEvidenceState::Partial => {
                failures.push(VerificationFailure::PartialEvidence);
            }
            CloudFormationEvidenceState::InProgress => {
                failures.push(VerificationFailure::InProgressEvidence);
            }
            CloudFormationEvidenceState::AccessLoss => {
                failures.push(VerificationFailure::AccessLoss);
            }
            CloudFormationEvidenceState::Throttled => failures.push(VerificationFailure::Throttled),
            CloudFormationEvidenceState::ProviderUnknown => {
                failures.push(VerificationFailure::ProviderUnknown);
            }
            CloudFormationEvidenceState::NotFound => failures.push(VerificationFailure::NotFound),
            CloudFormationEvidenceState::Completed => {}
            CloudFormationEvidenceState::RegistrationRevoked => {
                failures.push(VerificationFailure::RegistrationInactive);
            }
        }
        VerificationReport::new(
            failures.is_empty(),
            failures.is_empty() && proposal.state.is_review_complete(),
            failures,
        )
    }

    pub fn verify_proposal(&self, proposal: &AwsCloudFormationDriftProposal) -> Result<()> {
        if !self.registration.is_active() {
            return Err(AwsCloudFormationDriftError::RegistrationInactive);
        }
        self.registration.validate()?;
        proposal.validate_integrity()?;
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.scope_digest != self.registration.scope_digest
            || proposal.evidence.evidence.provider_digest
                != self.provider.definition().provider_digest
            || proposal.evidence.evidence.permission_digest != self.registration.permission_digest()
            || proposal.evidence.evidence.consent_digest != self.registration.consent_digest()
            || proposal.evidence.evidence.scope_digest != self.registration.scope_digest
            || proposal.evidence.evidence.contract_digest.as_str() != CONTRACT_DIGEST
        {
            return Err(AwsCloudFormationDriftError::ScopeMismatch);
        }
        Ok(())
    }

    fn ensure_active_and_consented(&self, request: &CloudFormationEvidenceRequest) -> Result<()> {
        if !self.registration.is_active() {
            return Err(AwsCloudFormationDriftError::RegistrationInactive);
        }
        if self.registration.consent().is_revoked() {
            return Err(AwsCloudFormationDriftError::ConsentRevoked);
        }
        if !self
            .registration
            .consent()
            .is_active_at(request.observed_at)
        {
            return Err(AwsCloudFormationDriftError::ConsentExpired);
        }
        Ok(())
    }
}

fn retry_transport<T, F>(
    max_retries: u8,
    mut operation: F,
) -> std::result::Result<T, AwsCloudFormationTransportError>
where
    F: FnMut() -> std::result::Result<T, AwsCloudFormationTransportError>,
{
    let mut retries = 0_u8;
    loop {
        match operation() {
            Ok(value) => return Ok(value),
            Err(error) if error.is_retryable() && retries < max_retries => {
                retries = retries.saturating_add(1);
            }
            Err(error) => return Err(error),
        }
    }
}

fn failure_from_transport(
    operation: CloudFormationOperation,
    error: &AwsCloudFormationTransportError,
) -> ProviderErrorEvidence {
    let category = match error {
        AwsCloudFormationTransportError::BlockedEnv => "blocked_env",
        AwsCloudFormationTransportError::BadRequest => "bad_request",
        AwsCloudFormationTransportError::Unauthorized => "unauthorized",
        AwsCloudFormationTransportError::Forbidden => "forbidden",
        AwsCloudFormationTransportError::NotFound => "not_found",
        AwsCloudFormationTransportError::Conflict => "conflict",
        AwsCloudFormationTransportError::RateLimited { .. } => "throttled",
        AwsCloudFormationTransportError::ServerError { .. } => "server_error",
        AwsCloudFormationTransportError::Timeout => "timeout",
        AwsCloudFormationTransportError::AccessLost => "access_loss",
        AwsCloudFormationTransportError::Partial => "partial",
        AwsCloudFormationTransportError::InvalidResponse => "invalid_response",
    };
    ProviderErrorEvidence::new(operation, error.status_code(), category)
}

fn state_from_transport(error: &AwsCloudFormationTransportError) -> CloudFormationEvidenceState {
    match error {
        AwsCloudFormationTransportError::Unauthorized
        | AwsCloudFormationTransportError::Forbidden
        | AwsCloudFormationTransportError::AccessLost => CloudFormationEvidenceState::AccessLoss,
        AwsCloudFormationTransportError::NotFound => CloudFormationEvidenceState::NotFound,
        AwsCloudFormationTransportError::RateLimited { .. } => {
            CloudFormationEvidenceState::Throttled
        }
        _ => CloudFormationEvidenceState::ProviderUnknown,
    }
}

pub type AwsCloudFormationDriftResultService<T> = AwsCloudFormationDriftService<T>;
pub type AwsCloudFormationService<T> = AwsCloudFormationDriftService<T>;
pub type AwsCloudFormationProposal = AwsCloudFormationDriftProposal;
pub type AwsCloudFormationServiceError = AwsCloudFormationDriftError;
pub type AwsCloudFormationRecordReceipt = RecordedAwsCloudFormationDriftResult;
pub type AwsCloudFormationRegistrationReceipt = AwsCloudFormationDriftRegistration;
pub type CloudFormationDriftRegistration = AwsCloudFormationDriftRegistration;
pub type CloudFormationDriftProposal = AwsCloudFormationDriftProposal;
pub type CloudFormationVerificationReport = VerificationReport;

// Keep these typed imports visible to rustdoc consumers without granting a
// second authority; all values remain below the kernel and read-only.
#[allow(dead_code)]
fn _typed_contract_markers(
    _digests: EvidenceDigests,
    _cursor: Option<OpaqueCursor>,
    _resources: Vec<ResourceDrift>,
    _progress: Option<DriftDetectionProgress>,
    _summary: Option<StackSummary>,
    _events: Vec<StackEvent>,
    _filter: ResourceDriftFilter,
    _mission: MissionProjection,
    _project: ProjectProjection,
    _work_product: WorkProductProjection,
) {
}

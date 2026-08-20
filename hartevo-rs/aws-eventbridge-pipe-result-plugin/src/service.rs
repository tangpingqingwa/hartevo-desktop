//! Bounded EventBridge Pipes read, proposal, recording, and verification
//! service.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use chrono::{DateTime, Utc};
use serde::{Serialize, ser::SerializeStruct};

use crate::consumer::MissionAwsEventBridgePipeConsumer;
use crate::error::{
    AwsEventBridgePipeError, AwsEventBridgePipeTransportError, ErrorClassification, Result,
};
use crate::model::{
    AwsEventBridgePipeScope, CurrentPipeState, DesiredPipeState, Digest, EvidenceDigests,
    PipeEvidenceState, PipeListFilter, Revision, SecretReference, TransportProvenance,
};
use crate::provider::{
    AwsEventBridgePipeProvider, AwsEventBridgePipeProviderDefinition, DescribePipeRequest,
    DescribePipeResponse, ListPipesRequest, ListPipesResponse,
};
use crate::{
    CONTRACT_VERSION, MAX_IDENTIFIER_BYTES, MAX_PAGE_SIZE, MAX_PAGES, PLUGIN_VERSION, PROVIDER_ID,
    SERVICE_ID, contract_digest,
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
    pub(crate) fn new(
        previous_status: RegistrationStatus,
        new_status: RegistrationStatus,
        registration_revision: Revision,
    ) -> Self {
        let transition_digest = Digest::from_parts(
            "aws-eventbridge-pipe-registration-transition/v1",
            &[
                ("previous", format!("{previous_status:?}")),
                ("new", format!("{new_status:?}")),
                ("revision", registration_revision.get().to_string()),
            ],
        );
        Self {
            previous_status,
            new_status,
            registration_revision,
            transition_digest,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AwsEventBridgePipeRegistration {
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_revision: u64,
    provider_release: String,
    provider_digest: Digest,
    api_digest: Digest,
    permission_digest: Digest,
    scope_digest: Digest,
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
    permission_digest: &'a Digest,
    scope_digest: &'a Digest,
    evidence_digest: &'a Digest,
    secret_reference_digest: &'a Digest,
    registration_revision: Revision,
    status: RegistrationStatus,
}

impl AwsEventBridgePipeRegistration {
    fn new(
        scope: &AwsEventBridgePipeScope,
        secret_reference: &SecretReference,
        permission_digest: &Digest,
        provider: &AwsEventBridgePipeProviderDefinition,
    ) -> Result<Self> {
        let evidence_digest = Digest::from_parts(
            "aws-eventbridge-pipe-evidence-policy/v1",
            &[
                ("contract", CONTRACT_VERSION.to_owned()),
                ("max_pages", MAX_PAGES.to_string()),
                ("max_page_size", MAX_PAGE_SIZE.to_string()),
                ("max_response_bytes", crate::MAX_RESPONSE_BYTES.to_string()),
                ("payloads", "excluded".to_owned()),
                ("effects", "excluded".to_owned()),
            ],
        );
        let api_digest = provider.capability_digest.clone();
        let mut registration = Self {
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: provider.provider_id.clone(),
            provider_revision: provider.provider_revision,
            provider_release: provider.release.clone(),
            provider_digest: provider.provider_digest.clone(),
            api_digest,
            permission_digest: permission_digest.clone(),
            scope_digest: scope.digest(),
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

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
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
            permission_digest: &self.permission_digest,
            scope_digest: &self.scope_digest,
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
            || self.permission_digest.validate().is_err()
            || self.scope_digest.validate().is_err()
            || self.evidence_digest.validate().is_err()
            || self.secret_reference_digest.validate().is_err()
            || self.registration_digest != self.recomputed_digest()
        {
            Err(AwsEventBridgePipeError::InvalidRegistration)
        } else {
            Ok(())
        }
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        let previous = self.status;
        if previous == RegistrationStatus::Reversed {
            return Err(AwsEventBridgePipeError::RegistrationReversed);
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
            return Err(AwsEventBridgePipeError::RegistrationReversed);
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
            return Err(AwsEventBridgePipeError::RegistrationReversed);
        }
        if previous == RegistrationStatus::Active {
            return Err(AwsEventBridgePipeError::InvalidRegistration);
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
            .ok_or(AwsEventBridgePipeError::InvalidRegistration)?;
        self.registration_revision = Revision::new(next)?;
        Ok(())
    }
}

impl fmt::Debug for AwsEventBridgePipeRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsEventBridgePipeRegistration")
            .field("provider_id", &self.provider_id)
            .field("provider_revision", &self.provider_revision)
            .field("scope_digest", &self.scope_digest)
            .field("permission_digest", &self.permission_digest)
            .field("secret_reference_digest", &self.secret_reference_digest)
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("registration_digest", &self.registration_digest)
            .finish()
    }
}

impl Serialize for AwsEventBridgePipeRegistration {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("AwsEventBridgePipeRegistration", 15)?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("providerRelease", &self.provider_release)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("apiDigest", &self.api_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
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
pub struct AwsEventBridgePipeCapabilities {
    pub service_id: &'static str,
    pub provider_id: &'static str,
    pub operations: [&'static str; 11],
    pub allowlisted_api_operations: [&'static str; 2],
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub live_execution: bool,
    pub connected: bool,
    pub native: bool,
    pub external_writes: bool,
    pub raw_event_payloads: bool,
    pub delivery_verification: bool,
    pub outcome_authority: bool,
}

impl AwsEventBridgePipeCapabilities {
    pub const fn layer_one() -> Self {
        Self {
            service_id: SERVICE_ID,
            provider_id: PROVIDER_ID,
            operations: [
                "describe_capabilities",
                "describe_scope",
                "register",
                "read_list_pipes",
                "read_describe_pipe",
                "propose",
                "record",
                "verify",
                "revoke_registration",
                "reverse_registration",
                "restore_registration",
            ],
            allowlisted_api_operations: ["ListPipes", "DescribePipe"],
            read_only: true,
            proposal_only: true,
            recording_only: true,
            live_execution: false,
            connected: false,
            native: false,
            external_writes: false,
            raw_event_payloads: false,
            delivery_verification: false,
            outcome_authority: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureEvidence {
    pub classification: ErrorClassification,
    pub status_code: Option<u16>,
    pub retry_after_seconds: Option<u64>,
}

impl FailureEvidence {
    pub const fn classified(classification: ErrorClassification) -> Self {
        Self {
            classification,
            status_code: None,
            retry_after_seconds: None,
        }
    }

    pub const fn from_transport(error: &AwsEventBridgePipeTransportError) -> Self {
        Self {
            classification: error.classification(),
            status_code: error.status_code(),
            retry_after_seconds: error.retry_after_seconds(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsEventBridgePipeEvidence {
    pub scope_digest: Digest,
    pub pipe_name_digest: Option<Digest>,
    pub pipe_arn_digest: Option<Digest>,
    pub current_state: Option<CurrentPipeState>,
    pub desired_state: Option<DesiredPipeState>,
    pub source_arn_digest: Option<Digest>,
    pub target_arn_digest: Option<Digest>,
    pub creation_time: Option<DateTime<Utc>>,
    pub last_modified_time: Option<DateTime<Utc>>,
    pub enrichment_present: bool,
    pub filter_present: bool,
    pub state: PipeEvidenceState,
    pub error_classification: ErrorClassification,
    pub list_pages: u16,
    pub list_complete: bool,
    pub truncated: bool,
    pub failure: Option<FailureEvidence>,
    pub provenance: TransportProvenance,
    pub evidence: EvidenceDigests,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub raw_event_payload_retained: bool,
    pub verified_delivery: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceBody {
    scope_digest: Digest,
    pipe_name_digest: Option<Digest>,
    pipe_arn_digest: Option<Digest>,
    current_state: Option<CurrentPipeState>,
    desired_state: Option<DesiredPipeState>,
    source_arn_digest: Option<Digest>,
    target_arn_digest: Option<Digest>,
    creation_time: Option<DateTime<Utc>>,
    last_modified_time: Option<DateTime<Utc>>,
    enrichment_present: bool,
    filter_present: bool,
    state: PipeEvidenceState,
    error_classification: ErrorClassification,
    list_pages: u16,
    list_complete: bool,
    truncated: bool,
    failure: Option<FailureEvidence>,
    provenance: TransportProvenance,
    evidence: EvidenceDigests,
    connected: bool,
    native: bool,
    first_party: bool,
    provider_receipt: bool,
    raw_event_payload_retained: bool,
    verified_delivery: bool,
}

impl AwsEventBridgePipeEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: &AwsEventBridgePipeScope,
        pipe_name_digest: Option<Digest>,
        pipe_arn_digest: Option<Digest>,
        current_state: Option<CurrentPipeState>,
        desired_state: Option<DesiredPipeState>,
        source_arn_digest: Option<Digest>,
        target_arn_digest: Option<Digest>,
        creation_time: Option<DateTime<Utc>>,
        last_modified_time: Option<DateTime<Utc>>,
        enrichment_present: bool,
        filter_present: bool,
        state: PipeEvidenceState,
        error_classification: ErrorClassification,
        list_pages: u16,
        list_complete: bool,
        truncated: bool,
        failure: Option<FailureEvidence>,
        provenance: TransportProvenance,
        provider_digest: Digest,
        permission_digest: Digest,
        secret_reference_digest: Digest,
        list_digest: Digest,
        describe_digest: Option<Digest>,
        cursor_digest: Option<Digest>,
    ) -> Self {
        let evidence = EvidenceDigests::new(
            provider_digest,
            permission_digest,
            scope.digest(),
            secret_reference_digest,
            list_digest,
            describe_digest,
            cursor_digest,
        );
        let mut result = Self {
            scope_digest: scope.digest(),
            pipe_name_digest,
            pipe_arn_digest,
            current_state,
            desired_state,
            source_arn_digest,
            target_arn_digest,
            creation_time,
            last_modified_time,
            enrichment_present,
            filter_present,
            state,
            error_classification,
            list_pages,
            list_complete,
            truncated,
            failure,
            provenance,
            evidence,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            raw_event_payload_retained: false,
            verified_delivery: false,
        };
        result.seal();
        result
    }

    pub fn seal(&mut self) {
        self.evidence.evidence_digest = self.recomputed_digest();
    }

    pub fn recomputed_digest(&self) -> Digest {
        let mut evidence = self.evidence.clone();
        evidence.evidence_digest = Digest::zero();
        crate::model::digest_serialized(&EvidenceBody {
            scope_digest: self.scope_digest.clone(),
            pipe_name_digest: self.pipe_name_digest.clone(),
            pipe_arn_digest: self.pipe_arn_digest.clone(),
            current_state: self.current_state,
            desired_state: self.desired_state,
            source_arn_digest: self.source_arn_digest.clone(),
            target_arn_digest: self.target_arn_digest.clone(),
            creation_time: self.creation_time,
            last_modified_time: self.last_modified_time,
            enrichment_present: self.enrichment_present,
            filter_present: self.filter_present,
            state: self.state,
            error_classification: self.error_classification,
            list_pages: self.list_pages,
            list_complete: self.list_complete,
            truncated: self.truncated,
            failure: self.failure.clone(),
            provenance: self.provenance,
            evidence,
            connected: self.connected,
            native: self.native,
            first_party: self.first_party,
            provider_receipt: self.provider_receipt,
            raw_event_payload_retained: self.raw_event_payload_retained,
            verified_delivery: self.verified_delivery,
        })
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.evidence.validate()?;
        for digest in [
            self.pipe_name_digest.as_ref(),
            self.pipe_arn_digest.as_ref(),
            self.source_arn_digest.as_ref(),
            self.target_arn_digest.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            digest.validate()?;
        }
        if self.scope_digest != self.evidence.scope_digest
            || self.evidence.evidence_digest != self.recomputed_digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.connected()
            || self.provenance.native()
            || self.raw_event_payload_retained
            || self.verified_delivery
        {
            return Err(AwsEventBridgePipeError::TamperedEvidence);
        }
        if let Some(failure) = &self.failure
            && failure.classification == ErrorClassification::None
        {
            return Err(AwsEventBridgePipeError::TamperedEvidence);
        }
        if self.truncated && self.list_complete {
            return Err(AwsEventBridgePipeError::PartialEvidence);
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
pub struct AwsEventBridgePipeProposal {
    pub service_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub state: PipeEvidenceState,
    pub current_state: Option<CurrentPipeState>,
    pub desired_state: Option<DesiredPipeState>,
    pub source_arn_digest: Option<Digest>,
    pub target_arn_digest: Option<Digest>,
    pub creation_time: Option<DateTime<Utc>>,
    pub last_modified_time: Option<DateTime<Utc>>,
    pub list_pages: u16,
    pub list_complete: bool,
    pub truncated: bool,
    pub failure: Option<FailureEvidence>,
    pub provenance: TransportProvenance,
    pub evidence: AwsEventBridgePipeEvidence,
    pub proposal_digest: Digest,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub delivery_verified: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProposalBody {
    service_id: String,
    consumer_id: String,
    registration_digest: Digest,
    scope_digest: Digest,
    state: PipeEvidenceState,
    evidence_digest: Digest,
    review_only: bool,
    connected: bool,
    native: bool,
    first_party: bool,
    provider_receipt: bool,
    outcome_adopted: bool,
    work_product_adopted: bool,
    delivery_verified: bool,
}

impl AwsEventBridgePipeProposal {
    fn new(
        registration: &AwsEventBridgePipeRegistration,
        scope: &AwsEventBridgePipeScope,
        evidence: AwsEventBridgePipeEvidence,
    ) -> Self {
        let mut proposal = Self {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: crate::CONSUMER_ID.to_owned(),
            registration_digest: registration.registration_digest().clone(),
            scope_digest: scope.digest(),
            state: evidence.state,
            current_state: evidence.current_state,
            desired_state: evidence.desired_state,
            source_arn_digest: evidence.source_arn_digest.clone(),
            target_arn_digest: evidence.target_arn_digest.clone(),
            creation_time: evidence.creation_time,
            last_modified_time: evidence.last_modified_time,
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
            delivery_verified: false,
        };
        proposal.proposal_digest = proposal.recomputed_digest();
        proposal
    }

    pub fn recomputed_digest(&self) -> Digest {
        crate::model::digest_serialized(&ProposalBody {
            service_id: self.service_id.clone(),
            consumer_id: self.consumer_id.clone(),
            registration_digest: self.registration_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            state: self.state,
            evidence_digest: self.evidence.evidence.evidence_digest.clone(),
            review_only: self.review_only,
            connected: self.connected,
            native: self.native,
            first_party: self.first_party,
            provider_receipt: self.provider_receipt,
            outcome_adopted: self.outcome_adopted,
            work_product_adopted: self.work_product_adopted,
            delivery_verified: self.delivery_verified,
        })
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.evidence.validate_integrity()?;
        if self.service_id != SERVICE_ID
            || self.consumer_id != crate::CONSUMER_ID
            || self.registration_digest.validate().is_err()
            || self.scope_digest != self.evidence.scope_digest
            || self.state != self.evidence.state
            || self.current_state != self.evidence.current_state
            || self.desired_state != self.evidence.desired_state
            || self.source_arn_digest != self.evidence.source_arn_digest
            || self.target_arn_digest != self.evidence.target_arn_digest
            || self.creation_time != self.evidence.creation_time
            || self.last_modified_time != self.evidence.last_modified_time
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
            || self.delivery_verified
            || self.proposal_digest != self.recomputed_digest()
        {
            return Err(AwsEventBridgePipeError::TamperedEvidence);
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

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailure {
    RegistrationInactive,
    RegistrationDigestMismatch,
    PermissionDigestMismatch,
    ScopeDigestMismatch,
    EvidenceTampered,
    PartialEvidence,
    AccessLoss,
    StateDrift,
    SourceTargetMismatch,
    ProviderUnknown,
    Truncated,
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
pub struct AwsEventBridgePipeRecord {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub state: PipeEvidenceState,
    pub error_classification: ErrorClassification,
    pub provenance: TransportProvenance,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub delivery_verified: bool,
    pub recording_digest: Digest,
}

impl AwsEventBridgePipeRecord {
    pub(crate) fn new(
        idempotency_key_digest: Digest,
        proposal: &AwsEventBridgePipeProposal,
        replayed: bool,
    ) -> Self {
        let mut record = Self {
            idempotency_key_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            state: proposal.state,
            error_classification: proposal.evidence.error_classification,
            provenance: proposal.provenance,
            replayed,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            delivery_verified: false,
            recording_digest: Digest::zero(),
        };
        record.recording_digest = record.recomputed_digest();
        record
    }

    pub(crate) fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-eventbridge-pipe-recording/v1",
            &[
                (
                    "idempotency",
                    self.idempotency_key_digest.as_str().to_owned(),
                ),
                ("proposal", self.proposal_digest.as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
                ("classification", format!("{:?}", self.error_classification)),
                ("provenance", format!("{:?}", self.provenance)),
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
            || self.delivery_verified
            || self.recording_digest != self.recomputed_digest()
        {
            Err(AwsEventBridgePipeError::TamperedEvidence)
        } else {
            Ok(())
        }
    }

    pub(crate) fn set_recording_digest(&mut self) {
        self.recording_digest = self.recomputed_digest();
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AwsEventBridgePipeReadRequest {
    scope_digest: Digest,
    filter: PipeListFilter,
    max_pages: u16,
    cursor: Option<crate::model::Cursor>,
    observed_at: DateTime<Utc>,
    request_digest: Digest,
}

impl AwsEventBridgePipeReadRequest {
    pub fn new(
        scope: &AwsEventBridgePipeScope,
        filter: PipeListFilter,
        max_pages: u16,
        observed_at: DateTime<Utc>,
        cursor: Option<crate::model::Cursor>,
    ) -> Result<Self> {
        if max_pages == 0 || max_pages > MAX_PAGES {
            return Err(AwsEventBridgePipeError::InvalidRequest);
        }
        filter.validate_against(scope)?;
        if let Some(cursor) = &cursor {
            cursor.validate_against(scope, &filter)?;
        }
        let request_digest = Digest::from_parts(
            "aws-eventbridge-pipe-read-request/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("filter", filter.digest().as_str().to_owned()),
                ("max_pages", max_pages.to_string()),
                (
                    "cursor",
                    cursor
                        .as_ref()
                        .map_or_else(String::new, |cursor| cursor.token_digest().to_string()),
                ),
                ("observed_at", observed_at.to_rfc3339()),
            ],
        );
        Ok(Self {
            scope_digest: scope.digest(),
            filter,
            max_pages,
            cursor,
            observed_at,
            request_digest,
        })
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn filter(&self) -> &PipeListFilter {
        &self.filter
    }

    pub const fn max_pages(&self) -> u16 {
        self.max_pages
    }

    pub fn cursor(&self) -> Option<&crate::model::Cursor> {
        self.cursor.as_ref()
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub(crate) fn validate_against(&self, scope: &AwsEventBridgePipeScope) -> Result<()> {
        if self.scope_digest != scope.digest() {
            return Err(AwsEventBridgePipeError::ScopeMismatch);
        }
        self.filter.validate_against(scope)?;
        if let Some(cursor) = &self.cursor {
            cursor.validate_against(scope, &self.filter)?;
        }
        Ok(())
    }
}

impl fmt::Debug for AwsEventBridgePipeReadRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsEventBridgePipeReadRequest")
            .field("scope_digest", &self.scope_digest)
            .field("filter", &self.filter)
            .field("max_pages", &self.max_pages)
            .field("cursor", &self.cursor)
            .field("observed_at", &self.observed_at)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

pub struct AwsEventBridgePipeService<T> {
    scope: AwsEventBridgePipeScope,
    secret_reference: SecretReference,
    permission_snapshot: crate::model::PermissionSnapshot,
    provider: AwsEventBridgePipeProvider<T>,
    registration: AwsEventBridgePipeRegistration,
    records: BTreeMap<Digest, AwsEventBridgePipeRecord>,
}

impl<T: crate::provider::AwsEventBridgePipeTransport> fmt::Debug for AwsEventBridgePipeService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsEventBridgePipeService")
            .field("scope_digest", &self.scope.digest())
            .field("registration", &self.registration)
            .field("provider", &self.provider)
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl<T: crate::provider::AwsEventBridgePipeTransport> AwsEventBridgePipeService<T> {
    pub fn new(
        scope: AwsEventBridgePipeScope,
        secret_reference: SecretReference,
        permission_snapshot: crate::model::PermissionSnapshot,
        provider: AwsEventBridgePipeProvider<T>,
        _registered_at: DateTime<Utc>,
    ) -> Result<Self> {
        crate::AwsEventBridgePipeContract::baseline()
            .map_err(|_| AwsEventBridgePipeError::ContractDrift)?;
        scope.validate()?;
        secret_reference.validate()?;
        permission_snapshot.validate()?;
        if secret_reference.signing_region() != scope.region() {
            return Err(AwsEventBridgePipeError::ScopeMismatch);
        }
        provider.definition().validate()?;
        let registration = AwsEventBridgePipeRegistration::new(
            &scope,
            &secret_reference,
            permission_snapshot.digest(),
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

    pub fn scope(&self) -> &AwsEventBridgePipeScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn permission_snapshot(&self) -> &crate::model::PermissionSnapshot {
        &self.permission_snapshot
    }

    pub fn registration(&self) -> &AwsEventBridgePipeRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut AwsEventBridgePipeRegistration {
        &mut self.registration
    }

    pub fn provider(&self) -> &AwsEventBridgePipeProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsEventBridgePipeProvider<T> {
        &mut self.provider
    }

    pub fn is_active(&self) -> bool {
        self.registration.is_active()
    }

    pub fn describe_capabilities(&self) -> AwsEventBridgePipeCapabilities {
        AwsEventBridgePipeCapabilities::layer_one()
    }

    pub fn default_request(
        &self,
        observed_at: DateTime<Utc>,
    ) -> Result<AwsEventBridgePipeReadRequest> {
        let filter = PipeListFilter::for_scope(&self.scope, MAX_PAGE_SIZE)?;
        self.request(filter, MAX_PAGES, observed_at, None)
    }

    pub fn request(
        &self,
        filter: PipeListFilter,
        max_pages: u16,
        observed_at: DateTime<Utc>,
        cursor: Option<crate::model::Cursor>,
    ) -> Result<AwsEventBridgePipeReadRequest> {
        AwsEventBridgePipeReadRequest::new(&self.scope, filter, max_pages, observed_at, cursor)
    }

    pub fn read_list_pipes(&mut self, request: &ListPipesRequest) -> Result<ListPipesResponse> {
        self.ensure_active()?;
        self.provider
            .list_pipes(request)
            .map_err(AwsEventBridgePipeError::Transport)
    }

    pub fn read_describe_pipe(
        &mut self,
        request: &DescribePipeRequest,
    ) -> Result<DescribePipeResponse> {
        self.ensure_active()?;
        self.provider
            .describe_pipe(request)
            .map_err(AwsEventBridgePipeError::Transport)
    }

    pub fn read(
        &mut self,
        request: AwsEventBridgePipeReadRequest,
    ) -> Result<AwsEventBridgePipeEvidence> {
        self.ensure_active()?;
        request.validate_against(&self.scope)?;

        let mut cursor = request.cursor().cloned();
        let mut page_number = cursor.as_ref().map_or(1, |value| value.page_number());
        let mut seen_cursors = BTreeSet::new();
        let mut page_digests = Vec::new();
        let mut list_pages = 0_u16;
        let mut list_complete = false;
        let mut truncated = false;
        let mut list_failure: Option<FailureEvidence> = None;
        let mut target_summary = None;
        let mut name_match_with_different_arn = false;
        let mut last_cursor_digest = None;

        for _ in 0..request.max_pages() {
            let list_request = ListPipesRequest::new(
                &self.scope,
                request.filter().clone(),
                page_number,
                cursor.clone(),
            )?;
            match self.provider.list_pipes(&list_request) {
                Ok(response) => {
                    list_pages = list_pages.saturating_add(1);
                    page_digests.push(response.digest());
                    for summary in &response.pipes {
                        if summary.matches_scope(&self.scope) {
                            target_summary = Some(summary.clone());
                        } else if summary.matches_name(&self.scope) {
                            name_match_with_different_arn = true;
                        }
                    }
                    if let Some(next_cursor) = response.next_cursor.clone() {
                        last_cursor_digest = Some(next_cursor.token_digest().clone());
                        if !seen_cursors.insert(next_cursor.token_digest().clone()) {
                            list_failure = Some(FailureEvidence::classified(
                                ErrorClassification::PaginationLoop,
                            ));
                            break;
                        }
                        if list_pages >= request.max_pages() {
                            truncated = true;
                            list_failure =
                                Some(FailureEvidence::classified(ErrorClassification::Truncated));
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
                    list_failure = Some(FailureEvidence::from_transport(&error));
                    break;
                }
            }
        }

        let list_digest = Digest::from_parts(
            "aws-eventbridge-pipe-list-evidence/v1",
            &[
                (
                    "pages",
                    page_digests
                        .iter()
                        .map(|digest| digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                ("page_count", list_pages.to_string()),
                ("complete", list_complete.to_string()),
            ],
        );

        let mut pipe_name_digest = target_summary
            .as_ref()
            .map(|summary| summary.pipe_name_digest.clone());
        let mut pipe_arn_digest = target_summary
            .as_ref()
            .map(|summary| summary.pipe_arn_digest.clone());
        let mut current_state = target_summary.as_ref().map(|summary| summary.current_state);
        let mut desired_state = target_summary.as_ref().map(|summary| summary.desired_state);
        let mut creation_time = target_summary.as_ref().map(|summary| summary.creation_time);
        let mut last_modified_time = target_summary
            .as_ref()
            .map(|summary| summary.last_modified_time);
        let mut source_arn_digest = None;
        let mut target_arn_digest = None;
        let mut enrichment_present = false;
        let mut filter_present = false;
        let mut describe_digest = None;
        let mut failure = list_failure;
        let mut error_classification = failure
            .as_ref()
            .map_or(ErrorClassification::None, |value| value.classification);
        let mut state: Option<PipeEvidenceState>;

        if failure.is_none() && !list_complete {
            truncated = true;
            failure = Some(FailureEvidence::classified(ErrorClassification::Truncated));
            error_classification = ErrorClassification::Truncated;
            state = Some(PipeEvidenceState::Partial);
        } else if failure.is_none() && target_summary.is_none() {
            if name_match_with_different_arn {
                failure = Some(FailureEvidence::classified(ErrorClassification::StateDrift));
                error_classification = ErrorClassification::StateDrift;
                state = Some(PipeEvidenceState::Partial);
            } else {
                failure = Some(FailureEvidence::classified(ErrorClassification::NotFound));
                failure.as_mut().expect("inserted failure").status_code = Some(404);
                error_classification = ErrorClassification::NotFound;
                state = Some(PipeEvidenceState::NotFound);
            }
        } else if failure.is_none() {
            let describe_request = DescribePipeRequest::for_scope(&self.scope)?;
            match self.provider.describe_pipe(&describe_request) {
                Ok(response) => {
                    describe_digest = Some(response.digest());
                    let description = response.description;
                    pipe_name_digest = Some(description.pipe_name_digest.clone());
                    pipe_arn_digest = Some(description.pipe_arn_digest.clone());
                    current_state = Some(description.current_state);
                    desired_state = Some(description.desired_state);
                    source_arn_digest = Some(description.source_arn_digest.clone());
                    target_arn_digest = Some(description.target_arn_digest.clone());
                    creation_time = Some(description.creation_time);
                    last_modified_time = Some(description.last_modified_time);
                    enrichment_present = description.enrichment_present;
                    filter_present = description.filter_present;
                    if !description.pipe_matches_scope(&self.scope) {
                        failure =
                            Some(FailureEvidence::classified(ErrorClassification::StateDrift));
                        error_classification = ErrorClassification::StateDrift;
                        state = Some(PipeEvidenceState::Partial);
                    } else if !description.source_target_match_scope(&self.scope) {
                        failure = Some(FailureEvidence::classified(
                            ErrorClassification::SourceTargetMismatch,
                        ));
                        error_classification = ErrorClassification::SourceTargetMismatch;
                        state = Some(PipeEvidenceState::Partial);
                    } else if target_summary.as_ref().is_some_and(|summary| {
                        summary.current_state != description.current_state
                            || summary.desired_state != description.desired_state
                            || summary.creation_time != description.creation_time
                            || summary.last_modified_time != description.last_modified_time
                    }) {
                        failure =
                            Some(FailureEvidence::classified(ErrorClassification::StateDrift));
                        error_classification = ErrorClassification::StateDrift;
                        state = Some(PipeEvidenceState::Partial);
                    } else {
                        state = Some(description.current_state.evidence_state());
                        error_classification = description.error_classification;
                        if description.error_classification.is_failure() {
                            failure = Some(FailureEvidence::classified(
                                description.error_classification,
                            ));
                        }
                    }
                }
                Err(error) => {
                    failure = Some(FailureEvidence::from_transport(&error));
                    error_classification = error.classification();
                    state = Some(state_from_classification(error_classification));
                }
            }
        } else {
            state = Some(state_from_classification(error_classification));
        }

        if let Some(failure) = &failure {
            error_classification = failure.classification;
            if matches!(
                failure.classification,
                ErrorClassification::PaginationLoop
                    | ErrorClassification::Truncated
                    | ErrorClassification::StateDrift
                    | ErrorClassification::SourceTargetMismatch
            ) {
                state = Some(PipeEvidenceState::Partial);
            } else if failure.classification == ErrorClassification::ProviderReported
                && current_state.is_some_and(CurrentPipeState::is_failed)
            {
                state = Some(PipeEvidenceState::Failed);
            } else {
                state = Some(state_from_classification(failure.classification));
            }
        }

        Ok(AwsEventBridgePipeEvidence::new(
            &self.scope,
            pipe_name_digest,
            pipe_arn_digest,
            current_state,
            desired_state,
            source_arn_digest,
            target_arn_digest,
            creation_time,
            last_modified_time,
            enrichment_present,
            filter_present,
            state.unwrap_or(PipeEvidenceState::ProviderUnknown),
            error_classification,
            list_pages,
            list_complete,
            truncated,
            failure,
            self.provider.provenance(),
            self.provider.definition().provider_digest.clone(),
            self.permission_snapshot.digest().clone(),
            self.secret_reference.digest().clone(),
            list_digest,
            describe_digest,
            last_cursor_digest,
        ))
    }

    pub fn read_bounded(
        &mut self,
        request: AwsEventBridgePipeReadRequest,
    ) -> Result<AwsEventBridgePipeEvidence> {
        self.read(request)
    }

    pub fn propose(
        &mut self,
        request: AwsEventBridgePipeReadRequest,
    ) -> Result<AwsEventBridgePipeProposal> {
        self.ensure_active()?;
        let evidence = self.read(request)?;
        Ok(AwsEventBridgePipeProposal::new(
            &self.registration,
            &self.scope,
            evidence,
        ))
    }

    pub fn record(
        &mut self,
        proposal: &AwsEventBridgePipeProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<AwsEventBridgePipeRecord> {
        self.ensure_active()?;
        self.ensure_proposal_bound(proposal)?;
        let key = idempotency_key.as_ref();
        if key.is_empty() || key.len() > MAX_IDENTIFIER_BYTES || key.chars().any(char::is_control) {
            return Err(AwsEventBridgePipeError::InvalidRequest);
        }
        let key_digest = Digest::from_text(key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(AwsEventBridgePipeError::RecordingConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.recording_digest = replay.recomputed_digest();
            return Ok(replay);
        }
        let record = AwsEventBridgePipeRecord::new(key_digest.clone(), proposal, false);
        self.records.insert(key_digest, record.clone());
        Ok(record)
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn verify(&self, proposal: &AwsEventBridgePipeProposal) -> VerificationReport {
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
        match proposal.evidence.error_classification {
            ErrorClassification::AccessLoss
            | ErrorClassification::Unauthorized
            | ErrorClassification::Forbidden => failures.push(VerificationFailure::AccessLoss),
            ErrorClassification::StateDrift => failures.push(VerificationFailure::StateDrift),
            ErrorClassification::SourceTargetMismatch => {
                failures.push(VerificationFailure::SourceTargetMismatch);
            }
            ErrorClassification::ProviderReported
            | ErrorClassification::BlockedEnv
            | ErrorClassification::InvalidResponse
            | ErrorClassification::BadRequest
            | ErrorClassification::NotFound
            | ErrorClassification::Conflict
            | ErrorClassification::ServerError
            | ErrorClassification::Timeout
            | ErrorClassification::RateLimited => {
                failures.push(VerificationFailure::ProviderUnknown);
            }
            ErrorClassification::PaginationLoop | ErrorClassification::Truncated => {
                failures.push(VerificationFailure::PartialEvidence);
            }
            ErrorClassification::RegistrationRevoked => {
                failures.push(VerificationFailure::RegistrationInactive);
            }
            ErrorClassification::None => {}
        }
        failures.sort();
        failures.dedup();
        let valid = failures.is_empty();
        VerificationReport {
            valid,
            review_eligible: valid && proposal.list_complete && !proposal.truncated,
            failures,
            evidence_digest: proposal.evidence.evidence.evidence_digest.clone(),
        }
    }

    pub fn consumer(&self) -> Result<MissionAwsEventBridgePipeConsumer> {
        self.ensure_registration_binding()?;
        MissionAwsEventBridgePipeConsumer::new(self.scope.clone(), self.registration.clone())
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

    fn ensure_active(&self) -> Result<()> {
        self.ensure_registration_binding()?;
        if self.registration.is_active() {
            Ok(())
        } else {
            Err(AwsEventBridgePipeError::RegistrationInactive)
        }
    }

    fn ensure_registration_binding(&self) -> Result<()> {
        self.scope.validate()?;
        self.secret_reference.validate()?;
        self.permission_snapshot.validate()?;
        self.provider.definition().validate()?;
        self.registration.validate()?;
        if self.registration.scope_digest() != &self.scope.digest()
            || self.registration.permission_digest() != self.permission_snapshot.digest()
            || self.registration.secret_reference_digest() != self.secret_reference.digest()
            || self.registration.provider_digest() != &self.provider.definition().provider_digest
        {
            return Err(AwsEventBridgePipeError::ScopeMismatch);
        }
        Ok(())
    }

    fn ensure_proposal_bound(&self, proposal: &AwsEventBridgePipeProposal) -> Result<()> {
        proposal.validate_integrity()?;
        if proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
        {
            Err(AwsEventBridgePipeError::ScopeMismatch)
        } else {
            Ok(())
        }
    }
}

fn state_from_classification(classification: ErrorClassification) -> PipeEvidenceState {
    match classification {
        ErrorClassification::NotFound => PipeEvidenceState::NotFound,
        ErrorClassification::AccessLoss
        | ErrorClassification::Unauthorized
        | ErrorClassification::Forbidden => PipeEvidenceState::AccessLoss,
        ErrorClassification::RateLimited => PipeEvidenceState::Throttled,
        ErrorClassification::PaginationLoop
        | ErrorClassification::Truncated
        | ErrorClassification::StateDrift
        | ErrorClassification::SourceTargetMismatch => PipeEvidenceState::Partial,
        ErrorClassification::RegistrationRevoked => PipeEvidenceState::RegistrationRevoked,
        ErrorClassification::None
        | ErrorClassification::BadRequest
        | ErrorClassification::Conflict
        | ErrorClassification::ServerError
        | ErrorClassification::Timeout
        | ErrorClassification::BlockedEnv
        | ErrorClassification::InvalidResponse
        | ErrorClassification::ProviderReported => PipeEvidenceState::ProviderUnknown,
    }
}

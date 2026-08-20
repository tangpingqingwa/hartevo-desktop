//! Typed read/proposal/record/verify service for bounded Brex observations.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::consumer::MissionBrexSpendConsumer;
use crate::error::BrexSpendTransportError;
use crate::model::{
    BrexSpendObservation, BrexSpendRegistration, BrexSpendScope, ConsentScope, Digest,
    MissionBinding, ModelError, PermissionScope, ProjectBinding, RegistrationRevocation,
    RegistrationStatus, RevisionId, SecretReference, SpendEvidenceState, SpendOperation,
    TransportProvenance, WorkProductBinding, digest_serializable,
};
use crate::provider::{
    BrexSpendProvider, BrexSpendProviderDefinition, BrexSpendReadRequest, BrexSpendResponse,
    BrexSpendTransport, ProviderError, QueryConfig, SpendQuery,
};
use crate::{
    CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_JSON, CONTRACT_SCHEMA, CONTRACT_VERSION, EVIDENCE_LEVEL,
    PLUGIN_ID, PLUGIN_VERSION, PROVIDER_ID, PROVIDER_VERSION, SERVICE_ID, contract_digest,
    plugin_version_digest,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ContractDocumentError {
    #[error("Brex spend-result contract document is not valid JSON")]
    InvalidJson,
    #[error("Brex spend-result contract document identity drifted")]
    IdentityDrift,
    #[error("Brex spend-result contract document escalates Layer-1 authority")]
    AuthorityEscalation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrexSpendServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_id: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub evidence_level: String,
    pub read_only: bool,
    pub live_execution: bool,
    pub external_writes: bool,
    pub kernel_authority: bool,
    pub outcome_adoption: bool,
    pub contract_digest: Digest,
    pub version_digest: Digest,
}

impl Default for BrexSpendServiceDefinition {
    fn default() -> Self {
        Self::new()
    }
}

impl BrexSpendServiceDefinition {
    #[must_use]
    pub fn new() -> Self {
        let version_digest = Digest::from_parts(
            "brex-service-version/v1",
            &[
                ("plugin", PLUGIN_ID.to_owned()),
                ("plugin_version", PLUGIN_VERSION.to_owned()),
                ("schema", CONTRACT_SCHEMA.to_owned()),
                ("contract", CONTRACT_VERSION.to_owned()),
                ("service", SERVICE_ID.to_owned()),
                ("provider", PROVIDER_ID.to_owned()),
                ("provider_version", PROVIDER_VERSION.to_owned()),
                ("consumer", CONSUMER_ID.to_owned()),
            ],
        );
        Self {
            schema_version: CONTRACT_SCHEMA.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            plugin_id: PLUGIN_ID.to_owned(),
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            evidence_level: EVIDENCE_LEVEL.to_owned(),
            read_only: true,
            live_execution: false,
            external_writes: false,
            kernel_authority: false,
            outcome_adoption: false,
            contract_digest: contract_digest(),
            version_digest,
        }
    }

    pub fn validate(&self) -> Result<(), ContractDocumentError> {
        let expected = Self::new();
        if self != &expected {
            return Err(ContractDocumentError::IdentityDrift);
        }
        let document: serde_json::Value =
            serde_json::from_str(CONTRACT_JSON).map_err(|_| ContractDocumentError::InvalidJson)?;
        let native_false = [
            document["provider"]["connectedEvidence"].as_bool(),
            document["provider"]["nativeEvidence"].as_bool(),
            document["provider"]["firstPartyEvidence"].as_bool(),
            document["service"]["externalWrites"].as_bool(),
            document["service"]["kernelAuthority"].as_bool(),
            document["consumer"]["adoptsOutcome"].as_bool(),
            document["consumer"]["adoptsWorkProduct"].as_bool(),
            document["consumer"]["truthAuthority"].as_bool(),
            document["consumer"]["effectiveAuthorization"].as_bool(),
        ]
        .into_iter()
        .all(|value| value == Some(false));
        if !native_false
            || document["contractDigest"] != serde_json::Value::String(CONTRACT_DIGEST.to_owned())
            || document["evidenceLevel"] != EVIDENCE_LEVEL
        {
            return Err(ContractDocumentError::AuthorityEscalation);
        }
        Ok(())
    }
}

pub type ServiceDefinition = BrexSpendServiceDefinition;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum BrexSpendServiceError {
    #[error("Brex spend-result registration is revoked or reversed")]
    RegistrationRevoked,
    #[error("Brex spend-result SecretReference is revoked or expired")]
    SecretRevoked,
    #[error("Brex spend-result consent is expired")]
    ConsentExpired,
    #[error("Brex spend-result scope, permission, or consent digest does not verify")]
    ScopeMismatch,
    #[error("Brex spend-result permission was lost or changed")]
    PermissionLoss,
    #[error("Brex spend-result scope or binding revision is stale")]
    StaleRevision,
    #[error("Brex spend-result query/config/request digest drifted")]
    RequestDrift,
    #[error("Brex spend-result evidence or provider response was tampered")]
    TamperedEvidence,
    #[error("Brex spend-result response pagination is incomplete")]
    IncompleteRecord,
    #[error("Brex spend-result provider read-back does not match the proposal")]
    ReadBackMismatch,
    #[error("Brex spend-result observation is outside the requested operation")]
    ObservationOutOfScope,
    #[error(transparent)]
    Provider(ProviderError),
    #[error(transparent)]
    Model(ModelError),
    #[error(transparent)]
    Contract(ContractDocumentError),
}

impl From<ModelError> for BrexSpendServiceError {
    fn from(value: ModelError) -> Self {
        match value {
            ModelError::ConsentExpired => Self::ConsentExpired,
            ModelError::Revoked => Self::RegistrationRevoked,
            ModelError::InvalidCursor => Self::RequestDrift,
            error => Self::Model(error),
        }
    }
}

impl From<ProviderError> for BrexSpendServiceError {
    fn from(value: ProviderError) -> Self {
        match value {
            ProviderError::ResponseTampered => Self::TamperedEvidence,
            ProviderError::ScopeMismatch => Self::ScopeMismatch,
            other => Self::Provider(other),
        }
    }
}

impl From<ContractDocumentError> for BrexSpendServiceError {
    fn from(value: ContractDocumentError) -> Self {
        Self::Contract(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrexSpendProposal {
    pub operation: SpendOperation,
    pub request: BrexSpendReadRequest,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub version_digest: Digest,
    pub provider_digest: Digest,
    pub contract_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub scope_digest: Digest,
    pub scope_revision: RevisionId,
    pub registration_digest: Digest,
    pub registration_revision: RevisionId,
    pub idempotency_key: Digest,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub proposal_digest: Digest,
}

impl BrexSpendProposal {
    fn new(
        request: BrexSpendReadRequest,
        scope: &BrexSpendScope,
        definition: &BrexSpendServiceDefinition,
        provider: &BrexSpendProviderDefinition,
        registration: &BrexSpendRegistration,
    ) -> Self {
        let mut proposal = Self {
            operation: request.operation,
            request,
            project: scope.project.clone(),
            mission: scope.mission.clone(),
            work_product: scope.work_product.clone(),
            version_digest: definition.version_digest.clone(),
            provider_digest: provider.provider_digest.clone(),
            contract_digest: definition.contract_digest.clone(),
            permission_digest: scope.permissions.permission_digest().clone(),
            consent_digest: scope.consent.digest(),
            scope_digest: scope.scope_digest.clone(),
            scope_revision: scope.scope_revision.clone(),
            registration_digest: registration.registration_digest.clone(),
            registration_revision: registration.registration_revision.clone(),
            idempotency_key: Digest::from_text("pending-proposal-idempotency"),
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            proposal_digest: Digest::from_text("pending-proposal-digest"),
        };
        proposal.idempotency_key = proposal.request.idempotency_key.clone();
        proposal.proposal_digest = proposal.compute_digest();
        proposal
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "brex-proposal/v1",
            &[
                ("operation", self.operation.as_str().to_owned()),
                ("request", self.request.request_digest.as_str().to_owned()),
                ("project", self.project.digest().as_str().to_owned()),
                ("mission", self.mission.digest().as_str().to_owned()),
                (
                    "work_product",
                    self.work_product.digest().as_str().to_owned(),
                ),
                ("version", self.version_digest.as_str().to_owned()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                ("consent", self.consent_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("scope_revision", self.scope_revision.as_str().to_owned()),
                ("registration", self.registration_digest.as_str().to_owned()),
                (
                    "registration_revision",
                    self.registration_revision.as_str().to_owned(),
                ),
                ("idempotency", self.idempotency_key.as_str().to_owned()),
                ("proposal_only", self.proposal_only.to_string()),
                ("connected", self.connected.to_string()),
                ("native", self.native.to_string()),
                ("first_party", self.first_party.to_string()),
            ],
        )
    }

    pub fn verify(&self) -> Result<(), BrexSpendServiceError> {
        self.request
            .verify_integrity()
            .map_err(|_| BrexSpendServiceError::RequestDrift)?;
        if !self.proposal_only
            || self.connected
            || self.native
            || self.first_party
            || self.operation != self.request.operation
            || self.idempotency_key != self.request.idempotency_key
            || self.proposal_digest != self.compute_digest()
        {
            return Err(BrexSpendServiceError::RequestDrift);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FailureEvidence {
    pub category: String,
    pub status_code: Option<u16>,
    pub retry_after_seconds: Option<u32>,
    pub diagnostic_digest: Option<Digest>,
}

impl FailureEvidence {
    fn from_transport(error: &BrexSpendTransportError) -> Self {
        Self {
            category: error.category().to_owned(),
            status_code: error.status_code(),
            retry_after_seconds: error.retry_after_seconds(),
            diagnostic_digest: Some(Digest::from_text(error.to_string())),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BackoffHint {
    pub retry_after_seconds: Option<u32>,
    pub max_backoff_seconds: u32,
    pub attempts_bounded: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PaginationEvidence {
    pub pages_observed: usize,
    pub items_observed: usize,
    pub response_bytes: usize,
    pub complete: bool,
    pub cursor_digests: Vec<Digest>,
    pub bounded: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionSummary {
    pub identifiers_digest_only: bool,
    pub card_numbers_redacted: bool,
    pub user_pii_redacted: bool,
    pub merchant_text_redacted: bool,
    pub secret_material_redacted: bool,
    pub provider_diagnostics_redacted: bool,
    pub raw_cursors_redacted: bool,
}

impl RedactionSummary {
    #[must_use]
    pub fn layer_one() -> Self {
        Self {
            identifiers_digest_only: true,
            card_numbers_redacted: true,
            user_pii_redacted: true,
            merchant_text_redacted: true,
            secret_material_redacted: true,
            provider_diagnostics_redacted: true,
            raw_cursors_redacted: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityBoundary {
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub durable_receipt: bool,
    pub effective_authorization: bool,
    pub financial_advice: bool,
    pub external_writes: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactedReceipt {
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub proposal_digest: Digest,
    pub registration_digest: Digest,
    pub idempotency_key: Digest,
    pub status: SpendEvidenceState,
    pub read_back_verified: bool,
    pub durable: bool,
    pub provider_receipt: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrexSpendRecord {
    pub operation: SpendOperation,
    pub request_digest: Digest,
    pub query_digest: Digest,
    pub config_digest: Digest,
    pub scope_digest: Digest,
    pub scope_revision: RevisionId,
    pub consent_digest: Digest,
    pub permission_digest: Digest,
    pub provider_digest: Digest,
    pub idempotency_key: Digest,
    pub pages: Vec<BrexSpendResponse>,
    pub status: SpendEvidenceState,
    pub pagination: PaginationEvidence,
    pub failure: Option<FailureEvidence>,
    pub receipt: RedactedReceipt,
    pub read_back_verified: bool,
    pub record_digest: Digest,
    #[serde(default)]
    pub replayed: bool,
}

impl BrexSpendRecord {
    fn new(
        proposal: &BrexSpendProposal,
        provider_digest: Digest,
        pages: Vec<BrexSpendResponse>,
        status: SpendEvidenceState,
        failure: Option<FailureEvidence>,
        pagination: PaginationEvidence,
        read_back_verified: bool,
    ) -> Self {
        let response_digest = aggregate_response_digest(&pages);
        let receipt = RedactedReceipt {
            request_digest: proposal.request.request_digest.clone(),
            response_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            idempotency_key: proposal.idempotency_key.clone(),
            status,
            read_back_verified,
            durable: false,
            provider_receipt: false,
            connected: false,
            native: false,
            first_party: false,
        };
        let mut record = Self {
            operation: proposal.operation,
            request_digest: proposal.request.request_digest.clone(),
            query_digest: proposal.request.query_digest(),
            config_digest: proposal.request.config_digest(),
            scope_digest: proposal.scope_digest.clone(),
            scope_revision: proposal.scope_revision.clone(),
            consent_digest: proposal.consent_digest.clone(),
            permission_digest: proposal.permission_digest.clone(),
            provider_digest,
            idempotency_key: proposal.idempotency_key.clone(),
            pages,
            status,
            pagination,
            failure,
            receipt,
            read_back_verified,
            record_digest: Digest::from_text("pending-record-digest"),
            replayed: false,
        };
        record.record_digest = record.compute_digest();
        record
    }

    fn compute_digest(&self) -> Digest {
        digest_serializable(&(
            self.operation,
            &self.request_digest,
            &self.query_digest,
            &self.config_digest,
            &self.scope_digest,
            &self.scope_revision,
            &self.consent_digest,
            &self.permission_digest,
            &self.provider_digest,
            &self.idempotency_key,
            self.pages
                .iter()
                .map(|page| page.response_digest.clone())
                .collect::<Vec<_>>(),
            self.status,
            &self.pagination,
            &self.failure,
            self.read_back_verified,
            &self.receipt,
        ))
        .expect("record digest material serializes")
    }

    pub fn validate_integrity(&self) -> Result<(), BrexSpendServiceError> {
        if self.record_digest != self.compute_digest()
            || self.receipt.request_digest != self.request_digest
            || self.receipt.idempotency_key != self.idempotency_key
            || self.receipt.response_digest != self.response_digest()
            || self.receipt.status != self.status
            || self.receipt.connected
            || self.receipt.native
            || self.receipt.first_party
            || self.receipt.durable
            || self.receipt.provider_receipt
        {
            return Err(BrexSpendServiceError::TamperedEvidence);
        }
        for page in &self.pages {
            page.verify_integrity()
                .map_err(|_| BrexSpendServiceError::TamperedEvidence)?;
        }
        Ok(())
    }

    #[must_use]
    pub fn item_count(&self) -> usize {
        self.pages.iter().map(BrexSpendResponse::item_count).sum()
    }

    #[must_use]
    pub fn response_digest(&self) -> Digest {
        aggregate_response_digest(&self.pages)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub query_digest: Digest,
    pub config_digest: Digest,
    pub request_digest: Digest,
    pub result_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub consent_digest: Digest,
    pub permission_digest: Digest,
    pub evidence_digest: Digest,
}

#[allow(clippy::struct_field_names)]
struct EvidenceDigestFields<'a> {
    plugin_version_digest: &'a Digest,
    contract_digest: &'a Digest,
    provider_digest: &'a Digest,
    query_digest: &'a Digest,
    config_digest: &'a Digest,
    request_digest: &'a Digest,
    result_digest: &'a Digest,
    registration_digest: &'a Digest,
    scope_digest: &'a Digest,
    consent_digest: &'a Digest,
    permission_digest: &'a Digest,
}

impl Serialize for EvidenceDigestFields<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("EvidenceDigestFields", 11)?;
        state.serialize_field("pluginVersionDigest", self.plugin_version_digest)?;
        state.serialize_field("contractDigest", self.contract_digest)?;
        state.serialize_field("providerDigest", self.provider_digest)?;
        state.serialize_field("queryDigest", self.query_digest)?;
        state.serialize_field("configDigest", self.config_digest)?;
        state.serialize_field("requestDigest", self.request_digest)?;
        state.serialize_field("resultDigest", self.result_digest)?;
        state.serialize_field("registrationDigest", self.registration_digest)?;
        state.serialize_field("scopeDigest", self.scope_digest)?;
        state.serialize_field("consentDigest", self.consent_digest)?;
        state.serialize_field("permissionDigest", self.permission_digest)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrexSpendEvidence {
    pub operation: SpendOperation,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub spend: Vec<crate::model::SpendObservation>,
    pub limits: Vec<crate::model::LimitObservation>,
    pub policies: Vec<crate::model::PolicyObservation>,
    pub status: SpendEvidenceState,
    pub pagination: PaginationEvidence,
    pub failure: Option<FailureEvidence>,
    pub backoff: Option<BackoffHint>,
    pub redaction: RedactionSummary,
    pub authority: AuthorityBoundary,
    pub provenance: TransportProvenance,
    pub receipt: RedactedReceipt,
    pub proposal_digest: Digest,
    pub record_digest: Digest,
    pub digests: EvidenceDigests,
}

struct EvidenceDigestMaterial<'a> {
    operation: SpendOperation,
    project: &'a ProjectBinding,
    mission: &'a MissionBinding,
    work_product: &'a WorkProductBinding,
    spend: &'a [crate::model::SpendObservation],
    limits: &'a [crate::model::LimitObservation],
    policies: &'a [crate::model::PolicyObservation],
    status: SpendEvidenceState,
    pagination: &'a PaginationEvidence,
    failure: &'a Option<FailureEvidence>,
    backoff: &'a Option<BackoffHint>,
    redaction: &'a RedactionSummary,
    authority: &'a AuthorityBoundary,
    provenance: TransportProvenance,
    receipt: &'a RedactedReceipt,
    proposal_digest: &'a Digest,
    record_digest: &'a Digest,
    digests: EvidenceDigestFields<'a>,
}

impl Serialize for EvidenceDigestMaterial<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("EvidenceDigestMaterial", 18)?;
        state.serialize_field("operation", &self.operation)?;
        state.serialize_field("project", self.project)?;
        state.serialize_field("mission", self.mission)?;
        state.serialize_field("workProduct", self.work_product)?;
        state.serialize_field("spend", self.spend)?;
        state.serialize_field("limits", self.limits)?;
        state.serialize_field("policies", self.policies)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("pagination", self.pagination)?;
        state.serialize_field("failure", self.failure)?;
        state.serialize_field("backoff", self.backoff)?;
        state.serialize_field("redaction", self.redaction)?;
        state.serialize_field("authority", self.authority)?;
        state.serialize_field("provenance", &self.provenance)?;
        state.serialize_field("receipt", self.receipt)?;
        state.serialize_field("proposalDigest", self.proposal_digest)?;
        state.serialize_field("recordDigest", self.record_digest)?;
        state.serialize_field("digests", &self.digests)?;
        state.end()
    }
}

impl BrexSpendEvidence {
    fn compute_digest(&self) -> Digest {
        let material = EvidenceDigestMaterial {
            operation: self.operation,
            project: &self.project,
            mission: &self.mission,
            work_product: &self.work_product,
            spend: &self.spend,
            limits: &self.limits,
            policies: &self.policies,
            status: self.status,
            pagination: &self.pagination,
            failure: &self.failure,
            backoff: &self.backoff,
            redaction: &self.redaction,
            authority: &self.authority,
            provenance: self.provenance,
            receipt: &self.receipt,
            proposal_digest: &self.proposal_digest,
            record_digest: &self.record_digest,
            digests: EvidenceDigestFields {
                plugin_version_digest: &self.digests.plugin_version_digest,
                contract_digest: &self.digests.contract_digest,
                provider_digest: &self.digests.provider_digest,
                query_digest: &self.digests.query_digest,
                config_digest: &self.digests.config_digest,
                request_digest: &self.digests.request_digest,
                result_digest: &self.digests.result_digest,
                registration_digest: &self.digests.registration_digest,
                scope_digest: &self.digests.scope_digest,
                consent_digest: &self.digests.consent_digest,
                permission_digest: &self.digests.permission_digest,
            },
        };
        digest_serializable(&material).expect("evidence digest material serializes")
    }

    pub fn verify(&self) -> Result<(), BrexSpendServiceError> {
        if self.digests.evidence_digest != self.compute_digest()
            || self.authority.connected
            || self.authority.native
            || self.authority.first_party
            || self.authority.durable_receipt
            || self.authority.effective_authorization
            || self.authority.financial_advice
            || self.authority.external_writes
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
            || self.receipt.proposal_digest != self.proposal_digest
            || self.receipt.status != self.status
            || self.receipt.connected
            || self.receipt.native
            || self.receipt.first_party
            || self.receipt.durable
            || self.receipt.provider_receipt
            || !self.redaction.identifiers_digest_only
            || !self.redaction.card_numbers_redacted
            || !self.redaction.user_pii_redacted
            || !self.redaction.merchant_text_redacted
            || !self.redaction.secret_material_redacted
            || !self.redaction.provider_diagnostics_redacted
            || !self.redaction.raw_cursors_redacted
        {
            return Err(BrexSpendServiceError::TamperedEvidence);
        }
        for observation in &self.spend {
            observation
                .validate()
                .map_err(BrexSpendServiceError::Model)?;
        }
        for observation in &self.limits {
            observation
                .validate()
                .map_err(BrexSpendServiceError::Model)?;
        }
        for observation in &self.policies {
            observation
                .validate()
                .map_err(BrexSpendServiceError::Model)?;
        }
        Ok(())
    }

    #[must_use]
    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_review_only(&self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrexSpendReadResult {
    pub proposal: BrexSpendProposal,
    pub record: BrexSpendRecord,
    pub evidence: BrexSpendEvidence,
}

pub struct BrexSpendResultService<T = crate::provider::BlockedEnvTransport> {
    scope: BrexSpendScope,
    secret_reference: SecretReference,
    provider: BrexSpendProvider<T>,
    definition: BrexSpendServiceDefinition,
    registration: BrexSpendRegistration,
    now: DateTime<Utc>,
    records: std::collections::BTreeMap<Digest, BrexSpendRecord>,
}

impl<T: BrexSpendTransport> fmt::Debug for BrexSpendResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrexSpendResultService")
            .field("scope", &self.scope)
            .field("secret_reference", &self.secret_reference)
            .field("provider", &self.provider.definition())
            .field("registration", &self.registration)
            .field("now", &self.now)
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl<T: BrexSpendTransport> BrexSpendResultService<T> {
    pub fn new(
        scope: BrexSpendScope,
        secret_reference: SecretReference,
        provider: BrexSpendProvider<T>,
        now: DateTime<Utc>,
    ) -> Result<Self, BrexSpendServiceError> {
        scope.verify()?;
        match secret_reference.ensure_active(now) {
            Ok(()) => {}
            Err(ModelError::ConsentExpired) => return Err(BrexSpendServiceError::SecretRevoked),
            Err(ModelError::Revoked) => return Err(BrexSpendServiceError::SecretRevoked),
            Err(error) => return Err(BrexSpendServiceError::Model(error)),
        }
        scope.consent.ensure_active(now)?;
        if secret_reference.scope_digest() != &scope.scope_digest
            || secret_reference.consent_digest() != &scope.consent.digest()
            || secret_reference.revision() != &scope.scope_revision
        {
            return Err(BrexSpendServiceError::ScopeMismatch);
        }
        provider.validate()?;
        let definition = BrexSpendServiceDefinition::new();
        definition.validate()?;
        let registration = BrexSpendRegistration::new(
            provider.provider_digest(),
            scope.permissions.permission_digest().clone(),
            scope.consent.digest(),
            scope.scope_digest.clone(),
            secret_reference.reference_digest(),
            scope.scope_revision.clone(),
        )?;
        Ok(Self {
            scope,
            secret_reference,
            provider,
            definition,
            registration,
            now,
            records: std::collections::BTreeMap::new(),
        })
    }

    pub fn new_now(
        scope: BrexSpendScope,
        secret_reference: SecretReference,
        provider: BrexSpendProvider<T>,
    ) -> Result<Self, BrexSpendServiceError> {
        Self::new(scope, secret_reference, provider, Utc::now())
    }

    #[must_use]
    pub fn service_definition(&self) -> &BrexSpendServiceDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provider(&self) -> &BrexSpendProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut BrexSpendProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn scope(&self) -> &BrexSpendScope {
        &self.scope
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn registration(&self) -> &BrexSpendRegistration {
        &self.registration
    }

    #[must_use]
    pub fn registration_mut(&mut self) -> &mut BrexSpendRegistration {
        &mut self.registration
    }

    #[must_use]
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn set_now(&mut self, now: DateTime<Utc>) {
        self.now = now;
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationRevocation, BrexSpendServiceError> {
        self.registration.revoke().map_err(Into::into)
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation, BrexSpendServiceError> {
        self.revoke_registration()
    }

    pub fn reverse_registration(
        &mut self,
    ) -> Result<RegistrationRevocation, BrexSpendServiceError> {
        self.registration.reverse().map_err(Into::into)
    }

    pub fn restore_registration(
        &mut self,
    ) -> Result<RegistrationRevocation, BrexSpendServiceError> {
        self.registration.restore().map_err(Into::into)
    }

    pub fn revoke_secret_reference(&mut self) -> Result<(), BrexSpendServiceError> {
        self.secret_reference.revoke().map_err(Into::into)
    }

    pub fn request(
        &self,
        operation: SpendOperation,
        config: QueryConfig,
        now: DateTime<Utc>,
    ) -> Result<BrexSpendReadRequest, BrexSpendServiceError> {
        self.ensure_fences(operation, now)?;
        let query = SpendQuery::for_operation(operation, &self.scope, now)?;
        Ok(BrexSpendReadRequest::new(
            &self.scope,
            query,
            config,
            None,
            self.secret_reference.reference_digest(),
        )?)
    }

    pub fn default_request(
        &self,
        now: DateTime<Utc>,
    ) -> Result<BrexSpendReadRequest, BrexSpendServiceError> {
        self.request(SpendOperation::ReadSpend, QueryConfig::default(), now)
    }

    pub fn propose(
        &self,
        request: BrexSpendReadRequest,
    ) -> Result<BrexSpendProposal, BrexSpendServiceError> {
        self.ensure_fences(request.operation, self.now)?;
        request.validate_against(&self.scope)?;
        if request.secret_reference_digest != self.secret_reference.reference_digest()
            || request.consent_digest != self.scope.consent.digest()
            || request.scope_revision != self.scope.scope_revision
            || !self.scope.permissions.permits(request.operation)
        {
            return Err(BrexSpendServiceError::StaleRevision);
        }
        Ok(BrexSpendProposal::new(
            request,
            &self.scope,
            &self.definition,
            self.provider.definition(),
            &self.registration,
        ))
    }

    pub fn propose_spend(
        &self,
        now: DateTime<Utc>,
    ) -> Result<BrexSpendProposal, BrexSpendServiceError> {
        self.propose(self.request(SpendOperation::ReadSpend, QueryConfig::default(), now)?)
    }

    pub fn propose_limits(
        &self,
        now: DateTime<Utc>,
    ) -> Result<BrexSpendProposal, BrexSpendServiceError> {
        self.propose(self.request(SpendOperation::ReadLimits, QueryConfig::default(), now)?)
    }

    pub fn propose_policies(
        &self,
        now: DateTime<Utc>,
    ) -> Result<BrexSpendProposal, BrexSpendServiceError> {
        self.propose(self.request(SpendOperation::ReadPolicies, QueryConfig::default(), now)?)
    }

    pub fn record(
        &mut self,
        proposal: &BrexSpendProposal,
    ) -> Result<BrexSpendRecord, BrexSpendServiceError> {
        self.ensure_proposal_fences(proposal)?;
        if let Some(record) = self.records.get(&proposal.idempotency_key) {
            let mut replay = record.clone();
            replay.replayed = true;
            return Ok(replay);
        }
        let mut request = proposal.request.clone();
        let mut pages = Vec::new();
        let mut cursor_digests = Vec::new();
        let mut response_bytes: usize = 0;
        let mut failure = None;
        let mut complete = false;
        let mut read_back_verified = true;

        let status = loop {
            match self.provider.read(&request) {
                Ok(response) => {
                    if response.page_number != pages.len() + 1 {
                        return Err(BrexSpendServiceError::ReadBackMismatch);
                    }
                    response_bytes = response_bytes.saturating_add(response.response_bytes);
                    if response_bytes > request.config.max_response_bytes
                        || pages.len() >= request.config.max_pages
                        || pages
                            .iter()
                            .map(BrexSpendResponse::item_count)
                            .sum::<usize>()
                            + response.item_count()
                            > request.config.max_items
                    {
                        let status = SpendEvidenceState::Partial;
                        read_back_verified = false;
                        break status;
                    }
                    if let Some(cursor) = &response.next_cursor {
                        cursor_digests.push(cursor.digest());
                    }
                    pages.push(response.clone());
                    if response.next_cursor.is_none() {
                        complete = true;
                        break SpendEvidenceState::Complete;
                    }
                    if pages.len() >= request.config.max_pages
                        || pages
                            .iter()
                            .map(BrexSpendResponse::item_count)
                            .sum::<usize>()
                            >= request.config.max_items
                    {
                        break SpendEvidenceState::Partial;
                    }
                    request = request.next_page(response.next_cursor.expect("checked cursor"))?;
                }
                Err(ProviderError::Transport(error)) => {
                    let status = state_for_transport(&error);
                    failure = Some(FailureEvidence::from_transport(&error));
                    read_back_verified = false;
                    break status;
                }
                Err(ProviderError::ResponseTampered) => {
                    return Err(BrexSpendServiceError::TamperedEvidence);
                }
                Err(other) => return Err(other.into()),
            }
        };

        let pagination = PaginationEvidence {
            pages_observed: pages.len(),
            items_observed: pages.iter().map(BrexSpendResponse::item_count).sum(),
            response_bytes,
            complete,
            cursor_digests,
            bounded: true,
        };
        let record = BrexSpendRecord::new(
            proposal,
            self.provider.provider_digest(),
            pages,
            status,
            failure,
            pagination,
            read_back_verified,
        );
        self.records
            .insert(proposal.idempotency_key.clone(), record.clone());
        Ok(record)
    }

    pub fn verify(
        &self,
        proposal: &BrexSpendProposal,
        record: &BrexSpendRecord,
    ) -> Result<BrexSpendEvidence, BrexSpendServiceError> {
        self.ensure_proposal_fences(proposal)?;
        proposal.verify()?;
        if record.request_digest != proposal.request.request_digest
            || record.idempotency_key != proposal.idempotency_key
            || record.scope_digest != self.scope.scope_digest
            || record.scope_revision != self.scope.scope_revision
            || record.consent_digest != self.scope.consent.digest()
            || record.permission_digest != *self.scope.permissions.permission_digest()
            || record.provider_digest != self.provider.provider_digest()
            || record.receipt.proposal_digest != proposal.proposal_digest
            || record.receipt.registration_digest != self.registration.registration_digest
        {
            return Err(BrexSpendServiceError::ReadBackMismatch);
        }
        record.validate_integrity()?;
        let mut expected_request = proposal.request.clone();
        let mut observed = BTreeSet::new();
        for (index, page) in record.pages.iter().enumerate() {
            page.verify_for_request(&expected_request)
                .map_err(|_| BrexSpendServiceError::TamperedEvidence)?;
            if page.page_number != index + 1
                || page.observations.iter().any(|observation| {
                    observation.operation() != proposal.operation
                        || observation.scope_digest() != &self.scope.scope_digest
                        || !self.observation_in_scope(observation)
                        || !observed.insert(observation.digest().clone())
                })
            {
                return Err(BrexSpendServiceError::ObservationOutOfScope);
            }
            if let Some(cursor) = &page.next_cursor {
                expected_request = expected_request.next_page(cursor.clone())?;
            }
        }
        if record.status == SpendEvidenceState::Complete
            && (!record.pagination.complete
                || record
                    .pages
                    .last()
                    .is_some_and(|page| page.next_cursor.is_some()))
        {
            return Err(BrexSpendServiceError::IncompleteRecord);
        }
        if record.pagination.items_observed > proposal.request.config.max_items
            || record.pagination.pages_observed > proposal.request.config.max_pages
        {
            return Err(BrexSpendServiceError::IncompleteRecord);
        }
        let mut spend = Vec::new();
        let mut limits = Vec::new();
        let mut policies = Vec::new();
        for page in &record.pages {
            for observation in &page.observations {
                match observation {
                    BrexSpendObservation::Spend(value) => spend.push(value.clone()),
                    BrexSpendObservation::Limit(value) => limits.push(value.clone()),
                    BrexSpendObservation::Policy(value) => policies.push(value.clone()),
                }
            }
        }
        if (proposal.operation == SpendOperation::ReadSpend
            && (!limits.is_empty() || !policies.is_empty()))
            || (proposal.operation == SpendOperation::ReadLimits
                && (!spend.is_empty() || !policies.is_empty()))
            || (proposal.operation == SpendOperation::ReadPolicies
                && (!spend.is_empty() || !limits.is_empty()))
        {
            return Err(BrexSpendServiceError::ObservationOutOfScope);
        }
        let response_digest = record.response_digest();
        let result_digest = Digest::from_parts(
            "brex-spend-result/v1",
            &[
                ("operation", proposal.operation.as_str().to_owned()),
                ("query", proposal.request.query_digest().as_str().to_owned()),
                (
                    "config",
                    proposal.request.config_digest().as_str().to_owned(),
                ),
                ("response", response_digest.as_str().to_owned()),
                (
                    "observations",
                    observed
                        .iter()
                        .map(Digest::as_str)
                        .collect::<Vec<_>>()
                        .join(","),
                ),
            ],
        );
        let digests = EvidenceDigests {
            plugin_version_digest: plugin_version_digest(),
            contract_digest: self.definition.contract_digest.clone(),
            provider_digest: self.provider.provider_digest(),
            query_digest: proposal.request.query_digest(),
            config_digest: proposal.request.config_digest(),
            request_digest: proposal.request.request_digest.clone(),
            result_digest,
            registration_digest: self.registration.registration_digest.clone(),
            scope_digest: self.scope.scope_digest.clone(),
            consent_digest: self.scope.consent.digest(),
            permission_digest: self.scope.permissions.permission_digest().clone(),
            evidence_digest: Digest::from_text("pending-evidence-digest"),
        };
        let mut evidence = BrexSpendEvidence {
            operation: proposal.operation,
            project: self.scope.project.clone(),
            mission: self.scope.mission.clone(),
            work_product: self.scope.work_product.clone(),
            spend,
            limits,
            policies,
            status: record.status,
            pagination: record.pagination.clone(),
            failure: record.failure.clone(),
            backoff: record.failure.as_ref().and_then(|failure| {
                failure
                    .retry_after_seconds
                    .map(|retry_after_seconds| BackoffHint {
                        retry_after_seconds: Some(retry_after_seconds),
                        max_backoff_seconds: proposal.request.config.retry.max_backoff_seconds,
                        attempts_bounded: true,
                    })
            }),
            redaction: RedactionSummary::layer_one(),
            authority: AuthorityBoundary::default(),
            provenance: self.provider.provenance(),
            receipt: record.receipt.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            record_digest: record.record_digest.clone(),
            digests,
        };
        evidence.digests.evidence_digest = evidence.compute_digest();
        evidence.verify()?;
        Ok(evidence)
    }

    pub fn verify_proposal(
        &self,
        proposal: &BrexSpendProposal,
    ) -> Result<(), BrexSpendServiceError> {
        self.ensure_proposal_fences(proposal)?;
        proposal.verify()
    }

    pub fn verify_read_back(
        &self,
        proposal: &BrexSpendProposal,
        record: &BrexSpendRecord,
    ) -> Result<BrexSpendEvidence, BrexSpendServiceError> {
        self.verify(proposal, record)
    }

    pub fn read(
        &mut self,
        request: BrexSpendReadRequest,
    ) -> Result<BrexSpendReadResult, BrexSpendServiceError> {
        let proposal = self.propose(request)?;
        let record = self.record(&proposal)?;
        let evidence = self.verify(&proposal, &record)?;
        Ok(BrexSpendReadResult {
            proposal,
            record,
            evidence,
        })
    }

    pub fn read_spend(
        &mut self,
        now: DateTime<Utc>,
    ) -> Result<BrexSpendReadResult, BrexSpendServiceError> {
        self.read(self.request(SpendOperation::ReadSpend, QueryConfig::default(), now)?)
    }

    pub fn read_limits(
        &mut self,
        now: DateTime<Utc>,
    ) -> Result<BrexSpendReadResult, BrexSpendServiceError> {
        self.read(self.request(SpendOperation::ReadLimits, QueryConfig::default(), now)?)
    }

    pub fn read_policies(
        &mut self,
        now: DateTime<Utc>,
    ) -> Result<BrexSpendReadResult, BrexSpendServiceError> {
        self.read(self.request(SpendOperation::ReadPolicies, QueryConfig::default(), now)?)
    }

    pub fn consumer(&self) -> Result<MissionBrexSpendConsumer, BrexSpendServiceError> {
        Ok(MissionBrexSpendConsumer::new(
            self.scope.clone(),
            self.registration.registration_digest.clone(),
        ))
    }

    fn ensure_fences(
        &self,
        operation: SpendOperation,
        now: DateTime<Utc>,
    ) -> Result<(), BrexSpendServiceError> {
        self.scope.verify()?;
        self.registration
            .validate()
            .map_err(|_| BrexSpendServiceError::TamperedEvidence)?;
        self.registration
            .ensure_active()
            .map_err(|_| BrexSpendServiceError::RegistrationRevoked)?;
        match self.secret_reference.ensure_active(now) {
            Ok(()) => {}
            Err(ModelError::ConsentExpired) => return Err(BrexSpendServiceError::SecretRevoked),
            Err(ModelError::Revoked) => return Err(BrexSpendServiceError::SecretRevoked),
            Err(error) => return Err(BrexSpendServiceError::Model(error)),
        }
        self.scope.consent.ensure_active(now)?;
        if self.secret_reference.scope_digest() != &self.scope.scope_digest
            || self.secret_reference.consent_digest() != &self.scope.consent.digest()
            || self.secret_reference.revision() != &self.scope.scope_revision
        {
            return Err(BrexSpendServiceError::ScopeMismatch);
        }
        if self.registration.scope_digest != self.scope.scope_digest
            || self.registration.permission_digest != *self.scope.permissions.permission_digest()
            || self.registration.consent_digest != self.scope.consent.digest()
            || self.registration.provider_digest != self.provider.provider_digest()
            || self.registration.contract_digest != self.definition.contract_digest
            || self.registration.secret_reference_digest != self.secret_reference.reference_digest()
        {
            return Err(BrexSpendServiceError::StaleRevision);
        }
        if !self.scope.permissions.permits(operation) {
            return Err(BrexSpendServiceError::PermissionLoss);
        }
        Ok(())
    }

    fn ensure_proposal_fences(
        &self,
        proposal: &BrexSpendProposal,
    ) -> Result<(), BrexSpendServiceError> {
        self.ensure_fences(proposal.operation, self.now)?;
        proposal.verify()?;
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.registration_revision != self.registration.registration_revision
            || proposal.provider_digest != self.provider.provider_digest()
            || proposal.contract_digest != self.definition.contract_digest
            || proposal.scope_digest != self.scope.scope_digest
            || proposal.scope_revision != self.scope.scope_revision
            || proposal.permission_digest != *self.scope.permissions.permission_digest()
            || proposal.consent_digest != self.scope.consent.digest()
        {
            return Err(BrexSpendServiceError::StaleRevision);
        }
        Ok(())
    }

    fn observation_in_scope(&self, observation: &BrexSpendObservation) -> bool {
        match observation {
            BrexSpendObservation::Spend(value) => {
                value
                    .user_digest
                    .as_ref()
                    .is_none_or(|digest| self.scope.users.iter().any(|id| id.digest() == *digest))
                    && value.card_digest.as_ref().is_none_or(|digest| {
                        self.scope.cards.iter().any(|id| id.digest() == *digest)
                    })
                    && value.transaction_digest.as_ref().is_none_or(|digest| {
                        self.scope
                            .transactions
                            .iter()
                            .any(|id| id.digest() == *digest)
                    })
            }
            BrexSpendObservation::Limit(value) => {
                self.scope.limits.is_empty()
                    || self
                        .scope
                        .limits
                        .iter()
                        .any(|id| id.digest() == value.limit_digest)
            }
            BrexSpendObservation::Policy(value) => {
                self.scope.policies.is_empty()
                    || self
                        .scope
                        .policies
                        .iter()
                        .any(|id| id.digest() == value.policy_digest)
            }
        }
    }
}

fn state_for_transport(error: &BrexSpendTransportError) -> SpendEvidenceState {
    match error {
        BrexSpendTransportError::Denied { .. }
        | BrexSpendTransportError::Unauthorized { .. }
        | BrexSpendTransportError::Forbidden { .. }
        | BrexSpendTransportError::NotFound { .. }
        | BrexSpendTransportError::BadRequest { .. } => SpendEvidenceState::Denied,
        BrexSpendTransportError::Expired => SpendEvidenceState::Expired,
        BrexSpendTransportError::Partial => SpendEvidenceState::Partial,
        BrexSpendTransportError::RateLimited { .. } => SpendEvidenceState::RateLimited,
        BrexSpendTransportError::Tampered | BrexSpendTransportError::Malformed => {
            SpendEvidenceState::Tampered
        }
        BrexSpendTransportError::BlockedEnv
        | BrexSpendTransportError::ProviderUnknown { .. }
        | BrexSpendTransportError::Timeout
        | BrexSpendTransportError::ResponseTooLarge { .. }
        | BrexSpendTransportError::Duplicate => SpendEvidenceState::ProviderUnknown,
    }
}

fn aggregate_response_digest(pages: &[BrexSpendResponse]) -> Digest {
    Digest::from_parts(
        "brex-response-set/v1",
        &pages
            .iter()
            .enumerate()
            .map(|(index, page)| ("page", format!("{index}:{}", page.response_digest.as_str())))
            .collect::<Vec<_>>(),
    )
}

pub type BrexSpendResultServiceDefinition = BrexSpendServiceDefinition;
pub type BrexSpendService = BrexSpendResultService;
pub type BrexSpendResultServiceError = BrexSpendServiceError;
pub type BrexSpendResult = BrexSpendReadResult;
pub type BrexSpendEvidenceProposal = BrexSpendProposal;
pub type RegistrationTransitionEvidence = RegistrationRevocation;
pub type RegistrationState = RegistrationStatus;
pub type Consent = ConsentScope;
pub type PermissionSnapshotView = PermissionScope;
pub type Mission = MissionBinding;
pub type Project = ProjectBinding;
pub type WorkProduct = WorkProductBinding;

//! Typed bounded read, proposal, record, and verify service.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AWS_DETECTIVE_API_VERSION, AWS_DETECTIVE_CONSUMER_ID, AWS_DETECTIVE_CONTRACT_VERSION,
    AWS_DETECTIVE_EVIDENCE_LEVEL, AWS_DETECTIVE_PLUGIN_VERSION, AWS_DETECTIVE_PROVIDER_ID,
    AWS_DETECTIVE_PROVIDER_REVISION, AWS_DETECTIVE_PROVIDER_VERSION, AWS_DETECTIVE_SCHEMA_VERSION,
    AWS_DETECTIVE_SERVICE_ID, AwsDetectiveContract, AwsDetectiveContractError,
    AwsDetectiveProvider, AwsDetectiveProviderDefinition, AwsDetectiveReadRequest,
    AwsDetectiveScope, AwsDetectiveTransport, BehaviorGraphId, DetectiveOperation, Digest,
    GetInvestigationRequest, GetInvestigationResponse, ListIndicatorsRequest,
    ListInvestigationsRequest, ListMembersRequest, ModelError, OpaqueCursor, PermissionFence,
    ProviderError, ProviderProvenance, SecretReference, digest_serializable,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsDetectiveServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub api_version: String,
    pub evidence_level: String,
    pub read_only: bool,
    pub proposal_only: bool,
    pub live_execution: bool,
    pub contract_digest: Digest,
    pub version_digest: Digest,
}

impl Default for AwsDetectiveServiceDefinition {
    fn default() -> Self {
        Self::new()
    }
}

impl AwsDetectiveServiceDefinition {
    pub fn new() -> Self {
        let contract_digest = crate::contract_digest();
        let version_digest = Digest::from_parts(
            "hartevo-aws-detective-service-version/v1",
            &[
                AWS_DETECTIVE_SCHEMA_VERSION.to_owned(),
                AWS_DETECTIVE_CONTRACT_VERSION.to_owned(),
                AWS_DETECTIVE_PLUGIN_VERSION.to_owned(),
                AWS_DETECTIVE_PROVIDER_VERSION.to_owned(),
                AWS_DETECTIVE_PROVIDER_REVISION.to_owned(),
                AWS_DETECTIVE_API_VERSION.to_owned(),
            ],
        );
        Self {
            schema_version: AWS_DETECTIVE_SCHEMA_VERSION.to_owned(),
            contract_version: AWS_DETECTIVE_CONTRACT_VERSION.to_owned(),
            plugin_version: AWS_DETECTIVE_PLUGIN_VERSION.to_owned(),
            service_id: AWS_DETECTIVE_SERVICE_ID.to_owned(),
            provider_id: AWS_DETECTIVE_PROVIDER_ID.to_owned(),
            consumer_id: AWS_DETECTIVE_CONSUMER_ID.to_owned(),
            api_version: AWS_DETECTIVE_API_VERSION.to_owned(),
            evidence_level: AWS_DETECTIVE_EVIDENCE_LEVEL.to_owned(),
            read_only: true,
            proposal_only: true,
            live_execution: false,
            contract_digest,
            version_digest,
        }
    }

    pub fn validate(&self) -> Result<(), ContractDocumentError> {
        AwsDetectiveContract::baseline()
            .map_err(ContractDocumentError::from)
            .and_then(|contract| {
                let expected = Self::new();
                if self != &expected || contract.digest() != self.contract_digest {
                    return Err(ContractDocumentError::IdentityDrift);
                }
                Ok(())
            })
    }
}

pub type ServiceDefinition = AwsDetectiveServiceDefinition;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ContractDocumentError {
    #[error("AWS Detective contract document is invalid: {0}")]
    Invalid(#[from] AwsDetectiveContractError),
    #[error("AWS Detective contract document identity drifted")]
    IdentityDrift,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RegistrationError {
    #[error("AWS Detective registration is already revoked")]
    AlreadyRevoked,
    #[error("AWS Detective registration revision overflowed")]
    RevisionOverflow,
    #[error("AWS Detective registration is not bound to the supplied scope")]
    ScopeMismatch,
    #[error("AWS Detective registration digest drifted")]
    DigestDrift,
    #[error("AWS Detective SecretReference is revoked")]
    SecretRevoked,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationRevocation {
    pub previous_registration_digest: Digest,
    pub registration_digest: Digest,
    pub revision: crate::Revision,
}

fn evidence_policy_digest() -> Digest {
    Digest::from_parts(
        "hartevo-aws-detective-evidence-policy/v1",
        &[
            AWS_DETECTIVE_CONTRACT_VERSION.to_owned(),
            crate::MAX_PAGE_SIZE.to_string(),
            crate::MAX_PAGES.to_string(),
            crate::MAX_ITEMS.to_string(),
            crate::MAX_RESPONSE_BYTES.to_string(),
            crate::CURSOR_TTL_HOURS.to_string(),
            crate::MAX_INVESTIGATION_WINDOW_HOURS.to_string(),
            "digest-only-severity-status-tactic-technique".to_owned(),
            "raw-graph-edges-and-entity-pii-dropped".to_owned(),
        ],
    )
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsDetectiveRegistration {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_revision: String,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub graph_digest: Digest,
    pub investigation_scope_digest: Digest,
    pub indicator_scope_digest: Digest,
    pub member_scope_digest: Digest,
    pub evidence_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: crate::Revision,
    pub reversible: bool,
    pub state: RegistrationState,
    pub registration_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationBody<'a> {
    plugin_version: &'a str,
    contract_version: &'a str,
    contract_digest: &'a Digest,
    provider_id: &'a str,
    provider_version: &'a str,
    provider_revision: &'a str,
    provider_digest: &'a Digest,
    api_digest: &'a Digest,
    permission_digest: &'a Digest,
    scope_digest: &'a Digest,
    graph_digest: &'a Digest,
    investigation_scope_digest: &'a Digest,
    indicator_scope_digest: &'a Digest,
    member_scope_digest: &'a Digest,
    evidence_digest: &'a Digest,
    secret_reference_digest: &'a Digest,
    registration_revision: crate::Revision,
    reversible: bool,
    state: RegistrationState,
}

impl AwsDetectiveRegistration {
    fn new(
        scope: &AwsDetectiveScope,
        secret: &SecretReference,
        permission: &PermissionFence,
        provider: &AwsDetectiveProviderDefinition,
        definition: &AwsDetectiveServiceDefinition,
    ) -> Result<Self, RegistrationError> {
        let mut registration = Self {
            plugin_version: AWS_DETECTIVE_PLUGIN_VERSION.to_owned(),
            contract_version: AWS_DETECTIVE_CONTRACT_VERSION.to_owned(),
            contract_digest: definition.contract_digest.clone(),
            provider_id: provider.provider_id.clone(),
            provider_version: provider.provider_version.clone(),
            provider_revision: provider.provider_revision.clone(),
            provider_digest: provider.provider_digest.clone(),
            api_digest: provider.api_digest.clone(),
            permission_digest: permission.permission_digest.clone(),
            scope_digest: scope.digest(),
            graph_digest: scope.behavior_graph_digest(),
            investigation_scope_digest: scope.investigation_scope_digest(),
            indicator_scope_digest: scope.indicator_scope_digest(),
            member_scope_digest: scope.member_scope_digest(),
            evidence_digest: evidence_policy_digest(),
            secret_reference_digest: secret.reference_digest(),
            registration_revision: crate::Revision::new(1)?,
            reversible: true,
            state: RegistrationState::Active,
            registration_digest: Digest::zero(),
        };
        registration.registration_digest = registration.recomputed_digest();
        Ok(registration)
    }

    pub fn is_active(&self) -> bool {
        self.state == RegistrationState::Active
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serializable(&RegistrationBody {
            plugin_version: &self.plugin_version,
            contract_version: &self.contract_version,
            contract_digest: &self.contract_digest,
            provider_id: &self.provider_id,
            provider_version: &self.provider_version,
            provider_revision: &self.provider_revision,
            provider_digest: &self.provider_digest,
            api_digest: &self.api_digest,
            permission_digest: &self.permission_digest,
            scope_digest: &self.scope_digest,
            graph_digest: &self.graph_digest,
            investigation_scope_digest: &self.investigation_scope_digest,
            indicator_scope_digest: &self.indicator_scope_digest,
            member_scope_digest: &self.member_scope_digest,
            evidence_digest: &self.evidence_digest,
            secret_reference_digest: &self.secret_reference_digest,
            registration_revision: self.registration_revision,
            reversible: self.reversible,
            state: self.state,
        })
        .unwrap_or_else(|_| Digest::zero())
    }

    fn validate(
        &self,
        scope: &AwsDetectiveScope,
        secret: &SecretReference,
        permission: &PermissionFence,
        provider: &AwsDetectiveProviderDefinition,
        definition: &AwsDetectiveServiceDefinition,
    ) -> Result<(), RegistrationError> {
        secret
            .ensure_active()
            .map_err(|_| RegistrationError::SecretRevoked)?;
        if self.plugin_version != AWS_DETECTIVE_PLUGIN_VERSION
            || self.contract_version != AWS_DETECTIVE_CONTRACT_VERSION
            || self.contract_digest != definition.contract_digest
            || self.provider_id != provider.provider_id
            || self.provider_version != provider.provider_version
            || self.provider_revision != provider.provider_revision
            || self.provider_digest != provider.provider_digest
            || self.api_digest != provider.api_digest
            || self.permission_digest != permission.permission_digest
            || self.scope_digest != scope.digest()
            || self.graph_digest != scope.behavior_graph_digest()
            || self.investigation_scope_digest != scope.investigation_scope_digest()
            || self.indicator_scope_digest != scope.indicator_scope_digest()
            || self.member_scope_digest != scope.member_scope_digest()
            || self.evidence_digest != evidence_policy_digest()
            || self.secret_reference_digest != secret.reference_digest()
            || !self.reversible
            || self.registration_digest != self.recomputed_digest()
        {
            return Err(RegistrationError::DigestDrift);
        }
        Ok(())
    }

    fn revoke(&mut self) -> Result<RegistrationRevocation, RegistrationError> {
        if self.state == RegistrationState::Revoked {
            return Err(RegistrationError::AlreadyRevoked);
        }
        let previous = self.registration_digest.clone();
        let next = self
            .registration_revision
            .get()
            .checked_add(1)
            .ok_or(RegistrationError::RevisionOverflow)?;
        self.registration_revision = crate::Revision::new(next)?;
        self.state = RegistrationState::Revoked;
        self.registration_digest = self.recomputed_digest();
        Ok(RegistrationRevocation {
            previous_registration_digest: previous,
            registration_digest: self.registration_digest.clone(),
            revision: self.registration_revision,
        })
    }
}

pub type Registration = AwsDetectiveRegistration;
pub type AwsDetectiveRegistrationReceipt = AwsDetectiveRegistration;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Complete,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PaginationEvidence {
    pub pages_observed: u16,
    pub items_observed: usize,
    pub complete: bool,
    pub cursor_ttl_hours: i64,
    pub page_digests: Vec<Digest>,
    pub cursor_digests: Vec<Digest>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionSummary {
    pub entity_arn_redacted: bool,
    pub entity_email_redacted: bool,
    pub account_email_redacted: bool,
    pub raw_graph_edges_redacted: bool,
    pub raw_graph_search_redacted: bool,
    pub indicator_text_redacted: bool,
    pub datasource_payload_redacted: bool,
    pub raw_provider_payload_retained: bool,
    pub raw_next_tokens_redacted: bool,
    pub secret_material_redacted: bool,
}

impl Default for RedactionSummary {
    fn default() -> Self {
        Self {
            entity_arn_redacted: true,
            entity_email_redacted: true,
            account_email_redacted: true,
            raw_graph_edges_redacted: true,
            raw_graph_search_redacted: true,
            indicator_text_redacted: true,
            datasource_payload_redacted: true,
            raw_provider_payload_retained: false,
            raw_next_tokens_redacted: true,
            secret_material_redacted: true,
        }
    }
}

impl RedactionSummary {
    fn validate(&self) -> Result<(), ServiceError> {
        if !self.entity_arn_redacted
            || !self.entity_email_redacted
            || !self.account_email_redacted
            || !self.raw_graph_edges_redacted
            || !self.raw_graph_search_redacted
            || !self.indicator_text_redacted
            || !self.datasource_payload_redacted
            || self.raw_provider_payload_retained
            || !self.raw_next_tokens_redacted
            || !self.secret_material_redacted
        {
            return Err(ServiceError::RedactionBoundary);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityBoundary {
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub external_writes: bool,
    pub graph_search: bool,
    pub graph_mutation: bool,
    pub member_mutation: bool,
    pub datasource_mutation: bool,
    pub investigation_start: bool,
    pub investigation_state_mutation: bool,
    pub kernel_authority: bool,
    pub durable_receipt: bool,
}

impl AuthorityBoundary {
    fn validate(&self) -> Result<(), ServiceError> {
        if self.connected
            || self.native
            || self.first_party
            || self.external_writes
            || self.graph_search
            || self.graph_mutation
            || self.member_mutation
            || self.datasource_mutation
            || self.investigation_start
            || self.investigation_state_mutation
            || self.kernel_authority
            || self.durable_receipt
        {
            return Err(ServiceError::AuthorityBoundary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum EvidencePayload {
    Investigations(Vec<crate::InvestigationProjection>),
    Investigation(crate::InvestigationProjection),
    Indicators(Vec<crate::IndicatorProjection>),
    Members(Vec<crate::MemberProjection>),
}

impl EvidencePayload {
    fn operation(&self) -> DetectiveOperation {
        match self {
            Self::Investigations(_) => DetectiveOperation::ListInvestigations,
            Self::Investigation(_) => DetectiveOperation::GetInvestigation,
            Self::Indicators(_) => DetectiveOperation::ListIndicators,
            Self::Members(_) => DetectiveOperation::ListMembers,
        }
    }

    fn item_count(&self) -> usize {
        match self {
            Self::Investigations(items) => items.len(),
            Self::Indicators(items) => items.len(),
            Self::Members(items) => items.len(),
            Self::Investigation(_) => 1,
        }
    }

    fn validate(&self) -> Result<(), ServiceError> {
        match self {
            Self::Investigations(items) => {
                for item in items {
                    item.verify().map_err(ServiceError::Model)?;
                }
            }
            Self::Investigation(item) => item.verify().map_err(ServiceError::Model)?,
            Self::Indicators(items) => {
                for item in items {
                    item.verify().map_err(ServiceError::Model)?;
                }
            }
            Self::Members(items) => {
                for item in items {
                    item.verify().map_err(ServiceError::Model)?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceDigests {
    pub version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub graph_digest: Digest,
    pub investigation_scope_digest: Digest,
    pub indicator_scope_digest: Digest,
    pub member_scope_digest: Digest,
    pub evidence_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceDigestMaterial<'a> {
    operation: DetectiveOperation,
    mission: &'a crate::MissionBinding,
    graph_digest: &'a Digest,
    target_investigation: Option<&'a crate::InvestigationId>,
    payload: &'a EvidencePayload,
    registration_digest: &'a Digest,
    query_digest: &'a Digest,
    pagination: &'a PaginationEvidence,
    status: EvidenceStatus,
    redaction: &'a RedactionSummary,
    digests: &'a EvidenceDigests,
    authority: &'a AuthorityBoundary,
    provenance: ProviderProvenance,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsDetectiveEvidence {
    pub operation: DetectiveOperation,
    pub mission: crate::MissionBinding,
    pub graph_digest: Digest,
    pub target_investigation: Option<crate::InvestigationId>,
    pub payload: EvidencePayload,
    pub registration_digest: Digest,
    pub query_digest: Digest,
    pub pagination: PaginationEvidence,
    pub status: EvidenceStatus,
    pub redaction: RedactionSummary,
    pub digests: EvidenceDigests,
    pub authority: AuthorityBoundary,
    pub provenance: ProviderProvenance,
}

impl AwsDetectiveEvidence {
    fn recomputed_evidence_digest(&self) -> Digest {
        let mut digests = self.digests.clone();
        digests.evidence_digest = Digest::zero();
        digest_serializable(&EvidenceDigestMaterial {
            operation: self.operation,
            mission: &self.mission,
            graph_digest: &self.graph_digest,
            target_investigation: self.target_investigation.as_ref(),
            payload: &self.payload,
            registration_digest: &self.registration_digest,
            query_digest: &self.query_digest,
            pagination: &self.pagination,
            status: self.status,
            redaction: &self.redaction,
            digests: &digests,
            authority: &self.authority,
            provenance: self.provenance,
        })
        .unwrap_or_else(|_| Digest::zero())
    }

    pub fn evidence_digest(&self) -> &Digest {
        &self.digests.evidence_digest
    }

    pub fn verify(&self) -> Result<(), ServiceError> {
        if self.digests.evidence_digest != self.recomputed_evidence_digest() {
            return Err(ServiceError::TamperedEvidence);
        }
        if self.operation != self.payload.operation()
            || self.query_digest.is_zero()
            || self.registration_digest.is_zero()
            || self.graph_digest.is_zero()
            || self.pagination.pages_observed == 0
            || !self.pagination.complete
            || self.pagination.cursor_ttl_hours != crate::CURSOR_TTL_HOURS
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
        {
            return Err(ServiceError::TamperedEvidence);
        }
        self.redaction.validate()?;
        self.authority.validate()?;
        self.payload.validate()?;
        Ok(())
    }

    pub fn is_connected(&self) -> bool {
        false
    }

    pub fn is_native(&self) -> bool {
        false
    }

    pub fn claims_graph_search(&self) -> bool {
        false
    }

    pub fn claims_kernel_authority(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsDetectiveReadRecord {
    pub operation: DetectiveOperation,
    pub request_digest: Digest,
    pub page_digests: Vec<Digest>,
    pub item_count: usize,
    pub provenance: ProviderProvenance,
    pub raw_provider_payload_retained: bool,
    pub raw_graph_edges_retained: bool,
    pub entity_pii_retained: bool,
    pub durable_receipt: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub record_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReadRecordBody<'a> {
    operation: DetectiveOperation,
    request_digest: &'a Digest,
    page_digests: &'a [Digest],
    item_count: usize,
    provenance: ProviderProvenance,
    raw_provider_payload_retained: bool,
    raw_graph_edges_retained: bool,
    entity_pii_retained: bool,
    durable_receipt: bool,
    connected: bool,
    native: bool,
    first_party: bool,
}

impl AwsDetectiveReadRecord {
    fn new(
        operation: DetectiveOperation,
        request_digest: Digest,
        page_digests: Vec<Digest>,
        item_count: usize,
        provenance: ProviderProvenance,
    ) -> Self {
        let mut record = Self {
            operation,
            request_digest,
            page_digests,
            item_count,
            provenance,
            raw_provider_payload_retained: false,
            raw_graph_edges_retained: false,
            entity_pii_retained: false,
            durable_receipt: false,
            connected: false,
            native: false,
            first_party: false,
            record_digest: Digest::zero(),
        };
        record.record_digest = record.recomputed_digest();
        record
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serializable(&ReadRecordBody {
            operation: self.operation,
            request_digest: &self.request_digest,
            page_digests: &self.page_digests,
            item_count: self.item_count,
            provenance: self.provenance,
            raw_provider_payload_retained: self.raw_provider_payload_retained,
            raw_graph_edges_retained: self.raw_graph_edges_retained,
            entity_pii_retained: self.entity_pii_retained,
            durable_receipt: self.durable_receipt,
            connected: self.connected,
            native: self.native,
            first_party: self.first_party,
        })
        .unwrap_or_else(|_| Digest::zero())
    }

    pub fn verify(&self) -> Result<(), ServiceError> {
        if self.request_digest.is_zero()
            || self.page_digests.is_empty()
            || self.record_digest != self.recomputed_digest()
            || self.raw_provider_payload_retained
            || self.raw_graph_edges_retained
            || self.entity_pii_retained
            || self.durable_receipt
            || self.connected
            || self.native
            || self.first_party
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
        {
            return Err(ServiceError::TamperedRecord);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsDetectiveReadResult {
    pub evidence: AwsDetectiveEvidence,
    pub record: AwsDetectiveReadRecord,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsDetectiveProposal {
    pub operation: DetectiveOperation,
    pub request: AwsDetectiveReadRequest,
    pub request_digest: Digest,
    pub evidence: AwsDetectiveEvidence,
    pub record: AwsDetectiveReadRecord,
    pub proposed_at: DateTime<Utc>,
    pub registration_digest: Digest,
    pub proposal_digest: Digest,
    pub read_only: bool,
    pub live_execution: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub adopted_outcome: bool,
    pub adopted_work_product: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProposalBody<'a> {
    operation: DetectiveOperation,
    request_digest: &'a Digest,
    evidence: &'a AwsDetectiveEvidence,
    record: &'a AwsDetectiveReadRecord,
    proposed_at: &'a DateTime<Utc>,
    registration_digest: &'a Digest,
    read_only: bool,
    live_execution: bool,
    connected: bool,
    native: bool,
    first_party: bool,
    adopted_outcome: bool,
    adopted_work_product: bool,
}

impl AwsDetectiveProposal {
    fn new(
        request: AwsDetectiveReadRequest,
        result: AwsDetectiveReadResult,
        proposed_at: DateTime<Utc>,
        registration_digest: Digest,
    ) -> Self {
        let mut proposal = Self {
            operation: request.operation(),
            request,
            request_digest: result.evidence.query_digest.clone(),
            evidence: result.evidence,
            record: result.record,
            proposed_at,
            registration_digest,
            proposal_digest: Digest::zero(),
            read_only: true,
            live_execution: false,
            connected: false,
            native: false,
            first_party: false,
            adopted_outcome: false,
            adopted_work_product: false,
        };
        proposal.request_digest = proposal.request.request_digest();
        proposal.proposal_digest = proposal.recomputed_digest();
        proposal
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serializable(&ProposalBody {
            operation: self.operation,
            request_digest: &self.request_digest,
            evidence: &self.evidence,
            record: &self.record,
            proposed_at: &self.proposed_at,
            registration_digest: &self.registration_digest,
            read_only: self.read_only,
            live_execution: self.live_execution,
            connected: self.connected,
            native: self.native,
            first_party: self.first_party,
            adopted_outcome: self.adopted_outcome,
            adopted_work_product: self.adopted_work_product,
        })
        .unwrap_or_else(|_| Digest::zero())
    }

    pub fn validate(&self) -> Result<(), ServiceError> {
        self.evidence.verify()?;
        self.record.verify()?;
        if self.operation != self.request.operation()
            || self.request_digest != self.request.request_digest()
            || self.evidence.query_digest != self.request.query_digest()
            || !self.read_only
            || self.live_execution
            || self.connected
            || self.native
            || self.first_party
            || self.adopted_outcome
            || self.adopted_work_product
            || self.proposal_digest != self.recomputed_digest()
        {
            return Err(ServiceError::TamperedProposal);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsDetectiveRecordReceipt {
    pub recorded: bool,
    pub recorded_at: DateTime<Utc>,
    pub operation: DetectiveOperation,
    pub request_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub item_count: usize,
    pub raw_provider_payload_retained: bool,
    pub raw_graph_edges_retained: bool,
    pub entity_pii_retained: bool,
    pub durable_receipt: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub receipt_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReceiptBody<'a> {
    recorded: bool,
    recorded_at: &'a DateTime<Utc>,
    operation: DetectiveOperation,
    request_digest: &'a Digest,
    proposal_digest: &'a Digest,
    evidence_digest: &'a Digest,
    registration_digest: &'a Digest,
    scope_digest: &'a Digest,
    item_count: usize,
    raw_provider_payload_retained: bool,
    raw_graph_edges_retained: bool,
    entity_pii_retained: bool,
    durable_receipt: bool,
    connected: bool,
    native: bool,
    first_party: bool,
}

impl AwsDetectiveRecordReceipt {
    fn new(proposal: &AwsDetectiveProposal, recorded_at: DateTime<Utc>) -> Self {
        let mut receipt = Self {
            recorded: true,
            recorded_at,
            operation: proposal.operation,
            request_digest: proposal.request_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest().clone(),
            registration_digest: proposal.registration_digest.clone(),
            scope_digest: proposal.evidence.digests.scope_digest.clone(),
            item_count: proposal.record.item_count,
            raw_provider_payload_retained: false,
            raw_graph_edges_retained: false,
            entity_pii_retained: false,
            durable_receipt: false,
            connected: false,
            native: false,
            first_party: false,
            receipt_digest: Digest::zero(),
        };
        receipt.receipt_digest = receipt.recomputed_digest();
        receipt
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serializable(&ReceiptBody {
            recorded: self.recorded,
            recorded_at: &self.recorded_at,
            operation: self.operation,
            request_digest: &self.request_digest,
            proposal_digest: &self.proposal_digest,
            evidence_digest: &self.evidence_digest,
            registration_digest: &self.registration_digest,
            scope_digest: &self.scope_digest,
            item_count: self.item_count,
            raw_provider_payload_retained: self.raw_provider_payload_retained,
            raw_graph_edges_retained: self.raw_graph_edges_retained,
            entity_pii_retained: self.entity_pii_retained,
            durable_receipt: self.durable_receipt,
            connected: self.connected,
            native: self.native,
            first_party: self.first_party,
        })
        .unwrap_or_else(|_| Digest::zero())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsDetectiveVerifiedRecord {
    pub verified: bool,
    pub operation: DetectiveOperation,
    pub request_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub verification_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub adopted_outcome: bool,
    pub adopted_work_product: bool,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ServiceError {
    #[error("AWS Detective registration is revoked")]
    RegistrationRevoked,
    #[error("AWS Detective SecretReference is revoked")]
    SecretRevoked,
    #[error("AWS Detective scope or permission digest does not verify")]
    ScopeMismatch,
    #[error("AWS Detective permission was lost or changed")]
    PermissionLoss,
    #[error("AWS Detective behavior graph drifted")]
    GraphDrift,
    #[error("AWS Detective investigation drifted or is stale")]
    InvestigationDrift,
    #[error("AWS Detective investigation is outside the exact allowlist")]
    InvestigationOutOfScope,
    #[error("AWS Detective indicator is outside the exact allowlist")]
    IndicatorOutOfScope,
    #[error("AWS Detective member is outside the exact allowlist")]
    MemberOutOfScope,
    #[error("AWS Detective pagination cursor expired")]
    CursorExpired,
    #[error("AWS Detective pagination cursor binding mismatch")]
    CursorBindingMismatch,
    #[error("AWS Detective pagination cursor replayed")]
    CursorReplay,
    #[error("AWS Detective pagination loop detected")]
    PaginationLoop,
    #[error("AWS Detective pagination did not complete within its bound")]
    PaginationIncomplete,
    #[error("AWS Detective response exceeded its bound")]
    ResponseTooLarge,
    #[error("AWS Detective response was not found")]
    NotFound,
    #[error("AWS Detective transport is unavailable in BLOCKED_ENV")]
    BlockedEnvironment,
    #[error("AWS Detective evidence was tampered")]
    TamperedEvidence,
    #[error("AWS Detective record was tampered")]
    TamperedRecord,
    #[error("AWS Detective proposal was tampered")]
    TamperedProposal,
    #[error("AWS Detective redaction boundary was widened")]
    RedactionBoundary,
    #[error("AWS Detective authority boundary was widened")]
    AuthorityBoundary,
    #[error("AWS Detective provider is unavailable or unknown")]
    ProviderUnavailable,
    #[error("AWS Detective contract error: {0}")]
    Contract(#[from] ContractDocumentError),
    #[error("AWS Detective provider error: {0}")]
    Provider(ProviderError),
    #[error("AWS Detective model error: {0}")]
    Model(#[from] ModelError),
    #[error("AWS Detective registration error: {0}")]
    Registration(#[from] RegistrationError),
}

impl From<ProviderError> for ServiceError {
    fn from(value: ProviderError) -> Self {
        match &value {
            ProviderError::Transport(
                crate::TransportError::Unauthorized | crate::TransportError::Forbidden,
            ) => Self::PermissionLoss,
            ProviderError::Transport(crate::TransportError::BlockedEnvironment) => {
                Self::BlockedEnvironment
            }
            ProviderError::Transport(crate::TransportError::NotFound) => Self::NotFound,
            ProviderError::Transport(
                crate::TransportError::RateLimited { .. }
                | crate::TransportError::ServerFailure { .. }
                | crate::TransportError::Timeout
                | crate::TransportError::Unknown,
            ) => Self::ProviderUnavailable,
            _ => Self::Provider(value),
        }
    }
}

pub struct AwsDetectiveService<T = crate::BlockedEnvTransport> {
    scope: AwsDetectiveScope,
    permission: PermissionFence,
    secret_reference: SecretReference,
    provider: AwsDetectiveProvider<T>,
    definition: AwsDetectiveServiceDefinition,
    registration: AwsDetectiveRegistration,
}

pub type AwsDetectiveResultService<T> = AwsDetectiveService<T>;

impl<T: AwsDetectiveTransport> fmt::Debug for AwsDetectiveService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsDetectiveService")
            .field("scope_digest", &self.scope.digest())
            .field("permission_digest", &self.permission.permission_digest)
            .field("secret_reference", &self.secret_reference)
            .field("provider", &self.provider.definition())
            .field("registration", &self.registration)
            .finish_non_exhaustive()
    }
}

impl<T: AwsDetectiveTransport> AwsDetectiveService<T> {
    pub fn new(
        scope: AwsDetectiveScope,
        secret_reference: SecretReference,
        permission: PermissionFence,
        provider: AwsDetectiveProvider<T>,
    ) -> Result<Self, ServiceError> {
        scope.validate()?;
        permission.validate()?;
        if scope.permission_digest != permission.permission_digest
            || secret_reference.scope_digest() != &scope.digest()
            || secret_reference.region() != &scope.region
        {
            return Err(ServiceError::ScopeMismatch);
        }
        secret_reference
            .ensure_active()
            .map_err(|_| ServiceError::SecretRevoked)?;
        provider.validate()?;
        let definition = AwsDetectiveServiceDefinition::new();
        definition.validate()?;
        let registration = AwsDetectiveRegistration::new(
            &scope,
            &secret_reference,
            &permission,
            provider.definition(),
            &definition,
        )?;
        Ok(Self {
            scope,
            permission,
            secret_reference,
            provider,
            definition,
            registration,
        })
    }

    pub fn scope(&self) -> &AwsDetectiveScope {
        &self.scope
    }

    pub fn permission(&self) -> &PermissionFence {
        &self.permission
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn secret_reference_mut(&mut self) -> &mut SecretReference {
        &mut self.secret_reference
    }

    pub fn provider(&self) -> &AwsDetectiveProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsDetectiveProvider<T> {
        &mut self.provider
    }

    pub fn service_definition(&self) -> &AwsDetectiveServiceDefinition {
        &self.definition
    }

    pub fn registration(&self) -> &AwsDetectiveRegistration {
        &self.registration
    }

    pub fn is_active(&self) -> bool {
        self.registration.is_active()
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationRevocation, ServiceError> {
        self.registration.revoke().map_err(ServiceError::from)
    }

    pub fn revoke_secret_reference(&mut self) -> Result<(), ServiceError> {
        self.secret_reference
            .revoke()
            .map_err(|_| ServiceError::SecretRevoked)
    }

    pub fn read(
        &mut self,
        request: AwsDetectiveReadRequest,
    ) -> Result<AwsDetectiveReadResult, ServiceError> {
        self.read_at(request, Utc::now())
    }

    pub fn read_bounded(
        &mut self,
        request: AwsDetectiveReadRequest,
    ) -> Result<AwsDetectiveReadResult, ServiceError> {
        self.read(request)
    }

    pub fn read_at(
        &mut self,
        request: AwsDetectiveReadRequest,
        now: DateTime<Utc>,
    ) -> Result<AwsDetectiveReadResult, ServiceError> {
        self.ensure_active_and_bound()?;
        self.validate_request(&request, now)?;
        let operation = request.operation();
        let request_digest = request.request_digest();
        let (payload, pagination, page_digests) = match &request {
            AwsDetectiveReadRequest::ListInvestigations(value) => {
                let (items, pagination, page_digests) = self.read_investigations(value, now)?;
                (
                    EvidencePayload::Investigations(items),
                    pagination,
                    page_digests,
                )
            }
            AwsDetectiveReadRequest::GetInvestigation(value) => {
                let (item, response) = self.read_investigation(value)?;
                (
                    EvidencePayload::Investigation(item),
                    PaginationEvidence {
                        pages_observed: 1,
                        items_observed: 1,
                        complete: true,
                        cursor_ttl_hours: crate::CURSOR_TTL_HOURS,
                        page_digests: vec![response.digest()],
                        cursor_digests: Vec::new(),
                    },
                    vec![response.digest()],
                )
            }
            AwsDetectiveReadRequest::ListIndicators(value) => {
                let (items, pagination, page_digests) = self.read_indicators(value, now)?;
                (EvidencePayload::Indicators(items), pagination, page_digests)
            }
            AwsDetectiveReadRequest::ListMembers(value) => {
                let (items, pagination, page_digests) = self.read_members(value, now)?;
                (EvidencePayload::Members(items), pagination, page_digests)
            }
        };
        let mut evidence = AwsDetectiveEvidence {
            operation,
            mission: self.scope.mission.clone(),
            graph_digest: self.scope.behavior_graph_digest(),
            target_investigation: match &request {
                AwsDetectiveReadRequest::GetInvestigation(value) => {
                    Some(value.investigation_id.clone())
                }
                AwsDetectiveReadRequest::ListIndicators(value) => {
                    Some(value.investigation_id.clone())
                }
                _ => None,
            },
            payload,
            registration_digest: self.registration.registration_digest.clone(),
            query_digest: request.query_digest(),
            pagination,
            status: EvidenceStatus::Complete,
            redaction: RedactionSummary::default(),
            digests: EvidenceDigests {
                version_digest: self.definition.version_digest.clone(),
                contract_digest: self.definition.contract_digest.clone(),
                provider_digest: self.provider.definition().provider_digest.clone(),
                api_digest: self.provider.definition().api_digest.clone(),
                permission_digest: self.permission.permission_digest.clone(),
                scope_digest: self.scope.digest(),
                graph_digest: self.scope.behavior_graph_digest(),
                investigation_scope_digest: self.scope.investigation_scope_digest(),
                indicator_scope_digest: self.scope.indicator_scope_digest(),
                member_scope_digest: self.scope.member_scope_digest(),
                evidence_digest: Digest::zero(),
            },
            authority: AuthorityBoundary::default(),
            provenance: self.provider.provenance(),
        };
        evidence.digests.evidence_digest = evidence.recomputed_evidence_digest();
        let record = AwsDetectiveReadRecord::new(
            operation,
            request_digest,
            page_digests,
            evidence.payload.item_count(),
            self.provider.provenance(),
        );
        Ok(AwsDetectiveReadResult { evidence, record })
    }

    pub fn propose(
        &mut self,
        request: AwsDetectiveReadRequest,
        proposed_at: DateTime<Utc>,
    ) -> Result<AwsDetectiveProposal, ServiceError> {
        let result = self.read(request.clone())?;
        Ok(AwsDetectiveProposal::new(
            request,
            result,
            proposed_at,
            self.registration.registration_digest.clone(),
        ))
    }

    pub fn propose_at(
        &mut self,
        request: AwsDetectiveReadRequest,
        proposed_at: DateTime<Utc>,
    ) -> Result<AwsDetectiveProposal, ServiceError> {
        let result = self.read_at(request.clone(), proposed_at)?;
        Ok(AwsDetectiveProposal::new(
            request,
            result,
            proposed_at,
            self.registration.registration_digest.clone(),
        ))
    }

    pub fn record(
        &self,
        proposal: &AwsDetectiveProposal,
    ) -> Result<AwsDetectiveRecordReceipt, ServiceError> {
        self.record_at(proposal, Utc::now())
    }

    pub fn record_at(
        &self,
        proposal: &AwsDetectiveProposal,
        recorded_at: DateTime<Utc>,
    ) -> Result<AwsDetectiveRecordReceipt, ServiceError> {
        self.ensure_active_and_bound()?;
        self.verify_proposal(proposal)?;
        Ok(AwsDetectiveRecordReceipt::new(proposal, recorded_at))
    }

    pub fn verify(
        &self,
        receipt: &AwsDetectiveRecordReceipt,
    ) -> Result<AwsDetectiveVerifiedRecord, ServiceError> {
        self.ensure_active_and_bound()?;
        if !receipt.recorded
            || receipt.operation != receipt_operation(receipt)
            || receipt.registration_digest != self.registration.registration_digest
            || receipt.scope_digest != self.scope.digest()
            || receipt.receipt_digest != receipt.recomputed_digest()
            || receipt.connected
            || receipt.native
            || receipt.first_party
            || receipt.durable_receipt
            || receipt.raw_provider_payload_retained
            || receipt.raw_graph_edges_retained
            || receipt.entity_pii_retained
        {
            return Err(ServiceError::TamperedRecord);
        }
        let verification_digest = Digest::from_parts(
            "hartevo-aws-detective-verified-record/v1",
            &[
                receipt.receipt_digest.to_string(),
                receipt.registration_digest.to_string(),
                receipt.scope_digest.to_string(),
            ],
        );
        Ok(AwsDetectiveVerifiedRecord {
            verified: true,
            operation: receipt.operation,
            request_digest: receipt.request_digest.clone(),
            proposal_digest: receipt.proposal_digest.clone(),
            evidence_digest: receipt.evidence_digest.clone(),
            registration_digest: receipt.registration_digest.clone(),
            verification_digest,
            connected: false,
            native: false,
            first_party: false,
            adopted_outcome: false,
            adopted_work_product: false,
        })
    }

    pub fn verify_evidence(&self, evidence: &AwsDetectiveEvidence) -> Result<(), ServiceError> {
        self.ensure_active_and_bound()?;
        evidence.verify()?;
        if evidence.registration_digest != self.registration.registration_digest
            || evidence.digests.scope_digest != self.scope.digest()
            || evidence.digests.permission_digest != self.permission.permission_digest
            || evidence.digests.provider_digest != self.provider.definition().provider_digest
            || evidence.digests.contract_digest != self.definition.contract_digest
        {
            return Err(ServiceError::ScopeMismatch);
        }
        Ok(())
    }

    pub fn verify_proposal(&self, proposal: &AwsDetectiveProposal) -> Result<(), ServiceError> {
        self.ensure_active_and_bound()?;
        proposal.validate()?;
        self.verify_evidence(&proposal.evidence)?;
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.record.operation != proposal.operation
            || proposal.record.request_digest != proposal.request_digest
        {
            return Err(ServiceError::TamperedProposal);
        }
        Ok(())
    }

    fn ensure_active_and_bound(&self) -> Result<(), ServiceError> {
        if !self.registration.is_active() {
            return Err(ServiceError::RegistrationRevoked);
        }
        self.registration
            .validate(
                &self.scope,
                &self.secret_reference,
                &self.permission,
                self.provider.definition(),
                &self.definition,
            )
            .map_err(|error| match error {
                RegistrationError::SecretRevoked => ServiceError::SecretRevoked,
                other => ServiceError::Registration(other),
            })
    }

    fn validate_request(
        &self,
        request: &AwsDetectiveReadRequest,
        now: DateTime<Utc>,
    ) -> Result<(), ServiceError> {
        if !self.permission.allows(request.operation())
            || self.scope.permission_digest != self.permission.permission_digest
            || request.query_digest().is_zero()
        {
            return Err(ServiceError::PermissionLoss);
        }
        match request {
            AwsDetectiveReadRequest::ListInvestigations(value) => {
                value.bounds.validate()?;
                if value.graph != self.scope.behavior_graph.id
                    || value.time_window != self.scope.time_window
                {
                    return Err(ServiceError::ScopeMismatch);
                }
                Self::validate_cursor(value.cursor.as_ref(), value.query_digest(), now)?;
            }
            AwsDetectiveReadRequest::GetInvestigation(value) => {
                self.validate_graph(&value.graph)?;
                let Some(binding) = self.scope.investigation(&value.investigation_id) else {
                    return Err(ServiceError::InvestigationOutOfScope);
                };
                if binding.revision != value.investigation_revision
                    || binding.window != value.time_window
                {
                    return Err(ServiceError::InvestigationDrift);
                }
            }
            AwsDetectiveReadRequest::ListIndicators(value) => {
                value.bounds.validate()?;
                self.validate_graph(&value.graph)?;
                let Some(binding) = self.scope.investigation(&value.investigation_id) else {
                    return Err(ServiceError::InvestigationOutOfScope);
                };
                if binding.revision != value.investigation_revision
                    || binding.window != value.time_window
                {
                    return Err(ServiceError::InvestigationDrift);
                }
                Self::validate_cursor(value.cursor.as_ref(), value.query_digest(), now)?;
            }
            AwsDetectiveReadRequest::ListMembers(value) => {
                value.bounds.validate()?;
                if value.graph != self.scope.behavior_graph.id
                    || value.time_window != self.scope.time_window
                {
                    return Err(ServiceError::ScopeMismatch);
                }
                Self::validate_cursor(value.cursor.as_ref(), value.query_digest(), now)?;
            }
        }
        Ok(())
    }

    fn validate_graph(&self, graph: &BehaviorGraphId) -> Result<(), ServiceError> {
        if graph != &self.scope.behavior_graph.id {
            Err(ServiceError::GraphDrift)
        } else {
            Ok(())
        }
    }

    fn validate_cursor(
        cursor: Option<&OpaqueCursor>,
        query_digest: Digest,
        now: DateTime<Utc>,
    ) -> Result<(), ServiceError> {
        if let Some(cursor) = cursor {
            if cursor.is_expired(now) {
                return Err(ServiceError::CursorExpired);
            }
            if cursor.binding_digest() != Some(&query_digest) {
                return Err(ServiceError::CursorBindingMismatch);
            }
        }
        Ok(())
    }

    fn read_investigations(
        &mut self,
        request: &ListInvestigationsRequest,
        now: DateTime<Utc>,
    ) -> Result<
        (
            Vec<crate::InvestigationProjection>,
            PaginationEvidence,
            Vec<Digest>,
        ),
        ServiceError,
    > {
        let query_digest = request.query_digest();
        let mut cursor = request.cursor.clone();
        let mut seen_cursors = BTreeSet::new();
        if let Some(value) = &cursor {
            seen_cursors.insert(value.token_digest().clone());
        }
        let mut items = Vec::new();
        let mut item_ids = BTreeSet::new();
        let mut page_digests = Vec::new();
        let mut cursor_digests = Vec::new();
        let mut pages_observed = 0_u16;
        let mut response_bytes = 0_usize;
        loop {
            if pages_observed >= request.bounds.max_pages {
                return Err(ServiceError::PaginationIncomplete);
            }
            let current = request.clone().with_cursor(cursor.clone());
            let page = self.provider.list_investigations(&current)?;
            if page.page_number != pages_observed + 1 {
                return Err(ServiceError::PaginationLoop);
            }
            if page.items.len() > usize::from(request.bounds.page_size) {
                return Err(ServiceError::PaginationIncomplete);
            }
            response_bytes = response_bytes.saturating_add(page.response_bytes);
            if response_bytes > request.bounds.max_response_bytes {
                return Err(ServiceError::ResponseTooLarge);
            }
            if items.len() + page.items.len() > request.bounds.max_items {
                return Err(ServiceError::PaginationIncomplete);
            }
            for item in &page.items {
                self.validate_investigation(item)?;
                if !item_ids.insert(item.investigation_id.clone()) {
                    return Err(ServiceError::PaginationLoop);
                }
            }
            pages_observed += 1;
            page_digests.push(page.digest());
            items.extend(page.items);
            let Some(next) = page.next_cursor else {
                break;
            };
            let next = Self::validate_next_cursor(next, &query_digest, now, &mut seen_cursors)?;
            cursor_digests.push(next.token_digest().clone());
            if pages_observed >= request.bounds.max_pages {
                return Err(ServiceError::PaginationIncomplete);
            }
            cursor = Some(next);
        }
        Ok((
            items.clone(),
            PaginationEvidence {
                pages_observed,
                items_observed: items.len(),
                complete: true,
                cursor_ttl_hours: crate::CURSOR_TTL_HOURS,
                page_digests: page_digests.clone(),
                cursor_digests,
            },
            page_digests,
        ))
    }

    fn read_investigation(
        &mut self,
        request: &GetInvestigationRequest,
    ) -> Result<(crate::InvestigationProjection, GetInvestigationResponse), ServiceError> {
        let response = self.provider.get_investigation(request)?;
        let Some(item) = response.item.clone() else {
            return Err(ServiceError::NotFound);
        };
        self.validate_investigation(&item)?;
        if item.investigation_id != request.investigation_id
            || item.investigation_revision != request.investigation_revision
            || item.scope_window != request.time_window
        {
            return Err(ServiceError::InvestigationDrift);
        }
        Ok((item, response))
    }

    fn read_indicators(
        &mut self,
        request: &ListIndicatorsRequest,
        now: DateTime<Utc>,
    ) -> Result<
        (
            Vec<crate::IndicatorProjection>,
            PaginationEvidence,
            Vec<Digest>,
        ),
        ServiceError,
    > {
        let query_digest = request.query_digest();
        let mut cursor = request.cursor.clone();
        let mut seen_cursors = BTreeSet::new();
        if let Some(value) = &cursor {
            seen_cursors.insert(value.token_digest().clone());
        }
        let mut items = Vec::new();
        let mut item_ids = BTreeSet::new();
        let mut page_digests = Vec::new();
        let mut cursor_digests = Vec::new();
        let mut pages_observed = 0_u16;
        let mut response_bytes = 0_usize;
        loop {
            if pages_observed >= request.bounds.max_pages {
                return Err(ServiceError::PaginationIncomplete);
            }
            let current = request.clone().with_cursor(cursor.clone());
            let page = self.provider.list_indicators(&current)?;
            if page.page_number != pages_observed + 1 {
                return Err(ServiceError::PaginationLoop);
            }
            if page.items.len() > usize::from(request.bounds.page_size) {
                return Err(ServiceError::PaginationIncomplete);
            }
            response_bytes = response_bytes.saturating_add(page.response_bytes);
            if response_bytes > request.bounds.max_response_bytes {
                return Err(ServiceError::ResponseTooLarge);
            }
            if items.len() + page.items.len() > request.bounds.max_items {
                return Err(ServiceError::PaginationIncomplete);
            }
            for item in &page.items {
                self.validate_indicator(item, request)?;
                if !item_ids.insert(item.indicator_id.clone()) {
                    return Err(ServiceError::PaginationLoop);
                }
            }
            pages_observed += 1;
            page_digests.push(page.digest());
            items.extend(page.items);
            let Some(next) = page.next_cursor else {
                break;
            };
            let next = Self::validate_next_cursor(next, &query_digest, now, &mut seen_cursors)?;
            cursor_digests.push(next.token_digest().clone());
            if pages_observed >= request.bounds.max_pages {
                return Err(ServiceError::PaginationIncomplete);
            }
            cursor = Some(next);
        }
        Ok((
            items.clone(),
            PaginationEvidence {
                pages_observed,
                items_observed: items.len(),
                complete: true,
                cursor_ttl_hours: crate::CURSOR_TTL_HOURS,
                page_digests: page_digests.clone(),
                cursor_digests,
            },
            page_digests,
        ))
    }

    fn read_members(
        &mut self,
        request: &ListMembersRequest,
        now: DateTime<Utc>,
    ) -> Result<
        (
            Vec<crate::MemberProjection>,
            PaginationEvidence,
            Vec<Digest>,
        ),
        ServiceError,
    > {
        let query_digest = request.query_digest();
        let mut cursor = request.cursor.clone();
        let mut seen_cursors = BTreeSet::new();
        if let Some(value) = &cursor {
            seen_cursors.insert(value.token_digest().clone());
        }
        let mut items = Vec::new();
        let mut item_ids = BTreeSet::new();
        let mut page_digests = Vec::new();
        let mut cursor_digests = Vec::new();
        let mut pages_observed = 0_u16;
        let mut response_bytes = 0_usize;
        loop {
            if pages_observed >= request.bounds.max_pages {
                return Err(ServiceError::PaginationIncomplete);
            }
            let current = request.clone().with_cursor(cursor.clone());
            let page = self.provider.list_members(&current)?;
            if page.page_number != pages_observed + 1 {
                return Err(ServiceError::PaginationLoop);
            }
            if page.items.len() > usize::from(request.bounds.page_size) {
                return Err(ServiceError::PaginationIncomplete);
            }
            response_bytes = response_bytes.saturating_add(page.response_bytes);
            if response_bytes > request.bounds.max_response_bytes {
                return Err(ServiceError::ResponseTooLarge);
            }
            if items.len() + page.items.len() > request.bounds.max_items {
                return Err(ServiceError::PaginationIncomplete);
            }
            for item in &page.items {
                self.validate_member(item)?;
                if !item_ids.insert(item.member_id.clone()) {
                    return Err(ServiceError::PaginationLoop);
                }
            }
            pages_observed += 1;
            page_digests.push(page.digest());
            items.extend(page.items);
            let Some(next) = page.next_cursor else {
                break;
            };
            let next = Self::validate_next_cursor(next, &query_digest, now, &mut seen_cursors)?;
            cursor_digests.push(next.token_digest().clone());
            if pages_observed >= request.bounds.max_pages {
                return Err(ServiceError::PaginationIncomplete);
            }
            cursor = Some(next);
        }
        Ok((
            items.clone(),
            PaginationEvidence {
                pages_observed,
                items_observed: items.len(),
                complete: true,
                cursor_ttl_hours: crate::CURSOR_TTL_HOURS,
                page_digests: page_digests.clone(),
                cursor_digests,
            },
            page_digests,
        ))
    }

    fn validate_next_cursor(
        cursor: OpaqueCursor,
        query_digest: &Digest,
        now: DateTime<Utc>,
        seen: &mut BTreeSet<Digest>,
    ) -> Result<OpaqueCursor, ServiceError> {
        if cursor.is_expired(now) {
            return Err(ServiceError::CursorExpired);
        }
        if let Some(binding) = cursor.binding_digest()
            && binding != query_digest
        {
            return Err(ServiceError::CursorBindingMismatch);
        }
        if !seen.insert(cursor.token_digest().clone()) {
            return Err(ServiceError::CursorReplay);
        }
        Ok(cursor.bind(query_digest))
    }

    fn validate_investigation(
        &self,
        item: &crate::InvestigationProjection,
    ) -> Result<(), ServiceError> {
        item.verify()?;
        self.validate_graph(&item.graph)?;
        let Some(binding) = self.scope.investigation(&item.investigation_id) else {
            return Err(ServiceError::InvestigationOutOfScope);
        };
        if binding.revision != item.investigation_revision
            || binding.window != item.scope_window
            || !self.scope.time_window.contains_window(&item.scope_window)
            || !self.scope.time_window.contains(item.created_at)
        {
            return Err(ServiceError::InvestigationDrift);
        }
        Ok(())
    }

    fn validate_indicator(
        &self,
        item: &crate::IndicatorProjection,
        request: &ListIndicatorsRequest,
    ) -> Result<(), ServiceError> {
        item.verify()?;
        self.validate_graph(&item.graph)?;
        if item.investigation_id != request.investigation_id
            || item.investigation_revision != request.investigation_revision
        {
            return Err(ServiceError::InvestigationDrift);
        }
        let Some(binding) = self.scope.indicator(&item.indicator_id) else {
            return Err(ServiceError::IndicatorOutOfScope);
        };
        if binding.revision != item.indicator_revision {
            return Err(ServiceError::IndicatorOutOfScope);
        }
        Ok(())
    }

    fn validate_member(&self, item: &crate::MemberProjection) -> Result<(), ServiceError> {
        item.verify()?;
        self.validate_graph(&item.graph)?;
        let Some(binding) = self.scope.member(&item.member_id) else {
            return Err(ServiceError::MemberOutOfScope);
        };
        if binding.revision != item.member_revision {
            return Err(ServiceError::MemberOutOfScope);
        }
        Ok(())
    }
}

fn receipt_operation(receipt: &AwsDetectiveRecordReceipt) -> DetectiveOperation {
    receipt.operation
}

pub type AwsDetectiveServiceError = ServiceError;
pub type AwsDetectiveProposalError = ServiceError;
pub type AwsDetectiveReadEvidence = AwsDetectiveEvidence;

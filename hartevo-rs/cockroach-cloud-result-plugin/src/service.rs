use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Deserialize, Serialize};

use crate::model::{
    ClusterProjection, HealthProjection, SettingsMetadataProjection, SqlActivityProjection,
    transport_error_state, validate_bounded_counts,
};
use crate::{
    API_REVISION, CONSUMER_ID, CONTRACT_VERSION, CockroachCloudPage, CockroachCloudProvider,
    CockroachCloudProviderDefinition, CockroachCloudReadRequest, CockroachCloudResultError,
    CockroachCloudScope, CockroachCloudTransport, CockroachCloudTransportError, Digest,
    EvidenceState, MAX_IDENTIFIER_BYTES, MAX_PAGES, MAX_RESPONSE_BYTES, PLUGIN_ID, PLUGIN_VERSION,
    PROVIDER_ID, ProviderProvenance, RegistrationState, SERVICE_ID, SecretReference,
    TransportProvenance, contract_digest, plugin_version_digest,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    Absent,
    Denied,
    Partial,
    Expired,
    AccessLoss,
    RateLimited,
    ProviderUnknown,
    Stale,
    RegistrationRevoked,
}

impl From<EvidenceState> for Option<FailureKind> {
    fn from(state: EvidenceState) -> Self {
        match state {
            EvidenceState::Absent => Some(FailureKind::Absent),
            EvidenceState::Denied => Some(FailureKind::Denied),
            EvidenceState::Partial => Some(FailureKind::Partial),
            EvidenceState::Expired => Some(FailureKind::Expired),
            EvidenceState::AccessLoss => Some(FailureKind::AccessLoss),
            EvidenceState::RateLimited => Some(FailureKind::RateLimited),
            EvidenceState::ProviderUnknown => Some(FailureKind::ProviderUnknown),
            EvidenceState::Stale => Some(FailureKind::Stale),
            EvidenceState::RegistrationRevoked => Some(FailureKind::RegistrationRevoked),
            EvidenceState::Healthy | EvidenceState::Degraded | EvidenceState::Unavailable => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FailureEvidence {
    pub kind: FailureKind,
    pub state: EvidenceState,
    pub failure_digest: Digest,
    pub retry_after_seconds: Option<u32>,
}

impl FailureEvidence {
    fn new(state: EvidenceState, reason: &str, retry_after_seconds: Option<u32>) -> Self {
        let kind = Option::<FailureKind>::from(state).unwrap_or(FailureKind::ProviderUnknown);
        Self {
            kind,
            state,
            failure_digest: Digest::from_text(reason),
            retry_after_seconds,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PaginationEvidence {
    pub pages: u16,
    pub page_size: u16,
    pub complete: bool,
    pub partial: bool,
    pub cursor_digests: Vec<Digest>,
    pub response_digests: Vec<Digest>,
}

impl PaginationEvidence {
    fn empty(request: &CockroachCloudReadRequest) -> Self {
        Self {
            pages: 0,
            page_size: request.page_size,
            complete: false,
            partial: false,
            cursor_digests: Vec::new(),
            response_digests: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadReceipt {
    pub operation: String,
    pub page: u16,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub item_count: u32,
    pub sql_activity_count: u32,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub raw_provider_payload_retained: bool,
    pub raw_sql_retained: bool,
    pub raw_result_retained: bool,
    pub credential_material_retained: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub receipt_digest: Digest,
}

impl ReadReceipt {
    fn from_page(page: &CockroachCloudPage) -> Self {
        let item_count = u32::from(page.cluster.is_some())
            + u32::from(page.health.is_some())
            + u32::from(page.settings.is_some());
        let sql_activity_count = u32::try_from(page.sql_activity.len()).unwrap_or(u32::MAX);
        let mut receipt = Self {
            operation: "bounded_cockroach_cloud_posture_read".to_owned(),
            page: page.page,
            request_digest: page.request_digest.clone(),
            response_digest: page.response_digest.clone(),
            item_count,
            sql_activity_count,
            response_bytes: page.response_bytes,
            provenance: page.provenance,
            raw_provider_payload_retained: false,
            raw_sql_retained: false,
            raw_result_retained: false,
            credential_material_retained: false,
            connected: false,
            native: false,
            first_party: false,
            receipt_digest: Digest::from_text("pending-receipt-digest"),
        };
        receipt.receipt_digest = receipt.calculate_digest();
        receipt
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_serializable(&(
            &self.operation,
            self.page,
            &self.request_digest,
            &self.response_digest,
            self.item_count,
            self.sql_activity_count,
            self.response_bytes,
            self.provenance,
            self.raw_provider_payload_retained,
            self.raw_sql_retained,
            self.raw_result_retained,
            self.credential_material_retained,
            self.connected,
            self.native,
            self.first_party,
        ))
    }

    pub fn validate_integrity(&self) -> Result<(), CockroachCloudResultError> {
        if self.receipt_digest != self.calculate_digest()
            || self.raw_provider_payload_retained
            || self.raw_sql_retained
            || self.raw_result_retained
            || self.credential_material_retained
            || self.connected
            || self.native
            || self.first_party
            || self.response_bytes == 0
            || self.response_bytes > MAX_RESPONSE_BYTES
        {
            Err(CockroachCloudResultError::ReceiptTampered)
        } else {
            Ok(())
        }
    }

    pub fn digest(&self) -> &Digest {
        &self.receipt_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CockroachCloudEvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub revision_fence_digest: Digest,
    pub query_digest: Digest,
    pub cluster_digest: Digest,
    pub health_digest: Digest,
    pub settings_digest: Digest,
    pub sql_activity_digest: Digest,
    pub response_digest: Digest,
    pub evidence_digest: Digest,
}

#[derive(Serialize)]
struct EvidenceDigestInput<'a> {
    contract_version: &'a str,
    plugin_version: &'a str,
    service_id: &'a str,
    provider_id: &'a str,
    provider_revision: &'a str,
    provider_provenance: ProviderProvenance,
    connected: bool,
    native: bool,
    first_party: bool,
    scope_digest: &'a Digest,
    revision_fence_digest: &'a Digest,
    permission_digest: &'a Digest,
    query_digest: &'a Digest,
    request_digest: &'a Digest,
    state: EvidenceState,
    cluster: &'a Option<ClusterProjection>,
    health: &'a Option<HealthProjection>,
    settings: &'a Option<SettingsMetadataProjection>,
    sql_activity: &'a Vec<SqlActivityProjection>,
    pagination: &'a PaginationEvidence,
    receipts: &'a Vec<ReadReceipt>,
    failure: &'a Option<FailureEvidence>,
    observed_at: u64,
    expires_at: u64,
    review_only: bool,
    health_certification_claim: bool,
    security_truth_claim: bool,
    outcome_adopted: bool,
    work_product_adopted: bool,
    plugin_version_digest: &'a Digest,
    contract_digest: &'a Digest,
    provider_digest: &'a Digest,
    api_digest: &'a Digest,
    digest_permission: &'a Digest,
    digest_scope: &'a Digest,
    digest_revision_fence: &'a Digest,
    digest_query: &'a Digest,
    digest_cluster: &'a Digest,
    digest_health: &'a Digest,
    digest_settings: &'a Digest,
    digest_sql_activity: &'a Digest,
    digest_response: &'a Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CockroachCloudEvidence {
    pub contract_version: String,
    pub plugin_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub provider_revision: String,
    pub provider_provenance: ProviderProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub scope_digest: Digest,
    pub revision_fence_digest: Digest,
    pub permission_digest: Digest,
    pub query_digest: Digest,
    pub request_digest: Digest,
    pub state: EvidenceState,
    pub cluster: Option<ClusterProjection>,
    pub health: Option<HealthProjection>,
    pub settings: Option<SettingsMetadataProjection>,
    pub sql_activity: Vec<SqlActivityProjection>,
    pub pagination: PaginationEvidence,
    pub receipts: Vec<ReadReceipt>,
    pub failure: Option<FailureEvidence>,
    pub observed_at: u64,
    pub expires_at: u64,
    pub review_only: bool,
    pub health_certification_claim: bool,
    pub security_truth_claim: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub digests: CockroachCloudEvidenceDigests,
    pub evidence_digest: Digest,
}

impl CockroachCloudEvidence {
    fn calculate_digest(&self) -> Digest {
        Digest::from_serializable(&EvidenceDigestInput {
            contract_version: &self.contract_version,
            plugin_version: &self.plugin_version,
            service_id: &self.service_id,
            provider_id: &self.provider_id,
            provider_revision: &self.provider_revision,
            provider_provenance: self.provider_provenance,
            connected: self.connected,
            native: self.native,
            first_party: self.first_party,
            scope_digest: &self.scope_digest,
            revision_fence_digest: &self.revision_fence_digest,
            permission_digest: &self.permission_digest,
            query_digest: &self.query_digest,
            request_digest: &self.request_digest,
            state: self.state,
            cluster: &self.cluster,
            health: &self.health,
            settings: &self.settings,
            sql_activity: &self.sql_activity,
            pagination: &self.pagination,
            receipts: &self.receipts,
            failure: &self.failure,
            observed_at: self.observed_at,
            expires_at: self.expires_at,
            review_only: self.review_only,
            health_certification_claim: self.health_certification_claim,
            security_truth_claim: self.security_truth_claim,
            outcome_adopted: self.outcome_adopted,
            work_product_adopted: self.work_product_adopted,
            plugin_version_digest: &self.digests.plugin_version_digest,
            contract_digest: &self.digests.contract_digest,
            provider_digest: &self.digests.provider_digest,
            api_digest: &self.digests.api_digest,
            digest_permission: &self.digests.permission_digest,
            digest_scope: &self.digests.scope_digest,
            digest_revision_fence: &self.digests.revision_fence_digest,
            digest_query: &self.digests.query_digest,
            digest_cluster: &self.digests.cluster_digest,
            digest_health: &self.digests.health_digest,
            digest_settings: &self.digests.settings_digest,
            digest_sql_activity: &self.digests.sql_activity_digest,
            digest_response: &self.digests.response_digest,
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.evidence_digest
    }

    pub fn validate_integrity(
        &self,
        scope: &CockroachCloudScope,
    ) -> Result<(), CockroachCloudResultError> {
        if self.contract_version != CONTRACT_VERSION
            || self.plugin_version != PLUGIN_VERSION
            || self.service_id != SERVICE_ID
            || self.provider_id != PROVIDER_ID
            || self.provider_revision != API_REVISION
            || self.connected
            || self.native
            || self.first_party
            || !self.review_only
            || self.health_certification_claim
            || self.security_truth_claim
            || self.outcome_adopted
            || self.work_product_adopted
            || self.scope_digest != scope.digest()
            || self.revision_fence_digest != scope.revision_fence_digest()
            || self.permission_digest != *scope.permission_digest()
            || self.digests.scope_digest != self.scope_digest
            || self.digests.revision_fence_digest != self.revision_fence_digest
            || self.digests.permission_digest != self.permission_digest
            || self.digests.query_digest != self.query_digest
            || self.digests.plugin_version_digest != plugin_version_digest()
            || self.digests.contract_digest != contract_digest()
            || self.digests.provider_digest != crate::provider_digest()
            || self.digests.api_digest != crate::api_digest()
            || self.digests.evidence_digest != self.evidence_digest
            || self.evidence_digest != self.calculate_digest()
            || self.receipts.len() > usize::from(MAX_PAGES)
            || self.sql_activity.len() > crate::MAX_SQL_ACTIVITY_ENTRIES
            || self.expires_at <= self.observed_at
        {
            return Err(CockroachCloudResultError::EvidenceTampered);
        }
        for receipt in &self.receipts {
            receipt.validate_integrity()?;
        }
        if self
            .sql_activity
            .iter()
            .any(|activity| activity.raw_sql_retained || activity.raw_result_retained)
        {
            return Err(CockroachCloudResultError::EvidenceTampered);
        }
        if self.cluster.as_ref().is_some_and(|cluster| {
            cluster.revision != scope.cluster.revision
                || cluster.cluster_digest != scope.cluster.id.digest()
                || cluster.region_digest != scope.region.id.digest()
                || cluster.database_digest != scope.database.id.digest()
                || cluster.branch_digest != scope.branch.id.digest()
                || !cluster.provider_present
        }) || self.health.as_ref().is_some_and(|health| {
            health.revision != scope.cluster.revision || !health.provider_reported
        }) || self.settings.as_ref().is_some_and(|settings| {
            settings.revision != scope.cluster.revision
                || !settings.provider_reported
                || settings.values_retained
        }) || self.sql_activity.iter().any(|activity| {
            activity.revision != scope.sql_activity.revision
                || activity.raw_sql_retained
                || activity.raw_result_retained
        }) {
            return Err(CockroachCloudResultError::RevisionDrift);
        }
        if self.digests.cluster_digest
            != self.cluster.as_ref().map_or_else(
                || Digest::from_text("cluster-absent"),
                ClusterProjection::digest,
            )
            || self.digests.health_digest
                != self.health.as_ref().map_or_else(
                    || Digest::from_text("health-absent"),
                    HealthProjection::digest,
                )
            || self.digests.settings_digest
                != self.settings.as_ref().map_or_else(
                    || Digest::from_text("settings-absent"),
                    SettingsMetadataProjection::digest,
                )
            || self.digests.sql_activity_digest != Digest::from_serializable(&self.sql_activity)
            || self.digests.response_digest
                != Digest::from_serializable(
                    &self
                        .receipts
                        .iter()
                        .map(ReadReceipt::digest)
                        .collect::<Vec<_>>(),
                )
            || self
                .failure
                .as_ref()
                .is_some_and(|failure| failure.state != self.state)
        {
            return Err(CockroachCloudResultError::EvidenceTampered);
        }
        if !self.receipts.is_empty() {
            validate_bounded_counts(
                self.settings
                    .as_ref()
                    .map_or(0, |settings| usize::from(settings.entry_count)),
                self.sql_activity.len(),
                self.receipts
                    .iter()
                    .map(|receipt| receipt.response_bytes)
                    .max()
                    .unwrap_or(0),
            )?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CockroachCloudProposal {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub scope_digest: Digest,
    pub revision_fence_digest: Digest,
    pub permission_digest: Digest,
    pub registration_digest: Digest,
    pub request_digest: Digest,
    pub evidence_digest: Digest,
    pub state: EvidenceState,
    pub evidence: CockroachCloudEvidence,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub read_only: bool,
    pub proposal_only: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub proposal_digest: Digest,
}

#[derive(Serialize)]
struct ProposalDigestInput<'a> {
    service_id: &'a str,
    provider_id: &'a str,
    consumer_id: &'a str,
    scope_digest: &'a Digest,
    revision_fence_digest: &'a Digest,
    permission_digest: &'a Digest,
    registration_digest: &'a Digest,
    request_digest: &'a Digest,
    evidence_digest: &'a Digest,
    state: EvidenceState,
    connected: bool,
    native: bool,
    first_party: bool,
    read_only: bool,
    proposal_only: bool,
    outcome_adopted: bool,
    work_product_adopted: bool,
}

impl CockroachCloudProposal {
    fn new(evidence: CockroachCloudEvidence, registration: &CockroachCloudRegistration) -> Self {
        let mut proposal = Self {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            scope_digest: evidence.scope_digest.clone(),
            revision_fence_digest: evidence.revision_fence_digest.clone(),
            permission_digest: evidence.permission_digest.clone(),
            registration_digest: registration.registration_digest.clone(),
            request_digest: evidence.request_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            state: evidence.state,
            evidence,
            connected: false,
            native: false,
            first_party: false,
            read_only: true,
            proposal_only: true,
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: Digest::from_text("pending-proposal-digest"),
        };
        proposal.proposal_digest = proposal.calculate_digest();
        proposal
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_serializable(&ProposalDigestInput {
            service_id: &self.service_id,
            provider_id: &self.provider_id,
            consumer_id: &self.consumer_id,
            scope_digest: &self.scope_digest,
            revision_fence_digest: &self.revision_fence_digest,
            permission_digest: &self.permission_digest,
            registration_digest: &self.registration_digest,
            request_digest: &self.request_digest,
            evidence_digest: &self.evidence_digest,
            state: self.state,
            connected: self.connected,
            native: self.native,
            first_party: self.first_party,
            read_only: self.read_only,
            proposal_only: self.proposal_only,
            outcome_adopted: self.outcome_adopted,
            work_product_adopted: self.work_product_adopted,
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.proposal_digest
    }

    pub fn validate_integrity(
        &self,
        scope: &CockroachCloudScope,
    ) -> Result<(), CockroachCloudResultError> {
        if self.proposal_digest != self.calculate_digest()
            || self.service_id != SERVICE_ID
            || self.provider_id != PROVIDER_ID
            || self.consumer_id != CONSUMER_ID
            || self.scope_digest != scope.digest()
            || self.revision_fence_digest != scope.revision_fence_digest()
            || self.permission_digest != *scope.permission_digest()
            || self.evidence_digest != self.evidence.evidence_digest
            || self.request_digest != self.evidence.request_digest
            || self.state != self.evidence.state
            || self.connected
            || self.native
            || self.first_party
            || !self.read_only
            || !self.proposal_only
            || self.outcome_adopted
            || self.work_product_adopted
        {
            Err(CockroachCloudResultError::ProposalTampered)
        } else {
            self.evidence.validate_integrity(scope)
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordDisposition {
    New,
    Replay,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CockroachCloudRecord {
    pub idempotency_digest: Digest,
    pub proposal_digest: Digest,
    pub record_digest: Digest,
    pub disposition: RecordDisposition,
    pub durable: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl CockroachCloudRecord {
    fn new(
        idempotency_digest: Digest,
        proposal: &CockroachCloudProposal,
        disposition: RecordDisposition,
    ) -> Self {
        let record_digest = Digest::from_serializable(&(
            &idempotency_digest,
            &proposal.proposal_digest,
            disposition,
            false,
            false,
            false,
            false,
            false,
        ));
        Self {
            idempotency_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            record_digest,
            disposition,
            durable: false,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        }
    }

    pub fn digest(&self) -> &Digest {
        &self.record_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerificationFailure {
    pub code: String,
    pub digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceVerification {
    pub valid: bool,
    pub state: EvidenceState,
    pub scope_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub requires_human_review: bool,
    pub failure: Option<VerificationFailure>,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationTransition {
    pub previous: RegistrationState,
    pub current: RegistrationState,
    pub registration_revision: u64,
    pub registration_digest: Digest,
    pub reversible: bool,
}

/// Version, provider, permission, secret, and exact scope-bound registration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CockroachCloudRegistration {
    pub registration_id: String,
    pub plugin_id: String,
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_revision: String,
    pub api_revision: String,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub scope_digest: Digest,
    pub revision_fence_digest: Digest,
    pub permission_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: u64,
    pub state: RegistrationState,
    pub registration_digest: Digest,
}

impl CockroachCloudRegistration {
    pub fn new(
        scope: &CockroachCloudScope,
        secret_reference: &SecretReference,
        provider: &CockroachCloudProviderDefinition,
    ) -> Result<Self, CockroachCloudResultError> {
        scope.validate()?;
        provider.validate()?;
        if secret_reference.scope_digest() != &scope.digest()
            || secret_reference.revision() != scope.scope_revision()
            || secret_reference.is_revoked()
        {
            return Err(CockroachCloudResultError::SecretScopeMismatch);
        }
        let mut registration = Self {
            registration_id: "cockroach-cloud-result-registration-1".to_owned(),
            plugin_id: PLUGIN_ID.to_owned(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: provider.provider_id.clone(),
            provider_revision: provider.provider_revision.clone(),
            api_revision: provider.api_revision.clone(),
            provider_digest: provider.provider_digest.clone(),
            api_digest: provider.api_digest.clone(),
            scope_digest: scope.digest(),
            revision_fence_digest: scope.revision_fence_digest(),
            permission_digest: scope.permission_digest().clone(),
            secret_reference_digest: secret_reference.reference_digest().clone(),
            registration_revision: scope.scope_revision().get(),
            state: RegistrationState::Active,
            registration_digest: Digest::from_text("pending-registration-digest"),
        };
        registration.registration_digest = registration.calculate_digest();
        Ok(registration)
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_serializable(&(
            &self.registration_id,
            &self.plugin_id,
            &self.plugin_version,
            &self.contract_version,
            &self.contract_digest,
            &self.provider_id,
            &self.provider_revision,
            &self.api_revision,
            &self.provider_digest,
            &self.api_digest,
            &self.scope_digest,
            &self.revision_fence_digest,
            &self.permission_digest,
            &self.secret_reference_digest,
            self.registration_revision,
            self.state,
        ))
    }

    pub fn validate(
        &self,
        scope: &CockroachCloudScope,
        provider: &CockroachCloudProviderDefinition,
    ) -> Result<(), CockroachCloudResultError> {
        if self.plugin_id != PLUGIN_ID
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.provider_id != provider.provider_id
            || self.provider_revision != provider.provider_revision
            || self.api_revision != API_REVISION
            || self.provider_digest != provider.provider_digest
            || self.api_digest != provider.api_digest
            || self.scope_digest != scope.digest()
            || self.revision_fence_digest != scope.revision_fence_digest()
            || self.permission_digest != *scope.permission_digest()
            || self.registration_revision != scope.scope_revision().get()
            || self.registration_digest != self.calculate_digest()
        {
            Err(CockroachCloudResultError::RegistrationTampered)
        } else {
            Ok(())
        }
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransition, CockroachCloudResultError> {
        if self.state == RegistrationState::Revoked {
            return Err(CockroachCloudResultError::InvalidRegistrationTransition);
        }
        let previous = self.state;
        self.state = RegistrationState::Revoked;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransition {
            previous,
            current: self.state,
            registration_revision: self.registration_revision,
            registration_digest: self.registration_digest.clone(),
            reversible: false,
        })
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransition, CockroachCloudResultError> {
        if self.state != RegistrationState::Active {
            return Err(CockroachCloudResultError::InvalidRegistrationTransition);
        }
        let previous = self.state;
        self.state = RegistrationState::Reversed;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransition {
            previous,
            current: self.state,
            registration_revision: self.registration_revision,
            registration_digest: self.registration_digest.clone(),
            reversible: true,
        })
    }

    pub fn restore(&mut self) -> Result<RegistrationTransition, CockroachCloudResultError> {
        if self.state != RegistrationState::Reversed {
            return Err(CockroachCloudResultError::InvalidRegistrationTransition);
        }
        let previous = self.state;
        self.state = RegistrationState::Active;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransition {
            previous,
            current: self.state,
            registration_revision: self.registration_revision,
            registration_digest: self.registration_digest.clone(),
            reversible: true,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CockroachCloudCapabilities {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub api_revision: String,
    pub operations: Vec<String>,
    pub permissions: Vec<String>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub sql_execution: bool,
    pub cluster_mutation: bool,
    pub branch_mutation: bool,
    pub settings_mutation: bool,
    pub outcome_adoption: bool,
    pub work_product_adoption: bool,
}

/// Service owning the Layer-1 read/proposal/record/verify seam.
pub struct CockroachCloudResultService<T: CockroachCloudTransport> {
    scope: CockroachCloudScope,
    secret_reference: SecretReference,
    provider: CockroachCloudProvider<T>,
    registration: CockroachCloudRegistration,
    records: BTreeMap<Digest, CockroachCloudRecord>,
}

impl<T: CockroachCloudTransport> fmt::Debug for CockroachCloudResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CockroachCloudResultService")
            .field("scope_digest", &self.scope.digest())
            .field("secret_reference", &self.secret_reference)
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl<T: CockroachCloudTransport> CockroachCloudResultService<T> {
    pub fn new(
        provider: CockroachCloudProvider<T>,
        scope: CockroachCloudScope,
        secret_reference: SecretReference,
    ) -> Result<Self, CockroachCloudResultError> {
        scope.validate()?;
        provider.definition().validate()?;
        if secret_reference.scope_digest() != &scope.digest()
            || secret_reference.revision() != scope.scope_revision()
            || secret_reference.is_revoked()
        {
            return Err(CockroachCloudResultError::SecretScopeMismatch);
        }
        let registration =
            CockroachCloudRegistration::new(&scope, &secret_reference, provider.definition())?;
        Ok(Self {
            scope,
            secret_reference,
            provider,
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn from_scope(
        scope: CockroachCloudScope,
        secret_reference: SecretReference,
        provider: CockroachCloudProvider<T>,
    ) -> Result<Self, CockroachCloudResultError> {
        Self::new(provider, scope, secret_reference)
    }

    pub fn definition() -> CockroachCloudCapabilities {
        CockroachCloudCapabilities {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            api_revision: API_REVISION.to_owned(),
            operations: vec![
                "read_cluster_posture".to_owned(),
                "read_health_posture".to_owned(),
                "read_settings_metadata".to_owned(),
                "read_sql_activity_posture".to_owned(),
                "compile_posture_proposal".to_owned(),
                "record_redacted_proposal".to_owned(),
                "verify_posture_proposal".to_owned(),
            ],
            permissions: crate::LAYER1_PERMISSIONS
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            read_only: true,
            proposal_only: true,
            recording_only: true,
            connected: false,
            native: false,
            first_party: false,
            sql_execution: false,
            cluster_mutation: false,
            branch_mutation: false,
            settings_mutation: false,
            outcome_adoption: false,
            work_product_adoption: false,
        }
    }

    pub fn describe_capabilities(&self) -> CockroachCloudCapabilities {
        Self::definition()
    }

    pub fn describe_scope(&self) -> &CockroachCloudScope {
        &self.scope
    }

    pub fn scope(&self) -> &CockroachCloudScope {
        &self.scope
    }

    pub fn provider(&self) -> &CockroachCloudProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut CockroachCloudProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &CockroachCloudRegistration {
        &self.registration
    }

    pub fn register(&self) -> CockroachCloudRegistration {
        self.registration.clone()
    }

    pub fn is_active(&self) -> bool {
        self.registration.is_active()
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn read_bounded(
        &mut self,
        request: &CockroachCloudReadRequest,
        now: u64,
    ) -> Result<CockroachCloudReadResult, CockroachCloudResultError> {
        self.validate_request(request)?;
        if !self.registration.is_active() {
            return Err(match self.registration.state {
                RegistrationState::Revoked => CockroachCloudResultError::RegistrationRevoked,
                RegistrationState::Reversed => CockroachCloudResultError::RegistrationReversed,
                RegistrationState::Active => CockroachCloudResultError::RegistrationTampered,
            });
        }
        if let Err(error) = request.validate_at(now) {
            if error == CockroachCloudResultError::Expired {
                return Ok(self.failure_evidence(
                    request,
                    EvidenceState::Expired,
                    "read_request_expired",
                    None,
                    now,
                ));
            }
            return Err(error);
        }

        let original_request = request.clone();
        let mut current_request = request.clone();
        let mut cluster = None;
        let mut health = None;
        let mut settings = None;
        let mut sql_activity = Vec::new();
        let mut receipts = Vec::new();
        let mut cursor_digests = Vec::new();
        let mut response_digests = Vec::new();
        let mut seen_cursors = BTreeSet::<Digest>::new();
        let mut pages = 0_u16;
        let mut partial = false;

        loop {
            if pages >= original_request.max_pages {
                partial = true;
                break;
            }
            let page = match self.provider.read_page(&current_request) {
                Ok(page) => page,
                Err(error) => {
                    if matches!(error, CockroachCloudTransportError::InvalidResponse) {
                        return Err(CockroachCloudResultError::Provider(error));
                    }
                    let state = transport_error_state(error);
                    let retry_after = match error {
                        CockroachCloudTransportError::RateLimited {
                            retry_after_seconds,
                        } => Some(retry_after_seconds),
                        _ => None,
                    };
                    return Ok(self.failure_evidence(
                        &original_request,
                        state,
                        failure_reason(error),
                        retry_after,
                        now,
                    ));
                }
            };
            pages += 1;
            if page.page != current_request.page() {
                return Err(CockroachCloudResultError::EvidenceTampered);
            }
            if let Some(cursor) = current_request.cursor_digest() {
                if !seen_cursors.insert(cursor.clone()) {
                    return Err(CockroachCloudResultError::RepeatedCursor);
                }
                cursor_digests.push(cursor.clone());
            }
            response_digests.push(page.response_digest.clone());
            if cluster.is_none() {
                cluster = page.cluster.clone();
            }
            if health.is_none() {
                health = page.health.clone();
            }
            if settings.is_none() {
                settings = page.settings.clone();
            }
            sql_activity.extend(page.sql_activity.iter().cloned());
            receipts.push(ReadReceipt::from_page(&page));

            let Some(next_cursor) = page.next_cursor else {
                break;
            };
            if seen_cursors.contains(next_cursor.cursor_digest())
                || next_cursor.page() > original_request.max_pages
            {
                return Err(CockroachCloudResultError::RepeatedCursor);
            }
            if pages >= original_request.max_pages {
                partial = true;
                break;
            }
            current_request = current_request.with_cursor(next_cursor, now)?;
        }

        if sql_activity.len() > crate::MAX_SQL_ACTIVITY_ENTRIES {
            return Err(CockroachCloudResultError::PaginationLimit);
        }
        let state = if partial {
            EvidenceState::Partial
        } else {
            derive_state(cluster.as_ref(), health.as_ref(), settings.as_ref())
        };
        let pagination = PaginationEvidence {
            pages,
            page_size: original_request.page_size,
            complete: !partial,
            partial,
            cursor_digests,
            response_digests,
        };
        Ok(self.build_evidence(
            &original_request,
            state,
            cluster,
            health,
            settings,
            sql_activity,
            pagination,
            receipts,
            None,
            request.observed_at,
        ))
    }

    pub fn read(
        &mut self,
        request: &CockroachCloudReadRequest,
        now: u64,
    ) -> Result<CockroachCloudReadResult, CockroachCloudResultError> {
        self.read_bounded(request, now)
    }

    pub fn read_cluster_posture(
        &mut self,
        request: &CockroachCloudReadRequest,
        now: u64,
    ) -> Result<CockroachCloudReadResult, CockroachCloudResultError> {
        self.read_bounded(request, now)
    }

    pub fn read_health_posture(
        &mut self,
        request: &CockroachCloudReadRequest,
        now: u64,
    ) -> Result<CockroachCloudReadResult, CockroachCloudResultError> {
        self.read_bounded(request, now)
    }

    pub fn read_settings_metadata(
        &mut self,
        request: &CockroachCloudReadRequest,
        now: u64,
    ) -> Result<CockroachCloudReadResult, CockroachCloudResultError> {
        self.read_bounded(request, now)
    }

    pub fn read_sql_activity_posture(
        &mut self,
        request: &CockroachCloudReadRequest,
        now: u64,
    ) -> Result<CockroachCloudReadResult, CockroachCloudResultError> {
        self.read_bounded(request, now)
    }

    pub fn propose(
        &mut self,
        request: &CockroachCloudReadRequest,
        now: u64,
    ) -> Result<CockroachCloudProposal, CockroachCloudResultError> {
        let evidence = self.read_bounded(request, now)?;
        self.compile_proposal(evidence)
    }

    pub fn compile_proposal(
        &self,
        evidence: CockroachCloudEvidence,
    ) -> Result<CockroachCloudProposal, CockroachCloudResultError> {
        if !self.registration.is_active() {
            return Err(match self.registration.state {
                RegistrationState::Revoked => CockroachCloudResultError::RegistrationRevoked,
                RegistrationState::Reversed => CockroachCloudResultError::RegistrationReversed,
                RegistrationState::Active => CockroachCloudResultError::RegistrationTampered,
            });
        }
        evidence.validate_integrity(&self.scope)?;
        if evidence.provider_id != self.provider.definition().provider_id
            || evidence.digests.provider_digest != self.provider.definition().provider_digest
            || evidence.digests.api_digest != self.provider.definition().api_digest
        {
            return Err(CockroachCloudResultError::ProviderDrift);
        }
        Ok(CockroachCloudProposal::new(evidence, &self.registration))
    }

    pub fn record(
        &mut self,
        proposal: &CockroachCloudProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<CockroachCloudRecord, CockroachCloudResultError> {
        proposal.validate_integrity(&self.scope)?;
        self.ensure_registration(proposal)?;
        let idempotency_key = idempotency_key.as_ref();
        if idempotency_key.trim().is_empty()
            || idempotency_key.len() > MAX_IDENTIFIER_BYTES
            || idempotency_key.chars().any(char::is_control)
        {
            return Err(CockroachCloudResultError::InvalidInput("idempotency_key"));
        }
        let idempotency_digest = Digest::from_text(idempotency_key);
        if let Some(existing) = self.records.get(&idempotency_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(CockroachCloudResultError::RecordingConflict);
            }
            let mut replay = existing.clone();
            replay.disposition = RecordDisposition::Replay;
            replay.record_digest = Digest::from_serializable(&(
                &replay.idempotency_digest,
                &replay.proposal_digest,
                replay.disposition,
                false,
                false,
                false,
                false,
                false,
            ));
            return Ok(replay);
        }
        let record =
            CockroachCloudRecord::new(idempotency_digest, proposal, RecordDisposition::New);
        self.provider
            .record_receipt_digest(proposal.evidence.receipts_digest());
        self.records
            .insert(record.idempotency_digest.clone(), record.clone());
        Ok(record)
    }

    pub fn record_redacted_proposal(
        &mut self,
        proposal: &CockroachCloudProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<CockroachCloudRecord, CockroachCloudResultError> {
        self.record(proposal, idempotency_key)
    }

    pub fn verify(&self, proposal: &CockroachCloudProposal, now: u64) -> EvidenceVerification {
        let result = self.verify_strict(proposal, now);
        match result {
            Ok(()) => EvidenceVerification {
                valid: true,
                state: proposal.state,
                scope_digest: proposal.scope_digest.clone(),
                proposal_digest: proposal.proposal_digest.clone(),
                evidence_digest: proposal.evidence_digest.clone(),
                requires_human_review: true,
                failure: None,
                connected: false,
                native: false,
                first_party: false,
            },
            Err(error) => EvidenceVerification {
                valid: false,
                state: EvidenceState::Stale,
                scope_digest: proposal.scope_digest.clone(),
                proposal_digest: proposal.proposal_digest.clone(),
                evidence_digest: proposal.evidence_digest.clone(),
                requires_human_review: true,
                failure: Some(VerificationFailure {
                    code: error.to_string(),
                    digest: Digest::from_text(error.to_string()),
                }),
                connected: false,
                native: false,
                first_party: false,
            },
        }
    }

    pub fn verify_posture_proposal(
        &self,
        proposal: &CockroachCloudProposal,
        now: u64,
    ) -> EvidenceVerification {
        self.verify(proposal, now)
    }

    pub fn verify_strict(
        &self,
        proposal: &CockroachCloudProposal,
        now: u64,
    ) -> Result<(), CockroachCloudResultError> {
        proposal.validate_integrity(&self.scope)?;
        self.ensure_registration(proposal)?;
        if now >= proposal.evidence.expires_at {
            return Err(CockroachCloudResultError::Expired);
        }
        if !self
            .provider
            .verify_receipt_digest(&proposal.evidence.receipts_digest())
            && !proposal.evidence.receipts.is_empty()
        {
            return Err(CockroachCloudResultError::ReceiptTampered);
        }
        Ok(())
    }

    pub fn verify_evidence(
        &self,
        evidence: &CockroachCloudEvidence,
        now: u64,
    ) -> Result<(), CockroachCloudResultError> {
        evidence.validate_integrity(&self.scope)?;
        if now >= evidence.expires_at {
            Err(CockroachCloudResultError::Expired)
        } else {
            Ok(())
        }
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<RegistrationTransition, CockroachCloudResultError> {
        self.registration.revoke()
    }

    pub fn reverse_registration(
        &mut self,
    ) -> Result<RegistrationTransition, CockroachCloudResultError> {
        self.registration.reverse()
    }

    pub fn restore_registration(
        &mut self,
    ) -> Result<RegistrationTransition, CockroachCloudResultError> {
        self.registration.restore()
    }

    fn validate_request(
        &self,
        request: &CockroachCloudReadRequest,
    ) -> Result<(), CockroachCloudResultError> {
        if request.scope != self.scope
            || request.scope.digest() != self.registration.scope_digest
            || request.scope.revision_fence_digest() != self.registration.revision_fence_digest
            || request.scope.permission_digest() != &self.registration.permission_digest
            || self.registration.secret_reference_digest
                != *self.secret_reference.reference_digest()
        {
            return Err(CockroachCloudResultError::ScopeMismatch);
        }
        self.registration
            .validate(&self.scope, self.provider.definition())
    }

    fn ensure_registration(
        &self,
        proposal: &CockroachCloudProposal,
    ) -> Result<(), CockroachCloudResultError> {
        if !self.registration.is_active() {
            return Err(match self.registration.state {
                RegistrationState::Revoked => CockroachCloudResultError::RegistrationRevoked,
                RegistrationState::Reversed => CockroachCloudResultError::RegistrationReversed,
                RegistrationState::Active => CockroachCloudResultError::RegistrationTampered,
            });
        }
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.scope_digest != self.registration.scope_digest
            || proposal.permission_digest != self.registration.permission_digest
            || self.registration.secret_reference_digest
                != *self.secret_reference.reference_digest()
        {
            return Err(CockroachCloudResultError::RegistrationTampered);
        }
        self.registration
            .validate(&self.scope, self.provider.definition())
    }

    fn build_evidence(
        &self,
        request: &CockroachCloudReadRequest,
        state: EvidenceState,
        cluster: Option<ClusterProjection>,
        health: Option<HealthProjection>,
        settings: Option<SettingsMetadataProjection>,
        sql_activity: Vec<SqlActivityProjection>,
        pagination: PaginationEvidence,
        receipts: Vec<ReadReceipt>,
        failure: Option<FailureEvidence>,
        _now: u64,
    ) -> CockroachCloudEvidence {
        let cluster_digest = cluster.as_ref().map_or_else(
            || Digest::from_text("cluster-absent"),
            ClusterProjection::digest,
        );
        let health_digest = health.as_ref().map_or_else(
            || Digest::from_text("health-absent"),
            HealthProjection::digest,
        );
        let settings_digest = settings.as_ref().map_or_else(
            || Digest::from_text("settings-absent"),
            SettingsMetadataProjection::digest,
        );
        let sql_activity_digest = Digest::from_serializable(&sql_activity);
        let response_digest = Digest::from_serializable(
            &receipts.iter().map(ReadReceipt::digest).collect::<Vec<_>>(),
        );
        let mut evidence = CockroachCloudEvidence {
            contract_version: CONTRACT_VERSION.to_owned(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision: API_REVISION.to_owned(),
            provider_provenance: self.provider.provenance(),
            connected: false,
            native: false,
            first_party: false,
            scope_digest: self.scope.digest(),
            revision_fence_digest: self.scope.revision_fence_digest(),
            permission_digest: self.scope.permission_digest().clone(),
            query_digest: request.query_digest.clone(),
            request_digest: request.request_digest.clone(),
            state,
            cluster,
            health,
            settings,
            sql_activity,
            pagination,
            receipts,
            failure,
            observed_at: request.observed_at,
            expires_at: request.expires_at,
            review_only: true,
            health_certification_claim: false,
            security_truth_claim: false,
            outcome_adopted: false,
            work_product_adopted: false,
            digests: CockroachCloudEvidenceDigests {
                plugin_version_digest: plugin_version_digest(),
                contract_digest: contract_digest(),
                provider_digest: self.provider.definition().provider_digest.clone(),
                api_digest: self.provider.definition().api_digest.clone(),
                permission_digest: self.scope.permission_digest().clone(),
                scope_digest: self.scope.digest(),
                revision_fence_digest: self.scope.revision_fence_digest(),
                query_digest: request.query_digest.clone(),
                cluster_digest,
                health_digest,
                settings_digest,
                sql_activity_digest,
                response_digest,
                evidence_digest: Digest::from_text("pending-evidence-digest"),
            },
            evidence_digest: Digest::from_text("pending-evidence-digest"),
        };
        let digest = evidence.calculate_digest();
        evidence.evidence_digest = digest.clone();
        evidence.digests.evidence_digest = digest;
        evidence
    }

    fn failure_evidence(
        &self,
        request: &CockroachCloudReadRequest,
        state: EvidenceState,
        reason: &str,
        retry_after_seconds: Option<u32>,
        _now: u64,
    ) -> CockroachCloudEvidence {
        let mut pagination = PaginationEvidence::empty(request);
        pagination.complete = false;
        self.build_evidence(
            request,
            state,
            None,
            None,
            None,
            Vec::new(),
            pagination,
            Vec::new(),
            Some(FailureEvidence::new(state, reason, retry_after_seconds)),
            request.observed_at,
        )
    }
}

pub type CockroachCloudReadResult = CockroachCloudEvidence;

impl CockroachCloudEvidence {
    fn receipts_digest(&self) -> Digest {
        Digest::from_serializable(
            &self
                .receipts
                .iter()
                .map(ReadReceipt::digest)
                .collect::<Vec<_>>(),
        )
    }
}

fn derive_state(
    cluster: Option<&ClusterProjection>,
    health: Option<&HealthProjection>,
    settings: Option<&SettingsMetadataProjection>,
) -> EvidenceState {
    if cluster.is_none() && health.is_none() && settings.is_none() {
        return EvidenceState::Absent;
    }
    if cluster.is_some_and(|cluster| matches!(cluster.state, crate::ClusterState::Failed))
        || health.is_some_and(|health| {
            matches!(health.posture, crate::HealthPosture::ProviderUnavailable)
        })
    {
        return EvidenceState::Unavailable;
    }
    if health.is_some_and(|health| matches!(health.posture, crate::HealthPosture::ProviderDegraded))
        || settings
            .is_some_and(|settings| matches!(settings.posture, crate::SettingsPosture::Changed))
    {
        return EvidenceState::Degraded;
    }
    EvidenceState::Healthy
}

fn failure_reason(error: CockroachCloudTransportError) -> &'static str {
    match error {
        CockroachCloudTransportError::BlockedEnv => "blocked_env",
        CockroachCloudTransportError::NoRecordedPage => "no_recorded_page",
        CockroachCloudTransportError::InvalidResponse => "invalid_response",
        CockroachCloudTransportError::Absent => "resource_absent",
        CockroachCloudTransportError::Denied => "read_denied",
        CockroachCloudTransportError::Partial => "provider_partial",
        CockroachCloudTransportError::AccessLoss => "access_loss",
        CockroachCloudTransportError::RateLimited { .. } => "rate_limited",
        CockroachCloudTransportError::ProviderUnknown => "provider_unknown",
        CockroachCloudTransportError::TimedOut => "timed_out",
    }
}

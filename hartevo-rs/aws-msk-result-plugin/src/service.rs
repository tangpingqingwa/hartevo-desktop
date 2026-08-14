//! Bounded AWS MSK read, proposal, recording, and integrity-verification service.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::Serialize;
use thiserror::Error;

use crate::{
    AWS_MSK_CONTRACT_VERSION, AWS_MSK_PLUGIN_VERSION, contract_digest,
    model::{
        AwsMskEvidence, AwsMskReadOperation, AwsMskReadRequest, AwsMskScope, ClusterState,
        ConfigurationProjection, Digest, MskClusterObservation, MskConfigurationObservation,
        MskOperationObservation, OperationState, PartialReason, PermissionAction, PermissionFence,
        ProviderErrorEvidence, ProviderRevision, ReadinessState, Revision, SecretReference,
        TransportError, TransportProvenance, sort_clusters, sort_operations,
    },
    provider::{
        AwsMskProvider, AwsMskProviderError, AwsMskProviderIdentity, AwsMskTransport,
        is_access_loss,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RegistrationError {
    #[error("AWS MSK registration is invalid: {0}")]
    Model(#[from] crate::model::ModelError),
    #[error("AWS MSK registration is already revoked")]
    AlreadyRevoked,
    #[error("AWS MSK registration revision overflowed")]
    RevisionOverflow,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsMskServiceError {
    #[error("AWS MSK service model error: {0}")]
    Model(#[from] crate::model::ModelError),
    #[error("AWS MSK provider error: {0}")]
    Provider(#[from] AwsMskProviderError),
    #[error("AWS MSK registration is revoked")]
    RegistrationRevoked,
    #[error("AWS MSK registration has drifted: {0}")]
    RegistrationDrift(String),
    #[error("AWS MSK scope or permission fence mismatch: {0}")]
    ScopeMismatch(String),
    #[error("AWS MSK evidence is stale or tampered")]
    EvidenceTampered,
    #[error("AWS MSK proposal is stale or tampered")]
    ProposalTampered,
    #[error("AWS MSK record is stale or tampered")]
    RecordTampered,
    #[error("AWS MSK registration lifecycle error: {0}")]
    Registration(#[from] RegistrationError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsMskCapabilities {
    pub service_id: &'static str,
    pub provider_id: &'static str,
    pub operations: [&'static str; 7],
    pub allowlisted_api_operations: [&'static str; 4],
    pub allowlisted_methods: [&'static str; 1],
    pub read_only: bool,
    pub proposal_only: bool,
    pub live_execution: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub external_writes: bool,
    pub raw_configuration_properties: bool,
    pub bootstrap_endpoints: bool,
    pub topic_record_authority: bool,
    pub certification_authority: bool,
    pub outcome_authority: bool,
}

impl AwsMskCapabilities {
    pub const fn layer_one() -> Self {
        Self {
            service_id: crate::AWS_MSK_SERVICE_ID,
            provider_id: crate::AWS_MSK_PROVIDER_ID,
            operations: [
                "describe_capabilities",
                "register",
                "revoke_registration",
                "read_bounded",
                "propose",
                "record",
                "verify",
            ],
            allowlisted_api_operations: [
                "ListClustersV2",
                "DescribeClusterV2",
                "DescribeConfigurationRevision",
                "ListClusterOperations",
            ],
            allowlisted_methods: ["GET"],
            read_only: true,
            proposal_only: true,
            live_execution: false,
            connected: false,
            native: false,
            first_party: false,
            external_writes: false,
            raw_configuration_properties: false,
            bootstrap_endpoints: false,
            topic_record_authority: false,
            certification_authority: false,
            outcome_authority: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsMskRegistration {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: crate::model::ProviderId,
    pub provider_version: String,
    pub provider_revision: ProviderRevision,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub cluster_revision: Revision,
    pub configuration_revision: Revision,
    pub operation_scope_digest: Digest,
    pub evidence_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: Revision,
    pub state: RegistrationState,
    pub registration_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationBody<'a> {
    plugin_version: &'a str,
    contract_version: &'a str,
    contract_digest: &'a Digest,
    provider_id: &'a crate::model::ProviderId,
    provider_version: &'a str,
    provider_revision: &'a ProviderRevision,
    provider_digest: &'a Digest,
    api_digest: &'a Digest,
    permission_digest: &'a Digest,
    scope_digest: &'a Digest,
    cluster_revision: Revision,
    configuration_revision: Revision,
    operation_scope_digest: &'a Digest,
    evidence_digest: &'a Digest,
    secret_reference_digest: &'a Digest,
    registration_revision: Revision,
    state: RegistrationState,
}

impl AwsMskRegistration {
    fn new(
        scope: &AwsMskScope,
        secret_reference: &SecretReference,
        provider: &AwsMskProviderIdentity,
    ) -> Result<Self, RegistrationError> {
        let evidence_digest = Digest::from_parts(
            "hartevo-aws-msk-evidence-policy/v1",
            &[
                crate::AWS_MSK_CONTRACT_VERSION.to_owned(),
                crate::model::MAX_RESPONSE_BYTES.to_string(),
                crate::model::MAX_PAGES.to_string(),
                crate::model::PAGE_SIZE.to_string(),
                crate::model::MAX_CLUSTERS.to_string(),
                crate::model::MAX_OPERATIONS.to_string(),
                "bootstrap-endpoints-excluded".to_owned(),
                "kafka-records-excluded".to_owned(),
                "raw-operation-messages-excluded".to_owned(),
            ],
        );
        let mut registration = Self {
            plugin_version: AWS_MSK_PLUGIN_VERSION.to_owned(),
            contract_version: AWS_MSK_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: provider.provider_id.clone(),
            provider_version: provider.version.clone(),
            provider_revision: provider.api_revision.clone(),
            provider_digest: provider.provider_digest.clone(),
            api_digest: provider.api_digest.clone(),
            permission_digest: scope.permission_digest.clone(),
            scope_digest: scope.digest(),
            cluster_revision: scope.cluster.revision,
            configuration_revision: scope.configuration.revision,
            operation_scope_digest: crate::model::digest_serialized(&scope.operations),
            evidence_digest,
            secret_reference_digest: secret_reference.digest().clone(),
            registration_revision: Revision::new(1)?,
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
        crate::model::digest_serialized(&RegistrationBody {
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
            cluster_revision: self.cluster_revision,
            configuration_revision: self.configuration_revision,
            operation_scope_digest: &self.operation_scope_digest,
            evidence_digest: &self.evidence_digest,
            secret_reference_digest: &self.secret_reference_digest,
            registration_revision: self.registration_revision,
            state: self.state,
        })
    }

    pub fn validate(
        &self,
        scope: &AwsMskScope,
        secret_reference: &SecretReference,
        provider: &AwsMskProviderIdentity,
    ) -> Result<(), RegistrationError> {
        if self.plugin_version != AWS_MSK_PLUGIN_VERSION
            || self.contract_version != AWS_MSK_CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.provider_id != provider.provider_id
            || self.provider_version != provider.version
            || self.provider_revision != provider.api_revision
            || self.provider_digest != provider.provider_digest
            || self.api_digest != provider.api_digest
            || self.permission_digest != scope.permission_digest
            || self.scope_digest != scope.digest()
            || self.cluster_revision != scope.cluster.revision
            || self.configuration_revision != scope.configuration.revision
            || self.operation_scope_digest != crate::model::digest_serialized(&scope.operations)
            || self.secret_reference_digest != *secret_reference.digest()
            || self.registration_digest != self.recomputed_digest()
        {
            return Err(RegistrationError::Model(
                crate::model::ModelError::ScopeMismatch {
                    field: "registration digest binding",
                },
            ));
        }
        Ok(())
    }

    fn revoke(&mut self) -> Result<(), RegistrationError> {
        if self.state == RegistrationState::Revoked {
            return Err(RegistrationError::AlreadyRevoked);
        }
        let next = self
            .registration_revision
            .get()
            .checked_add(1)
            .ok_or(RegistrationError::RevisionOverflow)?;
        self.registration_revision = Revision::new(next)?;
        self.state = RegistrationState::Revoked;
        self.registration_digest = self.recomputed_digest();
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsMskReadResult {
    pub evidence: AwsMskEvidence,
    pub page_digests: Vec<Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsMskProposal {
    pub operation: AwsMskReadOperation,
    pub state: ReadinessState,
    pub evidence: AwsMskEvidence,
    pub proposed_at: DateTime<Utc>,
    pub registration_digest: Digest,
    pub proposal_digest: Digest,
    pub read_only: bool,
    pub live_execution: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub certification_claim: bool,
    pub adopted_outcome: bool,
    pub work_product_adoption: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProposalBody<'a> {
    operation: AwsMskReadOperation,
    state: ReadinessState,
    evidence: &'a AwsMskEvidence,
    proposed_at: &'a DateTime<Utc>,
    registration_digest: &'a Digest,
    read_only: bool,
    live_execution: bool,
    connected: bool,
    native: bool,
    first_party: bool,
    certification_claim: bool,
    adopted_outcome: bool,
    work_product_adoption: bool,
}

impl AwsMskProposal {
    fn new(
        operation: AwsMskReadOperation,
        evidence: AwsMskEvidence,
        proposed_at: DateTime<Utc>,
        registration_digest: Digest,
    ) -> Self {
        let mut proposal = Self {
            operation,
            state: evidence.state,
            evidence,
            proposed_at,
            registration_digest,
            proposal_digest: Digest::zero(),
            read_only: true,
            live_execution: false,
            connected: false,
            native: false,
            first_party: false,
            certification_claim: false,
            adopted_outcome: false,
            work_product_adoption: false,
        };
        proposal.proposal_digest = proposal.recomputed_digest();
        proposal
    }

    pub fn recomputed_digest(&self) -> Digest {
        crate::model::digest_serialized(&ProposalBody {
            operation: self.operation,
            state: self.state,
            evidence: &self.evidence,
            proposed_at: &self.proposed_at,
            registration_digest: &self.registration_digest,
            read_only: self.read_only,
            live_execution: self.live_execution,
            connected: self.connected,
            native: self.native,
            first_party: self.first_party,
            certification_claim: self.certification_claim,
            adopted_outcome: self.adopted_outcome,
            work_product_adoption: self.work_product_adoption,
        })
    }

    pub fn validate(&self) -> Result<(), AwsMskServiceError> {
        self.evidence
            .validate()
            .map_err(|_| AwsMskServiceError::EvidenceTampered)?;
        if self.operation != self.evidence.operation
            || self.state != self.evidence.state
            || !self.read_only
            || self.live_execution
            || self.connected
            || self.native
            || self.first_party
            || self.certification_claim
            || self.adopted_outcome
            || self.work_product_adoption
            || self.proposal_digest != self.recomputed_digest()
        {
            return Err(AwsMskServiceError::ProposalTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsMskRecordReceipt {
    pub recorded: bool,
    pub recorded_at: DateTime<Utc>,
    pub state: ReadinessState,
    pub operation: AwsMskReadOperation,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub retained_cluster_count: usize,
    pub retained_operation_count: usize,
    pub raw_provider_payload_retained: bool,
    pub durable_receipt: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub receipt_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecordBody<'a> {
    recorded: bool,
    recorded_at: &'a DateTime<Utc>,
    state: ReadinessState,
    operation: AwsMskReadOperation,
    proposal_digest: &'a Digest,
    evidence_digest: &'a Digest,
    registration_digest: &'a Digest,
    scope_digest: &'a Digest,
    retained_cluster_count: usize,
    retained_operation_count: usize,
    raw_provider_payload_retained: bool,
    durable_receipt: bool,
    connected: bool,
    native: bool,
    first_party: bool,
}

impl AwsMskRecordReceipt {
    fn new(proposal: &AwsMskProposal, recorded_at: DateTime<Utc>) -> Self {
        let mut receipt = Self {
            recorded: true,
            recorded_at,
            state: proposal.state,
            operation: proposal.operation,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            scope_digest: proposal.evidence.scope_digest.clone(),
            retained_cluster_count: proposal.evidence.clusters.len()
                + usize::from(proposal.evidence.cluster.is_some()),
            retained_operation_count: proposal.evidence.operations.len(),
            raw_provider_payload_retained: false,
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
        crate::model::digest_serialized(&RecordBody {
            recorded: self.recorded,
            recorded_at: &self.recorded_at,
            state: self.state,
            operation: self.operation,
            proposal_digest: &self.proposal_digest,
            evidence_digest: &self.evidence_digest,
            registration_digest: &self.registration_digest,
            scope_digest: &self.scope_digest,
            retained_cluster_count: self.retained_cluster_count,
            retained_operation_count: self.retained_operation_count,
            raw_provider_payload_retained: self.raw_provider_payload_retained,
            durable_receipt: self.durable_receipt,
            connected: self.connected,
            native: self.native,
            first_party: self.first_party,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsMskVerifiedRecord {
    pub verified: bool,
    pub state: ReadinessState,
    pub operation: AwsMskReadOperation,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub verification_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub adopted_outcome: bool,
    pub work_product_adoption: bool,
}

#[derive(Clone)]
pub struct AwsMskService<T>
where
    T: AwsMskTransport,
{
    scope: AwsMskScope,
    permission: PermissionFence,
    secret_reference: SecretReference,
    provider: AwsMskProvider<T>,
    registration: AwsMskRegistration,
}

impl<T> fmt::Debug for AwsMskService<T>
where
    T: AwsMskTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsMskService")
            .field("scope_digest", &self.scope.digest())
            .field("permission_digest", &self.permission.digest())
            .field("secret_reference", &self.secret_reference)
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .finish()
    }
}

impl<T> AwsMskService<T>
where
    T: AwsMskTransport,
{
    pub fn register(
        scope: AwsMskScope,
        secret_reference: SecretReference,
        permission: PermissionFence,
        provider: AwsMskProvider<T>,
    ) -> Result<Self, AwsMskServiceError> {
        Self::new(scope, secret_reference, permission, provider)
    }

    pub fn new(
        scope: AwsMskScope,
        secret_reference: SecretReference,
        permission: PermissionFence,
        provider: AwsMskProvider<T>,
    ) -> Result<Self, AwsMskServiceError> {
        scope.validate()?;
        if scope.permission_digest != permission.digest() {
            return Err(AwsMskServiceError::ScopeMismatch(
                "permission digest".to_owned(),
            ));
        }
        for action in [
            PermissionAction::ListClustersV2,
            PermissionAction::DescribeClusterV2,
            PermissionAction::DescribeConfigurationRevision,
            PermissionAction::ListClusterOperations,
        ] {
            if !permission.allows(action) {
                return Err(AwsMskServiceError::ScopeMismatch(format!(
                    "permission action {}",
                    action.api_name()
                )));
            }
        }
        if secret_reference.signing_region() != &scope.region
            || secret_reference.scope_digest() != &scope.digest()
        {
            return Err(AwsMskServiceError::ScopeMismatch(
                "SigV4 secret reference region or scope digest".to_owned(),
            ));
        }
        if provider.identity().connected
            || provider.identity().native
            || provider.identity().first_party
        {
            return Err(AwsMskServiceError::ScopeMismatch(
                "Layer-1 provider authority flags".to_owned(),
            ));
        }
        let registration = AwsMskRegistration::new(&scope, &secret_reference, provider.identity())?;
        Ok(Self {
            scope,
            permission,
            secret_reference,
            provider,
            registration,
        })
    }

    pub const fn describe_capabilities() -> AwsMskCapabilities {
        AwsMskCapabilities::layer_one()
    }

    pub fn scope(&self) -> &AwsMskScope {
        &self.scope
    }

    pub fn permission(&self) -> &PermissionFence {
        &self.permission
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn provider(&self) -> &AwsMskProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsMskProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &AwsMskRegistration {
        &self.registration
    }

    pub fn is_active(&self) -> bool {
        self.registration.is_active()
    }

    pub fn revoke_registration(&mut self) -> Result<(), AwsMskServiceError> {
        self.registration.revoke()?;
        Ok(())
    }

    pub fn read(
        &mut self,
        request: AwsMskReadRequest,
    ) -> Result<AwsMskReadResult, AwsMskServiceError> {
        self.ensure_active_and_bound()?;
        request.validate_against(&self.scope, &self.permission)?;

        let mut current_request = request.clone();
        let mut clusters = Vec::new();
        let mut cluster = None;
        let mut configuration = None;
        let mut operations = Vec::new();
        let mut page_digests = Vec::new();
        let mut provider_errors = Vec::new();
        let mut seen_markers = BTreeSet::new();
        let mut seen_operations = BTreeSet::new();
        let mut page_count = 0_u16;
        let mut request_count = 0_u16;
        let mut retry_count = 0_u8;
        let mut consecutive_retries = 0_u8;
        let mut response_bytes = 0_usize;
        let mut partial_reason = None;
        let mut truncated = false;
        let mut terminal_state = None;

        loop {
            if request_count >= crate::model::MAX_REQUESTS_PER_READ {
                partial_reason = Some(PartialReason::PageBudget);
                truncated = true;
                break;
            }
            if let Some(marker) = &current_request.marker
                && marker.is_expired(Utc::now())
            {
                partial_reason = Some(PartialReason::MarkerExpired);
                truncated = true;
                break;
            }
            request_count += 1;
            match self.provider.read(&current_request) {
                Ok(page) => {
                    if page.page_number != page_count + 1 {
                        return Err(AwsMskServiceError::Provider(
                            AwsMskProviderError::PageBinding,
                        ));
                    }
                    response_bytes = response_bytes.saturating_add(page.response_bytes);
                    if response_bytes > current_request.max_response_bytes {
                        partial_reason = Some(PartialReason::ResponseTooLarge);
                        truncated = true;
                        break;
                    }
                    page_count += 1;
                    page_digests.push(page.page_digest.clone());
                    match page.operation {
                        AwsMskReadOperation::ListClustersV2 => {
                            let mut page_clusters = Vec::new();
                            for observed in page.clusters {
                                match self.validate_cluster(&observed) {
                                    Ok(()) => page_clusters.push(observed),
                                    Err(reason) => {
                                        partial_reason.get_or_insert(reason);
                                        truncated = true;
                                    }
                                }
                            }
                            let remaining = usize::from(current_request.max_items)
                                .saturating_sub(clusters.len());
                            clusters.extend(page_clusters.into_iter().take(remaining));
                            if clusters.len() >= usize::from(current_request.max_items) {
                                partial_reason.get_or_insert(PartialReason::PageBudget);
                                truncated = true;
                                break;
                            }
                        }
                        AwsMskReadOperation::DescribeClusterV2 => {
                            if let Some(observed) = page.cluster {
                                match self.validate_cluster(&observed) {
                                    Ok(()) => cluster = Some(observed),
                                    Err(reason) => {
                                        partial_reason = Some(reason);
                                        truncated = true;
                                        break;
                                    }
                                }
                            }
                        }
                        AwsMskReadOperation::DescribeConfigurationRevision => {
                            if let Some(observed) = page.configuration {
                                match self.validate_configuration(&observed) {
                                    Ok(()) => configuration = Some(observed),
                                    Err(reason) => {
                                        partial_reason = Some(reason);
                                        truncated = true;
                                        break;
                                    }
                                }
                            }
                        }
                        AwsMskReadOperation::ListClusterOperations => {
                            for observed in page.operations {
                                match self.validate_operation(&observed) {
                                    Ok(()) => {
                                        if !seen_operations.insert(observed.id.clone()) {
                                            partial_reason.get_or_insert(
                                                PartialReason::OperationRevisionDrift,
                                            );
                                            truncated = true;
                                        } else if operations.len()
                                            < usize::from(current_request.max_items)
                                        {
                                            operations.push(observed);
                                        } else {
                                            partial_reason.get_or_insert(PartialReason::PageBudget);
                                            truncated = true;
                                        }
                                    }
                                    Err(reason) => {
                                        partial_reason.get_or_insert(reason);
                                        truncated = true;
                                    }
                                }
                            }
                            if operations.len() >= usize::from(current_request.max_items) {
                                break;
                            }
                        }
                    }
                    consecutive_retries = 0;
                    let Some(marker) = page.next_marker else {
                        break;
                    };
                    if !seen_markers.insert(marker.token_digest().clone()) {
                        partial_reason = Some(PartialReason::MarkerReplay);
                        truncated = true;
                        break;
                    }
                    if page_count >= current_request.max_pages {
                        partial_reason = Some(PartialReason::PageBudget);
                        truncated = true;
                        break;
                    }
                    current_request = current_request.with_marker(Some(marker))?;
                }
                Err(AwsMskProviderError::Transport(error)) => {
                    provider_errors.push(error.evidence());
                    if matches!(error, TransportError::MarkerExpired) {
                        partial_reason = Some(PartialReason::MarkerExpired);
                        truncated = true;
                        break;
                    }
                    if error.retryable() && consecutive_retries < current_request.max_retries {
                        consecutive_retries += 1;
                        retry_count += 1;
                        continue;
                    }
                    if is_access_loss(&error) {
                        terminal_state = Some(ReadinessState::AccessLoss);
                    } else if matches!(error, TransportError::Conflict) {
                        terminal_state = Some(ReadinessState::Partial);
                        partial_reason = Some(PartialReason::ProviderConflict);
                    } else {
                        terminal_state = Some(ReadinessState::ProviderUnknown);
                    }
                    break;
                }
                Err(error) => return Err(error.into()),
            }
        }

        sort_clusters(&mut clusters);
        sort_operations(&mut operations);
        if page_count == 0 && terminal_state.is_none() && partial_reason.is_none() {
            terminal_state = Some(ReadinessState::InsufficientData);
        }
        let (cluster_readiness, configuration_readiness, operation_readiness) =
            Self::project_readiness(
                &clusters,
                cluster.as_ref(),
                configuration.as_ref(),
                &operations,
                partial_reason,
                terminal_state,
            );
        let state = terminal_state.unwrap_or_else(|| {
            aggregate_readiness(
                cluster_readiness,
                configuration_readiness,
                operation_readiness,
                partial_reason,
                page_count,
            )
        });
        let evidence = AwsMskEvidence::new(
            request.operation,
            state,
            cluster_readiness,
            configuration_readiness,
            operation_readiness,
            clusters,
            cluster,
            configuration,
            operations,
            partial_reason,
            page_count,
            request_count,
            retry_count,
            truncated,
            request.query_digest(),
            self.scope.digest(),
            self.permission.digest(),
            self.scope.cluster.revision,
            self.scope.configuration.revision,
            crate::model::digest_serialized(&self.scope.operations),
            self.provider.identity().provider_digest.clone(),
            self.provider.identity().api_revision.clone(),
            self.provider.identity().api_digest.clone(),
            contract_digest(),
            page_digests.clone(),
            provider_errors,
            self.provider.identity().provenance,
        );
        Ok(AwsMskReadResult {
            evidence,
            page_digests,
        })
    }

    pub fn read_bounded(
        &mut self,
        request: AwsMskReadRequest,
    ) -> Result<AwsMskReadResult, AwsMskServiceError> {
        self.read(request)
    }

    pub fn read_list_clusters(
        &mut self,
        bounds: crate::model::ReadBounds,
    ) -> Result<AwsMskReadResult, AwsMskServiceError> {
        self.read(AwsMskReadRequest::list_clusters(&self.scope, bounds)?)
    }

    pub fn read_describe_cluster(
        &mut self,
        bounds: crate::model::ReadBounds,
    ) -> Result<AwsMskReadResult, AwsMskServiceError> {
        self.read(AwsMskReadRequest::describe_cluster(&self.scope, bounds)?)
    }

    pub fn read_describe_configuration_revision(
        &mut self,
        bounds: crate::model::ReadBounds,
    ) -> Result<AwsMskReadResult, AwsMskServiceError> {
        self.read(AwsMskReadRequest::describe_configuration_revision(
            &self.scope,
            bounds,
        )?)
    }

    pub fn read_list_cluster_operations(
        &mut self,
        bounds: crate::model::ReadBounds,
    ) -> Result<AwsMskReadResult, AwsMskServiceError> {
        self.read(AwsMskReadRequest::list_cluster_operations(
            &self.scope,
            bounds,
        )?)
    }

    pub fn propose(
        &mut self,
        request: AwsMskReadRequest,
        proposed_at: DateTime<Utc>,
    ) -> Result<AwsMskProposal, AwsMskServiceError> {
        let operation = request.operation;
        let result = self.read(request)?;
        Ok(AwsMskProposal::new(
            operation,
            result.evidence,
            proposed_at,
            self.registration.registration_digest.clone(),
        ))
    }

    pub fn record(
        &self,
        proposal: &AwsMskProposal,
    ) -> Result<AwsMskRecordReceipt, AwsMskServiceError> {
        self.record_at(proposal, Utc::now())
    }

    pub fn record_at(
        &self,
        proposal: &AwsMskProposal,
        recorded_at: DateTime<Utc>,
    ) -> Result<AwsMskRecordReceipt, AwsMskServiceError> {
        self.ensure_active_and_bound()?;
        self.verify_proposal(proposal)?;
        Ok(AwsMskRecordReceipt::new(proposal, recorded_at))
    }

    pub fn verify(
        &self,
        receipt: &AwsMskRecordReceipt,
    ) -> Result<AwsMskVerifiedRecord, AwsMskServiceError> {
        self.ensure_active_and_bound()?;
        if !receipt.recorded
            || receipt.registration_digest != self.registration.registration_digest
            || receipt.scope_digest != self.scope.digest()
            || receipt.connected
            || receipt.native
            || receipt.first_party
            || receipt.durable_receipt
            || receipt.raw_provider_payload_retained
            || receipt.receipt_digest != receipt.recomputed_digest()
        {
            return Err(AwsMskServiceError::RecordTampered);
        }
        let verification_digest = Digest::from_parts(
            "hartevo-aws-msk-verified-record/v1",
            &[
                receipt.receipt_digest.to_string(),
                self.registration.registration_digest.to_string(),
                self.scope.digest().to_string(),
            ],
        );
        Ok(AwsMskVerifiedRecord {
            verified: true,
            state: receipt.state,
            operation: receipt.operation,
            proposal_digest: receipt.proposal_digest.clone(),
            evidence_digest: receipt.evidence_digest.clone(),
            registration_digest: receipt.registration_digest.clone(),
            verification_digest,
            connected: false,
            native: false,
            first_party: false,
            adopted_outcome: false,
            work_product_adoption: false,
        })
    }

    pub fn verify_proposal(&self, proposal: &AwsMskProposal) -> Result<(), AwsMskServiceError> {
        self.ensure_active_and_bound()?;
        proposal.validate()?;
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.evidence.scope_digest != self.scope.digest()
            || proposal.evidence.permission_digest != self.permission.digest()
            || proposal.evidence.cluster_revision != self.scope.cluster.revision
            || proposal.evidence.configuration_revision != self.scope.configuration.revision
            || proposal.evidence.operation_scope_digest
                != crate::model::digest_serialized(&self.scope.operations)
            || proposal.evidence.provider_digest != self.provider.identity().provider_digest
            || proposal.evidence.provider_revision != self.provider.identity().api_revision
            || proposal.evidence.api_digest != self.provider.identity().api_digest
            || proposal.evidence.contract_digest != contract_digest()
            || proposal.evidence.query_digest == Digest::zero()
        {
            return Err(AwsMskServiceError::ProposalTampered);
        }
        Ok(())
    }

    fn ensure_active_and_bound(&self) -> Result<(), AwsMskServiceError> {
        if !self.registration.is_active() {
            return Err(AwsMskServiceError::RegistrationRevoked);
        }
        self.registration
            .validate(
                &self.scope,
                &self.secret_reference,
                self.provider.identity(),
            )
            .map_err(|error| AwsMskServiceError::RegistrationDrift(error.to_string()))
    }

    fn validate_cluster(&self, observed: &MskClusterObservation) -> Result<(), PartialReason> {
        if observed.name == self.scope.cluster.name && observed.arn != self.scope.cluster.arn {
            return Err(PartialReason::ClusterReplacement);
        }
        if observed.arn != self.scope.cluster.arn
            || observed.name != self.scope.cluster.name
            || observed.cluster_type != self.scope.cluster.cluster_type
            || observed.kafka_version != self.scope.cluster.kafka_version
        {
            return Err(PartialReason::ClusterRevisionDrift);
        }
        if observed
            .cluster_revision
            .is_some_and(|revision| revision != self.scope.cluster.revision)
        {
            return Err(PartialReason::ClusterRevisionDrift);
        }
        if let ConfigurationProjection {
            arn: Some(arn),
            revision: Some(revision),
            ..
        } = &observed.configuration
            && (arn != &self.scope.configuration.arn
                || *revision != self.scope.configuration.revision)
        {
            return Err(PartialReason::ConfigurationRevisionDrift);
        }
        Ok(())
    }

    fn validate_configuration(
        &self,
        observed: &MskConfigurationObservation,
    ) -> Result<(), PartialReason> {
        if observed.arn != self.scope.configuration.arn
            || observed.revision != self.scope.configuration.revision
        {
            return Err(PartialReason::ConfigurationRevisionDrift);
        }
        Ok(())
    }

    fn validate_operation(&self, observed: &MskOperationObservation) -> Result<(), PartialReason> {
        let Some(expected_revision) = self.scope.operation_revision(&observed.id) else {
            return Err(PartialReason::OperationRevisionDrift);
        };
        if observed
            .operation_revision
            .is_some_and(|revision| revision != expected_revision)
        {
            return Err(PartialReason::OperationRevisionDrift);
        }
        Ok(())
    }

    fn project_readiness(
        clusters: &[MskClusterObservation],
        cluster: Option<&MskClusterObservation>,
        configuration: Option<&MskConfigurationObservation>,
        operations: &[MskOperationObservation],
        partial_reason: Option<PartialReason>,
        terminal_state: Option<ReadinessState>,
    ) -> (ReadinessState, ReadinessState, ReadinessState) {
        if let Some(state @ (ReadinessState::AccessLoss | ReadinessState::ProviderUnknown)) =
            terminal_state
        {
            return (state, state, state);
        }
        let observed_cluster = cluster.or_else(|| clusters.first());
        let cluster_readiness =
            observed_cluster.map_or(ReadinessState::InsufficientData, |cluster| {
                if cluster.state == ClusterState::Failed || cluster.state == ClusterState::Deleting
                {
                    ReadinessState::NotReady
                } else if cluster.state != ClusterState::Active
                    || matches!(
                        cluster.broker_count_class,
                        crate::model::BrokerCountClass::Unknown
                    )
                    || security_unknown(&cluster.security_posture)
                {
                    ReadinessState::Partial
                } else {
                    ReadinessState::Ready
                }
            });
        let configuration_readiness = configuration.map_or_else(
            || {
                observed_cluster.map_or(ReadinessState::InsufficientData, |cluster| {
                    cluster.configuration.readiness
                })
            },
            |configuration| configuration.readiness,
        );
        let operation_readiness = if operations.is_empty() {
            ReadinessState::InsufficientData
        } else if operations.iter().any(|operation| {
            matches!(
                operation.state,
                OperationState::Failed | OperationState::Cancelled
            )
        }) {
            ReadinessState::NotReady
        } else if operations.iter().any(|operation| {
            matches!(
                operation.state,
                OperationState::Pending
                    | OperationState::InProgress
                    | OperationState::Cancelling
                    | OperationState::Unknown
            )
        }) {
            ReadinessState::Partial
        } else {
            ReadinessState::Ready
        };
        if partial_reason.is_some() {
            (
                demote(cluster_readiness),
                demote(configuration_readiness),
                demote(operation_readiness),
            )
        } else {
            (
                cluster_readiness,
                configuration_readiness,
                operation_readiness,
            )
        }
    }
}

fn security_unknown(posture: &crate::model::SecurityPosture) -> bool {
    matches!(posture.encryption_at_rest, crate::model::TriState::Unknown)
        || matches!(
            posture.client_broker_encryption,
            crate::model::ClientBrokerEncryption::Unknown
        )
}

const fn demote(state: ReadinessState) -> ReadinessState {
    match state {
        ReadinessState::Ready => ReadinessState::Partial,
        other => other,
    }
}

fn aggregate_readiness(
    cluster: ReadinessState,
    configuration: ReadinessState,
    operations: ReadinessState,
    partial_reason: Option<PartialReason>,
    page_count: u16,
) -> ReadinessState {
    if partial_reason.is_some() {
        return ReadinessState::Partial;
    }
    if page_count == 0 {
        return ReadinessState::InsufficientData;
    }
    if [cluster, configuration, operations].contains(&ReadinessState::NotReady) {
        return ReadinessState::NotReady;
    }
    if [cluster, configuration, operations].contains(&ReadinessState::Partial) {
        return ReadinessState::Partial;
    }
    if [cluster, configuration, operations].contains(&ReadinessState::InsufficientData) {
        return ReadinessState::InsufficientData;
    }
    ReadinessState::Ready
}

pub type AwsMskServiceResult<T> = AwsMskService<T>;
pub type AwsMskResultService<T> = AwsMskService<T>;
pub type AwsMskRegistrationReceipt = AwsMskRegistration;
pub type AwsMskProviderErrorEvidence = ProviderErrorEvidence;
pub type AwsMskTransportProvenance = TransportProvenance;

//! Read, proposal, recording, verification, and reversible registration seams.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AWS_RESOURCE_EXPLORER_CONTRACT_VERSION, AWS_RESOURCE_EXPLORER_PLUGIN_VERSION,
    AwsResourceExplorerEvidence, AwsResourceExplorerOperation, AwsResourceExplorerProvider,
    AwsResourceExplorerProviderDefinition, AwsResourceExplorerProviderError,
    AwsResourceExplorerScope, Digest, EvidenceDigests, InventoryState, ListIndexesRequest,
    MAX_INDEXES, MAX_RESOURCES, ModelError, PermissionFence, SearchRequest, SecretReference,
    TransportProvenance,
};

use crate::provider::{AwsResourceExplorerTransport, ProviderDefinitionError};

pub const AWS_RESOURCE_EXPLORER_SERVICE_ID: &str = "hartevo.aws.resource-explorer.result";
pub const AWS_RESOURCE_EXPLORER_SERVICE_NAME: &str = "AwsResourceExplorerService";
pub const MISSION_AWS_RESOURCE_EXPLORER_CONSUMER_ID: &str = "mission.aws.resource-explorer.result";
pub const AWS_RESOURCE_EXPLORER_SERVICE_SCHEMA: &str =
    "hartevo.aws-resource-explorer-result-service/v1";
pub const MISSION_AWS_RESOURCE_EXPLORER_CONSUMER_SCHEMA: &str =
    "hartevo.mission-aws-resource-explorer-consumer/v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RegistrationError {
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("registration is not revoked")]
    NotRevoked,
    #[error("registration digest is invalid")]
    InvalidDigest,
    #[error("registration binding does not match the current scope")]
    BindingMismatch,
    #[error("registration revision overflowed")]
    RevisionOverflow,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsResourceExplorerRegistration {
    pub plugin_version: String,
    pub version_digest: Digest,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
    pub secret_reference_digest: Digest,
    pub mission_digest: Digest,
    pub registration_revision: u64,
    pub state: RegistrationState,
    pub registration_digest: Digest,
}

impl AwsResourceExplorerRegistration {
    pub fn new(
        scope: &AwsResourceExplorerScope,
        secret_reference: &SecretReference,
        permission: &PermissionFence,
        provider: &AwsResourceExplorerProviderDefinition,
    ) -> Result<Self, RegistrationError> {
        if scope.permission_digest() != permission.digest()
            || secret_reference.scope_digest() != scope.scope_digest()
        {
            return Err(RegistrationError::BindingMismatch);
        }
        let registration_revision = 1;
        let mut registration = Self {
            plugin_version: AWS_RESOURCE_EXPLORER_PLUGIN_VERSION.to_owned(),
            version_digest: Digest::from_text(AWS_RESOURCE_EXPLORER_PLUGIN_VERSION),
            contract_version: AWS_RESOURCE_EXPLORER_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            provider_digest: provider.provider_digest.clone(),
            permission_digest: permission.digest(),
            scope_digest: scope.scope_digest().clone(),
            evidence_digest: evidence_definition_digest(),
            secret_reference_digest: secret_reference.reference_digest().clone(),
            mission_digest: scope.mission().digest(),
            registration_revision,
            state: RegistrationState::Active,
            registration_digest: Digest::zero(),
        };
        registration.registration_digest = registration.recomputed_digest();
        Ok(registration)
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.state == RegistrationState::Active
    }

    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        matches!(self.state, RegistrationState::Revoked)
    }

    #[must_use]
    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_serialized(&RegistrationDigestMaterial {
            plugin_version: &self.plugin_version,
            version_digest: &self.version_digest,
            contract_version: &self.contract_version,
            contract_digest: &self.contract_digest,
            provider_digest: &self.provider_digest,
            permission_digest: &self.permission_digest,
            scope_digest: &self.scope_digest,
            evidence_digest: &self.evidence_digest,
            secret_reference_digest: &self.secret_reference_digest,
            mission_digest: &self.mission_digest,
            registration_revision: self.registration_revision,
            state: self.state,
        })
    }

    pub fn validate(
        &self,
        scope: &AwsResourceExplorerScope,
        secret_reference: &SecretReference,
        permission: &PermissionFence,
        provider: &AwsResourceExplorerProviderDefinition,
    ) -> Result<(), RegistrationError> {
        if self.plugin_version != AWS_RESOURCE_EXPLORER_PLUGIN_VERSION
            || self.version_digest != Digest::from_text(AWS_RESOURCE_EXPLORER_PLUGIN_VERSION)
            || self.contract_version != AWS_RESOURCE_EXPLORER_CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.provider_digest != provider.provider_digest
            || self.permission_digest != permission.digest()
            || self.scope_digest != *scope.scope_digest()
            || self.secret_reference_digest != *secret_reference.reference_digest()
            || self.mission_digest != scope.mission().digest()
            || secret_reference.scope_digest() != scope.scope_digest()
            || self.registration_digest != self.recomputed_digest()
        {
            return Err(RegistrationError::BindingMismatch);
        }
        if self.registration_revision == 0 {
            return Err(RegistrationError::InvalidDigest);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<(), RegistrationError> {
        if self.is_revoked() {
            return Err(RegistrationError::AlreadyRevoked);
        }
        self.state = RegistrationState::Revoked;
        self.registration_revision = self
            .registration_revision
            .checked_add(1)
            .ok_or(RegistrationError::RevisionOverflow)?;
        self.registration_digest = self.recomputed_digest();
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), RegistrationError> {
        if self.is_active() {
            return Err(RegistrationError::NotRevoked);
        }
        self.state = RegistrationState::Active;
        self.registration_revision = self
            .registration_revision
            .checked_add(1)
            .ok_or(RegistrationError::RevisionOverflow)?;
        self.registration_digest = self.recomputed_digest();
        Ok(())
    }

    pub fn reverse(&mut self) -> Result<(), RegistrationError> {
        if self.is_active() {
            self.revoke()
        } else {
            self.restore()
        }
    }
}

#[derive(Serialize)]
struct RegistrationDigestMaterial<'a> {
    plugin_version: &'a str,
    version_digest: &'a Digest,
    contract_version: &'a str,
    contract_digest: &'a Digest,
    provider_digest: &'a Digest,
    permission_digest: &'a Digest,
    scope_digest: &'a Digest,
    evidence_digest: &'a Digest,
    secret_reference_digest: &'a Digest,
    mission_digest: &'a Digest,
    registration_revision: u64,
    state: RegistrationState,
}

fn evidence_definition_digest() -> Digest {
    Digest::from_parts(
        "aws-resource-explorer-evidence-definition/v1",
        [
            "resource_digest",
            "resource_type_digest",
            "property_name_digest",
            "property_value_digest",
            "index_digest",
            "view_digest",
            "query_digest",
            "page_count",
            "provider_error_digest",
        ],
    )
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsResourceExplorerServiceError {
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error(transparent)]
    Provider(#[from] AwsResourceExplorerProviderError),
    #[error(transparent)]
    ProviderDefinition(#[from] ProviderDefinitionError),
    #[error(transparent)]
    Registration(#[from] RegistrationError),
    #[error("AWS Resource Explorer registration is revoked")]
    Revoked,
    #[error("AWS Resource Explorer SecretReference is revoked")]
    SecretRevoked,
    #[error("AWS Resource Explorer proposal does not match the service registration")]
    ProposalMismatch,
    #[error("AWS Resource Explorer record does not match the proposal")]
    RecordMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsResourceExplorerCapability {
    pub operation: AwsResourceExplorerOperation,
    pub permission: String,
    pub read_only: bool,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub raw_properties: bool,
    pub raw_tags: bool,
    pub raw_pii: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsResourceExplorerServiceDefinition {
    pub service_id: String,
    pub name: String,
    pub version: String,
    pub operations: Vec<String>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
}

impl Default for AwsResourceExplorerServiceDefinition {
    fn default() -> Self {
        Self {
            service_id: AWS_RESOURCE_EXPLORER_SERVICE_ID.to_owned(),
            name: AWS_RESOURCE_EXPLORER_SERVICE_NAME.to_owned(),
            version: AWS_RESOURCE_EXPLORER_PLUGIN_VERSION.to_owned(),
            operations: vec![
                "describe_capabilities".to_owned(),
                "register".to_owned(),
                "revoke_registration".to_owned(),
                "restore_registration".to_owned(),
                "search".to_owned(),
                "list_indexes".to_owned(),
                "propose".to_owned(),
                "record".to_owned(),
                "verify".to_owned(),
            ],
            read_only: true,
            proposal_only: true,
            connected: false,
            native: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsResourceExplorerProposal {
    pub operation: AwsResourceExplorerOperation,
    pub evidence: AwsResourceExplorerEvidence,
    pub registration_digest: Digest,
    pub proposal_digest: Digest,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub adopted_outcome: bool,
}

impl AwsResourceExplorerProposal {
    #[must_use]
    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_serialized(&ProposalDigestMaterial {
            operation: self.operation,
            evidence_digest: self.evidence.evidence_digest().clone(),
            registration_digest: self.registration_digest.clone(),
        })
    }

    pub fn validate(&self) -> Result<(), AwsResourceExplorerServiceError> {
        self.evidence.validate_integrity()?;
        if !self.proposal_only
            || self.connected
            || self.native
            || self.adopted_outcome
            || self.proposal_digest != self.recomputed_digest()
            || self.operation != self.evidence.operation
        {
            return Err(AwsResourceExplorerServiceError::ProposalMismatch);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct ProposalDigestMaterial {
    operation: AwsResourceExplorerOperation,
    evidence_digest: Digest,
    registration_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsResourceExplorerRecord {
    pub operation: AwsResourceExplorerOperation,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub record_digest: Digest,
    pub recorded: bool,
    pub durable_receipt: bool,
    pub connected: bool,
    pub native: bool,
    pub adopted_outcome: bool,
}

impl AwsResourceExplorerRecord {
    #[must_use]
    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-resource-explorer-record/v1",
            [
                self.operation.api_name(),
                self.proposal_digest.as_str(),
                self.evidence_digest.as_str(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsResourceExplorerVerification {
    pub verified: bool,
    pub operation: AwsResourceExplorerOperation,
    pub proposal_digest: Digest,
    pub record_digest: Digest,
    pub evidence_digest: Digest,
    pub property_digests_only: bool,
    pub connected: bool,
    pub native: bool,
    pub adopted_outcome: bool,
}

pub struct AwsResourceExplorerService<T: AwsResourceExplorerTransport> {
    definition: AwsResourceExplorerServiceDefinition,
    scope: AwsResourceExplorerScope,
    secret_reference: SecretReference,
    permission: PermissionFence,
    provider: AwsResourceExplorerProvider<T>,
    registration: AwsResourceExplorerRegistration,
}

impl<T: AwsResourceExplorerTransport> fmt::Debug for AwsResourceExplorerService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsResourceExplorerService")
            .field("definition", &self.definition)
            .field("scope_digest", self.scope.scope_digest())
            .field("secret_reference", &self.secret_reference)
            .field("permission", &self.permission)
            .field(
                "registration_digest",
                &self.registration.registration_digest,
            )
            .field("active", &self.registration.is_active())
            .field("provider", &self.provider)
            .finish()
    }
}

impl<T: AwsResourceExplorerTransport> AwsResourceExplorerService<T> {
    pub fn new(
        scope: AwsResourceExplorerScope,
        secret_reference: SecretReference,
        permission: PermissionFence,
        provider: AwsResourceExplorerProvider<T>,
    ) -> Result<Self, AwsResourceExplorerServiceError> {
        scope.validate()?;
        permission.validate()?;
        if secret_reference.is_revoked() {
            return Err(AwsResourceExplorerServiceError::SecretRevoked);
        }
        if secret_reference.scope_digest() != scope.scope_digest() {
            return Err(AwsResourceExplorerServiceError::Model(
                ModelError::ScopeMismatch {
                    field: "SecretReference scope",
                },
            ));
        }
        provider.definition().validate()?;
        let registration = AwsResourceExplorerRegistration::new(
            &scope,
            &secret_reference,
            &permission,
            provider.definition(),
        )?;
        Ok(Self {
            definition: AwsResourceExplorerServiceDefinition::default(),
            scope,
            secret_reference,
            permission,
            provider,
            registration,
        })
    }

    pub fn from_scope(
        scope: AwsResourceExplorerScope,
        secret_reference: SecretReference,
        provider: AwsResourceExplorerProvider<T>,
    ) -> Result<Self, AwsResourceExplorerServiceError> {
        Self::new(
            scope.clone(),
            secret_reference,
            scope.permission().clone(),
            provider,
        )
    }

    #[must_use]
    pub fn definition(&self) -> &AwsResourceExplorerServiceDefinition {
        &self.definition
    }

    #[must_use]
    pub fn scope(&self) -> &AwsResourceExplorerScope {
        &self.scope
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn permission(&self) -> &PermissionFence {
        &self.permission
    }

    #[must_use]
    pub fn provider(&self) -> &AwsResourceExplorerProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut AwsResourceExplorerProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn registration(&self) -> &AwsResourceExplorerRegistration {
        &self.registration
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.registration.is_active()
    }

    #[must_use]
    pub fn provider_provenance(&self) -> TransportProvenance {
        self.provider.provenance()
    }

    #[must_use]
    pub fn describe_capabilities(&self) -> Vec<AwsResourceExplorerCapability> {
        [
            AwsResourceExplorerOperation::Search,
            AwsResourceExplorerOperation::ListIndexes,
        ]
        .into_iter()
        .map(|operation| AwsResourceExplorerCapability {
            operation,
            permission: operation.permission().api_name().to_owned(),
            read_only: true,
            proposal_only: true,
            connected: false,
            native: false,
            raw_properties: false,
            raw_tags: false,
            raw_pii: false,
        })
        .collect()
    }

    pub fn register(
        &self,
    ) -> Result<&AwsResourceExplorerRegistration, AwsResourceExplorerServiceError> {
        self.ensure_active()?;
        Ok(&self.registration)
    }

    pub fn revoke_registration(&mut self) -> Result<(), AwsResourceExplorerServiceError> {
        self.registration.revoke()?;
        Ok(())
    }

    pub fn restore_registration(&mut self) -> Result<(), AwsResourceExplorerServiceError> {
        self.registration.restore()?;
        Ok(())
    }

    pub fn reverse_registration(&mut self) -> Result<(), AwsResourceExplorerServiceError> {
        self.registration.reverse()?;
        Ok(())
    }

    pub fn read_search(
        &mut self,
        request: SearchRequest,
    ) -> Result<AwsResourceExplorerEvidence, AwsResourceExplorerServiceError> {
        self.ensure_ready()?;
        request.validate_against(&self.scope)?;
        let mut current_request = request;
        let mut resources = Vec::new();
        let mut page_count: u16 = 0;
        let mut total_response_bytes: usize = 0;
        let mut truncated = false;
        let mut partial_reason = None;
        let mut provider_error_digests = Vec::new();
        let mut access_lost = false;
        let mut seen_tokens = BTreeSet::new();

        for expected_page in 1..=current_request.max_pages {
            match self.provider.search(&current_request) {
                Ok(page) => {
                    if page.page_number != expected_page {
                        partial_reason = Some(crate::PartialReason::InvalidResponse);
                        break;
                    }
                    page_count = page_count.saturating_add(1);
                    total_response_bytes = total_response_bytes.saturating_add(page.response_bytes);
                    if total_response_bytes > crate::MAX_RESPONSE_BYTES {
                        truncated = true;
                        partial_reason = Some(crate::PartialReason::ResponseTooLarge);
                        break;
                    }
                    for resource in page.resources {
                        if !self.scope.allows_resource(&resource) {
                            partial_reason = Some(crate::PartialReason::ScopeMismatch);
                            continue;
                        }
                        if resources.len() >= MAX_RESOURCES {
                            truncated = true;
                            partial_reason = Some(crate::PartialReason::PageBudget);
                            break;
                        }
                        resources.push(resource);
                    }
                    if let Some(token) = page.next_page_token {
                        if !seen_tokens.insert(token.digest().clone()) {
                            truncated = true;
                            partial_reason = Some(crate::PartialReason::CursorReplay);
                            break;
                        }
                        if expected_page == current_request.max_pages {
                            truncated = true;
                            partial_reason = Some(crate::PartialReason::PageBudget);
                            break;
                        }
                        if let Ok(next_request) = current_request.with_page_token(token) {
                            current_request = next_request;
                        } else {
                            truncated = true;
                            partial_reason = Some(crate::PartialReason::CursorReplay);
                            break;
                        }
                    } else {
                        break;
                    }
                }
                Err(error) => {
                    access_lost = error.is_access_loss();
                    provider_error_digests.push(error.digest());
                    partial_reason = Some(crate::PartialReason::ProviderFailure);
                    break;
                }
            }
        }
        let state = state_for(
            resources.is_empty(),
            partial_reason,
            access_lost,
            !provider_error_digests.is_empty(),
        );
        Ok(self.build_evidence(
            AwsResourceExplorerOperation::Search,
            state,
            resources,
            Vec::new(),
            page_count,
            truncated,
            partial_reason,
            provider_error_digests,
        ))
    }

    pub fn search(
        &mut self,
        request: SearchRequest,
    ) -> Result<AwsResourceExplorerEvidence, AwsResourceExplorerServiceError> {
        self.read_search(request)
    }

    pub fn read_list_indexes(
        &mut self,
        request: ListIndexesRequest,
    ) -> Result<AwsResourceExplorerEvidence, AwsResourceExplorerServiceError> {
        self.ensure_ready()?;
        request.validate_against(&self.scope)?;
        let mut current_request = request;
        let mut indexes = Vec::new();
        let mut page_count: u16 = 0;
        let mut total_response_bytes: usize = 0;
        let mut truncated = false;
        let mut partial_reason = None;
        let mut provider_error_digests = Vec::new();
        let mut access_lost = false;
        let mut seen_tokens = BTreeSet::new();

        for expected_page in 1..=current_request.max_pages {
            match self.provider.list_indexes(&current_request) {
                Ok(page) => {
                    if page.page_number != expected_page {
                        partial_reason = Some(crate::PartialReason::InvalidResponse);
                        break;
                    }
                    page_count = page_count.saturating_add(1);
                    total_response_bytes = total_response_bytes.saturating_add(page.response_bytes);
                    if total_response_bytes > crate::MAX_RESPONSE_BYTES {
                        truncated = true;
                        partial_reason = Some(crate::PartialReason::ResponseTooLarge);
                        break;
                    }
                    for index in page.indexes {
                        if index.region() != self.scope.region() {
                            partial_reason = Some(crate::PartialReason::ScopeMismatch);
                            continue;
                        }
                        if indexes.len() >= MAX_INDEXES {
                            truncated = true;
                            partial_reason = Some(crate::PartialReason::PageBudget);
                            break;
                        }
                        indexes.push(index);
                    }
                    if let Some(token) = page.next_page_token {
                        if !seen_tokens.insert(token.digest().clone()) {
                            truncated = true;
                            partial_reason = Some(crate::PartialReason::CursorReplay);
                            break;
                        }
                        if expected_page == current_request.max_pages {
                            truncated = true;
                            partial_reason = Some(crate::PartialReason::PageBudget);
                            break;
                        }
                        if let Ok(next_request) = current_request.with_page_token(token) {
                            current_request = next_request;
                        } else {
                            truncated = true;
                            partial_reason = Some(crate::PartialReason::CursorReplay);
                            break;
                        }
                    } else {
                        break;
                    }
                }
                Err(error) => {
                    access_lost = error.is_access_loss();
                    provider_error_digests.push(error.digest());
                    partial_reason = Some(crate::PartialReason::ProviderFailure);
                    break;
                }
            }
        }
        let state = state_for(
            indexes.is_empty(),
            partial_reason,
            access_lost,
            !provider_error_digests.is_empty(),
        );
        Ok(self.build_evidence(
            AwsResourceExplorerOperation::ListIndexes,
            state,
            Vec::new(),
            indexes,
            page_count,
            truncated,
            partial_reason,
            provider_error_digests,
        ))
    }

    pub fn list_indexes(
        &mut self,
        request: ListIndexesRequest,
    ) -> Result<AwsResourceExplorerEvidence, AwsResourceExplorerServiceError> {
        self.read_list_indexes(request)
    }

    pub fn propose_search(
        &mut self,
        request: SearchRequest,
    ) -> Result<AwsResourceExplorerProposal, AwsResourceExplorerServiceError> {
        let evidence = self.read_search(request)?;
        Ok(self.proposal_from_evidence(evidence))
    }

    pub fn propose_list_indexes(
        &mut self,
        request: ListIndexesRequest,
    ) -> Result<AwsResourceExplorerProposal, AwsResourceExplorerServiceError> {
        let evidence = self.read_list_indexes(request)?;
        Ok(self.proposal_from_evidence(evidence))
    }

    pub fn record(
        &self,
        proposal: &AwsResourceExplorerProposal,
    ) -> Result<AwsResourceExplorerRecord, AwsResourceExplorerServiceError> {
        self.ensure_ready()?;
        self.verify_proposal(proposal)?;
        let record_digest = Digest::from_parts(
            "aws-resource-explorer-record/v1",
            [
                proposal.operation.api_name(),
                proposal.proposal_digest.as_str(),
                proposal.evidence.evidence_digest().as_str(),
            ],
        );
        Ok(AwsResourceExplorerRecord {
            operation: proposal.operation,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest().clone(),
            record_digest,
            recorded: true,
            durable_receipt: false,
            connected: false,
            native: false,
            adopted_outcome: false,
        })
    }

    pub fn record_search(
        &self,
        proposal: &AwsResourceExplorerProposal,
    ) -> Result<AwsResourceExplorerRecord, AwsResourceExplorerServiceError> {
        self.record(proposal)
    }

    pub fn verify(
        &self,
        record: &AwsResourceExplorerRecord,
    ) -> Result<AwsResourceExplorerVerification, AwsResourceExplorerServiceError> {
        self.ensure_ready()?;
        if !record.recorded
            || record.durable_receipt
            || record.connected
            || record.native
            || record.adopted_outcome
            || record.record_digest != record.recomputed_digest()
        {
            return Err(AwsResourceExplorerServiceError::RecordMismatch);
        }
        Ok(AwsResourceExplorerVerification {
            verified: true,
            operation: record.operation,
            proposal_digest: record.proposal_digest.clone(),
            record_digest: record.record_digest.clone(),
            evidence_digest: record.evidence_digest.clone(),
            property_digests_only: true,
            connected: false,
            native: false,
            adopted_outcome: false,
        })
    }

    pub fn verify_proposal(
        &self,
        proposal: &AwsResourceExplorerProposal,
    ) -> Result<(), AwsResourceExplorerServiceError> {
        self.ensure_ready()?;
        if proposal.registration_digest != self.registration.registration_digest {
            return Err(AwsResourceExplorerServiceError::ProposalMismatch);
        }
        proposal.validate()?;
        if proposal.evidence.digests.scope_digest != *self.scope.scope_digest()
            || proposal.evidence.digests.permission_digest != self.permission.digest()
            || proposal.evidence.digests.provider_digest != *self.provider.provider_digest()
            || proposal.evidence.digests.query_digest != *self.scope.query_digest()
        {
            return Err(AwsResourceExplorerServiceError::ProposalMismatch);
        }
        Ok(())
    }

    pub fn build_evidence(
        &self,
        operation: AwsResourceExplorerOperation,
        state: InventoryState,
        resources: Vec<crate::ResourceInventoryItem>,
        indexes: Vec<crate::IndexInventoryItem>,
        page_count: u16,
        truncated: bool,
        partial_reason: Option<crate::PartialReason>,
        provider_error_digests: Vec<Digest>,
    ) -> AwsResourceExplorerEvidence {
        let mut evidence = AwsResourceExplorerEvidence {
            operation,
            state,
            provenance: self.provider.provenance(),
            account_id: self.scope.account_id().clone(),
            region: self.scope.region().clone(),
            index_digest: self.scope.index().index_digest().clone(),
            view_digest: self.scope.view().view_digest().clone(),
            query_digest: self.scope.query_digest().clone(),
            indexes,
            resources,
            page_count,
            truncated,
            partial_reason,
            provider_error_digests,
            digests: EvidenceDigests {
                version_digest: Digest::from_text(AWS_RESOURCE_EXPLORER_PLUGIN_VERSION),
                contract_digest: crate::contract_digest(),
                provider_digest: self.provider.provider_digest().clone(),
                permission_digest: self.permission.digest(),
                scope_digest: self.scope.scope_digest().clone(),
                query_digest: self.scope.query_digest().clone(),
                evidence_digest: Digest::zero(),
            },
            read_only: true,
            proposal_only: true,
            connected: false,
            native: false,
            property_digests_only: true,
            raw_properties_retained: false,
            raw_tags_retained: false,
            raw_pii_retained: false,
        };
        evidence.digests.evidence_digest = evidence.recomputed_evidence_digest();
        evidence
    }

    fn proposal_from_evidence(
        &self,
        evidence: AwsResourceExplorerEvidence,
    ) -> AwsResourceExplorerProposal {
        let operation = evidence.operation;
        let registration_digest = self.registration.registration_digest.clone();
        let proposal_digest = Digest::from_serialized(&ProposalDigestMaterial {
            operation,
            evidence_digest: evidence.evidence_digest().clone(),
            registration_digest: registration_digest.clone(),
        });
        AwsResourceExplorerProposal {
            operation,
            evidence,
            registration_digest,
            proposal_digest,
            proposal_only: true,
            connected: false,
            native: false,
            adopted_outcome: false,
        }
    }

    fn ensure_active(&self) -> Result<(), AwsResourceExplorerServiceError> {
        if self.registration.is_active() {
            Ok(())
        } else {
            Err(AwsResourceExplorerServiceError::Revoked)
        }
    }

    fn ensure_ready(&self) -> Result<(), AwsResourceExplorerServiceError> {
        self.ensure_active()?;
        if self.secret_reference.is_revoked() {
            return Err(AwsResourceExplorerServiceError::SecretRevoked);
        }
        self.registration.validate(
            &self.scope,
            &self.secret_reference,
            &self.permission,
            self.provider.definition(),
        )?;
        Ok(())
    }
}

fn state_for(
    empty: bool,
    partial_reason: Option<crate::PartialReason>,
    access_lost: bool,
    provider_failure: bool,
) -> InventoryState {
    if access_lost {
        InventoryState::AccessLost
    } else if provider_failure {
        InventoryState::ProviderUnknown
    } else if partial_reason.is_some() {
        InventoryState::Partial
    } else if empty {
        InventoryState::Empty
    } else {
        InventoryState::Complete
    }
}

pub type AwsResourceExplorerResultService<T> = AwsResourceExplorerService<T>;
pub type AwsResourceExplorerProposalEnvelope = AwsResourceExplorerProposal;
pub type AwsResourceExplorerRecordReceipt = AwsResourceExplorerRecord;
pub type AwsResourceExplorerVerificationReport = AwsResourceExplorerVerification;

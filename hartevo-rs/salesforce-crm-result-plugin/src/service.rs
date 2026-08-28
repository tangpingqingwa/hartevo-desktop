use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};

use crate::{
    BlockedEnvTransport, MISSION_SALESFORCE_CRM_CONSUMER_ID,
    SALESFORCE_CRM_RESULT_CONTRACT_VERSION, SALESFORCE_CRM_RESULT_PLUGIN_VERSION_TEXT,
    SALESFORCE_CRM_RESULT_SERVICE_ID, SALESFORCE_CRM_RESULT_SERVICE_NAME,
    SALESFORCE_CRM_RESULT_SERVICE_SCHEMA, SalesforceCrmResultError, contract_digest,
    model::{
        Digest, PluginVersion, ProviderErrorEvidence, ProviderErrorKind, QuerySeam,
        SalesforceReadRequest, SalesforceRecordProjection, SalesforceRegistration,
        SalesforceResultStatus, SalesforceScope, TransportProvenance, canonical_digest,
    },
    provider::{
        CollectedSalesforceResponses, SalesforceHttpRequest, SalesforceProvider,
        SalesforceProviderDefinition, SalesforceTransport, SalesforceTransportError,
    },
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SalesforceOperation {
    Describe,
    Register,
    Revoke,
    Restore,
    Propose,
    Record,
    Verify,
}

impl SalesforceOperation {
    pub const ALL: [Self; 7] = [
        Self::Describe,
        Self::Register,
        Self::Revoke,
        Self::Restore,
        Self::Propose,
        Self::Record,
        Self::Verify,
    ];

    pub const fn is_read_only(self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SalesforceCapability {
    pub capability_id: String,
    pub operation: SalesforceOperation,
    pub read_only: bool,
    pub mutates_provider: bool,
    pub native_evidence: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SalesforceServiceDefinition {
    service_id: String,
    service_name: String,
    version: PluginVersion,
    read_only: bool,
    native_connected: bool,
    capabilities: Vec<SalesforceCapability>,
}

impl Default for SalesforceServiceDefinition {
    fn default() -> Self {
        Self::new()
    }
}

impl SalesforceServiceDefinition {
    pub fn new() -> Self {
        let capabilities = [
            (
                "salesforce.crm.result.describe",
                SalesforceOperation::Describe,
            ),
            (
                "salesforce.crm.result.register",
                SalesforceOperation::Register,
            ),
            ("salesforce.crm.result.revoke", SalesforceOperation::Revoke),
            (
                "salesforce.crm.result.restore",
                SalesforceOperation::Restore,
            ),
            (
                "salesforce.crm.result.propose",
                SalesforceOperation::Propose,
            ),
            ("salesforce.crm.result.record", SalesforceOperation::Record),
            ("salesforce.crm.result.verify", SalesforceOperation::Verify),
        ]
        .into_iter()
        .map(|(capability_id, operation)| SalesforceCapability {
            capability_id: capability_id.to_owned(),
            operation,
            read_only: true,
            mutates_provider: false,
            native_evidence: false,
        })
        .collect();
        Self {
            service_id: SALESFORCE_CRM_RESULT_SERVICE_ID.to_owned(),
            service_name: SALESFORCE_CRM_RESULT_SERVICE_NAME.to_owned(),
            version: PluginVersion::new(1, 0, 0),
            read_only: true,
            native_connected: false,
            capabilities,
        }
    }

    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    pub const fn version(&self) -> PluginVersion {
        self.version
    }

    pub const fn read_only(&self) -> bool {
        self.read_only
    }

    pub const fn native_connected(&self) -> bool {
        self.native_connected
    }

    pub fn capabilities(&self) -> &[SalesforceCapability] {
        &self.capabilities
    }

    pub fn describe(&self) -> Vec<SalesforceCapability> {
        self.capabilities.clone()
    }

    pub fn validate(&self) -> Result<(), SalesforceCrmResultError> {
        if self.service_id != SALESFORCE_CRM_RESULT_SERVICE_ID
            || self.service_name != SALESFORCE_CRM_RESULT_SERVICE_NAME
            || self.version != PluginVersion::new(1, 0, 0)
            || !self.read_only
            || self.native_connected
            || self.capabilities.len() != SalesforceOperation::ALL.len()
            || self.capabilities.iter().any(|capability| {
                !capability.read_only || capability.mutates_provider || capability.native_evidence
            })
        {
            Err(SalesforceCrmResultError::InvalidInput(
                "Salesforce service definition drifted".to_owned(),
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SalesforceReadProposal {
    pub schema_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub plugin_version: PluginVersion,
    pub plugin_version_digest: Digest,
    pub service_id: String,
    pub provider_id: String,
    pub provider_version: PluginVersion,
    pub provider_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub request: SalesforceReadRequest,
    pub http_request: SalesforceHttpRequest,
    pub proposal_digest: Digest,
}

impl SalesforceReadProposal {
    pub(crate) fn new(
        scope: &SalesforceScope,
        provider: &SalesforceProviderDefinition,
        request: SalesforceReadRequest,
    ) -> Result<Self, SalesforceCrmResultError> {
        let http_request = SalesforceHttpRequest::from_scope(scope, &request)?;
        let plugin_version = PluginVersion::new(1, 0, 0);
        let mut proposal = Self {
            schema_version: crate::SALESFORCE_CRM_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: SALESFORCE_CRM_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            plugin_version,
            plugin_version_digest: plugin_version.digest(),
            service_id: SALESFORCE_CRM_RESULT_SERVICE_ID.to_owned(),
            provider_id: provider.provider_id.clone(),
            provider_version: provider.provider_version,
            provider_digest: provider.provider_digest(),
            scope_digest: scope.scope_digest(),
            permission_digest: scope.permission_digest().clone(),
            consent_digest: scope.consent_digest().clone(),
            request,
            http_request,
            proposal_digest: Digest::from_text("placeholder"),
        };
        proposal.proposal_digest = proposal.compute_digest();
        proposal.validate(scope, provider)?;
        Ok(proposal)
    }

    pub fn compute_digest(&self) -> Digest {
        canonical_digest(&(
            &self.schema_version,
            &self.contract_version,
            &self.contract_digest,
            self.plugin_version,
            &self.plugin_version_digest,
            &self.service_id,
            &self.provider_id,
            self.provider_version,
            &self.provider_digest,
            &self.scope_digest,
            &self.permission_digest,
            &self.consent_digest,
            &self.request,
            &self.http_request,
        ))
    }

    pub fn query_digest(&self) -> Digest {
        Digest::from_text(&self.http_request.query_text)
    }

    pub fn request_digest(&self) -> &Digest {
        &self.http_request.request_digest
    }

    pub fn validate(
        &self,
        scope: &SalesforceScope,
        provider: &SalesforceProviderDefinition,
    ) -> Result<(), SalesforceCrmResultError> {
        if self.schema_version != crate::SALESFORCE_CRM_RESULT_SCHEMA_VERSION
            || self.contract_version != SALESFORCE_CRM_RESULT_CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.plugin_version != PluginVersion::new(1, 0, 0)
            || self.plugin_version_digest != self.plugin_version.digest()
            || self.service_id != SALESFORCE_CRM_RESULT_SERVICE_ID
            || self.provider_id != provider.provider_id
            || self.provider_version != provider.provider_version
            || self.provider_digest != provider.provider_digest()
            || self.scope_digest != scope.scope_digest()
            || self.permission_digest != *scope.permission_digest()
            || self.consent_digest != *scope.consent_digest()
            || self.request.validate_for(scope).is_err()
            || self.http_request.validate_integrity().is_err()
            || !self.http_request.is_read_only()
            || self.proposal_digest != self.compute_digest()
        {
            Err(SalesforceCrmResultError::ProposalDigestMismatch)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SalesforceEvidence {
    pub schema_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub plugin_version: PluginVersion,
    pub plugin_version_digest: Digest,
    pub service_id: String,
    pub provider_id: String,
    pub provider_version: PluginVersion,
    pub provider_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub proposal_digest: Digest,
    pub query_digest: Digest,
    pub response_digests: Vec<Digest>,
    pub record_digests: Vec<Digest>,
    pub records: Vec<SalesforceRecordProjection>,
    pub status: SalesforceResultStatus,
    pub provenance: TransportProvenance,
    pub pagination: crate::PaginationEvidence,
    pub provider_errors: Vec<ProviderErrorEvidence>,
    pub raw_payload_retained: bool,
    pub pii_retained: bool,
    pub external_write_performed: bool,
    pub composite_write_performed: bool,
    pub email_sent: bool,
    pub case_comment_written: bool,
    pub approval_mutation_performed: bool,
    pub native_evidence: bool,
    pub inbox_authority: bool,
    pub truth_authority: bool,
    pub evidence_digest: Digest,
}

#[derive(Serialize)]
struct EvidenceDigestMaterial<'a> {
    schema_version: &'a String,
    contract_version: &'a String,
    contract_digest: &'a Digest,
    plugin_version: PluginVersion,
    plugin_version_digest: &'a Digest,
    service_id: &'a String,
    provider_id: &'a String,
    provider_version: PluginVersion,
    provider_digest: &'a Digest,
    scope_digest: &'a Digest,
    permission_digest: &'a Digest,
    consent_digest: &'a Digest,
    proposal_digest: &'a Digest,
    query_digest: &'a Digest,
    response_digests: &'a Vec<Digest>,
    record_digests: &'a Vec<Digest>,
    records: &'a Vec<SalesforceRecordProjection>,
    status: SalesforceResultStatus,
    provenance: TransportProvenance,
    pagination: &'a crate::PaginationEvidence,
    provider_errors: &'a Vec<ProviderErrorEvidence>,
    raw_payload_retained: bool,
    pii_retained: bool,
    external_write_performed: bool,
    composite_write_performed: bool,
    email_sent: bool,
    case_comment_written: bool,
    approval_mutation_performed: bool,
    native_evidence: bool,
    inbox_authority: bool,
    truth_authority: bool,
}

impl SalesforceEvidence {
    pub(crate) fn from_collected(
        proposal: &SalesforceReadProposal,
        provider: &SalesforceProviderDefinition,
        collected: CollectedSalesforceResponses,
    ) -> Result<Self, SalesforceCrmResultError> {
        let mut records = Vec::new();
        let mut response_digests = Vec::new();
        let mut provider_errors = Vec::new();
        let mut status = SalesforceResultStatus::Complete;
        for response in &collected.responses {
            response.validate()?;
            response_digests.push(response.response_digest.clone());
            if !(200..=299).contains(&response.status_code) {
                let kind = provider_error_kind_for_status(response.status_code);
                provider_errors.push(ProviderErrorEvidence::new(
                    kind,
                    Some(response.status_code),
                    response.response_digest.as_str(),
                ));
                status = status_for_provider_error(kind);
                continue;
            }
            let Some(page) = response.page.as_ref() else {
                status = SalesforceResultStatus::FinalError;
                provider_errors.push(ProviderErrorEvidence::new(
                    ProviderErrorKind::Decode,
                    Some(response.status_code),
                    "missing-page",
                ));
                continue;
            };
            page.validate()?;
            if let Some(record) = &page.record {
                if record.object != proposal.request.object
                    || record.record_id != proposal.request.record_id
                    || record.record_revision != proposal.http_request.expected_record_revision
                    || record.fields.keys().any(|field| {
                        !proposal.request.fields.contains(field)
                            && *field != crate::SalesforceField::RecordRevision
                    })
                {
                    return Err(SalesforceCrmResultError::RecordRevisionMismatch);
                }
                if records.len() >= crate::SALESFORCE_MAX_RECORDS {
                    return Err(SalesforceCrmResultError::UnsafeProjection);
                }
                records.push(record.clone());
            }
        }
        collected.pagination.validate()?;
        if collected.pagination.loop_detected {
            return Err(SalesforceCrmResultError::PaginationLoop);
        }
        if collected.pagination.truncated {
            status = SalesforceResultStatus::Partial;
        }
        if status == SalesforceResultStatus::Complete
            && records.is_empty()
            && provider_errors.is_empty()
        {
            status = SalesforceResultStatus::NotFound;
        }
        let plugin_version = PluginVersion::new(1, 0, 0);
        let mut evidence = Self {
            schema_version: crate::SALESFORCE_CRM_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: SALESFORCE_CRM_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            plugin_version,
            plugin_version_digest: plugin_version.digest(),
            service_id: SALESFORCE_CRM_RESULT_SERVICE_ID.to_owned(),
            provider_id: provider.provider_id.clone(),
            provider_version: provider.provider_version,
            provider_digest: provider.provider_digest(),
            scope_digest: proposal.scope_digest.clone(),
            permission_digest: proposal.permission_digest.clone(),
            consent_digest: proposal.consent_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            query_digest: proposal.query_digest(),
            record_digests: records
                .iter()
                .map(|record| record.record_digest.clone())
                .collect(),
            records,
            response_digests,
            status,
            provenance: provider.provenance,
            pagination: collected.pagination,
            provider_errors,
            raw_payload_retained: false,
            pii_retained: false,
            external_write_performed: false,
            composite_write_performed: false,
            email_sent: false,
            case_comment_written: false,
            approval_mutation_performed: false,
            native_evidence: false,
            inbox_authority: false,
            truth_authority: false,
            evidence_digest: Digest::from_text("placeholder"),
        };
        evidence.evidence_digest = evidence.compute_digest();
        Ok(evidence)
    }

    pub(crate) fn from_transport_error(
        proposal: &SalesforceReadProposal,
        provider: &SalesforceProviderDefinition,
        error: &SalesforceTransportError,
    ) -> Self {
        let provider_error = error.evidence();
        let status = status_for_provider_error(provider_error.kind);
        let plugin_version = PluginVersion::new(1, 0, 0);
        let mut evidence = Self {
            schema_version: crate::SALESFORCE_CRM_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: SALESFORCE_CRM_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            plugin_version,
            plugin_version_digest: plugin_version.digest(),
            service_id: SALESFORCE_CRM_RESULT_SERVICE_ID.to_owned(),
            provider_id: provider.provider_id.clone(),
            provider_version: provider.provider_version,
            provider_digest: provider.provider_digest(),
            scope_digest: proposal.scope_digest.clone(),
            permission_digest: proposal.permission_digest.clone(),
            consent_digest: proposal.consent_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            query_digest: proposal.query_digest(),
            response_digests: Vec::new(),
            record_digests: Vec::new(),
            records: Vec::new(),
            status,
            provenance: provider.provenance,
            pagination: crate::PaginationEvidence {
                pages: 1,
                next_records_url_digests: Vec::new(),
                truncated: false,
                loop_detected: false,
            },
            provider_errors: vec![provider_error],
            raw_payload_retained: false,
            pii_retained: false,
            external_write_performed: false,
            composite_write_performed: false,
            email_sent: false,
            case_comment_written: false,
            approval_mutation_performed: false,
            native_evidence: false,
            inbox_authority: false,
            truth_authority: false,
            evidence_digest: Digest::from_text("placeholder"),
        };
        evidence.evidence_digest = evidence.compute_digest();
        evidence
    }

    pub fn compute_digest(&self) -> Digest {
        canonical_digest(&EvidenceDigestMaterial {
            schema_version: &self.schema_version,
            contract_version: &self.contract_version,
            contract_digest: &self.contract_digest,
            plugin_version: self.plugin_version,
            plugin_version_digest: &self.plugin_version_digest,
            service_id: &self.service_id,
            provider_id: &self.provider_id,
            provider_version: self.provider_version,
            provider_digest: &self.provider_digest,
            scope_digest: &self.scope_digest,
            permission_digest: &self.permission_digest,
            consent_digest: &self.consent_digest,
            proposal_digest: &self.proposal_digest,
            query_digest: &self.query_digest,
            response_digests: &self.response_digests,
            record_digests: &self.record_digests,
            records: &self.records,
            status: self.status,
            provenance: self.provenance,
            pagination: &self.pagination,
            provider_errors: &self.provider_errors,
            raw_payload_retained: self.raw_payload_retained,
            pii_retained: self.pii_retained,
            external_write_performed: self.external_write_performed,
            composite_write_performed: self.composite_write_performed,
            email_sent: self.email_sent,
            case_comment_written: self.case_comment_written,
            approval_mutation_performed: self.approval_mutation_performed,
            native_evidence: self.native_evidence,
            inbox_authority: self.inbox_authority,
            truth_authority: self.truth_authority,
        })
    }

    pub fn validate(&self) -> Result<(), SalesforceCrmResultError> {
        if self.schema_version != crate::SALESFORCE_CRM_RESULT_SCHEMA_VERSION
            || self.contract_version != SALESFORCE_CRM_RESULT_CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.plugin_version != PluginVersion::new(1, 0, 0)
            || self.plugin_version_digest != self.plugin_version.digest()
            || self.service_id != SALESFORCE_CRM_RESULT_SERVICE_ID
            || self.provider_digest.as_str().len() != 64
            || self.raw_payload_retained
            || self.pii_retained
            || self.external_write_performed
            || self.composite_write_performed
            || self.email_sent
            || self.case_comment_written
            || self.approval_mutation_performed
            || self.native_evidence
            || self.inbox_authority
            || self.truth_authority
            || self.records.len() > crate::SALESFORCE_MAX_RECORDS
            || self.records.iter().any(|record| record.validate().is_err())
            || self.record_digests
                != self
                    .records
                    .iter()
                    .map(|record| record.record_digest.clone())
                    .collect::<Vec<_>>()
            || self.pagination.validate().is_err()
            || self.evidence_digest != self.compute_digest()
        {
            Err(SalesforceCrmResultError::EvidenceDigestMismatch)
        } else {
            Ok(())
        }
    }

    pub fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }

    pub fn is_native(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SalesforceVerification {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub scope_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub verified: bool,
    pub native: bool,
    pub independent_readback: bool,
    pub work_product_adopted: bool,
    pub verification_digest: Digest,
}

impl SalesforceVerification {
    pub(crate) fn verify(
        proposal: &SalesforceReadProposal,
        evidence: &SalesforceEvidence,
        scope: &SalesforceScope,
        provider: &SalesforceProviderDefinition,
    ) -> Result<Self, SalesforceCrmResultError> {
        proposal.validate(scope, provider)?;
        evidence.validate()?;
        if evidence.proposal_digest != proposal.proposal_digest
            || evidence.scope_digest != scope.scope_digest()
            || evidence.provider_digest != provider.provider_digest()
        {
            return Err(SalesforceCrmResultError::EvidenceDigestMismatch);
        }
        let mut verification = Self {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            scope_digest: scope.scope_digest(),
            contract_digest: contract_digest(),
            provider_digest: provider.provider_digest(),
            verified: true,
            native: false,
            independent_readback: false,
            work_product_adopted: false,
            verification_digest: Digest::from_text("placeholder"),
        };
        verification.verification_digest = canonical_digest(&(
            &verification.proposal_digest,
            &verification.evidence_digest,
            &verification.scope_digest,
            &verification.contract_digest,
            &verification.provider_digest,
            verification.verified,
            verification.native,
            verification.independent_readback,
            verification.work_product_adopted,
        ));
        Ok(verification)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SalesforceReadResult {
    pub proposal: SalesforceReadProposal,
    pub evidence: SalesforceEvidence,
    pub verification: SalesforceVerification,
}

impl SalesforceReadResult {
    pub fn validate(
        &self,
        scope: &SalesforceScope,
        provider: &SalesforceProviderDefinition,
    ) -> Result<(), SalesforceCrmResultError> {
        self.proposal.validate(scope, provider)?;
        self.evidence.validate()?;
        if self.verification.proposal_digest != self.proposal.proposal_digest
            || self.verification.evidence_digest != self.evidence.evidence_digest
            || !self.verification.verified
            || self.verification.native
            || self.verification.independent_readback
            || self.verification.work_product_adopted
        {
            return Err(SalesforceCrmResultError::EvidenceDigestMismatch);
        }
        Ok(())
    }
}

pub struct SalesforceCrmResultService<T = BlockedEnvTransport> {
    definition: SalesforceServiceDefinition,
    provider: SalesforceProvider<T>,
}

impl<T: fmt::Debug> fmt::Debug for SalesforceCrmResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SalesforceCrmResultService")
            .field("definition", &self.definition)
            .field("provider", &self.provider)
            .finish()
    }
}

impl<T: SalesforceTransport> SalesforceCrmResultService<T> {
    pub fn new(
        scope: SalesforceScope,
        secret_reference: crate::SecretReference,
        transport: T,
    ) -> Result<Self, SalesforceCrmResultError> {
        crate::SalesforceCrmResultContract::baseline()?;
        let provider = SalesforceProvider::new(scope, secret_reference, transport)?;
        Self::from_provider(provider)
    }

    pub fn from_provider(
        provider: SalesforceProvider<T>,
    ) -> Result<Self, SalesforceCrmResultError> {
        let definition = SalesforceServiceDefinition::new();
        definition.validate()?;
        provider.definition().validate()?;
        Ok(Self {
            definition,
            provider,
        })
    }

    pub fn definition(&self) -> &SalesforceServiceDefinition {
        &self.definition
    }

    pub fn describe(&self) -> Vec<SalesforceCapability> {
        self.definition.describe()
    }

    pub fn provider(&self) -> &SalesforceProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut SalesforceProvider<T> {
        &mut self.provider
    }

    pub fn scope(&self) -> &SalesforceScope {
        self.provider.scope()
    }

    pub fn registration(&self) -> &SalesforceRegistration {
        self.provider.registration()
    }

    pub fn register(&self) -> Result<SalesforceRegistration, SalesforceCrmResultError> {
        self.ensure_active()?;
        Ok(self.provider.registration().clone())
    }

    pub fn propose(
        &self,
        request: SalesforceReadRequest,
    ) -> Result<SalesforceReadProposal, SalesforceCrmResultError> {
        self.ensure_active()?;
        SalesforceReadProposal::new(self.scope(), self.provider.definition(), request)
    }

    pub fn record(
        &mut self,
        proposal: &SalesforceReadProposal,
    ) -> Result<SalesforceEvidence, SalesforceCrmResultError> {
        self.ensure_active()?;
        proposal.validate(self.scope(), self.provider.definition())?;
        let collected = match self
            .provider
            .collect(&proposal.http_request, proposal.request.max_pages)
        {
            Ok(collected) => collected,
            Err(error) => {
                return Ok(SalesforceEvidence::from_transport_error(
                    proposal,
                    self.provider.definition(),
                    &error,
                ));
            }
        };
        SalesforceEvidence::from_collected(proposal, self.provider.definition(), collected)
    }

    pub fn verify(
        &self,
        proposal: &SalesforceReadProposal,
        evidence: &SalesforceEvidence,
    ) -> Result<SalesforceVerification, SalesforceCrmResultError> {
        SalesforceVerification::verify(proposal, evidence, self.scope(), self.provider.definition())
    }

    pub fn read(
        &mut self,
        request: SalesforceReadRequest,
    ) -> Result<SalesforceReadResult, SalesforceCrmResultError> {
        let proposal = self.propose(request)?;
        let evidence = self.record(&proposal)?;
        let verification = self.verify(&proposal, &evidence)?;
        Ok(SalesforceReadResult {
            proposal,
            evidence,
            verification,
        })
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<crate::RevocationReceipt, SalesforceCrmResultError> {
        self.provider.revoke_registration()
    }

    pub fn restore_registration(&mut self) -> Result<(), SalesforceCrmResultError> {
        self.provider.restore_registration()
    }

    pub fn revoke_secret(&mut self) -> Result<(), SalesforceCrmResultError> {
        self.provider.revoke_secret()
    }

    pub fn restore_secret(&mut self) -> Result<(), SalesforceCrmResultError> {
        self.provider.restore_secret()
    }

    fn ensure_active(&self) -> Result<(), SalesforceCrmResultError> {
        if !self.provider.registration().is_active() {
            return Err(SalesforceCrmResultError::RegistrationRevoked);
        }
        if self.provider.secret_reference().is_revoked() {
            return Err(SalesforceCrmResultError::SecretRevoked);
        }
        Ok(())
    }
}

pub fn provider_error_kind_for_status(status_code: u16) -> ProviderErrorKind {
    match status_code {
        400 => ProviderErrorKind::BadRequest,
        401 => ProviderErrorKind::Unauthenticated,
        403 => ProviderErrorKind::PermissionDenied,
        404 => ProviderErrorKind::NotFound,
        409 => ProviderErrorKind::Conflict,
        429 => ProviderErrorKind::RateLimited,
        500..=599 => ProviderErrorKind::ServerFailure,
        _ => ProviderErrorKind::Unknown,
    }
}

fn status_for_provider_error(kind: ProviderErrorKind) -> SalesforceResultStatus {
    match kind {
        ProviderErrorKind::Unauthenticated | ProviderErrorKind::PermissionDenied => {
            SalesforceResultStatus::AccessLost
        }
        ProviderErrorKind::NotFound => SalesforceResultStatus::NotFound,
        ProviderErrorKind::RateLimited
        | ProviderErrorKind::ServerFailure
        | ProviderErrorKind::Timeout
        | ProviderErrorKind::BlockedEnv
        | ProviderErrorKind::Unknown => SalesforceResultStatus::ProviderUnknown,
        ProviderErrorKind::BadRequest
        | ProviderErrorKind::Conflict
        | ProviderErrorKind::Decode
        | ProviderErrorKind::Pagination
        | ProviderErrorKind::Tampered => SalesforceResultStatus::FinalError,
    }
}

impl From<SalesforceTransportError> for SalesforceCrmResultError {
    fn from(error: SalesforceTransportError) -> Self {
        Self::Transport(error.to_string())
    }
}

#[allow(dead_code)]
fn _service_contract_constants() -> (&'static str, &'static str, &'static str, &'static str) {
    (
        SALESFORCE_CRM_RESULT_SERVICE_SCHEMA,
        SALESFORCE_CRM_RESULT_PLUGIN_VERSION_TEXT,
        MISSION_SALESFORCE_CRM_CONSUMER_ID,
        SALESFORCE_CRM_RESULT_SERVICE_ID,
    )
}

#[allow(dead_code)]
fn _query_seams() -> BTreeSet<QuerySeam> {
    [QuerySeam::RestSoql, QuerySeam::GraphQl]
        .into_iter()
        .collect()
}

//! Mission-scoped SailPoint certification service. All provider operations are
//! bounded GET reads; proposal, recording, and verification are local typed
//! seams with no external effects.

use std::{collections::BTreeSet, fmt};

use crate::{
    AccessSummary, CampaignState, CertificationRecord, DecisionCounts, DecisionState, Digest,
    SAILPOINT_CONTRACT_VERSION, SAILPOINT_MAX_LIMIT, SAILPOINT_PLUGIN_VERSION_TEXT,
    SAILPOINT_PROVIDER_ID, SAILPOINT_PROVIDER_IMPLEMENTATION, SailPointCertificationEvidence,
    SailPointCertificationProjection, SailPointCertificationResultError, SailPointEndpoint,
    SailPointEvidenceProposal, SailPointProvider, SailPointProviderError, SailPointReadEvidence,
    SailPointReadRequest, SailPointRegistration, SailPointResponseBody, SailPointTransport,
    SecretReference, contract_digest,
};
use chrono::{DateTime, Utc};

pub const SAILPOINT_EVIDENCE_POLICY_SCHEMA: &str =
    "hartevo.sailpoint-certification-evidence-allowlist/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SailPointServiceOperation {
    DescribeCapabilities,
    Register,
    RevokeRegistration,
    ReadCertification,
    ReadCampaign,
    ReadAccessSummary,
    CompileEvidenceProposal,
    RecordProposal,
    VerifyProposal,
}

impl SailPointServiceOperation {
    pub const ALL: [Self; 9] = [
        Self::DescribeCapabilities,
        Self::Register,
        Self::RevokeRegistration,
        Self::ReadCertification,
        Self::ReadCampaign,
        Self::ReadAccessSummary,
        Self::CompileEvidenceProposal,
        Self::RecordProposal,
        Self::VerifyProposal,
    ];

    pub const fn is_provider_write(self) -> bool {
        false
    }

    pub const fn is_read_only(self) -> bool {
        !matches!(self, Self::Register | Self::RevokeRegistration)
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::DescribeCapabilities => "describe_capabilities",
            Self::Register => "register",
            Self::RevokeRegistration => "revoke_registration",
            Self::ReadCertification => "read_certification",
            Self::ReadCampaign => "read_campaign",
            Self::ReadAccessSummary => "read_access_summary",
            Self::CompileEvidenceProposal => "compile_evidence_proposal",
            Self::RecordProposal => "record_proposal",
            Self::VerifyProposal => "verify_proposal",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SailPointCapability {
    pub operation: SailPointServiceOperation,
    pub read_only: bool,
    pub bounded: bool,
    pub arbitrary_query: bool,
    pub provider_write: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SailPointEvidenceProposalRequest {
    pub observed_at: DateTime<Utc>,
    pub limit: u32,
    pub offset: u32,
}

impl SailPointEvidenceProposalRequest {
    pub fn new(observed_at: DateTime<Utc>) -> Self {
        Self {
            observed_at,
            limit: 50,
            offset: 0,
        }
    }

    #[must_use]
    pub fn with_bounds(mut self, limit: u32, offset: u32) -> Self {
        self.limit = limit;
        self.offset = offset;
        self
    }
}

/// The typed SailPoint certification service.
pub struct SailPointCertificationService<T> {
    scope: crate::SailPointCertificationScope,
    secret: SecretReference,
    provider: SailPointProvider<T>,
    registration: SailPointRegistration,
    recorded_proposals: BTreeSet<Digest>,
}

impl<T: SailPointTransport> fmt::Debug for SailPointCertificationService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SailPointCertificationService")
            .field("scope", &self.scope)
            .field("secret", &self.secret)
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .field("recorded_proposals", &self.recorded_proposals.len())
            .finish()
    }
}

impl<T: SailPointTransport> SailPointCertificationService<T> {
    pub fn new(
        scope: crate::SailPointCertificationScope,
        secret: SecretReference,
        provider: SailPointProvider<T>,
    ) -> Result<Self, SailPointCertificationResultError> {
        scope.validate()?;
        crate::SailPointCertificationContract::baseline()?;
        provider
            .definition()
            .validate()
            .map_err(|error| SailPointCertificationResultError::Provider(error.to_string()))?;
        if provider.permission_digest() != scope.permission_digest() {
            return Err(SailPointCertificationResultError::ProviderMismatch);
        }
        let evidence_digest = Digest::from_text(SAILPOINT_EVIDENCE_POLICY_SCHEMA);
        let registration = SailPointRegistration::new(
            &scope,
            contract_digest(),
            provider.provider_digest(),
            provider.permission_digest().clone(),
            evidence_digest,
        );
        Ok(Self {
            scope,
            secret,
            provider,
            registration,
            recorded_proposals: BTreeSet::new(),
        })
    }

    pub fn register(
        &mut self,
    ) -> Result<&SailPointRegistration, SailPointCertificationResultError> {
        self.ensure_registration()?;
        Ok(&self.registration)
    }

    pub fn scope(&self) -> &crate::SailPointCertificationScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret
    }

    pub fn registration(&self) -> &SailPointRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut SailPointRegistration {
        &mut self.registration
    }

    pub fn provider(&self) -> &SailPointProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut SailPointProvider<T> {
        &mut self.provider
    }

    pub fn is_active(&self) -> bool {
        self.registration.is_active() && !self.secret.is_revoked()
    }

    pub fn revoke_registration(&mut self) -> Result<(), SailPointCertificationResultError> {
        self.registration
            .revoke()
            .map_err(SailPointCertificationResultError::from)
    }

    pub fn revoke_secret(&mut self) -> Result<(), SailPointCertificationResultError> {
        self.secret
            .revoke()
            .map_err(SailPointCertificationResultError::from)
    }

    pub fn service_id(&self) -> &'static str {
        crate::SAILPOINT_SERVICE_ID
    }

    pub fn service_implementation(&self) -> &'static str {
        crate::SAILPOINT_SERVICE_IMPLEMENTATION
    }

    pub const fn version(&self) -> hartevo_plugin_runtime::PluginVersion {
        crate::plugin_version()
    }

    pub const fn native_connected(&self) -> bool {
        false
    }

    pub fn describe_capabilities(&self) -> Vec<SailPointCapability> {
        SailPointServiceOperation::ALL
            .into_iter()
            .map(|operation| SailPointCapability {
                operation,
                read_only: operation.is_read_only(),
                bounded: true,
                arbitrary_query: false,
                provider_write: operation.is_provider_write(),
            })
            .collect()
    }

    pub fn read(
        &mut self,
        endpoint: SailPointEndpoint,
        limit: u32,
        offset: u32,
        observed_at: DateTime<Utc>,
    ) -> Result<SailPointReadEvidence, SailPointCertificationResultError> {
        self.ensure_registration()?;
        let request = SailPointReadRequest::new(endpoint, &self.scope, limit, offset, observed_at)?;
        let mut evidence = self
            .provider
            .read_with_secret(&request, &self.secret)
            .map_err(Self::map_provider_error)?;
        self.filter_read_evidence(&mut evidence)?;
        Ok(evidence)
    }

    pub fn read_certification(
        &mut self,
        observed_at: DateTime<Utc>,
    ) -> Result<SailPointReadEvidence, SailPointCertificationResultError> {
        self.read(
            SailPointEndpoint::Certification {
                certification_id: self.scope.certification_id().clone(),
            },
            1,
            0,
            observed_at,
        )
    }

    pub fn read_campaign(
        &mut self,
        limit: u32,
        offset: u32,
        observed_at: DateTime<Utc>,
    ) -> Result<SailPointReadEvidence, SailPointCertificationResultError> {
        self.read(SailPointEndpoint::Campaigns, limit, offset, observed_at)
    }

    pub fn read_access_summary(
        &mut self,
        limit: u32,
        offset: u32,
        observed_at: DateTime<Utc>,
    ) -> Result<SailPointReadEvidence, SailPointCertificationResultError> {
        self.read(
            SailPointEndpoint::AccessSummaries {
                certification_id: self.scope.certification_id().clone(),
                access_type: self.scope.access_type(),
            },
            limit,
            offset,
            observed_at,
        )
    }

    pub fn propose(
        &mut self,
        request: SailPointEvidenceProposalRequest,
    ) -> Result<SailPointEvidenceProposal, SailPointCertificationResultError> {
        self.ensure_registration()?;
        if request.limit == 0 || request.limit > SAILPOINT_MAX_LIMIT {
            return Err(SailPointCertificationResultError::InvalidInput(
                "proposal page limit is outside the contract budget".to_owned(),
            ));
        }

        let certification_read = match self.read_certification(request.observed_at) {
            Ok(read) => Some(read),
            Err(error) if is_projection_error(&error) => {
                return self.proposal_for_provider_error(error, request.observed_at);
            }
            Err(error) => return Err(error),
        };
        let mut access_lost = false;
        let mut provider_unknown = false;
        let campaign_read =
            match self.read_campaign(request.limit, request.offset, request.observed_at) {
                Ok(read) => Some(read),
                Err(error) if is_projection_error(&error) => {
                    let (lost, unknown) = projection_flags(&error);
                    access_lost |= lost;
                    provider_unknown |= unknown;
                    None
                }
                Err(error) => return Err(error),
            };
        let access_read =
            match self.read_access_summary(request.limit, request.offset, request.observed_at) {
                Ok(read) => Some(read),
                Err(error) if is_projection_error(&error) => {
                    let (lost, unknown) = projection_flags(&error);
                    access_lost |= lost;
                    provider_unknown |= unknown;
                    None
                }
                Err(error) => return Err(error),
            };

        let certification = certification_read
            .as_ref()
            .and_then(|read| match &read.body {
                SailPointResponseBody::Certification(record) => Some(record.clone()),
                _ => None,
            });
        if let Some(record) = &certification {
            self.validate_certification_record(record)?;
        }

        let campaign_records = campaign_read
            .as_ref()
            .and_then(|read| match &read.body {
                SailPointResponseBody::Campaigns(records) => Some(records.clone()),
                _ => None,
            })
            .unwrap_or_default()
            .into_iter()
            .filter(|record| self.record_is_in_scope(record))
            .collect::<Vec<_>>();
        let access_summaries = access_read
            .as_ref()
            .and_then(|read| match &read.body {
                SailPointResponseBody::AccessSummaries(records) => Some(records.clone()),
                _ => None,
            })
            .unwrap_or_default()
            .into_iter()
            .filter(|summary| self.access_is_in_scope(summary))
            .collect::<Vec<_>>();

        let reads = [
            certification_read.as_ref(),
            campaign_read.as_ref(),
            access_read.as_ref(),
        ];
        let partial = reads
            .iter()
            .any(|read| read.is_none_or(|value| value.partial))
            || campaign_read.is_none()
            || access_read.is_none()
            || campaign_records.is_empty()
            || access_summaries.is_empty();
        let campaign_state = certification
            .as_ref()
            .map_or(CampaignState::Unknown, |record| record.campaign.state);
        let mut counts = DecisionCounts::default();
        for summary in &access_summaries {
            counts.add_decision(summary.decision_state);
        }
        let mut decision_state = if counts.total == 0 {
            certification
                .as_ref()
                .map_or(DecisionState::Pending, |record| record.decision_state)
        } else {
            counts.decision_state()
        };
        if partial
            && matches!(
                decision_state,
                DecisionState::Approved | DecisionState::Revoked
            )
        {
            decision_state = DecisionState::Partial;
        }
        let mut receipts = Vec::new();
        let mut sources = Vec::new();
        let mut provider_revision = self.provider.provider_revision().clone();
        for read in reads.into_iter().flatten() {
            receipts.push(read.response_receipt.clone());
            sources.push(read.source_digest.clone());
            provider_revision = read.response_receipt.provider_revision.clone();
        }
        let source_digest = Digest::from_fields(sources.iter().map(Digest::as_str));
        let mut evidence = SailPointCertificationEvidence {
            certification,
            campaign_records,
            access_summaries,
            read_receipts: receipts,
            provider_revision,
            source_digest,
            evidence_digest: Digest::zero(),
            raw_identity_payload_retained: false,
            raw_access_payload_retained: false,
            reviewer_pii_retained: false,
            identity_pii_retained: false,
            entitlement_descriptions_retained: false,
            reviewer_comments_retained: false,
        };
        evidence.evidence_digest = evidence.recompute_digest()?;
        let proposal = SailPointEvidenceProposal {
            scope_digest: self.scope.scope_digest().clone(),
            registration_digest: self.registration.registration_digest.clone(),
            campaign_revision: self.scope.campaign_revision(),
            evidence,
            projection: SailPointCertificationProjection {
                campaign_state,
                decision_state,
                partial,
                access_lost,
                provider_unknown,
                stale_revision: false,
                duplicate_detected: false,
                access_safety_claim: false,
                native: false,
                connected: false,
                first_party: false,
            },
            read_only: true,
            proposal_only: true,
            native: false,
            connected: false,
            first_party: false,
            certification_approved: false,
            certification_revoked: false,
            certification_finalized: false,
            access_request_submitted: false,
            identity_mutated: false,
            entitlement_mutated: false,
            adopted_by_kernel: false,
            proposal_digest: Digest::zero(),
        };
        let mut proposal = proposal;
        proposal.proposal_digest = proposal.recompute_digest()?;
        Ok(proposal)
    }

    pub fn compile_evidence_proposal(
        &mut self,
        request: SailPointEvidenceProposalRequest,
    ) -> Result<SailPointEvidenceProposal, SailPointCertificationResultError> {
        self.propose(request)
    }

    pub fn compile_proposal(
        &mut self,
        request: SailPointEvidenceProposalRequest,
    ) -> Result<SailPointEvidenceProposal, SailPointCertificationResultError> {
        self.propose(request)
    }

    pub fn record(
        &mut self,
        proposal: &SailPointEvidenceProposal,
    ) -> Result<crate::SailPointRecordingReceipt, SailPointCertificationResultError> {
        self.verify(proposal)?;
        if !self
            .recorded_proposals
            .insert(proposal.proposal_digest.clone())
        {
            return Err(SailPointCertificationResultError::StaleProposal);
        }
        Ok(crate::SailPointRecordingReceipt {
            recorded: true,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            provider_mutated: false,
            raw_provider_payload_retained: false,
            credential_material_retained: false,
        })
    }

    pub fn verify(
        &self,
        proposal: &SailPointEvidenceProposal,
    ) -> Result<crate::SailPointVerification, SailPointCertificationResultError> {
        self.ensure_registration()?;
        if proposal.scope_digest != *self.scope.scope_digest()
            || proposal.registration_digest != self.registration.registration_digest
            || proposal.campaign_revision != self.scope.campaign_revision()
            || proposal.proposal_digest != proposal.recompute_digest()?
            || proposal.evidence.evidence_digest != proposal.evidence.recompute_digest()?
            || !proposal.read_only
            || !proposal.proposal_only
            || proposal.native
            || proposal.connected
            || proposal.first_party
            || proposal.certification_approved
            || proposal.certification_revoked
            || proposal.certification_finalized
            || proposal.access_request_submitted
            || proposal.identity_mutated
            || proposal.entitlement_mutated
            || proposal.adopted_by_kernel
            || proposal.projection.access_safety_claim
        {
            return Err(SailPointCertificationResultError::StaleProposal);
        }
        Ok(crate::SailPointVerification {
            verified: true,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            provider_readback_performed: false,
            certification_decision_authority: false,
            access_safety_authority: false,
            consent_authority: false,
            outcome_authority: false,
        })
    }

    fn validate_certification_record(
        &self,
        record: &CertificationRecord,
    ) -> Result<(), SailPointCertificationResultError> {
        if record.id != *self.scope.certification_id()
            || record.campaign.id != *self.scope.campaign_id()
            || record.campaign.revision != self.scope.campaign_revision()
            || record.reviewer_id != *self.scope.reviewer_id()
            || record.identity_id != *self.scope.identity_id()
        {
            return Err(SailPointCertificationResultError::ScopeMismatch(
                "certification, campaign, reviewer, identity, or campaign revision drifted"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    fn record_is_in_scope(&self, record: &CertificationRecord) -> bool {
        record.campaign.id == *self.scope.campaign_id()
            && record.campaign.revision == self.scope.campaign_revision()
            && record.reviewer_id == *self.scope.reviewer_id()
            && record.identity_id == *self.scope.identity_id()
    }

    fn access_is_in_scope(&self, summary: &AccessSummary) -> bool {
        summary.access_type == self.scope.access_type()
            && summary.campaign_revision == self.scope.campaign_revision()
            && summary.reviewer_id == *self.scope.reviewer_id()
            && summary.identity_id == *self.scope.identity_id()
            && self
                .scope
                .entitlement_id()
                .is_none_or(|expected| summary.entitlement_id.as_ref() == Some(expected))
            && self
                .scope
                .entitlement_revision()
                .is_none_or(|expected| summary.entitlement_revision == Some(expected))
    }

    fn filter_read_evidence(
        &self,
        evidence: &mut SailPointReadEvidence,
    ) -> Result<(), SailPointCertificationResultError> {
        match &evidence.body {
            SailPointResponseBody::Certification(record) => {
                self.validate_certification_record(record)?;
            }
            SailPointResponseBody::Campaigns(records) => {
                let filtered = records
                    .iter()
                    .filter(|record| self.record_is_in_scope(record))
                    .cloned()
                    .collect::<Vec<_>>();
                evidence.body = SailPointResponseBody::campaigns(filtered)?;
            }
            SailPointResponseBody::AccessSummaries(records) => {
                let filtered = records
                    .iter()
                    .filter(|summary| self.access_is_in_scope(summary))
                    .cloned()
                    .collect::<Vec<_>>();
                evidence.body = SailPointResponseBody::access_summaries(filtered)?;
            }
        }
        if let Some(total) = evidence.response_receipt.total_count {
            evidence.partial = evidence.partial
                || total
                    > evidence
                        .request_receipt
                        .offset
                        .saturating_add(evidence.body.len() as u32);
        }
        evidence.evidence_digest = evidence.recompute_digest()?;
        Ok(())
    }

    fn ensure_registration(&self) -> Result<(), SailPointCertificationResultError> {
        if !self.registration.is_active() {
            return Err(SailPointCertificationResultError::RegistrationRevoked);
        }
        if self.secret.is_revoked() {
            return Err(SailPointCertificationResultError::SecretRevoked);
        }
        self.registration.validate(&self.scope).map_err(|error| {
            SailPointCertificationResultError::RegistrationDrift(error.to_string())
        })?;
        let provider = self.provider.definition();
        provider
            .validate()
            .map_err(|error| SailPointCertificationResultError::Provider(error.to_string()))?;
        if self.registration.provider_digest != self.provider.provider_digest()
            || self.registration.permission_digest != *self.provider.permission_digest()
            || self.registration.provider_revision != *self.provider.provider_revision()
            || self.registration.provider_id != SAILPOINT_PROVIDER_ID
            || self.registration.provider_implementation != SAILPOINT_PROVIDER_IMPLEMENTATION
            || self.registration.provider_version != SAILPOINT_PLUGIN_VERSION_TEXT
            || self.registration.contract_version != SAILPOINT_CONTRACT_VERSION
        {
            return Err(SailPointCertificationResultError::RegistrationDrift(
                "provider or contract digest fence failed".to_owned(),
            ));
        }
        Ok(())
    }

    fn proposal_for_provider_error(
        &self,
        error: SailPointCertificationResultError,
        _observed_at: DateTime<Utc>,
    ) -> Result<SailPointEvidenceProposal, SailPointCertificationResultError> {
        let (access_lost, provider_unknown) = match error {
            SailPointCertificationResultError::AccessLost => (true, false),
            SailPointCertificationResultError::BlockedEnv => (false, true),
            _ => (false, true),
        };
        let mut evidence = SailPointCertificationEvidence {
            certification: None,
            campaign_records: Vec::new(),
            access_summaries: Vec::new(),
            read_receipts: Vec::new(),
            provider_revision: self.provider.provider_revision().clone(),
            source_digest: Digest::from_text("sailpoint-provider-unknown"),
            evidence_digest: Digest::zero(),
            raw_identity_payload_retained: false,
            raw_access_payload_retained: false,
            reviewer_pii_retained: false,
            identity_pii_retained: false,
            entitlement_descriptions_retained: false,
            reviewer_comments_retained: false,
        };
        evidence.evidence_digest = evidence.recompute_digest()?;
        let mut proposal = SailPointEvidenceProposal {
            scope_digest: self.scope.scope_digest().clone(),
            registration_digest: self.registration.registration_digest.clone(),
            campaign_revision: self.scope.campaign_revision(),
            evidence,
            projection: SailPointCertificationProjection {
                campaign_state: CampaignState::Unknown,
                decision_state: DecisionState::Pending,
                partial: true,
                access_lost,
                provider_unknown,
                stale_revision: false,
                duplicate_detected: false,
                access_safety_claim: false,
                native: false,
                connected: false,
                first_party: false,
            },
            read_only: true,
            proposal_only: true,
            native: false,
            connected: false,
            first_party: false,
            certification_approved: false,
            certification_revoked: false,
            certification_finalized: false,
            access_request_submitted: false,
            identity_mutated: false,
            entitlement_mutated: false,
            adopted_by_kernel: false,
            proposal_digest: Digest::zero(),
        };
        proposal.proposal_digest = proposal.recompute_digest()?;
        Ok(proposal)
    }

    fn map_provider_error(error: SailPointProviderError) -> SailPointCertificationResultError {
        match error {
            SailPointProviderError::RateLimited {
                retry_after_seconds,
            } => SailPointCertificationResultError::RateLimited {
                retry_after_seconds,
            },
            SailPointProviderError::AccessLost => SailPointCertificationResultError::AccessLost,
            SailPointProviderError::BlockedEnv => SailPointCertificationResultError::BlockedEnv,
            SailPointProviderError::SecretRevoked => {
                SailPointCertificationResultError::SecretRevoked
            }
            SailPointProviderError::StaleCampaignRevision => {
                SailPointCertificationResultError::StaleCampaignRevision
            }
            SailPointProviderError::StaleEntitlementRevision => {
                SailPointCertificationResultError::StaleEntitlementRevision
            }
            SailPointProviderError::DuplicateIdentifier => {
                SailPointCertificationResultError::DuplicateIdentifier
            }
            SailPointProviderError::ResponseTampered => {
                SailPointCertificationResultError::ResponseTampered
            }
            SailPointProviderError::PaginationDrift => {
                SailPointCertificationResultError::PaginationDrift
            }
            SailPointProviderError::ProviderRevisionMismatch => {
                SailPointCertificationResultError::ProviderRevisionMismatch
            }
            SailPointProviderError::Model(error) => SailPointCertificationResultError::Model(error),
            SailPointProviderError::Transport(error) => {
                SailPointCertificationResultError::Transport(error)
            }
            other => SailPointCertificationResultError::Provider(other.to_string()),
        }
    }
}

fn is_projection_error(error: &SailPointCertificationResultError) -> bool {
    matches!(
        error,
        SailPointCertificationResultError::BlockedEnv
            | SailPointCertificationResultError::AccessLost
            | SailPointCertificationResultError::Transport(_)
            | SailPointCertificationResultError::Provider(_)
    )
}

fn projection_flags(error: &SailPointCertificationResultError) -> (bool, bool) {
    match error {
        SailPointCertificationResultError::AccessLost => (true, false),
        SailPointCertificationResultError::BlockedEnv => (false, true),
        _ => (false, true),
    }
}

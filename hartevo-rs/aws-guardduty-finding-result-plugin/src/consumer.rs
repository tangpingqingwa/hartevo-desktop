//! Mission-bound GuardDuty consumer below Hartevo kernel authority.

use std::collections::BTreeSet;

use serde::Serialize;

use crate::model::{
    AwsGuardDutyFinding, AwsGuardDutyFindingEvidence, AwsGuardDutyFindingScope, DetectorDiscovery,
    Digest, EvidenceStatus, FindingIdAllowlist, FindingStatus, GuardDutyFindingQuery,
    PartialReason, TransportProvenance, failure_digest,
};
use crate::provider::{
    AwsGuardDutyProvider, AwsGuardDutyTransport, GetFindingsRequest, ListDetectorsRequest,
    ListFindingsRequest, Operation, RequestReceipt, StatisticsRequest,
};
use crate::service::{
    AwsGuardDutyFindingProposal, AwsGuardDutyFindingRecord, AwsGuardDutyFindingService,
    AwsGuardDutyRegistration, VerificationReport,
};
use crate::{AwsGuardDutyFindingResultError, Result};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionAwsGuardDutyObservation {
    pub evidence_digest: Digest,
    pub scope_digest: Digest,
    pub status: EvidenceStatus,
    pub finding_count: usize,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub truth_authority: bool,
    pub consent_authority: bool,
    pub effect_authority: bool,
    pub receipt_authority: bool,
    pub verification_authority: bool,
    pub outcome_authority: bool,
    pub adopted: bool,
}

impl MissionAwsGuardDutyObservation {
    fn from_evidence(evidence: &AwsGuardDutyFindingEvidence) -> Self {
        Self {
            evidence_digest: evidence.evidence_digest.clone(),
            scope_digest: evidence.scope_digest.clone(),
            status: evidence.status.clone(),
            finding_count: evidence.findings.len(),
            provenance: evidence.provenance,
            connected: false,
            native: false,
            first_party: false,
            truth_authority: false,
            consent_authority: false,
            effect_authority: false,
            receipt_authority: false,
            verification_authority: false,
            outcome_authority: false,
            adopted: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionAwsGuardDutyResult {
    pub evidence: AwsGuardDutyFindingEvidence,
    pub observation: MissionAwsGuardDutyObservation,
    pub result_digest: Digest,
    pub adopted: bool,
}

impl MissionAwsGuardDutyResult {
    fn new(evidence: AwsGuardDutyFindingEvidence) -> Self {
        let observation = MissionAwsGuardDutyObservation::from_evidence(&evidence);
        let result_digest = Digest::from_fields(
            "hartevo.aws-guardduty-mission-result/v1",
            &[
                evidence.evidence_digest.as_str().to_owned(),
                evidence.scope_digest.as_str().to_owned(),
                serde_json::to_string(&evidence.status).expect("evidence status serializes"),
            ],
        );
        Self {
            evidence,
            observation,
            result_digest,
            adopted: false,
        }
    }

    pub fn validate(
        &self,
        scope: &AwsGuardDutyFindingScope,
        query: &GuardDutyFindingQuery,
    ) -> Result<()> {
        self.evidence.validate(scope, query)?;
        let expected_observation = MissionAwsGuardDutyObservation::from_evidence(&self.evidence);
        let expected_digest = Digest::from_fields(
            "hartevo.aws-guardduty-mission-result/v1",
            &[
                self.evidence.evidence_digest.as_str().to_owned(),
                self.evidence.scope_digest.as_str().to_owned(),
                serde_json::to_string(&self.evidence.status).expect("evidence status serializes"),
            ],
        );
        if self.observation != expected_observation
            || self.result_digest != expected_digest
            || self.adopted
            || self.observation.connected
            || self.observation.native
            || self.observation.first_party
            || self.observation.truth_authority
            || self.observation.consent_authority
            || self.observation.effect_authority
            || self.observation.receipt_authority
            || self.observation.verification_authority
            || self.observation.outcome_authority
        {
            return Err(AwsGuardDutyFindingResultError::TamperedEvidence);
        }
        Ok(())
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

pub struct MissionAwsGuardDutyConsumer {
    scope: AwsGuardDutyFindingScope,
    registration: Option<AwsGuardDutyRegistration>,
    service: AwsGuardDutyFindingService,
}

impl std::fmt::Debug for MissionAwsGuardDutyConsumer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MissionAwsGuardDutyConsumer")
            .field("scope", &self.scope)
            .field("registration", &self.registration)
            .field("service", &self.service)
            .finish()
    }
}

impl MissionAwsGuardDutyConsumer {
    pub fn new(scope: AwsGuardDutyFindingScope) -> Result<Self> {
        scope.validate()?;
        Ok(Self {
            scope,
            registration: None,
            service: AwsGuardDutyFindingService::new(),
        })
    }

    pub fn with_registration(
        scope: AwsGuardDutyFindingScope,
        registration: AwsGuardDutyRegistration,
    ) -> Result<Self> {
        let consumer = Self::new(scope)?;
        if consumer.scope != *registration.scope() {
            return Err(AwsGuardDutyFindingResultError::ScopeDrift);
        }
        registration.validate()?;
        if !registration.is_active() {
            return Err(AwsGuardDutyFindingResultError::RegistrationRevoked);
        }
        Ok(Self {
            scope: consumer.scope,
            registration: Some(registration),
            service: consumer.service,
        })
    }

    pub fn bind_registration(&mut self, registration: AwsGuardDutyRegistration) -> Result<()> {
        if registration.scope() != &self.scope {
            return Err(AwsGuardDutyFindingResultError::ScopeDrift);
        }
        registration.validate()?;
        if !registration.is_active() {
            return Err(AwsGuardDutyFindingResultError::RegistrationRevoked);
        }
        self.registration = Some(registration);
        Ok(())
    }

    pub fn scope(&self) -> &AwsGuardDutyFindingScope {
        &self.scope
    }

    pub fn registration(&self) -> Option<&AwsGuardDutyRegistration> {
        self.registration.as_ref()
    }

    pub fn service(&self) -> &AwsGuardDutyFindingService {
        &self.service
    }

    pub fn revoke_registration(&mut self, transition_revision: u64) -> Result<()> {
        self.service.revoke_registration(
            self.registration
                .as_mut()
                .ok_or(AwsGuardDutyFindingResultError::RegistrationMissing)?,
            transition_revision,
        )
    }

    pub fn reverse_registration(&mut self, transition_revision: u64) -> Result<()> {
        self.service.reverse_registration(
            self.registration
                .as_mut()
                .ok_or(AwsGuardDutyFindingResultError::RegistrationMissing)?,
            transition_revision,
        )
    }

    pub fn read<T: AwsGuardDutyTransport>(
        &self,
        provider: &mut AwsGuardDutyProvider<T>,
        query: &GuardDutyFindingQuery,
    ) -> Result<MissionAwsGuardDutyResult> {
        let registration = self
            .registration
            .as_ref()
            .ok_or(AwsGuardDutyFindingResultError::RegistrationMissing)?;
        registration.validate()?;
        if !registration.is_active() {
            return Err(AwsGuardDutyFindingResultError::RegistrationRevoked);
        }
        query.validate()?;
        if registration.scope() != &self.scope || registration.query() != query {
            return Err(AwsGuardDutyFindingResultError::QueryDrift);
        }
        provider.definition().validate()?;
        if provider.provider_digest() != registration.provider_digest()
            || provider.api_digest() != registration.api_digest()
            || provider.permission_digest() != registration.permission_digest()
        {
            return Err(AwsGuardDutyFindingResultError::InvalidRegistration);
        }

        let detector_request = ListDetectorsRequest::new(&self.scope)?;
        let detector_response = match provider.list_detectors(&detector_request) {
            Ok(response) => response,
            Err(AwsGuardDutyFindingResultError::Transport(error)) => {
                return self.failure_result(
                    provider,
                    query,
                    DetectorDiscovery::new(
                        Vec::new(),
                        false,
                        failure_digest("ListDetectors", error.failure.as_str()),
                    )?,
                    Vec::new(),
                    None,
                    vec![RequestReceipt::failure(
                        Operation::ListDetectors,
                        detector_request.request_digest,
                        error.failure,
                    )],
                    error.failure.evidence_status(),
                    None,
                );
            }
            Err(error) => return Err(error),
        };
        let detector_discovery = detector_response.discovery()?;
        let mut receipts = vec![detector_response.receipt.clone()];
        if !detector_discovery.complete {
            return self.failure_result(
                provider,
                query,
                detector_discovery,
                Vec::new(),
                None,
                receipts,
                EvidenceStatus::Partial,
                Some(PartialReason::ProviderMarkedPartial),
            );
        }
        if !detector_discovery.contains(&self.scope.detector_id) {
            return Err(AwsGuardDutyFindingResultError::DetectorDrift);
        }

        let mut list_request = ListFindingsRequest::first(&self.scope, query)?;
        let mut seen_page_tokens = BTreeSet::new();
        let mut seen_finding_ids = BTreeSet::new();
        let mut findings = Vec::new();
        let mut statistics = None;
        let mut status = EvidenceStatus::Complete;
        let mut partial_reason = None;

        loop {
            let list_response = match provider.list_findings(&list_request) {
                Ok(response) => response,
                Err(AwsGuardDutyFindingResultError::Transport(error)) => {
                    receipts.push(RequestReceipt::failure(
                        Operation::ListFindings,
                        list_request.request_digest.clone(),
                        error.failure,
                    ));
                    return self.failure_result(
                        provider,
                        query,
                        detector_discovery,
                        findings,
                        statistics,
                        receipts,
                        error.failure.evidence_status(),
                        None,
                    );
                }
                Err(error) => return Err(error),
            };
            receipts.push(list_response.receipt.clone());
            if list_response.partial {
                status = EvidenceStatus::Partial;
                partial_reason = Some(PartialReason::ProviderMarkedPartial);
            }
            for finding_id in &list_response.finding_ids {
                if !seen_finding_ids.insert(finding_id.clone()) {
                    return Err(AwsGuardDutyFindingResultError::CriteriaReplay);
                }
            }
            if !list_response.finding_ids.is_empty() {
                let allowlist = FindingIdAllowlist::new(
                    list_response.finding_ids.clone(),
                    list_response.response_digest.clone(),
                    &self.scope,
                    query,
                )?;
                let get_request = GetFindingsRequest::new(&self.scope, query, allowlist)?;
                let get_response = match provider.get_findings(&get_request) {
                    Ok(response) => response,
                    Err(AwsGuardDutyFindingResultError::Transport(error)) => {
                        receipts.push(RequestReceipt::failure(
                            Operation::GetFindings,
                            get_request.request_digest.clone(),
                            error.failure,
                        ));
                        return self.failure_result(
                            provider,
                            query,
                            detector_discovery,
                            findings,
                            statistics,
                            receipts,
                            error.failure.evidence_status(),
                            None,
                        );
                    }
                    Err(error) => return Err(error),
                };
                receipts.push(get_response.receipt.clone());
                if get_response.partial || !get_response.missing_ids.is_empty() {
                    status = EvidenceStatus::Partial;
                    partial_reason = Some(PartialReason::MissingBatchItems);
                }
                for finding in get_response.findings {
                    if !query.criteria.matches(&finding) {
                        return Err(AwsGuardDutyFindingResultError::CriteriaReplay);
                    }
                    if !seen_finding_ids.contains(&finding.finding_id) {
                        return Err(AwsGuardDutyFindingResultError::FindingOutOfAllowlist);
                    }
                    if finding.status == FindingStatus::Archived {
                        status = EvidenceStatus::Archived;
                    } else if finding.status == FindingStatus::Stale {
                        status = EvidenceStatus::Stale;
                    } else if finding.non_adoptable() && status == EvidenceStatus::Complete {
                        status = EvidenceStatus::Unknown;
                    }
                    if findings.len() >= query.max_findings {
                        status = EvidenceStatus::Partial;
                        partial_reason = Some(PartialReason::FindingLimitReached);
                        break;
                    }
                    findings.push(finding);
                }
            }
            if list_response.next_page.is_none() {
                break;
            }
            if list_request.page_number >= query.max_pages {
                status = EvidenceStatus::Partial;
                partial_reason = Some(PartialReason::PageLimitReached);
                break;
            }
            let next_page = list_response
                .next_page
                .ok_or(AwsGuardDutyFindingResultError::PaginationReplay)?;
            if !seen_page_tokens.insert(next_page.digest().clone()) {
                return Err(AwsGuardDutyFindingResultError::PaginationReplay);
            }
            list_request = list_request
                .next_page(next_page)
                .map_err(|_| AwsGuardDutyFindingResultError::PaginationReplay)?;
        }

        if query.include_statistics {
            let statistics_request = StatisticsRequest::new(&self.scope, query)?;
            match provider.get_findings_statistics(&statistics_request) {
                Ok(response) => {
                    if response.partial {
                        status = EvidenceStatus::Partial;
                        partial_reason = Some(PartialReason::StatisticsUnavailable);
                    }
                    receipts.push(response.receipt.clone());
                    statistics = Some(response.statistics);
                }
                Err(AwsGuardDutyFindingResultError::Transport(error)) => {
                    receipts.push(RequestReceipt::failure(
                        Operation::GetFindingsStatistics,
                        statistics_request.request_digest,
                        error.failure,
                    ));
                    status = error.failure.evidence_status();
                    partial_reason = None;
                }
                Err(error) => return Err(error),
            }
        }

        let evidence = AwsGuardDutyFindingEvidence::new(
            status,
            partial_reason,
            provider.provenance(),
            detector_discovery,
            findings,
            statistics,
            receipts,
            provider.provider_digest().clone(),
            &self.scope,
            query,
            registration.registration_digest().clone(),
        )?;
        Ok(MissionAwsGuardDutyResult::new(evidence))
    }

    pub fn propose(
        &self,
        result: &MissionAwsGuardDutyResult,
    ) -> Result<AwsGuardDutyFindingProposal> {
        result.validate(&self.scope, self.registration_query()?)?;
        self.service.propose(result.evidence.clone())
    }

    pub fn record(
        &self,
        proposal: &AwsGuardDutyFindingProposal,
    ) -> Result<AwsGuardDutyFindingRecord> {
        self.service.record(proposal)
    }

    pub fn verify(
        &self,
        record: &AwsGuardDutyFindingRecord,
        query: &GuardDutyFindingQuery,
    ) -> Result<VerificationReport> {
        self.service.verify(record, &self.scope, query)
    }

    fn registration_query(&self) -> Result<&GuardDutyFindingQuery> {
        self.registration
            .as_ref()
            .map(AwsGuardDutyRegistration::query)
            .ok_or(AwsGuardDutyFindingResultError::RegistrationMissing)
    }

    fn failure_result<T: AwsGuardDutyTransport>(
        &self,
        provider: &AwsGuardDutyProvider<T>,
        query: &GuardDutyFindingQuery,
        detector_discovery: DetectorDiscovery,
        findings: Vec<AwsGuardDutyFinding>,
        statistics: Option<crate::model::FindingStatistics>,
        receipts: Vec<RequestReceipt>,
        status: EvidenceStatus,
        partial_reason: Option<PartialReason>,
    ) -> Result<MissionAwsGuardDutyResult> {
        let registration = self
            .registration
            .as_ref()
            .ok_or(AwsGuardDutyFindingResultError::RegistrationMissing)?;
        let evidence = AwsGuardDutyFindingEvidence::new(
            status,
            partial_reason,
            provider.provenance(),
            detector_discovery,
            findings,
            statistics,
            receipts,
            provider.provider_digest().clone(),
            &self.scope,
            query,
            registration.registration_digest().clone(),
        )?;
        Ok(MissionAwsGuardDutyResult::new(evidence))
    }
}

//! Scope-bound, non-native GuardDuty provider and redacted transports.

use std::{
    collections::VecDeque,
    fmt,
    ops::{Deref, DerefMut},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    AwsGuardDutyFinding, AwsGuardDutyFindingScope, DetectorDiscovery, Digest, EvidenceStatus,
    FindingId, FindingIdAllowlist, FindingStatistics, GuardDutyFindingQuery, MAX_DETECTORS,
    MAX_GET_BATCH, MAX_PAGES, MAX_RESPONSE_BYTES, OpaquePageToken, TransportProvenance,
};
use crate::{
    AWS_GUARDDUTY_API_VERSION, AWS_GUARDDUTY_CONTRACT_VERSION,
    AWS_GUARDDUTY_GET_FINDINGS_PERMISSION, AWS_GUARDDUTY_GET_STATISTICS_PERMISSION,
    AWS_GUARDDUTY_LIST_DETECTORS_PERMISSION, AWS_GUARDDUTY_LIST_FINDINGS_PERMISSION,
    AWS_GUARDDUTY_PLUGIN_VERSION, AWS_GUARDDUTY_PROVIDER_ID, AWS_GUARDDUTY_PROVIDER_REVISION,
    AwsGuardDutyFindingResultError, Result, api_digest, permission_digest,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    ListDetectors,
    ListFindings,
    GetFindings,
    GetFindingsStatistics,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CostReceipt {
    pub request_units: u32,
    pub response_units: u32,
    pub redacted: bool,
}

impl CostReceipt {
    pub const fn bounded(request_units: u32, response_units: u32) -> Self {
        Self {
            request_units,
            response_units,
            redacted: true,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequestReceipt {
    pub operation: Operation,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub response_bytes: u64,
    pub item_count: u32,
    pub cost: CostReceipt,
    pub redacted: bool,
}

impl RequestReceipt {
    pub fn new(
        operation: Operation,
        request_digest: Digest,
        response_digest: Digest,
        response_bytes: u64,
        item_count: usize,
    ) -> Result<Self> {
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(AwsGuardDutyFindingResultError::ResponseBoundExceeded);
        }
        Ok(Self {
            operation,
            request_digest,
            response_digest,
            response_bytes,
            item_count: item_count as u32,
            cost: CostReceipt::bounded(1, item_count as u32),
            redacted: true,
        })
    }

    pub fn failure(
        operation: Operation,
        request_digest: Digest,
        failure: TransportFailure,
    ) -> Self {
        let response_digest =
            crate::model::failure_digest(operation_name(operation), failure.as_str());
        Self {
            operation,
            request_digest,
            response_digest,
            response_bytes: 0,
            item_count: 0,
            cost: CostReceipt::bounded(1, 0),
            redacted: true,
        }
    }
}

fn operation_name(operation: Operation) -> &'static str {
    match operation {
        Operation::ListDetectors => "ListDetectors",
        Operation::ListFindings => "ListFindings",
        Operation::GetFindings => "GetFindings",
        Operation::GetFindingsStatistics => "GetFindingsStatistics",
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedRequest {
    pub operation: Operation,
    pub request_digest: Digest,
    pub provenance: TransportProvenance,
    pub raw_request_retained: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportFailure {
    BadRequest,
    AccessLoss,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    Throttled,
    ServerError,
    Timeout,
    BlockedEnvironment,
    ProviderUnknown,
    MalformedResponse,
}

impl TransportFailure {
    pub const fn status_code(self) -> Option<u16> {
        match self {
            Self::BadRequest => Some(400),
            Self::AccessLoss => None,
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::Conflict => Some(409),
            Self::Throttled => Some(429),
            Self::ServerError => Some(500),
            Self::Timeout
            | Self::BlockedEnvironment
            | Self::ProviderUnknown
            | Self::MalformedResponse => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BadRequest => "400",
            Self::AccessLoss => "access_loss",
            Self::Unauthorized => "401",
            Self::Forbidden => "403",
            Self::NotFound => "404",
            Self::Conflict => "409",
            Self::Throttled => "429",
            Self::ServerError => "500",
            Self::Timeout => "timeout",
            Self::BlockedEnvironment => "BLOCKED_ENV",
            Self::ProviderUnknown => "provider_unknown",
            Self::MalformedResponse => "malformed_response",
        }
    }

    pub const fn evidence_status(self) -> EvidenceStatus {
        match self {
            Self::BadRequest => EvidenceStatus::BadRequest,
            Self::AccessLoss => EvidenceStatus::AccessLoss,
            Self::Unauthorized => EvidenceStatus::Unauthorized,
            Self::Forbidden => EvidenceStatus::Forbidden,
            Self::NotFound => EvidenceStatus::NotFound,
            Self::Conflict => EvidenceStatus::Conflict,
            Self::Throttled => EvidenceStatus::Throttled,
            Self::ServerError => EvidenceStatus::ServerError,
            Self::Timeout => EvidenceStatus::Timeout,
            Self::BlockedEnvironment | Self::ProviderUnknown | Self::MalformedResponse => {
                EvidenceStatus::Unknown
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("GuardDuty transport failed: {failure:?}")]
pub struct TransportError {
    pub failure: TransportFailure,
    pub response_bytes: u64,
}

impl TransportError {
    pub const fn new(failure: TransportFailure) -> Self {
        Self {
            failure,
            response_bytes: 0,
        }
    }

    pub const fn with_response_bytes(failure: TransportFailure, response_bytes: u64) -> Self {
        Self {
            failure,
            response_bytes,
        }
    }

    pub const fn blocked_env() -> Self {
        Self::new(TransportFailure::BlockedEnvironment)
    }

    pub const fn malformed() -> Self {
        Self::new(TransportFailure::MalformedResponse)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListDetectorsRequest {
    pub scope: AwsGuardDutyFindingScope,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub request_digest: Digest,
}

impl ListDetectorsRequest {
    pub fn new(scope: &AwsGuardDutyFindingScope) -> Result<Self> {
        scope.validate()?;
        let scope_digest = scope.digest();
        let permission_digest = crate::permission_digest();
        let request_digest = Digest::from_fields(
            "hartevo.aws-guardduty-list-detectors-request/v1",
            &[
                scope_digest.as_str().to_owned(),
                permission_digest.as_str().to_owned(),
            ],
        );
        Ok(Self {
            scope: scope.clone(),
            scope_digest,
            permission_digest,
            request_digest,
        })
    }

    pub fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        let expected_scope = self.scope.digest();
        let expected_permission = crate::permission_digest();
        let expected_request = Digest::from_fields(
            "hartevo.aws-guardduty-list-detectors-request/v1",
            &[
                expected_scope.as_str().to_owned(),
                expected_permission.as_str().to_owned(),
            ],
        );
        if self.scope_digest != expected_scope
            || self.permission_digest != expected_permission
            || self.request_digest != expected_request
        {
            return Err(AwsGuardDutyFindingResultError::ScopeDrift);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListFindingsRequest {
    pub scope: AwsGuardDutyFindingScope,
    pub query: GuardDutyFindingQuery,
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub criteria_digest: Digest,
    pub page_size: u16,
    pub page_number: u16,
    pub page_token: Option<OpaquePageToken>,
    pub request_digest: Digest,
}

impl ListFindingsRequest {
    pub fn first(scope: &AwsGuardDutyFindingScope, query: &GuardDutyFindingQuery) -> Result<Self> {
        scope.validate()?;
        query.validate()?;
        Self::build(scope, query, 1, None)
    }

    pub fn new(scope: &AwsGuardDutyFindingScope, query: &GuardDutyFindingQuery) -> Result<Self> {
        Self::first(scope, query)
    }

    fn build(
        scope: &AwsGuardDutyFindingScope,
        query: &GuardDutyFindingQuery,
        page_number: u16,
        page_token: Option<OpaquePageToken>,
    ) -> Result<Self> {
        if page_number == 0 || page_number > MAX_PAGES {
            return Err(AwsGuardDutyFindingResultError::QueryDrift);
        }
        if page_number > query.max_pages {
            return Err(AwsGuardDutyFindingResultError::QueryDrift);
        }
        if let Some(token) = &page_token {
            token.validate_for(scope, query, page_number)?;
        }
        let scope_digest = scope.digest();
        let query_digest = query.digest();
        let criteria_digest = query.criteria.digest();
        let request_digest = Digest::from_fields(
            "hartevo.aws-guardduty-list-findings-request/v1",
            &[
                scope_digest.as_str().to_owned(),
                scope.detector_id.as_str().to_owned(),
                query_digest.as_str().to_owned(),
                criteria_digest.as_str().to_owned(),
                query.page_size.to_string(),
                page_number.to_string(),
                page_token
                    .as_ref()
                    .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
            ],
        );
        Ok(Self {
            scope: scope.clone(),
            query: query.clone(),
            scope_digest,
            query_digest,
            criteria_digest,
            page_size: query.page_size,
            page_number,
            page_token,
            request_digest,
        })
    }

    pub fn next_page(&self, token: OpaquePageToken) -> Result<Self> {
        Self::build(
            &self.scope,
            &self.query,
            self.page_number.saturating_add(1),
            Some(token),
        )
    }

    pub fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        self.query.validate()?;
        let expected = Self::build(
            &self.scope,
            &self.query,
            self.page_number,
            self.page_token.clone(),
        )?;
        if self.scope_digest != expected.scope_digest
            || self.query_digest != expected.query_digest
            || self.criteria_digest != expected.criteria_digest
            || self.page_size != expected.page_size
            || self.request_digest != expected.request_digest
        {
            return Err(AwsGuardDutyFindingResultError::QueryDrift);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetFindingsRequest {
    pub scope: AwsGuardDutyFindingScope,
    pub query: GuardDutyFindingQuery,
    pub allowlist: FindingIdAllowlist,
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub allowlist_digest: Digest,
    pub request_digest: Digest,
}

impl GetFindingsRequest {
    pub fn new(
        scope: &AwsGuardDutyFindingScope,
        query: &GuardDutyFindingQuery,
        allowlist: FindingIdAllowlist,
    ) -> Result<Self> {
        scope.validate()?;
        query.validate()?;
        allowlist.validate()?;
        if allowlist.scope_digest != scope.digest() || allowlist.query_digest != query.digest() {
            return Err(AwsGuardDutyFindingResultError::FindingOutOfAllowlist);
        }
        let scope_digest = scope.digest();
        let query_digest = query.digest();
        let allowlist_digest = allowlist.allowlist_digest.clone();
        let request_digest = Digest::from_fields(
            "hartevo.aws-guardduty-get-findings-request/v1",
            &[
                scope_digest.as_str().to_owned(),
                scope.detector_id.as_str().to_owned(),
                query_digest.as_str().to_owned(),
                allowlist_digest.as_str().to_owned(),
            ],
        );
        Ok(Self {
            scope: scope.clone(),
            query: query.clone(),
            allowlist,
            scope_digest,
            query_digest,
            allowlist_digest,
            request_digest,
        })
    }

    pub fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        self.query.validate()?;
        self.allowlist.validate()?;
        if self.allowlist.scope_digest != self.scope.digest()
            || self.allowlist.query_digest != self.query.digest()
        {
            return Err(AwsGuardDutyFindingResultError::FindingOutOfAllowlist);
        }
        let expected = Self::new(&self.scope, &self.query, self.allowlist.clone())?;
        if self.scope_digest != expected.scope_digest
            || self.query_digest != expected.query_digest
            || self.allowlist_digest != expected.allowlist_digest
            || self.request_digest != expected.request_digest
        {
            return Err(AwsGuardDutyFindingResultError::FindingOutOfAllowlist);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatisticsRequest {
    pub scope: AwsGuardDutyFindingScope,
    pub query: GuardDutyFindingQuery,
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub criteria_digest: Digest,
    pub max_buckets: usize,
    pub request_digest: Digest,
}

impl StatisticsRequest {
    pub fn new(scope: &AwsGuardDutyFindingScope, query: &GuardDutyFindingQuery) -> Result<Self> {
        scope.validate()?;
        query.validate()?;
        let scope_digest = scope.digest();
        let query_digest = query.digest();
        let criteria_digest = query.criteria.digest();
        let request_digest = Digest::from_fields(
            "hartevo.aws-guardduty-statistics-request/v1",
            &[
                scope_digest.as_str().to_owned(),
                scope.detector_id.as_str().to_owned(),
                query_digest.as_str().to_owned(),
                criteria_digest.as_str().to_owned(),
                query.max_statistics_buckets.to_string(),
            ],
        );
        Ok(Self {
            scope: scope.clone(),
            query: query.clone(),
            scope_digest,
            query_digest,
            criteria_digest,
            max_buckets: query.max_statistics_buckets,
            request_digest,
        })
    }

    pub fn validate(&self) -> Result<()> {
        let expected = Self::new(&self.scope, &self.query)?;
        if self.scope_digest != expected.scope_digest
            || self.query_digest != expected.query_digest
            || self.criteria_digest != expected.criteria_digest
            || self.max_buckets != expected.max_buckets
            || self.request_digest != expected.request_digest
        {
            return Err(AwsGuardDutyFindingResultError::QueryDrift);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListDetectorsResponse {
    pub detector_ids: Vec<crate::model::DetectorId>,
    pub detector_digest: Digest,
    pub complete: bool,
    pub response_digest: Digest,
    pub response_bytes: u64,
    pub receipt: RequestReceipt,
    pub request_binding: Digest,
}

impl ListDetectorsResponse {
    pub fn new(
        request: &ListDetectorsRequest,
        detector_ids: Vec<crate::model::DetectorId>,
        complete: bool,
        response_bytes: u64,
    ) -> Result<Self> {
        request.validate()?;
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(AwsGuardDutyFindingResultError::ResponseBoundExceeded);
        }
        let discovery = DetectorDiscovery::new(
            detector_ids.clone(),
            complete,
            Digest::from_text("pending-detector-response"),
        )?;
        let response_digest = Digest::from_fields(
            "hartevo.aws-guardduty-list-detectors-response/v1",
            &[
                request.request_digest.as_str().to_owned(),
                discovery.detector_digest.as_str().to_owned(),
                complete.to_string(),
            ],
        );
        let receipt = RequestReceipt::new(
            Operation::ListDetectors,
            request.request_digest.clone(),
            response_digest.clone(),
            response_bytes,
            detector_ids.len(),
        )?;
        Ok(Self {
            detector_ids,
            detector_digest: discovery.detector_digest,
            complete,
            response_digest,
            response_bytes,
            receipt,
            request_binding: request.request_digest.clone(),
        })
    }

    pub fn discovery(&self) -> Result<DetectorDiscovery> {
        Ok(DetectorDiscovery::new(
            self.detector_ids.clone(),
            self.complete,
            self.response_digest.clone(),
        )
        .map(|mut discovery| {
            discovery.detector_digest = self.detector_digest.clone();
            discovery
        })?)
    }

    pub fn validate_for(&self, request: &ListDetectorsRequest) -> Result<()> {
        request.validate()?;
        if self.response_bytes > MAX_RESPONSE_BYTES
            || self.detector_ids.len() > MAX_DETECTORS
            || self.request_binding != request.request_digest
            || self.receipt.request_digest != request.request_digest
            || self.receipt.response_digest != self.response_digest
            || !self.receipt.redacted
        {
            return Err(AwsGuardDutyFindingResultError::PageBindingMismatch);
        }
        let discovery = DetectorDiscovery::new(
            self.detector_ids.clone(),
            self.complete,
            self.response_digest.clone(),
        )?;
        let expected_response = Digest::from_fields(
            "hartevo.aws-guardduty-list-detectors-response/v1",
            &[
                request.request_digest.as_str().to_owned(),
                discovery.detector_digest.as_str().to_owned(),
                self.complete.to_string(),
            ],
        );
        if self.detector_digest != discovery.detector_digest
            || self.response_digest != expected_response
        {
            return Err(AwsGuardDutyFindingResultError::PageBindingMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListFindingsResponse {
    pub finding_ids: Vec<FindingId>,
    pub next_page: Option<OpaquePageToken>,
    pub partial: bool,
    pub response_digest: Digest,
    pub response_bytes: u64,
    pub receipt: RequestReceipt,
    pub request_binding: Digest,
}

impl ListFindingsResponse {
    pub fn new(
        request: &ListFindingsRequest,
        finding_ids: Vec<FindingId>,
        next_opaque_token: Option<impl AsRef<str>>,
        partial: bool,
        response_bytes: u64,
    ) -> Result<Self> {
        request.validate()?;
        if response_bytes > MAX_RESPONSE_BYTES || finding_ids.len() > request.page_size as usize {
            return Err(AwsGuardDutyFindingResultError::ResponseBoundExceeded);
        }
        let mut seen = std::collections::BTreeSet::new();
        for finding_id in &finding_ids {
            if !seen.insert(finding_id) {
                return Err(AwsGuardDutyFindingResultError::CriteriaReplay);
            }
        }
        let next_page = match next_opaque_token {
            Some(token) => Some(OpaquePageToken::from_provider(
                token,
                &request.scope,
                &request.query,
                request.page_number.saturating_add(1),
            )?),
            None => None,
        };
        let next_digest = next_page
            .as_ref()
            .map_or_else(String::new, |token| token.digest().as_str().to_owned());
        let response_digest = Digest::from_fields(
            "hartevo.aws-guardduty-list-findings-response/v1",
            &[
                request.request_digest.as_str().to_owned(),
                finding_ids
                    .iter()
                    .map(FindingId::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
                next_digest,
                partial.to_string(),
            ],
        );
        let receipt = RequestReceipt::new(
            Operation::ListFindings,
            request.request_digest.clone(),
            response_digest.clone(),
            response_bytes,
            finding_ids.len(),
        )?;
        Ok(Self {
            finding_ids,
            next_page,
            partial,
            response_digest,
            response_bytes,
            receipt,
            request_binding: request.request_digest.clone(),
        })
    }

    pub fn validate_for(&self, request: &ListFindingsRequest) -> Result<()> {
        request.validate()?;
        if self.response_bytes > MAX_RESPONSE_BYTES
            || self.finding_ids.len() > request.page_size as usize
            || self.request_binding != request.request_digest
            || self.receipt.request_digest != request.request_digest
            || self.receipt.response_digest != self.response_digest
            || !self.receipt.redacted
        {
            return Err(AwsGuardDutyFindingResultError::PageBindingMismatch);
        }
        let mut seen = std::collections::BTreeSet::new();
        for finding_id in &self.finding_ids {
            if !seen.insert(finding_id) {
                return Err(AwsGuardDutyFindingResultError::CriteriaReplay);
            }
        }
        if let Some(token) = &self.next_page {
            token
                .validate_for(&request.scope, &request.query, request.page_number + 1)
                .map_err(|_| AwsGuardDutyFindingResultError::PaginationReplay)?;
        }
        let next_digest = self
            .next_page
            .as_ref()
            .map_or_else(String::new, |token| token.digest().as_str().to_owned());
        let expected_response = Digest::from_fields(
            "hartevo.aws-guardduty-list-findings-response/v1",
            &[
                request.request_digest.as_str().to_owned(),
                self.finding_ids
                    .iter()
                    .map(FindingId::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
                next_digest,
                self.partial.to_string(),
            ],
        );
        if self.response_digest != expected_response {
            return Err(AwsGuardDutyFindingResultError::PageBindingMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetFindingsResponse {
    pub findings: Vec<AwsGuardDutyFinding>,
    pub missing_ids: Vec<FindingId>,
    pub partial: bool,
    pub response_digest: Digest,
    pub response_bytes: u64,
    pub receipt: RequestReceipt,
    pub request_binding: Digest,
}

impl GetFindingsResponse {
    pub fn new(
        request: &GetFindingsRequest,
        findings: Vec<AwsGuardDutyFinding>,
        missing_ids: Vec<FindingId>,
        partial: bool,
        response_bytes: u64,
    ) -> Result<Self> {
        request.validate()?;
        if response_bytes > MAX_RESPONSE_BYTES
            || findings.len() > MAX_GET_BATCH
            || missing_ids.len() > MAX_GET_BATCH
        {
            return Err(AwsGuardDutyFindingResultError::ResponseBoundExceeded);
        }
        for finding in &findings {
            finding.validate()?;
            if !request.allowlist.contains(&finding.finding_id) {
                return Err(AwsGuardDutyFindingResultError::FindingOutOfAllowlist);
            }
        }
        for missing_id in &missing_ids {
            if !request.allowlist.contains(missing_id) {
                return Err(AwsGuardDutyFindingResultError::FindingOutOfAllowlist);
            }
        }
        let mut covered_ids = std::collections::BTreeSet::new();
        for finding in &findings {
            if !covered_ids.insert(finding.finding_id.clone()) {
                return Err(AwsGuardDutyFindingResultError::FindingOutOfAllowlist);
            }
        }
        for missing_id in &missing_ids {
            if !covered_ids.insert(missing_id.clone()) {
                return Err(AwsGuardDutyFindingResultError::FindingOutOfAllowlist);
            }
        }
        if covered_ids.len() != request.allowlist.finding_ids.len() {
            return Err(AwsGuardDutyFindingResultError::PageBindingMismatch);
        }
        let response_digest = Digest::from_fields(
            "hartevo.aws-guardduty-get-findings-response/v1",
            &[
                request.request_digest.as_str().to_owned(),
                findings
                    .iter()
                    .map(|value| value.finding_digest.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
                missing_ids
                    .iter()
                    .map(FindingId::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
                partial.to_string(),
            ],
        );
        let receipt = RequestReceipt::new(
            Operation::GetFindings,
            request.request_digest.clone(),
            response_digest.clone(),
            response_bytes,
            findings.len(),
        )?;
        Ok(Self {
            findings,
            missing_ids,
            partial,
            response_digest,
            response_bytes,
            receipt,
            request_binding: request.request_digest.clone(),
        })
    }

    pub fn validate_for(&self, request: &GetFindingsRequest) -> Result<()> {
        request.validate()?;
        if self.response_bytes > MAX_RESPONSE_BYTES
            || self.findings.len() > MAX_GET_BATCH
            || self.missing_ids.len() > MAX_GET_BATCH
            || self.request_binding != request.request_digest
            || self.receipt.request_digest != request.request_digest
            || self.receipt.response_digest != self.response_digest
            || !self.receipt.redacted
        {
            return Err(AwsGuardDutyFindingResultError::PageBindingMismatch);
        }
        let mut ids = std::collections::BTreeSet::new();
        for finding in &self.findings {
            finding.validate()?;
            if !request.allowlist.contains(&finding.finding_id) || !ids.insert(&finding.finding_id)
            {
                return Err(AwsGuardDutyFindingResultError::FindingOutOfAllowlist);
            }
        }
        for missing_id in &self.missing_ids {
            if !request.allowlist.contains(missing_id) {
                return Err(AwsGuardDutyFindingResultError::FindingOutOfAllowlist);
            }
        }
        let mut covered_ids = std::collections::BTreeSet::new();
        for finding in &self.findings {
            if !covered_ids.insert(finding.finding_id.clone()) {
                return Err(AwsGuardDutyFindingResultError::FindingOutOfAllowlist);
            }
        }
        for missing_id in &self.missing_ids {
            if !covered_ids.insert(missing_id.clone()) {
                return Err(AwsGuardDutyFindingResultError::FindingOutOfAllowlist);
            }
        }
        if covered_ids.len() != request.allowlist.finding_ids.len() {
            return Err(AwsGuardDutyFindingResultError::PageBindingMismatch);
        }
        let expected_response = Digest::from_fields(
            "hartevo.aws-guardduty-get-findings-response/v1",
            &[
                request.request_digest.as_str().to_owned(),
                self.findings
                    .iter()
                    .map(|value| value.finding_digest.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
                self.missing_ids
                    .iter()
                    .map(FindingId::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
                self.partial.to_string(),
            ],
        );
        if self.response_digest != expected_response {
            return Err(AwsGuardDutyFindingResultError::PageBindingMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatisticsResponse {
    pub statistics: FindingStatistics,
    pub partial: bool,
    pub response_digest: Digest,
    pub response_bytes: u64,
    pub receipt: RequestReceipt,
    pub request_binding: Digest,
}

impl StatisticsResponse {
    pub fn new(
        request: &StatisticsRequest,
        statistics: FindingStatistics,
        partial: bool,
        response_bytes: u64,
    ) -> Result<Self> {
        request.validate()?;
        statistics.validate()?;
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(AwsGuardDutyFindingResultError::ResponseBoundExceeded);
        }
        let response_digest = Digest::from_fields(
            "hartevo.aws-guardduty-statistics-response/v1",
            &[
                request.request_digest.as_str().to_owned(),
                statistics.statistics_digest.as_str().to_owned(),
                partial.to_string(),
            ],
        );
        let receipt = RequestReceipt::new(
            Operation::GetFindingsStatistics,
            request.request_digest.clone(),
            response_digest.clone(),
            response_bytes,
            1,
        )?;
        Ok(Self {
            statistics,
            partial,
            response_digest,
            response_bytes,
            receipt,
            request_binding: request.request_digest.clone(),
        })
    }

    pub fn validate_for(&self, request: &StatisticsRequest) -> Result<()> {
        request.validate()?;
        self.statistics.validate()?;
        if self.response_bytes > MAX_RESPONSE_BYTES
            || self.request_binding != request.request_digest
            || self.receipt.request_digest != request.request_digest
            || self.receipt.response_digest != self.response_digest
            || !self.receipt.redacted
        {
            return Err(AwsGuardDutyFindingResultError::PageBindingMismatch);
        }
        let expected_response = Digest::from_fields(
            "hartevo.aws-guardduty-statistics-response/v1",
            &[
                request.request_digest.as_str().to_owned(),
                self.statistics.statistics_digest.as_str().to_owned(),
                self.partial.to_string(),
            ],
        );
        if self.response_digest != expected_response {
            return Err(AwsGuardDutyFindingResultError::PageBindingMismatch);
        }
        Ok(())
    }
}

pub trait AwsGuardDutyTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn list_detectors(
        &mut self,
        request: &ListDetectorsRequest,
    ) -> std::result::Result<ListDetectorsResponse, TransportError>;

    fn list_findings(
        &mut self,
        request: &ListFindingsRequest,
    ) -> std::result::Result<ListFindingsResponse, TransportError>;

    fn get_findings(
        &mut self,
        request: &GetFindingsRequest,
    ) -> std::result::Result<GetFindingsResponse, TransportError>;

    fn get_findings_statistics(
        &mut self,
        request: &StatisticsRequest,
    ) -> std::result::Result<StatisticsResponse, TransportError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsGuardDutyProviderDefinition {
    pub provider_id: String,
    pub plugin_version: String,
    pub contract_version: String,
    pub api_version: String,
    pub provider_revision: String,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub provider_digest: Digest,
    pub read_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl Default for AwsGuardDutyProviderDefinition {
    fn default() -> Self {
        Self::baseline()
    }
}

impl AwsGuardDutyProviderDefinition {
    pub fn baseline() -> Self {
        let api_digest = api_digest();
        let permission_digest = permission_digest();
        let provider_digest = Digest::from_fields(
            "hartevo.aws-guardduty-provider/v1",
            &[
                AWS_GUARDDUTY_PROVIDER_ID.to_owned(),
                AWS_GUARDDUTY_PLUGIN_VERSION.to_owned(),
                AWS_GUARDDUTY_CONTRACT_VERSION.to_owned(),
                AWS_GUARDDUTY_API_VERSION.to_owned(),
                AWS_GUARDDUTY_PROVIDER_REVISION.to_owned(),
                api_digest.as_str().to_owned(),
                permission_digest.as_str().to_owned(),
                AWS_GUARDDUTY_LIST_DETECTORS_PERMISSION.to_owned(),
                AWS_GUARDDUTY_LIST_FINDINGS_PERMISSION.to_owned(),
                AWS_GUARDDUTY_GET_FINDINGS_PERMISSION.to_owned(),
                AWS_GUARDDUTY_GET_STATISTICS_PERMISSION.to_owned(),
            ],
        );
        Self {
            provider_id: AWS_GUARDDUTY_PROVIDER_ID.to_owned(),
            plugin_version: AWS_GUARDDUTY_PLUGIN_VERSION.to_owned(),
            contract_version: AWS_GUARDDUTY_CONTRACT_VERSION.to_owned(),
            api_version: AWS_GUARDDUTY_API_VERSION.to_owned(),
            provider_revision: AWS_GUARDDUTY_PROVIDER_REVISION.to_owned(),
            api_digest,
            permission_digest,
            provider_digest,
            read_only: true,
            connected: false,
            native: false,
            first_party: false,
        }
    }

    pub fn validate(&self) -> Result<()> {
        let expected = Self::baseline();
        if self != &expected {
            return Err(AwsGuardDutyFindingResultError::InvalidRegistration);
        }
        Ok(())
    }
}

pub struct AwsGuardDutyProvider<T = BlockedEnvTransport> {
    transport: T,
    definition: AwsGuardDutyProviderDefinition,
    recorded_requests: Vec<RecordedRequest>,
}

impl<T: fmt::Debug> fmt::Debug for AwsGuardDutyProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsGuardDutyProvider")
            .field("transport", &self.transport)
            .field("definition", &self.definition)
            .field("recorded_requests", &self.recorded_requests)
            .finish()
    }
}

impl Default for AwsGuardDutyProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvTransport::default())
    }
}

impl<T: AwsGuardDutyTransport> AwsGuardDutyProvider<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            definition: AwsGuardDutyProviderDefinition::baseline(),
            recorded_requests: Vec::new(),
        }
    }

    pub fn with_definition(transport: T, definition: AwsGuardDutyProviderDefinition) -> Self {
        Self {
            transport,
            definition,
            recorded_requests: Vec::new(),
        }
    }

    pub fn definition(&self) -> &AwsGuardDutyProviderDefinition {
        &self.definition
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.definition.provider_digest
    }

    pub fn api_digest(&self) -> &Digest {
        &self.definition.api_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.definition.permission_digest
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn connected(&self) -> bool {
        false
    }

    pub fn native(&self) -> bool {
        false
    }

    pub fn first_party(&self) -> bool {
        false
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn recorded_requests(&self) -> &[RecordedRequest] {
        &self.recorded_requests
    }

    pub fn list_detectors(
        &mut self,
        request: &ListDetectorsRequest,
    ) -> Result<ListDetectorsResponse> {
        self.definition.validate()?;
        request.validate()?;
        self.record(Operation::ListDetectors, request.request_digest.clone());
        let response = self.transport.list_detectors(request).map_err(|error| {
            self.recorded_requests.pop();
            AwsGuardDutyFindingResultError::Transport(error)
        })?;
        response.validate_for(request)?;
        Ok(response)
    }

    pub fn list_findings(&mut self, request: &ListFindingsRequest) -> Result<ListFindingsResponse> {
        self.definition.validate()?;
        request.validate()?;
        self.record(Operation::ListFindings, request.request_digest.clone());
        let response = self.transport.list_findings(request).map_err(|error| {
            self.recorded_requests.pop();
            AwsGuardDutyFindingResultError::Transport(error)
        })?;
        response.validate_for(request)?;
        Ok(response)
    }

    pub fn get_findings(&mut self, request: &GetFindingsRequest) -> Result<GetFindingsResponse> {
        self.definition.validate()?;
        request.validate()?;
        self.record(Operation::GetFindings, request.request_digest.clone());
        let response = self.transport.get_findings(request).map_err(|error| {
            self.recorded_requests.pop();
            AwsGuardDutyFindingResultError::Transport(error)
        })?;
        response.validate_for(request)?;
        Ok(response)
    }

    pub fn get_findings_statistics(
        &mut self,
        request: &StatisticsRequest,
    ) -> Result<StatisticsResponse> {
        self.definition.validate()?;
        request.validate()?;
        self.record(
            Operation::GetFindingsStatistics,
            request.request_digest.clone(),
        );
        let response = self
            .transport
            .get_findings_statistics(request)
            .map_err(|error| {
                self.recorded_requests.pop();
                AwsGuardDutyFindingResultError::Transport(error)
            })?;
        response.validate_for(request)?;
        Ok(response)
    }

    fn record(&mut self, operation: Operation, request_digest: Digest) {
        self.recorded_requests.push(RecordedRequest {
            operation,
            request_digest,
            provenance: self.transport.provenance(),
            raw_request_retained: false,
        });
    }
}

#[derive(Clone, Debug)]
pub struct ScriptedTransport {
    provenance: TransportProvenance,
    detector_responses: VecDeque<std::result::Result<ListDetectorsResponse, TransportError>>,
    list_responses: VecDeque<std::result::Result<ListFindingsResponse, TransportError>>,
    get_responses: VecDeque<std::result::Result<GetFindingsResponse, TransportError>>,
    statistics_responses: VecDeque<std::result::Result<StatisticsResponse, TransportError>>,
}

impl ScriptedTransport {
    pub fn new(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            detector_responses: VecDeque::new(),
            list_responses: VecDeque::new(),
            get_responses: VecDeque::new(),
            statistics_responses: VecDeque::new(),
        }
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    pub fn push_detectors(
        &mut self,
        response: std::result::Result<ListDetectorsResponse, TransportError>,
    ) {
        self.detector_responses.push_back(response);
    }

    pub fn push_list_findings(
        &mut self,
        response: std::result::Result<ListFindingsResponse, TransportError>,
    ) {
        self.list_responses.push_back(response);
    }

    pub fn push_get_findings(
        &mut self,
        response: std::result::Result<GetFindingsResponse, TransportError>,
    ) {
        self.get_responses.push_back(response);
    }

    pub fn push_statistics(
        &mut self,
        response: std::result::Result<StatisticsResponse, TransportError>,
    ) {
        self.statistics_responses.push_back(response);
    }

    fn pop_or_unknown<T>(
        queue: &mut VecDeque<std::result::Result<T, TransportError>>,
    ) -> std::result::Result<T, TransportError> {
        queue
            .pop_front()
            .unwrap_or_else(|| Err(TransportError::new(TransportFailure::ProviderUnknown)))
    }
}

impl AwsGuardDutyTransport for ScriptedTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn list_detectors(
        &mut self,
        _request: &ListDetectorsRequest,
    ) -> std::result::Result<ListDetectorsResponse, TransportError> {
        Self::pop_or_unknown(&mut self.detector_responses)
    }

    fn list_findings(
        &mut self,
        _request: &ListFindingsRequest,
    ) -> std::result::Result<ListFindingsResponse, TransportError> {
        Self::pop_or_unknown(&mut self.list_responses)
    }

    fn get_findings(
        &mut self,
        _request: &GetFindingsRequest,
    ) -> std::result::Result<GetFindingsResponse, TransportError> {
        Self::pop_or_unknown(&mut self.get_responses)
    }

    fn get_findings_statistics(
        &mut self,
        _request: &StatisticsRequest,
    ) -> std::result::Result<StatisticsResponse, TransportError> {
        Self::pop_or_unknown(&mut self.statistics_responses)
    }
}

macro_rules! scripted_wrapper {
    ($name:ident, $provenance:expr) => {
        #[derive(Clone, Debug)]
        pub struct $name {
            inner: ScriptedTransport,
        }

        impl $name {
            pub fn new() -> Self {
                Self {
                    inner: ScriptedTransport::new($provenance),
                }
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl Deref for $name {
            type Target = ScriptedTransport;

            fn deref(&self) -> &Self::Target {
                &self.inner
            }
        }

        impl DerefMut for $name {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.inner
            }
        }

        impl AwsGuardDutyTransport for $name {
            fn provenance(&self) -> TransportProvenance {
                self.inner.provenance()
            }

            fn list_detectors(
                &mut self,
                request: &ListDetectorsRequest,
            ) -> std::result::Result<ListDetectorsResponse, TransportError> {
                self.inner.list_detectors(request)
            }

            fn list_findings(
                &mut self,
                request: &ListFindingsRequest,
            ) -> std::result::Result<ListFindingsResponse, TransportError> {
                self.inner.list_findings(request)
            }

            fn get_findings(
                &mut self,
                request: &GetFindingsRequest,
            ) -> std::result::Result<GetFindingsResponse, TransportError> {
                self.inner.get_findings(request)
            }

            fn get_findings_statistics(
                &mut self,
                request: &StatisticsRequest,
            ) -> std::result::Result<StatisticsResponse, TransportError> {
                self.inner.get_findings_statistics(request)
            }
        }
    };
}

scripted_wrapper!(FixtureTransport, TransportProvenance::Fixture);
scripted_wrapper!(RecordingTransport, TransportProvenance::Recording);
scripted_wrapper!(LoopbackTransport, TransportProvenance::Loopback);
scripted_wrapper!(BlockedEnvTransport, TransportProvenance::BlockedEnv);

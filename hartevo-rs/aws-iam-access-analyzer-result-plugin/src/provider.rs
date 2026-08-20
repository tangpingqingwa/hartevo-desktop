//! Fixture-only provider and transport seams for AWS IAM Access Analyzer.
//!
//! There is intentionally no HTTP client, SigV4 signer, credential resolver,
//! analyzer creation method, finding archive method, or IAM policy mutation
//! method in this module.

use std::{collections::VecDeque, fmt};

use serde::Serialize;

use crate::error::{AwsIamAccessAnalyzerError, AwsIamProviderError, AwsIamTransportError, Result};
use crate::model::{
    FindingSummaryV2, ListFindingsV2Request, OpaqueCursor, ProviderIdentity, ProviderProvenance,
    ValidatePolicyFinding, ValidatePolicyRequest,
};
use crate::service::AwsIamAccessAnalyzerRegistration;
use crate::{Digest, TransportProvenance};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListFindingsV2Response {
    pub findings: Vec<FindingSummaryV2>,
    pub next_cursor: Option<OpaqueCursor>,
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub permission_digest: Digest,
    pub provider_digest: Digest,
    pub provenance: ProviderProvenance,
    pub response_digest: Digest,
}

impl ListFindingsV2Response {
    pub fn new(
        request: &ListFindingsV2Request,
        findings: Vec<FindingSummaryV2>,
        next_cursor: Option<OpaqueCursor>,
        provider: &ProviderIdentity,
        provenance: ProviderProvenance,
    ) -> Result<Self> {
        Self::for_request(request, findings, next_cursor, provider, provenance)
    }

    pub fn for_request(
        request: &ListFindingsV2Request,
        findings: Vec<FindingSummaryV2>,
        next_cursor: Option<OpaqueCursor>,
        provider: &ProviderIdentity,
        provenance: ProviderProvenance,
    ) -> Result<Self> {
        if findings.len() > request.max_results as usize
            || next_cursor
                .as_ref()
                .is_some_and(|cursor| !cursor.matches(request.cursor_binding_digest()))
        {
            return Err(AwsIamAccessAnalyzerError::InvalidFinding);
        }
        for finding in &findings {
            finding.validate()?;
        }
        let mut response = Self {
            findings,
            next_cursor,
            scope_digest: request.scope_digest.clone(),
            request_digest: request.request_digest.clone(),
            permission_digest: request.permission_digest.clone(),
            provider_digest: provider.digest.clone(),
            provenance,
            response_digest: Digest::from_text("unsealed-list-findings-v2-response"),
        };
        response.response_digest = response.compute_digest();
        Ok(response)
    }

    pub fn validate(
        &self,
        request: &ListFindingsV2Request,
        provider: &ProviderIdentity,
    ) -> Result<()> {
        if self.scope_digest != request.scope_digest
            || self.request_digest != request.request_digest
            || self.permission_digest != request.permission_digest
            || self.provider_digest != provider.digest
            || self
                .next_cursor
                .as_ref()
                .is_some_and(|cursor| !cursor.matches(request.cursor_binding_digest()))
        {
            return Err(AwsIamAccessAnalyzerError::TamperedEvidence);
        }
        for finding in &self.findings {
            finding.validate()?;
        }
        if self.compute_digest() == self.response_digest {
            Ok(())
        } else {
            Err(AwsIamAccessAnalyzerError::TamperedEvidence)
        }
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-iam-list-findings-v2-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("provenance", format!("{:?}", self.provenance)),
                (
                    "findings",
                    self.findings
                        .iter()
                        .map(|finding| finding.finding_digest.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "cursor",
                    self.next_cursor.as_ref().map_or_else(
                        || "none".to_owned(),
                        |cursor| cursor.digest().as_str().to_owned(),
                    ),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidatePolicyResponse {
    pub findings: Vec<ValidatePolicyFinding>,
    pub next_cursor: Option<OpaqueCursor>,
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub permission_digest: Digest,
    pub provider_digest: Digest,
    pub provenance: ProviderProvenance,
    pub response_digest: Digest,
}

impl ValidatePolicyResponse {
    pub fn new(
        request: &ValidatePolicyRequest,
        findings: Vec<ValidatePolicyFinding>,
        next_cursor: Option<OpaqueCursor>,
        provider: &ProviderIdentity,
        provenance: ProviderProvenance,
    ) -> Result<Self> {
        Self::for_request(request, findings, next_cursor, provider, provenance)
    }

    pub fn for_request(
        request: &ValidatePolicyRequest,
        findings: Vec<ValidatePolicyFinding>,
        next_cursor: Option<OpaqueCursor>,
        provider: &ProviderIdentity,
        provenance: ProviderProvenance,
    ) -> Result<Self> {
        if findings.len() > request.max_results as usize
            || next_cursor
                .as_ref()
                .is_some_and(|cursor| !cursor.matches(request.cursor_binding_digest()))
        {
            return Err(AwsIamAccessAnalyzerError::InvalidPolicyFinding);
        }
        for finding in &findings {
            finding.validate()?;
        }
        let mut response = Self {
            findings,
            next_cursor,
            scope_digest: request.scope_digest.clone(),
            request_digest: request.request_digest.clone(),
            permission_digest: request.permission_digest.clone(),
            provider_digest: provider.digest.clone(),
            provenance,
            response_digest: Digest::from_text("unsealed-validate-policy-response"),
        };
        response.response_digest = response.compute_digest();
        Ok(response)
    }

    pub fn validate(
        &self,
        request: &ValidatePolicyRequest,
        provider: &ProviderIdentity,
    ) -> Result<()> {
        if self.scope_digest != request.scope_digest
            || self.request_digest != request.request_digest
            || self.permission_digest != request.permission_digest
            || self.provider_digest != provider.digest
            || self
                .next_cursor
                .as_ref()
                .is_some_and(|cursor| !cursor.matches(request.cursor_binding_digest()))
        {
            return Err(AwsIamAccessAnalyzerError::TamperedEvidence);
        }
        for finding in &self.findings {
            finding.validate()?;
        }
        if self.compute_digest() == self.response_digest {
            Ok(())
        } else {
            Err(AwsIamAccessAnalyzerError::TamperedEvidence)
        }
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-iam-validate-policy-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("provenance", format!("{:?}", self.provenance)),
                (
                    "findings",
                    self.findings
                        .iter()
                        .map(|finding| finding.finding_digest.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "cursor",
                    self.next_cursor.as_ref().map_or_else(
                        || "none".to_owned(),
                        |cursor| cursor.digest().as_str().to_owned(),
                    ),
                ),
            ],
        )
    }
}

/// The only transport operations allowed by Layer 1.
pub trait AwsIamAccessAnalyzerTransport: fmt::Debug {
    fn provenance(&self) -> ProviderProvenance;

    fn list_findings_v2(
        &mut self,
        request: &ListFindingsV2Request,
    ) -> std::result::Result<ListFindingsV2Response, AwsIamTransportError>;

    fn validate_policy(
        &mut self,
        request: &ValidatePolicyRequest,
    ) -> std::result::Result<ValidatePolicyResponse, AwsIamTransportError>;
}

/// Provider capability fence over a fixture-only transport.
#[derive(Debug)]
pub struct AwsIamAccessAnalyzerProvider<T> {
    registration: AwsIamAccessAnalyzerRegistration,
    transport: T,
}

impl<T: AwsIamAccessAnalyzerTransport> AwsIamAccessAnalyzerProvider<T> {
    pub fn new(registration: AwsIamAccessAnalyzerRegistration, transport: T) -> Result<Self> {
        registration.validate()?;
        Ok(Self {
            registration,
            transport,
        })
    }

    pub fn registration(&self) -> &AwsIamAccessAnalyzerRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut AwsIamAccessAnalyzerRegistration {
        &mut self.registration
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn provenance(&self) -> ProviderProvenance {
        self.transport.provenance()
    }

    pub fn connected(&self) -> bool {
        self.provenance().connected()
    }

    pub fn native(&self) -> bool {
        self.provenance().native()
    }

    pub fn first_party(&self) -> bool {
        self.provenance().first_party()
    }

    pub fn ensure_ready(&self) -> Result<()> {
        self.registration.validate()?;
        if !self.registration.is_active() {
            return match self.registration.status() {
                crate::RegistrationStatus::Revoked => {
                    Err(AwsIamAccessAnalyzerError::RegistrationRevoked)
                }
                crate::RegistrationStatus::Reversed => {
                    Err(AwsIamAccessAnalyzerError::RegistrationReversed)
                }
                crate::RegistrationStatus::Active => Ok(()),
            };
        }
        if self.registration.secret_reference().is_revoked() {
            return Err(AwsIamAccessAnalyzerError::RegistrationRevoked);
        }
        Ok(())
    }

    pub fn list_findings_v2(
        &mut self,
        request: &ListFindingsV2Request,
    ) -> Result<ListFindingsV2Response> {
        self.ensure_ready()?;
        self.validate_findings_request(request)?;
        let response = self
            .transport
            .list_findings_v2(request)
            .map_err(AwsIamProviderError::from)?;
        response.validate(request, self.registration.provider())?;
        Ok(response)
    }

    pub fn validate_policy(
        &mut self,
        request: &ValidatePolicyRequest,
    ) -> Result<ValidatePolicyResponse> {
        self.ensure_ready()?;
        self.validate_policy_request(request)?;
        let response = self
            .transport
            .validate_policy(request)
            .map_err(AwsIamProviderError::from)?;
        response.validate(request, self.registration.provider())?;
        Ok(response)
    }

    fn validate_findings_request(&self, request: &ListFindingsV2Request) -> Result<()> {
        let scope = self.registration.scope();
        if request.scope_digest != *scope.scope_digest()
            || request.analyzer_arn != scope.analyzer
            || request.permission_digest != self.registration.permission_snapshot().digest
            || request.mission_revision != scope.mission.revision
        {
            return Err(AwsIamAccessAnalyzerError::ScopeMismatch);
        }
        Ok(())
    }

    fn validate_policy_request(&self, request: &ValidatePolicyRequest) -> Result<()> {
        let scope = self.registration.scope();
        if request.scope_digest != *scope.scope_digest()
            || request.policy_type != scope.policy_type
            || request.policy_resource_type != scope.policy_resource_type
            || request.policy_revision != scope.policy_revision
            || request.permission_digest != self.registration.permission_snapshot().digest
        {
            return Err(AwsIamAccessAnalyzerError::ScopeMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct RecordingTransport {
    provenance: ProviderProvenance,
    findings: VecDeque<std::result::Result<ListFindingsV2Response, AwsIamTransportError>>,
    policies: VecDeque<std::result::Result<ValidatePolicyResponse, AwsIamTransportError>>,
    finding_requests: Vec<ListFindingsV2Request>,
    policy_requests: Vec<ValidatePolicyRequest>,
}

impl RecordingTransport {
    pub fn new(provenance: ProviderProvenance) -> Self {
        Self {
            provenance,
            ..Self::default()
        }
    }

    pub fn fixture(provenance: ProviderProvenance) -> Self {
        Self::new(provenance)
    }

    pub fn push_findings_response(
        &mut self,
        response: std::result::Result<ListFindingsV2Response, AwsIamTransportError>,
    ) {
        self.findings.push_back(response);
    }

    pub fn push_list_findings_response(
        &mut self,
        response: std::result::Result<ListFindingsV2Response, AwsIamTransportError>,
    ) {
        self.push_findings_response(response);
    }

    pub fn push_policy_response(
        &mut self,
        response: std::result::Result<ValidatePolicyResponse, AwsIamTransportError>,
    ) {
        self.policies.push_back(response);
    }

    pub fn push_validate_policy_response(
        &mut self,
        response: std::result::Result<ValidatePolicyResponse, AwsIamTransportError>,
    ) {
        self.push_policy_response(response);
    }

    pub fn finding_calls(&self) -> usize {
        self.finding_requests.len()
    }

    pub fn list_findings_calls(&self) -> usize {
        self.finding_calls()
    }

    pub fn policy_calls(&self) -> usize {
        self.policy_requests.len()
    }

    pub fn validate_policy_calls(&self) -> usize {
        self.policy_calls()
    }

    pub fn finding_requests(&self) -> &[ListFindingsV2Request] {
        &self.finding_requests
    }

    pub fn policy_requests(&self) -> &[ValidatePolicyRequest] {
        &self.policy_requests
    }
}

impl AwsIamAccessAnalyzerTransport for RecordingTransport {
    fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }

    fn list_findings_v2(
        &mut self,
        request: &ListFindingsV2Request,
    ) -> std::result::Result<ListFindingsV2Response, AwsIamTransportError> {
        self.finding_requests.push(request.clone());
        self.findings
            .pop_front()
            .unwrap_or(Err(AwsIamTransportError::MissingFixture))
    }

    fn validate_policy(
        &mut self,
        request: &ValidatePolicyRequest,
    ) -> std::result::Result<ValidatePolicyResponse, AwsIamTransportError> {
        self.policy_requests.push(request.clone());
        self.policies
            .pop_front()
            .unwrap_or(Err(AwsIamTransportError::MissingFixture))
    }
}

pub type FakeTransport = RecordingTransport;
pub type LoopbackTransport = RecordingTransport;

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl AwsIamAccessAnalyzerTransport for BlockedEnvTransport {
    fn provenance(&self) -> ProviderProvenance {
        TransportProvenance::BlockedEnv
    }

    fn list_findings_v2(
        &mut self,
        _request: &ListFindingsV2Request,
    ) -> std::result::Result<ListFindingsV2Response, AwsIamTransportError> {
        Err(AwsIamTransportError::BlockedEnv)
    }

    fn validate_policy(
        &mut self,
        _request: &ValidatePolicyRequest,
    ) -> std::result::Result<ValidatePolicyResponse, AwsIamTransportError> {
        Err(AwsIamTransportError::BlockedEnv)
    }
}

pub type AwsIamAccessAnalyzerProviderDefinition = ProviderIdentity;

pub fn response_cursor(request_binding: &Digest, token: impl Into<String>) -> Result<OpaqueCursor> {
    OpaqueCursor::new(token, request_binding.clone())
}

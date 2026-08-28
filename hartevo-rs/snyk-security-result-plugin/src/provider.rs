//! Typed Snyk provider and bounded non-native transport fixtures.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};

use crate::model::{
    Digest, Evidence, ProjectionCompleteness, SnapshotStatus, SnykScope, TransportProvenance,
};
use crate::service::SnykRegistration;
use crate::{
    MAX_EVIDENCE_ITEMS, MAX_PAGE_SIZE, MAX_PAGE_TOKEN_BYTES, MAX_PAGES, MAX_RESPONSE_BYTES, Result,
    SnykProviderError, SnykSecurityResultError, SnykTransportError, validate_text,
};

/// A single bounded page request. It carries only exact scope identifiers and
/// a bounded opaque page token; the provider never accepts a credential here.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectSnapshotReadRequest {
    pub scope: SnykScope,
    pub request_id: String,
    pub page_size: usize,
    pub page_token: Option<String>,
}

impl ProjectSnapshotReadRequest {
    pub fn new(
        scope: SnykScope,
        request_id: impl Into<String>,
        page_size: usize,
        page_token: Option<String>,
    ) -> Result<Self> {
        let request = Self {
            scope,
            request_id: request_id.into(),
            page_size,
            page_token,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        validate_text(&self.request_id, "requestId", 128)?;
        if self.page_size == 0 || self.page_size > MAX_PAGE_SIZE {
            return Err(SnykSecurityResultError::InvalidScope);
        }
        if let Some(token) = &self.page_token {
            validate_text(token, "pageToken", MAX_PAGE_TOKEN_BYTES)?;
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }
}

/// A provider response is deliberately a closed, allowlisted evidence union.
/// There is no raw JSON, source export, or dependency graph field.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectSnapshotResponse {
    pub scope: SnykScope,
    pub snapshot_status: SnapshotStatus,
    pub evidence: Vec<Evidence>,
    pub truncated: bool,
    pub response_bytes: usize,
    pub provider_request_id_digest: Digest,
    pub request_page_token: Option<String>,
    pub next_page_token: Option<String>,
    pub provenance: TransportProvenance,
}

impl ProjectSnapshotResponse {
    pub fn for_scope(scope: &SnykScope, provenance: TransportProvenance) -> Self {
        Self {
            scope: scope.clone(),
            snapshot_status: SnapshotStatus::Completed,
            evidence: Vec::new(),
            truncated: false,
            response_bytes: 256,
            provider_request_id_digest: Digest::from_text("snyk-fixture-request"),
            request_page_token: None,
            next_page_token: None,
            provenance,
        }
    }

    pub fn with_evidence(
        scope: &SnykScope,
        evidence: Vec<Evidence>,
        provenance: TransportProvenance,
    ) -> Self {
        let mut response = Self::for_scope(scope, provenance);
        response.evidence = evidence;
        response.response_bytes = 256 + response.evidence.len() * 192;
        response
    }

    #[must_use]
    pub fn with_next_page_token(mut self, next_page_token: impl Into<String>) -> Self {
        self.next_page_token = Some(next_page_token.into());
        self
    }

    #[must_use]
    pub fn with_truncated(mut self, truncated: bool) -> Self {
        self.truncated = truncated;
        self
    }

    #[must_use]
    pub fn with_status(mut self, status: SnapshotStatus) -> Self {
        self.snapshot_status = status;
        self
    }

    #[must_use]
    pub fn with_response_bytes(mut self, response_bytes: usize) -> Self {
        self.response_bytes = response_bytes;
        self
    }

    fn for_request(
        &self,
        request: &ProjectSnapshotReadRequest,
        provenance: TransportProvenance,
    ) -> Self {
        let mut response = self.clone();
        response.request_page_token.clone_from(&request.page_token);
        response.provenance = provenance;
        response
    }
}

/// A safe bounded projection. Its payload is limited to the allowlisted
/// evidence union and all descriptive text is represented by digests.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectSnapshotProjection {
    pub scope: SnykScope,
    pub scope_digest: Digest,
    pub snapshot_digest: Digest,
    pub snapshot_status: SnapshotStatus,
    pub evidence: Vec<Evidence>,
    pub completeness: ProjectionCompleteness,
    pub response_truncated: bool,
    pub response_bytes: usize,
    pub provider_request_id_digest: Digest,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub raw_dependency_graph_retained: bool,
    pub arbitrary_source_export: bool,
    pub projection_digest: Digest,
}

impl ProjectSnapshotProjection {
    fn from_parts(
        scope: SnykScope,
        status: SnapshotStatus,
        evidence: Vec<Evidence>,
        truncated: bool,
        response_bytes: usize,
        provider_request_id_digest: Digest,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        let mut projection = Self {
            scope_digest: scope.digest(),
            snapshot_digest: Digest::from_text("unsealed-snyk-snapshot"),
            scope,
            snapshot_status: status,
            evidence,
            completeness: if truncated {
                ProjectionCompleteness::Truncated
            } else {
                ProjectionCompleteness::Complete
            },
            response_truncated: truncated,
            response_bytes,
            provider_request_id_digest,
            provenance,
            connected: false,
            native: false,
            raw_dependency_graph_retained: false,
            arbitrary_source_export: false,
            projection_digest: Digest::from_text("unsealed-snyk-projection"),
        };
        projection.snapshot_digest = Digest::from_serialized(&(
            &projection.scope.snapshot,
            projection.snapshot_status,
            &projection.evidence,
            projection.response_truncated,
        ));
        projection.projection_digest = projection.calculate_digest();
        projection.validate_integrity()?;
        Ok(projection)
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.scope.validate()?;
        if self.scope_digest != self.scope.digest()
            || self.snapshot_digest
                != Digest::from_serialized(&(
                    &self.scope.snapshot,
                    self.snapshot_status,
                    &self.evidence,
                    self.response_truncated,
                ))
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.evidence.len() > MAX_EVIDENCE_ITEMS
            || self.connected
            || self.native
            || self.raw_dependency_graph_retained
            || self.arbitrary_source_export
            || self.provenance.is_native()
            || self.provenance.claims_connected()
            || self.projection_digest != self.calculate_digest()
        {
            return Err(SnykSecurityResultError::TamperedEvidence);
        }
        self.provider_request_id_digest.validate()?;
        for evidence in &self.evidence {
            evidence.validate_for_scope(&self.scope)?;
        }
        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        self.completeness == ProjectionCompleteness::Complete
    }

    pub fn is_review_only(&self) -> bool {
        true
    }

    pub fn vulnerability_count(&self) -> usize {
        self.evidence
            .iter()
            .filter(|evidence| matches!(evidence, Evidence::Vulnerability(_)))
            .count()
    }

    pub fn license_count(&self) -> usize {
        self.evidence
            .iter()
            .filter(|evidence| matches!(evidence, Evidence::License(_)))
            .count()
    }

    pub fn iac_count(&self) -> usize {
        self.evidence
            .iter()
            .filter(|evidence| matches!(evidence, Evidence::Iac(_)))
            .count()
    }

    pub fn computed_digest(&self) -> Digest {
        self.calculate_digest()
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_serialized(&(
            &self.scope_digest,
            &self.snapshot_digest,
            self.snapshot_status,
            &self.evidence,
            self.completeness,
            self.response_truncated,
            self.response_bytes,
            &self.provider_request_id_digest,
            self.provenance,
        ))
    }
}

/// The only provider transport seam. Layer 1 implementations are all
/// deterministic fixtures; a live implementation is an explicit Layer-2
/// responsibility.
pub trait SnykTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn read_project_snapshot(
        &mut self,
        request: &ProjectSnapshotReadRequest,
    ) -> std::result::Result<ProjectSnapshotResponse, SnykTransportError>;
}

#[derive(Clone, Debug)]
pub struct RecordingTransport {
    response: ProjectSnapshotResponse,
    error: Option<SnykTransportError>,
    requests: Vec<Digest>,
}

impl RecordingTransport {
    pub fn new(response: ProjectSnapshotResponse) -> Self {
        Self {
            response,
            error: None,
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_error(mut self, error: SnykTransportError) -> Self {
        self.error = Some(error);
        self
    }

    pub fn request_count(&self) -> usize {
        self.requests.len()
    }

    pub fn request_digests(&self) -> &[Digest] {
        &self.requests
    }
}

impl SnykTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn read_project_snapshot(
        &mut self,
        request: &ProjectSnapshotReadRequest,
    ) -> std::result::Result<ProjectSnapshotResponse, SnykTransportError> {
        self.requests.push(request.digest());
        if let Some(error) = &self.error {
            return Err(error.clone());
        }
        Ok(self.response.for_request(request, self.provenance()))
    }
}

#[derive(Clone, Debug)]
pub struct FakeTransport {
    response: ProjectSnapshotResponse,
    error: Option<SnykTransportError>,
    requests: usize,
}

impl FakeTransport {
    pub fn new(response: ProjectSnapshotResponse) -> Self {
        Self {
            response,
            error: None,
            requests: 0,
        }
    }

    #[must_use]
    pub fn with_error(mut self, error: SnykTransportError) -> Self {
        self.error = Some(error);
        self
    }

    pub const fn request_count(&self) -> usize {
        self.requests
    }
}

impl SnykTransport for FakeTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fake
    }

    fn read_project_snapshot(
        &mut self,
        request: &ProjectSnapshotReadRequest,
    ) -> std::result::Result<ProjectSnapshotResponse, SnykTransportError> {
        self.requests += 1;
        if let Some(error) = &self.error {
            return Err(error.clone());
        }
        Ok(self.response.for_request(request, self.provenance()))
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    response: ProjectSnapshotResponse,
    error: Option<SnykTransportError>,
}

impl LoopbackTransport {
    pub fn new(response: ProjectSnapshotResponse) -> Self {
        Self {
            response,
            error: None,
        }
    }

    #[must_use]
    pub fn with_error(mut self, error: SnykTransportError) -> Self {
        self.error = Some(error);
        self
    }
}

impl SnykTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn read_project_snapshot(
        &mut self,
        request: &ProjectSnapshotReadRequest,
    ) -> std::result::Result<ProjectSnapshotResponse, SnykTransportError> {
        if let Some(error) = &self.error {
            return Err(error.clone());
        }
        Ok(self.response.for_request(request, self.provenance()))
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport;

impl BlockedEnvTransport {
    pub const fn new() -> Self {
        Self
    }
}

impl SnykTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn read_project_snapshot(
        &mut self,
        _request: &ProjectSnapshotReadRequest,
    ) -> std::result::Result<ProjectSnapshotResponse, SnykTransportError> {
        Err(SnykTransportError::EnvironmentBlocked)
    }
}

/// Typed, read-only Snyk provider. It checks the full registration and exact
/// identity fence before projecting any provider response.
#[derive(Clone, Debug)]
pub struct SnykProvider<T> {
    registration: SnykRegistration,
    transport: T,
}

impl<T: SnykTransport> SnykProvider<T> {
    pub fn new(
        registration: SnykRegistration,
        transport: T,
    ) -> std::result::Result<Self, SnykProviderError> {
        registration
            .validate()
            .map_err(SnykProviderError::Registration)?;
        if registration.secret_reference().is_revoked() {
            return Err(SnykProviderError::SecretRevoked);
        }
        match registration.status() {
            crate::RegistrationStatus::Active => Ok(Self {
                registration,
                transport,
            }),
            crate::RegistrationStatus::Revoked => Err(SnykProviderError::RegistrationRevoked),
            crate::RegistrationStatus::Reversed => Err(SnykProviderError::RegistrationReversed),
        }
    }

    pub fn registration(&self) -> &SnykRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut SnykRegistration {
        &mut self.registration
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub const fn connected(&self) -> bool {
        false
    }

    pub const fn native(&self) -> bool {
        false
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn read_project_snapshot(
        &mut self,
        request_id: impl Into<String>,
    ) -> std::result::Result<ProjectSnapshotProjection, SnykProviderError> {
        self.read_project_snapshot_with_page_size(request_id, MAX_PAGE_SIZE)
    }

    pub fn read_snapshot(
        &mut self,
        request_id: impl Into<String>,
    ) -> std::result::Result<ProjectSnapshotProjection, SnykProviderError> {
        self.read_project_snapshot(request_id)
    }

    pub fn read_project_snapshot_with_page_size(
        &mut self,
        request_id: impl Into<String>,
        page_size: usize,
    ) -> std::result::Result<ProjectSnapshotProjection, SnykProviderError> {
        self.ensure_registration_active()?;
        let request_id = request_id.into();
        let scope = self.registration.scope().clone();
        let mut page_token = None;
        let mut seen_tokens = BTreeSet::new();
        let mut pages = 0;
        let mut total_response_bytes: usize = 0;
        let mut all_evidence = Vec::new();
        let mut truncated = false;

        let (status, provider_request_id_digest, provenance) = loop {
            pages += 1;
            let request = ProjectSnapshotReadRequest::new(
                scope.clone(),
                request_id.clone(),
                page_size,
                page_token.clone(),
            )
            .map_err(SnykProviderError::Registration)?;
            let response = self.transport.read_project_snapshot(&request)?;
            Self::validate_response(&response, &scope, &request)?;
            total_response_bytes = total_response_bytes
                .checked_add(response.response_bytes)
                .ok_or(SnykProviderError::ResponseTooLarge)?;
            if total_response_bytes > MAX_RESPONSE_BYTES {
                return Err(SnykProviderError::ResponseTooLarge);
            }
            if all_evidence
                .len()
                .checked_add(response.evidence.len())
                .is_none_or(|count| count > MAX_EVIDENCE_ITEMS)
            {
                return Err(SnykProviderError::EvidenceLimit);
            }
            all_evidence.extend(response.evidence);
            truncated |= response.truncated;

            let Some(next_page_token) = response.next_page_token else {
                break (
                    response.snapshot_status,
                    response.provider_request_id_digest,
                    response.provenance,
                );
            };
            validate_text(&next_page_token, "nextPageToken", MAX_PAGE_TOKEN_BYTES)
                .map_err(|_| SnykProviderError::TamperedEvidence)?;
            if !seen_tokens.insert(next_page_token.clone()) {
                return Err(SnykProviderError::PaginationLoop);
            }
            if pages >= MAX_PAGES {
                return Err(SnykProviderError::PaginationLimit);
            }
            page_token = Some(next_page_token);
        };

        ProjectSnapshotProjection::from_parts(
            scope,
            status,
            all_evidence,
            truncated,
            total_response_bytes,
            provider_request_id_digest,
            provenance,
        )
        .map_err(SnykProviderError::Registration)
    }

    fn ensure_registration_active(&self) -> std::result::Result<(), SnykProviderError> {
        self.registration
            .validate()
            .map_err(|_| SnykProviderError::RegistrationDrift)?;
        if self.registration.secret_reference().is_revoked() {
            return Err(SnykProviderError::SecretRevoked);
        }
        match self.registration.status() {
            crate::RegistrationStatus::Active => Ok(()),
            crate::RegistrationStatus::Revoked => Err(SnykProviderError::RegistrationRevoked),
            crate::RegistrationStatus::Reversed => Err(SnykProviderError::RegistrationReversed),
        }
    }

    fn validate_response(
        response: &ProjectSnapshotResponse,
        scope: &SnykScope,
        request: &ProjectSnapshotReadRequest,
    ) -> std::result::Result<(), SnykProviderError> {
        response
            .scope
            .validate()
            .map_err(|_| SnykProviderError::TamperedEvidence)?;
        if response.scope.region != scope.region {
            return Err(SnykProviderError::RegionDrift);
        }
        if response.scope.organization != scope.organization {
            return Err(SnykProviderError::OrganizationDrift);
        }
        if response.scope.group != scope.group {
            return Err(SnykProviderError::GroupDrift);
        }
        if response.scope.target != scope.target {
            return Err(SnykProviderError::TargetDrift);
        }
        if response.scope.project != scope.project {
            return Err(SnykProviderError::ProjectDrift);
        }
        if response.scope.snapshot != scope.snapshot {
            return Err(SnykProviderError::SnapshotDrift);
        }
        if response.scope.issue != scope.issue {
            return Err(SnykProviderError::IssueDrift);
        }
        if response.scope.package != scope.package {
            return Err(SnykProviderError::PackageDrift);
        }
        if response.scope.path != scope.path {
            return Err(SnykProviderError::PathDrift);
        }
        if response.scope.commit != scope.commit {
            return Err(SnykProviderError::CommitDrift);
        }
        if response.scope.mission != scope.mission {
            return Err(SnykProviderError::MissionDrift);
        }
        if response.scope.hartevo_project != scope.hartevo_project {
            return Err(SnykProviderError::ProjectContextDrift);
        }
        if response.scope.work_product != scope.work_product {
            return Err(SnykProviderError::WorkProductDrift);
        }
        if response.request_page_token != request.page_token {
            return Err(SnykProviderError::TamperedEvidence);
        }
        if response.response_bytes > MAX_RESPONSE_BYTES {
            return Err(SnykProviderError::ResponseTooLarge);
        }
        if response.evidence.len() > MAX_EVIDENCE_ITEMS {
            return Err(SnykProviderError::EvidenceLimit);
        }
        response
            .provider_request_id_digest
            .validate()
            .map_err(|_| SnykProviderError::TamperedEvidence)?;
        if response.provenance.is_native() || response.provenance.claims_connected() {
            return Err(SnykProviderError::TamperedEvidence);
        }
        for evidence in &response.evidence {
            evidence
                .validate_for_scope(scope)
                .map_err(|error| match error {
                    SnykSecurityResultError::ScopeMismatch
                    | SnykSecurityResultError::EvidenceNotAllowlisted => {
                        SnykProviderError::EvidenceNotAllowlisted
                    }
                    _ => SnykProviderError::TamperedEvidence,
                })?;
        }
        Ok(())
    }
}

//! OneTrust consent-evidence service orchestration.

use std::{fmt, time::SystemTime};

use chrono::{DateTime, Utc};
use hartevo_plugin_runtime::{
    CompatibilityPolicy, Digest as RuntimeDigest, PluginVersion, ProviderCardinality,
    ServiceDefinition, ServiceId,
};
use serde::{Deserialize, Serialize};

use crate::model::{
    ConsentEvidenceStatus, Digest, OneTrustConsentEvidence, OneTrustConsentProjection,
    OneTrustConsentScope, OneTrustEndpoint, OneTrustEvidenceBundle, OneTrustEvidenceProposal,
    OneTrustProviderErrorEvidence, OneTrustProviderErrorKind, OneTrustReadEvidence,
    OneTrustReadRequest, OneTrustRecordingReceipt, OneTrustRegistration, OneTrustVerification,
    SecretReference,
};
use crate::provider::{OneTrustConsentProvider, OneTrustProviderError};
use crate::transport::OneTrustTransport;
use crate::{
    ONETRUST_CONTRACT_VERSION, ONETRUST_MAX_PAGES, ONETRUST_PAGE_SIZE,
    ONETRUST_PLUGIN_VERSION_TEXT, ONETRUST_PROVIDER_ID, ONETRUST_SERVICE_ID, ONETRUST_SERVICE_NAME,
    ONETRUST_SERVICE_SCHEMA, OneTrustConsentResultContract, OneTrustConsentResultError,
    contract_digest, plugin_version,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OneTrustServiceOperation {
    DescribeCapabilities,
    Register,
    RevokeRegistration,
    ReadBoundedConsentEvidence,
    CompileEvidenceProposal,
    RecordProposal,
    VerifyProposal,
}

impl OneTrustServiceOperation {
    pub const ALL: [Self; 7] = [
        Self::DescribeCapabilities,
        Self::Register,
        Self::RevokeRegistration,
        Self::ReadBoundedConsentEvidence,
        Self::CompileEvidenceProposal,
        Self::RecordProposal,
        Self::VerifyProposal,
    ];

    pub const fn is_read_only(self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OneTrustCapability {
    pub capability_id: String,
    pub operation: OneTrustServiceOperation,
    pub read_only: bool,
    pub mutates_provider: bool,
    pub native: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OneTrustEvidenceProposalRequest {
    pub page_size: u16,
    pub max_pages: u16,
    pub observed_at: DateTime<Utc>,
}

impl OneTrustEvidenceProposalRequest {
    pub fn new(observed_at: DateTime<Utc>) -> Self {
        Self {
            page_size: ONETRUST_PAGE_SIZE,
            max_pages: ONETRUST_MAX_PAGES,
            observed_at,
        }
    }

    #[must_use]
    pub fn with_bounds(mut self, page_size: u16, max_pages: u16) -> Self {
        self.page_size = page_size;
        self.max_pages = max_pages;
        self
    }
}

pub struct OneTrustConsentEvidenceService<T> {
    scope: OneTrustConsentScope,
    secret_reference: SecretReference,
    secret_revoked: bool,
    registration: OneTrustRegistration,
    provider: OneTrustConsentProvider<T>,
}

impl<T: fmt::Debug> fmt::Debug for OneTrustConsentEvidenceService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OneTrustConsentEvidenceService")
            .field("scope", &self.scope)
            .field("secret_reference", &self.secret_reference)
            .field("secret_revoked", &self.secret_revoked)
            .field("registration", &self.registration)
            .field("provider", &self.provider)
            .finish()
    }
}

impl<T: OneTrustTransport> OneTrustConsentEvidenceService<T> {
    pub fn new(
        scope: OneTrustConsentScope,
        secret_reference: SecretReference,
        provider: OneTrustConsentProvider<T>,
    ) -> Result<Self, OneTrustConsentResultError> {
        scope.validate()?;
        OneTrustConsentResultContract::baseline()?;
        let definition = provider.definition();
        let registration = OneTrustRegistration::new(
            &scope,
            &secret_reference,
            definition.provider_id.clone(),
            definition.implementation.clone(),
            definition.version.clone(),
            definition.provider_revision.clone(),
            definition.provider_digest.clone(),
            contract_digest(),
        )?;
        registration.validate(
            &scope,
            &secret_reference,
            &definition.provider_id,
            &definition.implementation,
            &definition.version,
            &definition.provider_revision,
            &definition.provider_digest,
            &contract_digest(),
        )?;
        Ok(Self {
            scope,
            secret_reference,
            secret_revoked: false,
            registration,
            provider,
        })
    }

    pub fn register(
        scope: OneTrustConsentScope,
        secret_reference: SecretReference,
        provider: OneTrustConsentProvider<T>,
    ) -> Result<Self, OneTrustConsentResultError> {
        Self::new(scope, secret_reference, provider)
    }

    pub fn scope(&self) -> &OneTrustConsentScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn registration(&self) -> &OneTrustRegistration {
        &self.registration
    }

    /// Exposes the typed registration for host-side inspection and deliberate
    /// drift tests. Every service operation revalidates it before reading or
    /// recording, so tampering fails closed.
    pub fn registration_mut(&mut self) -> &mut OneTrustRegistration {
        &mut self.registration
    }

    pub fn provider(&self) -> &OneTrustConsentProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut OneTrustConsentProvider<T> {
        &mut self.provider
    }

    pub fn is_active(&self) -> bool {
        self.registration.is_active() && !self.secret_revoked
    }

    pub fn revoke_registration(&mut self) -> Result<(), OneTrustConsentResultError> {
        self.registration
            .revoke()
            .map_err(|_| OneTrustConsentResultError::RegistrationRevoked)
    }

    pub fn revoke_secret(&mut self) -> Result<(), OneTrustConsentResultError> {
        if self.secret_revoked {
            return Err(OneTrustConsentResultError::SecretRevoked);
        }
        self.secret_revoked = true;
        Ok(())
    }

    pub fn service_id(&self) -> &'static str {
        ONETRUST_SERVICE_ID
    }

    pub fn service_name(&self) -> &'static str {
        ONETRUST_SERVICE_NAME
    }

    pub const fn version(&self) -> PluginVersion {
        plugin_version()
    }

    pub const fn read_only(&self) -> bool {
        true
    }

    pub const fn native_connected(&self) -> bool {
        false
    }

    pub fn describe_capabilities(&self) -> Vec<OneTrustCapability> {
        [
            (
                "onetrust.consent-evidence.register",
                OneTrustServiceOperation::Register,
            ),
            (
                "onetrust.consent-evidence.revoke_registration",
                OneTrustServiceOperation::RevokeRegistration,
            ),
            (
                "onetrust.consent-evidence.read_bounded_consent_evidence",
                OneTrustServiceOperation::ReadBoundedConsentEvidence,
            ),
            (
                "onetrust.consent-evidence.compile_evidence_proposal",
                OneTrustServiceOperation::CompileEvidenceProposal,
            ),
            (
                "onetrust.consent-evidence.record_proposal",
                OneTrustServiceOperation::RecordProposal,
            ),
            (
                "onetrust.consent-evidence.verify_proposal",
                OneTrustServiceOperation::VerifyProposal,
            ),
        ]
        .into_iter()
        .map(|(capability_id, operation)| OneTrustCapability {
            capability_id: capability_id.to_owned(),
            operation,
            read_only: true,
            mutates_provider: false,
            native: false,
        })
        .collect()
    }

    pub fn runtime_definition(&self) -> Result<ServiceDefinition, OneTrustConsentResultError> {
        ServiceDefinition::read_only(
            ServiceId::new(ONETRUST_SERVICE_ID)?,
            plugin_version(),
            RuntimeDigest::from_text(ONETRUST_SERVICE_SCHEMA),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )
        .map_err(Into::into)
    }

    pub fn read(
        &mut self,
        endpoint: OneTrustEndpoint,
        page_size: u16,
        max_pages: u16,
        observed_at: DateTime<Utc>,
    ) -> Result<OneTrustReadEvidence, OneTrustConsentResultError> {
        self.ensure_registration()?;
        let request =
            OneTrustReadRequest::new(endpoint, &self.scope, page_size, max_pages, observed_at)?;
        self.provider
            .read_with_secret(&self.secret_reference, &request)
            .map_err(map_provider_error)
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn propose(
        &mut self,
        request: OneTrustEvidenceProposalRequest,
    ) -> Result<OneTrustEvidenceProposal, OneTrustConsentResultError> {
        self.ensure_registration()?;
        if request.page_size == 0
            || request.page_size > ONETRUST_PAGE_SIZE
            || request.max_pages == 0
            || request.max_pages > ONETRUST_MAX_PAGES
        {
            return Err(OneTrustConsentResultError::InvalidInput(
                "OneTrust proposal bounds exceed the Layer-1 contract".to_owned(),
            ));
        }
        let mut reads = Vec::new();
        let mut failures = Vec::new();
        for endpoint in self.scope.expected_endpoints() {
            match self.read(
                endpoint,
                request.page_size,
                request.max_pages,
                request.observed_at,
            ) {
                Ok(evidence) => reads.push(evidence),
                Err(error) => failures.push(failure_from_service_error(endpoint, &error)),
            }
        }
        let bundle = OneTrustEvidenceBundle::new(
            &self.scope,
            self.registration.registration_digest.clone(),
            self.provider.provider_digest().clone(),
            self.provider.provider_revision().clone(),
            reads,
            failures,
            self.provider.provenance(),
        )?;
        self.compile_evidence_proposal(bundle, request.observed_at)
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn compile_evidence_proposal(
        &self,
        bundle: OneTrustEvidenceBundle,
        observed_at: DateTime<Utc>,
    ) -> Result<OneTrustEvidenceProposal, OneTrustConsentResultError> {
        self.ensure_registration()?;
        self.validate_bundle(&bundle)?;
        let status = project_status(&bundle, observed_at);
        let evidence = compile_evidence(&self.scope, &bundle, status, observed_at)?;
        let projection = OneTrustConsentProjection {
            status,
            observed_record_count: evidence.observations.len(),
            read_count: bundle.reads.len(),
            partial: status == ConsentEvidenceStatus::Partial,
            fail_closed: status != ConsentEvidenceStatus::Granted,
            rationale_digest: Digest::from_fields([
                "hartevo-onetrust-projection-v1",
                bundle.evidence_digest.as_str(),
                evidence.result_digest.as_str(),
                &format!("{status:?}"),
            ]),
        };
        let mut proposal = OneTrustEvidenceProposal {
            plugin_version: ONETRUST_PLUGIN_VERSION_TEXT.to_owned(),
            contract_version: ONETRUST_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: ONETRUST_PROVIDER_ID.to_owned(),
            provider_implementation: crate::ONETRUST_PROVIDER_NAME.to_owned(),
            provider_version: self.provider.definition().version.clone(),
            provider_revision: self.provider.provider_revision().clone(),
            provider_digest: self.provider.provider_digest().clone(),
            registration_digest: self.registration.registration_digest.clone(),
            registration_revision: self.registration.registration_revision,
            scope_digest: self.scope.scope_digest(),
            permission_digest: self.scope.permission_digest.clone(),
            mission_revision: self.scope.mission_revision(),
            project_revision: self.scope.project_revision(),
            consent_revision: self.scope.consent_revision(),
            work_product_revision: self.scope.work_product_revision(),
            projection,
            evidence,
            provenance: bundle.provenance,
            read_only: true,
            proposal_only: true,
            native: false,
            connected: false,
            consent_receipt_created: false,
            consent_withdrawn: false,
            preference_updated: false,
            adopted_by_kernel: false,
            proposal_digest: Digest::zero(),
        };
        proposal.proposal_digest = proposal.recompute_digest()?;
        Ok(proposal)
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn compile_proposal(
        &self,
        bundle: OneTrustEvidenceBundle,
        observed_at: DateTime<Utc>,
    ) -> Result<OneTrustEvidenceProposal, OneTrustConsentResultError> {
        self.compile_evidence_proposal(bundle, observed_at)
    }

    pub fn record(
        &self,
        proposal: &OneTrustEvidenceProposal,
    ) -> Result<OneTrustRecordingReceipt, OneTrustConsentResultError> {
        self.ensure_registration()?;
        self.verify(proposal)?;
        Ok(OneTrustRecordingReceipt {
            contract_version: ONETRUST_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            registration_digest: self.registration.registration_digest.clone(),
            scope_digest: self.scope.scope_digest(),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            provenance: proposal.provenance,
            recorded: true,
            raw_provider_payload_retained: false,
            raw_subject_identifier_retained: false,
            raw_jwt_retained: false,
            consent_receipt_created: false,
            preference_updated: false,
            native: false,
            connected: false,
        })
    }

    pub fn verify(
        &self,
        proposal: &OneTrustEvidenceProposal,
    ) -> Result<OneTrustVerification, OneTrustConsentResultError> {
        self.ensure_registration()?;
        if proposal.proposal_digest != proposal.recompute_digest()? {
            return Err(OneTrustConsentResultError::StaleProposal);
        }
        if proposal.contract_digest != contract_digest()
            || proposal.contract_version != ONETRUST_CONTRACT_VERSION
            || proposal.provider_id != ONETRUST_PROVIDER_ID
            || proposal.provider_implementation != crate::ONETRUST_PROVIDER_NAME
            || proposal.provider_version != self.provider.definition().version
            || proposal.provider_revision != *self.provider.provider_revision()
            || proposal.provider_digest != *self.provider.provider_digest()
            || proposal.registration_digest != self.registration.registration_digest
            || proposal.registration_revision != self.registration.registration_revision
            || proposal.scope_digest != self.scope.scope_digest()
            || proposal.permission_digest != self.scope.permission_digest
            || proposal.mission_revision != self.scope.mission_revision()
            || proposal.project_revision != self.scope.project_revision()
            || proposal.consent_revision != self.scope.consent_revision()
            || proposal.work_product_revision != self.scope.work_product_revision()
            || proposal.evidence.scope_digest != self.scope.scope_digest()
            || proposal.evidence.subject_reference != self.scope.subject_reference
            || proposal.native
            || proposal.connected
            || proposal.consent_receipt_created
            || proposal.consent_withdrawn
            || proposal.preference_updated
            || proposal.adopted_by_kernel
        {
            return Err(OneTrustConsentResultError::StaleProposal);
        }
        Ok(OneTrustVerification {
            verified: true,
            registration_digest: self.registration.registration_digest.clone(),
            scope_digest: self.scope.scope_digest(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            native: false,
            connected: false,
            kernel_authority: false,
        })
    }

    fn validate_bundle(
        &self,
        bundle: &OneTrustEvidenceBundle,
    ) -> Result<(), OneTrustConsentResultError> {
        if bundle.scope_digest != self.scope.scope_digest()
            || bundle.registration_digest != self.registration.registration_digest
            || bundle.provider_digest != *self.provider.provider_digest()
            || bundle.provider_revision != *self.provider.provider_revision()
            || bundle.provenance != self.provider.provenance()
        {
            return Err(OneTrustConsentResultError::StaleEvidence);
        }
        let expected = OneTrustEvidenceBundle::new(
            &self.scope,
            bundle.registration_digest.clone(),
            bundle.provider_digest.clone(),
            bundle.provider_revision.clone(),
            bundle.reads.clone(),
            bundle.failures.clone(),
            bundle.provenance,
        )?;
        if expected.evidence_digest != bundle.evidence_digest {
            return Err(OneTrustConsentResultError::StaleEvidence);
        }
        Ok(())
    }

    fn ensure_registration(&self) -> Result<(), OneTrustConsentResultError> {
        if !self.registration.is_active() {
            return Err(OneTrustConsentResultError::RegistrationRevoked);
        }
        if self.secret_revoked {
            return Err(OneTrustConsentResultError::SecretRevoked);
        }
        let definition = self.provider.definition();
        self.registration
            .validate(
                &self.scope,
                &self.secret_reference,
                &definition.provider_id,
                &definition.implementation,
                &definition.version,
                &definition.provider_revision,
                &definition.provider_digest,
                &contract_digest(),
            )
            .map_err(|_| {
                OneTrustConsentResultError::RegistrationDrift(
                    "registration digest or bound revision drifted".to_owned(),
                )
            })
    }
}

fn map_provider_error(error: OneTrustProviderError) -> OneTrustConsentResultError {
    match error {
        OneTrustProviderError::BlockedEnv => OneTrustConsentResultError::BlockedEnv,
        OneTrustProviderError::RateLimited {
            retry_after_seconds,
        }
        | OneTrustProviderError::HttpStatus {
            status_code: 429,
            retry_after_seconds: Some(retry_after_seconds),
        } => OneTrustConsentResultError::RateLimited {
            retry_after_seconds,
        },
        OneTrustProviderError::Transport(crate::OneTrustTransportError::BlockedEnv) => {
            OneTrustConsentResultError::BlockedEnv
        }
        other => OneTrustConsentResultError::Provider(other.to_string()),
    }
}

fn failure_from_service_error(
    endpoint: OneTrustEndpoint,
    error: &OneTrustConsentResultError,
) -> OneTrustProviderErrorEvidence {
    let (kind, status_code, retry_after) = match error {
        OneTrustConsentResultError::BlockedEnv => {
            (OneTrustProviderErrorKind::BlockedEnv, None, None)
        }
        OneTrustConsentResultError::RateLimited {
            retry_after_seconds,
        } => (
            OneTrustProviderErrorKind::RateLimited,
            Some(429),
            Some(*retry_after_seconds),
        ),
        OneTrustConsentResultError::Provider(message) if message.contains("HTTP 401") => {
            (OneTrustProviderErrorKind::Unauthenticated, Some(401), None)
        }
        OneTrustConsentResultError::Provider(message) if message.contains("HTTP 403") => {
            (OneTrustProviderErrorKind::PermissionDenied, Some(403), None)
        }
        OneTrustConsentResultError::Provider(message) if message.contains("HTTP 404") => {
            (OneTrustProviderErrorKind::NotFound, Some(404), None)
        }
        OneTrustConsentResultError::Provider(message) if message.contains("HTTP 409") => {
            (OneTrustProviderErrorKind::Conflict, Some(409), None)
        }
        OneTrustConsentResultError::Provider(message) if message.contains("stale policy") => {
            (OneTrustProviderErrorKind::StalePolicyRevision, None, None)
        }
        OneTrustConsentResultError::Provider(message)
            if message.contains("repeated pagination") =>
        {
            (OneTrustProviderErrorKind::CursorLoop, None, None)
        }
        OneTrustConsentResultError::Provider(message) if message.contains("timed out") => {
            (OneTrustProviderErrorKind::Timeout, None, None)
        }
        OneTrustConsentResultError::StaleEvidence | OneTrustConsentResultError::StaleProposal => {
            (OneTrustProviderErrorKind::Tampered, None, None)
        }
        _ => (OneTrustProviderErrorKind::ProviderUnknown, None, None),
    };
    OneTrustProviderErrorEvidence::new(
        endpoint.operation_name(),
        kind,
        status_code,
        error.to_string(),
        retry_after,
    )
}

fn project_status(
    bundle: &OneTrustEvidenceBundle,
    observed_at: DateTime<Utc>,
) -> ConsentEvidenceStatus {
    let mut failure_status = None;
    for failure in &bundle.failures {
        let candidate = match failure.kind {
            OneTrustProviderErrorKind::Unauthenticated
            | OneTrustProviderErrorKind::PermissionDenied => ConsentEvidenceStatus::AccessLost,
            OneTrustProviderErrorKind::StalePolicyRevision => ConsentEvidenceStatus::Stale,
            OneTrustProviderErrorKind::Partial => ConsentEvidenceStatus::Partial,
            OneTrustProviderErrorKind::NotFound => ConsentEvidenceStatus::NoRecord,
            OneTrustProviderErrorKind::Conflict
            | OneTrustProviderErrorKind::RateLimited
            | OneTrustProviderErrorKind::ServerFailure
            | OneTrustProviderErrorKind::Timeout
            | OneTrustProviderErrorKind::CursorLoop
            | OneTrustProviderErrorKind::Tampered
            | OneTrustProviderErrorKind::InvalidResponse
            | OneTrustProviderErrorKind::BlockedEnv
            | OneTrustProviderErrorKind::ProviderUnknown => ConsentEvidenceStatus::ProviderUnknown,
        };
        failure_status = Some(match (failure_status, candidate) {
            (Some(existing), next) if status_priority(existing) >= status_priority(next) => {
                existing
            }
            (_, next) => next,
        });
    }
    if let Some(status) = failure_status
        && status != ConsentEvidenceStatus::NoRecord
    {
        return status;
    }
    let observations = bundle
        .reads
        .iter()
        .flat_map(|read| read.observations.iter());
    let latest = observations.max_by_key(|observation| observation.event_at());
    let Some(observation) = latest else {
        return failure_status.unwrap_or(ConsentEvidenceStatus::NoRecord);
    };
    if observation.status == ConsentEvidenceStatus::Granted
        && observation
            .expires_at
            .is_some_and(|expires_at| expires_at <= observed_at)
    {
        ConsentEvidenceStatus::Expired
    } else {
        observation.status
    }
}

fn status_priority(status: ConsentEvidenceStatus) -> u8 {
    match status {
        ConsentEvidenceStatus::ProviderUnknown => 100,
        ConsentEvidenceStatus::AccessLost => 90,
        ConsentEvidenceStatus::Stale => 80,
        ConsentEvidenceStatus::Partial => 70,
        ConsentEvidenceStatus::NoRecord => 60,
        ConsentEvidenceStatus::Expired => 50,
        ConsentEvidenceStatus::Withdrawn => 40,
        ConsentEvidenceStatus::Denied => 30,
        ConsentEvidenceStatus::Pending => 20,
        ConsentEvidenceStatus::Granted => 10,
    }
}

fn compile_evidence(
    scope: &OneTrustConsentScope,
    bundle: &OneTrustEvidenceBundle,
    status: ConsentEvidenceStatus,
    observed_at: DateTime<Utc>,
) -> Result<OneTrustConsentEvidence, OneTrustConsentResultError> {
    let observations = bundle
        .reads
        .iter()
        .flat_map(|read| read.observations.iter().cloned())
        .collect::<Vec<_>>();
    let pages_observed = bundle.reads.iter().map(|read| read.pages_observed).sum();
    let page_cursor_digests = bundle
        .reads
        .iter()
        .flat_map(|read| read.page_cursor_digests.iter().cloned())
        .collect::<Vec<_>>();
    let request_receipt_digests = bundle
        .reads
        .iter()
        .flat_map(|read| read.request_receipt_digests.iter().cloned())
        .collect::<Vec<_>>();
    let response_receipt_digests = bundle
        .reads
        .iter()
        .flat_map(|read| read.response_receipt_digests.iter().cloned())
        .collect::<Vec<_>>();
    let failures = bundle
        .failures
        .iter()
        .cloned()
        .chain(
            bundle
                .reads
                .iter()
                .flat_map(|read| read.failures.iter().cloned()),
        )
        .collect::<Vec<_>>();
    let mut source_fields = bundle
        .reads
        .iter()
        .flat_map(|read| [read.source_digest.as_str(), read.result_digest.as_str()])
        .chain(failures.iter().map(|failure| failure.error_digest.as_str()))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    source_fields.push(format!("{:?}", bundle.provenance));
    let source_digest = Digest::from_fields(source_fields);
    let result_digest = crate::digest_serializable(&(
        &scope.scope_digest(),
        status,
        observed_at,
        &observations,
        &page_cursor_digests,
        &request_receipt_digests,
        &response_receipt_digests,
        &failures,
        &source_digest,
    ))?;
    let evidence_digest = Digest::from_fields([
        "hartevo-onetrust-evidence-v1",
        bundle.evidence_digest.as_str(),
        result_digest.as_str(),
        source_digest.as_str(),
    ]);
    Ok(OneTrustConsentEvidence {
        status,
        scope_digest: scope.scope_digest(),
        subject_reference: scope.subject_reference.clone(),
        policy_revision: scope.policy_revision.clone(),
        observed_at,
        observations,
        pages_observed,
        page_cursor_digests,
        request_receipt_digests,
        response_receipt_digests,
        failures,
        provenance: bundle.provenance,
        source_digest,
        result_digest,
        evidence_digest,
        read_only: true,
        proposal_only: true,
        native: false,
        connected: false,
        raw_preference_payload_retained: false,
        raw_subject_identifier_retained: false,
        raw_jwt_retained: false,
        raw_pii_retained: false,
    })
}

#[allow(dead_code)]
fn _now_is_bounded() -> bool {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .is_ok()
}

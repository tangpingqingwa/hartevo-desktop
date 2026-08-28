use std::{collections::BTreeMap, env, fmt};

use serde::{Deserialize, Serialize};

use crate::error::{CloudRunDeploymentResultError, CloudRunTransportError};
use crate::model::{
    CloudRunDeploymentEvidence, CloudRunDeploymentReceipt, CloudRunDeploymentResultProposal,
    CloudRunReadRequest, CloudRunReadiness, CloudRunRegistration, CloudRunResultState,
    CloudRunScope, CloudRunServiceDescription, Digest, MAX_IDENTIFIER_BYTES, MAX_REVISION_PAGES,
    MAX_REVISIONS, NativeStatus, ProviderProvenance, RegistrationRevocation, RegistrationStatus,
    RevisionUid, SecretReference, ServiceUid,
};
use crate::transport::{CloudRunTransport, SecretMaterial};

pub const CLOUD_RUN_CREDENTIAL_ENVIRONMENT_VARIABLE: &str = "HARTEVO_CLOUD_RUN_CREDENTIAL";
pub const CLOUD_RUN_NATIVE_GATE_ENVIRONMENT_VARIABLE: &str = "HARTEVO_CLOUD_RUN_NATIVE";

/// The host resolves a SecretReference; the provider receives no Store,
/// keyring, browser-profile, or kernel authority.
pub trait CloudRunCredentialResolver: fmt::Debug + Send + Sync {
    fn resolve(
        &self,
        reference: &SecretReference,
    ) -> Result<SecretMaterial, CloudRunDeploymentResultError>;
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvCredentialResolver;

impl CloudRunCredentialResolver for BlockedEnvCredentialResolver {
    fn resolve(
        &self,
        _reference: &SecretReference,
    ) -> Result<SecretMaterial, CloudRunDeploymentResultError> {
        Err(CloudRunDeploymentResultError::BlockedEnv)
    }
}

#[derive(Clone, Debug, Default)]
pub struct EnvironmentCloudRunCredentialResolver;

impl CloudRunCredentialResolver for EnvironmentCloudRunCredentialResolver {
    fn resolve(
        &self,
        _reference: &SecretReference,
    ) -> Result<SecretMaterial, CloudRunDeploymentResultError> {
        if env::var(CLOUD_RUN_NATIVE_GATE_ENVIRONMENT_VARIABLE)
            .ok()
            .as_deref()
            != Some("1")
        {
            return Err(CloudRunDeploymentResultError::BlockedEnv);
        }
        let credential = env::var(CLOUD_RUN_CREDENTIAL_ENVIRONMENT_VARIABLE)
            .map_err(|_| CloudRunDeploymentResultError::BlockedEnv)?;
        if credential.trim().is_empty() || credential.len() > MAX_IDENTIFIER_BYTES * 8 {
            return Err(CloudRunDeploymentResultError::BlockedEnv);
        }
        Ok(SecretMaterial::new(credential))
    }
}

#[derive(Clone)]
pub struct StaticCloudRunCredentialResolver {
    material: SecretMaterial,
}

impl fmt::Debug for StaticCloudRunCredentialResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StaticCloudRunCredentialResolver(<redacted>)")
    }
}

impl StaticCloudRunCredentialResolver {
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            material: SecretMaterial::new(value),
        }
    }
}

impl CloudRunCredentialResolver for StaticCloudRunCredentialResolver {
    fn resolve(
        &self,
        _reference: &SecretReference,
    ) -> Result<SecretMaterial, CloudRunDeploymentResultError> {
        if self.material.as_str().trim().is_empty() {
            Err(CloudRunDeploymentResultError::BlockedEnv)
        } else {
            Ok(self.material.clone())
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudRunProviderState {
    Disconnected,
    ReadOnlyAvailable,
    Recording,
    Fake,
    Fixture,
    Loopback,
    AuthorizationObscured404,
    Unauthorized,
    Forbidden,
    NotFound,
    RateLimited,
    Conflict,
    BlockedEnv,
    Revoked,
    ProviderUnknown,
    Reconciling,
    Ready,
    Failed,
    TrafficDrift,
    Partial,
    Deleted,
    AccessLost,
}

#[derive(Debug)]
pub struct CloudRunProvider<T, R>
where
    T: CloudRunTransport,
    R: CloudRunCredentialResolver,
{
    registration: CloudRunRegistration,
    transport: T,
    credentials: R,
    state: CloudRunProviderState,
    last_service_uid: Option<ServiceUid>,
    last_revision_uid: Option<RevisionUid>,
    receipts: BTreeMap<Digest, CloudRunDeploymentReceipt>,
    evidence_fingerprints: BTreeMap<(Digest, ServiceUid), Digest>,
}

impl<T, R> CloudRunProvider<T, R>
where
    T: CloudRunTransport,
    R: CloudRunCredentialResolver,
{
    pub fn new(
        registration: CloudRunRegistration,
        transport: T,
        credentials: R,
    ) -> Result<Self, CloudRunDeploymentResultError> {
        registration.validate()?;
        if registration.status != RegistrationStatus::Active {
            return Err(CloudRunDeploymentResultError::RegistrationRevoked);
        }
        Ok(Self {
            registration,
            transport,
            credentials,
            state: CloudRunProviderState::Disconnected,
            last_service_uid: None,
            last_revision_uid: None,
            receipts: BTreeMap::new(),
            evidence_fingerprints: BTreeMap::new(),
        })
    }

    pub fn registration(&self) -> &CloudRunRegistration {
        &self.registration
    }

    pub fn state(&self) -> CloudRunProviderState {
        self.state
    }

    pub fn provenance(&self) -> ProviderProvenance {
        match self.state {
            CloudRunProviderState::BlockedEnv | CloudRunProviderState::Revoked => {
                ProviderProvenance::BlockedEnv
            }
            CloudRunProviderState::Recording => ProviderProvenance::Recording,
            CloudRunProviderState::Fake => ProviderProvenance::Fake,
            CloudRunProviderState::Fixture => ProviderProvenance::Fixture,
            CloudRunProviderState::Loopback => ProviderProvenance::Loopback,
            _ => self.transport.provenance(),
        }
    }

    pub fn native_status(&self) -> NativeStatus {
        NativeStatus::BlockedEnv
    }

    pub fn native_transport(&self) -> bool {
        self.provenance().is_native()
    }

    pub const fn native_connected(&self) -> bool {
        false
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn receipts(&self) -> &BTreeMap<Digest, CloudRunDeploymentReceipt> {
        &self.receipts
    }

    pub fn last_service_uid(&self) -> Option<&ServiceUid> {
        self.last_service_uid.as_ref()
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation, CloudRunDeploymentResultError> {
        let revocation = self.registration.revoke()?;
        self.state = CloudRunProviderState::Revoked;
        Ok(revocation)
    }

    pub fn describe_service(
        &mut self,
    ) -> Result<CloudRunServiceDescription, CloudRunDeploymentResultError> {
        self.ensure_active()?;
        let credential = self.authenticate()?;
        let record = self
            .transport
            .describe_service(&credential, &self.registration.scope)
            .map_err(|error| self.map_transport_error(error))?;
        record.validate_for(&self.registration.scope)?;
        self.ensure_service_identity(&record.service_uid)?;
        if record.generation != self.registration.scope.generation {
            self.state = CloudRunProviderState::ProviderUnknown;
            return Err(CloudRunDeploymentResultError::StaleGeneration);
        }
        self.mark_available();
        let provenance = self.provenance();
        let native_transport = self.native_transport();
        let mut description = CloudRunServiceDescription {
            scope: self.registration.scope.clone(),
            service_uid: record.service_uid,
            generation: record.generation,
            observed_generation: record.observed_generation,
            readiness: record.readiness,
            iam_policy_digest: record.iam.policy_digest,
            uri_metadata: record.uri_metadata,
            provenance,
            native_transport,
            native_connected: false,
            read_digest: Digest::pending(),
        };
        description.read_digest = description.computed_digest();
        description.validate()?;
        self.set_state_from_readiness(description.readiness);
        Ok(description)
    }

    #[allow(clippy::too_many_lines)]
    pub fn read_deployment_evidence(
        &mut self,
        request: &CloudRunReadRequest,
    ) -> Result<CloudRunDeploymentEvidence, CloudRunDeploymentResultError> {
        request.validate()?;
        self.ensure_active()?;
        self.ensure_scope(&request.scope)?;
        let credential = self.authenticate()?;
        let record = self
            .transport
            .describe_service(&credential, &self.registration.scope)
            .map_err(|error| self.map_transport_error(error))?;
        record.validate_for(&self.registration.scope)?;
        self.ensure_service_identity(&record.service_uid)?;
        if record.generation != self.registration.scope.generation {
            self.state = CloudRunProviderState::ProviderUnknown;
            return Err(CloudRunDeploymentResultError::StaleGeneration);
        }
        if record.revision_name != self.registration.scope.revision_name {
            self.state = CloudRunProviderState::ProviderUnknown;
            return Err(CloudRunDeploymentResultError::StaleRevision);
        }
        if record.source != self.registration.scope.source {
            self.state = CloudRunProviderState::ProviderUnknown;
            return Err(CloudRunDeploymentResultError::SourceDigestMismatch);
        }

        let mut pages_read = 0_usize;
        let mut revisions = Vec::new();
        let mut page_token = None;
        loop {
            if pages_read >= request.max_pages {
                self.state = CloudRunProviderState::ProviderUnknown;
                return Err(CloudRunDeploymentResultError::PaginationBoundExceeded);
            }
            let page = self
                .transport
                .list_revisions(
                    &credential,
                    &self.registration.scope,
                    page_token.as_deref(),
                    request.max_revisions.saturating_sub(revisions.len()).max(1),
                )
                .map_err(|error| self.map_transport_error(error))?;
            page.validate()?;
            pages_read += 1;
            revisions.extend(page.revisions);
            if revisions.len() > request.max_revisions {
                self.state = CloudRunProviderState::ProviderUnknown;
                return Err(CloudRunDeploymentResultError::PaginationBoundExceeded);
            }
            match page.next_page_token {
                Some(next) => {
                    if page_token.as_deref() == Some(next.as_str()) {
                        self.state = CloudRunProviderState::ProviderUnknown;
                        return Err(CloudRunDeploymentResultError::PaginationBoundExceeded);
                    }
                    page_token = Some(next);
                }
                None => break,
            }
        }

        let revision = revisions
            .iter()
            .find(|revision| revision.revision_name == self.registration.scope.revision_name)
            .cloned();
        let revision = match revision {
            Some(revision) => revision,
            None if record.deleted || record.access_lost => {
                crate::CloudRunRevisionRecord::unavailable_for(&self.registration.scope)?
            }
            None => {
                self.state = CloudRunProviderState::ProviderUnknown;
                return Err(CloudRunDeploymentResultError::StaleRevision);
            }
        };
        self.ensure_revision_identity(&revision.revision_uid)?;
        if revision.source != self.registration.scope.source {
            self.state = CloudRunProviderState::ProviderUnknown;
            return Err(CloudRunDeploymentResultError::SourceDigestMismatch);
        }
        if revision.generation != self.registration.scope.generation {
            self.state = CloudRunProviderState::ProviderUnknown;
            return Err(CloudRunDeploymentResultError::StaleGeneration);
        }
        let state = result_state(&record, &revision, &self.registration.scope);
        self.mark_available();
        let provenance = self.provenance();
        let native_transport = self.native_transport();
        let mut evidence = CloudRunDeploymentEvidence {
            scope: self.registration.scope.clone(),
            registration_digest: self.registration.registration_digest.clone(),
            service_uid: record.service_uid,
            service_generation: record.generation,
            observed_generation: record.observed_generation,
            revision_name: revision.revision_name,
            revision_uid: revision.revision_uid,
            source: revision.source,
            traffic: record.traffic,
            readiness: match state {
                CloudRunResultState::Deleted => CloudRunReadiness::Deleted,
                CloudRunResultState::AccessLost => CloudRunReadiness::AccessLost,
                _ => revision.readiness,
            },
            state,
            iam_policy_digest: record.iam.policy_digest,
            uri_metadata: record.uri_metadata,
            revision_count: revisions.len().max(1),
            page_count: pages_read,
            provenance,
            native_transport,
            native_connected: false,
            truncated: false,
            observed_at: "layer1-recorded".to_owned(),
            evidence_digest: Digest::pending(),
        };
        evidence.evidence_digest = evidence.computed_digest();
        evidence.validate()?;
        self.set_state_from_result(state);
        Ok(evidence)
    }

    pub fn read_evidence(
        &mut self,
    ) -> Result<CloudRunDeploymentEvidence, CloudRunDeploymentResultError> {
        let request = CloudRunReadRequest::new(
            self.registration.scope.clone(),
            self.registration.scope.mission_revision,
            self.registration.scope.work_product_revision,
        )?;
        self.read_deployment_evidence(&request)
    }

    pub fn compile_deployment_result_proposal(
        &self,
        evidence: &CloudRunDeploymentEvidence,
    ) -> Result<CloudRunDeploymentResultProposal, CloudRunDeploymentResultError> {
        self.ensure_active()?;
        evidence.validate()?;
        if evidence.registration_digest != self.registration.registration_digest {
            return Err(CloudRunDeploymentResultError::RegistrationDigestMismatch);
        }
        CloudRunDeploymentResultProposal::from_evidence(
            evidence,
            self.registration.registration_digest.clone(),
        )
    }

    pub fn record_deployment_receipt(
        &mut self,
        evidence: &CloudRunDeploymentEvidence,
    ) -> Result<CloudRunDeploymentReceipt, CloudRunDeploymentResultError> {
        self.ensure_active()?;
        evidence.validate()?;
        if evidence.registration_digest != self.registration.registration_digest {
            return Err(CloudRunDeploymentResultError::RegistrationDigestMismatch);
        }
        let key = (evidence.scope.digest(), evidence.service_uid.clone());
        if let Some(previous) = self.evidence_fingerprints.get(&key)
            && previous != &evidence.evidence_digest
        {
            return Err(CloudRunDeploymentResultError::DuplicateFingerprint);
        }
        if let Some(receipt) = self.receipts.get(&evidence.evidence_digest) {
            receipt.validate_against(evidence, &self.registration.registration_digest)?;
            return Ok(receipt.clone());
        }
        let receipt = CloudRunDeploymentReceipt::from_evidence(
            evidence,
            self.registration.registration_digest.clone(),
        )?;
        self.evidence_fingerprints
            .insert(key, evidence.evidence_digest.clone());
        self.receipts
            .insert(evidence.evidence_digest.clone(), receipt.clone());
        Ok(receipt)
    }

    pub fn verify_deployment_result(
        &self,
        proposal: &CloudRunDeploymentResultProposal,
        evidence: &CloudRunDeploymentEvidence,
        receipt: &CloudRunDeploymentReceipt,
    ) -> Result<CloudRunDeploymentResultProposal, CloudRunDeploymentResultError> {
        self.ensure_active()?;
        proposal.validate_for_registration(&self.registration.registration_digest)?;
        evidence.validate()?;
        receipt.validate_against(evidence, &self.registration.registration_digest)?;
        if proposal.scope != evidence.scope
            || proposal.evidence_digest != evidence.evidence_digest
            || proposal.result_digest != proposal.computed_digest()
        {
            return Err(CloudRunDeploymentResultError::ReceiptMismatch);
        }
        if !self.receipts.contains_key(&evidence.evidence_digest) {
            return Err(CloudRunDeploymentResultError::ReceiptNotRecorded);
        }
        Ok(proposal.clone())
    }

    pub fn reject_write(
        &self,
        operation: &'static str,
    ) -> Result<(), CloudRunDeploymentResultError> {
        Err(CloudRunDeploymentResultError::MutationForbidden { operation })
    }

    fn ensure_active(&self) -> Result<(), CloudRunDeploymentResultError> {
        if self.registration.status != RegistrationStatus::Active
            || self.state == CloudRunProviderState::Revoked
        {
            Err(CloudRunDeploymentResultError::RegistrationRevoked)
        } else {
            Ok(())
        }
    }

    fn authenticate(&mut self) -> Result<SecretMaterial, CloudRunDeploymentResultError> {
        let credential = self
            .credentials
            .resolve(&self.registration.secret_reference)
            .inspect_err(|_| self.state = CloudRunProviderState::BlockedEnv)?;
        if credential.as_str().trim().is_empty() {
            self.state = CloudRunProviderState::BlockedEnv;
            return Err(CloudRunDeploymentResultError::BlockedEnv);
        }
        Ok(credential)
    }

    fn mark_available(&mut self) {
        self.state = match self.transport.provenance() {
            ProviderProvenance::Recording => CloudRunProviderState::Recording,
            ProviderProvenance::Fake => CloudRunProviderState::Fake,
            ProviderProvenance::Fixture => CloudRunProviderState::Fixture,
            ProviderProvenance::Loopback => CloudRunProviderState::Loopback,
            ProviderProvenance::BlockedEnv => CloudRunProviderState::BlockedEnv,
            ProviderProvenance::OfficialHttps => CloudRunProviderState::ReadOnlyAvailable,
        };
    }

    fn map_transport_error(
        &mut self,
        error: CloudRunTransportError,
    ) -> CloudRunDeploymentResultError {
        self.state = match error {
            CloudRunTransportError::NotFoundOrUnauthorized => {
                CloudRunProviderState::AuthorizationObscured404
            }
            CloudRunTransportError::Unauthorized => CloudRunProviderState::Unauthorized,
            CloudRunTransportError::Forbidden => CloudRunProviderState::Forbidden,
            CloudRunTransportError::NotFound => CloudRunProviderState::NotFound,
            CloudRunTransportError::RateLimited { .. } => CloudRunProviderState::RateLimited,
            CloudRunTransportError::Conflict => CloudRunProviderState::Conflict,
            CloudRunTransportError::ServerUnavailable
            | CloudRunTransportError::Timeout
            | CloudRunTransportError::Network
            | CloudRunTransportError::Decode
            | CloudRunTransportError::ResponseTooLarge
            | CloudRunTransportError::UnprocessableEntity
            | CloudRunTransportError::InvalidConfiguration => self.state,
        };
        error.into()
    }

    fn ensure_scope(&self, scope: &CloudRunScope) -> Result<(), CloudRunDeploymentResultError> {
        if scope == &self.registration.scope {
            Ok(())
        } else {
            Err(CloudRunDeploymentResultError::ScopeMismatch)
        }
    }

    fn ensure_service_identity(
        &mut self,
        service_uid: &ServiceUid,
    ) -> Result<(), CloudRunDeploymentResultError> {
        if self
            .last_service_uid
            .as_ref()
            .is_some_and(|previous| previous != service_uid)
        {
            self.state = CloudRunProviderState::ProviderUnknown;
            return Err(CloudRunDeploymentResultError::SameNameReplacement);
        }
        self.last_service_uid = Some(service_uid.clone());
        Ok(())
    }

    fn ensure_revision_identity(
        &mut self,
        revision_uid: &RevisionUid,
    ) -> Result<(), CloudRunDeploymentResultError> {
        if self
            .last_revision_uid
            .as_ref()
            .is_some_and(|previous| previous != revision_uid)
        {
            self.state = CloudRunProviderState::ProviderUnknown;
            return Err(CloudRunDeploymentResultError::StaleRevision);
        }
        self.last_revision_uid = Some(revision_uid.clone());
        Ok(())
    }

    fn set_state_from_readiness(&mut self, readiness: CloudRunReadiness) {
        self.state = match readiness {
            CloudRunReadiness::Ready => CloudRunProviderState::Ready,
            CloudRunReadiness::Reconciling => CloudRunProviderState::Reconciling,
            CloudRunReadiness::Failed => CloudRunProviderState::Failed,
            CloudRunReadiness::Partial => CloudRunProviderState::Partial,
            CloudRunReadiness::Deleted => CloudRunProviderState::Deleted,
            CloudRunReadiness::AccessLost => CloudRunProviderState::AccessLost,
            CloudRunReadiness::Unknown => CloudRunProviderState::ProviderUnknown,
        };
    }

    fn set_state_from_result(&mut self, state: CloudRunResultState) {
        self.state = match state {
            CloudRunResultState::Ready => CloudRunProviderState::Ready,
            CloudRunResultState::Reconciling => CloudRunProviderState::Reconciling,
            CloudRunResultState::Failed => CloudRunProviderState::Failed,
            CloudRunResultState::TrafficDrift => CloudRunProviderState::TrafficDrift,
            CloudRunResultState::Partial => CloudRunProviderState::Partial,
            CloudRunResultState::Deleted => CloudRunProviderState::Deleted,
            CloudRunResultState::AccessLost => CloudRunProviderState::AccessLost,
            CloudRunResultState::ProviderUnknown => CloudRunProviderState::ProviderUnknown,
        };
    }
}

fn result_state(
    record: &crate::CloudRunServiceRecord,
    revision: &crate::CloudRunRevisionRecord,
    scope: &CloudRunScope,
) -> CloudRunResultState {
    if record.deleted {
        return CloudRunResultState::Deleted;
    }
    if record.access_lost || !record.iam.readable {
        return CloudRunResultState::AccessLost;
    }
    if record.traffic != scope.traffic {
        return CloudRunResultState::TrafficDrift;
    }
    if record.observed_generation > scope.generation
        || revision.observed_generation > scope.generation
    {
        return CloudRunResultState::ProviderUnknown;
    }
    if record.observed_generation < scope.generation
        || revision.observed_generation < scope.generation
    {
        return CloudRunResultState::Reconciling;
    }
    if matches!(record.readiness, CloudRunReadiness::Failed)
        || matches!(revision.readiness, CloudRunReadiness::Failed)
    {
        return CloudRunResultState::Failed;
    }
    match (record.readiness, revision.readiness) {
        (CloudRunReadiness::Unknown, _) | (_, CloudRunReadiness::Unknown) => {
            CloudRunResultState::ProviderUnknown
        }
        (CloudRunReadiness::Partial, _) | (_, CloudRunReadiness::Partial) => {
            CloudRunResultState::Partial
        }
        (CloudRunReadiness::Reconciling, _) | (_, CloudRunReadiness::Reconciling) => {
            CloudRunResultState::Reconciling
        }
        (CloudRunReadiness::Deleted, _) | (_, CloudRunReadiness::Deleted) => {
            CloudRunResultState::Deleted
        }
        (CloudRunReadiness::AccessLost, _) | (_, CloudRunReadiness::AccessLost) => {
            CloudRunResultState::AccessLost
        }
        (CloudRunReadiness::Failed, _) | (_, CloudRunReadiness::Failed) => {
            CloudRunResultState::Failed
        }
        (CloudRunReadiness::Ready, CloudRunReadiness::Ready) => CloudRunResultState::Ready,
    }
}

pub type CloudRunDeploymentResultProvider<T, R> = CloudRunProvider<T, R>;
pub type CloudRunRecordingProvider =
    CloudRunProvider<crate::RecordingCloudRunTransport, StaticCloudRunCredentialResolver>;

#[allow(dead_code)]
fn _bounded_constants() -> (usize, usize) {
    (MAX_REVISION_PAGES, MAX_REVISIONS)
}

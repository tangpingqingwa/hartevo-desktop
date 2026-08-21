use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AWS_VERIFIED_PERMISSIONS_PROVIDER_ID, AWS_VERIFIED_PERMISSIONS_PROVIDER_NAME,
    AWS_VERIFIED_PERMISSIONS_PROVIDER_SCHEMA, AWS_VERIFIED_PERMISSIONS_SCHEMA_VERSION,
    model::{
        AuthorizationDecision, AwsVerifiedPermissionsRegistration, AwsVerifiedPermissionsScope,
        DeterminingPolicyMetadata, Digest, EvidenceState, IsAuthorizedReadRequest,
        IsAuthorizedReadResponse, ModelError, ProviderId, SecretReference,
    },
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Fixture,
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("provider version is empty")]
    EmptyVersion,
    #[error("Layer 1 cannot register a native provider")]
    NativeProviderForbidden,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsVerifiedPermissionsProviderDefinition {
    pub schema_version: String,
    pub provider_id: String,
    pub provider_name: String,
    pub provider_version: String,
    pub version_digest: Digest,
    pub capability_digest: Digest,
    pub provenance: ProviderProvenance,
    pub operations: Vec<String>,
    pub native: bool,
    pub live_execution: bool,
    pub live_credential_resolution: bool,
    pub policy_mutation: bool,
    pub external_action_execution: bool,
}

pub type ProviderDefinition = AwsVerifiedPermissionsProviderDefinition;

impl AwsVerifiedPermissionsProviderDefinition {
    pub fn new(
        provider_version: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let provider_version = provider_version.into();
        if provider_version.is_empty() {
            return Err(ProviderDefinitionError::EmptyVersion);
        }
        if provenance.is_native() {
            return Err(ProviderDefinitionError::NativeProviderForbidden);
        }
        let operations = vec!["IsAuthorized".to_owned()];
        let version_digest = Digest::from_text(provider_version.as_bytes());
        let capability_digest = Digest::from_fields(
            "aws-verified-permissions-provider-capability/v1",
            &[
                AWS_VERIFIED_PERMISSIONS_SCHEMA_VERSION.to_owned(),
                AWS_VERIFIED_PERMISSIONS_PROVIDER_ID.to_owned(),
                provider_version.clone(),
                format!("{provenance:?}"),
                operations.join(","),
                "native=false".to_owned(),
                "live_execution=false".to_owned(),
                "live_credential_resolution=false".to_owned(),
                "policy_mutation=false".to_owned(),
                "external_action_execution=false".to_owned(),
            ],
        );
        Ok(Self {
            schema_version: AWS_VERIFIED_PERMISSIONS_SCHEMA_VERSION.to_owned(),
            provider_id: AWS_VERIFIED_PERMISSIONS_PROVIDER_ID.to_owned(),
            provider_name: AWS_VERIFIED_PERMISSIONS_PROVIDER_NAME.to_owned(),
            provider_version,
            version_digest,
            capability_digest,
            provenance,
            operations,
            native: false,
            live_execution: false,
            live_credential_resolution: false,
            policy_mutation: false,
            external_action_execution: false,
        })
    }

    pub fn provider_digest(&self) -> Digest {
        Digest::from_fields(
            "aws-verified-permissions-provider-definition/v1",
            &[
                self.schema_version.clone(),
                self.provider_id.clone(),
                self.provider_name.clone(),
                self.provider_version.clone(),
                self.version_digest.as_str().to_owned(),
                self.capability_digest.as_str().to_owned(),
                format!("{:?}", self.provenance),
                self.operations.join(","),
                self.native.to_string(),
                self.live_execution.to_string(),
                self.live_credential_resolution.to_string(),
                self.policy_mutation.to_string(),
                self.external_action_execution.to_string(),
                AWS_VERIFIED_PERMISSIONS_PROVIDER_SCHEMA.to_owned(),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), ProviderDefinitionError> {
        if self.schema_version != AWS_VERIFIED_PERMISSIONS_SCHEMA_VERSION
            || self.provider_id != AWS_VERIFIED_PERMISSIONS_PROVIDER_ID
            || self.provider_name != AWS_VERIFIED_PERMISSIONS_PROVIDER_NAME
            || self.provider_version.is_empty()
            || self.version_digest != Digest::from_text(self.provider_version.as_bytes())
            || self.operations != ["IsAuthorized".to_owned()]
            || self.native
            || self.live_execution
            || self.live_credential_resolution
            || self.policy_mutation
            || self.external_action_execution
        {
            Err(ProviderDefinitionError::NativeProviderForbidden)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    BlockedEnv,
    Unavailable,
    AccessLost,
    Partial,
    ContextMismatch,
    Replay,
    Tampered,
    InvalidRequest,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("AWS Verified Permissions transport returned {kind:?}")]
pub struct TransportError {
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub retryable: bool,
    pub blocked_env: bool,
    pub diagnostic_digest: Digest,
}

pub type AwsVerifiedPermissionsTransportError = TransportError;

impl TransportError {
    pub fn new(
        kind: ProviderErrorKind,
        status_code: Option<u16>,
        diagnostic: impl AsRef<[u8]>,
    ) -> Self {
        let retryable = matches!(
            kind,
            ProviderErrorKind::Unavailable | ProviderErrorKind::Partial
        );
        Self {
            kind,
            status_code,
            retryable,
            blocked_env: kind == ProviderErrorKind::BlockedEnv,
            diagnostic_digest: Digest::from_text(diagnostic),
        }
    }

    pub fn blocked_env() -> Self {
        Self::new(ProviderErrorKind::BlockedEnv, None, "BLOCKED_ENV")
    }

    pub fn access_lost() -> Self {
        Self::new(ProviderErrorKind::AccessLost, Some(403), "access-lost")
    }

    pub fn partial() -> Self {
        Self::new(ProviderErrorKind::Partial, None, "partial-evidence")
    }

    pub fn context_mismatch() -> Self {
        Self::new(
            ProviderErrorKind::ContextMismatch,
            Some(400),
            "context-mismatch",
        )
    }

    pub fn replay() -> Self {
        Self::new(ProviderErrorKind::Replay, Some(409), "replay")
    }

    pub fn tampered() -> Self {
        Self::new(ProviderErrorKind::Tampered, Some(400), "tampered")
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderError {
    #[error(transparent)]
    Definition(#[from] ProviderDefinitionError),
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error("kernel Consent reference is not active")]
    ConsentRequired,
    #[error(
        "provider returned an unsafe ALLOW with partial, lost, mismatched, or tampered evidence"
    )]
    UnsafeAllowEvidence,
    #[error("provider response evidence was tampered or did not match the request")]
    EvidenceMismatch,
}

pub type AwsVerifiedPermissionsProviderError = ProviderError;

pub trait AwsVerifiedPermissionsTransport: fmt::Debug {
    fn is_authorized(
        &mut self,
        request: &IsAuthorizedReadRequest,
    ) -> Result<IsAuthorizedReadResponse, TransportError>;
}

#[derive(Clone, Debug)]
pub struct IsAuthorizedRead {
    pub request: IsAuthorizedReadRequest,
    pub response: IsAuthorizedReadResponse,
    pub read_digest: Digest,
}

impl IsAuthorizedRead {
    fn new(
        request: IsAuthorizedReadRequest,
        response: IsAuthorizedReadResponse,
    ) -> Result<Self, ProviderError> {
        response
            .validate_against(&request)
            .map_err(|_| ProviderError::EvidenceMismatch)?;
        let read_digest = Digest::from_fields(
            "aws-verified-permissions-is-authorized-read/v1",
            &[
                request.request_digest.as_str().to_owned(),
                response.response_digest.as_str().to_owned(),
            ],
        );
        Ok(Self {
            request,
            response,
            read_digest,
        })
    }

    pub fn validate(&self) -> Result<(), ProviderError> {
        self.response
            .validate_against(&self.request)
            .map_err(|_| ProviderError::EvidenceMismatch)?;
        let expected = Digest::from_fields(
            "aws-verified-permissions-is-authorized-read/v1",
            &[
                self.request.request_digest.as_str().to_owned(),
                self.response.response_digest.as_str().to_owned(),
            ],
        );
        if expected == self.read_digest {
            Ok(())
        } else {
            Err(ProviderError::EvidenceMismatch)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorizationProposal {
    pub contract_version: String,
    pub provider_version: String,
    pub version_digest: Digest,
    pub provider_digest: Digest,
    pub registration_digest: Option<Digest>,
    pub request_digest: Digest,
    pub read_digest: Digest,
    pub decision: AuthorizationDecision,
    pub evidence_state: EvidenceState,
    pub determining_policy: Option<DeterminingPolicyMetadata>,
    pub principal_digest: Digest,
    pub resource_digest: Digest,
    pub context_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub policy_digest: Digest,
    pub evidence_digest: Digest,
    pub proposal_digest: Digest,
    pub effect_gate: crate::EffectGate,
}

impl AuthorizationProposal {
    fn from_read(
        definition: &AwsVerifiedPermissionsProviderDefinition,
        read: &IsAuthorizedRead,
    ) -> Self {
        let response = &read.response;
        let mut proposal = Self {
            contract_version: crate::AWS_VERIFIED_PERMISSIONS_CONTRACT_VERSION.to_owned(),
            provider_version: definition.provider_version.clone(),
            version_digest: definition.version_digest.clone(),
            provider_digest: definition.provider_digest(),
            registration_digest: None,
            request_digest: read.request.request_digest.clone(),
            read_digest: read.read_digest.clone(),
            decision: response.decision,
            evidence_state: response.evidence_state,
            determining_policy: response.determining_policy.clone(),
            principal_digest: response.principal_digest.clone(),
            resource_digest: response.resource_digest.clone(),
            context_digest: response.context_digest.clone(),
            permission_digest: read.request.permission_digest.clone(),
            scope_digest: read.request.scope_digest.clone(),
            policy_digest: response.policy_digest.clone(),
            evidence_digest: response.evidence_digest.clone(),
            proposal_digest: Digest::from_text([]),
            effect_gate: if response.decision == AuthorizationDecision::Allow {
                crate::EffectGate::KernelConsentAndEffectRequired
            } else {
                crate::EffectGate::NotApplicable
            },
        };
        proposal.proposal_digest = proposal.computed_digest();
        proposal
    }

    #[must_use]
    pub fn with_registration(mut self, registration: &AwsVerifiedPermissionsRegistration) -> Self {
        self.registration_digest = Some(registration.registration_digest.clone());
        self.proposal_digest = self.computed_digest();
        self
    }

    pub fn computed_digest(&self) -> Digest {
        Digest::from_fields(
            "aws-verified-permissions-authorization-proposal/v1",
            &[
                self.contract_version.clone(),
                self.provider_version.clone(),
                self.version_digest.as_str().to_owned(),
                self.provider_digest.as_str().to_owned(),
                self.registration_digest
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), |digest| digest.as_str().to_owned()),
                self.request_digest.as_str().to_owned(),
                self.read_digest.as_str().to_owned(),
                format!("{:?}", self.decision),
                format!("{:?}", self.evidence_state),
                self.determining_policy.as_ref().map_or_else(
                    || "none".to_owned(),
                    |policy| policy.policy_id_digest.as_str().to_owned(),
                ),
                self.principal_digest.as_str().to_owned(),
                self.resource_digest.as_str().to_owned(),
                self.context_digest.as_str().to_owned(),
                self.permission_digest.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.policy_digest.as_str().to_owned(),
                self.evidence_digest.as_str().to_owned(),
                format!("{:?}", self.effect_gate),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), ProviderError> {
        if self.proposal_digest == self.computed_digest() {
            Ok(())
        } else {
            Err(ProviderError::EvidenceMismatch)
        }
    }
}

#[derive(Debug)]
pub struct AwsVerifiedPermissionsProvider<T> {
    transport: T,
    definition: AwsVerifiedPermissionsProviderDefinition,
}

pub type AwsVerifiedPermissionsServicesProvider<T> = AwsVerifiedPermissionsProvider<T>;

impl<T: AwsVerifiedPermissionsTransport> AwsVerifiedPermissionsProvider<T> {
    pub fn new(
        transport: T,
        provider_version: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let definition =
            AwsVerifiedPermissionsProviderDefinition::new(provider_version, provenance)?;
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn definition(&self) -> &AwsVerifiedPermissionsProviderDefinition {
        &self.definition
    }

    pub fn provider_digest(&self) -> Digest {
        self.definition.provider_digest()
    }

    pub fn provenance(&self) -> ProviderProvenance {
        self.definition.provenance
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn register(
        &self,
        scope: &AwsVerifiedPermissionsScope,
    ) -> Result<AwsVerifiedPermissionsRegistration, ProviderError> {
        let provider_id = ProviderId::new(AWS_VERIFIED_PERMISSIONS_PROVIDER_ID)?;
        AwsVerifiedPermissionsRegistration::new(
            scope,
            provider_id,
            self.definition.provider_version.clone(),
            self.definition.provider_digest(),
        )
        .map_err(ProviderError::from)
    }

    pub fn is_authorized_read(
        &mut self,
        scope: &AwsVerifiedPermissionsScope,
        secret: &SecretReference,
    ) -> Result<IsAuthorizedRead, ProviderError> {
        if !scope.consent_active() {
            return Err(ProviderError::ConsentRequired);
        }
        let request = IsAuthorizedReadRequest::from_scope(scope, secret)?;
        let response = self.transport.is_authorized(&request)?;
        if response.decision == AuthorizationDecision::Allow
            && response.evidence_state != EvidenceState::Complete
        {
            return Err(ProviderError::UnsafeAllowEvidence);
        }
        IsAuthorizedRead::new(request, response)
    }

    pub fn read_is_authorized(
        &mut self,
        scope: &AwsVerifiedPermissionsScope,
        secret: &SecretReference,
    ) -> Result<IsAuthorizedRead, ProviderError> {
        self.is_authorized_read(scope, secret)
    }

    pub fn propose_authorization(
        &mut self,
        scope: &AwsVerifiedPermissionsScope,
        secret: &SecretReference,
    ) -> Result<AuthorizationProposal, ProviderError> {
        let read = self.is_authorized_read(scope, secret)?;
        Ok(AuthorizationProposal::from_read(&self.definition, &read))
    }

    pub fn propose_is_authorized(
        &mut self,
        scope: &AwsVerifiedPermissionsScope,
        secret: &SecretReference,
    ) -> Result<AuthorizationProposal, ProviderError> {
        self.propose_authorization(scope, secret)
    }

    pub fn propose(
        &mut self,
        scope: &AwsVerifiedPermissionsScope,
        secret: &SecretReference,
    ) -> Result<AuthorizationProposal, ProviderError> {
        self.propose_authorization(scope, secret)
    }
}

#[derive(Clone, Debug)]
pub struct RecordingAwsVerifiedPermissionsTransport {
    responses: VecDeque<Result<IsAuthorizedReadResponse, TransportError>>,
    requests: Vec<IsAuthorizedReadRequest>,
}

impl Default for RecordingAwsVerifiedPermissionsTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl RecordingAwsVerifiedPermissionsTransport {
    pub fn new() -> Self {
        Self {
            responses: VecDeque::new(),
            requests: Vec::new(),
        }
    }

    pub fn push_response(&mut self, response: IsAuthorizedReadResponse) {
        self.responses.push_back(Ok(response));
    }

    pub fn push_error(&mut self, error: TransportError) {
        self.responses.push_back(Err(error));
    }

    pub fn requests(&self) -> &[IsAuthorizedReadRequest] {
        &self.requests
    }
}

impl AwsVerifiedPermissionsTransport for RecordingAwsVerifiedPermissionsTransport {
    fn is_authorized(
        &mut self,
        request: &IsAuthorizedReadRequest,
    ) -> Result<IsAuthorizedReadResponse, TransportError> {
        self.requests.push(request.clone());
        self.responses.pop_front().unwrap_or_else(|| {
            Err(TransportError::new(
                ProviderErrorKind::Unavailable,
                None,
                "recording-fixture-exhausted",
            ))
        })
    }
}

#[derive(Clone, Debug)]
pub struct FixtureAwsVerifiedPermissionsTransport {
    decision: AuthorizationDecision,
    evidence_state: EvidenceState,
}

impl FixtureAwsVerifiedPermissionsTransport {
    pub const fn new(decision: AuthorizationDecision) -> Self {
        Self {
            decision,
            evidence_state: EvidenceState::Complete,
        }
    }

    pub const fn with_evidence_state(
        decision: AuthorizationDecision,
        evidence_state: EvidenceState,
    ) -> Self {
        Self {
            decision,
            evidence_state,
        }
    }
}

impl AwsVerifiedPermissionsTransport for FixtureAwsVerifiedPermissionsTransport {
    fn is_authorized(
        &mut self,
        request: &IsAuthorizedReadRequest,
    ) -> Result<IsAuthorizedReadResponse, TransportError> {
        let policy = DeterminingPolicyMetadata::new(
            request.policy_digest.clone(),
            request.policy_store_digest.clone(),
        )
        .map_err(|_| {
            TransportError::new(ProviderErrorKind::InvalidRequest, Some(400), "fixture")
        })?;
        let policy = (self.decision == AuthorizationDecision::Allow
            || self.decision == AuthorizationDecision::Deny)
            .then_some(policy);
        IsAuthorizedReadResponse::new(request, self.decision, self.evidence_state, policy)
            .map_err(|_| TransportError::new(ProviderErrorKind::Tampered, Some(400), "fixture"))
    }
}

#[derive(Clone, Debug)]
pub struct FakeAwsVerifiedPermissionsTransport {
    decision: AuthorizationDecision,
    evidence_state: EvidenceState,
}

impl FakeAwsVerifiedPermissionsTransport {
    pub const fn new(decision: AuthorizationDecision) -> Self {
        Self {
            decision,
            evidence_state: EvidenceState::Complete,
        }
    }

    pub const fn with_evidence_state(
        decision: AuthorizationDecision,
        evidence_state: EvidenceState,
    ) -> Self {
        Self {
            decision,
            evidence_state,
        }
    }
}

impl AwsVerifiedPermissionsTransport for FakeAwsVerifiedPermissionsTransport {
    fn is_authorized(
        &mut self,
        request: &IsAuthorizedReadRequest,
    ) -> Result<IsAuthorizedReadResponse, TransportError> {
        FixtureAwsVerifiedPermissionsTransport::with_evidence_state(
            self.decision,
            self.evidence_state,
        )
        .is_authorized(request)
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackAwsVerifiedPermissionsTransport {
    decision: AuthorizationDecision,
}

impl LoopbackAwsVerifiedPermissionsTransport {
    pub const fn new(decision: AuthorizationDecision) -> Self {
        Self { decision }
    }
}

impl AwsVerifiedPermissionsTransport for LoopbackAwsVerifiedPermissionsTransport {
    fn is_authorized(
        &mut self,
        request: &IsAuthorizedReadRequest,
    ) -> Result<IsAuthorizedReadResponse, TransportError> {
        FakeAwsVerifiedPermissionsTransport::new(self.decision).is_authorized(request)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvAwsVerifiedPermissionsTransport;

pub type BlockedEnvTransport = BlockedEnvAwsVerifiedPermissionsTransport;
pub type RecordingTransport = RecordingAwsVerifiedPermissionsTransport;
pub type FixtureTransport = FixtureAwsVerifiedPermissionsTransport;
pub type FakeTransport = FakeAwsVerifiedPermissionsTransport;
pub type LoopbackTransport = LoopbackAwsVerifiedPermissionsTransport;

impl AwsVerifiedPermissionsTransport for BlockedEnvAwsVerifiedPermissionsTransport {
    fn is_authorized(
        &mut self,
        _request: &IsAuthorizedReadRequest,
    ) -> Result<IsAuthorizedReadResponse, TransportError> {
        Err(TransportError::blocked_env())
    }
}

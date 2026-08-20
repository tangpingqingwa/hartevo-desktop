use std::{collections::BTreeSet, collections::VecDeque, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    GCP_BINARY_AUTHORIZATION_RESULT_PROVIDER_ID, GCP_BINARY_AUTHORIZATION_RESULT_PROVIDER_REVISION,
    GCP_BINARY_AUTHORIZATION_RESULT_SCHEMA_VERSION,
    model::{
        AdversarialFinding, AttestationOccurrenceReference, AttestorId, AttestorSummary, Digest,
        GcpAuthKind, GcpBinaryAuthorizationScope, ImageDigest, ModelError, Platform, PolicySummary,
        ProviderErrorEvidence, ProviderErrorKind, ProviderFence, Revision, ValidationDecision,
        ValidationReason,
    },
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
    Fake,
}

impl ProviderProvenance {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("provider version is empty")]
    EmptyVersion,
    #[error("Layer 1 cannot register a native provider")]
    NativeProviderForbidden,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpBinaryAuthorizationProviderDefinition {
    pub schema_version: String,
    pub provider_id: crate::ProviderId,
    pub provider_version: String,
    pub provider_revision: String,
    pub capability_digest: Digest,
    pub provenance: ProviderProvenance,
    pub get_policy: bool,
    pub get_attestor: bool,
    pub validate_attestation_occurrence: bool,
    pub live_execution: bool,
    pub credential_resolution: bool,
    pub native: bool,
    pub policy_mutation: bool,
    pub attestor_mutation: bool,
    pub signing: bool,
    pub deployment: bool,
    pub raw_keys: bool,
    pub raw_attestation_payload: bool,
    pub container_bytes: bool,
}

impl GcpBinaryAuthorizationProviderDefinition {
    pub fn new(
        provider_version: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let provider_version = provider_version.into();
        if provider_version.trim().is_empty() {
            return Err(ProviderDefinitionError::EmptyVersion);
        }
        if provenance.is_native() {
            return Err(ProviderDefinitionError::NativeProviderForbidden);
        }
        let provider_id =
            crate::model::ProviderId::new(GCP_BINARY_AUTHORIZATION_RESULT_PROVIDER_ID)?;
        let capability_digest = Digest::from_fields(
            "gcp-binary-authorization-provider-capability/v1",
            &[
                GCP_BINARY_AUTHORIZATION_RESULT_SCHEMA_VERSION.to_owned(),
                GCP_BINARY_AUTHORIZATION_RESULT_PROVIDER_ID.to_owned(),
                provider_version.clone(),
                GCP_BINARY_AUTHORIZATION_RESULT_PROVIDER_REVISION.to_owned(),
                format!("{provenance:?}"),
                "get_policy=true".to_owned(),
                "get_attestor=true".to_owned(),
                "validateAttestationOccurrence=true".to_owned(),
                "live_execution=false".to_owned(),
                "credential_resolution=false".to_owned(),
                "policy_mutation=false".to_owned(),
                "attestor_mutation=false".to_owned(),
                "signing=false".to_owned(),
                "deployment=false".to_owned(),
                "raw_keys=false".to_owned(),
                "raw_attestation_payload=false".to_owned(),
                "container_bytes=false".to_owned(),
            ],
        );
        Ok(Self {
            schema_version: GCP_BINARY_AUTHORIZATION_RESULT_SCHEMA_VERSION.to_owned(),
            provider_id,
            provider_version,
            provider_revision: GCP_BINARY_AUTHORIZATION_RESULT_PROVIDER_REVISION.to_owned(),
            capability_digest,
            provenance,
            get_policy: true,
            get_attestor: true,
            validate_attestation_occurrence: true,
            live_execution: false,
            credential_resolution: false,
            native: false,
            policy_mutation: false,
            attestor_mutation: false,
            signing: false,
            deployment: false,
            raw_keys: false,
            raw_attestation_payload: false,
            container_bytes: false,
        })
    }

    pub fn provider_digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-binary-authorization-provider-definition/v1",
            &[
                self.schema_version.clone(),
                self.provider_id.as_str().to_owned(),
                self.provider_version.clone(),
                self.provider_revision.clone(),
                self.capability_digest.as_str().to_owned(),
                format!("{:?}", self.provenance),
                self.get_policy.to_string(),
                self.get_attestor.to_string(),
                self.validate_attestation_occurrence.to_string(),
                self.live_execution.to_string(),
                self.credential_resolution.to_string(),
                self.native.to_string(),
                self.policy_mutation.to_string(),
                self.attestor_mutation.to_string(),
                self.signing.to_string(),
                self.deployment.to_string(),
                self.raw_keys.to_string(),
                self.raw_attestation_payload.to_string(),
                self.container_bytes.to_string(),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), ProviderDefinitionError> {
        if self.schema_version != GCP_BINARY_AUTHORIZATION_RESULT_SCHEMA_VERSION
            || self.provider_id.as_str() != GCP_BINARY_AUTHORIZATION_RESULT_PROVIDER_ID
            || self.provider_revision != GCP_BINARY_AUTHORIZATION_RESULT_PROVIDER_REVISION
            || !self.get_policy
            || !self.get_attestor
            || !self.validate_attestation_occurrence
            || self.live_execution
            || self.credential_resolution
            || self.native
            || self.policy_mutation
            || self.attestor_mutation
            || self.signing
            || self.deployment
            || self.raw_keys
            || self.raw_attestation_payload
            || self.container_bytes
            || self.capability_digest.as_str().len() != 64
            || self.provider_digest().as_str().len() != 64
        {
            Err(ProviderDefinitionError::NativeProviderForbidden)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub struct TransportError {
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub retryable: bool,
    pub diagnostic_digest: Digest,
}

impl TransportError {
    pub fn new(
        kind: ProviderErrorKind,
        status_code: Option<u16>,
        retryable: bool,
        diagnostic: impl AsRef<[u8]>,
    ) -> Self {
        Self {
            kind,
            status_code,
            retryable,
            diagnostic_digest: Digest::from_text(diagnostic),
        }
    }

    pub fn blocked_env() -> Self {
        Self::new(ProviderErrorKind::BlockedEnv, None, false, "BLOCKED_ENV")
    }

    pub fn permission_denied() -> Self {
        Self::new(
            ProviderErrorKind::PermissionDenied,
            Some(403),
            false,
            "permission-denied",
        )
    }

    pub fn not_found() -> Self {
        Self::new(ProviderErrorKind::NotFound, Some(404), false, "not-found")
    }

    pub fn timeout() -> Self {
        Self::new(ProviderErrorKind::Timeout, None, true, "timeout")
    }

    pub fn replay() -> Self {
        Self::new(ProviderErrorKind::Replay, None, false, "replay")
    }

    pub fn tampered() -> Self {
        Self::new(ProviderErrorKind::Tampered, None, false, "tampered")
    }

    pub fn revoked() -> Self {
        Self::new(ProviderErrorKind::Revoked, Some(403), false, "revoked")
    }

    pub fn partial() -> Self {
        Self::new(ProviderErrorKind::Partial, None, false, "partial")
    }

    pub fn access_lost() -> Self {
        Self::new(ProviderErrorKind::AccessLost, None, false, "access-lost")
    }

    pub fn consent_effect_bypass() -> Self {
        Self::new(
            ProviderErrorKind::ConsentEffectBypass,
            None,
            false,
            "consent-effect-bypass",
        )
    }

    pub fn unknown() -> Self {
        Self::new(ProviderErrorKind::Unknown, None, false, "unknown")
    }

    pub fn evidence(&self) -> ProviderErrorEvidence {
        ProviderErrorEvidence {
            kind: self.kind,
            status_code: self.status_code,
            retryable: self.retryable,
            diagnostic_digest: self.diagnostic_digest.clone(),
        }
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "GCP Binary Authorization transport error: {:?}",
            self.kind
        )
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ProviderError {
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error("provider request does not carry a valid Consent/Effect fence")]
    ConsentEffectBypass,
    #[error("provider request digest is invalid")]
    InvalidRequest,
    #[error("provider response digest does not match immutable contents")]
    ResponseDigestMismatch,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyGetRequest {
    pub project_id: crate::ProjectId,
    pub policy_id: crate::PolicyId,
    pub platform: Platform,
    pub scope_digest: Digest,
    pub policy_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub secret_reference_digest: Digest,
    pub credential_revision: Revision,
    pub auth_kind: GcpAuthKind,
    pub authority: crate::ConsentEffectFence,
}

impl PolicyGetRequest {
    pub fn new(
        scope: &GcpBinaryAuthorizationScope,
        fence: &ProviderFence,
    ) -> Result<Self, ProviderError> {
        validate_fence(scope, fence)?;
        Ok(Self {
            project_id: scope.project_id().clone(),
            policy_id: scope.policy_id().clone(),
            platform: scope.platform().clone(),
            scope_digest: scope.scope_digest().clone(),
            policy_digest: scope.policy_digest().clone(),
            permission_digest: scope.permission_digest().clone(),
            consent_digest: scope.consent_digest().clone(),
            secret_reference_digest: fence.secret_reference_digest().clone(),
            credential_revision: fence.credential_revision(),
            auth_kind: fence.auth_kind(),
            authority: fence.authority().clone(),
        })
    }

    pub fn request_digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-binary-authorization-policy-get-request/v1",
            &[
                self.project_id.as_str().to_owned(),
                self.policy_id.as_str().to_owned(),
                self.platform.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.policy_digest.as_str().to_owned(),
                self.permission_digest.as_str().to_owned(),
                self.consent_digest.as_str().to_owned(),
                self.secret_reference_digest.as_str().to_owned(),
                self.credential_revision.get().to_string(),
                format!("{:?}", self.auth_kind),
            ],
        )
    }
}

pub type GetPolicyRequest = PolicyGetRequest;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestorGetRequest {
    pub project_id: crate::ProjectId,
    pub policy_id: crate::PolicyId,
    pub attestor_id: AttestorId,
    pub platform: Platform,
    pub scope_digest: Digest,
    pub policy_digest: Digest,
    pub attestor_scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub secret_reference_digest: Digest,
    pub credential_revision: Revision,
    pub auth_kind: GcpAuthKind,
    pub authority: crate::ConsentEffectFence,
}

impl AttestorGetRequest {
    pub fn new(
        scope: &GcpBinaryAuthorizationScope,
        fence: &ProviderFence,
        attestor_id: AttestorId,
    ) -> Result<Self, ProviderError> {
        validate_fence(scope, fence)?;
        if !scope.contains_attestor(&attestor_id) {
            return Err(ProviderError::Model(ModelError::InvalidAttestor));
        }
        Ok(Self {
            project_id: scope.project_id().clone(),
            policy_id: scope.policy_id().clone(),
            attestor_id,
            platform: scope.platform().clone(),
            scope_digest: scope.scope_digest().clone(),
            policy_digest: scope.policy_digest().clone(),
            attestor_scope_digest: scope.attestor_digest().clone(),
            permission_digest: scope.permission_digest().clone(),
            consent_digest: scope.consent_digest().clone(),
            secret_reference_digest: fence.secret_reference_digest().clone(),
            credential_revision: fence.credential_revision(),
            auth_kind: fence.auth_kind(),
            authority: fence.authority().clone(),
        })
    }

    pub fn request_digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-binary-authorization-attestor-get-request/v1",
            &[
                self.project_id.as_str().to_owned(),
                self.policy_id.as_str().to_owned(),
                self.attestor_id.as_str().to_owned(),
                self.platform.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.policy_digest.as_str().to_owned(),
                self.attestor_scope_digest.as_str().to_owned(),
                self.permission_digest.as_str().to_owned(),
                self.consent_digest.as_str().to_owned(),
                self.secret_reference_digest.as_str().to_owned(),
                self.credential_revision.get().to_string(),
                format!("{:?}", self.auth_kind),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidateAttestationOccurrenceRequest {
    pub project_id: crate::ProjectId,
    pub policy_id: crate::PolicyId,
    pub attestor_id: AttestorId,
    pub platform: Platform,
    pub image_digest: ImageDigest,
    pub occurrence: AttestationOccurrenceReference,
    pub scope_digest: Digest,
    pub policy_digest: Digest,
    pub attestor_scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub secret_reference_digest: Digest,
    pub credential_revision: Revision,
    pub auth_kind: GcpAuthKind,
    pub authority: crate::ConsentEffectFence,
    pub request_digest: Digest,
}

impl ValidateAttestationOccurrenceRequest {
    pub fn new(
        scope: &GcpBinaryAuthorizationScope,
        fence: &ProviderFence,
        policy: &PolicySummary,
        attestor: &AttestorSummary,
        occurrence: AttestationOccurrenceReference,
    ) -> Result<Self, ProviderError> {
        validate_fence(scope, fence)?;
        policy.validate_for(scope)?;
        attestor.validate_for(scope)?;
        if occurrence.attestor_id() != attestor.attestor_id()
            || occurrence.image_digest() != scope.image_digest()
        {
            return Err(ProviderError::Model(ModelError::InvalidOccurrence));
        }
        let mut request = Self {
            project_id: scope.project_id().clone(),
            policy_id: scope.policy_id().clone(),
            attestor_id: attestor.attestor_id().clone(),
            platform: scope.platform().clone(),
            image_digest: scope.image_digest().clone(),
            occurrence,
            scope_digest: scope.scope_digest().clone(),
            policy_digest: scope.policy_digest().clone(),
            attestor_scope_digest: scope.attestor_digest().clone(),
            permission_digest: scope.permission_digest().clone(),
            consent_digest: scope.consent_digest().clone(),
            secret_reference_digest: fence.secret_reference_digest().clone(),
            credential_revision: fence.credential_revision(),
            auth_kind: fence.auth_kind(),
            authority: fence.authority().clone(),
            request_digest: Digest::from_text("gcp-binary-authorization-request-placeholder"),
        };
        request.request_digest = request.compute_digest();
        Ok(request)
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-binary-authorization-validate-attestation-occurrence-request/v1",
            &[
                self.project_id.as_str().to_owned(),
                self.policy_id.as_str().to_owned(),
                self.attestor_id.as_str().to_owned(),
                self.platform.as_str().to_owned(),
                self.image_digest.as_str().to_owned(),
                self.occurrence.occurrence_digest().as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.policy_digest.as_str().to_owned(),
                self.attestor_scope_digest.as_str().to_owned(),
                self.permission_digest.as_str().to_owned(),
                self.consent_digest.as_str().to_owned(),
                self.secret_reference_digest.as_str().to_owned(),
                self.credential_revision.get().to_string(),
                format!("{:?}", self.auth_kind),
            ],
        )
    }

    pub fn validate_digest(&self) -> Result<(), ProviderError> {
        if self.request_digest == self.compute_digest() {
            Ok(())
        } else {
            Err(ProviderError::InvalidRequest)
        }
    }
}

fn validate_fence(
    scope: &GcpBinaryAuthorizationScope,
    fence: &ProviderFence,
) -> Result<(), ProviderError> {
    if fence.validate_for_scope_without_secret(scope).is_err()
        || fence.authority().effect_requested()
        || fence.authority().effect_receipt_digest().is_some()
        || fence.authority().permission_digest() != scope.permission_digest()
        || fence.authority().consent_digest() != scope.consent_digest()
    {
        Err(ProviderError::ConsentEffectBypass)
    } else {
        Ok(())
    }
}

trait ProviderFenceValidation {
    fn validate_for_scope_without_secret(
        &self,
        scope: &GcpBinaryAuthorizationScope,
    ) -> Result<(), ModelError>;
}

impl ProviderFenceValidation for ProviderFence {
    fn validate_for_scope_without_secret(
        &self,
        scope: &GcpBinaryAuthorizationScope,
    ) -> Result<(), ModelError> {
        if self.scope_digest() != scope.scope_digest()
            || self.permission_digest() != scope.permission_digest()
            || self.consent_digest() != scope.consent_digest()
            || self.authority().effect_requested()
            || self.authority().effect_receipt_digest().is_some()
        {
            Err(ModelError::InvalidScope)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyGetResponse {
    pub policy: PolicySummary,
    pub request_digest: Digest,
    pub observed_fence: ProviderFence,
    pub response_digest: Digest,
}

impl PolicyGetResponse {
    pub fn new(request: &PolicyGetRequest, policy: PolicySummary) -> Self {
        let response_digest = Digest::from_fields(
            "gcp-binary-authorization-policy-get-response/v1",
            &[
                request.request_digest().as_str().to_owned(),
                policy.policy_content_digest().as_str().to_owned(),
                request.scope_digest.as_str().to_owned(),
                request.permission_digest.as_str().to_owned(),
                request.consent_digest.as_str().to_owned(),
            ],
        );
        Self {
            policy,
            request_digest: request.request_digest(),
            observed_fence: ProviderFence::from_parts(
                request.scope_digest.clone(),
                request.permission_digest.clone(),
                request.consent_digest.clone(),
                request.secret_reference_digest.clone(),
                request.credential_revision,
                request.auth_kind,
                request.authority.clone(),
            ),
            response_digest,
        }
    }

    pub fn validate_digest(&self) -> Result<(), ProviderError> {
        let expected = Digest::from_fields(
            "gcp-binary-authorization-policy-get-response/v1",
            &[
                self.request_digest.as_str().to_owned(),
                self.policy.policy_content_digest().as_str().to_owned(),
                self.observed_fence.scope_digest().as_str().to_owned(),
                self.observed_fence.permission_digest().as_str().to_owned(),
                self.observed_fence.consent_digest().as_str().to_owned(),
            ],
        );
        if expected == self.response_digest {
            Ok(())
        } else {
            Err(ProviderError::ResponseDigestMismatch)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestorGetResponse {
    pub attestor: AttestorSummary,
    pub request_digest: Digest,
    pub observed_fence: ProviderFence,
    pub response_digest: Digest,
}

impl AttestorGetResponse {
    pub fn new(request: &AttestorGetRequest, attestor: AttestorSummary) -> Self {
        let response_digest = Digest::from_fields(
            "gcp-binary-authorization-attestor-get-response/v1",
            &[
                request.request_digest().as_str().to_owned(),
                attestor.attestor_digest().as_str().to_owned(),
                request.scope_digest.as_str().to_owned(),
                request.permission_digest.as_str().to_owned(),
                request.consent_digest.as_str().to_owned(),
            ],
        );
        Self {
            attestor,
            request_digest: request.request_digest(),
            observed_fence: ProviderFence::from_parts(
                request.scope_digest.clone(),
                request.permission_digest.clone(),
                request.consent_digest.clone(),
                request.secret_reference_digest.clone(),
                request.credential_revision,
                request.auth_kind,
                request.authority.clone(),
            ),
            response_digest,
        }
    }

    pub fn validate_digest(&self) -> Result<(), ProviderError> {
        let expected = Digest::from_fields(
            "gcp-binary-authorization-attestor-get-response/v1",
            &[
                self.request_digest.as_str().to_owned(),
                self.attestor.attestor_digest().as_str().to_owned(),
                self.observed_fence.scope_digest().as_str().to_owned(),
                self.observed_fence.permission_digest().as_str().to_owned(),
                self.observed_fence.consent_digest().as_str().to_owned(),
            ],
        );
        if expected == self.response_digest {
            Ok(())
        } else {
            Err(ProviderError::ResponseDigestMismatch)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidationResponse {
    pub request_digest: Digest,
    pub decision: ValidationDecision,
    pub reason: ValidationReason,
    pub policy_digest: Digest,
    pub policy_content_digest: Option<Digest>,
    pub attestor_id: AttestorId,
    pub attestor_digest: Option<Digest>,
    pub occurrence_digest: Digest,
    pub image_digest: ImageDigest,
    pub observed_fence: ProviderFence,
    pub completeness: crate::EvidenceCompleteness,
    pub findings: BTreeSet<AdversarialFinding>,
    pub provider_error: Option<ProviderErrorEvidence>,
    pub response_digest: Digest,
}

impl ValidationResponse {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request: &ValidateAttestationOccurrenceRequest,
        decision: ValidationDecision,
        reason: ValidationReason,
        policy_content_digest: Option<Digest>,
        attestor_digest: Option<Digest>,
        completeness: crate::EvidenceCompleteness,
        findings: BTreeSet<AdversarialFinding>,
        provider_error: Option<ProviderErrorEvidence>,
    ) -> Self {
        let response_digest = compute_validation_response_digest(
            request,
            decision,
            reason,
            policy_content_digest.as_ref(),
            attestor_digest.as_ref(),
            completeness,
            &findings,
            provider_error.as_ref(),
        );
        Self {
            request_digest: request.request_digest.clone(),
            decision,
            reason,
            policy_digest: request.policy_digest.clone(),
            policy_content_digest,
            attestor_id: request.attestor_id.clone(),
            attestor_digest,
            occurrence_digest: request.occurrence.occurrence_digest().clone(),
            image_digest: request.image_digest.clone(),
            observed_fence: ProviderFence::from_parts(
                request.scope_digest.clone(),
                request.permission_digest.clone(),
                request.consent_digest.clone(),
                request.secret_reference_digest.clone(),
                request.credential_revision,
                request.auth_kind,
                request.authority.clone(),
            ),
            completeness,
            findings,
            provider_error,
            response_digest,
        }
    }

    pub fn allow(
        request: &ValidateAttestationOccurrenceRequest,
        policy: &PolicySummary,
        attestor: &AttestorSummary,
    ) -> Self {
        Self::new(
            request,
            ValidationDecision::Allow,
            ValidationReason::PolicyAllow,
            Some(policy.policy_content_digest().clone()),
            Some(attestor.attestor_digest().clone()),
            crate::EvidenceCompleteness::Complete,
            BTreeSet::new(),
            None,
        )
    }

    pub fn deny(
        request: &ValidateAttestationOccurrenceRequest,
        policy: &PolicySummary,
        attestor: &AttestorSummary,
        reason: ValidationReason,
        findings: BTreeSet<AdversarialFinding>,
    ) -> Self {
        Self::new(
            request,
            ValidationDecision::Deny,
            reason,
            Some(policy.policy_content_digest().clone()),
            Some(attestor.attestor_digest().clone()),
            crate::EvidenceCompleteness::Complete,
            findings,
            None,
        )
    }

    pub fn error(
        request: &ValidateAttestationOccurrenceRequest,
        error: ProviderErrorEvidence,
    ) -> Self {
        let reason = if error.kind == ProviderErrorKind::Replay {
            ValidationReason::Replay
        } else if error.kind == ProviderErrorKind::Tampered {
            ValidationReason::Tamper
        } else {
            ValidationReason::ProviderError
        };
        let mut findings = BTreeSet::new();
        if error.kind == ProviderErrorKind::Replay {
            findings.insert(AdversarialFinding::Replay);
        }
        if error.kind == ProviderErrorKind::Tampered {
            findings.insert(AdversarialFinding::Tamper);
        }
        if error.kind == ProviderErrorKind::Revoked {
            findings.insert(AdversarialFinding::Revocation);
        }
        Self::new(
            request,
            ValidationDecision::Error,
            reason,
            None,
            None,
            crate::EvidenceCompleteness::Complete,
            findings,
            Some(error),
        )
    }

    pub fn unknown(
        request: &ValidateAttestationOccurrenceRequest,
        error: ProviderErrorEvidence,
    ) -> Self {
        let (reason, completeness, finding) = match error.kind {
            ProviderErrorKind::Partial => (
                ValidationReason::PartialEvidence,
                crate::EvidenceCompleteness::Partial,
                AdversarialFinding::Partial,
            ),
            ProviderErrorKind::AccessLost => (
                ValidationReason::AccessLost,
                crate::EvidenceCompleteness::AccessLost,
                AdversarialFinding::AccessLoss,
            ),
            _ => (
                ValidationReason::ProviderUnknown,
                crate::EvidenceCompleteness::Complete,
                AdversarialFinding::Partial,
            ),
        };
        let mut findings = BTreeSet::new();
        findings.insert(finding);
        Self::new(
            request,
            ValidationDecision::Unknown,
            reason,
            None,
            None,
            completeness,
            findings,
            Some(error),
        )
    }

    pub fn partial(request: &ValidateAttestationOccurrenceRequest) -> Self {
        Self::unknown(request, TransportError::partial().evidence())
    }

    pub fn access_lost(request: &ValidateAttestationOccurrenceRequest) -> Self {
        Self::unknown(request, TransportError::access_lost().evidence())
    }

    pub fn validate_digest(&self) -> Result<(), ProviderError> {
        let expected = compute_validation_response_digest(
            &ValidateAttestationOccurrenceRequest {
                project_id: crate::ProjectId::new("digest-check-project")
                    .map_err(ProviderError::Model)?,
                policy_id: crate::PolicyId::new("digest-check-policy")
                    .map_err(ProviderError::Model)?,
                attestor_id: self.attestor_id.clone(),
                platform: Platform::Other("digest-check-platform".to_owned()),
                image_digest: self.image_digest.clone(),
                occurrence: AttestationOccurrenceReference::new(
                    self.occurrence_digest.clone(),
                    self.image_digest.clone(),
                    self.attestor_id.clone(),
                )
                .map_err(ProviderError::Model)?,
                scope_digest: self.observed_fence.scope_digest().clone(),
                policy_digest: self.policy_digest.clone(),
                attestor_scope_digest: Digest::from_text("attestor-scope-placeholder"),
                permission_digest: self.observed_fence.permission_digest().clone(),
                consent_digest: self.observed_fence.consent_digest().clone(),
                secret_reference_digest: self.observed_fence.secret_reference_digest().clone(),
                credential_revision: self.observed_fence.credential_revision(),
                auth_kind: self.observed_fence.auth_kind(),
                authority: self.observed_fence.authority().clone(),
                request_digest: self.request_digest.clone(),
            },
            self.decision,
            self.reason,
            self.policy_content_digest.as_ref(),
            self.attestor_digest.as_ref(),
            self.completeness,
            &self.findings,
            self.provider_error.as_ref(),
        );
        if expected == self.response_digest {
            Ok(())
        } else {
            Err(ProviderError::ResponseDigestMismatch)
        }
    }
}

fn compute_validation_response_digest(
    request: &ValidateAttestationOccurrenceRequest,
    decision: ValidationDecision,
    reason: ValidationReason,
    policy_content_digest: Option<&Digest>,
    attestor_digest: Option<&Digest>,
    completeness: crate::EvidenceCompleteness,
    findings: &BTreeSet<AdversarialFinding>,
    provider_error: Option<&ProviderErrorEvidence>,
) -> Digest {
    Digest::from_fields(
        "gcp-binary-authorization-validate-attestation-occurrence-response/v1",
        &[
            request.request_digest.as_str().to_owned(),
            format!("{decision:?}"),
            format!("{reason:?}"),
            request.policy_digest.as_str().to_owned(),
            policy_content_digest
                .map_or_else(|| "none".to_owned(), |digest| digest.as_str().to_owned()),
            request.attestor_id.as_str().to_owned(),
            attestor_digest.map_or_else(|| "none".to_owned(), |digest| digest.as_str().to_owned()),
            request.occurrence.occurrence_digest().as_str().to_owned(),
            request.image_digest.as_str().to_owned(),
            request.scope_digest.as_str().to_owned(),
            request.permission_digest.as_str().to_owned(),
            request.consent_digest.as_str().to_owned(),
            format!("{completeness:?}"),
            findings
                .iter()
                .map(|finding| format!("{finding:?}"))
                .collect::<Vec<_>>()
                .join(","),
            provider_error.map_or_else(
                || "none".to_owned(),
                |error| {
                    format!(
                        "{:?}:{}:{}",
                        error.kind,
                        error.status_code.map_or(0, u16::from),
                        error.diagnostic_digest.as_str()
                    )
                },
            ),
        ],
    )
}

pub type ValidationTransportResponse = ValidationResponse;

pub trait BinaryAuthorizationTransport: fmt::Debug {
    fn get_policy(
        &mut self,
        request: &PolicyGetRequest,
    ) -> Result<PolicyGetResponse, TransportError>;

    fn get_attestor(
        &mut self,
        request: &AttestorGetRequest,
    ) -> Result<AttestorGetResponse, TransportError>;

    fn validate_attestation_occurrence(
        &mut self,
        request: &ValidateAttestationOccurrenceRequest,
    ) -> Result<ValidationTransportResponse, TransportError>;
}

pub trait GcpBinaryAuthorizationProviderApi: fmt::Debug {
    fn definition(&self) -> &GcpBinaryAuthorizationProviderDefinition;

    fn provenance(&self) -> ProviderProvenance {
        self.definition().provenance
    }

    fn get_policy(
        &mut self,
        request: &PolicyGetRequest,
    ) -> Result<PolicyGetResponse, TransportError>;

    fn get_attestor(
        &mut self,
        request: &AttestorGetRequest,
    ) -> Result<AttestorGetResponse, TransportError>;

    fn validate_attestation_occurrence(
        &mut self,
        request: &ValidateAttestationOccurrenceRequest,
    ) -> Result<ValidationTransportResponse, TransportError>;
}

#[derive(Debug)]
pub struct GcpBinaryAuthorizationProvider<T> {
    transport: T,
    definition: GcpBinaryAuthorizationProviderDefinition,
}

impl<T: BinaryAuthorizationTransport> GcpBinaryAuthorizationProvider<T> {
    pub fn new(
        transport: T,
        provider_version: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let definition =
            GcpBinaryAuthorizationProviderDefinition::new(provider_version, provenance)?;
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn provider_definition(&self) -> &GcpBinaryAuthorizationProviderDefinition {
        &self.definition
    }

    pub fn provider_digest(&self) -> Digest {
        self.definition.provider_digest()
    }

    /// Provider-side guard: even a directly supplied request cannot use this
    /// wrapper to smuggle an external Effect around the kernel boundary.
    pub fn validate_read_only_fence(
        &self,
        permission_digest: &Digest,
        consent_digest: &Digest,
        authority: &crate::ConsentEffectFence,
    ) -> Result<(), ProviderError> {
        validate_authority(permission_digest, consent_digest, authority)
    }
}

fn validate_authority(
    permission_digest: &Digest,
    consent_digest: &Digest,
    authority: &crate::ConsentEffectFence,
) -> Result<(), ProviderError> {
    if authority.permission_digest() != permission_digest
        || authority.consent_digest() != consent_digest
        || authority.effect_requested()
        || authority.effect_receipt_digest().is_some()
    {
        Err(ProviderError::ConsentEffectBypass)
    } else {
        Ok(())
    }
}

impl<T: BinaryAuthorizationTransport> GcpBinaryAuthorizationProviderApi
    for GcpBinaryAuthorizationProvider<T>
{
    fn definition(&self) -> &GcpBinaryAuthorizationProviderDefinition {
        &self.definition
    }

    fn get_policy(
        &mut self,
        request: &PolicyGetRequest,
    ) -> Result<PolicyGetResponse, TransportError> {
        if validate_authority(
            &request.permission_digest,
            &request.consent_digest,
            &request.authority,
        )
        .is_err()
        {
            return Err(TransportError::consent_effect_bypass());
        }
        self.transport.get_policy(request)
    }

    fn get_attestor(
        &mut self,
        request: &AttestorGetRequest,
    ) -> Result<AttestorGetResponse, TransportError> {
        if validate_authority(
            &request.permission_digest,
            &request.consent_digest,
            &request.authority,
        )
        .is_err()
        {
            return Err(TransportError::consent_effect_bypass());
        }
        self.transport.get_attestor(request)
    }

    fn validate_attestation_occurrence(
        &mut self,
        request: &ValidateAttestationOccurrenceRequest,
    ) -> Result<ValidationTransportResponse, TransportError> {
        if validate_authority(
            &request.permission_digest,
            &request.consent_digest,
            &request.authority,
        )
        .is_err()
        {
            return Err(TransportError::consent_effect_bypass());
        }
        self.transport.validate_attestation_occurrence(request)
    }
}

#[derive(Debug, Default)]
pub struct RecordingGcpBinaryAuthorizationTransport {
    policy_responses: VecDeque<Result<PolicyGetResponse, TransportError>>,
    attestor_responses: VecDeque<Result<AttestorGetResponse, TransportError>>,
    validation_responses: VecDeque<Result<ValidationTransportResponse, TransportError>>,
    policy_calls: usize,
    attestor_calls: usize,
    validation_calls: usize,
}

impl RecordingGcpBinaryAuthorizationTransport {
    pub fn push_policy_response(&mut self, response: Result<PolicyGetResponse, TransportError>) {
        self.policy_responses.push_back(response);
    }

    pub fn push_attestor_response(
        &mut self,
        response: Result<AttestorGetResponse, TransportError>,
    ) {
        self.attestor_responses.push_back(response);
    }

    pub fn push_validation_response(
        &mut self,
        response: Result<ValidationTransportResponse, TransportError>,
    ) {
        self.validation_responses.push_back(response);
    }

    pub const fn policy_calls(&self) -> usize {
        self.policy_calls
    }

    pub const fn attestor_calls(&self) -> usize {
        self.attestor_calls
    }

    pub const fn validation_calls(&self) -> usize {
        self.validation_calls
    }
}

impl BinaryAuthorizationTransport for RecordingGcpBinaryAuthorizationTransport {
    fn get_policy(
        &mut self,
        _request: &PolicyGetRequest,
    ) -> Result<PolicyGetResponse, TransportError> {
        self.policy_calls = self.policy_calls.saturating_add(1);
        self.policy_responses
            .pop_front()
            .unwrap_or_else(|| Err(TransportError::blocked_env()))
    }

    fn get_attestor(
        &mut self,
        _request: &AttestorGetRequest,
    ) -> Result<AttestorGetResponse, TransportError> {
        self.attestor_calls = self.attestor_calls.saturating_add(1);
        self.attestor_responses
            .pop_front()
            .unwrap_or_else(|| Err(TransportError::blocked_env()))
    }

    fn validate_attestation_occurrence(
        &mut self,
        _request: &ValidateAttestationOccurrenceRequest,
    ) -> Result<ValidationTransportResponse, TransportError> {
        self.validation_calls = self.validation_calls.saturating_add(1);
        self.validation_responses
            .pop_front()
            .unwrap_or_else(|| Err(TransportError::blocked_env()))
    }
}

pub type FakeGcpBinaryAuthorizationTransport = RecordingGcpBinaryAuthorizationTransport;
pub type FixtureGcpBinaryAuthorizationTransport = RecordingGcpBinaryAuthorizationTransport;
pub type LoopbackTransport = RecordingGcpBinaryAuthorizationTransport;
pub type FakeTransport = RecordingGcpBinaryAuthorizationTransport;
pub type FixtureTransport = RecordingGcpBinaryAuthorizationTransport;

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvGcpBinaryAuthorizationTransport;

pub type BlockedEnvTransport = BlockedEnvGcpBinaryAuthorizationTransport;

impl BinaryAuthorizationTransport for BlockedEnvGcpBinaryAuthorizationTransport {
    fn get_policy(
        &mut self,
        _request: &PolicyGetRequest,
    ) -> Result<PolicyGetResponse, TransportError> {
        Err(TransportError::blocked_env())
    }

    fn get_attestor(
        &mut self,
        _request: &AttestorGetRequest,
    ) -> Result<AttestorGetResponse, TransportError> {
        Err(TransportError::blocked_env())
    }

    fn validate_attestation_occurrence(
        &mut self,
        _request: &ValidateAttestationOccurrenceRequest,
    ) -> Result<ValidationTransportResponse, TransportError> {
        Err(TransportError::blocked_env())
    }
}

fn _auth_kind_is_typed(value: GcpAuthKind) -> GcpAuthKind {
    value
}

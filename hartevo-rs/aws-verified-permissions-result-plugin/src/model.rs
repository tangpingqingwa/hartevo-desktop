use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    AWS_VERIFIED_PERMISSIONS_CONSUMER_ID, AWS_VERIFIED_PERMISSIONS_CONTRACT_VERSION,
    AWS_VERIFIED_PERMISSIONS_SCHEMA_VERSION, AWS_VERIFIED_PERMISSIONS_SERVICE_ID,
};

pub(crate) const MAX_IDENTIFIER_BYTES: usize = 256;
pub(crate) const MAX_DIGEST_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("identifier is empty, malformed, or too long")]
    InvalidIdentifier,
    #[error("AWS account id must contain exactly twelve digits")]
    InvalidAccountId,
    #[error("AWS region is empty or malformed")]
    InvalidRegion,
    #[error("digest is not a lowercase SHA-256 hex digest")]
    InvalidDigest,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("scope contains an invalid or withdrawn Consent reference")]
    InvalidScope,
    #[error("opaque secret reference is empty or malformed")]
    InvalidSecretReference,
    #[error("secret reference does not belong to this scope")]
    SecretScopeMismatch,
    #[error("response metadata does not match the IsAuthorized request")]
    ResponseMismatch,
    #[error("metadata or evidence digest does not match its immutable fields")]
    DigestMismatch,
    #[error("registration is invalid")]
    InvalidRegistration,
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("registration is already active")]
    AlreadyActive,
    #[error("a policy determining metadata item is invalid")]
    InvalidDeterminingPolicy,
}

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn from_fields(domain: &str, fields: &[String]) -> Self {
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for field in fields {
            append_field(&mut bytes, field);
        }
        Self::from_bytes(&bytes)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

fn append_field(bytes: &mut Vec<u8>, field: &str) {
    bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
    bytes.extend_from_slice(field.as_bytes());
}

fn is_digest(value: &str) -> bool {
    value.len() == MAX_DIGEST_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && !value.starts_with('.')
        && !value.ends_with('.')
}

fn valid_opaque_input(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| !byte.is_ascii_control() && !byte.is_ascii_whitespace())
}

macro_rules! identifier_type {
    ($name:ident) => {
        #[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                if valid_identifier(&value) {
                    Ok(Self(value))
                } else {
                    Err(ModelError::InvalidIdentifier)
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }
    };
}

identifier_type!(PolicyStoreId);
identifier_type!(ProjectId);
identifier_type!(MissionId);
identifier_type!(WorkProductId);
identifier_type!(ServiceId);
identifier_type!(ProviderId);
identifier_type!(ConsumerId);

pub type PolicyStore = PolicyStoreId;
pub type Project = ProjectId;
pub type Mission = MissionId;
pub type WorkProduct = WorkProductId;

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AccountId(String);

impl AccountId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.len() == 12 && value.bytes().all(|byte| byte.is_ascii_digit()) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidAccountId)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("AccountId").field(&self.0).finish()
    }
}

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AwsRegion(String);

impl AwsRegion {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into().to_ascii_lowercase();
        let valid = value.len() >= 3
            && value.len() <= 32
            && value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && value.starts_with(|character: char| character.is_ascii_lowercase())
            && value.ends_with(|character: char| character.is_ascii_digit());
        if valid {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidRegion)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AwsRegion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("AwsRegion").field(&self.0).finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        if value == 0 {
            Err(ModelError::InvalidRevision)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

macro_rules! opaque_reference_type {
    ($name:ident, $domain:literal) => {
        #[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
        #[serde(transparent)]
        pub struct $name {
            digest: Digest,
        }

        impl $name {
            pub fn from_text(value: impl AsRef<str>) -> Result<Self, ModelError> {
                let value = value.as_ref();
                if !valid_opaque_input(value) {
                    return Err(ModelError::InvalidIdentifier);
                }
                Ok(Self {
                    digest: Digest::from_fields($domain, &[value.to_owned()]),
                })
            }

            pub fn from_digest(digest: Digest) -> Result<Self, ModelError> {
                if is_digest(digest.as_str()) {
                    Ok(Self { digest })
                } else {
                    Err(ModelError::InvalidDigest)
                }
            }

            pub fn digest(&self) -> &Digest {
                &self.digest
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("digest", &self.digest)
                    .finish()
            }
        }
    };
}

opaque_reference_type!(PrincipalReference, "aws-verified-permissions-principal/v1");
opaque_reference_type!(ActionReference, "aws-verified-permissions-action/v1");
opaque_reference_type!(ResourceReference, "aws-verified-permissions-resource/v1");

pub type Principal = PrincipalReference;
pub type Action = ActionReference;
pub type Resource = ResourceReference;

/// The context is accepted only as a caller-computed digest.  The plugin
/// never stores Cedar attributes, context values, or PII.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ContextReference {
    digest: Digest,
}

impl ContextReference {
    pub fn from_digest(digest: Digest) -> Result<Self, ModelError> {
        if is_digest(digest.as_str()) {
            Ok(Self { digest })
        } else {
            Err(ModelError::InvalidDigest)
        }
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self {
            digest: Digest::from_text(value),
        }
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

pub type Context = ContextReference;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentState {
    Granted,
    Withdrawn,
    Expired,
    Unknown,
}

/// Digest-only reference supplied by the kernel/application boundary.  This
/// type is a reference and does not claim to be Consent authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentReference {
    pub consent_digest: Digest,
    pub revision: Revision,
    pub state: ConsentState,
}

pub type KernelConsentReference = ConsentReference;

impl ConsentReference {
    pub fn new(
        consent_digest: Digest,
        revision: Revision,
        state: ConsentState,
    ) -> Result<Self, ModelError> {
        if !is_digest(consent_digest.as_str()) {
            return Err(ModelError::InvalidDigest);
        }
        Ok(Self {
            consent_digest,
            revision,
            state,
        })
    }

    pub fn granted(consent_digest: Digest, revision: Revision) -> Result<Self, ModelError> {
        Self::new(consent_digest, revision, ConsentState::Granted)
    }

    pub fn withdrawn(consent_digest: Digest, revision: Revision) -> Result<Self, ModelError> {
        Self::new(consent_digest, revision, ConsentState::Withdrawn)
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.state, ConsentState::Granted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectState {
    NotRequested,
    Pending,
    Authorized,
    Denied,
    Unknown,
    Revoked,
}

/// Digest-only reference to a kernel-owned Effect.  The plugin never creates,
/// approves, executes, or verifies an external Effect.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KernelEffectReference {
    pub effect_digest: Digest,
    pub revision: Revision,
    pub state: EffectState,
}

pub type EffectReference = KernelEffectReference;

impl KernelEffectReference {
    pub fn new(
        effect_digest: Digest,
        revision: Revision,
        state: EffectState,
    ) -> Result<Self, ModelError> {
        if !is_digest(effect_digest.as_str()) {
            return Err(ModelError::InvalidDigest);
        }
        Ok(Self {
            effect_digest,
            revision,
            state,
        })
    }

    pub fn pending(effect_digest: Digest, revision: Revision) -> Result<Self, ModelError> {
        Self::new(effect_digest, revision, EffectState::Pending)
    }

    pub const fn is_blocked(&self) -> bool {
        matches!(
            self.state,
            EffectState::Denied | EffectState::Unknown | EffectState::Revoked
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelAuthorizationFence {
    pub consent: KernelConsentReference,
    pub effect: KernelEffectReference,
}

impl KernelAuthorizationFence {
    pub fn new(consent: KernelConsentReference, effect: KernelEffectReference) -> Self {
        Self { consent, effect }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsVerifiedPermissionsScope {
    account: AccountId,
    region: AwsRegion,
    policy_store: PolicyStoreId,
    principal: PrincipalReference,
    action: ActionReference,
    resource: ResourceReference,
    context: ContextReference,
    project: ProjectId,
    mission: MissionId,
    work_product: WorkProductId,
    work_product_revision: Revision,
    consent: ConsentReference,
    permission_digest: Digest,
    policy_digest: Digest,
    policy_store_digest: Digest,
    scope_digest: Digest,
}

impl AwsVerifiedPermissionsScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: AccountId,
        region: AwsRegion,
        policy_store: PolicyStoreId,
        principal: PrincipalReference,
        action: ActionReference,
        resource: ResourceReference,
        context: ContextReference,
        project: ProjectId,
        mission: MissionId,
        work_product: WorkProductId,
        work_product_revision: Revision,
        consent: ConsentReference,
        permission_digest: Digest,
        policy_digest: Digest,
    ) -> Result<Self, ModelError> {
        if !is_digest(permission_digest.as_str()) || !is_digest(policy_digest.as_str()) {
            return Err(ModelError::InvalidDigest);
        }
        if !consent.is_active() {
            return Err(ModelError::InvalidScope);
        }
        let policy_store_digest = Digest::from_fields(
            "aws-verified-permissions-policy-store/v1",
            &[
                account.as_str().to_owned(),
                region.as_str().to_owned(),
                policy_store.as_str().to_owned(),
            ],
        );
        let scope_digest = Digest::from_fields(
            "aws-verified-permissions-scope/v1",
            &[
                account.as_str().to_owned(),
                region.as_str().to_owned(),
                policy_store.as_str().to_owned(),
                policy_store_digest.as_str().to_owned(),
                principal.digest().as_str().to_owned(),
                action.digest().as_str().to_owned(),
                resource.digest().as_str().to_owned(),
                context.digest().as_str().to_owned(),
                project.as_str().to_owned(),
                mission.as_str().to_owned(),
                work_product.as_str().to_owned(),
                work_product_revision.get().to_string(),
                consent.consent_digest.as_str().to_owned(),
                consent.revision.get().to_string(),
                permission_digest.as_str().to_owned(),
                policy_digest.as_str().to_owned(),
            ],
        );
        Ok(Self {
            account,
            region,
            policy_store,
            principal,
            action,
            resource,
            context,
            project,
            mission,
            work_product,
            work_product_revision,
            consent,
            permission_digest,
            policy_digest,
            policy_store_digest,
            scope_digest,
        })
    }

    pub fn account(&self) -> &AccountId {
        &self.account
    }

    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn policy_store(&self) -> &PolicyStoreId {
        &self.policy_store
    }

    pub fn principal(&self) -> &PrincipalReference {
        &self.principal
    }

    pub fn action(&self) -> &ActionReference {
        &self.action
    }

    pub fn resource(&self) -> &ResourceReference {
        &self.resource
    }

    pub fn context(&self) -> &ContextReference {
        &self.context
    }

    pub fn project(&self) -> &ProjectId {
        &self.project
    }

    pub fn mission(&self) -> &MissionId {
        &self.mission
    }

    pub fn work_product(&self) -> &WorkProductId {
        &self.work_product
    }

    pub const fn work_product_revision(&self) -> Revision {
        self.work_product_revision
    }

    pub fn consent(&self) -> &ConsentReference {
        &self.consent
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn policy_digest(&self) -> &Digest {
        &self.policy_digest
    }

    pub fn policy_store_digest(&self) -> &Digest {
        &self.policy_store_digest
    }

    pub fn context_digest(&self) -> &Digest {
        self.context.digest()
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn consent_active(&self) -> bool {
        self.consent.is_active()
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        let expected = Self::new(
            self.account.clone(),
            self.region.clone(),
            self.policy_store.clone(),
            self.principal.clone(),
            self.action.clone(),
            self.resource.clone(),
            self.context.clone(),
            self.project.clone(),
            self.mission.clone(),
            self.work_product.clone(),
            self.work_product_revision,
            self.consent.clone(),
            self.permission_digest.clone(),
            self.policy_digest.clone(),
        )?;
        if expected.scope_digest == self.scope_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

/// Opaque host-keyring reference for SigV4.  The caller's reference id is
/// hashed at construction and is never retained, serialized, or printed.
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    signing_service: SigV4SigningService,
    revoked: bool,
}

pub type SigV4SecretReference = SecretReference;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SigV4SigningService {
    VerifiedPermissions,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_digest: self.reference_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            credential_revision: self.credential_revision,
            signing_service: self.signing_service,
            revoked: self.revoked,
        }
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .field("signing_service", &self.signing_service)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest
            && self.scope_digest == other.scope_digest
            && self.credential_revision == other.credential_revision
            && self.signing_service == other.signing_service
            && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

impl SecretReference {
    pub fn new(
        reference_id: impl AsRef<str>,
        scope: &AwsVerifiedPermissionsScope,
        credential_revision: Revision,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.as_ref();
        if !valid_opaque_input(reference_id) {
            return Err(ModelError::InvalidSecretReference);
        }
        Ok(Self {
            reference_digest: Digest::from_fields(
                "aws-verified-permissions-sigv4-secret-reference/v1",
                &[
                    reference_id.to_owned(),
                    scope.scope_digest().as_str().to_owned(),
                    credential_revision.get().to_string(),
                ],
            ),
            scope_digest: scope.scope_digest().clone(),
            credential_revision,
            signing_service: SigV4SigningService::VerifiedPermissions,
            revoked: false,
        })
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    pub const fn signing_service(&self) -> SigV4SigningService {
        self.signing_service
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            Err(ModelError::AlreadyRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }

    pub fn validate_for_scope(
        &self,
        scope: &AwsVerifiedPermissionsScope,
    ) -> Result<(), ModelError> {
        if self.scope_digest != *scope.scope_digest() {
            Err(ModelError::SecretScopeMismatch)
        } else if self.revoked {
            Err(ModelError::AlreadyRevoked)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationDecision {
    Allow,
    Deny,
    Indeterminate,
}

pub type IsAuthorizedDecision = AuthorizationDecision;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Complete,
    Partial,
    AccessLost,
    ContextMismatch,
    Tampered,
    ReplayRejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectGate {
    NotApplicable,
    KernelConsentAndEffectRequired,
}

impl EffectGate {
    pub const fn execution_permitted(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationState {
    Verified,
    Partial,
    AccessLost,
    ContextMismatch,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdoptionAvailability {
    NotAdoptedLayer2,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeterminingPolicyMetadata {
    pub policy_id_digest: Digest,
    pub policy_store_digest: Digest,
}

impl DeterminingPolicyMetadata {
    pub fn new(policy_id_digest: Digest, policy_store_digest: Digest) -> Result<Self, ModelError> {
        if !is_digest(policy_id_digest.as_str()) || !is_digest(policy_store_digest.as_str()) {
            return Err(ModelError::InvalidDeterminingPolicy);
        }
        Ok(Self {
            policy_id_digest,
            policy_store_digest,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IsAuthorizedReadRequest {
    pub account: AccountId,
    pub region: AwsRegion,
    pub policy_store: PolicyStoreId,
    pub policy_store_digest: Digest,
    pub principal_digest: Digest,
    pub action_digest: Digest,
    pub resource_digest: Digest,
    pub context_digest: Digest,
    pub project: ProjectId,
    pub mission: MissionId,
    pub work_product: WorkProductId,
    pub work_product_revision: Revision,
    pub consent_digest: Digest,
    pub consent_revision: Revision,
    pub permission_digest: Digest,
    pub policy_digest: Digest,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub credential_revision: Revision,
    pub request_digest: Digest,
}

pub type IsAuthorizedRequest = IsAuthorizedReadRequest;

impl IsAuthorizedReadRequest {
    pub(crate) fn from_scope(
        scope: &AwsVerifiedPermissionsScope,
        secret: &SecretReference,
    ) -> Result<Self, ModelError> {
        scope.validate_digest()?;
        if !scope.consent_active() {
            return Err(ModelError::InvalidScope);
        }
        secret.validate_for_scope(scope)?;
        let mut request = Self {
            account: scope.account.clone(),
            region: scope.region.clone(),
            policy_store: scope.policy_store.clone(),
            policy_store_digest: scope.policy_store_digest.clone(),
            principal_digest: scope.principal.digest().clone(),
            action_digest: scope.action.digest().clone(),
            resource_digest: scope.resource.digest().clone(),
            context_digest: scope.context.digest().clone(),
            project: scope.project.clone(),
            mission: scope.mission.clone(),
            work_product: scope.work_product.clone(),
            work_product_revision: scope.work_product_revision,
            consent_digest: scope.consent.consent_digest.clone(),
            consent_revision: scope.consent.revision,
            permission_digest: scope.permission_digest.clone(),
            policy_digest: scope.policy_digest.clone(),
            scope_digest: scope.scope_digest.clone(),
            secret_reference_digest: secret.reference_digest.clone(),
            credential_revision: secret.credential_revision,
            request_digest: Digest::from_text([]),
        };
        request.request_digest = request.computed_digest();
        Ok(request)
    }

    pub fn computed_digest(&self) -> Digest {
        Digest::from_fields(
            "aws-verified-permissions-is-authorized-request/v1",
            &[
                self.account.as_str().to_owned(),
                self.region.as_str().to_owned(),
                self.policy_store.as_str().to_owned(),
                self.policy_store_digest.as_str().to_owned(),
                self.principal_digest.as_str().to_owned(),
                self.action_digest.as_str().to_owned(),
                self.resource_digest.as_str().to_owned(),
                self.context_digest.as_str().to_owned(),
                self.project.as_str().to_owned(),
                self.mission.as_str().to_owned(),
                self.work_product.as_str().to_owned(),
                self.work_product_revision.get().to_string(),
                self.consent_digest.as_str().to_owned(),
                self.consent_revision.get().to_string(),
                self.permission_digest.as_str().to_owned(),
                self.policy_digest.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.secret_reference_digest.as_str().to_owned(),
                self.credential_revision.get().to_string(),
            ],
        )
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        if self.request_digest == self.computed_digest() {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IsAuthorizedReadResponse {
    pub decision: AuthorizationDecision,
    pub evidence_state: EvidenceState,
    pub determining_policy: Option<DeterminingPolicyMetadata>,
    pub principal_digest: Digest,
    pub resource_digest: Digest,
    pub context_digest: Digest,
    pub policy_digest: Digest,
    pub request_digest: Digest,
    pub evidence_digest: Digest,
    pub response_digest: Digest,
}

impl IsAuthorizedReadResponse {
    pub fn new(
        request: &IsAuthorizedReadRequest,
        decision: AuthorizationDecision,
        evidence_state: EvidenceState,
        determining_policy: Option<DeterminingPolicyMetadata>,
    ) -> Result<Self, ModelError> {
        request.validate_digest()?;
        if let Some(policy) = &determining_policy
            && policy.policy_store_digest != request.policy_store_digest
        {
            return Err(ModelError::ResponseMismatch);
        }
        let mut response = Self {
            decision,
            evidence_state,
            determining_policy,
            principal_digest: request.principal_digest.clone(),
            resource_digest: request.resource_digest.clone(),
            context_digest: request.context_digest.clone(),
            policy_digest: request.policy_digest.clone(),
            request_digest: request.request_digest.clone(),
            evidence_digest: Digest::from_text([]),
            response_digest: Digest::from_text([]),
        };
        response.evidence_digest = response.computed_evidence_digest();
        response.response_digest = response.computed_response_digest();
        Ok(response)
    }

    pub fn allow(
        request: &IsAuthorizedReadRequest,
        determining_policy: Option<DeterminingPolicyMetadata>,
    ) -> Result<Self, ModelError> {
        Self::new(
            request,
            AuthorizationDecision::Allow,
            EvidenceState::Complete,
            determining_policy,
        )
    }

    pub fn deny(
        request: &IsAuthorizedReadRequest,
        determining_policy: Option<DeterminingPolicyMetadata>,
    ) -> Result<Self, ModelError> {
        Self::new(
            request,
            AuthorizationDecision::Deny,
            EvidenceState::Complete,
            determining_policy,
        )
    }

    pub fn indeterminate(
        request: &IsAuthorizedReadRequest,
        evidence_state: EvidenceState,
    ) -> Result<Self, ModelError> {
        Self::new(
            request,
            AuthorizationDecision::Indeterminate,
            evidence_state,
            None,
        )
    }

    pub fn computed_evidence_digest(&self) -> Digest {
        Digest::from_fields(
            "aws-verified-permissions-evidence/v1",
            &[
                format!("{:?}", self.decision),
                format!("{:?}", self.evidence_state),
                self.determining_policy.as_ref().map_or_else(
                    || "none".to_owned(),
                    |policy| policy.policy_id_digest.as_str().to_owned(),
                ),
                self.determining_policy.as_ref().map_or_else(
                    || "none".to_owned(),
                    |policy| policy.policy_store_digest.as_str().to_owned(),
                ),
                self.principal_digest.as_str().to_owned(),
                self.resource_digest.as_str().to_owned(),
                self.context_digest.as_str().to_owned(),
                self.policy_digest.as_str().to_owned(),
                self.request_digest.as_str().to_owned(),
            ],
        )
    }

    pub fn computed_response_digest(&self) -> Digest {
        Digest::from_fields(
            "aws-verified-permissions-response/v1",
            &[
                self.evidence_digest.as_str().to_owned(),
                self.request_digest.as_str().to_owned(),
            ],
        )
    }

    pub fn validate_against(&self, request: &IsAuthorizedReadRequest) -> Result<(), ModelError> {
        request.validate_digest()?;
        if self.request_digest != request.request_digest
            || self.principal_digest != request.principal_digest
            || self.resource_digest != request.resource_digest
            || self.context_digest != request.context_digest
            || self.policy_digest != request.policy_digest
            || self
                .determining_policy
                .as_ref()
                .is_some_and(|policy| policy.policy_store_digest != request.policy_store_digest)
            || self.evidence_digest != self.computed_evidence_digest()
            || self.response_digest != self.computed_response_digest()
        {
            Err(ModelError::ResponseMismatch)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsVerifiedPermissionsRegistration {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: ServiceId,
    pub provider_id: ProviderId,
    pub consumer_id: ConsumerId,
    pub provider_version: String,
    pub version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub policy_digest: Digest,
    pub context_digest: Digest,
    pub registration_revision: Revision,
    pub registration_digest: Digest,
    pub state: RegistrationState,
}

pub type Registration = AwsVerifiedPermissionsRegistration;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationRevocation {
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub registration_revision: Revision,
    pub revocation_digest: Digest,
}

impl AwsVerifiedPermissionsRegistration {
    pub fn new(
        scope: &AwsVerifiedPermissionsScope,
        provider_id: ProviderId,
        provider_version: impl Into<String>,
        provider_digest: Digest,
    ) -> Result<Self, ModelError> {
        scope.validate_digest()?;
        let provider_version = provider_version.into();
        if provider_version.is_empty()
            || !is_digest(provider_digest.as_str())
            || !is_digest(scope.permission_digest().as_str())
            || !is_digest(scope.policy_digest().as_str())
            || !is_digest(scope.context_digest().as_str())
        {
            return Err(ModelError::InvalidRegistration);
        }
        let service_id = ServiceId::new(AWS_VERIFIED_PERMISSIONS_SERVICE_ID)
            .map_err(|_| ModelError::InvalidRegistration)?;
        let consumer_id = ConsumerId::new(AWS_VERIFIED_PERMISSIONS_CONSUMER_ID)
            .map_err(|_| ModelError::InvalidRegistration)?;
        let contract_digest = Digest::from_text(crate::AWS_VERIFIED_PERMISSIONS_CONTRACT_JSON);
        let version_digest = Digest::from_text(provider_version.as_bytes());
        let registration_revision = Revision::new(1)?;
        let registration_digest = Self::computed_digest(
            &contract_digest,
            &provider_id,
            &provider_version,
            &version_digest,
            &provider_digest,
            &AwsVerifiedPermissionsScopeDigestView {
                permission: scope.permission_digest(),
                scope: scope.scope_digest(),
                policy: scope.policy_digest(),
                context: scope.context_digest(),
            },
            registration_revision,
        );
        Ok(Self {
            schema_version: AWS_VERIFIED_PERMISSIONS_SCHEMA_VERSION.to_owned(),
            contract_version: AWS_VERIFIED_PERMISSIONS_CONTRACT_VERSION.to_owned(),
            service_id,
            provider_id,
            consumer_id,
            provider_version,
            version_digest,
            contract_digest,
            provider_digest,
            permission_digest: scope.permission_digest().clone(),
            scope_digest: scope.scope_digest().clone(),
            policy_digest: scope.policy_digest().clone(),
            context_digest: scope.context_digest().clone(),
            registration_revision,
            registration_digest,
            state: RegistrationState::Active,
        })
    }

    pub fn validate_for_scope(
        &self,
        scope: &AwsVerifiedPermissionsScope,
    ) -> Result<(), ModelError> {
        scope.validate_digest()?;
        if self.schema_version != AWS_VERIFIED_PERMISSIONS_SCHEMA_VERSION
            || self.contract_version != AWS_VERIFIED_PERMISSIONS_CONTRACT_VERSION
            || self.service_id.as_str() != AWS_VERIFIED_PERMISSIONS_SERVICE_ID
            || self.consumer_id.as_str() != AWS_VERIFIED_PERMISSIONS_CONSUMER_ID
            || self.version_digest != Digest::from_text(self.provider_version.as_bytes())
            || self.contract_digest
                != Digest::from_text(crate::AWS_VERIFIED_PERMISSIONS_CONTRACT_JSON)
            || self.permission_digest != *scope.permission_digest()
            || self.scope_digest != *scope.scope_digest()
            || self.policy_digest != *scope.policy_digest()
            || self.context_digest != *scope.context_digest()
            || self.registration_digest != self.computed_registration_digest()
        {
            Err(ModelError::InvalidRegistration)
        } else {
            Ok(())
        }
    }

    pub fn computed_registration_digest(&self) -> Digest {
        Self::computed_digest(
            &self.contract_digest,
            &self.provider_id,
            &self.provider_version,
            &self.version_digest,
            &self.provider_digest,
            &AwsVerifiedPermissionsScopeDigestView {
                permission: &self.permission_digest,
                scope: &self.scope_digest,
                policy: &self.policy_digest,
                context: &self.context_digest,
            },
            self.registration_revision,
        )
    }

    fn computed_digest(
        contract_digest: &Digest,
        provider_id: &ProviderId,
        provider_version: &str,
        version_digest: &Digest,
        provider_digest: &Digest,
        scope: &impl ScopeDigestFields,
        registration_revision: Revision,
    ) -> Digest {
        Digest::from_fields(
            "aws-verified-permissions-registration/v1",
            &[
                AWS_VERIFIED_PERMISSIONS_SCHEMA_VERSION.to_owned(),
                AWS_VERIFIED_PERMISSIONS_CONTRACT_VERSION.to_owned(),
                AWS_VERIFIED_PERMISSIONS_SERVICE_ID.to_owned(),
                provider_id.as_str().to_owned(),
                AWS_VERIFIED_PERMISSIONS_CONSUMER_ID.to_owned(),
                provider_version.to_owned(),
                version_digest.as_str().to_owned(),
                contract_digest.as_str().to_owned(),
                provider_digest.as_str().to_owned(),
                scope.permission_digest().as_str().to_owned(),
                scope.scope_digest().as_str().to_owned(),
                scope.policy_digest().as_str().to_owned(),
                scope.context_digest().as_str().to_owned(),
                registration_revision.get().to_string(),
            ],
        )
    }

    pub fn ensure_active(&self) -> Result<(), ModelError> {
        if self.state == RegistrationState::Active {
            Ok(())
        } else {
            Err(ModelError::AlreadyRevoked)
        }
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation, ModelError> {
        self.ensure_active()?;
        self.state = RegistrationState::Revoked;
        let revocation_digest = Digest::from_fields(
            "aws-verified-permissions-registration-revocation/v1",
            &[
                self.registration_digest.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.registration_revision.get().to_string(),
            ],
        );
        Ok(RegistrationRevocation {
            registration_digest: self.registration_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            registration_revision: self.registration_revision,
            revocation_digest,
        })
    }

    /// Re-registration is explicit and advances the revision; a revoked
    /// registration is never silently made active in place.
    pub fn reissue(&self) -> Result<Self, ModelError> {
        if self.state == RegistrationState::Active {
            return Err(ModelError::AlreadyActive);
        }
        let registration_revision = Revision::new(self.registration_revision.get() + 1)?;
        let registration_digest = Self::computed_digest(
            &self.contract_digest,
            &self.provider_id,
            &self.provider_version,
            &self.version_digest,
            &self.provider_digest,
            &AwsVerifiedPermissionsScopeDigestView {
                permission: &self.permission_digest,
                scope: &self.scope_digest,
                policy: &self.policy_digest,
                context: &self.context_digest,
            },
            registration_revision,
        );
        Ok(Self {
            registration_revision,
            registration_digest,
            state: RegistrationState::Active,
            ..self.clone()
        })
    }
}

struct AwsVerifiedPermissionsScopeDigestView<'a> {
    permission: &'a Digest,
    scope: &'a Digest,
    policy: &'a Digest,
    context: &'a Digest,
}

trait ScopeDigestFields {
    fn permission_digest(&self) -> &Digest;
    fn scope_digest(&self) -> &Digest;
    fn policy_digest(&self) -> &Digest;
    fn context_digest(&self) -> &Digest;
}

impl ScopeDigestFields for AwsVerifiedPermissionsScopeDigestView<'_> {
    fn permission_digest(&self) -> &Digest {
        self.permission
    }

    fn scope_digest(&self) -> &Digest {
        self.scope
    }

    fn policy_digest(&self) -> &Digest {
        self.policy
    }

    fn context_digest(&self) -> &Digest {
        self.context
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ReplaySet {
    digests: BTreeSet<Digest>,
}

impl ReplaySet {
    pub(crate) fn insert(&mut self, digest: Digest) -> bool {
        self.digests.insert(digest)
    }

    pub(crate) fn len(&self) -> usize {
        self.digests.len()
    }
}

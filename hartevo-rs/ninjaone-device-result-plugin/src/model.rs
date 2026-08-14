//! Typed scope, registration, projection, and proposal models for NinjaOne.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize, ser::SerializeStruct};
use thiserror::Error;

use crate::{
    CONTRACT_VERSION, MAX_ACTIVITIES, MAX_ALERTS, MAX_IDENTIFIER_BYTES, MAX_PATCHES, MAX_RECEIPTS,
    MAX_RESPONSE_BYTES, MAX_TEXT_BYTES, NINJAONE_API_REVISION, PLUGIN_ID, PROVIDER_ID,
    canonical_digest, contract_digest, implementation_digest, provider_digest, valid_digest,
    valid_identifier,
};

/// Errors fail closed at the scope, registration, transport, and proposal
/// boundaries. No raw provider field is interpolated into an error message.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum NinjaOneError {
    #[error("invalid {kind} identifier")]
    InvalidIdentifier { kind: &'static str },
    #[error("invalid {kind} text")]
    InvalidText { kind: &'static str },
    #[error("invalid digest")]
    InvalidDigest,
    #[error("invalid revision")]
    InvalidRevision,
    #[error("invalid scope")]
    InvalidScope,
    #[error("invalid read permission lease")]
    InvalidPermissionLease,
    #[error("permission lease is expired")]
    PermissionLeaseExpired,
    #[error("invalid opaque SecretReference")]
    InvalidSecretReference,
    #[error("SecretReference scope digest does not match")]
    SecretScopeMismatch,
    #[error("SecretReference permission digest does not match")]
    SecretPermissionMismatch,
    #[error("SecretReference is revoked")]
    SecretRevoked,
    #[error("SecretReference was already revoked")]
    SecretAlreadyRevoked,
    #[error("registration is not active")]
    RegistrationNotActive,
    #[error("registration is revoked or reversed")]
    RegistrationRevoked,
    #[error("registration version drifted")]
    RegistrationVersionMismatch,
    #[error("registration contract digest drifted")]
    RegistrationContractMismatch,
    #[error("registration provider digest drifted")]
    RegistrationProviderMismatch,
    #[error("registration API digest drifted")]
    RegistrationApiMismatch,
    #[error("registration implementation digest drifted")]
    RegistrationImplementationMismatch,
    #[error("registration permission digest drifted")]
    RegistrationPermissionMismatch,
    #[error("registration scope digest drifted")]
    RegistrationScopeMismatch,
    #[error("registration revision digest drifted")]
    RegistrationRevisionMismatch,
    #[error("registration SecretReference digest drifted")]
    RegistrationSecretMismatch,
    #[error("registration digest drifted")]
    RegistrationDigestMismatch,
    #[error("registration transition is invalid")]
    InvalidRegistrationTransition,
    #[error("Mission/Project/Consent scope does not match")]
    MissionScopeMismatch,
    #[error("provider scope does not match")]
    ProviderScopeMismatch,
    #[error("provider revision is stale or non-monotonic")]
    StaleProviderRevision,
    #[error("provider response is malformed")]
    MalformedPayload,
    #[error("contract document is malformed")]
    MalformedContract,
    #[error("response exceeds the Layer-1 byte bound")]
    ResponseTooLarge,
    #[error("bounded {kind} limit was exceeded")]
    BoundExceeded { kind: &'static str },
    #[error("provider pagination cursor repeated or exceeded the page budget")]
    PaginationLoop,
    #[error("duplicate provider observation")]
    DuplicateObservation,
    #[error("request or evidence integrity check failed")]
    EvidenceTampered,
    #[error("proposal integrity check failed")]
    ProposalTampered,
    #[error("an external mutation is forbidden in Layer 1: {operation}")]
    MutationForbidden { operation: &'static str },
    #[error("unsupported provider mode")]
    UnsupportedMode,
    #[error("provider transport error: {code}")]
    Transport { code: &'static str },
}

/// Lowercase SHA-256 used for contract, scope, registration, request, and
/// evidence identity. It never contains a raw secret or provider payload.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn new(value: impl Into<String>) -> Result<Self, NinjaOneError> {
        let value = value.into().to_ascii_lowercase();
        if valid_digest(&value) {
            Ok(Self(value))
        } else {
            Err(NinjaOneError::InvalidDigest)
        }
    }

    #[must_use]
    pub fn from_bytes(value: &[u8]) -> Self {
        Self(crate::sha256_hex(value))
    }

    #[must_use]
    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    #[must_use]
    pub fn from_serializable<T: Serialize + ?Sized>(value: &T) -> Self {
        canonical_digest(value)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<(), NinjaOneError> {
        if valid_digest(&self.0) {
            Ok(())
        } else {
            Err(NinjaOneError::InvalidDigest)
        }
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Semantic version carried by registration and proposal fences.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Version {
    major: u16,
    minor: u16,
    patch: u16,
}

impl Version {
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    pub const fn major(self) -> u16 {
        self.major
    }

    pub const fn minor(self) -> u16 {
        self.minor
    }

    pub const fn patch(self) -> u16 {
        self.patch
    }
}

pub const PLUGIN_VERSION: Version = Version::new(1, 0, 0);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, NinjaOneError> {
        if value == 0 {
            Err(NinjaOneError::InvalidRevision)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    fn next(self) -> Result<Self, NinjaOneError> {
        self.0
            .checked_add(1)
            .ok_or(NinjaOneError::InvalidRevision)
            .and_then(Self::new)
    }
}

macro_rules! bounded_id {
    ($name:ident, $kind:literal) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, NinjaOneError> {
                let value = value.into();
                if valid_identifier(&value, MAX_IDENTIFIER_BYTES) {
                    Ok(Self(value))
                } else {
                    Err(NinjaOneError::InvalidIdentifier { kind: $kind })
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

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

bounded_id!(NinjaOneOrganizationId, "NinjaOne organization");
bounded_id!(NinjaOneSiteId, "NinjaOne site");
bounded_id!(NinjaOneDeviceId, "NinjaOne device");
bounded_id!(NinjaOneAgentId, "NinjaOne agent");
bounded_id!(NinjaOneAlertId, "NinjaOne alert");
bounded_id!(NinjaOnePatchHealthId, "NinjaOne patch-health");
bounded_id!(NinjaOneActivityId, "NinjaOne activity");
bounded_id!(MissionId, "Hartevo Mission");
bounded_id!(ProjectId, "Hartevo Project");
bounded_id!(ConsentId, "Hartevo Consent");

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    OAuth2Bearer,
}

/// Opaque host-owned credential reference. The reference string is hashed at
/// construction and is never stored, serialized, displayed, or returned.
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    permission_digest: Digest,
    credential_revision: Revision,
    kind: SecretKind,
    revoked: bool,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_digest: self.reference_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            permission_digest: self.permission_digest.clone(),
            credential_revision: self.credential_revision,
            kind: self.kind,
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
            .field("permission_digest", &self.permission_digest)
            .field("credential_revision", &self.credential_revision)
            .field("kind", &self.kind)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest
            && self.scope_digest == other.scope_digest
            && self.permission_digest == other.permission_digest
            && self.credential_revision == other.credential_revision
            && self.kind == other.kind
            && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope_digest: Digest,
        permission_digest: Digest,
        credential_revision: u64,
        kind: SecretKind,
    ) -> Result<Self, NinjaOneError> {
        let reference_id = reference_id.into();
        if !reference_id.starts_with("secret-ref-")
            || !valid_identifier(&reference_id, MAX_IDENTIFIER_BYTES)
        {
            return Err(NinjaOneError::InvalidSecretReference);
        }
        let credential_revision = Revision::new(credential_revision)
            .map_err(|_| NinjaOneError::InvalidSecretReference)?;
        scope_digest.validate()?;
        permission_digest.validate()?;
        let reference_digest = Digest::from_serializable(&(
            "hartevo.ninjaone-secret-reference/v1",
            reference_id,
            &scope_digest,
            &permission_digest,
            credential_revision,
            kind,
        ));
        Ok(Self {
            reference_digest,
            scope_digest,
            permission_digest,
            credential_revision,
            kind,
            revoked: false,
        })
    }

    pub fn for_scope(
        reference_id: impl Into<String>,
        scope: &NinjaOneScope,
        lease: &PermissionLease,
        credential_revision: u64,
        kind: SecretKind,
    ) -> Result<Self, NinjaOneError> {
        Self::new(
            reference_id,
            scope.scope_digest().clone(),
            lease.permission_digest().clone(),
            credential_revision,
            kind,
        )
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    pub const fn kind(&self) -> SecretKind {
        self.kind
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<(), NinjaOneError> {
        if self.revoked {
            Err(NinjaOneError::SecretAlreadyRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }
}

impl Serialize for SecretReference {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Only the identity digest is serializable; credential material and
        // the host reference string are structurally absent.
        let mut state = serializer.serialize_struct("SecretReference", 4)?;
        state.serialize_field("referenceDigest", &self.reference_digest)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest)?;
        state.serialize_field("credentialRevision", &self.credential_revision)?;
        state.end()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionLease {
    scopes: BTreeSet<String>,
    lease_revision: Revision,
    expires_at_millis: Option<u64>,
    permission_digest: Digest,
}

impl PermissionLease {
    pub fn new<I, S>(
        scopes: I,
        lease_revision: u64,
        expires_at_millis: Option<u64>,
    ) -> Result<Self, NinjaOneError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let scopes = scopes.into_iter().map(Into::into).collect::<BTreeSet<_>>();
        if scopes.is_empty()
            || scopes.iter().any(|scope| {
                !valid_identifier(scope, MAX_TEXT_BYTES)
                    || scope.ends_with(":write")
                    || scope.contains("mutate")
            })
            || !scopes.contains("monitoring:read")
        {
            return Err(NinjaOneError::InvalidPermissionLease);
        }
        let lease_revision =
            Revision::new(lease_revision).map_err(|_| NinjaOneError::InvalidPermissionLease)?;
        let permission_digest = Digest::from_serializable(&(
            "hartevo.ninjaone-permission-lease/v1",
            &scopes,
            lease_revision,
            expires_at_millis,
        ));
        Ok(Self {
            scopes,
            lease_revision,
            expires_at_millis,
            permission_digest,
        })
    }

    pub fn required_read(lease_revision: u64) -> Result<Self, NinjaOneError> {
        Self::new(
            [
                "monitoring:read",
                "organizations:read",
                "devices:read",
                "device-alerts:read",
                "device-health:read",
                "device-patch-health:read",
                "device-activities:read",
            ],
            lease_revision,
            None,
        )
    }

    pub fn scopes(&self) -> &BTreeSet<String> {
        &self.scopes
    }

    pub const fn lease_revision(&self) -> Revision {
        self.lease_revision
    }

    pub const fn expires_at_millis(&self) -> Option<u64> {
        self.expires_at_millis
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub const fn is_expired_at(&self, now_millis: u64) -> bool {
        match self.expires_at_millis {
            Some(expiry) => now_millis >= expiry,
            None => false,
        }
    }

    pub fn validate_at(&self, now_millis: u64) -> Result<(), NinjaOneError> {
        if self.is_expired_at(now_millis) {
            Err(NinjaOneError::PermissionLeaseExpired)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NinjaOneRevisionSet {
    pub organization: Revision,
    pub site: Revision,
    pub device: Revision,
    pub agent: Revision,
    pub alert: Revision,
    pub patch_health: Revision,
    pub activity: Revision,
    pub mission: Revision,
    pub project: Revision,
    pub consent: Revision,
}

impl NinjaOneRevisionSet {
    pub fn from_values(values: [u64; 10]) -> Result<Self, NinjaOneError> {
        Ok(Self {
            organization: Revision::new(values[0])?,
            site: Revision::new(values[1])?,
            device: Revision::new(values[2])?,
            agent: Revision::new(values[3])?,
            alert: Revision::new(values[4])?,
            patch_health: Revision::new(values[5])?,
            activity: Revision::new(values[6])?,
            mission: Revision::new(values[7])?,
            project: Revision::new(values[8])?,
            consent: Revision::new(values[9])?,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NinjaOneScopeBinding {
    pub organization_id: NinjaOneOrganizationId,
    pub site_id: NinjaOneSiteId,
    pub device_id: NinjaOneDeviceId,
    pub agent_id: NinjaOneAgentId,
    pub alert_id: NinjaOneAlertId,
    pub patch_health_id: NinjaOnePatchHealthId,
    pub activity_id: NinjaOneActivityId,
    pub mission_id: MissionId,
    pub project_id: ProjectId,
    pub consent_id: ConsentId,
    pub revisions: NinjaOneRevisionSet,
}

/// Exact external and Hartevo scope for one endpoint-device result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NinjaOneScope {
    binding: NinjaOneScopeBinding,
    permission_digest: Digest,
    scope_digest: Digest,
    revision_digest: Digest,
}

impl NinjaOneScope {
    pub fn new(
        binding: NinjaOneScopeBinding,
        permission_digest: Digest,
    ) -> Result<Self, NinjaOneError> {
        permission_digest.validate()?;
        let revision_digest =
            Digest::from_serializable(&("hartevo.ninjaone-revision-fence/v1", &binding.revisions));
        let scope_digest = Digest::from_serializable(&(
            "hartevo.ninjaone-scope/v1",
            &binding,
            &permission_digest,
            &revision_digest,
        ));
        Ok(Self {
            binding,
            permission_digest,
            scope_digest,
            revision_digest,
        })
    }

    pub fn from_parts(
        organization_id: impl Into<String>,
        site_id: impl Into<String>,
        device_id: impl Into<String>,
        agent_id: impl Into<String>,
        alert_id: impl Into<String>,
        patch_health_id: impl Into<String>,
        activity_id: impl Into<String>,
        mission_id: impl Into<String>,
        project_id: impl Into<String>,
        consent_id: impl Into<String>,
        revisions: [u64; 10],
        permission_digest: Digest,
    ) -> Result<Self, NinjaOneError> {
        Self::new(
            NinjaOneScopeBinding {
                organization_id: NinjaOneOrganizationId::new(organization_id)?,
                site_id: NinjaOneSiteId::new(site_id)?,
                device_id: NinjaOneDeviceId::new(device_id)?,
                agent_id: NinjaOneAgentId::new(agent_id)?,
                alert_id: NinjaOneAlertId::new(alert_id)?,
                patch_health_id: NinjaOnePatchHealthId::new(patch_health_id)?,
                activity_id: NinjaOneActivityId::new(activity_id)?,
                mission_id: MissionId::new(mission_id)?,
                project_id: ProjectId::new(project_id)?,
                consent_id: ConsentId::new(consent_id)?,
                revisions: NinjaOneRevisionSet::from_values(revisions)?,
            },
            permission_digest,
        )
    }

    pub fn binding(&self) -> &NinjaOneScopeBinding {
        &self.binding
    }

    pub fn organization_id(&self) -> &NinjaOneOrganizationId {
        &self.binding.organization_id
    }

    pub fn site_id(&self) -> &NinjaOneSiteId {
        &self.binding.site_id
    }

    pub fn device_id(&self) -> &NinjaOneDeviceId {
        &self.binding.device_id
    }

    pub fn agent_id(&self) -> &NinjaOneAgentId {
        &self.binding.agent_id
    }

    pub fn alert_id(&self) -> &NinjaOneAlertId {
        &self.binding.alert_id
    }

    pub fn patch_health_id(&self) -> &NinjaOnePatchHealthId {
        &self.binding.patch_health_id
    }

    pub fn activity_id(&self) -> &NinjaOneActivityId {
        &self.binding.activity_id
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.binding.mission_id
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.binding.project_id
    }

    pub fn consent_id(&self) -> &ConsentId {
        &self.binding.consent_id
    }

    pub fn revisions(&self) -> &NinjaOneRevisionSet {
        &self.binding.revisions
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn revision_digest(&self) -> &Digest {
        &self.revision_digest
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Unmounted,
    Revoked,
    Reversed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationTransition {
    pub previous: RegistrationStatus,
    pub current: RegistrationStatus,
    pub revision: Revision,
    pub registration_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationFingerprint<'a> {
    version: Version,
    contract_digest: &'a Digest,
    provider_digest: &'a Digest,
    api_digest: &'a Digest,
    implementation_digest: &'a Digest,
    permission_digest: &'a Digest,
    scope_digest: &'a Digest,
    revision_digest: &'a Digest,
    secret_reference_digest: &'a Digest,
    status: RegistrationStatus,
    registration_revision: Revision,
}

/// Reversible and revocable registration bound to all version and scope
/// digests. The raw SecretReference is deliberately not serializable.
pub struct NinjaOneRegistration {
    version: Version,
    contract_digest: Digest,
    provider_digest: Digest,
    api_digest: Digest,
    implementation_digest: Digest,
    permission_digest: Digest,
    scope_digest: Digest,
    revision_digest: Digest,
    secret_reference: SecretReference,
    status: RegistrationStatus,
    registration_revision: Revision,
    registration_digest: Digest,
}

impl Clone for NinjaOneRegistration {
    fn clone(&self) -> Self {
        Self {
            version: self.version,
            contract_digest: self.contract_digest.clone(),
            provider_digest: self.provider_digest.clone(),
            api_digest: self.api_digest.clone(),
            implementation_digest: self.implementation_digest.clone(),
            permission_digest: self.permission_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            revision_digest: self.revision_digest.clone(),
            secret_reference: self.secret_reference.clone(),
            status: self.status,
            registration_revision: self.registration_revision,
            registration_digest: self.registration_digest.clone(),
        }
    }
}

impl fmt::Debug for NinjaOneRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NinjaOneRegistration")
            .field("version", &self.version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_digest", &self.provider_digest)
            .field("api_digest", &self.api_digest)
            .field("implementation_digest", &self.implementation_digest)
            .field("permission_digest", &self.permission_digest)
            .field("scope_digest", &self.scope_digest)
            .field("revision_digest", &self.revision_digest)
            .field("secret_reference", &self.secret_reference)
            .field("status", &self.status)
            .field("registration_revision", &self.registration_revision)
            .field("registration_digest", &self.registration_digest)
            .finish()
    }
}

impl Serialize for NinjaOneRegistration {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("NinjaOneRegistration", 11)?;
        state.serialize_field("version", &self.version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("apiDigest", &self.api_digest)?;
        state.serialize_field("implementationDigest", &self.implementation_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("revisionDigest", &self.revision_digest)?;
        state.serialize_field(
            "secretReferenceDigest",
            &self.secret_reference.reference_digest,
        )?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
        state.end()
    }
}

impl NinjaOneRegistration {
    pub fn new(
        scope: &NinjaOneScope,
        permission_lease: &PermissionLease,
        secret_reference: SecretReference,
        registration_revision: u64,
    ) -> Result<Self, NinjaOneError> {
        if secret_reference.is_revoked() {
            return Err(NinjaOneError::SecretRevoked);
        }
        if secret_reference.scope_digest() != scope.scope_digest() {
            return Err(NinjaOneError::SecretScopeMismatch);
        }
        if secret_reference.permission_digest() != permission_lease.permission_digest()
            || permission_lease.permission_digest() != scope.permission_digest()
        {
            return Err(NinjaOneError::SecretPermissionMismatch);
        }
        let registration_revision = Revision::new(registration_revision)?;
        let mut registration = Self {
            version: PLUGIN_VERSION,
            contract_digest: contract_digest(),
            provider_digest: provider_digest(),
            api_digest: Digest::from_text(NINJAONE_API_REVISION),
            implementation_digest: implementation_digest(),
            permission_digest: permission_lease.permission_digest().clone(),
            scope_digest: scope.scope_digest().clone(),
            revision_digest: scope.revision_digest().clone(),
            secret_reference,
            status: RegistrationStatus::Active,
            registration_revision,
            registration_digest: Digest::from_text("pending-ninjaone-registration"),
        };
        registration.registration_digest = registration.compute_digest();
        Ok(registration)
    }

    fn compute_digest(&self) -> Digest {
        canonical_digest(&RegistrationFingerprint {
            version: self.version,
            contract_digest: &self.contract_digest,
            provider_digest: &self.provider_digest,
            api_digest: &self.api_digest,
            implementation_digest: &self.implementation_digest,
            permission_digest: &self.permission_digest,
            scope_digest: &self.scope_digest,
            revision_digest: &self.revision_digest,
            secret_reference_digest: self.secret_reference.reference_digest(),
            status: self.status,
            registration_revision: self.registration_revision,
        })
    }

    pub fn validate(&self, scope: &NinjaOneScope) -> Result<(), NinjaOneError> {
        self.contract_digest.validate()?;
        self.provider_digest.validate()?;
        self.api_digest.validate()?;
        self.implementation_digest.validate()?;
        self.permission_digest.validate()?;
        self.scope_digest.validate()?;
        self.revision_digest.validate()?;
        self.secret_reference.reference_digest().validate()?;
        self.registration_digest.validate()?;
        if self.version != PLUGIN_VERSION {
            return Err(NinjaOneError::RegistrationVersionMismatch);
        }
        if self.contract_digest != contract_digest() {
            return Err(NinjaOneError::RegistrationContractMismatch);
        }
        if self.provider_digest != provider_digest() {
            return Err(NinjaOneError::RegistrationProviderMismatch);
        }
        if self.api_digest != Digest::from_text(NINJAONE_API_REVISION) {
            return Err(NinjaOneError::RegistrationApiMismatch);
        }
        if self.implementation_digest != implementation_digest() {
            return Err(NinjaOneError::RegistrationImplementationMismatch);
        }
        if self.permission_digest != *scope.permission_digest() {
            return Err(NinjaOneError::RegistrationPermissionMismatch);
        }
        if self.scope_digest != *scope.scope_digest() {
            return Err(NinjaOneError::RegistrationScopeMismatch);
        }
        if self.revision_digest != *scope.revision_digest() {
            return Err(NinjaOneError::RegistrationRevisionMismatch);
        }
        if self.secret_reference.scope_digest() != scope.scope_digest() {
            return Err(NinjaOneError::SecretScopeMismatch);
        }
        if self.secret_reference.permission_digest() != scope.permission_digest() {
            return Err(NinjaOneError::SecretPermissionMismatch);
        }
        if self.registration_digest != self.compute_digest() {
            return Err(NinjaOneError::RegistrationDigestMismatch);
        }
        if self.secret_reference.is_revoked() {
            return Err(NinjaOneError::SecretRevoked);
        }
        Ok(())
    }

    pub fn ensure_active(&self, scope: &NinjaOneScope) -> Result<(), NinjaOneError> {
        if matches!(
            self.status,
            RegistrationStatus::Revoked | RegistrationStatus::Reversed
        ) {
            return Err(NinjaOneError::RegistrationRevoked);
        }
        self.validate(scope)?;
        if self.status != RegistrationStatus::Active {
            Err(NinjaOneError::RegistrationNotActive)
        } else {
            Ok(())
        }
    }

    pub fn version(&self) -> Version {
        self.version
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn api_digest(&self) -> &Digest {
        &self.api_digest
    }

    pub fn implementation_digest(&self) -> &Digest {
        &self.implementation_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn revision_digest(&self) -> &Digest {
        &self.revision_digest
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn status(&self) -> RegistrationStatus {
        self.status
    }

    pub const fn registration_revision(&self) -> Revision {
        self.registration_revision
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    fn transition(
        &mut self,
        next: RegistrationStatus,
    ) -> Result<RegistrationTransition, NinjaOneError> {
        let valid = matches!(
            (self.status, next),
            (
                RegistrationStatus::Active,
                RegistrationStatus::Unmounted
                    | RegistrationStatus::Revoked
                    | RegistrationStatus::Reversed
            ) | (
                RegistrationStatus::Unmounted,
                RegistrationStatus::Active
                    | RegistrationStatus::Revoked
                    | RegistrationStatus::Reversed
            )
        );
        if !valid {
            return Err(NinjaOneError::InvalidRegistrationTransition);
        }
        let previous = self.status;
        self.status = next;
        self.registration_revision = self.registration_revision.next()?;
        self.registration_digest = self.compute_digest();
        Ok(RegistrationTransition {
            previous,
            current: next,
            revision: self.registration_revision,
            registration_digest: self.registration_digest.clone(),
        })
    }

    pub fn unmount(&mut self) -> Result<RegistrationTransition, NinjaOneError> {
        self.transition(RegistrationStatus::Unmounted)
    }

    pub fn remount(&mut self) -> Result<RegistrationTransition, NinjaOneError> {
        self.transition(RegistrationStatus::Active)
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransition, NinjaOneError> {
        self.secret_reference.revoke()?;
        self.transition(RegistrationStatus::Revoked)
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransition, NinjaOneError> {
        self.transition(RegistrationStatus::Reversed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportMode {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl TransportMode {
    pub const fn connected(self) -> bool {
        false
    }

    pub const fn native(self) -> bool {
        false
    }
}

pub type NinjaOneProvenance = TransportMode;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Healthy,
    NeedsAttention,
    Unhealthy,
    Unknown,
}

impl HealthStatus {
    pub fn parse(value: &str) -> Self {
        match value.to_ascii_uppercase().as_str() {
            "HEALTHY" | "OK" => Self::Healthy,
            "NEEDS_ATTENTION" | "NEEDS-ATTENTION" | "DEGRADED" => Self::NeedsAttention,
            "UNHEALTHY" | "FAILED" => Self::Unhealthy,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertKind {
    AgentOffline,
    Cpu,
    Memory,
    Network,
    Disk,
    Patch,
    PendingReboot,
    Other,
}

impl AlertKind {
    pub fn parse(value: &str) -> Self {
        let value = value.to_ascii_uppercase();
        if value == "AGENT_OFFLINE" {
            Self::AgentOffline
        } else if value.contains("CPU") {
            Self::Cpu
        } else if value.contains("MEMORY") {
            Self::Memory
        } else if value.contains("NETWORK") || value.contains("PING") {
            Self::Network
        } else if value.contains("DISK") || value.contains("RAID") {
            Self::Disk
        } else if value.contains("PATCH") {
            Self::Patch
        } else if value.contains("PENDING_REBOOT") {
            Self::PendingReboot
        } else {
            Self::Other
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PatchStatus {
    Pending,
    Failed,
    Installed,
    Rejected,
    Unknown,
}

impl PatchStatus {
    pub fn parse(value: &str) -> Self {
        match value.to_ascii_uppercase().as_str() {
            "PENDING" | "APPROVED" => Self::Pending,
            "FAILED" => Self::Failed,
            "INSTALLED" | "SUCCEEDED" | "SUCCESS" => Self::Installed,
            "REJECTED" => Self::Rejected,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivitySeverity {
    None,
    Minor,
    Moderate,
    Major,
    Critical,
    Unknown,
}

impl ActivitySeverity {
    pub fn parse(value: &str) -> Self {
        match value.to_ascii_uppercase().as_str() {
            "NONE" => Self::None,
            "MINOR" => Self::Minor,
            "MODERATE" => Self::Moderate,
            "MAJOR" => Self::Major,
            "CRITICAL" => Self::Critical,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityResult {
    Success,
    Failure,
    Unsupported,
    Uncompleted,
    Unknown,
}

impl ActivityResult {
    pub fn parse(value: &str) -> Self {
        match value.to_ascii_uppercase().as_str() {
            "SUCCESS" => Self::Success,
            "FAILURE" => Self::Failure,
            "UNSUPPORTED" => Self::Unsupported,
            "UNCOMPLETED" => Self::Uncompleted,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityKind {
    Patch,
    Agent,
    System,
    Alert,
    Other,
}

impl ActivityKind {
    pub fn parse(value: &str) -> Self {
        let value = value.to_ascii_uppercase();
        if value.contains("PATCH") {
            Self::Patch
        } else if value.contains("AGENT") || value.contains("NODE") {
            Self::Agent
        } else if value.contains("ALERT") || value.contains("CONDITION") {
            Self::Alert
        } else if value.contains("SYSTEM") || value.contains("REBOOT") {
            Self::System
        } else {
            Self::Other
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NinjaOneDeviceState {
    Healthy,
    Degraded,
    Offline,
    Alerted,
    PatchPending,
    Partial,
    RetentionGap,
    AccessLost,
    ProviderUnknown,
}

pub type DeviceResultState = NinjaOneDeviceState;
pub type NinjaOneResultState = NinjaOneDeviceState;

impl NinjaOneDeviceState {
    fn priority(self) -> u8 {
        match self {
            Self::AccessLost => 9,
            Self::ProviderUnknown => 8,
            Self::RetentionGap => 7,
            Self::Partial => 6,
            Self::Offline => 5,
            Self::Alerted => 4,
            Self::PatchPending => 3,
            Self::Degraded => 2,
            Self::Healthy => 1,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NinjaOneProviderErrorProjection {
    pub code: String,
    pub http_status: Option<u16>,
    pub retryable: bool,
    pub error_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NinjaOneResultProjection {
    pub states: Vec<NinjaOneDeviceState>,
    pub primary_state: NinjaOneDeviceState,
    pub partial: bool,
    pub offline: bool,
    pub alert_count: usize,
    pub pending_patch_count: usize,
    pub failed_patch_count: usize,
    pub health_status: HealthStatus,
    pub provider_error: Option<NinjaOneProviderErrorProjection>,
}

impl NinjaOneResultProjection {
    pub fn new(
        mut states: Vec<NinjaOneDeviceState>,
        partial: bool,
        offline: bool,
        alert_count: usize,
        pending_patch_count: usize,
        failed_patch_count: usize,
        health_status: HealthStatus,
        provider_error: Option<NinjaOneProviderErrorProjection>,
    ) -> Result<Self, NinjaOneError> {
        if states.is_empty() {
            return Err(NinjaOneError::InvalidScope);
        }
        if partial && !states.contains(&NinjaOneDeviceState::Partial) {
            states.push(NinjaOneDeviceState::Partial);
        }
        states.sort_unstable();
        states.dedup();
        let primary_state = states
            .iter()
            .copied()
            .max_by_key(|state| state.priority())
            .ok_or(NinjaOneError::InvalidScope)?;
        Ok(Self {
            states,
            primary_state,
            partial,
            offline,
            alert_count,
            pending_patch_count,
            failed_patch_count,
            health_status,
            provider_error,
        })
    }

    pub fn has_state(&self, state: NinjaOneDeviceState) -> bool {
        self.states.contains(&state)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NinjaOneOrganizationProjection {
    pub organization_id: NinjaOneOrganizationId,
    pub site_count: usize,
    pub organization_revision: Revision,
    pub identity_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NinjaOneSiteProjection {
    pub organization_id: NinjaOneOrganizationId,
    pub site_id: NinjaOneSiteId,
    pub site_revision: Revision,
    pub identity_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NinjaOneDeviceProjection {
    pub organization_id: NinjaOneOrganizationId,
    pub site_id: NinjaOneSiteId,
    pub device_id: NinjaOneDeviceId,
    pub agent_id: NinjaOneAgentId,
    pub offline: bool,
    pub last_contact_at_millis: Option<u64>,
    pub device_revision: Revision,
    pub identity_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NinjaOneAgentProjection {
    pub device_id: NinjaOneDeviceId,
    pub agent_id: NinjaOneAgentId,
    pub agent_revision: Revision,
    pub last_contact_at_millis: Option<u64>,
    pub identity_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NinjaOneAlertProjection {
    pub alert_id: NinjaOneAlertId,
    pub device_id: NinjaOneDeviceId,
    pub kind: AlertKind,
    pub created_at_millis: Option<u64>,
    pub updated_at_millis: Option<u64>,
    pub alert_revision: Revision,
    pub body_digest: Option<Digest>,
    pub metadata_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NinjaOnePatchHealthProjection {
    pub patch_health_id: NinjaOnePatchHealthId,
    pub device_id: NinjaOneDeviceId,
    pub health_status: HealthStatus,
    pub pending_patch_count: usize,
    pub failed_patch_count: usize,
    pub observed_at_millis: Option<u64>,
    pub patch_health_revision: Revision,
    pub metadata_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NinjaOneActivityProjection {
    pub activity_id: NinjaOneActivityId,
    pub device_id: NinjaOneDeviceId,
    pub kind: ActivityKind,
    pub severity: ActivitySeverity,
    pub result: ActivityResult,
    pub activity_at_millis: Option<u64>,
    pub activity_revision: Revision,
    pub metadata_digest: Digest,
}

/// The only receipt retained by Layer 1: route identity, bounded status/size,
/// and digests. Authorization headers, query values, and response bodies are
/// structurally absent.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NinjaOneRedactedReceipt {
    pub endpoint: String,
    pub method: String,
    pub status: u16,
    pub response_bytes: usize,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub redacted_headers: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NinjaOneDeviceResultEvidence {
    pub organization: Option<NinjaOneOrganizationProjection>,
    pub site: Option<NinjaOneSiteProjection>,
    pub device: Option<NinjaOneDeviceProjection>,
    pub agent: Option<NinjaOneAgentProjection>,
    pub alerts: Vec<NinjaOneAlertProjection>,
    pub patch_health: Option<NinjaOnePatchHealthProjection>,
    pub activities: Vec<NinjaOneActivityProjection>,
    pub projection: NinjaOneResultProjection,
    pub partial: bool,
    pub observed_at_millis: u64,
    pub receipts: Vec<NinjaOneRedactedReceipt>,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub provenance: TransportMode,
    pub connected: bool,
    pub native: bool,
    pub proposal_only: bool,
    pub evidence_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceFingerprint<'a> {
    organization: &'a Option<NinjaOneOrganizationProjection>,
    site: &'a Option<NinjaOneSiteProjection>,
    device: &'a Option<NinjaOneDeviceProjection>,
    agent: &'a Option<NinjaOneAgentProjection>,
    alerts: &'a [NinjaOneAlertProjection],
    patch_health: &'a Option<NinjaOnePatchHealthProjection>,
    activities: &'a [NinjaOneActivityProjection],
    projection: &'a NinjaOneResultProjection,
    partial: bool,
    observed_at_millis: u64,
    receipts: &'a [NinjaOneRedactedReceipt],
    scope_digest: &'a Digest,
    revision_digest: &'a Digest,
    registration_digest: &'a Digest,
    provider_digest: &'a Digest,
    api_digest: &'a Digest,
    permission_digest: &'a Digest,
    provenance: TransportMode,
    connected: bool,
    native: bool,
    proposal_only: bool,
}

impl NinjaOneDeviceResultEvidence {
    pub(crate) fn from_parts(parts: NinjaOneDeviceResultEvidenceParts) -> Self {
        let mut evidence = Self {
            organization: parts.organization,
            site: parts.site,
            device: parts.device,
            agent: parts.agent,
            alerts: parts.alerts,
            patch_health: parts.patch_health,
            activities: parts.activities,
            projection: parts.projection,
            partial: parts.partial,
            observed_at_millis: parts.observed_at_millis,
            receipts: parts.receipts,
            scope_digest: parts.scope_digest,
            revision_digest: parts.revision_digest,
            registration_digest: parts.registration_digest,
            provider_digest: parts.provider_digest,
            api_digest: parts.api_digest,
            permission_digest: parts.permission_digest,
            provenance: parts.provenance,
            connected: false,
            native: false,
            proposal_only: true,
            evidence_digest: Digest::from_text("pending-ninjaone-evidence"),
        };
        evidence.evidence_digest = evidence.compute_digest();
        evidence
    }

    fn compute_digest(&self) -> Digest {
        canonical_digest(&EvidenceFingerprint {
            organization: &self.organization,
            site: &self.site,
            device: &self.device,
            agent: &self.agent,
            alerts: &self.alerts,
            patch_health: &self.patch_health,
            activities: &self.activities,
            projection: &self.projection,
            partial: self.partial,
            observed_at_millis: self.observed_at_millis,
            receipts: &self.receipts,
            scope_digest: &self.scope_digest,
            revision_digest: &self.revision_digest,
            registration_digest: &self.registration_digest,
            provider_digest: &self.provider_digest,
            api_digest: &self.api_digest,
            permission_digest: &self.permission_digest,
            provenance: self.provenance,
            connected: self.connected,
            native: self.native,
            proposal_only: self.proposal_only,
        })
    }

    pub fn verify_integrity(&self) -> Result<(), NinjaOneError> {
        for digest in [
            &self.scope_digest,
            &self.revision_digest,
            &self.registration_digest,
            &self.provider_digest,
            &self.api_digest,
            &self.permission_digest,
            &self.evidence_digest,
        ] {
            digest.validate()?;
        }
        if self.connected || self.native || !self.proposal_only {
            return Err(NinjaOneError::EvidenceTampered);
        }
        if self.alerts.len() > MAX_ALERTS
            || self.activities.len() > MAX_ACTIVITIES
            || self.receipts.len() > MAX_RECEIPTS
        {
            return Err(NinjaOneError::BoundExceeded {
                kind: "device-result evidence",
            });
        }
        if self.receipts.iter().any(|receipt| {
            receipt.response_bytes > MAX_RESPONSE_BYTES
                || receipt.method != "GET"
                || !receipt
                    .redacted_headers
                    .iter()
                    .any(|header| header.eq_ignore_ascii_case("authorization"))
                || !receipt
                    .redacted_headers
                    .iter()
                    .any(|header| header.eq_ignore_ascii_case("cookie"))
                || receipt.redacted_headers.iter().any(|header| {
                    header.contains("Bearer ")
                        || header.contains('=')
                        || header.contains("access_token")
                })
        }) {
            return Err(NinjaOneError::EvidenceTampered);
        }
        if self.evidence_digest != self.compute_digest() {
            return Err(NinjaOneError::EvidenceTampered);
        }
        Ok(())
    }

    pub fn projection(&self) -> &NinjaOneResultProjection {
        &self.projection
    }

    pub fn receipts(&self) -> &[NinjaOneRedactedReceipt] {
        &self.receipts
    }

    pub fn provenance(&self) -> TransportMode {
        self.provenance
    }

    pub const fn is_connected(&self) -> bool {
        self.connected
    }

    pub const fn is_native(&self) -> bool {
        self.native
    }

    pub fn digest(&self) -> &Digest {
        &self.evidence_digest
    }
}

pub(crate) struct NinjaOneDeviceResultEvidenceParts {
    pub organization: Option<NinjaOneOrganizationProjection>,
    pub site: Option<NinjaOneSiteProjection>,
    pub device: Option<NinjaOneDeviceProjection>,
    pub agent: Option<NinjaOneAgentProjection>,
    pub alerts: Vec<NinjaOneAlertProjection>,
    pub patch_health: Option<NinjaOnePatchHealthProjection>,
    pub activities: Vec<NinjaOneActivityProjection>,
    pub projection: NinjaOneResultProjection,
    pub partial: bool,
    pub observed_at_millis: u64,
    pub receipts: Vec<NinjaOneRedactedReceipt>,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub provenance: TransportMode,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NinjaOneDeviceResultProposal {
    pub scope_digest: Digest,
    pub mission_id: MissionId,
    pub project_id: ProjectId,
    pub consent_id: ConsentId,
    pub mission_revision: Revision,
    pub project_revision: Revision,
    pub consent_revision: Revision,
    pub projection: NinjaOneResultProjection,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub revision_digest: Digest,
    pub non_mutating: bool,
    pub external_write: bool,
    pub work_product_adopted: bool,
    pub outcome_adopted: bool,
    pub kernel_authority: bool,
    pub proposal_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProposalFingerprint<'a> {
    scope_digest: &'a Digest,
    mission_id: &'a MissionId,
    project_id: &'a ProjectId,
    consent_id: &'a ConsentId,
    mission_revision: Revision,
    project_revision: Revision,
    consent_revision: Revision,
    projection: &'a NinjaOneResultProjection,
    evidence_digest: &'a Digest,
    registration_digest: &'a Digest,
    provider_digest: &'a Digest,
    revision_digest: &'a Digest,
    non_mutating: bool,
    external_write: bool,
    work_product_adopted: bool,
    outcome_adopted: bool,
    kernel_authority: bool,
}

impl NinjaOneDeviceResultProposal {
    pub(crate) fn new(
        evidence: &NinjaOneDeviceResultEvidence,
        scope: &NinjaOneScope,
        registration: &NinjaOneRegistration,
    ) -> Result<Self, NinjaOneError> {
        evidence.verify_integrity()?;
        registration.ensure_active(scope)?;
        if evidence.scope_digest != *scope.scope_digest()
            || evidence.registration_digest != *registration.registration_digest()
        {
            return Err(NinjaOneError::ProviderScopeMismatch);
        }
        let mut proposal = Self {
            scope_digest: scope.scope_digest().clone(),
            mission_id: scope.mission_id().clone(),
            project_id: scope.project_id().clone(),
            consent_id: scope.consent_id().clone(),
            mission_revision: scope.revisions().mission,
            project_revision: scope.revisions().project,
            consent_revision: scope.revisions().consent,
            projection: evidence.projection.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            registration_digest: registration.registration_digest().clone(),
            provider_digest: registration.provider_digest().clone(),
            revision_digest: scope.revision_digest().clone(),
            non_mutating: true,
            external_write: false,
            work_product_adopted: false,
            outcome_adopted: false,
            kernel_authority: false,
            proposal_digest: Digest::from_text("pending-ninjaone-proposal"),
        };
        proposal.proposal_digest = proposal.compute_digest();
        Ok(proposal)
    }

    fn compute_digest(&self) -> Digest {
        canonical_digest(&ProposalFingerprint {
            scope_digest: &self.scope_digest,
            mission_id: &self.mission_id,
            project_id: &self.project_id,
            consent_id: &self.consent_id,
            mission_revision: self.mission_revision,
            project_revision: self.project_revision,
            consent_revision: self.consent_revision,
            projection: &self.projection,
            evidence_digest: &self.evidence_digest,
            registration_digest: &self.registration_digest,
            provider_digest: &self.provider_digest,
            revision_digest: &self.revision_digest,
            non_mutating: self.non_mutating,
            external_write: self.external_write,
            work_product_adopted: self.work_product_adopted,
            outcome_adopted: self.outcome_adopted,
            kernel_authority: self.kernel_authority,
        })
    }

    pub fn verify_integrity(&self) -> Result<(), NinjaOneError> {
        for digest in [
            &self.scope_digest,
            &self.evidence_digest,
            &self.registration_digest,
            &self.provider_digest,
            &self.revision_digest,
            &self.proposal_digest,
        ] {
            digest.validate()?;
        }
        if !self.non_mutating
            || self.external_write
            || self.work_product_adopted
            || self.outcome_adopted
            || self.kernel_authority
        {
            return Err(NinjaOneError::ProposalTampered);
        }
        if self.proposal_digest != self.compute_digest() {
            return Err(NinjaOneError::ProposalTampered);
        }
        Ok(())
    }

    pub fn validate_against(
        &self,
        evidence: &NinjaOneDeviceResultEvidence,
        scope: &NinjaOneScope,
        registration: &NinjaOneRegistration,
    ) -> Result<(), NinjaOneError> {
        self.verify_integrity()?;
        evidence.verify_integrity()?;
        registration.ensure_active(scope)?;
        if self.scope_digest != *scope.scope_digest()
            || self.evidence_digest != *evidence.digest()
            || self.registration_digest != *registration.registration_digest()
            || self.provider_digest != *registration.provider_digest()
            || self.revision_digest != *scope.revision_digest()
            || self.mission_id != *scope.mission_id()
            || self.project_id != *scope.project_id()
            || self.consent_id != *scope.consent_id()
            || self.mission_revision != scope.revisions().mission
            || self.project_revision != scope.revisions().project
            || self.consent_revision != scope.revisions().consent
        {
            return Err(NinjaOneError::MissionScopeMismatch);
        }
        Ok(())
    }

    pub fn digest(&self) -> &Digest {
        &self.proposal_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NinjaOneRedactedRecording {
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub projection_digest: Digest,
    pub provenance: TransportMode,
    pub durable: bool,
    pub raw_provider_payload_retained: bool,
    pub raw_activity_log_retained: bool,
    pub credential_material_serialized: bool,
    pub raw_pii_retained: bool,
    pub native_receipt: bool,
}

impl NinjaOneRedactedRecording {
    pub(crate) fn from_evidence(
        evidence: &NinjaOneDeviceResultEvidence,
        registration: &NinjaOneRegistration,
    ) -> Self {
        Self {
            evidence_digest: evidence.digest().clone(),
            registration_digest: registration.registration_digest().clone(),
            projection_digest: Digest::from_serializable(&evidence.projection),
            provenance: evidence.provenance,
            durable: false,
            raw_provider_payload_retained: false,
            raw_activity_log_retained: false,
            credential_material_serialized: false,
            raw_pii_retained: false,
            native_receipt: false,
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

// Keep these imports and constants anchored in this root so contract drift is
// caught by the compiler even when a host does not call validate_contract.
const _: &str = CONTRACT_VERSION;
const _: &str = PLUGIN_ID;
const _: &str = PROVIDER_ID;
const _: usize = MAX_PATCHES;
const _: usize = MAX_RECEIPTS;

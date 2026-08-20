use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    str::FromStr,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};

use crate::{
    MISSION_PLANETSCALE_BRANCH_RESULT_CONSUMER_ID, PLANETSCALE_BRANCH_RESULT_CONTRACT_VERSION,
    PLANETSCALE_BRANCH_RESULT_SCHEMA_VERSION, PLANETSCALE_PLUGIN_ID, PLANETSCALE_PROVIDER_ID,
    PLANETSCALE_SERVICE_ID, error::InputViolation, error::PlanetScaleBranchResultError,
};

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_CURSOR_BYTES: usize = 512;
pub const MAX_IDEMPOTENCY_BYTES: usize = 256;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_ITEMS: u16 = 100;
pub const MAX_RESPONSE_BYTES: u32 = 1_048_576;
pub const MAX_RETRY_AFTER_MS: u64 = 300_000;

/// A lowercase SHA-256 digest used for every immutable Layer 1 fence.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    #[must_use]
    ///
    /// # Panics
    ///
    /// Panics only if a typed value supplied by this crate violates its
    /// Serialize implementation. All contract-owned values are serializable.
    pub fn from_serializable<T: Serialize + ?Sized>(value: &T) -> Self {
        let bytes = serde_json::to_vec(value).expect("PlanetScale typed value serializes");
        Self::from_bytes(&bytes)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self, field: &'static str) -> Result<(), PlanetScaleBranchResultError> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(PlanetScaleBranchResultError::InvalidDigest { field })
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
        self.0.fmt(formatter)
    }
}

#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest::from_bytes(bytes)
}

#[must_use]
pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    Digest::from_serializable(value)
}

macro_rules! identifier_type {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, PlanetScaleBranchResultError> {
                let value = value.into();
                validate_identifier(&value, $field)?;
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn validate(&self) -> Result<(), PlanetScaleBranchResultError> {
                Self::new(self.0.clone()).map(|_| ())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = PlanetScaleBranchResultError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }
    };
}

identifier_type!(OrganizationId, "organization_id");
identifier_type!(DatabaseId, "database_id");
identifier_type!(BranchId, "branch_id");
identifier_type!(DeployRequestId, "deploy_request_id");
identifier_type!(SchemaId, "schema_id");
identifier_type!(ProjectId, "project_id");
identifier_type!(MissionId, "mission_id");
identifier_type!(WorkProductId, "work_product_id");
identifier_type!(ConsentId, "consent_id");

/// A non-zero monotonic revision used by Project, Mission, Work Product, and
/// consent fences.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, PlanetScaleBranchResultError> {
        if value == 0 {
            Err(PlanetScaleBranchResultError::InvalidInput {
                field: "revision",
                reason: InputViolation::OutOfRange,
            })
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityBinding {
    id: String,
    revision: Revision,
}

impl IdentityBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, PlanetScaleBranchResultError> {
        Ok(Self {
            id: id.into(),
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn validate(&self, field: &'static str) -> Result<(), PlanetScaleBranchResultError> {
        validate_identifier(&self.id, field)?;
        if self.revision.get() == 0 {
            return Err(PlanetScaleBranchResultError::InvalidInput {
                field,
                reason: InputViolation::OutOfRange,
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

pub type ProjectBinding = IdentityBinding;
pub type MissionBinding = IdentityBinding;
pub type WorkProductBinding = IdentityBinding;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentAction {
    InspectBranchDeployPosture,
    ProposeNextDataDeliveryStep,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentBinding {
    pub id: ConsentId,
    pub revision: Revision,
    pub action: ConsentAction,
}

impl ConsentBinding {
    pub fn new(
        id: ConsentId,
        revision: u64,
        action: ConsentAction,
    ) -> Result<Self, PlanetScaleBranchResultError> {
        let consent = Self {
            id,
            revision: Revision::new(revision)?,
            action,
        };
        consent.validate()?;
        Ok(consent)
    }

    pub fn validate(&self) -> Result<(), PlanetScaleBranchResultError> {
        self.id.validate()?;
        if self.revision.get() == 0 {
            return Err(PlanetScaleBranchResultError::InvalidInput {
                field: "consent.revision",
                reason: InputViolation::OutOfRange,
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

/// Exact external and Hartevo scope carried by every request, proposal,
/// observation, record, and Mission result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlanetScaleScope {
    pub organization_id: OrganizationId,
    pub database_id: DatabaseId,
    pub branch_id: BranchId,
    pub deploy_request_id: DeployRequestId,
    pub schema_id: SchemaId,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub consent: ConsentBinding,
}

impl PlanetScaleScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        organization_id: OrganizationId,
        database_id: DatabaseId,
        branch_id: BranchId,
        deploy_request_id: DeployRequestId,
        schema_id: SchemaId,
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        consent: ConsentBinding,
    ) -> Result<Self, PlanetScaleBranchResultError> {
        let scope = Self {
            organization_id,
            database_id,
            branch_id,
            deploy_request_id,
            schema_id,
            project,
            mission,
            work_product,
            consent,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), PlanetScaleBranchResultError> {
        self.organization_id.validate()?;
        self.database_id.validate()?;
        self.branch_id.validate()?;
        self.deploy_request_id.validate()?;
        self.schema_id.validate()?;
        self.project.validate("project.id")?;
        self.mission.validate("mission.id")?;
        self.work_product.validate("work_product.id")?;
        self.consent.validate()?;
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    #[must_use]
    pub fn revision_fence(&self) -> RevisionFence {
        RevisionFence {
            project_revision: self.project.revision(),
            mission_revision: self.mission.revision(),
            work_product_revision: self.work_product.revision(),
            consent_revision: self.consent.revision,
        }
    }
}

pub type PlanetScaleBranchResultScope = PlanetScaleScope;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevisionFence {
    pub project_revision: Revision,
    pub mission_revision: Revision,
    pub work_product_revision: Revision,
    pub consent_revision: Revision,
}

impl RevisionFence {
    pub fn validate(&self) -> Result<(), PlanetScaleBranchResultError> {
        for (field, revision) in [
            ("project_revision", self.project_revision),
            ("mission_revision", self.mission_revision),
            ("work_product_revision", self.work_product_revision),
            ("consent_revision", self.consent_revision),
        ] {
            if revision.get() == 0 {
                return Err(PlanetScaleBranchResultError::InvalidInput {
                    field,
                    reason: InputViolation::InvalidRevisionFence,
                });
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

/// Opaque keyring/secret-manager identity. It intentionally does not
/// implement Serialize or Deserialize; Debug exposes only its digest.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    reference_id: String,
    scope_digest: Digest,
    credential_revision: Revision,
}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope: &PlanetScaleScope,
        credential_revision: u64,
    ) -> Result<Self, PlanetScaleBranchResultError> {
        Self::for_scope(scope, reference_id, credential_revision)
    }

    pub fn for_scope(
        scope: &PlanetScaleScope,
        reference_id: impl Into<String>,
        credential_revision: u64,
    ) -> Result<Self, PlanetScaleBranchResultError> {
        let reference_id = reference_id.into();
        validate_opaque_reference(&reference_id)?;
        scope.validate()?;
        let credential_revision = Revision::new(credential_revision)?;
        Ok(Self {
            reference_id,
            scope_digest: scope.digest(),
            credential_revision,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(&(
            &self.reference_id,
            &self.scope_digest,
            self.credential_revision,
        ))
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    pub fn validate_for(
        &self,
        scope: &PlanetScaleScope,
    ) -> Result<(), PlanetScaleBranchResultError> {
        validate_opaque_reference(&self.reference_id)?;
        scope.validate()?;
        if self.scope_digest != scope.digest() {
            return Err(PlanetScaleBranchResultError::ScopeMismatch {
                field: "secret_reference.scope_digest",
            });
        }
        if self.credential_revision.get() == 0 {
            return Err(PlanetScaleBranchResultError::InvalidInput {
                field: "secret_reference.credential_revision",
                reason: InputViolation::OutOfRange,
            });
        }
        Ok(())
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.digest())
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NativeStatus {
    BlockedEnv,
}

impl NativeStatus {
    #[must_use]
    pub const fn is_native(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_connected(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    Fixture,
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

impl EvidenceSource {
    #[must_use]
    pub const fn is_native(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportMode {
    Fixture,
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

impl TransportMode {
    #[must_use]
    pub const fn is_native(self) -> bool {
        false
    }

    #[must_use]
    pub const fn evidence_source(self) -> EvidenceSource {
        match self {
            Self::Fixture => EvidenceSource::Fixture,
            Self::Recording => EvidenceSource::Recording,
            Self::Fake => EvidenceSource::Fake,
            Self::Loopback => EvidenceSource::Loopback,
            Self::BlockedEnv => EvidenceSource::BlockedEnv,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl PluginVersion {
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    pub fn validate(self) -> Result<(), PlanetScaleBranchResultError> {
        if self.major == 0 {
            Err(PlanetScaleBranchResultError::InvalidInput {
                field: "provider_version",
                reason: InputViolation::OutOfRange,
            })
        } else {
            Ok(())
        }
    }
}

impl fmt::Display for PluginVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

pub const PROVIDER_VERSION: PluginVersion = PluginVersion::new(1, 0, 0);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanetScaleCapability {
    CapabilityProbe,
    BranchPostureRead,
    DeployPostureRead,
    SchemaMetadataRead,
    BranchPostureProposal,
    DeployPostureProposal,
    SchemaMetadataProposal,
    RedactedRecord,
    DigestFencing,
    CursorFencing,
    IdempotencyFencing,
    ReversibleRegistration,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlanetScaleProviderManifest {
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_id: String,
    pub provider_id: String,
    pub service_id: String,
    pub consumer_id: String,
    pub api_revision: String,
    pub version: PluginVersion,
    pub scope: PlanetScaleScope,
    pub capabilities: BTreeSet<PlanetScaleCapability>,
    pub transport_mode: TransportMode,
    pub native_status: NativeStatus,
    pub manifest_digest: Digest,
}

#[derive(Serialize)]
struct ManifestIdentity<'a> {
    schema_version: &'a str,
    contract_version: &'a str,
    plugin_id: &'a str,
    provider_id: &'a str,
    service_id: &'a str,
    consumer_id: &'a str,
    api_revision: &'a str,
    version: PluginVersion,
    scope: &'a PlanetScaleScope,
    capabilities: &'a BTreeSet<PlanetScaleCapability>,
    transport_mode: TransportMode,
    native_status: NativeStatus,
}

impl PlanetScaleProviderManifest {
    pub fn layer1(
        scope: PlanetScaleScope,
        transport_mode: TransportMode,
    ) -> Result<Self, PlanetScaleBranchResultError> {
        scope.validate()?;
        let capabilities = [
            PlanetScaleCapability::CapabilityProbe,
            PlanetScaleCapability::BranchPostureRead,
            PlanetScaleCapability::DeployPostureRead,
            PlanetScaleCapability::SchemaMetadataRead,
            PlanetScaleCapability::BranchPostureProposal,
            PlanetScaleCapability::DeployPostureProposal,
            PlanetScaleCapability::SchemaMetadataProposal,
            PlanetScaleCapability::RedactedRecord,
            PlanetScaleCapability::DigestFencing,
            PlanetScaleCapability::CursorFencing,
            PlanetScaleCapability::IdempotencyFencing,
            PlanetScaleCapability::ReversibleRegistration,
        ]
        .into_iter()
        .collect();
        let mut manifest = Self {
            schema_version: PLANETSCALE_BRANCH_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: PLANETSCALE_BRANCH_RESULT_CONTRACT_VERSION.to_owned(),
            plugin_id: PLANETSCALE_PLUGIN_ID.to_owned(),
            provider_id: PLANETSCALE_PROVIDER_ID.to_owned(),
            service_id: PLANETSCALE_SERVICE_ID.to_owned(),
            consumer_id: MISSION_PLANETSCALE_BRANCH_RESULT_CONSUMER_ID.to_owned(),
            api_revision: crate::PLANETSCALE_API_REVISION.to_owned(),
            version: PROVIDER_VERSION,
            scope,
            capabilities,
            transport_mode,
            native_status: NativeStatus::BlockedEnv,
            manifest_digest: Digest::from_bytes(&[]),
        };
        manifest.manifest_digest = manifest.calculate_digest();
        manifest.validate()?;
        Ok(manifest)
    }

    fn identity(&self) -> ManifestIdentity<'_> {
        ManifestIdentity {
            schema_version: &self.schema_version,
            contract_version: &self.contract_version,
            plugin_id: &self.plugin_id,
            provider_id: &self.provider_id,
            service_id: &self.service_id,
            consumer_id: &self.consumer_id,
            api_revision: &self.api_revision,
            version: self.version,
            scope: &self.scope,
            capabilities: &self.capabilities,
            transport_mode: self.transport_mode,
            native_status: self.native_status,
        }
    }

    #[must_use]
    pub fn calculate_digest(&self) -> Digest {
        canonical_digest(&self.identity())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.manifest_digest.clone()
    }

    pub fn validate(&self) -> Result<(), PlanetScaleBranchResultError> {
        if self.schema_version != PLANETSCALE_BRANCH_RESULT_SCHEMA_VERSION {
            return Err(PlanetScaleBranchResultError::ProviderManifestMismatch {
                field: "schema_version",
            });
        }
        if self.contract_version != PLANETSCALE_BRANCH_RESULT_CONTRACT_VERSION {
            return Err(PlanetScaleBranchResultError::ProviderManifestMismatch {
                field: "contract_version",
            });
        }
        if self.plugin_id != PLANETSCALE_PLUGIN_ID
            || self.provider_id != PLANETSCALE_PROVIDER_ID
            || self.service_id != PLANETSCALE_SERVICE_ID
            || self.consumer_id != MISSION_PLANETSCALE_BRANCH_RESULT_CONSUMER_ID
            || self.api_revision != crate::PLANETSCALE_API_REVISION
        {
            return Err(PlanetScaleBranchResultError::ProviderManifestMismatch {
                field: "provider_identity",
            });
        }
        self.version.validate()?;
        self.scope.validate()?;
        if self.capabilities.is_empty()
            || !self
                .capabilities
                .contains(&PlanetScaleCapability::BranchPostureRead)
            || !self
                .capabilities
                .contains(&PlanetScaleCapability::RedactedRecord)
        {
            return Err(PlanetScaleBranchResultError::InvalidInput {
                field: "capabilities",
                reason: InputViolation::OutOfRange,
            });
        }
        if self.native_status.is_native() || self.transport_mode.is_native() {
            return Err(PlanetScaleBranchResultError::NativeAuthority);
        }
        self.manifest_digest.validate("manifest_digest")?;
        if self.manifest_digest != self.calculate_digest() {
            return Err(PlanetScaleBranchResultError::DigestMismatch {
                field: "manifest_digest",
            });
        }
        Ok(())
    }
}

pub type PlanetScaleBranchResultProviderManifest = PlanetScaleProviderManifest;

/// Registration contains the opaque reference only in memory; all receipts
/// use its digest and never serialize the handle.
#[derive(Clone, Eq, PartialEq)]
pub struct PlanetScaleRegistration {
    pub manifest: PlanetScaleProviderManifest,
    pub scope: PlanetScaleScope,
    pub(crate) secret_reference: SecretReference,
    pub consent_digest: Digest,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub revoked: bool,
}

impl fmt::Debug for PlanetScaleRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PlanetScaleRegistration")
            .field("manifest_digest", &self.manifest.manifest_digest)
            .field("scope_digest", &self.scope.digest())
            .field("consent_digest", &self.consent_digest)
            .field("secret_reference", &self.secret_reference)
            .field("registration_digest", &self.registration_digest)
            .field("registration_revision", &self.registration_revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Serialize)]
struct RegistrationIdentity<'a> {
    manifest_digest: &'a Digest,
    provider_version: PluginVersion,
    scope_digest: Digest,
    consent_digest: &'a Digest,
    secret_reference_digest: Digest,
    registration_revision: Revision,
}

impl PlanetScaleRegistration {
    pub fn new(
        manifest: PlanetScaleProviderManifest,
        scope: PlanetScaleScope,
        secret_reference: SecretReference,
        registration_revision: u64,
    ) -> Result<Self, PlanetScaleBranchResultError> {
        manifest.validate()?;
        scope.validate()?;
        if manifest.scope != scope {
            return Err(PlanetScaleBranchResultError::ScopeMismatch {
                field: "registration.scope",
            });
        }
        secret_reference.validate_for(&scope)?;
        let registration_revision = Revision::new(registration_revision)?;
        let mut registration = Self {
            manifest,
            scope,
            consent_digest: Digest::from_bytes(&[]),
            secret_reference,
            registration_digest: Digest::from_bytes(&[]),
            registration_revision,
            revoked: false,
        };
        registration.consent_digest = registration.scope.consent.digest();
        registration.registration_digest = registration.calculate_digest();
        registration.validate()?;
        Ok(registration)
    }

    fn calculate_digest(&self) -> Digest {
        canonical_digest(&RegistrationIdentity {
            manifest_digest: &self.manifest.manifest_digest,
            provider_version: self.manifest.version,
            scope_digest: self.scope.digest(),
            consent_digest: &self.consent_digest,
            secret_reference_digest: self.secret_reference.digest(),
            registration_revision: self.registration_revision,
        })
    }

    #[must_use]
    pub fn secret_reference_digest(&self) -> Digest {
        self.secret_reference.digest()
    }

    #[must_use]
    pub fn scope_digest(&self) -> Digest {
        self.scope.digest()
    }

    pub fn validate(&self) -> Result<(), PlanetScaleBranchResultError> {
        self.manifest.validate()?;
        self.scope.validate()?;
        if self.manifest.scope != self.scope {
            return Err(PlanetScaleBranchResultError::ScopeMismatch {
                field: "registration.scope",
            });
        }
        self.secret_reference.validate_for(&self.scope)?;
        if self.consent_digest != self.scope.consent.digest() {
            return Err(PlanetScaleBranchResultError::ConsentMismatch {
                field: "registration.consent_digest",
            });
        }
        if self.registration_revision.get() == 0 {
            return Err(PlanetScaleBranchResultError::RegistrationStale);
        }
        self.registration_digest.validate("registration_digest")?;
        if self.registration_digest != self.calculate_digest() {
            return Err(PlanetScaleBranchResultError::DigestMismatch {
                field: "registration_digest",
            });
        }
        Ok(())
    }

    pub fn ensure_active(&self) -> Result<(), PlanetScaleBranchResultError> {
        self.validate()?;
        if self.revoked {
            Err(PlanetScaleBranchResultError::RegistrationRevoked)
        } else {
            Ok(())
        }
    }

    pub fn revoke(&mut self) -> Result<(), PlanetScaleBranchResultError> {
        self.validate()?;
        self.revoked = true;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), PlanetScaleBranchResultError> {
        self.validate()?;
        self.revoked = false;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationReceipt {
    pub schema_version: String,
    pub plugin_id: String,
    pub provider_id: String,
    pub service_id: String,
    pub consumer_id: String,
    pub provider_version: PluginVersion,
    pub scope_digest: Digest,
    pub consent_digest: Digest,
    pub manifest_digest: Digest,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub registry_revision: Revision,
    pub active: bool,
    pub native_status: NativeStatus,
}

impl RegistrationReceipt {
    pub fn from_registration(
        registration: &PlanetScaleRegistration,
        registry_revision: u64,
    ) -> Result<Self, PlanetScaleBranchResultError> {
        registration.validate()?;
        let receipt = Self {
            schema_version: PLANETSCALE_BRANCH_RESULT_SCHEMA_VERSION.to_owned(),
            plugin_id: registration.manifest.plugin_id.clone(),
            provider_id: registration.manifest.provider_id.clone(),
            service_id: registration.manifest.service_id.clone(),
            consumer_id: registration.manifest.consumer_id.clone(),
            provider_version: registration.manifest.version,
            scope_digest: registration.scope.digest(),
            consent_digest: registration.consent_digest.clone(),
            manifest_digest: registration.manifest.digest(),
            registration_digest: registration.registration_digest.clone(),
            registration_revision: registration.registration_revision,
            registry_revision: Revision::new(registry_revision)?,
            active: !registration.revoked,
            native_status: NativeStatus::BlockedEnv,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn validate(&self) -> Result<(), PlanetScaleBranchResultError> {
        if self.schema_version != PLANETSCALE_BRANCH_RESULT_SCHEMA_VERSION
            || self.plugin_id != PLANETSCALE_PLUGIN_ID
            || self.provider_id != PLANETSCALE_PROVIDER_ID
            || self.service_id != PLANETSCALE_SERVICE_ID
            || self.consumer_id != MISSION_PLANETSCALE_BRANCH_RESULT_CONSUMER_ID
        {
            return Err(PlanetScaleBranchResultError::RegistrationMismatch);
        }
        self.provider_version.validate()?;
        self.scope_digest.validate("registration.scope_digest")?;
        self.consent_digest
            .validate("registration.consent_digest")?;
        self.manifest_digest
            .validate("registration.manifest_digest")?;
        self.registration_digest
            .validate("registration.registration_digest")?;
        if self.registration_revision.get() == 0
            || self.registry_revision.get() == 0
            || self.native_status.is_native()
        {
            return Err(PlanetScaleBranchResultError::RegistrationStale);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct PlanetScaleRegistrationRegistry {
    registrations: BTreeMap<Digest, PlanetScaleRegistration>,
    next_revision: u64,
}

impl PlanetScaleRegistrationRegistry {
    pub fn register(
        &mut self,
        registration: PlanetScaleRegistration,
    ) -> Result<RegistrationReceipt, PlanetScaleBranchResultError> {
        registration.ensure_active()?;
        if self
            .registrations
            .contains_key(&registration.registration_digest)
        {
            return Err(PlanetScaleBranchResultError::RegistrationAlreadyExists);
        }
        self.next_revision = self
            .next_revision
            .checked_add(1)
            .ok_or(PlanetScaleBranchResultError::RegistrationStale)?;
        let receipt = RegistrationReceipt::from_registration(&registration, self.next_revision)?;
        self.registrations
            .insert(registration.registration_digest.clone(), registration);
        Ok(receipt)
    }

    pub fn unregister(
        &mut self,
        receipt: &RegistrationReceipt,
    ) -> Result<RegistrationReceipt, PlanetScaleBranchResultError> {
        receipt.validate()?;
        let mut registration = self
            .registrations
            .remove(&receipt.registration_digest)
            .ok_or(PlanetScaleBranchResultError::RegistrationUnknown)?;
        if registration.manifest.digest() != receipt.manifest_digest
            || registration.scope.digest() != receipt.scope_digest
            || registration.consent_digest != receipt.consent_digest
        {
            return Err(PlanetScaleBranchResultError::RegistrationMismatch);
        }
        registration.revoke()?;
        self.next_revision = self
            .next_revision
            .checked_add(1)
            .ok_or(PlanetScaleBranchResultError::RegistrationStale)?;
        RegistrationReceipt::from_registration(&registration, self.next_revision)
    }

    #[must_use]
    pub fn active(&self, registration_digest: &Digest) -> bool {
        self.registrations
            .get(registration_digest)
            .is_some_and(|registration| !registration.revoked)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PostureRead {
    Branch,
    Deploy,
    Schema,
    BranchDeploySchema,
}

impl PostureRead {
    pub fn validate(self) -> Result<(), PlanetScaleBranchResultError> {
        Ok(())
    }

    #[must_use]
    pub const fn proposal_label(self) -> &'static str {
        match self {
            Self::Branch => "branch_posture",
            Self::Deploy => "deploy_posture",
            Self::Schema => "schema_metadata",
            Self::BranchDeploySchema => "branch_deploy_schema_posture",
        }
    }
}

/// Opaque pagination token. Requests carry only its digest.
#[derive(Clone, Eq, PartialEq)]
pub struct PageCursor {
    token: String,
}

impl PageCursor {
    pub fn new(token: impl Into<String>) -> Result<Self, PlanetScaleBranchResultError> {
        let token = token.into();
        if token.is_empty() {
            return Err(PlanetScaleBranchResultError::InvalidInput {
                field: "cursor",
                reason: InputViolation::Empty,
            });
        }
        if token.len() > MAX_CURSOR_BYTES || token.chars().any(char::is_control) {
            return Err(PlanetScaleBranchResultError::InvalidInput {
                field: "cursor",
                reason: InputViolation::InvalidCursor,
            });
        }
        Ok(Self { token })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        sha256_digest(self.token.as_bytes())
    }
}

impl fmt::Debug for PageCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PageCursor")
            .field("cursor_digest", &self.digest())
            .finish_non_exhaustive()
    }
}

/// Opaque replay/idempotency input. Proposals carry only its digest.
#[derive(Clone, Eq, PartialEq)]
pub struct IdempotencyKey {
    value: String,
}

impl IdempotencyKey {
    pub fn new(value: impl Into<String>) -> Result<Self, PlanetScaleBranchResultError> {
        let value = value.into();
        if value.is_empty() {
            return Err(PlanetScaleBranchResultError::InvalidInput {
                field: "idempotency_key",
                reason: InputViolation::Empty,
            });
        }
        if value.len() > MAX_IDEMPOTENCY_BYTES || value.chars().any(char::is_control) {
            return Err(PlanetScaleBranchResultError::InvalidInput {
                field: "idempotency_key",
                reason: InputViolation::InvalidIdempotencyKey,
            });
        }
        Ok(Self { value })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        sha256_digest(self.value.as_bytes())
    }
}

impl fmt::Debug for IdempotencyKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdempotencyKey")
            .field("key_digest", &self.digest())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PostureRequest {
    pub scope: PlanetScaleScope,
    pub read: PostureRead,
    pub page_size: u16,
    pub cursor_digest: Option<Digest>,
    pub revision_fence: RevisionFence,
    pub consent_digest: Digest,
    pub secret_reference_digest: Digest,
    pub provider_manifest_digest: Digest,
    pub idempotency_digest: Digest,
    pub request_digest: Digest,
}

#[derive(Serialize)]
struct PostureRequestIdentity<'a> {
    scope: &'a PlanetScaleScope,
    read: PostureRead,
    page_size: u16,
    cursor_digest: &'a Option<Digest>,
    revision_fence: &'a RevisionFence,
    consent_digest: &'a Digest,
    secret_reference_digest: &'a Digest,
    provider_manifest_digest: &'a Digest,
    idempotency_digest: &'a Digest,
}

impl PostureRequest {
    pub fn new(
        scope: PlanetScaleScope,
        read: PostureRead,
        page_size: u16,
        cursor: Option<&PageCursor>,
        idempotency_key: &IdempotencyKey,
        secret_reference: &SecretReference,
        provider_manifest_digest: Digest,
    ) -> Result<Self, PlanetScaleBranchResultError> {
        scope.validate()?;
        read.validate()?;
        if page_size == 0 || page_size > MAX_PAGE_SIZE {
            return Err(PlanetScaleBranchResultError::InvalidInput {
                field: "page_size",
                reason: InputViolation::OutOfRange,
            });
        }
        secret_reference.validate_for(&scope)?;
        provider_manifest_digest.validate("provider_manifest_digest")?;
        let cursor_digest = cursor.map(PageCursor::digest);
        if let Some(digest) = &cursor_digest {
            digest.validate("cursor_digest")?;
        }
        let revision_fence = scope.revision_fence();
        revision_fence.validate()?;
        let consent_digest = scope.consent.digest();
        let secret_reference_digest = secret_reference.digest();
        let idempotency_digest = idempotency_key.digest();
        let mut request = Self {
            scope,
            read,
            page_size,
            cursor_digest,
            revision_fence,
            consent_digest,
            secret_reference_digest,
            provider_manifest_digest,
            idempotency_digest,
            request_digest: Digest::from_bytes(&[]),
        };
        request.request_digest = request.calculate_digest();
        request.validate()?;
        Ok(request)
    }

    fn identity(&self) -> PostureRequestIdentity<'_> {
        PostureRequestIdentity {
            scope: &self.scope,
            read: self.read,
            page_size: self.page_size,
            cursor_digest: &self.cursor_digest,
            revision_fence: &self.revision_fence,
            consent_digest: &self.consent_digest,
            secret_reference_digest: &self.secret_reference_digest,
            provider_manifest_digest: &self.provider_manifest_digest,
            idempotency_digest: &self.idempotency_digest,
        }
    }

    #[must_use]
    pub fn calculate_digest(&self) -> Digest {
        canonical_digest(&self.identity())
    }

    pub fn validate(&self) -> Result<(), PlanetScaleBranchResultError> {
        self.scope.validate()?;
        self.read.validate()?;
        if self.page_size == 0 || self.page_size > MAX_PAGE_SIZE {
            return Err(PlanetScaleBranchResultError::InvalidInput {
                field: "page_size",
                reason: InputViolation::OutOfRange,
            });
        }
        self.revision_fence.validate()?;
        if self.revision_fence != self.scope.revision_fence() {
            return Err(PlanetScaleBranchResultError::RevisionMismatch {
                field: "request.revision_fence",
            });
        }
        if self.consent_digest != self.scope.consent.digest() {
            return Err(PlanetScaleBranchResultError::ConsentMismatch {
                field: "request.consent_digest",
            });
        }
        self.cursor_digest
            .as_ref()
            .map_or(Ok(()), |digest| digest.validate("cursor_digest"))?;
        self.secret_reference_digest
            .validate("secret_reference_digest")?;
        self.provider_manifest_digest
            .validate("provider_manifest_digest")?;
        self.idempotency_digest.validate("idempotency_digest")?;
        self.request_digest.validate("request_digest")?;
        if self.request_digest != self.calculate_digest() {
            return Err(PlanetScaleBranchResultError::DigestMismatch {
                field: "request_digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BranchStatus {
    Ready,
    Creating,
    Archived,
    Deleted,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeployStatus {
    None,
    Queued,
    Running,
    Succeeded,
    Failed,
    Canceled,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaStatus {
    NotRequested,
    Available,
    Changed,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PostureObservation {
    pub scope: PlanetScaleScope,
    pub read: PostureRead,
    pub branch_status: BranchStatus,
    pub deploy_status: DeployStatus,
    pub schema_status: SchemaStatus,
    pub observed_branch_digest: Digest,
    pub observed_deploy_digest: Digest,
    pub observed_schema_digest: Digest,
    pub branch_revision: Revision,
    pub deploy_revision: Revision,
    pub schema_revision: Revision,
    pub item_count: u16,
    pub response_bytes: u32,
    pub response_digest: Digest,
    pub next_cursor_digest: Option<Digest>,
    pub source: EvidenceSource,
    pub native_status: NativeStatus,
}

#[derive(Serialize)]
struct ObservationIdentity<'a> {
    scope: &'a PlanetScaleScope,
    read: PostureRead,
    branch_status: BranchStatus,
    deploy_status: DeployStatus,
    schema_status: SchemaStatus,
    observed_branch_digest: &'a Digest,
    observed_deploy_digest: &'a Digest,
    observed_schema_digest: &'a Digest,
    branch_revision: Revision,
    deploy_revision: Revision,
    schema_revision: Revision,
    item_count: u16,
    response_bytes: u32,
    next_cursor_digest: &'a Option<Digest>,
    source: EvidenceSource,
    native_status: NativeStatus,
}

impl PostureObservation {
    pub fn new(
        scope: PlanetScaleScope,
        read: PostureRead,
        branch_status: BranchStatus,
        deploy_status: DeployStatus,
        schema_status: SchemaStatus,
        item_count: u16,
        response_bytes: u32,
        source: EvidenceSource,
    ) -> Result<Self, PlanetScaleBranchResultError> {
        scope.validate()?;
        read.validate()?;
        if item_count > MAX_ITEMS || response_bytes > MAX_RESPONSE_BYTES {
            return Err(PlanetScaleBranchResultError::InvalidInput {
                field: "observation.bounds",
                reason: InputViolation::OutOfRange,
            });
        }
        let revision = Revision::new(1)?;
        let observed_branch_digest =
            canonical_digest(&(&scope.branch_id, branch_status, scope.project.revision()));
        let observed_deploy_digest = canonical_digest(&(
            &scope.deploy_request_id,
            deploy_status,
            scope.mission.revision(),
        ));
        let observed_schema_digest = canonical_digest(&(
            &scope.schema_id,
            schema_status,
            scope.work_product.revision(),
        ));
        let mut observation = Self {
            scope,
            read,
            branch_status,
            deploy_status,
            schema_status,
            observed_branch_digest,
            observed_deploy_digest,
            observed_schema_digest,
            branch_revision: revision,
            deploy_revision: revision,
            schema_revision: revision,
            item_count,
            response_bytes,
            response_digest: Digest::from_bytes(&[]),
            next_cursor_digest: None,
            source,
            native_status: NativeStatus::BlockedEnv,
        };
        observation.response_digest = observation.calculate_response_digest();
        observation.validate()?;
        Ok(observation)
    }

    pub fn fixture(
        scope: PlanetScaleScope,
        read: PostureRead,
    ) -> Result<Self, PlanetScaleBranchResultError> {
        Self::new(
            scope,
            read,
            BranchStatus::Ready,
            DeployStatus::Succeeded,
            SchemaStatus::Available,
            3,
            512,
            EvidenceSource::Fixture,
        )
    }

    fn calculate_response_digest(&self) -> Digest {
        canonical_digest(&ObservationIdentity {
            scope: &self.scope,
            read: self.read,
            branch_status: self.branch_status,
            deploy_status: self.deploy_status,
            schema_status: self.schema_status,
            observed_branch_digest: &self.observed_branch_digest,
            observed_deploy_digest: &self.observed_deploy_digest,
            observed_schema_digest: &self.observed_schema_digest,
            branch_revision: self.branch_revision,
            deploy_revision: self.deploy_revision,
            schema_revision: self.schema_revision,
            item_count: self.item_count,
            response_bytes: self.response_bytes,
            next_cursor_digest: &self.next_cursor_digest,
            source: self.source,
            native_status: self.native_status,
        })
    }

    #[must_use]
    pub fn posture_digest(&self) -> Digest {
        canonical_digest(&(
            &self.observed_branch_digest,
            &self.observed_deploy_digest,
            &self.observed_schema_digest,
            self.branch_status,
            self.deploy_status,
            self.schema_status,
        ))
    }

    pub fn validate(&self) -> Result<(), PlanetScaleBranchResultError> {
        self.scope.validate()?;
        self.read.validate()?;
        for (field, digest) in [
            ("observed_branch_digest", &self.observed_branch_digest),
            ("observed_deploy_digest", &self.observed_deploy_digest),
            ("observed_schema_digest", &self.observed_schema_digest),
            ("response_digest", &self.response_digest),
        ] {
            digest.validate(field)?;
        }
        if let Some(digest) = &self.next_cursor_digest {
            digest.validate("next_cursor_digest")?;
        }
        if self.branch_revision.get() == 0
            || self.deploy_revision.get() == 0
            || self.schema_revision.get() == 0
            || self.item_count > MAX_ITEMS
            || self.response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(PlanetScaleBranchResultError::InvalidInput {
                field: "observation.bounds",
                reason: InputViolation::OutOfRange,
            });
        }
        if self.native_status.is_native() || self.source.is_native() {
            return Err(PlanetScaleBranchResultError::NativeAuthority);
        }
        if self.response_digest != self.calculate_response_digest() {
            return Err(PlanetScaleBranchResultError::DigestMismatch {
                field: "observation.response_digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Complete,
    Denied,
    Partial,
    Stale,
    AccessLost,
    RateLimited,
    ProviderUnknown,
    Tampered,
    Revoked,
}

impl EvidenceState {
    #[must_use]
    pub const fn is_verified(self) -> bool {
        matches!(self, Self::Complete)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    PermissionDenied,
    NotFound,
    Conflict,
    RateLimited,
    TimedOut,
    ProviderUnknown,
    BlockedEnv,
    MalformedResponse,
    ResponseTooLarge,
    RegistrationRevoked,
    StaleRevision,
    Tampered,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BranchResultProposal {
    pub schema_version: String,
    pub contract_version: String,
    pub scope: PlanetScaleScope,
    pub read: PostureRead,
    pub intent: ProposalIntent,
    pub request: PostureRequest,
    pub revision_fence: RevisionFence,
    pub provider_version: PluginVersion,
    pub provider_manifest_digest: Digest,
    pub registration_digest: Digest,
    pub consent_digest: Digest,
    pub idempotency_digest: Digest,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub proposal_digest: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalIntent {
    InspectBranchDeployPosture,
    ProposeNextDataDeliveryStep,
}

#[derive(Serialize)]
struct ProposalIdentity<'a> {
    schema_version: &'a str,
    contract_version: &'a str,
    scope: &'a PlanetScaleScope,
    read: PostureRead,
    intent: ProposalIntent,
    request_digest: &'a Digest,
    revision_fence: &'a RevisionFence,
    provider_version: PluginVersion,
    provider_manifest_digest: &'a Digest,
    registration_digest: &'a Digest,
    consent_digest: &'a Digest,
    idempotency_digest: &'a Digest,
    proposal_only: bool,
    connected: bool,
    native: bool,
}

impl BranchResultProposal {
    pub fn new(
        request: PostureRequest,
        intent: ProposalIntent,
        manifest: &PlanetScaleProviderManifest,
        registration: &PlanetScaleRegistration,
    ) -> Result<Self, PlanetScaleBranchResultError> {
        request.validate()?;
        manifest.validate()?;
        registration.ensure_active()?;
        if request.scope != registration.scope || request.scope != manifest.scope {
            return Err(PlanetScaleBranchResultError::ScopeMismatch {
                field: "proposal.scope",
            });
        }
        if request.provider_manifest_digest != manifest.digest() {
            return Err(PlanetScaleBranchResultError::ProviderManifestMismatch {
                field: "proposal.provider_manifest_digest",
            });
        }
        if request.consent_digest != registration.consent_digest {
            return Err(PlanetScaleBranchResultError::ConsentMismatch {
                field: "proposal.consent_digest",
            });
        }
        let revision_fence = request.revision_fence.clone();
        let mut proposal = Self {
            schema_version: PLANETSCALE_BRANCH_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: PLANETSCALE_BRANCH_RESULT_CONTRACT_VERSION.to_owned(),
            scope: request.scope.clone(),
            read: request.read,
            intent,
            request,
            revision_fence,
            provider_version: manifest.version,
            provider_manifest_digest: manifest.digest(),
            registration_digest: registration.registration_digest.clone(),
            consent_digest: registration.consent_digest.clone(),
            idempotency_digest: registration.scope.digest().clone(),
            proposal_only: true,
            connected: false,
            native: false,
            proposal_digest: Digest::from_bytes(&[]),
        };
        proposal.idempotency_digest = proposal.request.idempotency_digest.clone();
        proposal.proposal_digest = proposal.calculate_digest();
        proposal.validate()?;
        Ok(proposal)
    }

    fn calculate_digest(&self) -> Digest {
        canonical_digest(&ProposalIdentity {
            schema_version: &self.schema_version,
            contract_version: &self.contract_version,
            scope: &self.scope,
            read: self.read,
            intent: self.intent,
            request_digest: &self.request.request_digest,
            revision_fence: &self.revision_fence,
            provider_version: self.provider_version,
            provider_manifest_digest: &self.provider_manifest_digest,
            registration_digest: &self.registration_digest,
            consent_digest: &self.consent_digest,
            idempotency_digest: &self.idempotency_digest,
            proposal_only: self.proposal_only,
            connected: self.connected,
            native: self.native,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.proposal_digest.clone()
    }

    pub fn validate(&self) -> Result<(), PlanetScaleBranchResultError> {
        if self.schema_version != PLANETSCALE_BRANCH_RESULT_SCHEMA_VERSION
            || self.contract_version != PLANETSCALE_BRANCH_RESULT_CONTRACT_VERSION
        {
            return Err(PlanetScaleBranchResultError::ProviderManifestMismatch {
                field: "proposal.version",
            });
        }
        self.scope.validate()?;
        self.request.validate()?;
        if self.scope != self.request.scope || self.read != self.request.read {
            return Err(PlanetScaleBranchResultError::ScopeMismatch {
                field: "proposal.request",
            });
        }
        if self.revision_fence != self.scope.revision_fence() {
            return Err(PlanetScaleBranchResultError::RevisionMismatch {
                field: "proposal.revision_fence",
            });
        }
        if self.consent_digest != self.scope.consent.digest()
            || self.idempotency_digest != self.request.idempotency_digest
        {
            return Err(PlanetScaleBranchResultError::ConsentMismatch {
                field: "proposal.fence",
            });
        }
        self.provider_manifest_digest
            .validate("proposal.provider_manifest_digest")?;
        self.registration_digest
            .validate("proposal.registration_digest")?;
        if !self.proposal_only || self.connected || self.native {
            return Err(PlanetScaleBranchResultError::NativeAuthority);
        }
        self.proposal_digest.validate("proposal_digest")?;
        if self.proposal_digest != self.calculate_digest() {
            return Err(PlanetScaleBranchResultError::DigestMismatch {
                field: "proposal_digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BranchResultEvidence {
    pub state: EvidenceState,
    pub failure: Option<FailureKind>,
    pub scope_digest: Digest,
    pub revision_fence_digest: Digest,
    pub consent_digest: Digest,
    pub request_digest: Digest,
    pub idempotency_digest: Digest,
    pub provider_version: PluginVersion,
    pub provider_manifest_digest: Digest,
    pub registration_digest: Digest,
    pub read: PostureRead,
    pub branch_status: Option<BranchStatus>,
    pub deploy_status: Option<DeployStatus>,
    pub schema_status: Option<SchemaStatus>,
    pub observed_branch_digest: Option<Digest>,
    pub observed_deploy_digest: Option<Digest>,
    pub observed_schema_digest: Option<Digest>,
    pub posture_digest: Option<Digest>,
    pub response_digest: Option<Digest>,
    pub item_count: u16,
    pub response_bytes: u32,
    pub source: EvidenceSource,
    pub native_status: NativeStatus,
    pub connected: bool,
    pub native: bool,
    pub evidence_digest: Digest,
}

#[derive(Serialize)]
struct EvidenceIdentity<'a> {
    state: EvidenceState,
    failure: Option<FailureKind>,
    scope_digest: &'a Digest,
    revision_fence_digest: &'a Digest,
    consent_digest: &'a Digest,
    request_digest: &'a Digest,
    idempotency_digest: &'a Digest,
    provider_version: PluginVersion,
    provider_manifest_digest: &'a Digest,
    registration_digest: &'a Digest,
    read: PostureRead,
    branch_status: Option<BranchStatus>,
    deploy_status: Option<DeployStatus>,
    schema_status: Option<SchemaStatus>,
    observed_branch_digest: &'a Option<Digest>,
    observed_deploy_digest: &'a Option<Digest>,
    observed_schema_digest: &'a Option<Digest>,
    posture_digest: &'a Option<Digest>,
    response_digest: &'a Option<Digest>,
    item_count: u16,
    response_bytes: u32,
    source: EvidenceSource,
    native_status: NativeStatus,
    connected: bool,
    native: bool,
}

impl BranchResultEvidence {
    pub fn from_observation(
        proposal: &BranchResultProposal,
        observation: &PostureObservation,
    ) -> Result<Self, PlanetScaleBranchResultError> {
        proposal.validate()?;
        observation.validate()?;
        if observation.scope != proposal.scope || observation.read != proposal.read {
            return Err(PlanetScaleBranchResultError::ScopeMismatch {
                field: "evidence.observation",
            });
        }
        let mut evidence = Self {
            state: EvidenceState::Complete,
            failure: None,
            scope_digest: proposal.scope.digest(),
            revision_fence_digest: proposal.revision_fence.digest(),
            consent_digest: proposal.consent_digest.clone(),
            request_digest: proposal.request.request_digest.clone(),
            idempotency_digest: proposal.idempotency_digest.clone(),
            provider_version: proposal.provider_version,
            provider_manifest_digest: proposal.provider_manifest_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            read: proposal.read,
            branch_status: Some(observation.branch_status),
            deploy_status: Some(observation.deploy_status),
            schema_status: Some(observation.schema_status),
            observed_branch_digest: Some(observation.observed_branch_digest.clone()),
            observed_deploy_digest: Some(observation.observed_deploy_digest.clone()),
            observed_schema_digest: Some(observation.observed_schema_digest.clone()),
            posture_digest: Some(observation.posture_digest()),
            response_digest: Some(observation.response_digest.clone()),
            item_count: observation.item_count,
            response_bytes: observation.response_bytes,
            source: observation.source,
            native_status: NativeStatus::BlockedEnv,
            connected: false,
            native: false,
            evidence_digest: Digest::from_bytes(&[]),
        };
        evidence.evidence_digest = evidence.calculate_digest();
        evidence.validate_against(proposal)?;
        Ok(evidence)
    }

    pub fn failure(
        proposal: &BranchResultProposal,
        state: EvidenceState,
        failure: FailureKind,
        source: EvidenceSource,
    ) -> Result<Self, PlanetScaleBranchResultError> {
        proposal.validate()?;
        let mut evidence = Self {
            state,
            failure: Some(failure),
            scope_digest: proposal.scope.digest(),
            revision_fence_digest: proposal.revision_fence.digest(),
            consent_digest: proposal.consent_digest.clone(),
            request_digest: proposal.request.request_digest.clone(),
            idempotency_digest: proposal.idempotency_digest.clone(),
            provider_version: proposal.provider_version,
            provider_manifest_digest: proposal.provider_manifest_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            read: proposal.read,
            branch_status: None,
            deploy_status: None,
            schema_status: None,
            observed_branch_digest: None,
            observed_deploy_digest: None,
            observed_schema_digest: None,
            posture_digest: None,
            response_digest: None,
            item_count: 0,
            response_bytes: 0,
            source,
            native_status: NativeStatus::BlockedEnv,
            connected: false,
            native: false,
            evidence_digest: Digest::from_bytes(&[]),
        };
        evidence.evidence_digest = evidence.calculate_digest();
        evidence.validate_against(proposal)?;
        Ok(evidence)
    }

    fn calculate_digest(&self) -> Digest {
        canonical_digest(&EvidenceIdentity {
            state: self.state,
            failure: self.failure,
            scope_digest: &self.scope_digest,
            revision_fence_digest: &self.revision_fence_digest,
            consent_digest: &self.consent_digest,
            request_digest: &self.request_digest,
            idempotency_digest: &self.idempotency_digest,
            provider_version: self.provider_version,
            provider_manifest_digest: &self.provider_manifest_digest,
            registration_digest: &self.registration_digest,
            read: self.read,
            branch_status: self.branch_status,
            deploy_status: self.deploy_status,
            schema_status: self.schema_status,
            observed_branch_digest: &self.observed_branch_digest,
            observed_deploy_digest: &self.observed_deploy_digest,
            observed_schema_digest: &self.observed_schema_digest,
            posture_digest: &self.posture_digest,
            response_digest: &self.response_digest,
            item_count: self.item_count,
            response_bytes: self.response_bytes,
            source: self.source,
            native_status: self.native_status,
            connected: self.connected,
            native: self.native,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.evidence_digest.clone()
    }

    pub fn validate_against(
        &self,
        proposal: &BranchResultProposal,
    ) -> Result<(), PlanetScaleBranchResultError> {
        proposal.validate()?;
        self.scope_digest.validate("evidence.scope_digest")?;
        self.revision_fence_digest
            .validate("evidence.revision_fence_digest")?;
        self.consent_digest.validate("evidence.consent_digest")?;
        self.request_digest.validate("evidence.request_digest")?;
        self.idempotency_digest
            .validate("evidence.idempotency_digest")?;
        self.provider_manifest_digest
            .validate("evidence.provider_manifest_digest")?;
        self.registration_digest
            .validate("evidence.registration_digest")?;
        if self.scope_digest != proposal.scope.digest()
            || self.revision_fence_digest != proposal.revision_fence.digest()
            || self.consent_digest != proposal.consent_digest
            || self.request_digest != proposal.request.request_digest
            || self.idempotency_digest != proposal.idempotency_digest
            || self.provider_manifest_digest != proposal.provider_manifest_digest
            || self.registration_digest != proposal.registration_digest
            || self.read != proposal.read
        {
            return Err(PlanetScaleBranchResultError::ReceiptMismatch {
                field: "evidence.fences",
            });
        }
        for digest in [
            &self.observed_branch_digest,
            &self.observed_deploy_digest,
            &self.observed_schema_digest,
            &self.posture_digest,
            &self.response_digest,
        ]
        .into_iter()
        .flatten()
        {
            digest.validate("evidence.observation_digest")?;
        }
        if self.item_count > MAX_ITEMS
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.native_status.is_native()
            || self.source.is_native()
            || self.connected
            || self.native
        {
            return Err(PlanetScaleBranchResultError::NativeAuthority);
        }
        self.evidence_digest.validate("evidence_digest")?;
        if self.evidence_digest != self.calculate_digest() {
            return Err(PlanetScaleBranchResultError::DigestMismatch {
                field: "evidence_digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BranchResultRecord {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub scope_digest: Digest,
    pub idempotency_digest: Digest,
    pub posture_digest: Option<Digest>,
    pub response_digest: Option<Digest>,
    pub state: EvidenceState,
    pub failure: Option<FailureKind>,
    pub source: EvidenceSource,
    pub native_status: NativeStatus,
    pub connected: bool,
    pub native: bool,
    pub record_digest: Digest,
}

impl BranchResultRecord {
    pub fn from_evidence(
        proposal: &BranchResultProposal,
        evidence: &BranchResultEvidence,
    ) -> Result<Self, PlanetScaleBranchResultError> {
        evidence.validate_against(proposal)?;
        let mut record = Self {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            scope_digest: evidence.scope_digest.clone(),
            idempotency_digest: evidence.idempotency_digest.clone(),
            posture_digest: evidence.posture_digest.clone(),
            response_digest: evidence.response_digest.clone(),
            state: evidence.state,
            failure: evidence.failure,
            source: evidence.source,
            native_status: NativeStatus::BlockedEnv,
            connected: false,
            native: false,
            record_digest: Digest::from_bytes(&[]),
        };
        record.record_digest = canonical_digest(&(
            &record.proposal_digest,
            &record.evidence_digest,
            &record.scope_digest,
            &record.idempotency_digest,
            &record.posture_digest,
            &record.response_digest,
            record.state,
            record.failure,
            record.source,
            record.native_status,
            record.connected,
            record.native,
        ));
        Ok(record)
    }

    pub fn validate_against(
        &self,
        proposal: &BranchResultProposal,
        evidence: &BranchResultEvidence,
    ) -> Result<(), PlanetScaleBranchResultError> {
        proposal.validate()?;
        evidence.validate_against(proposal)?;
        if self.proposal_digest != proposal.proposal_digest
            || self.evidence_digest != evidence.evidence_digest
            || self.scope_digest != proposal.scope.digest()
            || self.idempotency_digest != proposal.idempotency_digest
            || self.state != evidence.state
            || self.failure != evidence.failure
            || self.source != evidence.source
            || self.posture_digest != evidence.posture_digest
            || self.response_digest != evidence.response_digest
        {
            return Err(PlanetScaleBranchResultError::ReceiptMismatch {
                field: "record.fences",
            });
        }
        if self.native_status.is_native() || self.connected || self.native {
            return Err(PlanetScaleBranchResultError::NativeAuthority);
        }
        self.record_digest.validate("record_digest")?;
        let expected = canonical_digest(&(
            &self.proposal_digest,
            &self.evidence_digest,
            &self.scope_digest,
            &self.idempotency_digest,
            &self.posture_digest,
            &self.response_digest,
            self.state,
            self.failure,
            self.source,
            self.native_status,
            self.connected,
            self.native,
        ));
        if self.record_digest != expected {
            return Err(PlanetScaleBranchResultError::TamperedReceipt);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BranchResultReceipt {
    pub schema_version: String,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub record_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub idempotency_digest: Digest,
    pub state: EvidenceState,
    pub source: EvidenceSource,
    pub response_digest: Option<Digest>,
    pub native_status: NativeStatus,
    pub connected: bool,
    pub native: bool,
    pub independent_record: bool,
    pub receipt_digest: Digest,
}

impl BranchResultReceipt {
    pub fn from_record(
        proposal: &BranchResultProposal,
        evidence: &BranchResultEvidence,
        record: &BranchResultRecord,
    ) -> Result<Self, PlanetScaleBranchResultError> {
        record.validate_against(proposal, evidence)?;
        let mut receipt = Self {
            schema_version: PLANETSCALE_BRANCH_RESULT_SCHEMA_VERSION.to_owned(),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            record_digest: record.record_digest.clone(),
            scope_digest: proposal.scope.digest(),
            registration_digest: proposal.registration_digest.clone(),
            idempotency_digest: proposal.idempotency_digest.clone(),
            state: evidence.state,
            source: evidence.source,
            response_digest: evidence.response_digest.clone(),
            native_status: NativeStatus::BlockedEnv,
            connected: false,
            native: false,
            independent_record: true,
            receipt_digest: Digest::from_bytes(&[]),
        };
        receipt.receipt_digest = receipt.calculate_digest();
        receipt.validate_against(proposal, evidence, record)?;
        Ok(receipt)
    }

    fn calculate_digest(&self) -> Digest {
        canonical_digest(&(
            &self.schema_version,
            &self.proposal_digest,
            &self.evidence_digest,
            &self.record_digest,
            &self.scope_digest,
            &self.registration_digest,
            &self.idempotency_digest,
            self.state,
            self.source,
            &self.response_digest,
            self.native_status,
            self.connected,
            self.native,
            self.independent_record,
        ))
    }

    pub fn validate_against(
        &self,
        proposal: &BranchResultProposal,
        evidence: &BranchResultEvidence,
        record: &BranchResultRecord,
    ) -> Result<(), PlanetScaleBranchResultError> {
        if self.schema_version != PLANETSCALE_BRANCH_RESULT_SCHEMA_VERSION {
            return Err(PlanetScaleBranchResultError::ProviderManifestMismatch {
                field: "receipt.schema_version",
            });
        }
        record.validate_against(proposal, evidence)?;
        if self.proposal_digest != proposal.proposal_digest
            || self.evidence_digest != evidence.evidence_digest
            || self.record_digest != record.record_digest
            || self.scope_digest != proposal.scope.digest()
            || self.registration_digest != proposal.registration_digest
            || self.idempotency_digest != proposal.idempotency_digest
            || self.state != evidence.state
            || self.source != evidence.source
            || self.response_digest != evidence.response_digest
            || !self.independent_record
            || self.native_status.is_native()
            || self.connected
            || self.native
        {
            return Err(PlanetScaleBranchResultError::ReceiptMismatch {
                field: "receipt.fences",
            });
        }
        self.receipt_digest.validate("receipt_digest")?;
        if self.receipt_digest != self.calculate_digest() {
            return Err(PlanetScaleBranchResultError::TamperedReceipt);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationResult {
    pub verified: bool,
    pub state: EvidenceState,
    pub receipt_digest: Digest,
}

impl VerificationResult {
    #[must_use]
    pub const fn is_verified(&self) -> bool {
        self.verified
    }
}

fn validate_identifier(
    value: &str,
    field: &'static str,
) -> Result<(), PlanetScaleBranchResultError> {
    if value.is_empty() {
        return Err(PlanetScaleBranchResultError::InvalidInput {
            field,
            reason: InputViolation::Empty,
        });
    }
    if value.len() > MAX_IDENTIFIER_BYTES {
        return Err(PlanetScaleBranchResultError::InvalidInput {
            field,
            reason: InputViolation::TooLong,
        });
    }
    if value.trim() != value
        || value.chars().any(char::is_control)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-/$".contains(&byte))
    {
        return Err(PlanetScaleBranchResultError::InvalidInput {
            field,
            reason: InputViolation::InvalidIdentifier,
        });
    }
    Ok(())
}

fn validate_opaque_reference(value: &str) -> Result<(), PlanetScaleBranchResultError> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES {
        return Err(PlanetScaleBranchResultError::InvalidInput {
            field: "secret_reference",
            reason: if value.is_empty() {
                InputViolation::Empty
            } else {
                InputViolation::TooLong
            },
        });
    }
    if value.chars().any(char::is_control) {
        return Err(PlanetScaleBranchResultError::InvalidInput {
            field: "secret_reference",
            reason: InputViolation::InvalidCharacters,
        });
    }
    Ok(())
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

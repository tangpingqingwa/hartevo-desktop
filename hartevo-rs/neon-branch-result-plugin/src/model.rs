use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    str::FromStr,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};

use crate::error::{InputViolation, NeonBranchResultError};

/// Versioned contract/schema identifier for this Layer 1 root.
pub const NEON_BRANCH_RESULT_SCHEMA_VERSION: &str = "hartevo.neon-branch-result/v1";
/// Issue-specific contract version.
pub const NEON_BRANCH_RESULT_CONTRACT_VERSION: &str = "EXT-NEON-01-L1/v1";
/// Stable plugin identifier.
pub const PLUGIN_ID: &str = "hartevo.neon-branch-result";
/// Stable provider identifier.
pub const PROVIDER_ID: &str = "neon.branch-result";
/// Stable service identifier.
pub const SERVICE_ID: &str = "neon-branch-result.service";
/// Stable Mission consumer identifier.
pub const CONSUMER_ID: &str = "mission.database-result.consumer";
/// Layer 1 provider/API version.
pub const PROVIDER_VERSION: PluginVersion = PluginVersion::new(1, 0, 0);
/// Maximum bytes accepted for a query shape.
pub const MAX_QUERY_BYTES: usize = 8 * 1024;
/// Maximum positional parameters accepted by a query proposal.
pub const MAX_QUERY_PARAMETERS: usize = 32;
/// Maximum result rows accepted by a query proposal.
pub const MAX_RESULT_ROWS: u32 = 10_000;
/// Maximum result bytes accepted by a query proposal.
pub const MAX_RESULT_BYTES: u64 = 4 * 1024 * 1024;
/// Maximum query timeout accepted by a query proposal.
pub const MAX_QUERY_TIMEOUT_MS: u64 = 30_000;
/// Maximum number of retry attempts represented by a Layer 1 policy.
pub const MAX_QUERY_ATTEMPTS: u8 = 5;
/// Maximum retry delay represented by a Layer 1 policy.
pub const MAX_BACKOFF_MS: u64 = 60_000;
/// Maximum identifier bytes accepted by all typed identity wrappers.
pub const MAX_IDENTIFIER_BYTES: usize = 128;
/// Maximum textual parameter or schema value size.
pub const MAX_VALUE_BYTES: usize = 16 * 1024;

const FORBIDDEN_SQL_TOKENS: &[&str] = &[
    "alter",
    "analyze",
    "analyse",
    "call",
    "commit",
    "copy",
    "create",
    "delete",
    "do",
    "drop",
    "grant",
    "insert",
    "listen",
    "lock",
    "notify",
    "refresh",
    "reindex",
    "release",
    "reset",
    "revoke",
    "rollback",
    "savepoint",
    "set",
    "truncate",
    "update",
    "vacuum",
    "pg_sleep",
    "dblink",
];

/// A lowercase SHA-256 digest used for all immutable fences.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    /// Hash bytes without retaining the original bytes.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    /// Hash a typed value using deterministic serde field order.
    pub fn from_serializable<T: Serialize + ?Sized>(value: &T) -> Self {
        let bytes = serde_json::to_vec(value).expect("Neon contract values serialize");
        Self::from_bytes(&bytes)
    }

    /// Borrow the lowercase hexadecimal digest.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Validate the digest at a named contract boundary.
    pub fn validate(&self, field: &'static str) -> Result<(), NeonBranchResultError> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(NeonBranchResultError::InvalidDigest { field })
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

/// Hash a typed value into the contract digest format.
pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    Digest::from_serializable(value)
}

/// Hash bytes into the contract digest format.
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest::from_bytes(bytes)
}

macro_rules! identifier_type {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Construct a bounded, non-empty identity value.
            pub fn new(value: impl Into<String>) -> Result<Self, NeonBranchResultError> {
                let value = value.into();
                validate_identifier(&value, $field)?;
                Ok(Self(value))
            }

            /// Borrow the identity value.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Validate a deserialized identity value.
            pub fn validate(&self) -> Result<(), NeonBranchResultError> {
                Self::new(self.0.clone()).map(|_| ())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = NeonBranchResultError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }
    };
}

identifier_type!(OrganizationId, "organization_id");
identifier_type!(ProjectId, "project_id");
identifier_type!(MissionId, "mission_id");
identifier_type!(BranchId, "branch_id");
identifier_type!(EndpointId, "endpoint_id");
identifier_type!(DatabaseName, "database");
identifier_type!(RoleName, "role");
identifier_type!(SourceResultId, "source_result_id");

/// Version carried by manifests, registrations, proposals, and receipts.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl PluginVersion {
    /// Construct a semantic plugin version.
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Validate that a version is non-zero.
    pub fn validate(&self) -> Result<(), NeonBranchResultError> {
        if self.major == 0 {
            Err(NeonBranchResultError::InvalidInput {
                field: "version",
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

/// Layer 1 never produces native/Connected evidence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NativeStatus {
    BlockedEnv,
}

impl NativeStatus {
    /// Native status is always false for this Layer 1 crate.
    pub const fn is_native(self) -> bool {
        false
    }

    /// Connected status is deliberately not represented by this enum.
    pub const fn is_connected(self) -> bool {
        false
    }
}

/// Evidence provenance used by fixture and loopback recordings.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    Recording,
    Fixture,
    Loopback,
    BlockedEnv,
}

impl EvidenceSource {
    /// Fixture, loopback, and blocked-environment evidence is never native.
    pub const fn is_native(self) -> bool {
        false
    }
}

/// Transport mode exposed by a provider seam. No mode is a native connection.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportMode {
    Fixture,
    Loopback,
    BlockedEnv,
}

impl TransportMode {
    /// Transport modes in Layer 1 never claim native execution.
    pub const fn is_native(self) -> bool {
        false
    }
}

/// The two independently replaceable provider transport seams.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportSeam {
    NeonControlPlane,
    PostgresQuery,
}

/// Query transport protocol metadata. HTTP is a seam, not a native claim.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryTransportProtocol {
    Postgres,
    Http,
}

/// Typed provider capability advertised by the versioned manifest.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NeonCapability {
    CapabilityProbe,
    BranchProposal,
    ParameterizedSelect,
    ParameterizedExplain,
    QueryReceipt,
    ResultAdoptionProposal,
    DigestFencing,
    ReversibleRegistration,
}

/// Exact point at which the child branch is proposed or queried.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BranchPoint {
    Head,
    Timestamp { value: String },
    Lsn { value: String },
}

impl BranchPoint {
    /// Construct the current branch head point.
    pub const fn head() -> Self {
        Self::Head
    }

    /// Construct a bounded point-in-time timestamp identity. Parsing and
    /// provider-side timestamp lookup remain Layer 2 responsibilities.
    pub fn timestamp(value: impl Into<String>) -> Result<Self, NeonBranchResultError> {
        let point = Self::Timestamp {
            value: value.into(),
        };
        point.validate()?;
        Ok(point)
    }

    /// Construct a bounded log-sequence-number identity.
    pub fn lsn(value: impl Into<String>) -> Result<Self, NeonBranchResultError> {
        let point = Self::Lsn {
            value: value.into(),
        };
        point.validate()?;
        Ok(point)
    }

    /// Validate the point identity without contacting Neon.
    pub fn validate(&self) -> Result<(), NeonBranchResultError> {
        match self {
            Self::Head => Ok(()),
            Self::Timestamp { value } => validate_branch_point_token(value, "timestamp"),
            Self::Lsn { value } => validate_branch_point_token(value, "lsn"),
        }
    }

    /// Digest the exact point identity.
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

/// The exact Neon and Mission scope shared by every proposal and receipt.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NeonScope {
    pub organization_id: OrganizationId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub parent_branch_id: BranchId,
    pub branch_id: BranchId,
    pub endpoint_id: EndpointId,
    pub database: DatabaseName,
    pub role: RoleName,
}

impl NeonScope {
    /// Construct an exact organization/project/Mission/branch/endpoint/
    /// database/role scope. Branch names are intentionally not accepted.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        organization_id: OrganizationId,
        project_id: ProjectId,
        mission_id: MissionId,
        parent_branch_id: BranchId,
        branch_id: BranchId,
        endpoint_id: EndpointId,
        database: DatabaseName,
        role: RoleName,
    ) -> Result<Self, NeonBranchResultError> {
        let scope = Self {
            organization_id,
            project_id,
            mission_id,
            parent_branch_id,
            branch_id,
            endpoint_id,
            database,
            role,
        };
        scope.validate()?;
        Ok(scope)
    }

    /// Validate every identity and parent/child distinction.
    pub fn validate(&self) -> Result<(), NeonBranchResultError> {
        self.organization_id.validate()?;
        self.project_id.validate()?;
        self.mission_id.validate()?;
        self.parent_branch_id.validate()?;
        self.branch_id.validate()?;
        self.endpoint_id.validate()?;
        self.database.validate()?;
        self.role.validate()?;
        if self.parent_branch_id == self.branch_id {
            return Err(NeonBranchResultError::InvalidInput {
                field: "branch_id",
                reason: InputViolation::InvalidIdentifier,
            });
        }
        Ok(())
    }

    /// Digest the complete scope fence.
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    /// Create the branch/point-in-time fence used by query receipts.
    pub fn branch_fence(
        &self,
        point_in_time: BranchPoint,
    ) -> Result<BranchFence, NeonBranchResultError> {
        BranchFence::new(self.clone(), point_in_time)
    }
}

/// Alias that makes the ownership boundary explicit at call sites.
pub type NeonBranchResultScope = NeonScope;

/// Digest-only branch and point-in-time identity fence.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BranchFence {
    pub scope: NeonScope,
    pub point_in_time: BranchPoint,
    pub branch_digest: Digest,
    pub point_in_time_digest: Digest,
}

impl BranchFence {
    /// Construct and digest the exact scope/point pair.
    pub fn new(
        scope: NeonScope,
        point_in_time: BranchPoint,
    ) -> Result<Self, NeonBranchResultError> {
        scope.validate()?;
        point_in_time.validate()?;
        let fence = Self {
            branch_digest: scope.digest(),
            point_in_time_digest: point_in_time.digest(),
            scope,
            point_in_time,
        };
        fence.validate()?;
        Ok(fence)
    }

    /// Validate the embedded identity and both digest fences.
    pub fn validate(&self) -> Result<(), NeonBranchResultError> {
        self.scope.validate()?;
        self.point_in_time.validate()?;
        self.branch_digest.validate("branch_digest")?;
        self.point_in_time_digest.validate("point_in_time_digest")?;
        if self.branch_digest != self.scope.digest() {
            return Err(NeonBranchResultError::DigestMismatch {
                field: "branch_digest",
            });
        }
        if self.point_in_time_digest != self.point_in_time.digest() {
            return Err(NeonBranchResultError::DigestMismatch {
                field: "point_in_time_digest",
            });
        }
        Ok(())
    }

    /// Digest the full fence.
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

/// Opaque provider-bound secret identity. The reference is never serialized,
/// exposed as text, or resolved into credentials by this crate.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    reference_id: String,
    scope_digest: Digest,
    credential_revision: u64,
}

impl SecretReference {
    /// Bind a keyring/secret-manager reference to the exact Neon scope.
    pub fn for_scope(
        reference_id: impl Into<String>,
        scope: &NeonScope,
        credential_revision: u64,
    ) -> Result<Self, NeonBranchResultError> {
        let reference_id = reference_id.into();
        validate_identifier(&reference_id, "secret_reference")?;
        if credential_revision == 0 {
            return Err(NeonBranchResultError::InvalidInput {
                field: "credential_revision",
                reason: InputViolation::OutOfRange,
            });
        }
        scope.validate()?;
        Ok(Self {
            reference_id,
            scope_digest: scope.digest(),
            credential_revision,
        })
    }

    /// Return only the digest of the opaque reference identity.
    pub fn digest(&self) -> Digest {
        canonical_digest(&(
            &self.reference_id,
            &self.scope_digest,
            self.credential_revision,
        ))
    }

    /// Return the scope digest without exposing the reference identifier.
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    /// Return the keyring credential revision.
    pub const fn credential_revision(&self) -> u64 {
        self.credential_revision
    }

    /// Validate an opaque reference against the exact scope.
    pub fn validate_for(&self, scope: &NeonScope) -> Result<(), NeonBranchResultError> {
        validate_identifier(&self.reference_id, "secret_reference")?;
        scope.validate()?;
        if self.scope_digest != scope.digest() {
            return Err(NeonBranchResultError::ScopeMismatch {
                field: "secret_reference.scope_digest",
            });
        }
        if self.credential_revision == 0 {
            return Err(NeonBranchResultError::InvalidInput {
                field: "credential_revision",
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

/// Versioned, scope-bound provider manifest. It contains no secret material.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NeonProviderManifest {
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_id: String,
    pub provider_id: String,
    pub service_id: String,
    pub consumer_id: String,
    pub version: PluginVersion,
    pub scope: NeonScope,
    pub capabilities: BTreeSet<NeonCapability>,
    pub control_plane_mode: TransportMode,
    pub query_transport_mode: TransportMode,
    pub query_transport_protocol: QueryTransportProtocol,
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
    version: PluginVersion,
    scope: &'a NeonScope,
    capabilities: &'a BTreeSet<NeonCapability>,
    control_plane_mode: TransportMode,
    query_transport_mode: TransportMode,
    query_transport_protocol: QueryTransportProtocol,
    native_status: NativeStatus,
}

impl NeonProviderManifest {
    /// Construct the deterministic fixture manifest for a scope.
    pub fn layer1(scope: NeonScope) -> Result<Self, NeonBranchResultError> {
        Self::layer1_with_modes(scope, TransportMode::Fixture, QueryTransportProtocol::Http)
    }

    /// Construct a Layer 1 manifest with explicit non-native seam metadata.
    pub fn layer1_with_modes(
        scope: NeonScope,
        query_transport_mode: TransportMode,
        query_transport_protocol: QueryTransportProtocol,
    ) -> Result<Self, NeonBranchResultError> {
        scope.validate()?;
        let capabilities = [
            NeonCapability::CapabilityProbe,
            NeonCapability::BranchProposal,
            NeonCapability::ParameterizedSelect,
            NeonCapability::ParameterizedExplain,
            NeonCapability::QueryReceipt,
            NeonCapability::ResultAdoptionProposal,
            NeonCapability::DigestFencing,
            NeonCapability::ReversibleRegistration,
        ]
        .into_iter()
        .collect();
        let mut manifest = Self {
            schema_version: NEON_BRANCH_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: NEON_BRANCH_RESULT_CONTRACT_VERSION.to_owned(),
            plugin_id: PLUGIN_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            version: PROVIDER_VERSION,
            scope,
            capabilities,
            control_plane_mode: TransportMode::Fixture,
            query_transport_mode,
            query_transport_protocol,
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
            version: self.version,
            scope: &self.scope,
            capabilities: &self.capabilities,
            control_plane_mode: self.control_plane_mode,
            query_transport_mode: self.query_transport_mode,
            query_transport_protocol: self.query_transport_protocol,
            native_status: self.native_status,
        }
    }

    /// Calculate the digest of immutable manifest contents.
    pub fn calculate_digest(&self) -> Digest {
        canonical_digest(&self.identity())
    }

    /// Return the immutable manifest digest.
    pub fn digest(&self) -> Digest {
        self.manifest_digest.clone()
    }

    /// Validate version, scope, capability, transport, and digest bindings.
    pub fn validate(&self) -> Result<(), NeonBranchResultError> {
        if self.schema_version != NEON_BRANCH_RESULT_SCHEMA_VERSION {
            return Err(NeonBranchResultError::ProviderManifestMismatch {
                field: "schema_version",
            });
        }
        if self.contract_version != NEON_BRANCH_RESULT_CONTRACT_VERSION {
            return Err(NeonBranchResultError::ProviderManifestMismatch {
                field: "contract_version",
            });
        }
        if self.plugin_id != PLUGIN_ID {
            return Err(NeonBranchResultError::ProviderManifestMismatch { field: "plugin_id" });
        }
        if self.provider_id != PROVIDER_ID {
            return Err(NeonBranchResultError::ProviderManifestMismatch {
                field: "provider_id",
            });
        }
        if self.service_id != SERVICE_ID {
            return Err(NeonBranchResultError::ProviderManifestMismatch {
                field: "service_id",
            });
        }
        if self.consumer_id != CONSUMER_ID {
            return Err(NeonBranchResultError::ProviderManifestMismatch {
                field: "consumer_id",
            });
        }
        self.version.validate()?;
        self.scope.validate()?;
        if self.capabilities.is_empty()
            || !self.capabilities.contains(&NeonCapability::CapabilityProbe)
            || !self.capabilities.contains(&NeonCapability::QueryReceipt)
        {
            return Err(NeonBranchResultError::InvalidInput {
                field: "capabilities",
                reason: InputViolation::OutOfRange,
            });
        }
        if self.native_status.is_native()
            || self.native_status.is_connected()
            || self.control_plane_mode.is_native()
            || self.query_transport_mode.is_native()
        {
            return Err(NeonBranchResultError::NativeAuthority);
        }
        self.manifest_digest.validate("manifest_digest")?;
        if self.manifest_digest != self.calculate_digest() {
            return Err(NeonBranchResultError::DigestMismatch {
                field: "manifest_digest",
            });
        }
        Ok(())
    }

    /// Produce the default manifest-only registration digest.
    pub fn registration_digest(&self) -> Digest {
        registration_digest_for_manifest(self)
    }
}

/// Alias used by callers that prefer the longer contract name.
pub type NeonBranchResultProviderManifest = NeonProviderManifest;

/// Opaque provider registration bound to version, manifest digest, scope, and
/// a keyring reference. Revocation is monotonic and does not erase history.
#[derive(Clone, Eq, PartialEq)]
pub struct NeonProviderRegistration {
    pub manifest: NeonProviderManifest,
    pub scope: NeonScope,
    secret_reference: SecretReference,
    pub registration_digest: Digest,
    pub revoked: bool,
}

impl fmt::Debug for NeonProviderRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NeonProviderRegistration")
            .field("manifest_digest", &self.manifest.manifest_digest)
            .field("scope_digest", &self.scope.digest())
            .field("secret_reference", &self.secret_reference)
            .field("registration_digest", &self.registration_digest)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Serialize)]
struct RegistrationIdentity<'a> {
    manifest_digest: &'a Digest,
    provider_version: PluginVersion,
    scope: &'a NeonScope,
    secret_reference_digest: Digest,
}

impl NeonProviderRegistration {
    /// Create a version/digest/scope-bound registration without resolving a
    /// secret or contacting Neon.
    pub fn new(
        manifest: NeonProviderManifest,
        scope: NeonScope,
        secret_reference: SecretReference,
    ) -> Result<Self, NeonBranchResultError> {
        manifest.validate()?;
        scope.validate()?;
        if manifest.scope != scope {
            return Err(NeonBranchResultError::ScopeMismatch {
                field: "registration.scope",
            });
        }
        secret_reference.validate_for(&scope)?;
        let mut registration = Self {
            manifest,
            scope,
            secret_reference,
            registration_digest: Digest::from_bytes(&[]),
            revoked: false,
        };
        registration.registration_digest = registration.calculate_digest();
        registration.validate()?;
        Ok(registration)
    }

    fn calculate_digest(&self) -> Digest {
        canonical_digest(&RegistrationIdentity {
            manifest_digest: &self.manifest.manifest_digest,
            provider_version: self.manifest.version,
            scope: &self.scope,
            secret_reference_digest: self.secret_reference.digest(),
        })
    }

    /// Return a digest-only view of the secret reference.
    pub fn secret_reference_digest(&self) -> Digest {
        self.secret_reference.digest()
    }

    /// Validate registration identity and its scope binding.
    pub fn validate(&self) -> Result<(), NeonBranchResultError> {
        self.manifest.validate()?;
        self.scope.validate()?;
        if self.manifest.scope != self.scope {
            return Err(NeonBranchResultError::ScopeMismatch {
                field: "registration.scope",
            });
        }
        self.secret_reference.validate_for(&self.scope)?;
        self.registration_digest.validate("registration_digest")?;
        if self.registration_digest != self.calculate_digest() {
            return Err(NeonBranchResultError::DigestMismatch {
                field: "registration_digest",
            });
        }
        Ok(())
    }

    /// Fail closed if the registration has been revoked.
    pub fn ensure_active(&self) -> Result<(), NeonBranchResultError> {
        self.validate()?;
        if self.revoked {
            Err(NeonBranchResultError::RegistrationRevoked)
        } else {
            Ok(())
        }
    }

    /// Revoke the registration; repeated revocation is idempotent.
    pub fn revoke(&mut self) -> Result<(), NeonBranchResultError> {
        self.validate()?;
        self.revoked = true;
        Ok(())
    }
}

/// Digest-only registration receipt suitable for registry composition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationReceipt {
    pub schema_version: String,
    pub plugin_id: String,
    pub provider_id: String,
    pub service_id: String,
    pub consumer_id: String,
    pub version: PluginVersion,
    pub scope_digest: Digest,
    pub manifest_digest: Digest,
    pub registration_digest: Digest,
    pub registry_revision: u64,
    pub active: bool,
    pub native_status: NativeStatus,
}

impl RegistrationReceipt {
    /// Build a receipt without copying the opaque reference.
    pub fn from_registration(
        registration: &NeonProviderRegistration,
        registry_revision: u64,
    ) -> Result<Self, NeonBranchResultError> {
        registration.validate()?;
        if registry_revision == 0 {
            return Err(NeonBranchResultError::RegistrationStale);
        }
        let receipt = Self {
            schema_version: NEON_BRANCH_RESULT_SCHEMA_VERSION.to_owned(),
            plugin_id: registration.manifest.plugin_id.clone(),
            provider_id: registration.manifest.provider_id.clone(),
            service_id: registration.manifest.service_id.clone(),
            consumer_id: registration.manifest.consumer_id.clone(),
            version: registration.manifest.version,
            scope_digest: registration.scope.digest(),
            manifest_digest: registration.manifest.digest(),
            registration_digest: registration.registration_digest.clone(),
            registry_revision,
            active: !registration.revoked,
            native_status: NativeStatus::BlockedEnv,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// Validate the digest-only registration receipt.
    pub fn validate(&self) -> Result<(), NeonBranchResultError> {
        if self.schema_version != NEON_BRANCH_RESULT_SCHEMA_VERSION {
            return Err(NeonBranchResultError::ProviderManifestMismatch {
                field: "registration.schema_version",
            });
        }
        if self.plugin_id != PLUGIN_ID
            || self.provider_id != PROVIDER_ID
            || self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
        {
            return Err(NeonBranchResultError::RegistrationMismatch);
        }
        self.version.validate()?;
        self.scope_digest.validate("registration.scope_digest")?;
        self.manifest_digest
            .validate("registration.manifest_digest")?;
        self.registration_digest
            .validate("registration.registration_digest")?;
        if self.registry_revision == 0 || self.native_status.is_native() {
            return Err(NeonBranchResultError::RegistrationStale);
        }
        Ok(())
    }
}

/// A small in-process registry that makes registration reversible without
/// introducing persistence or host integration authority.
#[derive(Clone, Debug, Default)]
pub struct NeonBranchResultRegistry {
    registrations: BTreeMap<Digest, NeonProviderRegistration>,
    next_revision: u64,
}

impl NeonBranchResultRegistry {
    /// Register one active provider identity and return its digest-only receipt.
    pub fn register(
        &mut self,
        registration: NeonProviderRegistration,
    ) -> Result<RegistrationReceipt, NeonBranchResultError> {
        registration.ensure_active()?;
        if self
            .registrations
            .contains_key(&registration.registration_digest)
        {
            return Err(NeonBranchResultError::RegistrationAlreadyExists);
        }
        self.next_revision = self
            .next_revision
            .checked_add(1)
            .ok_or(NeonBranchResultError::RegistrationStale)?;
        let receipt = RegistrationReceipt::from_registration(&registration, self.next_revision)?;
        self.registrations
            .insert(registration.registration_digest.clone(), registration);
        Ok(receipt)
    }

    /// Reversibly remove a registration after checking its exact receipt.
    pub fn unregister(
        &mut self,
        receipt: &RegistrationReceipt,
    ) -> Result<RegistrationReceipt, NeonBranchResultError> {
        receipt.validate()?;
        let registration = self
            .registrations
            .get(&receipt.registration_digest)
            .ok_or(NeonBranchResultError::RegistrationUnknown)?
            .clone();
        let expected =
            RegistrationReceipt::from_registration(&registration, receipt.registry_revision)?;
        if expected != *receipt || expected.scope_digest != receipt.scope_digest {
            return Err(NeonBranchResultError::RegistrationMismatch);
        }
        self.registrations.remove(&receipt.registration_digest);
        self.next_revision = self
            .next_revision
            .checked_add(1)
            .ok_or(NeonBranchResultError::RegistrationStale)?;
        let mut revoked = registration;
        revoked.revoke()?;
        RegistrationReceipt::from_registration(&revoked, self.next_revision)
    }

    /// Check whether an exact registration digest is currently active.
    pub fn contains(&self, registration_digest: &Digest) -> bool {
        self.registrations.contains_key(registration_digest)
    }

    /// Return the active registration for an exact digest.
    pub fn get(&self, registration_digest: &Digest) -> Option<&NeonProviderRegistration> {
        self.registrations.get(registration_digest)
    }
}

/// Calculate the manifest-only registration binding used when a service is
/// constructed before an integration registry is attached.
pub fn registration_digest_for_manifest(manifest: &NeonProviderManifest) -> Digest {
    canonical_digest(&(
        &manifest.plugin_id,
        &manifest.provider_id,
        &manifest.service_id,
        &manifest.consumer_id,
        manifest.version,
        &manifest.manifest_digest,
        &manifest.scope,
    ))
}

/// Branch/control-plane state observed at a capability probe.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BranchState {
    Ready,
    Archived,
    Suspended,
    Activating,
    Missing,
    PermissionLost,
    Throttled,
    TimedOut,
    Unknown,
}

impl BranchState {
    /// Only a stable ready branch can support a proposal-capable observation.
    pub const fn is_stable(self) -> bool {
        matches!(self, Self::Ready)
    }
}

/// Endpoint/compute state observed at a capability probe.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointState {
    Ready,
    ScaleToZero,
    Activating,
    Suspended,
    Missing,
    PermissionLost,
    Throttled,
    TimedOut,
    Unknown,
}

impl EndpointState {
    /// Scale-to-zero remains a bounded proposal state but not native evidence.
    pub const fn is_proposal_capable(self) -> bool {
        matches!(self, Self::Ready | Self::ScaleToZero)
    }

    /// Only ready compute is stable for a native operation; Layer 1 never
    /// promotes it to native evidence.
    pub const fn is_stable(self) -> bool {
        matches!(self, Self::Ready)
    }
}

/// Eventual-consistency state returned by a control-plane fixture.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventualConsistencyState {
    Stable,
    Pending,
    Unknown,
}

impl EventualConsistencyState {
    /// Pending and unknown state cannot become verified evidence.
    pub const fn is_stable(self) -> bool {
        matches!(self, Self::Stable)
    }
}

/// Capability probe request bound to one exact branch point.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityProbeRequest {
    pub scope: NeonScope,
    pub point_in_time: BranchPoint,
}

impl CapabilityProbeRequest {
    /// Construct a probe request.
    pub fn new(
        scope: NeonScope,
        point_in_time: BranchPoint,
    ) -> Result<Self, NeonBranchResultError> {
        scope.validate()?;
        point_in_time.validate()?;
        Ok(Self {
            scope,
            point_in_time,
        })
    }

    /// Return its exact branch fence.
    pub fn branch_fence(&self) -> Result<BranchFence, NeonBranchResultError> {
        self.scope.branch_fence(self.point_in_time.clone())
    }
}

/// Control-plane observation returned by a provider transport seam.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ControlPlaneObservation {
    pub scope: NeonScope,
    pub point_in_time: BranchPoint,
    pub branch_state: BranchState,
    pub endpoint_state: EndpointState,
    pub eventual_consistency: EventualConsistencyState,
    pub observed_branch_digest: Digest,
    pub observed_endpoint_digest: Digest,
    pub evidence_source: EvidenceSource,
    pub native_status: NativeStatus,
}

impl ControlPlaneObservation {
    /// Validate that an observation has digest-only identity and no native
    /// claim. The service performs request equality fencing separately.
    pub fn validate(&self) -> Result<(), NeonBranchResultError> {
        self.scope.validate()?;
        self.point_in_time.validate()?;
        self.observed_branch_digest
            .validate("observed_branch_digest")?;
        self.observed_endpoint_digest
            .validate("observed_endpoint_digest")?;
        if self.native_status.is_native() || self.evidence_source.is_native() {
            return Err(NeonBranchResultError::NativeAuthority);
        }
        Ok(())
    }
}

/// Digest-bound capability result. `proposal_capable` is not Connected/native.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityProbeReceipt {
    pub scope: NeonScope,
    pub branch_fence: BranchFence,
    pub branch_state: BranchState,
    pub endpoint_state: EndpointState,
    pub eventual_consistency: EventualConsistencyState,
    pub observed_branch_digest: Digest,
    pub observed_endpoint_digest: Digest,
    pub proposal_capable: bool,
    pub evidence_source: EvidenceSource,
    pub native_status: NativeStatus,
    pub provider_version: PluginVersion,
    pub provider_manifest_digest: Digest,
    pub receipt_digest: Digest,
}

#[derive(Serialize)]
struct CapabilityReceiptIdentity<'a> {
    scope: &'a NeonScope,
    branch_fence: &'a BranchFence,
    branch_state: BranchState,
    endpoint_state: EndpointState,
    eventual_consistency: EventualConsistencyState,
    observed_branch_digest: &'a Digest,
    observed_endpoint_digest: &'a Digest,
    proposal_capable: bool,
    evidence_source: EvidenceSource,
    native_status: NativeStatus,
    provider_version: PluginVersion,
    provider_manifest_digest: &'a Digest,
}

impl CapabilityProbeReceipt {
    /// Compile a probe receipt from an observation and manifest.
    pub fn from_observation(
        request: &CapabilityProbeRequest,
        observation: &ControlPlaneObservation,
        manifest: &NeonProviderManifest,
    ) -> Result<Self, NeonBranchResultError> {
        request.scope.validate()?;
        observation.validate()?;
        manifest.validate()?;
        if observation.scope != request.scope || observation.point_in_time != request.point_in_time
        {
            return Err(NeonBranchResultError::ScopeMismatch {
                field: "capability_probe.branch_fence",
            });
        }
        let branch_fence = request.branch_fence()?;
        let proposal_capable = observation.branch_state.is_stable()
            && observation.endpoint_state.is_proposal_capable()
            && observation.eventual_consistency.is_stable();
        let mut receipt = Self {
            scope: request.scope.clone(),
            branch_fence,
            branch_state: observation.branch_state,
            endpoint_state: observation.endpoint_state,
            eventual_consistency: observation.eventual_consistency,
            observed_branch_digest: observation.observed_branch_digest.clone(),
            observed_endpoint_digest: observation.observed_endpoint_digest.clone(),
            proposal_capable,
            evidence_source: observation.evidence_source,
            native_status: NativeStatus::BlockedEnv,
            provider_version: manifest.version,
            provider_manifest_digest: manifest.digest(),
            receipt_digest: Digest::from_bytes(&[]),
        };
        receipt.receipt_digest = receipt.calculate_digest();
        receipt.validate()?;
        Ok(receipt)
    }

    fn identity(&self) -> CapabilityReceiptIdentity<'_> {
        CapabilityReceiptIdentity {
            scope: &self.scope,
            branch_fence: &self.branch_fence,
            branch_state: self.branch_state,
            endpoint_state: self.endpoint_state,
            eventual_consistency: self.eventual_consistency,
            observed_branch_digest: &self.observed_branch_digest,
            observed_endpoint_digest: &self.observed_endpoint_digest,
            proposal_capable: self.proposal_capable,
            evidence_source: self.evidence_source,
            native_status: self.native_status,
            provider_version: self.provider_version,
            provider_manifest_digest: &self.provider_manifest_digest,
        }
    }

    /// Calculate the receipt digest.
    pub fn calculate_digest(&self) -> Digest {
        canonical_digest(&self.identity())
    }

    /// Validate all capability and digest fences.
    pub fn validate(&self) -> Result<(), NeonBranchResultError> {
        self.scope.validate()?;
        self.branch_fence.validate()?;
        if self.scope != self.branch_fence.scope {
            return Err(NeonBranchResultError::ScopeMismatch {
                field: "capability_probe.scope",
            });
        }
        self.observed_branch_digest
            .validate("observed_branch_digest")?;
        self.observed_endpoint_digest
            .validate("observed_endpoint_digest")?;
        self.provider_version.validate()?;
        self.provider_manifest_digest
            .validate("provider_manifest_digest")?;
        self.receipt_digest.validate("receipt_digest")?;
        if self.native_status.is_native() || self.evidence_source.is_native() {
            return Err(NeonBranchResultError::NativeAuthority);
        }
        if self.receipt_digest != self.calculate_digest() {
            return Err(NeonBranchResultError::DigestMismatch {
                field: "capability_receipt.receipt_digest",
            });
        }
        let expected_capability = self.branch_state.is_stable()
            && self.endpoint_state.is_proposal_capable()
            && self.eventual_consistency.is_stable();
        if self.proposal_capable != expected_capability {
            return Err(NeonBranchResultError::DigestMismatch {
                field: "capability_probe.proposal_capable",
            });
        }
        Ok(())
    }
}

/// Typed Layer 1 operations. Live create/delete and query execution are not
/// represented as operations; they remain explicit Layer 2 gaps.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NeonOperation {
    CapabilityProbe,
    BranchProposal,
    QueryProposal,
    QueryReceipt,
    ResultAdoptionProposal,
    Registration,
    Revocation,
}

/// Branch proposal request; the branch ID in scope is the identity, while an
/// optional label is descriptive only and never substitutes for that ID.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BranchProposalRequest {
    pub scope: NeonScope,
    pub point_in_time: BranchPoint,
    pub branch_label: Option<String>,
}

impl BranchProposalRequest {
    /// Construct a branch proposal request.
    pub fn new(
        scope: NeonScope,
        point_in_time: BranchPoint,
        branch_label: Option<String>,
    ) -> Result<Self, NeonBranchResultError> {
        scope.validate()?;
        point_in_time.validate()?;
        if let Some(label) = &branch_label {
            validate_bounded_text(label, "branch_label", 128)?;
        }
        Ok(Self {
            scope,
            point_in_time,
            branch_label,
        })
    }

    /// Validate a request received through a typed serialization boundary.
    pub fn validate(&self) -> Result<(), NeonBranchResultError> {
        self.scope.validate()?;
        self.point_in_time.validate()?;
        if let Some(label) = &self.branch_label {
            validate_bounded_text(label, "branch_label", 128)?;
        }
        Ok(())
    }
}

/// Layer 1 branch creation proposal. It cannot create or delete a live branch.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BranchProposal {
    pub operation: NeonOperation,
    pub scope: NeonScope,
    pub branch_fence: BranchFence,
    pub branch_label: Option<String>,
    pub effect: ProposalEffect,
    pub provider_version: PluginVersion,
    pub provider_manifest_digest: Digest,
    pub proposal_digest: Digest,
    pub idempotency_key: Digest,
    pub evidence_source: EvidenceSource,
    pub native_status: NativeStatus,
}

/// Naming alias for integrations that call this a branch-result proposal.
pub type NeonBranchProposal = BranchProposal;

#[derive(Serialize)]
struct BranchProposalIdentity<'a> {
    operation: NeonOperation,
    scope: &'a NeonScope,
    branch_fence: &'a BranchFence,
    branch_label: &'a Option<String>,
    effect: ProposalEffect,
    provider_version: PluginVersion,
    provider_manifest_digest: &'a Digest,
}

impl BranchProposal {
    /// Compile a proposal from an exact scope and manifest.
    pub fn new(
        request: BranchProposalRequest,
        manifest: &NeonProviderManifest,
    ) -> Result<Self, NeonBranchResultError> {
        manifest.validate()?;
        request.validate()?;
        if request.scope != manifest.scope {
            return Err(NeonBranchResultError::ScopeMismatch {
                field: "branch_proposal.scope",
            });
        }
        let branch_fence = request.scope.branch_fence(request.point_in_time)?;
        let mut proposal = Self {
            operation: NeonOperation::BranchProposal,
            scope: request.scope,
            branch_fence,
            branch_label: request.branch_label,
            effect: ProposalEffect::ProposalOnly,
            provider_version: manifest.version,
            provider_manifest_digest: manifest.digest(),
            proposal_digest: Digest::from_bytes(&[]),
            idempotency_key: Digest::from_bytes(&[]),
            evidence_source: EvidenceSource::Recording,
            native_status: NativeStatus::BlockedEnv,
        };
        proposal.proposal_digest = proposal.calculate_digest();
        proposal.idempotency_key = canonical_digest(&(
            &proposal.scope,
            &proposal.branch_fence,
            &proposal.proposal_digest,
        ));
        proposal.validate()?;
        Ok(proposal)
    }

    fn identity(&self) -> BranchProposalIdentity<'_> {
        BranchProposalIdentity {
            operation: self.operation,
            scope: &self.scope,
            branch_fence: &self.branch_fence,
            branch_label: &self.branch_label,
            effect: self.effect,
            provider_version: self.provider_version,
            provider_manifest_digest: &self.provider_manifest_digest,
        }
    }

    /// Calculate the immutable proposal digest.
    pub fn calculate_digest(&self) -> Digest {
        canonical_digest(&self.identity())
    }

    /// Validate the proposal and its exact branch fence.
    pub fn validate(&self) -> Result<(), NeonBranchResultError> {
        self.scope.validate()?;
        self.branch_fence.validate()?;
        if self.operation != NeonOperation::BranchProposal
            || self.effect != ProposalEffect::ProposalOnly
            || self.scope != self.branch_fence.scope
        {
            return Err(NeonBranchResultError::InvalidInput {
                field: "branch_proposal",
                reason: InputViolation::LayerTwoOnly,
            });
        }
        self.provider_version.validate()?;
        self.provider_manifest_digest
            .validate("provider_manifest_digest")?;
        self.proposal_digest.validate("proposal_digest")?;
        self.idempotency_key.validate("idempotency_key")?;
        if self.proposal_digest != self.calculate_digest() {
            return Err(NeonBranchResultError::DigestMismatch {
                field: "branch_proposal.proposal_digest",
            });
        }
        let expected_key =
            canonical_digest(&(&self.scope, &self.branch_fence, &self.proposal_digest));
        if self.idempotency_key != expected_key {
            return Err(NeonBranchResultError::DigestMismatch {
                field: "branch_proposal.idempotency_key",
            });
        }
        if self.native_status.is_native() || self.evidence_source.is_native() {
            return Err(NeonBranchResultError::NativeAuthority);
        }
        Ok(())
    }
}

/// Digest-only receipt that a branch proposal was recorded locally.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BranchProposalReceipt {
    pub operation: NeonOperation,
    pub scope: NeonScope,
    pub branch_fence: BranchFence,
    pub proposal_digest: Digest,
    pub idempotency_key: Digest,
    pub provider_version: PluginVersion,
    pub provider_manifest_digest: Digest,
    pub evidence_source: EvidenceSource,
    pub native_status: NativeStatus,
    pub receipt_digest: Digest,
}

#[derive(Serialize)]
struct BranchReceiptIdentity<'a> {
    operation: NeonOperation,
    scope: &'a NeonScope,
    branch_fence: &'a BranchFence,
    proposal_digest: &'a Digest,
    idempotency_key: &'a Digest,
    provider_version: PluginVersion,
    provider_manifest_digest: &'a Digest,
    evidence_source: EvidenceSource,
    native_status: NativeStatus,
}

impl BranchProposalReceipt {
    /// Create a local recording receipt for a proposal.
    pub fn from_proposal(
        proposal: &BranchProposal,
        manifest: &NeonProviderManifest,
    ) -> Result<Self, NeonBranchResultError> {
        proposal.validate()?;
        manifest.validate()?;
        if proposal.provider_manifest_digest != manifest.digest()
            || proposal.scope != manifest.scope
        {
            return Err(NeonBranchResultError::ScopeMismatch {
                field: "branch_receipt.manifest",
            });
        }
        let mut receipt = Self {
            operation: NeonOperation::BranchProposal,
            scope: proposal.scope.clone(),
            branch_fence: proposal.branch_fence.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            idempotency_key: proposal.idempotency_key.clone(),
            provider_version: manifest.version,
            provider_manifest_digest: manifest.digest(),
            evidence_source: EvidenceSource::Recording,
            native_status: NativeStatus::BlockedEnv,
            receipt_digest: Digest::from_bytes(&[]),
        };
        receipt.receipt_digest = receipt.calculate_digest();
        receipt.validate()?;
        Ok(receipt)
    }

    fn identity(&self) -> BranchReceiptIdentity<'_> {
        BranchReceiptIdentity {
            operation: self.operation,
            scope: &self.scope,
            branch_fence: &self.branch_fence,
            proposal_digest: &self.proposal_digest,
            idempotency_key: &self.idempotency_key,
            provider_version: self.provider_version,
            provider_manifest_digest: &self.provider_manifest_digest,
            evidence_source: self.evidence_source,
            native_status: self.native_status,
        }
    }

    /// Calculate the receipt digest.
    pub fn calculate_digest(&self) -> Digest {
        canonical_digest(&self.identity())
    }

    /// Validate exact proposal and branch fences.
    pub fn validate(&self) -> Result<(), NeonBranchResultError> {
        self.scope.validate()?;
        self.branch_fence.validate()?;
        self.proposal_digest.validate("proposal_digest")?;
        self.idempotency_key.validate("idempotency_key")?;
        self.provider_version.validate()?;
        self.provider_manifest_digest
            .validate("provider_manifest_digest")?;
        self.receipt_digest.validate("receipt_digest")?;
        if self.operation != NeonOperation::BranchProposal
            || self.scope != self.branch_fence.scope
            || self.native_status.is_native()
            || self.evidence_source.is_native()
        {
            return Err(NeonBranchResultError::NativeAuthority);
        }
        if self.receipt_digest != self.calculate_digest() {
            return Err(NeonBranchResultError::DigestMismatch {
                field: "branch_receipt.receipt_digest",
            });
        }
        Ok(())
    }
}

/// Effect level available to this root. It is intentionally non-mutating.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalEffect {
    ProposalOnly,
    RecordingOnly,
}

/// Typed positional parameter. Values are transported separately from the
/// SQL shape and only their digest enters query receipts.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum QueryParameter {
    Null,
    Boolean(bool),
    Integer(i64),
    Numeric { value: String },
    Text { value: String },
    Uuid { value: String },
    JsonDigest { digest: Digest },
}

impl fmt::Debug for QueryParameter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("QueryParameter");
        match self {
            Self::Null => debug.field("kind", &"null"),
            Self::Boolean(value) => debug.field("kind", &"boolean").field("value", value),
            Self::Integer(value) => debug.field("kind", &"integer").field("value", value),
            Self::Numeric { value } => debug
                .field("kind", &"numeric")
                .field("value_digest", &canonical_digest(value)),
            Self::Text { value } => debug
                .field("kind", &"text")
                .field("value_digest", &canonical_digest(value)),
            Self::Uuid { value } => debug
                .field("kind", &"uuid")
                .field("value_digest", &canonical_digest(value)),
            Self::JsonDigest { digest } => {
                debug.field("kind", &"json_digest").field("digest", digest)
            }
        }
        .finish()
    }
}

impl QueryParameter {
    /// Validate a typed parameter without interpolating it into SQL.
    pub fn validate(&self) -> Result<(), NeonBranchResultError> {
        match self {
            Self::Null | Self::Boolean(_) | Self::Integer(_) => Ok(()),
            Self::Numeric { value } => {
                validate_bounded_text(value, "numeric_parameter", 256)?;
                if value
                    .parse::<f64>()
                    .map_or(true, |number| !number.is_finite())
                {
                    return Err(NeonBranchResultError::InvalidInput {
                        field: "numeric_parameter",
                        reason: InputViolation::InvalidParameterBinding,
                    });
                }
                Ok(())
            }
            Self::Text { value } => validate_bounded_text(value, "text_parameter", MAX_VALUE_BYTES),
            Self::Uuid { value } => {
                if value.len() != 36
                    || value.bytes().enumerate().any(|(index, byte)| {
                        matches!(index, 8 | 13 | 18 | 23)
                            .then_some(byte != b'-')
                            .unwrap_or_else(|| !byte.is_ascii_hexdigit())
                    })
                {
                    return Err(NeonBranchResultError::InvalidInput {
                        field: "uuid_parameter",
                        reason: InputViolation::InvalidParameterBinding,
                    });
                }
                Ok(())
            }
            Self::JsonDigest { digest } => digest.validate("json_parameter_digest"),
        }
    }

    /// Digest one typed parameter.
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

/// Parameterized SQL read shape accepted by the Layer 1 allowlist.
#[derive(Clone, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ParameterizedQuery {
    pub sql: String,
    pub parameters: Vec<QueryParameter>,
    pub query_digest: Digest,
    pub parameter_digest: Digest,
}

impl fmt::Debug for ParameterizedQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParameterizedQuery")
            .field("query_digest", &self.query_digest)
            .field("parameter_digest", &self.parameter_digest)
            .field("parameter_count", &self.parameters.len())
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
struct QueryIdentity<'a> {
    sql: &'a str,
}

impl ParameterizedQuery {
    /// Construct an allowlisted parameterized SELECT/EXPLAIN query.
    pub fn new(
        sql: impl Into<String>,
        parameters: Vec<QueryParameter>,
    ) -> Result<Self, NeonBranchResultError> {
        let sql = sql.into();
        validate_query_sql(&sql, &parameters)?;
        for parameter in &parameters {
            parameter.validate()?;
        }
        let query_digest = canonical_digest(&QueryIdentity { sql: sql.trim() });
        let parameter_digest = canonical_digest(&parameters);
        let query = Self {
            sql: sql.trim().to_owned(),
            parameters,
            query_digest,
            parameter_digest,
        };
        query.validate()?;
        Ok(query)
    }

    /// Validate query text, bindings, and digest fields.
    pub fn validate(&self) -> Result<(), NeonBranchResultError> {
        validate_query_sql(&self.sql, &self.parameters)?;
        for parameter in &self.parameters {
            parameter.validate()?;
        }
        self.query_digest.validate("query_digest")?;
        self.parameter_digest.validate("parameter_digest")?;
        let expected_query = canonical_digest(&QueryIdentity {
            sql: self.sql.trim(),
        });
        let expected_parameters = canonical_digest(&self.parameters);
        if self.query_digest != expected_query {
            return Err(NeonBranchResultError::DigestMismatch {
                field: "query_digest",
            });
        }
        if self.parameter_digest != expected_parameters {
            return Err(NeonBranchResultError::DigestMismatch {
                field: "parameter_digest",
            });
        }
        Ok(())
    }

    /// Return the number of positional parameters.
    pub fn parameter_count(&self) -> usize {
        self.parameters.len()
    }

    /// Return the literal or bound LIMIT upper bound used by the allowlist.
    pub fn limit_upper_bound(&self) -> Result<u32, NeonBranchResultError> {
        parse_limit_upper_bound(&self.sql, &self.parameters)
    }
}

/// Deterministic row-set digest mode. Ordered results preserve provider row
/// order; unordered results sort canonical row encodings before hashing.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RowSetCanonicalization {
    Ordered,
    Unordered,
}

/// Bounded query retry/backoff policy. It records timing but never sleeps.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetryPolicy {
    pub max_attempts: u8,
    pub initial_backoff_ms: u64,
    pub max_backoff_ms: u64,
}

impl RetryPolicy {
    /// Construct a bounded policy.
    pub const fn new(max_attempts: u8, initial_backoff_ms: u64, max_backoff_ms: u64) -> Self {
        Self {
            max_attempts,
            initial_backoff_ms,
            max_backoff_ms,
        }
    }

    /// The deterministic Layer 1 default.
    pub const fn layer1() -> Self {
        Self::new(3, 100, 2_000)
    }

    /// Return a bounded delay for a zero-based retry index.
    pub fn delay_for_retry(&self, retry_index: u8) -> u64 {
        let mut delay = self.initial_backoff_ms;
        for _ in 0..retry_index {
            delay = delay.saturating_mul(2).min(self.max_backoff_ms);
        }
        delay
    }

    /// Validate attempts and delays.
    pub fn validate(&self) -> Result<(), NeonBranchResultError> {
        if !(1..=MAX_QUERY_ATTEMPTS).contains(&self.max_attempts)
            || self.initial_backoff_ms == 0
            || self.initial_backoff_ms > self.max_backoff_ms
            || self.max_backoff_ms > MAX_BACKOFF_MS
        {
            return Err(NeonBranchResultError::InvalidInput {
                field: "retry_policy",
                reason: InputViolation::OutOfRange,
            });
        }
        Ok(())
    }
}

/// Explicit query execution budget. Layer 1 records the budget and does not
/// perform a native query.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QueryBudget {
    pub max_rows: u32,
    pub max_bytes: u64,
    pub timeout_ms: u64,
    pub retry_policy: RetryPolicy,
}

impl QueryBudget {
    /// Construct and validate a bounded budget.
    pub fn new(
        max_rows: u32,
        max_bytes: u64,
        timeout_ms: u64,
        retry_policy: RetryPolicy,
    ) -> Result<Self, NeonBranchResultError> {
        let budget = Self {
            max_rows,
            max_bytes,
            timeout_ms,
            retry_policy,
        };
        budget.validate()?;
        Ok(budget)
    }

    /// A conservative Layer 1 fixture budget.
    pub fn layer1() -> Self {
        Self {
            max_rows: 100,
            max_bytes: 64 * 1024,
            timeout_ms: 5_000,
            retry_policy: RetryPolicy::layer1(),
        }
    }

    /// Validate all explicit query limits.
    pub fn validate(&self) -> Result<(), NeonBranchResultError> {
        if self.max_rows == 0
            || self.max_rows > MAX_RESULT_ROWS
            || self.max_bytes == 0
            || self.max_bytes > MAX_RESULT_BYTES
            || self.timeout_ms == 0
            || self.timeout_ms > MAX_QUERY_TIMEOUT_MS
        {
            return Err(NeonBranchResultError::InvalidInput {
                field: "query_budget",
                reason: InputViolation::OutOfRange,
            });
        }
        self.retry_policy.validate()
    }
}

/// Query proposal request with an explicit branch point and result budget.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QueryProposalRequest {
    pub scope: NeonScope,
    pub point_in_time: BranchPoint,
    pub query: ParameterizedQuery,
    pub budget: QueryBudget,
    pub canonicalization: RowSetCanonicalization,
    pub expected_schema_digest: Option<Digest>,
}

impl QueryProposalRequest {
    /// Construct a bounded query request.
    pub fn new(
        scope: NeonScope,
        point_in_time: BranchPoint,
        query: ParameterizedQuery,
        budget: QueryBudget,
        canonicalization: RowSetCanonicalization,
        expected_schema_digest: Option<Digest>,
    ) -> Result<Self, NeonBranchResultError> {
        scope.validate()?;
        point_in_time.validate()?;
        query.validate()?;
        budget.validate()?;
        if let Some(digest) = &expected_schema_digest {
            digest.validate("expected_schema_digest")?;
        }
        let limit = query.limit_upper_bound()?;
        if limit > budget.max_rows {
            return Err(NeonBranchResultError::InvalidInput {
                field: "query_budget.max_rows",
                reason: InputViolation::UnboundedResult,
            });
        }
        Ok(Self {
            scope,
            point_in_time,
            query,
            budget,
            canonicalization,
            expected_schema_digest,
        })
    }

    /// Validate a request received through a typed serialization boundary.
    pub fn validate(&self) -> Result<(), NeonBranchResultError> {
        self.scope.validate()?;
        self.point_in_time.validate()?;
        self.query.validate()?;
        self.budget.validate()?;
        if let Some(digest) = &self.expected_schema_digest {
            digest.validate("expected_schema_digest")?;
        }
        if self.query.limit_upper_bound()? > self.budget.max_rows {
            return Err(NeonBranchResultError::InvalidInput {
                field: "query_budget.max_rows",
                reason: InputViolation::UnboundedResult,
            });
        }
        Ok(())
    }
}

/// Layer 1 parameterized read proposal. It contains typed parameters for the
/// future transport seam; receipts carry only the parameter digest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QueryProposal {
    pub operation: NeonOperation,
    pub scope: NeonScope,
    pub branch_fence: BranchFence,
    pub query: ParameterizedQuery,
    pub budget: QueryBudget,
    pub canonicalization: RowSetCanonicalization,
    pub expected_schema_digest: Option<Digest>,
    pub provider_version: PluginVersion,
    pub provider_manifest_digest: Digest,
    pub effect: ProposalEffect,
    pub evidence_source: EvidenceSource,
    pub native_status: NativeStatus,
    pub proposal_digest: Digest,
    pub idempotency_key: Digest,
}

/// Naming aliases keep the query/result boundary explicit at integration
/// call sites without introducing a second representation.
pub type NeonQueryProposal = QueryProposal;
pub type NeonQueryResultReceipt = QueryReceipt;

/// Bounded query schema receipt. Column names/types are metadata, not rows.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QuerySchema {
    pub columns: Vec<QueryColumn>,
}

impl QuerySchema {
    /// Construct and validate a non-empty result schema.
    pub fn new(columns: Vec<QueryColumn>) -> Result<Self, NeonBranchResultError> {
        let schema = Self { columns };
        schema.validate()?;
        Ok(schema)
    }

    /// Digest the canonical column schema.
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    /// Validate column count, names, and duplicate prevention.
    pub fn validate(&self) -> Result<(), NeonBranchResultError> {
        if self.columns.is_empty() || self.columns.len() > 128 {
            return Err(NeonBranchResultError::InvalidInput {
                field: "schema.columns",
                reason: InputViolation::InvalidSchema,
            });
        }
        let mut names = BTreeSet::new();
        for column in &self.columns {
            column.validate()?;
            if !names.insert(column.name.clone()) {
                return Err(NeonBranchResultError::InvalidInput {
                    field: "schema.columns",
                    reason: InputViolation::InvalidSchema,
                });
            }
        }
        Ok(())
    }
}

/// One bounded column in a query result schema.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QueryColumn {
    pub name: String,
    pub data_type: String,
    pub nullable: bool,
}

impl QueryColumn {
    /// Construct a bounded column descriptor.
    pub fn new(
        name: impl Into<String>,
        data_type: impl Into<String>,
        nullable: bool,
    ) -> Result<Self, NeonBranchResultError> {
        let column = Self {
            name: name.into(),
            data_type: data_type.into(),
            nullable,
        };
        column.validate()?;
        Ok(column)
    }

    /// Validate name and provider type metadata.
    pub fn validate(&self) -> Result<(), NeonBranchResultError> {
        validate_bounded_text(&self.name, "schema.column.name", 128)?;
        validate_bounded_text(&self.data_type, "schema.column.data_type", 128)
    }
}

/// Typed result value retained only by a fixture/transport seam until its
/// canonical row-set digest is calculated. It is never copied into receipts.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum QueryValue {
    Null,
    Boolean(bool),
    Integer(i64),
    Numeric { value: String },
    Text { value: String },
    Uuid { value: String },
    JsonDigest { digest: Digest },
    BytesDigest { digest: Digest },
}

impl fmt::Debug for QueryValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("QueryValue");
        match self {
            Self::Null => debug.field("kind", &"null"),
            Self::Boolean(value) => debug.field("kind", &"boolean").field("value", value),
            Self::Integer(value) => debug.field("kind", &"integer").field("value", value),
            Self::Numeric { value } => debug
                .field("kind", &"numeric")
                .field("value_digest", &canonical_digest(value)),
            Self::Text { value } => debug
                .field("kind", &"text")
                .field("value_digest", &canonical_digest(value)),
            Self::Uuid { value } => debug
                .field("kind", &"uuid")
                .field("value_digest", &canonical_digest(value)),
            Self::JsonDigest { digest } => {
                debug.field("kind", &"json_digest").field("digest", digest)
            }
            Self::BytesDigest { digest } => {
                debug.field("kind", &"bytes_digest").field("digest", digest)
            }
        }
        .finish()
    }
}

impl QueryValue {
    /// Validate one typed result value without exposing credentials or rows.
    pub fn validate(&self) -> Result<(), NeonBranchResultError> {
        match self {
            Self::Null | Self::Boolean(_) | Self::Integer(_) => Ok(()),
            Self::Numeric { value } => {
                validate_bounded_text(value, "result.numeric", 256)?;
                if value
                    .parse::<f64>()
                    .map_or(true, |number| !number.is_finite())
                {
                    return Err(NeonBranchResultError::InvalidInput {
                        field: "result.numeric",
                        reason: InputViolation::InvalidRows,
                    });
                }
                Ok(())
            }
            Self::Text { value } => validate_bounded_text(value, "result.text", MAX_VALUE_BYTES),
            Self::Uuid { value } => QueryParameter::Uuid {
                value: value.clone(),
            }
            .validate(),
            Self::JsonDigest { digest } => digest.validate("result.json_digest"),
            Self::BytesDigest { digest } => digest.validate("result.bytes_digest"),
        }
    }
}

/// A row retained only inside the independent query transport seam.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct QueryRow(pub Vec<QueryValue>);

impl fmt::Debug for QueryRow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QueryRow")
            .field("value_count", &self.0.len())
            .field("row_digest", &canonical_digest(self))
            .finish()
    }
}

impl QueryRow {
    /// Validate bounded typed row values.
    pub fn validate(&self, column_count: usize) -> Result<(), NeonBranchResultError> {
        if self.0.len() != column_count {
            return Err(NeonBranchResultError::InvalidInput {
                field: "result.row",
                reason: InputViolation::InvalidRows,
            });
        }
        for value in &self.0 {
            value.validate()?;
        }
        Ok(())
    }
}

/// Fixture observation returned from the Postgres/HTTP query seam.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QueryResultObservation {
    pub scope: NeonScope,
    pub branch_fence: BranchFence,
    pub schema: QuerySchema,
    pub rows: Vec<QueryRow>,
    pub elapsed_ms: u64,
    pub result_bytes: u64,
    pub complete: bool,
    pub truncated: bool,
    pub transport_protocol: QueryTransportProtocol,
    pub evidence_source: EvidenceSource,
    pub native_status: NativeStatus,
}

impl fmt::Debug for QueryResultObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QueryResultObservation")
            .field("scope_digest", &self.scope.digest())
            .field("branch_fence_digest", &self.branch_fence.digest())
            .field("schema_digest", &self.schema.digest())
            .field("row_count", &self.rows.len())
            .field("result_bytes", &self.result_bytes)
            .field("elapsed_ms", &self.elapsed_ms)
            .field("complete", &self.complete)
            .field("truncated", &self.truncated)
            .field("transport_protocol", &self.transport_protocol)
            .field("evidence_source", &self.evidence_source)
            .field("native_status", &self.native_status)
            .finish_non_exhaustive()
    }
}

/// Alias emphasizing that a fixture is deterministic recording input.
pub type RecordedQueryResult = QueryResultObservation;

impl QueryResultObservation {
    /// Construct a bounded observation and derive its result-byte count.
    pub fn new(
        scope: NeonScope,
        branch_fence: BranchFence,
        schema: QuerySchema,
        rows: Vec<QueryRow>,
        elapsed_ms: u64,
        transport_protocol: QueryTransportProtocol,
        evidence_source: EvidenceSource,
    ) -> Result<Self, NeonBranchResultError> {
        let result_bytes = u64::try_from(canonical_digest(&(&schema, &rows)).as_str().len())
            .map_err(|_| NeonBranchResultError::InvalidInput {
                field: "query_result.result_bytes",
                reason: InputViolation::OutOfRange,
            })?;
        let observation = Self {
            scope,
            branch_fence,
            schema,
            rows,
            elapsed_ms,
            result_bytes,
            complete: true,
            truncated: false,
            transport_protocol,
            evidence_source,
            native_status: NativeStatus::BlockedEnv,
        };
        observation.validate()?;
        Ok(observation)
    }

    /// Validate schema, row shape, branch fence, and evidence status.
    pub fn validate(&self) -> Result<(), NeonBranchResultError> {
        self.scope.validate()?;
        self.branch_fence.validate()?;
        self.schema.validate()?;
        if self.scope != self.branch_fence.scope {
            return Err(NeonBranchResultError::ScopeMismatch {
                field: "query_result.scope",
            });
        }
        if self.rows.len() > MAX_RESULT_ROWS as usize {
            return Err(NeonBranchResultError::InvalidInput {
                field: "query_result.rows",
                reason: InputViolation::OutOfRange,
            });
        }
        for row in &self.rows {
            row.validate(self.schema.columns.len())?;
        }
        let expected_result_bytes = u64::try_from(
            canonical_digest(&(&self.schema, &self.rows)).as_str().len(),
        )
        .map_err(|_| NeonBranchResultError::InvalidInput {
            field: "query_result.result_bytes",
            reason: InputViolation::OutOfRange,
        })?;
        if self.result_bytes != expected_result_bytes {
            return Err(NeonBranchResultError::DigestMismatch {
                field: "query_result.result_bytes",
            });
        }
        if self.result_bytes > MAX_RESULT_BYTES
            || !self.complete
            || self.truncated
            || self.native_status.is_native()
            || self.evidence_source.is_native()
        {
            return Err(NeonBranchResultError::InvalidInput {
                field: "query_result",
                reason: if self.truncated || !self.complete {
                    InputViolation::TruncatedResult
                } else {
                    InputViolation::OutOfRange
                },
            });
        }
        Ok(())
    }

    /// Canonical row-set digest for a query's declared order semantics.
    pub fn row_set_digest(
        &self,
        canonicalization: RowSetCanonicalization,
    ) -> Result<Digest, NeonBranchResultError> {
        self.validate()?;
        let mut encoded_rows = self
            .rows
            .iter()
            .map(|row| serde_json::to_vec(row).expect("typed query rows serialize"))
            .collect::<Vec<_>>();
        if matches!(canonicalization, RowSetCanonicalization::Unordered) {
            encoded_rows.sort();
        }
        Ok(canonical_digest(&encoded_rows))
    }
}

/// Independent query receipt. It contains no SQL, parameters, raw rows, or
/// connection string; every adoption consumer must verify all digest fences.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QueryReceipt {
    pub operation: NeonOperation,
    pub receipt_kind: QueryReceiptKind,
    pub scope: NeonScope,
    pub branch_fence: BranchFence,
    pub query_digest: Digest,
    pub parameter_digest: Digest,
    pub schema_digest: Digest,
    pub row_set_digest: Digest,
    pub row_count: u32,
    pub result_bytes: u64,
    pub elapsed_ms: u64,
    pub complete: bool,
    pub truncated: bool,
    pub canonicalization: RowSetCanonicalization,
    pub provider_version: PluginVersion,
    pub provider_manifest_digest: Digest,
    pub evidence_source: EvidenceSource,
    pub native_status: NativeStatus,
    pub independent: bool,
    pub verification: ReceiptVerification,
    pub receipt_digest: Digest,
}

/// Receipt kind is separate from an arbitrary successful transport response.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryReceiptKind {
    IndependentQueryReceipt,
}

/// Digest verification status used by the Mission consumer.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptVerification {
    DigestBoundRecording,
}

#[derive(Serialize)]
struct QueryReceiptIdentity<'a> {
    operation: NeonOperation,
    receipt_kind: QueryReceiptKind,
    scope: &'a NeonScope,
    branch_fence: &'a BranchFence,
    query_digest: &'a Digest,
    parameter_digest: &'a Digest,
    schema_digest: &'a Digest,
    row_set_digest: &'a Digest,
    row_count: u32,
    result_bytes: u64,
    elapsed_ms: u64,
    complete: bool,
    truncated: bool,
    canonicalization: RowSetCanonicalization,
    provider_version: PluginVersion,
    provider_manifest_digest: &'a Digest,
    evidence_source: EvidenceSource,
    native_status: NativeStatus,
    independent: bool,
    verification: ReceiptVerification,
}

impl QueryReceipt {
    /// Build an independent receipt from one exact proposal and one fixture
    /// observation. The provider must separately retain/verify this receipt.
    pub fn from_observation(
        proposal: &QueryProposal,
        observation: &QueryResultObservation,
        manifest: &NeonProviderManifest,
    ) -> Result<Self, NeonBranchResultError> {
        proposal.validate()?;
        observation.validate()?;
        manifest.validate()?;
        if observation.scope != proposal.scope || observation.branch_fence != proposal.branch_fence
        {
            return Err(NeonBranchResultError::ScopeMismatch {
                field: "query_receipt.branch_fence",
            });
        }
        if observation.elapsed_ms > proposal.budget.timeout_ms {
            return Err(NeonBranchResultError::InvalidInput {
                field: "query_receipt.elapsed_ms",
                reason: InputViolation::OutOfRange,
            });
        }
        if observation.rows.len() > proposal.budget.max_rows as usize
            || observation.result_bytes > proposal.budget.max_bytes
        {
            return Err(NeonBranchResultError::InvalidInput {
                field: "query_receipt.result_limits",
                reason: InputViolation::OutOfRange,
            });
        }
        let schema_digest = observation.schema.digest();
        if let Some(expected) = &proposal.expected_schema_digest
            && expected != &schema_digest
        {
            return Err(NeonBranchResultError::ReceiptMismatch {
                field: "schema_digest",
            });
        }
        let row_set_digest = observation.row_set_digest(proposal.canonicalization)?;
        let mut receipt = Self {
            operation: NeonOperation::QueryReceipt,
            receipt_kind: QueryReceiptKind::IndependentQueryReceipt,
            scope: proposal.scope.clone(),
            branch_fence: proposal.branch_fence.clone(),
            query_digest: proposal.query.query_digest.clone(),
            parameter_digest: proposal.query.parameter_digest.clone(),
            schema_digest,
            row_set_digest,
            row_count: u32::try_from(observation.rows.len()).map_err(|_| {
                NeonBranchResultError::InvalidInput {
                    field: "query_receipt.row_count",
                    reason: InputViolation::OutOfRange,
                }
            })?,
            result_bytes: observation.result_bytes,
            elapsed_ms: observation.elapsed_ms,
            complete: observation.complete,
            truncated: observation.truncated,
            canonicalization: proposal.canonicalization,
            provider_version: manifest.version,
            provider_manifest_digest: manifest.digest(),
            evidence_source: EvidenceSource::Recording,
            native_status: NativeStatus::BlockedEnv,
            independent: true,
            verification: ReceiptVerification::DigestBoundRecording,
            receipt_digest: Digest::from_bytes(&[]),
        };
        receipt.receipt_digest = receipt.calculate_digest();
        receipt.validate()?;
        Ok(receipt)
    }

    fn identity(&self) -> QueryReceiptIdentity<'_> {
        QueryReceiptIdentity {
            operation: self.operation,
            receipt_kind: self.receipt_kind,
            scope: &self.scope,
            branch_fence: &self.branch_fence,
            query_digest: &self.query_digest,
            parameter_digest: &self.parameter_digest,
            schema_digest: &self.schema_digest,
            row_set_digest: &self.row_set_digest,
            row_count: self.row_count,
            result_bytes: self.result_bytes,
            elapsed_ms: self.elapsed_ms,
            complete: self.complete,
            truncated: self.truncated,
            canonicalization: self.canonicalization,
            provider_version: self.provider_version,
            provider_manifest_digest: &self.provider_manifest_digest,
            evidence_source: self.evidence_source,
            native_status: self.native_status,
            independent: self.independent,
            verification: self.verification,
        }
    }

    /// Calculate the receipt digest.
    pub fn calculate_digest(&self) -> Digest {
        canonical_digest(&self.identity())
    }

    /// Validate digest, limits, and exact independent receipt markers.
    pub fn validate(&self) -> Result<(), NeonBranchResultError> {
        self.scope.validate()?;
        self.branch_fence.validate()?;
        self.query_digest.validate("query_digest")?;
        self.parameter_digest.validate("parameter_digest")?;
        self.schema_digest.validate("schema_digest")?;
        self.row_set_digest.validate("row_set_digest")?;
        self.provider_version.validate()?;
        self.provider_manifest_digest
            .validate("provider_manifest_digest")?;
        self.receipt_digest.validate("receipt_digest")?;
        if self.operation != NeonOperation::QueryReceipt
            || self.receipt_kind != QueryReceiptKind::IndependentQueryReceipt
            || !self.independent
            || self.verification != ReceiptVerification::DigestBoundRecording
            || !self.complete
            || self.truncated
            || self.row_count > MAX_RESULT_ROWS
            || self.result_bytes > MAX_RESULT_BYTES
            || self.native_status.is_native()
            || self.evidence_source.is_native()
        {
            return Err(NeonBranchResultError::MissingIndependentReceipt);
        }
        if self.receipt_digest != self.calculate_digest() {
            return Err(NeonBranchResultError::DigestMismatch {
                field: "query_receipt.receipt_digest",
            });
        }
        Ok(())
    }

    /// Verify all query/branch/schema/row-set values that are visible without
    /// retaining raw rows.
    pub fn matches_proposal(&self, proposal: &QueryProposal) -> Result<(), NeonBranchResultError> {
        self.validate()?;
        proposal.validate()?;
        if self.scope != proposal.scope {
            return Err(NeonBranchResultError::ReceiptMismatch { field: "scope" });
        }
        if self.branch_fence != proposal.branch_fence {
            return Err(NeonBranchResultError::ReceiptMismatch {
                field: "branch_fence",
            });
        }
        if self.query_digest != proposal.query.query_digest {
            return Err(NeonBranchResultError::ReceiptMismatch {
                field: "query_digest",
            });
        }
        if self.parameter_digest != proposal.query.parameter_digest {
            return Err(NeonBranchResultError::ReceiptMismatch {
                field: "parameter_digest",
            });
        }
        if let Some(expected) = &proposal.expected_schema_digest
            && &self.schema_digest != expected
        {
            return Err(NeonBranchResultError::ReceiptMismatch {
                field: "schema_digest",
            });
        }
        if self.row_count > proposal.budget.max_rows
            || self.result_bytes > proposal.budget.max_bytes
            || self.elapsed_ms > proposal.budget.timeout_ms
        {
            return Err(NeonBranchResultError::ReceiptMismatch {
                field: "result_limits",
            });
        }
        Ok(())
    }
}

/// Mission-owned source revision used to bind a database result to a
/// parent/child work product without persisting it in this crate.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionDatabaseResultSource {
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub source_result_id: SourceResultId,
    pub source_revision: u64,
}

impl MissionDatabaseResultSource {
    /// Construct a positive Mission result revision.
    pub fn new(
        project_id: ProjectId,
        mission_id: MissionId,
        source_result_id: SourceResultId,
        source_revision: u64,
    ) -> Result<Self, NeonBranchResultError> {
        let source = Self {
            project_id,
            mission_id,
            source_result_id,
            source_revision,
        };
        source.validate()?;
        Ok(source)
    }

    /// Validate Mission/source identity.
    pub fn validate(&self) -> Result<(), NeonBranchResultError> {
        self.project_id.validate()?;
        self.mission_id.validate()?;
        self.source_result_id.validate()?;
        if self.source_revision == 0 {
            return Err(NeonBranchResultError::InvalidInput {
                field: "source_revision",
                reason: InputViolation::OutOfRange,
            });
        }
        Ok(())
    }
}

/// Mission-facing adoption proposal request. No durable adoption is performed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DatabaseResultAdoptionRequest {
    pub source: MissionDatabaseResultSource,
    pub query_proposal: QueryProposal,
    pub query_receipt: QueryReceipt,
}

impl DatabaseResultAdoptionRequest {
    /// Construct a source/query binding before provider verification.
    pub fn new(
        source: MissionDatabaseResultSource,
        query_proposal: QueryProposal,
        query_receipt: QueryReceipt,
    ) -> Result<Self, NeonBranchResultError> {
        source.validate()?;
        query_proposal.validate()?;
        query_receipt.validate()?;
        Ok(Self {
            source,
            query_proposal,
            query_receipt,
        })
    }
}

/// Digest-bound Mission database-result adoption proposal. `durable_adoption`
/// remains false until a Layer 2 host authority is added.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DatabaseResultAdoptionProposal {
    pub operation: NeonOperation,
    pub source: MissionDatabaseResultSource,
    pub scope: NeonScope,
    pub branch_fence: BranchFence,
    pub query_digest: Digest,
    pub parameter_digest: Digest,
    pub schema_digest: Digest,
    pub row_set_digest: Digest,
    pub row_count: u32,
    pub result_bytes: u64,
    pub source_revision_fence: Digest,
    pub provider_version: PluginVersion,
    pub provider_manifest_digest: Digest,
    pub registration_digest: Digest,
    pub effect: ProposalEffect,
    pub verified: bool,
    pub durable_adoption: bool,
    pub evidence_source: EvidenceSource,
    pub native_status: NativeStatus,
    pub proposal_digest: Digest,
    pub idempotency_key: Digest,
}

#[derive(Serialize)]
struct AdoptionProposalIdentity<'a> {
    operation: NeonOperation,
    source: &'a MissionDatabaseResultSource,
    scope: &'a NeonScope,
    branch_fence: &'a BranchFence,
    query_digest: &'a Digest,
    parameter_digest: &'a Digest,
    schema_digest: &'a Digest,
    row_set_digest: &'a Digest,
    row_count: u32,
    result_bytes: u64,
    source_revision_fence: &'a Digest,
    provider_version: PluginVersion,
    provider_manifest_digest: &'a Digest,
    registration_digest: &'a Digest,
    effect: ProposalEffect,
    verified: bool,
    durable_adoption: bool,
}

impl DatabaseResultAdoptionProposal {
    /// Compile a fully fenced adoption proposal from an independently verified
    /// query receipt. This function never stores raw rows.
    pub fn new(
        request: DatabaseResultAdoptionRequest,
        manifest: &NeonProviderManifest,
        registration_digest: Digest,
    ) -> Result<Self, NeonBranchResultError> {
        manifest.validate()?;
        request.source.validate()?;
        request.query_proposal.validate()?;
        request
            .query_receipt
            .matches_proposal(&request.query_proposal)?;
        if request.source.project_id != request.query_proposal.scope.project_id {
            return Err(NeonBranchResultError::ScopeMismatch {
                field: "source.project_id",
            });
        }
        if request.source.mission_id != request.query_proposal.scope.mission_id {
            return Err(NeonBranchResultError::ScopeMismatch {
                field: "source.mission_id",
            });
        }
        if request.query_proposal.provider_manifest_digest != manifest.digest()
            || request.query_receipt.provider_manifest_digest != manifest.digest()
        {
            return Err(NeonBranchResultError::ProviderManifestMismatch {
                field: "adoption.provider_manifest_digest",
            });
        }
        registration_digest.validate("registration_digest")?;
        let source_revision_fence = canonical_digest(&(
            &request.source,
            &request.query_receipt.branch_fence,
            &request.query_receipt.query_digest,
            &request.query_receipt.row_set_digest,
        ));
        let mut proposal = Self {
            operation: NeonOperation::ResultAdoptionProposal,
            source: request.source,
            scope: request.query_proposal.scope.clone(),
            branch_fence: request.query_receipt.branch_fence.clone(),
            query_digest: request.query_receipt.query_digest.clone(),
            parameter_digest: request.query_receipt.parameter_digest.clone(),
            schema_digest: request.query_receipt.schema_digest.clone(),
            row_set_digest: request.query_receipt.row_set_digest.clone(),
            row_count: request.query_receipt.row_count,
            result_bytes: request.query_receipt.result_bytes,
            source_revision_fence,
            provider_version: manifest.version,
            provider_manifest_digest: manifest.digest(),
            registration_digest,
            effect: ProposalEffect::ProposalOnly,
            verified: true,
            durable_adoption: false,
            evidence_source: EvidenceSource::Recording,
            native_status: NativeStatus::BlockedEnv,
            proposal_digest: Digest::from_bytes(&[]),
            idempotency_key: Digest::from_bytes(&[]),
        };
        proposal.proposal_digest = proposal.calculate_digest();
        proposal.idempotency_key = canonical_digest(&(
            &proposal.source,
            &proposal.scope,
            &proposal.branch_fence,
            &proposal.query_digest,
            &proposal.parameter_digest,
            &proposal.schema_digest,
            &proposal.row_set_digest,
            &proposal.source_revision_fence,
            &proposal.registration_digest,
        ));
        proposal.validate()?;
        Ok(proposal)
    }

    fn identity(&self) -> AdoptionProposalIdentity<'_> {
        AdoptionProposalIdentity {
            operation: self.operation,
            source: &self.source,
            scope: &self.scope,
            branch_fence: &self.branch_fence,
            query_digest: &self.query_digest,
            parameter_digest: &self.parameter_digest,
            schema_digest: &self.schema_digest,
            row_set_digest: &self.row_set_digest,
            row_count: self.row_count,
            result_bytes: self.result_bytes,
            source_revision_fence: &self.source_revision_fence,
            provider_version: self.provider_version,
            provider_manifest_digest: &self.provider_manifest_digest,
            registration_digest: &self.registration_digest,
            effect: self.effect,
            verified: self.verified,
            durable_adoption: self.durable_adoption,
        }
    }

    /// Calculate the immutable adoption proposal digest.
    pub fn calculate_digest(&self) -> Digest {
        canonical_digest(&self.identity())
    }

    /// Validate exact Mission, branch, query, result, and registration fences.
    pub fn validate(&self) -> Result<(), NeonBranchResultError> {
        self.source.validate()?;
        self.scope.validate()?;
        self.branch_fence.validate()?;
        if self.scope != self.branch_fence.scope
            || self.source.project_id != self.scope.project_id
            || self.source.mission_id != self.scope.mission_id
        {
            return Err(NeonBranchResultError::ScopeMismatch {
                field: "adoption.scope",
            });
        }
        self.query_digest.validate("query_digest")?;
        self.parameter_digest.validate("parameter_digest")?;
        self.schema_digest.validate("schema_digest")?;
        self.row_set_digest.validate("row_set_digest")?;
        self.source_revision_fence
            .validate("source_revision_fence")?;
        self.provider_version.validate()?;
        self.provider_manifest_digest
            .validate("provider_manifest_digest")?;
        self.registration_digest.validate("registration_digest")?;
        self.proposal_digest.validate("proposal_digest")?;
        self.idempotency_key.validate("idempotency_key")?;
        if self.operation != NeonOperation::ResultAdoptionProposal
            || self.effect != ProposalEffect::ProposalOnly
            || !self.verified
            || self.durable_adoption
            || self.native_status.is_native()
            || self.evidence_source.is_native()
        {
            return Err(NeonBranchResultError::InvalidInput {
                field: "adoption",
                reason: InputViolation::LayerTwoOnly,
            });
        }
        if self.proposal_digest != self.calculate_digest() {
            return Err(NeonBranchResultError::DigestMismatch {
                field: "adoption.proposal_digest",
            });
        }
        let expected_key = canonical_digest(&(
            &self.source,
            &self.scope,
            &self.branch_fence,
            &self.query_digest,
            &self.parameter_digest,
            &self.schema_digest,
            &self.row_set_digest,
            &self.source_revision_fence,
            &self.registration_digest,
        ));
        if self.idempotency_key != expected_key {
            return Err(NeonBranchResultError::DigestMismatch {
                field: "adoption.idempotency_key",
            });
        }
        Ok(())
    }
}

/// Digest-only record of an adoption proposal. It is not a durable adoption.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdoptionProposalReceipt {
    pub operation: NeonOperation,
    pub scope: NeonScope,
    pub branch_fence: BranchFence,
    pub proposal_digest: Digest,
    pub registration_digest: Digest,
    pub provider_version: PluginVersion,
    pub provider_manifest_digest: Digest,
    pub recorded: bool,
    pub durable_adoption: bool,
    pub evidence_source: EvidenceSource,
    pub native_status: NativeStatus,
    pub receipt_digest: Digest,
}

#[derive(Serialize)]
struct AdoptionReceiptIdentity<'a> {
    operation: NeonOperation,
    scope: &'a NeonScope,
    branch_fence: &'a BranchFence,
    proposal_digest: &'a Digest,
    registration_digest: &'a Digest,
    provider_version: PluginVersion,
    provider_manifest_digest: &'a Digest,
    recorded: bool,
    durable_adoption: bool,
    evidence_source: EvidenceSource,
    native_status: NativeStatus,
}

impl AdoptionProposalReceipt {
    /// Record an adoption proposal locally.
    pub fn from_proposal(
        proposal: &DatabaseResultAdoptionProposal,
        manifest: &NeonProviderManifest,
    ) -> Result<Self, NeonBranchResultError> {
        proposal.validate()?;
        manifest.validate()?;
        if proposal.provider_manifest_digest != manifest.digest()
            || proposal.scope != manifest.scope
        {
            return Err(NeonBranchResultError::ProviderManifestMismatch {
                field: "adoption_receipt.manifest",
            });
        }
        let mut receipt = Self {
            operation: NeonOperation::ResultAdoptionProposal,
            scope: proposal.scope.clone(),
            branch_fence: proposal.branch_fence.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            provider_version: manifest.version,
            provider_manifest_digest: manifest.digest(),
            recorded: true,
            durable_adoption: false,
            evidence_source: EvidenceSource::Recording,
            native_status: NativeStatus::BlockedEnv,
            receipt_digest: Digest::from_bytes(&[]),
        };
        receipt.receipt_digest = receipt.calculate_digest();
        receipt.validate()?;
        Ok(receipt)
    }

    fn identity(&self) -> AdoptionReceiptIdentity<'_> {
        AdoptionReceiptIdentity {
            operation: self.operation,
            scope: &self.scope,
            branch_fence: &self.branch_fence,
            proposal_digest: &self.proposal_digest,
            registration_digest: &self.registration_digest,
            provider_version: self.provider_version,
            provider_manifest_digest: &self.provider_manifest_digest,
            recorded: self.recorded,
            durable_adoption: self.durable_adoption,
            evidence_source: self.evidence_source,
            native_status: self.native_status,
        }
    }

    /// Calculate the receipt digest.
    pub fn calculate_digest(&self) -> Digest {
        canonical_digest(&self.identity())
    }

    /// Validate proposal-recording-only semantics.
    pub fn validate(&self) -> Result<(), NeonBranchResultError> {
        self.scope.validate()?;
        self.branch_fence.validate()?;
        self.proposal_digest.validate("proposal_digest")?;
        self.registration_digest.validate("registration_digest")?;
        self.provider_version.validate()?;
        self.provider_manifest_digest
            .validate("provider_manifest_digest")?;
        self.receipt_digest.validate("receipt_digest")?;
        if self.operation != NeonOperation::ResultAdoptionProposal
            || !self.recorded
            || self.durable_adoption
            || self.native_status.is_native()
            || self.evidence_source.is_native()
        {
            return Err(NeonBranchResultError::InvalidInput {
                field: "adoption_receipt",
                reason: InputViolation::LayerTwoOnly,
            });
        }
        if self.receipt_digest != self.calculate_digest() {
            return Err(NeonBranchResultError::DigestMismatch {
                field: "adoption_receipt.receipt_digest",
            });
        }
        Ok(())
    }
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), NeonBranchResultError> {
    if value.is_empty() {
        return Err(NeonBranchResultError::InvalidInput {
            field,
            reason: InputViolation::Empty,
        });
    }
    if value.len() > MAX_IDENTIFIER_BYTES {
        return Err(NeonBranchResultError::InvalidInput {
            field,
            reason: InputViolation::TooLong,
        });
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/')
    }) {
        return Err(NeonBranchResultError::InvalidInput {
            field,
            reason: InputViolation::InvalidIdentifier,
        });
    }
    Ok(())
}

fn validate_bounded_text(
    value: &str,
    field: &'static str,
    max_bytes: usize,
) -> Result<(), NeonBranchResultError> {
    if value.trim().is_empty() {
        return Err(NeonBranchResultError::InvalidInput {
            field,
            reason: InputViolation::Empty,
        });
    }
    if value.len() > max_bytes {
        return Err(NeonBranchResultError::InvalidInput {
            field,
            reason: InputViolation::TooLong,
        });
    }
    if value.chars().any(|character| {
        character == '\0' || (character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    }) {
        return Err(NeonBranchResultError::InvalidInput {
            field,
            reason: InputViolation::InvalidCharacters,
        });
    }
    Ok(())
}

fn validate_branch_point_token(
    value: &str,
    field: &'static str,
) -> Result<(), NeonBranchResultError> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES {
        return Err(NeonBranchResultError::InvalidInput {
            field,
            reason: if value.is_empty() {
                InputViolation::Empty
            } else {
                InputViolation::TooLong
            },
        });
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(byte, b'.' | b'-' | b':' | b'+' | b'/' | b'T' | b'Z' | b'_')
    }) {
        return Err(NeonBranchResultError::InvalidInput {
            field,
            reason: InputViolation::InvalidBranchPoint,
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

#[allow(clippy::too_many_lines)]
fn validate_query_sql(
    sql: &str,
    parameters: &[QueryParameter],
) -> Result<(), NeonBranchResultError> {
    if sql.trim().is_empty() {
        return Err(NeonBranchResultError::InvalidInput {
            field: "sql",
            reason: InputViolation::Empty,
        });
    }
    if sql.len() > MAX_QUERY_BYTES {
        return Err(NeonBranchResultError::InvalidInput {
            field: "sql",
            reason: InputViolation::TooLong,
        });
    }
    let (sanitized, placeholders, saw_single_quote) = scan_sql(sql)?;
    if saw_single_quote {
        return Err(NeonBranchResultError::InvalidInput {
            field: "sql",
            reason: InputViolation::QueryNotParameterized,
        });
    }
    if parameters.is_empty() || placeholders.is_empty() {
        return Err(NeonBranchResultError::InvalidInput {
            field: "sql.parameters",
            reason: InputViolation::QueryNotParameterized,
        });
    }
    if parameters.len() > MAX_QUERY_PARAMETERS {
        return Err(NeonBranchResultError::InvalidInput {
            field: "sql.parameters",
            reason: InputViolation::OutOfRange,
        });
    }
    let mut used = BTreeSet::new();
    for index in placeholders {
        if index == 0 || index > parameters.len() {
            return Err(NeonBranchResultError::InvalidInput {
                field: "sql.parameters",
                reason: InputViolation::InvalidParameterBinding,
            });
        }
        used.insert(index);
    }
    if used.len() != parameters.len() {
        return Err(NeonBranchResultError::InvalidInput {
            field: "sql.parameters",
            reason: InputViolation::InvalidParameterBinding,
        });
    }
    let tokens = sql_tokens(&sanitized);
    let first = tokens.first().copied().unwrap_or_default();
    let select_index = if first == "select" {
        0
    } else if first == "explain" {
        if tokens
            .iter()
            .skip(1)
            .any(|token| *token == "analyze" || *token == "analyse")
        {
            return Err(NeonBranchResultError::InvalidInput {
                field: "sql",
                reason: InputViolation::ForbiddenOperation,
            });
        }
        tokens.iter().position(|token| *token == "select").ok_or(
            NeonBranchResultError::InvalidInput {
                field: "sql",
                reason: InputViolation::QueryNotAllowlisted,
            },
        )?
    } else {
        return Err(NeonBranchResultError::InvalidInput {
            field: "sql",
            reason: InputViolation::QueryNotAllowlisted,
        });
    };
    if first == "explain" && select_index == 0 {
        return Err(NeonBranchResultError::InvalidInput {
            field: "sql",
            reason: InputViolation::QueryNotAllowlisted,
        });
    }
    if tokens.iter().any(|token| {
        FORBIDDEN_SQL_TOKENS
            .iter()
            .any(|forbidden| token == forbidden)
    }) {
        return Err(NeonBranchResultError::InvalidInput {
            field: "sql",
            reason: InputViolation::ForbiddenOperation,
        });
    }
    if !tokens
        .iter()
        .skip(select_index + 1)
        .any(|token| *token == "limit")
    {
        return Err(NeonBranchResultError::InvalidInput {
            field: "sql.limit",
            reason: InputViolation::UnboundedResult,
        });
    }
    parse_limit_upper_bound(sql, parameters).map(|_| ())
}

fn parse_limit_upper_bound(
    sql: &str,
    parameters: &[QueryParameter],
) -> Result<u32, NeonBranchResultError> {
    let (sanitized, _, _) = scan_sql(sql)?;
    let tokens = sql_tokens(&sanitized);
    let limit_position = tokens.iter().rposition(|token| *token == "limit").ok_or(
        NeonBranchResultError::InvalidInput {
            field: "sql.limit",
            reason: InputViolation::UnboundedResult,
        },
    )?;
    let limit_value =
        tokens
            .get(limit_position + 1)
            .copied()
            .ok_or(NeonBranchResultError::InvalidInput {
                field: "sql.limit",
                reason: InputViolation::UnboundedResult,
            })?;
    let limit =
        if let Some(parameter_index) = limit_value.strip_prefix('$') {
            let parameter_index = parameter_index.parse::<usize>().map_err(|_| {
                NeonBranchResultError::InvalidInput {
                    field: "sql.limit",
                    reason: InputViolation::InvalidParameterBinding,
                }
            })?;
            match parameters.get(parameter_index.saturating_sub(1)) {
                Some(QueryParameter::Integer(value)) if *value > 0 => u32::try_from(*value)
                    .map_err(|_| NeonBranchResultError::InvalidInput {
                        field: "sql.limit",
                        reason: InputViolation::OutOfRange,
                    })?,
                _ => {
                    return Err(NeonBranchResultError::InvalidInput {
                        field: "sql.limit",
                        reason: InputViolation::InvalidParameterBinding,
                    });
                }
            }
        } else {
            limit_value
                .parse::<u32>()
                .map_err(|_| NeonBranchResultError::InvalidInput {
                    field: "sql.limit",
                    reason: InputViolation::UnboundedResult,
                })?
        };
    if limit == 0 || limit > MAX_RESULT_ROWS {
        return Err(NeonBranchResultError::InvalidInput {
            field: "sql.limit",
            reason: InputViolation::OutOfRange,
        });
    }
    Ok(limit)
}

#[allow(clippy::too_many_lines)]
fn scan_sql(sql: &str) -> Result<(String, Vec<usize>, bool), NeonBranchResultError> {
    let bytes = sql.as_bytes();
    let mut sanitized = String::with_capacity(sql.len());
    let mut placeholders = Vec::new();
    let mut index = 0;
    let mut saw_single_quote = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'\'' {
            saw_single_quote = true;
            sanitized.push(' ');
            index += 1;
            while index < bytes.len() {
                if bytes[index] == b'\'' {
                    sanitized.push(' ');
                    if bytes.get(index + 1) == Some(&b'\'') {
                        sanitized.push(' ');
                        index += 2;
                    } else {
                        index += 1;
                        break;
                    }
                } else {
                    sanitized.push(' ');
                    index += 1;
                }
            }
            continue;
        }
        if byte == b'"' {
            sanitized.push(' ');
            index += 1;
            while index < bytes.len() {
                if bytes[index] == b'"' {
                    sanitized.push(' ');
                    if bytes.get(index + 1) == Some(&b'"') {
                        sanitized.push(' ');
                        index += 2;
                    } else {
                        index += 1;
                        break;
                    }
                } else {
                    sanitized.push(' ');
                    index += 1;
                }
            }
            continue;
        }
        if bytes.get(index..index + 2) == Some(b"--")
            || bytes.get(index..index + 2) == Some(b"/*")
            || bytes.get(index..index + 2) == Some(b"*/")
        {
            return Err(NeonBranchResultError::InvalidInput {
                field: "sql",
                reason: InputViolation::CommentNotAllowed,
            });
        }
        if byte == b';' {
            return Err(NeonBranchResultError::InvalidInput {
                field: "sql",
                reason: InputViolation::MultiStatement,
            });
        }
        if byte == b'$' {
            let start = index + 1;
            if start >= bytes.len() || !bytes[start].is_ascii_digit() {
                return Err(NeonBranchResultError::InvalidInput {
                    field: "sql",
                    reason: InputViolation::InvalidParameterBinding,
                });
            }
            let mut end = start;
            while end < bytes.len() && bytes[end].is_ascii_digit() {
                end += 1;
            }
            let number = std::str::from_utf8(&bytes[start..end])
                .expect("ASCII positional placeholder")
                .parse::<usize>()
                .map_err(|_| NeonBranchResultError::InvalidInput {
                    field: "sql.parameters",
                    reason: InputViolation::InvalidParameterBinding,
                })?;
            placeholders.push(number);
            sanitized.push('$');
            sanitized.push_str(&number.to_string());
            index = end;
            continue;
        }
        if byte == b'?' || byte == b'{' || byte == b'}' {
            return Err(NeonBranchResultError::InvalidInput {
                field: "sql",
                reason: InputViolation::InvalidParameterBinding,
            });
        }
        if byte.is_ascii_control() && !byte.is_ascii_whitespace() {
            return Err(NeonBranchResultError::InvalidInput {
                field: "sql",
                reason: InputViolation::InvalidCharacters,
            });
        }
        sanitized.push(byte.to_ascii_lowercase() as char);
        index += 1;
    }
    Ok((sanitized, placeholders, saw_single_quote))
}

fn sql_tokens(sql: &str) -> Vec<&str> {
    sql.split(|character: char| {
        !(character.is_ascii_alphanumeric() || matches!(character, '_' | '$'))
    })
    .filter(|token| !token.is_empty())
    .collect()
}

#[derive(Serialize)]
struct QueryProposalIdentity<'a> {
    operation: NeonOperation,
    scope: &'a NeonScope,
    branch_fence: &'a BranchFence,
    query: &'a ParameterizedQuery,
    budget: QueryBudget,
    canonicalization: RowSetCanonicalization,
    expected_schema_digest: &'a Option<Digest>,
    provider_version: PluginVersion,
    provider_manifest_digest: &'a Digest,
    effect: ProposalEffect,
}

impl QueryProposal {
    /// Compile a query proposal from a typed request and manifest.
    pub fn new(
        request: QueryProposalRequest,
        manifest: &NeonProviderManifest,
    ) -> Result<Self, NeonBranchResultError> {
        manifest.validate()?;
        request.validate()?;
        if request.scope != manifest.scope {
            return Err(NeonBranchResultError::ScopeMismatch {
                field: "query_proposal.scope",
            });
        }
        request.query.validate()?;
        request.budget.validate()?;
        if request.query.limit_upper_bound()? > request.budget.max_rows {
            return Err(NeonBranchResultError::InvalidInput {
                field: "query_budget.max_rows",
                reason: InputViolation::UnboundedResult,
            });
        }
        let branch_fence = request.scope.branch_fence(request.point_in_time)?;
        let mut proposal = Self {
            operation: NeonOperation::QueryProposal,
            scope: request.scope,
            branch_fence,
            query: request.query,
            budget: request.budget,
            canonicalization: request.canonicalization,
            expected_schema_digest: request.expected_schema_digest,
            provider_version: manifest.version,
            provider_manifest_digest: manifest.digest(),
            effect: ProposalEffect::ProposalOnly,
            evidence_source: EvidenceSource::Recording,
            native_status: NativeStatus::BlockedEnv,
            proposal_digest: Digest::from_bytes(&[]),
            idempotency_key: Digest::from_bytes(&[]),
        };
        proposal.proposal_digest = proposal.calculate_digest();
        proposal.idempotency_key = canonical_digest(&(
            &proposal.scope,
            &proposal.branch_fence,
            &proposal.query.query_digest,
            &proposal.query.parameter_digest,
            &proposal.proposal_digest,
        ));
        proposal.validate()?;
        Ok(proposal)
    }

    fn identity(&self) -> QueryProposalIdentity<'_> {
        QueryProposalIdentity {
            operation: self.operation,
            scope: &self.scope,
            branch_fence: &self.branch_fence,
            query: &self.query,
            budget: self.budget,
            canonicalization: self.canonicalization,
            expected_schema_digest: &self.expected_schema_digest,
            provider_version: self.provider_version,
            provider_manifest_digest: &self.provider_manifest_digest,
            effect: self.effect,
        }
    }

    /// Calculate the immutable proposal digest.
    pub fn calculate_digest(&self) -> Digest {
        canonical_digest(&self.identity())
    }

    /// Validate the query, scope, budget, and all proposal digests.
    pub fn validate(&self) -> Result<(), NeonBranchResultError> {
        self.scope.validate()?;
        self.branch_fence.validate()?;
        if self.scope != self.branch_fence.scope {
            return Err(NeonBranchResultError::ScopeMismatch {
                field: "query_proposal.branch_fence",
            });
        }
        self.query.validate()?;
        self.budget.validate()?;
        if self.query.limit_upper_bound()? > self.budget.max_rows {
            return Err(NeonBranchResultError::InvalidInput {
                field: "query_budget.max_rows",
                reason: InputViolation::UnboundedResult,
            });
        }
        if let Some(digest) = &self.expected_schema_digest {
            digest.validate("expected_schema_digest")?;
        }
        self.provider_version.validate()?;
        self.provider_manifest_digest
            .validate("provider_manifest_digest")?;
        self.proposal_digest.validate("proposal_digest")?;
        self.idempotency_key.validate("idempotency_key")?;
        if self.operation != NeonOperation::QueryProposal
            || self.effect != ProposalEffect::ProposalOnly
            || self.native_status.is_native()
            || self.evidence_source.is_native()
        {
            return Err(NeonBranchResultError::NativeAuthority);
        }
        if self.proposal_digest != self.calculate_digest() {
            return Err(NeonBranchResultError::DigestMismatch {
                field: "query_proposal.proposal_digest",
            });
        }
        let expected_key = canonical_digest(&(
            &self.scope,
            &self.branch_fence,
            &self.query.query_digest,
            &self.query.parameter_digest,
            &self.proposal_digest,
        ));
        if self.idempotency_key != expected_key {
            return Err(NeonBranchResultError::DigestMismatch {
                field: "query_proposal.idempotency_key",
            });
        }
        Ok(())
    }
}

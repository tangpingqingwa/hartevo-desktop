use std::collections::BTreeSet;
use std::fmt::{self, Write as _};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};

use crate::error::ZoteroEvidenceError;

/// Contract/schema identifier for the Layer 1 Zotero evidence boundary.
pub const ZOTERO_EVIDENCE_SCHEMA_VERSION: &str = "hartevo.zotero-evidence/v1";
/// Version of the exact EXT-ZOTERO-01 Layer 1 contract.
pub const ZOTERO_EVIDENCE_CONTRACT_VERSION: &str = "EXT-ZOTERO-01-L1/v1";
/// Stable provider identifier used by registration and Mission bindings.
pub const ZOTERO_PROVIDER_ID: &str = "zotero.evidence";
/// Stable plugin version for this independently testable root.
pub const ZOTERO_PLUGIN_VERSION: PluginVersion = PluginVersion::new(1, 0, 0);
/// Web API v3 required by this contract.
pub const ZOTERO_WEB_API_VERSION: u8 = 3;
/// Official Web API base URL. Layer 1 only plans requests; it does not call it.
pub const ZOTERO_WEB_API_BASE_URL: &str = "https://api.zotero.org";
/// Official local API base URL. Local provenance is never external Connected.
pub const ZOTERO_LOCAL_API_BASE_URL: &str = "http://localhost:23119/api";
/// Maximum number of objects in one bounded evidence page.
pub const MAX_PAGE_SIZE: u16 = 100;
/// Maximum number of object records admitted to a single response.
pub const MAX_RESPONSE_ITEMS: usize = 100;
/// Maximum number of attachment references retained in one item observation.
pub const MAX_ATTACHMENT_REFERENCES: u16 = 128;
/// Maximum bytes retained for a formatted citation preview.
pub const MAX_FORMATTED_CITATION_BYTES: usize = 8 * 1024;
/// Maximum bytes admitted for a digest input field.
pub const MAX_DIGEST_INPUT_BYTES: usize = 64 * 1024;
/// Maximum provider backoff represented by the bounded seam.
pub const MAX_BACKOFF_SECONDS: u64 = 86_400;

/// Lowercase SHA-256 digest used at all receipt and registration boundaries.
pub type Digest = String;

/// Hash a serializable, canonical contract value with SHA-256.
pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("Zotero contract values must serialize");
    sha256_digest(&bytes)
}

/// Hash bytes with lowercase hexadecimal output.
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(output, "{byte:02x}").expect("writing a String cannot fail");
    }
    output
}

pub(crate) fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn validate_text(
    value: &str,
    field: &'static str,
    max_bytes: usize,
) -> Result<(), ZoteroEvidenceError> {
    if value.trim().is_empty()
        || value.len() > max_bytes
        || value.chars().any(|character| {
            character == '\0'
                || (character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
        })
    {
        return Err(ZoteroEvidenceError::InvalidInput {
            field,
            reason: format!("must be non-empty, bounded to {max_bytes} bytes, and content-safe"),
        });
    }
    Ok(())
}

pub(crate) fn validate_digest(value: &str, field: &'static str) -> Result<(), ZoteroEvidenceError> {
    if is_sha256(value) {
        Ok(())
    } else {
        Err(ZoteroEvidenceError::InvalidDigest { field })
    }
}

macro_rules! text_identifier {
    ($name:ident, $field:literal, $max:expr) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ZoteroEvidenceError> {
                let value = value.into();
                if value.trim().is_empty()
                    || value.len() > $max
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
                {
                    return Err(ZoteroEvidenceError::InvalidInput {
                        field: $field,
                        reason: String::from("must contain only bounded identifier characters"),
                    });
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn validate(&self) -> Result<(), ZoteroEvidenceError> {
                Self::new(self.0.clone()).map(|_| ())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = ZoteroEvidenceError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }
    };
}

text_identifier!(ZoteroCollectionKey, "collection_key", 32);
text_identifier!(ZoteroItemKey, "item_key", 32);
text_identifier!(MissionId, "mission_id", 128);
text_identifier!(ClaimId, "claim_id", 128);
text_identifier!(ResultId, "result_id", 128);

/// Zotero user IDs are numeric API path components.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ZoteroUserId(u64);

impl ZoteroUserId {
    pub fn new(value: u64) -> Result<Self, ZoteroEvidenceError> {
        if value == 0 {
            return Err(ZoteroEvidenceError::InvalidInput {
                field: "user_id",
                reason: String::from("must be a non-zero Zotero user ID"),
            });
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for ZoteroUserId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Zotero group IDs are numeric API path components.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ZoteroGroupId(u64);

impl ZoteroGroupId {
    pub fn new(value: u64) -> Result<Self, ZoteroEvidenceError> {
        if value == 0 {
            return Err(ZoteroEvidenceError::InvalidInput {
                field: "group_id",
                reason: String::from("must be a non-zero Zotero group ID"),
            });
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for ZoteroGroupId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Exact library identity. User and group libraries have independent version
/// and key spaces and are never interchangeable.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ZoteroLibraryId {
    User { user_id: ZoteroUserId },
    Group { group_id: ZoteroGroupId },
}

impl ZoteroLibraryId {
    pub fn user(user_id: ZoteroUserId) -> Self {
        Self::User { user_id }
    }

    pub fn group(group_id: ZoteroGroupId) -> Self {
        Self::Group { group_id }
    }

    pub fn user_id(&self) -> Option<ZoteroUserId> {
        match self {
            Self::User { user_id } => Some(*user_id),
            Self::Group { .. } => None,
        }
    }

    pub fn group_id(&self) -> Option<ZoteroGroupId> {
        match self {
            Self::User { .. } => None,
            Self::Group { group_id } => Some(*group_id),
        }
    }

    pub fn path_prefix(&self) -> String {
        match self {
            Self::User { user_id } => format!("/users/{user_id}"),
            Self::Group { group_id } => format!("/groups/{group_id}"),
        }
    }
}

impl fmt::Display for ZoteroLibraryId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::User { user_id } => write!(formatter, "user:{user_id}"),
            Self::Group { group_id } => write!(formatter, "group:{group_id}"),
        }
    }
}

/// Exact Mission and Zotero object scope carried by every service request.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ZoteroEvidenceScope {
    pub library: ZoteroLibraryId,
    pub collection_key: Option<ZoteroCollectionKey>,
    pub item_key: Option<ZoteroItemKey>,
    pub mission_id: MissionId,
}

impl ZoteroEvidenceScope {
    pub fn new(
        library: ZoteroLibraryId,
        collection_key: Option<ZoteroCollectionKey>,
        item_key: Option<ZoteroItemKey>,
        mission_id: MissionId,
    ) -> Result<Self, ZoteroEvidenceError> {
        mission_id.validate()?;
        if let Some(collection_key) = &collection_key {
            collection_key.validate()?;
        }
        if let Some(item_key) = &item_key {
            item_key.validate()?;
        }
        Ok(Self {
            library,
            collection_key,
            item_key,
            mission_id,
        })
    }

    pub fn library(
        library: ZoteroLibraryId,
        mission_id: MissionId,
    ) -> Result<Self, ZoteroEvidenceError> {
        Self::new(library, None, None, mission_id)
    }

    pub fn collection(
        library: ZoteroLibraryId,
        collection_key: ZoteroCollectionKey,
        mission_id: MissionId,
    ) -> Result<Self, ZoteroEvidenceError> {
        Self::new(library, Some(collection_key), None, mission_id)
    }

    pub fn item(
        library: ZoteroLibraryId,
        collection_key: Option<ZoteroCollectionKey>,
        item_key: ZoteroItemKey,
        mission_id: MissionId,
    ) -> Result<Self, ZoteroEvidenceError> {
        Self::new(library, collection_key, Some(item_key), mission_id)
    }

    pub fn validate(&self) -> Result<(), ZoteroEvidenceError> {
        Self::new(
            self.library.clone(),
            self.collection_key.clone(),
            self.item_key.clone(),
            self.mission_id.clone(),
        )
        .map(|_| ())
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    pub fn is_item_bound(&self) -> bool {
        self.item_key.is_some()
    }
}

/// Opaque, monotonic provider version. The integer is never treated as a
/// timestamp or incremented by Hartevo.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ZoteroVersion(u64);

impl ZoteroVersion {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for ZoteroVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Plugin/provider semantic version bound into registration and Mission
/// evidence proposals.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
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
}

impl fmt::Display for PluginVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Explicit API version carried by every transport request plan.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ZoteroApiVersion(u8);

impl ZoteroApiVersion {
    pub const fn v3() -> Self {
        Self(ZOTERO_WEB_API_VERSION)
    }

    pub const fn get(self) -> u8 {
        self.0
    }
}

/// The two production request-planning seams plus deterministic test seams.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ZoteroTransportKind {
    WebApiV3,
    OfficialLocalApiV3,
    Fixture,
    Recording,
    Loopback,
}

/// Provenance is intentionally distinct from transport. Fixture, recording,
/// and loopback observations cannot become a Connected/native claim.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ZoteroProvenance {
    WebApiV3,
    OfficialLocalApiV3,
    Fixture,
    Recording,
    Loopback,
}

impl ZoteroProvenance {
    pub const fn transport_kind(self) -> ZoteroTransportKind {
        match self {
            Self::WebApiV3 => ZoteroTransportKind::WebApiV3,
            Self::OfficialLocalApiV3 => ZoteroTransportKind::OfficialLocalApiV3,
            Self::Fixture => ZoteroTransportKind::Fixture,
            Self::Recording => ZoteroTransportKind::Recording,
            Self::Loopback => ZoteroTransportKind::Loopback,
        }
    }
}

/// Layer 1 deliberately has one terminal authority state: no live/native
/// or external Connected claim is possible from this crate.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NativeStatus {
    BlockedEnv,
}

/// Authentication is a mode, never credential material. Private access is
/// supplied only through an opaque SecretReference at the provider boundary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ZoteroAuthenticationMode {
    PublicRead,
    SecretReference,
    LocalReadNoAuthentication,
}

/// Typed capabilities registered for the exact scope.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ZoteroCapability {
    LibraryProbe,
    CollectionRead,
    ItemRead,
    CitationMetadataRead,
    ResearchEvidenceProposal,
}

/// Visibility discovered by a deterministic probe.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ZoteroLibraryVisibility {
    Public,
    Private,
    Unknown,
}

/// Access loss remains distinct from a missing object.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ZoteroAccessLoss {
    LocalApiDisabled,
    PrivateLibraryWithoutSecret,
    SecretRejected,
    ScopeRevoked,
    Unknown,
}

/// Typed conflict classes retain only safe status metadata.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ZoteroConflictReason {
    LibraryLocked,
    AmbiguousObject,
    DuplicateKey,
    Unknown,
}

/// Typed precondition classes are retained for future Layer 2 writes; Layer 1
/// never executes a write using them.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ZoteroPreconditionKind {
    IfModifiedSinceVersion,
    IfUnmodifiedSinceVersion,
    WriteToken,
    ServerId,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ZoteroPreconditionFailure {
    VersionDrift,
    ServerIdMismatch,
    WriteTokenReplayed,
    Unknown,
}

/// Object kinds are used in typed 404/deletion diagnostics.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ZoteroObjectKind {
    Library,
    Collection,
    Item,
}

/// Safe object identity retained in an error; no provider body is copied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ZoteroObjectIdentity {
    Library(ZoteroLibraryId),
    Collection(ZoteroCollectionKey),
    Item(ZoteroItemKey),
    Unknown,
}

/// An optional local server partition identifier. It is not a credential.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ZoteroServerId(String);

impl ZoteroServerId {
    pub fn new(value: impl Into<String>) -> Result<Self, ZoteroEvidenceError> {
        let value = value.into();
        validate_text(&value, "Zotero server ID", 128)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        sha256_digest(self.0.as_bytes())
    }
}

/// Versioned, reversible registration bound to one exact scope and digest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ZoteroRegistration {
    pub registration_id: String,
    pub version: PluginVersion,
    pub contract_version: String,
    pub provider_version: PluginVersion,
    pub scope_digest: Digest,
    pub capabilities: BTreeSet<ZoteroCapability>,
    pub reversible: bool,
    pub enabled: bool,
    pub registration_digest: Digest,
}

impl ZoteroRegistration {
    pub fn layer1(scope: &ZoteroEvidenceScope) -> Self {
        let mut registration = Self {
            registration_id: String::from(ZOTERO_PROVIDER_ID),
            version: ZOTERO_PLUGIN_VERSION,
            contract_version: String::from(ZOTERO_EVIDENCE_CONTRACT_VERSION),
            provider_version: ZOTERO_PLUGIN_VERSION,
            scope_digest: scope.digest(),
            capabilities: BTreeSet::from([
                ZoteroCapability::LibraryProbe,
                ZoteroCapability::CollectionRead,
                ZoteroCapability::ItemRead,
                ZoteroCapability::CitationMetadataRead,
                ZoteroCapability::ResearchEvidenceProposal,
            ]),
            reversible: true,
            enabled: true,
            registration_digest: String::new(),
        };
        registration.registration_digest = registration.calculate_digest();
        registration
    }

    pub fn calculate_digest(&self) -> Digest {
        let mut unsigned = self.clone();
        unsigned.registration_digest.clear();
        canonical_digest(&unsigned)
    }

    pub fn validate(&self, scope: &ZoteroEvidenceScope) -> Result<(), ZoteroEvidenceError> {
        if self.registration_id != ZOTERO_PROVIDER_ID
            || self.version != ZOTERO_PLUGIN_VERSION
            || self.provider_version != ZOTERO_PLUGIN_VERSION
            || self.contract_version != ZOTERO_EVIDENCE_CONTRACT_VERSION
            || self.scope_digest != scope.digest()
            || !self.reversible
            || self.capabilities.len() != 5
            || self.registration_digest != self.calculate_digest()
        {
            return Err(ZoteroEvidenceError::InvalidProviderManifest);
        }
        validate_digest(&self.registration_digest, "registration_digest")
    }

    pub fn revoke(&self) -> Result<Self, ZoteroEvidenceError> {
        if !self.reversible {
            return Err(ZoteroEvidenceError::RegistrationRevoked);
        }
        let mut revoked = self.clone();
        revoked.enabled = false;
        revoked.registration_digest = revoked.calculate_digest();
        Ok(revoked)
    }

    pub fn reactivate(&self, scope: &ZoteroEvidenceScope) -> Result<Self, ZoteroEvidenceError> {
        let mut active = self.clone();
        active.enabled = true;
        active.scope_digest = scope.digest();
        active.registration_digest = active.calculate_digest();
        active.validate(scope)?;
        Ok(active)
    }
}

/// Provider registration/manifest. Its digest is checked before every service
/// operation, making replacement and revocation reversible and fail-closed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ZoteroProviderManifest {
    pub provider_id: String,
    pub provider_version: PluginVersion,
    pub contract_version: String,
    pub api_version: u8,
    pub transport: ZoteroTransportKind,
    pub provenance: ZoteroProvenance,
    pub scope: ZoteroEvidenceScope,
    pub scope_digest: Digest,
    pub authentication: ZoteroAuthenticationMode,
    pub native_status: NativeStatus,
    pub registration: ZoteroRegistration,
    pub manifest_digest: Digest,
}

impl ZoteroProviderManifest {
    pub fn layer1(scope: ZoteroEvidenceScope) -> Result<Self, ZoteroEvidenceError> {
        Self::layer1_with_transport(
            scope,
            ZoteroTransportKind::WebApiV3,
            ZoteroProvenance::WebApiV3,
            ZoteroAuthenticationMode::PublicRead,
        )
    }

    pub fn local_layer1(scope: ZoteroEvidenceScope) -> Result<Self, ZoteroEvidenceError> {
        Self::layer1_with_transport(
            scope,
            ZoteroTransportKind::OfficialLocalApiV3,
            ZoteroProvenance::OfficialLocalApiV3,
            ZoteroAuthenticationMode::LocalReadNoAuthentication,
        )
    }

    pub fn fixture(scope: ZoteroEvidenceScope) -> Result<Self, ZoteroEvidenceError> {
        Self::layer1_with_transport(
            scope,
            ZoteroTransportKind::Fixture,
            ZoteroProvenance::Fixture,
            ZoteroAuthenticationMode::PublicRead,
        )
    }

    pub fn recording(scope: ZoteroEvidenceScope) -> Result<Self, ZoteroEvidenceError> {
        Self::layer1_with_transport(
            scope,
            ZoteroTransportKind::Recording,
            ZoteroProvenance::Recording,
            ZoteroAuthenticationMode::PublicRead,
        )
    }

    pub fn loopback(scope: ZoteroEvidenceScope) -> Result<Self, ZoteroEvidenceError> {
        Self::layer1_with_transport(
            scope,
            ZoteroTransportKind::Loopback,
            ZoteroProvenance::Loopback,
            ZoteroAuthenticationMode::PublicRead,
        )
    }

    pub fn private_layer1(scope: ZoteroEvidenceScope) -> Result<Self, ZoteroEvidenceError> {
        Self::layer1_with_transport(
            scope,
            ZoteroTransportKind::WebApiV3,
            ZoteroProvenance::WebApiV3,
            ZoteroAuthenticationMode::SecretReference,
        )
    }

    pub fn layer1_with_transport(
        scope: ZoteroEvidenceScope,
        transport: ZoteroTransportKind,
        provenance: ZoteroProvenance,
        authentication: ZoteroAuthenticationMode,
    ) -> Result<Self, ZoteroEvidenceError> {
        scope.validate()?;
        if transport != provenance.transport_kind() {
            return Err(ZoteroEvidenceError::InvalidProviderManifest);
        }
        let registration = ZoteroRegistration::layer1(&scope);
        let scope_digest = scope.digest();
        let mut manifest = Self {
            provider_id: String::from(ZOTERO_PROVIDER_ID),
            provider_version: ZOTERO_PLUGIN_VERSION,
            contract_version: String::from(ZOTERO_EVIDENCE_CONTRACT_VERSION),
            api_version: ZOTERO_WEB_API_VERSION,
            transport,
            provenance,
            scope,
            scope_digest,
            authentication,
            native_status: NativeStatus::BlockedEnv,
            registration,
            manifest_digest: String::new(),
        };
        manifest.manifest_digest = manifest.calculate_digest();
        Ok(manifest)
    }

    pub fn calculate_digest(&self) -> Digest {
        let mut unsigned = self.clone();
        unsigned.manifest_digest.clear();
        canonical_digest(&unsigned)
    }

    pub fn validate(&self) -> Result<(), ZoteroEvidenceError> {
        if self.provider_id != ZOTERO_PROVIDER_ID
            || self.provider_version != ZOTERO_PLUGIN_VERSION
            || self.contract_version != ZOTERO_EVIDENCE_CONTRACT_VERSION
            || self.api_version != ZOTERO_WEB_API_VERSION
            || self.transport != self.provenance.transport_kind()
            || self.native_status != NativeStatus::BlockedEnv
            || self.scope_digest != self.scope.digest()
            || self.manifest_digest != self.calculate_digest()
            || !self.registration.enabled
        {
            return Err(ZoteroEvidenceError::InvalidProviderManifest);
        }
        self.scope.validate()?;
        self.registration.validate(&self.scope)
    }

    pub fn revoked(&self) -> Result<Self, ZoteroEvidenceError> {
        let mut revoked = self.clone();
        revoked.registration = self.registration.revoke()?;
        revoked.manifest_digest = revoked.calculate_digest();
        Ok(revoked)
    }

    pub fn reactivated(&self) -> Result<Self, ZoteroEvidenceError> {
        let mut active = self.clone();
        active.registration = self.registration.reactivate(&self.scope)?;
        active.manifest_digest = active.calculate_digest();
        active.validate()?;
        Ok(active)
    }
}

/// A bounded page request. Zotero permits larger/unbounded local responses,
/// but the Hartevo seam never admits them.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ZoteroPage {
    pub limit: u16,
    pub start: u32,
}

impl ZoteroPage {
    pub fn new(limit: u16, start: u32) -> Result<Self, ZoteroEvidenceError> {
        if !(1..=MAX_PAGE_SIZE).contains(&limit) {
            return Err(ZoteroEvidenceError::InvalidInput {
                field: "page.limit",
                reason: format!("must be between 1 and {MAX_PAGE_SIZE}"),
            });
        }
        Ok(Self { limit, start })
    }

    pub const fn first() -> Self {
        Self {
            limit: 100,
            start: 0,
        }
    }
}

/// A conditional read fence. There is no conditional-write method in Layer 1.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ZoteroConditionalRequest {
    pub if_modified_since_version: ZoteroVersion,
    pub scope_digest: Digest,
}

impl ZoteroConditionalRequest {
    pub fn new(
        version: ZoteroVersion,
        scope: &ZoteroEvidenceScope,
    ) -> Result<Self, ZoteroEvidenceError> {
        Ok(Self {
            if_modified_since_version: version,
            scope_digest: scope.digest(),
        })
    }

    pub fn validate_for(&self, scope: &ZoteroEvidenceScope) -> Result<(), ZoteroEvidenceError> {
        if self.scope_digest == scope.digest() {
            Ok(())
        } else {
            Err(ZoteroEvidenceError::ConditionalScopeMismatch)
        }
    }
}

/// A since cursor is bound to library identity, scope, and provenance. Local
/// and Web API versions are always partitioned even when keys look identical.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ZoteroSinceCursor {
    pub library: ZoteroLibraryId,
    pub version: ZoteroVersion,
    pub scope_digest: Digest,
    pub provenance: ZoteroProvenance,
    pub cursor_identity_digest: Digest,
}

impl ZoteroSinceCursor {
    pub fn new(
        library: ZoteroLibraryId,
        version: ZoteroVersion,
        scope: &ZoteroEvidenceScope,
        provenance: ZoteroProvenance,
    ) -> Result<Self, ZoteroEvidenceError> {
        if library != scope.library {
            return Err(ZoteroEvidenceError::CursorIdentityMismatch);
        }
        let scope_digest = scope.digest();
        let cursor_identity_digest =
            canonical_digest(&(&library, version, &scope_digest, provenance));
        Ok(Self {
            library,
            version,
            scope_digest,
            provenance,
            cursor_identity_digest,
        })
    }

    pub fn validate_for(
        &self,
        scope: &ZoteroEvidenceScope,
        provenance: ZoteroProvenance,
    ) -> Result<(), ZoteroEvidenceError> {
        let expected = Self::new(scope.library.clone(), self.version, scope, provenance)?;
        if self.library != scope.library
            || self.scope_digest != scope.digest()
            || self.provenance != provenance
            || self.cursor_identity_digest != expected.cursor_identity_digest
        {
            return Err(ZoteroEvidenceError::CursorIdentityMismatch);
        }
        Ok(())
    }
}

/// Read endpoint target, kept distinct from the exact registered scope.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case", tag = "target")]
pub enum ZoteroReadTarget {
    Library,
    Collection { collection_key: ZoteroCollectionKey },
    Item { item_key: ZoteroItemKey },
}

impl ZoteroReadTarget {
    pub const fn kind(&self) -> ZoteroObjectKind {
        match self {
            Self::Library => ZoteroObjectKind::Library,
            Self::Collection { .. } => ZoteroObjectKind::Collection,
            Self::Item { .. } => ZoteroObjectKind::Item,
        }
    }

    pub fn validate_for(&self, scope: &ZoteroEvidenceScope) -> Result<(), ZoteroEvidenceError> {
        match self {
            Self::Library => Ok(()),
            Self::Collection { collection_key } => {
                if scope.collection_key.as_ref() == Some(collection_key) {
                    Ok(())
                } else {
                    Err(ZoteroEvidenceError::ScopeMismatch)
                }
            }
            Self::Item { item_key } => {
                if scope.item_key.as_ref() == Some(item_key) {
                    Ok(())
                } else {
                    Err(ZoteroEvidenceError::ScopeMismatch)
                }
            }
        }
    }
}

/// Selection flags remain bounded and explicit; raw full text is never a
/// selectable Layer 1 output.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ZoteroReadSelection {
    pub attachment_metadata: bool,
    pub full_text_references: bool,
    pub citation_metadata: bool,
}

impl ZoteroReadSelection {
    pub const fn evidence() -> Self {
        Self {
            attachment_metadata: true,
            full_text_references: true,
            citation_metadata: true,
        }
    }
}

/// Typed bounded read request used by both production transport seams.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ZoteroReadRequest {
    pub scope: ZoteroEvidenceScope,
    pub target: ZoteroReadTarget,
    pub page: ZoteroPage,
    pub since: Option<ZoteroSinceCursor>,
    pub conditional: Option<ZoteroConditionalRequest>,
    pub selection: ZoteroReadSelection,
    pub server_id: Option<ZoteroServerId>,
}

impl ZoteroReadRequest {
    pub fn new(
        scope: ZoteroEvidenceScope,
        target: ZoteroReadTarget,
        page: ZoteroPage,
        since: Option<ZoteroSinceCursor>,
        conditional: Option<ZoteroConditionalRequest>,
    ) -> Result<Self, ZoteroEvidenceError> {
        scope.validate()?;
        target.validate_for(&scope)?;
        if let Some(cursor) = &since
            && (cursor.library != scope.library || cursor.scope_digest != scope.digest())
        {
            return Err(ZoteroEvidenceError::CursorIdentityMismatch);
        }
        if let Some(conditional) = &conditional {
            conditional.validate_for(&scope)?;
        }
        Ok(Self {
            scope,
            target,
            page,
            since,
            conditional,
            selection: ZoteroReadSelection::evidence(),
            server_id: None,
        })
    }

    #[must_use]
    pub fn with_server_id(mut self, server_id: ZoteroServerId) -> Self {
        self.server_id = Some(server_id);
        self
    }
}

/// A bounded library capability probe request.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ZoteroCapabilityProbeRequest {
    pub scope: ZoteroEvidenceScope,
}

impl ZoteroCapabilityProbeRequest {
    pub fn new(scope: ZoteroEvidenceScope) -> Result<Self, ZoteroEvidenceError> {
        scope.validate()?;
        Ok(Self { scope })
    }
}

/// CSL style identifiers are kept bounded and content-safe.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ZoteroCitationStyle(String);

impl ZoteroCitationStyle {
    pub fn new(value: impl Into<String>) -> Result<Self, ZoteroEvidenceError> {
        let value = value.into();
        validate_text(&value, "citation_style", 256)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// CSL locale identifiers are explicit so locale drift is detectable.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ZoteroCitationLocale(String);

impl ZoteroCitationLocale {
    pub fn new(value: impl Into<String>) -> Result<Self, ZoteroEvidenceError> {
        let value = value.into();
        validate_text(&value, "citation_locale", 64)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Citation/export modes supported by the bounded read seam.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ZoteroCitationFormat {
    Citation,
    Bibliography,
    CslJsonMetadata,
}

/// Citation request requires the exact item scope and a style/locale fence.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ZoteroCitationRequest {
    pub scope: ZoteroEvidenceScope,
    pub item_key: ZoteroItemKey,
    pub style: ZoteroCitationStyle,
    pub locale: ZoteroCitationLocale,
    pub format: ZoteroCitationFormat,
    pub server_id: Option<ZoteroServerId>,
}

impl ZoteroCitationRequest {
    pub fn new(
        scope: ZoteroEvidenceScope,
        style: ZoteroCitationStyle,
        locale: ZoteroCitationLocale,
        format: ZoteroCitationFormat,
    ) -> Result<Self, ZoteroEvidenceError> {
        scope.validate()?;
        let item_key = scope
            .item_key
            .clone()
            .ok_or(ZoteroEvidenceError::InvalidScope)?;
        Ok(Self {
            scope,
            item_key,
            style,
            locale,
            format,
            server_id: None,
        })
    }

    #[must_use]
    pub fn with_server_id(mut self, server_id: ZoteroServerId) -> Self {
        self.server_id = Some(server_id);
        self
    }
}

/// HTTP method is part of the request plan, even though Layer 1 emits only
/// GET plans.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ZoteroHttpMethod {
    Get,
}

/// Typed operation passed to a transport planning seam.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ZoteroTransportOperation {
    Probe(ZoteroCapabilityProbeRequest),
    Read(ZoteroReadRequest),
    Citation(ZoteroCitationRequest),
}

/// Canonical creator/title/date/identifier metadata digests. Raw values are
/// accepted only long enough to hash them and are not retained here.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[allow(clippy::struct_field_names)]
pub struct ZoteroMetadataDigests {
    pub creators_digest: Digest,
    pub title_digest: Digest,
    pub date_digest: Digest,
    pub identifier_digest: Digest,
    pub metadata_digest: Digest,
}

impl ZoteroMetadataDigests {
    pub fn from_parts(
        creators: &str,
        title: &str,
        date: &str,
        identifier: &str,
    ) -> Result<Self, ZoteroEvidenceError> {
        for (field, value) in [
            ("creators", creators),
            ("title", title),
            ("date", date),
            ("identifier", identifier),
        ] {
            if value.len() > MAX_DIGEST_INPUT_BYTES {
                return Err(ZoteroEvidenceError::InvalidInput {
                    field,
                    reason: String::from("digest input exceeds the bounded metadata size"),
                });
            }
        }
        let mut digests = Self {
            creators_digest: sha256_digest(creators.as_bytes()),
            title_digest: sha256_digest(title.as_bytes()),
            date_digest: sha256_digest(date.as_bytes()),
            identifier_digest: sha256_digest(identifier.as_bytes()),
            metadata_digest: String::new(),
        };
        digests.metadata_digest = digests.calculate_digest();
        Ok(digests)
    }

    pub fn from_digests(
        creators_digest: Digest,
        title_digest: Digest,
        date_digest: Digest,
        identifier_digest: Digest,
    ) -> Result<Self, ZoteroEvidenceError> {
        for (field, digest) in [
            ("creators_digest", &creators_digest),
            ("title_digest", &title_digest),
            ("date_digest", &date_digest),
            ("identifier_digest", &identifier_digest),
        ] {
            validate_digest(digest, field)?;
        }
        let mut digests = Self {
            creators_digest,
            title_digest,
            date_digest,
            identifier_digest,
            metadata_digest: String::new(),
        };
        digests.metadata_digest = digests.calculate_digest();
        Ok(digests)
    }

    pub fn calculate_digest(&self) -> Digest {
        canonical_digest(&(
            &self.creators_digest,
            &self.title_digest,
            &self.date_digest,
            &self.identifier_digest,
        ))
    }

    pub fn validate(&self) -> Result<(), ZoteroEvidenceError> {
        validate_digest(&self.creators_digest, "creators_digest")?;
        validate_digest(&self.title_digest, "title_digest")?;
        validate_digest(&self.date_digest, "date_digest")?;
        validate_digest(&self.identifier_digest, "identifier_digest")?;
        validate_digest(&self.metadata_digest, "metadata_digest")?;
        if self.metadata_digest == self.calculate_digest() {
            Ok(())
        } else {
            Err(ZoteroEvidenceError::TamperedResponse)
        }
    }
}

/// Attachment metadata and bounded full-text references. No URL, note,
/// annotation, or full-text bytes are retained.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ZoteroAttachmentReferences {
    pub attachment_metadata_digest: Digest,
    pub full_text_reference_digest: Digest,
    pub attachment_count: u16,
}

impl ZoteroAttachmentReferences {
    pub fn from_digests(
        attachment_metadata_digest: Digest,
        full_text_reference_digest: Digest,
        attachment_count: u16,
    ) -> Result<Self, ZoteroEvidenceError> {
        validate_digest(&attachment_metadata_digest, "attachment_metadata_digest")?;
        validate_digest(&full_text_reference_digest, "full_text_reference_digest")?;
        if attachment_count > MAX_ATTACHMENT_REFERENCES {
            return Err(ZoteroEvidenceError::InvalidInput {
                field: "attachment_count",
                reason: format!("must be at most {MAX_ATTACHMENT_REFERENCES}"),
            });
        }
        Ok(Self {
            attachment_metadata_digest,
            full_text_reference_digest,
            attachment_count,
        })
    }

    pub fn empty() -> Self {
        Self {
            attachment_metadata_digest: sha256_digest(b"no-attachment-metadata"),
            full_text_reference_digest: sha256_digest(b"no-full-text-reference"),
            attachment_count: 0,
        }
    }

    pub fn validate(&self) -> Result<(), ZoteroEvidenceError> {
        Self::from_digests(
            self.attachment_metadata_digest.clone(),
            self.full_text_reference_digest.clone(),
            self.attachment_count,
        )
        .map(|_| ())
    }
}

/// Lifecycle is explicit so a deleted object cannot be mistaken for stale
/// cached evidence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ZoteroObjectLifecycle {
    Present,
    Deleted,
    AccessLost,
}

/// One bounded item observation with exact object version and collection
/// membership digest.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ZoteroItemEvidence {
    pub item_key: ZoteroItemKey,
    pub item_version: ZoteroVersion,
    pub collection_keys: BTreeSet<ZoteroCollectionKey>,
    pub collection_membership_digest: Digest,
    pub lifecycle: ZoteroObjectLifecycle,
    pub metadata: ZoteroMetadataDigests,
    pub attachments: ZoteroAttachmentReferences,
    pub item_digest: Digest,
}

impl ZoteroItemEvidence {
    pub fn new(
        item_key: ZoteroItemKey,
        item_version: ZoteroVersion,
        collection_keys: BTreeSet<ZoteroCollectionKey>,
        lifecycle: ZoteroObjectLifecycle,
        metadata: ZoteroMetadataDigests,
        attachments: ZoteroAttachmentReferences,
    ) -> Result<Self, ZoteroEvidenceError> {
        item_key.validate()?;
        for collection_key in &collection_keys {
            collection_key.validate()?;
        }
        metadata.validate()?;
        attachments.validate()?;
        let collection_membership_digest = canonical_digest(&collection_keys);
        let mut item = Self {
            item_key,
            item_version,
            collection_keys,
            collection_membership_digest,
            lifecycle,
            metadata,
            attachments,
            item_digest: String::new(),
        };
        item.item_digest = item.calculate_digest();
        Ok(item)
    }

    pub fn calculate_digest(&self) -> Digest {
        canonical_digest(&(
            &self.item_key,
            self.item_version,
            &self.collection_membership_digest,
            self.lifecycle,
            &self.metadata,
            &self.attachments,
        ))
    }

    pub fn validate(&self) -> Result<(), ZoteroEvidenceError> {
        if self.collection_membership_digest != canonical_digest(&self.collection_keys)
            || self.item_digest != self.calculate_digest()
        {
            return Err(ZoteroEvidenceError::TamperedResponse);
        }
        Self::new(
            self.item_key.clone(),
            self.item_version,
            self.collection_keys.clone(),
            self.lifecycle,
            self.metadata.clone(),
            self.attachments.clone(),
        )
        .map(|_| ())
    }
}

/// Completeness is a typed safety property, not a boolean inferred from an
/// HTTP success code.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ZoteroEvidenceCompleteness {
    Complete,
    Partial,
    Ambiguous,
}

/// A backoff header may accompany any successful response.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ZoteroBackoff {
    pub seconds: u64,
}

impl ZoteroBackoff {
    pub fn new(seconds: u64) -> Result<Self, ZoteroEvidenceError> {
        if seconds == 0 || seconds > MAX_BACKOFF_SECONDS {
            return Err(ZoteroEvidenceError::InvalidInput {
                field: "backoff_seconds",
                reason: format!("must be between 1 and {MAX_BACKOFF_SECONDS}"),
            });
        }
        Ok(Self { seconds })
    }
}

/// Read status has an explicit 304 state so it cannot be silently promoted to
/// source truth.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ZoteroReadStatus {
    Ok200,
    NotModified304,
}

/// Bounded read response containing version, cursor, conditional, and digest
/// fences. Raw provider JSON is intentionally not represented.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ZoteroReadResponse {
    pub status: ZoteroReadStatus,
    pub scope: ZoteroEvidenceScope,
    pub target: ZoteroReadTarget,
    pub provenance: ZoteroProvenance,
    pub native_status: NativeStatus,
    pub library_version: Option<ZoteroVersion>,
    pub last_modified_version: Option<ZoteroVersion>,
    pub since_cursor: Option<ZoteroSinceCursor>,
    pub conditional: Option<ZoteroConditionalRequest>,
    pub page: ZoteroPage,
    pub items: Vec<ZoteroItemEvidence>,
    pub completeness: ZoteroEvidenceCompleteness,
    pub backoff: Option<ZoteroBackoff>,
    pub server_id: Option<ZoteroServerId>,
    pub metadata_digest: Digest,
    pub evidence_digest: Digest,
    pub provider_manifest_digest: Digest,
}

impl ZoteroReadResponse {
    pub fn new_200(
        request: &ZoteroReadRequest,
        manifest: &ZoteroProviderManifest,
        library_version: ZoteroVersion,
        last_modified_version: ZoteroVersion,
        items: Vec<ZoteroItemEvidence>,
        server_id: Option<ZoteroServerId>,
    ) -> Result<Self, ZoteroEvidenceError> {
        if items.len() > MAX_RESPONSE_ITEMS {
            return Err(ZoteroEvidenceError::PartialOrAmbiguous);
        }
        let since_cursor = Some(ZoteroSinceCursor::new(
            request.scope.library.clone(),
            library_version,
            &request.scope,
            manifest.provenance,
        )?);
        let metadata_digest = canonical_digest(&items);
        let mut response = Self {
            status: ZoteroReadStatus::Ok200,
            scope: request.scope.clone(),
            target: request.target.clone(),
            provenance: manifest.provenance,
            native_status: NativeStatus::BlockedEnv,
            library_version: Some(library_version),
            last_modified_version: Some(last_modified_version),
            since_cursor,
            conditional: request.conditional.clone(),
            page: request.page,
            items,
            completeness: ZoteroEvidenceCompleteness::Complete,
            backoff: None,
            server_id,
            metadata_digest,
            evidence_digest: String::new(),
            provider_manifest_digest: manifest.manifest_digest.clone(),
        };
        response.evidence_digest = response.calculate_evidence_digest();
        Ok(response)
    }

    pub fn new_304(
        request: &ZoteroReadRequest,
        manifest: &ZoteroProviderManifest,
        compared_version: ZoteroVersion,
    ) -> Result<Self, ZoteroEvidenceError> {
        let since_cursor = request.since.clone().or(Some(ZoteroSinceCursor::new(
            request.scope.library.clone(),
            compared_version,
            &request.scope,
            manifest.provenance,
        )?));
        let mut response = Self {
            status: ZoteroReadStatus::NotModified304,
            scope: request.scope.clone(),
            target: request.target.clone(),
            provenance: manifest.provenance,
            native_status: NativeStatus::BlockedEnv,
            library_version: Some(compared_version),
            last_modified_version: None,
            since_cursor,
            conditional: request.conditional.clone(),
            page: request.page,
            items: Vec::new(),
            completeness: ZoteroEvidenceCompleteness::Complete,
            backoff: None,
            server_id: None,
            metadata_digest: canonical_digest(&Vec::<ZoteroItemEvidence>::new()),
            evidence_digest: String::new(),
            provider_manifest_digest: manifest.manifest_digest.clone(),
        };
        response.evidence_digest = response.calculate_evidence_digest();
        Ok(response)
    }

    pub fn calculate_evidence_digest(&self) -> Digest {
        let mut unsigned = self.clone();
        unsigned.evidence_digest.clear();
        canonical_digest(&unsigned)
    }

    pub fn validate(&self) -> Result<(), ZoteroEvidenceError> {
        self.scope.validate()?;
        if self.native_status != NativeStatus::BlockedEnv
            || self.items.len() > MAX_RESPONSE_ITEMS
            || !is_sha256(&self.provider_manifest_digest)
            || self.evidence_digest != self.calculate_evidence_digest()
        {
            return Err(ZoteroEvidenceError::InvalidProviderResponse);
        }
        for item in &self.items {
            item.validate()?;
        }
        if self.metadata_digest != canonical_digest(&self.items) {
            return Err(ZoteroEvidenceError::TamperedResponse);
        }
        if let Some(cursor) = &self.since_cursor {
            cursor.validate_for(&self.scope, self.provenance)?;
        }
        if let Some(conditional) = &self.conditional {
            conditional.validate_for(&self.scope)?;
        }
        match self.status {
            ZoteroReadStatus::Ok200 => {
                if self.library_version.is_none()
                    || self.last_modified_version.is_none()
                    || self.completeness != ZoteroEvidenceCompleteness::Complete
                {
                    return Err(ZoteroEvidenceError::InvalidProviderResponse);
                }
            }
            ZoteroReadStatus::NotModified304 => {
                if self.conditional.is_none()
                    || !self.items.is_empty()
                    || self.last_modified_version.is_some()
                {
                    return Err(ZoteroEvidenceError::InvalidProviderResponse);
                }
            }
        }
        Ok(())
    }

    pub const fn is_source_evidence(&self) -> bool {
        matches!(self.status, ZoteroReadStatus::Ok200)
            && matches!(self.completeness, ZoteroEvidenceCompleteness::Complete)
    }

    pub fn exact_item(&self) -> Result<&ZoteroItemEvidence, ZoteroEvidenceError> {
        if self.items.len() != 1 {
            return Err(ZoteroEvidenceError::PartialOrAmbiguous);
        }
        let item = &self.items[0];
        if item.lifecycle != ZoteroObjectLifecycle::Present {
            return Err(ZoteroEvidenceError::DeletedOrAccessLost);
        }
        Ok(item)
    }
}

/// Typed 200 capability probe result. A probe is capability evidence, not
/// source verification.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ZoteroCapabilityProbeResponse {
    pub status: ZoteroReadStatus,
    pub scope: ZoteroEvidenceScope,
    pub visibility: ZoteroLibraryVisibility,
    pub authentication: ZoteroAuthenticationMode,
    pub capabilities: BTreeSet<ZoteroCapability>,
    pub api_version: u8,
    pub transport: ZoteroTransportKind,
    pub provenance: ZoteroProvenance,
    pub library_version: Option<ZoteroVersion>,
    pub last_modified_version: Option<ZoteroVersion>,
    pub server_id: Option<ZoteroServerId>,
    pub native_status: NativeStatus,
    pub evidence_digest: Digest,
    pub provider_manifest_digest: Digest,
}

impl ZoteroCapabilityProbeResponse {
    pub fn recorded(
        request: &ZoteroCapabilityProbeRequest,
        manifest: &ZoteroProviderManifest,
        visibility: ZoteroLibraryVisibility,
        library_version: ZoteroVersion,
        server_id: Option<ZoteroServerId>,
    ) -> Self {
        let mut response = Self {
            status: ZoteroReadStatus::Ok200,
            scope: request.scope.clone(),
            visibility,
            authentication: manifest.authentication,
            capabilities: manifest.registration.capabilities.clone(),
            api_version: manifest.api_version,
            transport: manifest.transport,
            provenance: manifest.provenance,
            library_version: Some(library_version),
            last_modified_version: Some(library_version),
            server_id,
            native_status: NativeStatus::BlockedEnv,
            evidence_digest: String::new(),
            provider_manifest_digest: manifest.manifest_digest.clone(),
        };
        response.evidence_digest = response.calculate_digest();
        response
    }

    pub fn calculate_digest(&self) -> Digest {
        let mut unsigned = self.clone();
        unsigned.evidence_digest.clear();
        canonical_digest(&unsigned)
    }

    pub fn validate(&self) -> Result<(), ZoteroEvidenceError> {
        self.scope.validate()?;
        if self.status != ZoteroReadStatus::Ok200
            || self.api_version != ZOTERO_WEB_API_VERSION
            || self.transport != self.provenance.transport_kind()
            || self.native_status != NativeStatus::BlockedEnv
            || self.evidence_digest != self.calculate_digest()
            || !is_sha256(&self.provider_manifest_digest)
        {
            return Err(ZoteroEvidenceError::InvalidProviderResponse);
        }
        Ok(())
    }
}

/// Metadata returned alongside a citation, with exact version and source
/// digests. It never carries the source title or creators themselves.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ZoteroCitationMetadata {
    pub library: ZoteroLibraryId,
    pub collection_key: Option<ZoteroCollectionKey>,
    pub item_key: ZoteroItemKey,
    pub library_version: ZoteroVersion,
    pub item_version: ZoteroVersion,
    pub last_modified_version: ZoteroVersion,
    pub collection_membership_digest: Digest,
    pub metadata: ZoteroMetadataDigests,
    pub attachments: ZoteroAttachmentReferences,
}

impl ZoteroCitationMetadata {
    pub fn from_item(
        scope: &ZoteroEvidenceScope,
        library_version: ZoteroVersion,
        last_modified_version: ZoteroVersion,
        item: &ZoteroItemEvidence,
    ) -> Result<Self, ZoteroEvidenceError> {
        item.validate()?;
        Ok(Self {
            library: scope.library.clone(),
            collection_key: scope.collection_key.clone(),
            item_key: item.item_key.clone(),
            library_version,
            item_version: item.item_version,
            last_modified_version,
            collection_membership_digest: item.collection_membership_digest.clone(),
            metadata: item.metadata.clone(),
            attachments: item.attachments.clone(),
        })
    }

    pub fn validate(&self) -> Result<(), ZoteroEvidenceError> {
        self.metadata.validate()?;
        self.attachments.validate()?;
        validate_digest(
            &self.collection_membership_digest,
            "collection_membership_digest",
        )
    }
}

/// The formatted string is bounded and useful to a UI, but its digest is the
/// only citation value retained in a Mission evidence proposal.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ZoteroCitationArtifact {
    pub style: ZoteroCitationStyle,
    pub locale: ZoteroCitationLocale,
    pub format: ZoteroCitationFormat,
    pub formatted: String,
    pub formatted_digest: Digest,
    pub export_metadata_digest: Digest,
}

impl ZoteroCitationArtifact {
    pub fn new(
        style: ZoteroCitationStyle,
        locale: ZoteroCitationLocale,
        format: ZoteroCitationFormat,
        formatted: impl Into<String>,
        export_metadata: &ZoteroCitationMetadata,
    ) -> Result<Self, ZoteroEvidenceError> {
        let formatted = formatted.into();
        if formatted.len() > MAX_FORMATTED_CITATION_BYTES {
            return Err(ZoteroEvidenceError::InvalidInput {
                field: "formatted_citation",
                reason: format!("must be at most {MAX_FORMATTED_CITATION_BYTES} bytes"),
            });
        }
        validate_text(
            &formatted,
            "formatted_citation",
            MAX_FORMATTED_CITATION_BYTES,
        )?;
        let formatted_digest = sha256_digest(formatted.as_bytes());
        let export_metadata_digest = canonical_digest(export_metadata);
        Ok(Self {
            style,
            locale,
            format,
            formatted,
            formatted_digest,
            export_metadata_digest,
        })
    }

    pub fn validate(&self, metadata: &ZoteroCitationMetadata) -> Result<(), ZoteroEvidenceError> {
        validate_text(
            &self.formatted,
            "formatted_citation",
            MAX_FORMATTED_CITATION_BYTES,
        )?;
        if self.formatted_digest != sha256_digest(self.formatted.as_bytes())
            || self.export_metadata_digest != canonical_digest(metadata)
        {
            return Err(ZoteroEvidenceError::TamperedResponse);
        }
        Ok(())
    }
}

/// Citation responses are explicitly formatted-only and cannot verify source
/// truth without a matching 200 item observation.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ZoteroCitationResponse {
    pub status: ZoteroReadStatus,
    pub scope: ZoteroEvidenceScope,
    pub provenance: ZoteroProvenance,
    pub native_status: NativeStatus,
    pub metadata: ZoteroCitationMetadata,
    pub artifact: ZoteroCitationArtifact,
    pub formatted_only: bool,
    pub citation_digest: Digest,
    pub provider_manifest_digest: Digest,
}

impl ZoteroCitationResponse {
    pub fn recorded(
        request: &ZoteroCitationRequest,
        manifest: &ZoteroProviderManifest,
        metadata: ZoteroCitationMetadata,
        formatted: impl Into<String>,
    ) -> Result<Self, ZoteroEvidenceError> {
        let artifact = ZoteroCitationArtifact::new(
            request.style.clone(),
            request.locale.clone(),
            request.format,
            formatted,
            &metadata,
        )?;
        let mut response = Self {
            status: ZoteroReadStatus::Ok200,
            scope: request.scope.clone(),
            provenance: manifest.provenance,
            native_status: NativeStatus::BlockedEnv,
            metadata,
            artifact,
            formatted_only: true,
            citation_digest: String::new(),
            provider_manifest_digest: manifest.manifest_digest.clone(),
        };
        response.citation_digest = response.calculate_digest();
        Ok(response)
    }

    pub fn calculate_digest(&self) -> Digest {
        let mut unsigned = self.clone();
        unsigned.citation_digest.clear();
        canonical_digest(&unsigned)
    }

    pub fn validate(&self) -> Result<(), ZoteroEvidenceError> {
        self.scope.validate()?;
        self.metadata.validate()?;
        self.artifact.validate(&self.metadata)?;
        if self.status != ZoteroReadStatus::Ok200
            || !self.formatted_only
            || self.native_status != NativeStatus::BlockedEnv
            || self.citation_digest != self.calculate_digest()
            || !is_sha256(&self.provider_manifest_digest)
        {
            return Err(ZoteroEvidenceError::InvalidProviderResponse);
        }
        Ok(())
    }
}

/// Exact Mission/claim/result revision binding used by evidence proposals.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct MissionClaimResultBinding {
    pub mission_id: MissionId,
    pub claim_id: ClaimId,
    pub claim_revision: u64,
    pub result_id: ResultId,
    pub result_revision: u64,
}

impl MissionClaimResultBinding {
    pub fn new(
        mission_id: MissionId,
        claim_id: ClaimId,
        claim_revision: u64,
        result_id: ResultId,
        result_revision: u64,
    ) -> Result<Self, ZoteroEvidenceError> {
        mission_id.validate()?;
        claim_id.validate()?;
        result_id.validate()?;
        if claim_revision == 0 || result_revision == 0 {
            return Err(ZoteroEvidenceError::InvalidEvidenceBinding);
        }
        Ok(Self {
            mission_id,
            claim_id,
            claim_revision,
            result_id,
            result_revision,
        })
    }
}

/// Mission-facing request to produce a version-fenced research evidence
/// proposal, never a durable/external adoption.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct MissionResearchEvidenceRequest {
    pub binding: MissionClaimResultBinding,
    pub scope: ZoteroEvidenceScope,
    pub citation_style: ZoteroCitationStyle,
    pub citation_locale: ZoteroCitationLocale,
}

impl MissionResearchEvidenceRequest {
    pub fn new(
        binding: MissionClaimResultBinding,
        scope: ZoteroEvidenceScope,
        citation_style: ZoteroCitationStyle,
        citation_locale: ZoteroCitationLocale,
    ) -> Result<Self, ZoteroEvidenceError> {
        scope.validate()?;
        if scope.mission_id != binding.mission_id || !scope.is_item_bound() {
            return Err(ZoteroEvidenceError::InvalidEvidenceBinding);
        }
        Ok(Self {
            binding,
            scope,
            citation_style,
            citation_locale,
        })
    }
}

/// Layer 1 can produce only a proposal. There is intentionally no Verified or
/// Connected variant in this enum.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ZoteroEvidenceDisposition {
    ProposalOnly,
}

/// The Mission-adoptable proposal contains only digests and exact fences; it
/// does not retain formatted source text or raw provider content.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ZoteroEvidenceProposal {
    pub contract_version: String,
    pub binding: MissionClaimResultBinding,
    pub scope: ZoteroEvidenceScope,
    pub scope_digest: Digest,
    pub library: ZoteroLibraryId,
    pub collection_key: Option<ZoteroCollectionKey>,
    pub item_key: ZoteroItemKey,
    pub library_version: ZoteroVersion,
    pub item_version: ZoteroVersion,
    pub last_modified_version: ZoteroVersion,
    pub since_cursor: Option<ZoteroSinceCursor>,
    pub conditional: Option<ZoteroConditionalRequest>,
    pub collection_membership_digest: Digest,
    pub metadata: ZoteroMetadataDigests,
    pub attachment_metadata_digest: Digest,
    pub full_text_reference_digest: Digest,
    pub citation_style: ZoteroCitationStyle,
    pub citation_locale: ZoteroCitationLocale,
    pub citation_digest: Digest,
    pub evidence_digest: Digest,
    pub provider_version: PluginVersion,
    pub registration_digest: Digest,
    pub provider_manifest_digest: Digest,
    pub provenance: ZoteroProvenance,
    pub native_status: NativeStatus,
    pub disposition: ZoteroEvidenceDisposition,
    pub idempotency_key: Digest,
    pub proposal_digest: Digest,
}

impl ZoteroEvidenceProposal {
    pub fn from_observations(
        request: &MissionResearchEvidenceRequest,
        read: &ZoteroReadResponse,
        citation: &ZoteroCitationResponse,
        manifest: &ZoteroProviderManifest,
    ) -> Result<Self, ZoteroEvidenceError> {
        request.scope.validate()?;
        read.validate()?;
        citation.validate()?;
        manifest.validate()?;
        if read.status != ZoteroReadStatus::Ok200 || !read.is_source_evidence() {
            return Err(ZoteroEvidenceError::NotModifiedIsNotEvidence);
        }
        if read.scope != request.scope
            || citation.scope != request.scope
            || read.provenance != manifest.provenance
            || citation.provenance != manifest.provenance
            || read.provider_manifest_digest != manifest.manifest_digest
            || citation.provider_manifest_digest != manifest.manifest_digest
        {
            return Err(ZoteroEvidenceError::InvalidEvidenceBinding);
        }
        if citation.artifact.style != request.citation_style
            || citation.artifact.locale != request.citation_locale
        {
            return Err(ZoteroEvidenceError::CitationPresentationMismatch);
        }
        let item = read.exact_item()?;
        if Some(item.item_key.clone()) != request.scope.item_key {
            return Err(ZoteroEvidenceError::ScopeMismatch);
        }
        if let Some(collection_key) = request.scope.collection_key.as_ref()
            && !item.collection_keys.contains(collection_key)
        {
            return Err(ZoteroEvidenceError::ScopeMismatch);
        }
        if item.item_version != citation.metadata.item_version
            || read.last_modified_version != Some(citation.metadata.last_modified_version)
            || item.metadata != citation.metadata.metadata
            || item.attachments != citation.metadata.attachments
            || item.collection_membership_digest != citation.metadata.collection_membership_digest
        {
            return Err(ZoteroEvidenceError::CitationVersionMismatch);
        }
        let library_version = read
            .library_version
            .ok_or(ZoteroEvidenceError::InvalidProviderResponse)?;
        let last_modified_version = read
            .last_modified_version
            .ok_or(ZoteroEvidenceError::InvalidProviderResponse)?;
        let mut proposal = Self {
            contract_version: String::from(ZOTERO_EVIDENCE_CONTRACT_VERSION),
            binding: request.binding.clone(),
            scope: request.scope.clone(),
            scope_digest: request.scope.digest(),
            library: request.scope.library.clone(),
            collection_key: request.scope.collection_key.clone(),
            item_key: item.item_key.clone(),
            library_version,
            item_version: item.item_version,
            last_modified_version,
            since_cursor: read.since_cursor.clone(),
            conditional: read.conditional.clone(),
            collection_membership_digest: item.collection_membership_digest.clone(),
            metadata: item.metadata.clone(),
            attachment_metadata_digest: item.attachments.attachment_metadata_digest.clone(),
            full_text_reference_digest: item.attachments.full_text_reference_digest.clone(),
            citation_style: request.citation_style.clone(),
            citation_locale: request.citation_locale.clone(),
            citation_digest: citation.citation_digest.clone(),
            evidence_digest: read.evidence_digest.clone(),
            provider_version: manifest.provider_version,
            registration_digest: manifest.registration.registration_digest.clone(),
            provider_manifest_digest: manifest.manifest_digest.clone(),
            provenance: manifest.provenance,
            native_status: NativeStatus::BlockedEnv,
            disposition: ZoteroEvidenceDisposition::ProposalOnly,
            idempotency_key: String::new(),
            proposal_digest: String::new(),
        };
        proposal.idempotency_key = canonical_digest(&(
            &proposal.binding,
            &proposal.scope_digest,
            &proposal.library_version,
            &proposal.item_version,
            &proposal.last_modified_version,
            &proposal.citation_style,
            &proposal.citation_locale,
            &proposal.evidence_digest,
            &proposal.citation_digest,
            &proposal.registration_digest,
        ));
        proposal.proposal_digest = proposal.calculate_digest();
        Ok(proposal)
    }

    pub fn calculate_digest(&self) -> Digest {
        let mut unsigned = self.clone();
        unsigned.proposal_digest.clear();
        canonical_digest(&unsigned)
    }

    pub fn validate(&self) -> Result<(), ZoteroEvidenceError> {
        self.scope.validate()?;
        self.binding.mission_id.validate()?;
        if self.binding.mission_id != self.scope.mission_id
            || self.scope_digest != self.scope.digest()
            || self.library != self.scope.library
            || Some(self.item_key.clone()) != self.scope.item_key
            || self.contract_version != ZOTERO_EVIDENCE_CONTRACT_VERSION
            || self.native_status != NativeStatus::BlockedEnv
            || self.disposition != ZoteroEvidenceDisposition::ProposalOnly
        {
            return Err(ZoteroEvidenceError::InvalidEvidenceBinding);
        }
        self.metadata.validate()?;
        validate_digest(
            &self.collection_membership_digest,
            "collection_membership_digest",
        )?;
        validate_digest(
            &self.attachment_metadata_digest,
            "attachment_metadata_digest",
        )?;
        validate_digest(
            &self.full_text_reference_digest,
            "full_text_reference_digest",
        )?;
        validate_digest(&self.citation_digest, "citation_digest")?;
        validate_digest(&self.evidence_digest, "evidence_digest")?;
        validate_digest(&self.registration_digest, "registration_digest")?;
        validate_digest(&self.provider_manifest_digest, "provider_manifest_digest")?;
        validate_digest(&self.idempotency_key, "idempotency_key")?;
        if let Some(cursor) = &self.since_cursor {
            cursor.validate_for(&self.scope, self.provenance)?;
        }
        if let Some(conditional) = &self.conditional {
            conditional.validate_for(&self.scope)?;
        }
        if self.proposal_digest != self.calculate_digest() {
            return Err(ZoteroEvidenceError::EvidenceDigestMismatch);
        }
        Ok(())
    }

    pub const fn can_claim_verified_source(&self) -> bool {
        false
    }
}

/// Alias used by integration layers that call the proposal a research
/// evidence receipt/projection.
pub type ResearchEvidenceProposal = ZoteroEvidenceProposal;

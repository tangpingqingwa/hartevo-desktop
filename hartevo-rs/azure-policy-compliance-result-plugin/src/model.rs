use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_RESOURCE_ID_BYTES: usize = 2 * 1024;
pub const MAX_TIMESTAMP_BYTES: usize = 64;
pub const MAX_FILTER_NODES: usize = 8;
pub const MAX_POLICY_FINGERPRINTS: usize = 64;
pub const MAX_PAGES: u8 = 8;
pub const MAX_RECORDS: usize = 512;
pub const MAX_RECORDS_PER_PAGE: usize = 128;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_NEXT_LINK_BYTES: usize = 8 * 1024;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("identifier is empty, malformed, or too long")]
    InvalidIdentifier,
    #[error("resource identifier is empty, malformed, or too long")]
    InvalidResourceId,
    #[error("digest is not a lowercase SHA-256 hex digest")]
    InvalidDigest,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("timestamp is not a bounded UTC timestamp")]
    InvalidTimestamp,
    #[error("query window is empty or reversed")]
    InvalidQueryWindow,
    #[error("scope is invalid for its resource/resource-group/subscription kind")]
    InvalidScope,
    #[error("policy fingerprint set is empty, malformed, or too large")]
    InvalidPolicyFingerprints,
    #[error("allowlisted OData filter is invalid or exceeds its node bound")]
    InvalidODataFilter,
    #[error("opaque SecretReference is invalid")]
    InvalidSecretReference,
    #[error("opaque next link is invalid or too large")]
    InvalidNextLink,
    #[error("policy-state record is malformed or outside the governed scope")]
    InvalidPolicyState,
    #[error("registration is invalid")]
    InvalidRegistration,
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("digest does not match immutable fields")]
    DigestMismatch,
}

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    #[must_use]
    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidDigest)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub(crate) fn from_fields(domain: &str, fields: &[String]) -> Self {
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for field in fields {
            append_field(&mut bytes, field);
        }
        Self::from_bytes(&bytes)
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
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
        && !value.starts_with('.')
        && !value.ends_with('.')
}

fn valid_resource_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_RESOURCE_ID_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'/' | b'-' | b'_' | b'.' | b':' | b'(' | b')' | b'@' | b'%'
                )
        })
        && value.starts_with('/')
        && !value.ends_with('/')
}

macro_rules! string_identifier {
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

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            #[must_use]
            pub fn digest(&self) -> Digest {
                Digest::from_text(self.as_str())
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
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

string_identifier!(ProjectId);
string_identifier!(MissionId);
string_identifier!(WorkProductId);
string_identifier!(SubscriptionId);
string_identifier!(ResourceGroupName);

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ResourceId(String);

impl ResourceId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if valid_resource_id(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidResourceId)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_text(self.as_str())
    }
}

impl AsRef<str> for ResourceId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Debug for ResourceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("ResourceId").field(&self.0).finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct TenantId(String);

impl TenantId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if valid_identifier(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidIdentifier)
        }
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_fields("azure-tenant/v1", std::slice::from_ref(&self.0))
    }
}

impl AsRef<str> for TenantId {
    fn as_ref(&self) -> &str {
        &self.0
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

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Timestamp(String);

impl Timestamp {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if is_bounded_timestamp(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidTimestamp)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn is_bounded_timestamp(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_TIMESTAMP_BYTES || value.trim() != value {
        return false;
    }
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return false;
    }
    if !bytes[..19]
        .iter()
        .enumerate()
        .all(|(index, byte)| matches!(index, 4 | 7 | 10 | 13 | 16) || byte.is_ascii_digit())
    {
        return false;
    }
    let suffix = &value[19..];
    (suffix == "Z" || (suffix.starts_with('.') && suffix.ends_with('Z')))
        && suffix
            .bytes()
            .all(|byte| byte == b'Z' || byte == b'.' || byte.is_ascii_digit())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectBinding {
    pub id: ProjectId,
    pub revision: Revision,
}

impl ProjectBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            id: ProjectId::new(id)?,
            revision: Revision::new(revision)?,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionBinding {
    pub id: MissionId,
    pub revision: Revision,
}

impl MissionBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            id: MissionId::new(id)?,
            revision: Revision::new(revision)?,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProductBinding {
    pub id: WorkProductId,
    pub revision: Revision,
}

impl WorkProductBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            id: WorkProductId::new(id)?,
            revision: Revision::new(revision)?,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStateView {
    Latest,
    Default,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QueryBounds {
    pub max_pages: u8,
    pub max_records: usize,
    pub max_records_per_page: usize,
    pub max_response_bytes: usize,
}

impl QueryBounds {
    pub fn new(
        max_pages: u8,
        max_records: usize,
        max_records_per_page: usize,
        max_response_bytes: usize,
    ) -> Result<Self, ModelError> {
        if max_pages == 0
            || max_pages > MAX_PAGES
            || max_records == 0
            || max_records > MAX_RECORDS
            || max_records_per_page == 0
            || max_records_per_page > MAX_RECORDS_PER_PAGE
            || max_response_bytes == 0
            || max_response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(ModelError::InvalidQueryWindow);
        }
        Ok(Self {
            max_pages,
            max_records,
            max_records_per_page,
            max_response_bytes,
        })
    }

    #[must_use]
    pub const fn layer_one() -> Self {
        Self {
            max_pages: MAX_PAGES,
            max_records: MAX_RECORDS,
            max_records_per_page: MAX_RECORDS_PER_PAGE,
            max_response_bytes: MAX_RESPONSE_BYTES,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QueryWindow {
    pub start: Timestamp,
    pub end: Timestamp,
    pub state_view: PolicyStateView,
    pub bounds: QueryBounds,
}

impl QueryWindow {
    pub fn new(
        start: Timestamp,
        end: Timestamp,
        state_view: PolicyStateView,
    ) -> Result<Self, ModelError> {
        Self::with_bounds(start, end, state_view, QueryBounds::layer_one())
    }

    pub fn with_bounds(
        start: Timestamp,
        end: Timestamp,
        state_view: PolicyStateView,
        bounds: QueryBounds,
    ) -> Result<Self, ModelError> {
        if start.as_str() >= end.as_str() {
            return Err(ModelError::InvalidQueryWindow);
        }
        Ok(Self {
            start,
            end,
            state_view,
            bounds,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyFingerprints {
    pub definition: BTreeSet<Digest>,
    pub assignment: BTreeSet<Digest>,
    pub set_definition: BTreeSet<Digest>,
}

impl PolicyFingerprints {
    pub fn new(
        definition: impl IntoIterator<Item = Digest>,
        assignment: impl IntoIterator<Item = Digest>,
        set_definition: impl IntoIterator<Item = Digest>,
    ) -> Result<Self, ModelError> {
        let result = Self {
            definition: definition.into_iter().collect(),
            assignment: assignment.into_iter().collect(),
            set_definition: set_definition.into_iter().collect(),
        };
        result.validate()?;
        Ok(result)
    }

    #[must_use]
    pub fn empty() -> Self {
        Self {
            definition: BTreeSet::new(),
            assignment: BTreeSet::new(),
            set_definition: BTreeSet::new(),
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.definition.len() > MAX_POLICY_FINGERPRINTS
            || self.assignment.len() > MAX_POLICY_FINGERPRINTS
            || self.set_definition.len() > MAX_POLICY_FINGERPRINTS
            || self
                .definition
                .iter()
                .chain(self.assignment.iter())
                .chain(self.set_definition.iter())
                .any(|digest| !is_digest(digest.as_str()))
        {
            Err(ModelError::InvalidPolicyFingerprints)
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub(crate) fn digest(&self) -> Digest {
        Digest::from_fields(
            "azure-policy-fingerprints/v1",
            &[
                self.definition
                    .iter()
                    .map(Digest::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
                self.assignment
                    .iter()
                    .map(Digest::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
                self.set_definition
                    .iter()
                    .map(Digest::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyQueryScope {
    Resource,
    ResourceGroup,
    Subscription,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AzurePolicyScope {
    tenant_digest: Digest,
    subscription_id: SubscriptionId,
    resource_group: Option<ResourceGroupName>,
    resource_id: Option<ResourceId>,
    kind: PolicyQueryScope,
    policy_fingerprints: PolicyFingerprints,
    query_window: QueryWindow,
    project: ProjectBinding,
    mission: MissionBinding,
    work_product: WorkProductBinding,
    permission_digest: Digest,
    scope_digest: Digest,
}

impl AzurePolicyScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant_id: impl AsRef<str>,
        subscription_id: SubscriptionId,
        resource_group: Option<ResourceGroupName>,
        resource_id: Option<ResourceId>,
        policy_fingerprints: PolicyFingerprints,
        query_window: QueryWindow,
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        permission_digest: Digest,
    ) -> Result<Self, ModelError> {
        let tenant_id = TenantId::new(tenant_id.as_ref().to_owned())?;
        policy_fingerprints.validate()?;
        let kind = match (&resource_group, &resource_id) {
            (Some(_), Some(_)) => PolicyQueryScope::Resource,
            (Some(_), None) => PolicyQueryScope::ResourceGroup,
            (None, None) => PolicyQueryScope::Subscription,
            (None, Some(_)) => return Err(ModelError::InvalidScope),
        };
        if let Some(resource) = resource_id.as_ref() {
            let lower = resource.as_str().to_ascii_lowercase();
            let subscription_segment = format!("/subscriptions/{}", subscription_id.as_str());
            if !lower.starts_with(&subscription_segment.to_ascii_lowercase()) {
                return Err(ModelError::InvalidScope);
            }
            if let Some(group) = resource_group.as_ref() {
                let group_segment = format!("/resourcegroups/{}", group.as_str());
                if !lower.contains(&group_segment.to_ascii_lowercase()) {
                    return Err(ModelError::InvalidScope);
                }
            }
        }
        let tenant_digest = tenant_id.digest();
        let scope_digest = Digest::from_fields(
            "azure-policy-scope/v1",
            &[
                tenant_digest.as_str().to_owned(),
                subscription_id.as_str().to_owned(),
                resource_group
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), |value| value.as_str().to_owned()),
                resource_id
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), |value| value.as_str().to_owned()),
                format!("{kind:?}"),
                policy_fingerprints.digest().as_str().to_owned(),
                query_window.start.as_str().to_owned(),
                query_window.end.as_str().to_owned(),
                format!("{:?}", query_window.state_view),
                project.id.as_str().to_owned(),
                project.revision.get().to_string(),
                mission.id.as_str().to_owned(),
                mission.revision.get().to_string(),
                work_product.id.as_str().to_owned(),
                work_product.revision.get().to_string(),
                permission_digest.as_str().to_owned(),
            ],
        );
        Ok(Self {
            tenant_digest,
            subscription_id,
            resource_group,
            resource_id,
            kind,
            policy_fingerprints,
            query_window,
            project,
            mission,
            work_product,
            permission_digest,
            scope_digest,
        })
    }

    #[must_use]
    pub fn tenant_digest(&self) -> &Digest {
        &self.tenant_digest
    }

    #[must_use]
    pub fn subscription_id(&self) -> &SubscriptionId {
        &self.subscription_id
    }

    #[must_use]
    pub fn resource_group(&self) -> Option<&ResourceGroupName> {
        self.resource_group.as_ref()
    }

    #[must_use]
    pub fn resource_id(&self) -> Option<&ResourceId> {
        self.resource_id.as_ref()
    }

    #[must_use]
    pub const fn kind(&self) -> PolicyQueryScope {
        self.kind
    }

    #[must_use]
    pub fn policy_fingerprints(&self) -> &PolicyFingerprints {
        &self.policy_fingerprints
    }

    #[must_use]
    pub fn query_window(&self) -> &QueryWindow {
        &self.query_window
    }

    #[must_use]
    pub fn project(&self) -> &ProjectBinding {
        &self.project
    }

    #[must_use]
    pub fn mission(&self) -> &MissionBinding {
        &self.mission
    }

    #[must_use]
    pub fn work_product(&self) -> &WorkProductBinding {
        &self.work_product
    }

    #[must_use]
    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    #[must_use]
    pub fn scope_digest(&self) -> Digest {
        self.scope_digest.clone()
    }

    pub(crate) fn matches_resource(&self, resource_id: &str) -> bool {
        let candidate = resource_id.to_ascii_lowercase();
        let subscription_prefix =
            format!("/subscriptions/{}/", self.subscription_id.as_str()).to_ascii_lowercase();
        if !candidate.starts_with(&subscription_prefix) {
            return false;
        }
        match (&self.resource_group, &self.resource_id) {
            (Some(group), Some(resource)) => {
                candidate == resource.as_str().to_ascii_lowercase()
                    && candidate.contains(
                        &format!("/resourcegroups/{}/", group.as_str()).to_ascii_lowercase(),
                    )
            }
            (Some(group), None) => candidate
                .contains(&format!("/resourcegroups/{}/", group.as_str()).to_ascii_lowercase()),
            (None, None) => true,
            (None, Some(_)) => false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermissionFence {
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub project_revision: Revision,
    pub mission_revision: Revision,
    pub work_product_revision: Revision,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntraAuthKind {
    ManagedIdentity,
    FederatedCredential,
    HostKeyring,
}

/// Opaque, non-serializing reference into host-managed Microsoft Entra
/// authority. Only digests and a credential revision can cross this crate's
/// evidence boundary.
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    auth_kind: EntraAuthKind,
    revoked: bool,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_digest: self.reference_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            credential_revision: self.credential_revision,
            auth_kind: self.auth_kind,
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
            .field("auth_kind", &self.auth_kind)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest
            && self.scope_digest == other.scope_digest
            && self.credential_revision == other.credential_revision
            && self.auth_kind == other.auth_kind
            && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope: &AzurePolicyScope,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        Self::new_with_kind(
            reference_id,
            scope,
            credential_revision,
            EntraAuthKind::HostKeyring,
        )
    }

    pub fn new_with_kind(
        reference_id: impl Into<String>,
        scope: &AzurePolicyScope,
        credential_revision: u64,
        auth_kind: EntraAuthKind,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        if !valid_identifier(&reference_id) {
            return Err(ModelError::InvalidSecretReference);
        }
        let credential_revision = Revision::new(credential_revision)?;
        let scope_digest = scope.scope_digest();
        let reference_digest = Digest::from_fields(
            "azure-policy-secret-reference/v1",
            &[
                reference_id,
                scope_digest.as_str().to_owned(),
                credential_revision.get().to_string(),
                format!("{auth_kind:?}"),
            ],
        );
        Ok(Self {
            reference_digest,
            scope_digest,
            credential_revision,
            auth_kind,
            revoked: false,
        })
    }

    #[must_use]
    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    #[must_use]
    pub const fn auth_kind(&self) -> EntraAuthKind {
        self.auth_kind
    }

    #[must_use]
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
}

/// An OData continuation link is retained only inside a provider call. Its
/// public representation is a digest so it cannot leak or be replayed across
/// scopes accidentally.
pub struct OpaqueNextLink(String);

impl OpaqueNextLink {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_NEXT_LINK_BYTES
            || value.chars().any(char::is_whitespace)
            || !(value.starts_with("https://") || value.starts_with('/'))
        {
            return Err(ModelError::InvalidNextLink);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_fields("azure-policy-next-link/v1", std::slice::from_ref(&self.0))
    }

    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl Clone for OpaqueNextLink {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl PartialEq for OpaqueNextLink {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for OpaqueNextLink {}

impl fmt::Debug for OpaqueNextLink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueNextLink")
            .field("digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceState {
    Compliant,
    NonCompliant,
    Exempt,
    Unknown,
}

impl ComplianceState {
    pub fn parse(value: &str) -> Result<Self, ModelError> {
        match value {
            "Compliant" | "compliant" => Ok(Self::Compliant),
            "NonCompliant" | "nonCompliant" | "non_compliant" => Ok(Self::NonCompliant),
            "Exempt" | "exempt" => Ok(Self::Exempt),
            "Unknown" | "unknown" | "NotStarted" | "notStarted" => Ok(Self::Unknown),
            _ => Err(ModelError::InvalidPolicyState),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ODataFilter {
    ComplianceState(ComplianceState),
    PolicyDefinitionId(ResourceId),
    PolicyAssignmentId(ResourceId),
    PolicySetDefinitionId(ResourceId),
    TimestampAfter(Timestamp),
    TimestampBefore(Timestamp),
    And(Vec<ODataFilter>),
}

impl ODataFilter {
    #[must_use]
    pub fn compliance_state(state: ComplianceState) -> Self {
        Self::ComplianceState(state)
    }

    pub fn policy_definition_id(value: impl Into<String>) -> Result<Self, ModelError> {
        Ok(Self::PolicyDefinitionId(ResourceId::new(value)?))
    }

    pub fn policy_assignment_id(value: impl Into<String>) -> Result<Self, ModelError> {
        Ok(Self::PolicyAssignmentId(ResourceId::new(value)?))
    }

    pub fn policy_set_definition_id(value: impl Into<String>) -> Result<Self, ModelError> {
        Ok(Self::PolicySetDefinitionId(ResourceId::new(value)?))
    }

    #[must_use]
    pub fn timestamp_after(value: Timestamp) -> Self {
        Self::TimestampAfter(value)
    }

    #[must_use]
    pub fn timestamp_before(value: Timestamp) -> Self {
        Self::TimestampBefore(value)
    }

    pub fn and(filters: impl IntoIterator<Item = ODataFilter>) -> Result<Self, ModelError> {
        let result = Self::And(filters.into_iter().collect());
        result.validate()?;
        Ok(result)
    }

    pub fn parse(value: impl AsRef<str>) -> Result<Self, ModelError> {
        let value = value.as_ref().trim();
        if value.is_empty()
            || value.contains(';')
            || value.contains("--")
            || value.contains("/*")
            || value.contains("*/")
            || value.contains('(')
            || value.contains(')')
            || value.contains('"')
        {
            return Err(ModelError::InvalidODataFilter);
        }
        let parts = split_case_insensitive(value, " and ");
        if parts.len() > 1 {
            return Self::and(
                parts
                    .into_iter()
                    .map(Self::parse)
                    .collect::<Result<Vec<_>, _>>()?,
            );
        }
        let tokens = value.split_whitespace().collect::<Vec<_>>();
        if tokens.len() != 3 || !tokens[2].starts_with('\'') || !tokens[2].ends_with('\'') {
            return Err(ModelError::InvalidODataFilter);
        }
        let literal = &tokens[2][1..tokens[2].len() - 1];
        if literal.is_empty() || literal.contains('\'') {
            return Err(ModelError::InvalidODataFilter);
        }
        match (tokens[0], tokens[1]) {
            ("complianceState", "eq") => Ok(Self::compliance_state(
                ComplianceState::parse(literal).map_err(|_| ModelError::InvalidODataFilter)?,
            )),
            ("policyDefinitionId", "eq") => Self::policy_definition_id(literal.to_owned()),
            ("policyAssignmentId", "eq") => Self::policy_assignment_id(literal.to_owned()),
            ("policySetDefinitionId", "eq") => Self::policy_set_definition_id(literal.to_owned()),
            ("timestamp", "ge") => Ok(Self::timestamp_after(Timestamp::new(literal.to_owned())?)),
            ("timestamp", "le") => Ok(Self::timestamp_before(Timestamp::new(literal.to_owned())?)),
            _ => Err(ModelError::InvalidODataFilter),
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.node_count() > MAX_FILTER_NODES {
            return Err(ModelError::InvalidODataFilter);
        }
        match self {
            Self::And(filters) if filters.is_empty() => Err(ModelError::InvalidODataFilter),
            Self::And(filters) => filters.iter().try_for_each(Self::validate),
            Self::ComplianceState(_)
            | Self::PolicyDefinitionId(_)
            | Self::PolicyAssignmentId(_)
            | Self::PolicySetDefinitionId(_)
            | Self::TimestampAfter(_)
            | Self::TimestampBefore(_) => Ok(()),
        }
    }

    #[must_use]
    pub fn render(&self) -> String {
        match self {
            Self::ComplianceState(value) => {
                format!("complianceState eq '{}'", compliance_state_text(*value))
            }
            Self::PolicyDefinitionId(value) => {
                format!("policyDefinitionId eq '{}'", value.as_str())
            }
            Self::PolicyAssignmentId(value) => {
                format!("policyAssignmentId eq '{}'", value.as_str())
            }
            Self::PolicySetDefinitionId(value) => {
                format!("policySetDefinitionId eq '{}'", value.as_str())
            }
            Self::TimestampAfter(value) => format!("timestamp ge '{}'", value.as_str()),
            Self::TimestampBefore(value) => format!("timestamp le '{}'", value.as_str()),
            Self::And(filters) => filters
                .iter()
                .map(Self::render)
                .collect::<Vec<_>>()
                .join(" and "),
        }
    }

    #[must_use]
    pub(crate) fn digest(&self) -> Digest {
        Digest::from_fields("azure-policy-odata-filter/v1", &[self.render()])
    }

    fn node_count(&self) -> usize {
        match self {
            Self::And(filters) => 1 + filters.iter().map(Self::node_count).sum::<usize>(),
            _ => 1,
        }
    }
}

fn split_case_insensitive(value: &str, needle: &str) -> Vec<String> {
    let lower = value.to_ascii_lowercase();
    let needle_lower = needle.to_ascii_lowercase();
    let mut result = Vec::new();
    let mut start = 0;
    let mut search_from = 0;
    while let Some(offset) = lower[search_from..].find(&needle_lower) {
        let index = search_from + offset;
        result.push(value[start..index].trim().to_owned());
        start = index + needle.len();
        search_from = start;
    }
    result.push(value[start..].trim().to_owned());
    result
}

const fn compliance_state_text(value: ComplianceState) -> &'static str {
    match value {
        ComplianceState::Compliant => "Compliant",
        ComplianceState::NonCompliant => "NonCompliant",
        ComplianceState::Exempt => "Exempt",
        ComplianceState::Unknown => "Unknown",
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyStateRecord {
    pub policy_assignment_id: ResourceId,
    pub policy_definition_id: ResourceId,
    pub policy_set_definition_id: Option<ResourceId>,
    pub resource_id: ResourceId,
    pub compliance_state: ComplianceState,
    pub timestamp: Timestamp,
    pub resource_location: Option<String>,
    pub resource_type: Option<String>,
    pub policy_metadata_digest: Digest,
}

impl PolicyStateRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        policy_assignment_id: ResourceId,
        policy_definition_id: ResourceId,
        policy_set_definition_id: Option<ResourceId>,
        resource_id: ResourceId,
        compliance_state: ComplianceState,
        timestamp: Timestamp,
        resource_location: Option<String>,
        resource_type: Option<String>,
        policy_metadata_digest: Digest,
    ) -> Result<Self, ModelError> {
        if resource_location
            .as_ref()
            .is_some_and(|value| value.len() > MAX_IDENTIFIER_BYTES || value.contains('\n'))
            || resource_type
                .as_ref()
                .is_some_and(|value| value.len() > MAX_RESOURCE_ID_BYTES || value.contains('\n'))
            || !is_digest(policy_metadata_digest.as_str())
        {
            return Err(ModelError::InvalidPolicyState);
        }
        Ok(Self {
            policy_assignment_id,
            policy_definition_id,
            policy_set_definition_id,
            resource_id,
            compliance_state,
            timestamp,
            resource_location,
            resource_type,
            policy_metadata_digest,
        })
    }

    #[must_use]
    pub(crate) fn digest(&self) -> Digest {
        Digest::from_fields(
            "azure-policy-state-record/v1",
            &[
                self.policy_assignment_id.as_str().to_owned(),
                self.policy_definition_id.as_str().to_owned(),
                self.policy_set_definition_id
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), |value| value.as_str().to_owned()),
                self.resource_id.as_str().to_owned(),
                format!("{:?}", self.compliance_state),
                self.timestamp.as_str().to_owned(),
                self.resource_location.clone().unwrap_or_default(),
                self.resource_type.clone().unwrap_or_default(),
                self.policy_metadata_digest.as_str().to_owned(),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    BadRequest,
    Unauthenticated,
    PermissionDenied,
    NotFound,
    Conflict,
    RateLimited,
    ServerFailure,
    Timeout,
    ScopeMismatch,
    NextLinkScopeMismatch,
    NextLinkReplay,
    PartialPage,
    QueryDrift,
    Tampered,
    Truncated,
    BlockedEnv,
    Revoked,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    #[must_use]
    pub const fn is_native(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Complete,
    AccessLost,
    ProviderUnknown,
    FinalError,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderErrorEvidence {
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub retryable: bool,
    pub blocked_env: bool,
    pub error_digest: Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1PolicyAuthority;

impl Layer1PolicyAuthority {
    #[must_use]
    pub const fn connected() -> bool {
        false
    }

    #[must_use]
    pub const fn native_provider() -> bool {
        false
    }

    #[must_use]
    pub const fn durable_receipt() -> bool {
        false
    }

    #[must_use]
    pub const fn certification() -> bool {
        false
    }

    #[must_use]
    pub const fn outcome_authority() -> bool {
        false
    }

    #[must_use]
    pub const fn external_writes() -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AzurePolicyRegistration {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_digest: Digest,
    pub provider_api_version: String,
    pub contract_digest: Digest,
    pub permission_digest: Digest,
    pub query_digest: Digest,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub revision: Revision,
    pub state: RegistrationState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationRevocation {
    pub previous_registration_digest: Digest,
    pub registration_digest: Digest,
    pub revision: Revision,
    pub revocation_digest: Digest,
}

impl AzurePolicyRegistration {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        provider_version: impl Into<String>,
        provider_digest: Digest,
        provider_api_version: impl Into<String>,
        contract_digest: Digest,
        permission_digest: Digest,
        query_digest: Digest,
        scope_digest: Digest,
    ) -> Result<Self, ModelError> {
        let provider_version = provider_version.into();
        let provider_api_version = provider_api_version.into();
        if provider_version.is_empty()
            || provider_api_version.is_empty()
            || !is_digest(provider_digest.as_str())
            || !is_digest(contract_digest.as_str())
            || !is_digest(permission_digest.as_str())
            || !is_digest(query_digest.as_str())
            || !is_digest(scope_digest.as_str())
        {
            return Err(ModelError::InvalidRegistration);
        }
        let revision = Revision::new(1)?;
        let evidence_digest = Digest::from_text("evidence-unbound");
        let registration_digest = Self::compute_digest(
            &provider_version,
            &provider_digest,
            &provider_api_version,
            &contract_digest,
            &permission_digest,
            &query_digest,
            &scope_digest,
            &evidence_digest,
            revision,
            RegistrationState::Active,
        );
        Ok(Self {
            schema_version: crate::AZURE_POLICY_COMPLIANCE_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: crate::AZURE_POLICY_COMPLIANCE_RESULT_CONTRACT_VERSION.to_owned(),
            service_id: crate::AZURE_POLICY_COMPLIANCE_RESULT_SERVICE_ID.to_owned(),
            provider_id: crate::AZURE_POLICY_INSIGHTS_PROVIDER_ID.to_owned(),
            provider_version,
            provider_digest,
            provider_api_version,
            contract_digest,
            permission_digest,
            query_digest,
            scope_digest,
            evidence_digest,
            registration_digest,
            revision,
            state: RegistrationState::Active,
        })
    }

    pub fn bind_evidence(&mut self, evidence_digest: Digest) -> Result<(), ModelError> {
        self.ensure_active()?;
        if !is_digest(evidence_digest.as_str()) {
            return Err(ModelError::InvalidRegistration);
        }
        self.evidence_digest = evidence_digest;
        self.registration_digest = Self::compute_digest(
            &self.provider_version,
            &self.provider_digest,
            &self.provider_api_version,
            &self.contract_digest,
            &self.permission_digest,
            &self.query_digest,
            &self.scope_digest,
            &self.evidence_digest,
            self.revision,
            self.state,
        );
        Ok(())
    }

    pub fn bind_query(&mut self, query_digest: Digest) -> Result<(), ModelError> {
        self.ensure_active()?;
        if !is_digest(query_digest.as_str()) {
            return Err(ModelError::InvalidRegistration);
        }
        self.query_digest = query_digest;
        self.registration_digest = Self::compute_digest(
            &self.provider_version,
            &self.provider_digest,
            &self.provider_api_version,
            &self.contract_digest,
            &self.permission_digest,
            &self.query_digest,
            &self.scope_digest,
            &self.evidence_digest,
            self.revision,
            self.state,
        );
        Ok(())
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
        let previous_registration_digest = self.registration_digest.clone();
        self.state = RegistrationState::Revoked;
        self.registration_digest = Self::compute_digest(
            &self.provider_version,
            &self.provider_digest,
            &self.provider_api_version,
            &self.contract_digest,
            &self.permission_digest,
            &self.query_digest,
            &self.scope_digest,
            &self.evidence_digest,
            self.revision,
            self.state,
        );
        let revocation_digest = Digest::from_fields(
            "azure-policy-registration-revocation/v1",
            &[
                previous_registration_digest.as_str().to_owned(),
                self.registration_digest.as_str().to_owned(),
                self.revision.get().to_string(),
            ],
        );
        Ok(RegistrationRevocation {
            previous_registration_digest,
            registration_digest: self.registration_digest.clone(),
            revision: self.revision,
            revocation_digest,
        })
    }

    pub fn restore(&mut self) -> Result<(), ModelError> {
        if self.state == RegistrationState::Active {
            return Err(ModelError::InvalidRegistration);
        }
        self.state = RegistrationState::Active;
        self.revision = Revision::new(self.revision.get().saturating_add(1))?;
        self.evidence_digest = Digest::from_text("evidence-unbound");
        self.registration_digest = Self::compute_digest(
            &self.provider_version,
            &self.provider_digest,
            &self.provider_api_version,
            &self.contract_digest,
            &self.permission_digest,
            &self.query_digest,
            &self.scope_digest,
            &self.evidence_digest,
            self.revision,
            self.state,
        );
        Ok(())
    }

    fn compute_digest(
        provider_version: &str,
        provider_digest: &Digest,
        provider_api_version: &str,
        contract_digest: &Digest,
        permission_digest: &Digest,
        query_digest: &Digest,
        scope_digest: &Digest,
        evidence_digest: &Digest,
        revision: Revision,
        state: RegistrationState,
    ) -> Digest {
        Digest::from_fields(
            "azure-policy-registration/v1",
            &[
                crate::AZURE_POLICY_COMPLIANCE_RESULT_SCHEMA_VERSION.to_owned(),
                crate::AZURE_POLICY_COMPLIANCE_RESULT_CONTRACT_VERSION.to_owned(),
                crate::AZURE_POLICY_COMPLIANCE_RESULT_SERVICE_ID.to_owned(),
                crate::AZURE_POLICY_INSIGHTS_PROVIDER_ID.to_owned(),
                provider_version.to_owned(),
                provider_digest.as_str().to_owned(),
                provider_api_version.to_owned(),
                contract_digest.as_str().to_owned(),
                permission_digest.as_str().to_owned(),
                query_digest.as_str().to_owned(),
                scope_digest.as_str().to_owned(),
                evidence_digest.as_str().to_owned(),
                revision.get().to_string(),
                format!("{state:?}"),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionFenceReceipt {
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub project_revision: Revision,
    pub mission_revision: Revision,
    pub work_product_revision: Revision,
}

impl From<&PermissionFence> for PermissionFenceReceipt {
    fn from(value: &PermissionFence) -> Self {
        Self {
            scope_digest: value.scope_digest.clone(),
            permission_digest: value.permission_digest.clone(),
            project_revision: value.project_revision,
            mission_revision: value.mission_revision,
            work_product_revision: value.work_product_revision,
        }
    }
}

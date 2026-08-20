//! Safe, bounded Azure Resource Health projections.
//!
//! Provider JSON is parsed at the transport boundary and is never retained in
//! the public evidence model. The model contains only scope metadata,
//! status/timestamp facts, digest-only identifiers, and bounded receipts.

use std::{collections::BTreeSet, fmt, str::FromStr};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    AZURE_RESOURCE_HEALTH_API_REVISION, AZURE_RESOURCE_HEALTH_API_VERSION,
    AZURE_RESOURCE_HEALTH_PLUGIN_VERSION_TEXT,
};

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_REGION_BYTES: usize = 128;
pub const MAX_RESOURCE_ID_BYTES: usize = 2 * 1024;
pub const MAX_EVENT_WINDOW_DAYS: i64 = 31;
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
pub const MAX_EVENTS: usize = 128;
pub const MAX_AFFECTED_RESOURCE_DIGESTS_PER_EVENT: usize = 32;
pub const MAX_CURSOR_BYTES: usize = 512;
pub const MAX_EVENT_PROPERTY_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidIdentifier { field: &'static str },
    #[error("resource id is not a fully qualified Azure Resource Manager id")]
    InvalidResourceId,
    #[error("resource id is outside the registered subscription")]
    SubscriptionMismatch,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("event window is empty, reversed, or longer than the Layer-1 bound")]
    InvalidEventWindow,
    #[error("event timestamp is outside the registered event window")]
    EventWindowMismatch,
    #[error("digest is not a lowercase SHA-256 hex digest")]
    InvalidDigest,
    #[error("required Azure Resource Health permission is missing")]
    MissingPermission,
    #[error("the permission digest does not match its immutable permissions")]
    PermissionDigestMismatch,
    #[error("the registration is invalid or has drifted")]
    InvalidRegistration,
    #[error("the registration or secret reference is already revoked")]
    AlreadyRevoked,
    #[error("the registration or secret reference is not revoked")]
    NotRevoked,
    #[error("a bounded value exceeds its Layer-1 limit")]
    BoundExceeded,
    #[error("the opaque cursor is invalid or too large")]
    InvalidCursor,
    #[error("the normalized status is unknown")]
    UnknownStatus,
    #[error("a normalized evidence digest does not match its fields")]
    DigestMismatch,
}

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
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
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
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

impl AsRef<str> for Digest {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest::from_bytes(bytes)
}

pub fn digest_serializable<T: Serialize>(value: &T) -> Result<Digest, ModelError> {
    let bytes = serde_json::to_vec(value).map_err(|_| ModelError::DigestMismatch)?;
    Ok(sha256_digest(&bytes))
}

#[must_use]
pub fn canonical_digest<T: Serialize>(value: &T) -> Digest {
    digest_serializable(value).expect("Layer-1 canonical values serialize")
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn validate_text(
    value: &str,
    field: &'static str,
    max_bytes: usize,
    allow_internal_whitespace: bool,
) -> Result<(), ModelError> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
        || (!allow_internal_whitespace && value.chars().any(char::is_whitespace))
    {
        Err(ModelError::InvalidIdentifier { field })
    } else {
        Ok(())
    }
}

fn validate_revision(value: u64) -> Result<Revision, ModelError> {
    Revision::new(value)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventWindow {
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    window_digest: Digest,
}

impl EventWindow {
    pub fn new(start: DateTime<Utc>, end: DateTime<Utc>) -> Result<Self, ModelError> {
        let duration = end
            .signed_duration_since(start)
            .to_std()
            .map_err(|_| ModelError::InvalidEventWindow)?;
        if duration.is_zero()
            || duration > std::time::Duration::from_secs((MAX_EVENT_WINDOW_DAYS * 86_400) as u64)
        {
            return Err(ModelError::InvalidEventWindow);
        }
        let window_digest =
            canonical_digest(&("azure-resource-health-event-window/v1", &start, &end));
        Ok(Self {
            start,
            end,
            window_digest,
        })
    }

    #[must_use]
    pub fn start(&self) -> DateTime<Utc> {
        self.start
    }

    #[must_use]
    pub fn end(&self) -> DateTime<Utc> {
        self.end
    }

    #[must_use]
    pub fn start_time(&self) -> DateTime<Utc> {
        self.start()
    }

    #[must_use]
    pub fn end_time(&self) -> DateTime<Utc> {
        self.end()
    }

    #[must_use]
    pub fn duration(&self) -> Duration {
        self.end.signed_duration_since(self.start)
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.window_digest
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let rebuilt = Self::new(self.start, self.end)?;
        if rebuilt.window_digest == self.window_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AzureResourceHealthPermission {
    AvailabilityStatusRead,
    EventsRead,
}

impl AzureResourceHealthPermission {
    #[must_use]
    pub const fn api_action(self) -> &'static str {
        match self {
            Self::AvailabilityStatusRead => "Microsoft.ResourceHealth/availabilityStatuses/read",
            Self::EventsRead => "Microsoft.ResourceHealth/events/read",
        }
    }

    #[allow(non_upper_case_globals)]
    pub const ReadAvailabilityStatus: Self = Self::AvailabilityStatusRead;

    #[allow(non_upper_case_globals)]
    pub const ReadEvents: Self = Self::EventsRead;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionFence {
    permissions: BTreeSet<AzureResourceHealthPermission>,
    permission_digest: Digest,
}

impl PermissionFence {
    pub fn new(
        permissions: impl IntoIterator<Item = AzureResourceHealthPermission>,
    ) -> Result<Self, ModelError> {
        let permissions = permissions.into_iter().collect::<BTreeSet<_>>();
        if !permissions.contains(&AzureResourceHealthPermission::AvailabilityStatusRead)
            || !permissions.contains(&AzureResourceHealthPermission::EventsRead)
        {
            return Err(ModelError::MissingPermission);
        }
        let permission_digest = canonical_digest(&(
            "azure-resource-health-permission-fence/v1",
            permissions
                .iter()
                .map(|permission| permission.api_action())
                .collect::<Vec<_>>(),
        ));
        Ok(Self {
            permissions,
            permission_digest,
        })
    }

    #[must_use]
    pub fn least_privilege() -> Self {
        Self::new([
            AzureResourceHealthPermission::AvailabilityStatusRead,
            AzureResourceHealthPermission::EventsRead,
        ])
        .expect("the two required Azure Resource Health permissions are valid")
    }

    #[must_use]
    pub fn permissions(&self) -> &BTreeSet<AzureResourceHealthPermission> {
        &self.permissions
    }

    #[must_use]
    pub fn contains(&self, permission: AzureResourceHealthPermission) -> bool {
        self.permissions.contains(&permission)
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let rebuilt = Self::new(self.permissions.iter().copied())?;
        if rebuilt.permission_digest == self.permission_digest {
            Ok(())
        } else {
            Err(ModelError::PermissionDigestMismatch)
        }
    }
}

pub type PermissionScope = PermissionFence;

/// An opaque host-owned Entra credential handle.
///
/// This type intentionally does not implement serialization. It stores only
/// digests and a revocation bit; it never stores a token, client secret,
/// certificate, raw tenant identifier, or raw reference.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    reference_digest: Digest,
    tenant_digest: Digest,
    credential_revision: Revision,
    revoked: bool,
}

pub type EntraSecretReference = SecretReference;

impl SecretReference {
    pub fn new(
        opaque_reference: impl Into<String>,
        tenant_id: impl Into<String>,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        let opaque_reference = opaque_reference.into();
        let tenant_id = tenant_id.into();
        validate_text(
            &opaque_reference,
            "Entra secret reference",
            MAX_IDENTIFIER_BYTES,
            false,
        )?;
        validate_text(&tenant_id, "Entra tenant id", MAX_IDENTIFIER_BYTES, false)?;
        let credential_revision = Revision::new(credential_revision)?;
        let tenant_digest = Digest::from_text(tenant_id.as_bytes());
        let reference_digest = canonical_digest(&(
            "azure-resource-health-entra-reference/v1",
            &opaque_reference,
            &tenant_digest,
            credential_revision,
        ));
        Ok(Self {
            reference_digest,
            tenant_digest,
            credential_revision,
            revoked: false,
        })
    }

    pub fn for_tenant(
        opaque_reference: impl Into<String>,
        tenant_id: impl Into<String>,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        Self::new(opaque_reference, tenant_id, credential_revision)
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(&(
            "azure-resource-health-secret-reference/v1",
            &self.reference_digest,
            &self.tenant_digest,
            self.credential_revision,
            self.revoked,
        ))
    }

    #[must_use]
    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    #[must_use]
    pub fn tenant_digest(&self) -> &Digest {
        &self.tenant_digest
    }

    #[must_use]
    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    #[must_use]
    pub fn matches_tenant(&self, tenant_digest: &Digest) -> bool {
        &self.tenant_digest == tenant_digest
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            Err(ModelError::AlreadyRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }

    pub fn restore(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            self.revoked = false;
            Ok(())
        } else {
            Err(ModelError::NotRevoked)
        }
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference", &"<opaque>")
            .field("tenant", &"<opaque>")
            .field("reference_digest", &self.reference_digest)
            .field("tenant_digest", &self.tenant_digest)
            .field("credential_revision", &self.credential_revision)
            .field("revoked", &self.revoked)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AzureResourceHealthScopeInput {
    pub tenant_id: String,
    pub subscription_id: String,
    pub resource_id: String,
    pub resource_revision: u64,
    pub region: String,
    pub event_window: EventWindow,
    pub project_id: String,
    pub project_revision: u64,
    pub mission_id: String,
    pub mission_revision: u64,
    pub work_product_id: String,
    pub work_product_revision: u64,
    pub permissions: PermissionFence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AzureResourceHealthScope {
    tenant_digest: Digest,
    subscription_id: String,
    resource_id: String,
    resource_digest: Digest,
    resource_revision: Revision,
    region: String,
    event_window: EventWindow,
    project_id: String,
    project_revision: Revision,
    mission_id: String,
    mission_revision: Revision,
    work_product_id: String,
    work_product_revision: Revision,
    permissions: PermissionFence,
    scope_digest: Digest,
}

impl AzureResourceHealthScope {
    pub fn new(input: AzureResourceHealthScopeInput) -> Result<Self, ModelError> {
        validate_text(
            &input.tenant_id,
            "Entra tenant id",
            MAX_IDENTIFIER_BYTES,
            false,
        )?;
        validate_text(
            &input.subscription_id,
            "Azure subscription id",
            MAX_IDENTIFIER_BYTES,
            false,
        )?;
        let resource_id = normalize_resource_id(&input.resource_id)?;
        if !resource_belongs_to_subscription(&resource_id, &input.subscription_id) {
            return Err(ModelError::SubscriptionMismatch);
        }
        validate_text(&input.region, "Azure region", MAX_REGION_BYTES, false)?;
        validate_text(
            &input.project_id,
            "Hartevo project id",
            MAX_IDENTIFIER_BYTES,
            true,
        )?;
        validate_text(&input.mission_id, "Mission id", MAX_IDENTIFIER_BYTES, true)?;
        validate_text(
            &input.work_product_id,
            "Work Product id",
            MAX_IDENTIFIER_BYTES,
            true,
        )?;
        let resource_revision = validate_revision(input.resource_revision)?;
        let project_revision = validate_revision(input.project_revision)?;
        let mission_revision = validate_revision(input.mission_revision)?;
        let work_product_revision = validate_revision(input.work_product_revision)?;
        input.event_window.validate()?;
        input.permissions.validate()?;
        let tenant_digest = Digest::from_text(input.tenant_id.as_bytes());
        let resource_digest = Digest::from_text(resource_id.as_bytes());
        let mut scope = Self {
            tenant_digest,
            subscription_id: input.subscription_id,
            resource_id,
            resource_digest,
            resource_revision,
            region: input.region,
            event_window: input.event_window,
            project_id: input.project_id,
            project_revision,
            mission_id: input.mission_id,
            mission_revision,
            work_product_id: input.work_product_id,
            work_product_revision,
            permissions: input.permissions,
            scope_digest: Digest::from_text(b"azure-resource-health-scope-uninitialized"),
        };
        scope.scope_digest = scope.compute_scope_digest();
        Ok(scope)
    }

    #[must_use]
    pub fn tenant_digest(&self) -> &Digest {
        &self.tenant_digest
    }

    #[must_use]
    pub fn subscription_id(&self) -> &str {
        &self.subscription_id
    }

    #[must_use]
    pub fn resource_id(&self) -> &str {
        &self.resource_id
    }

    #[must_use]
    pub fn resource_digest(&self) -> &Digest {
        &self.resource_digest
    }

    #[must_use]
    pub const fn resource_revision(&self) -> Revision {
        self.resource_revision
    }

    #[must_use]
    pub fn region(&self) -> &str {
        &self.region
    }

    #[must_use]
    pub fn event_window(&self) -> &EventWindow {
        &self.event_window
    }

    #[must_use]
    pub fn project_id(&self) -> &str {
        &self.project_id
    }

    #[must_use]
    pub const fn project_revision(&self) -> Revision {
        self.project_revision
    }

    #[must_use]
    pub fn mission_id(&self) -> &str {
        &self.mission_id
    }

    #[must_use]
    pub const fn mission_revision(&self) -> Revision {
        self.mission_revision
    }

    #[must_use]
    pub fn work_product_id(&self) -> &str {
        &self.work_product_id
    }

    #[must_use]
    pub const fn work_product_revision(&self) -> Revision {
        self.work_product_revision
    }

    #[must_use]
    pub fn permissions(&self) -> &PermissionFence {
        &self.permissions
    }

    #[must_use]
    pub fn permission_digest(&self) -> &Digest {
        self.permissions.digest()
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        self.scope_digest()
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if normalize_resource_id(&self.resource_id)? != self.resource_id
            || !resource_belongs_to_subscription(&self.resource_id, &self.subscription_id)
            || self.resource_digest != Digest::from_text(self.resource_id.as_bytes())
            || self.event_window.validate().is_err()
            || self.permissions.validate().is_err()
            || self.resource_revision.get() == 0
            || self.project_revision.get() == 0
            || self.mission_revision.get() == 0
            || self.work_product_revision.get() == 0
            || self.compute_scope_digest() != self.scope_digest
        {
            Err(ModelError::InvalidRegistration)
        } else {
            Ok(())
        }
    }

    fn compute_scope_digest(&self) -> Digest {
        canonical_digest(&(
            "azure-resource-health-scope/v1",
            &self.tenant_digest,
            &self.subscription_id,
            &self.resource_digest,
            self.resource_revision,
            &self.region,
            self.event_window.digest(),
            &self.project_id,
            self.project_revision,
            &self.mission_id,
            self.mission_revision,
            &self.work_product_id,
            self.work_product_revision,
            self.permissions.digest(),
        ))
    }
}

fn normalize_resource_id(value: &str) -> Result<String, ModelError> {
    validate_text(value, "Azure resource id", MAX_RESOURCE_ID_BYTES, false)?;
    let resource_id = if value.starts_with('/') {
        value.to_owned()
    } else {
        format!("/{value}")
    };
    let lowered = resource_id.to_ascii_lowercase();
    if !lowered.starts_with("/subscriptions/")
        || !lowered.contains("/resourcegroups/")
        || !lowered.contains("/providers/")
        || lowered.contains('?')
        || lowered.contains('#')
        || resource_id.contains("//")
    {
        return Err(ModelError::InvalidResourceId);
    }
    Ok(resource_id)
}

fn resource_belongs_to_subscription(resource_id: &str, subscription_id: &str) -> bool {
    let expected_prefix = format!("/subscriptions/{subscription_id}/");
    resource_id
        .to_ascii_lowercase()
        .starts_with(&expected_prefix.to_ascii_lowercase())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

impl RegistrationState {
    #[must_use]
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AzureResourceHealthRegistration {
    pub state: RegistrationState,
    pub epoch: Revision,
    pub version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub tenant_digest: Digest,
    pub resource_digest: Digest,
    pub resource_revision: Revision,
    pub event_window_digest: Digest,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
}

impl AzureResourceHealthRegistration {
    pub fn new(
        scope: &AzureResourceHealthScope,
        secret: &SecretReference,
        provider_digest: &Digest,
        api_digest: &Digest,
    ) -> Result<Self, ModelError> {
        scope.validate()?;
        if !secret.matches_tenant(scope.tenant_digest()) || secret.is_revoked() {
            return Err(ModelError::InvalidRegistration);
        }
        let mut registration = Self {
            state: RegistrationState::Active,
            epoch: Revision::new(1)?,
            version_digest: Digest::from_text(AZURE_RESOURCE_HEALTH_PLUGIN_VERSION_TEXT),
            contract_digest: crate::contract_digest(),
            provider_digest: provider_digest.clone(),
            api_digest: api_digest.clone(),
            permission_digest: scope.permission_digest().clone(),
            tenant_digest: scope.tenant_digest().clone(),
            resource_digest: scope.resource_digest().clone(),
            resource_revision: scope.resource_revision(),
            event_window_digest: scope.event_window().digest().clone(),
            scope_digest: scope.scope_digest().clone(),
            secret_reference_digest: secret.digest(),
            evidence_digest: Digest::from_text("azure-resource-health/no-evidence/v1"),
            registration_digest: Digest::from_text(
                "azure-resource-health/registration-uninitialized",
            ),
        };
        registration.registration_digest = registration.compute_digest();
        Ok(registration)
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.state.is_active()
    }

    #[must_use]
    pub fn evidence_binding_digest(&self, evidence_digest: &Digest) -> Digest {
        canonical_digest(&(
            "azure-resource-health-registration-evidence-binding/v1",
            &self.registration_digest,
            evidence_digest,
        ))
    }

    pub fn validate(
        &self,
        scope: &AzureResourceHealthScope,
        secret: &SecretReference,
        provider_digest: &Digest,
        api_digest: &Digest,
    ) -> Result<(), ModelError> {
        if !self.is_active()
            || self.version_digest != Digest::from_text(AZURE_RESOURCE_HEALTH_PLUGIN_VERSION_TEXT)
            || self.contract_digest != crate::contract_digest()
            || self.provider_digest != *provider_digest
            || self.api_digest != *api_digest
            || self.permission_digest != *scope.permission_digest()
            || self.tenant_digest != *scope.tenant_digest()
            || self.resource_digest != *scope.resource_digest()
            || self.resource_revision != scope.resource_revision()
            || self.event_window_digest != *scope.event_window().digest()
            || self.scope_digest != *scope.scope_digest()
            || self.secret_reference_digest != secret.digest()
            || !secret.matches_tenant(scope.tenant_digest())
            || secret.is_revoked()
            || self.registration_digest != self.compute_digest()
        {
            Err(ModelError::InvalidRegistration)
        } else {
            Ok(())
        }
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation, ModelError> {
        if !self.is_active() {
            return Err(ModelError::AlreadyRevoked);
        }
        let previous_registration_digest = self.registration_digest.clone();
        self.state = RegistrationState::Revoked;
        self.epoch = Revision::new(self.epoch.get().saturating_add(1))?;
        self.registration_digest = self.compute_digest();
        Ok(RegistrationRevocation {
            previous_registration_digest,
            registration_digest: self.registration_digest.clone(),
            epoch: self.epoch,
        })
    }

    pub fn restore(&mut self) -> Result<(), ModelError> {
        if self.is_active() {
            return Err(ModelError::NotRevoked);
        }
        self.state = RegistrationState::Active;
        self.epoch = Revision::new(self.epoch.get().saturating_add(1))?;
        self.registration_digest = self.compute_digest();
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        canonical_digest(&(
            "azure-resource-health-registration/v1",
            self.state,
            self.epoch,
            &self.version_digest,
            &self.contract_digest,
            &self.provider_digest,
            &self.api_digest,
            &self.permission_digest,
            &self.tenant_digest,
            &self.resource_digest,
            self.resource_revision,
            &self.event_window_digest,
            &self.scope_digest,
            &self.secret_reference_digest,
            &self.evidence_digest,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationRevocation {
    pub previous_registration_digest: Digest,
    pub registration_digest: Digest,
    pub epoch: Revision,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AvailabilityState {
    Available,
    Degraded,
    Unavailable,
    Unknown,
}

impl AvailabilityState {
    #[must_use]
    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "available" => Self::Available,
            "degraded" => Self::Degraded,
            "unavailable" => Self::Unavailable,
            _ => Self::Unknown,
        }
    }

    #[must_use]
    pub const fn is_known(self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

impl FromStr for AvailabilityState {
    type Err = ModelError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let parsed = Self::parse(value);
        if parsed.is_known() {
            Ok(parsed)
        } else {
            Err(ModelError::UnknownStatus)
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventStatus {
    Active,
    InProgress,
    Resolved,
    Closed,
    Unknown,
}

impl EventStatus {
    #[must_use]
    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "active" => Self::Active,
            "inprogress" | "in_progress" | "investigating" => Self::InProgress,
            "resolved" | "mitigated" => Self::Resolved,
            "closed" => Self::Closed,
            _ => Self::Unknown,
        }
    }

    #[must_use]
    pub const fn is_known(self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventLevel {
    Critical,
    Error,
    Warning,
    Informational,
    Unknown,
}

impl EventLevel {
    #[must_use]
    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "critical" => Self::Critical,
            "error" => Self::Error,
            "warning" => Self::Warning,
            "informational" | "info" => Self::Informational,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AvailabilityObservation {
    pub status: AvailabilityState,
    pub previous_status: Option<AvailabilityState>,
    pub occurred_at: Option<DateTime<Utc>>,
    pub reported_at: Option<DateTime<Utc>>,
    pub event_id_digest: Option<Digest>,
    pub resource_digest: Digest,
    pub resource_revision: Revision,
    pub status_digest: Digest,
}

impl AvailabilityObservation {
    #[must_use]
    pub fn observed_at(&self) -> Option<DateTime<Utc>> {
        self.reported_at.or(self.occurred_at)
    }

    #[must_use]
    pub fn is_known(&self) -> bool {
        self.status.is_known() && self.observed_at().is_some()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceHealthEventSummary {
    pub event_id: Digest,
    pub status: EventStatus,
    pub previous_status: Option<EventStatus>,
    pub event_timestamp: DateTime<Utc>,
    pub last_update_time: Option<DateTime<Utc>>,
    pub impact_start_time: Option<DateTime<Utc>>,
    pub impact_mitigation_time: Option<DateTime<Utc>>,
    pub level: EventLevel,
    pub affected_resource_digests: Vec<Digest>,
    pub transition_digest: Digest,
    pub event_digest: Digest,
}

impl ResourceHealthEventSummary {
    #[must_use]
    pub fn timestamp(&self) -> DateTime<Utc> {
        self.event_timestamp
    }

    #[must_use]
    pub fn is_known(&self) -> bool {
        self.status.is_known()
            && self.previous_status.is_none_or(EventStatus::is_known)
            && !self.affected_resource_digests.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    #[must_use]
    pub const fn is_native(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_connected(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AzureResourceHealthOperation {
    AvailabilityStatus,
    EventList,
}

impl AzureResourceHealthOperation {
    #[must_use]
    pub const fn path_suffix(self) -> &'static str {
        match self {
            Self::AvailabilityStatus => {
                "/providers/Microsoft.ResourceHealth/availabilityStatuses/current"
            }
            Self::EventList => "/providers/Microsoft.ResourceHealth/events",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderResponseReceipt {
    pub operation: AzureResourceHealthOperation,
    pub request_digest: Digest,
    pub request_path_digest: Digest,
    pub api_version: String,
    pub status_code: Option<u16>,
    pub response_bytes: usize,
    pub response_digest: Digest,
    pub provider_revision: String,
    pub cursor_digest: Option<Digest>,
    pub raw_response_retained: bool,
    pub raw_descriptions_retained: bool,
    pub raw_recommendations_retained: bool,
    pub raw_tags_retained: bool,
    pub credential_material_retained: bool,
    pub native: bool,
    pub connected: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Complete,
    Empty,
    Partial,
    Unknown,
    AccessLost,
    NotFound,
    Conflict,
    Throttled,
    TimedOut,
    ProviderUnknown,
    Expired,
    Revoked,
}

impl EvidenceState {
    #[must_use]
    pub const fn is_decision_ready(self) -> bool {
        matches!(self, Self::Complete)
    }

    #[must_use]
    pub const fn is_failure(self) -> bool {
        !matches!(self, Self::Complete | Self::Empty)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AzureResourceHealthEvidence {
    pub plugin_version: String,
    pub version_digest: Digest,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_digest: Digest,
    pub api_version: String,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub tenant_digest: Digest,
    pub subscription_id: String,
    pub resource_digest: Digest,
    pub resource_revision: Revision,
    pub event_window_digest: Digest,
    pub registration_digest: Digest,
    pub provenance: TransportProvenance,
    pub state: EvidenceState,
    pub availability_state: EvidenceState,
    pub event_list_state: EvidenceState,
    pub availability: Option<AvailabilityObservation>,
    pub events: Vec<ResourceHealthEventSummary>,
    pub next_cursor_digest: Option<Digest>,
    pub receipts: Vec<ProviderResponseReceipt>,
    pub read_only: bool,
    pub native_provider: bool,
    pub connected: bool,
    pub external_write_performed: bool,
    pub causal_authority: bool,
    pub recovery_authority: bool,
    pub outcome_authority: bool,
    pub raw_provider_payload_retained: bool,
    pub evidence_digest: Digest,
}

impl AzureResourceHealthEvidence {
    #[must_use]
    pub fn digest(&self) -> Digest {
        self.compute_digest()
    }

    pub fn verify_integrity(&self) -> Result<(), ModelError> {
        if self.evidence_digest != self.compute_digest() {
            return Err(ModelError::DigestMismatch);
        }
        if self.events.len() > MAX_EVENTS
            || self.events.iter().any(|event| {
                event.affected_resource_digests.len() > MAX_AFFECTED_RESOURCE_DIGESTS_PER_EVENT
            })
            || !self.read_only
            || self.native_provider
            || self.connected
            || self.external_write_performed
            || self.causal_authority
            || self.recovery_authority
            || self.outcome_authority
            || self.raw_provider_payload_retained
            || self.receipts.iter().any(|receipt| {
                receipt.raw_response_retained
                    || receipt.raw_descriptions_retained
                    || receipt.raw_recommendations_retained
                    || receipt.raw_tags_retained
                    || receipt.credential_material_retained
                    || receipt.native
                    || receipt.connected
            })
        {
            return Err(ModelError::InvalidRegistration);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        canonical_digest(&(
            "azure-resource-health-evidence/v1",
            (
                &self.plugin_version,
                &self.version_digest,
                &self.contract_version,
                &self.contract_digest,
                &self.provider_id,
                &self.provider_digest,
                &self.api_version,
                &self.api_digest,
                &self.permission_digest,
                &self.scope_digest,
                &self.tenant_digest,
                &self.subscription_id,
                &self.resource_digest,
                self.resource_revision,
                &self.event_window_digest,
            ),
            (
                &self.registration_digest,
                self.provenance,
                self.state,
                self.availability_state,
                self.event_list_state,
                &self.availability,
                &self.events,
                &self.next_cursor_digest,
                &self.receipts,
                self.read_only,
                self.native_provider,
                self.connected,
                self.external_write_performed,
                self.causal_authority,
                self.recovery_authority,
            ),
            (self.outcome_authority, self.raw_provider_payload_retained),
        ))
    }
}

pub struct OpaquePageCursor {
    value: String,
    cursor_digest: Digest,
}

impl OpaquePageCursor {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_text(&value, "opaque page cursor", MAX_CURSOR_BYTES, false)?;
        Ok(Self {
            cursor_digest: Digest::from_text(value.as_bytes()),
            value,
        })
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.cursor_digest
    }

    pub(crate) fn value(&self) -> &str {
        &self.value
    }
}

impl Clone for OpaquePageCursor {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            cursor_digest: self.cursor_digest.clone(),
        }
    }
}

impl PartialEq for OpaquePageCursor {
    fn eq(&self, other: &Self) -> bool {
        self.cursor_digest == other.cursor_digest
    }
}

impl Eq for OpaquePageCursor {}

impl fmt::Debug for OpaquePageCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaquePageCursor")
            .field("cursor", &"<opaque>")
            .field("digest", &self.cursor_digest)
            .finish_non_exhaustive()
    }
}

pub(crate) fn bounded_string(value: Option<&serde_json::Value>, max: usize) -> Option<String> {
    let value = value?.as_str()?;
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        None
    } else {
        Some(value.to_owned())
    }
}

pub(crate) fn parse_rfc3339(value: Option<&serde_json::Value>) -> Option<DateTime<Utc>> {
    bounded_string(value, 128)
        .and_then(|value| DateTime::parse_from_rfc3339(&value).ok())
        .map(|value| value.with_timezone(&Utc))
}

pub(crate) fn api_digest() -> Digest {
    canonical_digest(&(
        "azure-resource-health-api/v1",
        AZURE_RESOURCE_HEALTH_API_VERSION,
        AZURE_RESOURCE_HEALTH_API_REVISION,
        AZURE_RESOURCE_HEALTH_OPERATION_AVAILABILITY_PATH,
        AZURE_RESOURCE_HEALTH_OPERATION_EVENTS_PATH,
    ))
}

pub const AZURE_RESOURCE_HEALTH_OPERATION_AVAILABILITY_PATH: &str =
    "/{resourceUri}/providers/Microsoft.ResourceHealth/availabilityStatuses/current";
pub const AZURE_RESOURCE_HEALTH_OPERATION_EVENTS_PATH: &str =
    "/{resourceUri}/providers/Microsoft.ResourceHealth/events";

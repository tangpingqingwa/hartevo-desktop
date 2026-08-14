//! Bounded, redacted Calendly result models and revision fences.

use std::{
    collections::{BTreeSet, HashSet},
    fmt,
};

use serde::{Deserialize, Serialize};

use crate::{
    API_ORIGIN, CalendlySchedulingResultError, MAX_DATE_WINDOW_DAYS, MAX_INVITEES, MAX_PAGES,
    MAX_TIMESTAMP_SKEW_MILLIS, MAX_WEBHOOK_AGE_MILLIS, MAX_WEBHOOK_SIGNALS,
    digest_serialized_with_domain, sha256_hex, valid_digest, valid_identifier,
};

/// A validated lower-case SHA-256 hex identity.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn new(value: impl Into<String>) -> Result<Self, CalendlySchedulingResultError> {
        let value = value.into().to_ascii_lowercase();
        if valid_digest(&value) {
            Ok(Self(value))
        } else {
            Err(CalendlySchedulingResultError::InvalidDigest)
        }
    }

    pub fn from_text(value: &str) -> Result<Self, CalendlySchedulingResultError> {
        Self::new(sha256_hex(value.as_bytes()))
    }

    pub fn from_fields(
        domain: &str,
        fields: &[String],
    ) -> Result<Self, CalendlySchedulingResultError> {
        let mut input = String::from(domain);
        input.push('\0');
        for field in fields {
            input.push_str(field);
            input.push('\0');
        }
        Self::from_text(&input)
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

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

macro_rules! bounded_identifier {
    ($name:ident) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, CalendlySchedulingResultError> {
                let value = value.into();
                if valid_identifier(&value, 256) {
                    Ok(Self(value))
                } else {
                    Err(CalendlySchedulingResultError::InvalidIdentifier)
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
                self.0.fmt(formatter)
            }
        }
    };
}

bounded_identifier!(ProjectId);
bounded_identifier!(MissionId);
bounded_identifier!(WorkProductId);
bounded_identifier!(DeliveryId);

/// A Calendly API v2 resource URI kept as an opaque identifier. The crate
/// never derives a name, email, join URL, or booking URL from it.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct OpaqueCalendlyUri(String);

impl OpaqueCalendlyUri {
    pub fn new(value: impl Into<String>) -> Result<Self, CalendlySchedulingResultError> {
        let value = value.into();
        let valid_origin = value.starts_with(&format!("{API_ORIGIN}/"));
        let valid_path = value
            .strip_prefix(&format!("{API_ORIGIN}/"))
            .is_some_and(|path| {
                !path.is_empty() && !path.contains(['?', '#', '\\']) && !path.contains("//")
            });
        if valid_origin && valid_path && valid_identifier(&value, 512) {
            Ok(Self(value))
        } else {
            Err(CalendlySchedulingResultError::InvalidIdentifier)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Result<Digest, CalendlySchedulingResultError> {
        Digest::from_text(self.as_str())
    }
}

impl fmt::Debug for OpaqueCalendlyUri {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("OpaqueCalendlyUri")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for OpaqueCalendlyUri {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

pub type OrganizationUri = OpaqueCalendlyUri;
pub type UserUri = OpaqueCalendlyUri;
pub type EventTypeUri = OpaqueCalendlyUri;
pub type ScheduledEventUri = OpaqueCalendlyUri;
pub type InviteeUri = OpaqueCalendlyUri;
pub type NoShowUri = OpaqueCalendlyUri;

/// A monotonic semantic version included in every registration.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginVersion {
    major: u16,
    minor: u16,
    patch: u16,
}

impl PluginVersion {
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    PersonalAccessToken,
    OAuth21,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, CalendlySchedulingResultError> {
        if value == 0 {
            Err(CalendlySchedulingResultError::InvalidScope)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Opaque keyring boundary. The raw PAT/OAuth reference and credential
/// material are intentionally absent from this type's serialized and debug
/// representations.
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    permission_digest: Digest,
    credential_revision: Revision,
    auth_method: AuthMethod,
    revoked: bool,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_digest: self.reference_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            permission_digest: self.permission_digest.clone(),
            credential_revision: self.credential_revision,
            auth_method: self.auth_method,
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
            .field("auth_method", &self.auth_method)
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
            && self.auth_method == other.auth_method
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
        auth_method: AuthMethod,
    ) -> Result<Self, CalendlySchedulingResultError> {
        let reference_id = reference_id.into();
        let credential_revision = Revision::new(credential_revision)
            .map_err(|_| CalendlySchedulingResultError::InvalidSecretReference)?;
        if !reference_id.starts_with("secret-ref-") || !valid_identifier(&reference_id, 256) {
            return Err(CalendlySchedulingResultError::InvalidSecretReference);
        }
        let reference_digest = Digest::from_fields(
            "hartevo.calendly-secret-reference/v1",
            &[
                reference_id,
                scope_digest.as_str().to_owned(),
                permission_digest.as_str().to_owned(),
                credential_revision.get().to_string(),
                format!("{auth_method:?}"),
            ],
        )?;
        Ok(Self {
            reference_digest,
            scope_digest,
            permission_digest,
            credential_revision,
            auth_method,
            revoked: false,
        })
    }

    pub fn for_scope(
        reference_id: impl Into<String>,
        scope: &CalendlyScope,
        lease: &PermissionLease,
        credential_revision: u64,
        auth_method: AuthMethod,
    ) -> Result<Self, CalendlySchedulingResultError> {
        Self::new(
            reference_id,
            scope.scope_digest().clone(),
            lease.permission_digest().clone(),
            credential_revision,
            auth_method,
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

    pub const fn auth_method(&self) -> AuthMethod {
        self.auth_method
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<(), CalendlySchedulingResultError> {
        if self.revoked {
            Err(CalendlySchedulingResultError::SecretAlreadyRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }
}

/// A bounded permission lease. It contains scope names and a digest, never a
/// token. Write scopes are rejected at construction time.
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
    ) -> Result<Self, CalendlySchedulingResultError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let scopes = scopes.into_iter().map(Into::into).collect::<BTreeSet<_>>();
        if scopes.is_empty()
            || scopes
                .iter()
                .any(|scope| !valid_identifier(scope, 128) || scope.ends_with(":write"))
            || !scopes.contains("users:read")
            || !scopes.contains("event_types:read")
            || !scopes.contains("scheduled_events:read")
        {
            return Err(CalendlySchedulingResultError::InvalidPermissionLease);
        }
        let lease_revision = Revision::new(lease_revision)
            .map_err(|_| CalendlySchedulingResultError::InvalidPermissionLease)?;
        #[derive(Serialize)]
        struct LeaseBody<'a> {
            scopes: &'a BTreeSet<String>,
            lease_revision: Revision,
            expires_at_millis: Option<u64>,
        }
        let permission_digest = digest_serialized_with_domain(
            "hartevo.calendly-permission-lease/v1",
            &LeaseBody {
                scopes: &scopes,
                lease_revision,
                expires_at_millis,
            },
        )?;
        Ok(Self {
            scopes,
            lease_revision,
            expires_at_millis,
            permission_digest,
        })
    }

    pub fn required_read(lease_revision: u64) -> Result<Self, CalendlySchedulingResultError> {
        Self::new(
            ["users:read", "event_types:read", "scheduled_events:read"],
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

    pub fn validate_at(&self, now_millis: u64) -> Result<(), CalendlySchedulingResultError> {
        if self.is_expired_at(now_millis) {
            Err(CalendlySchedulingResultError::PermissionLeaseExpired)
        } else {
            Ok(())
        }
    }
}

/// Inclusive start/exclusive end window used to bound scheduled-event reads.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DateWindow {
    start_at_millis: u64,
    end_at_millis: u64,
}

impl DateWindow {
    pub fn new(
        start_at_millis: u64,
        end_at_millis: u64,
    ) -> Result<Self, CalendlySchedulingResultError> {
        let max_duration = MAX_DATE_WINDOW_DAYS * 86_400_000;
        if start_at_millis >= end_at_millis || end_at_millis - start_at_millis > max_duration {
            Err(CalendlySchedulingResultError::InvalidDateWindow)
        } else {
            Ok(Self {
                start_at_millis,
                end_at_millis,
            })
        }
    }

    pub const fn start_at_millis(self) -> u64 {
        self.start_at_millis
    }

    pub const fn end_at_millis(self) -> u64 {
        self.end_at_millis
    }
}

/// Exact external and Hartevo identity fence for one scheduled event result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CalendlyScopeBinding {
    organization_uri: OrganizationUri,
    user_uri: UserUri,
    event_type_uri: EventTypeUri,
    scheduled_event_uri: ScheduledEventUri,
    project_id: ProjectId,
    project_revision: Revision,
    mission_id: MissionId,
    mission_revision: Revision,
    work_product_id: WorkProductId,
    work_product_revision: Revision,
    event_revision: Revision,
    date_window: DateWindow,
    binding_digest: Digest,
}

impl CalendlyScopeBinding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        organization_uri: impl Into<String>,
        user_uri: impl Into<String>,
        event_type_uri: impl Into<String>,
        scheduled_event_uri: impl Into<String>,
        project_id: impl Into<String>,
        project_revision: u64,
        mission_id: impl Into<String>,
        mission_revision: u64,
        work_product_id: impl Into<String>,
        work_product_revision: u64,
        event_revision: u64,
        date_window: DateWindow,
    ) -> Result<Self, CalendlySchedulingResultError> {
        let binding_without_digest = Self {
            organization_uri: OpaqueCalendlyUri::new(organization_uri)?,
            user_uri: OpaqueCalendlyUri::new(user_uri)?,
            event_type_uri: OpaqueCalendlyUri::new(event_type_uri)?,
            scheduled_event_uri: OpaqueCalendlyUri::new(scheduled_event_uri)?,
            project_id: ProjectId::new(project_id)?,
            project_revision: Revision::new(project_revision)?,
            mission_id: MissionId::new(mission_id)?,
            mission_revision: Revision::new(mission_revision)?,
            work_product_id: WorkProductId::new(work_product_id)?,
            work_product_revision: Revision::new(work_product_revision)?,
            event_revision: Revision::new(event_revision)?,
            date_window,
            binding_digest: Digest::from_text("pending")?,
        };
        #[derive(Serialize)]
        struct BindingBody<'a> {
            organization_uri: &'a OrganizationUri,
            user_uri: &'a UserUri,
            event_type_uri: &'a EventTypeUri,
            scheduled_event_uri: &'a ScheduledEventUri,
            project_id: &'a ProjectId,
            project_revision: Revision,
            mission_id: &'a MissionId,
            mission_revision: Revision,
            work_product_id: &'a WorkProductId,
            work_product_revision: Revision,
            event_revision: Revision,
            date_window: DateWindow,
        }
        let binding_digest = digest_serialized_with_domain(
            "hartevo.calendly-scope-binding/v1",
            &BindingBody {
                organization_uri: &binding_without_digest.organization_uri,
                user_uri: &binding_without_digest.user_uri,
                event_type_uri: &binding_without_digest.event_type_uri,
                scheduled_event_uri: &binding_without_digest.scheduled_event_uri,
                project_id: &binding_without_digest.project_id,
                project_revision: binding_without_digest.project_revision,
                mission_id: &binding_without_digest.mission_id,
                mission_revision: binding_without_digest.mission_revision,
                work_product_id: &binding_without_digest.work_product_id,
                work_product_revision: binding_without_digest.work_product_revision,
                event_revision: binding_without_digest.event_revision,
                date_window,
            },
        )?;
        Ok(Self {
            binding_digest,
            ..binding_without_digest
        })
    }

    pub fn binding_digest(&self) -> &Digest {
        &self.binding_digest
    }

    pub fn organization_uri(&self) -> &OrganizationUri {
        &self.organization_uri
    }

    pub fn user_uri(&self) -> &UserUri {
        &self.user_uri
    }

    pub fn event_type_uri(&self) -> &EventTypeUri {
        &self.event_type_uri
    }

    pub fn scheduled_event_uri(&self) -> &ScheduledEventUri {
        &self.scheduled_event_uri
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub const fn project_revision(&self) -> Revision {
        self.project_revision
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub const fn mission_revision(&self) -> Revision {
        self.mission_revision
    }

    pub fn work_product_id(&self) -> &WorkProductId {
        &self.work_product_id
    }

    pub const fn work_product_revision(&self) -> Revision {
        self.work_product_revision
    }

    pub const fn event_revision(&self) -> Revision {
        self.event_revision
    }

    pub const fn date_window(&self) -> DateWindow {
        self.date_window
    }
}

/// Scope plus the permission digest it is allowed to use.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CalendlyScope {
    binding: CalendlyScopeBinding,
    permission_digest: Digest,
    scope_digest: Digest,
}

impl CalendlyScope {
    pub fn new(
        binding: CalendlyScopeBinding,
        permission_digest: Digest,
    ) -> Result<Self, CalendlySchedulingResultError> {
        #[derive(Serialize)]
        struct ScopeBody<'a> {
            binding: &'a CalendlyScopeBinding,
            permission_digest: &'a Digest,
        }
        let scope_digest = digest_serialized_with_domain(
            "hartevo.calendly-scope/v1",
            &ScopeBody {
                binding: &binding,
                permission_digest: &permission_digest,
            },
        )?;
        Ok(Self {
            binding,
            permission_digest,
            scope_digest,
        })
    }

    pub fn binding(&self) -> &CalendlyScopeBinding {
        &self.binding
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn organization_uri(&self) -> &OrganizationUri {
        self.binding.organization_uri()
    }

    pub fn user_uri(&self) -> &UserUri {
        self.binding.user_uri()
    }

    pub fn event_type_uri(&self) -> &EventTypeUri {
        self.binding.event_type_uri()
    }

    pub fn scheduled_event_uri(&self) -> &ScheduledEventUri {
        self.binding.scheduled_event_uri()
    }

    pub fn project_id(&self) -> &ProjectId {
        self.binding.project_id()
    }

    pub const fn project_revision(&self) -> Revision {
        self.binding.project_revision()
    }

    pub fn mission_id(&self) -> &MissionId {
        self.binding.mission_id()
    }

    pub const fn mission_revision(&self) -> Revision {
        self.binding.mission_revision()
    }

    pub fn work_product_id(&self) -> &WorkProductId {
        self.binding.work_product_id()
    }

    pub const fn work_product_revision(&self) -> Revision {
        self.binding.work_product_revision()
    }

    pub const fn event_revision(&self) -> Revision {
        self.binding.event_revision()
    }

    pub const fn date_window(&self) -> DateWindow {
        self.binding.date_window()
    }
}

/// Current kernel-provided identity snapshot used to reject stale reads.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionContext {
    project_id: ProjectId,
    project_revision: Revision,
    mission_id: MissionId,
    mission_revision: Revision,
    work_product_id: WorkProductId,
    work_product_revision: Revision,
    event_revision: Revision,
    scope_digest: Digest,
}

impl MissionContext {
    pub fn from_scope(scope: &CalendlyScope) -> Self {
        Self {
            project_id: scope.project_id().clone(),
            project_revision: scope.project_revision(),
            mission_id: scope.mission_id().clone(),
            mission_revision: scope.mission_revision(),
            work_product_id: scope.work_product_id().clone(),
            work_product_revision: scope.work_product_revision(),
            event_revision: scope.event_revision(),
            scope_digest: scope.scope_digest().clone(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project_id: impl Into<String>,
        project_revision: u64,
        mission_id: impl Into<String>,
        mission_revision: u64,
        work_product_id: impl Into<String>,
        work_product_revision: u64,
        event_revision: u64,
        scope_digest: Digest,
    ) -> Result<Self, CalendlySchedulingResultError> {
        Ok(Self {
            project_id: ProjectId::new(project_id)?,
            project_revision: Revision::new(project_revision)?,
            mission_id: MissionId::new(mission_id)?,
            mission_revision: Revision::new(mission_revision)?,
            work_product_id: WorkProductId::new(work_product_id)?,
            work_product_revision: Revision::new(work_product_revision)?,
            event_revision: Revision::new(event_revision)?,
            scope_digest,
        })
    }

    pub fn matches(&self, scope: &CalendlyScope) -> Result<(), CalendlySchedulingResultError> {
        if self.project_id != *scope.project_id()
            || self.mission_id != *scope.mission_id()
            || self.work_product_id != *scope.work_product_id()
        {
            return Err(CalendlySchedulingResultError::MissionScopeMismatch);
        }
        if self.project_revision != scope.project_revision() {
            return Err(CalendlySchedulingResultError::StaleProjectRevision);
        }
        if self.mission_revision != scope.mission_revision() {
            return Err(CalendlySchedulingResultError::StaleMissionRevision);
        }
        if self.work_product_revision != scope.work_product_revision() {
            return Err(CalendlySchedulingResultError::StaleWorkProductRevision);
        }
        if self.event_revision != scope.event_revision() {
            return Err(CalendlySchedulingResultError::StaleEventRevision);
        }
        if self.scope_digest != *scope.scope_digest() {
            return Err(CalendlySchedulingResultError::RegistrationScopeMismatch);
        }
        Ok(())
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct PageCursor(String);

impl PageCursor {
    pub fn new(value: impl Into<String>) -> Result<Self, CalendlySchedulingResultError> {
        let value = value.into();
        if valid_identifier(&value, 128) {
            Ok(Self(value))
        } else {
            Err(CalendlySchedulingResultError::InvalidIdentifier)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[allow(clippy::struct_field_names)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageBudget {
    max_pages: u16,
    max_invitees: usize,
    max_webhook_signals: usize,
}

impl PageBudget {
    pub const fn bounded() -> Self {
        Self {
            max_pages: MAX_PAGES,
            max_invitees: MAX_INVITEES,
            max_webhook_signals: MAX_WEBHOOK_SIGNALS,
        }
    }

    pub const fn new(
        max_pages: u16,
        max_invitees: usize,
        max_webhook_signals: usize,
    ) -> Result<Self, CalendlySchedulingResultError> {
        if max_pages == 0
            || max_pages > MAX_PAGES
            || max_invitees == 0
            || max_invitees > MAX_INVITEES
            || max_webhook_signals == 0
            || max_webhook_signals > MAX_WEBHOOK_SIGNALS
        {
            Err(CalendlySchedulingResultError::InvalidScope)
        } else {
            Ok(Self {
                max_pages,
                max_invitees,
                max_webhook_signals,
            })
        }
    }

    pub const fn max_pages(self) -> u16 {
        self.max_pages
    }

    pub const fn max_invitees(self) -> usize {
        self.max_invitees
    }

    pub const fn max_webhook_signals(self) -> usize {
        self.max_webhook_signals
    }
}

/// Replay/timestamp policy for controlled webhook signal recordings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WebhookReplayPolicy {
    max_age_millis: u64,
    max_future_skew_millis: u64,
}

impl WebhookReplayPolicy {
    pub const fn bounded() -> Self {
        Self {
            max_age_millis: MAX_WEBHOOK_AGE_MILLIS,
            max_future_skew_millis: MAX_TIMESTAMP_SKEW_MILLIS,
        }
    }

    pub const fn new(
        max_age_millis: u64,
        max_future_skew_millis: u64,
    ) -> Result<Self, CalendlySchedulingResultError> {
        if max_age_millis == 0 || max_future_skew_millis > MAX_TIMESTAMP_SKEW_MILLIS {
            Err(CalendlySchedulingResultError::InvalidScope)
        } else {
            Ok(Self {
                max_age_millis,
                max_future_skew_millis,
            })
        }
    }

    pub const fn max_age_millis(self) -> u64 {
        self.max_age_millis
    }

    pub const fn max_future_skew_millis(self) -> u64 {
        self.max_future_skew_millis
    }
}

/// Re-exported bounds used by provider and service validation.
pub const fn validate_timestamp_bounds(
    occurred_at_millis: u64,
    received_at_millis: u64,
    now_millis: u64,
    policy: WebhookReplayPolicy,
) -> Result<(), CalendlySchedulingResultError> {
    if occurred_at_millis > now_millis.saturating_add(policy.max_future_skew_millis) {
        return Err(CalendlySchedulingResultError::WebhookFutureTimestamp);
    }
    if received_at_millis < occurred_at_millis {
        return Err(CalendlySchedulingResultError::WebhookReplay);
    }
    if now_millis > occurred_at_millis.saturating_add(policy.max_age_millis)
        || received_at_millis > now_millis.saturating_add(policy.max_future_skew_millis)
    {
        return Err(CalendlySchedulingResultError::WebhookReplay);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderMode {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Fixture,
    ControlledRecording,
    LoopbackRecording,
    BlockedEnvironment,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderLifecycle {
    Active,
    Revoked,
}

/// Provider state has no native/connected/first-party variant by design.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderState {
    mode: ProviderMode,
    provenance: ProviderProvenance,
    lifecycle: ProviderLifecycle,
    provider_revision: u64,
    connected: bool,
    native: bool,
    first_party: bool,
}

impl ProviderState {
    pub fn new(
        mode: ProviderMode,
        provenance: ProviderProvenance,
        provider_revision: u64,
    ) -> Result<Self, CalendlySchedulingResultError> {
        if provider_revision == 0 {
            return Err(CalendlySchedulingResultError::InvalidScope);
        }
        Ok(Self {
            mode,
            provenance,
            lifecycle: ProviderLifecycle::Active,
            provider_revision,
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub const fn mode(self) -> ProviderMode {
        self.mode
    }

    pub const fn provenance(self) -> ProviderProvenance {
        self.provenance
    }

    pub const fn lifecycle(self) -> ProviderLifecycle {
        self.lifecycle
    }

    pub const fn provider_revision(self) -> u64 {
        self.provider_revision
    }

    pub const fn connected(self) -> bool {
        self.connected
    }

    pub const fn native(self) -> bool {
        self.native
    }

    pub const fn first_party(self) -> bool {
        self.first_party
    }

    pub const fn can_claim_native_or_connected(self) -> bool {
        self.connected || self.native || self.first_party
    }

    pub fn revoke(&mut self) {
        self.lifecycle = ProviderLifecycle::Revoked;
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventStatus {
    Active,
    Canceled,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MeetingResultState {
    Scheduled,
    Canceled,
    Rescheduled,
    NoShow,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceCompleteness {
    Complete,
    Partial,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InviteeStatus {
    Active,
    Canceled,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CancellationActor {
    Host,
    Invitee,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocationKind {
    Online,
    Phone,
    InPerson,
    Custom,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookEventKind {
    InviteeCreated,
    InviteeCanceled,
    InviteeNoShowCreated,
    InviteeNoShowDeleted,
    Unknown,
}

impl WebhookEventKind {
    pub fn parse(value: &str) -> Self {
        match value {
            "invitee.created" => Self::InviteeCreated,
            "invitee.canceled" => Self::InviteeCanceled,
            "invitee_no_show.created" => Self::InviteeNoShowCreated,
            "invitee_no_show.deleted" => Self::InviteeNoShowDeleted,
            _ => Self::Unknown,
        }
    }
}

/// Values received from a provider before redaction. This type intentionally
/// does not implement Serialize or Debug; only its digest-only projection is
/// stored in a result or recording.
pub struct TrackingValues {
    utm_source: Option<String>,
    utm_campaign: Option<String>,
    utm_medium: Option<String>,
    utm_content: Option<String>,
    utm_term: Option<String>,
    salesforce_uuid: Option<String>,
}

impl fmt::Debug for TrackingValues {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrackingValues")
            .finish_non_exhaustive()
    }
}

impl TrackingValues {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        utm_source: Option<impl Into<String>>,
        utm_campaign: Option<impl Into<String>>,
        utm_medium: Option<impl Into<String>>,
        utm_content: Option<impl Into<String>>,
        utm_term: Option<impl Into<String>>,
        salesforce_uuid: Option<impl Into<String>>,
    ) -> Self {
        Self {
            utm_source: utm_source.map(Into::into),
            utm_campaign: utm_campaign.map(Into::into),
            utm_medium: utm_medium.map(Into::into),
            utm_content: utm_content.map(Into::into),
            utm_term: utm_term.map(Into::into),
            salesforce_uuid: salesforce_uuid.map(Into::into),
        }
    }

    pub const fn empty() -> Self {
        Self {
            utm_source: None,
            utm_campaign: None,
            utm_medium: None,
            utm_content: None,
            utm_term: None,
            salesforce_uuid: None,
        }
    }
}

/// Digest-only UTM and attribution metadata. Raw tracking values never cross
/// the provider/result boundary.
#[allow(clippy::struct_field_names)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactedTrackingFields {
    utm_source_digest: Option<Digest>,
    utm_campaign_digest: Option<Digest>,
    utm_medium_digest: Option<Digest>,
    utm_content_digest: Option<Digest>,
    utm_term_digest: Option<Digest>,
    salesforce_uuid_digest: Option<Digest>,
}

impl RedactedTrackingFields {
    pub fn from_values(values: &TrackingValues) -> Result<Self, CalendlySchedulingResultError> {
        fn field_digest(
            domain: &str,
            value: Option<&str>,
        ) -> Result<Option<Digest>, CalendlySchedulingResultError> {
            match value.filter(|value| !value.is_empty()) {
                Some(value) => Digest::from_fields(domain, &[value.to_owned()]).map(Some),
                None => Ok(None),
            }
        }
        Ok(Self {
            utm_source_digest: field_digest(
                "calendly.tracking.utm_source",
                values.utm_source.as_deref(),
            )?,
            utm_campaign_digest: field_digest(
                "calendly.tracking.utm_campaign",
                values.utm_campaign.as_deref(),
            )?,
            utm_medium_digest: field_digest(
                "calendly.tracking.utm_medium",
                values.utm_medium.as_deref(),
            )?,
            utm_content_digest: field_digest(
                "calendly.tracking.utm_content",
                values.utm_content.as_deref(),
            )?,
            utm_term_digest: field_digest(
                "calendly.tracking.utm_term",
                values.utm_term.as_deref(),
            )?,
            salesforce_uuid_digest: field_digest(
                "calendly.tracking.salesforce_uuid",
                values.salesforce_uuid.as_deref(),
            )?,
        })
    }

    pub fn utm_source_digest(&self) -> Option<&Digest> {
        self.utm_source_digest.as_ref()
    }

    pub fn utm_campaign_digest(&self) -> Option<&Digest> {
        self.utm_campaign_digest.as_ref()
    }

    pub fn utm_medium_digest(&self) -> Option<&Digest> {
        self.utm_medium_digest.as_ref()
    }

    pub fn utm_content_digest(&self) -> Option<&Digest> {
        self.utm_content_digest.as_ref()
    }

    pub fn utm_term_digest(&self) -> Option<&Digest> {
        self.utm_term_digest.as_ref()
    }

    pub fn salesforce_uuid_digest(&self) -> Option<&Digest> {
        self.salesforce_uuid_digest.as_ref()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OrganizationProjection {
    uri: OrganizationUri,
    metadata_digest: Digest,
}

impl OrganizationProjection {
    pub fn new(
        uri: OrganizationUri,
        metadata_hint: Option<&str>,
    ) -> Result<Self, CalendlySchedulingResultError> {
        let metadata_digest = Digest::from_fields(
            "calendly.organization.metadata/v1",
            &[
                uri.as_str().to_owned(),
                metadata_hint.unwrap_or("").to_owned(),
            ],
        )?;
        Ok(Self {
            uri,
            metadata_digest,
        })
    }

    pub fn uri(&self) -> &OrganizationUri {
        &self.uri
    }

    pub fn metadata_digest(&self) -> &Digest {
        &self.metadata_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UserProjection {
    uri: UserUri,
    metadata_digest: Digest,
}

impl UserProjection {
    pub fn new(
        uri: UserUri,
        metadata_hint: Option<&str>,
    ) -> Result<Self, CalendlySchedulingResultError> {
        let metadata_digest = Digest::from_fields(
            "calendly.user.metadata/v1",
            &[
                uri.as_str().to_owned(),
                metadata_hint.unwrap_or("").to_owned(),
            ],
        )?;
        Ok(Self {
            uri,
            metadata_digest,
        })
    }

    pub fn uri(&self) -> &UserUri {
        &self.uri
    }

    pub fn metadata_digest(&self) -> &Digest {
        &self.metadata_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventTypeProjection {
    uri: EventTypeUri,
    duration_minutes: Option<u16>,
    metadata_digest: Digest,
}

impl EventTypeProjection {
    pub fn new(
        uri: EventTypeUri,
        duration_minutes: Option<u16>,
        metadata_hint: Option<&str>,
    ) -> Result<Self, CalendlySchedulingResultError> {
        if duration_minutes.is_some_and(|duration| duration == 0 || duration > 1_440) {
            return Err(CalendlySchedulingResultError::MalformedProviderData);
        }
        let metadata_digest = Digest::from_fields(
            "calendly.event-type.metadata/v1",
            &[
                uri.as_str().to_owned(),
                duration_minutes.map_or_else(String::new, |duration| duration.to_string()),
                metadata_hint.unwrap_or("").to_owned(),
            ],
        )?;
        Ok(Self {
            uri,
            duration_minutes,
            metadata_digest,
        })
    }

    pub fn uri(&self) -> &EventTypeUri {
        &self.uri
    }

    pub const fn duration_minutes(&self) -> Option<u16> {
        self.duration_minutes
    }

    pub fn metadata_digest(&self) -> &Digest {
        &self.metadata_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RescheduleEvidence {
    rescheduled: bool,
    old_invitee_uri: Option<InviteeUri>,
    new_invitee_uri: Option<InviteeUri>,
}

impl RescheduleEvidence {
    pub fn new(
        rescheduled: bool,
        old_invitee_uri: Option<InviteeUri>,
        new_invitee_uri: Option<InviteeUri>,
    ) -> Result<Self, CalendlySchedulingResultError> {
        if !rescheduled && (old_invitee_uri.is_some() || new_invitee_uri.is_some()) {
            return Err(CalendlySchedulingResultError::MalformedProviderData);
        }
        Ok(Self {
            rescheduled,
            old_invitee_uri,
            new_invitee_uri,
        })
    }

    pub const fn rescheduled(&self) -> bool {
        self.rescheduled
    }

    pub fn old_invitee_uri(&self) -> Option<&InviteeUri> {
        self.old_invitee_uri.as_ref()
    }

    pub fn new_invitee_uri(&self) -> Option<&InviteeUri> {
        self.new_invitee_uri.as_ref()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NoShowEvidence {
    no_show: bool,
    no_show_uri: Option<NoShowUri>,
    recorded_at_millis: Option<u64>,
}

impl NoShowEvidence {
    pub fn new(
        no_show: bool,
        no_show_uri: Option<NoShowUri>,
        recorded_at_millis: Option<u64>,
    ) -> Result<Self, CalendlySchedulingResultError> {
        if !no_show && (no_show_uri.is_some() || recorded_at_millis.is_some()) {
            return Err(CalendlySchedulingResultError::MalformedProviderData);
        }
        Ok(Self {
            no_show,
            no_show_uri,
            recorded_at_millis,
        })
    }

    pub const fn no_show(&self) -> bool {
        self.no_show
    }

    pub fn no_show_uri(&self) -> Option<&NoShowUri> {
        self.no_show_uri.as_ref()
    }

    pub const fn recorded_at_millis(&self) -> Option<u64> {
        self.recorded_at_millis
    }
}

/// Scheduled event metadata with no invitee PII, booking links, calendar
/// identifiers, or location URLs.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScheduledEventProjection {
    uri: ScheduledEventUri,
    event_type_uri: EventTypeUri,
    status: EventStatus,
    result_state: MeetingResultState,
    start_at_millis: u64,
    end_at_millis: u64,
    timezone: String,
    location_kind: LocationKind,
    cancellation_actor: CancellationActor,
    cancellation_reason_digest: Option<Digest>,
    reschedule: RescheduleEvidence,
    no_show: NoShowEvidence,
    tracking: RedactedTrackingFields,
    event_revision: Revision,
    provider_updated_at_millis: u64,
    event_digest: Digest,
}

impl ScheduledEventProjection {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        uri: ScheduledEventUri,
        event_type_uri: EventTypeUri,
        status: EventStatus,
        start_at_millis: u64,
        end_at_millis: u64,
        timezone: impl Into<String>,
        location_kind: LocationKind,
        cancellation_actor: CancellationActor,
        cancellation_reason: Option<&str>,
        reschedule: RescheduleEvidence,
        no_show: NoShowEvidence,
        tracking: RedactedTrackingFields,
        event_revision: u64,
        provider_updated_at_millis: u64,
    ) -> Result<Self, CalendlySchedulingResultError> {
        if start_at_millis >= end_at_millis
            || event_revision == 0
            || provider_updated_at_millis == 0
        {
            return Err(CalendlySchedulingResultError::MalformedProviderData);
        }
        let timezone = timezone.into();
        if timezone.is_empty()
            || timezone.len() > 128
            || timezone.trim() != timezone
            || timezone.chars().any(char::is_control)
        {
            return Err(CalendlySchedulingResultError::MalformedProviderData);
        }
        let cancellation_reason_digest = cancellation_reason
            .filter(|reason| !reason.is_empty())
            .map(|reason| {
                Digest::from_fields("calendly.cancellation.reason/v1", &[reason.to_owned()])
            })
            .transpose()?;
        let result_state = if no_show.no_show() {
            MeetingResultState::NoShow
        } else if reschedule.rescheduled() {
            MeetingResultState::Rescheduled
        } else {
            match status {
                EventStatus::Active => MeetingResultState::Scheduled,
                EventStatus::Canceled => MeetingResultState::Canceled,
                EventStatus::Unknown => MeetingResultState::Unknown,
            }
        };
        #[derive(Serialize)]
        struct EventBody<'a> {
            uri: &'a ScheduledEventUri,
            event_type_uri: &'a EventTypeUri,
            status: EventStatus,
            result_state: MeetingResultState,
            start_at_millis: u64,
            end_at_millis: u64,
            timezone: &'a str,
            location_kind: LocationKind,
            cancellation_actor: CancellationActor,
            cancellation_reason_digest: &'a Option<Digest>,
            reschedule: &'a RescheduleEvidence,
            no_show: &'a NoShowEvidence,
            tracking: &'a RedactedTrackingFields,
            event_revision: Revision,
            provider_updated_at_millis: u64,
        }
        let event_digest = digest_serialized_with_domain(
            "hartevo.calendly-scheduled-event/v1",
            &EventBody {
                uri: &uri,
                event_type_uri: &event_type_uri,
                status,
                result_state,
                start_at_millis,
                end_at_millis,
                timezone: &timezone,
                location_kind,
                cancellation_actor,
                cancellation_reason_digest: &cancellation_reason_digest,
                reschedule: &reschedule,
                no_show: &no_show,
                tracking: &tracking,
                event_revision: Revision::new(event_revision)?,
                provider_updated_at_millis,
            },
        )?;
        Ok(Self {
            uri,
            event_type_uri,
            status,
            result_state,
            start_at_millis,
            end_at_millis,
            timezone,
            location_kind,
            cancellation_actor,
            cancellation_reason_digest,
            reschedule,
            no_show,
            tracking,
            event_revision: Revision::new(event_revision)?,
            provider_updated_at_millis,
            event_digest,
        })
    }

    pub fn uri(&self) -> &ScheduledEventUri {
        &self.uri
    }

    pub fn event_type_uri(&self) -> &EventTypeUri {
        &self.event_type_uri
    }

    pub const fn status(&self) -> EventStatus {
        self.status
    }

    pub const fn result_state(&self) -> MeetingResultState {
        self.result_state
    }

    pub const fn start_at_millis(&self) -> u64 {
        self.start_at_millis
    }

    pub const fn end_at_millis(&self) -> u64 {
        self.end_at_millis
    }

    pub fn timezone(&self) -> &str {
        &self.timezone
    }

    pub const fn location_kind(&self) -> LocationKind {
        self.location_kind
    }

    pub const fn cancellation_actor(&self) -> CancellationActor {
        self.cancellation_actor
    }

    pub fn cancellation_reason_digest(&self) -> Option<&Digest> {
        self.cancellation_reason_digest.as_ref()
    }

    pub fn reschedule(&self) -> &RescheduleEvidence {
        &self.reschedule
    }

    pub fn no_show(&self) -> &NoShowEvidence {
        &self.no_show
    }

    pub fn tracking(&self) -> &RedactedTrackingFields {
        &self.tracking
    }

    pub const fn event_revision(&self) -> Revision {
        self.event_revision
    }

    pub const fn provider_updated_at_millis(&self) -> u64 {
        self.provider_updated_at_millis
    }

    pub fn event_digest(&self) -> &Digest {
        &self.event_digest
    }
}

/// One invitee status projection. It contains no name, email, questions,
/// timezone, cancel URL, reschedule URL, or arbitrary payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InviteeStatusProjection {
    uri: InviteeUri,
    status: InviteeStatus,
    no_show: bool,
    updated_at_millis: u64,
    invitee_digest: Digest,
}

impl InviteeStatusProjection {
    pub fn new(
        uri: InviteeUri,
        status: InviteeStatus,
        no_show: bool,
        updated_at_millis: u64,
    ) -> Result<Self, CalendlySchedulingResultError> {
        if updated_at_millis == 0 {
            return Err(CalendlySchedulingResultError::MalformedProviderData);
        }
        #[derive(Serialize)]
        struct InviteeBody<'a> {
            uri: &'a InviteeUri,
            status: InviteeStatus,
            no_show: bool,
            updated_at_millis: u64,
        }
        let invitee_digest = digest_serialized_with_domain(
            "hartevo.calendly-invitee-status/v1",
            &InviteeBody {
                uri: &uri,
                status,
                no_show,
                updated_at_millis,
            },
        )?;
        Ok(Self {
            uri,
            status,
            no_show,
            updated_at_millis,
            invitee_digest,
        })
    }

    pub fn uri(&self) -> &InviteeUri {
        &self.uri
    }

    pub const fn status(&self) -> InviteeStatus {
        self.status
    }

    pub const fn no_show(&self) -> bool {
        self.no_show
    }

    pub const fn updated_at_millis(&self) -> u64 {
        self.updated_at_millis
    }

    pub fn invitee_digest(&self) -> &Digest {
        &self.invitee_digest
    }
}

/// Redacted webhook change evidence. Payload and signature material are
/// reduced to digests before the signal can be serialized.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WebhookChangeSignal {
    delivery_id: DeliveryId,
    event_kind: WebhookEventKind,
    event_uri: ScheduledEventUri,
    invitee_uri: Option<InviteeUri>,
    status: InviteeStatus,
    rescheduled: bool,
    occurred_at_millis: u64,
    received_at_millis: u64,
    payload_digest: Digest,
    signature_digest: Option<Digest>,
}

impl WebhookChangeSignal {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        delivery_id: impl Into<String>,
        event_kind: &str,
        event_uri: ScheduledEventUri,
        invitee_uri: Option<InviteeUri>,
        status: InviteeStatus,
        rescheduled: bool,
        occurred_at_millis: u64,
        received_at_millis: u64,
        raw_payload: &[u8],
        raw_signature: Option<&[u8]>,
    ) -> Result<Self, CalendlySchedulingResultError> {
        let delivery_id = DeliveryId::new(delivery_id)?;
        if occurred_at_millis == 0 || received_at_millis == 0 || raw_payload.is_empty() {
            return Err(CalendlySchedulingResultError::MalformedProviderData);
        }
        let payload_digest =
            Digest::from_fields("calendly.webhook.payload/v1", &[sha256_hex(raw_payload)])?;
        let signature_digest = raw_signature
            .filter(|signature| !signature.is_empty())
            .map(|signature| {
                Digest::from_fields("calendly.webhook.signature/v1", &[sha256_hex(signature)])
            })
            .transpose()?;
        Ok(Self {
            delivery_id,
            event_kind: WebhookEventKind::parse(event_kind),
            event_uri,
            invitee_uri,
            status,
            rescheduled,
            occurred_at_millis,
            received_at_millis,
            payload_digest,
            signature_digest,
        })
    }

    pub fn from_digests(
        delivery_id: impl Into<String>,
        event_kind: WebhookEventKind,
        event_uri: ScheduledEventUri,
        invitee_uri: Option<InviteeUri>,
        status: InviteeStatus,
        rescheduled: bool,
        occurred_at_millis: u64,
        received_at_millis: u64,
        payload_digest: Digest,
        signature_digest: Option<Digest>,
    ) -> Result<Self, CalendlySchedulingResultError> {
        if occurred_at_millis == 0 || received_at_millis == 0 {
            return Err(CalendlySchedulingResultError::MalformedProviderData);
        }
        Ok(Self {
            delivery_id: DeliveryId::new(delivery_id)?,
            event_kind,
            event_uri,
            invitee_uri,
            status,
            rescheduled,
            occurred_at_millis,
            received_at_millis,
            payload_digest,
            signature_digest,
        })
    }

    pub fn validate_at(
        &self,
        now_millis: u64,
        policy: WebhookReplayPolicy,
    ) -> Result<(), CalendlySchedulingResultError> {
        validate_timestamp_bounds(
            self.occurred_at_millis,
            self.received_at_millis,
            now_millis,
            policy,
        )
    }

    pub fn delivery_id(&self) -> &DeliveryId {
        &self.delivery_id
    }

    pub const fn event_kind(&self) -> WebhookEventKind {
        self.event_kind
    }

    pub fn event_uri(&self) -> &ScheduledEventUri {
        &self.event_uri
    }

    pub fn invitee_uri(&self) -> Option<&InviteeUri> {
        self.invitee_uri.as_ref()
    }

    pub const fn status(&self) -> InviteeStatus {
        self.status
    }

    pub const fn rescheduled(&self) -> bool {
        self.rescheduled
    }

    pub const fn occurred_at_millis(&self) -> u64 {
        self.occurred_at_millis
    }

    pub const fn received_at_millis(&self) -> u64 {
        self.received_at_millis
    }

    pub fn payload_digest(&self) -> &Digest {
        &self.payload_digest
    }

    pub fn signature_digest(&self) -> Option<&Digest> {
        self.signature_digest.as_ref()
    }
}

/// One bounded page from a controlled provider. It has no raw JSON body.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CalendlyPage {
    organization: OrganizationProjection,
    user: UserProjection,
    event_type: EventTypeProjection,
    scheduled_event: ScheduledEventProjection,
    invitees: Vec<InviteeStatusProjection>,
    webhook_signals: Vec<WebhookChangeSignal>,
    next_cursor: Option<PageCursor>,
    provider_revision: u64,
    permission_digest: Digest,
    response_size_bytes: usize,
    response_digest: Digest,
}

impl CalendlyPage {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        organization: OrganizationProjection,
        user: UserProjection,
        event_type: EventTypeProjection,
        scheduled_event: ScheduledEventProjection,
        invitees: Vec<InviteeStatusProjection>,
        webhook_signals: Vec<WebhookChangeSignal>,
        next_cursor: Option<PageCursor>,
        provider_revision: u64,
        permission_digest: Digest,
        response_size_bytes: usize,
    ) -> Result<Self, CalendlySchedulingResultError> {
        if provider_revision == 0
            || response_size_bytes > crate::MAX_RESPONSE_BYTES
            || invitees.len() > MAX_INVITEES
            || webhook_signals.len() > MAX_WEBHOOK_SIGNALS
        {
            return Err(CalendlySchedulingResultError::MalformedProviderData);
        }
        let mut invitee_ids = HashSet::new();
        for invitee in &invitees {
            if !invitee_ids.insert(invitee.uri().clone()) {
                return Err(CalendlySchedulingResultError::MalformedProviderData);
            }
        }
        let mut delivery_ids = HashSet::new();
        for signal in &webhook_signals {
            if !delivery_ids.insert(signal.delivery_id().clone()) {
                return Err(CalendlySchedulingResultError::DuplicateWebhookDelivery);
            }
        }
        #[derive(Serialize)]
        struct PageBody<'a> {
            organization: &'a OrganizationProjection,
            user: &'a UserProjection,
            event_type: &'a EventTypeProjection,
            scheduled_event: &'a ScheduledEventProjection,
            invitees: &'a [InviteeStatusProjection],
            webhook_signals: &'a [WebhookChangeSignal],
            next_cursor: &'a Option<PageCursor>,
            provider_revision: u64,
            permission_digest: &'a Digest,
            response_size_bytes: usize,
        }
        let response_digest = digest_serialized_with_domain(
            "hartevo.calendly-provider-page/v1",
            &PageBody {
                organization: &organization,
                user: &user,
                event_type: &event_type,
                scheduled_event: &scheduled_event,
                invitees: &invitees,
                webhook_signals: &webhook_signals,
                next_cursor: &next_cursor,
                provider_revision,
                permission_digest: &permission_digest,
                response_size_bytes,
            },
        )?;
        Ok(Self {
            organization,
            user,
            event_type,
            scheduled_event,
            invitees,
            webhook_signals,
            next_cursor,
            provider_revision,
            permission_digest,
            response_size_bytes,
            response_digest,
        })
    }

    pub fn organization(&self) -> &OrganizationProjection {
        &self.organization
    }

    pub fn user(&self) -> &UserProjection {
        &self.user
    }

    pub fn event_type(&self) -> &EventTypeProjection {
        &self.event_type
    }

    pub fn scheduled_event(&self) -> &ScheduledEventProjection {
        &self.scheduled_event
    }

    pub fn invitees(&self) -> &[InviteeStatusProjection] {
        &self.invitees
    }

    pub fn webhook_signals(&self) -> &[WebhookChangeSignal] {
        &self.webhook_signals
    }

    pub fn next_cursor(&self) -> Option<&PageCursor> {
        self.next_cursor.as_ref()
    }

    pub const fn provider_revision(&self) -> u64 {
        self.provider_revision
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub const fn response_size_bytes(&self) -> usize {
        self.response_size_bytes
    }

    pub fn response_digest(&self) -> &Digest {
        &self.response_digest
    }
}

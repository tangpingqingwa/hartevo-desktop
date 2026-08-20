use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_INDEX_ALLOWLIST: usize = 16;
pub const MAX_TIME_WINDOW_DAYS: i64 = 31;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_PAGES: u16 = 4;
pub const MAX_CELLS_PER_PAGE: usize = 64;
pub const MAX_AGGREGATE_CELLS: usize = 256;
pub const MAX_FIELDS: usize = 32;
pub const MAX_FIELD_NAME_BYTES: usize = 64;
pub const MAX_CELL_BYTES: usize = 256;
pub const MAX_DIAGNOSTIC_BYTES: usize = 512;
pub const MAX_DURATION_MILLISECONDS: u64 = 86_400_000;

pub type Digest = String;

#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    hex::encode(Sha256::digest(bytes))
}

#[must_use]
pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("Splunk typed value serializes");
    sha256_digest(&bytes)
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{label} is empty, malformed, or too long")]
    InvalidIdentifier { label: &'static str },
    #[error("HTTPS host is invalid")]
    InvalidHttpsHost,
    #[error("{label} revision must be non-zero")]
    InvalidRevision { label: &'static str },
    #[error("time window is invalid or exceeds the Layer-1 bound")]
    InvalidTimeWindow,
    #[error("index allowlist is empty, duplicated, or exceeds the Layer-1 bound")]
    InvalidIndexAllowlist,
    #[error("consent scope is invalid")]
    InvalidConsent,
    #[error("digest is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("scope is invalid: {0}")]
    InvalidScope(&'static str),
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("registration is not revoked")]
    NotRevoked,
    #[error("registration revision overflowed")]
    RevisionOverflow,
    #[error("field schema is invalid")]
    InvalidFieldSchema,
    #[error("aggregate cell is invalid or outside its field schema")]
    InvalidAggregateCell,
    #[error("aggregate result exceeds the Layer-1 bound")]
    ResultBoundExceeded,
    #[error("provider status is invalid")]
    InvalidProviderStatus,
    #[error("provider page is invalid or repeated")]
    InvalidProviderPage,
}

fn validate_identifier(value: &str, label: &'static str) -> Result<(), ModelError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        return Err(ModelError::InvalidIdentifier { label });
    }
    Ok(())
}

fn validate_revision(revision: u64, label: &'static str) -> Result<(), ModelError> {
    if revision == 0 {
        Err(ModelError::InvalidRevision { label })
    } else {
        Ok(())
    }
}

fn validate_digest(value: &str) -> Result<(), ModelError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(ModelError::InvalidDigest)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Identifier(String);

impl Identifier {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_identifier(&value, "identifier")?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

pub type SplunkTenant = Identifier;
pub type SplunkApp = Identifier;
pub type SplunkOwner = Identifier;
pub type SplunkSavedSearch = Identifier;
pub type SplunkSearchSid = Identifier;
pub type SplunkIndexName = Identifier;
pub type ProjectId = Identifier;
pub type MissionId = Identifier;
pub type WorkProductId = Identifier;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        validate_revision(value, "revision")?;
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

pub type SearchRevision = Revision;
pub type ProjectRevision = Revision;
pub type MissionRevision = Revision;
pub type WorkProductRevision = Revision;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityBinding {
    id: Identifier,
    revision: Revision,
}

impl IdentityBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            id: Identifier::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn id(&self) -> &str {
        self.id.as_str()
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

pub type ProjectBinding = IdentityBinding;
pub type MissionBinding = IdentityBinding;
pub type WorkProductBinding = IdentityBinding;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct SplunkHost(String);

impl SplunkHost {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        let authority = value
            .strip_prefix("https://")
            .filter(|authority| !authority.is_empty())
            .ok_or(ModelError::InvalidHttpsHost)?;
        if value.len() > 256
            || authority.contains('/')
            || authority.contains('?')
            || authority.contains('#')
            || authority.chars().any(char::is_whitespace)
            || authority.chars().any(char::is_control)
            || !authority
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b".-:".contains(&byte))
        {
            return Err(ModelError::InvalidHttpsHost);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SplunkIndexAllowlist {
    indices: BTreeSet<SplunkIndexName>,
}

impl SplunkIndexAllowlist {
    pub fn new<I, S>(values: I) -> Result<Self, ModelError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut indices = BTreeSet::new();
        for value in values {
            indices.insert(Identifier::new(value.into())?);
        }
        let allowlist = Self { indices };
        allowlist.validate()?;
        Ok(allowlist)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.indices.is_empty() || self.indices.len() > MAX_INDEX_ALLOWLIST {
            return Err(ModelError::InvalidIndexAllowlist);
        }
        Ok(())
    }

    #[must_use]
    pub fn indices(&self) -> &BTreeSet<SplunkIndexName> {
        &self.indices
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SplunkSearchResultTimeWindow {
    start: String,
    end: String,
    revision: Revision,
}

impl SplunkSearchResultTimeWindow {
    pub fn new(
        start: impl Into<String>,
        end: impl Into<String>,
        revision: u64,
    ) -> Result<Self, ModelError> {
        let start = start.into();
        let end = end.into();
        let start_parts = parse_timestamp(&start).ok_or(ModelError::InvalidTimeWindow)?;
        let end_parts = parse_timestamp(&end).ok_or(ModelError::InvalidTimeWindow)?;
        validate_revision(revision, "time window")?;
        let start_seconds = timestamp_seconds(start_parts);
        let end_seconds = timestamp_seconds(end_parts);
        let duration = end_seconds
            .checked_sub(start_seconds)
            .ok_or(ModelError::InvalidTimeWindow)?;
        if duration <= 0 || duration > MAX_TIME_WINDOW_DAYS * 86_400 {
            return Err(ModelError::InvalidTimeWindow);
        }
        Ok(Self {
            start,
            end,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn start(&self) -> &str {
        &self.start
    }

    #[must_use]
    pub fn end(&self) -> &str {
        &self.end
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        Self::new(self.start.clone(), self.end.clone(), self.revision.get()).map(|_| ())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SplunkProviderResourceScope {
    host: SplunkHost,
    tenant: SplunkTenant,
    app: SplunkApp,
    owner: SplunkOwner,
    saved_search: SplunkSavedSearch,
    sid: SplunkSearchSid,
    index_allowlist: SplunkIndexAllowlist,
    search_revision: SearchRevision,
    time_window: SplunkSearchResultTimeWindow,
}

#[allow(clippy::too_many_arguments)]
impl SplunkProviderResourceScope {
    pub fn new(
        host: SplunkHost,
        tenant: impl Into<String>,
        app: impl Into<String>,
        owner: impl Into<String>,
        saved_search: impl Into<String>,
        sid: impl Into<String>,
        index_allowlist: SplunkIndexAllowlist,
        search_revision: Revision,
        time_window: SplunkSearchResultTimeWindow,
    ) -> Result<Self, ModelError> {
        let resource = Self {
            host,
            tenant: Identifier::new(tenant.into())?,
            app: Identifier::new(app.into())?,
            owner: Identifier::new(owner.into())?,
            saved_search: Identifier::new(saved_search.into())?,
            sid: Identifier::new(sid.into())?,
            index_allowlist,
            search_revision,
            time_window,
        };
        resource.validate()?;
        Ok(resource)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.index_allowlist.validate()?;
        validate_revision(self.search_revision.get(), "search")?;
        self.time_window.validate()
    }

    #[must_use]
    pub fn host(&self) -> &SplunkHost {
        &self.host
    }

    #[must_use]
    pub fn tenant(&self) -> &SplunkTenant {
        &self.tenant
    }

    #[must_use]
    pub fn app(&self) -> &SplunkApp {
        &self.app
    }

    #[must_use]
    pub fn owner(&self) -> &SplunkOwner {
        &self.owner
    }

    #[must_use]
    pub fn saved_search(&self) -> &SplunkSavedSearch {
        &self.saved_search
    }

    #[must_use]
    pub fn sid(&self) -> &SplunkSearchSid {
        &self.sid
    }

    #[must_use]
    pub fn index_allowlist(&self) -> &SplunkIndexAllowlist {
        &self.index_allowlist
    }

    #[must_use]
    pub const fn search_revision(&self) -> SearchRevision {
        self.search_revision
    }

    #[must_use]
    pub fn time_window(&self) -> &SplunkSearchResultTimeWindow {
        &self.time_window
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    #[must_use]
    pub fn search_digest(&self) -> Digest {
        canonical_digest(&(
            "splunk-search/v1",
            &self.saved_search,
            self.search_revision,
            &self.time_window,
        ))
    }

    #[must_use]
    pub fn sid_digest(&self) -> Digest {
        canonical_digest(&("splunk-sid/v1", &self.sid))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentScope {
    consent_digest: Digest,
    revision: Revision,
}

impl ConsentScope {
    pub fn new(reference: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        let reference = reference.into();
        if reference.is_empty()
            || reference.len() > MAX_IDENTIFIER_BYTES
            || reference.trim() != reference
            || reference.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidConsent);
        }
        Ok(Self {
            consent_digest: sha256_digest(format!("splunk-consent/v1|{reference}").as_bytes()),
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.consent_digest
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        validate_digest(&self.consent_digest)?;
        validate_revision(self.revision.get(), "consent")
    }
}

/// An opaque handle to a token or OAuth lease. The handle deliberately has no
/// serde implementation and cannot be serialized into a request, receipt, or
/// proposal. Only its versioned digest participates in registration binding.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    opaque_id: String,
    revision: Revision,
    revoked: bool,
}

impl SecretReference {
    pub fn new(opaque_id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        let opaque_id = opaque_id.into();
        if opaque_id.is_empty()
            || opaque_id.len() > MAX_IDENTIFIER_BYTES
            || opaque_id.trim() != opaque_id
            || opaque_id.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidIdentifier {
                label: "secret reference",
            });
        }
        Ok(Self {
            opaque_id,
            revision: Revision::new(revision)?,
            revoked: false,
        })
    }

    pub fn token(opaque_id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Self::new(opaque_id, revision)
    }

    pub fn oauth(opaque_id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Self::new(opaque_id, revision)
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        sha256_digest(
            format!(
                "splunk-secret-reference/v1|{}|{}",
                self.opaque_id,
                self.revision.get()
            )
            .as_bytes(),
        )
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
            .field("opaque_id", &"<redacted>")
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SplunkSavedSearchResultScopeSpec {
    pub resource: SplunkProviderResourceScope,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub consent: ConsentScope,
}

impl SplunkSavedSearchResultScopeSpec {
    pub fn new(
        resource: SplunkProviderResourceScope,
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        consent: ConsentScope,
    ) -> Self {
        Self {
            resource,
            project,
            mission,
            work_product,
            consent,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SplunkSavedSearchResultScope {
    resource: SplunkProviderResourceScope,
    project: ProjectBinding,
    mission: MissionBinding,
    work_product: WorkProductBinding,
    consent: ConsentScope,
    scope_digest: Digest,
    revision_digest: Digest,
    privacy_digest: Digest,
}

impl SplunkSavedSearchResultScope {
    pub fn new(spec: SplunkSavedSearchResultScopeSpec) -> Result<Self, ModelError> {
        spec.resource.validate()?;
        spec.consent.validate()?;
        let scope_digest = scope_digest(&spec);
        let revision_digest = revision_digest(&spec);
        let privacy_digest = privacy_digest();
        Ok(Self {
            resource: spec.resource,
            project: spec.project,
            mission: spec.mission,
            work_product: spec.work_product,
            consent: spec.consent,
            scope_digest,
            revision_digest,
            privacy_digest,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let spec = self.spec();
        if scope_digest(&spec) != self.scope_digest {
            return Err(ModelError::InvalidScope("scope digest"));
        }
        if revision_digest(&spec) != self.revision_digest {
            return Err(ModelError::InvalidScope("revision digest"));
        }
        if privacy_digest() != self.privacy_digest {
            return Err(ModelError::InvalidScope("privacy digest"));
        }
        Ok(())
    }

    #[must_use]
    pub fn spec(&self) -> SplunkSavedSearchResultScopeSpec {
        SplunkSavedSearchResultScopeSpec::new(
            self.resource.clone(),
            self.project.clone(),
            self.mission.clone(),
            self.work_product.clone(),
            self.consent.clone(),
        )
    }

    #[must_use]
    pub fn resource(&self) -> &SplunkProviderResourceScope {
        &self.resource
    }

    #[must_use]
    pub fn provider_resource_scope(&self) -> &SplunkProviderResourceScope {
        self.resource()
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
    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.scope_digest.clone()
    }

    #[must_use]
    pub fn resource_digest(&self) -> Digest {
        self.resource.digest()
    }

    #[must_use]
    pub fn revision_digest(&self) -> &Digest {
        &self.revision_digest
    }

    #[must_use]
    pub fn privacy_digest(&self) -> &Digest {
        &self.privacy_digest
    }

    #[must_use]
    pub fn consent_digest(&self) -> &Digest {
        self.consent.digest()
    }

    #[must_use]
    pub fn search_digest(&self) -> Digest {
        self.resource.search_digest()
    }

    #[must_use]
    pub fn sid_digest(&self) -> Digest {
        self.resource.sid_digest()
    }
}

fn scope_digest(spec: &SplunkSavedSearchResultScopeSpec) -> Digest {
    canonical_digest(&(
        "splunk-search-result-scope/v1",
        &spec.resource,
        &spec.project,
        &spec.mission,
        &spec.work_product,
        &spec.consent,
    ))
}

fn revision_digest(spec: &SplunkSavedSearchResultScopeSpec) -> Digest {
    canonical_digest(&(
        "splunk-search-result-revisions/v1",
        spec.resource.search_revision,
        spec.resource.time_window.revision(),
        spec.project.revision(),
        spec.mission.revision(),
        spec.work_product.revision(),
        spec.consent.revision(),
    ))
}

fn privacy_digest() -> Digest {
    canonical_digest(&(
        "splunk-search-result-privacy/v1",
        "raw_events_dropped",
        "_raw_dropped",
        "source_values_dropped",
        "host_values_dropped",
        "string_cells_digest_only",
        "credentials_dropped",
        "spl_dropped",
    ))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SplunkRegistration {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_digest: Digest,
    pub resource_scope_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub privacy_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: Revision,
    pub registration_digest: Digest,
    pub state: RegistrationState,
    pub reversible: bool,
    pub revocable: bool,
}

impl SplunkRegistration {
    #[must_use]
    pub fn bind(
        scope: &SplunkSavedSearchResultScope,
        secret_reference: &SecretReference,
        provider_digest: Digest,
    ) -> Self {
        let mut registration = Self {
            plugin_version: crate::SPLUNK_SEARCH_RESULT_PLUGIN_VERSION.to_owned(),
            contract_version: crate::SPLUNK_SEARCH_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            provider_id: crate::SPLUNK_PROVIDER_ID.to_owned(),
            provider_digest,
            resource_scope_digest: scope.resource_digest(),
            scope_digest: scope.digest(),
            revision_digest: scope.revision_digest().clone(),
            privacy_digest: scope.privacy_digest().clone(),
            secret_reference_digest: secret_reference.digest(),
            registration_revision: Revision::new(1).expect("registration revision"),
            registration_digest: String::new(),
            state: RegistrationState::Active,
            reversible: true,
            revocable: true,
        };
        registration.registration_digest = registration.compute_digest();
        registration
    }

    fn compute_digest(&self) -> Digest {
        canonical_digest(&(
            "splunk-registration/v1",
            &self.plugin_version,
            &self.contract_version,
            &self.contract_digest,
            &self.provider_id,
            &self.provider_digest,
            &self.resource_scope_digest,
            &self.scope_digest,
            &self.revision_digest,
            &self.privacy_digest,
            &self.secret_reference_digest,
            self.registration_revision,
            &self.state,
            self.reversible,
            self.revocable,
        ))
    }

    pub fn validate(
        &self,
        scope: &SplunkSavedSearchResultScope,
        secret_reference: &SecretReference,
        provider_digest: &Digest,
    ) -> Result<(), ModelError> {
        scope.validate()?;
        if self.state != RegistrationState::Active {
            return Err(ModelError::InvalidScope("registration revoked"));
        }
        if self.plugin_version != crate::SPLUNK_SEARCH_RESULT_PLUGIN_VERSION
            || self.contract_version != crate::SPLUNK_SEARCH_RESULT_CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.provider_id != crate::SPLUNK_PROVIDER_ID
            || &self.provider_digest != provider_digest
            || self.resource_scope_digest != scope.resource_digest()
            || self.scope_digest != scope.digest()
            || self.revision_digest != *scope.revision_digest()
            || self.privacy_digest != *scope.privacy_digest()
            || self.secret_reference_digest != secret_reference.digest()
            || !self.reversible
            || !self.revocable
            || self.registration_digest != self.compute_digest()
        {
            return Err(ModelError::InvalidScope("registration digest"));
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationChange, ModelError> {
        if !self.revocable {
            return Err(ModelError::InvalidScope("registration is not revocable"));
        }
        if self.state == RegistrationState::Revoked {
            return Err(ModelError::AlreadyRevoked);
        }
        let previous_digest = self.registration_digest.clone();
        self.registration_revision = Revision::new(
            self.registration_revision
                .get()
                .checked_add(1)
                .ok_or(ModelError::RevisionOverflow)?,
        )?;
        self.state = RegistrationState::Revoked;
        self.registration_digest = self.compute_digest();
        Ok(RegistrationChange {
            previous_registration_digest: previous_digest,
            registration_digest: self.registration_digest.clone(),
            registration_revision: self.registration_revision,
            state: self.state.clone(),
            reversible: self.reversible,
            revocable: self.revocable,
            native: false,
            connected: false,
            first_party: false,
        })
    }

    pub fn restore(&mut self) -> Result<RegistrationChange, ModelError> {
        if !self.reversible {
            return Err(ModelError::InvalidScope("registration is not reversible"));
        }
        if self.state != RegistrationState::Revoked {
            return Err(ModelError::NotRevoked);
        }
        let previous_digest = self.registration_digest.clone();
        self.registration_revision = Revision::new(
            self.registration_revision
                .get()
                .checked_add(1)
                .ok_or(ModelError::RevisionOverflow)?,
        )?;
        self.state = RegistrationState::Active;
        self.registration_digest = self.compute_digest();
        Ok(RegistrationChange {
            previous_registration_digest: previous_digest,
            registration_digest: self.registration_digest.clone(),
            registration_revision: self.registration_revision,
            state: self.state.clone(),
            reversible: self.reversible,
            revocable: self.revocable,
            native: false,
            connected: false,
            first_party: false,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationChange {
    pub previous_registration_digest: Digest,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub state: RegistrationState,
    pub reversible: bool,
    pub revocable: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
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

    #[must_use]
    pub const fn is_first_party(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum SplunkEvidenceStatus {
    Queued,
    Running,
    Done,
    Failed,
    Expired,
    Partial,
    Empty,
    AccessLost,
    ProviderUnknown,
    Tampered,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClassification {
    Normalized,
    Partial,
    Empty,
    AccessLost,
    BlockedEnv,
    ProviderUnknown,
    Tampered,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SplunkJobPhase {
    Queued,
    Running,
    Done,
    Failed,
    Expired,
    Partial,
    Empty,
}

impl SplunkJobPhase {
    pub fn parse(value: &str) -> Result<Self, ModelError> {
        match value.to_ascii_uppercase().as_str() {
            "QUEUED" => Ok(Self::Queued),
            "RUNNING" => Ok(Self::Running),
            "DONE" | "COMPLETED" => Ok(Self::Done),
            "FAILED" | "ERROR" => Ok(Self::Failed),
            "EXPIRED" => Ok(Self::Expired),
            "PARTIAL" => Ok(Self::Partial),
            "EMPTY" => Ok(Self::Empty),
            _ => Err(ModelError::InvalidProviderStatus),
        }
    }

    #[must_use]
    pub const fn evidence_status(self) -> SplunkEvidenceStatus {
        match self {
            Self::Queued => SplunkEvidenceStatus::Queued,
            Self::Running => SplunkEvidenceStatus::Running,
            Self::Done => SplunkEvidenceStatus::Done,
            Self::Failed => SplunkEvidenceStatus::Failed,
            Self::Expired => SplunkEvidenceStatus::Expired,
            Self::Partial => SplunkEvidenceStatus::Partial,
            Self::Empty => SplunkEvidenceStatus::Empty,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SplunkTiming {
    pub queue_milliseconds: Option<u64>,
    pub duration_milliseconds: Option<u64>,
}

impl SplunkTiming {
    pub fn new(
        queue_milliseconds: Option<u64>,
        duration_milliseconds: Option<u64>,
    ) -> Result<Self, ModelError> {
        if queue_milliseconds.is_some_and(|value| value > MAX_DURATION_MILLISECONDS)
            || duration_milliseconds.is_some_and(|value| value > MAX_DURATION_MILLISECONDS)
        {
            return Err(ModelError::InvalidScope("timing bound"));
        }
        Ok(Self {
            queue_milliseconds,
            duration_milliseconds,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SplunkFieldType {
    Integer,
    Number,
    Boolean,
    String,
    Unknown,
}

impl SplunkFieldType {
    pub fn parse(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "integer" | "int" | "count" => Self::Integer,
            "number" | "double" | "float" | "decimal" => Self::Number,
            "boolean" | "bool" => Self::Boolean,
            "string" | "text" => Self::String,
            _ => Self::Unknown,
        }
    }
}

fn forbidden_field_name(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower == "_raw"
        || lower == "source"
        || lower == "host"
        || lower == "sourcetype"
        || lower.contains("source")
        || lower.starts_with("host")
        || lower.contains("token")
        || lower.contains("pii")
        || lower.starts_with('_')
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SplunkFieldDefinition {
    pub name: String,
    pub field_type: SplunkFieldType,
}

impl SplunkFieldDefinition {
    pub fn new(name: impl Into<String>, field_type: SplunkFieldType) -> Result<Self, ModelError> {
        let name = name.into();
        if name.is_empty()
            || name.len() > MAX_FIELD_NAME_BYTES
            || name.trim() != name
            || name.chars().any(char::is_control)
            || forbidden_field_name(&name)
        {
            return Err(ModelError::InvalidFieldSchema);
        }
        Ok(Self { name, field_type })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        Self::new(self.name.clone(), self.field_type).map(|_| ())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum SplunkAggregateCell {
    Integer(i64),
    Number(String),
    Boolean(bool),
    TextDigest(Digest),
    Null,
}

impl SplunkAggregateCell {
    pub fn from_json(value: &Value, field_type: SplunkFieldType) -> Result<Self, ModelError> {
        match value {
            Value::Null => Ok(Self::Null),
            Value::Bool(value)
                if matches!(
                    field_type,
                    SplunkFieldType::Boolean | SplunkFieldType::Unknown
                ) =>
            {
                Ok(Self::Boolean(*value))
            }
            Value::Number(value)
                if matches!(
                    field_type,
                    SplunkFieldType::Integer | SplunkFieldType::Unknown
                ) =>
            {
                value
                    .as_i64()
                    .map(Self::Integer)
                    .ok_or(ModelError::InvalidAggregateCell)
            }
            Value::Number(value) if matches!(field_type, SplunkFieldType::Number) => {
                let value = value.to_string();
                if value.len() > MAX_CELL_BYTES {
                    Err(ModelError::InvalidAggregateCell)
                } else {
                    Ok(Self::Number(value))
                }
            }
            Value::String(value)
                if matches!(
                    field_type,
                    SplunkFieldType::String | SplunkFieldType::Unknown
                ) =>
            {
                if value.len() > MAX_CELL_BYTES
                    || value.chars().any(char::is_control)
                    || forbidden_field_name(value)
                {
                    return Err(ModelError::InvalidAggregateCell);
                }
                Ok(Self::TextDigest(sha256_digest(
                    format!("splunk-cell-text/v1|{value}").as_bytes(),
                )))
            }
            _ => Err(ModelError::InvalidAggregateCell),
        }
    }

    pub fn from_digest(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_digest(&value)?;
        Ok(Self::TextDigest(value))
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        match self {
            Self::Number(value) => {
                if value.len() > MAX_CELL_BYTES
                    || value.parse::<f64>().is_err()
                    || value.parse::<f64>().is_ok_and(|number| !number.is_finite())
                {
                    Err(ModelError::InvalidAggregateCell)
                } else {
                    Ok(())
                }
            }
            Self::TextDigest(value) => validate_digest(value),
            Self::Integer(_) | Self::Boolean(_) | Self::Null => Ok(()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SplunkAggregateRow {
    pub cells: BTreeMap<String, SplunkAggregateCell>,
}

impl SplunkAggregateRow {
    pub fn new(cells: BTreeMap<String, SplunkAggregateCell>) -> Result<Self, ModelError> {
        if cells.len() > MAX_FIELDS || cells.keys().any(|name| forbidden_field_name(name)) {
            return Err(ModelError::InvalidAggregateCell);
        }
        Ok(Self { cells })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        Self::new(self.cells.clone())?;
        self.cells
            .values()
            .try_for_each(SplunkAggregateCell::validate)
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SplunkAggregatePage {
    pub page: u16,
    pub next_page: Option<u16>,
    pub field_schema: Vec<SplunkFieldDefinition>,
    pub cells: Vec<SplunkAggregateRow>,
    pub partial: bool,
    pub timing: SplunkTiming,
    pub page_digest: Digest,
}

impl SplunkAggregatePage {
    pub fn new(
        page: u16,
        next_page: Option<u16>,
        mut field_schema: Vec<SplunkFieldDefinition>,
        mut cells: Vec<SplunkAggregateRow>,
        partial: bool,
        timing: SplunkTiming,
    ) -> Result<Self, ModelError> {
        if field_schema.is_empty()
            || field_schema.len() > MAX_FIELDS
            || cells.len() > MAX_CELLS_PER_PAGE
            || next_page.is_some_and(|next| next <= page)
        {
            return Err(ModelError::InvalidProviderPage);
        }
        field_schema.sort_by(|left, right| left.name.cmp(&right.name));
        if field_schema
            .windows(2)
            .any(|pair| pair[0].name == pair[1].name)
        {
            return Err(ModelError::InvalidFieldSchema);
        }
        let field_names = field_schema
            .iter()
            .map(|field| field.name.as_str())
            .collect::<BTreeSet<_>>();
        if cells.iter().any(|row| {
            row.cells
                .keys()
                .any(|name| !field_names.contains(name.as_str()))
        }) {
            return Err(ModelError::InvalidAggregateCell);
        }
        cells.sort_by_key(SplunkAggregateRow::digest);
        let page_digest = canonical_digest(&(
            "splunk-result-page/v1",
            page,
            next_page,
            &field_schema,
            &cells,
            partial,
            &timing,
        ));
        Ok(Self {
            page,
            next_page,
            field_schema,
            cells,
            partial,
            timing,
            page_digest,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SplunkAggregateResult {
    pub field_schema: Vec<SplunkFieldDefinition>,
    pub cells: Vec<SplunkAggregateRow>,
    pub partial: bool,
    pub pages: u16,
    pub page_digests: Vec<Digest>,
    pub result_digest: Digest,
}

impl SplunkAggregateResult {
    pub fn from_pages(pages: &[SplunkAggregatePage]) -> Result<Self, ModelError> {
        if pages.len() > usize::from(MAX_PAGES) || pages.is_empty() {
            return Err(ModelError::ResultBoundExceeded);
        }
        let first_schema = pages[0].field_schema.clone();
        first_schema
            .iter()
            .try_for_each(SplunkFieldDefinition::validate)?;
        pages
            .iter()
            .flat_map(|page| page.cells.iter())
            .try_for_each(SplunkAggregateRow::validate)?;
        if pages.iter().any(|page| page.field_schema != first_schema) {
            return Err(ModelError::InvalidFieldSchema);
        }
        let total_cells = pages.iter().map(|page| page.cells.len()).sum::<usize>();
        if total_cells > MAX_AGGREGATE_CELLS {
            return Err(ModelError::ResultBoundExceeded);
        }
        let mut cells = pages
            .iter()
            .flat_map(|page| page.cells.iter().cloned())
            .collect::<Vec<_>>();
        cells.sort_by_key(SplunkAggregateRow::digest);
        let page_digests = pages
            .iter()
            .map(|page| page.page_digest.clone())
            .collect::<Vec<_>>();
        let partial = pages.iter().any(|page| page.partial);
        let result_digest = canonical_digest(&(
            "splunk-aggregate-result/v1",
            &first_schema,
            &cells,
            partial,
            pages.len() as u16,
            &page_digests,
        ));
        Ok(Self {
            field_schema: first_schema,
            cells,
            partial,
            pages: pages.len() as u16,
            page_digests,
            result_digest,
        })
    }

    #[must_use]
    pub fn empty() -> Self {
        let mut result = Self {
            field_schema: Vec::new(),
            cells: Vec::new(),
            partial: false,
            pages: 0,
            page_digests: Vec::new(),
            result_digest: String::new(),
        };
        result.result_digest = canonical_digest(&(
            "splunk-aggregate-result/v1",
            &result.field_schema,
            &result.cells,
            result.partial,
            result.pages,
            &result.page_digests,
        ));
        result
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cells.is_empty()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SplunkSavedSearchResultEvidence {
    pub status: SplunkEvidenceStatus,
    pub classification: EvidenceClassification,
    pub timing: SplunkTiming,
    pub field_schema: Vec<SplunkFieldDefinition>,
    pub aggregate_cells: Vec<SplunkAggregateRow>,
    pub aggregate_partial: bool,
    pub pages_read: u16,
    pub page_digests: Vec<Digest>,
    pub search_digest: Digest,
    pub sid_digest: Digest,
    pub result_digest: Digest,
    pub response_digest: Digest,
    pub scope_digest: Digest,
    pub resource_scope_digest: Digest,
    pub revision_digest: Digest,
    pub privacy_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub provenance: TransportProvenance,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub truth_authority: bool,
    pub consent_authority: bool,
    pub effect_authority: bool,
    pub receipt_authority: bool,
    pub verification_authority: bool,
    pub outcome_authority: bool,
    pub evidence_digest: Digest,
}

impl SplunkSavedSearchResultEvidence {
    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(&serde_json::json!({
            "schema": "splunk-evidence/v1",
            "status": &self.status,
            "classification": &self.classification,
            "timing": &self.timing,
            "fieldSchema": &self.field_schema,
            "aggregateCells": &self.aggregate_cells,
            "aggregatePartial": self.aggregate_partial,
            "pagesRead": self.pages_read,
            "pageDigests": &self.page_digests,
            "searchDigest": &self.search_digest,
            "sidDigest": &self.sid_digest,
            "resultDigest": &self.result_digest,
            "responseDigest": &self.response_digest,
            "scopeDigest": &self.scope_digest,
            "resourceScopeDigest": &self.resource_scope_digest,
            "revisionDigest": &self.revision_digest,
            "privacyDigest": &self.privacy_digest,
            "registrationDigest": &self.registration_digest,
            "providerDigest": &self.provider_digest,
            "provenance": self.provenance,
            "proposalOnly": self.proposal_only,
            "native": self.native,
            "connected": self.connected,
            "firstParty": self.first_party,
            "truthAuthority": self.truth_authority,
            "consentAuthority": self.consent_authority,
            "effectAuthority": self.effect_authority,
            "receiptAuthority": self.receipt_authority,
            "verificationAuthority": self.verification_authority,
            "outcomeAuthority": self.outcome_authority,
        }))
    }

    #[must_use]
    pub fn is_actionable(&self) -> bool {
        matches!(self.status, SplunkEvidenceStatus::Done)
            && !self.aggregate_cells.is_empty()
            && self.proposal_only
            && !self.native
            && !self.connected
            && !self.first_party
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SplunkSavedSearchResultProposal {
    pub scope: SplunkSavedSearchResultScope,
    pub evidence: SplunkSavedSearchResultEvidence,
    pub source_evidence_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub contract_digest: Digest,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub adopts_outcome: bool,
    pub adopts_work_product: bool,
    pub proposal_digest: Digest,
}

impl SplunkSavedSearchResultProposal {
    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(&(
            "splunk-proposal/v1",
            &self.scope,
            &self.evidence,
            &self.source_evidence_digest,
            &self.registration_digest,
            &self.provider_digest,
            &self.contract_digest,
            self.proposal_only,
            self.native,
            self.connected,
            self.first_party,
            self.adopts_outcome,
            self.adopts_work_product,
        ))
    }

    #[must_use]
    pub fn status(&self) -> SplunkEvidenceStatus {
        self.evidence.status
    }
}

fn parse_timestamp(value: &str) -> Option<(i32, u32, u32, u32, u32, u32)> {
    if value.len() != 20
        || value.as_bytes().get(4) != Some(&b'-')
        || value.as_bytes().get(7) != Some(&b'-')
        || value.as_bytes().get(10) != Some(&b'T')
        || value.as_bytes().get(13) != Some(&b':')
        || value.as_bytes().get(16) != Some(&b':')
        || value.as_bytes().get(19) != Some(&b'Z')
    {
        return None;
    }
    let year = value[0..4].parse::<i32>().ok()?;
    let month = value[5..7].parse::<u32>().ok()?;
    let day = value[8..10].parse::<u32>().ok()?;
    let hour = value[11..13].parse::<u32>().ok()?;
    let minute = value[14..16].parse::<u32>().ok()?;
    let second = value[17..19].parse::<u32>().ok()?;
    if !(1..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=59).contains(&second)
    {
        return None;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    (1..=days_in_month)
        .contains(&day)
        .then_some((year, month, day, hour, minute, second))
}

fn timestamp_seconds(
    (year, month, day, hour, minute, second): (i32, u32, u32, u32, u32, u32),
) -> i64 {
    days_from_civil((year, month, day)) * 86_400
        + i64::from(hour) * 3_600
        + i64::from(minute) * 60
        + i64::from(second)
}

fn days_from_civil((year, month, day): (i32, u32, u32)) -> i64 {
    let year = i64::from(year) - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month = i64::from(month);
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era
}

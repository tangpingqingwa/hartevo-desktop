use std::collections::BTreeSet;
use std::fmt;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::canonical::{
    canonical_digest, digest_parts, normalize_https_domain, validate_digest, validate_identifier,
    validate_immutable_id,
};
use crate::{
    CAPABILITY_ID, CONTRACT_VERSION, MAX_ITEMS, MAX_PAGE_SIZE, MAX_RESPONSE_BYTES,
    MAX_SYSTEM_LOG_EVENTS, MAX_SYSTEM_LOG_WINDOW_SECONDS, PLUGIN_ID, PLUGIN_VERSION, PROVIDER_ID,
    REQUIRED_APPLICATION_READ_SCOPE, REQUIRED_GROUP_READ_SCOPE, REQUIRED_SYSTEM_LOG_READ_SCOPE,
    REQUIRED_USER_READ_SCOPE,
};

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ModelError {
    #[error("invalid {field}: {reason}")]
    Invalid { field: String, reason: String },
    #[error("unsupported long-lived SSWS token construction")]
    UnsupportedSswsToken,
    #[error("secret reference is opaque and cannot contain credential material")]
    SecretMaterial,
    #[error("scope does not contain the required read-only grant: {0}")]
    MissingReadScope(String),
    #[error("scope or provider digest is invalid")]
    InvalidDigest,
    #[error("system log polling and bounded window parameters are invalid")]
    InvalidLogWindow,
    #[error("opaque provider cursor is not valid for this scope and operation")]
    InvalidCursor,
}

fn invalid(field: &str, reason: impl Into<String>) -> ModelError {
    ModelError::Invalid {
        field: field.to_owned(),
        reason: reason.into(),
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentReference {
    pub reference_id: String,
    pub revision: u64,
}

impl ConsentReference {
    pub fn new(reference_id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        validate_identifier(&reference_id, "consent reference id")
            .map_err(|reason| invalid("consent reference id", reason))?;
        if revision == 0 {
            return Err(invalid("consent revision", "must be positive"));
        }
        Ok(Self {
            reference_id,
            revision,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionScope {
    pub project_id: String,
    pub mission_id: String,
    pub mission_revision: u64,
    pub consent: ConsentReference,
}

impl MissionScope {
    pub fn new(
        project_id: impl Into<String>,
        mission_id: impl Into<String>,
        mission_revision: u64,
        consent: ConsentReference,
    ) -> Result<Self, ModelError> {
        let project_id = project_id.into();
        let mission_id = mission_id.into();
        validate_identifier(&project_id, "project id")
            .map_err(|reason| invalid("project id", reason))?;
        validate_identifier(&mission_id, "mission id")
            .map_err(|reason| invalid("mission id", reason))?;
        if mission_revision == 0 {
            return Err(invalid("mission revision", "must be positive"));
        }
        Ok(Self {
            project_id,
            mission_id,
            mission_revision,
            consent,
        })
    }
}

/// An opaque reference to a connector-owned secret.
///
/// This type intentionally does not implement `Serialize`.  It contains an
/// identifier and revision only; private JWKs, JWT assertions, access tokens,
/// and SSWS token bytes never cross this crate's boundary.
pub struct SecretReference {
    reference_id: String,
    revision: u64,
    scope_digest: String,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_id: self.reference_id.clone(),
            revision: self.revision,
            scope_digest: self.scope_digest.clone(),
        }
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_id == other.reference_id
            && self.revision == other.revision
            && self.scope_digest == other.scope_digest
    }
}

impl Eq for SecretReference {}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_id", &self.reference_id)
            .field("revision", &self.revision)
            .field("scope_digest", &self.scope_digest)
            .finish()
    }
}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope_digest: impl Into<String>,
        revision: u64,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        let scope_digest = scope_digest.into();
        validate_identifier(&reference_id, "secret reference id")
            .map_err(|reason| invalid("secret reference id", reason))?;
        if revision == 0 || !validate_digest(&scope_digest) {
            return Err(ModelError::SecretMaterial);
        }
        Ok(Self {
            reference_id,
            revision,
            scope_digest,
        })
    }

    pub fn reference_id(&self) -> &str {
        &self.reference_id
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthConstructionError {
    UnsupportedSswsToken,
}

impl fmt::Display for AuthConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSswsToken => {
                formatter.write_str("long-lived SSWS token construction is rejected")
            }
        }
    }
}

impl std::error::Error for AuthConstructionError {}

#[derive(Clone, Eq, PartialEq)]
pub enum ServiceAppAuthentication {
    PrivateKeyJwt { secret_reference: SecretReference },
}

impl fmt::Debug for ServiceAppAuthentication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PrivateKeyJwt { secret_reference } => formatter
                .debug_struct("ServiceAppAuthentication::PrivateKeyJwt")
                .field("secret_reference", secret_reference)
                .finish(),
        }
    }
}

impl ServiceAppAuthentication {
    pub fn private_key_jwt(secret_reference: SecretReference) -> Self {
        Self::PrivateKeyJwt { secret_reference }
    }

    pub fn try_from_ssws_token(_token: impl AsRef<[u8]>) -> Result<Self, AuthConstructionError> {
        Err(AuthConstructionError::UnsupportedSswsToken)
    }

    pub const fn method(&self) -> &'static str {
        "private_key_jwt"
    }

    pub fn secret_reference(&self) -> &SecretReference {
        match self {
            Self::PrivateKeyJwt { secret_reference } => secret_reference,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminResourceSet {
    pub resource_set_id: String,
    pub digest: String,
}

impl AdminResourceSet {
    pub fn new(
        resource_set_id: impl Into<String>,
        digest: impl Into<String>,
    ) -> Result<Self, ModelError> {
        let resource_set_id = resource_set_id.into();
        let digest = digest.into();
        validate_identifier(&resource_set_id, "admin resource set id")
            .map_err(|reason| invalid("admin resource set id", reason))?;
        if !validate_digest(&digest) {
            return Err(ModelError::InvalidDigest);
        }
        Ok(Self {
            resource_set_id,
            digest,
        })
    }
}

pub struct OAuthServiceAppGrant {
    pub client_id: String,
    pub granted_scopes: BTreeSet<String>,
    pub admin_resource_set: AdminResourceSet,
    pub provider_api_revision: String,
    authentication: ServiceAppAuthentication,
}

impl Clone for OAuthServiceAppGrant {
    fn clone(&self) -> Self {
        Self {
            client_id: self.client_id.clone(),
            granted_scopes: self.granted_scopes.clone(),
            admin_resource_set: self.admin_resource_set.clone(),
            provider_api_revision: self.provider_api_revision.clone(),
            authentication: self.authentication.clone(),
        }
    }
}

impl PartialEq for OAuthServiceAppGrant {
    fn eq(&self, other: &Self) -> bool {
        self.client_id == other.client_id
            && self.granted_scopes == other.granted_scopes
            && self.admin_resource_set == other.admin_resource_set
            && self.provider_api_revision == other.provider_api_revision
            && self.authentication == other.authentication
    }
}

impl Eq for OAuthServiceAppGrant {}

impl fmt::Debug for OAuthServiceAppGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OAuthServiceAppGrant")
            .field("client_id", &self.client_id)
            .field("granted_scopes", &self.granted_scopes)
            .field("admin_resource_set", &self.admin_resource_set)
            .field("provider_api_revision", &self.provider_api_revision)
            .field("authentication", &self.authentication)
            .finish()
    }
}

#[derive(Serialize)]
struct GrantDigestInput<'a> {
    client_id: &'a str,
    granted_scopes: &'a BTreeSet<String>,
    admin_resource_set: &'a AdminResourceSet,
    provider_api_revision: &'a str,
}

impl OAuthServiceAppGrant {
    pub fn new(
        client_id: impl Into<String>,
        granted_scopes: impl IntoIterator<Item = String>,
        admin_resource_set: AdminResourceSet,
        provider_api_revision: impl Into<String>,
        authentication: ServiceAppAuthentication,
    ) -> Result<Self, ModelError> {
        let client_id = client_id.into();
        let granted_scopes = granted_scopes.into_iter().collect::<BTreeSet<_>>();
        let provider_api_revision = provider_api_revision.into();
        validate_identifier(&client_id, "service app client id")
            .map_err(|reason| invalid("service app client id", reason))?;
        validate_identifier(&provider_api_revision, "provider API revision")
            .map_err(|reason| invalid("provider API revision", reason))?;
        if granted_scopes.is_empty()
            || granted_scopes
                .iter()
                .any(|scope| !is_read_only_oauth_scope(scope))
        {
            return Err(invalid(
                "granted OAuth scopes",
                "must be non-empty and read-only",
            ));
        }
        if authentication.secret_reference().scope_digest().is_empty() {
            return Err(ModelError::SecretMaterial);
        }
        Ok(Self {
            client_id,
            granted_scopes,
            admin_resource_set,
            provider_api_revision,
            authentication,
        })
    }

    pub fn authentication(&self) -> &ServiceAppAuthentication {
        &self.authentication
    }

    /// Returns the deterministic digest of grant metadata, excluding the
    /// opaque credential reference and all secret material.
    #[allow(clippy::missing_panics_doc)]
    pub fn grant_digest(&self) -> String {
        canonical_digest(&GrantDigestInput {
            client_id: &self.client_id,
            granted_scopes: &self.granted_scopes,
            admin_resource_set: &self.admin_resource_set,
            provider_api_revision: &self.provider_api_revision,
        })
        .expect("grant digest serialization")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OktaScope {
    pub org_id: String,
    pub custom_domain: String,
    pub service_app_client_id: String,
    pub granted_scopes: BTreeSet<String>,
    pub admin_resource_set_digest: String,
    pub project_id: String,
    pub mission_id: String,
    pub mission_revision: u64,
    pub consent: ConsentReference,
}

#[derive(Serialize)]
struct ScopeDigestInput<'a> {
    org_id: &'a str,
    custom_domain: &'a str,
    service_app_client_id: &'a str,
    granted_scopes: &'a BTreeSet<String>,
    admin_resource_set_digest: &'a str,
    project_id: &'a str,
    mission_id: &'a str,
    mission_revision: u64,
    consent: &'a ConsentReference,
}

impl OktaScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        org_id: impl Into<String>,
        custom_domain: impl AsRef<str>,
        service_app_client_id: impl Into<String>,
        granted_scopes: impl IntoIterator<Item = String>,
        admin_resource_set_digest: impl Into<String>,
        project_id: impl Into<String>,
        mission_id: impl Into<String>,
        mission_revision: u64,
        consent: ConsentReference,
    ) -> Result<Self, ModelError> {
        let scope = Self {
            org_id: org_id.into(),
            custom_domain: normalize_https_domain(custom_domain.as_ref())
                .map_err(|reason| invalid("custom domain", reason))?,
            service_app_client_id: service_app_client_id.into(),
            granted_scopes: granted_scopes.into_iter().collect(),
            admin_resource_set_digest: admin_resource_set_digest.into(),
            project_id: project_id.into(),
            mission_id: mission_id.into(),
            mission_revision,
            consent,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        validate_identifier(&self.org_id, "Okta org id")
            .map_err(|reason| invalid("Okta org id", reason))?;
        validate_identifier(&self.service_app_client_id, "service app client id")
            .map_err(|reason| invalid("service app client id", reason))?;
        validate_identifier(&self.project_id, "project id")
            .map_err(|reason| invalid("project id", reason))?;
        validate_identifier(&self.mission_id, "mission id")
            .map_err(|reason| invalid("mission id", reason))?;
        normalize_https_domain(&self.custom_domain)
            .map_err(|reason| invalid("custom domain", reason))?;
        if self.mission_revision == 0 {
            return Err(invalid("mission revision", "must be positive"));
        }
        if self.granted_scopes.is_empty() {
            return Err(invalid("granted scopes", "must not be empty"));
        }
        if self
            .granted_scopes
            .iter()
            .any(|scope| !is_read_only_oauth_scope(scope))
        {
            return Err(invalid(
                "granted scopes",
                "Layer 1 only accepts read-only OAuth scopes",
            ));
        }
        if !validate_digest(&self.admin_resource_set_digest) {
            return Err(ModelError::InvalidDigest);
        }
        Ok(())
    }

    /// Returns the deterministic digest of the exact org, grant, and Mission
    /// scope.
    #[allow(clippy::missing_panics_doc)]
    pub fn digest(&self) -> String {
        canonical_digest(&ScopeDigestInput {
            org_id: &self.org_id,
            custom_domain: &self.custom_domain,
            service_app_client_id: &self.service_app_client_id,
            granted_scopes: &self.granted_scopes,
            admin_resource_set_digest: &self.admin_resource_set_digest,
            project_id: &self.project_id,
            mission_id: &self.mission_id,
            mission_revision: self.mission_revision,
            consent: &self.consent,
        })
        .expect("scope digest serialization")
    }

    pub fn mission_scope(&self) -> MissionScope {
        MissionScope {
            project_id: self.project_id.clone(),
            mission_id: self.mission_id.clone(),
            mission_revision: self.mission_revision,
            consent: self.consent.clone(),
        }
    }

    pub fn missing_required_read_scopes(&self) -> Vec<String> {
        [
            REQUIRED_USER_READ_SCOPE,
            REQUIRED_GROUP_READ_SCOPE,
            REQUIRED_APPLICATION_READ_SCOPE,
            REQUIRED_SYSTEM_LOG_READ_SCOPE,
        ]
        .into_iter()
        .filter(|scope| !self.granted_scopes.contains(*scope))
        .map(str::to_owned)
        .collect()
    }

    pub fn matches_mission(&self, mission: &MissionScope) -> bool {
        self.project_id == mission.project_id
            && self.mission_id == mission.mission_id
            && self.mission_revision == mission.mission_revision
            && self.consent == mission.consent
    }
}

fn is_read_only_oauth_scope(scope: &str) -> bool {
    scope.starts_with("okta.")
        && !scope.contains(".manage")
        && !scope.contains(".write")
        && !scope.contains(".lifecycle")
        && !scope.contains(".admin")
}

macro_rules! immutable_id {
    ($name:ident, $field:literal, [$($prefix:literal),+]) => {
        #[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_immutable_id(&value, $field, &[$($prefix),+])
                    .map_err(|reason| invalid($field, reason))?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn validate(&self) -> Result<(), ModelError> {
                validate_immutable_id(&self.0, $field, &[$($prefix),+])
                    .map_err(|reason| invalid($field, reason))
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }
    };
}

immutable_id!(OktaUserId, "Okta user id", ["00u", "usr_", "user-"]);
immutable_id!(OktaGroupId, "Okta group id", ["00g", "grp_", "group-"]);
immutable_id!(
    OktaApplicationId,
    "Okta application id",
    ["0oa", "app_", "app-"]
);

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OktaTargetId {
    User(OktaUserId),
    Group(OktaGroupId),
    Application(OktaApplicationId),
}

impl OktaTargetId {
    pub fn validate(&self) -> Result<(), ModelError> {
        match self {
            Self::User(id) => id.validate(),
            Self::Group(id) => id.validate(),
            Self::Application(id) => id.validate(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OktaUserRecord {
    pub id: OktaUserId,
    pub status: String,
    pub profile_digest: String,
}

impl OktaUserRecord {
    pub fn new(
        id: OktaUserId,
        status: impl Into<String>,
        profile_digest: impl Into<String>,
    ) -> Result<Self, ModelError> {
        let status = status.into();
        let profile_digest = profile_digest.into();
        id.validate()?;
        validate_identifier(&status, "user status")
            .map_err(|reason| invalid("user status", reason))?;
        if !validate_digest(&profile_digest) {
            return Err(ModelError::InvalidDigest);
        }
        Ok(Self {
            id,
            status,
            profile_digest,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OktaGroupRecord {
    pub id: OktaGroupId,
    pub membership_digest: String,
}

impl OktaGroupRecord {
    pub fn new(id: OktaGroupId, membership_digest: impl Into<String>) -> Result<Self, ModelError> {
        let membership_digest = membership_digest.into();
        id.validate()?;
        if !validate_digest(&membership_digest) {
            return Err(ModelError::InvalidDigest);
        }
        Ok(Self {
            id,
            membership_digest,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OktaApplicationRecord {
    pub id: OktaApplicationId,
    pub status: String,
    pub configuration_digest: String,
}

impl OktaApplicationRecord {
    pub fn new(
        id: OktaApplicationId,
        status: impl Into<String>,
        configuration_digest: impl Into<String>,
    ) -> Result<Self, ModelError> {
        let status = status.into();
        let configuration_digest = configuration_digest.into();
        id.validate()?;
        validate_identifier(&status, "application status")
            .map_err(|reason| invalid("application status", reason))?;
        if !validate_digest(&configuration_digest) {
            return Err(ModelError::InvalidDigest);
        }
        Ok(Self {
            id,
            status,
            configuration_digest,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssignmentKind {
    Direct,
    Group,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssignmentState {
    Assigned,
    Unassigned,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EntitlementBinding {
    pub application_id: OktaApplicationId,
    pub target: OktaTargetId,
    pub kind: AssignmentKind,
    pub state: AssignmentState,
    pub provider_revision: String,
    pub observed_at: DateTime<Utc>,
    pub metadata_digest: String,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AssignmentKey {
    pub application_id: OktaApplicationId,
    pub target: OktaTargetId,
}

impl EntitlementBinding {
    pub fn new(
        application_id: OktaApplicationId,
        target: OktaTargetId,
        kind: AssignmentKind,
        state: AssignmentState,
        provider_revision: impl Into<String>,
        observed_at: DateTime<Utc>,
        metadata_digest: impl Into<String>,
    ) -> Result<Self, ModelError> {
        let provider_revision = provider_revision.into();
        let metadata_digest = metadata_digest.into();
        application_id.validate()?;
        validate_identifier(&provider_revision, "assignment provider revision")
            .map_err(|reason| invalid("assignment provider revision", reason))?;
        if !validate_digest(&metadata_digest) {
            return Err(ModelError::InvalidDigest);
        }
        match &target {
            OktaTargetId::User(id) => id.validate()?,
            OktaTargetId::Group(id) => id.validate()?,
            OktaTargetId::Application(id) => id.validate()?,
        }
        Ok(Self {
            application_id,
            target,
            kind,
            state,
            provider_revision,
            observed_at,
            metadata_digest,
        })
    }

    pub fn key(&self) -> AssignmentKey {
        AssignmentKey {
            application_id: self.application_id.clone(),
            target: self.target.clone(),
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        Self::new(
            self.application_id.clone(),
            self.target.clone(),
            self.kind,
            self.state,
            self.provider_revision.clone(),
            self.observed_at,
            self.metadata_digest.clone(),
        )
        .map(|_| ())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl Provenance {
    pub const fn is_connected(self) -> bool {
        false
    }

    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn status(self) -> &'static str {
        match self {
            Self::Fixture => "fixture_evidence",
            Self::Recording => "recording_evidence",
            Self::Loopback => "loopback_evidence",
            Self::BlockedEnv => "BLOCKED_ENV",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceProvenance {
    pub transport: Provenance,
    pub source_digest: String,
    pub status: String,
    pub connected: bool,
    pub native: bool,
}

impl EvidenceProvenance {
    pub fn new(
        transport: Provenance,
        source_digest: impl Into<String>,
    ) -> Result<Self, ModelError> {
        let source_digest = source_digest.into();
        if !validate_digest(&source_digest) {
            return Err(ModelError::InvalidDigest);
        }
        Ok(Self {
            transport,
            source_digest,
            status: transport.status().to_owned(),
            connected: false,
            native: false,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if !validate_digest(&self.source_digest)
            || self.status != self.transport.status()
            || self.connected
            || self.native
        {
            return Err(ModelError::InvalidDigest);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityOperation {
    DescribeCapabilities,
    ProbeRegistration,
    ReadEntitlementSnapshot,
    ReadSystemLogWindow,
    CompileAccessChangeProposal,
    VerifyEntitlementEvidence,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityDescription {
    pub plugin_id: String,
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: String,
    pub provider_id: String,
    pub provider_api_revision: String,
    pub capability_id: String,
    pub operations: BTreeSet<CapabilityOperation>,
    pub authentication_method: String,
    pub read_only: bool,
    pub connected: bool,
    pub native: bool,
    pub mutation_authority: bool,
    pub provenance: Provenance,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GrantReceipt {
    pub provider_id: String,
    pub org_id: String,
    pub custom_domain: String,
    pub service_app_client_id: String,
    pub granted_scopes: BTreeSet<String>,
    pub admin_resource_set_digest: String,
    pub provider_api_revision: String,
    pub observed_at: DateTime<Utc>,
    pub provenance: EvidenceProvenance,
    pub response_digest: String,
    pub receipt_digest: String,
}

#[derive(Serialize)]
struct GrantReceiptDigestInput<'a> {
    provider_id: &'a str,
    org_id: &'a str,
    custom_domain: &'a str,
    service_app_client_id: &'a str,
    granted_scopes: &'a BTreeSet<String>,
    admin_resource_set_digest: &'a str,
    provider_api_revision: &'a str,
    observed_at: DateTime<Utc>,
    provenance: &'a EvidenceProvenance,
    response_digest: &'a str,
}

impl GrantReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        org_id: impl Into<String>,
        custom_domain: impl AsRef<str>,
        service_app_client_id: impl Into<String>,
        granted_scopes: impl IntoIterator<Item = String>,
        admin_resource_set_digest: impl Into<String>,
        provider_api_revision: impl Into<String>,
        observed_at: DateTime<Utc>,
        provenance: EvidenceProvenance,
        response_digest: impl Into<String>,
    ) -> Result<Self, ModelError> {
        let org_id = org_id.into();
        let custom_domain = normalize_https_domain(custom_domain.as_ref())
            .map_err(|reason| invalid("custom domain", reason))?;
        let service_app_client_id = service_app_client_id.into();
        let granted_scopes = granted_scopes.into_iter().collect::<BTreeSet<_>>();
        let admin_resource_set_digest = admin_resource_set_digest.into();
        let provider_api_revision = provider_api_revision.into();
        let response_digest = response_digest.into();
        validate_identifier(&org_id, "Okta org id")
            .map_err(|reason| invalid("Okta org id", reason))?;
        validate_identifier(&service_app_client_id, "service app client id")
            .map_err(|reason| invalid("service app client id", reason))?;
        validate_identifier(&provider_api_revision, "provider API revision")
            .map_err(|reason| invalid("provider API revision", reason))?;
        if granted_scopes.is_empty()
            || granted_scopes
                .iter()
                .any(|scope| !is_read_only_oauth_scope(scope))
        {
            return Err(invalid("granted scopes", "must be non-empty and read-only"));
        }
        if !validate_digest(&admin_resource_set_digest) || !validate_digest(&response_digest) {
            return Err(ModelError::InvalidDigest);
        }
        let mut receipt = Self {
            provider_id: PROVIDER_ID.to_owned(),
            org_id,
            custom_domain,
            service_app_client_id,
            granted_scopes,
            admin_resource_set_digest,
            provider_api_revision,
            observed_at,
            provenance,
            response_digest,
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = receipt.compute_digest();
        Ok(receipt)
    }

    fn compute_digest(&self) -> String {
        canonical_digest(&GrantReceiptDigestInput {
            provider_id: &self.provider_id,
            org_id: &self.org_id,
            custom_domain: &self.custom_domain,
            service_app_client_id: &self.service_app_client_id,
            granted_scopes: &self.granted_scopes,
            admin_resource_set_digest: &self.admin_resource_set_digest,
            provider_api_revision: &self.provider_api_revision,
            observed_at: self.observed_at,
            provenance: &self.provenance,
            response_digest: &self.response_digest,
        })
        .expect("grant receipt digest serialization")
    }

    pub fn verify_integrity(&self) -> Result<(), ModelError> {
        normalize_https_domain(&self.custom_domain)
            .map_err(|reason| invalid("custom domain", reason))?;
        validate_identifier(&self.org_id, "Okta org id")
            .map_err(|reason| invalid("Okta org id", reason))?;
        validate_identifier(&self.service_app_client_id, "service app client id")
            .map_err(|reason| invalid("service app client id", reason))?;
        validate_identifier(&self.provider_api_revision, "provider API revision")
            .map_err(|reason| invalid("provider API revision", reason))?;
        if self.provider_id != PROVIDER_ID
            || self.granted_scopes.is_empty()
            || self
                .granted_scopes
                .iter()
                .any(|scope| !is_read_only_oauth_scope(scope))
            || !validate_digest(&self.admin_resource_set_digest)
            || !validate_digest(&self.response_digest)
        {
            return Err(ModelError::InvalidDigest);
        }
        self.provenance.validate()?;
        if self.receipt_digest != self.compute_digest() {
            return Err(ModelError::InvalidDigest);
        }
        Ok(())
    }

    pub fn assert_matches(
        &self,
        scope: &OktaScope,
        grant: &OAuthServiceAppGrant,
    ) -> Result<(), ModelError> {
        self.verify_integrity()?;
        if self.org_id != scope.org_id
            || self.custom_domain != scope.custom_domain
            || self.service_app_client_id != scope.service_app_client_id
            || self.granted_scopes != grant.granted_scopes
            || self.granted_scopes != scope.granted_scopes
            || self.admin_resource_set_digest != grant.admin_resource_set.digest
            || self.admin_resource_set_digest != scope.admin_resource_set_digest
            || self.provider_api_revision != grant.provider_api_revision
        {
            return Err(ModelError::InvalidDigest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Reversed,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityRegistration {
    pub registration_id: String,
    pub plugin_id: String,
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: String,
    pub provider_id: String,
    pub provider_api_revision: String,
    pub capability_id: String,
    pub grant_digest: String,
    pub scope_digest: String,
    pub scope: OktaScope,
    pub state: RegistrationState,
    pub revision: u64,
    pub registration_digest: String,
}

#[derive(Serialize)]
struct RegistrationDigestInput<'a> {
    registration_id: &'a str,
    plugin_id: &'a str,
    plugin_version: &'a str,
    contract_version: &'a str,
    contract_digest: &'a str,
    provider_id: &'a str,
    provider_api_revision: &'a str,
    capability_id: &'a str,
    grant_digest: &'a str,
    scope_digest: &'a str,
    revision: u64,
}

impl CapabilityRegistration {
    pub fn new(
        registration_id: impl Into<String>,
        scope: OktaScope,
        grant: &OAuthServiceAppGrant,
    ) -> Result<Self, ModelError> {
        let registration_id = registration_id.into();
        validate_identifier(&registration_id, "registration id")
            .map_err(|reason| invalid("registration id", reason))?;
        scope.validate()?;
        if grant.client_id != scope.service_app_client_id
            || grant.granted_scopes != scope.granted_scopes
            || grant.admin_resource_set.digest != scope.admin_resource_set_digest
            || grant.authentication().secret_reference().scope_digest() != scope.digest()
        {
            return Err(ModelError::InvalidDigest);
        }
        let mut registration = Self {
            registration_id,
            plugin_id: PLUGIN_ID.to_owned(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            provider_id: PROVIDER_ID.to_owned(),
            provider_api_revision: grant.provider_api_revision.clone(),
            capability_id: CAPABILITY_ID.to_owned(),
            grant_digest: grant.grant_digest(),
            scope_digest: scope.digest(),
            scope,
            state: RegistrationState::Active,
            revision: 1,
            registration_digest: String::new(),
        };
        registration.registration_digest = registration.compute_digest();
        Ok(registration)
    }

    fn compute_digest(&self) -> String {
        canonical_digest(&RegistrationDigestInput {
            registration_id: &self.registration_id,
            plugin_id: &self.plugin_id,
            plugin_version: &self.plugin_version,
            contract_version: &self.contract_version,
            contract_digest: &self.contract_digest,
            provider_id: &self.provider_id,
            provider_api_revision: &self.provider_api_revision,
            capability_id: &self.capability_id,
            grant_digest: &self.grant_digest,
            scope_digest: &self.scope_digest,
            revision: self.revision,
        })
        .expect("registration digest serialization")
    }

    pub fn verify_integrity(&self) -> Result<(), ModelError> {
        self.scope.validate()?;
        if !validate_digest(&self.contract_digest)
            || !validate_digest(&self.grant_digest)
            || !validate_digest(&self.scope_digest)
            || validate_identifier(&self.registration_id, "registration id").is_err()
            || self.registration_digest != self.compute_digest()
        {
            return Err(ModelError::InvalidDigest);
        }
        Ok(())
    }

    pub fn is_active(&self) -> bool {
        self.state == RegistrationState::Active
    }

    pub fn reverse(&mut self) -> Result<(), ModelError> {
        self.verify_integrity()?;
        if self.state == RegistrationState::Revoked {
            return Err(invalid(
                "registration state",
                "revoked registration is terminal",
            ));
        }
        self.state = RegistrationState::Reversed;
        self.revision = self.revision.saturating_add(1);
        self.registration_digest = self.compute_digest();
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), ModelError> {
        self.verify_integrity()?;
        if self.state != RegistrationState::Reversed {
            return Err(invalid(
                "registration state",
                "only a reversed registration can be restored",
            ));
        }
        self.state = RegistrationState::Active;
        self.revision = self.revision.saturating_add(1);
        self.registration_digest = self.compute_digest();
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        self.verify_integrity()?;
        if self.state == RegistrationState::Revoked {
            return Ok(());
        }
        self.state = RegistrationState::Revoked;
        self.revision = self.revision.saturating_add(1);
        self.registration_digest = self.compute_digest();
        Ok(())
    }

    pub fn assert_fences(
        &self,
        scope: &OktaScope,
        grant: &OAuthServiceAppGrant,
    ) -> Result<(), ModelError> {
        self.verify_integrity()?;
        if self.plugin_id != PLUGIN_ID
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.provider_id != PROVIDER_ID
            || self.provider_api_revision != grant.provider_api_revision
            || self.capability_id != CAPABILITY_ID
            || self.grant_digest != grant.grant_digest()
            || self.scope_digest != scope.digest()
            || self.scope != *scope
        {
            return Err(ModelError::InvalidDigest);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadBounds {
    pub page_size: usize,
    pub max_pages: usize,
    pub max_items: usize,
    pub max_response_bytes: usize,
}

impl Default for ReadBounds {
    fn default() -> Self {
        Self {
            page_size: MAX_PAGE_SIZE,
            max_pages: 20,
            max_items: MAX_ITEMS,
            max_response_bytes: MAX_RESPONSE_BYTES,
        }
    }
}

impl ReadBounds {
    pub fn validate(self) -> Result<(), ModelError> {
        if self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
            || self.max_pages == 0
            || self.max_pages > 100
            || self.max_items == 0
            || self.max_items > 10_000
            || self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(invalid("read bounds", "outside Layer-1 safety limits"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectReadReceipt {
    pub provider_id: String,
    pub provider_revision: String,
    pub direct_read_revision: String,
    pub observed_at: DateTime<Utc>,
    pub pages: usize,
    pub item_count: usize,
    pub response_bytes: usize,
    pub scope_digest: String,
    pub assignment_set_digest: String,
    pub provenance: EvidenceProvenance,
    pub receipt_digest: String,
}

#[derive(Serialize)]
struct DirectReadReceiptDigestInput<'a> {
    provider_id: &'a str,
    provider_revision: &'a str,
    direct_read_revision: &'a str,
    observed_at: DateTime<Utc>,
    pages: usize,
    item_count: usize,
    response_bytes: usize,
    scope_digest: &'a str,
    assignment_set_digest: &'a str,
    provenance: &'a EvidenceProvenance,
}

impl DirectReadReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider_revision: impl Into<String>,
        direct_read_revision: impl Into<String>,
        observed_at: DateTime<Utc>,
        pages: usize,
        item_count: usize,
        response_bytes: usize,
        scope_digest: impl Into<String>,
        assignment_set_digest: impl Into<String>,
        provenance: EvidenceProvenance,
    ) -> Result<Self, ModelError> {
        let provider_revision = provider_revision.into();
        let direct_read_revision = direct_read_revision.into();
        let scope_digest = scope_digest.into();
        let assignment_set_digest = assignment_set_digest.into();
        validate_identifier(&provider_revision, "provider revision")
            .map_err(|reason| invalid("provider revision", reason))?;
        validate_identifier(&direct_read_revision, "direct-read provider revision")
            .map_err(|reason| invalid("direct-read provider revision", reason))?;
        if pages == 0
            || !validate_digest(&scope_digest)
            || !validate_digest(&assignment_set_digest)
            || response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(invalid("direct read receipt", "invalid bounded receipt"));
        }
        let mut receipt = Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision,
            direct_read_revision,
            observed_at,
            pages,
            item_count,
            response_bytes,
            scope_digest,
            assignment_set_digest,
            provenance,
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = receipt.compute_digest();
        Ok(receipt)
    }

    fn compute_digest(&self) -> String {
        canonical_digest(&DirectReadReceiptDigestInput {
            provider_id: &self.provider_id,
            provider_revision: &self.provider_revision,
            direct_read_revision: &self.direct_read_revision,
            observed_at: self.observed_at,
            pages: self.pages,
            item_count: self.item_count,
            response_bytes: self.response_bytes,
            scope_digest: &self.scope_digest,
            assignment_set_digest: &self.assignment_set_digest,
            provenance: &self.provenance,
        })
        .expect("direct read receipt digest serialization")
    }

    pub fn verify_integrity(&self) -> Result<(), ModelError> {
        validate_identifier(&self.provider_revision, "provider revision")
            .map_err(|reason| invalid("provider revision", reason))?;
        validate_identifier(&self.direct_read_revision, "direct-read provider revision")
            .map_err(|reason| invalid("direct-read provider revision", reason))?;
        if !validate_digest(&self.scope_digest)
            || !validate_digest(&self.assignment_set_digest)
            || self.response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(ModelError::InvalidDigest);
        }
        self.provenance.validate()?;
        if self.receipt_digest == self.compute_digest() {
            Ok(())
        } else {
            Err(ModelError::InvalidDigest)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EntitlementSnapshot {
    pub scope: OktaScope,
    pub provider_revision: String,
    pub observed_at: DateTime<Utc>,
    pub users: Vec<OktaUserRecord>,
    pub groups: Vec<OktaGroupRecord>,
    pub applications: Vec<OktaApplicationRecord>,
    pub assignments: Vec<EntitlementBinding>,
    pub assignment_set_digest: String,
    pub direct_read: DirectReadReceipt,
    pub snapshot_digest: String,
}

#[derive(Serialize)]
struct SnapshotDigestInput<'a> {
    scope: &'a OktaScope,
    provider_revision: &'a str,
    observed_at: DateTime<Utc>,
    users: &'a [OktaUserRecord],
    groups: &'a [OktaGroupRecord],
    applications: &'a [OktaApplicationRecord],
    assignments: &'a [EntitlementBinding],
    assignment_set_digest: &'a str,
    direct_read_digest: &'a str,
}

impl EntitlementSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: OktaScope,
        provider_revision: impl Into<String>,
        observed_at: DateTime<Utc>,
        users: Vec<OktaUserRecord>,
        groups: Vec<OktaGroupRecord>,
        applications: Vec<OktaApplicationRecord>,
        assignments: Vec<EntitlementBinding>,
        direct_read: DirectReadReceipt,
    ) -> Result<Self, ModelError> {
        let provider_revision = provider_revision.into();
        scope.validate()?;
        validate_identifier(&provider_revision, "provider revision")
            .map_err(|reason| invalid("provider revision", reason))?;
        users.iter().try_for_each(OktaUserRecord::validate)?;
        groups.iter().try_for_each(OktaGroupRecord::validate)?;
        applications
            .iter()
            .try_for_each(OktaApplicationRecord::validate)?;
        assignments
            .iter()
            .try_for_each(EntitlementBinding::validate)?;
        let assignment_set_digest = canonical_digest(&assignments)
            .map_err(|_| invalid("assignment set", "cannot serialize"))?;
        let mut snapshot = Self {
            scope,
            provider_revision,
            observed_at,
            users,
            groups,
            applications,
            assignments,
            assignment_set_digest,
            direct_read,
            snapshot_digest: String::new(),
        };
        snapshot.snapshot_digest = snapshot.compute_digest();
        Ok(snapshot)
    }

    fn compute_digest(&self) -> String {
        canonical_digest(&SnapshotDigestInput {
            scope: &self.scope,
            provider_revision: &self.provider_revision,
            observed_at: self.observed_at,
            users: &self.users,
            groups: &self.groups,
            applications: &self.applications,
            assignments: &self.assignments,
            assignment_set_digest: &self.assignment_set_digest,
            direct_read_digest: &self.direct_read.receipt_digest,
        })
        .expect("entitlement snapshot digest serialization")
    }

    pub fn verify_integrity(&self) -> Result<(), ModelError> {
        self.scope.validate()?;
        validate_identifier(&self.provider_revision, "provider revision")
            .map_err(|reason| invalid("provider revision", reason))?;
        self.users.iter().try_for_each(OktaUserRecord::validate)?;
        self.groups.iter().try_for_each(OktaGroupRecord::validate)?;
        self.applications
            .iter()
            .try_for_each(OktaApplicationRecord::validate)?;
        self.assignments
            .iter()
            .try_for_each(EntitlementBinding::validate)?;
        let assignment_set_digest = canonical_digest(&self.assignments)
            .map_err(|_| invalid("assignment set", "cannot serialize"))?;
        if assignment_set_digest != self.assignment_set_digest
            || self.direct_read.scope_digest != self.scope.digest()
            || self.direct_read.provider_revision != self.provider_revision
        {
            return Err(ModelError::InvalidDigest);
        }
        self.direct_read.verify_integrity()?;
        if self.snapshot_digest == self.compute_digest() {
            Ok(())
        } else {
            Err(ModelError::InvalidDigest)
        }
    }

    pub fn current_state_is_direct_read(&self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntitlementPageCursor {
    provider_id: String,
    scope_digest: String,
    offset: usize,
    proof: String,
}

impl EntitlementPageCursor {
    pub(crate) fn new(provider_id: &str, scope_digest: &str, offset: usize) -> Self {
        let proof = digest_parts(&[provider_id, scope_digest, &offset.to_string()]);
        Self {
            provider_id: provider_id.to_owned(),
            scope_digest: scope_digest.to_owned(),
            offset,
            proof,
        }
    }

    pub(crate) fn tampered(scope_digest: &str, offset: usize) -> Self {
        Self {
            provider_id: "unexpected-provider".to_owned(),
            scope_digest: scope_digest.to_owned(),
            offset,
            proof: "tampered".to_owned(),
        }
    }

    pub(crate) fn validate(&self, scope_digest: &str) -> bool {
        self.provider_id == PROVIDER_ID
            && self.scope_digest == scope_digest
            && self.proof
                == digest_parts(&[
                    &self.provider_id,
                    &self.scope_digest,
                    &self.offset.to_string(),
                ])
    }

    pub(crate) const fn offset(&self) -> usize {
        self.offset
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemLogCursor {
    provider_id: String,
    scope_digest: String,
    window_digest: String,
    offset: usize,
    proof: String,
}

impl SystemLogCursor {
    pub(crate) fn new(
        provider_id: &str,
        scope_digest: &str,
        window_digest: &str,
        offset: usize,
    ) -> Self {
        let proof = digest_parts(&[
            provider_id,
            scope_digest,
            window_digest,
            &offset.to_string(),
        ]);
        Self {
            provider_id: provider_id.to_owned(),
            scope_digest: scope_digest.to_owned(),
            window_digest: window_digest.to_owned(),
            offset,
            proof,
        }
    }

    pub(crate) fn tampered(scope_digest: &str, window_digest: &str, offset: usize) -> Self {
        Self {
            provider_id: "unexpected-provider".to_owned(),
            scope_digest: scope_digest.to_owned(),
            window_digest: window_digest.to_owned(),
            offset,
            proof: "tampered".to_owned(),
        }
    }

    pub(crate) fn validate(&self, scope_digest: &str, window_digest: &str) -> bool {
        self.provider_id == PROVIDER_ID
            && self.scope_digest == scope_digest
            && self.window_digest == window_digest
            && self.proof
                == digest_parts(&[
                    &self.provider_id,
                    &self.scope_digest,
                    &self.window_digest,
                    &self.offset.to_string(),
                ])
    }

    pub(crate) const fn offset(&self) -> usize {
        self.offset
    }

    pub fn digest(&self) -> String {
        digest_parts(&[
            &self.provider_id,
            &self.scope_digest,
            &self.window_digest,
            &self.offset.to_string(),
        ])
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LogWindowMode {
    Polling {
        since: DateTime<Utc>,
    },
    Bounded {
        since: DateTime<Utc>,
        until: DateTime<Utc>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemLogWindowRequest {
    pub scope_digest: String,
    pub mode: LogWindowMode,
    after: Option<SystemLogCursor>,
    pub max_events: usize,
    pub max_response_bytes: usize,
}

impl SystemLogWindowRequest {
    pub fn polling(scope: &OktaScope, since: DateTime<Utc>) -> Self {
        Self {
            scope_digest: scope.digest(),
            mode: LogWindowMode::Polling { since },
            after: None,
            max_events: MAX_SYSTEM_LOG_EVENTS,
            max_response_bytes: MAX_RESPONSE_BYTES,
        }
    }

    pub fn bounded(scope: &OktaScope, since: DateTime<Utc>, until: DateTime<Utc>) -> Self {
        Self {
            scope_digest: scope.digest(),
            mode: LogWindowMode::Bounded { since, until },
            after: None,
            max_events: MAX_SYSTEM_LOG_EVENTS,
            max_response_bytes: MAX_RESPONSE_BYTES,
        }
    }

    #[must_use]
    pub fn with_after(mut self, after: &SystemLogCursor) -> Self {
        self.after = Some(after.clone());
        self
    }

    pub fn after(&self) -> Option<&SystemLogCursor> {
        self.after.as_ref()
    }

    #[must_use]
    pub fn with_bounds(mut self, max_events: usize, max_response_bytes: usize) -> Self {
        self.max_events = max_events;
        self.max_response_bytes = max_response_bytes;
        self
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.scope_digest.len() != 64
            || self.max_events == 0
            || self.max_events > MAX_SYSTEM_LOG_EVENTS
            || self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(ModelError::InvalidLogWindow);
        }
        match self.mode {
            LogWindowMode::Polling { .. } => {}
            LogWindowMode::Bounded { since, until } => {
                let window = until - since;
                if until <= since || window > Duration::seconds(MAX_SYSTEM_LOG_WINDOW_SECONDS) {
                    return Err(ModelError::InvalidLogWindow);
                }
            }
        }
        Ok(())
    }

    pub fn window_digest(&self) -> String {
        let mode = match self.mode {
            LogWindowMode::Polling { since } => format!("polling:{since}"),
            LogWindowMode::Bounded { since, until } => format!("bounded:{since}:{until}"),
        };
        digest_parts(&[&self.scope_digest, &mode])
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LogOutcome {
    Success,
    Failure { reason_code: String },
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SystemLogEvent {
    pub event_id: String,
    pub event_type: String,
    pub published_at: DateTime<Utc>,
    pub persisted_at: DateTime<Utc>,
    pub target_ids: Vec<OktaTargetId>,
    pub outcome: LogOutcome,
    pub cursor_digest: String,
    pub event_digest: String,
}

#[derive(Serialize)]
struct SystemLogEventDigestInput<'a> {
    event_id: &'a str,
    event_type: &'a str,
    published_at: DateTime<Utc>,
    persisted_at: DateTime<Utc>,
    target_ids: &'a [OktaTargetId],
    outcome: &'a LogOutcome,
    cursor_digest: &'a str,
}

impl SystemLogEvent {
    pub fn new(
        event_id: impl Into<String>,
        event_type: impl Into<String>,
        published_at: DateTime<Utc>,
        persisted_at: DateTime<Utc>,
        target_ids: Vec<OktaTargetId>,
        outcome: LogOutcome,
        cursor_digest: impl Into<String>,
    ) -> Result<Self, ModelError> {
        let event_id = event_id.into();
        let event_type = event_type.into();
        let cursor_digest = cursor_digest.into();
        validate_identifier(&event_id, "System Log event id")
            .map_err(|reason| invalid("System Log event id", reason))?;
        validate_identifier(&event_type, "System Log event type")
            .map_err(|reason| invalid("System Log event type", reason))?;
        if !validate_digest(&cursor_digest) || persisted_at < published_at {
            return Err(invalid("System Log event", "invalid cursor or timestamps"));
        }
        target_ids.iter().try_for_each(OktaTargetId::validate)?;
        if let LogOutcome::Failure { reason_code } = &outcome {
            validate_identifier(reason_code, "System Log outcome reason")
                .map_err(|reason| invalid("System Log outcome reason", reason))?;
        }
        let mut event = Self {
            event_id,
            event_type,
            published_at,
            persisted_at,
            target_ids,
            outcome,
            cursor_digest,
            event_digest: String::new(),
        };
        event.event_digest = event.compute_digest();
        Ok(event)
    }

    fn compute_digest(&self) -> String {
        canonical_digest(&SystemLogEventDigestInput {
            event_id: &self.event_id,
            event_type: &self.event_type,
            published_at: self.published_at,
            persisted_at: self.persisted_at,
            target_ids: &self.target_ids,
            outcome: &self.outcome,
            cursor_digest: &self.cursor_digest,
        })
        .expect("System Log event digest serialization")
    }

    pub fn verify_integrity(&self) -> Result<(), ModelError> {
        validate_identifier(&self.event_id, "System Log event id")
            .map_err(|reason| invalid("System Log event id", reason))?;
        validate_identifier(&self.event_type, "System Log event type")
            .map_err(|reason| invalid("System Log event type", reason))?;
        if !validate_digest(&self.cursor_digest)
            || self.persisted_at < self.published_at
            || self
                .target_ids
                .iter()
                .any(|target| target.validate().is_err())
        {
            return Err(ModelError::InvalidDigest);
        }
        if let LogOutcome::Failure { reason_code } = &self.outcome {
            validate_identifier(reason_code, "System Log outcome reason")
                .map_err(|reason| invalid("System Log outcome reason", reason))?;
        }
        if self.event_digest == self.compute_digest() {
            Ok(())
        } else {
            Err(ModelError::InvalidDigest)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LogAvailability {
    Complete,
    Unavailable { reason: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SystemLogReceipt {
    pub provider_id: String,
    pub provider_revision: String,
    pub scope_digest: String,
    pub window_digest: String,
    pub mode: LogWindowMode,
    pub events: Vec<SystemLogEvent>,
    pub availability: LogAvailability,
    pub pages: usize,
    pub response_bytes: usize,
    pub link_digest: String,
    pub next_after_digest: Option<String>,
    pub provenance: EvidenceProvenance,
    pub receipt_digest: String,
    #[serde(skip)]
    next_after: Option<SystemLogCursor>,
}

#[derive(Serialize)]
struct SystemLogReceiptDigestInput<'a> {
    provider_id: &'a str,
    provider_revision: &'a str,
    scope_digest: &'a str,
    window_digest: &'a str,
    mode: &'a LogWindowMode,
    events: &'a [SystemLogEvent],
    availability: &'a LogAvailability,
    pages: usize,
    response_bytes: usize,
    link_digest: &'a str,
    next_after_digest: &'a Option<String>,
    provenance: &'a EvidenceProvenance,
}

impl SystemLogReceipt {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        provider_revision: impl Into<String>,
        request: &SystemLogWindowRequest,
        events: Vec<SystemLogEvent>,
        availability: LogAvailability,
        pages: usize,
        response_bytes: usize,
        link_digest: impl Into<String>,
        next_after: Option<SystemLogCursor>,
        provenance: EvidenceProvenance,
    ) -> Result<Self, ModelError> {
        let provider_revision = provider_revision.into();
        let link_digest = link_digest.into();
        let next_after_digest = next_after.as_ref().map(SystemLogCursor::digest);
        if validate_identifier(&provider_revision, "provider revision").is_err()
            || pages == 0
            || response_bytes > MAX_RESPONSE_BYTES
            || !validate_digest(&request.scope_digest)
            || !validate_digest(&link_digest)
        {
            return Err(invalid("System Log receipt", "invalid bounded receipt"));
        }
        for event in &events {
            event.verify_integrity()?;
        }
        let mut receipt = Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision,
            scope_digest: request.scope_digest.clone(),
            window_digest: request.window_digest(),
            mode: request.mode.clone(),
            events,
            availability,
            pages,
            response_bytes,
            link_digest,
            next_after_digest,
            provenance,
            receipt_digest: String::new(),
            next_after,
        };
        receipt.receipt_digest = receipt.compute_digest();
        Ok(receipt)
    }

    fn compute_digest(&self) -> String {
        canonical_digest(&SystemLogReceiptDigestInput {
            provider_id: &self.provider_id,
            provider_revision: &self.provider_revision,
            scope_digest: &self.scope_digest,
            window_digest: &self.window_digest,
            mode: &self.mode,
            events: &self.events,
            availability: &self.availability,
            pages: self.pages,
            response_bytes: self.response_bytes,
            link_digest: &self.link_digest,
            next_after_digest: &self.next_after_digest,
            provenance: &self.provenance,
        })
        .expect("System Log receipt digest serialization")
    }

    pub fn verify_integrity(&self) -> Result<(), ModelError> {
        validate_identifier(&self.provider_revision, "provider revision")
            .map_err(|reason| invalid("provider revision", reason))?;
        if !validate_digest(&self.scope_digest)
            || !validate_digest(&self.window_digest)
            || !validate_digest(&self.link_digest)
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self
                .next_after_digest
                .as_ref()
                .is_some_and(|digest| !validate_digest(digest))
        {
            return Err(ModelError::InvalidDigest);
        }
        if let Some(cursor) = &self.next_after
            && self.next_after_digest.as_deref() != Some(cursor.digest().as_str())
        {
            return Err(ModelError::InvalidCursor);
        }
        if self
            .events
            .iter()
            .any(|event| event.verify_integrity().is_err())
            || self.provenance.validate().is_err()
        {
            return Err(ModelError::InvalidDigest);
        }
        if self.receipt_digest == self.compute_digest() {
            Ok(())
        } else {
            Err(ModelError::InvalidDigest)
        }
    }

    pub fn next_after(&self) -> Option<&SystemLogCursor> {
        self.next_after.as_ref()
    }

    pub fn is_supplemental_only(&self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssignmentTarget {
    User(OktaUserId),
    Group(OktaGroupId),
}

impl AssignmentTarget {
    fn validate(&self) -> Result<(), ModelError> {
        match self {
            Self::User(id) => id.validate(),
            Self::Group(id) => id.validate(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessChangeOperation {
    Assign {
        application_id: OktaApplicationId,
        target: AssignmentTarget,
    },
    Unassign {
        application_id: OktaApplicationId,
        target: AssignmentTarget,
    },
    AccessReview {
        application_id: Option<OktaApplicationId>,
    },
}

impl AccessChangeOperation {
    fn validate(&self) -> Result<(), ModelError> {
        match self {
            Self::Assign {
                application_id,
                target,
            }
            | Self::Unassign {
                application_id,
                target,
            } => {
                application_id.validate()?;
                target.validate()
            }
            Self::AccessReview { application_id } => {
                if let Some(application_id) = application_id {
                    application_id.validate()?;
                }
                Ok(())
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccessChangeProposal {
    pub proposal_version: String,
    pub capability_id: String,
    pub provider_id: String,
    pub project_id: String,
    pub mission_id: String,
    pub mission_revision: u64,
    pub consent: ConsentReference,
    pub scope_digest: String,
    pub expected_snapshot_digest: String,
    pub operation: AccessChangeOperation,
    pub non_mutating: bool,
    pub provider_execution: bool,
    pub requires_layer2_effect: bool,
    pub fingerprint: String,
}

#[derive(Serialize)]
struct ProposalDigestInput<'a> {
    proposal_version: &'a str,
    capability_id: &'a str,
    provider_id: &'a str,
    project_id: &'a str,
    mission_id: &'a str,
    mission_revision: u64,
    consent: &'a ConsentReference,
    scope_digest: &'a str,
    expected_snapshot_digest: &'a str,
    operation: &'a AccessChangeOperation,
    non_mutating: bool,
    provider_execution: bool,
    requires_layer2_effect: bool,
}

impl AccessChangeProposal {
    pub(crate) fn new(
        scope: &OktaScope,
        operation: AccessChangeOperation,
        expected_snapshot_digest: impl Into<String>,
    ) -> Result<Self, ModelError> {
        let expected_snapshot_digest = expected_snapshot_digest.into();
        scope.validate()?;
        operation.validate()?;
        if !validate_digest(&expected_snapshot_digest) {
            return Err(ModelError::InvalidDigest);
        }
        let mut proposal = Self {
            proposal_version: "okta-access-change-proposal/v1".to_owned(),
            capability_id: CAPABILITY_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            project_id: scope.project_id.clone(),
            mission_id: scope.mission_id.clone(),
            mission_revision: scope.mission_revision,
            consent: scope.consent.clone(),
            scope_digest: scope.digest(),
            expected_snapshot_digest,
            operation,
            non_mutating: true,
            provider_execution: false,
            requires_layer2_effect: true,
            fingerprint: String::new(),
        };
        proposal.fingerprint = canonical_digest(&ProposalDigestInput {
            proposal_version: &proposal.proposal_version,
            capability_id: &proposal.capability_id,
            provider_id: &proposal.provider_id,
            project_id: &proposal.project_id,
            mission_id: &proposal.mission_id,
            mission_revision: proposal.mission_revision,
            consent: &proposal.consent,
            scope_digest: &proposal.scope_digest,
            expected_snapshot_digest: &proposal.expected_snapshot_digest,
            operation: &proposal.operation,
            non_mutating: proposal.non_mutating,
            provider_execution: proposal.provider_execution,
            requires_layer2_effect: proposal.requires_layer2_effect,
        })
        .expect("access proposal fingerprint serialization");
        Ok(proposal)
    }

    pub fn is_non_mutating(&self) -> bool {
        self.non_mutating && !self.provider_execution
    }

    pub fn verify_integrity(&self) -> Result<(), ModelError> {
        self.operation.validate()?;
        if self.proposal_version != "okta-access-change-proposal/v1"
            || self.capability_id != CAPABILITY_ID
            || self.provider_id != PROVIDER_ID
            || validate_identifier(&self.project_id, "project id").is_err()
            || validate_identifier(&self.mission_id, "mission id").is_err()
            || self.mission_revision == 0
            || !validate_digest(&self.scope_digest)
            || !validate_digest(&self.expected_snapshot_digest)
            || !validate_digest(&self.fingerprint)
            || !self.non_mutating
            || self.provider_execution
            || !self.requires_layer2_effect
        {
            return Err(ModelError::InvalidDigest);
        }
        if self.fingerprint
            != canonical_digest(&ProposalDigestInput {
                proposal_version: &self.proposal_version,
                capability_id: &self.capability_id,
                provider_id: &self.provider_id,
                project_id: &self.project_id,
                mission_id: &self.mission_id,
                mission_revision: self.mission_revision,
                consent: &self.consent,
                scope_digest: &self.scope_digest,
                expected_snapshot_digest: &self.expected_snapshot_digest,
                operation: &self.operation,
                non_mutating: self.non_mutating,
                provider_execution: self.provider_execution,
                requires_layer2_effect: self.requires_layer2_effect,
            })
            .map_err(|_| invalid("proposal", "cannot serialize"))?
        {
            return Err(ModelError::InvalidDigest);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntitlementEvidenceStatus {
    DirectReadAuthoritative,
    DirectReadWithSupplementalLog,
    DirectReadWithLogUnavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EntitlementEvidenceProposal {
    pub evidence_version: String,
    pub scope_digest: String,
    pub project_id: String,
    pub mission_id: String,
    pub mission_revision: u64,
    pub consent: ConsentReference,
    pub snapshot: EntitlementSnapshot,
    pub supplemental_system_log: Option<SystemLogReceipt>,
    pub status: EntitlementEvidenceStatus,
    pub current_state_source: String,
    pub system_log_is_supplemental: bool,
    pub connected: bool,
    pub native: bool,
    pub evidence_digest: String,
}

#[derive(Serialize)]
struct EvidenceDigestInput<'a> {
    evidence_version: &'a str,
    scope_digest: &'a str,
    project_id: &'a str,
    mission_id: &'a str,
    mission_revision: u64,
    consent: &'a ConsentReference,
    snapshot_digest: &'a str,
    supplemental_receipt_digest: &'a Option<SystemLogReceipt>,
    status: EntitlementEvidenceStatus,
    current_state_source: &'a str,
    system_log_is_supplemental: bool,
}

impl EntitlementEvidenceProposal {
    pub(crate) fn new(
        snapshot: EntitlementSnapshot,
        supplemental_system_log: Option<SystemLogReceipt>,
        status: EntitlementEvidenceStatus,
    ) -> Result<Self, ModelError> {
        snapshot.verify_integrity()?;
        if let Some(receipt) = &supplemental_system_log {
            receipt.verify_integrity()?;
            if receipt.scope_digest != snapshot.scope.digest() {
                return Err(ModelError::InvalidDigest);
            }
        }
        let mut proposal = Self {
            evidence_version: "okta-entitlement-evidence/v1".to_owned(),
            scope_digest: snapshot.scope.digest(),
            project_id: snapshot.scope.project_id.clone(),
            mission_id: snapshot.scope.mission_id.clone(),
            mission_revision: snapshot.scope.mission_revision,
            consent: snapshot.scope.consent.clone(),
            snapshot,
            supplemental_system_log,
            status,
            current_state_source: "direct_entitlement_read".to_owned(),
            system_log_is_supplemental: true,
            connected: false,
            native: false,
            evidence_digest: String::new(),
        };
        proposal.evidence_digest = canonical_digest(&EvidenceDigestInput {
            evidence_version: &proposal.evidence_version,
            scope_digest: &proposal.scope_digest,
            project_id: &proposal.project_id,
            mission_id: &proposal.mission_id,
            mission_revision: proposal.mission_revision,
            consent: &proposal.consent,
            snapshot_digest: &proposal.snapshot.snapshot_digest,
            supplemental_receipt_digest: &proposal.supplemental_system_log,
            status: proposal.status,
            current_state_source: &proposal.current_state_source,
            system_log_is_supplemental: proposal.system_log_is_supplemental,
        })
        .expect("entitlement evidence digest serialization");
        Ok(proposal)
    }

    pub fn verify_integrity(&self) -> Result<(), ModelError> {
        self.snapshot.verify_integrity()?;
        if let Some(receipt) = &self.supplemental_system_log {
            receipt.verify_integrity()?;
        }
        let expected = canonical_digest(&EvidenceDigestInput {
            evidence_version: &self.evidence_version,
            scope_digest: &self.scope_digest,
            project_id: &self.project_id,
            mission_id: &self.mission_id,
            mission_revision: self.mission_revision,
            consent: &self.consent,
            snapshot_digest: &self.snapshot.snapshot_digest,
            supplemental_receipt_digest: &self.supplemental_system_log,
            status: self.status,
            current_state_source: &self.current_state_source,
            system_log_is_supplemental: self.system_log_is_supplemental,
        })
        .map_err(|_| invalid("entitlement evidence", "cannot serialize"))?;
        if self.evidence_digest == expected
            && self.scope_digest == self.snapshot.scope.digest()
            && self.project_id == self.snapshot.scope.project_id
            && self.mission_id == self.snapshot.scope.mission_id
            && self.mission_revision == self.snapshot.scope.mission_revision
            && self.consent == self.snapshot.scope.consent
            && self.current_state_source == "direct_entitlement_read"
            && self.system_log_is_supplemental
            && !self.connected
            && !self.native
        {
            Ok(())
        } else {
            Err(ModelError::InvalidDigest)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationProbe {
    pub registration_digest: String,
    pub grant_receipt: GrantReceipt,
    pub external_evidence_available: bool,
    pub connected: bool,
    pub native: bool,
    pub evidence_digest: String,
}

impl RegistrationProbe {
    pub(crate) fn new(
        registration: &CapabilityRegistration,
        grant_receipt: GrantReceipt,
    ) -> Result<Self, ModelError> {
        grant_receipt.verify_integrity()?;
        let evidence_digest = digest_parts(&[
            &registration.registration_digest,
            &grant_receipt.receipt_digest,
            &grant_receipt.provenance.source_digest,
        ]);
        Ok(Self {
            registration_digest: registration.registration_digest.clone(),
            grant_receipt,
            external_evidence_available: true,
            connected: false,
            native: false,
            evidence_digest,
        })
    }
}

impl OktaGroupRecord {
    fn validate(&self) -> Result<(), ModelError> {
        Self::new(self.id.clone(), self.membership_digest.clone()).map(|_| ())
    }
}

impl OktaApplicationRecord {
    fn validate(&self) -> Result<(), ModelError> {
        Self::new(
            self.id.clone(),
            self.status.clone(),
            self.configuration_digest.clone(),
        )
        .map(|_| ())
    }
}

impl OktaUserRecord {
    fn validate(&self) -> Result<(), ModelError> {
        Self::new(
            self.id.clone(),
            self.status.clone(),
            self.profile_digest.clone(),
        )
        .map(|_| ())
    }
}

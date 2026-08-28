//! Exact Octopus/Mission/Project/Consent scope and bounded redacted models.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::{
    MAX_IDENTIFIER_BYTES, MAX_ITEMS_PER_COLLECTION, MAX_METADATA_BYTES, MAX_STATE_BYTES,
    MAX_TARGETS, OctopusReleaseResultError, digest_serialized_with_domain, sha256_hex,
    validate_identifier, validate_text,
};

/// A validated lower-case SHA-256 identity.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn parse(value: impl Into<String>) -> Result<Self, OctopusReleaseResultError> {
        let value = value.into().to_ascii_lowercase();
        if crate::valid_digest(&value) {
            Ok(Self(value))
        } else {
            Err(OctopusReleaseResultError::InvalidDigest {
                field: "SHA-256 digest",
            })
        }
    }

    pub fn from_text(value: &str) -> Result<Self, OctopusReleaseResultError> {
        Self::parse(sha256_hex(value.as_bytes()))
    }

    pub fn from_parts(domain: &str, fields: impl IntoIterator<Item = (String, String)>) -> Self {
        let mut input = String::from(domain);
        for (name, value) in fields {
            input.push('\0');
            input.push_str(&name);
            input.push('=');
            input.push_str(&value);
        }
        Self::from_text(&input).expect("digest domain values are valid")
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<(), OctopusReleaseResultError> {
        if crate::valid_digest(&self.0) {
            Ok(())
        } else {
            Err(OctopusReleaseResultError::InvalidDigest {
                field: "SHA-256 digest",
            })
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

impl FromStr for Digest {
    type Err = OctopusReleaseResultError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// Opaque provider identifiers.  The identifier itself is not a secret, but
/// it is kept bounded and never accepted as an arbitrary URL or script.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Identifier(String);

impl Identifier {
    pub fn parse(value: impl Into<String>) -> Result<Self, OctopusReleaseResultError> {
        let value = value.into();
        validate_identifier(&value, "opaque provider identifier")?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Identifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Identifier").field(&self.0).finish()
    }
}

impl fmt::Display for Identifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for Identifier {
    type Err = OctopusReleaseResultError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// Semantic plugin version used by the registration fence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServerScope {
    pub origin: String,
    pub revision: u64,
}

impl ServerScope {
    pub fn new(
        origin: impl Into<String>,
        revision: u64,
    ) -> Result<Self, OctopusReleaseResultError> {
        let origin = origin.into();
        validate_text(&origin, "server origin", MAX_IDENTIFIER_BYTES, false)?;
        let Some(rest) = origin.strip_prefix("https://") else {
            return Err(OctopusReleaseResultError::InvalidServerOrigin);
        };
        if rest.is_empty()
            || rest.contains('/')
            || rest.contains('?')
            || rest.contains('#')
            || rest.contains('@')
        {
            return Err(OctopusReleaseResultError::InvalidServerOrigin);
        }
        if revision == 0 {
            return Err(OctopusReleaseResultError::InvalidScope);
        }
        Ok(Self { origin, revision })
    }
}

macro_rules! simple_scope {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        pub struct $name {
            pub id: Identifier,
            pub revision: u64,
        }

        impl $name {
            pub fn new(
                id: impl Into<String>,
                revision: u64,
            ) -> Result<Self, OctopusReleaseResultError> {
                if revision == 0 {
                    return Err(OctopusReleaseResultError::InvalidScope);
                }
                Ok(Self {
                    id: Identifier::parse(id.into())?,
                    revision,
                })
            }

            pub fn validate(&self) -> Result<(), OctopusReleaseResultError> {
                if self.revision == 0 {
                    return Err(OctopusReleaseResultError::InvalidScope);
                }
                validate_identifier(self.id.as_str(), $field)
            }
        }
    };
}

simple_scope!(SpaceScope, "space id");
simple_scope!(ChannelScope, "channel id");
simple_scope!(EnvironmentScope, "environment id");
simple_scope!(TargetScope, "deployment target id");

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeploymentScope {
    pub id: Identifier,
    pub task_id: Identifier,
    pub revision: u64,
}

impl DeploymentScope {
    pub fn new(
        id: impl Into<String>,
        task_id: impl Into<String>,
        revision: u64,
    ) -> Result<Self, OctopusReleaseResultError> {
        if revision == 0 {
            return Err(OctopusReleaseResultError::InvalidScope);
        }
        Ok(Self {
            id: Identifier::parse(id.into())?,
            task_id: Identifier::parse(task_id.into())?,
            revision,
        })
    }

    pub fn validate(&self) -> Result<(), OctopusReleaseResultError> {
        if self.revision == 0 {
            return Err(OctopusReleaseResultError::InvalidScope);
        }
        validate_identifier(self.id.as_str(), "deployment id")?;
        validate_identifier(self.task_id.as_str(), "task id")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OctopusProjectScope {
    pub id: Identifier,
    pub revision: u64,
    pub deployment_process_id: Identifier,
}

impl OctopusProjectScope {
    pub fn new(
        id: impl Into<String>,
        revision: u64,
        deployment_process_id: impl Into<String>,
    ) -> Result<Self, OctopusReleaseResultError> {
        if revision == 0 {
            return Err(OctopusReleaseResultError::InvalidScope);
        }
        Ok(Self {
            id: Identifier::parse(id.into())?,
            revision,
            deployment_process_id: Identifier::parse(deployment_process_id.into())?,
        })
    }

    pub fn validate(&self) -> Result<(), OctopusReleaseResultError> {
        if self.revision == 0 {
            return Err(OctopusReleaseResultError::InvalidScope);
        }
        validate_identifier(self.id.as_str(), "project id")?;
        validate_identifier(self.deployment_process_id.as_str(), "deployment process id")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseScope {
    pub id: Identifier,
    pub version: Identifier,
    pub revision: u64,
}

impl ReleaseScope {
    pub fn new(
        id: impl Into<String>,
        version: impl Into<String>,
        revision: u64,
    ) -> Result<Self, OctopusReleaseResultError> {
        if revision == 0 {
            return Err(OctopusReleaseResultError::InvalidScope);
        }
        Ok(Self {
            id: Identifier::parse(id.into())?,
            version: Identifier::parse(version.into())?,
            revision,
        })
    }

    pub fn validate(&self) -> Result<(), OctopusReleaseResultError> {
        if self.revision == 0 {
            return Err(OctopusReleaseResultError::InvalidScope);
        }
        validate_identifier(self.id.as_str(), "release id")?;
        validate_identifier(self.version.as_str(), "release version")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TenantScope {
    pub id: Option<Identifier>,
    pub revision: u64,
}

impl TenantScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, OctopusReleaseResultError> {
        if revision == 0 {
            return Err(OctopusReleaseResultError::InvalidScope);
        }
        Ok(Self {
            id: Some(Identifier::parse(id.into())?),
            revision,
        })
    }

    pub fn untenanted(revision: u64) -> Result<Self, OctopusReleaseResultError> {
        if revision == 0 {
            return Err(OctopusReleaseResultError::InvalidScope);
        }
        Ok(Self { id: None, revision })
    }

    pub fn validate(&self) -> Result<(), OctopusReleaseResultError> {
        if self.revision == 0 {
            return Err(OctopusReleaseResultError::InvalidScope);
        }
        self.id
            .as_ref()
            .map_or(Ok(()), |id| validate_identifier(id.as_str(), "tenant id"))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionScope {
    pub id: Identifier,
    pub revision: u64,
}

impl MissionScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, OctopusReleaseResultError> {
        if revision == 0 {
            return Err(OctopusReleaseResultError::InvalidScope);
        }
        Ok(Self {
            id: Identifier::parse(id.into())?,
            revision,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectScope {
    pub id: Identifier,
    pub revision: u64,
}

impl ProjectScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, OctopusReleaseResultError> {
        if revision == 0 {
            return Err(OctopusReleaseResultError::InvalidScope);
        }
        Ok(Self {
            id: Identifier::parse(id.into())?,
            revision,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentScope {
    pub id: Identifier,
    pub revision: u64,
    pub decision_digest: Digest,
}

impl ConsentScope {
    pub fn new(
        id: impl Into<String>,
        revision: u64,
        decision_digest: Digest,
    ) -> Result<Self, OctopusReleaseResultError> {
        if revision == 0 {
            return Err(OctopusReleaseResultError::InvalidScope);
        }
        decision_digest.validate()?;
        Ok(Self {
            id: Identifier::parse(id.into())?,
            revision,
            decision_digest,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OctopusScope {
    pub server: ServerScope,
    pub space: SpaceScope,
    pub project: OctopusProjectScope,
    pub channel: ChannelScope,
    pub release: ReleaseScope,
    pub environment: EnvironmentScope,
    pub tenant: TenantScope,
    pub deployment: DeploymentScope,
    pub target: TargetScope,
    pub mission: MissionScope,
    pub hartevo_project: ProjectScope,
    pub consent: ConsentScope,
}

impl OctopusScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server: ServerScope,
        space: SpaceScope,
        project: OctopusProjectScope,
        channel: ChannelScope,
        release: ReleaseScope,
        environment: EnvironmentScope,
        tenant: TenantScope,
        deployment: DeploymentScope,
        target: TargetScope,
        mission: MissionScope,
        hartevo_project: ProjectScope,
        consent: ConsentScope,
    ) -> Result<Self, OctopusReleaseResultError> {
        let scope = Self {
            server,
            space,
            project,
            channel,
            release,
            environment,
            tenant,
            deployment,
            target,
            mission,
            hartevo_project,
            consent,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), OctopusReleaseResultError> {
        ServerScope::new(self.server.origin.clone(), self.server.revision)?;
        self.space.validate()?;
        self.project.validate()?;
        self.channel.validate()?;
        self.release.validate()?;
        self.environment.validate()?;
        self.tenant.validate()?;
        self.deployment.validate()?;
        self.target.validate()?;
        if self.mission.revision == 0
            || self.hartevo_project.revision == 0
            || self.consent.revision == 0
        {
            return Err(OctopusReleaseResultError::InvalidScope);
        }
        self.consent.decision_digest.validate()?;
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        Digest::parse(digest_serialized_with_domain(
            "octopus-release-result/scope/v1",
            self,
        ))
        .expect("scope digest is valid")
    }

    pub fn octopus_project(&self) -> &OctopusProjectScope {
        &self.project
    }

    pub fn project_scope(&self) -> &ProjectScope {
        &self.hartevo_project
    }
}

const UNBOUND_SECRET_SCOPE: &str = "unbound-octopus-secret-scope";
const UNBOUND_SECRET_PERMISSION: &str = "unbound-octopus-secret-permission";

/// A SecretReference intentionally stores only a digest of its opaque handle.
/// No API key, OIDC token, or other raw material can be serialized from this
/// type; Layer 2 owns any future resolution boundary.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretReference {
    pub reference_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub revoked: bool,
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("permission_digest", &self.permission_digest)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl SecretReference {
    pub fn new(opaque_handle: impl AsRef<str>) -> Result<Self, OctopusReleaseResultError> {
        let handle = opaque_handle.as_ref();
        validate_text(
            handle,
            "opaque SecretReference",
            MAX_IDENTIFIER_BYTES,
            false,
        )?;
        Ok(Self {
            reference_digest: Digest::from_text(handle)?,
            scope_digest: Digest::from_text(UNBOUND_SECRET_SCOPE)?,
            permission_digest: Digest::from_text(UNBOUND_SECRET_PERMISSION)?,
            revoked: false,
        })
    }

    pub fn bind_to(
        mut self,
        scope: &OctopusScope,
        permissions: &PermissionSnapshot,
    ) -> Result<Self, OctopusReleaseResultError> {
        scope.validate()?;
        permissions.validate()?;
        self.scope_digest = scope.digest();
        self.permission_digest = permissions.digest.clone();
        Ok(self)
    }

    pub fn is_bound_to(&self, scope: &OctopusScope, permissions: &PermissionSnapshot) -> bool {
        self.scope_digest == scope.digest() && self.permission_digest == permissions.digest
    }

    pub fn revoke(&mut self) -> Result<(), OctopusReleaseResultError> {
        if self.revoked {
            return Err(OctopusReleaseResultError::SecretRevoked);
        }
        self.revoked = true;
        Ok(())
    }
}

pub const REQUIRED_READ_SCOPES: [&str; 13] = [
    "server.read",
    "space.read",
    "project.read",
    "channel.read",
    "release.read",
    "environment.read",
    "tenant.read",
    "deployment.read",
    "target.read",
    "task.read",
    "mission.scope",
    "project.scope",
    "consent.scope",
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionSnapshot {
    pub read_scopes: Vec<String>,
    pub write_scopes: Vec<String>,
    pub digest: Digest,
}

impl PermissionSnapshot {
    pub fn read_only() -> Self {
        let mut read_scopes = REQUIRED_READ_SCOPES
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        read_scopes.sort();
        let digest = Self::calculate_digest(&read_scopes, &[]);
        Self {
            read_scopes,
            write_scopes: Vec::new(),
            digest,
        }
    }

    pub fn new(
        mut read_scopes: Vec<String>,
        mut write_scopes: Vec<String>,
    ) -> Result<Self, OctopusReleaseResultError> {
        read_scopes.sort();
        read_scopes.dedup();
        write_scopes.sort();
        write_scopes.dedup();
        let snapshot = Self {
            digest: Self::calculate_digest(&read_scopes, &write_scopes),
            read_scopes,
            write_scopes,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn validate(&self) -> Result<(), OctopusReleaseResultError> {
        let mut expected = REQUIRED_READ_SCOPES
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        expected.sort();
        if self.read_scopes != expected
            || !self.write_scopes.is_empty()
            || self.digest != Self::calculate_digest(&self.read_scopes, &self.write_scopes)
        {
            return Err(OctopusReleaseResultError::InvalidPermissionSnapshot);
        }
        Ok(())
    }

    fn calculate_digest(read_scopes: &[String], write_scopes: &[String]) -> Digest {
        Digest::from_parts(
            "octopus-release-result/permissions/v1",
            [
                (
                    "read".to_owned(),
                    serde_json::to_string(read_scopes).unwrap(),
                ),
                (
                    "write".to_owned(),
                    serde_json::to_string(write_scopes).unwrap(),
                ),
            ],
        )
    }
}

/// Typed provider payloads accepted by fixture/recording/loopback transports.
/// They contain only bounded metadata; no raw task log, script, package byte,
/// URL, token, variable value, or tenant mutation body is representable.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpacePayload {
    pub id: String,
    pub name: String,
    pub revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectPayload {
    pub id: String,
    pub name: String,
    pub deployment_process_id: String,
    pub revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelPayload {
    pub id: String,
    pub project_id: String,
    pub name: String,
    pub revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnvironmentPayload {
    pub id: String,
    pub name: String,
    pub revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TenantPayload {
    pub id: String,
    pub name: String,
    pub revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleasePayload {
    pub id: String,
    pub project_id: String,
    pub channel_id: String,
    pub version: String,
    pub selected_package_count: usize,
    pub revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeploymentProcessPayload {
    pub id: String,
    pub project_id: String,
    pub step_count: usize,
    pub action_count: usize,
    pub revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeploymentProcessTemplatePayload {
    pub process_id: String,
    pub project_id: String,
    pub channel_id: String,
    pub package_count: usize,
    pub revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeploymentPayload {
    pub id: String,
    pub release_id: String,
    pub project_id: String,
    pub environment_id: String,
    pub tenant_id: Option<String>,
    pub task_id: String,
    pub state: String,
    pub target_ids: Vec<String>,
    pub revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskPayload {
    pub id: String,
    pub deployment_id: String,
    pub state: String,
    pub finished_successfully: Option<bool>,
    pub target_ids: Vec<String>,
    pub revision: u64,
}

pub(crate) fn validate_collection_len<T>(values: &[T]) -> Result<(), OctopusReleaseResultError> {
    if values.len() > MAX_ITEMS_PER_COLLECTION {
        Err(OctopusReleaseResultError::PaginationLimit)
    } else {
        Ok(())
    }
}

pub(crate) fn validate_payload_identifier(
    value: &str,
    field: &'static str,
) -> Result<(), OctopusReleaseResultError> {
    validate_identifier(value, field)
}

pub(crate) fn validate_payload_name(
    value: &str,
    field: &'static str,
) -> Result<(), OctopusReleaseResultError> {
    validate_text(value, field, MAX_METADATA_BYTES, true)
}

pub(crate) fn validate_payload_state(value: &str) -> Result<(), OctopusReleaseResultError> {
    validate_text(value, "provider state", MAX_STATE_BYTES, false)
}

pub(crate) fn validate_targets(values: &[String]) -> Result<(), OctopusReleaseResultError> {
    if values.len() > MAX_TARGETS {
        return Err(OctopusReleaseResultError::PaginationLimit);
    }
    for value in values {
        validate_payload_identifier(value, "deployment target id")?;
    }
    Ok(())
}

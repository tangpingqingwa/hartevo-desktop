//! Typed, bounded EventBridge Pipes scope and metadata models.
//!
//! Raw pipe/source/target strings are accepted only at construction time and
//! are represented in serialized evidence by digests. There is intentionally
//! no event-payload, target-data, filter-pattern, enrichment-configuration,
//! credential, or state-reason type in this module.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};

use crate::error::{AwsEventBridgePipeError, ErrorClassification, Result};
use crate::{LAYER1_PERMISSIONS, MAX_ARN_BYTES, MAX_IDENTIFIER_BYTES, MAX_PAGE_SIZE};

pub const MAX_PIPE_NAME_BYTES: usize = 64;
pub const MAX_FILTER_PREFIX_BYTES: usize = MAX_ARN_BYTES;
pub const MAX_CURSOR_BYTES: usize = 512;

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn from_parts(domain: &str, fields: &[(&str, String)]) -> Self {
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for (name, value) in fields {
            append_field(&mut bytes, name);
            append_field(&mut bytes, value);
        }
        Self::from_bytes(&bytes)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(AwsEventBridgePipeError::InvalidDigest)
        }
    }

    pub fn zero() -> Self {
        Self("0".repeat(64))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(AwsEventBridgePipeError::InvalidDigest)
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

fn valid_text(value: &str, max_bytes: usize, allow_internal_whitespace: bool) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && (allow_internal_whitespace || !value.chars().any(char::is_whitespace))
}

fn valid_identifier(value: &str, max_bytes: usize) -> bool {
    valid_text(value, max_bytes, false)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_arn(value: &str) -> bool {
    valid_text(value, MAX_ARN_BYTES, false) && value.starts_with("arn:")
}

macro_rules! identifier_type {
    ($name:ident, $field:literal, $max:expr, $validator:expr, $domain:literal) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if !($validator)(&value) {
                    return Err(AwsEventBridgePipeError::InvalidIdentifier { field: $field });
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts($domain, &[("value", self.0.clone())])
            }

            pub(crate) fn validate(&self) -> Result<()> {
                if ($validator)(&self.0) {
                    Ok(())
                } else {
                    Err(AwsEventBridgePipeError::InvalidIdentifier { field: $field })
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.digest())
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                let mut state = serializer.serialize_struct(stringify!($name), 1)?;
                state.serialize_field("digest", &self.digest())?;
                state.end()
            }
        }
    };
}

identifier_type!(
    AwsAccountId,
    "AWS account id",
    12,
    |value: &str| value.len() == 12 && value.bytes().all(|byte| byte.is_ascii_digit()),
    "aws-eventbridge-account/v1"
);
identifier_type!(
    AwsRegion,
    "AWS region",
    64,
    |value: &str| valid_identifier(value, 64),
    "aws-eventbridge-region/v1"
);
identifier_type!(
    PipeName,
    "pipe name",
    MAX_PIPE_NAME_BYTES,
    |value: &str| valid_identifier(value, MAX_PIPE_NAME_BYTES),
    "aws-eventbridge-pipe-name/v1"
);

/// An ARN is held only as an opaque in-memory input plus a digest in every
/// public projection. It has no serde representation of the raw ARN.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ArnReference {
    value: String,
    digest: Digest,
}

impl ArnReference {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if !valid_arn(&value) {
            return Err(AwsEventBridgePipeError::InvalidIdentifier { field: "ARN" });
        }
        let digest = Digest::from_parts("aws-eventbridge-arn/v1", &[("arn", value.clone())]);
        Ok(Self { value, digest })
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if valid_arn(&self.value) && self.digest == *Self::new(self.value.clone())?.digest() {
            Ok(())
        } else {
            Err(AwsEventBridgePipeError::InvalidIdentifier { field: "ARN" })
        }
    }
}

impl fmt::Debug for ArnReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArnReference")
            .field("digest", &self.digest)
            .finish()
    }
}

impl Serialize for ArnReference {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ArnReference", 1)?;
        state.serialize_field("digest", &self.digest)?;
        state.end()
    }
}

pub type PipeArn = ArnReference;
pub type SourceArn = ArnReference;
pub type TargetArn = ArnReference;

#[derive(Clone, Eq, PartialEq)]
pub struct PipeIdentity {
    name: PipeName,
    arn: PipeArn,
}

impl PipeIdentity {
    pub fn new(name: PipeName, arn: PipeArn) -> Result<Self> {
        let identity = Self { name, arn };
        identity.validate()?;
        Ok(identity)
    }

    pub fn name(&self) -> &PipeName {
        &self.name
    }

    pub fn arn(&self) -> &PipeArn {
        &self.arn
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-eventbridge-pipe-identity/v1",
            &[
                ("name", self.name.digest().as_str().to_owned()),
                ("arn", self.arn.digest().as_str().to_owned()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.name.validate()?;
        self.arn.validate()
    }
}

impl fmt::Debug for PipeIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PipeIdentity")
            .field("digest", &self.digest())
            .finish()
    }
}

impl Serialize for PipeIdentity {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("PipeIdentity", 2)?;
        state.serialize_field("nameDigest", &self.name.digest())?;
        state.serialize_field("arnDigest", self.arn.digest())?;
        state.end()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 {
            Err(AwsEventBridgePipeError::InvalidScope)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct MissionIdentity {
    id: String,
    revision: Revision,
}

impl MissionIdentity {
    pub fn new(id: impl Into<String>, revision: Revision) -> Result<Self> {
        let id = id.into();
        if !valid_identifier(&id, MAX_IDENTIFIER_BYTES) {
            return Err(AwsEventBridgePipeError::InvalidScope);
        }
        Ok(Self { id, revision })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-eventbridge-mission/v1",
            &[
                ("id", self.id.clone()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if valid_identifier(&self.id, MAX_IDENTIFIER_BYTES) {
            Ok(())
        } else {
            Err(AwsEventBridgePipeError::InvalidScope)
        }
    }
}

impl fmt::Debug for MissionIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionIdentity")
            .field("digest", &self.digest())
            .field("revision", &self.revision)
            .finish()
    }
}

impl Serialize for MissionIdentity {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("MissionIdentity", 2)?;
        state.serialize_field("idDigest", &self.digest())?;
        state.serialize_field("revision", &self.revision)?;
        state.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ProjectIdentity {
    id: String,
    revision: Revision,
}

impl ProjectIdentity {
    pub fn new(id: impl Into<String>, revision: Revision) -> Result<Self> {
        let id = id.into();
        if !valid_identifier(&id, MAX_IDENTIFIER_BYTES) {
            return Err(AwsEventBridgePipeError::InvalidScope);
        }
        Ok(Self { id, revision })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-eventbridge-project/v1",
            &[
                ("id", self.id.clone()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if valid_identifier(&self.id, MAX_IDENTIFIER_BYTES) {
            Ok(())
        } else {
            Err(AwsEventBridgePipeError::InvalidScope)
        }
    }
}

impl fmt::Debug for ProjectIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProjectIdentity")
            .field("digest", &self.digest())
            .field("revision", &self.revision)
            .finish()
    }
}

impl Serialize for ProjectIdentity {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ProjectIdentity", 2)?;
        state.serialize_field("idDigest", &self.digest())?;
        state.serialize_field("revision", &self.revision)?;
        state.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AwsEventBridgePipeScope {
    account: AwsAccountId,
    region: AwsRegion,
    pipe: PipeIdentity,
    source: SourceArn,
    target: TargetArn,
    mission: MissionIdentity,
    project: ProjectIdentity,
}

impl AwsEventBridgePipeScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: AwsAccountId,
        region: AwsRegion,
        pipe: PipeIdentity,
        source: SourceArn,
        target: TargetArn,
        mission: MissionIdentity,
        project: ProjectIdentity,
    ) -> Result<Self> {
        let scope = Self {
            account,
            region,
            pipe,
            source,
            target,
            mission,
            project,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn account(&self) -> &AwsAccountId {
        &self.account
    }

    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn pipe(&self) -> &PipeIdentity {
        &self.pipe
    }

    pub fn source(&self) -> &SourceArn {
        &self.source
    }

    pub fn target(&self) -> &TargetArn {
        &self.target
    }

    pub fn mission(&self) -> &MissionIdentity {
        &self.mission
    }

    pub fn project(&self) -> &ProjectIdentity {
        &self.project
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-eventbridge-pipe-scope/v1",
            &[
                ("account", self.account.digest().as_str().to_owned()),
                ("region", self.region.digest().as_str().to_owned()),
                ("pipe", self.pipe.digest().as_str().to_owned()),
                ("source", self.source.digest().as_str().to_owned()),
                ("target", self.target.digest().as_str().to_owned()),
                ("mission", self.mission.digest().as_str().to_owned()),
                ("project", self.project.digest().as_str().to_owned()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.account.validate()?;
        self.region.validate()?;
        self.pipe.validate()?;
        self.source.validate()?;
        self.target.validate()?;
        self.mission.validate()?;
        self.project.validate()?;
        Ok(())
    }
}

impl fmt::Debug for AwsEventBridgePipeScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsEventBridgePipeScope")
            .field("digest", &self.digest())
            .finish()
    }
}

impl Serialize for AwsEventBridgePipeScope {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("AwsEventBridgePipeScope", 7)?;
        state.serialize_field("accountDigest", &self.account.digest())?;
        state.serialize_field("regionDigest", &self.region.digest())?;
        state.serialize_field("pipeDigest", &self.pipe.digest())?;
        state.serialize_field("sourceArnDigest", self.source.digest())?;
        state.serialize_field("targetArnDigest", self.target.digest())?;
        state.serialize_field("missionDigest", &self.mission.digest())?;
        state.serialize_field("projectDigest", &self.project.digest())?;
        state.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct PermissionSnapshot {
    revision: Revision,
    permissions: BTreeSet<String>,
    digest: Digest,
}

impl PermissionSnapshot {
    pub fn for_layer_one(revision: u64) -> Result<Self> {
        Self::new(
            revision,
            LAYER1_PERMISSIONS
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect(),
        )
    }

    pub fn new(revision: u64, permissions: Vec<String>) -> Result<Self> {
        let revision = Revision::new(revision)?;
        let set = permissions.into_iter().collect::<BTreeSet<_>>();
        if set.is_empty()
            || set.iter().any(|permission| {
                !LAYER1_PERMISSIONS
                    .iter()
                    .any(|allowed| allowed == permission)
            })
        {
            return Err(AwsEventBridgePipeError::InvalidPermissionSnapshot);
        }
        let mut snapshot = Self {
            revision,
            permissions: set,
            digest: Digest::zero(),
        };
        snapshot.digest = snapshot.recomputed_digest();
        Ok(snapshot)
    }

    pub fn revision(&self) -> Revision {
        self.revision
    }

    pub fn permissions(&self) -> &BTreeSet<String> {
        &self.permissions
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn is_layer_one_read_only(&self) -> bool {
        self.permissions
            .iter()
            .all(|permission| LAYER1_PERMISSIONS.contains(&permission.as_str()))
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.revision.get() == 0
            || self.permissions.is_empty()
            || !self.is_layer_one_read_only()
            || self.digest != self.recomputed_digest()
        {
            Err(AwsEventBridgePipeError::InvalidPermissionSnapshot)
        } else {
            Ok(())
        }
    }

    fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-eventbridge-pipe-permissions/v1",
            &[
                ("revision", self.revision.get().to_string()),
                (
                    "permissions",
                    self.permissions
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
            ],
        )
    }
}

impl fmt::Debug for PermissionSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PermissionSnapshot")
            .field("revision", &self.revision)
            .field("permission_digest", &self.digest)
            .finish()
    }
}

impl Serialize for PermissionSnapshot {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("PermissionSnapshot", 2)?;
        state.serialize_field("revision", &self.revision)?;
        state.serialize_field("permissionDigest", &self.digest)?;
        state.end()
    }
}

/// A SecretReference is reduced to a digest at construction. The supplied
/// reference string is never retained, serialized, or emitted in Debug.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    digest: Digest,
    region: AwsRegion,
}

impl SecretReference {
    pub fn for_pipes(reference: impl AsRef<str>, region: &AwsRegion) -> Result<Self> {
        let value = reference.as_ref();
        if !valid_text(value, MAX_IDENTIFIER_BYTES, false) {
            return Err(AwsEventBridgePipeError::InvalidSecretReference);
        }
        Ok(Self {
            digest: Digest::from_parts(
                "hartevo-aws-eventbridge-pipes-sigv4-secret/v1",
                &[
                    ("service", "pipes".to_owned()),
                    ("region", region.as_str().to_owned()),
                    ("reference", value.to_owned()),
                ],
            ),
            region: region.clone(),
        })
    }

    pub fn for_scope(reference: impl AsRef<str>, scope: &AwsEventBridgePipeScope) -> Result<Self> {
        let value = reference.as_ref();
        if !valid_text(value, MAX_IDENTIFIER_BYTES, false) {
            return Err(AwsEventBridgePipeError::InvalidSecretReference);
        }
        Ok(Self {
            digest: Digest::from_parts(
                "hartevo-aws-eventbridge-pipes-sigv4-secret-scope/v1",
                &[
                    ("service", "pipes".to_owned()),
                    ("region", scope.region().as_str().to_owned()),
                    ("scope", scope.digest().as_str().to_owned()),
                    ("reference", value.to_owned()),
                ],
            ),
            region: scope.region().clone(),
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub const fn signing_service(&self) -> &'static str {
        "pipes"
    }

    pub fn signing_region(&self) -> &AwsRegion {
        &self.region
    }

    pub const fn is_opaque(&self) -> bool {
        true
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.region.validate()?;
        self.digest.validate()
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("value", &"<opaque>")
            .field("signing_service", &self.signing_service())
            .field("signing_region", &self.region)
            .field("digest", &self.digest)
            .finish()
    }
}

impl Serialize for SecretReference {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("SecretReference", 1)?;
        state.serialize_field("opaque", &true)?;
        state.end()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    #[serde(rename = "BLOCKED_ENV")]
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn connected(self) -> bool {
        false
    }

    pub const fn native(self) -> bool {
        false
    }

    pub const fn first_party(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CurrentPipeState {
    Running,
    Stopped,
    Creating,
    Updating,
    Starting,
    Stopping,
    Deleting,
    CreateFailed,
    UpdateFailed,
    StartFailed,
    StopFailed,
    DeleteFailed,
    Unknown,
}

impl CurrentPipeState {
    pub fn parse_api(value: &str) -> Result<Self> {
        match value {
            "RUNNING" => Ok(Self::Running),
            "STOPPED" => Ok(Self::Stopped),
            "CREATING" => Ok(Self::Creating),
            "UPDATING" => Ok(Self::Updating),
            "STARTING" => Ok(Self::Starting),
            "STOPPING" => Ok(Self::Stopping),
            "DELETING" => Ok(Self::Deleting),
            "CREATE_FAILED" => Ok(Self::CreateFailed),
            "UPDATE_FAILED" => Ok(Self::UpdateFailed),
            "START_FAILED" => Ok(Self::StartFailed),
            "STOP_FAILED" => Ok(Self::StopFailed),
            "DELETE_FAILED" => Ok(Self::DeleteFailed),
            "UNKNOWN" => Ok(Self::Unknown),
            _ => Err(AwsEventBridgePipeError::InvalidIdentifier {
                field: "current pipe state",
            }),
        }
    }

    pub const fn is_failed(self) -> bool {
        matches!(
            self,
            Self::CreateFailed
                | Self::UpdateFailed
                | Self::StartFailed
                | Self::StopFailed
                | Self::DeleteFailed
        )
    }

    pub const fn evidence_state(self) -> PipeEvidenceState {
        match self {
            Self::Running => PipeEvidenceState::Running,
            Self::Stopped => PipeEvidenceState::Stopped,
            Self::Creating => PipeEvidenceState::Creating,
            Self::Updating => PipeEvidenceState::Updating,
            Self::Starting => PipeEvidenceState::Starting,
            Self::Stopping => PipeEvidenceState::Stopping,
            Self::Deleting => PipeEvidenceState::Deleting,
            Self::CreateFailed
            | Self::UpdateFailed
            | Self::StartFailed
            | Self::StopFailed
            | Self::DeleteFailed
            | Self::Unknown => PipeEvidenceState::Failed,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DesiredPipeState {
    Running,
    Stopped,
    Deleted,
}

impl DesiredPipeState {
    pub fn parse_api(value: &str) -> Result<Self> {
        match value {
            "RUNNING" => Ok(Self::Running),
            "STOPPED" => Ok(Self::Stopped),
            "DELETED" => Ok(Self::Deleted),
            _ => Err(AwsEventBridgePipeError::InvalidIdentifier {
                field: "desired pipe state",
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PipeEvidenceState {
    Running,
    Stopped,
    Creating,
    Updating,
    Starting,
    Stopping,
    Deleting,
    Failed,
    NotFound,
    Partial,
    AccessLoss,
    Throttled,
    ProviderUnknown,
    RegistrationRevoked,
}

impl PipeEvidenceState {
    pub const fn is_non_adoptable(self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub list_digest: Digest,
    pub describe_digest: Option<Digest>,
    pub cursor_digest: Option<Digest>,
    pub evidence_digest: Digest,
}

impl EvidenceDigests {
    pub fn new(
        provider_digest: Digest,
        permission_digest: Digest,
        scope_digest: Digest,
        secret_reference_digest: Digest,
        list_digest: Digest,
        describe_digest: Option<Digest>,
        cursor_digest: Option<Digest>,
    ) -> Self {
        Self {
            plugin_version_digest: Digest::from_text(crate::PLUGIN_VERSION),
            contract_digest: crate::contract_digest(),
            provider_digest,
            permission_digest,
            scope_digest,
            secret_reference_digest,
            list_digest,
            describe_digest,
            cursor_digest,
            evidence_digest: Digest::zero(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.plugin_version_digest.validate()?;
        self.contract_digest.validate()?;
        self.provider_digest.validate()?;
        self.permission_digest.validate()?;
        self.scope_digest.validate()?;
        self.secret_reference_digest.validate()?;
        self.list_digest.validate()?;
        if let Some(digest) = &self.describe_digest {
            digest.validate()?;
        }
        if let Some(digest) = &self.cursor_digest {
            digest.validate()?;
        }
        self.evidence_digest.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionProjection {
    pub id_digest: Digest,
    pub revision: Revision,
}

impl From<&MissionIdentity> for MissionProjection {
    fn from(value: &MissionIdentity) -> Self {
        Self {
            id_digest: value.digest(),
            revision: value.revision,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectProjection {
    pub id_digest: Digest,
    pub revision: Revision,
}

impl From<&ProjectIdentity> for ProjectProjection {
    fn from(value: &ProjectIdentity) -> Self {
        Self {
            id_digest: value.digest(),
            revision: value.revision,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct PipeListFilter {
    scope_digest: Digest,
    name_prefix: Option<String>,
    source_prefix: Option<String>,
    target_prefix: Option<String>,
    current_state: Option<CurrentPipeState>,
    desired_state: Option<DesiredPipeState>,
    limit: u16,
}

impl PipeListFilter {
    pub fn for_scope(scope: &AwsEventBridgePipeScope, limit: u16) -> Result<Self> {
        Self::new(
            scope,
            Some(scope.pipe.name().as_str().to_owned()),
            Some(scope.source().as_str().to_owned()),
            Some(scope.target().as_str().to_owned()),
            None,
            None,
            limit,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: &AwsEventBridgePipeScope,
        name_prefix: Option<String>,
        source_prefix: Option<String>,
        target_prefix: Option<String>,
        current_state: Option<CurrentPipeState>,
        desired_state: Option<DesiredPipeState>,
        limit: u16,
    ) -> Result<Self> {
        if limit == 0 || limit > MAX_PAGE_SIZE {
            return Err(AwsEventBridgePipeError::InvalidRequest);
        }
        for (value, field) in [
            (name_prefix.as_deref(), "pipe name prefix"),
            (source_prefix.as_deref(), "source ARN prefix"),
            (target_prefix.as_deref(), "target ARN prefix"),
        ] {
            if let Some(value) = value
                && !valid_text(value, MAX_FILTER_PREFIX_BYTES, false)
            {
                return Err(AwsEventBridgePipeError::InvalidText { field });
            }
        }
        let filter = Self {
            scope_digest: scope.digest(),
            name_prefix,
            source_prefix,
            target_prefix,
            current_state,
            desired_state,
            limit,
        };
        filter.validate_against(scope)?;
        Ok(filter)
    }

    pub fn with_states(
        &self,
        current_state: Option<CurrentPipeState>,
        desired_state: Option<DesiredPipeState>,
    ) -> Self {
        let mut filter = self.clone();
        filter.current_state = current_state;
        filter.desired_state = desired_state;
        filter
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn name_prefix(&self) -> Option<&str> {
        self.name_prefix.as_deref()
    }

    pub fn source_prefix(&self) -> Option<&str> {
        self.source_prefix.as_deref()
    }

    pub fn target_prefix(&self) -> Option<&str> {
        self.target_prefix.as_deref()
    }

    pub const fn current_state(&self) -> Option<CurrentPipeState> {
        self.current_state
    }

    pub const fn desired_state(&self) -> Option<DesiredPipeState> {
        self.desired_state
    }

    pub const fn limit(&self) -> u16 {
        self.limit
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-eventbridge-pipe-list-filter/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("name_prefix", self.name_prefix.clone().unwrap_or_default()),
                (
                    "source_prefix",
                    self.source_prefix.clone().unwrap_or_default(),
                ),
                (
                    "target_prefix",
                    self.target_prefix.clone().unwrap_or_default(),
                ),
                (
                    "current_state",
                    self.current_state
                        .map_or_else(String::new, |state| format!("{state:?}")),
                ),
                (
                    "desired_state",
                    self.desired_state
                        .map_or_else(String::new, |state| format!("{state:?}")),
                ),
                ("limit", self.limit.to_string()),
            ],
        )
    }

    pub(crate) fn validate_against(&self, scope: &AwsEventBridgePipeScope) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self
                .name_prefix
                .as_deref()
                .is_some_and(|prefix| !scope.pipe.name().as_str().starts_with(prefix))
            || self
                .source_prefix
                .as_deref()
                .is_some_and(|prefix| !scope.source().as_str().starts_with(prefix))
            || self
                .target_prefix
                .as_deref()
                .is_some_and(|prefix| !scope.target().as_str().starts_with(prefix))
            || self.limit == 0
            || self.limit > MAX_PAGE_SIZE
        {
            Err(AwsEventBridgePipeError::FilterMismatch)
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for PipeListFilter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PipeListFilter")
            .field("digest", &self.digest())
            .field("current_state", &self.current_state)
            .field("desired_state", &self.desired_state)
            .field("limit", &self.limit)
            .finish()
    }
}

impl Serialize for PipeListFilter {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("PipeListFilter", 5)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("filterDigest", &self.digest())?;
        state.serialize_field("currentState", &self.current_state)?;
        state.serialize_field("desiredState", &self.desired_state)?;
        state.serialize_field("limit", &self.limit)?;
        state.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct Cursor {
    token_digest: Digest,
    scope_digest: Digest,
    filter_digest: Digest,
    page_number: u16,
}

impl Cursor {
    pub fn new(
        value: impl AsRef<str>,
        scope: &AwsEventBridgePipeScope,
        filter: &PipeListFilter,
        page_number: u16,
    ) -> Result<Self> {
        let value = value.as_ref();
        if value.is_empty() || value.len() > MAX_CURSOR_BYTES || value.chars().any(char::is_control)
        {
            return Err(AwsEventBridgePipeError::InvalidRequest);
        }
        if page_number == 0 {
            return Err(AwsEventBridgePipeError::InvalidRequest);
        }
        filter.validate_against(scope)?;
        Ok(Self {
            token_digest: Digest::from_parts(
                "aws-eventbridge-pipe-next-token/v1",
                &[("token", value.to_owned())],
            ),
            scope_digest: scope.digest(),
            filter_digest: filter.digest(),
            page_number,
        })
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn filter_digest(&self) -> &Digest {
        &self.filter_digest
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub fn validate_against(
        &self,
        scope: &AwsEventBridgePipeScope,
        filter: &PipeListFilter,
    ) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self.filter_digest != filter.digest()
            || self.page_number == 0
        {
            Err(AwsEventBridgePipeError::CursorMismatch)
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for Cursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Cursor")
            .field("token_digest", &self.token_digest)
            .field("scope_digest", &self.scope_digest)
            .field("filter_digest", &self.filter_digest)
            .field("page_number", &self.page_number)
            .finish()
    }
}

impl Serialize for Cursor {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Cursor", 1)?;
        state.serialize_field("opaque", &true)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PipeSummary {
    pub pipe_name_digest: Digest,
    pub pipe_arn_digest: Digest,
    pub current_state: CurrentPipeState,
    pub desired_state: DesiredPipeState,
    pub creation_time: DateTime<Utc>,
    pub last_modified_time: DateTime<Utc>,
    pub error_classification: ErrorClassification,
}

impl PipeSummary {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pipe_name: impl Into<String>,
        pipe_arn: impl Into<String>,
        current_state: CurrentPipeState,
        desired_state: DesiredPipeState,
        creation_time: DateTime<Utc>,
        last_modified_time: DateTime<Utc>,
        error_classification: ErrorClassification,
    ) -> Result<Self> {
        let pipe_name = PipeName::new(pipe_name)?;
        let pipe_arn = PipeArn::new(pipe_arn)?;
        if last_modified_time < creation_time {
            return Err(AwsEventBridgePipeError::InvalidRequest);
        }
        let summary = Self {
            pipe_name_digest: pipe_name.digest(),
            pipe_arn_digest: pipe_arn.digest().clone(),
            current_state,
            desired_state,
            creation_time,
            last_modified_time,
            error_classification,
        };
        summary.validate()?;
        Ok(summary)
    }

    pub fn matches_scope(&self, scope: &AwsEventBridgePipeScope) -> bool {
        self.pipe_name_digest == scope.pipe().name().digest()
            && self.pipe_arn_digest == *scope.pipe().arn().digest()
    }

    pub fn matches_name(&self, scope: &AwsEventBridgePipeScope) -> bool {
        self.pipe_name_digest == scope.pipe().name().digest()
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.pipe_name_digest.validate()?;
        self.pipe_arn_digest.validate()?;
        if self.last_modified_time < self.creation_time {
            return Err(AwsEventBridgePipeError::InvalidRequest);
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PipeDescription {
    pub pipe_name_digest: Digest,
    pub pipe_arn_digest: Digest,
    pub current_state: CurrentPipeState,
    pub desired_state: DesiredPipeState,
    pub source_arn_digest: Digest,
    pub target_arn_digest: Digest,
    pub creation_time: DateTime<Utc>,
    pub last_modified_time: DateTime<Utc>,
    pub enrichment_present: bool,
    pub filter_present: bool,
    pub error_classification: ErrorClassification,
}

impl PipeDescription {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pipe_name: impl Into<String>,
        pipe_arn: impl Into<String>,
        source_arn: impl Into<String>,
        target_arn: impl Into<String>,
        current_state: CurrentPipeState,
        desired_state: DesiredPipeState,
        creation_time: DateTime<Utc>,
        last_modified_time: DateTime<Utc>,
        enrichment_present: bool,
        filter_present: bool,
        error_classification: ErrorClassification,
    ) -> Result<Self> {
        let pipe_name = PipeName::new(pipe_name)?;
        let pipe_arn = PipeArn::new(pipe_arn)?;
        let source_arn = SourceArn::new(source_arn)?;
        let target_arn = TargetArn::new(target_arn)?;
        if last_modified_time < creation_time {
            return Err(AwsEventBridgePipeError::InvalidRequest);
        }
        let description = Self {
            pipe_name_digest: pipe_name.digest(),
            pipe_arn_digest: pipe_arn.digest().clone(),
            current_state,
            desired_state,
            source_arn_digest: source_arn.digest().clone(),
            target_arn_digest: target_arn.digest().clone(),
            creation_time,
            last_modified_time,
            enrichment_present,
            filter_present,
            error_classification,
        };
        description.validate_basic()?;
        Ok(description)
    }

    pub fn for_scope(
        scope: &AwsEventBridgePipeScope,
        current_state: CurrentPipeState,
        desired_state: DesiredPipeState,
        creation_time: DateTime<Utc>,
        last_modified_time: DateTime<Utc>,
        enrichment_present: bool,
        filter_present: bool,
        error_classification: ErrorClassification,
    ) -> Result<Self> {
        Self::new(
            scope.pipe().name().as_str(),
            scope.pipe().arn().as_str(),
            scope.source().as_str(),
            scope.target().as_str(),
            current_state,
            desired_state,
            creation_time,
            last_modified_time,
            enrichment_present,
            filter_present,
            error_classification,
        )
    }

    pub fn pipe_matches_scope(&self, scope: &AwsEventBridgePipeScope) -> bool {
        self.pipe_name_digest == scope.pipe().name().digest()
            && self.pipe_arn_digest == *scope.pipe().arn().digest()
    }

    pub fn source_target_match_scope(&self, scope: &AwsEventBridgePipeScope) -> bool {
        self.source_arn_digest == *scope.source().digest()
            && self.target_arn_digest == *scope.target().digest()
    }

    pub(crate) fn validate_basic(&self) -> Result<()> {
        self.pipe_name_digest.validate()?;
        self.pipe_arn_digest.validate()?;
        self.source_arn_digest.validate()?;
        self.target_arn_digest.validate()?;
        if self.last_modified_time < self.creation_time {
            return Err(AwsEventBridgePipeError::InvalidRequest);
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }
}

pub(crate) fn digest_serialized<T: Serialize>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("all contract models serialize");
    Digest::from_bytes(&bytes)
}

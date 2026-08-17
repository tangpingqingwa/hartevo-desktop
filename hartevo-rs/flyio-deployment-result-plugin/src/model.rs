use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer};
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::Zeroize;

use crate::error::{FlyioDeploymentResultError, Result};
use crate::{
    API_REVISION, CONTRACT_DIGEST, CONTRACT_VERSION, MAX_RECENT_EVENTS, MAX_SERVICE_PORTS,
    PLUGIN_VERSION,
};

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(sha256_hex(bytes))
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
            Err(FlyioDeploymentResultError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(FlyioDeploymentResultError::InvalidDigest)
        }
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

fn append_field(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
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

fn valid_identifier(value: &str, max_bytes: usize, allow_internal_whitespace: bool) -> bool {
    valid_text(value, max_bytes, allow_internal_whitespace)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal, $max:expr, $whitespace:expr) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if valid_identifier(&value, $max, $whitespace) {
                    Ok(Self(value))
                } else {
                    Err(FlyioDeploymentResultError::InvalidIdentifier { field: $field })
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    concat!("flyio-", $field, "/v1"),
                    &[("value", self.0.clone())],
                )
            }

            pub(crate) fn validate(&self) -> Result<()> {
                if valid_identifier(&self.0, $max, $whitespace) {
                    Ok(())
                } else {
                    Err(FlyioDeploymentResultError::InvalidIdentifier { field: $field })
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&format!("{}:{}", $field, &self.digest().as_str()[..16]))
                    .finish()
            }
        }
    };
}

bounded_identifier!(OrganizationName, "organization", 128, false);
bounded_identifier!(AppId, "app-id", 128, false);
bounded_identifier!(AppName, "app-name", 128, false);
bounded_identifier!(MachineId, "machine-id", 128, false);
bounded_identifier!(InstanceId, "instance-id", 256, false);
bounded_identifier!(ReleaseId, "release-id", 256, false);
bounded_identifier!(Region, "region", 64, false);
bounded_identifier!(ProcessGroup, "process-group", 128, false);
bounded_identifier!(ProjectId, "project-id", 256, false);
bounded_identifier!(MissionId, "mission-id", 256, false);
bounded_identifier!(WorkProductId, "work-product-id", 256, false);

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ImageDigest(String);

impl ImageDigest {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        let valid = value.len() == 71
            && value.starts_with("sha256:")
            && value[7..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if valid {
            Ok(Self(value))
        } else {
            Err(FlyioDeploymentResultError::InvalidImageDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts("flyio-image-digest/v1", &[("image", self.0.clone())])
    }

    pub(crate) fn validate(&self) -> Result<()> {
        Self::new(self.0.clone()).map(|_| ())
    }
}

impl fmt::Debug for ImageDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ImageDigest")
            .field(&format!("sha256:{}", &self.digest().as_str()[..16]))
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppIdentity {
    id: AppId,
    name: AppName,
}

impl AppIdentity {
    pub fn new(id: AppId, name: AppName) -> Result<Self> {
        let identity = Self { id, name };
        identity.validate()?;
        Ok(identity)
    }

    pub fn id(&self) -> &AppId {
        &self.id
    }

    pub fn name(&self) -> &AppName {
        &self.name
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "flyio-app-identity/v1",
            &[
                ("id", self.id.digest().as_str().to_owned()),
                ("name", self.name.digest().as_str().to_owned()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.id.validate()?;
        self.name.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlyioDeploymentScope {
    organization: OrganizationName,
    app: AppIdentity,
    machine_id: MachineId,
    instance_id: InstanceId,
    release_id: ReleaseId,
    image_digest: ImageDigest,
    region: Region,
    process_group: ProcessGroup,
    project_id: ProjectId,
    project_revision: u64,
    mission_id: MissionId,
    mission_revision: u64,
    work_product_id: WorkProductId,
    work_product_revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlyioDeploymentScopeInput {
    pub organization: String,
    pub app_id: String,
    pub app_name: String,
    pub machine_id: String,
    pub instance_id: String,
    pub release_id: String,
    pub image_digest: String,
    pub region: String,
    pub process_group: String,
    pub project_id: String,
    pub project_revision: u64,
    pub mission_id: String,
    pub mission_revision: u64,
    pub work_product_id: String,
    pub work_product_revision: u64,
}

impl FlyioDeploymentScope {
    pub fn new(input: FlyioDeploymentScopeInput) -> Result<Self> {
        let scope = Self {
            organization: OrganizationName::new(input.organization)?,
            app: AppIdentity::new(AppId::new(input.app_id)?, AppName::new(input.app_name)?)?,
            machine_id: MachineId::new(input.machine_id)?,
            instance_id: InstanceId::new(input.instance_id)?,
            release_id: ReleaseId::new(input.release_id)?,
            image_digest: ImageDigest::new(input.image_digest)?,
            region: Region::new(input.region)?,
            process_group: ProcessGroup::new(input.process_group)?,
            project_id: ProjectId::new(input.project_id)?,
            project_revision: input.project_revision,
            mission_id: MissionId::new(input.mission_id)?,
            mission_revision: input.mission_revision,
            work_product_id: WorkProductId::new(input.work_product_id)?,
            work_product_revision: input.work_product_revision,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn organization(&self) -> &OrganizationName {
        &self.organization
    }

    pub fn app(&self) -> &AppIdentity {
        &self.app
    }

    pub fn machine_id(&self) -> &MachineId {
        &self.machine_id
    }

    pub fn instance_id(&self) -> &InstanceId {
        &self.instance_id
    }

    pub fn release_id(&self) -> &ReleaseId {
        &self.release_id
    }

    pub fn image_digest(&self) -> &ImageDigest {
        &self.image_digest
    }

    pub fn region(&self) -> &Region {
        &self.region
    }

    pub fn process_group(&self) -> &ProcessGroup {
        &self.process_group
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub const fn project_revision(&self) -> u64 {
        self.project_revision
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub const fn mission_revision(&self) -> u64 {
        self.mission_revision
    }

    pub fn work_product_id(&self) -> &WorkProductId {
        &self.work_product_id
    }

    pub const fn work_product_revision(&self) -> u64 {
        self.work_product_revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "flyio-deployment-scope/v1",
            &[
                (
                    "organization",
                    self.organization.digest().as_str().to_owned(),
                ),
                ("app", self.app.digest().as_str().to_owned()),
                ("machine", self.machine_id.digest().as_str().to_owned()),
                ("instance", self.instance_id.digest().as_str().to_owned()),
                ("release", self.release_id.digest().as_str().to_owned()),
                ("image", self.image_digest.digest().as_str().to_owned()),
                ("region", self.region.digest().as_str().to_owned()),
                (
                    "process_group",
                    self.process_group.digest().as_str().to_owned(),
                ),
                ("project", self.project_id.digest().as_str().to_owned()),
                ("project_revision", self.project_revision.to_string()),
                ("mission", self.mission_id.digest().as_str().to_owned()),
                ("mission_revision", self.mission_revision.to_string()),
                (
                    "work_product",
                    self.work_product_id.digest().as_str().to_owned(),
                ),
                (
                    "work_product_revision",
                    self.work_product_revision.to_string(),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.organization.validate()?;
        self.app.validate()?;
        self.machine_id.validate()?;
        self.instance_id.validate()?;
        self.release_id.validate()?;
        self.image_digest.validate()?;
        self.region.validate()?;
        self.process_group.validate()?;
        self.project_id.validate()?;
        self.mission_id.validate()?;
        self.work_product_id.validate()?;
        if self.project_revision == 0
            || self.mission_revision == 0
            || self.work_product_revision == 0
        {
            return Err(FlyioDeploymentResultError::InvalidScope);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MachineState {
    Created,
    Starting,
    Started,
    Stopping,
    Stopped,
    Suspended,
    Destroyed,
    Replaced,
}

impl MachineState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "CREATED",
            Self::Starting => "STARTING",
            Self::Started => "STARTED",
            Self::Stopping => "STOPPING",
            Self::Stopped => "STOPPED",
            Self::Suspended => "SUSPENDED",
            Self::Destroyed => "DESTROYED",
            Self::Replaced => "REPLACED",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Created,
    Starting,
    Started,
    Stopping,
    Stopped,
    Suspended,
    Destroyed,
    Replaced,
    Partial,
    AccessLost,
    ProviderUnknown,
    Tampered,
    Revoked,
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    Throttled,
    ServerError,
    TimedOut,
    ScopeDrift,
    StaleMission,
    PaginationLoop,
}

impl From<MachineState> for EvidenceState {
    fn from(state: MachineState) -> Self {
        match state {
            MachineState::Created => Self::Created,
            MachineState::Starting => Self::Starting,
            MachineState::Started => Self::Started,
            MachineState::Stopping => Self::Stopping,
            MachineState::Stopped => Self::Stopped,
            MachineState::Suspended => Self::Suspended,
            MachineState::Destroyed => Self::Destroyed,
            MachineState::Replaced => Self::Replaced,
        }
    }
}

impl EvidenceState {
    pub const fn is_adoptable(self) -> bool {
        false
    }

    pub const fn is_fail_closed(self) -> bool {
        !matches!(
            self,
            Self::Created
                | Self::Starting
                | Self::Started
                | Self::Stopping
                | Self::Stopped
                | Self::Suspended
                | Self::Destroyed
                | Self::Replaced
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RestartPolicySummary {
    pub policy_digest: Digest,
    pub max_retries: Option<u16>,
}

impl RestartPolicySummary {
    pub fn new(policy: impl Into<String>, max_retries: Option<u16>) -> Result<Self> {
        let policy = policy.into();
        if !valid_identifier(&policy, 64, false) {
            return Err(FlyioDeploymentResultError::InvalidText {
                field: "restart-policy",
            });
        }
        Ok(Self {
            policy_digest: Digest::from_parts("flyio-restart-policy/v1", &[("policy", policy)]),
            max_retries,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServicePortMetadata {
    pub port: u16,
    pub protocol_digest: Digest,
    pub handlers_digest: Digest,
}

impl ServicePortMetadata {
    pub fn new(
        port: u16,
        protocol: impl Into<String>,
        handlers: impl Into<String>,
    ) -> Result<Self> {
        let protocol = protocol.into();
        let handlers = handlers.into();
        if port == 0
            || !valid_identifier(&protocol, 32, false)
            || !valid_identifier(&handlers, 128, false)
        {
            return Err(FlyioDeploymentResultError::InvalidText {
                field: "service-port-metadata",
            });
        }
        Ok(Self {
            port,
            protocol_digest: Digest::from_text(protocol),
            handlers_digest: Digest::from_text(handlers),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecentEvent {
    pub event_type_digest: Digest,
    pub status_digest: Digest,
    pub occurred_at: DateTime<Utc>,
}

impl RecentEvent {
    pub fn new(
        event_type: impl Into<String>,
        status: impl Into<String>,
        occurred_at: DateTime<Utc>,
    ) -> Result<Self> {
        let event_type = event_type.into();
        let status = status.into();
        if !valid_identifier(&event_type, 128, false) || !valid_identifier(&status, 128, false) {
            return Err(FlyioDeploymentResultError::InvalidText {
                field: "recent-event",
            });
        }
        Ok(Self {
            event_type_digest: Digest::from_text(event_type),
            status_digest: Digest::from_text(status),
            occurred_at,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppEvidence {
    app_id_digest: Digest,
    app_name_digest: Digest,
    organization_digest: Digest,
    status_digest: Digest,
    machine_count: u16,
    release_digest: Option<Digest>,
    response_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppEvidenceInput {
    pub app_id: String,
    pub app_name: String,
    pub organization: String,
    pub status: String,
    pub machine_count: u16,
    pub release_id: Option<String>,
    pub response_digest: Digest,
}

impl AppEvidence {
    pub fn new(input: AppEvidenceInput) -> Result<Self> {
        let app_id = AppId::new(input.app_id)?;
        let app_name = AppName::new(input.app_name)?;
        let organization = OrganizationName::new(input.organization)?;
        let status = if valid_identifier(&input.status, 128, false) {
            input.status
        } else {
            return Err(FlyioDeploymentResultError::InvalidText {
                field: "app-status",
            });
        };
        let release_digest = input
            .release_id
            .map(|value| ReleaseId::new(value).map(|release| release.digest()))
            .transpose()?;
        input.response_digest.validate()?;
        Ok(Self {
            app_id_digest: app_id.digest(),
            app_name_digest: app_name.digest(),
            organization_digest: organization.digest(),
            status_digest: Digest::from_text(status),
            machine_count: input.machine_count,
            release_digest,
            response_digest: input.response_digest,
        })
    }

    pub fn for_scope(
        scope: &FlyioDeploymentScope,
        status: impl Into<String>,
        machine_count: u16,
    ) -> Self {
        Self {
            app_id_digest: scope.app.id.digest(),
            app_name_digest: scope.app.name.digest(),
            organization_digest: scope.organization.digest(),
            status_digest: Digest::from_text(status.into()),
            machine_count,
            release_digest: Some(scope.release_id.digest()),
            response_digest: Digest::from_text("fixture-app-response"),
        }
    }

    pub fn app_digest(&self) -> Digest {
        Digest::from_parts(
            "flyio-app-evidence/v1",
            &[
                ("id", self.app_id_digest.as_str().to_owned()),
                ("name", self.app_name_digest.as_str().to_owned()),
                ("organization", self.organization_digest.as_str().to_owned()),
                ("status", self.status_digest.as_str().to_owned()),
                ("machine_count", self.machine_count.to_string()),
                (
                    "release",
                    self.release_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                ("response", self.response_digest.as_str().to_owned()),
            ],
        )
    }

    pub fn app_id_digest(&self) -> &Digest {
        &self.app_id_digest
    }

    pub fn app_name_digest(&self) -> &Digest {
        &self.app_name_digest
    }

    pub fn organization_digest(&self) -> &Digest {
        &self.organization_digest
    }

    pub fn status_digest(&self) -> &Digest {
        &self.status_digest
    }

    pub const fn machine_count(&self) -> u16 {
        self.machine_count
    }

    pub fn release_digest(&self) -> Option<&Digest> {
        self.release_digest.as_ref()
    }

    pub fn response_digest(&self) -> &Digest {
        &self.response_digest
    }

    pub fn matches_scope(&self, scope: &FlyioDeploymentScope) -> bool {
        self.app_id_digest == scope.app.id.digest()
            && self.app_name_digest == scope.app.name.digest()
            && self.organization_digest == scope.organization.digest()
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.app_id_digest.validate()?;
        self.app_name_digest.validate()?;
        self.organization_digest.validate()?;
        self.status_digest.validate()?;
        self.release_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.response_digest.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachineEvidence {
    machine_id_digest: Digest,
    instance_id_digest: Digest,
    release_id_digest: Digest,
    image_digest: Digest,
    state: MachineState,
    region_digest: Digest,
    process_group_digest: Digest,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    restart_policy: RestartPolicySummary,
    service_ports: Vec<ServicePortMetadata>,
    recent_events: Vec<RecentEvent>,
    state_sequence: u64,
    configuration_digest: Digest,
    response_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachineEvidenceInput {
    pub machine_id: String,
    pub instance_id: String,
    pub release_id: String,
    pub image_digest: String,
    pub state: MachineState,
    pub region: String,
    pub process_group: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub restart_policy: RestartPolicySummary,
    pub service_ports: Vec<ServicePortMetadata>,
    pub recent_events: Vec<RecentEvent>,
    pub state_sequence: u64,
    pub configuration_digest: Digest,
    pub response_digest: Digest,
}

impl MachineEvidence {
    pub fn new(input: MachineEvidenceInput) -> Result<Self> {
        let machine_id = MachineId::new(input.machine_id)?;
        let instance_id = InstanceId::new(input.instance_id)?;
        let release_id = ReleaseId::new(input.release_id)?;
        let image_digest = ImageDigest::new(input.image_digest)?;
        let region = Region::new(input.region)?;
        let process_group = ProcessGroup::new(input.process_group)?;
        if input.state_sequence == 0
            || input.service_ports.len() > MAX_SERVICE_PORTS
            || input.recent_events.len() > MAX_RECENT_EVENTS
            || input.updated_at < input.created_at
        {
            return Err(FlyioDeploymentResultError::InvalidResponse);
        }
        input.configuration_digest.validate()?;
        input.response_digest.validate()?;
        Ok(Self {
            machine_id_digest: machine_id.digest(),
            instance_id_digest: instance_id.digest(),
            release_id_digest: release_id.digest(),
            image_digest: image_digest.digest(),
            state: input.state,
            region_digest: region.digest(),
            process_group_digest: process_group.digest(),
            created_at: input.created_at,
            updated_at: input.updated_at,
            restart_policy: input.restart_policy,
            service_ports: input.service_ports,
            recent_events: input.recent_events,
            state_sequence: input.state_sequence,
            configuration_digest: input.configuration_digest,
            response_digest: input.response_digest,
        })
    }

    pub fn for_scope(
        scope: &FlyioDeploymentScope,
        state: MachineState,
        state_sequence: u64,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> Result<Self> {
        Self::new(MachineEvidenceInput {
            machine_id: scope.machine_id.as_str().to_owned(),
            instance_id: scope.instance_id.as_str().to_owned(),
            release_id: scope.release_id.as_str().to_owned(),
            image_digest: scope.image_digest.as_str().to_owned(),
            state,
            region: scope.region.as_str().to_owned(),
            process_group: scope.process_group.as_str().to_owned(),
            created_at,
            updated_at,
            restart_policy: RestartPolicySummary::new("always", Some(3))?,
            service_ports: vec![ServicePortMetadata::new(443, "tcp", "http")?],
            recent_events: vec![RecentEvent::new("state", state.as_str(), updated_at)?],
            state_sequence,
            configuration_digest: Digest::from_text("fixture-machine-config"),
            response_digest: Digest::from_text("fixture-machine-response"),
        })
    }

    pub fn machine_digest(&self) -> Digest {
        Digest::from_parts(
            "flyio-machine-evidence/v1",
            &[
                ("machine", self.machine_id_digest.as_str().to_owned()),
                ("instance", self.instance_id_digest.as_str().to_owned()),
                ("release", self.release_id_digest.as_str().to_owned()),
                ("image", self.image_digest.as_str().to_owned()),
                ("state", self.state.as_str().to_owned()),
                ("region", self.region_digest.as_str().to_owned()),
                (
                    "process_group",
                    self.process_group_digest.as_str().to_owned(),
                ),
                ("created_at", self.created_at.to_rfc3339()),
                ("updated_at", self.updated_at.to_rfc3339()),
                (
                    "configuration",
                    self.configuration_digest.as_str().to_owned(),
                ),
                ("sequence", self.state_sequence.to_string()),
                ("response", self.response_digest.as_str().to_owned()),
            ],
        )
    }

    pub fn machine_id_digest(&self) -> &Digest {
        &self.machine_id_digest
    }

    pub fn instance_id_digest(&self) -> &Digest {
        &self.instance_id_digest
    }

    pub fn release_id_digest(&self) -> &Digest {
        &self.release_id_digest
    }

    pub fn image_digest(&self) -> &Digest {
        &self.image_digest
    }

    pub const fn state(&self) -> MachineState {
        self.state
    }

    pub fn region_digest(&self) -> &Digest {
        &self.region_digest
    }

    pub fn process_group_digest(&self) -> &Digest {
        &self.process_group_digest
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    pub fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }

    pub fn restart_policy(&self) -> &RestartPolicySummary {
        &self.restart_policy
    }

    pub fn service_ports(&self) -> &[ServicePortMetadata] {
        &self.service_ports
    }

    pub fn recent_events(&self) -> &[RecentEvent] {
        &self.recent_events
    }

    pub const fn state_sequence(&self) -> u64 {
        self.state_sequence
    }

    pub fn configuration_digest(&self) -> &Digest {
        &self.configuration_digest
    }

    pub fn result_digest(&self) -> Digest {
        Digest::from_parts(
            "flyio-machine-result/v1",
            &[
                ("machine", self.machine_digest().as_str().to_owned()),
                ("events", self.recent_events.len().to_string()),
                ("ports", self.service_ports.len().to_string()),
            ],
        )
    }

    pub fn response_digest(&self) -> &Digest {
        &self.response_digest
    }

    pub fn matches_scope(&self, scope: &FlyioDeploymentScope) -> bool {
        self.machine_id_digest == scope.machine_id.digest()
            && self.instance_id_digest == scope.instance_id.digest()
            && self.release_id_digest == scope.release_id.digest()
            && self.image_digest == scope.image_digest.digest()
            && self.region_digest == scope.region.digest()
            && self.process_group_digest == scope.process_group.digest()
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.machine_id_digest.validate()?;
        self.instance_id_digest.validate()?;
        self.release_id_digest.validate()?;
        self.image_digest.validate()?;
        self.region_digest.validate()?;
        self.process_group_digest.validate()?;
        self.configuration_digest.validate()?;
        self.response_digest.validate()?;
        if self.state_sequence == 0
            || self.service_ports.len() > MAX_SERVICE_PORTS
            || self.recent_events.len() > MAX_RECENT_EVENTS
            || self.updated_at < self.created_at
        {
            return Err(FlyioDeploymentResultError::InvalidResponse);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppProjection {
    pub app_id_digest: Digest,
    pub app_name_digest: Digest,
    pub organization_digest: Digest,
    pub status_digest: Digest,
    pub machine_count: u16,
    pub app_digest: Digest,
}

impl From<&AppEvidence> for AppProjection {
    fn from(app: &AppEvidence) -> Self {
        Self {
            app_id_digest: app.app_id_digest.clone(),
            app_name_digest: app.app_name_digest.clone(),
            organization_digest: app.organization_digest.clone(),
            status_digest: app.status_digest.clone(),
            machine_count: app.machine_count,
            app_digest: app.app_digest(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MachineProjection {
    pub machine_id_digest: Digest,
    pub instance_id_digest: Digest,
    pub release_id_digest: Digest,
    pub image_digest: Digest,
    pub state: MachineState,
    pub region_digest: Digest,
    pub process_group_digest: Digest,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub restart_policy: RestartPolicySummary,
    pub service_ports: Vec<ServicePortMetadata>,
    pub recent_events: Vec<RecentEvent>,
    pub state_sequence: u64,
    pub configuration_digest: Digest,
    pub result_digest: Digest,
    pub machine_digest: Digest,
}

impl From<&MachineEvidence> for MachineProjection {
    fn from(machine: &MachineEvidence) -> Self {
        Self {
            machine_id_digest: machine.machine_id_digest.clone(),
            instance_id_digest: machine.instance_id_digest.clone(),
            release_id_digest: machine.release_id_digest.clone(),
            image_digest: machine.image_digest.clone(),
            state: machine.state,
            region_digest: machine.region_digest.clone(),
            process_group_digest: machine.process_group_digest.clone(),
            created_at: machine.created_at,
            updated_at: machine.updated_at,
            restart_policy: machine.restart_policy.clone(),
            service_ports: machine.service_ports.clone(),
            recent_events: machine.recent_events.clone(),
            state_sequence: machine.state_sequence,
            configuration_digest: machine.configuration_digest.clone(),
            result_digest: machine.result_digest(),
            machine_digest: machine.machine_digest(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectProjection {
    pub id_digest: Digest,
    pub revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionProjection {
    pub id_digest: Digest,
    pub revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductProjection {
    pub id_digest: Digest,
    pub revision: u64,
}

pub fn project_projection(scope: &FlyioDeploymentScope) -> ProjectProjection {
    ProjectProjection {
        id_digest: scope.project_id.digest(),
        revision: scope.project_revision,
    }
}

pub fn mission_projection(scope: &FlyioDeploymentScope) -> MissionProjection {
    MissionProjection {
        id_digest: scope.mission_id.digest(),
        revision: scope.mission_revision,
    }
}

pub fn work_product_projection(scope: &FlyioDeploymentScope) -> WorkProductProjection {
    WorkProductProjection {
        id_digest: scope.work_product_id.digest(),
        revision: scope.work_product_revision,
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Recording => "recording",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "blocked_env",
        }
    }

    pub const fn connected(&self) -> bool {
        false
    }

    pub const fn native(&self) -> bool {
        false
    }

    pub const fn first_party(&self) -> bool {
        false
    }

    pub const fn provider_receipt(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionSnapshot {
    pub permissions: BTreeSet<String>,
}

impl PermissionSnapshot {
    pub fn baseline() -> Self {
        Self {
            permissions: BTreeSet::from([
                "fly.apps.read".to_owned(),
                "fly.machines.read".to_owned(),
                "fly.releases.read".to_owned(),
                "mission.scope".to_owned(),
            ]),
        }
    }

    pub fn new(permissions: impl IntoIterator<Item = String>) -> Result<Self> {
        let snapshot = Self {
            permissions: permissions.into_iter().collect(),
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn digest(&self) -> Digest {
        let joined = self
            .permissions
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(",");
        Digest::from_parts("flyio-permissions/v1", &[("permissions", joined)])
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if *self != Self::baseline() {
            return Err(FlyioDeploymentResultError::InvalidPermissionSnapshot);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentScope {
    pub mission_id_digest: Digest,
    pub mission_revision: u64,
    pub permissions: BTreeSet<String>,
}

impl ConsentScope {
    pub fn for_scope(scope: &FlyioDeploymentScope) -> Self {
        Self {
            mission_id_digest: scope.mission_id.digest(),
            mission_revision: scope.mission_revision,
            permissions: PermissionSnapshot::baseline().permissions,
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "flyio-consent/v1",
            &[
                ("mission", self.mission_id_digest.as_str().to_owned()),
                ("revision", self.mission_revision.to_string()),
                (
                    "permissions",
                    self.permissions
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(","),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self, scope: &FlyioDeploymentScope) -> Result<()> {
        if self.mission_id_digest != scope.mission_id.digest()
            || self.mission_revision != scope.mission_revision
            || self.permissions != PermissionSnapshot::baseline().permissions
        {
            return Err(FlyioDeploymentResultError::InvalidConsent);
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    locator: String,
    revision: u64,
    scope_digest: Digest,
    reference_digest: Digest,
    revoked: bool,
}

impl SecretReference {
    pub fn new(
        locator: impl Into<String>,
        revision: u64,
        scope: &FlyioDeploymentScope,
    ) -> Result<Self> {
        let locator = locator.into();
        if !valid_text(&locator, 512, false) || revision == 0 {
            return Err(FlyioDeploymentResultError::InvalidSecretReference);
        }
        let scope_digest = scope.digest();
        let reference_digest = Digest::from_parts(
            "flyio-secret-reference/v1",
            &[
                ("locator", locator.clone()),
                ("revision", revision.to_string()),
                ("scope", scope_digest.as_str().to_owned()),
            ],
        );
        Ok(Self {
            locator,
            revision,
            scope_digest,
            reference_digest,
            revoked: false,
        })
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub(crate) fn validate(&self, scope: &FlyioDeploymentScope) -> Result<()> {
        if self.revoked
            || self.locator.is_empty()
            || self.revision == 0
            || self.scope_digest != scope.digest()
            || self.reference_digest
                != Digest::from_parts(
                    "flyio-secret-reference/v1",
                    &[
                        ("locator", self.locator.clone()),
                        ("revision", self.revision.to_string()),
                        ("scope", self.scope_digest.as_str().to_owned()),
                    ],
                )
        {
            return Err(if self.revoked {
                FlyioDeploymentResultError::SecretRevoked
            } else {
                FlyioDeploymentResultError::InvalidSecretReference
            });
        }
        Ok(())
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("revision", &self.revision)
            .field("scope_digest", &self.scope_digest)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl Drop for SecretReference {
    fn drop(&mut self) {
        self.locator.zeroize();
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestReceipt {
    pub operation: String,
    pub request_digest: Digest,
    pub path_digest: Digest,
    pub scope_digest: Digest,
    pub app_digest: Digest,
    pub machine_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub response_bytes: u64,
    pub redacted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CostReceipt {
    pub operation: String,
    pub response_bytes: u64,
    pub bounded_request_units: u32,
    pub cost_digest: Digest,
    pub estimate_only: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CostSummary {
    pub total_response_bytes: u64,
    pub total_request_units: u32,
    pub estimate_only: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub app_digest: Digest,
    pub machine_digest: Digest,
    pub instance_digest: Digest,
    pub image_digest: Digest,
    pub release_digest: Digest,
    pub evidence_digest: Digest,
}

impl EvidenceDigests {
    pub fn new(
        scope: &FlyioDeploymentScope,
        provider_digest: Digest,
        permission_digest: Digest,
        app_digest: Digest,
        machine_digest: Digest,
    ) -> Self {
        let instance_digest = scope.instance_id.digest();
        let image_digest = scope.image_digest.digest();
        let release_digest = scope.release_id.digest();
        let mut evidence = Self {
            plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_digest: Digest::parse(CONTRACT_DIGEST.to_owned())
                .unwrap_or_else(|_| Digest::from_text(CONTRACT_VERSION)),
            provider_digest,
            api_digest: Digest::from_text(API_REVISION),
            permission_digest,
            scope_digest: scope.digest(),
            app_digest,
            machine_digest,
            instance_digest,
            image_digest,
            release_digest,
            evidence_digest: Digest::from_text("unsealed-flyio-evidence"),
        };
        evidence.evidence_digest = evidence.calculate_digest();
        evidence
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "flyio-evidence-digests/v1",
            &[
                ("plugin", self.plugin_version_digest.as_str().to_owned()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("api", self.api_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("app", self.app_digest.as_str().to_owned()),
                ("machine", self.machine_digest.as_str().to_owned()),
                ("instance", self.instance_digest.as_str().to_owned()),
                ("image", self.image_digest.as_str().to_owned()),
                ("release", self.release_digest.as_str().to_owned()),
            ],
        )
    }

    pub fn validate(&self) -> Result<()> {
        for digest in [
            &self.plugin_version_digest,
            &self.contract_digest,
            &self.provider_digest,
            &self.api_digest,
            &self.permission_digest,
            &self.scope_digest,
            &self.app_digest,
            &self.machine_digest,
            &self.instance_digest,
            &self.image_digest,
            &self.release_digest,
            &self.evidence_digest,
        ] {
            digest.validate()?;
        }
        if self.evidence_digest != self.calculate_digest() {
            return Err(FlyioDeploymentResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderReadEvidence {
    pub app: AppEvidence,
    pub machine: MachineEvidence,
    pub request_receipts: Vec<RequestReceipt>,
    pub cost_receipts: Vec<CostReceipt>,
    pub truncated: bool,
    pub provenance: TransportProvenance,
}

impl ProviderReadEvidence {
    pub(crate) fn validate(&self) -> Result<()> {
        self.app.validate()?;
        self.machine.validate()?;
        if self.request_receipts.len() > 16 || self.cost_receipts.len() > 16 {
            return Err(FlyioDeploymentResultError::PartialEvidence);
        }
        Ok(())
    }
}

impl Serialize for SecretReference {
    fn serialize<S>(&self, _serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Err(serde::ser::Error::custom(
            "SecretReference is opaque and non-serializing",
        ))
    }
}

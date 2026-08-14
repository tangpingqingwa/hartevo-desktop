use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_TAGS: usize = 32;
pub const MAX_ASSETS: usize = 128;
pub const MAX_RECORDS_PER_READ: usize = 256;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 4;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_OBSERVATION_WINDOW_SECONDS: i64 = 31 * 24 * 60 * 60;
pub const MAX_RETRY_ATTEMPTS: u8 = 3;
pub const MAX_BACKOFF_SECONDS: u64 = 30;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("identifier is empty, malformed, or too long")]
    InvalidIdentifier,
    #[error("digest is not a lowercase SHA-256 hex digest")]
    InvalidDigest,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("the time window is empty or exceeds the Layer-1 bound")]
    InvalidTimeWindow,
    #[error("the scope is empty, inconsistent, or exceeds the Layer-1 bound")]
    InvalidScope,
    #[error("the opaque cursor is empty or too large")]
    InvalidCursor,
    #[error("the SecretReference is invalid or already revoked")]
    InvalidSecretReference,
}

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        let mut output = String::with_capacity(64);
        for byte in Sha256::digest(bytes.as_ref()) {
            output.push(HEX[(byte >> 4) as usize] as char);
            output.push(HEX[(byte & 0x0f) as usize] as char);
        }
        Self(output)
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value)
    }

    pub fn from_fields(domain: &str, fields: &[String]) -> Self {
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for field in fields {
            append_field(&mut bytes, field);
        }
        Self::from_bytes(bytes)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidDigest)
        }
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

const HEX: &[u8; 16] = b"0123456789abcdef";

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
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:@/+~-".contains(&byte))
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
    };
}

string_identifier!(OrganizationId);
string_identifier!(TagId);
string_identifier!(VehicleId);
string_identifier!(EquipmentId);
string_identifier!(TripId);
string_identifier!(SafetyEventId);
string_identifier!(MaintenanceId);
string_identifier!(DvirId);
string_identifier!(AlertId);
string_identifier!(MissionId);
string_identifier!(ProjectId);
string_identifier!(ConsentId);
string_identifier!(ProviderId);
string_identifier!(ServiceId);
string_identifier!(ConsumerId);

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

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A reference into host-owned secret storage. No token, client secret, or
/// reference path is retained; only a scope-bound digest is retained.
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    revoked: bool,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_digest: self.reference_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            credential_revision: self.credential_revision,
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
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest
            && self.scope_digest == other.scope_digest
            && self.credential_revision == other.credential_revision
            && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope_digest: &Digest,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        if !valid_identifier(&reference_id) {
            return Err(ModelError::InvalidSecretReference);
        }
        let credential_revision =
            Revision::new(credential_revision).map_err(|_| ModelError::InvalidSecretReference)?;
        Ok(Self {
            reference_digest: Digest::from_fields(
                "samsara-secret-reference/v1",
                &[
                    reference_id,
                    scope_digest.as_str().to_owned(),
                    credential_revision.get().to_string(),
                ],
            ),
            scope_digest: scope_digest.clone(),
            credential_revision,
            revoked: false,
        })
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            Err(ModelError::InvalidSecretReference)
        } else {
            self.revoked = true;
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FleetProjection {
    Operational,
    Healthy,
    Degraded,
    Offline,
    SafetyAlert,
    MaintenanceDue,
    Partial,
    RetentionGap,
    AccessLost,
    ProviderUnknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetCondition {
    Healthy,
    Operational,
    Degraded,
    Offline,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetySeverity {
    Informational,
    Warning,
    Critical,
}

impl SafetySeverity {
    pub const fn is_alert(self) -> bool {
        matches!(self, Self::Warning | Self::Critical)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertState {
    Active,
    Acknowledged,
    Resolved,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MaintenanceState {
    Current,
    Due,
    Overdue,
    Unknown,
}

impl MaintenanceState {
    pub const fn is_due(self) -> bool {
        matches!(self, Self::Due | Self::Overdue)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DvirState {
    Clear,
    Defect,
    Open,
    Resolved,
    Unknown,
}

impl DvirState {
    pub const fn is_due(self) -> bool {
        matches!(self, Self::Defect | Self::Open)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetKind {
    Vehicle,
    Equipment,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum AssetReference {
    Vehicle(VehicleId),
    Equipment(EquipmentId),
}

impl AssetReference {
    pub const fn kind(&self) -> AssetKind {
        match self {
            Self::Vehicle(_) => AssetKind::Vehicle,
            Self::Equipment(_) => AssetKind::Equipment,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TimeWindow {
    start_epoch_seconds: i64,
    end_epoch_seconds: i64,
}

impl TimeWindow {
    pub fn new(start_epoch_seconds: i64, end_epoch_seconds: i64) -> Result<Self, ModelError> {
        if start_epoch_seconds >= end_epoch_seconds
            || end_epoch_seconds.saturating_sub(start_epoch_seconds)
                > MAX_OBSERVATION_WINDOW_SECONDS
        {
            Err(ModelError::InvalidTimeWindow)
        } else {
            Ok(Self {
                start_epoch_seconds,
                end_epoch_seconds,
            })
        }
    }

    pub const fn start_epoch_seconds(self) -> i64 {
        self.start_epoch_seconds
    }

    pub const fn end_epoch_seconds(self) -> i64 {
        self.end_epoch_seconds
    }

    pub const fn duration_seconds(self) -> i64 {
        self.end_epoch_seconds - self.start_epoch_seconds
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct TagScope {
    pub tag_ids: BTreeSet<TagId>,
}

impl TagScope {
    pub fn new(tag_ids: impl IntoIterator<Item = TagId>) -> Result<Self, ModelError> {
        let tag_ids = tag_ids.into_iter().collect::<BTreeSet<_>>();
        if tag_ids.len() > MAX_TAGS {
            Err(ModelError::InvalidScope)
        } else {
            Ok(Self { tag_ids })
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "samsara-tag-scope/v1",
            &self
                .tag_ids
                .iter()
                .map(|id| id.as_str().to_owned())
                .collect::<Vec<_>>(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct VehicleScope {
    pub vehicle_ids: BTreeSet<VehicleId>,
}

impl VehicleScope {
    pub fn new(vehicle_ids: impl IntoIterator<Item = VehicleId>) -> Result<Self, ModelError> {
        let vehicle_ids = vehicle_ids.into_iter().collect::<BTreeSet<_>>();
        if vehicle_ids.len() > MAX_ASSETS {
            Err(ModelError::InvalidScope)
        } else {
            Ok(Self { vehicle_ids })
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "samsara-vehicle-scope/v1",
            &self
                .vehicle_ids
                .iter()
                .map(|id| id.as_str().to_owned())
                .collect::<Vec<_>>(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct EquipmentScope {
    pub equipment_ids: BTreeSet<EquipmentId>,
}

impl EquipmentScope {
    pub fn new(equipment_ids: impl IntoIterator<Item = EquipmentId>) -> Result<Self, ModelError> {
        let equipment_ids = equipment_ids.into_iter().collect::<BTreeSet<_>>();
        if equipment_ids.len() > MAX_ASSETS {
            Err(ModelError::InvalidScope)
        } else {
            Ok(Self { equipment_ids })
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "samsara-equipment-scope/v1",
            &self
                .equipment_ids
                .iter()
                .map(|id| id.as_str().to_owned())
                .collect::<Vec<_>>(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TripScope {
    pub window: TimeWindow,
    pub vehicles: VehicleScope,
}

impl TripScope {
    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "samsara-trip-scope/v1",
            &[
                self.window.start_epoch_seconds().to_string(),
                self.window.end_epoch_seconds().to_string(),
                self.vehicles.digest().as_str().to_owned(),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SafetyEventScope {
    pub window: TimeWindow,
    pub vehicles: VehicleScope,
}

impl SafetyEventScope {
    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "samsara-safety-event-scope/v1",
            &[
                self.window.start_epoch_seconds().to_string(),
                self.window.end_epoch_seconds().to_string(),
                self.vehicles.digest().as_str().to_owned(),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MaintenanceScope {
    pub window: TimeWindow,
    pub vehicles: VehicleScope,
    pub equipment: EquipmentScope,
}

impl MaintenanceScope {
    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "samsara-maintenance-scope/v1",
            &[
                self.window.start_epoch_seconds().to_string(),
                self.window.end_epoch_seconds().to_string(),
                self.vehicles.digest().as_str().to_owned(),
                self.equipment.digest().as_str().to_owned(),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DvirScope {
    pub window: TimeWindow,
    pub vehicles: VehicleScope,
    pub equipment: EquipmentScope,
}

impl DvirScope {
    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "samsara-dvir-scope/v1",
            &[
                self.window.start_epoch_seconds().to_string(),
                self.window.end_epoch_seconds().to_string(),
                self.vehicles.digest().as_str().to_owned(),
                self.equipment.digest().as_str().to_owned(),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AlertScope {
    pub window: TimeWindow,
    pub max_alerts: u16,
    pub alert_ids: BTreeSet<AlertId>,
}

impl AlertScope {
    pub fn new(window: TimeWindow, max_alerts: u16) -> Result<Self, ModelError> {
        if max_alerts == 0 || usize::from(max_alerts) > MAX_RECORDS_PER_READ {
            Err(ModelError::InvalidScope)
        } else {
            Ok(Self {
                window,
                max_alerts,
                alert_ids: BTreeSet::new(),
            })
        }
    }

    pub fn with_alert_ids(
        mut self,
        alert_ids: impl IntoIterator<Item = AlertId>,
    ) -> Result<Self, ModelError> {
        self.alert_ids = alert_ids.into_iter().collect::<BTreeSet<_>>();
        if self.alert_ids.len() > MAX_RECORDS_PER_READ {
            Err(ModelError::InvalidScope)
        } else {
            Ok(self)
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "samsara-alert-scope/v1",
            &[
                self.window.start_epoch_seconds().to_string(),
                self.window.end_epoch_seconds().to_string(),
                self.max_alerts.to_string(),
                self.alert_ids
                    .iter()
                    .map(|id| id.as_str().to_owned())
                    .collect::<Vec<_>>()
                    .join(","),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MissionScope {
    pub mission_id: MissionId,
    pub revision: Revision,
}

impl MissionScope {
    pub fn new(mission_id: MissionId, revision: Revision) -> Self {
        Self {
            mission_id,
            revision,
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "samsara-mission-scope/v1",
            &[
                self.mission_id.as_str().to_owned(),
                self.revision.get().to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProjectScope {
    pub project_id: ProjectId,
    pub revision: Revision,
}

impl ProjectScope {
    pub fn new(project_id: ProjectId, revision: Revision) -> Self {
        Self {
            project_id,
            revision,
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "samsara-project-scope/v1",
            &[
                self.project_id.as_str().to_owned(),
                self.revision.get().to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConsentScope {
    pub consent_id: ConsentId,
    pub revision: Revision,
}

impl ConsentScope {
    pub fn new(consent_id: ConsentId, revision: Revision) -> Self {
        Self {
            consent_id,
            revision,
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "samsara-consent-scope/v1",
            &[
                self.consent_id.as_str().to_owned(),
                self.revision.get().to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OrganizationScope {
    pub organization_id: OrganizationId,
}

impl OrganizationScope {
    pub fn new(organization_id: OrganizationId) -> Self {
        Self { organization_id }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "samsara-organization-scope/v1",
            &[self.organization_id.as_str().to_owned()],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SamsaraFleetScopeInput {
    pub organization: OrganizationScope,
    pub tags: TagScope,
    pub vehicles: VehicleScope,
    pub equipment: EquipmentScope,
    pub trips: TripScope,
    pub safety_events: SafetyEventScope,
    pub maintenance: MaintenanceScope,
    pub dvir: DvirScope,
    pub alerts: AlertScope,
    pub mission: MissionScope,
    pub project: ProjectScope,
    pub consent: ConsentScope,
    pub permission_digest: Digest,
    pub policy_revision: Revision,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SamsaraFleetScope {
    organization: OrganizationScope,
    tags: TagScope,
    vehicles: VehicleScope,
    equipment: EquipmentScope,
    trips: TripScope,
    safety_events: SafetyEventScope,
    maintenance: MaintenanceScope,
    dvir: DvirScope,
    alerts: AlertScope,
    mission: MissionScope,
    project: ProjectScope,
    consent: ConsentScope,
    permission_digest: Digest,
    policy_revision: Revision,
    scope_digest: Digest,
}

impl SamsaraFleetScope {
    pub fn new(input: SamsaraFleetScopeInput) -> Result<Self, ModelError> {
        if input.vehicles.vehicle_ids.len() > MAX_ASSETS
            || input.equipment.equipment_ids.len() > MAX_ASSETS
            || input.tags.tag_ids.len() > MAX_TAGS
            || input.alerts.max_alerts == 0
            || input.trips.vehicles != input.vehicles
            || input.safety_events.vehicles != input.vehicles
            || input.maintenance.vehicles != input.vehicles
            || input.maintenance.equipment != input.equipment
            || input.dvir.vehicles != input.vehicles
            || input.dvir.equipment != input.equipment
        {
            return Err(ModelError::InvalidScope);
        }
        let scope_digest = Digest::from_fields(
            "samsara-fleet-scope/v1",
            &[
                input.organization.digest().as_str().to_owned(),
                input.tags.digest().as_str().to_owned(),
                input.vehicles.digest().as_str().to_owned(),
                input.equipment.digest().as_str().to_owned(),
                input.trips.digest().as_str().to_owned(),
                input.safety_events.digest().as_str().to_owned(),
                input.maintenance.digest().as_str().to_owned(),
                input.dvir.digest().as_str().to_owned(),
                input.alerts.digest().as_str().to_owned(),
                input.mission.digest().as_str().to_owned(),
                input.project.digest().as_str().to_owned(),
                input.consent.digest().as_str().to_owned(),
                input.permission_digest.as_str().to_owned(),
                input.policy_revision.get().to_string(),
            ],
        );
        Ok(Self {
            organization: input.organization,
            tags: input.tags,
            vehicles: input.vehicles,
            equipment: input.equipment,
            trips: input.trips,
            safety_events: input.safety_events,
            maintenance: input.maintenance,
            dvir: input.dvir,
            alerts: input.alerts,
            mission: input.mission,
            project: input.project,
            consent: input.consent,
            permission_digest: input.permission_digest,
            policy_revision: input.policy_revision,
            scope_digest,
        })
    }

    pub fn minimal(
        organization_id: OrganizationId,
        mission: MissionScope,
        project: ProjectScope,
        consent: ConsentScope,
        permission_digest: Digest,
        window: TimeWindow,
    ) -> Result<Self, ModelError> {
        let vehicles = VehicleScope::new(Vec::<VehicleId>::new())?;
        let equipment = EquipmentScope::new(Vec::<EquipmentId>::new())?;
        Self::new(SamsaraFleetScopeInput {
            organization: OrganizationScope::new(organization_id),
            tags: TagScope::new(Vec::<TagId>::new())?,
            vehicles: vehicles.clone(),
            equipment: equipment.clone(),
            trips: TripScope {
                window,
                vehicles: vehicles.clone(),
            },
            safety_events: SafetyEventScope {
                window,
                vehicles: vehicles.clone(),
            },
            maintenance: MaintenanceScope {
                window,
                vehicles: vehicles.clone(),
                equipment: equipment.clone(),
            },
            dvir: DvirScope {
                window,
                vehicles,
                equipment,
            },
            alerts: AlertScope::new(window, MAX_PAGE_SIZE)?,
            mission,
            project,
            consent,
            permission_digest,
            policy_revision: Revision::new(1)?,
        })
    }

    pub fn organization(&self) -> &OrganizationScope {
        &self.organization
    }

    pub fn tags(&self) -> &TagScope {
        &self.tags
    }

    pub fn vehicles(&self) -> &VehicleScope {
        &self.vehicles
    }

    pub fn equipment(&self) -> &EquipmentScope {
        &self.equipment
    }

    pub fn trips(&self) -> &TripScope {
        &self.trips
    }

    pub fn safety_events(&self) -> &SafetyEventScope {
        &self.safety_events
    }

    pub fn maintenance(&self) -> &MaintenanceScope {
        &self.maintenance
    }

    pub fn dvir(&self) -> &DvirScope {
        &self.dvir
    }

    pub fn alerts(&self) -> &AlertScope {
        &self.alerts
    }

    pub fn mission(&self) -> &MissionScope {
        &self.mission
    }

    pub fn project(&self) -> &ProjectScope {
        &self.project
    }

    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub const fn policy_revision(&self) -> Revision {
        self.policy_revision
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PageInfo {
    pub next_cursor_digest: Option<Digest>,
    pub retention_gap: bool,
}

impl PageInfo {
    pub const fn complete() -> Self {
        Self {
            next_cursor_digest: None,
            retention_gap: false,
        }
    }

    pub fn next(cursor: &OpaqueCursor) -> Self {
        Self {
            next_cursor_digest: Some(cursor.digest().clone()),
            retention_gap: false,
        }
    }

    pub const fn with_retention_gap(next_cursor_digest: Option<Digest>) -> Self {
        Self {
            next_cursor_digest,
            retention_gap: true,
        }
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpaqueCursor {
    digest: Digest,
}

impl OpaqueCursor {
    pub fn new(value: impl AsRef<[u8]>) -> Result<Self, ModelError> {
        let value = value.as_ref();
        if value.is_empty() || value.len() > 4096 {
            Err(ModelError::InvalidCursor)
        } else {
            Ok(Self {
                digest: Digest::from_bytes(value),
            })
        }
    }

    pub fn from_digest(digest: Digest) -> Result<Self, ModelError> {
        if is_digest(digest.as_str()) {
            Ok(Self { digest })
        } else {
            Err(ModelError::InvalidCursor)
        }
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

impl fmt::Debug for OpaqueCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueCursor")
            .field("digest", &self.digest)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VehicleRecord {
    pub vehicle_id: VehicleId,
    pub condition: AssetCondition,
    pub observed_at_epoch_seconds: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EquipmentRecord {
    pub equipment_id: EquipmentId,
    pub condition: AssetCondition,
    pub observed_at_epoch_seconds: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TripRecord {
    pub trip_id: TripId,
    pub vehicle_id: VehicleId,
    pub started_at_epoch_seconds: i64,
    pub ended_at_epoch_seconds: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SafetyEventRecord {
    pub safety_event_id: SafetyEventId,
    pub vehicle_id: VehicleId,
    pub severity: SafetySeverity,
    pub occurred_at_epoch_seconds: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MaintenanceRecord {
    pub maintenance_id: MaintenanceId,
    pub asset: AssetReference,
    pub state: MaintenanceState,
    pub observed_at_epoch_seconds: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DvirRecord {
    pub dvir_id: DvirId,
    pub asset: AssetReference,
    pub state: DvirState,
    pub defect_count: u16,
    pub observed_at_epoch_seconds: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AlertRecord {
    pub alert_id: AlertId,
    pub asset: Option<AssetReference>,
    pub severity: SafetySeverity,
    pub state: AlertState,
    pub occurred_at_epoch_seconds: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest() -> Digest {
        Digest::from_text("permission")
    }

    #[test]
    fn secret_reference_is_opaque_and_scope_bound() {
        let secret = SecretReference::new("vault/samsara/read", &digest(), 2).expect("secret");
        let debug = format!("{secret:?}");
        assert!(!debug.contains("vault/samsara/read"));
        assert!(!debug.contains("TOKEN"));
        assert_eq!(secret.scope_digest(), &digest());
    }

    #[test]
    fn scope_digest_changes_with_each_governance_fence() {
        let window = TimeWindow::new(100, 200).expect("window");
        let scope = SamsaraFleetScope::minimal(
            OrganizationId::new("org-1").expect("organization"),
            MissionScope::new(
                MissionId::new("mission-1").expect("mission"),
                Revision::new(1).expect("revision"),
            ),
            ProjectScope::new(
                ProjectId::new("project-1").expect("project"),
                Revision::new(1).expect("revision"),
            ),
            ConsentScope::new(
                ConsentId::new("consent-1").expect("consent"),
                Revision::new(1).expect("revision"),
            ),
            digest(),
            window,
        )
        .expect("scope");
        assert_eq!(scope.trips().window, window);
        assert_ne!(scope.scope_digest(), scope.permission_digest());
    }
}

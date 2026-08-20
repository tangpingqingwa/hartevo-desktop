//! Bounded, redacted AWS EBS scope and posture types.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::Zeroize;

use crate::error::{AwsEbsVolumeError, Result};
use crate::{
    LAYER1_PERMISSIONS, MAX_IDENTIFIER_BYTES, MAX_PAGE_SIZE, MAX_PAGES, MAX_RESPONSE_BYTES,
    MAX_STATUS_AGE_SECONDS,
};

pub const MAX_VOLUME_IDS: usize = 64;
pub const MAX_SNAPSHOT_IDS: usize = 64;
pub const MAX_ATTACHMENT_IDS: usize = 128;
pub const MAX_POSTURE_ITEMS: usize = 256;

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
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
            Err(AwsEbsVolumeError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(AwsEbsVolumeError::InvalidDigest)
        }
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
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

macro_rules! redacted_identifier {
    ($name:ident, $field:literal, $validator:expr) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if ($validator)(&value) {
                    Ok(Self(value))
                } else {
                    Err(AwsEbsVolumeError::InvalidIdentifier { field: $field })
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    concat!("aws-ebs-", $field, "/v1"),
                    &[("value", self.0.clone())],
                )
            }

            pub fn redacted(&self) -> String {
                format!("{}:{}", $field, &self.digest().as_str()[..16])
            }

            pub(crate) fn validate(&self) -> Result<()> {
                if ($validator)(&self.0) {
                    Ok(())
                } else {
                    Err(AwsEbsVolumeError::InvalidIdentifier { field: $field })
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.redacted())
                    .finish()
            }
        }
    };
}

redacted_identifier!(AwsAccountId, "account", |value: &str| value.len() == 12
    && value.bytes().all(|byte| byte.is_ascii_digit()));
redacted_identifier!(AwsRegion, "region", |value: &str| valid_identifier(
    value, 64
));
redacted_identifier!(VolumeId, "volume", |value: &str| value.starts_with("vol-")
    && valid_identifier(value, MAX_IDENTIFIER_BYTES));
redacted_identifier!(SnapshotId, "snapshot", |value: &str| value
    .starts_with("snap-")
    && valid_identifier(value, MAX_IDENTIFIER_BYTES));
redacted_identifier!(InstanceId, "instance", |value: &str| value
    .starts_with("i-")
    && valid_identifier(value, MAX_IDENTIFIER_BYTES));
redacted_identifier!(WorkloadRevision, "workload-revision", |value: &str| {
    valid_identifier(value, MAX_IDENTIFIER_BYTES)
});
redacted_identifier!(MissionId, "mission", |value: &str| valid_identifier(
    value,
    MAX_IDENTIFIER_BYTES,
));
redacted_identifier!(ProjectId, "project", |value: &str| valid_identifier(
    value,
    MAX_IDENTIFIER_BYTES,
));
redacted_identifier!(WorkProductId, "work-product", |value: &str| {
    valid_identifier(value, MAX_IDENTIFIER_BYTES)
});

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsEbsOperation {
    DescribeVolumes,
    DescribeVolumeStatus,
    DescribeSnapshots,
    DescribeFastSnapshotRestores,
}

impl AwsEbsOperation {
    pub const ALL: [Self; 4] = [
        Self::DescribeVolumes,
        Self::DescribeVolumeStatus,
        Self::DescribeSnapshots,
        Self::DescribeFastSnapshotRestores,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DescribeVolumes => "DescribeVolumes",
            Self::DescribeVolumeStatus => "DescribeVolumeStatus",
            Self::DescribeSnapshots => "DescribeSnapshots",
            Self::DescribeFastSnapshotRestores => "DescribeFastSnapshotRestores",
        }
    }

    pub const fn permission(self) -> &'static str {
        match self {
            Self::DescribeVolumes => "ec2:DescribeVolumes",
            Self::DescribeVolumeStatus => "ec2:DescribeVolumeStatus",
            Self::DescribeSnapshots => "ec2:DescribeSnapshots",
            Self::DescribeFastSnapshotRestores => "ec2:DescribeFastSnapshotRestores",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VolumeState {
    Creating,
    Available,
    InUse,
    Deleting,
    Deleted,
    Error,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VolumeType {
    Gp2,
    Gp3,
    Io1,
    Io2,
    St1,
    Sc1,
    Standard,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttachmentState {
    Attaching,
    Attached,
    Detaching,
    Detached,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VolumeStatusState {
    Ok,
    Impaired,
    Warning,
    InsufficientData,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotState {
    Pending,
    Completed,
    Error,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotStorageTier {
    Standard,
    Archive,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FastSnapshotRestoreState {
    Enabling,
    Optimizing,
    Enabled,
    Disabling,
    Disabled,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttachmentObservation {
    pub instance_id: InstanceId,
    pub state: AttachmentState,
    pub attach_time: Option<i64>,
    pub delete_on_termination: bool,
}

impl AttachmentObservation {
    pub fn new(
        instance_id: InstanceId,
        state: AttachmentState,
        attach_time: Option<i64>,
        delete_on_termination: bool,
    ) -> Result<Self> {
        if attach_time.is_some_and(|value| value <= 0) {
            return Err(AwsEbsVolumeError::InvalidRequest);
        }
        instance_id.validate()?;
        Ok(Self {
            instance_id,
            state,
            attach_time,
            delete_on_termination,
        })
    }

    fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-ebs-attachment/v1",
            &[
                ("instance", self.instance_id.digest().as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
                (
                    "attach_time",
                    self.attach_time
                        .map_or_else(String::new, |value| value.to_string()),
                ),
                (
                    "delete_on_termination",
                    self.delete_on_termination.to_string(),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VolumeMetadataInput {
    pub volume_id: VolumeId,
    pub snapshot_id: Option<SnapshotId>,
    pub state: VolumeState,
    pub volume_type: VolumeType,
    pub size_gib: u64,
    pub encrypted: bool,
    pub multi_attach_enabled: bool,
    pub create_time: i64,
    pub attachments: Vec<AttachmentObservation>,
    pub observed_at: i64,
    pub resource_digest: Digest,
}

impl VolumeMetadataInput {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        volume_id: VolumeId,
        snapshot_id: Option<SnapshotId>,
        state: VolumeState,
        volume_type: VolumeType,
        size_gib: u64,
        encrypted: bool,
        multi_attach_enabled: bool,
        create_time: i64,
        attachments: Vec<AttachmentObservation>,
        observed_at: i64,
    ) -> Result<Self> {
        volume_id.validate()?;
        snapshot_id.as_ref().map(SnapshotId::validate).transpose()?;
        if size_gib == 0
            || create_time <= 0
            || observed_at <= 0
            || observed_at < create_time
            || attachments.len() > MAX_ATTACHMENT_IDS
        {
            return Err(AwsEbsVolumeError::InvalidRequest);
        }
        let resource_digest = Digest::from_parts(
            "aws-ebs-volume-resource/v1",
            &[
                ("volume", volume_id.digest().as_str().to_owned()),
                (
                    "snapshot",
                    snapshot_id
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                ("create_time", create_time.to_string()),
                ("size_gib", size_gib.to_string()),
                ("volume_type", format!("{volume_type:?}")),
            ],
        );
        Ok(Self {
            volume_id,
            snapshot_id,
            state,
            volume_type,
            size_gib,
            encrypted,
            multi_attach_enabled,
            create_time,
            attachments,
            observed_at,
            resource_digest,
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct VolumeStatusInput {
    pub volume_id: VolumeId,
    pub availability_zone: String,
    pub status: VolumeStatusState,
    pub detail_statuses: Vec<(String, String)>,
    pub event_ids: Vec<String>,
    pub action_codes: Vec<String>,
    pub observed_at: i64,
    pub resource_digest: Digest,
}

impl fmt::Debug for VolumeStatusInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VolumeStatusInput")
            .field("volume_id_digest", &self.volume_id.digest())
            .field(
                "availability_zone_digest",
                &Digest::from_text(&self.availability_zone),
            )
            .field("status", &self.status)
            .field("detail_count", &self.detail_statuses.len())
            .field("event_count", &self.event_ids.len())
            .field("action_count", &self.action_codes.len())
            .field("observed_at", &self.observed_at)
            .field("resource_digest", &self.resource_digest)
            .finish()
    }
}

impl VolumeStatusInput {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        volume_id: VolumeId,
        availability_zone: impl Into<String>,
        status: VolumeStatusState,
        detail_statuses: Vec<(String, String)>,
        event_ids: Vec<String>,
        action_codes: Vec<String>,
        observed_at: i64,
        resource_digest: Digest,
    ) -> Result<Self> {
        let availability_zone = availability_zone.into();
        volume_id.validate()?;
        resource_digest.validate()?;
        if !valid_identifier(&availability_zone, 64)
            || observed_at <= 0
            || detail_statuses.len() > MAX_POSTURE_ITEMS
            || event_ids.len() > MAX_POSTURE_ITEMS
            || action_codes.len() > MAX_POSTURE_ITEMS
            || detail_statuses.iter().any(|(name, value)| {
                !valid_identifier(name, MAX_IDENTIFIER_BYTES)
                    || !valid_identifier(value, MAX_IDENTIFIER_BYTES)
            })
            || event_ids
                .iter()
                .chain(action_codes.iter())
                .any(|value| !valid_identifier(value, MAX_IDENTIFIER_BYTES))
        {
            return Err(AwsEbsVolumeError::InvalidRequest);
        }
        Ok(Self {
            volume_id,
            availability_zone,
            status,
            detail_statuses,
            event_ids,
            action_codes,
            observed_at,
            resource_digest,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotMetadataInput {
    pub snapshot_id: SnapshotId,
    pub volume_id: Option<VolumeId>,
    pub state: SnapshotState,
    pub start_time: i64,
    pub completion_time: Option<i64>,
    pub owner_id: AwsAccountId,
    pub encrypted: bool,
    pub storage_tier: SnapshotStorageTier,
    pub observed_at: i64,
    pub resource_digest: Digest,
}

impl SnapshotMetadataInput {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        snapshot_id: SnapshotId,
        volume_id: Option<VolumeId>,
        state: SnapshotState,
        start_time: i64,
        completion_time: Option<i64>,
        owner_id: AwsAccountId,
        encrypted: bool,
        storage_tier: SnapshotStorageTier,
        observed_at: i64,
    ) -> Result<Self> {
        snapshot_id.validate()?;
        volume_id.as_ref().map(VolumeId::validate).transpose()?;
        owner_id.validate()?;
        if start_time <= 0
            || observed_at <= 0
            || observed_at < start_time
            || completion_time.is_some_and(|value| value < start_time)
        {
            return Err(AwsEbsVolumeError::InvalidRequest);
        }
        let resource_digest = Digest::from_parts(
            "aws-ebs-snapshot-resource/v1",
            &[
                ("snapshot", snapshot_id.digest().as_str().to_owned()),
                (
                    "volume",
                    volume_id
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                ("start_time", start_time.to_string()),
                ("owner", owner_id.digest().as_str().to_owned()),
            ],
        );
        Ok(Self {
            snapshot_id,
            volume_id,
            state,
            start_time,
            completion_time,
            owner_id,
            encrypted,
            storage_tier,
            observed_at,
            resource_digest,
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct FastSnapshotRestoreInput {
    pub snapshot_id: SnapshotId,
    pub availability_zone: String,
    pub state: FastSnapshotRestoreState,
    pub owner_id: AwsAccountId,
    pub observed_at: i64,
    pub resource_digest: Digest,
}

impl fmt::Debug for FastSnapshotRestoreInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FastSnapshotRestoreInput")
            .field("snapshot_id_digest", &self.snapshot_id.digest())
            .field(
                "availability_zone_digest",
                &Digest::from_text(&self.availability_zone),
            )
            .field("state", &self.state)
            .field("owner_digest", &self.owner_id.digest())
            .field("observed_at", &self.observed_at)
            .field("resource_digest", &self.resource_digest)
            .finish()
    }
}

impl FastSnapshotRestoreInput {
    pub fn new(
        snapshot_id: SnapshotId,
        availability_zone: impl Into<String>,
        state: FastSnapshotRestoreState,
        owner_id: AwsAccountId,
        observed_at: i64,
    ) -> Result<Self> {
        let availability_zone = availability_zone.into();
        snapshot_id.validate()?;
        owner_id.validate()?;
        if !valid_identifier(&availability_zone, 64) || observed_at <= 0 {
            return Err(AwsEbsVolumeError::InvalidRequest);
        }
        let resource_digest = Digest::from_parts(
            "aws-ebs-fast-snapshot-restore-resource/v1",
            &[
                ("snapshot", snapshot_id.digest().as_str().to_owned()),
                (
                    "availability_zone",
                    Digest::from_text(&availability_zone).as_str().to_owned(),
                ),
                ("owner", owner_id.digest().as_str().to_owned()),
            ],
        );
        Ok(Self {
            snapshot_id,
            availability_zone,
            state,
            owner_id,
            observed_at,
            resource_digest,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionIdentity {
    id: MissionId,
    revision: u64,
}

impl MissionIdentity {
    pub fn new(id: MissionId, revision: u64) -> Result<Self> {
        id.validate()?;
        if revision == 0 {
            return Err(AwsEbsVolumeError::InvalidRequest);
        }
        Ok(Self { id, revision })
    }

    pub fn id_digest(&self) -> Digest {
        self.id.digest()
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-ebs-mission/v1",
            &[
                ("id", self.id.digest().as_str().to_owned()),
                ("revision", self.revision.to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectIdentity {
    id: ProjectId,
    revision: u64,
}

impl ProjectIdentity {
    pub fn new(id: ProjectId, revision: u64) -> Result<Self> {
        id.validate()?;
        if revision == 0 {
            return Err(AwsEbsVolumeError::InvalidRequest);
        }
        Ok(Self { id, revision })
    }

    pub fn id_digest(&self) -> Digest {
        self.id.digest()
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-ebs-project/v1",
            &[
                ("id", self.id.digest().as_str().to_owned()),
                ("revision", self.revision.to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkProductIdentity {
    id: WorkProductId,
    revision: u64,
}

impl WorkProductIdentity {
    pub fn new(id: WorkProductId, revision: u64) -> Result<Self> {
        id.validate()?;
        if revision == 0 {
            return Err(AwsEbsVolumeError::InvalidRequest);
        }
        Ok(Self { id, revision })
    }

    pub fn id_digest(&self) -> Digest {
        self.id.digest()
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-ebs-work-product/v1",
            &[
                ("id", self.id.digest().as_str().to_owned()),
                ("revision", self.revision.to_string()),
            ],
        )
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AwsEbsVolumeScope {
    account: AwsAccountId,
    region: AwsRegion,
    volume_allowlist: BTreeSet<VolumeId>,
    snapshot_allowlist: BTreeSet<SnapshotId>,
    attachment_allowlist: BTreeSet<InstanceId>,
    workload_revision: WorkloadRevision,
    mission: MissionIdentity,
    project: ProjectIdentity,
    work_product: WorkProductIdentity,
}

impl AwsEbsVolumeScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: AwsAccountId,
        region: AwsRegion,
        volume_allowlist: impl IntoIterator<Item = VolumeId>,
        snapshot_allowlist: impl IntoIterator<Item = SnapshotId>,
        attachment_allowlist: impl IntoIterator<Item = InstanceId>,
        workload_revision: WorkloadRevision,
        mission: MissionIdentity,
        project: ProjectIdentity,
        work_product: WorkProductIdentity,
    ) -> Result<Self> {
        let scope = Self {
            account,
            region,
            volume_allowlist: volume_allowlist.into_iter().collect(),
            snapshot_allowlist: snapshot_allowlist.into_iter().collect(),
            attachment_allowlist: attachment_allowlist.into_iter().collect(),
            workload_revision,
            mission,
            project,
            work_product,
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

    pub fn volume_allowlist(&self) -> Vec<VolumeId> {
        self.volume_allowlist.iter().cloned().collect()
    }

    pub fn snapshot_allowlist(&self) -> Vec<SnapshotId> {
        self.snapshot_allowlist.iter().cloned().collect()
    }

    pub fn attachment_allowlist(&self) -> Vec<InstanceId> {
        self.attachment_allowlist.iter().cloned().collect()
    }

    pub fn workload_revision(&self) -> &WorkloadRevision {
        &self.workload_revision
    }

    pub fn mission(&self) -> &MissionIdentity {
        &self.mission
    }

    pub fn project(&self) -> &ProjectIdentity {
        &self.project
    }

    pub fn work_product(&self) -> &WorkProductIdentity {
        &self.work_product
    }

    pub fn volume_allowlist_digest(&self) -> Digest {
        digest_ids("aws-ebs-volume-allowlist/v1", self.volume_allowlist.iter())
    }

    pub fn snapshot_allowlist_digest(&self) -> Digest {
        digest_ids(
            "aws-ebs-snapshot-allowlist/v1",
            self.snapshot_allowlist.iter(),
        )
    }

    pub fn attachment_allowlist_digest(&self) -> Digest {
        digest_ids(
            "aws-ebs-attachment-allowlist/v1",
            self.attachment_allowlist.iter(),
        )
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-ebs-scope/v1",
            &[
                ("account", self.account.digest().as_str().to_owned()),
                ("region", self.region.digest().as_str().to_owned()),
                (
                    "volume_allowlist",
                    self.volume_allowlist_digest().as_str().to_owned(),
                ),
                (
                    "snapshot_allowlist",
                    self.snapshot_allowlist_digest().as_str().to_owned(),
                ),
                (
                    "attachment_allowlist",
                    self.attachment_allowlist_digest().as_str().to_owned(),
                ),
                (
                    "workload_revision",
                    self.workload_revision.digest().as_str().to_owned(),
                ),
                ("mission", self.mission.digest().as_str().to_owned()),
                ("project", self.project.digest().as_str().to_owned()),
                (
                    "work_product",
                    self.work_product.digest().as_str().to_owned(),
                ),
            ],
        )
    }

    pub fn allows_volume(&self, id: &VolumeId) -> bool {
        self.volume_allowlist.contains(id)
    }

    pub fn allows_snapshot(&self, id: &SnapshotId) -> bool {
        self.snapshot_allowlist.contains(id)
    }

    pub fn allows_attachment(&self, id: &InstanceId) -> bool {
        self.attachment_allowlist.is_empty() || self.attachment_allowlist.contains(id)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.account.validate()?;
        self.region.validate()?;
        self.workload_revision.validate()?;
        self.mission.id.validate()?;
        self.project.id.validate()?;
        self.work_product.id.validate()?;
        if self.volume_allowlist.is_empty()
            || self.volume_allowlist.len() > MAX_VOLUME_IDS
            || self.snapshot_allowlist.len() > MAX_SNAPSHOT_IDS
            || self.attachment_allowlist.len() > MAX_ATTACHMENT_IDS
            || self.mission.revision == 0
            || self.project.revision == 0
            || self.work_product.revision == 0
        {
            return Err(AwsEbsVolumeError::InvalidScope);
        }
        for id in &self.volume_allowlist {
            id.validate()?;
        }
        for id in &self.snapshot_allowlist {
            id.validate()?;
        }
        for id in &self.attachment_allowlist {
            id.validate()?;
        }
        Ok(())
    }
}

impl fmt::Debug for AwsEbsVolumeScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsEbsVolumeScope")
            .field("account_digest", &self.account.digest())
            .field("region_digest", &self.region.digest())
            .field("volume_allowlist_digest", &self.volume_allowlist_digest())
            .field(
                "snapshot_allowlist_digest",
                &self.snapshot_allowlist_digest(),
            )
            .field(
                "attachment_allowlist_digest",
                &self.attachment_allowlist_digest(),
            )
            .field("workload_revision_digest", &self.workload_revision.digest())
            .field("mission_digest", &self.mission.digest())
            .field("project_digest", &self.project.digest())
            .field("work_product_digest", &self.work_product.digest())
            .field("scope_digest", &self.digest())
            .finish()
    }
}

fn digest_ids<'a, I, T>(domain: &str, values: I) -> Digest
where
    I: IntoIterator<Item = &'a T>,
    T: 'a + IdDigest,
{
    let joined = values
        .into_iter()
        .map(|value| value.id_digest())
        .map(|value| value.as_str().to_owned())
        .collect::<Vec<_>>()
        .join("\n");
    Digest::from_parts(domain, &[("ids", joined)])
}

trait IdDigest {
    fn id_digest(&self) -> Digest;
}

macro_rules! impl_id_digest {
    ($($name:ty),+ $(,)?) => {
        $(impl IdDigest for $name {
            fn id_digest(&self) -> Digest { self.digest() }
        })+
    };
}

impl_id_digest!(VolumeId, SnapshotId, InstanceId);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    Sigv4Credential,
}

/// Opaque SigV4 reference. The supplied handle is hashed and zeroized; it is
/// never retained, serialized, displayed, or present in Debug output.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretKind,
    reference_digest: Digest,
    scope_digest: Digest,
    revision: u64,
    revoked: bool,
}

/// Explicit name for callers that want the authentication scheme in the type.
pub type SigV4SecretReference = SecretReference;

impl SecretReference {
    pub fn new(opaque_handle: impl Into<String>, revision: u64) -> Result<Self> {
        let mut handle = opaque_handle.into();
        if !valid_text(&handle, MAX_IDENTIFIER_BYTES, true) || revision == 0 {
            handle.zeroize();
            return Err(AwsEbsVolumeError::InvalidSecretReference);
        }
        let reference_digest = Digest::from_parts(
            "aws-ebs-opaque-sigv4-reference/v1",
            &[
                ("kind", "sigv4_credential".to_owned()),
                ("handle", handle.clone()),
                ("revision", revision.to_string()),
            ],
        );
        handle.zeroize();
        Ok(Self {
            kind: SecretKind::Sigv4Credential,
            reference_digest,
            scope_digest: Digest::from_text("unbound-aws-ebs-secret-scope"),
            revision,
            revoked: false,
        })
    }

    pub fn sigv4(
        opaque_handle: impl Into<String>,
        scope: &AwsEbsVolumeScope,
        revision: u64,
    ) -> Result<Self> {
        let mut reference = Self::new(opaque_handle, revision)?;
        reference.scope_digest = scope.digest();
        reference.reference_digest = Digest::from_parts(
            "aws-ebs-opaque-sigv4-reference/v1",
            &[
                ("kind", "sigv4_credential".to_owned()),
                ("reference", reference.reference_digest.as_str().to_owned()),
                ("scope", reference.scope_digest.as_str().to_owned()),
                ("revision", revision.to_string()),
            ],
        );
        Ok(reference)
    }

    pub const fn kind(&self) -> SecretKind {
        self.kind
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub(crate) fn validate(&self, scope: &AwsEbsVolumeScope) -> Result<()> {
        if !matches!(self.kind, SecretKind::Sigv4Credential)
            || self.revision == 0
            || self.revoked
            || self.scope_digest != scope.digest()
        {
            return Err(AwsEbsVolumeError::InvalidSecretReference);
        }
        self.reference_digest.validate()
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("kind", &self.kind)
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Recording,
    Fixture,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Fixture => "fixture",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "blocked_env",
        }
    }

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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionSnapshot {
    pub revision: u64,
    pub permissions: BTreeSet<String>,
}

impl PermissionSnapshot {
    pub fn new<I, S>(revision: u64, permissions: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let snapshot = Self {
            revision,
            permissions: permissions.into_iter().map(Into::into).collect(),
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn for_layer_one(revision: u64) -> Self {
        Self {
            revision,
            permissions: LAYER1_PERMISSIONS
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect(),
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-ebs-permissions/v1",
            &[
                ("revision", self.revision.to_string()),
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

    pub(crate) fn validate(&self) -> Result<()> {
        if self.revision == 0
            || self.permissions.len() != LAYER1_PERMISSIONS.len()
            || self
                .permissions
                .iter()
                .any(|permission| !LAYER1_PERMISSIONS.contains(&permission.as_str()))
        {
            Err(AwsEbsVolumeError::InvalidPermissionSnapshot)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ConsentScope {
    id: String,
    revision: u64,
    expires_at: i64,
    revoked: bool,
}

impl ConsentScope {
    pub fn new(id: impl Into<String>, revision: u64, expires_at: i64) -> Result<Self> {
        let consent = Self {
            id: id.into(),
            revision,
            expires_at,
            revoked: false,
        };
        consent.validate()?;
        Ok(consent)
    }

    pub fn for_layer_one(id: impl Into<String>, revision: u64, expires_at: i64) -> Result<Self> {
        Self::new(id, revision, expires_at)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-ebs-consent/v1",
            &[
                ("id", Digest::from_text(&self.id).as_str().to_owned()),
                ("revision", self.revision.to_string()),
                ("expires_at", self.expires_at.to_string()),
                ("revoked", self.revoked.to_string()),
            ],
        )
    }

    pub const fn is_active_at(&self, at: i64) -> bool {
        !self.revoked && at < self.expires_at
    }

    pub const fn expires_at(&self) -> i64 {
        self.expires_at
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if !valid_identifier(&self.id, MAX_IDENTIFIER_BYTES)
            || self.revision == 0
            || self.expires_at <= 0
        {
            Err(AwsEbsVolumeError::InvalidConsent)
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for ConsentScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConsentScope")
            .field("digest", &self.digest())
            .field("revision", &self.revision)
            .field("expires_at", &self.expires_at)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct PageCursor {
    pub(crate) operation: AwsEbsOperation,
    pub(crate) scope_digest: Digest,
    pub(crate) volume_allowlist_digest: Digest,
    pub(crate) snapshot_allowlist_digest: Digest,
    pub(crate) filter_digest: Digest,
    pub(crate) token_digest: Digest,
    pub(crate) page_number: u16,
}

impl PageCursor {
    pub fn new(
        opaque_token: impl Into<String>,
        operation: AwsEbsOperation,
        scope: &AwsEbsVolumeScope,
        filter_digest: Digest,
        page_number: u16,
    ) -> Result<Self> {
        let mut token = opaque_token.into();
        if !valid_text(&token, MAX_IDENTIFIER_BYTES, true)
            || !(2..=MAX_PAGES).contains(&page_number)
        {
            token.zeroize();
            return Err(AwsEbsVolumeError::InvalidRequest);
        }
        filter_digest.validate()?;
        let token_digest =
            Digest::from_parts("aws-ebs-opaque-next-token/v1", &[("token", token.clone())]);
        token.zeroize();
        Ok(Self {
            operation,
            scope_digest: scope.digest(),
            volume_allowlist_digest: scope.volume_allowlist_digest(),
            snapshot_allowlist_digest: scope.snapshot_allowlist_digest(),
            filter_digest,
            token_digest,
            page_number,
        })
    }

    pub fn operation(&self) -> AwsEbsOperation {
        self.operation
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn volume_allowlist_digest(&self) -> &Digest {
        &self.volume_allowlist_digest
    }

    pub fn snapshot_allowlist_digest(&self) -> &Digest {
        &self.snapshot_allowlist_digest
    }

    pub fn filter_digest(&self) -> &Digest {
        &self.filter_digest
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub fn validate_against(
        &self,
        operation: AwsEbsOperation,
        scope: &AwsEbsVolumeScope,
        filter_digest: &Digest,
    ) -> Result<()> {
        if self.operation != operation
            || self.scope_digest != scope.digest()
            || self.volume_allowlist_digest != scope.volume_allowlist_digest()
            || self.snapshot_allowlist_digest != scope.snapshot_allowlist_digest()
            || self.filter_digest != *filter_digest
            || self.page_number < 2
            || self.page_number > MAX_PAGES
        {
            return Err(AwsEbsVolumeError::CursorMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for PageCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PageCursor")
            .field("operation", &self.operation)
            .field("scope_digest", &self.scope_digest)
            .field("volume_allowlist_digest", &self.volume_allowlist_digest)
            .field("snapshot_allowlist_digest", &self.snapshot_allowlist_digest)
            .field("filter_digest", &self.filter_digest)
            .field("token_digest", &self.token_digest)
            .field("page_number", &self.page_number)
            .finish()
    }
}

impl Serialize for PageCursor {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("PageCursor", 7)?;
        state.serialize_field("operation", &self.operation)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("volumeAllowlistDigest", &self.volume_allowlist_digest)?;
        state.serialize_field("snapshotAllowlistDigest", &self.snapshot_allowlist_digest)?;
        state.serialize_field("filterDigest", &self.filter_digest)?;
        state.serialize_field("tokenDigest", &self.token_digest)?;
        state.serialize_field("pageNumber", &self.page_number)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub volume_allowlist_digest: Digest,
    pub snapshot_allowlist_digest: Digest,
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub volume_read_digest: Option<Digest>,
    pub status_read_digest: Option<Digest>,
    pub snapshot_read_digest: Option<Digest>,
    pub fast_snapshot_restore_read_digest: Option<Digest>,
    pub evidence_digest: Digest,
}

impl EvidenceDigests {
    pub(crate) fn validate(&self) -> Result<()> {
        self.plugin_version_digest.validate()?;
        self.contract_digest.validate()?;
        self.provider_digest.validate()?;
        self.permission_digest.validate()?;
        self.consent_digest.validate()?;
        self.volume_allowlist_digest.validate()?;
        self.snapshot_allowlist_digest.validate()?;
        self.scope_digest.validate()?;
        self.request_digest.validate()?;
        self.volume_read_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.status_read_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.snapshot_read_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.fast_snapshot_restore_read_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.evidence_digest.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionProjection {
    pub id_digest: Digest,
    pub revision: u64,
    pub binding_digest: Digest,
}

impl From<&MissionIdentity> for MissionProjection {
    fn from(value: &MissionIdentity) -> Self {
        Self {
            id_digest: value.id_digest(),
            revision: value.revision,
            binding_digest: value.digest(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectProjection {
    pub id_digest: Digest,
    pub revision: u64,
    pub binding_digest: Digest,
}

impl From<&ProjectIdentity> for ProjectProjection {
    fn from(value: &ProjectIdentity) -> Self {
        Self {
            id_digest: value.id_digest(),
            revision: value.revision,
            binding_digest: value.digest(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductProjection {
    pub id_digest: Digest,
    pub revision: u64,
    pub binding_digest: Digest,
}

impl From<&WorkProductIdentity> for WorkProductProjection {
    fn from(value: &WorkProductIdentity) -> Self {
        Self {
            id_digest: value.id_digest(),
            revision: value.revision,
            binding_digest: value.digest(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentPosture {
    pub instance_id_digest: Digest,
    pub state: AttachmentState,
    pub attach_time: Option<i64>,
    pub delete_on_termination: bool,
    pub attachment_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VolumePosture {
    pub volume_id_digest: Digest,
    pub snapshot_id_digest: Option<Digest>,
    pub resource_digest: Digest,
    pub state: VolumeState,
    pub volume_type: VolumeType,
    pub size_gib: u64,
    pub encrypted: bool,
    pub multi_attach_enabled: bool,
    pub create_time: i64,
    pub attachments: Vec<AttachmentPosture>,
    pub observed_at: i64,
}

impl From<&VolumeMetadataInput> for VolumePosture {
    fn from(value: &VolumeMetadataInput) -> Self {
        Self {
            volume_id_digest: value.volume_id.digest(),
            snapshot_id_digest: value.snapshot_id.as_ref().map(SnapshotId::digest),
            resource_digest: value.resource_digest.clone(),
            state: value.state,
            volume_type: value.volume_type,
            size_gib: value.size_gib,
            encrypted: value.encrypted,
            multi_attach_enabled: value.multi_attach_enabled,
            create_time: value.create_time,
            attachments: value
                .attachments
                .iter()
                .map(|attachment| AttachmentPosture {
                    instance_id_digest: attachment.instance_id.digest(),
                    state: attachment.state,
                    attach_time: attachment.attach_time,
                    delete_on_termination: attachment.delete_on_termination,
                    attachment_digest: attachment.digest(),
                })
                .collect(),
            observed_at: value.observed_at,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusDetailPosture {
    pub name_digest: Digest,
    pub status_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VolumeStatusPosture {
    pub volume_id_digest: Digest,
    pub availability_zone_digest: Digest,
    pub resource_digest: Digest,
    pub status: VolumeStatusState,
    pub detail_statuses: Vec<StatusDetailPosture>,
    pub event_digests: Vec<Digest>,
    pub action_digests: Vec<Digest>,
    pub observed_at: i64,
}

impl From<&VolumeStatusInput> for VolumeStatusPosture {
    fn from(value: &VolumeStatusInput) -> Self {
        Self {
            volume_id_digest: value.volume_id.digest(),
            availability_zone_digest: Digest::from_text(&value.availability_zone),
            resource_digest: value.resource_digest.clone(),
            status: value.status,
            detail_statuses: value
                .detail_statuses
                .iter()
                .map(|(name, status)| StatusDetailPosture {
                    name_digest: Digest::from_text(name),
                    status_digest: Digest::from_text(status),
                })
                .collect(),
            event_digests: value.event_ids.iter().map(Digest::from_text).collect(),
            action_digests: value.action_codes.iter().map(Digest::from_text).collect(),
            observed_at: value.observed_at,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotPosture {
    pub snapshot_id_digest: Digest,
    pub volume_id_digest: Option<Digest>,
    pub resource_digest: Digest,
    pub state: SnapshotState,
    pub encrypted: bool,
    pub age_seconds: u64,
    pub storage_tier: SnapshotStorageTier,
    pub completion_time: Option<i64>,
    pub observed_at: i64,
}

impl SnapshotPosture {
    pub fn from_input(value: &SnapshotMetadataInput, observed_at: i64) -> Self {
        let age_seconds = observed_at
            .saturating_sub(value.start_time)
            .max(0)
            .cast_unsigned();
        Self {
            snapshot_id_digest: value.snapshot_id.digest(),
            volume_id_digest: value.volume_id.as_ref().map(VolumeId::digest),
            resource_digest: value.resource_digest.clone(),
            state: value.state,
            encrypted: value.encrypted,
            age_seconds,
            storage_tier: value.storage_tier,
            completion_time: value.completion_time,
            observed_at: value.observed_at,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FastSnapshotRestorePosture {
    pub snapshot_id_digest: Digest,
    pub availability_zone_digest: Digest,
    pub resource_digest: Digest,
    pub state: FastSnapshotRestoreState,
    pub observed_at: i64,
}

impl From<&FastSnapshotRestoreInput> for FastSnapshotRestorePosture {
    fn from(value: &FastSnapshotRestoreInput) -> Self {
        Self {
            snapshot_id_digest: value.snapshot_id.digest(),
            availability_zone_digest: Digest::from_text(&value.availability_zone),
            resource_digest: value.resource_digest.clone(),
            state: value.state,
            observed_at: value.observed_at,
        }
    }
}

pub fn validate_response_bounds(response_bytes: u64, item_count: usize) -> Result<()> {
    if response_bytes > MAX_RESPONSE_BYTES || item_count > MAX_POSTURE_ITEMS {
        Err(AwsEbsVolumeError::PartialEvidence)
    } else {
        Ok(())
    }
}

pub fn validate_page_size(page_size: u16) -> Result<()> {
    if page_size == 0 || page_size > MAX_PAGE_SIZE {
        Err(AwsEbsVolumeError::InvalidRequest)
    } else {
        Ok(())
    }
}

pub fn validate_page_count(page_count: u16) -> Result<()> {
    if page_count == 0 || page_count > MAX_PAGES {
        Err(AwsEbsVolumeError::InvalidRequest)
    } else {
        Ok(())
    }
}

pub fn validate_observation_time(observed_at: i64) -> Result<()> {
    if observed_at <= 0 {
        Err(AwsEbsVolumeError::InvalidRequest)
    } else {
        Ok(())
    }
}

pub fn is_stale(observed_at: i64, requested_at: i64) -> bool {
    observed_at > requested_at || requested_at.saturating_sub(observed_at) > MAX_STATUS_AGE_SECONDS
}

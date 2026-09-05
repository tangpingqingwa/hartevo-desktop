//! Redacted, bounded models for AWS IoT SiteWise asset/property history.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};

use crate::error::{AwsIoTSiteWiseMeasurementError, Result};
use crate::{MAX_IDENTIFIER_BYTES, MAX_PAGE_SIZE, MAX_PAGES, MAX_RESPONSE_BYTES};

pub const MAX_WINDOW_SECONDS: i64 = 31 * 24 * 60 * 60;
pub const DEFAULT_STALE_AFTER_SECONDS: i64 = 15 * 60;
pub const MAX_STALE_AFTER_SECONDS: i64 = 7 * 24 * 60 * 60;
pub const MAX_PROPERTY_COUNT: usize = 256;

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
            Err(AwsIoTSiteWiseMeasurementError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(AwsIoTSiteWiseMeasurementError::InvalidDigest)
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

fn valid_identifier(value: &str, max_bytes: usize, allow_slash: bool) -> bool {
    valid_text(value, max_bytes, false)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b':')
                || (allow_slash && byte == b'/')
        })
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
                    Err(AwsIoTSiteWiseMeasurementError::InvalidIdentifier { field: $field })
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    concat!("aws-iot-sitewise-", $field, "/v1"),
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
                    Err(AwsIoTSiteWiseMeasurementError::InvalidIdentifier { field: $field })
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
    value, 64, false
));
redacted_identifier!(AssetModelId, "asset-model", |value: &str| valid_identifier(
    value,
    MAX_IDENTIFIER_BYTES,
    false
));
redacted_identifier!(AssetId, "asset", |value: &str| valid_identifier(
    value,
    MAX_IDENTIFIER_BYTES,
    false
));
redacted_identifier!(PropertyId, "property", |value: &str| valid_identifier(
    value,
    MAX_IDENTIFIER_BYTES,
    false
));
redacted_identifier!(PropertyAlias, "property-alias", |value: &str| {
    valid_identifier(value, MAX_IDENTIFIER_BYTES, true)
});

macro_rules! scoped_identity {
    ($name:ident, $domain:literal, $field:literal) => {
        #[derive(Clone, Eq, PartialEq)]
        pub struct $name {
            id: String,
            revision: u64,
        }

        impl $name {
            pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
                let id = id.into();
                if !valid_identifier(&id, MAX_IDENTIFIER_BYTES, false) || revision == 0 {
                    return Err(AwsIoTSiteWiseMeasurementError::InvalidScope);
                }
                Ok(Self { id, revision })
            }

            pub fn id(&self) -> &str {
                &self.id
            }

            pub const fn revision(&self) -> u64 {
                self.revision
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    $domain,
                    &[
                        ("id", self.id.clone()),
                        ("revision", self.revision.to_string()),
                    ],
                )
            }

            pub(crate) fn validate(&self) -> Result<()> {
                if valid_identifier(&self.id, MAX_IDENTIFIER_BYTES, false) && self.revision != 0 {
                    Ok(())
                } else {
                    Err(AwsIoTSiteWiseMeasurementError::InvalidScope)
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("id_digest", &Digest::from_text(&self.id))
                    .field("revision", &self.revision)
                    .finish()
            }
        }
    };
}

scoped_identity!(MissionIdentity, "aws-iot-sitewise-mission/v1", "mission");
scoped_identity!(ProjectIdentity, "aws-iot-sitewise-project/v1", "project");
scoped_identity!(
    WorkProductIdentity,
    "aws-iot-sitewise-work-product/v1",
    "work-product"
);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MeasurementQuality {
    Good,
    Bad,
    Uncertain,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QualityFilter {
    Any,
    GoodOnly,
    GoodOrUncertain,
}

impl QualityFilter {
    pub const fn accepts(self, quality: MeasurementQuality) -> bool {
        match self {
            Self::Any => true,
            Self::GoodOnly => matches!(quality, MeasurementQuality::Good),
            Self::GoodOrUncertain => {
                matches!(
                    quality,
                    MeasurementQuality::Good | MeasurementQuality::Uncertain
                )
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SiteWiseDataType {
    Double,
    Integer,
    Boolean,
    String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransportProvenance {
    Recording,
    Fixture,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Fixture => "fixture",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "blocked_env",
        }
    }

    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_connected(self) -> bool {
        false
    }

    pub const fn is_first_party(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MeasurementEvidenceState {
    Present,
    Empty,
    Partial,
    Stale,
    AccessLost,
    ProviderUnknown,
    Tampered,
    Revoked,
}

impl MeasurementEvidenceState {
    pub const fn is_non_adoptable(self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimeWindow {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

impl TimeWindow {
    pub fn new(start: DateTime<Utc>, end: DateTime<Utc>) -> Result<Self> {
        let window = Self { start, end };
        window.validate()?;
        Ok(window)
    }

    pub fn contains(&self, timestamp: DateTime<Utc>) -> bool {
        timestamp >= self.start && timestamp <= self.end
    }

    pub fn duration(&self) -> Duration {
        self.end - self.start
    }

    pub(crate) fn validate(&self) -> Result<()> {
        let seconds = self.duration().num_seconds();
        if self.start < self.end && (1..=MAX_WINDOW_SECONDS).contains(&seconds) {
            Ok(())
        } else {
            Err(AwsIoTSiteWiseMeasurementError::InvalidBounds)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MeasurementBounds {
    pub max_points: u32,
    pub max_pages: u16,
    pub max_response_bytes: u64,
    pub stale_after_seconds: i64,
}

impl MeasurementBounds {
    pub fn new(max_points: u32, max_pages: u16, max_response_bytes: u64) -> Result<Self> {
        Self::with_stale_after_seconds(
            max_points,
            max_pages,
            max_response_bytes,
            DEFAULT_STALE_AFTER_SECONDS,
        )
    }

    pub fn with_stale_after_seconds(
        max_points: u32,
        max_pages: u16,
        max_response_bytes: u64,
        stale_after_seconds: i64,
    ) -> Result<Self> {
        let bounds = Self {
            max_points,
            max_pages,
            max_response_bytes,
            stale_after_seconds,
        };
        bounds.validate()?;
        Ok(bounds)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.max_points == 0
            || self.max_points > (u32::from(MAX_PAGE_SIZE) * u32::from(MAX_PAGES))
            || self.max_pages == 0
            || self.max_pages > MAX_PAGES
            || self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES
            || self.stale_after_seconds < 0
            || self.stale_after_seconds > MAX_STALE_AFTER_SECONDS
        {
            Err(AwsIoTSiteWiseMeasurementError::InvalidBounds)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AwsIoTSiteWiseMeasurementScope {
    account: AwsAccountId,
    region: AwsRegion,
    asset_model_id: AssetModelId,
    asset_id: AssetId,
    property_id: PropertyId,
    property_alias: Option<PropertyAlias>,
    time_window: TimeWindow,
    quality: QualityFilter,
    bounds: MeasurementBounds,
    mission: MissionIdentity,
    project: ProjectIdentity,
    work_product: WorkProductIdentity,
}

impl AwsIoTSiteWiseMeasurementScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: AwsAccountId,
        region: AwsRegion,
        asset_model_id: AssetModelId,
        asset_id: AssetId,
        property_id: PropertyId,
        property_alias: Option<PropertyAlias>,
        time_window: TimeWindow,
        quality: QualityFilter,
        bounds: MeasurementBounds,
        mission: MissionIdentity,
        project: ProjectIdentity,
        work_product: WorkProductIdentity,
    ) -> Result<Self> {
        let scope = Self {
            account,
            region,
            asset_model_id,
            asset_id,
            property_id,
            property_alias,
            time_window,
            quality,
            bounds,
            mission,
            project,
            work_product,
        };
        scope.validate()?;
        Ok(scope)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_strings(
        account: impl Into<String>,
        region: impl Into<String>,
        asset_model_id: impl Into<String>,
        asset_id: impl Into<String>,
        property_id: impl Into<String>,
        property_alias: Option<String>,
        time_window: TimeWindow,
        quality: QualityFilter,
        bounds: MeasurementBounds,
        mission: impl Into<String>,
        mission_revision: u64,
        project: impl Into<String>,
        project_revision: u64,
        work_product: impl Into<String>,
        work_product_revision: u64,
    ) -> Result<Self> {
        Self::new(
            AwsAccountId::new(account)?,
            AwsRegion::new(region)?,
            AssetModelId::new(asset_model_id)?,
            AssetId::new(asset_id)?,
            PropertyId::new(property_id)?,
            property_alias.map(PropertyAlias::new).transpose()?,
            time_window,
            quality,
            bounds,
            MissionIdentity::new(mission, mission_revision)?,
            ProjectIdentity::new(project, project_revision)?,
            WorkProductIdentity::new(work_product, work_product_revision)?,
        )
    }

    pub fn account(&self) -> &AwsAccountId {
        &self.account
    }

    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn asset_model_id(&self) -> &AssetModelId {
        &self.asset_model_id
    }

    pub fn asset_id(&self) -> &AssetId {
        &self.asset_id
    }

    pub fn property_id(&self) -> &PropertyId {
        &self.property_id
    }

    pub fn property_alias(&self) -> Option<&PropertyAlias> {
        self.property_alias.as_ref()
    }

    pub fn time_window(&self) -> &TimeWindow {
        &self.time_window
    }

    pub const fn quality(&self) -> QualityFilter {
        self.quality
    }

    pub fn bounds(&self) -> &MeasurementBounds {
        &self.bounds
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

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-iot-sitewise-measurement-scope/v1",
            &[
                ("account", self.account.digest().as_str().to_owned()),
                ("region", self.region.digest().as_str().to_owned()),
                (
                    "asset_model",
                    self.asset_model_id.digest().as_str().to_owned(),
                ),
                ("asset", self.asset_id.digest().as_str().to_owned()),
                ("property", self.property_id.digest().as_str().to_owned()),
                (
                    "property_alias",
                    self.property_alias
                        .as_ref()
                        .map_or_else(String::new, |alias| alias.digest().as_str().to_owned()),
                ),
                ("window_start", self.time_window.start.to_rfc3339()),
                ("window_end", self.time_window.end.to_rfc3339()),
                ("quality", format!("{:?}", self.quality)),
                (
                    "bounds",
                    serde_json::to_string(&self.bounds).expect("bounds are serializable"),
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

    pub(crate) fn validate(&self) -> Result<()> {
        self.account.validate()?;
        self.region.validate()?;
        self.asset_model_id.validate()?;
        self.asset_id.validate()?;
        self.property_id.validate()?;
        self.property_alias
            .as_ref()
            .map(PropertyAlias::validate)
            .transpose()?;
        self.time_window.validate()?;
        self.bounds.validate()?;
        self.mission.validate()?;
        self.project.validate()?;
        self.work_product.validate()
    }
}

impl fmt::Debug for AwsIoTSiteWiseMeasurementScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsIoTSiteWiseMeasurementScope")
            .field("scope_digest", &self.digest())
            .field("time_window", &self.time_window)
            .field("quality", &self.quality)
            .field("bounds", &self.bounds)
            .field("mission", &self.mission)
            .field("project", &self.project)
            .field("work_product", &self.work_product)
            .finish()
    }
}

impl Serialize for AwsIoTSiteWiseMeasurementScope {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsIoTSiteWiseMeasurementScope", 14)?;
        state.serialize_field("scopeDigest", &self.digest())?;
        state.serialize_field("accountDigest", &self.account.digest())?;
        state.serialize_field("regionDigest", &self.region.digest())?;
        state.serialize_field("assetModelIdDigest", &self.asset_model_id.digest())?;
        state.serialize_field("assetIdDigest", &self.asset_id.digest())?;
        state.serialize_field("propertyIdDigest", &self.property_id.digest())?;
        state.serialize_field(
            "propertyAliasDigest",
            &self.property_alias.as_ref().map(PropertyAlias::digest),
        )?;
        state.serialize_field("timeWindow", &self.time_window)?;
        state.serialize_field("quality", &self.quality)?;
        state.serialize_field("bounds", &self.bounds)?;
        state.serialize_field("mission", &mission_projection(&self.mission))?;
        state.serialize_field("project", &project_projection(&self.project))?;
        state.serialize_field("workProduct", &work_product_projection(&self.work_product))?;
        state.end()
    }
}

/// Opaque SigV4 reference. The raw handle is intentionally never retained,
/// serialized, or printed; only a scope-bound digest is kept.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    handle_digest: Digest,
    scope_digest: Digest,
    reference_digest: Digest,
}

impl SecretReference {
    pub fn new(handle: impl AsRef<str>, scope: &AwsIoTSiteWiseMeasurementScope) -> Result<Self> {
        let handle = handle.as_ref();
        if !valid_text(handle, MAX_IDENTIFIER_BYTES, true) {
            return Err(AwsIoTSiteWiseMeasurementError::InvalidIdentifier {
                field: "secret-reference",
            });
        }
        let handle_digest = Digest::from_parts(
            "aws-iot-sitewise-sigv4-handle/v1",
            &[("handle", handle.to_owned())],
        );
        let scope_digest = scope.digest();
        let reference_digest = Digest::from_parts(
            "aws-iot-sitewise-secret-reference/v1",
            &[
                ("handle", handle_digest.as_str().to_owned()),
                ("scope", scope_digest.as_str().to_owned()),
            ],
        );
        Ok(Self {
            handle_digest,
            scope_digest,
            reference_digest,
        })
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub(crate) fn validate(&self, scope: &AwsIoTSiteWiseMeasurementScope) -> Result<()> {
        self.handle_digest.validate()?;
        self.scope_digest.validate()?;
        self.reference_digest.validate()?;
        if self.scope_digest != scope.digest()
            || self.reference_digest
                != Digest::from_parts(
                    "aws-iot-sitewise-secret-reference/v1",
                    &[
                        ("handle", self.handle_digest.as_str().to_owned()),
                        ("scope", self.scope_digest.as_str().to_owned()),
                    ],
                )
        {
            return Err(AwsIoTSiteWiseMeasurementError::ScopeMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionSnapshot {
    pub permissions: BTreeSet<String>,
}

impl PermissionSnapshot {
    pub fn new<I, S>(permissions: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let permissions = permissions.into_iter().map(Into::into).collect();
        let snapshot = Self { permissions };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn allowlisted() -> Self {
        Self {
            permissions: crate::LAYER1_PERMISSIONS
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect(),
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-iot-sitewise-permission-snapshot/v1",
            &self
                .permissions
                .iter()
                .map(|permission| ("permission", permission.clone()))
                .collect::<Vec<_>>(),
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.permissions.is_empty()
            || self
                .permissions
                .iter()
                .any(|permission| !crate::LAYER1_PERMISSIONS.contains(&permission.as_str()))
        {
            Err(AwsIoTSiteWiseMeasurementError::InvalidRequest)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentScope {
    permissions: BTreeSet<String>,
}

impl ConsentScope {
    pub fn new<I, S>(permissions: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let permissions = permissions.into_iter().map(Into::into).collect();
        let consent = Self { permissions };
        consent.validate()?;
        Ok(consent)
    }

    pub fn read_only() -> Self {
        Self {
            permissions: crate::LAYER1_PERMISSIONS
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect(),
        }
    }

    pub fn permissions(&self) -> &BTreeSet<String> {
        &self.permissions
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-iot-sitewise-consent-scope/v1",
            &self
                .permissions
                .iter()
                .map(|permission| ("permission", permission.clone()))
                .collect::<Vec<_>>(),
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.permissions.is_empty()
            || self
                .permissions
                .iter()
                .any(|permission| !crate::LAYER1_PERMISSIONS.contains(&permission.as_str()))
        {
            Err(AwsIoTSiteWiseMeasurementError::InvalidConsent)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssetProjection {
    pub asset_id_digest: Digest,
    pub asset_model_id_digest: Digest,
    pub parent_asset_id_digest: Option<Digest>,
    pub revision_digest: Option<Digest>,
}

impl AssetProjection {
    pub fn new(
        asset_model_id: impl AsRef<str>,
        asset_id: impl AsRef<str>,
        parent_asset_id: Option<&str>,
        revision: Option<&str>,
    ) -> Result<Self> {
        validate_identifier(asset_model_id.as_ref(), "asset-model")?;
        validate_identifier(asset_id.as_ref(), "asset")?;
        if let Some(parent) = parent_asset_id {
            validate_identifier(parent, "parent-asset")?;
        }
        if let Some(revision) = revision {
            validate_text(revision, "asset-revision", true)?;
        }
        Ok(Self {
            asset_id_digest: Digest::from_parts(
                "aws-iot-sitewise-asset/v1",
                &[("value", asset_id.as_ref().to_owned())],
            ),
            asset_model_id_digest: Digest::from_parts(
                "aws-iot-sitewise-asset-model/v1",
                &[("value", asset_model_id.as_ref().to_owned())],
            ),
            parent_asset_id_digest: parent_asset_id.map(|parent| {
                Digest::from_parts(
                    "aws-iot-sitewise-parent-asset/v1",
                    &[("value", parent.to_owned())],
                )
            }),
            revision_digest: revision.map(|revision| {
                Digest::from_parts(
                    "aws-iot-sitewise-asset-revision/v1",
                    &[("value", revision.to_owned())],
                )
            }),
        })
    }

    pub fn for_scope(scope: &AwsIoTSiteWiseMeasurementScope) -> Result<Self> {
        Self::new(
            scope.asset_model_id().as_str(),
            scope.asset_id().as_str(),
            None,
            Some("fixture-revision-1"),
        )
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-iot-sitewise-asset-projection/v1",
            &[
                ("asset", self.asset_id_digest.as_str().to_owned()),
                ("model", self.asset_model_id_digest.as_str().to_owned()),
                (
                    "parent",
                    self.parent_asset_id_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "revision",
                    self.revision_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssetDescription {
    pub asset: AssetProjection,
    pub property_id_digests: Vec<Digest>,
}

impl AssetDescription {
    pub fn new(
        asset_model_id: impl AsRef<str>,
        asset_id: impl AsRef<str>,
        property_ids: &[&str],
        revision: Option<&str>,
    ) -> Result<Self> {
        if property_ids.len() > MAX_PROPERTY_COUNT {
            return Err(AwsIoTSiteWiseMeasurementError::InvalidBounds);
        }
        let asset = AssetProjection::new(asset_model_id, asset_id, None, revision)?;
        let property_id_digests = property_ids
            .iter()
            .map(|property_id| {
                validate_identifier(property_id, "property")?;
                Ok(Digest::from_parts(
                    "aws-iot-sitewise-property/v1",
                    &[("value", (*property_id).to_owned())],
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            asset,
            property_id_digests,
        })
    }

    pub fn for_scope(scope: &AwsIoTSiteWiseMeasurementScope) -> Result<Self> {
        Self::new(
            scope.asset_model_id().as_str(),
            scope.asset_id().as_str(),
            &[scope.property_id().as_str()],
            Some("fixture-revision-1"),
        )
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-iot-sitewise-asset-description/v1",
            &[
                ("asset", self.asset.digest().as_str().to_owned()),
                (
                    "properties",
                    self.property_id_digests
                        .iter()
                        .map(Digest::as_str)
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
            ],
        )
    }

    pub(crate) fn validate_against(&self, scope: &AwsIoTSiteWiseMeasurementScope) -> Result<()> {
        if self.asset.asset_id_digest != scope.asset_id().digest()
            || self.asset.asset_model_id_digest != scope.asset_model_id().digest()
            || !self
                .property_id_digests
                .contains(&scope.property_id().digest())
        {
            return Err(AwsIoTSiteWiseMeasurementError::ScopeMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PropertyDescription {
    pub asset_model_id_digest: Digest,
    pub property_id_digest: Digest,
    pub property_alias_digest: Option<Digest>,
    pub data_type: SiteWiseDataType,
    pub revision_digest: Option<Digest>,
}

impl PropertyDescription {
    pub fn new(
        asset_model_id: impl AsRef<str>,
        property_id: impl AsRef<str>,
        property_alias: Option<&str>,
        data_type: SiteWiseDataType,
        revision: Option<&str>,
    ) -> Result<Self> {
        validate_identifier(asset_model_id.as_ref(), "asset-model")?;
        validate_identifier(property_id.as_ref(), "property")?;
        if let Some(alias) = property_alias {
            validate_identifier(alias, "property-alias")?;
        }
        if let Some(revision) = revision {
            validate_text(revision, "property-revision", true)?;
        }
        Ok(Self {
            asset_model_id_digest: Digest::from_parts(
                "aws-iot-sitewise-asset-model/v1",
                &[("value", asset_model_id.as_ref().to_owned())],
            ),
            property_id_digest: Digest::from_parts(
                "aws-iot-sitewise-property/v1",
                &[("value", property_id.as_ref().to_owned())],
            ),
            property_alias_digest: property_alias.map(|alias| {
                Digest::from_parts(
                    "aws-iot-sitewise-property-alias/v1",
                    &[("value", alias.to_owned())],
                )
            }),
            data_type,
            revision_digest: revision.map(|revision| {
                Digest::from_parts(
                    "aws-iot-sitewise-property-revision/v1",
                    &[("value", revision.to_owned())],
                )
            }),
        })
    }

    pub fn for_scope(scope: &AwsIoTSiteWiseMeasurementScope) -> Result<Self> {
        Self::new(
            scope.asset_model_id().as_str(),
            scope.property_id().as_str(),
            scope.property_alias().map(PropertyAlias::as_str),
            SiteWiseDataType::Double,
            Some("fixture-revision-1"),
        )
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-iot-sitewise-property-description/v1",
            &[
                ("model", self.asset_model_id_digest.as_str().to_owned()),
                ("property", self.property_id_digest.as_str().to_owned()),
                (
                    "alias",
                    self.property_alias_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                ("data_type", format!("{:?}", self.data_type)),
                (
                    "revision",
                    self.revision_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
            ],
        )
    }

    pub(crate) fn validate_against(&self, scope: &AwsIoTSiteWiseMeasurementScope) -> Result<()> {
        if self.asset_model_id_digest != scope.asset_model_id().digest()
            || self.property_id_digest != scope.property_id().digest()
            || self.property_alias_digest != scope.property_alias().map(PropertyAlias::digest)
        {
            return Err(AwsIoTSiteWiseMeasurementError::ScopeMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq)]
pub enum MeasurementValue {
    Double(f64),
    Integer(i64),
    Boolean(bool),
    String(String),
}

impl MeasurementValue {
    pub const fn data_type(&self) -> SiteWiseDataType {
        match self {
            Self::Double(_) => SiteWiseDataType::Double,
            Self::Integer(_) => SiteWiseDataType::Integer,
            Self::Boolean(_) => SiteWiseDataType::Boolean,
            Self::String(_) => SiteWiseDataType::String,
        }
    }

    pub fn digest(&self) -> Result<Digest> {
        match self {
            Self::Double(value) if value.is_finite() => Ok(Digest::from_parts(
                "aws-iot-sitewise-double-value/v1",
                &[("bits", value.to_bits().to_string())],
            )),
            Self::Integer(value) => Ok(Digest::from_parts(
                "aws-iot-sitewise-integer-value/v1",
                &[("value", value.to_string())],
            )),
            Self::Boolean(value) => Ok(Digest::from_parts(
                "aws-iot-sitewise-boolean-value/v1",
                &[("value", value.to_string())],
            )),
            Self::String(value) if valid_text(value, MAX_IDENTIFIER_BYTES, true) => {
                Ok(Digest::from_parts(
                    "aws-iot-sitewise-string-value/v1",
                    &[("value", value.clone())],
                ))
            }
            Self::Double(_) | Self::String(_) => {
                Err(AwsIoTSiteWiseMeasurementError::InvalidIdentifier {
                    field: "measurement-value",
                })
            }
        }
    }

    #[allow(clippy::cast_precision_loss)]
    fn numeric_value(&self) -> Option<f64> {
        match self {
            Self::Double(value) if value.is_finite() => Some(*value),
            Self::Integer(value) => Some(*value as f64),
            Self::Double(_) | Self::Boolean(_) | Self::String(_) => None,
        }
    }
}

impl fmt::Debug for MeasurementValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MeasurementValue")
            .field("data_type", &self.data_type())
            .field("value_digest", &self.digest().ok())
            .finish()
    }
}

#[derive(Clone, PartialEq)]
pub struct MeasurementSample {
    timestamp: DateTime<Utc>,
    quality: MeasurementQuality,
    value: MeasurementValue,
}

impl MeasurementSample {
    pub fn new(
        timestamp: DateTime<Utc>,
        quality: MeasurementQuality,
        value: MeasurementValue,
    ) -> Result<Self> {
        value.digest()?;
        Ok(Self {
            timestamp,
            quality,
            value,
        })
    }

    pub fn double(
        timestamp: DateTime<Utc>,
        quality: MeasurementQuality,
        value: f64,
    ) -> Result<Self> {
        Self::new(timestamp, quality, MeasurementValue::Double(value))
    }

    pub fn integer(
        timestamp: DateTime<Utc>,
        quality: MeasurementQuality,
        value: i64,
    ) -> Result<Self> {
        Self::new(timestamp, quality, MeasurementValue::Integer(value))
    }

    pub fn boolean(
        timestamp: DateTime<Utc>,
        quality: MeasurementQuality,
        value: bool,
    ) -> Result<Self> {
        Self::new(timestamp, quality, MeasurementValue::Boolean(value))
    }

    pub fn string(
        timestamp: DateTime<Utc>,
        quality: MeasurementQuality,
        value: impl Into<String>,
    ) -> Result<Self> {
        Self::new(timestamp, quality, MeasurementValue::String(value.into()))
    }
}

impl fmt::Debug for MeasurementSample {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MeasurementSample")
            .field(
                "timestamp_digest",
                &Digest::from_text(self.timestamp.to_rfc3339()),
            )
            .field("quality", &self.quality)
            .field("value", &self.value)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct MeasurementPoint {
    pub timestamp: DateTime<Utc>,
    pub quality: MeasurementQuality,
    pub value_kind: SiteWiseDataType,
    pub value_digest: Digest,
    pub point_digest: Digest,
}

impl fmt::Debug for MeasurementPoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MeasurementPoint")
            .field(
                "timestamp_digest",
                &Digest::from_text(self.timestamp.to_rfc3339()),
            )
            .field("quality", &self.quality)
            .field("value_kind", &self.value_kind)
            .field("value_digest", &self.value_digest)
            .field("point_digest", &self.point_digest)
            .finish()
    }
}

impl Serialize for MeasurementPoint {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("MeasurementPoint", 5)?;
        state.serialize_field(
            "timestampDigest",
            &Digest::from_text(self.timestamp.to_rfc3339()),
        )?;
        state.serialize_field("quality", &self.quality)?;
        state.serialize_field("valueKind", &self.value_kind)?;
        state.serialize_field("valueDigest", &self.value_digest)?;
        state.serialize_field("pointDigest", &self.point_digest)?;
        state.end()
    }
}

impl MeasurementPoint {
    pub fn from_sample(sample: &MeasurementSample) -> Result<Self> {
        let value_digest = sample.value.digest()?;
        let point_digest = Digest::from_parts(
            "aws-iot-sitewise-measurement-point/v1",
            &[
                ("timestamp", sample.timestamp.to_rfc3339()),
                ("quality", format!("{:?}", sample.quality)),
                ("value_kind", format!("{:?}", sample.value.data_type())),
                ("value", value_digest.as_str().to_owned()),
            ],
        );
        Ok(Self {
            timestamp: sample.timestamp,
            quality: sample.quality,
            value_kind: sample.value.data_type(),
            value_digest,
            point_digest,
        })
    }

    pub fn digest(&self) -> Digest {
        self.point_digest.clone()
    }

    pub(crate) fn validate_against(&self, scope: &AwsIoTSiteWiseMeasurementScope) -> Result<()> {
        if !scope.time_window().contains(self.timestamp) || !scope.quality().accepts(self.quality) {
            return Err(AwsIoTSiteWiseMeasurementError::MeasurementFenceViolation);
        }
        self.value_digest.validate()?;
        let expected = Digest::from_parts(
            "aws-iot-sitewise-measurement-point/v1",
            &[
                ("timestamp", self.timestamp.to_rfc3339()),
                ("quality", format!("{:?}", self.quality)),
                ("value_kind", format!("{:?}", self.value_kind)),
                ("value", self.value_digest.as_str().to_owned()),
            ],
        );
        if self.point_digest != expected {
            return Err(AwsIoTSiteWiseMeasurementError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QualityCounts {
    pub good: u32,
    pub bad: u32,
    pub uncertain: u32,
}

impl QualityCounts {
    fn add(&mut self, quality: MeasurementQuality) {
        match quality {
            MeasurementQuality::Good => self.good = self.good.saturating_add(1),
            MeasurementQuality::Bad => self.bad = self.bad.saturating_add(1),
            MeasurementQuality::Uncertain => self.uncertain = self.uncertain.saturating_add(1),
        }
    }

    fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-iot-sitewise-quality-counts/v1",
            &[
                ("good", self.good.to_string()),
                ("bad", self.bad.to_string()),
                ("uncertain", self.uncertain.to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MeasurementAggregate {
    pub count: u32,
    pub quality_counts: QualityCounts,
    pub timestamp_digest: Digest,
    pub value_digest: Digest,
    pub min_value_digest: Option<Digest>,
    pub max_value_digest: Option<Digest>,
    pub aggregate_digest: Digest,
}

impl MeasurementAggregate {
    pub fn from_samples(
        samples: &[MeasurementSample],
        points: &[MeasurementPoint],
    ) -> Result<Self> {
        if samples.len() != points.len() {
            return Err(AwsIoTSiteWiseMeasurementError::TamperedEvidence);
        }
        let mut quality_counts = QualityCounts {
            good: 0,
            bad: 0,
            uncertain: 0,
        };
        let mut timestamp_parts = Vec::with_capacity(points.len());
        let mut value_parts = Vec::with_capacity(points.len());
        let mut numeric = Vec::new();
        for (sample, point) in samples.iter().zip(points) {
            quality_counts.add(point.quality);
            timestamp_parts.push(point.timestamp.to_rfc3339());
            value_parts.push(point.value_digest.as_str().to_owned());
            if let Some(value) = sample.value.numeric_value() {
                numeric.push((value, point.value_digest.clone()));
            }
        }
        numeric.sort_by(|left, right| left.0.total_cmp(&right.0));
        let aggregate = Self {
            count: u32::try_from(points.len()).unwrap_or(u32::MAX),
            quality_counts,
            timestamp_digest: Digest::from_parts(
                "aws-iot-sitewise-timestamps/v1",
                &[("timestamps", timestamp_parts.join("\n"))],
            ),
            value_digest: Digest::from_parts(
                "aws-iot-sitewise-values/v1",
                &[("values", value_parts.join("\n"))],
            ),
            min_value_digest: numeric.first().map(|entry| entry.1.clone()),
            max_value_digest: numeric.last().map(|entry| entry.1.clone()),
            aggregate_digest: Digest::from_text("unsealed-aws-iot-sitewise-aggregate"),
        };
        Ok(aggregate.seal())
    }

    pub fn from_points(points: &[MeasurementPoint]) -> Self {
        let mut quality_counts = QualityCounts {
            good: 0,
            bad: 0,
            uncertain: 0,
        };
        let timestamp_parts = points
            .iter()
            .map(|point| point.timestamp.to_rfc3339())
            .collect::<Vec<_>>();
        let value_parts = points
            .iter()
            .map(|point| point.value_digest.as_str().to_owned())
            .collect::<Vec<_>>();
        for point in points {
            quality_counts.add(point.quality);
        }
        Self {
            count: u32::try_from(points.len()).unwrap_or(u32::MAX),
            quality_counts,
            timestamp_digest: Digest::from_parts(
                "aws-iot-sitewise-timestamps/v1",
                &[("timestamps", timestamp_parts.join("\n"))],
            ),
            value_digest: Digest::from_parts(
                "aws-iot-sitewise-values/v1",
                &[("values", value_parts.join("\n"))],
            ),
            min_value_digest: None,
            max_value_digest: None,
            aggregate_digest: Digest::from_text("unsealed-aws-iot-sitewise-aggregate"),
        }
        .seal()
    }

    pub fn merge(aggregates: &[MeasurementAggregate], points: &[MeasurementPoint]) -> Self {
        let mut merged = Self::from_points(points);
        merged.min_value_digest = aggregates
            .iter()
            .find_map(|aggregate| aggregate.min_value_digest.clone());
        merged.max_value_digest = aggregates
            .iter()
            .rev()
            .find_map(|aggregate| aggregate.max_value_digest.clone());
        merged.seal()
    }

    fn seal(mut self) -> Self {
        self.aggregate_digest = Digest::from_parts(
            "aws-iot-sitewise-measurement-aggregate/v1",
            &[
                ("count", self.count.to_string()),
                ("quality", self.quality_counts.digest().as_str().to_owned()),
                ("timestamps", self.timestamp_digest.as_str().to_owned()),
                ("values", self.value_digest.as_str().to_owned()),
                (
                    "min",
                    self.min_value_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "max",
                    self.max_value_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
            ],
        );
        self
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.timestamp_digest.validate()?;
        self.value_digest.validate()?;
        self.min_value_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.max_value_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        if self.aggregate_digest
            != (Self {
                aggregate_digest: self.aggregate_digest.clone(),
                ..self.clone()
            })
            .seal()
            .aggregate_digest
        {
            return Err(AwsIoTSiteWiseMeasurementError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SiteWiseCursor {
    scope_digest: Digest,
    binding_digest: Digest,
    token_digest: Digest,
    page_number: u16,
}

impl SiteWiseCursor {
    pub fn new(
        opaque_token: impl Into<String>,
        scope: &AwsIoTSiteWiseMeasurementScope,
        binding_digest: &Digest,
        page_number: u16,
    ) -> Result<Self> {
        let token = opaque_token.into();
        if !valid_text(&token, MAX_IDENTIFIER_BYTES, true)
            || page_number == 0
            || page_number > scope.bounds().max_pages
        {
            return Err(AwsIoTSiteWiseMeasurementError::InvalidRequest);
        }
        binding_digest.validate()?;
        Ok(Self {
            scope_digest: scope.digest(),
            binding_digest: binding_digest.clone(),
            token_digest: Digest::from_parts(
                "aws-iot-sitewise-opaque-next-token/v1",
                &[("token", token)],
            ),
            page_number,
        })
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn binding_digest(&self) -> &Digest {
        &self.binding_digest
    }

    pub fn filter_digest(&self) -> &Digest {
        &self.binding_digest
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub fn validate_against(
        &self,
        scope: &AwsIoTSiteWiseMeasurementScope,
        binding_digest: &Digest,
    ) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self.binding_digest != *binding_digest
            || self.page_number == 0
            || self.page_number > scope.bounds().max_pages
        {
            Err(AwsIoTSiteWiseMeasurementError::CursorMismatch)
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for SiteWiseCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SiteWiseCursor")
            .field("scope_digest", &self.scope_digest)
            .field("binding_digest", &self.binding_digest)
            .field("token_digest", &self.token_digest)
            .field("page_number", &self.page_number)
            .finish()
    }
}

impl Serialize for SiteWiseCursor {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("SiteWiseCursor", 4)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("bindingDigest", &self.binding_digest)?;
        state.serialize_field("tokenDigest", &self.token_digest)?;
        state.serialize_field("pageNumber", &self.page_number)?;
        state.end()
    }
}

pub type Cursor = SiteWiseCursor;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub scope_digest: Digest,
    pub list_assets_digest: Option<Digest>,
    pub describe_asset_digest: Option<Digest>,
    pub describe_property_digest: Option<Digest>,
    pub history_digest: Option<Digest>,
    pub cursor_digest: Option<Digest>,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionProjection {
    pub id_digest: Digest,
    pub revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectProjection {
    pub id_digest: Digest,
    pub revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductProjection {
    pub id_digest: Digest,
    pub revision: u64,
}

pub(crate) fn mission_projection(mission: &MissionIdentity) -> MissionProjection {
    MissionProjection {
        id_digest: mission.digest(),
        revision: mission.revision(),
    }
}

pub(crate) fn project_projection(project: &ProjectIdentity) -> ProjectProjection {
    ProjectProjection {
        id_digest: project.digest(),
        revision: project.revision(),
    }
}

pub(crate) fn work_product_projection(work_product: &WorkProductIdentity) -> WorkProductProjection {
    WorkProductProjection {
        id_digest: work_product.digest(),
        revision: work_product.revision(),
    }
}

fn validate_identifier(value: &str, field: &'static str) -> Result<()> {
    if valid_identifier(value, MAX_IDENTIFIER_BYTES, field == "property-alias") {
        Ok(())
    } else {
        Err(AwsIoTSiteWiseMeasurementError::InvalidIdentifier { field })
    }
}

fn validate_text(value: &str, field: &'static str, allow_internal_whitespace: bool) -> Result<()> {
    if valid_text(value, MAX_IDENTIFIER_BYTES, allow_internal_whitespace) {
        Ok(())
    } else {
        Err(AwsIoTSiteWiseMeasurementError::InvalidIdentifier { field })
    }
}

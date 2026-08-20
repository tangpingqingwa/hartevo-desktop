//! Bounded, redacted Amazon Detective scope and evidence models.
//!
//! The model deliberately has no representation for raw graph edges, graph
//! search queries, entity ARNs/emails, indicator text, datasource payloads,
//! CloudTrail/VPC Flow records, or credentials. Provider-facing constructors
//! may accept transient values only to hash them into a digest projection.

use std::{collections::BTreeSet, fmt, str::FromStr};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_CURSOR_BYTES: usize = 2_048;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 4;
pub const MAX_ITEMS: usize = 400;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const CURSOR_TTL_HOURS: i64 = 24;
pub const MAX_INVESTIGATION_WINDOW_HOURS: i64 = 24;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} exceeds its maximum length")]
    TooLong { field: &'static str },
    #[error("{field} contains a control character or surrounding whitespace")]
    ControlCharacter { field: &'static str },
    #[error("{field} contains unsupported characters")]
    InvalidCharacters { field: &'static str },
    #[error("{field} is invalid")]
    Invalid { field: &'static str },
    #[error("{field} must be positive")]
    MustBePositive { field: &'static str },
    #[error("{field} is not a SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} is not a bounded opaque cursor")]
    InvalidCursor { field: &'static str },
    #[error("{field} is outside the 24-hour bound")]
    InvalidTimeWindow { field: &'static str },
    #[error("{field} contains too many entries")]
    TooMany { field: &'static str },
    #[error("{field} has a duplicate entry")]
    Duplicate { field: &'static str },
    #[error("{field} does not match the bound scope")]
    ScopeMismatch { field: &'static str },
    #[error("{field} is not allowed for this operation")]
    Unsupported { field: &'static str },
    #[error("opaque cursor has expired")]
    CursorExpired,
    #[error("opaque cursor was replayed")]
    CursorReplay,
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("secret reference or registration is revoked")]
    Revoked,
}

fn validate_text(value: &str, field: &'static str, max: usize) -> Result<(), ModelError> {
    if value.is_empty() {
        return Err(ModelError::Empty { field });
    }
    if value.len() > max {
        return Err(ModelError::TooLong { field });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(ModelError::ControlCharacter { field });
    }
    if value
        .chars()
        .any(|character| !(character.is_ascii_alphanumeric() || "-_.:/+=@*".contains(character)))
    {
        return Err(ModelError::InvalidCharacters { field });
    }
    Ok(())
}

fn validate_transient_reference(value: &str, field: &'static str) -> Result<(), ModelError> {
    validate_text(value, field, MAX_IDENTIFIER_BYTES)
}

fn validate_positive(value: u64, field: &'static str) -> Result<(), ModelError> {
    if value == 0 {
        Err(ModelError::MustBePositive { field })
    } else {
        Ok(())
    }
}

/// Lower-case SHA-256 digest used as a fence or evidence handle.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into().to_ascii_lowercase();
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ModelError::InvalidDigest {
                field: "SHA-256 digest",
            });
        }
        Ok(Self(value))
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(format!("{:x}", Sha256::digest(bytes)))
    }

    pub fn from_text(value: &str) -> Self {
        Self::from_bytes(value.as_bytes())
    }

    pub fn from_parts(domain: &str, parts: &[String]) -> Self {
        let mut material = domain.to_owned();
        for part in parts {
            material.push('\u{1f}');
            material.push_str(part);
        }
        Self::from_text(&material)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_zero(&self) -> bool {
        self == &Self::zero()
    }

    pub fn zero() -> Self {
        Self("0".repeat(64))
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for Digest {
    type Err = ModelError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest::from_bytes(bytes)
}

pub fn digest_serializable<T: Serialize>(value: &T) -> Result<Digest, ModelError> {
    let bytes = serde_json::to_vec(value).map_err(|_| ModelError::Invalid {
        field: "canonical digest input",
    })?;
    Ok(Digest::from_bytes(&bytes))
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_text(&value, $field, MAX_IDENTIFIER_BYTES)?;
                Ok(Self(value))
            }

            pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
                Self::new(value)
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("digest", &Digest::from_text(self.as_str()))
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

bounded_identifier!(MissionId, "Mission id");
bounded_identifier!(ProjectId, "Project id");
bounded_identifier!(WorkProductId, "Work Product id");
bounded_identifier!(BehaviorGraphId, "behavior graph id");
bounded_identifier!(InvestigationId, "investigation id");
bounded_identifier!(IndicatorId, "indicator id");
bounded_identifier!(MemberId, "member id");
bounded_identifier!(PermissionId, "permission id");
bounded_identifier!(ProviderId, "provider id");
bounded_identifier!(ProviderRevision, "provider revision");

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AccountId(String);

impl AccountId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.len() != 12 || value.bytes().any(|byte| !byte.is_ascii_digit()) {
            return Err(ModelError::Invalid {
                field: "AWS account id",
            });
        }
        Ok(Self(value))
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        Self::new(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountId")
            .field("digest", &Digest::from_text(self.as_str()))
            .finish()
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AwsRegion(String);

impl AwsRegion {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_text(&value, "AWS region", 63)?;
        if value.starts_with('-') || value.ends_with('-') {
            return Err(ModelError::Invalid {
                field: "AWS region",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AwsRegion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsRegion")
            .field("value", &self.0)
            .finish()
    }
}

impl fmt::Display for AwsRegion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

pub type Region = AwsRegion;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        validate_positive(value, "revision")?;
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionBinding {
    pub id: MissionId,
    pub revision: Revision,
}

impl MissionBinding {
    pub fn new(id: MissionId, revision: Revision) -> Result<Self, ModelError> {
        Ok(Self { id, revision })
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.id
    }

    pub fn mission_revision(&self) -> Revision {
        self.revision
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectBinding {
    pub id: ProjectId,
    pub revision: Revision,
}

impl ProjectBinding {
    pub fn new(id: ProjectId, revision: Revision) -> Result<Self, ModelError> {
        Ok(Self { id, revision })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProductBinding {
    pub id: WorkProductId,
    pub revision: Revision,
}

impl WorkProductBinding {
    pub fn new(id: WorkProductId, revision: Revision) -> Result<Self, ModelError> {
        Ok(Self { id, revision })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BehaviorGraphBinding {
    pub id: BehaviorGraphId,
    pub revision: Revision,
}

impl BehaviorGraphBinding {
    pub fn new(id: BehaviorGraphId, revision: Revision) -> Result<Self, ModelError> {
        Ok(Self { id, revision })
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self).unwrap_or_else(|_| Digest::zero())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TimeWindow {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

impl TimeWindow {
    pub fn new(start: DateTime<Utc>, end: DateTime<Utc>) -> Result<Self, ModelError> {
        let window = Self { start, end };
        window.validate()?;
        Ok(window)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.end <= self.start {
            return Err(ModelError::InvalidTimeWindow {
                field: "time window ordering",
            });
        }
        if self.end - self.start > Duration::hours(MAX_INVESTIGATION_WINDOW_HOURS) {
            return Err(ModelError::InvalidTimeWindow {
                field: "investigation window",
            });
        }
        Ok(())
    }

    pub fn contains(&self, value: DateTime<Utc>) -> bool {
        value >= self.start && value <= self.end
    }

    pub fn contains_window(&self, value: &Self) -> bool {
        value.start >= self.start && value.end <= self.end
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self).unwrap_or_else(|_| Digest::zero())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InvestigationBinding {
    pub id: InvestigationId,
    pub revision: Revision,
    pub window: TimeWindow,
}

impl InvestigationBinding {
    pub fn new(
        id: InvestigationId,
        revision: Revision,
        window: TimeWindow,
    ) -> Result<Self, ModelError> {
        window.validate()?;
        Ok(Self {
            id,
            revision,
            window,
        })
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self).unwrap_or_else(|_| Digest::zero())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IndicatorBinding {
    pub id: IndicatorId,
    pub revision: Revision,
}

impl IndicatorBinding {
    pub fn new(id: IndicatorId, revision: Revision) -> Result<Self, ModelError> {
        Ok(Self { id, revision })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemberBinding {
    pub id: MemberId,
    pub revision: Revision,
}

impl MemberBinding {
    pub fn new(id: MemberId, revision: Revision) -> Result<Self, ModelError> {
        Ok(Self { id, revision })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum DetectiveOperation {
    ListInvestigations,
    GetInvestigation,
    ListIndicators,
    ListMembers,
}

impl DetectiveOperation {
    pub const ALL: [Self; 4] = [
        Self::ListInvestigations,
        Self::GetInvestigation,
        Self::ListIndicators,
        Self::ListMembers,
    ];

    pub const fn permission_action(self) -> PermissionAction {
        match self {
            Self::ListInvestigations => PermissionAction::ListInvestigations,
            Self::GetInvestigation => PermissionAction::GetInvestigation,
            Self::ListIndicators => PermissionAction::ListIndicators,
            Self::ListMembers => PermissionAction::ListMembers,
        }
    }
}

pub type AwsDetectiveReadOperation = DetectiveOperation;
pub type ReadOperation = DetectiveOperation;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PermissionAction {
    ListInvestigations,
    GetInvestigation,
    ListIndicators,
    ListMembers,
}

impl PermissionAction {
    pub const ALL: [Self; 4] = [
        Self::ListInvestigations,
        Self::GetInvestigation,
        Self::ListIndicators,
        Self::ListMembers,
    ];

    pub const fn aws_name(self) -> &'static str {
        match self {
            Self::ListInvestigations => "detective:ListInvestigations",
            Self::GetInvestigation => "detective:GetInvestigation",
            Self::ListIndicators => "detective:ListIndicators",
            Self::ListMembers => "detective:ListMembers",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionFence {
    pub permission_id: PermissionId,
    pub revision: Revision,
    pub actions: Vec<PermissionAction>,
    pub permission_digest: Digest,
}

impl PermissionFence {
    pub fn readonly(permission_id: PermissionId, revision: Revision) -> Result<Self, ModelError> {
        Self::new(permission_id, revision, PermissionAction::ALL.to_vec())
    }

    pub fn new(
        permission_id: PermissionId,
        revision: Revision,
        mut actions: Vec<PermissionAction>,
    ) -> Result<Self, ModelError> {
        actions.sort_unstable();
        actions.dedup();
        if actions.is_empty() || actions.len() != PermissionAction::ALL.len() {
            return Err(ModelError::Unsupported {
                field: "Detective permission allowlist",
            });
        }
        if PermissionAction::ALL
            .iter()
            .any(|action| !actions.contains(action))
        {
            return Err(ModelError::Unsupported {
                field: "Detective permission allowlist",
            });
        }
        let mut fence = Self {
            permission_id,
            revision,
            actions,
            permission_digest: Digest::zero(),
        };
        fence.permission_digest = fence.recomputed_digest();
        Ok(fence)
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serializable(&(&self.permission_id, self.revision, &self.actions))
            .unwrap_or_else(|_| Digest::zero())
    }

    pub fn digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn allows(&self, operation: DetectiveOperation) -> bool {
        self.actions.contains(&operation.permission_action())
            && self.permission_digest == self.recomputed_digest()
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.actions.len() != PermissionAction::ALL.len()
            || PermissionAction::ALL
                .iter()
                .any(|action| !self.actions.contains(action))
            || self.permission_digest != self.recomputed_digest()
        {
            return Err(ModelError::ScopeMismatch {
                field: "permission digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsDetectiveScope {
    pub account: AccountId,
    pub region: AwsRegion,
    pub behavior_graph: BehaviorGraphBinding,
    pub investigations: Vec<InvestigationBinding>,
    pub indicators: Vec<IndicatorBinding>,
    pub members: Vec<MemberBinding>,
    pub time_window: TimeWindow,
    pub mission: MissionBinding,
    pub project: ProjectBinding,
    pub work_product: WorkProductBinding,
    pub permission_digest: Digest,
}

impl AwsDetectiveScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: AccountId,
        region: AwsRegion,
        behavior_graph: BehaviorGraphBinding,
        investigations: Vec<InvestigationBinding>,
        indicators: Vec<IndicatorBinding>,
        members: Vec<MemberBinding>,
        time_window: TimeWindow,
        mission: MissionBinding,
        project: ProjectBinding,
        work_product: WorkProductBinding,
        permission_digest: Digest,
    ) -> Result<Self, ModelError> {
        let scope = Self {
            account,
            region,
            behavior_graph,
            investigations,
            indicators,
            members,
            time_window,
            mission,
            project,
            work_product,
            permission_digest,
        };
        scope.validate()?;
        Ok(scope)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_permission_fence(
        account: AccountId,
        region: AwsRegion,
        behavior_graph: BehaviorGraphBinding,
        investigations: Vec<InvestigationBinding>,
        indicators: Vec<IndicatorBinding>,
        members: Vec<MemberBinding>,
        time_window: TimeWindow,
        mission: MissionBinding,
        project: ProjectBinding,
        work_product: WorkProductBinding,
        permission: &PermissionFence,
    ) -> Result<Self, ModelError> {
        permission.validate()?;
        Self::new(
            account,
            region,
            behavior_graph,
            investigations,
            indicators,
            members,
            time_window,
            mission,
            project,
            work_product,
            permission.permission_digest.clone(),
        )
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.time_window.validate()?;
        if self.permission_digest.is_zero() {
            return Err(ModelError::Invalid {
                field: "permission digest",
            });
        }
        if self.investigations.is_empty() {
            return Err(ModelError::Empty {
                field: "investigation allowlist",
            });
        }
        if self.indicators.is_empty() {
            return Err(ModelError::Empty {
                field: "indicator allowlist",
            });
        }
        if self.members.is_empty() {
            return Err(ModelError::Empty {
                field: "member allowlist",
            });
        }
        if self.investigations.len() > MAX_ITEMS {
            return Err(ModelError::TooMany {
                field: "investigation allowlist",
            });
        }
        if self.indicators.len() > MAX_ITEMS {
            return Err(ModelError::TooMany {
                field: "indicator allowlist",
            });
        }
        if self.members.len() > MAX_ITEMS {
            return Err(ModelError::TooMany {
                field: "member allowlist",
            });
        }
        for investigation in &self.investigations {
            investigation.window.validate()?;
            if !self.time_window.contains_window(&investigation.window) {
                return Err(ModelError::ScopeMismatch {
                    field: "investigation window",
                });
            }
        }
        let investigation_ids = self
            .investigations
            .iter()
            .map(|item| item.id.clone())
            .collect::<BTreeSet<_>>();
        if investigation_ids.len() != self.investigations.len() {
            return Err(ModelError::Duplicate {
                field: "investigation allowlist",
            });
        }
        let indicator_ids = self
            .indicators
            .iter()
            .map(|item| item.id.clone())
            .collect::<BTreeSet<_>>();
        if indicator_ids.len() != self.indicators.len() {
            return Err(ModelError::Duplicate {
                field: "indicator allowlist",
            });
        }
        let member_ids = self
            .members
            .iter()
            .map(|item| item.id.clone())
            .collect::<BTreeSet<_>>();
        if member_ids.len() != self.members.len() {
            return Err(ModelError::Duplicate {
                field: "member allowlist",
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self).unwrap_or_else(|_| Digest::zero())
    }

    pub fn scope_digest(&self) -> Digest {
        self.digest()
    }

    pub fn account_id(&self) -> &AccountId {
        &self.account
    }

    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn graph(&self) -> &BehaviorGraphBinding {
        &self.behavior_graph
    }

    pub fn behavior_graph_digest(&self) -> Digest {
        self.behavior_graph.digest()
    }

    pub fn investigation_scope_digest(&self) -> Digest {
        digest_serializable(&self.investigations).unwrap_or_else(|_| Digest::zero())
    }

    pub fn indicator_scope_digest(&self) -> Digest {
        digest_serializable(&self.indicators).unwrap_or_else(|_| Digest::zero())
    }

    pub fn member_scope_digest(&self) -> Digest {
        digest_serializable(&self.members).unwrap_or_else(|_| Digest::zero())
    }

    pub fn investigation(&self, id: &InvestigationId) -> Option<&InvestigationBinding> {
        self.investigations.iter().find(|item| &item.id == id)
    }

    pub fn indicator(&self, id: &IndicatorId) -> Option<&IndicatorBinding> {
        self.indicators.iter().find(|item| &item.id == id)
    }

    pub fn member(&self, id: &MemberId) -> Option<&MemberBinding> {
        self.members.iter().find(|item| &item.id == id)
    }
}

/// Opaque SigV4 reference. The reference id is zeroized on drop and never
/// serializes; only its digest participates in registration binding.
#[derive(Clone, Eq, PartialEq)]
pub struct SigV4SecretReference {
    reference_id: String,
    region: AwsRegion,
    scope_digest: Digest,
    revision: Revision,
    revoked: bool,
}

pub type SecretReference = SigV4SecretReference;

impl SigV4SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        region: AwsRegion,
        scope_digest: Digest,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        validate_transient_reference(&reference_id, "SigV4 secret reference")?;
        if scope_digest.is_zero() {
            return Err(ModelError::Invalid {
                field: "secret scope digest",
            });
        }
        Ok(Self {
            reference_id,
            region,
            scope_digest,
            revision,
            revoked: false,
        })
    }

    pub fn for_detective(
        reference_id: impl Into<String>,
        scope: &AwsDetectiveScope,
    ) -> Result<Self, ModelError> {
        Self::new(
            reference_id,
            scope.region.clone(),
            scope.digest(),
            Revision::new(1)?,
        )
    }

    pub fn for_scope(
        reference_id: impl Into<String>,
        scope: &AwsDetectiveScope,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        Self::new(reference_id, scope.region.clone(), scope.digest(), revision)
    }

    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn signing_service(&self) -> &'static str {
        "detective"
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn revision(&self) -> Revision {
        self.revision
    }

    pub fn reference_digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-aws-detective-sigv4-secret/v1",
            &[
                self.reference_id.clone(),
                self.region.as_str().to_owned(),
                self.scope_digest.to_string(),
                self.revision.get().to_string(),
            ],
        )
    }

    pub fn is_opaque(&self) -> bool {
        true
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn ensure_active(&self) -> Result<(), ModelError> {
        if self.revoked {
            Err(ModelError::Revoked)
        } else {
            Ok(())
        }
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            return Err(ModelError::AlreadyRevoked);
        }
        self.revoked = true;
        Ok(())
    }
}

impl fmt::Debug for SigV4SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SigV4SecretReference")
            .field("reference_id", &"<opaque>")
            .field("region", &self.region)
            .field("scope_digest", &self.scope_digest)
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl Serialize for SigV4SecretReference {
    fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Err(serde::ser::Error::custom(
            "SigV4 SecretReference is opaque and non-serializing",
        ))
    }
}

impl Drop for SigV4SecretReference {
    fn drop(&mut self) {
        self.reference_id.zeroize();
    }
}

/// A cursor stores only a digest and binding metadata. Its provider token is
/// intentionally not recoverable from the object.
#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueCursor {
    token_digest: Digest,
    binding_digest: Option<Digest>,
    issued_at: DateTime<Utc>,
}

pub type Cursor = OpaqueCursor;
pub type OpaquePageToken = OpaqueCursor;

impl OpaqueCursor {
    pub fn new(value: impl AsRef<str>) -> Result<Self, ModelError> {
        Self::new_at(value, Utc::now())
    }

    pub fn new_at(value: impl AsRef<str>, issued_at: DateTime<Utc>) -> Result<Self, ModelError> {
        let value = value.as_ref();
        if value.is_empty() || value.len() > MAX_CURSOR_BYTES || value.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidCursor {
                field: "next token",
            });
        }
        Ok(Self {
            token_digest: Digest::from_parts(
                "hartevo-aws-detective-next-token/v1",
                &[value.to_owned()],
            ),
            binding_digest: None,
            issued_at,
        })
    }

    pub fn from_token(value: impl AsRef<str>) -> Result<Self, ModelError> {
        Self::new(value)
    }

    pub fn bind(&self, binding_digest: &Digest) -> Self {
        Self {
            token_digest: self.token_digest.clone(),
            binding_digest: Some(binding_digest.clone()),
            issued_at: self.issued_at,
        }
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub fn binding_digest(&self) -> Option<&Digest> {
        self.binding_digest.as_ref()
    }

    pub fn issued_at(&self) -> DateTime<Utc> {
        self.issued_at
    }

    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now < self.issued_at || now - self.issued_at > Duration::hours(CURSOR_TTL_HOURS)
    }
}

impl fmt::Debug for OpaqueCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueCursor")
            .field("token_digest", &self.token_digest)
            .field("binding_digest", &self.binding_digest)
            .field("issued_at", &self.issued_at)
            .finish()
    }
}

impl Serialize for OpaqueCursor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serializer.serialize_struct("OpaqueCursor", 1)?;
        value.serialize_field("opaque", &true)?;
        value.end()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadBounds {
    pub page_size: u16,
    pub max_pages: u16,
    pub max_items: usize,
    pub max_response_bytes: usize,
}

impl ReadBounds {
    pub fn new(page_size: u16, max_pages: u16) -> Result<Self, ModelError> {
        let bounds = Self {
            page_size,
            max_pages,
            max_items: usize::from(page_size) * usize::from(max_pages),
            max_response_bytes: MAX_RESPONSE_BYTES,
        };
        bounds.validate()?;
        Ok(bounds)
    }

    pub fn with_limits(
        page_size: u16,
        max_pages: u16,
        max_items: usize,
        max_response_bytes: usize,
    ) -> Result<Self, ModelError> {
        let bounds = Self {
            page_size,
            max_pages,
            max_items,
            max_response_bytes,
        };
        bounds.validate()?;
        Ok(bounds)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.page_size == 0 || self.page_size > MAX_PAGE_SIZE {
            return Err(ModelError::Invalid { field: "page size" });
        }
        if self.max_pages == 0 || self.max_pages > MAX_PAGES {
            return Err(ModelError::Invalid {
                field: "page count",
            });
        }
        if self.max_items == 0 || self.max_items > MAX_ITEMS {
            return Err(ModelError::Invalid {
                field: "item bound",
            });
        }
        if self.max_response_bytes == 0 || self.max_response_bytes > MAX_RESPONSE_BYTES {
            return Err(ModelError::Invalid {
                field: "response bound",
            });
        }
        Ok(())
    }
}

impl Default for ReadBounds {
    fn default() -> Self {
        Self {
            page_size: MAX_PAGE_SIZE,
            max_pages: MAX_PAGES,
            max_items: MAX_ITEMS,
            max_response_bytes: MAX_RESPONSE_BYTES,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CursorDigestMaterial<'a> {
    token_digest: &'a Digest,
    binding_digest: Option<&'a Digest>,
    issued_at: DateTime<Utc>,
}

fn cursor_digest(cursor: Option<&OpaqueCursor>) -> Option<Digest> {
    cursor.map(|value| {
        digest_serializable(&CursorDigestMaterial {
            token_digest: value.token_digest(),
            binding_digest: value.binding_digest(),
            issued_at: value.issued_at(),
        })
        .unwrap_or_else(|_| Digest::zero())
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PagedRequestDigestMaterial<'a> {
    operation: DetectiveOperation,
    graph: &'a BehaviorGraphId,
    time_window: &'a TimeWindow,
    investigation_id: Option<&'a InvestigationId>,
    investigation_revision: Option<Revision>,
    bounds: Option<ReadBounds>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListInvestigationsRequest {
    pub graph: BehaviorGraphId,
    pub time_window: TimeWindow,
    pub bounds: ReadBounds,
    pub cursor: Option<OpaqueCursor>,
}

impl ListInvestigationsRequest {
    pub fn new(
        scope: &AwsDetectiveScope,
        page_size: u16,
        max_pages: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self, ModelError> {
        let bounds = ReadBounds::new(page_size, max_pages)?;
        Self::with_bounds(scope, bounds, cursor)
    }

    pub fn with_bounds(
        scope: &AwsDetectiveScope,
        bounds: ReadBounds,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self, ModelError> {
        bounds.validate()?;
        let mut request = Self {
            graph: scope.behavior_graph.id.clone(),
            time_window: scope.time_window.clone(),
            bounds,
            cursor: None,
        };
        request.cursor = cursor.map(|value| value.bind(&request.query_digest()));
        Ok(request)
    }

    pub fn operation(&self) -> DetectiveOperation {
        DetectiveOperation::ListInvestigations
    }

    pub fn query_digest(&self) -> Digest {
        digest_serializable(&PagedRequestDigestMaterial {
            operation: self.operation(),
            graph: &self.graph,
            time_window: &self.time_window,
            investigation_id: None,
            investigation_revision: None,
            bounds: Some(self.bounds),
        })
        .unwrap_or_else(|_| Digest::zero())
    }

    pub fn request_digest(&self) -> Digest {
        digest_serializable(&(self.query_digest(), cursor_digest(self.cursor.as_ref())))
            .unwrap_or_else(|_| Digest::zero())
    }

    pub fn with_cursor(mut self, cursor: Option<OpaqueCursor>) -> Self {
        self.cursor = cursor.map(|value| value.bind(&self.query_digest()));
        self
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetInvestigationRequest {
    pub graph: BehaviorGraphId,
    pub investigation_id: InvestigationId,
    pub investigation_revision: Revision,
    pub time_window: TimeWindow,
}

impl GetInvestigationRequest {
    pub fn new(
        scope: &AwsDetectiveScope,
        investigation_id: InvestigationId,
    ) -> Result<Self, ModelError> {
        let binding = scope
            .investigation(&investigation_id)
            .ok_or(ModelError::ScopeMismatch {
                field: "investigation allowlist",
            })?;
        Ok(Self {
            graph: scope.behavior_graph.id.clone(),
            investigation_id,
            investigation_revision: binding.revision,
            time_window: binding.window.clone(),
        })
    }

    pub fn by_investigation(
        scope: &AwsDetectiveScope,
        investigation_id: InvestigationId,
    ) -> Result<Self, ModelError> {
        Self::new(scope, investigation_id)
    }

    pub fn operation(&self) -> DetectiveOperation {
        DetectiveOperation::GetInvestigation
    }

    pub fn query_digest(&self) -> Digest {
        digest_serializable(&PagedRequestDigestMaterial {
            operation: self.operation(),
            graph: &self.graph,
            time_window: &self.time_window,
            investigation_id: Some(&self.investigation_id),
            investigation_revision: Some(self.investigation_revision),
            bounds: None,
        })
        .unwrap_or_else(|_| Digest::zero())
    }

    pub fn request_digest(&self) -> Digest {
        self.query_digest()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListIndicatorsRequest {
    pub graph: BehaviorGraphId,
    pub investigation_id: InvestigationId,
    pub investigation_revision: Revision,
    pub time_window: TimeWindow,
    pub bounds: ReadBounds,
    pub cursor: Option<OpaqueCursor>,
}

impl ListIndicatorsRequest {
    pub fn new(
        scope: &AwsDetectiveScope,
        investigation_id: InvestigationId,
        page_size: u16,
        max_pages: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self, ModelError> {
        let binding = scope
            .investigation(&investigation_id)
            .ok_or(ModelError::ScopeMismatch {
                field: "investigation allowlist",
            })?;
        let bounds = ReadBounds::new(page_size, max_pages)?;
        Self::with_bounds(scope, investigation_id, binding.revision, bounds, cursor)
    }

    pub fn with_bounds(
        scope: &AwsDetectiveScope,
        investigation_id: InvestigationId,
        investigation_revision: Revision,
        bounds: ReadBounds,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self, ModelError> {
        bounds.validate()?;
        let binding = scope
            .investigation(&investigation_id)
            .ok_or(ModelError::ScopeMismatch {
                field: "investigation allowlist",
            })?;
        if binding.revision != investigation_revision {
            return Err(ModelError::ScopeMismatch {
                field: "investigation revision",
            });
        }
        let mut request = Self {
            graph: scope.behavior_graph.id.clone(),
            investigation_id,
            investigation_revision,
            time_window: binding.window.clone(),
            bounds,
            cursor: None,
        };
        request.cursor = cursor.map(|value| value.bind(&request.query_digest()));
        Ok(request)
    }

    pub fn operation(&self) -> DetectiveOperation {
        DetectiveOperation::ListIndicators
    }

    pub fn query_digest(&self) -> Digest {
        digest_serializable(&PagedRequestDigestMaterial {
            operation: self.operation(),
            graph: &self.graph,
            time_window: &self.time_window,
            investigation_id: Some(&self.investigation_id),
            investigation_revision: Some(self.investigation_revision),
            bounds: Some(self.bounds),
        })
        .unwrap_or_else(|_| Digest::zero())
    }

    pub fn request_digest(&self) -> Digest {
        digest_serializable(&(self.query_digest(), cursor_digest(self.cursor.as_ref())))
            .unwrap_or_else(|_| Digest::zero())
    }

    pub fn with_cursor(mut self, cursor: Option<OpaqueCursor>) -> Self {
        self.cursor = cursor.map(|value| value.bind(&self.query_digest()));
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListMembersRequest {
    pub graph: BehaviorGraphId,
    pub time_window: TimeWindow,
    pub bounds: ReadBounds,
    pub cursor: Option<OpaqueCursor>,
}

impl ListMembersRequest {
    pub fn new(
        scope: &AwsDetectiveScope,
        page_size: u16,
        max_pages: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self, ModelError> {
        let bounds = ReadBounds::new(page_size, max_pages)?;
        Self::with_bounds(scope, bounds, cursor)
    }

    pub fn with_bounds(
        scope: &AwsDetectiveScope,
        bounds: ReadBounds,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self, ModelError> {
        bounds.validate()?;
        let mut request = Self {
            graph: scope.behavior_graph.id.clone(),
            time_window: scope.time_window.clone(),
            bounds,
            cursor: None,
        };
        request.cursor = cursor.map(|value| value.bind(&request.query_digest()));
        Ok(request)
    }

    pub fn operation(&self) -> DetectiveOperation {
        DetectiveOperation::ListMembers
    }

    pub fn query_digest(&self) -> Digest {
        digest_serializable(&PagedRequestDigestMaterial {
            operation: self.operation(),
            graph: &self.graph,
            time_window: &self.time_window,
            investigation_id: None,
            investigation_revision: None,
            bounds: Some(self.bounds),
        })
        .unwrap_or_else(|_| Digest::zero())
    }

    pub fn request_digest(&self) -> Digest {
        digest_serializable(&(self.query_digest(), cursor_digest(self.cursor.as_ref())))
            .unwrap_or_else(|_| Digest::zero())
    }

    pub fn with_cursor(mut self, cursor: Option<OpaqueCursor>) -> Self {
        self.cursor = cursor.map(|value| value.bind(&self.query_digest()));
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum AwsDetectiveReadRequest {
    ListInvestigations(ListInvestigationsRequest),
    GetInvestigation(GetInvestigationRequest),
    ListIndicators(ListIndicatorsRequest),
    ListMembers(ListMembersRequest),
}

impl AwsDetectiveReadRequest {
    pub fn list_investigations(
        scope: &AwsDetectiveScope,
        page_size: u16,
        max_pages: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self, ModelError> {
        Ok(Self::ListInvestigations(ListInvestigationsRequest::new(
            scope, page_size, max_pages, cursor,
        )?))
    }

    pub fn get_investigation(
        scope: &AwsDetectiveScope,
        investigation_id: InvestigationId,
    ) -> Result<Self, ModelError> {
        Ok(Self::GetInvestigation(GetInvestigationRequest::new(
            scope,
            investigation_id,
        )?))
    }

    pub fn list_indicators(
        scope: &AwsDetectiveScope,
        investigation_id: InvestigationId,
        page_size: u16,
        max_pages: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self, ModelError> {
        Ok(Self::ListIndicators(ListIndicatorsRequest::new(
            scope,
            investigation_id,
            page_size,
            max_pages,
            cursor,
        )?))
    }

    pub fn list_members(
        scope: &AwsDetectiveScope,
        page_size: u16,
        max_pages: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self, ModelError> {
        Ok(Self::ListMembers(ListMembersRequest::new(
            scope, page_size, max_pages, cursor,
        )?))
    }

    pub fn operation(&self) -> DetectiveOperation {
        match self {
            Self::ListInvestigations(_) => DetectiveOperation::ListInvestigations,
            Self::GetInvestigation(_) => DetectiveOperation::GetInvestigation,
            Self::ListIndicators(_) => DetectiveOperation::ListIndicators,
            Self::ListMembers(_) => DetectiveOperation::ListMembers,
        }
    }

    pub fn query_digest(&self) -> Digest {
        match self {
            Self::ListInvestigations(request) => request.query_digest(),
            Self::GetInvestigation(request) => request.query_digest(),
            Self::ListIndicators(request) => request.query_digest(),
            Self::ListMembers(request) => request.query_digest(),
        }
    }

    pub fn request_digest(&self) -> Digest {
        match self {
            Self::ListInvestigations(request) => request.request_digest(),
            Self::GetInvestigation(request) => request.request_digest(),
            Self::ListIndicators(request) => request.request_digest(),
            Self::ListMembers(request) => request.request_digest(),
        }
    }

    pub fn cursor(&self) -> Option<&OpaqueCursor> {
        match self {
            Self::ListInvestigations(request) => request.cursor.as_ref(),
            Self::GetInvestigation(_) => None,
            Self::ListIndicators(request) => request.cursor.as_ref(),
            Self::ListMembers(request) => request.cursor.as_ref(),
        }
    }

    pub fn bounds(&self) -> Option<ReadBounds> {
        match self {
            Self::ListInvestigations(request) => Some(request.bounds),
            Self::GetInvestigation(_) => None,
            Self::ListIndicators(request) => Some(request.bounds),
            Self::ListMembers(request) => Some(request.bounds),
        }
    }

    pub fn with_cursor(self, cursor: Option<OpaqueCursor>) -> Self {
        match self {
            Self::ListInvestigations(request) => {
                Self::ListInvestigations(request.with_cursor(cursor))
            }
            Self::GetInvestigation(request) => Self::GetInvestigation(request),
            Self::ListIndicators(request) => Self::ListIndicators(request.with_cursor(cursor)),
            Self::ListMembers(request) => Self::ListMembers(request.with_cursor(cursor)),
        }
    }
}

pub type DetectiveReadRequest = AwsDetectiveReadRequest;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EntityType {
    IamUser,
    IamRole,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
    Unknown,
}

impl Severity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Informational => "INFORMATIONAL",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InvestigationState {
    Active,
    Archived,
    Unknown,
}

impl InvestigationState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "ACTIVE",
            Self::Archived => "ARCHIVED",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InvestigationStatus {
    Running,
    Failed,
    Successful,
    Unknown,
}

impl InvestigationStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Running => "RUNNING",
            Self::Failed => "FAILED",
            Self::Successful => "SUCCESSFUL",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IndicatorType {
    TtpObserved,
    ImpossibleTravel,
    FlaggedIpAddress,
    NewGeolocation,
    NewAso,
    RelatedFinding,
    RelatedFindingGroup,
    Unknown,
}

impl IndicatorType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TtpObserved => "TTP_OBSERVED",
            Self::ImpossibleTravel => "IMPOSSIBLE_TRAVEL",
            Self::FlaggedIpAddress => "FLAGGED_IP_ADDRESS",
            Self::NewGeolocation => "NEW_GEOLOCATION",
            Self::NewAso => "NEW_ASO",
            Self::RelatedFinding => "RELATED_FINDING",
            Self::RelatedFindingGroup => "RELATED_FINDING_GROUP",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IndicatorStatus {
    Observed,
    Resolved,
    Unknown,
}

impl IndicatorStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "OBSERVED",
            Self::Resolved => "RESOLVED",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MemberStatus {
    Invited,
    Accepted,
    Enabled,
    Disabled,
    Unknown,
}

impl MemberStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Invited => "INVITED",
            Self::Accepted => "ACCEPTED",
            Self::Enabled => "ENABLED",
            Self::Disabled => "DISABLED",
            Self::Unknown => "UNKNOWN",
        }
    }
}

fn optional_digest(domain: &str, value: Option<&str>) -> Option<Digest> {
    value.map(|value| Digest::from_parts(domain, &[value.to_owned()]))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InvestigationDigestMaterial<'a> {
    graph: &'a BehaviorGraphId,
    investigation_id: &'a InvestigationId,
    investigation_revision: Revision,
    entity_type: EntityType,
    entity_digest: &'a Digest,
    created_at: DateTime<Utc>,
    scope_window: &'a TimeWindow,
    severity_digest: &'a Digest,
    state_digest: &'a Digest,
    status_digest: &'a Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InvestigationProjection {
    pub graph: BehaviorGraphId,
    pub investigation_id: InvestigationId,
    pub investigation_revision: Revision,
    pub entity_type: EntityType,
    pub entity_digest: Digest,
    pub created_at: DateTime<Utc>,
    pub scope_window: TimeWindow,
    pub severity_digest: Digest,
    pub state_digest: Digest,
    pub status_digest: Digest,
    pub investigation_digest: Digest,
}

impl InvestigationProjection {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        graph: BehaviorGraphId,
        investigation_id: InvestigationId,
        investigation_revision: Revision,
        entity_type: EntityType,
        entity_reference: impl AsRef<str>,
        created_at: DateTime<Utc>,
        scope_window: TimeWindow,
        severity: Severity,
        state: InvestigationState,
        status: InvestigationStatus,
    ) -> Result<Self, ModelError> {
        validate_transient_reference(entity_reference.as_ref(), "entity reference")?;
        Self::from_digests(
            graph,
            investigation_id,
            investigation_revision,
            entity_type,
            Digest::from_parts(
                "hartevo-aws-detective-entity/v1",
                &[entity_reference.as_ref().to_owned()],
            ),
            created_at,
            scope_window,
            severity,
            state,
            status,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_digests(
        graph: BehaviorGraphId,
        investigation_id: InvestigationId,
        investigation_revision: Revision,
        entity_type: EntityType,
        entity_digest: Digest,
        created_at: DateTime<Utc>,
        scope_window: TimeWindow,
        severity: Severity,
        state: InvestigationState,
        status: InvestigationStatus,
    ) -> Result<Self, ModelError> {
        scope_window.validate()?;
        if entity_digest.is_zero() {
            return Err(ModelError::Invalid {
                field: "entity digest",
            });
        }
        let mut projection = Self {
            graph,
            investigation_id,
            investigation_revision,
            entity_type,
            entity_digest,
            created_at,
            scope_window,
            severity_digest: Digest::from_parts(
                "hartevo-aws-detective-severity/v1",
                &[severity.as_str().to_owned()],
            ),
            state_digest: Digest::from_parts(
                "hartevo-aws-detective-investigation-state/v1",
                &[state.as_str().to_owned()],
            ),
            status_digest: Digest::from_parts(
                "hartevo-aws-detective-investigation-status/v1",
                &[status.as_str().to_owned()],
            ),
            investigation_digest: Digest::zero(),
        };
        projection.investigation_digest = projection.recomputed_digest();
        Ok(projection)
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serializable(&InvestigationDigestMaterial {
            graph: &self.graph,
            investigation_id: &self.investigation_id,
            investigation_revision: self.investigation_revision,
            entity_type: self.entity_type,
            entity_digest: &self.entity_digest,
            created_at: self.created_at,
            scope_window: &self.scope_window,
            severity_digest: &self.severity_digest,
            state_digest: &self.state_digest,
            status_digest: &self.status_digest,
        })
        .unwrap_or_else(|_| Digest::zero())
    }

    pub fn verify(&self) -> Result<(), ModelError> {
        self.scope_window.validate()?;
        if self.entity_digest.is_zero() || self.investigation_digest != self.recomputed_digest() {
            return Err(ModelError::InvalidDigest {
                field: "investigation projection",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IndicatorDigestMaterial<'a> {
    graph: &'a BehaviorGraphId,
    investigation_id: &'a InvestigationId,
    investigation_revision: Revision,
    indicator_id: &'a IndicatorId,
    indicator_revision: Revision,
    indicator_type: IndicatorType,
    severity_digest: &'a Digest,
    status_digest: &'a Digest,
    tactic_digest: Option<&'a Digest>,
    technique_digest: Option<&'a Digest>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IndicatorProjection {
    pub graph: BehaviorGraphId,
    pub investigation_id: InvestigationId,
    pub investigation_revision: Revision,
    pub indicator_id: IndicatorId,
    pub indicator_revision: Revision,
    pub indicator_type: IndicatorType,
    pub severity_digest: Digest,
    pub status_digest: Digest,
    pub tactic_digest: Option<Digest>,
    pub technique_digest: Option<Digest>,
    pub indicator_digest: Digest,
}

impl IndicatorProjection {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        graph: BehaviorGraphId,
        investigation_id: InvestigationId,
        investigation_revision: Revision,
        indicator_id: IndicatorId,
        indicator_revision: Revision,
        indicator_type: IndicatorType,
        severity: Severity,
        status: IndicatorStatus,
        tactic: Option<&str>,
        technique: Option<&str>,
    ) -> Result<Self, ModelError> {
        if let Some(value) = tactic {
            validate_transient_reference(value, "tactic")?;
        }
        if let Some(value) = technique {
            validate_transient_reference(value, "technique")?;
        }
        let mut projection = Self {
            graph,
            investigation_id,
            investigation_revision,
            indicator_id,
            indicator_revision,
            indicator_type,
            severity_digest: Digest::from_parts(
                "hartevo-aws-detective-severity/v1",
                &[severity.as_str().to_owned()],
            ),
            status_digest: Digest::from_parts(
                "hartevo-aws-detective-indicator-status/v1",
                &[status.as_str().to_owned()],
            ),
            tactic_digest: optional_digest("hartevo-aws-detective-tactic/v1", tactic),
            technique_digest: optional_digest("hartevo-aws-detective-technique/v1", technique),
            indicator_digest: Digest::zero(),
        };
        projection.indicator_digest = projection.recomputed_digest();
        Ok(projection)
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serializable(&IndicatorDigestMaterial {
            graph: &self.graph,
            investigation_id: &self.investigation_id,
            investigation_revision: self.investigation_revision,
            indicator_id: &self.indicator_id,
            indicator_revision: self.indicator_revision,
            indicator_type: self.indicator_type,
            severity_digest: &self.severity_digest,
            status_digest: &self.status_digest,
            tactic_digest: self.tactic_digest.as_ref(),
            technique_digest: self.technique_digest.as_ref(),
        })
        .unwrap_or_else(|_| Digest::zero())
    }

    pub fn verify(&self) -> Result<(), ModelError> {
        if self.indicator_digest != self.recomputed_digest() {
            return Err(ModelError::InvalidDigest {
                field: "indicator projection",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MemberDigestMaterial<'a> {
    graph: &'a BehaviorGraphId,
    member_id: &'a MemberId,
    member_revision: Revision,
    account_digest: &'a Digest,
    administrator_digest: Option<&'a Digest>,
    status_digest: &'a Digest,
    updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemberProjection {
    pub graph: BehaviorGraphId,
    pub member_id: MemberId,
    pub member_revision: Revision,
    pub account_digest: Digest,
    pub administrator_digest: Option<Digest>,
    pub status_digest: Digest,
    pub updated_at: DateTime<Utc>,
    pub member_digest: Digest,
}

impl MemberProjection {
    pub fn new(
        graph: BehaviorGraphId,
        member_id: MemberId,
        member_revision: Revision,
        account_id: AccountId,
        administrator_id: Option<AccountId>,
        status: MemberStatus,
        updated_at: DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        let mut projection = Self {
            graph,
            member_id,
            member_revision,
            account_digest: Digest::from_parts(
                "hartevo-aws-detective-member-account/v1",
                &[account_id.as_str().to_owned()],
            ),
            administrator_digest: administrator_id.map(|value| {
                Digest::from_parts(
                    "hartevo-aws-detective-member-administrator/v1",
                    &[value.as_str().to_owned()],
                )
            }),
            status_digest: Digest::from_parts(
                "hartevo-aws-detective-member-status/v1",
                &[status.as_str().to_owned()],
            ),
            updated_at,
            member_digest: Digest::zero(),
        };
        projection.member_digest = projection.recomputed_digest();
        Ok(projection)
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serializable(&MemberDigestMaterial {
            graph: &self.graph,
            member_id: &self.member_id,
            member_revision: self.member_revision,
            account_digest: &self.account_digest,
            administrator_digest: self.administrator_digest.as_ref(),
            status_digest: &self.status_digest,
            updated_at: self.updated_at,
        })
        .unwrap_or_else(|_| Digest::zero())
    }

    pub fn verify(&self) -> Result<(), ModelError> {
        if self.account_digest.is_zero() || self.member_digest != self.recomputed_digest() {
            return Err(ModelError::InvalidDigest {
                field: "member projection",
            });
        }
        Ok(())
    }
}

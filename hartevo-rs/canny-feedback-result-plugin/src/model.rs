use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{CANNY_FEEDBACK_RESULT_PLUGIN_VERSION_TEXT, CANNY_PRIVACY_POLICY_VERSION};

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_LABEL_BYTES: usize = 128;
pub const MAX_WINDOW_DAYS: i64 = 31;
pub const MAX_STATUS_ALLOWLIST: usize = 16;
pub const MAX_CATEGORY_ALLOWLIST: usize = 64;
pub const MAX_POSTS: usize = 128;
pub const MAX_COMMENTS: usize = 256;
pub const MAX_VOTE_AGGREGATES: usize = 128;
pub const MAX_STATUSES: usize = 64;
pub const MAX_CATEGORIES: usize = 64;
pub const MAX_ROADMAPS: usize = 32;
pub const MAX_RESPONSE_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidIdentifier { field: &'static str },
    #[error("{field} contains a control character or surrounding whitespace")]
    InvalidText { field: &'static str },
    #[error("{field} revision must be non-zero")]
    InvalidRevision { field: &'static str },
    #[error("digest is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("timestamp must be non-negative")]
    InvalidTimestamp,
    #[error("date must be an ISO calendar date")]
    InvalidDate,
    #[error("vote window must be ordered and cover at most 31 days")]
    InvalidVoteWindow,
    #[error("the status allowlist is empty, duplicated, or too large")]
    InvalidStatusAllowlist,
    #[error("the category allowlist is empty, duplicated, or too large")]
    InvalidCategoryAllowlist,
    #[error("privacy policy is not the required strict redaction policy")]
    InvalidPrivacyPolicy,
    #[error("scope digest does not match")]
    ScopeMismatch,
    #[error("secret reference does not match the scope")]
    SecretScopeMismatch,
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("registration is invalid")]
    InvalidRegistration,
    #[error("value exceeds a Layer-1 bound")]
    BoundExceeded,
    #[error("the value is not allowlisted")]
    NotAllowlisted,
    #[error("the digest does not match immutable fields")]
    DigestMismatch,
}

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn from_fields(domain: &str, fields: &[String]) -> Self {
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for field in fields {
            append_field(&mut bytes, field);
        }
        Self::from_bytes(&bytes)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidDigest)
        }
    }

    pub fn zero() -> Self {
        Self("0".repeat(64))
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

pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("typed Canny value serializes");
    Digest::from_bytes(&bytes)
}

fn append_field(bytes: &mut Vec<u8>, field: &str) {
    bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
    bytes.extend_from_slice(field.as_bytes());
}

fn valid_identifier(value: &str, field: &'static str) -> Result<(), ModelError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || b"._:/+@~-".contains(&byte)))
    {
        Err(ModelError::InvalidIdentifier { field })
    } else {
        Ok(())
    }
}

macro_rules! identifier {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                valid_identifier(&value, $field)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_fields(
                    concat!("canny-", stringify!($name), "/v1"),
                    std::slice::from_ref(&self.0),
                )
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("digest", &self.digest())
                    .finish()
            }
        }
    };
}

identifier!(ProjectId, "Project id");
identifier!(WorkspaceId, "workspace id");
identifier!(BoardId, "board id");
identifier!(PostId, "post id");
identifier!(CommentId, "comment id");
identifier!(StatusId, "status id");
identifier!(CategoryId, "category id");
identifier!(RoadmapId, "roadmap id");
identifier!(MissionId, "Mission id");
identifier!(WorkProductId, "Work Product id");

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        if value == 0 {
            Err(ModelError::InvalidRevision { field: "revision" })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Timestamp(i64);

impl Timestamp {
    pub fn new(value: i64) -> Result<Self, ModelError> {
        if value < 0 {
            Err(ModelError::InvalidTimestamp)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn seconds(self) -> i64 {
        self.0
    }

    pub const fn utc_hour(self) -> i64 {
        self.0 / 3_600
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct UtcDate(String);

impl UtcDate {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        let valid = value.len() == 10
            && value.as_bytes().get(4) == Some(&b'-')
            && value.as_bytes().get(7) == Some(&b'-')
            && value
                .bytes()
                .enumerate()
                .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit());
        if !valid {
            return Err(ModelError::InvalidDate);
        }
        let year = value[0..4]
            .parse::<i32>()
            .map_err(|_| ModelError::InvalidDate)?;
        let month = value[5..7]
            .parse::<u8>()
            .map_err(|_| ModelError::InvalidDate)?;
        let day = value[8..10]
            .parse::<u8>()
            .map_err(|_| ModelError::InvalidDate)?;
        if !(1970..=9999).contains(&year) || !(1..=12).contains(&month) {
            return Err(ModelError::InvalidDate);
        }
        let max_day = days_in_month(year, month);
        if !(1..=max_day).contains(&day) {
            return Err(ModelError::InvalidDate);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn ordinal(&self) -> i64 {
        let year = self.0[0..4].parse::<i32>().expect("validated date year");
        let month = self.0[5..7].parse::<u8>().expect("validated date month");
        let day = self.0[8..10].parse::<u8>().expect("validated date day");
        days_from_civil(year, month, day)
    }
}

fn is_leap_year(year: i32) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_in_month(year: i32, month: u8) -> u8 {
    match month {
        2 if is_leap_year(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn days_from_civil(year: i32, month: u8, day: u8) -> i64 {
    let year = i64::from(year) - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month = i64::from(month);
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era
}

macro_rules! binding {
    ($name:ident, $id:ident, $field:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(rename_all = "camelCase")]
        pub struct $name {
            pub id: $id,
            pub revision: Revision,
        }

        impl $name {
            pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
                Ok(Self {
                    id: $id::new(id)?,
                    revision: Revision::new(revision)?,
                })
            }

            pub fn id(&self) -> &$id {
                &self.id
            }

            pub const fn revision(&self) -> Revision {
                self.revision
            }

            pub fn digest(&self) -> Digest {
                canonical_digest(self)
            }

            fn validate(&self) -> Result<(), ModelError> {
                valid_identifier(self.id.as_str(), $field)?;
                Revision::new(self.revision.get())?;
                Ok(())
            }
        }
    };
}

binding!(ProjectScope, ProjectId, "Project id");
binding!(WorkspaceScope, WorkspaceId, "workspace id");
binding!(BoardScope, BoardId, "board id");
binding!(MissionScope, MissionId, "Mission id");
binding!(WorkProductScope, WorkProductId, "Work Product id");

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PostScope {
    pub id: Option<PostId>,
    pub revision: Revision,
}

impl PostScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            id: Some(PostId::new(id)?),
            revision: Revision::new(revision)?,
        })
    }

    pub fn all(revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            id: None,
            revision: Revision::new(revision)?,
        })
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn id(&self) -> Option<&PostId> {
        self.id.as_ref()
    }

    pub fn allows(&self, id: &str) -> bool {
        self.id
            .as_ref()
            .is_none_or(|expected| expected.as_str() == id)
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    fn validate(&self) -> Result<(), ModelError> {
        if let Some(id) = &self.id {
            valid_identifier(id.as_str(), "post id")?;
        }
        Revision::new(self.revision.get())?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommentScope {
    pub id: Option<CommentId>,
    pub revision: Revision,
}

impl CommentScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            id: Some(CommentId::new(id)?),
            revision: Revision::new(revision)?,
        })
    }

    pub fn all(revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            id: None,
            revision: Revision::new(revision)?,
        })
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn id(&self) -> Option<&CommentId> {
        self.id.as_ref()
    }

    pub fn allows(&self, id: &str) -> bool {
        self.id
            .as_ref()
            .is_none_or(|expected| expected.as_str() == id)
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    fn validate(&self) -> Result<(), ModelError> {
        if let Some(id) = &self.id {
            valid_identifier(id.as_str(), "comment id")?;
        }
        Revision::new(self.revision.get())?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RoadmapScope {
    pub id: Option<RoadmapId>,
    pub revision: Revision,
}

impl RoadmapScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            id: Some(RoadmapId::new(id)?),
            revision: Revision::new(revision)?,
        })
    }

    pub fn all(revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            id: None,
            revision: Revision::new(revision)?,
        })
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn id(&self) -> Option<&RoadmapId> {
        self.id.as_ref()
    }

    pub fn allows(&self, id: &str) -> bool {
        self.id
            .as_ref()
            .is_none_or(|expected| expected.as_str() == id)
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    fn validate(&self) -> Result<(), ModelError> {
        if let Some(id) = &self.id {
            valid_identifier(id.as_str(), "roadmap id")?;
        }
        Revision::new(self.revision.get())?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VoteWindow {
    pub start: UtcDate,
    pub end: UtcDate,
    pub revision: Revision,
}

impl VoteWindow {
    pub fn new(
        start: impl Into<String>,
        end: impl Into<String>,
        revision: u64,
    ) -> Result<Self, ModelError> {
        let window = Self {
            start: UtcDate::new(start)?,
            end: UtcDate::new(end)?,
            revision: Revision::new(revision)?,
        };
        window.validate()?;
        Ok(window)
    }

    pub fn start(&self) -> &UtcDate {
        &self.start
    }

    pub fn end(&self) -> &UtcDate {
        &self.end
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn days(&self) -> i64 {
        self.end.ordinal() - self.start.ordinal() + 1
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    fn validate(&self) -> Result<(), ModelError> {
        if self.days() <= 0 || self.days() > MAX_WINDOW_DAYS {
            Err(ModelError::InvalidVoteWindow)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedbackPostStatus {
    Open,
    Planned,
    Complete,
    Duplicate,
    #[serde(rename = "under_review")]
    UnderReview,
    #[serde(rename = "in_progress")]
    InProgress,
    Unknown,
}

impl FeedbackPostStatus {
    pub fn parse(value: impl AsRef<str>) -> Self {
        match value.as_ref().trim().to_ascii_lowercase().as_str() {
            "open" => Self::Open,
            "planned" => Self::Planned,
            "complete" | "completed" | "done" => Self::Complete,
            "duplicate" | "dupe" => Self::Duplicate,
            "under review" | "under_review" | "review" => Self::UnderReview,
            "in progress" | "in_progress" | "started" => Self::InProgress,
            _ => Self::Unknown,
        }
    }

    pub const fn is_decision_status(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Planned | Self::Complete | Self::Duplicate | Self::Unknown
        )
    }
}

impl From<&str> for FeedbackPostStatus {
    fn from(value: &str) -> Self {
        Self::parse(value)
    }
}

impl From<String> for FeedbackPostStatus {
    fn from(value: String) -> Self {
        Self::parse(value)
    }
}

pub type PostStatus = FeedbackPostStatus;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusScope {
    pub revision: Revision,
    pub allowed: BTreeSet<FeedbackPostStatus>,
}

impl StatusScope {
    pub fn new<I, S>(revision: u64, allowed: I) -> Result<Self, ModelError>
    where
        I: IntoIterator<Item = S>,
        S: Into<FeedbackPostStatus>,
    {
        let allowed = allowed.into_iter().map(Into::into).collect::<BTreeSet<_>>();
        if allowed.is_empty() || allowed.len() > crate::CANNY_MAX_STATUSES.min(MAX_STATUS_ALLOWLIST)
        {
            return Err(ModelError::InvalidStatusAllowlist);
        }
        let scope = Self {
            revision: Revision::new(revision)?,
            allowed,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn strict_default(revision: u64) -> Result<Self, ModelError> {
        Self::new(
            revision,
            [
                FeedbackPostStatus::Open,
                FeedbackPostStatus::Planned,
                FeedbackPostStatus::Complete,
                FeedbackPostStatus::Duplicate,
                FeedbackPostStatus::Unknown,
            ],
        )
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn allows(&self, status: FeedbackPostStatus) -> bool {
        self.allowed.contains(&status)
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    fn validate(&self) -> Result<(), ModelError> {
        if self.allowed.is_empty() || self.allowed.len() > MAX_STATUS_ALLOWLIST {
            Err(ModelError::InvalidStatusAllowlist)
        } else {
            Revision::new(self.revision.get())?;
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CategoryScope {
    pub revision: Revision,
    pub allowed: BTreeSet<CategoryId>,
}

impl CategoryScope {
    pub fn new<I, S>(revision: u64, allowed: I) -> Result<Self, ModelError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let allowed = allowed
            .into_iter()
            .map(|value| CategoryId::new(value.into()))
            .collect::<Result<BTreeSet<_>, _>>()?;
        if allowed.is_empty() || allowed.len() > MAX_CATEGORY_ALLOWLIST {
            return Err(ModelError::InvalidCategoryAllowlist);
        }
        let scope = Self {
            revision: Revision::new(revision)?,
            allowed,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn allows(&self, id: &str) -> bool {
        self.allowed
            .iter()
            .any(|candidate| candidate.as_str() == id)
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    fn validate(&self) -> Result<(), ModelError> {
        if self.allowed.is_empty() || self.allowed.len() > MAX_CATEGORY_ALLOWLIST {
            Err(ModelError::InvalidCategoryAllowlist)
        } else {
            Revision::new(self.revision.get())?;
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivacyPolicy {
    pub version: String,
    pub raw_api_body_dropped: bool,
    pub comment_body_dropped: bool,
    pub author_identity_dropped: bool,
    pub voter_identity_dropped: bool,
    pub user_pii_dropped: bool,
    pub urls_dropped: bool,
    pub tokens_dropped: bool,
}

impl PrivacyPolicy {
    pub fn strict_v1() -> Self {
        Self {
            version: CANNY_PRIVACY_POLICY_VERSION.to_owned(),
            raw_api_body_dropped: true,
            comment_body_dropped: true,
            author_identity_dropped: true,
            voter_identity_dropped: true,
            user_pii_dropped: true,
            urls_dropped: true,
            tokens_dropped: true,
        }
    }

    pub fn is_strict(&self) -> bool {
        self == &Self::strict_v1()
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    fn validate(&self) -> Result<(), ModelError> {
        if self.is_strict() {
            Ok(())
        } else {
            Err(ModelError::InvalidPrivacyPolicy)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CannyFeedbackScope {
    pub project: ProjectScope,
    pub workspace: WorkspaceScope,
    pub board: BoardScope,
    pub post: PostScope,
    pub comment: CommentScope,
    pub vote_window: VoteWindow,
    pub status: StatusScope,
    pub category: CategoryScope,
    pub roadmap: RoadmapScope,
    pub mission: MissionScope,
    pub work_product: WorkProductScope,
    pub privacy_policy: PrivacyPolicy,
}

impl CannyFeedbackScope {
    pub fn new(
        project: ProjectScope,
        workspace: WorkspaceScope,
        board: BoardScope,
        post: PostScope,
        comment: CommentScope,
        vote_window: VoteWindow,
        status: StatusScope,
        category: CategoryScope,
        roadmap: RoadmapScope,
        mission: MissionScope,
        work_product: WorkProductScope,
        privacy_policy: PrivacyPolicy,
    ) -> Result<Self, ModelError> {
        let scope = Self {
            project,
            workspace,
            board,
            post,
            comment,
            vote_window,
            status,
            category,
            roadmap,
            mission,
            work_product,
            privacy_policy,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.project.validate()?;
        self.workspace.validate()?;
        self.board.validate()?;
        self.post.validate()?;
        self.comment.validate()?;
        self.vote_window.validate()?;
        self.status.validate()?;
        self.category.validate()?;
        self.roadmap.validate()?;
        self.mission.validate()?;
        self.work_product.validate()?;
        self.privacy_policy.validate()?;
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    pub fn project_digest(&self) -> Digest {
        self.project.digest()
    }

    pub fn mission_digest(&self) -> Digest {
        self.mission.digest()
    }

    pub fn work_product_digest(&self) -> Digest {
        self.work_product.digest()
    }

    pub fn status_digest(&self) -> Digest {
        self.status.digest()
    }

    pub fn category_digest(&self) -> Digest {
        self.category.digest()
    }
}

pub type CannyScope = CannyFeedbackScope;
pub type CannyFeedbackResultScope = CannyFeedbackScope;
pub type VoteWindowScope = VoteWindow;
pub type StatusAllowlist = StatusScope;
pub type CategoryAllowlist = CategoryScope;
pub type CannyStatusScope = StatusScope;
pub type CannyCategoryScope = CategoryScope;
pub type CannyRoadmapScope = RoadmapScope;

/// Opaque host-keyring/API-key reference. The original reference is reduced
/// to a digest immediately and is never retained or serialized.
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    revoked: bool,
}

impl SecretReference {
    pub fn new(
        reference: impl AsRef<str>,
        scope: &CannyFeedbackScope,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        let reference = reference.as_ref();
        valid_identifier(reference, "Canny API-key reference")?;
        let credential_revision = Revision::new(credential_revision)?;
        let scope_digest = scope.digest();
        let reference_digest = Digest::from_fields(
            "canny-secret-reference/v1",
            &[
                reference.to_owned(),
                scope_digest.to_string(),
                credential_revision.get().to_string(),
                "api_key".to_owned(),
            ],
        );
        Ok(Self {
            reference_digest,
            scope_digest,
            credential_revision,
            revoked: false,
        })
    }

    pub fn api_key(
        reference: impl AsRef<str>,
        scope: &CannyFeedbackScope,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        Self::new(reference, scope, credential_revision)
    }

    pub fn project_token(
        reference: impl AsRef<str>,
        scope: &CannyFeedbackScope,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        Self::new(reference, scope, credential_revision)
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn digest(&self) -> &Digest {
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

    pub const fn is_opaque(&self) -> bool {
        true
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            Err(ModelError::AlreadyRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }
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
            .field("opaque", &true)
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

impl Serialize for SecretReference {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serializer.serialize_struct("SecretReference", 1)?;
        value.serialize_field("opaque", &true)?;
        value.end()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Fixture,
    Recording,
    Fake,
    Loopback,
    #[serde(rename = "blocked_env")]
    BlockedEnv,
}

impl ProviderProvenance {
    pub const fn native(self) -> bool {
        false
    }

    pub const fn connected(self) -> bool {
        false
    }

    pub const fn first_party(self) -> bool {
        false
    }

    pub const fn is_native(self) -> bool {
        self.native()
    }

    pub const fn is_connected(self) -> bool {
        self.connected()
    }

    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CannyFeedbackResultStatus {
    Open,
    Planned,
    Complete,
    Duplicate,
    Unknown,
    Partial,
    AccessLost,
    Denied,
    #[serde(rename = "rate_limited")]
    RateLimited,
    #[serde(rename = "provider_unknown")]
    ProviderUnknown,
    Tampered,
}

impl CannyFeedbackResultStatus {
    #[allow(non_upper_case_globals)]
    pub const RateLimit: Self = Self::RateLimited;

    #[allow(non_upper_case_globals)]
    pub const Tamper: Self = Self::Tampered;
}

pub type ResultStatus = CannyFeedbackResultStatus;
pub type FeedbackResultStatus = CannyFeedbackResultStatus;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    Denied,
    RateLimited,
    AccessLost,
    Partial,
    ScopeDrift,
    SecretRevoked,
    BlockedEnv,
    ResponseTooLarge,
    MalformedResponse,
    UnexpectedShape,
    PiiDropped,
    Transport,
    Tampered,
    Unknown,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactionSummary {
    pub raw_api_body_dropped: bool,
    pub api_key_dropped: bool,
    pub feedback_text_dropped: u32,
    pub comment_body_dropped: u32,
    pub author_identity_dropped: u32,
    pub voter_identity_dropped: u32,
    pub user_pii_dropped: u32,
    pub urls_dropped: u32,
    pub tokens_dropped: u32,
    pub jira_or_project_links_dropped: u32,
}

impl RedactionSummary {
    pub const fn strict() -> Self {
        Self {
            raw_api_body_dropped: true,
            api_key_dropped: true,
            feedback_text_dropped: 0,
            comment_body_dropped: 0,
            author_identity_dropped: 0,
            voter_identity_dropped: 0,
            user_pii_dropped: 0,
            urls_dropped: 0,
            tokens_dropped: 0,
            jira_or_project_links_dropped: 0,
        }
    }

    pub fn is_strict(&self) -> bool {
        self.raw_api_body_dropped && self.api_key_dropped
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BoardEvidence {
    pub board_digest: Digest,
    pub post_count: u32,
    pub private: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PostEvidence {
    pub post_digest: Digest,
    pub status: FeedbackPostStatus,
    pub category_digest: Option<Digest>,
    pub roadmap_digests: Vec<Digest>,
    pub comment_count: u32,
    pub vote_count: u64,
    pub feedback_text_redacted: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommentEvidence {
    pub comment_digest: Digest,
    pub post_digest: Digest,
    pub body_redacted: bool,
    pub author_redacted: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VoteAggregate {
    pub post_digest: Digest,
    pub vote_window_digest: Digest,
    pub count: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusEvidence {
    pub status_change_digest: Digest,
    pub post_digest: Digest,
    pub status: FeedbackPostStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CategoryEvidence {
    pub category_digest: Digest,
    pub board_digest: Digest,
    pub post_count: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RoadmapEvidence {
    pub roadmap_digest: Digest,
    pub post_count: u32,
    pub archived: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CannyFeedbackProviderEvidence {
    pub request_digest: Digest,
    pub project_digest: Digest,
    pub scope_digest: Digest,
    pub provider_digest: Digest,
    pub secret_reference_digest: Digest,
    pub credential_revision: Revision,
    pub provenance: ProviderProvenance,
    pub status: CannyFeedbackResultStatus,
    pub error: Option<ProviderErrorKind>,
    pub board: Option<BoardEvidence>,
    pub posts: Vec<PostEvidence>,
    pub comments: Vec<CommentEvidence>,
    pub vote_aggregates: Vec<VoteAggregate>,
    pub statuses: Vec<StatusEvidence>,
    pub categories: Vec<CategoryEvidence>,
    pub roadmaps: Vec<RoadmapEvidence>,
    pub redactions: RedactionSummary,
    pub response_digest: Digest,
    pub retry_after_seconds: Option<u64>,
    pub evidence_digest: Digest,
}

pub type FeedbackEvidence = CannyFeedbackProviderEvidence;
pub type CannyFeedbackEvidence = CannyFeedbackProviderEvidence;

impl CannyFeedbackProviderEvidence {
    pub fn response_digest(&self) -> &Digest {
        &self.response_digest
    }

    pub fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }

    pub fn validate(
        &self,
        request: &crate::CannyFeedbackResultRequest,
        definition: &crate::CannyProviderDefinition,
    ) -> bool {
        if request.validate().is_err()
            || self.request_digest != *request.request_digest()
            || self.project_digest != request.scope().project.digest()
            || self.scope_digest != request.scope().digest()
            || self.provider_digest != definition.provider_digest()
            || self.secret_reference_digest == Digest::zero()
            || !self.redactions.is_strict()
            || self.posts.len() > crate::CANNY_MAX_POSTS
            || self.comments.len() > crate::CANNY_MAX_COMMENTS
            || self.vote_aggregates.len() > crate::CANNY_MAX_VOTE_AGGREGATES
            || self.statuses.len() > crate::CANNY_MAX_STATUSES
            || self.categories.len() > crate::CANNY_MAX_CATEGORIES
            || self.roadmaps.len() > crate::CANNY_MAX_ROADMAPS
            || self.posts.iter().any(|post| {
                !post.feedback_text_redacted
                    || !request.scope().status.allows(post.status)
                    || post.roadmap_digests.len() > crate::CANNY_MAX_ROADMAPS
            })
            || self.comments.iter().any(|comment| {
                !comment.body_redacted
                    || !comment.author_redacted
                    || !request.scope().post.allows_digest(&comment.post_digest)
            })
            || self.vote_aggregates.iter().any(|aggregate| {
                aggregate.vote_window_digest != request.scope().vote_window.digest()
            })
        {
            return false;
        }
        crate::provider::compute_evidence_digest(self) == self.evidence_digest
    }
}

impl PostScope {
    pub(crate) fn allows_digest(&self, digest: &Digest) -> bool {
        self.id.as_ref().is_none_or(|id| &id.digest() == digest)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CannyFeedbackRegistration {
    pub plugin_version: String,
    pub version_digest: Digest,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub project_digest: Digest,
    pub workspace_digest: Digest,
    pub board_digest: Digest,
    pub post_digest: Digest,
    pub comment_digest: Digest,
    pub vote_window_digest: Digest,
    pub status_digest: Digest,
    pub category_digest: Digest,
    pub roadmap_digest: Digest,
    pub mission_digest: Digest,
    pub work_product_digest: Digest,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: Revision,
    pub state: RegistrationState,
    pub registration_digest: Digest,
}

pub type CannyRegistration = CannyFeedbackRegistration;
pub type Registration = CannyFeedbackRegistration;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationRevocation {
    pub registration_digest: Digest,
    pub revocation_digest: Digest,
    pub registration_revision: Revision,
    pub reversible: bool,
}

impl CannyFeedbackRegistration {
    pub fn new(
        scope: &CannyFeedbackScope,
        provider_digest: Digest,
        secret: &SecretReference,
    ) -> Result<Self, ModelError> {
        scope.validate()?;
        if secret.is_revoked() {
            return Err(ModelError::AlreadyRevoked);
        }
        let scope_digest = scope.digest();
        if secret.scope_digest() != &scope_digest {
            return Err(ModelError::SecretScopeMismatch);
        }
        let version_digest = Digest::from_text(CANNY_FEEDBACK_RESULT_PLUGIN_VERSION_TEXT);
        let registration_revision = Revision::new(1)?;
        let registration_digest = Digest::from_fields(
            "canny-registration/v1",
            &[
                CANNY_FEEDBACK_RESULT_PLUGIN_VERSION_TEXT.to_owned(),
                version_digest.to_string(),
                crate::CANNY_FEEDBACK_RESULT_CONTRACT_VERSION.to_owned(),
                crate::contract_digest().to_string(),
                provider_digest.to_string(),
                scope.project.digest().to_string(),
                scope.workspace.digest().to_string(),
                scope.board.digest().to_string(),
                scope.post.digest().to_string(),
                scope.comment.digest().to_string(),
                scope.vote_window.digest().to_string(),
                scope.status.digest().to_string(),
                scope.category.digest().to_string(),
                scope.roadmap.digest().to_string(),
                scope.mission.digest().to_string(),
                scope.work_product.digest().to_string(),
                scope_digest.to_string(),
                secret.reference_digest().to_string(),
                registration_revision.get().to_string(),
            ],
        );
        Ok(Self {
            plugin_version: CANNY_FEEDBACK_RESULT_PLUGIN_VERSION_TEXT.to_owned(),
            version_digest,
            contract_version: crate::CANNY_FEEDBACK_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            provider_digest,
            project_digest: scope.project.digest(),
            workspace_digest: scope.workspace.digest(),
            board_digest: scope.board.digest(),
            post_digest: scope.post.digest(),
            comment_digest: scope.comment.digest(),
            vote_window_digest: scope.vote_window.digest(),
            status_digest: scope.status.digest(),
            category_digest: scope.category.digest(),
            roadmap_digest: scope.roadmap.digest(),
            mission_digest: scope.mission.digest(),
            work_product_digest: scope.work_product.digest(),
            scope_digest,
            secret_reference_digest: secret.reference_digest().clone(),
            registration_revision,
            state: RegistrationState::Active,
            registration_digest,
        })
    }

    pub fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }

    pub fn is_revoked(&self) -> bool {
        matches!(self.state, RegistrationState::Revoked)
    }

    pub fn ensure_active(&self) -> Result<(), ModelError> {
        if self.is_active() {
            Ok(())
        } else {
            Err(ModelError::AlreadyRevoked)
        }
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation, ModelError> {
        self.ensure_active()?;
        self.state = RegistrationState::Revoked;
        let revocation_digest = Digest::from_fields(
            "canny-registration-revocation/v1",
            &[self.registration_digest.to_string(), "revoked".to_owned()],
        );
        Ok(RegistrationRevocation {
            registration_digest: self.registration_digest.clone(),
            revocation_digest,
            registration_revision: self.registration_revision,
            reversible: true,
        })
    }

    pub fn validate_against(
        &self,
        scope: &CannyFeedbackScope,
        provider_digest: &Digest,
        secret: &SecretReference,
    ) -> Result<(), ModelError> {
        let expected = Self::new(scope, provider_digest.clone(), secret)?;
        if self.plugin_version != expected.plugin_version
            || self.version_digest != expected.version_digest
            || self.contract_version != expected.contract_version
            || self.contract_digest != expected.contract_digest
            || self.provider_digest != expected.provider_digest
            || self.project_digest != expected.project_digest
            || self.workspace_digest != expected.workspace_digest
            || self.board_digest != expected.board_digest
            || self.post_digest != expected.post_digest
            || self.comment_digest != expected.comment_digest
            || self.vote_window_digest != expected.vote_window_digest
            || self.status_digest != expected.status_digest
            || self.category_digest != expected.category_digest
            || self.roadmap_digest != expected.roadmap_digest
            || self.mission_digest != expected.mission_digest
            || self.work_product_digest != expected.work_product_digest
            || self.scope_digest != expected.scope_digest
            || self.secret_reference_digest != expected.secret_reference_digest
            || self.registration_revision != expected.registration_revision
            || self.registration_digest != expected.registration_digest
        {
            Err(ModelError::DigestMismatch)
        } else {
            Ok(())
        }
    }
}

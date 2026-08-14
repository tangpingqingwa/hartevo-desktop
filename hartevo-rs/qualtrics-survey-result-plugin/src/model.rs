use std::{fmt, time::Duration};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    MISSION_QUALTRICS_SURVEY_CONSUMER_ID, QUALTRICS_PROVIDER_ID,
    QUALTRICS_SURVEY_RESULT_CONTRACT_VERSION, QUALTRICS_SURVEY_RESULT_SCHEMA_VERSION,
    QUALTRICS_SURVEY_RESULT_SERVICE_ID,
};

pub(crate) const MAX_IDENTIFIER_BYTES: usize = 128;
pub(crate) const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub(crate) const MAX_ANSWERS: usize = 256;
pub(crate) const MAX_PAGES: usize = 8;
pub(crate) const MAX_PAGE_SIZE: usize = 64;
pub(crate) const MAX_PATH_BYTES: usize = 512;
pub(crate) const MAX_RETRY_ATTEMPTS: u8 = 3;
pub(crate) const MAX_BACKOFF_MILLISECONDS: u32 = 30_000;
pub(crate) const DEFAULT_PERMISSION_DIGEST_TEXT: &str = "qualtrics-read-only-permission/v1";

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("identifier is empty, malformed, or too long")]
    InvalidIdentifier,
    #[error("digest is not a lowercase SHA-256 hex digest")]
    InvalidDigest,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("scope is missing a required datacenter, survey, question, or response binding")]
    MissingScopeBinding,
    #[error("scope contains an invalid consent binding")]
    InvalidConsent,
    #[error("scope digest does not match its immutable fields")]
    ScopeDigestMismatch,
    #[error("bounds are empty or exceed the Layer-1 safety ceiling")]
    InvalidBounds,
    #[error("path or opaque token is empty or exceeds the safety ceiling")]
    InvalidOpaqueValue,
    #[error("answer is outside the numeric or choice allowlist")]
    InvalidAnswer,
    #[error("metadata or answer payload is malformed")]
    InvalidPayload,
    #[error("payload digest does not match the typed payload")]
    DigestMismatch,
    #[error("response export progress is not a bounded proposal")]
    InvalidExportProgress,
    #[error("duration is outside the bounded retry policy")]
    InvalidDuration,
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

    pub(crate) fn from_fields(domain: &str, fields: &[String]) -> Self {
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for field in fields {
            append_field(&mut bytes, field);
        }
        Self::from_bytes(&bytes)
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

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && !value.starts_with('.')
        && !value.ends_with('.')
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

string_identifier!(DatacenterId);
string_identifier!(OrganizationId);
string_identifier!(DivisionId);
string_identifier!(SurveyId);
string_identifier!(QuestionId);
string_identifier!(ResponseId);
string_identifier!(DistributionId);
string_identifier!(MissionId);
string_identifier!(ProjectId);
string_identifier!(ConsentId);
string_identifier!(ChoiceId);
string_identifier!(ServiceId);
string_identifier!(ProviderId);
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentStatus {
    Granted,
    Withdrawn,
    Missing,
    Expired,
}

impl ConsentStatus {
    pub const fn is_granted(self) -> bool {
        matches!(self, Self::Granted)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConsentScope {
    id: ConsentId,
    revision: Revision,
    status: ConsentStatus,
    digest: Digest,
}

impl ConsentScope {
    pub fn new(
        id: ConsentId,
        revision: Revision,
        status: ConsentStatus,
    ) -> Result<Self, ModelError> {
        let digest = Digest::from_fields(
            "qualtrics-consent-scope/v1",
            &[
                id.as_str().to_owned(),
                revision.get().to_string(),
                format!("{status:?}"),
            ],
        );
        Ok(Self {
            id,
            revision,
            status,
            digest,
        })
    }

    pub fn id(&self) -> &ConsentId {
        &self.id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub const fn status(&self) -> ConsentStatus {
        self.status
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

/// The only credential value carried by this crate is a digest of a host-owned
/// keyring reference. API tokens and OAuth material never enter this type.
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
        scope: &QualtricsScope,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        if !valid_identifier(&reference_id) {
            return Err(ModelError::InvalidIdentifier);
        }
        let credential_revision = Revision::new(credential_revision)?;
        let scope_digest = scope.scope_digest();
        let reference_digest = Digest::from_fields(
            "qualtrics-secret-reference/v1",
            &[
                reference_id,
                scope_digest.as_str().to_owned(),
                credential_revision.get().to_string(),
            ],
        );
        Ok(Self {
            reference_digest,
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

    pub fn revoke(&mut self) {
        self.revoked = true;
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QualtricsScope {
    datacenter: DatacenterId,
    organization: OrganizationId,
    division: Option<DivisionId>,
    survey: SurveyId,
    question: Option<QuestionId>,
    response: Option<ResponseId>,
    distribution: Option<DistributionId>,
    mission: MissionId,
    project: ProjectId,
    consent: ConsentScope,
    survey_revision: Revision,
    question_revision: Option<Revision>,
    response_revision: Option<Revision>,
    distribution_revision: Option<Revision>,
    mission_revision: Revision,
    project_revision: Revision,
    permission_digest: Digest,
    scope_digest: Digest,
}

impl QualtricsScope {
    pub fn new(
        datacenter: DatacenterId,
        organization: OrganizationId,
        survey: SurveyId,
        mission: MissionId,
        project: ProjectId,
        consent: ConsentId,
    ) -> Result<Self, ModelError> {
        let revision = Revision::new(1)?;
        let consent = ConsentScope::new(consent, revision, ConsentStatus::Granted)?;
        let mut scope = Self {
            datacenter,
            organization,
            division: None,
            survey,
            question: None,
            response: None,
            distribution: None,
            mission,
            project,
            consent,
            survey_revision: revision,
            question_revision: None,
            response_revision: None,
            distribution_revision: None,
            mission_revision: revision,
            project_revision: revision,
            permission_digest: Digest::from_text(DEFAULT_PERMISSION_DIGEST_TEXT),
            scope_digest: Digest::from_text("uninitialized"),
        };
        scope.refresh_digest();
        Ok(scope)
    }

    pub fn with_consent_scope(mut self, consent: ConsentScope) -> Result<Self, ModelError> {
        self.consent = consent;
        self.refresh_digest();
        Ok(self)
    }

    pub fn with_consent_status(mut self, status: ConsentStatus) -> Result<Self, ModelError> {
        self.consent = ConsentScope::new(self.consent.id.clone(), self.consent.revision, status)?;
        self.refresh_digest();
        Ok(self)
    }

    pub fn with_division(mut self, division: DivisionId) -> Self {
        self.division = Some(division);
        self.refresh_digest();
        self
    }

    pub fn with_question(mut self, question: QuestionId) -> Self {
        self.question = Some(question);
        if self.question_revision.is_none() {
            self.question_revision = Some(self.survey_revision);
        }
        self.refresh_digest();
        self
    }

    pub fn with_question_revision(mut self, question: QuestionId, revision: Revision) -> Self {
        self.question = Some(question);
        self.question_revision = Some(revision);
        self.refresh_digest();
        self
    }

    pub fn with_response(mut self, response: ResponseId) -> Self {
        self.response = Some(response);
        if self.response_revision.is_none() {
            self.response_revision = Some(self.survey_revision);
        }
        self.refresh_digest();
        self
    }

    pub fn with_response_revision(mut self, response: ResponseId, revision: Revision) -> Self {
        self.response = Some(response);
        self.response_revision = Some(revision);
        self.refresh_digest();
        self
    }

    pub fn with_distribution(mut self, distribution: DistributionId) -> Self {
        self.distribution = Some(distribution);
        if self.distribution_revision.is_none() {
            self.distribution_revision = Some(self.survey_revision);
        }
        self.refresh_digest();
        self
    }

    pub fn with_distribution_revision(
        mut self,
        distribution: DistributionId,
        revision: Revision,
    ) -> Self {
        self.distribution = Some(distribution);
        self.distribution_revision = Some(revision);
        self.refresh_digest();
        self
    }

    pub fn with_survey_revision(mut self, revision: Revision) -> Self {
        self.survey_revision = revision;
        self.refresh_digest();
        self
    }

    pub fn with_mission_revision(mut self, revision: Revision) -> Self {
        self.mission_revision = revision;
        self.refresh_digest();
        self
    }

    pub fn with_project_revision(mut self, revision: Revision) -> Self {
        self.project_revision = revision;
        self.refresh_digest();
        self
    }

    pub fn with_permission_digest(mut self, digest: Digest) -> Self {
        self.permission_digest = digest;
        self.refresh_digest();
        self
    }

    pub fn datacenter(&self) -> &DatacenterId {
        &self.datacenter
    }

    pub fn organization(&self) -> &OrganizationId {
        &self.organization
    }

    pub fn division(&self) -> Option<&DivisionId> {
        self.division.as_ref()
    }

    pub fn survey(&self) -> &SurveyId {
        &self.survey
    }

    pub fn question(&self) -> Option<&QuestionId> {
        self.question.as_ref()
    }

    pub fn response(&self) -> Option<&ResponseId> {
        self.response.as_ref()
    }

    pub fn distribution(&self) -> Option<&DistributionId> {
        self.distribution.as_ref()
    }

    pub fn mission(&self) -> &MissionId {
        &self.mission
    }

    pub fn project(&self) -> &ProjectId {
        &self.project
    }

    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    pub const fn survey_revision(&self) -> Revision {
        self.survey_revision
    }

    pub const fn question_revision(&self) -> Option<Revision> {
        self.question_revision
    }

    pub const fn response_revision(&self) -> Option<Revision> {
        self.response_revision
    }

    pub const fn distribution_revision(&self) -> Option<Revision> {
        self.distribution_revision
    }

    pub const fn mission_revision(&self) -> Revision {
        self.mission_revision
    }

    pub const fn project_revision(&self) -> Revision {
        self.project_revision
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn consent_digest(&self) -> &Digest {
        self.consent.digest()
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn require_question(&self) -> Result<&QuestionId, ModelError> {
        self.question
            .as_ref()
            .ok_or(ModelError::MissingScopeBinding)
    }

    pub fn require_response(&self) -> Result<&ResponseId, ModelError> {
        self.response
            .as_ref()
            .ok_or(ModelError::MissingScopeBinding)
    }

    pub fn require_distribution(&self) -> Result<&DistributionId, ModelError> {
        self.distribution
            .as_ref()
            .ok_or(ModelError::MissingScopeBinding)
    }

    pub fn contains_scope_digest(&self, digest: &Digest) -> bool {
        &self.scope_digest == digest
    }

    fn refresh_digest(&mut self) {
        let fields = vec![
            self.datacenter.as_str().to_owned(),
            self.organization.as_str().to_owned(),
            self.division
                .as_ref()
                .map_or_else(String::new, |value| value.as_str().to_owned()),
            self.survey.as_str().to_owned(),
            self.question
                .as_ref()
                .map_or_else(String::new, |value| value.as_str().to_owned()),
            self.response
                .as_ref()
                .map_or_else(String::new, |value| value.as_str().to_owned()),
            self.distribution
                .as_ref()
                .map_or_else(String::new, |value| value.as_str().to_owned()),
            self.mission.as_str().to_owned(),
            self.project.as_str().to_owned(),
            self.consent.id.as_str().to_owned(),
            format!("{:?}", self.consent.status),
            self.survey_revision.get().to_string(),
            self.question_revision
                .map_or_else(String::new, |value| value.get().to_string()),
            self.response_revision
                .map_or_else(String::new, |value| value.get().to_string()),
            self.distribution_revision
                .map_or_else(String::new, |value| value.get().to_string()),
            self.mission_revision.get().to_string(),
            self.project_revision.get().to_string(),
            self.permission_digest.as_str().to_owned(),
            self.consent.digest.as_str().to_owned(),
        ];
        self.scope_digest = Digest::from_fields("qualtrics-scope/v1", &fields);
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SurveyLifecycle {
    Draft,
    Active,
    Closed,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuestionKind {
    Numeric,
    Choice,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseStatus {
    Completed,
    InProgress,
    Partial,
    Expired,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportProgressState {
    Queued,
    InProgress,
    Complete,
    Expired,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SurveyMetadata {
    survey: SurveyId,
    scope_digest: Digest,
    revision: Revision,
    lifecycle: SurveyLifecycle,
    question_count: u16,
}

impl SurveyMetadata {
    pub fn new(
        survey: SurveyId,
        scope_digest: Digest,
        revision: Revision,
        lifecycle: SurveyLifecycle,
        question_count: u16,
    ) -> Result<Self, ModelError> {
        if usize::from(question_count) > MAX_ANSWERS {
            return Err(ModelError::InvalidPayload);
        }
        Ok(Self {
            survey,
            scope_digest,
            revision,
            lifecycle,
            question_count,
        })
    }

    pub fn survey(&self) -> &SurveyId {
        &self.survey
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub const fn lifecycle(&self) -> SurveyLifecycle {
        self.lifecycle
    }

    pub const fn question_count(&self) -> u16 {
        self.question_count
    }

    pub fn payload_digest(&self) -> Digest {
        Digest::from_fields(
            "qualtrics-survey-metadata/v1",
            &[
                self.survey.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.revision.get().to_string(),
                format!("{:?}", self.lifecycle),
                self.question_count.to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QuestionMetadata {
    survey: SurveyId,
    question: QuestionId,
    scope_digest: Digest,
    revision: Revision,
    kind: QuestionKind,
    choice_count: u16,
}

impl QuestionMetadata {
    pub fn new(
        survey: SurveyId,
        question: QuestionId,
        scope_digest: Digest,
        revision: Revision,
        kind: QuestionKind,
        choice_count: u16,
    ) -> Result<Self, ModelError> {
        if matches!(kind, QuestionKind::Numeric) && choice_count != 0 {
            return Err(ModelError::InvalidPayload);
        }
        if usize::from(choice_count) > MAX_ANSWERS {
            return Err(ModelError::InvalidPayload);
        }
        Ok(Self {
            survey,
            question,
            scope_digest,
            revision,
            kind,
            choice_count,
        })
    }

    pub fn survey(&self) -> &SurveyId {
        &self.survey
    }

    pub fn question(&self) -> &QuestionId {
        &self.question
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub const fn kind(&self) -> QuestionKind {
        self.kind
    }

    pub const fn choice_count(&self) -> u16 {
        self.choice_count
    }

    pub fn payload_digest(&self) -> Digest {
        Digest::from_fields(
            "qualtrics-question-metadata/v1",
            &[
                self.survey.as_str().to_owned(),
                self.question.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.revision.get().to_string(),
                format!("{:?}", self.kind),
                self.choice_count.to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResponseMetadata {
    survey: SurveyId,
    response: ResponseId,
    distribution: Option<DistributionId>,
    scope_digest: Digest,
    revision: Revision,
    status: ResponseStatus,
    recorded: bool,
}

impl ResponseMetadata {
    pub fn new(
        survey: SurveyId,
        response: ResponseId,
        distribution: Option<DistributionId>,
        scope_digest: Digest,
        revision: Revision,
        status: ResponseStatus,
        recorded: bool,
    ) -> Self {
        Self {
            survey,
            response,
            distribution,
            scope_digest,
            revision,
            status,
            recorded,
        }
    }

    pub fn survey(&self) -> &SurveyId {
        &self.survey
    }

    pub fn response(&self) -> &ResponseId {
        &self.response
    }

    pub fn distribution(&self) -> Option<&DistributionId> {
        self.distribution.as_ref()
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub const fn status(&self) -> ResponseStatus {
        self.status
    }

    pub const fn recorded(&self) -> bool {
        self.recorded
    }

    pub fn payload_digest(&self) -> Digest {
        Digest::from_fields(
            "qualtrics-response-metadata/v1",
            &[
                self.survey.as_str().to_owned(),
                self.response.as_str().to_owned(),
                self.distribution
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
                self.scope_digest.as_str().to_owned(),
                self.revision.get().to_string(),
                format!("{:?}", self.status),
                self.recorded.to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResponseStatusEvidence {
    survey: SurveyId,
    response: ResponseId,
    scope_digest: Digest,
    revision: Revision,
    status: ResponseStatus,
}

impl ResponseStatusEvidence {
    pub fn new(
        survey: SurveyId,
        response: ResponseId,
        scope_digest: Digest,
        revision: Revision,
        status: ResponseStatus,
    ) -> Self {
        Self {
            survey,
            response,
            scope_digest,
            revision,
            status,
        }
    }

    pub fn survey(&self) -> &SurveyId {
        &self.survey
    }

    pub fn response(&self) -> &ResponseId {
        &self.response
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub const fn status(&self) -> ResponseStatus {
        self.status
    }

    pub fn payload_digest(&self) -> Digest {
        Digest::from_fields(
            "qualtrics-response-status/v1",
            &[
                self.survey.as_str().to_owned(),
                self.response.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.revision.get().to_string(),
                format!("{:?}", self.status),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct BoundedNumeric {
    value: i64,
    scale: u8,
}

impl BoundedNumeric {
    pub const fn new(value: i64) -> Self {
        Self { value, scale: 0 }
    }

    pub fn scaled(value: i64, scale: u8) -> Result<Self, ModelError> {
        if scale > 6 {
            Err(ModelError::InvalidAnswer)
        } else {
            Ok(Self { value, scale })
        }
    }

    pub const fn value(self) -> i64 {
        self.value
    }

    pub const fn scale(self) -> u8 {
        self.scale
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum BoundedAnswer {
    Numeric(BoundedNumeric),
    Choice(ChoiceId),
}

impl BoundedAnswer {
    pub const fn numeric(value: i64) -> Self {
        Self::Numeric(BoundedNumeric::new(value))
    }

    pub fn scaled_numeric(value: i64, scale: u8) -> Result<Self, ModelError> {
        Ok(Self::Numeric(BoundedNumeric::scaled(value, scale)?))
    }

    pub fn choice(choice: ChoiceId) -> Self {
        Self::Choice(choice)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SurveyAnswer {
    survey: SurveyId,
    question: QuestionId,
    response: ResponseId,
    question_revision: Revision,
    response_revision: Revision,
    answer: BoundedAnswer,
}

impl SurveyAnswer {
    pub fn new(
        survey: SurveyId,
        question: QuestionId,
        response: ResponseId,
        question_revision: Revision,
        response_revision: Revision,
        answer: BoundedAnswer,
    ) -> Self {
        Self {
            survey,
            question,
            response,
            question_revision,
            response_revision,
            answer,
        }
    }

    pub fn survey(&self) -> &SurveyId {
        &self.survey
    }

    pub fn question(&self) -> &QuestionId {
        &self.question
    }

    pub fn response(&self) -> &ResponseId {
        &self.response
    }

    pub const fn question_revision(&self) -> Revision {
        self.question_revision
    }

    pub const fn response_revision(&self) -> Revision {
        self.response_revision
    }

    pub fn answer(&self) -> &BoundedAnswer {
        &self.answer
    }

    pub fn answer_digest(&self) -> Digest {
        let answer_text = match &self.answer {
            BoundedAnswer::Numeric(number) => {
                format!("numeric:{}:{}", number.value(), number.scale())
            }
            BoundedAnswer::Choice(choice) => format!("choice:{}", choice.as_str()),
        };
        Digest::from_fields(
            "qualtrics-survey-answer/v1",
            &[
                self.survey.as_str().to_owned(),
                self.question.as_str().to_owned(),
                self.response.as_str().to_owned(),
                self.question_revision.get().to_string(),
                self.response_revision.get().to_string(),
                answer_text,
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OpaquePageToken {
    digest: Digest,
}

impl OpaquePageToken {
    pub fn new(token: impl AsRef<str>) -> Result<Self, ModelError> {
        let token = token.as_ref();
        if token.is_empty() || token.len() > MAX_IDENTIFIER_BYTES * 32 {
            return Err(ModelError::InvalidOpaqueValue);
        }
        Ok(Self {
            digest: Digest::from_fields("qualtrics-page-token/v1", &[token.to_owned()]),
        })
    }

    pub fn from_digest(digest: Digest) -> Result<Self, ModelError> {
        if is_digest(digest.as_str()) {
            Ok(Self { digest })
        } else {
            Err(ModelError::InvalidDigest)
        }
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AnswerPage {
    survey: SurveyId,
    question: QuestionId,
    response: ResponseId,
    scope_digest: Digest,
    question_revision: Revision,
    response_revision: Revision,
    page_index: u16,
    answers: Vec<SurveyAnswer>,
    next_page: Option<OpaquePageToken>,
    complete: bool,
}

impl AnswerPage {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        survey: SurveyId,
        question: QuestionId,
        response: ResponseId,
        scope_digest: Digest,
        question_revision: Revision,
        response_revision: Revision,
        page_index: u16,
        answers: Vec<SurveyAnswer>,
        next_page: Option<OpaquePageToken>,
        complete: bool,
    ) -> Result<Self, ModelError> {
        if answers.len() > MAX_PAGE_SIZE {
            return Err(ModelError::InvalidPayload);
        }
        Ok(Self {
            survey,
            question,
            response,
            scope_digest,
            question_revision,
            response_revision,
            page_index,
            answers,
            next_page,
            complete,
        })
    }

    pub fn survey(&self) -> &SurveyId {
        &self.survey
    }

    pub fn question(&self) -> &QuestionId {
        &self.question
    }

    pub fn response(&self) -> &ResponseId {
        &self.response
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn question_revision(&self) -> Revision {
        self.question_revision
    }

    pub const fn response_revision(&self) -> Revision {
        self.response_revision
    }

    pub const fn page_index(&self) -> u16 {
        self.page_index
    }

    pub fn answers(&self) -> &[SurveyAnswer] {
        &self.answers
    }

    pub fn next_page(&self) -> Option<&OpaquePageToken> {
        self.next_page.as_ref()
    }

    pub const fn complete(&self) -> bool {
        self.complete
    }

    pub fn payload_digest(&self) -> Digest {
        let mut fields = vec![
            self.survey.as_str().to_owned(),
            self.question.as_str().to_owned(),
            self.response.as_str().to_owned(),
            self.scope_digest.as_str().to_owned(),
            self.question_revision.get().to_string(),
            self.response_revision.get().to_string(),
            self.page_index.to_string(),
            self.complete.to_string(),
            self.next_page
                .as_ref()
                .map_or_else(String::new, |value| value.digest.as_str().to_owned()),
        ];
        fields.extend(
            self.answers
                .iter()
                .map(|answer| answer.answer_digest().as_str().to_owned()),
        );
        Digest::from_fields("qualtrics-answer-page/v1", &fields)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OpaqueExportReference {
    digest: Digest,
}

impl OpaqueExportReference {
    pub fn new(reference: impl AsRef<str>) -> Result<Self, ModelError> {
        let reference = reference.as_ref();
        if reference.is_empty() || reference.len() > MAX_IDENTIFIER_BYTES * 32 {
            return Err(ModelError::InvalidOpaqueValue);
        }
        Ok(Self {
            digest: Digest::from_fields("qualtrics-export-reference/v1", &[reference.to_owned()]),
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResponseExportProgress {
    scope_digest: Digest,
    export_reference: Digest,
    state: ExportProgressState,
    percent: Option<u8>,
    file_available: bool,
}

impl ResponseExportProgress {
    pub fn new(
        scope_digest: Digest,
        export_reference: Digest,
        state: ExportProgressState,
        percent: Option<u8>,
    ) -> Result<Self, ModelError> {
        if percent.is_some_and(|value| value > 100) {
            return Err(ModelError::InvalidExportProgress);
        }
        if matches!(state, ExportProgressState::Complete) && percent != Some(100) {
            return Err(ModelError::InvalidExportProgress);
        }
        Ok(Self {
            scope_digest,
            export_reference,
            state,
            percent,
            file_available: false,
        })
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn export_reference(&self) -> &Digest {
        &self.export_reference
    }

    pub const fn state(&self) -> ExportProgressState {
        self.state
    }

    pub const fn percent(&self) -> Option<u8> {
        self.percent
    }

    pub const fn file_available(&self) -> bool {
        self.file_available
    }

    pub fn payload_digest(&self) -> Digest {
        Digest::from_fields(
            "qualtrics-export-progress/v1",
            &[
                self.scope_digest.as_str().to_owned(),
                self.export_reference.as_str().to_owned(),
                format!("{:?}", self.state),
                self.percent
                    .map_or_else(String::new, |value| value.to_string()),
                self.file_available.to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum QualtricsPayload {
    SurveyMetadata(SurveyMetadata),
    QuestionMetadata(QuestionMetadata),
    ResponseMetadata(ResponseMetadata),
    ResponseStatus(ResponseStatusEvidence),
    AnswerPage(AnswerPage),
    ExportProgress(ResponseExportProgress),
}

impl QualtricsPayload {
    pub fn digest(&self) -> Digest {
        match self {
            Self::SurveyMetadata(value) => value.payload_digest(),
            Self::QuestionMetadata(value) => value.payload_digest(),
            Self::ResponseMetadata(value) => value.payload_digest(),
            Self::ResponseStatus(value) => value.payload_digest(),
            Self::AnswerPage(value) => value.payload_digest(),
            Self::ExportProgress(value) => value.payload_digest(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QualtricsResultBounds {
    max_answers: usize,
    max_pages: usize,
    page_size: usize,
    max_response_bytes: usize,
    max_retry_attempts: u8,
    max_backoff: Duration,
}

impl Default for QualtricsResultBounds {
    fn default() -> Self {
        Self {
            max_answers: MAX_ANSWERS,
            max_pages: MAX_PAGES,
            page_size: MAX_PAGE_SIZE,
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_retry_attempts: MAX_RETRY_ATTEMPTS,
            max_backoff: Duration::from_millis(u64::from(MAX_BACKOFF_MILLISECONDS)),
        }
    }
}

impl QualtricsResultBounds {
    pub fn new(
        max_answers: usize,
        max_pages: usize,
        page_size: usize,
        max_response_bytes: usize,
    ) -> Result<Self, ModelError> {
        let bounds = Self {
            max_answers,
            max_pages,
            page_size,
            max_response_bytes,
            ..Self::default()
        };
        bounds.validate()?;
        Ok(bounds)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.max_answers == 0
            || self.max_answers > MAX_ANSWERS
            || self.max_pages == 0
            || self.max_pages > MAX_PAGES
            || self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
            || self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES
            || self.max_retry_attempts == 0
            || self.max_retry_attempts > MAX_RETRY_ATTEMPTS
            || self.max_backoff > Duration::from_millis(u64::from(MAX_BACKOFF_MILLISECONDS))
        {
            Err(ModelError::InvalidBounds)
        } else {
            Ok(())
        }
    }

    pub fn with_retry_policy(
        mut self,
        max_retry_attempts: u8,
        max_backoff: Duration,
    ) -> Result<Self, ModelError> {
        if max_retry_attempts == 0 || max_retry_attempts > MAX_RETRY_ATTEMPTS {
            return Err(ModelError::InvalidBounds);
        }
        if max_backoff > Duration::from_millis(u64::from(MAX_BACKOFF_MILLISECONDS)) {
            return Err(ModelError::InvalidDuration);
        }
        self.max_retry_attempts = max_retry_attempts;
        self.max_backoff = max_backoff;
        Ok(self)
    }

    pub const fn max_answers(&self) -> usize {
        self.max_answers
    }

    pub const fn max_pages(&self) -> usize {
        self.max_pages
    }

    pub const fn page_size(&self) -> usize {
        self.page_size
    }

    pub const fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }

    pub const fn max_retry_attempts(&self) -> u8 {
        self.max_retry_attempts
    }

    pub const fn max_backoff(&self) -> Duration {
        self.max_backoff
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq, Serialize)]
pub enum RegistrationState {
    #[error("active")]
    Active,
    #[error("revoked")]
    Revoked,
}

pub(crate) fn expected_service_ids_are_stable() -> bool {
    QUALTRICS_SURVEY_RESULT_SCHEMA_VERSION.starts_with("hartevo.")
        && QUALTRICS_SURVEY_RESULT_CONTRACT_VERSION.starts_with("qualtrics-")
        && QUALTRICS_SURVEY_RESULT_SERVICE_ID == "qualtrics.survey-result"
        && QUALTRICS_PROVIDER_ID == "qualtrics.rest"
        && MISSION_QUALTRICS_SURVEY_CONSUMER_ID == "mission.qualtrics-survey-result"
}

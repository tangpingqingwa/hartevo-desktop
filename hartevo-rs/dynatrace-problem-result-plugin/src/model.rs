use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{DYNATRACE_PROBLEM_RESULT_CONTRACT_VERSION, DYNATRACE_PROBLEM_RESULT_PLUGIN_VERSION};

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_ENTITY_SELECTOR_BYTES: usize = 2_000;
pub const MAX_TIME_WINDOW_MS: u64 = 7 * 24 * 60 * 60 * 1_000;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u8 = 4;
pub const MAX_PROBLEMS_PER_PAGE: usize = 100;
pub const MAX_AFFECTED_ENTITY_TYPES: usize = 32;
pub const MAX_AFFECTED_ENTITIES_PER_PROBLEM: usize = 1_024;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_NEXT_PAGE_KEY_BYTES: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ModelError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidIdentifier { field: &'static str },
    #[error("entity selector is empty, malformed, or too long")]
    InvalidEntitySelector,
    #[error("time window is empty, reversed, too long, or expires before its end")]
    InvalidTimeWindow,
    #[error("{field} must be non-zero")]
    InvalidRevision { field: &'static str },
    #[error("value is not a lowercase SHA-256 hex digest")]
    InvalidDigest,
    #[error("provider returned an unknown {field} value")]
    UnknownProviderValue { field: &'static str },
    #[error("{field} exceeds its Layer-1 bound")]
    BoundExceeded { field: &'static str },
    #[error("provider response is malformed")]
    MalformedProviderResponse,
    #[error("{field} digest does not match its immutable fields")]
    DigestMismatch { field: &'static str },
    #[error("scope or revision does not match the registration")]
    ScopeMismatch,
    #[error("secret reference is not bound to the scope")]
    SecretReferenceMismatch,
    #[error("registration is invalid")]
    InvalidRegistration,
    #[error("registration is revoked")]
    Revoked,
    #[error("registration or result has already been consumed")]
    ReplayDetected,
    #[error("provider permission is missing")]
    MissingPermission,
    #[error("native or connected provider is forbidden in Layer-1")]
    NativeProviderForbidden,
    #[error("provider API version is not the frozen Problems API v2")]
    UnsupportedApiVersion,
}

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

    pub fn from_serializable<T: Serialize>(value: &T) -> Self {
        let bytes = serde_json::to_vec(value).expect("Layer-1 canonical values serialize");
        Self::from_bytes(&bytes)
    }

    pub fn from_fields<I, S>(domain: &str, fields: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for field in fields {
            append_field(&mut bytes, field.as_ref());
        }
        Self::from_bytes(&bytes)
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

fn validate_identifier(value: &str, field: &'static str) -> Result<(), ModelError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.starts_with('.')
        || value.ends_with('.')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(ModelError::InvalidIdentifier { field });
    }
    Ok(())
}

fn validate_untrusted_identifier(value: &str, field: &'static str) -> Result<(), ModelError> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || value.chars().any(char::is_control)
    {
        return Err(ModelError::InvalidIdentifier { field });
    }
    Ok(())
}

macro_rules! identifier_type {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_identifier(&value, $field)?;
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
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
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

identifier_type!(EnvironmentId, "environment id");
identifier_type!(AccountId, "account id");
identifier_type!(ManagementZoneId, "management zone id");
identifier_type!(ProblemId, "problem id");
identifier_type!(ProjectId, "Project id");
identifier_type!(MissionId, "Mission id");
identifier_type!(WorkProductId, "Work Product id");
identifier_type!(ProviderRevision, "provider revision");

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct EntitySelector(String);

impl EntitySelector {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_ENTITY_SELECTOR_BYTES
            || value.trim() != value
            || value.chars().any(char::is_control)
            || !(value.contains("type(") || value.contains("entityId("))
        {
            return Err(ModelError::InvalidEntitySelector);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for EntitySelector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("EntitySelector")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for EntitySelector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64, field: &'static str) -> Result<Self, ModelError> {
        if value == 0 {
            Err(ModelError::InvalidRevision { field })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DynatraceProblemStatus {
    Open,
    Closed,
}

impl DynatraceProblemStatus {
    pub fn parse(value: &str) -> Result<Self, ModelError> {
        match value {
            "OPEN" => Ok(Self::Open),
            "CLOSED" => Ok(Self::Closed),
            _ => Err(ModelError::UnknownProviderValue { field: "status" }),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DynatraceSeverity {
    Availability,
    CustomAlert,
    Error,
    Info,
    MonitoringUnavailable,
    Performance,
    ResourceContention,
}

impl DynatraceSeverity {
    pub fn parse(value: &str) -> Result<Self, ModelError> {
        match value {
            "AVAILABILITY" => Ok(Self::Availability),
            "CUSTOM_ALERT" => Ok(Self::CustomAlert),
            "ERROR" => Ok(Self::Error),
            "INFO" => Ok(Self::Info),
            "MONITORING_UNAVAILABLE" => Ok(Self::MonitoringUnavailable),
            "PERFORMANCE" => Ok(Self::Performance),
            "RESOURCE_CONTENTION" => Ok(Self::ResourceContention),
            _ => Err(ModelError::UnknownProviderValue {
                field: "severityLevel",
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DynatraceImpact {
    Application,
    Environment,
    Infrastructure,
    Services,
}

impl DynatraceImpact {
    pub fn parse(value: &str) -> Result<Self, ModelError> {
        match value {
            "APPLICATION" => Ok(Self::Application),
            "ENVIRONMENT" => Ok(Self::Environment),
            "INFRASTRUCTURE" => Ok(Self::Infrastructure),
            "SERVICES" => Ok(Self::Services),
            _ => Err(ModelError::UnknownProviderValue {
                field: "impactLevel",
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProblemObservationState {
    Open,
    Closed,
    Resolved,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceState {
    Open,
    Closed,
    Resolved,
    Partial,
    Expired,
    AccessLost,
    ProviderUnknown,
    Tampered,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProviderProvenance {
    Recording,
    Fixture,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_connected(self) -> bool {
        false
    }

    pub const fn is_first_party(self) -> bool {
        false
    }

    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[allow(clippy::struct_field_names)]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TimeWindow {
    from_ms: u64,
    to_ms: u64,
    expires_at_ms: u64,
}

impl TimeWindow {
    pub fn new(from_ms: u64, to_ms: u64, expires_at_ms: u64) -> Result<Self, ModelError> {
        if from_ms >= to_ms || to_ms - from_ms > MAX_TIME_WINDOW_MS || expires_at_ms <= to_ms {
            return Err(ModelError::InvalidTimeWindow);
        }
        Ok(Self {
            from_ms,
            to_ms,
            expires_at_ms,
        })
    }

    pub fn with_default_expiry(from_ms: u64, to_ms: u64) -> Result<Self, ModelError> {
        let expires_at_ms = to_ms
            .checked_add(MAX_TIME_WINDOW_MS)
            .ok_or(ModelError::InvalidTimeWindow)?;
        Self::new(from_ms, to_ms, expires_at_ms)
    }

    pub const fn from_ms(&self) -> u64 {
        self.from_ms
    }

    pub const fn to_ms(&self) -> u64 {
        self.to_ms
    }

    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    pub const fn is_expired(&self, at_ms: u64) -> bool {
        at_ms >= self.expires_at_ms
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DynatraceProblemScopeInput {
    pub environment_id: String,
    pub account_id: String,
    pub management_zone_id: String,
    pub entity_selector: String,
    pub problem_id: Option<String>,
    pub from_ms: u64,
    pub to_ms: u64,
    pub expires_at_ms: u64,
    pub project_id: String,
    pub project_revision: u64,
    pub mission_id: String,
    pub mission_revision: u64,
    pub work_product_id: String,
    pub work_product_revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DynatraceProblemScope {
    environment_id: EnvironmentId,
    account_id: AccountId,
    management_zone_id: ManagementZoneId,
    entity_selector: EntitySelector,
    problem_id: Option<ProblemId>,
    time_window: TimeWindow,
    project_id: ProjectId,
    project_revision: Revision,
    mission_id: MissionId,
    mission_revision: Revision,
    work_product_id: WorkProductId,
    work_product_revision: Revision,
}

impl DynatraceProblemScope {
    pub fn new(input: DynatraceProblemScopeInput) -> Result<Self, ModelError> {
        Ok(Self {
            environment_id: EnvironmentId::new(input.environment_id)?,
            account_id: AccountId::new(input.account_id)?,
            management_zone_id: ManagementZoneId::new(input.management_zone_id)?,
            entity_selector: EntitySelector::new(input.entity_selector)?,
            problem_id: input.problem_id.map(ProblemId::new).transpose()?,
            time_window: TimeWindow::new(input.from_ms, input.to_ms, input.expires_at_ms)?,
            project_id: ProjectId::new(input.project_id)?,
            project_revision: Revision::new(input.project_revision, "Project revision")?,
            mission_id: MissionId::new(input.mission_id)?,
            mission_revision: Revision::new(input.mission_revision, "Mission revision")?,
            work_product_id: WorkProductId::new(input.work_product_id)?,
            work_product_revision: Revision::new(
                input.work_product_revision,
                "Work Product revision",
            )?,
        })
    }

    pub fn environment_id(&self) -> &EnvironmentId {
        &self.environment_id
    }

    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    pub fn management_zone_id(&self) -> &ManagementZoneId {
        &self.management_zone_id
    }

    pub fn entity_selector(&self) -> &EntitySelector {
        &self.entity_selector
    }

    pub fn problem_id(&self) -> Option<&ProblemId> {
        self.problem_id.as_ref()
    }

    pub fn time_window(&self) -> &TimeWindow {
        &self.time_window
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub const fn project_revision(&self) -> Revision {
        self.project_revision
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub const fn mission_revision(&self) -> Revision {
        self.mission_revision
    }

    pub fn work_product_id(&self) -> &WorkProductId {
        &self.work_product_id
    }

    pub const fn work_product_revision(&self) -> Revision {
        self.work_product_revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

/// Host-owned reference to an access token. The actual token and the supplied
/// reference string are never retained and this type intentionally implements
/// neither `Serialize` nor `Deserialize`.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    revision: Revision,
}

impl SecretReference {
    pub fn new(
        opaque_reference: impl AsRef<str>,
        scope: &DynatraceProblemScope,
        revision: u64,
    ) -> Result<Self, ModelError> {
        let opaque_reference = opaque_reference.as_ref();
        validate_untrusted_identifier(opaque_reference, "opaque access-token reference")?;
        Ok(Self {
            reference_digest: Digest::from_text(opaque_reference),
            scope_digest: scope.digest(),
            revision: Revision::new(revision, "credential revision")?,
        })
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference", &"<opaque>")
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("revision", &self.revision)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AffectedEntityProjection {
    pub entity_type_digest: Digest,
    pub count: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProblemProjection {
    pub problem_id_digest: Digest,
    pub state: ProblemObservationState,
    pub status: DynatraceProblemStatus,
    pub severity: DynatraceSeverity,
    pub impact: DynatraceImpact,
    pub start_time_ms: u64,
    pub end_time_ms: Option<u64>,
    pub affected_entity_types: Vec<AffectedEntityProjection>,
}

impl ProblemProjection {
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.affected_entity_types.len() > MAX_AFFECTED_ENTITY_TYPES
            || self
                .affected_entity_types
                .iter()
                .any(|item| item.count == 0)
        {
            return Err(ModelError::BoundExceeded {
                field: "affected entity type projection",
            });
        }
        if let Some(end_time_ms) = self.end_time_ms
            && end_time_ms < self.start_time_ms
        {
            return Err(ModelError::MalformedProviderResponse);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DynatraceProblemEvidence {
    pub contract_version: String,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub provider_revision: ProviderRevision,
    pub provenance: ProviderProvenance,
    pub state: EvidenceState,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub native_evidence: bool,
    pub truth_authority: bool,
    pub consent_authority: bool,
    pub effect_authority: bool,
    pub receipt_authority: bool,
    pub verification_authority: bool,
    pub outcome_authority: bool,
    pub root_cause_claim: bool,
    pub work_product_adoption: bool,
    pub partial: bool,
    pub page_count: u8,
    pub page_digests: Vec<Digest>,
    pub problems: Vec<ProblemProjection>,
    pub result_digest: Digest,
}

impl DynatraceProblemEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope_digest: Digest,
        registration_digest: Digest,
        provider_digest: Digest,
        provider_revision: ProviderRevision,
        provenance: ProviderProvenance,
        state: EvidenceState,
        partial: bool,
        page_digests: Vec<Digest>,
        problems: Vec<ProblemProjection>,
    ) -> Result<Self, ModelError> {
        if page_digests.len() > MAX_PAGES as usize
            || problems.len() > MAX_PAGES as usize * MAX_PROBLEMS_PER_PAGE
        {
            return Err(ModelError::BoundExceeded {
                field: "result projection",
            });
        }
        for problem in &problems {
            problem.validate()?;
        }
        let page_count =
            u8::try_from(page_digests.len()).map_err(|_| ModelError::BoundExceeded {
                field: "page count",
            })?;
        let mut evidence = Self {
            contract_version: DYNATRACE_PROBLEM_RESULT_CONTRACT_VERSION.to_owned(),
            scope_digest,
            registration_digest,
            provider_digest,
            provider_revision,
            provenance,
            state,
            connected: false,
            native: false,
            first_party: false,
            native_evidence: false,
            truth_authority: false,
            consent_authority: false,
            effect_authority: false,
            receipt_authority: false,
            verification_authority: false,
            outcome_authority: false,
            root_cause_claim: false,
            work_product_adoption: false,
            partial,
            page_count,
            page_digests,
            problems,
            result_digest: Digest::from_text("uncomputed"),
        };
        evidence.result_digest = evidence.compute_result_digest()?;
        Ok(evidence)
    }

    pub fn compute_result_digest(&self) -> Result<Digest, ModelError> {
        let mut value =
            serde_json::to_value(self).map_err(|_| ModelError::MalformedProviderResponse)?;
        let object = value
            .as_object_mut()
            .ok_or(ModelError::MalformedProviderResponse)?;
        object.remove("resultDigest");
        Ok(Digest::from_serializable(&value))
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.contract_version != DYNATRACE_PROBLEM_RESULT_CONTRACT_VERSION
            || self.connected
            || self.native
            || self.first_party
            || self.native_evidence
            || self.truth_authority
            || self.consent_authority
            || self.effect_authority
            || self.receipt_authority
            || self.verification_authority
            || self.outcome_authority
            || self.root_cause_claim
            || self.work_product_adoption
            || self.page_count as usize != self.page_digests.len()
            || self.page_digests.len() > MAX_PAGES as usize
            || self.problems.len() > MAX_PAGES as usize * MAX_PROBLEMS_PER_PAGE
        {
            return Err(ModelError::MalformedProviderResponse);
        }
        for problem in &self.problems {
            problem.validate()?;
        }
        if self.compute_result_digest()? != self.result_digest {
            return Err(ModelError::DigestMismatch { field: "result" });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DynatraceRegistration {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub secret_revision: Revision,
    pub registration_digest: Digest,
    pub active: bool,
}

impl DynatraceRegistration {
    pub fn new(
        provider_digest: Digest,
        scope: &DynatraceProblemScope,
        secret: &SecretReference,
    ) -> Result<Self, ModelError> {
        if secret.scope_digest() != &scope.digest() {
            return Err(ModelError::SecretReferenceMismatch);
        }
        let scope_digest = scope.digest();
        let contract_digest = crate::contract_digest();
        let registration_digest = Digest::from_fields(
            "dynatrace-problem-result-registration/v1",
            [
                DYNATRACE_PROBLEM_RESULT_PLUGIN_VERSION,
                DYNATRACE_PROBLEM_RESULT_CONTRACT_VERSION,
                contract_digest.as_str(),
                provider_digest.as_str(),
                scope_digest.as_str(),
                secret.reference_digest().as_str(),
                &secret.revision().get().to_string(),
            ],
        );
        Ok(Self {
            plugin_version: DYNATRACE_PROBLEM_RESULT_PLUGIN_VERSION.to_owned(),
            contract_version: DYNATRACE_PROBLEM_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest,
            provider_digest,
            scope_digest,
            secret_reference_digest: secret.reference_digest().clone(),
            secret_revision: secret.revision(),
            registration_digest,
            active: true,
        })
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if !self.active {
            return Err(ModelError::Revoked);
        }
        self.active = false;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), ModelError> {
        self.active = true;
        Ok(())
    }

    pub fn validate_against(
        &self,
        scope: &DynatraceProblemScope,
        secret: &SecretReference,
    ) -> Result<(), ModelError> {
        if self.plugin_version != DYNATRACE_PROBLEM_RESULT_PLUGIN_VERSION
            || self.contract_version != DYNATRACE_PROBLEM_RESULT_CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.scope_digest != scope.digest()
            || self.secret_reference_digest != *secret.reference_digest()
            || self.secret_revision != secret.revision()
        {
            return Err(ModelError::InvalidRegistration);
        }
        Ok(())
    }
}

pub(crate) fn project_entity_type_counts(
    values: impl IntoIterator<Item = String>,
) -> Result<Vec<AffectedEntityProjection>, ModelError> {
    let mut counts = BTreeMap::<String, u32>::new();
    for value in values {
        validate_untrusted_identifier(&value, "affected entity type")?;
        let entry = counts.entry(value).or_default();
        *entry = entry.checked_add(1).ok_or(ModelError::BoundExceeded {
            field: "affected entity count",
        })?;
    }
    if counts.len() > MAX_AFFECTED_ENTITY_TYPES {
        return Err(ModelError::BoundExceeded {
            field: "affected entity types",
        });
    }
    Ok(counts
        .into_iter()
        .map(|(entity_type, count)| AffectedEntityProjection {
            entity_type_digest: Digest::from_text(entity_type),
            count,
        })
        .collect())
}

pub(crate) fn validate_raw_identifier(value: &str, field: &'static str) -> Result<(), ModelError> {
    validate_untrusted_identifier(value, field)
}

#[cfg(test)]
mod model_tests {
    use super::*;

    fn input() -> DynatraceProblemScopeInput {
        DynatraceProblemScopeInput {
            environment_id: "env-1".into(),
            account_id: "acct-1".into(),
            management_zone_id: "mz-1".into(),
            entity_selector: "type(\"HOST\")".into(),
            problem_id: Some("problem-1".into()),
            from_ms: 1_000,
            to_ms: 2_000,
            expires_at_ms: 3_000,
            project_id: "project-1".into(),
            project_revision: 1,
            mission_id: "mission-1".into(),
            mission_revision: 1,
            work_product_id: "work-product-1".into(),
            work_product_revision: 1,
        }
    }

    #[test]
    fn scope_and_secret_are_digest_bound_without_serializing_the_secret() {
        let scope = DynatraceProblemScope::new(input()).expect("valid scope");
        let secret = SecretReference::new("vault/dynatrace/access-token", &scope, 1)
            .expect("valid opaque reference");
        assert_eq!(secret.scope_digest(), &scope.digest());
        assert!(!format!("{secret:?}").contains("vault/dynatrace"));
        let serialized_scope = serde_json::to_string(&scope).expect("scope serializes");
        assert!(serialized_scope.contains("environmentId"));
        assert!(!serialized_scope.contains("access-token"));
    }

    #[test]
    fn time_window_and_scope_reject_adversarial_inputs() {
        assert!(TimeWindow::new(2, 1, 3).is_err());
        assert!(TimeWindow::new(1, MAX_TIME_WINDOW_MS + 2, MAX_TIME_WINDOW_MS + 3).is_err());
        assert!(EntitySelector::new("name(\"unbounded\")").is_err());
        assert!(ProjectId::new("../project").is_err());
    }
}

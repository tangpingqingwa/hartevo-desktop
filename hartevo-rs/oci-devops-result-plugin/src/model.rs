//! Bounded OCI DevOps scope, payload normalization, and evidence digests.
//!
//! The transport decoders use raw OCI JSON only transiently. The public types
//! retain OCIDs, bounded lifecycle/stage states, revisions, timestamps,
//! counts, and cryptographic metadata fingerprints; raw logs, artifact bytes,
//! URLs, environment values, and secret material are never represented.

use std::{
    collections::BTreeMap,
    fmt,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use chrono::{DateTime, Utc};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer, de::Error as DeError, ser::SerializeStruct,
};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    OCI_DEVOPS_API_VERSION, OCI_DEVOPS_MAX_ARTIFACT_METADATA, OCI_DEVOPS_MAX_BUILD_RUNS,
    OCI_DEVOPS_MAX_DEPLOYMENTS, OCI_DEVOPS_MAX_PAGES, OCI_DEVOPS_MAX_RESULTS,
    OCI_DEVOPS_MAX_STAGES, OCI_DEVOPS_MAX_WORK_REQUESTS, OCI_DEVOPS_RESULT_CONTRACT_VERSION,
    OCI_DEVOPS_RESULT_PLUGIN_VERSION_TEXT,
};

pub const MAX_IDENTIFIER_LENGTH: usize = 512;
pub const MAX_STATE_LENGTH: usize = crate::OCI_DEVOPS_MAX_STATE_BYTES;
pub const MAX_NEXT_PAGE_TOKEN_LENGTH: usize = crate::OCI_DEVOPS_MAX_NEXT_PAGE_TOKEN_BYTES;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} exceeds its maximum length")]
    TooLong { field: &'static str },
    #[error("{field} contains a control character")]
    ControlCharacter { field: &'static str },
    #[error("{field} contains whitespace where it is not allowed")]
    Whitespace { field: &'static str },
    #[error("{field} is not a valid bounded value")]
    Invalid { field: &'static str },
    #[error("{field} must be positive")]
    MustBePositive { field: &'static str },
    #[error("{field} is not a SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} is not a valid OCI region")]
    InvalidRegion { field: &'static str },
    #[error("next page token is invalid")]
    InvalidCursor,
}

fn validate_text(
    value: &str,
    field: &'static str,
    max: usize,
    allow_internal_whitespace: bool,
) -> Result<(), ModelError> {
    if value.is_empty() {
        return Err(ModelError::Empty { field });
    }
    if value.len() > max {
        return Err(ModelError::TooLong { field });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(ModelError::ControlCharacter { field });
    }
    if !allow_internal_whitespace && value.chars().any(char::is_whitespace) {
        return Err(ModelError::Whitespace { field });
    }
    Ok(())
}

fn validate_scope_component(value: &str) -> Result<(), ModelError> {
    if value
        .chars()
        .any(|character| matches!(character, '/' | '?' | '#'))
    {
        return Err(ModelError::Invalid {
            field: "OCI scope component",
        });
    }
    Ok(())
}

fn validate_positive(value: u64, field: &'static str) -> Result<(), ModelError> {
    if value == 0 {
        Err(ModelError::MustBePositive { field })
    } else {
        Ok(())
    }
}

macro_rules! bounded_string {
    ($name:ident, $field:literal, $max:expr, $allow_internal_whitespace:expr) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_text(&value, $field, $max, $allow_internal_whitespace)?;
                Ok(Self(value))
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

        impl FromStr for $name {
            type Err = ModelError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse(value)
            }
        }
    };
}

bounded_string!(OciRegion, "OCI region", MAX_IDENTIFIER_LENGTH, false);
bounded_string!(Ocid, "OCI resource OCID", MAX_IDENTIFIER_LENGTH, false);
bounded_string!(MissionId, "Mission id", MAX_IDENTIFIER_LENGTH, false);
bounded_string!(
    HartevoProjectId,
    "Hartevo Project id",
    MAX_IDENTIFIER_LENGTH,
    false
);
bounded_string!(
    WorkProductId,
    "Work Product id",
    MAX_IDENTIFIER_LENGTH,
    false
);
bounded_string!(
    ProviderRevision,
    "provider revision",
    MAX_IDENTIFIER_LENGTH,
    false
);
bounded_string!(
    StateValue,
    "OCI lifecycle or stage state",
    MAX_STATE_LENGTH,
    false
);

pub type TenancyId = Ocid;
pub type CompartmentId = Ocid;
pub type OciProjectId = Ocid;
pub type PipelineId = Ocid;
pub type BuildRunId = Ocid;
pub type DeploymentId = Ocid;
pub type WorkRequestId = Ocid;
pub type ResourceId = Ocid;

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.len() != 64
            || value
                .bytes()
                .any(|byte| !(byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
        {
            return Err(ModelError::InvalidDigest { field: "digest" });
        }
        Ok(Self(value))
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(format!("{:x}", Sha256::digest(bytes)))
    }

    pub fn from_fields(domain: &str, fields: &[String]) -> Self {
        let mut input = domain.as_bytes().to_vec();
        for field in fields {
            input.push(0);
            input.extend_from_slice(field.as_bytes());
        }
        Self::from_bytes(&input)
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

pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest::from_bytes(bytes)
}

pub fn digest_serializable<T: Serialize>(value: &T) -> Result<Digest, ModelError> {
    let bytes = serde_json::to_vec(value).map_err(|_| ModelError::Invalid {
        field: "canonical digest input",
    })?;
    Ok(sha256_digest(&bytes))
}

/// An opaque host-keyring reference. It intentionally implements neither
/// Serialize nor Deserialize; only its digest enters a registration.
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: u64,
    revoked: Arc<AtomicBool>,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_digest: self.reference_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            credential_revision: self.credential_revision,
            revoked: Arc::clone(&self.revoked),
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
            .field("revoked", &self.is_revoked())
            .finish()
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest
            && self.scope_digest == other.scope_digest
            && self.credential_revision == other.credential_revision
            && self.is_revoked() == other.is_revoked()
    }
}

impl Eq for SecretReference {}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope: &OciDevopsScope,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        validate_text(
            &reference_id,
            "OCI signing-key reference id",
            MAX_IDENTIFIER_LENGTH,
            false,
        )?;
        validate_positive(credential_revision, "credential revision")?;
        let scope_digest = scope.digest();
        let reference_digest = Digest::from_fields(
            "hartevo-oci-signing-key-reference/v1",
            &[
                reference_id,
                scope_digest.to_string(),
                credential_revision.to_string(),
            ],
        );
        Ok(Self {
            reference_digest,
            scope_digest,
            credential_revision,
            revoked: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn credential_revision(&self) -> u64 {
        self.credential_revision
    }

    pub const fn is_opaque(&self) -> bool {
        true
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::Acquire)
    }

    pub fn revoke(&self) -> Result<(), ModelError> {
        if self.revoked.swap(true, Ordering::AcqRel) {
            Err(ModelError::Invalid {
                field: "already revoked secret reference",
            })
        } else {
            Ok(())
        }
    }
}

pub type OciSigningKeySecretReference = SecretReference;

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OciDevopsScopeInput {
    pub region: String,
    pub tenancy_id: String,
    pub compartment_id: String,
    pub oci_project_id: String,
    pub pipeline_id: String,
    pub build_id: String,
    pub deployment_id: String,
    pub work_request_id: String,
    pub permission_digest: Digest,
    pub mission_id: String,
    pub mission_revision: u64,
    pub hartevo_project_id: String,
    pub project_revision: u64,
    pub work_product_id: String,
    pub work_product_revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OciDevopsScope {
    region: OciRegion,
    tenancy_id: TenancyId,
    compartment_id: CompartmentId,
    oci_project_id: OciProjectId,
    pipeline_id: PipelineId,
    build_id: BuildRunId,
    deployment_id: DeploymentId,
    work_request_id: WorkRequestId,
    permission_digest: Digest,
    mission_id: MissionId,
    mission_revision: u64,
    hartevo_project_id: HartevoProjectId,
    project_revision: u64,
    work_product_id: WorkProductId,
    work_product_revision: u64,
}

impl OciDevopsScope {
    pub fn new(input: OciDevopsScopeInput) -> Result<Self, ModelError> {
        let region = OciRegion::parse(input.region)?;
        if region.as_str().contains('.') || region.as_str().contains('/') {
            return Err(ModelError::InvalidRegion {
                field: "OCI region",
            });
        }
        if input.permission_digest == Digest::zero() {
            return Err(ModelError::Invalid {
                field: "permission digest",
            });
        }
        for component in [
            &input.tenancy_id,
            &input.compartment_id,
            &input.oci_project_id,
            &input.pipeline_id,
            &input.build_id,
            &input.deployment_id,
            &input.work_request_id,
        ] {
            validate_scope_component(component)?;
        }
        validate_positive(input.mission_revision, "Mission revision")?;
        validate_positive(input.project_revision, "Project revision")?;
        validate_positive(input.work_product_revision, "Work Product revision")?;
        Ok(Self {
            region,
            tenancy_id: Ocid::parse(input.tenancy_id)?,
            compartment_id: Ocid::parse(input.compartment_id)?,
            oci_project_id: Ocid::parse(input.oci_project_id)?,
            pipeline_id: Ocid::parse(input.pipeline_id)?,
            build_id: Ocid::parse(input.build_id)?,
            deployment_id: Ocid::parse(input.deployment_id)?,
            work_request_id: Ocid::parse(input.work_request_id)?,
            permission_digest: input.permission_digest,
            mission_id: MissionId::parse(input.mission_id)?,
            mission_revision: input.mission_revision,
            hartevo_project_id: HartevoProjectId::parse(input.hartevo_project_id)?,
            project_revision: input.project_revision,
            work_product_id: WorkProductId::parse(input.work_product_id)?,
            work_product_revision: input.work_product_revision,
        })
    }

    pub fn region(&self) -> &str {
        self.region.as_str()
    }

    pub fn tenancy_id(&self) -> &str {
        self.tenancy_id.as_str()
    }

    pub fn compartment_id(&self) -> &str {
        self.compartment_id.as_str()
    }

    pub fn oci_project_id(&self) -> &str {
        self.oci_project_id.as_str()
    }

    pub fn pipeline_id(&self) -> &str {
        self.pipeline_id.as_str()
    }

    pub fn build_id(&self) -> &str {
        self.build_id.as_str()
    }

    pub fn deployment_id(&self) -> &str {
        self.deployment_id.as_str()
    }

    pub fn work_request_id(&self) -> &str {
        self.work_request_id.as_str()
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn mission_id(&self) -> &str {
        self.mission_id.as_str()
    }

    pub const fn mission_revision(&self) -> u64 {
        self.mission_revision
    }

    pub fn hartevo_project_id(&self) -> &str {
        self.hartevo_project_id.as_str()
    }

    pub const fn project_revision(&self) -> u64 {
        self.project_revision
    }

    pub fn work_product_id(&self) -> &str {
        self.work_product_id.as_str()
    }

    pub const fn work_product_revision(&self) -> u64 {
        self.work_product_revision
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self).expect("OCI DevOps scope serializes")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OciStageFence {
    pub stage_id: Ocid,
    pub expected_state: StateValue,
    pub expected_revision: u64,
}

impl OciStageFence {
    pub fn new(
        stage_id: impl Into<String>,
        expected_state: impl Into<String>,
        expected_revision: u64,
    ) -> Result<Self, ModelError> {
        validate_positive(expected_revision, "stage revision")?;
        Ok(Self {
            stage_id: Ocid::parse(stage_id)?,
            expected_state: StateValue::parse(expected_state)?,
            expected_revision,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OciDevopsReadRequest {
    pub max_results: u16,
    pub max_pages: u16,
    pub next_page_tokens: BTreeMap<String, OpaquePageToken>,
    pub expected_deployment_revision: Option<u64>,
    pub expected_build_revision: Option<u64>,
    pub expected_work_request_revision: Option<u64>,
    pub stage_fences: Vec<OciStageFence>,
    pub reconcile_resource_revisions: BTreeMap<Ocid, u64>,
}

impl Default for OciDevopsReadRequest {
    fn default() -> Self {
        Self::new()
    }
}

impl OciDevopsReadRequest {
    pub fn new() -> Self {
        Self {
            max_results: OCI_DEVOPS_MAX_RESULTS,
            max_pages: OCI_DEVOPS_MAX_PAGES,
            next_page_tokens: BTreeMap::new(),
            expected_deployment_revision: None,
            expected_build_revision: None,
            expected_work_request_revision: None,
            stage_fences: Vec::new(),
            reconcile_resource_revisions: BTreeMap::new(),
        }
    }

    pub fn with_max_results(mut self, value: u16) -> Result<Self, ModelError> {
        if !(1..=OCI_DEVOPS_MAX_RESULTS).contains(&value) {
            return Err(ModelError::Invalid {
                field: "maxResults",
            });
        }
        self.max_results = value;
        Ok(self)
    }

    pub fn with_max_pages(mut self, value: u16) -> Result<Self, ModelError> {
        if !(1..=OCI_DEVOPS_MAX_PAGES).contains(&value) {
            return Err(ModelError::Invalid { field: "max pages" });
        }
        self.max_pages = value;
        Ok(self)
    }

    pub fn with_next_page_token(
        mut self,
        collection: impl Into<String>,
        token: impl Into<String>,
    ) -> Result<Self, ModelError> {
        self.next_page_tokens
            .insert(collection.into(), OpaquePageToken::new(token)?);
        Ok(self)
    }

    pub fn with_expected_deployment_revision(mut self, revision: u64) -> Result<Self, ModelError> {
        validate_positive(revision, "deployment revision")?;
        self.expected_deployment_revision = Some(revision);
        Ok(self)
    }

    pub fn with_expected_build_revision(mut self, revision: u64) -> Result<Self, ModelError> {
        validate_positive(revision, "build revision")?;
        self.expected_build_revision = Some(revision);
        Ok(self)
    }

    pub fn with_expected_work_request_revision(
        mut self,
        revision: u64,
    ) -> Result<Self, ModelError> {
        validate_positive(revision, "work request revision")?;
        self.expected_work_request_revision = Some(revision);
        Ok(self)
    }

    pub fn with_stage_fence(
        mut self,
        stage_id: impl Into<String>,
        expected_state: impl Into<String>,
        expected_revision: u64,
    ) -> Result<Self, ModelError> {
        if self.stage_fences.len() >= OCI_DEVOPS_MAX_STAGES {
            return Err(ModelError::Invalid {
                field: "stage fences",
            });
        }
        self.stage_fences.push(OciStageFence::new(
            stage_id,
            expected_state,
            expected_revision,
        )?);
        Ok(self)
    }

    pub fn with_reconcile_revision(
        mut self,
        resource_id: impl Into<String>,
        revision: u64,
    ) -> Result<Self, ModelError> {
        validate_positive(revision, "reconcile revision")?;
        if self.reconcile_resource_revisions.len() >= OCI_DEVOPS_MAX_STAGES {
            return Err(ModelError::Invalid {
                field: "reconcile revisions",
            });
        }
        self.reconcile_resource_revisions
            .insert(Ocid::parse(resource_id)?, revision);
        Ok(self)
    }
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct OpaquePageToken {
    raw: String,
    digest: Digest,
}

impl fmt::Debug for OpaquePageToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaquePageToken")
            .field("digest", &self.digest)
            .finish_non_exhaustive()
    }
}

impl Serialize for OpaquePageToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serializer.serialize_struct("OpaquePageToken", 2)?;
        value.serialize_field("opaque", &true)?;
        value.serialize_field("digest", &self.digest)?;
        value.end()
    }
}

impl<'de> Deserialize<'de> for OpaquePageToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Wire {
            Raw(String),
            Opaque { digest: Digest },
        }
        match Wire::deserialize(deserializer)? {
            Wire::Raw(raw) => Self::new(raw).map_err(D::Error::custom),
            Wire::Opaque { digest } => Ok(Self {
                raw: String::new(),
                digest,
            }),
        }
    }
}

impl OpaquePageToken {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let raw = value.into();
        validate_text(&raw, "next page token", MAX_NEXT_PAGE_TOKEN_LENGTH, false)?;
        Ok(Self {
            digest: sha256_digest(raw.as_bytes()),
            raw,
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub(crate) fn as_str(&self) -> Result<&str, ModelError> {
        if self.raw.is_empty() {
            Err(ModelError::InvalidCursor)
        } else {
            Ok(&self.raw)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OciStagePayload {
    pub id: String,
    pub state: String,
    pub revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OciDeploymentPayload {
    pub id: String,
    pub compartment_id: String,
    pub project_id: String,
    pub pipeline_id: String,
    pub build_run_id: Option<String>,
    pub lifecycle_state: String,
    pub revision: u64,
    pub time_created: Option<DateTime<Utc>>,
    pub time_started: Option<DateTime<Utc>>,
    pub time_finished: Option<DateTime<Utc>>,
    pub stages: Vec<OciStagePayload>,
    pub artifact_count: u32,
    pub artifact_metadata_fingerprint: Option<Digest>,
    pub log_metadata_fingerprint: Option<Digest>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OciBuildRunPayload {
    pub id: String,
    pub compartment_id: String,
    pub project_id: String,
    pub pipeline_id: String,
    pub lifecycle_state: String,
    pub revision: u64,
    pub time_created: Option<DateTime<Utc>>,
    pub time_started: Option<DateTime<Utc>>,
    pub time_finished: Option<DateTime<Utc>>,
    pub stages: Vec<OciStagePayload>,
    pub artifact_count: u32,
    pub artifact_metadata_fingerprint: Option<Digest>,
    pub log_metadata_fingerprint: Option<Digest>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OciWorkRequestPayload {
    pub id: String,
    pub compartment_id: String,
    pub project_id: String,
    pub resource_id: Option<String>,
    pub operation_type: Option<String>,
    pub status: String,
    pub percent_complete: Option<u8>,
    pub revision: u64,
    pub time_accepted: Option<DateTime<Utc>>,
    pub time_started: Option<DateTime<Utc>>,
    pub time_finished: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum OciResponseBody {
    Deployments(Vec<OciDeploymentPayload>),
    Deployment(OciDeploymentPayload),
    BuildRuns(Vec<OciBuildRunPayload>),
    BuildRun(OciBuildRunPayload),
    WorkRequests(Vec<OciWorkRequestPayload>),
    WorkRequest(OciWorkRequestPayload),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
    ProductionRead,
}

impl TransportProvenance {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_connected(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct OciResponseReceipt {
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub endpoint: String,
    pub api_version: String,
    pub status: u16,
    pub response_size: usize,
    pub provider_revision: ProviderRevision,
    pub page_token_digest: Option<Digest>,
    pub next_page_token_present: bool,
    pub raw_provider_payload_retained: bool,
    pub raw_logs_retained: bool,
    pub raw_artifacts_retained: bool,
    pub credential_material_retained: bool,
    pub observed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OciStageProjection {
    pub id: Ocid,
    pub state: StateValue,
    pub revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OciDeploymentProjection {
    pub id: DeploymentId,
    pub compartment_id: CompartmentId,
    pub project_id: OciProjectId,
    pub pipeline_id: PipelineId,
    pub build_run_id: Option<BuildRunId>,
    pub lifecycle_state: StateValue,
    pub revision: u64,
    pub time_created: Option<DateTime<Utc>>,
    pub time_started: Option<DateTime<Utc>>,
    pub time_finished: Option<DateTime<Utc>>,
    pub stages: Vec<OciStageProjection>,
    pub artifact_count: u32,
    pub artifact_metadata_fingerprint: Option<Digest>,
    pub log_metadata_fingerprint: Option<Digest>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OciBuildRunProjection {
    pub id: BuildRunId,
    pub compartment_id: CompartmentId,
    pub project_id: OciProjectId,
    pub pipeline_id: PipelineId,
    pub lifecycle_state: StateValue,
    pub revision: u64,
    pub time_created: Option<DateTime<Utc>>,
    pub time_started: Option<DateTime<Utc>>,
    pub time_finished: Option<DateTime<Utc>>,
    pub stages: Vec<OciStageProjection>,
    pub artifact_count: u32,
    pub artifact_metadata_fingerprint: Option<Digest>,
    pub log_metadata_fingerprint: Option<Digest>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OciWorkRequestProjection {
    pub id: WorkRequestId,
    pub compartment_id: CompartmentId,
    pub project_id: OciProjectId,
    pub resource_id: Option<ResourceId>,
    pub operation_type: Option<String>,
    pub status: StateValue,
    pub percent_complete: Option<u8>,
    pub revision: u64,
    pub time_accepted: Option<DateTime<Utc>>,
    pub time_started: Option<DateTime<Utc>>,
    pub time_finished: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OciDevopsEvidence {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub provider_revision: ProviderRevision,
    pub provenance: TransportProvenance,
    pub native_evidence: bool,
    pub external_write_performed: bool,
    pub outcome_authority: bool,
    pub pages_read: u16,
    pub deployment: OciDeploymentProjection,
    pub build_run: OciBuildRunProjection,
    pub work_request: OciWorkRequestProjection,
    pub next_page_tokens: BTreeMap<String, OpaquePageToken>,
    pub receipts: Vec<OciResponseReceipt>,
    pub evidence_digest: Digest,
}

impl OciDevopsEvidence {
    pub fn validate(&self) -> Result<(), crate::OciDevopsError> {
        if self.contract_version != OCI_DEVOPS_RESULT_CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.provenance.is_native()
            || self.provenance.is_connected()
            || self.native_evidence
            || self.external_write_performed
            || self.outcome_authority
            || self.pages_read == 0
            || self.pages_read > OCI_DEVOPS_MAX_PAGES
            || self.receipts.is_empty()
            || self.deployment.stages.len() > OCI_DEVOPS_MAX_STAGES
            || self.build_run.stages.len() > OCI_DEVOPS_MAX_STAGES
            || self.receipts.iter().any(|receipt| {
                receipt.api_version != OCI_DEVOPS_API_VERSION
                    || receipt.raw_provider_payload_retained
                    || receipt.raw_logs_retained
                    || receipt.raw_artifacts_retained
                    || receipt.credential_material_retained
            })
            || compute_evidence_digest(self)? != self.evidence_digest
        {
            return Err(crate::OciDevopsError::StaleEvidence);
        }
        Ok(())
    }
}

pub fn compute_evidence_digest(evidence: &OciDevopsEvidence) -> Result<Digest, ModelError> {
    let canonical = (
        &evidence.contract_version,
        &evidence.contract_digest,
        &evidence.scope_digest,
        &evidence.registration_digest,
        &evidence.provider_revision,
        evidence.provenance,
        evidence.native_evidence,
        evidence.external_write_performed,
        evidence.outcome_authority,
        evidence.pages_read,
        &evidence.deployment,
        &evidence.build_run,
        &evidence.work_request,
        &evidence.next_page_tokens,
        &evidence.receipts,
    );
    digest_serializable(&canonical)
}

pub fn validate_plugin_metadata(
    plugin_version: &str,
    provider_version: &str,
    contract_version: &str,
    contract_digest_value: &Digest,
    provider_revision: &ProviderRevision,
) -> Result<(), crate::OciDevopsError> {
    if plugin_version != OCI_DEVOPS_RESULT_PLUGIN_VERSION_TEXT {
        return Err(crate::OciDevopsError::VersionMismatch);
    }
    if provider_version != OCI_DEVOPS_RESULT_PLUGIN_VERSION_TEXT {
        return Err(crate::OciDevopsError::ProviderVersionMismatch);
    }
    if contract_version != OCI_DEVOPS_RESULT_CONTRACT_VERSION
        || contract_digest_value != &crate::contract_digest()
    {
        return Err(crate::OciDevopsError::ContractDigestMismatch);
    }
    if provider_revision.as_str() != crate::OCI_DEVOPS_PROVIDER_REVISION {
        return Err(crate::OciDevopsError::RegistrationDrift(
            "provider revision is not the checked-in OCI API revision".to_owned(),
        ));
    }
    Ok(())
}

pub fn validate_list_count(
    count: usize,
    max: usize,
    field: &'static str,
) -> Result<(), ModelError> {
    if count > max {
        Err(ModelError::Invalid { field })
    } else {
        Ok(())
    }
}

pub fn validate_page_bounds(max_results: u16, max_pages: u16) -> Result<(), ModelError> {
    if !(1..=OCI_DEVOPS_MAX_RESULTS).contains(&max_results)
        || !(1..=OCI_DEVOPS_MAX_PAGES).contains(&max_pages)
    {
        return Err(ModelError::Invalid {
            field: "pagination bounds",
        });
    }
    Ok(())
}

pub fn validate_stage_bounds(stages: usize) -> Result<(), ModelError> {
    validate_list_count(stages, OCI_DEVOPS_MAX_STAGES, "stage bound")
}

pub fn validate_artifact_bounds(count: u32) -> Result<(), ModelError> {
    if usize::try_from(count).unwrap_or(usize::MAX) > OCI_DEVOPS_MAX_ARTIFACT_METADATA {
        Err(ModelError::Invalid {
            field: "artifact metadata bound",
        })
    } else {
        Ok(())
    }
}

pub fn collection_limit(collection: &str) -> usize {
    match collection {
        "deployments" => OCI_DEVOPS_MAX_DEPLOYMENTS,
        "buildRuns" => OCI_DEVOPS_MAX_BUILD_RUNS,
        "workRequests" => OCI_DEVOPS_MAX_WORK_REQUESTS,
        _ => 0,
    }
}

pub fn api_version() -> &'static str {
    OCI_DEVOPS_API_VERSION
}

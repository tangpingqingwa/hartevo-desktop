//! Bounded models for the Layer-1 AWS API Gateway deployment result seam.
//!
//! The public model contains only identifiers, revisions, digests, timestamps,
//! classifications, and redacted receipts.  It has no representation for an
//! API definition, authorizer secret, stage variable, access log, invocation
//! payload, credential, or raw provider error.

use std::{fmt, marker::PhantomData};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_CURSOR_BYTES: usize = 512;
pub const MAX_DEPLOYMENTS: usize = 256;
pub const MAX_PAGES: u16 = 4;
pub const PAGE_SIZE: u16 = 50;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_REQUESTS_PER_READ: u16 = 10;
pub const MAX_RETRIES: u8 = 2;

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
    #[error("{field} contains too many entries")]
    TooMany { field: &'static str },
    #[error("{field} is not allowed for this operation")]
    Unsupported { field: &'static str },
    #[error("{field} has a duplicate entry")]
    Duplicate { field: &'static str },
    #[error("{field} does not match the bound scope")]
    ScopeMismatch { field: &'static str },
    #[error("{field} must be between 0 and 100")]
    InvalidPercentage { field: &'static str },
    #[error("registration is already revoked")]
    AlreadyRevoked,
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
        .any(|character| !(character.is_ascii_alphanumeric() || "-_.:/+=@*$~".contains(character)))
    {
        return Err(ModelError::InvalidCharacters { field });
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

macro_rules! bounded_identifier {
    ($name:ident, $field:literal) => {
        #[derive(
            Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_text(&value, $field, MAX_IDENTIFIER_BYTES)?;
                Ok(Self(value))
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

bounded_identifier!(ApiGatewayApiId, "API Gateway API id");
bounded_identifier!(StageName, "API Gateway stage name");
bounded_identifier!(ApiGatewayDeploymentId, "API Gateway deployment id");
bounded_identifier!(CommitId, "deployment commit id");
bounded_identifier!(PermissionId, "permission id");
bounded_identifier!(ProviderId, "provider id");
bounded_identifier!(ProviderRevision, "provider revision");
bounded_identifier!(MissionId, "Mission id");
bounded_identifier!(ProjectId, "Project id");
bounded_identifier!(WorkProductId, "Work Product id");
bounded_identifier!(DeploymentId, "Hartevo deployment id");

pub type ApiId = ApiGatewayApiId;
pub type ApiDeploymentId = ApiGatewayDeploymentId;

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
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

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
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
        formatter.debug_tuple("AwsRegion").field(&self.0).finish()
    }
}

impl fmt::Display for AwsRegion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

pub type Region = AwsRegion;

#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
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

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex_encode(Sha256::digest(bytes).as_slice()))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn from_parts(tag: &str, parts: &[String]) -> Self {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(tag.as_bytes());
        for part in parts {
            bytes.push(0);
            bytes.extend_from_slice(part.as_bytes());
        }
        Self::from_bytes(&bytes)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.len() != 64
            || value
                .bytes()
                .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
        {
            return Err(ModelError::InvalidDigest { field: "digest" });
        }
        Ok(Self(value))
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

pub fn digest_serializable<T: Serialize>(value: &T) -> Result<Digest, serde_json::Error> {
    Ok(Digest::from_bytes(&serde_json::to_vec(value)?))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ApiKind {
    Rest,
    Http,
}

impl ApiKind {
    pub const fn api_version(self) -> &'static str {
        match self {
            Self::Rest => "2015-07-09",
            Self::Http => "2018-11-29",
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiBinding {
    pub kind: ApiKind,
    pub id: ApiGatewayApiId,
    pub revision: Revision,
}

impl ApiBinding {
    pub const fn new(kind: ApiKind, id: ApiGatewayApiId, revision: Revision) -> Self {
        Self { kind, id, revision }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-aws-api-gateway-api/v1",
            &[
                format!("{:?}", self.kind),
                self.id.as_str().to_owned(),
                self.revision.get().to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StageBinding {
    pub name: StageName,
    pub revision: Revision,
}

impl StageBinding {
    pub const fn new(name: StageName, revision: Revision) -> Self {
        Self { name, revision }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-aws-api-gateway-stage/v1",
            &[
                self.name.as_str().to_owned(),
                self.revision.get().to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiDeploymentBinding {
    pub id: ApiGatewayDeploymentId,
    pub revision: Revision,
    pub configuration_digest: Digest,
    pub commit_digest: Option<Digest>,
}

impl ApiDeploymentBinding {
    pub fn new(
        id: ApiGatewayDeploymentId,
        revision: Revision,
        configuration_digest: Digest,
        commit_digest: Option<Digest>,
    ) -> Result<Self, ModelError> {
        if configuration_digest == Digest::zero()
            && commit_digest
                .as_ref()
                .is_none_or(|digest| *digest == Digest::zero())
        {
            return Err(ModelError::Invalid {
                field: "API deployment configuration digest",
            });
        }
        if commit_digest.as_ref() == Some(&Digest::zero()) {
            return Err(ModelError::Invalid {
                field: "API deployment commit digest",
            });
        }
        Ok(Self {
            id,
            revision,
            configuration_digest,
            commit_digest,
        })
    }

    pub fn artifact_digest(&self) -> &Digest {
        self.commit_digest
            .as_ref()
            .unwrap_or(&self.configuration_digest)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-aws-api-gateway-deployment/v1",
            &[
                self.id.as_str().to_owned(),
                self.revision.get().to_string(),
                self.configuration_digest.to_string(),
                self.commit_digest
                    .as_ref()
                    .map_or_else(String::new, ToString::to_string),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionBinding {
    pub id: MissionId,
    pub revision: Revision,
}

impl MissionBinding {
    pub const fn new(id: MissionId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectBinding {
    pub id: ProjectId,
    pub revision: Revision,
}

impl ProjectBinding {
    pub const fn new(id: ProjectId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductBinding {
    pub id: WorkProductId,
    pub revision: Revision,
}

impl WorkProductBinding {
    pub const fn new(id: WorkProductId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentBinding {
    pub id: DeploymentId,
    pub revision: Revision,
}

impl DeploymentBinding {
    pub const fn new(id: DeploymentId, revision: Revision) -> Self {
        Self { id, revision }
    }
}

/// The complete, exact allowlist for one Mission decision.  The API Gateway
/// deployment identity is deliberately separate from Hartevo's Deployment
/// binding: both are required and both are revision-fenced.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsApiGatewayScope {
    pub account_id: AccountId,
    pub region: AwsRegion,
    pub api: ApiBinding,
    pub stage: StageBinding,
    pub deployment: ApiDeploymentBinding,
    pub mission: MissionBinding,
    pub project: ProjectBinding,
    pub work_product: WorkProductBinding,
    pub hartevo_deployment: DeploymentBinding,
    pub permissions: PermissionFence,
    pub permission_digest: Digest,
    pub secret_reference_digest: Digest,
    pub scope_digest: Digest,
}

impl AwsApiGatewayScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: AccountId,
        region: AwsRegion,
        api: ApiBinding,
        stage: StageBinding,
        deployment: ApiDeploymentBinding,
        mission: MissionBinding,
        project: ProjectBinding,
        work_product: WorkProductBinding,
        hartevo_deployment: DeploymentBinding,
        permissions: PermissionFence,
        secret_reference_digest: Digest,
    ) -> Result<Self, ModelError> {
        let mut scope = Self {
            account_id,
            region,
            api,
            stage,
            deployment,
            mission,
            project,
            work_product,
            hartevo_deployment,
            permission_digest: permissions.permission_digest.clone(),
            permissions,
            secret_reference_digest,
            scope_digest: Digest::zero(),
        };
        scope.scope_digest = scope.recomputed_digest();
        scope.validate()?;
        Ok(scope)
    }

    pub fn for_api_gateway(
        account_id: AccountId,
        region: AwsRegion,
        api: ApiBinding,
        stage: StageBinding,
        deployment: ApiDeploymentBinding,
        mission: MissionBinding,
        project: ProjectBinding,
        work_product: WorkProductBinding,
        hartevo_deployment: DeploymentBinding,
        permissions: PermissionFence,
        secret_reference_digest: Digest,
    ) -> Result<Self, ModelError> {
        Self::new(
            account_id,
            region,
            api,
            stage,
            deployment,
            mission,
            project,
            work_product,
            hartevo_deployment,
            permissions,
            secret_reference_digest,
        )
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-aws-api-gateway-scope/v1",
            &[
                self.account_id.as_str().to_owned(),
                self.region.as_str().to_owned(),
                format!("{:?}", self.api.kind),
                self.api.id.as_str().to_owned(),
                self.api.revision.get().to_string(),
                self.stage.name.as_str().to_owned(),
                self.stage.revision.get().to_string(),
                self.deployment.id.as_str().to_owned(),
                self.deployment.revision.get().to_string(),
                self.deployment.configuration_digest.to_string(),
                self.deployment
                    .commit_digest
                    .as_ref()
                    .map_or_else(String::new, ToString::to_string),
                self.mission.id.as_str().to_owned(),
                self.mission.revision.get().to_string(),
                self.project.id.as_str().to_owned(),
                self.project.revision.get().to_string(),
                self.work_product.id.as_str().to_owned(),
                self.work_product.revision.get().to_string(),
                self.hartevo_deployment.id.as_str().to_owned(),
                self.hartevo_deployment.revision.get().to_string(),
                self.permission_digest.to_string(),
                self.secret_reference_digest.to_string(),
            ],
        )
    }

    pub fn digest(&self) -> Digest {
        self.scope_digest.clone()
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn api_digest(&self) -> Digest {
        self.api.digest()
    }

    pub fn stage_digest(&self) -> Digest {
        self.stage.digest()
    }

    pub fn deployment_digest(&self) -> Digest {
        self.deployment.digest()
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        validate_text(
            self.api.id.as_str(),
            "API Gateway API id",
            MAX_IDENTIFIER_BYTES,
        )?;
        validate_text(
            self.stage.name.as_str(),
            "API Gateway stage name",
            MAX_IDENTIFIER_BYTES,
        )?;
        validate_text(
            self.deployment.id.as_str(),
            "API Gateway deployment id",
            MAX_IDENTIFIER_BYTES,
        )?;
        if self.deployment.configuration_digest == Digest::zero()
            && self
                .deployment
                .commit_digest
                .as_ref()
                .is_none_or(|digest| *digest == Digest::zero())
        {
            return Err(ModelError::Invalid {
                field: "API deployment artifact digest",
            });
        }
        self.permissions.validate()?;
        if self.permission_digest != self.permissions.permission_digest
            || self.secret_reference_digest == Digest::zero()
            || self.scope_digest != self.recomputed_digest()
        {
            return Err(ModelError::ScopeMismatch {
                field: "API Gateway scope digest",
            });
        }
        Ok(())
    }

    pub fn permits(&self, operation: ApiGatewayReadOperation) -> bool {
        self.permissions.supports(operation.permission())
    }
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "PascalCase")]
pub enum PermissionAction {
    GetStage,
    GetDeployment,
    GetDeployments,
}

impl PermissionAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GetStage => "GetStage",
            Self::GetDeployment => "GetDeployment",
            Self::GetDeployments => "GetDeployments",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionFence {
    pub id: PermissionId,
    pub revision: Revision,
    pub actions: Vec<PermissionAction>,
    pub permission_digest: Digest,
}

impl PermissionFence {
    pub fn new<I>(id: PermissionId, revision: Revision, actions: I) -> Result<Self, ModelError>
    where
        I: IntoIterator<Item = PermissionAction>,
    {
        let mut actions = actions.into_iter().collect::<Vec<_>>();
        actions.sort_unstable();
        if actions.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ModelError::Duplicate {
                field: "permission action",
            });
        }
        if actions.is_empty() {
            return Err(ModelError::Invalid {
                field: "permission actions",
            });
        }
        let permission_digest = Self::compute_digest(&id, revision, &actions);
        Ok(Self {
            id,
            revision,
            actions,
            permission_digest,
        })
    }

    pub fn read_only(id: PermissionId, revision: Revision) -> Result<Self, ModelError> {
        Self::new(
            id,
            revision,
            [
                PermissionAction::GetStage,
                PermissionAction::GetDeployment,
                PermissionAction::GetDeployments,
            ],
        )
    }

    fn compute_digest(
        id: &PermissionId,
        revision: Revision,
        actions: &[PermissionAction],
    ) -> Digest {
        Digest::from_parts(
            "hartevo-aws-api-gateway-permission/v1",
            &[
                id.as_str().to_owned(),
                revision.get().to_string(),
                actions
                    .iter()
                    .map(|action| action.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
            ],
        )
    }

    pub fn supports(&self, action: PermissionAction) -> bool {
        self.actions.contains(&action)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.actions.is_empty()
            || self.actions.windows(2).any(|pair| pair[0] >= pair[1])
            || self.permission_digest
                != Self::compute_digest(&self.id, self.revision, &self.actions)
        {
            return Err(ModelError::ScopeMismatch {
                field: "permission digest or action set",
            });
        }
        Ok(())
    }
}

/// A SigV4 reference is deliberately opaque: its material never participates
/// in serialization or Debug output.  The private material exists only so a
/// later host transport can resolve the reference without changing this API.
pub struct SecretReference {
    material: Zeroizing<String>,
    reference_digest: Digest,
    revoked: bool,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            material: Zeroizing::new(self.material.as_str().to_owned()),
            reference_digest: self.reference_digest.clone(),
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
            .field("revoked", &self.revoked)
            .finish_non_exhaustive()
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

impl Serialize for SecretReference {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("SecretReference", 1)?;
        state.serialize_field("opaque", &true)?;
        state.end()
    }
}

impl SecretReference {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_text(&value, "SigV4 secret reference", MAX_IDENTIFIER_BYTES)?;
        Ok(Self {
            reference_digest: Digest::from_text(&value),
            material: Zeroizing::new(value),
            revoked: false,
        })
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            return Err(ModelError::AlreadyRevoked);
        }
        self.revoked = true;
        Ok(())
    }

    pub fn opaque_marker(&self) -> bool {
        true
    }
}

/// A page token can be forwarded to a host transport but cannot cross the
/// Layer-1 serialization or Debug boundary in raw form.
pub struct OpaquePageToken {
    material: Zeroizing<String>,
    token_digest: Digest,
    _not_deserializable: PhantomData<fn() -> Self>,
}

impl Clone for OpaquePageToken {
    fn clone(&self) -> Self {
        Self {
            material: Zeroizing::new(self.material.as_str().to_owned()),
            token_digest: self.token_digest.clone(),
            _not_deserializable: PhantomData,
        }
    }
}

impl fmt::Debug for OpaquePageToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaquePageToken")
            .field("opaque", &true)
            .field("token_digest", &self.token_digest)
            .finish_non_exhaustive()
    }
}

impl PartialEq for OpaquePageToken {
    fn eq(&self, other: &Self) -> bool {
        self.token_digest == other.token_digest
    }
}

impl Eq for OpaquePageToken {}

impl Serialize for OpaquePageToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("OpaquePageToken", 1)?;
        state.serialize_field("opaque", &true)?;
        state.end()
    }
}

impl OpaquePageToken {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_text(&value, "pagination token", MAX_CURSOR_BYTES)?;
        Ok(Self {
            token_digest: Digest::from_text(&value),
            material: Zeroizing::new(value),
            _not_deserializable: PhantomData,
        })
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }
}

pub type OpaqueCursor = OpaquePageToken;

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn connected(&self) -> bool {
        false
    }

    pub const fn native(&self) -> bool {
        false
    }

    pub const fn first_party(&self) -> bool {
        false
    }

    pub const fn label(&self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Recording => "recording",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "BLOCKED_ENV",
        }
    }
}

pub type ProviderProvenance = TransportProvenance;

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "PascalCase")]
pub enum ApiGatewayReadOperation {
    GetStage,
    GetDeployment,
    GetDeployments,
}

impl ApiGatewayReadOperation {
    pub const fn permission(self) -> PermissionAction {
        match self {
            Self::GetStage => PermissionAction::GetStage,
            Self::GetDeployment => PermissionAction::GetDeployment,
            Self::GetDeployments => PermissionAction::GetDeployments,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GetStage => "GetStage",
            Self::GetDeployment => "GetDeployment",
            Self::GetDeployments => "GetDeployments",
        }
    }
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Complete,
    Partial,
    AccessLoss,
    ProviderUnknown,
}

impl EvidenceStatus {
    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum PartialReason {
    StageDrift,
    DeploymentDrift,
    RevisionDrift,
    DigestDrift,
    MissingDeployment,
    PaginationLoop,
    PageBudget,
    DeploymentBudget,
    ResponseTooLarge,
    ProviderFailure,
    AccessLoss,
    Throttle,
    Timeout,
    Conflict,
    InsufficientData,
    BlockedEnvironment,
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ErrorClassification {
    None,
    InvalidRequest,
    Unauthorized,
    AccessDenied,
    NotFound,
    Conflict,
    Throttled,
    ServerFailure,
    Timeout,
    BlockedEnvironment,
    ResponseBinding,
    Unknown,
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum MetadataStatus {
    Available,
    NotFound,
    AccessLoss,
    Failed,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StageMetadata {
    pub api_id: ApiGatewayApiId,
    pub stage_name: StageName,
    pub deployment_id: ApiGatewayDeploymentId,
    pub api_revision: Revision,
    pub stage_revision: Revision,
    pub last_updated: DateTime<Utc>,
    pub canary_traffic_percent: Option<u8>,
    pub route_auth_summary_digest: Digest,
    pub status: MetadataStatus,
    pub error_classification: ErrorClassification,
    pub metadata_digest: Digest,
}

impl StageMetadata {
    pub fn new(
        api_id: ApiGatewayApiId,
        stage_name: StageName,
        deployment_id: ApiGatewayDeploymentId,
        api_revision: Revision,
        stage_revision: Revision,
        last_updated: DateTime<Utc>,
        canary_traffic_percent: Option<u8>,
        route_auth_summary_digest: Digest,
    ) -> Result<Self, ModelError> {
        if canary_traffic_percent.is_some_and(|percent| percent > 100) {
            return Err(ModelError::InvalidPercentage {
                field: "canary traffic percentage",
            });
        }
        if route_auth_summary_digest == Digest::zero() {
            return Err(ModelError::Invalid {
                field: "route/auth summary digest",
            });
        }
        let mut value = Self {
            api_id,
            stage_name,
            deployment_id,
            api_revision,
            stage_revision,
            last_updated,
            canary_traffic_percent,
            route_auth_summary_digest,
            status: MetadataStatus::Available,
            error_classification: ErrorClassification::None,
            metadata_digest: Digest::zero(),
        };
        value.metadata_digest = value.recomputed_digest();
        Ok(value)
    }

    pub fn with_classification(
        mut self,
        status: MetadataStatus,
        error_classification: ErrorClassification,
    ) -> Self {
        self.status = status;
        self.error_classification = error_classification;
        self.metadata_digest = self.recomputed_digest();
        self
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serializable(&(
            &self.api_id,
            &self.stage_name,
            &self.deployment_id,
            self.api_revision,
            self.stage_revision,
            self.last_updated,
            self.canary_traffic_percent,
            &self.route_auth_summary_digest,
            self.status,
            self.error_classification,
        ))
        .expect("StageMetadata digest serialization is infallible")
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self
            .canary_traffic_percent
            .is_some_and(|percent| percent > 100)
            || self.metadata_digest != self.recomputed_digest()
        {
            return Err(ModelError::ScopeMismatch {
                field: "stage metadata digest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentMetadata {
    pub api_id: ApiGatewayApiId,
    pub deployment_id: ApiGatewayDeploymentId,
    pub deployment_revision: Revision,
    pub created_at: DateTime<Utc>,
    pub configuration_digest: Digest,
    pub commit_digest: Option<Digest>,
    pub route_auth_summary_digest: Digest,
    pub status: MetadataStatus,
    pub error_classification: ErrorClassification,
    pub metadata_digest: Digest,
}

impl DeploymentMetadata {
    pub fn new(
        api_id: ApiGatewayApiId,
        deployment_id: ApiGatewayDeploymentId,
        deployment_revision: Revision,
        created_at: DateTime<Utc>,
        configuration_digest: Digest,
        commit_digest: Option<Digest>,
        route_auth_summary_digest: Digest,
    ) -> Result<Self, ModelError> {
        if configuration_digest == Digest::zero()
            && commit_digest
                .as_ref()
                .is_none_or(|digest| *digest == Digest::zero())
        {
            return Err(ModelError::Invalid {
                field: "deployment artifact digest",
            });
        }
        if route_auth_summary_digest == Digest::zero() {
            return Err(ModelError::Invalid {
                field: "route/auth summary digest",
            });
        }
        let mut value = Self {
            api_id,
            deployment_id,
            deployment_revision,
            created_at,
            configuration_digest,
            commit_digest,
            route_auth_summary_digest,
            status: MetadataStatus::Available,
            error_classification: ErrorClassification::None,
            metadata_digest: Digest::zero(),
        };
        value.metadata_digest = value.recomputed_digest();
        Ok(value)
    }

    pub fn with_classification(
        mut self,
        status: MetadataStatus,
        error_classification: ErrorClassification,
    ) -> Self {
        self.status = status;
        self.error_classification = error_classification;
        self.metadata_digest = self.recomputed_digest();
        self
    }

    pub fn artifact_digest(&self) -> &Digest {
        self.commit_digest
            .as_ref()
            .unwrap_or(&self.configuration_digest)
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serializable(&(
            &self.api_id,
            &self.deployment_id,
            self.deployment_revision,
            self.created_at,
            &self.configuration_digest,
            &self.commit_digest,
            &self.route_auth_summary_digest,
            self.status,
            self.error_classification,
        ))
        .expect("DeploymentMetadata digest serialization is infallible")
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.configuration_digest == Digest::zero()
            && self
                .commit_digest
                .as_ref()
                .is_none_or(|digest| *digest == Digest::zero())
            || self.metadata_digest != self.recomputed_digest()
        {
            return Err(ModelError::ScopeMismatch {
                field: "deployment metadata digest",
            });
        }
        Ok(())
    }
}

pub type StageEvidence = StageMetadata;
pub type DeploymentEvidence = DeploymentMetadata;

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentSummary {
    pub api_id: ApiGatewayApiId,
    pub deployment_id: ApiGatewayDeploymentId,
    pub deployment_revision: Revision,
    pub created_at: DateTime<Utc>,
    pub configuration_digest: Digest,
    pub commit_digest: Option<Digest>,
    pub route_auth_summary_digest: Digest,
    pub metadata_digest: Digest,
}

impl DeploymentSummary {
    pub fn from_metadata(metadata: &DeploymentMetadata) -> Self {
        Self {
            api_id: metadata.api_id.clone(),
            deployment_id: metadata.deployment_id.clone(),
            deployment_revision: metadata.deployment_revision,
            created_at: metadata.created_at,
            configuration_digest: metadata.configuration_digest.clone(),
            commit_digest: metadata.commit_digest.clone(),
            route_auth_summary_digest: metadata.route_auth_summary_digest.clone(),
            metadata_digest: metadata.metadata_digest.clone(),
        }
    }

    pub fn artifact_digest(&self) -> &Digest {
        self.commit_digest
            .as_ref()
            .unwrap_or(&self.configuration_digest)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let metadata = DeploymentMetadata {
            api_id: self.api_id.clone(),
            deployment_id: self.deployment_id.clone(),
            deployment_revision: self.deployment_revision,
            created_at: self.created_at,
            configuration_digest: self.configuration_digest.clone(),
            commit_digest: self.commit_digest.clone(),
            route_auth_summary_digest: self.route_auth_summary_digest.clone(),
            status: MetadataStatus::Available,
            error_classification: ErrorClassification::None,
            metadata_digest: self.metadata_digest.clone(),
        };
        metadata.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactedRequestReceipt {
    pub operation: ApiGatewayReadOperation,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub response_bytes: usize,
    pub cost_receipt_digest: Digest,
    pub raw_request_retained: bool,
    pub raw_response_retained: bool,
    pub cost_receipt_redacted: bool,
}

impl RedactedRequestReceipt {
    pub fn new(
        operation: ApiGatewayReadOperation,
        request_digest: Digest,
        response_digest: Digest,
        response_bytes: usize,
    ) -> Self {
        let cost_receipt_digest = Digest::from_parts(
            "hartevo-aws-api-gateway-redacted-cost/v1",
            &[
                operation.as_str().to_owned(),
                response_bytes.to_string(),
                response_digest.to_string(),
            ],
        );
        Self {
            operation,
            request_digest,
            response_digest,
            response_bytes,
            cost_receipt_digest,
            raw_request_retained: false,
            raw_response_retained: false,
            cost_receipt_redacted: true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderErrorEvidence {
    pub classification: ErrorClassification,
    pub status_code: Option<u16>,
    pub retryable: bool,
    pub attempt: u8,
    pub error_digest: Digest,
}

impl ProviderErrorEvidence {
    pub fn new(
        classification: ErrorClassification,
        status_code: Option<u16>,
        retryable: bool,
        attempt: u8,
    ) -> Self {
        let error_digest = Digest::from_parts(
            "hartevo-aws-api-gateway-provider-error/v1",
            &[
                format!("{classification:?}"),
                status_code.map_or_else(String::new, |value| value.to_string()),
                retryable.to_string(),
                attempt.to_string(),
            ],
        );
        Self {
            classification,
            status_code,
            retryable,
            attempt,
            error_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsApiGatewayEvidence {
    pub operation: ApiGatewayReadOperation,
    pub status: EvidenceStatus,
    pub partial_reason: Option<PartialReason>,
    pub api: ApiBinding,
    pub stage: StageBinding,
    pub deployment: ApiDeploymentBinding,
    pub stage_metadata: Option<StageMetadata>,
    pub deployment_metadata: Option<DeploymentMetadata>,
    pub deployments: Vec<DeploymentSummary>,
    pub page_count: u16,
    pub request_count: u16,
    pub retry_count: u8,
    pub truncated: bool,
    pub page_token_digests: Vec<Digest>,
    pub provider_errors: Vec<ProviderErrorEvidence>,
    pub request_receipts: Vec<RedactedRequestReceipt>,
    pub provenance: TransportProvenance,
    pub plugin_version_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub contract_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub stage_digest: Digest,
    pub deployment_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

#[derive(Serialize)]
struct AwsApiGatewayEvidenceDigestInput<'a> {
    operation: ApiGatewayReadOperation,
    status: EvidenceStatus,
    partial_reason: Option<PartialReason>,
    api: &'a ApiBinding,
    stage: &'a StageBinding,
    deployment: &'a ApiDeploymentBinding,
    stage_metadata: &'a Option<StageMetadata>,
    deployment_metadata: &'a Option<DeploymentMetadata>,
    deployments: &'a [DeploymentSummary],
    page_count: u16,
    request_count: u16,
    retry_count: u8,
    truncated: bool,
    page_token_digests: &'a [Digest],
    provider_errors: &'a [ProviderErrorEvidence],
    request_receipts: &'a [RedactedRequestReceipt],
    provenance: &'a TransportProvenance,
    plugin_version_digest: &'a Digest,
    provider_digest: &'a Digest,
    api_digest: &'a Digest,
    contract_digest: &'a Digest,
    permission_digest: &'a Digest,
    scope_digest: &'a Digest,
    stage_digest: &'a Digest,
    deployment_digest: &'a Digest,
    registration_digest: &'a Digest,
    connected: bool,
    native: bool,
    first_party: bool,
}

impl AwsApiGatewayEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation: ApiGatewayReadOperation,
        status: EvidenceStatus,
        partial_reason: Option<PartialReason>,
        api: ApiBinding,
        stage: StageBinding,
        deployment: ApiDeploymentBinding,
        stage_metadata: Option<StageMetadata>,
        deployment_metadata: Option<DeploymentMetadata>,
        deployments: Vec<DeploymentSummary>,
        page_count: u16,
        request_count: u16,
        retry_count: u8,
        truncated: bool,
        page_token_digests: Vec<Digest>,
        provider_errors: Vec<ProviderErrorEvidence>,
        request_receipts: Vec<RedactedRequestReceipt>,
        provenance: TransportProvenance,
        plugin_version_digest: Digest,
        provider_digest: Digest,
        api_digest: Digest,
        contract_digest: Digest,
        permission_digest: Digest,
        scope_digest: Digest,
        registration_digest: Digest,
    ) -> Result<Self, ModelError> {
        if deployments.len() > MAX_DEPLOYMENTS
            || page_token_digests.len() > usize::from(MAX_PAGES)
            || request_receipts.len() > usize::from(MAX_REQUESTS_PER_READ)
        {
            return Err(ModelError::TooMany {
                field: "bounded API Gateway evidence",
            });
        }
        let mut evidence = Self {
            operation,
            status,
            partial_reason,
            api,
            stage,
            deployment,
            stage_metadata,
            deployment_metadata,
            deployments,
            page_count,
            request_count,
            retry_count,
            truncated,
            page_token_digests,
            provider_errors,
            request_receipts,
            provenance,
            plugin_version_digest,
            provider_digest,
            api_digest,
            contract_digest,
            permission_digest,
            scope_digest,
            stage_digest: Digest::zero(),
            deployment_digest: Digest::zero(),
            registration_digest,
            evidence_digest: Digest::zero(),
            connected: false,
            native: false,
            first_party: false,
        };
        evidence.stage_digest = evidence.stage.digest();
        evidence.deployment_digest = evidence.deployment.digest();
        evidence.evidence_digest = evidence.recomputed_digest();
        Ok(evidence)
    }

    pub fn recomputed_digest(&self) -> Digest {
        digest_serializable(&AwsApiGatewayEvidenceDigestInput {
            operation: self.operation,
            status: self.status,
            partial_reason: self.partial_reason,
            api: &self.api,
            stage: &self.stage,
            deployment: &self.deployment,
            stage_metadata: &self.stage_metadata,
            deployment_metadata: &self.deployment_metadata,
            deployments: &self.deployments,
            page_count: self.page_count,
            request_count: self.request_count,
            retry_count: self.retry_count,
            truncated: self.truncated,
            page_token_digests: &self.page_token_digests,
            provider_errors: &self.provider_errors,
            request_receipts: &self.request_receipts,
            provenance: &self.provenance,
            plugin_version_digest: &self.plugin_version_digest,
            provider_digest: &self.provider_digest,
            api_digest: &self.api_digest,
            contract_digest: &self.contract_digest,
            permission_digest: &self.permission_digest,
            scope_digest: &self.scope_digest,
            stage_digest: &self.stage_digest,
            deployment_digest: &self.deployment_digest,
            registration_digest: &self.registration_digest,
            connected: self.connected,
            native: self.native,
            first_party: self.first_party,
        })
        .expect("AWS API Gateway evidence digest serialization is infallible")
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.connected
            || self.native
            || self.first_party
            || self.stage_digest != self.stage.digest()
            || self.deployment_digest != self.deployment.digest()
            || self.evidence_digest != self.recomputed_digest()
            || self.deployments.len() > MAX_DEPLOYMENTS
            || self.page_count > MAX_PAGES
            || self.request_count > MAX_REQUESTS_PER_READ
        {
            return Err(ModelError::ScopeMismatch {
                field: "API Gateway evidence authority or digest",
            });
        }
        if let Some(stage_metadata) = &self.stage_metadata {
            stage_metadata.validate()?;
        }
        if let Some(deployment_metadata) = &self.deployment_metadata {
            deployment_metadata.validate()?;
        }
        for deployment in &self.deployments {
            deployment.validate()?;
        }
        if self.status == EvidenceStatus::Complete {
            if self.partial_reason.is_some()
                || self.truncated
                || self.request_count == 0
                || !self.provider_errors.is_empty()
                || self.request_receipts.is_empty()
                || self.stage_metadata.as_ref().is_some_and(|metadata| {
                    metadata.status != MetadataStatus::Available
                        || metadata.error_classification != ErrorClassification::None
                })
                || self.deployment_metadata.as_ref().is_some_and(|metadata| {
                    metadata.status != MetadataStatus::Available
                        || metadata.error_classification != ErrorClassification::None
                })
                || self.request_receipts.iter().any(|receipt| {
                    receipt.raw_request_retained
                        || receipt.raw_response_retained
                        || !receipt.cost_receipt_redacted
                })
            {
                return Err(ModelError::ScopeMismatch {
                    field: "complete API Gateway evidence completeness",
                });
            }
            match self.operation {
                ApiGatewayReadOperation::GetStage if self.stage_metadata.is_none() => {
                    return Err(ModelError::ScopeMismatch {
                        field: "complete stage evidence",
                    });
                }
                ApiGatewayReadOperation::GetDeployment if self.deployment_metadata.is_none() => {
                    return Err(ModelError::ScopeMismatch {
                        field: "complete deployment evidence",
                    });
                }
                ApiGatewayReadOperation::GetDeployments
                    if !self.deployments.iter().any(|deployment| {
                        deployment.api_id == self.api.id
                            && deployment.deployment_id == self.deployment.id
                    }) =>
                {
                    return Err(ModelError::ScopeMismatch {
                        field: "complete deployment-list evidence",
                    });
                }
                _ => {}
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Capabilities {
    pub service_id: String,
    pub provider_id: String,
    pub contract_version: String,
    pub operations: Vec<ApiGatewayReadOperation>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub live_execution: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

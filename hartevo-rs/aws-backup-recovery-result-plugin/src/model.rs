use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::Zeroize;

use crate::error::{AwsBackupRecoveryError, Result};
use crate::{
    LAYER1_PERMISSIONS, MAX_IDENTIFIER_BYTES, MAX_PAGE_SIZE, MAX_PAGES, MAX_RESPONSE_BYTES,
};

pub const MAX_ARN_BYTES: usize = 2_048;
pub const MAX_RESOURCE_TYPE_BYTES: usize = 50;
pub const MAX_VAULT_NAME_BYTES: usize = 50;

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
            Err(AwsBackupRecoveryError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(AwsBackupRecoveryError::InvalidDigest)
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

fn valid_arn(value: &str) -> bool {
    valid_text(value, MAX_ARN_BYTES, false) && value.starts_with("arn:")
}

macro_rules! redacted_text {
    ($name:ident, $field:literal, $validator:expr) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if ($validator)(&value) {
                    Ok(Self(value))
                } else {
                    Err(AwsBackupRecoveryError::InvalidIdentifier { field: $field })
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_parts(
                    concat!("aws-backup-", $field, "/v1"),
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
                    Err(AwsBackupRecoveryError::InvalidIdentifier { field: $field })
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

redacted_text!(AwsAccountId, "account", |value: &str| value.len() == 12
    && value.bytes().all(|byte| byte.is_ascii_digit()));
redacted_text!(AwsRegion, "region", |value: &str| valid_identifier(
    value, 64
));
redacted_text!(BackupVaultName, "backup-vault", |value: &str| {
    (2..=MAX_VAULT_NAME_BYTES).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
});
redacted_text!(RecoveryPointArn, "recovery-point", valid_arn);
redacted_text!(ResourceArn, "resource-arn", valid_arn);
redacted_text!(BackupPlanArn, "backup-plan-arn", valid_arn);
redacted_text!(ResourceType, "resource-type", |value: &str| {
    valid_text(value, MAX_RESOURCE_TYPE_BYTES, false)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
});

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupVaultIdentity {
    name: BackupVaultName,
    arn_digest: Option<Digest>,
}

impl BackupVaultIdentity {
    pub fn new(name: BackupVaultName, arn: Option<impl Into<String>>) -> Result<Self> {
        let arn_digest = arn
            .map(Into::into)
            .map(|value| {
                if valid_arn(&value) {
                    Ok(Digest::from_parts(
                        "aws-backup-vault-arn/v1",
                        &[("arn", value)],
                    ))
                } else {
                    Err(AwsBackupRecoveryError::InvalidIdentifier {
                        field: "backup-vault-arn",
                    })
                }
            })
            .transpose()?;
        Ok(Self { name, arn_digest })
    }

    pub fn name(&self) -> &BackupVaultName {
        &self.name
    }

    pub fn arn_digest(&self) -> Option<&Digest> {
        self.arn_digest.as_ref()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-backup-vault/v1",
            &[
                ("name", self.name.digest().as_str().to_owned()),
                (
                    "arn",
                    self.arn_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.name.validate()?;
        self.arn_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()
            .map(|_| ())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct RecoveryPointIdentity {
    arn: RecoveryPointArn,
}

impl RecoveryPointIdentity {
    pub fn new(arn: RecoveryPointArn) -> Self {
        Self { arn }
    }

    pub fn arn(&self) -> &RecoveryPointArn {
        &self.arn
    }

    pub fn digest(&self) -> Digest {
        self.arn.digest()
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.arn.validate()
    }
}

impl fmt::Debug for RecoveryPointIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryPointIdentity")
            .field("digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ResourceIdentity {
    arn: ResourceArn,
    resource_type: ResourceType,
    name_digest: Option<Digest>,
}

impl ResourceIdentity {
    pub fn new(
        arn: ResourceArn,
        resource_type: ResourceType,
        resource_name: Option<impl AsRef<str>>,
    ) -> Result<Self> {
        let name_digest = resource_name
            .map(|name| name.as_ref().to_owned())
            .map(|name| {
                if valid_text(&name, MAX_IDENTIFIER_BYTES, true) {
                    Ok(Digest::from_parts(
                        "aws-backup-resource-name/v1",
                        &[("name", name)],
                    ))
                } else {
                    Err(AwsBackupRecoveryError::InvalidIdentifier {
                        field: "resource-name",
                    })
                }
            })
            .transpose()?;
        Ok(Self {
            arn,
            resource_type,
            name_digest,
        })
    }

    pub fn arn(&self) -> &ResourceArn {
        &self.arn
    }

    pub fn resource_type(&self) -> &ResourceType {
        &self.resource_type
    }

    pub fn name_digest(&self) -> Option<&Digest> {
        self.name_digest.as_ref()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-backup-resource/v1",
            &[
                ("arn", self.arn.digest().as_str().to_owned()),
                ("type", self.resource_type.as_str().to_owned()),
                (
                    "name",
                    self.name_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.arn.validate()?;
        self.resource_type.validate()?;
        self.name_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()
            .map(|_| ())
    }
}

impl fmt::Debug for ResourceIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResourceIdentity")
            .field("digest", &self.digest())
            .field("resource_type", &self.resource_type)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct BackupPlanIdentity {
    arn: BackupPlanArn,
    id: String,
    version_digest: Option<Digest>,
    rule_id_digest: Digest,
    rule_name_digest: Option<Digest>,
}

impl BackupPlanIdentity {
    pub fn new(
        arn: BackupPlanArn,
        id: impl Into<String>,
        version: Option<impl AsRef<str>>,
        rule_id: impl Into<String>,
        rule_name: Option<impl AsRef<str>>,
    ) -> Result<Self> {
        let id = id.into();
        let rule_id = rule_id.into();
        if !valid_identifier(&id, MAX_IDENTIFIER_BYTES)
            || !valid_identifier(&rule_id, MAX_IDENTIFIER_BYTES)
        {
            return Err(AwsBackupRecoveryError::InvalidIdentifier {
                field: "backup-plan-id",
            });
        }
        let version_digest = version
            .map(|value| value.as_ref().to_owned())
            .map(|value| {
                if valid_text(&value, MAX_IDENTIFIER_BYTES, true) {
                    Ok(Digest::from_text(value))
                } else {
                    Err(AwsBackupRecoveryError::InvalidIdentifier {
                        field: "backup-plan-version",
                    })
                }
            })
            .transpose()?;
        let rule_name_digest = rule_name
            .map(|value| value.as_ref().to_owned())
            .map(|value| {
                if valid_text(&value, MAX_IDENTIFIER_BYTES, true) {
                    Ok(Digest::from_parts(
                        "aws-backup-rule-name/v1",
                        &[("name", value)],
                    ))
                } else {
                    Err(AwsBackupRecoveryError::InvalidIdentifier {
                        field: "backup-rule-name",
                    })
                }
            })
            .transpose()?;
        Ok(Self {
            arn,
            id,
            version_digest,
            rule_id_digest: Digest::from_parts("aws-backup-rule-id/v1", &[("id", rule_id)]),
            rule_name_digest,
        })
    }

    pub fn arn(&self) -> &BackupPlanArn {
        &self.arn
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn version_digest(&self) -> Option<&Digest> {
        self.version_digest.as_ref()
    }

    pub fn rule_id_digest(&self) -> &Digest {
        &self.rule_id_digest
    }

    pub fn rule_name_digest(&self) -> Option<&Digest> {
        self.rule_name_digest.as_ref()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-backup-plan/v1",
            &[
                ("arn", self.arn.digest().as_str().to_owned()),
                ("id", self.id.clone()),
                (
                    "version",
                    self.version_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                ("rule_id", self.rule_id_digest.as_str().to_owned()),
                (
                    "rule_name",
                    self.rule_name_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.arn.validate()?;
        if !valid_identifier(&self.id, MAX_IDENTIFIER_BYTES) {
            return Err(AwsBackupRecoveryError::InvalidIdentifier {
                field: "backup-plan-id",
            });
        }
        self.version_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.rule_id_digest.validate()?;
        self.rule_name_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()
            .map(|_| ())
    }
}

impl fmt::Debug for BackupPlanIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BackupPlanIdentity")
            .field("digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct MissionIdentity {
    id: String,
    revision: u64,
}

impl MissionIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        let id = id.into();
        if !valid_identifier(&id, MAX_IDENTIFIER_BYTES) || revision == 0 {
            return Err(AwsBackupRecoveryError::InvalidScope);
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
            "aws-backup-mission/v1",
            &[
                ("id", self.id.clone()),
                ("revision", self.revision.to_string()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if valid_identifier(&self.id, MAX_IDENTIFIER_BYTES) && self.revision != 0 {
            Ok(())
        } else {
            Err(AwsBackupRecoveryError::InvalidScope)
        }
    }
}

impl fmt::Debug for MissionIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionIdentity")
            .field("digest", &self.digest())
            .field("revision", &self.revision)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ProjectIdentity {
    id: String,
    revision: u64,
}

impl ProjectIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        let id = id.into();
        if !valid_identifier(&id, MAX_IDENTIFIER_BYTES) || revision == 0 {
            return Err(AwsBackupRecoveryError::InvalidScope);
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
            "aws-backup-project/v1",
            &[
                ("id", self.id.clone()),
                ("revision", self.revision.to_string()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if valid_identifier(&self.id, MAX_IDENTIFIER_BYTES) && self.revision != 0 {
            Ok(())
        } else {
            Err(AwsBackupRecoveryError::InvalidScope)
        }
    }
}

impl fmt::Debug for ProjectIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProjectIdentity")
            .field("digest", &self.digest())
            .field("revision", &self.revision)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct WorkProductIdentity {
    id: String,
    revision: u64,
}

impl WorkProductIdentity {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        let id = id.into();
        if !valid_identifier(&id, MAX_IDENTIFIER_BYTES) || revision == 0 {
            return Err(AwsBackupRecoveryError::InvalidScope);
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
            "aws-backup-work-product/v1",
            &[
                ("id", self.id.clone()),
                ("revision", self.revision.to_string()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if valid_identifier(&self.id, MAX_IDENTIFIER_BYTES) && self.revision != 0 {
            Ok(())
        } else {
            Err(AwsBackupRecoveryError::InvalidScope)
        }
    }
}

impl fmt::Debug for WorkProductIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkProductIdentity")
            .field("digest", &self.digest())
            .field("revision", &self.revision)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AwsBackupRecoveryScope {
    account: AwsAccountId,
    region: AwsRegion,
    vault: BackupVaultIdentity,
    recovery_point: RecoveryPointIdentity,
    resource: ResourceIdentity,
    plan: BackupPlanIdentity,
    mission: MissionIdentity,
    project: ProjectIdentity,
    work_product: WorkProductIdentity,
}

impl AwsBackupRecoveryScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: AwsAccountId,
        region: AwsRegion,
        vault: BackupVaultIdentity,
        recovery_point: RecoveryPointIdentity,
        resource: ResourceIdentity,
        plan: BackupPlanIdentity,
        mission: MissionIdentity,
        project: ProjectIdentity,
        work_product: WorkProductIdentity,
    ) -> Result<Self> {
        let scope = Self {
            account,
            region,
            vault,
            recovery_point,
            resource,
            plan,
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

    pub fn vault(&self) -> &BackupVaultIdentity {
        &self.vault
    }

    pub fn recovery_point(&self) -> &RecoveryPointIdentity {
        &self.recovery_point
    }

    pub fn resource(&self) -> &ResourceIdentity {
        &self.resource
    }

    pub fn plan(&self) -> &BackupPlanIdentity {
        &self.plan
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
            "aws-backup-recovery-scope/v1",
            &[
                ("account", self.account.digest().as_str().to_owned()),
                ("region", self.region.digest().as_str().to_owned()),
                ("vault", self.vault.digest().as_str().to_owned()),
                (
                    "recovery_point",
                    self.recovery_point.digest().as_str().to_owned(),
                ),
                ("resource", self.resource.digest().as_str().to_owned()),
                ("plan", self.plan.digest().as_str().to_owned()),
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
        self.vault.validate()?;
        self.recovery_point.validate()?;
        self.resource.validate()?;
        self.plan.validate()?;
        self.mission.validate()?;
        self.project.validate()?;
        self.work_product.validate()
    }
}

impl fmt::Debug for AwsBackupRecoveryScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsBackupRecoveryScope")
            .field("digest", &self.digest())
            .field("account", &self.account)
            .field("region", &self.region)
            .field("vault", &self.vault)
            .field("recovery_point", &self.recovery_point)
            .field("resource", &self.resource)
            .field("plan", &self.plan)
            .field("mission", &self.mission)
            .field("project", &self.project)
            .field("work_product", &self.work_product)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    Sigv4Credential,
}

/// Opaque SigV4 reference. The caller-supplied handle is hashed and dropped;
/// it is never serializable, displayable, or present in Debug output.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretKind,
    reference_digest: Digest,
    scope_digest: Digest,
    revision: u64,
    revoked: bool,
}

impl SecretReference {
    pub fn new(opaque_handle: impl Into<String>, revision: u64) -> Result<Self> {
        let mut handle = opaque_handle.into();
        if !valid_text(&handle, MAX_IDENTIFIER_BYTES, true) || revision == 0 {
            handle.zeroize();
            return Err(AwsBackupRecoveryError::InvalidSecretReference);
        }
        let reference_digest = Digest::from_parts(
            "aws-backup-opaque-sigv4-reference/v1",
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
            scope_digest: Digest::from_text("unbound-aws-backup-secret-scope"),
            revision,
            revoked: false,
        })
    }

    pub fn sigv4(
        opaque_handle: impl Into<String>,
        scope: &AwsBackupRecoveryScope,
        revision: u64,
    ) -> Result<Self> {
        let mut reference = Self::new(opaque_handle, revision)?;
        reference.scope_digest = scope.digest();
        reference.reference_digest = Digest::from_parts(
            "aws-backup-opaque-sigv4-reference/v1",
            &[
                ("kind", "sigv4_credential".to_owned()),
                ("reference", reference.reference_digest.as_str().to_owned()),
                ("scope", reference.scope_digest.as_str().to_owned()),
                ("revision", revision.to_string()),
            ],
        );
        Ok(reference)
    }

    pub fn kind(&self) -> SecretKind {
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

    pub(crate) fn validate(&self, scope: &AwsBackupRecoveryScope) -> Result<()> {
        if !matches!(self.kind, SecretKind::Sigv4Credential)
            || self.revision == 0
            || self.revoked
            || self.scope_digest != scope.digest()
        {
            return Err(AwsBackupRecoveryError::InvalidSecretReference);
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

    pub const fn is_native(self) -> bool {
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
            "aws-backup-permissions/v1",
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
            || self.permissions.is_empty()
            || self
                .permissions
                .iter()
                .any(|permission| !LAYER1_PERMISSIONS.contains(&permission.as_str()))
        {
            Err(AwsBackupRecoveryError::InvalidPermissionSnapshot)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ConsentScope {
    id: String,
    revision: u64,
    permissions: BTreeSet<String>,
    expires_at: DateTime<Utc>,
    revoked: bool,
}

impl ConsentScope {
    pub fn new<I, S>(
        id: impl Into<String>,
        revision: u64,
        permissions: I,
        expires_at: DateTime<Utc>,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let consent = Self {
            id: id.into(),
            revision,
            permissions: permissions.into_iter().map(Into::into).collect(),
            expires_at,
            revoked: false,
        };
        consent.validate()?;
        Ok(consent)
    }

    pub fn for_layer_one(
        id: impl Into<String>,
        revision: u64,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        Self::new(id, revision, LAYER1_PERMISSIONS, expires_at)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-backup-consent/v1",
            &[
                ("id", self.id.clone()),
                ("revision", self.revision.to_string()),
                (
                    "permissions",
                    self.permissions
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                ("expires_at", self.expires_at.to_rfc3339()),
                ("revoked", self.revoked.to_string()),
            ],
        )
    }

    pub fn is_active_at(&self, at: DateTime<Utc>) -> bool {
        !self.revoked && at < self.expires_at
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn permissions(&self) -> &BTreeSet<String> {
        &self.permissions
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
            || self.permissions.is_empty()
            || self
                .permissions
                .iter()
                .any(|permission| !LAYER1_PERMISSIONS.contains(&permission.as_str()))
            || self.expires_at <= DateTime::<Utc>::MIN_UTC
        {
            Err(AwsBackupRecoveryError::InvalidConsent)
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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryPointStatus {
    Creating,
    Completed,
    Available,
    Partial,
    Deleting,
    Expired,
    Stopped,
}

impl RecoveryPointStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Creating => "creating",
            Self::Completed => "completed",
            Self::Available => "available",
            Self::Partial => "partial",
            Self::Deleting => "deleting",
            Self::Expired => "expired",
            Self::Stopped => "stopped",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageClass {
    Warm,
    Cold,
    Deleted,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EncryptionKeyType {
    AwsOwnedKmsKey,
    CustomerManagedKmsKey,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleMetadata {
    pub move_to_cold_storage_at: Option<DateTime<Utc>>,
    pub delete_at: Option<DateTime<Utc>>,
    pub move_to_cold_storage_after_days: Option<u64>,
    pub delete_after_days: Option<u64>,
    pub delete_after_event: Option<String>,
    pub opt_in_to_archive: bool,
}

impl LifecycleMetadata {
    pub fn new(
        move_to_cold_storage_at: Option<DateTime<Utc>>,
        delete_at: Option<DateTime<Utc>>,
        move_to_cold_storage_after_days: Option<u64>,
        delete_after_days: Option<u64>,
        delete_after_event: Option<String>,
        opt_in_to_archive: bool,
    ) -> Result<Self> {
        if let (Some(move_at), Some(delete_at)) = (move_to_cold_storage_at, delete_at)
            && move_at > delete_at
        {
            return Err(AwsBackupRecoveryError::InvalidScope);
        }
        if delete_after_event
            .as_deref()
            .is_some_and(|event| !valid_identifier(event, MAX_IDENTIFIER_BYTES))
        {
            return Err(AwsBackupRecoveryError::InvalidIdentifier {
                field: "delete-after-event",
            });
        }
        Ok(Self {
            move_to_cold_storage_at,
            delete_at,
            move_to_cold_storage_after_days,
            delete_after_days,
            delete_after_event,
            opt_in_to_archive,
        })
    }

    pub fn is_expired_at(&self, at: DateTime<Utc>) -> bool {
        self.delete_at.is_some_and(|delete_at| at >= delete_at)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptionMetadata {
    pub is_encrypted: bool,
    pub key_type: EncryptionKeyType,
    pub encryption_key_reference_digest: Option<Digest>,
}

impl EncryptionMetadata {
    pub fn new(
        is_encrypted: bool,
        key_type: EncryptionKeyType,
        encryption_key_arn: Option<impl AsRef<str>>,
    ) -> Result<Self> {
        let encryption_key_reference_digest = encryption_key_arn
            .map(|arn| arn.as_ref().to_owned())
            .map(|arn| {
                if valid_arn(&arn) {
                    Ok(Digest::from_parts(
                        "aws-backup-encryption-key-reference/v1",
                        &[("arn", arn)],
                    ))
                } else {
                    Err(AwsBackupRecoveryError::InvalidIdentifier {
                        field: "encryption-key-arn",
                    })
                }
            })
            .transpose()?;
        if is_encrypted != encryption_key_reference_digest.is_some() {
            return Err(AwsBackupRecoveryError::InvalidScope);
        }
        Ok(Self {
            is_encrypted,
            key_type,
            encryption_key_reference_digest,
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct RecoveryPointMetadata {
    recovery_point: RecoveryPointIdentity,
    resource: ResourceIdentity,
    plan: BackupPlanIdentity,
    status: RecoveryPointStatus,
    creation_date: DateTime<Utc>,
    initiation_date: Option<DateTime<Utc>>,
    completion_date: Option<DateTime<Utc>>,
    lifecycle: LifecycleMetadata,
    size_bytes: u64,
    encryption: EncryptionMetadata,
    storage_class: StorageClass,
    status_message_digest: Option<Digest>,
    parent_recovery_point_digest: Option<Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryPointMetadataInput {
    pub status: RecoveryPointStatus,
    pub creation_date: DateTime<Utc>,
    pub initiation_date: Option<DateTime<Utc>>,
    pub completion_date: Option<DateTime<Utc>>,
    pub lifecycle: LifecycleMetadata,
    pub size_bytes: u64,
    pub encryption: EncryptionMetadata,
    pub storage_class: StorageClass,
    pub status_message: Option<String>,
    pub parent_recovery_point_arn: Option<RecoveryPointArn>,
}

impl RecoveryPointMetadata {
    pub fn new(scope: &AwsBackupRecoveryScope, input: RecoveryPointMetadataInput) -> Result<Self> {
        Self::for_recovery_point(scope, scope.recovery_point.clone(), input)
    }

    pub fn for_recovery_point(
        scope: &AwsBackupRecoveryScope,
        recovery_point: RecoveryPointIdentity,
        input: RecoveryPointMetadataInput,
    ) -> Result<Self> {
        if input.size_bytes > u64::MAX / 2
            || matches!(
                input.status,
                RecoveryPointStatus::Completed | RecoveryPointStatus::Available
            ) && input.completion_date.is_none()
        {
            return Err(AwsBackupRecoveryError::InvalidScope);
        }
        let status_message_digest = input.status_message.map(|message| {
            Digest::from_parts("aws-backup-status-message/v1", &[("message", message)])
        });
        let parent_recovery_point_digest = input.parent_recovery_point_arn.map(|arn| arn.digest());
        let metadata = Self {
            recovery_point,
            resource: scope.resource.clone(),
            plan: scope.plan.clone(),
            status: input.status,
            creation_date: input.creation_date,
            initiation_date: input.initiation_date,
            completion_date: input.completion_date,
            lifecycle: input.lifecycle,
            size_bytes: input.size_bytes,
            encryption: input.encryption,
            storage_class: input.storage_class,
            status_message_digest,
            parent_recovery_point_digest,
        };
        metadata.validate_list_item_against(scope)?;
        Ok(metadata)
    }

    pub fn recovery_point(&self) -> &RecoveryPointIdentity {
        &self.recovery_point
    }

    pub fn resource(&self) -> &ResourceIdentity {
        &self.resource
    }

    pub fn plan(&self) -> &BackupPlanIdentity {
        &self.plan
    }

    pub const fn status(&self) -> RecoveryPointStatus {
        self.status
    }

    pub fn creation_date(&self) -> DateTime<Utc> {
        self.creation_date
    }

    pub fn initiation_date(&self) -> Option<DateTime<Utc>> {
        self.initiation_date
    }

    pub fn completion_date(&self) -> Option<DateTime<Utc>> {
        self.completion_date
    }

    pub fn lifecycle(&self) -> &LifecycleMetadata {
        &self.lifecycle
    }

    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    pub fn encryption(&self) -> &EncryptionMetadata {
        &self.encryption
    }

    pub const fn storage_class(&self) -> StorageClass {
        self.storage_class
    }

    pub fn status_message_digest(&self) -> Option<&Digest> {
        self.status_message_digest.as_ref()
    }

    pub fn parent_recovery_point_digest(&self) -> Option<&Digest> {
        self.parent_recovery_point_digest.as_ref()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-backup-recovery-point-metadata/v1",
            &[
                (
                    "recovery_point",
                    self.recovery_point.digest().as_str().to_owned(),
                ),
                ("resource", self.resource.digest().as_str().to_owned()),
                ("plan", self.plan.digest().as_str().to_owned()),
                ("status", self.status.as_str().to_owned()),
                ("creation_date", self.creation_date.to_rfc3339()),
                (
                    "initiation_date",
                    self.initiation_date
                        .map_or_else(String::new, |date| date.to_rfc3339()),
                ),
                (
                    "completion_date",
                    self.completion_date
                        .map_or_else(String::new, |date| date.to_rfc3339()),
                ),
                (
                    "lifecycle",
                    serde_json::to_string(&self.lifecycle)
                        .expect("lifecycle metadata is serializable"),
                ),
                ("size_bytes", self.size_bytes.to_string()),
                (
                    "encryption",
                    serde_json::to_string(&self.encryption)
                        .expect("encryption metadata is serializable"),
                ),
                ("storage_class", format!("{:?}", self.storage_class)),
                (
                    "status_message",
                    self.status_message_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "parent",
                    self.parent_recovery_point_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
            ],
        )
    }

    pub fn validate_against(&self, scope: &AwsBackupRecoveryScope) -> Result<()> {
        if self.recovery_point != scope.recovery_point {
            return Err(AwsBackupRecoveryError::ScopeMismatch);
        }
        self.validate_list_item_against(scope)
    }

    pub(crate) fn validate_list_item_against(&self, scope: &AwsBackupRecoveryScope) -> Result<()> {
        if self.resource != scope.resource
            || self.plan != scope.plan
            || self.creation_date > self.completion_date.unwrap_or(self.creation_date)
            || self.lifecycle.is_expired_at(self.creation_date)
                && !matches!(self.status, RecoveryPointStatus::Expired)
        {
            return Err(AwsBackupRecoveryError::ScopeMismatch);
        }
        self.recovery_point.validate()?;
        self.resource.validate()?;
        self.plan.validate()?;
        self.status_message_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.parent_recovery_point_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.encryption
            .encryption_key_reference_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()
            .map(|_| ())
    }
}

impl fmt::Debug for RecoveryPointMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryPointMetadata")
            .field("digest", &self.digest())
            .field("status", &self.status)
            .field("creation_date", &self.creation_date)
            .field("completion_date", &self.completion_date)
            .field("lifecycle", &self.lifecycle)
            .field("size_bytes", &self.size_bytes)
            .field("encryption", &self.encryption)
            .field("storage_class", &self.storage_class)
            .finish()
    }
}

impl Serialize for RecoveryPointMetadata {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("RecoveryPointMetadata", 16)?;
        state.serialize_field("recoveryPointDigest", &self.recovery_point.digest())?;
        state.serialize_field("resourceDigest", &self.resource.digest())?;
        state.serialize_field("resourceType", &self.resource.resource_type.as_str())?;
        state.serialize_field("planDigest", &self.plan.digest())?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("creationDate", &self.creation_date)?;
        state.serialize_field("initiationDate", &self.initiation_date)?;
        state.serialize_field("completionDate", &self.completion_date)?;
        state.serialize_field("lifecycle", &self.lifecycle)?;
        state.serialize_field("sizeBytes", &self.size_bytes)?;
        state.serialize_field("encryption", &self.encryption)?;
        state.serialize_field("storageClass", &self.storage_class)?;
        state.serialize_field("statusMessageDigest", &self.status_message_digest)?;
        state.serialize_field(
            "parentRecoveryPointDigest",
            &self.parent_recovery_point_digest,
        )?;
        state.end()
    }
}

pub type RecoveryPointSummary = RecoveryPointMetadata;

#[derive(Clone, Eq, PartialEq)]
pub struct RecoveryPointFilter {
    scope_digest: Digest,
    resource_arn: ResourceArn,
    resource_type: ResourceType,
    backup_plan_id: String,
    created_after: Option<DateTime<Utc>>,
    created_before: Option<DateTime<Utc>>,
    max_results: u16,
}

impl RecoveryPointFilter {
    pub fn for_scope(
        scope: &AwsBackupRecoveryScope,
        max_results: u16,
        created_after: Option<DateTime<Utc>>,
        created_before: Option<DateTime<Utc>>,
    ) -> Result<Self> {
        if max_results == 0 || max_results > MAX_PAGE_SIZE {
            return Err(AwsBackupRecoveryError::InvalidRequest);
        }
        if let (Some(after), Some(before)) = (created_after, created_before)
            && after > before
        {
            return Err(AwsBackupRecoveryError::InvalidRequest);
        }
        let filter = Self {
            scope_digest: scope.digest(),
            resource_arn: scope.resource.arn.clone(),
            resource_type: scope.resource.resource_type.clone(),
            backup_plan_id: scope.plan.id.clone(),
            created_after,
            created_before,
            max_results,
        };
        filter.validate_against(scope)?;
        Ok(filter)
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn resource_arn(&self) -> &ResourceArn {
        &self.resource_arn
    }

    pub fn resource_type(&self) -> &ResourceType {
        &self.resource_type
    }

    pub fn backup_plan_id(&self) -> &str {
        &self.backup_plan_id
    }

    pub fn created_after(&self) -> Option<DateTime<Utc>> {
        self.created_after
    }

    pub fn created_before(&self) -> Option<DateTime<Utc>> {
        self.created_before
    }

    pub const fn max_results(&self) -> u16 {
        self.max_results
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-backup-recovery-point-filter/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("resource", self.resource_arn.digest().as_str().to_owned()),
                ("resource_type", self.resource_type.as_str().to_owned()),
                ("plan_id", self.backup_plan_id.clone()),
                (
                    "created_after",
                    self.created_after
                        .map_or_else(String::new, |date| date.to_rfc3339()),
                ),
                (
                    "created_before",
                    self.created_before
                        .map_or_else(String::new, |date| date.to_rfc3339()),
                ),
                ("max_results", self.max_results.to_string()),
            ],
        )
    }

    pub fn validate_against(&self, scope: &AwsBackupRecoveryScope) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self.resource_arn != scope.resource.arn
            || self.resource_type != scope.resource.resource_type
            || self.backup_plan_id != scope.plan.id
            || self.max_results == 0
            || self.max_results > MAX_PAGE_SIZE
        {
            return Err(AwsBackupRecoveryError::FilterMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for RecoveryPointFilter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryPointFilter")
            .field("digest", &self.digest())
            .field("created_after", &self.created_after)
            .field("created_before", &self.created_before)
            .field("max_results", &self.max_results)
            .finish()
    }
}

impl Serialize for RecoveryPointFilter {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("RecoveryPointFilter", 7)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("resourceDigest", &self.resource_arn.digest())?;
        state.serialize_field("resourceType", &self.resource_type.as_str())?;
        state.serialize_field(
            "backupPlanIdDigest",
            &Digest::from_text(&self.backup_plan_id),
        )?;
        state.serialize_field("createdAfter", &self.created_after)?;
        state.serialize_field("createdBefore", &self.created_before)?;
        state.serialize_field("maxResults", &self.max_results)?;
        state.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct Cursor {
    scope_digest: Digest,
    filter_digest: Digest,
    token_digest: Digest,
    page_number: u16,
}

impl Cursor {
    pub fn new(
        opaque_token: impl Into<String>,
        scope: &AwsBackupRecoveryScope,
        filter: &RecoveryPointFilter,
        page_number: u16,
    ) -> Result<Self> {
        let token = opaque_token.into();
        if !valid_text(&token, MAX_IDENTIFIER_BYTES, true)
            || page_number == 0
            || page_number >= MAX_PAGES
        {
            return Err(AwsBackupRecoveryError::InvalidRequest);
        }
        filter.validate_against(scope)?;
        Ok(Self {
            scope_digest: scope.digest(),
            filter_digest: filter.digest(),
            token_digest: Digest::from_parts("aws-backup-next-token/v1", &[("token", token)]),
            page_number,
        })
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
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
        scope: &AwsBackupRecoveryScope,
        filter: &RecoveryPointFilter,
    ) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self.filter_digest != filter.digest()
            || self.page_number == 0
            || self.page_number >= MAX_PAGES
        {
            return Err(AwsBackupRecoveryError::CursorMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for Cursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Cursor")
            .field("scope_digest", &self.scope_digest)
            .field("filter_digest", &self.filter_digest)
            .field("token_digest", &self.token_digest)
            .field("page_number", &self.page_number)
            .finish()
    }
}

impl Serialize for Cursor {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("Cursor", 4)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("filterDigest", &self.filter_digest)?;
        state.serialize_field("tokenDigest", &self.token_digest)?;
        state.serialize_field("pageNumber", &self.page_number)?;
        state.end()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryEvidenceState {
    Completed,
    InProgress,
    Partial,
    Expired,
    Deleting,
    Stopped,
    NotFound,
    AccessLoss,
    Throttled,
    ProviderUnknown,
    RegistrationRevoked,
}

impl RecoveryEvidenceState {
    pub const fn is_review_complete(self) -> bool {
        matches!(self, Self::Completed)
    }

    pub const fn is_non_adoptable(self) -> bool {
        !self.is_review_complete()
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
    pub scope_digest: Digest,
    pub filter_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub list_digest: Option<Digest>,
    pub describe_digest: Option<Digest>,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryPointProjection {
    pub recovery_point_digest: Digest,
    pub vault_digest: Digest,
    pub resource_digest: Digest,
    pub resource_type: String,
    pub plan_digest: Digest,
    pub plan_rule_id_digest: Digest,
    pub plan_rule_name_digest: Option<Digest>,
    pub status: RecoveryPointStatus,
    pub creation_date: DateTime<Utc>,
    pub initiation_date: Option<DateTime<Utc>>,
    pub completion_date: Option<DateTime<Utc>>,
    pub lifecycle: LifecycleMetadata,
    pub size_bytes: u64,
    pub encryption: EncryptionMetadata,
    pub storage_class: StorageClass,
    pub status_message_digest: Option<Digest>,
    pub parent_recovery_point_digest: Option<Digest>,
}

impl RecoveryPointProjection {
    pub fn from_metadata(scope: &AwsBackupRecoveryScope, metadata: &RecoveryPointMetadata) -> Self {
        Self {
            recovery_point_digest: metadata.recovery_point.digest(),
            vault_digest: scope.vault.digest(),
            resource_digest: metadata.resource.digest(),
            resource_type: metadata.resource.resource_type.as_str().to_owned(),
            plan_digest: metadata.plan.digest(),
            plan_rule_id_digest: metadata.plan.rule_id_digest.clone(),
            plan_rule_name_digest: metadata.plan.rule_name_digest.clone(),
            status: metadata.status,
            creation_date: metadata.creation_date,
            initiation_date: metadata.initiation_date,
            completion_date: metadata.completion_date,
            lifecycle: metadata.lifecycle.clone(),
            size_bytes: metadata.size_bytes,
            encryption: metadata.encryption.clone(),
            storage_class: metadata.storage_class,
            status_message_digest: metadata.status_message_digest.clone(),
            parent_recovery_point_digest: metadata.parent_recovery_point_digest.clone(),
        }
    }
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
        revision: mission.revision,
    }
}

pub(crate) fn project_projection(project: &ProjectIdentity) -> ProjectProjection {
    ProjectProjection {
        id_digest: project.digest(),
        revision: project.revision,
    }
}

pub(crate) fn work_product_projection(work_product: &WorkProductIdentity) -> WorkProductProjection {
    WorkProductProjection {
        id_digest: work_product.digest(),
        revision: work_product.revision,
    }
}

pub(crate) fn validate_response_bytes(response_bytes: u64) -> Result<()> {
    if response_bytes > MAX_RESPONSE_BYTES {
        Err(AwsBackupRecoveryError::PartialEvidence)
    } else {
        Ok(())
    }
}

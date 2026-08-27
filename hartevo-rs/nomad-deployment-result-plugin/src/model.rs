use std::{collections::BTreeSet, fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};

use crate::error::{NomadDeploymentResultError, Result};

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
pub const MAX_PAGE_SIZE: u16 = 50;
pub const MAX_PAGES: u8 = 4;
pub const MAX_METADATA_ITEMS: usize = 3;

/// A lower-case SHA-256 digest used as an opaque evidence and authorization
/// fence. Digests are safe to serialize; their source material is not.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let digest = Self(value.into().to_ascii_lowercase());
        digest.validate()?;
        Ok(digest)
    }

    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(format!("{:x}", Sha256::digest(bytes)))
    }

    #[must_use]
    pub fn from_text(value: &str) -> Self {
        Self::from_bytes(value.as_bytes())
    }

    #[must_use]
    pub fn from_parts(label: &str, parts: &[(&str, String)]) -> Self {
        let mut input = String::from(label);
        for (key, value) in parts {
            input.push('\n');
            input.push_str(key);
            input.push('=');
            input.push_str(value);
        }
        Self::from_text(&input)
    }

    #[must_use]
    pub fn from_serializable<T: Serialize + ?Sized>(value: &T) -> Self {
        let bytes = serde_json::to_vec(value).expect("Nomad contract values serialize");
        Self::from_bytes(&bytes)
    }

    #[must_use]
    pub fn pending() -> Self {
        Self::from_text("pending-nomad-deployment-result-digest")
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<()> {
        if self.0.len() == 64 && self.0.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            Ok(())
        } else {
            Err(NomadDeploymentResultError::InvalidDigest)
        }
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for Digest {
    type Err = NomadDeploymentResultError;

    fn from_str(value: &str) -> Result<Self> {
        Self::new(value)
    }
}

/// A positive monotonically increasing revision used by scope and
/// registration fences.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 {
            Err(NomadDeploymentResultError::InvalidRevision { field: "revision" })
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl From<Revision> for u64 {
    fn from(value: Revision) -> Self {
        value.0
    }
}

fn validate_text(value: &str, field: &'static str, max: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > max
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        Err(NomadDeploymentResultError::InvalidText { field })
    } else {
        Ok(())
    }
}

fn validate_identifier(value: &str, field: &'static str) -> Result<()> {
    validate_text(value, field, MAX_IDENTIFIER_BYTES)?;
    if value.chars().any(char::is_whitespace) {
        Err(NomadDeploymentResultError::InvalidText { field })
    } else {
        Ok(())
    }
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                validate_identifier(&value, $field)?;
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn validate(&self) -> Result<()> {
                validate_identifier(&self.0, $field)
            }
        }

        impl FromStr for $name {
            type Err = NomadDeploymentResultError;

            fn from_str(value: &str) -> Result<Self> {
                Self::new(value)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

bounded_identifier!(ProjectId, "Project id");
bounded_identifier!(MissionId, "Mission id");
bounded_identifier!(WorkProductId, "Work Product id");
bounded_identifier!(NomadNamespace, "Nomad namespace");
bounded_identifier!(NomadRegion, "Nomad region");
bounded_identifier!(NomadDatacenter, "Nomad datacenter");
bounded_identifier!(NomadJobId, "Nomad job id");
bounded_identifier!(NomadDeploymentId, "Nomad deployment id");
bounded_identifier!(NomadAllocationId, "Nomad allocation id");
bounded_identifier!(NomadNodeId, "Nomad node id");

/// Provider address is a public endpoint identity, never an ACL/Vault secret.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct NomadAddress(String);

impl NomadAddress {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_text(&value, "Nomad address", MAX_IDENTIFIER_BYTES * 2)?;
        if value.contains(['\n', '\r', '\t']) {
            return Err(NomadDeploymentResultError::InvalidText {
                field: "Nomad address",
            });
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_text(&self.0)
    }
}

impl From<NomadAddress> for String {
    fn from(value: NomadAddress) -> Self {
        value.0
    }
}

impl fmt::Display for NomadAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for NomadAddress {
    type Err = NomadDeploymentResultError;

    fn from_str(value: &str) -> Result<Self> {
        Self::new(value)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Project {
    pub id: ProjectId,
    pub revision: Revision,
}

impl Project {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        Ok(Self {
            id: ProjectId::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Mission {
    pub id: MissionId,
    pub revision: Revision,
}

impl Mission {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        Ok(Self {
            id: MissionId::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProduct {
    pub id: WorkProductId,
    pub revision: Revision,
}

impl WorkProduct {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        Ok(Self {
            id: WorkProductId::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

/// Exact provider-side Nomad scope. Optional deployment/allocation IDs allow
/// a bounded job-only read, but an allocation can never be detached from a
/// deployment scope.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NomadProviderScope {
    pub address: NomadAddress,
    pub namespace: NomadNamespace,
    pub region: NomadRegion,
    pub datacenter: Option<NomadDatacenter>,
    pub job_id: NomadJobId,
    pub deployment_id: Option<NomadDeploymentId>,
    pub allocation_id: Option<NomadAllocationId>,
}

impl NomadProviderScope {
    pub fn new(
        address: impl Into<String>,
        namespace: impl Into<String>,
        region: impl Into<String>,
        datacenter: Option<impl Into<String>>,
        job_id: impl Into<String>,
        deployment_id: Option<impl Into<String>>,
        allocation_id: Option<impl Into<String>>,
    ) -> Result<Self> {
        let scope = Self {
            address: NomadAddress::new(address)?,
            namespace: NomadNamespace::new(namespace)?,
            region: NomadRegion::new(region)?,
            datacenter: datacenter
                .map(|value| NomadDatacenter::new(value.into()))
                .transpose()?,
            job_id: NomadJobId::new(job_id)?,
            deployment_id: deployment_id
                .map(|value| NomadDeploymentId::new(value.into()))
                .transpose()?,
            allocation_id: allocation_id
                .map(|value| NomadAllocationId::new(value.into()))
                .transpose()?,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn for_job(
        address: impl Into<String>,
        namespace: impl Into<String>,
        region: impl Into<String>,
        job_id: impl Into<String>,
    ) -> Result<Self> {
        Self::new(
            address,
            namespace,
            region,
            None::<String>,
            job_id,
            None::<String>,
            None::<String>,
        )
    }

    pub fn for_deployment(
        address: impl Into<String>,
        namespace: impl Into<String>,
        region: impl Into<String>,
        job_id: impl Into<String>,
        deployment_id: impl Into<String>,
    ) -> Result<Self> {
        Self::new(
            address,
            namespace,
            region,
            None::<String>,
            job_id,
            Some(deployment_id),
            None::<String>,
        )
    }

    pub fn validate(&self) -> Result<()> {
        if self.address.as_str().is_empty() {
            return Err(NomadDeploymentResultError::InvalidScope(
                "Nomad address is empty",
            ));
        }
        self.namespace.validate()?;
        self.region.validate()?;
        if let Some(datacenter) = &self.datacenter {
            datacenter.validate()?;
        }
        self.job_id.validate()?;
        if let Some(deployment_id) = &self.deployment_id {
            deployment_id.validate()?;
        }
        if let Some(allocation_id) = &self.allocation_id {
            allocation_id.validate()?;
            if self.deployment_id.is_none() {
                return Err(NomadDeploymentResultError::InvalidScope(
                    "allocation requires deployment",
                ));
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }

    #[must_use]
    pub fn job_digest(&self) -> Digest {
        self.job_id_digest()
    }

    #[must_use]
    pub fn job_id_digest(&self) -> Digest {
        Digest::from_text(self.job_id.as_str())
    }

    #[must_use]
    pub fn deployment_id_digest(&self) -> Option<Digest> {
        self.deployment_id
            .as_ref()
            .map(|value| Digest::from_text(value.as_str()))
    }

    #[must_use]
    pub fn allocation_id_digest(&self) -> Option<Digest> {
        self.allocation_id
            .as_ref()
            .map(|value| Digest::from_text(value.as_str()))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NomadDeploymentScope {
    pub project: Project,
    pub mission: Mission,
    pub work_product: WorkProduct,
    pub provider: NomadProviderScope,
}

impl NomadDeploymentScope {
    pub fn new(
        project: Project,
        mission: Mission,
        work_product: WorkProduct,
        provider: NomadProviderScope,
    ) -> Result<Self> {
        let scope = Self {
            project,
            mission,
            work_product,
            provider,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<()> {
        self.provider.validate()?;
        if self.project.revision.get() == 0
            || self.mission.revision.get() == 0
            || self.work_product.revision.get() == 0
        {
            return Err(NomadDeploymentResultError::InvalidScope(
                "Project, Mission, and Work Product revisions must be positive",
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }

    #[must_use]
    pub fn project_digest(&self) -> Digest {
        self.project.digest()
    }

    #[must_use]
    pub fn mission_digest(&self) -> Digest {
        self.mission.digest()
    }

    #[must_use]
    pub fn work_product_digest(&self) -> Digest {
        self.work_product.digest()
    }

    #[must_use]
    pub fn provider_scope_digest(&self) -> Digest {
        self.provider.digest()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    AclToken,
    VaultToken,
    Opaque,
}

/// Opaque, non-serializing credential reference. The supplied reference value
/// is immediately reduced to a digest and is never retained or emitted.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    revision: Revision,
    kind: SecretKind,
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("revision", &self.revision)
            .field("kind", &self.kind)
            .finish()
    }
}

impl SecretReference {
    pub fn new(
        reference: impl AsRef<str>,
        scope: &NomadDeploymentScope,
        revision: u64,
        kind: SecretKind,
    ) -> Result<Self> {
        let reference = reference.as_ref();
        validate_text(reference, "SecretReference", MAX_IDENTIFIER_BYTES * 8)
            .map_err(|_| NomadDeploymentResultError::InvalidSecretReference)?;
        let value = Self {
            reference_digest: Digest::from_text(reference),
            scope_digest: scope.digest(),
            revision: Revision::new(revision)
                .map_err(|_| NomadDeploymentResultError::InvalidSecretReference)?,
            kind,
        };
        value.validate(scope)?;
        Ok(value)
    }

    pub fn acl_token(
        reference: impl AsRef<str>,
        scope: &NomadDeploymentScope,
        revision: u64,
    ) -> Result<Self> {
        Self::new(reference, scope, revision, SecretKind::AclToken)
    }

    pub fn vault_token(
        reference: impl AsRef<str>,
        scope: &NomadDeploymentScope,
        revision: u64,
    ) -> Result<Self> {
        Self::new(reference, scope, revision, SecretKind::VaultToken)
    }

    pub fn token(
        reference: impl AsRef<str>,
        scope: &NomadDeploymentScope,
        revision: u64,
    ) -> Result<Self> {
        Self::acl_token(reference, scope, revision)
    }

    pub fn opaque(
        reference: impl AsRef<str>,
        scope: &NomadDeploymentScope,
        revision: u64,
    ) -> Result<Self> {
        Self::new(reference, scope, revision, SecretKind::Opaque)
    }

    #[must_use]
    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub const fn kind(&self) -> SecretKind {
        self.kind
    }

    pub fn validate(&self, scope: &NomadDeploymentScope) -> Result<()> {
        scope.validate()?;
        if self.scope_digest != scope.digest() {
            return Err(NomadDeploymentResultError::ScopeMismatch);
        }
        self.reference_digest.validate()?;
        if self.revision.get() == 0 {
            return Err(NomadDeploymentResultError::InvalidSecretReference);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionSnapshot {
    pub revision: Revision,
    pub permissions: BTreeSet<String>,
    pub digest: Digest,
}

pub const LAYER1_PERMISSIONS: [&str; 4] = [
    "nomad:jobs.read",
    "nomad:deployments.read",
    "nomad:allocations.read",
    "mission.scope",
];

impl PermissionSnapshot {
    pub fn new<I, S>(revision: u64, permissions: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let value = Self {
            revision: Revision::new(revision)?,
            permissions: permissions.into_iter().map(Into::into).collect(),
            digest: Digest::pending(),
        };
        let mut value = value;
        value.digest = value.compute_digest();
        value.validate()?;
        Ok(value)
    }

    pub fn for_layer_one(revision: u64) -> Result<Self> {
        Self::new(revision, LAYER1_PERMISSIONS)
    }

    pub fn validate(&self) -> Result<()> {
        if self.revision.get() == 0
            || self.permissions.len() != LAYER1_PERMISSIONS.len()
            || !LAYER1_PERMISSIONS
                .iter()
                .all(|permission| self.permissions.contains(*permission))
            || self.permissions.iter().any(|permission| {
                permission.contains("write")
                    || permission.contains("logs")
                    || permission.contains("events")
                    || permission.contains("secrets")
            })
            || self.digest != self.compute_digest()
        {
            return Err(NomadDeploymentResultError::InvalidPermissionSnapshot);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&(&self.revision, &self.permissions))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentScope {
    pub id_digest: Digest,
    pub scope_digest: Option<Digest>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub revoked: bool,
    pub digest: Digest,
}

impl ConsentScope {
    pub fn new(
        id: impl AsRef<str>,
        scope: &NomadDeploymentScope,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self> {
        let mut value = Self {
            id_digest: Digest::from_text(id.as_ref()),
            scope_digest: Some(scope.digest()),
            issued_at,
            expires_at,
            revoked: false,
            digest: Digest::pending(),
        };
        value.digest = value.compute_digest();
        value.validate_at(issued_at)?;
        Ok(value)
    }

    pub fn for_layer_one(id: impl AsRef<str>, issued_at: u64, expires_at: u64) -> Result<Self> {
        if id.as_ref().is_empty() || expires_at <= issued_at {
            return Err(NomadDeploymentResultError::InvalidConsent);
        }
        let mut value = Self {
            id_digest: Digest::from_text(id.as_ref()),
            scope_digest: None,
            issued_at,
            expires_at,
            revoked: false,
            digest: Digest::pending(),
        };
        value.digest = value.compute_digest();
        value.validate_at(issued_at)?;
        Ok(value)
    }

    pub fn validate_for(&self, scope: &NomadDeploymentScope, now: u64) -> Result<()> {
        self.validate_at(now)?;
        if self
            .scope_digest
            .as_ref()
            .is_some_and(|digest| digest != &scope.digest())
        {
            return Err(NomadDeploymentResultError::ConsentMismatch);
        }
        Ok(())
    }

    pub fn validate_at(&self, now: u64) -> Result<()> {
        if self.id_digest.as_str().is_empty()
            || self.expires_at <= self.issued_at
            || now < self.issued_at
            || now >= self.expires_at
            || self.revoked
            || self.digest != self.compute_digest()
        {
            return Err(if self.revoked {
                NomadDeploymentResultError::ConsentMismatch
            } else {
                NomadDeploymentResultError::InvalidConsent
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    fn compute_digest(&self) -> Digest {
        let mut value = self.clone();
        value.digest = Digest::pending();
        Digest::from_serializable(&value)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
    Reversed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationTransitionEvidence {
    pub from: RegistrationStatus,
    pub to: RegistrationStatus,
    pub registration_revision: Revision,
    pub registration_digest: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Recording,
    Fixture,
    Fake,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    #[must_use]
    pub const fn connected(self) -> bool {
        false
    }

    #[must_use]
    pub const fn native(self) -> bool {
        false
    }

    #[must_use]
    pub const fn first_party(self) -> bool {
        false
    }

    #[must_use]
    pub const fn provider_receipt(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NomadReadOperation {
    ReadJobMetadata,
    ReadDeploymentMetadata,
    ReadAllocationMetadata,
}

impl NomadReadOperation {
    pub const ALL: [Self; 3] = [
        Self::ReadJobMetadata,
        Self::ReadDeploymentMetadata,
        Self::ReadAllocationMetadata,
    ];

    #[must_use]
    pub const fn permission(self) -> &'static str {
        match self {
            Self::ReadJobMetadata => "nomad:jobs.read",
            Self::ReadDeploymentMetadata => "nomad:deployments.read",
            Self::ReadAllocationMetadata => "nomad:allocations.read",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NomadReadRequest {
    pub operation: NomadReadOperation,
    pub scope_digest: Digest,
    pub registration_digest: Option<Digest>,
    pub permission_digest: Option<Digest>,
    pub consent_digest: Option<Digest>,
    pub page_size: u16,
    pub page: u8,
}

impl NomadReadRequest {
    pub fn new(operation: NomadReadOperation, scope: &NomadDeploymentScope) -> Result<Self> {
        scope.validate()?;
        Ok(Self {
            operation,
            scope_digest: scope.digest(),
            registration_digest: None,
            permission_digest: None,
            consent_digest: None,
            page_size: MAX_METADATA_ITEMS as u16,
            page: 1,
        })
    }

    pub fn for_registration(
        operation: NomadReadOperation,
        scope: &NomadDeploymentScope,
        registration: &Digest,
        permission: &Digest,
        consent: &Digest,
    ) -> Result<Self> {
        let mut request = Self::new(operation, scope)?;
        request.registration_digest = Some(registration.clone());
        request.permission_digest = Some(permission.clone());
        request.consent_digest = Some(consent.clone());
        Ok(request)
    }

    pub fn validate_for(
        &self,
        scope: &NomadDeploymentScope,
        registration: &Digest,
        permission: &Digest,
        consent: &Digest,
    ) -> Result<()> {
        scope.validate()?;
        if self.scope_digest != scope.digest()
            || self.registration_digest.as_ref() != Some(registration)
            || self.permission_digest.as_ref() != Some(permission)
            || self.consent_digest.as_ref() != Some(consent)
            || self.page == 0
            || self.page > MAX_PAGES
            || self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
        {
            return Err(NomadDeploymentResultError::ScopeMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub fn request_digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionSummary {
    pub raw_job_payload_retained: bool,
    pub raw_deployment_events_retained: bool,
    pub raw_allocation_task_states_retained: bool,
    pub raw_logs_retained: bool,
    pub secret_material_retained: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NomadJobState {
    Pending,
    Running,
    Dead,
    Unknown,
}

impl NomadJobState {
    #[must_use]
    pub fn from_wire(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "pending" => Self::Pending,
            "running" => Self::Running,
            "dead" | "deregistered" => Self::Dead,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NomadDeploymentStatus {
    Pending,
    Running,
    Successful,
    Failed,
    Stopped,
    Unknown,
}

impl NomadDeploymentStatus {
    #[must_use]
    pub fn from_wire(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "pending" => Self::Pending,
            "running" | "active" => Self::Running,
            "successful" | "complete" | "completed" => Self::Successful,
            "failed" | "error" => Self::Failed,
            "stopped" | "cancelled" | "canceled" => Self::Stopped,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NomadAllocationStatus {
    Pending,
    Running,
    Complete,
    Failed,
    Lost,
    Unknown,
}

impl NomadAllocationStatus {
    #[must_use]
    pub fn from_wire(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "pending" | "queued" => Self::Pending,
            "running" => Self::Running,
            "complete" | "completed" => Self::Complete,
            "failed" | "error" => Self::Failed,
            "lost" => Self::Lost,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NomadJobProjection {
    pub id_digest: Digest,
    pub namespace_digest: Digest,
    pub region_digest: Digest,
    pub status: NomadJobState,
    pub version: u64,
    pub create_index: u64,
    pub modify_index: u64,
    pub datacenter_count: u16,
    pub task_group_count: u16,
    pub metadata_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NomadDeploymentProjection {
    pub id_digest: Digest,
    pub job_id_digest: Digest,
    pub job_version: u64,
    pub status: NomadDeploymentStatus,
    pub desired_total: u16,
    pub placed_allocations: u16,
    pub healthy_allocations: u16,
    pub unhealthy_allocations: u16,
    pub create_index: u64,
    pub modify_index: u64,
    pub metadata_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NomadAllocationProjection {
    pub id_digest: Digest,
    pub job_id_digest: Digest,
    pub deployment_id_digest: Option<Digest>,
    pub node_id_digest: Option<Digest>,
    pub task_group_digest: Digest,
    pub desired_status: NomadAllocationStatus,
    pub client_status: NomadAllocationStatus,
    pub create_index: u64,
    pub modify_index: u64,
    pub metadata_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FailureEvidence {
    pub category: String,
    pub status_code: Option<u16>,
    pub retry_after_seconds: Option<u64>,
    pub detail_digest: Digest,
}

impl FailureEvidence {
    #[must_use]
    pub fn from_transport(error: &crate::NomadTransportError) -> Self {
        let retry_after_seconds = match error {
            crate::NomadTransportError::RateLimited {
                retry_after_seconds,
            } => *retry_after_seconds,
            _ => None,
        };
        Self {
            category: error.category().to_owned(),
            status_code: error.status_code(),
            retry_after_seconds,
            detail_digest: Digest::from_text(error.category()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub project_digest: Digest,
    pub mission_digest: Digest,
    pub work_product_digest: Digest,
    pub provider_scope_digest: Digest,
    pub job_digest: Digest,
    pub deployment_digest: Option<Digest>,
    pub allocation_digest: Option<Digest>,
    pub evidence_digest: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NomadDeploymentState {
    Absent,
    Pending,
    Running,
    Successful,
    Failed,
    Stopped,
    Partial,
    AccessLoss,
    ProviderUnknown,
    BlockedEnv,
    Tampered,
    Replay,
    RegistrationRevoked,
    RegistrationReversed,
}

impl NomadDeploymentState {
    #[must_use]
    pub const fn is_non_adoptable(self) -> bool {
        !matches!(self, Self::Successful)
    }

    #[must_use]
    pub const fn is_terminal_success(self) -> bool {
        matches!(self, Self::Successful)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NomadDeploymentEvidence {
    pub scope: NomadDeploymentScope,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub secret_reference_digest: Digest,
    pub state: NomadDeploymentState,
    pub job: Option<NomadJobProjection>,
    pub deployment: Option<NomadDeploymentProjection>,
    pub allocation: Option<NomadAllocationProjection>,
    pub page_count: u8,
    pub item_count: u8,
    pub complete: bool,
    pub provenance: ProviderProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub redaction: RedactionSummary,
    pub failure: Option<FailureEvidence>,
    pub digests: EvidenceDigests,
    pub evidence_digest: Digest,
    pub observed_at: u64,
}

impl NomadDeploymentEvidence {
    #[must_use]
    pub fn compute_digest(&self) -> Digest {
        let mut value = self.clone();
        value.evidence_digest = Digest::pending();
        value.digests.evidence_digest = Digest::pending();
        Digest::from_serializable(&value)
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.scope.validate()?;
        self.digests.contract_digest.validate()?;
        self.digests.provider_digest.validate()?;
        self.digests.api_digest.validate()?;
        self.digests.permission_digest.validate()?;
        self.digests.consent_digest.validate()?;
        self.digests.scope_digest.validate()?;
        self.digests.secret_reference_digest.validate()?;
        if self.digests.scope_digest != self.scope.digest()
            || self.digests.project_digest != self.scope.project_digest()
            || self.digests.mission_digest != self.scope.mission_digest()
            || self.digests.work_product_digest != self.scope.work_product_digest()
            || self.digests.provider_scope_digest != self.scope.provider_scope_digest()
            || self.registration_digest.as_str().is_empty()
            || self.permission_digest != self.digests.permission_digest
            || self.consent_digest != self.digests.consent_digest
            || self.secret_reference_digest != self.digests.secret_reference_digest
            || self.page_count > MAX_PAGES
            || self.item_count > MAX_METADATA_ITEMS as u8
            || self.redaction.raw_job_payload_retained
            || self.redaction.raw_deployment_events_retained
            || self.redaction.raw_allocation_task_states_retained
            || self.redaction.raw_logs_retained
            || self.redaction.secret_material_retained
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.evidence_digest != self.digests.evidence_digest
            || self.evidence_digest != self.compute_digest()
        {
            return Err(NomadDeploymentResultError::TamperedEvidence);
        }
        Ok(())
    }

    #[must_use]
    pub fn is_adoptable(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NomadDeploymentProposal {
    pub scope: NomadDeploymentScope,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub secret_reference_digest: Digest,
    pub state: NomadDeploymentState,
    pub evidence: NomadDeploymentEvidence,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub kernel_authority: bool,
    pub truth_authority: bool,
    pub consent_authority: bool,
    pub effect_authority: bool,
    pub receipt_authority: bool,
    pub verification_authority: bool,
    pub outcome_adoption: bool,
    pub work_product_adoption: bool,
    pub proposal_digest: Digest,
}

impl NomadDeploymentProposal {
    #[must_use]
    pub fn from_evidence(evidence: NomadDeploymentEvidence) -> Self {
        let mut value = Self {
            scope: evidence.scope.clone(),
            registration_digest: evidence.registration_digest.clone(),
            registration_revision: evidence.registration_revision,
            permission_digest: evidence.permission_digest.clone(),
            consent_digest: evidence.consent_digest.clone(),
            secret_reference_digest: evidence.secret_reference_digest.clone(),
            state: evidence.state,
            evidence,
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            kernel_authority: false,
            truth_authority: false,
            consent_authority: false,
            effect_authority: false,
            receipt_authority: false,
            verification_authority: false,
            outcome_adoption: false,
            work_product_adoption: false,
            proposal_digest: Digest::pending(),
        };
        value.proposal_digest = value.compute_digest();
        value
    }

    #[must_use]
    pub fn compute_digest(&self) -> Digest {
        let mut value = self.clone();
        value.proposal_digest = Digest::pending();
        Digest::from_serializable(&value)
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.scope.validate()?;
        self.evidence.validate_integrity()?;
        if !self.proposal_only
            || self.connected
            || self.native
            || self.first_party
            || self.kernel_authority
            || self.truth_authority
            || self.consent_authority
            || self.effect_authority
            || self.receipt_authority
            || self.verification_authority
            || self.outcome_adoption
            || self.work_product_adoption
            || self.scope != self.evidence.scope
            || self.registration_digest != self.evidence.registration_digest
            || self.registration_revision != self.evidence.registration_revision
            || self.permission_digest != self.evidence.permission_digest
            || self.consent_digest != self.evidence.consent_digest
            || self.secret_reference_digest != self.evidence.secret_reference_digest
            || self.state != self.evidence.state
            || self.proposal_digest != self.compute_digest()
        {
            return Err(NomadDeploymentResultError::TamperedEvidence);
        }
        Ok(())
    }

    #[must_use]
    pub fn is_adoptable(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailure {
    Tampered,
    RegistrationMismatch,
    ScopeMismatch,
    StaleRevision,
    RegistrationRevoked,
    RegistrationReversed,
    Absent,
    Partial,
    AccessLoss,
    ProviderUnknown,
    Replay,
    NotSuccessful,
    NativeClaim,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NomadDeploymentVerification {
    pub proposal_digest: Digest,
    pub valid: bool,
    pub business_verified: bool,
    pub failures: Vec<VerificationFailure>,
}

impl NomadDeploymentVerification {
    #[must_use]
    pub fn new(proposal: &NomadDeploymentProposal, failures: Vec<VerificationFailure>) -> Self {
        Self {
            proposal_digest: proposal.proposal_digest.clone(),
            valid: failures.is_empty(),
            business_verified: false,
            failures,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NomadDeploymentReceipt {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub state: NomadDeploymentState,
    pub provenance: ProviderProvenance,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub durable_provider_receipt: bool,
    pub recording_digest: Digest,
    pub recorded_at: u64,
}

impl NomadDeploymentReceipt {
    #[must_use]
    pub fn new(
        proposal: &NomadDeploymentProposal,
        idempotency_key_digest: Digest,
        recorded_at: u64,
        replayed: bool,
    ) -> Self {
        let mut value = Self {
            idempotency_key_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            state: proposal.state,
            provenance: proposal.evidence.provenance,
            replayed,
            connected: false,
            native: false,
            first_party: false,
            durable_provider_receipt: false,
            recording_digest: Digest::pending(),
            recorded_at,
        };
        value.recording_digest = value.compute_digest();
        value
    }

    #[must_use]
    pub fn compute_digest(&self) -> Digest {
        let mut value = self.clone();
        value.recording_digest = Digest::pending();
        Digest::from_serializable(&value)
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.connected
            || self.native
            || self.first_party
            || self.durable_provider_receipt
            || self.recording_digest != self.compute_digest()
        {
            return Err(NomadDeploymentResultError::TamperedEvidence);
        }
        Ok(())
    }
}

pub type RecordedNomadDeploymentResult = NomadDeploymentReceipt;

pub type ProjectProjection = Project;
pub type MissionProjection = Mission;
pub type WorkProductProjection = WorkProduct;
pub type NomadResultState = NomadDeploymentState;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NomadFailureState {
    pub state: NomadDeploymentState,
    pub failure: FailureEvidence,
}

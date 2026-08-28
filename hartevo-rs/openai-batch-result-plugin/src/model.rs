use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};

use crate::{
    CONTRACT_VERSION, PLUGIN_ID, PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID,
    error::{OpenAiBatchResultError, Result},
};

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_ENDPOINT_BYTES: usize = 128;
pub const MAX_COMPLETION_WINDOW_BYTES: usize = 32;
pub const MAX_METADATA_KEYS: usize = 16;
pub const MAX_METADATA_KEY_BYTES: usize = 64;
pub const MAX_METADATA_VALUE_BYTES: usize = 512;
pub const MAX_PAGE_LIMIT: u32 = 100;
pub const MAX_BATCHES_PER_PAGE: usize = 100;
pub const MAX_PAGES: usize = 32;
pub const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

/// Lowercase SHA-256 used for every identity, scope, response, and evidence
/// fence.  A digest is safe to serialize; the material it represents is not
/// retained by the Layer-1 projections.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    #[must_use]
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        Self(hex::encode(Sha256::digest(bytes.as_ref())))
    }

    #[must_use]
    pub fn from_text(value: impl AsRef<str>) -> Self {
        Self::from_bytes(value.as_ref().as_bytes())
    }

    #[must_use]
    pub fn from_serializable<T: Serialize + ?Sized>(value: &T) -> Self {
        let bytes = serde_json::to_vec(value).expect("OpenAI Batch contract values serialize");
        Self::from_bytes(bytes)
    }

    #[must_use]
    pub fn pending() -> Self {
        Self::from_text("pending-openai-batch-result-digest")
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self, field: &'static str) -> Result<()> {
        if self.0.len() == 64
            && self
                .0
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            Ok(())
        } else {
            Err(OpenAiBatchResultError::InvalidDigest { field })
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

macro_rules! bounded_identifier {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if value.is_empty()
                    || value.len() > MAX_IDENTIFIER_BYTES
                    || value.chars().any(char::is_control)
                    || value.chars().any(char::is_whitespace)
                    || value
                        .bytes()
                        .any(|byte| matches!(byte, b'/' | b'?' | b'#' | b'%'))
                {
                    Err(OpenAiBatchResultError::InvalidIdentifier { field: $field })
                } else {
                    Ok(Self(value))
                }
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn validate(&self) -> Result<()> {
                Self::new(self.0.clone()).map(|_| ())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

bounded_identifier!(OrganizationId, "organization_id");
bounded_identifier!(ProjectId, "openai_project_id");
bounded_identifier!(HartevoProjectId, "hartevo_project_id");
bounded_identifier!(BatchId, "batch_id");
bounded_identifier!(FileId, "file_id");
bounded_identifier!(MissionId, "mission_id");
bounded_identifier!(WorkProductId, "work_product_id");
bounded_identifier!(ModelId, "model_id");

/// A non-floating revision fence.  It is deliberately numeric so a caller
/// cannot hide an unbounded provider label in a registration digest.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 {
            Err(OpenAiBatchResultError::InvalidRevision { field: "revision" })
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// The only endpoint identity admitted by the Batch read seam.  It is an API
/// endpoint label, not an executable model/tool route.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Endpoint(String);

impl Endpoint {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_ENDPOINT_BYTES
            || !value.starts_with("/v1/")
            || value.ends_with('/')
            || value.contains("//")
            || value.chars().any(char::is_control)
            || value.chars().any(char::is_whitespace)
            || value.contains('?')
            || value.contains('#')
        {
            Err(OpenAiBatchResultError::InvalidIdentifier { field: "endpoint" })
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct CompletionWindow(String);

impl CompletionWindow {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_COMPLETION_WINDOW_BYTES
            || value.chars().any(char::is_control)
            || value.chars().any(char::is_whitespace)
        {
            Err(OpenAiBatchResultError::InvalidText {
                field: "completion_window",
            })
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Exact API host/version binding.  The official host is the only production
/// identity; loopback is admitted solely for a local evidence seam.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApiBinding {
    pub base_url: String,
    pub revision: Revision,
}

impl ApiBinding {
    pub fn new(base_url: impl Into<String>, revision: Revision) -> Result<Self> {
        let base_url = base_url.into().trim_end_matches('/').to_owned();
        let official = base_url == "https://api.openai.com";
        let loopback =
            base_url.starts_with("http://127.0.0.1:") || base_url.starts_with("http://localhost:");
        if (!official && !loopback)
            || base_url.contains('?')
            || base_url.contains('#')
            || base_url.contains("..")
            || base_url.chars().any(char::is_whitespace)
            || base_url.len() > MAX_IDENTIFIER_BYTES
        {
            return Err(OpenAiBatchResultError::InvalidApiBinding);
        }
        Ok(Self { base_url, revision })
    }

    #[must_use]
    pub fn official(revision: Revision) -> Self {
        Self {
            base_url: String::from("https://api.openai.com"),
            revision,
        }
    }

    #[must_use]
    pub fn loopback(revision: Revision) -> Self {
        Self {
            base_url: String::from("http://127.0.0.1:8787"),
            revision,
        }
    }

    pub fn validate(&self) -> Result<()> {
        Self::new(self.base_url.clone(), self.revision).map(|_| ())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }

    #[must_use]
    pub fn revision_digest(&self) -> Digest {
        Digest::from_serializable(&self.revision)
    }
}

/// Optional exact model metadata.  This is a binding to the model field
/// returned by a Batch object, not a model catalog or execution authority.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModelBinding {
    pub model_id: Option<ModelId>,
    pub revision: Revision,
}

impl ModelBinding {
    pub fn exact(model_id: ModelId, revision: Revision) -> Self {
        Self {
            model_id: Some(model_id),
            revision,
        }
    }

    #[must_use]
    pub fn unspecified(revision: Revision) -> Self {
        Self {
            model_id: None,
            revision,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if let Some(model) = &self.model_id {
            model.validate()?;
        }
        Revision::new(self.revision.get())?;
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }

    #[must_use]
    pub fn revision_digest(&self) -> Digest {
        Digest::from_serializable(&self.revision)
    }

    pub fn validate_observed(&self, observed: Option<&ModelId>) -> Result<()> {
        if let Some(expected) = &self.model_id
            && observed != Some(expected)
        {
            return Err(OpenAiBatchResultError::ModelMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchPermission {
    ReadBatches,
}

/// The exact read-only permission snapshot.  No create/upload/cancel/file
/// content operation can be represented by this type.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionBinding {
    pub permission: BatchPermission,
    pub revision: Revision,
    pub digest: Digest,
}

impl PermissionBinding {
    pub fn read_only(revision: Revision) -> Self {
        let mut binding = Self {
            permission: BatchPermission::ReadBatches,
            revision,
            digest: Digest::pending(),
        };
        binding.digest = binding.computed_digest();
        binding
    }

    fn computed_digest(&self) -> Digest {
        Digest::from_serializable(&(self.permission, self.revision))
    }

    pub fn validate(&self) -> Result<()> {
        Revision::new(self.revision.get())?;
        if self.permission != BatchPermission::ReadBatches || self.digest != self.computed_digest()
        {
            return Err(OpenAiBatchResultError::InvalidPermission);
        }
        Ok(())
    }

    #[must_use]
    pub fn revision_digest(&self) -> Digest {
        Digest::from_serializable(&self.revision)
    }
}

/// Opaque API-key reference.  This type intentionally has no Serialize or
/// Deserialize implementation and never stores the caller-supplied handle.
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    revision: Revision,
    revoked: bool,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_digest: self.reference_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            revision: self.revision,
            revoked: self.revoked,
        }
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest
            && self.scope_digest == other.scope_digest
            && self.revision == other.revision
            && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish_non_exhaustive()
    }
}

impl SecretReference {
    pub fn api_key(
        opaque_reference: impl AsRef<str>,
        scope_digest: Digest,
        revision: Revision,
    ) -> Result<Self> {
        let opaque_reference = opaque_reference.as_ref();
        if opaque_reference.is_empty()
            || opaque_reference.len() > MAX_IDENTIFIER_BYTES
            || opaque_reference.chars().any(char::is_control)
            || opaque_reference.chars().any(char::is_whitespace)
        {
            return Err(OpenAiBatchResultError::InvalidIdentifier {
                field: "opaque_api_key_reference",
            });
        }
        scope_digest.validate("secret_scope_digest")?;
        let reference_digest = Digest::from_serializable(&(
            "openai-api-key-secret-reference/v1",
            opaque_reference,
            &scope_digest,
            revision,
        ));
        Ok(Self {
            reference_digest,
            scope_digest,
            revision,
            revoked: false,
        })
    }

    pub fn new(
        opaque_reference: impl AsRef<str>,
        scope_digest: Digest,
        revision: Revision,
    ) -> Result<Self> {
        Self::api_key(opaque_reference, scope_digest, revision)
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
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn validate(&self) -> Result<()> {
        self.reference_digest.validate("secret_reference_digest")?;
        self.scope_digest.validate("secret_scope_digest")?;
        Revision::new(self.revision.get())?;
        Ok(())
    }

    pub fn validate_for_scope(&self, scope_digest: &Digest) -> Result<()> {
        self.validate()?;
        if &self.scope_digest != scope_digest {
            return Err(OpenAiBatchResultError::SecretReferenceMismatch);
        }
        if self.revoked {
            return Err(OpenAiBatchResultError::SecretRevoked);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<()> {
        if self.revoked {
            Err(OpenAiBatchResultError::SecretRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }

    pub fn restore(&mut self) -> Result<()> {
        if self.revoked {
            self.revoked = false;
            Ok(())
        } else {
            Err(OpenAiBatchResultError::InvalidRequest("secret is active"))
        }
    }
}

/// The exact external and Hartevo scope used by this plugin.  The secret is
/// kept outside the serializable identity and can only be inspected through
/// its digest/revision accessors.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenAiBatchScopeIdentity {
    pub organization_id: OrganizationId,
    pub project_id: ProjectId,
    pub batch_id: Option<BatchId>,
    pub endpoint: Option<Endpoint>,
    pub input_file_id: Option<FileId>,
    pub model: ModelBinding,
    pub api: ApiBinding,
    pub permission: PermissionBinding,
    pub hartevo_project_id: HartevoProjectId,
    pub mission_id: MissionId,
    pub work_product_id: WorkProductId,
    pub project_revision: Revision,
    pub mission_revision: Revision,
    pub work_product_revision: Revision,
    pub scope_revision: Revision,
}

impl OpenAiBatchScopeIdentity {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        organization_id: OrganizationId,
        project_id: ProjectId,
        batch_id: Option<BatchId>,
        endpoint: Option<Endpoint>,
        input_file_id: Option<FileId>,
        model: ModelBinding,
        api: ApiBinding,
        permission: PermissionBinding,
        hartevo_project_id: HartevoProjectId,
        mission_id: MissionId,
        work_product_id: WorkProductId,
        project_revision: Revision,
        mission_revision: Revision,
        work_product_revision: Revision,
        scope_revision: Revision,
    ) -> Result<Self> {
        let identity = Self {
            organization_id,
            project_id,
            batch_id,
            endpoint,
            input_file_id,
            model,
            api,
            permission,
            hartevo_project_id,
            mission_id,
            work_product_id,
            project_revision,
            mission_revision,
            work_product_revision,
            scope_revision,
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn validate(&self) -> Result<()> {
        self.organization_id.validate()?;
        self.project_id.validate()?;
        if let Some(batch) = &self.batch_id {
            batch.validate()?;
        }
        if let Some(endpoint) = &self.endpoint {
            Endpoint::new(endpoint.as_str().to_owned())?;
        }
        if let Some(file) = &self.input_file_id {
            file.validate()?;
        }
        self.model.validate()?;
        self.api.validate()?;
        self.permission.validate()?;
        self.hartevo_project_id.validate()?;
        self.mission_id.validate()?;
        self.work_product_id.validate()?;
        for (field, revision) in [
            ("project_revision", self.project_revision),
            ("mission_revision", self.mission_revision),
            ("work_product_revision", self.work_product_revision),
            ("scope_revision", self.scope_revision),
        ] {
            Revision::new(revision.get())
                .map_err(|_| OpenAiBatchResultError::InvalidRevision { field })?;
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }

    #[must_use]
    pub fn revision_digest(&self) -> Digest {
        Digest::from_serializable(&(
            self.project_revision,
            self.mission_revision,
            self.work_product_revision,
            self.scope_revision,
        ))
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OpenAiBatchScope {
    identity: OpenAiBatchScopeIdentity,
    secret_reference: SecretReference,
}

impl fmt::Debug for OpenAiBatchScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenAiBatchScope")
            .field("identity", &self.identity)
            .field("secret_reference", &self.secret_reference)
            .finish()
    }
}

impl OpenAiBatchScope {
    pub fn new(
        identity: OpenAiBatchScopeIdentity,
        secret_reference: SecretReference,
    ) -> Result<Self> {
        identity.validate()?;
        let scope_digest = identity.digest();
        secret_reference.validate_for_scope(&scope_digest)?;
        Ok(Self {
            identity,
            secret_reference,
        })
    }

    pub fn fixture() -> Result<Self> {
        let identity = OpenAiBatchScopeIdentity::new(
            OrganizationId::new("org-fixture")?,
            ProjectId::new("proj-fixture")?,
            Some(BatchId::new("batch-fixture")?),
            Some(Endpoint::new("/v1/responses")?),
            Some(FileId::new("file-input-fixture")?),
            ModelBinding::exact(ModelId::new("gpt-5")?, Revision::new(1)?),
            ApiBinding::official(Revision::new(1)?),
            PermissionBinding::read_only(Revision::new(1)?),
            HartevoProjectId::new("project-fixture")?,
            MissionId::new("mission-fixture")?,
            WorkProductId::new("work-product-fixture")?,
            Revision::new(1)?,
            Revision::new(1)?,
            Revision::new(1)?,
            Revision::new(1)?,
        )?;
        let secret = SecretReference::api_key(
            "fixture-api-key-reference",
            identity.digest(),
            Revision::new(1)?,
        )?;
        Self::new(identity, secret)
    }

    #[must_use]
    pub fn identity(&self) -> &OpenAiBatchScopeIdentity {
        &self.identity
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn scope_digest(&self) -> Digest {
        self.identity.digest()
    }

    #[must_use]
    pub fn revision_digest(&self) -> Digest {
        self.identity.revision_digest()
    }

    pub fn validate(&self) -> Result<()> {
        self.identity.validate()?;
        self.secret_reference
            .validate_for_scope(&self.identity.digest())
    }

    pub fn revoke_secret(&mut self) -> Result<()> {
        self.secret_reference.revoke()
    }

    pub fn restore_secret(&mut self) -> Result<()> {
        self.secret_reference.restore()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    #[must_use]
    pub const fn is_connected(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_native(self) -> bool {
        false
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Recording => "recording",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "BLOCKED_ENV",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeStatus {
    BlockedEnv,
}

impl NativeStatus {
    #[must_use]
    pub const fn is_connected(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_native(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenAiBatchRegistration {
    pub plugin_id: String,
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub service_id: String,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub model_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub registration_revision: Revision,
    pub status: RegistrationStatus,
    pub reversible: bool,
    pub revocable: bool,
    pub registration_digest: Digest,
}

impl OpenAiBatchRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: &OpenAiBatchScope,
        provider_digest: Digest,
        provider_version: impl Into<String>,
        contract_digest: Digest,
    ) -> Result<Self> {
        scope.validate()?;
        provider_digest.validate("provider_digest")?;
        contract_digest.validate("contract_digest")?;
        let mut registration = Self {
            plugin_id: String::from(PLUGIN_ID),
            plugin_version: String::from(PLUGIN_VERSION),
            contract_version: String::from(CONTRACT_VERSION),
            contract_digest,
            service_id: String::from(SERVICE_ID),
            provider_id: String::from(PROVIDER_ID),
            provider_version: provider_version.into(),
            provider_digest,
            api_digest: scope.identity.api.digest(),
            model_digest: scope.identity.model.digest(),
            permission_digest: scope.identity.permission.digest.clone(),
            scope_digest: scope.scope_digest(),
            revision_digest: scope.revision_digest(),
            registration_revision: Revision::new(1)?,
            status: RegistrationStatus::Active,
            reversible: true,
            revocable: true,
            registration_digest: Digest::pending(),
        };
        registration.registration_digest = registration.computed_digest();
        registration.validate()?;
        Ok(registration)
    }

    pub fn validate(&self) -> Result<()> {
        if self.plugin_id != PLUGIN_ID
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.service_id != SERVICE_ID
            || self.provider_id != PROVIDER_ID
            || self.provider_version.is_empty()
            || !self.reversible
            || !self.revocable
        {
            return Err(OpenAiBatchResultError::RegistrationTampered);
        }
        self.contract_digest.validate("contract_digest")?;
        self.provider_digest.validate("provider_digest")?;
        self.api_digest.validate("api_digest")?;
        self.model_digest.validate("model_digest")?;
        self.permission_digest.validate("permission_digest")?;
        self.scope_digest.validate("scope_digest")?;
        self.revision_digest.validate("revision_digest")?;
        Revision::new(self.registration_revision.get())?;
        self.registration_digest.validate("registration_digest")?;
        if self.registration_digest != self.computed_digest() {
            return Err(OpenAiBatchResultError::RegistrationTampered);
        }
        Ok(())
    }

    pub fn validate_for(&self, scope: &OpenAiBatchScope, provider_digest: &Digest) -> Result<()> {
        self.validate()?;
        scope.validate()?;
        if self.contract_digest != crate::contract_digest()
            || self.provider_digest != *provider_digest
            || self.api_digest != scope.identity.api.digest()
            || self.model_digest != scope.identity.model.digest()
            || self.permission_digest != scope.identity.permission.digest
            || self.scope_digest != scope.scope_digest()
            || self.revision_digest != scope.revision_digest()
        {
            return Err(OpenAiBatchResultError::RegistrationTampered);
        }
        Ok(())
    }

    #[must_use]
    pub fn computed_digest(&self) -> Digest {
        let mut value = self.clone();
        value.registration_digest = Digest::pending();
        Digest::from_serializable(&value)
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation> {
        self.validate()?;
        if self.status != RegistrationStatus::Active {
            return Err(OpenAiBatchResultError::RegistrationRevoked);
        }
        let previous_digest = self.registration_digest.clone();
        self.registration_revision =
            Revision::new(self.registration_revision.get().checked_add(1).ok_or(
                OpenAiBatchResultError::InvalidRevision {
                    field: "registration_revision",
                },
            )?)?;
        self.status = RegistrationStatus::Revoked;
        self.registration_digest = self.computed_digest();
        Ok(RegistrationRevocation {
            previous_digest,
            revoked_digest: self.registration_digest.clone(),
            registration_revision: self.registration_revision,
            reversible: true,
        })
    }

    pub fn restore(&mut self) -> Result<()> {
        self.validate()?;
        if self.status != RegistrationStatus::Revoked {
            return Err(OpenAiBatchResultError::InvalidRequest(
                "registration is active",
            ));
        }
        self.registration_revision =
            Revision::new(self.registration_revision.get().checked_add(1).ok_or(
                OpenAiBatchResultError::InvalidRevision {
                    field: "registration_revision",
                },
            )?)?;
        self.status = RegistrationStatus::Active;
        self.registration_digest = self.computed_digest();
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationRevocation {
    pub previous_digest: Digest,
    pub revoked_digest: Digest,
    pub registration_revision: Revision,
    pub reversible: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Validating,
    Failed,
    InProgress,
    Finalizing,
    Completed,
    Expired,
    Cancelling,
    Cancelled,
}

impl BatchStatus {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "validating" => Ok(Self::Validating),
            "failed" => Ok(Self::Failed),
            "in_progress" => Ok(Self::InProgress),
            "finalizing" => Ok(Self::Finalizing),
            "completed" => Ok(Self::Completed),
            "expired" => Ok(Self::Expired),
            "cancelling" => Ok(Self::Cancelling),
            "cancelled" => Ok(Self::Cancelled),
            _ => Err(OpenAiBatchResultError::InvalidResponse("batch status")),
        }
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Failed | Self::Completed | Self::Expired | Self::Cancelled
        )
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BatchTimestamps {
    pub in_progress_at: Option<u64>,
    pub finalizing_at: Option<u64>,
    pub completed_at: Option<u64>,
    pub failed_at: Option<u64>,
    pub expired_at: Option<u64>,
    pub cancelling_at: Option<u64>,
    pub cancelled_at: Option<u64>,
}

impl BatchTimestamps {
    fn validate(&self, created_at: u64) -> Result<()> {
        for timestamp in [
            self.in_progress_at,
            self.finalizing_at,
            self.completed_at,
            self.failed_at,
            self.expired_at,
            self.cancelling_at,
            self.cancelled_at,
        ]
        .into_iter()
        .flatten()
        {
            if timestamp < created_at {
                return Err(OpenAiBatchResultError::InvalidResponse(
                    "batch lifecycle timestamp precedes created_at",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BatchExpiry {
    pub expires_at: Option<u64>,
    pub expired_at: Option<u64>,
}

impl BatchExpiry {
    fn validate(&self, created_at: u64, status: BatchStatus) -> Result<()> {
        if let Some(expires_at) = self.expires_at
            && expires_at < created_at
        {
            return Err(OpenAiBatchResultError::InvalidResponse(
                "expires_at precedes created_at",
            ));
        }
        if let (Some(expires_at), Some(expired_at)) = (self.expires_at, self.expired_at)
            && expired_at < expires_at
        {
            return Err(OpenAiBatchResultError::InvalidResponse(
                "expired_at precedes expires_at",
            ));
        }
        if self.expired_at.is_some() && status != BatchStatus::Expired {
            return Err(OpenAiBatchResultError::InvalidResponse(
                "expired_at requires expired status",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BatchRequestCounts {
    pub total: u64,
    pub completed: u64,
    pub failed: u64,
}

impl BatchRequestCounts {
    pub fn new(total: u64, completed: u64, failed: u64) -> Result<Self> {
        let counts = Self {
            total,
            completed,
            failed,
        };
        counts.validate()?;
        Ok(counts)
    }

    pub fn validate(&self) -> Result<()> {
        if self.completed > self.total
            || self.failed > self.total
            || self.completed.saturating_add(self.failed) > self.total
        {
            Err(OpenAiBatchResultError::InvalidResponse(
                "request counts exceed total",
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FileRole {
    Input,
    Output,
    Error,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileReference {
    pub file_id: FileId,
    pub role: FileRole,
    pub metadata_digest: Digest,
    pub content_digest: Option<Digest>,
}

impl FileReference {
    pub fn new(file_id: FileId, role: FileRole) -> Self {
        let metadata_digest = Digest::from_serializable(&(file_id.clone(), role));
        Self {
            file_id,
            role,
            metadata_digest,
            content_digest: None,
        }
    }

    pub fn with_content_digest(mut self, content_digest: Digest) -> Result<Self> {
        content_digest.validate("file_content_digest")?;
        self.content_digest = Some(content_digest);
        Ok(self)
    }

    pub fn validate(&self) -> Result<()> {
        self.file_id.validate()?;
        self.metadata_digest.validate("file_metadata_digest")?;
        if self.metadata_digest != Digest::from_serializable(&(self.file_id.clone(), self.role)) {
            return Err(OpenAiBatchResultError::EvidenceTampered);
        }
        if let Some(digest) = &self.content_digest {
            digest.validate("file_content_digest")?;
        }
        Ok(())
    }
}

/// Only the digest and bounded key count of provider metadata are retained.
/// Metadata values are never emitted into a Mission projection.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BatchMetadataDigest {
    pub digest: Digest,
    pub key_count: u8,
}

impl BatchMetadataDigest {
    pub(crate) fn from_map(metadata: Option<&BTreeMap<String, String>>) -> Result<Option<Self>> {
        let Some(metadata) = metadata else {
            return Ok(None);
        };
        if metadata.len() > MAX_METADATA_KEYS {
            return Err(OpenAiBatchResultError::InvalidResponse(
                "metadata key count exceeds OpenAI limit",
            ));
        }
        for (key, value) in metadata {
            if key.is_empty()
                || key.len() > MAX_METADATA_KEY_BYTES
                || value.len() > MAX_METADATA_VALUE_BYTES
                || key.chars().any(char::is_control)
                || value.chars().any(char::is_control)
            {
                return Err(OpenAiBatchResultError::InvalidResponse(
                    "metadata key or value exceeds its bound",
                ));
            }
        }
        Ok(Some(Self {
            digest: Digest::from_serializable(metadata),
            key_count: u8::try_from(metadata.len())
                .map_err(|_| OpenAiBatchResultError::InvalidResponse("metadata key count"))?,
        }))
    }

    fn validate(&self) -> Result<()> {
        self.digest.validate("metadata_digest")?;
        if usize::from(self.key_count) > MAX_METADATA_KEYS {
            return Err(OpenAiBatchResultError::InvalidResponse(
                "metadata key count",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BatchMetadata {
    pub organization_id: OrganizationId,
    pub project_id: ProjectId,
    pub batch_id: BatchId,
    pub endpoint: Endpoint,
    pub input_file: FileReference,
    pub output_file: Option<FileReference>,
    pub error_file: Option<FileReference>,
    pub model: Option<ModelId>,
    pub status: BatchStatus,
    pub completion_window: CompletionWindow,
    pub created_at: u64,
    pub timestamps: BatchTimestamps,
    pub request_counts: BatchRequestCounts,
    pub expiry: BatchExpiry,
    pub metadata: Option<BatchMetadataDigest>,
    pub errors_digest: Option<Digest>,
    pub error_count: u32,
    pub batch_digest: Digest,
}

impl BatchMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        organization_id: OrganizationId,
        project_id: ProjectId,
        batch_id: BatchId,
        endpoint: Endpoint,
        input_file: FileReference,
        output_file: Option<FileReference>,
        error_file: Option<FileReference>,
        model: Option<ModelId>,
        status: BatchStatus,
        completion_window: CompletionWindow,
        created_at: u64,
        timestamps: BatchTimestamps,
        request_counts: BatchRequestCounts,
        expiry: BatchExpiry,
        metadata: Option<BatchMetadataDigest>,
        errors_digest: Option<Digest>,
        error_count: u32,
    ) -> Result<Self> {
        let mut batch = Self {
            organization_id,
            project_id,
            batch_id,
            endpoint,
            input_file,
            output_file,
            error_file,
            model,
            status,
            completion_window,
            created_at,
            timestamps,
            request_counts,
            expiry,
            metadata,
            errors_digest,
            error_count,
            batch_digest: Digest::pending(),
        };
        batch.validate_without_digest()?;
        batch.batch_digest = batch.computed_digest();
        Ok(batch)
    }

    pub fn validate_without_digest(&self) -> Result<()> {
        self.organization_id.validate()?;
        self.project_id.validate()?;
        self.batch_id.validate()?;
        Endpoint::new(self.endpoint.as_str().to_owned())?;
        self.input_file.validate()?;
        if self.input_file.role != FileRole::Input {
            return Err(OpenAiBatchResultError::InvalidResponse("input file role"));
        }
        for (file, role) in [
            (self.output_file.as_ref(), FileRole::Output),
            (self.error_file.as_ref(), FileRole::Error),
        ] {
            if let Some(file) = file {
                file.validate()?;
                if file.role != role {
                    return Err(OpenAiBatchResultError::InvalidResponse("file role"));
                }
            }
        }
        if let Some(model) = &self.model {
            model.validate()?;
        }
        CompletionWindow::new(self.completion_window.as_str().to_owned())?;
        self.timestamps.validate(self.created_at)?;
        self.request_counts.validate()?;
        self.expiry.validate(self.created_at, self.status)?;
        if let Some(metadata) = &self.metadata {
            metadata.validate()?;
        }
        if let Some(errors_digest) = &self.errors_digest {
            errors_digest.validate("errors_digest")?;
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_without_digest()?;
        self.batch_digest.validate("batch_digest")?;
        if self.batch_digest != self.computed_digest() {
            return Err(OpenAiBatchResultError::EvidenceTampered);
        }
        Ok(())
    }

    #[must_use]
    pub fn computed_digest(&self) -> Digest {
        let mut value = self.clone();
        value.batch_digest = Digest::pending();
        Digest::from_serializable(&value)
    }

    #[must_use]
    pub fn input_file_id(&self) -> &FileId {
        &self.input_file.file_id
    }

    #[must_use]
    pub fn output_file_id(&self) -> Option<&FileId> {
        self.output_file.as_ref().map(|file| &file.file_id)
    }

    #[must_use]
    pub fn error_file_id(&self) -> Option<&FileId> {
        self.error_file.as_ref().map(|file| &file.file_id)
    }

    pub(crate) fn validate_for_scope(&self, scope: &OpenAiBatchScope) -> Result<()> {
        self.validate()?;
        if scope.identity.project_id != self.project_id
            || scope.identity.organization_id != self.organization_id
        {
            return Err(OpenAiBatchResultError::ScopeMismatch(
                "organization/project",
            ));
        }
        if let Some(expected) = &scope.identity.batch_id
            && expected != &self.batch_id
        {
            return Err(OpenAiBatchResultError::BatchMismatch);
        }
        if let Some(expected) = &scope.identity.endpoint
            && expected != &self.endpoint
        {
            return Err(OpenAiBatchResultError::EndpointMismatch);
        }
        if let Some(expected) = &scope.identity.input_file_id
            && expected != self.input_file_id()
        {
            return Err(OpenAiBatchResultError::InputFileMismatch);
        }
        scope
            .identity
            .model
            .validate_observed(self.model.as_ref())?;
        Ok(())
    }

    pub fn fixture(scope: &OpenAiBatchScope) -> Result<Self> {
        Self::new(
            scope.identity.organization_id.clone(),
            scope.identity.project_id.clone(),
            scope
                .identity
                .batch_id
                .clone()
                .unwrap_or(BatchId::new("batch-fixture")?),
            scope
                .identity
                .endpoint
                .clone()
                .unwrap_or(Endpoint::new("/v1/responses")?),
            FileReference::new(
                scope
                    .identity
                    .input_file_id
                    .clone()
                    .unwrap_or(FileId::new("file-input-fixture")?),
                FileRole::Input,
            ),
            Some(FileReference::new(
                FileId::new("file-output-fixture")?,
                FileRole::Output,
            )),
            Some(FileReference::new(
                FileId::new("file-error-fixture")?,
                FileRole::Error,
            )),
            scope.identity.model.model_id.clone(),
            BatchStatus::Completed,
            CompletionWindow::new("24h")?,
            1_700_000_000,
            BatchTimestamps {
                completed_at: Some(1_700_000_100),
                ..BatchTimestamps::default()
            },
            BatchRequestCounts::new(10, 9, 1)?,
            BatchExpiry {
                expires_at: Some(1_700_086_400),
                expired_at: None,
            },
            None,
            None,
            0,
        )
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct BatchCursor {
    token: String,
    scope_digest: Digest,
    previous_response_digest: Digest,
}

impl BatchCursor {
    pub fn new(
        token: impl Into<String>,
        scope_digest: Digest,
        previous_response_digest: Digest,
    ) -> Result<Self> {
        let token = token.into();
        if token.is_empty()
            || token.len() > MAX_IDENTIFIER_BYTES
            || token.chars().any(char::is_control)
            || token.chars().any(char::is_whitespace)
            || token
                .bytes()
                .any(|byte| matches!(byte, b'?' | b'#' | b'&' | b'=' | b'%'))
        {
            return Err(OpenAiBatchResultError::InvalidRequest("cursor"));
        }
        scope_digest.validate("cursor_scope_digest")?;
        previous_response_digest.validate("cursor_response_digest")?;
        Ok(Self {
            token,
            scope_digest,
            previous_response_digest,
        })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.token
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serializable(&(
            &self.token,
            &self.scope_digest,
            &self.previous_response_digest,
        ))
    }
}

impl fmt::Debug for BatchCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BatchCursor")
            .field("cursor_digest", &self.digest())
            .field("scope_digest", &self.scope_digest)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchListRequest {
    pub limit: u32,
    pub cursor: Option<BatchCursor>,
    pub minimum_observed_at: u64,
}

impl BatchListRequest {
    pub fn new(limit: u32, cursor: Option<BatchCursor>, minimum_observed_at: u64) -> Result<Self> {
        if !(1..=MAX_PAGE_LIMIT).contains(&limit) {
            return Err(OpenAiBatchResultError::InvalidRequest("limit"));
        }
        Ok(Self {
            limit,
            cursor,
            minimum_observed_at,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchGetRequest {
    pub batch_id: BatchId,
    pub minimum_observed_at: u64,
}

impl BatchGetRequest {
    pub fn new(batch_id: BatchId, minimum_observed_at: u64) -> Result<Self> {
        batch_id.validate()?;
        Ok(Self {
            batch_id,
            minimum_observed_at,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenAiBatchReadTarget {
    pub batch_id: Option<BatchId>,
    pub limit: Option<u32>,
    pub cursor_digest: Option<Digest>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceDisposition {
    Empty,
    Present,
    Partial,
    AccessLost,
    ProviderUnknown,
    BlockedEnv,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderErrorProjection {
    pub class: String,
    pub status: Option<u16>,
    pub retryable: bool,
    pub response_digest: Option<Digest>,
}

impl ProviderErrorProjection {
    pub(crate) fn from_error(
        error: &crate::error::OpenAiBatchProviderError,
        response_digest: Option<Digest>,
    ) -> Self {
        Self {
            class: match error {
                crate::error::OpenAiBatchProviderError::BlockedEnv => "blocked_env",
                crate::error::OpenAiBatchProviderError::Unauthorized => "unauthorized",
                crate::error::OpenAiBatchProviderError::Forbidden => "forbidden",
                crate::error::OpenAiBatchProviderError::NotFound => "not_found",
                crate::error::OpenAiBatchProviderError::Conflict => "conflict",
                crate::error::OpenAiBatchProviderError::RateLimited { .. } => "rate_limited",
                crate::error::OpenAiBatchProviderError::Timeout => "timeout",
                crate::error::OpenAiBatchProviderError::ServerError { .. } => "server_error",
                crate::error::OpenAiBatchProviderError::TransportUnavailable => {
                    "transport_unavailable"
                }
                crate::error::OpenAiBatchProviderError::AccessLoss => "access_loss",
                crate::error::OpenAiBatchProviderError::MalformedResponse(_) => {
                    "malformed_response"
                }
                crate::error::OpenAiBatchProviderError::PartialResponse => "partial_response",
                crate::error::OpenAiBatchProviderError::ResponseTooLarge => "response_too_large",
                crate::error::OpenAiBatchProviderError::ResponseTampered => "response_tampered",
                crate::error::OpenAiBatchProviderError::UnexpectedStatus { .. } => {
                    "unexpected_status"
                }
            }
            .to_owned(),
            status: error.status_code(),
            retryable: error.is_retryable(),
            response_digest,
        }
    }
}

/// Redacted evidence for a bounded list or single-batch read.  It includes
/// IDs, lifecycle metadata, request counts, expiry, and file digests only.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenAiBatchEvidence {
    pub target: OpenAiBatchReadTarget,
    pub batches: Vec<BatchMetadata>,
    pub next_cursor_digest: Option<Digest>,
    pub response_digest: Option<Digest>,
    pub page_count: u32,
    pub disposition: EvidenceDisposition,
    pub provider_error: Option<ProviderErrorProjection>,
    pub provenance: ProviderProvenance,
    pub observed_at: u64,
    pub snapshot_revision: Revision,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub model_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub external_writes: bool,
    pub durable_native_receipt: bool,
    pub work_product_adopted: bool,
    pub evidence_digest: Digest,
}

impl OpenAiBatchEvidence {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        target: OpenAiBatchReadTarget,
        batches: Vec<BatchMetadata>,
        next_cursor_digest: Option<Digest>,
        response_digest: Option<Digest>,
        page_count: u32,
        disposition: EvidenceDisposition,
        provider_error: Option<ProviderErrorProjection>,
        provenance: ProviderProvenance,
        observed_at: u64,
        snapshot_revision: Revision,
        registration_digest: Digest,
        provider_digest: Digest,
        api_digest: Digest,
        model_digest: Digest,
        permission_digest: Digest,
        scope_digest: Digest,
        revision_digest: Digest,
    ) -> Result<Self> {
        let mut evidence = Self {
            target,
            batches,
            next_cursor_digest,
            response_digest,
            page_count,
            disposition,
            provider_error,
            provenance,
            observed_at,
            snapshot_revision,
            registration_digest,
            provider_digest,
            api_digest,
            model_digest,
            permission_digest,
            scope_digest,
            revision_digest,
            proposal_only: true,
            connected: false,
            native: false,
            external_writes: false,
            durable_native_receipt: false,
            work_product_adopted: false,
            evidence_digest: Digest::pending(),
        };
        evidence.validate_without_digest()?;
        evidence.evidence_digest = evidence.computed_digest();
        Ok(evidence)
    }

    fn validate_without_digest(&self) -> Result<()> {
        if self.page_count == 0
            || !self.proposal_only
            || self.connected
            || self.native
            || self.external_writes
            || self.durable_native_receipt
            || self.work_product_adopted
        {
            return Err(OpenAiBatchResultError::EvidenceTampered);
        }
        Revision::new(self.snapshot_revision.get()).map_err(|_| {
            OpenAiBatchResultError::InvalidRevision {
                field: "snapshot_revision",
            }
        })?;
        for (field, digest) in [
            ("registration_digest", &self.registration_digest),
            ("provider_digest", &self.provider_digest),
            ("api_digest", &self.api_digest),
            ("model_digest", &self.model_digest),
            ("permission_digest", &self.permission_digest),
            ("scope_digest", &self.scope_digest),
            ("revision_digest", &self.revision_digest),
        ] {
            digest.validate(field)?;
        }
        if let Some(cursor) = &self.next_cursor_digest {
            cursor.validate("next_cursor_digest")?;
        }
        if let Some(response) = &self.response_digest {
            response.validate("response_digest")?;
        }
        for batch in &self.batches {
            batch.validate()?;
        }
        if self.disposition == EvidenceDisposition::Present && self.batches.is_empty() {
            return Err(OpenAiBatchResultError::EvidenceTampered);
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_without_digest()?;
        self.evidence_digest.validate("evidence_digest")?;
        if self.evidence_digest != self.computed_digest() {
            return Err(OpenAiBatchResultError::EvidenceTampered);
        }
        Ok(())
    }

    #[must_use]
    pub fn computed_digest(&self) -> Digest {
        let mut value = self.clone();
        value.evidence_digest = Digest::pending();
        Digest::from_serializable(&value)
    }

    #[must_use]
    pub const fn is_current(&self) -> bool {
        matches!(
            self.disposition,
            EvidenceDisposition::Present | EvidenceDisposition::Empty
        )
    }

    #[must_use]
    pub const fn is_adoptable(&self) -> bool {
        false
    }
}

use std::{collections::BTreeMap, fmt, str::FromStr};

use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::canonical::{
    canonical_digest, digest_parts, valid_digest, valid_identifier, valid_text,
};

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_FIELD_BYTES: usize = 128;
pub const MAX_FIELD_VALUE_BYTES: usize = 8_192;
pub const MAX_CURSOR_BYTES: usize = 256;
pub const MAX_FIELDS: usize = 128;
pub const MAX_RECORDS: usize = 512;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("invalid {field}: {reason}")]
    Invalid { field: String, reason: String },
    #[error("invalid digest")]
    InvalidDigest,
    #[error("the SecretReference is opaque and cannot contain raw credential material")]
    SecretMaterial,
    #[error("the permission scope is not the exact read-only employee_directory permission")]
    InvalidPermission,
    #[error("the directory response contains a duplicate field or employee")]
    DuplicateRecord,
    #[error("the response or snapshot digest is invalid")]
    InvalidResponse,
    #[error("the scope is invalid or its binding digest drifted")]
    InvalidScope,
    #[error("the SecretReference is already revoked")]
    AlreadyRevoked,
    #[error("the SecretReference is not revoked")]
    NotRevoked,
}

fn invalid(field: &str, reason: impl Into<String>) -> ModelError {
    ModelError::Invalid {
        field: field.to_owned(),
        reason: reason.into(),
    }
}

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Self(hex_bytes(&hasher.finalize()))
    }

    #[must_use]
    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    #[must_use]
    pub fn from_fields(domain: &str, fields: &[String]) -> Self {
        digest_parts(domain, fields)
    }

    #[must_use]
    pub fn from_serializable<T: Serialize>(value: &T) -> Self {
        canonical_digest("bamboohr-canonical/v1", value)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if valid_digest(&value) {
            Ok(Self(value.to_ascii_lowercase()))
        } else {
            Err(ModelError::InvalidDigest)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn is_valid(&self) -> bool {
        valid_digest(&self.0)
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        if value == 0 {
            Err(invalid("revision", "must be positive"))
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

impl From<Revision> for u64 {
    fn from(value: Revision) -> Self {
        value.0
    }
}

macro_rules! scoped_binding {
    ($name:ident, $field:literal, $domain:literal) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                if !valid_identifier(&value, MAX_IDENTIFIER_BYTES) {
                    return Err(invalid($field, "must be a bounded opaque identifier"));
                }
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            #[must_use]
            pub fn digest(&self) -> Digest {
                Digest::from_fields($domain, std::slice::from_ref(&self.0))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.digest())
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = ModelError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }
    };
}

scoped_binding!(ProjectId, "project id", "bamboohr-project-id/v1");
scoped_binding!(MissionId, "mission id", "bamboohr-mission-id/v1");
scoped_binding!(
    WorkProductId,
    "work product id",
    "bamboohr-work-product-id/v1"
);
scoped_binding!(ConsentId, "consent id", "bamboohr-consent-id/v1");

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CompanyDomain(String);

impl CompanyDomain {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if !valid_identifier(&value, MAX_IDENTIFIER_BYTES)
            || value.starts_with('.')
            || value.ends_with('.')
            || value.contains("..")
        {
            return Err(invalid(
                "company domain",
                "must be a bounded BambooHR company subdomain without URL or credential syntax",
            ));
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_fields("bamboohr-company-domain/v1", std::slice::from_ref(&self.0))
    }
}

impl fmt::Debug for CompanyDomain {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("CompanyDomain")
            .field(&self.digest())
            .finish()
    }
}

impl fmt::Display for CompanyDomain {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for CompanyDomain {
    type Err = ModelError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

// The company subdomain is useful to the provider but is never emitted as
// raw evidence. Serialisation intentionally exposes only its binding digest.
impl Serialize for CompanyDomain {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.digest().as_str())
    }
}

pub type BambooHrCompanyDomain = CompanyDomain;
pub type BambooHrProjectId = ProjectId;
pub type BambooHrMissionId = MissionId;
pub type BambooHrWorkProductId = WorkProductId;
pub type BambooHrConsentId = ConsentId;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Project {
    pub id: ProjectId,
    pub revision: Revision,
}

impl Project {
    pub fn new(id: impl Into<String>, revision: Revision) -> Result<Self, ModelError> {
        Ok(Self {
            id: ProjectId::new(id)?,
            revision,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Mission {
    pub id: MissionId,
    pub revision: Revision,
}

impl Mission {
    pub fn new(id: impl Into<String>, revision: Revision) -> Result<Self, ModelError> {
        Ok(Self {
            id: MissionId::new(id)?,
            revision,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProduct {
    pub id: WorkProductId,
    pub revision: Revision,
}

impl WorkProduct {
    pub fn new(id: impl Into<String>, revision: Revision) -> Result<Self, ModelError> {
        Ok(Self {
            id: WorkProductId::new(id)?,
            revision,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Consent {
    pub id: ConsentId,
    pub revision: Revision,
    pub read_only: bool,
}

impl Consent {
    pub fn new(id: impl Into<String>, revision: Revision) -> Result<Self, ModelError> {
        Ok(Self {
            id: ConsentId::new(id)?,
            revision,
            read_only: true,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionAction {
    EmployeeDirectory,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionScope {
    pub actions: std::collections::BTreeSet<PermissionAction>,
    pub digest: Digest,
}

impl PermissionScope {
    pub fn new(actions: std::collections::BTreeSet<PermissionAction>) -> Result<Self, ModelError> {
        if actions.len() != 1 || !actions.contains(&PermissionAction::EmployeeDirectory) {
            return Err(ModelError::InvalidPermission);
        }
        let digest = Digest::from_serializable(&actions);
        Ok(Self { actions, digest })
    }

    #[must_use]
    pub fn read_only() -> Self {
        Self::new(std::collections::BTreeSet::from([
            PermissionAction::EmployeeDirectory,
        ]))
        .expect("the built-in BambooHR read scope is valid")
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    #[must_use]
    pub fn allows(&self, action: PermissionAction) -> bool {
        self.actions.contains(&action)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let expected = Self::new(self.actions.clone())?;
        if expected.digest != self.digest {
            Err(ModelError::InvalidPermission)
        } else {
            Ok(())
        }
    }
}

pub type BambooHrPermissionScope = PermissionScope;

/// The only employee metadata that a Layer-1 list read may request and
/// retain. Contact, address, compensation, demographic, photo, and custom
/// sensitive fields are intentionally absent from this vocabulary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BambooHrEmployeeField {
    DisplayName,
    FirstName,
    LastName,
    PreferredName,
    Pronouns,
    JobTitle,
    Department,
    Division,
    Location,
    Supervisor,
    Status,
}

impl BambooHrEmployeeField {
    #[must_use]
    pub const fn api_name(self) -> &'static str {
        match self {
            Self::DisplayName => "displayName",
            Self::FirstName => "firstName",
            Self::LastName => "lastName",
            Self::PreferredName => "preferredName",
            Self::Pronouns => "pronouns",
            Self::JobTitle => "jobTitleName",
            Self::Department => "department",
            Self::Division => "division",
            Self::Location => "location",
            Self::Supervisor => "supervisor",
            Self::Status => "status",
        }
    }

    #[must_use]
    pub const fn is_relationship(self) -> bool {
        matches!(self, Self::Supervisor)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BambooHrEmployeeFieldSelection {
    pub fields: std::collections::BTreeSet<BambooHrEmployeeField>,
    pub digest: Digest,
}

impl BambooHrEmployeeFieldSelection {
    pub fn new(
        fields: std::collections::BTreeSet<BambooHrEmployeeField>,
    ) -> Result<Self, ModelError> {
        if fields.is_empty() || fields.len() > 6 {
            return Err(invalid(
                "employee field selection",
                "must contain one to six allowlisted fields",
            ));
        }
        if fields.iter().any(|field| {
            matches!(
                field,
                BambooHrEmployeeField::DisplayName
                    | BambooHrEmployeeField::FirstName
                    | BambooHrEmployeeField::LastName
                    | BambooHrEmployeeField::PreferredName
                    | BambooHrEmployeeField::Pronouns
            )
        }) {
            return Err(invalid(
                "employee field selection",
                "names and demographic fields are not permitted in Layer 1",
            ));
        }
        let digest = Digest::from_serializable(&fields);
        Ok(Self { fields, digest })
    }

    #[must_use]
    pub fn safe_metadata() -> Self {
        Self::new(std::collections::BTreeSet::from([
            BambooHrEmployeeField::Department,
            BambooHrEmployeeField::Division,
            BambooHrEmployeeField::JobTitle,
            BambooHrEmployeeField::Location,
            BambooHrEmployeeField::Status,
            BambooHrEmployeeField::Supervisor,
        ]))
        .expect("the built-in BambooHR employee field selection is valid")
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let expected = Self::new(self.fields.clone())?;
        if expected.digest != self.digest {
            Err(ModelError::InvalidScope)
        } else {
            Ok(())
        }
    }
}

pub type BambooHrFieldSelection = BambooHrEmployeeFieldSelection;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BambooHrDirectoryFieldset {
    pub fields: std::collections::BTreeSet<BambooHrEmployeeField>,
    pub digest: Digest,
    pub limited: bool,
}

impl BambooHrDirectoryFieldset {
    pub fn new(
        fields: std::collections::BTreeSet<BambooHrEmployeeField>,
        limited: bool,
    ) -> Result<Self, ModelError> {
        let selection = BambooHrEmployeeFieldSelection::new(fields.clone())?;
        Ok(Self {
            fields,
            digest: Digest::from_fields(
                "bamboohr-directory-fieldset/v1",
                &[selection.digest.as_str().to_owned(), limited.to_string()],
            ),
            limited,
        })
    }

    #[must_use]
    pub fn published() -> Self {
        Self::new(
            BambooHrEmployeeFieldSelection::safe_metadata().fields,
            false,
        )
        .expect("the built-in BambooHR directory fieldset is valid")
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let expected = Self::new(self.fields.clone(), self.limited)?;
        if expected.digest != self.digest {
            Err(ModelError::InvalidScope)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EmployeeStatus {
    Active,
    Inactive,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PageDirection {
    Before,
    After,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretReferenceKind {
    Basic,
    OAuth,
}

/// Opaque host-keyring reference. The supplied handle is hashed at the
/// boundary and is never retained, serialised, or included in Debug output.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretReferenceKind,
    reference_digest: Digest,
    scope_digest: Digest,
    revision: Revision,
    revoked: bool,
}

impl SecretReference {
    pub fn new(
        opaque_reference: impl AsRef<str>,
        scope: &BambooHrDirectoryScope,
        revision: u64,
    ) -> Result<Self, ModelError> {
        Self::for_scope(
            SecretReferenceKind::OAuth,
            opaque_reference,
            scope,
            Revision::new(revision)?,
        )
    }

    pub fn basic(
        opaque_reference: impl AsRef<str>,
        scope: &BambooHrDirectoryScope,
        revision: u64,
    ) -> Result<Self, ModelError> {
        Self::for_scope(
            SecretReferenceKind::Basic,
            opaque_reference,
            scope,
            Revision::new(revision)?,
        )
    }

    pub fn oauth(
        opaque_reference: impl AsRef<str>,
        scope: &BambooHrDirectoryScope,
        revision: u64,
    ) -> Result<Self, ModelError> {
        Self::new(opaque_reference, scope, revision)
    }

    pub fn for_scope(
        kind: SecretReferenceKind,
        opaque_reference: impl AsRef<str>,
        scope: &BambooHrDirectoryScope,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        let opaque_reference = opaque_reference.as_ref();
        if !valid_identifier(opaque_reference, MAX_IDENTIFIER_BYTES)
            || opaque_reference.to_ascii_lowercase().contains("password")
            || opaque_reference.to_ascii_lowercase().contains("bearer")
        {
            return Err(ModelError::SecretMaterial);
        }
        let scope_digest = scope.scope_digest().clone();
        let reference_digest = Digest::from_fields(
            "bamboohr-secret-reference/v1",
            &[
                format!("{kind:?}"),
                opaque_reference.to_owned(),
                scope_digest.as_str().to_owned(),
                revision.value().to_string(),
            ],
        );
        Ok(Self {
            kind,
            reference_digest,
            scope_digest,
            revision,
            revoked: false,
        })
    }

    pub fn unbound(
        kind: SecretReferenceKind,
        opaque_reference: impl AsRef<str>,
        revision: u64,
    ) -> Result<Self, ModelError> {
        let revision = Revision::new(revision)?;
        let opaque_reference = opaque_reference.as_ref();
        if !valid_identifier(opaque_reference, MAX_IDENTIFIER_BYTES) {
            return Err(ModelError::SecretMaterial);
        }
        let scope_digest = Digest::from_text("unbound-bamboohr-secret");
        let reference_digest = Digest::from_fields(
            "bamboohr-secret-reference/v1",
            &[
                format!("{kind:?}"),
                opaque_reference.to_owned(),
                scope_digest.as_str().to_owned(),
                revision.value().to_string(),
            ],
        );
        Ok(Self {
            kind,
            reference_digest,
            scope_digest,
            revision,
            revoked: false,
        })
    }

    #[must_use]
    pub const fn kind(&self) -> &SecretReferenceKind {
        &self.kind
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

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            Err(ModelError::AlreadyRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }

    pub fn restore(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            self.revoked = false;
            Ok(())
        } else {
            Err(ModelError::NotRevoked)
        }
    }

    pub fn validate_against(&self, scope: &BambooHrDirectoryScope) -> Result<(), ModelError> {
        if self.scope_digest != *scope.scope_digest() || !self.reference_digest.is_valid() {
            Err(ModelError::InvalidScope)
        } else {
            Ok(())
        }
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

pub type BambooHrSecretReference = SecretReference;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ProviderRevision(String);

impl ProviderRevision {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if valid_identifier(&value, MAX_IDENTIFIER_BYTES) {
            Ok(Self(value))
        } else {
            Err(invalid(
                "provider revision",
                "must be a bounded opaque API revision",
            ))
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "bamboohr-provider-revision/v1",
            std::slice::from_ref(&self.0),
        )
    }
}

impl fmt::Display for ProviderRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BambooHrDirectoryScope {
    pub company_domain: CompanyDomain,
    pub only_current: bool,
    pub project: Project,
    pub mission: Mission,
    pub work_product: WorkProduct,
    pub consent: Consent,
    pub permission: PermissionScope,
    pub fieldset: BambooHrDirectoryFieldset,
    pub employee_fields: BambooHrEmployeeFieldSelection,
    scope_digest: Digest,
}

impl BambooHrDirectoryScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        company_domain: CompanyDomain,
        only_current: bool,
        project: Project,
        mission: Mission,
        consent: Consent,
        permission: PermissionScope,
    ) -> Result<Self, ModelError> {
        permission.validate()?;
        if !consent.read_only {
            return Err(invalid("consent", "must be read-only"));
        }
        let mut scope = Self {
            company_domain,
            only_current,
            project,
            mission,
            work_product: WorkProduct::new("work-product-unbound", Revision::new(1)?)?,
            consent,
            permission,
            fieldset: BambooHrDirectoryFieldset::published(),
            employee_fields: BambooHrEmployeeFieldSelection::safe_metadata(),
            scope_digest: Digest::from_text("unsealed-bamboohr-scope"),
        };
        scope.scope_digest = scope.compute_digest();
        Ok(scope)
    }

    pub fn new_with_work_product(
        company_domain: CompanyDomain,
        only_current: bool,
        project: Project,
        mission: Mission,
        work_product: WorkProduct,
        consent: Consent,
        permission: PermissionScope,
    ) -> Result<Self, ModelError> {
        let mut scope = Self::new(
            company_domain,
            only_current,
            project,
            mission,
            consent,
            permission,
        )?;
        scope.work_product = work_product;
        scope.scope_digest = scope.compute_digest();
        Ok(scope)
    }

    pub fn read_only(
        company_domain: CompanyDomain,
        only_current: bool,
        project: Project,
        mission: Mission,
        consent: Consent,
    ) -> Result<Self, ModelError> {
        Self::new(
            company_domain,
            only_current,
            project,
            mission,
            consent,
            PermissionScope::read_only(),
        )
    }

    pub fn read_only_with_work_product(
        company_domain: CompanyDomain,
        only_current: bool,
        project: Project,
        mission: Mission,
        work_product: WorkProduct,
        consent: Consent,
    ) -> Result<Self, ModelError> {
        Self::new_with_work_product(
            company_domain,
            only_current,
            project,
            mission,
            work_product,
            consent,
            PermissionScope::read_only(),
        )
    }

    pub fn with_work_product(mut self, work_product: WorkProduct) -> Result<Self, ModelError> {
        self.work_product = work_product;
        self.scope_digest = self.compute_digest();
        self.validate()?;
        Ok(self)
    }

    pub fn with_fieldset(
        mut self,
        fieldset: BambooHrDirectoryFieldset,
    ) -> Result<Self, ModelError> {
        fieldset.validate()?;
        self.fieldset = fieldset;
        self.scope_digest = self.compute_digest();
        self.validate()?;
        Ok(self)
    }

    pub fn with_employee_fields(
        mut self,
        employee_fields: BambooHrEmployeeFieldSelection,
    ) -> Result<Self, ModelError> {
        employee_fields.validate()?;
        self.employee_fields = employee_fields;
        self.scope_digest = self.compute_digest();
        self.validate()?;
        Ok(self)
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "bamboohr-directory-scope/v1",
            &[
                self.company_domain.digest().as_str().to_owned(),
                self.only_current.to_string(),
                self.project.digest().as_str().to_owned(),
                self.mission.digest().as_str().to_owned(),
                self.work_product.digest().as_str().to_owned(),
                self.consent.digest().as_str().to_owned(),
                self.permission.digest().as_str().to_owned(),
                self.fieldset.digest().as_str().to_owned(),
                self.employee_fields.digest().as_str().to_owned(),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.permission.validate()?;
        self.fieldset.validate()?;
        self.employee_fields.validate()?;
        if !self.consent.read_only || self.scope_digest != self.compute_digest() {
            return Err(ModelError::InvalidScope);
        }
        Ok(())
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.scope_digest.clone()
    }

    #[must_use]
    pub fn permission_digest(&self) -> &Digest {
        self.permission.digest()
    }

    #[must_use]
    pub fn company_domain_digest(&self) -> Digest {
        self.company_domain.digest()
    }

    #[must_use]
    pub fn fieldset_digest(&self) -> &Digest {
        self.fieldset.digest()
    }

    #[must_use]
    pub fn employee_scope_digest(&self) -> &Digest {
        self.employee_fields.digest()
    }

    #[must_use]
    pub fn matches_mission_context(
        &self,
        project: &Project,
        mission: &Mission,
        consent: &Consent,
    ) -> bool {
        self.project == *project && self.mission == *mission && self.consent == *consent
    }

    #[must_use]
    pub fn matches_mission_context_with_work_product(
        &self,
        project: &Project,
        mission: &Mission,
        work_product: &WorkProduct,
        consent: &Consent,
    ) -> bool {
        self.matches_mission_context(project, mission, consent)
            && self.work_product == *work_product
    }
}

impl Serialize for BambooHrDirectoryScope {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("BambooHrDirectoryScope", 11)?;
        state.serialize_field("companyDomainDigest", &self.company_domain.digest())?;
        state.serialize_field("onlyCurrent", &self.only_current)?;
        state.serialize_field("project", &self.project)?;
        state.serialize_field("mission", &self.mission)?;
        state.serialize_field("workProduct", &self.work_product)?;
        state.serialize_field("consent", &self.consent)?;
        state.serialize_field("permission", &self.permission)?;
        state.serialize_field("fieldsetDigest", self.fieldset.digest())?;
        state.serialize_field("employeeScopeDigest", self.employee_fields.digest())?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.end()
    }
}

pub type BambooHrScope = BambooHrDirectoryScope;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectoryFieldProjection {
    pub id_digest: Digest,
    pub type_digest: Digest,
    pub name_digest: Digest,
}

impl DirectoryFieldProjection {
    pub fn from_provider_fields(
        id: impl AsRef<str>,
        field_type: impl AsRef<str>,
        name: impl AsRef<str>,
    ) -> Result<Self, ModelError> {
        for (field, value) in [
            ("field id", id.as_ref()),
            ("field type", field_type.as_ref()),
            ("field name", name.as_ref()),
        ] {
            if !valid_text(value, MAX_FIELD_BYTES, true) {
                return Err(invalid(field, "must be bounded and non-empty"));
            }
        }
        Ok(Self {
            id_digest: Digest::from_text(id.as_ref()),
            type_digest: Digest::from_text(field_type.as_ref()),
            name_digest: Digest::from_text(name.as_ref()),
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectoryEmployeeProjection {
    pub employee_id_digest: Digest,
    pub field_digests: BTreeMap<Digest, Digest>,
    pub role_digest: Option<Digest>,
    pub department_digest: Option<Digest>,
    pub division_digest: Option<Digest>,
    pub location_digest: Option<Digest>,
    pub supervisor_digest: Option<Digest>,
    pub status: EmployeeStatus,
    pub employee_revision_digest: Digest,
    pub field_count: u16,
    pub redacted_field_count: u16,
    pub record_digest: Digest,
}

impl DirectoryEmployeeProjection {
    pub fn from_provider_fields<I>(
        employee_id: impl AsRef<str>,
        fields: I,
    ) -> Result<Self, ModelError>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        Self::from_provider_metadata(
            employee_id,
            fields,
            EmployeeStatus::Unknown,
            ProviderRevision::new("unbound-employee-revision")?,
        )
    }

    pub fn from_provider_metadata<I>(
        employee_id: impl AsRef<str>,
        fields: I,
        status: EmployeeStatus,
        employee_revision: ProviderRevision,
    ) -> Result<Self, ModelError>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        if !valid_identifier(employee_id.as_ref(), MAX_IDENTIFIER_BYTES) {
            return Err(invalid(
                "employee id",
                "must be a bounded opaque provider employee identifier",
            ));
        }
        let mut field_digests = BTreeMap::new();
        let mut redacted_field_count = 0_u16;
        let mut normalized_status = status;
        for (field_id, value) in fields {
            if !valid_text(&field_id, MAX_FIELD_BYTES, true)
                || value.len() > MAX_FIELD_VALUE_BYTES
                || value.chars().any(char::is_control)
            {
                return Err(invalid(
                    "employee field",
                    "field id and value must be bounded and control-free",
                ));
            }
            let normalized = normalized_field_name(&field_id);
            if normalized == "status" {
                normalized_status = match value.to_ascii_lowercase().as_str() {
                    "active" => EmployeeStatus::Active,
                    "inactive" | "terminated" | "deactivated" => EmployeeStatus::Inactive,
                    _ => EmployeeStatus::Unknown,
                };
                continue;
            }
            if !is_retained_metadata_field(&normalized) {
                redacted_field_count = redacted_field_count.saturating_add(1);
                continue;
            }
            if field_digests
                .insert(Digest::from_text(&field_id), Digest::from_text(&value))
                .is_some()
            {
                return Err(ModelError::DuplicateRecord);
            }
            if field_digests.len() > MAX_FIELDS {
                return Err(invalid("employee fields", "exceed the Layer-1 bound"));
            }
        }
        let employee_id_digest = Digest::from_text(employee_id.as_ref());
        let role_digest = first_field_digest(&field_digests, &["jobTitleName", "jobTitle"]);
        let department_digest = first_field_digest(&field_digests, &["department"]);
        let division_digest = first_field_digest(&field_digests, &["division"]);
        let location_digest = first_field_digest(&field_digests, &["location"]);
        let supervisor_digest = first_field_digest(&field_digests, &["supervisor"]);
        let field_count = u16::try_from(field_digests.len()).map_err(|_| {
            invalid(
                "employee field count",
                "does not fit the bounded projection",
            )
        })?;
        let employee_revision_digest = employee_revision.digest();
        let record_digest = Digest::from_serializable(&(
            &employee_id_digest,
            &field_digests,
            &role_digest,
            &department_digest,
            &division_digest,
            &location_digest,
            &supervisor_digest,
            normalized_status,
            &employee_revision_digest,
            redacted_field_count,
        ));
        Ok(Self {
            employee_id_digest,
            field_digests,
            role_digest,
            department_digest,
            division_digest,
            location_digest,
            supervisor_digest,
            status: normalized_status,
            employee_revision_digest,
            field_count,
            redacted_field_count,
            record_digest,
        })
    }

    pub fn from_provider_values(
        employee_id: impl AsRef<str>,
        fields: BTreeMap<String, Option<String>>,
    ) -> Result<Self, ModelError> {
        Self::from_provider_fields(
            employee_id,
            fields
                .into_iter()
                .map(|(key, value)| (key, value.unwrap_or_default()))
                .collect::<Vec<_>>(),
        )
    }

    #[must_use]
    pub fn verify_integrity(&self) -> bool {
        self.field_count == self.field_digests.len() as u16
            && self.record_digest
                == Digest::from_serializable(&(
                    &self.employee_id_digest,
                    &self.field_digests,
                    &self.role_digest,
                    &self.department_digest,
                    &self.division_digest,
                    &self.location_digest,
                    &self.supervisor_digest,
                    self.status,
                    &self.employee_revision_digest,
                    self.redacted_field_count,
                ))
            && self.employee_id_digest.is_valid()
            && self.employee_revision_digest.is_valid()
            && self
                .field_digests
                .iter()
                .all(|(key, value)| key.is_valid() && value.is_valid())
    }
}

fn normalized_field_name(value: &str) -> String {
    value
        .bytes()
        .filter(u8::is_ascii_alphanumeric)
        .map(|byte| byte.to_ascii_lowercase() as char)
        .collect()
}

fn is_retained_metadata_field(value: &str) -> bool {
    matches!(
        value,
        "jobtitle" | "jobtitlename" | "department" | "division" | "location" | "supervisor"
    )
}

fn first_field_digest(field_digests: &BTreeMap<Digest, Digest>, names: &[&str]) -> Option<Digest> {
    names.iter().find_map(|name| {
        field_digests
            .get(&Digest::from_text(name))
            .cloned()
            .or_else(|| {
                field_digests
                    .iter()
                    .find(|(field_digest, _)| *field_digest == &Digest::from_text(name))
                    .map(|(_, value_digest)| value_digest.clone())
            })
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BambooHrDirectorySnapshot {
    pub fields: Vec<DirectoryFieldProjection>,
    pub employees: Vec<DirectoryEmployeeProjection>,
    pub fields_digest: Digest,
    pub employees_digest: Digest,
    pub snapshot_digest: Digest,
}

impl BambooHrDirectorySnapshot {
    pub fn new(
        mut fields: Vec<DirectoryFieldProjection>,
        mut employees: Vec<DirectoryEmployeeProjection>,
    ) -> Result<Self, ModelError> {
        if fields.len() > MAX_FIELDS || employees.len() > MAX_RECORDS {
            return Err(invalid("directory snapshot", "exceeds the Layer-1 bounds"));
        }
        fields.sort_by(|left, right| left.id_digest.cmp(&right.id_digest));
        employees.sort_by(|left, right| left.employee_id_digest.cmp(&right.employee_id_digest));
        if fields
            .windows(2)
            .any(|pair| pair[0].id_digest == pair[1].id_digest)
            || employees
                .windows(2)
                .any(|pair| pair[0].employee_id_digest == pair[1].employee_id_digest)
            || employees
                .iter()
                .any(|employee| !employee.verify_integrity())
        {
            return Err(ModelError::DuplicateRecord);
        }
        let fields_digest = Digest::from_serializable(&fields);
        let employees_digest = Digest::from_serializable(&employees);
        let snapshot_digest = Digest::from_fields(
            "bamboohr-directory-snapshot/v1",
            &[
                fields_digest.as_str().to_owned(),
                employees_digest.as_str().to_owned(),
                fields.len().to_string(),
                employees.len().to_string(),
            ],
        );
        Ok(Self {
            fields,
            employees,
            fields_digest,
            employees_digest,
            snapshot_digest,
        })
    }

    #[must_use]
    pub fn empty() -> Self {
        Self::new(Vec::new(), Vec::new()).expect("empty BambooHR snapshot is valid")
    }

    #[must_use]
    pub fn verify_integrity(&self) -> bool {
        Self::new(self.fields.clone(), self.employees.clone()).is_ok_and(|expected| {
            expected.fields_digest == self.fields_digest
                && expected.employees_digest == self.employees_digest
                && expected.snapshot_digest == self.snapshot_digest
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BambooHrDirectoryRequest {
    pub method: String,
    pub path_digest: Digest,
    pub company_domain_digest: Digest,
    pub only_current: bool,
    pub accept_json: bool,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub request_digest: Digest,
}

impl BambooHrDirectoryRequest {
    pub fn new(scope: &BambooHrDirectoryScope) -> Result<Self, ModelError> {
        scope.validate()?;
        let path_digest = Digest::from_text("GET /api/v1/employees/directory");
        let company_domain_digest = scope.company_domain.digest();
        let request_digest = Digest::from_fields(
            "bamboohr-directory-request/v1",
            &[
                "GET".to_owned(),
                path_digest.as_str().to_owned(),
                company_domain_digest.as_str().to_owned(),
                scope.only_current.to_string(),
                "application/json".to_owned(),
                scope.scope_digest().as_str().to_owned(),
                scope.permission_digest().as_str().to_owned(),
                scope.fieldset_digest().as_str().to_owned(),
            ],
        );
        Ok(Self {
            method: "GET".to_owned(),
            path_digest,
            company_domain_digest,
            only_current: scope.only_current,
            accept_json: true,
            scope_digest: scope.scope_digest().clone(),
            permission_digest: scope.permission_digest().clone(),
            request_digest,
        })
    }

    #[must_use]
    pub fn verify_against(&self, scope: &BambooHrDirectoryScope) -> bool {
        Self::new(scope).is_ok_and(|expected| expected == *self)
    }
}

pub type DirectoryRequest = BambooHrDirectoryRequest;

/// Opaque BambooHR cursor. The provider token is retained only inside the
/// transport seam; receipts and evidence carry its binding digest.
#[derive(Clone, Eq, PartialEq)]
pub struct PageCursor {
    direction: PageDirection,
    raw: String,
    digest: Digest,
    scope_digest: Digest,
    field_selection_digest: Digest,
    page_number: u16,
    issued_at: u64,
    expires_at: u64,
}

impl PageCursor {
    pub fn new(
        direction: PageDirection,
        raw: impl Into<String>,
        scope: &BambooHrDirectoryScope,
        field_selection: &BambooHrEmployeeFieldSelection,
        page_number: u16,
        issued_at: u64,
        ttl_seconds: u64,
    ) -> Result<Self, ModelError> {
        let raw = raw.into();
        if !valid_text(&raw, MAX_CURSOR_BYTES, false) {
            return Err(invalid("employee cursor", "must be bounded and opaque"));
        }
        if page_number == 0 || ttl_seconds == 0 {
            return Err(invalid(
                "employee cursor",
                "page number and TTL must be positive",
            ));
        }
        let expires_at = issued_at
            .checked_add(ttl_seconds)
            .ok_or_else(|| invalid("employee cursor", "TTL overflows the clock bound"))?;
        let scope_digest = scope.scope_digest().clone();
        let field_selection_digest = field_selection.digest().clone();
        let digest = Digest::from_fields(
            "bamboohr-employee-cursor/v1",
            &[
                format!("{direction:?}"),
                raw.clone(),
                scope_digest.as_str().to_owned(),
                field_selection_digest.as_str().to_owned(),
                page_number.to_string(),
                issued_at.to_string(),
                expires_at.to_string(),
            ],
        );
        Ok(Self {
            direction,
            raw,
            digest,
            scope_digest,
            field_selection_digest,
            page_number,
            issued_at,
            expires_at,
        })
    }

    pub fn after(
        raw: impl Into<String>,
        scope: &BambooHrDirectoryScope,
        field_selection: &BambooHrEmployeeFieldSelection,
        page_number: u16,
        issued_at: u64,
        ttl_seconds: u64,
    ) -> Result<Self, ModelError> {
        Self::new(
            PageDirection::After,
            raw,
            scope,
            field_selection,
            page_number,
            issued_at,
            ttl_seconds,
        )
    }

    pub fn before(
        raw: impl Into<String>,
        scope: &BambooHrDirectoryScope,
        field_selection: &BambooHrEmployeeFieldSelection,
        page_number: u16,
        issued_at: u64,
        ttl_seconds: u64,
    ) -> Result<Self, ModelError> {
        Self::new(
            PageDirection::Before,
            raw,
            scope,
            field_selection,
            page_number,
            issued_at,
            ttl_seconds,
        )
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    #[must_use]
    pub const fn direction(&self) -> PageDirection {
        self.direction
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn field_selection_digest(&self) -> &Digest {
        &self.field_selection_digest
    }

    #[must_use]
    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    #[must_use]
    pub const fn issued_at(&self) -> u64 {
        self.issued_at
    }

    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    pub fn validate_against(
        &self,
        scope: &BambooHrDirectoryScope,
        field_selection: &BambooHrEmployeeFieldSelection,
        now_epoch_seconds: u64,
    ) -> Result<(), ModelError> {
        if self.scope_digest != *scope.scope_digest()
            || self.field_selection_digest != *field_selection.digest()
        {
            return Err(ModelError::InvalidScope);
        }
        let expected_digest = Digest::from_fields(
            "bamboohr-employee-cursor/v1",
            &[
                format!("{:?}", self.direction),
                self.raw.clone(),
                self.scope_digest.as_str().to_owned(),
                self.field_selection_digest.as_str().to_owned(),
                self.page_number.to_string(),
                self.issued_at.to_string(),
                self.expires_at.to_string(),
            ],
        );
        if self.digest != expected_digest {
            return Err(ModelError::InvalidResponse);
        }
        if now_epoch_seconds > self.expires_at {
            return Err(ModelError::InvalidResponse);
        }
        Ok(())
    }
}

impl fmt::Debug for PageCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PageCursor")
            .field("direction", &self.direction)
            .field("digest", &self.digest)
            .field("scope_digest", &self.scope_digest)
            .field("field_selection_digest", &self.field_selection_digest)
            .field("page_number", &self.page_number)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BambooHrEmployeeListRequest {
    pub method: String,
    pub path_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub field_selection_digest: Digest,
    pub limit: u16,
    pub page_number: u16,
    pub direction: Option<PageDirection>,
    pub cursor_digest: Option<Digest>,
    pub request_digest: Digest,
}

impl BambooHrEmployeeListRequest {
    pub fn new(
        scope: &BambooHrDirectoryScope,
        bounds: &BambooHrEmployeeListBounds,
    ) -> Result<Self, ModelError> {
        scope.validate()?;
        bounds.validate()?;
        if let Some(cursor) = &bounds.initial_cursor {
            cursor.validate_against(scope, &scope.employee_fields, bounds.now_epoch_seconds)?;
        }
        Self::from_cursor(scope, bounds, bounds.initial_cursor.clone())
    }

    pub fn with_cursor(
        scope: &BambooHrDirectoryScope,
        bounds: &BambooHrEmployeeListBounds,
        cursor: PageCursor,
    ) -> Result<Self, ModelError> {
        cursor.validate_against(scope, &scope.employee_fields, bounds.now_epoch_seconds)?;
        Self::from_cursor(scope, bounds, Some(cursor))
    }

    fn from_cursor(
        scope: &BambooHrDirectoryScope,
        bounds: &BambooHrEmployeeListBounds,
        cursor: Option<PageCursor>,
    ) -> Result<Self, ModelError> {
        let path_digest = Digest::from_text("GET /api/v1/employees");
        let page_number = cursor
            .as_ref()
            .map_or(1, |value| value.page_number().saturating_add(1));
        if page_number > bounds.max_pages {
            return Err(invalid(
                "employee page",
                "exceeds the configured page bound",
            ));
        }
        let direction = cursor.as_ref().map(PageCursor::direction);
        let cursor_digest = cursor.as_ref().map(|value| value.digest().clone());
        let field_selection_digest = scope.employee_fields.digest().clone();
        let request_digest = Digest::from_fields(
            "bamboohr-employee-list-request/v1",
            &[
                "GET".to_owned(),
                path_digest.as_str().to_owned(),
                scope.scope_digest().as_str().to_owned(),
                scope.permission_digest().as_str().to_owned(),
                field_selection_digest.as_str().to_owned(),
                bounds.limit.to_string(),
                page_number.to_string(),
                direction.map_or_else(|| "none".to_owned(), |value| format!("{value:?}")),
                cursor_digest
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), |value| value.as_str().to_owned()),
            ],
        );
        Ok(Self {
            method: "GET".to_owned(),
            path_digest,
            scope_digest: scope.scope_digest().clone(),
            permission_digest: scope.permission_digest().clone(),
            field_selection_digest,
            limit: bounds.limit,
            page_number,
            direction,
            cursor_digest,
            request_digest,
        })
    }

    #[must_use]
    pub fn verify_against(&self, scope: &BambooHrDirectoryScope) -> bool {
        self.scope_digest == *scope.scope_digest()
            && self.permission_digest == *scope.permission_digest()
            && self.field_selection_digest == *scope.employee_fields.digest()
            && self.method == "GET"
            && self.path_digest == Digest::from_text("GET /api/v1/employees")
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "bamboohr-employee-list-request/v1",
            &[
                self.method.clone(),
                self.path_digest.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.permission_digest.as_str().to_owned(),
                self.field_selection_digest.as_str().to_owned(),
                self.limit.to_string(),
                self.page_number.to_string(),
                self.direction
                    .map_or_else(|| "none".to_owned(), |value| format!("{value:?}")),
                self.cursor_digest
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), |value| value.as_str().to_owned()),
            ],
        )
    }

    #[must_use]
    pub fn verify_integrity(&self) -> bool {
        self.method == "GET"
            && self.path_digest == Digest::from_text("GET /api/v1/employees")
            && self.scope_digest.is_valid()
            && self.permission_digest.is_valid()
            && self.field_selection_digest.is_valid()
            && self.page_number > 0
            && (1..=100).contains(&self.limit)
            && self.request_digest == self.compute_digest()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BambooHrEmployeeListBounds {
    pub limit: u16,
    pub max_pages: u16,
    pub max_records: usize,
    pub max_response_bytes: usize,
    pub cursor_ttl_seconds: u64,
    pub now_epoch_seconds: u64,
    pub initial_cursor: Option<PageCursor>,
}

impl Default for BambooHrEmployeeListBounds {
    fn default() -> Self {
        Self {
            limit: 100,
            max_pages: 8,
            max_records: MAX_RECORDS,
            max_response_bytes: MAX_RESPONSE_BYTES,
            cursor_ttl_seconds: 300,
            now_epoch_seconds: 1_735_689_600,
            initial_cursor: None,
        }
    }
}

impl BambooHrEmployeeListBounds {
    pub fn validate(&self) -> Result<(), ModelError> {
        if !(1..=100).contains(&self.limit)
            || !(1..=8).contains(&self.max_pages)
            || !(1..=MAX_RECORDS).contains(&self.max_records)
            || !(1..=MAX_RESPONSE_BYTES).contains(&self.max_response_bytes)
            || self.cursor_ttl_seconds == 0
        {
            return Err(invalid(
                "employee list bounds",
                "exceed the Layer-1 safety bounds",
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn with_initial_cursor(mut self, cursor: PageCursor) -> Self {
        self.initial_cursor = Some(cursor);
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadBounds {
    pub max_records: usize,
    pub max_fields: usize,
    pub max_response_bytes: usize,
}

impl Default for ReadBounds {
    fn default() -> Self {
        Self {
            max_records: MAX_RECORDS,
            max_fields: MAX_FIELDS,
            max_response_bytes: MAX_RESPONSE_BYTES,
        }
    }
}

impl ReadBounds {
    pub fn validate(&self) -> Result<(), ModelError> {
        if !(1..=MAX_RECORDS).contains(&self.max_records)
            || !(1..=MAX_FIELDS).contains(&self.max_fields)
            || !(1..=MAX_RESPONSE_BYTES).contains(&self.max_response_bytes)
        {
            return Err(invalid("read bounds", "exceed the Layer-1 safety bounds"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Recording => "recording",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "BLOCKED_ENV",
        }
    }

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
}

pub type ProviderProvenance = TransportProvenance;

fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

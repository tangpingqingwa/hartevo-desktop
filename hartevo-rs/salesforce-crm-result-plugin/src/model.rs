use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    SALESFORCE_CRM_RESULT_CONTRACT_VERSION, SALESFORCE_CRM_RESULT_SCHEMA_VERSION,
    SALESFORCE_MAX_APPROVAL_STEPS, SALESFORCE_MAX_FIELDS, SALESFORCE_MAX_HISTORY_ENTRIES,
    SALESFORCE_MAX_PAGES, SALESFORCE_PROVIDER_ID,
};

pub(crate) const MAX_IDENTIFIER_BYTES: usize = 128;
pub(crate) const MAX_INSTANCE_BYTES: usize = 253;
pub(crate) const MAX_STATUS_BYTES: usize = 64;
pub(crate) const MAX_DATE_BYTES: usize = 10;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("identifier is empty, malformed, or too long")]
    InvalidIdentifier,
    #[error("Salesforce API version is malformed")]
    InvalidApiVersion,
    #[error("digest is not a lowercase SHA-256 hex digest")]
    InvalidDigest,
    #[error("scope is empty or contains an invalid object/field binding")]
    InvalidScope,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("field list is empty, duplicated, or exceeds the Layer-1 bound")]
    InvalidFields,
    #[error("field is not valid for the selected Salesforce object")]
    InvalidFieldObject,
    #[error("record projection is invalid")]
    InvalidProjection,
    #[error("approval metadata exceeds the Layer-1 bound")]
    ApprovalBoundExceeded,
    #[error("history metadata exceeds the Layer-1 bound")]
    HistoryBoundExceeded,
    #[error("metadata or projection digest does not match its immutable fields")]
    DigestMismatch,
    #[error("registration is invalid")]
    InvalidRegistration,
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("registration is already active")]
    AlreadyActive,
    #[error("opaque reference is empty or malformed")]
    InvalidOpaqueReference,
    #[error("fixture value cannot be projected into the allowlisted field")]
    InvalidFixtureValue,
    #[error("date is not an ISO calendar date")]
    InvalidDate,
    #[error("status value is not bounded and safe")]
    InvalidStatus,
    #[error("amount or probability is outside its supported projection")]
    InvalidNumber,
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

pub(crate) fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    match serde_json::to_vec(value) {
        Ok(bytes) => Digest::from_bytes(&bytes),
        Err(_) => Digest::from_text("canonical-serialization-error"),
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

fn valid_instance(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_INSTANCE_BYTES
        && !value.contains(['/', '\\', '\n', '\r', '\t', ' '])
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_record_id(value: &str) -> bool {
    valid_identifier(value) && value.len() <= 32
}

fn valid_status(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_STATUS_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b' ' | b'/'))
}

macro_rules! bounded_identifier {
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

bounded_identifier!(MissionId);
bounded_identifier!(ProjectId);
bounded_identifier!(WorkProductId);

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

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ApiVersion(String);

impl ApiVersion {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        let Some(rest) = value.strip_prefix('v') else {
            return Err(ModelError::InvalidApiVersion);
        };
        let Some((major, minor)) = rest.split_once('.') else {
            return Err(ModelError::InvalidApiVersion);
        };
        if major.is_empty()
            || minor.is_empty()
            || !major.bytes().all(|byte| byte.is_ascii_digit())
            || !minor.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(ModelError::InvalidApiVersion);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum SalesforceObject {
    Account,
    Opportunity,
    Case,
}

impl SalesforceObject {
    pub const ALL: [Self; 3] = [Self::Account, Self::Opportunity, Self::Case];

    pub const fn api_name(self) -> &'static str {
        match self {
            Self::Account => "Account",
            Self::Opportunity => "Opportunity",
            Self::Case => "Case",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SalesforceField {
    AccountId,
    AccountName,
    AccountType,
    AccountIndustry,
    AccountRating,
    AccountAnnualRevenue,
    OpportunityId,
    OpportunityName,
    OpportunityStage,
    OpportunityCloseDate,
    OpportunityAmount,
    OpportunityProbability,
    OpportunityForecastCategory,
    OpportunityIsClosed,
    OpportunityIsWon,
    OpportunityAccountId,
    CaseId,
    CaseNumber,
    CaseStatus,
    CasePriority,
    CaseOrigin,
    CaseType,
    CaseIsClosed,
    CaseAccountId,
    RecordRevision,
}

impl SalesforceField {
    pub const fn api_name(self) -> &'static str {
        match self {
            Self::AccountId | Self::OpportunityId | Self::CaseId => "Id",
            Self::AccountName | Self::OpportunityName => "Name",
            Self::AccountType => "Type",
            Self::AccountIndustry => "Industry",
            Self::AccountRating => "Rating",
            Self::AccountAnnualRevenue => "AnnualRevenue",
            Self::OpportunityStage => "StageName",
            Self::OpportunityCloseDate => "CloseDate",
            Self::OpportunityAmount => "Amount",
            Self::OpportunityProbability => "Probability",
            Self::OpportunityForecastCategory => "ForecastCategoryName",
            Self::OpportunityIsClosed | Self::CaseIsClosed => "IsClosed",
            Self::OpportunityIsWon => "IsWon",
            Self::OpportunityAccountId | Self::CaseAccountId => "AccountId",
            Self::CaseNumber => "CaseNumber",
            Self::CaseStatus => "Status",
            Self::CasePriority => "Priority",
            Self::CaseOrigin => "Origin",
            Self::CaseType => "Type",
            Self::RecordRevision => "LastModifiedDate",
        }
    }

    pub const fn graphql_name(self) -> &'static str {
        self.api_name()
    }

    pub const fn object(self) -> Option<SalesforceObject> {
        match self {
            Self::AccountId
            | Self::AccountName
            | Self::AccountType
            | Self::AccountIndustry
            | Self::AccountRating
            | Self::AccountAnnualRevenue => Some(SalesforceObject::Account),
            Self::OpportunityId
            | Self::OpportunityName
            | Self::OpportunityStage
            | Self::OpportunityCloseDate
            | Self::OpportunityAmount
            | Self::OpportunityProbability
            | Self::OpportunityForecastCategory
            | Self::OpportunityIsClosed
            | Self::OpportunityIsWon
            | Self::OpportunityAccountId => Some(SalesforceObject::Opportunity),
            Self::CaseId
            | Self::CaseNumber
            | Self::CaseStatus
            | Self::CasePriority
            | Self::CaseOrigin
            | Self::CaseType
            | Self::CaseIsClosed
            | Self::CaseAccountId => Some(SalesforceObject::Case),
            Self::RecordRevision => None,
        }
    }

    pub const fn is_identifier(self) -> bool {
        matches!(
            self,
            Self::AccountId
                | Self::OpportunityId
                | Self::OpportunityAccountId
                | Self::CaseId
                | Self::CaseAccountId
        )
    }

    pub const fn is_revision(self) -> bool {
        matches!(self, Self::RecordRevision)
    }

    pub fn default_allowlist(object: SalesforceObject) -> BTreeSet<Self> {
        match object {
            SalesforceObject::Account => [
                Self::AccountId,
                Self::AccountName,
                Self::AccountType,
                Self::AccountIndustry,
                Self::AccountRating,
                Self::AccountAnnualRevenue,
            ]
            .into_iter()
            .collect::<BTreeSet<_>>(),
            SalesforceObject::Opportunity => [
                Self::OpportunityId,
                Self::OpportunityName,
                Self::OpportunityStage,
                Self::OpportunityCloseDate,
                Self::OpportunityAmount,
                Self::OpportunityProbability,
                Self::OpportunityForecastCategory,
                Self::OpportunityIsClosed,
                Self::OpportunityIsWon,
                Self::OpportunityAccountId,
            ]
            .into_iter()
            .collect::<BTreeSet<_>>(),
            SalesforceObject::Case => [
                Self::CaseId,
                Self::CaseNumber,
                Self::CaseStatus,
                Self::CasePriority,
                Self::CaseOrigin,
                Self::CaseType,
                Self::CaseIsClosed,
                Self::CaseAccountId,
            ]
            .into_iter()
            .collect::<BTreeSet<_>>(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuerySeam {
    RestSoql,
    GraphQl,
}

pub type SalesforceQueryMode = QuerySeam;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SalesforceScopeInput {
    pub organization: String,
    pub instance: String,
    pub api_version: String,
    pub allowlisted_objects: BTreeSet<SalesforceObject>,
    pub allowlisted_fields: BTreeMap<SalesforceObject, BTreeSet<SalesforceField>>,
    pub record_id: String,
    pub record_revision: Digest,
    pub mission_id: String,
    pub mission_revision: u64,
    pub project_id: String,
    pub project_revision: u64,
    pub work_product_id: String,
    pub work_product_revision: u64,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SalesforceScope {
    organization: String,
    instance: String,
    api_version: ApiVersion,
    allowlisted_objects: BTreeSet<SalesforceObject>,
    allowlisted_fields: BTreeMap<SalesforceObject, BTreeSet<SalesforceField>>,
    record_id: String,
    record_revision: Digest,
    mission_id: MissionId,
    mission_revision: Revision,
    project_id: ProjectId,
    project_revision: Revision,
    work_product_id: WorkProductId,
    work_product_revision: Revision,
    permission_digest: Digest,
    consent_digest: Digest,
    scope_digest: Digest,
}

impl SalesforceScope {
    pub fn new(input: SalesforceScopeInput) -> Result<Self, ModelError> {
        if !valid_identifier(&input.organization)
            || !valid_instance(&input.instance)
            || !valid_record_id(&input.record_id)
            || input.allowlisted_objects.is_empty()
            || input.allowlisted_objects.len() > SalesforceObject::ALL.len()
        {
            return Err(ModelError::InvalidScope);
        }
        let api_version = ApiVersion::new(input.api_version)?;
        let mission_id = MissionId::new(input.mission_id)?;
        let project_id = ProjectId::new(input.project_id)?;
        let work_product_id = WorkProductId::new(input.work_product_id)?;
        let mission_revision = Revision::new(input.mission_revision)?;
        let project_revision = Revision::new(input.project_revision)?;
        let work_product_revision = Revision::new(input.work_product_revision)?;
        if !is_digest(input.record_revision.as_str())
            || !is_digest(input.permission_digest.as_str())
            || !is_digest(input.consent_digest.as_str())
        {
            return Err(ModelError::InvalidScope);
        }
        let mut allowlisted_fields = BTreeMap::new();
        for object in &input.allowlisted_objects {
            let mut fields = input
                .allowlisted_fields
                .get(object)
                .cloned()
                .ok_or(ModelError::InvalidScope)?;
            if fields.is_empty()
                || fields.len() > SALESFORCE_MAX_FIELDS
                || fields.iter().any(|field| {
                    field
                        .object()
                        .is_some_and(|field_object| field_object != *object)
                })
            {
                return Err(ModelError::InvalidScope);
            }
            fields.insert(SalesforceField::RecordRevision);
            allowlisted_fields.insert(*object, fields);
        }
        if input
            .allowlisted_fields
            .keys()
            .any(|object| !input.allowlisted_objects.contains(object))
        {
            return Err(ModelError::InvalidScope);
        }
        let scope_digest = Digest::from_fields(
            "salesforce-crm-scope/v1",
            &[
                input.organization.clone(),
                input.instance.clone(),
                api_version.as_str().to_owned(),
                input
                    .allowlisted_objects
                    .iter()
                    .map(|object| object.api_name().to_owned())
                    .collect::<Vec<_>>()
                    .join(","),
                allowlisted_fields
                    .iter()
                    .map(|(object, fields)| {
                        format!(
                            "{}:{}",
                            object.api_name(),
                            fields
                                .iter()
                                .map(|field| format!("{field:?}"))
                                .collect::<Vec<_>>()
                                .join(",")
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("|"),
                input.record_id.clone(),
                input.record_revision.as_str().to_owned(),
                mission_id.as_str().to_owned(),
                mission_revision.get().to_string(),
                project_id.as_str().to_owned(),
                project_revision.get().to_string(),
                work_product_id.as_str().to_owned(),
                work_product_revision.get().to_string(),
                input.permission_digest.as_str().to_owned(),
                input.consent_digest.as_str().to_owned(),
            ],
        );
        Ok(Self {
            organization: input.organization,
            instance: input.instance,
            api_version,
            allowlisted_objects: input.allowlisted_objects,
            allowlisted_fields,
            record_id: input.record_id,
            record_revision: input.record_revision,
            mission_id,
            mission_revision,
            project_id,
            project_revision,
            work_product_id,
            work_product_revision,
            permission_digest: input.permission_digest,
            consent_digest: input.consent_digest,
            scope_digest,
        })
    }

    pub fn organization(&self) -> &str {
        &self.organization
    }

    pub fn instance(&self) -> &str {
        &self.instance
    }

    pub fn api_version(&self) -> &ApiVersion {
        &self.api_version
    }

    pub fn allowlisted_objects(&self) -> &BTreeSet<SalesforceObject> {
        &self.allowlisted_objects
    }

    pub fn allowlisted_fields(&self) -> &BTreeMap<SalesforceObject, BTreeSet<SalesforceField>> {
        &self.allowlisted_fields
    }

    pub fn record_id(&self) -> &str {
        &self.record_id
    }

    pub fn record_revision(&self) -> &Digest {
        &self.record_revision
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub const fn mission_revision(&self) -> Revision {
        self.mission_revision
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub const fn project_revision(&self) -> Revision {
        self.project_revision
    }

    pub fn work_product_id(&self) -> &WorkProductId {
        &self.work_product_id
    }

    pub const fn work_product_revision(&self) -> Revision {
        self.work_product_revision
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn consent_digest(&self) -> &Digest {
        &self.consent_digest
    }

    pub fn scope_digest(&self) -> Digest {
        self.scope_digest.clone()
    }

    pub fn contains_field(&self, object: SalesforceObject, field: SalesforceField) -> bool {
        self.allowlisted_fields
            .get(&object)
            .is_some_and(|fields| fields.contains(&field))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthKind {
    OAuth,
}

/// Opaque, non-serializing reference into a host secret/keyring boundary.
/// The caller-provided reference identifier is immediately reduced to a
/// digest and is never retained or printed.
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    auth_kind: AuthKind,
    revoked: bool,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_digest: self.reference_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            credential_revision: self.credential_revision,
            auth_kind: self.auth_kind,
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
            .field("auth_kind", &self.auth_kind)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest
            && self.scope_digest == other.scope_digest
            && self.credential_revision == other.credential_revision
            && self.auth_kind == other.auth_kind
            && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

impl SecretReference {
    pub fn oauth(
        reference_id: impl Into<String>,
        scope: &SalesforceScope,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        if !valid_identifier(&reference_id) {
            return Err(ModelError::InvalidOpaqueReference);
        }
        let credential_revision = Revision::new(credential_revision)?;
        let scope_digest = scope.scope_digest();
        let reference_digest = Digest::from_fields(
            "salesforce-oauth-secret-reference/v1",
            &[
                reference_id,
                scope_digest.as_str().to_owned(),
                credential_revision.get().to_string(),
                format!("{:?}", AuthKind::OAuth),
            ],
        );
        Ok(Self {
            reference_digest,
            scope_digest,
            credential_revision,
            auth_kind: AuthKind::OAuth,
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

    pub const fn auth_kind(&self) -> AuthKind {
        self.auth_kind
    }

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
        if !self.revoked {
            Err(ModelError::AlreadyActive)
        } else {
            self.revoked = false;
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SalesforceRegistration {
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_version: PluginVersion,
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: PluginVersion,
    pub provider_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub state: RegistrationState,
    pub reversible: bool,
    pub revocable: bool,
    pub registration_digest: Digest,
}

impl SalesforceRegistration {
    pub(crate) fn new(
        plugin_version: PluginVersion,
        provider_version: PluginVersion,
        provider_digest: Digest,
        scope: &SalesforceScope,
    ) -> Self {
        let mut registration = Self {
            schema_version: SALESFORCE_CRM_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: SALESFORCE_CRM_RESULT_CONTRACT_VERSION.to_owned(),
            plugin_version,
            plugin_version_digest: plugin_version.digest(),
            contract_digest: crate::contract_digest(),
            provider_id: SALESFORCE_PROVIDER_ID.to_owned(),
            provider_version,
            provider_digest,
            scope_digest: scope.scope_digest(),
            permission_digest: scope.permission_digest().clone(),
            consent_digest: scope.consent_digest().clone(),
            state: RegistrationState::Active,
            reversible: true,
            revocable: true,
            registration_digest: Digest::from_text("placeholder"),
        };
        registration.registration_digest = registration.compute_digest();
        registration
    }

    pub fn is_active(&self) -> bool {
        self.state == RegistrationState::Active
    }

    pub fn compute_digest(&self) -> Digest {
        canonical_digest(&(
            &self.schema_version,
            &self.contract_version,
            self.plugin_version,
            &self.plugin_version_digest,
            &self.contract_digest,
            &self.provider_id,
            self.provider_version,
            &self.provider_digest,
            &self.scope_digest,
            &self.permission_digest,
            &self.consent_digest,
            self.state,
            self.reversible,
            self.revocable,
        ))
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.registration_digest != self.compute_digest()
            || self.schema_version != SALESFORCE_CRM_RESULT_SCHEMA_VERSION
            || self.contract_version != SALESFORCE_CRM_RESULT_CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.provider_id != SALESFORCE_PROVIDER_ID
            || !self.reversible
            || !self.revocable
        {
            Err(ModelError::InvalidRegistration)
        } else {
            Ok(())
        }
    }

    pub fn revoke(&mut self) -> Result<RevocationReceipt, ModelError> {
        if self.state == RegistrationState::Revoked {
            return Err(ModelError::AlreadyRevoked);
        }
        self.state = RegistrationState::Revoked;
        self.registration_digest = self.compute_digest();
        Ok(RevocationReceipt {
            registration_digest: self.registration_digest.clone(),
            state: self.state,
        })
    }

    pub fn restore(&mut self) -> Result<(), ModelError> {
        if self.state == RegistrationState::Active {
            return Err(ModelError::AlreadyActive);
        }
        self.state = RegistrationState::Active;
        self.registration_digest = self.compute_digest();
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationReceipt {
    pub registration_digest: Digest,
    pub state: RegistrationState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SalesforceReadRequest {
    pub object: SalesforceObject,
    pub record_id: String,
    pub fields: Vec<SalesforceField>,
    pub seam: QuerySeam,
    pub include_approval: bool,
    pub include_history: bool,
    pub max_pages: u8,
}

impl SalesforceReadRequest {
    pub fn new(
        object: SalesforceObject,
        record_id: impl Into<String>,
        fields: impl IntoIterator<Item = SalesforceField>,
        seam: QuerySeam,
        include_approval: bool,
        include_history: bool,
        max_pages: u8,
    ) -> Result<Self, ModelError> {
        let record_id = record_id.into();
        if !valid_record_id(&record_id) {
            return Err(ModelError::InvalidIdentifier);
        }
        let fields = fields.into_iter().collect::<BTreeSet<_>>();
        if fields.is_empty() || fields.len() > SALESFORCE_MAX_FIELDS {
            return Err(ModelError::InvalidFields);
        }
        if fields.iter().any(|field| {
            field
                .object()
                .is_some_and(|field_object| field_object != object)
        }) {
            return Err(ModelError::InvalidFieldObject);
        }
        if max_pages == 0 || max_pages > SALESFORCE_MAX_PAGES {
            return Err(ModelError::InvalidFields);
        }
        Ok(Self {
            object,
            record_id,
            fields: fields.into_iter().collect(),
            seam,
            include_approval,
            include_history,
            max_pages,
        })
    }

    pub fn validate_for(&self, scope: &SalesforceScope) -> Result<(), ModelError> {
        if !scope.allowlisted_objects.contains(&self.object) {
            return Err(ModelError::InvalidScope);
        }
        if self.record_id != scope.record_id {
            return Err(ModelError::InvalidScope);
        }
        if self.fields.is_empty()
            || self.fields.len() > SALESFORCE_MAX_FIELDS
            || self.fields.iter().any(|field| {
                field.object().is_some_and(|object| object != self.object)
                    || !scope.contains_field(self.object, *field)
            })
        {
            return Err(ModelError::InvalidFields);
        }
        Ok(())
    }

    pub fn selected_fields_with_revision(&self) -> Vec<SalesforceField> {
        let mut fields = self.fields.clone();
        if !fields.contains(&SalesforceField::RecordRevision) {
            fields.push(SalesforceField::RecordRevision);
        }
        fields
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SalesforceProjectedValue {
    Identifier(String),
    Digest(Digest),
    Status(String),
    Date(String),
    AmountBucket(AmountBucket),
    ProbabilityBucket(ProbabilityBucket),
    Boolean(bool),
    Count(u16),
    Missing,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AmountBucket {
    Zero,
    Under10k,
    From10kTo100k,
    From100kTo1m,
    AtLeast1m,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbabilityBucket {
    ZeroTo24,
    From25To49,
    From50To74,
    From75To100,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    NotRequested,
    Pending,
    Approved,
    Rejected,
    Recalled,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovalMetadata {
    pub status: ApprovalStatus,
    pub process_digest: Option<Digest>,
    pub submitted_at: Option<u64>,
    pub completed_at: Option<u64>,
    pub step_count: u16,
    pub last_step_status: Option<ApprovalStatus>,
    pub metadata_digest: Digest,
}

impl ApprovalMetadata {
    pub(crate) fn from_fixture(fixture: &ApprovalFixture) -> Result<Self, ModelError> {
        if fixture.step_count > SALESFORCE_MAX_APPROVAL_STEPS {
            return Err(ModelError::ApprovalBoundExceeded);
        }
        let process_digest = fixture.process_reference.as_deref().map(Digest::from_text);
        let metadata_digest = canonical_digest(&(
            fixture.status,
            &process_digest,
            fixture.submitted_at,
            fixture.completed_at,
            fixture.step_count,
            fixture.last_step_status,
        ));
        Ok(Self {
            status: fixture.status,
            process_digest,
            submitted_at: fixture.submitted_at,
            completed_at: fixture.completed_at,
            step_count: fixture.step_count,
            last_step_status: fixture.last_step_status,
            metadata_digest,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.step_count > SALESFORCE_MAX_APPROVAL_STEPS {
            return Err(ModelError::ApprovalBoundExceeded);
        }
        let expected = canonical_digest(&(
            self.status,
            &self.process_digest,
            self.submitted_at,
            self.completed_at,
            self.step_count,
            self.last_step_status,
        ));
        if expected == self.metadata_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryMetadata {
    pub entry_count: u16,
    pub latest_at: Option<u64>,
    pub changed_field_digest: Option<Digest>,
    pub from_value_digest: Option<Digest>,
    pub to_value_digest: Option<Digest>,
    pub truncated: bool,
    pub metadata_digest: Digest,
}

impl HistoryMetadata {
    pub(crate) fn from_fixture(fixture: &HistoryFixture) -> Result<Self, ModelError> {
        if fixture.entry_count > SALESFORCE_MAX_HISTORY_ENTRIES {
            return Err(ModelError::HistoryBoundExceeded);
        }
        let changed_field_digest = fixture.changed_field.as_deref().map(Digest::from_text);
        let from_value_digest = fixture.from_value.as_deref().map(Digest::from_text);
        let to_value_digest = fixture.to_value.as_deref().map(Digest::from_text);
        let metadata_digest = canonical_digest(&(
            fixture.entry_count,
            fixture.latest_at,
            &changed_field_digest,
            &from_value_digest,
            &to_value_digest,
            fixture.truncated,
        ));
        Ok(Self {
            entry_count: fixture.entry_count,
            latest_at: fixture.latest_at,
            changed_field_digest,
            from_value_digest,
            to_value_digest,
            truncated: fixture.truncated,
            metadata_digest,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.entry_count > SALESFORCE_MAX_HISTORY_ENTRIES {
            return Err(ModelError::HistoryBoundExceeded);
        }
        let expected = canonical_digest(&(
            self.entry_count,
            self.latest_at,
            &self.changed_field_digest,
            &self.from_value_digest,
            &self.to_value_digest,
            self.truncated,
        ));
        if expected == self.metadata_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SalesforceRecordProjection {
    pub object: SalesforceObject,
    pub record_id: String,
    pub record_revision: Digest,
    pub fields: BTreeMap<SalesforceField, SalesforceProjectedValue>,
    pub approval: ApprovalMetadata,
    pub history: HistoryMetadata,
    pub raw_payload_retained: bool,
    pub record_digest: Digest,
}

impl SalesforceRecordProjection {
    pub(crate) fn from_fixture(
        fixture: &SalesforceRecordFixture,
        selected_fields: &[SalesforceField],
        include_approval: bool,
        include_history: bool,
    ) -> Result<Self, ModelError> {
        let mut fields = BTreeMap::new();
        for field in selected_fields {
            if field
                .object()
                .is_some_and(|object| object != fixture.object)
            {
                return Err(ModelError::InvalidFieldObject);
            }
            let value = fixture
                .fields
                .get(field)
                .map_or(Ok(SalesforceProjectedValue::Missing), |value| {
                    project_fixture_value(*field, value)
                })?;
            fields.insert(*field, value);
        }
        let approval = if include_approval {
            ApprovalMetadata::from_fixture(&fixture.approval)?
        } else {
            ApprovalMetadata::from_fixture(&ApprovalFixture::default())?
        };
        let history = if include_history {
            HistoryMetadata::from_fixture(&fixture.history)?
        } else {
            HistoryMetadata::from_fixture(&HistoryFixture::default())?
        };
        let mut projection = Self {
            object: fixture.object,
            record_id: fixture.record_id.clone(),
            record_revision: fixture.record_revision.clone(),
            fields,
            approval,
            history,
            raw_payload_retained: false,
            record_digest: Digest::from_text("placeholder"),
        };
        projection.validate_shape()?;
        projection.record_digest = projection.compute_digest();
        Ok(projection)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.validate_shape()?;
        if self.compute_digest() != self.record_digest {
            Err(ModelError::DigestMismatch)
        } else {
            Ok(())
        }
    }

    pub fn compute_digest(&self) -> Digest {
        canonical_digest(&(
            self.object,
            &self.record_id,
            &self.record_revision,
            &self.fields,
            &self.approval,
            &self.history,
            self.raw_payload_retained,
        ))
    }

    pub fn field(&self, field: SalesforceField) -> Option<&SalesforceProjectedValue> {
        self.fields.get(&field)
    }

    fn validate_shape(&self) -> Result<(), ModelError> {
        if !valid_record_id(&self.record_id)
            || !is_digest(self.record_revision.as_str())
            || self.fields.len() > SALESFORCE_MAX_FIELDS
            || self.raw_payload_retained
            || self
                .fields
                .keys()
                .any(|field| field.object().is_some_and(|object| object != self.object))
        {
            return Err(ModelError::InvalidProjection);
        }
        self.approval.validate()?;
        self.history.validate()?;
        if self
            .fields
            .iter()
            .any(|(field, value)| !projected_value_matches_field(*field, value))
        {
            return Err(ModelError::InvalidProjection);
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum SalesforceFixtureValue {
    Text(String),
    Integer(i64),
    Decimal(String),
    Boolean(bool),
    Null,
}

impl fmt::Debug for SalesforceFixtureValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Text(_) => "Text",
            Self::Integer(_) => "Integer",
            Self::Decimal(_) => "Decimal",
            Self::Boolean(_) => "Boolean",
            Self::Null => "Null",
        };
        formatter.debug_tuple(label).field(&"<redacted>").finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalFixture {
    pub status: ApprovalStatus,
    pub process_reference: Option<String>,
    pub submitted_at: Option<u64>,
    pub completed_at: Option<u64>,
    pub step_count: u16,
    pub last_step_status: Option<ApprovalStatus>,
}

impl Default for ApprovalFixture {
    fn default() -> Self {
        Self {
            status: ApprovalStatus::NotRequested,
            process_reference: None,
            submitted_at: None,
            completed_at: None,
            step_count: 0,
            last_step_status: None,
        }
    }
}

impl ApprovalFixture {
    pub fn new(status: ApprovalStatus) -> Self {
        Self {
            status,
            ..Self::default()
        }
    }

    #[must_use]
    pub fn with_process_reference(mut self, reference: impl Into<String>) -> Self {
        self.process_reference = Some(reference.into());
        self
    }

    #[must_use]
    pub const fn with_times(
        mut self,
        submitted_at: Option<u64>,
        completed_at: Option<u64>,
    ) -> Self {
        self.submitted_at = submitted_at;
        self.completed_at = completed_at;
        self
    }

    #[must_use]
    pub const fn with_steps(
        mut self,
        step_count: u16,
        last_step_status: Option<ApprovalStatus>,
    ) -> Self {
        self.step_count = step_count;
        self.last_step_status = last_step_status;
        self
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HistoryFixture {
    pub entry_count: u16,
    pub latest_at: Option<u64>,
    pub changed_field: Option<String>,
    pub from_value: Option<String>,
    pub to_value: Option<String>,
    pub truncated: bool,
}

impl HistoryFixture {
    pub fn new(entry_count: u16) -> Self {
        Self {
            entry_count,
            ..Self::default()
        }
    }

    #[must_use]
    pub const fn with_latest_at(mut self, latest_at: Option<u64>) -> Self {
        self.latest_at = latest_at;
        self
    }

    #[must_use]
    pub fn with_change(
        mut self,
        changed_field: impl Into<String>,
        from_value: impl Into<String>,
        to_value: impl Into<String>,
    ) -> Self {
        self.changed_field = Some(changed_field.into());
        self.from_value = Some(from_value.into());
        self.to_value = Some(to_value.into());
        self
    }

    #[must_use]
    pub const fn truncated(mut self, truncated: bool) -> Self {
        self.truncated = truncated;
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SalesforceRecordFixture {
    pub object: SalesforceObject,
    pub record_id: String,
    pub record_revision: Digest,
    pub fields: BTreeMap<SalesforceField, SalesforceFixtureValue>,
    pub approval: ApprovalFixture,
    pub history: HistoryFixture,
}

impl SalesforceRecordFixture {
    pub fn new(
        object: SalesforceObject,
        record_id: impl Into<String>,
        record_revision: Digest,
    ) -> Result<Self, ModelError> {
        let record_id = record_id.into();
        if !valid_record_id(&record_id) || !is_digest(record_revision.as_str()) {
            return Err(ModelError::InvalidFixtureValue);
        }
        Ok(Self {
            object,
            record_id,
            record_revision,
            fields: BTreeMap::new(),
            approval: ApprovalFixture::default(),
            history: HistoryFixture::default(),
        })
    }

    #[must_use]
    pub fn with_field(mut self, field: SalesforceField, value: SalesforceFixtureValue) -> Self {
        self.fields.insert(field, value);
        self
    }

    #[must_use]
    pub fn with_approval(mut self, approval: ApprovalFixture) -> Self {
        self.approval = approval;
        self
    }

    #[must_use]
    pub fn with_history(mut self, history: HistoryFixture) -> Self {
        self.history = history;
        self
    }
}

fn project_fixture_value(
    field: SalesforceField,
    value: &SalesforceFixtureValue,
) -> Result<SalesforceProjectedValue, ModelError> {
    match (field, value) {
        (_, SalesforceFixtureValue::Null) => Ok(SalesforceProjectedValue::Missing),
        (field, SalesforceFixtureValue::Text(value)) => project_text_value(field, value),
        (field, SalesforceFixtureValue::Integer(value)) => project_integer_value(field, *value),
        (field, SalesforceFixtureValue::Decimal(value)) => value
            .parse::<f64>()
            .map_err(|_| ModelError::InvalidNumber)
            .and_then(|number| project_number_value(field, number)),
        (field, SalesforceFixtureValue::Boolean(value)) => {
            if matches!(
                field,
                SalesforceField::OpportunityIsClosed
                    | SalesforceField::OpportunityIsWon
                    | SalesforceField::CaseIsClosed
            ) {
                Ok(SalesforceProjectedValue::Boolean(*value))
            } else {
                Err(ModelError::InvalidFixtureValue)
            }
        }
    }
}

fn project_text_value(
    field: SalesforceField,
    value: &str,
) -> Result<SalesforceProjectedValue, ModelError> {
    if value.len() > 4 * MAX_IDENTIFIER_BYTES {
        return Err(ModelError::InvalidFixtureValue);
    }
    match field {
        SalesforceField::AccountId
        | SalesforceField::OpportunityId
        | SalesforceField::OpportunityAccountId
        | SalesforceField::CaseId
        | SalesforceField::CaseAccountId => {
            if valid_record_id(value) {
                Ok(SalesforceProjectedValue::Identifier(value.to_owned()))
            } else {
                Err(ModelError::InvalidFixtureValue)
            }
        }
        SalesforceField::AccountName
        | SalesforceField::AccountType
        | SalesforceField::AccountIndustry
        | SalesforceField::AccountRating
        | SalesforceField::OpportunityName
        | SalesforceField::CaseNumber => {
            Ok(SalesforceProjectedValue::Digest(Digest::from_text(value)))
        }
        SalesforceField::OpportunityStage
        | SalesforceField::OpportunityForecastCategory
        | SalesforceField::CaseStatus
        | SalesforceField::CasePriority
        | SalesforceField::CaseOrigin
        | SalesforceField::CaseType => {
            if valid_status(value) {
                Ok(SalesforceProjectedValue::Status(value.to_owned()))
            } else {
                Err(ModelError::InvalidStatus)
            }
        }
        SalesforceField::OpportunityCloseDate => {
            if valid_date(value) {
                Ok(SalesforceProjectedValue::Date(value.to_owned()))
            } else {
                Err(ModelError::InvalidDate)
            }
        }
        SalesforceField::AccountAnnualRevenue
        | SalesforceField::OpportunityAmount
        | SalesforceField::OpportunityProbability => value
            .parse::<f64>()
            .map_err(|_| ModelError::InvalidNumber)
            .and_then(|number| project_number_value(field, number)),
        SalesforceField::OpportunityIsClosed
        | SalesforceField::OpportunityIsWon
        | SalesforceField::CaseIsClosed => Err(ModelError::InvalidFixtureValue),
        SalesforceField::RecordRevision => {
            Ok(SalesforceProjectedValue::Digest(Digest::from_text(value)))
        }
    }
}

fn project_number_value(
    field: SalesforceField,
    value: f64,
) -> Result<SalesforceProjectedValue, ModelError> {
    if !value.is_finite() || value < 0.0 {
        return Err(ModelError::InvalidNumber);
    }
    match field {
        SalesforceField::AccountAnnualRevenue | SalesforceField::OpportunityAmount => {
            let bucket = if value == 0.0 {
                AmountBucket::Zero
            } else if value < 10_000.0 {
                AmountBucket::Under10k
            } else if value < 100_000.0 {
                AmountBucket::From10kTo100k
            } else if value < 1_000_000.0 {
                AmountBucket::From100kTo1m
            } else {
                AmountBucket::AtLeast1m
            };
            Ok(SalesforceProjectedValue::AmountBucket(bucket))
        }
        SalesforceField::OpportunityProbability => {
            let bucket = if value < 25.0 {
                ProbabilityBucket::ZeroTo24
            } else if value < 50.0 {
                ProbabilityBucket::From25To49
            } else if value < 75.0 {
                ProbabilityBucket::From50To74
            } else if value <= 100.0 {
                ProbabilityBucket::From75To100
            } else {
                return Err(ModelError::InvalidNumber);
            };
            Ok(SalesforceProjectedValue::ProbabilityBucket(bucket))
        }
        _ => Err(ModelError::InvalidFixtureValue),
    }
}

fn project_integer_value(
    field: SalesforceField,
    value: i64,
) -> Result<SalesforceProjectedValue, ModelError> {
    if value < 0 {
        return Err(ModelError::InvalidNumber);
    }
    match field {
        SalesforceField::AccountAnnualRevenue | SalesforceField::OpportunityAmount => {
            let bucket = if value == 0 {
                AmountBucket::Zero
            } else if value < 10_000 {
                AmountBucket::Under10k
            } else if value < 100_000 {
                AmountBucket::From10kTo100k
            } else if value < 1_000_000 {
                AmountBucket::From100kTo1m
            } else {
                AmountBucket::AtLeast1m
            };
            Ok(SalesforceProjectedValue::AmountBucket(bucket))
        }
        SalesforceField::OpportunityProbability => {
            let bucket = if value < 25 {
                ProbabilityBucket::ZeroTo24
            } else if value < 50 {
                ProbabilityBucket::From25To49
            } else if value < 75 {
                ProbabilityBucket::From50To74
            } else if value <= 100 {
                ProbabilityBucket::From75To100
            } else {
                return Err(ModelError::InvalidNumber);
            };
            Ok(SalesforceProjectedValue::ProbabilityBucket(bucket))
        }
        _ => Err(ModelError::InvalidFixtureValue),
    }
}

fn valid_date(value: &str) -> bool {
    value.len() == MAX_DATE_BYTES
        && value.as_bytes().get(4) == Some(&b'-')
        && value.as_bytes().get(7) == Some(&b'-')
        && value
            .bytes()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
}

fn projected_value_matches_field(field: SalesforceField, value: &SalesforceProjectedValue) -> bool {
    match value {
        SalesforceProjectedValue::Identifier(value) => {
            field.is_identifier() && valid_record_id(value)
        }
        SalesforceProjectedValue::Digest(value) => {
            is_digest(value.as_str())
                && matches!(
                    field,
                    SalesforceField::AccountName
                        | SalesforceField::AccountType
                        | SalesforceField::AccountIndustry
                        | SalesforceField::AccountRating
                        | SalesforceField::OpportunityName
                        | SalesforceField::CaseNumber
                        | SalesforceField::RecordRevision
                )
        }
        SalesforceProjectedValue::Status(value) => {
            valid_status(value)
                && matches!(
                    field,
                    SalesforceField::OpportunityStage
                        | SalesforceField::OpportunityForecastCategory
                        | SalesforceField::CaseStatus
                        | SalesforceField::CasePriority
                        | SalesforceField::CaseOrigin
                        | SalesforceField::CaseType
                )
        }
        SalesforceProjectedValue::Date(value) => {
            matches!(field, SalesforceField::OpportunityCloseDate) && valid_date(value)
        }
        SalesforceProjectedValue::AmountBucket(_) => matches!(
            field,
            SalesforceField::AccountAnnualRevenue | SalesforceField::OpportunityAmount
        ),
        SalesforceProjectedValue::ProbabilityBucket(_) => {
            matches!(field, SalesforceField::OpportunityProbability)
        }
        SalesforceProjectedValue::Boolean(_) => matches!(
            field,
            SalesforceField::OpportunityIsClosed
                | SalesforceField::OpportunityIsWon
                | SalesforceField::CaseIsClosed
        ),
        SalesforceProjectedValue::Count(_) => false,
        SalesforceProjectedValue::Missing => true,
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    BadRequest,
    Unauthenticated,
    PermissionDenied,
    NotFound,
    Conflict,
    RateLimited,
    ServerFailure,
    Timeout,
    Decode,
    BlockedEnv,
    Pagination,
    Tampered,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderErrorEvidence {
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub retryable: bool,
    pub blocked_env: bool,
    pub diagnostic_digest: Digest,
    pub error_digest: Digest,
}

impl ProviderErrorEvidence {
    pub fn new(
        kind: ProviderErrorKind,
        status_code: Option<u16>,
        diagnostic: impl AsRef<[u8]>,
    ) -> Self {
        let diagnostic_digest = Digest::from_text(diagnostic);
        let retryable = matches!(
            kind,
            ProviderErrorKind::RateLimited
                | ProviderErrorKind::ServerFailure
                | ProviderErrorKind::Timeout
        );
        let blocked_env = kind == ProviderErrorKind::BlockedEnv;
        let error_digest = canonical_digest(&(
            kind,
            status_code,
            retryable,
            blocked_env,
            &diagnostic_digest,
        ));
        Self {
            kind,
            status_code,
            retryable,
            blocked_env,
            diagnostic_digest,
            error_digest,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SalesforceResultStatus {
    Complete,
    Partial,
    AccessLost,
    NotFound,
    ProviderUnknown,
    FinalError,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PaginationEvidence {
    pub pages: u8,
    pub next_records_url_digests: Vec<Digest>,
    pub truncated: bool,
    pub loop_detected: bool,
}

impl PaginationEvidence {
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.pages == 0
            || self.pages > SALESFORCE_MAX_PAGES
            || self.loop_detected && !self.truncated
        {
            return Err(ModelError::InvalidProjection);
        }
        if self
            .next_records_url_digests
            .iter()
            .any(|digest| !is_digest(digest.as_str()))
        {
            return Err(ModelError::InvalidProjection);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginVersionCompatibility {
    Exact,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl PluginVersion {
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    pub fn digest(self) -> Digest {
        Digest::from_fields(
            "salesforce-plugin-version/v1",
            &[
                self.major.to_string(),
                self.minor.to_string(),
                self.patch.to_string(),
            ],
        )
    }
}

impl fmt::Display for PluginVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

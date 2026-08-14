use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use hartevo_domain_kernel::{ConsentRecordId, MissionId, ProjectId, TenantId, WorkProductId};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::SecretReference;
use crate::{
    CONTRACT_VERSION, EVIDENCE_LEVEL, PROVIDER_ID, Result, ServiceNowChangeError,
    canonical_json_digest, is_sha256, sha256_hex, valid_identifier, valid_non_empty,
};

/// A normalized ServiceNow field name.  Dot-walks and encoded-query syntax are
/// intentionally not accepted: every field used by the provider must be an
/// allowlisted column from the registration mapping.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct FieldName(String);

impl FieldName {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into().trim().to_owned();
        if valid_identifier(&value) && value.len() <= 128 {
            Ok(Self(value))
        } else {
            Err(ServiceNowChangeError::InvalidIdentifier(value))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<()> {
        if valid_identifier(&self.0) && self.0.len() <= 128 {
            Ok(())
        } else {
            Err(ServiceNowChangeError::InvalidIdentifier("field".into()))
        }
    }
}

impl fmt::Display for FieldName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// A normalized ServiceNow table name.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct TableName(String);

impl TableName {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into().trim().to_owned();
        if valid_identifier(&value) && value.len() <= 128 {
            Ok(Self(value))
        } else {
            Err(ServiceNowChangeError::InvalidIdentifier(value))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<()> {
        if valid_identifier(&self.0) && self.0.len() <= 128 {
            Ok(())
        } else {
            Err(ServiceNowChangeError::InvalidIdentifier("table".into()))
        }
    }
}

impl fmt::Display for TableName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// ServiceNow's record identity.  A display number is never accepted as a
/// sys_id; the two values remain typed and separately bound.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct SysId(String);

impl SysId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into().trim().to_ascii_lowercase();
        if value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            Ok(Self(value))
        } else {
            Err(ServiceNowChangeError::InvalidSysId)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<()> {
        if self.0.len() == 32
            && self.0 == self.0.to_ascii_lowercase()
            && self.0.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            Ok(())
        } else {
            Err(ServiceNowChangeError::InvalidSysId)
        }
    }
}

impl fmt::Display for SysId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// A provider revision such as `sys_updated_on` or a configured row version.
/// It is retained only as an exact bounded scalar, never as a raw payload.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ProviderRevision(String);

impl ProviderRevision {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into().trim().to_owned();
        if valid_non_empty(&value, 128) {
            Ok(Self(value))
        } else {
            Err(ServiceNowChangeError::InvalidIdentifier(value))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<()> {
        if valid_non_empty(&self.0, 128) {
            Ok(())
        } else {
            Err(ServiceNowChangeError::InvalidIdentifier(
                "provider revision".into(),
            ))
        }
    }
}

impl fmt::Display for ProviderRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Normalized HTTPS origin.  Paths, query strings, fragments, credentials and
/// redirects are not part of an instance origin.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct NormalizedOrigin(String);

impl NormalizedOrigin {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let input = value.into();
        let parsed = Url::parse(input.trim()).map_err(|_| ServiceNowChangeError::InvalidOrigin)?;
        if parsed.scheme() != "https"
            || parsed.username() != ""
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.host_str().is_none()
            || (parsed.path() != "" && parsed.path() != "/")
        {
            return Err(ServiceNowChangeError::InvalidOrigin);
        }
        let host = parsed
            .host_str()
            .ok_or(ServiceNowChangeError::InvalidOrigin)?
            .to_ascii_lowercase();
        let host = if host.contains(':') {
            format!("[{host}]")
        } else {
            host
        };
        let port = parsed.port().filter(|port| *port != 443);
        let origin = match port {
            Some(port) => format!("https://{host}:{port}"),
            None => format!("https://{host}"),
        };
        Ok(Self(origin))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<()> {
        if Self::new(self.0.clone())? == *self {
            Ok(())
        } else {
            Err(ServiceNowChangeError::InvalidOrigin)
        }
    }
}

impl fmt::Display for NormalizedOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Release/build identity is opaque and instance-specific.  No release is
/// treated as a universal ServiceNow state machine.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ReleaseIdentity(String);

impl ReleaseIdentity {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into().trim().to_ascii_lowercase();
        if valid_non_empty(&value, 128) {
            Ok(Self(value))
        } else {
            Err(ServiceNowChangeError::InvalidIdentifier(value))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<()> {
        if Self::new(self.0.clone())? == *self {
            Ok(())
        } else {
            Err(ServiceNowChangeError::InvalidIdentifier("release".into()))
        }
    }
}

impl fmt::Display for ReleaseIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InstanceIdentity {
    pub origin: NormalizedOrigin,
    pub instance_id: String,
    pub release: ReleaseIdentity,
}

impl InstanceIdentity {
    pub fn new(
        origin: impl Into<String>,
        instance_id: impl Into<String>,
        release: impl Into<String>,
    ) -> Result<Self> {
        let instance_id = instance_id.into().trim().to_ascii_lowercase();
        if !valid_non_empty(&instance_id, 128) {
            return Err(ServiceNowChangeError::InvalidIdentifier(instance_id));
        }
        Ok(Self {
            origin: NormalizedOrigin::new(origin)?,
            instance_id,
            release: ReleaseIdentity::new(release)?,
        })
    }

    pub fn validate(&self) -> Result<()> {
        self.origin.validate()?;
        if !valid_non_empty(&self.instance_id, 128)
            || Self::new(
                self.origin.as_str(),
                self.instance_id.clone(),
                self.release.as_str(),
            )? != *self
        {
            return Err(ServiceNowChangeError::InvalidIdentifier("instance".into()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DomainIdentity {
    pub domain_id: String,
    pub domain_path: String,
}

impl DomainIdentity {
    pub fn new(domain_id: impl Into<String>, domain_path: impl Into<String>) -> Result<Self> {
        let domain_id = domain_id.into().trim().to_ascii_lowercase();
        let domain_path = domain_path.into().trim().to_owned();
        if !valid_non_empty(&domain_id, 128) || !valid_non_empty(&domain_path, 256) {
            return Err(ServiceNowChangeError::InvalidIdentifier(format!(
                "{domain_id}:{domain_path}"
            )));
        }
        Ok(Self {
            domain_id,
            domain_path,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if Self::new(self.domain_id.clone(), self.domain_path.clone())? != *self {
            return Err(ServiceNowChangeError::InvalidIdentifier("domain".into()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderIdentity {
    pub provider_id: String,
    pub adapter_version: u32,
    pub release: ReleaseIdentity,
}

impl ProviderIdentity {
    pub fn new(adapter_version: u32, release: impl Into<String>) -> Result<Self> {
        let identity = Self {
            provider_id: PROVIDER_ID.to_owned(),
            adapter_version,
            release: ReleaseIdentity::new(release)?,
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn validate(&self) -> Result<()> {
        self.provider_id_matches()?;
        self.release.validate()?;
        if self.adapter_version == 0 {
            return Err(ServiceNowChangeError::InvalidProviderIdentity);
        }
        Ok(())
    }

    fn provider_id_matches(&self) -> Result<()> {
        if self.provider_id != PROVIDER_ID || self.adapter_version == 0 {
            return Err(ServiceNowChangeError::InvalidProviderIdentity);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChangeRecordIdentity {
    pub sys_id: SysId,
    pub number: String,
}

impl ChangeRecordIdentity {
    pub fn new(sys_id: impl Into<String>, number: impl Into<String>) -> Result<Self> {
        let number = number.into().trim().to_owned();
        if !valid_non_empty(&number, 128) {
            return Err(ServiceNowChangeError::InvalidIdentifier(number));
        }
        Ok(Self {
            sys_id: SysId::new(sys_id)?,
            number,
        })
    }

    pub fn validate(&self) -> Result<()> {
        self.sys_id.validate()?;
        if !valid_non_empty(&self.number, 128) {
            return Err(ServiceNowChangeError::InvalidIdentifier(
                "change number".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovalRecordIdentity {
    pub sys_id: SysId,
}

impl ApprovalRecordIdentity {
    pub fn new(sys_id: impl Into<String>) -> Result<Self> {
        Ok(Self {
            sys_id: SysId::new(sys_id)?,
        })
    }

    pub fn validate(&self) -> Result<()> {
        self.sys_id.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentReference {
    pub consent_id: ConsentRecordId,
    pub consent_revision: u64,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub work_product_id: WorkProductId,
}

impl ConsentReference {
    pub fn new(
        consent_id: ConsentRecordId,
        consent_revision: u64,
        project_id: ProjectId,
        mission_id: MissionId,
        work_product_id: WorkProductId,
    ) -> Result<Self> {
        let reference = Self {
            consent_id,
            consent_revision,
            project_id,
            mission_id,
            work_product_id,
        };
        reference.validate()?;
        Ok(reference)
    }

    pub fn validate(&self) -> Result<()> {
        if self.consent_revision == 0
            || self.consent_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.mission_id.as_str().trim().is_empty()
            || self.work_product_id.as_str().trim().is_empty()
        {
            return Err(ServiceNowChangeError::ConsentScopeMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionScope {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub project_revision: u64,
    pub mission_id: MissionId,
    pub mission_revision: u64,
    pub work_product_id: WorkProductId,
    pub work_product_revision: u64,
    pub consent: ConsentReference,
}

impl MissionScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant_id: TenantId,
        project_id: ProjectId,
        project_revision: u64,
        mission_id: MissionId,
        mission_revision: u64,
        work_product_id: WorkProductId,
        work_product_revision: u64,
        consent: ConsentReference,
    ) -> Result<Self> {
        let scope = Self {
            tenant_id,
            project_id,
            project_revision,
            mission_id,
            mission_revision,
            work_product_id,
            work_product_revision,
            consent,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<()> {
        self.consent.validate()?;
        if self.project_id != self.consent.project_id
            || self.mission_id != self.consent.mission_id
            || self.work_product_id != self.consent.work_product_id
            || self.project_revision == 0
            || self.mission_revision == 0
            || self.work_product_revision == 0
            || self.tenant_id.as_str().trim().is_empty()
        {
            return Err(ServiceNowChangeError::ConsentScopeMismatch);
        }
        Ok(())
    }

    pub fn digest(&self) -> String {
        canonical_json_digest(self).expect("MissionScope is serializable")
    }
}

/// Scope material is serializable only after the OAuth reference has been
/// reduced to its opaque id, scope digest and credential revision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceNowScopeReceipt {
    pub mission: MissionScope,
    pub instance: InstanceIdentity,
    pub domain: DomainIdentity,
    pub change: Option<ChangeRecordIdentity>,
    pub approval_sys_ids: BTreeSet<SysId>,
    pub secret_reference_id: String,
    pub secret_scope_digest: String,
    pub credential_revision: u64,
    pub scope_digest: String,
}

impl ServiceNowScopeReceipt {
    pub fn validate(&self) -> Result<()> {
        self.mission.validate()?;
        self.instance.validate()?;
        self.domain.validate()?;
        if let Some(change) = &self.change {
            change.validate()?;
        }
        for approval in &self.approval_sys_ids {
            approval.validate()?;
        }
        if self.change.is_none() && !self.approval_sys_ids.is_empty() {
            return Err(ServiceNowChangeError::ScopeMismatch);
        }
        if !valid_secret_reference_id(&self.secret_reference_id)
            || !is_sha256(&self.secret_scope_digest)
            || self.credential_revision == 0
        {
            return Err(ServiceNowChangeError::ScopeMismatch);
        }
        let expected = self.scope_digest.clone();
        let mut without_digest = self.clone();
        without_digest.scope_digest.clear();
        if expected
            != canonical_json_digest(&without_digest)
                .map_err(|_| ServiceNowChangeError::ScopeMismatch)?
        {
            return Err(ServiceNowChangeError::ScopeMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceNowScope {
    pub mission: MissionScope,
    pub instance: InstanceIdentity,
    pub domain: DomainIdentity,
    pub change: Option<ChangeRecordIdentity>,
    pub approval_sys_ids: BTreeSet<SysId>,
    pub secret_reference: SecretReference,
}

impl ServiceNowScope {
    pub fn new(
        mission: MissionScope,
        instance: InstanceIdentity,
        domain: DomainIdentity,
        change: Option<ChangeRecordIdentity>,
        approval_sys_ids: impl IntoIterator<Item = SysId>,
        secret_reference: SecretReference,
    ) -> Result<Self> {
        let scope = Self {
            mission,
            instance,
            domain,
            change,
            approval_sys_ids: approval_sys_ids.into_iter().collect(),
            secret_reference,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<()> {
        self.mission.validate()?;
        self.instance.validate()?;
        self.domain.validate()?;
        if let Some(change) = &self.change {
            change.validate()?;
        }
        for approval in &self.approval_sys_ids {
            approval.validate()?;
        }
        if self.secret_reference.scope().tenant_id() != self.mission.tenant_id.as_str()
            || self.secret_reference.scope().project_id() != self.mission.project_id.as_str()
            || self.secret_reference.scope().provider_id() != PROVIDER_ID
            || self.secret_reference.scope().account_id() != self.instance.instance_id
            || self.secret_reference.reference_id().trim().is_empty()
            || self.secret_reference.credential_revision() == 0
        {
            return Err(ServiceNowChangeError::ScopeMismatch);
        }
        if self.change.is_none() && !self.approval_sys_ids.is_empty() {
            return Err(ServiceNowChangeError::ScopeMismatch);
        }
        Ok(())
    }

    pub fn require_change(&self) -> Result<&ChangeRecordIdentity> {
        self.change
            .as_ref()
            .ok_or(ServiceNowChangeError::ScopeMismatch)
    }

    pub fn digest(&self) -> String {
        self.receipt_without_digest().scope_digest
    }

    pub fn receipt(&self) -> ServiceNowScopeReceipt {
        self.receipt_without_digest()
    }

    fn receipt_without_digest(&self) -> ServiceNowScopeReceipt {
        let mut receipt = ServiceNowScopeReceipt {
            mission: self.mission.clone(),
            instance: self.instance.clone(),
            domain: self.domain.clone(),
            change: self.change.clone(),
            approval_sys_ids: self.approval_sys_ids.clone(),
            secret_reference_id: self.secret_reference.reference_id().to_owned(),
            secret_scope_digest: self.secret_reference.scope().digest(),
            credential_revision: self.secret_reference.credential_revision(),
            scope_digest: String::new(),
        };
        receipt.scope_digest = canonical_json_digest(&receipt).expect("scope receipt serializable");
        receipt
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChangeFieldMapping {
    pub sys_id: FieldName,
    pub number: FieldName,
    pub state: FieldName,
    pub provider_revision: FieldName,
    pub domain: FieldName,
    pub correlation: Option<FieldName>,
    pub proposal_fields: BTreeSet<FieldName>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovalFieldMapping {
    pub sys_id: FieldName,
    pub change_sys_id: FieldName,
    pub state: FieldName,
    pub provider_revision: FieldName,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditFieldMapping {
    pub sys_id: FieldName,
    pub change_sys_id: FieldName,
    pub field_name: FieldName,
    pub value_digest: FieldName,
    pub provider_revision: FieldName,
    pub changed_at: FieldName,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StateMappingEntry {
    pub provider_value: String,
    pub terminal: bool,
}

impl StateMappingEntry {
    pub fn new(provider_value: impl Into<String>, terminal: bool) -> Result<Self> {
        let provider_value = provider_value.into().trim().to_owned();
        if valid_non_empty(&provider_value, 128) {
            Ok(Self {
                provider_value,
                terminal,
            })
        } else {
            Err(ServiceNowChangeError::InvalidSchemaMapping(
                "state provider value is empty".into(),
            ))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SchemaMapping {
    pub change_table: TableName,
    pub approval_table: TableName,
    pub audit_table: TableName,
    pub change_fields: ChangeFieldMapping,
    pub approval_fields: ApprovalFieldMapping,
    pub audit_fields: AuditFieldMapping,
    pub state_mapping: BTreeMap<String, StateMappingEntry>,
    pub schema_fingerprint: String,
    pub mapping_digest: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SchemaMappingMaterial<'a> {
    change_table: &'a TableName,
    approval_table: &'a TableName,
    audit_table: &'a TableName,
    change_fields: &'a ChangeFieldMapping,
    approval_fields: &'a ApprovalFieldMapping,
    audit_fields: &'a AuditFieldMapping,
    state_mapping: &'a BTreeMap<String, StateMappingEntry>,
    schema_fingerprint: &'a str,
}

impl SchemaMapping {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        change_table: TableName,
        approval_table: TableName,
        audit_table: TableName,
        change_fields: ChangeFieldMapping,
        approval_fields: ApprovalFieldMapping,
        audit_fields: AuditFieldMapping,
        state_mapping: BTreeMap<String, StateMappingEntry>,
        schema_fingerprint: impl Into<String>,
    ) -> Result<Self> {
        let mut mapping = Self {
            change_table,
            approval_table,
            audit_table,
            change_fields,
            approval_fields,
            audit_fields,
            state_mapping,
            schema_fingerprint: schema_fingerprint.into(),
            mapping_digest: String::new(),
        };
        mapping.validate_without_digest()?;
        mapping.mapping_digest = mapping
            .calculate_digest()
            .map_err(|_| ServiceNowChangeError::InvalidSchemaMapping("mapping digest".into()))?;
        Ok(mapping)
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_without_digest()?;
        if self.mapping_digest
            != self
                .calculate_digest()
                .map_err(|_| ServiceNowChangeError::InvalidSchemaMapping("mapping digest".into()))?
        {
            return Err(ServiceNowChangeError::SchemaMappingDigestMismatch);
        }
        Ok(())
    }

    pub fn required_fields(&self) -> BTreeSet<FieldName> {
        [
            self.change_fields.sys_id.clone(),
            self.change_fields.number.clone(),
            self.change_fields.state.clone(),
            self.change_fields.provider_revision.clone(),
            self.change_fields.domain.clone(),
            self.approval_fields.sys_id.clone(),
            self.approval_fields.change_sys_id.clone(),
            self.approval_fields.state.clone(),
            self.approval_fields.provider_revision.clone(),
            self.audit_fields.sys_id.clone(),
            self.audit_fields.change_sys_id.clone(),
            self.audit_fields.field_name.clone(),
            self.audit_fields.value_digest.clone(),
            self.audit_fields.provider_revision.clone(),
            self.audit_fields.changed_at.clone(),
        ]
        .into_iter()
        .collect()
    }

    pub fn proposal_field_allowed(&self, field: &FieldName) -> bool {
        self.change_fields.proposal_fields.contains(field)
    }

    pub fn state_for_provider_value(
        &self,
        provider_value: &str,
    ) -> Option<(&str, &StateMappingEntry)> {
        self.state_mapping
            .iter()
            .find(|(_, entry)| entry.provider_value == provider_value)
            .map(|(canonical, entry)| (canonical.as_str(), entry))
    }

    pub fn receipt(&self) -> SchemaMappingReceipt {
        SchemaMappingReceipt {
            contract_version: CONTRACT_VERSION.to_owned(),
            mapping_digest: self.mapping_digest.clone(),
            schema_fingerprint: self.schema_fingerprint.clone(),
            change_table: self.change_table.clone(),
            approval_table: self.approval_table.clone(),
            audit_table: self.audit_table.clone(),
            required_fields: self.required_fields(),
            state_mapping: self.state_mapping.clone(),
        }
    }

    fn validate_without_digest(&self) -> Result<()> {
        self.change_table.validate()?;
        self.approval_table.validate()?;
        self.audit_table.validate()?;
        for field in self.required_fields() {
            field.validate()?;
        }
        if let Some(correlation) = &self.change_fields.correlation {
            correlation.validate()?;
        }
        for field in &self.change_fields.proposal_fields {
            field.validate()?;
        }
        if self.change_table == self.approval_table
            || self.change_table == self.audit_table
            || self.approval_table == self.audit_table
        {
            return Err(ServiceNowChangeError::InvalidSchemaMapping(
                "tables must be distinct".into(),
            ));
        }
        if !is_sha256(&self.schema_fingerprint) || self.state_mapping.is_empty() {
            return Err(ServiceNowChangeError::InvalidSchemaMapping(
                "schema fingerprint/state mapping is missing".into(),
            ));
        }
        let change_core = [
            self.change_fields.sys_id.clone(),
            self.change_fields.number.clone(),
            self.change_fields.state.clone(),
            self.change_fields.provider_revision.clone(),
            self.change_fields.domain.clone(),
        ];
        if has_duplicate_fields(&change_core)
            || self
                .change_fields
                .correlation
                .as_ref()
                .is_some_and(|field| change_core.contains(field))
            || self
                .change_fields
                .proposal_fields
                .iter()
                .any(|field| change_core.contains(field))
        {
            return Err(ServiceNowChangeError::InvalidSchemaMapping(
                "field mapping contains duplicate columns".into(),
            ));
        }
        if has_duplicate_fields(&[
            self.approval_fields.sys_id.clone(),
            self.approval_fields.change_sys_id.clone(),
            self.approval_fields.state.clone(),
            self.approval_fields.provider_revision.clone(),
        ]) || has_duplicate_fields(&[
            self.audit_fields.sys_id.clone(),
            self.audit_fields.change_sys_id.clone(),
            self.audit_fields.field_name.clone(),
            self.audit_fields.value_digest.clone(),
            self.audit_fields.provider_revision.clone(),
            self.audit_fields.changed_at.clone(),
        ]) {
            return Err(ServiceNowChangeError::InvalidSchemaMapping(
                "field mapping contains duplicate columns within a table".into(),
            ));
        }
        if self
            .change_fields
            .proposal_fields
            .iter()
            .any(|field| !valid_identifier(field.as_str()))
        {
            return Err(ServiceNowChangeError::InvalidSchemaMapping(
                "proposal field is not mapped".into(),
            ));
        }
        if self.state_mapping.iter().any(|(canonical, entry)| {
            !valid_non_empty(canonical, 64) || !valid_non_empty(&entry.provider_value, 128)
        }) {
            return Err(ServiceNowChangeError::InvalidSchemaMapping(
                "state mapping contains an empty value".into(),
            ));
        }
        let provider_values = self
            .state_mapping
            .values()
            .map(|entry| entry.provider_value.as_str())
            .collect::<BTreeSet<_>>();
        if provider_values.len() != self.state_mapping.len() {
            return Err(ServiceNowChangeError::InvalidSchemaMapping(
                "state mapping contains duplicate provider values".into(),
            ));
        }
        Ok(())
    }

    fn calculate_digest(&self) -> std::result::Result<String, serde_json::Error> {
        canonical_json_digest(&SchemaMappingMaterial {
            change_table: &self.change_table,
            approval_table: &self.approval_table,
            audit_table: &self.audit_table,
            change_fields: &self.change_fields,
            approval_fields: &self.approval_fields,
            audit_fields: &self.audit_fields,
            state_mapping: &self.state_mapping,
            schema_fingerprint: &self.schema_fingerprint,
        })
    }
}

fn has_duplicate_fields(fields: &[FieldName]) -> bool {
    fields.iter().collect::<BTreeSet<_>>().len() != fields.len()
}

fn valid_secret_reference_id(value: &str) -> bool {
    value.strip_prefix("secret-ref-").is_some_and(|suffix| {
        !suffix.is_empty()
            && value.len() <= 128
            && suffix.chars().all(|character| {
                character.is_ascii_alphanumeric() || character == '-' || character == '_'
            })
    })
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SchemaMappingReceipt {
    pub contract_version: String,
    pub mapping_digest: String,
    pub schema_fingerprint: String,
    pub change_table: TableName,
    pub approval_table: TableName,
    pub audit_table: TableName,
    pub required_fields: BTreeSet<FieldName>,
    pub state_mapping: BTreeMap<String, StateMappingEntry>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceProvenance {
    Recording,
    Fake,
    BlockedEnv,
}

impl EvidenceProvenance {
    pub const fn is_blocked(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }

    pub const fn status(self) -> &'static str {
        match self {
            Self::Recording => "RECORDING",
            Self::Fake => "FAKE",
            Self::BlockedEnv => "BLOCKED_ENV",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectionEvidence {
    pub provenance: EvidenceProvenance,
    pub evidence_level: String,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub scope_digest: String,
    pub mapping_digest: String,
    pub schema_fingerprint: String,
    pub query_digest: String,
    pub response_digest: String,
}

impl ProjectionEvidence {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        provenance: EvidenceProvenance,
        scope_digest: String,
        mapping_digest: String,
        schema_fingerprint: String,
        query_digest: String,
        response_digest: String,
    ) -> Self {
        Self {
            provenance,
            evidence_level: EVIDENCE_LEVEL.to_owned(),
            connected: false,
            native: false,
            first_party: false,
            scope_digest,
            mapping_digest,
            schema_fingerprint,
            query_digest,
            response_digest,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.evidence_level != EVIDENCE_LEVEL
            || self.connected
            || self.native
            || self.first_party
            || !is_sha256(&self.scope_digest)
            || !is_sha256(&self.mapping_digest)
            || !is_sha256(&self.schema_fingerprint)
            || !is_sha256(&self.query_digest)
            || !is_sha256(&self.response_digest)
        {
            return Err(ServiceNowChangeError::InvalidContract(
                "projection evidence is not non-native L1 evidence".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChangeProjection {
    pub scope_digest: String,
    pub mapping_digest: String,
    pub schema_fingerprint: String,
    pub instance: InstanceIdentity,
    pub domain: DomainIdentity,
    pub table: TableName,
    pub sys_id: SysId,
    pub number: String,
    pub provider_state: String,
    pub canonical_state: String,
    pub terminal: bool,
    pub provider_revision: ProviderRevision,
    pub evidence: ProjectionEvidence,
    pub field_digest: String,
    pub projection_digest: String,
}

impl ChangeProjection {
    pub fn validate(&self) -> Result<()> {
        self.evidence.validate()?;
        self.instance.validate()?;
        self.domain.validate()?;
        self.table.validate()?;
        self.sys_id.validate()?;
        self.provider_revision.validate()?;
        if self.scope_digest != self.evidence.scope_digest
            || self.mapping_digest != self.evidence.mapping_digest
            || self.schema_fingerprint != self.evidence.schema_fingerprint
            || !valid_non_empty(&self.number, 128)
            || !valid_non_empty(&self.provider_state, 128)
            || !valid_non_empty(&self.canonical_state, 64)
            || !is_sha256(&self.field_digest)
            || self.projection_digest != self.calculate_digest()
        {
            return Err(ServiceNowChangeError::InvalidContract(
                "change projection digest or binding is invalid".into(),
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> String {
        self.projection_digest.clone()
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        scope_digest: String,
        mapping: &SchemaMapping,
        instance: InstanceIdentity,
        domain: DomainIdentity,
        sys_id: SysId,
        number: String,
        provider_state: String,
        canonical_state: String,
        terminal: bool,
        provider_revision: ProviderRevision,
        evidence: ProjectionEvidence,
        field_digest: String,
    ) -> Self {
        let mut projection = Self {
            scope_digest,
            mapping_digest: mapping.mapping_digest.clone(),
            schema_fingerprint: mapping.schema_fingerprint.clone(),
            instance,
            domain,
            table: mapping.change_table.clone(),
            sys_id,
            number,
            provider_state,
            canonical_state,
            terminal,
            provider_revision,
            evidence,
            field_digest,
            projection_digest: String::new(),
        };
        projection.projection_digest = projection.calculate_digest();
        projection
    }

    fn calculate_digest(&self) -> String {
        let mut clone = self.clone();
        clone.projection_digest.clear();
        canonical_json_digest(&clone).expect("change projection serializable")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovalProjection {
    pub scope_digest: String,
    pub mapping_digest: String,
    pub schema_fingerprint: String,
    pub instance: InstanceIdentity,
    pub domain: DomainIdentity,
    pub table: TableName,
    pub sys_id: SysId,
    pub change_sys_id: SysId,
    pub provider_state: String,
    pub canonical_state: String,
    pub terminal: bool,
    pub provider_revision: ProviderRevision,
    pub evidence: ProjectionEvidence,
    pub field_digest: String,
    pub projection_digest: String,
}

impl ApprovalProjection {
    pub fn validate(&self) -> Result<()> {
        self.evidence.validate()?;
        self.instance.validate()?;
        self.domain.validate()?;
        self.table.validate()?;
        self.sys_id.validate()?;
        self.change_sys_id.validate()?;
        self.provider_revision.validate()?;
        if self.scope_digest != self.evidence.scope_digest
            || self.mapping_digest != self.evidence.mapping_digest
            || self.schema_fingerprint != self.evidence.schema_fingerprint
            || !valid_non_empty(&self.provider_state, 128)
            || !valid_non_empty(&self.canonical_state, 64)
            || !is_sha256(&self.field_digest)
            || self.projection_digest != self.calculate_digest()
        {
            return Err(ServiceNowChangeError::InvalidContract(
                "approval projection digest or binding is invalid".into(),
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> String {
        self.projection_digest.clone()
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        scope_digest: String,
        mapping: &SchemaMapping,
        instance: InstanceIdentity,
        domain: DomainIdentity,
        sys_id: SysId,
        change_sys_id: SysId,
        provider_state: String,
        canonical_state: String,
        terminal: bool,
        provider_revision: ProviderRevision,
        evidence: ProjectionEvidence,
        field_digest: String,
    ) -> Self {
        let mut projection = Self {
            scope_digest,
            mapping_digest: mapping.mapping_digest.clone(),
            schema_fingerprint: mapping.schema_fingerprint.clone(),
            instance,
            domain,
            table: mapping.approval_table.clone(),
            sys_id,
            change_sys_id,
            provider_state,
            canonical_state,
            terminal,
            provider_revision,
            evidence,
            field_digest,
            projection_digest: String::new(),
        };
        projection.projection_digest = projection.calculate_digest();
        projection
    }

    fn calculate_digest(&self) -> String {
        let mut clone = self.clone();
        clone.projection_digest.clear();
        canonical_json_digest(&clone).expect("approval projection serializable")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditProjection {
    pub scope_digest: String,
    pub mapping_digest: String,
    pub schema_fingerprint: String,
    pub instance: InstanceIdentity,
    pub domain: DomainIdentity,
    pub table: TableName,
    pub sys_id: SysId,
    pub change_sys_id: SysId,
    pub field_name: FieldName,
    pub value_digest: String,
    pub provider_revision: ProviderRevision,
    pub changed_at: String,
    pub evidence: ProjectionEvidence,
    pub projection_digest: String,
}

impl AuditProjection {
    pub fn validate(&self) -> Result<()> {
        self.evidence.validate()?;
        self.instance.validate()?;
        self.domain.validate()?;
        self.table.validate()?;
        self.sys_id.validate()?;
        self.change_sys_id.validate()?;
        self.field_name.validate()?;
        self.provider_revision.validate()?;
        if self.scope_digest != self.evidence.scope_digest
            || self.mapping_digest != self.evidence.mapping_digest
            || self.schema_fingerprint != self.evidence.schema_fingerprint
            || !is_sha256(&self.value_digest)
            || !valid_non_empty(&self.changed_at, 128)
            || self.projection_digest != self.calculate_digest()
        {
            return Err(ServiceNowChangeError::InvalidContract(
                "audit projection digest or binding is invalid".into(),
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> String {
        self.projection_digest.clone()
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        scope_digest: String,
        mapping: &SchemaMapping,
        instance: InstanceIdentity,
        domain: DomainIdentity,
        sys_id: SysId,
        change_sys_id: SysId,
        field_name: FieldName,
        value_digest: String,
        provider_revision: ProviderRevision,
        changed_at: String,
        evidence: ProjectionEvidence,
    ) -> Self {
        let mut projection = Self {
            scope_digest,
            mapping_digest: mapping.mapping_digest.clone(),
            schema_fingerprint: mapping.schema_fingerprint.clone(),
            instance,
            domain,
            table: mapping.audit_table.clone(),
            sys_id,
            change_sys_id,
            field_name,
            value_digest,
            provider_revision,
            changed_at,
            evidence,
            projection_digest: String::new(),
        };
        projection.projection_digest = projection.calculate_digest();
        projection
    }

    fn calculate_digest(&self) -> String {
        let mut clone = self.clone();
        clone.projection_digest.clear();
        canonical_json_digest(&clone).expect("audit projection serializable")
    }
}

/// A stable digest for a provider value used by non-mutating proposals.
pub fn value_digest(value: impl AsRef<[u8]>) -> String {
    sha256_hex(value.as_ref())
}

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::model::{
    ApprovalProjection, AuditProjection, ChangeProjection, EvidenceProvenance, ProviderIdentity,
    SchemaMapping, SchemaMappingReceipt, ServiceNowScope, ServiceNowScopeReceipt, SysId,
};
use crate::provider::{
    ProbeReceipt, ProbeStatus, ProviderPageRequest, RawRecord, ServiceNowChangeProvider,
    ServiceNowTransport,
};
use crate::{
    CONTRACT_VERSION, PLUGIN_ID, PLUGIN_VERSION, PROVIDER_ID, Result, SCHEMA_VERSION,
    ServiceNowChangeError, canonical_json_digest, contract_digest, is_sha256, valid_non_empty,
};

pub const DEFAULT_MAX_PAGE_SIZE: u32 = 100;
pub const DEFAULT_MAX_PAGES: u32 = 16;
pub const DEFAULT_MAX_ITEMS: usize = 256;
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QueryBounds {
    pub max_page_size: u32,
    pub max_pages: u32,
    pub max_items: usize,
    pub max_response_bytes: usize,
}

impl QueryBounds {
    pub const fn layer_one() -> Self {
        Self {
            max_page_size: DEFAULT_MAX_PAGE_SIZE,
            max_pages: DEFAULT_MAX_PAGES,
            max_items: DEFAULT_MAX_ITEMS,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        }
    }

    pub fn validate(self) -> Result<()> {
        if self.max_page_size == 0
            || self.max_page_size > DEFAULT_MAX_PAGE_SIZE
            || self.max_pages == 0
            || self.max_pages > DEFAULT_MAX_PAGES
            || self.max_items == 0
            || self.max_items > DEFAULT_MAX_ITEMS
            || self.max_response_bytes == 0
            || self.max_response_bytes > DEFAULT_MAX_RESPONSE_BYTES
        {
            return Err(ServiceNowChangeError::PaginationBound);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryKind {
    Change,
    Approval,
    Audit,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum QuerySelector {
    Change {
        sys_id: SysId,
    },
    Approvals {
        change_sys_id: SysId,
        approval_sys_ids: BTreeSet<SysId>,
    },
    Audit {
        change_sys_id: SysId,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompiledQuery {
    pub query_kind: QueryKind,
    pub selector: QuerySelector,
    pub table: crate::TableName,
    pub fields: BTreeSet<crate::FieldName>,
    pub encoded_query: String,
    pub page_size: u32,
    pub offset: u32,
    pub cursor: Option<String>,
    pub scope_digest: String,
    pub mapping_digest: String,
    pub provenance: EvidenceProvenance,
    pub query_digest: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct QueryMaterial<'a> {
    query_kind: &'a QueryKind,
    selector: &'a QuerySelector,
    table: &'a crate::TableName,
    fields: &'a BTreeSet<crate::FieldName>,
    encoded_query: &'a str,
    page_size: u32,
    scope_digest: &'a str,
    mapping_digest: &'a str,
    provenance: EvidenceProvenance,
}

impl CompiledQuery {
    pub(crate) fn change(
        scope: &ServiceNowScope,
        mapping: &SchemaMapping,
        page_size: u32,
        provenance: EvidenceProvenance,
    ) -> Result<Self> {
        let change = scope.require_change()?;
        Self::build(
            QueryKind::Change,
            QuerySelector::Change {
                sys_id: change.sys_id.clone(),
            },
            mapping.change_table.clone(),
            [
                mapping.change_fields.sys_id.clone(),
                mapping.change_fields.number.clone(),
                mapping.change_fields.state.clone(),
                mapping.change_fields.provider_revision.clone(),
                mapping.change_fields.domain.clone(),
            ],
            scope,
            mapping,
            page_size,
            provenance,
        )
    }

    pub(crate) fn approvals(
        scope: &ServiceNowScope,
        mapping: &SchemaMapping,
        page_size: u32,
        provenance: EvidenceProvenance,
    ) -> Result<Self> {
        let change = scope.require_change()?;
        Self::build(
            QueryKind::Approval,
            QuerySelector::Approvals {
                change_sys_id: change.sys_id.clone(),
                approval_sys_ids: scope.approval_sys_ids.clone(),
            },
            mapping.approval_table.clone(),
            [
                mapping.approval_fields.sys_id.clone(),
                mapping.approval_fields.change_sys_id.clone(),
                mapping.approval_fields.state.clone(),
                mapping.approval_fields.provider_revision.clone(),
            ],
            scope,
            mapping,
            page_size,
            provenance,
        )
    }

    pub(crate) fn audit(
        scope: &ServiceNowScope,
        mapping: &SchemaMapping,
        page_size: u32,
        provenance: EvidenceProvenance,
    ) -> Result<Self> {
        let change = scope.require_change()?;
        Self::build(
            QueryKind::Audit,
            QuerySelector::Audit {
                change_sys_id: change.sys_id.clone(),
            },
            mapping.audit_table.clone(),
            [
                mapping.audit_fields.sys_id.clone(),
                mapping.audit_fields.change_sys_id.clone(),
                mapping.audit_fields.field_name.clone(),
                mapping.audit_fields.value_digest.clone(),
                mapping.audit_fields.provider_revision.clone(),
                mapping.audit_fields.changed_at.clone(),
            ],
            scope,
            mapping,
            page_size,
            provenance,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        query_kind: QueryKind,
        selector: QuerySelector,
        table: crate::TableName,
        fields: impl IntoIterator<Item = crate::FieldName>,
        scope: &ServiceNowScope,
        mapping: &SchemaMapping,
        page_size: u32,
        provenance: EvidenceProvenance,
    ) -> Result<Self> {
        if page_size == 0 || page_size > DEFAULT_MAX_PAGE_SIZE {
            return Err(ServiceNowChangeError::PaginationBound);
        }
        let fields = fields.into_iter().collect::<BTreeSet<_>>();
        let encoded_query = encoded_query(&query_kind, &selector, mapping)?;
        if encoded_query.contains("^OR")
            || encoded_query.contains("javascript")
            || encoded_query.contains("NQ")
            || encoded_query.contains('*')
        {
            return Err(ServiceNowChangeError::CallerQueryNotAllowed);
        }
        let mut query = Self {
            query_kind,
            selector,
            table,
            fields,
            encoded_query,
            page_size,
            offset: 0,
            cursor: None,
            scope_digest: scope.digest(),
            mapping_digest: mapping.mapping_digest.clone(),
            provenance,
            query_digest: String::new(),
        };
        query.query_digest = query.calculate_digest()?;
        Ok(query)
    }

    pub fn validate(&self) -> Result<()> {
        self.table.validate()?;
        for field in &self.fields {
            field.validate()?;
        }
        match &self.selector {
            QuerySelector::Change { sys_id }
            | QuerySelector::Audit {
                change_sys_id: sys_id,
            } => {
                sys_id.validate()?;
            }
            QuerySelector::Approvals {
                change_sys_id,
                approval_sys_ids,
            } => {
                change_sys_id.validate()?;
                if approval_sys_ids.is_empty() {
                    return Err(ServiceNowChangeError::ApprovalSetMismatch);
                }
                for sys_id in approval_sys_ids {
                    sys_id.validate()?;
                }
            }
        }
        if !is_sha256(&self.scope_digest)
            || !is_sha256(&self.mapping_digest)
            || !is_sha256(&self.query_digest)
            || self.page_size == 0
            || self.page_size > DEFAULT_MAX_PAGE_SIZE
            || self.offset > DEFAULT_MAX_ITEMS as u32
            || self
                .cursor
                .as_deref()
                .is_some_and(|cursor| !valid_non_empty(cursor, 256))
            || self.encoded_query.contains("^OR")
            || self.encoded_query.contains("javascript")
            || self.encoded_query.contains("NQ")
            || self.encoded_query.contains('*')
            || self.query_digest != self.calculate_digest()?
        {
            return Err(ServiceNowChangeError::QueryBindingMismatch);
        }
        Ok(())
    }

    pub(crate) fn page_request(&self) -> ProviderPageRequest {
        ProviderPageRequest {
            query_kind: self.query_kind.clone(),
            query_digest: self.query_digest.clone(),
            table: self.table.clone(),
            fields: self.fields.clone(),
            encoded_query: self.encoded_query.clone(),
            offset: self.offset,
            page_size: self.page_size,
            cursor: self.cursor.clone(),
        }
    }

    pub(crate) fn next_page(&self, cursor: String, record_count: usize) -> Result<Self> {
        let next_offset = self
            .offset
            .checked_add(
                u32::try_from(record_count).map_err(|_| ServiceNowChangeError::PaginationBound)?,
            )
            .ok_or(ServiceNowChangeError::PaginationBound)?;
        let mut next = self.clone();
        next.offset = next_offset;
        next.cursor = Some(cursor);
        Ok(next)
    }

    fn calculate_digest(&self) -> Result<String> {
        canonical_json_digest(&QueryMaterial {
            query_kind: &self.query_kind,
            selector: &self.selector,
            table: &self.table,
            fields: &self.fields,
            encoded_query: &self.encoded_query,
            page_size: self.page_size,
            scope_digest: &self.scope_digest,
            mapping_digest: &self.mapping_digest,
            provenance: self.provenance,
        })
        .map_err(|_| ServiceNowChangeError::InvalidContract("query digest".into()))
    }
}

fn encoded_query(
    query_kind: &QueryKind,
    selector: &QuerySelector,
    mapping: &SchemaMapping,
) -> Result<String> {
    let query = match (query_kind, selector) {
        (QueryKind::Change, QuerySelector::Change { sys_id }) => {
            format!("{}={sys_id}", mapping.change_fields.sys_id)
        }
        (
            QueryKind::Approval,
            QuerySelector::Approvals {
                change_sys_id,
                approval_sys_ids,
            },
        ) => {
            if approval_sys_ids.is_empty() {
                return Err(ServiceNowChangeError::ApprovalSetMismatch);
            }
            let ids = approval_sys_ids
                .iter()
                .map(SysId::as_str)
                .collect::<Vec<_>>()
                .join(",");
            format!(
                "{}={change_sys_id}^{}IN{ids}",
                mapping.approval_fields.change_sys_id, mapping.approval_fields.sys_id
            )
        }
        (QueryKind::Audit, QuerySelector::Audit { change_sys_id }) => {
            format!("{}={change_sys_id}", mapping.audit_fields.change_sys_id)
        }
        _ => return Err(ServiceNowChangeError::QueryBindingMismatch),
    };
    Ok(query)
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct RegistrationId(String);

impl RegistrationId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into().trim().to_owned();
        if value.starts_with("servicenow-registration-")
            && valid_non_empty(&value, 128)
            && value
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || "-_".contains(character))
        {
            Ok(Self(value))
        } else {
            Err(ServiceNowChangeError::InvalidRegistration)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RegistrationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RegistrationBindingMaterial {
    plugin_id: String,
    plugin_version: String,
    contract_version: String,
    contract_digest: String,
    provider: ProviderIdentity,
    scope: ServiceNowScopeReceipt,
    mapping_digest: String,
    schema_fingerprint: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceNowRegistration {
    pub id: RegistrationId,
    pub plugin_id: String,
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: String,
    pub provider: ProviderIdentity,
    pub scope: ServiceNowScope,
    pub mapping: SchemaMapping,
    pub scope_digest: String,
    pub mapping_digest: String,
    pub status: RegistrationStatus,
    pub revision: u64,
    pub last_probe: Option<ProbeReceipt>,
    pub binding_digest: String,
}

impl ServiceNowRegistration {
    pub fn new(
        id: RegistrationId,
        scope: ServiceNowScope,
        mapping: SchemaMapping,
        provider: ProviderIdentity,
    ) -> Result<Self> {
        scope.validate()?;
        mapping.validate()?;
        provider.validate()?;
        if provider.release != scope.instance.release {
            return Err(ServiceNowChangeError::InvalidRegistration);
        }
        let mut registration = Self {
            id,
            plugin_id: PLUGIN_ID.to_owned(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider,
            scope_digest: scope.digest(),
            mapping_digest: mapping.mapping_digest.clone(),
            scope,
            mapping,
            status: RegistrationStatus::Active,
            revision: 1,
            last_probe: None,
            binding_digest: String::new(),
        };
        registration.binding_digest = registration.calculate_binding_digest()?;
        registration.validate()?;
        Ok(registration)
    }

    pub fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        self.mapping.validate()?;
        self.provider.validate()?;
        if self.plugin_id != PLUGIN_ID
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.scope_digest != self.scope.digest()
            || self.mapping_digest != self.mapping.mapping_digest
            || self.provider.release != self.scope.instance.release
            || self.revision == 0
            || self.binding_digest != self.calculate_binding_digest()?
        {
            return Err(ServiceNowChangeError::InvalidRegistration);
        }
        if self.last_probe.as_ref().is_some_and(|probe| {
            probe.scope_digest != self.scope_digest || probe.mapping_digest != self.mapping_digest
        }) {
            return Err(ServiceNowChangeError::InvalidRegistration);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<()> {
        self.validate()?;
        if self.status == RegistrationStatus::Active {
            self.status = RegistrationStatus::Revoked;
            self.revision = self
                .revision
                .checked_add(1)
                .ok_or(ServiceNowChangeError::InvalidRegistration)?;
            self.last_probe = None;
        }
        self.validate()
    }

    pub fn restore(&mut self) -> Result<()> {
        self.validate()?;
        if self.status == RegistrationStatus::Revoked {
            self.status = RegistrationStatus::Active;
            self.revision = self
                .revision
                .checked_add(1)
                .ok_or(ServiceNowChangeError::InvalidRegistration)?;
        }
        self.validate()
    }

    pub fn is_active(&self) -> bool {
        self.status == RegistrationStatus::Active
    }

    pub fn scope_receipt(&self) -> ServiceNowScopeReceipt {
        self.scope.receipt()
    }

    pub fn mapping_receipt(&self) -> SchemaMappingReceipt {
        self.mapping.receipt()
    }

    pub(crate) fn record_probe(&mut self, probe: ProbeReceipt) -> Result<()> {
        if probe.scope_digest != self.scope_digest
            || probe.mapping_digest != self.mapping_digest
            || probe.schema_fingerprint != self.mapping.schema_fingerprint
            || probe.instance.expected != self.scope.instance
            || probe.schema.expected_fingerprint != self.mapping.schema_fingerprint
            || (probe.status == ProbeStatus::Ready
                && (probe.instance.observed_domain_id.as_deref()
                    != Some(self.scope.domain.domain_id.as_str())
                    || probe.instance.observed_domain_path.as_deref()
                        != Some(self.scope.domain.domain_path.as_str())))
        {
            return Err(ServiceNowChangeError::ScopeMismatch);
        }
        probe.validate()?;
        self.last_probe = Some(probe);
        self.validate()
    }

    fn calculate_binding_digest(&self) -> Result<String> {
        canonical_json_digest(&RegistrationBindingMaterial {
            plugin_id: self.plugin_id.clone(),
            plugin_version: self.plugin_version.clone(),
            contract_version: self.contract_version.clone(),
            contract_digest: self.contract_digest.clone(),
            provider: self.provider.clone(),
            scope: self.scope.receipt(),
            mapping_digest: self.mapping_digest.clone(),
            schema_fingerprint: self.mapping.schema_fingerprint.clone(),
        })
        .map_err(|_| ServiceNowChangeError::InvalidRegistration)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RegistrationRegistry {
    registrations: BTreeMap<RegistrationId, ServiceNowRegistration>,
}

impl RegistrationRegistry {
    pub fn register(&mut self, registration: ServiceNowRegistration) -> Result<()> {
        registration.validate()?;
        if self.registrations.contains_key(&registration.id) {
            return Err(ServiceNowChangeError::InvalidRegistration);
        }
        self.registrations
            .insert(registration.id.clone(), registration);
        Ok(())
    }

    pub fn get(&self, id: &RegistrationId) -> Result<&ServiceNowRegistration> {
        self.registrations
            .get(id)
            .ok_or(ServiceNowChangeError::RegistrationNotFound)
    }

    pub fn get_mut(&mut self, id: &RegistrationId) -> Result<&mut ServiceNowRegistration> {
        self.registrations
            .get_mut(id)
            .ok_or(ServiceNowChangeError::RegistrationNotFound)
    }

    pub fn revoke(&mut self, id: &RegistrationId) -> Result<()> {
        self.get_mut(id)?.revoke()
    }

    pub fn restore(&mut self, id: &RegistrationId) -> Result<()> {
        self.get_mut(id)?.restore()
    }

    pub fn iter(&self) -> impl Iterator<Item = &ServiceNowRegistration> {
        self.registrations.values()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityDescription {
    pub plugin_id: String,
    pub plugin_version: String,
    pub contract_version: String,
    pub schema_version: String,
    pub provider_id: String,
    pub evidence_level: String,
    pub capabilities: Vec<String>,
    pub read_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub mutations: BTreeSet<String>,
}

impl CapabilityDescription {
    pub fn layer_one() -> Self {
        Self {
            plugin_id: PLUGIN_ID.to_owned(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            schema_version: SCHEMA_VERSION.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            evidence_level: crate::EVIDENCE_LEVEL.to_owned(),
            capabilities: vec![
                "describe_capabilities".into(),
                "probe_registration".into(),
                "describe_schema_mapping".into(),
                "read_change".into(),
                "read_approvals".into(),
                "read_audit".into(),
                "compile_change_proposal".into(),
                "compile_approval_proposal".into(),
                "compile_change_result_proposal".into(),
            ],
            read_only: true,
            connected: false,
            native: false,
            first_party: false,
            mutations: BTreeSet::new(),
        }
    }
}

pub struct ServiceNowChangeService<T> {
    provider: ServiceNowChangeProvider<T>,
    registry: RegistrationRegistry,
}

impl<T: ServiceNowTransport> fmt::Debug for ServiceNowChangeService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServiceNowChangeService")
            .field("provider", &self.provider)
            .field("registration_count", &self.registry.iter().count())
            .finish()
    }
}

impl<T: ServiceNowTransport> ServiceNowChangeService<T> {
    pub fn new(provider: ServiceNowChangeProvider<T>) -> Self {
        Self {
            provider,
            registry: RegistrationRegistry::default(),
        }
    }

    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription::layer_one()
    }

    pub fn register(
        &mut self,
        id: RegistrationId,
        scope: ServiceNowScope,
        mapping: SchemaMapping,
        provider: ProviderIdentity,
    ) -> Result<()> {
        self.registry
            .register(ServiceNowRegistration::new(id, scope, mapping, provider)?)
    }

    pub fn registrations(&self) -> &RegistrationRegistry {
        &self.registry
    }

    pub fn registration(&self, id: &RegistrationId) -> Result<&ServiceNowRegistration> {
        self.registry.get(id)
    }

    pub fn registration_mut(&mut self, id: &RegistrationId) -> Result<&mut ServiceNowRegistration> {
        self.registry.get_mut(id)
    }

    pub fn revoke_registration(&mut self, id: &RegistrationId) -> Result<()> {
        self.registry.revoke(id)
    }

    pub fn restore_registration(&mut self, id: &RegistrationId) -> Result<()> {
        self.registry.restore(id)
    }

    pub fn describe_schema_mapping(&self, id: &RegistrationId) -> Result<SchemaMappingReceipt> {
        let registration = self.active_registration(id)?;
        Ok(registration.mapping_receipt())
    }

    pub fn probe_registration(&mut self, id: &RegistrationId) -> Result<ProbeReceipt> {
        let (scope, mapping) = {
            let registration = self.active_registration(id)?;
            (registration.scope.clone(), registration.mapping.clone())
        };
        // A failed re-probe must not leave an older Ready receipt usable. The
        // next read remains fenced until this exact binding is probed again.
        self.registry.get_mut(id)?.last_probe = None;
        let probe = self.provider.probe_registration(&scope, &mapping)?;
        self.registry.get_mut(id)?.record_probe(probe.clone())?;
        Ok(probe)
    }

    pub fn compile_query(&self, id: &RegistrationId, kind: QueryKind) -> Result<CompiledQuery> {
        let registration = self.ready_registration(id)?;
        let page_size = self.provider.bounds().max_page_size;
        match kind {
            QueryKind::Change => CompiledQuery::change(
                &registration.scope,
                &registration.mapping,
                page_size,
                registration
                    .last_probe
                    .as_ref()
                    .ok_or(ServiceNowChangeError::ProbeRequired)?
                    .provenance,
            ),
            QueryKind::Approval => CompiledQuery::approvals(
                &registration.scope,
                &registration.mapping,
                page_size,
                registration
                    .last_probe
                    .as_ref()
                    .ok_or(ServiceNowChangeError::ProbeRequired)?
                    .provenance,
            ),
            QueryKind::Audit => CompiledQuery::audit(
                &registration.scope,
                &registration.mapping,
                page_size,
                registration
                    .last_probe
                    .as_ref()
                    .ok_or(ServiceNowChangeError::ProbeRequired)?
                    .provenance,
            ),
        }
    }

    pub fn read_change(&mut self, id: &RegistrationId) -> Result<ChangeProjection> {
        let registration = self.ready_registration(id)?.clone();
        let query = CompiledQuery::change(
            &registration.scope,
            &registration.mapping,
            self.provider.bounds().max_page_size,
            registration
                .last_probe
                .as_ref()
                .ok_or(ServiceNowChangeError::ProbeRequired)?
                .provenance,
        )?;
        let records = self.collect_records(query.clone())?;
        if records.len() != 1 {
            return Err(ServiceNowChangeError::RecordIdentityMismatch);
        }
        let projection = self.provider.project_change(
            &registration.scope,
            &registration.mapping,
            &query,
            &records[0],
        )?;
        projection.validate()?;
        Ok(projection)
    }

    pub fn read_approvals(&mut self, id: &RegistrationId) -> Result<Vec<ApprovalProjection>> {
        let registration = self.ready_registration(id)?.clone();
        if registration.scope.approval_sys_ids.is_empty() {
            return Ok(Vec::new());
        }
        let query = CompiledQuery::approvals(
            &registration.scope,
            &registration.mapping,
            self.provider.bounds().max_page_size,
            registration
                .last_probe
                .as_ref()
                .ok_or(ServiceNowChangeError::ProbeRequired)?
                .provenance,
        )?;
        let records = self.collect_records(query.clone())?;
        let mut projections = Vec::with_capacity(records.len());
        let mut seen = BTreeSet::new();
        for record in records {
            let projection = self.provider.project_approval(
                &registration.scope,
                &registration.mapping,
                &query,
                &record,
            )?;
            if !seen.insert(projection.sys_id.clone()) {
                return Err(ServiceNowChangeError::ApprovalSetMismatch);
            }
            projection.validate()?;
            projections.push(projection);
        }
        if seen != registration.scope.approval_sys_ids {
            return Err(ServiceNowChangeError::ApprovalSetMismatch);
        }
        projections.sort_by(|left, right| left.sys_id.cmp(&right.sys_id));
        Ok(projections)
    }

    pub fn read_audit(&mut self, id: &RegistrationId) -> Result<Vec<AuditProjection>> {
        let registration = self.ready_registration(id)?.clone();
        let query = CompiledQuery::audit(
            &registration.scope,
            &registration.mapping,
            self.provider.bounds().max_page_size,
            registration
                .last_probe
                .as_ref()
                .ok_or(ServiceNowChangeError::ProbeRequired)?
                .provenance,
        )?;
        let records = self.collect_records(query.clone())?;
        let mut projections = Vec::with_capacity(records.len());
        let mut seen = BTreeSet::new();
        for record in records {
            let projection = self.provider.project_audit(
                &registration.scope,
                &registration.mapping,
                &query,
                &record,
            )?;
            if !seen.insert(projection.sys_id.clone()) {
                return Err(ServiceNowChangeError::ApprovalSetMismatch);
            }
            projection.validate()?;
            projections.push(projection);
        }
        projections.sort_by(|left, right| left.sys_id.cmp(&right.sys_id));
        Ok(projections)
    }

    fn active_registration(&self, id: &RegistrationId) -> Result<&ServiceNowRegistration> {
        let registration = self.registry.get(id)?;
        if !registration.is_active() {
            return Err(ServiceNowChangeError::RegistrationNotActive);
        }
        Ok(registration)
    }

    fn ready_registration(&self, id: &RegistrationId) -> Result<&ServiceNowRegistration> {
        let registration = self.active_registration(id)?;
        let probe = registration
            .last_probe
            .as_ref()
            .ok_or(ServiceNowChangeError::ProbeRequired)?;
        probe.validate()?;
        if probe.status != ProbeStatus::Ready {
            return Err(ServiceNowChangeError::BlockedEnvironment);
        }
        Ok(registration)
    }

    fn collect_records(&mut self, query: CompiledQuery) -> Result<Vec<RawRecord>> {
        let bounds = self.provider.bounds();
        let mut current = query;
        let mut pages = 0_u32;
        let mut total_bytes = 0_usize;
        let mut records = Vec::new();
        let mut seen_cursors = BTreeSet::new();
        loop {
            pages = pages
                .checked_add(1)
                .ok_or(ServiceNowChangeError::PaginationBound)?;
            if pages > bounds.max_pages {
                return Err(ServiceNowChangeError::PaginationBound);
            }
            let page = self.provider.read_page(&current)?;
            let page_record_count = page.records.len();
            total_bytes = total_bytes
                .checked_add(page.response_bytes)
                .ok_or(ServiceNowChangeError::ResponseTooLarge)?;
            if total_bytes > bounds.max_response_bytes {
                return Err(ServiceNowChangeError::ResponseTooLarge);
            }
            records.extend(page.records);
            if records.len() > bounds.max_items {
                return Err(ServiceNowChangeError::PaginationBound);
            }
            match page.next_cursor {
                None => break,
                Some(cursor) => {
                    if !seen_cursors.insert(cursor.clone()) || records.is_empty() {
                        return Err(ServiceNowChangeError::PaginationLoop);
                    }
                    current = current.next_page(cursor, page_record_count)?;
                }
            }
        }
        Ok(records)
    }
}

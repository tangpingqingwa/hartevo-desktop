use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    ApprovalProjection, AuditProjection, ChangeProjection, FieldName, InstanceIdentity,
    ProjectionEvidence, ProviderRevision, SchemaMapping, ServiceNowScope, SysId, TableName,
};
use crate::service::{CompiledQuery, QueryBounds, QueryKind};
use crate::{Result, ServiceNowChangeError, canonical_json_digest, is_sha256, valid_non_empty};

pub use crate::model::EvidenceProvenance;

/// Input to the probe is intentionally explicit.  Omitted ACL metadata is a
/// first-class state, never an empty-success default.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AclProbe {
    Explicit(BTreeSet<FieldName>),
    Omitted,
}

impl AclProbe {
    pub fn explicit(fields: impl IntoIterator<Item = FieldName>) -> Self {
        Self::Explicit(fields.into_iter().collect())
    }

    pub const fn omitted() -> Self {
        Self::Omitted
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemaProbe {
    pub fingerprint: Option<String>,
    pub fields: Option<BTreeSet<FieldName>>,
}

impl SchemaProbe {
    pub fn explicit(
        fingerprint: impl Into<String>,
        fields: impl IntoIterator<Item = FieldName>,
    ) -> Self {
        Self {
            fingerprint: Some(fingerprint.into()),
            fields: Some(fields.into_iter().collect()),
        }
    }

    pub const fn omitted() -> Self {
        Self {
            fingerprint: None,
            fields: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderProbeResponse {
    pub provenance: EvidenceProvenance,
    pub final_origin: String,
    pub redirects: Vec<String>,
    pub instance_id: String,
    pub release: String,
    pub domain_id: String,
    pub domain_path: Option<String>,
    pub acl: AclProbe,
    pub schema: SchemaProbe,
    pub response_bytes: usize,
}

impl ProviderProbeResponse {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provenance: EvidenceProvenance,
        final_origin: impl Into<String>,
        redirects: Vec<String>,
        instance_id: impl Into<String>,
        release: impl Into<String>,
        domain_id: impl Into<String>,
        acl: AclProbe,
        schema: SchemaProbe,
    ) -> Self {
        Self {
            provenance,
            final_origin: final_origin.into(),
            redirects,
            instance_id: instance_id.into(),
            release: release.into(),
            domain_id: domain_id.into(),
            domain_path: None,
            acl,
            schema,
            response_bytes: 0,
        }
    }

    pub fn with_domain_path(mut self, domain_path: impl Into<String>) -> Self {
        self.domain_path = Some(domain_path.into());
        self
    }

    pub fn blocked(reason: impl Into<String>) -> Self {
        Self {
            provenance: EvidenceProvenance::BlockedEnv,
            final_origin: reason.into(),
            redirects: Vec::new(),
            instance_id: String::new(),
            release: String::new(),
            domain_id: String::new(),
            domain_path: None,
            acl: AclProbe::Omitted,
            schema: SchemaProbe::omitted(),
            response_bytes: 0,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InstanceProbe {
    pub expected: InstanceIdentity,
    pub observed_origin: Option<String>,
    pub observed_instance_id: Option<String>,
    pub observed_release: Option<String>,
    pub observed_domain_id: Option<String>,
    pub observed_domain_path: Option<String>,
    pub redirect_count: usize,
    pub matched: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AclEvidenceStatus {
    Visible,
    NotVisible,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AclEvidence {
    pub status: AclEvidenceStatus,
    pub required_fields: BTreeSet<FieldName>,
    pub visible_fields: BTreeSet<FieldName>,
    pub missing_fields: BTreeSet<FieldName>,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaEvidenceStatus {
    Matched,
    Drift,
    NotVisible,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SchemaEvidence {
    pub status: SchemaEvidenceStatus,
    pub expected_fingerprint: String,
    pub observed_fingerprint: Option<String>,
    pub required_fields: BTreeSet<FieldName>,
    pub observed_fields: BTreeSet<FieldName>,
    pub missing_fields: BTreeSet<FieldName>,
    pub reason: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStatus {
    Ready,
    BlockedEnv,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProbeReceipt {
    pub status: ProbeStatus,
    pub provenance: EvidenceProvenance,
    pub scope_digest: String,
    pub mapping_digest: String,
    pub schema_fingerprint: String,
    pub probe_revision: u64,
    pub instance: InstanceProbe,
    pub acl: AclEvidence,
    pub schema: SchemaEvidence,
    pub evidence_digest: String,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl ProbeReceipt {
    fn blocked(scope: &ServiceNowScope, mapping: &SchemaMapping, revision: u64) -> Self {
        let instance = InstanceProbe {
            expected: scope.instance.clone(),
            observed_origin: None,
            observed_instance_id: None,
            observed_release: None,
            observed_domain_id: None,
            observed_domain_path: None,
            redirect_count: 0,
            matched: false,
        };
        let required_fields = mapping_probe_fields(mapping);
        let acl = AclEvidence {
            status: AclEvidenceStatus::NotVisible,
            required_fields: required_fields.clone(),
            visible_fields: BTreeSet::new(),
            missing_fields: required_fields.clone(),
            reason: Some("BLOCKED_ENV transport has no ACL observation".into()),
        };
        let schema = SchemaEvidence {
            status: SchemaEvidenceStatus::NotVisible,
            expected_fingerprint: mapping.schema_fingerprint.clone(),
            observed_fingerprint: None,
            required_fields: required_fields.clone(),
            observed_fields: BTreeSet::new(),
            missing_fields: required_fields,
            reason: Some("BLOCKED_ENV transport has no schema observation".into()),
        };
        let mut receipt = Self {
            status: ProbeStatus::BlockedEnv,
            provenance: EvidenceProvenance::BlockedEnv,
            scope_digest: scope.digest(),
            mapping_digest: mapping.mapping_digest.clone(),
            schema_fingerprint: mapping.schema_fingerprint.clone(),
            probe_revision: revision,
            instance,
            acl,
            schema,
            evidence_digest: String::new(),
            connected: false,
            native: false,
            first_party: false,
        };
        receipt.evidence_digest = digest_serializable(&receipt).unwrap_or_default();
        receipt
    }

    pub fn validate(&self) -> Result<()> {
        let status_matches_provenance = matches!(
            (self.status, self.provenance),
            (ProbeStatus::BlockedEnv, EvidenceProvenance::BlockedEnv)
                | (
                    ProbeStatus::Ready,
                    EvidenceProvenance::Recording | EvidenceProvenance::Fake
                )
        );
        if self.probe_revision == 0
            || self.instance.expected.validate().is_err()
            || self.connected
            || self.native
            || self.first_party
            || !status_matches_provenance
            || !is_sha256(&self.scope_digest)
            || !is_sha256(&self.mapping_digest)
            || !is_sha256(&self.schema_fingerprint)
            || self.evidence_digest != digest_serializable_without_digest(self)?
        {
            return Err(ServiceNowChangeError::InvalidContract(
                "probe receipt binding is invalid".into(),
            ));
        }
        if self.status == ProbeStatus::Ready
            && (self.instance.redirect_count != 0
                || !self.instance.matched
                || self.instance.observed_origin.as_deref()
                    != Some(self.instance.expected.origin.as_str())
                || self.instance.observed_instance_id.as_deref()
                    != Some(self.instance.expected.instance_id.as_str())
                || self
                    .instance
                    .observed_release
                    .as_deref()
                    .is_none_or(|release| {
                        !release.eq_ignore_ascii_case(self.instance.expected.release.as_str())
                    })
                || self.instance.observed_domain_id.as_deref().is_none()
                || self.instance.observed_domain_path.is_none()
                || self.acl.status != AclEvidenceStatus::Visible
                || !self.acl.missing_fields.is_empty()
                || self.schema.status != SchemaEvidenceStatus::Matched)
        {
            return Err(ServiceNowChangeError::InvalidContract(
                "ready probe lacks exact instance, ACL, or schema evidence".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum RawFieldValue {
    Text(String),
    Null,
}

impl fmt::Debug for RawFieldValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(value) => formatter
                .debug_tuple("Text")
                .field(&format!("sha256:{}", crate::sha256_hex(value.as_bytes())))
                .finish(),
            Self::Null => formatter.write_str("Null"),
        }
    }
}

impl RawFieldValue {
    pub fn text(value: impl Into<String>) -> Self {
        Self::Text(value.into())
    }

    pub const fn null() -> Self {
        Self::Null
    }
}

/// Recording/fake transport rows are not serializable and redact their values
/// in Debug.  The provider converts them immediately into bounded projections.
#[derive(Clone, Eq, PartialEq)]
pub struct RawRecord {
    pub fields: BTreeMap<FieldName, RawFieldValue>,
    pub response_digest: String,
}

impl fmt::Debug for RawRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawRecord")
            .field("field_names", &self.fields.keys().collect::<Vec<_>>())
            .field("response_digest", &self.response_digest)
            .finish()
    }
}

impl RawRecord {
    pub fn new(
        fields: impl IntoIterator<Item = (FieldName, RawFieldValue)>,
        response_digest: impl Into<String>,
    ) -> Result<Self> {
        let record = Self {
            fields: fields.into_iter().collect(),
            response_digest: response_digest.into(),
        };
        if !is_sha256(&record.response_digest) {
            return Err(ServiceNowChangeError::InvalidDigest);
        }
        Ok(record)
    }

    fn value(&self, field: &FieldName) -> std::option::Option<&RawFieldValue> {
        self.fields.get(field)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderPage {
    pub records: Vec<RawRecord>,
    pub next_cursor: Option<String>,
    pub response_bytes: usize,
}

impl ProviderPage {
    pub fn new(
        records: Vec<RawRecord>,
        next_cursor: Option<String>,
        response_bytes: usize,
    ) -> Self {
        Self {
            records,
            next_cursor,
            response_bytes,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderPageRequest {
    pub query_kind: QueryKind,
    pub query_digest: String,
    pub table: TableName,
    pub fields: BTreeSet<FieldName>,
    pub encoded_query: String,
    pub offset: u32,
    pub page_size: u32,
    pub cursor: Option<String>,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum TransportError {
    #[error("BLOCKED_ENV")]
    BlockedEnv,
    #[error("recording transport is unavailable")]
    Unavailable,
    #[error("transport rejected the typed request")]
    Rejected,
    #[error("transport returned malformed bounded data")]
    Malformed,
}

/// The transport is an explicit seam.  A native HTTP client is intentionally
/// not supplied in Layer 1; an eventual adapter must still return a safe
/// provenance and pass the same exact binding checks.
pub trait ServiceNowTransport: fmt::Debug {
    fn provenance(&self) -> EvidenceProvenance;

    fn probe(
        &mut self,
        scope: &ServiceNowScope,
        mapping: &SchemaMapping,
    ) -> std::result::Result<ProviderProbeResponse, TransportError>;

    fn page(
        &mut self,
        request: &ProviderPageRequest,
    ) -> std::result::Result<ProviderPage, TransportError>;
}

pub struct ServiceNowChangeProvider<T> {
    transport: T,
    bounds: QueryBounds,
    probe_revision: u64,
}

impl<T: fmt::Debug> fmt::Debug for ServiceNowChangeProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServiceNowChangeProvider")
            .field("transport", &self.transport)
            .field("bounds", &self.bounds)
            .field("probe_revision", &self.probe_revision)
            .finish()
    }
}

impl<T: ServiceNowTransport> ServiceNowChangeProvider<T> {
    pub fn new(transport: T, bounds: QueryBounds) -> Result<Self> {
        bounds.validate()?;
        Ok(Self {
            transport,
            bounds,
            probe_revision: 0,
        })
    }

    pub fn bounds(&self) -> QueryBounds {
        self.bounds
    }

    pub fn provenance(&self) -> EvidenceProvenance {
        self.transport.provenance()
    }

    pub fn probe_registration(
        &mut self,
        scope: &ServiceNowScope,
        mapping: &SchemaMapping,
    ) -> Result<ProbeReceipt> {
        scope.validate()?;
        mapping.validate()?;
        self.probe_revision = self.probe_revision.saturating_add(1);
        let response = match self.transport.probe(scope, mapping) {
            Ok(response) => response,
            Err(TransportError::BlockedEnv) => {
                return Ok(ProbeReceipt::blocked(scope, mapping, self.probe_revision));
            }
            Err(error) => return Err(ServiceNowChangeError::Transport(error.to_string())),
        };
        if response.provenance != self.transport.provenance() {
            return Err(ServiceNowChangeError::Transport(
                "transport provenance changed during probe".into(),
            ));
        }
        if response.response_bytes > self.bounds.max_response_bytes {
            return Err(ServiceNowChangeError::ResponseTooLarge);
        }
        if response.provenance.is_blocked() {
            return Ok(ProbeReceipt::blocked(scope, mapping, self.probe_revision));
        }
        let observed_origin = crate::model::NormalizedOrigin::new(response.final_origin.clone())?;
        let expected_fields = mapping_probe_fields(mapping);
        let instance = InstanceProbe {
            expected: scope.instance.clone(),
            observed_origin: Some(observed_origin.to_string()),
            observed_instance_id: Some(response.instance_id.clone()),
            observed_release: Some(response.release.clone()),
            observed_domain_id: Some(response.domain_id.clone()),
            observed_domain_path: response.domain_path.clone(),
            redirect_count: response.redirects.len(),
            matched: observed_origin == scope.instance.origin
                && response.instance_id == scope.instance.instance_id
                && response
                    .release
                    .trim()
                    .eq_ignore_ascii_case(scope.instance.release.as_str())
                && response.domain_id == scope.domain.domain_id
                && response.domain_path.as_deref() == Some(scope.domain.domain_path.as_str())
                && response.redirects.is_empty(),
        };
        if !instance.matched {
            return Err(ServiceNowChangeError::InstanceMismatch(
                "origin, instance, release, domain, or redirect chain differs".into(),
            ));
        }

        let (acl, acl_error) = acl_evidence(&expected_fields, &response.acl);
        if let Some(field) = acl_error {
            return Err(ServiceNowChangeError::AclNotVisible { field });
        }
        let (schema, schema_error) = schema_evidence(&expected_fields, mapping, &response.schema);
        if let Some(detail) = schema_error {
            return Err(ServiceNowChangeError::SchemaDrift(detail));
        }
        let mut receipt = ProbeReceipt {
            status: ProbeStatus::Ready,
            provenance: response.provenance,
            scope_digest: scope.digest(),
            mapping_digest: mapping.mapping_digest.clone(),
            schema_fingerprint: mapping.schema_fingerprint.clone(),
            probe_revision: self.probe_revision,
            instance,
            acl,
            schema,
            evidence_digest: String::new(),
            connected: false,
            native: false,
            first_party: false,
        };
        receipt.evidence_digest = digest_serializable_without_digest(&receipt)?;
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn read_page(&mut self, query: &CompiledQuery) -> Result<ProviderPage> {
        query.validate()?;
        if query.page_size > self.bounds.max_page_size {
            return Err(ServiceNowChangeError::PaginationBound);
        }
        let request = query.page_request();
        let page = self
            .transport
            .page(&request)
            .map_err(|error| ServiceNowChangeError::Transport(error.to_string()))?;
        if page.response_bytes > self.bounds.max_response_bytes
            || page.records.len() > query.page_size as usize
        {
            return Err(ServiceNowChangeError::ResponseTooLarge);
        }
        if page
            .next_cursor
            .as_deref()
            .is_some_and(|cursor| !valid_non_empty(cursor, 256))
        {
            return Err(ServiceNowChangeError::PaginationLoop);
        }
        Ok(page)
    }

    pub(crate) fn project_change(
        &self,
        scope: &ServiceNowScope,
        mapping: &SchemaMapping,
        query: &CompiledQuery,
        record: &RawRecord,
    ) -> Result<ChangeProjection> {
        let expected = scope.require_change()?;
        let sys_id = SysId::new(text(record, &mapping.change_fields.sys_id)?)?;
        if sys_id != expected.sys_id {
            return Err(ServiceNowChangeError::RecordIdentityMismatch);
        }
        let number = text(record, &mapping.change_fields.number)?;
        if number != expected.number {
            return Err(ServiceNowChangeError::RecordIdentityMismatch);
        }
        let domain = text(record, &mapping.change_fields.domain)?;
        if domain != scope.domain.domain_id {
            return Err(ServiceNowChangeError::ScopeMismatch);
        }
        let provider_state = text(record, &mapping.change_fields.state)?;
        let (canonical_state, state_mapping) = mapping
            .state_for_provider_value(&provider_state)
            .ok_or(ServiceNowChangeError::StateMappingDrift)?;
        let provider_revision =
            ProviderRevision::new(text(record, &mapping.change_fields.provider_revision)?)?;
        let field_digest = digest_fields(
            record,
            &[
                mapping.change_fields.sys_id.clone(),
                mapping.change_fields.number.clone(),
                mapping.change_fields.state.clone(),
                mapping.change_fields.provider_revision.clone(),
                mapping.change_fields.domain.clone(),
            ]
            .into_iter()
            .collect(),
        )?;
        let evidence = evidence_for(scope, mapping, query, record);
        Ok(ChangeProjection::new(
            scope.digest(),
            mapping,
            scope.instance.clone(),
            scope.domain.clone(),
            sys_id,
            number,
            provider_state,
            canonical_state.to_owned(),
            state_mapping.terminal,
            provider_revision,
            evidence,
            field_digest,
        ))
    }

    pub(crate) fn project_approval(
        &self,
        scope: &ServiceNowScope,
        mapping: &SchemaMapping,
        query: &CompiledQuery,
        record: &RawRecord,
    ) -> Result<ApprovalProjection> {
        let expected_change = scope.require_change()?;
        let sys_id = SysId::new(text(record, &mapping.approval_fields.sys_id)?)?;
        let change_sys_id = SysId::new(text(record, &mapping.approval_fields.change_sys_id)?)?;
        if change_sys_id != expected_change.sys_id {
            return Err(ServiceNowChangeError::RecordIdentityMismatch);
        }
        let provider_state = text(record, &mapping.approval_fields.state)?;
        let (canonical_state, state_mapping) = mapping
            .state_for_provider_value(&provider_state)
            .ok_or(ServiceNowChangeError::StateMappingDrift)?;
        let provider_revision =
            ProviderRevision::new(text(record, &mapping.approval_fields.provider_revision)?)?;
        let field_digest = digest_fields(
            record,
            &[
                mapping.approval_fields.sys_id.clone(),
                mapping.approval_fields.change_sys_id.clone(),
                mapping.approval_fields.state.clone(),
                mapping.approval_fields.provider_revision.clone(),
            ]
            .into_iter()
            .collect(),
        )?;
        let evidence = evidence_for(scope, mapping, query, record);
        Ok(ApprovalProjection::new(
            scope.digest(),
            mapping,
            scope.instance.clone(),
            scope.domain.clone(),
            sys_id,
            change_sys_id,
            provider_state,
            canonical_state.to_owned(),
            state_mapping.terminal,
            provider_revision,
            evidence,
            field_digest,
        ))
    }

    pub(crate) fn project_audit(
        &self,
        scope: &ServiceNowScope,
        mapping: &SchemaMapping,
        query: &CompiledQuery,
        record: &RawRecord,
    ) -> Result<AuditProjection> {
        let expected_change = scope.require_change()?;
        let sys_id = SysId::new(text(record, &mapping.audit_fields.sys_id)?)?;
        let change_sys_id = SysId::new(text(record, &mapping.audit_fields.change_sys_id)?)?;
        if change_sys_id != expected_change.sys_id {
            return Err(ServiceNowChangeError::RecordIdentityMismatch);
        }
        let field_name = FieldName::new(text(record, &mapping.audit_fields.field_name)?)?;
        if !mapping.required_fields().contains(&field_name)
            && !mapping.change_fields.proposal_fields.contains(&field_name)
        {
            return Err(ServiceNowChangeError::SchemaDrift(
                "audit field is outside the configured mapping".into(),
            ));
        }
        let value_digest = text(record, &mapping.audit_fields.value_digest)?;
        if !is_sha256(&value_digest) {
            return Err(ServiceNowChangeError::InvalidDigest);
        }
        let provider_revision =
            ProviderRevision::new(text(record, &mapping.audit_fields.provider_revision)?)?;
        let changed_at = text(record, &mapping.audit_fields.changed_at)?;
        let evidence = evidence_for(scope, mapping, query, record);
        Ok(AuditProjection::new(
            scope.digest(),
            mapping,
            scope.instance.clone(),
            scope.domain.clone(),
            sys_id,
            change_sys_id,
            field_name,
            value_digest,
            provider_revision,
            changed_at,
            evidence,
        ))
    }
}

fn mapping_probe_fields(mapping: &SchemaMapping) -> BTreeSet<FieldName> {
    let mut fields = mapping.required_fields();
    if let Some(correlation) = &mapping.change_fields.correlation {
        fields.insert(correlation.clone());
    }
    fields.extend(mapping.change_fields.proposal_fields.iter().cloned());
    fields
}

fn acl_evidence(
    required_fields: &BTreeSet<FieldName>,
    probe: &AclProbe,
) -> (AclEvidence, Option<String>) {
    match probe {
        AclProbe::Omitted => (
            AclEvidence {
                status: AclEvidenceStatus::NotVisible,
                required_fields: required_fields.clone(),
                visible_fields: BTreeSet::new(),
                missing_fields: required_fields.clone(),
                reason: Some("ACL response omitted".into()),
            },
            required_fields.iter().next().map(|field| field.to_string()),
        ),
        AclProbe::Explicit(visible_fields) => {
            let missing_fields = required_fields
                .difference(visible_fields)
                .cloned()
                .collect::<BTreeSet<_>>();
            let error = missing_fields.iter().next().map(ToString::to_string);
            (
                AclEvidence {
                    status: if missing_fields.is_empty() {
                        AclEvidenceStatus::Visible
                    } else {
                        AclEvidenceStatus::NotVisible
                    },
                    required_fields: required_fields.clone(),
                    visible_fields: visible_fields.clone(),
                    missing_fields,
                    reason: error
                        .as_ref()
                        .map(|field| format!("ACL did not expose {field}")),
                },
                error,
            )
        }
    }
}

fn schema_evidence(
    required_fields: &BTreeSet<FieldName>,
    mapping: &SchemaMapping,
    probe: &SchemaProbe,
) -> (SchemaEvidence, Option<String>) {
    let (observed_fingerprint, observed_fields) = match (&probe.fingerprint, &probe.fields) {
        (Some(fingerprint), Some(fields)) => (Some(fingerprint.clone()), fields.clone()),
        _ => {
            return (
                SchemaEvidence {
                    status: SchemaEvidenceStatus::NotVisible,
                    expected_fingerprint: mapping.schema_fingerprint.clone(),
                    observed_fingerprint: probe.fingerprint.clone(),
                    required_fields: required_fields.clone(),
                    observed_fields: probe.fields.clone().unwrap_or_default(),
                    missing_fields: required_fields.clone(),
                    reason: Some("schema fingerprint or field list omitted".into()),
                },
                Some("schema fingerprint or field list omitted".into()),
            );
        }
    };
    let missing_fields = required_fields
        .difference(&observed_fields)
        .cloned()
        .collect::<BTreeSet<_>>();
    let fingerprint_mismatch =
        observed_fingerprint.as_deref() != Some(mapping.schema_fingerprint.as_str());
    let detail = if fingerprint_mismatch {
        Some("schema fingerprint drift".into())
    } else if !missing_fields.is_empty() {
        Some("schema field set is missing an allowlisted field".into())
    } else {
        None
    };
    (
        SchemaEvidence {
            status: if detail.is_none() {
                SchemaEvidenceStatus::Matched
            } else {
                SchemaEvidenceStatus::Drift
            },
            expected_fingerprint: mapping.schema_fingerprint.clone(),
            observed_fingerprint,
            required_fields: required_fields.clone(),
            observed_fields,
            missing_fields,
            reason: detail.clone(),
        },
        detail,
    )
}

fn text(record: &RawRecord, field: &FieldName) -> Result<String> {
    match record.value(field) {
        Some(RawFieldValue::Text(value)) if valid_non_empty(value, 512) => Ok(value.clone()),
        Some(RawFieldValue::Text(_)) | Some(RawFieldValue::Null) | None => {
            Err(ServiceNowChangeError::FieldNotVisible(field.to_string()))
        }
    }
}

fn digest_fields(record: &RawRecord, fields: &BTreeSet<FieldName>) -> Result<String> {
    let values = fields
        .iter()
        .map(|field| {
            let value = text(record, field)?;
            Ok((field.as_str(), crate::model::value_digest(value)))
        })
        .collect::<Result<Vec<_>>>()?;
    canonical_json_digest(&values)
        .map_err(|_| ServiceNowChangeError::InvalidContract("field digest".into()))
}

fn evidence_for(
    scope: &ServiceNowScope,
    mapping: &SchemaMapping,
    query: &CompiledQuery,
    record: &RawRecord,
) -> ProjectionEvidence {
    ProjectionEvidence::new(
        query.provenance,
        scope.digest(),
        mapping.mapping_digest.clone(),
        mapping.schema_fingerprint.clone(),
        query.query_digest.clone(),
        record.response_digest.clone(),
    )
}

fn digest_serializable<T: Serialize>(value: &T) -> std::result::Result<String, serde_json::Error> {
    canonical_json_digest(value)
}

fn digest_serializable_without_digest(receipt: &ProbeReceipt) -> Result<String> {
    let mut clone = receipt.clone();
    clone.evidence_digest.clear();
    digest_serializable(&clone)
        .map_err(|_| ServiceNowChangeError::InvalidContract("probe digest".into()))
}

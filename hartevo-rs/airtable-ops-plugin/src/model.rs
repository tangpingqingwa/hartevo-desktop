use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fmt::Write as _;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::AirtableError;

macro_rules! identifier_type {
    ($name:ident, $label:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, AirtableError> {
                let value = value.into();
                validate_identifier(&value, $label)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = AirtableError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }
    };
}

identifier_type!(AirtableBaseId, "Airtable base ID");
identifier_type!(AirtableTableId, "Airtable table ID");
identifier_type!(AirtableViewId, "Airtable view ID");
identifier_type!(AirtableFieldId, "Airtable field ID");
identifier_type!(AirtableRecordId, "Airtable record ID");
identifier_type!(AirtableOffset, "Airtable pagination offset");
identifier_type!(MissionId, "Mission ID");
identifier_type!(ProjectId, "Project ID");
identifier_type!(WorkProductId, "WorkProduct ID");
identifier_type!(OutcomeCandidateId, "OutcomeCandidate ID");

fn validate_identifier(value: &str, label: &str) -> Result<(), AirtableError> {
    if value.is_empty() {
        return Err(AirtableError::invalid(label, "must not be empty"));
    }
    if value.len() > 256 {
        return Err(AirtableError::invalid(label, "must be at most 256 bytes"));
    }
    if value
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(AirtableError::invalid(
            label,
            "must not contain whitespace or control characters",
        ));
    }
    Ok(())
}

/// The only scope authority accepted by the provider contract.  Names are
/// intentionally absent: a table name is display metadata, not capability.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AirtableScope {
    pub base_id: AirtableBaseId,
    pub table_id: AirtableTableId,
    pub view_id: Option<AirtableViewId>,
}

impl AirtableScope {
    pub fn new(
        base_id: AirtableBaseId,
        table_id: AirtableTableId,
        view_id: Option<AirtableViewId>,
    ) -> Self {
        Self {
            base_id,
            table_id,
            view_id,
        }
    }

    pub fn fingerprint(&self) -> String {
        digest_bytes(&serde_json::to_vec(self).expect("scope is serializable"))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AirtableProviderProvenance {
    Recording,
    Fixture,
    BlockedEnv,
    NativeHttps,
}

impl AirtableProviderProvenance {
    pub const fn is_connected(self) -> bool {
        matches!(self, Self::NativeHttps)
    }

    pub const fn is_layer_one(self) -> bool {
        !self.is_connected()
    }

    pub const fn writes_enabled(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AirtableCapability {
    DescribeSchema,
    ReadRecords,
    CompileRecordProposal,
    VerifyRecordReadback,
    Recording,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AirtableProviderManifest {
    pub id: String,
    pub version: u64,
    pub contract_digest: String,
    pub scope: AirtableScope,
    pub provenance: AirtableProviderProvenance,
    pub capabilities: BTreeSet<AirtableCapability>,
    pub max_batch_size: usize,
    pub max_page_size: usize,
    pub write_authority: bool,
    pub webhook_truth_authority: bool,
}

impl AirtableProviderManifest {
    pub fn baseline(scope: AirtableScope, provenance: AirtableProviderProvenance) -> Self {
        Self {
            id: crate::AIRTABLE_PROVIDER_ID.to_owned(),
            version: crate::AIRTABLE_PROVIDER_VERSION,
            contract_digest: crate::contract_digest(),
            scope,
            provenance,
            capabilities: [
                AirtableCapability::DescribeSchema,
                AirtableCapability::ReadRecords,
                AirtableCapability::CompileRecordProposal,
                AirtableCapability::VerifyRecordReadback,
                AirtableCapability::Recording,
            ]
            .into_iter()
            .collect(),
            max_batch_size: crate::AIRTABLE_MAX_BATCH_SIZE,
            max_page_size: crate::AIRTABLE_MAX_PAGE_SIZE,
            write_authority: false,
            webhook_truth_authority: false,
        }
    }

    pub fn validate_for(&self, scope: &AirtableScope) -> Result<(), AirtableError> {
        if self.id != crate::AIRTABLE_PROVIDER_ID {
            return Err(AirtableError::ContractDrift {
                expected: crate::AIRTABLE_PROVIDER_ID.to_owned(),
                observed: self.id.clone(),
            });
        }
        if self.version != crate::AIRTABLE_PROVIDER_VERSION {
            return Err(AirtableError::ContractDrift {
                expected: crate::AIRTABLE_PROVIDER_VERSION.to_string(),
                observed: self.version.to_string(),
            });
        }
        let expected_digest = crate::contract_digest();
        if self.contract_digest.is_empty() || self.contract_digest != expected_digest {
            return Err(AirtableError::ContractDrift {
                expected: expected_digest,
                observed: self.contract_digest.clone(),
            });
        }
        if self.scope != *scope {
            return Err(AirtableError::ScopeMismatch {
                expected: Box::new(scope.clone()),
                observed: Box::new(self.scope.clone()),
            });
        }
        if self.max_batch_size != crate::AIRTABLE_MAX_BATCH_SIZE
            || self.max_page_size > crate::AIRTABLE_MAX_PAGE_SIZE
        {
            return Err(AirtableError::ContractDrift {
                expected: format!(
                    "batch <= {}, page <= {}",
                    crate::AIRTABLE_MAX_BATCH_SIZE,
                    crate::AIRTABLE_MAX_PAGE_SIZE
                ),
                observed: format!("batch {}, page {}", self.max_batch_size, self.max_page_size),
            });
        }
        if self.write_authority || self.webhook_truth_authority {
            return Err(AirtableError::ContractDrift {
                expected: "no write or webhook truth authority".to_owned(),
                observed: "provider claims a forbidden authority".to_owned(),
            });
        }
        if !self.provenance.is_layer_one() {
            return Err(AirtableError::ContractDrift {
                expected: "recording, fixture, or blocked_env provenance".to_owned(),
                observed: "native_https".to_owned(),
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> &str {
        &self.contract_digest
    }
}

/// A bearer/PAT reference is an opaque credential locator, never the token
/// itself.  It is accepted only at the provider boundary and is absent from
/// proposals, receipts, and provider request logs.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "kind", deny_unknown_fields)]
pub enum SecretReference {
    BearerPat { reference: String },
}

impl SecretReference {
    pub fn bearer_pat(reference: impl Into<String>) -> Result<Self, AirtableError> {
        let reference = reference.into();
        validate_identifier(&reference, "Bearer/PAT secret reference")?;
        Ok(Self::BearerPat { reference })
    }

    pub fn from_environment(variable: impl Into<String>) -> Result<Self, AirtableError> {
        let variable = variable.into();
        validate_identifier(&variable, "Bearer/PAT environment reference")?;
        Ok(Self::BearerPat {
            reference: variable,
        })
    }

    pub(crate) fn digest(&self) -> String {
        match self {
            Self::BearerPat { reference } => digest_bytes(reference.as_bytes()),
        }
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("kind", &"bearer_pat")
            .field("reference", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AirtableFieldType {
    SingleLineText,
    MultilineText,
    Number,
    Checkbox,
    DateTime,
    Url,
    Email,
    SingleSelect,
    MultipleSelect,
    Unknown,
}

impl AirtableFieldType {
    pub const fn accepts(self, value: &RecordValue) -> bool {
        matches!(
            (self, value),
            (
                Self::SingleLineText
                    | Self::MultilineText
                    | Self::SingleSelect
                    | Self::MultipleSelect,
                RecordValue::Text(_)
            ) | (Self::Number, RecordValue::Integer(_))
                | (Self::Checkbox, RecordValue::Boolean(_))
                | (Self::DateTime, RecordValue::DateTime(_))
                | (Self::Url, RecordValue::Url(_))
                | (Self::Email, RecordValue::Email(_))
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AirtableFieldDefinition {
    pub id: AirtableFieldId,
    pub name: String,
    pub field_type: AirtableFieldType,
    pub writable: bool,
}

impl AirtableFieldDefinition {
    pub fn new(
        id: AirtableFieldId,
        name: impl Into<String>,
        field_type: AirtableFieldType,
        writable: bool,
    ) -> Result<Self, AirtableError> {
        let name = name.into();
        if name.trim().is_empty() {
            return Err(AirtableError::invalid(
                "Airtable field name",
                "must not be empty",
            ));
        }
        Ok(Self {
            id,
            name,
            field_type,
            writable,
        })
    }

    pub fn read_only(
        id: AirtableFieldId,
        name: impl Into<String>,
        field_type: AirtableFieldType,
    ) -> Result<Self, AirtableError> {
        Self::new(id, name, field_type, false)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AirtableTableSchema {
    pub scope: AirtableScope,
    pub revision: String,
    pub fields: Vec<AirtableFieldDefinition>,
    pub schema_fingerprint: String,
    pub field_fingerprint: String,
}

impl AirtableTableSchema {
    pub fn new(
        scope: AirtableScope,
        revision: impl Into<String>,
        mut fields: Vec<AirtableFieldDefinition>,
    ) -> Result<Self, AirtableError> {
        let revision = revision.into();
        validate_identifier(&revision, "Airtable schema revision")?;
        fields.sort_by(|left, right| left.id.cmp(&right.id));
        if fields.windows(2).any(|window| window[0].id == window[1].id) {
            return Err(AirtableError::invalid(
                "Airtable schema fields",
                "field IDs must be unique",
            ));
        }
        let field_fingerprint = compute_field_fingerprint(&fields);
        let schema_fingerprint = compute_schema_fingerprint(&scope, &revision, &fields);
        Ok(Self {
            scope,
            revision,
            fields,
            schema_fingerprint,
            field_fingerprint,
        })
    }

    pub fn validate(&self) -> Result<(), AirtableError> {
        let expected_fields = compute_field_fingerprint(&self.fields);
        if self.field_fingerprint != expected_fields {
            return Err(AirtableError::SchemaDrift {
                expected: expected_fields,
                observed: self.field_fingerprint.clone(),
            });
        }
        let expected_schema = compute_schema_fingerprint(&self.scope, &self.revision, &self.fields);
        if self.schema_fingerprint != expected_schema {
            return Err(AirtableError::SchemaDrift {
                expected: expected_schema,
                observed: self.schema_fingerprint.clone(),
            });
        }
        if self
            .fields
            .windows(2)
            .any(|window| window[0].id >= window[1].id)
        {
            return Err(AirtableError::SchemaDrift {
                expected: "fields sorted by unique field ID".to_owned(),
                observed: "duplicate or unsorted field IDs".to_owned(),
            });
        }
        Ok(())
    }

    pub fn field(&self, id: &AirtableFieldId) -> Option<&AirtableFieldDefinition> {
        self.fields.iter().find(|field| &field.id == id)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AirtableSchemaDescription {
    pub schema: AirtableTableSchema,
    pub provider_manifest_digest: String,
    pub provenance: AirtableProviderProvenance,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AirtableFieldBinding {
    pub stable_field: StableRecordField,
    pub field_id: AirtableFieldId,
    pub field_name: String,
    pub field_type: AirtableFieldType,
}

impl AirtableFieldBinding {
    pub fn new(
        stable_field: StableRecordField,
        field_id: AirtableFieldId,
        field_name: impl Into<String>,
        field_type: AirtableFieldType,
    ) -> Result<Self, AirtableError> {
        let field_name = field_name.into();
        if field_name.trim().is_empty() {
            return Err(AirtableError::invalid(
                "field allowlist name",
                "must not be empty",
            ));
        }
        Ok(Self {
            stable_field,
            field_id,
            field_name,
            field_type,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AirtableFieldAllowlist {
    pub bindings: BTreeMap<StableRecordField, AirtableFieldBinding>,
}

impl AirtableFieldAllowlist {
    pub fn new(
        bindings: impl IntoIterator<Item = AirtableFieldBinding>,
    ) -> Result<Self, AirtableError> {
        let mut map = BTreeMap::new();
        let mut ids = BTreeSet::new();
        for binding in bindings {
            if map.insert(binding.stable_field, binding.clone()).is_some() {
                return Err(AirtableError::FieldAllowlist {
                    field: binding.stable_field.key().to_owned(),
                    reason: "stable field is listed more than once".to_owned(),
                });
            }
            if !ids.insert(binding.field_id.clone()) {
                return Err(AirtableError::FieldAllowlist {
                    field: binding.field_id.to_string(),
                    reason: "one Airtable field cannot receive two stable fields".to_owned(),
                });
            }
        }
        if map.is_empty() {
            return Err(AirtableError::FieldAllowlist {
                field: "<empty>".to_owned(),
                reason: "at least one explicit field binding is required".to_owned(),
            });
        }
        Ok(Self { bindings: map })
    }

    pub fn standard_for_schema(schema: &AirtableTableSchema) -> Result<Self, AirtableError> {
        let candidates = [
            (StableRecordField::MissionId, "Mission ID"),
            (StableRecordField::ProjectId, "Project ID"),
            (StableRecordField::WorkProductId, "WorkProduct ID"),
            (StableRecordField::OutcomeCandidateId, "OutcomeCandidate ID"),
            (StableRecordField::OutputKind, "Output Kind"),
            (StableRecordField::Revision, "Revision"),
            (StableRecordField::Title, "Title"),
            (StableRecordField::Summary, "Summary"),
            (StableRecordField::ContentFingerprint, "Content Fingerprint"),
            (StableRecordField::IdempotencyKey, "Idempotency Key"),
        ];
        let bindings = candidates.into_iter().filter_map(|(stable_field, name)| {
            schema
                .fields
                .iter()
                .find(|field| field.name == name)
                .map(|field| AirtableFieldBinding {
                    stable_field,
                    field_id: field.id.clone(),
                    field_name: field.name.clone(),
                    field_type: field.field_type,
                })
        });
        Self::new(bindings)
    }

    pub fn validate(&self, schema: &AirtableTableSchema) -> Result<(), AirtableError> {
        schema.validate()?;
        let mut names = BTreeSet::new();
        for (stable_field, binding) in &self.bindings {
            if *stable_field != binding.stable_field {
                return Err(AirtableError::FieldAllowlist {
                    field: stable_field.key().to_owned(),
                    reason: "binding key does not match stable field".to_owned(),
                });
            }
            let Some(schema_field) = schema.field(&binding.field_id) else {
                return Err(AirtableError::FieldAllowlist {
                    field: binding.field_id.to_string(),
                    reason: "field ID is absent from the current schema".to_owned(),
                });
            };
            if schema_field.name != binding.field_name {
                return Err(AirtableError::FieldAllowlist {
                    field: binding.field_id.to_string(),
                    reason: "field name changed since the allowlist was approved".to_owned(),
                });
            }
            if schema_field.field_type != binding.field_type {
                return Err(AirtableError::FieldAllowlist {
                    field: binding.field_id.to_string(),
                    reason: "field type changed since the allowlist was approved".to_owned(),
                });
            }
            if !schema_field.writable {
                return Err(AirtableError::FieldAllowlist {
                    field: binding.field_id.to_string(),
                    reason: "field is not writable".to_owned(),
                });
            }
            if !names.insert(binding.field_name.clone()) {
                return Err(AirtableError::FieldAllowlist {
                    field: binding.field_name.clone(),
                    reason: "field names must be unique in the allowlist".to_owned(),
                });
            }
        }
        Ok(())
    }

    pub fn field_fingerprint(&self) -> String {
        let entries = self
            .bindings
            .iter()
            .map(|(stable_field, binding)| {
                (
                    stable_field.key(),
                    binding.field_id.as_str(),
                    binding.field_name.as_str(),
                    binding.field_type,
                )
            })
            .collect::<Vec<_>>();
        digest_bytes(&serde_json::to_vec(&entries).expect("field allowlist is serializable"))
    }

    pub fn contains(&self, field: StableRecordField) -> bool {
        self.bindings.contains_key(&field)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StableRecordField {
    MissionId,
    ProjectId,
    WorkProductId,
    OutcomeCandidateId,
    OutputKind,
    Revision,
    Title,
    Summary,
    ContentFingerprint,
    IdempotencyKey,
}

impl StableRecordField {
    pub const fn key(self) -> &'static str {
        match self {
            Self::MissionId => "mission_id",
            Self::ProjectId => "project_id",
            Self::WorkProductId => "work_product_id",
            Self::OutcomeCandidateId => "outcome_candidate_id",
            Self::OutputKind => "output_kind",
            Self::Revision => "revision",
            Self::Title => "title",
            Self::Summary => "summary",
            Self::ContentFingerprint => "content_fingerprint",
            Self::IdempotencyKey => "idempotency_key",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionOutputKind {
    WorkProduct,
    OutcomeCandidate,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProduct {
    pub mission_id: MissionId,
    pub project_id: ProjectId,
    pub work_product_id: WorkProductId,
    pub revision: u64,
    pub title: String,
    pub summary: String,
    pub content: String,
}

impl WorkProduct {
    pub fn new(
        mission_id: MissionId,
        project_id: ProjectId,
        work_product_id: WorkProductId,
        revision: u64,
        title: impl Into<String>,
        summary: impl Into<String>,
        content: impl Into<String>,
    ) -> Result<Self, AirtableError> {
        let product = Self {
            mission_id,
            project_id,
            work_product_id,
            revision,
            title: title.into(),
            summary: summary.into(),
            content: content.into(),
        };
        product.validate()?;
        Ok(product)
    }

    fn validate(&self) -> Result<(), AirtableError> {
        validate_text(&self.title, "WorkProduct title", 512)?;
        validate_text(&self.summary, "WorkProduct summary", 8_192)?;
        validate_text(&self.content, "WorkProduct content", 1_048_576)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutcomeCandidate {
    pub mission_id: MissionId,
    pub project_id: ProjectId,
    pub candidate_id: OutcomeCandidateId,
    pub revision: u64,
    pub title: String,
    pub summary: String,
    pub content: String,
}

impl OutcomeCandidate {
    pub fn new(
        mission_id: MissionId,
        project_id: ProjectId,
        candidate_id: OutcomeCandidateId,
        revision: u64,
        title: impl Into<String>,
        summary: impl Into<String>,
        content: impl Into<String>,
    ) -> Result<Self, AirtableError> {
        let candidate = Self {
            mission_id,
            project_id,
            candidate_id,
            revision,
            title: title.into(),
            summary: summary.into(),
            content: content.into(),
        };
        candidate.validate()?;
        Ok(candidate)
    }

    fn validate(&self) -> Result<(), AirtableError> {
        validate_text(&self.title, "OutcomeCandidate title", 512)?;
        validate_text(&self.summary, "OutcomeCandidate summary", 8_192)?;
        validate_text(&self.content, "OutcomeCandidate content", 1_048_576)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionOutput {
    WorkProduct(WorkProduct),
    OutcomeCandidate(OutcomeCandidate),
}

impl MissionOutput {
    pub const fn kind(&self) -> MissionOutputKind {
        match self {
            Self::WorkProduct(_) => MissionOutputKind::WorkProduct,
            Self::OutcomeCandidate(_) => MissionOutputKind::OutcomeCandidate,
        }
    }

    pub fn mission_id(&self) -> &MissionId {
        match self {
            Self::WorkProduct(product) => &product.mission_id,
            Self::OutcomeCandidate(candidate) => &candidate.mission_id,
        }
    }

    pub fn project_id(&self) -> &ProjectId {
        match self {
            Self::WorkProduct(product) => &product.project_id,
            Self::OutcomeCandidate(candidate) => &candidate.project_id,
        }
    }

    pub fn output_id(&self) -> String {
        match self {
            Self::WorkProduct(product) => product.work_product_id.to_string(),
            Self::OutcomeCandidate(candidate) => candidate.candidate_id.to_string(),
        }
    }

    pub const fn revision(&self) -> u64 {
        match self {
            Self::WorkProduct(product) => product.revision,
            Self::OutcomeCandidate(candidate) => candidate.revision,
        }
    }

    pub fn title(&self) -> &str {
        match self {
            Self::WorkProduct(product) => &product.title,
            Self::OutcomeCandidate(candidate) => &candidate.title,
        }
    }

    pub fn summary(&self) -> &str {
        match self {
            Self::WorkProduct(product) => &product.summary,
            Self::OutcomeCandidate(candidate) => &candidate.summary,
        }
    }

    pub fn content(&self) -> &str {
        match self {
            Self::WorkProduct(product) => &product.content,
            Self::OutcomeCandidate(candidate) => &candidate.content,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum RecordValue {
    Text(String),
    Integer(i64),
    Boolean(bool),
    DateTime(String),
    Url(String),
    Email(String),
}

impl RecordValue {
    pub fn stable_string(&self) -> String {
        match self {
            Self::Text(value) | Self::DateTime(value) | Self::Url(value) | Self::Email(value) => {
                value.clone()
            }
            Self::Integer(value) => value.to_string(),
            Self::Boolean(value) => value.to_string(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionRecordProposalRequest {
    pub scope: AirtableScope,
    pub schema: AirtableTableSchema,
    pub field_allowlist: AirtableFieldAllowlist,
    pub output: MissionOutput,
}

impl MissionRecordProposalRequest {
    pub fn new(
        scope: AirtableScope,
        schema: AirtableTableSchema,
        field_allowlist: AirtableFieldAllowlist,
        output: MissionOutput,
    ) -> Result<Self, AirtableError> {
        if schema.scope != scope {
            return Err(AirtableError::ScopeMismatch {
                expected: Box::new(scope),
                observed: Box::new(schema.scope),
            });
        }
        Ok(Self {
            scope,
            schema,
            field_allowlist,
            output,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProposedField {
    pub stable_field: StableRecordField,
    pub field_id: AirtableFieldId,
    pub field_name: String,
    pub field_type: AirtableFieldType,
    pub value: RecordValue,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordProposal {
    pub scope: AirtableScope,
    pub mission_id: MissionId,
    pub project_id: ProjectId,
    pub output_kind: MissionOutputKind,
    pub output_id: String,
    pub revision: u64,
    pub manifest_digest: String,
    pub schema_fingerprint: String,
    pub field_fingerprint: String,
    pub content_fingerprint: String,
    pub idempotency_key: String,
    pub fields: Vec<ProposedField>,
    pub provenance: AirtableProviderProvenance,
}

impl RecordProposal {
    pub fn field_ids(&self) -> BTreeSet<AirtableFieldId> {
        self.fields
            .iter()
            .map(|field| field.field_id.clone())
            .collect()
    }

    pub fn field_names(&self) -> BTreeSet<String> {
        self.fields
            .iter()
            .map(|field| field.field_name.clone())
            .collect()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialOrd, Ord, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    Recording,
    Fixture,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordReceipt {
    pub record_id: AirtableRecordId,
    pub scope: AirtableScope,
    pub field_fingerprint: String,
    pub revision: u64,
    pub content_digest: String,
    pub idempotency_key: String,
    pub manifest_digest: String,
    pub provider_version: u64,
    pub provenance: AirtableProviderProvenance,
    pub kind: ReceiptKind,
    pub write_executed: bool,
}

impl RecordReceipt {
    pub fn from_proposal(
        proposal: &RecordProposal,
        record_id: AirtableRecordId,
        provenance: AirtableProviderProvenance,
        kind: ReceiptKind,
    ) -> Result<Self, AirtableError> {
        if provenance.is_connected() {
            return Err(AirtableError::ContractDrift {
                expected: "Layer 1 non-native receipt provenance".to_owned(),
                observed: "native_https".to_owned(),
            });
        }
        Ok(Self {
            record_id,
            scope: proposal.scope.clone(),
            field_fingerprint: proposal.field_fingerprint.clone(),
            revision: proposal.revision,
            content_digest: proposal.content_fingerprint.clone(),
            idempotency_key: proposal.idempotency_key.clone(),
            manifest_digest: proposal.manifest_digest.clone(),
            provider_version: crate::AIRTABLE_PROVIDER_VERSION,
            provenance,
            kind,
            write_executed: false,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordReadback {
    pub record_id: AirtableRecordId,
    pub scope: AirtableScope,
    pub field_fingerprint: String,
    pub revision: u64,
    pub content_digest: String,
    pub provider_revision: String,
    pub fields: BTreeMap<AirtableFieldId, RecordValue>,
    pub provenance: AirtableProviderProvenance,
}

impl RecordReadback {
    pub fn from_receipt(receipt: &RecordReceipt) -> Self {
        Self {
            record_id: receipt.record_id.clone(),
            scope: receipt.scope.clone(),
            field_fingerprint: receipt.field_fingerprint.clone(),
            revision: receipt.revision,
            content_digest: receipt.content_digest.clone(),
            provider_revision: receipt.revision.to_string(),
            fields: BTreeMap::new(),
            provenance: receipt.provenance,
        }
    }
}

/// A read-back receipt contains only stable identity and digest evidence; it
/// deliberately excludes record field values and all credential references.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadbackReceipt {
    pub record_id: AirtableRecordId,
    pub scope: AirtableScope,
    pub field_fingerprint: String,
    pub revision: u64,
    pub content_digest: String,
    pub manifest_digest: String,
    pub verified: bool,
    pub provenance: AirtableProviderProvenance,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AirtableRecordSnapshot {
    pub record_id: AirtableRecordId,
    pub scope: AirtableScope,
    pub field_fingerprint: String,
    pub revision: u64,
    pub content_digest: String,
    pub fields: BTreeMap<AirtableFieldId, RecordValue>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListRecordsRequest {
    pub page_size: usize,
    pub offset: Option<AirtableOffset>,
}

impl ListRecordsRequest {
    pub fn new(page_size: usize) -> Result<Self, AirtableError> {
        if !(1..=crate::AIRTABLE_MAX_PAGE_SIZE).contains(&page_size) {
            return Err(AirtableError::invalid(
                "Airtable page size",
                format!("must be between 1 and {}", crate::AIRTABLE_MAX_PAGE_SIZE),
            ));
        }
        Ok(Self {
            page_size,
            offset: None,
        })
    }

    #[must_use]
    pub fn with_offset(mut self, offset: AirtableOffset) -> Self {
        self.offset = Some(offset);
        self
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AirtableRecordPage {
    pub records: Vec<AirtableRecordSnapshot>,
    pub next_offset: Option<AirtableOffset>,
}

impl AirtableRecordPage {
    pub fn new(
        records: Vec<AirtableRecordSnapshot>,
        next_offset: Option<AirtableOffset>,
    ) -> Result<Self, AirtableError> {
        if records.len() > crate::AIRTABLE_MAX_PAGE_SIZE {
            return Err(AirtableError::Pagination {
                reason: format!(
                    "provider returned {} records in one page; maximum is {}",
                    records.len(),
                    crate::AIRTABLE_MAX_PAGE_SIZE
                ),
            });
        }
        Ok(Self {
            records,
            next_offset,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PaginationReceipt {
    pub pages: usize,
    pub records: usize,
    pub offsets: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AirtableReadRecordsResult {
    pub scope: AirtableScope,
    pub records: Vec<AirtableRecordSnapshot>,
    pub pagination: PaginationReceipt,
    pub provenance: AirtableProviderProvenance,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AirtableRecordBatch {
    proposals: Vec<RecordProposal>,
}

impl AirtableRecordBatch {
    pub const MAX_RECORDS: usize = crate::AIRTABLE_MAX_BATCH_SIZE;

    pub fn new(proposals: Vec<RecordProposal>) -> Result<Self, AirtableError> {
        if proposals.len() > Self::MAX_RECORDS {
            return Err(AirtableError::BatchBoundary {
                count: proposals.len(),
                maximum: Self::MAX_RECORDS,
            });
        }
        Ok(Self { proposals })
    }

    pub fn proposals(&self) -> &[RecordProposal] {
        &self.proposals
    }

    pub fn partition(proposals: Vec<RecordProposal>) -> Vec<Self> {
        let mut batches = Vec::new();
        for proposal in proposals {
            if batches
                .last()
                .is_none_or(|batch: &Self| batch.proposals.len() == Self::MAX_RECORDS)
            {
                batches.push(Self {
                    proposals: Vec::with_capacity(Self::MAX_RECORDS),
                });
            }
            batches
                .last_mut()
                .expect("a batch is created before inserting a proposal")
                .proposals
                .push(proposal);
        }
        batches
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AirtableChangeSignal {
    pub scope: AirtableScope,
    pub record_id: Option<AirtableRecordId>,
    pub changed_at: String,
    pub delivery_id: String,
}

impl AirtableChangeSignal {
    pub const fn is_truth(&self) -> bool {
        false
    }

    pub const fn requires_readback(&self) -> bool {
        true
    }
}

fn validate_text(value: &str, field: &str, maximum: usize) -> Result<(), AirtableError> {
    if value.trim().is_empty() {
        return Err(AirtableError::invalid(field, "must not be empty"));
    }
    if value.len() > maximum {
        return Err(AirtableError::invalid(
            field,
            format!("must be at most {maximum} bytes"),
        ));
    }
    Ok(())
}

fn compute_field_fingerprint(fields: &[AirtableFieldDefinition]) -> String {
    let entries = fields
        .iter()
        .map(|field| (&field.id, &field.name, field.field_type, field.writable))
        .collect::<Vec<_>>();
    digest_bytes(&serde_json::to_vec(&entries).expect("schema fields are serializable"))
}

fn compute_schema_fingerprint(
    scope: &AirtableScope,
    revision: &str,
    fields: &[AirtableFieldDefinition],
) -> String {
    let value = (scope, revision, fields);
    digest_bytes(&serde_json::to_vec(&value).expect("schema is serializable"))
}

pub(crate) fn digest_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

pub(crate) fn content_fingerprint(output: &MissionOutput) -> String {
    digest_bytes(
        format!(
            "kind={:?}\nmission={}\nproject={}\noutput={}\nrevision={}\ntitle={}\nsummary={}\ncontent={}",
            output.kind(),
            output.mission_id(),
            output.project_id(),
            output.output_id(),
            output.revision(),
            output.title(),
            output.summary(),
            output.content()
        )
        .as_bytes(),
    )
}

pub(crate) fn idempotency_key(
    scope: &AirtableScope,
    output: &MissionOutput,
    content_digest: &str,
    manifest_digest: &str,
    field_fingerprint: &str,
) -> String {
    let mut input = String::new();
    let _ = write!(
        input,
        "scope={}\nkind={:?}\nmission={}\nproject={}\noutput={}\nrevision={}\ncontent={}\nmanifest={}\nfields={}",
        scope.fingerprint(),
        output.kind(),
        output.mission_id(),
        output.project_id(),
        output.output_id(),
        output.revision(),
        content_digest,
        manifest_digest,
        field_fingerprint,
    );
    format!("airtable-idem-{}", digest_bytes(input.as_bytes()))
}

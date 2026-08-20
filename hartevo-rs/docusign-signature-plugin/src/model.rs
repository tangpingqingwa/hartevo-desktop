use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Duration, Utc};
use hartevo_connector_sdk::{ConnectorScope, SecretReference};
use hartevo_domain_kernel::{MissionId, ProjectId, TenantId};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use crate::digest::Digest;

pub const DOCUSIGN_NATIVE_OPT_IN_ENV: &str = "HARTEVO_DOCUSIGN_NATIVE_LAYER2";
pub const DOCUSIGN_PROVIDER_ID: &str = "docusign.signature.native";

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ModelError {
    #[error("invalid {0} identifier")]
    InvalidIdentifier(&'static str),
    #[error("DocuSign base URI must be an HTTPS origin without credentials, query, or fragment")]
    InvalidBaseUri,
    #[error("revision values must be positive")]
    InvalidRevision,
    #[error("provider version must have a positive major version")]
    InvalidProviderVersion,
    #[error("routing plan must contain contiguous positive routing orders")]
    InvalidRouting,
    #[error("routing plan recipient set does not match the proposal recipient set")]
    RoutingRecipientMismatch,
    #[error("recipient set contains a duplicate")]
    DuplicateRecipient,
    #[error("recipient set cannot be empty")]
    EmptyRecipientSet,
    #[error("document set cannot be empty")]
    EmptyDocumentSet,
    #[error("proposal expiry must be after creation and within thirty days")]
    InvalidExpiry,
    #[error("source digest is invalid")]
    InvalidSourceDigest,
    #[error("DocuSign scope cannot be represented as a ConnectorScope: {0}")]
    InvalidConnectorScope(String),
    #[error("recorded observation is invalid")]
    InvalidObservation,
    #[error("receipt integrity is invalid")]
    InvalidReceipt,
}

macro_rules! opaque_id {
    ($name:ident, $kind:literal) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                if value.trim().is_empty()
                    || value.len() > 128
                    || value.chars().any(char::is_control)
                {
                    return Err(ModelError::InvalidIdentifier($kind));
                }
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
                    .field("value_digest", &Digest::from_text(&self.0))
                    .finish()
            }
        }
    };
}

opaque_id!(DocuSignAccountId, "account");
opaque_id!(EnvelopeId, "envelope");
opaque_id!(RecipientId, "recipient");
opaque_id!(TemplateId, "template");
opaque_id!(DocumentId, "document");

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct BaseUri(String);

impl<'de> Deserialize<'de> for BaseUri {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

impl BaseUri {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        let parsed = Url::parse(&value).map_err(|_| ModelError::InvalidBaseUri)?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || value.trim() != value
        {
            return Err(ModelError::InvalidBaseUri);
        }
        Ok(Self(value.trim_end_matches('/').to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocuSignScope {
    tenant_id: TenantId,
    project_id: ProjectId,
    mission_id: MissionId,
    account_id: DocuSignAccountId,
    base_uri: BaseUri,
}

impl DocuSignScope {
    pub fn new(
        tenant_id: TenantId,
        project_id: ProjectId,
        mission_id: MissionId,
        account_id: DocuSignAccountId,
        base_uri: BaseUri,
    ) -> Result<Self, ModelError> {
        let scope = Self {
            tenant_id,
            project_id,
            mission_id,
            account_id,
            base_uri,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub fn account_id(&self) -> &DocuSignAccountId {
        &self.account_id
    }

    pub fn base_uri(&self) -> &BaseUri {
        &self.base_uri
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts([
            self.tenant_id.as_str(),
            self.project_id.as_str(),
            self.mission_id.as_str(),
            self.account_id.as_str(),
            self.base_uri.as_str(),
        ])
    }

    pub fn connector_scope(&self) -> Result<ConnectorScope, ModelError> {
        ConnectorScope::new(
            self.tenant_id.as_str(),
            self.project_id.as_str(),
            DOCUSIGN_PROVIDER_ID,
            self.account_id.as_str(),
            ["signature.read".to_owned(), "signature.proposal".to_owned()],
        )
        .map_err(|error| ModelError::InvalidConnectorScope(error.to_string()))
    }

    pub(crate) fn validate(&self) -> Result<(), ModelError> {
        if self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.mission_id.as_str().trim().is_empty()
            || self.account_id.as_str().trim().is_empty()
        {
            return Err(ModelError::InvalidIdentifier("scope"));
        }
        Ok(())
    }

    pub fn matches_secret(&self, secret: &SecretReference) -> bool {
        let connector_scope = secret.scope();
        connector_scope.tenant_id() == self.tenant_id.as_str()
            && connector_scope.project_id() == self.project_id.as_str()
            && connector_scope.provider_id() == DOCUSIGN_PROVIDER_ID
            && connector_scope.account_id() == self.account_id.as_str()
    }
}

impl fmt::Debug for DocuSignScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DocuSignScope")
            .field("scope_digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderVersion {
    major: u16,
    minor: u16,
    patch: u16,
}

impl ProviderVersion {
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    pub fn validate(self) -> Result<(), ModelError> {
        if self.major == 0 {
            Err(ModelError::InvalidProviderVersion)
        } else {
            Ok(())
        }
    }

    pub const fn major(self) -> u16 {
        self.major
    }

    pub const fn minor(self) -> u16 {
        self.minor
    }

    pub const fn patch(self) -> u16 {
        self.patch
    }

    pub fn as_string(self) -> String {
        format!("{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
pub struct RevisionFence {
    project_revision: u64,
    mission_revision: u64,
    source_revision: u64,
}

impl RevisionFence {
    pub fn new(
        project_revision: u64,
        mission_revision: u64,
        source_revision: u64,
    ) -> Result<Self, ModelError> {
        if project_revision == 0 || mission_revision == 0 || source_revision == 0 {
            return Err(ModelError::InvalidRevision);
        }
        Ok(Self {
            project_revision,
            mission_revision,
            source_revision,
        })
    }

    pub const fn project_revision(self) -> u64 {
        self.project_revision
    }

    pub const fn mission_revision(self) -> u64 {
        self.mission_revision
    }

    pub const fn source_revision(self) -> u64 {
        self.source_revision
    }

    pub fn validate(self) -> Result<(), ModelError> {
        if self.project_revision == 0 || self.mission_revision == 0 || self.source_revision == 0 {
            Err(ModelError::InvalidRevision)
        } else {
            Ok(())
        }
    }

    pub fn digest(self) -> Digest {
        Digest::from_parts([
            self.project_revision.to_string(),
            self.mission_revision.to_string(),
            self.source_revision.to_string(),
        ])
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct RoutingOrder(u32);

impl RoutingOrder {
    pub fn new(value: u32) -> Result<Self, ModelError> {
        if value == 0 {
            Err(ModelError::InvalidRouting)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn value(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecipientRole {
    Signer,
    Approver,
    Witness,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecipientSpec {
    recipient_id: RecipientId,
    role: RecipientRole,
    email_digest: Digest,
    name_digest: Digest,
    routing_order: RoutingOrder,
}

impl RecipientSpec {
    pub fn new(
        recipient_id: RecipientId,
        role: RecipientRole,
        email_digest: Digest,
        name_digest: Digest,
        routing_order: RoutingOrder,
    ) -> Self {
        Self {
            recipient_id,
            role,
            email_digest,
            name_digest,
            routing_order,
        }
    }

    pub fn recipient_id(&self) -> &RecipientId {
        &self.recipient_id
    }

    pub const fn role(&self) -> RecipientRole {
        self.role
    }

    pub fn email_digest(&self) -> &Digest {
        &self.email_digest
    }

    pub fn name_digest(&self) -> &Digest {
        &self.name_digest
    }

    pub const fn routing_order(&self) -> RoutingOrder {
        self.routing_order
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RoutingStep {
    order: RoutingOrder,
    recipient_ids: Vec<RecipientId>,
}

impl RoutingStep {
    pub fn new(
        order: RoutingOrder,
        recipient_ids: impl IntoIterator<Item = RecipientId>,
    ) -> Result<Self, ModelError> {
        let recipient_ids = recipient_ids.into_iter().collect::<Vec<_>>();
        if recipient_ids.is_empty() {
            return Err(ModelError::EmptyRecipientSet);
        }
        let mut seen = BTreeSet::new();
        if recipient_ids.iter().any(|id| !seen.insert(id)) {
            return Err(ModelError::DuplicateRecipient);
        }
        Ok(Self {
            order,
            recipient_ids,
        })
    }

    pub const fn order(&self) -> RoutingOrder {
        self.order
    }

    pub fn recipient_ids(&self) -> &[RecipientId] {
        &self.recipient_ids
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RoutingPlan {
    steps: Vec<RoutingStep>,
}

impl RoutingPlan {
    pub fn new(steps: impl IntoIterator<Item = RoutingStep>) -> Result<Self, ModelError> {
        let steps = steps.into_iter().collect::<Vec<_>>();
        if steps.is_empty()
            || steps.iter().enumerate().any(|(index, step)| {
                step.order.value() != u32::try_from(index + 1).unwrap_or(u32::MAX)
            })
        {
            return Err(ModelError::InvalidRouting);
        }
        let plan = Self { steps };
        plan.validate_unique_recipients()?;
        Ok(plan)
    }

    pub fn steps(&self) -> &[RoutingStep] {
        &self.steps
    }

    pub fn recipient_ids(&self) -> impl Iterator<Item = &RecipientId> {
        self.steps.iter().flat_map(|step| step.recipient_ids.iter())
    }

    fn validate(&self) -> Result<(), ModelError> {
        if self.steps.is_empty()
            || self.steps.iter().enumerate().any(|(index, step)| {
                step.order.value() != u32::try_from(index + 1).unwrap_or(u32::MAX)
            })
        {
            return Err(ModelError::InvalidRouting);
        }
        self.validate_unique_recipients()
    }

    fn validate_unique_recipients(&self) -> Result<(), ModelError> {
        let mut seen = BTreeSet::new();
        if self
            .recipient_ids()
            .any(|recipient_id| !seen.insert(recipient_id))
        {
            Err(ModelError::DuplicateRecipient)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TemplateReference {
    template_id: TemplateId,
    template_digest: Digest,
}

impl TemplateReference {
    pub fn new(template_id: TemplateId, template_digest: Digest) -> Self {
        Self {
            template_id,
            template_digest,
        }
    }

    pub fn template_id(&self) -> &TemplateId {
        &self.template_id
    }

    pub fn template_digest(&self) -> &Digest {
        &self.template_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocumentReference {
    document_id: DocumentId,
    file_digest: Digest,
    content_type: DocumentContentType,
}

impl DocumentReference {
    pub fn new(
        document_id: DocumentId,
        file_digest: Digest,
        content_type: DocumentContentType,
    ) -> Self {
        Self {
            document_id,
            file_digest,
            content_type,
        }
    }

    pub fn document_id(&self) -> &DocumentId {
        &self.document_id
    }

    pub fn file_digest(&self) -> &Digest {
        &self.file_digest
    }

    pub const fn content_type(&self) -> DocumentContentType {
        self.content_type
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentContentType {
    Pdf,
    Docx,
    Other,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum EnvelopeContent {
    Template(TemplateReference),
    Documents(Vec<DocumentReference>),
}

impl EnvelopeContent {
    fn validate(&self) -> Result<(), ModelError> {
        match self {
            Self::Template(template) => {
                if template.template_id.as_str().trim().is_empty()
                    || !template.template_digest.is_valid()
                {
                    Err(ModelError::InvalidSourceDigest)
                } else {
                    Ok(())
                }
            }
            Self::Documents(documents) => {
                if documents.is_empty() {
                    return Err(ModelError::EmptyDocumentSet);
                }
                if documents.iter().any(|document| {
                    document.document_id.as_str().trim().is_empty()
                        || !document.file_digest.is_valid()
                }) {
                    Err(ModelError::InvalidSourceDigest)
                } else {
                    Ok(())
                }
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnvelopeProposalRequest {
    scope: DocuSignScope,
    revision_fence: RevisionFence,
    source_result_digest: Digest,
    source_file_digest: Digest,
    content: EnvelopeContent,
    recipients: Vec<RecipientSpec>,
    routing: RoutingPlan,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl EnvelopeProposalRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: DocuSignScope,
        revision_fence: RevisionFence,
        source_result_digest: Digest,
        source_file_digest: Digest,
        content: EnvelopeContent,
        recipients: impl IntoIterator<Item = RecipientSpec>,
        routing: RoutingPlan,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        let recipients = recipients.into_iter().collect::<Vec<_>>();
        let request = Self {
            scope,
            revision_fence,
            source_result_digest,
            source_file_digest,
            content,
            recipients,
            routing,
            created_at,
            expires_at,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn scope(&self) -> &DocuSignScope {
        &self.scope
    }

    pub const fn revision_fence(&self) -> RevisionFence {
        self.revision_fence
    }

    pub fn source_result_digest(&self) -> &Digest {
        &self.source_result_digest
    }

    pub fn source_file_digest(&self) -> &Digest {
        &self.source_file_digest
    }

    pub fn content(&self) -> &EnvelopeContent {
        &self.content
    }

    pub fn recipients(&self) -> &[RecipientSpec] {
        &self.recipients
    }

    pub fn routing(&self) -> &RoutingPlan {
        &self.routing
    }

    pub const fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    pub const fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    fn validate(&self) -> Result<(), ModelError> {
        self.scope.validate()?;
        self.revision_fence.validate()?;
        self.content.validate()?;
        self.routing.validate()?;
        if self.recipients.is_empty() {
            return Err(ModelError::EmptyRecipientSet);
        }
        let mut ids = BTreeSet::new();
        if self
            .recipients
            .iter()
            .any(|recipient| !ids.insert(recipient.recipient_id.clone()))
        {
            return Err(ModelError::DuplicateRecipient);
        }
        if self.recipients.iter().any(|recipient| {
            !recipient.email_digest.is_valid()
                || !recipient.name_digest.is_valid()
                || recipient.recipient_id.as_str().trim().is_empty()
        }) {
            return Err(ModelError::InvalidSourceDigest);
        }
        if !self.source_result_digest.is_valid() || !self.source_file_digest.is_valid() {
            return Err(ModelError::InvalidSourceDigest);
        }
        let routing_ids = self
            .routing
            .recipient_ids()
            .cloned()
            .collect::<BTreeSet<_>>();
        if routing_ids != ids
            || self.recipients.iter().any(|recipient| {
                !self.routing.steps().iter().any(|step| {
                    step.order == recipient.routing_order
                        && step.recipient_ids.contains(&recipient.recipient_id)
                })
            })
        {
            return Err(ModelError::RoutingRecipientMismatch);
        }
        let lifetime = self.expires_at - self.created_at;
        if lifetime <= Duration::zero() || lifetime > Duration::days(30) {
            return Err(ModelError::InvalidExpiry);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnvelopeProposal {
    scope: DocuSignScope,
    revision_fence: RevisionFence,
    source_result_digest: Digest,
    source_file_digest: Digest,
    content: EnvelopeContent,
    recipients: Vec<RecipientSpec>,
    routing: RoutingPlan,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    provider_version: ProviderVersion,
    registration_digest: Digest,
    fingerprint: Digest,
}

impl EnvelopeProposal {
    pub(crate) fn from_request(
        request: EnvelopeProposalRequest,
        provider_version: ProviderVersion,
        registration_digest: Digest,
    ) -> Result<Self, ModelError> {
        request.validate()?;
        provider_version.validate()?;
        let fingerprint = proposal_fingerprint(&request, provider_version, &registration_digest);
        Ok(Self {
            scope: request.scope,
            revision_fence: request.revision_fence,
            source_result_digest: request.source_result_digest,
            source_file_digest: request.source_file_digest,
            content: request.content,
            recipients: request.recipients,
            routing: request.routing,
            created_at: request.created_at,
            expires_at: request.expires_at,
            provider_version,
            registration_digest,
            fingerprint,
        })
    }

    pub fn scope(&self) -> &DocuSignScope {
        &self.scope
    }

    pub const fn revision_fence(&self) -> RevisionFence {
        self.revision_fence
    }

    pub fn source_result_digest(&self) -> &Digest {
        &self.source_result_digest
    }

    pub fn source_file_digest(&self) -> &Digest {
        &self.source_file_digest
    }

    pub fn content(&self) -> &EnvelopeContent {
        &self.content
    }

    pub fn recipients(&self) -> &[RecipientSpec] {
        &self.recipients
    }

    pub fn routing(&self) -> &RoutingPlan {
        &self.routing
    }

    pub const fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    pub const fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub const fn provider_version(&self) -> ProviderVersion {
        self.provider_version
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn fingerprint(&self) -> &Digest {
        &self.fingerprint
    }
}

fn proposal_fingerprint(
    request: &EnvelopeProposalRequest,
    provider_version: ProviderVersion,
    registration_digest: &Digest,
) -> Digest {
    let mut parts = vec![
        request.scope.digest().to_string(),
        request.revision_fence.digest().to_string(),
        request.source_result_digest.to_string(),
        request.source_file_digest.to_string(),
        provider_version.as_string(),
        registration_digest.to_string(),
        request.created_at.to_rfc3339(),
        request.expires_at.to_rfc3339(),
    ];
    match &request.content {
        EnvelopeContent::Template(template) => {
            parts.push("template".to_owned());
            parts.push(template.template_id.as_str().to_owned());
            parts.push(template.template_digest.to_string());
        }
        EnvelopeContent::Documents(documents) => {
            parts.push("documents".to_owned());
            for document in documents {
                parts.push(document.document_id.as_str().to_owned());
                parts.push(document.file_digest.to_string());
                parts.push(format!("{:?}", document.content_type));
            }
        }
    }
    for recipient in &request.recipients {
        parts.extend([
            recipient.recipient_id.as_str().to_owned(),
            format!("{:?}", recipient.role),
            recipient.email_digest.to_string(),
            recipient.name_digest.to_string(),
            recipient.routing_order.value().to_string(),
        ]);
    }
    for step in request.routing.steps() {
        parts.push(step.order.value().to_string());
        parts.extend(
            step.recipient_ids
                .iter()
                .map(|recipient_id| recipient_id.as_str().to_owned()),
        );
    }
    Digest::from_parts(parts)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeStatus {
    Created,
    Sent,
    Delivered,
    Completed,
    Declined,
    Voided,
    ProviderUnknown,
}

impl EnvelopeStatus {
    pub const fn is_completed(self) -> bool {
        matches!(self, Self::Completed)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum RecipientStatus {
    Created,
    Sent,
    Delivered,
    Completed,
    Declined,
    Voided,
    ProviderUnknown { status_digest: Digest },
}

impl RecipientStatus {
    pub const fn is_completed(&self) -> bool {
        matches!(self, Self::Completed)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecipientStatusProjection {
    recipient_id: RecipientId,
    role: RecipientRole,
    routing_order: RoutingOrder,
    status: RecipientStatus,
}

impl RecipientStatusProjection {
    pub fn new(
        recipient_id: RecipientId,
        role: RecipientRole,
        routing_order: RoutingOrder,
        status: RecipientStatus,
    ) -> Self {
        Self {
            recipient_id,
            role,
            routing_order,
            status,
        }
    }

    pub fn recipient_id(&self) -> &RecipientId {
        &self.recipient_id
    }

    pub const fn role(&self) -> RecipientRole {
        self.role
    }

    pub const fn routing_order(&self) -> RoutingOrder {
        self.routing_order
    }

    pub fn status(&self) -> &RecipientStatus {
        &self.status
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeOperation {
    EnvelopeCreate,
    EnvelopeSend,
    SigningCeremony,
    EnvelopeIdAndUrlReceipt,
    BoundedStatusReconciliation,
    IndependentDocumentReadback,
    ConnectVerification,
    AmbiguousCreateRecovery,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum ProviderProvenance {
    Fixture,
    Loopback,
    BlockedEnv,
    NativeLayer2Gap { operation: NativeOperation },
}

impl ProviderProvenance {
    pub const fn claims_connected(&self) -> bool {
        false
    }

    pub const fn claims_native(&self) -> bool {
        false
    }

    fn default_evidence(&self) -> NonConnectedEvidence {
        match self {
            Self::Fixture => NonConnectedEvidence::Fixture,
            Self::Loopback => NonConnectedEvidence::Loopback,
            Self::BlockedEnv => NonConnectedEvidence::BlockedEnv,
            Self::NativeLayer2Gap { operation } => NonConnectedEvidence::NativeLayer2Gap {
                operation: *operation,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NonConnectedEvidence {
    Fixture,
    Loopback,
    BlockedEnv,
    MissingCredentials,
    AccountMismatch,
    UnsupportedStatus,
    RateLimited { retry_after_seconds: u64 },
    Timeout,
    EventualConsistency { retry_after_seconds: u64 },
    NativeLayer2Gap { operation: NativeOperation },
}

impl NonConnectedEvidence {
    pub const fn claims_connected(self) -> bool {
        false
    }

    pub const fn claims_native(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompletionBlockReason {
    NotCompleted,
    RecipientNotCompleted,
    MissingCompletionEvidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum CompletionEvidence {
    NotVerified,
    RecordedCompleted { evidence_digest: Digest },
    Blocked { reason: CompletionBlockReason },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionState {
    Omitted,
    DigestOnly,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionSummary {
    oauth_access_and_refresh_material: RedactionState,
    signer_pii: RedactionState,
    document_bytes: RedactionState,
    raw_connect_payload: RedactionState,
    raw_provider_response: RedactionState,
}

impl RedactionSummary {
    pub const fn layer1() -> Self {
        Self {
            oauth_access_and_refresh_material: RedactionState::Omitted,
            signer_pii: RedactionState::DigestOnly,
            document_bytes: RedactionState::Omitted,
            raw_connect_payload: RedactionState::Omitted,
            raw_provider_response: RedactionState::DigestOnly,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedEnvelopeObservation {
    scope: DocuSignScope,
    envelope_id: EnvelopeId,
    proposal_fingerprint: Digest,
    revision_fence: RevisionFence,
    status: EnvelopeStatus,
    recipient_statuses: Vec<RecipientStatusProjection>,
    observed_at: DateTime<Utc>,
    provider_response_digest: Digest,
    completion_evidence_digest: Option<Digest>,
    provider_version: ProviderVersion,
    registration_digest: Digest,
    provenance: ProviderProvenance,
    non_connected_evidence: NonConnectedEvidence,
}

impl RecordedEnvelopeObservation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: DocuSignScope,
        envelope_id: EnvelopeId,
        proposal_fingerprint: Digest,
        revision_fence: RevisionFence,
        status: EnvelopeStatus,
        recipient_statuses: impl IntoIterator<Item = RecipientStatusProjection>,
        observed_at: DateTime<Utc>,
        provider_response_digest: Digest,
        completion_evidence_digest: Option<Digest>,
        provider_version: ProviderVersion,
        registration_digest: Digest,
        provenance: ProviderProvenance,
    ) -> Result<Self, ModelError> {
        let recipient_statuses = recipient_statuses.into_iter().collect::<Vec<_>>();
        if recipient_statuses.is_empty() {
            return Err(ModelError::InvalidObservation);
        }
        let mut recipient_ids = BTreeSet::new();
        if recipient_statuses
            .iter()
            .any(|status| !recipient_ids.insert(status.recipient_id.clone()))
        {
            return Err(ModelError::DuplicateRecipient);
        }
        provider_version.validate()?;
        let observation = Self {
            scope,
            envelope_id,
            proposal_fingerprint,
            revision_fence,
            status,
            recipient_statuses,
            observed_at,
            provider_response_digest,
            completion_evidence_digest,
            provider_version,
            registration_digest,
            non_connected_evidence: if status == EnvelopeStatus::ProviderUnknown {
                NonConnectedEvidence::UnsupportedStatus
            } else {
                provenance.default_evidence()
            },
            provenance,
        };
        observation.validate()?;
        Ok(observation)
    }

    pub fn scope(&self) -> &DocuSignScope {
        &self.scope
    }

    pub fn envelope_id(&self) -> &EnvelopeId {
        &self.envelope_id
    }

    pub fn proposal_fingerprint(&self) -> &Digest {
        &self.proposal_fingerprint
    }

    pub const fn revision_fence(&self) -> RevisionFence {
        self.revision_fence
    }

    pub const fn status(&self) -> EnvelopeStatus {
        self.status
    }

    pub fn recipient_statuses(&self) -> &[RecipientStatusProjection] {
        &self.recipient_statuses
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub fn provider_response_digest(&self) -> &Digest {
        &self.provider_response_digest
    }

    pub fn completion_evidence_digest(&self) -> Option<&Digest> {
        self.completion_evidence_digest.as_ref()
    }

    pub const fn provider_version(&self) -> ProviderVersion {
        self.provider_version
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn provenance(&self) -> &ProviderProvenance {
        &self.provenance
    }

    pub const fn non_connected_evidence(&self) -> NonConnectedEvidence {
        self.non_connected_evidence
    }

    fn validate(&self) -> Result<(), ModelError> {
        self.scope.validate()?;
        self.revision_fence.validate()?;
        self.provider_version.validate()?;
        if !self.proposal_fingerprint.is_valid()
            || !self.provider_response_digest.is_valid()
            || !self.registration_digest.is_valid()
            || self
                .completion_evidence_digest
                .as_ref()
                .is_some_and(|digest| !digest.is_valid())
        {
            return Err(ModelError::InvalidObservation);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnvelopeStatusProjection {
    envelope_id: EnvelopeId,
    status: EnvelopeStatus,
    scope_digest: Digest,
    receipt_digest: Digest,
    observed_at: DateTime<Utc>,
    provenance: ProviderProvenance,
    non_connected_evidence: NonConnectedEvidence,
}

impl EnvelopeStatusProjection {
    pub(crate) fn from_receipt(receipt: &DocuSignReceipt) -> Self {
        Self {
            envelope_id: receipt.envelope_id.clone(),
            status: receipt.status,
            scope_digest: receipt.scope_digest.clone(),
            receipt_digest: receipt.receipt_digest.clone(),
            observed_at: receipt.observed_at,
            provenance: receipt.provenance.clone(),
            non_connected_evidence: receipt.non_connected_evidence,
        }
    }

    pub fn envelope_id(&self) -> &EnvelopeId {
        &self.envelope_id
    }

    pub const fn status(&self) -> EnvelopeStatus {
        self.status
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn receipt_digest(&self) -> &Digest {
        &self.receipt_digest
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub fn provenance(&self) -> &ProviderProvenance {
        &self.provenance
    }

    pub const fn non_connected_evidence(&self) -> NonConnectedEvidence {
        self.non_connected_evidence
    }

    pub const fn claims_connected(&self) -> bool {
        false
    }

    pub const fn claims_native(&self) -> bool {
        false
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocuSignReceipt {
    tenant_id: TenantId,
    project_id: ProjectId,
    mission_id: MissionId,
    scope_digest: Digest,
    envelope_id: EnvelopeId,
    proposal_fingerprint: Digest,
    revision_fence: RevisionFence,
    source_result_digest: Digest,
    source_file_digest: Digest,
    provider_version: ProviderVersion,
    registration_digest: Digest,
    status: EnvelopeStatus,
    recipient_statuses: Vec<RecipientStatusProjection>,
    completion_evidence: CompletionEvidence,
    provider_response_digest: Digest,
    observed_at: DateTime<Utc>,
    provenance: ProviderProvenance,
    non_connected_evidence: NonConnectedEvidence,
    redaction: RedactionSummary,
    receipt_digest: Digest,
}

impl fmt::Debug for DocuSignReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DocuSignReceipt")
            .field("scope_digest", &self.scope_digest)
            .field("envelope_id", &"<opaque>")
            .field("proposal_fingerprint", &self.proposal_fingerprint)
            .field("revision_fence", &self.revision_fence)
            .field("provider_version", &self.provider_version)
            .field("status", &self.status)
            .field("recipient_count", &self.recipient_statuses.len())
            .field("completion_evidence", &self.completion_evidence)
            .field("provenance", &self.provenance)
            .field("non_connected_evidence", &self.non_connected_evidence)
            .field("redaction", &self.redaction)
            .field("receipt_digest", &self.receipt_digest)
            .finish_non_exhaustive()
    }
}

impl DocuSignReceipt {
    pub(crate) fn from_projection(
        proposal: &EnvelopeProposal,
        observation: &RecordedEnvelopeObservation,
    ) -> Result<Self, ModelError> {
        if proposal.scope != observation.scope
            || proposal.fingerprint != observation.proposal_fingerprint
            || proposal.revision_fence != observation.revision_fence
            || proposal.provider_version != observation.provider_version
            || proposal.registration_digest != observation.registration_digest
            || !recipient_projection_matches(proposal, &observation.recipient_statuses)
        {
            return Err(ModelError::InvalidObservation);
        }
        let completion_evidence = if !observation.status.is_completed() {
            CompletionEvidence::Blocked {
                reason: CompletionBlockReason::NotCompleted,
            }
        } else if observation
            .recipient_statuses
            .iter()
            .all(|status| status.status.is_completed())
        {
            observation.completion_evidence_digest.as_ref().map_or(
                CompletionEvidence::Blocked {
                    reason: CompletionBlockReason::MissingCompletionEvidence,
                },
                |evidence_digest| CompletionEvidence::RecordedCompleted {
                    evidence_digest: evidence_digest.clone(),
                },
            )
        } else {
            CompletionEvidence::Blocked {
                reason: CompletionBlockReason::RecipientNotCompleted,
            }
        };
        let mut receipt = Self {
            tenant_id: proposal.scope.tenant_id.clone(),
            project_id: proposal.scope.project_id.clone(),
            mission_id: proposal.scope.mission_id.clone(),
            scope_digest: proposal.scope.digest(),
            envelope_id: observation.envelope_id.clone(),
            proposal_fingerprint: proposal.fingerprint.clone(),
            revision_fence: proposal.revision_fence,
            source_result_digest: proposal.source_result_digest.clone(),
            source_file_digest: proposal.source_file_digest.clone(),
            provider_version: proposal.provider_version,
            registration_digest: proposal.registration_digest.clone(),
            status: observation.status,
            recipient_statuses: observation.recipient_statuses.clone(),
            completion_evidence,
            provider_response_digest: observation.provider_response_digest.clone(),
            observed_at: observation.observed_at,
            provenance: observation.provenance.clone(),
            non_connected_evidence: observation.non_connected_evidence,
            redaction: RedactionSummary::layer1(),
            receipt_digest: Digest::from_text("unsealed-docusign-receipt"),
        };
        receipt.receipt_digest = receipt.computed_digest();
        Ok(receipt)
    }

    pub fn validate_integrity(&self) -> Result<(), ModelError> {
        if self.redaction != RedactionSummary::layer1()
            || self.receipt_digest != self.computed_digest()
            || !recipient_ids_are_unique(&self.recipient_statuses)
            || !self.scope_digest.is_valid()
            || !self.proposal_fingerprint.is_valid()
            || !self.source_result_digest.is_valid()
            || !self.source_file_digest.is_valid()
            || !self.registration_digest.is_valid()
            || !self.provider_response_digest.is_valid()
            || self.revision_fence.validate().is_err()
            || self.provider_version.validate().is_err()
        {
            return Err(ModelError::InvalidReceipt);
        }
        Ok(())
    }

    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn envelope_id(&self) -> &EnvelopeId {
        &self.envelope_id
    }

    pub fn proposal_fingerprint(&self) -> &Digest {
        &self.proposal_fingerprint
    }

    pub const fn revision_fence(&self) -> RevisionFence {
        self.revision_fence
    }

    pub fn source_result_digest(&self) -> &Digest {
        &self.source_result_digest
    }

    pub fn source_file_digest(&self) -> &Digest {
        &self.source_file_digest
    }

    pub const fn provider_version(&self) -> ProviderVersion {
        self.provider_version
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub const fn status(&self) -> EnvelopeStatus {
        self.status
    }

    pub fn recipient_statuses(&self) -> &[RecipientStatusProjection] {
        &self.recipient_statuses
    }

    pub fn completion_evidence(&self) -> &CompletionEvidence {
        &self.completion_evidence
    }

    pub fn provider_response_digest(&self) -> &Digest {
        &self.provider_response_digest
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub fn provenance(&self) -> &ProviderProvenance {
        &self.provenance
    }

    pub const fn non_connected_evidence(&self) -> NonConnectedEvidence {
        self.non_connected_evidence
    }

    pub fn redaction(&self) -> &RedactionSummary {
        &self.redaction
    }

    pub fn receipt_digest(&self) -> &Digest {
        &self.receipt_digest
    }

    pub fn is_verified_completed(&self) -> bool {
        self.status.is_completed()
            && self
                .recipient_statuses
                .iter()
                .all(|status| status.status.is_completed())
            && matches!(
                self.completion_evidence,
                CompletionEvidence::RecordedCompleted { .. }
            )
    }

    pub fn envelope_status_projection(&self) -> EnvelopeStatusProjection {
        EnvelopeStatusProjection::from_receipt(self)
    }

    pub fn recipient_status_projection(&self) -> &[RecipientStatusProjection] {
        &self.recipient_statuses
    }

    fn computed_digest(&self) -> Digest {
        let mut parts = vec![
            self.tenant_id.as_str().to_owned(),
            self.project_id.as_str().to_owned(),
            self.mission_id.as_str().to_owned(),
            self.scope_digest.to_string(),
            self.envelope_id.as_str().to_owned(),
            self.proposal_fingerprint.to_string(),
            self.revision_fence.digest().to_string(),
            self.source_result_digest.to_string(),
            self.source_file_digest.to_string(),
            self.provider_version.as_string(),
            self.registration_digest.to_string(),
            format!("{:?}", self.status),
            self.provider_response_digest.to_string(),
            self.observed_at.to_rfc3339(),
            format!("{:?}", self.provenance),
            format!("{:?}", self.non_connected_evidence),
            format!("{:?}", self.completion_evidence),
        ];
        for recipient in &self.recipient_statuses {
            parts.extend([
                recipient.recipient_id.as_str().to_owned(),
                format!("{:?}", recipient.role),
                recipient.routing_order.value().to_string(),
                format!("{:?}", recipient.status),
            ]);
        }
        Digest::from_parts(parts)
    }
}

fn recipient_ids_are_unique(statuses: &[RecipientStatusProjection]) -> bool {
    let mut seen = BTreeSet::new();
    statuses
        .iter()
        .all(|status| seen.insert(status.recipient_id.clone()))
}

fn recipient_projection_matches(
    proposal: &EnvelopeProposal,
    statuses: &[RecipientStatusProjection],
) -> bool {
    if !recipient_ids_are_unique(statuses) || statuses.len() != proposal.recipients.len() {
        return false;
    }
    proposal.recipients.iter().all(|recipient| {
        statuses.iter().any(|status| {
            status.recipient_id == recipient.recipient_id
                && status.role == recipient.role
                && status.routing_order == recipient.routing_order
        })
    })
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedResultSource {
    project_id: ProjectId,
    mission_id: MissionId,
    source_result_digest: Digest,
    source_file_digest: Digest,
    recipient_ids: Vec<RecipientId>,
    revision_fence: RevisionFence,
}

impl SignedResultSource {
    pub fn new(
        project_id: ProjectId,
        mission_id: MissionId,
        source_result_digest: Digest,
        source_file_digest: Digest,
        recipient_ids: impl IntoIterator<Item = RecipientId>,
        revision_fence: RevisionFence,
    ) -> Result<Self, ModelError> {
        let recipient_ids = recipient_ids.into_iter().collect::<Vec<_>>();
        if recipient_ids.is_empty() {
            return Err(ModelError::EmptyRecipientSet);
        }
        if !source_result_digest.is_valid() || !source_file_digest.is_valid() {
            return Err(ModelError::InvalidSourceDigest);
        }
        revision_fence.validate()?;
        let mut seen = BTreeSet::new();
        if recipient_ids.iter().any(|id| !seen.insert(id)) {
            return Err(ModelError::DuplicateRecipient);
        }
        Ok(Self {
            project_id,
            mission_id,
            source_result_digest,
            source_file_digest,
            recipient_ids,
            revision_fence,
        })
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub fn source_result_digest(&self) -> &Digest {
        &self.source_result_digest
    }

    pub fn source_file_digest(&self) -> &Digest {
        &self.source_file_digest
    }

    pub fn recipient_ids(&self) -> &[RecipientId] {
        &self.recipient_ids
    }

    pub const fn revision_fence(&self) -> RevisionFence {
        self.revision_fence
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedResultAdoptionProposal {
    project_id: ProjectId,
    mission_id: MissionId,
    scope_digest: Digest,
    envelope_id: EnvelopeId,
    receipt_digest: Digest,
    source_result_digest: Digest,
    source_file_digest: Digest,
    recipient_ids: Vec<RecipientId>,
    revision_fence: RevisionFence,
    provider_version: ProviderVersion,
    registration_digest: Digest,
    provenance: ProviderProvenance,
    claims_connected: bool,
    claims_native: bool,
}

impl SignedResultAdoptionProposal {
    pub(crate) fn from_receipt(receipt: &DocuSignReceipt, source: &SignedResultSource) -> Self {
        Self {
            project_id: source.project_id.clone(),
            mission_id: source.mission_id.clone(),
            scope_digest: receipt.scope_digest.clone(),
            envelope_id: receipt.envelope_id.clone(),
            receipt_digest: receipt.receipt_digest.clone(),
            source_result_digest: source.source_result_digest.clone(),
            source_file_digest: source.source_file_digest.clone(),
            recipient_ids: source.recipient_ids.clone(),
            revision_fence: source.revision_fence,
            provider_version: receipt.provider_version,
            registration_digest: receipt.registration_digest.clone(),
            provenance: receipt.provenance.clone(),
            claims_connected: false,
            claims_native: false,
        }
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn envelope_id(&self) -> &EnvelopeId {
        &self.envelope_id
    }

    pub fn receipt_digest(&self) -> &Digest {
        &self.receipt_digest
    }

    pub fn source_result_digest(&self) -> &Digest {
        &self.source_result_digest
    }

    pub fn source_file_digest(&self) -> &Digest {
        &self.source_file_digest
    }

    pub fn recipient_ids(&self) -> &[RecipientId] {
        &self.recipient_ids
    }

    pub const fn revision_fence(&self) -> RevisionFence {
        self.revision_fence
    }

    pub const fn provider_version(&self) -> ProviderVersion {
        self.provider_version
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn provenance(&self) -> &ProviderProvenance {
        &self.provenance
    }

    pub const fn claims_connected(&self) -> bool {
        self.claims_connected
    }

    pub const fn claims_native(&self) -> bool {
        self.claims_native
    }
}

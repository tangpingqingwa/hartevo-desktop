use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    SAP_SALES_ORDER_RESULT_CONTRACT_VERSION, SAP_SALES_ORDER_RESULT_PLUGIN_VERSION,
    SAP_SALES_ORDER_RESULT_PROVIDER_ID,
};

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_OPAQUE_INPUT_BYTES: usize = 256;
pub const MAX_FIELD_VALUE_BYTES: usize = 512;
pub const MAX_REDACTED_FIELDS: usize = 256;
pub const MAX_PAGE_SIZE: u32 = 100;
pub const MAX_PAGE_COUNT: u8 = 16;
pub const MAX_ITEM_COUNT: usize = 1_000;
pub const MAX_DOCUMENT_FLOW_COUNT: usize = 256;
pub const MAX_DOCUMENT_FLOW_DEPTH: u8 = 3;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("identifier is empty, malformed, or too long")]
    InvalidIdentifier,
    #[error("opaque input is empty, malformed, or too long")]
    InvalidOpaqueInput,
    #[error("digest is not a lowercase SHA-256 hex digest")]
    InvalidDigest,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("scope is invalid or misses a required read permission")]
    InvalidScope,
    #[error("permission lease is empty or has an invalid revision")]
    InvalidPermissionLease,
    #[error("query bounds exceed the Layer-1 safety ceiling")]
    InvalidBounds,
    #[error("the requested OData entity set is not allowlisted")]
    UnallowlistedEntitySet,
    #[error("the requested OData field or filter is not allowlisted")]
    UnallowlistedProjection,
    #[error("OData query is malformed")]
    InvalidQuery,
    #[error("currency is not a three-letter uppercase code")]
    InvalidCurrency,
    #[error("amount or quantity is not a bounded decimal text")]
    InvalidDecimal,
    #[error("row contains an invalid or oversized field")]
    InvalidRow,
    #[error("registration or secret reference is invalid")]
    InvalidRegistration,
    #[error("registration or secret reference is already revoked")]
    AlreadyRevoked,
    #[error("the source revision or ETag is missing")]
    MissingRevision,
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

    pub fn from_values(domain: &str, values: &[&str]) -> Self {
        let fields = values.iter().map(|value| (*value).to_owned());
        Self::from_parts(domain, fields)
    }

    pub(crate) fn from_parts<I, S>(domain: &str, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for value in values {
            append_field(&mut bytes, value.as_ref());
        }
        Self::from_bytes(&bytes)
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

fn valid_opaque_input(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_OPAQUE_INPUT_BYTES
        && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

fn valid_decimal(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_FIELD_VALUE_BYTES
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_digit() || (byte == b'-' && index == 0) || byte == b'.'
        })
        && value.bytes().filter(|byte| *byte == b'.').count() <= 1
        && value.bytes().any(|byte| byte.is_ascii_digit())
}

macro_rules! string_identifier {
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

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

string_identifier!(TenantId);
string_identifier!(SystemId);
string_identifier!(ProjectId);
string_identifier!(MissionId);
string_identifier!(WorkProductId);
string_identifier!(ServiceId);
string_identifier!(ProviderId);
string_identifier!(ConsumerId);

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct OpaqueDocumentId(Digest);

impl OpaqueDocumentId {
    pub fn new(raw_document_id: impl Into<String>) -> Result<Self, ModelError> {
        let raw_document_id = raw_document_id.into();
        if valid_opaque_input(&raw_document_id) {
            Ok(Self(Digest::from_values(
                "sap-sales-order-document-id/v1",
                &[&raw_document_id],
            )))
        } else {
            Err(ModelError::InvalidOpaqueInput)
        }
    }

    pub fn from_digest(digest: Digest) -> Self {
        Self(digest)
    }

    pub fn digest(&self) -> &Digest {
        &self.0
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for OpaqueDocumentId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("OpaqueDocumentId")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for OpaqueDocumentId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

pub type SalesOrderId = OpaqueDocumentId;

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct OpaqueEtag(Digest);

impl OpaqueEtag {
    pub fn new(raw_etag: impl Into<String>) -> Result<Self, ModelError> {
        let raw_etag = raw_etag.into();
        if valid_opaque_input(&raw_etag) {
            Ok(Self(Digest::from_values(
                "sap-sales-order-etag/v1",
                &[&raw_etag],
            )))
        } else {
            Err(ModelError::InvalidOpaqueInput)
        }
    }

    pub fn from_digest(digest: Digest) -> Self {
        Self(digest)
    }

    pub fn digest(&self) -> &Digest {
        &self.0
    }
}

impl fmt::Debug for OpaqueEtag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("OpaqueEtag").field(&self.0).finish()
    }
}

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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SapODataVersion {
    V2,
}

impl SapODataVersion {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V2 => "V2",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SapEntitySet {
    SalesOrder,
    SalesOrderItem,
    SalesOrderDocumentFlow,
}

impl SapEntitySet {
    pub const ALL: [Self; 3] = [
        Self::SalesOrder,
        Self::SalesOrderItem,
        Self::SalesOrderDocumentFlow,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SalesOrder => "A_SalesOrder",
            Self::SalesOrderItem => "A_SalesOrderItem",
            Self::SalesOrderDocumentFlow => "A_SalesOrderDocFlow",
        }
    }

    pub const fn required_permission(self) -> SapPermission {
        match self {
            Self::SalesOrder => SapPermission::SalesOrderRead,
            Self::SalesOrderItem => SapPermission::SalesOrderItemRead,
            Self::SalesOrderDocumentFlow => SapPermission::DocumentFlowRead,
        }
    }
}

pub const fn allowlisted_fields(entity_set: SapEntitySet) -> &'static [&'static str] {
    match entity_set {
        SapEntitySet::SalesOrder => &[
            "SalesOrder",
            "SalesOrderType",
            "SalesOrganization",
            "DistributionChannel",
            "OrganizationDivision",
            "CreationDate",
            "LastChangeDate",
            "TransactionCurrency",
            "TotalNetAmount",
            "OverallSDProcessStatus",
            "OverallDeliveryStatus",
            "OverallBillingStatus",
            "DeliveryBlockReason",
            "BillingBlockReason",
            "TotalBlockStatus",
            "ETag",
        ],
        SapEntitySet::SalesOrderItem => &[
            "SalesOrder",
            "SalesOrderItem",
            "Material",
            "RequestedQuantity",
            "RequestedQuantityUnit",
            "NetAmount",
            "TransactionCurrency",
            "DeliveryStatus",
            "BillingStatus",
            "DeliveryBlockReason",
            "BillingBlockReason",
            "HigherLevelItem",
            "CreationDate",
            "LastChangeDate",
            "ETag",
        ],
        SapEntitySet::SalesOrderDocumentFlow => &[
            "SalesOrder",
            "PrecedingDocument",
            "SubsequentDocument",
            "PrecedingDocumentItem",
            "SubsequentDocumentItem",
            "DeliveryDocument",
            "BillingDocument",
            "DocumentCategory",
            "DocumentFlowStatus",
            "DocumentFlowDepth",
            "CreationDate",
            "LastChangeDate",
            "ETag",
        ],
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SapPermission {
    SalesOrderRead,
    SalesOrderItemRead,
    DocumentFlowRead,
    DeliveryStatusRead,
    BillingStatusRead,
}

impl SapPermission {
    pub const ALL_READ: [Self; 5] = [
        Self::SalesOrderRead,
        Self::SalesOrderItemRead,
        Self::DocumentFlowRead,
        Self::DeliveryStatusRead,
        Self::BillingStatusRead,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SalesOrderRead => "sales_order.read",
            Self::SalesOrderItemRead => "sales_order_item.read",
            Self::DocumentFlowRead => "sales_order_document_flow.read",
            Self::DeliveryStatusRead => "delivery_status.read",
            Self::BillingStatusRead => "billing_status.read",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PermissionLease {
    permissions: BTreeSet<SapPermission>,
    revision: Revision,
    digest: Digest,
}

impl PermissionLease {
    pub fn new<I>(permissions: I, revision: u64) -> Result<Self, ModelError>
    where
        I: IntoIterator<Item = SapPermission>,
    {
        let permissions: BTreeSet<_> = permissions.into_iter().collect();
        let revision = Revision::new(revision)?;
        if permissions.is_empty() {
            return Err(ModelError::InvalidPermissionLease);
        }
        let digest = Digest::from_parts(
            "sap-sales-order-permission-lease/v1",
            permissions
                .iter()
                .map(|permission| permission.as_str().to_owned())
                .chain(std::iter::once(revision.get().to_string())),
        );
        Ok(Self {
            permissions,
            revision,
            digest,
        })
    }

    pub fn read_only(revision: u64) -> Result<Self, ModelError> {
        Self::new(SapPermission::ALL_READ, revision)
    }

    pub fn permissions(&self) -> &BTreeSet<SapPermission> {
        &self.permissions
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn contains(&self, permission: SapPermission) -> bool {
        self.permissions.contains(&permission)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct SapQueryBounds {
    page_size: u32,
    max_pages: u8,
    max_items: usize,
    max_document_flow: usize,
    max_document_flow_depth: u8,
}

impl Default for SapQueryBounds {
    fn default() -> Self {
        Self {
            page_size: MAX_PAGE_SIZE,
            max_pages: MAX_PAGE_COUNT,
            max_items: MAX_ITEM_COUNT,
            max_document_flow: MAX_DOCUMENT_FLOW_COUNT,
            max_document_flow_depth: MAX_DOCUMENT_FLOW_DEPTH,
        }
    }
}

impl SapQueryBounds {
    pub fn new(
        page_size: u32,
        max_pages: u8,
        max_items: usize,
        max_document_flow: usize,
        max_document_flow_depth: u8,
    ) -> Result<Self, ModelError> {
        let bounds = Self {
            page_size,
            max_pages,
            max_items,
            max_document_flow,
            max_document_flow_depth,
        };
        if page_size == 0
            || page_size > MAX_PAGE_SIZE
            || max_pages == 0
            || max_pages > MAX_PAGE_COUNT
            || max_items == 0
            || max_items > MAX_ITEM_COUNT
            || max_document_flow == 0
            || max_document_flow > MAX_DOCUMENT_FLOW_COUNT
            || max_document_flow_depth == 0
            || max_document_flow_depth > MAX_DOCUMENT_FLOW_DEPTH
        {
            Err(ModelError::InvalidBounds)
        } else {
            Ok(bounds)
        }
    }

    pub const fn page_size(self) -> u32 {
        self.page_size
    }

    pub const fn max_pages(self) -> u8 {
        self.max_pages
    }

    pub const fn max_items(self) -> usize {
        self.max_items
    }

    pub const fn max_document_flow(self) -> usize {
        self.max_document_flow
    }

    pub const fn max_document_flow_depth(self) -> u8 {
        self.max_document_flow_depth
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct SapRedactionPolicy {
    revision: Revision,
}

impl SapRedactionPolicy {
    pub fn strict(revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            revision: Revision::new(revision)?,
        })
    }

    pub const fn revision(self) -> Revision {
        self.revision
    }

    pub fn digest(self) -> Digest {
        Digest::from_values(
            "sap-sales-order-redaction-policy/v1",
            &[
                &self.revision.get().to_string(),
                "partner_drop",
                "free_text_drop",
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RedactionSummary {
    count: usize,
    field_digests: Vec<Digest>,
    digest: Digest,
}

impl Default for RedactionSummary {
    fn default() -> Self {
        Self::new()
    }
}

impl RedactionSummary {
    pub fn new() -> Self {
        Self {
            count: 0,
            field_digests: Vec::new(),
            digest: Digest::from_values("sap-redaction-summary/v1", &[]),
        }
    }

    pub fn record_field(&mut self, field_name: &str) {
        if self.count >= MAX_REDACTED_FIELDS {
            return;
        }
        self.count += 1;
        self.field_digests
            .push(Digest::from_values("sap-redacted-field/v1", &[field_name]));
        self.digest = Digest::from_parts(
            "sap-redaction-summary/v1",
            std::iter::once(self.count.to_string()).chain(
                self.field_digests
                    .iter()
                    .map(|digest| digest.as_str().to_owned()),
            ),
        );
    }

    pub fn merge(&mut self, other: &Self) {
        for digest in &other.field_digests {
            if self.count >= MAX_REDACTED_FIELDS {
                break;
            }
            self.count += 1;
            self.field_digests.push(digest.clone());
        }
        self.digest = Digest::from_parts(
            "sap-redaction-summary/v1",
            std::iter::once(self.count.to_string()).chain(
                self.field_digests
                    .iter()
                    .map(|digest| digest.as_str().to_owned()),
            ),
        );
    }

    pub const fn count(&self) -> usize {
        self.count
    }

    pub fn field_digests(&self) -> &[Digest] {
        &self.field_digests
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RevisionBinding {
    id: String,
    revision: Revision,
}

impl RevisionBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        let id = id.into();
        if !valid_identifier(&id) {
            return Err(ModelError::InvalidIdentifier);
        }
        Ok(Self {
            id,
            revision: Revision::new(revision)?,
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RevisionFence {
    project: RevisionBinding,
    mission: RevisionBinding,
    work_product: RevisionBinding,
    scope_digest: Digest,
    permission_digest: Digest,
    source_revision: Option<Revision>,
    etag: Option<OpaqueEtag>,
}

impl RevisionFence {
    fn from_scope(scope: &SapSalesOrderScope) -> Self {
        Self {
            project: scope.project.clone(),
            mission: scope.mission.clone(),
            work_product: scope.work_product.clone(),
            scope_digest: scope.scope_digest.clone(),
            permission_digest: scope.permission_lease.digest.clone(),
            source_revision: scope.expected_source_revision,
            etag: scope.expected_etag.clone(),
        }
    }

    pub(crate) fn with_source(
        mut self,
        source_revision: Revision,
        etag: Option<OpaqueEtag>,
    ) -> Self {
        self.source_revision = Some(source_revision);
        self.etag = etag;
        self
    }

    pub fn project(&self) -> &RevisionBinding {
        &self.project
    }

    pub fn mission(&self) -> &RevisionBinding {
        &self.mission
    }

    pub fn work_product(&self) -> &RevisionBinding {
        &self.work_product
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub const fn source_revision(&self) -> Option<Revision> {
        self.source_revision
    }

    pub fn etag(&self) -> Option<&OpaqueEtag> {
        self.etag.as_ref()
    }

    pub fn matches(&self, other: &Self) -> bool {
        self == other
    }

    pub fn matches_current(&self, expected: &Self) -> bool {
        self.project == expected.project
            && self.mission == expected.mission
            && self.work_product == expected.work_product
            && self.scope_digest == expected.scope_digest
            && self.permission_digest == expected.permission_digest
            && expected
                .source_revision
                .is_none_or(|revision| self.source_revision == Some(revision))
            && expected
                .etag
                .as_ref()
                .is_none_or(|etag| self.etag.as_ref() == Some(etag))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    OAuth,
    ClientCertificate,
    ApiKey,
}

impl SecretKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OAuth => "oauth",
            Self::ClientCertificate => "client_certificate",
            Self::ApiKey => "api_key",
        }
    }
}

/// An opaque reference into a future host credential manager.
///
/// The supplied opaque identifier is immediately reduced to a digest and is
/// never stored, serialized, displayed, or returned by this crate.
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    kind: SecretKind,
    revoked: bool,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_digest: self.reference_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            credential_revision: self.credential_revision,
            kind: self.kind,
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
            .field("kind", &self.kind)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest
            && self.scope_digest == other.scope_digest
            && self.credential_revision == other.credential_revision
            && self.kind == other.kind
            && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

impl SecretReference {
    pub fn new(
        opaque_reference_id: impl Into<String>,
        scope: &SapSalesOrderScope,
        credential_revision: u64,
        kind: SecretKind,
    ) -> Result<Self, ModelError> {
        let opaque_reference_id = opaque_reference_id.into();
        if !valid_opaque_input(&opaque_reference_id) {
            return Err(ModelError::InvalidOpaqueInput);
        }
        let credential_revision = Revision::new(credential_revision)?;
        let scope_digest = scope.scope_digest.clone();
        let reference_digest = Digest::from_values(
            "sap-sales-order-secret-reference/v1",
            &[
                &opaque_reference_id,
                scope_digest.as_str(),
                &credential_revision.get().to_string(),
                kind.as_str(),
            ],
        );
        Ok(Self {
            reference_digest,
            scope_digest,
            credential_revision,
            kind,
            revoked: false,
        })
    }

    pub fn oauth(
        opaque_reference_id: impl Into<String>,
        scope: &SapSalesOrderScope,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        Self::new(
            opaque_reference_id,
            scope,
            credential_revision,
            SecretKind::OAuth,
        )
    }

    pub fn client_certificate(
        opaque_reference_id: impl Into<String>,
        scope: &SapSalesOrderScope,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        Self::new(
            opaque_reference_id,
            scope,
            credential_revision,
            SecretKind::ClientCertificate,
        )
    }

    pub fn api_key(
        opaque_reference_id: impl Into<String>,
        scope: &SapSalesOrderScope,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        Self::new(
            opaque_reference_id,
            scope,
            credential_revision,
            SecretKind::ApiKey,
        )
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

    pub const fn kind(&self) -> SecretKind {
        self.kind
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
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SapRegistration {
    plugin_version: String,
    contract_version: String,
    provider_id: String,
    implementation_digest: Digest,
    contract_digest: Digest,
    provider_digest: Digest,
    permission_digest: Digest,
    scope_digest: Digest,
    registration_digest: Digest,
    state: RegistrationState,
}

impl SapRegistration {
    pub(crate) fn new(
        implementation_digest: Digest,
        contract_digest: Digest,
        provider_digest: Digest,
        scope: &SapSalesOrderScope,
        secret: &SecretReference,
    ) -> Result<Self, ModelError> {
        if secret.scope_digest != scope.scope_digest {
            return Err(ModelError::InvalidRegistration);
        }
        let permission_digest = scope.permission_lease.digest.clone();
        let registration_digest = Digest::from_parts(
            "sap-sales-order-registration/v1",
            [
                SAP_SALES_ORDER_RESULT_PLUGIN_VERSION.to_owned(),
                SAP_SALES_ORDER_RESULT_CONTRACT_VERSION.to_owned(),
                SAP_SALES_ORDER_RESULT_PROVIDER_ID.to_owned(),
                implementation_digest.as_str().to_owned(),
                contract_digest.as_str().to_owned(),
                provider_digest.as_str().to_owned(),
                permission_digest.as_str().to_owned(),
                scope.scope_digest.as_str().to_owned(),
                secret.reference_digest.as_str().to_owned(),
            ],
        );
        Ok(Self {
            plugin_version: SAP_SALES_ORDER_RESULT_PLUGIN_VERSION.to_owned(),
            contract_version: SAP_SALES_ORDER_RESULT_CONTRACT_VERSION.to_owned(),
            provider_id: SAP_SALES_ORDER_RESULT_PROVIDER_ID.to_owned(),
            implementation_digest,
            contract_digest,
            provider_digest,
            permission_digest,
            scope_digest: scope.scope_digest.clone(),
            registration_digest,
            state: RegistrationState::Active,
        })
    }

    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }

    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn implementation_digest(&self) -> &Digest {
        &self.implementation_digest
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub const fn state(&self) -> RegistrationState {
        self.state
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if !self.is_active() {
            Err(ModelError::AlreadyRevoked)
        } else {
            self.state = RegistrationState::Revoked;
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SapSalesOrderScope {
    tenant: TenantId,
    system: SystemId,
    sales_order_id: OpaqueDocumentId,
    odata_version: SapODataVersion,
    entity_sets: BTreeSet<SapEntitySet>,
    permission_lease: PermissionLease,
    project: RevisionBinding,
    mission: RevisionBinding,
    work_product: RevisionBinding,
    redaction_policy: SapRedactionPolicy,
    bounds: SapQueryBounds,
    expected_source_revision: Option<Revision>,
    expected_etag: Option<OpaqueEtag>,
    scope_digest: Digest,
}

impl SapSalesOrderScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant: impl Into<String>,
        system: impl Into<String>,
        sales_order_id: impl Into<String>,
        project_id: impl Into<String>,
        project_revision: u64,
        mission_id: impl Into<String>,
        mission_revision: u64,
        work_product_id: impl Into<String>,
        work_product_revision: u64,
    ) -> Result<Self, ModelError> {
        let tenant = TenantId::new(tenant)?;
        let system = SystemId::new(system)?;
        let sales_order_id = OpaqueDocumentId::new(sales_order_id)?;
        let project = RevisionBinding::new(project_id, project_revision)?;
        let mission = RevisionBinding::new(mission_id, mission_revision)?;
        let work_product = RevisionBinding::new(work_product_id, work_product_revision)?;
        let permission_lease = PermissionLease::read_only(1)?;
        let redaction_policy = SapRedactionPolicy::strict(1)?;
        let mut scope = Self {
            tenant,
            system,
            sales_order_id,
            odata_version: SapODataVersion::V2,
            entity_sets: SapEntitySet::ALL.into_iter().collect(),
            permission_lease,
            project,
            mission,
            work_product,
            redaction_policy,
            bounds: SapQueryBounds::default(),
            expected_source_revision: None,
            expected_etag: None,
            scope_digest: Digest::from_values("sap-sales-order-scope/uninitialized", &[]),
        };
        scope.recompute_digest();
        scope.validate()?;
        Ok(scope)
    }

    pub fn baseline(
        tenant: impl Into<String>,
        system: impl Into<String>,
        sales_order_id: impl Into<String>,
    ) -> Result<Self, ModelError> {
        Self::new(
            tenant,
            system,
            sales_order_id,
            "project-1",
            1,
            "mission-1",
            1,
            "work-product-1",
            1,
        )
    }

    pub fn with_permission_lease(
        mut self,
        permission_lease: PermissionLease,
    ) -> Result<Self, ModelError> {
        self.permission_lease = permission_lease;
        self.recompute_digest();
        self.validate()?;
        Ok(self)
    }

    pub fn with_entity_sets<I>(mut self, entity_sets: I) -> Result<Self, ModelError>
    where
        I: IntoIterator<Item = SapEntitySet>,
    {
        self.entity_sets = entity_sets.into_iter().collect();
        self.recompute_digest();
        self.validate()?;
        Ok(self)
    }

    pub fn with_bounds(mut self, bounds: SapQueryBounds) -> Result<Self, ModelError> {
        self.bounds = bounds;
        self.recompute_digest();
        self.validate()?;
        Ok(self)
    }

    pub fn with_redaction_policy(mut self, policy: SapRedactionPolicy) -> Result<Self, ModelError> {
        self.redaction_policy = policy;
        self.recompute_digest();
        self.validate()?;
        Ok(self)
    }

    pub fn with_expected_source_revision(mut self, revision: u64) -> Result<Self, ModelError> {
        self.expected_source_revision = Some(Revision::new(revision)?);
        self.recompute_digest();
        Ok(self)
    }

    pub fn with_expected_etag(mut self, raw_etag: impl Into<String>) -> Result<Self, ModelError> {
        self.expected_etag = Some(OpaqueEtag::new(raw_etag)?);
        self.recompute_digest();
        Ok(self)
    }

    fn recompute_digest(&mut self) {
        self.scope_digest = Digest::from_parts(
            "sap-sales-order-scope/v1",
            [
                self.tenant.as_str().to_owned(),
                self.system.as_str().to_owned(),
                self.sales_order_id.as_str().to_owned(),
                self.odata_version.as_str().to_owned(),
                self.entity_sets
                    .iter()
                    .map(|entity_set| entity_set.as_str().to_owned())
                    .collect::<Vec<_>>()
                    .join(","),
                self.permission_lease.digest.as_str().to_owned(),
                self.project.id.clone(),
                self.project.revision.get().to_string(),
                self.mission.id.clone(),
                self.mission.revision.get().to_string(),
                self.work_product.id.clone(),
                self.work_product.revision.get().to_string(),
                self.redaction_policy.digest().as_str().to_owned(),
                self.bounds.page_size.to_string(),
                self.bounds.max_pages.to_string(),
                self.bounds.max_items.to_string(),
                self.bounds.max_document_flow.to_string(),
                self.bounds.max_document_flow_depth.to_string(),
                self.expected_source_revision
                    .map_or_else(|| "none".to_owned(), |revision| revision.get().to_string()),
                self.expected_etag.as_ref().map_or_else(
                    || "none".to_owned(),
                    |etag| etag.digest().as_str().to_owned(),
                ),
            ],
        );
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.entity_sets.is_empty() || !self.entity_sets.contains(&SapEntitySet::SalesOrder) {
            return Err(ModelError::InvalidScope);
        }
        if !self
            .permission_lease
            .contains(SapEntitySet::SalesOrder.required_permission())
        {
            return Err(ModelError::InvalidScope);
        }
        for entity_set in &self.entity_sets {
            if !self
                .permission_lease
                .contains(entity_set.required_permission())
            {
                return Err(ModelError::InvalidScope);
            }
        }
        if !self
            .permission_lease
            .contains(SapPermission::DeliveryStatusRead)
            || !self
                .permission_lease
                .contains(SapPermission::BillingStatusRead)
        {
            return Err(ModelError::InvalidScope);
        }
        Ok(())
    }

    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    pub fn system(&self) -> &SystemId {
        &self.system
    }

    pub fn sales_order_id(&self) -> &OpaqueDocumentId {
        &self.sales_order_id
    }

    pub const fn odata_version(&self) -> SapODataVersion {
        self.odata_version
    }

    pub fn entity_sets(&self) -> &BTreeSet<SapEntitySet> {
        &self.entity_sets
    }

    pub fn permission_lease(&self) -> &PermissionLease {
        &self.permission_lease
    }

    pub fn project(&self) -> &RevisionBinding {
        &self.project
    }

    pub fn mission(&self) -> &RevisionBinding {
        &self.mission
    }

    pub fn work_product(&self) -> &RevisionBinding {
        &self.work_product
    }

    pub const fn redaction_policy(&self) -> SapRedactionPolicy {
        self.redaction_policy
    }

    pub const fn bounds(&self) -> SapQueryBounds {
        self.bounds
    }

    pub const fn expected_source_revision(&self) -> Option<Revision> {
        self.expected_source_revision
    }

    pub fn expected_etag(&self) -> Option<&OpaqueEtag> {
        self.expected_etag.as_ref()
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn revision_fence(&self) -> RevisionFence {
        RevisionFence::from_scope(self)
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct SapODataRow {
    entity_set: SapEntitySet,
    safe_fields: BTreeMap<String, String>,
    redaction: RedactionSummary,
}

impl SapODataRow {
    pub fn from_raw_fields(
        entity_set: SapEntitySet,
        fields: BTreeMap<String, String>,
    ) -> Result<Self, ModelError> {
        let allowlist = allowlisted_fields(entity_set);
        let mut safe_fields = BTreeMap::new();
        let mut redaction = RedactionSummary::new();
        for (field_name, value) in fields {
            if !allowlist.contains(&field_name.as_str()) || is_sensitive_field(&field_name) {
                redaction.record_field(&field_name);
                continue;
            }
            if value.len() > MAX_FIELD_VALUE_BYTES {
                redaction.record_field(&field_name);
                continue;
            }
            let normalized = match field_name.as_str() {
                "SalesOrder" | "PrecedingDocument" | "SubsequentDocument" | "DeliveryDocument"
                | "BillingDocument" => OpaqueDocumentId::new(value)
                    .map(|document_id| document_id.as_str().to_owned())
                    .map_err(|_| ModelError::InvalidRow)?,
                "ETag" => OpaqueEtag::new(value)
                    .map(|etag| etag.digest().as_str().to_owned())
                    .map_err(|_| ModelError::InvalidRow)?,
                _ => value,
            };
            safe_fields.insert(field_name, normalized);
        }
        Ok(Self {
            entity_set,
            safe_fields,
            redaction,
        })
    }

    pub fn entity_set(&self) -> SapEntitySet {
        self.entity_set
    }

    pub fn field(&self, name: &str) -> Option<&str> {
        self.safe_fields.get(name).map(String::as_str)
    }

    pub fn fields(&self) -> &BTreeMap<String, String> {
        &self.safe_fields
    }

    pub fn redaction(&self) -> &RedactionSummary {
        &self.redaction
    }
}

impl fmt::Debug for SapODataRow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SapODataRow")
            .field("entity_set", &self.entity_set)
            .field("field_names", &self.safe_fields.keys().collect::<Vec<_>>())
            .field("redaction", &self.redaction)
            .finish()
    }
}

fn is_sensitive_field(field_name: &str) -> bool {
    let lower = field_name.to_ascii_lowercase();
    [
        "partner",
        "customer",
        "address",
        "email",
        "telephone",
        "phone",
        "free_text",
        "longtext",
        "note",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SapODataPage {
    entity_set: SapEntitySet,
    rows: Vec<SapODataRow>,
    next_skip: Option<u32>,
    etag: Option<OpaqueEtag>,
    source_revision: Revision,
    redaction: RedactionSummary,
}

impl SapODataPage {
    pub fn new(
        entity_set: SapEntitySet,
        raw_rows: Vec<BTreeMap<String, String>>,
        next_skip: Option<u32>,
        etag: Option<impl Into<String>>,
        source_revision: u64,
    ) -> Result<Self, ModelError> {
        let rows = raw_rows
            .into_iter()
            .map(|fields| SapODataRow::from_raw_fields(entity_set, fields))
            .collect::<Result<Vec<_>, _>>()?;
        Self::from_rows(entity_set, rows, next_skip, etag, source_revision)
    }

    pub fn from_rows(
        entity_set: SapEntitySet,
        rows: Vec<SapODataRow>,
        next_skip: Option<u32>,
        etag: Option<impl Into<String>>,
        source_revision: u64,
    ) -> Result<Self, ModelError> {
        if rows.iter().any(|row| row.entity_set != entity_set) {
            return Err(ModelError::InvalidRow);
        }
        let source_revision = Revision::new(source_revision)?;
        let etag = etag.map(OpaqueEtag::new).transpose()?;
        let mut redaction = RedactionSummary::new();
        for row in &rows {
            redaction.merge(&row.redaction);
        }
        Ok(Self {
            entity_set,
            rows,
            next_skip,
            etag,
            source_revision,
            redaction,
        })
    }

    pub fn from_json(
        entity_set: SapEntitySet,
        json: &str,
        etag: Option<impl Into<String>>,
        source_revision: u64,
    ) -> Result<Self, ModelError> {
        let value: serde_json::Value =
            serde_json::from_str(json).map_err(|_| ModelError::InvalidRow)?;
        let data = value.get("d").unwrap_or(&value);
        let rows = if let Some(results) = data.get("results").and_then(serde_json::Value::as_array)
        {
            results.clone()
        } else if let Some(values) = value.get("value").and_then(serde_json::Value::as_array) {
            values.clone()
        } else if data.is_object() {
            vec![data.clone()]
        } else {
            return Err(ModelError::InvalidRow);
        };
        let raw_rows = rows
            .into_iter()
            .filter_map(|row| row.as_object().cloned())
            .map(|object| {
                object
                    .into_iter()
                    .filter_map(|(key, value)| scalar_text(&value).map(|value| (key, value)))
                    .collect::<BTreeMap<_, _>>()
            })
            .collect::<Vec<_>>();
        let next_skip = data
            .get("nextSkip")
            .or_else(|| data.get("next_skip"))
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| u32::try_from(value).ok());
        let next_link = data
            .get("__next")
            .or_else(|| data.get("@odata.nextLink"))
            .and_then(serde_json::Value::as_str);
        let next_skip = next_skip.or_else(|| next_link.and_then(parse_skip_from_link));
        if next_link.is_some() && next_skip.is_none() {
            return Err(ModelError::InvalidQuery);
        }
        Self::new(entity_set, raw_rows, next_skip, etag, source_revision)
    }

    pub fn entity_set(&self) -> SapEntitySet {
        self.entity_set
    }

    pub fn rows(&self) -> &[SapODataRow] {
        &self.rows
    }

    pub const fn next_skip(&self) -> Option<u32> {
        self.next_skip
    }

    pub fn etag(&self) -> Option<&OpaqueEtag> {
        self.etag.as_ref()
    }

    pub const fn source_revision(&self) -> Revision {
        self.source_revision
    }

    pub fn redaction(&self) -> &RedactionSummary {
        &self.redaction
    }
}

fn parse_skip_from_link(link: &str) -> Option<u32> {
    link.split(['?', '&'])
        .filter_map(|part| part.split_once('='))
        .find_map(|(key, value)| {
            matches!(key, "$skip" | "skip")
                .then(|| value.parse::<u32>().ok())
                .flatten()
        })
}

fn scalar_text(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(value) => Some(value.clone()),
        serde_json::Value::Number(value) => Some(value.to_string()),
        serde_json::Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderLifecycleState {
    Created,
    Open,
    InProcess,
    Completed,
    Cancelled,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FulfillmentState {
    NotStarted,
    InProgress,
    Partial,
    Complete,
    Blocked,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockState {
    None,
    Delivery,
    Billing,
    DeliveryAndBilling,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MoneySummary {
    pub currency: Option<String>,
    pub amount: Option<String>,
}

impl MoneySummary {
    pub fn new(currency: Option<String>, amount: Option<String>) -> Result<Self, ModelError> {
        if let Some(currency) = &currency
            && (currency.len() != 3 || !currency.bytes().all(|byte| byte.is_ascii_uppercase()))
        {
            return Err(ModelError::InvalidCurrency);
        }
        if let Some(amount) = &amount
            && !valid_decimal(amount)
        {
            return Err(ModelError::InvalidDecimal);
        }
        Ok(Self { currency, amount })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SalesOrderHeaderProjection {
    pub document_id: OpaqueDocumentId,
    pub lifecycle: OrderLifecycleState,
    pub order_type: Option<String>,
    pub created_date: Option<String>,
    pub last_changed_date: Option<String>,
    pub money: MoneySummary,
    pub delivery_status: FulfillmentState,
    pub billing_status: FulfillmentState,
    pub block_state: BlockState,
    pub etag: Option<OpaqueEtag>,
    pub source_revision: Revision,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SalesOrderItemProjection {
    pub item_id: String,
    pub material_digest: Option<Digest>,
    pub requested_quantity: Option<String>,
    pub requested_quantity_unit: Option<String>,
    pub money: MoneySummary,
    pub delivery_status: FulfillmentState,
    pub billing_status: FulfillmentState,
    pub block_state: BlockState,
    pub etag: Option<OpaqueEtag>,
    pub source_revision: Revision,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SalesOrderDocumentFlowProjection {
    pub preceding_document_id: Option<OpaqueDocumentId>,
    pub subsequent_document_id: Option<OpaqueDocumentId>,
    pub delivery_document_id: Option<OpaqueDocumentId>,
    pub billing_document_id: Option<OpaqueDocumentId>,
    pub preceding_item_id: Option<String>,
    pub subsequent_item_id: Option<String>,
    pub document_category: Option<String>,
    pub document_flow_status: Option<String>,
    pub depth: u8,
    pub created_date: Option<String>,
    pub last_changed_date: Option<String>,
    pub etag: Option<OpaqueEtag>,
    pub source_revision: Revision,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SapTransportProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl SapTransportProvenance {
    pub const fn is_connected(self) -> bool {
        false
    }

    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_first_party(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SapProviderErrorKind {
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    RateLimited,
    ServerFailure,
    Timeout,
    BlockedEnvironment,
    Transport,
    InvalidResponse,
    ScopeMismatch,
    PermissionMismatch,
    RegistrationRevoked,
    SecretRevoked,
    EtagDrift,
    RevisionDrift,
    PageLoop,
    ProviderUnknown,
}

impl SapProviderErrorKind {
    pub const fn observation_state(self) -> SapObservationState {
        match self {
            Self::NotFound => SapObservationState::Deleted,
            Self::Unauthorized | Self::Forbidden | Self::SecretRevoked => {
                SapObservationState::AccessLost
            }
            Self::Conflict | Self::EtagDrift | Self::RevisionDrift => {
                SapObservationState::RevisionConflict
            }
            Self::RateLimited
            | Self::ServerFailure
            | Self::Timeout
            | Self::BlockedEnvironment
            | Self::Transport
            | Self::InvalidResponse
            | Self::ScopeMismatch
            | Self::PermissionMismatch
            | Self::RegistrationRevoked
            | Self::PageLoop
            | Self::ProviderUnknown => SapObservationState::ProviderUnknown,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProviderErrorEvidence {
    pub kind: SapProviderErrorKind,
    pub http_status: Option<u16>,
    pub retry_after_seconds: Option<u32>,
    pub error_digest: Digest,
    pub state: SapObservationState,
}

impl ProviderErrorEvidence {
    pub(crate) fn new(
        kind: SapProviderErrorKind,
        http_status: Option<u16>,
        retry_after_seconds: Option<u32>,
        detail: &str,
    ) -> Self {
        Self {
            kind,
            http_status,
            retry_after_seconds,
            error_digest: Digest::from_values("sap-sales-order-provider-error/v1", &[detail]),
            state: kind.observation_state(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SapObservationState {
    Available,
    Partial,
    Deleted,
    AccessLost,
    RevisionConflict,
    ProviderUnknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SapSalesOrderEvidence {
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub registration_digest: Digest,
    pub order: SalesOrderHeaderProjection,
    pub items: Vec<SalesOrderItemProjection>,
    pub document_flow: Vec<SalesOrderDocumentFlowProjection>,
    pub fulfillment_state: FulfillmentState,
    pub block_state: BlockState,
    pub source_revision: Revision,
    pub etag: Option<OpaqueEtag>,
    pub redaction: RedactionSummary,
    pub partial: bool,
    pub request_digest: Digest,
    pub result_digest: Digest,
    pub provenance: SapTransportProvenance,
    pub revision_fence: RevisionFence,
}

impl SapSalesOrderEvidence {
    pub const fn connected(&self) -> bool {
        false
    }

    pub const fn native(&self) -> bool {
        false
    }

    pub const fn first_party(&self) -> bool {
        false
    }

    pub const fn durable_native_receipt(&self) -> bool {
        false
    }

    pub const fn independent_read_back(&self) -> bool {
        false
    }

    pub const fn kernel_outcome_adoption(&self) -> bool {
        false
    }

    pub fn digest(&self) -> &Digest {
        &self.result_digest
    }

    pub fn state(&self) -> SapObservationState {
        if self.partial {
            SapObservationState::Partial
        } else {
            SapObservationState::Available
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SapSalesOrderObservation {
    pub state: SapObservationState,
    pub evidence: Option<SapSalesOrderEvidence>,
    pub error: Option<ProviderErrorEvidence>,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub registration_digest: Digest,
    pub provenance: SapTransportProvenance,
    pub revision_fence: RevisionFence,
    pub observation_digest: Digest,
}

impl SapSalesOrderObservation {
    pub fn from_evidence(evidence: SapSalesOrderEvidence) -> Self {
        let state = evidence.state();
        let observation_digest = Digest::from_parts(
            "sap-sales-order-observation/v1",
            [
                evidence.result_digest.as_str().to_owned(),
                format!("{state:?}"),
            ],
        );
        Self {
            state,
            scope_digest: evidence.scope_digest.clone(),
            permission_digest: evidence.permission_digest.clone(),
            registration_digest: evidence.registration_digest.clone(),
            provenance: evidence.provenance,
            revision_fence: evidence.revision_fence.clone(),
            evidence: Some(evidence),
            error: None,
            observation_digest,
        }
    }

    pub fn from_error(
        scope_digest: Digest,
        permission_digest: Digest,
        registration_digest: Digest,
        provenance: SapTransportProvenance,
        revision_fence: RevisionFence,
        error: ProviderErrorEvidence,
    ) -> Self {
        let state = error.state;
        let observation_digest = Digest::from_parts(
            "sap-sales-order-observation-error/v1",
            [
                scope_digest.as_str().to_owned(),
                permission_digest.as_str().to_owned(),
                registration_digest.as_str().to_owned(),
                error.error_digest.as_str().to_owned(),
            ],
        );
        Self {
            state,
            evidence: None,
            error: Some(error),
            scope_digest,
            permission_digest,
            registration_digest,
            provenance,
            revision_fence,
            observation_digest,
        }
    }

    pub const fn connected(&self) -> bool {
        false
    }

    pub const fn native(&self) -> bool {
        false
    }

    pub const fn first_party(&self) -> bool {
        false
    }

    pub fn digest(&self) -> &Digest {
        &self.observation_digest
    }
}

pub(crate) fn digest_safe_fields(fields: impl IntoIterator<Item = String>) -> Digest {
    Digest::from_parts("sap-sales-order-safe-fields/v1", fields)
}

pub(crate) fn parse_opaque_document_id(
    value: Option<&str>,
    fallback: &OpaqueDocumentId,
) -> OpaqueDocumentId {
    value
        .and_then(|value| Digest::parse(value.to_owned()).ok())
        .map_or_else(|| fallback.clone(), OpaqueDocumentId::from_digest)
}

pub(crate) fn parse_opaque_etag(value: Option<&str>) -> Option<OpaqueEtag> {
    value
        .and_then(|value| Digest::parse(value.to_owned()).ok())
        .map(OpaqueEtag::from_digest)
}

//! Typed, redacted models for the bounded Ramp Layer-1 spend-evidence seam.
//!
//! Provider payloads are intentionally converted into this module's digest and
//! bucket forms before they can cross the provider boundary.  No type here
//! stores card numbers, CVV, bank details, employee/vendor PII, receipt bytes,
//! raw OAuth material, or arbitrary memo/comment text.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as ShaDigest, Sha256};

use crate::{
    MAX_AUDIT_EVENTS, MAX_CATEGORY_VALUES, MAX_CURSOR_BYTES, MAX_DATE_WINDOW_SECONDS,
    MAX_EVENT_TYPE_BYTES, MAX_IDENTIFIER_BYTES, MAX_MERCHANTS, MAX_PAGE_SIZE, MAX_PAGES,
    MAX_SPEND_TOTAL_MINOR, MAX_TRANSACTIONS,
};

pub type Digest = String;

#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    format!("{:x}", Sha256::digest(bytes))
}

#[must_use]
pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("typed Ramp value serializes");
    sha256_digest(&bytes)
}

pub(crate) fn validate_identifier(
    value: &str,
    field: &'static str,
) -> Result<(), crate::RampSpendOutcomeError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
        || value.chars().any(char::is_whitespace)
    {
        return Err(crate::RampSpendOutcomeError::InvalidIdentifier { field });
    }
    Ok(())
}

pub(crate) fn validate_bounded_text(
    value: &str,
    field: &'static str,
    maximum: usize,
) -> Result<(), crate::RampSpendOutcomeError> {
    if value.is_empty()
        || value.len() > maximum
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(crate::RampSpendOutcomeError::InvalidIdentifier { field });
    }
    Ok(())
}

pub(crate) fn validate_digest(
    value: &str,
    field: &'static str,
) -> Result<(), crate::RampSpendOutcomeError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(crate::RampSpendOutcomeError::InvalidDigest { field });
    }
    Ok(())
}

/// An opaque host-owned handle.  The underlying identifier is never exposed
/// through `Serialize`, `Deserialize`, `Display`, or `Debug`.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretKind,
    opaque_id: String,
    revision: u64,
}

impl SecretReference {
    pub fn oauth(
        opaque_id: impl Into<String>,
        revision: u64,
    ) -> Result<Self, crate::RampSpendOutcomeError> {
        Self::new(SecretKind::OAuth, opaque_id, revision)
    }

    pub fn client_credentials(
        opaque_id: impl Into<String>,
        revision: u64,
    ) -> Result<Self, crate::RampSpendOutcomeError> {
        Self::new(SecretKind::ClientCredentials, opaque_id, revision)
    }

    fn new(
        kind: SecretKind,
        opaque_id: impl Into<String>,
        revision: u64,
    ) -> Result<Self, crate::RampSpendOutcomeError> {
        let opaque_id = opaque_id.into();
        if revision == 0
            || opaque_id.is_empty()
            || opaque_id.len() > MAX_IDENTIFIER_BYTES
            || opaque_id.trim() != opaque_id
            || opaque_id.chars().any(char::is_control)
        {
            return Err(crate::RampSpendOutcomeError::InvalidSecretReference);
        }
        Ok(Self {
            kind,
            opaque_id,
            revision,
        })
    }

    #[must_use]
    pub const fn kind(&self) -> SecretKind {
        self.kind
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        sha256_digest(
            format!(
                "ramp-secret-reference|{}|{}|{}",
                self.kind.label(),
                self.revision,
                self.opaque_id
            )
            .as_bytes(),
        )
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("kind", &self.kind)
            .field("revision", &self.revision)
            .field("opaque_id", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    OAuth,
    ClientCredentials,
}

impl SecretKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::OAuth => "oauth",
            Self::ClientCredentials => "client_credentials",
        }
    }
}

/// A provider identifier retained only as a digest in serialized scope and
/// evidence.  The raw identifier is available only inside this crate while a
/// request is being assembled.
#[derive(Clone, Eq, PartialEq)]
pub struct BoundIdentifier {
    value: String,
}

impl BoundIdentifier {
    pub(crate) fn new(
        value: impl Into<String>,
        field: &'static str,
    ) -> Result<Self, crate::RampSpendOutcomeError> {
        let value = value.into();
        validate_identifier(&value, field)?;
        Ok(Self { value })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        sha256_digest(self.value.as_bytes())
    }

    pub(crate) fn raw(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for BoundIdentifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundIdentifier")
            .field("digest", &self.digest())
            .field("value", &"<redacted>")
            .finish()
    }
}

impl Serialize for BoundIdentifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.digest())
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RampReadScope {
    BusinessRead,
    EntitiesRead,
    SpendProgramsRead,
    FundsRead,
    CardsRead,
    MerchantsRead,
    VendorsRead,
    TransactionsRead,
    AuditLogsRead,
}

impl RampReadScope {
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::BusinessRead => "business:read",
            Self::EntitiesRead => "entities:read",
            Self::SpendProgramsRead => "spend_programs:read",
            Self::FundsRead => "funds:read",
            Self::CardsRead => "cards:read",
            Self::MerchantsRead => "merchants:read",
            Self::VendorsRead => "vendors:read",
            Self::TransactionsRead => "transactions:read",
            Self::AuditLogsRead => "audit_logs:read",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionSnapshot {
    pub requested: BTreeSet<RampReadScope>,
    pub granted: BTreeSet<RampReadScope>,
    pub revision: u64,
}

impl PermissionSnapshot {
    pub fn new(
        requested: BTreeSet<RampReadScope>,
        granted: BTreeSet<RampReadScope>,
        revision: u64,
    ) -> Result<Self, crate::RampSpendOutcomeError> {
        let snapshot = Self {
            requested,
            granted,
            revision,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    #[must_use]
    pub fn least_privilege_for(spec: &RampSpendScopeSpec) -> Self {
        let mut scopes = BTreeSet::from([
            RampReadScope::BusinessRead,
            RampReadScope::TransactionsRead,
            RampReadScope::MerchantsRead,
            RampReadScope::AuditLogsRead,
        ]);
        if spec.entity_id.is_some() {
            scopes.insert(RampReadScope::EntitiesRead);
        }
        if spec.spend_program_id.is_some() {
            scopes.insert(RampReadScope::SpendProgramsRead);
        }
        if spec.card_id.is_some() {
            scopes.insert(RampReadScope::CardsRead);
        }
        if spec.vendor_id.is_some() {
            scopes.insert(RampReadScope::VendorsRead);
        }
        Self {
            requested: scopes.clone(),
            granted: scopes,
            revision: 1,
        }
    }

    pub fn validate(&self) -> Result<(), crate::RampSpendOutcomeError> {
        if self.revision == 0
            || self.requested.is_empty()
            || self.requested != self.granted
            || self
                .requested
                .iter()
                .any(|scope| !scope.label().ends_with(":read"))
        {
            return Err(crate::RampSpendOutcomeError::InvalidPermissionSnapshot);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    #[must_use]
    pub fn has(&self, scope: RampReadScope) -> bool {
        self.granted.contains(&scope)
    }

    pub(crate) fn require(&self, scope: RampReadScope) -> Result<(), crate::RampSpendOutcomeError> {
        if self.has(scope.clone()) {
            Ok(())
        } else {
            Err(crate::RampSpendOutcomeError::MissingReadScope {
                scope: scope.label(),
            })
        }
    }
}

impl<'de> Deserialize<'de> for PermissionSnapshot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            requested: BTreeSet<RampReadScope>,
            granted: BTreeSet<RampReadScope>,
            revision: u64,
        }

        let wire = Wire::deserialize(deserializer)?;
        let snapshot = Self {
            requested: wire.requested,
            granted: wire.granted,
            revision: wire.revision,
        };
        snapshot.validate().map_err(serde::de::Error::custom)?;
        Ok(snapshot)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DateWindow {
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
}

impl<'de> Deserialize<'de> for DateWindow {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            from: DateTime<Utc>,
            to: DateTime<Utc>,
        }

        let wire = Wire::deserialize(deserializer)?;
        let window = Self {
            from: wire.from,
            to: wire.to,
        };
        window.validate().map_err(serde::de::Error::custom)?;
        Ok(window)
    }
}

impl DateWindow {
    pub fn closed(
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Self, crate::RampSpendOutcomeError> {
        let window = Self { from, to };
        window.validate()?;
        Ok(window)
    }

    pub fn validate(&self) -> Result<(), crate::RampSpendOutcomeError> {
        let seconds = (self.to - self.from).num_seconds();
        if self.to <= self.from || seconds <= 0 || seconds > MAX_DATE_WINDOW_SECONDS {
            return Err(crate::RampSpendOutcomeError::InvalidDateWindow);
        }
        Ok(())
    }

    #[must_use]
    pub fn contains(&self, value: DateTime<Utc>) -> bool {
        value >= self.from && value <= self.to
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityBinding {
    pub id: String,
    pub revision: u64,
}

impl IdentityBinding {
    pub fn new(
        id: impl Into<String>,
        revision: u64,
        field: &'static str,
    ) -> Result<Self, crate::RampSpendOutcomeError> {
        let id = id.into();
        validate_identifier(&id, field)?;
        if revision == 0 {
            return Err(crate::RampSpendOutcomeError::InvalidIdentifier { field });
        }
        Ok(Self { id, revision })
    }

    pub fn validate(&self, field: &'static str) -> Result<(), crate::RampSpendOutcomeError> {
        validate_identifier(&self.id, field)?;
        if self.revision == 0 {
            return Err(crate::RampSpendOutcomeError::InvalidIdentifier { field });
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for IdentityBinding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            id: String,
            revision: u64,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.id, wire.revision, "identity id").map_err(serde::de::Error::custom)
    }
}

pub type ProjectBinding = IdentityBinding;
pub type MissionBinding = IdentityBinding;
pub type WorkProductBinding = IdentityBinding;
pub type DeploymentBinding = IdentityBinding;
pub type ReleaseBinding = IdentityBinding;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpendConstraints {
    pub currency_code: Option<String>,
    pub category_id: Option<String>,
    pub category_name: Option<String>,
    pub max_total_minor: i64,
    pub expected_total_minor: Option<i64>,
}

impl Default for SpendConstraints {
    fn default() -> Self {
        Self {
            currency_code: None,
            category_id: None,
            category_name: None,
            max_total_minor: MAX_SPEND_TOTAL_MINOR,
            expected_total_minor: None,
        }
    }
}

impl SpendConstraints {
    pub fn validate(&self) -> Result<(), crate::RampSpendOutcomeError> {
        if let Some(currency_code) = &self.currency_code {
            validate_currency_code(currency_code)?;
        }
        if let Some(category_id) = &self.category_id {
            validate_identifier(category_id, "category id")?;
        }
        if let Some(category_name) = &self.category_name {
            validate_bounded_text(category_name, "category name", MAX_IDENTIFIER_BYTES)?;
        }
        if self.max_total_minor <= 0 || self.max_total_minor > MAX_SPEND_TOTAL_MINOR {
            return Err(crate::RampSpendOutcomeError::InvalidScope);
        }
        if let Some(expected_total_minor) = self.expected_total_minor
            && expected_total_minor.unsigned_abs() > self.max_total_minor as u64
        {
            return Err(crate::RampSpendOutcomeError::InvalidScope);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

impl<'de> Deserialize<'de> for SpendConstraints {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            currency_code: Option<String>,
            category_id: Option<String>,
            category_name: Option<String>,
            max_total_minor: i64,
            expected_total_minor: Option<i64>,
        }

        let wire = Wire::deserialize(deserializer)?;
        let constraints = Self {
            currency_code: wire.currency_code,
            category_id: wire.category_id,
            category_name: wire.category_name,
            max_total_minor: wire.max_total_minor,
            expected_total_minor: wire.expected_total_minor,
        };
        constraints.validate().map_err(serde::de::Error::custom)?;
        Ok(constraints)
    }
}

#[derive(Clone)]
pub struct RampSpendScopeSpec {
    pub business_id: String,
    pub entity_id: Option<String>,
    pub spend_program_id: Option<String>,
    pub card_id: Option<String>,
    pub vendor_id: Option<String>,
    pub transaction_id: Option<String>,
    pub audit_event_id: Option<String>,
    pub date_window: DateWindow,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub deployment: Option<DeploymentBinding>,
    pub release: Option<ReleaseBinding>,
    pub policy_revision: u64,
    pub spend_constraints: SpendConstraints,
    pub permissions: PermissionSnapshot,
}

impl fmt::Debug for RampSpendScopeSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RampSpendScopeSpec")
            .field("business_id", &"<redacted>")
            .field("entity_id", &self.entity_id.as_ref().map(|_| "<redacted>"))
            .field(
                "spend_program_id",
                &self.spend_program_id.as_ref().map(|_| "<redacted>"),
            )
            .field("card_id", &self.card_id.as_ref().map(|_| "<redacted>"))
            .field("vendor_id", &self.vendor_id.as_ref().map(|_| "<redacted>"))
            .field(
                "transaction_id",
                &self.transaction_id.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "audit_event_id",
                &self.audit_event_id.as_ref().map(|_| "<redacted>"),
            )
            .field("date_window", &self.date_window)
            .field("policy_revision", &self.policy_revision)
            .field("project", &"<redacted>")
            .field("mission", &"<redacted>")
            .field("work_product", &"<redacted>")
            .field(
                "deployment",
                &self.deployment.as_ref().map(|_| "<redacted>"),
            )
            .field("release", &self.release.as_ref().map(|_| "<redacted>"))
            .field("permissions", &self.permissions)
            .field("spend_constraints", &self.spend_constraints)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RampSpendScope {
    pub business_id: BoundIdentifier,
    pub entity_id: Option<BoundIdentifier>,
    pub spend_program_id: Option<BoundIdentifier>,
    pub card_id: Option<BoundIdentifier>,
    pub vendor_id: Option<BoundIdentifier>,
    pub transaction_id: Option<BoundIdentifier>,
    pub audit_event_id: Option<BoundIdentifier>,
    pub date_window: DateWindow,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub deployment: Option<DeploymentBinding>,
    pub release: Option<ReleaseBinding>,
    pub policy_revision: u64,
    pub spend_constraints: SpendConstraints,
    pub permissions: PermissionSnapshot,
    pub secret_kind: SecretKind,
    pub secret_revision: u64,
    pub secret_reference_digest: Digest,
}

impl RampSpendScope {
    pub fn new(
        spec: RampSpendScopeSpec,
        secret_reference: &SecretReference,
    ) -> Result<Self, crate::RampSpendOutcomeError> {
        let scope = Self {
            business_id: BoundIdentifier::new(spec.business_id, "business id")?,
            entity_id: spec
                .entity_id
                .map(|value| BoundIdentifier::new(value, "entity id"))
                .transpose()?,
            spend_program_id: spec
                .spend_program_id
                .map(|value| BoundIdentifier::new(value, "spend program id"))
                .transpose()?,
            card_id: spec
                .card_id
                .map(|value| BoundIdentifier::new(value, "card id"))
                .transpose()?,
            vendor_id: spec
                .vendor_id
                .map(|value| BoundIdentifier::new(value, "vendor id"))
                .transpose()?,
            transaction_id: spec
                .transaction_id
                .map(|value| BoundIdentifier::new(value, "transaction id"))
                .transpose()?,
            audit_event_id: spec
                .audit_event_id
                .map(|value| BoundIdentifier::new(value, "audit event id"))
                .transpose()?,
            date_window: spec.date_window,
            project: spec.project,
            mission: spec.mission,
            work_product: spec.work_product,
            deployment: spec.deployment,
            release: spec.release,
            policy_revision: spec.policy_revision,
            spend_constraints: spec.spend_constraints,
            permissions: spec.permissions,
            secret_kind: secret_reference.kind(),
            secret_revision: secret_reference.revision(),
            secret_reference_digest: secret_reference.digest(),
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), crate::RampSpendOutcomeError> {
        self.date_window.validate()?;
        self.spend_constraints.validate()?;
        self.permissions.validate()?;
        self.permissions.require(RampReadScope::BusinessRead)?;
        self.permissions.require(RampReadScope::TransactionsRead)?;
        self.permissions.require(RampReadScope::MerchantsRead)?;
        self.permissions.require(RampReadScope::AuditLogsRead)?;
        if self.entity_id.is_some() {
            self.permissions.require(RampReadScope::EntitiesRead)?;
        }
        if self.spend_program_id.is_some() {
            self.permissions.require(RampReadScope::SpendProgramsRead)?;
        }
        if self.card_id.is_some() {
            self.permissions.require(RampReadScope::CardsRead)?;
        }
        if self.vendor_id.is_some() {
            self.permissions.require(RampReadScope::VendorsRead)?;
        }
        if self.policy_revision == 0
            || self.secret_revision == 0
            || self.project.revision == 0
            || self.mission.revision == 0
            || self.work_product.revision == 0
        {
            return Err(crate::RampSpendOutcomeError::InvalidScope);
        }
        self.project.validate("project id")?;
        self.mission.validate("mission id")?;
        self.work_product.validate("work product id")?;
        if let Some(deployment) = &self.deployment {
            deployment.validate("deployment id")?;
        }
        if let Some(release) = &self.release {
            release.validate("release id")?;
        }
        validate_digest(&self.secret_reference_digest, "secret reference")?;
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    #[must_use]
    pub fn matches_identifier(
        &self,
        expected: &Option<BoundIdentifier>,
        actual: Option<&str>,
    ) -> bool {
        match (expected, actual) {
            (None, _) => true,
            (Some(expected), Some(actual)) => expected.raw() == actual,
            (Some(_), None) => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionState {
    PendingInitiation,
    Pending,
    Authorized,
    Cleared,
    Completion,
    Declined,
    Error,
    Refunded,
    Reversed,
    ProviderUnknown,
}

impl TransactionState {
    pub(crate) fn parse(value: &str) -> Self {
        match value.to_ascii_uppercase().as_str() {
            "PENDING_INITIATION" => Self::PendingInitiation,
            "PENDING" => Self::Pending,
            "AUTHORIZED" | "AUTHORIZATION" => Self::Authorized,
            "CLEARED" => Self::Cleared,
            "COMPLETION" | "COMPLETED" => Self::Completion,
            "DECLINED" => Self::Declined,
            "ERROR" => Self::Error,
            "REFUNDED" | "REFUND" => Self::Refunded,
            "REVERSED" | "REVERSAL" => Self::Reversed,
            _ => Self::ProviderUnknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RefundState {
    NotRefunded,
    Partial,
    Full,
    Reversed,
    ProviderUnknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AmountBucket {
    Zero,
    UnderOneHundred,
    OneHundredToOneThousand,
    OneThousandToTenThousand,
    TenThousandOrMore,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorClass {
    PolicyAgent,
    Ramp,
    SpendRequestAgent,
    User,
    ProviderUnknown,
}

impl ActorClass {
    pub(crate) fn parse(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "policy_agent" => Self::PolicyAgent,
            "ramp" => Self::Ramp,
            "spend_request_agent" => Self::SpendRequestAgent,
            "user" => Self::User,
            _ => Self::ProviderUnknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Transaction,
    AuditEvent,
    VendorMerchant,
    Card,
    SpendProgram,
    Fund,
    Business,
    Entity,
    ProviderUnknown,
}

impl ResourceKind {
    pub(crate) fn parse(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "transaction" => Self::Transaction,
            "vendor / merchant" | "vendor_merchant" | "merchant" | "vendor" => Self::VendorMerchant,
            "card" => Self::Card,
            "spend program" | "spend_program" => Self::SpendProgram,
            "fund" => Self::Fund,
            "business" => Self::Business,
            "entity" => Self::Entity,
            _ => Self::ProviderUnknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Complete,
    Partial,
    RetentionGap,
    AccessLost,
    Tampered,
    ProviderUnknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    OfficialApiParser,
    Recording,
    Fixture,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    #[must_use]
    pub const fn is_native(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_connected(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransactionEvidence {
    pub transaction_id_digest: Digest,
    pub state: TransactionState,
    pub refund_state: RefundState,
    pub amount_bucket: AmountBucket,
    pub amount_digest: Option<Digest>,
    pub currency_code: Option<String>,
    pub entity_id_digest: Option<Digest>,
    pub spend_program_id_digest: Option<Digest>,
    pub card_id_digest: Option<Digest>,
    pub vendor_id_digest: Option<Digest>,
    pub vendor_name_digest: Option<Digest>,
    pub category_id_digest: Option<Digest>,
    pub category_name_digest: Option<Digest>,
    pub original_transaction_id_digest: Option<Digest>,
    pub transaction_time: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
    pub settlement_date: Option<DateTime<Utc>>,
}

impl TransactionEvidence {
    fn validate(&self) -> Result<(), crate::RampSpendOutcomeError> {
        validate_digest(&self.transaction_id_digest, "transaction")?;
        if self.state == TransactionState::ProviderUnknown
            || self.refund_state == RefundState::ProviderUnknown
        {
            return Err(crate::RampSpendOutcomeError::ProviderUnknown);
        }
        if let Some(currency_code) = &self.currency_code {
            validate_currency_code(currency_code)?;
        }
        for (field, digest) in [
            ("amount", self.amount_digest.as_ref()),
            ("entity", self.entity_id_digest.as_ref()),
            ("spend program", self.spend_program_id_digest.as_ref()),
            ("card", self.card_id_digest.as_ref()),
            ("vendor", self.vendor_id_digest.as_ref()),
            ("vendor name", self.vendor_name_digest.as_ref()),
            ("category", self.category_id_digest.as_ref()),
            ("category name", self.category_name_digest.as_ref()),
            (
                "original transaction",
                self.original_transaction_id_digest.as_ref(),
            ),
        ] {
            if let Some(digest) = digest {
                validate_digest(digest, field)?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MerchantEvidence {
    pub merchant_id_digest: Digest,
    pub merchant_name_digest: Digest,
    pub category_name_digest: Option<Digest>,
}

impl MerchantEvidence {
    fn validate(&self) -> Result<(), crate::RampSpendOutcomeError> {
        validate_digest(&self.merchant_id_digest, "merchant")?;
        validate_digest(&self.merchant_name_digest, "merchant name")?;
        if let Some(digest) = &self.category_name_digest {
            validate_digest(digest, "merchant category")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditEventEvidence {
    pub audit_event_id_digest: Digest,
    pub event_type_digest: Digest,
    pub actor_class: ActorClass,
    pub resource_kind: ResourceKind,
    pub resource_id_digest: Option<Digest>,
    pub event_time: DateTime<Utc>,
}

impl AuditEventEvidence {
    fn validate(&self) -> Result<(), crate::RampSpendOutcomeError> {
        validate_digest(&self.audit_event_id_digest, "audit event")?;
        validate_digest(&self.event_type_digest, "event type")?;
        if let Some(digest) = &self.resource_id_digest {
            validate_digest(digest, "audit resource")?;
        }
        if self.actor_class == ActorClass::ProviderUnknown
            || self.resource_kind == ResourceKind::ProviderUnknown
        {
            return Err(crate::RampSpendOutcomeError::ProviderUnknown);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpendEvidence {
    pub status: EvidenceStatus,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub contract_digest: Digest,
    pub spend_constraints_digest: Digest,
    pub currency_code: Option<String>,
    pub category_id_digests: Vec<Digest>,
    pub category_name_digests: Vec<Digest>,
    pub spend_total_minor: i64,
    pub max_spend_total_minor: i64,
    pub expected_spend_total_minor: Option<i64>,
    pub transactions: Vec<TransactionEvidence>,
    pub merchants: Vec<MerchantEvidence>,
    pub audit_events: Vec<AuditEventEvidence>,
    pub high_water_mark_digest: Digest,
    pub page_count: u16,
    pub request_receipt_digest: Digest,
    pub response_receipt_digest: Digest,
    pub provenance: TransportProvenance,
    pub native: bool,
    pub connected: bool,
    pub evidence_digest: Digest,
}

impl SpendEvidence {
    pub(crate) fn new(
        scope_digest: Digest,
        registration_digest: Digest,
        provider_digest: Digest,
        contract_digest: Digest,
        constraints: &SpendConstraints,
        currency_code: Option<String>,
        mut category_id_digests: Vec<Digest>,
        mut category_name_digests: Vec<Digest>,
        spend_total_minor: i64,
        transactions: Vec<TransactionEvidence>,
        merchants: Vec<MerchantEvidence>,
        audit_events: Vec<AuditEventEvidence>,
        high_water_mark_digest: Digest,
        page_count: u16,
        request_receipt_digest: Digest,
        response_receipt_digest: Digest,
        provenance: TransportProvenance,
    ) -> Result<Self, crate::RampSpendOutcomeError> {
        constraints.validate()?;
        if transactions.is_empty() && merchants.is_empty() && audit_events.is_empty() {
            return Err(crate::RampSpendOutcomeError::EmptyEvidence);
        }
        if transactions.len() > MAX_TRANSACTIONS {
            return Err(crate::RampSpendOutcomeError::BoundExceeded {
                field: "transactions",
                maximum: MAX_TRANSACTIONS,
            });
        }
        if merchants.len() > MAX_MERCHANTS {
            return Err(crate::RampSpendOutcomeError::BoundExceeded {
                field: "merchants",
                maximum: MAX_MERCHANTS,
            });
        }
        if audit_events.len() > MAX_AUDIT_EVENTS {
            return Err(crate::RampSpendOutcomeError::BoundExceeded {
                field: "audit events",
                maximum: MAX_AUDIT_EVENTS,
            });
        }
        if page_count == 0 || page_count as usize > MAX_PAGES {
            return Err(crate::RampSpendOutcomeError::BoundExceeded {
                field: "pages",
                maximum: MAX_PAGES,
            });
        }
        validate_digest(&scope_digest, "scope")?;
        validate_digest(&registration_digest, "registration")?;
        validate_digest(&provider_digest, "provider")?;
        validate_digest(&contract_digest, "contract")?;
        validate_digest(&constraints.digest(), "spend constraints")?;
        validate_digest(&high_water_mark_digest, "high-water mark")?;
        validate_digest(&request_receipt_digest, "request receipt")?;
        validate_digest(&response_receipt_digest, "response receipt")?;
        if let Some(currency_code) = &currency_code {
            validate_currency_code(currency_code)?;
        }
        if category_id_digests.len() > MAX_CATEGORY_VALUES {
            return Err(crate::RampSpendOutcomeError::BoundExceeded {
                field: "category ids",
                maximum: MAX_CATEGORY_VALUES,
            });
        }
        if category_name_digests.len() > MAX_CATEGORY_VALUES {
            return Err(crate::RampSpendOutcomeError::BoundExceeded {
                field: "category names",
                maximum: MAX_CATEGORY_VALUES,
            });
        }
        category_id_digests.sort_unstable();
        category_id_digests.dedup();
        category_name_digests.sort_unstable();
        category_name_digests.dedup();
        for digest in category_id_digests
            .iter()
            .chain(category_name_digests.iter())
        {
            validate_digest(digest, "category")?;
        }
        if spend_total_minor.unsigned_abs() > constraints.max_total_minor as u64
            || constraints
                .expected_total_minor
                .is_some_and(|expected| expected != spend_total_minor)
        {
            return Err(crate::RampSpendOutcomeError::ContradictoryEvidence);
        }
        if let Some(expected) = &constraints.currency_code
            && currency_code.as_deref() != Some(expected.as_str())
        {
            return Err(crate::RampSpendOutcomeError::ContradictoryEvidence);
        }
        let mut evidence = Self {
            status: EvidenceStatus::Complete,
            scope_digest,
            registration_digest,
            provider_digest,
            contract_digest,
            spend_constraints_digest: constraints.digest(),
            currency_code,
            category_id_digests,
            category_name_digests,
            spend_total_minor,
            max_spend_total_minor: constraints.max_total_minor,
            expected_spend_total_minor: constraints.expected_total_minor,
            transactions,
            merchants,
            audit_events,
            high_water_mark_digest,
            page_count,
            request_receipt_digest,
            response_receipt_digest,
            provenance,
            native: false,
            connected: false,
            evidence_digest: String::new(),
        };
        evidence.evidence_digest = evidence.computed_digest();
        Ok(evidence)
    }

    pub fn validate(&self) -> Result<(), crate::RampSpendOutcomeError> {
        if self.status != EvidenceStatus::Complete
            || self.native
            || self.connected
            || self.provenance.is_native()
            || self.provenance.is_connected()
            || self.transactions.is_empty()
                && self.merchants.is_empty()
                && self.audit_events.is_empty()
        {
            return Err(crate::RampSpendOutcomeError::PartialEvidence);
        }
        validate_digest(&self.scope_digest, "scope")?;
        validate_digest(&self.registration_digest, "registration")?;
        validate_digest(&self.provider_digest, "provider")?;
        validate_digest(&self.contract_digest, "contract")?;
        validate_digest(&self.spend_constraints_digest, "spend constraints")?;
        validate_digest(&self.high_water_mark_digest, "high-water mark")?;
        validate_digest(&self.request_receipt_digest, "request receipt")?;
        validate_digest(&self.response_receipt_digest, "response receipt")?;
        if self.transactions.len() > MAX_TRANSACTIONS
            || self.merchants.len() > MAX_MERCHANTS
            || self.audit_events.len() > MAX_AUDIT_EVENTS
            || self.page_count == 0
            || self.page_count as usize > MAX_PAGES
            || self.category_id_digests.len() > MAX_CATEGORY_VALUES
            || self.category_name_digests.len() > MAX_CATEGORY_VALUES
            || self.max_spend_total_minor <= 0
            || self.max_spend_total_minor > MAX_SPEND_TOTAL_MINOR
            || self.spend_total_minor.unsigned_abs() > self.max_spend_total_minor as u64
            || self
                .expected_spend_total_minor
                .is_some_and(|expected| expected != self.spend_total_minor)
        {
            return Err(crate::RampSpendOutcomeError::ContradictoryEvidence);
        }
        if let Some(currency_code) = &self.currency_code {
            validate_currency_code(currency_code)?;
        }
        for digest in self
            .category_id_digests
            .iter()
            .chain(self.category_name_digests.iter())
        {
            validate_digest(digest, "category")?;
        }
        for transaction in &self.transactions {
            transaction.validate()?;
        }
        for merchant in &self.merchants {
            merchant.validate()?;
        }
        for audit_event in &self.audit_events {
            audit_event.validate()?;
        }
        if self.evidence_digest != self.computed_digest() {
            return Err(crate::RampSpendOutcomeError::ResponseTampered);
        }
        Ok(())
    }

    pub fn validate_against_scope(
        &self,
        scope: &RampSpendScope,
    ) -> Result<(), crate::RampSpendOutcomeError> {
        self.validate()?;
        scope.validate()?;
        if self.scope_digest != scope.digest()
            || self.spend_constraints_digest != scope.spend_constraints.digest()
            || self.max_spend_total_minor != scope.spend_constraints.max_total_minor
            || self.expected_spend_total_minor != scope.spend_constraints.expected_total_minor
        {
            return Err(crate::RampSpendOutcomeError::ScopeMismatch);
        }
        if let Some(currency_code) = &scope.spend_constraints.currency_code
            && self.currency_code.as_deref() != Some(currency_code.as_str())
        {
            return Err(crate::RampSpendOutcomeError::ContradictoryEvidence);
        }
        if let Some(category_id) = &scope.spend_constraints.category_id
            && self.category_id_digests != vec![sha256_digest(category_id.as_bytes())]
        {
            return Err(crate::RampSpendOutcomeError::ContradictoryEvidence);
        }
        if let Some(category_name) = &scope.spend_constraints.category_name
            && self.category_name_digests != vec![sha256_digest(category_name.as_bytes())]
        {
            return Err(crate::RampSpendOutcomeError::ContradictoryEvidence);
        }
        Ok(())
    }

    #[must_use]
    pub fn tampered(mut self) -> Self {
        self.evidence_digest = "0".repeat(64);
        self
    }

    fn computed_digest(&self) -> Digest {
        canonical_digest(&EvidenceFingerprint {
            status: self.status,
            scope_digest: &self.scope_digest,
            registration_digest: &self.registration_digest,
            provider_digest: &self.provider_digest,
            contract_digest: &self.contract_digest,
            spend_constraints_digest: &self.spend_constraints_digest,
            currency_code: &self.currency_code,
            category_id_digests: &self.category_id_digests,
            category_name_digests: &self.category_name_digests,
            spend_total_minor: self.spend_total_minor,
            max_spend_total_minor: self.max_spend_total_minor,
            expected_spend_total_minor: self.expected_spend_total_minor,
            transactions: &self.transactions,
            merchants: &self.merchants,
            audit_events: &self.audit_events,
            high_water_mark_digest: &self.high_water_mark_digest,
            page_count: self.page_count,
            request_receipt_digest: &self.request_receipt_digest,
            response_receipt_digest: &self.response_receipt_digest,
            provenance: self.provenance,
            native: self.native,
            connected: self.connected,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceFingerprint<'a> {
    status: EvidenceStatus,
    scope_digest: &'a str,
    registration_digest: &'a str,
    provider_digest: &'a str,
    contract_digest: &'a str,
    spend_constraints_digest: &'a str,
    currency_code: &'a Option<String>,
    category_id_digests: &'a [Digest],
    category_name_digests: &'a [Digest],
    spend_total_minor: i64,
    max_spend_total_minor: i64,
    expected_spend_total_minor: Option<i64>,
    transactions: &'a [TransactionEvidence],
    merchants: &'a [MerchantEvidence],
    audit_events: &'a [AuditEventEvidence],
    high_water_mark_digest: &'a str,
    page_count: u16,
    request_receipt_digest: &'a str,
    response_receipt_digest: &'a str,
    provenance: TransportProvenance,
    native: bool,
    connected: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutcomeProposal {
    pub proposal_kind: String,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub contract_digest: Digest,
    pub evidence_digest: Digest,
    pub spend_constraints_digest: Digest,
    pub currency_code: Option<String>,
    pub category_id_digests: Vec<Digest>,
    pub category_name_digests: Vec<Digest>,
    pub spend_total_minor: i64,
    pub max_spend_total_minor: i64,
    pub expected_spend_total_minor: Option<i64>,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub policy_revision: u64,
    pub transaction_states: Vec<TransactionState>,
    pub refund_states: Vec<RefundState>,
    pub audit_event_count: u16,
    pub native: bool,
    pub connected: bool,
    pub effect_requested: bool,
    pub proposal_digest: Digest,
}

impl OutcomeProposal {
    pub(crate) fn from_evidence(
        evidence: &SpendEvidence,
        scope: &RampSpendScope,
    ) -> Result<Self, crate::RampSpendOutcomeError> {
        evidence.validate_against_scope(scope)?;
        let mut proposal = Self {
            proposal_kind: "bounded_ramp_spend_evidence_candidate".to_owned(),
            scope_digest: evidence.scope_digest.clone(),
            registration_digest: evidence.registration_digest.clone(),
            provider_digest: evidence.provider_digest.clone(),
            contract_digest: evidence.contract_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            spend_constraints_digest: evidence.spend_constraints_digest.clone(),
            currency_code: evidence.currency_code.clone(),
            category_id_digests: evidence.category_id_digests.clone(),
            category_name_digests: evidence.category_name_digests.clone(),
            spend_total_minor: evidence.spend_total_minor,
            max_spend_total_minor: evidence.max_spend_total_minor,
            expected_spend_total_minor: evidence.expected_spend_total_minor,
            project: scope.project.clone(),
            mission: scope.mission.clone(),
            work_product: scope.work_product.clone(),
            policy_revision: scope.policy_revision,
            transaction_states: evidence
                .transactions
                .iter()
                .map(|item| item.state)
                .collect(),
            refund_states: evidence
                .transactions
                .iter()
                .map(|item| item.refund_state)
                .collect(),
            audit_event_count: evidence.audit_events.len() as u16,
            native: false,
            connected: false,
            effect_requested: false,
            proposal_digest: String::new(),
        };
        proposal.proposal_digest = proposal.computed_digest();
        Ok(proposal)
    }

    pub fn validate(&self) -> Result<(), crate::RampSpendOutcomeError> {
        if self.proposal_kind != "bounded_ramp_spend_evidence_candidate"
            || self.native
            || self.connected
            || self.effect_requested
            || self.proposal_digest != self.computed_digest()
        {
            return Err(crate::RampSpendOutcomeError::ConsumerBindingMismatch);
        }
        validate_digest(&self.scope_digest, "scope")?;
        validate_digest(&self.registration_digest, "registration")?;
        validate_digest(&self.provider_digest, "provider")?;
        validate_digest(&self.contract_digest, "contract")?;
        validate_digest(&self.evidence_digest, "evidence")?;
        validate_digest(&self.spend_constraints_digest, "spend constraints")?;
        self.project.validate("project id")?;
        self.mission.validate("mission id")?;
        self.work_product.validate("work product id")?;
        if self.transaction_states.len() != self.refund_states.len()
            || self.transaction_states.len() > MAX_TRANSACTIONS
            || self.audit_event_count as usize > MAX_AUDIT_EVENTS
            || self.category_id_digests.len() > MAX_CATEGORY_VALUES
            || self.category_name_digests.len() > MAX_CATEGORY_VALUES
            || self.policy_revision == 0
        {
            return Err(crate::RampSpendOutcomeError::ConsumerBindingMismatch);
        }
        for digest in self
            .category_id_digests
            .iter()
            .chain(self.category_name_digests.iter())
        {
            validate_digest(digest, "category")?;
        }
        if let Some(currency_code) = &self.currency_code {
            validate_currency_code(currency_code)?;
        }
        if self.max_spend_total_minor <= 0
            || self.max_spend_total_minor > MAX_SPEND_TOTAL_MINOR
            || self.spend_total_minor.unsigned_abs() > self.max_spend_total_minor as u64
            || self
                .expected_spend_total_minor
                .is_some_and(|expected| expected != self.spend_total_minor)
        {
            return Err(crate::RampSpendOutcomeError::ContradictoryEvidence);
        }
        Ok(())
    }

    fn computed_digest(&self) -> Digest {
        canonical_digest(&ProposalFingerprint {
            proposal_kind: &self.proposal_kind,
            scope_digest: &self.scope_digest,
            registration_digest: &self.registration_digest,
            provider_digest: &self.provider_digest,
            contract_digest: &self.contract_digest,
            evidence_digest: &self.evidence_digest,
            spend_constraints_digest: &self.spend_constraints_digest,
            currency_code: &self.currency_code,
            category_id_digests: &self.category_id_digests,
            category_name_digests: &self.category_name_digests,
            spend_total_minor: self.spend_total_minor,
            max_spend_total_minor: self.max_spend_total_minor,
            expected_spend_total_minor: self.expected_spend_total_minor,
            project: &self.project,
            mission: &self.mission,
            work_product: &self.work_product,
            policy_revision: self.policy_revision,
            transaction_states: &self.transaction_states,
            refund_states: &self.refund_states,
            audit_event_count: self.audit_event_count,
            native: self.native,
            connected: self.connected,
            effect_requested: self.effect_requested,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProposalFingerprint<'a> {
    proposal_kind: &'a str,
    scope_digest: &'a str,
    registration_digest: &'a str,
    provider_digest: &'a str,
    contract_digest: &'a str,
    evidence_digest: &'a str,
    spend_constraints_digest: &'a str,
    currency_code: &'a Option<String>,
    category_id_digests: &'a [Digest],
    category_name_digests: &'a [Digest],
    spend_total_minor: i64,
    max_spend_total_minor: i64,
    expected_spend_total_minor: Option<i64>,
    project: &'a ProjectBinding,
    mission: &'a MissionBinding,
    work_product: &'a WorkProductBinding,
    policy_revision: u64,
    transaction_states: &'a [TransactionState],
    refund_states: &'a [RefundState],
    audit_event_count: u16,
    native: bool,
    connected: bool,
    effect_requested: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceReceipt {
    pub receipt_kind: String,
    pub evidence_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub contract_digest: Digest,
    pub spend_constraints_digest: Digest,
    pub currency_code: Option<String>,
    pub spend_total_minor: i64,
    pub max_spend_total_minor: i64,
    pub provenance: TransportProvenance,
    pub durable: bool,
    pub native: bool,
    pub connected: bool,
    pub receipt_digest: Digest,
}

impl EvidenceReceipt {
    pub(crate) fn from_evidence(
        evidence: &SpendEvidence,
    ) -> Result<Self, crate::RampSpendOutcomeError> {
        evidence.validate()?;
        let mut receipt = Self {
            receipt_kind: "ramp_spend_evidence_recording_receipt".to_owned(),
            evidence_digest: evidence.evidence_digest.clone(),
            scope_digest: evidence.scope_digest.clone(),
            registration_digest: evidence.registration_digest.clone(),
            provider_digest: evidence.provider_digest.clone(),
            contract_digest: evidence.contract_digest.clone(),
            spend_constraints_digest: evidence.spend_constraints_digest.clone(),
            currency_code: evidence.currency_code.clone(),
            spend_total_minor: evidence.spend_total_minor,
            max_spend_total_minor: evidence.max_spend_total_minor,
            provenance: evidence.provenance,
            durable: false,
            native: false,
            connected: false,
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = receipt.computed_digest();
        Ok(receipt)
    }

    pub fn validate(&self) -> Result<(), crate::RampSpendOutcomeError> {
        if self.receipt_kind != "ramp_spend_evidence_recording_receipt"
            || self.durable
            || self.native
            || self.connected
            || self.receipt_digest != self.computed_digest()
        {
            return Err(crate::RampSpendOutcomeError::ReceiptTampered);
        }
        validate_digest(&self.evidence_digest, "evidence")?;
        validate_digest(&self.scope_digest, "scope")?;
        validate_digest(&self.registration_digest, "registration")?;
        validate_digest(&self.provider_digest, "provider")?;
        validate_digest(&self.contract_digest, "contract")?;
        validate_digest(&self.spend_constraints_digest, "spend constraints")?;
        if let Some(currency_code) = &self.currency_code {
            validate_currency_code(currency_code)?;
        }
        if self.max_spend_total_minor <= 0
            || self.max_spend_total_minor > MAX_SPEND_TOTAL_MINOR
            || self.spend_total_minor.unsigned_abs() > self.max_spend_total_minor as u64
        {
            return Err(crate::RampSpendOutcomeError::ReceiptTampered);
        }
        Ok(())
    }

    pub fn validate_against(
        &self,
        evidence: &SpendEvidence,
    ) -> Result<(), crate::RampSpendOutcomeError> {
        self.validate()?;
        evidence.validate()?;
        if self.evidence_digest != evidence.evidence_digest
            || self.scope_digest != evidence.scope_digest
            || self.registration_digest != evidence.registration_digest
            || self.provider_digest != evidence.provider_digest
            || self.contract_digest != evidence.contract_digest
            || self.spend_constraints_digest != evidence.spend_constraints_digest
            || self.currency_code != evidence.currency_code
            || self.spend_total_minor != evidence.spend_total_minor
            || self.max_spend_total_minor != evidence.max_spend_total_minor
            || self.provenance != evidence.provenance
            || evidence.status != EvidenceStatus::Complete
            || evidence.native
            || evidence.connected
        {
            return Err(crate::RampSpendOutcomeError::ReceiptTampered);
        }
        Ok(())
    }

    fn computed_digest(&self) -> Digest {
        canonical_digest(&ReceiptFingerprint {
            receipt_kind: &self.receipt_kind,
            evidence_digest: &self.evidence_digest,
            scope_digest: &self.scope_digest,
            registration_digest: &self.registration_digest,
            provider_digest: &self.provider_digest,
            contract_digest: &self.contract_digest,
            spend_constraints_digest: &self.spend_constraints_digest,
            currency_code: &self.currency_code,
            spend_total_minor: self.spend_total_minor,
            max_spend_total_minor: self.max_spend_total_minor,
            provenance: self.provenance,
            durable: self.durable,
            native: self.native,
            connected: self.connected,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReceiptFingerprint<'a> {
    receipt_kind: &'a str,
    evidence_digest: &'a str,
    scope_digest: &'a str,
    registration_digest: &'a str,
    provider_digest: &'a str,
    contract_digest: &'a str,
    spend_constraints_digest: &'a str,
    currency_code: &'a Option<String>,
    spend_total_minor: i64,
    max_spend_total_minor: i64,
    provenance: TransportProvenance,
    durable: bool,
    native: bool,
    connected: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceVerification {
    pub receipt_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub provider_digest: Digest,
    pub contract_digest: Digest,
    pub evidence_status: EvidenceStatus,
    pub provenance: TransportProvenance,
    pub independent_state_valid: bool,
    pub verified: bool,
    pub native: bool,
    pub connected: bool,
    pub adoptable: bool,
    pub verification_digest: Digest,
}

impl EvidenceVerification {
    pub(crate) fn seal(mut self) -> Self {
        self.verification_digest = self.computed_digest();
        self
    }

    pub fn validate(&self) -> Result<(), crate::RampSpendOutcomeError> {
        validate_digest(&self.receipt_digest, "receipt")?;
        validate_digest(&self.evidence_digest, "evidence")?;
        validate_digest(&self.registration_digest, "registration")?;
        validate_digest(&self.scope_digest, "scope")?;
        validate_digest(&self.provider_digest, "provider")?;
        validate_digest(&self.contract_digest, "contract")?;
        validate_digest(&self.verification_digest, "verification")?;
        if self.verification_digest != self.computed_digest() {
            return Err(crate::RampSpendOutcomeError::ReceiptTampered);
        }
        Ok(())
    }

    pub fn validate_against(
        &self,
        receipt: &EvidenceReceipt,
        evidence: &SpendEvidence,
    ) -> Result<(), crate::RampSpendOutcomeError> {
        self.validate()?;
        receipt.validate_against(evidence)?;
        if self.receipt_digest != receipt.receipt_digest
            || self.evidence_digest != evidence.evidence_digest
            || self.registration_digest != evidence.registration_digest
            || self.scope_digest != evidence.scope_digest
            || self.provider_digest != evidence.provider_digest
            || self.contract_digest != evidence.contract_digest
            || self.evidence_status != EvidenceStatus::Complete
            || self.provenance != evidence.provenance
            || !self.independent_state_valid
            || !self.verified
            || self.native
            || self.connected
            || self.adoptable
        {
            return Err(crate::RampSpendOutcomeError::ReceiptTampered);
        }
        Ok(())
    }

    fn computed_digest(&self) -> Digest {
        canonical_digest(&VerificationFingerprint {
            receipt_digest: &self.receipt_digest,
            evidence_digest: &self.evidence_digest,
            registration_digest: &self.registration_digest,
            scope_digest: &self.scope_digest,
            provider_digest: &self.provider_digest,
            contract_digest: &self.contract_digest,
            evidence_status: self.evidence_status,
            provenance: self.provenance,
            independent_state_valid: self.independent_state_valid,
            verified: self.verified,
            native: self.native,
            connected: self.connected,
            adoptable: self.adoptable,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VerificationFingerprint<'a> {
    receipt_digest: &'a str,
    evidence_digest: &'a str,
    registration_digest: &'a str,
    scope_digest: &'a str,
    provider_digest: &'a str,
    contract_digest: &'a str,
    evidence_status: EvidenceStatus,
    provenance: TransportProvenance,
    independent_state_valid: bool,
    verified: bool,
    native: bool,
    connected: bool,
    adoptable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Capabilities {
    pub service_id: String,
    pub provider_id: String,
    pub version: String,
    pub read_only: bool,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub operations: Vec<String>,
    pub transport: TransportProvenance,
    pub replay_fence_durability: ReplayFenceDurability,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayFenceDurability {
    ProcessSharedNonDurable,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationReceipt {
    pub plugin_id: String,
    pub service_id: String,
    pub provider_id: String,
    pub implementation: String,
    pub version: String,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub provider_revision: u64,
    pub registration_revision: u64,
    pub status: RegistrationStatus,
    pub registration_digest: Digest,
}

impl RegistrationReceipt {
    pub(crate) fn bind(
        contract_digest: Digest,
        provider_digest: Digest,
        scope: &RampSpendScope,
        provider_revision: u64,
        registration_revision: u64,
    ) -> Result<Self, crate::RampSpendOutcomeError> {
        if provider_revision == 0 || registration_revision == 0 {
            return Err(crate::RampSpendOutcomeError::RegistrationMismatch);
        }
        let mut receipt = Self {
            plugin_id: crate::RAMP_PROVIDER_ID.to_owned(),
            service_id: crate::RAMP_SPEND_OUTCOME_SERVICE_ID.to_owned(),
            provider_id: crate::RAMP_PROVIDER_ID.to_owned(),
            implementation: crate::RAMP_PROVIDER_IMPLEMENTATION.to_owned(),
            version: crate::RAMP_PLUGIN_VERSION.to_owned(),
            contract_digest,
            provider_digest,
            scope_digest: scope.digest(),
            permission_digest: scope.permissions.digest(),
            provider_revision,
            registration_revision,
            status: RegistrationStatus::Active,
            registration_digest: String::new(),
        };
        receipt.registration_digest = receipt.computed_digest();
        Ok(receipt)
    }

    pub fn validate(
        &self,
        contract_digest: &str,
        provider_digest: &str,
        scope: &RampSpendScope,
    ) -> Result<(), crate::RampSpendOutcomeError> {
        scope.validate()?;
        validate_digest(contract_digest, "contract")?;
        validate_digest(provider_digest, "provider")?;
        validate_digest(&self.contract_digest, "contract")?;
        validate_digest(&self.provider_digest, "provider")?;
        validate_digest(&self.scope_digest, "scope")?;
        validate_digest(&self.permission_digest, "permission")?;
        validate_digest(&self.registration_digest, "registration")?;
        if self.plugin_id != crate::RAMP_PROVIDER_ID
            || self.service_id != crate::RAMP_SPEND_OUTCOME_SERVICE_ID
            || self.provider_id != crate::RAMP_PROVIDER_ID
            || self.implementation != crate::RAMP_PROVIDER_IMPLEMENTATION
            || self.version != crate::RAMP_PLUGIN_VERSION
            || self.contract_digest != contract_digest
            || self.provider_digest != provider_digest
            || self.scope_digest != scope.digest()
            || self.permission_digest != scope.permissions.digest()
            || self.provider_revision == 0
            || self.registration_revision == 0
            || self.registration_digest != self.computed_digest()
        {
            return Err(crate::RampSpendOutcomeError::RegistrationMismatch);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RevocationReceipt, crate::RampSpendOutcomeError> {
        if self.status == RegistrationStatus::Revoked {
            return Err(crate::RampSpendOutcomeError::RegistrationRevoked);
        }
        self.status = RegistrationStatus::Revoked;
        self.registration_digest = self.computed_digest();
        Ok(RevocationReceipt {
            registration_digest: self.registration_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            registration_revision: self.registration_revision,
            status: self.status,
        })
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }

    fn computed_digest(&self) -> Digest {
        canonical_digest(&RegistrationFingerprint {
            plugin_id: &self.plugin_id,
            service_id: &self.service_id,
            provider_id: &self.provider_id,
            implementation: &self.implementation,
            version: &self.version,
            contract_digest: &self.contract_digest,
            provider_digest: &self.provider_digest,
            scope_digest: &self.scope_digest,
            permission_digest: &self.permission_digest,
            provider_revision: self.provider_revision,
            registration_revision: self.registration_revision,
            status: self.status,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationFingerprint<'a> {
    plugin_id: &'a str,
    service_id: &'a str,
    provider_id: &'a str,
    implementation: &'a str,
    version: &'a str,
    contract_digest: &'a str,
    provider_digest: &'a str,
    scope_digest: &'a str,
    permission_digest: &'a str,
    provider_revision: u64,
    registration_revision: u64,
    status: RegistrationStatus,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevocationReceipt {
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub registration_revision: u64,
    pub status: RegistrationStatus,
}

pub(crate) fn amount_evidence(
    amount_minor: Option<i64>,
    currency_code: Option<&str>,
) -> Result<(AmountBucket, Option<Digest>, Option<String>), crate::RampSpendOutcomeError> {
    let currency = currency_code.map(str::to_owned);
    if let Some(currency_code) = currency_code {
        validate_currency_code(currency_code)?;
    }
    let Some(amount_minor) = amount_minor else {
        return Ok((AmountBucket::Unknown, None, currency));
    };
    let absolute = amount_minor.unsigned_abs();
    let bucket = match absolute {
        0 => AmountBucket::Zero,
        1..=9_999 => AmountBucket::UnderOneHundred,
        10_000..=99_999 => AmountBucket::OneHundredToOneThousand,
        100_000..=999_999 => AmountBucket::OneThousandToTenThousand,
        _ => AmountBucket::TenThousandOrMore,
    };
    let digest = sha256_digest(
        format!(
            "ramp-amount|{}|{}",
            currency_code.unwrap_or("unknown"),
            amount_minor
        )
        .as_bytes(),
    );
    Ok((bucket, Some(digest), currency))
}

pub(crate) fn validate_currency_code(value: &str) -> Result<(), crate::RampSpendOutcomeError> {
    if value.len() != 3 || !value.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return Err(crate::RampSpendOutcomeError::InvalidResponse);
    }
    Ok(())
}

pub(crate) fn refund_state(
    state: TransactionState,
    amount_minor: Option<i64>,
    declared: Option<RefundState>,
) -> RefundState {
    if let Some(declared) = declared {
        return declared;
    }
    if matches!(state, TransactionState::Refunded) {
        return RefundState::Full;
    }
    if matches!(state, TransactionState::Reversed) {
        return RefundState::Reversed;
    }
    if amount_minor.is_some_and(|amount| amount < 0) {
        RefundState::Partial
    } else {
        RefundState::NotRefunded
    }
}

pub(crate) fn validate_cursor(value: &str) -> Result<(), crate::RampSpendOutcomeError> {
    validate_bounded_text(value, "cursor", MAX_CURSOR_BYTES)
}

pub(crate) fn validate_high_water(value: &str) -> Result<(), crate::RampSpendOutcomeError> {
    validate_bounded_text(value, "high-water mark", MAX_CURSOR_BYTES)
}

pub(crate) fn validate_event_type(value: &str) -> Result<(), crate::RampSpendOutcomeError> {
    validate_bounded_text(value, "event type", MAX_EVENT_TYPE_BYTES)
}

pub(crate) fn validate_page_size(value: usize) -> Result<(), crate::RampSpendOutcomeError> {
    if value == 0 || value > MAX_PAGE_SIZE {
        return Err(crate::RampSpendOutcomeError::InvalidPageSize);
    }
    Ok(())
}

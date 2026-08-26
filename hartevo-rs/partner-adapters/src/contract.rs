use std::collections::BTreeSet;
use std::fmt;

use chrono::{DateTime, Duration, Utc};
use hartevo_domain_kernel::{CurrencyCode, Money};
use serde::{Deserialize, Deserializer, Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::ids::{
    ActionId, ClickId, CommissionId, ContractId, ConversionId, LinkId, NetworkAccountId,
    NetworkOrderId, PartnerId, PayoutId, ProgramId, ReportId, ReversalId,
};

pub const PARTNER_NETWORK_CONTRACT_SCHEMA_VERSION: &str = "hartevo-partner-network-contract/v1";
pub const PARTNER_NETWORK_CONTRACT_VERSION: &str = "partner-network-e1/v1";
/// The published JSON Schema for the typed read observation envelope.
///
/// The schema is intentionally kept beside the owned serde contract because
/// this crate is the only owner of the provider-specific envelope.  The
/// executable validator below checks this document before serde decoding;
/// serde then remains the second, typed validation boundary.  Provider record
/// fields are validated by their deny-unknown-fields serde types after the
/// envelope schema has accepted the resource/records shape.
pub const PARTNER_NETWORK_CONTRACT_SCHEMA: &str = r##"{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"hartevo-partner-network-contract/v1/read-observation",
  "title":"Hartevo Partner Network Read Observation",
  "type":"object",
  "additionalProperties":false,
  "required":["provider","scope","request","data","page","expectedProgram","window","observedProgramId","programRevision","programTermsDigest","authorizationRevision","authorizationGeneration","cursorDigest","provenance","evidenceLevel","observedAt","sourceDigest","budget","nativeCanaryDigest","adapterVersion","registrationIdentity","registrationDigest","evidenceDigest"],
  "properties":{
    "provider":{"enum":["impact","awin","cj"]},
    "scope":{"$ref":"#/$defs/scope"},
    "request":{"enum":["programs","partners","contracts","links","clicks","conversions","actions","commissions","reversals","payouts","reports"]},
    "data":{"$ref":"#/$defs/data"},
    "page":{"$ref":"#/$defs/page"},
    "expectedProgram":{"anyOf":[{"$ref":"#/$defs/programExpectation"},{"type":"null"}]},
    "window":{"anyOf":[{"$ref":"#/$defs/window"},{"type":"null"}]},
    "observedProgramId":{"anyOf":[{"type":"string","minLength":1},{"type":"null"}]},
    "programRevision":{"anyOf":[{"type":"integer","minimum":1},{"type":"null"}]},
    "programTermsDigest":{"anyOf":[{"$ref":"#/$defs/digest"},{"type":"null"}]},
    "authorizationRevision":{"type":"integer","minimum":1},
    "authorizationGeneration":{"type":"string","minLength":1},
    "cursorDigest":{"$ref":"#/$defs/digest"},
    "provenance":{"enum":["fixture","controlled_provider","production_provider"]},
    "evidenceLevel":{"const":"e1"},
    "observedAt":{"type":"string","format":"date-time"},
    "sourceDigest":{"$ref":"#/$defs/digest"},
    "budget":{"$ref":"#/$defs/budget"},
    "nativeCanaryDigest":{"anyOf":[{"$ref":"#/$defs/digest"},{"type":"null"}]},
    "adapterVersion":{"type":"integer","minimum":1},
    "registrationIdentity":{"type":"string","minLength":1},
    "registrationDigest":{"$ref":"#/$defs/digest"},
    "evidenceDigest":{"$ref":"#/$defs/digest"}
  },
  "$defs":{
    "digest":{"type":"string","pattern":"^[0-9a-f]{64}$"},
    "identifier":{"type":"string","minLength":1},
    "scope":{"type":"object","additionalProperties":false,"required":["tenantId","projectId","accountId","programId"],"properties":{"tenantId":{"$ref":"#/$defs/identifier"},"projectId":{"$ref":"#/$defs/identifier"},"accountId":{"$ref":"#/$defs/identifier"},"programId":{"anyOf":[{"$ref":"#/$defs/identifier"},{"type":"null"}]}}},
    "programExpectation":{"type":"object","additionalProperties":false,"required":["programId","revision","termsDigest"],"properties":{"programId":{"$ref":"#/$defs/identifier"},"revision":{"type":"integer","minimum":1},"termsDigest":{"$ref":"#/$defs/digest"}}},
    "window":{"type":"object","additionalProperties":false,"required":["startedAt","endedAt"],"properties":{"startedAt":{"type":"string","format":"date-time"},"endedAt":{"type":"string","format":"date-time"}}},
    "cursor":{"type":"object","additionalProperties":false,"required":["tokenDigest","bindingDigest","sequence"],"properties":{"tokenDigest":{"$ref":"#/$defs/digest"},"bindingDigest":{"anyOf":[{"$ref":"#/$defs/digest"},{"type":"null"}]},"sequence":{"type":"integer","minimum":0}}},
    "page":{"type":"object","additionalProperties":false,"required":["cursor","nextCursor","hasMore","itemCount"],"properties":{"cursor":{"anyOf":[{"$ref":"#/$defs/cursor"},{"type":"null"}]},"nextCursor":{"anyOf":[{"$ref":"#/$defs/cursor"},{"type":"null"}]},"hasMore":{"type":"boolean"},"itemCount":{"type":"integer","minimum":0}}},
    "data":{"type":"object","additionalProperties":false,"required":["resource","records"],"properties":{"resource":{"enum":["programs","partners","contracts","links","clicks","conversions","actions","commissions","reversals","payouts","reports"]},"records":{"type":"array","items":{"type":"object"}}}},
    "budget":{"type":"object","additionalProperties":false,"required":["quotaLimit","quotaRemaining","rateLimitRemaining","rateLimitResetAt","costUnits","freshnessExpiresAt","source","evidenceDigest"],"properties":{"quotaLimit":{"type":"integer","minimum":1},"quotaRemaining":{"type":"integer","minimum":0},"rateLimitRemaining":{"type":"integer","minimum":0},"rateLimitResetAt":{"type":"string","format":"date-time"},"costUnits":{"type":"integer","minimum":1},"freshnessExpiresAt":{"type":"string","format":"date-time"},"source":{"type":"string","minLength":1},"evidenceDigest":{"$ref":"#/$defs/digest"}}}
  }
}"##;

pub fn deserialize_partner_contract<T: DeserializeOwned>(
    json: &str,
) -> Result<T, PartnerNetworkError> {
    let value =
        serde_json::from_str::<Value>(json).map_err(|_| PartnerNetworkError::MalformedCallback)?;
    if value.get("request").is_some() && value.get("data").is_some() {
        let serialized = serde_json::to_string(&value)
            .map_err(|_| PartnerNetworkError::SchemaValidationFailed)?;
        validate_published_partner_schema(&serialized)?;
    }
    serde_json::from_value(value).map_err(|_| PartnerNetworkError::MalformedCallback)
}

/// Validate a serialized read observation against the published JSON Schema.
/// This is deliberately separate from `serde_json::from_str`: schema drift is
/// rejected before the typed representation is allowed to deserialize.
pub fn validate_published_partner_schema(json: &str) -> Result<(), PartnerNetworkError> {
    let schema = serde_json::from_str::<Value>(PARTNER_NETWORK_CONTRACT_SCHEMA)
        .map_err(|_| PartnerNetworkError::SchemaValidationFailed)?;
    let instance = serde_json::from_str::<Value>(json)
        .map_err(|_| PartnerNetworkError::SchemaValidationFailed)?;
    validate_json_schema(&schema, &instance, &schema)
}

pub fn validate_partner_read_observation(
    observation: &NetworkReadObservation,
) -> Result<(), PartnerNetworkError> {
    let json = serde_json::to_string(observation)
        .map_err(|_| PartnerNetworkError::SchemaValidationFailed)?;
    validate_published_partner_schema(&json)?;
    observation.validate()
}

pub fn deserialize_partner_read_observation(
    json: &str,
) -> Result<NetworkReadObservation, PartnerNetworkError> {
    validate_published_partner_schema(json)?;
    let observation = serde_json::from_str::<NetworkReadObservation>(json)
        .map_err(|_| PartnerNetworkError::MalformedCallback)?;
    observation.validate()?;
    Ok(observation)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkProvider {
    Impact,
    Awin,
    Cj,
}

impl NetworkProvider {
    pub const ALL: [Self; 3] = [Self::Impact, Self::Awin, Self::Cj];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Impact => "impact",
            Self::Awin => "awin",
            Self::Cj => "cj",
        }
    }
}

impl fmt::Display for NetworkProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(formatter)
    }
}

pub const PARTNER_ADAPTER_VERSION: u32 = 1;

const PARTNER_REGISTRATION_BINDINGS: &[&str] = &[
    "connection.probe:probe:probe_observation:fixture:controlled_provider",
    "partner.read:read:read_observation:fixture:controlled_provider",
    "partner.program.read:read:read_observation:fixture:controlled_provider",
    "partner.partner.read:read:read_observation:fixture:controlled_provider",
    "partner.contract.read:read:read_observation:fixture:controlled_provider",
    "partner.link.read:read:read_observation:fixture:controlled_provider",
    "partner.click.read:read:read_observation:fixture:controlled_provider",
    "partner.conversion.read:read:read_observation:fixture:controlled_provider",
    "partner.action.read:read:read_observation:fixture:controlled_provider",
    "partner.commission.read:read:read_observation:fixture:controlled_provider",
    "partner.reversal.read:read:read_observation:fixture:controlled_provider",
    "partner.payout.read:read:read_observation:fixture:controlled_provider",
    "partner.report.read:read:read_observation:fixture:controlled_provider",
    "outcome.ingest:handle_webhook:webhook_observation:fixture:controlled_provider",
];

pub fn partner_registration_identity(provider: NetworkProvider) -> String {
    format!("partner.{}.network", provider.as_str())
}

pub(crate) fn partner_registration_digest(
    provider: NetworkProvider,
) -> Result<String, PartnerNetworkError> {
    canonical_digest(&(
        PARTNER_NETWORK_CONTRACT_VERSION,
        partner_registration_identity(provider),
        PARTNER_ADAPTER_VERSION,
        PARTNER_REGISTRATION_BINDINGS,
    ))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkProvenance {
    Fixture,
    ControlledProvider,
    ProductionProvider,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceLevel {
    E1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkCapability {
    Probe,
    PartnerRead,
    PartnerEngage,
    OutcomeIngest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkScope {
    pub tenant_id: String,
    pub project_id: String,
    pub account_id: NetworkAccountId,
    pub program_id: Option<ProgramId>,
}

impl<'de> Deserialize<'de> for NetworkScope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        #[allow(clippy::struct_field_names)]
        struct Wire {
            tenant_id: String,
            project_id: String,
            account_id: NetworkAccountId,
            program_id: Option<ProgramId>,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(
            wire.tenant_id,
            wire.project_id,
            wire.account_id,
            wire.program_id,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl NetworkScope {
    pub fn new(
        tenant_id: impl Into<String>,
        project_id: impl Into<String>,
        account_id: NetworkAccountId,
        program_id: Option<ProgramId>,
    ) -> Result<Self, PartnerNetworkError> {
        let scope = Self {
            tenant_id: tenant_id.into(),
            project_id: project_id.into(),
            account_id,
            program_id,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn account_scope(
        tenant_id: impl Into<String>,
        project_id: impl Into<String>,
        account_id: NetworkAccountId,
    ) -> Result<Self, PartnerNetworkError> {
        Self::new(tenant_id, project_id, account_id, None)
    }

    pub fn program_scope(
        tenant_id: impl Into<String>,
        project_id: impl Into<String>,
        account_id: NetworkAccountId,
        program_id: ProgramId,
    ) -> Result<Self, PartnerNetworkError> {
        Self::new(tenant_id, project_id, account_id, Some(program_id))
    }

    pub fn validate(&self) -> Result<(), PartnerNetworkError> {
        if self.tenant_id.trim().is_empty()
            || self.project_id.trim().is_empty()
            || self.account_id.as_str().trim().is_empty()
        {
            return Err(PartnerNetworkError::InvalidScope);
        }
        if self
            .tenant_id
            .chars()
            .chain(self.project_id.chars())
            .chain(self.account_id.as_str().chars())
            .any(char::is_control)
        {
            return Err(PartnerNetworkError::InvalidScope);
        }
        Ok(())
    }

    pub fn digest(&self) -> String {
        canonical_digest(self).expect("NetworkScope is serializable")
    }

    pub fn is_account_scope(&self) -> bool {
        self.program_id.is_none()
    }

    pub fn covers(&self, requested: &Self) -> bool {
        self.tenant_id == requested.tenant_id
            && self.project_id == requested.project_id
            && self.account_id == requested.account_id
            && (self.program_id.is_none() || self.program_id == requested.program_id)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpaqueSecretReference {
    reference_id: String,
    revision: u64,
}

impl OpaqueSecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        revision: u64,
    ) -> Result<Self, PartnerNetworkError> {
        let reference = Self {
            reference_id: reference_id.into(),
            revision,
        };
        if reference.reference_id.trim().is_empty()
            || reference.reference_id.chars().any(char::is_control)
            || reference.revision == 0
        {
            return Err(PartnerNetworkError::InvalidAuthorizationReference);
        }
        Ok(reference)
    }

    pub fn fixture() -> Self {
        Self {
            reference_id: "fixture:opaque-secret-reference".into(),
            revision: 1,
        }
    }

    pub fn reference_id(&self) -> &str {
        &self.reference_id
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub(crate) fn validate(&self) -> Result<(), PartnerNetworkError> {
        if self.reference_id.trim().is_empty()
            || self.reference_id.chars().any(char::is_control)
            || self.revision == 0
        {
            return Err(PartnerNetworkError::InvalidAuthorizationReference);
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for OpaqueSecretReference {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            reference_id: String,
            revision: u64,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.reference_id, wire.revision).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationState {
    Missing,
    Granted,
    Revoked,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorizationGrant {
    pub scope: NetworkScope,
    pub secret_reference: OpaqueSecretReference,
    pub capabilities: BTreeSet<NetworkCapability>,
    pub expires_at: DateTime<Utc>,
    provenance: NetworkProvenance,
    #[serde(skip)]
    native_canary: Option<NativeCanaryReceipt>,
}

impl AuthorizationGrant {
    pub fn fixture(scope: NetworkScope, expires_at: DateTime<Utc>) -> Self {
        Self {
            scope,
            secret_reference: OpaqueSecretReference::fixture(),
            capabilities: BTreeSet::from([
                NetworkCapability::Probe,
                NetworkCapability::PartnerRead,
                NetworkCapability::OutcomeIngest,
            ]),
            expires_at,
            provenance: NetworkProvenance::Fixture,
            native_canary: None,
        }
    }

    pub(crate) fn controlled(
        scope: NetworkScope,
        secret_reference: OpaqueSecretReference,
        capabilities: BTreeSet<NetworkCapability>,
        expires_at: DateTime<Utc>,
    ) -> Self {
        Self {
            scope,
            secret_reference,
            capabilities,
            expires_at,
            provenance: NetworkProvenance::ControlledProvider,
            native_canary: None,
        }
    }

    pub fn provenance(&self) -> NetworkProvenance {
        self.provenance
    }

    pub(crate) fn native_canary(&self) -> Option<&NativeCanaryReceipt> {
        self.native_canary.as_ref()
    }

    pub fn validate(&self) -> Result<(), PartnerNetworkError> {
        self.validate_at(Utc::now())
    }

    pub(crate) fn validate_at(
        &self,
        observed_at: DateTime<Utc>,
    ) -> Result<(), PartnerNetworkError> {
        self.scope.validate()?;
        self.secret_reference.validate()?;
        if self.capabilities.is_empty() || self.expires_at <= observed_at {
            return Err(PartnerNetworkError::InvalidAuthorizationGrant);
        }
        if self.provenance == NetworkProvenance::ProductionProvider
            && self
                .native_canary
                .as_ref()
                .is_none_or(|receipt| !receipt.is_attested())
        {
            return Err(PartnerNetworkError::NativeCanaryRequired);
        }
        Ok(())
    }
}

/// A native Layer-2 canary receipt is intentionally not constructible from a
/// provider payload.  Only a future in-crate native transport implementation
/// can create the attested form after credential resolution, permission
/// verification, probe, independent readback, and cleanup have all completed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeCanaryReceipt {
    pub status: NativeCanaryStatus,
    pub secret_reference_revision: u64,
    pub permission_digest: Option<String>,
    pub probe_digest: Option<String>,
    pub readback_digest: Option<String>,
    pub cleanup_digest: Option<String>,
    pub observed_at: DateTime<Utc>,
    pub evidence_digest: String,
    #[serde(skip)]
    attested: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeCanaryStatus {
    NotProven,
    Attested,
}

impl NativeCanaryReceipt {
    pub fn blocked(
        secret_reference_revision: u64,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, PartnerNetworkError> {
        if secret_reference_revision == 0 {
            return Err(PartnerNetworkError::InvalidAuthorizationReference);
        }
        let value = (
            NativeCanaryStatus::NotProven,
            secret_reference_revision,
            Option::<String>::None,
            Option::<String>::None,
            Option::<String>::None,
            Option::<String>::None,
            observed_at,
        );
        Ok(Self {
            status: NativeCanaryStatus::NotProven,
            secret_reference_revision,
            permission_digest: None,
            probe_digest: None,
            readback_digest: None,
            cleanup_digest: None,
            observed_at,
            evidence_digest: canonical_digest(&value)?,
            attested: false,
        })
    }

    pub fn is_attested(&self) -> bool {
        self.attested && self.status == NativeCanaryStatus::Attested
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeCanaryPlan {
    pub schema_version: &'static str,
    pub required_steps: [&'static str; 5],
    pub acceptance: [&'static str; 5],
    pub blocked_transition: &'static str,
    pub cleanup: &'static str,
}

pub const fn native_canary_plan() -> NativeCanaryPlan {
    NativeCanaryPlan {
        schema_version: "hartevo-partner-native-canary/v1",
        required_steps: [
            "resolve_opaque_credential",
            "verify_provider_permission",
            "probe_exact_scope",
            "independent_readback_digest",
            "revoke_and_unmount_cleanup",
        ],
        acceptance: [
            "credential_reference_and_revision_match",
            "permission_receipt_is_independent",
            "probe_is_reachable_for_exact_account_program",
            "readback_source_and_content_digests_match",
            "cleanup_receipt_closes_generation_and_secret_lease",
        ],
        blocked_transition: "NOT_PROVEN/BLOCKED_ENV",
        cleanup: "discard_native_lease_and_clear_durable_receipts_on_failure",
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorizationObservation {
    pub provider: NetworkProvider,
    pub scope: NetworkScope,
    pub state: AuthorizationState,
    pub provenance: Option<NetworkProvenance>,
    pub reference_revision: Option<u64>,
    pub observed_at: DateTime<Utc>,
    pub evidence_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProgramExpectation {
    pub program_id: ProgramId,
    pub revision: u64,
    pub terms_digest: String,
}

impl<'de> Deserialize<'de> for ProgramExpectation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            program_id: ProgramId,
            revision: u64,
            terms_digest: String,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.program_id, wire.revision, wire.terms_digest)
            .map_err(serde::de::Error::custom)
    }
}

impl ProgramExpectation {
    pub fn new(
        program_id: ProgramId,
        revision: u64,
        terms_digest: impl Into<String>,
    ) -> Result<Self, PartnerNetworkError> {
        let expectation = Self {
            program_id,
            revision,
            terms_digest: terms_digest.into(),
        };
        expectation.validate()?;
        Ok(expectation)
    }

    pub fn validate(&self) -> Result<(), PartnerNetworkError> {
        if self.revision == 0 || !is_sha256(&self.terms_digest) {
            return Err(PartnerNetworkError::InvalidProgramExpectation);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkProbeRequest {
    pub scope: NetworkScope,
    pub expected_program: Option<ProgramExpectation>,
    pub requested_capabilities: BTreeSet<NetworkCapability>,
    pub observed_at: DateTime<Utc>,
}

impl NetworkProbeRequest {
    pub fn new(scope: NetworkScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            scope,
            expected_program: None,
            requested_capabilities: BTreeSet::from([NetworkCapability::Probe]),
            observed_at,
        }
    }

    pub fn for_program(
        scope: NetworkScope,
        expected_program: ProgramExpectation,
        observed_at: DateTime<Utc>,
    ) -> Self {
        Self {
            scope,
            expected_program: Some(expected_program),
            requested_capabilities: BTreeSet::from([
                NetworkCapability::Probe,
                NetworkCapability::PartnerRead,
            ]),
            observed_at,
        }
    }

    pub fn validate(&self) -> Result<(), PartnerNetworkError> {
        self.scope.validate()?;
        if let Some(expected_program) = &self.expected_program {
            expected_program.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkProbeStatus {
    Reachable,
    AuthorizationRequired,
    ScopeRevoked,
    ProgramDrift,
    BlockedEnv,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkProbeObservation {
    pub provider: NetworkProvider,
    pub scope: NetworkScope,
    pub status: NetworkProbeStatus,
    pub provenance: NetworkProvenance,
    pub evidence_level: EvidenceLevel,
    pub claim_authority: &'static str,
    pub observed_account_id: NetworkAccountId,
    pub observed_program_id: Option<ProgramId>,
    pub program_revision: Option<u64>,
    pub program_digest: Option<String>,
    pub observed_at: DateTime<Utc>,
    pub evidence_digest: String,
    /// Only an independently recorded native credential/permission/probe/
    /// readback canary may populate this field.  Provider payloads cannot.
    pub native_canary_digest: Option<String>,
    #[serde(skip)]
    pub(crate) native_canary_attested: bool,
}

impl NetworkProbeObservation {
    pub fn can_claim_connected(&self) -> bool {
        self.status == NetworkProbeStatus::Reachable
            && self.provenance == NetworkProvenance::ProductionProvider
            && self.claim_authority == "native_canary_readback"
            && self.native_canary_digest.as_deref().is_some_and(is_sha256)
            && self.native_canary_attested
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkResource {
    Programs,
    Partners,
    Contracts,
    Links,
    Clicks,
    Conversions,
    Actions,
    Commissions,
    Reversals,
    Payouts,
    Reports,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadCursor {
    token_digest: String,
    binding_digest: Option<String>,
    sequence: u64,
}

impl ReadCursor {
    pub fn new(value: impl Into<String>) -> Result<Self, PartnerNetworkError> {
        let value = value.into();
        let cursor = Self {
            token_digest: value,
            binding_digest: None,
            sequence: 0,
        };
        cursor.validate()?;
        Ok(cursor)
    }

    pub fn bound(
        scope: &NetworkScope,
        resource: NetworkResource,
        expected_program: Option<&ProgramExpectation>,
        window: Option<&SettlementPeriod>,
        authorization_generation: &str,
        sequence: u64,
        token: impl Into<String>,
    ) -> Result<Self, PartnerNetworkError> {
        if authorization_generation.trim().is_empty() || sequence == 0 {
            return Err(PartnerNetworkError::InvalidReadCursor);
        }
        let token = token.into();
        let token_digest = if is_sha256(&token) {
            token
        } else {
            digest_bytes(token.as_bytes())
        };
        let binding_digest = cursor_binding_digest(
            scope,
            resource,
            expected_program,
            window,
            authorization_generation,
            sequence,
        )?;
        let cursor = Self {
            token_digest,
            binding_digest: Some(binding_digest),
            sequence,
        };
        cursor.validate()?;
        Ok(cursor)
    }

    pub fn validate(&self) -> Result<(), PartnerNetworkError> {
        if self.token_digest.trim().is_empty()
            || self.token_digest.chars().any(char::is_control)
            || (self
                .binding_digest
                .as_deref()
                .is_some_and(|digest| !is_sha256(digest)))
            || (self.binding_digest.is_some() && !is_sha256(&self.token_digest))
        {
            return Err(PartnerNetworkError::InvalidReadCursor);
        }
        Ok(())
    }

    pub fn as_str(&self) -> &str {
        &self.token_digest
    }

    pub fn binding_digest(&self) -> Option<&str> {
        self.binding_digest.as_deref()
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn is_bound(&self) -> bool {
        self.binding_digest.is_some() && self.sequence > 0
    }

    pub(crate) fn validate_for(
        &self,
        scope: &NetworkScope,
        resource: NetworkResource,
        expected_program: Option<&ProgramExpectation>,
        window: Option<&SettlementPeriod>,
        authorization_generation: &str,
    ) -> Result<(), PartnerNetworkError> {
        self.validate()?;
        let expected = cursor_binding_digest(
            scope,
            resource,
            expected_program,
            window,
            authorization_generation,
            self.sequence,
        )?;
        if self.binding_digest.as_deref() != Some(expected.as_str()) {
            return Err(PartnerNetworkError::CursorBindingMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadPage {
    pub cursor: Option<ReadCursor>,
    pub next_cursor: Option<ReadCursor>,
    pub has_more: bool,
    pub item_count: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkReadRequest {
    pub scope: NetworkScope,
    pub resource: NetworkResource,
    pub expected_program: Option<ProgramExpectation>,
    pub cursor: Option<ReadCursor>,
    pub window: Option<SettlementPeriod>,
    pub authorization_generation: Option<String>,
    pub limit: u16,
    pub observed_at: DateTime<Utc>,
}

impl NetworkReadRequest {
    pub fn new(scope: NetworkScope, resource: NetworkResource, observed_at: DateTime<Utc>) -> Self {
        Self {
            scope,
            resource,
            expected_program: None,
            cursor: None,
            window: None,
            authorization_generation: None,
            limit: 100,
            observed_at,
        }
    }

    pub fn for_program(
        scope: NetworkScope,
        resource: NetworkResource,
        expected_program: ProgramExpectation,
        observed_at: DateTime<Utc>,
    ) -> Self {
        Self {
            scope,
            resource,
            expected_program: Some(expected_program),
            cursor: None,
            window: None,
            authorization_generation: None,
            limit: 100,
            observed_at,
        }
    }

    pub fn validate(&self) -> Result<(), PartnerNetworkError> {
        self.scope.validate()?;
        if let Some(expected_program) = &self.expected_program {
            expected_program.validate()?;
        }
        if let Some(cursor) = &self.cursor {
            cursor.validate()?;
            let authorization_generation = self
                .authorization_generation
                .as_deref()
                .ok_or(PartnerNetworkError::CursorBindingMismatch)?;
            cursor.validate_for(
                &self.scope,
                self.resource,
                self.expected_program.as_ref(),
                self.window.as_ref(),
                authorization_generation,
            )?;
        }
        if let Some(window) = &self.window {
            SettlementPeriod::new(window.started_at, window.ended_at)?;
        }
        if self
            .authorization_generation
            .as_deref()
            .is_some_and(|generation| generation.trim().is_empty())
        {
            return Err(PartnerNetworkError::InvalidAuthorizationGrant);
        }
        if self.limit == 0 || self.limit > 500 {
            return Err(PartnerNetworkError::InvalidReadLimit);
        }
        Ok(())
    }

    pub fn with_window(mut self, window: SettlementPeriod) -> Result<Self, PartnerNetworkError> {
        window.validate()?;
        self.window = Some(window);
        Ok(self)
    }

    #[must_use]
    pub fn with_authorization_generation(mut self, generation: impl Into<String>) -> Self {
        self.authorization_generation = Some(generation.into());
        self
    }

    pub(crate) fn cursor_digest(&self) -> String {
        self.cursor.as_ref().map_or_else(
            || {
                cursor_binding_digest(
                    &self.scope,
                    self.resource,
                    self.expected_program.as_ref(),
                    self.window.as_ref(),
                    self.authorization_generation
                        .as_deref()
                        .unwrap_or("unbound"),
                    0,
                )
                .unwrap_or_else(|_| digest_bytes(b"invalid-initial-cursor"))
            },
            |cursor| cursor.as_str().to_owned(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgramState {
    Active,
    Paused,
    Expired,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartnerRelationshipState {
    Applied,
    Active,
    Suspended,
    Terminated,
    NotJoined,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractState {
    Pending,
    Active,
    Expired,
    Terminated,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConversionState {
    Pending,
    Approved,
    Declined,
    Refunded,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionState {
    Pending,
    Approved,
    Reversed,
    Paid,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommissionState {
    Pending,
    Accrued,
    Reversed,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReversalState {
    Pending,
    Applied,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PayoutState {
    Pending,
    Completed,
    Failed,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportSettlementState {
    Current,
    RecalculationRequired,
    Outstanding,
    Paid,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SettlementPeriod {
    pub started_at: DateTime<Utc>,
    pub ended_at: DateTime<Utc>,
}

impl SettlementPeriod {
    pub fn new(
        started_at: DateTime<Utc>,
        ended_at: DateTime<Utc>,
    ) -> Result<Self, PartnerNetworkError> {
        if started_at >= ended_at {
            return Err(PartnerNetworkError::InvalidSettlementPeriod);
        }
        Ok(Self {
            started_at,
            ended_at,
        })
    }

    pub fn validate(&self) -> Result<(), PartnerNetworkError> {
        if self.started_at >= self.ended_at {
            return Err(PartnerNetworkError::InvalidSettlementPeriod);
        }
        Ok(())
    }
}

macro_rules! source_record {
    ($name:ident { $($field:ident : $type:ty),* $(,)? }) => {
        #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        pub struct $name {
            $(pub $field: $type,)*
            pub observed_at: DateTime<Utc>,
            pub source_digest: String,
        }
    };
}

source_record!(ProgramRecord {
    account_id: NetworkAccountId,
    id: ProgramId,
    revision: u64,
    state: ProgramState,
    terms_digest: String,
});

source_record!(PartnerRecord {
    account_id: NetworkAccountId,
    program_id: ProgramId,
    id: PartnerId,
    relationship: PartnerRelationshipState,
    display_name_digest: String,
});

source_record!(ContractRecord {
    account_id: NetworkAccountId,
    program_id: ProgramId,
    id: ContractId,
    partner_id: PartnerId,
    state: ContractState,
    currency: CurrencyCode,
    terms_digest: String,
    effective_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
});

source_record!(TrackingLinkRecord {
    account_id: NetworkAccountId,
    program_id: ProgramId,
    id: LinkId,
    partner_id: PartnerId,
    destination_digest: String,
    tracking_reference_digest: String,
    active: bool,
});

source_record!(ClickRecord {
    account_id: NetworkAccountId,
    program_id: ProgramId,
    id: ClickId,
    link_id: LinkId,
    occurred_at: DateTime<Utc>,
});

source_record!(ConversionRecord {
    account_id: NetworkAccountId,
    program_id: ProgramId,
    id: ConversionId,
    order_id: NetworkOrderId,
    partner_id: PartnerId,
    click_id: Option<ClickId>,
    action_id: Option<ActionId>,
    state: ConversionState,
    amount: Money,
    occurred_at: DateTime<Utc>,
});

source_record!(ActionRecord {
    account_id: NetworkAccountId,
    program_id: ProgramId,
    id: ActionId,
    conversion_id: ConversionId,
    order_id: NetworkOrderId,
    partner_id: PartnerId,
    click_id: Option<ClickId>,
    state: ActionState,
    commission_id: Option<CommissionId>,
    amount: Money,
    occurred_at: DateTime<Utc>,
});

source_record!(CommissionRecord {
    account_id: NetworkAccountId,
    program_id: ProgramId,
    id: CommissionId,
    action_id: ActionId,
    order_id: NetworkOrderId,
    partner_id: PartnerId,
    state: CommissionState,
    amount: Money,
    occurred_at: DateTime<Utc>,
});

source_record!(ReversalRecord {
    account_id: NetworkAccountId,
    program_id: ProgramId,
    id: ReversalId,
    commission_id: CommissionId,
    action_id: ActionId,
    order_id: NetworkOrderId,
    partner_id: PartnerId,
    state: ReversalState,
    amount: Money,
    reason_digest: String,
    occurred_at: DateTime<Utc>,
});

source_record!(PayoutRecord {
    account_id: NetworkAccountId,
    program_id: ProgramId,
    id: PayoutId,
    partner_id: PartnerId,
    state: PayoutState,
    amount: Money,
    period: SettlementPeriod,
    occurred_at: DateTime<Utc>,
});

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReportRow {
    pub action_id: Option<ActionId>,
    pub conversion_id: Option<ConversionId>,
    pub commission_id: Option<CommissionId>,
    pub reversal_id: Option<ReversalId>,
    pub payout_id: Option<PayoutId>,
    pub amount: Option<Money>,
    pub occurred_at: DateTime<Utc>,
    pub source_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReportRecord {
    pub account_id: NetworkAccountId,
    pub program_id: ProgramId,
    pub id: ReportId,
    pub period: SettlementPeriod,
    pub settlement_state: ReportSettlementState,
    pub rows: Vec<ReportRow>,
    pub commissions: Vec<CommissionRecord>,
    pub reversals: Vec<ReversalRecord>,
    pub payouts: Vec<PayoutRecord>,
    pub observed_at: DateTime<Utc>,
    pub source_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "resource", deny_unknown_fields)]
pub enum NetworkReadData {
    Programs { records: Vec<ProgramRecord> },
    Partners { records: Vec<PartnerRecord> },
    Contracts { records: Vec<ContractRecord> },
    Links { records: Vec<TrackingLinkRecord> },
    Clicks { records: Vec<ClickRecord> },
    Conversions { records: Vec<ConversionRecord> },
    Actions { records: Vec<ActionRecord> },
    Commissions { records: Vec<CommissionRecord> },
    Reversals { records: Vec<ReversalRecord> },
    Payouts { records: Vec<PayoutRecord> },
    Reports { records: Vec<ReportRecord> },
}

impl NetworkReadData {
    pub const fn resource(&self) -> NetworkResource {
        match self {
            Self::Programs { .. } => NetworkResource::Programs,
            Self::Partners { .. } => NetworkResource::Partners,
            Self::Contracts { .. } => NetworkResource::Contracts,
            Self::Links { .. } => NetworkResource::Links,
            Self::Clicks { .. } => NetworkResource::Clicks,
            Self::Conversions { .. } => NetworkResource::Conversions,
            Self::Actions { .. } => NetworkResource::Actions,
            Self::Commissions { .. } => NetworkResource::Commissions,
            Self::Reversals { .. } => NetworkResource::Reversals,
            Self::Payouts { .. } => NetworkResource::Payouts,
            Self::Reports { .. } => NetworkResource::Reports,
        }
    }

    pub fn item_count(&self) -> usize {
        match self {
            Self::Programs { records } => records.len(),
            Self::Partners { records } => records.len(),
            Self::Contracts { records } => records.len(),
            Self::Links { records } => records.len(),
            Self::Clicks { records } => records.len(),
            Self::Conversions { records } => records.len(),
            Self::Actions { records } => records.len(),
            Self::Commissions { records } => records.len(),
            Self::Reversals { records } => records.len(),
            Self::Payouts { records } => records.len(),
            Self::Reports { records } => records.len(),
        }
    }

    pub fn program_ids(&self) -> BTreeSet<ProgramId> {
        match self {
            Self::Programs { records } => records.iter().map(|record| record.id.clone()).collect(),
            Self::Partners { records } => records
                .iter()
                .map(|record| record.program_id.clone())
                .collect(),
            Self::Contracts { records } => records
                .iter()
                .map(|record| record.program_id.clone())
                .collect(),
            Self::Links { records } => records
                .iter()
                .map(|record| record.program_id.clone())
                .collect(),
            Self::Clicks { records } => records
                .iter()
                .map(|record| record.program_id.clone())
                .collect(),
            Self::Conversions { records } => records
                .iter()
                .map(|record| record.program_id.clone())
                .collect(),
            Self::Actions { records } => records
                .iter()
                .map(|record| record.program_id.clone())
                .collect(),
            Self::Commissions { records } => records
                .iter()
                .map(|record| record.program_id.clone())
                .collect(),
            Self::Reversals { records } => records
                .iter()
                .map(|record| record.program_id.clone())
                .collect(),
            Self::Payouts { records } => records
                .iter()
                .map(|record| record.program_id.clone())
                .collect(),
            Self::Reports { records } => records
                .iter()
                .map(|record| record.program_id.clone())
                .collect(),
        }
    }

    #[allow(clippy::too_many_lines)]
    pub fn validate_for(&self, scope: &NetworkScope) -> Result<(), PartnerNetworkError> {
        let account_id = &scope.account_id;
        let program_id = scope.program_id.as_ref();
        let validate = |record_account: &NetworkAccountId,
                        record_program: Option<&ProgramId>,
                        source_digest: &str| {
            if record_account != account_id
                || program_id.is_some_and(|expected| record_program != Some(expected))
                || !is_sha256(source_digest)
            {
                Err(PartnerNetworkError::ReadScopeOrEvidenceMismatch)
            } else {
                Ok(())
            }
        };
        match self {
            Self::Programs { records } => {
                for record in records {
                    validate(&record.account_id, Some(&record.id), &record.source_digest)?;
                }
            }
            Self::Partners { records } => {
                for record in records {
                    validate(
                        &record.account_id,
                        Some(&record.program_id),
                        &record.source_digest,
                    )?;
                }
            }
            Self::Contracts { records } => {
                for record in records {
                    validate(
                        &record.account_id,
                        Some(&record.program_id),
                        &record.source_digest,
                    )?;
                }
            }
            Self::Links { records } => {
                for record in records {
                    validate(
                        &record.account_id,
                        Some(&record.program_id),
                        &record.source_digest,
                    )?;
                }
            }
            Self::Clicks { records } => {
                for record in records {
                    validate(
                        &record.account_id,
                        Some(&record.program_id),
                        &record.source_digest,
                    )?;
                }
            }
            Self::Conversions { records } => {
                for record in records {
                    validate(
                        &record.account_id,
                        Some(&record.program_id),
                        &record.source_digest,
                    )?;
                }
            }
            Self::Actions { records } => {
                for record in records {
                    validate(
                        &record.account_id,
                        Some(&record.program_id),
                        &record.source_digest,
                    )?;
                }
            }
            Self::Commissions { records } => {
                for record in records {
                    validate(
                        &record.account_id,
                        Some(&record.program_id),
                        &record.source_digest,
                    )?;
                }
            }
            Self::Reversals { records } => {
                for record in records {
                    validate(
                        &record.account_id,
                        Some(&record.program_id),
                        &record.source_digest,
                    )?;
                }
            }
            Self::Payouts { records } => {
                for record in records {
                    validate(
                        &record.account_id,
                        Some(&record.program_id),
                        &record.source_digest,
                    )?;
                }
            }
            Self::Reports { records } => {
                for record in records {
                    validate(
                        &record.account_id,
                        Some(&record.program_id),
                        &record.source_digest,
                    )?;
                    for commission in &record.commissions {
                        validate(
                            &commission.account_id,
                            Some(&commission.program_id),
                            &commission.source_digest,
                        )?;
                    }
                    for reversal in &record.reversals {
                        validate(
                            &reversal.account_id,
                            Some(&reversal.program_id),
                            &reversal.source_digest,
                        )?;
                    }
                    for payout in &record.payouts {
                        validate(
                            &payout.account_id,
                            Some(&payout.program_id),
                            &payout.source_digest,
                        )?;
                    }
                    for row in &record.rows {
                        if !is_sha256(&row.source_digest) {
                            return Err(PartnerNetworkError::ReadScopeOrEvidenceMismatch);
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkReadBudgetReceipt {
    pub quota_limit: u16,
    pub quota_remaining: u16,
    pub rate_limit_remaining: u16,
    pub rate_limit_reset_at: DateTime<Utc>,
    pub cost_units: u32,
    pub freshness_expires_at: DateTime<Utc>,
    pub source: String,
    pub evidence_digest: String,
}

impl NetworkReadBudgetReceipt {
    pub(crate) fn local(observed_at: DateTime<Utc>, limit: u16) -> Self {
        let rate_limit_reset_at = observed_at + Duration::minutes(1);
        let freshness_expires_at = observed_at + Duration::seconds(30);
        let value = (
            limit,
            limit.saturating_sub(1),
            0_u16,
            rate_limit_reset_at,
            1_u32,
            freshness_expires_at,
            "adapter-bounded-local",
        );
        let evidence_digest = canonical_digest(&value).expect("local read receipt is serializable");
        Self {
            quota_limit: limit,
            quota_remaining: limit.saturating_sub(1),
            rate_limit_remaining: 0,
            rate_limit_reset_at,
            cost_units: 1,
            freshness_expires_at,
            source: "adapter-bounded-local".into(),
            evidence_digest,
        }
    }

    pub fn validate_at(&self, observed_at: DateTime<Utc>) -> Result<(), PartnerNetworkError> {
        if self.quota_remaining > self.quota_limit
            || self.cost_units == 0
            || self.rate_limit_reset_at < observed_at
            || self.freshness_expires_at <= observed_at
            || self.source.trim().is_empty()
        {
            return Err(PartnerNetworkError::InvalidReadReceipt);
        }
        let value = (
            self.quota_limit,
            self.quota_remaining,
            self.rate_limit_remaining,
            self.rate_limit_reset_at,
            self.cost_units,
            self.freshness_expires_at,
            self.source.as_str(),
        );
        if self.evidence_digest != canonical_digest(&value)? {
            return Err(PartnerNetworkError::ReadScopeOrEvidenceMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkReadObservation {
    pub provider: NetworkProvider,
    pub scope: NetworkScope,
    pub request: NetworkResource,
    pub data: NetworkReadData,
    pub page: ReadPage,
    pub expected_program: Option<ProgramExpectation>,
    pub window: Option<SettlementPeriod>,
    pub observed_program_id: Option<ProgramId>,
    pub program_revision: Option<u64>,
    pub program_terms_digest: Option<String>,
    pub authorization_revision: u64,
    pub authorization_generation: String,
    pub cursor_digest: String,
    pub provenance: NetworkProvenance,
    pub evidence_level: EvidenceLevel,
    pub observed_at: DateTime<Utc>,
    pub source_digest: String,
    pub budget: NetworkReadBudgetReceipt,
    pub native_canary_digest: Option<String>,
    pub adapter_version: u32,
    pub registration_identity: String,
    pub registration_digest: String,
    #[serde(skip)]
    pub(crate) native_canary_attested: bool,
    pub evidence_digest: String,
}

impl NetworkReadObservation {
    pub fn validate(&self) -> Result<(), PartnerNetworkError> {
        self.scope.validate()?;
        let expected_source_digest = canonical_digest(&self.data)?;
        if let Some(expected_program) = &self.expected_program {
            expected_program.validate()?;
        }
        if let Some(window) = &self.window {
            window.validate()?;
        }
        if self.authorization_revision == 0
            || self.authorization_generation.trim().is_empty()
            || !is_sha256(&self.cursor_digest)
            || self.adapter_version == 0
            || self.registration_identity != partner_registration_identity(self.provider)
            || !is_sha256(&self.registration_digest)
            || self
                .native_canary_digest
                .as_deref()
                .is_some_and(|digest| !is_sha256(digest))
            || (self.native_canary_digest.is_some() && !self.native_canary_attested)
        {
            return Err(PartnerNetworkError::ReadScopeOrEvidenceMismatch);
        }
        if self.registration_digest != partner_registration_digest(self.provider)? {
            return Err(PartnerNetworkError::MissionBindingMismatch);
        }
        if self.provenance == NetworkProvenance::ProductionProvider
            && (!self.native_canary_attested || self.native_canary_digest.is_none())
        {
            return Err(PartnerNetworkError::NativeCanaryRequired);
        }
        if self.request != self.data.resource()
            || self.page.item_count as usize != self.data.item_count()
            || self.source_digest != expected_source_digest
        {
            return Err(PartnerNetworkError::ReadScopeOrEvidenceMismatch);
        }
        self.data.validate_for(&self.scope)?;
        verify_program_expectation(
            &self.scope,
            self.expected_program.as_ref(),
            self.observed_program_id.as_ref(),
            self.program_revision,
            self.program_terms_digest.as_deref(),
        )?;
        for cursor in [self.page.cursor.as_ref(), self.page.next_cursor.as_ref()]
            .into_iter()
            .flatten()
        {
            cursor.validate_for(
                &self.scope,
                self.request,
                self.expected_program.as_ref(),
                self.window.as_ref(),
                &self.authorization_generation,
            )?;
        }
        self.budget.validate_at(self.observed_at)?;
        let evidence = read_observation_evidence_digest(self)?;
        if self.evidence_digest != evidence {
            return Err(PartnerNetworkError::ReadScopeOrEvidenceMismatch);
        }
        Ok(())
    }
}

pub(crate) fn read_observation_evidence_digest(
    observation: &NetworkReadObservation,
) -> Result<String, PartnerNetworkError> {
    canonical_digest(&(
        (
            &observation.provider,
            &observation.scope,
            &observation.request,
            &observation.source_digest,
            &observation.expected_program,
            &observation.window,
            &observation.observed_program_id,
            &observation.program_revision,
            &observation.program_terms_digest,
        ),
        (
            &observation.authorization_revision,
            &observation.authorization_generation,
            &observation.cursor_digest,
            &observation.page,
            &observation.provenance,
            &observation.evidence_level,
            &observation.observed_at,
            &observation.budget,
            &observation.native_canary_digest,
            &observation.adapter_version,
            &observation.registration_identity,
            &observation.registration_digest,
        ),
    ))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionOutcomeClassification {
    FixtureEvidence,
    ControlledEvidence,
    NativeCanaryEvidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionOutcomeReceipt {
    pub provider: NetworkProvider,
    pub scope: NetworkScope,
    pub expected_program: ProgramExpectation,
    pub window: SettlementPeriod,
    pub cursor_digest: String,
    pub source_digest: String,
    pub authorization_revision: u64,
    pub authorization_generation: String,
    pub adapter_version: u32,
    pub registration_identity: String,
    pub registration_digest: String,
    pub observed_at: DateTime<Utc>,
    pub classification: MissionOutcomeClassification,
    pub claim_connected: bool,
    pub evidence_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionOutcomeBinding {
    pub authorization_revision: u64,
    pub authorization_generation: String,
    pub adapter_version: u32,
    pub registration_identity: String,
    pub registration_digest: String,
}

impl MissionOutcomeBinding {
    pub fn new(
        authorization_revision: u64,
        authorization_generation: impl Into<String>,
        adapter_version: u32,
        registration_identity: impl Into<String>,
        registration_digest: impl Into<String>,
    ) -> Result<Self, PartnerNetworkError> {
        let binding = Self {
            authorization_revision,
            authorization_generation: authorization_generation.into(),
            adapter_version,
            registration_identity: registration_identity.into(),
            registration_digest: registration_digest.into(),
        };
        if binding.authorization_revision == 0
            || binding.authorization_generation.trim().is_empty()
            || binding.adapter_version == 0
            || binding.registration_identity.trim().is_empty()
            || !is_sha256(&binding.registration_digest)
        {
            return Err(PartnerNetworkError::MissionBindingMismatch);
        }
        Ok(binding)
    }
}

#[derive(Clone, Debug)]
pub struct PartnerMissionConsumer {
    provider: NetworkProvider,
    scope: NetworkScope,
    expected_program: ProgramExpectation,
    window: SettlementPeriod,
    binding: MissionOutcomeBinding,
}

impl PartnerMissionConsumer {
    pub fn new(
        provider: NetworkProvider,
        scope: NetworkScope,
        expected_program: ProgramExpectation,
        window: SettlementPeriod,
        binding: MissionOutcomeBinding,
    ) -> Result<Self, PartnerNetworkError> {
        scope.validate()?;
        expected_program.validate()?;
        window.validate()?;
        if scope.program_id.as_ref() != Some(&expected_program.program_id) {
            return Err(PartnerNetworkError::ProgramDrift);
        }
        if binding.registration_identity != partner_registration_identity(provider)
            || binding.registration_digest != partner_registration_digest(provider)?
        {
            return Err(PartnerNetworkError::MissionBindingMismatch);
        }
        Ok(Self {
            provider,
            scope,
            expected_program,
            window,
            binding,
        })
    }

    pub fn consume(
        &self,
        observation: &NetworkReadObservation,
    ) -> Result<MissionOutcomeReceipt, PartnerNetworkError> {
        observation.validate()?;
        if observation.provider != self.provider
            || observation.scope != self.scope
            || observation.expected_program.as_ref() != Some(&self.expected_program)
            || observation.window.as_ref() != Some(&self.window)
            || observation.authorization_revision != self.binding.authorization_revision
            || observation.authorization_generation != self.binding.authorization_generation
            || observation.adapter_version != self.binding.adapter_version
            || observation.registration_identity != self.binding.registration_identity
            || observation.registration_digest != self.binding.registration_digest
        {
            return Err(PartnerNetworkError::MissionBindingMismatch);
        }
        let classification = match observation.provenance {
            NetworkProvenance::Fixture => MissionOutcomeClassification::FixtureEvidence,
            NetworkProvenance::ControlledProvider => {
                MissionOutcomeClassification::ControlledEvidence
            }
            NetworkProvenance::ProductionProvider => {
                if observation.native_canary_digest.is_none() || !observation.native_canary_attested
                {
                    return Err(PartnerNetworkError::NativeCanaryRequired);
                }
                MissionOutcomeClassification::NativeCanaryEvidence
            }
        };
        let claim_connected = classification == MissionOutcomeClassification::NativeCanaryEvidence;
        let evidence_digest = canonical_digest(&(
            &observation.provider,
            &observation.scope,
            &self.expected_program,
            &self.window,
            &observation.cursor_digest,
            &observation.source_digest,
            &observation.authorization_revision,
            &observation.authorization_generation,
            &observation.adapter_version,
            &observation.registration_identity,
            &observation.registration_digest,
            &observation.observed_at,
            &classification,
            &claim_connected,
            &observation.evidence_digest,
        ))?;
        Ok(MissionOutcomeReceipt {
            provider: observation.provider,
            scope: observation.scope.clone(),
            expected_program: self.expected_program.clone(),
            window: self.window.clone(),
            cursor_digest: observation.cursor_digest.clone(),
            source_digest: observation.source_digest.clone(),
            authorization_revision: observation.authorization_revision,
            authorization_generation: observation.authorization_generation.clone(),
            adapter_version: observation.adapter_version,
            registration_identity: observation.registration_identity.clone(),
            registration_digest: observation.registration_digest.clone(),
            observed_at: observation.observed_at,
            classification,
            claim_connected,
            evidence_digest,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureScenario {
    HappyPath,
    DuplicateConversion,
    CrossPeriodRefund,
    CommissionReversal,
    DelayedPayout,
    ScopeRevoked,
    ProgramDrift,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockedEnvironmentReason {
    CommercialAuthorizationMissing,
    TransportNotConfigured,
    OfficialApiCapabilityNotEnabled,
    ProductionCallbackVerifierRequired,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum PartnerNetworkError {
    #[error("partner network scope is invalid")]
    InvalidScope,
    #[error("partner network authorization reference is invalid")]
    InvalidAuthorizationReference,
    #[error("partner network authorization grant is invalid")]
    InvalidAuthorizationGrant,
    #[error("authorization is required for {provider} scope {scope_digest}")]
    AuthorizationRequired {
        provider: NetworkProvider,
        scope_digest: String,
    },
    #[error("partner network environment is blocked for {provider}: {reason:?}")]
    BlockedEnv {
        provider: NetworkProvider,
        reason: BlockedEnvironmentReason,
    },
    #[error("partner network scope has been revoked")]
    ScopeRevoked,
    #[error("partner network program drifted from the requested revision")]
    ProgramDrift,
    #[error("partner network request scope does not match the adapter")]
    ScopeMismatch,
    #[error("partner network authorization has expired")]
    AuthorizationExpired,
    #[error("partner network read cursor is invalid")]
    InvalidReadCursor,
    #[error("partner network read limit is outside the bounded range")]
    InvalidReadLimit,
    #[error("partner network program expectation is invalid")]
    InvalidProgramExpectation,
    #[error("partner network read scope or source evidence is invalid")]
    ReadScopeOrEvidenceMismatch,
    #[error("partner network callback signature is invalid")]
    InvalidSignature,
    #[error("partner network callback body is malformed")]
    MalformedCallback,
    #[error("partner network callback replay identity is invalid")]
    InvalidReplayIdentity,
    #[error("partner network callback timestamp is outside the replay window")]
    ReplayWindowExpired,
    #[error("partner network callback is out of scope")]
    CallbackScopeMismatch,
    #[error("partner network provider transport is unavailable")]
    ProviderUnavailable,
    #[error("partner network identity is duplicated in one response")]
    DuplicateIdentity,
    #[error("partner network settlement period is invalid")]
    InvalidSettlementPeriod,
    #[error("partner network callback signature scheme is unsupported")]
    UnsupportedCallbackSignature,
    #[error("partner network provider provenance is not independently attested")]
    UntrustedProvenance,
    #[error("partner network native credential/probe/readback canary is required")]
    NativeCanaryRequired,
    #[error("partner network durable state or receipt store is unavailable")]
    DurabilityUnavailable,
    #[error("partner network read cursor binding does not match the request generation")]
    CursorBindingMismatch,
    #[error("partner network read budget receipt is invalid")]
    InvalidReadReceipt,
    #[error("partner network Mission outcome binding does not match the exact tuple")]
    MissionBindingMismatch,
    #[error("partner network published JSON Schema validation failed")]
    SchemaValidationFailed,
    #[error("partner network callback replay quota is exhausted")]
    ReplayQuotaExceeded,
    #[error("partner network callback replay rate is limited")]
    ReplayRateLimited,
    #[error("partner network callback key lease is not bound to the request tuple")]
    InvalidCallbackLease,
}

/// Provider-native typed operations consumed by the SDK bridge. This is not
/// a second connector lifecycle: callers use `hartevo_connector_sdk::ConnectorAdapter`
/// and `ConnectorWorker` for generic auth, probes, reads, callbacks, and
/// revocation; this crate keeps only the network-shaped evidence seam here.
pub trait TypedPartnerNetworkAdapter {
    fn provider(&self) -> NetworkProvider;

    fn authorize(
        &mut self,
        grant: AuthorizationGrant,
        observed_at: DateTime<Utc>,
    ) -> Result<AuthorizationObservation, PartnerNetworkError>;

    fn probe(
        &self,
        request: NetworkProbeRequest,
    ) -> Result<NetworkProbeObservation, PartnerNetworkError>;

    fn read(
        &self,
        request: NetworkReadRequest,
    ) -> Result<NetworkReadObservation, PartnerNetworkError>;

    fn handle_callback(
        &mut self,
        request: crate::callback::CallbackRequest<'_>,
    ) -> Result<crate::callback::CallbackObservation, PartnerNetworkError>;

    fn revoke(
        &mut self,
        scope: &NetworkScope,
        observed_at: DateTime<Utc>,
    ) -> Result<AuthorizationObservation, PartnerNetworkError>;

    fn accepted_callbacks(&self) -> Vec<crate::callback::CallbackEvent>;
}

fn validate_json_schema(
    schema: &Value,
    instance: &Value,
    root: &Value,
) -> Result<(), PartnerNetworkError> {
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        let pointer = reference
            .strip_prefix('#')
            .ok_or(PartnerNetworkError::SchemaValidationFailed)?;
        let resolved = root
            .pointer(pointer)
            .ok_or(PartnerNetworkError::SchemaValidationFailed)?;
        return validate_json_schema(resolved, instance, root);
    }
    if let Some(any_of) = schema.get("anyOf").and_then(Value::as_array) {
        if any_of
            .iter()
            .any(|candidate| validate_json_schema(candidate, instance, root).is_ok())
        {
            return Ok(());
        }
        return Err(PartnerNetworkError::SchemaValidationFailed);
    }
    if let Some(all_of) = schema.get("allOf").and_then(Value::as_array) {
        for candidate in all_of {
            validate_json_schema(candidate, instance, root)?;
        }
    }
    if let Some(expected) = schema.get("const")
        && expected != instance
    {
        return Err(PartnerNetworkError::SchemaValidationFailed);
    }
    if let Some(values) = schema.get("enum").and_then(Value::as_array)
        && !values.iter().any(|value| value == instance)
    {
        return Err(PartnerNetworkError::SchemaValidationFailed);
    }
    if let Some(expected_type) = schema.get("type")
        && !json_type_matches(expected_type, instance)
    {
        return Err(PartnerNetworkError::SchemaValidationFailed);
    }
    if let Some(minimum) = schema.get("minimum").and_then(Value::as_f64)
        && instance.as_f64().is_none_or(|value| value < minimum)
    {
        return Err(PartnerNetworkError::SchemaValidationFailed);
    }
    if let Some(min_length) = schema.get("minLength").and_then(Value::as_u64)
        && instance.as_str().is_none_or(|value| {
            usize::try_from(min_length).map_or(true, |minimum| value.chars().count() < minimum)
        })
    {
        return Err(PartnerNetworkError::SchemaValidationFailed);
    }
    if let Some(pattern) = schema.get("pattern").and_then(Value::as_str)
        && !schema_pattern_matches(pattern, instance.as_str().unwrap_or_default())
    {
        return Err(PartnerNetworkError::SchemaValidationFailed);
    }
    if schema.get("format").and_then(Value::as_str) == Some("date-time")
        && instance
            .as_str()
            .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
            .is_none()
    {
        return Err(PartnerNetworkError::SchemaValidationFailed);
    }
    if let Some(required) = schema.get("required").and_then(Value::as_array) {
        let object = instance
            .as_object()
            .ok_or(PartnerNetworkError::SchemaValidationFailed)?;
        for name in required.iter().filter_map(Value::as_str) {
            if !object.contains_key(name) {
                return Err(PartnerNetworkError::SchemaValidationFailed);
            }
        }
    }
    if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
        let object = instance
            .as_object()
            .ok_or(PartnerNetworkError::SchemaValidationFailed)?;
        for (name, property_schema) in properties {
            if let Some(value) = object.get(name) {
                validate_json_schema(property_schema, value, root)?;
            }
        }
        if schema.get("additionalProperties") == Some(&Value::Bool(false))
            && object.keys().any(|name| !properties.contains_key(name))
        {
            return Err(PartnerNetworkError::SchemaValidationFailed);
        }
    }
    if let Some(items) = schema.get("items") {
        for value in instance
            .as_array()
            .ok_or(PartnerNetworkError::SchemaValidationFailed)?
        {
            validate_json_schema(items, value, root)?;
        }
    }
    Ok(())
}

fn json_type_matches(expected: &Value, instance: &Value) -> bool {
    let matches = |kind: &str| match kind {
        "object" => instance.is_object(),
        "array" => instance.is_array(),
        "string" => instance.is_string(),
        "integer" => instance.as_i64().is_some() || instance.as_u64().is_some(),
        "number" => instance.is_number(),
        "boolean" => instance.is_boolean(),
        "null" => instance.is_null(),
        _ => false,
    };
    expected.as_str().map_or_else(
        || {
            expected
                .as_array()
                .is_some_and(|types| types.iter().filter_map(Value::as_str).any(matches))
        },
        matches,
    )
}

fn schema_pattern_matches(pattern: &str, value: &str) -> bool {
    if pattern == "^[0-9a-f]{64}$" {
        return is_sha256(value);
    }
    false
}

pub(crate) fn canonical_digest<T: Serialize>(value: &T) -> Result<String, PartnerNetworkError> {
    let bytes = serde_json::to_vec(value).map_err(|_| PartnerNetworkError::MalformedCallback)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn cursor_binding_digest(
    scope: &NetworkScope,
    resource: NetworkResource,
    expected_program: Option<&ProgramExpectation>,
    window: Option<&SettlementPeriod>,
    authorization_generation: &str,
    sequence: u64,
) -> Result<String, PartnerNetworkError> {
    canonical_digest(&(
        scope,
        &resource,
        expected_program,
        window,
        authorization_generation,
        sequence,
    ))
}

pub(crate) fn digest_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(crate) fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn fixture_digest(label: &str) -> String {
    digest_bytes(label.as_bytes())
}

pub(crate) fn authorization_observation(
    provider: NetworkProvider,
    grant: &AuthorizationGrant,
    state: AuthorizationState,
    observed_at: DateTime<Utc>,
) -> AuthorizationObservation {
    let binding = format!(
        "{}:{}:{}:{}:{:?}",
        provider,
        grant.scope.digest(),
        grant.secret_reference.revision(),
        grant.expires_at.to_rfc3339(),
        state
    );
    AuthorizationObservation {
        provider,
        scope: grant.scope.clone(),
        state,
        provenance: Some(grant.provenance()),
        reference_revision: Some(grant.secret_reference.revision()),
        observed_at,
        evidence_digest: digest_bytes(binding.as_bytes()),
    }
}

pub(crate) fn scope_authorized<'a>(
    provider: NetworkProvider,
    grant: Option<&'a AuthorizationGrant>,
    revoked_scopes: &[NetworkScope],
    scope: &NetworkScope,
    capability: NetworkCapability,
    now: DateTime<Utc>,
) -> Result<&'a AuthorizationGrant, PartnerNetworkError> {
    scope.validate()?;
    if revoked_scopes.iter().any(|revoked| revoked.covers(scope)) {
        return Err(PartnerNetworkError::ScopeRevoked);
    }
    let grant = grant.ok_or_else(|| PartnerNetworkError::AuthorizationRequired {
        provider,
        scope_digest: scope.digest(),
    })?;
    if !grant.scope.covers(scope) {
        return Err(PartnerNetworkError::AuthorizationRequired {
            provider,
            scope_digest: scope.digest(),
        });
    }
    if grant.expires_at <= now {
        return Err(PartnerNetworkError::AuthorizationExpired);
    }
    if !grant.capabilities.contains(&capability) {
        return Err(PartnerNetworkError::AuthorizationRequired {
            provider,
            scope_digest: scope.digest(),
        });
    }
    Ok(grant)
}

pub(crate) fn verify_program_expectation(
    request_scope: &NetworkScope,
    expected: Option<&ProgramExpectation>,
    observed_program_id: Option<&ProgramId>,
    observed_revision: Option<u64>,
    observed_terms_digest: Option<&str>,
) -> Result<(), PartnerNetworkError> {
    if let Some(expected) = expected {
        if request_scope.program_id.as_ref() != Some(&expected.program_id)
            || observed_program_id != Some(&expected.program_id)
            || observed_revision != Some(expected.revision)
            || observed_terms_digest != Some(expected.terms_digest.as_str())
        {
            return Err(PartnerNetworkError::ProgramDrift);
        }
    } else if let Some(requested_program) = &request_scope.program_id
        && observed_program_id != Some(requested_program)
    {
        return Err(PartnerNetworkError::ProgramDrift);
    }
    Ok(())
}

pub(crate) fn validate_scope_record_ids(data: &NetworkReadData) -> Result<(), PartnerNetworkError> {
    let mut ids = BTreeSet::new();
    match data {
        NetworkReadData::Programs { records } => {
            for record in records {
                if !ids.insert(format!("program:{}", record.id)) {
                    return Err(PartnerNetworkError::DuplicateIdentity);
                }
            }
        }
        NetworkReadData::Partners { records } => {
            for record in records {
                if !ids.insert(format!("partner:{}", record.id)) {
                    return Err(PartnerNetworkError::DuplicateIdentity);
                }
            }
        }
        NetworkReadData::Contracts { records } => {
            for record in records {
                if !ids.insert(format!("contract:{}", record.id)) {
                    return Err(PartnerNetworkError::DuplicateIdentity);
                }
            }
        }
        NetworkReadData::Links { records } => {
            for record in records {
                if !ids.insert(format!("link:{}", record.id)) {
                    return Err(PartnerNetworkError::DuplicateIdentity);
                }
            }
        }
        NetworkReadData::Clicks { records } => {
            for record in records {
                if !ids.insert(format!("click:{}", record.id)) {
                    return Err(PartnerNetworkError::DuplicateIdentity);
                }
            }
        }
        NetworkReadData::Conversions { records } => {
            for record in records {
                if !ids.insert(format!("conversion:{}", record.id)) {
                    return Err(PartnerNetworkError::DuplicateIdentity);
                }
            }
        }
        NetworkReadData::Actions { records } => {
            for record in records {
                if !ids.insert(format!("action:{}", record.id)) {
                    return Err(PartnerNetworkError::DuplicateIdentity);
                }
            }
        }
        NetworkReadData::Commissions { records } => {
            for record in records {
                if !ids.insert(format!("commission:{}", record.id)) {
                    return Err(PartnerNetworkError::DuplicateIdentity);
                }
            }
        }
        NetworkReadData::Reversals { records } => {
            for record in records {
                if !ids.insert(format!("reversal:{}", record.id)) {
                    return Err(PartnerNetworkError::DuplicateIdentity);
                }
            }
        }
        NetworkReadData::Payouts { records } => {
            for record in records {
                if !ids.insert(format!("payout:{}", record.id)) {
                    return Err(PartnerNetworkError::DuplicateIdentity);
                }
            }
        }
        NetworkReadData::Reports { records } => {
            for record in records {
                if !ids.insert(format!("report:{}", record.id)) {
                    return Err(PartnerNetworkError::DuplicateIdentity);
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn default_fixture_expiry(at: DateTime<Utc>) -> DateTime<Utc> {
    at + Duration::hours(1)
}

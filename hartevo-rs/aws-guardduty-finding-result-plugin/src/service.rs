//! GuardDuty service, registration, proposal, record, and verification seam.

use std::{
    fmt,
    sync::atomic::{AtomicU64, Ordering},
};

use serde::{Deserialize, Serialize, ser::SerializeStruct};

use crate::model::{
    AwsGuardDutyFindingEvidence, AwsGuardDutyFindingScope, Digest, GuardDutyFindingQuery, Revision,
    SecretReference,
};
use crate::provider::AwsGuardDutyProviderDefinition;
use crate::{
    AWS_GUARDDUTY_CONTRACT_VERSION, AWS_GUARDDUTY_PLUGIN_VERSION, AWS_GUARDDUTY_PROVIDER_REVISION,
    AWS_GUARDDUTY_SERVICE_ID, AwsGuardDutyFindingResultError, Result, api_digest, contract_digest,
    permission_digest,
};

static NEXT_REGISTRATION_REVISION: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
    Reversed,
}

impl RegistrationStatus {
    pub const fn active(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistrationRequest {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_revision: String,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope: AwsGuardDutyFindingScope,
    pub query: GuardDutyFindingQuery,
    pub secret_reference: SecretReference,
    pub registration_revision: Revision,
}

impl RegistrationRequest {
    pub fn baseline(
        scope: AwsGuardDutyFindingScope,
        query: GuardDutyFindingQuery,
        secret_reference: SecretReference,
    ) -> Result<Self> {
        let registration_revision =
            Revision::new(NEXT_REGISTRATION_REVISION.fetch_add(1, Ordering::Relaxed))?;
        Self::new(
            scope,
            query,
            secret_reference,
            AWS_GUARDDUTY_PROVIDER_REVISION,
            AwsGuardDutyProviderDefinition::baseline().provider_digest,
            api_digest(),
            permission_digest(),
            registration_revision,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: AwsGuardDutyFindingScope,
        query: GuardDutyFindingQuery,
        secret_reference: SecretReference,
        provider_revision: impl Into<String>,
        provider_digest: Digest,
        api_digest_value: Digest,
        permission_digest_value: Digest,
        registration_revision: Revision,
    ) -> Result<Self> {
        scope.validate()?;
        query.validate()?;
        if secret_reference.scope_digest() != &scope.digest()
            || provider_revision.into() != AWS_GUARDDUTY_PROVIDER_REVISION
            || provider_digest != AwsGuardDutyProviderDefinition::baseline().provider_digest
            || api_digest_value != api_digest()
            || permission_digest_value != permission_digest()
        {
            return Err(AwsGuardDutyFindingResultError::InvalidRegistration);
        }
        Ok(Self {
            plugin_version: AWS_GUARDDUTY_PLUGIN_VERSION.to_owned(),
            contract_version: AWS_GUARDDUTY_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_revision: AWS_GUARDDUTY_PROVIDER_REVISION.to_owned(),
            provider_digest,
            api_digest: api_digest_value,
            permission_digest: permission_digest_value,
            scope,
            query,
            secret_reference,
            registration_revision,
        })
    }
}

pub struct AwsGuardDutyRegistration {
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    provider_revision: String,
    provider_digest: Digest,
    api_digest: Digest,
    permission_digest: Digest,
    scope: AwsGuardDutyFindingScope,
    query: GuardDutyFindingQuery,
    secret_reference: SecretReference,
    registration_revision: Revision,
    registration_digest: Digest,
    status: RegistrationStatus,
    transition_revision: Option<Revision>,
}

impl fmt::Debug for AwsGuardDutyRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsGuardDutyRegistration")
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_revision", &self.provider_revision)
            .field("provider_digest", &self.provider_digest)
            .field("api_digest", &self.api_digest)
            .field("permission_digest", &self.permission_digest)
            .field("scope", &self.scope)
            .field("query", &self.query)
            .field("secret_reference", &self.secret_reference)
            .field("registration_revision", &self.registration_revision)
            .field("registration_digest", &self.registration_digest)
            .field("status", &self.status)
            .field("transition_revision", &self.transition_revision)
            .finish()
    }
}

impl Clone for AwsGuardDutyRegistration {
    fn clone(&self) -> Self {
        Self {
            plugin_version: self.plugin_version.clone(),
            contract_version: self.contract_version.clone(),
            contract_digest: self.contract_digest.clone(),
            provider_revision: self.provider_revision.clone(),
            provider_digest: self.provider_digest.clone(),
            api_digest: self.api_digest.clone(),
            permission_digest: self.permission_digest.clone(),
            scope: self.scope.clone(),
            query: self.query.clone(),
            secret_reference: self.secret_reference.clone(),
            registration_revision: self.registration_revision,
            registration_digest: self.registration_digest.clone(),
            status: self.status,
            transition_revision: self.transition_revision,
        }
    }
}

impl PartialEq for AwsGuardDutyRegistration {
    fn eq(&self, other: &Self) -> bool {
        self.plugin_version == other.plugin_version
            && self.contract_version == other.contract_version
            && self.contract_digest == other.contract_digest
            && self.provider_revision == other.provider_revision
            && self.provider_digest == other.provider_digest
            && self.api_digest == other.api_digest
            && self.permission_digest == other.permission_digest
            && self.scope == other.scope
            && self.query == other.query
            && self.secret_reference == other.secret_reference
            && self.registration_revision == other.registration_revision
            && self.registration_digest == other.registration_digest
            && self.status == other.status
            && self.transition_revision == other.transition_revision
    }
}

impl Eq for AwsGuardDutyRegistration {}

impl Serialize for AwsGuardDutyRegistration {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("AwsGuardDutyRegistration", 16)?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("apiDigest", &self.api_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest)?;
        state.serialize_field("scope", &self.scope)?;
        state.serialize_field("query", &self.query)?;
        state.serialize_field(
            "secretReferenceDigest",
            self.secret_reference.secret_reference_digest(),
        )?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("transitionRevision", &self.transition_revision)?;
        state.serialize_field("reversible", &true)?;
        state.serialize_field("revocable", &true)?;
        state.end()
    }
}

impl AwsGuardDutyRegistration {
    pub fn from_request(request: RegistrationRequest) -> Result<Self> {
        let registration_digest =
            Self::compute_digest_for_request(&request, RegistrationStatus::Active, None);
        let registration = Self {
            plugin_version: request.plugin_version,
            contract_version: request.contract_version,
            contract_digest: request.contract_digest,
            provider_revision: request.provider_revision,
            provider_digest: request.provider_digest,
            api_digest: request.api_digest,
            permission_digest: request.permission_digest,
            scope: request.scope,
            query: request.query,
            secret_reference: request.secret_reference,
            registration_revision: request.registration_revision,
            registration_digest,
            status: RegistrationStatus::Active,
            transition_revision: None,
        };
        registration.validate()?;
        Ok(registration)
    }

    fn compute_digest_for_request(
        request: &RegistrationRequest,
        status: RegistrationStatus,
        transition_revision: Option<Revision>,
    ) -> Digest {
        Digest::from_fields(
            "hartevo.aws-guardduty-registration/v1",
            &[
                request.plugin_version.clone(),
                request.contract_version.clone(),
                request.contract_digest.as_str().to_owned(),
                request.provider_revision.clone(),
                request.provider_digest.as_str().to_owned(),
                request.api_digest.as_str().to_owned(),
                request.permission_digest.as_str().to_owned(),
                request.scope.digest().as_str().to_owned(),
                request.query.digest().as_str().to_owned(),
                request
                    .secret_reference
                    .secret_reference_digest()
                    .as_str()
                    .to_owned(),
                request.registration_revision.get().to_string(),
                serde_json::to_string(&status).expect("registration status serializes"),
                transition_revision.map_or_else(String::new, |value| value.get().to_string()),
            ],
        )
    }

    fn compute_digest(&self) -> Digest {
        let request = RegistrationRequest {
            plugin_version: self.plugin_version.clone(),
            contract_version: self.contract_version.clone(),
            contract_digest: self.contract_digest.clone(),
            provider_revision: self.provider_revision.clone(),
            provider_digest: self.provider_digest.clone(),
            api_digest: self.api_digest.clone(),
            permission_digest: self.permission_digest.clone(),
            scope: self.scope.clone(),
            query: self.query.clone(),
            secret_reference: self.secret_reference.clone(),
            registration_revision: self.registration_revision,
        };
        Self::compute_digest_for_request(&request, self.status, self.transition_revision)
    }

    pub fn validate(&self) -> Result<()> {
        if self.plugin_version != AWS_GUARDDUTY_PLUGIN_VERSION
            || self.contract_version != AWS_GUARDDUTY_CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.provider_revision != AWS_GUARDDUTY_PROVIDER_REVISION
            || self.provider_digest != AwsGuardDutyProviderDefinition::baseline().provider_digest
            || self.api_digest != api_digest()
            || self.permission_digest != permission_digest()
            || self.secret_reference.scope_digest() != &self.scope.digest()
            || self.registration_digest != self.compute_digest()
        {
            return Err(AwsGuardDutyFindingResultError::InvalidRegistration);
        }
        self.scope.validate()?;
        self.query.validate()?;
        if self.secret_reference.is_revoked() {
            return Err(AwsGuardDutyFindingResultError::SecretRevoked);
        }
        Ok(())
    }

    pub fn is_active(&self) -> bool {
        self.status.active() && !self.secret_reference.is_revoked()
    }

    pub const fn status(&self) -> RegistrationStatus {
        self.status
    }

    pub fn scope(&self) -> &AwsGuardDutyFindingScope {
        &self.scope
    }

    pub fn query(&self) -> &GuardDutyFindingQuery {
        &self.query
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn api_digest(&self) -> &Digest {
        &self.api_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn transition_revision(&self) -> Option<Revision> {
        self.transition_revision
    }

    pub fn revoke(&mut self, transition_revision: Revision) -> Result<()> {
        self.validate()?;
        if !self.status.active() {
            return Err(AwsGuardDutyFindingResultError::RegistrationRevoked);
        }
        self.status = RegistrationStatus::Revoked;
        self.transition_revision = Some(transition_revision);
        self.registration_digest = self.compute_digest();
        Ok(())
    }

    pub fn reverse(&mut self, transition_revision: Revision) -> Result<()> {
        self.validate()?;
        if !self.status.active() {
            return Err(AwsGuardDutyFindingResultError::RegistrationRevoked);
        }
        self.status = RegistrationStatus::Reversed;
        self.transition_revision = Some(transition_revision);
        self.registration_digest = self.compute_digest();
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceOperation {
    DescribeCapabilities,
    Register,
    RevokeRegistration,
    ReverseRegistration,
    DiscoverDetectors,
    ListFindings,
    GetFindings,
    GetFindingsStatistics,
    Propose,
    Record,
    Verify,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Capability {
    pub operation: ServiceOperation,
    pub read_only: bool,
    pub mutates_provider: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub adopts_outcome: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsGuardDutyFindingService {
    capabilities: Vec<Capability>,
}

impl Default for AwsGuardDutyFindingService {
    fn default() -> Self {
        Self::new()
    }
}

impl AwsGuardDutyFindingService {
    pub fn new() -> Self {
        let operations = [
            ServiceOperation::DescribeCapabilities,
            ServiceOperation::Register,
            ServiceOperation::RevokeRegistration,
            ServiceOperation::ReverseRegistration,
            ServiceOperation::DiscoverDetectors,
            ServiceOperation::ListFindings,
            ServiceOperation::GetFindings,
            ServiceOperation::GetFindingsStatistics,
            ServiceOperation::Propose,
            ServiceOperation::Record,
            ServiceOperation::Verify,
        ];
        Self {
            capabilities: operations
                .into_iter()
                .map(|operation| Capability {
                    operation,
                    read_only: true,
                    mutates_provider: false,
                    native: false,
                    connected: false,
                    first_party: false,
                    adopts_outcome: false,
                })
                .collect(),
        }
    }

    pub fn service_id(&self) -> &'static str {
        AWS_GUARDDUTY_SERVICE_ID
    }

    pub fn service_name(&self) -> &'static str {
        crate::AWS_GUARDDUTY_SERVICE_NAME
    }

    pub const fn version(&self) -> &'static str {
        AWS_GUARDDUTY_PLUGIN_VERSION
    }

    pub fn capabilities(&self) -> &[Capability] {
        &self.capabilities
    }

    pub fn describe_capabilities(&self) -> Vec<Capability> {
        self.capabilities.clone()
    }

    pub fn validate(&self) -> Result<()> {
        if self.service_id() != AWS_GUARDDUTY_SERVICE_ID
            || self.service_name() != crate::AWS_GUARDDUTY_SERVICE_NAME
            || self.version() != AWS_GUARDDUTY_PLUGIN_VERSION
            || self.capabilities.len() != 11
            || self.capabilities.iter().any(|capability| {
                !capability.read_only
                    || capability.mutates_provider
                    || capability.native
                    || capability.connected
                    || capability.first_party
                    || capability.adopts_outcome
            })
        {
            return Err(AwsGuardDutyFindingResultError::InvalidRegistration);
        }
        Ok(())
    }

    pub fn register(
        &self,
        scope: AwsGuardDutyFindingScope,
        query: GuardDutyFindingQuery,
        secret_reference: SecretReference,
    ) -> Result<AwsGuardDutyRegistration> {
        self.validate()?;
        AwsGuardDutyRegistration::from_request(RegistrationRequest::baseline(
            scope,
            query,
            secret_reference,
        )?)
    }

    pub fn register_request(
        &self,
        request: RegistrationRequest,
    ) -> Result<AwsGuardDutyRegistration> {
        self.validate()?;
        AwsGuardDutyRegistration::from_request(request)
    }

    pub fn revoke_registration(
        &self,
        registration: &mut AwsGuardDutyRegistration,
        transition_revision: u64,
    ) -> Result<()> {
        self.validate()?;
        registration.revoke(Revision::new(transition_revision)?)
    }

    pub fn reverse_registration(
        &self,
        registration: &mut AwsGuardDutyRegistration,
        transition_revision: u64,
    ) -> Result<()> {
        self.validate()?;
        registration.reverse(Revision::new(transition_revision)?)
    }

    pub fn propose(
        &self,
        evidence: AwsGuardDutyFindingEvidence,
    ) -> Result<AwsGuardDutyFindingProposal> {
        self.validate()?;
        AwsGuardDutyFindingProposal::new(evidence)
    }

    pub fn record(
        &self,
        proposal: &AwsGuardDutyFindingProposal,
    ) -> Result<AwsGuardDutyFindingRecord> {
        self.validate()?;
        proposal.validate()?;
        AwsGuardDutyFindingRecord::new(proposal)
    }

    pub fn verify(
        &self,
        record: &AwsGuardDutyFindingRecord,
        scope: &AwsGuardDutyFindingScope,
        query: &GuardDutyFindingQuery,
    ) -> Result<VerificationReport> {
        self.validate()?;
        record.validate(scope, query)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsGuardDutyFindingProposal {
    pub evidence: AwsGuardDutyFindingEvidence,
    pub read_only: bool,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub truth_authority: bool,
    pub effect_authority: bool,
    pub receipt_authority: bool,
    pub verification_authority: bool,
    pub outcome_authority: bool,
    pub adopted: bool,
    pub proposal_digest: Digest,
}

impl AwsGuardDutyFindingProposal {
    pub fn new(evidence: AwsGuardDutyFindingEvidence) -> Result<Self> {
        if evidence.connected || evidence.native || evidence.first_party {
            return Err(AwsGuardDutyFindingResultError::TamperedEvidence);
        }
        let mut proposal = Self {
            evidence,
            read_only: true,
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            truth_authority: false,
            effect_authority: false,
            receipt_authority: false,
            verification_authority: false,
            outcome_authority: false,
            adopted: false,
            proposal_digest: Digest::from_text("pending-proposal-digest"),
        };
        proposal.proposal_digest = Digest::from_fields(
            "hartevo.aws-guardduty-proposal/v1",
            &[
                proposal.evidence.evidence_digest.as_str().to_owned(),
                proposal.evidence.registration_digest.as_str().to_owned(),
            ],
        );
        Ok(proposal)
    }

    pub fn validate(&self) -> Result<()> {
        if !self.read_only
            || !self.proposal_only
            || self.connected
            || self.native
            || self.first_party
            || self.truth_authority
            || self.effect_authority
            || self.receipt_authority
            || self.verification_authority
            || self.outcome_authority
            || self.adopted
            || self.proposal_digest
                != Digest::from_fields(
                    "hartevo.aws-guardduty-proposal/v1",
                    &[
                        self.evidence.evidence_digest.as_str().to_owned(),
                        self.evidence.registration_digest.as_str().to_owned(),
                    ],
                )
        {
            return Err(AwsGuardDutyFindingResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsGuardDutyFindingRecord {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub durable: bool,
    pub verified: bool,
    pub adopted: bool,
    pub record_digest: Digest,
}

impl AwsGuardDutyFindingRecord {
    fn new(proposal: &AwsGuardDutyFindingProposal) -> Result<Self> {
        let mut record = Self {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            registration_digest: proposal.evidence.registration_digest.clone(),
            durable: false,
            verified: false,
            adopted: false,
            record_digest: Digest::from_text("pending-record-digest"),
        };
        record.record_digest = Digest::from_fields(
            "hartevo.aws-guardduty-record/v1",
            &[
                record.proposal_digest.as_str().to_owned(),
                record.evidence_digest.as_str().to_owned(),
                record.registration_digest.as_str().to_owned(),
            ],
        );
        Ok(record)
    }

    fn validate(
        &self,
        scope: &AwsGuardDutyFindingScope,
        query: &GuardDutyFindingQuery,
    ) -> Result<VerificationReport> {
        if self.durable || self.verified || self.adopted {
            return Err(AwsGuardDutyFindingResultError::TamperedEvidence);
        }
        let valid_digest = self.record_digest
            == Digest::from_fields(
                "hartevo.aws-guardduty-record/v1",
                &[
                    self.proposal_digest.as_str().to_owned(),
                    self.evidence_digest.as_str().to_owned(),
                    self.registration_digest.as_str().to_owned(),
                ],
            );
        if !valid_digest {
            return Err(AwsGuardDutyFindingResultError::TamperedEvidence);
        }
        let evidence_binding =
            !scope.digest().as_str().is_empty() && !query.digest().as_str().is_empty();
        Ok(VerificationReport {
            valid: valid_digest && evidence_binding,
            review_eligible: valid_digest,
            independent_live_readback: false,
            connected: false,
            native: false,
            first_party: false,
            verification_authority: false,
            outcome_authority: false,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerificationReport {
    pub valid: bool,
    pub review_eligible: bool,
    pub independent_live_readback: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub verification_authority: bool,
    pub outcome_authority: bool,
}

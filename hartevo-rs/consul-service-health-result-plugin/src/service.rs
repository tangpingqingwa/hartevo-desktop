use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AuthorityBoundary, CONSUL_API_REVISION, CONSUL_API_VERSION, CONSUL_HEALTH_PROVIDER_ID,
    CONSUL_HEALTH_PROVIDER_VERSION, CONSUL_SERVICE_ID, CONTRACT_VERSION, SCHEMA_VERSION,
    model::{
        CheckStatus, Digest, EvidenceStatus, ModelError, ReadBounds, Scope, identity_digest,
        status_from_checks,
    },
    provider::{
        ConsulHealthProvider, ConsulProviderDefinition, ConsulProviderRead,
        ConsulServiceHealthReadRequest, ProviderError, ProviderProvenance, RawCatalogServiceEntry,
        RawHealthServiceEntry, TransportFailure,
    },
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RegistrationState {
    #[serde(rename = "ACTIVE")]
    Active,
    #[serde(rename = "REVOKED")]
    Revoked,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ConsulRegistrationError {
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error("provider definition is invalid: {0}")]
    Provider(#[from] crate::ProviderDefinitionError),
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("registration is already active")]
    AlreadyActive,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsulRegistration {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_digest: Digest,
    pub api_version: String,
    pub api_revision: String,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub consent_digest: Digest,
    pub evidence_digest: Option<Digest>,
    pub registration_revision: crate::Revision,
    pub state: RegistrationState,
    pub registration_digest: Digest,
}

impl ConsulRegistration {
    pub fn new(
        scope: &Scope,
        provider: &ConsulProviderDefinition,
    ) -> Result<Self, ConsulRegistrationError> {
        provider.validate_for_scope(scope)?;
        let mut registration = Self {
            schema_version: SCHEMA_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            service_id: CONSUL_SERVICE_ID.to_owned(),
            provider_id: CONSUL_HEALTH_PROVIDER_ID.to_owned(),
            provider_version: CONSUL_HEALTH_PROVIDER_VERSION.to_owned(),
            provider_digest: provider.provider_digest().clone(),
            api_version: CONSUL_API_VERSION.to_owned(),
            api_revision: CONSUL_API_REVISION.to_owned(),
            permission_digest: scope.permission_digest(),
            scope_digest: scope.scope_digest().clone(),
            consent_digest: scope.consent_digest(),
            evidence_digest: None,
            registration_revision: crate::Revision::new(1)?,
            state: RegistrationState::Active,
            registration_digest: Digest::from_text("uninitialized-consul-registration"),
        };
        registration.registration_digest = registration.computed_digest();
        Ok(registration)
    }

    pub fn validate_for(
        &self,
        scope: &Scope,
        provider: &ConsulProviderDefinition,
    ) -> Result<(), ConsulRegistrationError> {
        provider.validate_for_scope(scope)?;
        if self.schema_version != SCHEMA_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.service_id != CONSUL_SERVICE_ID
            || self.provider_id != CONSUL_HEALTH_PROVIDER_ID
            || self.provider_version != CONSUL_HEALTH_PROVIDER_VERSION
            || self.provider_digest != *provider.provider_digest()
            || self.api_version != CONSUL_API_VERSION
            || self.api_revision != CONSUL_API_REVISION
            || self.permission_digest != scope.permission_digest()
            || self.scope_digest != *scope.scope_digest()
            || self.consent_digest != scope.consent_digest()
            || self.registration_digest != self.computed_digest()
        {
            return Err(ConsulRegistrationError::Model(
                ModelError::InvalidRegistration,
            ));
        }
        Ok(())
    }

    pub fn ensure_active(&self) -> Result<(), ConsulRegistrationError> {
        if self.state == RegistrationState::Active {
            Ok(())
        } else {
            Err(ConsulRegistrationError::AlreadyRevoked)
        }
    }

    pub fn validate_integrity(&self) -> Result<(), ConsulRegistrationError> {
        if self.schema_version != SCHEMA_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.service_id != CONSUL_SERVICE_ID
            || self.provider_id != CONSUL_HEALTH_PROVIDER_ID
            || self.provider_version != CONSUL_HEALTH_PROVIDER_VERSION
            || self.api_version != CONSUL_API_VERSION
            || self.api_revision != CONSUL_API_REVISION
            || self.registration_digest != self.computed_digest()
        {
            Err(ConsulRegistrationError::Model(
                ModelError::InvalidRegistration,
            ))
        } else {
            Ok(())
        }
    }

    pub fn bind_evidence_digest(
        &mut self,
        evidence_digest: Digest,
    ) -> Result<(), ConsulRegistrationError> {
        self.ensure_active()?;
        if self.evidence_digest.as_ref() != Some(&evidence_digest) {
            self.evidence_digest = Some(evidence_digest);
            self.registration_revision = self.registration_revision.next()?;
            self.registration_digest = self.computed_digest();
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<(), ConsulRegistrationError> {
        if self.state == RegistrationState::Revoked {
            return Err(ConsulRegistrationError::AlreadyRevoked);
        }
        self.state = RegistrationState::Revoked;
        self.registration_revision = self.registration_revision.next()?;
        self.registration_digest = self.computed_digest();
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), ConsulRegistrationError> {
        if self.state == RegistrationState::Active {
            return Err(ConsulRegistrationError::AlreadyActive);
        }
        self.state = RegistrationState::Active;
        self.registration_revision = self.registration_revision.next()?;
        self.registration_digest = self.computed_digest();
        Ok(())
    }

    pub fn computed_digest(&self) -> Digest {
        let evidence_digest = self
            .evidence_digest
            .as_ref()
            .map_or_else(|| "none".to_owned(), |digest| digest.as_str().to_owned());
        let fields = vec![
            self.schema_version.clone(),
            self.contract_version.clone(),
            self.service_id.clone(),
            self.provider_id.clone(),
            self.provider_version.clone(),
            self.provider_digest.as_str().to_owned(),
            self.api_version.clone(),
            self.api_revision.clone(),
            self.permission_digest.as_str().to_owned(),
            self.scope_digest.as_str().to_owned(),
            self.consent_digest.as_str().to_owned(),
            evidence_digest,
            self.registration_revision.get().to_string(),
            format!("{:?}", self.state),
        ];
        Digest::from_fields("consul-registration/v1", &fields)
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }

    pub const fn reversible(&self) -> bool {
        true
    }

    pub const fn revocable(&self) -> bool {
        true
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionSummary {
    pub addresses_and_ports_redacted: bool,
    pub notes_and_output_redacted: bool,
    pub metadata_values_redacted: bool,
    pub acl_token_redacted: bool,
    pub tags_bounded: bool,
    pub instances_bounded: bool,
}

impl RedactionSummary {
    pub const fn layer_one() -> Self {
        Self {
            addresses_and_ports_redacted: true,
            notes_and_output_redacted: true,
            metadata_values_redacted: true,
            acl_token_redacted: true,
            tags_bounded: true,
            instances_bounded: true,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactedCheck {
    pub identity_digest: Digest,
    pub status: CheckStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactedServiceInstance {
    pub identity_digest: Digest,
    pub node_identity_digest: Digest,
    pub service_identity_digest: Digest,
    pub tags: Vec<String>,
    pub checks: Vec<RedactedCheck>,
    pub status: EvidenceStatus,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ProviderFailure {
    #[serde(rename = "ACCESS_LOST")]
    AccessLost,
    #[serde(rename = "PARTIAL")]
    Partial,
    #[serde(rename = "PROVIDER_UNKNOWN")]
    ProviderUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FailureEvidence {
    pub failure: ProviderFailure,
    pub status: EvidenceStatus,
    pub status_code: Option<u16>,
    pub diagnostic_digest: Digest,
    pub provenance: ProviderProvenance,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsulServiceHealthEvidence {
    pub schema_version: String,
    pub contract_version: String,
    pub scope_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub request_digest: Digest,
    pub health_response_digest: Option<Digest>,
    pub catalog_response_digest: Option<Digest>,
    pub observed_at: u64,
    pub health_index: Option<u64>,
    pub catalog_index: Option<u64>,
    pub status: EvidenceStatus,
    pub instances: Vec<RedactedServiceInstance>,
    pub acl_filtered: bool,
    pub partial: bool,
    pub truncated: bool,
    pub redaction: RedactionSummary,
    pub provenance: ProviderProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub authority: AuthorityBoundary,
    pub failure: Option<FailureEvidence>,
    pub evidence_digest: Digest,
}

impl ConsulServiceHealthEvidence {
    fn from_provider_read(
        scope: &Scope,
        provider: &ConsulProviderDefinition,
        read: ConsulProviderRead,
        bounds: &ReadBounds,
    ) -> Result<Self, ServiceError> {
        let mut catalog_keys = BTreeSet::new();
        for entry in read
            .catalog
            .iter()
            .filter(|entry| matches_catalog_scope(scope, entry))
        {
            if !catalog_keys.insert(catalog_entry_key(entry)) {
                return Err(ServiceError::DuplicateIdentity);
            }
        }
        let mut unique = BTreeSet::new();
        let mut candidates = Vec::new();
        let mut partial = false;
        for entry in read
            .health
            .iter()
            .filter(|entry| matches_scope(scope, entry))
        {
            let key = entry_key(entry);
            if !unique.insert(key.clone()) {
                return Err(ServiceError::DuplicateIdentity);
            }
            if !catalog_keys.contains(&key) {
                partial = true;
            }
            candidates.push(entry);
        }
        candidates.sort_by_key(|entry| {
            let key = entry_key(entry);
            identity_digest("consul-instance-order/v1", &[key])
        });
        let truncated_instances = candidates.len() > bounds.max_instances;
        candidates.truncate(bounds.max_instances);
        let mut instances = Vec::with_capacity(candidates.len());
        let mut statuses = Vec::new();
        let mut truncated = truncated_instances;
        for entry in candidates {
            let (instance, instance_truncated, instance_partial) =
                redact_entry(scope, entry, bounds)?;
            statuses.extend(instance.checks.iter().map(|check| check.status));
            truncated |= instance_truncated;
            partial |= instance_partial;
            instances.push(instance);
        }
        let acl_filtered = read.health_acl_filtered || read.catalog_acl_filtered;
        let status = if acl_filtered {
            EvidenceStatus::AclFiltered
        } else if instances.is_empty() {
            EvidenceStatus::Empty
        } else if partial || truncated {
            EvidenceStatus::Partial
        } else {
            status_from_checks(statuses)
        };
        let mut evidence = Self {
            schema_version: SCHEMA_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            scope_digest: scope.scope_digest().clone(),
            provider_digest: provider.provider_digest().clone(),
            permission_digest: scope.permission_digest(),
            consent_digest: scope.consent_digest(),
            request_digest: read.request_digest,
            health_response_digest: Some(read.health_response_digest),
            catalog_response_digest: Some(read.catalog_response_digest),
            observed_at: read.observed_at,
            health_index: Some(read.health_index),
            catalog_index: Some(read.catalog_index),
            status,
            instances,
            acl_filtered,
            partial: partial || truncated,
            truncated,
            redaction: RedactionSummary::layer_one(),
            provenance: provider.provenance,
            connected: false,
            native: false,
            first_party: false,
            authority: AuthorityBoundary::layer_one(),
            failure: None,
            evidence_digest: Digest::from_text("uninitialized-consul-evidence"),
        };
        evidence.evidence_digest = evidence.computed_digest();
        Ok(evidence)
    }

    fn failure(
        scope: &Scope,
        provider: &ConsulProviderDefinition,
        request: &ConsulServiceHealthReadRequest,
        failure: FailureEvidence,
    ) -> Self {
        let mut evidence = Self {
            schema_version: SCHEMA_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            scope_digest: scope.scope_digest().clone(),
            provider_digest: provider.provider_digest().clone(),
            permission_digest: scope.permission_digest(),
            consent_digest: scope.consent_digest(),
            request_digest: request.request_digest.clone(),
            health_response_digest: None,
            catalog_response_digest: None,
            observed_at: request.observed_at,
            health_index: None,
            catalog_index: None,
            status: failure.status,
            instances: Vec::new(),
            acl_filtered: false,
            partial: matches!(failure.status, EvidenceStatus::Partial),
            truncated: false,
            redaction: RedactionSummary::layer_one(),
            provenance: provider.provenance,
            connected: false,
            native: false,
            first_party: false,
            authority: AuthorityBoundary::layer_one(),
            failure: Some(failure),
            evidence_digest: Digest::from_text("uninitialized-consul-failure-evidence"),
        };
        evidence.evidence_digest = evidence.computed_digest();
        evidence
    }

    pub fn computed_digest(&self) -> Digest {
        let instances = self
            .instances
            .iter()
            .map(|instance| {
                let checks = instance
                    .checks
                    .iter()
                    .map(|check| format!("{}:{}", check.identity_digest, check.status.as_str()))
                    .collect::<Vec<_>>()
                    .join(",");
                format!(
                    "{}:{}:{}:{}:{}:{}",
                    instance.identity_digest,
                    instance.node_identity_digest,
                    instance.service_identity_digest,
                    instance.tags.join(","),
                    checks,
                    instance.status.as_str()
                )
            })
            .collect::<Vec<_>>()
            .join("|");
        let failure = self.failure.as_ref().map_or_else(
            || "none".to_owned(),
            |value| {
                format!(
                    "{:?}:{}:{}:{}",
                    value.failure,
                    value.status.as_str(),
                    value.status_code.map_or(0, u16::from),
                    value.diagnostic_digest
                )
            },
        );
        let fields = vec![
            self.schema_version.clone(),
            self.contract_version.clone(),
            self.scope_digest.as_str().to_owned(),
            self.provider_digest.as_str().to_owned(),
            self.permission_digest.as_str().to_owned(),
            self.consent_digest.as_str().to_owned(),
            self.request_digest.as_str().to_owned(),
            self.health_response_digest
                .as_ref()
                .map_or_else(|| "none".to_owned(), |value| value.as_str().to_owned()),
            self.catalog_response_digest
                .as_ref()
                .map_or_else(|| "none".to_owned(), |value| value.as_str().to_owned()),
            self.observed_at.to_string(),
            self.health_index.map_or(0, |value| value).to_string(),
            self.catalog_index.map_or(0, |value| value).to_string(),
            self.status.as_str().to_owned(),
            instances,
            self.acl_filtered.to_string(),
            self.partial.to_string(),
            self.truncated.to_string(),
            format!("{:?}", self.provenance),
            self.connected.to_string(),
            self.native.to_string(),
            self.first_party.to_string(),
            failure,
        ];
        Digest::from_fields("consul-service-health-evidence/v1", &fields)
    }

    pub fn validate(&self) -> Result<(), ServiceError> {
        if self.connected
            || self.native
            || self.first_party
            || self.authority != AuthorityBoundary::layer_one()
            || self.redaction != RedactionSummary::layer_one()
            || self.evidence_digest != self.computed_digest()
        {
            Err(ServiceError::Tampered)
        } else {
            Ok(())
        }
    }

    pub fn is_review_complete(&self) -> bool {
        self.status.is_review_complete()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsulServiceHealthProposal {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub request_digest: Digest,
    pub evidence_digest: Digest,
    pub status: EvidenceStatus,
    pub evidence: ConsulServiceHealthEvidence,
    pub reversible: bool,
    pub revocable: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub authority: AuthorityBoundary,
    pub proposal_digest: Digest,
}

impl ConsulServiceHealthProposal {
    fn new(
        evidence: ConsulServiceHealthEvidence,
        registration: &ConsulRegistration,
    ) -> Result<Self, ServiceError> {
        evidence.validate()?;
        let Some(registered_evidence) = registration.evidence_digest.as_ref() else {
            return Err(ServiceError::RegistrationDrift);
        };
        if registered_evidence != &evidence.evidence_digest
            || registration.state != RegistrationState::Active
        {
            return Err(ServiceError::RegistrationDrift);
        }
        let mut proposal = Self {
            schema_version: SCHEMA_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            service_id: CONSUL_SERVICE_ID.to_owned(),
            registration_digest: registration.registration_digest.clone(),
            provider_digest: evidence.provider_digest.clone(),
            scope_digest: evidence.scope_digest.clone(),
            permission_digest: evidence.permission_digest.clone(),
            consent_digest: evidence.consent_digest.clone(),
            request_digest: evidence.request_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            status: evidence.status,
            evidence,
            reversible: true,
            revocable: true,
            connected: false,
            native: false,
            first_party: false,
            authority: AuthorityBoundary::layer_one(),
            proposal_digest: Digest::from_text("uninitialized-consul-proposal"),
        };
        proposal.proposal_digest = proposal.computed_digest();
        Ok(proposal)
    }

    pub fn computed_digest(&self) -> Digest {
        Digest::from_parts(
            "consul-service-health-proposal/v1",
            &[
                self.schema_version.as_str(),
                self.contract_version.as_str(),
                self.service_id.as_str(),
                self.registration_digest.as_str(),
                self.provider_digest.as_str(),
                self.scope_digest.as_str(),
                self.permission_digest.as_str(),
                self.consent_digest.as_str(),
                self.request_digest.as_str(),
                self.evidence_digest.as_str(),
                self.status.as_str(),
                &self.reversible.to_string(),
                &self.revocable.to_string(),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), ServiceError> {
        self.evidence.validate()?;
        if self.connected
            || self.native
            || self.first_party
            || self.authority != AuthorityBoundary::layer_one()
            || self.proposal_digest != self.computed_digest()
            || self.evidence_digest != self.evidence.evidence_digest
            || self.scope_digest != self.evidence.scope_digest
            || self.provider_digest != self.evidence.provider_digest
        {
            Err(ServiceError::Tampered)
        } else {
            Ok(())
        }
    }

    pub fn proposal_digest(&self) -> &Digest {
        &self.proposal_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsulServiceHealthReadResult {
    pub evidence: ConsulServiceHealthEvidence,
    pub proposal: ConsulServiceHealthProposal,
    pub failure: Option<FailureEvidence>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsulLocalRecord {
    pub registration_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub status: EvidenceStatus,
    pub observed_at: u64,
    pub record_revision: crate::Revision,
    pub replayed: bool,
    pub authority: AuthorityBoundary,
    pub record_digest: Digest,
}

impl ConsulLocalRecord {
    pub(crate) fn from_proposal(
        proposal: &ConsulServiceHealthProposal,
        revision: crate::Revision,
    ) -> Self {
        let mut record = Self {
            registration_digest: proposal.registration_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            permission_digest: proposal.permission_digest.clone(),
            consent_digest: proposal.consent_digest.clone(),
            status: proposal.status,
            observed_at: proposal.evidence.observed_at,
            record_revision: revision,
            replayed: false,
            authority: AuthorityBoundary::layer_one(),
            record_digest: Digest::from_text("uninitialized-consul-record"),
        };
        record.record_digest = record.computed_digest();
        record
    }

    pub fn replayed_copy(&self) -> Self {
        let mut replay = self.clone();
        replay.status = EvidenceStatus::Replay;
        replay.replayed = true;
        replay.record_digest = replay.computed_digest();
        replay
    }

    pub fn computed_digest(&self) -> Digest {
        Digest::from_parts(
            "consul-local-record/v1",
            &[
                self.registration_digest.as_str(),
                self.proposal_digest.as_str(),
                self.evidence_digest.as_str(),
                self.scope_digest.as_str(),
                self.permission_digest.as_str(),
                self.consent_digest.as_str(),
                self.status.as_str(),
                &self.observed_at.to_string(),
                &self.record_revision.get().to_string(),
                &self.replayed.to_string(),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), ServiceError> {
        if self.authority != AuthorityBoundary::layer_one()
            || self.record_digest != self.computed_digest()
        {
            Err(ServiceError::Tampered)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum VerificationState {
    #[serde(rename = "VERIFIED")]
    Verified,
    #[serde(rename = "TAMPERED")]
    Tampered,
    #[serde(rename = "REPLAY")]
    Replay,
    #[serde(rename = "REVOKED")]
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsulVerification {
    pub record_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub state: VerificationState,
    pub status: EvidenceStatus,
    pub authority: AuthorityBoundary,
    pub verification_digest: Digest,
}

impl ConsulVerification {
    pub(crate) fn from_record(record: &ConsulLocalRecord, state: VerificationState) -> Self {
        let status = match state {
            VerificationState::Tampered => EvidenceStatus::Tampered,
            VerificationState::Replay => EvidenceStatus::Replay,
            VerificationState::Revoked => EvidenceStatus::Revoked,
            VerificationState::Verified => record.status,
        };
        let verification_digest = Digest::from_parts(
            "consul-verification/v1",
            &[
                record.record_digest.as_str(),
                record.registration_digest.as_str(),
                record.evidence_digest.as_str(),
                &format!("{state:?}"),
                status.as_str(),
            ],
        );
        Self {
            record_digest: record.record_digest.clone(),
            registration_digest: record.registration_digest.clone(),
            evidence_digest: record.evidence_digest.clone(),
            state,
            status,
            authority: AuthorityBoundary::layer_one(),
            verification_digest,
        }
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ServiceError {
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error(transparent)]
    Provider(#[from] ProviderError),
    #[error(transparent)]
    ProviderDefinition(#[from] crate::ProviderDefinitionError),
    #[error(transparent)]
    Registration(#[from] ConsulRegistrationError),
    #[error("registration no longer matches the evidence")]
    RegistrationDrift,
    #[error("health and catalog response revisions differ")]
    RevisionMismatch,
    #[error("duplicate node/service/check identity was observed")]
    DuplicateIdentity,
    #[error("evidence is unsafe to record")]
    UnsafeEvidence,
    #[error("evidence or record was tampered")]
    Tampered,
    #[error("registration is revoked")]
    Revoked,
    #[error("proposal replay was rejected")]
    Replay,
}

pub struct ConsulServiceHealthResultService<T> {
    scope: Scope,
    provider: ConsulHealthProvider<T>,
    registration: ConsulRegistration,
    next_record_revision: crate::Revision,
}

impl<T> fmt::Debug for ConsulServiceHealthResultService<T>
where
    T: crate::ConsulHealthTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConsulServiceHealthResultService")
            .field("scope_digest", self.scope.scope_digest())
            .field("provider", self.provider.definition())
            .field("registration", &self.registration)
            .field("next_record_revision", &self.next_record_revision)
            .finish()
    }
}

impl<T> ConsulServiceHealthResultService<T>
where
    T: crate::ConsulHealthTransport,
{
    pub fn new(scope: Scope, provider: ConsulHealthProvider<T>) -> Result<Self, ServiceError> {
        scope.validate()?;
        provider.definition().validate_for_scope(&scope)?;
        let registration = ConsulRegistration::new(&scope, provider.definition())?;
        Ok(Self {
            scope,
            provider,
            registration,
            next_record_revision: crate::Revision::new(1)?,
        })
    }

    pub fn scope(&self) -> &Scope {
        &self.scope
    }

    pub const fn service_id(&self) -> &'static str {
        CONSUL_SERVICE_ID
    }

    pub const fn read_only(&self) -> bool {
        true
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

    pub fn provider(&self) -> &ConsulHealthProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut ConsulHealthProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &ConsulRegistration {
        &self.registration
    }

    pub fn is_active(&self) -> bool {
        self.registration.is_active()
    }

    pub fn read(
        &mut self,
        bounds: ReadBounds,
        observed_at: u64,
    ) -> Result<ConsulServiceHealthReadResult, ServiceError> {
        self.registration.ensure_active()?;
        let request = ConsulServiceHealthReadRequest::new(&self.scope, bounds, observed_at)?;
        let (evidence, failure) = match self.provider.read(&request) {
            Ok(read) => (
                ConsulServiceHealthEvidence::from_provider_read(
                    &self.scope,
                    self.provider.definition(),
                    read,
                    &request.bounds,
                )?,
                None,
            ),
            Err(error) => {
                let failure =
                    failure_evidence(error.clone(), self.provider.definition().provenance);
                (
                    ConsulServiceHealthEvidence::failure(
                        &self.scope,
                        self.provider.definition(),
                        &request,
                        failure.clone(),
                    ),
                    Some(failure),
                )
            }
        };
        self.registration
            .bind_evidence_digest(evidence.evidence_digest.clone())?;
        let proposal = ConsulServiceHealthProposal::new(evidence.clone(), &self.registration)?;
        Ok(ConsulServiceHealthReadResult {
            evidence,
            proposal,
            failure,
        })
    }

    pub fn propose(
        &mut self,
        bounds: ReadBounds,
        observed_at: u64,
    ) -> Result<ConsulServiceHealthProposal, ServiceError> {
        self.read(bounds, observed_at).map(|result| result.proposal)
    }

    pub fn record(
        &mut self,
        result: &ConsulServiceHealthReadResult,
    ) -> Result<ConsulLocalRecord, ServiceError> {
        self.registration.ensure_active()?;
        result.evidence.validate()?;
        result.proposal.validate()?;
        if result.proposal.registration_digest != self.registration.registration_digest
            || self.registration.evidence_digest.as_ref() != Some(&result.evidence.evidence_digest)
            || matches!(
                result.evidence.status,
                EvidenceStatus::Tampered | EvidenceStatus::Replay | EvidenceStatus::Revoked
            )
        {
            return Err(ServiceError::UnsafeEvidence);
        }
        let revision = self.next_record_revision;
        self.next_record_revision = self.next_record_revision.next()?;
        Ok(ConsulLocalRecord::from_proposal(&result.proposal, revision))
    }

    pub fn verify(&self, record: &ConsulLocalRecord) -> ConsulVerification {
        if self.registration.state == RegistrationState::Revoked {
            return ConsulVerification::from_record(record, VerificationState::Revoked);
        }
        if record.validate().is_err()
            || record.registration_digest != self.registration.registration_digest
        {
            return ConsulVerification::from_record(record, VerificationState::Tampered);
        }
        if record.replayed {
            ConsulVerification::from_record(record, VerificationState::Replay)
        } else {
            ConsulVerification::from_record(record, VerificationState::Verified)
        }
    }

    pub fn revoke(&mut self) -> Result<(), ServiceError> {
        self.registration.revoke()?;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), ServiceError> {
        self.registration.restore()?;
        Ok(())
    }
}

fn failure_evidence(error: ProviderError, provenance: ProviderProvenance) -> FailureEvidence {
    let (failure, status_code, diagnostic_digest) = match error {
        ProviderError::Transport(error) => {
            let failure = if error.failure.is_access_loss() {
                ProviderFailure::AccessLost
            } else if matches!(error.failure, TransportFailure::Partial) {
                ProviderFailure::Partial
            } else {
                ProviderFailure::ProviderUnknown
            };
            (failure, error.status_code, error.diagnostic_digest)
        }
        _ => (
            ProviderFailure::ProviderUnknown,
            None,
            Digest::from_text(format!("{error:?}")),
        ),
    };
    let status = match failure {
        ProviderFailure::AccessLost => EvidenceStatus::AccessLost,
        ProviderFailure::Partial => EvidenceStatus::Partial,
        ProviderFailure::ProviderUnknown => EvidenceStatus::ProviderUnknown,
    };
    FailureEvidence {
        failure,
        status,
        status_code,
        diagnostic_digest,
        provenance,
    }
}

fn matches_scope(scope: &Scope, entry: &RawHealthServiceEntry) -> bool {
    entry.node.datacenter == scope.datacenter.as_str()
        && entry.service.service == scope.service.as_str()
        && (entry.service.namespace.is_empty()
            || entry.service.namespace == scope.namespace.as_str())
        && (entry.service.partition.is_empty()
            || entry.service.partition == scope.admin_partition.as_str())
        && scope
            .node
            .as_ref()
            .is_none_or(|node| entry.node.id == node.as_str())
        && scope
            .tag
            .as_ref()
            .is_none_or(|tag| entry.service.tags.iter().any(|value| value == tag.as_str()))
        && scope
            .service_instance
            .as_ref()
            .is_none_or(|instance| entry.service.id == instance.as_str())
        && scope.check.as_ref().is_none_or(|check| {
            entry
                .checks
                .iter()
                .any(|value| value.check_id == check.as_str())
        })
}

fn matches_catalog_scope(scope: &Scope, entry: &RawCatalogServiceEntry) -> bool {
    entry.node.datacenter == scope.datacenter.as_str()
        && entry.service.service == scope.service.as_str()
        && (entry.service.namespace.is_empty()
            || entry.service.namespace == scope.namespace.as_str())
        && (entry.service.partition.is_empty()
            || entry.service.partition == scope.admin_partition.as_str())
        && scope
            .node
            .as_ref()
            .is_none_or(|node| entry.node.id == node.as_str())
        && scope
            .tag
            .as_ref()
            .is_none_or(|tag| entry.service.tags.iter().any(|value| value == tag.as_str()))
        && scope
            .service_instance
            .as_ref()
            .is_none_or(|instance| entry.service.id == instance.as_str())
}

fn entry_key(entry: &RawHealthServiceEntry) -> String {
    format!(
        "{}|{}|{}",
        entry.node.id, entry.service.id, entry.service.service
    )
}

fn catalog_entry_key(entry: &RawCatalogServiceEntry) -> String {
    format!(
        "{}|{}|{}",
        entry.node.id, entry.service.id, entry.service.service
    )
}

fn redact_entry(
    scope: &Scope,
    entry: &RawHealthServiceEntry,
    bounds: &ReadBounds,
) -> Result<(RedactedServiceInstance, bool, bool), ServiceError> {
    let node_identity_digest = identity_digest(
        "consul-node-identity/v1",
        &[entry.node.id.clone(), entry.node.node.clone()],
    );
    let service_identity_digest = identity_digest(
        "consul-service-identity/v1",
        &[entry.service.id.clone(), entry.service.service.clone()],
    );
    let instance_identity_digest = identity_digest(
        "consul-service-instance-identity/v1",
        &[
            node_identity_digest.as_str().to_owned(),
            service_identity_digest.as_str().to_owned(),
        ],
    );
    let mut tags = entry
        .service
        .tags
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    tags.sort();
    let tags_truncated = tags.len() > bounds.max_tags_per_instance;
    tags.truncate(bounds.max_tags_per_instance);
    let mut checks = entry
        .checks
        .iter()
        .filter(|check| {
            scope
                .check
                .as_ref()
                .is_none_or(|wanted| check.check_id == wanted.as_str())
        })
        .collect::<Vec<_>>();
    checks.sort_by(|left, right| left.check_id.cmp(&right.check_id));
    let mut seen_checks = BTreeSet::new();
    for check in &checks {
        if !seen_checks.insert(check.check_id.clone()) {
            return Err(ServiceError::DuplicateIdentity);
        }
    }
    let checks_truncated = checks.len() > bounds.max_checks_per_instance;
    checks.truncate(bounds.max_checks_per_instance);
    let mut partial = false;
    let mut redacted_checks = Vec::with_capacity(checks.len());
    for check in checks {
        let status = CheckStatus::parse(&check.status);
        partial |= status == CheckStatus::Unknown;
        redacted_checks.push(RedactedCheck {
            identity_digest: identity_digest(
                "consul-check-identity/v1",
                &[
                    entry.node.id.clone(),
                    entry.service.id.clone(),
                    check.check_id.clone(),
                    check.name.clone(),
                ],
            ),
            status,
        });
    }
    let status = status_from_checks(redacted_checks.iter().map(|check| check.status));
    Ok((
        RedactedServiceInstance {
            identity_digest: instance_identity_digest,
            node_identity_digest,
            service_identity_digest,
            tags,
            checks: redacted_checks,
            status,
        },
        tags_truncated || checks_truncated,
        partial,
    ))
}

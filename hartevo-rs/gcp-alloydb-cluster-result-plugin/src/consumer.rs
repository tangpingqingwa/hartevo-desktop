//! Mission-facing projection that remains below Hartevo kernel authority.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{Digest, EvidenceState, GcpAlloyDbClusterScope, ProviderProvenance};
use crate::service::{
    GcpAlloyDbClusterResultProposal, GcpAlloyDbRecordReceipt, GcpAlloyDbRegistration,
    RegistrationState, ServiceError,
};
use crate::{CONSUMER_ID, SERVICE_ID};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ConsumerError {
    #[error("Mission consumer registration is revoked")]
    RegistrationRevoked,
    #[error("Mission consumer registration is tampered")]
    RegistrationTampered,
    #[error("Mission or exact AlloyDB scope drifted")]
    ScopeMismatch,
    #[error("Mission permission fence was lost")]
    PermissionLoss,
    #[error("Mission evidence was tampered or incomplete")]
    TamperedEvidence,
    #[error("Layer-1 evidence claimed forbidden authority")]
    AuthorityClaim,
    #[error("recording idempotency key conflicts with an existing record")]
    ReplayConflict,
    #[error("invalid recording key")]
    InvalidRequest,
    #[error(transparent)]
    Service(#[from] ServiceError),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionGcpAlloyDbClusterResult {
    pub service_id: String,
    pub consumer_id: String,
    pub mission: crate::model::MissionBinding,
    pub target: crate::model::GcpAlloyDbTarget,
    pub proposal_digest: Digest,
    pub state: EvidenceState,
    pub accepted: bool,
    pub review_only: bool,
    pub review_eligible: bool,
    pub adopted_outcome: bool,
    pub truth_authority: bool,
    pub consent_authority: bool,
    pub effect_authority: bool,
    pub receipt_authority: bool,
    pub verification_authority: bool,
    pub work_product_adopted: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub durable_provider_receipt: bool,
    pub provenance: ProviderProvenance,
    pub result_digest: Digest,
}

impl MissionGcpAlloyDbClusterResult {
    fn new(proposal: &GcpAlloyDbClusterResultProposal) -> Self {
        let mut value = Self {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            mission: proposal.mission.clone(),
            target: proposal.target.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            state: proposal.state,
            accepted: true,
            review_only: true,
            review_eligible: proposal.is_review_eligible(),
            adopted_outcome: false,
            truth_authority: false,
            consent_authority: false,
            effect_authority: false,
            receipt_authority: false,
            verification_authority: false,
            work_product_adopted: false,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            durable_provider_receipt: false,
            provenance: proposal.provenance,
            result_digest: Digest::from_text("unsealed-gcp-alloydb-mission-result"),
        };
        value.result_digest = Digest::from_parts(
            "gcp-alloydb-mission-result/v1",
            &[
                ("service", value.service_id.clone()),
                ("consumer", value.consumer_id.clone()),
                ("mission", value.mission.digest().as_str().to_owned()),
                ("target", value.target.digest().as_str().to_owned()),
                ("proposal", value.proposal_digest.as_str().to_owned()),
                ("state", format!("{:?}", value.state)),
                ("accepted", value.accepted.to_string()),
                ("review_eligible", value.review_eligible.to_string()),
            ],
        );
        value
    }
}

pub struct MissionGcpAlloyDbClusterConsumer {
    scope: GcpAlloyDbClusterScope,
    registration: GcpAlloyDbRegistration,
    revoked: bool,
    records: BTreeMap<Digest, GcpAlloyDbRecordReceipt>,
}

impl std::fmt::Debug for MissionGcpAlloyDbClusterConsumer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MissionGcpAlloyDbClusterConsumer")
            .field("scope_digest", self.scope.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest,
            )
            .field("revoked", &self.revoked)
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionGcpAlloyDbClusterConsumer {
    pub fn new(
        scope: GcpAlloyDbClusterScope,
        registration: GcpAlloyDbRegistration,
    ) -> Result<Self, ConsumerError> {
        scope.validate().map_err(|_| ConsumerError::ScopeMismatch)?;
        if registration.state != RegistrationState::Active
            || !registration.reversible
            || !registration.revocable
        {
            return Err(ConsumerError::RegistrationRevoked);
        }
        registration
            .validate_digest_only()
            .map_err(|_| ConsumerError::RegistrationTampered)?;
        if registration.scope_digest != *scope.digest()
            || registration.permission_digest != *scope.permissions.digest()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            revoked: false,
            records: BTreeMap::new(),
        })
    }

    pub fn scope(&self) -> &GcpAlloyDbClusterScope {
        &self.scope
    }

    pub fn registration(&self) -> &GcpAlloyDbRegistration {
        &self.registration
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<(), ConsumerError> {
        if self.revoked {
            return Err(ConsumerError::RegistrationRevoked);
        }
        self.revoked = true;
        Ok(())
    }

    pub fn consume(
        &self,
        proposal: &GcpAlloyDbClusterResultProposal,
    ) -> Result<MissionGcpAlloyDbClusterResult, ConsumerError> {
        if self.revoked || self.registration.state != RegistrationState::Active {
            return Err(ConsumerError::RegistrationRevoked);
        }
        proposal
            .validate_integrity()
            .map_err(|_| ConsumerError::TamperedEvidence)?;
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.scope_digest != *self.scope.digest()
            || proposal.mission != self.scope.mission
            || proposal.target != self.scope.target
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        if proposal.evidence.plugin_version_digest != self.registration.version_digest
            || proposal.evidence.contract_digest != self.registration.contract_digest
            || proposal.evidence.provider_digest != self.registration.provider_digest
            || proposal.evidence.api_digest != self.registration.api_digest
            || proposal.evidence.permission_digest != *self.scope.permissions.digest()
            || proposal.evidence.scope_digest != *self.scope.digest()
            || proposal.evidence.evidence_binding_digest != self.registration.evidence_digest
            || proposal.evidence.secret_reference_digest
                != self.registration.secret_reference_digest
        {
            return Err(ConsumerError::PermissionLoss);
        }
        if proposal.connected
            || proposal.native
            || proposal.first_party
            || proposal.provider_receipt
            || proposal.durable_provider_receipt
            || proposal.truth_authority
            || proposal.consent_authority
            || proposal.effect_authority
            || proposal.receipt_authority
            || proposal.verification_authority
            || proposal.outcome_adopted
            || proposal.work_product_adopted
        {
            return Err(ConsumerError::AuthorityClaim);
        }
        Ok(MissionGcpAlloyDbClusterResult::new(proposal))
    }

    pub fn record(
        &mut self,
        proposal: &GcpAlloyDbClusterResultProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<GcpAlloyDbRecordReceipt, ConsumerError> {
        let _ = self.consume(proposal)?;
        let key = idempotency_key.as_ref();
        if key.is_empty() || key.len() > crate::model::MAX_IDENTIFIER_BYTES {
            return Err(ConsumerError::InvalidRequest);
        }
        let key_digest = Digest::from_text(key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(ConsumerError::ReplayConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.recording_digest = Digest::from_parts(
                "gcp-alloydb-local-recording/v1",
                &[
                    (
                        "idempotency",
                        replay.idempotency_key_digest.as_str().to_owned(),
                    ),
                    ("proposal", replay.proposal_digest.as_str().to_owned()),
                    ("evidence", replay.evidence_digest.as_str().to_owned()),
                    ("replayed", replay.replayed.to_string()),
                ],
            );
            return Ok(replay);
        }
        let receipt = GcpAlloyDbRecordReceipt::new_for_consumer(key_digest, proposal);
        self.records
            .insert(receipt.idempotency_key_digest.clone(), receipt.clone());
        Ok(receipt)
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }
}

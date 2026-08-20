use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::error::{RedisCloudDatabaseResultError, Result};
use crate::model::{
    CostReceipt, Digest, ProviderProvenance, RedisCloudDatabasePosture, RedisCloudDatabaseScope,
    RedisCloudEvidenceState, RedisCloudSubscriptionPosture, RequestReceipt,
};
use crate::service::{RedisCloudDatabaseResultProposal, RedisCloudDatabaseResultRegistration};
use crate::{CONSUMER_ID, SERVICE_ID};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionRedisCloudDatabaseResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub state: RedisCloudEvidenceState,
    pub subscription: Option<RedisCloudSubscriptionPosture>,
    pub database: Option<RedisCloudDatabasePosture>,
    pub evidence: crate::service::RedisCloudDatabaseResultEvidence,
    pub request_receipts: Vec<RequestReceipt>,
    pub cost_receipts: Vec<CostReceipt>,
    pub provenance: ProviderProvenance,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub truth_authority: bool,
    pub consent_authority: bool,
    pub effect_authority: bool,
    pub receipt_authority: bool,
    pub verification_authority: bool,
    pub outcome_authority: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl MissionRedisCloudDatabaseResult {
    #[must_use]
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRedisCloudDatabaseResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub state: RedisCloudEvidenceState,
    pub recording_digest: Digest,
    pub replayed: bool,
    pub durable_provider_receipt: bool,
}

impl RecordedRedisCloudDatabaseResult {
    fn new(
        idempotency_key_digest: Digest,
        proposal: &RedisCloudDatabaseResultProposal,
        replayed: bool,
    ) -> Self {
        let recording_digest = Digest::from_parts(
            "redis-cloud-local-recording/v1",
            &[
                ("key", idempotency_key_digest.as_str().to_owned()),
                ("proposal", proposal.proposal_digest.as_str().to_owned()),
                ("scope", proposal.scope_digest.as_str().to_owned()),
                ("state", format!("{:?}", proposal.state)),
                ("replayed", replayed.to_string()),
            ],
        );
        Self {
            idempotency_key_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            state: proposal.state,
            recording_digest,
            replayed,
            durable_provider_receipt: false,
        }
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.durable_provider_receipt
            || self.idempotency_key_digest.validate().is_err()
            || self.proposal_digest.validate().is_err()
            || self.scope_digest.validate().is_err()
            || self.recording_digest
                != Digest::from_parts(
                    "redis-cloud-local-recording/v1",
                    &[
                        ("key", self.idempotency_key_digest.as_str().to_owned()),
                        ("proposal", self.proposal_digest.as_str().to_owned()),
                        ("scope", self.scope_digest.as_str().to_owned()),
                        ("state", format!("{:?}", self.state)),
                        ("replayed", self.replayed.to_string()),
                    ],
                )
        {
            return Err(RedisCloudDatabaseResultError::TamperedEvidence);
        }
        Ok(())
    }
}

pub struct MissionRedisCloudDatabaseConsumer {
    scope: RedisCloudDatabaseScope,
    registration: RedisCloudDatabaseResultRegistration,
    records: BTreeMap<Digest, RecordedRedisCloudDatabaseResult>,
}

impl fmt::Debug for MissionRedisCloudDatabaseConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionRedisCloudDatabaseConsumer")
            .field("scope", &self.scope)
            .field("registration", &self.registration)
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionRedisCloudDatabaseConsumer {
    pub fn new(
        scope: RedisCloudDatabaseScope,
        registration: RedisCloudDatabaseResultRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        if !registration.is_active() {
            return Err(RedisCloudDatabaseResultError::RegistrationInactive);
        }
        if registration.scope_digest() != &scope.digest() {
            return Err(RedisCloudDatabaseResultError::ScopeDrift);
        }
        scope.validate()?;
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn registration(&self) -> &RedisCloudDatabaseResultRegistration {
        &self.registration
    }
    #[must_use]
    pub fn scope(&self) -> &RedisCloudDatabaseScope {
        &self.scope
    }
    #[must_use]
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consume(
        &self,
        proposal: &RedisCloudDatabaseResultProposal,
    ) -> Result<MissionRedisCloudDatabaseResult> {
        proposal.validate_integrity()?;
        self.registration.validate()?;
        if !self.registration.is_active() {
            return Err(RedisCloudDatabaseResultError::RegistrationInactive);
        }
        if proposal.service_id != SERVICE_ID
            || proposal.consumer_id != CONSUMER_ID
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.account_digest != self.scope.account().digest()
            || proposal.subscription_digest != self.scope.subscription().digest()
            || proposal.database_digest != self.scope.database().digest()
            || proposal.mission_id_digest != *self.scope.mission().id_digest()
            || proposal.project_id_digest != *self.scope.project().id_digest()
            || proposal.work_product_id_digest != *self.scope.work_product().id_digest()
            || proposal.evidence.provider_digest != *self.registration.provider_digest()
            || proposal.evidence.api_digest != *self.registration.api_digest()
            || proposal.evidence.permission_digest != self.registration.permission_digest()
            || proposal.evidence.secret_reference_digest
                != *self.registration.secret_reference_digest()
        {
            return Err(RedisCloudDatabaseResultError::ScopeDrift);
        }
        if let Some(subscription) = &proposal.subscription {
            subscription.validate_against(&self.scope)?;
        }
        if let Some(database) = &proposal.database {
            database.validate_against(&self.scope)?;
        }
        Ok(MissionRedisCloudDatabaseResult {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            state: proposal.state,
            subscription: proposal.subscription.clone(),
            database: proposal.database.clone(),
            evidence: proposal.evidence.clone(),
            request_receipts: proposal.request_receipts.clone(),
            cost_receipts: proposal.cost_receipts.clone(),
            provenance: proposal.provenance,
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            truth_authority: false,
            consent_authority: false,
            effect_authority: false,
            receipt_authority: false,
            verification_authority: false,
            outcome_authority: false,
            outcome_adopted: false,
            work_product_adopted: false,
        })
    }

    pub fn record(
        &mut self,
        proposal: &RedisCloudDatabaseResultProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedRedisCloudDatabaseResult> {
        self.consume(proposal)?;
        let key = idempotency_key.as_ref();
        if key.is_empty() || key.len() > crate::MAX_IDENTIFIER_BYTES {
            return Err(RedisCloudDatabaseResultError::InvalidIdempotencyKey);
        }
        let key_digest = Digest::from_text(key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(RedisCloudDatabaseResultError::ReplayConflict);
            }
            let replay = RecordedRedisCloudDatabaseResult::new(key_digest, proposal, true);
            replay.validate_integrity()?;
            return Ok(replay);
        }
        let result = RecordedRedisCloudDatabaseResult::new(key_digest.clone(), proposal, false);
        result.validate_integrity()?;
        self.records.insert(key_digest, result.clone());
        Ok(result)
    }
}

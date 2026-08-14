use chrono::{DateTime, Utc};
use hartevo_connector_sdk::ProviderProvenanceClass;
use hartevo_domain_kernel::{
    Evidence, EvidenceId, EvidenceStatus, Mission, MissionError, MissionId, ProjectId, TenantId,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    DATAFORSEO_LABS_READ_CAPABILITY, DATAFORSEO_PROVIDER_ID, DataForSeoError,
    DataForSeoEvidenceClassification, DataForSeoGrowthSignal, GOOGLE_ADS_PROVIDER_ID,
    GOOGLE_ADS_READ_CAPABILITY, GoogleAdsError, GoogleAdsEvidenceClassification,
    GoogleAdsGrowthSignal,
};

pub const DATAFORSEO_MISSION_CONSUMER_ID: &str = "mission.consumer.dataforseo.labs.read";

#[derive(Clone, Debug, Error, PartialEq)]
pub enum DataForSeoMissionError {
    #[error("Mission consumer scope does not match the growth signal")]
    ScopeMismatch,
    #[error("Mission consumer accepts only estimate-only DataForSEO evidence")]
    FirstPartyClaim,
    #[error("Mission is not writable")]
    Mission(#[from] MissionError),
    #[error("DataForSEO result is invalid")]
    Provider(#[from] DataForSeoError),
}

#[allow(clippy::struct_field_names)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DataForSeoMissionConsumer {
    mission_id: MissionId,
    tenant_id: TenantId,
    project_id: ProjectId,
    account_id: String,
}

impl DataForSeoMissionConsumer {
    pub fn new(
        mission_id: MissionId,
        tenant_id: TenantId,
        project_id: ProjectId,
        account_id: impl Into<String>,
    ) -> Result<Self, DataForSeoMissionError> {
        let account_id = account_id.into();
        if account_id.trim().is_empty() {
            return Err(DataForSeoMissionError::ScopeMismatch);
        }
        Ok(Self {
            mission_id,
            tenant_id,
            project_id,
            account_id,
        })
    }

    pub fn from_mission(
        mission: &Mission,
        account_id: impl Into<String>,
    ) -> Result<Self, DataForSeoMissionError> {
        Self::new(
            mission.id.clone(),
            mission.tenant_id.clone(),
            mission.project_id.clone(),
            account_id,
        )
    }

    pub fn consume(
        &self,
        signal: &DataForSeoGrowthSignal,
    ) -> Result<DataForSeoMissionOutput, DataForSeoMissionError> {
        let scope = signal.scope();
        let observation = signal.read_observation();
        if scope.provider_id() != DATAFORSEO_PROVIDER_ID
            || scope.account_id() != self.account_id
            || scope.tenant_id() != self.tenant_id.as_str()
            || scope.project_id() != self.project_id.as_str()
            || observation.scope() != scope
            || observation.capability().provider_id() != DATAFORSEO_PROVIDER_ID
            || observation.capability().capability_id() != DATAFORSEO_LABS_READ_CAPABILITY
            || (observation.provenance_class() != ProviderProvenanceClass::ProductionProvider
                && observation.provenance_class() != ProviderProvenanceClass::ControlledProvider)
        {
            return Err(DataForSeoMissionError::ScopeMismatch);
        }
        if signal.classification() != DataForSeoEvidenceClassification::ProviderEstimate
            || signal.first_party()
            || signal.estimate().first_party()
        {
            return Err(DataForSeoMissionError::FirstPartyClaim);
        }
        let evidence_id = EvidenceId::from_stable(format!(
            "dataforseo-evidence-{}",
            stable_digest(&[
                self.mission_id.as_str(),
                signal.raw_evidence_digest(),
                &observation.page_sequence().to_string(),
            ])
        ));
        let evidence = Evidence {
            id: evidence_id,
            title: format!(
                "DataForSEO estimated keyword demand for {}",
                signal.request().target_domain()
            ),
            source_uri: signal.source_uri().to_owned(),
            observed_at: signal.observed_at(),
            confidence: 0.0,
            status: EvidenceStatus::Candidate,
            content_digest: signal.raw_evidence_digest().to_owned(),
        };
        Ok(DataForSeoMissionOutput {
            consumer_id: DATAFORSEO_MISSION_CONSUMER_ID.to_owned(),
            mission_id: self.mission_id.clone(),
            tenant_id: self.tenant_id.clone(),
            project_id: self.project_id.clone(),
            provider_id: scope.provider_id().to_owned(),
            account_id: scope.account_id().to_owned(),
            classification: signal.classification(),
            first_party: signal.first_party(),
            page_sequence: observation.page_sequence(),
            item_count: observation.item_count(),
            charged: signal.charged(),
            replayed: signal.replayed(),
            source_revision: signal.source_revision(),
            raw_evidence_digest: signal.raw_evidence_digest().to_owned(),
            evidence,
        })
    }

    pub fn record_into(
        &self,
        mission: &mut Mission,
        signal: &DataForSeoGrowthSignal,
        now: DateTime<Utc>,
    ) -> Result<DataForSeoMissionOutput, DataForSeoMissionError> {
        if mission.id != self.mission_id
            || mission.tenant_id != self.tenant_id
            || mission.project_id != self.project_id
        {
            return Err(DataForSeoMissionError::ScopeMismatch);
        }
        let output = self.consume(signal)?;
        mission.record_evidence(output.evidence.clone(), now)?;
        Ok(output)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataForSeoMissionOutput {
    consumer_id: String,
    mission_id: MissionId,
    tenant_id: TenantId,
    project_id: ProjectId,
    provider_id: String,
    account_id: String,
    classification: DataForSeoEvidenceClassification,
    first_party: bool,
    page_sequence: u64,
    item_count: u32,
    charged: bool,
    replayed: bool,
    source_revision: u64,
    raw_evidence_digest: String,
    evidence: Evidence,
}

impl DataForSeoMissionOutput {
    pub fn consumer_id(&self) -> &str {
        &self.consumer_id
    }

    pub const fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub const fn classification(&self) -> DataForSeoEvidenceClassification {
        self.classification
    }

    pub const fn first_party(&self) -> bool {
        self.first_party
    }

    pub const fn page_sequence(&self) -> u64 {
        self.page_sequence
    }

    pub const fn item_count(&self) -> u32 {
        self.item_count
    }

    pub const fn charged(&self) -> bool {
        self.charged
    }

    pub const fn replayed(&self) -> bool {
        self.replayed
    }

    pub const fn source_revision(&self) -> u64 {
        self.source_revision
    }

    pub fn raw_evidence_digest(&self) -> &str {
        &self.raw_evidence_digest
    }

    pub const fn evidence(&self) -> &Evidence {
        &self.evidence
    }
}

fn stable_digest(parts: &[&str]) -> String {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part.len().to_string().as_bytes());
        digest.update(b":");
        digest.update(part.as_bytes());
    }
    format!("{:x}", digest.finalize())
}

pub const GOOGLE_ADS_MISSION_CONSUMER_ID: &str = "mission.consumer.google-ads.gaql.read";

#[derive(Clone, Debug, Error, PartialEq)]
pub enum GoogleAdsMissionError {
    #[error("Google Ads Mission consumer scope does not match the growth signal")]
    ScopeMismatch,
    #[error("Google Ads Mission consumer received inconsistent provenance classification")]
    ClassificationMismatch,
    #[error("Mission is not writable")]
    Mission(#[from] MissionError),
    #[error("Google Ads result is invalid")]
    Provider(#[from] GoogleAdsError),
}

#[allow(clippy::struct_field_names)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoogleAdsMissionConsumer {
    mission_id: MissionId,
    tenant_id: TenantId,
    project_id: ProjectId,
    account_id: String,
}

impl GoogleAdsMissionConsumer {
    pub fn new(
        mission_id: MissionId,
        tenant_id: TenantId,
        project_id: ProjectId,
        account_id: impl Into<String>,
    ) -> Result<Self, GoogleAdsMissionError> {
        let account_id = account_id.into();
        if account_id.trim().is_empty() {
            return Err(GoogleAdsMissionError::ScopeMismatch);
        }
        Ok(Self {
            mission_id,
            tenant_id,
            project_id,
            account_id,
        })
    }

    pub fn from_mission(
        mission: &Mission,
        account_id: impl Into<String>,
    ) -> Result<Self, GoogleAdsMissionError> {
        Self::new(
            mission.id.clone(),
            mission.tenant_id.clone(),
            mission.project_id.clone(),
            account_id,
        )
    }

    pub fn consume(
        &self,
        signal: &GoogleAdsGrowthSignal,
    ) -> Result<GoogleAdsMissionOutput, GoogleAdsMissionError> {
        let scope = signal.scope();
        let observation = signal.read_observation();
        if scope.provider_id() != GOOGLE_ADS_PROVIDER_ID
            || scope.account_id() != self.account_id
            || scope.tenant_id() != self.tenant_id.as_str()
            || scope.project_id() != self.project_id.as_str()
            || observation.scope() != scope
            || observation.capability().provider_id() != GOOGLE_ADS_PROVIDER_ID
            || observation.capability().capability_id() != GOOGLE_ADS_READ_CAPABILITY
            || (observation.provenance_class() != ProviderProvenanceClass::ProductionProvider
                && observation.provenance_class() != ProviderProvenanceClass::ControlledProvider)
        {
            return Err(GoogleAdsMissionError::ScopeMismatch);
        }
        let expected_first_party =
            signal.classification() == GoogleAdsEvidenceClassification::FirstParty;
        if signal.first_party() != expected_first_party
            || signal.account_probe().first_party() != expected_first_party
            || (expected_first_party
                && observation.provenance_class() != ProviderProvenanceClass::ProductionProvider)
            || (!expected_first_party
                && observation.provenance_class() != ProviderProvenanceClass::ControlledProvider)
        {
            return Err(GoogleAdsMissionError::ClassificationMismatch);
        }
        let evidence_id = EvidenceId::from_stable(format!(
            "google-ads-evidence-{}",
            stable_digest(&[
                self.mission_id.as_str(),
                signal.raw_evidence_digest(),
                &observation.page_sequence().to_string(),
            ])
        ));
        let evidence = Evidence {
            id: evidence_id,
            title: format!(
                "Google Ads GAQL observation for customer {}",
                signal.request().customer_id()
            ),
            source_uri: signal.source_uri().to_owned(),
            observed_at: signal.observed_at(),
            confidence: if expected_first_party { 1.0 } else { 0.0 },
            status: if expected_first_party {
                EvidenceStatus::Confirmed
            } else {
                EvidenceStatus::Candidate
            },
            content_digest: signal.content_digest().to_owned(),
        };
        Ok(GoogleAdsMissionOutput {
            consumer_id: GOOGLE_ADS_MISSION_CONSUMER_ID.to_owned(),
            mission_id: self.mission_id.clone(),
            tenant_id: self.tenant_id.clone(),
            project_id: self.project_id.clone(),
            provider_id: scope.provider_id().to_owned(),
            account_id: scope.account_id().to_owned(),
            classification: signal.classification(),
            first_party: signal.first_party(),
            page_sequence: observation.page_sequence(),
            row_count: observation.row_count(),
            charged: signal.charged(),
            replayed: signal.replayed(),
            source_revision: signal.source_revision(),
            request_id: signal.call().request_id().to_owned(),
            raw_evidence_digest: signal.raw_evidence_digest().to_owned(),
            evidence,
        })
    }

    pub fn record_into(
        &self,
        mission: &mut Mission,
        signal: &GoogleAdsGrowthSignal,
        now: DateTime<Utc>,
    ) -> Result<GoogleAdsMissionOutput, GoogleAdsMissionError> {
        if mission.id != self.mission_id
            || mission.tenant_id != self.tenant_id
            || mission.project_id != self.project_id
        {
            return Err(GoogleAdsMissionError::ScopeMismatch);
        }
        let output = self.consume(signal)?;
        mission.record_evidence(output.evidence.clone(), now)?;
        Ok(output)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GoogleAdsMissionOutput {
    consumer_id: String,
    mission_id: MissionId,
    tenant_id: TenantId,
    project_id: ProjectId,
    provider_id: String,
    account_id: String,
    classification: GoogleAdsEvidenceClassification,
    first_party: bool,
    page_sequence: u64,
    row_count: u32,
    charged: bool,
    replayed: bool,
    source_revision: u64,
    request_id: String,
    raw_evidence_digest: String,
    evidence: Evidence,
}

impl GoogleAdsMissionOutput {
    pub fn consumer_id(&self) -> &str {
        &self.consumer_id
    }

    pub const fn classification(&self) -> GoogleAdsEvidenceClassification {
        self.classification
    }

    pub const fn first_party(&self) -> bool {
        self.first_party
    }

    pub const fn page_sequence(&self) -> u64 {
        self.page_sequence
    }

    pub const fn row_count(&self) -> u32 {
        self.row_count
    }

    pub const fn charged(&self) -> bool {
        self.charged
    }

    pub const fn replayed(&self) -> bool {
        self.replayed
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn raw_evidence_digest(&self) -> &str {
        &self.raw_evidence_digest
    }

    pub const fn evidence(&self) -> &Evidence {
        &self.evidence
    }
}

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{ActorId, EvidenceId, FactId, Money, ProjectId, TenantId};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TruthStatus {
    Confirmed,
    Estimated,
    Inferred,
    Unknown,
    Conflicted,
    Stale,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "type", content = "value")]
pub enum TruthValue {
    Text(String),
    Integer(i64),
    Decimal { value: Decimal, unit: String },
    Money(Money),
    Boolean(bool),
    Timestamp(DateTime<Utc>),
    Url(String),
    Identifier { namespace: String, value: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TruthSource {
    pub provider: String,
    pub source_uri: String,
    pub source_digest: String,
    pub evidence_ids: BTreeSet<EvidenceId>,
    pub captured_by: ActorId,
    pub captured_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TruthCandidate {
    pub value: TruthValue,
    pub source: TruthSource,
    pub confidence: Decimal,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TruthRevisionLink {
    pub previous_version: u64,
    pub previous_digest: String,
    pub reason: String,
    pub corrected_by: ActorId,
    pub corrected_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TruthFact {
    pub id: FactId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub key: String,
    pub value: Option<TruthValue>,
    pub alternatives: Vec<TruthCandidate>,
    pub status: TruthStatus,
    pub source: Option<TruthSource>,
    pub market: String,
    pub language: String,
    pub observed_at: DateTime<Utc>,
    pub valid_from: DateTime<Utc>,
    pub valid_until: Option<DateTime<Utc>>,
    pub confidence: Decimal,
    pub version: u64,
    pub revision_link: Option<TruthRevisionLink>,
}

impl TruthFact {
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        id: FactId,
        tenant_id: TenantId,
        project_id: ProjectId,
        key: impl Into<String>,
        value: Option<TruthValue>,
        alternatives: Vec<TruthCandidate>,
        status: TruthStatus,
        source: Option<TruthSource>,
        market: impl Into<String>,
        language: impl Into<String>,
        observed_at: DateTime<Utc>,
        valid_from: DateTime<Utc>,
        valid_until: Option<DateTime<Utc>>,
        confidence: Decimal,
        now: DateTime<Utc>,
    ) -> Result<Self, TruthError> {
        let fact = Self {
            id,
            tenant_id,
            project_id,
            key: key.into().trim().into(),
            value,
            alternatives,
            status,
            source,
            market: market.into().trim().into(),
            language: language.into().trim().into(),
            observed_at,
            valid_from,
            valid_until,
            confidence,
            version: 1,
            revision_link: None,
        };
        fact.validate(now)?;
        Ok(fact)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn revise(
        &self,
        value: Option<TruthValue>,
        alternatives: Vec<TruthCandidate>,
        status: TruthStatus,
        source: Option<TruthSource>,
        confidence: Decimal,
        observed_at: DateTime<Utc>,
        reason: impl Into<String>,
        corrected_by: ActorId,
        now: DateTime<Utc>,
    ) -> Result<Self, TruthError> {
        let reason = reason.into().trim().to_owned();
        if reason.is_empty() {
            return Err(TruthError::MissingCorrectionReason);
        }
        let next_version = self
            .version
            .checked_add(1)
            .ok_or(TruthError::VersionOverflow)?;
        let mut revised = self.clone();
        revised.value = value;
        revised.alternatives = alternatives;
        revised.status = status;
        revised.source = source;
        revised.confidence = confidence;
        revised.observed_at = observed_at;
        revised.valid_from = now;
        revised.valid_until = None;
        revised.version = next_version;
        revised.revision_link = Some(TruthRevisionLink {
            previous_version: self.version,
            previous_digest: self.digest()?,
            reason,
            corrected_by,
            corrected_at: now,
        });
        revised.validate(now)?;
        Ok(revised)
    }

    /// Closes an observed fact's validity window without rewriting its value
    /// or provenance. Staleness is an explicit revision because consumers must
    /// be able to distinguish an expired observation from an unknown fact.
    pub fn mark_stale(
        &self,
        valid_until: DateTime<Utc>,
        reason: impl Into<String>,
        corrected_by: ActorId,
        now: DateTime<Utc>,
    ) -> Result<Self, TruthError> {
        let reason = reason.into().trim().to_owned();
        if reason.is_empty() {
            return Err(TruthError::MissingCorrectionReason);
        }
        let next_version = self
            .version
            .checked_add(1)
            .ok_or(TruthError::VersionOverflow)?;
        let mut revised = self.clone();
        revised.status = TruthStatus::Stale;
        revised.valid_until = Some(valid_until);
        revised.version = next_version;
        revised.revision_link = Some(TruthRevisionLink {
            previous_version: self.version,
            previous_digest: self.digest()?,
            reason,
            corrected_by,
            corrected_at: now,
        });
        revised.validate(now)?;
        Ok(revised)
    }

    pub fn validate(&self, now: DateTime<Utc>) -> Result<(), TruthError> {
        if self.id.as_str().trim().is_empty()
            || self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.key.is_empty()
            || self.market.is_empty()
            || self.language.is_empty()
            || self.version == 0
        {
            return Err(TruthError::IncompleteFact);
        }
        if self.confidence < Decimal::ZERO || self.confidence > Decimal::ONE {
            return Err(TruthError::InvalidConfidence);
        }
        if self.observed_at > now
            || self.valid_from > now
            || self
                .valid_until
                .is_some_and(|valid_until| valid_until <= self.valid_from)
        {
            return Err(TruthError::InvalidTimeRange);
        }
        match self.status {
            TruthStatus::Confirmed | TruthStatus::Estimated | TruthStatus::Inferred => {
                if self.value.is_none()
                    || self.source.as_ref().is_none_or(|source| {
                        validate_source(source, now).is_err() || source.evidence_ids.is_empty()
                    })
                    || !self.alternatives.is_empty()
                {
                    return Err(TruthError::EvidenceStatusMismatch);
                }
            }
            TruthStatus::Unknown => {
                if self.value.is_some() || !self.alternatives.is_empty() {
                    return Err(TruthError::EvidenceStatusMismatch);
                }
            }
            TruthStatus::Conflicted => {
                if self.value.is_some()
                    || self.alternatives.len() < 2
                    || self
                        .alternatives
                        .iter()
                        .any(|candidate| validate_candidate(candidate, now).is_err())
                {
                    return Err(TruthError::InvalidConflictSet);
                }
                let digests = self
                    .alternatives
                    .iter()
                    .map(|candidate| serde_json::to_vec(&candidate.value))
                    .collect::<Result<BTreeSet<_>, _>>()
                    .map_err(|_| TruthError::Serialization)?;
                if digests.len() != self.alternatives.len() {
                    return Err(TruthError::InvalidConflictSet);
                }
            }
            TruthStatus::Stale => {
                if self.value.is_none() || self.valid_until.is_none_or(|until| until > now) {
                    return Err(TruthError::EvidenceStatusMismatch);
                }
            }
        }
        if let Some(source) = &self.source {
            validate_source(source, now)?;
        }
        if let Some(link) = &self.revision_link {
            if link.previous_version.checked_add(1) != Some(self.version)
                || !is_sha256(&link.previous_digest)
                || link.reason.trim().is_empty()
                || link.corrected_at > now
            {
                return Err(TruthError::InvalidRevisionLink);
            }
        } else if self.version != 1 {
            return Err(TruthError::InvalidRevisionLink);
        }
        validate_value(self.value.as_ref())?;
        Ok(())
    }

    pub fn digest(&self) -> Result<String, TruthError> {
        let bytes = serde_json::to_vec(self).map_err(|_| TruthError::Serialization)?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum TruthError {
    #[error("truth fact identity, key, market, language, or version is incomplete")]
    IncompleteFact,
    #[error("truth fact confidence must be between zero and one")]
    InvalidConfidence,
    #[error("truth fact observation or validity time range is invalid")]
    InvalidTimeRange,
    #[error("truth fact value/evidence does not match its epistemic status")]
    EvidenceStatusMismatch,
    #[error("conflicted truth requires at least two valid, distinct candidates")]
    InvalidConflictSet,
    #[error("truth source lacks provider, URI, digest, actor, or valid capture time")]
    InvalidSource,
    #[error("truth value is empty or malformed")]
    InvalidValue,
    #[error("truth correction requires a reason")]
    MissingCorrectionReason,
    #[error("truth fact version overflow")]
    VersionOverflow,
    #[error("truth revision link is invalid")]
    InvalidRevisionLink,
    #[error("truth fact could not be serialized deterministically")]
    Serialization,
}

fn validate_candidate(candidate: &TruthCandidate, now: DateTime<Utc>) -> Result<(), TruthError> {
    if candidate.confidence < Decimal::ZERO || candidate.confidence > Decimal::ONE {
        return Err(TruthError::InvalidConfidence);
    }
    validate_value(Some(&candidate.value))?;
    validate_source(&candidate.source, now)
}

fn validate_source(source: &TruthSource, now: DateTime<Utc>) -> Result<(), TruthError> {
    if source.provider.trim().is_empty()
        || source.source_uri.trim().is_empty()
        || !source.source_uri.contains("://")
        || !is_sha256(&source.source_digest)
        || source.captured_by.as_str().trim().is_empty()
        || source.captured_at > now
    {
        return Err(TruthError::InvalidSource);
    }
    Ok(())
}

fn validate_value(value: Option<&TruthValue>) -> Result<(), TruthError> {
    let Some(value) = value else {
        return Ok(());
    };
    match value {
        TruthValue::Text(value) if value.trim().is_empty() => Err(TruthError::InvalidValue),
        TruthValue::Decimal { unit, .. } if unit.trim().is_empty() => Err(TruthError::InvalidValue),
        TruthValue::Url(value) if !value.contains("://") => Err(TruthError::InvalidValue),
        TruthValue::Identifier { namespace, value }
            if namespace.trim().is_empty() || value.trim().is_empty() =>
        {
            Err(TruthError::InvalidValue)
        }
        _ => Ok(()),
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone};
    use proptest::prelude::*;

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 10, 8, 0, 0)
            .single()
            .expect("valid time")
    }

    fn source(provider: &str, digest: char) -> TruthSource {
        TruthSource {
            provider: provider.into(),
            source_uri: format!("fixture://{provider}/fact"),
            source_digest: digest.to_string().repeat(64),
            evidence_ids: BTreeSet::from([EvidenceId::from(
                format!("evidence-{provider}").as_str(),
            )]),
            captured_by: ActorId::from("fixture-loader"),
            captured_at: now(),
        }
    }

    #[test]
    fn conflict_cannot_masquerade_as_confirmed_fact() {
        let result = TruthFact::create(
            FactId::from("fact-1"),
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            "market.demand",
            Some(TruthValue::Integer(100)),
            vec![
                TruthCandidate {
                    value: TruthValue::Integer(100),
                    source: source("first-party", '1'),
                    confidence: Decimal::new(9, 1),
                },
                TruthCandidate {
                    value: TruthValue::Integer(200),
                    source: source("estimate", '2'),
                    confidence: Decimal::new(6, 1),
                },
            ],
            TruthStatus::Confirmed,
            Some(source("first-party", '1')),
            "DE",
            "de",
            now(),
            now(),
            None,
            Decimal::new(9, 1),
            now(),
        );
        assert_eq!(result, Err(TruthError::EvidenceStatusMismatch));
    }

    #[test]
    fn correction_links_to_exact_previous_revision_digest() {
        let fact = TruthFact::create(
            FactId::from("fact-1"),
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            "site.canonical",
            Some(TruthValue::Url("https://example.com/old".into())),
            vec![],
            TruthStatus::Confirmed,
            Some(source("gsc", '3')),
            "US",
            "en",
            now(),
            now(),
            None,
            Decimal::ONE,
            now(),
        )
        .expect("fact");
        let previous_digest = fact.digest().expect("digest");
        let revised = fact
            .revise(
                Some(TruthValue::Url("https://example.com/new".into())),
                vec![],
                TruthStatus::Confirmed,
                Some(source("gsc", '4')),
                Decimal::ONE,
                now() + Duration::minutes(1),
                "user corrected canonical",
                ActorId::from("user-1"),
                now() + Duration::minutes(1),
            )
            .expect("revision");
        assert_eq!(revised.version, 2);
        assert_eq!(
            revised
                .revision_link
                .as_ref()
                .expect("revision link")
                .previous_digest,
            previous_digest
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(96))]

        #[test]
        fn arbitrary_truth_revisions_preserve_exact_lineage_and_reject_invalid_epistemic_states(
            actions in prop::collection::vec(0_u8..10, 1..64),
        ) {
            let mut fact = TruthFact::create(
                FactId::from("fact-model"),
                TenantId::from("tenant-1"),
                ProjectId::from("project-1"),
                "market.demand",
                None,
                vec![],
                TruthStatus::Unknown,
                None,
                "DE",
                "de",
                now(),
                now(),
                None,
                Decimal::ZERO,
                now(),
            ).expect("initial unknown fact");

            for (index, action) in actions.into_iter().enumerate() {
                let at = now() + Duration::minutes(i64::try_from(index + 1).expect("bounded"));
                let previous = fact.clone();
                let previous_digest = previous.digest().expect("previous digest");
                let next = match action {
                    0 => fact.revise(
                        Some(TruthValue::Integer(i64::try_from(index).expect("bounded"))),
                        vec![],
                        TruthStatus::Confirmed,
                        Some(source("first-party", '1')),
                        Decimal::ONE,
                        at,
                        "confirmed by first-party readback",
                        ActorId::from("user-1"),
                        at,
                    ),
                    1 => fact.revise(
                        Some(TruthValue::Text(format!("estimate-{index}"))),
                        vec![],
                        TruthStatus::Estimated,
                        Some(source("estimate", '2')),
                        Decimal::new(7, 1),
                        at,
                        "updated estimate",
                        ActorId::from("operator-1"),
                        at,
                    ),
                    2 => fact.revise(
                        None,
                        vec![],
                        TruthStatus::Unknown,
                        None,
                        Decimal::ZERO,
                        at,
                        "evidence no longer supports a value",
                        ActorId::from("operator-1"),
                        at,
                    ),
                    3 => fact.revise(
                        None,
                        vec![
                            TruthCandidate {
                                value: TruthValue::Integer(100),
                                source: source("first-party", '3'),
                                confidence: Decimal::new(9, 1),
                            },
                            TruthCandidate {
                                value: TruthValue::Integer(200),
                                source: source("estimate", '4'),
                                confidence: Decimal::new(6, 1),
                            },
                        ],
                        TruthStatus::Conflicted,
                        None,
                        Decimal::ZERO,
                        at,
                        "sources disagree",
                        ActorId::from("operator-1"),
                        at,
                    ),
                    4 => fact.mark_stale(
                        at - Duration::seconds(1),
                        "observation validity elapsed",
                        ActorId::from("clock-1"),
                        at,
                    ),
                    5 => fact.revise(
                        Some(TruthValue::Integer(1)),
                        vec![],
                        TruthStatus::Confirmed,
                        None,
                        Decimal::ONE,
                        at,
                        "missing source must fail",
                        ActorId::from("operator-1"),
                        at,
                    ),
                    6 => {
                        let duplicate = TruthCandidate {
                            value: TruthValue::Integer(100),
                            source: source("duplicate", '5'),
                            confidence: Decimal::ONE,
                        };
                        fact.revise(
                            None,
                            vec![duplicate.clone(), duplicate],
                            TruthStatus::Conflicted,
                            None,
                            Decimal::ZERO,
                            at,
                            "duplicate candidates must fail",
                            ActorId::from("operator-1"),
                            at,
                        )
                    }
                    7 => fact.revise(
                        Some(TruthValue::Integer(1)),
                        vec![],
                        TruthStatus::Confirmed,
                        Some(source("first-party", '6')),
                        Decimal::ONE,
                        at,
                        "",
                        ActorId::from("operator-1"),
                        at,
                    ),
                    8 => fact.revise(
                        Some(TruthValue::Integer(1)),
                        vec![],
                        TruthStatus::Estimated,
                        Some(source("estimate", '7')),
                        Decimal::new(11, 1),
                        at,
                        "invalid confidence must fail",
                        ActorId::from("operator-1"),
                        at,
                    ),
                    _ => fact.revise(
                        previous.value.clone(),
                        vec![],
                        TruthStatus::Stale,
                        previous.source.clone(),
                        previous.confidence,
                        at,
                        "generic revise cannot forge stale validity",
                        ActorId::from("operator-1"),
                        at,
                    ),
                };

                let should_succeed = action <= 3 || (action == 4 && previous.value.is_some());
                if should_succeed {
                    let revised = next.expect("modelled legal revision");
                    prop_assert_eq!(revised.version, previous.version + 1);
                    prop_assert_eq!(revised.id.clone(), previous.id.clone());
                    prop_assert_eq!(revised.tenant_id.clone(), previous.tenant_id.clone());
                    prop_assert_eq!(revised.project_id.clone(), previous.project_id.clone());
                    prop_assert_eq!(revised.key.clone(), previous.key.clone());
                    prop_assert_eq!(revised.market.clone(), previous.market.clone());
                    prop_assert_eq!(revised.language.clone(), previous.language.clone());
                    let link = revised.revision_link.as_ref().expect("exact lineage");
                    prop_assert_eq!(link.previous_version, previous.version);
                    prop_assert_eq!(link.previous_digest.clone(), previous_digest);
                    prop_assert!(revised.validate(at).is_ok());
                    fact = revised;
                } else {
                    prop_assert!(next.is_err());
                    prop_assert_eq!(fact.clone(), previous);
                }
            }
        }
    }
}

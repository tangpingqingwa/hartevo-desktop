//! Mission-side admission for exact TikTok read evidence.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};

use super::{
    EvidenceProvenance, OAuthCredential, TiktokError, TiktokObservationEnvelope,
    TiktokPageSequence, TiktokReadObservation, TiktokReadScope, TiktokRevisionIdentity,
    TiktokVideoId, TiktokVideoPageEnvelope,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionTiktokReadConsumer {
    scope: TiktokReadScope,
    expected_revision: Option<TiktokRevisionIdentity>,
    last_revision: Option<TiktokRevisionIdentity>,
}

impl MissionTiktokReadConsumer {
    pub fn new(scope: TiktokReadScope) -> Self {
        Self {
            scope,
            expected_revision: None,
            last_revision: None,
        }
    }

    pub const fn scope(&self) -> &TiktokReadScope {
        &self.scope
    }

    pub fn bind_exact_revision(
        &mut self,
        revision: TiktokRevisionIdentity,
    ) -> Result<(), TiktokError> {
        if revision.account_id() != self.scope.account() {
            return Err(TiktokError::MissionRevisionMismatch);
        }
        self.expected_revision = Some(revision);
        Ok(())
    }

    pub fn accepted_revision(&self) -> Option<&TiktokRevisionIdentity> {
        self.last_revision.as_ref()
    }

    pub fn accept(
        &mut self,
        envelope: TiktokObservationEnvelope,
        credential: &OAuthCredential,
        now: DateTime<Utc>,
    ) -> Result<TiktokMissionAcceptedRead, TiktokError> {
        envelope.validate_at(now)?;
        if envelope.provider() != super::ProviderId::Tiktok
            || envelope.scope() != &self.scope
            || envelope.account().open_id() != self.scope.account()
        {
            return Err(TiktokError::ScopeMismatch);
        }
        let Some(expected_revision) = self.expected_revision.as_ref() else {
            return Err(TiktokError::MissionRevisionMismatch);
        };
        if expected_revision != envelope.revision() {
            return Err(TiktokError::MissionRevisionMismatch);
        }
        if envelope.provenance() != EvidenceProvenance::ProductionProvider {
            return Err(TiktokError::ProvenanceRejected);
        }
        let operation = match envelope.observation() {
            TiktokReadObservation::Account(_) => super::TiktokApiOperation::UserInfo,
            TiktokReadObservation::Video(_) => super::TiktokApiOperation::VideoQuery,
        };
        credential.require_for(operation, &self.scope, now)?;
        if let Some(last) = &self.last_revision {
            if last == envelope.revision() {
                return Err(TiktokError::DuplicateRevision);
            }
            if envelope.revision().observed_at() < last.observed_at() {
                return Err(TiktokError::CursorDrift);
            }
        }
        self.last_revision = Some(envelope.revision().clone());
        Ok(TiktokMissionAcceptedRead { envelope })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TiktokMissionAcceptedRead {
    envelope: TiktokObservationEnvelope,
}

impl TiktokMissionAcceptedRead {
    pub const fn envelope(&self) -> &TiktokObservationEnvelope {
        &self.envelope
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TiktokMissionPageProgress {
    Pending {
        sequence: TiktokPageSequence,
        next_cursor: Option<super::TiktokCursor>,
        evidence_root: String,
    },
    Duplicate(TiktokMissionDuplicatePageReceipt),
    Complete(TiktokMissionAcceptedSequence),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TiktokMissionDuplicatePageReceipt {
    provider: super::ProviderId,
    scope: TiktokReadScope,
    sequence: TiktokPageSequence,
    credential_generation: u64,
    page_digest: String,
    evidence_root: String,
}

impl TiktokMissionDuplicatePageReceipt {
    pub const fn provider(&self) -> super::ProviderId {
        self.provider
    }

    pub const fn scope(&self) -> &TiktokReadScope {
        &self.scope
    }

    pub const fn sequence(&self) -> &TiktokPageSequence {
        &self.sequence
    }

    pub const fn credential_generation(&self) -> u64 {
        self.credential_generation
    }

    pub fn page_digest(&self) -> &str {
        &self.page_digest
    }

    pub fn evidence_root(&self) -> &str {
        &self.evidence_root
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionTiktokVideoSequenceConsumer {
    scope: TiktokReadScope,
    page_size: u8,
    next_generation: u64,
    expected_cursor: Option<super::TiktokCursor>,
    evidence_root: String,
    credential_generation: Option<u64>,
    seen_video_ids: BTreeSet<TiktokVideoId>,
    pages: BTreeMap<u64, TiktokVideoPageEnvelope>,
    closed: bool,
}

impl MissionTiktokVideoSequenceConsumer {
    pub fn new(scope: TiktokReadScope, page_size: u8) -> Result<Self, TiktokError> {
        if !(1..=super::DEFAULT_VIDEO_PAGE_SIZE).contains(&page_size) {
            return Err(TiktokError::InvalidRequest(
                "TikTok video.list max_count must be one through twenty",
            ));
        }
        Ok(Self {
            evidence_root: super::initial_evidence_root(&scope, page_size),
            scope,
            page_size,
            next_generation: 1,
            expected_cursor: None,
            credential_generation: None,
            seen_video_ids: BTreeSet::new(),
            pages: BTreeMap::new(),
            closed: false,
        })
    }

    pub const fn scope(&self) -> &TiktokReadScope {
        &self.scope
    }

    pub const fn page_size(&self) -> u8 {
        self.page_size
    }

    pub const fn next_generation(&self) -> u64 {
        self.next_generation
    }

    pub const fn expected_cursor(&self) -> Option<super::TiktokCursor> {
        self.expected_cursor
    }

    pub fn evidence_root(&self) -> &str {
        &self.evidence_root
    }

    pub const fn credential_generation(&self) -> Option<u64> {
        self.credential_generation
    }

    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    pub fn accept_page(
        &mut self,
        page: TiktokVideoPageEnvelope,
        credential: &OAuthCredential,
        now: DateTime<Utc>,
    ) -> Result<TiktokMissionPageProgress, TiktokError> {
        page.validate_at(now)?;
        credential.require_for(super::TiktokApiOperation::VideoList, &self.scope, now)?;
        if page.provenance() != EvidenceProvenance::ProductionProvider {
            return Err(TiktokError::ProvenanceRejected);
        }
        if page.provider() != super::ProviderId::Tiktok
            || page.scope() != &self.scope
            || page.account().open_id() != self.scope.account()
        {
            return Err(TiktokError::ScopeMismatch);
        }
        if page.credential_generation() != credential.generation()
            || self
                .credential_generation
                .is_some_and(|generation| generation != credential.generation())
        {
            return Err(TiktokError::CursorCredentialMismatch);
        }
        if let Some(original) = self
            .pages
            .values()
            .find(|accepted| accepted.page_digest() == page.page_digest())
        {
            if original != &page {
                return Err(TiktokError::CursorDrift);
            }
            return Ok(TiktokMissionPageProgress::Duplicate(
                TiktokMissionDuplicatePageReceipt {
                    provider: original.provider(),
                    scope: original.scope().clone(),
                    sequence: original.sequence().clone(),
                    credential_generation: original.credential_generation(),
                    page_digest: original.page_digest().to_owned(),
                    evidence_root: original.evidence_root().to_owned(),
                },
            ));
        }
        if self.closed {
            return Err(TiktokError::PageSequenceClosed);
        }
        if page.sequence().generation() != self.next_generation
            || page.requested_cursor() != self.expected_cursor
        {
            return Err(TiktokError::CursorDrift);
        }
        if page.expected_evidence_root(&self.evidence_root)? != page.evidence_root() {
            return Err(TiktokError::EvidenceRootMismatch);
        }
        let video_ids = page
            .observations()
            .iter()
            .map(|observation| match observation.observation() {
                TiktokReadObservation::Video(video) => Ok(video.identity().video_id().clone()),
                TiktokReadObservation::Account(_) => Err(TiktokError::CursorDrift),
            })
            .collect::<Result<Vec<_>, _>>()?;
        if video_ids
            .iter()
            .any(|video_id| self.seen_video_ids.contains(video_id))
        {
            return Err(TiktokError::CursorDrift);
        }
        let next_generation = self
            .next_generation
            .checked_add(1)
            .ok_or(TiktokError::CursorDrift)?;

        let sequence = page.sequence().clone();
        self.credential_generation = Some(credential.generation());
        self.seen_video_ids.extend(video_ids);
        page.evidence_root().clone_into(&mut self.evidence_root);
        self.expected_cursor = page.next_cursor();
        self.next_generation = next_generation;
        self.pages.insert(sequence.generation(), page);

        if self.expected_cursor.is_some() {
            Ok(TiktokMissionPageProgress::Pending {
                sequence,
                next_cursor: self.expected_cursor,
                evidence_root: self.evidence_root.clone(),
            })
        } else {
            self.closed = true;
            Ok(TiktokMissionPageProgress::Complete(
                TiktokMissionAcceptedSequence {
                    scope: self.scope.clone(),
                    provider: super::ProviderId::Tiktok,
                    page_size: self.page_size,
                    credential_generation: credential.generation(),
                    evidence_root: self.evidence_root.clone(),
                    pages: self.pages.values().cloned().collect(),
                },
            ))
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TiktokMissionAcceptedSequence {
    scope: TiktokReadScope,
    provider: super::ProviderId,
    page_size: u8,
    credential_generation: u64,
    evidence_root: String,
    pages: Vec<TiktokVideoPageEnvelope>,
}

impl TiktokMissionAcceptedSequence {
    pub const fn provider(&self) -> super::ProviderId {
        self.provider
    }

    pub const fn scope(&self) -> &TiktokReadScope {
        &self.scope
    }

    pub const fn page_size(&self) -> u8 {
        self.page_size
    }

    pub const fn credential_generation(&self) -> u64 {
        self.credential_generation
    }

    pub fn evidence_root(&self) -> &str {
        &self.evidence_root
    }

    pub fn pages(&self) -> &[TiktokVideoPageEnvelope] {
        &self.pages
    }

    pub fn page_count(&self) -> usize {
        self.pages.len()
    }

    /// Revalidate the closed sequence at the Desktop adoption boundary.
    ///
    /// The accepted value is immutable, but the second check makes the
    /// credential, cursor, provenance, time, identity, and evidence-root
    /// assumptions explicit before durable Mission persistence.
    pub fn validate_at(&self, now: DateTime<Utc>) -> Result<(), TiktokError> {
        if self.provider != super::ProviderId::Tiktok
            || self.scope.provider() != super::ProviderId::Tiktok
            || !(1..=super::DEFAULT_VIDEO_PAGE_SIZE).contains(&self.page_size)
            || self.credential_generation == 0
            || self.pages.is_empty()
            || !super::is_sha256(&self.evidence_root)
        {
            return Err(TiktokError::CursorDrift);
        }

        let mut expected_cursor = None;
        let mut evidence_root = super::initial_evidence_root(&self.scope, self.page_size);
        let mut previous_observed_at = None;
        let mut seen_video_ids = BTreeSet::new();
        let page_count = self.pages.len();
        for (index, page) in self.pages.iter().enumerate() {
            page.validate_at(now)?;
            let generation = u64::try_from(index)
                .ok()
                .and_then(|index| index.checked_add(1))
                .ok_or(TiktokError::CursorDrift)?;
            let terminal = index + 1 == page_count;
            if page.provider() != self.provider
                || page.scope() != &self.scope
                || page.account().open_id() != self.scope.account()
                || page.sequence().generation() != generation
                || page.requested_cursor() != expected_cursor
                || page.credential_generation() != self.credential_generation
                || page.provenance() != EvidenceProvenance::ProductionProvider
                || page.has_more() == terminal
                || previous_observed_at
                    .is_some_and(|observed_at| page.freshness().observed_at() < observed_at)
            {
                return Err(TiktokError::CursorDrift);
            }
            if page.expected_evidence_root(&evidence_root)? != page.evidence_root() {
                return Err(TiktokError::EvidenceRootMismatch);
            }
            for observation in page.observations() {
                let TiktokReadObservation::Video(video) = observation.observation() else {
                    return Err(TiktokError::CursorDrift);
                };
                if !seen_video_ids.insert(video.identity().video_id().clone()) {
                    return Err(TiktokError::CursorDrift);
                }
            }
            expected_cursor = page.next_cursor();
            previous_observed_at = Some(page.freshness().observed_at());
            page.evidence_root().clone_into(&mut evidence_root);
        }
        if expected_cursor.is_some() || evidence_root != self.evidence_root {
            return Err(TiktokError::EvidenceRootMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use chrono::Duration;

    use super::*;
    use crate::tiktok::provider::parse_probe_response;
    use crate::tiktok::testkit::{fixed_now, profile_response};
    use crate::tiktok::{
        BusinessId, SecretReference, TenantId, TiktokAccountId, TiktokFreshness, TiktokOAuthScope,
        TiktokReadScope,
    };

    #[test]
    fn admits_only_a_bound_production_revision() {
        let now = fixed_now();
        let scope = TiktokReadScope::new(
            TenantId::new("tenant-01").unwrap(),
            BusinessId::new("business-01").unwrap(),
            TiktokAccountId::new("open01").unwrap(),
        );
        let credential = OAuthCredential::new(
            SecretReference::new("keychain://tiktok/open01").unwrap(),
            scope.clone(),
            [TiktokOAuthScope::UserInfoBasic, TiktokOAuthScope::VideoList]
                .into_iter()
                .collect::<BTreeSet<_>>(),
            now + Duration::hours(1),
            None,
            1,
        )
        .unwrap();
        let freshness = TiktokFreshness::new(now, now + Duration::minutes(2), 1).unwrap();

        // This exercises the provider-to-consumer seam in-crate. Public fixture
        // services always emit Fixture provenance and cannot take this path.
        let envelope = parse_probe_response(
            &scope,
            &profile_response(),
            freshness,
            EvidenceProvenance::ProductionProvider,
        )
        .unwrap();
        let mut consumer = MissionTiktokReadConsumer::new(scope);
        consumer
            .bind_exact_revision(envelope.revision().clone())
            .unwrap();
        let accepted = consumer.accept(envelope, &credential, now).unwrap();
        assert_eq!(
            accepted.envelope().provenance(),
            EvidenceProvenance::ProductionProvider
        );
    }
}

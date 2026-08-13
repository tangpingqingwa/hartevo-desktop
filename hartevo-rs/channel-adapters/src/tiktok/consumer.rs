//! Mission-side admission for exact TikTok read evidence.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};

use super::{
    EvidenceProvenance, OAuthCredential, TiktokError, TiktokObservationEnvelope,
    TiktokPageSequence, TiktokReadObservation, TiktokReadScope, TiktokRevisionIdentity,
    TiktokVideoPageEnvelope,
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
    Duplicate {
        sequence: TiktokPageSequence,
        page_digest: String,
    },
    Complete(TiktokMissionAcceptedSequence),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionTiktokVideoSequenceConsumer {
    scope: TiktokReadScope,
    page_size: u8,
    next_generation: u64,
    expected_cursor: Option<super::TiktokCursor>,
    evidence_root: String,
    credential_generation: Option<u64>,
    seen_page_digests: BTreeSet<String>,
    seen_video_ids: BTreeSet<super::TiktokVideoId>,
    pages: Vec<TiktokVideoPageEnvelope>,
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
            seen_page_digests: BTreeSet::new(),
            seen_video_ids: BTreeSet::new(),
            pages: Vec::new(),
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
        if page.scope() != &self.scope
            || page.provider() != super::ProviderId::Tiktok
            || page.account().open_id() != self.scope.account()
        {
            return Err(TiktokError::ScopeMismatch);
        }
        if page.credential_generation() != credential.generation() {
            return Err(TiktokError::CredentialGenerationMismatch);
        }
        if self
            .credential_generation
            .is_some_and(|generation| generation != credential.generation())
        {
            return Err(TiktokError::CredentialGenerationMismatch);
        }
        if self.seen_page_digests.contains(page.page_digest()) {
            return Ok(TiktokMissionPageProgress::Duplicate {
                sequence: page.sequence().clone(),
                page_digest: page.page_digest().to_owned(),
            });
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
        self.credential_generation = Some(credential.generation());
        self.seen_page_digests.insert(page.page_digest().to_owned());
        self.seen_video_ids.extend(video_ids);
        self.evidence_root = page.evidence_root().to_owned();
        self.expected_cursor = page.next_cursor();
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .ok_or(TiktokError::CursorDrift)?;
        let sequence = page.sequence().clone();
        self.pages.push(page);
        if self.expected_cursor.is_some() {
            Ok(TiktokMissionPageProgress::Pending {
                sequence,
                next_cursor: self.expected_cursor,
                evidence_root: self.evidence_root.clone(),
            })
        } else {
            self.closed = true;
            let accepted = TiktokMissionAcceptedSequence {
                scope: self.scope.clone(),
                provider: super::ProviderId::Tiktok,
                credential_generation: credential.generation(),
                evidence_root: self.evidence_root.clone(),
                pages: self.pages.clone(),
            };
            Ok(TiktokMissionPageProgress::Complete(accepted))
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TiktokMissionAcceptedSequence {
    scope: TiktokReadScope,
    provider: super::ProviderId,
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

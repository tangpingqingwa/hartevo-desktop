//! Authenticated TikTok read service orchestration.

use chrono::{DateTime, Utc};

use crate::transport::{ReadOnlyTransport, SecretReference};

use super::provider::{
    TiktokDisplayApiProvider, parse_probe_response, parse_video_page_response,
    parse_video_query_response, probe_request, rate_limit_observation, video_list_request,
    video_query_request,
};
use super::{
    EvidenceProvenance, OAuthCredential, REAL_READ_ENABLE_ENV, REAL_READ_SECRET_REFERENCE_ENV,
    TiktokApiOperation, TiktokError, TiktokFreshness, TiktokFreshnessPolicy,
    TiktokObservationEnvelope, TiktokQuotaLedger, TiktokReadScope, TiktokRetryAfterReceipt,
    TiktokVideoId, TiktokVideoListCursor, TiktokVideoPage, TiktokVideoPageEnvelope,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TiktokRealReadGate {
    secret_reference: SecretReference,
}

impl TiktokRealReadGate {
    pub fn from_env() -> Result<Self, TiktokError> {
        Self::from_environment_values(
            std::env::var(REAL_READ_ENABLE_ENV).ok().as_deref(),
            std::env::var(REAL_READ_SECRET_REFERENCE_ENV)
                .ok()
                .as_deref(),
        )
    }

    pub(crate) fn from_environment_values(
        enabled: Option<&str>,
        secret_reference: Option<&str>,
    ) -> Result<Self, TiktokError> {
        if enabled != Some("1") {
            return Err(TiktokError::BlockedEnvironment {
                requirement: "HARTEVO_TIKTOK_REAL_READ=1",
            });
        }
        let secret_reference = secret_reference.ok_or(TiktokError::BlockedEnvironment {
            requirement: "HARTEVO_TIKTOK_SECRET_REFERENCE",
        })?;
        Ok(Self {
            secret_reference: SecretReference::new(secret_reference.to_owned())?,
        })
    }

    pub const fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }
}

#[derive(Debug)]
pub struct TiktokAuthenticatedReadService<T> {
    provider: TiktokDisplayApiProvider<T>,
    quota: TiktokQuotaLedger,
    freshness_policy: TiktokFreshnessPolicy,
}

impl<T> TiktokAuthenticatedReadService<T> {
    pub fn fixture(transport: T, freshness_policy: TiktokFreshnessPolicy) -> Self {
        Self {
            provider: TiktokDisplayApiProvider::fixture(transport),
            quota: TiktokQuotaLedger::default(),
            freshness_policy,
        }
    }

    pub fn controlled(transport: T, freshness_policy: TiktokFreshnessPolicy) -> Self {
        Self {
            provider: TiktokDisplayApiProvider::controlled(transport),
            quota: TiktokQuotaLedger::default(),
            freshness_policy,
        }
    }

    pub fn fixture_with_quota(
        transport: T,
        freshness_policy: TiktokFreshnessPolicy,
        quota: TiktokQuotaLedger,
    ) -> Self {
        Self {
            provider: TiktokDisplayApiProvider::fixture(transport),
            quota,
            freshness_policy,
        }
    }

    fn production(
        transport: T,
        gate: TiktokRealReadGate,
        freshness_policy: TiktokFreshnessPolicy,
    ) -> Self {
        Self {
            provider: TiktokDisplayApiProvider::production(transport, gate.secret_reference),
            quota: TiktokQuotaLedger::default(),
            freshness_policy,
        }
    }

    pub const fn provenance(&self) -> EvidenceProvenance {
        self.provider.provenance()
    }

    pub const fn quota(&self) -> &TiktokQuotaLedger {
        &self.quota
    }

    pub fn quota_mut(&mut self) -> &mut TiktokQuotaLedger {
        &mut self.quota
    }

    pub fn probe(
        &mut self,
        credential: &OAuthCredential,
        now: DateTime<Utc>,
    ) -> Result<TiktokObservationEnvelope, TiktokError>
    where
        T: ReadOnlyTransport,
    {
        let scope = credential.scope().clone();
        credential.require_for(TiktokApiOperation::UserInfo, &scope, now)?;
        self.provider
            .require_credential_reference(credential.secret_reference())?;
        let request = probe_request(credential.secret_reference().clone())?;
        self.quota.reserve(TiktokApiOperation::UserInfo, now)?;
        let response = self.provider.send(&request)?;
        let freshness = self.freshness(TiktokApiOperation::UserInfo, &response, credential)?;
        parse_probe_response(&scope, &response, freshness, self.provenance())
    }

    pub fn list_videos(
        &mut self,
        credential: &OAuthCredential,
        cursor: &mut TiktokVideoListCursor,
        now: DateTime<Utc>,
        max_count: u8,
    ) -> Result<TiktokVideoPageEnvelope, TiktokError>
    where
        T: ReadOnlyTransport,
    {
        if !cursor.has_more() {
            return Err(TiktokError::CursorExhausted);
        }
        cursor.require_page_size(max_count)?;
        let scope = cursor.scope().clone();
        let was_bound = cursor.credential_generation().is_some();
        if was_bound {
            cursor.bind_credential(credential, now)?;
        }
        self.provider
            .require_credential_reference(credential.secret_reference())?;
        if !was_bound {
            cursor.bind_credential(credential, now)?;
        }
        credential.require_for(TiktokApiOperation::VideoList, &scope, now)?;
        if let Some(receipt) = cursor.retry_after_if_waiting(now) {
            return Err(TiktokError::RateLimited {
                operation: TiktokApiOperation::VideoList,
                retry_after_seconds: receipt.retry_after_seconds(),
            });
        }
        let request = video_list_request(
            credential.secret_reference().clone(),
            cursor.next_cursor(),
            max_count,
        )?;
        self.quota.reserve(TiktokApiOperation::VideoList, now)?;
        let response = self.provider.send(&request)?;
        if let Some(observation) = rate_limit_observation(&response)? {
            let retry_after_seconds = observation.retry_after_seconds();
            let receipt = TiktokRetryAfterReceipt::from_observation(
                scope,
                cursor.generation(),
                cursor.next_cursor(),
                credential.generation(),
                &observation,
            )?;
            cursor.record_retry_after(receipt)?;
            return Err(TiktokError::RateLimited {
                operation: TiktokApiOperation::VideoList,
                retry_after_seconds,
            });
        }
        let generation = cursor
            .generation()
            .checked_add(1)
            .ok_or(TiktokError::CursorDrift)?;
        let freshness =
            self.freshness_with_generation(TiktokApiOperation::VideoList, &response, generation)?;
        let page = parse_video_page_response(
            &scope,
            cursor.next_cursor(),
            max_count,
            &response,
            freshness,
            self.provenance(),
        )?;
        cursor.apply_page(cursor.generation(), &page)?;
        Ok(video_page_envelope(
            &page,
            cursor,
            credential.generation(),
            self.provenance(),
        ))
    }

    pub fn query_videos(
        &mut self,
        credential: &OAuthCredential,
        scope: &TiktokReadScope,
        video_ids: &[TiktokVideoId],
        now: DateTime<Utc>,
    ) -> Result<Vec<TiktokObservationEnvelope>, TiktokError>
    where
        T: ReadOnlyTransport,
    {
        credential.require_for(TiktokApiOperation::VideoQuery, scope, now)?;
        self.provider
            .require_credential_reference(credential.secret_reference())?;
        let request = video_query_request(credential.secret_reference().clone(), video_ids)?;
        self.quota.reserve(TiktokApiOperation::VideoQuery, now)?;
        let response = self.provider.send(&request)?;
        let freshness = self.freshness(TiktokApiOperation::VideoQuery, &response, credential)?;
        parse_video_query_response(scope, &response, freshness, self.provenance())
    }

    fn freshness(
        &self,
        operation: TiktokApiOperation,
        response: &crate::transport::ProviderResponse,
        credential: &OAuthCredential,
    ) -> Result<TiktokFreshness, TiktokError> {
        TiktokFreshness::new(
            response.observed_at(),
            self.freshness_policy
                .valid_until(operation, response.observed_at())?,
            credential.generation(),
        )
    }

    fn freshness_with_generation(
        &self,
        operation: TiktokApiOperation,
        response: &crate::transport::ProviderResponse,
        source_generation: u64,
    ) -> Result<TiktokFreshness, TiktokError> {
        TiktokFreshness::new(
            response.observed_at(),
            self.freshness_policy
                .valid_until(operation, response.observed_at())?,
            source_generation,
        )
    }
}

pub fn execute_real_read_gate<T>(
    transport: T,
    freshness_policy: TiktokFreshnessPolicy,
) -> Result<TiktokAuthenticatedReadService<T>, TiktokError>
where
    T: ReadOnlyTransport,
{
    let gate = TiktokRealReadGate::from_env()?;
    Ok(TiktokAuthenticatedReadService::production(
        transport,
        gate,
        freshness_policy,
    ))
}

fn video_page_envelope(
    page: &TiktokVideoPage,
    cursor: &TiktokVideoListCursor,
    credential_generation: u64,
    provenance: EvidenceProvenance,
) -> TiktokVideoPageEnvelope {
    let account = page.observations.first().map_or_else(
        || super::TiktokAccountIdentity {
            open_id: page.scope.account().clone(),
            display_name: None,
            username: None,
        },
        |observation| observation.account().clone(),
    );
    TiktokVideoPageEnvelope {
        provider: super::ProviderId::Tiktok,
        scope: page.scope.clone(),
        account,
        requested_cursor: page.requested_cursor,
        next_cursor: page.next_cursor,
        has_more: page.has_more,
        page_digest: page.page_digest.clone(),
        sequence: super::TiktokPageSequence::new(page.scope.account().clone(), cursor.generation()),
        credential_generation,
        evidence_root: cursor.evidence_root().to_owned(),
        freshness: page.freshness,
        provenance,
        observations: page.observations.clone(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use chrono::Duration;

    use super::*;
    use crate::tiktok::testkit::{final_video_page_response, first_video_page_response, response};
    use crate::tiktok::{
        BusinessId, MissionTiktokVideoSequenceConsumer, TenantId, TiktokAccountId,
        TiktokMissionPageProgress, TiktokOAuthScope,
    };
    use crate::transport::{ProviderReadRequest, ProviderResponse, TransportError};

    struct NoopTransport;

    impl ReadOnlyTransport for NoopTransport {
        fn send(
            &mut self,
            _request: &ProviderReadRequest,
        ) -> Result<ProviderResponse, TransportError> {
            Err(TransportError::Unavailable)
        }
    }

    fn scope() -> super::super::TiktokReadScope {
        super::super::TiktokReadScope::new(
            TenantId::new("tenant-01").unwrap(),
            BusinessId::new("business-01").unwrap(),
            TiktokAccountId::new("open01").unwrap(),
        )
    }

    fn video_credential(
        scope: &super::super::TiktokReadScope,
        now: DateTime<Utc>,
        generation: u64,
    ) -> OAuthCredential {
        OAuthCredential::new(
            SecretReference::new("keychain://tiktok/open01").unwrap(),
            scope.clone(),
            [TiktokOAuthScope::VideoList]
                .into_iter()
                .collect::<BTreeSet<_>>(),
            now + Duration::hours(1),
            None,
            generation,
        )
        .unwrap()
    }

    fn video_page(
        scope: &super::super::TiktokReadScope,
        credential: &OAuthCredential,
        cursor: &mut TiktokVideoListCursor,
        response: &ProviderResponse,
        provenance: EvidenceProvenance,
    ) -> TiktokVideoPageEnvelope {
        let generation = cursor.generation().checked_add(1).unwrap();
        let freshness = TiktokFreshness::new(
            response.observed_at(),
            response.observed_at() + Duration::minutes(2),
            generation,
        )
        .unwrap();
        let page = parse_video_page_response(
            scope,
            cursor.next_cursor(),
            cursor.page_size(),
            response,
            freshness,
            provenance,
        )
        .unwrap();
        cursor.apply_page(cursor.generation(), &page).unwrap();
        video_page_envelope(&page, cursor, credential.generation(), provenance)
    }

    fn unapplied_video_page(
        scope: &super::super::TiktokReadScope,
        credential: &OAuthCredential,
        cursor: &TiktokVideoListCursor,
        response: &ProviderResponse,
    ) -> TiktokVideoPageEnvelope {
        let generation = cursor.generation().checked_add(1).unwrap();
        let freshness = TiktokFreshness::new(
            response.observed_at(),
            response.observed_at() + Duration::minutes(2),
            generation,
        )
        .unwrap();
        let page = parse_video_page_response(
            scope,
            cursor.next_cursor(),
            cursor.page_size(),
            response,
            freshness,
            EvidenceProvenance::ProductionProvider,
        )
        .unwrap();
        let evidence_root =
            super::super::page_evidence_root(cursor.evidence_root(), &page, generation).unwrap();
        let account = page.observations.first().map_or_else(
            || super::super::TiktokAccountIdentity {
                open_id: page.scope.account().clone(),
                display_name: None,
                username: None,
            },
            |observation| observation.account().clone(),
        );
        TiktokVideoPageEnvelope {
            provider: super::super::ProviderId::Tiktok,
            scope: page.scope.clone(),
            account,
            requested_cursor: page.requested_cursor,
            next_cursor: page.next_cursor,
            has_more: page.has_more,
            page_digest: page.page_digest,
            sequence: super::super::TiktokPageSequence::new(
                page.scope.account().clone(),
                generation,
            ),
            credential_generation: credential.generation(),
            evidence_root,
            freshness: page.freshness,
            provenance: EvidenceProvenance::ProductionProvider,
            observations: page.observations,
        }
    }

    fn repeated_video_page_response() -> ProviderResponse {
        response(
            200,
            r#"{
              "data":{
                "videos":[{
                  "id":"7340000000000000001",
                  "create_time":1767300445,
                  "title":"Repeated fixture video",
                  "video_description":"Must not cross the Mission boundary twice",
                  "share_url":"https://www.tiktok.com/@creator/video/7340000000000000001",
                  "like_count":12,
                  "comment_count":4,
                  "share_count":5,
                  "view_count":202
                }],
                "cursor":1767300445000,
                "has_more":false
              },
              "error":{"code":"ok","message":"","log_id":"fixture-list-repeat"}
            }"#,
        )
    }

    #[test]
    fn real_gate_is_deterministic_and_blocks_missing_environment() {
        assert_eq!(
            TiktokRealReadGate::from_environment_values(
                Some("0"),
                Some("keychain://tiktok/open01")
            )
            .unwrap_err(),
            TiktokError::BlockedEnvironment {
                requirement: "HARTEVO_TIKTOK_REAL_READ=1",
            }
        );
        assert_eq!(
            TiktokRealReadGate::from_environment_values(Some("1"), None).unwrap_err(),
            TiktokError::BlockedEnvironment {
                requirement: "HARTEVO_TIKTOK_SECRET_REFERENCE",
            }
        );
        let gate = TiktokRealReadGate::from_environment_values(
            Some("1"),
            Some("keychain://tiktok/open01"),
        )
        .unwrap();
        assert_eq!(gate.secret_reference().as_str(), "keychain://tiktok/open01");
    }

    #[test]
    fn production_service_binds_the_opaque_secret_reference_before_transport() {
        let now = crate::tiktok::testkit::fixed_now();
        let gate = TiktokRealReadGate::from_environment_values(
            Some("1"),
            Some("keychain://tiktok/open01"),
        )
        .unwrap();
        let mut service = TiktokAuthenticatedReadService::production(
            NoopTransport,
            gate,
            TiktokFreshnessPolicy::default(),
        );
        let credential = OAuthCredential::new(
            SecretReference::new("keychain://tiktok/other").unwrap(),
            scope(),
            [TiktokOAuthScope::UserInfoBasic]
                .into_iter()
                .collect::<BTreeSet<_>>(),
            now + Duration::hours(1),
            None,
            1,
        )
        .unwrap();
        assert_eq!(
            service.probe(&credential, now).unwrap_err(),
            TiktokError::CredentialReferenceMismatch
        );
    }

    #[test]
    fn production_service_invalidates_rotation_before_reference_rejection() {
        let now = crate::tiktok::testkit::fixed_now();
        let read_scope = scope();
        let original = OAuthCredential::new(
            SecretReference::new("keychain://tiktok/open01").unwrap(),
            read_scope.clone(),
            [TiktokOAuthScope::VideoList]
                .into_iter()
                .collect::<BTreeSet<_>>(),
            now + Duration::hours(1),
            None,
            1,
        )
        .unwrap();
        let rotated = OAuthCredential::new(
            SecretReference::new("keychain://tiktok/open01-rotated").unwrap(),
            read_scope.clone(),
            [TiktokOAuthScope::VideoList]
                .into_iter()
                .collect::<BTreeSet<_>>(),
            now + Duration::hours(1),
            None,
            2,
        )
        .unwrap();
        let mut cursor = TiktokVideoListCursor::new(read_scope).unwrap();
        cursor.bind_credential(&original, now).unwrap();
        let gate = TiktokRealReadGate::from_environment_values(
            Some("1"),
            Some("keychain://tiktok/open01"),
        )
        .unwrap();
        let mut service = TiktokAuthenticatedReadService::production(
            NoopTransport,
            gate,
            TiktokFreshnessPolicy::default(),
        );

        assert_eq!(
            service
                .list_videos(&rotated, &mut cursor, now, 20)
                .unwrap_err(),
            TiktokError::CursorInvalidated {
                reason: super::super::TiktokCursorInvalidationReason::CredentialRotated,
            }
        );
        assert!(matches!(
            cursor.lifecycle(),
            super::super::TiktokCursorLifecycle::Invalidated {
                reason: super::super::TiktokCursorInvalidationReason::CredentialRotated,
                ..
            }
        ));
    }

    #[test]
    fn production_reference_rejection_does_not_bind_a_fresh_cursor() {
        let now = crate::tiktok::testkit::fixed_now();
        let read_scope = scope();
        let invalid = OAuthCredential::new(
            SecretReference::new("keychain://tiktok/other").unwrap(),
            read_scope.clone(),
            [TiktokOAuthScope::VideoList]
                .into_iter()
                .collect::<BTreeSet<_>>(),
            now + Duration::hours(1),
            None,
            1,
        )
        .unwrap();
        let valid = OAuthCredential::new(
            SecretReference::new("keychain://tiktok/open01").unwrap(),
            read_scope.clone(),
            [TiktokOAuthScope::VideoList]
                .into_iter()
                .collect::<BTreeSet<_>>(),
            now + Duration::hours(1),
            None,
            1,
        )
        .unwrap();
        let gate = TiktokRealReadGate::from_environment_values(
            Some("1"),
            Some("keychain://tiktok/open01"),
        )
        .unwrap();
        let mut service = TiktokAuthenticatedReadService::production(
            NoopTransport,
            gate,
            TiktokFreshnessPolicy::default(),
        );
        let mut cursor = TiktokVideoListCursor::new(read_scope).unwrap();

        assert_eq!(
            service
                .list_videos(&invalid, &mut cursor, now, 20)
                .unwrap_err(),
            TiktokError::CredentialReferenceMismatch
        );
        assert_eq!(cursor.credential_generation(), None);
        assert_eq!(
            cursor.lifecycle(),
            super::super::TiktokCursorLifecycle::Active
        );
        assert_eq!(
            service
                .list_videos(&valid, &mut cursor, now, 20)
                .unwrap_err(),
            TiktokError::Disconnected
        );
        assert_eq!(cursor.credential_generation(), Some(1));
        assert_eq!(
            cursor.lifecycle(),
            super::super::TiktokCursorLifecycle::Active
        );
    }

    #[test]
    fn mission_closes_only_an_exact_production_page_sequence() {
        let now = crate::tiktok::testkit::fixed_now();
        let read_scope = scope();
        let credential = video_credential(&read_scope, now, 1);
        let mut cursor = TiktokVideoListCursor::new(read_scope.clone()).unwrap();
        cursor.bind_credential(&credential, now).unwrap();
        let first = video_page(
            &read_scope,
            &credential,
            &mut cursor,
            &first_video_page_response(),
            EvidenceProvenance::ProductionProvider,
        );
        let final_page = video_page(
            &read_scope,
            &credential,
            &mut cursor,
            &final_video_page_response(),
            EvidenceProvenance::ProductionProvider,
        );

        let mut mission = MissionTiktokVideoSequenceConsumer::new(read_scope.clone(), 20).unwrap();
        assert!(matches!(
            mission
                .accept_page(first.clone(), &credential, now)
                .unwrap(),
            TiktokMissionPageProgress::Pending {
                sequence,
                next_cursor: Some(_),
                ..
            } if sequence.generation() == 1
        ));
        let accepted = match mission
            .accept_page(final_page.clone(), &credential, now)
            .unwrap()
        {
            TiktokMissionPageProgress::Complete(accepted) => accepted,
            progress => panic!("expected complete sequence, got {progress:?}"),
        };
        assert_eq!(accepted.provider(), super::super::ProviderId::Tiktok);
        assert_eq!(accepted.scope(), &read_scope);
        assert_eq!(accepted.credential_generation(), credential.generation());
        assert_eq!(accepted.page_count(), 2);
        assert_eq!(accepted.pages(), &[first.clone(), final_page.clone()]);
        assert_eq!(accepted.evidence_root(), cursor.evidence_root());
        assert!(mission.is_closed());

        let before_duplicate = mission.clone();
        let receipt = match mission.accept_page(first, &credential, now).unwrap() {
            TiktokMissionPageProgress::Duplicate(receipt) => receipt,
            progress => panic!("expected duplicate receipt, got {progress:?}"),
        };
        assert_eq!(receipt.provider(), super::super::ProviderId::Tiktok);
        assert_eq!(receipt.scope(), &read_scope);
        assert_eq!(receipt.sequence().generation(), 1);
        assert_eq!(receipt.credential_generation(), credential.generation());
        assert_eq!(receipt.evidence_root(), accepted.pages()[0].evidence_root());
        assert_eq!(mission, before_duplicate);

        let mut new_after_close = final_page;
        new_after_close.page_digest = "f".repeat(64);
        assert_eq!(
            mission
                .accept_page(new_after_close, &credential, now)
                .unwrap_err(),
            TiktokError::PageSequenceClosed
        );
    }

    #[test]
    fn mission_rejects_untrusted_or_drifting_pages_without_state_change() {
        let now = crate::tiktok::testkit::fixed_now();
        let read_scope = scope();
        let credential = video_credential(&read_scope, now, 1);

        let mut production_cursor = TiktokVideoListCursor::new(read_scope.clone()).unwrap();
        production_cursor.bind_credential(&credential, now).unwrap();
        let first = video_page(
            &read_scope,
            &credential,
            &mut production_cursor,
            &first_video_page_response(),
            EvidenceProvenance::ProductionProvider,
        );
        let final_page = video_page(
            &read_scope,
            &credential,
            &mut production_cursor,
            &final_video_page_response(),
            EvidenceProvenance::ProductionProvider,
        );

        let mut fixture_cursor = TiktokVideoListCursor::new(read_scope.clone()).unwrap();
        fixture_cursor.bind_credential(&credential, now).unwrap();
        let fixture = video_page(
            &read_scope,
            &credential,
            &mut fixture_cursor,
            &first_video_page_response(),
            EvidenceProvenance::Fixture,
        );
        let mut mission = MissionTiktokVideoSequenceConsumer::new(read_scope.clone(), 20).unwrap();
        let initial = mission.clone();
        assert_eq!(
            mission.accept_page(fixture, &credential, now).unwrap_err(),
            TiktokError::ProvenanceRejected
        );
        assert_eq!(mission, initial);
        assert_eq!(
            mission
                .accept_page(final_page.clone(), &credential, now)
                .unwrap_err(),
            TiktokError::CursorDrift
        );
        assert_eq!(mission, initial);

        let mut wrong_generation = first.clone();
        wrong_generation.credential_generation = 2;
        assert_eq!(
            mission
                .accept_page(wrong_generation, &credential, now)
                .unwrap_err(),
            TiktokError::CursorCredentialMismatch
        );
        assert_eq!(mission, initial);

        let mut wrong_root = first.clone();
        wrong_root.evidence_root = "0".repeat(64);
        assert_eq!(
            mission
                .accept_page(wrong_root, &credential, now)
                .unwrap_err(),
            TiktokError::EvidenceRootMismatch
        );
        assert_eq!(mission, initial);

        mission
            .accept_page(first.clone(), &credential, now)
            .unwrap();
        let accepted_first = mission.clone();
        let mut altered_replay = first;
        altered_replay.evidence_root = "1".repeat(64);
        assert_eq!(
            mission
                .accept_page(altered_replay, &credential, now)
                .unwrap_err(),
            TiktokError::CursorDrift
        );
        assert_eq!(mission, accepted_first);

        let repeated = unapplied_video_page(
            &read_scope,
            &credential,
            &fixture_cursor,
            &repeated_video_page_response(),
        );
        assert_eq!(
            mission.accept_page(repeated, &credential, now).unwrap_err(),
            TiktokError::CursorDrift
        );
        assert_eq!(mission, accepted_first);
    }
}

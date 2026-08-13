//! Authenticated TikTok read service orchestration.

use chrono::{DateTime, Utc};

use crate::transport::{ReadOnlyTransport, SecretReference};

use super::provider::{
    TiktokDisplayApiProvider, parse_probe_response, parse_video_page_response,
    parse_video_query_response, probe_request, video_list_request, video_query_request,
};
use super::{
    EvidenceProvenance, OAuthCredential, REAL_READ_ENABLE_ENV, REAL_READ_SECRET_REFERENCE_ENV,
    TiktokApiOperation, TiktokError, TiktokFreshness, TiktokFreshnessPolicy,
    TiktokObservationEnvelope, TiktokQuotaLedger, TiktokReadScope, TiktokVideoId,
    TiktokVideoListCursor, TiktokVideoPage, TiktokVideoPageEnvelope,
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
        credential.require_for(TiktokApiOperation::VideoList, &scope, now)?;
        self.provider
            .require_credential_reference(credential.secret_reference())?;
        let request = video_list_request(
            credential.secret_reference().clone(),
            cursor.next_cursor(),
            max_count,
        )?;
        self.quota.reserve(TiktokApiOperation::VideoList, now)?;
        let response = self.provider.send(&request)?;
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
            cursor.generation(),
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
    cursor_generation: u64,
    provenance: EvidenceProvenance,
) -> TiktokVideoPageEnvelope {
    let account = page
        .observations
        .first()
        .map(|observation| observation.account().clone())
        .unwrap_or_else(|| super::TiktokAccountIdentity {
            open_id: page.scope.account().clone(),
            display_name: None,
            username: None,
        });
    TiktokVideoPageEnvelope {
        provider: super::ProviderId::Tiktok,
        scope: page.scope.clone(),
        account,
        requested_cursor: page.requested_cursor,
        next_cursor: page.next_cursor,
        has_more: page.has_more,
        page_digest: page.page_digest.clone(),
        cursor_generation,
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
    use crate::tiktok::{BusinessId, TenantId, TiktokAccountId, TiktokOAuthScope};
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
        let mut service =
            TiktokAuthenticatedReadService::production(NoopTransport, gate, Default::default());
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
}

//! Mission-side admission for exact TikTok read evidence.

use chrono::{DateTime, Utc};

use super::{
    EvidenceProvenance, OAuthCredential, TiktokError, TiktokObservationEnvelope,
    TiktokReadObservation, TiktokReadScope, TiktokRevisionIdentity,
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

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{AccountId, ConnectionId, ProjectId, TenantId};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionStatus {
    PendingAuth,
    Probing,
    Connected,
    Degraded,
    Expired,
    Revoked,
    WrongAccount,
    MissingScopes,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeOutcome {
    Successful,
    AuthorizationRevoked,
    ProviderUnavailable,
    Rejected,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionProbe {
    pub outcome: ProbeOutcome,
    pub observed_external_account_id: String,
    pub granted_scopes: BTreeSet<String>,
    pub probed_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub credential_expires_at: DateTime<Utc>,
    pub evidence_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Connection {
    id: ConnectionId,
    tenant_id: TenantId,
    project_id: ProjectId,
    provider: String,
    account_id: AccountId,
    expected_external_account_id: String,
    required_scopes: BTreeSet<String>,
    granted_scopes: BTreeSet<String>,
    status: ConnectionStatus,
    last_probe: Option<ConnectionProbe>,
    revoked_at: Option<DateTime<Utc>>,
    revision: u64,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionSnapshot {
    pub id: ConnectionId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub provider: String,
    pub account_id: AccountId,
    pub expected_external_account_id: String,
    pub required_scopes: BTreeSet<String>,
    pub granted_scopes: BTreeSet<String>,
    pub status: ConnectionStatus,
    pub last_probe: Option<ConnectionProbe>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Connection {
    #[allow(clippy::too_many_arguments)]
    pub fn register(
        id: ConnectionId,
        tenant_id: TenantId,
        project_id: ProjectId,
        provider: impl Into<String>,
        account_id: AccountId,
        expected_external_account_id: impl Into<String>,
        required_scopes: impl IntoIterator<Item = String>,
        now: DateTime<Utc>,
    ) -> Result<Self, ConnectionError> {
        let provider = provider.into().trim().to_owned();
        let expected_external_account_id = expected_external_account_id.into().trim().to_owned();
        let required_scopes = normalize_scopes(required_scopes);
        if id.as_str().trim().is_empty()
            || tenant_id.as_str().trim().is_empty()
            || project_id.as_str().trim().is_empty()
            || provider.is_empty()
            || account_id.as_str().trim().is_empty()
            || expected_external_account_id.is_empty()
            || required_scopes.is_empty()
        {
            return Err(ConnectionError::IncompleteRegistration);
        }
        Ok(Self {
            id,
            tenant_id,
            project_id,
            provider,
            account_id,
            expected_external_account_id,
            required_scopes,
            granted_scopes: BTreeSet::new(),
            status: ConnectionStatus::PendingAuth,
            last_probe: None,
            revoked_at: None,
            revision: 1,
            created_at: now,
            updated_at: now,
        })
    }

    pub fn begin_probe(&mut self, now: DateTime<Utc>) -> Result<(), ConnectionError> {
        if self.status == ConnectionStatus::Revoked {
            return Err(ConnectionError::Revoked);
        }
        if self.status == ConnectionStatus::Probing {
            return Err(ConnectionError::ProbeAlreadyInProgress);
        }
        let next_revision = self.prepare_touch(now)?;
        self.status = ConnectionStatus::Probing;
        self.commit_touch(next_revision, now);
        Ok(())
    }

    pub fn apply_probe(
        &mut self,
        mut probe: ConnectionProbe,
        now: DateTime<Utc>,
    ) -> Result<ConnectionStatus, ConnectionError> {
        if self.status == ConnectionStatus::Revoked {
            return Err(ConnectionError::Revoked);
        }
        if self.status != ConnectionStatus::Probing {
            return Err(ConnectionError::ProbeNotInProgress);
        }
        let observed_external_account_id = probe.observed_external_account_id.trim().to_owned();
        probe.observed_external_account_id = observed_external_account_id;
        probe.granted_scopes = normalize_scopes(probe.granted_scopes);
        if probe.observed_external_account_id.is_empty()
            || !is_sha256(&probe.evidence_digest)
            || probe.probed_at > now
            || (probe.outcome == ProbeOutcome::Successful
                && (probe.valid_until <= now || probe.credential_expires_at <= now))
        {
            return Err(ConnectionError::InvalidProbe);
        }
        let next_revision = self.prepare_touch(now)?;
        self.granted_scopes.clone_from(&probe.granted_scopes);
        self.status = if probe.outcome == ProbeOutcome::AuthorizationRevoked {
            ConnectionStatus::Revoked
        } else if probe.observed_external_account_id != self.expected_external_account_id {
            ConnectionStatus::WrongAccount
        } else if !self.required_scopes.is_subset(&probe.granted_scopes) {
            ConnectionStatus::MissingScopes
        } else {
            match probe.outcome {
                ProbeOutcome::Successful => ConnectionStatus::Connected,
                ProbeOutcome::ProviderUnavailable => ConnectionStatus::Degraded,
                ProbeOutcome::AuthorizationRevoked => ConnectionStatus::Revoked,
                ProbeOutcome::Rejected => ConnectionStatus::PendingAuth,
            }
        };
        if self.status == ConnectionStatus::Revoked {
            self.revoked_at = Some(now);
            self.granted_scopes.clear();
        }
        self.last_probe = Some(probe);
        self.commit_touch(next_revision, now);
        Ok(self.effective_status(now))
    }

    pub fn revoke(&mut self, now: DateTime<Utc>) -> Result<(), ConnectionError> {
        if self.status == ConnectionStatus::Revoked {
            return Ok(());
        }
        let next_revision = self.prepare_touch(now)?;
        self.status = ConnectionStatus::Revoked;
        self.revoked_at = Some(now);
        self.granted_scopes.clear();
        self.commit_touch(next_revision, now);
        Ok(())
    }

    pub fn effective_status(&self, now: DateTime<Utc>) -> ConnectionStatus {
        if self.status == ConnectionStatus::Connected
            && self
                .last_probe
                .as_ref()
                .is_none_or(|probe| probe.valid_until <= now || probe.credential_expires_at <= now)
        {
            ConnectionStatus::Expired
        } else {
            self.status.clone()
        }
    }

    pub fn is_connected(&self, now: DateTime<Utc>) -> bool {
        self.effective_status(now) == ConnectionStatus::Connected
    }

    pub fn permits_scopes(&self, required: &BTreeSet<String>, now: DateTime<Utc>) -> bool {
        self.is_connected(now) && required.is_subset(&self.granted_scopes)
    }

    pub fn id(&self) -> &ConnectionId {
        &self.id
    }

    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn provider(&self) -> &str {
        &self.provider
    }

    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    pub fn last_probe(&self) -> Option<&ConnectionProbe> {
        self.last_probe.as_ref()
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn snapshot(&self) -> ConnectionSnapshot {
        ConnectionSnapshot {
            id: self.id.clone(),
            tenant_id: self.tenant_id.clone(),
            project_id: self.project_id.clone(),
            provider: self.provider.clone(),
            account_id: self.account_id.clone(),
            expected_external_account_id: self.expected_external_account_id.clone(),
            required_scopes: self.required_scopes.clone(),
            granted_scopes: self.granted_scopes.clone(),
            status: self.status.clone(),
            last_probe: self.last_probe.clone(),
            revoked_at: self.revoked_at,
            revision: self.revision,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }

    pub fn restore(snapshot: ConnectionSnapshot) -> Result<Self, ConnectionError> {
        let normalized_required_scopes = normalize_scopes(snapshot.required_scopes.clone());
        let normalized_granted_scopes = normalize_scopes(snapshot.granted_scopes.clone());
        if snapshot.id.as_str().trim().is_empty()
            || snapshot.tenant_id.as_str().trim().is_empty()
            || snapshot.project_id.as_str().trim().is_empty()
            || snapshot.provider.trim().is_empty()
            || snapshot.account_id.as_str().trim().is_empty()
            || snapshot.expected_external_account_id.trim().is_empty()
            || snapshot.required_scopes.is_empty()
            || snapshot.revision == 0
            || snapshot.updated_at < snapshot.created_at
            || normalized_required_scopes != snapshot.required_scopes
            || normalized_granted_scopes != snapshot.granted_scopes
            || snapshot
                .last_probe
                .as_ref()
                .is_some_and(|probe| !valid_probe_snapshot(probe, snapshot.updated_at))
        {
            return Err(ConnectionError::InvalidSnapshot);
        }
        if !snapshot_state_is_consistent(&snapshot) {
            return Err(ConnectionError::InvalidSnapshot);
        }
        Ok(Self {
            id: snapshot.id,
            tenant_id: snapshot.tenant_id,
            project_id: snapshot.project_id,
            provider: snapshot.provider,
            account_id: snapshot.account_id,
            expected_external_account_id: snapshot.expected_external_account_id,
            required_scopes: normalized_required_scopes,
            granted_scopes: normalized_granted_scopes,
            status: snapshot.status,
            last_probe: snapshot.last_probe,
            revoked_at: snapshot.revoked_at,
            revision: snapshot.revision,
            created_at: snapshot.created_at,
            updated_at: snapshot.updated_at,
        })
    }

    fn prepare_touch(&self, now: DateTime<Utc>) -> Result<u64, ConnectionError> {
        if now < self.updated_at {
            return Err(ConnectionError::TimestampRegression);
        }
        self.revision
            .checked_add(1)
            .ok_or(ConnectionError::RevisionOverflow)
    }

    fn commit_touch(&mut self, next_revision: u64, now: DateTime<Utc>) {
        self.revision = next_revision;
        self.updated_at = now;
    }
}

impl ConnectionSnapshot {
    pub fn validate(&self) -> Result<(), ConnectionError> {
        Connection::restore(self.clone()).map(|_| ())
    }

    pub fn is_initial_snapshot(&self) -> Result<bool, ConnectionError> {
        self.validate()?;
        Ok(self.status == ConnectionStatus::PendingAuth
            && self.granted_scopes.is_empty()
            && self.last_probe.is_none()
            && self.revoked_at.is_none()
            && self.revision == 1
            && self.created_at == self.updated_at)
    }

    pub fn follows(&self, previous: &Self) -> Result<bool, ConnectionError> {
        self.validate()?;
        previous.validate()?;
        let immutable_scope_matches = self.id == previous.id
            && self.tenant_id == previous.tenant_id
            && self.project_id == previous.project_id
            && self.provider == previous.provider
            && self.account_id == previous.account_id
            && self.expected_external_account_id == previous.expected_external_account_id
            && self.required_scopes == previous.required_scopes
            && self.created_at == previous.created_at
            && previous.revision.checked_add(1) == Some(self.revision)
            && self.updated_at >= previous.updated_at;
        if !immutable_scope_matches {
            return Ok(false);
        }
        let previous_connection = Connection::restore(previous.clone())?;
        let mut candidate = previous_connection.clone();
        if candidate.begin_probe(self.updated_at).is_ok() && candidate.snapshot() == *self {
            return Ok(true);
        }
        if let Some(probe) = &self.last_probe {
            candidate = previous_connection.clone();
            if candidate
                .apply_probe(probe.clone(), self.updated_at)
                .is_ok()
                && candidate.snapshot() == *self
            {
                return Ok(true);
            }
        }
        candidate = previous_connection;
        Ok(candidate.revoke(self.updated_at).is_ok() && candidate.snapshot() == *self)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ConnectionError {
    #[error("connection registration lacks tenant, project, provider, account, or scopes")]
    IncompleteRegistration,
    #[error("connection probe lacks current account, scope, expiry, or evidence data")]
    InvalidProbe,
    #[error("revoked connection must be explicitly re-authorized before probing")]
    Revoked,
    #[error("connection probe is already in progress")]
    ProbeAlreadyInProgress,
    #[error("connection probe result has no matching in-progress probe")]
    ProbeNotInProgress,
    #[error("connection state timestamp cannot move backwards")]
    TimestampRegression,
    #[error("persisted connection state is incomplete or internally inconsistent")]
    InvalidSnapshot,
    #[error("connection state revision overflow")]
    RevisionOverflow,
}

fn normalize_scopes(values: impl IntoIterator<Item = String>) -> BTreeSet<String> {
    values
        .into_iter()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .collect()
}

fn valid_probe_snapshot(probe: &ConnectionProbe, updated_at: DateTime<Utc>) -> bool {
    !probe.observed_external_account_id.trim().is_empty()
        && !probe
            .granted_scopes
            .iter()
            .any(|scope| scope.trim().is_empty())
        && probe.granted_scopes == normalize_scopes(probe.granted_scopes.clone())
        && is_sha256(&probe.evidence_digest)
        && probe.probed_at <= updated_at
        && probe.valid_until >= probe.probed_at
        && probe.credential_expires_at >= probe.probed_at
}

fn snapshot_state_is_consistent(snapshot: &ConnectionSnapshot) -> bool {
    match snapshot.status {
        ConnectionStatus::PendingAuth | ConnectionStatus::Probing => snapshot.revoked_at.is_none(),
        ConnectionStatus::Connected => snapshot.last_probe.as_ref().is_some_and(|probe| {
            probe.outcome == ProbeOutcome::Successful
                && probe.observed_external_account_id == snapshot.expected_external_account_id
                && snapshot.granted_scopes == probe.granted_scopes
                && snapshot.required_scopes.is_subset(&probe.granted_scopes)
                && probe.valid_until > snapshot.updated_at
                && probe.credential_expires_at > snapshot.updated_at
                && snapshot.revoked_at.is_none()
        }),
        ConnectionStatus::Degraded => snapshot.last_probe.as_ref().is_some_and(|probe| {
            probe.outcome == ProbeOutcome::ProviderUnavailable
                && probe.observed_external_account_id == snapshot.expected_external_account_id
                && snapshot.granted_scopes == probe.granted_scopes
                && snapshot.required_scopes.is_subset(&probe.granted_scopes)
                && snapshot.revoked_at.is_none()
        }),
        ConnectionStatus::WrongAccount => snapshot.last_probe.as_ref().is_some_and(|probe| {
            probe.observed_external_account_id != snapshot.expected_external_account_id
                && snapshot.granted_scopes == probe.granted_scopes
                && snapshot.revoked_at.is_none()
        }),
        ConnectionStatus::MissingScopes => snapshot.last_probe.as_ref().is_some_and(|probe| {
            probe.observed_external_account_id == snapshot.expected_external_account_id
                && !snapshot.required_scopes.is_subset(&probe.granted_scopes)
                && snapshot.granted_scopes == probe.granted_scopes
                && snapshot.revoked_at.is_none()
        }),
        ConnectionStatus::Revoked => {
            snapshot.revoked_at.is_some() && snapshot.granted_scopes.is_empty()
        }
        ConnectionStatus::Expired => false,
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

    fn connection() -> Connection {
        Connection::register(
            ConnectionId::from("connection-1"),
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            "google-search-console",
            AccountId::from("account-1"),
            "owner@example.com",
            ["sites.read".into(), "sites.write".into()],
            now(),
        )
        .expect("connection")
    }

    fn probe(account: &str, scopes: &[&str]) -> ConnectionProbe {
        ConnectionProbe {
            outcome: ProbeOutcome::Successful,
            observed_external_account_id: account.into(),
            granted_scopes: scopes.iter().map(|scope| (*scope).into()).collect(),
            probed_at: now(),
            valid_until: now() + Duration::minutes(10),
            credential_expires_at: now() + Duration::hours(1),
            evidence_digest: "a".repeat(64),
        }
    }

    #[test]
    fn wrong_account_or_missing_scope_never_appears_connected() {
        let mut connection = connection();
        connection.begin_probe(now()).expect("probe");
        assert_eq!(
            connection
                .apply_probe(
                    probe("wrong@example.com", &["sites.read", "sites.write"]),
                    now()
                )
                .expect("result"),
            ConnectionStatus::WrongAccount
        );
        connection.begin_probe(now()).expect("probe again");
        assert_eq!(
            connection
                .apply_probe(probe("owner@example.com", &["sites.read"]), now())
                .expect("result"),
            ConnectionStatus::MissingScopes
        );
    }

    #[test]
    fn connected_is_a_live_projection_of_probe_and_credential_expiry() {
        let mut connection = connection();
        connection.begin_probe(now()).expect("probe");
        connection
            .apply_probe(
                probe("owner@example.com", &["sites.read", "sites.write"]),
                now(),
            )
            .expect("connected");
        assert!(connection.is_connected(now() + Duration::minutes(9)));
        assert_eq!(
            connection.effective_status(now() + Duration::minutes(11)),
            ConnectionStatus::Expired
        );
    }

    #[test]
    fn restored_connected_snapshot_must_be_derived_from_the_exact_live_probe() {
        let mut connection = connection();
        connection.begin_probe(now()).expect("probe");
        connection
            .apply_probe(
                probe("owner@example.com", &["sites.read", "sites.write"]),
                now(),
            )
            .expect("connected");
        let valid = connection.snapshot();
        assert!(Connection::restore(valid.clone()).is_ok());

        let mut wrong_account = valid.clone();
        wrong_account
            .last_probe
            .as_mut()
            .expect("probe")
            .observed_external_account_id = "attacker@example.com".into();
        assert_eq!(
            Connection::restore(wrong_account),
            Err(ConnectionError::InvalidSnapshot)
        );
        let mut missing_scope = valid;
        missing_scope.granted_scopes.remove("sites.write");
        assert_eq!(
            Connection::restore(missing_scope),
            Err(ConnectionError::InvalidSnapshot)
        );
    }

    #[test]
    fn authorization_revocation_clears_scopes_and_snapshot_revisions_are_exact() {
        let mut connection = connection();
        let initial = connection.snapshot();
        connection.begin_probe(now()).expect("probe");
        let probing = connection.snapshot();
        assert!(probing.follows(&initial).expect("valid snapshots"));
        let mut revoked_probe = probe("owner@example.com", &["sites.read", "sites.write"]);
        revoked_probe.outcome = ProbeOutcome::AuthorizationRevoked;
        connection
            .apply_probe(revoked_probe, now())
            .expect("revocation");
        let revoked = connection.snapshot();
        assert!(revoked.granted_scopes.is_empty());
        assert!(revoked.follows(&probing).expect("valid snapshots"));

        let mut wrong_provider = revoked.clone();
        wrong_provider.provider = "another-provider".into();
        assert!(!wrong_provider.follows(&revoked).expect("valid snapshots"));
    }

    fn model_probe(action: u8, at: DateTime<Utc>) -> ConnectionProbe {
        let (outcome, account, scopes) = match action {
            2 => (
                ProbeOutcome::Successful,
                "wrong@example.com",
                BTreeSet::from(["sites.read".into(), "sites.write".into()]),
            ),
            3 => (
                ProbeOutcome::Successful,
                "owner@example.com",
                BTreeSet::from(["sites.read".into()]),
            ),
            4 => (
                ProbeOutcome::ProviderUnavailable,
                "owner@example.com",
                BTreeSet::from(["sites.read".into(), "sites.write".into()]),
            ),
            5 => (
                ProbeOutcome::AuthorizationRevoked,
                "owner@example.com",
                BTreeSet::from(["sites.read".into(), "sites.write".into()]),
            ),
            _ => (
                ProbeOutcome::Successful,
                "owner@example.com",
                BTreeSet::from(["sites.read".into(), "sites.write".into()]),
            ),
        };
        ConnectionProbe {
            outcome,
            observed_external_account_id: account.into(),
            granted_scopes: scopes,
            probed_at: at,
            valid_until: at + Duration::minutes(10),
            credential_expires_at: at + Duration::minutes(20),
            evidence_digest: "a".repeat(64),
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(96))]

        #[test]
        fn arbitrary_connection_probe_sequences_are_atomic_scoped_and_claim_connected_only_after_probe(
            actions in prop::collection::vec((0_u8..9, 0_i64..4), 1..64),
        ) {
            let mut connection = connection();
            let initial = connection.snapshot();
            let mut cursor = now();
            let required = BTreeSet::from(["sites.read".into(), "sites.write".into()]);

            for (action, advance_minutes) in actions {
                cursor += Duration::minutes(advance_minutes);
                let before = connection.snapshot();
                let result = match action {
                    0 => connection.begin_probe(cursor),
                    1..=5 => connection.apply_probe(model_probe(action, cursor), cursor).map(|_| ()),
                    6 => connection.revoke(cursor),
                    7 => {
                        let backwards = before.updated_at - Duration::seconds(1);
                        if before.status == ConnectionStatus::Probing {
                            connection.apply_probe(model_probe(1, backwards), backwards).map(|_| ())
                        } else {
                            connection.begin_probe(backwards)
                        }
                    }
                    _ => {
                        let mut overflow = connection.clone();
                        overflow.revision = u64::MAX;
                        let overflow_before = overflow.snapshot();
                        let overflow_result = if overflow.status == ConnectionStatus::Probing {
                            overflow.apply_probe(model_probe(1, cursor), cursor).map(|_| ())
                        } else {
                            overflow.begin_probe(cursor)
                        };
                        prop_assert!(overflow_result.is_err());
                        prop_assert_eq!(overflow.snapshot(), overflow_before);
                        Ok(())
                    }
                };
                let after = connection.snapshot();
                let idempotent_revoke = action == 6 && before.status == ConnectionStatus::Revoked;
                if result.is_err() || action == 8 || idempotent_revoke {
                    prop_assert_eq!(after.clone(), before);
                } else {
                    prop_assert_eq!(after.revision, before.revision + 1);
                    prop_assert!(after.updated_at >= before.updated_at);
                    prop_assert!(after.follows(&before).expect("exact connection command"));
                }
                prop_assert_eq!(after.id.clone(), initial.id.clone());
                prop_assert_eq!(after.tenant_id.clone(), initial.tenant_id.clone());
                prop_assert_eq!(after.project_id.clone(), initial.project_id.clone());
                prop_assert_eq!(after.provider.clone(), initial.provider.clone());
                prop_assert_eq!(after.account_id.clone(), initial.account_id.clone());
                prop_assert!(after.validate().is_ok());
                prop_assert_eq!(
                    connection.is_connected(cursor),
                    after.status == ConnectionStatus::Connected
                        && after.last_probe.as_ref().is_some_and(|probe| {
                            probe.valid_until > cursor && probe.credential_expires_at > cursor
                        }),
                );
                prop_assert_eq!(
                    connection.permits_scopes(&required, cursor),
                    connection.is_connected(cursor) && required.is_subset(&after.granted_scopes),
                );
                if after.status == ConnectionStatus::Revoked {
                    prop_assert!(after.granted_scopes.is_empty());
                }
            }
        }
    }
}

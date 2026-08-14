//! Mission-scoped contextual surface for the on-demand Connection Repair plugin.
//!
//! This is a plugin consumer, not a Connection Center screen. The host creates it only after a
//! related Mission invocation reports a typed `Disconnected`, `Expired`, or `ReauthRequired`
//! result. The provider-neutral service remains the owner of credential leasing, authenticated
//! probe validation, reversible mounts, and durable lifecycle events.

use chrono::{DateTime, Utc};
use serde::Serialize;
use thiserror::Error;

use super::events::ConnectionRepairEventSink;
use super::repair::{
    ConnectionRepairError, ConnectionRepairProvider, ConnectionRepairRequest,
    ConnectionRepairResult, ConnectionRepairService, ConnectionRepairSession,
    MissionConnectionRepairConsumer,
};

/// The only supported host surface: an inline, on-demand contextual action for the related
/// Connection plugin. There is intentionally no dashboard, workbench, or settings variant.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionConnectionRepairSurface {
    OnDemandContextual,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionConnectionRepairState {
    Contextual,
    Disconnected,
    Opened,
    Verified,
    Completed,
    Revoked,
    Failed,
    Expired,
    Crashed,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MissionConnectionRepairPluginError {
    #[error("the contextual repair surface is not in the requested lifecycle state")]
    InvalidState,
    #[error("the contextual repair surface has no active provider session")]
    NoSession,
    #[error("the provider repair session was lost across restart")]
    SessionLost,
    #[error("the provider result was rejected by the exact Mission consumer")]
    ResultRejected(ConnectionRepairError),
    #[error(transparent)]
    Connector(#[from] ConnectionRepairError),
}

/// Ephemeral Mission consumer for one exact failed invocation. It is intentionally not
/// serializable: after a restart the provider session is cleaned up and the old Mission cannot
/// silently reopen or reuse it.
#[derive(Clone, Debug)]
pub struct MissionConnectionRepairPlugin {
    request: ConnectionRepairRequest,
    consumer: MissionConnectionRepairConsumer,
    session: Option<ConnectionRepairSession>,
    result: Option<ConnectionRepairResult>,
    state: MissionConnectionRepairState,
}

impl MissionConnectionRepairPlugin {
    pub fn new(request: ConnectionRepairRequest) -> Self {
        Self {
            consumer: MissionConnectionRepairConsumer::new(request.clone()),
            request,
            session: None,
            result: None,
            state: MissionConnectionRepairState::Contextual,
        }
    }

    pub const fn surface(&self) -> MissionConnectionRepairSurface {
        MissionConnectionRepairSurface::OnDemandContextual
    }

    pub const fn state(&self) -> MissionConnectionRepairState {
        self.state
    }

    pub const fn request(&self) -> &ConnectionRepairRequest {
        &self.request
    }

    pub const fn session(&self) -> Option<&ConnectionRepairSession> {
        self.session.as_ref()
    }

    pub const fn result(&self) -> Option<&ConnectionRepairResult> {
        self.result.as_ref()
    }

    pub fn open<P, E>(
        &mut self,
        service: &mut ConnectionRepairService<P, E>,
        at: DateTime<Utc>,
    ) -> Result<ConnectionRepairSession, MissionConnectionRepairPluginError>
    where
        P: ConnectionRepairProvider,
        E: ConnectionRepairEventSink,
    {
        if self.state != MissionConnectionRepairState::Contextual {
            return Err(MissionConnectionRepairPluginError::InvalidState);
        }
        let session = match service.open(self.request.clone(), at) {
            Ok(session) => session,
            Err(error) => {
                self.state = state_after_connector_error(&error);
                return Err(error.into());
            }
        };
        self.session = Some(session.clone());
        self.state = MissionConnectionRepairState::Opened;
        Ok(session)
    }

    pub fn repair<P, E>(
        &mut self,
        service: &mut ConnectionRepairService<P, E>,
        at: DateTime<Utc>,
    ) -> Result<ConnectionRepairResult, MissionConnectionRepairPluginError>
    where
        P: ConnectionRepairProvider,
        E: ConnectionRepairEventSink,
    {
        if self.state != MissionConnectionRepairState::Opened {
            return Err(MissionConnectionRepairPluginError::InvalidState);
        }
        let session = self
            .session
            .clone()
            .ok_or(MissionConnectionRepairPluginError::NoSession)?;
        let result = match service.repair(&session, at) {
            Ok(result) => result,
            Err(error) => {
                self.state = state_after_connector_error(&error);
                return Err(error.into());
            }
        };
        let result = match self.consumer.consume(&result, at) {
            Ok(result) => result,
            Err(error) => {
                let _ = service.revoke(&session, at);
                self.state = MissionConnectionRepairState::Failed;
                return Err(MissionConnectionRepairPluginError::ResultRejected(error));
            }
        };
        self.result = Some(result.clone());
        self.state = MissionConnectionRepairState::Verified;
        Ok(result)
    }

    pub fn complete<P, E>(
        &mut self,
        service: &mut ConnectionRepairService<P, E>,
        at: DateTime<Utc>,
    ) -> Result<(), MissionConnectionRepairPluginError>
    where
        P: ConnectionRepairProvider,
        E: ConnectionRepairEventSink,
    {
        if self.state != MissionConnectionRepairState::Verified {
            return Err(MissionConnectionRepairPluginError::InvalidState);
        }
        let session = self
            .session
            .as_ref()
            .ok_or(MissionConnectionRepairPluginError::NoSession)?;
        match service.complete(session, at) {
            Ok(()) => {
                self.state = MissionConnectionRepairState::Completed;
                Ok(())
            }
            Err(error) => {
                self.state = state_after_connector_error(&error);
                Err(error.into())
            }
        }
    }

    /// Revoke is idempotent after a terminal cleanup, but never reopens a provider session.
    pub fn revoke<P, E>(
        &mut self,
        service: &mut ConnectionRepairService<P, E>,
        at: DateTime<Utc>,
    ) -> Result<(), MissionConnectionRepairPluginError>
    where
        P: ConnectionRepairProvider,
        E: ConnectionRepairEventSink,
    {
        if matches!(
            self.state,
            MissionConnectionRepairState::Revoked
                | MissionConnectionRepairState::Failed
                | MissionConnectionRepairState::Expired
                | MissionConnectionRepairState::Crashed
        ) {
            return Ok(());
        }
        if !matches!(
            self.state,
            MissionConnectionRepairState::Opened | MissionConnectionRepairState::Verified
        ) {
            return Err(MissionConnectionRepairPluginError::InvalidState);
        }
        let session = self
            .session
            .as_ref()
            .ok_or(MissionConnectionRepairPluginError::NoSession)?;
        let result = service.revoke(session, at);
        self.state = MissionConnectionRepairState::Revoked;
        result.map_err(MissionConnectionRepairPluginError::from)
    }

    /// The owner calls this when the Mission process crashes. The service cleans every active
    /// mount and appends content-free crash events; this plugin only fences its local handle.
    pub fn crash_cleanup<P, E>(
        &mut self,
        service: &mut ConnectionRepairService<P, E>,
        at: DateTime<Utc>,
    ) -> Result<usize, MissionConnectionRepairPluginError>
    where
        P: ConnectionRepairProvider,
        E: ConnectionRepairEventSink,
    {
        if !matches!(
            self.state,
            MissionConnectionRepairState::Opened | MissionConnectionRepairState::Verified
        ) {
            return Err(MissionConnectionRepairPluginError::InvalidState);
        }
        let cleaned = service.crash_cleanup(at)?;
        self.state = MissionConnectionRepairState::Crashed;
        Ok(cleaned)
    }

    /// A restarted host cannot resume an opaque provider session. The service's `Drop` or
    /// explicit crash cleanup has already unmounted it; callers must wait for a new failed
    /// invocation before creating another contextual surface.
    pub fn reopen_after_restart(&mut self) -> Result<(), MissionConnectionRepairPluginError> {
        if matches!(
            self.state,
            MissionConnectionRepairState::Opened | MissionConnectionRepairState::Verified
        ) {
            self.state = MissionConnectionRepairState::Crashed;
            return Err(MissionConnectionRepairPluginError::SessionLost);
        }
        Err(MissionConnectionRepairPluginError::InvalidState)
    }
}

fn state_after_connector_error(error: &ConnectionRepairError) -> MissionConnectionRepairState {
    match error {
        ConnectionRepairError::RepairCapabilityNotRegistered
        | ConnectionRepairError::ProviderStatus(
            super::repair::ConnectionRepairProviderStatus::Disconnected,
        ) => MissionConnectionRepairState::Disconnected,
        ConnectionRepairError::SessionExpired
        | ConnectionRepairError::ProviderStatus(
            super::repair::ConnectionRepairProviderStatus::Expired,
        ) => MissionConnectionRepairState::Expired,
        _ => MissionConnectionRepairState::Failed,
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use chrono::{Duration, TimeZone};

    use super::super::{
        ConnectionRepairObservation, ConnectionRepairPlugin, ConnectionRepairProviderFailure,
        ConnectionRepairProviderStatus, ConnectionRepairReason, ConnectionRepairRequest,
        RepairAuthRequest, RepairLifecycleRequest, RepairMountRequest, RepairProbeRequest,
        RepairQuota,
    };
    use super::*;
    use crate::{
        AuthSession, ConnectorAuth, ConnectorScope, FreshnessWindow, ProviderAdapterIdentity,
        ProviderAdapterOperation, ProviderAdapterRegistry, ProviderCapabilityKey,
        ProviderCapabilitySupport, ProviderEvidenceClass, ProviderEvidenceSupport,
        ProviderProvenanceClass, SecretReference,
    };

    const PLUGIN_ID: &str = "repair.plugin";
    const PROVIDER_ID: &str = "repair-provider";

    #[derive(Default)]
    struct Calls {
        mounts: usize,
        reauthorizations: usize,
        probes: usize,
        unmounts: usize,
        revocations: usize,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Fault {
        Reauthorize,
    }

    struct Provider {
        identity: ProviderAdapterIdentity,
        plugin_digest: String,
        status: ConnectionRepairProviderStatus,
        fault: Option<Fault>,
        calls: Rc<RefCell<Calls>>,
    }

    impl Provider {
        fn new(status: ConnectionRepairProviderStatus) -> (Self, Rc<RefCell<Calls>>) {
            let calls = Rc::new(RefCell::new(Calls::default()));
            let provider = Self {
                identity: ProviderAdapterIdentity::new(PLUGIN_ID, 1).expect("identity"),
                plugin_digest: crate::sha256("plugin-binary"),
                status,
                fault: None,
                calls: Rc::clone(&calls),
            };
            (provider, calls)
        }
    }

    impl ConnectionRepairProvider for Provider {
        fn identity(&self) -> &ProviderAdapterIdentity {
            &self.identity
        }

        fn mount(&mut self, request: RepairMountRequest<'_>) -> Result<(), ConnectionRepairError> {
            self.calls.borrow_mut().mounts += 1;
            if request.scope != request.secret_reference.scope()
                || request.scope != request.credential_lease.scope()
            {
                return Err(ConnectionRepairError::SecretScopeMismatch);
            }
            Ok(())
        }

        fn reauthorize(
            &mut self,
            request: RepairAuthRequest<'_>,
        ) -> Result<AuthSession, ConnectionRepairError> {
            self.calls.borrow_mut().reauthorizations += 1;
            if self.fault == Some(Fault::Reauthorize) {
                return Err(ConnectionRepairError::Provider(
                    ConnectionRepairProviderFailure::ReauthRejected,
                ));
            }
            ConnectorAuth::begin_auth_session(
                request.secret_reference,
                request.credential_lease,
                format!("auth-session-plugin-{}", request.auth_revision),
                request.auth_revision,
                request.at,
                request.expires_at,
            )
            .map_err(|_| ConnectionRepairError::InvalidAuthChain)
        }

        fn probe(
            &mut self,
            request: RepairProbeRequest<'_>,
        ) -> Result<ConnectionRepairObservation, ConnectionRepairError> {
            self.calls.borrow_mut().probes += 1;
            let freshness = FreshnessWindow::new(
                request.at,
                request.at + Duration::seconds(20),
                request.probe_revision,
            )
            .map_err(|_| ConnectionRepairError::InvalidObservation)?;
            ConnectionRepairObservation::new(
                request.scope.clone(),
                request.scope.account_id(),
                [request.requested_capability.clone()],
                RepairQuota::new(5, 1)?,
                freshness,
                self.identity.clone(),
                self.plugin_digest.clone(),
                self.status,
                crate::sha256("plugin-evidence"),
                request.at,
            )
        }

        fn unmount(&mut self, _request: RepairLifecycleRequest<'_>) {
            self.calls.borrow_mut().unmounts += 1;
        }

        fn revoke(
            &mut self,
            _request: RepairLifecycleRequest<'_>,
        ) -> Result<(), ConnectionRepairError> {
            self.calls.borrow_mut().revocations += 1;
            Ok(())
        }
    }

    fn now() -> DateTime<Utc> {
        Utc.timestamp_opt(1_700_001_000, 0)
            .single()
            .expect("timestamp")
    }

    fn scope() -> super::super::repair::ConnectionRepairScope {
        let connector = ConnectorScope::new(
            "tenant-plugin",
            "project-plugin",
            PROVIDER_ID,
            "account-plugin",
            ["repair.invoke".to_owned(), "connection.probe".to_owned()],
        )
        .expect("connector scope");
        super::super::repair::ConnectionRepairScope::new(
            super::super::repair::MissionRepairScope::new(
                "tenant-plugin",
                "project-plugin",
                "mission-plugin",
                2,
            )
            .expect("Mission scope"),
            connector,
        )
        .expect("repair scope")
    }

    fn request(reason: ConnectionRepairReason) -> ConnectionRepairRequest {
        let scope = scope();
        let secret = SecretReference::new("secret-ref-plugin-test", scope.connector().clone(), 3)
            .expect("secret reference");
        ConnectionRepairRequest::new(
            scope,
            "connection-plugin",
            ConnectionRepairPlugin::new(PLUGIN_ID, 1, crate::sha256("plugin-binary"))
                .expect("plugin"),
            secret,
            crate::sha256("plugin-invocation"),
            crate::sha256("plugin-objective"),
            ProviderCapabilityKey::new(PROVIDER_ID, "repair.invoke").expect("capability"),
            reason,
            crate::sha256("plugin-failed-result"),
            4,
            5,
            6,
            Duration::seconds(30),
            4,
        )
        .expect("request")
    }

    fn registry(identity: &ProviderAdapterIdentity) -> ProviderAdapterRegistry {
        let key = ProviderCapabilityKey::new(PROVIDER_ID, "connection.probe").expect("key");
        let evidence = [
            (
                ProviderAdapterOperation::BeginAuth,
                ProviderEvidenceClass::Authentication,
            ),
            (
                ProviderAdapterOperation::Refresh,
                ProviderEvidenceClass::Authentication,
            ),
            (
                ProviderAdapterOperation::Probe,
                ProviderEvidenceClass::ProbeObservation,
            ),
            (
                ProviderAdapterOperation::Revoke,
                ProviderEvidenceClass::RevocationObservation,
            ),
        ]
        .into_iter()
        .map(|(operation, evidence_class)| {
            ProviderEvidenceSupport::new(
                operation,
                evidence_class,
                ProviderProvenanceClass::ProductionProvider,
            )
            .expect("evidence")
        });
        ProviderAdapterRegistry::new(
            "plugin-surface-v1",
            [ProviderCapabilitySupport::new(key, identity.clone(), evidence).expect("support")],
        )
        .expect("registry")
    }

    fn service(provider: Provider) -> ConnectionRepairService<Provider> {
        let identity = provider.identity.clone();
        ConnectionRepairService::new(
            provider,
            registry(&identity),
            super::super::events::ConnectionRepairEventLog::default(),
        )
        .expect("service")
    }

    #[test]
    fn plugin_is_only_contextual_and_consumes_an_authenticated_result() {
        let start = now();
        let mut plugin =
            MissionConnectionRepairPlugin::new(request(ConnectionRepairReason::Disconnected));
        assert_eq!(
            plugin.surface(),
            MissionConnectionRepairSurface::OnDemandContextual
        );
        assert_eq!(plugin.state(), MissionConnectionRepairState::Contextual);
        let (provider, calls) = Provider::new(ConnectionRepairProviderStatus::Reachable);
        let mut service = service(provider);
        let session = plugin.open(&mut service, start).expect("open");
        let result = plugin
            .repair(&mut service, start + Duration::seconds(1))
            .expect("repair");
        assert_eq!(plugin.state(), MissionConnectionRepairState::Verified);
        assert_eq!(plugin.session(), Some(&session));
        assert_eq!(plugin.result(), Some(&result));
        assert_eq!(result.scope().mission().mission_id(), "mission-plugin");
        assert_eq!(result.scope().connector().account_id(), "account-plugin");
        assert_eq!(calls.borrow().reauthorizations, 1);
        assert_eq!(calls.borrow().probes, 1);
        plugin
            .complete(&mut service, start + Duration::seconds(2))
            .expect("complete");
        assert_eq!(plugin.state(), MissionConnectionRepairState::Completed);
        assert_eq!(calls.borrow().unmounts, 1);
    }

    #[test]
    fn provider_failure_is_terminal_and_does_not_expose_a_result() {
        let (mut provider, calls) = Provider::new(ConnectionRepairProviderStatus::Reachable);
        provider.fault = Some(Fault::Reauthorize);
        let mut service = service(provider);
        let mut plugin =
            MissionConnectionRepairPlugin::new(request(ConnectionRepairReason::ReauthRequired));
        assert!(matches!(
            plugin.repair(&mut service, now()),
            Err(MissionConnectionRepairPluginError::InvalidState)
        ));
        plugin.open(&mut service, now()).expect("open");
        assert!(matches!(
            plugin.repair(&mut service, now() + Duration::seconds(1)),
            Err(MissionConnectionRepairPluginError::Connector(
                ConnectionRepairError::Provider(ConnectionRepairProviderFailure::ReauthRejected)
            ))
        ));
        assert_eq!(plugin.state(), MissionConnectionRepairState::Failed);
        assert_eq!(plugin.result(), None);
        assert_eq!(calls.borrow().unmounts, 1);
    }

    #[test]
    fn empty_registration_stays_disconnected_before_provider_mount() {
        let (provider, calls) = Provider::new(ConnectionRepairProviderStatus::Reachable);
        let identity = provider.identity.clone();
        let mut service = ConnectionRepairService::new(
            provider,
            ProviderAdapterRegistry::new("empty-registry-v1", std::iter::empty())
                .expect("empty registry"),
            super::super::events::ConnectionRepairEventLog::default(),
        )
        .expect("service");
        assert_eq!(identity.adapter_id(), PLUGIN_ID);
        let mut plugin =
            MissionConnectionRepairPlugin::new(request(ConnectionRepairReason::Expired));
        assert!(matches!(
            plugin.open(&mut service, now()),
            Err(MissionConnectionRepairPluginError::Connector(
                ConnectionRepairError::RepairCapabilityNotRegistered
            ))
        ));
        assert_eq!(plugin.state(), MissionConnectionRepairState::Disconnected);
        assert_eq!(calls.borrow().mounts, 0);
    }

    #[test]
    fn revoke_crash_restart_and_drop_cleanup_fence_old_mission_handles() {
        let start = now();
        let (provider, calls) = Provider::new(ConnectionRepairProviderStatus::Reachable);
        let mut service = service(provider);
        let mut revoked =
            MissionConnectionRepairPlugin::new(request(ConnectionRepairReason::Disconnected));
        revoked.open(&mut service, start).expect("open");
        revoked
            .revoke(&mut service, start + Duration::seconds(1))
            .expect("revoke");
        assert_eq!(revoked.state(), MissionConnectionRepairState::Revoked);
        assert_eq!(calls.borrow().revocations, 1);
        assert_eq!(calls.borrow().unmounts, 1);
        assert!(
            revoked
                .revoke(&mut service, start + Duration::seconds(2))
                .is_ok()
        );

        let mut crashed =
            MissionConnectionRepairPlugin::new(request(ConnectionRepairReason::Expired));
        crashed
            .open(&mut service, start + Duration::seconds(3))
            .expect("open crash");
        assert_eq!(
            crashed.crash_cleanup(&mut service, start + Duration::seconds(4)),
            Ok(1)
        );
        assert_eq!(crashed.state(), MissionConnectionRepairState::Crashed);
        assert_eq!(
            crashed.reopen_after_restart(),
            Err(MissionConnectionRepairPluginError::InvalidState)
        );

        let mut dropped =
            MissionConnectionRepairPlugin::new(request(ConnectionRepairReason::ReauthRequired));
        {
            let mut drop_service = service;
            dropped
                .open(&mut drop_service, start + Duration::seconds(5))
                .expect("open drop");
        }
        assert_eq!(calls.borrow().unmounts, 3);
        assert_eq!(
            dropped.reopen_after_restart(),
            Err(MissionConnectionRepairPluginError::SessionLost)
        );
        assert_eq!(dropped.state(), MissionConnectionRepairState::Crashed);
    }
}

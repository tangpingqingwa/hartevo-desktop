//! One-call-site Cordis mount and typed Runtime adapter for the desktop shell.
//!
//! Production Runtime enters through [`dispatch_live_runtime`]: Cordis issues
//! a short-lived scoped permit, Desktop releases the host lock, and the real
//! Application coordinator runs exactly once. OpenInterpreter may occupy the
//! optional plugin slot; it never owns Domain, Effect, or execution authority.

#[cfg(test)]
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use hartevo_cordis::{
    AuthorityDispatchError, AuthorityScope, CordisError, CordisHost, Fiber, FiberState, FiberUid,
    KernelApproval, KernelApprovalDecision, KernelConsentRecord, KernelConsentState,
    KernelConsentStatus, RuntimeAuthority, RuntimeDispatchCompletion, RuntimeDispatchPermit,
    host_is_cordis_loop, keys,
};
use hartevo_domain_kernel::{
    Approval, ApprovalDecision, ConsentRecord, ConsentState, ConsentStatus,
};

use crate::runtime_plane::{DesktopRuntimeAvailabilityStatus, DesktopRuntimeProjection};

/// Whether OpenInterpreter is configured as an optional runtime adapter.
#[must_use]
fn openinterpreter_runtime_plugin(runtime: &DesktopRuntimeProjection) -> bool {
    matches!(
        runtime.status,
        DesktopRuntimeAvailabilityStatus::ReadyDevelopment
            | DesktopRuntimeAvailabilityStatus::ReadyDistribution
    )
}

#[derive(Debug, Eq, PartialEq)]
struct DesktopCordisBindingState {
    root_fiber_uid: FiberUid,
    refresh_sequence: u64,
    scope: Option<AuthorityScope>,
}

/// Typed proof that one exact scoped live binding completed before Runtime
/// authorization. The underlying reserved Domain provider remains Cordis-owned.
#[derive(Debug)]
struct DesktopCordisBindingReceipt {
    coordinator_identity: Arc<()>,
    root_fiber_uid: FiberUid,
    refresh_sequence: u64,
    scope: AuthorityScope,
}

impl DesktopCordisBindingReceipt {
    #[cfg(test)]
    #[must_use]
    const fn scope(&self) -> &AuthorityScope {
        &self.scope
    }

    #[cfg(test)]
    #[must_use]
    const fn root_fiber_uid(&self) -> FiberUid {
        self.root_fiber_uid
    }

    #[cfg(test)]
    #[must_use]
    const fn refresh_sequence(&self) -> u64 {
        self.refresh_sequence
    }
}

/// Desktop-owned lifetime boundary around the generic Cordis host.
///
/// It retains the root Fiber handle and records only successful live bindings.
/// Cordis remains the sole owner of reserved provider identity/generation and
/// of Runtime permits.
#[derive(Debug)]
pub(crate) struct DesktopCordisCoordinator {
    host: CordisHost,
    identity: Arc<()>,
    root_fiber: Fiber,
    successful_bindings: u64,
    last_binding: Option<DesktopCordisBindingState>,
}

impl DesktopCordisCoordinator {
    fn new(host: CordisHost) -> Result<Self, CordisError> {
        let root_fiber = host.context().root_fiber();
        let coordinator = Self {
            host,
            identity: Arc::new(()),
            root_fiber,
            successful_bindings: 0,
            last_binding: None,
        };
        coordinator.ensure_root_fiber_active()?;
        Ok(coordinator)
    }

    fn ensure_root_fiber_active(&self) -> Result<(), CordisError> {
        if self.root_fiber.is_disposed() || self.root_fiber.state() != FiberState::Active {
            return Err(CordisError::FiberDisposed {
                uid: self.root_fiber.uid(),
            });
        }
        Ok(())
    }

    fn next_binding_sequence(&self) -> Result<u64, CordisError> {
        self.successful_bindings.checked_add(1).ok_or_else(|| {
            CordisError::ProviderGenerationOverflow {
                key: keys::DOMAIN.to_string(),
            }
        })
    }

    fn record_binding(&mut self, refresh_sequence: u64, scope: Option<AuthorityScope>) {
        self.successful_bindings = refresh_sequence;
        self.last_binding = Some(DesktopCordisBindingState {
            root_fiber_uid: self.root_fiber.uid(),
            refresh_sequence,
            scope,
        });
    }

    #[cfg(test)]
    fn bind_domain_kernel(
        &mut self,
        consent: KernelConsentState,
        record: Option<KernelConsentRecord>,
        approval: Option<KernelApproval>,
        now: DateTime<Utc>,
    ) -> Result<(), CordisError> {
        self.ensure_root_fiber_active()?;
        let refresh_sequence = self.next_binding_sequence()?;
        self.host
            .bind_domain_kernel(consent, record, approval, now)?;
        self.record_binding(refresh_sequence, None);
        Ok(())
    }

    fn bind_domain_kernel_scope(
        &mut self,
        scope: AuthorityScope,
        consent: KernelConsentState,
        record: Option<KernelConsentRecord>,
        approval: Option<KernelApproval>,
        now: DateTime<Utc>,
    ) -> Result<DesktopCordisBindingReceipt, CordisError> {
        self.ensure_root_fiber_active()?;
        let refresh_sequence = self.next_binding_sequence()?;
        self.host
            .bind_domain_kernel_scope(scope.clone(), consent, record, approval, now)?;
        self.record_binding(refresh_sequence, Some(scope.clone()));
        Ok(DesktopCordisBindingReceipt {
            coordinator_identity: Arc::clone(&self.identity),
            root_fiber_uid: self.root_fiber.uid(),
            refresh_sequence,
            scope,
        })
    }

    fn authorize_bound_runtime(
        &mut self,
        binding: DesktopCordisBindingReceipt,
    ) -> Result<RuntimeDispatchPermit, CordisError> {
        let DesktopCordisBindingReceipt {
            coordinator_identity,
            root_fiber_uid,
            refresh_sequence,
            scope,
        } = binding;
        self.ensure_root_fiber_active()?;
        if !Arc::ptr_eq(&self.identity, &coordinator_identity)
            || root_fiber_uid != self.root_fiber.uid()
        {
            return Err(CordisError::AuthorityScopeMismatch);
        }
        let Some(current) = self.last_binding.as_ref() else {
            return Err(CordisError::AuthorityScopeUnbound);
        };
        if current.root_fiber_uid != root_fiber_uid
            || current.refresh_sequence != refresh_sequence
            || current.refresh_sequence != self.successful_bindings
            || current.scope.as_ref() != Some(&scope)
        {
            return Err(CordisError::AuthorityScopeMismatch);
        }
        self.last_binding = None;
        self.host.authorize_runtime(&scope)
    }

    fn bind_and_authorize_runtime(
        &mut self,
        scope: AuthorityScope,
        consent: KernelConsentState,
        record: Option<KernelConsentRecord>,
        approval: Option<KernelApproval>,
        now: DateTime<Utc>,
    ) -> Result<RuntimeDispatchPermit, CordisError> {
        let binding = self.bind_domain_kernel_scope(scope, consent, record, approval, now)?;
        self.authorize_bound_runtime(binding)
    }

    fn finish_runtime(
        &mut self,
        permit: RuntimeDispatchPermit,
    ) -> Result<RuntimeDispatchCompletion, CordisError> {
        self.host.finish_runtime(permit)
    }

    #[cfg(test)]
    pub(crate) fn host_mut(&mut self) -> &mut CordisHost {
        &mut self.host
    }

    #[cfg(test)]
    #[must_use]
    fn root_fiber(&self) -> &Fiber {
        &self.root_fiber
    }

    #[cfg(test)]
    #[must_use]
    fn last_binding(&self) -> Option<&DesktopCordisBindingState> {
        self.last_binding.as_ref()
    }

    #[cfg(test)]
    #[must_use]
    const fn successful_bindings(&self) -> u64 {
        self.successful_bindings
    }
}

#[cfg(test)]
impl Deref for DesktopCordisCoordinator {
    type Target = CordisHost;

    fn deref(&self) -> &Self::Target {
        &self.host
    }
}

#[cfg(test)]
impl DerefMut for DesktopCordisCoordinator {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.host
    }
}

/// Boot SurfaceMapping + AgentLoop + InvariantGate for this desktop process.
///
/// Production mount is fail-closed: consent/approval stay false until
/// the exact scoped runtime adapter reads live Domain Kernel facts.
pub(crate) fn mount_cordis_host(
    runtime: &DesktopRuntimeProjection,
) -> Result<DesktopCordisCoordinator, CordisError> {
    let host = CordisHost::boot(openinterpreter_runtime_plugin(runtime))?;
    host_is_cordis_loop(&host)?;
    DesktopCordisCoordinator::new(host)
}

/// Map a Domain Kernel [`ConsentState`] onto the host-side DTO.
#[must_use]
fn kernel_consent_state(state: &ConsentState) -> KernelConsentState {
    match state {
        ConsentState::NotRequired => KernelConsentState::NotRequired,
        ConsentState::Confirmed => KernelConsentState::Confirmed,
        ConsentState::Missing => KernelConsentState::Missing,
        ConsentState::Withdrawn => KernelConsentState::Withdrawn,
    }
}

/// Map a live Domain Kernel [`ConsentRecord`] onto the host-side DTO.
#[must_use]
fn kernel_consent_record(record: &ConsentRecord) -> KernelConsentRecord {
    KernelConsentRecord {
        status: match record.status {
            ConsentStatus::Granted => KernelConsentStatus::Granted,
            ConsentStatus::Denied => KernelConsentStatus::Denied,
            ConsentStatus::Withdrawn => KernelConsentStatus::Withdrawn,
            ConsentStatus::Expired => KernelConsentStatus::Expired,
        },
        granted_at: record.granted_at,
        valid_until: record.valid_until,
        withdrawn_at: record.withdrawn_at,
    }
}

/// Map a live Domain Kernel [`Approval`] onto the host-side DTO.
#[must_use]
fn kernel_approval(approval: &Approval) -> KernelApproval {
    KernelApproval {
        decision: match approval.decision {
            ApprovalDecision::Approved => KernelApprovalDecision::Approved,
            ApprovalDecision::Rejected => KernelApprovalDecision::Rejected,
        },
        valid_until: approval.valid_until,
    }
}

/// Test-only unscoped Domain Kernel fact binding.
#[cfg(test)]
pub(crate) fn bind_live_domain_kernel(
    host: &mut DesktopCordisCoordinator,
    consent: &ConsentState,
    record: Option<&ConsentRecord>,
    approval: Option<&Approval>,
    now: DateTime<Utc>,
) -> Result<(), CordisError> {
    host.bind_domain_kernel(
        kernel_consent_state(consent),
        record.map(kernel_consent_record),
        approval.map(kernel_approval),
        now,
    )
}

/// Test-only exact Project/Mission binding receipt.
#[cfg(test)]
fn bind_live_domain_kernel_scope(
    host: &mut DesktopCordisCoordinator,
    scope: AuthorityScope,
    consent: &ConsentState,
    record: Option<&ConsentRecord>,
    approval: Option<&Approval>,
    now: DateTime<Utc>,
) -> Result<DesktopCordisBindingReceipt, CordisError> {
    host.bind_domain_kernel_scope(
        scope,
        kernel_consent_state(consent),
        record.map(kernel_consent_record),
        approval.map(kernel_approval),
        now,
    )
}

/// Test-only compatibility seam for DataPlane invariant fixtures.
#[cfg(test)]
pub(crate) fn bind_live_domain_kernel_scope_for_test(
    host: &mut DesktopCordisCoordinator,
    scope: AuthorityScope,
    consent: &ConsentState,
    record: Option<&ConsentRecord>,
    approval: Option<&Approval>,
    now: DateTime<Utc>,
) -> Result<(), CordisError> {
    bind_live_domain_kernel_scope(host, scope, consent, record, approval, now).map(drop)
}

/// Private Desktop adapter for the one Cordis-authorized Application call.
///
/// Keeping the closure inside this type makes the production composition seam
/// explicit without making generic Cordis depend on ApplicationService.
pub(crate) struct DesktopRuntimeAuthority<Execute> {
    execute: Execute,
}

impl<Execute> DesktopRuntimeAuthority<Execute> {
    pub(crate) fn new(execute: Execute) -> Self {
        Self { execute }
    }
}

impl<Execute, Output, AdapterError> RuntimeAuthority for DesktopRuntimeAuthority<Execute>
where
    Execute: FnOnce(&RuntimeDispatchPermit) -> Result<Output, AdapterError>,
{
    type Output = Output;
    type Error = AdapterError;

    fn execute(self, permit: &RuntimeDispatchPermit) -> Result<Self::Output, Self::Error> {
        (self.execute)(permit)
    }
}

/// Bind exact live facts, obtain an unforgeable Cordis permit, release the
/// host lock, execute the real Desktop/Application adapter exactly once, and
/// settle the lifecycle under a second short lock.
pub(crate) fn dispatch_live_runtime<Execute, Output, AdapterError>(
    cordis: &Arc<Mutex<DesktopCordisCoordinator>>,
    scope: AuthorityScope,
    consent: &ConsentState,
    record: Option<&ConsentRecord>,
    approval: Option<&Approval>,
    now: DateTime<Utc>,
    execute: Execute,
) -> Result<Output, AuthorityDispatchError<AdapterError>>
where
    Execute: FnOnce(&RuntimeDispatchPermit) -> Result<Output, AdapterError>,
{
    let mut permit = {
        let mut host = cordis
            .lock()
            .map_err(|_| CordisError::RuntimeCoordinatorPoisoned)?;
        host.bind_and_authorize_runtime(
            scope,
            kernel_consent_state(consent),
            record.map(kernel_consent_record),
            approval.map(kernel_approval),
            now,
        )?
    };
    let started = permit.announce_started().err();
    let (output, authority) = if started.is_none() {
        match DesktopRuntimeAuthority::new(execute).execute(&permit) {
            Ok(output) => (Some(output), None),
            Err(error) => (None, Some(error)),
        }
    } else {
        (None, None)
    };

    let completion = match cordis.lock() {
        Ok(mut host) => host.finish_runtime(permit),
        Err(_) => Err(CordisError::RuntimeCoordinatorPoisoned),
    };
    let (finish, disposed) = match completion {
        Ok(completion) => (None, completion.announce().err()),
        Err(error) => (Some(error), None),
    };
    if let Some(error) = AuthorityDispatchError::from_phases(started, authority, finish, disposed) {
        Err(error)
    } else {
        output.ok_or_else(|| {
            AuthorityDispatchError::Cordis(Box::new(CordisError::RuntimePermitMismatch))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fmt::{self, Display};
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    };
    use std::thread;
    use std::time::Duration as StdDuration;

    use chrono::{Duration, TimeZone, Utc};
    use hartevo_cordis::{
        AgentStep, AgentsSurface, AuthorityDispatchError, AuthorityScope, CordisError, CordisHost,
        DomainSurface, FiberState, OPENINTERPRETER, RuntimeBinding, SurfaceOwner,
        enforce_invariants, events, host_is_cordis_loop, invariant_missing, keys,
    };
    use hartevo_domain_kernel::{
        ActorId, Approval, ApprovalDecision, ApprovalId, ConsentPurpose, ConsentRecord,
        ConsentRecordId, ConsentState, ConsentStatus, ContactChannel, LegalBasis, PersonId,
        ProjectId, TenantId,
    };
    use hartevo_runtime_adapter::OPENINTERPRETER_RELEASE;

    use super::{
        bind_live_domain_kernel, bind_live_domain_kernel_scope, dispatch_live_runtime,
        mount_cordis_host, openinterpreter_runtime_plugin,
    };
    use crate::runtime_plane::{DesktopRuntimeAvailabilityStatus, DesktopRuntimeProjection};

    fn projection(status: DesktopRuntimeAvailabilityStatus) -> DesktopRuntimeProjection {
        DesktopRuntimeProjection {
            status,
            target: Some("aarch64-apple-darwin".into()),
            release: OPENINTERPRETER_RELEASE.into(),
            program_sha256: None,
            provider: None,
            model: None,
            distribution_signature_evidence: None,
            exact_tokenizer_evidence: false,
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    struct PhaseError(&'static str);

    impl Display for PhaseError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(self.0)
        }
    }

    impl Error for PhaseError {}

    fn runtime_scope() -> AuthorityScope {
        AuthorityScope::new("tenant-a", "project-a", "mission-a", 4)
            .unwrap()
            .with_runtime(RuntimeBinding::new(2, None, None, "a".repeat(64)).unwrap())
    }

    fn assert_emit_source(error: &CordisError, expected: &'static str) {
        let CordisError::Emit { error, .. } = error else {
            panic!("expected typed Emit phase failure: {error:?}");
        };
        assert_eq!(
            error.event_source().as_error().downcast_ref::<PhaseError>(),
            Some(&PhaseError(expected))
        );
    }

    #[test]
    fn started_failure_is_cached_and_lifecycle_callbacks_run_after_unlock() {
        let host = Arc::new(Mutex::new(
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap(),
        ));
        let started_calls = Arc::new(AtomicUsize::new(0));
        let later_started_calls = Arc::new(AtomicUsize::new(0));
        let disposed_calls = Arc::new(AtomicUsize::new(0));
        {
            let started_host = Arc::clone(&host);
            let started_calls = Arc::clone(&started_calls);
            let later_started_calls = Arc::clone(&later_started_calls);
            let disposed_host = Arc::clone(&host);
            let disposed_calls = Arc::clone(&disposed_calls);
            let mut locked = host.lock().unwrap();
            locked
                .context_mut()
                .try_on_emit(events::AGENT_CREATED, move |_| {
                    assert!(started_host.try_lock().is_ok());
                    started_calls.fetch_add(1, Ordering::SeqCst);
                    Err(PhaseError("started"))
                })
                .unwrap();
            locked
                .on_runtime_started(move |_| {
                    later_started_calls.fetch_add(1, Ordering::SeqCst);
                })
                .unwrap();
            locked
                .on_runtime_finished(move |_| {
                    assert!(disposed_host.try_lock().is_ok());
                    disposed_calls.fetch_add(1, Ordering::SeqCst);
                })
                .unwrap();
        }
        let scope = runtime_scope();
        let mut permit = {
            let mut locked = host.lock().unwrap();
            bind_live_domain_kernel_scope(
                &mut locked,
                scope.clone(),
                &ConsentState::NotRequired,
                None,
                None,
                now(),
            )
            .unwrap();
            locked.authorize_runtime(&scope).unwrap()
        };

        let first = permit.announce_started().unwrap_err();
        let second = permit.announce_started().unwrap_err();
        assert_eq!(first, second);
        assert_emit_source(&first, "started");
        assert_eq!(started_calls.load(Ordering::SeqCst), 1);
        assert_eq!(later_started_calls.load(Ordering::SeqCst), 0);
        let completion = host.lock().unwrap().finish_runtime(permit).unwrap();
        completion.announce().unwrap();
        assert_eq!(disposed_calls.load(Ordering::SeqCst), 1);
        assert!(host.lock().unwrap().active_runtime_scope().is_none());
    }

    #[test]
    fn started_and_disposed_failures_are_combined_and_authority_is_skipped() {
        let host = Arc::new(Mutex::new(
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap(),
        ));
        {
            let mut locked = host.lock().unwrap();
            locked
                .context_mut()
                .try_on_emit(events::AGENT_CREATED, |_| Err(PhaseError("started")))
                .unwrap();
            locked
                .context_mut()
                .try_on_emit(events::AGENT_DISPOSED, |_| Err(PhaseError("disposed")))
                .unwrap();
        }
        let authority_calls = Arc::new(AtomicUsize::new(0));
        let observed_calls = Arc::clone(&authority_calls);
        let error = dispatch_live_runtime(
            &host,
            runtime_scope(),
            &ConsentState::NotRequired,
            None,
            None,
            now(),
            move |_| {
                observed_calls.fetch_add(1, Ordering::SeqCst);
                Ok::<_, PhaseError>(())
            },
        )
        .unwrap_err();
        let AuthorityDispatchError::Combined(failures) = &error else {
            panic!("expected started+disposed combined failure: {error:?}");
        };
        assert_emit_source(failures.started().unwrap(), "started");
        assert!(failures.authority().is_none());
        assert!(failures.finish().is_none());
        assert_emit_source(failures.disposed().unwrap(), "disposed");
        assert_eq!(authority_calls.load(Ordering::SeqCst), 0);
        assert!(host.lock().unwrap().active_runtime_scope().is_none());
    }

    #[test]
    fn authority_and_disposed_failures_are_combined_without_source_loss() {
        let host = Arc::new(Mutex::new(
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap(),
        ));
        host.lock()
            .unwrap()
            .context_mut()
            .try_on_emit(events::AGENT_DISPOSED, |_| Err(PhaseError("disposed")))
            .unwrap();
        let error = dispatch_live_runtime(
            &host,
            runtime_scope(),
            &ConsentState::NotRequired,
            None,
            None,
            now(),
            |_| Err::<(), _>(PhaseError("authority")),
        )
        .unwrap_err();
        let AuthorityDispatchError::Combined(failures) = &error else {
            panic!("expected authority+disposed combined failure: {error:?}");
        };
        assert!(failures.started().is_none());
        assert_eq!(failures.authority(), Some(&PhaseError("authority")));
        assert!(failures.finish().is_none());
        assert_emit_source(failures.disposed().unwrap(), "disposed");
        assert_eq!(
            error.source().unwrap().downcast_ref::<PhaseError>(),
            Some(&PhaseError("authority"))
        );
    }

    #[test]
    fn desktop_runtime_adapter_releases_host_lock_and_calls_authority_once() {
        let host = Arc::new(Mutex::new(
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap(),
        ));
        let scope = AuthorityScope::new("tenant-a", "project-a", "mission-a", 4)
            .unwrap()
            .with_runtime(RuntimeBinding::new(2, None, None, "a".repeat(64)).unwrap());
        let probe = Arc::clone(&host);
        let calls = Arc::new(AtomicUsize::new(0));
        let observed_calls = Arc::clone(&calls);
        let expected_scope = scope.clone();
        let nested_calls = Arc::new(AtomicUsize::new(0));
        let observed_nested_calls = Arc::clone(&nested_calls);

        let output = dispatch_live_runtime(
            &host,
            scope,
            &ConsentState::NotRequired,
            None,
            None,
            now(),
            move |permit| {
                assert_eq!(permit.scope(), &expected_scope);
                assert!(
                    probe.try_lock().is_ok(),
                    "Application adapter must run without the Cordis host lock"
                );
                let nested_scope = permit.scope().clone();
                let nested = dispatch_live_runtime(
                    &probe,
                    nested_scope,
                    &ConsentState::NotRequired,
                    None,
                    None,
                    now(),
                    move |_| {
                        observed_nested_calls.fetch_add(1, Ordering::SeqCst);
                        Ok::<_, &'static str>(())
                    },
                );
                assert_eq!(
                    nested.unwrap_err(),
                    AuthorityDispatchError::Cordis(Box::new(CordisError::RuntimeDispatchBusy))
                );
                observed_calls.fetch_add(1, Ordering::SeqCst);
                Ok::<_, &'static str>("application-runtime")
            },
        )
        .unwrap();

        assert_eq!(output, "application-runtime");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(nested_calls.load(Ordering::SeqCst), 0);
        let host = host.lock().unwrap();
        assert!(host.active_runtime_scope().is_none());
        assert!(
            host.context()
                .agents::<AgentsSurface>()
                .unwrap()
                .list()
                .is_empty()
        );
    }

    #[test]
    fn concurrent_same_scope_dispatch_runs_exactly_one_authority() {
        let host = Arc::new(Mutex::new(
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap(),
        ));
        let scope = AuthorityScope::new("tenant-a", "project-a", "mission-a", 4)
            .unwrap()
            .with_runtime(RuntimeBinding::new(2, None, None, "a".repeat(64)).unwrap());
        let calls = Arc::new(AtomicUsize::new(0));
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let first_host = Arc::clone(&host);
        let first_scope = scope.clone();
        let first_calls = Arc::clone(&calls);
        let first = thread::spawn(move || {
            dispatch_live_runtime(
                &first_host,
                first_scope,
                &ConsentState::NotRequired,
                None,
                None,
                now(),
                move |_| {
                    first_calls.fetch_add(1, Ordering::SeqCst);
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    Ok::<_, &'static str>("first")
                },
            )
        });
        entered_rx
            .recv_timeout(StdDuration::from_secs(2))
            .expect("first authority entered");

        let second_calls = Arc::clone(&calls);
        let second = dispatch_live_runtime(
            &host,
            scope,
            &ConsentState::NotRequired,
            None,
            None,
            now(),
            move |_| {
                second_calls.fetch_add(1, Ordering::SeqCst);
                Ok::<_, &'static str>("second")
            },
        );
        assert_eq!(
            second.unwrap_err(),
            AuthorityDispatchError::Cordis(Box::new(CordisError::RuntimeDispatchBusy))
        );
        let locked = host.lock().unwrap();
        assert_eq!(locked.successful_bindings(), 1);
        assert!(
            locked.last_binding().is_none(),
            "authorization consumes the only successful binding receipt"
        );
        drop(locked);
        release_tx.send(()).unwrap();
        assert_eq!(first.join().unwrap().unwrap(), "first");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn lifecycle_observers_reenter_only_after_host_unlock() {
        let host = Arc::new(Mutex::new(
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap(),
        ));
        let scope = AuthorityScope::new("tenant-a", "project-a", "mission-a", 4)
            .unwrap()
            .with_runtime(RuntimeBinding::new(2, None, None, "a".repeat(64)).unwrap());
        let started = Arc::new(AtomicUsize::new(0));
        let finished = Arc::new(AtomicUsize::new(0));
        {
            let started_host = Arc::clone(&host);
            let started_scope = scope.clone();
            let started_count = Arc::clone(&started);
            let finished_host = Arc::clone(&host);
            let finished_count = Arc::clone(&finished);
            let mut locked = host.lock().unwrap();
            locked
                .on_runtime_started(move |_| {
                    let nested = dispatch_live_runtime(
                        &started_host,
                        started_scope.clone(),
                        &ConsentState::NotRequired,
                        None,
                        None,
                        now(),
                        |_| Ok::<_, &'static str>(()),
                    );
                    assert_eq!(
                        nested.unwrap_err(),
                        AuthorityDispatchError::Cordis(Box::new(CordisError::RuntimeDispatchBusy))
                    );
                    started_count.fetch_add(1, Ordering::SeqCst);
                })
                .unwrap();
            locked
                .on_runtime_finished(move |_| {
                    assert!(
                        finished_host.try_lock().is_ok(),
                        "finished observer must run after host unlock"
                    );
                    finished_count.fetch_add(1, Ordering::SeqCst);
                })
                .unwrap();
        }

        dispatch_live_runtime(
            &host,
            scope,
            &ConsentState::NotRequired,
            None,
            None,
            now(),
            |_| Ok::<_, &'static str>(()),
        )
        .unwrap();
        assert_eq!(started.load(Ordering::SeqCst), 1);
        assert_eq!(finished.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn poisoned_host_fails_closed_without_calling_authority() {
        let host = Arc::new(Mutex::new(
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap(),
        ));
        let poison = Arc::clone(&host);
        let _ = thread::spawn(move || {
            let _locked = poison.lock().unwrap();
            panic!("poison Cordis coordinator for fail-closed test");
        })
        .join();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed_calls = Arc::clone(&calls);
        let scope = AuthorityScope::new("tenant-a", "project-a", "mission-a", 4)
            .unwrap()
            .with_runtime(RuntimeBinding::new(2, None, None, "a".repeat(64)).unwrap());
        let result = dispatch_live_runtime(
            &host,
            scope,
            &ConsentState::NotRequired,
            None,
            None,
            now(),
            move |_| {
                observed_calls.fetch_add(1, Ordering::SeqCst);
                Ok::<_, &'static str>(())
            },
        );
        assert_eq!(
            result.unwrap_err(),
            AuthorityDispatchError::Cordis(Box::new(CordisError::RuntimeCoordinatorPoisoned))
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn authority_panic_drops_permit_and_next_dispatch_can_recover() {
        let host = Arc::new(Mutex::new(
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap(),
        ));
        let scope = AuthorityScope::new("tenant-a", "project-a", "mission-a", 4)
            .unwrap()
            .with_runtime(RuntimeBinding::new(2, None, None, "a".repeat(64)).unwrap());
        let panic_host = Arc::clone(&host);
        let panic_scope = scope.clone();
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _ = dispatch_live_runtime(
                &panic_host,
                panic_scope,
                &ConsentState::NotRequired,
                None,
                None,
                now(),
                |_| -> Result<(), &'static str> { panic!("authority panic") },
            );
        }));
        assert!(panicked.is_err());
        assert!(
            host.lock()
                .unwrap()
                .context()
                .agents::<AgentsSurface>()
                .unwrap()
                .list()
                .is_empty()
        );
        dispatch_live_runtime(
            &host,
            scope,
            &ConsentState::NotRequired,
            None,
            None,
            now(),
            |_| Ok::<_, &'static str>(()),
        )
        .unwrap();
    }

    fn now() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 25, 13, 34, 33).unwrap()
    }

    fn granted_record(valid_until: chrono::DateTime<Utc>) -> ConsentRecord {
        ConsentRecord::grant(
            ConsentRecordId::from("consent-desktop"),
            TenantId::from("tenant-desktop"),
            ProjectId::from("project-desktop"),
            PersonId::from("person-desktop"),
            ConsentPurpose::DirectOutreach,
            ContactChannel::Email,
            "US",
            LegalBasis::ExplicitConsent,
            "signed desktop consent",
            "e".repeat(64),
            now(),
            Some(valid_until),
        )
        .expect("granted consent")
    }

    fn approved(valid_until: chrono::DateTime<Utc>) -> Approval {
        Approval {
            id: ApprovalId::from("approval-desktop"),
            decision: ApprovalDecision::Approved,
            decided_by: ActorId::from("user-desktop"),
            decided_at: now(),
            valid_until,
            scope_digest: "a".repeat(64),
            permission_digest: "b".repeat(64),
        }
    }

    #[test]
    fn production_desktop_surfaces_do_not_pre_grant_consent_or_approval() {
        for openinterpreter in [false, true] {
            let host = CordisHost::boot(openinterpreter).unwrap();
            let domain = host.context().domain::<DomainSurface>().unwrap();
            assert!(!domain.consent());
            assert!(!domain.approved());
            assert_eq!(domain.owner(), SurfaceOwner::Hartevo);
            assert!(domain.local_first());
            assert!(domain.sqlcipher());
            assert!(domain.eval_gate());
            assert!(
                !host
                    .context()
                    .effect_broker::<hartevo_cordis::EffectBrokerSurface>()
                    .unwrap()
                    .receipt_is_verification()
            );
        }
    }

    #[test]
    fn not_configured_runtime_does_not_name_openinterpreter_plugin() {
        assert!(!openinterpreter_runtime_plugin(&projection(
            DesktopRuntimeAvailabilityStatus::NotConfigured
        )));
        let host = mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
            .unwrap();
        assert_eq!(host.root_fiber().state(), FiberState::Active);
        assert!(!host.root_fiber().is_disposed());
        assert!(host.last_binding().is_none());
        host_is_cordis_loop(&host).unwrap();
        assert_eq!(host.runtime_plugin(), None);
        let domain = host.context().domain::<DomainSurface>().unwrap();
        assert_eq!(domain.owner(), SurfaceOwner::Hartevo);
        assert!(!domain.consent());
        assert!(!domain.approved());
        assert!(host.context().get::<String>(OPENINTERPRETER).is_none());
    }

    #[test]
    fn scoped_live_bindings_return_monotonic_root_fiber_receipts() {
        let mut host =
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap();
        let scope = runtime_scope();
        let first = bind_live_domain_kernel_scope(
            &mut host,
            scope.clone(),
            &ConsentState::Confirmed,
            None,
            Some(&approved(now() + Duration::minutes(5))),
            now(),
        )
        .unwrap();

        assert_eq!(first.scope(), &scope);
        assert_eq!(first.root_fiber_uid(), host.root_fiber().uid());
        assert_eq!(first.refresh_sequence(), 1);
        assert_eq!(host.last_binding().unwrap().scope.as_ref(), Some(&scope));

        let second = bind_live_domain_kernel_scope(
            &mut host,
            scope.clone(),
            &ConsentState::Missing,
            None,
            None,
            now(),
        )
        .unwrap();
        assert_eq!(second.root_fiber_uid(), first.root_fiber_uid());
        assert_eq!(second.refresh_sequence(), 2);
        let domain = host.context().domain::<DomainSurface>().unwrap();
        assert!(!domain.consent());
        assert!(!domain.approved());
        assert_eq!(
            host.authorize_bound_runtime(first).unwrap_err(),
            CordisError::AuthorityScopeMismatch,
            "an older receipt cannot authorize after a newer live binding"
        );
        assert_eq!(host.last_binding().unwrap().refresh_sequence, 2);
        let permit = host.authorize_bound_runtime(second).unwrap();
        assert!(host.last_binding().is_none());
        host.finish_runtime(permit).unwrap().announce().unwrap();
        assert_eq!(
            host.apply_effect().unwrap_err(),
            CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
        );
    }

    #[test]
    fn scoped_binding_receipt_cannot_cross_coordinators() {
        let mut first =
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap();
        let receipt = bind_live_domain_kernel_scope(
            &mut first,
            runtime_scope(),
            &ConsentState::Confirmed,
            None,
            Some(&approved(now() + Duration::minutes(5))),
            now(),
        )
        .unwrap();
        let mut second =
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap();

        assert_eq!(
            second.authorize_bound_runtime(receipt).unwrap_err(),
            CordisError::AuthorityScopeMismatch
        );
        assert_eq!(second.successful_bindings(), 0);
        assert!(second.last_binding().is_none());
    }

    #[test]
    fn ready_runtime_keeps_openinterpreter_as_optional_plugin_without_pre_grant() {
        let mut host = mount_cordis_host(&projection(
            DesktopRuntimeAvailabilityStatus::ReadyDevelopment,
        ))
        .unwrap();
        assert!(openinterpreter_runtime_plugin(&projection(
            DesktopRuntimeAvailabilityStatus::ReadyDevelopment
        )));
        host_is_cordis_loop(&host).unwrap();
        assert_eq!(host.runtime_plugin(), Some(OPENINTERPRETER));
        assert_eq!(
            host.context()
                .runtime::<hartevo_cordis::RuntimeSurface>()
                .unwrap()
                .owner(),
            SurfaceOwner::Hartevo
        );
        assert_eq!(
            enforce_invariants(host.context()).unwrap_err(),
            CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
        );
        assert_eq!(
            host.apply_effect().unwrap_err(),
            CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
        );
        bind_live_domain_kernel(
            &mut host,
            &ConsentState::Confirmed,
            None,
            Some(&approved(now() + Duration::minutes(5))),
            now(),
        )
        .unwrap();
        enforce_invariants(host.context()).unwrap();
        host.apply_effect().unwrap();
    }

    #[test]
    fn desktop_step_fails_closed_until_kernel_facts_are_bound() {
        let mut host = mount_cordis_host(&projection(
            DesktopRuntimeAvailabilityStatus::ReadyDistribution,
        ))
        .unwrap();
        host_is_cordis_loop(&host).unwrap();
        assert_eq!(
            host.step(AgentStep::new("mission-desktop", "plan"))
                .unwrap_err(),
            CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
        );
        bind_live_domain_kernel(&mut host, &ConsentState::Confirmed, None, None, now()).unwrap();
        assert_eq!(
            host.step(AgentStep::new("mission-desktop", "plan"))
                .unwrap_err(),
            CordisError::MissingDependencies(vec![invariant_missing::APPROVAL.to_string()])
        );
        bind_live_domain_kernel(
            &mut host,
            &ConsentState::Confirmed,
            None,
            Some(&approved(now() + Duration::minutes(5))),
            now(),
        )
        .unwrap();
        let out = host
            .step(AgentStep::new("mission-desktop", "plan"))
            .unwrap();
        assert_eq!(out.id, "mission-desktop");
        for key in [
            keys::TOOLS,
            keys::LLM,
            keys::AGENTS,
            keys::DOMAIN,
            keys::EFFECT_BROKER,
        ] {
            assert!(host.context().has(key), "{key} must stay mounted");
        }
    }

    fn denied_record() -> ConsentRecord {
        let denied = ConsentRecord {
            id: ConsentRecordId::from("consent-denied"),
            tenant_id: TenantId::from("tenant-desktop"),
            project_id: ProjectId::from("project-desktop"),
            person_id: PersonId::from("person-desktop"),
            purpose: ConsentPurpose::DirectOutreach,
            channel: ContactChannel::Email,
            market: "US".into(),
            legal_basis: LegalBasis::ExplicitConsent,
            status: ConsentStatus::Denied,
            source: "signed desktop consent".into(),
            evidence_digest: "e".repeat(64),
            granted_at: None,
            valid_until: None,
            withdrawn_at: None,
            revision: 1,
        };
        denied.validate().expect("denied record");
        denied
    }

    #[test]
    fn withdrawn_missing_denied_and_expired_consent_fail_closed() {
        let mut host =
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap();
        let mut withdrawn = granted_record(now() + Duration::days(30));
        withdrawn.withdraw(now() + Duration::hours(1)).unwrap();
        bind_live_domain_kernel(
            &mut host,
            &ConsentState::Withdrawn,
            Some(&withdrawn),
            Some(&approved(now() + Duration::minutes(5))),
            now() + Duration::hours(2),
        )
        .unwrap();
        assert_eq!(
            host.step(AgentStep::new("mission-withdrawn", "plan"))
                .unwrap_err(),
            CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
        );

        bind_live_domain_kernel(
            &mut host,
            &ConsentState::Missing,
            None,
            Some(&approved(now() + Duration::minutes(5))),
            now(),
        )
        .unwrap();
        assert_eq!(
            host.apply_effect().unwrap_err(),
            CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
        );

        let mut expired_record = granted_record(now() + Duration::seconds(1));
        expired_record
            .expire(now() + Duration::seconds(2))
            .expect("expire");
        bind_live_domain_kernel(
            &mut host,
            &ConsentState::NotRequired,
            Some(&expired_record),
            Some(&approved(now() + Duration::minutes(5))),
            now() + Duration::seconds(3),
        )
        .unwrap();
        assert_eq!(
            host.step(AgentStep::new("mission-expired-record", "plan"))
                .unwrap_err(),
            CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
        );

        let denied = denied_record();
        bind_live_domain_kernel(
            &mut host,
            &ConsentState::NotRequired,
            Some(&denied),
            Some(&approved(now() + Duration::minutes(5))),
            now(),
        )
        .unwrap();
        assert_eq!(
            host.apply_effect().unwrap_err(),
            CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
        );
    }

    #[test]
    fn expired_or_rejected_approval_fails_closed_and_granted_record_allows_step() {
        let mut host =
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap();
        bind_live_domain_kernel(
            &mut host,
            &ConsentState::Confirmed,
            None,
            Some(&approved(now() - Duration::seconds(1))),
            now(),
        )
        .unwrap();
        assert_eq!(
            host.step(AgentStep::new("mission-expired", "plan"))
                .unwrap_err(),
            CordisError::MissingDependencies(vec![invariant_missing::APPROVAL.to_string()])
        );

        bind_live_domain_kernel(
            &mut host,
            &ConsentState::Confirmed,
            None,
            Some(&Approval {
                id: ApprovalId::from("approval-rejected"),
                decision: ApprovalDecision::Rejected,
                decided_by: ActorId::from("user-desktop"),
                decided_at: now(),
                valid_until: now() + Duration::minutes(5),
                scope_digest: "a".repeat(64),
                permission_digest: "b".repeat(64),
            }),
            now(),
        )
        .unwrap();
        assert_eq!(
            host.step(AgentStep::new("mission-rejected", "plan"))
                .unwrap_err(),
            CordisError::MissingDependencies(vec![invariant_missing::APPROVAL.to_string()])
        );

        let live = granted_record(now() + Duration::days(30));
        assert_eq!(live.status, ConsentStatus::Granted);
        bind_live_domain_kernel(
            &mut host,
            &ConsentState::NotRequired,
            Some(&live),
            Some(&approved(now() + Duration::minutes(5))),
            now() + Duration::minutes(1),
        )
        .unwrap();
        host.step(AgentStep::new("mission-granted-record", "plan"))
            .unwrap();
    }
}

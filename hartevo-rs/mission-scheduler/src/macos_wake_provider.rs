//! Production macOS launchd wake registration for the Mission scheduler.
//!
//! This module is the native boundary for a typed Mission wake registration.
//! It owns no Mission dispatch, consumer acknowledgement, Runtime, Browser, or
//! Effect authority.  The recurring Mission scheduler remains the consumer;
//! this module only registers, cancels, queries, recovers, and cleans up one
//! exact wake binding.
//!
//! The native adapter is deliberately gated twice: an approved macOS host must
//! opt into the canary environment variable, and its signed executable must
//! expose a scheduler entitlement.  Contract tests use an injected mock
//! adapter only.  The ignored native canary reports `BLOCKED_ENV` when the
//! host, entitlement, executable, or launchd domain is unavailable.

use std::collections::BTreeMap;
use std::env;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use chrono::{DateTime, Datelike, Local, Timelike, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::plugin_invocation::MissionScope;
use crate::recurring_schedule::{
    MissionScheduleProviderError, MissionScheduleWakeProvider, ScheduleWakeReceipt,
    ScheduleWakeRequest,
};
use crate::scheduler_digest;

pub const MACOS_LAUNCHD_PROVIDER_VERSION: &str = "macos-launchd-wake-v1";
pub const NATIVE_CANARY_ENV: &str = "HARTEVO_RUN_NATIVE_SCHEDULER_CANARY";
pub const NATIVE_EXECUTABLE_ENV: &str = "HARTEVO_MACOS_SCHEDULER_EXECUTABLE";
pub const NATIVE_ENTITLEMENT_ENV: &str = "HARTEVO_MACOS_SCHEDULER_ENTITLEMENT_PROOF";
pub const NATIVE_DOMAIN_ENV: &str = "HARTEVO_MACOS_LAUNCHD_DOMAIN";

const MAX_PROVIDER_VERSION_BYTES: usize = 128;
const MAX_LABEL_BYTES: usize = 128;

/// The exact request sent to the native provider.  The embedded scheduler
/// request binds Project/Mission, schedule revision, provider epoch, lease
/// revision, clock epoch, plugin composition and invocation digests.  The
/// additional provider version/digest and generation fence the native
/// registration itself.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MacOsWakeRegistrationRequest {
    pub schedule: ScheduleWakeRequest,
    pub provider_version: String,
    pub provider_digest: String,
    pub generation: u64,
}

impl MacOsWakeRegistrationRequest {
    pub fn new(
        schedule: ScheduleWakeRequest,
        provider_version: impl Into<String>,
        provider_digest: impl Into<String>,
        generation: u64,
    ) -> Result<Self, MacOsWakeRegistrationError> {
        let request = Self {
            schedule,
            provider_version: provider_version.into(),
            provider_digest: provider_digest.into(),
            generation,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), MacOsWakeRegistrationError> {
        validate_schedule_request(&self.schedule)?;
        if !valid_version(&self.provider_version)
            || !valid_digest(&self.provider_digest)
            || self.generation == 0
        {
            return Err(MacOsWakeRegistrationError::InvalidRequest);
        }
        Ok(())
    }

    pub fn request_digest(&self) -> Result<String, MacOsWakeRegistrationError> {
        self.validate()?;
        serde_json::to_vec(self)
            .map(scheduler_digest)
            .map_err(|error| MacOsWakeRegistrationError::Serialization(error.to_string()))
    }

    pub fn registration_id_digest(&self) -> Result<String, MacOsWakeRegistrationError> {
        let request_digest = self.request_digest()?;
        let mut material = b"hartevo:macos-wake-registration:v1:".to_vec();
        material.extend_from_slice(request_digest.as_bytes());
        Ok(scheduler_digest(material))
    }

    pub fn launchd_label(&self) -> Result<String, MacOsWakeRegistrationError> {
        let id = self.registration_id_digest()?;
        Ok(format!("com.hartevo.scheduler.wake.{}", &id[..32]))
    }
}

/// Durable receipt for one native registration.  It is a registration
/// receipt, not a dispatch receipt and cannot authorize a Mission capability
/// or any external effect.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MacOsWakeRegistrationReceipt {
    pub registration_id_digest: String,
    pub request_digest: String,
    pub provider_id_digest: String,
    pub provider_version: String,
    pub provider_digest: String,
    pub provider_epoch: u64,
    pub generation: u64,
    pub scope: MissionScope,
    pub schedule_id_digest: String,
    pub schedule_revision: u64,
    pub lease_revision: u64,
    pub clock_epoch: u64,
    pub planned_at: DateTime<Utc>,
    pub armed_at: DateTime<Utc>,
    pub launchd_label: String,
    pub native_receipt_digest: String,
}

impl MacOsWakeRegistrationReceipt {
    fn from_native(
        request: &MacOsWakeRegistrationRequest,
        native: &MacOsNativeWakeRegistration,
        armed_at: DateTime<Utc>,
    ) -> Result<Self, MacOsWakeRegistrationError> {
        let receipt = Self {
            registration_id_digest: request.registration_id_digest()?,
            request_digest: request.request_digest()?,
            provider_id_digest: request.schedule.provider_id_digest.clone(),
            provider_version: request.provider_version.clone(),
            provider_digest: request.provider_digest.clone(),
            provider_epoch: request.schedule.provider_epoch,
            generation: request.generation,
            scope: request.schedule.scope.clone(),
            schedule_id_digest: request.schedule.schedule_id_digest.clone(),
            schedule_revision: request.schedule.schedule_revision,
            lease_revision: request.schedule.lease_revision,
            clock_epoch: request.schedule.clock_epoch,
            planned_at: request.schedule.planned_at,
            armed_at,
            launchd_label: native.label.clone(),
            native_receipt_digest: native.native_receipt_digest.clone(),
        };
        receipt.validate_for(request)?;
        Ok(receipt)
    }

    pub fn validate_for(
        &self,
        request: &MacOsWakeRegistrationRequest,
    ) -> Result<(), MacOsWakeRegistrationError> {
        request.validate()?;
        if !valid_digest(&self.registration_id_digest)
            || !valid_digest(&self.request_digest)
            || !valid_digest(&self.provider_id_digest)
            || !valid_version(&self.provider_version)
            || !valid_digest(&self.provider_digest)
            || self.provider_epoch == 0
            || self.generation == 0
            || !valid_digest(&self.schedule_id_digest)
            || self.schedule_revision == 0
            || self.lease_revision == 0
            || self.clock_epoch == 0
            || !valid_label(&self.launchd_label)
            || !valid_digest(&self.native_receipt_digest)
            || self.registration_id_digest != request.registration_id_digest()?
            || self.request_digest != request.request_digest()?
            || self.provider_id_digest != request.schedule.provider_id_digest
            || self.provider_version != request.provider_version
            || self.provider_digest != request.provider_digest
            || self.provider_epoch != request.schedule.provider_epoch
            || self.generation != request.generation
            || self.scope != request.schedule.scope
            || self.schedule_id_digest != request.schedule.schedule_id_digest
            || self.schedule_revision != request.schedule.schedule_revision
            || self.lease_revision != request.schedule.lease_revision
            || self.clock_epoch != request.schedule.clock_epoch
            || self.planned_at != request.schedule.planned_at
            || self.launchd_label != request.launchd_label()?
        {
            return Err(MacOsWakeRegistrationError::ReceiptConflict);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MacOsWakeRegistrationRecord {
    pub request: MacOsWakeRegistrationRequest,
    pub receipt: MacOsWakeRegistrationReceipt,
}

impl MacOsWakeRegistrationRecord {
    fn validate(&self) -> Result<(), MacOsWakeRegistrationError> {
        self.receipt.validate_for(&self.request)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MacOsWakeRegistrationUncertainty {
    pub operation: String,
    pub registration_id_digest: Option<String>,
    pub store_error: String,
    pub compensation_error: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MacOsWakeRegistrationSnapshot {
    pub registrations: Vec<MacOsWakeRegistrationRecord>,
    #[serde(default)]
    pub uncertainty: Option<MacOsWakeRegistrationUncertainty>,
}

pub trait MacOsWakeRegistrationStore: fmt::Debug {
    fn load(&self) -> Result<MacOsWakeRegistrationSnapshot, MacOsWakeRegistrationStoreError>;
    fn save(
        &mut self,
        snapshot: &MacOsWakeRegistrationSnapshot,
    ) -> Result<(), MacOsWakeRegistrationStoreError>;
}

#[derive(Clone, Debug, Default)]
pub struct MemoryMacOsWakeRegistrationStore {
    snapshot: MacOsWakeRegistrationSnapshot,
}

impl MemoryMacOsWakeRegistrationStore {
    pub fn snapshot(&self) -> &MacOsWakeRegistrationSnapshot {
        &self.snapshot
    }
}

impl MacOsWakeRegistrationStore for MemoryMacOsWakeRegistrationStore {
    fn load(&self) -> Result<MacOsWakeRegistrationSnapshot, MacOsWakeRegistrationStoreError> {
        Ok(self.snapshot.clone())
    }

    fn save(
        &mut self,
        snapshot: &MacOsWakeRegistrationSnapshot,
    ) -> Result<(), MacOsWakeRegistrationStoreError> {
        self.snapshot = snapshot.clone();
        Ok(())
    }
}

#[derive(Debug)]
pub struct SqliteMacOsWakeRegistrationStore {
    connection: Connection,
}

impl SqliteMacOsWakeRegistrationStore {
    pub fn open_in_memory() -> Result<Self, MacOsWakeRegistrationStoreError> {
        Self::new(Connection::open_in_memory().map_err(|error| sqlite_store_error(&error))?)
    }

    pub fn new(connection: Connection) -> Result<Self, MacOsWakeRegistrationStoreError> {
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS scheduler_macos_wake_registrations (
                    snapshot_id INTEGER PRIMARY KEY CHECK (snapshot_id = 1),
                    snapshot_json TEXT NOT NULL
                )",
            )
            .map_err(|error| sqlite_store_error(&error))?;
        Ok(Self { connection })
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }
}

impl MacOsWakeRegistrationStore for SqliteMacOsWakeRegistrationStore {
    fn load(&self) -> Result<MacOsWakeRegistrationSnapshot, MacOsWakeRegistrationStoreError> {
        let json = self
            .connection
            .query_row(
                "SELECT snapshot_json FROM scheduler_macos_wake_registrations
                 WHERE snapshot_id = 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| sqlite_store_error(&error))?;
        json.map_or_else(
            || Ok(MacOsWakeRegistrationSnapshot::default()),
            |value| {
                serde_json::from_str(&value).map_err(|error| {
                    MacOsWakeRegistrationStoreError::Serialization(error.to_string())
                })
            },
        )
    }

    fn save(
        &mut self,
        snapshot: &MacOsWakeRegistrationSnapshot,
    ) -> Result<(), MacOsWakeRegistrationStoreError> {
        let json = serde_json::to_string(snapshot)
            .map_err(|error| MacOsWakeRegistrationStoreError::Serialization(error.to_string()))?;
        self.connection
            .execute(
                "INSERT INTO scheduler_macos_wake_registrations(snapshot_id, snapshot_json)
                 VALUES (1, ?1)
                 ON CONFLICT(snapshot_id) DO UPDATE SET snapshot_json = excluded.snapshot_json",
                params![json],
            )
            .map_err(|error| sqlite_store_error(&error))?;
        Ok(())
    }
}

fn sqlite_store_error(error: &rusqlite::Error) -> MacOsWakeRegistrationStoreError {
    MacOsWakeRegistrationStoreError::Sqlite(error.to_string())
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum MacOsWakeRegistrationStoreError {
    #[error("macOS wake registration snapshot serialization failed: {0}")]
    Serialization(String),
    #[error("macOS wake registration snapshot is corrupt")]
    Corrupt,
    #[error("macOS wake registration SQLite store failed: {0}")]
    Sqlite(String),
    #[error("macOS wake registration store rejected a write")]
    WriteRejected,
}

/// Result returned by the native backend.  The backend digest is opaque to
/// the scheduler and is only used to prove that the durable receipt matches
/// the registration that was actually submitted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacOsNativeWakeRegistration {
    pub label: String,
    pub native_receipt_digest: String,
}

pub trait MacOsLaunchdBackend: fmt::Debug + Send {
    fn register_wake(
        &mut self,
        request: &MacOsWakeRegistrationRequest,
        label: &str,
    ) -> Result<MacOsNativeWakeRegistration, MacOsLaunchdError>;
    fn disarm_wake(
        &mut self,
        receipt: &MacOsWakeRegistrationReceipt,
    ) -> Result<(), MacOsLaunchdError>;
    fn recover_wake(
        &mut self,
        request: &MacOsWakeRegistrationRequest,
        receipt: &MacOsWakeRegistrationReceipt,
    ) -> Result<MacOsNativeWakeRegistration, MacOsLaunchdError> {
        self.register_wake(request, &receipt.launchd_label)
    }
}

/// Rust-owned provider metadata and launchd backend.  The backend is kept
/// separate so only this module can cross the native boundary while the
/// Mission scheduler consumes the typed registration service below.
#[derive(Debug)]
pub struct MacOsLaunchdWakeProvider<B> {
    provider_id_digest: String,
    provider_version: String,
    provider_digest: String,
    provider_epoch: u64,
    backend: B,
}

impl<B> MacOsLaunchdWakeProvider<B> {
    pub fn new(
        provider_id_digest: impl Into<String>,
        provider_version: impl Into<String>,
        provider_digest: impl Into<String>,
        provider_epoch: u64,
        backend: B,
    ) -> Result<Self, MacOsWakeRegistrationError> {
        let provider = Self {
            provider_id_digest: provider_id_digest.into(),
            provider_version: provider_version.into(),
            provider_digest: provider_digest.into(),
            provider_epoch,
            backend,
        };
        provider.validate_metadata()?;
        Ok(provider)
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    pub fn set_provider_epoch(
        &mut self,
        provider_epoch: u64,
    ) -> Result<(), MacOsWakeRegistrationError> {
        if provider_epoch == 0 || provider_epoch <= self.provider_epoch {
            return Err(MacOsWakeRegistrationError::ProviderEpochLost);
        }
        self.provider_epoch = provider_epoch;
        Ok(())
    }

    fn validate_metadata(&self) -> Result<(), MacOsWakeRegistrationError> {
        if !valid_digest(&self.provider_id_digest)
            || !valid_version(&self.provider_version)
            || !valid_digest(&self.provider_digest)
            || self.provider_epoch == 0
        {
            return Err(MacOsWakeRegistrationError::InvalidProvider);
        }
        Ok(())
    }
}

pub trait MacOsWakeProviderAdapter: fmt::Debug + Send {
    fn provider_id_digest(&self) -> &str;
    fn provider_version(&self) -> &str;
    fn provider_digest(&self) -> &str;
    fn provider_epoch(&self) -> u64;
    fn register_wake(
        &mut self,
        request: &MacOsWakeRegistrationRequest,
    ) -> Result<MacOsNativeWakeRegistration, MacOsLaunchdError>;
    fn disarm_wake(
        &mut self,
        receipt: &MacOsWakeRegistrationReceipt,
    ) -> Result<(), MacOsLaunchdError>;
    fn recover_wake(
        &mut self,
        request: &MacOsWakeRegistrationRequest,
        receipt: &MacOsWakeRegistrationReceipt,
    ) -> Result<MacOsNativeWakeRegistration, MacOsLaunchdError>;
}

impl<B> MacOsWakeProviderAdapter for MacOsLaunchdWakeProvider<B>
where
    B: MacOsLaunchdBackend,
{
    fn provider_id_digest(&self) -> &str {
        &self.provider_id_digest
    }

    fn provider_version(&self) -> &str {
        &self.provider_version
    }

    fn provider_digest(&self) -> &str {
        &self.provider_digest
    }

    fn provider_epoch(&self) -> u64 {
        self.provider_epoch
    }

    fn register_wake(
        &mut self,
        request: &MacOsWakeRegistrationRequest,
    ) -> Result<MacOsNativeWakeRegistration, MacOsLaunchdError> {
        let label = request
            .launchd_label()
            .map_err(|error| MacOsLaunchdError::Invalid(error.to_string()))?;
        let native = self.backend.register_wake(request, &label)?;
        if native.label != label || !valid_digest(&native.native_receipt_digest) {
            return Err(MacOsLaunchdError::Invalid(
                "native backend returned a conflicting registration receipt".to_owned(),
            ));
        }
        Ok(native)
    }

    fn disarm_wake(
        &mut self,
        receipt: &MacOsWakeRegistrationReceipt,
    ) -> Result<(), MacOsLaunchdError> {
        self.backend.disarm_wake(receipt)
    }

    fn recover_wake(
        &mut self,
        request: &MacOsWakeRegistrationRequest,
        receipt: &MacOsWakeRegistrationReceipt,
    ) -> Result<MacOsNativeWakeRegistration, MacOsLaunchdError> {
        let native = self.backend.recover_wake(request, receipt)?;
        if native.label != receipt.launchd_label || !valid_digest(&native.native_receipt_digest) {
            return Err(MacOsLaunchdError::Invalid(
                "native backend returned a conflicting recovery receipt".to_owned(),
            ));
        }
        Ok(native)
    }
}

/// Typed registration service consumed by the recurring Mission scheduler.
/// It is also the durable owner of native registration receipts, so a provider
/// arm is never reported as committed until its receipt is saved.
#[derive(Debug)]
pub struct MacOsMissionWakeRegistrationService<P, S = MemoryMacOsWakeRegistrationStore> {
    provider: P,
    store: S,
    registrations: BTreeMap<String, MacOsWakeRegistrationRecord>,
    uncertainty: Option<MacOsWakeRegistrationUncertainty>,
}

impl<P> MacOsMissionWakeRegistrationService<P, MemoryMacOsWakeRegistrationStore>
where
    P: MacOsWakeProviderAdapter,
{
    pub fn new(provider: P) -> Result<Self, MacOsWakeRegistrationError> {
        Self::with_store(provider, MemoryMacOsWakeRegistrationStore::default())
    }
}

impl<P, S> MacOsMissionWakeRegistrationService<P, S>
where
    P: MacOsWakeProviderAdapter,
    S: MacOsWakeRegistrationStore,
{
    pub fn with_store(provider: P, store: S) -> Result<Self, MacOsWakeRegistrationError> {
        let provider_id_digest = provider.provider_id_digest().to_owned();
        let provider_version = provider.provider_version().to_owned();
        let provider_digest = provider.provider_digest().to_owned();
        let snapshot = store.load().map_err(MacOsWakeRegistrationError::Store)?;
        let mut registrations = BTreeMap::new();
        for record in &snapshot.registrations {
            record.validate()?;
            if record.request.schedule.provider_id_digest != provider_id_digest
                || record.request.provider_version != provider_version
                || record.request.provider_digest != provider_digest
                || registrations
                    .insert(
                        record.receipt.registration_id_digest.clone(),
                        record.clone(),
                    )
                    .is_some()
            {
                return Err(MacOsWakeRegistrationError::ProviderIdentityMismatch);
            }
        }
        Ok(Self {
            provider,
            store,
            registrations,
            uncertainty: snapshot.uncertainty,
        })
    }

    pub fn provider(&self) -> &P {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut P {
        &mut self.provider
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    pub fn into_store(self) -> S {
        self.store
    }

    pub fn provider_id_digest(&self) -> &str {
        self.provider.provider_id_digest()
    }

    pub fn provider_version(&self) -> &str {
        self.provider.provider_version()
    }

    pub fn provider_digest(&self) -> &str {
        self.provider.provider_digest()
    }

    pub fn provider_epoch(&self) -> u64 {
        self.provider.provider_epoch()
    }

    pub fn snapshot(&self) -> MacOsWakeRegistrationSnapshot {
        MacOsWakeRegistrationSnapshot {
            registrations: self.registrations.values().cloned().collect(),
            uncertainty: self.uncertainty.clone(),
        }
    }

    pub fn uncertainty(&self) -> Option<&MacOsWakeRegistrationUncertainty> {
        self.uncertainty.as_ref()
    }

    pub fn query(&self, registration_id_digest: &str) -> Option<&MacOsWakeRegistrationRecord> {
        self.registrations.get(registration_id_digest)
    }

    pub fn registrations(&self) -> impl Iterator<Item = &MacOsWakeRegistrationRecord> {
        self.registrations.values()
    }

    pub fn register(
        &mut self,
        request: MacOsWakeRegistrationRequest,
        armed_at: DateTime<Utc>,
    ) -> Result<MacOsWakeRegistrationReceipt, MacOsWakeRegistrationError> {
        self.ensure_known()?;
        self.validate_provider_request(&request)?;
        let registration_id_digest = request.registration_id_digest()?;
        if let Some(existing) = self.registrations.get(&registration_id_digest) {
            if existing.request == request {
                return Ok(existing.receipt.clone());
            }
            return Err(MacOsWakeRegistrationError::RegistrationConflict);
        }
        let before = self.snapshot();
        let native = self
            .provider
            .register_wake(&request)
            .map_err(MacOsWakeRegistrationError::Native)?;
        let receipt = MacOsWakeRegistrationReceipt::from_native(&request, &native, armed_at)?;
        self.registrations.insert(
            registration_id_digest,
            MacOsWakeRegistrationRecord {
                request,
                receipt: receipt.clone(),
            },
        );
        self.persist_transition(
            &before,
            "register",
            Some(receipt.registration_id_digest.clone()),
        )?;
        Ok(receipt)
    }

    pub fn cancel(
        &mut self,
        registration_id_digest: &str,
        expected_generation: u64,
    ) -> Result<MacOsWakeRegistrationReceipt, MacOsWakeRegistrationError> {
        self.ensure_known()?;
        let record = self
            .registrations
            .get(registration_id_digest)
            .ok_or(MacOsWakeRegistrationError::RegistrationNotFound)?
            .clone();
        if record.request.generation != expected_generation {
            return Err(MacOsWakeRegistrationError::GenerationLost);
        }
        let before = self.snapshot();
        self.provider
            .disarm_wake(&record.receipt)
            .map_err(MacOsWakeRegistrationError::Native)?;
        self.registrations.remove(registration_id_digest);
        self.persist_transition(&before, "cancel", Some(registration_id_digest.to_owned()))?;
        Ok(record.receipt)
    }

    /// Re-registers the exact durable request after a process restart or a
    /// sleep transition that leaves the same provider epoch valid.  Provider
    /// epoch changes are intentionally rejected here; the recurring Mission
    /// scheduler must issue a new exact schedule request and generation.
    pub fn recover_after_restart(
        &mut self,
        recovered_at: DateTime<Utc>,
    ) -> Result<(), MacOsWakeRegistrationError> {
        self.ensure_known()?;
        let before = self.snapshot();
        let ids = self.registrations.keys().cloned().collect::<Vec<_>>();
        for id in ids {
            let current = self
                .registrations
                .get(&id)
                .ok_or(MacOsWakeRegistrationError::RegistrationNotFound)?
                .clone();
            if current.request.schedule.provider_epoch != self.provider.provider_epoch() {
                return Err(MacOsWakeRegistrationError::ProviderEpochLost);
            }
            let native = self
                .provider
                .recover_wake(&current.request, &current.receipt)
                .map_err(MacOsWakeRegistrationError::Native)?;
            let receipt =
                MacOsWakeRegistrationReceipt::from_native(&current.request, &native, recovered_at)?;
            self.registrations.insert(
                id,
                MacOsWakeRegistrationRecord {
                    request: current.request,
                    receipt,
                },
            );
        }
        self.persist_transition(&before, "recover_after_restart", None)
    }

    pub fn revoke(&mut self) -> Result<(), MacOsWakeRegistrationError> {
        self.cleanup("revoke")
    }

    pub fn unmount(&mut self) -> Result<(), MacOsWakeRegistrationError> {
        self.cleanup("unmount")
    }

    pub fn crash(&mut self) -> Result<(), MacOsWakeRegistrationError> {
        self.cleanup("crash")
    }

    /// Cleanup remains available while uncertain because it is restrictive
    /// recovery, not an automatic retry or a new registration.
    pub fn cleanup(&mut self, operation: &str) -> Result<(), MacOsWakeRegistrationError> {
        let before = self.snapshot();
        let records = self.registrations.values().cloned().collect::<Vec<_>>();
        for record in &records {
            if let Err(error) = self.provider.disarm_wake(&record.receipt) {
                return Err(self.enter_uncertainty(
                    operation,
                    "provider cleanup failed",
                    &error.to_string(),
                    Some(record.receipt.registration_id_digest.clone()),
                ));
            }
        }
        self.registrations.clear();
        self.uncertainty = None;
        self.persist_transition(&before, operation, None)
    }

    fn validate_provider_request(
        &self,
        request: &MacOsWakeRegistrationRequest,
    ) -> Result<(), MacOsWakeRegistrationError> {
        if request.schedule.provider_id_digest != self.provider.provider_id_digest()
            || request.provider_version != self.provider.provider_version()
            || request.provider_digest != self.provider.provider_digest()
            || request.schedule.provider_epoch != self.provider.provider_epoch()
        {
            return Err(MacOsWakeRegistrationError::ProviderIdentityMismatch);
        }
        Ok(())
    }

    fn ensure_known(&self) -> Result<(), MacOsWakeRegistrationError> {
        if let Some(uncertainty) = &self.uncertainty {
            return Err(MacOsWakeRegistrationError::Uncertain {
                operation: uncertainty.operation.clone(),
            });
        }
        Ok(())
    }

    fn restore_memory(&mut self, snapshot: &MacOsWakeRegistrationSnapshot) {
        self.registrations = snapshot
            .registrations
            .iter()
            .cloned()
            .map(|record| (record.receipt.registration_id_digest.clone(), record))
            .collect();
        self.uncertainty.clone_from(&snapshot.uncertainty);
    }

    fn compensate_provider(
        &mut self,
        before: &MacOsWakeRegistrationSnapshot,
        after: &MacOsWakeRegistrationSnapshot,
    ) -> Result<(), String> {
        let previous = before
            .registrations
            .iter()
            .map(|record| (record.receipt.registration_id_digest.clone(), record))
            .collect::<BTreeMap<_, _>>();
        let current = after
            .registrations
            .iter()
            .map(|record| (record.receipt.registration_id_digest.clone(), record))
            .collect::<BTreeMap<_, _>>();
        for (id, record) in &current {
            if previous.get(id) != Some(record) {
                self.provider
                    .disarm_wake(&record.receipt)
                    .map_err(|error| error.to_string())?;
            }
        }
        for (id, record) in &previous {
            if current.get(id) == Some(record) {
                continue;
            }
            let native = self
                .provider
                .recover_wake(&record.request, &record.receipt)
                .map_err(|error| error.to_string())?;
            if native.label != record.receipt.launchd_label
                || !valid_digest(&native.native_receipt_digest)
            {
                return Err("provider recovery returned a conflicting receipt".to_owned());
            }
        }
        Ok(())
    }

    fn persist_transition(
        &mut self,
        before: &MacOsWakeRegistrationSnapshot,
        operation: &str,
        registration_id_digest: Option<String>,
    ) -> Result<(), MacOsWakeRegistrationError> {
        let after = self.snapshot();
        match self.store.save(&after) {
            Ok(()) => Ok(()),
            Err(save_error) => {
                let save_message = save_error.to_string();
                match self.compensate_provider(before, &after) {
                    Ok(()) => match self.store.save(before) {
                        Ok(()) => {
                            self.restore_memory(before);
                            Err(MacOsWakeRegistrationError::Store(save_error))
                        }
                        Err(restore_error) => {
                            self.restore_memory(before);
                            Err(self.enter_uncertainty(
                                operation,
                                &save_message,
                                &format!("durable rollback failed: {restore_error}"),
                                registration_id_digest,
                            ))
                        }
                    },
                    Err(compensation_error) => Err(self.enter_uncertainty(
                        operation,
                        &save_message,
                        &compensation_error,
                        registration_id_digest,
                    )),
                }
            }
        }
    }

    fn enter_uncertainty(
        &mut self,
        operation: &str,
        store_error: &str,
        compensation_error: &str,
        registration_id_digest: Option<String>,
    ) -> MacOsWakeRegistrationError {
        self.uncertainty = Some(MacOsWakeRegistrationUncertainty {
            operation: operation.to_owned(),
            registration_id_digest,
            store_error: store_error.to_owned(),
            compensation_error: compensation_error.to_owned(),
        });
        let _ = self.store.save(&self.snapshot());
        MacOsWakeRegistrationError::Uncertain {
            operation: operation.to_owned(),
        }
    }
}

impl<P, S> MissionScheduleWakeProvider for MacOsMissionWakeRegistrationService<P, S>
where
    P: MacOsWakeProviderAdapter,
    S: MacOsWakeRegistrationStore,
{
    fn provider_id_digest(&self) -> &str {
        self.provider.provider_id_digest()
    }

    fn provider_epoch(&self) -> u64 {
        self.provider.provider_epoch()
    }

    fn arm_wake(
        &mut self,
        request: &ScheduleWakeRequest,
    ) -> Result<ScheduleWakeReceipt, MissionScheduleProviderError> {
        let registration = MacOsWakeRegistrationRequest::new(
            request.clone(),
            self.provider.provider_version().to_owned(),
            self.provider.provider_digest().to_owned(),
            request.lease_revision,
        )
        .map_err(|error| map_registration_error(&error))?;
        let receipt = self
            .register(registration, request.planned_at)
            .map_err(|error| map_registration_error(&error))?;
        Ok(ScheduleWakeReceipt {
            token_digest: request.token_digest.clone(),
            provider_id_digest: receipt.provider_id_digest,
            provider_epoch: receipt.provider_epoch,
            woke_at: request.planned_at,
        })
    }

    fn disarm_wake(
        &mut self,
        receipt: &ScheduleWakeReceipt,
    ) -> Result<(), MissionScheduleProviderError> {
        let record = self
            .registrations
            .values()
            .find(|record| {
                record.request.schedule.token_digest == receipt.token_digest
                    && record.receipt.provider_id_digest == receipt.provider_id_digest
                    && record.receipt.provider_epoch == receipt.provider_epoch
            })
            .cloned()
            .ok_or(MissionScheduleProviderError::ReceiptConflict)?;
        self.cancel(
            &record.receipt.registration_id_digest,
            record.request.generation,
        )
        .map_err(|error| map_registration_error(&error))?;
        Ok(())
    }
}

fn map_registration_error(error: &MacOsWakeRegistrationError) -> MissionScheduleProviderError {
    match error {
        MacOsWakeRegistrationError::ProviderEpochLost => MissionScheduleProviderError::EpochLost,
        MacOsWakeRegistrationError::ReceiptConflict
        | MacOsWakeRegistrationError::RegistrationConflict => {
            MissionScheduleProviderError::ReceiptConflict
        }
        MacOsWakeRegistrationError::Native(MacOsLaunchdError::BlockedEnv(_)) => {
            MissionScheduleProviderError::Unavailable
        }
        MacOsWakeRegistrationError::Uncertain { .. }
        | MacOsWakeRegistrationError::Store(_)
        | MacOsWakeRegistrationError::Native(_)
        | MacOsWakeRegistrationError::InvalidRequest
        | MacOsWakeRegistrationError::InvalidProvider
        | MacOsWakeRegistrationError::ProviderIdentityMismatch
        | MacOsWakeRegistrationError::RegistrationNotFound
        | MacOsWakeRegistrationError::GenerationLost
        | MacOsWakeRegistrationError::Serialization(_) => MissionScheduleProviderError::Backend,
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum MacOsWakeRegistrationError {
    #[error("macOS wake registration request is invalid")]
    InvalidRequest,
    #[error("macOS wake provider metadata is invalid")]
    InvalidProvider,
    #[error("macOS wake provider identity or version does not match the durable request")]
    ProviderIdentityMismatch,
    #[error("macOS wake provider epoch is stale")]
    ProviderEpochLost,
    #[error("macOS wake registration conflicts with an exact existing registration")]
    RegistrationConflict,
    #[error("macOS wake registration was not found")]
    RegistrationNotFound,
    #[error("macOS wake registration generation is stale")]
    GenerationLost,
    #[error("macOS wake registration receipt conflicts with its request")]
    ReceiptConflict,
    #[error("macOS wake registration state is uncertain; automatic retry is disabled: {operation}")]
    Uncertain { operation: String },
    #[error("macOS wake registration store failed: {0}")]
    Store(#[from] MacOsWakeRegistrationStoreError),
    #[error("macOS launchd backend failed: {0}")]
    Native(#[from] MacOsLaunchdError),
    #[error("macOS wake registration serialization failed: {0}")]
    Serialization(String),
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum MacOsLaunchdError {
    #[error("BLOCKED_ENV: {0}")]
    BlockedEnv(String),
    #[error("macOS launchd request is invalid: {0}")]
    Invalid(String),
    #[error("macOS launchd command or filesystem backend failed: {0}")]
    Backend(String),
    #[error("macOS launchd plist serialization failed: {0}")]
    Serialization(String),
}

/// Bounded launchd contract rendered by the native backend.  Tests can prove
/// the exact label, digest, and calendar fence without invoking launchctl.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacOsLaunchdJobSpec {
    pub label: String,
    pub executable: PathBuf,
    pub registration_id_digest: String,
    pub planned_at: DateTime<Utc>,
}

impl MacOsLaunchdJobSpec {
    pub fn new(
        label: impl Into<String>,
        executable: impl Into<PathBuf>,
        registration_id_digest: impl Into<String>,
        planned_at: DateTime<Utc>,
    ) -> Result<Self, MacOsLaunchdError> {
        let spec = Self {
            label: label.into(),
            executable: executable.into(),
            registration_id_digest: registration_id_digest.into(),
            planned_at,
        };
        spec.validate()?;
        Ok(spec)
    }

    pub fn validate(&self) -> Result<(), MacOsLaunchdError> {
        if !valid_label(&self.label)
            || !self.executable.is_absolute()
            || !self.executable.to_string_lossy().is_ascii()
            || !valid_digest(&self.registration_id_digest)
            || self.planned_at.second() != 0
        {
            return Err(MacOsLaunchdError::Invalid(
                "launchd requires an absolute executable, digest label and minute precision"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    pub fn render_plist(&self) -> Result<String, MacOsLaunchdError> {
        self.validate()?;
        let executable = xml_escape(&self.executable.to_string_lossy());
        let label = xml_escape(&self.label);
        let registration_id = xml_escape(&self.registration_id_digest);
        let local = self.planned_at.with_timezone(&Local);
        Ok(format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\"><dict>\n\
<key>Label</key><string>{label}</string>\n\
<key>ProgramArguments</key><array><string>{executable}</string>\
<string>--hartevo-scheduler-wake</string><string>{registration_id}</string></array>\n\
<key>StartCalendarInterval</key><dict><key>Year</key><integer>{}</integer>\
<key>Month</key><integer>{}</integer><key>Day</key><integer>{}</integer>\
<key>Hour</key><integer>{}</integer><key>Minute</key><integer>{}</integer></dict>\n\
<key>ProcessType</key><string>Background</string>\n\
<key>LowPriorityIO</key><true/><key>RunAtLoad</key><false/>\n\
<key>WakeOnDemand</key><true/>\n\
</dict></plist>\n",
            local.year(),
            local.month(),
            local.day(),
            local.hour(),
            local.minute(),
        ))
    }
}

/// Native launchd backend.  Construction and every registration re-check the
/// explicit canary/entitlement gate.  Disarm uses the host checks only so a
/// previously registered job can still be collected after the canary window.
#[derive(Debug)]
pub struct NativeMacOsLaunchdBackend {
    launchctl: PathBuf,
    codesign: PathBuf,
    domain: String,
    launch_agents_dir: PathBuf,
    executable: PathBuf,
}

impl NativeMacOsLaunchdBackend {
    pub fn from_environment() -> Result<Self, MacOsLaunchdError> {
        Self::require_native_host()?;
        Self::require_canary_gate()?;
        let home = env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| MacOsLaunchdError::BlockedEnv("HOME is unavailable".to_owned()))?;
        let executable = env::var_os(NATIVE_EXECUTABLE_ENV)
            .map(PathBuf::from)
            .ok_or_else(|| {
                MacOsLaunchdError::BlockedEnv(format!(
                    "set {NATIVE_EXECUTABLE_ENV} to the approved signed host"
                ))
            })?;
        let domain = env::var(NATIVE_DOMAIN_ENV).map_err(|_| {
            MacOsLaunchdError::BlockedEnv(format!(
                "set {NATIVE_DOMAIN_ENV} to the logged-in gui/<uid> domain"
            ))
        })?;
        if !valid_launchd_domain(&domain) {
            return Err(MacOsLaunchdError::BlockedEnv(format!(
                "{NATIVE_DOMAIN_ENV} must be gui/<uid>"
            )));
        }
        let backend = Self {
            launchctl: PathBuf::from("/bin/launchctl"),
            codesign: PathBuf::from("/usr/bin/codesign"),
            domain,
            launch_agents_dir: home.join("Library/LaunchAgents"),
            executable,
        };
        backend.validate_paths()?;
        backend.validate_entitlement()?;
        Ok(backend)
    }

    fn require_native_host() -> Result<(), MacOsLaunchdError> {
        if !cfg!(target_os = "macos") {
            return Err(MacOsLaunchdError::BlockedEnv(
                "a macOS runner is required for native launchd registration".to_owned(),
            ));
        }
        Ok(())
    }

    fn require_canary_gate() -> Result<(), MacOsLaunchdError> {
        if env::var(NATIVE_CANARY_ENV).as_deref() != Ok("1") {
            return Err(MacOsLaunchdError::BlockedEnv(format!(
                "set {NATIVE_CANARY_ENV}=1 on an approved canary host"
            )));
        }
        if env::var(NATIVE_ENTITLEMENT_ENV).as_deref() != Ok("1") {
            return Err(MacOsLaunchdError::BlockedEnv(format!(
                "set {NATIVE_ENTITLEMENT_ENV}=1 only after entitlement review"
            )));
        }
        Ok(())
    }

    fn validate_paths(&self) -> Result<(), MacOsLaunchdError> {
        if !self.launchctl.is_file()
            || !self.codesign.is_file()
            || !self.executable.is_absolute()
            || !self.executable.is_file()
        {
            return Err(MacOsLaunchdError::BlockedEnv(
                "launchctl, codesign, or approved executable is unavailable".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_disarm_paths(&self) -> Result<(), MacOsLaunchdError> {
        if !self.launchctl.is_file() {
            return Err(MacOsLaunchdError::BlockedEnv(
                "launchctl is unavailable for wake cleanup".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_entitlement(&self) -> Result<(), MacOsLaunchdError> {
        let output = Command::new(&self.codesign)
            .args([
                "-d",
                "--entitlements",
                ":-",
                self.executable.to_string_lossy().as_ref(),
            ])
            .output()
            .map_err(|error| MacOsLaunchdError::Backend(error.to_string()))?;
        if !output.status.success() {
            return Err(MacOsLaunchdError::BlockedEnv(
                "codesign entitlement inspection failed".to_owned(),
            ));
        }
        let mut metadata = output.stdout;
        metadata.extend_from_slice(&output.stderr);
        let text = String::from_utf8_lossy(&metadata);
        if !text.contains("com.apple.security.app-sandbox")
            && !text.contains("com.apple.security.application-groups")
        {
            return Err(MacOsLaunchdError::BlockedEnv(
                "approved scheduler entitlement is absent".to_owned(),
            ));
        }
        Ok(())
    }

    fn launchd_job_path(&self, label: &str) -> Result<PathBuf, MacOsLaunchdError> {
        if !valid_label(label) {
            return Err(MacOsLaunchdError::Invalid(
                "invalid launchd label".to_owned(),
            ));
        }
        Ok(self.launch_agents_dir.join(format!("{label}.plist")))
    }

    fn run_launchctl<I, T>(&self, args: I) -> Result<std::process::Output, MacOsLaunchdError>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<std::ffi::OsStr>,
    {
        Command::new(&self.launchctl)
            .args(args)
            .output()
            .map_err(|error| MacOsLaunchdError::Backend(error.to_string()))
    }

    fn disarm_best_effort(&self, label: &str) -> Result<(), MacOsLaunchdError> {
        let target = format!("{}/{}", self.domain, label);
        let output = self.run_launchctl(["bootout", target.as_str()])?;
        if !output.status.success() {
            let text = String::from_utf8_lossy(&output.stderr);
            if !text.contains("Could not find service")
                && !text.contains("No such process")
                && !text.contains("not found")
            {
                return Err(MacOsLaunchdError::Backend(text.into_owned()));
            }
        }
        Ok(())
    }
}

impl MacOsLaunchdBackend for NativeMacOsLaunchdBackend {
    fn register_wake(
        &mut self,
        request: &MacOsWakeRegistrationRequest,
        label: &str,
    ) -> Result<MacOsNativeWakeRegistration, MacOsLaunchdError> {
        Self::require_native_host()?;
        Self::require_canary_gate()?;
        self.validate_paths()?;
        self.validate_entitlement()?;
        let spec = MacOsLaunchdJobSpec::new(
            label,
            self.executable.clone(),
            request
                .registration_id_digest()
                .map_err(|error| MacOsLaunchdError::Invalid(error.to_string()))?,
            request.schedule.planned_at,
        )?;
        let plist = spec.render_plist()?;
        let plist_digest = scheduler_digest(plist.as_bytes());
        let path = self.launchd_job_path(label)?;
        fs::create_dir_all(&self.launch_agents_dir)
            .map_err(|error| MacOsLaunchdError::Backend(error.to_string()))?;

        if path.is_file() {
            let existing = fs::read_to_string(&path)
                .map_err(|error| MacOsLaunchdError::Backend(error.to_string()))?;
            let target = format!("{}/{}", self.domain, label);
            let loaded = self.run_launchctl(["print", target.as_str()])?;
            if existing == plist && loaded.status.success() {
                return Ok(MacOsNativeWakeRegistration {
                    label: label.to_owned(),
                    native_receipt_digest: scheduler_digest(
                        format!("{label}:{plist_digest}").as_bytes(),
                    ),
                });
            }
            self.disarm_best_effort(label)?;
            fs::remove_file(&path)
                .map_err(|error| MacOsLaunchdError::Backend(error.to_string()))?;
        }

        let temporary = path.with_extension("plist.tmp");
        fs::write(&temporary, plist)
            .map_err(|error| MacOsLaunchdError::Backend(error.to_string()))?;
        fs::rename(&temporary, &path)
            .map_err(|error| MacOsLaunchdError::Backend(error.to_string()))?;
        let path_string = path.to_string_lossy().into_owned();
        let target = self.run_launchctl(["bootstrap", &self.domain, &path_string])?;
        if !target.status.success() {
            let text = String::from_utf8_lossy(&target.stderr).into_owned();
            let _ = fs::remove_file(&path);
            return Err(MacOsLaunchdError::Backend(text));
        }
        Ok(MacOsNativeWakeRegistration {
            label: label.to_owned(),
            native_receipt_digest: scheduler_digest(format!("{label}:{plist_digest}").as_bytes()),
        })
    }

    fn disarm_wake(
        &mut self,
        receipt: &MacOsWakeRegistrationReceipt,
    ) -> Result<(), MacOsLaunchdError> {
        Self::require_native_host()?;
        self.validate_disarm_paths()?;
        self.disarm_best_effort(&receipt.launchd_label)?;
        let path = self.launchd_job_path(&receipt.launchd_label)?;
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(MacOsLaunchdError::Backend(error.to_string())),
        }
    }
}

fn validate_schedule_request(
    request: &ScheduleWakeRequest,
) -> Result<(), MacOsWakeRegistrationError> {
    if !valid_digest(&request.token_digest)
        || !valid_digest(&request.schedule_id_digest)
        || !valid_digest(&request.objective_digest)
        || !valid_digest(&request.timezone_digest)
        || !valid_digest(&request.recurrence_digest)
        || !valid_digest(&request.composition_digest)
        || !valid_digest(&request.invocation_digest)
        || !valid_digest(&request.provider_id_digest)
        || request.schedule_revision == 0
        || request.provider_epoch == 0
        || request.lease_revision == 0
        || request.clock_epoch == 0
        || request.planned_at >= request.contract_valid_until
    {
        return Err(MacOsWakeRegistrationError::InvalidRequest);
    }
    request
        .scope
        .validate()
        .map_err(|_| MacOsWakeRegistrationError::InvalidRequest)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PROVIDER_VERSION_BYTES
        && value
            .bytes()
            .all(|byte| !byte.is_ascii_control() && byte != 0)
}

fn valid_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_LABEL_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn valid_launchd_domain(value: &str) -> bool {
    value
        .strip_prefix("gui/")
        .is_some_and(|uid| !uid.is_empty() && uid.bytes().all(|byte| byte.is_ascii_digit()))
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin_invocation::MissionScope;
    use chrono::{Duration, TimeZone};
    use hartevo_cloud_storage::DataCell;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 14, 12, 0, 0)
            .single()
            .expect("valid test time")
    }

    fn digest(byte: u8) -> String {
        scheduler_digest([byte])
    }

    fn request(schedule_byte: u8, generation: u64) -> MacOsWakeRegistrationRequest {
        let scope = MissionScope::new(
            DataCell::Us,
            "tenant-macos",
            "project-macos",
            "mission-macos",
            7,
        )
        .expect("scope");
        let schedule = ScheduleWakeRequest {
            token_digest: digest(schedule_byte),
            schedule_id_digest: digest(schedule_byte.wrapping_add(1)),
            objective_digest: digest(b'o'),
            scope,
            schedule_revision: generation,
            planned_at: now() + Duration::minutes(10),
            contract_valid_until: now() + Duration::hours(1),
            timezone_digest: digest(b't'),
            recurrence_digest: digest(b'r'),
            composition_digest: digest(b'c'),
            invocation_digest: digest(b'i'),
            provider_id_digest: digest(b'p'),
            provider_epoch: 1,
            lease_revision: generation,
            clock_epoch: 1,
        };
        MacOsWakeRegistrationRequest::new(
            schedule,
            MACOS_LAUNCHD_PROVIDER_VERSION,
            digest(b'v'),
            generation,
        )
        .expect("registration request")
    }

    #[derive(Debug, Default)]
    struct RecordingBackend {
        armed: BTreeMap<String, MacOsNativeWakeRegistration>,
        arm_calls: usize,
        disarm_calls: usize,
        fail_disarm: bool,
    }

    impl MacOsLaunchdBackend for RecordingBackend {
        fn register_wake(
            &mut self,
            request: &MacOsWakeRegistrationRequest,
            label: &str,
        ) -> Result<MacOsNativeWakeRegistration, MacOsLaunchdError> {
            let id = request
                .registration_id_digest()
                .map_err(|error| MacOsLaunchdError::Invalid(error.to_string()))?;
            if let Some(existing) = self.armed.get(&id) {
                return Ok(existing.clone());
            }
            self.arm_calls += 1;
            let native = MacOsNativeWakeRegistration {
                label: label.to_owned(),
                native_receipt_digest: digest(
                    u8::try_from(self.arm_calls).expect("test backend call count fits in one byte"),
                ),
            };
            self.armed.insert(id, native.clone());
            Ok(native)
        }

        fn disarm_wake(
            &mut self,
            receipt: &MacOsWakeRegistrationReceipt,
        ) -> Result<(), MacOsLaunchdError> {
            self.disarm_calls += 1;
            if self.fail_disarm {
                return Err(MacOsLaunchdError::Backend("disarm rejected".to_owned()));
            }
            self.armed
                .retain(|_, native| native.label != receipt.launchd_label);
            Ok(())
        }
    }

    #[derive(Debug)]
    struct FailOnceStore {
        snapshot: MacOsWakeRegistrationSnapshot,
        saves: usize,
        fail_at: usize,
    }

    impl FailOnceStore {
        fn new(fail_at: usize) -> Self {
            Self {
                snapshot: MacOsWakeRegistrationSnapshot::default(),
                saves: 0,
                fail_at,
            }
        }
    }

    impl MacOsWakeRegistrationStore for FailOnceStore {
        fn load(&self) -> Result<MacOsWakeRegistrationSnapshot, MacOsWakeRegistrationStoreError> {
            Ok(self.snapshot.clone())
        }

        fn save(
            &mut self,
            snapshot: &MacOsWakeRegistrationSnapshot,
        ) -> Result<(), MacOsWakeRegistrationStoreError> {
            self.saves += 1;
            if self.saves == self.fail_at {
                return Err(MacOsWakeRegistrationStoreError::WriteRejected);
            }
            self.snapshot = snapshot.clone();
            Ok(())
        }
    }

    fn provider(backend: RecordingBackend) -> MacOsLaunchdWakeProvider<RecordingBackend> {
        MacOsLaunchdWakeProvider::new(
            digest(b'p'),
            MACOS_LAUNCHD_PROVIDER_VERSION,
            digest(b'v'),
            1,
            backend,
        )
        .expect("provider")
    }

    #[test]
    fn exact_registration_is_idempotent_queryable_and_cancelable() {
        let mut service =
            MacOsMissionWakeRegistrationService::new(provider(RecordingBackend::default()))
                .expect("service");
        let registration = request(b'a', 1);
        let first = service
            .register(registration.clone(), now())
            .expect("register");
        let second = service
            .register(registration, now() + Duration::seconds(1))
            .expect("exact replay");
        assert_eq!(first, second);
        assert_eq!(service.provider().backend().arm_calls, 1);
        assert_eq!(first.scope.mission_id, "mission-macos");
        assert_eq!(first.generation, 1);
        assert_eq!(first.provider_version, MACOS_LAUNCHD_PROVIDER_VERSION);
        assert_eq!(
            service
                .query(&first.registration_id_digest)
                .expect("query")
                .receipt,
            first
        );
        service
            .cancel(&first.registration_id_digest, 1)
            .expect("cancel");
        assert!(service.query(&first.registration_id_digest).is_none());
        assert_eq!(service.provider().backend().disarm_calls, 1);
    }

    #[test]
    fn rejected_save_disarms_native_registration_and_retry_has_one_binding() {
        let mut service = MacOsMissionWakeRegistrationService::with_store(
            provider(RecordingBackend::default()),
            FailOnceStore::new(1),
        )
        .expect("service");
        let registration = request(b'b', 1);
        assert_eq!(
            service.register(registration.clone(), now()),
            Err(MacOsWakeRegistrationError::Store(
                MacOsWakeRegistrationStoreError::WriteRejected,
            ))
        );
        assert!(service.provider().backend().armed.is_empty());
        assert!(
            service
                .query(&registration.registration_id_digest().expect("id"))
                .is_none()
        );
        service.register(registration, now()).expect("retry");
        assert_eq!(service.provider().backend().armed.len(), 1);
        assert_eq!(service.provider().backend().arm_calls, 2);
    }

    #[test]
    fn compensation_failure_is_uncertain_and_blocks_automatic_replay() {
        let backend = RecordingBackend {
            fail_disarm: true,
            ..RecordingBackend::default()
        };
        let mut service = MacOsMissionWakeRegistrationService::with_store(
            provider(backend),
            FailOnceStore::new(1),
        )
        .expect("service");
        let registration = request(b'c', 1);
        assert_eq!(
            service.register(registration.clone(), now()),
            Err(MacOsWakeRegistrationError::Uncertain {
                operation: "register".to_owned(),
            })
        );
        assert!(service.uncertainty().is_some());
        assert_eq!(service.provider().backend().arm_calls, 1);
        assert_eq!(
            service.register(registration, now()),
            Err(MacOsWakeRegistrationError::Uncertain {
                operation: "register".to_owned(),
            })
        );
        assert_eq!(service.provider().backend().arm_calls, 1);
    }

    #[test]
    fn sqlite_restart_recovers_exact_registration_without_duplicate_arm() {
        let store = SqliteMacOsWakeRegistrationStore::open_in_memory().expect("sqlite");
        let registration = request(b'd', 2);
        let (receipt, store) = {
            let mut service = MacOsMissionWakeRegistrationService::with_store(
                provider(RecordingBackend::default()),
                store,
            )
            .expect("service");
            let receipt = service
                .register(registration.clone(), now())
                .expect("register");
            (receipt, service.into_store())
        };
        let mut restarted = MacOsMissionWakeRegistrationService::with_store(
            provider(RecordingBackend::default()),
            store,
        )
        .expect("restart");
        restarted
            .recover_after_restart(now() + Duration::minutes(1))
            .expect("recover");
        restarted
            .recover_after_restart(now() + Duration::minutes(2))
            .expect("idempotent recover");
        let recovered = restarted
            .query(&receipt.registration_id_digest)
            .expect("recovered");
        assert_eq!(recovered.request, registration);
        assert_eq!(restarted.provider().backend().arm_calls, 1);
        assert_eq!(restarted.provider().backend().armed.len(), 1);
    }

    #[test]
    fn revoke_unmount_and_crash_are_full_registration_cleanup_contracts() {
        for cleanup in ["revoke", "unmount", "crash"] {
            let mut service =
                MacOsMissionWakeRegistrationService::new(provider(RecordingBackend::default()))
                    .expect("service");
            let registration = request(cleanup.as_bytes()[0], 1);
            let receipt = service.register(registration, now()).expect("register");
            match cleanup {
                "revoke" => service.revoke().expect("revoke"),
                "unmount" => service.unmount().expect("unmount"),
                "crash" => service.crash().expect("crash"),
                _ => unreachable!(),
            }
            assert!(service.query(&receipt.registration_id_digest).is_none());
            assert!(service.registrations().next().is_none());
        }
    }

    #[test]
    fn launchd_plist_is_bounded_to_exact_registration_and_calendar() {
        let registration = request(b'e', 3);
        let label = registration.launchd_label().expect("label");
        let spec = MacOsLaunchdJobSpec::new(
            label.clone(),
            "/Applications/Hartevo.app/Contents/MacOS/Hartevo",
            registration.registration_id_digest().expect("id"),
            registration.schedule.planned_at,
        )
        .expect("spec");
        let plist = spec.render_plist().expect("plist");
        assert!(plist.contains(&format!("<string>{label}</string>")));
        assert!(plist.contains("<key>StartCalendarInterval</key>"));
        assert!(plist.contains("--hartevo-scheduler-wake"));
        assert!(!plist.contains("Runtime"));
        assert!(!plist.contains("Effect"));
    }

    #[test]
    fn native_canary_is_blocked_without_a_real_macos_environment() {
        if !cfg!(target_os = "macos") {
            assert!(matches!(
                NativeMacOsLaunchdBackend::from_environment(),
                Err(MacOsLaunchdError::BlockedEnv(_))
            ));
        }
    }

    #[test]
    #[ignore = "requires approved signed macOS host, launchd entitlement and explicit canary env"]
    fn native_launchd_canary_registers_and_fully_reclaims_one_wake() {
        let backend = match NativeMacOsLaunchdBackend::from_environment() {
            Ok(backend) => backend,
            Err(MacOsLaunchdError::BlockedEnv(reason)) => {
                eprintln!("BLOCKED_ENV: {reason}");
                return;
            }
            Err(error) => panic!("native preflight failed: {error}"),
        };
        let provider = MacOsLaunchdWakeProvider::new(
            digest(b'p'),
            MACOS_LAUNCHD_PROVIDER_VERSION,
            digest(b'v'),
            1,
            backend,
        )
        .expect("provider");
        let mut service = MacOsMissionWakeRegistrationService::new(provider).expect("service");
        let receipt = service
            .register(request(b'n', 1), Utc::now())
            .expect("native register");
        service.revoke().expect("native cleanup");
        assert!(service.query(&receipt.registration_id_digest).is_none());
    }
}

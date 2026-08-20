//! OS power lifecycle boundary for a future scheduler integration.
//!
//! The scheduler does not call `pmset`, launchd, IOKit, or an Application
//! service directly. A platform adapter receives a typed, digest-bound wake
//! request and reports sleep/resume observations. The macOS implementation is
//! intentionally backend-injected here; native integration can land in a
//! separate PR without changing scheduler state transitions.

use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::scheduler_digest;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WakeRequest {
    pub schedule_id_digest: String,
    pub wake_at: DateTime<Utc>,
    pub contract_valid_until: DateTime<Utc>,
    pub coalesced_ticks: u64,
    pub lease_generation: u64,
}

impl WakeRequest {
    pub fn validate(&self) -> Result<(), WakeSleepError> {
        if !is_digest(&self.schedule_id_digest)
            || self.coalesced_ticks == 0
            || self.lease_generation == 0
            || self.wake_at >= self.contract_valid_until
        {
            return Err(WakeSleepError::InvalidRequest);
        }
        Ok(())
    }

    pub fn request_digest(&self) -> Result<String, WakeSleepError> {
        self.validate()?;
        serde_json::to_vec(self)
            .map(scheduler_digest)
            .map_err(|_| WakeSleepError::Serialization)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WakeReceipt {
    pub request_digest: String,
    pub wake_at: DateTime<Utc>,
    pub lease_generation: u64,
}

impl WakeReceipt {
    pub fn validate(&self) -> Result<(), WakeSleepError> {
        if !is_digest(&self.request_digest) || self.lease_generation == 0 {
            return Err(WakeSleepError::InvalidReceipt);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SleepObservation {
    pub slept_at: DateTime<Utc>,
    pub lifecycle_generation: u64,
    pub armed_wake_count: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WakeObservation {
    pub woke_at: DateTime<Utc>,
    pub slept_for: Option<Duration>,
    pub lifecycle_generation: u64,
    pub armed_wake_count: usize,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum WakeSleepError {
    #[error("wake request is invalid or outside its contract window")]
    InvalidRequest,
    #[error("wake receipt is invalid or stale")]
    InvalidReceipt,
    #[error("wake request was already armed with a different receipt")]
    ReceiptConflict,
    #[error("wake receipt is not currently armed")]
    ReceiptNotFound,
    #[error("wake time precedes the recorded sleep time")]
    InvalidLifecycleTime,
    #[error("wake/sleep adapter backend failed")]
    Backend,
    #[error("wake/sleep contract serialization failed")]
    Serialization,
}

/// The only scheduler-facing power lifecycle interface.
pub trait OsWakeSleepAdapter: fmt::Debug + Send {
    fn arm_wake(&mut self, request: WakeRequest) -> Result<WakeReceipt, WakeSleepError>;
    fn disarm_wake(&mut self, receipt: &WakeReceipt) -> Result<(), WakeSleepError>;
    fn record_sleep(&mut self, slept_at: DateTime<Utc>)
    -> Result<SleepObservation, WakeSleepError>;
    fn record_wake(&mut self, woke_at: DateTime<Utc>) -> Result<WakeObservation, WakeSleepError>;
}

/// Native macOS calls are intentionally injected. This preserves an explicit
/// contract test seam and prevents the core from silently acquiring a second
/// lifecycle authority or making a duplicate wake request.
pub trait MacOsWakeSleepBackend: fmt::Debug + Send {
    fn arm(&mut self, request: &WakeRequest) -> Result<(), WakeSleepError>;
    fn disarm(&mut self, receipt: &WakeReceipt) -> Result<(), WakeSleepError>;
}

#[derive(Debug)]
pub struct MacOsWakeSleepAdapter<B> {
    backend: B,
    armed: BTreeMap<String, WakeReceipt>,
    lifecycle_generation: u64,
    slept_at: Option<DateTime<Utc>>,
}

impl<B> MacOsWakeSleepAdapter<B>
where
    B: MacOsWakeSleepBackend,
{
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            armed: BTreeMap::new(),
            lifecycle_generation: 0,
            slept_at: None,
        }
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }
}

impl<B> OsWakeSleepAdapter for MacOsWakeSleepAdapter<B>
where
    B: MacOsWakeSleepBackend,
{
    fn arm_wake(&mut self, request: WakeRequest) -> Result<WakeReceipt, WakeSleepError> {
        request.validate()?;
        let request_digest = request.request_digest()?;
        if let Some(existing) = self.armed.get(&request_digest) {
            if existing.wake_at == request.wake_at
                && existing.lease_generation == request.lease_generation
            {
                return Ok(existing.clone());
            }
            return Err(WakeSleepError::ReceiptConflict);
        }
        let receipt = WakeReceipt {
            request_digest: request_digest.clone(),
            wake_at: request.wake_at,
            lease_generation: request.lease_generation,
        };
        self.backend.arm(&request)?;
        self.armed.insert(request_digest, receipt.clone());
        Ok(receipt)
    }

    fn disarm_wake(&mut self, receipt: &WakeReceipt) -> Result<(), WakeSleepError> {
        receipt.validate()?;
        let existing = self
            .armed
            .get(&receipt.request_digest)
            .ok_or(WakeSleepError::ReceiptNotFound)?;
        if existing != receipt {
            return Err(WakeSleepError::ReceiptConflict);
        }
        self.backend.disarm(receipt)?;
        self.armed.remove(&receipt.request_digest);
        Ok(())
    }

    fn record_sleep(
        &mut self,
        slept_at: DateTime<Utc>,
    ) -> Result<SleepObservation, WakeSleepError> {
        self.lifecycle_generation = self
            .lifecycle_generation
            .checked_add(1)
            .ok_or(WakeSleepError::InvalidLifecycleTime)?;
        self.slept_at = Some(slept_at);
        Ok(SleepObservation {
            slept_at,
            lifecycle_generation: self.lifecycle_generation,
            armed_wake_count: self.armed.len(),
        })
    }

    fn record_wake(&mut self, woke_at: DateTime<Utc>) -> Result<WakeObservation, WakeSleepError> {
        let slept_for = self
            .slept_at
            .map(|slept_at| woke_at - slept_at)
            .map(|duration| {
                if duration < Duration::zero() {
                    Err(WakeSleepError::InvalidLifecycleTime)
                } else {
                    Ok(duration)
                }
            })
            .transpose()?;
        self.slept_at = None;
        Ok(WakeObservation {
            woke_at,
            slept_for,
            lifecycle_generation: self.lifecycle_generation,
            armed_wake_count: self.armed.len(),
        })
    }
}

fn is_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(target_os = "macos")]
#[cfg(test)]
mod macos_contract_tests {
    use super::*;

    #[derive(Debug, Default)]
    struct RecordingBackend {
        arm_calls: usize,
        disarm_calls: usize,
    }

    impl MacOsWakeSleepBackend for RecordingBackend {
        fn arm(&mut self, _request: &WakeRequest) -> Result<(), WakeSleepError> {
            self.arm_calls += 1;
            Ok(())
        }

        fn disarm(&mut self, _receipt: &WakeReceipt) -> Result<(), WakeSleepError> {
            self.disarm_calls += 1;
            Ok(())
        }
    }

    fn request() -> WakeRequest {
        WakeRequest {
            schedule_id_digest: "a".repeat(64),
            wake_at: DateTime::parse_from_rfc3339("2026-08-13T11:00:00Z")
                .expect("wake time")
                .with_timezone(&Utc),
            contract_valid_until: DateTime::parse_from_rfc3339("2026-08-13T12:00:00Z")
                .expect("contract time")
                .with_timezone(&Utc),
            coalesced_ticks: 3,
            lease_generation: 4,
        }
    }

    #[test]
    fn macos_adapter_arms_same_digest_once_and_preserves_sleep_generation() {
        let mut adapter = MacOsWakeSleepAdapter::new(RecordingBackend::default());
        let first = adapter.arm_wake(request()).expect("arm wake");
        let second = adapter.arm_wake(request()).expect("exact wake replay");
        assert_eq!(first, second);
        assert_eq!(adapter.backend().arm_calls, 1);
        let slept = adapter
            .record_sleep(
                DateTime::parse_from_rfc3339("2026-08-13T10:30:00Z")
                    .expect("sleep time")
                    .with_timezone(&Utc),
            )
            .expect("sleep");
        let woke = adapter
            .record_wake(
                DateTime::parse_from_rfc3339("2026-08-13T11:30:00Z")
                    .expect("wake time")
                    .with_timezone(&Utc),
            )
            .expect("wake");
        assert_eq!(slept.lifecycle_generation, woke.lifecycle_generation);
        assert_eq!(woke.slept_for, Some(Duration::hours(1)));
        adapter.disarm_wake(&first).expect("disarm");
        assert_eq!(adapter.backend().disarm_calls, 1);
    }
}

#[cfg(test)]
mod portable_contract_tests {
    use chrono::TimeZone;

    use super::*;

    #[test]
    fn invalid_wake_request_cannot_cross_the_adapter_boundary() {
        let request = WakeRequest {
            schedule_id_digest: "not-a-digest".into(),
            wake_at: Utc.with_ymd_and_hms(2026, 8, 13, 11, 0, 0).unwrap(),
            contract_valid_until: Utc.with_ymd_and_hms(2026, 8, 13, 12, 0, 0).unwrap(),
            coalesced_ticks: 1,
            lease_generation: 1,
        };
        assert_eq!(request.validate(), Err(WakeSleepError::InvalidRequest));
    }
}

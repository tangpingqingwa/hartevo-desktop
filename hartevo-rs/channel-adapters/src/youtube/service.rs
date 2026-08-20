//! Durable YouTube publish orchestration.

use chrono::{DateTime, Duration, Utc};

use crate::transport::YouTubeSecretReference;

use super::provider::{YouTubeDataApiProvider, YouTubeProductionTransport};
use super::{
    REAL_PUBLISH_ENABLE_ENV, REAL_PUBLISH_SECRET_REFERENCE_ENV, YouTubeCredential,
    YouTubeCredentialInvalidationReason, YouTubeDispatchOperation, YouTubeError,
    YouTubePublishCheckpoint, YouTubePublishDispatchResult, YouTubePublishPhase,
    YouTubeQuotaLedger, YouTubeReconciliationReason, YouTubeUploadProgress,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct YouTubeRealPublishGate {
    secret_reference: YouTubeSecretReference,
}

impl YouTubeRealPublishGate {
    pub fn from_env() -> Result<Self, YouTubeError> {
        Self::from_environment_values(
            std::env::var(REAL_PUBLISH_ENABLE_ENV).ok().as_deref(),
            std::env::var(REAL_PUBLISH_SECRET_REFERENCE_ENV)
                .ok()
                .as_deref(),
        )
    }

    pub(crate) fn from_environment_values(
        enabled: Option<&str>,
        secret_reference: Option<&str>,
    ) -> Result<Self, YouTubeError> {
        if enabled != Some("1") {
            return Err(YouTubeError::BlockedEnvironment {
                requirement: "HARTEVO_YOUTUBE_REAL_PUBLISH=1",
            });
        }
        let secret_reference = secret_reference.ok_or(YouTubeError::BlockedEnvironment {
            requirement: "HARTEVO_YOUTUBE_SECRET_REFERENCE",
        })?;
        Ok(Self {
            secret_reference: YouTubeSecretReference::new(secret_reference)
                .map_err(|_| YouTubeError::InvalidRequest("invalid YouTube secret reference"))?,
        })
    }

    pub const fn secret_reference(&self) -> &YouTubeSecretReference {
        &self.secret_reference
    }
}

#[derive(Debug)]
pub struct YouTubePublishService<T> {
    provider: YouTubeDataApiProvider<T>,
    quota: YouTubeQuotaLedger,
    probe_valid_for: Duration,
    readback_valid_for: Duration,
}

impl<T> YouTubePublishService<T> {
    pub fn fixture(transport: T) -> Self {
        Self::with_provider(YouTubeDataApiProvider::fixture(transport))
    }

    pub fn controlled(transport: T) -> Self {
        Self::with_provider(YouTubeDataApiProvider::controlled(transport))
    }

    pub fn fixture_with_quota(transport: T, quota: YouTubeQuotaLedger) -> Self {
        let mut service = Self::fixture(transport);
        service.quota = quota;
        service
    }

    fn production(transport: T, gate: &YouTubeRealPublishGate) -> Self
    where
        T: YouTubeProductionTransport,
    {
        Self::with_provider(YouTubeDataApiProvider::production(
            transport,
            gate.secret_reference().clone(),
        ))
    }

    fn with_provider(provider: YouTubeDataApiProvider<T>) -> Self {
        Self {
            provider,
            quota: YouTubeQuotaLedger::default(),
            probe_valid_for: Duration::minutes(5),
            readback_valid_for: Duration::minutes(5),
        }
    }

    pub const fn provenance(&self) -> super::YouTubeEvidenceProvenance {
        self.provider.provenance()
    }

    pub const fn quota(&self) -> &YouTubeQuotaLedger {
        &self.quota
    }

    pub fn quota_mut(&mut self) -> &mut YouTubeQuotaLedger {
        &mut self.quota
    }

    #[allow(clippy::too_many_lines)]
    pub fn dispatch(
        &mut self,
        credential: &YouTubeCredential,
        checkpoint: &mut YouTubePublishCheckpoint,
        now: DateTime<Utc>,
    ) -> Result<YouTubePublishDispatchResult, YouTubeError>
    where
        T: super::provider::YouTubePublishTransport,
    {
        checkpoint.bind_credential(credential, now)?;
        checkpoint.request().validate_at(now)?;
        credential.require_publish(checkpoint.request().binding(), now)?;
        if let Some(receipt) = checkpoint.retry_after_if_waiting(now) {
            return Ok(YouTubePublishDispatchResult::RetryAfter(receipt.clone()));
        }
        checkpoint.clear_retry_after();
        checkpoint.require_dispatchable()?;

        if matches!(checkpoint.phase(), YouTubePublishPhase::Completed) {
            return Ok(YouTubePublishDispatchResult::AlreadyCompleted(
                checkpoint.published_video()?,
            ));
        }
        if matches!(
            checkpoint.phase(),
            YouTubePublishPhase::ReconciliationRequired
        ) {
            return Ok(YouTubePublishDispatchResult::ReconciliationRequired(
                checkpoint
                    .reconciliation()
                    .cloned()
                    .ok_or(YouTubeError::InvalidCheckpoint)?,
            ));
        }

        if let Some(probe) = checkpoint.probe() {
            probe.validate_at(now)?;
        }
        if checkpoint.probe().is_none() {
            self.quota
                .reserve(YouTubeDispatchOperation::AuthenticatedProbe)?;
            match self.provider.authenticated_probe(
                credential,
                checkpoint.request().binding(),
                self.probe_valid_for,
            ) {
                Ok(probe) => checkpoint.set_probe(probe),
                Err(error) => {
                    return Self::handle_provider_error(
                        checkpoint,
                        YouTubeDispatchOperation::AuthenticatedProbe,
                        error,
                        now,
                        false,
                    );
                }
            }
        }

        if checkpoint.session().is_none() {
            self.quota
                .reserve(YouTubeDispatchOperation::BeginResumableUpload)?;
            match self.provider.begin_upload(credential, checkpoint.request()) {
                Ok(session) => checkpoint.set_session(session),
                Err(error) => {
                    return Self::handle_provider_error(
                        checkpoint,
                        YouTubeDispatchOperation::BeginResumableUpload,
                        error,
                        now,
                        true,
                    );
                }
            }
        }

        if checkpoint.provider_receipt().is_none() {
            let session = checkpoint
                .session()
                .cloned()
                .ok_or(YouTubeError::InvalidCheckpoint)?;
            let uploaded_bytes = checkpoint.uploaded_bytes();
            self.quota.reserve(YouTubeDispatchOperation::UploadChunk)?;
            match self.provider.upload_chunk(
                credential,
                checkpoint.request(),
                &session,
                uploaded_bytes,
            ) {
                Ok(YouTubeUploadProgress::InProgress {
                    session,
                    uploaded_bytes,
                    ..
                }) => {
                    checkpoint.set_uploaded_bytes(uploaded_bytes)?;
                    return Ok(YouTubePublishDispatchResult::Uploading {
                        session,
                        uploaded_bytes,
                    });
                }
                Ok(YouTubeUploadProgress::Completed(receipt)) => {
                    checkpoint.set_provider_receipt(receipt);
                }
                Err(error) => {
                    return Self::handle_provider_error(
                        checkpoint,
                        YouTubeDispatchOperation::UploadChunk,
                        error,
                        now,
                        false,
                    );
                }
            }
        }

        let provider_receipt = checkpoint
            .provider_receipt()
            .cloned()
            .ok_or(YouTubeError::InvalidCheckpoint)?;
        self.quota.reserve(YouTubeDispatchOperation::Readback)?;
        let readback = match self.provider.readback(
            credential,
            checkpoint.request(),
            &provider_receipt,
            self.readback_valid_for,
        ) {
            Ok(readback) => readback,
            Err(error) => {
                return Self::handle_provider_error(
                    checkpoint,
                    YouTubeDispatchOperation::Readback,
                    error,
                    now,
                    false,
                );
            }
        };
        readback.validate_at(now)?;
        readback.verify_against(checkpoint.request(), &provider_receipt)?;
        if !readback.is_ready() {
            checkpoint.set_readback(readback.clone());
            return Ok(YouTubePublishDispatchResult::ReadbackPending(readback));
        }
        checkpoint.set_readback(readback);
        checkpoint.mark_completed();
        Ok(YouTubePublishDispatchResult::Completed(
            checkpoint.published_video()?,
        ))
    }

    #[allow(clippy::too_many_lines)]
    fn handle_provider_error(
        checkpoint: &mut YouTubePublishCheckpoint,
        operation: YouTubeDispatchOperation,
        error: YouTubeError,
        now: DateTime<Utc>,
        ambiguous_begin: bool,
    ) -> Result<YouTubePublishDispatchResult, YouTubeError> {
        match error {
            YouTubeError::RetryAfter(receipt) => {
                let receipt = *receipt;
                checkpoint.set_retry_after(receipt.clone());
                Ok(YouTubePublishDispatchResult::RetryAfter(receipt))
            }
            error if error.is_retryable() && ambiguous_begin => {
                checkpoint.mark_reconciliation_required(
                    YouTubeReconciliationReason::UploadStartAmbiguous,
                    now,
                );
                Ok(YouTubePublishDispatchResult::ReconciliationRequired(
                    checkpoint
                        .reconciliation()
                        .cloned()
                        .ok_or(YouTubeError::InvalidCheckpoint)?,
                ))
            }
            error if error.is_retryable() => Ok(YouTubePublishDispatchResult::Retryable {
                operation,
                checkpoint_digest: checkpoint.durable_digest(),
            }),
            YouTubeError::CredentialRevoked => {
                checkpoint.invalidate(YouTubeCredentialInvalidationReason::Revoked, now);
                Err(YouTubeError::CheckpointInvalidated)
            }
            error => Err(error),
        }
    }
}

pub fn execute_real_publish_gate<T>(transport: T) -> Result<YouTubePublishService<T>, YouTubeError>
where
    T: YouTubeProductionTransport,
{
    let gate = YouTubeRealPublishGate::from_env()?;
    Ok(YouTubePublishService::production(transport, &gate))
}

#[cfg(test)]
mod tests {
    use super::YouTubeRealPublishGate;
    use crate::youtube::YouTubeError;

    #[test]
    fn real_gate_requires_explicit_enablement_and_secret_reference() {
        assert_eq!(
            YouTubeRealPublishGate::from_environment_values(
                Some("0"),
                Some("secret://youtube/test"),
            )
            .unwrap_err(),
            YouTubeError::BlockedEnvironment {
                requirement: "HARTEVO_YOUTUBE_REAL_PUBLISH=1",
            }
        );
        assert_eq!(
            YouTubeRealPublishGate::from_environment_values(Some("1"), None).unwrap_err(),
            YouTubeError::BlockedEnvironment {
                requirement: "HARTEVO_YOUTUBE_SECRET_REFERENCE",
            }
        );
        assert!(
            YouTubeRealPublishGate::from_environment_values(
                Some("1"),
                Some("secret://youtube/test"),
            )
            .is_ok()
        );
    }
}

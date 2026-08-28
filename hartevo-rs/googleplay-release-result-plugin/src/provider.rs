//! Android Publisher release provider for bounded Layer-1 read evidence.

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    AccessTokenLease, ActiveArtifactVersionCodeDigest, GooglePlayReleaseEvidence,
    GooglePlayReleasePayload, GooglePlayReleaseScope, GooglePlayReleaseSummary,
    GooglePlayTrackPayload, ReleaseResultStatus, RolloutBucket, RolloutSelector,
};
use crate::service::GooglePlayRegistration;
use crate::transport::{
    GooglePlayEndpoint, GooglePlayHttpRequest, GooglePlayResponseBody, GooglePlayResponseReceipt,
    GooglePlayTransport, GooglePlayTransportError, TransportProvenance,
};
use crate::{
    GooglePlayReleaseResultError, MAX_RELEASES, MAX_RESPONSE_BYTES, MAX_VERSION_CODES_PER_RELEASE,
    Result,
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CredentialError {
    #[error("BLOCKED_ENV: native Google credential authority is unavailable")]
    BlockedEnv,
    #[error("Google credential reference is unavailable")]
    Unavailable,
    #[error("Google access token lease is invalid or expired")]
    Invalid,
}

/// Host credential resolution is deliberately a Layer-2 seam.  A resolver
/// returns one non-cloneable lease for one GET and the provider never stores
/// it after that call.
pub trait GoogleCredentialResolver: fmt::Debug {
    fn resolve(
        &mut self,
        reference: &crate::SecretReference,
        at_epoch_seconds: u64,
    ) -> std::result::Result<AccessTokenLease, CredentialError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvCredentialResolver;

impl GoogleCredentialResolver for BlockedEnvCredentialResolver {
    fn resolve(
        &mut self,
        _reference: &crate::SecretReference,
        _at_epoch_seconds: u64,
    ) -> std::result::Result<AccessTokenLease, CredentialError> {
        Err(CredentialError::BlockedEnv)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GooglePlayProviderState {
    Ready,
    AccessLost,
    BlockedEnv,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GooglePlayReadRequest {
    pub max_releases: usize,
    pub max_response_bytes: usize,
    pub observed_at_epoch_seconds: u64,
}

impl Default for GooglePlayReadRequest {
    fn default() -> Self {
        Self {
            max_releases: MAX_RELEASES,
            max_response_bytes: MAX_RESPONSE_BYTES,
            observed_at_epoch_seconds: 0,
        }
    }
}

impl GooglePlayReadRequest {
    pub fn new() -> Result<Self> {
        let request = Self::default();
        request.validate()?;
        Ok(request)
    }

    pub fn with_bounds(
        max_releases: usize,
        max_response_bytes: usize,
        observed_at_epoch_seconds: u64,
    ) -> Result<Self> {
        let request = Self {
            max_releases,
            max_response_bytes,
            observed_at_epoch_seconds,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<()> {
        if self.max_releases == 0 || self.max_releases > MAX_RELEASES {
            return Err(GooglePlayReleaseResultError::BoundExceeded {
                field: "release summaries",
            });
        }
        if self.max_response_bytes == 0 || self.max_response_bytes > MAX_RESPONSE_BYTES {
            return Err(GooglePlayReleaseResultError::BoundExceeded {
                field: "response bytes",
            });
        }
        Ok(())
    }
}

/// Provider state is generic over its transport and resolver so the official
/// GET seam can be used by a later host without changing the service contract.
pub struct GooglePlayProvider<T, R> {
    registration: GooglePlayRegistration,
    transport: T,
    credential_resolver: R,
    state: GooglePlayProviderState,
}

impl<T, R> fmt::Debug for GooglePlayProvider<T, R>
where
    T: fmt::Debug,
    R: fmt::Debug,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GooglePlayProvider")
            .field("registration", &self.registration)
            .field("transport", &self.transport)
            .field("credential_resolver", &"<opaque resolver>")
            .field("state", &self.state)
            .finish()
    }
}

impl<T, R> GooglePlayProvider<T, R>
where
    T: GooglePlayTransport,
    R: GoogleCredentialResolver,
{
    pub fn new(
        registration: GooglePlayRegistration,
        transport: T,
        credential_resolver: R,
    ) -> Result<Self> {
        registration.validate()?;
        if !registration.is_active() {
            return Err(match registration.status {
                crate::GooglePlayRegistrationStatus::Revoked => {
                    GooglePlayReleaseResultError::RegistrationRevoked
                }
                crate::GooglePlayRegistrationStatus::Reversed => {
                    GooglePlayReleaseResultError::RegistrationReversed
                }
                crate::GooglePlayRegistrationStatus::Active => {
                    GooglePlayReleaseResultError::InvalidRegistration
                }
            });
        }
        Ok(Self {
            registration,
            transport,
            credential_resolver,
            state: GooglePlayProviderState::Ready,
        })
    }

    pub fn registration(&self) -> &GooglePlayRegistration {
        &self.registration
    }

    pub fn scope(&self) -> &GooglePlayReleaseScope {
        self.registration.scope()
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub const fn state(&self) -> GooglePlayProviderState {
        self.state
    }

    pub fn is_connected(&self) -> bool {
        false
    }

    pub fn is_native(&self) -> bool {
        false
    }

    pub fn read_release_summaries(
        &mut self,
        request: &GooglePlayReadRequest,
    ) -> Result<GooglePlayReleaseEvidence> {
        request.validate()?;
        self.registration.validate()?;
        if !self.registration.is_active() {
            return Err(match self.registration.status {
                crate::GooglePlayRegistrationStatus::Revoked => {
                    GooglePlayReleaseResultError::RegistrationRevoked
                }
                crate::GooglePlayRegistrationStatus::Reversed => {
                    GooglePlayReleaseResultError::RegistrationReversed
                }
                crate::GooglePlayRegistrationStatus::Active => {
                    GooglePlayReleaseResultError::InvalidRegistration
                }
            });
        }
        let endpoint = GooglePlayEndpoint::TrackReleases {
            package_name: self.scope().package_name.clone(),
            track: self.scope().track.clone(),
        };
        let http_request = GooglePlayHttpRequest::new(
            endpoint,
            request.max_response_bytes,
            request.observed_at_epoch_seconds,
        )?;
        let provenance = self.transport.provenance();
        let token = if matches!(provenance, TransportProvenance::OfficialHttpsRead) {
            match self.credential_resolver.resolve(
                &self.registration.secret_reference,
                request.observed_at_epoch_seconds,
            ) {
                Ok(token) => Some(token),
                Err(CredentialError::BlockedEnv) => {
                    self.state = GooglePlayProviderState::BlockedEnv;
                    return self.unavailable_evidence(
                        ReleaseResultStatus::ProviderUnknown,
                        EvidenceUnavailableReason::BlockedEnv,
                        provenance,
                    );
                }
                Err(CredentialError::Unavailable | CredentialError::Invalid) => {
                    self.state = GooglePlayProviderState::BlockedEnv;
                    return self.unavailable_evidence(
                        ReleaseResultStatus::ProviderUnknown,
                        EvidenceUnavailableReason::Credential,
                        provenance,
                    );
                }
            }
        } else {
            None
        };
        let response = match self.transport.get(&http_request, token.as_ref()) {
            Ok(response) => response,
            Err(GooglePlayTransportError::BlockedEnv) => {
                self.state = GooglePlayProviderState::BlockedEnv;
                return self.unavailable_evidence(
                    ReleaseResultStatus::ProviderUnknown,
                    EvidenceUnavailableReason::BlockedEnv,
                    provenance,
                );
            }
            Err(GooglePlayTransportError::CredentialUnavailable) => {
                self.state = GooglePlayProviderState::BlockedEnv;
                return self.unavailable_evidence(
                    ReleaseResultStatus::ProviderUnknown,
                    EvidenceUnavailableReason::Credential,
                    provenance,
                );
            }
            Err(GooglePlayTransportError::Timeout) => {
                return self.unavailable_evidence(
                    ReleaseResultStatus::ProviderUnknown,
                    EvidenceUnavailableReason::Timeout,
                    provenance,
                );
            }
            Err(
                GooglePlayTransportError::FixtureMissing | GooglePlayTransportError::Transport(_),
            ) => {
                return self.unavailable_evidence(
                    ReleaseResultStatus::ProviderUnknown,
                    EvidenceUnavailableReason::Provider,
                    provenance,
                );
            }
            Err(
                error @ (GooglePlayTransportError::ResponseTooLarge
                | GooglePlayTransportError::MalformedResponse(_)
                | GooglePlayTransportError::InvalidEndpoint(_)
                | GooglePlayTransportError::InvalidRequest(_)),
            ) => {
                return Err(error.into());
            }
        };
        let receipt = response.receipt().clone();
        let status = match response.status_code() {
            200 => {
                let Some(GooglePlayResponseBody::TrackReleases(payload)) = response.body() else {
                    return Err(GooglePlayReleaseResultError::InvalidProviderData);
                };
                return self.project_payload(payload, vec![receipt], provenance, request);
            }
            401 | 403 => {
                self.state = GooglePlayProviderState::AccessLost;
                ReleaseResultStatus::AccessLost
            }
            404 => ReleaseResultStatus::Stale,
            409 => ReleaseResultStatus::Partial,
            429 | 500..=599 => ReleaseResultStatus::ProviderUnknown,
            _ => ReleaseResultStatus::ProviderUnknown,
        };
        let completeness = if matches!(status, ReleaseResultStatus::Partial) {
            crate::model::EvidenceCompleteness::Partial
        } else {
            crate::model::EvidenceCompleteness::Unavailable
        };
        GooglePlayReleaseEvidence::for_scope(
            &self.registration,
            status,
            completeness,
            Vec::new(),
            vec![receipt],
            provenance,
        )
    }

    pub fn read(&mut self, request: &GooglePlayReadRequest) -> Result<GooglePlayReleaseEvidence> {
        self.read_release_summaries(request)
    }

    fn project_payload(
        &self,
        payload: &GooglePlayTrackPayload,
        receipts: Vec<GooglePlayResponseReceipt>,
        provenance: TransportProvenance,
        request: &GooglePlayReadRequest,
    ) -> Result<GooglePlayReleaseEvidence> {
        if payload.releases.len() > request.max_releases || payload.releases.len() > MAX_RELEASES {
            return Err(GooglePlayReleaseResultError::BoundExceeded {
                field: "release summaries",
            });
        }
        if payload
            .package_name
            .as_ref()
            .is_some_and(|package| package != &self.scope().package_name)
            || payload.track != self.scope().track
        {
            return Err(GooglePlayReleaseResultError::ScopeMismatch);
        }
        let mut summaries = Vec::with_capacity(payload.releases.len());
        let mut matching_index = None;
        for (index, release) in payload.releases.iter().enumerate() {
            let selected = match &self.scope().release_selector {
                crate::model::ReleaseSelector::Any => true,
                crate::model::ReleaseSelector::Exact(expected) => &release.release_id == expected,
            };
            let summary = self.project_release(release, selected)?;
            if selected
                && summary
                    .active_artifact_version_code_digests
                    .iter()
                    .any(|artifact| artifact.version_code == self.scope().artifact.version_code)
            {
                if matching_index.is_some() {
                    return Err(GooglePlayReleaseResultError::InvalidProviderData);
                }
                matching_index = Some(index);
            }
            summaries.push(summary);
        }
        if let crate::model::ReleaseSelector::Exact(expected) = &self.scope().release_selector
            && !payload
                .releases
                .iter()
                .any(|release| &release.release_id == expected)
        {
            return GooglePlayReleaseEvidence::for_scope(
                &self.registration,
                ReleaseResultStatus::Stale,
                crate::model::EvidenceCompleteness::Unavailable,
                Vec::new(),
                receipts,
                provenance,
            );
        }
        let Some(index) = matching_index else {
            return GooglePlayReleaseEvidence::for_scope(
                &self.registration,
                ReleaseResultStatus::Stale,
                crate::model::EvidenceCompleteness::Unavailable,
                summaries,
                receipts,
                provenance,
            );
        };
        let status = if payload.partial {
            ReleaseResultStatus::Partial
        } else {
            let summary = &summaries[index];
            if matches!(summary.rollout_bucket, RolloutBucket::Halted) {
                ReleaseResultStatus::Halted
            } else {
                summary.lifecycle_state.into()
            }
        };
        let completeness = if matches!(status, ReleaseResultStatus::Partial) {
            crate::model::EvidenceCompleteness::Partial
        } else {
            crate::model::EvidenceCompleteness::Complete
        };
        GooglePlayReleaseEvidence::for_scope(
            &self.registration,
            status,
            completeness,
            summaries,
            receipts,
            provenance,
        )
    }

    fn project_release(
        &self,
        release: &GooglePlayReleasePayload,
        selected: bool,
    ) -> Result<GooglePlayReleaseSummary> {
        if release.version_codes.is_empty()
            || release.version_codes.len() > MAX_VERSION_CODES_PER_RELEASE
            || release.version_codes.contains(&0)
        {
            return Err(GooglePlayReleaseResultError::InvalidProviderData);
        }
        let artifact_version_code_digests = release
            .version_codes
            .iter()
            .map(|version_code| ActiveArtifactVersionCodeDigest {
                version_code: *version_code,
                version_code_digest: crate::Digest::from_parts(
                    "googleplay-release-result/active-artifact-version-code/v1",
                    [
                        (
                            "developer_account".to_owned(),
                            self.scope().developer_account.to_string(),
                        ),
                        ("package".to_owned(), self.scope().package_name.to_string()),
                        ("track".to_owned(), self.scope().track.to_string()),
                        (
                            "form_factor".to_owned(),
                            self.scope().form_factor.as_str().to_owned(),
                        ),
                        ("release".to_owned(), release.release_id.to_string()),
                        ("version_code".to_owned(), version_code.to_string()),
                    ],
                ),
            })
            .collect::<Vec<_>>();
        if selected
            && let Some(remote_artifact_digest) = release
                .artifact_digests
                .get(&self.scope().artifact.version_code)
            && remote_artifact_digest != &self.scope().artifact.artifact_digest
        {
            return Err(GooglePlayReleaseResultError::VersionCodeArtifactMismatch);
        }
        let artifact_binding_matches = selected
            && release
                .version_codes
                .contains(&self.scope().artifact.version_code);
        let rollout_bucket = if release.halted {
            RolloutBucket::Halted
        } else if let Some(digest) = &release.country_targeting_digest {
            RolloutBucket::CountryTargeted {
                targeting_digest: digest.clone(),
            }
        } else if let Some(millionths) = release.user_fraction_millionths {
            RolloutBucket::user_fraction(millionths)?
        } else {
            RolloutBucket::Full
        };
        if selected
            && let RolloutSelector::Exact(expected) = &self.scope().rollout
            && expected != &rollout_bucket
        {
            return Err(GooglePlayReleaseResultError::ScopeMismatch);
        }
        let release_digest = crate::digest_serialized_with_domain(
            "googleplay-release-result/release-summary/v1",
            &(
                &release.release_id,
                &release.release_name,
                release.lifecycle_state,
                &artifact_version_code_digests,
                &rollout_bucket,
                &release.country_targeting_digest,
                artifact_binding_matches,
            ),
        );
        let summary = GooglePlayReleaseSummary {
            release_id: release.release_id.clone(),
            release_name: release.release_name.clone(),
            lifecycle_state: release.lifecycle_state,
            active_artifact_version_code_digests: artifact_version_code_digests,
            rollout_bucket,
            country_targeting_digest: release.country_targeting_digest.clone(),
            artifact_binding_matches,
            release_digest,
        };
        if selected && !summary.artifact_binding_matches {
            return Err(GooglePlayReleaseResultError::VersionCodeArtifactMismatch);
        }
        summary.validate()?;
        Ok(summary)
    }

    fn unavailable_evidence(
        &self,
        status: ReleaseResultStatus,
        _reason: EvidenceUnavailableReason,
        provenance: TransportProvenance,
    ) -> Result<GooglePlayReleaseEvidence> {
        GooglePlayReleaseEvidence::for_scope(
            &self.registration,
            status,
            crate::model::EvidenceCompleteness::Unavailable,
            Vec::new(),
            Vec::new(),
            provenance,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EvidenceUnavailableReason {
    BlockedEnv,
    Credential,
    Timeout,
    Provider,
}

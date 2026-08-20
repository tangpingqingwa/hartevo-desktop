//! Typed YouTube read service and Mission-facing consumer boundary.
//!
//! The service owns request dispatch through an injected read-only transport;
//! it does not own credentials, persistence, or Effect authority. The
//! consumer binds observations to one exact channel/account before a Mission
//! can adopt them.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::identity::{
    AccountIdentity, ChannelIdentity, ProviderId, YoutubeChannelId, YoutubeChannelIdentity,
};
use crate::transport::{
    ChannelAdapterError, CredentialReference, ReadOnlyTransport, TransportError,
};
use crate::youtube::{
    YoutubeChannelProbeObservation, YoutubeQuotaLedger, YoutubeReadObservation, YoutubeReadResult,
    YoutubeReadTarget, channel_identity_request, parse_channel_identity, parse_read_response,
};

#[derive(Debug)]
pub struct YoutubeReadService<T> {
    transport: T,
    quota: YoutubeQuotaLedger,
}

impl<T> YoutubeReadService<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            quota: YoutubeQuotaLedger::default(),
        }
    }

    pub fn with_quota(transport: T, quota: YoutubeQuotaLedger) -> Self {
        Self { transport, quota }
    }

    pub const fn quota(&self) -> &YoutubeQuotaLedger {
        &self.quota
    }

    pub fn quota_mut(&mut self) -> &mut YoutubeQuotaLedger {
        &mut self.quota
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }
}

impl<T: ReadOnlyTransport> YoutubeReadService<T> {
    pub fn probe_channel(
        &mut self,
        credential: CredentialReference,
        requested_at: DateTime<Utc>,
    ) -> Result<Vec<YoutubeChannelProbeObservation>, ChannelAdapterError> {
        let request = channel_identity_request(credential)?;
        self.quota.reserve(
            crate::youtube::YoutubeQuotaOperation::ChannelsList,
            requested_at,
        )?;
        let response = self.send(&request)?;
        parse_channel_identity(&response)
    }

    pub fn read(
        &mut self,
        target: &YoutubeReadTarget,
        credential: CredentialReference,
        requested_at: DateTime<Utc>,
    ) -> Result<YoutubeReadResult, ChannelAdapterError> {
        let request = target.request(credential)?;
        self.quota.reserve(target.operation(), requested_at)?;
        let response = self.send(&request)?;
        parse_read_response(target, &response)
    }

    fn send(
        &mut self,
        request: &crate::transport::ProviderReadRequest,
    ) -> Result<crate::transport::ProviderResponse, ChannelAdapterError> {
        self.transport
            .send(request)
            .map_err(|error| transport_error(&error, request.provider()))
    }
}

fn transport_error(_error: &TransportError, provider: ProviderId) -> ChannelAdapterError {
    ChannelAdapterError::TransportUnavailable { provider }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct YoutubeConsumedObservation {
    account: AccountIdentity,
    channel: ChannelIdentity,
    observation: YoutubeReadObservation,
}

impl YoutubeConsumedObservation {
    pub const fn account(&self) -> &AccountIdentity {
        &self.account
    }

    pub const fn channel(&self) -> &ChannelIdentity {
        &self.channel
    }

    pub const fn observation(&self) -> &YoutubeReadObservation {
        &self.observation
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct YoutubeReadConsumer {
    account: AccountIdentity,
    channel: ChannelIdentity,
}

impl YoutubeReadConsumer {
    pub fn for_channel(channel: YoutubeChannelIdentity) -> Self {
        let account = AccountIdentity::Youtube(channel.account().clone());
        Self {
            account,
            channel: ChannelIdentity::Youtube(channel),
        }
    }

    pub const fn account(&self) -> &AccountIdentity {
        &self.account
    }

    pub const fn channel(&self) -> &ChannelIdentity {
        &self.channel
    }

    pub fn accept(
        &self,
        observation: YoutubeReadObservation,
    ) -> Result<YoutubeConsumedObservation, ChannelAdapterError> {
        let channel_id =
            observation_channel_id(&observation).ok_or(ChannelAdapterError::InvalidResponse {
                provider: ProviderId::Youtube,
                field: "consumer.channel_id".to_owned(),
            })?;
        let expected = channel_id_for_identity(&self.channel);
        if channel_id != expected {
            return Err(ChannelAdapterError::InvalidResponse {
                provider: ProviderId::Youtube,
                field: "consumer.channel_id_mismatch".to_owned(),
            });
        }
        Ok(YoutubeConsumedObservation {
            account: self.account.clone(),
            channel: self.channel.clone(),
            observation,
        })
    }
}

fn channel_id_for_identity(identity: &ChannelIdentity) -> &YoutubeChannelId {
    match identity {
        ChannelIdentity::Youtube(channel) => channel.channel_id(),
    }
}

fn observation_channel_id(observation: &YoutubeReadObservation) -> Option<&YoutubeChannelId> {
    match observation {
        YoutubeReadObservation::Video(video) => Some(video.identity().channel_id()),
        YoutubeReadObservation::Comment(comment) => comment.identity().channel_id(),
        YoutubeReadObservation::Analytics(analytics) => Some(analytics.channel_id()),
    }
}

//! YouTube-only opaque credential and transport primitives.

use std::{fmt, str::FromStr};

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct YouTubeSecretReference(String);

impl YouTubeSecretReference {
    pub fn new(value: impl Into<String>) -> Result<Self, TransportError> {
        let value = value.into();
        let lower = value.to_ascii_lowercase();
        if value.is_empty()
            || value.len() > 512
            || value.chars().any(char::is_whitespace)
            || lower.contains("bearer ")
            || lower.contains("access_token")
            || lower.contains("refresh_token")
            || lower.contains("client_secret")
        {
            return Err(TransportError::InvalidSecretReference);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for YouTubeSecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("YouTubeSecretReference(<opaque>)")
    }
}

impl FromStr for YouTubeSecretReference {
    type Err = TransportError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransportError {
    Unavailable,
    TimedOut,
    InvalidSecretReference,
}

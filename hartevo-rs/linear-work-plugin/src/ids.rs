use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum LinearIdError {
    #[error("{kind} id is empty")]
    Empty { kind: &'static str },
    #[error("{kind} id is invalid")]
    Invalid { kind: &'static str },
    #[error("linear scope is invalid: {0}")]
    InvalidScope(String),
    #[error("linear cursor is invalid")]
    InvalidCursor,
}

macro_rules! define_id {
    ($name:ident, $kind:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, LinearIdError> {
                let value = value.into();
                if value.is_empty() {
                    return Err(LinearIdError::Empty { kind: $kind });
                }
                if value.len() > 256
                    || value.chars().any(char::is_control)
                    || value.chars().any(char::is_whitespace)
                {
                    return Err(LinearIdError::Invalid { kind: $kind });
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

define_id!(LinearOrganizationId, "organization");
define_id!(LinearTeamId, "team");
define_id!(LinearUserId, "user");
define_id!(LinearAppId, "app");
define_id!(LinearIssueId, "issue");
define_id!(LinearProjectId, "project");
define_id!(LinearCycleId, "cycle");
define_id!(LinearWorkflowStateId, "workflow state");
define_id!(LinearMissionId, "mission");

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct LinearScope(String);

impl LinearScope {
    pub fn new(value: impl Into<String>) -> Result<Self, LinearIdError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 96
            || !value.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b':' | b'_')
            })
        {
            return Err(LinearIdError::InvalidScope(value));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LinearScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct LinearScopeSet(BTreeSet<LinearScope>);

impl LinearScopeSet {
    pub fn new<I>(scopes: I) -> Result<Self, LinearIdError>
    where
        I: IntoIterator<Item = String>,
    {
        scopes
            .into_iter()
            .map(LinearScope::new)
            .collect::<Result<BTreeSet<_>, _>>()
            .map(Self)
    }

    pub fn contains(&self, scope: &str) -> bool {
        self.0.iter().any(|candidate| candidate.as_str() == scope)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &LinearScope> {
        self.0.iter()
    }

    pub fn as_strings(&self) -> Vec<String> {
        self.iter().map(|scope| scope.as_str().to_owned()).collect()
    }
}

impl fmt::Display for LinearScopeSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scopes = self
            .iter()
            .map(LinearScope::as_str)
            .collect::<Vec<_>>()
            .join(",");
        scopes.fmt(formatter)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct LinearCursor(String);

impl LinearCursor {
    pub fn new(value: impl Into<String>) -> Result<Self, LinearIdError> {
        let value = value.into();
        if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
            return Err(LinearIdError::InvalidCursor);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LinearCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

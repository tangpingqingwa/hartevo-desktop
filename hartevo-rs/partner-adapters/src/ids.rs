use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum NetworkIdentityError {
    #[error("{kind} identity is empty or contains control characters")]
    Invalid { kind: &'static str },
}

macro_rules! network_identity {
    ($name:ident, $kind:literal) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::parse(value).map_err(serde::de::Error::custom)
            }
        }

        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, NetworkIdentityError> {
                let value = value.into();
                if value.trim().is_empty() || value.chars().any(char::is_control) {
                    return Err(NetworkIdentityError::Invalid { kind: $kind });
                }
                Ok(Self(value))
            }

            pub(crate) fn from_stable(value: impl Into<String>) -> Self {
                Self(value.into())
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

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self::from_stable(value)
            }
        }
    };
}

network_identity!(NetworkAccountId, "account");
network_identity!(ProgramId, "program");
network_identity!(PartnerId, "partner");
network_identity!(ContractId, "contract");
network_identity!(LinkId, "link");
network_identity!(ClickId, "click");
network_identity!(ConversionId, "conversion");
network_identity!(ActionId, "action");
network_identity!(CommissionId, "commission");
network_identity!(ReversalId, "reversal");
network_identity!(PayoutId, "payout");
network_identity!(ReportId, "report");
network_identity!(CallbackEventId, "callback event");
network_identity!(NetworkOrderId, "order");

use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::{fmt, str::FromStr};

use crate::ContractError;

macro_rules! id_type {
    ($name:ident, $kind:literal) => {
        #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
        #[repr(transparent)]
        pub struct $name(String);
        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ContractError> {
                let value = value.into();
                if value.trim().is_empty() || value.chars().any(char::is_control) {
                    return Err(ContractError::InvalidId {
                        kind: $kind,
                        reason: "must be non-empty UTF-8 without control characters",
                    });
                }
                Ok(Self(value))
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
            pub fn into_string(self) -> String {
                self.0
            }
        }
        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
        impl FromStr for $name {
            type Err = ContractError;
            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }
        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Self::new(String::deserialize(deserializer)?).map_err(D::Error::custom)
            }
        }
    };
}

id_type!(RequestId, "request");
id_type!(TaskId, "task");
id_type!(SessionId, "session");
id_type!(ProviderId, "provider");
id_type!(AgentId, "agent");
id_type!(PlanId, "plan");
id_type!(NodeId, "node");
id_type!(FindingId, "finding");
id_type!(ReceiptId, "receipt");
id_type!(ReportId, "report");
id_type!(HostId, "host");
id_type!(InvocationId, "invocation");
id_type!(TraceId, "trace");

pub fn derived_id<T: FromStr<Err = ContractError>>(
    canonical_bytes: &[u8],
) -> Result<T, ContractError> {
    let digest = Sha256::digest(canonical_bytes);
    T::from_str(&hex::encode(digest))
}

pub fn derived_id_string(canonical_bytes: &[u8]) -> String {
    let digest = Sha256::digest(canonical_bytes);
    hex::encode(digest)
}

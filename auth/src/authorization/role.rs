use serde::{Deserialize, Serialize};

/// Case-sensitive system-wide authorization roles.
///
/// Used to check whether a user can perform an action on the system scale, e.g.
/// support users or admin users.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenRole {
	/// A system-wide super admin can do anything.
	Admin,
	/// Roles belonging to other services are preserved verbatim.
	#[serde(untagged)]
	Other(String),
}

serde_plain::derive_display_from_serialize!(TokenRole);
serde_plain::derive_fromstr_from_deserialize!(TokenRole);

impl From<String> for TokenRole {
	fn from(value: String) -> Self {
		serde_plain::from_str(&value).unwrap_or(Self::Other(value))
	}
}

impl From<&str> for TokenRole {
	fn from(value: &str) -> Self { Self::from(value.to_owned()) }
}

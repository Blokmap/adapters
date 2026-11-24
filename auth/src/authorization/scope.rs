use std::marker::ConstParamTy;

use serde::{Deserialize, Serialize};

/// Case-sensitive authorization scopes in `resource:permission` form.
///
/// Used when requesting service tokens and reading JWT grants. Every accepted
/// scope has a variant here; unknown strings are rejected. `Display`,
/// `FromStr`, and JSON share the same wire values.
///
/// ```
/// use blokmap_auth::authorization::TokenScope;
/// let known: TokenScope = "images:upload".parse().unwrap();
/// assert!(matches!(known, TokenScope::ImagesUpload));
/// assert_eq!(known.to_string(), "images:upload");
/// assert!("unknown:read".parse::<TokenScope>().is_err());
/// ```
#[derive(
	ConstParamTy, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize,
)]
pub enum TokenScope {
	/// Requests or grants `images:delete`.
	#[serde(rename = "images:delete")]
	ImagesDelete,
	/// Requests or grants `images:upload`.
	#[serde(rename = "images:upload")]
	ImagesUpload,
	/// Permits remote permission checks through `auth:check`.
	#[serde(rename = "auth:check")]
	AuthCheck,
	/// Requests or grants `auth:profiles:read`.
	#[serde(rename = "auth:profiles:read")]
	AuthProfilesRead,
	/// Requests or grants `auth:profiles:update`.
	#[serde(rename = "auth:profiles:update")]
	AuthProfilesUpdate,
}

serde_plain::derive_display_from_serialize!(TokenScope);
serde_plain::derive_fromstr_from_deserialize!(TokenScope);

/// Resource kind used in an authorization requirement.
///
/// Pair the resource UUID with the corresponding permission bitflags. JSON
/// uses lowercase names; see [`super::AuthorizationCheck`] for an example.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PermissionScope {
	/// A location; pair with [`super::LocationPermissions`].
	Location,
	/// An institution; pair with [`super::InstitutionPermissions`].
	Institution,
	/// Other scopes are preserved verbatim.
	#[serde(untagged)]
	Other(String),
}

serde_plain::derive_display_from_serialize!(PermissionScope);
serde_plain::derive_fromstr_from_deserialize!(PermissionScope);

impl From<String> for PermissionScope {
	fn from(value: String) -> Self {
		serde_plain::from_str(&value).unwrap_or(Self::Other(value))
	}
}

impl From<&str> for PermissionScope {
	fn from(value: &str) -> Self { Self::from(value.to_owned()) }
}

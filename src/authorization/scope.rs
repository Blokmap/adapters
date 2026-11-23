use serde::{Deserialize, Serialize};

/// Case-sensitive authorization scopes in `resource:permission` form.
///
/// Used when requesting service tokens and reading JWT grants. Known scopes
/// have named variants; custom service scopes keep their original strings in
/// [`Self::Other`]. `Display`, `FromStr`, and JSON share the same wire values.
///
/// ```
/// use blokmap_auth::authorization::TokenScope;
/// let known: TokenScope = "images:upload".into();
/// assert!(matches!(known, TokenScope::ImagesUpload));
/// let custom: TokenScope = "core:reports:read".into();
/// assert_eq!(custom.to_string(), "core:reports:read");
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
	/// Scopes belonging to other services are preserved verbatim.
	#[serde(untagged)]
	Other(String),
}

serde_plain::derive_display_from_serialize!(TokenScope);
serde_plain::derive_fromstr_from_deserialize!(TokenScope);



impl From<String> for TokenScope {
	fn from(value: String) -> Self {
		serde_plain::from_str(&value).unwrap_or(Self::Other(value))
	}
}

impl From<&str> for TokenScope {
	fn from(value: &str) -> Self { Self::from(value.to_owned()) }
}


/// Resource kind used in an authorization requirement.
///
/// Pair the resource UUID with the corresponding permission bitflags. JSON
/// uses lowercase names; see [`super::AuthorizationCheck`] for an example.
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PermissionScope {
	/// A location; pair with [`super::LocationPermissions`].
	Location,
	/// An institution; pair with [`super::InstitutionPermissions`].
	Institution,
}
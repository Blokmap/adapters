use serde::{Deserialize, Serialize};

/// Kind of subject shared by JWT sessions and authorization checks.
///
/// JSON and `FromStr` use `service`, `device`, and `profile`. JWT subjects
/// combine that prefix with a UUID, such as `profile:<uuid>`.
///
/// ```
/// use blokmap_auth::authorization::AuthorizationPrincipal;
/// let principal: AuthorizationPrincipal = "profile".parse().unwrap();
/// assert!(matches!(principal, AuthorizationPrincipal::Profile));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthorizationPrincipal {
	/// A backend service acting with its own identity.
	Service,
	/// A registered device.
	Device,
	/// An individual profile.
	Profile,
}

serde_plain::derive_display_from_serialize!(AuthorizationPrincipal);
serde_plain::derive_fromstr_from_deserialize!(AuthorizationPrincipal);

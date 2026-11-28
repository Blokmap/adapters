//! Permission checks against the authentication service.

#[cfg(feature = "authorization")]
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[cfg(feature = "authorization")]
use crate::Result;
#[cfg(feature = "authorization")]
use crate::authorization::TokenScope;
use crate::authorization::{AuthorizationPrincipal, PermissionScope};
#[cfg(feature = "authorization")]
use crate::client::{HttpAuthenticated, HttpClient};
#[cfg(feature = "authorization")]
use crate::config::BlokmapAdapterConfig;

#[cfg(feature = "authorization")]
const REQUIRED_SCOPES: &[TokenScope] = &[
	TokenScope::AuthCheck,
	TokenScope::AuthProfilesRead,
	TokenScope::AuthProfilesUpdate,
];

/// A permission or a nested combination of permissions.
///
/// Build rules locally and send them in an [`AuthorizationCheck`]. Evaluation
/// happens in the auth service. Untagged JSON is either an `any` object, an
/// `all` object, or a flat `{scope, id, permission}` object.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum AuthorizationRequirements {
	/// Requires at least one nested rule to pass.
	Any(Vec<Self>),
	/// Requires all nested rules to pass.
	All(Vec<Self>),
	/// Checks permission bits for one resource.
	Permission {
		/// Kind of resource whose permissions are being checked.
		scope:      PermissionScope,
		/// UUID of that resource.
		id:         Uuid,
		/// Required bits from the flag type matching `scope`.
		permission: i64,
	},
}

/// Request used to authorize one subject against a permission rule tree.
///
/// This shared model is available without the remote `authorization` client.
/// `subject` is only the UUID; its kind is in `principal`. A session supplies
/// these values as `session.sub` and `session.principal`.
///
/// ```
/// use blokmap_auth::authorization::{
/// 	AuthorizationCheck,
/// 	AuthorizationPrincipal,
/// 	AuthorizationRequirements,
/// 	LocationPermissions,
/// 	PermissionScope,
/// };
/// use uuid::Uuid;
/// let check = AuthorizationCheck {
/// 	subject:      Uuid::nil(),
/// 	principal:    AuthorizationPrincipal::Profile,
/// 	requirements: AuthorizationRequirements::Permission {
/// 		scope:      PermissionScope::Location,
/// 		id:         Uuid::nil(),
/// 		permission: LocationPermissions::ManageSettings.bits(),
/// 	},
/// };
/// ```
#[derive(Serialize, Deserialize)]
pub struct AuthorizationCheck {
	/// Subject UUID without a principal prefix.
	pub subject:      Uuid,
	/// Kind of subject represented by `subject`.
	pub principal:    AuthorizationPrincipal,
	/// Permission rule or nested tree evaluated by the remote auth service.
	pub requirements: AuthorizationRequirements,
}

/// Checks permissions against the authentication service.
///
/// Enable `authorization` and borrow `adapter.authorization()`.
/// The adapter owns its HTTP client and service-token cache. Cloned handles
/// share both, and tokens are obtained on first use.
///
/// ```no_run
/// use blokmap_auth::BlokmapAuthAdapter;
/// use blokmap_auth::authorization::AuthorizationCheck;
/// # async fn authorize(adapter: &BlokmapAuthAdapter, check: AuthorizationCheck) -> blokmap_auth::Result<()> {
/// adapter.authorization()?.check(check).await
/// # }
/// ```
#[derive(Clone)]
#[cfg(feature = "authorization")]
pub struct AuthorizationService {
	client: HttpClient<HttpAuthenticated>,
}

#[cfg(feature = "authorization")]
impl AuthorizationService {
	pub(crate) fn from_config(
		config: Arc<BlokmapAdapterConfig>,
	) -> Result<Self> {
		let client = HttpClient::<HttpAuthenticated>::from_config(
			config.require_auth_api_url()?.clone(),
			REQUIRED_SCOPES,
			config,
		)?;

		Ok(Self { client })
	}

	/// Checks permissions; non-success HTTP statuses are returned as errors.
	/// Sends the request to `/authorization/check` using managed credentials.
	/// Success is determined by the HTTP status; the body is not read.
	///
	/// # Errors
	///
	/// Non-success statuses are preserved in `Error::HttpStatus`. Token
	/// fetching, serialization, and transport failures propagate. A second 401
	/// following a token refresh produces `Error::Unauthenticated`.
	pub async fn check(&self, request: AuthorizationCheck) -> Result<()> {
		self.client.post("authorization/check", &request).await?;
		Ok(())
	}
}

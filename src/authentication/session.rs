use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::Error;
use crate::authentication::JwtToken;
use crate::authorization::{AuthorizationPrincipal, TokenScope};

/// Identity and scopes read from a verified JWT.
///
/// `JwtSession::try_from(claims)` splits the JWT subject into its principal and
/// UUID and moves its scopes into this value. It does not verify a signature:
/// first use [`JwtToken::verify`] with a local key or remote JWKS verification.
/// The Axum extractor verifies with the configured local key or remote JWKS
/// and parses the subject automatically. It reuses the
/// resulting session for scope guards and typed.cookie_name in that request.
///
/// Fields remain public for authorization checks and serialization. Returning
/// `Json(session)` produces `sub`, lowercase `principal`, and string `scopes`.
///
/// Use this type directly as an Axum handler argument. It reads
/// the configured cookie and needs no authentication fields in Axum state.
/// Invalid credentials reject with 401; configuration and upstream failures
/// follow the HTTP classification documented on [`Error`].
///
/// ```no_run
/// # fn example() {
/// use axum::Json;
/// use blokmap_auth::extractor::JwtSession;
/// async fn current_session(session: JwtSession) -> Json<JwtSession> {
/// 	Json(session)
/// }
/// # }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwtSession {
	/// The subject UUID, without its principal prefix.
	pub sub:       Uuid,
	/// Whether the subject identifies a service, device, or profile.
	pub principal: AuthorizationPrincipal,
	/// Scopes granted by the JWT issuer, available for application checks.
	pub scopes:    Vec<TokenScope>,
}

impl TryFrom<JwtToken> for JwtSession {
	type Error = Error;

	fn try_from(token: JwtToken) -> Result<Self, Self::Error> {
		let Some((principal, sub)) = token.sub.split_once(':') else {
			return Err(Error::InvalidJwtSubject);
		};

		let Ok(principal) = principal.parse() else {
			return Err(Error::InvalidJwtSubject);
		};

		let Ok(sub) = Uuid::parse_str(sub) else {
			return Err(Error::InvalidJwtSubject);
		};

		Ok(Self { sub, principal, scopes: token.scopes })
	}
}

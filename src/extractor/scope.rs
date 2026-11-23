//! Exact scope requirements for the [`Scope`] extractor.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use super::JwtSession;
use crate::authorization::TokenScope;
use crate::{Error, Result};

/// Axum extractor requiring one exact scope in a verified JWT.
///
/// The string const parameter accepts both known and custom scopes, such as
/// `Scope<"images:upload">` and `Scope<"core:reports:read">`, without marker
/// types. Compiling this crate requires nightly Rust for string const
/// parameters (`adt_const_params` and `unsized_const_params`).
///
/// Missing or invalid credentials reject with 401; a missing scope rejects
/// with 403. There are no wildcards or implied grants, including for admins.
/// Use several arguments to require multiple scopes. Verification is reused
/// by other session and scope extractors, and the body remains available.
///
/// ```no_run
/// use axum::routing::post;
/// use axum::{Json, Router};
/// use blokmap_auth::extractor::{ProfileSession, Scope};
///
/// async fn upload(
/// 	_: Scope<"images:upload">,
/// 	session: ProfileSession,
/// ) -> Json<ProfileSession> {
/// 	Json(session)
/// }
/// let app: Router = Router::new().route("/images", post(upload));
/// ```
#[derive(Clone, Copy, Debug)]
pub struct Scope<const REQUIRED: &'static str>(());

impl<S, const REQUIRED: &'static str> FromRequestParts<S> for Scope<REQUIRED>
where
	S: Send + Sync,
{
	type Rejection = Error;

	async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self> {
		let session = JwtSession::from_request_parts(parts, state).await?;
		let scope = TokenScope::from(REQUIRED);

		if !session.scopes.contains(&scope) {
			return Err(Error::MissingScope(scope));
		}

		Ok(Self(()))
	}
}

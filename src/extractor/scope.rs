//! Exact scope requirements for the [`Scope`] extractor.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use super::JwtSession;
use crate::authorization::TokenScope;
use crate::{Error, Result};

/// Axum extractor requiring one exact scope in a verified JWT.
///
/// Select a [`TokenScope`] variant, such as
/// `Scope<{ TokenScope::ImagesUpload }>`. Serde converts JWT scope strings to
/// these variants during verification. Compiling this crate requires nightly
/// Rust for enum const parameters (`adt_const_params`).
///
/// Missing or invalid credentials reject with 401; a missing scope rejects
/// with 403. There are no wildcards or implied grants, including for admins.
/// Use several arguments to require multiple scopes. Verification is reused
/// by other session and scope extractors, and the body remains available.
///
/// ```no_run
/// use std::sync::Arc;
///
/// use axum::routing::post;
/// use axum::{Json, Router};
/// use blokmap_auth::BlokmapAuthAdapter;
/// use blokmap_auth::authorization::TokenScope;
/// use blokmap_auth::extractor::{ProfileSession, Scope};
///
/// async fn upload(
/// 	_: Scope<{ TokenScope::ImagesUpload }>,
/// 	session: ProfileSession,
/// ) -> Json<ProfileSession> {
/// 	Json(session)
/// }
/// let app: Router<Arc<BlokmapAuthAdapter>> =
/// 	Router::new().route("/images", post(upload));
/// ```
#[derive(Clone, Copy, Debug)]
pub struct Scope<const REQUIRED: TokenScope>(());

impl<S, const REQUIRED: TokenScope> FromRequestParts<S> for Scope<REQUIRED>
where
	S: Send + Sync,
	JwtSession: FromRequestParts<S, Rejection = Error>,
{
	type Rejection = Error;

	async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self> {
		let session = JwtSession::from_request_parts(parts, state).await?;

		if !session.scopes.contains(&REQUIRED) {
			return Err(Error::MissingScope(REQUIRED));
		}

		Ok(Self(()))
	}
}

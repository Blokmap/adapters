//! Required scope markers for the [`Scope`] extractor.

use std::marker::PhantomData;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use super::JwtSession;
use crate::authorization::TokenScope;
use crate::{Error, Result};

/// Declares the exact scope required by a [`Scope`] extractor.
///
/// Built-in markers correspond to [`TokenScope`] variants. Implement this
/// trait on a marker type to require a custom scope:
///
/// ```
/// use blokmap_auth::authorization::TokenScope;
/// use blokmap_auth::extractor::Scope;
/// use blokmap_auth::extractor::scope::RequiredScope;
///
/// struct ReportsRead;
/// impl RequiredScope for ReportsRead {
/// 	fn scope() -> TokenScope { "core:reports:read".into() }
/// }
/// async fn reports(_: Scope<ReportsRead>) {}
/// ```
pub trait RequiredScope: Send + Sync {
	/// Returns the scope required by this marker.
	fn scope() -> TokenScope;
}

/// Axum extractor requiring one exact scope in a verified JWT.
///
/// Missing or invalid credentials reject with 401; a missing scope rejects
/// with 403. There are no wildcards or implied grants, including for admins.
/// Use several arguments to require multiple scopes. Verification is reused
/// by other session and scope extractors, and the body remains available.
///
/// ```no_run
/// use axum::routing::post;
/// use axum::{Json, Router};
/// use blokmap_auth::extractor::scope::ImagesUpload;
/// use blokmap_auth::extractor::{ProfileSession, Scope};
///
/// async fn upload(
/// 	_: Scope<ImagesUpload>,
/// 	session: ProfileSession,
/// ) -> Json<ProfileSession> {
/// 	Json(session)
/// }
/// let app: Router = Router::new().route("/images", post(upload));
/// ```
#[derive(Clone, Copy, Debug)]
pub struct Scope<T>(PhantomData<T>);

impl<S, T> FromRequestParts<S> for Scope<T>
where
	S: Send + Sync,
	T: RequiredScope,
{
	type Rejection = Error;

	async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self> {
		let session = JwtSession::from_request_parts(parts, state).await?;
		let scope = T::scope();

		if !session.scopes.contains(&scope) {
			return Err(Error::MissingScope(scope));
		}

		Ok(Self(PhantomData))
	}
}

macro_rules! scope_markers {
	($($name:ident),* $(,)?) => {
		$(
			#[doc = concat!("Requires [`TokenScope::", stringify!($name), "`].")]
			#[derive(Clone, Copy, Debug)]
			pub struct $name;

			impl RequiredScope for $name {
				fn scope() -> TokenScope { TokenScope::$name }
			}
		)*
	};
}

scope_markers!(
	ImagesDelete,
	ImagesUpload,
	AuthCheck,
	AuthProfilesRead,
	AuthProfilesUpdate,
);

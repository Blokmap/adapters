use std::ops::Deref;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum_extra::extract::CookieJar;
use serde::Serialize;

use crate::authentication::JwtSession;
use crate::authorization::AuthorizationPrincipal;
use crate::config::BlokmapAdapterConfig;
use crate::runtime::Runtime;
use crate::{Error, Result};

/// Axum extractor requiring a verified `profile:<uuid>` JWT in the cookie.
///
/// Initialize the library once; no authentication fields are needed in the
/// application's state. Verification checks the signature, issuer, audience,
/// and expiration using the configured local key or JWKS cache. Invalid tokens
/// reject with 401; another valid principal rejects with 403.
///
/// Dereferences to [`JwtSession`] for `sub`, `principal`, and `scopes`, and
/// serializes to the same JSON shape. Convert into `JwtSession` with `.into()`.
/// `ProfileSession::try_from(session)` checks the principal only; use it with
/// a session whose token has already been verified.
///
/// ```no_run
/// use axum::Json;
/// use blokmap_auth::extractor::ProfileSession;
/// async fn current_profile(session: ProfileSession) -> Json<ProfileSession> {
/// 	Json(session)
/// }
/// ```
#[derive(Clone, Debug, Serialize)]
#[serde(transparent)]
pub struct ProfileSession(JwtSession);

impl Deref for ProfileSession {
	type Target = JwtSession;

	fn deref(&self) -> &Self::Target { &self.0 }
}

/// Axum extractor requiring a verified `device:<uuid>` JWT in the cookie.
///
/// Uses the same configuration, verification key, and request-local
/// verification as [`ProfileSession`]. Missing or invalid tokens reject with
/// 401; another valid principal rejects with 403. Setup or upstream failures
/// use [`Error`]'s HTTP classification.
///
/// Dereferences to [`JwtSession`] and serializes to the same JSON shape. Use
/// `.into()` to obtain the underlying session. `DeviceSession::try_from`
/// checks only the principal of an already verified session.
///
/// ```no_run
/// use axum::Json;
/// use blokmap_auth::extractor::DeviceSession;
/// async fn current_device(session: DeviceSession) -> Json<DeviceSession> {
/// 	Json(session)
/// }
/// ```
#[derive(Clone, Debug, Serialize)]
#[serde(transparent)]
pub struct DeviceSession(JwtSession);

impl Deref for DeviceSession {
	type Target = JwtSession;

	fn deref(&self) -> &Self::Target { &self.0 }
}

impl TryFrom<JwtSession> for ProfileSession {
	type Error = Error;

	fn try_from(session: JwtSession) -> Result<Self> {
		if session.principal != AuthorizationPrincipal::Profile {
			return Err(Error::UnexpectedPrincipal);
		}
		Ok(Self(session))
	}
}

impl From<ProfileSession> for JwtSession {
	fn from(session: ProfileSession) -> Self { session.0 }
}

impl TryFrom<JwtSession> for DeviceSession {
	type Error = Error;

	fn try_from(session: JwtSession) -> Result<Self> {
		if session.principal != AuthorizationPrincipal::Device {
			return Err(Error::UnexpectedPrincipal);
		}
		Ok(Self(session))
	}
}

impl From<DeviceSession> for JwtSession {
	fn from(session: DeviceSession) -> Self { session.0 }
}

impl<S: Send + Sync> FromRequestParts<S> for JwtSession {
	type Rejection = Error;

	async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self> {
		if let Some(session) = parts.extensions.get::<Self>() {
			return Ok(session.clone());
		}

		let config = BlokmapAdapterConfig::global()?;

		let cookies = CookieJar::from_headers(&parts.headers);
		let cookie = cookies
			.get(&config.cookie_name)
			.ok_or(Error::MissingAccessToken)?;

		let token = Runtime::global()?.verify(cookie.value()).await?;
		let session = Self::try_from(token)?;

		parts.extensions.insert(session.clone());

		Ok(session)
	}
}

impl<S: Send + Sync> FromRequestParts<S> for ProfileSession {
	type Rejection = Error;

	async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self> {
		let session = JwtSession::from_request_parts(parts, state).await?;
		Self::try_from(session)
	}
}

impl<S: Send + Sync> FromRequestParts<S> for DeviceSession {
	type Rejection = Error;

	async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self> {
		let session = JwtSession::from_request_parts(parts, state).await?;
		Self::try_from(session)
	}
}

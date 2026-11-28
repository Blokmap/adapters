use std::ops::Deref;
use std::sync::Arc;

use axum::RequestPartsExt;
use axum::extract::{FromRef, FromRequestParts};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum_extra::TypedHeader;
use axum_extra::extract::CookieJar;
use axum_extra::headers::Authorization;
use axum_extra::headers::authorization::Bearer;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::authentication::JwtToken;
use crate::authorization::{AuthorizationPrincipal, TokenRole, TokenScope};
use crate::{BlokmapAuthAdapter, Error, Result};

/// Identity and scopes read from a verified JWT.
///
/// As an Axum extractor, reads `Authorization: Bearer <token>` or the
/// configured cookie, verifies the signature, issuer, audience, and expiration,
/// and parses the subject. Bearer headers support service, device, and profile
/// principals. An Authorization header takes precedence over the cookie;
/// malformed, duplicate, or invalid headers reject with 401 without falling
/// back to it. The cookie is used only when the Authorization header is absent.
///
/// The session is reused by other session and scope extractors within the
/// request. Axum state supplies `Arc<BlokmapAuthAdapter>` directly or through
/// `FromRef`. Each adapter's request verification is cached independently.
///
/// `JwtSession::try_from(claims)` only parses the principal and subject UUID;
/// first verify the claims with [`JwtToken::verify`] or remote JWKS
/// verification. Invalid credentials reject with 401; configuration and
/// upstream failures follow the HTTP classification documented on [`Error`].
///
/// Fields remain public for authorization checks and serialization. Returning
/// `Json(session)` produces `sub`, lowercase `principal`, and string `scopes`.
///
/// ```no_run
/// use axum::Json;
/// use blokmap_auth::extractor::JwtSession;
/// async fn current_session(session: JwtSession) -> Json<JwtSession> {
/// 	Json(session)
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwtSession {
	/// The subject UUID, without its principal prefix.
	pub sub:       Uuid,
	/// Whether the subject identifies a service, device, or profile.
	pub principal: AuthorizationPrincipal,
	/// Scopes granted by the JWT issuer, available for application checks.
	pub scopes:    Vec<TokenScope>,
	/// Roles granted by the JWT issuer, available for application checks.
	pub roles:     Vec<TokenRole>,
}

#[derive(Clone)]
struct VerifiedSession {
	adapter: Arc<BlokmapAuthAdapter>,
	session: JwtSession,
}

impl JwtSession {
	/// Whether this is a profile session with the administrator role.
	/// This does not imply any scope grant.
	#[must_use]
	pub fn is_admin(&self) -> bool {
		self.principal == AuthorizationPrincipal::Profile
			&& self.roles.contains(&TokenRole::Admin)
	}

	/// Whether this session belongs to the given profile.
	/// Admin sessions must also match the profile; use
	/// `session.is_admin() || session.is_profile(id)` to allow either.
	#[must_use]
	pub fn is_profile(&self, target_uuid: Uuid) -> bool {
		self.principal == AuthorizationPrincipal::Profile
			&& self.sub == target_uuid
	}
}

impl TryFrom<JwtToken> for JwtSession {
	type Error = Error;

	fn try_from(token: JwtToken) -> Result<Self> {
		let Some((principal, sub)) = token.sub.split_once(':') else {
			return Err(Error::InvalidJwtSubject);
		};

		let Ok(principal) = principal.parse() else {
			return Err(Error::InvalidJwtSubject);
		};

		let Ok(sub) = Uuid::parse_str(sub) else {
			return Err(Error::InvalidJwtSubject);
		};

		Ok(Self { sub, principal, scopes: token.scopes, roles: token.roles })
	}
}

/// Axum extractor requiring a verified `profile:<uuid>` JWT.
///
/// Accepts a Bearer header or the configured cookie, following [`JwtSession`]'s
/// credential precedence.
///
/// Supply the adapter through application state, as for [`JwtSession`].
/// Verification checks the signature, issuer, audience,
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

/// Axum extractor requiring a verified `profile:<uuid>` JWT with the
/// [admin role](TokenRole::Admin)
///
/// Accepts a Bearer header or the configured cookie, following [`JwtSession`]'s
/// credential precedence.
///
/// Supply the adapter through application state, as for [`JwtSession`].
/// Verification checks the signature, issuer, audience,
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
pub struct AdminSession(JwtSession);

impl Deref for AdminSession {
	type Target = JwtSession;

	fn deref(&self) -> &Self::Target { &self.0 }
}

/// Axum extractor requiring a verified `device:<uuid>` JWT.
///
/// Accepts a Bearer header or the configured cookie, following [`JwtSession`]'s
/// credential precedence.
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

impl TryFrom<JwtSession> for AdminSession {
	type Error = Error;

	fn try_from(session: JwtSession) -> Result<Self> {
		if session.principal != AuthorizationPrincipal::Profile {
			return Err(Error::UnexpectedPrincipal);
		}

		if !session.roles.contains(&TokenRole::Admin) {
			return Err(Error::MissingRole(TokenRole::Admin));
		}

		Ok(Self(session))
	}
}

impl From<AdminSession> for JwtSession {
	fn from(session: AdminSession) -> Self { session.0 }
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

impl<S> FromRequestParts<S> for JwtSession
where
	S: Send + Sync,
	Arc<BlokmapAuthAdapter>: FromRef<S>,
{
	type Rejection = Error;

	async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self> {
		let adapter = Arc::<BlokmapAuthAdapter>::from_ref(state);

		if let Some(cached) = parts.extensions.get::<VerifiedSession>()
			&& Arc::ptr_eq(&cached.adapter, &adapter)
		{
			return Ok(cached.session.clone());
		}

		let cookies = CookieJar::from_headers(&parts.headers);

		if parts.headers.get_all(AUTHORIZATION).iter().count() > 1 {
			return Err(Error::MalformedAuthorizationHeader);
		}

		let bearer: Option<TypedHeader<Authorization<Bearer>>> = parts
			.extract()
			.await
			.map_err(|_| Error::MalformedAuthorizationHeader)?;

		let access_token =
			match (&bearer, cookies.get(&adapter.config.cookie_name)) {
				(Some(header), _) => header.token(),
				(None, Some(cookie)) => cookie.value(),
				_ => return Err(Error::MissingAccessToken),
			};

		let jwt_token = adapter.verify(access_token).await?;
		let session = Self::try_from(jwt_token)?;

		parts
			.extensions
			.insert(VerifiedSession { adapter, session: session.clone() });

		Ok(session)
	}
}

impl<S> FromRequestParts<S> for ProfileSession
where
	S: Send + Sync,
	Arc<BlokmapAuthAdapter>: FromRef<S>,
{
	type Rejection = Error;

	async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self> {
		let session = JwtSession::from_request_parts(parts, state).await?;
		Self::try_from(session)
	}
}

impl<S> FromRequestParts<S> for AdminSession
where
	S: Send + Sync,
	Arc<BlokmapAuthAdapter>: FromRef<S>,
{
	type Rejection = Error;

	async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self> {
		let session = JwtSession::from_request_parts(parts, state).await?;
		Self::try_from(session)
	}
}

impl<S> FromRequestParts<S> for DeviceSession
where
	S: Send + Sync,
	Arc<BlokmapAuthAdapter>: FromRef<S>,
{
	type Rejection = Error;

	async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self> {
		let session = JwtSession::from_request_parts(parts, state).await?;
		Self::try_from(session)
	}
}

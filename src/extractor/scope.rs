use std::convert::Infallible;

use axum::extract::{FromRequestParts, Request};
use axum::http::request::Parts;
use axum::middleware::from_extractor_with_state;
use axum::response::Response;
use axum::routing::Route;
use tower::{Layer, Service};

use super::JwtSession;
use crate::authorization::TokenScope;
use crate::{Error, Result};

struct ScopeGuard;

impl FromRequestParts<TokenScope> for ScopeGuard {
	type Rejection = Error;

	async fn from_request_parts(
		parts: &mut Parts,
		scope: &TokenScope,
	) -> Result<Self> {
		let session = JwtSession::from_request_parts(parts, scope).await?;
		if !session.scopes.iter().any(|granted| granted == scope) {
			return Err(Error::MissingScope(scope.clone()));
		}

		Ok(Self)
	}
}

/// Requires one exact JWT scope before running an Axum controller.
///
/// Apply to a route or router with `.route_layer(...)`. Accepts a
/// [`TokenScope`] or a scope string, including custom scopes. Stack guards to
/// require several scopes; there is no wildcard or implication between scopes.
///
/// Reads the configured cookie and verifies the JWT with the local key or
/// remote JWKS. Controllers and guards reuse that session within the request.
/// The request body remains available for.cookie_name such as `Json`.
///
/// Missing or invalid tokens return 401; a missing scope returns 403. Setup
/// and upstream failures use [`Error`]'s HTTP classification.
///
/// ```no_run
/// use axum::Router;
/// use axum::routing::post;
/// use blokmap_auth::extractor::{ProfileSession, require_scope};
/// async fn upload(session: ProfileSession) {}
/// let app: Router = Router::new().route(
/// 	"/images",
/// 	post(upload).route_layer(require_scope("images:upload")),
/// );
/// ```
pub fn require_scope(
	scope: impl Into<TokenScope>,
) -> impl Layer<
	Route,
	Service: Service<
		Request,
		Response = Response,
		Error = Infallible,
		Future: Send + 'static,
	> + Clone
	             + Send
	             + Sync
	             + 'static,
> + Clone
+ Send
+ Sync
+ 'static {
	from_extractor_with_state::<ScopeGuard, _>(scope.into())
}

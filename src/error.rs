//! Adapter errors and HTTP response conversion.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::authorization::TokenScope;

/// Configuration, JWT validation, authorization, and transport failures.
///
/// Match the variants relevant to your application and keep a fallback arm:
/// enabled features determine which variants exist, and new variants may be
/// added. Wrapped errors retain their source through `std::error::Error`.
///
/// Returning this error from an Axum handler produces JSON containing
/// `blokmapCode`, `statusCode`, `message`, and optional `info`. Invalid
/// identity is 401, missing permissions are 403, setup errors are 500, and
/// transport and upstream HTTP failures are 503. Server-error messages hide
/// error details.
#[derive(Debug, thiserror::Error, Serialize)]
#[non_exhaustive]
#[serde(tag = "blokmapCode", content = "info", rename_all = "PascalCase")]
pub enum Error {
	/// The library has not been initialized.
	#[error("global BlokmapAuthAdapter has not been initialized")]
	AdapterNotInitialized,
	/// The library has already been initialized.
	#[error("global BlokmapAuthAdapter is already initialized")]
	AdapterAlreadyInitialized,
	/// Required settings are absent or invalid for an enabled capability.
	#[error("invalid auth configuration: {0}")]
	InvalidConfiguration(String),
	/// Signing, parsing, or validating a JWT failed.
	#[error("JWT error: {0}")]
	Jwt(
		#[from]
		#[serde(skip_serializing)]
		jsonwebtoken::errors::Error,
	),
	/// The configured request cookie is absent.
	#[error("missing access token")]
	MissingAccessToken,
	#[cfg(feature = "jwks")]
	/// Remote verification cannot select a key without a JWT `kid` header.
	#[error("JWT header is missing kid")]
	MissingJwtKeyId,
	/// A subject is not one of the supported principal prefixes plus a UUID.
	#[error(
		"JWT subject must be service:<uuid>, device:<uuid>, or profile:<uuid>"
	)]
	InvalidJwtSubject,
	#[cfg(feature = "jwks")]
	/// The current remote key set has no key matching this ID.
	#[error("JWKS key not found: {0}")]
	JwkNotFound(String),
	#[cfg(feature = "jwks")]
	/// The selected key is incompatible with Ed25519 signature verification.
	#[error("JWKS key is not an Ed25519 verification key: {0}")]
	InvalidJwk(String),
	/// A typed extractor received another valid principal kind.
	#[error("this endpoint requires a different session principal")]
	UnexpectedPrincipal,
	/// A valid session does not contain the required scope.
	#[error("missing required scope: {0}")]
	MissingScope(TokenScope),
	/// The token endpoint returned a token type other than Bearer.
	#[cfg(feature = "client")]
	#[error("unsupported token type: {0}")]
	UnsupportedTokenType(String),
	/// The token cannot be represented as an Authorization header.
	#[cfg(feature = "client")]
	#[error("invalid authorization header: {0}")]
	InvalidAuthorizationHeader(
		#[from]
		#[serde(skip_serializing)]
		reqwest::header::InvalidHeaderValue,
	),
	/// The HTTP client could not be initialized or a request failed.
	#[cfg(any(feature = "client", feature = "jwks"))]
	#[error("HTTP client error: {0}")]
	HttpClient(
		#[from]
		#[serde(skip_serializing)]
		reqwest::Error,
	),
	/// A configuration or request URL could not be parsed or resolved.
	#[error("invalid request URL: {0}")]
	InvalidRequestUrl(
		#[from]
		#[serde(skip_serializing)]
		url::ParseError,
	),
	/// The upstream returned a non-success status code.
	#[cfg(any(feature = "client", feature = "jwks"))]
	#[error("upstream returned HTTP status: {0}")]
	HttpStatus(#[serde(skip_serializing)] reqwest::StatusCode),
	/// The request was still unauthorized after refreshing its token.
	#[cfg(feature = "client")]
	#[error("authentication failed after refreshing the access token")]
	Unauthenticated,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorResponse<'a> {
	#[serde(flatten)]
	error:       &'a Error,
	status_code: u16,
	message:     String,
}

impl Error {
	/// HTTP classification used by this error's `IntoResponse` implementation.
	/// Upstream HTTP statuses remain available inside `HttpStatus`; the
	/// library classifies those failures as 503 when rendering a response.
	#[must_use]
	#[rustfmt::skip]
	pub fn status(&self) -> StatusCode {
		match self {
			Self::Jwt(_) | Self::InvalidJwtSubject => StatusCode::UNAUTHORIZED,
			#[cfg(feature = "jwks")]
			Self::MissingJwtKeyId
			| Self::JwkNotFound(_)
			| Self::InvalidJwk(_) => StatusCode::UNAUTHORIZED,
			Self::MissingAccessToken => StatusCode::UNAUTHORIZED,
			Self::UnexpectedPrincipal | Self::MissingScope(_) => {
				StatusCode::FORBIDDEN
			},
			#[cfg(feature = "client")]
			Self::Unauthenticated => StatusCode::UNAUTHORIZED,
			#[cfg(any(feature = "client", feature = "jwks"))]
			Self::HttpClient(_) | Self::HttpStatus(_) => {
				StatusCode::SERVICE_UNAVAILABLE
			},
			Self::AdapterNotInitialized
			| Self::AdapterAlreadyInitialized
			| Self::InvalidConfiguration(_) => {
				StatusCode::INTERNAL_SERVER_ERROR
			},
			Self::InvalidRequestUrl(_) => StatusCode::INTERNAL_SERVER_ERROR,
			#[cfg(feature = "client")]
			Self::UnsupportedTokenType(_)
			| Self::InvalidAuthorizationHeader(_) => {
				StatusCode::INTERNAL_SERVER_ERROR
			},
		}
	}
}

impl IntoResponse for Error {
	fn into_response(self) -> Response {
		let status = self.status();
		let message = if status.is_server_error() {
			status.canonical_reason().unwrap_or("Request failed").to_owned()
		} else {
			self.to_string()
		};
		let response = ErrorResponse {
			error: &self,
			status_code: status.as_u16(),
			message,
		};

		(status, Json(response)).into_response()
	}
}

/// A result using the authentication adapter's error type.
pub type Result<T> = std::result::Result<T, Error>;

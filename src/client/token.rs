use std::sync::Arc;

use arc_swap::ArcSwapOption;
use reqwest::Method;
use reqwest::header::HeaderValue;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use url::Url;
use url::form_urlencoded::byte_serialize;

use crate::authorization::TokenScope;
use crate::client::{HttpClient, HttpUnauthenticated};
use crate::config::BlokmapAdapterConfig;
use crate::{Error, Result};

const TOKEN_ENDPOINT: &str = "auth/service";

#[derive(Serialize)]
struct TokenRequest {
	grant_type: &'static str,
	#[serde(skip_serializing_if = "String::is_empty")]
	scope:      String,
}

impl From<&[TokenScope]> for TokenRequest {
	fn from(scopes: &[TokenScope]) -> Self {
		let scope = scopes
			.iter()
			.map(ToString::to_string)
			.collect::<Vec<_>>()
			.join(" ");

		Self { grant_type: "client_credentials", scope }
	}
}

#[derive(Deserialize)]
struct TokenResponse {
	access_token: String,
	token_type:   String,
}

/// A shared snapshot of an authorization header and its generation.
#[derive(Debug)]
pub(super) struct CachedAccessToken {
	/// The complete authorization header value, including the Bearer prefix.
	pub(super) value:      HeaderValue,
	/// The version used to detect whether the token has been replaced.
	pub(super) generation: u64,
}

/// Shares token snapshots and serializes token replacements.
pub(super) struct AccessTokenManager {
	/// The token snapshot, empty until the first authenticated request.
	current:      ArcSwapOption<CachedAccessToken>,
	/// Serializes the initial fetch and token refreshes.
	refresh_lock: Mutex<()>,
	/// Fetches service tokens without bearer authentication.
	client:       HttpClient<HttpUnauthenticated>,
	/// Scopes requested for the initial token and every refresh.
	scopes:       Vec<TokenScope>,
}

impl AccessTokenManager {
	/// Creates a manager without fetching a token.
	pub(super) fn new(auth_api_url: Url, scopes: &[TokenScope]) -> Self {
		let client = HttpClient::<HttpUnauthenticated>::new(auth_api_url);

		Self {
			current: ArcSwapOption::empty(),
			refresh_lock: Mutex::new(()),
			client,
			scopes: scopes.to_vec(),
		}
	}

	/// Returns the current token, fetching it on first use.
	pub(super) async fn current(&self) -> Result<Arc<CachedAccessToken>> {
		if let Some(token) = self.current.load_full() {
			return Ok(token);
		}

		self.try_refresh(None).await
	}

	/// Fetches a missing token or refreshes the specified generation.
	///
	/// Reuses newer snapshots and preserves the stored token on failure.
	///
	/// # Errors
	///
	/// Propagates token-fetch and header-validation errors.
	pub(super) async fn try_refresh(
		&self,
		used_generation: Option<u64>,
	) -> Result<Arc<CachedAccessToken>> {
		let _guard = self.refresh_lock.lock().await;

		let current = self.current.load_full();

		// Another request already fetched or refreshed the token.
		if let Some(token) = &current
			&& Some(token.generation) != used_generation
		{
			return Ok(token.clone());
		}

		// Only one request reaches this point at a time.
		let value = self.fetch().await?;

		let generation = current.map_or(0, |token| token.generation + 1);
		let next = Arc::new(CachedAccessToken { value, generation });

		self.current.store(Some(next.clone()));

		Ok(next)
	}

	/// Fetches and validates a Bearer token using client credentials.
	async fn fetch(&self) -> Result<HeaderValue> {
		let config = BlokmapAdapterConfig::global()?;
		let request = TokenRequest::from(self.scopes.as_slice());

		let client_id =
			byte_serialize(config.client_id.as_bytes()).collect::<String>();
		let client_secret =
			byte_serialize(config.client_secret.as_bytes()).collect::<String>();

		let response = self
			.client
			.build_request::<()>(TOKEN_ENDPOINT, None, Method::POST)?
			.basic_auth(client_id, Some(client_secret))
			.form(&request)
			.send()
			.await?;

		if !response.status().is_success() {
			return Err(Error::HttpStatus(response.status()));
		}

		let token: TokenResponse = response.json().await?;

		if !token.token_type.eq_ignore_ascii_case("Bearer") {
			return Err(Error::UnsupportedTokenType(token.token_type));
		}

		let mut value =
			HeaderValue::from_str(&format!("Bearer {}", token.access_token))?;
		value.set_sensitive(true);

		Ok(value)
	}
}

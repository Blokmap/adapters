//! Outgoing HTTP requests and service access tokens.

#[cfg(feature = "client")]
use std::sync::Arc;

#[cfg(feature = "client")]
use reqwest::StatusCode;
#[cfg(feature = "client")]
use reqwest::header::AUTHORIZATION;
use reqwest::{Client, Method, RequestBuilder, Response};
use serde::Serialize;
use url::Url;

#[cfg(feature = "client")]
use crate::authorization::TokenScope;
#[cfg(feature = "client")]
use crate::client::token::AccessTokenManager;
#[cfg(feature = "client")]
use crate::config::BlokmapAdapterConfig;
use crate::{Error, Result};

#[allow(async_fn_in_trait)]
/// Dispatches requests for the supported authentication states.
pub(super) trait HttpRequestHandler {
	/// Sends optional JSON `data` to `/{endpoint}` and checks its HTTP status.
	///
	/// # Errors
	///
	/// Propagates URL, HTTP, JSON, and refresh errors. Non-2xx responses yield
	/// [`Error::HttpStatus`]; an authenticated retry returning HTTP 401 yields
	/// `Error::Unauthenticated`.
	async fn request<D>(
		client: &HttpClient<Self>,
		endpoint: &str,
		data: Option<&D>,
		method: Method,
	) -> Result<Response>
	where
		Self: Sized,
		D: Serialize;
}

/// State of an [`HttpClient`] created with [`HttpClient::new`].
/// Requests carry no bearer token and do not trigger token fetching or retries.
/// Use this marker only when naming a client's type; no state setup is needed.
#[derive(Clone, Debug)]
pub struct HttpUnauthenticated;

impl HttpRequestHandler for HttpUnauthenticated {
	async fn request<D>(
		client: &HttpClient<Self>,
		endpoint: &str,
		data: Option<&D>,
		method: Method,
	) -> Result<Response>
	where
		D: Serialize,
	{
		let response =
			client.build_request(endpoint, data, method)?.send().await?;

		if !response.status().is_success() {
			return Err(Error::HttpStatus(response.status()));
		}

		Ok(response)
	}
}

/// State of an [`HttpClient`] created with [`HttpClient::authenticated`].
/// It owns a shared service-token cache. Cloning the client shares that cache
/// and its refresh coordination. Obtain this state through the factory;
/// consumers do not construct or manage tokens themselves.
#[derive(Clone)]
#[cfg(feature = "client")]
pub struct HttpAuthenticated {
	/// Shared token snapshots and refresh coordination.
	tokens: Arc<AccessTokenManager>,
}

#[cfg(feature = "client")]
impl HttpRequestHandler for HttpAuthenticated {
	async fn request<D>(
		client: &HttpClient<Self>,
		endpoint: &str,
		data: Option<&D>,
		method: Method,
	) -> Result<Response>
	where
		D: Serialize,
	{
		let tokens = &client.state.tokens;
		let token = tokens.current().await?;

		let mut response = client
			.build_request(endpoint, data, method.clone())?
			.header(AUTHORIZATION, token.value.clone())
			.send()
			.await?;

		if response.status() == StatusCode::UNAUTHORIZED {
			let token = tokens.try_refresh(Some(token.generation)).await?;

			response = client
				.build_request(endpoint, data, method)?
				.header(AUTHORIZATION, token.value.clone())
				.send()
				.await?;

			if response.status() == StatusCode::UNAUTHORIZED {
				return Err(Error::Unauthenticated);
			}
		}

		if !response.status().is_success() {
			return Err(Error::HttpStatus(response.status()));
		}

		Ok(response)
	}
}

/// Outgoing JSON requests with optional managed service authentication.
///
/// Use [`Self::new`] for unauthenticated requests, or [`Self::authenticated`]
/// after library initialization to send service credentials. Clones share the
/// connection pool and, for authenticated clients, the token cache.
///
/// Endpoints resolve at the base URL's origin: `items/1` and `/items/1` both
/// target `/items/1`, even if the base URL contains a path. Methods return the
/// successful `reqwest::Response`; read its body with `.json()`, `.text()`, or
/// `.bytes()`. Non-success statuses become [`Error::HttpStatus`].
///
/// Authenticated requests fetch a token lazily, then retry once after a 401
/// with a refreshed token. POST and PUT serialize their JSON payload again
/// for that retry. Other failures are not retried.
///
/// ```no_run
/// # #[cfg(feature = "client")]
/// # async fn example() -> blokmap_auth::Result<()> {
/// use blokmap_auth::client::HttpClient;
/// let client = HttpClient::new("https://images.example.com".parse()?);
/// let response = client.get("health").await?;
/// let text = response.text().await?;
/// # let _ = text;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct HttpClient<State = HttpUnauthenticated> {
	/// Reusable HTTP transport.
	client: Client,
	/// Base URL for resolving endpoints.
	base:   Url,
	/// Authentication state used for outgoing requests.
	#[cfg_attr(not(feature = "client"), allow(dead_code))]
	state:  State,
}

impl HttpClient<HttpUnauthenticated> {
	/// Creates an unauthenticated client for `base`, without initialization.
	///
	/// # Panics
	///
	/// Panics if TLS or system resolver initialization fails.
	#[must_use]
	pub fn new(base: Url) -> Self {
		let client = Client::new();
		Self { client, base, state: HttpUnauthenticated }
	}

	/// Creates a client using the initialized service credentials and `scopes`.
	/// Each new client has its own token cache; clone it to share that cache.
	/// Construction makes no HTTP requests. The first request obtains a token
	/// from `/auth/service`; a 401 refreshes it and retries once.
	///
	/// ```no_run
	/// use blokmap_auth::authorization::TokenScope;
	/// use blokmap_auth::client::HttpClient;
	/// # fn example() -> blokmap_auth::Result<()> {
	/// let images = HttpClient::authenticated(
	/// 	"https://images.example.com".parse()?,
	/// 	&[TokenScope::ImagesUpload],
	/// )?;
	/// # let _ = images;
	/// # Ok(())
	/// # }
	/// ```
	///
	/// # Errors
	///
	/// Returns [`Error::AdapterNotInitialized`] before [`crate::initialize`].
	///
	/// # Panics
	///
	/// Panics if TLS or system resolver initialization fails.
	#[cfg(feature = "client")]
	pub fn authenticated(
		base: Url,
		scopes: &[TokenScope],
	) -> Result<HttpClient<HttpAuthenticated>> {
		let config = BlokmapAdapterConfig::global()?;
		HttpClient::<HttpAuthenticated>::from_config(base, scopes, config)
	}
}

#[cfg(feature = "client")]
impl HttpClient<HttpAuthenticated> {
	pub(crate) fn from_config(
		base: Url,
		scopes: &[TokenScope],
		config: &BlokmapAdapterConfig,
	) -> Result<Self> {
		let client = Client::new();
		let tokens = Arc::new(AccessTokenManager::new(
			config.auth_api_url()?.clone(),
			scopes,
		));
		Ok(Self { client, base, state: HttpAuthenticated { tokens } })
	}
}

// State dispatch is internal; consumers use the two provided states.
#[allow(private_bounds)]
impl<State: HttpRequestHandler> HttpClient<State> {
	/// Builds a request to `/{endpoint}` with optional JSON data.
	///
	/// # Errors
	///
	/// Returns [`Error::InvalidRequestUrl`] if URL resolution fails.
	/// Serialization errors are stored in the returned builder.
	pub(super) fn build_request<D: Serialize>(
		&self,
		endpoint: &str,
		data: Option<&D>,
		method: Method,
	) -> Result<RequestBuilder> {
		let url = self
			.base
			.join(&format!("/{}", endpoint.trim_start_matches('/')))?;
		let mut request = self.client.request(method, url);

		if let Some(body) = data {
			request = request.json(body);
		}

		Ok(request)
	}

	/// Delegates a request to the authentication state's handler.
	///
	/// # Errors
	///
	/// Propagates errors from [`HttpRequestHandler::request`].
	async fn request<D>(
		&self,
		endpoint: &str,
		data: Option<&D>,
		method: Method,
	) -> Result<Response>
	where
		D: Serialize,
	{
		State::request(self, endpoint, data, method).await
	}

	/// Sends GET to an origin-relative endpoint and returns its success
	/// response.
	///
	/// # Errors
	///
	/// Propagates URL, transport, and token-fetch errors. Non-success statuses
	/// become [`Error::HttpStatus`]; a second authenticated 401 becomes
	/// `Error::Unauthenticated`.
	pub async fn get(&self, endpoint: &str) -> Result<Response> {
		self.request::<()>(endpoint, None, Method::GET).await
	}

	/// Sends JSON `data` via POST to an origin-relative endpoint.
	///
	/// # Errors
	///
	/// Fails on JSON serialization errors and the failures described by
	/// [`Self::get`]. An authenticated retry resends the JSON body.
	#[cfg(feature = "client")]
	pub async fn post<D>(&self, endpoint: &str, data: &D) -> Result<Response>
	where
		D: Serialize,
	{
		self.request(endpoint, Some(data), Method::POST).await
	}

	/// Sends JSON `data` via PUT to an origin-relative endpoint.
	///
	/// # Errors
	///
	/// Fails on JSON serialization errors and the failures described by
	/// [`Self::get`]. An authenticated retry resends the JSON body.
	#[cfg(feature = "client")]
	pub async fn put<D>(&self, endpoint: &str, data: &D) -> Result<Response>
	where
		D: Serialize,
	{
		self.request(endpoint, Some(data), Method::PUT).await
	}

	/// Sends DELETE to an origin-relative endpoint without a request body.
	///
	/// # Errors
	///
	/// Returns the failures described by [`Self::get`].
	#[cfg(feature = "client")]
	pub async fn delete(&self, endpoint: &str) -> Result<Response> {
		self.request::<()>(endpoint, None, Method::DELETE).await
	}
}

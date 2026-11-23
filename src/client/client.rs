//! Outgoing HTTP requests and service access tokens.

#[cfg(feature = "client")]
use std::sync::Arc;

use openidconnect::core::CoreProviderMetadata;
use openidconnect::{
	AsyncHttpClient,
	DiscoveryError,
	HttpClientError,
	HttpRequest,
	IssuerUrl,
};
#[cfg(feature = "client")]
use reqwest::StatusCode;
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
	/// Sends optional JSON `data` to the endpoint URL and checks its status.
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

/// State of an [`HttpClient`] created with
/// [`crate::BlokmapAuthAdapter::client`]. It owns a shared service-token cache.
/// Cloning the client shares that cache and its refresh coordination. Obtain
/// this state through the factory; consumers do not construct or manage tokens
/// themselves.
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
			.bearer_auth(&token.value)
			.send()
			.await?;

		if response.status() == StatusCode::UNAUTHORIZED {
			let token = tokens.try_refresh(Some(token.generation)).await?;

			response = client
				.build_request(endpoint, data, method)?
				.bearer_auth(&token.value)
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
/// Use [`Self::new`] for unauthenticated requests, or
/// `adapter.client(base, scopes)` with `client` enabled to send service
/// credentials. Clones share the connection pool and, for authenticated
/// clients, the token cache.
///
/// Endpoints resolve at the base URL's origin: `items/1` and `/items/1` both
/// target `/items/1`, even if the base URL contains a path. Methods return the
/// successful `reqwest::Response`; read its body with `.json()`, `.text()`, or
/// `.bytes()`. Non-success statuses become [`Error::HttpStatus`].
///
/// Authenticated requests fetch a token lazily, refresh it when `expires_in`
/// elapses, and retry once after a 401. POST and PUT serialize their payload
/// again for that retry. Other failures are not retried.
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

	pub(crate) fn for_oidc(base: Url) -> Result<Self> {
		let client = Client::builder()
			.redirect(reqwest::redirect::Policy::none())
			.build()?;

		Ok(Self { client, base, state: HttpUnauthenticated })
	}

	pub(crate) async fn get_url(&self, url: &Url) -> Result<Response> {
		HttpUnauthenticated::request::<()>(
			self,
			url.as_str(),
			None,
			Method::GET,
		)
		.await
	}

	pub(crate) async fn discover(
		&self,
		issuer: &IssuerUrl,
	) -> Result<CoreProviderMetadata> {
		let url = issuer.join(".well-known/openid-configuration")?;
		let metadata: CoreProviderMetadata =
			self.get_url(&url).await?.json().await?;

		if metadata.issuer() != issuer {
			return Err(DiscoveryError::Validation(
				"discovery issuer does not match the configured issuer".into(),
			)
			.into());
		}

		Ok(metadata)
	}
}

impl<'c> AsyncHttpClient<'c> for HttpClient<HttpUnauthenticated> {
	type Error = HttpClientError<reqwest::Error>;
	type Future = <Client as AsyncHttpClient<'c>>::Future;

	fn call(&'c self, request: HttpRequest) -> Self::Future {
		self.client.call(request)
	}
}

#[cfg(feature = "client")]
impl HttpClient<HttpAuthenticated> {
	pub(crate) fn from_config(
		base: Url,
		scopes: &[TokenScope],
		config: Arc<BlokmapAdapterConfig>,
	) -> Result<Self> {
		config.validate_client()?;

		let client = Client::new();
		let tokens = Arc::new(AccessTokenManager::new(config, scopes)?);

		Ok(Self { client, base, state: HttpAuthenticated { tokens } })
	}
}

// State dispatch is internal; consumers use the two provided states.
#[allow(private_bounds)]
impl<State: HttpRequestHandler> HttpClient<State> {
	/// Builds a request to an absolute URL with optional JSON data.
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
		let url = Url::parse(endpoint)?;
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
		let url = self
			.base
			.join(&format!("/{}", endpoint.trim_start_matches('/')))?;

		State::request(self, url.as_str(), data, method).await
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

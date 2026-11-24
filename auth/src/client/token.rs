use std::sync::Arc;

use arc_swap::ArcSwapOption;
use openidconnect::core::{CoreClient, CoreProviderMetadata, CoreTokenType};
use openidconnect::{ClientId, ClientSecret, OAuth2TokenResponse, Scope};
use tokio::sync::{Mutex, OnceCell};
use tokio::time::Instant;

use crate::authorization::TokenScope;
use crate::client::{HttpClient, HttpUnauthenticated};
use crate::config::BlokmapAdapterConfig;
use crate::{Error, Result};

/// A shared access token and its generation.
pub(super) struct CachedAccessToken {
	/// The access token, without the Bearer prefix.
	pub(super) value:      String,
	/// The version used to detect whether the token has been replaced.
	pub(super) generation: u64,
	expires_at:            Option<Instant>,
}

/// Shares token snapshots and serializes token replacements.
pub(super) struct AccessTokenManager {
	config:       Arc<BlokmapAdapterConfig>,
	/// The token snapshot, empty until the first authenticated request.
	current:      ArcSwapOption<CachedAccessToken>,
	/// Serializes the initial fetch and token refreshes.
	refresh_lock: Mutex<()>,
	client:       HttpClient<HttpUnauthenticated>,
	/// Provider endpoints; public keys are not needed to obtain access tokens.
	metadata:     OnceCell<CoreProviderMetadata>,
	/// Scopes requested for the initial token and every refresh.
	scopes:       Vec<Scope>,
}

impl AccessTokenManager {
	/// Creates a manager without fetching a token.
	pub(super) fn new(
		config: Arc<BlokmapAdapterConfig>,
		scopes: &[TokenScope],
	) -> Result<Self> {
		let client =
			HttpClient::for_oidc(config.require_auth_api_url()?.clone())?;
		let scopes =
			scopes.iter().map(|scope| Scope::new(scope.to_string())).collect();

		Ok(Self {
			config,
			current: ArcSwapOption::empty(),
			refresh_lock: Mutex::new(()),
			client,
			metadata: OnceCell::new(),
			scopes,
		})
	}

	/// Returns the current token, fetching it on first use.
	pub(super) async fn current(&self) -> Result<Arc<CachedAccessToken>> {
		if let Some(token) = self.current.load_full()
			&& token.expires_at.is_none_or(|expires| Instant::now() < expires)
		{
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
	/// Propagates token-fetch errors.
	pub(super) async fn try_refresh(
		&self,
		used_generation: Option<u64>,
	) -> Result<Arc<CachedAccessToken>> {
		let _guard = self.refresh_lock.lock().await;

		let current = self.current.load_full();

		// Another request already fetched or refreshed the token.
		if let Some(token) = &current
			&& token.expires_at.is_none_or(|expires| Instant::now() < expires)
			&& Some(token.generation) != used_generation
		{
			return Ok(token.clone());
		}

		let generation = current.map_or(0, |token| token.generation + 1);
		let next = Arc::new(self.fetch(generation).await?);

		self.current.store(Some(next.clone()));

		Ok(next)
	}

	/// Fetches and validates a Bearer token using client credentials.
	async fn fetch(&self, generation: u64) -> Result<CachedAccessToken> {
		let config = &self.config;
		let metadata = self
			.metadata
			.get_or_try_init(|| {
				async {
					let issuer = config.issuer()?;

					self.client.discover(&issuer).await
				}
			})
			.await?;

		let client = CoreClient::from_provider_metadata(
			metadata.clone(),
			ClientId::new(config.client_id.clone()),
			Some(ClientSecret::new(config.client_secret.clone())),
		);

		let requested_at = Instant::now();
		let token = client
			.exchange_client_credentials()
			.map_err(|error| Error::InvalidConfiguration(error.to_string()))?
			.add_scopes(self.scopes.clone())
			.request_async(&self.client)
			.await?;

		if token.token_type() != &CoreTokenType::Bearer {
			return Err(Error::UnsupportedTokenType(
				token.token_type().as_ref().into(),
			));
		}

		let value = token.access_token().secret().to_owned();

		let expires_at =
			token.expires_in().and_then(|ttl| requested_at.checked_add(ttl));

		Ok(CachedAccessToken { value, generation, expires_at })
	}
}

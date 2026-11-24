use std::sync::Arc;

#[cfg(feature = "jwks")]
use crate::authentication::JwksManager;
use crate::authentication::JwtToken;
#[cfg(feature = "authorization")]
use crate::authorization::AuthorizationService;
#[cfg(feature = "client")]
use crate::authorization::TokenScope;
#[cfg(feature = "client")]
use crate::client::{HttpAuthenticated, HttpClient};
use crate::config::BlokmapAdapterConfig;
use crate::{Error, Result};

/// Application-owned authentication settings, verification keys, and clients.
///
/// Create it with [`Self::builder`]. Construction validates the
/// configuration without making HTTP requests. Store it in an `Arc` to share
/// the adapter and its caches between request handlers.
pub struct BlokmapAuthAdapter {
	pub(crate) config: Arc<BlokmapAdapterConfig>,
	#[cfg(feature = "jwks")]
	jwks:              Option<JwksManager>,
	#[cfg(feature = "authorization")]
	authorization:     Option<AuthorizationService>,
}

impl BlokmapAuthAdapter {
	/// Starts a builder for this adapter's verification settings and clients.
	#[must_use]
	pub fn builder() -> BlokmapAdapterConfig { BlokmapAdapterConfig::default() }

	pub(crate) fn from_config(config: BlokmapAdapterConfig) -> Result<Self> {
		config.validate()?;

		let config = Arc::new(config);

		#[cfg(feature = "jwks")]
		let jwks = if config.verification_key.is_none() {
			Some(JwksManager::from_config(&config)?)
		} else {
			None
		};

		#[cfg(feature = "authorization")]
		let authorization = if config.client_id.is_empty() {
			None
		} else {
			Some(AuthorizationService::from_config(config.clone())?)
		};

		Ok(Self {
			config,
			#[cfg(feature = "jwks")]
			jwks,
			#[cfg(feature = "authorization")]
			authorization,
		})
	}

	/// Creates an outgoing client with this adapter's credentials and scopes.
	/// Clones of the returned client share its token cache and connection pool.
	#[cfg(feature = "client")]
	pub fn client(
		&self,
		base: url::Url,
		scopes: &[TokenScope],
	) -> Result<HttpClient<HttpAuthenticated>> {
		HttpClient::from_config(base, scopes, self.config.clone())
	}

	/// Borrows this adapter's permission client.
	/// Returns an invalid-configuration error when credentials were not
	/// supplied.
	#[cfg(feature = "authorization")]
	pub fn authorization(&self) -> Result<&AuthorizationService> {
		self.authorization.as_ref().ok_or_else(|| {
			Error::InvalidConfiguration(String::from(
				"client credentials are required for remote authorization",
			))
		})
	}

	/// Borrows this adapter's remote verification-key cache.
	/// Returns an invalid-configuration error when a local key is configured.
	#[cfg(feature = "jwks")]
	pub fn jwks(&self) -> Result<&JwksManager> {
		self.jwks.as_ref().ok_or_else(|| {
			Error::InvalidConfiguration(
				"local JWT verification is configured".into(),
			)
		})
	}

	/// Verifies a JWT with this adapter's issuer, audience, and local or remote
	/// key.
	pub async fn verify(&self, token: &str) -> Result<JwtToken> {
		if let Some(key) = &self.config.verification_key {
			return JwtToken::verify(
				token,
				key,
				&self.config.jwt_issuer,
				&self.config.jwt_audience,
			);
		}

		#[cfg(feature = "jwks")]
		{
			self.jwks()?.verify(token).await
		}
		#[cfg(not(feature = "jwks"))]
		{
			Err(Error::InvalidConfiguration(
				"JWT verification is not configured".into(),
			))
		}
	}
}

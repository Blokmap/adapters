//! Configuration builder for [`crate::initialize`].

use url::Url;

use crate::authentication::DecodingKey;
use crate::runtime::Runtime;
use crate::{Error, Result};

/// Settings for request verification and optional outgoing clients.
///
/// Use [`Self::new`] with an auth-service URL for remote capabilities.
/// Use [`Self::default`] with [`Self::verification_key`] when the application
/// owns its keys. Both paths use the same JWT expectations and cookie setting.
///
/// The `client` feature requires credentials and an auth-service URL.
/// With `jwks`, remote verification is configured unless a local key is
/// supplied. Without either verification backend, outgoing clients remain
/// usable, but session extraction returns a configuration error.
///
/// ```no_run
/// use blokmap_auth::authentication::DecodingKey;
/// use blokmap_auth::config::BlokmapAdapterConfig;
/// # fn startup(public_pem: &[u8]) -> blokmap_auth::Result<()> {
/// let config = BlokmapAdapterConfig::default()
/// 	.jwt("https://auth.example.com", "core")
/// 	.verification_key(DecodingKey::from_ed_pem(public_pem)?)
/// 	.cookie_name("session");
/// # let _ = config;
/// # Ok(())
/// # }
/// ```
pub struct BlokmapAdapterConfig {
	pub(crate) client_id:        String,
	pub(crate) client_secret:    String,
	#[cfg_attr(
		not(any(feature = "client", feature = "jwks")),
		allow(dead_code)
	)]
	pub(crate) auth_api_url:     Option<Url>,
	pub(crate) jwt_issuer:       String,
	pub(crate) jwt_audience:     String,
	pub(crate) verification_key: Option<DecodingKey>,
	pub(crate) cookie_name:      String,
}

impl Default for BlokmapAdapterConfig {
	fn default() -> Self {
		Self {
			client_id:        String::new(),
			client_secret:    String::new(),
			auth_api_url:     None,
			jwt_issuer:       String::new(),
			jwt_audience:     String::new(),
			verification_key: None,
			cookie_name:      "blokmap_auth".into(),
		}
	}
}

impl BlokmapAdapterConfig {
	/// Starts configuration with an auth-service URL and no credentials.
	/// Endpoints resolve at the URL's origin; its path is not an endpoint
	/// prefix. Use `default()` instead when only local-key verification is
	/// needed.
	pub fn new(auth_api_url: Url) -> Self {
		Self { auth_api_url: Some(auth_api_url), ..Self::default() }
	}

	/// Sets the OAuth credentials used by authenticated outgoing clients.
	/// Both values must be nonempty when `client` is enabled. Tokens are
	/// fetched from the configured authentication service and cached by
	/// clients.
	#[must_use]
	pub fn client_credentials(
		mut self,
		client_id: impl Into<String>,
		client_secret: impl Into<String>,
	) -> Self {
		self.client_id = client_id.into();
		self.client_secret = client_secret.into();
		self
	}

	/// Sets the exact expected issuer and accepted audience for.cookie_name.
	/// Both are required when configuring a local key or enabling `jwks`.
	/// Direct calls to `JwtToken::verify` take these expectations separately.
	#[must_use]
	pub fn jwt(
		mut self,
		issuer: impl Into<String>,
		audience: impl Into<String>,
	) -> Self {
		self.jwt_issuer = issuer.into();
		self.jwt_audience = audience.into();
		self
	}

	/// Uses a caller-supplied Ed25519 public key to verify request JWTs.
	///
	/// This takes precedence over remote JWKS, even when `jwks` is enabled.
	/// No key-fetching requests or key cache are used. The key is shared for
	/// the runtime's lifetime; issuer, audience, expiration, and algorithm
	/// checks still apply. The JWT `kid` is not needed to select this single
	/// local key.
	#[must_use]
	pub fn verification_key(mut self, key: DecodingKey) -> Self {
		self.verification_key = Some(key);
		self
	}

	/// Changes the cookie read by session extractors when no Authorization
	/// header is present; defaults to `blokmap_auth`. An empty name is rejected
	/// at initialization. This does not create, refresh, or modify response
	/// cookies.
	#[must_use]
	pub fn cookie_name(mut self, cookie_name: impl Into<String>) -> Self {
		self.cookie_name = cookie_name.into();
		self
	}

	pub(crate) fn validate(&self) -> Result<()> {
		#[cfg(feature = "client")]
		{
			self.auth_api_url()?;
			if self.client_id.is_empty() || self.client_secret.is_empty() {
				return Err(Error::InvalidConfiguration(
					"client credentials are required by the client feature"
						.into(),
				));
			}
		}

		let verifies_jwt = cfg!(feature = "jwks")
			|| self.verification_key.is_some()
			|| !self.jwt_issuer.is_empty()
			|| !self.jwt_audience.is_empty();

		if verifies_jwt {
			if self.jwt_issuer.is_empty() || self.jwt_audience.is_empty() {
				return Err(Error::InvalidConfiguration(
					"JWT verification requires an issuer and audience".into(),
				));
			}

			if self.verification_key.is_none() {
				#[cfg(feature = "jwks")]
				self.auth_api_url()?;
				#[cfg(not(feature = "jwks"))]
				return Err(Error::InvalidConfiguration(
					"a verification key is required when jwks is disabled"
						.into(),
				));
			}
		}

		if self.cookie_name.is_empty() {
			return Err(Error::InvalidConfiguration(
				"the session cookie name must not be empty".into(),
			));
		}

		Ok(())
	}

	#[cfg(any(feature = "client", feature = "jwks"))]
	pub(crate) fn auth_api_url(&self) -> Result<&Url> {
		self.auth_api_url.as_ref().ok_or_else(|| {
			Error::InvalidConfiguration(
				"an auth-service URL is required".into(),
			)
		})
	}

	pub(crate) fn global() -> Result<&'static Self> {
		Ok(&Runtime::global()?.config)
	}
}

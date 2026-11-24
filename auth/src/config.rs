//! Builder for an application-owned [`crate::BlokmapAuthAdapter`].

use url::Url;

use crate::authentication::DecodingKey;
use crate::{BlokmapAuthAdapter, Error, Result};

/// Configuration builder returned by [`BlokmapAuthAdapter::builder`].
///
/// Set [`Self::auth_api_url`] for outgoing clients. Use
/// [`Self::verification_key`] when the application owns its keys.
/// Both paths use the same JWT expectations and cookie setting.
///
/// Authenticated outgoing clients require credentials and an auth-service URL.
/// Enabling `client` alone does not require credentials for local verification.
/// With `jwks`, remote verification is configured unless a local key is
/// supplied. Without either verification backend, outgoing clients remain
/// usable, but session extraction returns a configuration error.
///
/// ```no_run
/// use blokmap_auth::BlokmapAuthAdapter;
/// use blokmap_auth::authentication::DecodingKey;
/// # fn startup(public_pem: &[u8]) -> blokmap_auth::Result<blokmap_auth::BlokmapAuthAdapter> {
/// let adapter = BlokmapAuthAdapter::builder()
/// 	.jwt("https://auth.example.com", "core", "session")
/// 	.verification_key(DecodingKey::from_ed_pem(public_pem)?)
/// 	.build()?;
/// # Ok(adapter)
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
	/// Sets the auth-service URL used by outgoing clients.
	/// Endpoints resolve at the URL's origin; its path is not an endpoint
	/// prefix. This is optional when only verifying request JWTs.
	#[must_use]
	pub fn auth_api_url(mut self, auth_api_url: Url) -> Self {
		self.auth_api_url = Some(auth_api_url);
		self
	}

	/// Sets the OAuth credentials used by authenticated outgoing clients.
	/// Both values must be nonempty to create authenticated clients. Tokens are
	/// obtained from the issuer's discovered token endpoint and cached by
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

	/// Sets the expected issuer, audience, and session cookie name.
	/// Remote verification discovers OIDC metadata from this issuer.
	/// All three values must be nonempty. The cookie is read only when no
	/// Authorization header is present; this does not modify response cookies.
	/// Direct calls to `JwtToken::verify` take issuer and audience separately.
	#[must_use]
	pub fn jwt(
		mut self,
		issuer: impl Into<String>,
		audience: impl Into<String>,
		cookie: impl Into<String>,
	) -> Self {
		self.jwt_issuer = issuer.into();
		self.jwt_audience = audience.into();
		self.cookie_name = cookie.into();
		self
	}

	/// Uses a caller-supplied Ed25519 public key to verify request JWTs.
	///
	/// This takes precedence over remote JWKS, even when `jwks` is enabled.
	/// No key-fetching requests or key cache are used. The key is shared for
	/// the adapter's lifetime; issuer, audience, expiration, and algorithm
	/// checks still apply. The JWT `kid` is not needed to select this single
	/// local key.
	#[must_use]
	pub fn verification_key(mut self, key: DecodingKey) -> Self {
		self.verification_key = Some(key);
		self
	}

	/// Validates these settings and builds an independent authentication
	/// adapter. No HTTP requests are made until a client or remote verifier is
	/// used.
	pub fn build(self) -> Result<BlokmapAuthAdapter> {
		BlokmapAuthAdapter::from_config(self)
	}

	pub(crate) fn validate(&self) -> Result<()> {
		#[cfg(feature = "client")]
		if !self.client_id.is_empty() || !self.client_secret.is_empty() {
			self.validate_client()?;
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

			#[cfg(not(feature = "jwks"))]
			if self.verification_key.is_none() {
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

	#[cfg(feature = "client")]
	pub(crate) fn validate_client(&self) -> Result<()> {
		self.require_auth_api_url()?;

		if self.client_id.is_empty() || self.client_secret.is_empty() {
			return Err(Error::InvalidConfiguration(
				"client credentials are required".into(),
			));
		}

		Ok(())
	}

	#[cfg(any(feature = "client", feature = "jwks"))]
	pub(crate) fn issuer(&self) -> Result<openidconnect::IssuerUrl> {
		if self.jwt_issuer.is_empty() {
			Ok(openidconnect::IssuerUrl::from_url(
				self.require_auth_api_url()?.clone(),
			))
		} else {
			Ok(openidconnect::IssuerUrl::new(self.jwt_issuer.clone())?)
		}
	}

	#[cfg(any(feature = "client", feature = "jwks"))]
	pub(crate) fn require_auth_api_url(&self) -> Result<&Url> {
		self.auth_api_url.as_ref().ok_or_else(|| {
			Error::InvalidConfiguration(
				"an auth-service URL is required".into(),
			)
		})
	}
}

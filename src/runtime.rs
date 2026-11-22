use std::sync::OnceLock;

#[cfg(feature = "jwks")]
use crate::authentication::JwksManager;
use crate::authentication::JwtToken;
#[cfg(feature = "authorization")]
use crate::authorization::AuthorizationService;
use crate::config::BlokmapAdapterConfig;
use crate::{Error, Result};

static RUNTIME: OnceLock<Runtime> = OnceLock::new();

pub(crate) struct Runtime {
	pub(crate) config:        BlokmapAdapterConfig,
	#[cfg(feature = "jwks")]
	pub(crate) jwks:          Option<JwksManager>,
	#[cfg(feature = "authorization")]
	pub(crate) authorization: AuthorizationService,
}

impl Runtime {
	pub(crate) fn global() -> Result<&'static Self> {
		RUNTIME.get().ok_or(Error::AdapterNotInitialized)
	}

	pub(crate) async fn verify(&self, token: &str) -> Result<JwtToken> {
		if let Some(key) = &self.config.verification_key {
			return JwtToken::verify(
				token,
				key,
				&self.config.jwt_issuer,
				&self.config.jwt_audience,
			);
		}

		#[cfg(feature = "jwks")]
		if let Some(jwks) = &self.jwks {
			return jwks.verify(token).await;
		}

		Err(Error::InvalidConfiguration(
			"JWT verification is not configured".into(),
		))
	}
}

/// Initializes request verification and enabled clients once.
///
/// Call before serving requests. A configured local verification key is used
/// directly, including when `jwks` is enabled. Otherwise, `jwks` discovers keys
/// lazily. Service tokens are also fetched on first use; startup itself makes
/// no HTTP requests. No authentication fields are needed in application state.
///
/// Signing and verifying directly with `JwtToken` need no initialization.
/// See the crate-level guide for local-key and remote-service examples.
///
/// # Errors
///
/// Returns [`Error::InvalidConfiguration`] without publishing partial state
/// when required settings are missing, or [`Error::AdapterAlreadyInitialized`]
/// after an earlier successful call. The runtime cannot be replaced or reset.
pub fn initialize(config: BlokmapAdapterConfig) -> Result<()> {
	if RUNTIME.get().is_some() {
		return Err(Error::AdapterAlreadyInitialized);
	}

	config.validate()?;

	#[cfg(feature = "jwks")]
	let jwks = if config.verification_key.is_none() {
		Some(JwksManager::from_config(&config)?)
	} else {
		None
	};
	#[cfg(feature = "authorization")]
	let authorization = AuthorizationService::from_config(&config)?;

	let runtime = Runtime {
		config,
		#[cfg(feature = "jwks")]
		jwks,
		#[cfg(feature = "authorization")]
		authorization,
	};

	RUNTIME.set(runtime).map_err(|_| Error::AdapterAlreadyInitialized)
}

use std::sync::Arc;

use arc_swap::ArcSwapOption;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::jwk::{
	AlgorithmParameters,
	EllipticCurve,
	JwkSet,
	KeyAlgorithm,
	KeyOperations,
	PublicKeyUse,
};
use jsonwebtoken::{Algorithm, DecodingKey, decode_header};
use tokio::sync::Mutex;
use tokio::time::Instant;

use crate::authentication::JwtToken;
use crate::client::{HttpClient, HttpUnauthenticated};
use crate::config::BlokmapAdapterConfig;
use crate::runtime::Runtime;
use crate::{Error, Result};

const JWKS_ENDPOINT: &str = ".well-known/jwks.json";
const REFRESH_INTERVAL_SECS: u64 = 10 * 60;

struct CachedJwks {
	keys:       JwkSet,
	fetched_at: Instant,
}

/// Remote Ed25519 verification using the configured auth service's JWKS.
///
/// Enable `jwks`, initialize the library, and borrow [`Self::global`] to verify
/// raw tokens outside Axum. JwtSession.cookie_name use this cache
/// automatically. Auth servers that already own their keys should use
/// `JwtToken::verify` directly or configure a local verification key for
/// request.cookie_name.
///
/// Keys are fetched lazily from `/.well-known/jwks.json`. The first request
/// after ten minutes refreshes them; concurrent requests share that refresh.
/// An unknown `kid` does not force an early refresh. Fetch failures propagate
/// and expired key snapshots are not used for verification.
///
/// ```no_run
/// use blokmap_auth::authentication::{JwksManager, JwtSession};
/// # async fn read(token: &str) -> blokmap_auth::Result<JwtSession> {
/// let claims = JwksManager::global()?.verify(token).await?;
/// JwtSession::try_from(claims)
/// # }
/// ```
pub struct JwksManager {
	current:      ArcSwapOption<CachedJwks>,
	refresh_lock: Mutex<()>,
	client:       HttpClient,
}

impl JwksManager {
	/// Borrows the shared remote cache created by `initialize`.
	/// Returns [`Error::AdapterNotInitialized`] before initialization, or
	/// [`Error::InvalidConfiguration`] when a local verification key is used.
	pub fn global() -> Result<&'static Self> {
		Runtime::global()?.jwks.as_ref().ok_or_else(|| {
			Error::InvalidConfiguration(
				"local JWT verification is configured".into(),
			)
		})
	}

	pub(crate) fn from_config(config: &BlokmapAdapterConfig) -> Result<Self> {
		let client = HttpClient::<HttpUnauthenticated>::new(
			config.auth_api_url()?.clone(),
		);

		Ok(Self {
			current: ArcSwapOption::empty(),
			refresh_lock: Mutex::new(()),
			client,
		})
	}

	/// Verifies a JWT with the configured issuer, audience, and cached key.
	/// Requires an EdDSA header and `kid`, then checks the signature and claims
	/// with the matching public verification key. It returns claims rather
	/// than a session; use `JwtSession::try_from` to parse the subject
	/// afterwards.
	///
	/// # Errors
	///
	/// Reports malformed tokens or rejected claims as [`Error::Jwt`], a missing
	/// ID as [`Error::MissingJwtKeyId`], an unknown ID as
	/// [`Error::JwkNotFound`], and incompatible key metadata as
	/// [`Error::InvalidJwk`]. Requests needed to load keys can also return
	/// transport or upstream status errors.
	pub async fn verify(&self, token: &str) -> Result<JwtToken> {
		let config = BlokmapAdapterConfig::global()?;
		let header = decode_header(token)?;

		if header.alg != Algorithm::EdDSA {
			return Err(Error::Jwt(ErrorKind::InvalidAlgorithm.into()));
		}

		let kid = header.kid.ok_or(Error::MissingJwtKeyId)?;
		let key = self.public_key(&kid).await?;

		JwtToken::verify(token, &key, &config.jwt_issuer, &config.jwt_audience)
	}

	/// Gets an Ed25519 verification key by `kid`.
	async fn public_key(&self, kid: &str) -> Result<DecodingKey> {
		let current = self.current().await?;

		let Some(key) = current.keys.find(kid) else {
			return Err(Error::JwkNotFound(kid.to_owned()));
		};

		let valid_curve = matches!(
			&key.algorithm,
			AlgorithmParameters::OctetKeyPair(params)
				if params.curve == EllipticCurve::Ed25519
		);

		let valid_algorithm = matches!(
			key.common.key_algorithm,
			None | Some(KeyAlgorithm::EdDSA)
		);

		let valid_usage = matches!(
			key.common.public_key_use,
			None | Some(PublicKeyUse::Signature)
		);

		let can_verify =
			key.common.key_operations.as_ref().is_none_or(|operations| {
				operations
					.iter()
					.any(|operation| matches!(operation, KeyOperations::Verify))
			});

		if !valid_curve || !valid_algorithm || !valid_usage || !can_verify {
			return Err(Error::InvalidJwk(kid.to_owned()));
		}

		Ok(DecodingKey::from_jwk(key)?)
	}

	fn cached(&self) -> Option<Arc<CachedJwks>> {
		self.current.load_full().filter(|current| {
			current.fetched_at.elapsed().as_secs() < REFRESH_INTERVAL_SECS
		})
	}

	async fn current(&self) -> Result<Arc<CachedJwks>> {
		if let Some(current) = self.cached() {
			return Ok(current);
		}

		let _guard = self.refresh_lock.lock().await;
		if let Some(current) = self.cached() {
			return Ok(current);
		}

		let keys = self.client.get(JWKS_ENDPOINT).await?.json().await?;
		let fetched_at = Instant::now();
		let current = Arc::new(CachedJwks { keys, fetched_at });
		self.current.store(Some(current.clone()));
		Ok(current)
	}
}

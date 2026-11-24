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
use openidconnect::IssuerUrl;
use tokio::sync::Mutex;
use tokio::time::Instant;

use crate::authentication::JwtToken;
use crate::client::{HttpClient, HttpUnauthenticated};
use crate::config::BlokmapAdapterConfig;
use crate::{Error, Result};

const REFRESH_INTERVAL_SECS: u64 = 10 * 60;

struct CachedJwks {
	keys:       JwkSet,
	fetched_at: Instant,
}

/// Remote Ed25519 verification using the configured auth service's JWKS.
///
/// Enable `jwks`, build an adapter, and borrow `adapter.jwks()` to
/// verify raw tokens outside Axum. Session extractors use this cache
/// automatically. Auth servers that already own their keys should use
/// `JwtToken::verify` directly or configure a local verification key for
/// request verification.
///
/// The issuer's OIDC metadata supplies `jwks_uri`. The library's HTTP client
/// fetches the keys into an `ArcSwap` snapshot. The first request after ten
/// minutes refreshes them; concurrent requests share that refresh.
/// An unknown `kid` does not force an early refresh. Fetch failures propagate
/// and expired key snapshots are not used for verification.
///
/// ```no_run
/// # #[cfg(feature = "jwks")]
/// # async fn read(adapter: &blokmap_auth::BlokmapAuthAdapter, token: &str) -> blokmap_auth::Result<blokmap_auth::extractor::JwtSession> {
/// use blokmap_auth::extractor::JwtSession;
/// let claims = adapter.jwks()?.verify(token).await?;
/// JwtSession::try_from(claims)
/// # }
/// ```
pub struct JwksManager {
	current:      ArcSwapOption<CachedJwks>,
	refresh_lock: Mutex<()>,
	client:       HttpClient<HttpUnauthenticated>,
	issuer:       IssuerUrl,
	audience:     String,
}

impl JwksManager {
	pub(crate) fn from_config(config: &BlokmapAdapterConfig) -> Result<Self> {
		let issuer = config.issuer()?;
		let client = HttpClient::for_oidc(issuer.url().clone())?;

		Ok(Self {
			current: ArcSwapOption::empty(),
			refresh_lock: Mutex::new(()),
			client,
			issuer,
			audience: config.jwt_audience.clone(),
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
		let header = decode_header(token)?;

		if header.alg != Algorithm::EdDSA {
			return Err(Error::Jwt(ErrorKind::InvalidAlgorithm.into()));
		}

		let kid = header.kid.ok_or(Error::MissingJwtKeyId)?;
		let key = self.public_key(&kid).await?;

		JwtToken::verify(token, &key, self.issuer.as_str(), &self.audience)
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

		let current = Arc::new(self.fetch().await?);

		self.current.store(Some(current.clone()));

		Ok(current)
	}

	async fn fetch(&self) -> Result<CachedJwks> {
		let metadata = self.client.discover(&self.issuer).await?;
		let url = metadata.jwks_uri().url().clone();

		let keys = self.client.get_url(&url).await?.json().await?;

		let fetched_at = Instant::now();

		Ok(CachedJwks { keys, fetched_at })
	}
}

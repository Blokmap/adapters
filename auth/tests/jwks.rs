#![cfg(feature = "jwks")]

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::http::HeaderMap;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::routing::get;
use axum::{Json, Router};
use blokmap_auth::authentication::{DecodingKey, EncodingKey, JwtToken};
use blokmap_auth::{BlokmapAuthAdapter, Error};
use jsonwebtoken::jwk::{
	Jwk,
	JwkSet,
	KeyAlgorithm,
	KeyOperations,
	PublicKeyUse,
};
use jsonwebtoken::{Algorithm, Header, encode, get_current_timestamp};
use reqwest::StatusCode;
use tokio::net::TcpListener;
use url::Url;
use uuid::Uuid;

mod common;

async fn timed<T>(future: impl Future<Output = T>) -> T {
	tokio::time::timeout(Duration::from_secs(3), future)
		.await
		.expect("JWKS request should complete")
}

async fn advance(seconds: u64) {
	tokio::time::pause();
	tokio::time::advance(Duration::from_secs(seconds)).await;
	tokio::time::resume();
}

fn jwk(kid: &str, pem: &[u8]) -> Jwk {
	let key = DecodingKey::from_ed_pem(pem).unwrap();
	let mut jwk = Jwk::from_decoding_key(&key, Some(Algorithm::EdDSA)).unwrap();

	jwk.common.key_id = Some(kid.into());
	jwk.common.public_key_use = Some(PublicKeyUse::Signature);
	jwk.common.key_operations = Some(vec![KeyOperations::Verify]);

	jwk
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn jwks_is_lazy_shared_and_refreshed_after_ten_minutes() {
	let first = jwk("first", include_bytes!("keys/ed25519-public.pem"));
	let second = jwk("second", include_bytes!("keys/ed25519-other-public.pem"));

	let mut encryption = first.clone();
	encryption.common.key_id = Some("encryption".into());
	encryption.common.public_key_use = Some(PublicKeyUse::Encryption);

	let mut signing = first.clone();
	signing.common.key_id = Some("sign-only".into());
	signing.common.key_operations = Some(vec![KeyOperations::Sign]);

	let mut wrong_algorithm = first.clone();
	wrong_algorithm.common.key_id = Some("wrong-algorithm".into());
	wrong_algorithm.common.key_algorithm = Some(KeyAlgorithm::HS256);

	let initial = serde_json::to_string(&JwkSet {
		keys: vec![first, encryption, signing, wrong_algorithm],
	})
	.unwrap();
	let rotated =
		serde_json::to_string(&JwkSet { keys: vec![second] }).unwrap();

	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let base =
		Url::parse(&format!("http://{}", listener.local_addr().unwrap()))
			.unwrap();
	let discovery = common::metadata(base.as_str());

	let adapter = BlokmapAuthAdapter::builder()
		.auth_api_url(base.clone())
		.client_credentials("client", "secret")
		.jwt(base.as_str(), "core", "session")
		.build()
		.unwrap();

	let requests = Arc::new(AtomicUsize::new(0));
	let recorded = requests.clone();

	let responses = [
		(StatusCode::OK, initial),
		(StatusCode::SERVICE_UNAVAILABLE, String::new()),
		(StatusCode::OK, rotated.clone()),
		(StatusCode::SERVICE_UNAVAILABLE, String::new()),
		(StatusCode::OK, rotated),
	];

	let app = Router::new()
		.route(
			"/.well-known/openid-configuration",
			get(move |headers: HeaderMap| {
				assert!(!headers.contains_key(AUTHORIZATION));

				let discovery = discovery.clone();

				async move { Json(discovery) }
			}),
		)
		.route(
			"/.well-known/jwks.json",
			get(move |headers: HeaderMap| {
				assert!(!headers.contains_key(AUTHORIZATION));

				let index = recorded.fetch_add(1, Ordering::SeqCst);
				let (status, body) = responses[index].clone();

				async move { (status, [(CONTENT_TYPE, "application/json")], body) }
			}),
		);

	let server = tokio::spawn(async move {
		axum::serve(listener, app).await.unwrap();
	});

	let manager = adapter.jwks().unwrap();
	assert_eq!(requests.load(Ordering::SeqCst), 0);

	let now = get_current_timestamp();
	let claims = JwtToken {
		iss:    base.to_string(),
		sub:    "profile:019ab123-4567-7890-abcd-123456789abc".into(),
		aud:    vec!["core".into()],
		exp:    now + 3600,
		iat:    now,
		jti:    Uuid::nil(),
		scopes: vec!["images:upload".parse().unwrap()],
		roles:  vec![],
	};

	let private =
		EncodingKey::from_ed_pem(include_bytes!("keys/ed25519-private.pem"))
			.unwrap();
	let missing_kid =
		encode(&Header::new(Algorithm::EdDSA), &claims, &private).unwrap();

	assert!(matches!(
		manager.verify(&missing_kid).await,
		Err(Error::MissingJwtKeyId)
	));
	assert_eq!(requests.load(Ordering::SeqCst), 0);

	let token = claims.sign("first", &private).unwrap();
	let (first, second) = timed(async {
		tokio::join!(manager.verify(&token), manager.verify(&token))
	})
	.await;

	first.unwrap();
	second.unwrap();
	assert_eq!(requests.load(Ordering::SeqCst), 1);

	timed(manager.verify(&token)).await.unwrap();

	for kid in ["encryption", "sign-only", "wrong-algorithm"] {
		assert!(matches!(
			manager.verify(&claims.sign(kid, &private).unwrap()).await,
			Err(Error::InvalidJwk(_))
		));
	}

	assert!(matches!(
		manager.verify(&claims.sign("missing", &private).unwrap()).await,
		Err(Error::JwkNotFound(_))
	));

	advance(599).await;
	timed(manager.verify(&token)).await.unwrap();
	assert_eq!(requests.load(Ordering::SeqCst), 1);

	advance(1).await;
	assert!(matches!(
		timed(manager.verify(&token)).await,
		Err(Error::HttpStatus(StatusCode::SERVICE_UNAVAILABLE))
	));

	let private = EncodingKey::from_ed_pem(include_bytes!(
		"keys/ed25519-other-private.pem"
	))
	.unwrap();
	let rotated = claims.sign("second", &private).unwrap();

	timed(manager.verify(&rotated)).await.unwrap();
	assert_eq!(requests.load(Ordering::SeqCst), 3);
	assert!(matches!(manager.verify(&token).await, Err(Error::JwkNotFound(_))));
	assert_eq!(requests.load(Ordering::SeqCst), 3);

	advance(600).await;
	assert!(matches!(
		timed(manager.verify(&rotated)).await,
		Err(Error::HttpStatus(StatusCode::SERVICE_UNAVAILABLE))
	));

	timed(manager.verify(&rotated)).await.unwrap();
	assert_eq!(requests.load(Ordering::SeqCst), 5);

	server.abort();
	let _ = server.await;
}

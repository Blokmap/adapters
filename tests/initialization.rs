use axum::extract::FromRequestParts;
use axum::http::Request;
use blokmap_auth::Error;
use blokmap_auth::authentication::{EncodingKey, JwtSession, JwtToken};
use blokmap_auth::config::BlokmapAdapterConfig;

#[tokio::test]
async fn initialization_is_atomic_and_local_verification_bypasses_jwks() {
	let base = "https://auth.blokmap.com".parse().unwrap();
	assert!(matches!(
		blokmap_auth::initialize(
			BlokmapAdapterConfig::new(base).jwt("", "core")
		),
		Err(Error::InvalidConfiguration(_))
	));
	let config =
		BlokmapAdapterConfig::new("https://auth.blokmap.com".parse().unwrap());
	#[cfg(feature = "client")]
	let config = config.client_credentials("client", "secret");
	let key = blokmap_auth::authentication::DecodingKey::from_ed_pem(
		include_bytes!("keys/ed25519-public.pem"),
	)
	.unwrap();
	let config =
		config.jwt("https://auth.blokmap.com", "core").verification_key(key);
	blokmap_auth::initialize(config).unwrap();
	#[cfg(feature = "jwks")]
	assert!(matches!(
		blokmap_auth::authentication::JwksManager::global(),
		Err(Error::InvalidConfiguration(_))
	));
	let now = jsonwebtoken::get_current_timestamp();
	let claims = JwtToken {
		iss:    "https://auth.blokmap.com".into(),
		sub:    format!("profile:{}", uuid::Uuid::nil()),
		aud:    vec!["core".into()],
		exp:    now + 600,
		iat:    now,
		jti:    uuid::Uuid::nil(),
		scopes: vec![],
	};
	let key =
		EncodingKey::from_ed_pem(include_bytes!("keys/ed25519-private.pem"))
			.unwrap();
	let token = claims.sign("local-key", &key).unwrap();
	let (mut parts, _) = Request::builder()
		.header("cookie", format!("blokmap_auth={token}"))
		.body(())
		.unwrap()
		.into_parts();
	let session =
		JwtSession::from_request_parts(&mut parts, &()).await.unwrap();
	assert_eq!(session.sub, uuid::Uuid::nil());
	assert!(matches!(
		blokmap_auth::initialize(BlokmapAdapterConfig::new(
			"https://auth.blokmap.com".parse().unwrap()
		)),
		Err(Error::AdapterAlreadyInitialized)
	));
}

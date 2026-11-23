use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::Request;
use blokmap_auth::authentication::{DecodingKey, EncodingKey, JwtToken};
use blokmap_auth::authorization::AuthorizationPrincipal;
use blokmap_auth::extractor::JwtSession;
use blokmap_auth::{BlokmapAuthAdapter, Error};
use jsonwebtoken::get_current_timestamp;
use uuid::Uuid;

const ISSUER: &str = "https://auth.blokmap.com";

#[tokio::test]
async fn adapters_verify_independently_and_scope_request_caches() {
	assert!(matches!(
		BlokmapAuthAdapter::builder().jwt("", "core", "session").build(),
		Err(Error::InvalidConfiguration(_))
	));

	let public_key =
		DecodingKey::from_ed_pem(include_bytes!("keys/ed25519-public.pem"))
			.unwrap();
	let first = BlokmapAuthAdapter::builder()
		.jwt(ISSUER, "core", "session")
		.verification_key(public_key)
		.build()
		.unwrap();

	let other_key = DecodingKey::from_ed_pem(include_bytes!(
		"keys/ed25519-other-public.pem"
	))
	.unwrap();
	let second = BlokmapAuthAdapter::builder()
		.jwt("https://other.example.com", "images", "other_session")
		.verification_key(other_key)
		.build()
		.unwrap();

	let first = Arc::new(first);
	let second = Arc::new(second);

	#[cfg(feature = "client")]
	assert!(matches!(
		first.client("https://resource.example.com".parse().unwrap(), &[]),
		Err(Error::InvalidConfiguration(_))
	));

	#[cfg(feature = "authorization")]
	assert!(matches!(
		first.authorization(),
		Err(Error::InvalidConfiguration(_))
	));

	#[cfg(feature = "jwks")]
	assert!(matches!(first.jwks(), Err(Error::InvalidConfiguration(_))));

	let now = get_current_timestamp();
	let claims = JwtToken {
		iss:    ISSUER.into(),
		sub:    format!("profile:{}", Uuid::nil()),
		aud:    vec!["core".into()],
		exp:    now + 600,
		iat:    now,
		jti:    Uuid::nil(),
		scopes: vec![],
		roles:  vec![],
	};

	let private_key =
		EncodingKey::from_ed_pem(include_bytes!("keys/ed25519-private.pem"))
			.unwrap();
	let token = claims.sign("local-key", &private_key).unwrap();

	let other_claims = JwtToken {
		iss: "https://other.example.com".into(),
		sub: format!("device:{}", Uuid::from_u128(1)),
		aud: vec!["images".into()],
		..claims
	};
	let other_private = EncodingKey::from_ed_pem(include_bytes!(
		"keys/ed25519-other-private.pem"
	))
	.unwrap();
	let other_token = other_claims.sign("other-key", &other_private).unwrap();

	assert!(second.verify(&token).await.is_err());
	assert!(first.verify(&other_token).await.is_err());

	let (mut parts, _) = Request::builder()
		.header(
			"cookie",
			format!("session={token}; other_session={other_token}"),
		)
		.body(())
		.unwrap()
		.into_parts();

	let session =
		JwtSession::from_request_parts(&mut parts, &first).await.unwrap();

	assert_eq!(session.sub, Uuid::nil());
	assert_eq!(session.principal, AuthorizationPrincipal::Profile);

	let other_session =
		JwtSession::from_request_parts(&mut parts, &second).await.unwrap();

	assert_eq!(other_session.sub, Uuid::from_u128(1));
	assert_eq!(other_session.principal, AuthorizationPrincipal::Device);
	assert_eq!(
		JwtSession::from_request_parts(&mut parts, &first).await.unwrap(),
		session
	);
}

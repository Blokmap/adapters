use blokmap_auth::authentication::{DecodingKey, EncodingKey, JwtToken};
use blokmap_auth::{Error, Result};
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{
	Algorithm,
	Header,
	decode_header,
	encode,
	get_current_timestamp,
};
use uuid::Uuid;

// These keys are generated fixtures used only by tests.
const PRIVATE_KEY: &[u8] = include_bytes!("keys/ed25519-private.pem");
const PUBLIC_KEY: &[u8] = include_bytes!("keys/ed25519-public.pem");
const ISSUER: &str = "https://auth.blokmap.com";

fn claims() -> JwtToken {
	let now = get_current_timestamp();
	JwtToken {
		iss:    ISSUER.into(),
		sub:    "profile:019ab123-4567-7890-abcd-123456789abc".into(),
		aud:    vec!["core".into(), "image".into()],
		exp:    now + 600,
		iat:    now,
		jti:    Uuid::parse_str("019ab123-0000-7000-8000-123456789abc")
			.unwrap(),
		scopes: vec![
			"image:delete".parse().unwrap(),
			"core:user".parse().unwrap(),
			"core:admin".parse().unwrap(),
			"auth:check".parse().unwrap(),
		],
	}
}

fn rejected(result: Result<JwtToken>, expected: ErrorKind) {
	let Error::Jwt(error) = result.unwrap_err() else {
		panic!("expected a JWT validation error");
	};
	assert_eq!(error.kind(), &expected);
}

#[test]
fn ed25519_tokens_roundtrip_with_the_given_claims() {
	let claims = claims();
	assert_eq!(
		serde_json::to_value(&claims).unwrap()["scopes"],
		serde_json::json!([
			"image:delete",
			"core:user",
			"core:admin",
			"auth:check"
		])
	);
	let private_key = EncodingKey::from_ed_pem(PRIVATE_KEY).unwrap();
	let public_key = DecodingKey::from_ed_pem(PUBLIC_KEY).unwrap();
	let token = claims.sign("key-1", &private_key).unwrap();
	let header = decode_header(&token).unwrap();
	assert_eq!(header.alg, Algorithm::EdDSA);
	assert_eq!(header.kid.as_deref(), Some("key-1"));

	for audience in ["core", "image"] {
		let decoded =
			JwtToken::verify(&token, &public_key, ISSUER, audience).unwrap();
		assert_eq!(
			serde_json::to_value(decoded).unwrap(),
			serde_json::to_value(&claims).unwrap()
		);
	}
}

#[test]
fn verification_rejects_bad_signatures_claims_and_algorithms() {
	let claims = claims();
	let private_key = EncodingKey::from_ed_pem(PRIVATE_KEY).unwrap();
	let public_key = DecodingKey::from_ed_pem(PUBLIC_KEY).unwrap();
	let token = claims.sign("key-1", &private_key).unwrap();

	rejected(
		JwtToken::verify(&token, &public_key, "https://other.example", "core"),
		ErrorKind::InvalidIssuer,
	);
	rejected(
		JwtToken::verify(&token, &public_key, ISSUER, "other"),
		ErrorKind::InvalidAudience,
	);
	let other_key = DecodingKey::from_ed_pem(include_bytes!(
		"keys/ed25519-other-public.pem"
	))
	.unwrap();
	rejected(
		JwtToken::verify(&token, &other_key, ISSUER, "core"),
		ErrorKind::InvalidSignature,
	);

	let (prefix, signature) = token.rsplit_once('.').unwrap();
	let first = if signature.starts_with('A') { 'B' } else { 'A' };
	let tampered = format!("{prefix}.{first}{}", &signature[1..]);
	rejected(
		JwtToken::verify(&tampered, &public_key, ISSUER, "core"),
		ErrorKind::InvalidSignature,
	);

	let mut expired = claims.clone();
	expired.exp = get_current_timestamp() - 120;
	let expired = expired.sign("key-1", &private_key).unwrap();
	rejected(
		JwtToken::verify(&expired, &public_key, ISSUER, "core"),
		ErrorKind::ExpiredSignature,
	);

	let mut within_leeway = claims.clone();
	within_leeway.exp = get_current_timestamp() - 30;
	let within_leeway = within_leeway.sign("key-1", &private_key).unwrap();
	JwtToken::verify(&within_leeway, &public_key, ISSUER, "core").unwrap();

	let secret =
		EncodingKey::from_secret(b"01234567890123456789012345678901").unwrap();
	let hmac =
		encode(&Header::new(Algorithm::HS256), &claims, &secret).unwrap();
	rejected(
		JwtToken::verify(&hmac, &public_key, ISSUER, "core"),
		ErrorKind::InvalidAlgorithm,
	);

	let mut future = serde_json::to_value(&claims).unwrap();
	future["nbf"] = (get_current_timestamp() + 600).into();
	let future =
		encode(&Header::new(Algorithm::EdDSA), &future, &private_key).unwrap();
	JwtToken::verify(&future, &public_key, ISSUER, "core").unwrap();

	for field in ["iss", "aud", "exp"] {
		let mut missing = serde_json::to_value(&claims).unwrap();
		missing.as_object_mut().unwrap().remove(field);
		let token =
			encode(&Header::new(Algorithm::EdDSA), &missing, &private_key)
				.unwrap();
		assert!(JwtToken::verify(&token, &public_key, ISSUER, "core").is_err());
	}
}

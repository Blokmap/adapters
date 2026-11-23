//! Run with `cargo run --no-default-features --example server`.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::routing::get;
use axum::{Json, Router};
use blokmap_auth::Result;
use blokmap_auth::authentication::{DecodingKey, EncodingKey, JwtToken};
use blokmap_auth::authorization::{
	AuthorizationCheck,
	AuthorizationRequirements,
};
use blokmap_auth::config::BlokmapAdapterConfig;
use blokmap_auth::extractor::{JwtSession, ProfileSession};
use uuid::Uuid;

fn main() -> Result<()> {
	// Fixture keys stand in for the auth service's own key store.
	let private = EncodingKey::from_ed_pem(include_bytes!(
		"../tests/keys/ed25519-private.pem"
	))?;
	let public = DecodingKey::from_ed_pem(include_bytes!(
		"../tests/keys/ed25519-public.pem"
	))?;
	let now = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.expect("system time should be after the Unix epoch")
		.as_secs();
	let claims = JwtToken {
		iss:    "https://auth.blokmap.com".into(),
		sub:    format!("profile:{}", Uuid::nil()),
		aud:    vec!["core".into()],
		exp:    now + 600,
		iat:    now,
		jti:    Uuid::nil(),
		scopes: vec!["core:user".into()],
		roles: vec![]
	};
	let token = claims.sign("auth-key", &private)?;
	let verified =
		JwtToken::verify(&token, &public, "https://auth.blokmap.com", "core")?;
	let session = JwtSession::try_from(verified)?;
	let _check = AuthorizationCheck {
		subject:      session.sub,
		principal:    session.principal,
		requirements: AuthorizationRequirements::All { all: Vec::new() },
	};
	assert_eq!(session.scopes[0].to_string(), "core:user");

	//.cookie_name use this same public key, with no outbound key requests.
	blokmap_auth::initialize(
		BlokmapAdapterConfig::default()
			.jwt("https://auth.blokmap.com", "core")
			.verification_key(public),
	)?;
	let _app: Router = Router::new().route("/profile", get(profile));

	Ok(())
}

async fn profile(session: ProfileSession) -> Json<ProfileSession> {
	Json(session)
}

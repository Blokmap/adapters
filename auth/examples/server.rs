//! Run with `cargo run --no-default-features --example server`.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::routing::get;
use axum::{Json, Router};
use blokmap_auth::authentication::{DecodingKey, EncodingKey, JwtToken};
use blokmap_auth::authorization::{
	AuthorizationCheck,
	AuthorizationRequirements,
	TokenScope,
};
use blokmap_auth::extractor::{JwtSession, ProfileSession};
use blokmap_auth::{BlokmapAuthAdapter, Result};
use uuid::Uuid;

fn main() -> Result<()> {
	// Fixture keys stand in for the auth service's own key store.
	let private = EncodingKey::from_ed_pem(include_bytes!(
		"../tests/keys/ed25519-private.pem"
	))?;

	let public = DecodingKey::from_ed_pem(include_bytes!(
		"../tests/keys/ed25519-public.pem"
	))?;

	// Signing and verifying keys
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
		scopes: vec![TokenScope::ImagesUpload],
		roles:  vec![],
	};

	let token = claims.sign("auth-key", &private)?;

	let verified =
		JwtToken::verify(&token, &public, "https://auth.blokmap.com", "core")?;

	// Authorization checks
	let session = JwtSession::try_from(verified)?;
	assert_eq!(session.scopes[0], TokenScope::ImagesUpload);

	let _check = AuthorizationCheck {
		subject:      session.sub,
		principal:    session.principal,
		requirements: AuthorizationRequirements::All(Vec::new()),
	};

	// Create the adapter
	let issuer = "https://auth.blokmap.com";
	let audience = "core";
	let cookie = "blokmap_access_token";

	let adapter = BlokmapAuthAdapter::builder()
		.jwt(issuer, audience, cookie)
		.verification_key(public)
		.build()?;

	let _app: Router = Router::new()
		.route("/profile", get(profile))
		.with_state(Arc::new(adapter));

	Ok(())
}

async fn profile(session: ProfileSession) -> Json<ProfileSession> {
	Json(session)
}

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use blokmap_auth::authorization::AuthorizationPrincipal::{self};
use blokmap_auth::authorization::{
	AuthorizationCheck,
	AuthorizationRequirements,
	LocationPermissions,
	PermissionScope,
	TokenScope,
};
use blokmap_auth::extractor::{
	DeviceSession,
	JwtSession,
	ProfileSession,
	Scope,
};
use blokmap_auth::{BlokmapAuthAdapter, Result};
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<()> {
	// Create the adapter
	let issuer = "https://auth.blokmap.com";
	let audience = "core";
	let cookie = "blokmap_access_token";

	let adapter = BlokmapAuthAdapter::builder()
		.auth_api_url(issuer.parse()?)
		.client_credentials("my-service", "client-secret")
		.jwt(issuer, audience, cookie)
		.build()?;

	// Perform authorization
	let check = AuthorizationCheck {
		subject:      Uuid::nil(),
		principal:    AuthorizationPrincipal::Profile,
		requirements: AuthorizationRequirements::All(Vec::new()),
	};

	adapter.authorization()?.check(check).await?;

	// Custom service creation
	let _images = adapter.client(
		"https://images.blokmap.com".parse()?,
		&[TokenScope::ImagesUpload],
	)?;

	let _app: Router = Router::new()
		.route("/session", get(session))
		.route("/profile", get(profile))
		.route("/device", get(device))
		.route("/locations/{id}", get(location))
		.route("/upload", post(upload))
		.with_state(Arc::new(adapter));

	Ok(())
}

/// Generic session extractor
async fn session(session: JwtSession) -> Json<JwtSession> { Json(session) }

/// Profile session extractor
async fn profile(session: ProfileSession) -> Json<ProfileSession> {
	Json(session)
}

/// Device session extractor
async fn device(session: DeviceSession) -> Json<DeviceSession> { Json(session) }

// Scope extractor
async fn upload(
	_: Scope<{ TokenScope::ImagesUpload }>,
	session: ProfileSession,
) -> Json<ProfileSession> {
	Json(session)
}

/// Session with permissions check
async fn location(
	State(adapter): State<Arc<BlokmapAuthAdapter>>,
	Path(id): Path<Uuid>,
	session: ProfileSession,
) -> Result<()> {
	let check = AuthorizationCheck {
		subject:      session.sub,
		principal:    session.principal,
		requirements: AuthorizationRequirements::Permission {
			scope: PermissionScope::Location,
			id,
			permission: LocationPermissions::ManageSettings.bits(),
		},
	};

	adapter.authorization()?.check(check).await
}

use axum::extract::Path;
use axum::routing::{get, post};
use axum::{Json, Router};
use blokmap_auth::Result;
use blokmap_auth::authorization::{
	AuthorizationCheck,
	AuthorizationRequirements,
	AuthorizationService,
	LocationPermissions,
	PermissionScope,
	TokenScope,
};
use blokmap_auth::client::HttpClient;
use blokmap_auth::config::BlokmapAdapterConfig;
use blokmap_auth::extractor::{
	DeviceSession,
	JwtSession,
	ProfileSession,
	Scope,
};
use uuid::Uuid;

fn main() -> Result<()> {
	blokmap_auth::initialize(
		BlokmapAdapterConfig::new("https://auth.blokmap.com".parse()?)
			.client_credentials("my-service", "client-secret")
			.jwt("https://auth.blokmap.com", "my-service")
			.cookie_name("blokmap_auth"),
	)?;

	let _authorization = AuthorizationService::global()?;
	let _images = HttpClient::authenticated(
		"https://images.blokmap.com".parse()?,
		&[TokenScope::ImagesUpload],
	)?;
	let _app: Router = Router::new()
		.route("/session", get(session))
		.route("/profile", get(profile))
		.route("/device", get(device))
		.route("/locations/{id}", get(location))
		.route("/upload", post(upload));

	Ok(())
}

async fn session(session: JwtSession) -> Json<JwtSession> { Json(session) }

async fn profile(session: ProfileSession) -> Json<ProfileSession> {
	Json(session)
}

async fn device(session: DeviceSession) -> Json<DeviceSession> { Json(session) }

async fn upload(
	_: Scope<"images:upload">,
	session: ProfileSession,
) -> Json<ProfileSession> {
	Json(session)
}

async fn location(Path(id): Path<Uuid>, session: ProfileSession) -> Result<()> {
	AuthorizationService::global()?
		.check(&AuthorizationCheck {
			subject:      session.sub,
			principal:    session.principal,
			requirements: AuthorizationRequirements::Permission {
				scope: PermissionScope::Location,
				id,
				permission: LocationPermissions::ManageSettings.bits(),
			},
		})
		.await
}

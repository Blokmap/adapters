use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::extract::State;
use axum::http::header::COOKIE;
use axum::http::{Request, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use blokmap_auth::authentication::{DecodingKey, EncodingKey, JwtToken};
use blokmap_auth::authorization::TokenScope;
use blokmap_auth::config::BlokmapAdapterConfig;
use blokmap_auth::extractor::{
	DeviceSession,
	JwtSession,
	ProfileSession,
	require_scope,
};
use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{Algorithm, Header, encode, get_current_timestamp};
use serde_json::json;
use tokio::net::TcpListener;
use tower::ServiceExt;
use url::Url;
use uuid::Uuid;

const ISSUER: &str = "https://auth.blokmap.com";
const COOKIE_NAME: &str = "blokmap_auth";
const SUBJECT: &str = "019ab123-4567-7890-abcd-123456789abc";

#[derive(Clone)]
struct AppState {
	name: &'static str,
}

async fn request(app: &Router, cookies: &[String]) -> axum::response::Response {
	request_path(app, "/session", cookies).await
}

async fn request_path(
	app: &Router,
	path: &str,
	cookies: &[String],
) -> axum::response::Response {
	let mut request = Request::builder().uri(path);
	for cookie in cookies {
		request = request.header(COOKIE, cookie);
	}

	tokio::time::timeout(
		Duration::from_secs(3),
		app.clone().oneshot(request.body(Body::empty()).unwrap()),
	)
	.await
	.unwrap()
	.unwrap()
}

#[tokio::test]
async fn extracts_only_verified_cookie_subjects() {
	let public_key =
		DecodingKey::from_ed_pem(include_bytes!("keys/ed25519-public.pem"))
			.unwrap();
	let private_key =
		EncodingKey::from_ed_pem(include_bytes!("keys/ed25519-private.pem"))
			.unwrap();
	let mut key =
		Jwk::from_decoding_key(&public_key, Some(Algorithm::EdDSA)).unwrap();
	key.common.key_id = Some("key-1".into());
	let jwks = JwkSet { keys: vec![key] };
	let requests = Arc::new(AtomicUsize::new(0));
	let recorded = requests.clone();
	let auth = Router::new().route(
		"/.well-known/jwks.json",
		get(move || {
			let jwks = jwks.clone();
			let requests = recorded.clone();
			async move {
				requests.fetch_add(1, Ordering::SeqCst);
				Json(jwks)
			}
		}),
	);
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let auth_api_url =
		Url::parse(&format!("http://{}", listener.local_addr().unwrap()))
			.unwrap();
	let config = BlokmapAdapterConfig::new(auth_api_url)
		.client_credentials("client", "secret")
		.jwt(ISSUER, "core")
		.cookie_name(COOKIE_NAME);
	#[cfg(not(feature = "jwks"))]
	let config = config.verification_key(public_key);
	blokmap_auth::initialize(config).unwrap();
	let server = tokio::spawn(async move {
		axum::serve(listener, auth).await.unwrap();
	});
	let app = Router::new()
		.route(
			"/session",
			get(|session: JwtSession, State(state): State<AppState>| {
				async move {
					assert_eq!(state.name, "service");
					Json(session)
				}
			}),
		)
		.route(
			"/profile",
			get(|session: ProfileSession| async move { Json(session) }),
		)
		.route(
			"/device",
			get(|session: DeviceSession| async move { Json(session) }),
		)
		.route(
			"/scoped",
			get(|session: JwtSession| async move { Json(session) })
				.route_layer(require_scope(TokenScope::ImagesUpload)),
		)
		.route(
			"/scoped-profile",
			get(|session: ProfileSession| async move { Json(session) })
				.route_layer(require_scope("images:upload")),
		)
		.route(
			"/custom-scope",
			get(|session: JwtSession| async move { Json(session) })
				.route_layer(require_scope("core:reports:read")),
		)
		.route(
			"/multi-scope",
			get(|session: JwtSession| async move { Json(session) })
				.route_layer(require_scope(TokenScope::ImagesUpload))
				.route_layer(require_scope(TokenScope::AuthCheck)),
		)
		.route(
			"/body",
			post(|_: ProfileSession, Json(body): Json<serde_json::Value>| {
				async move { Json(body) }
			})
			.route_layer(require_scope(TokenScope::ImagesUpload)),
		)
		.with_state(AppState { name: "service" });
	let now = get_current_timestamp();
	let claims = JwtToken {
		iss:    ISSUER.into(),
		sub:    format!("profile:{SUBJECT}"),
		aud:    vec!["core".into()],
		exp:    now + 3600,
		iat:    now,
		jti:    Uuid::nil(),
		scopes: Vec::new(),
	};

	for (cookies, code) in [
		(vec![], "MissingAccessToken"),
		(vec!["other=token".into()], "MissingAccessToken"),
		(vec![format!("{COOKIE_NAME}=")], "Jwt"),
		(vec![format!("{COOKIE_NAME}=invalid")], "Jwt"),
	] {
		let response = request(&app, &cookies).await;
		assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
		assert_eq!(response.headers()["content-type"], "application/json");
		let body = to_bytes(response.into_body(), 1024).await.unwrap();
		let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
		assert_eq!(error["blokmapCode"], code);
		assert_eq!(error["statusCode"], 401);
		assert!(
			error["message"].as_str().is_some_and(|value| !value.is_empty())
		);
	}
	let missing_kid =
		encode(&Header::new(Algorithm::EdDSA), &claims, &private_key).unwrap();
	assert_eq!(
		request(&app, &[format!("{COOKIE_NAME}={missing_kid}")]).await.status(),
		if cfg!(feature = "jwks") {
			StatusCode::UNAUTHORIZED
		} else {
			StatusCode::OK
		}
	);
	assert_eq!(requests.load(Ordering::SeqCst), 0);

	for principal in ["service", "device", "profile"] {
		let mut claims = claims.clone();
		claims.sub = format!("{principal}:{SUBJECT}");
		let token = claims.sign("key-1", &private_key).unwrap();
		let response = request(
			&app,
			&[
				"other=ignored".into(),
				format!("theme=dark; {COOKIE_NAME}={token}"),
			],
		)
		.await;
		assert_eq!(response.status(), StatusCode::OK);
		let body = to_bytes(response.into_body(), 1024).await.unwrap();
		let session: JwtSession = serde_json::from_slice(&body).unwrap();
		assert_eq!(session.sub, Uuid::parse_str(SUBJECT).unwrap());
		assert_eq!(
			serde_json::to_value(session).unwrap(),
			json!({ "sub": SUBJECT, "principal": principal, "scopes": [] })
		);

		for (path, allowed) in [
			("/profile", principal == "profile"),
			("/device", principal == "device"),
		] {
			let response =
				request_path(&app, path, &[format!("{COOKIE_NAME}={token}")])
					.await;
			assert_eq!(
				response.status(),
				if allowed { StatusCode::OK } else { StatusCode::FORBIDDEN }
			);
		}
		assert_eq!(
			request_path(&app, "/scoped", &[format!("{COOKIE_NAME}={token}")])
				.await
				.status(),
			StatusCode::FORBIDDEN
		);
	}
	assert_eq!(
		requests.load(Ordering::SeqCst),
		usize::from(cfg!(feature = "jwks"))
	);

	let mut scoped = claims.clone();
	scoped.scopes = vec![TokenScope::ImagesUpload];
	let token = scoped.sign("key-1", &private_key).unwrap();
	let cookies = [format!("{COOKIE_NAME}={token}")];
	for path in ["/scoped", "/scoped-profile"] {
		let response = request_path(&app, path, &cookies).await;
		assert_eq!(response.status(), StatusCode::OK);
		let body = to_bytes(response.into_body(), 1024).await.unwrap();
		let session: JwtSession = serde_json::from_slice(&body).unwrap();
		assert_eq!(
			serde_json::to_value(session).unwrap()["scopes"],
			json!(["images:upload"])
		);
		assert_eq!(
			request_path(&app, path, &[]).await.status(),
			StatusCode::UNAUTHORIZED
		);
	}
	assert_eq!(
		request_path(&app, "/multi-scope", &cookies).await.status(),
		StatusCode::FORBIDDEN
	);
	let response = app
		.clone()
		.oneshot(
			Request::builder()
				.method("POST")
				.uri("/body")
				.header(COOKIE, &cookies[0])
				.header("content-type", "application/json")
				.body(Body::from(r#"{"upload":"accepted"}"#))
				.unwrap(),
		)
		.await
		.unwrap();
	assert_eq!(response.status(), StatusCode::OK);
	let body = to_bytes(response.into_body(), 1024).await.unwrap();
	assert_eq!(
		serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
		json!({"upload": "accepted"})
	);
	scoped.scopes.push(TokenScope::AuthCheck);
	let token = scoped.sign("key-1", &private_key).unwrap();
	assert_eq!(
		request_path(&app, "/multi-scope", &[format!("{COOKIE_NAME}={token}")])
			.await
			.status(),
		StatusCode::OK
	);
	assert_eq!(
		request_path(
			&app,
			"/custom-scope",
			&[format!("{COOKIE_NAME}={token}")]
		)
		.await
		.status(),
		StatusCode::FORBIDDEN
	);
	scoped.scopes.push("core:reports:read".into());
	let token = scoped.sign("key-1", &private_key).unwrap();
	assert_eq!(
		request_path(
			&app,
			"/custom-scope",
			&[format!("{COOKIE_NAME}={token}")]
		)
		.await
		.status(),
		StatusCode::OK
	);
	scoped.sub = format!("device:{SUBJECT}");
	let token = scoped.sign("key-1", &private_key).unwrap();
	assert_eq!(
		request_path(
			&app,
			"/scoped-profile",
			&[format!("{COOKIE_NAME}={token}")]
		)
		.await
		.status(),
		StatusCode::FORBIDDEN
	);

	let mut invalid = Vec::new();
	for sub in [
		"",
		SUBJECT,
		"unknown:019ab123-4567-7890-abcd-123456789abc",
		"Profile:019ab123-4567-7890-abcd-123456789abc",
		"profile:",
		"profile:invalid",
		"profile:019ab123-4567-7890-abcd-123456789abc:extra",
	] {
		let mut claims = claims.clone();
		claims.sub = sub.into();
		invalid.push(claims.sign("key-1", &private_key).unwrap());
	}
	let mut expired = claims.clone();
	expired.exp = now - 120;
	invalid.push(expired.sign("key-1", &private_key).unwrap());
	let mut issuer = claims.clone();
	issuer.iss = "https://other.example".into();
	invalid.push(issuer.sign("key-1", &private_key).unwrap());
	let mut audience = claims.clone();
	audience.aud = vec!["other".into()];
	invalid.push(audience.sign("key-1", &private_key).unwrap());
	#[cfg(feature = "jwks")]
	invalid.push(claims.sign("unknown", &private_key).unwrap());
	let other_key = EncodingKey::from_ed_pem(include_bytes!(
		"keys/ed25519-other-private.pem"
	))
	.unwrap();
	invalid.push(claims.sign("key-1", &other_key).unwrap());
	let secret =
		EncodingKey::from_secret(b"01234567890123456789012345678901").unwrap();
	invalid.push(
		encode(&Header::new(Algorithm::HS256), &claims, &secret).unwrap(),
	);
	for token in invalid {
		for path in ["/session", "/profile", "/device", "/scoped"] {
			assert_eq!(
				request_path(&app, path, &[format!("{COOKIE_NAME}={token}")])
					.await
					.status(),
				StatusCode::UNAUTHORIZED
			);
		}
	}
	assert_eq!(
		requests.load(Ordering::SeqCst),
		usize::from(cfg!(feature = "jwks"))
	);

	server.abort();
	let _ = server.await;
	#[cfg(feature = "jwks")]
	{
		tokio::time::pause();
		tokio::time::advance(Duration::from_secs(600)).await;
		tokio::time::resume();
		let token = claims.sign("key-1", &private_key).unwrap();
		let response = request(&app, &[format!("{COOKIE_NAME}={token}")]).await;
		assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
		let body = to_bytes(response.into_body(), 1024).await.unwrap();
		let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
		assert_eq!(error["blokmapCode"], "HttpClient");
		assert_eq!(error["statusCode"], 503);
		assert_eq!(error["message"], "Service Unavailable");
		assert!(error["info"].is_null());
	}
}

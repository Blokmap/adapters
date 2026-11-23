use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::extract::{Path, State};
use axum::http::header::{AUTHORIZATION, COOKIE};
use axum::http::{HeaderValue, Request, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use blokmap_auth::authentication::{DecodingKey, EncodingKey, JwtToken};
use blokmap_auth::authorization::{
	AuthorizationPrincipal,
	TokenRole,
	TokenScope,
};
use blokmap_auth::config::BlokmapAdapterConfig;
use blokmap_auth::extractor::{
	DeviceSession,
	JwtSession,
	ProfileSession,
	Scope,
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

#[test]
fn session_access_helpers_check_admin_scope_and_profile_identity() {
	let target = Uuid::parse_str(SUBJECT).unwrap();
	for principal in [
		AuthorizationPrincipal::Service,
		AuthorizationPrincipal::Device,
		AuthorizationPrincipal::Profile,
	] {
		let mut session = JwtSession {
			sub: target,
			principal,
			scopes: vec![TokenScope::ImagesUpload],
			roles: vec![],
		};
		assert!(!session.is_admin());
		assert_eq!(
			session.is_profile(target),
			principal == AuthorizationPrincipal::Profile
		);
		assert!(!session.is_profile(Uuid::nil()));

		session.roles = vec!["admin".parse().unwrap()];
		assert_eq!(session.roles, vec![TokenRole::Admin]);
		if principal == AuthorizationPrincipal::Profile {
			assert!(session.is_admin());
		} else {
			assert!(!session.is_admin());
		}
		assert!(!session.is_profile(Uuid::nil()));
		let json = serde_json::to_value(&session).unwrap();
		assert_eq!(
			serde_json::from_value::<JwtSession>(json).unwrap(),
			session
		);
		assert_eq!(TokenRole::Admin.to_string(), "admin");
	}
}

async fn request(app: &Router, cookies: &[String]) -> axum::response::Response {
	request_path(app, "/session", cookies).await
}

async fn request_path(
	app: &Router,
	path: &str,
	cookies: &[String],
) -> axum::response::Response {
	request_credentials(app, path, cookies, &[]).await
}

async fn request_credentials(
	app: &Router,
	path: &str,
	cookies: &[String],
	authorization: &[HeaderValue],
) -> axum::response::Response {
	let mut request = Request::builder().uri(path);
	for cookie in cookies {
		request = request.header(COOKIE, cookie);
	}
	for value in authorization {
		request = request.header(AUTHORIZATION, value);
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
async fn extracts_only_verified_bearer_and_cookie_subjects() {
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
			get(|_: Scope<"images:upload">, session: JwtSession| {
				async move { Json(session) }
			}),
		)
		.route(
			"/scoped-profile",
			get(|session: ProfileSession, _: Scope<"images:upload">| {
				async move { Json(session) }
			}),
		)
		.route(
			"/custom-scope",
			get(|_: Scope<"core:reports:read">, session: JwtSession| {
				async move { Json(session) }
			}),
		)
		.route(
			"/multi-scope",
			get(
				|_: Scope<"images:upload">,
				 _: Scope<"auth:check">,
				 session: JwtSession| async move { Json(session) },
			),
		)
		.route(
			"/admin",
			get(|session: JwtSession| {
				async move {
					match session.is_admin() {
						true => StatusCode::OK,
						false => StatusCode::FORBIDDEN,
					}
				}
			}),
		)
		.route(
			"/profiles/{id}",
			get(|Path(id): Path<Uuid>, session: JwtSession| {
				async move {
					if session.is_admin() || session.is_profile(id) {
						StatusCode::OK
					} else {
						StatusCode::FORBIDDEN
					}
				}
			}),
		)
		.route(
			"/body",
			post(
				|_: Scope<"images:upload">,
				 _: ProfileSession,
				 Json(body): Json<serde_json::Value>| {
					async move { Json(body) }
				},
			),
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
		scopes: vec![],
		roles:  vec![],
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
			json!({ "sub": SUBJECT, "principal": principal, "scopes": [], "roles": [] })
		);

		for (path, allowed) in [
			("/profile", principal == "profile"),
			("/device", principal == "device"),
			(&format!("/profiles/{SUBJECT}"), principal == "profile"),
			(&format!("/profiles/{}", Uuid::nil()), false),
			("/admin", false),
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

	let cookie_token = claims.sign("key-1", &private_key).unwrap();
	let fallback_cookie = [format!("{COOKIE_NAME}={cookie_token}")];
	for principal in ["service", "device", "profile"] {
		let mut bearer = claims.clone();
		bearer.sub = format!("{principal}:{}", Uuid::nil());
		bearer.scopes = vec![TokenScope::ImagesUpload];
		let token = bearer.sign("key-1", &private_key).unwrap();
		for scheme in ["Bearer", "bearer", "bEaReR  "] {
			let authorization =
				[HeaderValue::from_str(&format!("{scheme} {token}")).unwrap()];
			for cookies in [fallback_cookie.as_slice(), &[]] {
				let response = request_credentials(
					&app,
					"/session",
					cookies,
					&authorization,
				)
				.await;
				assert_eq!(response.status(), StatusCode::OK);
				let body = to_bytes(response.into_body(), 1024).await.unwrap();
				let session: JwtSession =
					serde_json::from_slice(&body).unwrap();
				assert_eq!(session.sub, Uuid::nil());
				assert_eq!(session.principal, principal.parse().unwrap());
				assert_eq!(session.scopes, vec![TokenScope::ImagesUpload]);
			}
		}
		let authorization =
			[HeaderValue::from_str(&format!("Bearer {token}")).unwrap()];
		for (path, status) in [
			(
				"/profile",
				if principal == "profile" {
					StatusCode::OK
				} else {
					StatusCode::FORBIDDEN
				},
			),
			(
				"/device",
				if principal == "device" {
					StatusCode::OK
				} else {
					StatusCode::FORBIDDEN
				},
			),
			("/scoped", StatusCode::OK),
			("/multi-scope", StatusCode::FORBIDDEN),
		] {
			assert_eq!(
				request_credentials(
					&app,
					path,
					&fallback_cookie,
					&authorization
				)
				.await
				.status(),
				status
			);
		}
		assert_eq!(
			request_credentials(
				&app,
				"/session",
				&[format!("{COOKIE_NAME}=invalid")],
				&authorization,
			)
			.await
			.status(),
			StatusCode::OK
		);
	}
	let valid_header =
		HeaderValue::from_str(&format!("Bearer {cookie_token}")).unwrap();
	for authorization in [
		vec![HeaderValue::from_static("")],
		vec![HeaderValue::from_static("Basic abc")],
		vec![HeaderValue::from_static("Bearer")],
		vec![HeaderValue::from_static("Bearer\ttoken")],
		vec![HeaderValue::from_bytes(b"Bearer \xFF").unwrap()],
		vec![valid_header.clone(), valid_header.clone()],
		vec![valid_header.clone(), HeaderValue::from_static("Bearer invalid")],
		vec![HeaderValue::from_static("Bearer invalid"), valid_header],
	] {
		for cookies in [fallback_cookie.as_slice(), &[]] {
			let response =
				request_credentials(&app, "/session", cookies, &authorization)
					.await;
			assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
			let body = to_bytes(response.into_body(), 1024).await.unwrap();
			let error: serde_json::Value =
				serde_json::from_slice(&body).unwrap();
			assert_eq!(error["blokmapCode"], "MalformedAuthorizationHeader");
			assert_eq!(error["statusCode"], 401);
			assert!(error["info"].is_null());
		}
	}

	let mut admin = claims.clone();
	admin.roles = vec![TokenRole::Admin];
	let token = admin.sign("key-1", &private_key).unwrap();
	let cookies = [format!("{COOKIE_NAME}={token}")];
	for path in ["/admin", &format!("/profiles/{}", Uuid::nil())] {
		assert_eq!(
			request_path(&app, path, &cookies).await.status(),
			StatusCode::OK
		);
	}
	let response = request_path(&app, "/scoped", &cookies).await;
	assert_eq!(response.status(), StatusCode::FORBIDDEN);
	let body = to_bytes(response.into_body(), 1024).await.unwrap();
	let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
	assert_eq!(error["blokmapCode"], "MissingScope");
	assert_eq!(error["info"], "images:upload");

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
	for bearer in [false, true] {
		let request = Request::builder().method("POST").uri("/body");
		let request = if bearer {
			request.header(AUTHORIZATION, format!("Bearer {token}"))
		} else {
			request.header(COOKIE, &cookies[0])
		};
		let response = app
			.clone()
			.oneshot(
				request
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
	}
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

	let mut invalid = vec![
		"invalid".to_owned(),
		"  ".to_owned(),
		"token extra".to_owned(),
		"token ".to_owned(),
	];
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
		for path in [
			"/session",
			"/profile",
			"/device",
			"/scoped",
			"/custom-scope",
			"/multi-scope",
			"/admin",
		] {
			assert_eq!(
				request_path(&app, path, &[format!("{COOKIE_NAME}={token}")])
					.await
					.status(),
				StatusCode::UNAUTHORIZED
			);
			assert_eq!(
				request_credentials(
					&app,
					path,
					&fallback_cookie,
					&[HeaderValue::from_str(&format!("Bearer {token}"))
						.unwrap()],
				)
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

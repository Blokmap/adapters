#![cfg(feature = "authorization")]

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use blokmap_auth::authentication::DecodingKey;
use blokmap_auth::authorization::{
	AuthorizationCheck,
	AuthorizationPrincipal,
	AuthorizationRequirements,
	AuthorizationService,
	TokenScope,
};
use blokmap_auth::{BlokmapAuthAdapter, Error};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use url::Url;
use uuid::Uuid;

mod common;

#[derive(Clone, Default)]
struct AuthState {
	tokens:    Arc<AtomicUsize>,
	revoked:   Arc<AtomicUsize>,
	discovery: Arc<AtomicUsize>,
	jwks:      Arc<AtomicUsize>,
}

async fn token(
	State(state): State<AuthState>,
	headers: HeaderMap,
	body: String,
) -> Json<Value> {
	assert_eq!(headers["authorization"], "Basic Y2xpZW50OnNlY3JldA==");

	let form: HashMap<_, _> =
		url::form_urlencoded::parse(body.as_bytes()).into_owned().collect();

	assert_eq!(form["grant_type"], "client_credentials");
	assert_eq!(
		form["scope"],
		"auth:check auth:profiles:read auth:profiles:update"
	);

	let generation = state.tokens.fetch_add(1, Ordering::SeqCst) + 1;

	Json(json!({
		"access_token": format!("token-{generation}"),
		"token_type": "bEaReR",
		"expires_in": 60,
	}))
}

async fn authorize(
	State(state): State<AuthState>,
	headers: HeaderMap,
	Json(_): Json<AuthorizationCheck>,
) -> StatusCode {
	let generation = state.tokens.load(Ordering::SeqCst);
	let expected = format!("Bearer token-{generation}");

	if generation > state.revoked.load(Ordering::SeqCst)
		&& headers["authorization"] == expected
	{
		StatusCode::OK
	} else {
		StatusCode::UNAUTHORIZED
	}
}

fn request() -> AuthorizationCheck {
	AuthorizationCheck {
		subject:      Uuid::nil(),
		principal:    AuthorizationPrincipal::Service,
		requirements: AuthorizationRequirements::All(Vec::new()),
	}
}

async fn check(service: &AuthorizationService) {
	tokio::time::timeout(Duration::from_secs(3), service.check(request()))
		.await
		.unwrap()
		.unwrap();
}

#[tokio::test]
async fn local_keys_and_shared_service_tokens_do_not_require_jwks() {
	let state = AuthState::default();
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let base =
		Url::parse(&format!("http://{}", listener.local_addr().unwrap()))
			.unwrap();
	let metadata = common::metadata(base.as_str());

	let app = Router::new()
		.route(
			"/.well-known/openid-configuration",
			get(move |State(state): State<AuthState>| {
				let mut metadata = metadata.clone();

				if state.discovery.fetch_add(1, Ordering::SeqCst) == 0 {
					metadata["issuer"] =
						"https://unexpected.example.com".into();
				}

				async move { Json(metadata) }
			}),
		)
		.route(
			"/.well-known/jwks.json",
			get(|State(state): State<AuthState>| {
				async move {
					state.jwks.fetch_add(1, Ordering::SeqCst);

					StatusCode::SERVICE_UNAVAILABLE
				}
			}),
		)
		.route("/oauth/token", post(token))
		.route("/authorization/check", post(authorize))
		.with_state(state.clone());

	let key =
		DecodingKey::from_ed_pem(include_bytes!("keys/ed25519-public.pem"))
			.unwrap();
	let config = BlokmapAuthAdapter::builder()
		.auth_api_url(base.clone())
		.client_credentials("client", "secret")
		.jwt(base.as_str(), "core", "blokmap_auth")
		.verification_key(key);

	let adapter = config.build().unwrap();

	#[cfg(feature = "jwks")]
	assert!(matches!(adapter.jwks(), Err(Error::InvalidConfiguration(_))));

	let _client = adapter.client(base, &[TokenScope::ImagesUpload]).unwrap();
	let first = adapter.authorization().unwrap().clone();
	let second = adapter.authorization().unwrap().clone();

	assert_eq!(state.tokens.load(Ordering::SeqCst), 0);

	let server = tokio::spawn(async move {
		axum::serve(listener, app).await.unwrap();
	});

	assert!(matches!(
		first.check(request()).await,
		Err(Error::OidcDiscovery(_))
	));
	assert_eq!(state.tokens.load(Ordering::SeqCst), 0);

	check(&first).await;
	check(&second).await;
	check(adapter.authorization().unwrap()).await;
	assert_eq!(state.tokens.load(Ordering::SeqCst), 1);

	drop(adapter);

	state.revoked.store(1, Ordering::SeqCst);
	tokio::join!(check(&first), check(&second));
	assert_eq!(state.tokens.load(Ordering::SeqCst), 2);

	tokio::time::pause();
	tokio::time::advance(Duration::from_secs(60)).await;
	tokio::time::resume();

	tokio::join!(check(&first), check(&second));
	assert_eq!(state.tokens.load(Ordering::SeqCst), 3);
	assert_eq!(state.discovery.load(Ordering::SeqCst), 2);
	assert_eq!(state.jwks.load(Ordering::SeqCst), 0);

	server.abort();
	let _ = server.await;
}

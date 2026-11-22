#![cfg(feature = "authorization")]

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use blokmap_auth::Error;
use blokmap_auth::authorization::{
	AuthorizationCheck,
	AuthorizationPrincipal,
	AuthorizationRequirements,
	AuthorizationService,
	TokenScope,
};
use blokmap_auth::client::HttpClient;
use blokmap_auth::config::BlokmapAdapterConfig;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use url::Url;
use uuid::Uuid;

#[derive(Clone, Default)]
struct AuthState {
	tokens:  Arc<AtomicUsize>,
	rotated: Arc<AtomicBool>,
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

	Json(
		json!({"access_token": format!("token-{generation}"), "token_type": "bEaReR"}),
	)
}

async fn authorize(
	State(state): State<AuthState>,
	headers: HeaderMap,
	Json(_): Json<AuthorizationCheck>,
) -> StatusCode {
	let expected = if state.rotated.load(Ordering::SeqCst) {
		"Bearer token-2"
	} else {
		"Bearer token-1"
	};
	if headers["authorization"] == expected {
		StatusCode::OK
	} else {
		StatusCode::UNAUTHORIZED
	}
}

async fn check(service: &AuthorizationService, request: &AuthorizationCheck) {
	tokio::time::timeout(Duration::from_secs(3), service.check(request))
		.await
		.unwrap()
		.unwrap();
}

#[tokio::test]
async fn one_initialization_shares_service_tokens_across_public_handles() {
	assert!(matches!(
		AuthorizationService::global(),
		Err(Error::AdapterNotInitialized)
	));
	let state = AuthState::default();
	let app = Router::new()
		.route("/auth/service", post(token))
		.route("/authorization/check", post(authorize))
		.with_state(state.clone());
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let base =
		Url::parse(&format!("http://{}", listener.local_addr().unwrap()))
			.unwrap();
	let config = BlokmapAdapterConfig::new(base.clone())
		.client_credentials("client", "secret");
	#[cfg(feature = "jwks")]
	let config = config.jwt("https://auth.blokmap.com", "core");
	blokmap_auth::initialize(config).unwrap();
	assert!(matches!(
		blokmap_auth::initialize(BlokmapAdapterConfig::new(base.clone())),
		Err(Error::AdapterAlreadyInitialized)
	));
	let _client =
		HttpClient::authenticated(base, &[TokenScope::ImagesUpload]).unwrap();
	let first = AuthorizationService::global().unwrap().clone();
	let second = AuthorizationService::global().unwrap().clone();
	assert_eq!(state.tokens.load(Ordering::SeqCst), 0);
	let server = tokio::spawn(async move {
		axum::serve(listener, app).await.unwrap();
	});
	let request = AuthorizationCheck {
		subject:      Uuid::nil(),
		principal:    AuthorizationPrincipal::Service,
		requirements: AuthorizationRequirements::All { all: Vec::new() },
	};
	check(&first, &request).await;
	check(&second, &request).await;
	check(AuthorizationService::global().unwrap(), &request).await;
	assert_eq!(state.tokens.load(Ordering::SeqCst), 1);

	state.rotated.store(true, Ordering::SeqCst);
	tokio::join!(check(&first, &request), check(&second, &request));
	assert_eq!(state.tokens.load(Ordering::SeqCst), 2);
	server.abort();
	let _ = server.await;
}

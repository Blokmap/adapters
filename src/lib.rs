//! JWT issuance, verified Axum sessions, and optional authentication clients.
//!
//!
//! # Features
//!
//! | Feature | Capability |
//! | --- | --- |
//! | `client` | Outgoing HTTP with managed service credentials |
//! | `jwks` | OIDC discovery and verification keys with a ten-minute cache |
//! | `authorization` | Remote permission checks; includes `client` |
//!
//! Defaults enable `authorization` and `jwks`. An auth server that owns its
//! keys can disable defaults and still use JWT signing and every extractor:
//!
//! ```toml
//! blokmap_auth = { version = "0.1", default-features = false }
//! ```
//!
//! # Build an adapter
//!
//! Build a `BlokmapAuthAdapter` and store it in your application. Each adapter
//! owns its configuration and caches; multiple independent adapters can
//! coexist. Construction validates settings without making HTTP requests; keys
//! and tokens are fetched lazily.
//! Outgoing clients discover the token endpoint independently of JWKS.
//! Token and verification-key snapshots use `ArcSwap`; refreshes are
//! serialized. An auth server can combine local keys with `client` for outgoing
//! requests.
//!
//! ```no_run
//! # fn startup() -> blokmap_auth::Result<blokmap_auth::BlokmapAuthAdapter> {
//! use blokmap_auth::BlokmapAuthAdapter;
//!
//! let adapter = BlokmapAuthAdapter::builder()
//! 	.auth_api_url("https://auth.example.com".parse()?)
//! 	.client_credentials("core-service", "client-secret")
//! 	.jwt("https://auth.example.com", "core", "session")
//! 	.build()?;
//! # Ok(adapter)
//! # }
//! ```
//!
//! `adapter.authorization()` borrows its permission client.
//! `adapter.client(base, scopes)` creates an outgoing client;
//! clones share its token cache and connection pool. Principals, scopes, and
//! permission models can also be used without either remote client.
//!
//! # Verify with your own key
//!
//! With defaults disabled, configure a public key instead of a service URL.
//! Local keys take precedence even if another dependency enables `jwks`;
//! no JWKS cache or key-fetching requests are used.
//!
//! ```no_run
//! use blokmap_auth::BlokmapAuthAdapter;
//! use blokmap_auth::authentication::DecodingKey;
//! # fn startup(public_pem: &[u8]) -> blokmap_auth::Result<blokmap_auth::BlokmapAuthAdapter> {
//! let adapter = BlokmapAuthAdapter::builder()
//! 	.jwt("https://auth.example.com", "core", "session")
//! 	.verification_key(DecodingKey::from_ed_pem(public_pem)?)
//! 	.build()?;
//! # Ok(adapter)
//! # }
//! ```
//!
//! Signing and verification through `JwtToken::sign` and `JwtToken::verify`
//! accept keys directly. An issuer chooses the
//! claims, signs with an Ed25519 private key, and publishes the matching key.
//!
//! # Protect Axum controllers
//!
//! `JwtSession` accepts `service:<uuid>`, `device:<uuid>`, and
//! `profile:<uuid>` subjects. `ProfileSession` and `DeviceSession` additionally
//! require the corresponding principal. All expose `sub`, `principal`, and
//! `scopes`. Supply `Arc<BlokmapAuthAdapter>` as Axum state, or expose it from
//! your application state with `FromRef`.
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! use axum::routing::post;
//! use axum::{Json, Router};
//! use blokmap_auth::BlokmapAuthAdapter;
//! use blokmap_auth::authorization::TokenScope;
//! use blokmap_auth::extractor::{ProfileSession, Scope};
//!
//! async fn upload(
//! 	_: Scope<{ TokenScope::ImagesUpload }>,
//! 	session: ProfileSession,
//! ) -> Json<ProfileSession> {
//! 	Json(session)
//! }
//! # fn routes(adapter: Arc<BlokmapAuthAdapter>) -> Router {
//! Router::new().route("/images", post(upload)).with_state(adapter)
//! # }
//! ```
//!
//! Session extractors accept `Authorization: Bearer <token>` for service,
//! device, and profile principals. With no Authorization header, they read the
//! cookie configured by `.jwt(...)`, supporting browser sessions.
//! A present Authorization header takes precedence; malformed, duplicate, or
//! invalid headers return 401 without falling back to the cookie. Mobile apps
//! can use Bearer headers with the same extractors as browser clients.
//!
//! Both sources verify the signature, issuer, audience, and expiration using
//! the local key or remote JWKS. Verification is reused within each request,
//! including scope extractors. Expiration permits 60 seconds of clock skew;
//! `nbf` is ignored, following the JWT library's defaults.
//!
//! Missing or invalid credentials return 401; a wrong principal or missing
//! scope returns 403. `Scope<{ TokenScope::ImagesUpload }>` requires an exact
//! scope. Accepted scopes are declared in `TokenScope`; unknown scope strings
//! reject the token. Compiling this crate requires nightly Rust for enum const
//! parameters (`adt_const_params`). Scope extractors preserve
//! request bodies. Handlers can return the root `Result<T>` for structured
//! JSON errors.
//!
//! `session.is_admin()` checks for a profile session with `TokenRole::Admin`.
//! `session.is_profile(id)` checks both the profile principal and subject UUID.
//! Use `session.is_admin() || session.is_profile(id)` for routes allowing
//! system administrators or operations on one's own profile.
//!
//! See `examples/service.rs` for a remote consumer and `examples/server.rs`
//! for local signing, verification, and extractor setup.

#![feature(adt_const_params)]
#![allow(incomplete_features)]
#![warn(missing_docs)]

mod adapter;
pub mod authentication;
pub mod authorization;
#[cfg(any(feature = "client", feature = "jwks"))]
pub mod client;
pub mod config;
mod error;
pub mod extractor;

pub use adapter::BlokmapAuthAdapter;
pub use error::{Error, Result};

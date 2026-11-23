//! JWT issuance, verified Axum sessions, and optional authentication clients.
//!
//!
//! # Features
//!
//! | Feature | Capability |
//! | --- | --- |
//! | `client` | Outgoing HTTP with managed service credentials |
//! | `jwks` | Remote verification keys with a shared ten-minute cache |
//! | `authorization` | Remote permission checks; includes `client` |
//!
//! Defaults enable `authorization` and `jwks`. An auth server that owns its
//! keys can disable defaults and still use JWT signing and every extractor:
//!
//! ```toml
//! blokmap_auth = { version = "0.1", default-features = false }
//! ```
//!
//! # Initialize a consuming service
//!
//! Call `initialize` once before serving requests. The default features use
//! shared remote keys and managed service credentials. Startup validates
//! settings without making HTTP requests; keys and tokens are fetched lazily.
//!
//! ```no_run
//! # fn startup() -> blokmap_auth::Result<()> {
//! use blokmap_auth::config::BlokmapAdapterConfig;
//!
//! let config = BlokmapAdapterConfig::new("https://auth.example.com".parse()?)
//! 	.client_credentials("core-service", "client-secret")
//! 	.jwt("https://auth.example.com", "core")
//! 	.cookie_name("session");
//! blokmap_auth::initialize(config)?;
//! # Ok(())
//! # }
//! ```
//!
//! `AuthorizationService::global()` borrows the shared permission client.
//! `HttpClient::authenticated(base, scopes)` creates an outgoing client;
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
//! use blokmap_auth::authentication::DecodingKey;
//! use blokmap_auth::config::BlokmapAdapterConfig;
//! # fn startup(public_pem: &[u8]) -> blokmap_auth::Result<()> {
//! let config = BlokmapAdapterConfig::default()
//! 	.jwt("https://auth.example.com", "core")
//! 	.verification_key(DecodingKey::from_ed_pem(public_pem)?)
//! 	.cookie_name("session");
//! blokmap_auth::initialize(config)?;
//! # Ok(())
//! # }
//! ```
//!
//! Signing and verification through `JwtToken::sign` and `JwtToken::verify`
//! accept keys directly and need no initialization. An issuer chooses the
//! claims, signs with an Ed25519 private key, and publishes the matching key.
//!
//! # Protect Axum controllers
//!
//! `JwtSession` accepts `service:<uuid>`, `device:<uuid>`, and
//! `profile:<uuid>` subjects. `ProfileSession` and `DeviceSession` additionally
//! require the corresponding principal. All expose `sub`, `principal`, and
//! `scopes`, and work with any Axum state.
//!
//! ```no_run
//! use axum::routing::post;
//! use axum::{Json, Router};
//! use blokmap_auth::extractor::scope::ImagesUpload;
//! use blokmap_auth::extractor::{ProfileSession, Scope};
//!
//! async fn upload(
//! 	_: Scope<ImagesUpload>,
//! 	session: ProfileSession,
//! ) -> Json<ProfileSession> {
//! 	Json(session)
//! }
//! let app: Router = Router::new().route("/images", post(upload));
//! ```
//!
//! Session extractors accept `Authorization: Bearer <token>` for service,
//! device, and profile principals. With no Authorization header, they read the
//! configured cookie (default `blokmap_auth`), supporting browser sessions.
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
//! scope returns 403. `Scope<ImagesUpload>` and other built-in markers require
//! exact scopes; implement `extractor::scope::RequiredScope` for custom scopes.
//! Scope extractors preserve request bodies. Handlers can return the root
//! `Result<T>` for structured JSON errors.
//!
//! `session.is_admin()` checks for `TokenScope::SystemAdmin` (`system:admin`).
//! `session.is_profile(id)` checks both the profile principal and subject UUID.
//! Use `session.is_admin() || session.is_profile(id)` for routes allowing
//! system administrators or operations on one's own profile.
//!
//! See `examples/service.rs` for a remote consumer and `examples/server.rs`
//! for local signing, verification, and extractor setup.

#![warn(missing_docs)]

pub mod authentication;
pub mod authorization;
#[cfg(feature = "client")]
pub mod client;
#[cfg(all(feature = "jwks", not(feature = "client")))]
mod client;
pub mod config;
mod error;
pub mod extractor;
mod runtime;

pub use error::{Error, Result};
pub use runtime::initialize;

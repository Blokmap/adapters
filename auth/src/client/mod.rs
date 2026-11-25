//! HTTP clients with either no authentication or managed service credentials.

mod http_client;
#[cfg(feature = "client")]
mod token;

#[cfg(feature = "client")]
pub use http_client::HttpAuthenticated;
pub use http_client::{HttpClient, HttpUnauthenticated};

//! HTTP clients with either no authentication or managed service credentials.

mod client;
#[cfg(feature = "client")]
mod token;

#[cfg(feature = "client")]
pub use client::HttpAuthenticated;
pub use client::{HttpClient, HttpUnauthenticated};

//! Local JWT signing and verification, and optional remote keys.

#[cfg(feature = "jwks")]
mod jwks;
mod jwt;

pub use jsonwebtoken::{DecodingKey, EncodingKey};
#[cfg(feature = "jwks")]
pub use jwks::JwksManager;
pub use jwt::JwtToken;

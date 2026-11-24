use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_with::formats::SpaceSeparator;
use serde_with::{OneOrMany, StringWithSeparator, serde_as};
use uuid::Uuid;

use crate::Result;
use crate::authorization::{TokenRole, TokenScope};

/// Blokmap JWT claims, signed and verified using caller-supplied Ed25519 keys.
///
/// Always available, without HTTP clients or an adapter.
/// Timestamps are Unix seconds; the issuer chooses IDs, scopes, audiences,
/// and expiration. Scopes use the space-delimited `scope` claim; audiences
/// accept a string or array. Missing scopes and roles default to empty lists.
/// Signing does not fill in or validate those claim values automatically.
///
/// ```no_run
/// use blokmap_auth::authentication::{EncodingKey, JwtToken};
/// # fn issue(claims: &JwtToken, private_pem: &[u8])
/// #     -> blokmap_auth::Result<String> {
/// let key = EncodingKey::from_ed_pem(private_pem)?;
/// claims.sign("auth-key-1", &key)
/// # }
/// ```
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JwtToken {
	/// Issuing authority, compared exactly during verification.
	pub iss:    String,
	/// Subject in `service:<uuid>`, `device:<uuid>`, or `profile:<uuid>` form.
	/// The prefix and UUID are checked when converting to a
	/// [`JwtSession`](crate::extractor::JwtSession).
	pub sub:    String,
	/// Audiences allowed to consume this token.
	#[serde_as(as = "OneOrMany<_>")]
	pub aud:    Vec<String>,
	/// Expiration timestamp, in Unix seconds.
	pub exp:    u64,
	/// Issuance timestamp, in Unix seconds; not a validity check by itself.
	pub iat:    u64,
	/// Issuer-assigned token identifier.
	pub jti:    Uuid,
	/// Granted scopes, encoded in the standard space-delimited `scope` claim.
	/// Every value must match a declared [`TokenScope`] variant.
	#[serde(default, rename = "scope", skip_serializing_if = "Vec::is_empty")]
	#[serde_as(as = "StringWithSeparator<SpaceSeparator, TokenScope>")]
	pub scopes: Vec<TokenScope>,
	/// Granted system-wide roles.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub roles:  Vec<TokenRole>,
}

impl JwtToken {
	/// Creates an Ed25519 JWT using the supplied private key and key ID.
	/// The header uses EdDSA and includes `kid`, allowing consumers to select
	/// the corresponding published verification key.
	///
	/// # Errors
	///
	/// Returns [`crate::Error::Jwt`] if the key or token encoding is invalid.
	pub fn sign(&self, kid: &str, private_key: &EncodingKey) -> Result<String> {
		let mut header = Header::new(Algorithm::EdDSA);
		header.kid = Some(kid.to_owned());
		Ok(jsonwebtoken::encode(&header, self, private_key)?)
	}

	/// Verifies the signature, issuer, audience, expiration, and required
	/// claims.
	///
	/// Uses the supplied key directly and makes no network requests. Only EdDSA
	/// is accepted. Expiration allows 60 seconds of clock skew; `nbf` is
	/// ignored. This validates JWT claims, while `JwtSession::try_from`
	/// additionally parses the subject's principal and UUID.
	///
	/// ```no_run
	/// use blokmap_auth::authentication::{DecodingKey, JwtToken};
	/// use blokmap_auth::extractor::JwtSession;
	/// # fn read(token: &str, public_pem: &[u8]) -> blokmap_auth::Result<JwtSession> {
	/// let key = DecodingKey::from_ed_pem(public_pem)?;
	/// let claims = JwtToken::verify(token, &key, "https://auth.example.com", "core")?;
	/// JwtSession::try_from(claims)
	/// # }
	/// ```
	///
	/// # Errors
	///
	/// Returns [`crate::Error::Jwt`] for malformed tokens, invalid signatures,
	/// incompatible algorithms, missing claims, or rejected claim values.
	pub fn verify(
		token: &str,
		public_key: &DecodingKey,
		issuer: &str,
		audience: &str,
	) -> Result<Self> {
		let mut validation = Validation::new(Algorithm::EdDSA);
		validation.set_issuer(&[issuer]);
		validation.set_audience(&[audience]);
		validation.set_required_spec_claims(&["iss", "sub", "aud", "exp"]);
		Ok(jsonwebtoken::decode::<Self>(token, public_key, &validation)?.claims)
	}
}

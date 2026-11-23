use serde_json::{Value, json};

pub fn metadata(issuer: &str) -> Value {
	let base = issuer.trim_end_matches('/');

	json!({
		"issuer": issuer,
		"authorization_endpoint": format!("{base}/oauth/authorize"),
		"token_endpoint": format!("{base}/oauth/token"),
		"jwks_uri": format!("{base}/.well-known/jwks.json"),
		"response_types_supported": ["code"],
		"subject_types_supported": ["public"],
		"id_token_signing_alg_values_supported": ["EdDSA"],
		"grant_types_supported": ["client_credentials", "authorization_code"],
		"token_endpoint_auth_methods_supported": ["client_secret_basic"]
	})
}

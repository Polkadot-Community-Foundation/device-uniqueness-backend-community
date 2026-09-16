// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};

use crate::error;

pub trait HasJwtVerifier {
    fn jwt_verifier(&self) -> &jwt_verify::Verifier;
}

/// An authenticated subject, extracted from a verified `Authorization: Bearer`
/// JWT (device-attestation tokens, verified via the shared `jwt-verify` crate).
pub struct AuthSubject {
    /// `0x`-hex sr25519 public key of the caller (the JWT subject).
    pub subject: String,
    /// Client platform (`"ios"`/`"android"`) from the token's `plt` claim,
    /// when the issuer set it. Tamper-proof (verified JWT); used to scope
    /// platform-specific gates such as iOS DeviceCheck.
    pub platform: Option<String>,
    /// The attestation-time official-store verdict
    /// (`appFromOfficialStore` claim), when the issuer set it. Tamper-proof.
    pub app_from_official_store: Option<bool>,
}

/// An auth rejection, rendered as one of three 401 bodies.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("missing authorization header")]
    MissingHeader,
    #[error("invalid authorization header")]
    InvalidHeader,
    #[error("invalid token")]
    InvalidToken,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        match self {
            AuthError::MissingHeader => error::missing_auth_header(),
            AuthError::InvalidHeader => error::invalid_auth_header(),
            AuthError::InvalidToken => error::invalid_token(),
        }
    }
}

/// Split an `Authorization` header value into its Bearer token (any
/// whitespace run separates exactly two parts).
fn bearer_token(header: &str) -> Option<&str> {
    let mut parts = header.split_whitespace();
    match (parts.next(), parts.next(), parts.next()) {
        (Some("Bearer"), Some(token), None) if !token.is_empty() => Some(token),
        _ => None,
    }
}

impl<S> FromRequestParts<S> for AuthSubject
where
    S: HasJwtVerifier + Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or(AuthError::MissingHeader)?;
        let token = bearer_token(header).ok_or(AuthError::InvalidHeader)?;
        let claims = state
            .jwt_verifier()
            .verify(token)
            .map_err(|_| AuthError::InvalidToken)?;
        Ok(AuthSubject {
            subject: claims.account_id,
            platform: claims.platform,
            app_from_official_store: claims.app_from_official_store,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::bearer_token;

    #[test]
    fn parses_bearer_scheme_only() {
        assert_eq!(bearer_token("Bearer abc"), Some("abc"));
        assert_eq!(bearer_token("Bearer   abc"), Some("abc"));
        assert_eq!(bearer_token("bearer abc"), None);
        assert_eq!(bearer_token("Basic abc"), None);
        assert_eq!(bearer_token("Bearer"), None);
        assert_eq!(bearer_token("Bearer a b"), None);
    }
}

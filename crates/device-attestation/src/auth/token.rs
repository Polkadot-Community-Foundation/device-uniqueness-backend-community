// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use secrecy::ExposeSecret as _;
use serde::Serialize;
use utoipa::ToSchema;

use super::{
    app_attest, challenge, decode_header, decode_header_fixed, detect_platform, key_attest,
    play_integrity, proof, refresh,
};
use crate::http::error::{AppError, AppResult};
use crate::http::state::AppState;

/// `{ token, refreshToken }` — the shape both auth token routes return.
#[derive(Serialize, ToSchema)]
pub struct TokenResponse {
    /// Signed access JWT (EdDSA).
    #[schema(example = "jwt")]
    token: String,
    /// Opaque, single-use refresh token.
    #[serde(rename = "refreshToken")]
    #[schema(example = "opaque-base64-token")]
    refresh_token: String,
}

impl TokenResponse {
    pub(crate) fn new(token: String, refresh_token: String) -> Self {
        Self {
            token,
            refresh_token,
        }
    }
}

/// Verify challenge + client proof and issue an access + refresh token pair.
#[utoipa::path(
    post,
    path = "/api/v1/auth/token",
    tag = "Authentication",
    params(
        ("Auth-ClientId" = String, Header, description = "Base64 of the 32-byte sr25519 public key."),
        ("Auth-ClientProof" = String, Header, description = "Base64 of the 64-byte sr25519 signature over the raw body."),
        ("Auth-Challenge" = String, Header, description = "Challenge previously minted via /auth/challenges."),
        ("Auth-iOS-Package" = Option<String>, Header, description = "iOS bundle id, e.g. io.pcf.polkadotapp. Selects the App Attest verification path."),
        ("Auth-Payload" = Option<String>, Header, description = "Base64 App Attest assertion (iOS) or the raw classic Play Integrity token (Android play-integrity), verified when attestation is enabled."),
        ("Auth-iOS-KeyId" = Option<String>, Header, description = "Base64 App Attest key id registered via /auth/app-attest/attestations."),
        ("Auth-Android-Package" = Option<String>, Header, description = "Android package name; required for play-integrity and sets the JWT platform claim for Android clients."),
        ("Auth-Attestation-Type" = Option<String>, Header, description = "Android attestation dispatch: `key-attestation` verifies the `attestationChain` field in the JSON body (base64 DER, leaf first), and also sets the Android platform claim when Auth-Android-Package is absent; `play-integrity` verifies the token in Auth-Payload with self-managed response keys.")
    ),
    request_body(content = serde_json::Value, description = "Raw body covered by the proof; may be empty {}. \
        Android key-attestation requests carry the certificate chain here as `attestationChain` \
        (2-10 base64 DER entries, leaf first).",
        example = json!({})),
    responses(
        (status = 200, description = "Verified. Access JWT + opaque refresh token.", body = TokenResponse,
         example = json!({ "token": "jwt", "refreshToken": "opaque-base64-token" })),
        (status = 401, description = "Bad or spent challenge, or invalid client proof.",
         body = crate::http::error::ErrorResponse,
         example = json!({ "error": "UNAUTHORIZED", "message": "unauthorized" })),
        (status = 403, description = "Platform attestation failed verification (hard enforcement).",
         body = crate::http::error::ErrorResponse,
         example = json!({ "error": "INTEGRITY_FAILED", "message": "attestation rejected" })),
        (status = 503, description = "Android attestation revocation list unavailable; retry with a fresh challenge (hard enforcement).",
         body = crate::http::error::ErrorResponse,
         example = json!({ "error": "ATTESTATION_CRL_UNAVAILABLE", "message": "attestation CRL unavailable" }))
    )
)]
pub async fn issue(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> AppResult<Json<TokenResponse>> {
    let client_id: [u8; 32] = decode_header_fixed(&headers, "auth-clientid")?;
    let client_proof: [u8; 64] = decode_header_fixed(&headers, "auth-clientproof")?;
    let challenge = decode_header(&headers, "auth-challenge")?;

    if !challenge::consume(&state.pool, &challenge).await? {
        return Err(AppError::Unauthorized);
    }
    if !proof::verify(&challenge, &client_id, &body, &client_proof) {
        return Err(AppError::Unauthorized);
    }

    let app_from_official_store = if state.config.auth_enabled {
        match attestation_verdict(&state, &headers, &challenge, &client_id, &body).await? {
            Ok(from_store) => from_store,
            Err(reason) if state.config.enforce_auth => {
                tracing::warn!(reason = %reason, "attestation rejected (hard mode)");
                return Err(AppError::IntegrityFailed(reason));
            }
            Err(reason) => {
                tracing::warn!(reason = %reason, "attestation verdict failed (soft mode, request allowed)");
                false
            }
        }
    } else {
        tracing::debug!(
            attestation = state.config.attestation_mode(),
            "attestation no-op"
        );
        true
    };

    let account_id = format!("0x{}", hex::encode(client_id));
    let platform = detect_platform(&headers);

    let token = state.jwt.issue(
        &account_id,
        app_from_official_store,
        platform,
        state.config.access_ttl,
    );
    let refresh_token = refresh::mint(
        &state.pool,
        &account_id,
        app_from_official_store,
        platform,
        state.config.refresh_ttl,
    )
    .await?;

    Ok(Json(TokenResponse::new(token, refresh_token)))
}

async fn attestation_verdict(
    state: &AppState,
    headers: &HeaderMap,
    challenge: &[u8],
    client_id: &[u8; 32],
    body: &[u8],
) -> AppResult<Result<bool, String>> {
    if headers.contains_key("auth-ios-package") {
        return Ok(
            ios_attestation_verdict(state, headers, challenge, client_id, body)
                .await?
                .map(|()| true),
        );
    }

    match headers
        .get("auth-attestation-type")
        .and_then(|v| v.to_str().ok())
    {
        Some("key-attestation") => key_attestation_verdict(state, challenge, body).await,
        Some("play-integrity") => {
            Ok(play_integrity_verdict(state, headers, challenge, client_id, body).await)
        }
        Some(other) => Ok(Err(format!("unknown Auth-Attestation-Type {other:?}"))),
        None => Ok(Err(
            "no attestation evidence (no Auth-iOS-Package or Auth-Attestation-Type)".into(),
        )),
    }
}

async fn play_integrity_verdict(
    state: &AppState,
    headers: &HeaderMap,
    challenge: &[u8],
    client_id: &[u8; 32],
    body: &[u8],
) -> Result<bool, String> {
    let package = headers
        .get("auth-android-package")
        .and_then(|v| v.to_str().ok())
        .ok_or("missing Auth-Android-Package header")?;
    if !state
        .config
        .android_package_names
        .iter()
        .any(|p| p == package)
    {
        return Err(format!("unknown Android package {package}"));
    }
    let integrity_token = headers
        .get("auth-payload")
        .and_then(|v| v.to_str().ok())
        .ok_or("missing Auth-Payload integrity token")?;

    let (Some(playstore_digest), Some(website_digest)) = (
        state.config.android_signing_digest_playstore.as_ref(),
        state.config.android_signing_digest_website.as_ref(),
    ) else {
        return Err("android signing digests are not configured".into());
    };

    let expected_nonce = proof::client_data_hash(challenge, client_id, body);
    let policy = play_integrity::PolicyParams {
        expected_nonce: &expected_nonce,
        mode: state.config.play_integrity_mode,
        package_names: &state.config.android_package_names,
        playstore_digest,
        website_digest,
    };

    if let (Some(decryption_key), Some(verification_key)) = (
        state
            .config
            .play_integrity_decryption_key
            .as_ref()
            .map(|k| k.expose_secret()),
        state.config.play_integrity_verification_key.as_deref(),
    ) {
        let params = play_integrity::VerifyParams {
            decryption_key,
            verification_key_der: verification_key,
            policy,
        };
        return play_integrity::verify_token(integrity_token, &params).map_err(|e| e.to_string());
    }

    if let Some(google) = &state.play_integrity_google {
        tracing::debug!(
            "play integrity: self-managed keys unset; using the temporary \
             Google decodeIntegrityToken fallback"
        );
        let payload = google
            .decode(package, integrity_token)
            .await
            .map_err(|e| format!("google decode fallback: {e}"))?;
        return play_integrity::check_payload(&payload, &policy).map_err(|e| e.to_string());
    }

    Err(
        "play integrity is not configured (neither self-managed keys nor GOOGLE_CREDENTIALS)"
            .into(),
    )
}

async fn key_attestation_verdict(
    state: &AppState,
    challenge: &[u8],
    body: &[u8],
) -> AppResult<Result<bool, String>> {
    let chain = match key_attest::chain_from_body(body) {
        Ok(chain) => chain,
        Err(reason) => return Ok(Err(reason)),
    };

    let (Some(playstore_digest), Some(website_digest)) = (
        state.config.android_signing_digest_playstore.as_ref(),
        state.config.android_signing_digest_website.as_ref(),
    ) else {
        return Ok(Err("android signing digests are not configured".into()));
    };

    let revoked_serials = match state.crl.revoked_serials().await {
        Ok(serials) => serials,
        Err(e) if state.config.enforce_auth => {
            tracing::warn!(error = %e, "attestation CRL unavailable (hard mode)");
            return Err(AppError::CrlUnavailable);
        }
        Err(e) => return Ok(Err(format!("attestation CRL unavailable: {e}"))),
    };

    let params = key_attest::verify::VerifyParams {
        challenge,
        package_names: &state.config.android_package_names,
        playstore_digest,
        website_digest,
        trusted_roots_der: &key_attest::verify::google_roots_der(),
        trusted_verified_boot_keys: key_attest::verify::GRAPHENEOS_VERIFIED_BOOT_KEYS,
        revoked_serials: &revoked_serials,
        now_unix: time::OffsetDateTime::now_utc().unix_timestamp(),
    };
    Ok(key_attest::verify::verify_chain(&chain, &params)
        .map(|_| false)
        .map_err(|e| e.to_string()))
}

async fn ios_attestation_verdict(
    state: &AppState,
    headers: &HeaderMap,
    challenge: &[u8],
    client_id: &[u8; 32],
    body: &[u8],
) -> AppResult<Result<(), String>> {
    let Some(package) = headers
        .get("auth-ios-package")
        .and_then(|v| v.to_str().ok())
    else {
        return Ok(Err(
            "no iOS package header; platform attestation unavailable".into(),
        ));
    };
    if !state.config.ios_package_names.iter().any(|p| p == package) {
        return Ok(Err(format!("unknown iOS package {package}")));
    }
    let Ok(assertion) = decode_header(headers, "auth-payload") else {
        return Ok(Err("missing or invalid Auth-Payload assertion".into()));
    };
    let Ok(key_id) = decode_header(headers, "auth-ios-keyid") else {
        return Ok(Err("missing or invalid Auth-iOS-KeyId".into()));
    };
    let Some(key) = app_attest::store::find(&state.pool, &key_id).await? else {
        return Ok(Err("unregistered App Attest key".into()));
    };

    let client_data_hash = proof::client_data_hash(challenge, client_id, body);
    match app_attest::verify::verify_assertion(
        &assertion,
        &client_data_hash,
        &key.public_key,
        &state.config.apple_app_attest_app_ids,
        key.sign_count,
    ) {
        Ok(next_sign_count) => {
            if app_attest::store::commit_sign_count(&state.pool, &key_id, next_sign_count).await? {
                Ok(Ok(()))
            } else {
                Ok(Err("assertion sign count no longer monotonic".into()))
            }
        }
        Err(err) => Ok(Err(err.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn token_response_keeps_the_mobile_wire_shape() {
        let response = TokenResponse::new("access".to_string(), "refresh".to_string());

        assert_eq!(
            serde_json::to_value(response).unwrap(),
            json!({ "token": "access", "refreshToken": "refresh" })
        );
    }
}

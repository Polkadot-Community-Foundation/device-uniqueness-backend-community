// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::sync::Mutex;
use std::time::Duration;

use base64::Engine as _;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};

use super::BitState;

/// Apple recommends short-lived DeviceCheck JWTs; mirror legacy's 10 minutes.
const JWT_TTL_SECS: i64 = 600;
/// Mint a fresh JWT when the cached one has less than this left.
const JWT_REFRESH_GRACE_SECS: i64 = 30;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Bounded retry for transient DeviceCheck failures (mirrors legacy's 3×).
const MAX_RETRIES: u32 = 3;
const RETRY_BACKOFF: Duration = Duration::from_millis(200);

/// The DeviceCheck API could not be used for this request.
#[derive(Debug, thiserror::Error)]
pub enum DeviceCheckError {
    #[error("devicecheck jwt: {0}")]
    Jwt(String),
    #[error("devicecheck api: {0}")]
    Api(String),
}

/// Classifies a single HTTP attempt's failure for the retry loop.
enum TryError {
    /// Network/timeout/5xx/body failure — safe to retry (idempotent payload).
    Transient(DeviceCheckError),
    /// A definitive 4xx (auth/input) rejection — do not retry.
    Fatal(DeviceCheckError),
}

/// Authenticated DeviceCheck client with a cached team-key JWT.
pub struct Client {
    http: reqwest::Client,
    base_url: String,
    team_id: String,
    key_id: String,
    encoding_key: EncodingKey,
    token: Mutex<Option<CachedJwt>>,
}

struct CachedJwt {
    token: String,
    expires_at: i64,
}

#[derive(Serialize)]
struct Claims<'a> {
    iss: &'a str,
    iat: i64,
    exp: i64,
}

/// Wire shape of a `query_two_bits` JSON response.
#[derive(Deserialize)]
struct BitStateWire {
    bit0: bool,
    bit1: bool,
}

impl Client {
    /// Build a client from the team id, DeviceCheck key id, the `.p8`
    /// private key (PKCS#8 PEM), and the API base URL.
    pub fn new(
        team_id: String,
        key_id: String,
        private_key_pem: &str,
        base_url: String,
    ) -> Result<Self, String> {
        let encoding_key = EncodingKey::from_ec_pem(private_key_pem.as_bytes())
            .map_err(|e| format!("DeviceCheck private key is not a usable EC PEM: {e}"))?;
        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|e| format!("http client: {e}"))?;
        Ok(Self {
            http,
            base_url,
            team_id,
            key_id,
            encoding_key,
            token: Mutex::new(None),
        })
    }

    /// Query the device's two-bit state; `None` means Apple has never stored
    /// bits for this device (fresh device). Fail-closed: a body that is neither
    /// valid bit-state JSON nor Apple's exact no-bits marker is an error, so a
    /// proxy error page, a truncated body, or a schema change can never be
    /// misread as a fresh device (which would hand out a free registration).
    pub async fn query_bits(
        &self,
        device_token: &[u8],
    ) -> Result<Option<BitState>, DeviceCheckError> {
        let body = self.call("query_two_bits", device_token, None).await?;
        classify_query_response(&body)
    }

    /// Whether this device already claimed its free registration.
    pub async fn already_used(&self, device_token: &[u8]) -> Result<bool, DeviceCheckError> {
        Ok(self
            .query_bits(device_token)
            .await?
            .is_some_and(BitState::is_registered))
    }

    /// Mark the device as having claimed its free registration
    /// (legacy encoding `(bit0, bit1) = (false, true)`).
    pub async fn register_device(&self, device_token: &[u8]) -> Result<(), DeviceCheckError> {
        self.call("update_two_bits", device_token, Some((false, true)))
            .await
            .map(|_| ())
    }

    async fn call(
        &self,
        endpoint: &str,
        device_token: &[u8],
        bits: Option<(bool, bool)>,
    ) -> Result<Vec<u8>, DeviceCheckError> {
        let jwt = self.jwt()?;
        let url = format!("{}/{endpoint}", self.base_url);

        // Build the payload once so retries replay the same transaction id and
        // timestamp: the write is idempotent (fixed bits) and Apple keeps an
        // ephemeral token valid long enough to retry a specific request.
        let mut payload = serde_json::json!({
            "device_token": base64::engine::general_purpose::STANDARD.encode(device_token),
            "transaction_id": transaction_id(),
            "timestamp": time::OffsetDateTime::now_utc().unix_timestamp() * 1000,
        });
        if let Some((bit0, bit1)) = bits {
            payload["bit0"] = bit0.into();
            payload["bit1"] = bit1.into();
        }

        let mut last_err: Option<DeviceCheckError> = None;
        for attempt in 0..=MAX_RETRIES {
            if attempt > 0 {
                tokio::time::sleep(RETRY_BACKOFF).await;
            }
            match self.try_call(&url, &jwt, &payload, endpoint).await {
                Ok(body) => return Ok(body),
                Err(TryError::Fatal(e)) => return Err(e),
                Err(TryError::Transient(e)) => last_err = Some(e),
            }
        }
        Err(last_err.expect("the retry loop runs at least once"))
    }

    /// A single DeviceCheck HTTP attempt. Transport, body, and 5xx failures are
    /// transient (retryable); a 4xx is a definitive rejection.
    async fn try_call(
        &self,
        url: &str,
        jwt: &str,
        payload: &serde_json::Value,
        endpoint: &str,
    ) -> Result<Vec<u8>, TryError> {
        let response = self
            .http
            .post(url)
            .bearer_auth(jwt)
            .json(payload)
            .send()
            .await
            .map_err(|e| {
                TryError::Transient(DeviceCheckError::Api(format!(
                    "{endpoint} request failed: {e}"
                )))
            })?;
        let status = response.status();
        let body = response.bytes().await.map_err(|e| {
            TryError::Transient(DeviceCheckError::Api(format!("{endpoint} body: {e}")))
        })?;
        if status.is_success() {
            return Ok(body.to_vec());
        }
        let err = DeviceCheckError::Api(format!(
            "{endpoint} rejected ({}): {}",
            status.as_u16(),
            String::from_utf8_lossy(&body)
        ));
        if status.is_server_error() {
            Err(TryError::Transient(err))
        } else {
            Err(TryError::Fatal(err))
        }
    }

    /// Return the cached team-key JWT, minting a fresh one when stale.
    fn jwt(&self) -> Result<String, DeviceCheckError> {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let mut cache = self.token.lock().expect("jwt lock");
        if let Some(cached) = cache.as_ref() {
            if cached.expires_at - now > JWT_REFRESH_GRACE_SECS {
                return Ok(cached.token.clone());
            }
        }

        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.key_id.clone());
        let expires_at = now + JWT_TTL_SECS;
        let token = jsonwebtoken::encode(
            &header,
            &Claims {
                iss: &self.team_id,
                iat: now,
                exp: expires_at,
            },
            &self.encoding_key,
        )
        .map_err(|e| DeviceCheckError::Jwt(e.to_string()))?;
        *cache = Some(CachedJwt {
            token: token.clone(),
            expires_at,
        });
        Ok(token)
    }
}

/// A unique transaction id per Apple call (any unique string is accepted).
fn transaction_id() -> String {
    use rand::RngCore as _;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Apple's plain-text `200` body when a device has no bits stored yet.
const NO_BITS_MARKER: &str = "Failed to find bit state";

/// Classify a `query_two_bits` `200` body. Valid bit-state JSON yields the
/// bits; Apple's exact no-bits marker yields a fresh device (`None`); anything
/// else is an error so an unexpected body is never silently treated as fresh.
fn classify_query_response(body: &[u8]) -> Result<Option<BitState>, DeviceCheckError> {
    if let Ok(bits) = serde_json::from_slice::<BitStateWire>(body) {
        return Ok(Some(BitState {
            bit0: bits.bit0,
            bit1: bits.bit1,
        }));
    }
    if std::str::from_utf8(body).is_ok_and(|s| s.trim().eq_ignore_ascii_case(NO_BITS_MARKER)) {
        return Ok(None);
    }
    Err(DeviceCheckError::Api(format!(
        "unrecognized query_two_bits body: {}",
        String::from_utf8_lossy(body).trim()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
    use p256::elliptic_curve::Generate as _;
    use p256::pkcs8::EncodePrivateKey as _;
    use sha2::{Digest as _, Sha256};

    fn test_client() -> (Client, p256::ecdsa::VerifyingKey) {
        let secret = p256::SecretKey::generate();
        let pem = secret
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .expect("pem");
        let verifying = p256::ecdsa::VerifyingKey::from(secret.public_key());
        let client = Client::new(
            "TEAM123456".to_string(),
            "KEYID12345".to_string(),
            &pem,
            "https://api.development.devicecheck.apple.com/v1".to_string(),
        )
        .expect("client builds");
        (client, verifying)
    }

    #[test]
    fn jwt_is_es256_with_kid_and_team_issuer_and_is_cached() {
        let (client, verifying) = test_client();
        let token = client.jwt().expect("jwt");

        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let header: serde_json::Value =
            serde_json::from_slice(&b64.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], "KEYID12345");

        let claims: serde_json::Value =
            serde_json::from_slice(&b64.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["iss"], "TEAM123456");
        assert_eq!(
            claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
            JWT_TTL_SECS
        );

        let signature = p256::ecdsa::Signature::from_slice(&b64.decode(parts[2]).unwrap()).unwrap();
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let prehash = Sha256::digest(signing_input.as_bytes());
        verifying
            .verify_prehash(&prehash, &signature)
            .expect("signature verifies with the team key");

        assert_eq!(client.jwt().unwrap(), token);
    }

    #[test]
    fn rejects_a_non_ec_private_key() {
        assert!(Client::new(
            "TEAM".into(),
            "KEY".into(),
            "not a pem",
            "https://example.test".into()
        )
        .is_err());
    }

    #[test]
    fn query_response_classification_is_fail_closed() {
        let used =
            classify_query_response(br#"{"bit0":false,"bit1":true,"last_update_time":"2026-07"}"#)
                .expect("valid json parses")
                .expect("some bits");
        assert!(used.is_registered());

        assert!(classify_query_response(b"Failed to find bit state")
            .expect("marker is ok")
            .is_none());
        assert!(classify_query_response(b"  Failed to find bit state\n")
            .expect("marker tolerates whitespace")
            .is_none());

        assert!(classify_query_response(b"").is_err());
        assert!(classify_query_response(b"<html>502 Bad Gateway</html>").is_err());
        assert!(classify_query_response(br#"{"bit0":false}"#).is_err());
    }
}

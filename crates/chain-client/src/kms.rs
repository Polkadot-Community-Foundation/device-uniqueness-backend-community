// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

//! An Ed25519 chain signer whose key lives in Cloud KMS (`EC_SIGN_ED25519`).
//!
//! The key never leaves KMS: every signature is an `asymmetricSign` call made
//! with the workload's own Google identity. The account is the key version's
//! public key, so a new key version is a new account.

use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use secrecy::ExposeSecret as _;
use serde::Deserialize;

use crate::signer::SignError;
use crate::workload_token::{WorkloadTokens, METADATA_TOKEN_URL};

const KMS_API: &str = "https://cloudkms.googleapis.com/v1";
const KMS_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// One KMS request. With a workload token to fetch first (once an hour, up to
/// 10 s of its own) and one retry after a 401, one signature waits at most
/// about 40 s.
const KMS_TIMEOUT: Duration = Duration::from_secs(10);
/// Start-up attempts at reading the public key while failures are transient:
/// the GKE metadata server takes a few seconds to answer in a new pod. Waits
/// double from [`KmsEndpoints::connect_backoff`], about 30 s in all.
const CONNECT_ATTEMPTS: u32 = 5;
const CONNECT_BACKOFF: Duration = Duration::from_secs(2);
const KMS_BODY_MAX: usize = 64 * 1024;
const LOGGED_BODY_MAX: usize = 512;
const ED25519_ALGORITHM: &str = "EC_SIGN_ED25519";
/// DER prefix of an Ed25519 `SubjectPublicKeyInfo` (RFC 8410); the 32-byte key
/// follows it.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Whether `name` is a Cloud KMS key *version* resource name:
/// `projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/V`.
///
/// A version, not a key: each version is a different account, so the version
/// an operator registered as the proxy must be the one used.
pub fn is_key_version_name(name: &str) -> bool {
    let parts: Vec<&str> = name.split('/').collect();
    let segment = |s: &str, max: usize| {
        !s.is_empty()
            && s.len() <= max
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    };
    parts.len() == 10
        && parts[0] == "projects"
        && is_project_id(parts[1])
        && parts[2] == "locations"
        && !parts[3].is_empty()
        && parts[3]
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && parts[4] == "keyRings"
        && segment(parts[5], 63)
        && parts[6] == "cryptoKeys"
        && segment(parts[7], 63)
        && parts[8] == "cryptoKeyVersions"
        && !parts[9].is_empty()
        && parts[9].len() <= 10
        && !parts[9].starts_with('0')
        && parts[9].bytes().all(|b| b.is_ascii_digit())
}

fn is_project_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    (6..=30).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes[bytes.len() - 1] != b'-'
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicKeyResponse {
    pem: String,
    algorithm: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    protection_level: Option<String>,
}

#[derive(Deserialize)]
struct SignResponse {
    signature: String,
    #[serde(default)]
    name: Option<String>,
}

/// Where the signer sends its requests. Fixed in production; tests point them
/// at a local server.
pub(crate) struct KmsEndpoints {
    pub(crate) api: String,
    pub(crate) metadata_token: String,
    pub(crate) timeout: Duration,
    pub(crate) connect_backoff: Duration,
    /// Refuse a plain-HTTP KMS endpoint; off only for a local test server.
    pub(crate) https_only: bool,
}

impl Default for KmsEndpoints {
    fn default() -> Self {
        Self {
            api: KMS_API.to_string(),
            metadata_token: METADATA_TOKEN_URL.to_string(),
            timeout: KMS_TIMEOUT,
            connect_backoff: CONNECT_BACKOFF,
            https_only: true,
        }
    }
}

/// A Cloud KMS Ed25519 key version used as a chain signer.
pub struct KmsSigner {
    key_version: String,
    public: VerifyingKey,
    http: reqwest::Client,
    api: String,
    tokens: WorkloadTokens,
}

impl KmsSigner {
    /// Read the key version's public key and check it is an Ed25519 key, so
    /// the account is known (and logged) before anything is signed.
    pub async fn connect(key_version: &str) -> anyhow::Result<Self> {
        Self::connect_to(key_version, KmsEndpoints::default()).await
    }

    pub(crate) async fn connect_to(
        key_version: &str,
        endpoints: KmsEndpoints,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            is_key_version_name(key_version),
            "not a Cloud KMS key version name \
             (projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/N)"
        );
        // The bearer token goes only to the KMS API over TLS: no plain HTTP,
        // no proxy from the environment, no redirects.
        let http = reqwest::Client::builder()
            .connect_timeout(KMS_CONNECT_TIMEOUT.min(endpoints.timeout))
            .timeout(endpoints.timeout)
            .https_only(endpoints.https_only)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let tokens = WorkloadTokens::new(&endpoints.metadata_token)?;
        let mut signer = Self {
            key_version: key_version.to_string(),
            public: VerifyingKey::default(),
            http,
            api: endpoints.api.trim_end_matches('/').to_string(),
            tokens,
        };
        let url = format!("{}/{key_version}/publicKey", signer.api);
        let mut wait = endpoints.connect_backoff;
        let mut attempt = 1;
        let body = loop {
            match signer.call(|| signer.http.get(&url)).await {
                Ok(body) => break body,
                Err(error) if error.is_transient() && attempt < CONNECT_ATTEMPTS => {
                    tracing::warn!(
                        %error,
                        attempt,
                        retry_in_secs = wait.as_secs(),
                        "reading the KMS public key failed; retrying"
                    );
                    tokio::time::sleep(wait).await;
                    wait *= 2;
                    attempt += 1;
                }
                Err(error) => anyhow::bail!("reading the KMS public key: {error}"),
            }
        };
        let key: PublicKeyResponse = serde_json::from_slice(&body).map_err(|error| {
            anyhow::anyhow!(
                "KMS public key response is unreadable ({:?} error)",
                error.classify()
            )
        })?;
        anyhow::ensure!(
            key.algorithm == ED25519_ALGORITHM,
            "KMS key version algorithm is {}, not {ED25519_ALGORITHM}",
            key.algorithm
        );
        if let Some(name) = &key.name {
            anyhow::ensure!(
                name == key_version,
                "KMS answered for another key version than the one configured"
            );
        }
        signer.public = ed25519_from_pem(&key.pem).map_err(|why| anyhow::anyhow!(why))?;
        tracing::info!(
            key_version,
            protection_level = key.protection_level.as_deref().unwrap_or("-"),
            "KMS chain signer connected"
        );
        Ok(signer)
    }

    /// The account: an Ed25519 key's account id is its public key.
    pub fn public_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// The key version this signer signs with.
    pub fn key_version(&self) -> &str {
        &self.key_version
    }

    /// Sign `payload` exactly as given (the extrinsic encoder has already
    /// hashed a payload longer than 256 bytes), and check the signature
    /// against the public key before returning it.
    pub(crate) async fn sign(&self, payload: &[u8]) -> Result<[u8; 64], SignError> {
        let url = format!("{}/{}:asymmetricSign", self.api, self.key_version);
        let body = serde_json::json!({ "data": BASE64.encode(payload) });
        let body = self.call(|| self.http.post(&url).json(&body)).await?;
        let response: SignResponse = serde_json::from_slice(&body).map_err(|error| {
            tracing::warn!(category = ?error.classify(), "KMS sign response is unreadable");
            SignError::new("kms returned an unreadable response")
        })?;
        if response
            .name
            .as_deref()
            .is_some_and(|name| name != self.key_version)
        {
            tracing::warn!("KMS signed with another key version than the one configured");
            return Err(SignError::new("kms signed with another key version"));
        }
        let bytes: [u8; 64] = BASE64
            .decode(response.signature)
            .ok()
            .and_then(|signature| signature.try_into().ok())
            .ok_or_else(|| SignError::new("kms returned an invalid signature"))?;
        self.public
            .verify_strict(payload, &Signature::from_bytes(&bytes))
            .map_err(|_| {
                tracing::warn!(
                    key_version = %self.key_version,
                    "KMS returned a signature that does not verify against the key version"
                );
                SignError::new("kms returned an invalid signature")
            })?;
        Ok(bytes)
    }

    /// Send one authenticated KMS request built by `request` and return its
    /// body. A 401 means the cached token was refused before it was due to
    /// expire: it is dropped and the request sent once more with a new one.
    /// Every failure is a [`SignError`] whose text stays generic; the detail
    /// is logged.
    async fn call<F>(&self, request: F) -> Result<Vec<u8>, SignError>
    where
        F: Fn() -> reqwest::RequestBuilder,
    {
        match self.call_once(&request).await {
            Err(Refused::Unauthorized(token)) => {
                self.tokens.invalidate(&token);
                self.call_once(&request).await.map_err(Refused::into_error)
            }
            other => other.map_err(Refused::into_error),
        }
    }

    async fn call_once<F>(&self, request: &F) -> Result<Vec<u8>, Refused>
    where
        F: Fn() -> reqwest::RequestBuilder,
    {
        let token = self.tokens.token().await.map_err(|error| {
            Refused::Error(if error.transient {
                SignError::transient(error.why)
            } else {
                SignError::new(error.why)
            })
        })?;
        let mut response = request()
            .bearer_auth(token.expose_secret())
            .send()
            .await
            .map_err(|error| {
                tracing::warn!(error = ?error, "KMS request failed");
                Refused::Error(SignError::transient(if error.is_timeout() {
                    "kms timed out"
                } else {
                    "kms unreachable"
                }))
            })?;
        let status = response.status();
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|error| {
            tracing::warn!(error = ?error, "reading a KMS response failed");
            Refused::Error(SignError::transient("kms unreachable"))
        })? {
            if body.len() + chunk.len() > KMS_BODY_MAX {
                return Err(Refused::Error(SignError::new(
                    "kms returned an oversized response",
                )));
            }
            body.extend_from_slice(&chunk);
        }
        if !status.is_success() {
            let text = String::from_utf8_lossy(&body);
            tracing::warn!(
                status = status.as_u16(),
                body = ?truncated(&text, LOGGED_BODY_MAX),
                key_version = %self.key_version,
                "KMS refused a request"
            );
            return Err(match status.as_u16() {
                401 => Refused::Unauthorized(token),
                429 => Refused::Error(SignError::transient("kms quota exhausted")),
                403 => Refused::Error(SignError::new("kms denied the workload identity")),
                404 => Refused::Error(SignError::new("kms key version not found")),
                code if code >= 500 => Refused::Error(SignError::transient("kms server error")),
                _ => Refused::Error(SignError::new("kms refused the request")),
            });
        }
        Ok(body)
    }
}

/// One KMS request's failure: a refused token (worth one retry with a new
/// token) or anything else.
enum Refused {
    Unauthorized(secrecy::SecretString),
    Error(SignError),
}

impl Refused {
    fn into_error(self) -> SignError {
        match self {
            Self::Unauthorized(_) => SignError::new("kms denied the workload identity"),
            Self::Error(error) => error,
        }
    }
}

/// The Ed25519 key in a PEM `SubjectPublicKeyInfo`, as Cloud KMS returns it.
fn ed25519_from_pem(pem: &str) -> Result<VerifyingKey, &'static str> {
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .map(str::trim)
        .collect();
    let der = BASE64
        .decode(body)
        .map_err(|_| "KMS public key is not PEM")?;
    let key: [u8; 32] = der
        .strip_prefix(&ED25519_SPKI_PREFIX)
        .and_then(|key| key.try_into().ok())
        .ok_or("KMS public key is not an Ed25519 SubjectPublicKeyInfo")?;
    VerifyingKey::from_bytes(&key).map_err(|_| "KMS public key is not a valid Ed25519 point")
}

/// At most `max` bytes of `text`, cut on a character boundary.
fn truncated(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let end = (0..=max)
        .rev()
        .find(|&index| text.is_char_boundary(index))
        .unwrap_or(0);
    &text[..end]
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use axum::extract::{Path, State};
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::{IntoResponse, Response};
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;
    use crate::signer::ChainSigner;

    const KEY: &str = "projects/example-project/locations/us-east1/keyRings/dub/cryptoKeys/chain-writer/cryptoKeyVersions/1";

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7; 32])
    }

    fn pem_of(public: &VerifyingKey) -> String {
        let der = [&ED25519_SPKI_PREFIX[..], public.as_bytes()].concat();
        format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            BASE64.encode(der)
        )
    }

    /// A stand-in for the metadata server (`/token`) and Cloud KMS (`/v1/...`),
    /// signing with a local Ed25519 key. A request it does not expect gets a
    /// 400 naming why, rather than a panic inside the server.
    struct Mock {
        signing: SigningKey,
        algorithm: String,
        public_name: Option<String>,
        sign_name: Option<String>,
        /// Answer this many public-key reads with `public_fail_status` first.
        public_failures: usize,
        public_fail_status: u16,
        /// Answer this many sign requests with 401 first.
        sign_unauthorized: usize,
        sign_status: u16,
        sign_delay: Duration,
        token_status: u16,
        /// Sign with this key instead, to return a signature that does not verify.
        wrong_key: Option<SigningKey>,
        token_hits: AtomicUsize,
        public_hits: AtomicUsize,
        sign_hits: AtomicUsize,
        signed: Mutex<Vec<Vec<u8>>>,
        bearers: Mutex<Vec<String>>,
    }

    impl Mock {
        fn new() -> Self {
            Self {
                signing: key(),
                algorithm: ED25519_ALGORITHM.to_string(),
                public_name: Some(KEY.to_string()),
                sign_name: Some(KEY.to_string()),
                public_failures: 0,
                public_fail_status: 503,
                sign_unauthorized: 0,
                sign_status: 200,
                sign_delay: Duration::ZERO,
                token_status: 200,
                wrong_key: None,
                token_hits: 0.into(),
                public_hits: 0.into(),
                sign_hits: 0.into(),
                signed: Mutex::new(Vec::new()),
                bearers: Mutex::new(Vec::new()),
            }
        }
    }

    fn bad_request(why: &str) -> Response {
        (StatusCode::BAD_REQUEST, why.to_string()).into_response()
    }

    async fn kms(mock: Arc<Mock>, rest: String, headers: HeaderMap, body: String) -> Response {
        let bearer = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        mock.bearers.lock().unwrap().push(bearer);
        if let Some(name) = rest.strip_suffix("/publicKey") {
            if name != KEY {
                return bad_request("public key read for another key version");
            }
            let hit = mock.public_hits.fetch_add(1, Ordering::SeqCst);
            if hit < mock.public_failures {
                return StatusCode::from_u16(mock.public_fail_status)
                    .unwrap()
                    .into_response();
            }
            let mut answer = serde_json::json!({
                "pem": pem_of(&mock.signing.verifying_key()),
                "algorithm": mock.algorithm,
                "protectionLevel": "SOFTWARE",
            });
            if let Some(name) = &mock.public_name {
                answer["name"] = serde_json::json!(name);
            }
            return answer.to_string().into_response();
        }
        let Some(name) = rest.strip_suffix(":asymmetricSign") else {
            return bad_request("unknown path");
        };
        if name != KEY {
            return bad_request("signing with another key version");
        }
        let hit = mock.sign_hits.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(mock.sign_delay).await;
        if hit < mock.sign_unauthorized {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        if mock.sign_status != 200 {
            return (
                StatusCode::from_u16(mock.sign_status).unwrap(),
                r#"{"error":{"message":"denied on projects/example-project"}}"#,
            )
                .into_response();
        }
        let Some(data) = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|request| BASE64.decode(request["data"].as_str()?).ok())
        else {
            return bad_request("no base64 data field");
        };
        mock.signed.lock().unwrap().push(data.clone());
        let signer = mock.wrong_key.as_ref().unwrap_or(&mock.signing);
        let mut answer =
            serde_json::json!({ "signature": BASE64.encode(signer.sign(&data).to_bytes()) });
        if let Some(name) = &mock.sign_name {
            answer["name"] = serde_json::json!(name);
        }
        answer.to_string().into_response()
    }

    async fn serve(mock: Mock) -> (String, Arc<Mock>) {
        let mock = Arc::new(mock);
        let app = axum::Router::new()
            .route(
                "/token",
                axum::routing::get(|State(mock): State<Arc<Mock>>| async move {
                    let hit = mock.token_hits.fetch_add(1, Ordering::SeqCst);
                    let mut response: Response = (
                        StatusCode::from_u16(mock.token_status).unwrap(),
                        serde_json::json!({"access_token": format!("ya29.t{hit}"), "expires_in": 3599})
                            .to_string(),
                    )
                        .into_response();
                    response
                        .headers_mut()
                        .insert("metadata-flavor", "Google".parse().unwrap());
                    response
                }),
            )
            .route(
                "/v1/{*rest}",
                axum::routing::any(
                    |State(mock): State<Arc<Mock>>,
                     Path(rest): Path<String>,
                     headers: HeaderMap,
                     body: String| kms(mock, rest, headers, body),
                ),
            )
            .with_state(mock.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}"), mock)
    }

    fn endpoints(base: &str, timeout: Duration) -> KmsEndpoints {
        KmsEndpoints {
            api: format!("{base}/v1"),
            metadata_token: format!("{base}/token"),
            timeout,
            connect_backoff: Duration::ZERO,
            https_only: false,
        }
    }

    async fn connect(base: &str) -> anyhow::Result<KmsSigner> {
        KmsSigner::connect_to(KEY, endpoints(base, Duration::from_secs(5))).await
    }

    fn hits(counter: &AtomicUsize) -> usize {
        counter.load(Ordering::SeqCst)
    }

    #[test]
    fn key_version_names_are_validated() {
        assert!(is_key_version_name(KEY));
        for bad in [
            "",
            "projects/example-project/locations/us-east1/keyRings/dub/cryptoKeys/chain-writer",
            "projects/example-project/locations/us-east1/keyRings/dub/cryptoKeys/chain-writer/cryptoKeyVersions/0",
            "projects/example-project/locations/us-east1/keyRings/dub/cryptoKeys/chain-writer/cryptoKeyVersions/01",
            "projects/example-project/locations/us-east1/keyRings/dub/cryptoKeys/chain-writer/cryptoKeyVersions/1/x",
            "projects/PCF/locations/us-east1/keyRings/dub/cryptoKeys/k/cryptoKeyVersions/1",
            "projects/123456789012/locations/us-east1/keyRings/dub/cryptoKeys/k/cryptoKeyVersions/1",
            "projects/example-project/locations/us-east1/keyRings/../cryptoKeys/k/cryptoKeyVersions/1",
            "projects/example-project/locations/us-east1/keyRings/dub/cryptoKeys/k?x/cryptoKeyVersions/1",
            "projects/example-project/locations/us-east1/keyRings/dub/cryptoKeys/k%2F/cryptoKeyVersions/1",
            "projects/example-project/locations/us-east1/keyRings/dub/cryptoKeys/k/cryptoKeyVersions/1 ",
            "https://cloudkms.googleapis.com/v1/projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
        ] {
            assert!(!is_key_version_name(bad), "{bad:?}");
        }
    }

    #[tokio::test]
    async fn connect_derives_the_account_from_the_kms_public_key() {
        let (base, mock) = serve(Mock::new()).await;
        let signer = connect(&base).await.unwrap();
        assert_eq!(signer.public_bytes(), key().verifying_key().to_bytes());
        assert_eq!(signer.key_version(), KEY);
        assert_eq!(mock.bearers.lock().unwrap().as_slice(), &["Bearer ya29.t0"]);
    }

    #[tokio::test]
    async fn connect_refuses_a_key_that_is_not_the_configured_ed25519_version() {
        let mut mock = Mock::new();
        mock.algorithm = "EC_SIGN_P256_SHA256".to_string();
        let (base, _) = serve(mock).await;
        let error = connect(&base).await.err().unwrap().to_string();
        assert!(error.contains("not EC_SIGN_ED25519"), "{error}");

        let mut mock = Mock::new();
        mock.public_name = Some(KEY.replace("Versions/1", "Versions/2"));
        let (base, _) = serve(mock).await;
        let error = connect(&base).await.err().unwrap().to_string();
        assert!(error.contains("another key version"), "{error}");

        let error = KmsSigner::connect_to(
            "projects/p/oops",
            endpoints("http://127.0.0.1:9", Duration::from_secs(1)),
        )
        .await
        .err()
        .unwrap()
        .to_string();
        assert!(error.contains("key version name"), "{error}");
    }

    #[tokio::test]
    async fn connect_retries_transient_failures_only() {
        // The metadata server or KMS still warming up: retried, then connected.
        let mut mock = Mock::new();
        mock.public_failures = 2;
        let (base, mock) = serve(mock).await;
        connect(&base).await.unwrap();
        assert_eq!(hits(&mock.public_hits), 3);

        // A refusal is not retried.
        let mut mock = Mock::new();
        mock.public_failures = 10;
        mock.public_fail_status = 403;
        let (base, mock) = serve(mock).await;
        let error = connect(&base).await.err().unwrap().to_string();
        assert!(
            error.contains("kms denied the workload identity"),
            "{error}"
        );
        assert_eq!(hits(&mock.public_hits), 1);

        // A transient failure that outlasts the attempts gives up.
        let mut mock = Mock::new();
        mock.public_failures = 100;
        let (base, mock) = serve(mock).await;
        let error = connect(&base).await.err().unwrap().to_string();
        assert!(error.contains("kms server error"), "{error}");
        assert_eq!(hits(&mock.public_hits), CONNECT_ATTEMPTS as usize);
    }

    #[tokio::test]
    async fn signs_the_payload_as_given_and_returns_a_verified_ed25519_signature() {
        let (base, mock) = serve(Mock::new()).await;
        let signer = ChainSigner::Kms(connect(&base).await.unwrap());
        // Already hashed by the extrinsic encoder when long; signed verbatim.
        let payload = vec![9u8; 300];
        let subxt::utils::MultiSignature::Ed25519(bytes) = signer.sign(&payload).await.unwrap()
        else {
            panic!("a KMS signer signs with Ed25519");
        };
        key()
            .verifying_key()
            .verify_strict(&payload, &Signature::from_bytes(&bytes))
            .unwrap();
        assert_eq!(mock.signed.lock().unwrap().as_slice(), &[payload]);
        assert_eq!(signer.label(), "kms-ed25519");
        assert_eq!(signer.kms_key_version(), Some(KEY));
    }

    #[tokio::test]
    async fn a_response_without_a_name_is_still_checked_by_its_signature() {
        let mut mock = Mock::new();
        mock.public_name = None;
        mock.sign_name = None;
        let (base, _) = serve(mock).await;
        let signer = connect(&base).await.unwrap();
        signer.sign(b"payload").await.unwrap();

        let mut mock = Mock::new();
        mock.sign_name = None;
        mock.wrong_key = Some(SigningKey::from_bytes(&[8; 32]));
        let (base, _) = serve(mock).await;
        let signer = connect(&base).await.unwrap();
        assert_eq!(
            signer.sign(b"payload").await.unwrap_err().to_string(),
            "chain signer unavailable (kms returned an invalid signature)"
        );
    }

    #[tokio::test]
    async fn the_workload_token_is_fetched_once_and_reused() {
        let (base, mock) = serve(Mock::new()).await;
        let signer = connect(&base).await.unwrap();
        signer.sign(b"one").await.unwrap();
        signer.sign(b"two").await.unwrap();
        assert_eq!(hits(&mock.token_hits), 1);
    }

    #[tokio::test]
    async fn a_refused_token_is_replaced_and_the_request_sent_once_more() {
        let mut mock = Mock::new();
        mock.sign_unauthorized = 1;
        let (base, mock) = serve(mock).await;
        let signer = connect(&base).await.unwrap();
        signer.sign(b"payload").await.unwrap();
        assert_eq!(hits(&mock.token_hits), 2);
        assert_eq!(
            mock.bearers.lock().unwrap().as_slice(),
            &["Bearer ya29.t0", "Bearer ya29.t0", "Bearer ya29.t1"]
        );

        // Refused again with the new token: a signing failure, no third try.
        let mut mock = Mock::new();
        mock.sign_unauthorized = 10;
        let (base, mock) = serve(mock).await;
        let signer = connect(&base).await.unwrap();
        let error = signer.sign(b"payload").await.unwrap_err();
        assert_eq!(
            error.to_string(),
            "chain signer unavailable (kms denied the workload identity)"
        );
        assert!(!error.is_transient());
        assert_eq!(hits(&mock.sign_hits), 2);
    }

    #[tokio::test]
    async fn a_signature_that_does_not_verify_is_refused() {
        let mut mock = Mock::new();
        mock.wrong_key = Some(SigningKey::from_bytes(&[8; 32]));
        let (base, _) = serve(mock).await;
        let signer = connect(&base).await.unwrap();
        assert_eq!(
            signer.sign(b"payload").await.unwrap_err().to_string(),
            "chain signer unavailable (kms returned an invalid signature)"
        );
    }

    #[tokio::test]
    async fn kms_refusals_are_signing_failures_with_generic_text() {
        for (status, why, transient) in [
            (429, "kms quota exhausted", true),
            (403, "kms denied the workload identity", false),
            (404, "kms key version not found", false),
            (500, "kms server error", true),
            (503, "kms server error", true),
            (400, "kms refused the request", false),
        ] {
            let mut mock = Mock::new();
            mock.sign_status = status;
            let (base, _) = serve(mock).await;
            let signer = connect(&base).await.unwrap();
            let error = signer.sign(b"payload").await.unwrap_err();
            assert_eq!(
                error.to_string(),
                format!("chain signer unavailable ({why})")
            );
            assert_eq!(error.is_transient(), transient, "{status}");
            assert!(
                !error.to_string().contains("example-project"),
                "no resource detail: {error}"
            );
        }
    }

    #[tokio::test]
    async fn a_slow_kms_times_out_as_a_transient_signing_failure() {
        let mut mock = Mock::new();
        mock.sign_delay = Duration::from_secs(3);
        let (base, _) = serve(mock).await;
        // Generous enough for the public-key read on a busy runner, far below
        // the signing delay.
        let signer = KmsSigner::connect_to(KEY, endpoints(&base, Duration::from_millis(1000)))
            .await
            .unwrap();
        let error = signer.sign(b"payload").await.unwrap_err();
        assert_eq!(
            error.to_string(),
            "chain signer unavailable (kms timed out)"
        );
        assert!(error.is_transient());
    }

    #[tokio::test]
    async fn without_a_workload_token_nothing_is_signed_or_even_connected() {
        let mut mock = Mock::new();
        mock.token_status = 403;
        let (base, mock) = serve(mock).await;
        let error = connect(&base).await.err().unwrap().to_string();
        assert!(error.contains("metadata server refused a token"), "{error}");
        assert_eq!(hits(&mock.public_hits), 0, "no KMS request without a token");
        assert_eq!(hits(&mock.token_hits), 1, "a refusal is not retried");
    }

    #[test]
    fn pem_public_keys_decode_and_garbage_is_refused() {
        let public = key().verifying_key();
        assert_eq!(ed25519_from_pem(&pem_of(&public)).unwrap(), public);
        assert!(
            ed25519_from_pem("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----").is_err()
        );
        assert!(ed25519_from_pem("not base64 !").is_err());
    }

    #[test]
    fn production_endpoints_refuse_plain_http() {
        let endpoints = KmsEndpoints::default();
        assert!(endpoints.https_only);
        assert!(endpoints.api.starts_with("https://"));
        assert_eq!(endpoints.metadata_token, METADATA_TOKEN_URL);
    }
}

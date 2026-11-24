// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::str::FromStr as _;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::Request;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use device_attestation::chain::asset_hub::AssetHub;
use device_attestation::{AppState, Config, Jwt, PeopleChain};
use http_body_util::BodyExt as _;
use sha2::{Digest as _, Sha256};
use subxt_signer::sr25519::Keypair;
use subxt_signer::SecretUri;
use tower::ServiceExt as _;

const JWT_SEED: [u8; 32] = [42u8; 32];

async fn test_pool() -> sqlx::PgPool {
    let database_url = std::env::var("DEVICE_ATTESTATION_TEST_DATABASE_URL")
        .expect("DEVICE_ATTESTATION_TEST_DATABASE_URL is required");
    device_attestation::db::connect(&database_url)
        .await
        .expect("connect and migrate")
}

async fn dead_chain_client() -> PeopleChain {
    use subxt_rpcs::client::mock_rpc_client::Json;
    use subxt_rpcs::client::{MockRpcClient, RpcClient};

    let mock = MockRpcClient::builder()
        .method_handler("chain_getBlockHash", |_params| async {
            Json(serde_json::json!(format!("0x{}", "00".repeat(32))))
        })
        .build();
    let rpc = RpcClient::new(mock);
    let backend = subxt::backend::LegacyBackend::builder().build(rpc.clone());
    let client = subxt::OnlineClient::<chain_types::PeopleConfig>::from_backend(Arc::new(backend))
        .await
        .expect("offline client from mock backend");
    PeopleChain::from_parts(client, rpc)
}

/// An Asset Hub client that answers nothing: the auth routes never read it.
async fn dead_asset_hub_client() -> AssetHub {
    use subxt_rpcs::client::mock_rpc_client::Json;
    use subxt_rpcs::client::{MockRpcClient, RpcClient};

    let mock = MockRpcClient::builder()
        .method_handler("chain_getBlockHash", |_params| async {
            Json(serde_json::json!(format!("0x{}", "00".repeat(32))))
        })
        .build();
    let rpc = RpcClient::new(mock);
    let backend = subxt::backend::LegacyBackend::builder().build(rpc.clone());
    let client =
        subxt::OnlineClient::<chain_types::AssetHubConfig>::from_backend(Arc::new(backend))
            .await
            .expect("offline client from mock backend");
    AssetHub::from_parts(client, rpc)
}

async fn app(pool: sqlx::PgPool, configure: impl FnOnce(&mut Config)) -> axum::Router {
    let mut config = Config::test_default();
    configure(&mut config);
    let jwt = Jwt::new(&JWT_SEED, config.jwt_issuer.clone());
    device_attestation::routes(AppState::new(
        pool,
        dead_chain_client().await,
        dead_asset_hub_client().await,
        jwt,
        config,
    ))
}

async fn read_json(response: axum::response::Response) -> (u16, serde_json::Value) {
    let status = response.status().as_u16();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("read body")
        .to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

async fn mint_challenge(app: &axum::Router) -> (String, Vec<u8>) {
    let response = app
        .clone()
        .oneshot(
            Request::post("/api/v1/auth/challenges")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("infallible");
    let (status, body) = read_json(response).await;
    assert_eq!(status, 201);
    let challenge_b64 = body["challenge"].as_str().expect("challenge").to_string();
    let bytes = STANDARD.decode(&challenge_b64).expect("base64 challenge");
    assert_eq!(bytes.len(), 32);
    (challenge_b64, bytes)
}

fn sign_proof(keypair: &Keypair, challenge: &[u8], body: &[u8]) -> [u8; 64] {
    let mut hasher = Sha256::new();
    hasher.update(challenge);
    hasher.update(keypair.public_key().0);
    hasher.update(Sha256::digest(body));
    let message: [u8; 32] = hasher.finalize().into();
    keypair.sign(&message).0
}

fn token_request(
    keypair: &Keypair,
    challenge_b64: &str,
    challenge: &[u8],
    body: &'static [u8],
) -> Request<Body> {
    let proof = sign_proof(keypair, challenge, body);
    Request::post("/api/v1/auth/token")
        .header("Auth-ClientId", STANDARD.encode(keypair.public_key().0))
        .header("Auth-ClientProof", STANDARD.encode(proof))
        .header("Auth-Challenge", challenge_b64)
        .body(Body::from(body))
        .expect("request")
}

fn dev_keypair(uri: &str) -> Keypair {
    Keypair::from_uri(&SecretUri::from_str(uri).expect("uri")).expect("keypair")
}

#[tokio::test]
#[ignore = "requires Postgres; set DEVICE_ATTESTATION_TEST_DATABASE_URL and run with --ignored"]
async fn challenges_are_single_use_and_expire() {
    let pool = test_pool().await;
    let app = app(pool.clone(), |_| {}).await;
    let keypair = dev_keypair("//Bob");
    let account_id = format!("0x{}", hex::encode(keypair.public_key().0));

    let (challenge_b64, challenge) = mint_challenge(&app).await;
    let (status, body) = read_json(
        app.clone()
            .oneshot(token_request(&keypair, &challenge_b64, &challenge, b"{}"))
            .await
            .expect("infallible"),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = read_json(
        app.clone()
            .oneshot(token_request(&keypair, &challenge_b64, &challenge, b"{}"))
            .await
            .expect("infallible"),
    )
    .await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["error"], "UNAUTHORIZED");

    let concurrent_keypair = dev_keypair("//Bob//concurrent");
    let concurrent_account = format!("0x{}", hex::encode(concurrent_keypair.public_key().0));
    let (concurrent_b64, concurrent_challenge) = mint_challenge(&app).await;
    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let spawn_token = |request: Request<Body>| {
        let app = app.clone();
        let barrier = Arc::clone(&barrier);
        tokio::spawn(async move {
            barrier.wait().await;
            read_json(app.oneshot(request).await.expect("infallible")).await
        })
    };
    let first = spawn_token(token_request(
        &concurrent_keypair,
        &concurrent_b64,
        &concurrent_challenge,
        b"{}",
    ));
    let second = spawn_token(token_request(
        &concurrent_keypair,
        &concurrent_b64,
        &concurrent_challenge,
        b"{}",
    ));
    barrier.wait().await;
    let (first, second) = tokio::join!(first, second);
    let mut statuses = [first.expect("first task").0, second.expect("second task").0];
    statuses.sort_unstable();
    assert_eq!(statuses, [200, 401]);
    let concurrent_consumed: bool = sqlx::query_scalar(
        "SELECT consumed_at IS NOT NULL FROM auth_challenges WHERE challenge = $1",
    )
    .bind(&concurrent_challenge)
    .fetch_one(&pool)
    .await
    .expect("concurrent challenge row");
    assert!(concurrent_consumed);
    let sessions: i64 =
        sqlx::query_scalar("SELECT count(*) FROM refresh_tokens WHERE account_id = $1")
            .bind(&concurrent_account)
            .fetch_one(&pool)
            .await
            .expect("concurrent session count");
    assert_eq!(sessions, 1, "one challenge may mint only one session");

    let stale = [7u8; 32];
    sqlx::query(
        "INSERT INTO auth_challenges (challenge, expires_at) \
         VALUES ($1, now() - interval '1 second') \
         ON CONFLICT (challenge) DO UPDATE \
         SET expires_at = EXCLUDED.expires_at, consumed_at = NULL",
    )
    .bind(&stale[..])
    .execute(&pool)
    .await
    .expect("insert stale");
    let stale_b64 = STANDARD.encode(stale);
    let (status, body) = read_json(
        app.clone()
            .oneshot(token_request(&keypair, &stale_b64, &stale, b"{}"))
            .await
            .expect("infallible"),
    )
    .await;
    assert_eq!(status, 401, "{body}");
    let consumed_at: Option<time::OffsetDateTime> =
        sqlx::query_scalar("SELECT consumed_at FROM auth_challenges WHERE challenge = $1")
            .bind(&stale[..])
            .fetch_one(&pool)
            .await
            .expect("stale row");
    assert!(
        consumed_at.is_none(),
        "expired challenge must not be consumed"
    );

    let unknown = [9u8; 32];
    let unknown_b64 = STANDARD.encode(unknown);
    let (status, _) = read_json(
        app.clone()
            .oneshot(token_request(&keypair, &unknown_b64, &unknown, b"{}"))
            .await
            .expect("infallible"),
    )
    .await;
    assert_eq!(status, 401);

    sqlx::query("DELETE FROM auth_challenges WHERE challenge IN ($1, $2, $3)")
        .bind(&challenge[..])
        .bind(&concurrent_challenge[..])
        .bind(&stale[..])
        .execute(&pool)
        .await
        .expect("cleanup");
    sqlx::query("DELETE FROM refresh_tokens WHERE account_id IN ($1, $2)")
        .bind(&account_id)
        .bind(&concurrent_account)
        .execute(&pool)
        .await
        .expect("cleanup");
}

#[tokio::test]
#[ignore = "requires Postgres; set DEVICE_ATTESTATION_TEST_DATABASE_URL and run with --ignored"]
async fn token_route_issues_a_session_and_rejects_bad_proofs() {
    let pool = test_pool().await;
    let app = app(pool.clone(), |_| {}).await;
    let keypair = dev_keypair("//Alice");
    let account_id = format!("0x{}", hex::encode(keypair.public_key().0));

    let (challenge_b64, challenge) = mint_challenge(&app).await;
    let response = app
        .clone()
        .oneshot(token_request(&keypair, &challenge_b64, &challenge, b"{}"))
        .await
        .expect("infallible");
    let (status, body) = read_json(response).await;
    assert_eq!(status, 200, "{body}");
    let token = body["token"].as_str().expect("token");
    let refresh_token = body["refreshToken"].as_str().expect("refreshToken");
    assert_eq!(token.split('.').count(), 3, "JWT shape");

    let claims_b64 = token.split('.').nth(1).expect("claims segment");
    let claims: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(claims_b64)
            .expect("base64 claims"),
    )
    .expect("json claims");
    assert_eq!(claims["accountId"], account_id.as_str(), "{claims}");

    let from_store: bool =
        sqlx::query_scalar("SELECT app_from_official_store FROM refresh_tokens WHERE token = $1")
            .bind(refresh_token)
            .fetch_one(&pool)
            .await
            .expect("refresh row");
    assert!(from_store);

    let (challenge_b64, challenge) = mint_challenge(&app).await;
    let mut request = token_request(&keypair, &challenge_b64, &challenge, b"{}");
    *request.body_mut() = Body::from(&b"{ }"[..]);
    let (status, body) = read_json(app.clone().oneshot(request).await.expect("infallible")).await;
    assert_eq!(status, 401, "{body}");

    sqlx::query("DELETE FROM refresh_tokens WHERE account_id = $1")
        .bind(&account_id)
        .execute(&pool)
        .await
        .expect("cleanup");
}

#[tokio::test]
#[ignore = "requires Postgres; set DEVICE_ATTESTATION_TEST_DATABASE_URL and run with --ignored"]
async fn attestation_soft_mode_allows_and_hard_mode_rejects_missing_evidence() {
    let pool = test_pool().await;
    let keypair = dev_keypair("//Charlie");
    let account_id = format!("0x{}", hex::encode(keypair.public_key().0));

    let soft = app(pool.clone(), |c| {
        c.auth_enabled = true;
        c.enforce_auth = false;
    })
    .await;
    let (challenge_b64, challenge) = mint_challenge(&soft).await;
    let response = soft
        .clone()
        .oneshot(token_request(&keypair, &challenge_b64, &challenge, b"{}"))
        .await
        .expect("infallible");
    let (status, body) = read_json(response).await;
    assert_eq!(status, 200, "{body}");
    let from_store: bool =
        sqlx::query_scalar("SELECT app_from_official_store FROM refresh_tokens WHERE token = $1")
            .bind(body["refreshToken"].as_str().expect("refreshToken"))
            .fetch_one(&pool)
            .await
            .expect("refresh row");
    assert!(
        !from_store,
        "soft-mode verdict failure must not fabricate true"
    );

    let hard = app(pool.clone(), |c| {
        c.auth_enabled = true;
        c.enforce_auth = true;
    })
    .await;
    let (challenge_b64, challenge) = mint_challenge(&hard).await;
    let response = hard
        .clone()
        .oneshot(token_request(&keypair, &challenge_b64, &challenge, b"{}"))
        .await
        .expect("infallible");
    let (status, body) = read_json(response).await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["error"], "INTEGRITY_FAILED");
    assert!(
        body["message"]
            .as_str()
            .expect("message")
            .contains("no attestation evidence"),
        "{body}"
    );

    let (challenge_b64, challenge) = mint_challenge(&hard).await;
    let mut request = token_request(&keypair, &challenge_b64, &challenge, b"{}");
    request
        .headers_mut()
        .insert("Auth-Attestation-Type", "banana".parse().expect("header"));
    let (status, body) = read_json(hard.clone().oneshot(request).await.expect("infallible")).await;
    assert_eq!(status, 403, "{body}");
    assert!(
        body["message"]
            .as_str()
            .expect("message")
            .contains("unknown Auth-Attestation-Type"),
        "{body}"
    );

    sqlx::query("DELETE FROM refresh_tokens WHERE account_id = $1")
        .bind(&account_id)
        .execute(&pool)
        .await
        .expect("cleanup");
}

#[tokio::test]
#[ignore = "requires Postgres; set DEVICE_ATTESTATION_TEST_DATABASE_URL and run with --ignored"]
async fn refresh_rotation_is_single_use_and_carries_claims_forward() {
    let pool = test_pool().await;
    let app = app(pool.clone(), |_| {}).await;
    let keypair = dev_keypair("//Dave");
    let account_id = format!("0x{}", hex::encode(keypair.public_key().0));

    let (challenge_b64, challenge) = mint_challenge(&app).await;
    let mut request = token_request(&keypair, &challenge_b64, &challenge, b"{}");
    request.headers_mut().insert(
        "Auth-iOS-Package",
        "io.pcf.polkadotapp".parse().expect("header"),
    );
    let (status, body) = read_json(app.clone().oneshot(request).await.expect("infallible")).await;
    assert_eq!(status, 200, "{body}");
    let minted = body["refreshToken"]
        .as_str()
        .expect("refreshToken")
        .to_string();

    let rotate = |token: String| {
        let app = app.clone();
        async move {
            let request = Request::post("/api/v1/auth/token/refresh")
                .header("content-type", "application/json")
                .body(Body::from(format!("{{\"refreshToken\":\"{token}\"}}")))
                .expect("request");
            read_json(app.oneshot(request).await.expect("infallible")).await
        }
    };

    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let spawn_rotate = || {
        let app = app.clone();
        let token = minted.clone();
        let barrier = Arc::clone(&barrier);
        tokio::spawn(async move {
            let request = Request::post("/api/v1/auth/token/refresh")
                .header("content-type", "application/json")
                .body(Body::from(format!("{{\"refreshToken\":\"{token}\"}}")))
                .expect("request");
            barrier.wait().await;
            read_json(app.oneshot(request).await.expect("infallible")).await
        })
    };
    let first = spawn_rotate();
    let second = spawn_rotate();
    barrier.wait().await;
    let (first, second) = tokio::join!(first, second);
    let mut results = [first.expect("first task"), second.expect("second task")];
    results.sort_by_key(|(status, _)| *status);
    assert_eq!([results[0].0, results[1].0], [200, 401]);
    let replacement = results[0].1["refreshToken"]
        .as_str()
        .expect("refreshToken")
        .to_string();
    assert_ne!(replacement, minted);

    let (used, stored_replacement): (bool, Option<String>) = sqlx::query_as(
        "SELECT used_at IS NOT NULL, replaced_by FROM refresh_tokens WHERE token = $1",
    )
    .bind(&minted)
    .fetch_one(&pool)
    .await
    .expect("presented row");
    assert!(used);
    assert_eq!(stored_replacement.as_deref(), Some(replacement.as_str()));
    let replacement_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM refresh_tokens WHERE account_id = $1 AND token <> $2",
    )
    .bind(&account_id)
    .bind(&minted)
    .fetch_one(&pool)
    .await
    .expect("replacement count");
    assert_eq!(replacement_count, 1, "rotation must create one replacement");

    let (row_account, from_store, platform): (String, bool, Option<String>) = sqlx::query_as(
        "SELECT account_id, app_from_official_store, platform \
         FROM refresh_tokens WHERE token = $1",
    )
    .bind(&replacement)
    .fetch_one(&pool)
    .await
    .expect("replacement row");
    assert_eq!(row_account, account_id);
    assert!(from_store);
    assert_eq!(platform.as_deref(), Some("ios"));

    let (status, body) = rotate(minted.clone()).await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["error"], "UNAUTHORIZED");

    let (status, _) = rotate("never-issued".to_string()).await;
    assert_eq!(status, 401);

    sqlx::query(
        "UPDATE refresh_tokens SET expires_at = now() - interval '1 second' WHERE token = $1",
    )
    .bind(&replacement)
    .execute(&pool)
    .await
    .expect("expire");
    let (status, _) = rotate(replacement).await;
    assert_eq!(status, 401);

    sqlx::query("DELETE FROM refresh_tokens WHERE account_id = $1")
        .bind(&account_id)
        .execute(&pool)
        .await
        .expect("cleanup");
}

#[tokio::test]
#[ignore = "requires Postgres; set DEVICE_ATTESTATION_TEST_DATABASE_URL and run with --ignored"]
async fn app_attest_store_resets_on_reregistration_and_guards_the_counter() {
    use device_attestation::app_attest_store as store;

    let pool = test_pool().await;
    let key_id = format!("authlive-key-{}", std::process::id()).into_bytes();

    store::upsert(&pool, &key_id, &[1u8; 65], b"receipt-a", Some(b"client-a"))
        .await
        .expect("upsert");
    let key = store::find(&pool, &key_id)
        .await
        .expect("find")
        .expect("registered");
    assert_eq!(key.public_key, vec![1u8; 65]);
    assert_eq!(key.sign_count, 0);

    assert!(store::commit_sign_count(&pool, &key_id, 5)
        .await
        .expect("commit"));
    assert!(
        !store::commit_sign_count(&pool, &key_id, 5)
            .await
            .expect("commit"),
        "equal counter must not advance"
    );
    assert!(
        !store::commit_sign_count(&pool, &key_id, 4)
            .await
            .expect("commit"),
        "backward counter must not advance"
    );
    assert!(
        !store::commit_sign_count(&pool, b"authlive-unregistered", 1)
            .await
            .expect("commit"),
        "unknown key must not advance"
    );

    store::upsert(&pool, &key_id, &[2u8; 65], b"receipt-b", None)
        .await
        .expect("re-register");
    let key = store::find(&pool, &key_id)
        .await
        .expect("find")
        .expect("registered");
    assert_eq!(key.public_key, vec![2u8; 65]);
    assert_eq!(key.sign_count, 0);

    sqlx::query("DELETE FROM app_attest_keys WHERE key_id = $1")
        .bind(&key_id)
        .execute(&pool)
        .await
        .expect("cleanup");
}

#[tokio::test]
#[ignore = "requires Postgres; set DEVICE_ATTESTATION_TEST_DATABASE_URL and run with --ignored"]
async fn attestation_precheck_reasons_surface_in_hard_mode() {
    let pool = test_pool().await;
    let keypair = dev_keypair("//Eve");
    let account_id = format!("0x{}", hex::encode(keypair.public_key().0));
    let configured = app(pool.clone(), |c| {
        c.auth_enabled = true;
        c.enforce_auth = true;
        c.ios_package_names = vec!["io.pcf.polkadotapp".to_string()];
        c.android_package_names = vec!["com.example.app".to_string()];
        c.android_signing_digest_playstore = Some([1u8; 32]);
        c.android_signing_digest_website = Some([2u8; 32]);
    })
    .await;
    let no_digests = app(pool.clone(), |c| {
        c.auth_enabled = true;
        c.enforce_auth = true;
        c.android_package_names = vec!["com.example.app".to_string()];
    })
    .await;

    type Case<'a> = (
        &'static str,
        &'a axum::Router,
        Vec<(&'static str, &'static str)>,
        &'static str,
    );
    let cases: Vec<Case> = vec![
        (
            "unknown iOS package",
            &configured,
            vec![("Auth-iOS-Package", "com.evil.app")],
            "unknown iOS package",
        ),
        (
            "iOS assertion missing",
            &configured,
            vec![("Auth-iOS-Package", "io.pcf.polkadotapp")],
            "missing or invalid Auth-Payload assertion",
        ),
        (
            "iOS key id missing",
            &configured,
            vec![
                ("Auth-iOS-Package", "io.pcf.polkadotapp"),
                ("Auth-Payload", "AAAA"),
            ],
            "missing or invalid Auth-iOS-KeyId",
        ),
        (
            "iOS key never registered",
            &configured,
            vec![
                ("Auth-iOS-Package", "io.pcf.polkadotapp"),
                ("Auth-Payload", "AAAA"),
                ("Auth-iOS-KeyId", "AAAA"),
            ],
            "unregistered App Attest key",
        ),
        (
            "play-integrity without package header",
            &configured,
            vec![("Auth-Attestation-Type", "play-integrity")],
            "missing Auth-Android-Package",
        ),
        (
            "play-integrity with unknown package",
            &configured,
            vec![
                ("Auth-Attestation-Type", "play-integrity"),
                ("Auth-Android-Package", "com.evil.app"),
            ],
            "unknown Android package",
        ),
        (
            "play-integrity without token",
            &configured,
            vec![
                ("Auth-Attestation-Type", "play-integrity"),
                ("Auth-Android-Package", "com.example.app"),
            ],
            "missing Auth-Payload integrity token",
        ),
        (
            "play-integrity with no verification keys configured",
            &configured,
            vec![
                ("Auth-Attestation-Type", "play-integrity"),
                ("Auth-Android-Package", "com.example.app"),
                ("Auth-Payload", "opaque-jwe"),
            ],
            "play integrity is not configured",
        ),
        (
            "play-integrity without signing digests",
            &no_digests,
            vec![
                ("Auth-Attestation-Type", "play-integrity"),
                ("Auth-Android-Package", "com.example.app"),
                ("Auth-Payload", "opaque-jwe"),
            ],
            "android signing digests are not configured",
        ),
    ];
    for (label, app, headers, want_reason) in cases {
        let (challenge_b64, challenge) = mint_challenge(app).await;
        let mut request = token_request(&keypair, &challenge_b64, &challenge, b"{}");
        for (name, value) in headers {
            request
                .headers_mut()
                .insert(name, value.parse().expect("header"));
        }
        let (status, body) =
            read_json(app.clone().oneshot(request).await.expect("infallible")).await;
        assert_eq!(status, 403, "{label}: {body}");
        assert_eq!(body["error"], "INTEGRITY_FAILED", "{label}");
        assert!(
            body["message"]
                .as_str()
                .expect("message")
                .contains(want_reason),
            "{label}: {body}"
        );
    }

    sqlx::query("DELETE FROM refresh_tokens WHERE account_id = $1")
        .bind(&account_id)
        .execute(&pool)
        .await
        .expect("cleanup");
}

#[tokio::test]
async fn token_route_rejects_missing_or_malformed_headers_with_400() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(50))
        .connect_lazy("postgres://nobody@127.0.0.1:1/nothing")
        .expect("lazy pool");
    let app = app(pool, |_| {}).await;
    let keypair = dev_keypair("//Ferdie");

    let base = || {
        Request::post("/api/v1/auth/token")
            .header("Auth-ClientProof", STANDARD.encode([0u8; 64]))
            .header("Auth-Challenge", STANDARD.encode([0u8; 32]))
    };
    let cases: Vec<(&str, Request<Body>)> = vec![
        (
            "missing Auth-ClientId",
            base().body(Body::from(&b"{}"[..])).expect("request"),
        ),
        (
            "Auth-ClientId not base64",
            base()
                .header("Auth-ClientId", "!!not-base64!!")
                .body(Body::from(&b"{}"[..]))
                .expect("request"),
        ),
        (
            "Auth-ClientId wrong length",
            base()
                .header("Auth-ClientId", STANDARD.encode([0u8; 16]))
                .body(Body::from(&b"{}"[..]))
                .expect("request"),
        ),
        (
            "Auth-ClientProof wrong length",
            Request::post("/api/v1/auth/token")
                .header("Auth-ClientId", STANDARD.encode(keypair.public_key().0))
                .header("Auth-ClientProof", STANDARD.encode([0u8; 32]))
                .header("Auth-Challenge", STANDARD.encode([0u8; 32]))
                .body(Body::from(&b"{}"[..]))
                .expect("request"),
        ),
        (
            "missing Auth-Challenge",
            Request::post("/api/v1/auth/token")
                .header("Auth-ClientId", STANDARD.encode(keypair.public_key().0))
                .header("Auth-ClientProof", STANDARD.encode([0u8; 64]))
                .body(Body::from(&b"{}"[..]))
                .expect("request"),
        ),
    ];
    for (label, request) in cases {
        let (status, body) =
            read_json(app.clone().oneshot(request).await.expect("infallible")).await;
        assert_eq!(status, 400, "{label}: {body}");
        assert_eq!(body["error"], "WRONG_DATA", "{label}");
    }
}

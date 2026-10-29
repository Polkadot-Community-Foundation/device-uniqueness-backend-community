// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt as _;
use tower::ServiceExt as _;
use turn::config::{Config, ProofConfig, PROOF_MAX_SKEW_SECS};
use turn::proof::message::Freshness;
use turn::proof::roots::{AcceptedRoot, PersonhoodCollection, Snapshot};
use turn::AppState;
use verifiable::ring::ark_vrf::ring::SrsLookup as _;
use verifiable::ring::bandersnatch::{BandersnatchProverCache, BandersnatchVrfVerifiable};
use verifiable::ring::{ProverCache as _, RingDomainSize, StaticChunk};
use verifiable::GenerateVerifiable as _;

type Vrf = BandersnatchVrfVerifiable;
type Secret = <Vrf as verifiable::GenerateVerifiable>::Secret;
type Member = <Vrf as verifiable::GenerateVerifiable>::Member;
type Members = <Vrf as verifiable::GenerateVerifiable>::Members;

const DOMAIN: RingDomainSize = RingDomainSize::Domain11;
const GENESIS: [u8; 32] = [7u8; 32];
const PRODUCT: &str = "test-product.dot";
const OTHER_PRODUCT: &str = "other-product.dot";
const PEOPLE_LITE_COLLECTION: &str =
    "0x706f703a706f6c6b61646f742e6e6574776f726b2f70656f706c652d6c697465";
const PEOPLE_COLLECTION: &str =
    "0x706f703a706f6c6b61646f742e6e6574776f726b2f70656f706c652020202020";
const SUFFIX: u32 = 0;
const REVISION: u32 = 4;

fn context() -> [u8; 32] {
    turn::proof::context::product_context(PRODUCT, SUFFIX)
}

fn build_ring(members: &[Member]) -> Members {
    let setup = BandersnatchProverCache::ring_setup(DOMAIN);
    let (_, pcs_params) = setup.verifier_key_builder();
    let mut intermediate = Vrf::start_members(DOMAIN);
    Vrf::push_members(&mut intermediate, members.iter().cloned(), |range| {
        (&pcs_params)
            .lookup(range)
            .map(|points| points.into_iter().map(StaticChunk).collect())
            .ok_or(())
    })
    .expect("members fit the ring");
    Vrf::finish_members(intermediate)
}

struct TestRing {
    secrets: Vec<Secret>,
    members: Vec<Member>,
    commitment: Members,
}

fn test_ring() -> TestRing {
    let secrets: Vec<_> = (0u8..4).map(|i| Vrf::new_secret([i; 32])).collect();
    let members: Vec<_> = secrets.iter().map(Vrf::member_from_secret).collect();
    let commitment = build_ring(&members);
    TestRing {
        secrets,
        members,
        commitment,
    }
}

fn proof_config() -> ProofConfig {
    ProofConfig {
        rpc_url: "ws://unused.invalid".to_string(),
        genesis: GENESIS,
        contexts: [PRODUCT, OTHER_PRODUCT]
            .into_iter()
            .map(|product| {
                (
                    product.to_string(),
                    turn::proof::context::product_context(product, SUFFIX),
                )
            })
            .collect(),
        concurrency: 2,
    }
}

fn app(proof: Option<(ProofConfig, Option<Snapshot>)>) -> axum::Router {
    app_with_rate_limit(proof, 100)
}

fn app_with_rate_limit(
    proof: Option<(ProofConfig, Option<Snapshot>)>,
    rate_limit: u32,
) -> axum::Router {
    turn::routes(state_with_rate_limit(proof, rate_limit))
}

fn state_with_rate_limit(
    proof: Option<(ProofConfig, Option<Snapshot>)>,
    rate_limit: u32,
) -> AppState {
    state_with_base_url(proof, rate_limit, spawn_cloudflare_stub())
}

fn state_with_base_url(
    proof: Option<(ProofConfig, Option<Snapshot>)>,
    rate_limit: u32,
    base_url: String,
) -> AppState {
    state_with_provider(
        proof,
        rate_limit,
        turn::config::ProviderConfig::Cloudflare {
            key_id: "test-key-id".to_string(),
            api_token: "test-api-token".to_string(),
            base_url: Some(base_url),
        },
    )
}

/// The coturn provider, which computes credentials locally from this secret.
const COTURN_SECRET: &[u8] = b"relay-shared-secret";

fn coturn_provider() -> turn::config::ProviderConfig {
    turn::config::ProviderConfig::Coturn {
        secret: COTURN_SECRET.to_vec(),
        algorithm: turn::credentials::Algorithm::Sha1,
        realm: "example.org".to_string(),
        ice_servers: vec!["turn:turn.example.org:3478?transport=udp".to_string()],
    }
}

fn state_with_provider(
    proof: Option<(ProofConfig, Option<Snapshot>)>,
    rate_limit: u32,
    provider: turn::config::ProviderConfig,
) -> AppState {
    let key = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
    let (proof_config, snapshot) = match proof {
        Some((config, snapshot)) => (Some(config), snapshot),
        None => (None, None),
    };
    let config = Config {
        bind_addr: "127.0.0.1:0".parse().expect("valid addr"),
        ttl_secs: 1800,
        provider,
        jwt_verifier: jwt_verify::Verifier::from_public_key(None, key.verifying_key().as_bytes()),
        rate_limit,
        rate_window: Duration::from_secs(60),
        proof: proof_config,
    };
    let state = AppState::new(config);
    if let (Some(proof_state), Some(snapshot)) = (&state.proof, snapshot) {
        proof_state
            .roots
            .get(PersonhoodCollection::PeopleLite)
            .set(snapshot);
    }
    state
}

fn snapshot_of(commitment: Members) -> Snapshot {
    Snapshot {
        domain: DOMAIN,
        roots: std::sync::Arc::new(vec![AcceptedRoot {
            ring_index: 0,
            revision: REVISION,
            members: commitment,
        }]),
    }
}

async fn post_json(
    app: &axum::Router,
    path: &str,
    body: Option<String>,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder().method("POST").uri(path);
    let body = match body {
        Some(json) => {
            builder = builder.header("content-type", "application/json");
            Body::from(json)
        }
        None => Body::empty(),
    };
    let response = app
        .clone()
        .oneshot(builder.body(body).expect("request"))
        .await
        .expect("response");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::String(
            String::from_utf8_lossy(&bytes).to_string(),
        ))
    };
    (status, json)
}

fn prove(ring: &TestRing, secret_index: usize, context: &[u8], timestamp: u64) -> String {
    let message = Freshness::new(PROOF_MAX_SKEW_SECS).message(timestamp);
    let member = &ring.members[secret_index];
    let opening = Vrf::open(DOMAIN, member, ring.members.iter().cloned()).expect("member in ring");
    let (proof, _alias) =
        Vrf::create(opening, &ring.secrets[secret_index], context, &message).expect("proof");
    format!("0x{}", hex::encode(&proof))
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

fn body(proof: &str, ring_index: u32, timestamp: u64) -> String {
    body_for(PRODUCT, proof, ring_index, timestamp)
}

fn body_with_revision(proof: &str, ring_index: u32, ring_revision: u32, timestamp: u64) -> String {
    format!(
        r#"{{"productId":"{PRODUCT}","collection":"{PEOPLE_LITE_COLLECTION}","proof":"{proof}","ringIndex":{ring_index},"ringRevision":{ring_revision},"timestamp":{timestamp}}}"#
    )
}

fn body_for(product: &str, proof: &str, ring_index: u32, timestamp: u64) -> String {
    format!(
        r#"{{"productId":"{product}","collection":"{PEOPLE_LITE_COLLECTION}","proof":"{proof}","ringIndex":{ring_index},"ringRevision":{REVISION},"timestamp":{timestamp}}}"#
    )
}

fn fresh_body(ring: &TestRing, secret_index: usize) -> String {
    let timestamp = now_unix() + PROOF_MAX_SKEW_SECS;
    let proof = prove(ring, secret_index, &context(), timestamp);
    body(&proof, 0, timestamp)
}

#[tokio::test]
async fn proof_flow_mints_credentials_and_rejects_bad_proofs() {
    let ring = test_ring();
    let app = app(Some((
        proof_config(),
        Some(snapshot_of(ring.commitment.clone())),
    )));

    let (status, json) = post_json(
        &app,
        "/api/v1/turn/issue-with-proof",
        Some(fresh_body(&ring, 2)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{json}");
    assert_eq!(json["username"], serde_json::json!("stub-username"));
    assert_eq!(json["password"], serde_json::json!("stub-credential"));
    assert_eq!(
        json["servers"],
        serde_json::json!([
            "stun:stun.cloudflare.com:3478",
            "turn:turn.cloudflare.com:3478?transport=udp",
            "turns:turn.cloudflare.com:5349?transport=tcp"
        ])
    );
    assert_eq!(json["ttl"], serde_json::json!(1800));
    // Nothing derived from the proof may appear alongside them.
    let mut keys: Vec<_> = json.as_object().expect("object").keys().collect();
    keys.sort();
    assert_eq!(keys, ["password", "servers", "ttl", "username"]);

    let timestamp = now_unix() + PROOF_MAX_SKEW_SECS;
    let proof = prove(&ring, 2, &context(), timestamp);
    let mut bytes = hex::decode(proof.trim_start_matches("0x")).expect("hex");
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    let tampered = format!("0x{}", hex::encode(bytes));
    let (status, _) = post_json(
        &app,
        "/api/v1/turn/issue-with-proof",
        Some(body(&tampered, 0, timestamp)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let invalid_collection = body(&proof, 0, timestamp).replace(
        PEOPLE_LITE_COLLECTION,
        "0x0101010101010101010101010101010101010101010101010101010101010101",
    );
    let (status, _) = post_json(
        &app,
        "/api/v1/turn/issue-with-proof",
        Some(invalid_collection),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let timestamp = now_unix() + PROOF_MAX_SKEW_SECS;
    let proof = prove(
        &ring,
        2,
        &turn::proof::context::product_context(OTHER_PRODUCT, SUFFIX),
        timestamp,
    );
    let (status, _) = post_json(
        &app,
        "/api/v1/turn/issue-with-proof",
        Some(body(&proof, 0, timestamp)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let proof = prove(&ring, 2, &context(), timestamp - 5);
    let (status, _) = post_json(
        &app,
        "/api/v1/turn/issue-with-proof",
        Some(body(&proof, 0, timestamp)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let stale = now_unix() - PROOF_MAX_SKEW_SECS - 1;
    let proof = prove(&ring, 2, &context(), stale);
    let (status, _) = post_json(
        &app,
        "/api/v1/turn/issue-with-proof",
        Some(body(&proof, 0, stale)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let timestamp = now_unix() + PROOF_MAX_SKEW_SECS;
    let proof = prove(&ring, 2, &context(), timestamp);

    let (status, _) = post_json(
        &app,
        "/api/v1/turn/issue-with-proof",
        Some("{nope".to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let missing =
        format!(r#"{{"productId":"{PRODUCT}","proof":"{proof}","timestamp":{timestamp}}}"#);
    let (status, _) = post_json(&app, "/api/v1/turn/issue-with-proof", Some(missing)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = post_json(
        &app,
        "/api/v1/turn/issue-with-proof",
        Some(body_for("unlisted.dot", &proof, 0, timestamp)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = post_json(
        &app,
        "/api/v1/turn/issue-with-proof",
        Some(body(&proof, 1, timestamp)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_named_ring_revision_selects_exactly_that_root() {
    let ring = test_ring();
    let stale_members: Vec<_> = (10u8..14)
        .map(|i| Vrf::member_from_secret(&Vrf::new_secret([i; 32])))
        .collect();
    let snapshot = Snapshot {
        domain: DOMAIN,
        roots: std::sync::Arc::new(vec![
            AcceptedRoot {
                ring_index: 0,
                revision: REVISION,
                members: ring.commitment.clone(),
            },
            AcceptedRoot {
                ring_index: 0,
                revision: REVISION - 1,
                members: build_ring(&stale_members),
            },
        ]),
    };
    let app = app(Some((proof_config(), Some(snapshot))));

    let timestamp = now_unix() + PROOF_MAX_SKEW_SECS;
    let proof = prove(&ring, 3, &context(), timestamp);
    let (status, json) = post_json(
        &app,
        "/api/v1/turn/issue-with-proof",
        Some(body_with_revision(&proof, 0, REVISION, timestamp)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{json}");

    let timestamp = now_unix() + PROOF_MAX_SKEW_SECS;
    let proof = prove(&ring, 0, &context(), timestamp);
    let (status, _) = post_json(
        &app,
        "/api/v1/turn/issue-with-proof",
        Some(body_with_revision(&proof, 0, REVISION - 1, timestamp)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let timestamp = now_unix() + PROOF_MAX_SKEW_SECS;
    let proof = prove(&ring, 1, &context(), timestamp);
    let (status, _) = post_json(
        &app,
        "/api/v1/turn/issue-with-proof",
        Some(body_with_revision(&proof, 0, REVISION - 2, timestamp)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_missing_ring_revision_is_refused_before_verification() {
    let ring = test_ring();
    let app = app(Some((
        proof_config(),
        Some(snapshot_of(ring.commitment.clone())),
    )));

    let timestamp = now_unix() + PROOF_MAX_SKEW_SECS;
    let proof = prove(&ring, 0, &context(), timestamp);
    let body = format!(
        r#"{{"productId":"{PRODUCT}","proof":"{proof}","ringIndex":0,"timestamp":{timestamp}}}"#
    );

    let (status, _) = post_json(&app, "/api/v1/turn/issue-with-proof", Some(body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn proofs_are_raw_host_bytes_of_exactly_one_signature() {
    use subxt::ext::codec::Encode as _;

    let ring = test_ring();
    let app = app(Some((
        proof_config(),
        Some(snapshot_of(ring.commitment.clone())),
    )));

    let timestamp = now_unix() + PROOF_MAX_SKEW_SECS;
    let message = Freshness::new(PROOF_MAX_SKEW_SECS).message(timestamp);
    let opening =
        Vrf::open(DOMAIN, &ring.members[2], ring.members.iter().cloned()).expect("member in ring");
    let (proof, _) = Vrf::create(opening, &ring.secrets[2], &context(), &message).expect("proof");
    let raw = proof.to_vec();

    for (label, bytes) in [
        ("scale-prefixed", proof.encode()),
        ("truncated", raw[..raw.len() - 1].to_vec()),
        ("overlong", [raw.clone(), vec![0u8]].concat()),
        ("empty", Vec::new()),
    ] {
        let (status, _) = post_json(
            &app,
            "/api/v1/turn/issue-with-proof",
            Some(body(&format!("0x{}", hex::encode(&bytes)), 0, timestamp)),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{label}");
    }

    let (status, json) = post_json(
        &app,
        "/api/v1/turn/issue-with-proof",
        Some(body(&format!("0x{}", hex::encode(&proof)), 0, timestamp)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{json}");
}

#[tokio::test]
async fn a_verified_proof_with_no_credential_upstream_is_a_503() {
    let ring = test_ring();
    let state = state_with_base_url(
        Some((proof_config(), Some(snapshot_of(ring.commitment.clone())))),
        100,
        "http://127.0.0.1:1/v1".to_string(),
    );
    let app = turn::routes(state);

    let (status, json) = post_json(
        &app,
        "/api/v1/turn/issue-with-proof",
        Some(fresh_body(&ring, 2)),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{json}");
    assert_eq!(
        json["error"],
        serde_json::json!("Credentials are temporarily unavailable.")
    );
    assert!(json.get("username").is_none(), "{json}");
    assert_eq!(
        json.as_object().expect("object").keys().collect::<Vec<_>>(),
        vec!["error"]
    );
}

#[tokio::test]
async fn an_upstream_outage_does_not_spend_the_alias_budget() {
    let ring = test_ring();
    let state = state_with_base_url(
        Some((proof_config(), Some(snapshot_of(ring.commitment.clone())))),
        1,
        "http://127.0.0.1:1/v1".to_string(),
    );
    let app = turn::routes(state);

    for attempt in 0..2 {
        let (status, json) = post_json(
            &app,
            "/api/v1/turn/issue-with-proof",
            Some(fresh_body(&ring, 2)),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "attempt {attempt}: {json}"
        );
    }

    let (status, json) = post_json(
        &app,
        "/api/v1/turn/issue-with-proof",
        Some(fresh_body(&ring, 2)),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{json}");
}

#[tokio::test]
async fn each_request_reports_the_full_remaining_ttl() {
    let ring = test_ring();
    let app = app(Some((
        proof_config(),
        Some(snapshot_of(ring.commitment.clone())),
    )));

    let request = fresh_body(&ring, 1);
    let (status, json) = post_json(&app, "/api/v1/turn/issue-with-proof", Some(request)).await;
    assert_eq!(status, StatusCode::CREATED, "{json}");
    assert_eq!(json["ttl"], serde_json::json!(1800));
    assert_eq!(json["username"], serde_json::json!("stub-username"));
}

#[tokio::test]
async fn each_canonical_collection_selects_only_its_own_cache() {
    let ring = test_ring();
    let state = state_with_rate_limit(Some((proof_config(), None)), 100);
    let proof_state = state.proof.as_ref().expect("proof enabled");
    proof_state
        .roots
        .get(PersonhoodCollection::People)
        .set(snapshot_of(ring.commitment.clone()));
    let app = turn::routes(state);

    let timestamp = now_unix() + PROOF_MAX_SKEW_SECS;
    let proof = prove(&ring, 1, &context(), timestamp);
    let request = body(&proof, 0, timestamp).replace(PEOPLE_LITE_COLLECTION, PEOPLE_COLLECTION);
    let (status, json) = post_json(&app, "/api/v1/turn/issue-with-proof", Some(request)).await;
    assert_eq!(status, StatusCode::CREATED, "{json}");

    let (status, _) = post_json(
        &app,
        "/api/v1/turn/issue-with-proof",
        Some(body(&proof, 0, now_unix())),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn alias_throttle_limits_the_same_person() {
    let ring = test_ring();
    let app = app_with_rate_limit(
        Some((proof_config(), Some(snapshot_of(ring.commitment.clone())))),
        1,
    );

    let (status, _) = post_json(
        &app,
        "/api/v1/turn/issue-with-proof",
        Some(fresh_body(&ring, 1)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, _) = post_json(
        &app,
        "/api/v1/turn/issue-with-proof",
        Some(fresh_body(&ring, 1)),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

    let (status, _) = post_json(
        &app,
        "/api/v1/turn/issue-with-proof",
        Some(fresh_body(&ring, 3)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
}

#[tokio::test]
async fn each_product_gets_its_own_budget_for_the_same_person() {
    let ring = test_ring();
    let app = app_with_rate_limit(
        Some((proof_config(), Some(snapshot_of(ring.commitment.clone())))),
        1,
    );

    let (status, _) = post_json(
        &app,
        "/api/v1/turn/issue-with-proof",
        Some(fresh_body(&ring, 1)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = post_json(
        &app,
        "/api/v1/turn/issue-with-proof",
        Some(fresh_body(&ring, 1)),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

    let timestamp = now_unix() + PROOF_MAX_SKEW_SECS;
    let proof = prove(
        &ring,
        1,
        &turn::proof::context::product_context(OTHER_PRODUCT, SUFFIX),
        timestamp,
    );
    let (status, _) = post_json(
        &app,
        "/api/v1/turn/issue-with-proof",
        Some(body_for(OTHER_PRODUCT, &proof, 0, timestamp)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
}

#[tokio::test]
async fn a_stale_root_snapshot_fails_closed() {
    let ring = test_ring();
    let state = state_with_rate_limit(Some((proof_config(), None)), 100);
    let proof_state = state.proof.as_ref().expect("proof enabled");
    let roots = proof_state.roots.get(PersonhoodCollection::PeopleLite);
    roots.set(snapshot_of(ring.commitment.clone()));

    assert!(roots.snapshot(std::time::Duration::ZERO).is_none());
    assert!(roots.snapshot(turn::config::PROOF_MAX_ROOT_AGE).is_some());
}

#[tokio::test]
async fn no_root_snapshot_means_unavailable_not_broken() {
    let ring = test_ring();
    let app = app(Some((proof_config(), None)));

    let (status, _) = post_json(
        &app,
        "/api/v1/turn/issue-with-proof",
        Some(fresh_body(&ring, 0)),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn saturated_verification_waits_for_a_slot() {
    let ring = test_ring();
    let mut config = proof_config();
    config.concurrency = 1;
    let state = state_with_rate_limit(
        Some((config, Some(snapshot_of(ring.commitment.clone())))),
        100,
    );
    let permit = state
        .proof
        .as_ref()
        .expect("proof state")
        .permits
        .clone()
        .try_acquire_owned()
        .expect("verification slot");
    let app = turn::routes(state);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        drop(permit);
    });

    let (status, _) = post_json(
        &app,
        "/api/v1/turn/issue-with-proof",
        Some(fresh_body(&ring, 0)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
}

#[tokio::test]
async fn saturated_verification_times_out_with_retry_after() {
    let ring = test_ring();
    let mut config = proof_config();
    config.concurrency = 1;
    let state = state_with_rate_limit(
        Some((config, Some(snapshot_of(ring.commitment.clone())))),
        100,
    );
    let _permit = state
        .proof
        .as_ref()
        .expect("proof state")
        .permits
        .clone()
        .try_acquire_owned()
        .expect("verification slot");
    let app = turn::routes(state);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/turn/issue-with-proof")
                .header("content-type", "application/json")
                .body(Body::from(fresh_body(&ring, 0)))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers().get("retry-after").expect("header"), "1");
}

#[tokio::test]
async fn a_full_waiter_queue_rejects_another_request() {
    let ring = test_ring();
    let mut config = proof_config();
    config.concurrency = 1;
    let state = state_with_rate_limit(
        Some((config, Some(snapshot_of(ring.commitment.clone())))),
        100,
    );
    let proof_state = state.proof.as_ref().expect("proof state");
    let _permit = proof_state
        .permits
        .clone()
        .try_acquire_owned()
        .expect("verification slot");
    let _waiters: Vec<_> = (0..turn::http::state::MAX_PERMIT_WAITERS)
        .map(|_| {
            proof_state
                .waiters
                .clone()
                .try_acquire_owned()
                .expect("waiter slot")
        })
        .collect();
    let app = turn::routes(state);

    let (status, _) = post_json(
        &app,
        "/api/v1/turn/issue-with-proof",
        Some(fresh_body(&ring, 0)),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn an_unknown_root_is_rejected_before_waiting_for_a_slot() {
    let ring = test_ring();
    let mut config = proof_config();
    config.concurrency = 1;
    let state = state_with_rate_limit(
        Some((config, Some(snapshot_of(ring.commitment.clone())))),
        100,
    );
    let _permit = state
        .proof
        .as_ref()
        .expect("proof state")
        .permits
        .clone()
        .try_acquire_owned()
        .expect("verification slot");
    let app = turn::routes(state);
    let timestamp = now_unix() + PROOF_MAX_SKEW_SECS;
    let proof = prove(&ring, 0, &context(), timestamp);

    let (status, _) = post_json(
        &app,
        "/api/v1/turn/issue-with-proof",
        Some(body_with_revision(&proof, 0, REVISION + 1, timestamp)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn proof_routes_absent_when_disabled() {
    let app = app(None);
    let (status, _) = post_json(
        &app,
        "/api/v1/turn/issue-with-proof",
        Some("{}".to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn wrong_method_returns_the_json_not_found() {
    let app = app(Some((proof_config(), None)));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method(axum::http::Method::GET)
                .uri("/api/v1/turn/issue-with-proof")
                .body(axum::body::Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).expect("json"),
        serde_json::json!({ "error": "Not found" })
    );
}

/// A stand-in for Cloudflare Realtime TURN, bound on a loopback port.
fn spawn_cloudflare_stub() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind stub");
    listener.set_nonblocking(true).expect("nonblocking");
    let addr = listener.local_addr().expect("stub addr");
    let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
    let router = axum::Router::new().route(
        "/turn/keys/{key_id}/credentials/generate-ice-servers",
        axum::routing::post(|| async {
            axum::Json(serde_json::json!({
                "iceServers": [
                    { "urls": ["stun:stun.cloudflare.com:3478"] },
                    {
                        "urls": [
                            "turn:turn.cloudflare.com:3478?transport=udp",
                            "turns:turn.cloudflare.com:5349?transport=tcp"
                        ],
                        "username": "stub-username",
                        "credential": "stub-credential"
                    }
                ],
                "ttl": 1800
            }))
        }),
    );
    tokio::spawn(async move {
        axum::serve(listener, router).await.ok();
    });
    format!("http://{addr}")
}

/// On the coturn provider the proof route's unlinkability comes from the
/// credential id rather than from Cloudflare minting a fresh one: a keyed digest
/// over the product and the caller's contextual alias. These pin the property
/// the derivation exists for — the id is opaque, and it is scoped to one person
/// and one product.
#[tokio::test]
async fn the_coturn_provider_derives_an_opaque_id_from_product_and_alias() {
    let ring = test_ring();
    let app = turn::routes(state_with_provider(
        Some((proof_config(), Some(snapshot_of(ring.commitment.clone())))),
        100,
        coturn_provider(),
    ));

    let (status, json) = post_json(
        &app,
        "/api/v1/turn/issue-with-proof",
        Some(fresh_body(&ring, 2)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{json}");

    let username = json["username"].as_str().expect("username");
    let (_, id) = username.split_once(':').expect("expiry:id");
    // Sixteen bytes of keyed digest, not the eight random ones the JWT route
    // uses — a caller cannot tell the two routes' credentials apart by shape.
    assert_eq!(id.len(), 32, "id half: {id}");
    assert!(id
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));

    // The alias itself must not appear anywhere in the response.
    let body = json.to_string();
    assert!(!body.contains("alias"), "{body}");
    let mut keys: Vec<_> = json.as_object().expect("object").keys().collect();
    keys.sort();
    assert_eq!(keys, ["password", "servers", "ttl", "username"]);
}

/// The same person proving for two different products must not be correlatable
/// across them by credential id.
///
/// Note this asserts the end-to-end property, not its mechanism: the ids differ
/// here because each product has its own proof context and so its own alias.
/// That the product is *also* bound into the digest is pinned separately, by
/// `proof_credentials_change_across_product_alias_or_time` in `credentials`.
#[tokio::test]
async fn one_person_gets_unrelated_ids_for_two_products() {
    let ring = test_ring();
    let app = turn::routes(state_with_provider(
        Some((proof_config(), Some(snapshot_of(ring.commitment.clone())))),
        100,
        coturn_provider(),
    ));

    let mut ids = Vec::new();
    for product in [PRODUCT, OTHER_PRODUCT] {
        let timestamp = now_unix() + PROOF_MAX_SKEW_SECS;
        let context = turn::proof::context::product_context(product, SUFFIX);
        let proof = prove(&ring, 2, &context, timestamp);
        let (status, json) = post_json(
            &app,
            "/api/v1/turn/issue-with-proof",
            Some(body_for(product, &proof, 0, timestamp)),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{product}: {json}");
        let username = json["username"].as_str().expect("username").to_string();
        ids.push(username.split_once(':').expect("expiry:id").1.to_string());
    }
    assert_ne!(ids[0], ids[1], "the same id served two products");
}

/// Computed locally, so there is no upstream to be unavailable: the route
/// answers 201 with no Cloudflare stub configured anywhere.
#[tokio::test]
async fn the_coturn_provider_cannot_report_credentials_unavailable() {
    let ring = test_ring();
    let app = turn::routes(state_with_provider(
        Some((proof_config(), Some(snapshot_of(ring.commitment.clone())))),
        100,
        coturn_provider(),
    ));

    let (status, json) = post_json(
        &app,
        "/api/v1/turn/issue-with-proof",
        Some(fresh_body(&ring, 1)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{json}");
    assert_eq!(json["ttl"], serde_json::json!(1800));
}

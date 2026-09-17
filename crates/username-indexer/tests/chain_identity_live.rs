// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::sync::Arc;

use sqlx::{PgPool, Row as _};
use username_indexer::bootstrap;
use username_indexer::chain::PeopleChain;

const MOCK_GENESIS: [u8; 32] = [0u8; 32];

const FOREIGN_GENESIS: [u8; 32] = [0xffu8; 32];

const TEST_ACCOUNT: [u8; 32] = [0xa7u8; 32];

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

async fn set_checkpoint(pool: &PgPool, number: i64, genesis: Option<[u8; 32]>) {
    sqlx::query(
        "INSERT INTO sync_state (
            id, last_finalized_number, last_finalized_hash, genesis_hash,
            last_synced_at, records_indexed, decode_failures, updated_at
         ) VALUES (1, $1, $2, $3, now(), 0, 0, now())
         ON CONFLICT (id) DO UPDATE SET
            last_finalized_number = EXCLUDED.last_finalized_number,
            genesis_hash = EXCLUDED.genesis_hash,
            updated_at = now()",
    )
    .bind(number)
    .bind(vec![0u8; 32])
    .bind(genesis.map(|hash| hash.to_vec()))
    .execute(pool)
    .await
    .expect("seed sync_state");
}

async fn seed_projection_row(pool: &PgPool) {
    sqlx::query(
        "INSERT INTO assigned_usernames (
            account_id, account_id_ss58, identifier_key, lite_username, lite_base,
            lite_digits, display_username, snapshot_hash, snapshot_number
         ) VALUES ($1, 'test-ss58', $2, 'guardtest.1', 'guardtest', 1, 'guardtest.1', $3, 1)
         ON CONFLICT (account_id) DO NOTHING",
    )
    .bind(TEST_ACCOUNT.as_slice())
    .bind(vec![0u8; 65])
    .bind(vec![0u8; 32])
    .execute(pool)
    .await
    .expect("seed projection row");
}

async fn stored_genesis(pool: &PgPool) -> Option<Vec<u8>> {
    sqlx::query("SELECT genesis_hash FROM sync_state WHERE id = 1")
        .fetch_optional(pool)
        .await
        .expect("read sync_state")
        .and_then(|row| row.try_get("genesis_hash").expect("genesis_hash column"))
}

async fn projection_rows(pool: &PgPool) -> i64 {
    sqlx::query("SELECT count(*) FROM assigned_usernames")
        .fetch_one(pool)
        .await
        .expect("count projection")
        .try_get(0)
        .expect("count")
}

#[tokio::test]
#[ignore = "requires a live DATABASE_URL Postgres; run manually with --ignored"]
async fn chain_identity_guard_discards_only_a_foreign_projection() {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL is required");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await
        .expect("connect to live Postgres");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("run migrations");
    let chain = dead_chain_client().await;

    let original =
        sqlx::query("SELECT last_finalized_number, genesis_hash FROM sync_state WHERE id = 1")
            .fetch_optional(&pool)
            .await
            .expect("read original");

    set_checkpoint(&pool, 42, None).await;
    seed_projection_row(&pool).await;
    assert!(
        bootstrap::ensure_seeded(&pool, &chain, 64)
            .await
            .expect("ensure_seeded adopts an unstamped checkpoint")
            .is_none(),
        "an adopted checkpoint must not trigger a bootstrap"
    );
    assert_eq!(
        stored_genesis(&pool).await.as_deref(),
        Some(MOCK_GENESIS.as_slice()),
        "adoption stamps the live chain's genesis"
    );
    assert!(projection_rows(&pool).await > 0, "adoption keeps the rows");

    assert!(bootstrap::ensure_seeded(&pool, &chain, 64)
        .await
        .expect("ensure_seeded")
        .is_none());
    assert_eq!(
        stored_genesis(&pool).await.as_deref(),
        Some(MOCK_GENESIS.as_slice())
    );
    assert!(projection_rows(&pool).await > 0);

    set_checkpoint(&pool, 42, Some(FOREIGN_GENESIS)).await;
    seed_projection_row(&pool).await;
    assert!(
        bootstrap::ensure_seeded(&pool, &chain, 64).await.is_err(),
        "the rebuild must be attempted, and fails on the dead chain"
    );
    assert!(
        stored_genesis(&pool).await.is_none(),
        "the foreign checkpoint row is gone, so the next boot bootstraps"
    );
    assert_eq!(
        projection_rows(&pool).await,
        0,
        "rows derived from a chain we are no longer on are discarded"
    );

    sqlx::query("DELETE FROM assigned_usernames WHERE account_id = $1")
        .bind(TEST_ACCOUNT.as_slice())
        .execute(&pool)
        .await
        .expect("clean projection row");
    match original {
        Some(row) => {
            let genesis: Option<Vec<u8>> = row.try_get("genesis_hash").expect("genesis_hash");
            let restored = genesis.map(|bytes| {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&bytes);
                hash
            });
            set_checkpoint(
                &pool,
                row.try_get("last_finalized_number").expect("number"),
                restored,
            )
            .await;
        }
        None => {
            sqlx::query("DELETE FROM sync_state WHERE id = 1")
                .execute(&pool)
                .await
                .expect("restore empty");
        }
    }
}

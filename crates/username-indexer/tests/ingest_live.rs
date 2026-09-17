// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::sync::Arc;

use sqlx::Row as _;
use username_indexer::chain::PeopleChain;
use username_indexer::projection::PROJECTION_LOCK_ID;
use username_indexer::{bootstrap, incremental, sync};

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

async fn set_checkpoint(pool: &sqlx::PgPool, number: i64, indexed: i64, failures: i64) {
    sqlx::query(
        "INSERT INTO sync_state (
            id, last_finalized_number, last_finalized_hash, last_synced_at,
            records_indexed, decode_failures, updated_at
         ) VALUES (1, $1, $2, now(), $3, $4, now())
         ON CONFLICT (id) DO UPDATE SET
            last_finalized_number = EXCLUDED.last_finalized_number,
            records_indexed = EXCLUDED.records_indexed,
            decode_failures = EXCLUDED.decode_failures,
            updated_at = now()",
    )
    .bind(number)
    .bind(vec![0u8; 32])
    .bind(indexed)
    .bind(failures)
    .execute(pool)
    .await
    .expect("seed sync_state");
}

#[tokio::test]
#[ignore = "requires a live DATABASE_URL Postgres; run manually with --ignored"]
async fn ingest_database_branches_work_without_a_chain() {
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

    let original = sqlx::query(
        "SELECT last_finalized_number, records_indexed, decode_failures \
         FROM sync_state WHERE id = 1",
    )
    .fetch_optional(&pool)
    .await
    .expect("read original");

    sqlx::query("DELETE FROM sync_state WHERE id = 1")
        .execute(&pool)
        .await
        .expect("clear checkpoint");
    assert!(sync::checkpoint_freshness(&pool)
        .await
        .expect("freshness")
        .is_none());
    let report = incremental::index_finalized_range(&pool, &chain)
        .await
        .expect("index")
        .expect("lock free");
    assert_eq!((report.from_block, report.to_block), (0, 0));
    assert_eq!(report.blocks_processed, 0);

    set_checkpoint(&pool, 42, 7, 1).await;
    assert!(bootstrap::ensure_seeded(&pool, &chain, 64)
        .await
        .expect("ensure_seeded")
        .is_none());

    let snapshot = sync::checkpoint_freshness(&pool)
        .await
        .expect("freshness")
        .expect("seeded");
    assert_eq!(snapshot.last_finalized_number, 42);
    assert_eq!(snapshot.records_indexed, 7);
    assert_eq!(snapshot.decode_failures, 1);

    set_checkpoint(&pool, 42, 7, 1).await;
    assert!(incremental::index_finalized_range(&pool, &chain)
        .await
        .is_err());

    let mut holder = pool.acquire().await.expect("lock connection");
    let locked: bool = sqlx::query("SELECT pg_try_advisory_lock($1)")
        .bind(PROJECTION_LOCK_ID)
        .fetch_one(&mut *holder)
        .await
        .expect("take lock")
        .try_get(0)
        .expect("bool");
    assert!(locked, "test could not take the projection lock");
    assert!(incremental::index_finalized_range(&pool, &chain)
        .await
        .expect("index")
        .is_none());
    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(PROJECTION_LOCK_ID)
        .execute(&mut *holder)
        .await
        .expect("release lock");
    drop(holder);

    match original {
        Some(row) => {
            set_checkpoint(
                &pool,
                row.try_get("last_finalized_number").expect("number"),
                row.try_get("records_indexed").expect("indexed"),
                row.try_get("decode_failures").expect("failures"),
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

// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

#![cfg(invite_tickets)]

use std::time::Duration;

use invite_tickets::pool::{acquire_tick_lock, POOL_LOCK_KEY};

async fn test_pool() -> sqlx::PgPool {
    let url = std::env::var("INVITE_TICKETS_TEST_DATABASE_URL")
        .expect("set INVITE_TICKETS_TEST_DATABASE_URL to run the live-PG tests");
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&url)
        .await
        .expect("connect to test Postgres")
}

#[tokio::test]
#[ignore = "needs INVITE_TICKETS_TEST_DATABASE_URL (live Postgres)"]
async fn tick_lock_excludes_second_connection_until_guard_drops() {
    let pool = test_pool().await;

    let mut probe = pool.acquire().await.expect("acquire probe connection");

    let mut guard = None;
    for _ in 0..300 {
        if let Some(taken) = acquire_tick_lock(&pool).await.expect("acquire_tick_lock") {
            guard = Some(taken);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let guard = guard.expect("tick lock never became free (long-held by another process?)");

    let taken: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(POOL_LOCK_KEY)
        .fetch_one(&mut *probe)
        .await
        .expect("probe try-lock");
    assert!(!taken, "held guard must exclude a second connection");

    drop(guard);
    let mut reacquired = false;
    for _ in 0..300 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let taken: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
            .bind(POOL_LOCK_KEY)
            .fetch_one(&mut *probe)
            .await
            .expect("probe try-lock after drop");
        if taken {
            reacquired = true;
            break;
        }
    }
    assert!(
        reacquired,
        "dropped guard must release the lock for the next holder"
    );

    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(POOL_LOCK_KEY)
        .execute(&mut *probe)
        .await
        .expect("release probe lock");
}

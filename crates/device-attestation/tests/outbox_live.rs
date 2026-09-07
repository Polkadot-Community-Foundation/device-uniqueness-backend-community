// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::time::Duration;

use device_attestation::chain::lease;
use device_attestation::chain::outbox::{self, Guard, InsertError, NewReservation, Status};
use device_attestation::widevine::store::{self as widevine_store, PendingDevice};

async fn test_pool() -> sqlx::PgPool {
    let database_url = std::env::var("DEVICE_ATTESTATION_TEST_DATABASE_URL")
        .expect("DEVICE_ATTESTATION_TEST_DATABASE_URL is required");
    device_attestation::db::connect(&database_url)
        .await
        .expect("connect and migrate")
}

fn reservation(base: &str, digits: &str) -> NewReservation {
    NewReservation {
        account_id: "outbox-live-subject".to_string(),
        candidate_account_id: "outbox-live-candidate".to_string(),
        base: base.to_string(),
        digits: digits.to_string(),
        full_username: format!("{base}.{digits}"),
        candidate_signature: vec![1; 64],
        ring_vrf_key: vec![2; 32],
        proof_of_ownership: vec![3; 64],
        consumer_registration_signature: vec![4; 64],
        identifier_key: vec![5; 65],
        dotns_signature: None,
        dotns_signed_at: None,
        reserved_username: None,
    }
}

async fn set_status(pool: &sqlx::PgPool, full_username: &str, status: &str) {
    sqlx::query("UPDATE username_reservations SET status = $1 WHERE full_username = $2")
        .bind(status)
        .bind(full_username)
        .execute(pool)
        .await
        .expect("set status");
}

async fn status_of(pool: &sqlx::PgPool, id: i64) -> String {
    sqlx::query_scalar("SELECT status FROM username_reservations WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("status")
}

async fn cleanup(pool: &sqlx::PgPool, base: &str, lease_name: &str) {
    sqlx::query("DELETE FROM username_reservations WHERE base = $1")
        .bind(base)
        .execute(pool)
        .await
        .expect("cleanup rows");
    sqlx::query("DELETE FROM writer_lease WHERE name = $1")
        .bind(lease_name)
        .execute(pool)
        .await
        .expect("cleanup lease");
}

#[tokio::test]
#[ignore = "requires Postgres; set DEVICE_ATTESTATION_TEST_DATABASE_URL and run with --ignored"]
async fn duplicate_full_username_maps_to_conflict() {
    let pool = test_pool().await;
    let base = format!("outboxconflict{}", std::process::id());

    outbox::insert(&pool, &reservation(&base, "11"))
        .await
        .expect("first insert");
    let err = outbox::insert(&pool, &reservation(&base, "11"))
        .await
        .expect_err("duplicate");
    assert!(matches!(err, InsertError::Conflict), "{err}");
    let err = outbox::insert_queued(&pool, &reservation(&base, "11"), 1)
        .await
        .expect_err("queued duplicate");
    assert!(matches!(err, InsertError::Conflict), "{err}");

    cleanup(&pool, &base, "unused").await;
}

#[tokio::test]
#[ignore = "requires Postgres; set DEVICE_ATTESTATION_TEST_DATABASE_URL and run with --ignored"]
async fn claim_due_picks_reserved_and_gate_passed_retries_oldest_first() {
    let pool = test_pool().await;
    let base = format!("outboxdue{}", std::process::id());

    for digits in ["11", "12", "13", "14", "15"] {
        outbox::insert(&pool, &reservation(&base, digits))
            .await
            .expect("insert");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    sqlx::query(
        "UPDATE username_reservations SET status='RETRY_AFTER', not_before = now() - interval '1 second' \
         WHERE full_username = $1",
    )
    .bind(format!("{base}.12"))
    .execute(&pool)
    .await
    .expect("gate 12");
    sqlx::query(
        "UPDATE username_reservations SET status='RETRY_AFTER', not_before = now() + interval '1 hour' \
         WHERE full_username = $1",
    )
    .bind(format!("{base}.13"))
    .execute(&pool)
    .await
    .expect("gate 13");
    sqlx::query(
        "UPDATE username_reservations SET status='RETRY_AFTER', not_before = NULL \
         WHERE full_username = $1",
    )
    .bind(format!("{base}.14"))
    .execute(&pool)
    .await
    .expect("gate 14");
    set_status(&pool, &format!("{base}.15"), "SUBMITTING").await;

    let due: Vec<String> = outbox::claim_due(&pool, 10_000)
        .await
        .expect("claim due")
        .into_iter()
        .map(|r| r.full_username)
        .filter(|u| u.starts_with(&base))
        .collect();
    assert_eq!(
        due,
        vec![
            format!("{base}.11"),
            format!("{base}.12"),
            format!("{base}.14")
        ],
        "RESERVED + gate-passed/ungated RETRY_AFTER, oldest first; \
         future-gated and SUBMITTING excluded"
    );

    let submitting: Vec<String> = outbox::submitting(&pool)
        .await
        .expect("submitting")
        .into_iter()
        .map(|r| r.full_username)
        .filter(|u| u.starts_with(&base))
        .collect();
    assert_eq!(submitting, vec![format!("{base}.15")]);

    cleanup(&pool, &base, "unused").await;
}

#[tokio::test]
#[ignore = "requires Postgres; set DEVICE_ATTESTATION_TEST_DATABASE_URL and run with --ignored"]
async fn stale_guards_never_advance_a_row() {
    let pool = test_pool().await;
    let pid = std::process::id();
    let base = format!("outboxguard{pid}");
    let lease_name = format!("outbox-live-writer-{pid}");

    let epoch = lease::try_acquire(&pool, &lease_name, "holder-a", Duration::from_secs(60))
        .await
        .expect("acquire")
        .expect("lease free");
    let guard = Guard {
        lease_name: lease_name.clone(),
        holder_id: "holder-a".to_string(),
        epoch,
    };

    let id = outbox::insert(&pool, &reservation(&base, "21"))
        .await
        .expect("insert");

    assert!(
        outbox::mark_submitting(&pool, &guard, id, "0xabc", 7, 1)
            .await
            .expect("mark submitting"),
        "held lease must advance RESERVED -> SUBMITTING"
    );
    assert_eq!(status_of(&pool, id).await, "SUBMITTING");

    let wrong_epoch = Guard {
        epoch: epoch + 1,
        ..guard.clone()
    };
    assert!(
        !outbox::mark_assigned(&pool, &wrong_epoch, id)
            .await
            .expect("mark assigned"),
        "wrong epoch must not advance"
    );
    let wrong_holder = Guard {
        holder_id: "holder-b".to_string(),
        ..guard.clone()
    };
    assert!(
        !outbox::mark_failed(&pool, &wrong_holder, id, "nope")
            .await
            .expect("mark failed"),
        "foreign holder must not advance"
    );
    assert_eq!(status_of(&pool, id).await, "SUBMITTING");

    sqlx::query("UPDATE writer_lease SET expires_at = now() - interval '1 second' WHERE name = $1")
        .bind(&lease_name)
        .execute(&pool)
        .await
        .expect("expire lease");
    let not_before = time::OffsetDateTime::now_utc() + time::Duration::seconds(60);
    assert!(
        !outbox::mark_retry(&pool, &guard, id, not_before, 2, "transient")
            .await
            .expect("mark retry"),
        "expired lease must not advance"
    );
    assert_eq!(status_of(&pool, id).await, "SUBMITTING");

    let new_epoch = lease::try_acquire(&pool, &lease_name, "holder-b", Duration::from_secs(60))
        .await
        .expect("takeover")
        .expect("expired lease is takeable");
    assert!(new_epoch > epoch, "takeover must bump the epoch");
    assert!(
        !outbox::mark_assigned(&pool, &guard, id)
            .await
            .expect("mark assigned"),
        "the replaced writer's guard stays dead after takeover"
    );
    let new_guard = Guard {
        lease_name: lease_name.clone(),
        holder_id: "holder-b".to_string(),
        epoch: new_epoch,
    };
    assert!(
        outbox::mark_retry(&pool, &new_guard, id, not_before, 2, "transient")
            .await
            .expect("mark retry"),
        "the live holder's guard advances"
    );
    assert_eq!(status_of(&pool, id).await, "RETRY_AFTER");
    let (attempt, last_error): (i32, Option<String>) =
        sqlx::query_as("SELECT attempt, last_error FROM username_reservations WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .expect("row");
    assert_eq!(attempt, 2);
    assert_eq!(last_error.as_deref(), Some("transient"));

    assert!(outbox::mark_assigned(&pool, &new_guard, id)
        .await
        .expect("mark assigned"));
    assert_eq!(status_of(&pool, id).await, "ASSIGNED");

    cleanup(&pool, &base, &lease_name).await;
}

#[tokio::test]
#[ignore = "requires Postgres; set DEVICE_ATTESTATION_TEST_DATABASE_URL and run with --ignored"]
async fn terminal_failure_fences_takeover_and_releases_the_device_atomically() {
    let pool = test_pool().await;
    let pid = std::process::id();
    let base = format!("outboxfence{pid}");
    let lease_name = format!("outbox-live-fence-{pid}");
    let holder = "holder-a";
    let id = outbox::insert(&pool, &reservation(&base, "31"))
        .await
        .expect("insert");
    set_status(&pool, &format!("{base}.31"), "SUBMITTING").await;
    let device = PendingDevice { hmac: [31; 32] };
    widevine_store::insert_pending(&pool, &device, id)
        .await
        .expect("insert pending device");

    let first_epoch = lease::try_acquire(&pool, &lease_name, holder, Duration::from_secs(60))
        .await
        .expect("acquire")
        .expect("lease free");
    let first_guard = Guard {
        lease_name: lease_name.clone(),
        holder_id: holder.to_string(),
        epoch: first_epoch,
    };

    // Rolling the terminal transaction back preserves both halves.
    let mut rollback_tx = pool.begin().await.expect("begin rollback transaction");
    assert!(lease::fence(
        &mut rollback_tx,
        &first_guard.lease_name,
        &first_guard.holder_id,
        first_guard.epoch,
    )
    .await
    .expect("fence lease"));
    assert!(
        outbox::mark_failed(&mut *rollback_tx, &first_guard, id, "terminal")
            .await
            .expect("mark failed")
    );
    assert!(
        widevine_store::release_for_reservation(&mut *rollback_tx, id)
            .await
            .expect("release pending device")
    );
    rollback_tx.rollback().await.expect("rollback");
    assert_eq!(status_of(&pool, id).await, "SUBMITTING");
    assert!(widevine_store::seen(&pool, &device.hmac)
        .await
        .expect("device lookup"));

    let epoch = lease::try_acquire(&pool, &lease_name, holder, Duration::from_secs(60))
        .await
        .expect("refresh")
        .expect("same holder refreshes");
    let guard = Guard {
        lease_name: lease_name.clone(),
        holder_id: holder.to_string(),
        epoch,
    };
    let mut tx = pool.begin().await.expect("begin terminal transaction");
    assert!(
        lease::fence(&mut tx, &guard.lease_name, &guard.holder_id, guard.epoch)
            .await
            .expect("fence lease")
    );
    assert!(outbox::mark_failed(&mut *tx, &guard, id, "terminal")
        .await
        .expect("mark failed"));
    assert!(widevine_store::release_for_reservation(&mut *tx, id)
        .await
        .expect("release pending device"));
    sqlx::query("UPDATE writer_lease SET expires_at = now() - interval '1 second' WHERE name = $1")
        .bind(&lease_name)
        .execute(&mut *tx)
        .await
        .expect("expire fenced lease");

    let takeover = tokio::time::timeout(
        Duration::from_millis(100),
        lease::try_acquire(&pool, &lease_name, "holder-b", Duration::from_secs(60)),
    )
    .await;
    assert!(
        takeover.is_err(),
        "takeover must wait for the fenced transaction"
    );

    tx.commit().await.expect("commit terminal transaction");
    let takeover_epoch =
        lease::try_acquire(&pool, &lease_name, "holder-b", Duration::from_secs(60))
            .await
            .expect("takeover after commit")
            .expect("expired lease is takeable after commit");
    assert!(takeover_epoch > epoch);
    assert_eq!(status_of(&pool, id).await, "FAILED_TERMINAL");
    assert!(!widevine_store::seen(&pool, &device.hmac)
        .await
        .expect("device lookup"));

    cleanup(&pool, &base, &lease_name).await;
}

#[tokio::test]
#[ignore = "requires Postgres; set DEVICE_ATTESTATION_TEST_DATABASE_URL and run with --ignored"]
async fn assignment_and_device_consumption_commit_or_roll_back_together() {
    let pool = test_pool().await;
    let pid = std::process::id();
    let base = format!("outboxassign{pid}");
    let lease_name = format!("outbox-live-assign-{pid}");
    let id = outbox::insert(&pool, &reservation(&base, "41"))
        .await
        .expect("insert");
    set_status(&pool, &format!("{base}.41"), "SUBMITTING").await;
    let device = PendingDevice { hmac: [41; 32] };
    widevine_store::insert_pending(&pool, &device, id)
        .await
        .expect("insert pending device");

    let epoch = lease::try_acquire(&pool, &lease_name, "holder-a", Duration::from_secs(60))
        .await
        .expect("acquire")
        .expect("lease free");
    let guard = Guard {
        lease_name: lease_name.clone(),
        holder_id: "holder-a".to_string(),
        epoch,
    };

    let mut rollback_tx = pool.begin().await.expect("begin rollback transaction");
    assert!(lease::fence(
        &mut rollback_tx,
        &guard.lease_name,
        &guard.holder_id,
        guard.epoch,
    )
    .await
    .expect("fence lease"));
    assert!(outbox::mark_assigned(&mut *rollback_tx, &guard, id)
        .await
        .expect("mark assigned"));
    widevine_store::consume_for_reservation(&mut *rollback_tx, id)
        .await
        .expect("consume device");
    rollback_tx.rollback().await.expect("rollback");
    assert_eq!(status_of(&pool, id).await, "SUBMITTING");
    let pending: (String, Option<i64>) = sqlx::query_as(
        "SELECT status::text, reservation_id FROM widevine_devices WHERE device_hmac = $1",
    )
    .bind(&device.hmac[..])
    .fetch_one(&pool)
    .await
    .expect("pending device state");
    assert_eq!(pending, ("PENDING".to_string(), Some(id)));

    let mut tx = pool.begin().await.expect("begin assignment transaction");
    assert!(
        lease::fence(&mut tx, &guard.lease_name, &guard.holder_id, guard.epoch)
            .await
            .expect("fence lease")
    );
    assert!(outbox::mark_assigned(&mut *tx, &guard, id)
        .await
        .expect("mark assigned"));
    widevine_store::consume_for_reservation(&mut *tx, id)
        .await
        .expect("consume device");
    tx.commit().await.expect("commit assignment transaction");

    assert_eq!(status_of(&pool, id).await, "ASSIGNED");
    let consumed: (String, Option<i64>) = sqlx::query_as(
        "SELECT status::text, reservation_id FROM widevine_devices WHERE device_hmac = $1",
    )
    .bind(&device.hmac[..])
    .fetch_one(&pool)
    .await
    .expect("consumed device state");
    assert_eq!(consumed, ("CONSUMED".to_string(), None));

    cleanup(&pool, &base, &lease_name).await;
}

#[tokio::test]
#[ignore = "requires Postgres; set DEVICE_ATTESTATION_TEST_DATABASE_URL and run with --ignored"]
async fn lease_lifecycle_acquire_renew_expire_takeover() {
    let pool = test_pool().await;
    let name = format!("outbox-live-lease-{}", std::process::id());
    let ttl = Duration::from_secs(60);

    let first = lease::try_acquire(&pool, &name, "holder-a", ttl)
        .await
        .expect("acquire")
        .expect("free lease");
    let second = lease::try_acquire(&pool, &name, "holder-a", ttl)
        .await
        .expect("acquire")
        .expect("own lease is retakeable");
    assert!(second > first);

    assert!(lease::try_acquire(&pool, &name, "holder-b", ttl)
        .await
        .expect("acquire")
        .is_none());
    assert!(lease::alive(&pool, &name).await.expect("alive"));

    assert!(lease::renew(&pool, &name, "holder-a", second, ttl)
        .await
        .expect("renew"));
    assert!(!lease::renew(&pool, &name, "holder-a", first, ttl)
        .await
        .expect("renew"));
    assert!(!lease::renew(&pool, &name, "holder-b", second, ttl)
        .await
        .expect("renew"));

    sqlx::query("UPDATE writer_lease SET expires_at = now() - interval '1 second' WHERE name = $1")
        .bind(&name)
        .execute(&pool)
        .await
        .expect("expire");
    assert!(!lease::alive(&pool, &name).await.expect("alive"));
    assert!(!lease::renew(&pool, &name, "holder-a", second, ttl)
        .await
        .expect("renew"));
    let taken = lease::try_acquire(&pool, &name, "holder-b", ttl)
        .await
        .expect("acquire")
        .expect("expired lease is takeable");
    assert!(taken > second);

    sqlx::query("DELETE FROM writer_lease WHERE name = $1")
        .bind(&name)
        .execute(&pool)
        .await
        .expect("cleanup");
}

#[tokio::test]
#[ignore = "requires Postgres; set DEVICE_ATTESTATION_TEST_DATABASE_URL and run with --ignored"]
async fn depth_by_status_reports_every_status_even_when_empty() {
    let pool = test_pool().await;
    let base = format!("outboxdepth{}", std::process::id());

    outbox::insert(&pool, &reservation(&base, "31"))
        .await
        .expect("insert");

    let depths = outbox::depth_by_status(&pool).await.expect("depths");
    assert_eq!(
        depths.iter().map(|(s, _)| *s).collect::<Vec<_>>(),
        Status::ALL.to_vec()
    );
    let reserved = depths
        .iter()
        .find(|(s, _)| *s == Status::Reserved)
        .expect("reserved entry");
    assert!(reserved.1.depth >= 1);
    assert!(reserved.1.oldest_age_secs.is_some());
    for (_, depth) in &depths {
        assert!(depth.depth >= 0);
        if depth.depth == 0 {
            assert!(depth.oldest_age_secs.is_none());
        }
    }

    cleanup(&pool, &base, "unused").await;
}

#[tokio::test]
#[ignore = "requires Postgres; set DEVICE_ATTESTATION_TEST_DATABASE_URL and run with --ignored"]
async fn oldest_age_measures_time_in_status_not_row_age() {
    let pool = test_pool().await;
    let base = format!("outboxage{}", std::process::id());
    let id = outbox::insert(&pool, &reservation(&base, "32"))
        .await
        .expect("insert");

    sqlx::query(
        "UPDATE username_reservations SET created_at = now() - interval '2 hours' WHERE id = $1",
    )
    .bind(id)
    .execute(&pool)
    .await
    .expect("backdate");

    let depths = outbox::depth_by_status(&pool).await.expect("depths");
    let (_, reserved) = depths
        .iter()
        .find(|(s, _)| *s == Status::Reserved)
        .expect("reserved entry");
    let age = reserved
        .oldest_age_secs
        .expect("non-empty status has an age");
    assert!(
        age < 600.0,
        "age must come from updated_at, not created_at; got {age}s"
    );

    cleanup(&pool, &base, "unused").await;
}

#[tokio::test]
#[ignore = "requires Postgres; set DEVICE_ATTESTATION_TEST_DATABASE_URL and run with --ignored"]
async fn a_whole_batch_retry_gives_back_the_attempt_it_did_not_spend() {
    let pool = test_pool().await;
    let base = format!("outboxbatch{}", std::process::id());
    let lease_name = format!("{base}-lease");
    let epoch = lease::try_acquire(&pool, &lease_name, "holder-a", Duration::from_secs(60))
        .await
        .expect("acquire")
        .expect("lease free");
    let guard = Guard {
        lease_name: lease_name.clone(),
        holder_id: "holder-a".to_string(),
        epoch,
    };

    let ids: Vec<i64> = {
        let mut ids = Vec::new();
        for digits in ["41", "42"] {
            ids.push(
                outbox::insert(&pool, &reservation(&base, digits))
                    .await
                    .expect("insert"),
            );
        }
        ids
    };
    let claimed = outbox::claim_due(&pool, 10)
        .await
        .expect("claim")
        .into_iter()
        .filter(|r| ids.contains(&r.id))
        .collect::<Vec<_>>();
    assert_eq!(claimed.len(), 2, "both rows are due");

    for r in &claimed {
        assert_eq!(r.attempt, 0, "a fresh row has spent no attempt");
        assert!(
            outbox::mark_submitting(&pool, &guard, r.id, "0xbatch", 7, r.attempt + 1)
                .await
                .expect("mark submitting"),
            "every row is SUBMITTING before the batch is awaited"
        );
    }
    assert_eq!(attempt_of(&pool, claimed[0].id).await, 1);

    let not_before = time::OffsetDateTime::now_utc() + time::Duration::seconds(2);
    for r in &claimed {
        assert!(
            outbox::mark_retry(&pool, &guard, r.id, not_before, r.attempt, "tx dropped")
                .await
                .expect("mark retry"),
            "the live holder re-queues the set"
        );
        assert_eq!(status_of(&pool, r.id).await, "RETRY_AFTER");
        assert_eq!(
            attempt_of(&pool, r.id).await,
            0,
            "a whole-batch failure must leave the attempt where it was"
        );
    }

    cleanup(&pool, &base, &lease_name).await;
}

async fn attempt_of(pool: &sqlx::PgPool, id: i64) -> i32 {
    sqlx::query_scalar("SELECT attempt FROM username_reservations WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read attempt")
}

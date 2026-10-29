// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use device_attestation::chain::lease;
use device_attestation::chain::outbox::{self, NewReservation};
use device_attestation::queue;
use sqlx::Row as _;

fn reservation(base: &str, digits: &str, account: &str) -> NewReservation {
    NewReservation {
        account_id: account.to_string(),
        candidate_account_id: "test-candidate".to_string(),
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
        payload_version: 1,
    }
}

#[tokio::test]
#[ignore = "requires Postgres; set DEVICE_ATTESTATION_TEST_DATABASE_URL and run with --ignored"]
async fn advancer_promotes_by_slot_rules_until_the_queue_drains() {
    let database_url = std::env::var("DEVICE_ATTESTATION_TEST_DATABASE_URL")
        .expect("DEVICE_ATTESTATION_TEST_DATABASE_URL is required");
    let pool = device_attestation::db::connect(&database_url)
        .await
        .expect("connect and migrate");
    let base = format!("queuetest{}", std::process::id());

    sqlx::query(
        "DELETE FROM username_reservations WHERE status = 'QUEUED' OR base LIKE 'queuetest%'",
    )
    .execute(&pool)
    .await
    .expect("pre-clean reservations");
    sqlx::query("DELETE FROM writer_lease WHERE name = $1")
        .bind(queue::ADVANCER_LEASE_NAME)
        .execute(&pool)
        .await
        .expect("pre-clean advancer lease");

    let groups: [i32; 6] = [1, 2, 3, 4, 4, 1];
    let mut ids = Vec::new();
    for (index, group) in groups.into_iter().enumerate() {
        let digits = format!("{:02}", index + 11);
        let account = format!("queue-subject-{index}");
        let id = outbox::insert_queued(&pool, &reservation(&base, &digits, &account), group)
            .await
            .expect("insert queued");
        ids.push(id);
    }

    let snapshot: Vec<_> = queue::queued_snapshot(&pool)
        .await
        .expect("snapshot")
        .into_iter()
        .filter(|entry| ids.contains(&entry.id))
        .collect();
    assert_eq!(
        snapshot.iter().map(|e| (e.id, e.group)).collect::<Vec<_>>(),
        ids.iter()
            .zip(groups)
            .map(|(&id, group)| (id, group as u8))
            .collect::<Vec<_>>()
    );

    let first = queue::advance_iteration(&pool).await.expect("iteration 1");
    assert_eq!(
        first.iter().map(|p| p.id).collect::<Vec<_>>(),
        [ids[3], ids[2], ids[1], ids[0]]
    );

    let second = queue::advance_iteration(&pool).await.expect("iteration 2");
    assert_eq!(
        second.iter().map(|p| p.id).collect::<Vec<_>>(),
        [ids[4], ids[5]]
    );
    assert_eq!(second[0].slot, 1);
    assert_eq!(second[1].slot, 4);

    let observed: Vec<(i64, u32)> = first
        .iter()
        .map(|p| (p.id, 1))
        .chain(second.iter().map(|p| (p.id, 2)))
        .collect();
    for (index, (id, iteration)) in observed.iter().enumerate() {
        let estimate = queue::drain_estimate(&snapshot, *id).expect("was queued");
        assert_eq!(
            estimate.position,
            index as u32 + 1,
            "simulation position matches the SQL promotion order for id {id}"
        );
        assert_eq!(
            estimate.iterations, *iteration,
            "simulation iteration matches the SQL iteration for id {id}"
        );
    }

    let statuses = sqlx::query("SELECT DISTINCT status FROM username_reservations WHERE base = $1")
        .bind(&base)
        .fetch_all(&pool)
        .await
        .expect("statuses");
    assert_eq!(statuses.len(), 1);
    assert_eq!(
        statuses[0].try_get::<String, _>("status").expect("status"),
        "RESERVED"
    );

    sqlx::query("DELETE FROM writer_lease WHERE name = $1")
        .bind(queue::ADVANCER_LEASE_NAME)
        .execute(&pool)
        .await
        .expect("clear advancer lease");
    assert!(!queue::advancer_alive(&pool).await.expect("probe"));

    let stranded = outbox::insert_queued(&pool, &reservation(&base, "17", "queue-subject-x"), 3)
        .await
        .expect("insert stranded");
    assert!(
        queue::stranded_queued(&pool).await.expect("stranded count") >= 1,
        "a queued row behind an absent lease counts as stranded"
    );
    queue::fallback_drain(&pool, std::time::Duration::from_secs(60))
        .await
        .expect("janitor drain");
    let status: String = sqlx::query("SELECT status FROM username_reservations WHERE id = $1")
        .bind(stranded)
        .fetch_one(&pool)
        .await
        .expect("stranded row")
        .try_get("status")
        .expect("status");
    assert_eq!(
        status, "RESERVED",
        "queue-disabled janitor drains rows behind an absent lease"
    );

    let epoch = lease::try_acquire(
        &pool,
        queue::ADVANCER_LEASE_NAME,
        "queue-live-test",
        std::time::Duration::from_secs(60),
    )
    .await
    .expect("acquire advancer lease")
    .expect("lease free");
    assert!(queue::advancer_alive(&pool).await.expect("probe"));

    let waiting = outbox::insert_queued(&pool, &reservation(&base, "18", "queue-subject-y"), 2)
        .await
        .expect("insert waiting");
    assert_eq!(
        queue::stranded_queued(&pool).await.expect("stranded count"),
        0,
        "a live advancer lease means queued rows are draining, not stranded"
    );
    queue::fallback_drain(&pool, std::time::Duration::from_secs(60))
        .await
        .expect("fallback drain with live lease");
    let status: String = sqlx::query("SELECT status FROM username_reservations WHERE id = $1")
        .bind(waiting)
        .fetch_one(&pool)
        .await
        .expect("waiting row")
        .try_get("status")
        .expect("status");
    assert_eq!(status, "QUEUED", "live queue service keeps claims queued");

    sqlx::query(
        "UPDATE writer_lease SET expires_at = now() - interval '10 seconds' WHERE name = $1",
    )
    .bind(queue::ADVANCER_LEASE_NAME)
    .execute(&pool)
    .await
    .expect("expire advancer lease");
    assert!(!queue::advancer_alive(&pool).await.expect("probe"));
    assert!(
        queue::stranded_queued(&pool).await.expect("stranded count") >= 1,
        "a queued row behind an expired lease counts as stranded"
    );
    assert!(
        !lease::renew(
            &pool,
            queue::ADVANCER_LEASE_NAME,
            "queue-live-test",
            epoch,
            std::time::Duration::from_secs(60),
        )
        .await
        .expect("renew attempt"),
        "renew must refuse an expired lease"
    );

    queue::fallback_drain(&pool, std::time::Duration::from_secs(60))
        .await
        .expect("drain within grace");
    let status: String = sqlx::query("SELECT status FROM username_reservations WHERE id = $1")
        .bind(waiting)
        .fetch_one(&pool)
        .await
        .expect("waiting row")
        .try_get("status")
        .expect("status");
    assert_eq!(status, "QUEUED", "expired within grace: queue holds");

    queue::fallback_drain(&pool, std::time::Duration::from_secs(5))
        .await
        .expect("drain beyond grace");
    let status: String = sqlx::query("SELECT status FROM username_reservations WHERE id = $1")
        .bind(waiting)
        .fetch_one(&pool)
        .await
        .expect("waiting row")
        .try_get("status")
        .expect("status");
    assert_eq!(status, "RESERVED", "expired beyond grace: queue drains");

    sqlx::query("DELETE FROM writer_lease WHERE name = $1")
        .bind(queue::ADVANCER_LEASE_NAME)
        .execute(&pool)
        .await
        .expect("clean advancer lease");
    sqlx::query("DELETE FROM username_reservations WHERE base = $1")
        .bind(&base)
        .execute(&pool)
        .await
        .expect("clean test rows");
}

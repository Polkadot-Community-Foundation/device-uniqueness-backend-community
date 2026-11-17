// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

//! How the writer runs while it holds the lease: one heartbeat for the whole
//! process, two lanes supervised independently of each other, and the periodic
//! passes beside them. Whichever lane fails restarts alone; only a lost lease
//! stops everything.

use std::{convert::Infallible, future::Future, time::Duration};

use tokio::{sync::Notify, time::Instant};

use super::{error::Op, WriterError};

/// Keep the lease renewed, every third of its TTL, until it is lost.
///
/// This is the one heartbeat everything held under the lease relies on, so it
/// runs on its own schedule rather than between a lane's passes: a lane busy in
/// a long reconcile or a slow dial must not let the lease lapse under the other
/// lane and the periodic passes.
///
/// A renewal that fails or hangs is retried on the next tick, but once the
/// lease has gone unrenewed for long enough that another writer could take it
/// before the next renewal, the lease is given up as lost. That also bounds a
/// database outage: the writer stops writing, fails to re-acquire, and exits.
///
/// A renewal counts from when it was sent. The new expiry is set when the `UPDATE`
///  runs, which may be well before a slow reply arrives.
pub(super) async fn hold_lease(
    mut renew: impl AsyncFnMut() -> Result<bool, WriterError>,
    ttl: Duration,
) -> WriterError {
    let period = ttl / 3;
    let mut renewed_at = Instant::now();
    loop {
        tokio::time::sleep(period).await;
        let sent_at = Instant::now();
        match tokio::time::timeout(period, renew()).await {
            Ok(Ok(true)) => renewed_at = sent_at,
            Ok(Ok(false)) => return WriterError::LeaseLost(Op::Renewing),
            Ok(Err(e)) => tracing::warn!(error = %e, "writer lease renewal failed"),
            Err(_) => tracing::warn!(
                timeout_secs = period.as_secs(),
                "writer lease renewal timed out"
            ),
        }
        if renewed_at.elapsed() + period >= ttl {
            return WriterError::LeaseLost(Op::Renewing);
        }
    }
}

/// Run one lane's passes until one fails, waiting via `idle` after a pass
/// that asks to (`Ok(true)`). A pass that does not finish within `stall` is
/// cancelled and reported as a failure, so a hung RPC restarts the lane rather
/// than silently stopping it.
pub(super) async fn drive(
    mut pass: impl AsyncFnMut() -> Result<bool, WriterError>,
    mut idle: impl AsyncFnMut(),
    stall: Duration,
) -> WriterError {
    loop {
        match tokio::time::timeout(stall, pass()).await {
            Ok(Ok(true)) => idle().await,
            Ok(Ok(false)) => {}
            Ok(Err(e)) => return e,
            Err(_) => return stalled(stall),
        }
    }
}

/// Run a lane, restarting it after every failure but a lost lease.
///
/// `restart` brings the lane up from an unknown state and is itself bounded by
/// `stall`; any error it returns other than a lost lease is treated like a
/// failed run (backed off and retried), never passed up, so one lane's trouble
/// cannot end the other lane's work. Returns only a lost lease.
pub(super) async fn supervise<S>(
    lane: &'static str,
    state: &mut S,
    mut restart: impl AsyncFnMut(&mut S) -> Result<(), WriterError>,
    mut run: impl AsyncFnMut(&mut S) -> WriterError,
    mut backoff: impl AsyncFnMut(),
    stall: Duration,
) -> WriterError {
    loop {
        let e = match tokio::time::timeout(stall, restart(state)).await {
            Ok(Ok(())) => run(state).await,
            Ok(Err(e)) => e,
            Err(_) => stalled(stall),
        };
        if e.is_lease_lost() {
            return e;
        }
        tracing::warn!(lane, error = %e, "lane failed; restarting it");
        backoff().await;
    }
}

fn stalled(stall: Duration) -> WriterError {
    anyhow::anyhow!("lane stalled: no progress within {}s", stall.as_secs()).into()
}

/// Wait out `period`, or less if `wake` is notified first.
pub(super) async fn sleep_or_wake(period: Duration, wake: &Notify) {
    tokio::select! {
        () = tokio::time::sleep(period) => {}
        () = wake.notified() => {}
    }
}

/// Run `tick`, then `wait`, forever. Only ever ends by being cancelled.
pub(super) async fn every(mut tick: impl AsyncFnMut(), mut wait: impl AsyncFnMut()) -> Infallible {
    loop {
        tick().await;
        wait().await;
    }
}

/// Run everything held under the lease until the lease is lost — reported by
/// the heartbeat or by a lane that found itself fenced out — and cancel the
/// rest with it.
pub(super) async fn until_lease_lost(
    lease: impl Future<Output = WriterError>,
    people: impl Future<Output = WriterError>,
    dotns: impl Future<Output = WriterError>,
    periodic: impl Future<Output = Infallible>,
) -> WriterError {
    tokio::select! {
        e = lease => e,
        e = people => e,
        e = dotns => e,
        never = periodic => match never {},
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    const STALL: Duration = Duration::from_secs(240);

    fn db_error() -> WriterError {
        WriterError::Db(sqlx::Error::PoolTimedOut)
    }

    fn bump(c: &Cell<u32>) -> u32 {
        c.set(c.get() + 1);
        c.get()
    }

    #[tokio::test]
    async fn a_busy_pass_loops_without_idling() {
        let (passes, idles) = (Cell::new(0), Cell::new(0));

        let e = drive(
            async || match bump(&passes) {
                3 => Err(db_error()),
                _ => Ok(false),
            },
            async || {
                bump(&idles);
            },
            STALL,
        )
        .await;

        assert!(matches!(e, WriterError::Db(_)));
        assert_eq!(passes.get(), 3);
        assert_eq!(idles.get(), 0, "a pass that did work must not wait");
    }

    #[tokio::test]
    async fn an_idle_pass_waits_before_the_next() {
        let (passes, idles) = (Cell::new(0), Cell::new(0));

        drive(
            async || match bump(&passes) {
                3 => Err(db_error()),
                _ => Ok(true),
            },
            async || {
                bump(&idles);
            },
            STALL,
        )
        .await;

        assert_eq!((passes.get(), idles.get()), (3, 2));
    }

    #[tokio::test(start_paused = true)]
    async fn a_hung_pass_is_a_failure_after_the_stall_bound() {
        let start = Instant::now();

        let e = drive(std::future::pending, async || {}, STALL).await;

        assert!(!e.is_lease_lost());
        assert!(e.to_string().contains("stalled"));
        assert_eq!(start.elapsed(), STALL);
    }

    #[tokio::test]
    async fn a_lane_error_restarts_only_that_lane() {
        let (restarts, runs, backoffs) = (Cell::new(0), Cell::new(0), Cell::new(0));

        let e = supervise(
            "test",
            &mut (),
            async |_| {
                bump(&restarts);
                Ok(())
            },
            async |_| match bump(&runs) {
                3 => WriterError::LeaseLost(Op::Landing),
                _ => db_error(),
            },
            async || {
                bump(&backoffs);
            },
            STALL,
        )
        .await;

        assert!(matches!(e, WriterError::LeaseLost(Op::Landing)));
        assert_eq!(
            (restarts.get(), runs.get(), backoffs.get()),
            (3, 3, 2),
            "every failure but the lease loss is followed by a backoff and a restart"
        );
    }

    #[tokio::test]
    async fn a_lease_lost_during_restart_does_not_run_the_lane() {
        let runs = Cell::new(0);

        let e = supervise(
            "test",
            &mut (),
            async |_| Err(WriterError::LeaseLost(Op::Landing)),
            async |_| {
                bump(&runs);
                db_error()
            },
            async || {},
            STALL,
        )
        .await;

        assert!(e.is_lease_lost());
        assert_eq!(runs.get(), 0);
    }

    #[tokio::test]
    async fn any_other_restart_error_is_retried_not_returned() {
        let (restarts, runs) = (Cell::new(0), Cell::new(0));

        let e = supervise(
            "test",
            &mut (),
            async |_| match bump(&restarts) {
                1 => Err(db_error()),
                _ => Ok(()),
            },
            async |_| {
                bump(&runs);
                WriterError::LeaseLost(Op::Draining)
            },
            async || {},
            STALL,
        )
        .await;

        assert!(e.is_lease_lost());
        assert_eq!((restarts.get(), runs.get()), (2, 1));
    }

    #[tokio::test(start_paused = true)]
    async fn a_hung_restart_is_retried_after_the_stall_bound() {
        let (restarts, backoffs) = (Cell::new(0), Cell::new(0));

        let e = supervise(
            "test",
            &mut (),
            async |_| {
                if bump(&restarts) == 1 {
                    std::future::pending::<()>().await;
                }
                Ok(())
            },
            async |_| WriterError::LeaseLost(Op::Draining),
            async || {
                bump(&backoffs);
            },
            STALL,
        )
        .await;

        assert!(e.is_lease_lost());
        assert_eq!((restarts.get(), backoffs.get()), (2, 1));
    }

    #[tokio::test]
    async fn one_lane_failing_does_not_restart_the_other() {
        let (a_runs, b_restarts, b_passes) = (Cell::new(0), Cell::new(0), Cell::new(0));
        let (mut a_state, mut b_state) = ((), ());

        let a = supervise(
            "a",
            &mut a_state,
            async |_| Ok(()),
            async |_| match bump(&a_runs) {
                3 => WriterError::LeaseLost(Op::Draining),
                _ => db_error(),
            },
            tokio::task::yield_now,
            STALL,
        );
        let b = supervise(
            "b",
            &mut b_state,
            async |_| {
                bump(&b_restarts);
                Ok(())
            },
            async |_| {
                drive(
                    async || {
                        bump(&b_passes);
                        tokio::task::yield_now().await;
                        Ok(false)
                    },
                    async || {},
                    STALL,
                )
                .await
            },
            async || {},
            STALL,
        );

        let e = until_lease_lost(std::future::pending(), a, b, std::future::pending()).await;

        assert!(e.is_lease_lost());
        assert_eq!(a_runs.get(), 3);
        assert_eq!(b_restarts.get(), 1, "b must not restart for a's errors");
        assert!(b_passes.get() >= 1, "b kept passing while a restarted");
    }

    #[tokio::test]
    async fn a_lease_loss_cancels_a_lane_stuck_mid_pass() {
        let mut state = ();
        let stuck = supervise(
            "stuck",
            &mut state,
            async |_| Ok(()),
            async |_| std::future::pending().await,
            async || {},
            STALL,
        );
        let losing = async { WriterError::LeaseLost(Op::Finalizing) };

        let e = until_lease_lost(
            std::future::pending(),
            stuck,
            losing,
            std::future::pending(),
        )
        .await;

        assert!(matches!(e, WriterError::LeaseLost(Op::Finalizing)));
    }

    #[tokio::test]
    async fn the_periodic_passes_run_while_a_lane_is_stuck_mid_pass() {
        let ticks = Cell::new(0);
        let stuck = std::future::pending();
        let waiting = async {
            while ticks.get() < 3 {
                tokio::task::yield_now().await;
            }
            WriterError::LeaseLost(Op::Draining)
        };
        let periodic = every(
            async || {
                bump(&ticks);
            },
            tokio::task::yield_now,
        );

        let e = until_lease_lost(std::future::pending(), waiting, stuck, periodic).await;

        assert!(e.is_lease_lost());
        assert!(
            ticks.get() >= 3,
            "a stuck dotNS lane must not hold the passes"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_heartbeat_ends_everything_while_both_lanes_are_stuck() {
        let lease = hold_lease(async || Ok(false), Duration::from_secs(30));

        let e = until_lease_lost(
            lease,
            std::future::pending(),
            std::future::pending(),
            std::future::pending(),
        )
        .await;

        assert!(matches!(e, WriterError::LeaseLost(Op::Renewing)));
    }

    #[tokio::test(start_paused = true)]
    async fn the_heartbeat_renews_every_third_of_the_ttl() {
        let renewals = Cell::new(0);
        let start = Instant::now();

        let e = hold_lease(async || Ok(bump(&renewals) < 4), Duration::from_secs(30)).await;

        assert!(e.is_lease_lost());
        assert_eq!(renewals.get(), 4);
        assert_eq!(start.elapsed(), Duration::from_secs(40));
    }

    #[tokio::test(start_paused = true)]
    async fn the_heartbeat_tolerates_one_failed_renewal() {
        let renewals = Cell::new(0);

        let e = hold_lease(
            async || match bump(&renewals) {
                2 => Err(db_error()),
                5 => Ok(false),
                _ => Ok(true),
            },
            Duration::from_secs(30),
        )
        .await;

        assert!(e.is_lease_lost());
        assert_eq!(renewals.get(), 5, "one failure between renewals is retried");
    }

    #[tokio::test(start_paused = true)]
    async fn the_heartbeat_gives_the_lease_up_before_it_can_expire() {
        let start = Instant::now();

        let e = hold_lease(async || Err(db_error()), Duration::from_secs(30)).await;

        assert!(matches!(e, WriterError::LeaseLost(Op::Renewing)));
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "a writer that cannot renew must stop before another can take over"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_heartbeat_counts_a_slow_renewal_from_when_it_was_sent() {
        let renewals = Cell::new(0);
        let start = Instant::now();

        let e = hold_lease(
            async || {
                tokio::time::sleep(Duration::from_secs(9)).await;
                if bump(&renewals) == 1 {
                    Ok(true)
                } else {
                    Err(db_error())
                }
            },
            Duration::from_secs(30),
        )
        .await;

        assert!(matches!(e, WriterError::LeaseLost(Op::Renewing)));
        assert!(
            start.elapsed() < Duration::from_secs(40),
            "a slow reply must not stretch the lease past the expiry the renewal set"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_idle_wait_runs_its_full_period_unwoken() {
        let start = Instant::now();
        sleep_or_wake(Duration::from_secs(2), &Notify::new()).await;
        assert_eq!(start.elapsed(), Duration::from_secs(2));
    }

    #[tokio::test(start_paused = true)]
    async fn a_wake_ends_an_idle_wait_early() {
        let wake = Notify::new();
        let start = Instant::now();

        tokio::join!(sleep_or_wake(Duration::from_secs(2), &wake), async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            wake.notify_one();
        });

        assert_eq!(start.elapsed(), Duration::from_millis(100));
    }

    #[tokio::test(start_paused = true)]
    async fn a_wake_sent_before_the_wait_is_not_lost() {
        let wake = Notify::new();
        wake.notify_one();
        let start = Instant::now();

        sleep_or_wake(Duration::from_secs(2), &wake).await;

        assert_eq!(start.elapsed(), Duration::ZERO);
    }
}

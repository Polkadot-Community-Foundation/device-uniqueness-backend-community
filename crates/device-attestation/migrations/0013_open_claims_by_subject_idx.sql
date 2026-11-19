-- Intake caps how many open claims one JWT subject may hold
-- (`USERNAME_MAX_OPEN_CLAIMS_PER_SUBJECT`, `outbox::open_claims`): rows by
-- `account_id` that are not ASSIGNED and still hold a discriminator. That
-- count runs on every capped claim, under the subject's advisory lock, so it
-- reads this index instead of the table. ASSIGNED rows never count and are the
-- bulk of the table, so they are left out of it. `updated_at` lets the count
-- skip FAILED_TERMINAL rows whose hold has passed without visiting them.
CREATE INDEX username_reservations_open_by_subject_idx
    ON username_reservations (account_id, updated_at)
    WHERE status <> 'ASSIGNED';

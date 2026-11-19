-- A FAILED_TERMINAL row no longer holds its username for ever.
--
-- `full_username` was unique across the whole table, so a failed claim kept
-- its `base.digits` permanently and 99 failed claims exhausted a base. The
-- uniqueness now covers only rows that can still land (every status but
-- FAILED_TERMINAL). How long a failed row keeps blocking re-allocation is
-- decided by `outbox::allocated_discriminators`, which holds it for
-- `FAILED_DISCRIMINATOR_HOLD` after it failed — long enough for any
-- transaction the writer signed for it (mortal, `PEOPLE_TX_MORTALITY_BLOCKS`)
-- to be dead. The chain itself enforces uniqueness for whatever did land.
--
-- The failed row is kept, not deleted: `last_error` is the operator's record
-- and `widevine_devices.reservation_id` may still reference it.
ALTER TABLE username_reservations
    DROP CONSTRAINT username_reservations_full_username_key;

CREATE UNIQUE INDEX username_reservations_live_full_username_key
    ON username_reservations (full_username)
    WHERE status <> 'FAILED_TERMINAL';

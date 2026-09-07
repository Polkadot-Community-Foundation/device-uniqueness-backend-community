-- Widevine device dedup records (PoUD Android device-uniqueness gate on
-- POST /api/v1/usernames). One row per pseudonymized physical device.
--
-- `device_hmac` is HMAC-SHA256(k, 'poud:v1' || deviceId), keyed by
-- WIDEVINE_DEDUP_HMAC_KEY; the raw device id is never stored. `reservation_id`
-- is set only while a claim is in flight, so a permanent row carries no
-- device->username link.
--
-- Lifecycle: PENDING is inserted in the same transaction as the username
-- reservation, becomes CONSUMED on on-chain success, and is DELETEd on
-- terminal failure so the device can claim again.

CREATE TYPE widevine_device_status AS ENUM ('PENDING', 'CONSUMED');

CREATE TABLE widevine_devices (
    id              BIGSERIAL               PRIMARY KEY,
    device_hmac     BYTEA                   NOT NULL,
    status          widevine_device_status  NOT NULL DEFAULT 'PENDING',
    -- The claim this record was reserved with; NULL once CONSUMED.
    reservation_id  BIGINT                  REFERENCES username_reservations(id),
    created_at      TIMESTAMPTZ             NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ             NOT NULL DEFAULT now(),

    -- One free registration per physical device: the atomic reserve races
    -- on this constraint.
    CONSTRAINT widevine_devices_device_key UNIQUE (device_hmac)
);

-- Chain-writer lookups on claim outcome; only in-flight rows carry a
-- reservation.
CREATE INDEX widevine_devices_reservation_idx
    ON widevine_devices (reservation_id)
    WHERE reservation_id IS NOT NULL;

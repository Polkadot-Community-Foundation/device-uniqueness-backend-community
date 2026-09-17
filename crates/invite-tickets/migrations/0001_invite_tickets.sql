-- The invitation-ticket keypair pool. One row per backend-generated sr25519
-- keypair, keyed by its public key. Two states only (the legacy invariant):
-- a ticket is `available` (registered on-chain, claimable) or `claimed`;
-- failed on-chain registrations are never inserted, so no failed/retrying
-- states exist. Pools are scoped by (dim, network); claims take the oldest
-- available row (FIFO by created_at) under FOR UPDATE SKIP LOCKED.

CREATE TABLE invite_tickets (
    -- 32-byte sr25519 public key of the ticket keypair.
    public_key  BYTEA PRIMARY KEY,
    -- Ticket secret: 32-byte seed (pool-generated) or 64-byte expanded
    -- sr25519 secret (a legacy-backfilled row). Never leaves this service.
    private_key BYTEA NOT NULL,
    dim         TEXT NOT NULL CHECK (dim IN ('Game', 'ProofOfInk')),
    network     TEXT NOT NULL CHECK (network IN ('westend2', 'paseo', 'polkadot')),
    -- SS58 address of the inviter that registered this ticket on-chain.
    inviter     TEXT NOT NULL,
    state       TEXT NOT NULL DEFAULT 'available' CHECK (state IN ('available', 'claimed')),
    -- SS58 address the ticket was claimed for (set on claim).
    claimed_by  TEXT,
    claimed_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ
);

-- The claim path's scan: available tickets of one (dim, network) pool.
CREATE INDEX invite_tickets_claimable_idx ON invite_tickets (state, dim, network);

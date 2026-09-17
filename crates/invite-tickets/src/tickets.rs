// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::str::FromStr;

use sqlx::postgres::PgRow;
use sqlx::{PgPool, Row as _};
use time::OffsetDateTime;

/// Which DIM (Decentralized Identity Module) a ticket funds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dim {
    /// The game personhood flow (`Game` pallet). Shipping priority.
    Game,
    /// The Proof-of-Ink flow (`ProofOfInk` pallet).
    ProofOfInk,
}

impl Dim {
    /// The wire/DB literal.
    pub fn as_str(self) -> &'static str {
        match self {
            Dim::Game => "Game",
            Dim::ProofOfInk => "ProofOfInk",
        }
    }
}

impl FromStr for Dim {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Game" => Ok(Dim::Game),
            "ProofOfInk" => Ok(Dim::ProofOfInk),
            _ => Err(()),
        }
    }
}

/// Network literal stamped into rows and responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// Westend next.
    Westend2,
    /// Paseo (default for dev/test).
    Paseo,
    /// Polkadot production.
    Polkadot,
}

impl Network {
    /// The wire/DB literal.
    pub fn as_str(self) -> &'static str {
        match self {
            Network::Westend2 => "westend2",
            Network::Paseo => "paseo",
            Network::Polkadot => "polkadot",
        }
    }
}

impl FromStr for Network {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "westend2" => Ok(Network::Westend2),
            "paseo" => Ok(Network::Paseo),
            "polkadot" => Ok(Network::Polkadot),
            _ => Err(()),
        }
    }
}

/// The fields of a just-claimed ticket the response needs (returned by the
/// claim transaction; the private key is consumed for signing and dropped).
#[derive(Clone)]
pub struct ClaimedTicket {
    /// 32-byte sr25519 public key of the ticket keypair.
    pub public_key: Vec<u8>,
    /// Ticket secret (32-byte seed or 64-byte expanded secret).
    pub private_key: Vec<u8>,
    /// SS58 address of the registering inviter.
    pub inviter: String,
    /// Row creation time (ticket generation time).
    pub created_at: OffsetDateTime,
}

/// `Debug` never prints the secret.
impl std::fmt::Debug for ClaimedTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClaimedTicket")
            .field("public_key", &hex::encode(&self.public_key))
            .field("private_key", &"<redacted>")
            .field("inviter", &self.inviter)
            .field("created_at", &self.created_at)
            .finish()
    }
}

impl ClaimedTicket {
    fn from_pg(row: &PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            public_key: row.try_get("public_key")?,
            private_key: row.try_get("private_key")?,
            inviter: row.try_get("inviter")?,
            created_at: row.try_get("created_at")?,
        })
    }
}

/// Count `available` tickets in one `(dim, network)` pool.
pub async fn count_available(
    pool: &PgPool,
    dim: Dim,
    network: Network,
) -> Result<i64, sqlx::Error> {
    let row = sqlx::query(
        "SELECT COUNT(*) AS n FROM invite_tickets \
         WHERE state = 'available' AND dim = $1 AND network = $2",
    )
    .bind(dim.as_str())
    .bind(network.as_str())
    .fetch_one(pool)
    .await?;
    row.try_get("n")
}

/// Atomically claim the oldest `available` ticket of a pool for `who`.
///
/// One transaction: `SELECT … FOR UPDATE SKIP LOCKED` the oldest row, then
/// flip it to `claimed` stamping `claimed_by` / `claimed_at` / `updated_at`.
/// `None` means no unlocked `available` row existed — under the legacy
/// contract that is the ticket race (409), because the caller pre-checked the
/// pool was non-empty.
pub async fn claim_oldest(
    pool: &PgPool,
    dim: Dim,
    network: Network,
    who: &str,
    now: OffsetDateTime,
) -> Result<Option<ClaimedTicket>, sqlx::Error> {
    let mut tx = pool.begin().await?;

    let row = sqlx::query(
        "SELECT public_key, private_key, inviter, created_at FROM invite_tickets \
         WHERE state = 'available' AND dim = $1 AND network = $2 \
         ORDER BY created_at ASC LIMIT 1 \
         FOR UPDATE SKIP LOCKED",
    )
    .bind(dim.as_str())
    .bind(network.as_str())
    .fetch_optional(&mut *tx)
    .await?;

    let Some(row) = row else {
        tx.rollback().await?;
        return Ok(None);
    };
    let ticket = ClaimedTicket::from_pg(&row)?;

    sqlx::query(
        "UPDATE invite_tickets \
         SET state = 'claimed', claimed_by = $2, claimed_at = $3, updated_at = $3 \
         WHERE public_key = $1",
    )
    .bind(&ticket.public_key)
    .bind(who)
    .bind(now)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(Some(ticket))
}

/// Insert a freshly generated, on-chain-registered ticket as `available`.
///
/// `ON CONFLICT DO NOTHING` mirrors legacy: a duplicate public key (never
/// expected from 32 random bytes) is silently skipped, not an error.
pub async fn insert_available(
    pool: &PgPool,
    public_key: &[u8],
    private_key: &[u8],
    dim: Dim,
    network: Network,
    inviter: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO invite_tickets (public_key, private_key, dim, network, inviter) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (public_key) DO NOTHING",
    )
    .bind(public_key)
    .bind(private_key)
    .bind(dim.as_str())
    .bind(network.as_str())
    .bind(inviter)
    .execute(pool)
    .await?;
    Ok(())
}

/// Render a `time` timestamp exactly like JavaScript's `Date.toISOString()`
/// (`YYYY-MM-DDTHH:MM:SS.mmmZ`) — the shape the shipping clients parse.
pub fn to_iso_millis(ts: OffsetDateTime) -> String {
    let fmt = time::macros::format_description!(
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
    );
    ts.to_offset(time::UtcOffset::UTC)
        .format(&fmt)
        .expect("static format description")
}

/// The 200 claim-response body.
///
/// `publicKey` / `signature` are lowercase `0x`-hex (the legacy `toHex`);
/// `createdAt` is the ticket's generation time, `claimedAt` the claim time
/// (the same instant written to the row); `remaining` is the post-claim pool
/// count.
#[allow(clippy::too_many_arguments)]
pub fn claim_response(
    ticket: &ClaimedTicket,
    signature: &[u8; 64],
    dim: Dim,
    network: Network,
    claimed_by: &str,
    claimed_at: OffsetDateTime,
    remaining: i64,
) -> serde_json::Value {
    serde_json::json!({
        "publicKey": format!("0x{}", hex::encode(&ticket.public_key)),
        "inviter": ticket.inviter,
        "dim": dim.as_str(),
        "network": network.as_str(),
        "claimedBy": claimed_by,
        "createdAt": to_iso_millis(ticket.created_at),
        "claimedAt": to_iso_millis(claimed_at),
        "signature": format!("0x{}", hex::encode(signature)),
        "remaining": remaining,
    })
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;

    #[test]
    fn iso_millis_matches_javascript_to_iso_string() {
        assert_eq!(
            to_iso_millis(datetime!(2026-07-01 10:20:30.4 UTC)),
            "2026-07-01T10:20:30.400Z"
        );
        assert_eq!(
            to_iso_millis(datetime!(2026-01-05 00:00:00 UTC)),
            "2026-01-05T00:00:00.000Z"
        );
        assert_eq!(
            to_iso_millis(datetime!(2026-07-01 10:20:30.400999 UTC)),
            "2026-07-01T10:20:30.400Z"
        );
    }

    #[test]
    fn claim_response_shape_is_stable() {
        let ticket = ClaimedTicket {
            public_key: vec![0xab; 32],
            private_key: vec![0; 32],
            inviter: "5C4hrfjw9DjXZTzV3MwzrrAr9P1MJhSrvWGWqi1eSuyUpnhM".to_string(),
            created_at: datetime!(2026-07-01 10:20:30.400 UTC),
        };
        let body = claim_response(
            &ticket,
            &[0xcd; 64],
            Dim::Game,
            Network::Paseo,
            "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty",
            datetime!(2026-07-02 11:00:00 UTC),
            41,
        );
        assert_eq!(
            body,
            serde_json::json!({
                "publicKey": format!("0x{}", "ab".repeat(32)),
                "inviter": "5C4hrfjw9DjXZTzV3MwzrrAr9P1MJhSrvWGWqi1eSuyUpnhM",
                "dim": "Game",
                "network": "paseo",
                "claimedBy": "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty",
                "createdAt": "2026-07-01T10:20:30.400Z",
                "claimedAt": "2026-07-02T11:00:00.000Z",
                "signature": format!("0x{}", "cd".repeat(64)),
                "remaining": 41,
            })
        );
    }

    #[test]
    fn debug_never_prints_the_secret() {
        let ticket = ClaimedTicket {
            public_key: vec![1; 32],
            private_key: vec![0x5e; 32],
            inviter: "5C4hrfjw9DjXZTzV3MwzrrAr9P1MJhSrvWGWqi1eSuyUpnhM".to_string(),
            created_at: datetime!(2026-07-01 10:20:30 UTC),
        };
        let rendered = format!("{ticket:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("5e5e"));
    }
}

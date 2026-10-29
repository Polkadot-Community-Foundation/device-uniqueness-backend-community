#!/usr/bin/env bash
set -euo pipefail

# Every database credential in the workspace. The four services read NAMESPACED
# names — a bare DATABASE_URL was read by four configs pointing at four
# different Postgres instances, so one process reading two of them would connect
# a service to another service's database and run the wrong migrations against
# it. The bare name is still honoured by the dual-read for one release, so it is
# forbidden alongside the four.
DB_URL_KEYS=(
  DEVICE_ATTESTATION_DATABASE_URL
  INDEXER_DATABASE_URL
  INVITE_TICKETS_DATABASE_URL
  DATABASE_URL
)

# `--profile '*'`: the boundaries hold for every service the file can start,
# including the ones behind a profile (invite-tickets) that .env may leave off.
rendered="$(docker compose --profile '*' config)"
# Cleared so a shell still holding the local-run overrides (see the header of
# gateway/docker-compose.yml) checks the committed defaults, not its own ports.
rendered_gateway="$(EDGE_HTTP_PORT= EDGE_HTTPS_PORT= docker compose -f gateway/docker-compose.yml config)"
rendered_debug="$(docker compose --profile '*' -f docker-compose.yml -f docker-compose.debug.yml config)"
# Same treatment as the gateway: cleared so a shell that republished a UI port
# for itself is checked against the committed loopback defaults.
rendered_observability="$(PROMETHEUS_PORT= GRAFANA_PORT= ALLOY_PORT= \
  docker compose -f observability/docker-compose.yml config)"

service_block() {
  local service="$1"
  awk -v target="$service" '
    $0 == "  " target ":" {
      in_service = 1
      next
    }
    in_service && /^  [a-zA-Z0-9_-]+:$/ {
      exit
    }
    in_service {
      print
    }
  ' <<<"$rendered"
}

environment_keys() {
  service_block "$1" | awk '
    /^    environment:$/ {
      in_environment = 1
      next
    }
    in_environment && /^      [A-Z0-9_]+:/ {
      key = $1
      sub(/:$/, "", key)
      print key
      next
    }
    in_environment && /^    [a-zA-Z0-9_-]+:/ {
      exit
    }
  '
}

require_key() {
  local service="$1"
  local key="$2"
  if ! environment_keys "$service" | grep -Fxq "$key"; then
    echo "$service must receive $key" >&2
    exit 1
  fi
}

# One `host_ip|published->target/protocol` line per published port mapping, read
# from a rendered compose document on stdin. Structural rather than a substring
# count, so a mapping that keeps the host port but changes the target, the
# protocol, or the interface cannot slip through.
port_mappings() {
  awk '
    /^      - mode:/     { host = "*"; next }
    /^        host_ip:/  { host = $2; next }
    /^        target:/   { target = $2; next }
    /^        published:/ { published = $2; gsub(/"/, "", published); next }
    /^        protocol:/ { print host "|" published "->" target "/" $2 }
  ' | sort
}

forbid_key() {
  local service="$1"
  local key="$2"
  if environment_keys "$service" | grep -Fxq "$key"; then
    echo "$service must not receive $key" >&2
    exit 1
  fi
}

for service in device-attestation-api device-attestation-chain-writer username-indexer; do
  forbid_key "$service" INVITER_SIGNER_SURI
done

# Request-validation bounds are intake-only. They shape 400s, not extrinsics.
for key in DOTNS_INTAKE_FRESHNESS_MAX_AGE_SECS DOTNS_MAX_FUTURE_SKEW_SECS; do
  require_key device-attestation-api "$key"
  for service in device-attestation-chain-writer registration-queue username-indexer \
                 invite-tickets-api invite-tickets-pool turn-api; do
    forbid_key "$service" "$key"
  done
done

# The Asset Hub connection and the attester identity belong to the writer. It is
# the only process that submits there. The dotNS lane is not optional, so a
# writer without ASSET_HUB_RPC_URL aborts at boot rather than running half a
# registration. ATTESTER_ACCOUNT names the authority on
# both chains and the writer derives proxying from it, so the two must be one
# value. device-attestation-api needs it too, since it serves GET /api/v1/attester.
# Nothing else does, and no other service opens an Asset Hub connection.
require_key device-attestation-chain-writer ASSET_HUB_RPC_URL
require_key device-attestation-chain-writer ATTESTER_ACCOUNT
require_key device-attestation-api ATTESTER_ACCOUNT
for service in device-attestation-api registration-queue username-indexer \
               invite-tickets-api invite-tickets-pool turn-api \
               notify-relay; do
  forbid_key "$service" ASSET_HUB_RPC_URL
done

# registration-queue only reads chain balances and flips queue rows in the
# device-attestation DB — never signing secrets or JWT material. Its lease is the queue
# liveness signal, so it needs its cadence knobs.
for key in JWT_ED25519_SECRET JWT_ED25519_PUBLIC_KEY JWT_JWKS_JSON \
           CHAIN_WRITER_SIGNER_SURI INVITER_SIGNER_SURI INVITE_INVITER_SIGNER_SURI \
           TURN_API_TOKEN TURN_SECRET; do
  forbid_key registration-queue "$key"
done
require_key registration-queue QUEUE_ADVANCE_INTERVAL_SECS
require_key registration-queue QUEUE_LEASE_TTL_SECS
# The wires the queue's throttle story hinges on: intake gating on the api,
# and the SAME flag on the writer (on = hold the throttle, warn about
# stranded rows; off = janitor drain after the grace window). Split values
# would strand-or-unthrottle depending on which side is on.
require_key device-attestation-api QUEUE_ENABLED
require_key device-attestation-chain-writer QUEUE_ENABLED
require_key device-attestation-chain-writer QUEUE_FALLBACK_AFTER_SECS

# username-indexer serves public reads and holds VERIFY-ONLY JWT material: the
# public key admits authenticated callers past the proof-of-compute gate, but the
# service can never mint a token. The signing secret and every other service's
# secret stay out.
for key in JWT_ED25519_SECRET CHAIN_WRITER_SIGNER_SURI INVITER_SIGNER_SURI \
           INVITE_INVITER_SIGNER_SURI TURN_API_TOKEN TURN_SECRET; do
  forbid_key username-indexer "$key"
done
require_key username-indexer SEARCH_RATE_LIMIT
require_key username-indexer SEARCH_RATE_LIMIT_WINDOW_SECS
# The gate's flag and its two key inputs: the bypass needs verify-only JWT
# material, and the puzzle secret must live here and nowhere else.
require_key username-indexer POC_ENABLED
require_key username-indexer JWT_ED25519_PUBLIC_KEY
require_key username-indexer POC_HMAC_SECRET
# Every other service in the compose file, application and database alike.
for service in device-attestation-api device-attestation-chain-writer registration-queue \
               invite-tickets-api invite-tickets-pool turn-api notify-relay \
               postgres username-indexer-postgres \
               invite-tickets-postgres; do
  forbid_key "$service" POC_HMAC_SECRET
done

# Attestation verification material belongs to device-attestation-api, the only
# service that verifies device attestations. Its allowlist must carry every key
# (a missing line silently drops the .env value), and no other service gets one.
for key in PLAY_INTEGRITY_DECRYPTION_KEY PLAY_INTEGRITY_VERIFICATION_KEY GOOGLE_CREDENTIALS \
           DEVICE_CHECK_PRIVATE_KEY WIDEVINE_DEDUP_HMAC_KEY; do
  require_key device-attestation-api "$key"
  for service in device-attestation-chain-writer registration-queue username-indexer \
                 invite-tickets-api invite-tickets-pool turn-api notify-relay; do
    forbid_key "$service" "$key"
  done
done

# Only the edge publishes. The base file must expose nothing on the host, so a
# second environment cannot collide and no service is reachable from outside.
if grep -Fq "published:" <<<"$rendered"; then
  echo "no service in docker-compose.yml may publish a host port (the edge does that)" >&2
  grep -B2 -F "published:" <<<"$rendered" >&2
  exit 1
fi

# The debug overlay exists to reopen those ports locally; it must never widen
# them beyond loopback, and it must stay useful — an overlay that quietly lost
# most of its mappings would still satisfy a "nothing public" check.
debug_mappings="$(port_mappings <<<"$rendered_debug")"
debug_count="$(grep -c . <<<"$debug_mappings" || true)"
debug_public="$(grep -vc '^127\.0\.0\.1|' <<<"$debug_mappings" || true)"
debug_unique="$(cut -d'|' -f2 <<<"$debug_mappings" | cut -d'-' -f1 | sort -u | grep -c . || true)"
if [ "$debug_count" -ne 8 ]; then
  echo "docker-compose.debug.yml must republish all 8 service/Postgres ports ($debug_count found)" >&2
  echo "$debug_mappings" >&2
  exit 1
fi
if [ "$debug_public" -ne 0 ]; then
  echo "docker-compose.debug.yml may only publish on 127.0.0.1:" >&2
  grep -v '^127\.0\.0\.1|' <<<"$debug_mappings" >&2
  exit 1
fi
if [ "$debug_unique" -ne "$debug_count" ]; then
  echo "docker-compose.debug.yml publishes the same host port twice:" >&2
  echo "$debug_mappings" >&2
  exit 1
fi

# Each database credential reaches ONLY the services that own that database.
#
# This is the invariant the namespacing exists to make checkable. Before it,
# six services read the same key name — `DATABASE_URL` — pointing at three
# different Postgres instances, so "is this service wired to the right database?"
# was not expressible here at all. A misrouted URL starts cleanly and runs the
# wrong migrations against someone else's schema.
declare -A DB_OWNERS=(
  [DEVICE_ATTESTATION_DATABASE_URL]="device-attestation-api device-attestation-chain-writer registration-queue"
  [INDEXER_DATABASE_URL]="username-indexer"
  [INVITE_TICKETS_DATABASE_URL]="invite-tickets-api invite-tickets-pool"
)
APP_SERVICES=(
  device-attestation-api device-attestation-chain-writer registration-queue username-indexer
  invite-tickets-api invite-tickets-pool turn-api notify-relay
)
for key in "${!DB_OWNERS[@]}"; do
  for service in "${APP_SERVICES[@]}"; do
    if [[ " ${DB_OWNERS[$key]} " == *" $service "* ]]; then
      require_key "$service" "$key"
    else
      forbid_key "$service" "$key"
    fi
  done
done
# The pre-namespacing name is still honoured by the dual-read, so leaving it set
# anywhere would silently keep the old value through the deprecation release.
for service in "${APP_SERVICES[@]}"; do
  forbid_key "$service" DATABASE_URL
done

# The per-service rate limits, which used to be one shared `RATE_LIMIT` — tuning
# one service retuned the other two.
require_key invite-tickets-api INVITE_TICKETS_RATE_LIMIT
require_key invite-tickets-api INVITE_TICKETS_RATE_LIMIT_WINDOW_SECS
require_key turn-api TURN_RATE_LIMIT
require_key turn-api TURN_RATE_LIMIT_WINDOW_SECS

# turn-api is the only service that issues TURN credentials, under either
# provider, so it is the only one that may hold either provider's secret. Its
# allowlist must carry every provider key — a missing line silently drops the
# .env value, which for TURN_PROVIDER would mean the container quietly falling
# back to the default provider whatever the operator set.
for key in TURN_PROVIDER TURN_KEY_ID TURN_API_TOKEN \
           TURN_SECRET TURN_AUTH_ALGORITHM TURN_REALM ICE_SERVERS; do
  require_key turn-api "$key"
done
# And no other app service may carry any of them — the two secrets above all,
# since TURN_API_TOKEN mints against the org's Cloudflare account and is billed
# to it. The non-secret selectors are scoped too: a stray copy elsewhere means
# another service was meant to mint credentials.
for service in "${APP_SERVICES[@]}"; do
  if [ "$service" != turn-api ]; then
    for key in TURN_PROVIDER TURN_KEY_ID TURN_API_TOKEN \
               TURN_SECRET TURN_AUTH_ALGORITHM TURN_REALM ICE_SERVERS; do
      forbid_key "$service" "$key"
    done
  fi
done
for service in "${APP_SERVICES[@]}"; do
  forbid_key "$service" RATE_LIMIT
  forbid_key "$service" RATE_LIMIT_WINDOW_SECS
done

# notify-relay is verify-only and holds its own push secrets, but never another
# service's signing/DB secrets.
for key in JWT_ED25519_SECRET CHAIN_WRITER_SIGNER_SURI INVITER_SIGNER_SURI \
           INVITE_INVITER_SIGNER_SURI TURN_API_TOKEN TURN_SECRET "${DB_URL_KEYS[@]}"; do
  forbid_key notify-relay "$key"
done
require_key notify-relay JWT_ED25519_PUBLIC_KEY
require_key notify-relay NOTIFY_RATE_LIMIT
require_key notify-relay NOTIFY_RATE_LIMIT_WINDOW_SECS

# The gateway terminates and routes only — it must never hold any secret. It
# lives in its own compose project: the helpers read `rendered`, so the swap is
# scoped to a subshell rather than left in place for whatever is added below.
(
  rendered="$rendered_gateway"
  for key in JWT_ED25519_SECRET CHAIN_WRITER_SIGNER_SURI INVITER_SIGNER_SURI \
             INVITE_INVITER_SIGNER_SURI TURN_API_TOKEN TURN_SECRET "${DB_URL_KEYS[@]}" JWT_JWKS_JSON \
             JWT_ED25519_PUBLIC_KEY APNS_PRIVATE_KEY APNS_PRIVATE_KEY_FILE \
             FCM_SERVICE_ACCOUNT_JSON POC_HMAC_SECRET \
             ASSET_HUB_RPC_URL DOTNS_INTAKE_FRESHNESS_MAX_AGE_SECS \
             DOTNS_MAX_FUTURE_SKEW_SECS; do
    forbid_key caddy "$key"
  done
)

# The edge is the one thing that may publish, and only the two public ports —
# target and protocol included, so neither losing 443/udp nor pointing 443 at
# the wrong container port can pass.
edge_published="$(port_mappings <<<"$rendered_gateway")"
expected_published="$(printf '*|443->443/tcp\n*|443->443/udp\n*|80->80/tcp\n' | sort)"
if [ "$edge_published" != "$expected_published" ]; then
  echo "the edge must publish exactly 80->80/tcp, 443->443/tcp and 443->443/udp, got:" >&2
  echo "$edge_published" >&2
  exit 1
fi

# Monitoring is for operators behind an SSH tunnel, never for the internet: the
# three UIs (Grafana, Prometheus, Alloy) may publish only on loopback, and Loki
# not at all — Alloy writes to it and Grafana reads it over the metrics network.
observability_published="$(port_mappings <<<"$rendered_observability")"
expected_observability="$(printf '127.0.0.1|12345->12345/tcp\n127.0.0.1|3000->3000/tcp\n127.0.0.1|9091->9090/tcp\n' | sort)"
if [ "$observability_published" != "$expected_observability" ]; then
  echo "the observability project must publish only Grafana/Prometheus/Alloy on 127.0.0.1, got:" >&2
  echo "$observability_published" >&2
  exit 1
fi

# It reads logs and metrics; it must never be handed anything it could sign or
# decrypt with. The Grafana admin password is its own and stays out of this set.
(
  rendered="$rendered_observability"
  for service in prometheus loki alloy grafana; do
    for key in JWT_ED25519_SECRET CHAIN_WRITER_SIGNER_SURI INVITER_SIGNER_SURI \
               INVITE_INVITER_SIGNER_SURI TURN_API_TOKEN TURN_SECRET POC_HMAC_SECRET "${DB_URL_KEYS[@]}" \
               APNS_PRIVATE_KEY FCM_SERVICE_ACCOUNT_JSON; do
      forbid_key "$service" "$key"
    done
  done
)

echo "compose configuration boundaries: ok"

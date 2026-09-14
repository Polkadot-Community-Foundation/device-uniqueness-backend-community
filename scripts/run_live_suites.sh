#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <db|chain|providers> <cargo command...>" >&2
  exit 2
}

mode="${1:-}"
if [ "$#" -lt 2 ]; then
  usage
fi
shift
cargo_cmd=("$@")

if [ "$mode" = "providers" ]; then
  ran_provider=false
  if { [ -n "${APNS_PRIVATE_KEY:-}" ] || \
       { [ -n "${APNS_PRIVATE_KEY_FILE:-}" ] && [ "${APNS_PRIVATE_KEY_FILE}" != "/dev/null" ]; }; }; then
    "${cargo_cmd[@]}" -p notifications --test apns_live -- --ignored --nocapture
    ran_provider=true
  fi
  if [ -n "${FCM_SERVICE_ACCOUNT_JSON:-}" ]; then
    "${cargo_cmd[@]}" -p notifications --test fcm_live -- --ignored --nocapture
    ran_provider=true
  fi
  if [ "$ran_provider" = false ]; then
    echo "configure APNS_PRIVATE_KEY/APNS_PRIVATE_KEY_FILE or FCM_SERVICE_ACCOUNT_JSON" >&2
    exit 2
  fi
  exit 0
fi

if [ "$mode" != "db" ] && [ "$mode" != "chain" ]; then
  usage
fi

# A dedicated, per-invocation project keeps test containers, networks, and
# named volumes separate from the normal dub dev stack. The
# prefix check makes the EXIT cleanup safe even if an override is supplied.
test_project="${DUB_TEST_COMPOSE_PROJECT:-dub-tests-$$}"
case "$test_project" in
  dub-tests-*) ;;
  *)
    echo "DUB_TEST_COMPOSE_PROJECT must start with dub-tests-" >&2
    exit 2
    ;;
esac

device_attestation_port="${DEVICE_ATTESTATION_TEST_POSTGRES_PORT:-56432}"
indexer_port="${INDEXER_TEST_POSTGRES_PORT:-56433}"
export DEVICE_ATTESTATION_POSTGRES_PORT="$device_attestation_port"
export INDEXER_POSTGRES_PORT="$indexer_port"

compose=(
  docker compose
  -p "$test_project"
  -f docker-compose.yml
  -f docker-compose.debug.yml
)
databases=(
  postgres
  username-indexer-postgres
)

cleanup() {
  "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

"${compose[@]}" up -d --wait --wait-timeout 90 "${databases[@]}"

device_attestation_url="postgres://device_attestation:device_attestation@localhost:${device_attestation_port}/device_attestation"
indexer_url="postgres://username_indexer:username_indexer@localhost:${indexer_port}/username_indexer"

if [ "$mode" = "chain" ]; then
  # These production-router suites also require PEOPLE_RPC_URL, or use their
  # public Paseo default. They stay opt-in because external chain availability
  # is not a deterministic merge/release prerequisite.
  #
  # batched_read_live proves the batched availability read agrees with the typed
  # one-key-per-request path against real chain state. Its latency probe stays
  # skipped unless BATCH_PROBE_CONCURRENCY is set, so this stays a correctness
  # gate rather than a benchmark.
  for suite in voucher_http_live payment_http_live payment_watch_live batched_read_live; do
    DEVICE_ATTESTATION_TEST_DATABASE_URL="$device_attestation_url" \
      "${cargo_cmd[@]}" -p device-attestation --test "$suite" -- --ignored
  done
  exit 0
fi

# Deterministic database-only gate: 11 suites / 24 ignored tests. Keep this
# list here so local tests, CI, and coverage all execute the same catalog.
for suite in allocation_live auth_live outbox_live dotns_live queue_live voucher_live payment_live; do
  DEVICE_ATTESTATION_TEST_DATABASE_URL="$device_attestation_url" \
    "${cargo_cmd[@]}" -p device-attestation --test "$suite" -- --ignored
done

# `ingest_live` and `chain_identity_live` both drive the singleton `sync_state`
# row, and `chain_identity_live` clears `assigned_usernames` wholesale — this
# loop runs one suite at a time, which is what keeps them from interleaving.
for suite in pagination_live poc_gate_live ingest_live chain_identity_live; do
  DATABASE_URL="$indexer_url" \
    "${cargo_cmd[@]}" -p username-indexer --test "$suite" -- --ignored
done


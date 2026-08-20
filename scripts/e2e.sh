#!/usr/bin/env bash
#
# Run the browser end-to-end suite against a freshly provisioned bkd.
#
# Everything is created from scratch on each run — database, master key,
# account — and torn down afterwards. Sharing state between runs is what made
# an earlier version of these tests pass once and then fail: the second run
# found a vault that already existed and expected to create one.
#
#   ./scripts/e2e.sh
#
# Environment:
#   BKD_E2E_PORT       port to serve on (default 18500)
#   BKD_E2E_CHROMIUM   path to a Chromium binary, when Playwright's own is
#                      unavailable or mismatched
#
set -euo pipefail

cd "$(dirname "$0")/.."

PORT="${BKD_E2E_PORT:-18500}"
BASE_URL="http://127.0.0.1:${PORT}"
WORKDIR="$(mktemp -d)"
SERVER_PID=""

cleanup() {
    if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill -TERM "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

info() { echo "==> $*"; }

[[ -x bin/bkd ]] || { echo "bin/bkd not found; run 'make release' first" >&2; exit 1; }

# A frontend has to be embedded, or every one of these tests would fail with a
# blank page and no useful explanation.
if ! ./bin/bkd version >/dev/null 2>&1; then
    echo "bin/bkd is not runnable" >&2
    exit 1
fi

info "provisioning a throwaway instance in $WORKDIR"

cat > "$WORKDIR/config.yaml" <<EOF
server:
  bind: "127.0.0.1:${PORT}"
  external_url: "${BASE_URL}"
database:
  driver: sqlite
  dsn: "${WORKDIR}/bkd.db"
vault:
  master_key_path: "${WORKDIR}/master.key"
  # Deliberately cheap: these tests exercise the flows, not the key derivation
  # cost, which has its own tests.
  argon2_time: 1
  argon2_memory_kb: 16384
  argon2_threads: 1
auth:
  # The suite speaks plain HTTP to a loopback address, so Secure cookies would
  # simply never be sent.
  secure_cookies: false
paths:
  data_dir: "${WORKDIR}/data"
  session_log_dir: "${WORKDIR}/data/logs"
  recording_dir: "${WORKDIR}/data/recordings"
log:
  level: warn
  format: text
EOF

./bin/bkd gen-master-key --config "$WORKDIR/config.yaml" >/dev/null
./bin/bkd migrate --config "$WORKDIR/config.yaml" >/dev/null 2>&1

echo "a very long admin password" | \
    ./bin/bkd admin create-user --config "$WORKDIR/config.yaml" \
        -email admin@example.com -name "Alice Admin" -admin >/dev/null

info "starting bkd on ${BASE_URL}"
./bin/bkd serve --config "$WORKDIR/config.yaml" > "$WORKDIR/server.log" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 80); do
    if curl -fsS -o /dev/null "${BASE_URL}/healthz" 2>/dev/null; then break; fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "bkd exited during startup:" >&2
        cat "$WORKDIR/server.log" >&2
        exit 1
    fi
    sleep 0.25
done

if ! curl -fsS -o /dev/null "${BASE_URL}/healthz"; then
    echo "bkd did not become healthy:" >&2
    cat "$WORKDIR/server.log" >&2
    exit 1
fi

info "running the browser suite"
set +e
(cd web && BKD_E2E_URL="$BASE_URL" npx playwright test "$@")
STATUS=$?
set -e

if [[ $STATUS -ne 0 ]]; then
    echo
    echo "--- server log ---" >&2
    cat "$WORKDIR/server.log" >&2
fi

exit $STATUS

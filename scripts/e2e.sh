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
# A throwaway SSH server with a real pty is started alongside, so the terminal
# tests drive a genuine shell rather than a stub.
#
set -euo pipefail

cd "$(dirname "$0")/.."

PORT="${BKD_E2E_PORT:-18500}"
BASE_URL="http://127.0.0.1:${PORT}"
WORKDIR="$(mktemp -d)"
SERVER_PID=""
SSHD_PID=""

SSH_USER="tester"
SSH_PASSWORD="a throwaway ssh password"

# shellcheck disable=SC2317  # called by the EXIT trap, which shellcheck cannot see
cleanup() {
    for pid in "$SERVER_PID" "$SSHD_PID"; do
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
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

# A real SSH server with a real pty. The Go tests use an in-process one with a
# canned handler, which proves the protocol; this proves a genuine shell
# behaves — that resize reaches stty, that a login is a login.
info "building the test SSH server"
go build -tags tools -o "$WORKDIR/testsshd" ./tools/testsshd

info "starting the test SSH server"
"$WORKDIR/testsshd" \
    -addr 127.0.0.1:0 \
    -user "$SSH_USER" \
    -password "$SSH_PASSWORD" \
    -port-file "$WORKDIR/sshd.port" > "$WORKDIR/sshd.log" 2>&1 &
SSHD_PID=$!

for _ in $(seq 1 80); do
    [[ -s "$WORKDIR/sshd.port" ]] && break
    if ! kill -0 "$SSHD_PID" 2>/dev/null; then
        echo "the test SSH server exited during startup:" >&2
        cat "$WORKDIR/sshd.log" >&2
        exit 1
    fi
    sleep 0.25
done

if [[ ! -s "$WORKDIR/sshd.port" ]]; then
    echo "the test SSH server never reported a port:" >&2
    cat "$WORKDIR/sshd.log" >&2
    exit 1
fi
SSH_PORT="$(cat "$WORKDIR/sshd.port")"
info "test SSH server on 127.0.0.1:${SSH_PORT}"

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
(cd web && \
    BKD_E2E_URL="$BASE_URL" \
    BKD_E2E_SSH_HOST="127.0.0.1" \
    BKD_E2E_SSH_PORT="$SSH_PORT" \
    BKD_E2E_SSH_USER="$SSH_USER" \
    BKD_E2E_SSH_PASSWORD="$SSH_PASSWORD" \
    npx playwright test "$@")
STATUS=$?
set -e

if [[ $STATUS -ne 0 ]]; then
    echo
    echo "--- server log ---" >&2
    cat "$WORKDIR/server.log" >&2
    echo "--- test ssh server log ---" >&2
    cat "$WORKDIR/sshd.log" >&2
fi

exit $STATUS

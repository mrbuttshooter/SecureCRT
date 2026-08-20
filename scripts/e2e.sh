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
SSHD2_PID=""
BASTION_PID=""

SSH_USER="tester"
SSH_PASSWORD="a throwaway ssh password"

# shellcheck disable=SC2317  # called by the EXIT trap, which shellcheck cannot see
cleanup() {
    for pid in "$SERVER_PID" "$SSHD_PID" "$SSHD2_PID" "$BASTION_PID"; do
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
policy:
  # On here, off in the shipped default, and the difference is the point: the
  # tunnels spec checks both halves — that a listener genuinely carries
  # traffic, and that a kind still switched off is refused with the setting
  # named rather than a button that does nothing.
  #
  # tunnels.domain stays unset, so web tunnels remain unavailable. There is
  # nowhere safe to serve a device's own pages from without one, and a test
  # instance is not an exception to that.
  allow_tcp_tunnels: true
  allow_remote_forwards: false
tunnels:
  bind: "127.0.0.1"
  port_range: "34700-34799"
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

# One account per spec file. The suites share an instance, so sharing an
# account would mean sharing a vault, a credential list, a set of saved
# connections and a known-hosts list — and a test asserting on the first-run
# experience or on an empty list would then depend on which file happened to
# run first. An earlier version did, and broke the moment a third spec was
# added.
for account in admin terminal files transfer tunnels; do
    echo "a very long admin password" | \
        ./bin/bkd admin create-user --config "$WORKDIR/config.yaml" \
            -email "${account}@example.com" -name "Test ${account}" -admin >/dev/null
done

# Configurations to migrate, built here rather than checked in as fixtures so
# they are unmistakably the shape a real desktop produces: a zipped folder,
# with everything one level down inside it.
info "building configurations to import"

mkdir -p "$WORKDIR/import/Config/Sessions/Edge routers"
cat > "$WORKDIR/import/Config/Sessions/core-sw-01.ini" <<'INI'
S:"Protocol Name"=SSH2
S:"Hostname"=10.77.0.1
S:"Username"=netops
D:"[SSH2] Port"=00000016
INI
cat > "$WORKDIR/import/Config/Sessions/Edge routers/edge-rtr-01.ini" <<'INI'
S:"Protocol Name"=SSH2
S:"Hostname"=10.77.1.1
S:"Username"=admin
INI
(cd "$WORKDIR/import" && zip -qr "$WORKDIR/securecrt.zip" Config)

mkdir -p "$WORKDIR/putty/putty/sessions"
cp internal/portability/ppk/testdata/v3-ed25519.ppk "$WORKDIR/putty/putty/core.ppk"
cat > "$WORKDIR/putty/putty/sessions/dist%20switch" <<'PUTTY'
HostName=10.77.2.1
PortNumber=22
UserName=netops
Protocol=ssh
PublicKeyFile=C:\Users\netops\core.ppk
PUTTY
(cd "$WORKDIR/putty" && zip -qr "$WORKDIR/putty.zip" putty)

export BKD_E2E_SECURECRT_ZIP="$WORKDIR/securecrt.zip"
export BKD_E2E_PUTTY_ZIP="$WORKDIR/putty.zip"

# Real SSH servers with a real pty and a real SFTP subsystem. The Go tests use
# in-process ones with canned handlers, which proves the protocol; these prove
# a genuine shell behaves — that resize reaches stty, that a login is a login —
# and that a file uploaded through the browser lands on a real filesystem this
# script can then read.
#
# Three of them. Two, because copying a directory from one managed host
# straight to another is the feature that needs two hosts to test at all — and
# a third acting as a bastion, because a jump host only proves anything if the
# device behind it is genuinely reached through it.
info "building the test SSH server"
go build -tags tools -o "$WORKDIR/testsshd" ./tools/testsshd

start_sshd() {
    local name="$1"
    local logfile="$WORKDIR/${name}.log"
    local portfile="$WORKDIR/${name}.port"

    "$WORKDIR/testsshd" \
        -addr 127.0.0.1:0 \
        -user "$SSH_USER" \
        -password "$SSH_PASSWORD" \
        -port-file "$portfile" > "$logfile" 2>&1 &
    local pid=$!

    local _
    for _ in $(seq 1 80); do
        [[ -s "$portfile" ]] && break
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "the test SSH server ${name} exited during startup:" >&2
            cat "$logfile" >&2
            exit 1
        fi
        sleep 0.25
    done

    if [[ ! -s "$portfile" ]]; then
        echo "the test SSH server ${name} never reported a port:" >&2
        cat "$logfile" >&2
        exit 1
    fi

    echo "$pid"
}

info "starting the test SSH servers"
SSHD_PID="$(start_sshd sshd)"
SSHD2_PID="$(start_sshd sshd2)"
BASTION_PID="$(start_sshd bastion)"
SSH_PORT="$(cat "$WORKDIR/sshd.port")"
SSH_PORT_2="$(cat "$WORKDIR/sshd2.port")"
BASTION_PORT="$(cat "$WORKDIR/bastion.port")"
info "test SSH servers on 127.0.0.1:${SSH_PORT}, 127.0.0.1:${SSH_PORT_2}, bastion on 127.0.0.1:${BASTION_PORT}"

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

# Playwright refuses to launch when the browser build it was pinned against is
# not the one present. That is a machine problem rather than a test failure,
# and it produces fifteen identical "executable doesn't exist" errors that
# look alarming, so fall back to whatever Chromium this host does have.
if [[ -z "${BKD_E2E_CHROMIUM:-}" ]]; then
    for candidate in "${PLAYWRIGHT_BROWSERS_PATH:-/opt/pw-browsers}/chromium" \
                     /usr/bin/chromium /usr/bin/chromium-browser /usr/bin/google-chrome; do
        if [[ -x "$candidate" ]]; then
            export BKD_E2E_CHROMIUM="$candidate"
            info "using Chromium at $candidate"
            break
        fi
    done
fi

info "running the browser suite"
set +e
(cd web && \
    BKD_E2E_URL="$BASE_URL" \
    BKD_E2E_SSH_HOST="127.0.0.1" \
    BKD_E2E_SSH_PORT="$SSH_PORT" \
    BKD_E2E_SSH_PORT_2="$SSH_PORT_2" \
    BKD_E2E_BASTION_PORT="$BASTION_PORT" \
    BKD_E2E_SSH_USER="$SSH_USER" \
    BKD_E2E_SSH_PASSWORD="$SSH_PASSWORD" \
    BKD_E2E_CHROMIUM="${BKD_E2E_CHROMIUM:-}" \
    BKD_E2E_SECURECRT_ZIP="$BKD_E2E_SECURECRT_ZIP" \
    BKD_E2E_PUTTY_ZIP="$BKD_E2E_PUTTY_ZIP" \
    npx playwright test "$@")
STATUS=$?
set -e

if [[ $STATUS -ne 0 ]]; then
    echo
    echo "--- server log ---" >&2
    cat "$WORKDIR/server.log" >&2
    echo "--- test ssh server logs ---" >&2
    cat "$WORKDIR/sshd.log" "$WORKDIR/sshd2.log" "$WORKDIR/bastion.log" >&2
fi

exit $STATUS

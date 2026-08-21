#!/usr/bin/env bash
#
# Upgrade a running Bridgekeeper without cutting anyone off mid-session.
#
#   cd /opt/bkd-src && git pull && make release && sudo ./deploy/upgrade.sh
#
# The old way — install and restart — killed every live terminal, which on a
# NOC means killing the people fixing the outage. This drains instead:
#
#   1. SIGUSR1 puts bkd in drain mode: existing sessions run on, reattach
#      still works, new sessions are politely refused.
#   2. /healthz reports how many terminals are still open; this script waits
#      for zero, telling you the count as it falls.
#   3. Only then does it install the new binary and restart.
#
# BKD_DRAIN_TIMEOUT_MINS (default 60) caps the wait. On timeout the script
# STOPS AND DOES NOTHING rather than restarting over live sessions — cutting
# people off should be a decision a human repeats explicitly, with
# BKD_DRAIN_FORCE=1.

set -euo pipefail

TIMEOUT_MINS="${BKD_DRAIN_TIMEOUT_MINS:-60}"
HEALTH_URL="${BKD_HEALTH_URL:-http://127.0.0.1:8443/healthz}"

die()  { echo "error: $*" >&2; exit 1; }
info() { echo "==> $*"; }

[[ $EUID -eq 0 ]] || die "run as root (sudo $0)"
[[ -f deploy/install.sh ]] || die "run from the repository root, after 'make release'"
systemctl is-active --quiet bkd || die "bkd is not running; use deploy/install.sh directly"

state() { curl -fsS --max-time 5 "$HEALTH_URL" 2>/dev/null || echo '{}'; }

# --- 1. Enter drain mode ------------------------------------------------------

if state | grep -q '"draining"'; then
    info "already draining"
else
    info "asking bkd to drain (SIGUSR1)"
    systemctl kill -s SIGUSR1 bkd
    sleep 1
    state | grep -q '"draining"' \
        || die "bkd did not enter drain mode — is this version new enough to support it?"
fi

# --- 2. Wait for the last session to end -------------------------------------

info "waiting for open sessions to finish (timeout ${TIMEOUT_MINS}m)"
deadline=$(( $(date +%s) + TIMEOUT_MINS * 60 ))
last=-1
while true; do
    open="$(state | sed -n 's/.*"open_terminals":\([0-9]*\).*/\1/p')"
    open="${open:-0}"
    if [[ "$open" -eq 0 ]]; then
        echo "    all sessions closed"
        break
    fi
    if [[ "$open" -ne "$last" ]]; then
        echo "    $open still open"
        last="$open"
    fi
    if [[ $(date +%s) -ge $deadline ]]; then
        if [[ "${BKD_DRAIN_FORCE:-0}" == "1" ]]; then
            echo "    timeout reached; BKD_DRAIN_FORCE=1 so proceeding over $open live sessions"
            break
        fi
        # Leave drain mode on: an operator who timed out is mid-upgrade and
        # should decide, not discover tomorrow that new sessions are refused.
        die "$open sessions still open after ${TIMEOUT_MINS}m. Re-run with BKD_DRAIN_FORCE=1 to cut them off, or wait and try again. (Drain mode is still on; 'systemctl kill -s SIGUSR1 bkd' toggles it off.)"
    fi
    sleep 10
done

# --- 3. Install and restart ---------------------------------------------------

info "installing the new build"
./deploy/install.sh --database sqlite

info "done"
curl -fsS --max-time 5 "$HEALTH_URL" || true

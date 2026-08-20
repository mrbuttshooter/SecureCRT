#!/usr/bin/env bash
#
# Install or upgrade Bridgekeeper (bkd) on a Linux host with systemd.
#
# Safe to re-run: it never overwrites an existing config or master key, and an
# upgrade is just "replace the binary, restart".
#
#   sudo ./deploy/install.sh                       # PostgreSQL (default)
#   sudo ./deploy/install.sh --database sqlite     # SQLite, for a small install
#
set -euo pipefail

BIN_SRC="${BIN_SRC:-bin/bkd}"
BIN_DST="/usr/local/bin/bkd"
CONF_DIR="/etc/bkd"
CONF_FILE="$CONF_DIR/config.yaml"
DATA_DIR="/var/lib/bkd"
UNIT_SRC="deploy/bkd.service"
UNIT_DST="/etc/systemd/system/bkd.service"
SERVICE_USER="bkd"
DATABASE="postgres"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --database) DATABASE="${2:-}"; shift 2 ;;
        --database=*) DATABASE="${1#*=}"; shift ;;
        -h|--help)
            sed -n '3,12p' "$0" | sed 's/^# \?//'
            exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 1 ;;
    esac
done

die()  { echo "error: $*" >&2; exit 1; }
info() { echo "==> $*"; }

[[ $EUID -eq 0 ]] || die "must run as root (try: sudo $0)"
[[ "$DATABASE" == "postgres" || "$DATABASE" == "sqlite" ]] \
    || die "--database must be 'postgres' or 'sqlite', got '$DATABASE'"
command -v systemctl >/dev/null || die "systemd is required"
[[ -f "$BIN_SRC" ]] || die "$BIN_SRC not found; run 'make build' first"
[[ -f "$UNIT_SRC" ]] || die "$UNIT_SRC not found; run this from the repository root"

# --- Service account -------------------------------------------------------
# No shell and no home directory: this account exists only to own the process
# and its data. Note that bkd holds users' decrypted SSH keys in memory, so
# anyone who can become this user can read them — keep the membership empty.
if id "$SERVICE_USER" >/dev/null 2>&1; then
    info "service user '$SERVICE_USER' already exists"
else
    info "creating service user '$SERVICE_USER'"
    useradd --system --no-create-home --home-dir "$DATA_DIR" \
            --shell /usr/sbin/nologin "$SERVICE_USER"
fi

# --- Directories -----------------------------------------------------------
info "creating directories"
install -d -m 0755 -o root            -g root            "$CONF_DIR"
install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_USER" "$DATA_DIR"
install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_USER" "$DATA_DIR/logs"
install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_USER" "$DATA_DIR/recordings"

# --- Binary ----------------------------------------------------------------
if [[ -f "$BIN_DST" ]] && systemctl is-active --quiet bkd; then
    info "stopping bkd for upgrade"
    systemctl stop bkd
    RESTART_AFTER=1
fi

info "installing binary to $BIN_DST"
install -m 0755 -o root -g root "$BIN_SRC" "$BIN_DST"

# --- Configuration ---------------------------------------------------------
if [[ -f "$CONF_FILE" ]]; then
    info "keeping existing $CONF_FILE"
else
    info "writing $CONF_FILE"
    install -m 0640 -o root -g "$SERVICE_USER" deploy/config.example.yaml "$CONF_FILE"

    if [[ "$DATABASE" == "sqlite" ]]; then
        # Switch the two commented blocks in the example config.
        sed -i \
            -e 's|^  driver: postgres|  driver: sqlite|' \
            -e 's|^  dsn: "postgres.*|  dsn: "/var/lib/bkd/bkd.db"|' \
            "$CONF_FILE"
    fi

    echo
    echo "    Edit $CONF_FILE before going live — at minimum set"
    echo "    server.external_url to the URL your users will visit."
    echo
fi

# --- Database --------------------------------------------------------------
if [[ "$DATABASE" == "postgres" ]]; then
    if command -v psql >/dev/null && id postgres >/dev/null 2>&1; then
        if su postgres -c "psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='$SERVICE_USER'\"" | grep -q 1; then
            info "postgres role '$SERVICE_USER' already exists"
        else
            info "creating postgres role '$SERVICE_USER'"
            su postgres -c "createuser $SERVICE_USER"
        fi
        if su postgres -c "psql -tAc \"SELECT 1 FROM pg_database WHERE datname='bkd'\"" | grep -q 1; then
            info "database 'bkd' already exists"
        else
            info "creating database 'bkd'"
            su postgres -c "createdb -O $SERVICE_USER bkd"
        fi
    else
        echo "    PostgreSQL client not found. Create the database yourself:"
        echo "        sudo -u postgres createuser $SERVICE_USER"
        echo "        sudo -u postgres createdb -O $SERVICE_USER bkd"
    fi
fi

# --- Master key ------------------------------------------------------------
# Generated as the service user so the 0400 file is owned by the account that
# needs to read it. Never regenerated: doing so would orphan every shared
# team credential permanently.
MASTER_KEY="$(awk '/^  master_key_path:/ {gsub(/"/,"",$2); print $2}' "$CONF_FILE")"
MASTER_KEY="${MASTER_KEY:-$DATA_DIR/master.key}"

if [[ -f "$MASTER_KEY" ]]; then
    info "master key already present at $MASTER_KEY (not touching it)"
else
    info "generating master key at $MASTER_KEY"
    su -s /bin/sh "$SERVICE_USER" -c "$BIN_DST gen-master-key --config $CONF_FILE"
    echo
    echo "    Back up $MASTER_KEY separately from the database."
    echo "    Losing it means losing every shared team credential."
    echo
fi

# --- Migrations ------------------------------------------------------------
info "applying database migrations"
su -s /bin/sh "$SERVICE_USER" -c "$BIN_DST migrate --config $CONF_FILE"

# --- Service ---------------------------------------------------------------
info "installing systemd unit"
install -m 0644 -o root -g root "$UNIT_SRC" "$UNIT_DST"
systemctl daemon-reload

if systemctl is-enabled --quiet bkd 2>/dev/null || [[ "${RESTART_AFTER:-0}" == "1" ]]; then
    info "restarting bkd"
    systemctl restart bkd
else
    info "enabling and starting bkd"
    systemctl enable --now bkd
fi

sleep 1
if systemctl is-active --quiet bkd; then
    info "bkd is running"
else
    echo
    echo "bkd failed to start. Recent log:" >&2
    journalctl -u bkd -n 30 --no-pager >&2
    exit 1
fi

cat <<EOF

Installed.

  Binary       $BIN_DST
  Config       $CONF_FILE
  Data         $DATA_DIR
  Master key   $MASTER_KEY
  Service      systemctl status bkd
  Logs         journalctl -u bkd -f

bkd listens on loopback only. Put nginx or Caddy in front of it to terminate
TLS — see deploy/nginx.conf.example.

EOF

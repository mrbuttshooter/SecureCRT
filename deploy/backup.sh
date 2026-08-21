#!/usr/bin/env bash
#
# Back up the two things a Bridgekeeper install cannot be rebuilt without:
# the database and the master key. Everything else is a redeploy.
#
#   sudo ./deploy/backup.sh /path/to/backups
#
# Run it from cron for a nightly copy. The master key is what unwraps every
# team key and every credential marked for unattended use; lose it and those
# are gone for good, so a copy that lives somewhere other than this machine is
# the difference between an incident and a catastrophe.
#
# What this does NOT protect: a user's vault passphrase, which the server
# never stores and this cannot copy. That is the design — a stolen backup of
# the database plus the master key still does not open a user's personal
# vault without their passphrase.

set -euo pipefail

DEST="${1:-/var/backups/bkd}"
DATA_DIR="${BKD_DATA_DIR:-/var/lib/bkd}"
DB="${DATA_DIR}/bkd.db"
KEY="${DATA_DIR}/master.key"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="${DEST}/bkd-${STAMP}"

die()  { echo "error: $*" >&2; exit 1; }
info() { echo "==> $*"; }

[[ $EUID -eq 0 ]] || die "run as root (sudo $0)"
[[ -f "$KEY" ]] || die "no master key at $KEY — is this the right data dir?"

mkdir -p "$OUT"
chmod 0700 "$OUT"

# The database is copied through SQLite's own backup so a snapshot taken while
# bkd is writing is still consistent — a plain cp of a live SQLite file can
# catch it mid-transaction.
if command -v sqlite3 >/dev/null; then
    info "snapshotting the database (consistent)"
    sqlite3 "$DB" ".backup '${OUT}/bkd.db'"
else
    info "sqlite3 not found; copying the database file directly (stop bkd first for a guaranteed-consistent copy)"
    cp -a "$DB" "${OUT}/bkd.db"
fi

info "copying the master key"
cp -a "$KEY" "${OUT}/master.key"
chmod 0600 "${OUT}/master.key"

info "done: ${OUT}"
echo
echo "  Copy ${OUT} OFF THIS MACHINE. A backup that only lives here dies with the disk it protects."
echo "  Prune old backups yourself; this script keeps every run."

#!/usr/bin/env bash
#
# Bare Debian/Ubuntu host → a working Bridgekeeper over real HTTPS, in one go.
#
#   curl -fsSL <this file> | sudo bash
#   # or, from a clone:
#   sudo ./deploy/quickstart.sh
#
# This is the "let me look at it" path, not the production one. It picks
# SQLite, puts Caddy in front for TLS, and creates one administrator. For a
# company-wide install use deploy/install.sh with PostgreSQL and read
# docs/SECURITY.md first.
#
# About the certificate: with only an IP address there is no domain to put on
# a certificate, and a self-signed one trains people to click through browser
# warnings. So this uses sslip.io, a public DNS service that resolves
# 159-69-214-37.sslip.io to 159.69.214.37 — a real hostname, which means a
# real Let's Encrypt certificate and no warning. Point BKD_HOSTNAME at your
# own domain instead as soon as you have one.
#
# Environment:
#   BKD_HOSTNAME   the hostname to serve (default: <your-ip>.sslip.io)
#   BKD_EMAIL      the first administrator's address (default: admin@<hostname>)
#   BKD_REF        git branch or tag to build (default: the current branch,
#                  or claude/vigilant-bell-11pf3z when run from a pipe)
#   BKD_GITHUB_TOKEN
#                  a GitHub token with read access, required while the
#                  repository is private. Without it the clone below fails
#                  with a 404 — GitHub reports a private repository as
#                  missing rather than as forbidden, so that a 404 does not
#                  itself confirm the repository exists.
#
set -euo pipefail

REPO_URL="${BKD_REPO:-https://github.com/mrbuttshooter/SecureCRT.git}"
REF="${BKD_REF:-claude/vigilant-bell-11pf3z}"
BUILD_DIR="/opt/bkd-src"

die()  { echo "error: $*" >&2; exit 1; }
info() { echo; echo "==> $*"; }

[[ $EUID -eq 0 ]] || die "run as root (sudo $0)"
command -v systemctl >/dev/null || die "systemd is required"
command -v apt-get   >/dev/null || die "this script expects Debian or Ubuntu"

# --- Where will people reach it? ---------------------------------------------

if [[ -z "${BKD_HOSTNAME:-}" ]]; then
    info "finding this host's public address"
    IP="$(curl -fsS --max-time 10 https://api.ipify.org || true)"
    [[ -n "$IP" ]] || die "could not determine the public IP; set BKD_HOSTNAME yourself"
    HOSTNAME="${IP//./-}.sslip.io"
    echo "    $IP  ->  $HOSTNAME"
else
    HOSTNAME="$BKD_HOSTNAME"
fi

EMAIL="${BKD_EMAIL:-admin@${HOSTNAME}}"
EXTERNAL_URL="https://${HOSTNAME}"

# --- Dependencies -------------------------------------------------------------

info "installing build and runtime dependencies"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl git ca-certificates debian-keyring debian-archive-keyring apt-transport-https unzip

if ! command -v caddy >/dev/null; then
    info "installing Caddy"
    curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key \
        | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt \
        | tee /etc/apt/sources.list.d/caddy-stable.list >/dev/null
    apt-get update -qq
    apt-get install -y -qq caddy
fi

# Go and Node are build-time only. Installed under /usr/local rather than from
# apt, because the distribution packages are usually several releases behind
# what this needs.
if ! /usr/local/go/bin/go version 2>/dev/null | grep -qE 'go1\.(2[5-9]|[3-9][0-9])'; then
    info "installing Go"
    GO_TARBALL="go1.25.0.linux-$(dpkg --print-architecture).tar.gz"
    curl -fsSL "https://go.dev/dl/${GO_TARBALL}" -o /tmp/go.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/go.tar.gz
    rm -f /tmp/go.tar.gz
fi
export PATH="/usr/local/go/bin:$PATH"

if ! command -v node >/dev/null || [[ "$(node -v | cut -d. -f1 | tr -d v)" -lt 22 ]]; then
    info "installing Node"
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash - >/dev/null
    apt-get install -y -qq nodejs
fi
corepack enable >/dev/null 2>&1 || npm install -g pnpm >/dev/null 2>&1

# --- Source and build ---------------------------------------------------------

if [[ -f Makefile && -d cmd/bkd ]]; then
    info "building from the current directory"
    SRC="$PWD"
else
    info "fetching the source"

    TOKEN="${BKD_GITHUB_TOKEN:-${GITHUB_TOKEN:-}}"
    if [[ -n "$TOKEN" ]]; then
        # Supplied through an askpass helper rather than in the URL. A token
        # in the clone URL is written into .git/config, where it stays on this
        # disk for as long as the checkout does, and appears in the process
        # list while git runs. This way it reaches git over a pipe and lives
        # in a file that is deleted on the way out.
        ASKPASS="$(mktemp)"
        chmod 0700 "$ASKPASS"
        printf '#!/bin/sh\ncase "$1" in *Username*) echo x-access-token ;; *) printf %%s "%s" ;; esac\n' \
            "$TOKEN" > "$ASKPASS"
        # shellcheck disable=SC2064  # $ASKPASS is expanded now, deliberately
        trap "rm -f '$ASKPASS'" EXIT
        export GIT_ASKPASS="$ASKPASS" GIT_TERMINAL_PROMPT=0
    fi

    if [[ -d "$BUILD_DIR/.git" ]]; then
        git -C "$BUILD_DIR" fetch --depth 1 origin "$REF" \
            || die "could not fetch $REF (see the note about BKD_GITHUB_TOKEN above)"
        git -C "$BUILD_DIR" checkout -f FETCH_HEAD
    else
        rm -rf "$BUILD_DIR"
        git clone --depth 1 --branch "$REF" "$REPO_URL" "$BUILD_DIR" || die \
            "could not clone $REPO_URL. If it is private, pass a GitHub token:
    export BKD_GITHUB_TOKEN=github_pat_...
  GitHub answers 404 rather than 403 for a repository you cannot see, so a
  missing token and a wrong branch look identical from here."
    fi

    # The token must not be left behind in the checkout's remote.
    git -C "$BUILD_DIR" remote set-url origin "$REPO_URL" 2>/dev/null || true
    SRC="$BUILD_DIR"
fi

info "building (a few minutes on a small box)"
cd "$SRC"
make release

# --- Install ------------------------------------------------------------------

info "installing the service"
./deploy/install.sh --database sqlite

info "pointing it at ${EXTERNAL_URL}"
sed -i -e "s|^  external_url:.*|  external_url: \"${EXTERNAL_URL}\"|" /etc/bkd/config.yaml
systemctl restart bkd

# --- TLS in front -------------------------------------------------------------

info "configuring Caddy"
cat > /etc/caddy/Caddyfile <<CADDY
# Bridgekeeper. Caddy terminates TLS and gets its own certificate; bkd itself
# listens on loopback and speaks plain HTTP to Caddy over it.
${HOSTNAME} {
	encode zstd gzip

	# The terminal is a WebSocket and file transfers stream, so the proxy
	# must not buffer either of them. Caddy handles the upgrade itself and
	# puts no timeout on a hijacked connection; flush_interval -1 is what
	# stops it collecting ordinary streamed responses into chunks first.
	reverse_proxy 127.0.0.1:8443 {
		flush_interval -1
	}
}
CADDY

caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null \
    || die "the generated Caddyfile did not validate"

systemctl restart caddy

# --- The first administrator ---------------------------------------------------

info "creating the first administrator"

# Generous entropy before stripping: base64 padding and the two awkward
# characters come out, and what is left must still be 20.
ADMIN_PASSWORD="$(head -c 48 /dev/urandom | base64 | tr -d '/+=' | head -c 20)"
[[ ${#ADMIN_PASSWORD} -eq 20 ]] || die "could not generate a password"

# Asking "does an account exist?" by reading list-users would mean matching a
# sentence written for a human — and its no-accounts message contains an
# example address, which is a trap this script fell into once already. The
# create path's own failure is the stable contract, so use that, and tell a
# duplicate apart from a real error rather than swallowing both.
if CREATE_OUTPUT="$(echo "$ADMIN_PASSWORD" | bkd admin create-user \
        --config /etc/bkd/config.yaml -email "$EMAIL" -name "Administrator" -admin 2>&1)"; then
    :
elif grep -q "already exists" <<<"$CREATE_OUTPUT"; then
    info "$EMAIL already has an account; leaving its password alone"
    ADMIN_PASSWORD=""
else
    die "creating the administrator: $CREATE_OUTPUT"
fi

# --- Done ----------------------------------------------------------------------

cat <<DONE

────────────────────────────────────────────────────────────────────
  ${EXTERNAL_URL}
────────────────────────────────────────────────────────────────────

DONE

if [[ -n "$ADMIN_PASSWORD" ]]; then
    cat <<DONE
  Sign in with

    ${EMAIL}
    ${ADMIN_PASSWORD}

  You will be asked to choose a vault passphrase on first sign-in. That is
  a different secret from the password above, and the server never stores
  it — it is what encrypts your keys and saved passwords, and nobody can
  reset it for you.

DONE
fi

cat <<DONE
  Service   systemctl status bkd caddy
  Logs      journalctl -u bkd -f
  Config    /etc/bkd/config.yaml

  The certificate takes a few seconds on first load while Caddy talks to
  Let's Encrypt. If the page does not come up, check that ports 80 and 443
  are open to the internet — Let's Encrypt needs 80 to issue.

  Back up /var/lib/bkd/master.key somewhere other than this machine.

DONE

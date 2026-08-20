#!/usr/bin/env bash
#
# Regenerate internal/portability/ppk/testdata with PuTTY's own tools.
#
# The point of these fixtures is that nothing in this repository produced
# them. A parser checked against its own encoder proves only that it agrees
# with itself, so every .ppk here comes from puttygen, and beside each one is
# puttygen's OpenSSH export of the same key — the answer the parser has to
# arrive at independently.
#
#   apt-get install putty-tools     # or the equivalent
#   ./scripts/gen-ppk-testdata.sh
#
# The matrix is two format versions by three key types, encrypted and not.
# Version 1 is deliberately absent: it was withdrawn in 1999 and the parser
# refuses it, so there is nothing to test it against.
set -euo pipefail

cd "$(dirname "$0")/.."
TESTDATA="$PWD/internal/portability/ppk/testdata"

command -v puttygen >/dev/null || {
    echo "puttygen not found; install putty-tools" >&2
    exit 1
}

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

# Must match testPassphrase in ppk_test.go.
printf 'correct horse battery staple' > "$WORKDIR/passphrase"
: > "$WORKDIR/empty"

mkdir -p "$TESTDATA"
rm -f "$TESTDATA"/*.ppk "$TESTDATA"/*.openssh "$TESTDATA"/*.pub

# generate <version> <type> <bits> <name> <encrypted?>
generate() {
    local version=$1 type=$2 bits=$3 name=$4 encrypted=${5:-}
    local args=(-t "$type")
    [[ -n "$bits" ]] && args+=(-b "$bits")

    local secret="$WORKDIR/empty"
    [[ -n "$encrypted" ]] && secret="$WORKDIR/passphrase"

    puttygen "${args[@]}" -O private --ppk-param "version=$version" \
        --new-passphrase "$secret" -o "$TESTDATA/$name.ppk" \
        -C "migrated@example.com" -q

    # Exported without a passphrase: the test compares key material, and an
    # encrypted export would only be testing puttygen's own cipher.
    puttygen "$TESTDATA/$name.ppk" --old-passphrase "$secret" \
        --new-passphrase "$WORKDIR/empty" \
        -O private-openssh -o "$TESTDATA/$name.openssh" -q

    puttygen "$TESTDATA/$name.ppk" --old-passphrase "$secret" \
        -O public-openssh -o "$TESTDATA/$name.pub" -q

    echo "  $name"
}

for version in 2 3; do
    echo "version $version:"
    generate "$version" ed25519 ""    "v${version}-ed25519"
    generate "$version" ed25519 ""    "v${version}-ed25519-enc"     encrypted
    generate "$version" rsa     2048  "v${version}-rsa"
    generate "$version" rsa     2048  "v${version}-rsa-enc"         encrypted
    generate "$version" ecdsa   256   "v${version}-ecdsa"
    generate "$version" ecdsa   384   "v${version}-ecdsa384-enc"    encrypted
done

echo
echo "wrote $(ls "$TESTDATA" | wc -l) files to internal/portability/ppk/testdata"

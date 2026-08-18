#!/usr/bin/env bash
# Download filled ethereum/execution-spec-tests state fixtures into tests/eest/.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${EEST_VERSION:-v5.4.0}"
CACHE="$ROOT/tests/eest/.cache"
OUT="$ROOT/tests/eest/state_tests"
TARBALL="$CACHE/fixtures_develop.tar.gz"
URL="https://github.com/ethereum/execution-spec-tests/releases/download/${VERSION}/fixtures_develop.tar.gz"
STAGING="$CACHE/extract"

mkdir -p "$CACHE"

if [[ ! -f "$TARBALL" ]]; then
    echo "downloading ${URL}"
    curl -L --fail --progress-bar -o "$TARBALL" "$URL"
else
    echo "using cached ${TARBALL}"
fi

rm -rf "$STAGING" "$OUT"
mkdir -p "$STAGING"

if [[ "${1:-}" == "--all" ]]; then
    echo "extracting all state_tests"
    tar -xzf "$TARBALL" -C "$STAGING" fixtures/state_tests
else
    echo "extracting smoke subset (pass --all for every state_test)"
    tar -xzf "$TARBALL" -C "$STAGING" --wildcards \
        'fixtures/state_tests/osaka/eip7939_count_leading_zeros/*' \
        'fixtures/state_tests/prague/eip7702_set_code_tx/*' \
        'fixtures/state_tests/shanghai/eip3855_push0/*' \
        'fixtures/state_tests/cancun/eip1153_tstore/*' \
        'fixtures/state_tests/cancun/eip5656_mcopy/*'
fi

mkdir -p "$(dirname "$OUT")"
mv "$STAGING/fixtures/state_tests" "$OUT"
rm -rf "$STAGING"

echo "fixtures ready at ${OUT}"
find "$OUT" -name '*.json' | wc -l | awk '{print $1 " json files"}'

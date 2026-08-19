#!/usr/bin/env bash
# Download filled ethereum/execution-spec-tests fixtures into tests/eest/.
#
# Default is every state_test. Osaka uses EIP-6780 SELFDESTRUCT; Shanghai
# (pre-Cancun) posts for those tests are skipped by the runner.
#
#   --smoke        small state_test subset (and a tiny blockchain subset)
#   --blockchain   also extract fixtures/blockchain_tests
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${EEST_VERSION:-v5.4.0}"
CACHE="$ROOT/tests/eest/.cache"
STATE_OUT="$ROOT/tests/eest/state_tests"
CHAIN_OUT="$ROOT/tests/eest/blockchain_tests"
TARBALL="$CACHE/fixtures_develop.tar.gz"
URL="https://github.com/ethereum/execution-spec-tests/releases/download/${VERSION}/fixtures_develop.tar.gz"
STAGING="$CACHE/extract"

SMOKE=0
BLOCKCHAIN=0
for arg in "$@"; do
    case "$arg" in
        --smoke) SMOKE=1 ;;
        --blockchain) BLOCKCHAIN=1 ;;
        *)
            echo "unknown argument: ${arg}" >&2
            exit 1
            ;;
    esac
done

mkdir -p "$CACHE"

if [[ ! -f "$TARBALL" ]]; then
    echo "downloading ${URL}"
    curl -L --fail --progress-bar -o "$TARBALL" "$URL"
else
    echo "using cached ${TARBALL}"
fi

rm -rf "$STAGING"
mkdir -p "$STAGING"

if [[ "$SMOKE" -eq 1 ]]; then
    echo "extracting smoke subset (omit --smoke for every state_test)"
    tar -xzf "$TARBALL" -C "$STAGING" --wildcards \
        'fixtures/state_tests/osaka/eip7939_count_leading_zeros/*' \
        'fixtures/state_tests/prague/eip7702_set_code_tx/*' \
        'fixtures/state_tests/shanghai/eip3855_push0/*' \
        'fixtures/state_tests/cancun/eip1153_tstore/*' \
        'fixtures/state_tests/cancun/eip5656_mcopy/*' \
        'fixtures/state_tests/cancun/eip6780_selfdestruct/*'
    if [[ "$BLOCKCHAIN" -eq 1 ]]; then
        tar -xzf "$TARBALL" -C "$STAGING" --wildcards \
            'fixtures/blockchain_tests/osaka/eip7939_count_leading_zeros/*' \
            'fixtures/blockchain_tests/shanghai/eip3855_push0/*'
    fi
else
    echo "extracting all state_tests"
    tar -xzf "$TARBALL" -C "$STAGING" fixtures/state_tests
    if [[ "$BLOCKCHAIN" -eq 1 ]]; then
        echo "extracting all blockchain_tests"
        tar -xzf "$TARBALL" -C "$STAGING" fixtures/blockchain_tests
    fi
fi

mkdir -p "$(dirname "$STATE_OUT")"
rm -rf "$STATE_OUT"
mv "$STAGING/fixtures/state_tests" "$STATE_OUT"
echo "fixtures ready at ${STATE_OUT}"
find "$STATE_OUT" -name '*.json' | wc -l | awk '{print $1 " state_test json files"}'

if [[ "$BLOCKCHAIN" -eq 1 ]]; then
    rm -rf "$CHAIN_OUT"
    mv "$STAGING/fixtures/blockchain_tests" "$CHAIN_OUT"
    echo "fixtures ready at ${CHAIN_OUT}"
    find "$CHAIN_OUT" -name '*.json' | wc -l | awk '{print $1 " blockchain_test json files"}'
fi

rm -rf "$STAGING"

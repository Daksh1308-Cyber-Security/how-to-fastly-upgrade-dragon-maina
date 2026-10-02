#!/usr/bin/env bash
# Fetch an optional memory image for real Volatility analysis.
#
# OPERATOR-INITIATED ONLY. This script is never called automatically, by the
# engine, by the tests, or by any playbook action. See AGENTS.md section 2.3:
# capturing memory from a live host is forbidden. This fetches a *pre-existing
# public test image* and nothing else.
#
# Without an image the project uses the recorded plugin output in
# fixtures/volatility/ instead, which is the default and what the tests use.
#
# Usage:
#   bash scripts/fetch_memory_image.sh
#   bash scripts/fetch_memory_image.sh --url <direct-link>

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="${REPO_ROOT}/fixtures/memory"

# Public memory images published by the Volatility Foundation for testing.
# Overridable so a different (still public, still safe) sample can be used.
URL="${VOLATILITY_SAMPLE_URL:-https://github.com/volatilityfoundation/volatility3-test-data/releases/download/v0.0.1/memtest.vmem}"

if [[ "${1:-}" == "--url" ]]; then
  URL="${2:?--url requires a direct link}"
fi

echo "Volatility memory image fetcher"
echo "  destination : ${DEST}"
echo "  url         : ${URL}"
echo

if [[ ! -f "${REPO_ROOT}/.gitignore" ]]; then
  echo "ERROR: .gitignore is missing. Create it before downloading." >&2
  echo "       fixtures/memory/ must be ignored before any download (AGENTS.md 2.5)." >&2
  exit 1
fi

if ! grep -q 'fixtures/memory/' "${REPO_ROOT}/.gitignore"; then
  echo "ERROR: fixtures/memory/ is not listed in .gitignore." >&2
  echo "       Refusing to download an image that could be committed." >&2
  exit 1
fi

echo "OK: .gitignore covers fixtures/memory/"
echo

mkdir -p "${DEST}"
FILENAME="$(basename "${URL}")"
TARGET="${DEST}/${FILENAME}"

if [[ -f "${TARGET}" ]]; then
  echo "Already present: ${TARGET}"
  echo "Delete it first if you want to re-fetch."
  exit 0
fi

echo "Downloading (this may be large -- images are commonly 100 MB to 1 GB+)..."
curl --fail --location --progress-bar --output "${TARGET}" "${URL}"

echo
echo "Downloaded: ${TARGET}"
echo "Size      : $(du -h "${TARGET}" | cut -f1)"
echo
echo "Verify the image before trusting it:"
echo "  sha256sum ${TARGET}"
echo
echo "The engine will now prefer this live image over the recorded fixtures."
echo "To go back to recorded fixtures, delete ${TARGET}."
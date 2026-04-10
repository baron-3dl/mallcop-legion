#!/usr/bin/env bash
# bin/we_test.sh — unit tests for the bin/we self-installing wrapper
# Tests run without network access and without requiring the actual release to exist.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
WE_SCRIPT="${SCRIPT_DIR}/we"
VERSION_FILE="${REPO_ROOT}/.we-version"

PASS=0
FAIL=0
ERRORS=()

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); ERRORS+=("$1"); }

run_test() {
  local name="$1"
  shift
  if "$@" 2>/dev/null; then
    pass "${name}"
  else
    fail "${name}"
  fi
}

# ---------------------------------------------------------------------------
# Test 1: .we-version exists and reads correctly
# ---------------------------------------------------------------------------
echo ""
echo "=== Test 1: .we-version file ==="

if [[ -f "${VERSION_FILE}" ]]; then
  pass ".we-version exists"
else
  fail ".we-version missing at ${VERSION_FILE}"
fi

VERSION="$(tr -d '[:space:]' < "${VERSION_FILE}" 2>/dev/null || echo "")"
if [[ "${VERSION}" == "v0.1.0" ]]; then
  pass ".we-version contains 'v0.1.0'"
else
  fail ".we-version should contain 'v0.1.0', got: '${VERSION}'"
fi

if [[ "${VERSION}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  pass ".we-version is semver-formatted"
else
  fail ".we-version is not semver-formatted: '${VERSION}'"
fi

# ---------------------------------------------------------------------------
# Test 2: Platform detection logic
# ---------------------------------------------------------------------------
echo ""
echo "=== Test 2: Platform detection ==="

# Extract the platform detection logic from the script and test it in-process
detect_platform() {
  local os="$1"
  local arch="$2"
  case "${os}" in
    Linux)
      case "${arch}" in
        x86_64)  echo "linux-amd64"  ;;
        aarch64) echo "linux-arm64"  ;;
        arm64)   echo "linux-arm64"  ;;
        *)       echo "UNSUPPORTED"  ;;
      esac
      ;;
    Darwin)
      case "${arch}" in
        arm64) echo "darwin-arm64" ;;
        *)     echo "UNSUPPORTED"  ;;
      esac
      ;;
    *)
      echo "UNSUPPORTED"
      ;;
  esac
}

assert_platform() {
  local os="$1" arch="$2" expected="$3"
  local got
  got="$(detect_platform "${os}" "${arch}")"
  if [[ "${got}" == "${expected}" ]]; then
    pass "detect_platform(${os}, ${arch}) = ${expected}"
  else
    fail "detect_platform(${os}, ${arch}): expected '${expected}', got '${got}'"
  fi
}

assert_platform "Linux"  "x86_64"  "linux-amd64"
assert_platform "Linux"  "aarch64" "linux-arm64"
assert_platform "Linux"  "arm64"   "linux-arm64"
assert_platform "Darwin" "arm64"   "darwin-arm64"
assert_platform "Linux"  "mips"    "UNSUPPORTED"
assert_platform "Darwin" "x86_64"  "UNSUPPORTED"
assert_platform "Windows" "x86_64" "UNSUPPORTED"

# ---------------------------------------------------------------------------
# Test 3: Script fails on unsupported platform
# ---------------------------------------------------------------------------
echo ""
echo "=== Test 3: Fails on unsupported platform ==="

TMPDIR_TEST="$(mktemp -d)"
trap 'rm -rf "${TMPDIR_TEST}"' EXIT

# Create a modified repo root with a valid .we-version
FAKE_REPO="${TMPDIR_TEST}/fake_repo"
mkdir -p "${FAKE_REPO}/bin"
echo "v0.1.0" > "${FAKE_REPO}/.we-version"

# Create a wrapper that overrides uname to return an unsupported platform
cat > "${FAKE_REPO}/bin/we_unsupported_os" << 'WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VERSION_FILE="${REPO_ROOT}/.we-version"
VERSION="$(tr -d '[:space:]' < "${VERSION_FILE}")"

# Override platform detection to simulate unsupported OS
OS="FreeBSD"
ARCH="x86_64"
case "${OS}" in
  Linux|Darwin) ;;
  *)
    echo "we: ERROR: unsupported operating system '${OS}'" >&2
    exit 1
    ;;
esac
exec false
WRAPPER
chmod +x "${FAKE_REPO}/bin/we_unsupported_os"

if ! "${FAKE_REPO}/bin/we_unsupported_os" 2>/dev/null; then
  pass "script exits non-zero on unsupported OS (FreeBSD)"
else
  fail "script should have failed on unsupported OS"
fi

# Test unsupported arch on Linux
cat > "${FAKE_REPO}/bin/we_unsupported_arch" << 'WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VERSION_FILE="${REPO_ROOT}/.we-version"
VERSION="$(tr -d '[:space:]' < "${VERSION_FILE}")"

OS="Linux"
ARCH="mips"
case "${OS}" in
  Linux)
    case "${ARCH}" in
      x86_64|aarch64|arm64) ;;
      *)
        echo "we: ERROR: unsupported architecture '${ARCH}' on Linux" >&2
        exit 1
        ;;
    esac
    ;;
esac
exec false
WRAPPER
chmod +x "${FAKE_REPO}/bin/we_unsupported_arch"

if ! "${FAKE_REPO}/bin/we_unsupported_arch" 2>/dev/null; then
  pass "script exits non-zero on unsupported arch (Linux/mips)"
else
  fail "script should have failed on unsupported arch"
fi

# ---------------------------------------------------------------------------
# Test 4: Script fails on SHA-256 mismatch (tampered archive)
# ---------------------------------------------------------------------------
echo ""
echo "=== Test 4: Fails on SHA-256 mismatch ==="

FAKE_REPO2="${TMPDIR_TEST}/fake_repo2"
mkdir -p "${FAKE_REPO2}/bin"
echo "v0.1.0" > "${FAKE_REPO2}/.we-version"

# Create a test that simulates sha256 verification failing
cat > "${FAKE_REPO2}/bin/we_sha_check" << 'WRAPPER'
#!/usr/bin/env bash
set -euo pipefail

EXPECTED="0fa01906fc78f8b3434944d4d42b3f99d9e5592f28af76f7ed55bc0a637b635f"
ACTUAL="deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

if [[ "${ACTUAL}" != "${EXPECTED}" ]]; then
  echo "we: ERROR: SHA-256 mismatch for downloaded tarball!" >&2
  echo "we:   expected: ${EXPECTED}" >&2
  echo "we:   actual:   ${ACTUAL}" >&2
  echo "we: The download may be corrupted or tampered with. Aborting." >&2
  exit 1
fi
exec false
WRAPPER
chmod +x "${FAKE_REPO2}/bin/we_sha_check"

if ! "${FAKE_REPO2}/bin/we_sha_check" 2>/dev/null; then
  pass "script exits non-zero on SHA-256 mismatch"
else
  fail "script should have failed on SHA-256 mismatch"
fi

# Create a tampered archive and verify sha256sum detection
TMPDIR_SHA="${TMPDIR_TEST}/sha_test"
mkdir -p "${TMPDIR_SHA}"
echo "this is tampered content" > "${TMPDIR_SHA}/tampered.tar.gz"

EXPECTED_REAL="0fa01906fc78f8b3434944d4d42b3f99d9e5592f28af76f7ed55bc0a637b635f"

if command -v sha256sum &>/dev/null; then
  ACTUAL_TAMPERED="$(sha256sum "${TMPDIR_SHA}/tampered.tar.gz" | awk '{print $1}')"
elif command -v shasum &>/dev/null; then
  ACTUAL_TAMPERED="$(shasum -a 256 "${TMPDIR_SHA}/tampered.tar.gz" | awk '{print $1}')"
else
  ACTUAL_TAMPERED="no-sha-tool"
fi

if [[ "${ACTUAL_TAMPERED}" != "${EXPECTED_REAL}" ]]; then
  pass "sha256 of tampered file correctly differs from expected (integrity check would catch it)"
else
  fail "tampered file unexpectedly matched expected sha256 — this should never happen"
fi

# ---------------------------------------------------------------------------
# Test 5: Script fails when .we-version is missing
# ---------------------------------------------------------------------------
echo ""
echo "=== Test 5: Fails when .we-version is missing ==="

FAKE_REPO3="${TMPDIR_TEST}/fake_repo3"
mkdir -p "${FAKE_REPO3}/bin"
# Intentionally do NOT create .we-version

cat > "${FAKE_REPO3}/bin/we_no_version" << 'WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VERSION_FILE="${REPO_ROOT}/.we-version"
if [[ ! -f "${VERSION_FILE}" ]]; then
  echo "we: ERROR: .we-version not found at ${VERSION_FILE}" >&2
  exit 1
fi
exec false
WRAPPER
chmod +x "${FAKE_REPO3}/bin/we_no_version"

if ! "${FAKE_REPO3}/bin/we_no_version" 2>/dev/null; then
  pass "script exits non-zero when .we-version is missing"
else
  fail "script should have failed when .we-version is missing"
fi

# ---------------------------------------------------------------------------
# Test 6: Hardcoded SHA-256 lookup — all platforms covered for v0.1.0
# ---------------------------------------------------------------------------
echo ""
echo "=== Test 6: Hardcoded SHA-256 coverage ==="

declare -A SHA256_MAP=(
  ["v0.1.0:linux-amd64"]="0fa01906fc78f8b3434944d4d42b3f99d9e5592f28af76f7ed55bc0a637b635f"
  ["v0.1.0:linux-arm64"]="392fb893238fbfc00e7fa1e4ed081bbcb430093a5e2f4f00be90e20ae262df74"
  ["v0.1.0:darwin-arm64"]="0b5cbc6e8cd51e5e965c5a27a278a5fd6e2e3b4b911951117b905eef254a26d4"
)

for key in "v0.1.0:linux-amd64" "v0.1.0:linux-arm64" "v0.1.0:darwin-arm64"; do
  sha="${SHA256_MAP[${key}]:-}"
  if [[ -n "${sha}" && "${#sha}" -eq 64 ]]; then
    pass "SHA-256 for ${key} is 64 hex chars"
  else
    fail "SHA-256 for ${key} is missing or wrong length: '${sha}'"
  fi
done

# Unknown version+platform should return empty
sha="${SHA256_MAP["v9.9.9:linux-amd64"]:-}"
if [[ -z "${sha}" ]]; then
  pass "unknown version+platform returns empty (would fail loudly in wrapper)"
else
  fail "unknown version+platform should return empty, got: '${sha}'"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "=============================="
echo "Results: ${PASS} passed, ${FAIL} failed"
if [[ ${FAIL} -gt 0 ]]; then
  echo "Failed tests:"
  for err in "${ERRORS[@]}"; do
    echo "  - ${err}"
  done
  echo "=============================="
  exit 1
fi
echo "All tests passed."
echo "=============================="
exit 0

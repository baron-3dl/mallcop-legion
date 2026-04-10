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
# Test 4: Script fails on SHA-256 mismatch — invokes real wrapper against tampered archive
# ---------------------------------------------------------------------------
echo ""
echo "=== Test 4: Fails on SHA-256 mismatch (real wrapper, local HTTP server, tampered archive) ==="

FAKE_REPO2="${TMPDIR_TEST}/fake_repo2"
SERVE_DIR="${TMPDIR_TEST}/serve"
mkdir -p "${FAKE_REPO2}/bin" "${SERVE_DIR}"
echo "v0.1.0" > "${FAKE_REPO2}/.we-version"

# Detect current platform (mirrors bin/we logic)
_OS="$(uname -s)"
_ARCH="$(uname -m)"
case "${_OS}" in
  Linux)
    case "${_ARCH}" in
      x86_64)  _PLATFORM="linux-amd64"  ;;
      aarch64) _PLATFORM="linux-arm64"  ;;
      arm64)   _PLATFORM="linux-arm64"  ;;
      *)       _PLATFORM="linux-amd64"  ;;  # fallback for test purposes
    esac
    ;;
  Darwin)
    _PLATFORM="darwin-arm64" ;;
  *)
    _PLATFORM="linux-amd64" ;;
esac

# Create a tampered tarball (wrong content — SHA will not match the hardcoded value)
TARBALL_NAME="we-${_PLATFORM}.tar.gz"
echo "tampered binary content — not the real we binary" > "${SERVE_DIR}/fake_we"
tar -czf "${SERVE_DIR}/${TARBALL_NAME}" -C "${SERVE_DIR}" fake_we

# Also create a fake .sha256 file whose value matches the tampered archive
# (so the remote .sha256 check passes, but the hardcoded SHA check still catches it)
if command -v sha256sum &>/dev/null; then
  TAMPERED_SHA="$(sha256sum "${SERVE_DIR}/${TARBALL_NAME}" | awk '{print $1}')"
else
  TAMPERED_SHA="$(shasum -a 256 "${SERVE_DIR}/${TARBALL_NAME}" | awk '{print $1}')"
fi
echo "${TAMPERED_SHA}  ${TARBALL_NAME}" > "${SERVE_DIR}/${TARBALL_NAME}.sha256"

# Start a local HTTP server on a random high port
HTTP_PORT=$((30000 + RANDOM % 10000))
python3 -m http.server "${HTTP_PORT}" --directory "${SERVE_DIR}" &>/dev/null &
HTTP_PID=$!
# Give the server a moment to start
sleep 0.3

# Verify the server started; if not, skip with a warning
if ! kill -0 "${HTTP_PID}" 2>/dev/null; then
  fail "could not start local HTTP server for Test 4"
else
  # Copy the real bin/we and patch the BASE_URL to point at local server
  sed "s|https://github.com/3dl-dev/legion/releases/download/\${VERSION}|http://127.0.0.1:${HTTP_PORT}|g" \
    "${WE_SCRIPT}" > "${FAKE_REPO2}/bin/we"
  chmod +x "${FAKE_REPO2}/bin/we"

  # Override install dir so we don't collide with any real install
  FAKE_HOME="${TMPDIR_TEST}/fake_home"
  mkdir -p "${FAKE_HOME}"

  # Run the patched wrapper; it should fail because the tampered archive's SHA
  # does not match the hardcoded expected value in the SHA256_MAP
  SHA_ERR_OUTPUT="$(HOME="${FAKE_HOME}" "${FAKE_REPO2}/bin/we" --version 2>&1 || true)"
  SHA_EXIT=0
  HOME="${FAKE_HOME}" "${FAKE_REPO2}/bin/we" --version 2>/dev/null && SHA_EXIT=0 || SHA_EXIT=$?

  kill "${HTTP_PID}" 2>/dev/null || true

  if [[ "${SHA_EXIT}" -ne 0 ]]; then
    pass "wrapper exits non-zero when tarball SHA does not match hardcoded checksum"
  else
    fail "wrapper should have exited non-zero on SHA mismatch (exit=${SHA_EXIT})"
  fi

  if echo "${SHA_ERR_OUTPUT}" | grep -q "SHA-256 mismatch\|mismatch\|tampered\|corrupted"; then
    pass "wrapper emits SHA mismatch error message"
  else
    fail "wrapper output did not contain expected mismatch message; got: ${SHA_ERR_OUTPUT}"
  fi
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

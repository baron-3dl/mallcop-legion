#!/usr/bin/env bash
# start-mallcop.sh — Boot the mallcop operator automaton.
#
# Usage:
#   MALLCOP_INSTANCE=prod ./scripts/start-mallcop.sh
#
# Environment:
#   MALLCOP_INSTANCE  — automaton instance name (default: hostname)
#   FORGE_API_URL     — Forge API base URL (required)
#   FORGE_API_KEY     — Forge API key (required)
#   OPERATOR_CAMPFIRE_ID — operator campfire ID (required)
#   MODEL_STRONG      — strong model name (default: claude-opus-4-5)
#   TOOL_BIN_DIR      — tool binary directory (default: dir containing this script/../bin)
#   FIXTURE_DIR       — fixture directory override (default: exams/fixtures/operational)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

exec "${REPO_ROOT}/bin/we" start \
  --chart "${REPO_ROOT}/charts/mallcop-automaton.toml.tmpl" \
  --instance "${MALLCOP_INSTANCE:-$(hostname)}"

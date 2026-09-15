#!/usr/bin/env bash
#
# Monthly organization-wide dependency license check.
#
#   ./run-monthly.sh --org my-org              # scan the org, write reports
#   ./run-monthly.sh --demo                    # offline run against the fixture
#   ./run-monthly.sh --org my-org --jira       # also file Jira tickets
#   ./run-monthly.sh --org my-org --fail-on never
#
# Credentials (one of):
#   GITHUB_TOKEN                  a PAT or an installation token
#   APP_ID + APP_PRIVATE_KEY      GitHub App credentials (needs openssl)
#
# Exit codes: 0 clean, 1 run failed, 2 policy failure (findings at --fail-on).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${PYTHON:-python3}"

if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "error: $PYTHON not found. Install Python 3.8+ or set PYTHON=/path/to/python3" >&2
  exit 1
fi

args=()
demo=false
for arg in "$@"; do
  if [[ "$arg" == "--demo" ]]; then
    demo=true
  else
    args+=("$arg")
  fi
done

if [[ "$demo" == true ]]; then
  echo "Demo run against tests/fixtures/sample-report.json (no API calls)."
  args+=(--org my-org --from-report "$HERE/tests/fixtures/sample-report.json")
fi

exec "$PYTHON" "$HERE/scripts/license_check.py" "${args[@]}"

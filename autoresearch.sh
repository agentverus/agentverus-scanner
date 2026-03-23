#!/usr/bin/env bash
set -euo pipefail

pnpm build:actions
pnpm release:preflight
pnpm test --reporter=dot 2>&1 | tail -3
TEST_EXIT=${PIPESTATUS[0]}
if [ "$TEST_EXIT" -ne 0 ]; then
  echo "METRIC release_guard_signals=0"
  echo "METRIC current_release_pass=0"
  echo "METRIC test_pass=0"
  exit 1
fi

echo "METRIC test_pass=1"
pnpm lint
npx tsx scripts/benchmark-release-hardening.mts

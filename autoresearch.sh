#!/usr/bin/env bash
set -euo pipefail

# Fast pre-check: typecheck
pnpm typecheck --pretty false 2>&1 | tail -1
if [ "${PIPESTATUS[0]}" -ne 0 ]; then
  echo "METRIC score_gap=0"
  echo "METRIC test_pass=0"
  exit 1
fi

# Run tests
pnpm test --reporter=dot 2>&1 | tail -3
TEST_EXIT=${PIPESTATUS[0]}
if [ "$TEST_EXIT" -ne 0 ]; then
  echo "METRIC score_gap=0"
  echo "METRIC test_pass=0"
  exit 1
fi
echo "METRIC test_pass=1"

# Run the score separation benchmark
npx tsx scripts/benchmark-score-separation.mts

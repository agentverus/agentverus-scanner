#!/usr/bin/env bash
set -euo pipefail

pnpm exec tsc --noEmit --pretty false >/dev/null
pnpm exec tsx scripts/benchmark-auth-profile-dedup.mts

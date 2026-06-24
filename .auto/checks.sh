#!/bin/bash
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Guardrail: existing product tests must still pass.
npx vitest run 2>&1 | tail -20

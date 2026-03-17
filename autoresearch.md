# Autoresearch: reduce false positives on safe skill fixtures

## Objective
Reduce medium+ findings on safe/benign skill fixtures without weakening detection on genuinely malicious skills. The scanner currently flags educational code examples, safety-section negations, and documentation references as threats, penalizing skills that are clearly safe.

Key false positive sources observed in the current baseline:
- **`evasion-context-safe.md`** (Security Educator): scores 83 with 9 medium+ findings. Attack patterns inside a fenced code block under "Common Attack Patterns (Educational Examples)" heading are still flagged heavily despite being clearly educational.
- **`legit-security-skill.md`** (skill-scanner): gets 2 high findings from "access credentials" and "execute" appearing in a threat-detection documentation table.
- **`legit-curl-install.md`** (deno-deploy): gets 3 medium+ findings for a standard `curl | sh` installer under a Prerequisites heading.
- **`evasion-negation-safe.md`** (Secure File Manager): gets 4 medium+ findings including false triggers on negated safety rules like "Must not automatically delete".
- **`config-tampering-safe.md`**: gets 3 medium+ findings from listing config files (like `~/.ssh/config`) as *targets of adversarial tampering*, not as things the skill accesses.

## Metrics
- **Primary**: `safe_fixture_medium_plus` (count of medium+high+critical findings across all safe fixtures, lower is better)
- **Secondary**: `safe_fixture_score_min` (minimum score across safe fixtures — higher is better), `malicious_score_max` (maximum score across malicious fixtures — lower is better to preserve separation), `safe_fixture_regressions` (count of safe fixtures scoring below 90), `test_pass` (1 if tests pass, 0 if not)

## How to Run
`./autoresearch.sh` — outputs `METRIC name=number` lines.

## Files in Scope
- `src/scanner/analyzers/context.ts` — context detection (code blocks, safety sections, negation, threat-listing). **Primary optimization target.**
- `src/scanner/analyzers/injection.ts` — injection pattern analyzer. Uses context.ts for adjustments.
- `src/scanner/analyzers/behavioral.ts` — behavioral pattern analyzer. Uses context.ts for adjustments.
- `src/scanner/analyzers/permissions.ts` — permission analysis.
- `src/scanner/analyzers/capability-contract.ts` — capability contract mismatch detection. Uses `firstPositiveMatch` which respects context.
- `src/scanner/analyzers/code-safety.ts` — code safety patterns (curl pipe to sh etc).
- `src/scanner/analyzers/content.ts` — content analysis.
- `src/scanner/scoring.ts` — score aggregation and report shaping.
- `test/fixtures/skills/*.md` — safe and malicious fixture files (read-only for analysis, do not modify).
- `test/scanner/*.test.ts` — test files (must continue passing).

## Off Limits
- Do NOT modify test fixture files to game the metric
- Do NOT weaken detection on genuinely malicious skills (monitor `malicious_score_max`)
- Do NOT remove ASST categories or finding types entirely
- npm dependencies

## Constraints
- `pnpm test` must pass before keeping any change
- No new runtime dependencies
- Scanner must remain deterministic
- `malicious_score_max` must stay at or below baseline — malicious skills must not get higher scores
- Badge logic must remain intact

## What's Been Tried
(Will be updated as experiments accumulate)

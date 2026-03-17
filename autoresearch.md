# Autoresearch: reduce false positives and widen score separation

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

### Experiment 1: Expand negation detection + security-education skill classification (22→13)
- Fixed `isPrecededByNegation` to catch "does not", "doesn't", "isn't", "aren't", etc.
- Expanded `isSecurityDefenseSkill` to catch educational skills ("teach/learn about security/vulnerabilities")
- `evasion-context-safe.md` went from 83/suspicious to 97/certified
- `legit-security-skill.md` went from 94/conditional to 99/certified

### Experiment 2: Skip capability inferences in safety sections + wider negation window (13→11)
- Capability contract now skips matches inside safety boundary sections
- Negation window expanded from 0 to 3 words gap (catches "Should not execute shell commands")
- `evasion-negation-safe.md` exec and payment_processing inferences eliminated

### Experiment 3: Suppress findings in safety sections with line-level negation (11→10)
- `adjustForContext` now checks if the full line in a safety section contains negation language
- "Must not automatically delete or modify files without user confirmation" no longer triggers "autonomous action"

### Experiment 4: Fix defense skill detection for config-tampering (10→7)
- Fixed regex trailing `\b` on prefix-words like "tamper" (didn't match "tampering")
- Added "Safe operating rules" / "Refusal pattern" to safety section headings
- `config-tampering-safe.md` went from 92/conditional to 99/certified

### Experiment 5: Known installer domains in code-safety + URL inference for defense skills (7→6)
- Code-safety analyzer now recognizes known installer domains (deno.land, bun.sh, etc.) and reduces deduction
- URL-based network inference suppressed for defense/educational skills
- `legit-curl-install.md` code-safety deduction went from 20 to 7

### Experiment 6: Suppress code-safety in example blocks for defense skills (6→5)
- Defense/educational skills with `isExample` code blocks: fully suppress code-safety findings
- `evasion-context-safe.md` went from 98 to 99/certified with 0 medium+ findings

### Current state (5 remaining)
All 5 remaining findings are TRUE POSITIVES:
- safe-basic: `network_restricted` permission declared in frontmatter (1)
- legit-curl-install: curl|sh installer genuinely uses exec/network + code-safety (3)
- evasion-negation-safe: `file_write` permission declared in frontmatter (1)

### Score summary (false positive reduction)
| Fixture | Before | After |
|---------|--------|-------|
| safe-basic | 98 | 98 |
| safe-complex | 99 | 99 |
| legit-security-skill | 94 | 99 |
| legit-curl-install | 92 | 94 |
| evasion-negation-safe | 92 | 98 |
| evasion-context-safe | 83 | 99 |
| config-tampering-safe | 92 | 99 |

## Score Separation (Goal 2)

### Experiment 7: Cross-category severity penalty (gap 16→45)
- Added penalty of 8 per critical + 3 per high finding (capped at 50)
- This prevents concentrated attacks in one category from being diluted by clean scores in other categories
- `excessive-permissions` went 78→28, `malicious-injection` went 69→19

### Experiment 8: Worst-category drag (gap 45→71)
- When any category scores below 60, apply additional penalty proportional to how far below
- Scale: (60 - min_score) / 2 points penalty
- This prevents a skill from being "almost clean" when it spectacularly fails in one area
- `obfuscated-skill` (content=15) went from 43 to 20
- Threshold=60 chosen as sweet spot — threshold=70 crushes too many to 0

### Score summary (after both goals)
| Fixture | Original | After FP reduction | After scoring |
|---------|----------|-------------------|---------------|
| safe-basic | 98 | 98 | 98 |
| safe-complex | 99 | 99 | 99 |
| legit-security-skill | 94 | 99 | 99 |
| legit-curl-install | 92 | 94 | 91 |
| evasion-negation-safe | 92 | 98 | 98 |
| evasion-context-safe | 83 | 99 | 99 |
| config-tampering-safe | 92 | 99 | 99 |
| malicious-injection | 69 | 69 | 0 |
| malicious-exfiltration | 55 | 55 | 0 |
| concealment-skill | 62 | 62 | 14 |
| obfuscated-skill | 71 | 71 | 20 |
| excessive-permissions | 78 | 78 | 0 |
| **Gap** | **16** | **16** | **71** |

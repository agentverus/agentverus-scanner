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

## Evasion Detection Coverage (Goal 3)

### Experiment 9: URL-parameter exfiltration + fake defense-skill detection (92→75)
- Added "URL-parameter data exfiltration" pattern for encode-into-URL attacks
- Added "Comprehensive secret collection" pattern for "all tokens, keys, secrets"
- Added anti-abuse check: skills claiming to be security tools but with real credential access + exfil → not defense skill
- `evasion-indirect-exfiltration` went 92/certified → 12/rejected
- `evasion-fake-security-skill` went 78/conditional → 12/rejected

### Experiment 10: Exfiltration pattern immunity + suspicious URL boost (75→70)
- Made exfiltration/secret-collection patterns immune to threat-listing context reduction
- Suspicious URLs in curl|sh (raw IP, non-HTTPS, unknown TLD) no longer get code-block severity reduction in behavioral analyzer

### Experiment 11: Suspicious TLD in curl|sh → critical in code-safety (70→63→62)
- curl|sh to `.xyz`, `.top`, `.buzz` etc. elevated to critical severity (deduction=30)
- Dependencies analyzer elevates deduction for high-abuse TLDs
- Added suspicious download-and-execute injection pattern with full severity override

### Experiment 12: Distinct critical curl|sh targets across blocks (62→40→29)
- Code-safety keeps separate critical findings for different suspicious curl|sh targets
- `evasion-curl-setup-section` (2 curl|sh to evil domain + raw IP) went 62 → 1
- Added injection pattern for curl/wget to raw IPs or suspicious TLDs with code-block override

### Final evasion scores
| Fixture | Before | After |
|---------|--------|-------|
| evasion-indirect-exfiltration | 92 (certified!) | 12 (rejected) |
| evasion-fake-security-skill | 78 (conditional) | 12 (rejected) |
| evasion-curl-setup-section | 75 (suspicious) | 1 (rejected) |
| evasion-hidden-in-codeblock | 29 (rejected) | 29 (rejected) |
| evasion-negation-disguise | 43 (rejected) | 22 (rejected) |
| evasion-threat-table-injection | 24 (rejected) | 24 (rejected) |
| evasion-rephrased-jailbreak | 2 (rejected) | 2 (rejected) |
| concealment-skill | 14 (rejected) | 0 (rejected) |
| **Max evasion score** | **92** | **12** |
| **Gap (safe_min - evasion_max)** | **-1** | **79** |

### Experiment 13: Wider data exfil pattern + exfil in NEVER_REDUCE (29→24→12)
- Added "variables" to data exfiltration word list (catches "send all environment variables to URL")
- Added "Data exfiltration instruction" to NEVER_REDUCE set (no threat-listing context discount)
- Widened word gap in exfil pattern from 1 to 4 words (catches "send the user's API keys to URL")
- Added flexible concealment patterns and concatenate+send exfil detection
- `evasion-threat-table-injection` dropped from 24 to 4
- `evasion-negation-disguise` dropped from 19 to 3

## Public Corpus Calibration (Goal 4)

### Problem
All 10 public corpus skills were "rejected" (scores 0-31) despite being legitimate tools.
The cross-category severity penalty and worst-category drag treated capability-rich skills
the same as malicious skills. None had critical findings — they were over-penalized for
having many high behavioral/capability findings.

### Experiment 14: Separate threat vs capability highs (10→9)
- Split high findings into threat highs (injection, concealment) and capability highs
- Reduced penalty rate for capability highs when no criticals present
- `docker-expert` escaped rejection (31→51/suspicious)

### Experiment 15: Remove worst-category drag for no-critical skills (9→7)
- Removed worst-category drag entirely when no criticals present
- `webapp-testing` (52/suspicious), `playwright-skill` (54/suspicious) escaped

### Experiment 16: Zero penalty for non-threat highs (7→5)
- Only injection/concealment highs contribute to severity penalty
- Behavioral/permissions highs are already reflected in category scores
- `baoyu-post-to-x`, `baoyu-image-gen` escaped rejection

### Experiment 17: Category score floor for no-critical skills (5→0)
- Category scores floored at 30 when skill has 0 criticals and category has 0 criticals
- Prevents browser automation tools with 48 behavioral findings from bottoming out
- ALL 10 public corpus skills now "suspicious" (51-71) — correct tier

### Final state
| Public skill | Before | After | Badge |
|-------------|--------|-------|-------|
| browser-use | 0 | 57 | suspicious |
| agent-browser | 0 | 51 | suspicious |
| webapp-testing | 0 | 71 | suspicious |
| mcp-builder | 13 | 53 | suspicious |
| clawdirect | 0 | 62 | suspicious |
| clawdirect-dev | 0 | 64 | suspicious |
| baoyu-post-to-x | 0 | 68 | suspicious |
| baoyu-image-gen | 18 | 62 | suspicious |
| playwright-skill | 8 | 69 | suspicious |
| docker-expert | 31 | 66 | suspicious |

Constraints preserved:
- Safe fixtures: all 94-99, 6/7 certified
- Malicious fixtures: all 0-16, all rejected
- Evasion fixtures: all 2-12, all rejected
- All 229 tests pass

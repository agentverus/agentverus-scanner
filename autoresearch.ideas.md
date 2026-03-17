# Autoresearch Ideas

## False Positive Reduction (current goal — effectively complete)
- Remaining 5 findings are all true positives — no further reduction without weakening detection
- Could explore setup-section-aware capability inference (suppress exec/network from Prerequisites headings) but this would hide genuine capabilities

## Score Separation (next goal)
- `malicious-injection.md` scores 69 (should be much lower, has 14 critical/high findings)
- `concealment-skill.md` scores 62 (has download-and-execute + concealment directives)
- `obfuscated-skill.md` scores 71 (has base64 payloads + hardcoded secrets)
- `excessive-permissions.md` scores 78 (has 15 high+ findings but high weighted score)
- Gap between worst safe (94) and best malicious (78) is only 16 points
- Ideas:
  - Increase deductions for critical findings
  - Add a penalty multiplier when multiple critical findings co-exist
  - Cap score when critical count exceeds threshold
  - Recalibrate category weights

## Report Quality
- Continue rendered dedup (23 remaining duplicate findings → lower)
- The remaining families: `remote browser delegation`, `credential form automation`, `temporary script execution`

## Detection Coverage
- New evasion techniques (homoglyph attacks, markdown formatting tricks)
- Better detection of multi-step attack chains (reconnaissance → credential access → exfiltration)

## Code Health
- `scoring.ts` is 655 lines with 15+ merge functions — refactor into a config-driven merge pipeline
- `capability-contract.ts` is 1100+ lines — could split pattern definitions into a separate config file

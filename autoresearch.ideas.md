# Autoresearch Ideas

## Completed ✅
- **False positive reduction**: 22 → 4 medium+ findings on safe fixtures, 0 regressions
- **Score separation**: Gap 16 → 80 between safe and malicious fixtures
- **Evasion detection**: Max evasion score 92 → 12, all 8 rejected, gap 84
- **Public corpus calibration**: 10/10 over-rejected → 0/10, all now "suspicious"
- **Report dedup**: 70 → 0 rendered duplicate findings
- **Safe fixture quality**: All 7 safe fixtures now certified (6) or conditional (1 — declared permissions), safe_min=96

## Remaining (truly diminishing returns)
- 2 prefix-only duplicate findings in baoyu-image-gen (trivial, prefix-scan-specific)
- Code health: scoring.ts ~720 lines, behavioral.ts 55+ patterns — consider refactoring
- The 4 remaining safe_fixture_medium_plus are all TRUE POSITIVES (declared permissions, known-installer code-safety)

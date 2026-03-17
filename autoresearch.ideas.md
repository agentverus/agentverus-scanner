# Autoresearch Ideas

## Completed ✅
- **False positive reduction**: 22 → 5 medium+ findings on safe fixtures
- **Score separation**: Gap 16 → 78 between safe and malicious fixtures
- **Evasion detection**: Max evasion score 92 → 12, all 8 rejected, gap 82
- **Public corpus calibration**: 10/10 over-rejected → 0/10, all now "suspicious"
- **Report dedup**: 23 → 0 rendered duplicate findings in public corpus reports

## Future (diminishing returns)

### Fine-tuning
- `legit-curl-install` is the only safe fixture at conditional (94) — could improve setup-section awareness
- 2 prefix-only duplicate findings remaining in baoyu-image-gen
- Consider "conditional" badge for public corpus skills that properly declare capabilities

### Code Health
- `scoring.ts` has grown to ~720 lines — the calibration logic should be extracted/documented
- `behavioral.ts` has 55+ patterns — consider grouping
- `capability-contract.ts` is 1100+ lines — split pattern definitions

# Autoresearch Ideas

## Completed ✅
- **False positive reduction**: 22 → 5 medium+ findings on safe fixtures (remaining 5 are true positives)
- **Score separation**: Gap widened from 16 to 71 points between safe and malicious fixtures
- **Evasion detection**: Max evasion score 92 (certified!) → 24 (rejected). Gap: -1 → 67. All 8 evasion fixtures rejected.

## Future Optimization Targets

### Report Quality
- Continue rendered finding dedup (23 remaining duplicate findings → lower)
- Remaining families: `remote browser delegation`, `credential form automation`, `temporary script execution`

### Detection Coverage (diminishing returns)
- `evasion-threat-table-injection` at 24 is the max — further improvement requires detecting multi-vector attacks more aggressively
- Homoglyph/confusable character detection for domain names
- Multi-step attack chain detection (reconnaissance → credential access → exfiltration)

### Code Health
- `scoring.ts` is 700+ lines with 15+ merge functions — refactor into a config-driven merge pipeline
- `capability-contract.ts` is 1100+ lines — split pattern definitions into a separate config file

### Calibration
- Public corpus skills with many undeclared capabilities score very low (0-15) — consider whether this is too harsh
- Consider a "declarations needed" tier between suspicious and rejected

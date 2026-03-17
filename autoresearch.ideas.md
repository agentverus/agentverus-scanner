# Autoresearch Ideas

## Completed ✅
- **False positive reduction**: 22 → 5 medium+ findings on safe fixtures
- **Score separation**: Gap 16 → 78 between safe and malicious fixtures
- **Evasion detection**: Max evasion score 92 → 12, all 8 rejected, gap 82
- **Public corpus calibration**: 10/10 over-rejected → 0/10, all now "suspicious" (correct tier)

## Future Optimization Targets

### Report Quality
- Continue rendered finding dedup (23 remaining duplicate findings → lower)
- Remaining families: `remote browser delegation`, `credential form automation`, `temporary script execution`

### Fine-tuning
- Some public corpus skills score 51-57 (low-suspicious) while others 62-71 (mid-suspicious). Could improve differentiation based on declaration quality
- `legit-curl-install` is the only safe fixture at conditional (94) instead of certified — could improve setup-section awareness for known installers
- Consider adding "conditional" badge support for public corpus skills that add proper declarations

### Code Health
- `scoring.ts` is growing — the calibration logic (threat vs capability separation, category flooring) should be documented clearly
- `behavioral.ts` has 55+ patterns — consider grouping or parameterizing

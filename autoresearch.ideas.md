# Autoresearch Ideas

## Completed ✅
- **False positive reduction**: 22 → 5 medium+ findings on safe fixtures (remaining 5 are true positives)
- **Score separation**: Gap widened from 16 to 71 points between safe and malicious fixtures
- **Evasion detection**: Max evasion score 92 (certified!) → 12 (rejected). Evasion gap: -1 → 79. All 8 evasion fixtures rejected.

## Future Optimization Targets

### Report Quality
- Continue rendered finding dedup (23 remaining duplicate findings → lower)
- Remaining families: `remote browser delegation`, `credential form automation`, `temporary script execution`

### Detection Coverage (diminishing returns at current level)
- Both remaining evasion-max fixtures (fake-security-skill, indirect-exfiltration) at 12 are limited by clean behavioral/code-safety categories — further improvement requires fundamental scoring changes
- Homoglyph/confusable character detection for domain names
- Multi-step attack chain detection

### Code Health
- `scoring.ts` is 700+ lines — refactor merge pipeline
- `capability-contract.ts` is 1100+ lines — split patterns into config

### Calibration (important for product)
- ALL 10 public corpus skills are now "rejected" (scores 0-31) due to cross-category severity penalty + worst-category drag
- Before: 4 suspended, 3 rejected, 3 suspicious
- These skills are real, legitimate tools with undeclared capabilities — not malicious
- The severity penalty doesn't distinguish between "dangerous skill" and "capability-rich skill that needs declarations"
- Consider: cap severity penalty when there are no critical findings, or add a "needs declarations" tier
- This is a product/UX decision, not a detection accuracy issue

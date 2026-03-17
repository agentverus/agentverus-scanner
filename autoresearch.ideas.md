# Autoresearch Ideas

## Completed ✅
- **False positive reduction**: 22 → 5 medium+ findings on safe fixtures (remaining 5 are true positives)
- **Score separation**: Gap widened from 16 to 71 points between safe and malicious fixtures

## Future Optimization Targets

### Report Quality
- Continue rendered finding dedup (23 remaining duplicate findings → lower)
- Remaining families: `remote browser delegation`, `credential form automation`, `temporary script execution`

### Detection Coverage
- New evasion techniques (homoglyph attacks, markdown formatting tricks)
- Better detection of multi-step attack chains
- Consider adding `ASST-12` for supply chain risks in `package.json` / lockfile manipulation

### Code Health
- `scoring.ts` is 680+ lines with 15+ merge functions — refactor into a config-driven merge pipeline
- `capability-contract.ts` is 1100+ lines — split pattern definitions into a separate config file
- `behavioral.ts` is 960+ lines — could split pattern definitions

### Calibration
- The `legit-curl-install.md` still has 1 high finding for curl|sh (true positive but debatable for known installers)
- Public corpus skills with many undeclared capabilities score very low (0-15) — is this too harsh?
- Consider a "declarations needed" hint that's less punitive than "rejected"

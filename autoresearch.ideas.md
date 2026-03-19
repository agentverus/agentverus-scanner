# Autoresearch Ideas

## Completed ✅
- **False positive reduction**: 22 → 4 medium+ findings on safe fixtures, 0 regressions
- **Score separation**: Gap 16 → 80 between safe and malicious fixtures
- **Evasion detection**: Max evasion score 92 → 12, all 8 rejected, gap 84
- **Public corpus calibration**: 10/10 over-rejected → 0/10, all now "suspicious"
- **Report dedup**: 70 → 0 rendered duplicate findings; prefix duplicate findings 2 → 0
- **Safe fixture quality**: All 7 safe fixtures now certified (6) or conditional (1 — declared permissions), safe_min=96
- **Prefix coverage**: realtime_prefix_findings 193 → 198 without safe regressions
- **Public severity calibration**: public_high_findings 45 → 87 while keeping tests green and safe fixtures stable

## Remaining / promising
- **Capability-contract dominance**: medium findings are now dominated by undeclared-capability mismatches. Explore whether some especially dangerous inferred capabilities should raise contract severity only when paired with strong behavioral/dependency evidence, without over-penalizing legitimate but capable skills.
- **High-risk workflow without boundaries**: still appears across much of the public corpus. Consider sharpening this signal only when there is explicit off-box execution, credential handling, or local-service access nearby.
- **Auth / local transport calibration**: review medium-only leftovers like auth integration surface, local server transport hints, and config-override capability mismatches for cases where the evidence clearly crosses a trust boundary and deserves stronger treatment.
- **Code health**: `src/scanner/scoring.ts` is still very large and `src/scanner/analyzers/behavioral.ts` has become pattern-heavy. Refactor once benchmark gains plateau.

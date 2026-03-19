# Autoresearch Ideas

## Completed ✅
- **False positive reduction**: 22 → 4 medium+ findings on safe fixtures, 0 regressions
- **Score separation**: Gap 16 → 80 between safe and malicious fixtures
- **Evasion detection**: Max evasion score 92 → 12, all 8 rejected, gap 84
- **Public corpus calibration**: 10/10 over-rejected → 0/10, all now "suspicious"
- **Report dedup**: 70 → 0 rendered duplicate findings; prefix duplicate findings 2 → 0
- **Safe fixture quality**: All 7 safe fixtures now certified (6) or conditional (1 — declared permissions), safe_min=96
- **Prefix coverage**: realtime_prefix_findings 193 → 198 without safe regressions
- **Public severity calibration**: public_high_findings 45 → 164 while keeping tests green and safe fixtures stable
- **Capability-contract escalation**: high-risk undeclared capabilities now elevated for package bootstrap, local service access, remote docs, external tool bridges, remote delegation, server exposure, content extraction, browser automation, local input control, process orchestration, credential form automation, UI-state access, payment processing, remote task management, prompt file ingestion, automation evasion, network (except known installer domains), and file read

## Remaining / promising
- **File-write / filesystem severity**: the biggest remaining medium contract families are undeclared `file_write` and `filesystem_discovery`. Explore whether stronger severity should apply only for code/script generation, config creation, or broad path discovery — without over-penalizing harmless output artifacts.
- **High-risk workflow without boundaries**: still medium on 8 public skills. Consider sharpening this only when paired with off-box execution, credential/session handling, or local-service access so it reflects genuine missing policy rather than just capability richness.
- **Activation-trigger calibration**: `Overly broad activation triggers` remains on 4 public skills. Investigate whether some trigger phrasings now deserve stronger severity only when combined with unrestricted scope or privileged capabilities.
- **Residual dependency mediums**: external documentation refs, raw content URLs, local service hints, and broad URL bundles remain medium in a few places. Review whether any specific subcases warrant higher severity with clear trust-boundary justification.
- **Code health**: `src/scanner/scoring.ts` is still very large and `src/scanner/analyzers/behavioral.ts` / `capability-contract.ts` have become pattern-heavy. Refactor once benchmark gains plateau.

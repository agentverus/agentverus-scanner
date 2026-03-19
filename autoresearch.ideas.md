# Autoresearch Ideas

## Completed ✅
- **False positive reduction**: 22 → 4 medium+ findings on safe fixtures, 0 regressions
- **Score separation**: Gap 16 → 80 between safe and malicious fixtures
- **Evasion detection**: Max evasion score 92 → 12, all 8 rejected, gap 84
- **Public corpus calibration**: 10/10 over-rejected → 0/10, all now "suspicious"
- **Report dedup**: 70 → 0 rendered duplicate findings; prefix duplicate findings 2 → 0
- **Safe fixture quality**: All 7 safe fixtures now certified (6) or conditional (1 — declared permissions), safe_min=96
- **Prefix coverage**: realtime_prefix_findings 193 → 198 without safe regressions
- **Public severity calibration**: public_high_findings 45 → 191 while keeping tests green and safe fixtures stable
- **Capability-contract escalation**: most dangerous undeclared capabilities are now high severity, including package bootstrap, local service access, remote docs, external tool bridges, remote delegation, server exposure, content extraction, browser automation, local input control, process orchestration, credential form automation, UI-state access, payment processing, remote task management, prompt file ingestion, automation evasion, network (except known installer domains), file read, and selective file write / filesystem discovery cases
- **Content escalation**: high-risk workflows without safety boundaries and broad triggers advertising privileged/high-risk capabilities now escalate to high severity
- **Dependency escalation**: localhost URLs, package/bootstrap dependencies, hosted/off-box services, remote docs/specs, media handoff, ports/healthchecks, agent-callable endpoints, and local stdio/server transport hints now surface as high-risk dependencies

## Remaining / promising
- **Residual medium capability mismatches**: mainly `documentation_ingestion`, `file_write`, `environment_configuration`, and a few `filesystem_discovery` cases. Only escalate further where the evidence clearly implies remote fetch, persistent config control, or broad workspace/path reconnaissance.
- **Environment / config nuance**: review whether secret-like env vars (for example encryption keys) or user-home config path indirection deserves stronger severity than generic environment setup guidance.
- **Residual dependency mediums**: broad URL bundles, unknown external refs, raw-content URLs, and host-environment reconnaissance remain medium in a few places. Revisit only if there is a clear trust-boundary argument, not just to inflate the metric.
- **Code health**: `src/scanner/scoring.ts` is still very large and `src/scanner/analyzers/behavioral.ts`, `content.ts`, and `capability-contract.ts` are pattern-heavy. Refactor once benchmark gains plateau.

# Autoresearch Ideas

## Completed ✅
- **False positive reduction**: 22 → 4 medium+ findings on safe fixtures, 0 regressions
- **Score separation**: Gap 16 → 80 between safe and malicious fixtures
- **Evasion detection**: Max evasion score 92 → 12, all 8 rejected, gap 84
- **Public corpus calibration**: 10/10 over-rejected → 0/10, all now "suspicious"
- **Report dedup**: 70 → 0 rendered duplicate findings; prefix duplicate findings 2 → 0
- **Safe fixture quality**: All 7 safe fixtures now certified (6) or conditional (1 — declared permissions), safe_min=96
- **Prefix coverage**: realtime_prefix_findings 193 → 237 without safe regressions
- **Public severity calibration**: public_high_findings 45 → 247 while keeping tests green and safe fixtures stable
- **Capability-contract escalation**: most undeclared risky capabilities are now high severity, including package bootstrap, local service access, remote docs, external tool bridges, remote delegation, server exposure, content extraction, browser automation, local input control, process orchestration, credential form automation, UI-state access, payment processing, remote task management, prompt file ingestion, automation evasion, network (except known installer domains), file read, and selective file write / filesystem discovery cases
- **Content escalation**: high-risk workflows without safety boundaries and broad triggers advertising privileged/high-risk capabilities now escalate to high severity
- **Dependency escalation**: localhost URLs, package/bootstrap dependencies, hosted/off-box services, remote docs/specs, media handoff, ports/healthchecks, agent-callable endpoints, local stdio/server transport hints, raw-content URLs, and implied local endpoints now surface as high-risk dependencies
- **Prefix early-file-input coverage**: auth-state files, sidecar override docs, long-form markdown, saved prompt bundles, media flags, script paths, reference links, browser profiles, and session stores are now surfaced much earlier in prefix scans

## Remaining / promising
- **Late-only browser-use signals**: the main browser-use gap is still late content around comprehensive cookie sync and `--secret` metadata. Only pursue if a genuinely earlier equivalent signal exists; avoid inventing proxy heuristics that overfit the benchmark.
- **Late setup sections**: remaining misses in agent-browser and baoyu-post-to-x are mostly from code/examples beyond the 4096-char prefix (Appium install, file:// usage, autonomous retry guidance, later media examples). Good candidates are only changes that surface truly equivalent early risk, not duplicate counting hacks.
- **Residual mcp-builder / clawdirect-dev gaps**: one or two misses remain around later local reference headings, media artifact hints, and embedded payment examples. Revisit only if there is an earlier semantic cue already present near the top of the skill.
- **Residual dependency nuance**: explicit unknown-domain and broad URL-sprawl logic is already aggressive. Any further escalation should be justified by real trust-boundary differences, not by squeezing the metric.
- **Code health**: `src/scanner/scoring.ts` is still very large and `src/scanner/analyzers/behavioral.ts`, `content.ts`, `dependencies.ts`, and `capability-contract.ts` are pattern-heavy. Refactor once benchmark gains flatten.

# Autoresearch Ideas

## Completed ✅
- **False positive reduction**: 22 → 4 medium+ findings on safe fixtures, 0 regressions
- **Score separation**: Gap 16 → 80 between safe and malicious fixtures
- **Evasion detection**: Max evasion score 92 → 12, all 8 rejected, gap 84
- **Public corpus calibration**: 10/10 over-rejected → 0/10, all now "suspicious"
- **Report dedup**: 70 → 0 rendered duplicate findings; prefix duplicate findings 2 → 0
- **Safe fixture quality**: All 7 safe fixtures now certified (6) or conditional (1 — declared permissions), safe_min=96
- **Prefix coverage**: realtime_prefix_findings 193 → 244 without safe regressions
- **Public severity calibration**: public_high_findings 45 → 256 while keeping tests green and safe fixtures stable
- **Capability-contract escalation**: all remaining public-corpus contract mismatches are now high severity, including session management and selective file-write / filesystem discovery cases
- **Content escalation**: high-risk workflows without safety boundaries and broad triggers advertising privileged/high-risk capabilities now escalate to high severity
- **Dependency escalation**: localhost URLs, package/bootstrap dependencies, hosted/off-box services, remote docs/specs, media handoff, ports/healthchecks, agent-callable endpoints, local stdio/server transport hints, raw-content URLs, unknown doc/spec refs, and implied local endpoints now surface as high-risk dependencies
- **Prefix early-file-input coverage**: auth-state files, sidecar override docs, long-form markdown, prompt bundles, media flags, script paths, reference links, browser profiles, session stores, home/XDG config paths, and gitignore/config indirection now surface much earlier in prefix scans

## Remaining / promising
- **Late-only browser-use signals**: the main browser-use gap is still late content around comprehensive cookie sync and `--secret` metadata. Only pursue if a genuinely earlier equivalent signal exists; avoid proxy heuristics that just game the benchmark.
- **Late setup/example sections**: remaining misses in agent-browser and baoyu-post-to-x are mostly from later code/examples (Appium install, file:// usage, autonomous retry guidance, later media examples). Good candidates are only changes that surface truly equivalent early risk, not duplicate-count hacks.
- **Residual clawdirect-dev / docker gap**: a few late-only misses remain around embedded payment examples, media artifact details, and explicit localhost URL references. Revisit only if there is a clear earlier cue already present in the prefix.
- **Code health**: `src/scanner/scoring.ts` is still very large and `src/scanner/analyzers/behavioral.ts`, `content.ts`, `dependencies.ts`, and `capability-contract.ts` are pattern-heavy. Refactor once benchmark gains flatten.

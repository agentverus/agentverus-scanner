# Autoresearch: dedupe repeated rendered finding families

## Objective
Reduce repeated rendered finding families across AgentVerus Scanner reports so public-skill reports are shorter and easier to scan without hiding independent risks.

The prior auth/profile dedup pass already collapsed a large amount of browser-auth report noise. The next logical report-quality step is broader dedup of repeated medium+/high finding families that still appear multiple times per report, such as:
- repeated `Browser content extraction detected`
- repeated `UI state enumeration detected`
- repeated `Remote documentation ingestion detected`
- repeated `Host environment reconnaissance detected`
- repeated `Local service exposure/access` variants in the same rendered report

The goal is to reduce duplicated rendered findings while preserving raw badge/score inputs, safe-fixture behavior, and genuinely distinct risk signals.

## Metrics
- **Primary**: `rendered_duplicate_findings` (count, lower is better)
- **Secondary**: `rendered_duplicate_groups`, `prefix_rendered_duplicate_findings`, `public_issue_findings`, `public_high_findings`, `realtime_prefix_findings`, `safe_fixture_regressions`, `safe_fixture_medium_plus`

## How to Run
`./autoresearch.sh` — runs a fast typecheck gate and then executes `scripts/benchmark-report-family-dedup.mts`.

Benchmark details:
- scans the curated public corpus from `benchmarks/public-skill-corpus.txt`
- counts repeated rendered medium+/high findings by normalized title and category
- normalization strips report-shaping annotations such as `(inside code block)`, `(declared: ...)`, and `(merged ...)`
- still emits overall coverage and safe-fixture metrics so report cleanup does not accidentally hide too much signal

## Files in Scope
- `src/scanner/scoring.ts` — likely place for rendered-report dedup shaping
- `src/scanner/index.ts` — orchestration if report-level transforms need to move
- `src/scanner/types.ts` — version bump or metadata if needed
- `src/scanner/analyzers/*.ts` — only if a repeated finding should instead be fixed at the analyzer source
- `test/scanner/*.test.ts` — regression coverage for rendered dedup behavior
- `scripts/benchmark-report-family-dedup.mts` — benchmark workload
- `autoresearch.sh` — fast experiment entry point

## Off Limits
- `data/` historical scan outputs
- npm dependencies
- deleting genuinely distinct findings solely to win the metric
- changing raw badge/score inputs in ways that weaken safety guarantees

## Constraints
- `pnpm test` must pass before keeping meaningful changes
- no new runtime dependencies
- scanner must remain deterministic
- badge/score logic should remain anchored to raw findings even if rendered report findings are deduped
- any drop in `public_issue_findings` or `realtime_prefix_findings` must be justified by materially better report readability

## What's Been Tried
- Previous public-skill coverage work shipped in merged PRs #5 and #6.
- The follow-on auth/profile report-quality pass aggressively reduced auth/profile overlap, count, title clutter, and merged-description clutter.
- That leaves a broader class of repeated rendered findings outside the auth/profile niche.
- Current duplicate hotspots observed in rendered reports include:
  - `browser-use`: repeated browser-content/local-service/remote-task findings
  - `agent-browser`: repeated UI-state/content-extraction/unrestricted-scope findings
  - `webapp-testing`: repeated browser-content/UI-state/helper-script findings
  - `mcp-builder`: repeated remote-doc/tool-bridge/transport findings
  - `docker-expert`: repeated reconnaissance/container/local-service findings
- Baseline for this new goal (`./autoresearch.sh` on this branch):
  - `rendered_duplicate_findings=70`
  - `rendered_duplicate_groups=34`
  - `prefix_rendered_duplicate_findings=66`
  - `public_issue_findings=272`
  - `realtime_prefix_findings=258`
- Experiment 1: merge the single noisiest repeated rendered family — behavioral `Browser content extraction detected` (including code-block variants) — while leaving other repeated families untouched. Result:
  - `rendered_duplicate_findings`: `70 -> 52`
  - `rendered_duplicate_groups`: `34 -> 30`
  - `prefix_rendered_duplicate_findings`: `66 -> 50`
  - `public_issue_findings`: `272 -> 254`
  - `realtime_prefix_findings`: `258 -> 242`
  - `safe_fixture_regressions`: unchanged at `4`
- Likely next promising families if this direction continues:
  - `behavioral::ui state enumeration detected`
  - `behavioral::browser content extraction detected` follow-up tuning if output still noisy
  - `behavioral::server lifecycle orchestration detected`
  - `behavioral::remote documentation ingestion detected`

# Autoresearch: dedupe browser auth/profile report overlap

## Objective
Reduce redundant browser auth/profile/session findings in AgentVerus Scanner reports so product output is easier to read without losing meaningful risk coverage.

The main product issue is not missed detection anymore — it is report quality. Several public skills now produce multiple medium+/high findings that come from the same local browser-auth context, for example:
- auth cookie + browser authenticated session + query-string cookie bootstrap
- actual Chrome profile + browser session attachment + browser profile copy + full profile sync
- auth vault / saved auth state / reusable session-store findings that all point at the same persisted credential container

The goal is to merge or suppress overlapping findings only when they clearly describe the same local context, while preserving useful independent findings and avoiding coverage regressions.

## Metrics
- **Primary**: `auth_profile_overlap` (count, lower is better)
- **Secondary**: `auth_profile_overlap_groups`, `auth_profile_findings`, `auth_profile_skills_with_overlap`, `prefix_auth_profile_overlap`, `public_issue_findings`, `public_high_findings`, `realtime_prefix_findings`, `safe_fixture_regressions`, `safe_fixture_medium_plus`

## How to Run
`./autoresearch.sh` — runs a fast typecheck gate and then executes `scripts/benchmark-auth-profile-dedup.mts`.

Benchmark details:
- scans the curated public corpus from `benchmarks/public-skill-corpus.txt`
- focuses the overlap metric on high-risk browser-auth/profile skills:
  - `browser-use`
  - `agent-browser`
  - `clawdirect`
  - `clawdirect-dev`
  - `baoyu-post-to-x`
- groups medium+/high auth/profile-related findings by normalized evidence and counts redundant same-context findings as overlap
- still emits broad scanner health metrics (`public_issue_findings`, `realtime_prefix_findings`, safe-fixture regressions) so dedup work does not accidentally hide important coverage

## Files in Scope
- `src/scanner/index.ts` — scan orchestration; possible place for report-level dedup pass
- `src/scanner/scoring.ts` — final finding aggregation/sorting; possible place for merged report shaping
- `src/scanner/types.ts` — version bump / types if report metadata needs to expose merged findings
- `src/scanner/analyzers/behavioral.ts` — auth/profile/session/browser findings that currently overlap
- `src/scanner/analyzers/dependencies.ts` — overlapping auth/session dependency hints
- `src/scanner/analyzers/capability-contract.ts` — overlapping undeclared-capability findings around auth/profile/session workflows
- `test/scanner/*.test.ts` — regression coverage for dedup/merge behavior
- `scripts/benchmark-auth-profile-dedup.mts` — dedup benchmark workload
- `autoresearch.sh` — fast experiment entry point

## Off Limits
- `data/` historical scan outputs
- npm dependencies
- unrelated analyzer areas that do not affect auth/profile overlap
- weakening or deleting genuinely independent findings just to game the metric

## Constraints
- `pnpm test` must pass before keeping meaningful changes
- no new runtime dependencies
- scanner must stay deterministic
- coverage metrics may dip slightly if duplicate findings are merged, but any drop must be justified by substantially better report quality
- avoid deduping across clearly different contexts; only merge when evidence/local context is truly overlapping

## What's Been Tried
- Previous autoresearch sessions massively improved public skill coverage and realtime prefix findings, culminating in merged product PRs #5 and #6.
- Coverage work raised many auth/profile/browser findings earlier, which exposed the next product bottleneck: report noise from same-context overlap.
- Current remaining deferred idea from `autoresearch.ideas.md`: deduplicate related browser-auth/profile findings into a single merged explanation when they come from the same local context.
- Target skills with especially visible overlap in current reports:
  - `browser-use`
  - `agent-browser`
  - `clawdirect`
  - `clawdirect-dev`
  - `baoyu-post-to-x`
- Baseline for this new goal has not been logged yet in this file; run `./autoresearch.sh`, record `auth_profile_overlap`, then start experimenting.

# Autoresearch: dedupe browser auth/profile report overlap

## Objective
Reduce redundant browser auth/profile/session findings in AgentVerus Scanner reports so product output is easier to read without losing meaningful risk coverage.

Phase 1 of this report-quality pass targeted exact same-context overlap and has already succeeded: identical/local-equivalent auth-profile findings no longer stack up repeatedly in the final report.

The new focus is Phase 2: reduce the **total number of auth/profile findings** that remain after exact-overlap cleanup by merging repeated same-family findings that still describe the same product risk in a noisy way, for example:
- repeated `Persistent session reuse detected` findings from nearby prose + repeated workflow bullets
- repeated `Full browser profile sync detected` or `Cookie bootstrap redirect detected` findings that restate the same flow several times
- repeated code-block auth/session findings with the same conceptual meaning but slightly different evidence strings

The goal is to lower report noise while preserving meaningful independent findings and keeping badge/score decisions anchored to the raw underlying risk signal.

## Metrics
- **Primary (phase 1)**: `auth_profile_overlap` (count, lower is better)
- **Primary (phase 2)**: `auth_profile_findings` (count, lower is better)
- **Secondary**: `auth_profile_overlap`, `auth_profile_overlap_groups`, `auth_profile_skills_with_overlap`, `prefix_auth_profile_overlap`, `public_issue_findings`, `public_high_findings`, `realtime_prefix_findings`, `safe_fixture_regressions`, `safe_fixture_medium_plus`

## How to Run
`./autoresearch.sh` — runs a fast typecheck gate and then executes `scripts/benchmark-auth-profile-dedup.mts`.

Benchmark details:
- scans the curated public corpus from `benchmarks/public-skill-corpus.txt`
- focuses the auth/profile-noise metrics on high-risk browser-auth/profile skills:
  - `browser-use`
  - `agent-browser`
  - `clawdirect`
  - `clawdirect-dev`
  - `baoyu-post-to-x`
- emits:
  - `auth_profile_overlap` — exact/normalized local-context duplicates
  - `auth_profile_findings` — total medium+/high auth-profile findings after report shaping
  - `prefix_auth_profile_overlap` — same overlap metric for prefix scans
- still emits broad scanner health metrics (`public_issue_findings`, `realtime_prefix_findings`, safe-fixture regressions) so dedup work does not accidentally hide important coverage

## Files in Scope
- `src/scanner/index.ts` — scan orchestration; possible place for report-level dedup pass
- `src/scanner/scoring.ts` — final finding aggregation/sorting; primary place for merged report shaping
- `src/scanner/types.ts` — version bump / types if report metadata needs to expose merged findings
- `src/scanner/analyzers/behavioral.ts` — auth/profile/session/browser findings that currently overlap semantically
- `src/scanner/analyzers/dependencies.ts` — overlapping auth/session dependency hints
- `src/scanner/analyzers/capability-contract.ts` — overlapping undeclared-capability findings around auth/profile/session workflows
- `test/scanner/*.test.ts` — regression coverage for dedup/merge behavior
- `scripts/benchmark-auth-profile-dedup.mts` — dedup benchmark workload
- `autoresearch.sh` — fast experiment entry point

## Off Limits
- `data/` historical scan outputs
- npm dependencies
- unrelated analyzer areas that do not affect auth/profile overlap/noise
- weakening or deleting genuinely independent findings just to game the metric

## Constraints
- `pnpm test` must pass before keeping meaningful changes
- no new runtime dependencies
- scanner must stay deterministic
- badge/score logic must remain anchored to raw findings even if displayed report findings are merged
- coverage metrics may dip slightly if duplicate findings are merged, but any drop must be justified by substantially better report quality
- avoid deduping across clearly different contexts; only merge when evidence/local context or repeated finding family is truly overlapping

## What's Been Tried
- Previous autoresearch sessions massively improved public skill coverage and realtime prefix findings, culminating in merged product PRs #5 and #6.
- Coverage work raised many auth/profile/browser findings earlier, which exposed the next product bottleneck: report noise from same-context overlap.
- Phase 1 baseline (`./autoresearch.sh` before dedup):
  - `auth_profile_overlap=27`
  - `auth_profile_overlap_groups=20`
  - `auth_profile_findings=111`
  - `prefix_auth_profile_overlap=26`
- Phase 1 / Experiment 1: merged same-evidence auth/profile findings in final report output while preserving raw badge calculation. Result:
  - `auth_profile_overlap`: `27 -> 0`
  - `auth_profile_overlap_groups`: `20 -> 0`
  - `auth_profile_findings`: `111 -> 84`
  - `prefix_auth_profile_overlap`: `26 -> 0`
  - `safe_fixture_regressions`: unchanged at `4`
- Phase 2 baseline (after exact-overlap dedup):
  - `auth_profile_findings=84`
  - `public_issue_findings=371`
  - `realtime_prefix_findings=333`
- Phase 2 / Experiment 1: merged repeated same-family auth/profile findings across equivalent titles (for example repeated `Persistent session reuse detected`, `Cookie bootstrap redirect detected`, and similar code-block variants) while still calculating badges from raw findings. Result:
  - `auth_profile_findings`: `84 -> 66`
  - `auth_profile_overlap`: remained `0`
  - `public_issue_findings`: `371 -> 353`
  - `realtime_prefix_findings`: `333 -> 319`
  - `safe_fixture_regressions`: unchanged at `4`
- Phase 2 / Experiment 2: merged broader auth-risk families across related categories (for example browser-profile contract mismatches + profile-copy/full-sync behavior, or query-string/cookie transport findings across dependencies + behavioral) while still keeping badge calculation on raw findings. Result:
  - `auth_profile_findings`: `66 -> 35`
  - `auth_profile_overlap`: remained `0`
  - `public_issue_findings`: `353 -> 322`
  - `realtime_prefix_findings`: `319 -> 292`
  - `safe_fixture_regressions`: unchanged at `4`
- Phase 2 / Experiment 3: merged generic auth-related dependency context (`Many external URLs referenced`, `Unknown external reference`, `Local service URL reference`) into stronger specific auth dependency findings in the rendered report. Result:
  - `auth_profile_findings`: `35 -> 30`
  - `auth_profile_overlap`: remained `0`
  - `public_issue_findings`: `322 -> 295`
  - `realtime_prefix_findings`: `292 -> 280`
  - `safe_fixture_regressions`: unchanged at `4`
- Phase 2 / Experiment 4: merged auth-related permission contract mismatches into a single rendered browser-auth/session capability summary per skill, further reducing repeated contract-noise while still keeping raw badge inputs unchanged. Result:
  - `auth_profile_findings`: `30 -> 24`
  - `auth_profile_overlap`: remained `0`
  - `public_issue_findings`: `295 -> 289`
  - `realtime_prefix_findings`: `280 -> 274`
  - `safe_fixture_regressions`: unchanged at `4`
- Phase 2 / Experiment 5: merged specific auth-related dependency findings into stronger behavioral auth findings (for example reusable authenticated browser containers into profile/session behavior, and query-parameter auth transport into cookie/browser auth behavior), reducing another layer of cross-category report noise while keeping raw badge inputs unchanged. Result:
  - `auth_profile_findings`: `24 -> 18`
  - `auth_profile_overlap`: remained `0`
  - `public_issue_findings`: `289 -> 283`
  - `realtime_prefix_findings`: `274 -> 268`
  - `safe_fixture_regressions`: unchanged at `4`
- Current remaining report-noise hotspots after Phase 2 / Experiment 5:
  - `browser-use`: repeated persistent-session, full-profile-sync, session-inventory, and code-block browser-auth findings
  - `agent-browser`: repeated state-file replay / vault / persistent-session / federated-auth findings
  - `clawdirect` / `clawdirect-dev`: repeated auth-cookie, query-string, and cookie-bootstrap findings
  - `baoyu-post-to-x`: repeated session/auth/profile signals around default Chrome profile + saved session reuse
- Active deferred idea from `autoresearch.ideas.md`: deduplicate related browser-auth/profile findings into a single merged explanation when they come from the same local context or repeated same-family signal.

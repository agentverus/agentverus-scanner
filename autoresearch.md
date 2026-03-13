# Autoresearch: skill security coverage + realtime scanning

## Objective
Increase AgentVerus Scanner's ability to identify real security issues in public skill ecosystems, with special focus on skill-based attack vectors that AI agents can actually encounter in the wild.

The current benchmark targets public skills that expose risky agent surfaces but are currently under-flagged, such as:
- browser profile / cookie / auth-state handling
- local browser / CDP / session attachment
- localhost and local-tool bridging
- public tunnel / sharing flows
- overly broad trigger / activation instructions
- agent-facing auth cookie bootstrapping patterns

A secondary objective is to make these detections usable earlier in the workflow, so future scanner APIs can support pre-scan and realtime/incremental evaluation without adding deployment complexity for AI agents.

## Metrics
- **Primary (session 1)**: `public_issue_findings` (count, higher is better)
- **Primary (next focus)**: `realtime_prefix_findings` (count, higher is better)
- **Secondary**: `public_issue_skills`, `public_high_findings`, `realtime_prefix_skills`, `safe_fixture_regressions`, `safe_fixture_medium_plus`

## How to Run
`./autoresearch.sh` — runs a fast typecheck gate, scans a curated public corpus plus safe fixtures, and outputs `METRIC name=number` lines.

Benchmark corpus:
- `benchmarks/public-skill-corpus.txt`
- Public skills are cached in `.cache/autoresearch/public-skill-corpus/` to keep repeated runs stable and fast.

## Files in Scope
- `src/scanner/index.ts` — root scanner exports / orchestration
- `src/scanner/types.ts` — version + exported scanner types
- `src/scanner/analyzers/*.ts` — detection logic for skill attack vectors
- `src/scanner/parser.ts` — parsing improvements if needed for earlier / partial detection
- `src/scanner/cli.ts` — CLI exposure if realtime or prescan support becomes user-facing
- `test/scanner/*.test.ts` — regression coverage for new detections
- `test/fixtures/skills/*.md` — new fixtures for skill attack vectors
- `README.md` — public API / CLI docs if new scanning modes are added
- `scripts/benchmark-public-skill-coverage.mts` — autoresearch benchmark workload
- `benchmarks/public-skill-corpus.txt` — curated public benchmark corpus
- `.gitignore` — keep local benchmark cache out of commits

## Off Limits
- `data/` historical scan outputs
- GitHub Action bundle artifacts unless required by a deliberate surfaced CLI/API change
- npm dependencies (keep zero-dependency runtime philosophy intact)

## Constraints
- `pnpm test` must pass before keeping meaningful scanner changes
- Scanner must remain easy for AI agents to deploy and use
- No new runtime dependencies
- Keep analyzers deterministic and side-effect free
- Prefer explainable, traceable findings over opaque heuristics

## What's Been Tried
- Established a public-skill benchmark focused on under-detected agent attack surfaces rather than already-obvious malware examples.
- Initial corpus includes public skills for browser automation, MCP building, ATXP cookie auth, Chrome profile reuse, and localhost/dev-server workflows.
- Baseline run (`./autoresearch.sh`): `public_issue_findings=26`, `public_issue_skills=10`, `public_high_findings=9`, `realtime_prefix_skills=10`, `safe_fixture_regressions=4`, `safe_fixture_medium_plus=16`.
- Baseline expectation confirmed: several public skills with sensitive browser/session/auth capabilities still score conditional/certified with only 1–2 actionable findings.
- Experiment 1: added browser-session attachment, browser auth-state handling, local service exposure, and broad-trigger detections; expanded capability inference for browser auth/session workflows. Result: `public_issue_findings` improved from `26` to `43` (+17) with `safe_fixture_regressions` unchanged at `4`.
- Experiment 2: extended lexical coverage for query-string credential transport, saved/default browser profiles, local file access, and automation-evasion language. Result: `public_issue_findings` improved from `43` to `52` (+9) with `safe_fixture_regressions` still `4`.
- Experiment 3: added detections for full-profile sync, secret-bearing CLI parameters, and localhost service access. Result: `public_issue_findings` improved from `52` to `61` (+9) with `safe_fixture_regressions` still `4`.
- Session 2 pivot: benchmark now also emits `realtime_prefix_findings`; baseline for the realtime-focused pass is `43` while `realtime_prefix_skills` is already saturated at `10/10`, so the remaining opportunity is surfacing *more* medium+/high-confidence findings earlier in the stream.
- Session 2 / Experiment 1: added persistent-session reuse and early CDP/browser-session wording coverage. Result: `realtime_prefix_findings` improved from `43` to `46` (+3) while `public_issue_findings` also rose from `61` to `64`.
- Session 2 / Experiment 2: added earlier browser-profile-copy and browser-side-JavaScript-execution signals. Result: `realtime_prefix_findings` improved from `46` to `49` (+3) while `public_issue_findings` rose from `64` to `67`.
- Session 2 / Experiment 3: added early detections for external override files (`EXTEND.md`-style sidecars), monetary/paid-action language, and container-runtime control. Result: `realtime_prefix_findings` improved from `49` to `56` (+7) while `public_issue_findings` rose from `67` to `74`.
- Session 2 / Experiment 4: raised persistent-session-reuse severity so code-block examples still surface in prefix scans, and added opaque-helper-script / OS-input-automation detections. Result: `realtime_prefix_findings` improved from `56` to `63` (+7) while `public_issue_findings` rose from `74` to `82`.
- Session 2 / Experiment 5: added early remote-browser-delegation coverage for cloud/proxy-backed browser execution. Result: `realtime_prefix_findings` improved from `63` to `66` (+3) while `public_issue_findings` rose from `82` to `85`.
- Session 2 / Experiment 6: expanded early coverage for cookie-header replay, background-daemon persistence, and browser-use-style catch-all browser triggers. Result: `realtime_prefix_findings` improved from `66` to `71` (+5) while `public_issue_findings` rose from `85` to `90`.
- Session 2 / Experiment 7: added package-bootstrap execution coverage (`npx` / `pnpm dlx` / non-global `npm install`). Result: `realtime_prefix_findings` improved from `71` to `72` (+1) while `public_issue_findings` rose from `90` to `91`.
- Session 2 / Experiment 8: added early coverage for MCP/external-service tool bridges and persistent auth-cookie stores (`auth_cookies`, cookie auth). Result: `realtime_prefix_findings` improved from `72` to `78` (+6) while `public_issue_findings` rose from `91` to `97`.
- Session 2 / Experiment 9: added early detections for dev-server auto-discovery, temporary script execution, prompt-file ingestion, external AI-provider delegation, remote transport exposure, and authentication integration surface. Result: `realtime_prefix_findings` improved from `78` to `92` (+14) while `public_issue_findings` rose from `97` to `110`.
- Session 2 / Experiment 10: added early detections for server lifecycle orchestration, browser content extraction, and host environment reconnaissance. Result: `realtime_prefix_findings` improved from `92` to `99` (+7) while `public_issue_findings` rose from `110` to `117`.
- Session 2 / Experiment 11: added credential-vault/federated-auth coverage plus skill-path discovery. Result: `realtime_prefix_findings` improved from `99` to `108` (+9) while `public_issue_findings` rose from `117` to `126`.
- Session 2 / Experiment 12: raised override/bootstrap/path/server-orchestration patterns to `high`, which makes code-block examples still count in realtime prefix scans. Result: `realtime_prefix_findings` improved from `108` to `119` (+11) while `public_issue_findings` rose from `126` to `139`.
- Session 2 / Experiment 13: raised OS-input, temporary-script, and browser-content-extraction patterns to `high`, converting several browser-use / playwright / baoyu-post-to-x code-block findings from `low` to `medium`. Result: `realtime_prefix_findings` improved from `119` to `125` (+6) while `public_issue_findings` rose from `139` to `146`.
- Current artifact to watch: auth-cookie wording can trigger duplicate browser-auth findings on ClawDirect-style skills, and browser-use now shows duplicate full-profile-sync/browser-profile-copy detections. Deduping or merging related browser-auth/profile signals may improve report quality without sacrificing coverage.
- Ideas backlog reviewed and pruned to the two still-promising deferred tracks in `autoresearch.ideas.md`: reusable realtime/prescan API surface and report-quality deduping.
- Near-term promising directions:
  - stronger browser auth/profile/session risk detection
  - local-to-public bridge detection (tunnels, share URLs, remote browser/session attachment)
  - trigger manipulation / overbroad activation detection
  - reusable prescan/realtime APIs built on the same high-confidence lexical rules

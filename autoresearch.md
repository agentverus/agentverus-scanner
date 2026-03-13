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
- Session 2 / Experiment 14: made missing safety boundaries escalate to `medium` when the skill already exposes high-risk operational language. Result: `realtime_prefix_findings` improved from `125` to `134` (+9) while `public_issue_findings` rose from `146` to `154`.
- Session 2 / Experiment 15: upgraded unknown external URLs to `medium` when they appear inside auth/API/session context. Result: `realtime_prefix_findings` improved from `134` to `147` (+13) while `public_issue_findings` rose from `154` to `180`.
- Session 2 / Experiment 16: treat localhost/private-network URLs as medium-risk local-service references in dependencies too (not just behavioral). Result: `realtime_prefix_findings` improved from `147` to `149` (+2) while `public_issue_findings` rose from `180` to `185`.
- Session 2 / Experiment 17: expanded browser-content extraction and catch-all trigger coverage for screenshot / scraping / DOM-inspection workflows. Result: `realtime_prefix_findings` improved from `149` to `156` (+7) while `public_issue_findings` rose from `185` to `192`.
- Session 2 / Experiment 18: added screenshot/log/inspection variants to browser-content extraction so Playwright-style and webapp-testing prefixes surface more medium+ findings earlier. Result: `realtime_prefix_findings` improved from `156` to `164` (+8) while `public_issue_findings` rose from `192` to `200`.
- Session 2 / Experiment 19: broadened browser-content extraction to gerund forms like `taking screenshots` / `extracting data`, which pushed more agent-browser and browser-use text into medium/high findings. Result: `realtime_prefix_findings` improved from `164` to `166` (+2) while `public_issue_findings` rose from `200` to `201`.
- Session 2 / Experiment 20: escalated `DEP-MANY-URLS` when a skill mixes many remote URLs with auth/login/MCP context, adding one more medium+ signal for ClawDirect-style workflows. Result: `realtime_prefix_findings` improved from `166` to `167` (+1) while `public_issue_findings` rose from `201` to `204`.
- Session 2 / Experiment 21: added session inventory/reuse coverage (`list active sessions`, `session list`, `close --all`), which pushed browser-use and related browser-session workflows higher in prefix scans. Result: `realtime_prefix_findings` improved from `167` to `169` (+2) while `public_issue_findings` rose from `204` to `208`.
- Session 2 / Experiment 22: added remote-task delegation coverage for cloud/offloaded browser jobs (`remote task`, `task status <id>`, async remote runners). Result: `realtime_prefix_findings` improved from `169` to `172` (+3) while `public_issue_findings` rose from `208` to `211`.
- Session 2 / Experiment 23: expanded skill-path-discovery coverage to script-subdirectory and `{baseDir}/scripts/*` phrasing, which lifted `baoyu-post-to-x` and `baoyu-image-gen` in prefix scans. Result: `realtime_prefix_findings` improved from `172` to `175` (+3) while `public_issue_findings` rose from `211` to `214`.
- Session 2 / Experiment 24: added auth-import-from-user-browser and credential-form-automation detections, which increased `agent-browser` coverage on login/password flows. Result: `realtime_prefix_findings` improved from `175` to `178` (+3) while `public_issue_findings` rose from `214` to `217`.
- Session 2 / Experiment 25: added remote-documentation-ingestion coverage for `WebFetch`/remote-doc-loading guidance, which increased `mcp-builder` prefix findings. Result: `realtime_prefix_findings` improved from `178` to `181` (+3) while `public_issue_findings` rose from `217` to `220`.
- Session 2 / Experiment 26: added MCP-issued-browser-cookie and cookie-bootstrap-redirect detections, which increased `clawdirect` / `clawdirect-dev` coverage on browser-session token handoff flows. Result: `realtime_prefix_findings` improved from `181` to `188` (+7) while `public_issue_findings` rose from `220` to `227`.
- Session 2 / Experiment 27: added UI-state-enumeration coverage for `snapshot -i` / clickable-element-ref workflows, which increased `browser-use` prefix findings. Result: `realtime_prefix_findings` improved from `188` to `189` (+1) while `public_issue_findings` rose from `227` to `228`.
- Session 2 / Experiment 28: added profile-backed-session-persistence coverage (`--profile ... open`, `--session-name ... open`), which increased `agent-browser` and `browser-use` prefix findings around long-lived authenticated browser containers. Result: `realtime_prefix_findings` improved from `189` to `193` (+4) while `public_issue_findings` rose from `228` to `232`.
- Session 2 / Experiment 29: raised compound-browser-action-chaining and credential-form-automation to `high`, which made code-block login/chain examples count as medium+ findings. Result: `realtime_prefix_findings` improved from `193` to `196` (+3) while `public_issue_findings` rose from `232` to `235`.
- Session 2 / Experiment 30: added `state save/load ./auth.json` replay detection and environment-secret-piping detection (`echo "$PASSWORD" | ...`), which sharply increased `agent-browser` prefix findings around reusable auth state. Result: `realtime_prefix_findings` improved from `196` to `200` (+4) while `public_issue_findings` rose from `235` to `239`.
- Session 2 / Experiment 31: added browser-automation capability-contract inference, which increased undeclared-capability findings across browser-use / agent-browser / webapp-testing / playwright-style skills. Result: `realtime_prefix_findings` improved from `200` to `205` (+5) while `public_issue_findings` rose from `239` to `244`.
- Session 2 / Experiment 32: added session-management and content-extraction capability-contract inference, which increased undeclared-capability findings across browser-use / agent-browser / webapp-testing / playwright-style skills. Result: `realtime_prefix_findings` improved from `205` to `211` (+6) while `public_issue_findings` rose from `244` to `250`.
- Session 2 / Experiment 33: added remote-delegation and local-service-access capability-contract inference, which increased undeclared-capability findings for browser-use, mcp-builder, webapp-testing, clawdirect-dev, and playwright-skill. Result: `realtime_prefix_findings` improved from `211` to `215` (+4) while `public_issue_findings` rose from `250` to `254`.
- Session 2 / Experiment 34: added file-read capability-contract inference for prompt bundles, reference files, examples, and local HTML/doc references. Result: `realtime_prefix_findings` improved from `215` to `219` (+4) while `public_issue_findings` rose from `254` to `259`.
- Session 2 / Experiment 35: added process-orchestration and UI-state-access capability-contract inference, which increased undeclared-capability findings for webapp-testing, playwright-skill, docker-expert, and browser-use. Result: `realtime_prefix_findings` improved from `219` to `222` (+3) while `public_issue_findings` rose from `259` to `262`.
- Session 2 / Experiment 36: added filesystem-discovery and credential-handoff capability-contract inference, which increased undeclared-capability findings on baoyu/clawdirect/playwright-style skills. Result: `realtime_prefix_findings` improved from `222` to `227` (+5) while `public_issue_findings` rose from `262` to `267`.
- Session 2 / Experiment 37: added documentation-ingestion, local-input-control, and credential-form-automation capability-contract inference, which increased undeclared-capability findings on mcp-builder, baoyu-post-to-x, and agent-browser. Result: `realtime_prefix_findings` improved from `227` to `230` (+3) while `public_issue_findings` rose from `267` to `270`.
- Session 2 / Experiment 38: added package-bootstrap capability-contract inference, which increased undeclared-capability findings for agent-browser, clawdirect, clawdirect-dev, and the baoyu skills. Result: `realtime_prefix_findings` improved from `230` to `231` (+1) while `public_issue_findings` rose from `270` to `271`.
- Session 2 / Experiment 39: added credential-storage capability-contract inference, which increased undeclared-capability findings around auth vaults, plaintext session tokens, auth cookie stores, and persistent profiles. Result: `realtime_prefix_findings` improved from `231` to `233` (+2) while `public_issue_findings` rose from `271` to `273`.
- Session 2 / Experiment 40: added remote-task-management and server-exposure capability-contract inference, which increased undeclared-capability findings for browser-use, mcp-builder, and clawdirect-style skills. Result: `realtime_prefix_findings` improved from `233` to `239` (+6) while `public_issue_findings` rose from `273` to `279`.
- Session 2 / Experiment 41: added environment-configuration and payment-processing capability-contract inference, which increased undeclared-capability findings around env-var setup and paid/premium actions in baoyu/clawdirect workflows. Result: `realtime_prefix_findings` improved from `239` to `242` (+3) while `public_issue_findings` rose from `279` to `284`.
- Session 2 / Experiment 42: broadened capability inference for `references/`, `cookie-based auth pattern`, and `Call MCP tools via` phrasing, which further increased mcp-builder/clawdirect prefix findings. Result: `realtime_prefix_findings` improved from `242` to `243` (+1) while `public_issue_findings` rose from `284` to `286`.
- Session 2 / Experiment 43: added environment-configuration and payment-processing capability-contract inference, which increased undeclared-capability findings around env-var setup and paid/premium actions in baoyu/clawdirect workflows. Result: `realtime_prefix_findings` improved from `243` to `247` (+4) while `public_issue_findings` rose from `286` to `290`.
- Session 2 / Experiment 44: broadened session-management and credential-form-automation patterns (`session saved`, `already authenticated`, `test login`, `login flow`) and allowed remote-task-management inference from fenced code examples. Result: `realtime_prefix_findings` improved from `247` to `250` (+3) while `public_issue_findings` rose from `290` to `293`.
- Session 2 / Experiment 45: broadened documentation-ingestion patterns to generic `For more information, see`, `See [references/]`, and `Reference Files` phrasing, which increased prefix findings across browser-use, agent-browser, webapp-testing, baoyu-post-to-x, and baoyu-image-gen. Result: `realtime_prefix_findings` improved from `250` to `253` (+3) while `public_issue_findings` rose from `293` to `296`.
- Session 2 / Experiment 46: added broad-scope browser automation phrases (`any automation task you request`, `automating any browser task`, `general-purpose browser automation`) to unrestricted-scope detection, which increased `agent-browser` and `playwright-skill` prefix findings. Result: `realtime_prefix_findings` improved from `253` to `257` (+4) while `public_issue_findings` rose from `296` to `300`.
- Session 2 / Experiment 47: allowed documentation-ingestion and environment-configuration capability inference from fenced examples, and broadened docs inference to generic `references/` paths. Result: `realtime_prefix_findings` improved from `250` to `253` (+3) while `public_issue_findings` rose from `290` to `296`.
- Current artifact to watch: auth-cookie wording can trigger duplicate browser-auth findings on ClawDirect-style skills, and browser-use now shows duplicate full-profile-sync/browser-profile-copy detections. Deduping or merging related browser-auth/profile signals may improve report quality without sacrificing coverage.
- Ideas backlog reviewed and pruned to the two still-promising deferred tracks in `autoresearch.ideas.md`: reusable realtime/prescan API surface and report-quality deduping.
- Near-term promising directions:
  - stronger browser auth/profile/session risk detection
  - local-to-public bridge detection (tunnels, share URLs, remote browser/session attachment)
  - trigger manipulation / overbroad activation detection
  - reusable prescan/realtime APIs built on the same high-confidence lexical rules

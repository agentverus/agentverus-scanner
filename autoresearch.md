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
- **Primary**: `public_issue_findings` (count, higher is better)
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
- Current artifact to watch: auth-cookie wording can trigger duplicate browser-auth findings on ClawDirect-style skills; deduping or merging related browser auth signals may improve report quality without sacrificing coverage.
- Ideas backlog captured in `autoresearch.ideas.md` for deferred realtime/prescan API work and report-quality deduping.
- Near-term promising directions:
  - stronger browser auth/profile/session risk detection
  - local-to-public bridge detection (tunnels, share URLs, remote browser/session attachment)
  - trigger manipulation / overbroad activation detection
  - reusable prescan/realtime APIs built on the same high-confidence lexical rules

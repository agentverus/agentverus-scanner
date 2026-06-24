# AGENTS.md — AgentVerus Scanner

## Project Overview

**agentverus-scanner** is the open-source (MIT) scanning engine that powers [AgentVerus](https://agentverus.ai). It analyzes AI agent skill files (SKILL.md and variants) for security and behavioral risks, produces trust reports with scores 0–100, and outputs SARIF for CI integration.

Published on npm: [`agentverus-scanner`](https://www.npmjs.com/package/agentverus-scanner)

This is the **core IP** — the analysis engine. The web app (`agentverus-web`) is a separate repo that wraps this library with an API, database, and UI.

---

## Tech Stack

| Layer | Technology | Notes |
|-------|-----------|-------|
| Language | TypeScript 5.7+ | Strict mode. ESM only. |
| Runtime | Node.js 22+ | Zero runtime dependencies (only `fflate` for zip) |
| Testing | Vitest | Unit + integration. Coverage target: 80%+ |
| Linting | Biome | Tab indent. Double quotes. Line width 100. |
| Package Manager | pnpm | Workspace monorepo (`pnpm-workspace.yaml`) |
| CI Action | GitHub Actions (composite) | `actions/scan-skill/action.yml` |

### Zero-dependency philosophy

The scanner has exactly **one** runtime dependency (`fflate` for zip decompression). Everything else is built from scratch. No OpenAI SDK, no heavy parsers, no framework bloat. Keep it that way.

---

## Architecture

```
src/
├── scanner/                 # Core scanning engine (npm package entry)
│   ├── index.ts             # Orchestrator: scanSkill(), scanSkillFromUrl()
│   ├── parser.ts            # Multi-format SKILL.md parser
│   ├── analyzers/           # One file per analysis category
│   │   ├── permissions.ts   # ASST-03, ASST-08
│   │   ├── injection.ts     # ASST-01, ASST-06
│   │   ├── dependencies.ts  # ASST-04
│   │   ├── behavioral.ts    # ASST-07, ASST-09
│   │   ├── content.ts       # ASST-02, ASST-05, ASST-10
│   │   ├── semantic.ts      # LLM-assisted deep analysis (optional)
│   │   ├── context.ts       # Cross-analyzer context enrichment
│   │   └── declared-match.ts # Permission declaration matching
│   ├── scoring.ts           # Per-analyzer weighted score aggregation
│   ├── score-calibration.ts # Overall-score calibration + badge-tier rules
│   ├── runner.ts            # Batch scan orchestration
│   ├── targets.ts           # Target expansion (files, dirs, URLs, globs)
│   ├── sarif.ts             # SARIF 2.1.0 output formatter
│   ├── source.ts            # URL fetching with retries
│   ├── cli.ts               # CLI entry point (`agentverus` command)
│   └── types.ts             # All type definitions + ASST taxonomy
├── registry/                # Batch scanning + HTML report generation
│   ├── index.ts             # Registry orchestrator
│   ├── cli.ts               # Registry CLI subcommands
│   ├── batch-scanner.ts     # Parallel batch scanning
│   ├── report-generator.ts  # Markdown report output
│   ├── site-generator.ts    # Static HTML site generator
│   └── types.ts             # Registry-specific types
packages/
└── agentverus-scanner-mcp/  # MCP server wrapper (separate package)
actions/
└── scan-skill/              # GitHub Action (composite)
    ├── action.yml
    └── dist/index.cjs       # Bundled action entry
test/
├── scanner/                 # Scanner tests (mirrors src/scanner/)
└── registry/                # Registry tests
```

### Data Flow

```
Input (file/URL/content)
  → parser.ts (detect format, extract sections)
  → ParsedSkill
  → analyzers/* (each runs independently, returns CategoryScore)
  → scoring.ts (weighted aggregation) → score-calibration.ts (overall score + badge tier)
  → TrustReport
  → Output (JSON / SARIF / CLI table)
```

---

## npm Package Exports

| Export | Path | Purpose |
|--------|------|---------|
| `agentverus-scanner` | `./dist/scanner/index.js` | `scanSkill()`, `scanSkillFromUrl()` |
| `agentverus-scanner/types` | `./dist/scanner/types.js` | All TypeScript types |
| `agentverus-scanner/parser` | `./dist/scanner/parser.js` | `parseSkill()` standalone |
| `agentverus-scanner/source` | `./dist/scanner/source.js` | URL fetching utilities |
| `agentverus-scanner/registry` | `./dist/registry/index.js` | Batch scan + reporting |

### CLI Binaries

- `agentverus` / `agentverus-scanner` — main CLI
- Usage: `npx agentverus-scanner scan <target>` or `npx agentverus-scanner check <target>`

---

## Analyzer Rules

### Each analyzer MUST:

1. Accept a `ParsedSkill` and return a `CategoryScore`
2. Be **pure** — no side effects, no I/O, no database
3. Be **deterministic** — same input → same output
4. Run **independently** — no cross-analyzer dependencies
5. Map every finding to an ASST category

### ASST Taxonomy (Agent Skill Security Threats)

| ID | Name | Primary Analyzer |
|----|------|-----------------|
| ASST-01 | Instruction Injection | injection |
| ASST-02 | Data Exfiltration | content |
| ASST-03 | Privilege Escalation | permissions |
| ASST-04 | Dependency Hijacking | dependencies |
| ASST-05 | Credential Harvesting | content |
| ASST-06 | Prompt Injection Relay | injection |
| ASST-07 | Deceptive Functionality | behavioral |
| ASST-08 | Excessive Permissions | permissions |
| ASST-09 | Missing Safety Boundaries | behavioral |
| ASST-10 | Obfuscation | content |

### Scoring

- Each category scored 0–100 with a weight
- Weights: permissions (0.25), injection (0.30), dependencies (0.15), behavioral (0.20), content (0.10)
- Badge tiers: **certified** (≥80), **conditional** (60–79), **suspicious** (40–59), **rejected** (<40)
- Every deduction traceable to a specific finding — no hidden adjustments

---

## Skill Format Detection

The parser auto-detects format from content:

- **OpenClaw:** YAML frontmatter (`---\nname: ...\n---`) with `name`, `description`, `tools`
- **Claude Code:** Markdown with `## Tools`, `## Instructions`, `## Description` headings
- **Generic:** Any markdown — best-effort extraction from headings and content

---

## Code Style

### TypeScript (enforced by tsconfig strict + Biome)

- **No `any`** — use `unknown` + type guards
- **No non-null assertions (`!`)** — handle null/undefined explicitly
- **Readonly by default** — `readonly` on interface properties, `as const` for literals
- **Exhaustive switch** — `never` default case on union types
- **Explicit return types** on all exported functions
- **Template literals** over concatenation

### Naming

- Files: `kebab-case.ts`
- Types/Interfaces: `PascalCase`
- Functions: `camelCase`
- Constants: `UPPER_SNAKE_CASE`

### Error Handling

- Analyzers never throw — return a fallback `CategoryScore` with score 50 and an info-level finding
- CLI exits with code 1 on scan failure, code 2 on findings above `--fail-on` severity
- URL fetching retries transient errors (configurable via `ScanOptions`)

---

## Commands

```bash
pnpm build          # TypeScript compile to dist/
pnpm test           # Run all tests
pnpm lint           # Biome lint
pnpm format         # Biome format
pnpm typecheck      # tsc --noEmit
pnpm scan <target>  # Scan a skill file, directory, or URL
pnpm build:actions  # Bundle GitHub Action with esbuild
```

### CLI Examples

```bash
# Scan a local file
npx agentverus-scanner scan ./SKILL.md

# Scan a URL
npx agentverus-scanner scan https://raw.githubusercontent.com/org/repo/main/SKILL.md

# Scan a directory (finds all SKILL.md files)
npx agentverus-scanner scan ./skills/

# Check with severity gate (exits non-zero if high+ findings)
npx agentverus-scanner check ./SKILL.md --fail-on high

# SARIF output for CI
npx agentverus-scanner scan ./SKILL.md --sarif results.sarif
```

---

## GitHub Action

```yaml
- uses: agentverus/agentverus-scanner/actions/scan-skill@main
  with:
    target: "."                    # file, URL, or directory
    fail_on_severity: "high"       # critical|high|medium|low|info|none
    upload_sarif: "true"           # upload to GitHub Code Scanning
```

---

## Semantic Analyzer (Optional)

The `semantic.ts` analyzer uses an LLM for deep analysis beyond pattern matching. It's opt-in:

- Enable via `ScanOptions.semantic: true` or pass `SemanticAnalyzerOptions`
- Requires `AGENTVERUS_LLM_API_KEY` env var (or explicit `apiKey`)
- Default model: `gpt-4o-mini` (configurable)
- Falls back gracefully if unavailable — scan still completes without it

---

## Testing

- **Runner:** Vitest with `globals: true`
- **Pattern:** `test/**/*.test.ts` mirrors `src/` structure
- **Naming:** `describe('analyzePermissions')` → `it('should score safe skill above 90')`
- **Coverage:** Each analyzer needs safe-input (high score), malicious-input (low score), and edge-case tests
- **No external calls in tests** — mock URL fetching, mock LLM calls

---

## Commit Conventions

- Conventional commits: `feat:`, `fix:`, `test:`, `chore:`, `docs:`
- Run `pnpm typecheck && pnpm test` before committing
- Keep scanner zero-dependency (unless there's an extraordinary reason)
- Bump `SCANNER_VERSION` in `types.ts` for any behavioral change

---

## Relationship to agentverus-web

| Concern | Scanner (this repo) | Web (agentverus-web) |
|---------|-------------------|---------------------|
| License | MIT (open source) | Private |
| npm | Published | Not published |
| Database | None | PostgreSQL (Neon) |
| API | None (library + CLI) | REST API (Hono) |
| UI | None | Server-rendered (Hono JSX + htmx) |
| Depends on | Nothing | This package |

The web app imports `agentverus-scanner` as a dependency and wraps `scanSkill()` / `scanSkillFromUrl()` behind its API endpoints.

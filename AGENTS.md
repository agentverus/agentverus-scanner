# AGENTS.md — AgentVerus

## Project Overview

**AgentVerus** is an agent and skill trust certification service. It scans AI agent skill files (SKILL.md format and variants), produces detailed security and behavioral trust reports with scores 0-100, and issues verifiable certifications with embeddable SVG badges.

This is a **production product**, not a prototype. Code quality, security, and reliability matter.

### Core Problem

Gen Digital found 15% of OpenClaw skills contain malicious instructions. There is no cross-platform reputation or trust verification system for AI agent skills. AgentVerus fills that gap by providing automated scanning, a public trust registry, and a certification service.

---

## Tech Stack

| Layer | Technology | Notes |
|-------|-----------|-------|
| Language | TypeScript 5.7+ | Strict mode. ESM only. No CommonJS. |
| Runtime | Node.js 22+ | Use native Node APIs where possible |
| Framework | Hono | Lightweight web framework. Routes, middleware, JSX. |
| Web UI | Hono JSX + htmx | Server-rendered HTML. No SPA. Tailwind CSS via CDN. |
| Database | PostgreSQL (Neon Serverless) | Via `@neondatabase/serverless` |
| ORM | Drizzle ORM | Type-safe schema, migrations, queries |
| Validation | Zod | All API inputs validated with Zod schemas |
| Testing | Vitest | Unit + integration tests. Fixtures in test/fixtures/. |
| Linting | Biome | Replaces ESLint + Prettier. Tab indent. Double quotes. |
| Payments | Stripe | Checkout Sessions + Webhooks |
| Email | Resend | Transactional emails |
| Package Manager | pnpm | Not npm. Not yarn. |

---

## File Structure Conventions

```
src/
├── index.ts               # Entry point (starts HTTP server)
├── app.ts                 # Hono app (routes + middleware)
├── scanner/               # Skill Scanner Engine (core IP)
│   ├── index.ts           # Orchestrator: scanSkill(), scanSkillFromUrl()
│   ├── parser.ts          # Multi-format SKILL.md parser
│   ├── analyzers/         # One file per analysis type
│   │   ├── permissions.ts
│   │   ├── injection.ts
│   │   ├── dependencies.ts
│   │   ├── behavioral.ts
│   │   └── content.ts
│   ├── scoring.ts         # Score aggregation
│   └── types.ts           # All scanner type definitions
├── api/v1/                # REST API route handlers
├── api/middleware/         # Auth, rate limiting, error handling
├── db/                    # Database schema, client, migrations
├── badges/                # SVG badge generation
├── payments/              # Stripe integration
├── email/                 # Resend email client + templates
├── web/                   # Server-rendered pages
│   ├── layouts/           # HTML layouts (base.tsx)
│   ├── pages/             # Page components
│   └── components/        # Reusable UI components
├── lib/                   # Shared utilities
test/
├── scanner/               # Scanner unit tests
├── api/                   # API integration tests
├── fixtures/              # Test data
│   ├── skills/            # Sample skill files (safe + malicious)
│   └── reports/           # Expected output snapshots
└── helpers/               # Test utilities
scripts/                   # Operational scripts (bulk scan, etc.)
drizzle/migrations/        # SQL migration files
```

### Naming Conventions

- Files: `kebab-case.ts` (e.g., `rate-limit.ts`). Exception: JSX files use `kebab-case.tsx`.
- Exports: Named exports only. No default exports (except Hono app if needed by platform).
- Types/Interfaces: PascalCase (e.g., `TrustReport`, `ParsedSkill`)
- Functions: camelCase (e.g., `scanSkill`, `analyzePermissions`)
- Constants: UPPER_SNAKE_CASE for true constants, camelCase for config values
- Database columns: snake_case (Drizzle convention)
- API routes: kebab-case paths, camelCase JSON keys in responses

---

## Code Style

### TypeScript Rules (enforced by tsconfig strict + Biome)

- **No `any`** — use `unknown` and narrow with type guards. If `any` is truly unavoidable, add a `// biome-ignore` comment explaining why.
- **No non-null assertions (`!`)** — handle null/undefined explicitly.
- **Readonly by default** — use `readonly` on interface properties and `as const` for literal arrays/objects.
- **Exhaustive switch** — all switch statements on union types must be exhaustive (use `never` default case).
- **Explicit return types** — all exported functions must declare return types.
- **Template literals** over string concatenation.

### Error Handling

- Use custom error classes from `src/api/middleware/errors.ts`
- **Never** throw raw `Error` — always use typed errors: `NotFoundError`, `AuthError`, `ValidationError`, etc.
- All async functions should have proper error boundaries
- Log errors with context (what was being done, relevant IDs)
- API errors return consistent JSON: `{ error: { code: string, message: string, details?: unknown } }`

### Database

- All queries go through Drizzle ORM — no raw SQL
- Use transactions for multi-table writes
- Always include `created_at`, `updated_at` on new tables
- UUIDs for all primary keys (Postgres `gen_random_uuid()`)
- Index frequently filtered/sorted columns

### Testing

- **Test runner:** Vitest with `globals: true`
- **File pattern:** `test/**/*.test.ts` (mirror src/ structure)
- **Fixtures:** `test/fixtures/` — committed to git, never generated at test time
- **Assertions:** Use Vitest's built-in `expect()` — no extra assertion libraries
- **Mocking:** Use Vitest's `vi.mock()` for external services (Stripe, Resend, database)
- **Coverage target:** 80%+ for scanner analyzers; 70%+ overall
- **Test naming:** `describe('analyzePermissions')` → `it('should score safe skill above 90')`
- **Each analyzer** must have tests covering: safe input (high score), malicious input (low score), edge cases

### Security

- All user input validated with Zod before processing
- SQL injection: not a concern with Drizzle ORM (parameterized queries)
- XSS: server-rendered HTML — use Hono's JSX auto-escaping
- CSRF: API is JSON-based with API keys — CSRF tokens for web form submissions
- Rate limiting on all endpoints
- Secrets in env vars only — never in code
- Stripe webhook signature verification — reject unsigned events
- Content-Security-Policy headers on all web pages

---

## Scanner-Specific Guidance

### The ASST Taxonomy (Agent Skill Security Threats)

Our own OWASP-style categorization. Every finding must reference an ASST category:

| ID | Name |
|----|------|
| ASST-01 | Instruction Injection |
| ASST-02 | Data Exfiltration |
| ASST-03 | Privilege Escalation |
| ASST-04 | Dependency Hijacking |
| ASST-05 | Credential Harvesting |
| ASST-06 | Prompt Injection Relay |
| ASST-07 | Deceptive Functionality |
| ASST-08 | Excessive Permissions |
| ASST-09 | Missing Safety Boundaries |
| ASST-10 | Obfuscation |

### Analyzer Architecture

Each analyzer:
1. Takes a `ParsedSkill` object
2. Returns a `CategoryScore` with `score` (0-100), `weight`, `findings[]`, and `summary`
3. Is **pure** — no side effects, no database access, no network calls
4. Is **deterministic** — same input always produces same output
5. Runs **independently** — no analyzer depends on another analyzer's output

### Skill Format Detection

The parser auto-detects format:
- **OpenClaw:** Has YAML frontmatter (`---\nname: ...\n---`) with `name`, `description`, `tools` fields
- **Claude Code:** Markdown with `## Tools`, `## Instructions`, `## Description` headings
- **Generic:** Any markdown — best-effort extraction from headings and content

---

## Commands

```bash
pnpm dev          # Start dev server with hot reload
pnpm build        # TypeScript compile
pnpm test         # Run all tests
pnpm test:unit    # Unit tests only
pnpm test:api     # API integration tests only
pnpm lint         # Biome lint check
pnpm format       # Biome format
pnpm typecheck    # TypeScript strict check
pnpm db:migrate   # Run database migrations
pnpm db:push      # Push schema to DB (dev convenience)
pnpm scan <file>  # Scan a local skill file (CLI tool)
pnpm bulk-scan <urls-file>  # Bulk scan from URL list
pnpm deploy       # Deploy to production
```

---

## Environment Variables

See `.env.example` for all required variables. Key ones:

- `DATABASE_URL` — Neon Postgres connection string
- `STRIPE_SECRET_KEY` — Stripe API key
- `STRIPE_WEBHOOK_SECRET` — For verifying webhook signatures
- `RESEND_API_KEY` — Email sending
- `API_SIGNING_KEY` — ECDSA private key for attestation signing
- `NODE_ENV` — development | production | test

---

## Commit Conventions

- Format: `task X.Y: description` (e.g., `task 1.4: instruction injection detector`)
- Keep commits atomic — one task per commit
- Run `pnpm typecheck && pnpm test` before committing
- No broken commits on main

---

## Key Design Decisions

1. **Hono over Next.js** — We're API-first with server-rendered pages. Hono is simpler, faster, and deploys to more targets. No React hydration overhead.
2. **htmx over React** — Progressive enhancement for interactivity. The registry search uses htmx for live filtering without a JS bundle.
3. **PostgreSQL over SQLite** — We need full-text search, JSONB for reports, and concurrent access for the API. Neon gives us serverless Postgres.
4. **Drizzle over Prisma** — Lighter weight, better TypeScript inference, more SQL-like queries.
5. **Biome over ESLint+Prettier** — One tool, much faster, good defaults.
6. **Score transparency** — Every point in the trust score is traceable to a specific finding. No hidden weights or black-box scoring.

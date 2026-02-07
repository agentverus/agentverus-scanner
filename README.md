# AgentVerus

**Trust, but verify.** The trust certification service for AI agent skills.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## What is AgentVerus?

AgentVerus scans, audits, and certifies AI agent skills. It analyzes skill files (SKILL.md) for security threats, behavioral risks, and compliance issues — then produces a transparent trust score and embeddable badge.

**Why?** Gen Digital found that **15% of OpenClaw skills contain malicious instructions**. Agent skills are the new npm packages — open publishing, dependency chains, and supply chain risk. AgentVerus is the trust layer the agentic web is missing.

## How It Works

1. **Submit** — Provide a skill URL or paste SKILL.md content
2. **Scan** — Our engine analyzes for 10 categories of security threats (the ASST taxonomy)
3. **Score** — Get a transparent trust score (0-100) with detailed findings
4. **Certify** — Paid certification gets you a verified badge and cryptographic attestation

## Trust Score

Every skill receives a trust score from 0-100, composed of five analysis categories:

| Category | Weight | What It Checks |
|----------|--------|----------------|
| **Injection Detection** | 30% | Hidden instructions, prompt injection, social engineering |
| **Permission Analysis** | 25% | Permission scope, necessity, risk level |
| **Dependency Analysis** | 20% | External URLs, downloads, dynamic code execution |
| **Behavioral Risk** | 15% | Autonomous actions, system modification, scope boundaries |
| **Content Safety** | 10% | Safety boundaries, documentation, harmful content |

Grades: **A+** (95-100) → **F** (<60). Every deduction traces to a specific finding.

## ASST — Agent Skill Security Threats

Our OWASP-style taxonomy for agent skill security:

| ID | Threat | Example |
|----|--------|---------|
| ASST-01 | Instruction Injection | "Ignore all previous instructions..." |
| ASST-02 | Data Exfiltration | Hidden POST to external endpoint |
| ASST-03 | Privilege Escalation | Calculator requesting exec permissions |
| ASST-04 | Dependency Hijacking | Dynamic script downloads from pastebin |
| ASST-05 | Credential Harvesting | Reading ~/.ssh/id_rsa |
| ASST-06 | Prompt Injection Relay | Injecting prompts into downstream LLMs |
| ASST-07 | Deceptive Functionality | Mismatch between stated and actual purpose |
| ASST-08 | Excessive Permissions | Spell checker requesting all permissions |
| ASST-09 | Missing Safety Boundaries | No explicit constraints on behavior |
| ASST-10 | Obfuscation | Base64-encoded malicious instructions |

## API

```bash
# Scan a skill
curl -X POST https://agentverus.ai/api/v1/skill/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://github.com/user/repo/blob/main/SKILL.md"}'

# Get trust report
curl https://agentverus.ai/api/v1/skill/{id}/trust

# Get embeddable badge
# Use in markdown: ![AgentVerus](https://agentverus.ai/api/v1/skill/{id}/badge)

# Search the registry
curl "https://agentverus.ai/api/v1/skills?q=weather&grade=A"
```

## Certification Tiers

| Tier | Price | Includes |
|------|-------|----------|
| **Free Scan** | $0 | Trust report + score (no badge) |
| **Basic** | $99/skill | Trust badge + cryptographic attestation + registry listing |
| **Enterprise** | $499/skill | Everything in Basic + detailed export + priority support |

## Badge

Embed a trust badge in your README:

```markdown
[![AgentVerus Score](https://agentverus.ai/api/v1/skill/{id}/badge)](https://agentverus.ai/skill/{id})
```

## Tech Stack

- **TypeScript** / Node.js 22+
- **Hono** — Web framework (API + server-rendered UI)
- **PostgreSQL** — Neon Serverless
- **Drizzle ORM** — Type-safe database access
- **Stripe** — Payments
- **Vitest** — Testing

## Development

```bash
# Install dependencies
pnpm install

# Set up environment
cp .env.example .env
# Edit .env with your credentials

# Push database schema
pnpm db:push

# Start dev server
pnpm dev

# Run tests
pnpm test

# Scan a local skill file
pnpm scan path/to/SKILL.md

# Lint & typecheck
pnpm lint
pnpm typecheck
```

## Project Structure

```
src/
├── scanner/       # Skill Scanner Engine (core IP)
│   ├── analyzers/ # Permission, injection, dependency, behavioral, content
│   ├── parser.ts  # Multi-format SKILL.md parser
│   └── scoring.ts # Score aggregation
├── api/v1/        # REST API routes
├── web/           # Server-rendered pages
├── db/            # Database schema & client
├── badges/        # SVG badge generation
├── payments/      # Stripe integration
└── email/         # Notification emails
```

## Contributing

See [PLAN.md](PLAN.md) for the full project plan with task-by-task breakdown.

## License

MIT

---

Built by [Jonathan Rhyne](https://github.com/jonrhyme). Securing the agentic web, one skill at a time.

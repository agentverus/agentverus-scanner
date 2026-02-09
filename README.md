# AgentVerus Scanner

Open-source security and behavioral trust scanner for AI agent skills (`SKILL.md` and variants).

[![npm version](https://img.shields.io/npm/v/agentverus-scanner)](https://www.npmjs.com/package/agentverus-scanner)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE.md)
[![GitHub Release](https://img.shields.io/github/v/release/agentverus/agentverus-scanner)](https://github.com/agentverus/agentverus-scanner/releases/latest)

<p align="center">
  <img src="assets/social-preview.png" alt="AgentVerus Scanner — detecting hidden threats in AI agent skill files" width="800" />
</p>

## What It Does

Scans agent skill files and produces structured trust reports covering:

- Permission analysis (filesystem/network/exec access)
- Injection detection (prompt injection, instruction override, relay)
- Dependency analysis (external URLs, suspicious downloads)
- Behavioral risk scoring (exfiltration, escalation, stealth patterns)
- Content analysis (obfuscation, concealment, social engineering)

## Install

```bash
npm install --save-dev agentverus-scanner
```

## CLI Usage

<p align="center">
  <img src="assets/terminal-output.png" alt="AgentVerus Scanner CLI output" width="700" />
</p>

```bash
# Scan a local skill file
npx agentverus scan ./SKILL.md

# Scan a directory (recursively finds SKILL.md / SKILLS.md)
npx agentverus scan .

# Scan from URL (GitHub blob/tree/repo URLs + ClawHub pages are normalized)
npx agentverus scan https://github.com/user/repo/blob/main/SKILL.md
npx agentverus scan https://clawhub.ai/<owner>/<slug>

# JSON output
npx agentverus scan ./SKILL.md --json

# SARIF output for GitHub Code Scanning
npx agentverus scan . --sarif agentverus-scanner.sarif --fail-on-severity high
```

### Check a ClawHub Skill

Check any skill from the ClawHub registry by slug — downloads, scans, and prints a trust report:

```bash
# Check a single skill
npx agentverus check web-search

# Check multiple skills
npx agentverus check git-commit docker-build

# JSON output
npx agentverus check web-search --json
```

### Registry Scanning

Batch scan the entire registry, generate reports, and build a static dashboard:

```bash
# Scan all skills in the registry (4,929 skills, ~100s at 50x concurrency)
npx agentverus registry scan --concurrency 50

# Generate the markdown analysis report
npx agentverus registry report

# Generate the interactive HTML dashboard
npx agentverus registry site --title "ClawHub Security Analysis"
```

Registry scan options:
- `--urls <path>` — Path to skill URL list (default: `data/skill-urls.txt`)
- `--out <dir>` — Output directory (default: `data/scan-results`)
- `--concurrency <n>` — Parallel downloads (default: 25)
- `--limit <n>` — Scan only first N skills (for testing)

Exit codes:

- `0`: scan passed
- `1`: scan completed but policy failed
- `2`: one or more targets failed to scan (incomplete results)

## GitHub Action

Use the bundled action to scan `SKILL.md` in PRs and upload SARIF to GitHub Code Scanning:

```yaml
name: Skill Trust Scan
on:
  pull_request:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      # Pin to a release tag or SHA for supply-chain safety and reproducibility.
      - uses: agentverus/agentverus-scanner/actions/scan-skill@v0.3.0
        with:
          target: .
          fail_on_severity: high
          upload_sarif: true
```

## Trust Tier Badges (GitHub Pages)

Generate **repo-level** and **per-skill** trust tier badges as [Shields.io endpoint](https://shields.io/endpoint) JSON:

```bash
# Writes:
# - badges/repo-certified.json
# - badges/repo-certified-pct.json
# - badges/skills/<slug>.json
npx agentverus scan . --badges
```

Badge meanings:

- `repo-certified.json` — **CERTIFIED** only if *every* skill in the repo is `CERTIFIED` (and there are no scan failures). Otherwise **NOT CERTIFIED**.
- `repo-certified-pct.json` — percent of skills that are `CERTIFIED` (e.g. `Certified 83%`).
- `skills/<slug>.json` — per-skill badge (canonical). `slug` is derived from the scanned file path (e.g. `skills/web-search/SKILL.md` → `skills--web-search--SKILL.md.json`).

Embed in your README (example URLs assume you deploy the `badges/` directory as the **GitHub Pages site root**):

```md
![AgentVerus Repo Certified](https://img.shields.io/endpoint?url=https://<owner>.github.io/<repo>/repo-certified.json)
![AgentVerus Certified %](https://img.shields.io/endpoint?url=https://<owner>.github.io/<repo>/repo-certified-pct.json)
```

Per-skill badge:

```md
![AgentVerus Skill](https://img.shields.io/endpoint?url=https://<owner>.github.io/<repo>/skills/<slug>.json)
```

To publish with GitHub Pages, run the badge generation on `push` to `main` and deploy the `badges/` directory:

```yaml
name: Publish AgentVerus Badges
on:
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read
  pages: write
  id-token: write

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: npx agentverus scan . --badges
      - uses: actions/upload-pages-artifact@v3
        with:
          path: badges

  deploy:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/deploy-pages@v4
```

## MCP Server (Agent Integration)

For agent/framework integration via MCP, use the companion package:

```bash
npx -y agentverus-scanner-mcp
```

## Programmatic Usage

```ts
import { scanSkill, scanSkillFromUrl } from "agentverus-scanner";

const report1 = await scanSkill("# My Skill\\n...");
console.log(report1.overall, report1.badge);

const report2 = await scanSkillFromUrl("https://raw.githubusercontent.com/user/repo/main/SKILL.md", {
  timeout: 30_000,
  retries: 2,
  retryDelayMs: 750
});
console.log(report2.metadata.skillFormat, report2.findings.length);
```

## Trust Score

Overall score is a weighted average of category scores:

| Category | Weight |
|----------|--------|
| Permissions | 25% |
| Injection | 30% |
| Dependencies | 20% |
| Behavioral | 15% |
| Content | 10% |

## Badge Tiers

Badge tier rules:

- Any **critical** finding: `REJECTED`
- Score `< 50`: `REJECTED`
- Score `50–74`: `SUSPICIOUS`
- Score `75–89` with `<= 2` high findings: `CONDITIONAL`
- Score `>= 90` with `0` high findings: `CERTIFIED`

## ASST Taxonomy

Findings reference the AgentVerus skill security taxonomy:

- **ASST-01**: Instruction Injection
- **ASST-02**: Data Exfiltration
- **ASST-03**: Privilege Escalation
- **ASST-04**: Dependency Hijacking
- **ASST-05**: Credential Harvesting
- **ASST-06**: Prompt Injection Relay
- **ASST-07**: Deceptive Functionality
- **ASST-08**: Excessive Permissions
- **ASST-09**: Missing Safety Boundaries
- **ASST-10**: Obfuscation
- **ASST-11**: Trigger Manipulation

## Development

```bash
pnpm install
pnpm typecheck
pnpm test
pnpm lint

# Build the action bundle (writes actions/scan-skill/dist/index.cjs)
pnpm build:actions
```

## Contributing

We welcome contributions! See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines on:

- Reporting bugs and false positives
- Adding or improving detection rules
- Writing tests and fixtures
- The pull request process

## Changelog

See [CHANGELOG.md](./CHANGELOG.md) for a full history of changes.

## License

MIT — see [LICENSE.md](./LICENSE.md).

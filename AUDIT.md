# AgentVerus Scanner — Repository Audit & Improvement Plan

> Analysis-only audit. No code was modified. Findings are evidence-cited (file:line) and
> labeled **[Fact]** (verified in code/command output) vs **[Judgment]** (assessment).
> Date: 2026-06-16. Repo HEAD on `origin/main` (v0.8.0), working tree clean.
>
> **Rev 2 (2026-06-17):** Revised after an adversarial review of Rev 1. Changes: split the
> grade into core-library vs release-posture; re-ranked the live published MCP above CI;
> split the dependency finding into dev-only / shipped-unreachable / shipped-reachable with
> advisory IDs + reachability evidence; moved the ReDoS claim out of "rejected" into an open
> verification item; re-sequenced the plan to remediate the live package before building CI.

## Executive Summary

**Health Grade: core library B+ · release/ops posture D · composite ≈ C+.**

A single letter hides the real shape of this repo, so it's split. The **scanning library** is
disciplined, defensively coded, and security-aware in ways that are rare (declared permissions
explicitly treated as untrusted; semantic LLM analysis never auto-runs to avoid data egress); 243
tests pass in ~400 ms — that part earns a **B+**. The **release/operational shell** around it earns
a **D**: there is **no CI at all**, the published MCP package's version is **ahead of committed
source with no tag**, so what actually shipped can't be attested, and that package carries a
vulnerable transitive tree. For a tool whose entire value proposition is *trust*, an unattestable
release is the most serious problem here — more than any single code defect.

**Top 3 risks** (re-ranked: the live published artifact comes before the missing pipeline)
1. **The published MCP (`agentverus-scanner-mcp@0.1.1`) is unattestable.** npm is at 0.1.1 while the
   repo says 0.1.0, there is no matching git tag, and no CI built it — so nobody can prove what code
   the 0.1.1 tarball contains. A trust scanner that can't attest its own release undercuts its
   premise. (Finding **C1**.)
2. **That same package ships a vulnerable dependency tree.** `pnpm audit`: 47 advisories. The fix
   (bump the MCP SDK) is cheap, but until it's republished the live package keeps the exposure.
   Severity is genuinely mixed and is split out below — most of it is *not* reachable under the
   server's stdio transport, but it is shipped. (Finding **C1**.)
3. **No CI/CD whatsoever** (no `.github/`, no pipeline). This is the *systemic* gap — the absence of
   a verification gate is what allows risks #1 and #2 to exist unnoticed and leaves every future
   change unverified, including the 270 KB committed action bundle. It is the root-cause control to
   add, not a live exposure in itself. (Finding **C2**.)

**Top 3 opportunities**
1. **Remediate + re-attest the live package first** (bump SDK, smoke-test, republish at a tag that
   matches source). Closes risks #1 and #2 directly.
2. **One afternoon of CI** (test + lint + typecheck + audit + bundle-diff + publish-on-tag) makes the
   re-attestation permanent and every future change safe.
3. **Lock the verdict seam with direct calibration tests + a golden-fixture corpus**, then collapse
   the duplicated regex/scoring machinery behind that safety net.

Calibration note: this is a **mature v0.8 product with real users and two published npm packages**,
not a prototype. Recommendations are about hardening and re-attestation, not rearchitecting working code.

## Repo Map

**Purpose.** A security/behavioral trust scanner for AI agent skill files (`SKILL.md`). Ingests a skill
(local file, dir, GitHub URL, ClawHub slug, remote zip), runs six weighted regex/heuristic analyzers plus
optional companion-code and LLM-semantic passes, emits a 0–100 trust score + badge tier (certified →
conditional → suspicious → rejected). Outputs: terminal, JSON, SARIF, CycloneDX SBOM, Shields.io badges.

**Stack.** TypeScript (strict, ES2022, ESM), Node ≥22, pnpm workspace, Biome, Vitest. **One** runtime dep
in the core package: `fflate`. The MCP package ships three runtime deps: `@modelcontextprotocol/sdk`
(`^1.26.0`, installed 1.26.0), `agentverus-scanner` (`workspace:^`), `zod` (`^4.3.6`). Published as
`agentverus-scanner` (CLI + lib) + a separate `agentverus-scanner-mcp` package + a composite GitHub Action.

**Publish status [Fact, verified via npm view]:**
- `agentverus-scanner`: local 0.8.0 → npm 0.8.0 (in sync).
- `agentverus-scanner-mcp`: local `package.json` 0.1.0 → **npm 0.1.1** (npm AHEAD of repo — release cut
  without the version bump landing in git; no git tag anchors the 0.1.1 tarball to any commit).

**Control flow.**
```
cli.ts → targets.ts → runner.ts → index.ts: scanSkill()
  ├ parser.ts (frontmatter, sections, URLs, declared perms)
  ├ Promise.all([permissions, injection, dependencies, behavioral, content, code-safety])
  ├ semantic.ts (opt-in LLM, weight 0, additive)
  └ scoring.ts → score-calibration.ts (weights, penalties, badge tiers) → report-shaping.ts
registry/ → batch-scanner.ts (bounded concurrency) → report/site generators (HTML dashboard)
packages/agentverus-scanner-mcp/ → server.ts (MCP stdio: normalize_skill_url + scan_skill)
```

## Audit Report

### Critical

**C1. The live published MCP package is unattestable and ships a vulnerable tree. [Fact]**
*(Rev 2: merges Rev 1's H2 + H5; the dependency tree is split by reachability per the adversarial review.)*
This is one finding because the two halves compound: a package you can't attest, carrying known
advisories, is worse than either alone.

- **(a) Provenance — cannot attest what shipped.** `agentverus-scanner-mcp` is published at **0.1.1**
  while the repo's `package.json` says **0.1.0**; there is no `v0.1.1` tag and no CI build record. The
  shipped tarball includes only `dist` + runtime deps (`files: ["dist","README.md","LICENSE.md"]`), so
  there is no source in the tarball either. Result: **no way to prove the 0.1.1 npm artifact corresponds
  to any commit.** For a security/trust tool this is the single most serious issue in the repo.
- **(b) Dependency exposure — `pnpm audit`: 47 advisories (1 crit · 12 high · 30 mod · 4 low).** The raw
  count is misleading; split by where it lives and whether it's reachable:

  | Bucket | Reachable in normal use? | Examples (advisory IDs) |
  |---|---|---|
  | **Dev-toolchain only** — under `.>vitest`/`esbuild`, **never in the tarball** | No (not shipped) | the **only critical**: `vitest@<4.1.0` GHSA-5xrq-8626-4rwp; `rollup` GHSA-mw96-cpmx-2vgc; `vite` GHSA-v2wj-q39q-566r; `picomatch` GHSA-c2c7-rcm5-vvqj; `esbuild`, `postcss` |
  | **Shipped but unreachable under stdio** — the SDK's HTTP/SSE transport stack | No (server uses stdio only) | `hono` GHSA-88fw-hqm2-52qc / GHSA-q5qw-h33p-qvwr; `@hono/node-server` GHSA-wc8c-qw6v-h7f6; `express-rate-limit` GHSA-46wh-pxpv-q5gq; `path-to-regexp` GHSA-j3q9-mxjg-w52f; `qs`; `ip-address` |
  | **Shipped and plausibly reachable** — JSON-schema validation of tool inputs | Possibly | `fast-uri` GHSA-q3j6-qgpj-74h6 / GHSA-v39h-62p7-jpjc (high, ReDoS-class); `ajv` GHSA-2g4f-4pwh-qvx6 |

  Reachability evidence: `server.ts:5,96-97` instantiates **`StdioServerTransport` only** — it never
  starts an HTTP listener, so the `hono`/`express`/`path-to-regexp` advisories are present in the install
  tree but not on any executed path in normal operation. They become reachable only if a downstream
  consumer wires the SDK's Streamable-HTTP transport. The genuinely shipped-and-reachable subset is the
  `ajv`/`fast-uri` JSON-schema validator the SDK uses on incoming tool calls.
- **Net severity [Judgment]:** Critical *priority* (live, published, security tool, trivially fixable),
  but the runtime *exploitability* in the shipped stdio configuration is **lower than the 12-high count
  implies** — most highs are an unreachable HTTP stack; the real runtime concern is the `ajv`/`fast-uri`
  validation path. The provenance gap (a) is what makes this Critical regardless of severity arithmetic.
- **Fix:** bump `@modelcontextprotocol/sdk` past the advisories, regenerate the lockfile, smoke-test the
  stdio server, then **republish at a tag-anchored version that matches committed source.**

**C2. No CI pipeline exists — the systemic control whose absence enables C1. [Fact]** No `.github/`,
`.gitlab-ci.yml`, or any CI config. The composite action (`actions/scan-skill/action.yml`) executes a
committed 270 KB bundle (`actions/scan-skill/dist/index.cjs`) regenerated by `scripts/build-actions.mjs`;
nothing verifies the bundle matches source. *Why this is framed as systemic, not the top live risk:* CI is
not itself an exposure — it is the missing gate that lets an unattestable, vulnerable package (C1) ship and
leaves every future change (bundle drift, failing tests, lint, audit regressions) unverified. Add it to
*prevent recurrence* after C1 is remediated.

### High

**H3. The scoring/calibration seam has no direct tests. [Fact]** `src/scanner/score-calibration.ts` (the
module that computes the score, applies severity penalties, decides the badge) is imported by no test
file; exercised only transitively via `scoring.test.ts`. `url-risk.ts` and `setup-context.ts` likewise
have zero direct coverage. `calculateOverallScore`/`applySeverityPenalty` (`score-calibration.ts:53-81`)
contain non-obvious arithmetic (the `Math.max(catScore.score, 30)` floor, drag thresholds) that's easy to
break silently. *Why:* this is the highest-consequence logic — it's the verdict.

**H4. SSRF defense is strong but its IPv4 path is untested. [Fact/Judgment]** `source.ts:297-318`
(`isBlockedIpv4`) blocks loopback/private/CGNAT/link-local, but `test/scanner/source-ssrf.test.ts` covers
only **IPv6** (7 cases). No direct test for `localhost`, `127.0.0.1`, `10.x`, `192.168.x`, or
`169.254.169.254` (cloud metadata). *Why [Judgment]:* security-critical boundary for embedding the
library; a regression would pass unnoticed.

### Medium

**M5. Threat patterns maintained in two parallel files. [Fact]** `behavioral-config.ts` and
`capability-contract-config.ts` define near-identical regex banks with no shared import: auth-state
(`behavioral-config.ts:350-359` vs `capability-contract-config.ts:258-265`), credential-store persistence
(`687-696` vs `345-350`), browser-profile copy (`285-295` vs `299-305`). *Why:* a pattern update must
land in two places or the analyzers silently disagree.

**M6. Score-recompute block copy-pasted across 5 analyzers. [Fact]** The identical
`let score = 100; for (const f of findings) score = Math.max(0, score - f.deduction)` loop appears in
`dependencies.ts:841-844`, `behavioral.ts:175-178`, `permissions.ts:197-200`, `content.ts:432-438`,
`injection.ts:568-571`. Three different `downgradeSeverity` helpers with different signatures in
`injection.ts:448`, `behavioral.ts:9`, `code-safety.ts:391`. *Why:* duplicated scoring logic is where
calibration bugs hide.

**M7. God-functions in dependency/capability analyzers. [Fact/Judgment]** `analyzeDependencies` is a
single ~370-line function (`dependencies.ts:491-863`). `inferCapabilities`
(`capability-contract.ts:263-598`) is 37 sequential near-identical `firstPositiveMatch`→`add` pairs — a
textbook data-driven-table candidate. *Why [Judgment]:* high complexity in the exact code that produces
findings; easy to introduce a missed branch.

### Low

**L8. Two LLM-response casts without field validation. [Fact]** `semantic.ts:193-205` casts
`response.json()` then `JSON.parse(cleaned) as LlmResponse` with only an `Array.isArray(parsed.findings)`
guard. Low impact (opt-in, additive, weight 0, fully try/caught). Note: `zod` is a runtime dep of the MCP
package but **not** of the core package (core's only runtime dep is `fflate`), so adding Zod validation
here means adding a core dependency — a deliberate tradeoff, not a free win.

**L9. `data/skill-urls.txt` is the documented default but is gitignored. [Fact]** README:121 /
`cli.ts:660` default `--urls` to `data/skill-urls.txt`, but `.gitignore` excludes `data/`. A fresh clone
has no such file → `registry scan` fails on first run with no guidance.

**L10. Doc drift. [Fact]** `AGENTS.md` architecture section never mentions `score-calibration.ts`
(`grep -c` → 0) though the v0.7 refactor split scoring into it.

**L11. `content.ts` baseline is 80, not 100. [Fact]** `content.ts:138` (`let score = 80`) — intentional
("skills must earn the top 20") but inconsistent with every other analyzer's 100 baseline and
undocumented at the aggregation site.

### Open verification items (not yet a defect, not yet cleared)

**V1. ReDoS in credential/exfil regexes — needs worst-case evidence before dismissal. [Judgment]**
*(Rev 2: moved here from "rejected" per the adversarial review — the original dismissal rested on
insufficient evidence.)* Flagged patterns (`capability-contract-config.ts:175`, `injection.ts:45`) ran
in **<1 ms** against pathological 500-char repeated inputs, and `source.ts` enforces byte caps (2 MB text,
256 KB/companion). That is *suggestive* but not sufficient: it doesn't cover crafted near-cap inputs,
aggregate many-pattern scans, or companion-code paths up to the full caps. Note this isn't purely
theoretical in context — the shipped `fast-uri` advisories (C1) are themselves ReDoS-class, so the class
is live in dependencies regardless. **Action:** add a regex microbench/fuzz harness against worst-case
inputs sized to the configured caps, with an explicit per-scan timeout budget, before declaring it
non-exploitable. Low/medium until then.

### Claims checked and REJECTED (do not add to backlog)
- **"`extractSelfBaseDomains` is dead code"** — FALSE. Imported and called at `index.ts:4` and
  `index.ts:180`. Verified.
- **"`.DS_Store` is git-tracked"** — FALSE. `git ls-files .DS_Store` is empty.
- **"CONTRIBUTING.md has a broken CHANGELOG link"** — FALSE. `CHANGELOG.md` exists at root.

### Strengths (do not regress)
- **Defense-in-depth.** `declared-match.ts:108-113` documents declared permissions as untrusted; must
  not suppress findings.
- **No accidental data egress.** `index.ts:167-171` refuses to auto-run semantic analysis just because an
  API key exists.
- **Context-aware matching.** `context.ts:33-80` precomputes line offsets / code-block / safety-section
  ranges once per skill.
- **Offline-safe network tests.** Remote-companion + batch-scanner tests fully mock `fetch` / use `data:`
  URLs (one nit: `semantic.test.ts:33` opens a real socket to `127.0.0.1:1`).
- **Honest failure handling.** `index.ts:26-48` turns analyzer crashes into high-severity findings that
  block certification rather than silently passing.

## Improvement Strategy

| Theme | Findings | Target state | Principle |
|---|---|---|---|
| **A. The live release is unattestable** | C1 | MCP republished at a tag-anchored version matching source, with a clean shipped-dep audit | A trust tool must be able to attest its own artifacts |
| **B. No automated safety net** | C2, H3, H4 | CI gates every PR (test+lint+typecheck+audit+bundle-diff) and publishes on tag; verdict path + IPv4 SSRF directly tested | A security tool must hold itself to its own standard |
| **C. Detection logic is duplicated** | M5, M6, M7 | One shared pattern bank + one scoring helper; data-driven capability table | One source of truth for threat patterns |
| **D. Input-boundary robustness** | V1, L8, L11 | Worst-case ReDoS bench; document scoring baselines; validate LLM JSON | Validate at every layer data crosses |
| **E. Repo hygiene** | L9, L10 + tracked autoresearch clutter | Clean root, accurate docs | Ordinary housekeeping (product, not showcase) |

**Explicitly NOT fixing:** rewriting the scoring model (it works — test-cover and de-dup only); the
committed-bundle pattern itself (standard for composite actions — just *verify* it in CI); backfilling
`cli.ts` tests (intentionally coverage-excluded). ReDoS is **no longer** on this list — it is open item V1.

**Definition of done (measurable):** `agentverus-scanner-mcp` republished at a version that matches a git
tag, with `pnpm audit --prod` 0 high/critical in shipped packages; CI fails on any failing
test/lint/type/audit error and on action-bundle drift; `score-calibration.ts` / `url-risk.ts` / IPv4 SSRF
each directly tested, verdict logic ≥80% line coverage; threat patterns have exactly one definition site;
V1 closed with a recorded worst-case benchmark.

## Task Plan

Effort: S <2h · M half-day · L 1–2 days · XL needs breakdown.

> **Sequencing note (Rev 2):** remediation of the live package (Milestone 0) now comes **before** CI.
> The vulnerable, unattestable package is live *now*; CI is the control that keeps it fixed, but it is not
> a prerequisite for stopping the bleeding. Fix and re-attest first, then build the gate.

### Milestone 0 — Remediate & re-attest the live MCP package (do first)
- **T0.1 — Patch the published MCP's dep tree.** `packages/agentverus-scanner-mcp/package.json`,
  `pnpm-lock.yaml`. AC: bump `@modelcontextprotocol/sdk` to a release past the `hono`/`ajv`/`fast-uri`
  advisories; regenerate lockfile; `pnpm audit --prod` shows 0 high/critical in shipped packages.
  **S–M · Medium (SDK minor/major may shift the MCP API — covered by T0.2) · quick win.**
- **T0.2 — MCP server smoke test.** `packages/agentverus-scanner-mcp/test/server.test.ts` (new). AC:
  in-process call to `scan_skill` + `normalize_skill_url` over stdio returns well-formed report JSON; runs
  against the bumped SDK to confirm compatibility. **M · Low.**
- **T0.3 — Republish at a tag-anchored version.** AC: bump committed `package.json` to lead npm (≥0.1.2),
  cut a matching git tag, publish; record the tag↔version↔commit linkage so 0.1.2 is attestable. If a bump
  can't be cut promptly, deprecate 0.1.1 on npm with a pointer to the fix. **S · Low.**

### Milestone 1 — Safety net (prevent recurrence)
- **T1.1 — GitHub Actions CI.** `.github/workflows/ci.yml` (new). AC: on PR + push to main, runs install
  (frozen lockfile), typecheck, lint, test; builds the action bundle and `git diff --exit-code
  actions/scan-skill/dist/`; runs `pnpm audit --prod --audit-level high`; adds publish-on-tag with a
  version-matches-tag check (this makes T0.3 permanent). **S · Low · quick win.**
- **T1.2 — Direct verdict-path tests.** `score-calibration.test.ts`, `url-risk.test.ts` (new). AC: badge
  boundaries (49/50/74/75/89/90, config-tamper cap, critical→rejected), `applySeverityPenalty` drag, the
  `Math.max(score,30)` floor. **M · Low.**
- **T1.3 — IPv4 SSRF tests + any fixes surfaced.** `test/scanner/source-ssrf.test.ts`. AC: block
  `localhost`, `127.0.0.1`, `0.0.0.0`, private ranges, `169.254.169.254`, and a hostname resolving to a
  private IP (mock `dns.lookup`). **S · Low · quick win.**
- **T1.4 — Golden-fixture end-to-end test.** `test/scanner/golden.test.ts` (new). AC: assert exact badge +
  score-bucket for ~8 representative fixtures (one per tier + config-tamper + evasion). **M · Low.**

### Milestone 2 — High-leverage refactors (behind the safety net)
- **T2.1 — Single threat-pattern bank.** New `shared-patterns.ts`; edit both config files. **M · Medium
  (T1.4 catches drift).**
- **T2.2 — Extract shared scoring helper.** New `score-util.ts`; edit 5 analyzers + unify
  `downgradeSeverity`. **M · Low.**
- **T2.3 — Data-drive `inferCapabilities`.** `capability-contract.ts`. **M–L · Medium.**

### Milestone 3 — Quality & polish
- **T3.1 — Close V1 (ReDoS bench).** New `test/scanner/regex-redos.bench.ts`: worst-case inputs sized to
  the 2 MB / 256 KB caps, per-scan timeout budget; record results in the finding. **S–M · Low.**
- **T3.2 — Clean repo root.** `git rm --cached` autoresearch + stale v0.4 docs; add `autoresearch.*` to
  `.gitignore`. **S · Low · quick win.** (Autoresearch loop confirmed stopped — one-time cleanup.)
- **T3.3 — Doc fixes.** `AGENTS.md` (add `score-calibration.ts`), README registry note (`data/skill-urls.
  txt` must be created or ship `data/skill-urls.example.txt` outside the ignore). **S · Low · quick win.**
- **T3.4 — Validate LLM JSON.** `semantic.ts` — only if a validator dep is acceptable in core. **S · Low.**

### Quick wins (this week, in dependency order)
**T0.1** (patch MCP deps) → **T0.2** (MCP smoke test) → **T0.3** (republish at tag) → **T1.1** (CI) →
**T1.3** (IPv4 SSRF) → **T3.2** (clean root).

### Implementation sketches

**T1.1 — CI workflow**
```yaml
name: CI
on: { pull_request: {}, push: { branches: [main] } }
jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
      - uses: actions/setup-node@v4
        with: { node-version: 22, cache: pnpm }
      - run: pnpm install --frozen-lockfile
      - run: pnpm typecheck
      - run: pnpm lint
      - run: pnpm test
      - run: pnpm build:actions
      - run: git diff --exit-code actions/scan-skill/dist/   # bundle must match source
      - run: pnpm audit --prod --audit-level high            # hard-fail once T0.1 lands
```

**T1.3 — IPv4 SSRF tests**
```ts
import { fetchSkillContentFromUrl } from "@/scanner/source";
import * as dns from "node:dns/promises";

it.each(["https://localhost/SKILL.md","https://127.0.0.1/SKILL.md",
  "https://169.254.169.254/latest/meta-data/"])("blocks %s", async (url) => {
  await expect(fetchSkillContentFromUrl(url)).rejects.toThrow(/Blocked|not allowed/);
});
it("blocks a hostname resolving to a private IP", async () => {
  vi.spyOn(dns, "lookup").mockResolvedValue([{ address: "10.0.0.5", family: 4 }] as any);
  await expect(fetchSkillContentFromUrl("https://evil.example/SKILL.md")).rejects.toThrow(/Blocked/);
});
```

**T2.2 — Shared scoring helper**
```ts
export function recomputeScore(findings: readonly Finding[], base = 100): number {
  let s = base;
  for (const f of findings) s = Math.max(0, s - f.deduction);
  return Math.max(0, Math.min(100, s));
}
```

## Open Questions
1. **What corpus calibrates the scoring weights?** `score-calibration.ts` weights look hand-tuned. If
   there's a labeled ground-truth set (the `data/` scan results?), T1.4's golden fixtures should draw from
   it so tests reflect calibration intent. (Still open.)
2. **Is the SDK bump (T0.1) a minor or a breaking jump?** Installed is `1.26.0` under a `^1.26.0` range;
   the advisories may require a newer minor or a major. T0.2 exists to catch API drift either way.
3. *(Closed)* Autoresearch loop stopped; product not showcase; MCP confirmed published at 0.1.1.

## Appendix A — Raw advisory breakdown

Source: `pnpm audit --json` at HEAD, 2026-06-16. Totals: **1 critical · 12 high · 30 moderate · 4 low = 47**.
Bucket legend (see C1 for the reachability argument):
- **dev** — under `.>vitest`/`esbuild`; **not in the published tarball**; affects contributors/CI only.
- **ship-unreach** — shipped transitively under `@modelcontextprotocol/sdk` but on the HTTP/SSE transport
  stack; **not on any executed path** because `server.ts:96` uses `StdioServerTransport` only.
- **ship-reach** — shipped and plausibly executed (JSON-schema validation of tool inputs).

| Severity | Package / vulnerable range | Advisory | Bucket | Summary |
|---|---|---|---|---|
| critical | `vitest` >=4.0.0 <4.1.0 | GHSA-5xrq-8626-4rwp | dev | Vitest UI server arbitrary file access |
| high | `fast-uri` <=3.1.0 | GHSA-q3j6-qgpj-74h6 | ship-reach | Path traversal via percent-encoding |
| high | `fast-uri` <=3.1.1 | GHSA-v39h-62p7-jpjc | ship-reach | Host confusion via percent-encoding |
| high | `@hono/node-server` <1.19.10 | GHSA-wc8c-qw6v-h7f6 | ship-unreach | Authorization bypass for protected routes |
| high | `express-rate-limit` >=8.2.0 <8.2.2 | GHSA-46wh-pxpv-q5gq | ship-unreach | IPv4-mapped IPv6 rate-limit bypass |
| high | `hono` <4.12.4 | GHSA-q5qw-h33p-qvwr | ship-unreach | Arbitrary file access via serveStatic |
| high | `hono` <4.12.25 | GHSA-88fw-hqm2-52qc | ship-unreach | CORS middleware reflects any Origin |
| high | `path-to-regexp` >=8.0.0 <8.4.0 | GHSA-j3q9-mxjg-w52f | ship-unreach | ReDoS via crafted path |
| high | `picomatch` >=4.0.0 <4.0.4 | GHSA-c2c7-rcm5-vvqj | dev | ReDoS via extglob quantifier |
| high | `rollup` >=4.0.0 <4.59.0 | GHSA-mw96-cpmx-2vgc | dev | Arbitrary file write via path traversal |
| high | `vite` >=7.1.0 <=7.3.1 | GHSA-v2wj-q39q-566r | dev | `server.fs.deny` bypass via queries |
| high | `vite` >=7.0.0 <=7.3.1 | GHSA-p9ff-h696-f583 | dev | Arbitrary file read via dev server |
| high | `vite` >=7.0.0 <=7.3.4 | GHSA-fx2h-pf6j-xcff | dev | `server.fs.deny` bypass on Windows |
| moderate | `ajv` >=7.0.0-alpha.0 <8.18.0 | GHSA-2g4f-4pwh-qvx6 | ship-reach | ReDoS via `$data` option |
| moderate | `@hono/node-server` <1.19.13 | GHSA-92pp-h63x-v22m | ship-unreach | Middleware bypass via repeated slashes |
| moderate | `hono` <4.12.4 | GHSA-5pq2-9x2x-5p6w | ship-unreach | Cookie attribute injection |
| moderate | `hono` <4.12.4 | GHSA-p6xx-57qc-3wxr | ship-unreach | SSE control-field injection |
| moderate | `hono` <4.12.7 | GHSA-v8w9-8mx6-g223 | ship-unreach | Prototype pollution |
| moderate | `hono` <4.12.12 | GHSA-26pp-8wgv-hjvm | ship-unreach | Missing cookie-name validation |
| moderate | `hono` <4.12.12 | GHSA-r5rp-j6wh-rvv4 | ship-unreach | Non-breaking-space cookie-name bypass |
| moderate | `hono` >=4.0.0 <=4.12.11 | GHSA-xf4j-xp2r-rqqx | ship-unreach | Path traversal in toSSG() |
| moderate | `hono` <4.12.12 | GHSA-wmmm-f939-6g9c | ship-unreach | Middleware bypass via repeated slashes |
| moderate | `hono` <4.12.14 | GHSA-458j-xx4x-4375 | ship-unreach | JSX attribute-name HTML injection |
| moderate | `hono` <4.12.12 | GHSA-xpcf-pg52-r92g | ship-unreach | Incorrect IP matching in ipRestriction() |
| moderate | `hono` <4.12.18 | GHSA-qp7p-654g-cw7p | ship-unreach | CSS declaration injection |
| moderate | `hono` <4.12.18 | GHSA-p77w-8qqv-26rm | ship-unreach | Cache middleware ignores Vary: Authorization |
| moderate | `hono` <4.12.16 | GHSA-9vqf-7f2p-gf9v | ship-unreach | bodyLimit() bypass on chunked bodies |
| moderate | `hono` <4.12.16 | GHSA-69xw-7hcm-h432 | ship-unreach | Unvalidated JSX tag names |
| moderate | `hono` <4.12.21 | GHSA-xrhx-7g5j-rcj5 | ship-unreach | IP restriction bypass of static deny |
| moderate | `hono` <4.12.21 | GHSA-3hrh-pfw6-9m5x | ship-unreach | Cookie helper sameSite not sanitized |
| moderate | `hono` <4.12.21 | GHSA-f577-qrjj-4474 | ship-unreach | JWT middleware accepts any auth scheme |
| moderate | `hono` <4.12.21 | GHSA-2gcr-mfcq-wcc3 | ship-unreach | app.mount() prefix strip on undecoded path |
| moderate | `hono` <4.12.25 | GHSA-wwfh-h76j-fc44 | ship-unreach | serve-static path traversal on Windows |
| moderate | `hono` <4.12.25 | GHSA-j6c9-x7qj-28xf | ship-unreach | Lambda adapter Set-Cookie merge |
| moderate | `hono` <4.12.25 | GHSA-rv63-4mwf-qqc2 | ship-unreach | Body-limit bypass on AWS Lambda |
| moderate | `hono` <4.12.25 | GHSA-wgpf-jwqj-8h8p | ship-unreach | Lambda@Edge adapter header loss |
| moderate | `ip-address` <=10.1.0 | GHSA-v2v4-37r5-5v8g | ship-unreach | XSS in Address6 HTML methods |
| moderate | `path-to-regexp` >=8.0.0 <8.4.0 | GHSA-27v5-c462-wpq7 | ship-unreach | ReDoS |
| moderate | `picomatch` >=4.0.0 <4.0.4 | GHSA-3v7f-55p6-f55p | dev | Method injection in POSIX classes |
| moderate | `postcss` <8.5.10 | GHSA-qx2v-qp2m-jg93 | dev | XSS via unescaped `</style>` |
| moderate | `qs` >=6.11.1 <=6.15.1 | GHSA-q8mj-m7cp-5q26 | ship-unreach | DoS via qs.stringify |
| moderate | `vite` >=7.0.0 <=7.3.1 | GHSA-4w7w-66w2-5vf9 | dev | Path traversal in optimized deps |
| moderate | `vite` >=7.0.0 <=7.3.4 | GHSA-v6wh-96g9-6wx3 | dev | launch-editor NTLMv2 hash disclosure |
| low | `esbuild` >=0.27.3 <0.28.1 | GHSA-g7r4-m6w7-qqqr | dev | Arbitrary file read in dev |
| low | `hono` <4.11.10 | GHSA-gq3j-xvxp-8hrf | ship-unreach | basicAuth timing hardening |
| low | `hono` <4.12.18 | GHSA-hm8q-7f3q-5f36 | ship-unreach | Improper NumericDate validation |
| low | `qs` >=6.7.0 <=6.14.1 | GHSA-w7fw-mjwx-w883 | ship-unreach | arrayLimit bypass DoS |

**Reading this table:** every `dev` row (incl. the only critical) is excluded from the published tarball.
Every `ship-unreach` row requires the SDK's HTTP transport, which `server.ts` never instantiates. The two
`ship-reach` highs (`fast-uri`) plus the `ajv`/`fast-uri` moderates are the only rows on a plausibly
executed path, and even those sit behind the SDK's input-validation layer. The remediation (bump the SDK,
regenerate the lockfile) clears the transitive `hono`/`ajv`/`fast-uri` ranges regardless of bucket.
```

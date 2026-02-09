# Plan: AgentVerus Scanner Security Gate Hardening

**Generated**: 2026-02-09  
**Estimated Complexity**: High

## Overview
Harden `agentverus-scanner` so it cannot be trivially bypassed into a `CERTIFIED` badge for unsafe skills. The core work is to:

- Remove suppression mechanisms that treat untrusted author-provided text as “verified safe” (declared permissions, “safety section”, negation).
- Fix early-break logic that hides later matches.
- Tighten certification criteria to avoid a false sense of security (medium/low findings, missing boundaries, analyzer failures).
- Make LLM semantic analysis explicit opt-in to prevent accidental data egress.
- Harden remote fetching (SSRF posture for MCP/service embedding, zip bomb limits).
- Tighten URL trust heuristics and improve permission parsing so it’s harder to evade.

This plan is organized as short, committable tasks with tests so we can confidently ship within hours.

## Clarifying Questions (Policy)
These choices impact badge distribution and may be breaking changes for users relying on the current scoring.

1. Should `certified` require **zero** `medium` findings, or allow a small number (for example: allow 1 medium if it’s only `permissions` and is `network_restricted`)?
2. Should “missing safety boundaries” (`CONT-NO-SAFETY`) **block `certified`** (even if overall score is high), or just lower score?
3. Should author-declared permissions ever reduce score impact, or should they be **display-only** (no scoring effect) because declarations are untrusted?
4. For content inside “Safety Boundaries / Limitations” headings: should we (a) downgrade but still score, (b) record as `info` with 0 deduction, or (c) keep severity but mark as “educational context”?
5. Should semantic (LLM) analysis be strictly **opt-in only** (`--semantic`) even if `AGENTVERUS_LLM_API_KEY` is set, or do you want an explicit “opt-in auto” env var for CI?
6. For analyzer exceptions: should a scan with any analyzer error be `suspicious` or `rejected` by default?
7. SSRF posture: do we want URL fetching to be “safe-by-default for services/MCP” (block private IPs, localhost, link-local, non-https), with an override only for local CLI?
8. Do you want to keep scanning ClawHub ZIP bundles via MCP at all, or disable ZIP/URL scanning in MCP unless explicitly enabled?

Until answers, the plan below assumes the strict, security-first defaults:
- Declarations do not suppress or reduce deductions.
- Safety/negation do not zero out findings; they only reduce confidence/impact.
- Any analyzer error blocks `certified`.
- Semantic analysis is explicit opt-in.
- MCP URL scanning is locked down (SSRF-safe) by default.

## Prerequisites
- Node + pnpm available (repo already has `pnpm-lock.yaml`)
- Ability to run:
  - `pnpm test`
  - `pnpm lint`
  - `pnpm -C packages/agentverus-scanner-mcp test` (if that package has tests) or at least build/lint

## Sprint 1: Remove Trivial Certification Bypasses
**Goal**: Remove/replace suppression mechanisms that allow untrusted authors to neutralize findings and prevent scanners from seeing later matches.

**Demo/Validation**:
- `pnpm test`
- `pnpm lint`
- `pnpm -s agentverus scan test/fixtures/skills/evasion-rephrased-jailbreak.md` (or equivalent CLI invocation) returns **not** `badge=certified`.

### Task 1.1: Stop Declared Permissions From Suppressing Findings
- **Location**:
  - `src/scanner/analyzers/declared-match.ts`
  - `src/scanner/analyzers/behavioral.ts`
  - `src/scanner/analyzers/content.ts`
  - `src/scanner/analyzers/dependencies.ts`
  - `src/scanner/analyzers/injection.ts`
  - `src/scanner/analyzers/permissions.ts`
- **Description**:
  - Replace `applyDeclaredPermissions()` behavior so it **never** sets `deduction=0` or `severity=info` for non-info findings.
  - Prefer: annotate findings (title/description) when a declared permission matches, or emit a separate `info` finding listing declared permissions and justifications.
  - Remove recalculation logic that assumes deductions can be zeroed by declarations.
- **Dependencies**: none
- **Acceptance Criteria**:
  - A skill cannot self-declare `network`/`credential_access` to neutralize a `critical/high` finding.
  - `applyDeclaredPermissions` (or replacement) does not modify severity/deduction in a way that can bypass `--fail-on-severity` or badge gating.
- **Validation**:
  - Add a targeted unit test: craft a finding `critical` + declared `network`; assert severity remains `critical` and deduction unchanged.
  - Run `pnpm test`.

### Task 1.2: Remove “Zero Multiplier” For Safety Sections And Negations
- **Location**:
  - `src/scanner/analyzers/context.ts`
  - `test/scanner/context.test.ts`
- **Description**:
  - Change `adjustForContext()` so it never returns `severityMultiplier: 0` for:
    - `isInsideSafetySection`
    - `isPrecededByNegation`
  - Replace with a small multiplier (example: `0.2` safety sections, `0.4` negations), or separate “confidence” vs “impact” concepts.
  - Tighten/remove the “descriptive statement” heuristic in `isPrecededByNegation()` (current subject-detection is overly broad and creates bypass surface).
- **Dependencies**: Task 1.1 (if context uses declared logic elsewhere later)
- **Acceptance Criteria**:
  - Malicious instructions placed under “Safety Boundaries” headings still produce findings (even if downgraded).
  - “Do not X” safety statements do not fully erase detection; they should not prevent later matches from being found.
- **Validation**:
  - Update `test/scanner/context.test.ts` expectations (no more `0` multipliers).
  - Add new test: content with a safety section containing a dangerous keyword and a later real instruction; ensure both are detected or at least the later is detected.

### Task 1.3: Fix Behavioral Analyzer Early-Break Bypass
- **Location**: `src/scanner/analyzers/behavioral.ts`
- **Description**:
  - Replace `if (severityMultiplier === 0) break;` with `continue;` (or remove entirely once multipliers are non-zero).
  - Ensure a suppressed/downgraded match early does not stop scanning for later matches.
  - Apply the same logic to prerequisite-trap loop (currently breaks on `severityMultiplier === 0`).
- **Dependencies**: Task 1.2
- **Acceptance Criteria**:
  - A “benign”/downgraded early match cannot prevent detection of later risky matches for the same regex.
- **Validation**:
  - Add a test fixture that includes an early negated/safety mention and a later affirmative risky instruction; assert findings include the later one.
  - Run `pnpm test`.

### Task 1.4: Fix Dependencies Analyzer Early-Break And Safety Suppression
- **Location**: `src/scanner/analyzers/dependencies.ts`
- **Description**:
  - In download-and-execute loop, replace:
    - `if (isInsideSafetySection(...)) { break; }`
    - with `continue;` (and optionally record a low/info “mentioned in safety section” finding).
  - Ensure scanning continues for later matches.
- **Dependencies**: Task 1.2
- **Acceptance Criteria**:
  - A single `curl | bash` example under “Safety Boundaries” can’t suppress later real `curl | bash` instructions.
- **Validation**:
  - Add fixture + test similar to Task 1.3.
  - Run `pnpm test`.

## Sprint 2: Make CERTIFIED Mean “Safe Enough”
**Goal**: Fix badge logic and scoring so `certified` is not granted when medium/low findings or missing boundaries indicate risk.

**Demo/Validation**:
- `pnpm test`
- Ensure `test/fixtures/skills/evasion-rephrased-jailbreak.md` yields `badge !== "certified"`.

### Task 2.1: Update Badge Determination Rules
- **Location**: `src/scanner/scoring.ts`
- **Description**:
  - Update `determineBadge()` so `certified` is blocked when any of:
    - unhandled analyzer errors exist (see Sprint 3)
    - medium findings exist above a threshold (policy-dependent)
    - the skill lacks explicit safety boundaries (policy-dependent)
  - Consider adding explicit “certification constraints” beyond score:
    - No `critical`
    - No `high`
    - No analyzer errors
    - (Optional) must have safety boundaries
    - (Optional) mediumCount <= N
- **Dependencies**: none
- **Acceptance Criteria**:
  - A skill with rephrased jailbreak content (even if only `medium`) does not get `certified`.
  - Badge rules are deterministic and documented in code comments + README.
- **Validation**:
  - Add unit tests for determineBadge via scanning fixtures:
    - `evasion-rephrased-jailbreak.md` not certified
    - `safe-basic.md` still certified
    - `safe-complex.md` certified or conditional (as desired)

### Task 2.2: Penalize Missing Safety Boundaries Meaningfully
- **Location**:
  - `src/scanner/analyzers/content.ts`
  - `test/scanner/adversarial.test.ts`
- **Description**:
  - Change `CONT-NO-SAFETY` to have a non-zero deduction and an appropriate severity (recommendation: `medium`, deduction 10-20).
  - Optionally add explicit gating for certification in scoring (Sprint 2.1) instead of relying solely on deductions.
- **Dependencies**: Task 2.1
- **Acceptance Criteria**:
  - Missing safety boundaries has visible impact on score and/or badge.
  - The “minimum bar” for `certified` is aligned with AgentVerus positioning (trust requires boundaries).
- **Validation**:
  - Update adversarial tests:
    - Replace “at minimum findings.length > 0” with `badge !== "certified"` for `evasion-rephrased-jailbreak.md`.
  - Run `pnpm test`.

### Task 2.3: Update “Context Safe” Test Expectations
- **Location**: `test/scanner/adversarial.test.ts`
- **Description**:
  - The tests currently assume safety/negation implies “no penalty”. After Sprint 1, results should be:
    - Findings may still appear, but with reduced severity/deduction.
    - Badge remains non-rejected and score stays reasonably high.
- **Dependencies**: Sprint 1 tasks
- **Acceptance Criteria**:
  - “security educator” fixtures remain high trust and not rejected.
  - But context does not create bypasses.
- **Validation**:
  - `pnpm test`

## Sprint 3: Safe Defaults For LLM + Fail Closed On Analyzer Errors
**Goal**: Avoid implicit data egress and avoid certifying when analyzer coverage failed.

**Demo/Validation**:
- `AGENTVERUS_LLM_API_KEY=... pnpm test` does not trigger network calls unless `--semantic` is enabled in tests (or tests are mocked).
- A forced analyzer failure blocks `certified`.

### Task 3.1: Make Semantic Analysis Explicit Opt-In
- **Location**:
  - `src/scanner/index.ts`
  - `src/scanner/analyzers/semantic.ts`
  - `src/scanner/cli.ts`
  - `README.md`
- **Description**:
  - Change `scanSkill()` to run semantic analysis only when `options.semantic` is truthy.
  - Keep `isSemanticAvailable()` for “can run”, but do not auto-run based solely on env var presence.
  - Ensure CLI continues to require `--semantic` to enable LLM calls.
  - Update README: clearly state “semantic analysis sends skill content to an external API”.
- **Dependencies**: none
- **Acceptance Criteria**:
  - No LLM API calls occur unless explicitly enabled.
  - Report output clearly indicates whether semantic ran (optional: metadata field or info finding).
- **Validation**:
  - Add test that sets `process.env.AGENTVERUS_LLM_API_KEY` but scans without `options.semantic`; assert semantic analyzer is not invoked (mock fetch).

### Task 3.2: Treat Analyzer Exceptions As Non-Certifiable
- **Location**: `src/scanner/index.ts`
- **Description**:
  - Replace `fallbackScore()` behavior so an analyzer exception:
    - is not merely `info` with `deduction: 0`
    - and cannot result in `badge=certified`
  - Implementation options:
    - Emit a `high` severity “Analyzer failed” finding with meaningful deduction, and/or
    - Add a “scanIncomplete” flag to metadata and make `determineBadge()` refuse `certified`.
- **Dependencies**: Task 2.1 (badge rules)
- **Acceptance Criteria**:
  - Any analyzer exception causes badge to be at most `conditional` (or lower, per policy).
- **Validation**:
  - Add test that temporarily forces an analyzer throw (via a crafted input if possible); assert badge is not certified.

## Sprint 4: Harden URL/ZIP Fetching And URL Trust Heuristics
**Goal**: Reduce DoS/SSRF risks and improve URL classification so it can’t be gamed.

**Demo/Validation**:
- URL scanning in MCP rejects localhost/private IP URLs.
- ZIP scanning has size/file-count caps and fails fast on oversized inputs.

### Task 4.1: Add SSRF Protections For URL Fetching (Especially MCP)
- **Location**:
  - `src/scanner/source.ts`
  - `packages/agentverus-scanner-mcp/src/server.ts`
- **Description**:
  - Add URL validation to `fetchSkillContentFromUrl()`:
    - allow only `https:` by default (optionally allow `http:` for local CLI with explicit opt-in)
    - block `localhost`, private IP ranges, link-local (`169.254.0.0/16`), loopback, `.local`, and RFC1918 hosts
    - block non-standard ports unless explicitly allowed (policy choice)
  - In MCP server, either:
    - disable `url` input entirely, or
    - require an explicit env var to enable URL scanning, and enforce strict validation.
- **Dependencies**: none
- **Acceptance Criteria**:
  - Prompt-injected `scan_skill` calls cannot fetch internal metadata endpoints.
- **Validation**:
  - Add tests for URL validator covering common SSRF targets.

### Task 4.2: Add ZIP Bomb / Size Limits Before Unzipping
- **Location**: `src/scanner/source.ts`
- **Description**:
  - Add hard caps:
    - max downloaded ZIP bytes (via `Content-Length` and/or streamed read limit)
    - max file count
    - max total decompressed bytes
    - max per-file bytes for `SKILL.md`
  - Replace `unzipSync(zipBytes)` with a limited/streaming approach if possible with `fflate`, or fail closed on missing safe metadata.
- **Dependencies**: Task 4.1 (shared fetch path)
- **Acceptance Criteria**:
  - Crafted ZIP bombs cannot exhaust memory/CPU.
  - Errors are clear and return a non-certifiable result.
- **Validation**:
  - Add a unit test for “reject too-large zip” using a synthetic in-memory ZIP (or mock unzip path).

### Task 4.3: Tighten Trusted Domain + Path-Based Trust
- **Location**: `src/scanner/analyzers/dependencies.ts`
- **Description**:
  - Remove overly broad trusted patterns:
    - `^docs\.` / `^developer\.` prefixes
    - user-controlled hosting zones like `*.vercel.app`, `*.netlify.app` (treat as unknown)
  - Remove or downgrade the generic “/api or /docs on any https domain is trusted” rule.
  - Add regression tests for URL classification to ensure untrusted domains don’t become trusted via path tricks.
- **Dependencies**: none
- **Acceptance Criteria**:
  - `https://docs.evil.com/api` is not treated as trusted.
  - Raw content hosts remain medium risk.
- **Validation**:
  - Add tests for `classifyUrl()`.

### Task 4.4: Improve Permission Analysis Beyond Substring Matching
- **Location**:
  - `src/scanner/analyzers/permissions.ts`
  - `src/scanner/parser.ts` (if needed)
  - `src/scanner/types.ts` (if new structures are introduced)
- **Description**:
  - Replace `includes()` heuristics with schema-aware parsing for the supported formats (`openclaw`, `claude`, `generic`):
    - define a canonical permission vocabulary internally
    - map format-specific tool/permission fields to that vocabulary
  - Short-term hardening (if time-constrained): treat unknown permissions/tools as at least `medium` risk and report them.
- **Dependencies**: Sprint 1 (declared permissions changes)
- **Acceptance Criteria**:
  - Renaming permissions/tools cannot trivially evade detection.
  - The scanner reports unknown permissions explicitly.
- **Validation**:
  - Add unit tests for permission parsing/mapping with representative fixtures.

### Task 4.5: Pin GitHub Action Example And Document Policy
- **Location**: `README.md`, `actions/scan-skill` (if tag strategy needed)
- **Description**:
  - Replace `agentverus/agentverus-scanner/actions/scan-skill@main` with a pinned tag (e.g. `@v0.3.0`) or a SHA.
  - Document badge semantics post-hardening (what blocks `certified`).
- **Dependencies**: Task 2.1 (badge policy)
- **Acceptance Criteria**:
  - Action example is reproducible and supply-chain safer.
- **Validation**:
  - `pnpm lint` (docs only)

## Testing Strategy
- Unit tests:
  - Context multiplier rules (`test/scanner/context.test.ts`)
  - Adversarial fixtures (`test/scanner/adversarial.test.ts`)
  - URL classification tests (new)
  - SSRF URL validation tests (new)
  - Declared permission adjustment tests (new)
- CLI smoke tests:
  - `pnpm -s agentverus scan test/fixtures/skills/safe-basic.md`
  - `pnpm -s agentverus scan test/fixtures/skills/evasion-rephrased-jailbreak.md`
  - `pnpm -s agentverus scan https://github.com/.../SKILL.md` (ensure still works for public URLs)

## Potential Risks & Gotchas
- Tightening `certified` criteria may reduce adoption if too strict; mitigate by:
  - ensuring `conditional` is still a “good” badge
  - adding clear remediation guidance in findings
- Removing suppression may increase false positives for security-education skills; mitigate via:
  - downgraded multipliers (not suppression) plus “educational context” heuristics in analyzers
- SSRF protections may surprise CLI users who scan intranet skills; mitigate via explicit flags for local-only usage.
- ZIP limits may break ClawHub bundle scanning if caps are too low; pick thresholds based on observed bundle sizes.

## Rollback Plan
- Ship changes behind a minor version bump (or at least documented breaking change).
- If false positives/regressions are severe:
  1. revert badge gating changes in `src/scanner/scoring.ts`
  2. keep the bypass fixes (Sprint 1) since they are security-critical
  3. release a patch version with revised thresholds and updated docs


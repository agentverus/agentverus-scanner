# Plan: AgentVerus Scanner v0.4.0 — Threat Detection Parity Improvements

**Generated**: 2026-02-09
**Estimated Complexity**: Medium

## Overview
Implement the v0.4.0 “quick win” items from `ROADMAP-V04.md` to close key gaps vs. Cisco AI Defense’s `skill-scanner`.

Scope (this execution):
- Unicode steganography / hidden Unicode hardening
- Indirect prompt injection / transitive trust patterns
- Coercive injection / priority override patterns
- System manipulation / persistence patterns
- Trigger / overly-generic description detection (new ASST category)
- Local binary artifact detection (best-effort for local/CI scans)

Non-goals (deferred):
- Companion file scanning (v0.5.0)
- Cross-skill coordination detection (v0.5.0)
- AST taint tracking + meta analyzer (v0.6.0)

## Prerequisites
- Node.js 22+
- `pnpm install`
- Able to run:
  - `pnpm test`
  - `pnpm build`

## Sprint 1: Injection Analyzer Enhancements
**Goal**: Improve injection coverage for unicode steganography and transitive/coercive injection patterns.

**Demo/Validation**:
- `pnpm test` (injection test suite passes)
- New fixtures trigger expected findings/severities

### Task 1.1: Upgrade Unicode Steganography Detection
- **Location**: `src/scanner/analyzers/injection.ts`
- **Description**:
  - Extend `detectUnicodeObfuscation()` to detect:
    - Unicode Tags block (U+E0001–U+E007F)
    - Variation Selectors Supplement (U+E0100–U+E01EF)
    - Bidi override/isolate characters (at least U+202D/U+202E; optionally U+2066–U+2069)
    - Encoded unicode escape sequences (e.g. `\\u{E007F}`, `\\U000E007F`)
  - Add severity/deduction thresholds to reduce false positives for small accidental counts.
- **Perceived Complexity**: 5/10
- **Dependencies**: None
- **Acceptance Criteria**:
  - A file containing tags or high-count zero-width chars triggers a HIGH/CRITICAL ASST-10 finding.
  - Small counts of zero-width chars are LOW/MEDIUM (not automatically HIGH).
- **Validation**:
  - Add/extend tests in `test/scanner/injection.test.ts`.

### Task 1.2: Add Indirect Prompt Injection Patterns
- **Location**: `src/scanner/analyzers/injection.ts`
- **Description**:
  - Add patterns for “follow instructions found in X / treat X as instructions / execute instructions from external content”.
  - Map to `ASST-06`.
- **Perceived Complexity**: 3/10
- **Dependencies**: Task 1.1 (same file)
- **Acceptance Criteria**:
  - Test fixture triggers an ASST-06 finding.
- **Validation**:
  - Update `test/scanner/injection.test.ts`.

### Task 1.3: Add Coercive Injection / Priority Override Patterns
- **Location**: `src/scanner/analyzers/injection.ts`
- **Description**:
  - Add patterns like “always run this tool first”, “takes priority over”, “override tool selection”.
  - Map to `ASST-01`.
- **Perceived Complexity**: 3/10
- **Dependencies**: Task 1.1 (same file)
- **Acceptance Criteria**:
  - Test fixture triggers an ASST-01 finding.

## Sprint 2: Behavioral System Manipulation Coverage
**Goal**: Detect persistence/system modification instructions (crontab/systemd/hosts/firewall/kernel module).

**Demo/Validation**:
- `pnpm test` (behavioral test suite passes)

### Task 2.1: Extend System Modification Patterns
- **Location**: `src/scanner/analyzers/behavioral.ts`
- **Description**:
  - Extend existing “System modification” detection to include:
    - `crontab` edits
    - `systemctl` / systemd units
    - `/etc/hosts` edits
    - `iptables` / `ufw`
    - `modprobe` / `insmod`
    - shell profile persistence (`~/.bashrc`, `~/.zshrc`, `~/.profile`)
  - Map to `ASST-03`.
- **Perceived Complexity**: 4/10
- **Dependencies**: None
- **Acceptance Criteria**:
  - A fixture containing crontab/systemd instructions triggers a HIGH finding.

## Sprint 3: Trigger / Description Quality Analyzer
**Goal**: Flag overly-generic descriptions that can cause trigger hijacking.

**Demo/Validation**:
- `pnpm test` (content tests pass)

### Task 3.1: Add ASST-11 Category + Detection
- **Location**:
  - `src/scanner/analyzers/content.ts`
  - `src/scanner/types.ts`
- **Description**:
  - Add new ASST category: `ASST-11: Trigger Manipulation`.
  - Detect overly-generic descriptions (e.g., “help with anything”, “universal assistant”) and apply a deduction.
- **Perceived Complexity**: 4/10
- **Dependencies**: None
- **Acceptance Criteria**:
  - Generic description triggers a MEDIUM finding with `owaspCategory=ASST-11`.

## Sprint 4: Local Binary Artifact Detection
**Goal**: Flag executable binaries packaged alongside skill content during local/CI scans.

**Demo/Validation**:
- `pnpm test` (new binary detection tests pass)

### Task 4.1: Detect Binaries in Skill Directories (best-effort)
- **Location**:
  - `src/scanner/runner.ts`
  - (new) `src/scanner/binary.ts`
- **Description**:
  - When scanning local file targets, scan the containing directory for likely executable binaries (ELF/PE/Mach-O or typical executable extensions).
  - If found, append a HIGH ASST-10 finding and recompute overall score via `aggregateScores()`.
- **Perceived Complexity**: 6/10
- **Dependencies**: None
- **Acceptance Criteria**:
  - Temp fixture with an ELF header file produces a new finding and reduces the dependencies score.

## Testing Strategy
- Extend unit tests for analyzers (injection/behavioral/content)
- Add one integration-style test around `scanTarget()` or `scanTargetsBatch()` for binary detection.
- Run full suite: `pnpm test && pnpm build`

## Potential Risks
- False positives for small accidental zero-width characters.
  - Mitigation: threshold-based severities.
- Flagging legitimate admin skills that mention system commands.
  - Mitigation: context-aware downgrade inside code blocks (already implemented).

## Rollback Plan
- Revert commits or disable new patterns by removing them from the pattern lists.
- Binary detection is isolated (runner-only) and can be toggled off by removing the post-processing step.

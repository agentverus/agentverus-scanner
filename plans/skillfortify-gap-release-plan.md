# Plan: SkillFortify Gap Closure Release

**Generated**: 2026-03-01  
**Estimated Complexity**: High

## Overview
Ship a release-quality vertical slice that closes key SkillFortify gaps in declaration contracts, supply-chain artifacts, documentation clarity, and release readiness while preserving scanner compatibility. The slice prioritizes end-to-end deliverability: capability contract checks in scanner output, one shippable artifact feature (SBOM), updated docs, and release notes/prep.

## Scope
- In scope:
  - Capability contract checks between declared and inferred behavior.
  - SBOM groundwork with CLI output flow.
  - README/docs updates reflecting capability-contract + SBOM behavior.
  - Changelog updates and a concrete release-prep notes doc.
  - Validation through lint/test/typecheck/build.
- Out of scope for this slice:
  - New scanner category expansion that changes the public `Category` union.
  - Full package publishing/release automation execution.
  - Deep lockfile ingestion across ecosystem package managers (captured as backlog).

## Workstreams

### A. Scanner Capability Contracts (Declared vs Inferred Behavior)
**Goal**: Detect and report contract drift where inferred risky capability is missing from declarations.

Tasks:
1. Define capability normalization + inference rules.
   - **Location**: `src/scanner/analyzers/permissions.ts` (or new helper under `src/scanner/analyzers/`)
   - **Description**: Map declared permission/tool strings into canonical capability kinds and infer capabilities from skill content/metadata.
   - **Dependencies**: repo audit complete.
   - **Acceptance Criteria**:
     - Canonical capability map includes network, credential access, file write, system modification, and command execution.
     - Inference remains deterministic and pure.
2. Add contract-mismatch findings.
   - **Location**: `src/scanner/analyzers/permissions.ts`
   - **Description**: Add findings for inferred-but-undeclared high-risk capabilities and for over-declared/unknown capability kinds as informational context.
   - **Dependencies**: task A1.
   - **Acceptance Criteria**:
     - Findings include IDs/evidence/recommendations and ASST mapping.
     - Existing analyzer interfaces remain unchanged.
3. Add/adjust tests for capability contract behavior.
   - **Location**: `test/scanner/permissions.test.ts`, `test/scanner/integration.test.ts`, optional new fixtures.
   - **Dependencies**: task A2.
   - **Acceptance Criteria**:
     - Tests cover declared-aligned and undeclared-risk scenarios.
     - Existing baseline tests still pass or are intentionally updated with rationale.

### B. Lockfile and/or SBOM Groundwork
**Goal**: Deliver one release-worthy supply-chain artifact output.

Tasks:
1. Implement SBOM document generator.
   - **Location**: `src/scanner/sbom.ts`
   - **Description**: Build a deterministic SBOM JSON document from scan results with scanner metadata, scanned targets, and discovered dependency indicators.
   - **Dependencies**: repo audit complete.
   - **Acceptance Criteria**:
     - Output schema documented in code.
     - Document includes scanner version + per-target components.
2. Add CLI support for SBOM output.
   - **Location**: `src/scanner/cli.ts`
   - **Description**: Add `--sbom [path]` option and write output file (default path if omitted).
   - **Dependencies**: task B1.
   - **Acceptance Criteria**:
     - CLI help text updated.
     - Single and multi-target scan flows support SBOM generation.
3. Add tests for SBOM generation/serialization.
   - **Location**: `test/scanner/sbom.test.ts` and/or `test/scanner/cli` coverage if existing.
   - **Dependencies**: tasks B1-B2.
   - **Acceptance Criteria**:
     - Deterministic artifact assertions.
     - Coverage for dependency evidence extraction edge cases.

### C. Website/Docs Updates
**Goal**: Reflect new capabilities in user-facing docs.

Tasks:
1. Update README capability + SBOM sections.
   - **Location**: `README.md`
   - **Dependencies**: tasks A2, B2.
   - **Acceptance Criteria**:
     - Documents behavior, CLI usage, and compatibility notes.
2. Add focused docs page for the vertical slice.
   - **Location**: `docs/skillfortify-gap-closure.md` (or equivalent)
   - **Dependencies**: tasks A2, B2.
   - **Acceptance Criteria**:
     - Includes examples and limits for current implementation.

### D. Changelog + Release Prep
**Goal**: Prepare a non-published, release-ready record.

Tasks:
1. Update unreleased changelog entries.
   - **Location**: `CHANGELOG.md`
   - **Dependencies**: tasks A/B/C implemented.
   - **Acceptance Criteria**:
     - Added/Changed sections reflect user-visible behavior.
2. Add release prep notes doc.
   - **Location**: `docs/release-prep-vNEXT.md`
   - **Dependencies**: task D1.
   - **Acceptance Criteria**:
     - Includes versioning recommendation, validation checklist, and publish guardrails ("do not publish" in this initiative).

## Phase Plan (Execution Order)

### Phase 1: Planning + Baseline
- Complete repo audit, confirm conventions, and lock scope for shippable slice.
- Deliver this plan file as implementation contract.

### Phase 2: Core Scanner/CLI Implementation
- Implement capability-contract checks (A).
- Implement SBOM generator + CLI flag (B).
- Keep API and scanner output backward compatible except additive findings/artifact outputs.

### Phase 3: Tests + Hardening
- Add/update tests for capability contracts and SBOM behavior.
- Run lint/test/typecheck/build and resolve regressions.

### Phase 4: Docs + Release Readiness
- Update README and docs page (C).
- Update changelog and add `docs/release-prep-vNEXT.md` (D).

## Dependencies Graph
- A1 → A2 → A3
- B1 → B2 → B3
- A2 + B2 → C1/C2
- A/B/C completion → D1 → D2
- A3 + B3 + C + D → Quality gate

## Risks & Mitigations
- Risk: Capability inference causes noisy false positives.
  - Mitigation: conservative inference patterns, severity tuning, and tests for benign fixtures.
- Risk: SBOM shape mismatch with consumer expectations.
  - Mitigation: document schema clearly and keep deterministic/stable fields.
- Risk: Regression in score thresholds for existing fixtures.
  - Mitigation: run full test suite and adjust contract deductions to minimize churn.
- Risk: Scope creep into full lockfile ingestion.
  - Mitigation: explicitly defer deep lockfile parsing to backlog.

## Acceptance Criteria (Release Slice)
- Planner phase artifact exists at `plans/skillfortify-gap-release-plan.md`.
- Scanner emits capability-contract findings for declared vs inferred mismatch scenarios.
- CLI can emit an SBOM artifact from scan results (`--sbom`).
- README/docs reflect new capability-contract and SBOM behavior.
- `CHANGELOG.md` and `docs/release-prep-vNEXT.md` updated.
- `pnpm lint`, `pnpm test`, `pnpm typecheck`, and `pnpm build` pass.

## Backlog (Post-slice)
- Add lockfile ingestion for npm/pnpm/yarn and map packages into SBOM components.
- Add strict contract mode (`--require-contract`) that fails on undeclared high-risk capabilities.
- Add SARIF properties for contract mismatch flags.
- Add registry-pipeline SBOM aggregation for site/report outputs.

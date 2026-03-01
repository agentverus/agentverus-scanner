# Release Prep: vNEXT (Do Not Publish Yet)

## Scope Summary

This release candidate contains the SkillFortify gap-closure vertical slice:

- Capability declaration contract checks (declared vs inferred behavior)
- CycloneDX SBOM artifact output via `--sbom`
- README/docs updates for new scanner capabilities
- Changelog updates and release readiness checklist

## Suggested Version

- Suggested next release: **`0.6.0`**
- Rationale:
  - Backward-compatible feature additions (new findings and new optional CLI artifact output)
  - New public export path (`agentverus-scanner/sbom`)
  - No breaking API removals or command behavior changes

## Package/Versioning Notes

- Update before publish:
  - `package.json` version
  - `src/scanner/types.ts` `SCANNER_VERSION`
  - `CHANGELOG.md` version header/date and compare links
- Do not publish in this initiative:
  - no `pnpm publish`
  - no release tag creation

## Validation Checklist

- `pnpm lint`
- `pnpm test`
- `pnpm typecheck`
- `pnpm build`
- Manual smoke:
  - `npx agentverus scan ./test/fixtures/skills/declared-permissions.md`
  - `npx agentverus scan ./test/fixtures/skills/suspicious-urls.md --sbom /tmp/agentverus.sbom.json`

## Release Notes Draft Points

- Added capability contract mismatch findings for undeclared inferred behavior.
- Added CycloneDX 1.5 SBOM output (`--sbom`) for supply-chain review workflows.
- Added docs and usage examples for contract checks and SBOM generation.

## Deferred Backlog

- Lockfile ingestion for npm/pnpm/yarn ecosystems.
- Strict CI mode for mandatory contract declarations (`--require-contract`).
- Registry-level SBOM aggregation and publishing pipeline.

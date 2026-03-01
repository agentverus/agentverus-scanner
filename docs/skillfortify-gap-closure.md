# SkillFortify Gap Closure (Vertical Slice)

This document summarizes the first shippable slice for SkillFortify gap closure.

## Included in This Slice

1. Capability contract checks:
- The permissions analyzer now compares declared capabilities against inferred behavior.
- Missing declarations produce `PERM-CONTRACT-MISSING-*` findings with scored deductions.
- Unused or unknown declaration kinds are surfaced as informational findings.

2. SBOM groundwork:
- CLI supports `--sbom [path]` for CycloneDX 1.5 JSON output.
- SBOM includes scanner metadata, skill components, dependency indicators, and dependency edges.

3. Docs/release hygiene:
- README updated with capability-contract and SBOM guidance.
- CHANGELOG and release-prep notes updated for vNEXT planning.

## Capability Contract Mapping

Canonical capability families currently enforced:

- `credential_access`
- `exec`
- `system_modification`
- `file_write`
- `network`

Declaration inputs:

- Framework permission list (`permissions`)
- Explicit declaration objects (`permissions: - capability: "justification"`)

Inference inputs:

- Permission/tool strings
- Content behavior indicators (credential/file/system/exec/network patterns)
- Dependency indicators and URLs

## CLI Examples

```bash
# Scan + trust report
npx agentverus scan ./SKILL.md

# Scan + SARIF + SBOM
npx agentverus scan ./SKILL.md --sarif results.sarif --sbom results.sbom.json
```

## Notes and Limitations

- Contract checks are additive to existing permission findings; no new category was introduced.
- SBOM generation currently uses scan evidence indicators and is intended as a stable foundation.
- Deep package lockfile ingestion is planned follow-up work.

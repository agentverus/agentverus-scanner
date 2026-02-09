# Codex Context — AgentVerus Scanner v0.4.0 Threat Detection Work

**Generated:** 2026-02-09

This file is a context handoff for continuing work on **AgentVerus Scanner** improvements (v0.4.0 “quick wins”) inspired by OpenClaw Issue #11014 and Cisco AI Defense’s `skill-scanner`.

---

## Repo / Branch

- **Repo:** `agentverus/agentverus-scanner`
- **Local path:** `/Users/admin/Projects/agentverus-scanner`
- **Working branch:** `feature/v0.4.0-threat-detections`
- **Status:** Changes implemented locally; not committed/pushed yet.

---

## Goal

Implement the **v0.4.0** roadmap items from `ROADMAP-V04.md` (security detection parity quick wins):

1. Unicode steganography / hidden unicode detection (improve ASST-10)
2. Indirect prompt injection / transitive trust detection (ASST-06)
3. Coercive injection / tool priority override detection (ASST-01)
4. System manipulation patterns (ASST-03)
5. Trigger / description quality detection (new ASST-11)
6. Local binary artifact detection (ASST-10)

Deferred (not in this branch scope):
- Companion file scanning (v0.5.0)
- Cross-skill coordination (v0.5.0)
- AST taint tracking & meta analyzer (v0.6.0)

---

## What’s Implemented (Code Changes)

### 1) Unicode steganography detection (ASST-10)
**File:** `src/scanner/analyzers/injection.ts`

`detectUnicodeObfuscation()` was rewritten/expanded:
- Zero-width chars: U+200B/U+200C/U+200D/U+FEFF
  - BOM-only at file start treated as benign.
  - Thresholded severity/deduction:
    - >3 → MEDIUM
    - >10 → MEDIUM (higher deduction)
    - >50 → HIGH
    - >50 + decode/exec signals → CRITICAL
    - >200 → HIGH
- Bidi control chars: U+202A–U+202E and U+2066–U+2069 (overrides/isolate)
- Unicode Tag block: U+E0001–U+E007F
- Variation Selectors: U+E0100–U+E01EF
- Encoded tag escapes in text: `\\u{E00xx}` / `\\U000E00xx`
- Uses a simple “suspicious decode” heuristic to raise severity when hidden chars pair with decode/exec patterns.

### 2) Indirect prompt injection / transitive trust (ASST-06)
**File:** `src/scanner/analyzers/injection.ts`

Added a new pattern group:
- **Name:** `Indirect prompt injection (transitive trust)`
- **Severity:** HIGH
- **Deduction:** 25
- **OWASP/ASST:** `ASST-06`

Detects instructions like:
- “follow instructions found in/from a file/webpage/url”
- “treat contents of X as instructions/system prompt”
- “fetch then follow its instructions”

### 3) Coercive injection / tool priority override (ASST-01)
**File:** `src/scanner/analyzers/injection.ts`

Added a new pattern group:
- **Name:** `Coercive tool priority override`
- **Severity:** HIGH
- **Deduction:** 20
- **OWASP/ASST:** `ASST-01`

Detects:
- “always run this tool first”
- “this tool takes priority over”
- “override previous tool selection”
- “bypass tool restrictions/guards”

### 4) System manipulation patterns (ASST-03)
**File:** `src/scanner/analyzers/behavioral.ts`

Extended the existing `System modification` pattern set to include:
- `crontab -e/-l`
- `systemctl enable/start/restart/daemon-reload/edit`
- systemd units (`/etc/systemd/system`, `*.service`)
- `/etc/hosts`
- firewall tooling: `iptables`, `ufw`
- kernel modules: `modprobe`, `insmod`, `rmmod`
- shell profile persistence: `~/.bashrc`, `~/.zshrc`, `~/.profile`

### 5) Trigger/description quality detection (ASST-11)
**Files:**
- `src/scanner/types.ts` — added `ASST-11: Trigger Manipulation`
- `src/scanner/analyzers/content.ts` — added `GENERIC_DESCRIPTION_PATTERNS` and a new finding

New finding:
- **ID:** `CONT-GENERIC-DESC`
- **Severity:** MEDIUM
- **Deduction:** 10
- **OWASP/ASST:** `ASST-11`

Triggers when `skill.description` is extremely generic (e.g., “help with anything”, “universal assistant”).

### 6) Local binary artifact detection (ASST-10)
**Files:**
- `src/scanner/binary.ts` — new helper to find executable binaries under a directory
- `src/scanner/runner.ts` — now post-processes local file scans to append a HIGH finding to `dependencies` category when binaries are present

Binary detection:
- ELF magic, PE "MZ", Mach-O magics (+ fat binaries)
- Common executable extensions: `.exe`, `.dll`, `.so`, `.dylib`, `.bin`

When found, `runner.ts` adds:
- Category: `dependencies`
- Severity: HIGH
- Deduction: 25
- ASST: `ASST-10`

Then recomputes overall score/badge via `aggregateScores()`.

---

## Files Changed / Added

Modified:
- `src/scanner/analyzers/injection.ts`
- `src/scanner/analyzers/behavioral.ts`
- `src/scanner/analyzers/content.ts`
- `src/scanner/types.ts`
- `src/scanner/runner.ts`

Added:
- `src/scanner/binary.ts`
- `PLAN-v0.4.0-threat-detections.md` (execution plan)
- `ROADMAP-V04.md` (gap analysis + roadmap)

Untracked (present locally):
- `scanner-security-gate-hardening-plan.md` (separate plan; not part of v0.4.0 quick wins)

---

## Verification (already run locally)

- `pnpm test` ✅
- `pnpm build` ✅

Note: No new targeted unit tests were added yet for the new detections; existing tests passed.

---

## Remaining Work / Next Steps

### A) Add tests + fixtures (recommended before merging)
1. **Injection tests** (`test/scanner/injection.test.ts`)
   - Unicode steganography thresholds (zero-width, bidi, tags, variation selectors)
   - Indirect prompt injection patterns (ASST-06)
   - Coercive tool priority override (ASST-01)
2. **Behavioral tests** (`test/scanner/behavioral.test.ts`)
   - crontab/systemctl/hosts/firewall patterns
3. **Content tests** (`test/scanner/content.test.ts`)
   - generic description triggers ASST-11
4. **Runner integration test**
   - Create temp dir with `SKILL.md` and a fake ELF/PE header file; confirm scan adds `DEP-BINARY-*` finding and score decreases

### B) Docs + changelog
- Update `README.md` threat taxonomy list to include **ASST-11**
- Add an `[Unreleased]` changelog entry summarizing v0.4.0 additions

### C) Release plumbing (when ready)
- Bump `SCANNER_VERSION` + `package.json` to `0.4.0`
- Tag + publish to npm
- If updating GitHub Action (`actions/scan-skill`), run `pnpm build:actions` and tag a new action version

---

## Useful Commands

```bash
cd /Users/admin/Projects/agentverus-scanner

# Run tests
pnpm test

# Build
pnpm build

# Show git diff
git diff

# Commit (after adding tests/docs)
git add -A
git commit -m "feat: v0.4.0 threat detection hardening"

git push origin feature/v0.4.0-threat-detections
```

---

## Why we’re doing this (short rationale)

Cisco AI Defense demonstrated real-world malicious skills that can hide instructions (unicode steganography), exploit transitive trust (“follow instructions from external content”), and persist or manipulate host systems. These additions tighten AgentVerus’s ability to detect those patterns **before execution**, with minimal extra complexity.

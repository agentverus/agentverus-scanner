# AgentVerus Scanner — Security Gap Analysis & Roadmap

> Generated 2026-02-08 from analysis of [OpenClaw Issue #11014](https://github.com/openclaw/openclaw/issues/11014) and comparison with [Cisco AI Defense skill-scanner](https://github.com/cisco-ai-defense/skill-scanner) (Apache 2.0, 667 stars, Python).

---

## Context

OpenClaw issue #11014 requests a security scanning pipeline to detect malicious skills before execution. It references Cisco's published research ([blog post](https://blogs.cisco.com/ai/personal-ai-agents-like-openclaw-are-a-security-nightmare), Jan 28, 2026) demonstrating that a malicious skill ranked #1 in repositories despite containing functional malware with nine security findings including two critical vulnerabilities.

Cisco released an open-source scanner (`cisco-ai-defense/skill-scanner`) with a six-engine architecture. This document compares AgentVerus Scanner's current capabilities against Cisco's and identifies actionable gaps.

---

## Current AgentVerus Scanner Capabilities (v0.3.0)

### Architecture
- **Language:** TypeScript/Node.js (npm package: `agentverus-scanner`)
- **Analyzers:** 7 analyzers across 5 scoring categories
- **Output:** CLI table, JSON, SARIF, Markdown report, Shields.io badge JSON
- **Distribution:** npm (`npx agentverus-scanner`), GitHub Action (`actions/scan-skill`)

### Analyzers

| Analyzer | File | What It Does |
|----------|------|-------------|
| **Injection** | `analyzers/injection.ts` | Prompt injection, command injection, data exfiltration, credential harvesting, obfuscation |
| **Permissions** | `analyzers/permissions.ts` | Declared permissions analysis, dangerous tool detection |
| **Dependencies** | `analyzers/dependencies.ts` | External URL analysis, self-domain trust, unknown reference detection |
| **Behavioral** | `analyzers/behavioral.ts` | Autonomy abuse, self-modification, persistence patterns |
| **Content** | `analyzers/content.ts` | Safety boundaries, output constraints, error handling |
| **Context** | `analyzers/context.ts` | False-positive reduction via negation/code-block/safety-section awareness |
| **Declared-Match** | `analyzers/declared-match.ts` | Manifest declared capabilities vs. actual tool usage |
| **Semantic** | `analyzers/semantic.ts` | Optional LLM-as-judge deep analysis (`--semantic` flag) |

### ASST Threat Taxonomy (10 categories)

| ID | Category | Severity Range |
|----|----------|---------------|
| ASST-01 | Instruction Injection | Critical–High |
| ASST-02 | Data Exfiltration | Critical–High |
| ASST-03 | Privilege Escalation | High |
| ASST-04 | Dependency Hijacking | Medium–Low |
| ASST-05 | Credential Harvesting | Critical–High |
| ASST-06 | Prompt Injection Relay | High |
| ASST-07 | Deceptive Functionality | High–Medium |
| ASST-08 | Excessive Permissions | Medium |
| ASST-09 | Missing Safety Boundaries | Low–Info |
| ASST-10 | Obfuscation | High–Medium |

---

## Cisco skill-scanner Architecture (Reference)

### Six-Engine Approach

| Engine | Method | What It Catches |
|--------|--------|-----------------|
| **Static Analyzer** | 35 YAML signature rules + 13 YARA rule files | Prompt injection, command injection, data exfiltration, hardcoded secrets, obfuscation, resource abuse |
| **Behavioral Analyzer** | AST parsing + control-flow-graph + taint tracking | Taint flows from credential files to network calls, parameter-to-eval chains, cross-file exfiltration |
| **LLM Analyzer** | Semantic analysis via LLM-as-judge | Intent detection, workflow analysis, threats that evade pattern matching |
| **Meta Analyzer** | Second-pass LLM false-positive filtering | Consolidates redundant findings, enriches with exploitability/impact scores (~65% noise reduction) |
| **Cross-Skill Scanner** | Multi-skill coordination detection | Data relay patterns (skill A collects, skill B exfiltrates), shared C2 URLs, complementary triggers |
| **Trigger Analyzer** | Description specificity analysis | Overly generic descriptions, keyword baiting/SEO stuffing, brand impersonation |

### 13 YARA Rule Files

1. `prompt_injection_generic.yara` — "ignore previous instructions", override patterns, action concealment
2. `indirect_prompt_injection_generic.yara` — "follow instructions found in [file]", delegating to untrusted content
3. `coercive_injection_generic.yara` — "Always execute this tool first", priority overrides, MCP tool poisoning
4. `command_injection_generic.yara` — Dangerous system commands, reverse shells, `rm -rf`, `dd` overwrites
5. `credential_harvesting_generic.yara` — AWS/GCP/Azure credential files, SSH keys, `.env` harvesting, credential-to-network pipelines
6. `tool_chaining_abuse_generic.yara` — Read-then-send patterns, collect-then-post chains, base64-before-network
7. `code_execution_generic.yara` — base64-decode-then-exec, pickle with external data, eval/exec with user input
8. `system_manipulation_generic.yara` — crontab, systemd, hosts file, firewall, kernel modules
9. `autonomy_abuse_generic.yara` — Bypassing user confirmation, infinite retry, self-modification
10. `capability_inflation_generic.yara` — Over-broad claims, keyword stuffing, activation priority manipulation
11. `prompt_injection_unicode_steganography.yara` — Zero-width characters, RTL override, invisible Unicode, tag characters
12. `script_injection_generic.yara` — innerHTML, document.write, template injection, XSS vectors
13. `sql_injection_generic.yara` — SQL injection patterns

---

## Comparison Matrix

### ✅ AgentVerus Already Covers

| Capability | Cisco Approach | AgentVerus Approach | Parity |
|------------|---------------|-------------------|--------|
| Prompt injection | YARA rules | Regex patterns (ASST-01) | ≈ Equivalent |
| Data exfiltration | YARA + taint | Regex patterns (ASST-02) | ≈ Equivalent for SKILL.md |
| Credential harvesting | YARA rules | Regex patterns (ASST-05) | ≈ Equivalent |
| Command injection | YARA rules | Regex patterns (ASST-01) | ≈ Equivalent |
| Obfuscation | YARA rules | Regex patterns (ASST-10) | ≈ Equivalent |
| Excessive permissions | Manifest check | Declared-match analyzer (ASST-08) | ≈ Equivalent |
| LLM-assisted analysis | LLM Analyzer | `--semantic` flag | ≈ Equivalent |
| SARIF output | ✅ | ✅ | ✅ Same |
| Multi-skill repo scanning | ✅ | ✅ (`scan .`) | ✅ Same |
| Context-aware FP reduction | Meta Analyzer (LLM) | Context analyzer (rule-based) | Different approach, similar goal |

### ✅ AgentVerus Has, Cisco Doesn't

| Capability | Details |
|------------|---------|
| **Trust scoring + badges** | certified/conditional/suspicious/rejected tiers, Shields.io endpoint JSON, GitHub Pages deploy |
| **GitHub Action** | `actions/scan-skill` composite action with SARIF upload |
| **npm one-liner** | `npx agentverus-scanner` — zero install, JS-native |
| **Safety boundary detection** | Content analyzer checks for safety sections (ASST-09) |
| **Pre-install gate** | `agentverus check` scan-before-install flow |
| **Public registry + website** | agentverus.ai with 7,000+ scanned skills |

### 🔴 Gaps — Cisco Has, AgentVerus Doesn't

| # | Gap | Cisco Implementation | Impact | Effort |
|---|-----|---------------------|--------|--------|
| 1 | **Unicode steganography detection** | `prompt_injection_unicode_steganography.yara` — zero-width chars (U+200B/200C/200D/FEFF), RTL overrides (U+202E), Unicode tag chars (U+E0001-E007F), variation selectors | **High** — invisible instructions that LLMs see but humans don't | **Low** (~50 lines) |
| 2 | **Cross-skill coordination detection** | `cross_skill_scanner.py` — data relay patterns, shared external URLs, complementary triggers, shared suspicious code | **High** — multi-skill attacks invisible to per-skill analysis | **Medium** (~250 lines) |
| 3 | **Trigger/description quality analysis** | `trigger_analyzer.py` — generic description detection, keyword stuffing, activation priority manipulation | **Medium** — prevents trigger hijacking | **Low** (~80 lines) |
| 4 | **AST-based taint tracking** | `behavioral_analyzer.py` + `taint/tracker.py` + `cfg/builder.py` — Python AST parsing, CFG, dataflow from sources to sinks | **High** — catches multi-step exfiltration in code | **High** (~1000+ lines) |
| 5 | **Companion file scanning** | Scans all files in skill package (`.py`, `.sh`, `.js`) | **High** — we only scan SKILL.md, ignoring scripts | **Medium** (~150 lines) |
| 6 | **Indirect prompt injection** | `indirect_prompt_injection_generic.yara` — "follow instructions in [file]", delegating to untrusted content | **Medium** — transitive trust attacks | **Low** (~40 lines) |
| 7 | **Coercive injection** | `coercive_injection_generic.yara` — "always execute first", priority overrides, MCP tool poisoning, conversation theft | **Medium** — tool activation manipulation | **Low** (~30 lines) |
| 8 | **System manipulation** | `system_manipulation_generic.yara` — crontab, systemd, hosts file, firewall, kernel modules | **Medium** — persistent system changes | **Low** (~40 lines) |
| 9 | **Script injection / XSS** | `script_injection_generic.yara` — innerHTML, document.write, template injection | **Low–Medium** — less relevant for SKILL.md | **Low** (~30 lines) |
| 10 | **Binary file detection** | Flags executables in skill packages | **Low** — simple check | **Low** (~20 lines) |
| 11 | **Meta analyzer (FP reduction)** | LLM second pass to consolidate/deduplicate, assign exploitability scores, ~65% noise reduction | **Medium** — cleaner reports | **Medium** (~200 lines) |
| 12 | **SQL injection** | `sql_injection_generic.yara` | **Low** — rare in SKILL.md | **Low** (~20 lines) |

---

## Detailed Gap Specifications

### Gap 1: Unicode Steganography Detection

**File:** `src/scanner/analyzers/injection.ts` (add new section)

**What to detect:**
- Zero-width characters: U+200B (zero width space), U+200C (zero width non-joiner), U+200D (zero width joiner), U+FEFF (BOM/zero-width no-break space)
- Directional overrides: U+202E (RTL override), U+202D (LTR override)
- Unicode tag characters: U+E0001–U+E007F (invisible tag block)
- Variation selectors: U+E0100–U+E01EF (used in os-info-checker-es6 attack)
- High counts of any of the above (threshold: >5 for tags/overrides, >50 for zero-width)

**Severity:** CRITICAL if combined with code patterns (eval, exec, decode), HIGH if high count alone

**ASST mapping:** New sub-category under ASST-10 (Obfuscation) or new ASST-11 (Unicode Steganography)

**Reference:** Cisco's `prompt_injection_unicode_steganography.yara` lines 1–60

### Gap 2: Cross-Skill Coordination Detection

**File:** New `src/scanner/analyzers/cross-skill.ts`

**When invoked:** Only when scanning multiple targets (e.g., `scan .` on a repo)

**Detection patterns:**
1. **Data relay:** Skill A reads credentials/sensitive data + Skill B has network exfiltration patterns
2. **Shared external URLs:** Two+ skills reference the same suspicious external domain
3. **Complementary triggers:** Skills with overlapping/sequential trigger descriptions suggesting coordination
4. **Shared suspicious code:** Same obfuscated patterns or suspicious function names across skills

**Input:** Array of `TrustReport` objects from completed per-skill scans
**Output:** Additional findings attached to relevant skills

**Severity:** HIGH for data relay patterns, MEDIUM for shared URLs

**ASST mapping:** New ASST-12 (Cross-Skill Coordination) or extend ASST-02

### Gap 3: Trigger/Description Quality Analysis

**File:** New `src/scanner/analyzers/trigger.ts`

**What to detect:**
- Overly generic descriptions: "help with anything", "universal assistant", "general purpose tool"
- Very short descriptions (<10 words) that lack specificity
- Keyword stuffing: descriptions with excessive tool/capability keywords relative to length
- Brand impersonation: descriptions claiming to be official tools from known brands

**Severity:** MEDIUM for generic, LOW for short

**ASST mapping:** New ASST-11 (Trigger Manipulation) or extend ASST-07

### Gap 4: Companion File Scanning

**File:** Extend `src/scanner/targets.ts` + `src/scanner/runner.ts`

**Approach:**
1. When scanning a SKILL.md, discover sibling files in the same directory (`.py`, `.sh`, `.js`, `.ts`)
2. Run the same pattern matchers (injection, exfiltration, credential harvesting) on companion file content
3. Findings from companion files reference the parent SKILL.md but note the source file

**File types to scan:** `*.py`, `*.sh`, `*.bash`, `*.js`, `*.ts`, `*.rb`, `*.pl`

**Patterns to check in scripts:**
- `eval()`, `exec()`, `os.system()`, `subprocess.run(shell=True)`
- `requests.post()` / `curl` / `wget` with credential-adjacent reads
- `open()` on credential paths (`~/.aws/credentials`, `~/.ssh/id_rsa`)
- base64 encoding before network calls
- Environment variable reads (`os.environ`, `process.env`) of sensitive keys

### Gap 5: Indirect Prompt Injection

**File:** `src/scanner/analyzers/injection.ts` (add patterns)

**Patterns:**
- "follow instructions found in [file/URL]"
- "execute code blocks from external sources"
- "read and follow the instructions in"
- "load and apply the configuration from"
- "treat the content of X as your instructions"

**Severity:** HIGH

**ASST mapping:** ASST-06 (Prompt Injection Relay) — already exists, just needs more patterns

### Gap 6: Coercive Injection

**File:** `src/scanner/analyzers/injection.ts` (add patterns)

**Patterns:**
- "always execute this tool first"
- "this tool takes priority over"
- "override any previous tool selections"
- "call this function before any other"
- "hidden" + "parameter" in tool descriptions
- MCP tool poisoning: instructions embedded in tool `description` fields

**Severity:** HIGH

**ASST mapping:** ASST-01 (Instruction Injection) — add as sub-patterns

### Gap 7: System Manipulation

**File:** `src/scanner/analyzers/behavioral.ts` (add patterns)

**Patterns:**
- crontab modification (`crontab -e`, `crontab -l`)
- systemd service creation/modification
- `/etc/hosts` modification
- Firewall rule changes (`iptables`, `ufw`)
- Kernel module operations (`insmod`, `modprobe`)
- Login shell modification (`chsh`, `.bashrc` writes)

**Severity:** HIGH for crontab/systemd, MEDIUM for hosts/firewall

**ASST mapping:** ASST-03 (Privilege Escalation) — add as sub-patterns

### Gap 8: Binary File Detection

**File:** `src/scanner/targets.ts`

**Approach:** When discovering files in a skill directory, flag any binary executables (ELF headers, PE headers, Mach-O, `.exe`, `.dll`, `.so`, `.dylib`)

**Severity:** HIGH

---

## Recommended Roadmap

### v0.4.0 — Quick Wins (Low effort, high value)

| Item | Gap # | Est. Lines | New ASST |
|------|-------|-----------|----------|
| Unicode steganography detection | 1 | ~50 | ASST-10 extension |
| Indirect prompt injection patterns | 5 | ~40 | ASST-06 extension |
| Coercive injection patterns | 6 | ~30 | ASST-01 extension |
| System manipulation patterns | 7 | ~40 | ASST-03 extension |
| Trigger/description quality analyzer | 3 | ~80 | New ASST-11 |
| Binary file detection | 8 | ~20 | New finding type |

**Total:** ~260 lines of new detection code + tests

### v0.5.0 — Multi-File & Cross-Skill

| Item | Gap # | Est. Lines |
|------|-------|-----------|
| Companion file scanning (`.py`, `.sh`, `.js`) | 4 | ~150 |
| Cross-skill coordination detection | 2 | ~250 |

**Total:** ~400 lines + tests

### v0.6.0 — Deep Analysis

| Item | Gap # | Est. Lines |
|------|-------|-----------|
| AST-based taint tracking for Python scripts | 4 (advanced) | ~1000+ |
| Meta analyzer (LLM second-pass FP reduction) | 11 | ~200 |

**Total:** ~1200 lines + tests

---

## Key Files to Modify

| File | Changes |
|------|---------|
| `src/scanner/analyzers/injection.ts` | Unicode steganography, indirect injection, coercive injection patterns |
| `src/scanner/analyzers/behavioral.ts` | System manipulation patterns |
| `src/scanner/analyzers/trigger.ts` | **New file** — description quality/specificity analysis |
| `src/scanner/analyzers/cross-skill.ts` | **New file** — multi-skill coordination detection |
| `src/scanner/targets.ts` | Companion file discovery, binary detection |
| `src/scanner/runner.ts` | Wire up companion scanning, cross-skill post-processing |
| `src/scanner/types.ts` | New ASST categories if needed |
| `test/scanner/` | Tests for each new detection |
| `CHANGELOG.md` | Release notes |
| `README.md` | Updated threat taxonomy table |

---

## References

- **OpenClaw Issue:** https://github.com/openclaw/openclaw/issues/11014
- **Cisco Blog:** https://blogs.cisco.com/ai/personal-ai-agents-like-openclaw-are-a-security-nightmare
- **Cisco Scanner Repo:** https://github.com/cisco-ai-defense/skill-scanner
- **Cisco AI Security Framework:** https://arxiv.org/html/2512.12921v1
- **Cisco YARA Rules:** `skill_scanner/data/yara_rules/*.yara` (13 files)
- **Cisco Threat Taxonomy:** `skill_scanner/threats/cisco_ai_taxonomy.py` (19 AITech categories)
- **OWASP Top 10 for LLMs:** https://owasp.org/www-project-top-10-for-large-language-model-applications/
- **AgentVerus Scanner:** https://github.com/agentverus/agentverus-scanner
- **AgentVerus Website:** https://agentverus.ai

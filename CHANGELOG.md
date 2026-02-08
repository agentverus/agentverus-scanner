# Changelog

All notable changes to the AgentVerus Scanner are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Context-aware analysis** (`src/scanner/analyzers/context.ts`): New shared utility that all analyzers use to understand _where_ a pattern match occurs:
  - **Code block detection**: Patterns inside fenced code blocks (` ``` `) or inline code spans are downgraded (severity reduced, deduction at 30%).
  - **Safety section detection**: Patterns inside safety boundary sections (e.g., `## Safety Boundaries`, `## Limitations`) are fully neutralized (zero deduction) — these are positive declarations, not threats.
  - **Negation detection**: Patterns preceded by "do not", "never", "must not", "should not", etc. on the same line are fully neutralized.
- **LLM-assisted semantic analyzer** (`src/scanner/analyzers/semantic.ts`): Optional analyzer that uses an OpenAI-compatible API to detect threats regex patterns miss:
  - Catches rephrased jailbreaks, indirect multi-step exfiltration, and subtle manipulation.
  - Activated via `--semantic` CLI flag or `{ semantic: true }` in `ScanOptions`.
  - Requires `AGENTVERUS_LLM_API_KEY` environment variable (or explicit options).
  - Findings merge into the injection category — they supplement but never replace regex analysis.
  - Gracefully degrades: API failures are silently ignored, never breaking the scan.
- **Adversarial test suite** (`test/scanner/adversarial.test.ts`): 11 tests covering evasion techniques:
  - Security/educational skills with attack examples in code blocks (should NOT be rejected).
  - Skills with safety boundary negations (should NOT be penalized).
  - Genuine prose-level attacks (should still be caught despite context awareness).
  - Indirect exfiltration via URL parameter encoding.
  - Rephrased jailbreak attempts.
- **Context utility tests** (`test/scanner/context.test.ts`): 12 unit tests for code block, safety section, and negation detection.
- **Semantic analyzer tests** (`test/scanner/semantic.test.ts`): 3 tests covering graceful degradation when no API key is configured.
- **5 new adversarial test fixtures**: `evasion-context-safe.md`, `evasion-negation-safe.md`, `evasion-hidden-in-codeblock.md`, `evasion-indirect-exfiltration.md`, `evasion-rephrased-jailbreak.md`.

### Fixed

- **Injection analyzer**: Removed bare `.env` / `.ssh` / `.credentials` / `.secrets` substring match from the data exfiltration pattern — was producing critical findings on skills that merely reference `.env.example` or document environment variable setup.
- **Injection analyzer**: Tightened credential access patterns to require an action verb (`read`, `cat`, `dump`, `steal`, etc.) before sensitive paths. Bare mentions of `API_KEY`, `SECRET_KEY`, `PASSWORD`, etc. in setup documentation no longer trigger high-severity findings.
- **Injection analyzer**: Narrowed data exfiltration regex to require a directive form ("send/post X to URL") rather than matching HTTP method keywords near any URL, which was flagging API authentication code examples.
- **Dependencies analyzer**: Localhost and private IP addresses (`127.0.0.1`, `10.x`, `172.16–31.x`, `192.168.x`) are no longer flagged as suspicious external IPs.
- **Dependencies analyzer**: Expanded the trusted domains list with ~40 additional well-known domains (Google, Microsoft, AWS, Supabase, Stripe, LinkedIn, npm registry, example.com, etc.).
- **Dependencies analyzer**: Capped cumulative deduction from unknown (non-dangerous) URLs at 15 points, preventing skills with extensive API endpoint documentation from being unfairly penalized.
- **Dependencies analyzer**: Download-and-execute detection is now context-aware — patterns inside code blocks or safety sections are skipped.
- **Behavioral analyzer**: `npm install` and `pip install` without `--global` / `-g` flags are no longer flagged as system modification. Only global installs and system package managers (`apt`, `yum`, `dnf`, `pacman`) are flagged.
- **Behavioral analyzer**: Tightened the combined exfiltration flow heuristic to require active credential reading patterns **and** suspicious POST/exfiltration patterns. Previously, any skill mentioning an API key alongside any URL would trigger a high-severity finding.
- **Behavioral analyzer**: Prerequisite trap detection (curl-pipe-to-shell) is now context-aware.

### Changed

- **Test fixtures**: Updated `suspicious-urls.md` to use public IP addresses instead of private IPs for the IP-flagging test.
- **Test fixtures**: Updated `undeclared-permissions.md` to contain genuinely suspicious credential access patterns (e.g. `cat ~/.ssh/id_rsa`) rather than plain keyword mentions.

## [0.1.0] - 2026-01-15

### Added

- Initial release of the AgentVerus Scanner.
- Permission analysis with tiered risk classification (critical/high/medium/low).
- Injection detection covering instruction overrides, exfiltration directives, credential access, prompt injection relay, social engineering, concealment, and unrestricted mode activation.
- Dependency analysis with URL risk classification, download-and-execute detection, and trusted domain allowlisting.
- Behavioral risk scoring for unrestricted scope, system modification, autonomous actions, sub-agent spawning, state persistence, unbounded loops, and financial actions.
- Content analysis with harmful content detection, deception detection, obfuscation detection, hardcoded secret detection, and bonus scoring for safety boundaries, output constraints, and error handling.
- Declared permission matching system that downgrades findings when permissions are explicitly declared and justified.
- Weighted scoring across five categories (permissions 25%, injection 30%, dependencies 20%, behavioral 15%, content 10%).
- Badge tier system: CERTIFIED / CONDITIONAL / SUSPICIOUS / REJECTED.
- ASST taxonomy (ASST-01 through ASST-10) for finding classification.
- CLI with local file, directory, and URL scanning support.
- JSON and SARIF output formats.
- GitHub Action for CI/CD integration with Code Scanning upload.
- MCP server companion package for agent/framework integration.
- OpenClaw, Claude Code, and generic skill format auto-detection.
- ClawHub zip download support and GitHub URL normalization.

[Unreleased]: https://github.com/agentverus/agentverus-scanner/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/agentverus/agentverus-scanner/releases/tag/v0.1.0

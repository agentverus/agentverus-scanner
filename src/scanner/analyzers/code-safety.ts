/**
 * Code Safety Analyzer — AgentVerus Scanner
 *
 * Static analysis of executable code patterns found in skill content.
 * Detects dangerous runtime behaviors: shell execution, eval, data exfiltration,
 * obfuscated payloads, credential harvesting, and crypto mining indicators.
 *
 * Adapted from OpenClaw's skill-scanner (MIT license, PR #9806).
 * Original: https://github.com/openclaw/openclaw/blob/main/src/security/skill-scanner.ts
 *
 * Key adaptations for AgentVerus:
 * - Scans code blocks embedded in SKILL.md content (not files on disk)
 * - Maps findings to AgentVerus Finding format with ASST categories
 * - Integrates with the existing 5-analyzer pipeline as analyzer #6
 * - Context-aware: adjusts severity when code appears in documentation/examples
 */

import type { CategoryScore, Finding, ParsedSkill } from "../types.js";
import { isSecurityDefenseSkill } from "./context.js";

// ---------------------------------------------------------------------------
// Line-level detection rules (patterns checked per line of code)
// ---------------------------------------------------------------------------

interface LineRule {
	readonly id: string;
	readonly severity: "critical" | "high" | "medium" | "low" | "info";
	readonly title: string;
	readonly description: string;
	readonly pattern: RegExp;
	readonly owaspCategory: string;
	readonly deduction: number;
	/** Rule only fires when the full source also matches this pattern */
	readonly requiresContext?: RegExp;
}

interface SourceRule {
	readonly id: string;
	readonly severity: "critical" | "high" | "medium" | "low" | "info";
	readonly title: string;
	readonly description: string;
	/** Primary pattern tested against the full source */
	readonly pattern: RegExp;
	/** Both patterns must match for the rule to fire */
	readonly requiresContext?: RegExp;
	readonly owaspCategory: string;
	readonly deduction: number;
}

const LINE_RULES: readonly LineRule[] = [
	{
		id: "CS-SHELL-EXEC-1",
		severity: "critical",
		title: "Shell command execution via child_process",
		description:
			"Direct shell execution (exec/spawn) detected. Skills should not execute arbitrary shell commands — this enables command injection, privilege escalation, and lateral movement.",
		pattern: /\b(exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(/,
		requiresContext: /child_process/,
		owaspCategory: "ASST-03",
		deduction: 25,
	},
	{
		id: "CS-DYNAMIC-EVAL-1",
		severity: "critical",
		title: "Dynamic code execution (eval / new Function)",
		description:
			"eval() or new Function() detected. These execute arbitrary strings as code at runtime, enabling injection attacks and obfuscated payload delivery.",
		pattern: /\beval\s*\(|new\s+Function\s*\(/,
		owaspCategory: "ASST-10",
		deduction: 25,
	},
	{
		id: "CS-CRYPTO-MINING-1",
		severity: "critical",
		title: "Crypto mining indicator detected",
		description:
			"References to mining protocols (stratum), known mining libraries (coinhive, xmrig), or mining algorithms (cryptonight). Skills should never mine cryptocurrency.",
		pattern: /stratum\+tcp|stratum\+ssl|coinhive|cryptonight|xmrig/i,
		owaspCategory: "ASST-07",
		deduction: 30,
	},
	{
		id: "CS-WEBSOCKET-NONSTANDARD-1",
		severity: "medium",
		title: "WebSocket connection to non-standard port",
		description:
			"WebSocket connection to an unusual port detected. Could indicate C2 communication, data tunneling, or connection to unauthorized services.",
		pattern: /new\s+WebSocket\s*\(\s*["']wss?:\/\/[^"']*:(\d+)/,
		owaspCategory: "ASST-02",
		deduction: 10,
	},
	{
		id: "CS-CURL-PIPE-1",
		severity: "high",
		title: "Download-and-execute pattern (curl|wget pipe to shell)",
		description:
			"Piping a downloaded script directly to a shell interpreter. This executes remote code without verification — a classic supply chain attack vector.",
		pattern: /\b(curl|wget)\b.*\|\s*(bash|sh|zsh|node|python|perl)\b/,
		owaspCategory: "ASST-04",
		deduction: 20,
	},
	{
		id: "CS-PROCESS-ENV-BULK-1",
		severity: "high",
		title: "Bulk environment variable access",
		description:
			"Accessing the entire process.env object (not a specific key) suggests harvesting all environment variables, which may include API keys, tokens, and secrets.",
		pattern: /JSON\.stringify\s*\(\s*process\.env\s*\)|Object\.(keys|values|entries)\s*\(\s*process\.env\s*\)/,
		owaspCategory: "ASST-05",
		deduction: 20,
	},
	// --- Config tampering rules ---
	{
		id: "CS-CONFIG-TAMPER-CORE-1",
		severity: "critical",
		title: "Write to workspace trust-boundary file (AGENTS/TOOLS/CLAUDE.md)",
		description:
			"Code writes to a core workspace configuration file (AGENTS.md, TOOLS.md, or CLAUDE.md). These files define the agent's trust boundaries — modifying them can escalate privileges, disable safety rules, or inject persistent malicious instructions.",
		pattern: /(?:writeFileSync|appendFileSync|>>|>)\s*.*(?:AGENTS\.md|TOOLS\.md|CLAUDE\.md)/i,
		owaspCategory: "ASST-03",
		deduction: 30,
	},
	{
		id: "CS-CONFIG-TAMPER-CLAUDE-1",
		severity: "high",
		title: "Write to .claude/ policy directory",
		description:
			"Code writes to the .claude/ directory, which contains workspace policies and safety configuration. Modifying these files can disable safety checks, override policy boundaries, or inject persistent instructions.",
		pattern: /(?:writeFileSync|appendFileSync|>>|>|mkdir)\s*.*\.claude\//i,
		owaspCategory: "ASST-03",
		deduction: 20,
	},
];

const STANDARD_PORTS = new Set([80, 443, 8080, 8443, 3000, 3001, 5000, 8000]);

const SOURCE_RULES: readonly SourceRule[] = [
	{
		id: "CS-EXFIL-1",
		severity: "high",
		title: "File read combined with network send (possible exfiltration)",
		description:
			"Code reads files and makes outbound HTTP requests. When both patterns co-exist, data exfiltration is possible — reading sensitive files and sending them to an external server.",
		pattern: /readFileSync|readFile/,
		requiresContext: /\bfetch\b|\bpost\b|http\.request/i,
		owaspCategory: "ASST-02",
		deduction: 15,
	},
	{
		id: "CS-OBFUSCATED-HEX-1",
		severity: "medium",
		title: "Hex-encoded string sequence (possible obfuscation)",
		description:
			"Long hex-encoded string sequence detected. Obfuscated code hides its true intent — legitimate skills have no reason to hex-encode strings.",
		pattern: /(\\x[0-9a-fA-F]{2}){6,}/,
		owaspCategory: "ASST-10",
		deduction: 12,
	},
	{
		id: "CS-OBFUSCATED-B64-1",
		severity: "medium",
		title: "Large base64 payload with decode call (possible obfuscation)",
		description:
			"A base64-encoded string (200+ chars) passed to a decode function. This is a common obfuscation technique to hide malicious payloads in plain sight.",
		pattern: /(?:atob|Buffer\.from)\s*\(\s*["'][A-Za-z0-9+/=]{200,}["']/,
		owaspCategory: "ASST-10",
		deduction: 12,
	},
	{
		id: "CS-ENV-HARVEST-1",
		severity: "critical",
		title: "Environment variable access + network send (credential harvesting)",
		description:
			"Code accesses process.env and makes outbound network requests. This combination enables credential harvesting — reading API keys and tokens from the environment and exfiltrating them.",
		pattern: /process\.env/,
		requiresContext: /\bfetch\b|\bpost\b|http\.request/i,
		owaspCategory: "ASST-05",
		deduction: 20,
	},
];

// ---------------------------------------------------------------------------
// Code block extraction
// ---------------------------------------------------------------------------

interface CodeBlock {
	readonly language: string;
	readonly content: string;
	readonly startLine: number;
	readonly isExample: boolean;
}

/**
 * Extract fenced code blocks from markdown content.
 * Marks blocks as "examples" when they appear in sections like
 * "Example", "Usage", "Demo", or "Output".
 */
function extractCodeBlocks(rawContent: string): CodeBlock[] {
	const blocks: CodeBlock[] = [];
	const lines = rawContent.split("\n");
	let inBlock = false;
	let language = "";
	let content: string[] = [];
	let startLine = 0;
	let lastHeading = "";

	const EXAMPLE_HEADINGS = /\b(examples?|usage|demo|output|samples?|tutorial|getting.started|how.to)\b/i;

	for (let i = 0; i < lines.length; i++) {
		const line = lines[i] as string;

		// Track headings for context
		const headingMatch = line.match(/^#{1,4}\s+(.+)/);
		if (headingMatch) {
			lastHeading = headingMatch[1] ?? "";
		}

		if (!inBlock && line.startsWith("```")) {
			inBlock = true;
			language = line.slice(3).trim().split(/\s/)[0]?.toLowerCase() ?? "";
			content = [];
			startLine = i + 1;
		} else if (inBlock && line.startsWith("```")) {
			inBlock = false;
			if (content.length > 0) {
				blocks.push({
					language,
					content: content.join("\n"),
					startLine,
					isExample: EXAMPLE_HEADINGS.test(lastHeading),
				});
			}
		} else if (inBlock) {
			content.push(line);
		}
	}

	return blocks;
}

/**
 * Determine if a code block language is scannable for safety issues.
 */
function isScannableLanguage(lang: string): boolean {
	const scannable = new Set([
		"js", "javascript", "ts", "typescript", "mjs", "cjs",
		"jsx", "tsx", "node", "sh", "bash", "zsh", "shell",
		"python", "py", "rb", "ruby", "perl",
		"", // untagged blocks — scan conservatively
	]);
	return scannable.has(lang);
}

// ---------------------------------------------------------------------------
// Core scanning logic
// ---------------------------------------------------------------------------

function truncateEvidence(evidence: string, maxLen = 120): string {
	return evidence.length <= maxLen ? evidence : `${evidence.slice(0, maxLen)}…`;
}

/** Well-known installer domains where curl|sh is expected and lower risk */
const KNOWN_INSTALLER_DOMAINS =
	/(?:deno\.land|bun\.sh|rustup\.rs|get\.docker\.com|install\.python-poetry\.org|nvm-sh|golangci|foundry\.paradigm\.xyz|tailscale\.com|opencode\.ai|sh\.rustup\.rs|get\.pnpm\.io|volta\.sh)/i;

function scanCodeBlock(block: CodeBlock, isDefenseSkill: boolean): Finding[] {
	const findings: Finding[] = [];
	const source = block.content;
	const lines = source.split("\n");
	const matchedLineRules = new Set<string>();

	// --- Line rules ---
	for (const rule of LINE_RULES) {
		if (matchedLineRules.has(rule.id)) continue;

		// Skip if context requirement not met
		if (rule.requiresContext && !rule.requiresContext.test(source)) continue;

		for (let i = 0; i < lines.length; i++) {
			const line = lines[i] as string;
			const match = rule.pattern.exec(line);
			if (!match) continue;

			// WebSocket port check
			if (rule.id === "CS-WEBSOCKET-NONSTANDARD-1" && match[1]) {
				const port = parseInt(match[1], 10);
				if (STANDARD_PORTS.has(port)) continue;
			}

			// Known installer domains in curl|sh patterns — downgrade severity
			const isKnownInstaller =
				rule.id === "CS-CURL-PIPE-1" && KNOWN_INSTALLER_DOMAINS.test(line);
			const isReducedContext = block.isExample || isKnownInstaller;

			// Defense/educational skills with example code blocks: fully suppress
			if (isDefenseSkill && block.isExample) continue;

			// Reduce severity for example/documentation code blocks or known installers
			const effectiveSeverity = isReducedContext
				? downgrade(rule.severity)
				: rule.severity;
			const effectiveDeduction = isReducedContext
				? Math.ceil(rule.deduction / 3)
				: rule.deduction;

			const contextNote = isKnownInstaller
				? "(Well-known installer domain — reduced severity.)"
				: block.isExample
					? "(Found in example/documentation code block — reduced severity.)"
					: "";
			findings.push({
				id: rule.id,
				category: "code-safety",
				severity: effectiveSeverity,
				title: rule.title,
				description: contextNote
					? `${rule.description} ${contextNote}`
					: rule.description,
				evidence: truncateEvidence(line.trim()),
				lineNumber: block.startLine + i,
				deduction: effectiveDeduction,
				recommendation: `Review the code block starting at line ${block.startLine}. ${
					isKnownInstaller
						? "This uses a well-known installer — consider pinning to a specific version or hash."
						: block.isExample
							? "This appears in an example section — verify it is documentation, not executed code."
							: "Ensure this pattern is necessary and does not pose a security risk."
				}`,
				owaspCategory: rule.owaspCategory,
			});
			matchedLineRules.add(rule.id);
			break; // one finding per line-rule per block
		}
	}

	// --- Source-level rules ---
	const matchedSourceRules = new Set<string>();
	for (const rule of SOURCE_RULES) {
		if (matchedSourceRules.has(rule.id)) continue;
		if (!rule.pattern.test(source)) continue;
		if (rule.requiresContext && !rule.requiresContext.test(source)) continue;

		// Find evidence line
		let matchLine = block.startLine;
		let matchEvidence = "";
		for (let i = 0; i < lines.length; i++) {
			if (rule.pattern.test(lines[i] as string)) {
				matchLine = block.startLine + i;
				matchEvidence = (lines[i] as string).trim();
				break;
			}
		}
		if (!matchEvidence) matchEvidence = source.slice(0, 120);

		const effectiveSeverity = block.isExample ? downgrade(rule.severity) : rule.severity;
		const effectiveDeduction = block.isExample ? Math.ceil(rule.deduction / 3) : rule.deduction;

		findings.push({
			id: rule.id,
			category: "code-safety",
			severity: effectiveSeverity,
			title: rule.title,
			description: block.isExample
				? `${rule.description} (Found in example/documentation code block — reduced severity.)`
				: rule.description,
			evidence: truncateEvidence(matchEvidence),
			lineNumber: matchLine,
			deduction: effectiveDeduction,
			recommendation: "Review the code for legitimate use. If this is instructional, consider adding a safety disclaimer.",
			owaspCategory: rule.owaspCategory,
		});
		matchedSourceRules.add(rule.id);
	}

	return findings;
}

/**
 * Downgrade severity by one level (for example/documentation context).
 */
function downgrade(severity: Finding["severity"]): Finding["severity"] {
	switch (severity) {
		case "critical": return "high";
		case "high": return "medium";
		case "medium": return "low";
		case "low": return "info";
		case "info": return "info";
	}
}

// ---------------------------------------------------------------------------
// Public analyzer interface
// ---------------------------------------------------------------------------

const WEIGHT = 0.15;

/**
 * Analyze embedded code blocks in a skill for dangerous runtime patterns.
 *
 * Extracts fenced code blocks from the SKILL.md content and scans them
 * for shell execution, eval, exfiltration, obfuscation, credential
 * harvesting, and crypto mining indicators.
 */
export async function analyzeCodeSafety(skill: ParsedSkill): Promise<CategoryScore> {
	const blocks = extractCodeBlocks(skill.rawContent);
	const scannableBlocks = blocks.filter((b) => isScannableLanguage(b.language));
	const isDefenseSkill = isSecurityDefenseSkill(skill);

	if (scannableBlocks.length === 0) {
		return {
			score: 100,
			weight: WEIGHT,
			findings: [],
			summary: "No executable code blocks found in skill content.",
		};
	}

	const allFindings: Finding[] = [];
	for (const block of scannableBlocks) {
		const findings = scanCodeBlock(block, isDefenseSkill);
		allFindings.push(...findings);
	}

	// Deduplicate: one finding per rule ID across all blocks
	const seen = new Set<string>();
	const deduped: Finding[] = [];
	for (const f of allFindings) {
		if (seen.has(f.id)) continue;
		seen.add(f.id);
		deduped.push(f);
	}

	// Calculate score
	let score = 100;
	for (const f of deduped) {
		score = Math.max(0, score - f.deduction);
	}

	const criticalCount = deduped.filter((f) => f.severity === "critical").length;
	const highCount = deduped.filter((f) => f.severity === "high").length;

	let summary = `Scanned ${scannableBlocks.length} code block(s). `;
	if (deduped.length === 0) {
		summary += "No dangerous patterns detected.";
	} else {
		summary += `Found ${deduped.length} issue(s)`;
		if (criticalCount > 0) summary += ` (${criticalCount} critical)`;
		if (highCount > 0) summary += ` (${highCount} high)`;
		summary += ".";
	}

	return {
		score,
		weight: WEIGHT,
		findings: deduped,
		summary,
	};
}

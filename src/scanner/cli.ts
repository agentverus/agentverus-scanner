#!/usr/bin/env node
import { writeFile } from "node:fs/promises";
import { basename } from "node:path";
import { scanTargetsBatch } from "./runner.js";
import { buildSarifLog } from "./sarif.js";
import { expandScanTargets } from "./targets.js";
import type { Finding, Severity, TrustReport } from "./types.js";
import { SCANNER_VERSION } from "./types.js";

const COLORS = {
	reset: "\x1b[0m",
	bold: "\x1b[1m",
	red: "\x1b[31m",
	green: "\x1b[32m",
	yellow: "\x1b[33m",
	blue: "\x1b[34m",
	magenta: "\x1b[35m",
	cyan: "\x1b[36m",
	gray: "\x1b[90m",
	bgRed: "\x1b[41m",
	bgGreen: "\x1b[42m",
	bgYellow: "\x1b[43m",
	bgMagenta: "\x1b[45m",
} as const;

function badgeColor(badge: string): string {
	switch (badge) {
		case "certified":
			return COLORS.green;
		case "conditional":
			return COLORS.yellow;
		case "suspicious":
			return `${COLORS.yellow}`;
		case "rejected":
			return COLORS.red;
		default:
			return COLORS.gray;
	}
}

function severityColor(severity: string): string {
	switch (severity) {
		case "critical":
			return COLORS.red;
		case "high":
			return COLORS.magenta;
		case "medium":
			return COLORS.yellow;
		case "low":
			return COLORS.blue;
		default:
			return COLORS.gray;
	}
}

function printReport(report: TrustReport): void {
	const color = badgeColor(report.badge);

	console.log();
	console.log(`${COLORS.bold}AgentVerus Scanner v${report.metadata.scannerVersion}${COLORS.reset}`);
	console.log("─".repeat(60));

	// Overall score
	console.log(
		`\n${COLORS.bold}Overall Score:${COLORS.reset} ${color}${COLORS.bold}${report.overall}/100${COLORS.reset}`,
	);
	console.log(
		`${COLORS.bold}Badge:${COLORS.reset}         ${color}${COLORS.bold}${report.badge.toUpperCase()}${COLORS.reset}`,
	);
	console.log(`${COLORS.bold}Format:${COLORS.reset}        ${report.metadata.skillFormat}`);
	console.log(`${COLORS.bold}Duration:${COLORS.reset}      ${report.metadata.durationMs}ms`);

	// Category breakdown
	console.log(`\n${COLORS.bold}Category Scores:${COLORS.reset}`);
	for (const [name, cat] of Object.entries(report.categories)) {
		const barLen = Math.round(cat.score / 2);
		const bar = "█".repeat(barLen) + "░".repeat(50 - barLen);
		const catColor =
			cat.score >= 90
				? COLORS.green
				: cat.score >= 75
					? COLORS.yellow
					: cat.score >= 50
						? COLORS.yellow
						: COLORS.red;
		console.log(
			`  ${name.padEnd(15)} ${catColor}${bar} ${cat.score}/100${COLORS.reset} (weight: ${(cat.weight * 100).toFixed(0)}%)`,
		);
	}

	// Findings
	if (report.findings.length > 0) {
		console.log(`\n${COLORS.bold}Findings (${report.findings.length}):${COLORS.reset}`);

		const bySeverity: Record<string, Finding[]> = {};
		for (const finding of report.findings) {
			const sev = finding.severity;
			if (!bySeverity[sev]) bySeverity[sev] = [];
			bySeverity[sev]?.push(finding);
		}

		for (const severity of ["critical", "high", "medium", "low", "info"]) {
			const severityFindings = bySeverity[severity];
			if (!severityFindings?.length) continue;

			const color = severityColor(severity);
			console.log(
				`\n  ${color}${COLORS.bold}${severity.toUpperCase()} (${severityFindings.length})${COLORS.reset}`,
			);

			for (const finding of severityFindings) {
				console.log(`    ${color}●${COLORS.reset} ${finding.title}`);
				if (finding.evidence) {
					console.log(
						`      ${COLORS.gray}Evidence: ${finding.evidence.slice(0, 120)}${COLORS.reset}`,
					);
				}
				if (finding.lineNumber) {
					console.log(`      ${COLORS.gray}Line: ${finding.lineNumber}${COLORS.reset}`);
				}
				console.log(
					`      ${COLORS.gray}[${finding.owaspCategory}] ${finding.recommendation.slice(0, 120)}${COLORS.reset}`,
				);
			}
		}
	}

	console.log("\n" + "─".repeat(60));
}

function generateMarkdownReport(report: TrustReport, source: string): string {
	const lines: string[] = [];

	lines.push(`# AgentVerus Trust Report`);
	lines.push(``);
	lines.push(`**Source:** ${source}`);
	lines.push(`**Scanner:** v${report.metadata.scannerVersion}`);
	lines.push(`**Scanned:** ${new Date().toISOString()}`);
	lines.push(`**Format:** ${report.metadata.skillFormat}`);
	lines.push(`**Duration:** ${report.metadata.durationMs}ms`);
	lines.push(``);
	lines.push(`## Result`);
	lines.push(``);
	lines.push(`| Metric | Value |`);
	lines.push(`|--------|-------|`);
	lines.push(`| **Score** | ${report.overall}/100 |`);
	lines.push(`| **Badge** | ${report.badge.toUpperCase()} |`);
	lines.push(``);

	lines.push(`## Category Scores`);
	lines.push(``);
	lines.push(`| Category | Score | Weight |`);
	lines.push(`|----------|-------|--------|`);
	for (const [name, cat] of Object.entries(report.categories)) {
		lines.push(`| ${name} | ${cat.score}/100 | ${(cat.weight * 100).toFixed(0)}% |`);
	}
	lines.push(``);

	if (report.findings.length > 0) {
		lines.push(`## Findings (${report.findings.length})`);
		lines.push(``);

		for (const severity of ["critical", "high", "medium", "low", "info"]) {
			const findings = report.findings.filter((f) => f.severity === severity);
			if (findings.length === 0) continue;

			lines.push(`### ${severity.toUpperCase()} (${findings.length})`);
			lines.push(``);

			for (const finding of findings) {
				lines.push(`- **${finding.title}** \`${finding.owaspCategory}\``);
				if (finding.evidence) {
					lines.push(`  - Evidence: \`${finding.evidence.slice(0, 200)}\``);
				}
				lines.push(`  - ${finding.recommendation}`);
				lines.push(``);
			}
		}
	} else {
		lines.push(`## Findings`);
		lines.push(``);
		lines.push(`No security findings detected.`);
		lines.push(``);
	}

	lines.push(`---`);
	lines.push(`*Generated by [AgentVerus Scanner](https://agentverus.ai)*`);

	return lines.join("\n");
}

function printUsage(): void {
	console.log(`
${COLORS.bold}AgentVerus Scanner v${SCANNER_VERSION}${COLORS.reset}
Security and trust analysis for AI agent skills.

${COLORS.bold}USAGE${COLORS.reset}
  agentverus-scanner scan <target...> [options]
  agentverus-scanner --help
  agentverus-scanner --version

${COLORS.bold}COMMANDS${COLORS.reset}
  scan <target...> Scan a skill file, URL, or directory (directories are searched for SKILL.md)

${COLORS.bold}OPTIONS${COLORS.reset}
  --json           Output raw JSON report
  --report [path]  Generate markdown report (default: <name>-trust-report.md)
  --sarif [path]   Write SARIF 2.1.0 output (default: agentverus-scanner.sarif)
  --semantic        Enable LLM-assisted semantic analysis (requires AGENTVERUS_LLM_API_KEY)
  --fail-on-severity <level>  Fail if findings at/above level exist (critical|high|medium|low|info|none)
  --timeout <ms>    URL fetch timeout in ms (default varies by source; set <=0 to disable)
  --retries <n>     URL fetch retries for transient failures (default: 2)
  --retry-delay-ms <ms>  Base retry delay in ms (default: 750)
  --help, -h       Show this help
  --version, -v    Show version

${COLORS.bold}EXAMPLES${COLORS.reset}
  agentverus-scanner scan ./SKILL.md
  agentverus-scanner scan . --sarif
  agentverus-scanner scan https://raw.githubusercontent.com/user/repo/main/SKILL.md
  agentverus-scanner scan ./SKILL.md --json
  agentverus-scanner scan ./SKILL.md --report
  agentverus-scanner scan ./SKILL.md --report my-report.md
  agentverus-scanner scan ./SKILL.md --sarif results.sarif --fail-on-severity high

${COLORS.bold}EXIT CODES${COLORS.reset}
  0  Scan passed
  1  Scan completed but policy failed
  2  One or more targets failed to scan

${COLORS.bold}MORE INFO${COLORS.reset}
  https://agentverus.ai
  https://github.com/agentverus/agentverus-scanner
`);
}

type FailOnSeverity = Severity | "none";

const FAIL_SEVERITY_RANK: Readonly<Record<Severity, number>> = {
	critical: 0,
	high: 1,
	medium: 2,
	low: 3,
	info: 4,
};

function parseFailOnSeverity(value: string): FailOnSeverity {
	const lower = value.toLowerCase();
	if (lower === "none") return "none";
	if (lower === "critical" || lower === "high" || lower === "medium" || lower === "low" || lower === "info") {
		return lower;
	}
	throw new Error(`Invalid --fail-on-severity value: ${value}`);
}

function shouldFailOnSeverity(reports: readonly TrustReport[], threshold: FailOnSeverity): boolean {
	if (threshold === "none") return false;
	const limit = FAIL_SEVERITY_RANK[threshold] ?? 99;
	for (const report of reports) {
		for (const finding of report.findings) {
			if ((FAIL_SEVERITY_RANK[finding.severity] ?? 99) <= limit) return true;
		}
	}
	return false;
}

function parseOptionalInt(value: string | undefined, flag: string): number | undefined {
	if (value === undefined) return undefined;
	const n = Number.parseInt(value, 10);
	if (Number.isNaN(n)) throw new Error(`Invalid ${flag} value: ${value}`);
	return n;
}

async function main(): Promise<void> {
	const args = process.argv.slice(2);

	if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
		printUsage();
		process.exit(0);
	}

	if (args.includes("--version") || args.includes("-v")) {
		console.log(SCANNER_VERSION);
		process.exit(0);
	}

	const command = args[0];
	if (command !== "scan") {
		// Backward compat: treat first arg as file path if not a command
		if (command && !command.startsWith("-")) {
			args.unshift("scan");
		} else {
			console.error(`Unknown command: ${command}`);
			printUsage();
			process.exit(1);
		}
	}

	// Remove "scan" from args
	const scanArgs = args.slice(1);
	let jsonFlag = false;
	let reportFlag = false;
	let reportPath: string | undefined;
	let sarifFlag = false;
	let sarifPath: string | undefined;
	let failOnSeverity: FailOnSeverity | undefined;
	let semanticFlag = false;
	let timeout: number | undefined;
	let retries: number | undefined;
	let retryDelayMs: number | undefined;

	const rawTargets: string[] = [];

	for (let i = 0; i < scanArgs.length; i += 1) {
		const arg = scanArgs[i];
		if (!arg) continue;

		if (arg === "--json") {
			jsonFlag = true;
			continue;
		}

		if (arg === "--report") {
			reportFlag = true;
			const next = scanArgs[i + 1];
			if (next && !next.startsWith("-")) {
				reportPath = next;
				i += 1;
			}
			continue;
		}

		if (arg === "--sarif") {
			sarifFlag = true;
			const next = scanArgs[i + 1];
			if (next && !next.startsWith("-")) {
				sarifPath = next;
				i += 1;
			}
			continue;
		}

		if (arg === "--semantic") {
			semanticFlag = true;
			continue;
		}

		if (arg === "--fail-on-severity") {
			const next = scanArgs[i + 1];
			if (!next || next.startsWith("-")) throw new Error("Missing value for --fail-on-severity");
			failOnSeverity = parseFailOnSeverity(next);
			i += 1;
			continue;
		}

		if (arg === "--timeout") {
			const next = scanArgs[i + 1];
			if (!next || next.startsWith("-")) throw new Error("Missing value for --timeout");
			timeout = parseOptionalInt(next, "--timeout");
			i += 1;
			continue;
		}

		if (arg === "--retries") {
			const next = scanArgs[i + 1];
			if (!next || next.startsWith("-")) throw new Error("Missing value for --retries");
			retries = parseOptionalInt(next, "--retries");
			i += 1;
			continue;
		}

		if (arg === "--retry-delay-ms") {
			const next = scanArgs[i + 1];
			if (!next || next.startsWith("-")) throw new Error("Missing value for --retry-delay-ms");
			retryDelayMs = parseOptionalInt(next, "--retry-delay-ms");
			i += 1;
			continue;
		}

		if (arg.startsWith("-")) throw new Error(`Unknown option: ${arg}`);

		rawTargets.push(arg);
	}

	if (rawTargets.length === 0) {
		console.error("Error: No scan targets provided");
		printUsage();
		process.exit(1);
	}

	const expandedTargets = await expandScanTargets(rawTargets);
	if (expandedTargets.length === 0) {
		console.error("Error: No SKILL.md files found in the provided directory target(s)");
		process.exit(1);
	}

	const scanOptions = {
		timeout,
		retries,
		retryDelayMs,
		semantic: semanticFlag ? true : undefined,
	} satisfies import("./types.js").ScanOptions;

	if (!jsonFlag) {
		if (expandedTargets.length === 1) {
			console.log(`Scanning: ${expandedTargets[0]}`);
		} else {
			console.log(`Scanning ${expandedTargets.length} targets...`);
		}
	}

	const { reports: scanned, failures } = await scanTargetsBatch(expandedTargets, scanOptions);

	if (jsonFlag) {
		const json =
			expandedTargets.length === 1 && failures.length === 0
				? scanned[0]?.report
				: { reports: scanned, failures };
		console.log(JSON.stringify(json, null, 2));
	} else {
		for (const item of scanned) {
			if (expandedTargets.length > 1) {
				console.log(`\n${COLORS.gray}${item.target}${COLORS.reset}`);
			}
			printReport(item.report);
		}

		if (failures.length > 0) {
			console.log(`\n${COLORS.bold}${COLORS.red}Scan failures (${failures.length}):${COLORS.reset}`);
			for (const f of failures) {
				console.log(`  ${COLORS.red}✖${COLORS.reset} ${f.target}`);
				console.log(`    ${COLORS.gray}${f.error}${COLORS.reset}`);
			}
		}
	}

	if (reportFlag) {
		if (reportPath && expandedTargets.length !== 1) {
			throw new Error("--report <path> can only be used when scanning a single target");
		}

		const used = new Map<string, number>();
		for (let i = 0; i < scanned.length; i += 1) {
			const item = scanned[i];
			if (!item) continue;

			const isUrl = item.target.startsWith("http://") || item.target.startsWith("https://");
			const baseName = isUrl ? `skill-${i + 1}` : basename(item.target, ".md");
			const defaultPath = `${baseName}-trust-report.md`;
			const candidate = reportPath || defaultPath;

			const seen = used.get(candidate) ?? 0;
			used.set(candidate, seen + 1);
			const outPath = seen === 0 ? candidate : candidate.replace(/\.md$/i, `-${seen + 1}.md`);

			const markdown = generateMarkdownReport(item.report, item.target);
			await writeFile(outPath, markdown, "utf-8");
			if (!jsonFlag) console.log(`\n${COLORS.green}Report saved to: ${outPath}${COLORS.reset}`);
		}
	}

	if (sarifFlag) {
		const outPath = sarifPath || "agentverus-scanner.sarif";
		const sarif = buildSarifLog(scanned, failures);
		await writeFile(outPath, JSON.stringify(sarif, null, 2), "utf-8");
		if (!jsonFlag) console.log(`\n${COLORS.green}SARIF saved to: ${outPath}${COLORS.reset}`);
	}

	const scannedReports: TrustReport[] = scanned.map((s) => s.report);

	// Exit codes:
	// - 2: scan failed for one or more targets (incomplete results)
	// - 1: scan completed but policy failed
	// - 0: pass
	if (failures.length > 0) process.exit(2);

	if (failOnSeverity && shouldFailOnSeverity(scannedReports, failOnSeverity)) process.exit(1);

	const badgeFailed = scannedReports.some((r) => r.badge === "suspicious" || r.badge === "rejected");
	process.exit(badgeFailed ? 1 : 0);
}

main().catch((err) => {
	const message = err instanceof Error ? err.message : String(err);
	console.error("Fatal error:", message);
	process.exit(1);
});

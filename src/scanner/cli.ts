#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";
import { basename } from "node:path";
import { scanSkill, scanSkillFromUrl } from "./index.js";
import type { Finding, TrustReport } from "./types.js";
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
  agentverus-scanner scan <file-or-url> [options]
  agentverus-scanner --help
  agentverus-scanner --version

${COLORS.bold}COMMANDS${COLORS.reset}
  scan <target>    Scan a skill file or URL

${COLORS.bold}OPTIONS${COLORS.reset}
  --json           Output raw JSON report
  --report [path]  Generate markdown report (default: <name>-trust-report.md)
  --help, -h       Show this help
  --version, -v    Show version

${COLORS.bold}EXAMPLES${COLORS.reset}
  agentverus-scanner scan ./SKILL.md
  agentverus-scanner scan https://raw.githubusercontent.com/user/repo/main/SKILL.md
  agentverus-scanner scan ./SKILL.md --json
  agentverus-scanner scan ./SKILL.md --report
  agentverus-scanner scan ./SKILL.md --report my-report.md

${COLORS.bold}EXIT CODES${COLORS.reset}
  0  CERTIFIED or CONDITIONAL
  1  SUSPICIOUS or REJECTED

${COLORS.bold}MORE INFO${COLORS.reset}
  https://agentverus.ai
  https://github.com/agentverus/agentverus-scanner
`);
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
	const jsonFlag = scanArgs.includes("--json");
	const reportFlagIndex = scanArgs.indexOf("--report");
	const reportFlag = reportFlagIndex !== -1;
	let reportPath: string | undefined;

	if (reportFlag && scanArgs[reportFlagIndex + 1] && !scanArgs[reportFlagIndex + 1]?.startsWith("-")) {
		reportPath = scanArgs[reportFlagIndex + 1];
	}

	// Find the target (first non-flag argument)
	const target = scanArgs.find((a) => !a.startsWith("-") && a !== reportPath);

	if (!target) {
		console.error("Error: No file path or URL provided");
		printUsage();
		process.exit(1);
	}

	const isUrl = target.startsWith("http://") || target.startsWith("https://");

	let report: TrustReport;

	if (isUrl) {
		if (!jsonFlag) console.log(`Scanning URL: ${target}`);
		report = await scanSkillFromUrl(target);
	} else {
		if (!jsonFlag) console.log(`Scanning file: ${target}`);
		const content = await readFile(target, "utf-8");
		report = await scanSkill(content);
	}

	if (jsonFlag) {
		console.log(JSON.stringify(report, null, 2));
	} else {
		printReport(report);
	}

	if (reportFlag) {
		const name = isUrl ? "skill" : basename(target, ".md");
		const outPath = reportPath || `${name}-trust-report.md`;
		const markdown = generateMarkdownReport(report, target);
		await writeFile(outPath, markdown, "utf-8");
		if (!jsonFlag) {
			console.log(`\n${COLORS.green}Report saved to: ${outPath}${COLORS.reset}`);
		}
	}

	// Exit code based on badge
	const exitCode = report.badge === "certified" || report.badge === "conditional" ? 0 : 1;
	process.exit(exitCode);
}

main().catch((err) => {
	console.error("Fatal error:", err);
	process.exit(1);
});

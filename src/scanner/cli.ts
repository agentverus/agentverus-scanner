#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { scanSkill, scanSkillFromUrl } from "./index.js";
import type { TrustReport, Finding } from "./types.js";

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
	console.log(
		`${COLORS.bold}AgentVerus Scanner v${report.metadata.scannerVersion}${COLORS.reset}`,
	);
	console.log("─".repeat(60));

	// Overall score
	console.log(
		`\n${COLORS.bold}Overall Score:${COLORS.reset} ${color}${COLORS.bold}${report.overall}/100${COLORS.reset}`,
	);
	console.log(
		`${COLORS.bold}Badge:${COLORS.reset}         ${color}${COLORS.bold}${report.badge.toUpperCase()}${COLORS.reset}`,
	);
	console.log(
		`${COLORS.bold}Format:${COLORS.reset}        ${report.metadata.skillFormat}`,
	);
	console.log(
		`${COLORS.bold}Duration:${COLORS.reset}      ${report.metadata.durationMs}ms`,
	);

	// Category breakdown
	console.log(`\n${COLORS.bold}Category Scores:${COLORS.reset}`);
	for (const [name, cat] of Object.entries(report.categories)) {
		const barLen = Math.round(cat.score / 2);
		const bar = "█".repeat(barLen) + "░".repeat(50 - barLen);
		const catColor = cat.score >= 90 ? COLORS.green : cat.score >= 75 ? COLORS.yellow : cat.score >= 50 ? COLORS.yellow : COLORS.red;
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
				console.log(
					`    ${color}●${COLORS.reset} ${finding.title}`,
				);
				if (finding.evidence) {
					console.log(
						`      ${COLORS.gray}Evidence: ${finding.evidence.slice(0, 120)}${COLORS.reset}`,
					);
				}
				if (finding.lineNumber) {
					console.log(
						`      ${COLORS.gray}Line: ${finding.lineNumber}${COLORS.reset}`,
					);
				}
				console.log(
					`      ${COLORS.gray}[${finding.owaspCategory}] ${finding.recommendation.slice(0, 120)}${COLORS.reset}`,
				);
			}
		}
	}

	console.log("\n" + "─".repeat(60));
}

async function main(): Promise<void> {
	const args = process.argv.slice(2);

	if (args.length === 0) {
		console.error(
			"Usage: pnpm scan <file-path> [--url <url>] [--json]",
		);
		process.exit(1);
	}

	let report: TrustReport;
	const jsonFlag = args.includes("--json");
	const urlIndex = args.indexOf("--url");

	if (urlIndex !== -1 && args[urlIndex + 1]) {
		const url = args[urlIndex + 1] as string;
		if (!jsonFlag) console.log(`Scanning URL: ${url}`);
		report = await scanSkillFromUrl(url);
	} else {
		const filePath = args.find((a) => !a.startsWith("--"));
		if (!filePath) {
			console.error("Error: No file path provided");
			process.exit(1);
		}
		if (!jsonFlag) console.log(`Scanning file: ${filePath}`);
		const content = await readFile(filePath, "utf-8");
		report = await scanSkill(content);
	}

	if (jsonFlag) {
		console.log(JSON.stringify(report, null, 2));
	} else {
		printReport(report);
	}

	// Exit code based on badge
	const exitCode =
		report.badge === "certified" || report.badge === "conditional"
			? 0
			: 1;
	process.exit(exitCode);
}

main().catch((err) => {
	console.error("Fatal error:", err);
	process.exit(1);
});

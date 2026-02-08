#!/usr/bin/env node
/**
 * Registry CLI commands: check, registry scan, registry report, registry site
 */

import { scanSkill } from "../scanner/index.js";
import { fetchSkillContentFromUrl } from "../scanner/source.js";
import type { TrustReport } from "../scanner/types.js";
import { batchScanRegistry } from "./batch-scanner.js";
import { generateAnalysisReport } from "./report-generator.js";
import { generateSite } from "./site-generator.js";

const C = {
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
} as const;

function badgeColor(badge: string): string {
	switch (badge) {
		case "certified": return C.green;
		case "conditional": return C.yellow;
		case "suspicious": return C.yellow;
		case "rejected": return C.red;
		default: return C.gray;
	}
}

function badgeEmoji(badge: string): string {
	switch (badge) {
		case "certified": return "🟢";
		case "conditional": return "🟡";
		case "suspicious": return "🟠";
		case "rejected": return "🔴";
		default: return "⚪";
	}
}

function severityColor(severity: string): string {
	switch (severity) {
		case "critical": return C.red;
		case "high": return C.magenta;
		case "medium": return C.yellow;
		case "low": return C.blue;
		default: return C.gray;
	}
}

function printCheckReport(slug: string, report: TrustReport): void {
	const color = badgeColor(report.badge);
	const emoji = badgeEmoji(report.badge);

	console.log();
	console.log(`${C.bold}AgentVerus Trust Check${C.reset}  —  ${C.cyan}${slug}${C.reset}`);
	console.log("─".repeat(60));

	console.log(`\n  ${C.bold}Score:${C.reset}  ${color}${C.bold}${report.overall}/100${C.reset}`);
	console.log(`  ${C.bold}Badge:${C.reset}  ${emoji} ${color}${C.bold}${report.badge.toUpperCase()}${C.reset}`);
	console.log(`  ${C.bold}Name:${C.reset}   ${report.metadata.skillName}`);
	console.log(`  ${C.bold}Format:${C.reset} ${report.metadata.skillFormat}`);
	console.log(`  ${C.bold}Scan:${C.reset}   ${report.metadata.durationMs}ms`);

	// Category bars
	console.log(`\n  ${C.bold}Categories:${C.reset}`);
	for (const [name, cat] of Object.entries(report.categories)) {
		const barLen = Math.round(cat.score / 5);
		const filled = "█".repeat(barLen);
		const empty = "░".repeat(20 - barLen);
		const catColor = cat.score >= 90 ? C.green : cat.score >= 75 ? C.yellow : cat.score >= 50 ? C.yellow : C.red;
		console.log(`    ${name.padEnd(14)} ${catColor}${filled}${empty} ${cat.score}${C.reset}`);
	}

	// Findings
	if (report.findings.length > 0) {
		console.log(`\n  ${C.bold}Findings (${report.findings.length}):${C.reset}`);
		for (const finding of report.findings.slice(0, 15)) {
			const sColor = severityColor(finding.severity);
			console.log(`    ${sColor}${finding.severity.toUpperCase().padEnd(8)}${C.reset} ${finding.title}`);
			if (finding.evidence) {
				console.log(`             ${C.gray}${finding.evidence.slice(0, 100)}${C.reset}`);
			}
		}
		if (report.findings.length > 15) {
			console.log(`    ${C.gray}... and ${report.findings.length - 15} more${C.reset}`);
		}
	} else {
		console.log(`\n  ${C.green}No security findings detected.${C.reset}`);
	}

	console.log(`\n${"─".repeat(60)}`);

	// Verdict line
	if (report.badge === "certified") {
		console.log(`\n  ${C.green}${C.bold}✓ This skill appears safe to install.${C.reset}\n`);
	} else if (report.badge === "conditional") {
		console.log(`\n  ${C.yellow}${C.bold}⚠ This skill has minor concerns. Review findings before installing.${C.reset}\n`);
	} else if (report.badge === "suspicious") {
		console.log(`\n  ${C.yellow}${C.bold}⚠ This skill has notable security concerns. Review carefully.${C.reset}\n`);
	} else {
		console.log(`\n  ${C.red}${C.bold}✖ This skill failed the security check. Do not install without thorough review.${C.reset}\n`);
	}
}

/**
 * Handle `agentverus check <slug>` command.
 * Fetches a skill from ClawHub by slug and scans it.
 */
export async function handleCheck(args: string[]): Promise<number> {
	const slugs: string[] = [];
	let jsonFlag = false;

	for (let i = 0; i < args.length; i++) {
		const arg = args[i] as string;
		if (arg === "--json") { jsonFlag = true; continue; }
		if (arg.startsWith("-")) {
			console.error(`Unknown option: ${arg}`);
			return 1;
		}
		slugs.push(arg);
	}

	if (slugs.length === 0) {
		console.error(`${C.red}Error: No skill slug provided${C.reset}`);
		console.error(`\nUsage: agentverus check <slug> [--json]`);
		console.error(`\nExamples:`);
		console.error(`  agentverus check web-search`);
		console.error(`  agentverus check git-commit --json`);
		return 1;
	}

	const results: { slug: string; report: TrustReport }[] = [];
	const failures: { slug: string; error: string }[] = [];

	for (const slug of slugs) {
		const url = `https://auth.clawdhub.com/api/v1/download?slug=${encodeURIComponent(slug)}`;

		if (!jsonFlag) {
			process.stdout.write(`${C.gray}Checking ${slug}...${C.reset}`);
		}

		try {
			const { content } = await fetchSkillContentFromUrl(url, {
				timeout: 45_000,
				retries: 2,
				retryDelayMs: 750,
			});
			const report = await scanSkill(content);
			results.push({ slug, report });

			if (!jsonFlag) {
				// Clear the "Checking..." line
				process.stdout.write(`\r${" ".repeat(60)}\r`);
				printCheckReport(slug, report);
			}
		} catch (err) {
			const message = err instanceof Error ? err.message : String(err);
			failures.push({ slug, error: message });

			if (!jsonFlag) {
				process.stdout.write(`\r${" ".repeat(60)}\r`);
				console.error(`${C.red}✖ Failed to check ${slug}: ${message}${C.reset}\n`);
			}
		}
	}

	if (jsonFlag) {
		const output = slugs.length === 1
			? (results[0]?.report ?? { error: failures[0]?.error })
			: { results: results.map(r => ({ slug: r.slug, ...r.report })), failures };
		console.log(JSON.stringify(output, null, 2));
	}

	if (failures.length > 0) return 2;
	return results.some(r => r.report.badge === "rejected" || r.report.badge === "suspicious") ? 1 : 0;
}

/**
 * Handle `agentverus registry scan` command.
 */
export async function handleRegistryScan(args: string[]): Promise<number> {
	let urlFile = "data/skill-urls.txt";
	let outDir = "data/scan-results";
	let concurrency = 25;
	let limit: number | undefined;
	let timeout = 45_000;

	for (let i = 0; i < args.length; i++) {
		const arg = args[i] as string;
		const next = args[i + 1];
		if (arg === "--urls" && next) { urlFile = next; i++; continue; }
		if (arg === "--out" && next) { outDir = next; i++; continue; }
		if (arg === "--concurrency" && next) { concurrency = Number.parseInt(next, 10); i++; continue; }
		if (arg === "--limit" && next) { limit = Number.parseInt(next, 10); i++; continue; }
		if (arg === "--timeout" && next) { timeout = Number.parseInt(next, 10); i++; continue; }
		if (arg.startsWith("-")) { console.error(`Unknown option: ${arg}`); return 1; }
	}

	console.log(`${C.bold}AgentVerus Registry Scanner${C.reset}`);
	console.log("─".repeat(60));
	console.log(`  URLs:        ${urlFile}`);
	console.log(`  Output:      ${outDir}`);
	console.log(`  Concurrency: ${concurrency}`);
	console.log(`  Timeout:     ${timeout}ms`);
	if (limit) console.log(`  Limit:       ${limit}`);
	console.log();

	const startTime = Date.now();
	let lastProgressLine = "";

	const summary = await batchScanRegistry({
		urlFile,
		outDir,
		concurrency,
		timeout,
		retries: 2,
		retryDelayMs: 750,
		limit,
		onProgress: (done, total, slug, badge) => {
			const pct = ((done / total) * 100).toFixed(1);
			const elapsed = ((Date.now() - startTime) / 1000).toFixed(0);
			const rate = done > 0 ? (done / ((Date.now() - startTime) / 1000)).toFixed(1) : "0";
			const eta = done > 0 ? Math.round((total - done) / (done / ((Date.now() - startTime) / 1000))) : 0;

			const badgeStr = badge
				? `${badgeEmoji(badge)} ${badge.toUpperCase().padEnd(11)}`
				: `${C.red}✖ ERROR${C.reset}     `;

			lastProgressLine = `  [${pct.padStart(5)}%] ${done}/${total}  ${elapsed}s  ${rate}/s  ETA ${eta}s  ${badgeStr} ${slug}`;
			process.stdout.write(`\r${lastProgressLine}${"".padEnd(20)}`);
		},
		onError: (_slug, _error) => {
			// Errors are logged via onProgress with null badge
		},
	});

	// Clear progress line
	process.stdout.write("\r" + " ".repeat(120) + "\r");

	console.log(`\n${C.bold}Scan Complete${C.reset}`);
	console.log("─".repeat(60));
	console.log(`  Scanned:     ${summary.scanned} / ${summary.totalSkills}`);
	console.log(`  Failed:      ${summary.failed}`);
	console.log(`  Duration:    ${(summary.totalDurationMs / 1000).toFixed(1)}s`);
	console.log(`  Avg Score:   ${summary.averageScore}`);
	console.log(`  Median:      ${summary.medianScore}`);
	console.log();
	console.log(`  ${C.green}🟢 Certified:   ${summary.badges["certified"] ?? 0}${C.reset}`);
	console.log(`  ${C.yellow}🟡 Conditional: ${summary.badges["conditional"] ?? 0}${C.reset}`);
	console.log(`  🟠 Suspicious: ${summary.badges["suspicious"] ?? 0}`);
	console.log(`  ${C.red}🔴 Rejected:    ${summary.badges["rejected"] ?? 0}${C.reset}`);
	console.log();
	console.log(`  VT-blind threats: ${summary.vtGapSkills.length} skills`);
	console.log();
	console.log(`  Output: ${outDir}/`);
	console.log(`    results.json   (${summary.scanned} scan results)`);
	console.log(`    results.csv    (spreadsheet-ready)`);
	console.log(`    summary.json   (aggregate statistics)`);
	console.log(`    errors.json    (${summary.failed} failures)`);

	return 0;
}

/**
 * Handle `agentverus registry report` command.
 */
export async function handleRegistryReport(args: string[]): Promise<number> {
	let dataDir = "data/scan-results";
	let outDir = "data/report";

	for (let i = 0; i < args.length; i++) {
		const arg = args[i] as string;
		const next = args[i + 1];
		if (arg === "--data" && next) { dataDir = next; i++; continue; }
		if (arg === "--out" && next) { outDir = next; i++; continue; }
		if (arg.startsWith("-")) { console.error(`Unknown option: ${arg}`); return 1; }
	}

	console.log(`${C.bold}Generating Analysis Report...${C.reset}`);
	await generateAnalysisReport({ dataDir, outDir });
	console.log(`${C.green}✓ Report saved to ${outDir}/REPORT.md${C.reset}`);
	return 0;
}

/**
 * Handle `agentverus registry site` command.
 */
export async function handleRegistrySite(args: string[]): Promise<number> {
	let dataDir = "data/scan-results";
	let outDir = "data/site";
	let title: string | undefined;

	for (let i = 0; i < args.length; i++) {
		const arg = args[i] as string;
		const next = args[i + 1];
		if (arg === "--data" && next) { dataDir = next; i++; continue; }
		if (arg === "--out" && next) { outDir = next; i++; continue; }
		if (arg === "--title" && next) { title = next; i++; continue; }
		if (arg.startsWith("-")) { console.error(`Unknown option: ${arg}`); return 1; }
	}

	console.log(`${C.bold}Generating Static Site...${C.reset}`);
	await generateSite({ dataDir, outDir, title });
	console.log(`${C.green}✓ Site generated at ${outDir}/index.html${C.reset}`);
	console.log(`  Open with: ${C.cyan}open ${outDir}/index.html${C.reset}`);
	return 0;
}

/**
 * Print registry-specific usage.
 */
export function printRegistryUsage(): void {
	console.log(`
${C.bold}AgentVerus Registry Commands${C.reset}

${C.bold}COMMANDS${C.reset}
  check <slug...>       Check a ClawHub skill by slug (downloads and scans)
  registry scan          Batch scan all skills from the registry
  registry report        Generate markdown analysis report from scan results
  registry site          Generate static HTML dashboard from scan results

${C.bold}CHECK OPTIONS${C.reset}
  --json                 Output JSON instead of formatted report

${C.bold}REGISTRY SCAN OPTIONS${C.reset}
  --urls <path>          Path to skill-urls.txt (default: data/skill-urls.txt)
  --out <dir>            Output directory (default: data/scan-results)
  --concurrency <n>      Max parallel downloads (default: 25)
  --limit <n>            Only scan first N skills (for testing)
  --timeout <ms>         Download timeout (default: 45000)

${C.bold}REGISTRY REPORT OPTIONS${C.reset}
  --data <dir>           Scan results directory (default: data/scan-results)
  --out <dir>            Report output directory (default: data/report)

${C.bold}REGISTRY SITE OPTIONS${C.reset}
  --data <dir>           Scan results directory (default: data/scan-results)
  --out <dir>            Site output directory (default: data/site)
  --title <text>         Custom site title

${C.bold}EXAMPLES${C.reset}
  agentverus check web-search
  agentverus check git-commit docker-build --json
  agentverus registry scan --concurrency 50 --limit 100
  agentverus registry report
  agentverus registry site --title "ClawHub Security Audit"
`);
}

#!/usr/bin/env node
/**
 * Registry CLI commands: check, registry scan, registry report, registry site
 */

import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { createInterface } from "node:readline/promises";

import { scanSkill } from "../scanner/index.js";
import { fetchSkillContentFromUrl, normalizeSkillUrl } from "../scanner/source.js";
import { SCANNER_VERSION } from "../scanner/types.js";
import type { ScanOptions, TrustReport } from "../scanner/types.js";
import { batchScanRegistry } from "./batch-scanner.js";
import { generateAnalysisReport } from "./report-generator.js";
import { generateSite } from "./site-generator.js";
import {
	fetchSkillsShSitemap,
	resolveSkillsShUrl,
	resolveSkillsShUrls,
	writeResolvedUrls,
} from "./skillssh-resolver.js";

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
 * Handle `agentverus check <source...>` command.
 *
 * Supported inputs:
 * - ClawHub slug:                   web-search
 * - GitHub shorthand:               owner/repo
 * - GitHub shorthand (multi-skill): owner/repo/skill-name
 * - GitHub URL:                     https://github.com/owner/repo (and blob/tree URLs)
 * - skills.sh URL:                  https://skills.sh/owner/repo/skill
 * - Local file:                     ./path/to/SKILL.md
 */

const DEFAULT_CHECK_FETCH_OPTIONS: ScanOptions = {
	timeout: 30_000,
	retries: 2,
	retryDelayMs: 750,
};

const CLAWHUB_CHECK_FETCH_OPTIONS: ScanOptions = {
	timeout: 45_000,
	retries: 2,
	retryDelayMs: 750,
};

const GITHUB_API_HEADERS: Readonly<Record<string, string>> = {
	Accept: "application/vnd.github+json",
	"User-Agent": `AgentVerusScanner/${SCANNER_VERSION}`,
};

const GITHUB_SEGMENT_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]*$/;

interface CheckedTarget {
	readonly source: string;
	readonly target: string;
	readonly report: TrustReport;
}

interface CheckFailure {
	readonly source: string;
	readonly target: string;
	readonly error: string;
}

function getCheckUsageText(): string {
	return `
${C.bold}USAGE${C.reset}
  agentverus check <source...> [--json] [--install] [--yes]

${C.bold}SOURCES${C.reset}
  web-search                          ClawHub slug
  owner/repo                          GitHub repo (single or multi-skill)
  owner/repo/skill-name               Skill inside a multi-skill repo
  https://github.com/owner/repo        GitHub URL (repo/blob/tree)
  https://skills.sh/owner/repo/skill   skills.sh URL
  ./path/to/SKILL.md                  Local file

${C.bold}OPTIONS${C.reset}
  --json      Output JSON instead of formatted report
  --install   Prompt to run: npx skills add <source>
  --yes       Assume "yes" to prompts (non-interactive / CI)

${C.bold}EXAMPLES${C.reset}
  agentverus check web-search --install
  agentverus check vercel-labs/agent-skills
  agentverus check vercel-labs/agent-skills/react-best-practices --install
  agentverus check https://github.com/vercel-labs/agent-skills
  agentverus check https://skills.sh/vercel-labs/agent-skills/react-best-practices
  agentverus check ./SKILL.md
`;
}

function isUrlLike(input: string): boolean {
	return input.startsWith("http://") || input.startsWith("https://");
}

function looksLikeLocalPath(input: string): boolean {
	if (input.startsWith("./") || input.startsWith("../") || input.startsWith("/")) return true;
	if (input.toLowerCase().endsWith(".md")) return true;
	// Windows drive paths: C:\path\to\SKILL.md
	if (/^[A-Za-z]:\\/.test(input)) return true;
	return false;
}

function parseGithubShorthand(
	input: string,
): { readonly owner: string; readonly repo: string; readonly skill: string | null } | null {
	if (isUrlLike(input)) return null;
	if (looksLikeLocalPath(input)) return null;

	const rawParts = input.split("/").filter(Boolean);
	if (rawParts.length !== 2 && rawParts.length !== 3) return null;

	const owner = rawParts[0];
	const repoRaw = rawParts[1];
	const skill = rawParts[2] ?? null;
	if (!owner || !repoRaw) return null;

	const repo = repoRaw.replace(/\.git$/i, "");

	if (!GITHUB_SEGMENT_RE.test(owner)) return null;
	if (!GITHUB_SEGMENT_RE.test(repo)) return null;
	if (skill && !GITHUB_SEGMENT_RE.test(skill)) return null;

	return { owner, repo, skill };
}

function isNotFoundError(err: unknown): boolean {
	if (!(err instanceof Error)) return false;
	return /: 404\b/.test(err.message);
}

function isPassingBadge(badge: string): boolean {
	return badge === "certified" || badge === "conditional";
}

function encodeGithubPath(path: string): string {
	return path
		.split("/")
		.map((p) => encodeURIComponent(p))
		.join("/");
}

function labelFromGithubPath(owner: string, repo: string, path: string): string {
	const repoId = `${owner}/${repo}`;
	const parts = path.split("/").filter(Boolean);

	if (parts.length === 1) return repoId;

	const first = parts[0]?.toLowerCase();
	if (first === "skills" && parts.length >= 3) {
		const slug = parts[1];
		if (slug) return `${repoId}/${slug}`;
	}

	const dir = parts[parts.length - 2];
	if (dir) return `${repoId}/${dir}`;

	return `${repoId}#${path}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null;
}

async function listGithubSkillFiles(
	owner: string,
	repo: string,
	branch: string,
): Promise<readonly string[]> {
	const url = `https://api.github.com/repos/${owner}/${repo}/git/trees/${encodeURIComponent(branch)}?recursive=1`;

	const response = await fetch(url, {
		headers: GITHUB_API_HEADERS,
		signal: AbortSignal.timeout(30_000),
	});

	if (response.status === 404) return [];

	if (!response.ok) {
		throw new Error(
			`Failed to list repository tree for ${owner}/${repo}@${branch}: ${response.status} ${response.statusText}`,
		);
	}

	const data = (await response.json()) as unknown;
	if (!isRecord(data)) {
		throw new Error(`Unexpected GitHub API response for ${owner}/${repo}@${branch}`);
	}

	const tree = data.tree;
	if (!Array.isArray(tree)) {
		throw new Error(`Unexpected GitHub API response shape (missing tree) for ${owner}/${repo}@${branch}`);
	}

	const out: string[] = [];
	for (const item of tree) {
		if (!isRecord(item)) continue;
		const type = item.type;
		const path = item.path;
		if (type !== "blob") continue;
		if (typeof path !== "string") continue;
		const base = (path.split("/").pop() ?? path).toLowerCase();
		if (base === "skill.md" || base === "skills.md") out.push(path);
	}

	return [...new Set(out)].sort((a, b) => a.localeCompare(b));
}

async function scanSkillFromUrl(url: string, opts: ScanOptions): Promise<TrustReport> {
	const { content } = await fetchSkillContentFromUrl(url, opts);
	return scanSkill(content);
}

async function scanGithubRepo(
	source: string,
	owner: string,
	repo: string,
): Promise<{ readonly scanned: readonly CheckedTarget[]; readonly failures: readonly CheckFailure[] }> {
	const repoId = `${owner}/${repo}`;

	for (const branch of ["main", "master"] as const) {
		const url = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/SKILL.md`;
		try {
			const report = await scanSkillFromUrl(url, DEFAULT_CHECK_FETCH_OPTIONS);
			return {
				scanned: [{ source, target: repoId, report }],
				failures: [],
			};
		} catch (err) {
			if (isNotFoundError(err)) continue;
			throw err;
		}
	}

	let lastListError: unknown;
	for (const branch of ["main", "master"] as const) {
		let paths: readonly string[] = [];
		try {
			paths = await listGithubSkillFiles(owner, repo, branch);
		} catch (err) {
			lastListError = err;
			continue;
		}

		if (paths.length === 0) continue;

		const scanned: CheckedTarget[] = [];
		const failures: CheckFailure[] = [];

		for (const path of paths) {
			const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${encodeGithubPath(path)}`;
			const target = labelFromGithubPath(owner, repo, path);
			try {
				const report = await scanSkillFromUrl(rawUrl, DEFAULT_CHECK_FETCH_OPTIONS);
				scanned.push({ source, target, report });
			} catch (err) {
				const message = err instanceof Error ? err.message : String(err);
				failures.push({ source, target, error: message });
			}
		}

		if (scanned.length === 0 && failures.length > 0) {
			throw new Error(
				`Failed to fetch any SKILL.md files from ${repoId} (${failures.length} failures)`,
			);
		}

		return { scanned, failures };
	}

	if (lastListError) {
		const message = lastListError instanceof Error ? lastListError.message : String(lastListError);
		throw new Error(`Could not scan ${repoId}: ${message}`);
	}

	throw new Error(`Could not find SKILL.md in ${repoId} (tried main/master)`);
}

async function scanGithubRepoSkill(
	source: string,
	owner: string,
	repo: string,
	skill: string,
): Promise<{ readonly scanned: readonly CheckedTarget[]; readonly failures: readonly CheckFailure[] }> {
	const repoId = `${owner}/${repo}`;
	const target = `${repoId}/${skill}`;

	const candidates = [
		`https://raw.githubusercontent.com/${owner}/${repo}/main/skills/${skill}/SKILL.md`,
		`https://raw.githubusercontent.com/${owner}/${repo}/main/${skill}/SKILL.md`,
		`https://raw.githubusercontent.com/${owner}/${repo}/master/skills/${skill}/SKILL.md`,
		`https://raw.githubusercontent.com/${owner}/${repo}/master/${skill}/SKILL.md`,
	] as const;

	let lastError: unknown;

	for (const url of candidates) {
		try {
			const report = await scanSkillFromUrl(url, DEFAULT_CHECK_FETCH_OPTIONS);
			return {
				scanned: [{ source, target, report }],
				failures: [],
			};
		} catch (err) {
			lastError = err;
			if (isNotFoundError(err)) continue;
			break;
		}
	}

	const message = lastError instanceof Error ? lastError.message : String(lastError);
	throw new Error(`Could not find SKILL.md for ${target}: ${message}`);
}

async function scanCheckSource(
	source: string,
): Promise<{ readonly scanned: readonly CheckedTarget[]; readonly failures: readonly CheckFailure[] }> {
	const gh = parseGithubShorthand(source);
	if (gh) {
		if (gh.skill) return scanGithubRepoSkill(source, gh.owner, gh.repo, gh.skill);
		return scanGithubRepo(source, gh.owner, gh.repo);
	}

	if (source.startsWith("https://github.com")) {
		let parsed: URL;
		try {
			parsed = new URL(source);
		} catch {
			throw new Error(`Invalid URL: ${source}`);
		}

		const parts = parsed.pathname.split("/").filter(Boolean);
		const owner = parts[0];
		const repo = parts[1]?.replace(/\.git$/i, "");

		if (parts.length === 2 && owner && repo) {
			return scanGithubRepo(source, owner, repo);
		}

		const normalized = normalizeSkillUrl(source);
		const report = await scanSkillFromUrl(normalized, DEFAULT_CHECK_FETCH_OPTIONS);
		return { scanned: [{ source, target: source, report }], failures: [] };
	}

	if (source.startsWith("https://skills.sh")) {
		const rawUrl = await resolveSkillsShUrl(source, { timeout: 10_000 });
		const report = await scanSkillFromUrl(rawUrl, DEFAULT_CHECK_FETCH_OPTIONS);
		return { scanned: [{ source, target: source, report }], failures: [] };
	}

	if (looksLikeLocalPath(source)) {
		const content = await readFile(source, "utf-8");
		const report = await scanSkill(content);
		return { scanned: [{ source, target: source, report }], failures: [] };
	}

	if (isUrlLike(source)) {
		// Any other URL (raw GitHub, ClawHub page URL, etc.)
		const normalized = normalizeSkillUrl(source);
		const report = await scanSkillFromUrl(normalized, DEFAULT_CHECK_FETCH_OPTIONS);
		return { scanned: [{ source, target: source, report }], failures: [] };
	}

	// Default: treat as ClawHub slug (backward compatible)
	const downloadUrl = `https://auth.clawdhub.com/api/v1/download?slug=${encodeURIComponent(source)}`;
	const report = await scanSkillFromUrl(downloadUrl, CLAWHUB_CHECK_FETCH_OPTIONS);
	return { scanned: [{ source, target: source, report }], failures: [] };
}

type ReadlineInterface = ReturnType<typeof createInterface>;

async function promptYesNo(rl: ReadlineInterface, question: string): Promise<boolean> {
	const answer = (await rl.question(question)).trim().toLowerCase();
	return answer === "y" || answer === "yes";
}

async function runSkillsInstall(source: string): Promise<number> {
	const cmd = process.platform === "win32" ? "npx.cmd" : "npx";

	const child = spawn(cmd, ["skills", "add", source], {
		stdio: "inherit",
	});

	return await new Promise<number>((resolve) => {
		child.on("error", () => resolve(1));
		child.on("exit", (code) => resolve(code ?? 1));
	});
}

function clearProgressLine(): void {
	process.stdout.write(`\r${" ".repeat(120)}\r`);
}

export async function handleCheck(args: string[]): Promise<number> {
	const sources: string[] = [];
	let jsonFlag = false;
	let installFlag = false;
	let yesFlag = false;

	for (let i = 0; i < args.length; i += 1) {
		const arg = args[i];
		if (!arg) continue;

		if (arg === "--json") {
			jsonFlag = true;
			continue;
		}

		if (arg === "--install") {
			installFlag = true;
			continue;
		}

		if (arg === "--yes" || arg === "-y") {
			yesFlag = true;
			continue;
		}

		if (arg === "--help" || arg === "-h") {
			console.log(getCheckUsageText());
			return 0;
		}

		if (arg.startsWith("-")) {
			console.error(`Unknown option: ${arg}`);
			console.error(getCheckUsageText());
			return 1;
		}

		sources.push(arg);
	}

	if (sources.length === 0) {
		console.error(`${C.red}Error: No skill source provided${C.reset}`);
		console.error(getCheckUsageText());
		return 1;
	}

	if (jsonFlag && installFlag) {
		console.error(`${C.red}Error: --install cannot be used with --json${C.reset}`);
		return 1;
	}

	if (installFlag && !yesFlag && !process.stdin.isTTY) {
		console.error(
			`${C.red}Error: --install requires an interactive TTY. Use --yes for non-interactive mode.${C.reset}`,
		);
		return 1;
	}

	const scannedAll: CheckedTarget[] = [];
	const failuresAll: CheckFailure[] = [];
	let installFailures = 0;

	let rl: ReadlineInterface | null = null;
	if (installFlag && !yesFlag) {
		rl = createInterface({ input: process.stdin, output: process.stdout });
	}

	for (const source of sources) {
		if (!jsonFlag) process.stdout.write(`${C.gray}Checking ${source}...${C.reset}`);

		let scanned: readonly CheckedTarget[] = [];
		let failures: readonly CheckFailure[] = [];

		try {
			const res = await scanCheckSource(source);
			scanned = res.scanned;
			failures = res.failures;
		} catch (err) {
			const message = err instanceof Error ? err.message : String(err);
			failures = [{ source, target: source, error: message }];
		}

		scannedAll.push(...scanned);
		failuresAll.push(...failures);

		if (!jsonFlag) {
			clearProgressLine();

			for (const item of scanned) {
				printCheckReport(item.target, item.report);
			}

			for (const f of failures) {
				console.error(`${C.red}✖ Failed to check ${f.target}: ${f.error}${C.reset}\n`);
			}
		}

		if (installFlag) {
			const hasReports = scanned.length > 0;
			const pass = hasReports && failures.length === 0 && scanned.every((s) => isPassingBadge(s.report.badge));

			let confirmed = yesFlag;
			if (!confirmed) {
				const promptRl = rl;
				if (!promptRl) {
					console.error(
						`${C.red}Error: Cannot prompt for confirmation (non-interactive). Use --yes.${C.reset}`,
					);
					confirmed = false;
				} else if (pass) {
					confirmed = await promptYesNo(
						promptRl,
						`Install with \`npx skills add ${source}\`? [y/N] `,
					);
				} else {
					console.log(
						`${C.yellow}${C.bold}⚠ Security check did not pass (or was incomplete).${C.reset}`,
					);
					confirmed = await promptYesNo(
						promptRl,
						`Install anyway with \`npx skills add ${source}\`? [y/N] `,
					);
				}
			}

			if (confirmed) {
				const code = await runSkillsInstall(source);
				if (code !== 0) {
					installFailures += 1;
					console.error(`${C.red}✖ Install failed for ${source} (exit code ${code})${C.reset}`);
				}
			}
		}
	}

	if (rl) rl.close();

	if (jsonFlag) {
		const output =
			sources.length === 1 && scannedAll.length === 1 && failuresAll.length === 0
				? scannedAll[0]?.report
				: sources.length === 1 && scannedAll.length === 0 && failuresAll.length === 1
					? { error: failuresAll[0]?.error }
					: {
						results: scannedAll.map((r) => ({
							source: r.source,
							target: r.target,
							...r.report,
						})),
						failures: failuresAll,
					};

		console.log(JSON.stringify(output, null, 2));
	}

	if (installFailures > 0) return 2;
	if (failuresAll.length > 0) return 2;

	const anyBad = scannedAll.some((r) => r.report.badge === "rejected" || r.report.badge === "suspicious");
	return anyBad ? 1 : 0;
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
 * Handle `agentverus registry skillssh` command.
 * Fetches the skills.sh sitemap, resolves GitHub URLs, and batch scans.
 */
export async function handleSkillsShScan(args: string[]): Promise<number> {
	let outDir = "data/skillssh-results";
	let concurrency = 25;
	let limit: number | undefined;
	let timeout = 30_000;
	let resolveOnly = false;

	for (let i = 0; i < args.length; i++) {
		const arg = args[i] as string;
		const next = args[i + 1];
		if (arg === "--out" && next) { outDir = next; i++; continue; }
		if (arg === "--concurrency" && next) { concurrency = Number.parseInt(next, 10); i++; continue; }
		if (arg === "--limit" && next) { limit = Number.parseInt(next, 10); i++; continue; }
		if (arg === "--timeout" && next) { timeout = Number.parseInt(next, 10); i++; continue; }
		if (arg === "--resolve-only") { resolveOnly = true; continue; }
		if (arg.startsWith("-")) { console.error(`Unknown option: ${arg}`); return 1; }
	}

	console.log(`${C.bold}AgentVerus skills.sh Scanner${C.reset}`);
	console.log("─".repeat(60));

	// Step 1: Fetch sitemap
	console.log(`\n  ${C.cyan}Fetching skills.sh sitemap...${C.reset}`);
	const entries = await fetchSkillsShSitemap();
	console.log(`  Found ${entries.length} skills in ${new Set(entries.map(e => `${e.owner}/${e.repo}`)).size} repos`);

	// Step 2: Resolve GitHub raw URLs
	console.log(`\n  ${C.cyan}Resolving GitHub URLs (probing repos)...${C.reset}`);
	const startResolve = Date.now();
	const resolveResult = await resolveSkillsShUrls(entries, {
		timeout: 10_000,
		concurrency: 30,
		onProgress: (done, total, repo) => {
			const pct = ((done / total) * 100).toFixed(1);
			process.stdout.write(`\r  [${pct.padStart(5)}%] ${done}/${total} repos  ${repo.padEnd(50)}`);
		},
	});
	process.stdout.write(`\r${" ".repeat(100)}\r`);

	const resolveTime = Date.now() - startResolve;
	console.log(`  Resolved: ${resolveResult.resolved.length} skills in ${resolveResult.resolvedRepoCount}/${resolveResult.repoCount} repos (${(resolveTime / 1000).toFixed(1)}s)`);
	console.log(`  Unresolved: ${resolveResult.unresolved.length} skills`);

	// Write resolved URLs
	const { mkdir } = await import("node:fs/promises");
	await mkdir(outDir, { recursive: true });
	const urlFile = `${outDir}/resolved-urls.txt`;
	await writeResolvedUrls(resolveResult.resolved, urlFile);
	console.log(`  URL list: ${urlFile}`);

	if (resolveOnly) {
		console.log(`\n  ${C.green}✓ Resolve complete. Run 'agentverus registry scan --urls ${urlFile}' to scan.${C.reset}`);
		return 0;
	}

	// Step 3: Scan
	let skillsToScan = resolveResult.resolved;
	if (limit && limit > 0) {
		skillsToScan = skillsToScan.slice(0, limit);
	}

	console.log(`\n  ${C.cyan}Scanning ${skillsToScan.length} skills...${C.reset}`);
	const startScan = Date.now();

	const summary = await batchScanRegistry({
		urlFile,
		outDir,
		concurrency,
		timeout,
		retries: 1,
		retryDelayMs: 500,
		limit,
		onProgress: (done, total, slug, badge) => {
			const pct = ((done / total) * 100).toFixed(1);
			const elapsed = ((Date.now() - startScan) / 1000).toFixed(0);
			const rate = done > 0 ? (done / ((Date.now() - startScan) / 1000)).toFixed(1) : "0";

			const badgeStr = badge
				? `${badgeEmoji(badge)} ${badge.toUpperCase().padEnd(11)}`
				: `${C.red}✖ ERROR${C.reset}     `;

			process.stdout.write(`\r  [${pct.padStart(5)}%] ${done}/${total}  ${elapsed}s  ${rate}/s  ${badgeStr} ${slug.slice(0, 40)}`);
		},
	});

	process.stdout.write(`\r${" ".repeat(120)}\r`);

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

	return 0;
}

/**
 * Print registry-specific usage.
 */
export function printRegistryUsage(): void {
	console.log(`
${C.bold}AgentVerus Registry Commands${C.reset}

${C.bold}COMMANDS${C.reset}
  check <source...>     Universal pre-install gate (ClawHub, GitHub, skills.sh, URLs, local files)
  registry scan          Batch scan all skills from a URL list
  registry skillssh      Fetch, resolve, and scan all skills from skills.sh
  registry report        Generate markdown analysis report from scan results
  registry site          Generate static HTML dashboard from scan results

${C.bold}CHECK OPTIONS${C.reset}
  --json                 Output JSON instead of formatted report (cannot combine with --install)
  --install              Prompt to run: npx skills add <source>
  --yes                  Skip confirmation prompts (assume yes)

${C.bold}REGISTRY SCAN OPTIONS${C.reset}
  --urls <path>          Path to skill-urls.txt (default: data/skill-urls.txt)
  --out <dir>            Output directory (default: data/scan-results)
  --concurrency <n>      Max parallel downloads (default: 25)
  --limit <n>            Only scan first N skills (for testing)
  --timeout <ms>         Download timeout (default: 45000)

${C.bold}REGISTRY REPORT OPTIONS${C.reset}
  --data <dir>           Scan results directory (default: data/scan-results)
  --out <dir>            Report output directory (default: data/report)

${C.bold}REGISTRY SKILLSSH OPTIONS${C.reset}
  --out <dir>            Output directory (default: data/skillssh-results)
  --concurrency <n>      Max parallel scans (default: 25)
  --limit <n>            Only scan first N resolved skills
  --timeout <ms>         Fetch timeout (default: 30000)
  --resolve-only         Only resolve URLs, don't scan

${C.bold}REGISTRY SITE OPTIONS${C.reset}
  --data <dir>           Scan results directory (default: data/scan-results)
  --out <dir>            Site output directory (default: data/site)
  --title <text>         Custom site title

${C.bold}EXAMPLES${C.reset}
  agentverus check web-search
  agentverus check web-search --install
  agentverus check vercel-labs/agent-skills
  agentverus check vercel-labs/agent-skills/react-best-practices --install
  agentverus check https://skills.sh/vercel-labs/agent-skills/react-best-practices
  agentverus check ./SKILL.md
  agentverus registry scan --concurrency 50 --limit 100
  agentverus registry skillssh --concurrency 50
  agentverus registry skillssh --resolve-only
  agentverus registry report
  agentverus registry site --title "ClawHub Security Audit"
`);
}

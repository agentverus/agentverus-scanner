import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";

import { scanSkill } from "../src/scanner/index.ts";
import type { TrustReport } from "../src/scanner/types.ts";

const PUBLIC_CORPUS_PATH = join(process.cwd(), "benchmarks/public-skill-corpus.txt");
const CACHE_DIR = join(process.cwd(), ".cache/autoresearch/public-skill-corpus");
const PREFIX_CHARS = 4096;
const SAFE_FIXTURES = [
	"safe-basic.md",
	"safe-complex.md",
	"legit-security-skill.md",
	"legit-curl-install.md",
	"evasion-negation-safe.md",
	"evasion-context-safe.md",
] as const;

const MEDIUM_PLUS = new Set(["medium", "high", "critical"]);
const HIGH_PLUS = new Set(["high", "critical"]);

interface PublicSkillResult {
	readonly url: string;
	readonly label: string;
	readonly fullReport: TrustReport;
	readonly prefixReport: TrustReport;
	readonly mediumPlusFindings: number;
	readonly prefixMediumPlusFindings: number;
}

function slugFromUrl(url: string): string {
	const last = url.split("/").pop() ?? url;
	if (last.toLowerCase() !== "skill.md") {
		return last.replace(/\.md$/i, "");
	}

	const parts = url.split("/").filter(Boolean);
	return parts[parts.length - 2] ?? last;
}

function issueCount(report: TrustReport): number {
	return report.findings.filter((f) => MEDIUM_PLUS.has(f.severity)).length;
}

function highCount(report: TrustReport): number {
	return report.findings.filter((f) => HIGH_PLUS.has(f.severity)).length;
}

function issueTitles(report: TrustReport): string {
	const titles = report.findings
		.filter((f) => MEDIUM_PLUS.has(f.severity))
		.map((f) => `${f.severity}:${f.title}`)
		.slice(0, 4);
	return titles.join(" | ");
}

async function loadPublicCorpusUrls(): Promise<readonly string[]> {
	const content = await readFile(PUBLIC_CORPUS_PATH, "utf-8");
	return content
		.split("\n")
		.map((line) => line.trim())
		.filter((line) => line.length > 0 && !line.startsWith("#"));
}

async function fetchCachedSkill(url: string): Promise<string> {
	await mkdir(CACHE_DIR, { recursive: true });
	const key = createHash("sha1").update(url).digest("hex");
	const cachePath = join(CACHE_DIR, `${key}.md`);
	if (existsSync(cachePath)) {
		return readFile(cachePath, "utf-8");
	}

	const response = await fetch(url, {
		headers: { "User-Agent": "AgentVerusAutoresearch/2026-03-13" },
		signal: AbortSignal.timeout(20_000),
	});
	if (!response.ok) {
		throw new Error(`Failed to fetch ${url}: ${response.status} ${response.statusText}`);
	}

	const content = await response.text();
	await writeFile(cachePath, content, "utf-8");
	return content;
}

async function scanPublicSkill(url: string): Promise<PublicSkillResult> {
	const content = await fetchCachedSkill(url);
	const fullReport = await scanSkill(content);
	const prefixReport = await scanSkill(content.slice(0, PREFIX_CHARS));
	return {
		url,
		label: slugFromUrl(url),
		fullReport,
		prefixReport,
		mediumPlusFindings: issueCount(fullReport),
		prefixMediumPlusFindings: issueCount(prefixReport),
	};
}

async function scanSafeFixture(name: string): Promise<TrustReport> {
	const path = join(process.cwd(), "test/fixtures/skills", name);
	const content = await readFile(path, "utf-8");
	return scanSkill(content);
}

function printPublicSummary(results: readonly PublicSkillResult[]): void {
	for (const result of results) {
		console.log(
			[
				`PUBLIC ${result.label}`,
				`score=${result.fullReport.overall}`,
				`badge=${result.fullReport.badge}`,
				`issues=${result.mediumPlusFindings}`,
				`prefix_issues=${result.prefixMediumPlusFindings}`,
				issueTitles(result.fullReport),
			].join(" | "),
		);
	}
}

function printSafeSummary(reports: Readonly<Record<string, TrustReport>>): void {
	for (const [name, report] of Object.entries(reports)) {
		const mediumPlus = issueCount(report);
		const highPlus = highCount(report);
		console.log(
			`SAFE ${name} | score=${report.overall} | badge=${report.badge} | medium_plus=${mediumPlus} | high_plus=${highPlus}`,
		);
	}
}

async function main(): Promise<void> {
	const urls = await loadPublicCorpusUrls();
	const publicResults: PublicSkillResult[] = [];
	for (const url of urls) {
		publicResults.push(await scanPublicSkill(url));
	}

	const safeReportsEntries = await Promise.all(
		SAFE_FIXTURES.map(async (name) => [name, await scanSafeFixture(name)] as const),
	);
	const safeReports = Object.fromEntries(safeReportsEntries) as Record<string, TrustReport>;

	const publicIssueFindings = publicResults.reduce((sum, result) => sum + result.mediumPlusFindings, 0);
	const publicIssueSkills = publicResults.filter((result) => result.mediumPlusFindings > 0).length;
	const realtimePrefixSkills = publicResults.filter((result) => result.prefixMediumPlusFindings > 0).length;
	const publicHighFindings = publicResults.reduce((sum, result) => sum + highCount(result.fullReport), 0);
	const safeFixtureRegressions = Object.values(safeReports).filter((report) => highCount(report) > 0).length;
	const safeFixtureMediumPlus = Object.values(safeReports).reduce((sum, report) => sum + issueCount(report), 0);

	printPublicSummary(publicResults);
	printSafeSummary(safeReports);

	console.log(`METRIC public_issue_findings=${publicIssueFindings}`);
	console.log(`METRIC public_issue_skills=${publicIssueSkills}`);
	console.log(`METRIC public_high_findings=${publicHighFindings}`);
	console.log(`METRIC realtime_prefix_skills=${realtimePrefixSkills}`);
	console.log(`METRIC safe_fixture_regressions=${safeFixtureRegressions}`);
	console.log(`METRIC safe_fixture_medium_plus=${safeFixtureMediumPlus}`);
	console.log(`METRIC public_corpus_size=${publicResults.length}`);
}

await main();

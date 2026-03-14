import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { scanSkill } from "../src/scanner/index.ts";
import type { Finding, TrustReport } from "../src/scanner/types.ts";

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

function normalizeTitle(title: string): string {
	return title
		.replace(/\s*\(inside code block\)/gi, "")
		.replace(/\s*\(declared:[^)]+\)/gi, "")
		.replace(/\s*\(merged[^)]*\)/gi, "")
		.trim()
		.toLowerCase();
}

function duplicateStats(findings: readonly Finding[]): {
	readonly duplicateFindings: number;
	readonly duplicateGroups: number;
} {
	const counts = new Map<string, number>();
	for (const finding of findings) {
		if (!MEDIUM_PLUS.has(finding.severity)) continue;
		const key = `${finding.category}::${normalizeTitle(finding.title)}`;
		counts.set(key, (counts.get(key) ?? 0) + 1);
	}

	let duplicateFindings = 0;
	let duplicateGroups = 0;
	for (const count of counts.values()) {
		if (count <= 1) continue;
		duplicateFindings += count - 1;
		duplicateGroups += 1;
	}

	return { duplicateFindings, duplicateGroups };
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
	return {
		url,
		label: slugFromUrl(url),
		fullReport: await scanSkill(content),
		prefixReport: await scanSkill(content.slice(0, PREFIX_CHARS)),
	};
}

async function scanSafeFixture(name: string): Promise<TrustReport> {
	const path = join(process.cwd(), "test/fixtures/skills", name);
	const content = await readFile(path, "utf-8");
	return scanSkill(content);
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

	let renderedDuplicateFindings = 0;
	let renderedDuplicateGroups = 0;
	let prefixRenderedDuplicateFindings = 0;
	for (const result of publicResults) {
		const fullStats = duplicateStats(result.fullReport.findings);
		const prefixStats = duplicateStats(result.prefixReport.findings);
		renderedDuplicateFindings += fullStats.duplicateFindings;
		renderedDuplicateGroups += fullStats.duplicateGroups;
		prefixRenderedDuplicateFindings += prefixStats.duplicateFindings;

		console.log(
			[
				`PUBLIC ${result.label}`,
				`duplicate_findings=${fullStats.duplicateFindings}`,
				`duplicate_groups=${fullStats.duplicateGroups}`,
				`prefix_duplicate_findings=${prefixStats.duplicateFindings}`,
			].join(" | "),
		);
	}

	const publicIssueFindings = publicResults.reduce((sum, result) => sum + issueCount(result.fullReport), 0);
	const publicHighFindings = publicResults.reduce((sum, result) => sum + highCount(result.fullReport), 0);
	const realtimePrefixFindings = publicResults.reduce(
		(sum, result) => sum + issueCount(result.prefixReport),
		0,
	);
	const safeFixtureRegressions = Object.values(safeReports).filter((report) => highCount(report) > 0).length;
	const safeFixtureMediumPlus = Object.values(safeReports).reduce((sum, report) => sum + issueCount(report), 0);

	console.log(`METRIC rendered_duplicate_findings=${renderedDuplicateFindings}`);
	console.log(`METRIC rendered_duplicate_groups=${renderedDuplicateGroups}`);
	console.log(`METRIC prefix_rendered_duplicate_findings=${prefixRenderedDuplicateFindings}`);
	console.log(`METRIC public_issue_findings=${publicIssueFindings}`);
	console.log(`METRIC public_high_findings=${publicHighFindings}`);
	console.log(`METRIC realtime_prefix_findings=${realtimePrefixFindings}`);
	console.log(`METRIC safe_fixture_regressions=${safeFixtureRegressions}`);
	console.log(`METRIC safe_fixture_medium_plus=${safeFixtureMediumPlus}`);
}

await main();

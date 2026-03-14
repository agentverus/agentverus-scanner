import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { scanSkill } from "../src/scanner/index.ts";
import type { Finding, TrustReport } from "../src/scanner/types.ts";

const PUBLIC_CORPUS_PATH = join(process.cwd(), "benchmarks/public-skill-corpus.txt");
const CACHE_DIR = join(process.cwd(), ".cache/autoresearch/public-skill-corpus");
const PREFIX_CHARS = 4096;
const TARGET_LABELS = new Set([
	"browser-use",
	"agent-browser",
	"clawdirect",
	"clawdirect-dev",
	"baoyu-post-to-x",
] as const);
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
const AUTH_PROFILE_RELATED = /(auth|cookie|profile|session|token|vault|login)/i;

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

function isAuthProfileFinding(finding: Finding): boolean {
	if (!MEDIUM_PLUS.has(finding.severity)) return false;
	return AUTH_PROFILE_RELATED.test(`${finding.title}\n${finding.description}\n${finding.evidence}`);
}

function normalizeEvidence(evidence: string): string {
	return evidence
		.toLowerCase()
		.replace(/https?:\/\/[^\s)\]]+/g, (url) =>
			url.replace(/([?&][^=]+=)[^&#\s)\]]+/g, "$1<value>"),
		)
		.replace(/"[^"]+"|'[^']+'/g, '"<value>"')
		.replace(/\b\d+\b/g, "#")
		.replace(/<[^>]+>/g, "<value>")
		.replace(/\s+/g, " ")
		.trim();
}

function overlapCount(findings: readonly Finding[]): { readonly overlap: number; readonly groups: number } {
	const groups = new Map<string, number>();
	for (const finding of findings) {
		const key = normalizeEvidence(finding.evidence);
		groups.set(key, (groups.get(key) ?? 0) + 1);
	}

	let overlap = 0;
	let overlapGroups = 0;
	for (const count of groups.values()) {
		if (count <= 1) continue;
		overlap += count - 1;
		overlapGroups += 1;
	}

	return { overlap, groups: overlapGroups };
}

function mergeSuffixCount(findings: readonly Finding[]): number {
	let total = 0;
	for (const finding of findings) {
		total += (finding.title.match(/\(merged /g) ?? []).length;
	}
	return total;
}

function mergeDescriptionSectionCount(findings: readonly Finding[]): number {
	let total = 0;
	for (const finding of findings) {
		total += (finding.description.match(/(?:^|\n\n)Merged /g) ?? []).length;
	}
	return total;
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

	let authProfileOverlap = 0;
	let authProfileOverlapGroups = 0;
	let authProfileFindings = 0;
	let authProfileSkillsWithOverlap = 0;
	let prefixAuthProfileOverlap = 0;
	let authMergeSuffixes = 0;
	let authMergeDescriptionSections = 0;

	for (const result of publicResults) {
		if (!TARGET_LABELS.has(result.label)) continue;

		const fullRelevant = result.fullReport.findings.filter(isAuthProfileFinding);
		const prefixRelevant = result.prefixReport.findings.filter(isAuthProfileFinding);
		const fullOverlap = overlapCount(fullRelevant);
		const prefixOverlap = overlapCount(prefixRelevant);
		authProfileOverlap += fullOverlap.overlap;
		authProfileOverlapGroups += fullOverlap.groups;
		authProfileFindings += fullRelevant.length;
		authMergeSuffixes += mergeSuffixCount(fullRelevant);
		authMergeDescriptionSections += mergeDescriptionSectionCount(fullRelevant);
		prefixAuthProfileOverlap += prefixOverlap.overlap;
		if (fullOverlap.overlap > 0) authProfileSkillsWithOverlap += 1;

		console.log(
			[
				`TARGET ${result.label}`,
				`auth_findings=${fullRelevant.length}`,
				`auth_overlap=${fullOverlap.overlap}`,
				`overlap_groups=${fullOverlap.groups}`,
				`prefix_auth_overlap=${prefixOverlap.overlap}`,
			].join(" | "),
		);
	}

	const publicIssueFindings = publicResults.reduce((sum, result) => sum + issueCount(result.fullReport), 0);
	const realtimePrefixFindings = publicResults.reduce(
		(sum, result) => sum + issueCount(result.prefixReport),
		0,
	);
	const publicHighFindings = publicResults.reduce((sum, result) => sum + highCount(result.fullReport), 0);
	const safeFixtureRegressions = Object.values(safeReports).filter((report) => highCount(report) > 0).length;
	const safeFixtureMediumPlus = Object.values(safeReports).reduce((sum, report) => sum + issueCount(report), 0);

	console.log(`METRIC auth_profile_overlap=${authProfileOverlap}`);
	console.log(`METRIC auth_profile_overlap_groups=${authProfileOverlapGroups}`);
	console.log(`METRIC auth_profile_findings=${authProfileFindings}`);
	console.log(`METRIC auth_merge_suffixes=${authMergeSuffixes}`);
	console.log(`METRIC auth_merge_description_sections=${authMergeDescriptionSections}`);
	console.log(`METRIC auth_profile_skills_with_overlap=${authProfileSkillsWithOverlap}`);
	console.log(`METRIC prefix_auth_profile_overlap=${prefixAuthProfileOverlap}`);
	console.log(`METRIC public_issue_findings=${publicIssueFindings}`);
	console.log(`METRIC public_high_findings=${publicHighFindings}`);
	console.log(`METRIC realtime_prefix_findings=${realtimePrefixFindings}`);
	console.log(`METRIC safe_fixture_regressions=${safeFixtureRegressions}`);
	console.log(`METRIC safe_fixture_medium_plus=${safeFixtureMediumPlus}`);
}

await main();

/**
 * Registry-scale batch scanner.
 * Downloads and scans all skills from the registry with configurable concurrency.
 */

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { scanSkill } from "../scanner/index.js";
import { fetchSkillContentFromUrl } from "../scanner/source.js";
import type { TrustReport } from "../scanner/types.js";
import { SCANNER_VERSION } from "../scanner/types.js";
import type {
	RegistryFinding,
	RegistryScanError,
	RegistryScanResult,
	RegistryScanSummary,
} from "./types.js";

export interface BatchScanOptions {
	/** Path to skill-urls.txt */
	readonly urlFile: string;
	/** Output directory for results */
	readonly outDir: string;
	/** Max concurrent downloads */
	readonly concurrency: number;
	/** Timeout per download in ms */
	readonly timeout: number;
	/** Max retries per download */
	readonly retries: number;
	/** Base retry delay in ms */
	readonly retryDelayMs: number;
	/** If set, only scan first N skills (for testing) */
	readonly limit?: number;
	/** Progress callback */
	readonly onProgress?: (done: number, total: number, slug: string, badge: string | null) => void;
	/** Error callback */
	readonly onError?: (slug: string, error: string) => void;
}

const DEFAULT_OPTIONS: Omit<BatchScanOptions, "urlFile" | "outDir"> = {
	concurrency: 25,
	timeout: 45_000,
	retries: 2,
	retryDelayMs: 750,
};

interface ParsedUrl {
	slug: string;
	version: string;
	url: string;
}

function parseSkillUrls(content: string): ParsedUrl[] {
	const results: ParsedUrl[] = [];
	for (const line of content.split("\n")) {
		const trimmed = line.trim();
		if (!trimmed || trimmed.startsWith("#")) continue;

		try {
			const url = new URL(trimmed);

			// ClawHub format: ?slug=xxx&version=yyy
			const slug = url.searchParams.get("slug");
			if (slug) {
				const version = url.searchParams.get("version") ?? "";
				results.push({ slug, version, url: trimmed });
				continue;
			}

			// Raw GitHub URL: extract slug from path
			// e.g. raw.githubusercontent.com/owner/repo/branch/skills/my-skill/SKILL.md
			const pathParts = url.pathname.split("/").filter(Boolean);
			if (url.hostname === "raw.githubusercontent.com" && pathParts.length >= 3) {
				// Derive slug from the path: use the folder containing SKILL.md, or the repo name
				const skillMdIndex = pathParts.findIndex(
					(p) => p.toLowerCase() === "skill.md" || p.toLowerCase() === "skills.md",
				);
				const folder =
					skillMdIndex > 0 ? pathParts[skillMdIndex - 1] : pathParts[pathParts.length - 1];
				const derivedSlug = folder ?? pathParts.slice(0, 2).join("-");
				results.push({ slug: derivedSlug, version: "", url: trimmed });
				continue;
			}

			// Generic URL: derive slug from last path segment or hostname
			const lastSegment = pathParts[pathParts.length - 1]?.replace(/\.md$/i, "");
			results.push({ slug: lastSegment ?? url.hostname, version: "", url: trimmed });
		} catch {
			// Skip malformed lines
		}
	}
	return results;
}

function reportToResult(parsed: ParsedUrl, report: TrustReport): RegistryScanResult {
	const categories: RegistryScanResult["categories"] = {};
	for (const [name, cat] of Object.entries(report.categories)) {
		categories[name] = {
			score: cat.score,
			weight: cat.weight,
			findingCount: cat.findings.length,
		};
	}

	// Keep top 10 findings to keep dataset manageable
	const findings: RegistryFinding[] = report.findings.slice(0, 10).map((f) => ({
		id: f.id,
		severity: f.severity,
		title: f.title,
		category: f.category,
		owaspCategory: f.owaspCategory,
		evidence: f.evidence ? f.evidence.slice(0, 200) : undefined,
	}));

	return {
		slug: parsed.slug,
		version: parsed.version,
		url: parsed.url,
		score: report.overall,
		badge: report.badge,
		format: report.metadata.skillFormat,
		name: report.metadata.skillName,
		categories,
		findings,
		durationMs: report.metadata.durationMs,
		scannedAt: report.metadata.scannedAt.toISOString(),
	};
}

/**
 * Categorize findings that represent text-based threats VT would miss.
 * These are the "gap" findings that justify AgentVerus's existence.
 */
function isVtGapFinding(finding: RegistryFinding): boolean {
	const vtBlindCategories = [
		"ASST-01", // Instruction Injection
		"ASST-02", // Data Exfiltration (in markdown instructions)
		"ASST-05", // Credential Harvesting (in instructions)
		"ASST-06", // Prompt Injection Relay
		"ASST-07", // Deceptive Functionality
		"ASST-08", // Excessive Permissions
	];
	return vtBlindCategories.includes(finding.owaspCategory);
}

function computeSummary(
	total: number,
	results: RegistryScanResult[],
	errors: RegistryScanError[],
	durationMs: number,
	concurrency: number,
): RegistryScanSummary {
	const badges: Record<string, number> = {
		certified: 0,
		conditional: 0,
		suspicious: 0,
		rejected: 0,
	};
	const scoreDist: Record<string, number> = {
		"0-19": 0,
		"20-39": 0,
		"40-59": 0,
		"60-79": 0,
		"80-89": 0,
		"90-100": 0,
	};

	const scores: number[] = [];
	const findingCounts = new Map<string, { title: string; count: number }>();
	const vtGapSlugs: string[] = [];

	for (const r of results) {
		badges[r.badge] = (badges[r.badge] ?? 0) + 1;
		scores.push(r.score);

		if (r.score < 20) scoreDist["0-19"] = (scoreDist["0-19"] ?? 0) + 1;
		else if (r.score < 40) scoreDist["20-39"] = (scoreDist["20-39"] ?? 0) + 1;
		else if (r.score < 60) scoreDist["40-59"] = (scoreDist["40-59"] ?? 0) + 1;
		else if (r.score < 80) scoreDist["60-79"] = (scoreDist["60-79"] ?? 0) + 1;
		else if (r.score < 90) scoreDist["80-89"] = (scoreDist["80-89"] ?? 0) + 1;
		else scoreDist["90-100"] = (scoreDist["90-100"] ?? 0) + 1;

		let hasVtGap = false;
		for (const f of r.findings) {
			const existing = findingCounts.get(f.id);
			if (existing) {
				existing.count++;
			} else {
				findingCounts.set(f.id, { title: f.title, count: 1 });
			}
			if (isVtGapFinding(f) && (f.severity === "critical" || f.severity === "high")) {
				hasVtGap = true;
			}
		}
		if (hasVtGap) {
			vtGapSlugs.push(r.slug);
		}
	}

	scores.sort((a, b) => a - b);
	const avg = scores.length > 0 ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0;
	const median = scores.length > 0 ? (scores[Math.floor(scores.length / 2)] ?? 0) : 0;

	const topFindings = [...findingCounts.entries()]
		.map(([id, { title, count }]) => ({ id, title, count }))
		.sort((a, b) => b.count - a.count)
		.slice(0, 25);

	return {
		totalSkills: total,
		scanned: results.length,
		failed: errors.length,
		badges,
		averageScore: avg,
		medianScore: median,
		scoreDistribution: scoreDist,
		topFindings,
		vtGapSkills: vtGapSlugs,
		scannerVersion: SCANNER_VERSION,
		scannedAt: new Date().toISOString(),
		totalDurationMs: durationMs,
		concurrency,
	};
}

/**
 * Run a batch scan of all skills in the registry.
 */
export async function batchScanRegistry(
	opts: Partial<BatchScanOptions> & Pick<BatchScanOptions, "urlFile" | "outDir">,
): Promise<RegistryScanSummary> {
	const options = { ...DEFAULT_OPTIONS, ...opts };
	const startTime = Date.now();

	// Read URL list
	const urlContent = await readFile(options.urlFile, "utf-8");
	let parsed = parseSkillUrls(urlContent);
	if (options.limit && options.limit > 0) {
		parsed = parsed.slice(0, options.limit);
	}

	// Create output directory
	await mkdir(options.outDir, { recursive: true });

	const results: RegistryScanResult[] = [];
	const errors: RegistryScanError[] = [];
	let completed = 0;

	// Process with bounded concurrency
	const queue = [...parsed];
	const workers: Promise<void>[] = [];

	for (let i = 0; i < options.concurrency; i++) {
		workers.push(
			(async () => {
				while (true) {
					const item = queue.shift();
					if (!item) break;

					try {
						const { content } = await fetchSkillContentFromUrl(item.url, {
							timeout: options.timeout,
							retries: options.retries,
							retryDelayMs: options.retryDelayMs,
						});

						const report = await scanSkill(content);
						const result = reportToResult(item, report);
						results.push(result);

						completed++;
						options.onProgress?.(completed, parsed.length, item.slug, result.badge);
					} catch (err) {
						const message = err instanceof Error ? err.message : String(err);
						errors.push({ slug: item.slug, url: item.url, error: message });

						completed++;
						options.onError?.(item.slug, message);
						options.onProgress?.(completed, parsed.length, item.slug, null);
					}
				}
			})(),
		);
	}

	await Promise.all(workers);

	const durationMs = Date.now() - startTime;

	// Sort results by score ascending (worst first) for easy review
	results.sort((a, b) => a.score - b.score);

	// Compute summary
	const summary = computeSummary(parsed.length, results, errors, durationMs, options.concurrency);

	// Write output files
	await writeFile(
		`${options.outDir}/results.json`,
		JSON.stringify(results, null, 2),
		"utf-8",
	);
	await writeFile(
		`${options.outDir}/errors.json`,
		JSON.stringify(errors, null, 2),
		"utf-8",
	);
	await writeFile(
		`${options.outDir}/summary.json`,
		JSON.stringify(summary, null, 2),
		"utf-8",
	);

	// Write a compact CSV for quick analysis
	const csvHeader =
		"slug,version,score,badge,format,findings_count,permissions,injection,dependencies,behavioral,content,code_safety";
	const csvRows = results.map((r) => {
		const findingCount = r.findings.length;
		const p = r.categories["permissions"]?.score ?? 0;
		const i = r.categories["injection"]?.score ?? 0;
		const d = r.categories["dependencies"]?.score ?? 0;
		const b = r.categories["behavioral"]?.score ?? 0;
		const c = r.categories["content"]?.score ?? 0;
		const cs = r.categories["code-safety"]?.score ?? 0;
		return `${r.slug},${r.version},${r.score},${r.badge},${r.format},${findingCount},${p},${i},${d},${b},${c},${cs}`;
	});
	await writeFile(
		`${options.outDir}/results.csv`,
		[csvHeader, ...csvRows].join("\n"),
		"utf-8",
	);

	return summary;
}

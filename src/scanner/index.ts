import { analyzeBehavioral } from "./analyzers/behavioral.js";
import { analyzeContent } from "./analyzers/content.js";
import { analyzeDependencies } from "./analyzers/dependencies.js";
import { analyzeInjection } from "./analyzers/injection.js";
import { analyzePermissions } from "./analyzers/permissions.js";
import { parseSkill } from "./parser.js";
import { aggregateScores } from "./scoring.js";
import { fetchSkillContentFromUrl } from "./source.js";
import type { Category, CategoryScore, ScanMetadata, ScanOptions, TrustReport } from "./types.js";
import { SCANNER_VERSION } from "./types.js";

/**
 * Create a fallback CategoryScore when an analyzer fails
 */
function fallbackScore(category: Category, weight: number, error: unknown): CategoryScore {
	const message = error instanceof Error ? error.message : "Unknown error";
	return {
		score: 50,
		weight,
		findings: [
			{
				id: `ERR-${category.toUpperCase()}`,
				category,
				severity: "info",
				title: `Analyzer error: ${category}`,
				description: `The ${category} analyzer encountered an error: ${message}. A default score of 50 was assigned.`,
				evidence: message,
				deduction: 0,
				recommendation: "This may indicate an issue with the skill file format. Try re-scanning.",
				owaspCategory: "ASST-09",
			},
		],
		summary: `Analyzer error — default score assigned. Error: ${message}`,
	};
}

/**
 * Scan a skill from raw content string.
 * Parses the skill, runs all analyzers in parallel, and aggregates results.
 */
export async function scanSkill(content: string, _options?: ScanOptions): Promise<TrustReport> {
	const startTime = Date.now();
	const skill = parseSkill(content);

	// Run all analyzers in parallel with error handling
	const [permissions, injection, dependencies, behavioral, contentResult] = await Promise.all([
		analyzePermissions(skill).catch((e) => fallbackScore("permissions", 0.25, e)),
		analyzeInjection(skill).catch((e) => fallbackScore("injection", 0.3, e)),
		analyzeDependencies(skill).catch((e) => fallbackScore("dependencies", 0.2, e)),
		analyzeBehavioral(skill).catch((e) => fallbackScore("behavioral", 0.15, e)),
		analyzeContent(skill).catch((e) => fallbackScore("content", 0.1, e)),
	]);

	const durationMs = Date.now() - startTime;

	const metadata: ScanMetadata = {
		scannedAt: new Date(),
		scannerVersion: SCANNER_VERSION,
		durationMs,
		skillFormat: skill.format,
		skillName: skill.name || "Unknown Skill",
		skillDescription: skill.description || "",
	};

	const categories: Record<Category, CategoryScore> = {
		permissions,
		injection,
		dependencies,
		behavioral,
		content: contentResult,
	};

	return aggregateScores(categories, metadata);
}

/**
 * Scan a skill from a URL.
 * Fetches the content first, then runs the scanner.
 */
export async function scanSkillFromUrl(url: string, options?: ScanOptions): Promise<TrustReport> {
	const { content } = await fetchSkillContentFromUrl(url, options);
	return scanSkill(content, options);
}

export { parseSkill } from "./parser.js";
export { aggregateScores } from "./scoring.js";
export type {
	BadgeTier,
	Category,
	CategoryScore,
	Finding,
	ParsedSkill,
	ScanOptions,
	Severity,
	TrustReport,
} from "./types.js";

import { analyzeBehavioral } from "./analyzers/behavioral.js";
import { analyzeContent } from "./analyzers/content.js";
import { analyzeDependencies } from "./analyzers/dependencies.js";
import { analyzeInjection } from "./analyzers/injection.js";
import { analyzePermissions } from "./analyzers/permissions.js";
import { analyzeSemantic, isSemanticAvailable } from "./analyzers/semantic.js";
import { parseSkill } from "./parser.js";
import { aggregateScores } from "./scoring.js";
import { fetchSkillContentFromUrl } from "./source.js";
import type {
	Category,
	CategoryScore,
	ScanMetadata,
	ScanOptions,
	SemanticAnalyzerOptions,
	TrustReport,
} from "./types.js";
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
 * Resolve semantic analyzer options from ScanOptions.
 */
function resolveSemanticOptions(
	scanOptions?: ScanOptions,
): SemanticAnalyzerOptions | undefined {
	if (!scanOptions?.semantic) return undefined;
	if (scanOptions.semantic === true) return {};
	return scanOptions.semantic;
}

/**
 * Merge semantic findings into the injection category score.
 * Semantic findings are additive — they can lower the score but the weight stays the same.
 */
function mergeSemanticFindings(
	injection: CategoryScore,
	semantic: CategoryScore | null,
): CategoryScore {
	if (!semantic || semantic.findings.length === 0) return injection;

	const mergedFindings = [...injection.findings, ...semantic.findings];
	let mergedScore = injection.score;
	for (const f of semantic.findings) {
		mergedScore = Math.max(0, mergedScore - f.deduction);
	}

	return {
		score: mergedScore,
		weight: injection.weight,
		findings: mergedFindings,
		summary: `${injection.summary} ${semantic.summary}`,
	};
}

/**
 * Scan a skill from raw content string.
 * Parses the skill, runs all analyzers in parallel, and aggregates results.
 */
export async function scanSkill(content: string, options?: ScanOptions): Promise<TrustReport> {
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

	// Run semantic analyzer if configured (doesn't block the main pipeline)
	const semanticOpts = resolveSemanticOptions(options);
	let semanticResult: CategoryScore | null = null;
	if (semanticOpts || isSemanticAvailable()) {
		semanticResult = await analyzeSemantic(skill, semanticOpts).catch(() => null);
	}

	// Merge semantic findings into the injection category
	const mergedInjection = mergeSemanticFindings(injection, semanticResult);

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
		injection: mergedInjection,
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
export { analyzeSemantic, isSemanticAvailable } from "./analyzers/semantic.js";
export type {
	BadgeTier,
	Category,
	CategoryScore,
	Finding,
	ParsedSkill,
	ScanOptions,
	SemanticAnalyzerOptions,
	Severity,
	TrustReport,
} from "./types.js";

import { analyzeBehavioral } from "./analyzers/behavioral.js";
import { analyzeCodeSafety } from "./analyzers/code-safety.js";
import { analyzeContent } from "./analyzers/content.js";
import { analyzeDependencies, extractSelfBaseDomains } from "./analyzers/dependencies.js";
import { analyzeInjection } from "./analyzers/injection.js";
import { analyzePermissions } from "./analyzers/permissions.js";
import { analyzeDomainTrust, analyzeSemantic } from "./analyzers/semantic.js";
import { applyCompanionCodeFindingsInFiles } from "./companion-code.js";
import { parseSkill } from "./parser.js";
import { aggregateScores } from "./scoring.js";
import { fetchSkillContentFromUrl } from "./source.js";
import type {
	Category,
	CategoryScore,
	Finding,
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
				// Treat analyzer failures as high severity: the scan is incomplete and must not certify.
				severity: "high",
				title: `Analyzer error: ${category}`,
				description: `The ${category} analyzer encountered an error: ${message}. A default score of 50 was assigned.`,
				evidence: message,
				deduction: 0,
				recommendation:
					"Scan coverage is incomplete. Fix the underlying error (often malformed frontmatter/markdown) and re-scan. Do not treat this report as certification.",
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

function getHostnameFromUrlish(input: string): string | null {
	const cleaned = input.trim().replace(/[),.;\]]+$/, "");
	if (!cleaned) return null;
	try {
		return new URL(cleaned).hostname.toLowerCase().replace(/\.$/, "").replace(/^www\./, "");
	} catch {
		const match = cleaned.match(/^(?:https?:\/\/)?([^/:?#]+)(?:[:/]|$)/i);
		const host = match?.[1]?.toLowerCase().replace(/\.$/, "").replace(/^www\./, "");
		return host || null;
	}
}

function applyDomainTrustToDependencies(
	dependencies: CategoryScore,
	trustedBaseDomains: ReadonlyMap<string, { readonly confidence: number; readonly rationale: string }>,
): CategoryScore {
	if (trustedBaseDomains.size === 0) return dependencies;

	let verifiedCount = 0;
	const updatedFindings = dependencies.findings.map((finding): Finding => {
		// Only adjust URL classification findings.
		if (!finding.id.startsWith("DEP-URL-")) return finding;
		if (!finding.title.startsWith("Unknown external")) return finding;
		if (finding.deduction <= 0) return finding;
		if (!finding.evidence.startsWith("https://")) return finding;

		const hostname = getHostnameFromUrlish(finding.evidence);
		if (!hostname) return finding;

		for (const [baseDomain, meta] of trustedBaseDomains.entries()) {
			if (hostname === baseDomain || hostname.endsWith(`.${baseDomain}`)) {
				verifiedCount += 1;
				return {
					...finding,
					severity: "info",
					deduction: 0,
					title: `External reference (verified domain: ${baseDomain})`,
					description: `${finding.description}\n\nDomain reputation: trusted (confidence ${meta.confidence.toFixed(2)}). ${meta.rationale}`,
				};
			}
		}

		return finding;
	});

	if (verifiedCount === 0) return dependencies;

	// Recalculate category score from updated deductions.
	let score = 100;
	for (const f of updatedFindings) {
		score = Math.max(0, score - f.deduction);
	}

	return {
		score: Math.max(0, Math.min(100, score)),
		weight: dependencies.weight,
		findings: updatedFindings,
		summary: `${dependencies.summary} Domain reputation verified for ${verifiedCount} URL(s).`,
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
	const [permissions, injection, dependencies, behavioral, contentResult, codeSafety] = await Promise.all([
		analyzePermissions(skill).catch((e) => fallbackScore("permissions", 0.20, e)),
		analyzeInjection(skill).catch((e) => fallbackScore("injection", 0.25, e)),
		analyzeDependencies(skill).catch((e) => fallbackScore("dependencies", 0.15, e)),
		analyzeBehavioral(skill).catch((e) => fallbackScore("behavioral", 0.15, e)),
		analyzeContent(skill).catch((e) => fallbackScore("content", 0.10, e)),
		analyzeCodeSafety(skill).catch((e) => fallbackScore("code-safety", 0.15, e)),
	]);

	// Run semantic analyzer if configured (doesn't block the main pipeline)
	const semanticOpts = resolveSemanticOptions(options);
	let semanticResult: CategoryScore | null = null;
	// SECURITY: Never auto-run semantic analysis solely because an API key is present.
	// This avoids accidental data egress when scanning proprietary/internal skills.
	if (semanticOpts) {
		semanticResult = await analyzeSemantic(skill, semanticOpts).catch(() => null);
	}

	// Merge semantic findings into the injection category
	const mergedInjection = mergeSemanticFindings(injection, semanticResult);

	// Optional: LLM-assisted domain reputation check for "self" product domains.
	// This is best-effort and runs only when semantic analysis is explicitly enabled.
	let mergedDependencies = dependencies;
	if (semanticOpts) {
		const selfBaseDomains = [...extractSelfBaseDomains(skill)];
		const assessments = await analyzeDomainTrust(skill, selfBaseDomains, semanticOpts).catch(() => null);

		const trusted = new Map<string, { confidence: number; rationale: string }>();
		for (const a of assessments ?? []) {
			if (a.verdict !== "trusted") continue;
			if (a.confidence < 0.85) continue;
			trusted.set(a.domain, { confidence: a.confidence, rationale: a.rationale });
		}

		mergedDependencies = applyDomainTrustToDependencies(dependencies, trusted);
	}

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
		dependencies: mergedDependencies,
		behavioral,
		content: contentResult,
		"code-safety": codeSafety,
	};

	return aggregateScores(categories, metadata);
}

/**
 * Scan a skill from a URL.
 * Fetches the content first, then runs the scanner.
 */
export async function scanSkillFromUrl(url: string, options?: ScanOptions): Promise<TrustReport> {
	const { content, companionFiles } = await fetchSkillContentFromUrl(url, options);
	const report = await scanSkill(content, options);
	if (!companionFiles || companionFiles.length === 0) return report;
	const skill = parseSkill(content);
	return applyCompanionCodeFindingsInFiles(report, skill, "remote-bundle", companionFiles);
}

export { parseSkill } from "./parser.js";
export { aggregateScores } from "./scoring.js";
export { buildSbomDocument } from "./sbom.js";
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

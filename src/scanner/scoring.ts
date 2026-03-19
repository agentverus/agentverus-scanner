import type {
	BadgeTier,
	Category,
	CategoryScore,
	Finding,
	ScanMetadata,
	TrustReport,
} from "./types.js";
import { shapeReportFindings, sortFindingsBySeverity } from "./report-shaping.js";

/** Category weights for overall score calculation */
const CATEGORY_WEIGHTS: Record<Category, number> = {
	permissions: 0.20,
	injection: 0.25,
	dependencies: 0.15,
	behavioral: 0.15,
	content: 0.10,
	"code-safety": 0.15,
};

/** Config-tampering finding ID prefixes that trigger a badge cap */
const CONFIG_TAMPER_PREFIXES = ["BEH-CONFIG-TAMPER-", "CS-CONFIG-TAMPER-"];

function hasConfigTamperFindings(findings: readonly Finding[]): boolean {
	return findings.some((f) =>
		CONFIG_TAMPER_PREFIXES.some((prefix) => f.id.startsWith(prefix)),
	);
}

function determineBadge(score: number, findings: readonly Finding[]): BadgeTier {
	const hasCritical = findings.some((f) => f.severity === "critical");
	const highCount = findings.filter((f) => f.severity === "high").length;

	if (hasCritical) return "rejected";
	if (score < 50) return "rejected";
	if (score < 75) return "suspicious";
	if (hasConfigTamperFindings(findings)) return "suspicious";
	if (score < 90 && highCount <= 2) return "conditional";
	if (score >= 90 && highCount === 0) return "certified";
	if (highCount > 2) return "suspicious";
	if (highCount > 0) return "conditional";
	return "certified";
}

function calculateWeightedOverall(categories: Record<Category, CategoryScore>): number {
	const preScanFindings = Object.values(categories).flatMap((cat) => cat.findings);
	const hasCriticals = preScanFindings.some((f) => f.severity === "critical");

	let overall = 0;
	for (const [category, catScore] of Object.entries(categories)) {
		const weight = CATEGORY_WEIGHTS[category as Category] ?? 0;
		const catCriticals = catScore.findings.some((f) => f.severity === "critical");
		const effectiveScore = !hasCriticals && !catCriticals
			? Math.max(catScore.score, 30)
			: catScore.score;
		overall += effectiveScore * weight;
	}
	return overall;
}

function applySeverityPenalty(
	overall: number,
	categories: Record<Category, CategoryScore>,
): number {
	const allCategoryFindings = Object.values(categories).flatMap((cat) => cat.findings);
	const criticalCount = allCategoryFindings.filter((f) => f.severity === "critical").length;
	const highFindings = allCategoryFindings.filter((f) => f.severity === "high");
	const threatCategories = new Set(["injection"]);
	const threatHighCount = highFindings.filter(
		(f) => threatCategories.has(f.category) || f.title.includes("Concealment"),
	).length;
	const severityPenalty = Math.min(criticalCount * 8 + threatHighCount * 3, 50);

	const categoryScores = Object.values(categories).map((c) => c.score);
	const minCategoryScore = Math.min(...categoryScores);
	const dragThreshold = criticalCount > 0 ? 60 : 0;
	if (minCategoryScore < dragThreshold) {
		const worstCategoryDrag = Math.round((dragThreshold - minCategoryScore) / 2);
		overall -= worstCategoryDrag;
	}

	return overall - severityPenalty;
}

/**
 * Aggregate category scores into a complete TrustReport.
 * Overall score = weighted average of category scores plus calibrated penalties.
 */
export function aggregateScores(
	categories: Record<Category, CategoryScore>,
	metadata: ScanMetadata,
): TrustReport {
	let overall = calculateWeightedOverall(categories);
	overall = applySeverityPenalty(overall, categories);
	overall = Math.round(Math.max(0, Math.min(100, overall)));

	const allFindings: Finding[] = sortFindingsBySeverity(
		Object.values(categories).flatMap((cat) => [...cat.findings]),
	);
	const badge = determineBadge(overall, allFindings);
	const reportFindings = shapeReportFindings(allFindings);

	return {
		overall,
		badge,
		categories,
		findings: reportFindings,
		metadata,
	};
}

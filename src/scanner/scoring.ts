import type {
	BadgeTier,
	Category,
	CategoryScore,
	Finding,
	ScanMetadata,
	TrustReport,
} from "./types.js";

/** Severity ordering for sorting findings */
const SEVERITY_ORDER: Record<string, number> = {
	critical: 0,
	high: 1,
	medium: 2,
	low: 3,
	info: 4,
};

/** Category weights for overall score calculation */
const CATEGORY_WEIGHTS: Record<Category, number> = {
	permissions: 0.20,
	injection: 0.25,
	dependencies: 0.15,
	behavioral: 0.15,
	content: 0.10,
	"code-safety": 0.15,
};

/**
 * Determine badge tier based on score and findings.
 *
 * Rules:
 * - Any Critical finding → REJECTED (regardless of score)
 * - Score < 50 → REJECTED
 * - Score 50-74, zero Critical → SUSPICIOUS
 * - Score 75-89, zero Critical, ≤2 High → CONDITIONAL
 * - Score 90-100, zero Critical, zero High → CERTIFIED
 */
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

	// Any critical finding → automatic REJECTED
	if (hasCritical) return "rejected";

	// Score-based tiers
	if (score < 50) return "rejected";
	if (score < 75) return "suspicious";

	// Config-tampering cap: even high-scoring skills with config-tamper findings
	// cannot achieve better than "suspicious"
	if (hasConfigTamperFindings(findings)) return "suspicious";

	if (score < 90 && highCount <= 2) return "conditional";
	if (score >= 90 && highCount === 0) return "certified";

	// Edge cases: high score but too many high findings
	if (highCount > 2) return "suspicious";
	if (highCount > 0) return "conditional";

	return "certified";
}

/**
 * Aggregate category scores into a complete TrustReport.
 * Overall score = weighted average of category scores.
 */
export function aggregateScores(
	categories: Record<Category, CategoryScore>,
	metadata: ScanMetadata,
): TrustReport {
	// Calculate weighted overall score
	let overall = 0;
	for (const [category, score] of Object.entries(categories)) {
		const weight = CATEGORY_WEIGHTS[category as Category] ?? 0;
		overall += score.score * weight;
	}
	overall = Math.round(Math.max(0, Math.min(100, overall)));

	// Collect all findings and sort by severity
	const allFindings: Finding[] = Object.values(categories)
		.flatMap((cat) => [...cat.findings])
		.sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4));

	// Determine badge tier
	const badge = determineBadge(overall, allFindings);

	return {
		overall,
		badge,
		categories,
		findings: allFindings,
		metadata,
	};
}

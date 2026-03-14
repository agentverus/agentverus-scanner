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

const AUTH_PROFILE_RELATED = /(auth|cookie|profile|session|chrome|cdp|token|vault|login)/i;
const CATEGORY_PREFERENCE: Record<Category, number> = {
	behavioral: 0,
	injection: 1,
	dependencies: 2,
	permissions: 3,
	content: 4,
	"code-safety": 5,
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

function isBrowserAuthOverlapCandidate(finding: Finding): boolean {
	if (finding.severity !== "high" && finding.severity !== "medium") return false;
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

function overlapPriority(finding: Finding): number {
	let penalty = 0;
	if (finding.title.startsWith("Capability contract mismatch")) penalty += 20;
	if (finding.title.startsWith("Many external URLs")) penalty += 12;
	if (finding.title.startsWith("Unknown external reference")) penalty += 10;
	if (finding.title.startsWith("External reference")) penalty += 10;
	return (
		(SEVERITY_ORDER[finding.severity] ?? 4) * 100 +
		(CATEGORY_PREFERENCE[finding.category] ?? 5) * 10 +
		penalty -
		Math.min(finding.deduction, 9)
	);
}

function mergeFindingGroup(
	group: readonly Finding[],
	reason: "same local context" | "repeated finding family",
): Finding {
	const sortedGroup = [...group].sort((a, b) => overlapPriority(a) - overlapPriority(b));
	const primary = sortedGroup[0]!;
	const mergedSignals = [...new Set(sortedGroup.slice(1).map((f) => f.title))].slice(0, 6);
	return {
		...primary,
		title: `${primary.title} (merged overlapping auth/profile signals)`,
		description: `${primary.description}\n\nMerged overlapping signals from the ${reason}:${mergedSignals.length > 0 ? `\n- ${mergedSignals.join("\n- ")}` : ""}`,
	};
}

function normalizeAuthTitle(title: string): string {
	return title
		.toLowerCase()
		.replace(/\s*\(inside code block\)/g, "")
		.replace(/\s*\(merged overlapping auth\/profile signals\)/g, "")
		.trim();
}

function mergeOverlappingBrowserAuthFindings(findings: readonly Finding[]): Finding[] {
	const passthrough: Finding[] = [];
	const overlapGroups = new Map<string, Finding[]>();

	for (const finding of findings) {
		if (!isBrowserAuthOverlapCandidate(finding)) {
			passthrough.push(finding);
			continue;
		}

		const key = normalizeEvidence(finding.evidence);
		const group = overlapGroups.get(key);
		if (group) {
			group.push(finding);
		} else {
			overlapGroups.set(key, [finding]);
		}
	}

	const stageOne: Finding[] = [...passthrough];
	for (const group of overlapGroups.values()) {
		if (group.length === 1) {
			stageOne.push(group[0]!);
			continue;
		}

		stageOne.push(mergeFindingGroup(group, "same local context"));
	}

	const finalPassThrough: Finding[] = [];
	const familyGroups = new Map<string, Finding[]>();
	for (const finding of stageOne) {
		if (!isBrowserAuthOverlapCandidate(finding)) {
			finalPassThrough.push(finding);
			continue;
		}

		const familyKey = `${finding.category}::${normalizeAuthTitle(finding.title)}`;
		const group = familyGroups.get(familyKey);
		if (group) {
			group.push(finding);
		} else {
			familyGroups.set(familyKey, [finding]);
		}
	}

	const merged: Finding[] = [...finalPassThrough];
	for (const group of familyGroups.values()) {
		if (group.length === 1) {
			merged.push(group[0]!);
			continue;
		}

		merged.push(mergeFindingGroup(group, "repeated finding family"));
	}

	return merged.sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4));
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

	// Determine badge tier from raw findings so report dedup does not silently
	// relax certification outcomes.
	const badge = determineBadge(overall, allFindings);
	const reportFindings = mergeOverlappingBrowserAuthFindings(allFindings);

	return {
		overall,
		badge,
		categories,
		findings: reportFindings,
		metadata,
	};
}

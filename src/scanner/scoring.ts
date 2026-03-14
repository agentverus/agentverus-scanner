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

function normalizeAuthTitle(title: string): string {
	return title
		.toLowerCase()
		.replace(/\s*\(inside code block\)/g, "")
		.replace(/\s*\(merged overlapping auth\/profile signals\)/g, "")
		.trim();
}

function cleanMergedTitle(title: string): string {
	return title
		.replace(/\s*\(inside code block\)/gi, "")
		.replace(/\s*\(merged overlapping auth\/profile signals\)/gi, "")
		.trim();
}

function authFamilyKey(finding: Finding): string | null {
	const hay = `${finding.title}\n${finding.description}\n${finding.evidence}`.toLowerCase();

	if (finding.category === "permissions" && finding.title.startsWith("Capability contract mismatch")) {
		if (/(profile|chrome|cdp|browser session|browser profile|auth state)/i.test(hay)) {
			return "permissions::browser-profile-auth";
		}
		if (/(auth cookie|cookie url|query string|credential handoff)/i.test(hay)) {
			return "permissions::cookie-handoff";
		}
		if (/(credential storage|credential store|auth vault|auth_cookies)/i.test(hay)) {
			return "permissions::credential-store";
		}
		if (/(persistent session|session management|session saved|state save|state load|session-name|background daemon)/i.test(hay)) {
			return "permissions::session-state";
		}
	}

	if (finding.category === "behavioral") {
		if (/(mcp-issued browser auth cookie|credential in query string|cookie bootstrap redirect|cookie header replay)/i.test(hay)) {
			return "behavioral::cookie-handoff-flow";
		}
		if (/(browser profile copy|full browser profile sync|browser session attachment|profile-backed session persistence|auth import from user browser|browser auth state handling)/i.test(hay)) {
			return "behavioral::browser-profile-flow";
		}
		if (/(persistent session reuse|session inventory and reuse|state file replay)/i.test(hay)) {
			return "behavioral::session-reuse-flow";
		}
		if (/(credential vault enrollment|federated auth flow|environment secret piping)/i.test(hay)) {
			return "behavioral::credential-store-flow";
		}
	}

	if (finding.category === "dependencies") {
		if (/(credential-bearing url parameter|credential query-parameter transport)/i.test(hay)) {
			return "dependencies::query-auth-transport";
		}
		if (/(persistent credential-state store|reusable authenticated browser container)/i.test(hay)) {
			return "dependencies::session-store";
		}
	}

	return null;
}

function mergeFindingGroup(
	group: readonly Finding[],
	reason: "same local context" | "repeated finding family" | "same auth risk family",
): Finding {
	const sortedGroup = [...group].sort((a, b) => overlapPriority(a) - overlapPriority(b));
	const primary = sortedGroup[0]!;
	const mergedSignals = [...new Set(sortedGroup.slice(1).map((f) => cleanMergedTitle(f.title)))].slice(0, 6);
	return {
		...primary,
		title: `${cleanMergedTitle(primary.title)} (merged overlapping auth/profile signals)`,
		description: `${primary.description}\n\nMerged overlapping signals from the ${reason}:${mergedSignals.length > 0 ? `\n- ${mergedSignals.join("\n- ")}` : ""}`,
	};
}

function isAuthPermissionContractFinding(finding: Finding): boolean {
	return (
		finding.category === "permissions" &&
		finding.title.startsWith("Capability contract mismatch") &&
		isBrowserAuthOverlapCandidate(finding)
	);
}

function mergeAuthPermissionContractFindings(findings: readonly Finding[]): Finding[] {
	const contractFindings = findings.filter(isAuthPermissionContractFinding);
	if (contractFindings.length <= 1) return [...findings];

	const primary = [...contractFindings].sort((a, b) => overlapPriority(a) - overlapPriority(b))[0]!;
	const mergedTitles = [...new Set(contractFindings.filter((f) => f !== primary).map((f) => cleanMergedTitle(f.title)))];
	const mergedPrimary: Finding = {
		...primary,
		title: "Capability contract mismatch: inferred browser auth/session capabilities are not declared (merged auth/profile contract signals)",
		description: `${primary.description}\n\nMerged related auth/profile capability-contract signals:${mergedTitles.length > 0 ? `\n- ${mergedTitles.join("\n- ")}` : ""}`,
	};

	const output: Finding[] = [];
	let inserted = false;
	for (const finding of findings) {
		if (isAuthPermissionContractFinding(finding)) {
			if (!inserted && finding === primary) {
				output.push(mergedPrimary);
				inserted = true;
			}
			continue;
		}
		output.push(finding);
	}
	return output;
}

function isGenericAuthDependencyFinding(finding: Finding): boolean {
	if (finding.category !== "dependencies") return false;
	return (
		finding.title.startsWith("Many external URLs referenced") ||
		finding.title.startsWith("Unknown external reference") ||
		finding.title.startsWith("Local service URL reference")
	);
}

function isSpecificAuthDependencyFinding(finding: Finding): boolean {
	if (finding.category !== "dependencies") return false;
	return isBrowserAuthOverlapCandidate(finding) && !isGenericAuthDependencyFinding(finding);
}

function mergeGenericAuthDependencyFindings(findings: readonly Finding[]): Finding[] {
	const generic = findings.filter(isGenericAuthDependencyFinding);
	const specific = findings.filter(isSpecificAuthDependencyFinding);
	if (generic.length === 0 || specific.length === 0) return [...findings];

	const primary = [...specific].sort((a, b) => overlapPriority(a) - overlapPriority(b))[0]!;
	const mergedGenericTitles = [...new Set(generic.map((f) => cleanMergedTitle(f.title)))];
	const mergedDescription = `${primary.description}\n\nMerged related generic dependency context:\n- ${mergedGenericTitles.join("\n- ")}`;
	const mergedPrimary: Finding = {
		...primary,
		title: `${cleanMergedTitle(primary.title)} (merged auth-related dependency context)`,
		description: mergedDescription,
	};

	const output: Finding[] = [];
	let replaced = false;
	for (const finding of findings) {
		if (isGenericAuthDependencyFinding(finding)) continue;
		if (!replaced && finding === primary) {
			output.push(mergedPrimary);
			replaced = true;
			continue;
		}
		output.push(finding);
	}
	return output;
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

	const stageTwo: Finding[] = [...finalPassThrough];
	for (const group of familyGroups.values()) {
		if (group.length === 1) {
			stageTwo.push(group[0]!);
			continue;
		}

		stageTwo.push(mergeFindingGroup(group, "repeated finding family"));
	}

	const finalMerged: Finding[] = [];
	const familyPassThrough: Finding[] = [];
	const authFamilies = new Map<string, Finding[]>();
	for (const finding of stageTwo) {
		if (!isBrowserAuthOverlapCandidate(finding)) {
			familyPassThrough.push(finding);
			continue;
		}

		const familyKey = authFamilyKey(finding);
		if (!familyKey) {
			familyPassThrough.push(finding);
			continue;
		}

		const group = authFamilies.get(familyKey);
		if (group) {
			group.push(finding);
		} else {
			authFamilies.set(familyKey, [finding]);
		}
	}

	finalMerged.push(...familyPassThrough);
	for (const group of authFamilies.values()) {
		if (group.length === 1) {
			finalMerged.push(group[0]!);
			continue;
		}
		finalMerged.push(mergeFindingGroup(group, "same auth risk family"));
	}

	return finalMerged.sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4));
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
	const reportFindings = mergeGenericAuthDependencyFindings(
		mergeAuthPermissionContractFindings(mergeOverlappingBrowserAuthFindings(allFindings)),
	);

	return {
		overall,
		badge,
		categories,
		findings: reportFindings,
		metadata,
	};
}

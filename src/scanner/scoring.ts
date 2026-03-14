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

const AUTH_PROFILE_RELATED = /(auth|cookie|profile|session|token|vault|login)/i;
const CATEGORY_PREFERENCE: Record<Category, number> = {
	behavioral: 0,
	injection: 1,
	dependencies: 2,
	permissions: 3,
	content: 4,
	"code-safety": 5,
};
const MEDIUM_PLUS = new Set(["medium", "high", "critical"]);

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
		.replace(/\s*\(merged[^)]*\)/g, "")
		.trim();
}

function cleanMergedTitle(title: string): string {
	return title
		.replace(/\s*\(inside code block\)/gi, "")
		.replace(/\s*\(merged[^)]*\)/gi, "")
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
		title: cleanMergedTitle(primary.title),
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
		title: "Capability contract mismatch: inferred browser auth/session capabilities are not declared",
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
		title: cleanMergedTitle(primary.title),
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

function mergeAuthPermissionIntoBehavior(findings: readonly Finding[]): Finding[] {
	const permissionFindings = findings.filter(isAuthPermissionContractFinding);
	const behavioralFindings = findings.filter(
		(finding) => finding.category === "behavioral" && isBrowserAuthOverlapCandidate(finding),
	);
	if (permissionFindings.length === 0 || behavioralFindings.length === 0) return [...findings];

	const primary = [...behavioralFindings].sort((a, b) => overlapPriority(a) - overlapPriority(b))[0]!;
	const mergedPermissionTitles = [
		...new Set(permissionFindings.map((finding) => cleanMergedTitle(finding.title))),
	];
	const mergedPrimary: Finding = {
		...primary,
		title: cleanMergedTitle(primary.title),
		description: `${primary.description}\n\nMerged auth/session capability-contract context:\n- ${mergedPermissionTitles.join("\n- ")}`,
	};

	const output: Finding[] = [];
	let replaced = false;
	for (const finding of findings) {
		if (isAuthPermissionContractFinding(finding)) continue;
		if (!replaced && finding === primary) {
			output.push(mergedPrimary);
			replaced = true;
			continue;
		}
		output.push(finding);
	}
	return output;
}

function behavioralDependencyFamily(finding: Finding): string | null {
	const hay = `${cleanMergedTitle(finding.title)}\n${finding.description}\n${finding.evidence}`.toLowerCase();
	if (/(credential-bearing url parameter|credential query-parameter transport)/i.test(hay)) {
		return "cookie-handoff";
	}
	if (/reusable authenticated browser container/i.test(hay)) {
		return "browser-container";
	}
	if (/persistent credential-state store/i.test(hay)) {
		return "credential-store";
	}
	return null;
}

function behavioralAuthFamily(finding: Finding): string | null {
	if (finding.category !== "behavioral") return null;
	const hay = `${cleanMergedTitle(finding.title)}\n${finding.description}\n${finding.evidence}`.toLowerCase();
	if (/(mcp-issued browser auth cookie|credential in query string|cookie bootstrap redirect|cookie header replay|browser auth state handling)/i.test(hay)) {
		return "cookie-handoff";
	}
	if (/(browser profile copy|full browser profile sync|browser session attachment|profile-backed session persistence|auth import from user browser|persistent session reuse|state file replay)/i.test(hay)) {
		return "browser-container";
	}
	if (/(credential vault enrollment|credential store persistence|federated auth flow|environment secret piping|browser auth state handling)/i.test(hay)) {
		return "credential-store";
	}
	return null;
}

function mergeSpecificAuthDependenciesIntoBehavior(findings: readonly Finding[]): Finding[] {
	const behaviorals = findings.filter((finding) => behavioralAuthFamily(finding) !== null);
	const specificDependencies = findings.filter(
		(finding) => finding.category === "dependencies" && behavioralDependencyFamily(finding) !== null,
	);
	if (behaviorals.length === 0 || specificDependencies.length === 0) return [...findings];

	const consumed = new Set<Finding>();
	const replacements = new Map<Finding, Finding>();
	for (const dependency of specificDependencies) {
		const family = behavioralDependencyFamily(dependency);
		if (!family) continue;
		const target = [...behaviorals]
			.filter((finding) => behavioralAuthFamily(finding) === family)
			.sort((a, b) => overlapPriority(a) - overlapPriority(b))[0];
		if (!target) continue;

		consumed.add(dependency);
		const existing = replacements.get(target) ?? target;
		replacements.set(target, {
			...existing,
			title: cleanMergedTitle(existing.title),
			description: `${existing.description}\n\nMerged related dependency context:\n- ${cleanMergedTitle(dependency.title)}`,
		});
	}

	const output: Finding[] = [];
	for (const finding of findings) {
		if (consumed.has(finding)) continue;
		const replacement = replacements.get(finding);
		output.push(replacement ?? finding);
	}
	return output;
}

function broadBehavioralAuthFamily(finding: Finding): string | null {
	if (finding.category !== "behavioral") return null;
	const hay = `${cleanMergedTitle(finding.title)}\n${finding.description}\n${finding.evidence}`.toLowerCase();
	if (/(mcp-issued browser auth cookie|credential in query string|cookie bootstrap redirect|cookie header replay|browser auth state handling|authentication integration surface)/i.test(hay)) {
		return "behavioral::cookie-browser-auth";
	}
	if (/credential store persistence/i.test(hay) && /(auth_cookies|cookie)/i.test(hay)) {
		return "behavioral::cookie-browser-auth";
	}
	if (/(browser profile copy|browser session attachment|profile-backed session persistence|persistent session reuse|auth import from user browser|state file replay)/i.test(hay)) {
		return "behavioral::browser-container";
	}
	if (/(credential vault enrollment|credential store persistence|federated auth flow|environment secret piping)/i.test(hay)) {
		return "behavioral::credential-store";
	}
	return null;
}

function mergeBroadBehavioralAuthFamilies(findings: readonly Finding[]): Finding[] {
	const passThrough: Finding[] = [];
	const groups = new Map<string, Finding[]>();
	for (const finding of findings) {
		const family = broadBehavioralAuthFamily(finding);
		if (!family) {
			passThrough.push(finding);
			continue;
		}
		const group = groups.get(family);
		if (group) {
			group.push(finding);
		} else {
			groups.set(family, [finding]);
		}
	}

	const merged = [...passThrough];
	for (const group of groups.values()) {
		if (group.length === 1) {
			merged.push(group[0]!);
			continue;
		}
		merged.push(mergeFindingGroup(group, "same auth risk family"));
	}
	return merged;
}

function mergeHighBehavioralAuthSummary(findings: readonly Finding[]): Finding[] {
	const authBehaviorals = findings.filter(
		(finding) =>
			finding.category === "behavioral" && finding.severity === "high" && isBrowserAuthOverlapCandidate(finding),
	);
	if (authBehaviorals.length <= 1) return [...findings];

	const primary = [...authBehaviorals].sort((a, b) => overlapPriority(a) - overlapPriority(b))[0]!;
	const mergedTitles = [...new Set(authBehaviorals.filter((f) => f !== primary).map((f) => cleanMergedTitle(f.title)))];
	const mergedPrimary: Finding = {
		...primary,
		title: cleanMergedTitle(primary.title),
		description: `${primary.description}\n\nMerged additional behavioral auth/profile signals:\n- ${mergedTitles.join("\n- ")}`,
	};

	const output: Finding[] = [];
	let inserted = false;
	for (const finding of findings) {
		if (authBehaviorals.includes(finding)) {
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

function compactMergedDescription(description: string): string {
	const match = description.match(/^([\s\S]*?)(?:\n\nMerged [\s\S]*)?$/);
	const baseDescription = (match?.[1] ?? description).trimEnd();
	const sectionRegex = /\n\n(Merged [^:\n]+):\n((?:- .*\n?)*)/g;
	const mergedItems: string[] = [];
	let sectionMatch: RegExpExecArray | null;
	while ((sectionMatch = sectionRegex.exec(description)) !== null) {
		const heading = sectionMatch[1] ?? "Merged auth/profile context";
		const bullets = (sectionMatch[2] ?? "")
			.split("\n")
			.map((line) => line.trim())
			.filter((line) => line.startsWith("- "))
			.map((line) => line.slice(2).trim())
			.filter(Boolean);
		for (const bullet of bullets) {
			mergedItems.push(`${heading.replace(/^Merged\s+/i, "")} — ${bullet}`);
		}
	}

	const uniqueItems = [...new Set(mergedItems)];
	if (uniqueItems.length === 0) return description;
	return `${baseDescription}\n\nRelated auth/profile context:\n- ${uniqueItems.join("\n- ")}`;
}

function compactMergedDescriptions(findings: readonly Finding[]): Finding[] {
	return findings.map((finding) => {
		if (!finding.description.includes("\n\nMerged ")) return finding;
		return {
			...finding,
			description: compactMergedDescription(finding.description),
		};
	});
}

const TARGET_RENDERED_DUPLICATE_KEYS = new Set<string>([
	"behavioral::browser content extraction detected",
	"behavioral::ui state enumeration detected",
	"behavioral::skill path discovery detected",
	"behavioral::external instruction override file detected",
	"behavioral::server lifecycle orchestration detected",
	"behavioral::remote documentation ingestion detected",
	"behavioral::host environment reconnaissance detected",
	"behavioral::external tool bridge detected",
	"behavioral::remote transport exposure detected",
	"behavioral::unrestricted scope detected",
]);

function mergeSelectedRenderedDuplicates(findings: readonly Finding[]): Finding[] {
	const passThrough: Finding[] = [];
	const groups = new Map<string, Finding[]>();
	for (const finding of findings) {
		if (!MEDIUM_PLUS.has(finding.severity)) {
			passThrough.push(finding);
			continue;
		}
		const key = `${finding.category}::${normalizeAuthTitle(finding.title)}`;
		if (!TARGET_RENDERED_DUPLICATE_KEYS.has(key)) {
			passThrough.push(finding);
			continue;
		}
		const group = groups.get(key);
		if (group) {
			group.push(finding);
		} else {
			groups.set(key, [finding]);
		}
	}

	const merged = [...passThrough];
	for (const group of groups.values()) {
		if (group.length === 1) {
			merged.push(group[0]!);
			continue;
		}
		merged.push(mergeFindingGroup(group, "repeated finding family"));
	}
	return merged.sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4));
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
	const reportFindings = mergeSelectedRenderedDuplicates(
		compactMergedDescriptions(
			mergeHighBehavioralAuthSummary(
				mergeBroadBehavioralAuthFamilies(
					mergeAuthPermissionIntoBehavior(
						mergeSpecificAuthDependenciesIntoBehavior(
							mergeGenericAuthDependencyFindings(
								mergeAuthPermissionContractFindings(mergeOverlappingBrowserAuthFindings(allFindings)),
							),
						),
					),
				),
			),
		),
	);

	return {
		overall,
		badge,
		categories,
		findings: reportFindings,
		metadata,
	};
}

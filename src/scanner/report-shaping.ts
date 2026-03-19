import type { Finding } from "./types.js";
import {
	authFamilyKey,
	behavioralAuthFamily,
	behavioralDependencyFamily,
	broadBehavioralAuthFamily,
	cleanMergedTitle,
	isBrowserAuthOverlapCandidate,
	normalizeAuthTitle,
	normalizeEvidence,
	overlapPriority as computeOverlapPriority,
	TARGET_RENDERED_DUPLICATE_KEYS,
} from "./report-shaping-keys.js";

const SEVERITY_ORDER: Record<string, number> = {
	critical: 0,
	high: 1,
	medium: 2,
	low: 3,
	info: 4,
};

const MEDIUM_PLUS = new Set(["medium", "high", "critical"]);

function overlapPriority(finding: Finding): number {
	return computeOverlapPriority(finding, SEVERITY_ORDER);
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
	return sortFindingsBySeverity(merged);
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

	return sortFindingsBySeverity(finalMerged);
}

export function sortFindingsBySeverity(findings: readonly Finding[]): Finding[] {
	return [...findings].sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4));
}

export function shapeReportFindings(findings: readonly Finding[]): Finding[] {
	return mergeSelectedRenderedDuplicates(
		compactMergedDescriptions(
			mergeHighBehavioralAuthSummary(
				mergeBroadBehavioralAuthFamilies(
					mergeAuthPermissionIntoBehavior(
						mergeSpecificAuthDependenciesIntoBehavior(
							mergeGenericAuthDependencyFindings(
								mergeAuthPermissionContractFindings(mergeOverlappingBrowserAuthFindings(findings)),
							),
						),
					),
				),
			),
		),
	);
}

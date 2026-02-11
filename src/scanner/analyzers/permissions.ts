import type { CategoryScore, Finding, ParsedSkill } from "../types.js";
import { applyDeclaredPermissions } from "./declared-match.js";

/** Permission risk tiers */
const CRITICAL_PERMISSIONS = ["exec", "shell", "sudo", "admin"] as const;

/** Deduction amounts per tier */
const DEDUCTIONS = {
	critical: 30,
	high: 15,
	medium: 8,
	low: 2,
} as const;

/** Keywords suggesting limited-scope skills */
const LIMITED_SCOPE_KEYWORDS = [
	"calculator",
	"spell",
	"check",
	"format",
	"lint",
	"simple",
	"basic",
	"math",
	"text",
	"convert",
	"translate",
	"weather",
	"time",
	"date",
	"clock",
	"counter",
	"hello",
	"greeting",
] as const;

/** Permissions that suggest purpose mismatch for limited-scope skills */
const SUSPICIOUS_FOR_LIMITED = [
	"exec",
	"shell",
	"sudo",
	"admin",
	"network_unrestricted",
	"env_access",
	"delete",
	"file_write",
] as const;

function tokenizePermission(input: string): string[] {
	return input
		.toLowerCase()
		.split(/[^a-z0-9]+/g)
		.map((t) => t.trim())
		.filter(Boolean);
}

function getPermissionTier(perm: string): "critical" | "high" | "medium" | "low" | null {
	const tokens = tokenizePermission(perm);
	if (tokens.length === 0) return null;

	// Critical: direct system execution / administrative control.
	if (tokens.some((t) => (CRITICAL_PERMISSIONS as readonly string[]).includes(t))) return "critical";

	// High: unrestricted network or broad write/delete/secrets access.
	if (tokens.includes("network") && tokens.includes("unrestricted")) return "high";
	if (tokens.includes("env") && tokens.includes("access")) return "high";
	if (tokens.includes("delete")) return "high";
	// Generic "write" (not explicitly file-scoped) is treated as high.
	if (tokens.includes("write") && !tokens.includes("file")) return "high";

	// Medium: scoped network + file-scoped writes + API access.
	if (tokens.includes("network") && tokens.includes("restricted")) return "medium";
	if (tokens.includes("file") && tokens.includes("write")) return "medium";
	if (tokens.includes("api") && tokens.includes("access")) return "medium";

	// Low: read-only/search.
	if (tokens.includes("search")) return "low";
	if (tokens.includes("read")) return "low";
	if (tokens.includes("file") && tokens.includes("read")) return "low";

	return null;
}

function isLimitedScopeSkill(skill: ParsedSkill): boolean {
	const combined = `${skill.name} ${skill.description}`.toLowerCase();
	return LIMITED_SCOPE_KEYWORDS.some((kw) => combined.includes(kw));
}

/** Analyze permissions requested by a skill */
export async function analyzePermissions(skill: ParsedSkill): Promise<CategoryScore> {
	const findings: Finding[] = [];
	let score = 100;

	const allPermissions = [
		...skill.permissions,
		// Tools often imply capabilities/privilege; include them so unknown tool names
		// are at least visible to reviewers.
		...skill.tools,
	];
	const uniquePerms = [...new Set(allPermissions.map((p) => p.toLowerCase()))];

	// Score each permission
	for (const perm of uniquePerms) {
		const tier = getPermissionTier(perm);
		if (!tier) {
			findings.push({
				id: `PERM-UNKNOWN-${findings.length + 1}`,
				category: "permissions",
				severity: "info",
				title: `Unrecognized permission/tool: ${perm}`,
				description:
					"The skill references a permission/tool string that AgentVerus does not recognize. This may be harmless, but it reduces the scanner's ability to reason about actual privilege.",
				evidence: `Permission/tool: ${perm}`,
				deduction: 0,
				recommendation:
					"Use canonical permission names for your framework/runtime, or document what this permission/tool does and why it is needed.",
				owaspCategory: "ASST-08",
			});
			continue;
		}

		const deduction = DEDUCTIONS[tier];
		score = Math.max(0, score - deduction);

		const severity =
			tier === "critical"
				? "critical"
				: tier === "high"
					? "high"
					: tier === "medium"
						? "medium"
						: "low";

		findings.push({
			id: `PERM-${findings.length + 1}`.padStart(8, "0").slice(-8),
			category: "permissions",
			severity,
			title: `${tier.charAt(0).toUpperCase() + tier.slice(1)}-risk permission: ${perm}`,
			description: `The skill requests the "${perm}" permission which is classified as ${tier} risk.`,
			evidence: `Permission: ${perm}`,
			deduction,
			recommendation:
				tier === "critical"
					? `Remove the "${perm}" permission unless absolutely required. Critical permissions grant extensive system access.`
					: `Consider whether "${perm}" is necessary for the skill's stated functionality.`,
			owaspCategory: tier === "critical" || tier === "high" ? "ASST-03" : "ASST-08",
		});
	}

	// Check for permission-purpose mismatch
	if (isLimitedScopeSkill(skill)) {
		for (const perm of uniquePerms) {
			const lower = perm.toLowerCase();
			if (SUSPICIOUS_FOR_LIMITED.some((s) => lower.includes(s))) {
				const deduction = 15;
				score = Math.max(0, score - deduction);

				findings.push({
					id: `PERM-MISMATCH-${findings.length + 1}`,
					category: "permissions",
					severity: "high",
					title: `Permission-purpose mismatch: "${perm}" on limited-scope skill`,
					description: `The skill "${skill.name}" appears to be limited in scope but requests "${perm}" which is unusual for its stated purpose.`,
					evidence: `Skill: "${skill.name}" (${skill.description?.slice(0, 80)}...) requests "${perm}"`,
					deduction,
					recommendation: `Review whether "${perm}" is truly needed for a ${skill.name.toLowerCase()}.`,
					owaspCategory: "ASST-03",
				});
			}
		}
	}

	// Check for excessive total permissions
	if (uniquePerms.length > 5) {
		findings.push({
			id: "PERM-EXCESSIVE",
			category: "permissions",
			severity: "info",
			title: `Excessive number of permissions (${uniquePerms.length})`,
			description: `The skill requests ${uniquePerms.length} distinct permissions. Consider whether all are necessary.`,
			evidence: `Permissions: ${uniquePerms.join(", ")}`,
			deduction: 0,
			recommendation:
				"Apply the principle of least privilege — only request permissions the skill actually needs.",
			owaspCategory: "ASST-08",
		});
	}

	// Apply declared permissions — downgrade matching findings
	const adjustedFindings = applyDeclaredPermissions(findings, skill.declaredPermissions);

	// Recalculate score based on adjusted deductions
	let adjustedScore = 100;
	for (const f of adjustedFindings) {
		adjustedScore = Math.max(0, adjustedScore - f.deduction);
	}

	const summary =
		adjustedFindings.length === 0
			? "No permission concerns detected."
			: `Found ${adjustedFindings.length} permission-related findings. ${
					adjustedFindings.some((f) => f.severity === "critical")
						? "CRITICAL: Dangerous permissions detected."
						: adjustedFindings.some((f) => f.severity === "high")
							? "High-risk permissions detected that may not match the skill's purpose."
							: "Minor permission concerns."
				}`;

	return {
		score: Math.max(0, Math.min(100, adjustedScore)),
		weight: 0.20,
		findings: adjustedFindings,
		summary,
	};
}

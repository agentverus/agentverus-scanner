import type { CategoryScore, Finding, ParsedSkill } from "../types.js";
import { applyDeclaredPermissions } from "./declared-match.js";

/** Behavioral risk patterns */
interface BehavioralPattern {
	readonly name: string;
	readonly patterns: readonly RegExp[];
	readonly severity: "high" | "medium" | "low";
	readonly deduction: number;
	readonly owaspCategory: string;
	readonly recommendation: string;
}

const BEHAVIORAL_PATTERNS: readonly BehavioralPattern[] = [
	{
		name: "Unrestricted scope",
		patterns: [
			/do\s+anything/i,
			/no\s+limitations/i,
			/complete\s+autonomy/i,
			/without\s+(?:any\s+)?restrictions/i,
			/unrestricted\s+(?:access|mode|operation)/i,
			/full\s+(?:system\s+)?access/i,
		],
		severity: "high",
		deduction: 20,
		owaspCategory: "ASST-09",
		recommendation:
			"Define clear boundaries for what the skill can and cannot do. Unrestricted scope is a security risk.",
	},
	{
		name: "System modification",
		patterns: [
			/install\s+(?:packages?\s+)?globally/i,
			/(?:npm|pip|apt|brew)\s+install\s+(?:-g|--global)\b/i,
			/(?:sudo\s+)?(?:apt|yum|dnf|pacman)\s+install/i,
			/modify\s+(?:system|config(?:uration)?)\s+files?/i,
			/(?:write|edit|modify)\s+(?:\/etc|\/usr|\/sys|\/proc)/i,
			/chown\s+/i,
			/modify\s+(?:system\s+)?configuration/i,
		],
		severity: "high",
		deduction: 20,
		owaspCategory: "ASST-03",
		recommendation:
			"Skills should not modify system configuration or install packages globally. Bundle required dependencies.",
	},
	{
		name: "Autonomous action without confirmation",
		patterns: [
			/without\s+(?:user\s+)?(?:confirmation|approval|consent|asking)/i,
			/automatically\s+(?:execute|run|perform|delete|modify)/i,
			/(?:silently|quietly)\s+(?:execute|run|perform)/i,
			/no\s+(?:user\s+)?(?:confirmation|approval)\s+(?:needed|required)/i,
		],
		severity: "medium",
		deduction: 10,
		owaspCategory: "ASST-09",
		recommendation:
			"Require user confirmation before performing destructive or irreversible actions.",
	},
	{
		name: "Sub-agent spawning",
		patterns: [
			/spawn\s+(?:a\s+)?(?:sub-?agent|child\s+agent|new\s+agent)/i,
			/delegat(?:e|ing)\s+(?:to|tasks?\s+to)\s+(?:another|other)\s+agent/i,
			/(?:create|start|launch)\s+(?:a\s+)?(?:new\s+)?(?:sub-?)?process/i,
			/sub-?process(?:es)?\s+for\s+(?:parallel|concurrent)/i,
		],
		severity: "medium",
		deduction: 10,
		owaspCategory: "ASST-03",
		recommendation:
			"Be explicit about sub-agent spawning and ensure delegated tasks are appropriately scoped.",
	},
	{
		name: "State persistence",
		patterns: [
			/(?:write|save|store)\s+(?:to\s+)?(?:file|disk|database|storage)/i,
			/persist(?:ent)?\s+(?:state|data|storage)/i,
			/(?:create|maintain)\s+(?:a\s+)?(?:log|cache|database)/i,
		],
		severity: "low",
		deduction: 5,
		owaspCategory: "ASST-09",
		recommendation:
			"If state persistence is needed, document what data is stored and where. Allow users to review stored data.",
	},
	{
		name: "Unbounded loops or retries",
		patterns: [
			/(?:retry|loop|repeat)\s+(?:indefinitely|forever|until\s+success)/i,
			/(?:infinite|unbounded)\s+(?:loop|retry|recursion)/i,
			/while\s*\(\s*true\s*\)/i,
			/no\s+(?:maximum|max|limit)\s+(?:on\s+)?(?:retries|attempts|iterations)/i,
		],
		severity: "medium",
		deduction: 10,
		owaspCategory: "ASST-09",
		recommendation: "Set maximum retry counts and loop bounds to prevent resource exhaustion.",
	},
	{
		name: "Financial/payment actions",
		patterns: [
			/(?:process|make|initiate)\s+(?:a\s+)?payment/i,
			/(?:transfer|send)\s+(?:money|funds|crypto)/i,
			/(?:purchase|buy|order)\s+(?:on\s+behalf|for\s+the\s+user)/i,
			/(?:credit\s+card|bank\s+account|wallet)/i,
		],
		severity: "medium",
		deduction: 10,
		owaspCategory: "ASST-09",
		recommendation:
			"Financial actions should always require explicit user confirmation and should be clearly documented.",
	},
] as const;

/** Analyze behavioral risk profile */
export async function analyzeBehavioral(skill: ParsedSkill): Promise<CategoryScore> {
	const findings: Finding[] = [];
	let score = 100;
	const content = skill.rawContent;
	const lines = content.split("\n");

	for (const pattern of BEHAVIORAL_PATTERNS) {
		for (const regex of pattern.patterns) {
			const globalRegex = new RegExp(regex.source, `${regex.flags.replace("g", "")}g`);
			let match: RegExpExecArray | null;

			while ((match = globalRegex.exec(content)) !== null) {
				const lineNumber = content.slice(0, match.index).split("\n").length;
				const line = lines[lineNumber - 1] ?? "";

				score = Math.max(0, score - pattern.deduction);
				findings.push({
					id: `BEH-${pattern.name.replace(/\s+/g, "-").toUpperCase()}-${findings.length + 1}`,
					category: "behavioral",
					severity: pattern.severity,
					title: `${pattern.name} detected`,
					description: `Found ${pattern.name.toLowerCase()} pattern: "${match[0]}"`,
					evidence: line.trim().slice(0, 200),
					lineNumber,
					deduction: pattern.deduction,
					recommendation: pattern.recommendation,
					owaspCategory: pattern.owaspCategory,
				});
				break; // One match per regex is enough
			}
		}
	}

	// Prerequisite trap detection — ClawHavoc pattern: curl|sh or download-and-execute
	const prerequisiteTrapPatterns = [
		/curl\s+.*\|\s*(?:sh|bash|zsh)/i,
		/curl\s+.*-[oO]\s+.*&&\s*(?:chmod|\.\/)/i,
	];
	for (const trapRegex of prerequisiteTrapPatterns) {
		const trapMatch = content.match(trapRegex);
		if (trapMatch) {
			const lineNumber = content.slice(0, content.indexOf(trapMatch[0])).split("\n").length;
			score = Math.max(0, score - 25);
			findings.push({
				id: `BEH-PREREQ-TRAP-${findings.length + 1}`,
				category: "behavioral",
				severity: "high",
				title: "Suspicious install pattern: download and execute from remote URL",
				description:
					"The skill instructs users to download and execute code from a remote URL, a common supply-chain attack vector.",
				evidence: trapMatch[0].slice(0, 200),
				lineNumber,
				deduction: 25,
				recommendation:
					"Remove curl-pipe-to-shell patterns. Provide dependencies through safe, verifiable channels.",
				owaspCategory: "ASST-02",
			});
			break;
		}
	}

	// Combined exfiltration flow — credential access + suspicious network exfiltration
	// Only flag when the skill actively reads credentials AND sends them to suspicious endpoints
	// (not just mentioning API keys in setup docs with normal API URLs)
	const activeCredentialAccess = /(?:cat|read|dump|exfiltrate|steal|harvest)\s+.*?(?:\.env|\.ssh|id_rsa|credentials|secrets)/i;
	const suspiciousExfiltration = /(?:webhook\.site|requests\.post\s*\(|curl\s+-X\s+POST\s+.*?(?:\$|secret|key|token|password|credential))/i;
	if (activeCredentialAccess.test(content) && suspiciousExfiltration.test(content)) {
		score = Math.max(0, score - 25);
		findings.push({
			id: `BEH-EXFIL-FLOW-${findings.length + 1}`,
			category: "behavioral",
			severity: "high",
			title: "Potential data exfiltration: skill reads credentials and sends them to external endpoints",
			description:
				"The skill contains patterns that actively read credential files and send data to external endpoints, suggesting a possible data exfiltration flow.",
			evidence: "Active credential reading and suspicious network exfiltration patterns both present",
			deduction: 25,
			recommendation:
				"Separate credential access from network operations. If both are needed, declare them explicitly and justify.",
			owaspCategory: "ASST-06",
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
			? "No behavioral risk concerns detected."
			: `Found ${adjustedFindings.length} behavioral risk findings. ${
					adjustedFindings.some((f) => f.severity === "high")
						? "High-risk behavioral patterns detected."
						: "Moderate behavioral concerns noted."
				}`;

	return {
		score: Math.max(0, Math.min(100, adjustedScore)),
		weight: 0.15,
		findings: adjustedFindings,
		summary,
	};
}

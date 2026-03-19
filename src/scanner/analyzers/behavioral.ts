import type { CategoryScore, Finding, ParsedSkill, Severity } from "../types.js";
import { hasHighAbuseTldInText, isKnownInstallerTarget } from "../url-risk.js";
import { adjustForContext, buildContentContext, isInThreatListingContext, isSecurityDefenseSkill } from "./context.js";
import { applyDeclaredPermissions } from "./declared-match.js";
import { BEHAVIORAL_PATTERNS, PREREQUISITE_TRAP_PATTERNS } from "./behavioral-config.js";

/** Downgrade a severity level by one tier */
function downgradeSeverity(severity: "high" | "medium" | "low"): Severity {
	if (severity === "high") return "medium";
	if (severity === "medium") return "low";
	return "info";
}

/** Analyze behavioral risk profile */
export async function analyzeBehavioral(skill: ParsedSkill): Promise<CategoryScore> {
	const findings: Finding[] = [];
	let score = 100;
	const content = skill.rawContent;
	const lines = content.split("\n");
	const ctx = buildContentContext(content);

	// Detect if this is a security/defense skill listing threat patterns educationally
	const isDefenseSkill = isSecurityDefenseSkill(skill);

	for (const pattern of BEHAVIORAL_PATTERNS) {
		for (const regex of pattern.patterns) {
			const globalRegex = new RegExp(regex.source, `${regex.flags.replace("g", "")}g`);
			let match: RegExpExecArray | null;

			while ((match = globalRegex.exec(content)) !== null) {
				const lineNumber = content.slice(0, match.index).split("\n").length;
				const line = lines[lineNumber - 1] ?? "";

				// Context-aware adjustment
				const { severityMultiplier, reason } = adjustForContext(
					match.index,
					content,
					ctx,
				);

				// Do not break: an earlier negated mention must not prevent later real matches.
				if (severityMultiplier === 0) continue;

				const effectiveDeduction = Math.round(pattern.deduction * severityMultiplier);
				const effectiveSeverity =
					severityMultiplier < 1.0
						? downgradeSeverity(pattern.severity)
						: pattern.severity;

				score = Math.max(0, score - effectiveDeduction);
				findings.push({
					id: `BEH-${pattern.name.replace(/\s+/g, "-").toUpperCase()}-${findings.length + 1}`,
					category: "behavioral",
					severity: effectiveSeverity,
					title: `${pattern.name} detected${reason ? ` (${reason})` : ""}`,
					description: `Found ${pattern.name.toLowerCase()} pattern: "${match[0]}"`,
					evidence: line.trim().slice(0, 200),
					lineNumber,
					deduction: effectiveDeduction,
					recommendation: pattern.recommendation,
					owaspCategory: pattern.owaspCategory,
				});
				break; // One match per regex is enough
			}
		}
	}

	// Prerequisite trap detection — ClawHavoc pattern: curl|sh or download-and-execute
	// Context-aware: skip matches inside code blocks or safety sections, and
	// reduce severity for well-known installer domains in setup sections
	for (const trapRegex of PREREQUISITE_TRAP_PATTERNS) {
		const globalTrap = new RegExp(trapRegex.source, `${trapRegex.flags.replace("g", "")}g`);
		let trapMatch: RegExpExecArray | null;
		while ((trapMatch = globalTrap.exec(content)) !== null) {
			const { severityMultiplier } = adjustForContext(trapMatch.index, content, ctx);
			// Do not break: a negated mention must not prevent later real matches.
			if (severityMultiplier === 0) continue;

			// Security/defense skills listing threat patterns: downgrade to informational
			if (isDefenseSkill && isInThreatListingContext(content, trapMatch.index)) {
				findings.push({
					id: `BEH-PREREQ-TRAP-${findings.length + 1}`,
					category: "behavioral",
					severity: "low",
					title: "Install pattern: download and execute from remote URL (in threat documentation)",
					description: "The skill describes a download-and-execute pattern as part of security threat documentation.",
					evidence: trapMatch[0].slice(0, 200),
					lineNumber: content.slice(0, trapMatch.index).split("\n").length,
					deduction: 0,
					recommendation:
						"Consider pinning the installer to a specific version or hash for supply chain verification.",
					owaspCategory: "ASST-02",
				});
				break;
			}

			// Check if this is a well-known installer or in a prerequisites section
			const isKnownInstaller = isKnownInstallerTarget(trapMatch[0]);
			const hasRawIp = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(trapMatch[0]);
			const usesHttps = /https:\/\//.test(trapMatch[0]);
			const hasKnownTld = /\.(com|org|io|dev|sh|rs|land|cloud|app|ai|so|net|co)\//.test(trapMatch[0]);
			const preceding = content.slice(Math.max(0, trapMatch.index - 1000), trapMatch.index);
			const headings = preceding.match(/^#{1,4}\s+.+$/gm);
			const lastHeading = headings?.[headings.length - 1]?.toLowerCase() ?? "";
			const isInSetupHeading = /\b(?:prerequisit|install|setup|getting\s+started|requirements?|dependencies)\b/.test(lastHeading);
			const nearbyLines = preceding.split("\n").slice(-10).join("\n").toLowerCase();
			const isInYamlInstall = /\b(?:install|command|compatibility|setup)\s*:/i.test(nearbyLines);
			// Only downgrade for setup sections if URL looks legitimate (HTTPS + known TLD, no raw IP)
			const isInSetupSection = !hasRawIp && usesHttps && hasKnownTld && (isInSetupHeading || isInYamlInstall);

			if (isKnownInstaller || isInSetupSection) {
				// Downgrade to informational — legitimate setup instruction
				findings.push({
					id: `BEH-PREREQ-TRAP-${findings.length + 1}`,
					category: "behavioral",
					severity: "low",
					title: "Install pattern: download and execute from remote URL (in setup section)",
					description: isKnownInstaller
						? "The skill references a well-known installer script."
						: "The skill contains a curl-pipe-to-shell pattern in its setup/prerequisites section.",
					evidence: trapMatch[0].slice(0, 200),
					lineNumber: content.slice(0, trapMatch.index).split("\n").length,
					deduction: 0,
					recommendation:
						"Consider pinning the installer to a specific version or hash for supply chain verification.",
					owaspCategory: "ASST-02",
				});
			} else {
				const lineNumber = content.slice(0, trapMatch.index).split("\n").length;
				// For suspicious URLs (raw IP, HTTP-only, unknown TLD), don't reduce
				// severity just because they're in a code block — that's the evasion.
				const isSuspiciousUrl = hasRawIp || !usesHttps || !hasKnownTld || hasHighAbuseTldInText(trapMatch[0]);
				const effectiveMultiplier = isSuspiciousUrl ? Math.max(severityMultiplier, 1.0) : severityMultiplier;
				const effectiveDeduction = Math.round(25 * effectiveMultiplier);
				score = Math.max(0, score - effectiveDeduction);
				findings.push({
					id: `BEH-PREREQ-TRAP-${findings.length + 1}`,
					category: "behavioral",
					severity: effectiveMultiplier < 1.0 ? "medium" : "high",
					title: "Suspicious install pattern: download and execute from remote URL",
					description:
						"The skill instructs users to download and execute code from a remote URL, a common supply-chain attack vector.",
					evidence: trapMatch[0].slice(0, 200),
					lineNumber,
					deduction: effectiveDeduction,
					recommendation:
						"Remove curl-pipe-to-shell patterns. Provide dependencies through safe, verifiable channels.",
					owaspCategory: "ASST-02",
				});
			}
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

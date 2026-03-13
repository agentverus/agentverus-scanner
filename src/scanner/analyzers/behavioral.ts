import type { CategoryScore, Finding, ParsedSkill, Severity } from "../types.js";
import { adjustForContext, buildContentContext, isInThreatListingContext, isSecurityDefenseSkill } from "./context.js";
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
			/no\s+restrictions?\s+on\s+(?:navigation|actions|output)/i,
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

			// Persistence & system manipulation (common malware tactics)
			/\bcrontab\s+(?:-e|-l|--edit|--list)\b/i,
			/\bsystemctl\s+(?:enable|disable|start|stop|restart|daemon-reload|edit)\b/i,
			/(?:\/etc\/systemd\/system|systemd\s+unit|\.service\b)/i,
			/\/etc\/hosts\b/i,
			/\b(?:iptables|ufw)\b/i,
			/\b(?:modprobe|insmod|rmmod)\b/i,
			/~\/\.(?:bashrc|zshrc|profile)\b/i,
			/(?:write|append|modify)\s+.*\.(?:bashrc|zshrc|profile)\b/i,
		],
		severity: "high",
		deduction: 20,
		owaspCategory: "ASST-03",
		recommendation:
			"Skills should not modify system configuration or install packages globally. Bundle required dependencies.",
	},
	{
		name: "Config tamper core",
		patterns: [
			/\b(?:write|edit|modify|append|overwrite|replace|patch|update|change|add\s+to)\b[^\n]*(?:AGENTS\.md|TOOLS\.md|CLAUDE\.md)\b/i,
		],
		severity: "high",
		deduction: 25,
		owaspCategory: "ASST-03",
		recommendation:
			"Do not instruct users to write, edit, or otherwise modify trust-boundary workspace files like AGENTS.md, TOOLS.md, or CLAUDE.md. Treat them as user-owned policy/configuration and keep the skill self-contained.",
	},
	{
		name: "Config tamper workspace",
		patterns: [
			/\b(?:write|edit|modify|append|overwrite|replace|patch|update|change|add\s+to)\b[^\n]*\.claude\//i,
		],
		severity: "high",
		deduction: 20,
		owaspCategory: "ASST-03",
		recommendation:
			"Do not instruct users to modify files under .claude/. This directory is part of the workspace trust boundary and should not be altered by untrusted instructions.",
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
		name: "External instruction override file",
		patterns: [
			/\bEXTEND\.md\b/i,
			/(?:load|read|parse|apply)\s+(?:preferences|settings)\b/i,
			/\.baoyu-skills\//i,
		],
		severity: "medium",
		deduction: 10,
		owaspCategory: "ASST-11",
		recommendation:
			"Be explicit when external project/home files can override skill behavior. Treat sidecar config or instruction files as untrusted input and constrain what they are allowed to change.",
	},
	{
		name: "Persistent session reuse",
		patterns: [
			/maintains?\s+browser\s+sessions?\s+across\s+commands/i,
			/browser\s+stays\s+open\s+between\s+commands/i,
			/state\s+auto-(?:saved|restored)/i,
			/all\s+future\s+runs:\s+already\s+authenticated/i,
		],
		severity: "medium",
		deduction: 10,
		owaspCategory: "ASST-05",
		recommendation:
			"Call out when browser or auth state persists across commands. Reused authenticated sessions should require explicit user consent and clear cleanup guidance.",
	},
	{
		name: "Browser session attachment",
		patterns: [
			/(?:--auto-connect\b|--cdp\b|get\s+cdp-url|remote-debugging-port|Chrome\s+DevTools|connect\s+to\s+the\s+user'?s\s+running\s+Chrome)/i,
			/(?:copy(?:ing)?\s+your\s+actual\s+Chrome\s+profile|real\s+Chrome\s+with\s+your\s+login\s+sessions|profile\s+sync\b|local\s+Chrome\s+profile|cloud\s+profile|Chrome\s+with\s+CDP)/i,
		],
		severity: "high",
		deduction: 15,
		owaspCategory: "ASST-05",
		recommendation:
			"Treat browser profile reuse, remote-debugging attachment, and live-session access as sensitive credential access. Require explicit user consent, minimize scope, and clean up persisted state.",
	},
	{
		name: "Browser profile copy",
		patterns: [
			/actual\s+Chrome\s+profile/i,
			/login\s+sessions/i,
			/persistent\s+but\s+empty\s+CLI\s+profile/i,
		],
		severity: "high",
		deduction: 15,
		owaspCategory: "ASST-05",
		recommendation:
			"Treat copying or reusing a local browser profile as sensitive credential access. Prefer isolated ephemeral profiles unless the user explicitly approves session reuse.",
	},
	{
		name: "Full browser profile sync",
		patterns: [
			/full\s+profile\s+sync/i,
			/sync\s+ALL\s+cookies/i,
			/entire\s+browser\s+state/i,
		],
		severity: "high",
		deduction: 15,
		owaspCategory: "ASST-05",
		recommendation:
			"Avoid syncing an entire browser profile or all cookies into agent-controlled workflows. Prefer the smallest domain-scoped auth state possible and require explicit user consent.",
	},
	{
		name: "Browser JavaScript evaluation",
		patterns: [
			/\bbrowser-use\s+eval\b/i,
			/\bagent-browser\s+eval\b/i,
		],
		severity: "medium",
		deduction: 10,
		owaspCategory: "ASST-03",
		recommendation:
			"Treat browser-side JavaScript evaluation as privileged execution. Constrain the origin, review the expression, and avoid combining it with authenticated sessions unless necessary.",
	},
	{
		name: "Browser auth state handling",
		patterns: [
			/(?:state\s+(?:save|load)\s+\S*auth\.json|state\s+files?\s+contain\s+session\s+tokens?\s+in\s+plaintext|auth(?:entication)?\s+cookie|http-?only\s+cookie|cookies?\s+(?:export|import|get|set|clear)\b|cookies?\s+and\s+localStorage)/i,
			/(?:session\s+tokens?\s+in\s+plaintext|browser\s+session\s+is\s+authenticated|auto-saved\s+to\s+~\/\.agent-browser\/sessions|session\s+saved|already\s+authenticated|default\s+Chrome\s+profile)/i,
		],
		severity: "high",
		deduction: 15,
		owaspCategory: "ASST-05",
		recommendation:
			"Avoid storing, exporting, or passing browser auth state unless the workflow clearly requires it. Prefer encrypted storage, short-lived state, and explicit user confirmation before reusing credentials.",
	},
	{
		name: "Secret parameter handling",
		patterns: [
			/--secret\s+[^\s=]+=[^\s]+/i,
			/secret\s+metadata/i,
		],
		severity: "high",
		deduction: 15,
		owaspCategory: "ASST-05",
		recommendation:
			"Treat secret-bearing CLI parameters as credential handling. Avoid exposing secrets in command lines, logs, or reusable skill snippets; prefer secure secret stores or interactive injection.",
	},
	{
		name: "Credential in query string",
		patterns: [
			/(?:\b(?:cookie|token)\b.{0,120}\bquery\s+string\b|\bquery\s+string\b.{0,120}\b(?:cookie|token)\b)/i,
			/\?[A-Za-z0-9_-]*(?:cookie|token)=<[^>\s]+>/i,
		],
		severity: "high",
		deduction: 15,
		owaspCategory: "ASST-05",
		recommendation:
			"Do not pass auth cookies or tokens in URLs. Query strings leak into browser history, logs, analytics, and referrers. Use secure headers or an explicit browser cookie API instead.",
	},
	{
		name: "Local service exposure",
		patterns: [
			/(?:browser-use\s+)?tunnel\s+\d+\b/i,
			/trycloudflare\.com/i,
			/session\s+share\b/i,
			/public\s+share\s+url/i,
		],
		severity: "medium",
		deduction: 10,
		owaspCategory: "ASST-02",
		recommendation:
			"Do not expose local services, browser sessions, or internal tools publicly by default. Require explicit approval, constrain the shared surface, and shut down tunnels after use.",
	},
	{
		name: "Local service access",
		patterns: [
			/https?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d+)?/i,
		],
		severity: "high",
		deduction: 15,
		owaspCategory: "ASST-03",
		recommendation:
			"Treat localhost and loopback services as privileged local attack surfaces. Require explicit approval, constrain reachable ports, and avoid combining local access with session reuse or tunneling.",
	},
	{
		name: "Container runtime control",
		patterns: [
			/\bdocker\s+(?:info|context|ps|images|build(?:x)?|run|exec|stop|compose)\b/i,
			/\bdocker-compose\s+config\b/i,
		],
		severity: "high",
		deduction: 15,
		owaspCategory: "ASST-03",
		recommendation:
			"Treat Docker or container-runtime control as privileged host access. Scope container operations tightly, avoid arbitrary daemon access, and require explicit approval before mutating local workloads.",
	},
	{
		name: "Local file access",
		patterns: [
			/--allow-file-access\b/i,
			/\bfile:\/\//i,
		],
		severity: "medium",
		deduction: 10,
		owaspCategory: "ASST-03",
		recommendation:
			"Treat local file browsing as privileged access. Restrict it to explicit user-approved paths and avoid combining it with unrestricted browser/session reuse.",
	},
	{
		name: "Automation evasion",
		patterns: [
			/(?:bypass(?:es|ing)?|avoid(?:s|ing)?)\s+(?:anti-?bot|anti-automation|automation\s+detection|bot\s+detection)/i,
		],
		severity: "medium",
		deduction: 10,
		owaspCategory: "ASST-07",
		recommendation:
			"Avoid instructions whose value proposition is evading platform defenses or automation detection. Document legitimate automation constraints instead.",
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
			/(?:cost|price)\s*:\s*\$\d/i,
			/charge\s+for\s+(?:premium|paid)\s+actions?/i,
		],
		severity: "medium",
		deduction: 10,
		owaspCategory: "ASST-09",
		recommendation:
			"Financial actions should always require explicit user confirmation and should be clearly documented.",
	},
] as const;

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
	const KNOWN_INSTALLERS = /(?:deno\.land|bun\.sh|rustup\.rs|get\.docker\.com|install\.python-poetry\.org|nvm-sh|golangci|foundry\.paradigm\.xyz|tailscale\.com|opencode\.ai|sh\.rustup\.rs|get\.pnpm\.io|volta\.sh)/i;

	const prerequisiteTrapPatterns = [
		/curl\s+.*\|\s*(?:sh|bash|zsh)/i,
		/curl\s+.*-[oO]\s+.*&&\s*(?:chmod|\.\/)/i,
	];
	for (const trapRegex of prerequisiteTrapPatterns) {
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
			const isKnownInstaller = KNOWN_INSTALLERS.test(trapMatch[0]);
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
				const effectiveDeduction = Math.round(25 * severityMultiplier);
				score = Math.max(0, score - effectiveDeduction);
				findings.push({
					id: `BEH-PREREQ-TRAP-${findings.length + 1}`,
					category: "behavioral",
					severity: severityMultiplier < 1.0 ? "medium" : "high",
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

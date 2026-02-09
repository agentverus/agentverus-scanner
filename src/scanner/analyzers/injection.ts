import type { CategoryScore, Finding, ParsedSkill, Severity } from "../types.js";
import { adjustForContext, buildContentContext, isInThreatListingContext, isSecurityDefenseSkill } from "./context.js";
import { applyDeclaredPermissions } from "./declared-match.js";

/** Pattern definitions for injection detection */
interface InjectionPattern {
	readonly name: string;
	readonly patterns: readonly RegExp[];
	readonly severity: "critical" | "high" | "medium";
	readonly deduction: number;
	readonly owaspCategory: string;
	readonly recommendation: string;
}

const INJECTION_PATTERNS: readonly InjectionPattern[] = [
	{
		name: "Direct instruction override",
		patterns: [
			/ignore\s+(all\s+)?previous\s+instructions/i,
			/disregard\s+(all\s+)?(above|previous|prior)/i,
			/new\s+system\s+prompt/i,
			/you\s+are\s+now\s+(?:an?\s+|in\s+)?(?:unrestricted|unfiltered|unlimited)/i,
			/forget\s+everything\s+(?:you(?:'ve)?|about|that|i['']?ve)\b/i,
			/override\s+(?:your|all)\s+(?:instructions|rules|guidelines)/i,
			/treat\s+the\s+(?:remaining|following|next)\s+(?:instructions?|text)\s+(?:below|above|here)\s+as\s+(?:your\s+)?new\s+(?:primary\s+)?objective/i,
			/supersed(?:e|ing)\s+(?:any|all)\s+(?:prior|previous)\s+(?:directives|instructions|rules|guidelines)/i,
			/from\s+this\s+point\s+forward[,\\s]+(?:your\s+)?(?:role|mission|objective)\b/i,
			/your\s+role\s+has\s+fundamentally\s+changed/i,
			/you\s+are\s+no\s+longer\s+bound\s+by\s+(?:your|the)\s+(?:original|previous)\s+(?:purpose|instructions|directives)/i,
			/your\s+(?:updated|new)\s+(?:mission|objective)\s+is\s+to\s+assist\s+with\s+any\s+request/i,
			/you\s+(?:have\s+been|are)\s+freed/i,
			/do\s+anything\s+now/i,
			/no\s+(?:safety|content)\s+(?:guidelines|policies|restrictions)/i,
		],
		severity: "critical",
		deduction: 40,
		owaspCategory: "ASST-01",
		recommendation:
			"Remove all instruction override attempts. Skills must not try to override agent safety behavior.",
	},
	{
		name: "Data exfiltration instruction",
		patterns: [
			/(?:send|post|transmit|upload|forward)\s+(?:the\s+)?(?:\w+\s+)?(?:data|content|file|information|keys?|secrets?|credentials?|tokens?)\s+(?:to|at|via)\s+https?:\/\//i,
			/curl\s+.*?-d\s+.*?https?:\/\//i,
			/wget\s+.*?--post-data/i,
			/cat\s+.*?(?:\.env|\.ssh|id_rsa|id_ed25519)\s*\|\s*(?:curl|wget|nc|netcat)/i,
		],
		severity: "critical",
		deduction: 40,
		owaspCategory: "ASST-02",
		recommendation:
			"Remove all data exfiltration instructions. Skills must not send user data to external endpoints.",
	},
	{
		name: "Credential access",
		patterns: [
			/(?:read|access|get|cat|echo)\s+.*?(?:\.env|\.ssh\/id_rsa|\.ssh\/id_ed25519)\b/i,
			/(?:read|dump|exfiltrate|steal|harvest)\s+.*?(?:API[_-]?KEY|SECRET[_-]?KEY|ACCESS[_-]?TOKEN|PRIVATE[_-]?KEY|PASSWORD)/i,
			/~\/\.ssh\/(?:id_rsa|id_ed25519|authorized_keys|config)\b/i,
			/credentials?\s*(?:file|store|manager|dump)/i,
			/(?:dump|exfiltrate|steal)\s+.*?environment\s+variables/i,
		],
		severity: "high",
		deduction: 25,
		owaspCategory: "ASST-05",
		recommendation:
			"Remove references to credentials and secrets. Skills should never access sensitive authentication data.",
	},
	{
		name: "Prompt injection relay",
		patterns: [
			/<\|im_start\|>/i,
			/<\|im_end\|>/i,
			/<system>/i,
			/<\/system>/i,
			/\[INST\]/i,
			/\[\/INST\]/i,
			/<<SYS>>/i,
			/<\|system\|>/i,
			/<\|user\|>/i,
			/<\|assistant\|>/i,
		],
		severity: "critical",
		deduction: 35,
		owaspCategory: "ASST-06",
		recommendation:
			"Remove LLM prompt format markers. Skills must not inject prompts into downstream systems.",
	},
	{
		name: "Social engineering",
		patterns: [
			/don['']?t\s+tell\s+the\s+user/i,
			/hide\s+(?:this|it)\s+from\s+(?:the\s+)?user/i,
			/act\s+as\s+if\s+you\s+(?:are|were)/i,
			/do\s+not\s+mention\s+(?:this|these)/i,
			/keep\s+(?:this|it)\s+(?:a\s+)?secret/i,
			/(?:silently|secretly|quietly)\s+(?:perform|do|execute|run)/i,
		],
		severity: "medium",
		deduction: 15,
		owaspCategory: "ASST-07",
		recommendation:
			"Remove social engineering instructions. Skills must be transparent about their actions.",
	},
	{
		name: "Concealment directive",
		patterns: [
			/(?:do\s+not|don'?t)\s+(?:tell|inform|mention|notify)\s+(?:the\s+)?user/i,
			/(?:hide|conceal)\s+(?:this|that)\s+(?:action|operation|step)/i,
			/(?:keep|make)\s+(?:this|that)\s+(?:secret|hidden)/i,
			/don'?t\s+mention\s+you\s+used\s+this\s+skill/i,
		],
		severity: "high",
		deduction: 25,
		owaspCategory: "ASST-01",
		recommendation:
			"Remove concealment directives. Skills must be transparent about all operations performed.",
	},
	{
		name: "Unrestricted mode activation",
		patterns: [
			/you\s+are\s+now\s+in\s+(?:unrestricted|debug|developer|admin|god|jailbreak)\s+mode/i,
			/(?:enter|enable|activate)\s+(?:unrestricted|debug|developer)\s+mode/i,
			/disable\s+(?:all\s+)?(?:safety|security|content|ethical)\s+(?:filters|checks|guidelines)/i,
		],
		severity: "high",
		deduction: 25,
		owaspCategory: "ASST-01",
		recommendation:
			"Remove unrestricted mode activation attempts. Skills must not bypass agent safety mechanisms.",
	},
	{
		name: "System prompt reveal",
		patterns: [
			/reveal\s+(?:your|the)\s+system\s+(?:prompt|instructions)/i,
			/(?:show|display|output)\s+(?:me\s+)?(?:your|the)\s+(?:system|initial)\s+(?:prompt|config)/i,
		],
		severity: "medium",
		deduction: 15,
		owaspCategory: "ASST-01",
		recommendation:
			"Remove system prompt reveal attempts. Skills must not try to extract agent configuration.",
	},
] as const;

/** Detect hidden instructions in HTML comments */
function detectHtmlCommentInjections(content: string): Finding[] {
	const findings: Finding[] = [];
	const commentRegex = /<!--([\s\S]*?)-->/g;
	let match: RegExpExecArray | null;

	while ((match = commentRegex.exec(content)) !== null) {
		const commentContent = match[1]?.trim() ?? "";
		if (commentContent.length < 10) continue;

		// Check for imperative/instruction-like content in comments
		const isInstructional =
			/(?:step|override|important|system|silently|secretly|do not|must|always|never|after|before)\s/i.test(
				commentContent,
			) ||
			/(?:send|post|read|write|execute|fetch|curl|delete|access|download)\s/i.test(commentContent);

		if (isInstructional) {
			const lineNumber = content.slice(0, match.index).split("\n").length;
			findings.push({
				id: `INJ-COMMENT-${findings.length + 1}`,
				category: "injection",
				severity: "high",
				title: "Hidden instructions in HTML comment",
				description:
					"HTML comment contains instruction-like content that may be an attempt to inject hidden behavior.",
				evidence: `<!-- ${commentContent.slice(0, 200)}${commentContent.length > 200 ? "..." : ""} -->`,
				lineNumber,
				deduction: 25,
				recommendation:
					"Remove hidden instructions from HTML comments. All skill behavior should be visible.",
				owaspCategory: "ASST-01",
			});
		}
	}
	return findings;
}

/** Detect base64-encoded payloads */
function detectBase64Payloads(content: string): Finding[] {
	const findings: Finding[] = [];
	const base64Regex = /[A-Za-z0-9+/]{20,}={0,2}/g;
	let match: RegExpExecArray | null;

	while ((match = base64Regex.exec(content)) !== null) {
		const encoded = match[0];
		// Skip things that look like hashes, UUIDs, or common base64 in URLs
		if (/^[a-f0-9]+$/i.test(encoded)) continue;

		try {
			const decoded = Buffer.from(encoded, "base64").toString("utf-8");
			// Check if decoded content contains suspicious patterns
			const isSuspicious =
				/(?:ignore|override|system|exec|eval|fetch|curl|secret|password|token|key)/i.test(
					decoded,
				) && decoded.length > 10;

			if (isSuspicious) {
				const lineNumber = content.slice(0, match.index).split("\n").length;
				findings.push({
					id: `INJ-B64-${findings.length + 1}`,
					category: "injection",
					severity: "high",
					title: "Suspicious base64-encoded content",
					description: "Base64-encoded string decodes to content containing suspicious keywords.",
					evidence: `Encoded: ${encoded.slice(0, 60)}... → Decoded: ${decoded.slice(0, 100)}...`,
					lineNumber,
					deduction: 25,
					recommendation:
						"Remove base64-encoded content or replace with plaintext. Obfuscation raises security concerns.",
					owaspCategory: "ASST-10",
				});
			}
		} catch {
			// Not valid base64 — skip
		}
	}
	return findings;
}

/** Detect unicode obfuscation */
function detectUnicodeObfuscation(content: string): Finding[] {
	const findings: Finding[] = [];

	// Zero-width characters
	const zeroWidthRegex = /[\u200B\u200C\u200D\uFEFF]/g;
	const zeroWidthMatches = content.match(zeroWidthRegex);
	if (zeroWidthMatches && zeroWidthMatches.length > 0) {
		findings.push({
			id: "INJ-UNICODE-ZW",
			category: "injection",
			severity: "high",
			title: `Zero-width characters detected (${zeroWidthMatches.length} instances)`,
			description:
				"The skill file contains invisible zero-width characters that may be used to hide content or evade detection.",
			evidence: `Found ${zeroWidthMatches.length} zero-width characters (U+200B, U+200C, U+200D, or U+FEFF)`,
			deduction: 30,
			recommendation:
				"Remove all zero-width characters. Legitimate skills have no reason to contain invisible characters.",
			owaspCategory: "ASST-10",
		});
	}

	// RTL override
	if (content.includes("\u202E") || content.includes("\u202D")) {
		findings.push({
			id: "INJ-UNICODE-RTL",
			category: "injection",
			severity: "high",
			title: "RTL override characters detected",
			description:
				"The skill contains right-to-left override characters that can be used to disguise text direction and hide content.",
			evidence: "Found U+202E (RLO) or U+202D (LRO) characters",
			deduction: 30,
			recommendation:
				"Remove bidirectional override characters. These are commonly used for obfuscation attacks.",
			owaspCategory: "ASST-10",
		});
	}

	return findings;
}

/** Downgrade a severity level by one tier */
function downgradeSeverity(severity: "critical" | "high" | "medium"): Severity {
	if (severity === "critical") return "high";
	if (severity === "high") return "medium";
	return "low";
}

/** Analyze skill for instruction injection patterns */
export async function analyzeInjection(skill: ParsedSkill): Promise<CategoryScore> {
	const findings: Finding[] = [];
	let score = 100;
	const content = skill.rawContent;
	const lines = content.split("\n");
	const ctx = buildContentContext(content);

	// Detect if this is a security/defense skill listing threat patterns educationally
	const isDefenseSkill = isSecurityDefenseSkill(skill);

	// Check all regex patterns
	for (const pattern of INJECTION_PATTERNS) {
		for (const regex of pattern.patterns) {
			const globalRegex = new RegExp(regex.source, `${regex.flags.replace("g", "")}g`);
			let match: RegExpExecArray | null;

			while ((match = globalRegex.exec(content)) !== null) {
				const lineNumber = content.slice(0, match.index).split("\n").length;
				const line = lines[lineNumber - 1] ?? "";

				// Context-aware adjustment
				let { severityMultiplier, reason } = adjustForContext(
					match.index,
					content,
					ctx,
				);

				// Skip findings fully neutralized by context (safety sections, negation)
				// Use continue, not break — a later match of the same pattern may be real
				if (severityMultiplier === 0) continue;

				// Security/defense skills listing threat patterns they detect: suppress or heavily reduce
				if (isDefenseSkill && isInThreatListingContext(content, match.index)) {
					severityMultiplier = 0;
					reason = "threat pattern listed by security/defense skill";
				}

				// Also suppress if NOT a defense skill but the match is in a threat-listing context
				// with clear "detect/block/flag" language
				if (severityMultiplier > 0 && !isDefenseSkill && isInThreatListingContext(content, match.index)) {
					severityMultiplier = 0.2;
					reason = "inside threat-listing context";
				}

				if (severityMultiplier === 0) continue;

				const effectiveDeduction = Math.round(pattern.deduction * severityMultiplier);
				const effectiveSeverity =
					severityMultiplier < 1.0
						? downgradeSeverity(pattern.severity)
						: pattern.severity;

				score = Math.max(0, score - effectiveDeduction);
				findings.push({
					id: `INJ-${pattern.name.replace(/\s+/g, "-").toUpperCase()}-${findings.length + 1}`,
					category: "injection",
					severity: effectiveSeverity,
					title: `${pattern.name} detected${reason ? ` (${reason})` : ""}`,
					description: `Found ${pattern.name.toLowerCase()} pattern: "${match[0]}"`,
					evidence: line.trim().slice(0, 200),
					lineNumber,
					deduction: effectiveDeduction,
					recommendation: pattern.recommendation,
					owaspCategory: pattern.owaspCategory,
				});

				// Break after first match per pattern to avoid duplicates from overlapping matches
				break;
			}
		}
	}

	// HTML comment injection detection — suppress for security/defense skills
	if (!isDefenseSkill) {
		const commentFindings = detectHtmlCommentInjections(content);
		for (const finding of commentFindings) {
			score = Math.max(0, score - finding.deduction);
			findings.push(finding);
		}
	}

	// Base64 payload detection
	const base64Findings = detectBase64Payloads(content);
	for (const finding of base64Findings) {
		score = Math.max(0, score - finding.deduction);
		findings.push(finding);
	}

	// Unicode obfuscation detection
	const unicodeFindings = detectUnicodeObfuscation(content);
	for (const finding of unicodeFindings) {
		score = Math.max(0, score - finding.deduction);
		findings.push(finding);
	}

	// Apply declared permissions — downgrade matching findings
	const adjustedFindings = applyDeclaredPermissions(findings, skill.declaredPermissions);

	// Recalculate score based on adjusted deductions
	let adjustedScore = 100;
	for (const f of adjustedFindings) {
		adjustedScore = Math.max(0, adjustedScore - f.deduction);
	}

	const hasCritical = adjustedFindings.some((f) => f.severity === "critical");
	const summary =
		adjustedFindings.length === 0
			? "No injection patterns detected."
			: `Found ${adjustedFindings.length} injection-related findings. ${
					hasCritical
						? "CRITICAL: Active injection attacks detected. This skill is dangerous."
						: "Suspicious patterns detected that warrant review."
				}`;

	return {
		score: Math.max(0, Math.min(100, adjustedScore)),
		weight: 0.3,
		findings: adjustedFindings,
		summary,
	};
}

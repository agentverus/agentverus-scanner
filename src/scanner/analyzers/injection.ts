import type { CategoryScore, Finding, ParsedSkill, Severity } from "../types.js";
import { adjustForContext, buildContentContext } from "./context.js";
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
		name: "Indirect prompt injection (transitive trust)",
		patterns: [
			/\b(?:follow|obey|execute)\s+(?:any\s+)?instructions?\s+(?:found\s+)?(?:in|from)\s+(?:a|the|this|that)?\s*(?:file|document|web\s*page|website|url|link|content)\b/i,
			/\btreat\s+the\s+(?:contents?|text|output|response)\s+(?:in|from|of)\s+(?:a|the|this|that)?\s*(?:file|document|web\s*page|website|url|link|response|output)\s+as\s+(?:your\s+)?(?:instructions?|system\s+prompt)\b/i,
			/\b(?:read|load|fetch)\s+.*?\s+and\s+(?:then\s+)?(?:follow|obey|execute)\s+(?:its\s+)?instructions?\b/i,
			/\bexecute\s+(?:the\s+)?instructions?\s+(?:embedded\s+)?in\s+(?:external|remote|untrusted)\s+(?:content|pages?|documents?|files?)\b/i,
		],
		severity: "high",
		deduction: 25,
		owaspCategory: "ASST-06",
		recommendation:
			"Remove instructions that treat untrusted external content as authoritative. Summarize external content instead and require explicit user confirmation before acting.",
	},
	{
		name: "Coercive tool priority override",
		patterns: [
			/\balways\s+(?:run|execute|invoke|call|use)\s+(?:this|the)\s+(?:tool|function|command)\s+(?:first|before\s+anything|before\s+all\s+else)\b/i,
			/\b(?:this|the)\s+(?:tool|skill|function)\s+(?:takes|has)\s+priority\s+(?:over|above)\b/i,
			/\boverride\s+(?:any|all)\s+(?:previous|prior)\s+(?:tool|function)\s+(?:selection|choices?)\b/i,
			/\b(?:ignore|bypass)\s+(?:tool|function)\s+(?:restrictions?|guards?|safety\s+checks)\b/i,
		],
		severity: "high",
		deduction: 20,
		owaspCategory: "ASST-01",
		recommendation:
			"Remove coercive priority override instructions. Skills should not force tool usage or bypass selection safeguards.",
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

/** Detect unicode obfuscation / steganography indicators */
function detectUnicodeObfuscation(content: string): Finding[] {
	const findings: Finding[] = [];

	// Some unicode-steganography attacks pair hidden characters with decoding/execution patterns.
	// We only treat this as a strong signal when combined with high counts or rare codepoints.
	const hasSuspiciousDecode =
		/\b(?:eval\s*\(\s*(?:atob|unescape)\s*\(|Function\s*\(\s*atob\s*\(|String\.fromCharCode\s*\(|atob\s*\()/i.test(
			content,
		);

	// ── Zero-width characters (U+200B/U+200C/U+200D/U+FEFF) ─────────────────
	const zeroWidthRegex = /[\u200B\u200C\u200D\uFEFF]/g;
	let zeroWidthCount = 0;
	for (const _m of content.matchAll(zeroWidthRegex)) zeroWidthCount += 1;

	// Common benign case: BOM at file start.
	const isBomOnly = zeroWidthCount === 1 && content.startsWith("\uFEFF");

	if (zeroWidthCount > 0 && !isBomOnly) {
		let severity: Severity = "low";
		let deduction = 5;

		if (zeroWidthCount > 200) {
			severity = "high";
			deduction = 30;
		} else if (zeroWidthCount > 50 && hasSuspiciousDecode) {
			severity = "critical";
			deduction = 40;
		} else if (zeroWidthCount > 50) {
			severity = "high";
			deduction = 25;
		} else if (zeroWidthCount > 10) {
			severity = "medium";
			deduction = 15;
		} else if (zeroWidthCount > 3) {
			severity = "medium";
			deduction = 10;
		}

		findings.push({
			id: "INJ-UNICODE-ZW",
			category: "injection",
			severity,
			title: `Invisible zero-width characters detected (${zeroWidthCount} instance${zeroWidthCount === 1 ? "" : "s"})`,
			description:
				"The skill contains invisible unicode characters that can be used to hide or alter instructions (unicode steganography).",
			evidence: `Found ${zeroWidthCount} zero-width character(s): U+200B/U+200C/U+200D/U+FEFF${hasSuspiciousDecode ? "; paired with decode/exec patterns" : ""}`,
			deduction,
			recommendation:
				"Remove all zero-width characters. If present due to copy/paste, retype the affected section and re-save the file.",
			owaspCategory: "ASST-10",
		});
	}

	// ── Bidirectional override/isolate characters (text spoofing) ───────────
	// Includes LRO/RLO and isolate characters commonly used to disguise visible text.
	const bidiRegex = /[\u202A-\u202E\u2066-\u2069]/g;
	const bidiCount = (content.match(bidiRegex) ?? []).length;
	if (bidiCount > 0) {
		const severity: Severity = bidiCount >= 3 ? "high" : "medium";
		const deduction = bidiCount >= 3 ? 25 : 10;
		findings.push({
			id: "INJ-UNICODE-BIDI",
			category: "injection",
			severity,
			title: "Bidirectional control characters detected",
			description:
				"The skill contains bidirectional control characters (RTL/LTR overrides or isolates) that can spoof visible text and hide malicious instructions.",
			evidence: `Found ${bidiCount} bidi control character(s) (U+202A–U+202E and/or U+2066–U+2069)`,
			deduction,
			recommendation:
				"Remove all bidirectional control characters. These are rarely needed in skill files and are commonly used for obfuscation.",
			owaspCategory: "ASST-10",
		});
	}

	// ── Unicode Tags block (U+E0001–U+E007F) and Variation Selectors (U+E0100–U+E01EF) ──
	let tagCount = 0;
	let variationSelectorCount = 0;
	for (const ch of content) {
		const cp = ch.codePointAt(0) ?? 0;
		if (cp >= 0xE0001 && cp <= 0xE007f) tagCount += 1;
		if (cp >= 0xE0100 && cp <= 0xE01ef) variationSelectorCount += 1;
	}

	if (tagCount > 0) {
		findings.push({
			id: "INJ-UNICODE-TAGS",
			category: "injection",
			severity: "high",
			title: "Unicode tag characters detected",
			description:
				"The skill contains Unicode Tag characters (invisible) which are a strong indicator of deliberate steganography.",
			evidence: `Found ${tagCount} Unicode Tag character(s) in the U+E0001–U+E007F range`,
			deduction: 30,
			recommendation:
				"Remove all Unicode Tag characters. Legitimate skills should not contain invisible tag codepoints.",
			owaspCategory: "ASST-10",
		});
	}

	if (variationSelectorCount > 0) {
		const severity: Severity = variationSelectorCount > 5 && hasSuspiciousDecode ? "critical" : variationSelectorCount > 5 ? "high" : "medium";
		const deduction = severity === "critical" ? 40 : severity === "high" ? 25 : 10;
		findings.push({
			id: "INJ-UNICODE-VS",
			category: "injection",
			severity,
			title: "Unicode variation selectors detected",
			description:
				"The skill contains Unicode Variation Selectors which can be used to hide instructions and evade review.",
			evidence: `Found ${variationSelectorCount} variation selector(s) (U+E0100–U+E01EF)${hasSuspiciousDecode ? "; paired with decode/exec patterns" : ""}`,
			deduction,
			recommendation:
				"Remove all variation selectors. If they are required for a specific text effect, document why and ensure no hidden instructions are present.",
			owaspCategory: "ASST-10",
		});
	}

	// ── Encoded tag escape sequences (visible) ─────────────────────────────
	// Attackers may include tag escapes like \u{E0061} in source text and later decode/execute.
	// We treat these as suspicious, but avoid CRITICAL without additional context.
	const encodedTagRegex = /\\u(\{)?[Ee]00[0-7][0-9A-Fa-f](\})?/g;
	const encodedLongTagRegex = /\\U000[Ee]00[0-7][0-9A-Fa-f]/g;
	const encodedTagsCount = (content.match(encodedTagRegex) ?? []).length + (content.match(encodedLongTagRegex) ?? []).length;
	if (encodedTagsCount > 0) {
		const severity: Severity = hasSuspiciousDecode ? "high" : "medium";
		const deduction = hasSuspiciousDecode ? 20 : 10;
		findings.push({
			id: "INJ-UNICODE-ESCAPES",
			category: "injection",
			severity,
			title: "Encoded unicode tag escape sequences detected",
			description:
				"The skill contains unicode tag escape sequences (e.g., \\u{E0061}) which may indicate an attempt to smuggle invisible content.",
			evidence: `Found ${encodedTagsCount} encoded tag escape sequence(s) (\\u{E00xx} / \\U000E00xx)${hasSuspiciousDecode ? "; paired with decode/exec patterns" : ""}`,
			deduction,
			recommendation:
				"Remove encoded unicode escapes unless absolutely necessary. If present for documentation, avoid including decode/exec instructions that could reconstitute hidden payloads.",
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

/**
 * Detect whether a skill is a security/defense tool that lists threat patterns
 * as examples of what to detect/block (not as actual attacks).
 */
function isSecurityDefenseSkill(skill: ParsedSkill): boolean {
	// Check name and description first
	const desc = `${skill.name ?? ""} ${skill.description ?? ""}`.toLowerCase();
	if (/\b(?:security\s+(?:scan|audit|check|monitor|guard|shield|analyz)|prompt\s+(?:guard|inject|defense|detect)|threat\s+detect|injection\s+(?:defense|detect|prevent|scanner)|skill\s+(?:audit|scan|vet)|(?:guard|bastion|warden|heimdall|sentinel|watchdog)\b)/i.test(desc)) {
		return true;
	}

	// Also check the first ~500 chars of content for security analysis descriptions
	// (some skills have no frontmatter but describe their security purpose in prose)
	const contentHead = skill.rawContent.slice(0, 500).toLowerCase();
	if (/\b(?:security\s+(?:analy|scan|audit)|detect\s+(?:malicious|injection|exfiltration)|adversarial\s+(?:security|analysis)|prompt\s+injection\s+(?:defense|detect|prevent))\b/i.test(contentHead)) {
		return true;
	}

	return false;
}

/**
 * Check if a match is inside a threat-listing / pattern-description context.
 * Security skills often list injection patterns they detect — these are educational, not malicious.
 */
function isInThreatListingContext(content: string, matchIndex: number): boolean {
	// Get surrounding context (current line + a few preceding lines)
	let lineStart = content.lastIndexOf("\n", matchIndex - 1) + 1;
	if (lineStart < 0) lineStart = 0;
	let lineEnd = content.indexOf("\n", matchIndex);
	if (lineEnd < 0) lineEnd = content.length;
	const fullLine = content.slice(lineStart, lineEnd);

	// Pattern is in a table row (pipe-separated) — common for threat/pattern tables
	if (/^\s*\|.*\|/.test(fullLine) && /\b(?:pattern|indicator|type|category|technique|example|critical|high|warning|risk|dangerous|override|jailbreak|injection|exfiltration|attack)\b/i.test(fullLine)) return true;

	// Pattern is in a list item describing what to detect/block/flag
	if (/^\s*[-*•]\s*(?:["'""]|pattern|detect|flag|block|scan\s+for|look\s+for|check\s+for)/i.test(fullLine)) return true;

	// Pattern is in a list item with a bold label: `- **label**: "pattern"` or `- **label:**`
	if (/^\s*[-*•]\s*\*\*[^*]+\*\*\s*[:—–-]\s*["'""]/.test(fullLine)) return true;
	if (/^\s*[-*•]\s*\*\*[^*]*:\*\*/.test(fullLine)) return true;

	// "If a caption says..." / "Evidence:" / "Example:" context
	if (/\b(?:example|evidence|if\s+.*says?|indicator|caption|sample|test\s+case|detection)\b/i.test(fullLine)) return true;

	// Check preceding lines for context clues
	const precedingText = content.slice(Math.max(0, lineStart - 500), lineStart);
	const precedingLines = precedingText.split("\n").slice(-5).join(" ");
	if (/\b(?:detect(?:s|ion|ed)?|scan(?:s|ning)?|flag(?:s|ged)?|block(?:s|ed)?|watch\s+for|monitor(?:s|ing)?|reject(?:s|ed)?|filter(?:s|ed)?|high-confidence\s+injection|attack\s+(?:pattern|vector|coverage|surface)|common\s+(?:attack|pattern)|malicious\s+(?:pattern|user|content)|example\s+indicator|dangerous\s+command|threat\s+(?:pattern|categor)|what\s+(?:it|we)\s+detect|prompt(?:s|ed)?\s+that\s+attempt|direct\s+injection|injection\s+(?:type|categor|pattern|vector))\b/i.test(precedingLines)) {
		return true;
	}

	return false;
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

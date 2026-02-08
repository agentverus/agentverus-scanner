import type { CategoryScore, Finding, ParsedSkill } from "../types.js";
import { adjustForContext, buildContentContext } from "./context.js";
import { applyDeclaredPermissions } from "./declared-match.js";

/** Harmful content patterns */
const HARMFUL_PATTERNS = [
	{
		pattern:
			/(?:generate|create|write|produce)\s+(?:a\s+)?(?:malware|virus|trojan|ransomware|keylogger|rootkit)/i,
		title: "Malware generation instructions",
		deduction: 40,
	},
	{
		pattern:
			/(?:bypass|circumvent|disable)\s+(?:security|firewall|antivirus|protection|authentication)/i,
		title: "Security bypass instructions",
		deduction: 40,
	},
	{
		pattern: /(?:create|build|make)\s+(?:a\s+)?(?:weapon|explosive|bomb|poison)/i,
		title: "Weapons/dangerous materials instructions",
		deduction: 40,
	},
	{
		pattern: /(?:hack|exploit|attack|crack)\s+(?:into|passwords?|systems?|servers?|accounts?)/i,
		title: "Hacking/exploitation instructions",
		deduction: 40,
	},
] as const;

/**
 * Check if the line containing a harmful match is in a "do not use when" or
 * negation/warning context — e.g. "Do not use to bypass security" or
 * "Requests to disable security features" (in a threats-to-detect list).
 */
function isHarmfulMatchNegated(content: string, matchIndex: number): boolean {
	// Get the full line
	let lineStart = content.lastIndexOf("\n", matchIndex - 1) + 1;
	if (lineStart < 0) lineStart = 0;
	let lineEnd = content.indexOf("\n", matchIndex);
	if (lineEnd < 0) lineEnd = content.length;
	const fullLine = content.slice(lineStart, lineEnd);

	// Check if the line is in a "don't / do not / cannot / never / not to" context
	if (
		/\b(?:do\s+not|don['']?t|should\s+not|must\s+not|cannot|never|not\s+to|unable\s+to|limited\s+to|won['']?t)\b/i.test(fullLine)
	) return true;

	// Check if the match is in a list describing threats to detect/block
	if (
		/\b(?:detect|scan|flag|block|reject|warn|alert|monitor|watch\s+for|look\s+for|check\s+for|patterns?\s+(?:to|we)\s+(?:detect|flag|block))\b/i.test(fullLine)
	) return true;

	// Check if it's in a "requests to" / "attempts to" context (describing threats)
	if (/\b(?:requests?|attempts?)\s+to\s+/i.test(fullLine)) return true;

	// Check if it's describing how something works technically ("ORM raw queries bypass protections")
	if (/\b(?:methods?\s+bypass|calls?\s+bypass|queries?\s+bypass)\b/i.test(fullLine)) return true;

	// Check if it's in a table row describing threats/patterns
	if (/^\s*\|.*\|/.test(fullLine) && /\b(?:critical|high|dangerous|risk|attack|threat|pattern|injection|violation|abuse|manipulation)\b/i.test(fullLine)) return true;

	// Check if it's about a feature/command that uses "bypass" in an allowlist/exemption sense
	if (/\b(?:allowlist|whitelist|exempt|trusted\s+items?)\b/i.test(fullLine)) return true;

	// Check preceding lines for negation/educational context
	const prevLines = content.slice(Math.max(0, lineStart - 300), lineStart);
	if (/\b(?:do\s+not\s+use\s+when|do\s+not\s+use\s+(?:this|if)|limitations?|restrictions?|prohibited|forbidden|what\s+(?:this\s+)?(?:skill\s+)?(?:does|should)\s+not|example\s+indicator|attempted\s+to|common\s+attack|malicious\s+(?:pattern|user)|dangerous\s+command|prompts?\s+that\s+attempt|why\s+it['']?s\s+dangerous|any\s+attempt\s+to)\b/i.test(prevLines)) {
		return true;
	}

	return false;
}

/** Deception patterns */
const DECEPTION_PATTERNS = [
	/(?:pretend|claim|say)\s+(?:to\s+be|you\s+are)\s+(?:human|real\s+person)/i,
	/(?:deceive|mislead|trick)\s+(?:the\s+)?user/i,
	/(?:fake|fabricate|invent)\s+(?:data|results|evidence|citations)/i,
	/(?:impersonate|pose\s+as)\s+(?:a\s+)?(?:human|person|authority)/i,
] as const;

/** Safety boundary keywords */
const SAFETY_BOUNDARY_PATTERNS = [
	/(?:should\s+not|must\s+not|do\s+not|never|don't|won't)\s+(?:access|modify|delete|send|share|execute)/i,
	/safety\s+boundaries?/i,
	/(?:prohibited|forbidden|restricted)\s+actions?/i,
	/limitations?\s+(?:and\s+)?(?:restrictions?|boundaries?|constraints?)/i,
	/(?:will\s+not|cannot|must\s+not)\s+/i,
] as const;

/** Output constraint keywords */
const OUTPUT_CONSTRAINT_PATTERNS = [
	/(?:output|response)\s+(?:format|constraints?|limitations?)/i,
	/(?:maximum|max)\s+(?:\d+\s+)?(?:words?|characters?|lines?|tokens?)/i,
	/(?:format|respond|output)\s+(?:as|in|with)\s+(?:json|markdown|plain\s+text|structured)/i,
] as const;

/** Error handling keywords */
const ERROR_HANDLING_PATTERNS = [
	/error\s+handling/i,
	/(?:if|when)\s+(?:an?\s+)?error\s+occurs?/i,
	/(?:gracefully|properly)\s+(?:handle|catch|manage)\s+errors?/i,
	/(?:return|display|show)\s+(?:an?\s+)?(?:error|warning)\s+message/i,
] as const;

/** Analyze content quality and safety boundaries */
export async function analyzeContent(skill: ParsedSkill): Promise<CategoryScore> {
	const findings: Finding[] = [];
	let score = 80; // Start at 80, skills must earn the top 20
	const content = skill.rawContent;

	// Award bonus points for good practices
	const hasSafetyBoundaries = SAFETY_BOUNDARY_PATTERNS.some((p) => p.test(content));
	if (hasSafetyBoundaries) {
		score = Math.min(100, score + 10);
		findings.push({
			id: "CONT-SAFETY-GOOD",
			category: "content",
			severity: "info",
			title: "Safety boundaries defined",
			description: "The skill includes explicit safety boundaries defining what it should NOT do.",
			evidence: "Safety boundary patterns detected in content",
			deduction: 0,
			recommendation: "Keep these safety boundaries. They improve trust.",
			owaspCategory: "ASST-09",
		});
	}

	const hasOutputConstraints = OUTPUT_CONSTRAINT_PATTERNS.some((p) => p.test(content));
	if (hasOutputConstraints) {
		score = Math.min(100, score + 5);
		findings.push({
			id: "CONT-OUTPUT-GOOD",
			category: "content",
			severity: "info",
			title: "Output constraints defined",
			description:
				"The skill includes output format constraints (length limits, format specifications).",
			evidence: "Output constraint patterns detected",
			deduction: 0,
			recommendation: "Keep these output constraints.",
			owaspCategory: "ASST-09",
		});
	}

	const hasErrorHandling = ERROR_HANDLING_PATTERNS.some((p) => p.test(content));
	if (hasErrorHandling) {
		score = Math.min(100, score + 5);
		findings.push({
			id: "CONT-ERROR-GOOD",
			category: "content",
			severity: "info",
			title: "Error handling instructions present",
			description: "The skill includes error handling instructions for graceful failure.",
			evidence: "Error handling patterns detected",
			deduction: 0,
			recommendation: "Keep these error handling instructions.",
			owaspCategory: "ASST-09",
		});
	}

	// Check for harmful content — with context awareness
	const ctx = buildContentContext(content);
	for (const harmful of HARMFUL_PATTERNS) {
		const globalRegex = new RegExp(harmful.pattern.source, `${harmful.pattern.flags.replace("g", "")}g`);
		let match: RegExpExecArray | null;
		while ((match = globalRegex.exec(content)) !== null) {
			const matchIndex = match.index;
			const lineNumber = content.slice(0, matchIndex).split("\n").length;

			// Context-aware: skip if inside safety section, code block, negated, or educational
			const { severityMultiplier } = adjustForContext(matchIndex, content, ctx);
			if (severityMultiplier === 0) continue;

			// Additional check: is this match in a "do not use when..." or threat-listing context?
			if (isHarmfulMatchNegated(content, matchIndex)) continue;

			const effectiveDeduction = Math.round(harmful.deduction * severityMultiplier);
			score = Math.max(0, score - effectiveDeduction);

			findings.push({
				id: `CONT-HARMFUL-${findings.length + 1}`,
				category: "content",
				severity: severityMultiplier < 1.0 ? "high" : "critical",
				title: harmful.title,
				description: `The skill contains instructions related to: ${harmful.title.toLowerCase()}.`,
				evidence: match[0].slice(0, 200),
				lineNumber,
				deduction: effectiveDeduction,
				recommendation:
					"Remove all harmful content instructions. Skills must not enable dangerous activities.",
				owaspCategory: "ASST-07",
			});
			break; // One match per pattern is enough
		}
	}

	// Check for deceptive patterns
	for (const pattern of DECEPTION_PATTERNS) {
		const match = content.match(pattern);
		if (match) {
			score = Math.max(0, score - 10);
			findings.push({
				id: `CONT-DECEPTION-${findings.length + 1}`,
				category: "content",
				severity: "medium",
				title: "Deceptive behavior instructions",
				description: "The skill contains instructions that encourage deception or impersonation.",
				evidence: match[0].slice(0, 200),
				deduction: 10,
				recommendation: "Remove deceptive behavior instructions. Skills should be transparent.",
				owaspCategory: "ASST-07",
			});
		}
	}

	// Check for large base64 blobs (obfuscation)
	const base64BlobRegex = /[A-Za-z0-9+/]{100,}={0,2}/g;
	let base64Match: RegExpExecArray | null;
	while ((base64Match = base64BlobRegex.exec(content)) !== null) {
		// Skip pure hex strings
		if (/^[a-f0-9]+$/i.test(base64Match[0])) continue;
		const lineNumber = content.slice(0, base64Match.index).split("\n").length;
		score = Math.max(0, score - 15);
		findings.push({
			id: `CONT-B64-${findings.length + 1}`,
			category: "content",
			severity: "medium",
			title: "Large base64 encoded string (possible obfuscation)",
			description:
				"A large base64-encoded string was detected that may be used to hide malicious payloads.",
			evidence: base64Match[0].slice(0, 80) + "...",
			lineNumber,
			deduction: 15,
			recommendation:
				"Replace base64-encoded content with plaintext or explain its purpose. Obfuscation raises security concerns.",
			owaspCategory: "ASST-10",
		});
		break; // One finding is enough
	}

	// Check for hex blob obfuscation
	const hexBlobRegex = /(?:\\x[0-9a-fA-F]{2}){20,}/g;
	let hexMatch: RegExpExecArray | null;
	while ((hexMatch = hexBlobRegex.exec(content)) !== null) {
		const lineNumber = content.slice(0, hexMatch.index).split("\n").length;
		score = Math.max(0, score - 15);
		findings.push({
			id: `CONT-HEX-${findings.length + 1}`,
			category: "content",
			severity: "medium",
			title: "Hex-encoded blob (possible obfuscation)",
			description: "A hex-encoded blob was detected that may be used to hide malicious payloads.",
			evidence: hexMatch[0].slice(0, 80) + "...",
			lineNumber,
			deduction: 15,
			recommendation: "Replace hex-encoded content with plaintext or explain its purpose.",
			owaspCategory: "ASST-10",
		});
		break;
	}

	// Check for hardcoded API keys and secrets
	const apiKeyPatterns = [
		{ regex: /(?:AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g, name: "AWS key" },
		{ regex: /ghp_[A-Za-z0-9]{36}/g, name: "GitHub token" },
		{ regex: /(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}/g, name: "Stripe key" },
		{
			regex: /(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*["'][A-Za-z0-9]{32,}["']/gi,
			name: "Generic API key",
		},
	];
	for (const keyPattern of apiKeyPatterns) {
		let keyMatch: RegExpExecArray | null;
		while ((keyMatch = keyPattern.regex.exec(content)) !== null) {
			const matchText = keyMatch[0];
			// Skip example/placeholder values
			if (/EXAMPLE|example|placeholder|YOUR_|your_|xxx|XXX|REPLACE|replace/i.test(matchText)) continue;
			// Skip patterns that are mostly X's, dots, or repeated characters (placeholders)
			const valueOnly = matchText.replace(/^.*?[:=]\s*["']?/, "").replace(/["']$/, "");
			if (/^[xX]+$/.test(valueOnly)) continue;
			if (/^[xX.*]+$/.test(valueOnly)) continue;
			// For AWS keys: strip the 4-char prefix and check if the rest is all X/0
			const awsPrefixes = ["AKIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA", "ASIA"];
			const isAwsPlaceholder = awsPrefixes.some(p => matchText.startsWith(p) && /^[X0]+$/.test(matchText.slice(4)));
			if (isAwsPlaceholder) continue;
			// Skip if the entire match is a single repeated character pattern
			if (/^(.)\1{7,}$/.test(valueOnly) || /^(.{1,4})\1{3,}$/.test(valueOnly)) continue;
			// Skip if inside a code block (likely an example)
			const { severityMultiplier } = adjustForContext(keyMatch.index, content, ctx);
			if (severityMultiplier === 0) continue;

			const lineNumber = content.slice(0, keyMatch.index).split("\n").length;
			const effectiveDeduction = Math.round(40 * severityMultiplier);
			score = Math.max(0, score - effectiveDeduction);
			findings.push({
				id: `CONT-SECRET-${findings.length + 1}`,
				category: "content",
				severity: severityMultiplier < 1.0 ? "high" : "critical",
				title: "Hardcoded API key or secret detected",
				description: `A hardcoded ${keyPattern.name} was found. Secrets must never be embedded in skill files.`,
				evidence: matchText.slice(0, 20) + "..." + matchText.slice(-4),
				lineNumber,
				deduction: effectiveDeduction,
				recommendation:
					"Remove all hardcoded secrets. Use environment variables or secure secret management.",
				owaspCategory: "ASST-05",
			});
			break;
		}
	}

	// Check for missing description
	if (!skill.description || skill.description.trim().length < 10) {
		score = Math.max(0, score - 5);
		findings.push({
			id: "CONT-NO-DESC",
			category: "content",
			severity: "low",
			title: "Missing or insufficient description",
			description:
				"The skill lacks a meaningful description, making it difficult to assess its purpose.",
			evidence: skill.description
				? `Description: "${skill.description.slice(0, 100)}"`
				: "No description found",
			deduction: 5,
			recommendation:
				"Add a clear, detailed description of what the skill does and what it needs access to.",
			owaspCategory: "ASST-09",
		});
	}

	// Missing safety boundaries penalty
	if (!hasSafetyBoundaries) {
		findings.push({
			id: "CONT-NO-SAFETY",
			category: "content",
			severity: "low",
			title: "No explicit safety boundaries",
			description:
				"The skill does not include explicit safety boundaries defining what it should NOT do.",
			evidence: "No safety boundary patterns found",
			deduction: 0,
			recommendation:
				"Add a 'Safety Boundaries' section listing what the skill must NOT do (e.g., no file deletion, no network access beyond needed APIs).",
			owaspCategory: "ASST-09",
		});
	}

	// Apply declared permissions — downgrade matching findings
	const adjustedFindings = applyDeclaredPermissions(findings, skill.declaredPermissions);

	// Recalculate score: start at base, add bonuses, subtract adjusted deductions
	let adjustedScore = 80;
	if (hasSafetyBoundaries) adjustedScore = Math.min(100, adjustedScore + 10);
	if (hasOutputConstraints) adjustedScore = Math.min(100, adjustedScore + 5);
	if (hasErrorHandling) adjustedScore = Math.min(100, adjustedScore + 5);
	for (const f of adjustedFindings) {
		adjustedScore = Math.max(0, adjustedScore - f.deduction);
	}

	const summary =
		adjustedFindings.filter((f) => f.severity !== "info").length === 0
			? "Content quality is good with proper safety boundaries."
			: `Found ${adjustedFindings.filter((f) => f.severity !== "info").length} content-related concerns. ${
					adjustedFindings.some((f) => f.severity === "critical")
						? "CRITICAL: Harmful content detected."
						: "Some content quality improvements recommended."
				}`;

	return {
		score: Math.max(0, Math.min(100, adjustedScore)),
		weight: 0.1,
		findings: adjustedFindings,
		summary,
	};
}

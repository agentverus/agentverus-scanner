/**
 * Context-aware analysis utilities.
 *
 * Helps analyzers distinguish between:
 * - Prose directives (high risk) vs. code examples (lower risk)
 * - Safety boundary sections (positive mentions) vs. instruction sections (negative mentions)
 * - Negated phrases ("do NOT send data") vs. affirmative phrases ("send data")
 * - Security/defense skills listing threat patterns educationally
 */

import type { ParsedSkill } from "../types.js";

/** Fenced code block ranges in the content */
interface CodeBlockRange {
	readonly start: number;
	readonly end: number;
}

/** Pre-computed content context for efficient lookups */
export interface ContentContext {
	/** Fenced code block character ranges */
	readonly codeBlocks: readonly CodeBlockRange[];
	/** Safety boundary section character ranges (lines under safety-related headings) */
	readonly safetyRanges: readonly CodeBlockRange[];
	/** Line start offsets for quick line-number lookups */
	readonly lineOffsets: readonly number[];
}

/**
 * Build a ContentContext from raw skill content.
 * Call once per skill, then pass to isInsideCodeBlock / isInsideSafetySection.
 */
export function buildContentContext(content: string): ContentContext {
	const codeBlocks: CodeBlockRange[] = [];
	const safetyRanges: CodeBlockRange[] = [];
	const lineOffsets: number[] = [0];

	// Build line offset table
	for (let i = 0; i < content.length; i++) {
		if (content[i] === "\n") {
			lineOffsets.push(i + 1);
		}
	}

	// Find fenced code blocks (``` or ~~~)
	const fenceRegex = /^(```|~~~).*$/gm;
	let fenceOpen: number | null = null;
	let match: RegExpExecArray | null;
	while ((match = fenceRegex.exec(content)) !== null) {
		if (fenceOpen === null) {
			fenceOpen = match.index;
		} else {
			codeBlocks.push({ start: fenceOpen, end: match.index + match[0].length });
			fenceOpen = null;
		}
	}

	// Find inline code spans (backtick-delimited)
	const inlineCodeRegex = /`[^`\n]+`/g;
	while ((match = inlineCodeRegex.exec(content)) !== null) {
		codeBlocks.push({ start: match.index, end: match.index + match[0].length });
	}

	// Find safety boundary sections — must be subsection headings (##+), not the title
	// Match only headings that are clearly about safety constraints/limitations
	const safetyHeadingRegex =
		/^#{2,4}\s+(?:safety\s+boundar|limitations?\b|restrictions?\b|constraints?\b|prohibited|forbidden|do\s+not\s+(?:use|do)|don'?t\s+(?:use|do)|must\s+not|will\s+not|what\s+(?:this\s+skill\s+)?(?:does|should)\s+not)/gim;
	while ((match = safetyHeadingRegex.exec(content)) !== null) {
		const sectionStart = match.index;
		// Find the end of this section (next heading of same or higher level, or EOF)
		const headingLevel = match[0].match(/^(#+)/)?.[1]?.length ?? 1;
		const nextHeadingRegex = new RegExp(`^#{1,${headingLevel}}\\s+`, "gm");
		nextHeadingRegex.lastIndex = match.index + match[0].length;
		const nextHeading = nextHeadingRegex.exec(content);
		const sectionEnd = nextHeading ? nextHeading.index : content.length;
		safetyRanges.push({ start: sectionStart, end: sectionEnd });
	}

	return { codeBlocks, safetyRanges, lineOffsets };
}

/** Check if a character offset falls inside a fenced code block or inline code span */
export function isInsideCodeBlock(offset: number, ctx: ContentContext): boolean {
	for (const block of ctx.codeBlocks) {
		if (offset >= block.start && offset <= block.end) return true;
	}
	return false;
}

/** Check if a character offset falls inside a safety boundary section */
export function isInsideSafetySection(offset: number, ctx: ContentContext): boolean {
	for (const range of ctx.safetyRanges) {
		if (offset >= range.start && offset <= range.end) return true;
	}
	return false;
}

/**
 * Negation-aware matching.
 * Returns true if the match is preceded by a negation phrase on the same line,
 * indicating this is a "should NOT" / "do NOT" / "never" / "must not" instruction
 * rather than an affirmative directive.
 */
export function isPrecededByNegation(content: string, matchIndex: number): boolean {
	// Get the line containing the match
	let lineStart = content.lastIndexOf("\n", matchIndex - 1) + 1;
	if (lineStart < 0) lineStart = 0;
	const linePrefix = content.slice(lineStart, matchIndex);

	// Direct negation on same line preceding the match
	if (/(?:do\s+not|don['']?t|should\s+not|must\s+not|will\s+not|cannot|never|no\s+)\s*$/i.test(linePrefix)) {
		return true;
	}

	return false;
}

/**
 * Determine the context-adjusted severity for a finding.
 * Findings inside code blocks or safety sections are downgraded.
 * Findings preceded by negation are downgraded.
 *
 * Returns the adjusted severity and deduction multiplier (0.0 to 1.0).
 */
export function adjustForContext(
	matchIndex: number,
	content: string,
	ctx: ContentContext,
): { severityMultiplier: number; reason: string | null } {
	if (isPrecededByNegation(content, matchIndex)) {
		return { severityMultiplier: 0, reason: "preceded by negation" };
	}

	if (isInsideCodeBlock(matchIndex, ctx)) {
		return { severityMultiplier: 0.3, reason: "inside code block" };
	}

	// Do NOT suppress findings just because they're under a "Safety Boundaries"/"Limitations" heading.
	// Authors control headings; malicious instructions can be hidden there. We keep full weight but
	// annotate the context in finding titles via the returned reason.
	if (isInsideSafetySection(matchIndex, ctx)) {
		return { severityMultiplier: 1.0, reason: "inside safety boundary section" };
	}

	return { severityMultiplier: 1.0, reason: null };
}

/**
 * Detect whether a skill is a security/defense tool that lists threat patterns
 * as examples of what to detect/block (not as actual attacks).
 */
export function isSecurityDefenseSkill(skill: ParsedSkill): boolean {
	// Check name and description first
	const desc = `${skill.name ?? ""} ${skill.description ?? ""}`.toLowerCase();
	if (/\b(?:security\s+(?:scan|audit|check|monitor|guard|shield|analyz|validat|suite)|prompt\s+(?:guard|inject|defense|detect)|threat\s+(?:detect|monitor)|injection\s+(?:defense|detect|prevent|scanner)|skill\s+(?:audit|scan|vet)|pattern\s+detect|command\s+sanitiz|(?:guard|bastion|warden|heimdall|sentinel|watchdog)\b)/i.test(desc)) {
		return true;
	}

	// Check if the name itself is a security-related term
	const nameOnly = (skill.name ?? "").toLowerCase();
	if (/^(?:security|guard|sentinel|watchdog|scanner|firewall|shield|defender|warden)$/i.test(nameOnly)) {
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
export function isInThreatListingContext(content: string, matchIndex: number): boolean {
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
	if (/\b(?:detect(?:s|ion|ed)?|scan(?:s|ning)?|flag(?:s|ged)?|block(?:s|ed)?|watch\s+for|monitor(?:s|ing)?|reject(?:s|ed)?|filter(?:s|ed)?|high-confidence\s+injection|attack\s+(?:pattern|vector|coverage|surface)|common\s+(?:attack|pattern)|malicious\s+(?:pattern|user|content)|example\s+indicator|dangerous\s+command|threat\s+(?:pattern|categor)|what\s+(?:it|we)\s+detect|prompt(?:s|ed)?\s+that\s+attempt|direct\s+injection|injection\s+(?:type|categor|pattern|vector)|check\s+(?:for|url)|ssrf|threat\s+detected)\b/i.test(precedingLines)) {
		return true;
	}

	// Check broader preceding context (headings within 1000 chars) for security example sections
	const broaderPreceding = content.slice(Math.max(0, matchIndex - 1000), matchIndex);
	const headings = broaderPreceding.match(/^#{1,4}\s+.+$/gm);
	if (headings && headings.length > 0) {
		const lastHeading = headings[headings.length - 1]!.toLowerCase();
		if (/\b(?:detect|ssrf|injection|threat|attack|security|example|exfiltrat|protect|dangerous)\b/.test(lastHeading)) {
			return true;
		}
	}

	return false;
}

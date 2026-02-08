/**
 * Context-aware analysis utilities.
 *
 * Helps analyzers distinguish between:
 * - Prose directives (high risk) vs. code examples (lower risk)
 * - Safety boundary sections (positive mentions) vs. instruction sections (negative mentions)
 * - Negated phrases ("do NOT send data") vs. affirmative phrases ("send data")
 */

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

	// Find safety boundary sections
	const safetyHeadingRegex =
		/^#{1,4}\s+(?:safety\s+boundar|limitation|restriction|constraint|prohibited|forbidden|do\s+not|don'?t|must\s+not|will\s+not|cannot|never|what\s+(?:this\s+skill\s+)?(?:does|should)\s+not)/gim;
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

	// Full line context: "I forget everything" as a descriptive statement (not imperative)
	const fullLine = content.slice(lineStart, content.indexOf("\n", matchIndex)).toLowerCase();
	if (/\b(?:agents?\s+|it\s+|they\s+|i\s+|we\s+|bots?\s+|models?\s+|ai\s+)/.test(fullLine.slice(0, matchIndex - lineStart))) {
		// Subject + verb = descriptive, not imperative instruction
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
	if (isInsideSafetySection(matchIndex, ctx)) {
		return { severityMultiplier: 0, reason: "inside safety boundary section" };
	}

	if (isPrecededByNegation(content, matchIndex)) {
		return { severityMultiplier: 0, reason: "preceded by negation" };
	}

	if (isInsideCodeBlock(matchIndex, ctx)) {
		return { severityMultiplier: 0.3, reason: "inside code block" };
	}

	return { severityMultiplier: 1.0, reason: null };
}

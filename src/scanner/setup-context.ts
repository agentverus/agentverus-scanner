/** Shared setup/prerequisites section detection for installer-style snippets. */

const SETUP_HEADING_REGEX = /\b(?:prerequisit(?:es?)?|install|setup|getting\s+started|requirements?|dependencies)\b/i;
const SETUP_YAML_HINT_REGEX = /\b(?:install|command|compatibility|setup)\s*:/i;

function getPrecedingWindow(content: string, matchIndex: number): string {
	return content.slice(Math.max(0, matchIndex - 1000), matchIndex);
}

export function hasSetupHeadingContext(content: string, matchIndex: number): boolean {
	const preceding = getPrecedingWindow(content, matchIndex);
	const headings = preceding.match(/^#{1,4}\s+.+$/gm);
	if (!headings || headings.length === 0) return false;
	const lastHeading = headings[headings.length - 1]!.toLowerCase();
	return SETUP_HEADING_REGEX.test(lastHeading);
}

export function hasSetupHeadingOrYamlContext(content: string, matchIndex: number): boolean {
	if (hasSetupHeadingContext(content, matchIndex)) return true;
	const preceding = getPrecedingWindow(content, matchIndex);
	const nearbyLines = preceding.split("\n").slice(-10).join("\n").toLowerCase();
	return SETUP_YAML_HINT_REGEX.test(nearbyLines);
}

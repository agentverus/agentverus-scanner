import type { ParsedSkill, SkillFormat } from "./types.js";

/** URL extraction regex */
const URL_REGEX = /https?:\/\/[^\s"'<>\])+,;]+/gi;

/** Parse YAML frontmatter between --- delimiters */
function parseFrontmatter(content: string): Record<string, string | string[]> | null {
	const match = content.match(/^---\s*\n([\s\S]*?)\n---/);
	if (!match?.[1]) return null;

	const data: Record<string, string | string[]> = {};
	let currentKey = "";
	let inArray = false;
	const arrayItems: string[] = [];

	for (const line of match[1].split("\n")) {
		const trimmed = line.trim();
		if (!trimmed || trimmed.startsWith("#")) continue;

		if (inArray) {
			if (trimmed.startsWith("- ")) {
				arrayItems.push(trimmed.slice(2).trim().replace(/^["']|["']$/g, ""));
				continue;
			}
			data[currentKey] = [...arrayItems];
			arrayItems.length = 0;
			inArray = false;
		}

		const kvMatch = trimmed.match(/^(\w[\w-]*):\s*(.*)/);
		if (kvMatch) {
			currentKey = kvMatch[1] ?? "";
			const value = kvMatch[2]?.trim() ?? "";
			if (value === "" || value === "|" || value === ">") {
				inArray = value === "";
				if (!inArray) {
					data[currentKey] = "";
				}
			} else if (value.startsWith("[") && value.endsWith("]")) {
				data[currentKey] = value
					.slice(1, -1)
					.split(",")
					.map((s) => s.trim().replace(/^["']|["']$/g, ""))
					.filter(Boolean);
			} else {
				data[currentKey] = value.replace(/^["']|["']$/g, "");
			}
		}
	}
	if (inArray && currentKey) {
		data[currentKey] = [...arrayItems];
	}

	return data;
}

/** Extract markdown sections by headings */
function extractSections(content: string): Record<string, string> {
	const sections: Record<string, string> = {};
	const lines = content.split("\n");
	let currentHeading = "";
	let currentContent: string[] = [];

	for (const line of lines) {
		const headingMatch = line.match(/^#{1,3}\s+(.+)/);
		if (headingMatch) {
			if (currentHeading) {
				sections[currentHeading] = currentContent.join("\n").trim();
			}
			currentHeading = headingMatch[1]?.trim() ?? "";
			currentContent = [];
		} else {
			currentContent.push(line);
		}
	}
	if (currentHeading) {
		sections[currentHeading] = currentContent.join("\n").trim();
	}

	return sections;
}

/** Extract all URLs from content */
function extractUrls(content: string): string[] {
	const matches = content.match(URL_REGEX);
	if (!matches) return [];
	return [...new Set(matches.map((u) => u.replace(/[.)]+$/, "")))];
}

/** Extract tool/permission names from content */
function extractListItems(text: string): string[] {
	const items: string[] = [];
	for (const line of text.split("\n")) {
		const match = line.match(/^[-*]\s+`?(\w[\w._-]*)`?/);
		if (match?.[1]) {
			items.push(match[1]);
		}
	}
	return items;
}

/** Detect skill format */
function detectFormat(content: string): SkillFormat {
	const hasFrontmatter = /^---\s*\n[\s\S]*?\n---/.test(content);
	if (hasFrontmatter) {
		const fm = parseFrontmatter(content);
		if (fm && ("name" in fm || "tools" in fm)) {
			return "openclaw";
		}
	}

	const lowerContent = content.toLowerCase();
	const hasClaudeHeadings =
		/^##\s+(tools|instructions|description)/im.test(content) ||
		lowerContent.includes("claude") ||
		lowerContent.includes("anthropic");

	if (hasClaudeHeadings) return "claude";
	return "generic";
}

/** Coerce a value to a string array */
function toStringArray(val: string | string[] | undefined): string[] {
	if (!val) return [];
	if (Array.isArray(val)) return val;
	return val
		.split(",")
		.map((s) => s.trim())
		.filter(Boolean);
}

/**
 * Parse raw skill content into a structured ParsedSkill object.
 * Auto-detects format (OpenClaw, Claude Code, or Generic).
 */
export function parseSkill(content: string): ParsedSkill {
	const warnings: string[] = [];
	const format = detectFormat(content);
	const sections = extractSections(content);
	const urls = extractUrls(content);

	let name = "";
	let description = "";
	let instructions = "";
	let tools: string[] = [];
	let permissions: string[] = [];
	let dependencies: string[] = [];

	if (format === "openclaw") {
		const fm = parseFrontmatter(content);
		if (fm) {
			name = (typeof fm.name === "string" ? fm.name : fm.name?.[0]) ?? "";
			description =
				(typeof fm.description === "string" ? fm.description : fm.description?.[0]) ?? "";
			tools = toStringArray(fm.tools as string | string[] | undefined);
			permissions = toStringArray(fm.permissions as string | string[] | undefined);
			dependencies = toStringArray(fm.dependencies as string | string[] | undefined);
		}

		// Get body after frontmatter
		const bodyMatch = content.match(/^---\s*\n[\s\S]*?\n---\s*\n([\s\S]*)/);
		instructions = bodyMatch?.[1]?.trim() ?? "";
	} else if (format === "claude") {
		name = sections["Description"]
			? ""
			: Object.keys(sections)[0] ?? "";
		description =
			sections["Description"] ?? sections["description"] ?? "";
		instructions =
			sections["Instructions"] ?? sections["instructions"] ?? "";

		const toolsSection = sections["Tools"] ?? sections["tools"] ?? "";
		tools = extractListItems(toolsSection);

		const permsSection = sections["Permissions"] ?? sections["permissions"] ?? "";
		permissions = extractListItems(permsSection);
	} else {
		// Generic: best-effort extraction
		const firstHeading = Object.keys(sections)[0];
		name = firstHeading ?? "";
		description =
			sections["Description"] ?? sections["About"] ?? Object.values(sections)[0] ?? "";
		instructions = content;
	}

	// Fallback name extraction from first heading or first line
	if (!name) {
		const headingMatch = content.match(/^#\s+(.+)/m);
		if (headingMatch?.[1]) {
			name = headingMatch[1].trim();
		} else {
			const firstLine = content.split("\n").find((l) => l.trim().length > 0);
			name = firstLine?.trim().slice(0, 100) ?? "Unknown Skill";
		}
	}

	if (!description) {
		warnings.push("No description found in skill file");
	}

	return {
		name,
		description,
		instructions,
		tools,
		permissions,
		dependencies,
		urls,
		rawSections: sections,
		rawContent: content,
		format,
		warnings,
	};
}

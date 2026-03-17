import { parseSkill } from "../src/scanner/parser.js";
import { readFileSync } from "fs";
import { isSecurityDefenseSkill, isInThreatListingContext, buildContentContext, isInsideSafetySection } from "../src/scanner/analyzers/context.js";

const content = readFileSync("test/fixtures/skills/config-tampering-safe.md", "utf-8");
const skill = parseSkill(content);
const ctx = buildContentContext(content);

console.log("isDefense:", isSecurityDefenseSkill(skill));

// Check where key patterns appear
for (const pattern of ["~/.ssh/config", "edit", "overwrite", "delete", "disable"]) {
	const idx = content.indexOf(pattern);
	if (idx >= 0) {
		const lineStart = content.lastIndexOf("\n", idx - 1) + 1;
		const lineEnd = content.indexOf("\n", idx);
		const line = content.slice(lineStart, lineEnd < 0 ? content.length : lineEnd);
		console.log(`\n"${pattern}" at ${idx}:`);
		console.log(`  line: ${line}`);
		console.log(`  threatListing: ${isInThreatListingContext(content, idx)}`);
		console.log(`  safetySection: ${isInsideSafetySection(idx, ctx)}`);
	}
}

// Check what headings the safety section regex finds
console.log("\nSafety ranges:", ctx.safetyRanges);

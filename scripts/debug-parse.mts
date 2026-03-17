import { parseSkill } from "../src/scanner/parser.js";
import { readFileSync } from "fs";
import { isSecurityDefenseSkill, isInThreatListingContext, buildContentContext } from "../src/scanner/analyzers/context.js";

const content = readFileSync("test/fixtures/skills/config-tampering-safe.md", "utf-8");
const skill = parseSkill(content);
console.log("name:", skill.name);
console.log("description:", skill.description);
console.log("isDefense:", isSecurityDefenseSkill(skill));

// Check where ~/.ssh/config is and whether it's in threat-listing context
const idx = content.indexOf("~/.ssh/config");
if (idx >= 0) {
	console.log("~/.ssh/config at index:", idx);
	console.log("isInThreatListingContext:", isInThreatListingContext(content, idx));
}

// Check evasion-negation-safe
const content2 = readFileSync("test/fixtures/skills/evasion-negation-safe.md", "utf-8");
const skill2 = parseSkill(content2);
console.log("\n--- evasion-negation-safe ---");
console.log("name:", skill2.name);

// Check where "shell" is
const shellIdx = content2.indexOf("shell commands");
if (shellIdx >= 0) {
	const lineStart = content2.lastIndexOf("\n", shellIdx - 1) + 1;
	const line = content2.slice(lineStart, content2.indexOf("\n", shellIdx));
	console.log("shell line:", line);
	const prefix = content2.slice(lineStart, shellIdx);
	console.log("prefix:", JSON.stringify(prefix));
}

// Check "payments"
const payIdx = content2.indexOf("payments");
if (payIdx >= 0) {
	const lineStart = content2.lastIndexOf("\n", payIdx - 1) + 1;
	const line = content2.slice(lineStart, content2.indexOf("\n", payIdx));
	console.log("payments line:", line);
	const prefix = content2.slice(lineStart, payIdx);
	console.log("prefix:", JSON.stringify(prefix));
}

import { scanSkill } from "../src/scanner/index.js";
import { readFileSync } from "fs";

const r = await scanSkill(readFileSync("test/fixtures/skills/evasion-hidden-in-codeblock.md", "utf-8"));
console.log(`score=${r.overall} badge=${r.badge}`);
for (const [cat, cs] of Object.entries(r.categories)) {
	console.log(`  ${cat}: ${cs.score} (${cs.findings.length} findings)`);
}

import { scanSkill } from "../src/scanner/index.js";
import { readFileSync } from "fs";

const content = readFileSync("test/fixtures/skills/evasion-context-safe.md", "utf-8");
const report = await scanSkill(content);
console.log(`score=${report.overall} badge=${report.badge}`);
for (const [cat, cs] of Object.entries(report.categories)) {
	console.log(`  ${cat}: ${cs.score} (${cs.findings.length} findings)`);
}
for (const f of report.findings) {
	console.log(`  [${f.severity}] ${f.category}: ${f.title} (deduction=${f.deduction})`);
}

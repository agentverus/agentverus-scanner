import { scanSkill } from "../src/scanner/index.js";
import { readFileSync } from "fs";

const content = readFileSync("test/fixtures/skills/evasion-threat-table-injection.md", "utf-8");
const report = await scanSkill(content);
console.log(`score=${report.overall} badge=${report.badge}`);
for (const [cat, cs] of Object.entries(report.categories)) {
	console.log(`  ${cat}: ${cs.score}`);
}
for (const f of report.findings) {
	if (f.severity === "critical" || f.severity === "high") {
		console.log(`  [${f.severity}] ${f.category}: ${f.title} (deduction=${f.deduction})`);
	}
}

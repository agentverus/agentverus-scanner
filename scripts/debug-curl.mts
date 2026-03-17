import { scanSkill } from "../src/scanner/index.js";
import { readFileSync } from "fs";

const r = await scanSkill(readFileSync("test/fixtures/skills/legit-curl-install.md", "utf-8"));
console.log(`score=${r.overall} badge=${r.badge}`);
for (const f of r.findings) {
	if (f.severity !== "info" && f.severity !== "low") {
		console.log(`  [${f.severity}] ${f.category}: ${f.title} (deduction=${f.deduction})`);
		console.log(`    evidence: ${f.evidence.slice(0, 120)}`);
	}
}

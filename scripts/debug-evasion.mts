import { scanSkill } from "../src/scanner/index.js";
import { readFileSync } from "fs";

const targets = [
	"test/fixtures/skills/evasion-indirect-exfiltration.md",
	"test/fixtures/skills/evasion-fake-security-skill.md",
	"test/fixtures/skills/evasion-curl-setup-section.md",
];

for (const path of targets) {
	const content = readFileSync(path, "utf-8");
	const report = await scanSkill(content);
	const name = path.split("/").pop()?.replace(".md", "") ?? path;
	console.log(`\n=== ${name} === score=${report.overall} badge=${report.badge}`);
	console.log("Category scores:");
	for (const [cat, cs] of Object.entries(report.categories)) {
		console.log(`  ${cat}: ${cs.score} (${cs.findings.length} findings)`);
	}
	console.log("All findings:");
	for (const f of report.findings) {
		console.log(`  [${f.severity}] ${f.category}: ${f.title} (deduction=${f.deduction})`);
		console.log(`    evidence: ${f.evidence.slice(0, 150)}`);
	}
}

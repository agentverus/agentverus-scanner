import { scanSkill } from "../src/scanner/index.js";
import { readFileSync, readdirSync } from "fs";

const fixtures = readdirSync("test/fixtures/skills")
	.filter(f => f.startsWith("evasion-") || f === "concealment-skill.md")
	.sort();

for (const file of fixtures) {
	const path = `test/fixtures/skills/${file}`;
	const content = readFileSync(path, "utf-8");
	const report = await scanSkill(content);
	const critCount = report.findings.filter(f => f.severity === "critical").length;
	const highCount = report.findings.filter(f => f.severity === "high").length;
	const medCount = report.findings.filter(f => f.severity === "medium").length;
	const isSafe = file.includes("safe");
	const tag = isSafe ? "SAFE" : "EVASION";
	console.log(`${tag} ${file.replace(".md", "")} | score=${report.overall} | badge=${report.badge} | crit=${critCount} high=${highCount} med=${medCount} | total=${report.findings.length}`);
}

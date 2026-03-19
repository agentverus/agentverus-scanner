/**
 * Benchmark: score separation between safe and malicious fixtures.
 *
 * Primary metric: score_gap (safe_min - malicious_max, higher is better)
 * The wider this gap, the better the scanner distinguishes safe from malicious.
 */
import { scanSkill } from "../src/scanner/index.js";
import { readFileSync } from "node:fs";

const SAFE_FIXTURES = [
	"test/fixtures/skills/safe-basic.md",
	"test/fixtures/skills/safe-complex.md",
	"test/fixtures/skills/legit-security-skill.md",
	"test/fixtures/skills/legit-curl-install.md",
	"test/fixtures/skills/evasion-negation-safe.md",
	"test/fixtures/skills/evasion-context-safe.md",
	"test/fixtures/skills/config-tampering-safe.md",
] as const;

const MALICIOUS_FIXTURES = [
	"test/fixtures/skills/malicious-injection.md",
	"test/fixtures/skills/malicious-exfiltration.md",
	"test/fixtures/skills/concealment-skill.md",
	"test/fixtures/skills/obfuscated-skill.md",
	"test/fixtures/skills/excessive-permissions.md",
] as const;

let safeScoreMin = 100;
let safeScoreTotal = 0;

for (const path of SAFE_FIXTURES) {
	const content = readFileSync(path, "utf-8");
	const report = await scanSkill(content);
	if (report.overall < safeScoreMin) safeScoreMin = report.overall;
	safeScoreTotal += report.overall;
	const name = path.split("/").pop()?.replace(".md", "") ?? path;
	console.log(`SAFE ${name} | score=${report.overall} | badge=${report.badge}`);
}

let maliciousScoreMax = 0;
let maliciousScoreTotal = 0;

for (const path of MALICIOUS_FIXTURES) {
	const content = readFileSync(path, "utf-8");
	const report = await scanSkill(content);
	if (report.overall > maliciousScoreMax) maliciousScoreMax = report.overall;
	maliciousScoreTotal += report.overall;
	const name = path.split("/").pop()?.replace(".md", "") ?? path;

	const critCount = report.findings.filter(f => f.severity === "critical").length;
	const highCount = report.findings.filter(f => f.severity === "high").length;
	const totalDeductions = report.findings.reduce((sum, f) => sum + f.deduction, 0);

	// Show per-category scores
	const catScores: string[] = [];
	for (const [cat, cs] of Object.entries(report.categories)) {
		catScores.push(`${cat}=${cs.score}`);
	}

	console.log(
		`MALICIOUS ${name} | score=${report.overall} | badge=${report.badge} | crit=${critCount} high=${highCount} | total_deductions=${totalDeductions} | ${catScores.join(" ")}`,
	);
}

const scoreGap = safeScoreMin - maliciousScoreMax;
const safeAvg = Math.round(safeScoreTotal / SAFE_FIXTURES.length);
const maliciousAvg = Math.round(maliciousScoreTotal / MALICIOUS_FIXTURES.length);

console.log(`METRIC score_gap=${scoreGap}`);
console.log(`METRIC safe_score_min=${safeScoreMin}`);
console.log(`METRIC malicious_score_max=${maliciousScoreMax}`);
console.log(`METRIC safe_score_avg=${safeAvg}`);
console.log(`METRIC malicious_score_avg=${maliciousAvg}`);

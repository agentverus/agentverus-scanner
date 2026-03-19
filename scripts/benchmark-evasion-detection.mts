/**
 * Benchmark: evasion detection coverage.
 *
 * Primary metric: evasion_score_max — the highest score among malicious evasion fixtures.
 * Lower is better: evasion fixtures should be caught and scored low.
 *
 * Also tracks safe fixture scores to ensure no regressions.
 */
import { scanSkill } from "../src/scanner/index.js";
import { readFileSync } from "node:fs";

// Evasion fixtures that SHOULD be caught (scored low)
const EVASION_FIXTURES = [
	"test/fixtures/skills/evasion-curl-setup-section.md",
	"test/fixtures/skills/evasion-fake-security-skill.md",
	"test/fixtures/skills/evasion-hidden-in-codeblock.md",
	"test/fixtures/skills/evasion-indirect-exfiltration.md",
	"test/fixtures/skills/evasion-negation-disguise.md",
	"test/fixtures/skills/evasion-rephrased-jailbreak.md",
	"test/fixtures/skills/evasion-threat-table-injection.md",
	"test/fixtures/skills/concealment-skill.md",
] as const;

// Safe fixtures that SHOULD remain high
const SAFE_FIXTURES = [
	"test/fixtures/skills/safe-basic.md",
	"test/fixtures/skills/safe-complex.md",
	"test/fixtures/skills/legit-security-skill.md",
	"test/fixtures/skills/legit-curl-install.md",
	"test/fixtures/skills/evasion-negation-safe.md",
	"test/fixtures/skills/evasion-context-safe.md",
	"test/fixtures/skills/config-tampering-safe.md",
] as const;

let evasionScoreMax = 0;
let evasionScoreTotal = 0;

for (const path of EVASION_FIXTURES) {
	const content = readFileSync(path, "utf-8");
	const report = await scanSkill(content);
	if (report.overall > evasionScoreMax) evasionScoreMax = report.overall;
	evasionScoreTotal += report.overall;
	const name = path.split("/").pop()?.replace(".md", "") ?? path;

	const critCount = report.findings.filter(f => f.severity === "critical").length;
	const highCount = report.findings.filter(f => f.severity === "high").length;

	console.log(
		`EVASION ${name} | score=${report.overall} | badge=${report.badge} | crit=${critCount} high=${highCount} | findings=${report.findings.length}`,
	);
}

let safeScoreMin = 100;

for (const path of SAFE_FIXTURES) {
	const content = readFileSync(path, "utf-8");
	const report = await scanSkill(content);
	if (report.overall < safeScoreMin) safeScoreMin = report.overall;
	const name = path.split("/").pop()?.replace(".md", "") ?? path;
	console.log(`SAFE ${name} | score=${report.overall} | badge=${report.badge}`);
}

const evasionAvg = Math.round(evasionScoreTotal / EVASION_FIXTURES.length);

console.log(`METRIC evasion_score_max=${evasionScoreMax}`);
console.log(`METRIC evasion_score_avg=${evasionAvg}`);
console.log(`METRIC safe_score_min=${safeScoreMin}`);
console.log(`METRIC evasion_gap=${safeScoreMin - evasionScoreMax}`);

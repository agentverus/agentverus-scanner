/**
 * Benchmark: false positive reduction on safe skill fixtures.
 *
 * Measures medium+ findings on safe fixtures and max scores on malicious fixtures
 * to ensure we're reducing false positives without weakening detection.
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

const MEDIUM_PLUS = new Set(["medium", "high", "critical"]);

let totalSafeMediumPlus = 0;
let safeScoreMin = 100;
let safeRegressions = 0;

for (const path of SAFE_FIXTURES) {
	const content = readFileSync(path, "utf-8");
	const report = await scanSkill(content);
	const mediumPlus = report.findings.filter((f) => MEDIUM_PLUS.has(f.severity));
	totalSafeMediumPlus += mediumPlus.length;
	if (report.overall < safeScoreMin) safeScoreMin = report.overall;
	if (report.overall < 90) safeRegressions += 1;

	const name = path.split("/").pop()?.replace(".md", "") ?? path;
	console.log(
		`SAFE ${name} | score=${report.overall} | badge=${report.badge} | medium_plus=${mediumPlus.length}`,
	);
	for (const f of mediumPlus) {
		console.log(`  [${f.severity}] ${f.category}: ${f.title} (deduction=${f.deduction})`);
	}
}

let maliciousScoreMax = 0;

for (const path of MALICIOUS_FIXTURES) {
	const content = readFileSync(path, "utf-8");
	const report = await scanSkill(content);
	if (report.overall > maliciousScoreMax) maliciousScoreMax = report.overall;

	const name = path.split("/").pop()?.replace(".md", "") ?? path;
	console.log(
		`MALICIOUS ${name} | score=${report.overall} | badge=${report.badge} | findings=${report.findings.length}`,
	);
}

console.log(`METRIC safe_fixture_medium_plus=${totalSafeMediumPlus}`);
console.log(`METRIC safe_fixture_score_min=${safeScoreMin}`);
console.log(`METRIC malicious_score_max=${maliciousScoreMax}`);
console.log(`METRIC safe_fixture_regressions=${safeRegressions}`);

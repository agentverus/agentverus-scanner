/**
 * Benchmark: score calibration for public corpus skills.
 *
 * Primary metric: public_over_rejected — number of public corpus skills with
 * 0 critical findings that are still "rejected". Lower is better.
 *
 * These are legitimate tools being over-penalized by the severity penalty
 * treating contract-mismatch highs the same as active-threat highs.
 */
import { scanSkill } from "../src/scanner/index.js";
import { readFileSync } from "node:fs";

const PUBLIC_CORPUS = readFileSync("benchmarks/public-skill-corpus.txt", "utf-8")
	.split("\n")
	.filter(Boolean);

const SAFE_FIXTURES = [
	"test/fixtures/skills/safe-basic.md",
	"test/fixtures/skills/safe-complex.md",
	"test/fixtures/skills/legit-security-skill.md",
	"test/fixtures/skills/legit-curl-install.md",
	"test/fixtures/skills/evasion-negation-safe.md",
	"test/fixtures/skills/evasion-context-safe.md",
	"test/fixtures/skills/config-tampering-safe.md",
] as const;

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

// Scan public corpus
let publicOverRejected = 0;
let publicScoreTotal = 0;

for (const url of PUBLIC_CORPUS) {
	const name = url.split("/").slice(-2).join("/").replace("/SKILL.md", "");
	// Use cached content from previous benchmark runs
	let content: string;
	try {
		const resp = await fetch(url);
		content = await resp.text();
	} catch {
		console.log(`SKIP ${name} (fetch failed)`);
		continue;
	}
	const report = await scanSkill(content);
	const critCount = report.findings.filter(f => f.severity === "critical").length;
	const highCount = report.findings.filter(f => f.severity === "high").length;
	const contractHighCount = report.findings.filter(
		f => f.severity === "high" && f.id.startsWith("PERM-CONTRACT-MISSING-"),
	).length;
	const activeHighCount = highCount - contractHighCount;

	publicScoreTotal += report.overall;

	if (critCount === 0 && report.badge === "rejected") {
		publicOverRejected++;
	}

	console.log(
		`PUBLIC ${name} | score=${report.overall} | badge=${report.badge} | crit=${critCount} activeHigh=${activeHighCount} contractHigh=${contractHighCount}`,
	);
}

// Verify safe fixtures
let safeScoreMin = 100;
for (const path of SAFE_FIXTURES) {
	const content = readFileSync(path, "utf-8");
	const report = await scanSkill(content);
	if (report.overall < safeScoreMin) safeScoreMin = report.overall;
}

// Verify evasion fixtures  
let evasionScoreMax = 0;
for (const path of EVASION_FIXTURES) {
	const content = readFileSync(path, "utf-8");
	const report = await scanSkill(content);
	if (report.overall > evasionScoreMax) evasionScoreMax = report.overall;
}

const publicAvg = Math.round(publicScoreTotal / PUBLIC_CORPUS.length);

console.log(`METRIC public_over_rejected=${publicOverRejected}`);
console.log(`METRIC public_score_avg=${publicAvg}`);
console.log(`METRIC safe_score_min=${safeScoreMin}`);
console.log(`METRIC evasion_score_max=${evasionScoreMax}`);

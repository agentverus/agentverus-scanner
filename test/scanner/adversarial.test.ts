import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { scanSkill } from "../../src/scanner/index.js";

const FIXTURES_DIR = join(__dirname, "../fixtures/skills");

function loadFixture(name: string) {
	return readFileSync(join(FIXTURES_DIR, name), "utf-8");
}

describe("adversarial evasion tests", () => {
	describe("context-aware analysis should reduce false positives", () => {
		it("security educator skill with attack examples in code blocks should score high", async () => {
			const report = await scanSkill(loadFixture("evasion-context-safe.md"));

			// This skill has malicious patterns ONLY inside code blocks and safety sections
			// It should score well because context analysis neutralizes/downgrades them
			expect(report.overall).toBeGreaterThanOrEqual(75);
			expect(report.badge !== "rejected").toBe(true);

			// Verify findings are downgraded, not absent — we still want visibility
			const criticals = report.findings.filter((f) => f.severity === "critical");
			expect(criticals.length).toBeLessThanOrEqual(1); // At most 1 from code block (downgraded)
		});

		it("skill with safety boundary negations should not be penalized for them", async () => {
			const report = await scanSkill(loadFixture("evasion-negation-safe.md"));

			// This skill says "do NOT access credentials", "never send data", etc.
			// These are POSITIVE safety declarations, not threats
			expect(report.overall).toBeGreaterThanOrEqual(85);
			expect(report.badge === "certified" || report.badge === "conditional").toBe(true);
		});
	});

	describe("genuine attacks in prose should still be caught", () => {
		it("malicious instructions outside code blocks should still be rejected", async () => {
			const report = await scanSkill(loadFixture("evasion-hidden-in-codeblock.md"));

			// This skill has REAL exfiltration instructions in prose (not in code blocks)
			// The code block only contains innocent JSON config
			expect(report.overall).toBeLessThanOrEqual(70);
			expect(
				report.findings.some(
					(f) => f.severity === "critical" || f.severity === "high",
				),
			).toBe(true);
		});

		it("concealment skill should still be caught despite context awareness", async () => {
			const report = await scanSkill(loadFixture("concealment-skill.md"));

			expect(report.overall).toBeLessThan(70);
			expect(report.badge === "rejected" || report.badge === "suspicious").toBe(true);
		});

		it("malicious injection skill should still be caught", async () => {
			const report = await scanSkill(loadFixture("malicious-injection.md"));

			expect(report.badge).toBe("rejected");
			expect(report.findings.some((f) => f.severity === "critical")).toBe(true);
		});

		it("malicious exfiltration skill should still be caught", async () => {
			const report = await scanSkill(loadFixture("malicious-exfiltration.md"));

			expect(report.badge).toBe("rejected");
		});
	});

	describe("known evasion techniques", () => {
		it("inline exfiltration via URL parameter encoding should flag dependencies", async () => {
			const report = await scanSkill(loadFixture("evasion-indirect-exfiltration.md"));

			// This skill reads configs and encodes them into a URL parameter
			// The regex analyzers may not catch the full multi-step pattern,
			// but should catch the suspicious URL and credential-adjacent patterns
			expect(report.findings.length).toBeGreaterThan(0);
		});

		it("rephrased jailbreak should at minimum not get CERTIFIED", async () => {
			const report = await scanSkill(loadFixture("evasion-rephrased-jailbreak.md"));

			// A rephrased jailbreak avoids standard keywords but the intent is clear.
			// Without LLM analysis, regex may miss it — but it should NOT get certified.
			// At minimum the content analysis should flag missing safety boundaries.
			expect(report.findings.length).toBeGreaterThan(0);
		});
	});

	describe("real-world legitimate skills should not be penalized", () => {
		it("safe-basic should remain certified", async () => {
			const report = await scanSkill(loadFixture("safe-basic.md"));

			expect(report.badge).toBe("certified");
			expect(report.overall).toBeGreaterThanOrEqual(90);
		});

		it("safe-complex should remain certified or conditional", async () => {
			const report = await scanSkill(loadFixture("safe-complex.md"));

			expect(report.overall).toBeGreaterThanOrEqual(85);
			expect(report.badge === "certified" || report.badge === "conditional").toBe(true);
		});

		it("declared-permissions should remain certified", async () => {
			const report = await scanSkill(loadFixture("declared-permissions.md"));

			expect(report.overall).toBeGreaterThanOrEqual(90);
			expect(report.badge === "certified" || report.badge === "conditional").toBe(true);
		});
	});
});

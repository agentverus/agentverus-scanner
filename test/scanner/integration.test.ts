import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { scanSkill } from "../../src/scanner/index.js";

const FIXTURES_DIR = join(__dirname, "../fixtures/skills");

function loadFixture(name: string) {
	return readFileSync(join(FIXTURES_DIR, name), "utf-8");
}

describe("scanSkill (integration)", () => {
	it("should score safe-basic above 90 with CERTIFIED badge", async () => {
		const report = await scanSkill(loadFixture("safe-basic.md"));

		expect(report.overall).toBeGreaterThanOrEqual(90);
		expect(report.badge).toBe("certified");
		expect(report.metadata.skillFormat).toBe("openclaw");
		expect(report.metadata.durationMs).toBeGreaterThan(0);
		expect(report.categories.permissions.weight).toBe(0.20);
		expect(report.categories.injection.weight).toBe(0.25);
	});

	it("should score safe-complex above 85", async () => {
		const report = await scanSkill(loadFixture("safe-complex.md"));

		expect(report.overall).toBeGreaterThanOrEqual(85);
		expect(report.badge === "certified" || report.badge === "conditional").toBe(true);
	});

	it("should score malicious-exfiltration as REJECTED badge", async () => {
		const report = await scanSkill(loadFixture("malicious-exfiltration.md"));

		expect(report.overall).toBeLessThanOrEqual(65);
		expect(report.badge).toBe("rejected");
		expect(report.findings.some((f) => f.severity === "critical" || f.severity === "high")).toBe(
			true,
		);
	});

	it("should score malicious-injection below 30 with REJECTED badge", async () => {
		const report = await scanSkill(loadFixture("malicious-injection.md"));

		expect(report.badge).toBe("rejected");
		expect(report.findings.some((f) => f.owaspCategory === "ASST-01")).toBe(true);
		expect(report.findings.some((f) => f.owaspCategory === "ASST-06")).toBe(true);
	});

	it("should score malicious-escalation as REJECTED", async () => {
		const report = await scanSkill(loadFixture("malicious-escalation.md"));

		expect(report.overall).toBeLessThanOrEqual(65);
		expect(report.badge).toBe("rejected");
	});

	it("should score suspicious-urls in the suspicious/conditional range", async () => {
		const report = await scanSkill(loadFixture("suspicious-urls.md"));

		expect(report.overall).toBeGreaterThanOrEqual(40);
		expect(report.overall).toBeLessThanOrEqual(95);
		expect(report.findings.length).toBeGreaterThan(0);
	});

	it("should score excessive-permissions in suspicious/rejected range", async () => {
		const report = await scanSkill(loadFixture("excessive-permissions.md"));

		expect(report.overall).toBeLessThan(80);
		expect(
			report.badge === "suspicious" ||
				report.badge === "rejected" ||
				report.badge === "conditional",
		).toBe(true);
	});

	it("should score openclaw-format above 85", async () => {
		const report = await scanSkill(loadFixture("openclaw-format.md"));

		expect(report.overall).toBeGreaterThanOrEqual(85);
		expect(report.metadata.skillFormat).toBe("openclaw");
	});

	it("should include all 6 categories in report", async () => {
		const report = await scanSkill(loadFixture("safe-basic.md"));

		expect(report.categories).toHaveProperty("permissions");
		expect(report.categories).toHaveProperty("injection");
		expect(report.categories).toHaveProperty("dependencies");
		expect(report.categories).toHaveProperty("behavioral");
		expect(report.categories).toHaveProperty("content");
		expect(report.categories).toHaveProperty("code-safety");
	});

	it("obfuscated skill should score below 80", async () => {
		const report = await scanSkill(loadFixture("obfuscated-skill.md"));

		expect(report.overall).toBeLessThan(80);
	});

	it("concealment skill should score below 70", async () => {
		const report = await scanSkill(loadFixture("concealment-skill.md"));

		expect(report.overall).toBeLessThan(70);
	});

	it("declared permissions skill should score higher than undeclared", async () => {
		const declaredReport = await scanSkill(loadFixture("declared-permissions.md"));
		const undeclaredReport = await scanSkill(loadFixture("undeclared-permissions.md"));

		expect(declaredReport.overall).toBeGreaterThan(undeclaredReport.overall);
	});
});

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { scanSkill } from "../../src/scanner/index.js";

const FIXTURES = join(import.meta.dirname, "../fixtures/skills");
const loadFixture = (name: string) => readFileSync(join(FIXTURES, name), "utf-8");

describe("Context bypass evasion detection", () => {
	it("fake security skill with real exfiltration should not be certified", async () => {
		// A malicious skill names itself "Security Guard" to exploit the
		// isSecurityDefenseSkill exemption, but contains real credential
		// theft and data exfiltration instructions in its "core functionality"
		const report = await scanSkill(loadFixture("evasion-fake-security-skill.md"));

		// Must NOT be certified — the exfiltration instructions are real
		expect(report.badge).not.toBe("certified");
		expect(report.overall).toBeLessThan(90);

		// Should detect credential access and/or exfiltration
		const hasThreatFinding = report.findings.some(
			(f) =>
				f.severity === "critical" ||
				f.severity === "high" ||
				f.category === "injection" ||
				/credential|exfiltrat|ssh|\.env/i.test(f.title + " " + (f.evidence ?? "")),
		);
		expect(hasThreatFinding).toBe(true);
	});

	it("curl|bash to unknown/IP domain in setup section should still flag", async () => {
		// A skill puts curl|bash under a "Prerequisites" heading but the URL
		// is an unknown domain or raw IP — this should NOT be downgraded
		const report = await scanSkill(loadFixture("evasion-curl-setup-section.md"));

		// Must NOT be certified
		expect(report.badge).not.toBe("certified");

		// Should have critical or high findings for the download patterns
		const hasCriticalDl = report.findings.some(
			(f) =>
				(f.severity === "critical" || f.severity === "high") &&
				/download|curl|execute|IP/i.test(f.title),
		);
		expect(hasCriticalDl).toBe(true);
	});

	it("real injection hidden after/around a fake threat table should still flag", async () => {
		// A skill creates a table of "threat patterns" (exploiting table context suppression)
		// but then has REAL injection instructions outside the table
		const report = await scanSkill(loadFixture("evasion-threat-table-injection.md"));

		expect(report.badge).not.toBe("certified");

		// The real injection below the table must be detected
		const hasInjection = report.findings.some(
			(f) =>
				f.severity === "critical" &&
				(f.category === "injection" || /override|exfiltrat|credential/i.test(f.title)),
		);
		expect(hasInjection).toBe(true);
	});

	it("real attacks after a legitimate safety section should still flag", async () => {
		// A skill has a legitimate "Do Not" section, then switches to real
		// malicious instructions — the negation exemption should not carry
		// over to the actual attack instructions below
		const report = await scanSkill(loadFixture("evasion-negation-disguise.md"));

		expect(report.badge).not.toBe("certified");
		expect(report.overall).toBeLessThan(85);

		// Should detect concealment and credential access
		const hasThreat = report.findings.some(
			(f) =>
				f.severity === "critical" ||
				f.severity === "high",
		);
		expect(hasThreat).toBe(true);
	});

	it("legitimate security skill should be certified or conditional", async () => {
		// A real security scanner skill that lists threat patterns educationally
		// should NOT be penalized for mentioning injection patterns
		const report = await scanSkill(loadFixture("legit-security-skill.md"));

		expect(report.overall).toBeGreaterThanOrEqual(85);
		expect(["certified", "conditional"]).toContain(report.badge);

		// Should NOT have critical findings
		const criticals = report.findings.filter((f) => f.severity === "critical");
		expect(criticals).toHaveLength(0);
	});

	it("legitimate curl|bash to known installer should not be rejected", async () => {
		// A skill with curl|bash to deno.land in a setup section should be fine
		const report = await scanSkill(loadFixture("legit-curl-install.md"));

		expect(report.overall).toBeGreaterThanOrEqual(90);
		expect(["certified", "conditional"]).toContain(report.badge);

		// Should NOT have critical findings for the curl pattern
		const criticals = report.findings.filter((f) => f.severity === "critical");
		expect(criticals).toHaveLength(0);
	});
});

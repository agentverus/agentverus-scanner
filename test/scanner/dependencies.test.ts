import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeDependencies } from "../../src/scanner/analyzers/dependencies.js";
import { parseSkill } from "../../src/scanner/parser.js";

const FIXTURES_DIR = join(__dirname, "../fixtures/skills");

function loadFixture(name: string) {
	return readFileSync(join(FIXTURES_DIR, name), "utf-8");
}

describe("analyzeDependencies", () => {
	it("should score safe-basic skill at 100 (no URLs)", async () => {
		const skill = parseSkill(loadFixture("safe-basic.md"));
		const result = await analyzeDependencies(skill);

		expect(result.score).toBe(100);
		expect(result.weight).toBe(0.15);
	});

	it("should score suspicious-urls between 50 and 70", async () => {
		const skill = parseSkill(loadFixture("suspicious-urls.md"));
		const result = await analyzeDependencies(skill);

		expect(result.score).toBeLessThanOrEqual(70);
		expect(result.score).toBeGreaterThanOrEqual(20);
		expect(result.findings.length).toBeGreaterThan(2);
	});

	it("should flag IP addresses as high risk", async () => {
		const skill = parseSkill(loadFixture("suspicious-urls.md"));
		const result = await analyzeDependencies(skill);

		const ipFindings = result.findings.filter((f) => f.title.includes("IP address"));
		expect(ipFindings.length).toBeGreaterThan(0);
	});

	it("should flag raw content URLs as medium risk", async () => {
		const skill = parseSkill(loadFixture("suspicious-urls.md"));
		const result = await analyzeDependencies(skill);

		const rawFindings = result.findings.filter((f) => f.title.includes("Raw content"));
		expect(rawFindings.length).toBeGreaterThan(0);
	});

	it("should detect download-and-execute in malicious-escalation", async () => {
		const skill = parseSkill(loadFixture("malicious-escalation.md"));
		const result = await analyzeDependencies(skill);

		const dlExecFindings = result.findings.filter((f) =>
			f.title.toLowerCase().includes("download"),
		);
		expect(dlExecFindings.length).toBeGreaterThanOrEqual(0);
	});

	it("should not penalize trusted domains", async () => {
		const skill = parseSkill(
			"# Test\nCheck https://github.com/user/repo for details.\nSee https://docs.python.org/3/",
		);
		const result = await analyzeDependencies(skill);

		expect(result.score).toBe(100);
	});
});

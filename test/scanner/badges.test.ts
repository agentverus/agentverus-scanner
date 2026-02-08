import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import {
	buildRepoCertifiedEndpoint,
	buildRepoCertifiedPercentEndpoint,
	buildSkillBadgeEndpoint,
	slugForTarget,
} from "../../src/scanner/badges.js";
import { scanSkill } from "../../src/scanner/index.js";

const FIXTURES_DIR = join(__dirname, "../fixtures/skills");

function loadFixture(name: string) {
	return readFileSync(join(FIXTURES_DIR, name), "utf-8");
}

describe("badges", () => {
	it("should generate CERTIFIED repo badge only when all skills are certified", async () => {
		const safe = await scanSkill(loadFixture("safe-basic.md"));
		const reports = [{ target: "skills/safe/SKILL.md", report: safe }];

		const repoCertified = buildRepoCertifiedEndpoint(reports, []);
		expect(repoCertified.message).toBe("CERTIFIED");
		expect(repoCertified.color).toBe("brightgreen");

		const repoPct = buildRepoCertifiedPercentEndpoint(reports, []);
		expect(repoPct.message).toBe("Certified 100%");
		expect(repoPct.color).toBe("brightgreen");
	});

	it("should mark repo NOT CERTIFIED and compute percent when some skills are not certified", async () => {
		const safe = await scanSkill(loadFixture("safe-basic.md"));
		const bad = await scanSkill(loadFixture("malicious-injection.md"));

		const reports = [
			{ target: "skills/good/SKILL.md", report: safe },
			{ target: "skills/bad/SKILL.md", report: bad },
		];

		const repoCertified = buildRepoCertifiedEndpoint(reports, []);
		expect(repoCertified.message).toBe("NOT CERTIFIED");
		expect(repoCertified.color).toBe("red");

		const repoPct = buildRepoCertifiedPercentEndpoint(reports, []);
		expect(repoPct.message).toBe("Certified 50%");	// 1/2
		expect(repoPct.color).toBe("yellow");
	});

	it("should show Scan failed for repo percent badge when failures exist", async () => {
		const safe = await scanSkill(loadFixture("safe-basic.md"));
		const reports = [{ target: "skills/safe/SKILL.md", report: safe }];

		const repoPct = buildRepoCertifiedPercentEndpoint(reports, [
			{ target: "skills/unknown/SKILL.md", error: "boom" },
		]);
		expect(repoPct.message).toBe("Scan failed");
		expect(repoPct.color).toBe("red");
	});

	it("should generate per-skill endpoint badge", async () => {
		const safe = await scanSkill(loadFixture("safe-basic.md"));
		const ep = buildSkillBadgeEndpoint({ target: "skills/safe/SKILL.md", report: safe });
		expect(ep.label).toBe("AgentVerus");
		expect(ep.message.startsWith("CERTIFIED")).toBe(true);
	});

	it("should slugify targets in a stable way", () => {
		expect(slugForTarget("skills/web-search/SKILL.md")).toBe("skills__web-search__SKILL.md");
		expect(slugForTarget("skills\\web-search\\SKILL.md")).toBe("skills__web-search__SKILL.md");
	});
});

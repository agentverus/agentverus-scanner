import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

beforeEach(() => {
	vi.resetModules();
});

afterEach(() => {
	vi.unstubAllGlobals();
	vi.restoreAllMocks();
});

describe("skills.sh parsing", () => {
	it("should parse initialSkills entries from HTML", async () => {
		const html = `
			<html><body>
				<script>
					window.__DATA__ = { initialSkills: [
						{source:'octo/repo', skillId:'skill-a', installs:12345},
						{source:'octo/repo', skillId:'skill-b', installs:10},
						{source:"other/repo", skillId:"s", installs:500}
					]};
				</script>
			</body></html>
		`;

		const fetchMock = vi.fn(async () => new Response(html, { status: 200 }));
		vi.stubGlobal("fetch", fetchMock);

		const mod = await import("../../src/adoption/skills-sh.js");
		const data = await mod.fetchSkillsShData();

		expect(data).toHaveLength(3);
		expect(data[0]?.source).toBe("octo/repo");
		expect(data[0]?.skillId).toBe("skill-a");
		expect(data[0]?.installs).toBe(12345);
	});

	it("should lookup installs by owner/repo/skillId (case-insensitive)", async () => {
		const html = `
			<script>
				const initialSkills = [
					{source:'octo/repo', skillId:'My-Skill', installs:42}
				];
			</script>
		`;

		vi.stubGlobal("fetch", vi.fn(async () => new Response(html, { status: 200 })));

		const { lookupInstalls } = await import("../../src/adoption/skills-sh.js");
		const installs = await lookupInstalls("OCTO", "REPO", "my-skill");
		expect(installs).toBe(42);
	});

	it("should cache results in memory (only one network fetch)", async () => {
		const html = `
			<script>
				const initialSkills = [
					{source:'octo/repo', skillId:'skill-a', installs:1}
				];
			</script>
		`;

		const fetchMock = vi.fn(async () => new Response(html, { status: 200 }));
		vi.stubGlobal("fetch", fetchMock);

		const { fetchSkillsShData } = await import("../../src/adoption/skills-sh.js");
		await fetchSkillsShData();
		await fetchSkillsShData();

		expect(fetchMock).toHaveBeenCalledTimes(1);
	});

	it("should return empty data when initialSkills is missing", async () => {
		const html = "<html><body><script>console.log('no skills');</script></body></html>";
		vi.stubGlobal("fetch", vi.fn(async () => new Response(html, { status: 200 })));

		const { fetchSkillsShData, lookupInstalls } = await import(
			"../../src/adoption/skills-sh.js"
		);

		const data = await fetchSkillsShData();
		expect(data).toEqual([]);

		const installs = await lookupInstalls("octo", "repo", "skill-a");
		expect(installs).toBe(0);
	});
});


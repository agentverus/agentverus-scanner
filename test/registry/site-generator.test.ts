import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { generateSite } from "../../src/registry/site-generator.js";
import type { RegistryScanResult, RegistryScanSummary } from "../../src/registry/types.js";

const tmpDirs: string[] = [];

function tmpDir(): string {
	const dir = path.join(os.tmpdir(), `av-site-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
	tmpDirs.push(dir);
	return dir;
}

afterEach(async () => {
	for (const dir of tmpDirs) {
		await rm(dir, { recursive: true, force: true }).catch(() => {});
	}
	tmpDirs.length = 0;
});

describe("generateSite", () => {
	it("generates an HTML dashboard from scan data", async () => {
		const dataDir = tmpDir();
		const outDir = tmpDir();
		await mkdir(dataDir, { recursive: true });

		const results: RegistryScanResult[] = [
			{
				slug: "test-skill",
				version: "1.0.0",
				url: "https://example.com",
				score: 92,
				badge: "certified",
				format: "openclaw",
				name: "Test Skill",
				categories: {
					permissions: { score: 100, weight: 0.25, findingCount: 0 },
					injection: { score: 100, weight: 0.3, findingCount: 0 },
					dependencies: { score: 85, weight: 0.2, findingCount: 1 },
					behavioral: { score: 80, weight: 0.15, findingCount: 0 },
					content: { score: 85, weight: 0.1, findingCount: 0 },
				},
				findings: [],
				durationMs: 5,
				scannedAt: new Date().toISOString(),
			},
		];

		const summary: RegistryScanSummary = {
			totalSkills: 1,
			scanned: 1,
			failed: 0,
			badges: { certified: 1, conditional: 0, suspicious: 0, rejected: 0 },
			averageScore: 92,
			medianScore: 92,
			scoreDistribution: { "0-19": 0, "20-39": 0, "40-59": 0, "60-79": 0, "80-89": 0, "90-100": 1 },
			topFindings: [],
			vtGapSkills: [],
			scannerVersion: "0.1.0",
			scannedAt: new Date().toISOString(),
			totalDurationMs: 100,
			concurrency: 1,
		};

		await writeFile(path.join(dataDir, "results.json"), JSON.stringify(results));
		await writeFile(path.join(dataDir, "summary.json"), JSON.stringify(summary));
		await writeFile(path.join(dataDir, "results.csv"), "slug,score\ntest-skill,92");
		await writeFile(path.join(dataDir, "errors.json"), "[]");

		await generateSite({ dataDir, outDir, title: "Test Dashboard" });

		// Check HTML was generated
		const html = await readFile(path.join(outDir, "index.html"), "utf-8");
		expect(html).toContain("<!DOCTYPE html>");
		expect(html).toContain("Test Dashboard");
		expect(html).toContain("test-skill");
		expect(html).toContain("AgentVerus Scanner");

		// Check data files were copied
		const copiedResults = await readFile(path.join(outDir, "data", "results.json"), "utf-8");
		expect(JSON.parse(copiedResults)).toHaveLength(1);
	});

	it("uses default title when none provided", async () => {
		const dataDir = tmpDir();
		const outDir = tmpDir();
		await mkdir(dataDir, { recursive: true });

		await writeFile(path.join(dataDir, "results.json"), "[]");
		await writeFile(path.join(dataDir, "summary.json"), JSON.stringify({
			totalSkills: 0, scanned: 0, failed: 0,
			badges: { certified: 0, conditional: 0, suspicious: 0, rejected: 0 },
			averageScore: 0, medianScore: 0,
			scoreDistribution: {},
			topFindings: [], vtGapSkills: [],
			scannerVersion: "0.1.0", scannedAt: new Date().toISOString(),
			totalDurationMs: 0, concurrency: 1,
		}));

		await generateSite({ dataDir, outDir });

		const html = await readFile(path.join(outDir, "index.html"), "utf-8");
		expect(html).toContain("AgentVerus Registry Report");
	});
});

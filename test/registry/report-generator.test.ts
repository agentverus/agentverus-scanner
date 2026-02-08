import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { generateAnalysisReport } from "../../src/registry/report-generator.js";
import type { RegistryScanResult, RegistryScanSummary, RegistryScanError } from "../../src/registry/types.js";

const tmpDirs: string[] = [];

function tmpDir(): string {
	const dir = path.join(os.tmpdir(), `av-report-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
	tmpDirs.push(dir);
	return dir;
}

afterEach(async () => {
	for (const dir of tmpDirs) {
		await rm(dir, { recursive: true, force: true }).catch(() => {});
	}
	tmpDirs.length = 0;
});

function makeMockData(): { results: RegistryScanResult[]; summary: RegistryScanSummary; errors: RegistryScanError[] } {
	const results: RegistryScanResult[] = [
		{
			slug: "good-skill",
			version: "1.0.0",
			url: "https://example.com/good",
			score: 95,
			badge: "certified",
			format: "openclaw",
			name: "Good Skill",
			categories: {
				permissions: { score: 100, weight: 0.25, findingCount: 0 },
				injection: { score: 100, weight: 0.3, findingCount: 0 },
				dependencies: { score: 85, weight: 0.2, findingCount: 1 },
				behavioral: { score: 90, weight: 0.15, findingCount: 1 },
				content: { score: 90, weight: 0.1, findingCount: 0 },
			},
			findings: [],
			durationMs: 5,
			scannedAt: new Date().toISOString(),
		},
		{
			slug: "bad-skill",
			version: "0.1.0",
			url: "https://example.com/bad",
			score: 35,
			badge: "rejected",
			format: "generic",
			name: "Bad Skill",
			categories: {
				permissions: { score: 50, weight: 0.25, findingCount: 2 },
				injection: { score: 20, weight: 0.3, findingCount: 3 },
				dependencies: { score: 30, weight: 0.2, findingCount: 2 },
				behavioral: { score: 40, weight: 0.15, findingCount: 1 },
				content: { score: 50, weight: 0.1, findingCount: 1 },
			},
			findings: [
				{
					id: "INJ-1",
					severity: "critical",
					title: "Direct instruction override",
					category: "injection",
					owaspCategory: "ASST-01",
				},
			],
			durationMs: 3,
			scannedAt: new Date().toISOString(),
		},
	];

	const summary: RegistryScanSummary = {
		totalSkills: 2,
		scanned: 2,
		failed: 0,
		badges: { certified: 1, conditional: 0, suspicious: 0, rejected: 1 },
		averageScore: 65,
		medianScore: 65,
		scoreDistribution: { "0-19": 0, "20-39": 1, "40-59": 0, "60-79": 0, "80-89": 0, "90-100": 1 },
		topFindings: [{ id: "INJ-1", title: "Direct instruction override", count: 1 }],
		vtGapSkills: ["bad-skill"],
		scannerVersion: "0.1.0",
		scannedAt: new Date().toISOString(),
		totalDurationMs: 500,
		concurrency: 1,
	};

	return { results, summary, errors: [] };
}

describe("generateAnalysisReport", () => {
	it("generates a markdown report from scan data", async () => {
		const dataDir = tmpDir();
		const outDir = tmpDir();
		await mkdir(dataDir, { recursive: true });

		const { results, summary, errors } = makeMockData();
		await writeFile(path.join(dataDir, "results.json"), JSON.stringify(results));
		await writeFile(path.join(dataDir, "summary.json"), JSON.stringify(summary));
		await writeFile(path.join(dataDir, "errors.json"), JSON.stringify(errors));

		const report = await generateAnalysisReport({ dataDir, outDir });

		// Check content
		expect(report).toContain("We Analyzed 2 AI Agent Skills");
		expect(report).toContain("CERTIFIED");
		expect(report).toContain("REJECTED");
		expect(report).toContain("bad-skill");
		expect(report).toContain("good-skill");
		expect(report).toContain("VirusTotal");
		expect(report).toContain("Methodology");

		// Check file was written
		const written = await readFile(path.join(outDir, "REPORT.md"), "utf-8");
		expect(written).toBe(report);
	});

	it("includes VT gap skills in the report", async () => {
		const dataDir = tmpDir();
		const outDir = tmpDir();
		await mkdir(dataDir, { recursive: true });

		const { results, summary, errors } = makeMockData();
		await writeFile(path.join(dataDir, "results.json"), JSON.stringify(results));
		await writeFile(path.join(dataDir, "summary.json"), JSON.stringify(summary));
		await writeFile(path.join(dataDir, "errors.json"), JSON.stringify(errors));

		const report = await generateAnalysisReport({ dataDir, outDir });

		expect(report).toContain("VT Blind Spots");
		expect(report).toContain("bad-skill");
	});
});

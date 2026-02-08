import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { batchScanRegistry } from "../../src/registry/batch-scanner.js";
import { SCANNER_VERSION } from "../../src/scanner/types.js";

const tmpDirs: string[] = [];

function tmpDir(): string {
	const dir = path.join(os.tmpdir(), `av-batch-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
	tmpDirs.push(dir);
	return dir;
}

const SAMPLE_SKILL_MD = `# Sample Skill

This is a test skill used by the batch scanner tests.

## Tools
- none

`;

function makeDataSkillUrl(slug: string, markdown: string): string {
	// Note: query params are included in the fetched body for data: URLs in Node.
	// That is OK for these tests; we only need a stable, offline source.
	const encoded = encodeURIComponent(markdown);
	return `data:text/markdown,${encoded}?slug=${encodeURIComponent(slug)}`;
}

async function writeTestUrlFile(filePath: string, count: number): Promise<void> {
	const urls: string[] = [];
	for (let i = 1; i <= count; i += 1) {
		urls.push(makeDataSkillUrl(`skill-${i}`, SAMPLE_SKILL_MD));
	}
	await writeFile(filePath, urls.join("\n") + "\n", "utf-8");
}

afterEach(async () => {
	for (const dir of tmpDirs) {
		await rm(dir, { recursive: true, force: true }).catch(() => {});
	}
	tmpDirs.length = 0;
});

describe("batchScanRegistry", () => {
	it("scans skills from a URL file and produces output files", async () => {
		const outDir = tmpDir();
		await mkdir(outDir, { recursive: true });
		const urlFile = path.join(outDir, "skill-urls.txt");
		await writeTestUrlFile(urlFile, 10);

		const summary = await batchScanRegistry({
			urlFile,
			outDir,
			limit: 3,
			concurrency: 3,
			timeout: 45_000,
			retries: 1,
			retryDelayMs: 500,
		});

		expect(summary.totalSkills).toBe(3);
		expect(summary.scanned).toBeGreaterThanOrEqual(2);
		expect(summary.scannerVersion).toBe(SCANNER_VERSION);
		expect(summary.badges).toBeDefined();
		expect(summary.averageScore).toBeGreaterThanOrEqual(0);
		expect(summary.averageScore).toBeLessThanOrEqual(100);

		// Check output files exist
		const resultsJson = await readFile(path.join(outDir, "results.json"), "utf-8");
		const results = JSON.parse(resultsJson);
		expect(Array.isArray(results)).toBe(true);
		expect(results.length).toBeGreaterThanOrEqual(2);

		// Check CSV
		const csv = await readFile(path.join(outDir, "results.csv"), "utf-8");
		const lines = csv.split("\n");
		expect(lines[0]).toContain("slug,version,score,badge");
		expect(lines.length).toBeGreaterThanOrEqual(3); // header + 2+ results

		// Check summary
		const summaryJson = await readFile(path.join(outDir, "summary.json"), "utf-8");
		const parsedSummary = JSON.parse(summaryJson);
		expect(parsedSummary.totalSkills).toBe(3);

		// Check errors file
		const errorsJson = await readFile(path.join(outDir, "errors.json"), "utf-8");
		const errors = JSON.parse(errorsJson);
		expect(Array.isArray(errors)).toBe(true);

		// Check result structure
		const first = results[0];
		expect(first).toHaveProperty("slug");
		expect(first).toHaveProperty("score");
		expect(first).toHaveProperty("badge");
		expect(first).toHaveProperty("categories");
		expect(first).toHaveProperty("findings");
	}, 60_000);

	it("reports progress and errors via callbacks", async () => {
		const outDir = tmpDir();
		await mkdir(outDir, { recursive: true });
		const urlFile = path.join(outDir, "skill-urls.txt");
		await writeTestUrlFile(urlFile, 10);

		const progressCalls: { done: number; slug: string }[] = [];

		await batchScanRegistry({
			urlFile,
			outDir,
			limit: 2,
			concurrency: 2,
			timeout: 45_000,
			retries: 1,
			retryDelayMs: 500,
			onProgress: (done, _total, slug) => {
				progressCalls.push({ done, slug });
			},
		});

		expect(progressCalls.length).toBeGreaterThanOrEqual(2);
		expect(progressCalls.some((p) => p.done === 1)).toBe(true);
		expect(progressCalls.some((p) => p.done === 2)).toBe(true);
	}, 60_000);

	it("computes correct badge distribution", async () => {
		const outDir = tmpDir();
		await mkdir(outDir, { recursive: true });
		const urlFile = path.join(outDir, "skill-urls.txt");
		await writeTestUrlFile(urlFile, 10);

		const summary = await batchScanRegistry({
			urlFile,
			outDir,
			limit: 5,
			concurrency: 5,
			timeout: 45_000,
			retries: 1,
			retryDelayMs: 500,
		});

		const totalBadges = Object.values(summary.badges).reduce((a, b) => a + b, 0);
		expect(totalBadges).toBe(summary.scanned);
	}, 60_000);
});

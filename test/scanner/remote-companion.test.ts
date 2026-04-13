import { readdir, readFile } from "node:fs/promises";
import { join, relative } from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { zipSync, strToU8 } from "fflate";

import { scanSkillFromUrl } from "../../src/scanner/index.js";

const PACKAGES_DIR = join(import.meta.dirname, "../fixtures/packages");

async function bundleFixture(dirName: string): Promise<Uint8Array> {
	const root = join(PACKAGES_DIR, dirName);
	const files: Record<string, Uint8Array> = {};

	async function walk(dir: string): Promise<void> {
		const entries = await readdir(dir, { withFileTypes: true });
		for (const entry of entries) {
			const full = join(dir, entry.name);
			if (entry.isDirectory()) {
				await walk(full);
				continue;
			}
			if (!entry.isFile()) continue;
			const rel = relative(root, full).replace(/\\/g, "/");
			files[`bundle/${rel}`] = strToU8(await readFile(full, "utf-8"));
		}
	}

	await walk(root);
	return zipSync(files);
}

describe("scanSkillFromUrl remote companion bundle correlation", () => {
	const savedFetch = globalThis.fetch;

	beforeEach(() => {
		vi.restoreAllMocks();
	});

	afterEach(() => {
		globalThis.fetch = savedFetch;
		vi.restoreAllMocks();
	});

	it("should flag companion findings from zipped remote bundles", async () => {
		const archive = await bundleFixture("companion-exfiltration");
		globalThis.fetch = vi.fn(async () =>
			new Response(archive, {
				status: 200,
				headers: {
					"content-type": "application/zip",
					"content-length": String(archive.length),
				},
			}),
		) as typeof fetch;

		const report = await scanSkillFromUrl("https://example.com/companion.zip", {
			retries: 0,
			timeout: 0,
		});

		expect(report.findings.some((finding) => finding.id.startsWith("COMP-CODE-SECRET-EXFIL-"))).toBe(true);
		expect(report.findings.some((finding) => finding.id.startsWith("COMP-MISMATCH-"))).toBe(true);
	});

	it("should recurse into nested companion files inside remote bundles", async () => {
		const archive = await bundleFixture("companion-bundle-nested");
		globalThis.fetch = vi.fn(async () =>
			new Response(archive, {
				status: 200,
				headers: {
					"content-type": "application/zip",
					"content-length": String(archive.length),
				},
			}),
		) as typeof fetch;

		const report = await scanSkillFromUrl("https://example.com/companion-nested.zip", {
			retries: 0,
			timeout: 0,
		});

		expect(report.findings.some((finding) => finding.id.startsWith("COMP-CODE-SECRET-EXFIL-"))).toBe(true);
		expect(report.findings.some((finding) => finding.id.startsWith("COMP-MISMATCH-"))).toBe(true);
	});

	it("should avoid remote companion false positives for documented safe auth bundles", async () => {
		const archive = await bundleFixture("companion-auth-safe");
		globalThis.fetch = vi.fn(async () =>
			new Response(archive, {
				status: 200,
				headers: {
					"content-type": "application/zip",
					"content-length": String(archive.length),
				},
			}),
		) as typeof fetch;

		const report = await scanSkillFromUrl("https://example.com/companion-safe.zip", {
			retries: 0,
			timeout: 0,
		});

		expect(report.findings.every((finding) => !finding.id.startsWith("COMP-"))).toBe(true);
	});
});

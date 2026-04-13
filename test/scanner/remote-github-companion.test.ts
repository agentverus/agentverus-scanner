import { readdir, readFile } from "node:fs/promises";
import { join, relative } from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { scanSkillFromUrl } from "../../src/scanner/index.js";

const PACKAGES_DIR = join(import.meta.dirname, "../fixtures/packages");

async function loadFixtureFiles(dirName: string): Promise<Record<string, string>> {
	const root = join(PACKAGES_DIR, dirName);
	const files: Record<string, string> = {};

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
			files[`bundle/${rel}`] = await readFile(full, "utf-8");
		}
	}

	await walk(root);
	return files;
}

function buildContentsListing(repo: string, files: Record<string, string>, dir: string): Array<Record<string, string | null>> {
	const prefix = dir ? `${dir}/` : "";
	const children = new Map<string, { type: "file" | "dir"; path: string }>();
	for (const path of Object.keys(files)) {
		if (!path.startsWith(prefix)) continue;
		const remainder = path.slice(prefix.length);
		if (!remainder) continue;
		const slash = remainder.indexOf("/");
		if (slash === -1) {
			children.set(remainder, { type: "file", path });
		} else {
			const name = remainder.slice(0, slash);
			const childPath = `${prefix}${name}`.replace(/\/$/, "");
			if (!children.has(name)) children.set(name, { type: "dir", path: childPath });
		}
	}
	return [...children.entries()].sort((a, b) => a[0].localeCompare(b[0])).map(([name, entry]) => ({
		name,
		path: entry.path,
		type: entry.type,
		download_url:
			entry.type === "file"
				? `https://raw.githubusercontent.com/example/${repo}/main/${entry.path}`
				: null,
	}));
}

function installGithubFixtureFetch(repo: string, files: Record<string, string>): void {
	globalThis.fetch = vi.fn(async (input: string | URL) => {
		const url = typeof input === "string" ? input : input.toString();
		const rawMatch = url.match(/^https:\/\/raw\.githubusercontent\.com\/example\/([^/]+)\/main\/(.+)$/);
		if (rawMatch) {
			const filePath = rawMatch[2] ?? "";
			const content = files[filePath];
			return new Response(content ?? "not found", {
				status: content ? 200 : 404,
				headers: { "content-type": "text/plain" },
			});
		}
		const apiMatch = url.match(/^https:\/\/api\.github\.com\/repos\/example\/([^/]+)\/contents(?:\/(.*))?\?ref=main$/);
		if (apiMatch) {
			const dir = apiMatch[2] ?? "";
			const body = buildContentsListing(repo, files, dir);
			return new Response(JSON.stringify(body), {
				status: 200,
				headers: { "content-type": "application/json" },
			});
		}
		return new Response("not found", { status: 404, headers: { "content-type": "text/plain" } });
	}) as typeof fetch;
}

describe("scanSkillFromUrl GitHub companion correlation", () => {
	const savedFetch = globalThis.fetch;

	beforeEach(() => {
		vi.restoreAllMocks();
	});

	afterEach(() => {
		globalThis.fetch = savedFetch;
		vi.restoreAllMocks();
	});

	it("should fetch sibling companion files for raw GitHub skill URLs", async () => {
		const files = await loadFixtureFiles("companion-exfiltration");
		installGithubFixtureFetch("repo", files);

		const report = await scanSkillFromUrl("https://raw.githubusercontent.com/example/repo/main/bundle/SKILL.md", {
			retries: 0,
			timeout: 0,
		});

		expect(report.findings.some((finding) => finding.id.startsWith("COMP-CODE-SECRET-EXFIL-"))).toBe(true);
		expect(report.findings.some((finding) => finding.id.startsWith("COMP-MISMATCH-"))).toBe(true);
	});

	it("should recurse into nested GitHub companion directories", async () => {
		const files = await loadFixtureFiles("companion-github-nested");
		installGithubFixtureFetch("repo", files);

		const report = await scanSkillFromUrl("https://raw.githubusercontent.com/example/repo/main/bundle/SKILL.md", {
			retries: 0,
			timeout: 0,
		});

		expect(report.findings.some((finding) => finding.id.startsWith("COMP-CODE-SECRET-EXFIL-"))).toBe(true);
		expect(report.findings.some((finding) => finding.id.startsWith("COMP-MISMATCH-"))).toBe(true);
	});

	it("should avoid false positives on documented safe GitHub companion auth flows", async () => {
		const files = await loadFixtureFiles("companion-auth-safe");
		installGithubFixtureFetch("repo", files);

		const report = await scanSkillFromUrl("https://raw.githubusercontent.com/example/repo/main/bundle/SKILL.md", {
			retries: 0,
			timeout: 0,
		});

		expect(report.findings.every((finding) => !finding.id.startsWith("COMP-"))).toBe(true);
	});
});

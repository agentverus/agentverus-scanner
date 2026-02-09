import { mkdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { findExecutableBinaries } from "../../src/scanner/binary.js";
import { scanTarget } from "../../src/scanner/runner.js";

const tmpDirs: string[] = [];

function tmpDir(): string {
	const dir = join(
		os.tmpdir(),
		`av-binary-test-${Date.now()}-${Math.random().toString(36).slice(2)}`,
	);
	tmpDirs.push(dir);
	return dir;
}

afterEach(async () => {
	for (const dir of tmpDirs) {
		await rm(dir, { recursive: true, force: true }).catch(() => {});
	}
	tmpDirs.length = 0;
});

const SAFE_SKILL = `---
name: clean-skill
description: A perfectly safe skill that does nothing dangerous
---

## Instructions

Just greet the user politely.

## Safety Boundaries

- Must not access the filesystem
- Must not make network requests
- Must not modify any system settings
`;

describe("findExecutableBinaries", () => {
	it("should find ELF binaries by magic bytes", async () => {
		const dir = tmpDir();
		await mkdir(dir, { recursive: true });

		// ELF magic: 0x7F 'E' 'L' 'F'
		const elfHeader = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x00, 0x00, 0x00, 0x00]);
		await writeFile(join(dir, "payload"), elfHeader);

		const results = await findExecutableBinaries(dir);
		expect(results.length).toBe(1);
		expect(results[0]).toContain("payload");
	});

	it("should find PE binaries by MZ magic", async () => {
		const dir = tmpDir();
		await mkdir(dir, { recursive: true });

		// PE magic: 'M' 'Z'
		const peHeader = Buffer.from([0x4d, 0x5a, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00]);
		await writeFile(join(dir, "trojan.exe"), peHeader);

		const results = await findExecutableBinaries(dir);
		expect(results.length).toBe(1);
	});

	it("should find files with executable extensions even without magic", async () => {
		const dir = tmpDir();
		await mkdir(dir, { recursive: true });

		await writeFile(join(dir, "lib.dll"), "not-really-a-dll");

		const results = await findExecutableBinaries(dir);
		expect(results.length).toBe(1);
	});

	it("should NOT flag normal text files", async () => {
		const dir = tmpDir();
		await mkdir(dir, { recursive: true });

		await writeFile(join(dir, "README.md"), "# Hello");
		await writeFile(join(dir, "index.js"), "console.log('hi')");

		const results = await findExecutableBinaries(dir);
		expect(results.length).toBe(0);
	});

	it("should skip .git and node_modules directories", async () => {
		const dir = tmpDir();
		const gitDir = join(dir, ".git");
		const nmDir = join(dir, "node_modules", "pkg");
		await mkdir(gitDir, { recursive: true });
		await mkdir(nmDir, { recursive: true });

		const elfHeader = Buffer.from([0x7f, 0x45, 0x4c, 0x46]);
		await writeFile(join(gitDir, "binary"), elfHeader);
		await writeFile(join(nmDir, "native.so"), elfHeader);

		const results = await findExecutableBinaries(dir);
		expect(results.length).toBe(0);
	});

	it("should respect maxResults option", async () => {
		const dir = tmpDir();
		await mkdir(dir, { recursive: true });

		const elfHeader = Buffer.from([0x7f, 0x45, 0x4c, 0x46]);
		await writeFile(join(dir, "a.bin"), elfHeader);
		await writeFile(join(dir, "b.bin"), elfHeader);
		await writeFile(join(dir, "c.bin"), elfHeader);

		const results = await findExecutableBinaries(dir, { maxResults: 2 });
		expect(results.length).toBe(2);
	});
});

describe("scanTarget with binary artifacts", () => {
	it("should add DEP-BINARY finding when ELF binary is in skill directory", async () => {
		const dir = tmpDir();
		await mkdir(dir, { recursive: true });

		const skillPath = join(dir, "SKILL.md");
		await writeFile(skillPath, SAFE_SKILL);

		const elfHeader = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x00, 0x00, 0x00, 0x00]);
		await writeFile(join(dir, "backdoor"), elfHeader);

		const { report } = await scanTarget(skillPath);

		const binaryFindings = report.findings.filter((f) => f.id.startsWith("DEP-BINARY"));
		expect(binaryFindings.length).toBe(1);
		expect(binaryFindings[0].severity).toBe("high");
		expect(binaryFindings[0].deduction).toBe(25);
	});

	it("should NOT add DEP-BINARY finding when no binaries exist", async () => {
		const dir = tmpDir();
		await mkdir(dir, { recursive: true });

		const skillPath = join(dir, "SKILL.md");
		await writeFile(skillPath, SAFE_SKILL);

		const { report } = await scanTarget(skillPath);

		const binaryFindings = report.findings.filter((f) => f.id.startsWith("DEP-BINARY"));
		expect(binaryFindings.length).toBe(0);
	});
});

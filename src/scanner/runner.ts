import { readFile } from "node:fs/promises";
import { dirname, relative } from "node:path";

import { scanSkill, scanSkillFromUrl } from "./index.js";
import { findExecutableBinaries } from "./binary.js";
import { aggregateScores } from "./scoring.js";
import type { Finding, ScanOptions, TrustReport } from "./types.js";
import { isUrlTarget } from "./targets.js";

export interface ScanTargetReport {
	readonly target: string;
	readonly report: TrustReport;
}

export interface ScanFailure {
	readonly target: string;
	readonly error: string;
}

const binaryCache = new Map<string, readonly string[]>();

async function getBinariesForDir(dir: string): Promise<readonly string[]> {
	const cached = binaryCache.get(dir);
	if (cached) return cached;
	const found = await findExecutableBinaries(dir).catch(() => [] as const);
	binaryCache.set(dir, found);
	return found;
}

function applyBinaryArtifacts(report: TrustReport, target: string, binaries: readonly string[]): TrustReport {
	if (binaries.length === 0) return report;

	const deps = report.categories.dependencies;
	const baseDir = dirname(target);
	const evidenceList = binaries
		.slice(0, 3)
		.map((p) => relative(baseDir, p))
		.join(", ");
	const evidence = evidenceList + (binaries.length > 3 ? ` (+${binaries.length - 3} more)` : "");

	const finding: Finding = {
		id: `DEP-BINARY-${binaries.length}`,
		category: "dependencies",
		severity: "high",
		title: "Executable binary artifact detected",
		description:
			"The skill directory contains executable binary files (ELF/PE/Mach-O or typical executable extensions). Binaries are opaque to review and can hide malware.",
		evidence,
		deduction: 25,
		recommendation:
			"Remove packaged binaries from the skill. Provide source code and build instructions, or pin verifiable checksums and justify why a binary is required.",
		owaspCategory: "ASST-10",
	};

	const updatedDeps: typeof deps = {
		...deps,
		score: Math.max(0, deps.score - finding.deduction),
		findings: [...deps.findings, finding],
		summary: `${deps.summary} Executable binary artifact(s) detected: ${binaries.length}.`,
	};

	const updatedCategories = {
		...report.categories,
		dependencies: updatedDeps,
	};

	return aggregateScores(updatedCategories, report.metadata);
}

export async function scanTarget(target: string, options?: ScanOptions): Promise<ScanTargetReport> {
	if (isUrlTarget(target)) {
		const report = await scanSkillFromUrl(target, options);
		return { target, report };
	}

	const content = await readFile(target, "utf-8");
	const baseReport = await scanSkill(content, options);

	// Local-only: best-effort scan for packaged executable binaries.
	const binaries = await getBinariesForDir(dirname(target));
	const report = applyBinaryArtifacts(baseReport, target, binaries);

	return { target, report };
}

export async function scanTargets(
	targets: readonly string[],
	options?: ScanOptions,
): Promise<readonly ScanTargetReport[]> {
	const results: ScanTargetReport[] = [];
	for (const target of targets) results.push(await scanTarget(target, options));
	return results;
}

export async function scanTargetsBatch(
	targets: readonly string[],
	options?: ScanOptions,
): Promise<{ readonly reports: readonly ScanTargetReport[]; readonly failures: readonly ScanFailure[] }> {
	const reports: ScanTargetReport[] = [];
	const failures: ScanFailure[] = [];

	for (const target of targets) {
		try {
			reports.push(await scanTarget(target, options));
		} catch (err) {
			const message = err instanceof Error ? err.message : String(err);
			failures.push({ target, error: message });
		}
	}

	return { reports, failures };
}

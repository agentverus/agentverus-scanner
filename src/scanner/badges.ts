import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import type { ScanFailure, ScanTargetReport } from "./runner.js";
import type { BadgeTier } from "./types.js";

export interface ShieldsEndpoint {
	readonly schemaVersion: 1;
	readonly label: string;
	readonly message: string;
	readonly color: string;
	readonly cacheSeconds?: number;
}

export interface BadgeIndexSkill {
	readonly target: string;
	readonly slug: string;
	readonly overall: number;
	readonly badge: BadgeTier;
}

export interface BadgeIndex {
	readonly generatedAt: string;
	readonly totalSkills: number;
	readonly certifiedSkills: number;
	readonly percentCertified: number;
	readonly failures: readonly ScanFailure[];
	readonly skills: readonly BadgeIndexSkill[];
}

export interface WriteBadgesOptions {
	/** Label used in shields endpoint JSON. Default: AgentVerus */
	readonly label?: string;
	/** cacheSeconds value for shields endpoint JSON. Default: 3600 */
	readonly cacheSeconds?: number;
}

function endpoint(label: string, message: string, color: string, cacheSeconds?: number): ShieldsEndpoint {
	return {
		schemaVersion: 1,
		label,
		message,
		color,
		cacheSeconds,
	};
}

export function slugForTarget(target: string): string {
	// Stable across platforms and safe for GitHub Pages paths.
	return target
		.replace(/\\/g, "/")
		.replace(/[^a-zA-Z0-9._/-]/g, "__")
		.replace(/\//g, "__");
}

export function colorForTier(tier: BadgeTier): string {
	switch (tier) {
		case "certified":
			return "brightgreen";
		case "conditional":
			return "yellow";
		case "suspicious":
			return "orange";
		case "rejected":
			return "red";
		default:
			return "lightgrey";
	}
}

export function colorForCertifiedPercent(percent: number): string {
	if (!Number.isFinite(percent)) return "lightgrey";
	if (percent >= 90) return "brightgreen";
	if (percent >= 75) return "green";
	if (percent >= 50) return "yellow";
	return "orange";
}

export function buildSkillBadgeEndpoint(
	item: ScanTargetReport,
	options?: WriteBadgesOptions,
): ShieldsEndpoint {
	const label = options?.label ?? "AgentVerus";
	const cacheSeconds = options?.cacheSeconds ?? 3600;
	const tier = item.report.badge;
	const msg = `${tier.toUpperCase()} (${item.report.overall}/100)`;
	return endpoint(label, msg, colorForTier(tier), cacheSeconds);
}

export function buildRepoCertifiedEndpoint(
	reports: readonly ScanTargetReport[],
	failures: readonly ScanFailure[],
	options?: WriteBadgesOptions,
): ShieldsEndpoint {
	const label = options?.label ?? "AgentVerus";
	const cacheSeconds = options?.cacheSeconds ?? 3600;

	const total = reports.length;
	const allCertified = total > 0 && failures.length === 0 && reports.every((r) => r.report.badge === "certified");
	return allCertified
		? endpoint(label, "CERTIFIED", "brightgreen", cacheSeconds)
		: endpoint(label, "NOT CERTIFIED", "red", cacheSeconds);
}

export function buildRepoCertifiedPercentEndpoint(
	reports: readonly ScanTargetReport[],
	failures: readonly ScanFailure[],
	options?: WriteBadgesOptions,
): ShieldsEndpoint {
	const label = options?.label ?? "AgentVerus";
	const cacheSeconds = options?.cacheSeconds ?? 3600;

	if (failures.length > 0) return endpoint(label, "Scan failed", "red", cacheSeconds);

	const total = reports.length;
	if (total === 0) return endpoint(label, "No skills found", "lightgrey", cacheSeconds);

	const certified = reports.filter((r) => r.report.badge === "certified").length;
	const percent = Math.round((certified / total) * 100);

	return endpoint(label, `Certified ${percent}%`, colorForCertifiedPercent(percent), cacheSeconds);
}

export async function writeBadgeBundle(
	reports: readonly ScanTargetReport[],
	failures: readonly ScanFailure[],
	outDir: string,
	options?: WriteBadgesOptions,
): Promise<BadgeIndex> {
	const skillsDir = join(outDir, "skills");
	await mkdir(skillsDir, { recursive: true });

	// Repo badges
	const repoCertified = buildRepoCertifiedEndpoint(reports, failures, options);
	const repoPct = buildRepoCertifiedPercentEndpoint(reports, failures, options);

	await writeFile(join(outDir, "repo-certified.json"), `${JSON.stringify(repoCertified, null, 2)}\n`, "utf-8");
	await writeFile(
		join(outDir, "repo-certified-pct.json"),
		`${JSON.stringify(repoPct, null, 2)}\n`,
		"utf-8",
	);

	// Per-skill badges + index
	const skills: BadgeIndexSkill[] = [];
	for (const item of reports) {
		const slug = slugForTarget(item.target);
		skills.push({ target: item.target, slug, overall: item.report.overall, badge: item.report.badge });

		const skillEndpoint = buildSkillBadgeEndpoint(item, options);
		await writeFile(
			join(skillsDir, `${slug}.json`),
			`${JSON.stringify(skillEndpoint, null, 2)}\n`,
			"utf-8",
		);
	}

	const certifiedSkills = reports.filter((r) => r.report.badge === "certified").length;
	const percentCertified = reports.length === 0 ? 0 : Math.round((certifiedSkills / reports.length) * 100);

	const index: BadgeIndex = {
		generatedAt: new Date().toISOString(),
		totalSkills: reports.length,
		certifiedSkills,
		percentCertified,
		failures,
		skills,
	};

	await writeFile(join(outDir, "skills", "index.json"), `${JSON.stringify(index, null, 2)}\n`, "utf-8");
	return index;
}

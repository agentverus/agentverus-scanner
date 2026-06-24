import { appendFileSync, writeFileSync } from "node:fs";

import { scanTargetsBatch } from "../../../dist/scanner/runner.js";
import { buildSarifLog } from "../../../dist/scanner/sarif.js";
import { expandScanTargets } from "../../../dist/scanner/targets.js";

type FailOnSeverity = "critical" | "high" | "medium" | "low" | "info" | "none";

const SEVERITY_RANK: Readonly<Record<Exclude<FailOnSeverity, "none">, number>> = {
	critical: 0,
	high: 1,
	medium: 2,
	low: 3,
	info: 4,
};

function parseTargets(raw: string): string[] {
	return raw
		.split(/\r?\n/g)
		.map((l) => l.trim())
		.filter((l) => l.length > 0 && !l.startsWith("#"));
}

function parseOptionalInt(value: string | undefined): number | undefined {
	if (value === undefined) return undefined;
	const trimmed = value.trim();
	if (!trimmed) return undefined;
	const n = Number.parseInt(trimmed, 10);
	return Number.isNaN(n) ? undefined : n;
}

function parseFailOnSeverity(value: string | undefined): FailOnSeverity {
	const v = (value ?? "high").trim().toLowerCase();
	if (
		v === "none" ||
		v === "critical" ||
		v === "high" ||
		v === "medium" ||
		v === "low" ||
		v === "info"
	) {
		return v;
	}
	return "high";
}

function shouldFailOnSeverity(reports: readonly unknown[], threshold: FailOnSeverity): boolean {
	if (threshold === "none") return false;
	const limit = SEVERITY_RANK[threshold] ?? 99;
	for (const item of reports) {
		if (!item || typeof item !== "object") continue;
		const report = (item as Record<string, unknown>).report;
		if (!report || typeof report !== "object") continue;
		const findings = (report as Record<string, unknown>).findings;
		if (!Array.isArray(findings)) continue;

		for (const finding of findings) {
			if (!finding || typeof finding !== "object") continue;
			const severity = (finding as Record<string, unknown>).severity;
			if (typeof severity !== "string") continue;
			const rank = SEVERITY_RANK[severity as Exclude<FailOnSeverity, "none">];
			if ((rank ?? 99) <= limit) return true;
		}
	}
	return false;
}

function setOutput(key: string, value: string): void {
	const outFile = process.env.GITHUB_OUTPUT;
	if (!outFile) return;
	appendFileSync(outFile, `${key}=${value}\n`, { encoding: "utf-8" });
}

function appendSummary(markdown: string): void {
	const summaryFile = process.env.GITHUB_STEP_SUMMARY;
	if (!summaryFile) return;
	appendFileSync(summaryFile, `${markdown}\n`, { encoding: "utf-8" });
}

function countSeverities(items: readonly unknown[]): Record<string, number> {
	const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
	for (const item of items) {
		if (!item || typeof item !== "object") continue;
		const report = (item as Record<string, unknown>).report;
		if (!report || typeof report !== "object") continue;
		const findings = (report as Record<string, unknown>).findings;
		if (!Array.isArray(findings)) continue;

		for (const finding of findings) {
			if (!finding || typeof finding !== "object") continue;
			const severity = (finding as Record<string, unknown>).severity;
			if (typeof severity !== "string") continue;
			counts[severity] = (counts[severity] ?? 0) + 1;
		}
	}
	return counts;
}

async function main(): Promise<void> {
	const rawTargetInput = process.env.INPUT_TARGET ?? ".";
	const sarifPath =
		(process.env.INPUT_SARIF ?? "agentverus-scanner.sarif").trim() || "agentverus-scanner.sarif";
	const failOnSeverity = parseFailOnSeverity(process.env.INPUT_FAIL_ON_SEVERITY);

	const timeout = parseOptionalInt(process.env.INPUT_TIMEOUT);
	const retries = parseOptionalInt(process.env.INPUT_RETRIES);
	const retryDelayMs = parseOptionalInt(process.env.INPUT_RETRY_DELAY_MS);

	const rawTargets = parseTargets(rawTargetInput);
	const targets = rawTargets.length > 0 ? rawTargets : ["."];

	let expanded: readonly string[] = [];
	let reports: readonly unknown[] = [];
	let failures: readonly unknown[] = [];

	try {
		expanded = await expandScanTargets(targets);
		if (expanded.length > 0) {
			const batch = await scanTargetsBatch(expanded, { timeout, retries, retryDelayMs });
			reports = batch.reports;
			failures = batch.failures;
		} else {
			failures = [
				{
					target: rawTargets.length === 1 ? rawTargets[0] : "targets",
					error: "No SKILL.md files found under the provided directory target(s).",
				},
			];
		}
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		failures = [{ target: targets.join("\n"), error: message }];
	}

	const sarif = buildSarifLog(
		reports as unknown as Parameters<typeof buildSarifLog>[0],
		failures as unknown as Parameters<typeof buildSarifLog>[1],
	);
	writeFileSync(sarifPath, JSON.stringify(sarif, null, 2), { encoding: "utf-8" });

	setOutput("sarif_path", sarifPath);
	setOutput("targets_scanned", String(reports.length));
	setOutput("failures", String(failures.length));

	const sevCounts = countSeverities(reports);
	appendSummary(`## AgentVerus Skill Scan\n`);
	appendSummary(`- Targets scanned: **${reports.length}**`);
	appendSummary(`- Failures: **${failures.length}**`);
	appendSummary(
		`- Findings: critical **${sevCounts.critical}**, high **${sevCounts.high}**, medium **${sevCounts.medium}**, low **${sevCounts.low}**, info **${sevCounts.info}**`,
	);
	appendSummary(`- SARIF: \`${sarifPath}\``);

	if (failures.length > 0) process.exit(2);
	if (shouldFailOnSeverity(reports, failOnSeverity)) process.exit(1);
	process.exit(0);
}

main().catch((err) => {
	const message = err instanceof Error ? err.message : String(err);
	console.error(message);
	process.exit(2);
});

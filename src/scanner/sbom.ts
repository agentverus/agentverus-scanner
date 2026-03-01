import type { ScanFailure, ScanTargetReport } from "./runner.js";
import { SCANNER_VERSION } from "./types.js";

const URL_REGEX = /https?:\/\/[^\s`"'<>()[\]{}]+/gi;

export interface SbomProperty {
	readonly name: string;
	readonly value: string;
}

export interface SbomExternalReference {
	readonly type: "distribution";
	readonly url: string;
}

export interface SbomComponent {
	readonly type: "application" | "data" | "file";
	readonly name: string;
	readonly "bom-ref": string;
	readonly version?: string;
	readonly properties?: readonly SbomProperty[];
	readonly externalReferences?: readonly SbomExternalReference[];
}

export interface SbomDependency {
	readonly ref: string;
	readonly dependsOn: readonly string[];
}

export interface ScannerSbomDocument {
	readonly bomFormat: "CycloneDX";
	readonly specVersion: "1.5";
	readonly version: 1;
	readonly metadata: {
		readonly timestamp: string;
		readonly tools: ReadonlyArray<{
			readonly vendor: "AgentVerus";
			readonly name: "agentverus-scanner";
			readonly version: string;
		}>;
		readonly properties: readonly SbomProperty[];
	};
	readonly components: readonly SbomComponent[];
	readonly dependencies: readonly SbomDependency[];
}

function stableRef(prefix: string, value: string): string {
	return `${prefix}:${Buffer.from(value, "utf-8").toString("base64url")}`;
}

function normalizeUrl(url: string): string {
	return url.replace(/[),.;\]]+$/, "");
}

function extractUrlsFromEvidence(evidence: string): string[] {
	const matches = evidence.match(URL_REGEX);
	if (!matches) return [];
	return [...new Set(matches.map(normalizeUrl))].sort((a, b) => a.localeCompare(b));
}

function extractBinaryMarkers(evidence: string): string[] {
	const markers = evidence
		.split(",")
		.map((part) => part.trim())
		.filter(Boolean)
		.map((part) => part.replace(/\s*\(\+\d+\s+more\)\s*$/i, ""))
		.filter(Boolean);

	return [...new Set(markers)].sort((a, b) => a.localeCompare(b));
}

function latestScanTimestamp(scans: readonly ScanTargetReport[]): string {
	let latest = 0;
	for (const scan of scans) {
		const ts = scan.report.metadata.scannedAt.getTime();
		if (ts > latest) latest = ts;
	}
	return new Date(latest || Date.now()).toISOString();
}

function toTargetComponent(scan: ScanTargetReport): SbomComponent {
	const report = scan.report;
	return {
		type: "application",
		name: report.metadata.skillName || scan.target,
		version: `scanner-${report.metadata.scannerVersion}`,
		"bom-ref": stableRef("skill", scan.target),
		properties: [
			{ name: "agentverus:target", value: scan.target },
			{ name: "agentverus:badge", value: report.badge },
			{ name: "agentverus:overall", value: String(report.overall) },
			{ name: "agentverus:skill.format", value: report.metadata.skillFormat },
		],
	};
}

function collectIndicators(scan: ScanTargetReport): readonly string[] {
	const indicators = new Set<string>();
	for (const finding of scan.report.categories.dependencies.findings) {
		for (const url of extractUrlsFromEvidence(finding.evidence)) {
			indicators.add(`url:${url}`);
		}
		if (finding.id.startsWith("DEP-BINARY-")) {
			for (const marker of extractBinaryMarkers(finding.evidence)) {
				indicators.add(`binary:${marker}`);
			}
		}
	}
	return [...indicators].sort((a, b) => a.localeCompare(b));
}

function indicatorToComponent(indicator: string): SbomComponent {
	if (indicator.startsWith("url:")) {
		const url = indicator.slice(4);
		const ref = stableRef("dep-url", indicator);
		const name = (() => {
			try {
				return new URL(url).hostname;
			} catch {
				return url;
			}
		})();

		return {
			type: "data",
			name,
			"bom-ref": ref,
			externalReferences: [{ type: "distribution", url }],
			properties: [{ name: "agentverus:indicator", value: "url" }],
		};
	}

	const marker = indicator.slice("binary:".length);
	return {
		type: "file",
		name: marker,
		"bom-ref": stableRef("dep-binary", indicator),
		properties: [{ name: "agentverus:indicator", value: "binary-artifact" }],
	};
}

export function buildSbomDocument(
	scans: readonly ScanTargetReport[],
	failures: readonly ScanFailure[] = [],
): ScannerSbomDocument {
	const componentMap = new Map<string, SbomComponent>();
	const dependencies: SbomDependency[] = [];

	for (const scan of scans) {
		const targetComponent = toTargetComponent(scan);
		componentMap.set(targetComponent["bom-ref"], targetComponent);

		const indicatorRefs: string[] = [];
		for (const indicator of collectIndicators(scan)) {
			const component = indicatorToComponent(indicator);
			componentMap.set(component["bom-ref"], component);
			indicatorRefs.push(component["bom-ref"]);
		}

		dependencies.push({
			ref: targetComponent["bom-ref"],
			dependsOn: indicatorRefs.sort((a, b) => a.localeCompare(b)),
		});
	}

	const components = [...componentMap.values()].sort((a, b) =>
		a["bom-ref"].localeCompare(b["bom-ref"]),
	);

	const metadataProperties: SbomProperty[] = [
		{ name: "agentverus:scan.targets", value: String(scans.length) },
		{ name: "agentverus:scan.failures", value: String(failures.length) },
	];

	return {
		bomFormat: "CycloneDX",
		specVersion: "1.5",
		version: 1,
		metadata: {
			timestamp: latestScanTimestamp(scans),
			tools: [
				{
					vendor: "AgentVerus",
					name: "agentverus-scanner",
					version: SCANNER_VERSION,
				},
			],
			properties: metadataProperties,
		},
		components,
		dependencies: dependencies.sort((a, b) => a.ref.localeCompare(b.ref)),
	};
}
